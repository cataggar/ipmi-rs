//! Checked Kontron Firmware Update Manager queries.
//!
//! Firmware NetFn 0x08 is not universally supported. Every FWUM packet is
//! identity-checked against the *selected* board on LUN zero. These methods
//! do not implement ipmitool's CLI output or claim tested hardware support.

use ipmi_rs_core::{
    app::DeviceId,
    connection::{IpmiConnection, NotEnoughData},
    oem::fwum::{
        BankStatus, FwumParseError, FwumTarget, GetInfo, GetStatus, GetTraceChunk, Info,
        TraceEntry, MAX_BANKS, TRACE_CHUNKS,
    },
};

use crate::{oem::OemError, oem::TargetDeviceId, Ipmi, IpmiError};

#[cfg(feature = "kontron-fwum-update")]
mod update;
#[cfg(feature = "kontron-fwum-update")]
pub use update::*;

/// Device ID and FWUM protocol info, from separate requests to the same target.
#[derive(Debug)]
pub struct Inventory {
    /// Full Get Device ID result.
    pub device: DeviceId,
    /// Firmware NetFn Get Firmware Info response.
    pub firmware: Info,
    /// Kontron 5002's SDR revision in auxiliary firmware byte zero, if present.
    pub kontron_5002_sdr_revision: Option<u8>,
}

/// A bounded snapshot of bank states.
#[derive(Debug)]
pub struct BankInventory {
    /// Board and FWUM identity.
    pub inventory: Inventory,
    /// Exactly `inventory.firmware.bank_count` entries (at most 16).
    pub banks: Vec<BankStatus>,
}

/// Failure to read verified FWUM information.
#[derive(Debug)]
pub enum FwumReadError<CON> {
    /// Get Device ID failed (no firmware command sent).
    Device(IpmiError<CON, NotEnoughData>),
    /// Get Device ID returned a different vendor, product, or unavailable device.
    UnsupportedDevice {
        /// Observed manufacturer.
        manufacturer: u32,
        /// Observed board product.
        product: u16,
    },
    /// Firmware Info returned a different controller device ID.
    ControllerMismatch {
        /// Device ID from App Get Device ID.
        device_id: u8,
        /// Device ID from Firmware Get Info.
        firmware_device_id: u8,
    },
    /// Bank count is zero or would exceed the read bound.
    BankLimit(u8),
    /// An identity-checked Firmware/OEM command failed.
    Command(OemError<CON, FwumParseError>),
}

fn retryable<CON, P>(error: &IpmiError<CON, P>) -> bool {
    matches!(
        error,
        IpmiError::Connection(_)
            | IpmiError::Failed {
                completion_code: ipmi_rs_core::connection::CompletionErrorCode::NodeBusy,
                ..
            }
    )
}

fn retry_oem<CON, P>(error: &OemError<CON, P>) -> bool {
    match error {
        OemError::Identity(err) => retryable(err),
        OemError::Command(err) => retryable(err),
        OemError::UnsupportedDevice { .. } => false,
    }
}

impl<CON: IpmiConnection> Ipmi<CON> {
    fn fwum_read<C: ipmi_rs_core::oem::OemCommand + Clone>(
        &mut self,
        command: C,
    ) -> Result<C::Output, OemError<CON::Error, C::Error>> {
        // Only reads call this method. Never route mutating commands through it.
        for attempt in 0..3 {
            match self.send_oem(command.clone()) {
                Err(error) if attempt < 2 && retry_oem(&error) => {}
                result => return result,
            }
        }
        unreachable!("the third attempt always returns")
    }

    /// Verify the exact Kontron IANA/board and read typed FWUM inventory.
    ///
    /// `target.product_id` must come from the operator's known board; it is
    /// checked before *every* firmware request. Read-only busy/transport errors
    /// are retried at most twice, but malformed data and mismatches are not.
    pub fn fwum_inventory(
        &mut self,
        target: FwumTarget,
    ) -> Result<Inventory, FwumReadError<CON::Error>> {
        let device = {
            let mut result = None;
            for attempt in 0..3 {
                match self.send_recv(TargetDeviceId(target.address)) {
                    Err(error) if attempt < 2 && retryable(&error) => {}
                    other => {
                        result = Some(other);
                        break;
                    }
                }
            }
            result
                .expect("bounded identity read")
                .map_err(FwumReadError::Device)?
        };
        if device.manufacturer_id != 15000
            || target.product_id == 0
            || device.product_id != target.product_id
            || !device.device_available
        {
            return Err(FwumReadError::UnsupportedDevice {
                manufacturer: device.manufacturer_id,
                product: device.product_id,
            });
        }
        let firmware = self
            .fwum_read(GetInfo(target))
            .map_err(FwumReadError::Command)?;
        if firmware.controller_device_id != device.device_id {
            return Err(FwumReadError::ControllerMismatch {
                device_id: device.device_id,
                firmware_device_id: firmware.controller_device_id,
            });
        }
        if firmware.bank_count == 0 || firmware.bank_count > MAX_BANKS {
            return Err(FwumReadError::BankLimit(firmware.bank_count));
        }
        let kontron_5002_sdr_revision = if device.product_id == 5002 {
            device.aux_revision.map(|aux| aux[0])
        } else {
            None
        };
        Ok(Inventory {
            device,
            firmware,
            kontron_5002_sdr_revision,
        })
    }

    /// Read at most 16 bank statuses, without silently omitting a failed bank.
    pub fn fwum_banks(
        &mut self,
        target: FwumTarget,
    ) -> Result<BankInventory, FwumReadError<CON::Error>> {
        let inventory = self.fwum_inventory(target)?;
        let mut banks = Vec::with_capacity(usize::from(inventory.firmware.bank_count));
        for bank in 0..inventory.firmware.bank_count {
            banks.push(
                self.fwum_read(GetStatus { target, bank })
                    .map_err(FwumReadError::Command)?,
            );
        }
        Ok(BankInventory { inventory, banks })
    }

    /// Read exactly seven bounded trace chunks, at most 49 typed entries.
    pub fn fwum_trace(
        &mut self,
        target: FwumTarget,
    ) -> Result<Vec<TraceEntry>, FwumReadError<CON::Error>> {
        self.fwum_inventory(target)?;
        let mut trace = Vec::with_capacity(49);
        for index in 0..TRACE_CHUNKS {
            trace.extend(
                self.fwum_read(GetTraceChunk { target, index })
                    .map_err(FwumReadError::Command)?,
            );
        }
        Ok(trace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipmi_rs_core::oem::OemCommand;

    #[test]
    fn source_derived_info_bank_and_trace_parsing_is_bounded() {
        assert_eq!(
            GetInfo::parse_success_response(&[6, 0x22, 2, 3, 0x45, 2, 0]).unwrap(),
            Info {
                protocol_revision: 6,
                controller_device_id: 0x22,
                debug_build: false,
                sequence_address: true,
                revision: ipmi_rs_core::oem::fwum::Revision {
                    major: 3,
                    minor: 4,
                    subminor: 5,
                    sdr: None,
                },
                bank_count: 2,
                sequence_format: true,
            }
        );
        assert!(matches!(
            GetInfo::parse_success_response(&[6, 0x22]),
            Err(FwumParseError::Truncated { .. })
        ));
        assert_eq!(
            GetStatus::parse_success_response(&[3, 0, 1, 0, 2, 0x10, 4])
                .unwrap()
                .length,
            256
        );
        assert_eq!(
            GetStatus::parse_success_response(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
                .unwrap()
                .length,
            0
        );
        assert!(GetStatus::parse_success_response(&[3, 1]).is_err());
        let mut trace = [0; 21];
        trace[..6].copy_from_slice(&[0x0b, 3, 0, 0xc0, 2, 0x82]);
        assert_eq!(
            GetTraceChunk::parse_success_response(&trace).unwrap().len(),
            2
        );
        assert!(GetTraceChunk::parse_success_response(&trace[..20]).is_err());
        trace[1] = 4;
        assert!(GetTraceChunk::parse_success_response(&trace).is_err());
    }
}
