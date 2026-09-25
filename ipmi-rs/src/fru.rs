//! Bounded FRU transfers built on the sans-IO storage commands.

use ipmi_rs_core::{
    connection::{CompletionErrorCode, IpmiConnection},
    storage::fru::{
        discover_fru_devices, FruCommandError, FruDevice, FruInfo, FruInventory, FruParseError,
        GetFruInventoryAreaInfo, ReadFruData, WriteFruData, DEFAULT_CHUNK_BYTES,
    },
};

use crate::{Ipmi, IpmiError};

/// Failure to read or decode inventory; partial reads are never returned.
#[derive(Debug)]
pub enum FruReadError<E> {
    /// Transport, completion code, or command response failure.
    Command(IpmiError<E, FruCommandError>),
    /// Invalid read size, alignment, or returned count.
    Transfer(FruCommandError),
    /// Invalid FRU layout, checksum, or field.
    Inventory(FruParseError),
}

/// Failure of an explicitly requested inventory write.
#[derive(Debug)]
pub enum FruWriteError<E> {
    /// Rejected before sending anything; no mutation occurred.
    InvalidImage(FruParseError),
    /// Image size disagrees with the FRU Info response; nothing was sent.
    SizeMismatch,
    /// Invalid transfer before sending anything.
    InvalidTransfer(FruCommandError),
    /// A command was sent but its outcome is not certain. No retry is made.
    /// `bytes_confirmed` counts earlier chunks, not this chunk.
    OutcomeUnknown {
        /// Offset of the affected chunk.
        offset: usize,
        /// Number of bytes acknowledged before the affected chunk.
        bytes_confirmed: usize,
        /// Transport, completion code, or malformed acknowledgement.
        source: IpmiError<E, FruCommandError>,
    },
    /// A short/overlong acknowledgement cannot establish the write outcome.
    OutcomeUnconfirmed {
        /// Offset of the affected chunk.
        offset: usize,
        /// Number of bytes acknowledged before this chunk.
        bytes_confirmed: usize,
        /// Bad acknowledgement count.
        error: FruCommandError,
    },
}

fn shrinkable<E>(error: &IpmiError<E, FruCommandError>) -> bool {
    let completion = match error {
        IpmiError::Failed {
            completion_code, ..
        } => Some(*completion_code),
        IpmiError::Command {
            completion_code, ..
        } => *completion_code,
        _ => None,
    };
    matches!(
        completion,
        Some(
            CompletionErrorCode::RequestDataLenInvalid
                | CompletionErrorCode::RequestDataLengthLimitExceeded
                | CompletionErrorCode::CannotReturnNumOfRequestedBytes
        )
    )
}

impl<C: IpmiConnection> Ipmi<C> {
    /// Find the built-in FRU and logical inventory locators from the SDR iterator.
    /// This returns candidates only, not inventory contents.
    pub fn fru_devices(&mut self) -> Vec<FruDevice> {
        let records: Vec<_> = self.sdrs().collect();
        discover_fru_devices(&records)
    }

    /// Query size and access method for one candidate FRU.
    pub fn fru_info(
        &mut self,
        device: FruDevice,
    ) -> Result<FruInfo, IpmiError<C::Error, FruCommandError>> {
        self.send_recv(GetFruInventoryAreaInfo::new(
            device.id,
            device.target,
            device.lun,
        ))
    }

    /// Read an entire FRU without modifying it. Chunks are at most 16 bytes
    /// and shrink on size-related completion codes, never on other errors.
    pub fn read_fru_image(&mut self, device: FruDevice) -> Result<Vec<u8>, FruReadError<C::Error>> {
        let info = self.fru_info(device).map_err(FruReadError::Command)?;
        if info.access == ipmi_rs_core::storage::fru::FruAccess::Word
            && !info.size.is_multiple_of(2)
        {
            return Err(FruReadError::Transfer(FruCommandError::Unaligned));
        }
        let mut bytes = Vec::with_capacity(info.size as usize);
        let mut chunk_size = DEFAULT_CHUNK_BYTES;
        while bytes.len() < info.size as usize {
            let offset = bytes.len();
            let count = chunk_size.min(info.size as usize - offset);
            let command = ReadFruData::new(
                device.id,
                device.target,
                device.lun,
                info,
                offset as u16,
                count as u8,
            )
            .map_err(FruReadError::Transfer)?;
            match self.send_recv(command) {
                Ok(response) => {
                    bytes.extend(command.verify(response).map_err(FruReadError::Transfer)?)
                }
                Err(error) if shrinkable(&error) && chunk_size > info.access_unit() => {
                    chunk_size = (chunk_size / 2).max(info.access_unit());
                }
                Err(error) => return Err(FruReadError::Command(error)),
            }
        }
        Ok(bytes)
    }

    /// Read and validate a complete FRU inventory image.
    pub fn read_fru_inventory(
        &mut self,
        device: FruDevice,
    ) -> Result<FruInventory, FruReadError<C::Error>> {
        let bytes = self.read_fru_image(device)?;
        FruInventory::parse(&bytes).map_err(FruReadError::Inventory)
    }

    /// Explicitly replace a complete FRU image after validating its layout,
    /// checksums and fields. This method does not read or repair inventory and
    /// never retries a write, even on size errors or a lost response. It may
    /// partially change the remote inventory on failure; verify independently.
    pub fn write_fru_image(
        &mut self,
        device: FruDevice,
        info: FruInfo,
        image: &[u8],
    ) -> Result<(), FruWriteError<C::Error>> {
        if image.len() != info.size as usize {
            return Err(FruWriteError::SizeMismatch);
        }
        FruInventory::parse(image).map_err(FruWriteError::InvalidImage)?;
        if info.access == ipmi_rs_core::storage::fru::FruAccess::Word
            && !image.len().is_multiple_of(2)
        {
            return Err(FruWriteError::InvalidTransfer(FruCommandError::Unaligned));
        }
        for (index, part) in image.chunks(DEFAULT_CHUNK_BYTES).enumerate() {
            let offset = index * DEFAULT_CHUNK_BYTES;
            let command = WriteFruData::new(
                device.id,
                device.target,
                device.lun,
                info,
                offset as u16,
                part.to_vec(),
            )
            .map_err(FruWriteError::InvalidTransfer)?;
            match self.send_recv(command.clone()) {
                Ok(count) => {
                    command
                        .verify(count)
                        .map_err(|error| FruWriteError::OutcomeUnconfirmed {
                            offset,
                            bytes_confirmed: offset,
                            error,
                        })?
                }
                Err(source) => {
                    return Err(FruWriteError::OutcomeUnknown {
                        offset,
                        bytes_confirmed: offset,
                        source,
                    })
                }
            }
        }
        Ok(())
    }
}

trait AccessUnit {
    fn access_unit(&self) -> usize;
}

impl AccessUnit for FruInfo {
    fn access_unit(&self) -> usize {
        match self.access {
            ipmi_rs_core::storage::fru::FruAccess::Byte => 1,
            ipmi_rs_core::storage::fru::FruAccess::Word => 2,
        }
    }
}
