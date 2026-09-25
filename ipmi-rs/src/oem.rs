//! Checked OEM dispatch for [`Ipmi`].
//!
//! The sender reads Get Device ID on LUN zero at the selected destination
//! immediately before every OEM request. A failed identity lookup or a vendor
//! (or required board-product) mismatch prevents the OEM request from being
//! sent. This does not prove a firmware feature or eliminate device swaps
//! between the two transactions; those require on-device verification.

pub use ipmi_rs_core::oem::{dell, kontron, quanta, OemCommand};

/// Bounded Sun/Oracle ILOM commands and workflows.
pub mod sun;

/// Intel ME inventory and guarded firmware operations.
pub mod ime;

use crate::{
    app::{DeviceId, GetDeviceId},
    connection::{
        Address, Channel, CompletionErrorCode, IpmiCommand, IpmiConnection, LogicalUnit, Message,
        NotEnoughData,
    },
    Ipmi, IpmiError,
};

/// A failed OEM dispatch: lookup, unsupported destination, or command failure.
#[derive(Debug)]
pub enum OemError<ConnectionError, CommandError> {
    /// The target's Get Device ID failed; no OEM request was sent.
    Identity(IpmiError<ConnectionError, NotEnoughData>),
    /// The destination does not match the command's required vendor/product.
    UnsupportedDevice {
        /// Manufacturer observed in Get Device ID.
        manufacturer_id: u32,
        /// Product observed in Get Device ID.
        product_id: u16,
        /// Manufacturer required by the command.
        expected_manufacturer_id: u32,
        /// Required product, if this command is board-specific.
        expected_product_id: Option<u16>,
    },
    /// The OEM command failed after the identity check.
    Command(IpmiError<ConnectionError, CommandError>),
}

struct TargetDeviceId(Option<(Address, Channel)>);

impl From<TargetDeviceId> for Message {
    fn from(_: TargetDeviceId) -> Self {
        GetDeviceId.into()
    }
}

impl IpmiCommand for TargetDeviceId {
    type Output = DeviceId;
    type Error = NotEnoughData;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        GetDeviceId::parse_success_response(data)
    }

    fn target(&self) -> Option<(Address, Channel)> {
        self.0
    }
}

struct Checked<C> {
    command: C,
    target: Option<(Address, Channel)>,
    lun: LogicalUnit,
}

impl<C: OemCommand> From<Checked<C>> for Message {
    fn from(command: Checked<C>) -> Self {
        command.command.into_message()
    }
}

impl<C: OemCommand> IpmiCommand for Checked<C> {
    type Output = C::Output;
    type Error = C::Error;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        C::parse_success_response(data)
    }

    fn handle_completion_code(code: CompletionErrorCode, data: &[u8]) -> Option<Self::Error> {
        C::handle_completion_code(code, data)
    }

    fn target(&self) -> Option<(Address, Channel)> {
        self.target
    }

    fn target_lun(&self) -> LogicalUnit {
        self.lun
    }
}

impl<CON: IpmiConnection> Ipmi<CON> {
    /// Verify the selected destination before sending a typed OEM command.
    ///
    /// A mutation is never automatically retried. A transport error after
    /// dispatch leaves its outcome unknown, including boot/firmware writes.
    /// [`Ipmi::send_recv`] and raw [`Message`] requests remain available
    /// independently of this checked opt-in API.
    pub fn send_oem<C: OemCommand>(
        &mut self,
        command: C,
    ) -> Result<C::Output, OemError<CON::Error, C::Error>> {
        let target = command.target();
        let lun = command.lun();
        let device = self
            .send_recv(TargetDeviceId(target))
            .map_err(OemError::Identity)?;
        if device.manufacturer_id != C::MANUFACTURER_ID
            || C::PRODUCT_ID.is_some_and(|product| device.product_id != product)
            || !command.supports(&device)
        {
            return Err(OemError::UnsupportedDevice {
                manufacturer_id: device.manufacturer_id,
                product_id: device.product_id,
                expected_manufacturer_id: C::MANUFACTURER_ID,
                expected_product_id: C::PRODUCT_ID,
            });
        }

        self.send_recv(Checked {
            command,
            target,
            lun,
        })
        .map_err(OemError::Command)
    }
}
