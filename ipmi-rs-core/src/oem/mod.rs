//! OEM commands are sent with `ipmi_rs::Ipmi::send_oem`, which checks the
//! destination's Get Device ID before dispatch. Raw
//! [`Message`](crate::connection::Message) requests
//! remain available for commands not yet modeled here.
//!
//! `Get Device ID` is sent to LUN zero at the same BMC or bridged IPMB
//! address/channel as the OEM command. OEM commands can use a different LUN.

use crate::{
    app::DeviceId,
    connection::{Address, Channel, CompletionErrorCode, LogicalUnit, Message},
};

pub mod dell;
pub mod ime;
pub mod kontron;
pub mod quanta;
pub mod sun;

/// A vendor command that must be routed through an identity-checking sender.
///
/// This intentionally does not implement [`crate::connection::IpmiCommand`].
/// Callers can still use [`Message`] explicitly as a raw escape hatch.
pub trait OemCommand {
    /// The parsed command response.
    type Output;
    /// A command-specific parsing or completion-code error.
    type Error;

    /// The Get Device ID manufacturer number required for this command.
    const MANUFACTURER_ID: u32;
    /// A product ID required for a board-specific command, if applicable.
    const PRODUCT_ID: Option<u16> = None;

    /// Construct the wire request after the destination has been checked.
    fn into_message(self) -> Message;

    /// Parse successful response data, excluding the completion code.
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error>;

    /// Interpret command-specific, non-success completion codes.
    fn handle_completion_code(
        _completion_code: CompletionErrorCode,
        _data: &[u8],
    ) -> Option<Self::Error> {
        None
    }

    /// A bridged destination; `None` targets the session BMC.
    ///
    /// The checked sender snapshots this once for identity lookup and dispatch.
    fn target(&self) -> Option<(Address, Channel)> {
        None
    }

    /// The OEM command's logical unit; identity discovery always uses LUN zero.
    /// The checked sender snapshots this once before the identity lookup.
    fn lun(&self) -> LogicalUnit {
        LogicalUnit::Zero
    }

    /// Apply additional device restrictions; manufacturer/product are
    /// independently enforced by the checked sender and cannot be bypassed.
    fn supports(&self, device: &DeviceId) -> bool {
        device.manufacturer_id == Self::MANUFACTURER_ID
            && Self::PRODUCT_ID.is_none_or(|product| device.product_id == product)
    }
}
