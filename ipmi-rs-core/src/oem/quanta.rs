//! Quanta QCT platform discovery used by OEM memory SEL decoding.

use crate::connection::{Message, NetFn};

use super::OemCommand;

/// Query a Quanta BMC's platform ID with the QCT magic request prefix.
#[derive(Debug, Clone, Copy)]
pub struct GetPlatformId;

/// Known Quanta platform IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Grantley.
    Grantley,
    /// Purley.
    Purley,
}

/// The platform ID response was missing or not recognized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformError {
    /// The response was empty.
    TooShort,
    /// The BMC returned an unknown platform (including zero).
    Unsupported(u8),
}

impl OemCommand for GetPlatformId {
    type Output = Platform;
    type Error = PlatformError;
    const MANUFACTURER_ID: u32 = 7244;

    fn into_message(self) -> Message {
        Message::new_request(NetFn::Reserved(0x36), 0x65, vec![0x4C, 0x1C, 0, 2])
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        match data.first().ok_or(PlatformError::TooShort)? {
            1 => Ok(Platform::Grantley),
            2 => Ok(Platform::Purley),
            &id => Err(PlatformError::Unsupported(id)),
        }
    }
}
