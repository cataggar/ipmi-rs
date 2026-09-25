//! Quanta QCT platform discovery used by OEM memory SEL decoding.

use crate::connection::{Message, NetFn};
use crate::storage::sel::{Entry, SelEntryInfo};

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

/// Quanta Purley DIMM location from a sensor-specific memory SEL record.
///
/// Channels are zero-based (0 = A, 7 = H); the CPU and DIMM numbers are also
/// zero-based. This data is separate from the CLI's `CPU0_A0` presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryLocation {
    pub cpu: u8,
    pub channel: u8,
    pub dimm: u8,
}

impl MemoryLocation {
    /// Decode a Purley memory SEL record returned by `GetSelEntry`, after
    /// checking the target's identity and querying its platform with
    /// `Ipmi::send_oem(GetPlatformId)`.
    ///
    /// Grantley has no memory-location mapping in the ipmitool source.
    /// Standard SEL records do not carry a manufacturer ID; the caller must
    /// supply a platform obtained from the same Quanta device as the record.
    pub fn from_sel_entry(platform: Platform, info: &SelEntryInfo) -> Option<Self> {
        let Entry::System {
            sensor_type: 0x0C,
            event_type: 0x6F,
            ..
        } = &info.entry
        else {
            return None;
        };

        if platform != Platform::Purley {
            return None;
        }

        let location = info.raw[15];
        Some(Self {
            cpu: (location >> 6) & 0x03,
            channel: (location >> 3) & 0x07,
            dimm: location & 0x07,
        })
    }
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
