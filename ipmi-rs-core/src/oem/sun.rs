//! Sun/Oracle ILOM version discovery.

use crate::connection::{Message, NetFn};

use super::OemCommand;

/// Query the Sun service processor's ILOM version.
///
/// The response is based on `sunoem_version_response_t` in `ipmi_sunoem.c`.
#[derive(Debug, Clone, Copy)]
pub struct GetVersion;

/// Parsed ILOM version fields and NUL-terminated display string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// Major version.
    pub major: u8,
    /// Minor version.
    pub minor: u8,
    /// Update version.
    pub update: u8,
    /// Micro version.
    pub micro: u8,
    /// The firmware's human-readable version string.
    pub text: String,
}

/// The ILOM version reply is truncated or contains invalid UTF-8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionError {
    /// A version reply shorter than the 65-byte prefix.
    TooShort(usize),
    /// Invalid UTF-8 in the version string.
    InvalidText,
}

impl OemCommand for GetVersion {
    type Output = Version;
    type Error = VersionError;
    const MANUFACTURER_ID: u32 = 42;

    fn into_message(self) -> Message {
        Message::new_request(NetFn::Reserved(0x2E), 0x24, Vec::new())
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let bytes = data.get(25..65).ok_or(VersionError::TooShort(data.len()))?;
        let end = bytes
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(bytes.len());
        let text = std::str::from_utf8(&bytes[..end])
            .map_err(|_| VersionError::InvalidText)?
            .to_owned();
        Ok(Version {
            major: data[1],
            minor: data[2],
            update: data[3],
            micro: data[4],
            text,
        })
    }
}
