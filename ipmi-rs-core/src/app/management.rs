//! Read-only management-controller identity and self-test commands.

use core::fmt;

use crate::connection::{IpmiCommand, Message, NetFn};

/// Get Device GUID (App `0x37`).
#[derive(Clone, Copy, Debug)]
pub struct GetDeviceGuid;

impl From<GetDeviceGuid> for Message {
    fn from(_: GetDeviceGuid) -> Self {
        Message::new_request(NetFn::App, 0x37, vec![])
    }
}

impl IpmiCommand for GetDeviceGuid {
    type Output = DeviceGuid;
    type Error = ManagementResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let raw = data
            .try_into()
            .map_err(|_| ManagementResponseError::Length {
                expected: 16,
                actual: data.len(),
            })?;
        Ok(DeviceGuid { raw })
    }
}

/// A 16-byte GUID in **IPMI wire order** (IPMI 2.0 §20.8).
///
/// Unlike RFC 4122 or SMBIOS byte order, IPMI puts the 6-byte node first
/// (least-significant byte first), then clock sequence, time-high, time-mid,
/// and time-low, each least-significant byte first. Some nonconforming BMCs
/// use other layouts; `raw()` preserves their bytes without guessing a format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceGuid {
    raw: [u8; 16],
}

impl DeviceGuid {
    /// Exact bytes returned by the controller; no UUID-order auto-detection.
    pub fn raw(self) -> [u8; 16] {
        self.raw
    }

    /// Render assuming the specified IPMI layout, in conventional UUID notation.
    pub fn ipmi_uuid(self) -> String {
        let b = self.raw;
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            u16::from_le_bytes([b[10], b[11]]),
            u16::from_le_bytes([b[8], b[9]]),
            b[7],
            b[6],
            b[5],
            b[4],
            b[3],
            b[2],
            b[1],
            b[0],
        )
    }
}

/// Get Self Test Results (App `0x04`).
#[derive(Clone, Copy, Debug)]
pub struct GetSelfTestResults;

impl From<GetSelfTestResults> for Message {
    fn from(_: GetSelfTestResults) -> Self {
        Message::new_request(NetFn::App, 0x04, vec![])
    }
}

impl IpmiCommand for GetSelfTestResults {
    type Output = SelfTestResult;
    type Error = ManagementResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.len() != 2 {
            return Err(ManagementResponseError::Length {
                expected: 2,
                actual: data.len(),
            });
        }
        Ok(SelfTestResult {
            status: SelfTestStatus::from(data[0]),
            detail: data[1],
        })
    }
}

/// Malformed management-controller response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementResponseError {
    /// Expected and actual response length.
    Length { expected: usize, actual: usize },
}

/// First self-test byte. Unknown and OEM values are kept verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfTestStatus {
    /// Tests passed (`0x55`).
    Passed,
    /// Self-test not implemented (`0x56`).
    NotImplemented,
    /// A device is corrupted (`0x57`); detail is a diagnostic bitmask.
    DeviceCorrupted,
    /// Fatal error (`0x58`); detail is the failure code.
    FatalError,
    /// Self-test status not available (`0xff`).
    NotAvailable,
    /// Unknown, including device-specific values.
    Other(u8),
}

impl From<u8> for SelfTestStatus {
    fn from(value: u8) -> Self {
        match value {
            0x55 => Self::Passed,
            0x56 => Self::NotImplemented,
            0x57 => Self::DeviceCorrupted,
            0x58 => Self::FatalError,
            0xff => Self::NotAvailable,
            other => Self::Other(other),
        }
    }
}

/// Both self-test bytes, including the raw second-byte diagnostics/failure code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelfTestResult {
    /// Self-test status.
    pub status: SelfTestStatus,
    /// Diagnostic flags for `DeviceCorrupted`, failure code for `FatalError`,
    /// and controller-defined data for other statuses.
    pub detail: u8,
}

impl fmt::Display for DeviceGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.ipmi_uuid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_fixture_and_wire_order() {
        let request: Message = GetDeviceGuid.into();
        assert_eq!(
            (request.netfn_raw(), request.cmd(), request.data()),
            (6, 0x37, &[][..])
        );
        let raw = [
            0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xb2, 0xa1, 0xd4, 0xc3, 0xf6, 0xe5, 0x4a, 0x3b,
            0x2c, 0x1d,
        ];
        let guid = GetDeviceGuid::parse_success_response(&raw).unwrap();
        assert_eq!(guid.raw(), raw);
        assert_eq!(guid.ipmi_uuid(), "1d2c3b4a-e5f6-c3d4-a1b2-112233445566");
        for n in [0, 15, 17] {
            assert_eq!(
                GetDeviceGuid::parse_success_response(&vec![0; n]),
                Err(ManagementResponseError::Length {
                    expected: 16,
                    actual: n
                })
            );
        }
    }

    #[test]
    fn self_test_fixture_preserves_codes_and_diagnostics() {
        let request: Message = GetSelfTestResults.into();
        assert_eq!(
            (request.netfn_raw(), request.cmd(), request.data()),
            (6, 4, &[][..])
        );
        for (code, status) in [
            (0x55, SelfTestStatus::Passed),
            (0x56, SelfTestStatus::NotImplemented),
            (0x57, SelfTestStatus::DeviceCorrupted),
            (0x58, SelfTestStatus::FatalError),
            (0xff, SelfTestStatus::NotAvailable),
            (0x80, SelfTestStatus::Other(0x80)),
        ] {
            assert_eq!(
                GetSelfTestResults::parse_success_response(&[code, 0xa5]),
                Ok(SelfTestResult {
                    status,
                    detail: 0xa5
                })
            );
        }
        for n in [0, 1, 3] {
            assert_eq!(
                GetSelfTestResults::parse_success_response(&vec![0; n]),
                Err(ManagementResponseError::Length {
                    expected: 2,
                    actual: n
                })
            );
        }
    }
}
