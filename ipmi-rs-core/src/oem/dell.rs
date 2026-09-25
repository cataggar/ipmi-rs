//! Dell iDRAC power-cap queries (not power-cap mutations).

use crate::connection::{Message, NetFn, NotEnoughData};

use super::OemCommand;

/// Read whether the Dell power cap is enabled and may be set.
///
/// `ipmi_delloem.c` sends OEM NetFn `0x30`, command `0xBA` with `[1, 0xFF]`.
/// Some generations return a license or unsupported-command completion code.
#[derive(Debug, Clone, Copy)]
pub struct GetPowerCapStatus;

/// Power-cap bits from the first response byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerCapStatus {
    /// Whether the power cap is currently enabled.
    pub enabled: bool,
    /// Whether the BMC permits changing the power cap.
    pub can_set: bool,
}

impl OemCommand for GetPowerCapStatus {
    type Output = PowerCapStatus;
    type Error = NotEnoughData;
    const MANUFACTURER_ID: u32 = 674;

    fn into_message(self) -> Message {
        Message::new_request(NetFn::Reserved(0x30), 0xBA, vec![1, 0xFF])
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let flags = *data.first().ok_or(NotEnoughData)?;
        Ok(PowerCapStatus {
            enabled: flags & 0x01 != 0,
            can_set: flags & 0x02 != 0,
        })
    }
}
