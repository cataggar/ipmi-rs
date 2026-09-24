//! Activate and deactivate the Serial-over-LAN payload (IPMI 2.0, table 24-2).

use crate::connection::{CompletionErrorCode, IpmiCommand, Message, NetFn};

/// SOL payload instance, 1 through 15.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolInstance(u8);

impl SolInstance {
    /// Construct a valid payload instance.
    pub fn new(value: u8) -> Option<Self> {
        (1..=15).contains(&value).then_some(Self(value))
    }

    /// Return the instance number.
    pub fn value(self) -> u8 {
        self.0
    }
}

/// Activate Payload response (the 12 bytes following completion code).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolActivation {
    /// Auxiliary response bytes.
    pub auxiliary: [u8; 4],
    /// BMC's maximum inbound SOL payload size, including four header bytes.
    pub max_input: u16,
    /// BMC's maximum outbound SOL payload size, including four header bytes.
    pub max_output: u16,
    /// UDP port on which SOL is available.
    pub port: u16,
    /// VLAN number; nonzero requires VLAN routing support.
    pub vlan: u16,
}

/// SOL activation/deactivation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolPayloadError {
    /// The activation response was not exactly 12 bytes.
    InvalidLength(usize),
    /// An invalid payload size or UDP port was negotiated.
    InvalidLimits,
    /// Another session has activated this payload.
    AlreadyActive,
    /// SOL is disabled.
    Disabled,
    /// Activation limit reached.
    LimitReached,
    /// Cannot activate with encryption.
    EncryptionUnavailable,
    /// Cannot activate without encryption.
    EncryptionRequired,
    /// Deactivation requested for an inactive payload.
    AlreadyInactive,
}

/// Activate SOL using both authentication and encryption. These cannot be disabled.
#[derive(Clone, Copy, Debug)]
pub struct ActivateSol {
    /// Payload instance to activate.
    pub instance: SolInstance,
}

impl From<ActivateSol> for Message {
    fn from(value: ActivateSol) -> Self {
        Message::new_request(
            NetFn::App,
            0x48,
            vec![1, value.instance.value(), 0xc6, 0, 0, 0],
        )
    }
}

impl IpmiCommand for ActivateSol {
    type Output = SolActivation;
    type Error = SolPayloadError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        match code {
            CompletionErrorCode::CommandSpecific(0x80) => Some(SolPayloadError::AlreadyActive),
            CompletionErrorCode::CommandSpecific(0x81) => Some(SolPayloadError::Disabled),
            CompletionErrorCode::CommandSpecific(0x82) => Some(SolPayloadError::LimitReached),
            CompletionErrorCode::CommandSpecific(0x83) => {
                Some(SolPayloadError::EncryptionUnavailable)
            }
            CompletionErrorCode::CommandSpecific(0x84) => Some(SolPayloadError::EncryptionRequired),
            _ => None,
        }
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let Ok(bytes): Result<&[u8; 12], _> = data.try_into() else {
            return Err(SolPayloadError::InvalidLength(data.len()));
        };
        let max_input = u16::from_le_bytes([bytes[4], bytes[5]]);
        let max_output = u16::from_le_bytes([bytes[6], bytes[7]]);
        let port = u16::from_le_bytes([bytes[8], bytes[9]]);
        if max_input <= 4 || max_output <= 4 || port == 0 {
            return Err(SolPayloadError::InvalidLimits);
        }
        Ok(SolActivation {
            auxiliary: bytes[..4].try_into().unwrap(),
            max_input,
            max_output,
            port,
            vlan: u16::from_le_bytes([bytes[10], bytes[11]]),
        })
    }
}

/// Deactivate SOL on the specified instance.
#[derive(Clone, Copy, Debug)]
pub struct DeactivateSol {
    /// Payload instance to deactivate.
    pub instance: SolInstance,
}

impl From<DeactivateSol> for Message {
    fn from(value: DeactivateSol) -> Self {
        Message::new_request(
            NetFn::App,
            0x49,
            vec![1, value.instance.value(), 0, 0, 0, 0],
        )
    }
}

impl IpmiCommand for DeactivateSol {
    type Output = ();
    type Error = SolPayloadError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        match code {
            CompletionErrorCode::CommandSpecific(0x80) => Some(SolPayloadError::AlreadyInactive),
            CompletionErrorCode::CommandSpecific(0x81) => Some(SolPayloadError::Disabled),
            _ => None,
        }
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(SolPayloadError::InvalidLength(data.len()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_and_deactivation_wires_and_limits() {
        assert!(SolInstance::new(0).is_none());
        assert!(SolInstance::new(16).is_none());
        let instance = SolInstance::new(15).unwrap();
        let command: Message = ActivateSol { instance }.into();
        assert_eq!(command.cmd(), 0x48);
        assert_eq!(command.data(), [1, 15, 0xc6, 0, 0, 0]);
        let command: Message = DeactivateSol { instance }.into();
        assert_eq!(command.cmd(), 0x49);
        assert_eq!(command.data(), [1, 15, 0, 0, 0, 0]);
        let data = [0, 0, 0, 0, 0x10, 0, 0x20, 0, 0x6f, 2, 0, 0];
        assert_eq!(
            ActivateSol::parse_success_response(&data).unwrap().port,
            623
        );
        for len in 0..12 {
            assert!(matches!(
                ActivateSol::parse_success_response(&data[..len]),
                Err(SolPayloadError::InvalidLength(_))
            ));
        }
        assert!(matches!(
            ActivateSol::handle_completion_code(CompletionErrorCode::CommandSpecific(0x83), &[]),
            Some(SolPayloadError::EncryptionUnavailable)
        ));
    }
}
