use crate::connection::{IpmiCommand, Message, NetFn};

/// Warm-reset the BMC (App command `0x03`), not the host.
///
/// A transport timeout leaves the outcome unknown. Do not replay this command
/// automatically or infer success or failure from a temporarily unreachable BMC.
#[derive(Debug, Clone, Copy)]
pub struct WarmReset;

/// Cold-reset the BMC (App command `0x02`), not the host.
///
/// The controller may stop responding before it can acknowledge a cold reset.
/// A transport timeout leaves the outcome unknown; do not automatically retry.
#[derive(Debug, Clone, Copy)]
pub struct ColdReset;

/// A reset response unexpectedly contained data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnexpectedResetResponseLength(pub usize);

macro_rules! reset_command {
    ($command:ty, $code:expr) => {
        impl From<$command> for Message {
            fn from(_: $command) -> Self {
                Message::new_request(NetFn::App, $code, Vec::new())
            }
        }

        impl IpmiCommand for $command {
            type Output = ();
            type Error = UnexpectedResetResponseLength;

            fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
                if data.is_empty() {
                    Ok(())
                } else {
                    Err(UnexpectedResetResponseLength(data.len()))
                }
            }
        }
    };
}

reset_command!(WarmReset, 0x03);
reset_command!(ColdReset, 0x02);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_requests_and_responses() {
        for (message, command) in [
            (Message::from(WarmReset), 0x03),
            (Message::from(ColdReset), 0x02),
        ] {
            assert_eq!(message.netfn_raw(), 0x06);
            assert_eq!(message.cmd(), command);
            assert!(message.data().is_empty());
        }
        assert_eq!(WarmReset::parse_success_response(&[]), Ok(()));
        assert_eq!(ColdReset::parse_success_response(&[]), Ok(()));
        assert_eq!(
            WarmReset::parse_success_response(&[0x00]),
            Err(UnexpectedResetResponseLength(1))
        );
    }
}
