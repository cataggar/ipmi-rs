use std::convert::Infallible;

use crate::connection::{IpmiCommand, Message, NetFn};

/// An explicit action affecting the host's power, not the BMC's own state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerAction {
    /// Power down the host (`0x00`).
    Off,
    /// Power up the host (`0x01`).
    On,
    /// Power cycle the host (`0x02`).
    Cycle,
    /// Hard-reset the host (`0x03`); does not reset the BMC.
    HardReset,
}

impl PowerAction {
    /// The byte encoded in the Chassis Control request.
    pub const fn value(self) -> u8 {
        match self {
            Self::Off => 0x00,
            Self::On => 0x01,
            Self::Cycle => 0x02,
            Self::HardReset => 0x03,
        }
    }
}

/// Request a host power action (Chassis netfn, command `0x02`).
///
/// Constructing this command requires an explicit [`PowerAction`].
/// A missing response, timeout, or ambiguous failure does not prove that the
/// host was unaffected. Never automatically resend this command, including on
/// a "node busy" completion code. A later status read cannot establish
/// whether a cycle or reset occurred.
#[derive(Clone, Copy, Debug)]
pub struct ChassisControl {
    action: PowerAction,
}

impl ChassisControl {
    /// Create a chassis control command for the requested host power action.
    pub const fn new(action: PowerAction) -> Self {
        Self { action }
    }

    /// The requested host power action.
    pub const fn action(&self) -> PowerAction {
        self.action
    }
}

impl From<ChassisControl> for Message {
    fn from(command: ChassisControl) -> Self {
        Message::new_request(NetFn::Chassis, 0x02, vec![command.action.value()])
    }
}

impl IpmiCommand for ChassisControl {
    type Output = ();
    type Error = Infallible;

    fn parse_success_response(_: &[u8]) -> Result<Self::Output, Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_action_sends_exactly_one_byte() {
        let fixtures = [
            (PowerAction::Off, 0x00),
            (PowerAction::On, 0x01),
            (PowerAction::Cycle, 0x02),
            (PowerAction::HardReset, 0x03),
        ];
        for (action, expected) in fixtures {
            let command = ChassisControl::new(action);
            assert_eq!(command.action(), action);
            let request: Message = command.into();
            assert_eq!(request.netfn_raw(), NetFn::Chassis.request_value());
            assert_eq!(request.cmd(), 0x02);
            assert_eq!(request.data(), [expected]);
            assert_eq!(ChassisControl::parse_success_response(&[]), Ok(()));
        }
    }
}
