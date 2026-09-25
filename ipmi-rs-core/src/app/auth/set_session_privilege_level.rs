use crate::connection::{IpmiCommand, Message, NetFn};

use super::PrivilegeLevel;

/// Set the active privilege on an authenticated IPMI 1.5 session (App 0x3B).
///
/// The maximum privilege returned by Activate Session is only a ceiling;
/// it does not change the active level.
#[derive(Clone, Copy, Debug)]
pub struct SetSessionPrivilegeLevel {
    /// Privilege to make active for this session.
    pub privilege: PrivilegeLevel,
}

/// Invalid Set Session Privilege Level response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetSessionPrivilegeError {
    /// A successful response must contain exactly one byte.
    InvalidLength(usize),
    /// The returned privilege is reserved, invalid, or has nonzero reserved bits.
    InvalidPrivilege(u8),
}

impl From<SetSessionPrivilegeLevel> for Message {
    fn from(command: SetSessionPrivilegeLevel) -> Self {
        Message::new_request(NetFn::App, 0x3b, vec![command.privilege.into()])
    }
}

impl IpmiCommand for SetSessionPrivilegeLevel {
    type Output = PrivilegeLevel;
    type Error = SetSessionPrivilegeError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let [value] = data else {
            return Err(SetSessionPrivilegeError::InvalidLength(data.len()));
        };
        if value & 0xf0 != 0 {
            return Err(SetSessionPrivilegeError::InvalidPrivilege(*value));
        }
        PrivilegeLevel::try_from(*value)
            .map_err(|_| SetSessionPrivilegeError::InvalidPrivilege(*value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_command_and_echoed_active_level() {
        let request: Message = SetSessionPrivilegeLevel {
            privilege: PrivilegeLevel::Administrator,
        }
        .into();
        assert_eq!(request.netfn_raw(), 0x06);
        assert_eq!(request.cmd(), 0x3b);
        assert_eq!(request.data(), [4]);
        assert_eq!(
            SetSessionPrivilegeLevel::parse_success_response(&[4]),
            Ok(PrivilegeLevel::Administrator)
        );
        assert_eq!(
            SetSessionPrivilegeLevel::parse_success_response(&[2]),
            Ok(PrivilegeLevel::User)
        );
        for invalid in [&[][..], &[4, 4], &[0], &[6], &[0x84]] {
            assert!(SetSessionPrivilegeLevel::parse_success_response(invalid).is_err());
        }
    }
}
