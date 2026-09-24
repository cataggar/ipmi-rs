use crate::connection::{IpmiCommand, Message, NetFn};

/// Read the host's chassis status without changing its power state.
///
/// IPMI 2.0, Get Chassis Status (Chassis netfn, command `0x01`).
#[derive(Clone, Copy, Debug, Default)]
pub struct GetChassisStatus;

impl From<GetChassisStatus> for Message {
    fn from(_: GetChassisStatus) -> Self {
        Message::new_request(NetFn::Chassis, 0x01, Vec::new())
    }
}

impl IpmiCommand for GetChassisStatus {
    type Output = ChassisStatus;
    type Error = ChassisStatusParseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        ChassisStatus::from_data(data)
    }
}

/// A successful Get Chassis Status response must contain at least three bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChassisStatusParseError {
    /// The response omitted one or more of the three required status bytes.
    ShortResponse {
        /// The number of status bytes actually received (excluding the completion code).
        actual: usize,
    },
}

/// Power restore policy reported by the chassis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerRestorePolicy {
    /// Always remain powered off after power is restored (`0b00`).
    AlwaysOff,
    /// Restore the power state prior to the outage (`0b01`).
    RestorePrevious,
    /// Always power on after power is restored (`0b10`).
    AlwaysOn,
    /// A reserved or unrecognized policy value, preserved as received.
    Unknown(u8),
}

impl From<u8> for PowerRestorePolicy {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::AlwaysOff,
            1 => Self::RestorePrevious,
            2 => Self::AlwaysOn,
            other => Self::Unknown(other),
        }
    }
}

/// Flags indicating why the most recent power change occurred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LastPowerEvent {
    /// AC power failed.
    pub ac_failed: bool,
    /// The power supply was overloaded.
    pub power_overload: bool,
    /// The power interlock was activated.
    pub power_interlock: bool,
    /// A power fault was detected.
    pub power_fault: bool,
    /// A power command was issued.
    pub power_command: bool,
}

/// Optional front-panel button capabilities and status (fourth status byte).
///
/// IPMI 2.0 Rev 1.1, §28.2: bits 7–4 indicate whether disabling each button
/// is allowed; bits 3–0 independently indicate whether each button is disabled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrontPanelButtons {
    /// Whether disabling the standby (sleep) button is allowed.
    pub sleep_button_disable_allowed: bool,
    /// Whether disabling the diagnostic interrupt button is allowed.
    pub diagnostic_button_disable_allowed: bool,
    /// Whether disabling the reset button is allowed.
    pub reset_button_disable_allowed: bool,
    /// Whether disabling the power off button is allowed.
    pub power_off_button_disable_allowed: bool,
    /// Whether the standby (sleep) button is currently disabled.
    pub sleep_button_disabled: bool,
    /// Whether the diagnostic interrupt button is currently disabled.
    pub diagnostic_button_disabled: bool,
    /// Whether the reset button is currently disabled.
    pub reset_button_disabled: bool,
    /// Whether the power off button is currently disabled.
    pub power_off_button_disabled: bool,
}

impl FrontPanelButtons {
    fn from_byte(value: u8) -> Self {
        Self {
            sleep_button_disable_allowed: value & 0x80 != 0,
            diagnostic_button_disable_allowed: value & 0x40 != 0,
            reset_button_disable_allowed: value & 0x20 != 0,
            power_off_button_disable_allowed: value & 0x10 != 0,
            sleep_button_disabled: value & 0x08 != 0,
            diagnostic_button_disabled: value & 0x04 != 0,
            reset_button_disabled: value & 0x02 != 0,
            power_off_button_disabled: value & 0x01 != 0,
        }
    }
}

/// Chassis status returned by the BMC; describes the host, not the BMC's own power.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChassisStatus {
    /// Whether host power is on.
    pub system_power_on: bool,
    /// Whether a power overload is detected.
    pub power_overload: bool,
    /// Whether the power interlock is active.
    pub power_interlock: bool,
    /// Whether the main power has a fault.
    pub main_power_fault: bool,
    /// Whether power control has a fault.
    pub power_control_fault: bool,
    /// The reported power restore policy; reserved values are retained.
    pub power_restore_policy: PowerRestorePolicy,
    /// Events that contributed to the last host power change.
    pub last_power_event: LastPowerEvent,
    /// Whether chassis intrusion is active.
    pub chassis_intrusion: bool,
    /// Whether front-panel lockout is active.
    pub front_panel_lockout: bool,
    /// Whether a drive fault is detected.
    pub drive_fault: bool,
    /// Whether a cooling or fan fault is detected.
    pub cooling_fan_fault: bool,
    /// Front-panel button information, if the BMC supplied a fourth byte.
    pub front_panel_buttons: Option<FrontPanelButtons>,
}

impl ChassisStatus {
    /// Parse response data without the completion code.
    ///
    /// At least three bytes are required; the fourth byte, when supplied,
    /// describes front-panel buttons. Extra trailing bytes are ignored.
    pub fn from_data(data: &[u8]) -> Result<Self, ChassisStatusParseError> {
        if data.len() < 3 {
            return Err(ChassisStatusParseError::ShortResponse { actual: data.len() });
        }

        let current = data[0];
        let last = data[1];
        let misc = data[2];

        Ok(Self {
            system_power_on: current & 0x01 != 0,
            power_overload: current & 0x02 != 0,
            power_interlock: current & 0x04 != 0,
            main_power_fault: current & 0x08 != 0,
            power_control_fault: current & 0x10 != 0,
            power_restore_policy: PowerRestorePolicy::from((current >> 5) & 0x03),
            last_power_event: LastPowerEvent {
                ac_failed: last & 0x01 != 0,
                power_overload: last & 0x02 != 0,
                power_interlock: last & 0x04 != 0,
                power_fault: last & 0x08 != 0,
                power_command: last & 0x10 != 0,
            },
            chassis_intrusion: misc & 0x01 != 0,
            front_panel_lockout: misc & 0x02 != 0,
            drive_fault: misc & 0x04 != 0,
            cooling_fan_fault: misc & 0x08 != 0,
            front_panel_buttons: data.get(3).copied().map(FrontPanelButtons::from_byte),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_request_has_no_body() {
        let request: Message = GetChassisStatus.into();
        assert_eq!(request.netfn_raw(), NetFn::Chassis.request_value());
        assert_eq!(request.cmd(), 0x01);
        assert_eq!(request.data(), []);
    }

    #[test]
    fn parses_minimum_status_and_restore_policies() {
        let policies = [
            PowerRestorePolicy::AlwaysOff,
            PowerRestorePolicy::RestorePrevious,
            PowerRestorePolicy::AlwaysOn,
            PowerRestorePolicy::Unknown(3),
        ];
        for (value, policy) in policies.into_iter().enumerate() {
            let status = ChassisStatus::from_data(&[(value as u8) << 5, 0, 0]).unwrap();
            assert_eq!(status.power_restore_policy, policy);
            assert!(!status.system_power_on);
            assert_eq!(status.front_panel_buttons, None);
        }
    }

    #[test]
    fn parses_all_status_and_event_flags() {
        let status = ChassisStatus::from_data(&[0x9f, 0xff, 0xff]).unwrap();
        assert!(status.system_power_on);
        assert!(status.power_overload);
        assert!(status.power_interlock);
        assert!(status.main_power_fault);
        assert!(status.power_control_fault);
        assert_eq!(status.power_restore_policy, PowerRestorePolicy::AlwaysOff);
        assert_eq!(
            status.last_power_event,
            LastPowerEvent {
                ac_failed: true,
                power_overload: true,
                power_interlock: true,
                power_fault: true,
                power_command: true,
            }
        );
        assert!(status.chassis_intrusion);
        assert!(status.front_panel_lockout);
        assert!(status.drive_fault);
        assert!(status.cooling_fan_fault);
    }

    #[test]
    fn parses_individual_flags_without_cross_talk() {
        for bit in 0..5 {
            let status = ChassisStatus::from_data(&[1 << bit, 1 << bit, 1 << bit]).unwrap();
            let current = [
                status.system_power_on,
                status.power_overload,
                status.power_interlock,
                status.main_power_fault,
                status.power_control_fault,
            ];
            let events = [
                status.last_power_event.ac_failed,
                status.last_power_event.power_overload,
                status.last_power_event.power_interlock,
                status.last_power_event.power_fault,
                status.last_power_event.power_command,
            ];
            for (index, active) in current.into_iter().enumerate() {
                assert_eq!(active, index == bit);
            }
            for (index, active) in events.into_iter().enumerate() {
                assert_eq!(active, index == bit);
            }
            let misc = [
                status.chassis_intrusion,
                status.front_panel_lockout,
                status.drive_fault,
                status.cooling_fan_fault,
            ];
            for (index, active) in misc.into_iter().enumerate() {
                assert_eq!(active, index == bit);
            }
        }
    }

    #[test]
    fn parses_optional_front_panel_flags_and_extra_data() {
        let buttons = ChassisStatus::from_data(&[0, 0, 0, 0xa5, 0xff])
            .unwrap()
            .front_panel_buttons
            .unwrap();
        assert!(buttons.sleep_button_disable_allowed);
        assert!(!buttons.diagnostic_button_disable_allowed);
        assert!(buttons.reset_button_disable_allowed);
        assert!(!buttons.power_off_button_disable_allowed);
        assert!(!buttons.sleep_button_disabled);
        assert!(buttons.diagnostic_button_disabled);
        assert!(!buttons.reset_button_disabled);
        assert!(buttons.power_off_button_disabled);

        let buttons = ChassisStatus::from_data(&[0, 0, 0, 0])
            .unwrap()
            .front_panel_buttons
            .unwrap();
        assert!(!buttons.power_off_button_disable_allowed);
        assert!(!buttons.power_off_button_disabled);
    }

    #[test]
    fn parses_each_front_panel_flag_independently() {
        for bit in 0..8 {
            let buttons = ChassisStatus::from_data(&[0, 0, 0, 1 << bit])
                .unwrap()
                .front_panel_buttons
                .unwrap();
            let flags = [
                buttons.power_off_button_disabled,
                buttons.reset_button_disabled,
                buttons.diagnostic_button_disabled,
                buttons.sleep_button_disabled,
                buttons.power_off_button_disable_allowed,
                buttons.reset_button_disable_allowed,
                buttons.diagnostic_button_disable_allowed,
                buttons.sleep_button_disable_allowed,
            ];
            for (index, active) in flags.into_iter().enumerate() {
                assert_eq!(active, index == bit);
            }
        }
    }

    #[test]
    fn rejects_each_short_response() {
        for actual in 0..3 {
            assert_eq!(
                ChassisStatus::from_data(&[0, 0][..actual]),
                Err(ChassisStatusParseError::ShortResponse { actual })
            );
        }
    }
}
