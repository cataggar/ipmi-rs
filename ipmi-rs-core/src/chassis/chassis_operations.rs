use crate::connection::{IpmiCommand, Message, NetFn};

/// A successful chassis response with an unexpected number of data bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChassisResponseLength {
    /// Expected response length, excluding the completion code.
    pub expected: usize,
    /// Actual response length, excluding the completion code.
    pub actual: usize,
}

fn check_length(data: &[u8], expected: usize) -> Result<(), ChassisResponseLength> {
    if data.len() == expected {
        Ok(())
    } else {
        Err(ChassisResponseLength {
            expected,
            actual: data.len(),
        })
    }
}

/// Explicit Set Chassis Identify behavior (Chassis command `0x04`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifyMode {
    /// Use the BMC default interval (typically 15 seconds); send no data bytes.
    Default,
    /// Identify for this many seconds; zero stops identification.
    ForSeconds(u8),
    /// Identify indefinitely, if the BMC supports the optional force byte.
    ForceOn,
}

/// Set the chassis identification indicator, without controlling host power.
///
/// Some BMCs reject `ForceOn` with an invalid-length completion code. Never
/// retry any of these mutations automatically if the response is lost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChassisIdentify {
    mode: IdentifyMode,
}

impl ChassisIdentify {
    /// Select an explicit identify mode.
    pub const fn new(mode: IdentifyMode) -> Self {
        Self { mode }
    }
}

impl From<ChassisIdentify> for Message {
    fn from(command: ChassisIdentify) -> Self {
        let data = match command.mode {
            IdentifyMode::Default => vec![],
            IdentifyMode::ForSeconds(interval) => vec![interval],
            IdentifyMode::ForceOn => vec![0, 1],
        };
        Message::new_request(NetFn::Chassis, 0x04, data)
    }
}

impl IpmiCommand for ChassisIdentify {
    type Output = ();
    type Error = ChassisResponseLength;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        check_length(data, 0)
    }
}

/// A policy to apply *after an AC power failure*, not a host power action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerRestorePolicySetting {
    /// Stay off when AC power returns.
    AlwaysOff,
    /// Restore the preceding power state.
    RestorePrevious,
    /// Power on when AC power returns.
    AlwaysOn,
}

impl PowerRestorePolicySetting {
    /// The policy code used by Set Power Restore Policy.
    pub const fn value(self) -> u8 {
        match self {
            Self::AlwaysOff => 0,
            Self::RestorePrevious => 1,
            Self::AlwaysOn => 2,
        }
    }
}

/// Supported restore policies returned by Chassis command `0x06`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupportedPowerRestorePolicies {
    /// Raw support bits, including any controller-specific bits.
    pub raw: u8,
}

impl SupportedPowerRestorePolicies {
    /// Whether the BMC reports support for this policy.
    pub const fn supports(self, policy: PowerRestorePolicySetting) -> bool {
        self.raw & (1 << policy.value()) != 0
    }
}

/// Query supported restore policies without changing the current policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GetPowerRestorePolicySupport;

/// Explicitly set the policy for the host after AC power is restored.
///
/// This does not power-cycle the host or change its current power state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetPowerRestorePolicy {
    policy: PowerRestorePolicySetting,
}

impl SetPowerRestorePolicy {
    /// Select one known policy; no "no change" value is accepted for a write.
    pub const fn new(policy: PowerRestorePolicySetting) -> Self {
        Self { policy }
    }
}

impl From<GetPowerRestorePolicySupport> for Message {
    fn from(_: GetPowerRestorePolicySupport) -> Self {
        Message::new_request(NetFn::Chassis, 0x06, vec![3])
    }
}

impl From<SetPowerRestorePolicy> for Message {
    fn from(command: SetPowerRestorePolicy) -> Self {
        Message::new_request(NetFn::Chassis, 0x06, vec![command.policy.value()])
    }
}

fn parse_supported_policies(
    data: &[u8],
) -> Result<SupportedPowerRestorePolicies, ChassisResponseLength> {
    check_length(data, 1)?;
    Ok(SupportedPowerRestorePolicies { raw: data[0] })
}

impl IpmiCommand for GetPowerRestorePolicySupport {
    type Output = SupportedPowerRestorePolicies;
    type Error = ChassisResponseLength;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        parse_supported_policies(data)
    }
}

impl IpmiCommand for SetPowerRestorePolicy {
    type Output = SupportedPowerRestorePolicies;
    type Error = ChassisResponseLength;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        parse_supported_policies(data)
    }
}

/// Standard reason codes in Get System Restart Cause (Chassis command `0x07`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartReason {
    Unknown,
    ChassisControl,
    ResetButton,
    PowerButton,
    Watchdog,
    Oem,
    AlwaysRestorePolicy,
    RestorePreviousPolicy,
    PefReset,
    PefPowerCycle,
    SoftReset,
    RtcWakeup,
    /// A reserved or controller-defined reason code.
    Other(u8),
}

impl From<u8> for RestartReason {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Unknown,
            1 => Self::ChassisControl,
            2 => Self::ResetButton,
            3 => Self::PowerButton,
            4 => Self::Watchdog,
            5 => Self::Oem,
            6 => Self::AlwaysRestorePolicy,
            7 => Self::RestorePreviousPolicy,
            8 => Self::PefReset,
            9 => Self::PefPowerCycle,
            10 => Self::SoftReset,
            11 => Self::RtcWakeup,
            other => Self::Other(other),
        }
    }
}

/// The complete two-byte restart cause response; reserved bits are retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartCause {
    /// Decoded low-nibble restart reason.
    pub reason: RestartReason,
    /// Unmodified cause byte (high nibble may be controller-defined).
    pub raw_cause: u8,
    /// Channel used for the restart request, as reported by the BMC.
    pub channel: u8,
}

/// Read the last host restart cause, without restarting the host.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GetSystemRestartCause;

impl From<GetSystemRestartCause> for Message {
    fn from(_: GetSystemRestartCause) -> Self {
        Message::new_request(NetFn::Chassis, 0x07, vec![])
    }
}

impl IpmiCommand for GetSystemRestartCause {
    type Output = RestartCause;
    type Error = ChassisResponseLength;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        check_length(data, 2)?;
        Ok(RestartCause {
            reason: RestartReason::from(data[0] & 0x0f),
            raw_cause: data[0],
            channel: data[1],
        })
    }
}

/// The five-byte Get POH Counter response (Chassis command `0x0f`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowerOnHours {
    /// Minutes represented by each count.
    pub minutes_per_count: u8,
    /// Unsigned counter in little-endian wire order.
    pub count: u32,
}

impl PowerOnHours {
    /// Total elapsed minutes; uses wide arithmetic to avoid overflow.
    pub const fn total_minutes(self) -> u64 {
        self.minutes_per_count as u64 * self.count as u64
    }
}

/// Read the host's power-on-hours counter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GetPowerOnHours;

impl From<GetPowerOnHours> for Message {
    fn from(_: GetPowerOnHours) -> Self {
        Message::new_request(NetFn::Chassis, 0x0f, vec![])
    }
}

impl IpmiCommand for GetPowerOnHours {
    type Output = PowerOnHours;
    type Error = ChassisResponseLength;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        check_length(data, 5)?;
        Ok(PowerOnHours {
            minutes_per_count: data[0],
            count: u32::from_le_bytes([data[1], data[2], data[3], data[4]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_modes_are_distinct_mutations() {
        for (mode, expected) in [
            (IdentifyMode::Default, vec![]),
            (IdentifyMode::ForSeconds(0), vec![0]),
            (IdentifyMode::ForSeconds(42), vec![42]),
            (IdentifyMode::ForceOn, vec![0, 1]),
        ] {
            let request = Message::from(ChassisIdentify::new(mode));
            assert_eq!(request.netfn_raw(), 0);
            assert_eq!(request.cmd(), 4);
            assert_eq!(request.data(), expected);
        }
        assert_eq!(ChassisIdentify::parse_success_response(&[]), Ok(()));
        assert_eq!(
            ChassisIdentify::parse_success_response(&[1]),
            Err(ChassisResponseLength {
                expected: 0,
                actual: 1
            })
        );
    }

    #[test]
    fn policy_query_and_each_explicit_write_use_one_byte() {
        let request = Message::from(GetPowerRestorePolicySupport);
        assert_eq!(
            (request.netfn_raw(), request.cmd(), request.data()),
            (0, 6, &[3][..])
        );
        for (policy, byte) in [
            (PowerRestorePolicySetting::AlwaysOff, 0),
            (PowerRestorePolicySetting::RestorePrevious, 1),
            (PowerRestorePolicySetting::AlwaysOn, 2),
        ] {
            let request = Message::from(SetPowerRestorePolicy::new(policy));
            assert_eq!(
                (request.netfn_raw(), request.cmd(), request.data()),
                (0, 6, &[byte][..])
            );
        }
        let policies = GetPowerRestorePolicySupport::parse_success_response(&[0x87]).unwrap();
        assert_eq!(policies.raw, 0x87);
        for policy in [
            PowerRestorePolicySetting::AlwaysOff,
            PowerRestorePolicySetting::RestorePrevious,
            PowerRestorePolicySetting::AlwaysOn,
        ] {
            assert!(policies.supports(policy));
        }
        assert_eq!(
            SetPowerRestorePolicy::parse_success_response(&[3]),
            Ok(SupportedPowerRestorePolicies { raw: 3 })
        );
        for data in [&[][..], &[0, 1][..]] {
            assert_eq!(
                SetPowerRestorePolicy::parse_success_response(data),
                Err(ChassisResponseLength {
                    expected: 1,
                    actual: data.len()
                })
            );
        }
    }

    #[test]
    fn restart_reason_and_poh_are_read_only_and_exact_length() {
        for (cmd, request) in [
            (7, Message::from(GetSystemRestartCause)),
            (15, Message::from(GetPowerOnHours)),
        ] {
            assert_eq!(request.netfn_raw(), 0);
            assert_eq!(request.cmd(), cmd);
            assert!(request.data().is_empty());
        }
        for code in 0..16 {
            let result =
                GetSystemRestartCause::parse_success_response(&[0xf0 | code, 0xa5]).unwrap();
            assert_eq!(result.raw_cause, 0xf0 | code);
            assert_eq!(result.channel, 0xa5);
            assert_eq!(result.reason, RestartReason::from(code));
        }
        let hours = GetPowerOnHours::parse_success_response(&[1, 0x40, 0xe2, 1, 0]).unwrap();
        assert_eq!(hours.count, 123456);
        assert_eq!(hours.total_minutes(), 123456);
        assert_eq!(
            PowerOnHours {
                minutes_per_count: 255,
                count: u32::MAX
            }
            .total_minutes(),
            u32::MAX as u64 * 255
        );
        for len in [0, 1, 3, 6] {
            assert_eq!(
                GetPowerOnHours::parse_success_response(&[0; 6][..len]),
                Err(ChassisResponseLength {
                    expected: 5,
                    actual: len
                })
            );
        }
        assert_eq!(
            GetSystemRestartCause::parse_success_response(&[1]),
            Err(ChassisResponseLength {
                expected: 2,
                actual: 1
            })
        );
    }
}
