//! Intel Node Manager OEM commands, explicitly enabled by the caller.
//!
//! NetFn 0x2e, Intel IANA 0x000157. No probing is performed automatically.
//! Obtain a [`NodeManager`] handle by explicitly opting in, or from a matching
//! `GetDeviceId` manufacturer ID. A non-Intel BMC may still forward NM requests
//! to an Intel management engine; opting in is the caller's responsibility.

use crate::{
    app::DeviceId,
    connection::{IpmiCommand, Message, NetFn},
};

const NETFN: NetFn = NetFn::Reserved(0x2e);
const IANA: [u8; 3] = [0x57, 0x01, 0x00];

fn request(command: u8, data: &[u8]) -> Message {
    let mut payload = IANA.to_vec();
    payload.extend_from_slice(data);
    Message::new_request(NETFN, command, payload)
}

fn checked(data: &[u8], len: usize) -> Result<(), NmError> {
    if data.len() != len {
        return Err(NmError::Length {
            expected: len,
            actual: data.len(),
        });
    }
    if data[..3] != IANA {
        return Err(NmError::Vendor([data[0], data[1], data[2]]));
    }
    Ok(())
}

fn ack(data: &[u8]) -> Result<NmMutation, NmError> {
    checked(data, 3)?;
    Ok(NmMutation::Acknowledged)
}

/// Invalid/unsupported OEM response or out-of-bounds write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NmError {
    /// Expected exact payload size.
    Length { expected: usize, actual: usize },
    /// Unexpected IANA enterprise ID.
    Vendor([u8; 3]),
    /// Unsupported Node Manager version.
    Version(u8),
    /// Invalid, reserved or unsupported value.
    Value(u8),
    /// Invalid bounds or inconsistent ranges.
    Bounds,
}

/// A successful OEM mutation response is only an acknowledgement, not a readback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NmMutation {
    /// Controller acknowledged this specific request.
    Acknowledged,
}

/// Token for sending Intel Node Manager OEM requests.
///
/// No network discovery is initiated by this token. Check `discover()` and
/// `capabilities()` explicitly before configuring policies, especially on
/// BMCs that proxy the commands to a separate management engine.
#[derive(Clone, Copy, Debug)]
pub struct NodeManager {
    _private: (),
}

impl NodeManager {
    /// Explicitly enable Intel OEM commands (including when the BMC is not Intel).
    pub fn opt_in() -> Self {
        Self { _private: () }
    }

    /// Permit probing only if `GetDeviceId` identified Intel's manufacturer ID.
    /// This does not imply that Node Manager is present or that the BMC is capable.
    pub fn from_device_id(id: &DeviceId) -> Option<Self> {
        (id.manufacturer_id == 0x000157).then(Self::opt_in)
    }

    /// Probe the Node Manager version (0xca).
    pub fn discover(self) -> Discover {
        Discover { _private: () }
    }

    /// Get capability bounds for a policy domain and trigger (0xc9).
    pub fn capabilities(
        self,
        domain: NmDomain,
        trigger: NmTrigger,
    ) -> Result<GetCapabilities, NmError> {
        trigger.value()?;
        Ok(GetCapabilities { domain, trigger })
    }

    /// Get a policy (0xc2).
    pub fn policy(self, domain: NmDomain, id: u8) -> GetPolicy {
        GetPolicy { domain, id }
    }

    /// Upsert a policy (0xc1), with all fields explicitly specified.
    pub fn set_policy(self, policy: PolicySettings) -> Result<SetPolicy, NmError> {
        policy.validate()?;
        Ok(SetPolicy {
            update: PolicyUpdate::Upsert(policy),
        })
    }

    /// Remove a policy (0xc1). Does not guess whether a previous request succeeded.
    pub fn remove_policy(self, domain: NmDomain, id: u8) -> SetPolicy {
        SetPolicy {
            update: PolicyUpdate::Remove { domain, id },
        }
    }

    /// Enable or disable policy control at a specified scope (0xc0).
    pub fn control(self, scope: ControlScope) -> ControlPolicy {
        ControlPolicy { scope }
    }

    /// Set platform power draw range in watts (0xcb).
    pub fn set_power_range(
        self,
        domain: NmDomain,
        minimum_watts: u16,
        maximum_watts: u16,
    ) -> Result<SetPowerRange, NmError> {
        if minimum_watts > maximum_watts {
            return Err(NmError::Bounds);
        }
        Ok(SetPowerRange {
            domain,
            minimum_watts,
            maximum_watts,
        })
    }

    /// Get NM alert destination (0xcf).
    pub fn alert(self) -> GetAlert {
        GetAlert { _private: () }
    }

    /// Configure NM alert destination (0xce).
    pub fn set_alert(self, alert: AlertDestination) -> Result<SetAlert, NmError> {
        if alert.channel > 0x0f || alert.string_selector > 0x7f {
            return Err(NmError::Bounds);
        }
        Ok(SetAlert { alert })
    }

    /// Get up to three alert thresholds (0xc4).
    pub fn thresholds(self, domain: NmDomain, id: u8) -> GetThresholds {
        GetThresholds { domain, id }
    }

    /// Replace zero to three alert thresholds (0xc3).
    pub fn set_thresholds(
        self,
        domain: NmDomain,
        id: u8,
        thresholds: &[u16],
    ) -> Result<SetThresholds, NmError> {
        if thresholds.len() > 3 {
            return Err(NmError::Bounds);
        }
        Ok(SetThresholds {
            domain,
            id,
            thresholds: thresholds.to_vec(),
        })
    }
}

/// A domain managed by Intel NM. Unknown domains cannot be used for writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NmDomain {
    /// Whole platform.
    Platform,
    /// CPUs.
    Cpu,
    /// Memory.
    Memory,
    /// Hardware protection.
    Protection,
    /// Input/output.
    Io,
}

impl NmDomain {
    /// NM domain selector.
    pub fn value(self) -> u8 {
        match self {
            Self::Platform => 0,
            Self::Cpu => 1,
            Self::Memory => 2,
            Self::Protection => 3,
            Self::Io => 4,
        }
    }

    fn from_value(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Platform),
            1 => Some(Self::Cpu),
            2 => Some(Self::Memory),
            3 => Some(Self::Protection),
            4 => Some(Self::Io),
            _ => None,
        }
    }
}

/// Policy trigger type, with unknown/extension values preserved on reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NmTrigger {
    /// No trigger; power policy limits measured in watts.
    Power,
    /// Inlet temperature measured in degrees Celsius.
    InletTemperature,
    /// Missing power reading timeout (tenths of seconds).
    MissingReading,
    /// Time since host reset (tenths of seconds).
    AfterReset,
    /// Boot-time policy.
    Boot,
    /// Reserved or OEM trigger code; cannot be written.
    Other(u8),
}

impl NmTrigger {
    fn value(self) -> Result<u8, NmError> {
        match self {
            Self::Power => Ok(0),
            Self::InletTemperature => Ok(1),
            Self::MissingReading => Ok(2),
            Self::AfterReset => Ok(3),
            Self::Boot => Ok(4),
            Self::Other(v) => Err(NmError::Value(v)),
        }
    }

    fn from_value(v: u8) -> Self {
        match v {
            0 => Self::Power,
            1 => Self::InletTemperature,
            2 => Self::MissingReading,
            3 => Self::AfterReset,
            4 => Self::Boot,
            _ => Self::Other(v),
        }
    }
}

/// Correction aggressiveness, preserving reserved code 3 on reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NmCorrection {
    /// Automatic.
    Automatic,
    /// Soft.
    Soft,
    /// Aggressive.
    Aggressive,
    /// Unknown correction code; cannot be written.
    Other(u8),
}

impl NmCorrection {
    fn value(self) -> Result<u8, NmError> {
        match self {
            Self::Automatic => Ok(0),
            Self::Soft => Ok(1),
            Self::Aggressive => Ok(2),
            Self::Other(v) => Err(NmError::Value(v)),
        }
    }

    fn from_value(v: u8) -> Self {
        match v {
            0 => Self::Automatic,
            1 => Self::Soft,
            2 => Self::Aggressive,
            _ => Self::Other(v),
        }
    }
}

/// Query Node Manager version (requires explicit `NodeManager` opt-in).
#[derive(Clone, Copy, Debug)]
pub struct Discover {
    _private: (),
}

impl From<Discover> for Message {
    fn from(_: Discover) -> Self {
        request(0xca, &[1, 0])
    }
}

/// NM version and firmware revision; unknown versions are rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version {
    /// NM version: 1=1.0, 2=1.5, 3=2.0, 4=2.5, 5=3.0.
    pub nm_version: u8,
    /// Reported IPMI version code.
    pub ipmi_version: u8,
    /// Patch revision.
    pub patch: u8,
    /// Major firmware revision.
    pub major: u8,
    /// Minor firmware revision (packed decimal).
    pub minor: u8,
}

impl IpmiCommand for Discover {
    type Output = Version;
    type Error = NmError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        checked(data, 8)?;
        if !(1..=5).contains(&data[3]) {
            return Err(NmError::Version(data[3]));
        }
        Ok(Version {
            nm_version: data[3],
            ipmi_version: data[4],
            patch: data[5],
            major: data[6],
            minor: data[7],
        })
    }
}

/// Get NM capabilities (0xc9).
#[derive(Clone, Copy, Debug)]
pub struct GetCapabilities {
    domain: NmDomain,
    trigger: NmTrigger,
}

impl From<GetCapabilities> for Message {
    fn from(value: GetCapabilities) -> Self {
        request(
            0xc9,
            &[value.domain.value(), value.trigger.value().unwrap() | 0x10],
        )
    }
}

/// Available policy ranges. Value units depend on the requested trigger:
/// power = watts, inlet = °C, missing reading/reset = tenths of seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// Maximum count of policies.
    pub max_policies: u8,
    /// Maximum limit in trigger units.
    pub max_value: u16,
    /// Minimum limit in trigger units.
    pub min_value: u16,
    /// Minimum correction interval, milliseconds.
    pub min_correction_ms: u32,
    /// Maximum correction interval, milliseconds.
    pub max_correction_ms: u32,
    /// Minimum statistics period, seconds.
    pub min_statistics_seconds: u16,
    /// Maximum statistics period, seconds.
    pub max_statistics_seconds: u16,
    /// Uninterpreted scope flags; domain is in low nibble.
    pub scope: u8,
}

impl IpmiCommand for GetCapabilities {
    type Output = Capabilities;
    type Error = NmError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        checked(data, 21)?;
        let caps = Capabilities {
            max_policies: data[3],
            max_value: u16::from_le_bytes([data[4], data[5]]),
            min_value: u16::from_le_bytes([data[6], data[7]]),
            min_correction_ms: u32::from_le_bytes(data[8..12].try_into().unwrap()),
            max_correction_ms: u32::from_le_bytes(data[12..16].try_into().unwrap()),
            min_statistics_seconds: u16::from_le_bytes([data[16], data[17]]),
            max_statistics_seconds: u16::from_le_bytes([data[18], data[19]]),
            scope: data[20],
        };
        if caps.min_value > caps.max_value
            || caps.min_correction_ms > caps.max_correction_ms
            || caps.min_statistics_seconds > caps.max_statistics_seconds
        {
            return Err(NmError::Bounds);
        }
        Ok(caps)
    }
}

/// Fully specified NM power policy; numeric bounds are controller-specific:
/// call `capabilities(domain, trigger)` to obtain the supported range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicySettings {
    /// Policy domain.
    pub domain: NmDomain,
    /// 0..=255 policy identifier.
    pub id: u8,
    /// Whether this policy is enabled.
    pub enabled: bool,
    /// Whether policy controls power.
    pub power_control: bool,
    /// Policy trigger.
    pub trigger: NmTrigger,
    /// Correction aggressiveness.
    pub correction: NmCorrection,
    /// True for volatile policy.
    pub volatile: bool,
    /// Request alert on policy exception.
    pub alert: bool,
    /// Request shutdown on policy exception.
    pub shutdown: bool,
    /// Power limit, watts; for boot-time policies this is a controller-specific core count.
    pub limit: u16,
    /// Correction interval in milliseconds.
    pub correction_ms: u32,
    /// Trigger limit (units determined by trigger).
    pub trigger_limit: u16,
    /// Statistics reporting period in seconds.
    pub statistics_seconds: u16,
}

impl PolicySettings {
    fn validate(self) -> Result<(), NmError> {
        self.trigger.value()?;
        self.correction.value()?;
        Ok(())
    }

    /// Validate controller-advertised limits before constructing an upsert.
    /// `GetCapabilities` must be requested for this policy's domain and
    /// trigger; the controller can still reject a stale capability snapshot.
    pub fn validate_against(&self, caps: &Capabilities) -> Result<(), NmError> {
        self.validate()?;
        let value = match self.trigger {
            NmTrigger::InletTemperature | NmTrigger::MissingReading | NmTrigger::AfterReset => {
                Some(self.trigger_limit)
            }
            NmTrigger::Power => Some(self.limit),
            NmTrigger::Boot | NmTrigger::Other(_) => None,
        };
        if value.is_some_and(|v| v < caps.min_value || v > caps.max_value)
            || self.correction_ms < caps.min_correction_ms
            || self.correction_ms > caps.max_correction_ms
            || self.statistics_seconds < caps.min_statistics_seconds
            || self.statistics_seconds > caps.max_statistics_seconds
        {
            return Err(NmError::Bounds);
        }
        Ok(())
    }
}

/// NM policy readback, including raw OEM/unknown flag bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Recognized low-nibble domain, if any.
    pub domain: Option<NmDomain>,
    /// Raw domain/enabled/status flags.
    pub domain_flags: u8,
    /// Known trigger or `Other` for OEM triggers.
    pub trigger: NmTrigger,
    /// Known correction mode or `Other`.
    pub correction: NmCorrection,
    /// Whether policy controls power.
    pub power_control: bool,
    /// Whether retention is volatile.
    pub volatile: bool,
    /// Raw exception flags (known: alert bit 0, shutdown bit 1).
    pub exception_flags: u8,
    /// Policy limit (watts or trigger-specific value).
    pub limit: u16,
    /// Correction interval in milliseconds.
    pub correction_ms: u32,
    /// Trigger limit in trigger-specific units.
    pub trigger_limit: u16,
    /// Statistics period in seconds.
    pub statistics_seconds: u16,
}

/// Get a policy (0xc2).
#[derive(Clone, Copy, Debug)]
pub struct GetPolicy {
    domain: NmDomain,
    id: u8,
}

impl From<GetPolicy> for Message {
    fn from(value: GetPolicy) -> Self {
        request(0xc2, &[value.domain.value(), value.id])
    }
}

impl IpmiCommand for GetPolicy {
    type Output = Policy;
    type Error = NmError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        checked(data, 16)?;
        Ok(Policy {
            domain: NmDomain::from_value(data[3] & 0x0f),
            domain_flags: data[3],
            trigger: NmTrigger::from_value(data[4] & 0x0f),
            correction: NmCorrection::from_value((data[4] >> 5) & 3),
            power_control: data[4] & 0x10 != 0,
            volatile: data[4] & 0x80 != 0,
            exception_flags: data[5],
            limit: u16::from_le_bytes([data[6], data[7]]),
            correction_ms: u32::from_le_bytes(data[8..12].try_into().unwrap()),
            trigger_limit: u16::from_le_bytes([data[12], data[13]]),
            statistics_seconds: u16::from_le_bytes([data[14], data[15]]),
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum PolicyUpdate {
    Upsert(PolicySettings),
    Remove { domain: NmDomain, id: u8 },
}

/// Set or remove one policy (0xc1). Never sent implicitly or retried.
#[derive(Clone, Copy, Debug)]
pub struct SetPolicy {
    update: PolicyUpdate,
}

impl From<SetPolicy> for Message {
    fn from(value: SetPolicy) -> Self {
        let (domain, id, policy_type, exception, limit, correction, trigger_limit, stats) =
            match value.update {
                PolicyUpdate::Upsert(p) => (
                    p.domain.value() | (u8::from(p.enabled) << 4),
                    p.id,
                    p.trigger.value().unwrap()
                        | (u8::from(p.power_control) << 4)
                        | (p.correction.value().unwrap() << 5)
                        | (u8::from(p.volatile) << 7),
                    u8::from(p.alert) | (u8::from(p.shutdown) << 1),
                    p.limit,
                    p.correction_ms,
                    p.trigger_limit,
                    p.statistics_seconds,
                ),
                PolicyUpdate::Remove { domain, id } => (domain.value(), id, 0, 0, 0, 0, 0, 0),
            };
        let mut body = vec![domain, id, policy_type, exception];
        body.extend_from_slice(&limit.to_le_bytes());
        body.extend_from_slice(&correction.to_le_bytes());
        body.extend_from_slice(&trigger_limit.to_le_bytes());
        body.extend_from_slice(&stats.to_le_bytes());
        request(0xc1, &body)
    }
}

impl IpmiCommand for SetPolicy {
    type Output = NmMutation;
    type Error = NmError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        ack(data)
    }
}

/// Policy control target and new state (0xc0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlScope {
    /// Enable/disable NM globally.
    Global(bool),
    /// Enable/disable a domain.
    Domain(NmDomain, bool),
    /// Enable/disable one policy.
    Policy(NmDomain, u8, bool),
}

/// Enable or disable NM policy control.
#[derive(Clone, Copy, Debug)]
pub struct ControlPolicy {
    scope: ControlScope,
}

impl From<ControlPolicy> for Message {
    fn from(value: ControlPolicy) -> Self {
        let (scope, domain, id, enabled) = match value.scope {
            ControlScope::Global(on) => (0, 0, 0, on),
            ControlScope::Domain(d, on) => (2, d.value(), 0, on),
            ControlScope::Policy(d, id, on) => (4, d.value(), id, on),
        };
        request(0xc0, &[scope | u8::from(enabled), domain, id])
    }
}

impl IpmiCommand for ControlPolicy {
    type Output = NmMutation;
    type Error = NmError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        ack(data)
    }
}

/// Set the permitted power range for a domain (0xcb).
#[derive(Clone, Copy, Debug)]
pub struct SetPowerRange {
    domain: NmDomain,
    minimum_watts: u16,
    maximum_watts: u16,
}

impl From<SetPowerRange> for Message {
    fn from(value: SetPowerRange) -> Self {
        let mut body = vec![value.domain.value()];
        body.extend_from_slice(&value.minimum_watts.to_le_bytes());
        body.extend_from_slice(&value.maximum_watts.to_le_bytes());
        request(0xcb, &body)
    }
}

impl IpmiCommand for SetPowerRange {
    type Output = NmMutation;
    type Error = NmError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        ack(data)
    }
}

/// NM alert receiver and LAN destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlertDestination {
    /// BMC channel, 0..=15.
    pub channel: u8,
    /// If false, unregister the alert receiver.
    pub registered: bool,
    /// LAN destination number.
    pub destination: u8,
    /// If true, select an alert string.
    pub use_string: bool,
    /// Alert string number, 0..=127.
    pub string_selector: u8,
}

/// Get alert destination (0xcf).
#[derive(Clone, Copy, Debug)]
pub struct GetAlert {
    _private: (),
}

impl From<GetAlert> for Message {
    fn from(_: GetAlert) -> Self {
        request(0xcf, &[])
    }
}

impl IpmiCommand for GetAlert {
    type Output = AlertDestination;
    type Error = NmError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        checked(data, 6)?;
        if data[3] & 0x70 != 0 {
            return Err(NmError::Value(data[3]));
        }
        Ok(AlertDestination {
            channel: data[3] & 0x0f,
            registered: data[3] & 0x80 == 0,
            destination: data[4],
            use_string: data[5] & 0x80 != 0,
            string_selector: data[5] & 0x7f,
        })
    }
}

/// Set or clear alert receiver (0xce).
#[derive(Clone, Copy, Debug)]
pub struct SetAlert {
    alert: AlertDestination,
}

impl From<SetAlert> for Message {
    fn from(value: SetAlert) -> Self {
        let a = value.alert;
        request(
            0xce,
            &[
                a.channel | (u8::from(!a.registered) << 7),
                a.destination,
                a.string_selector | (u8::from(a.use_string) << 7),
            ],
        )
    }
}

impl IpmiCommand for SetAlert {
    type Output = NmMutation;
    type Error = NmError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        ack(data)
    }
}

/// Get alert threshold list (0xc4).
#[derive(Clone, Copy, Debug)]
pub struct GetThresholds {
    domain: NmDomain,
    id: u8,
}

impl From<GetThresholds> for Message {
    fn from(value: GetThresholds) -> Self {
        request(0xc4, &[value.domain.value(), value.id])
    }
}

impl IpmiCommand for GetThresholds {
    type Output = Vec<u16>;
    type Error = NmError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.len() < 4 {
            return Err(NmError::Length {
                expected: 4,
                actual: data.len(),
            });
        }
        let count = usize::from(data[3]);
        if count > 3 {
            return Err(NmError::Bounds);
        }
        checked(data, 4 + count * 2)?;
        Ok(data[4..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect())
    }
}

/// Replace all alert thresholds (0xc3), up to three. Values are in the
/// corresponding policy's trigger units: watts, °C, or tenths of seconds.
#[derive(Clone, Debug)]
pub struct SetThresholds {
    domain: NmDomain,
    id: u8,
    thresholds: Vec<u16>,
}

impl From<SetThresholds> for Message {
    fn from(value: SetThresholds) -> Self {
        let mut body = vec![value.domain.value(), value.id, value.thresholds.len() as u8];
        for threshold in value.thresholds {
            body.extend_from_slice(&threshold.to_le_bytes());
        }
        request(0xc3, &body)
    }
}

impl IpmiCommand for SetThresholds {
    type Output = NmMutation;
    type Error = NmError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        ack(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(command: impl Into<Message>, code: u8, body: &[u8]) {
        let message = command.into();
        assert_eq!(message.netfn_raw(), 0x2e);
        assert_eq!(message.cmd(), code);
        assert_eq!(
            message.data(),
            IANA.iter().chain(body).copied().collect::<Vec<_>>()
        );
    }

    #[test]
    fn discovery_is_opt_in_and_validates_version_and_vendor() {
        let mut device = DeviceId::from_data(&[1, 1, 1, 0, 0x51, 0, 0x57, 1, 0, 1, 0]).unwrap();
        assert!(NodeManager::from_device_id(&device).is_some());
        device.manufacturer_id = 0x4242;
        assert!(NodeManager::from_device_id(&device).is_none());
        let nm = NodeManager::opt_in();
        wire(nm.discover(), 0xca, &[1, 0]);
        assert_eq!(
            Discover::parse_success_response(&[0x57, 1, 0, 3, 0x20, 5, 2, 0x14])
                .unwrap()
                .nm_version,
            3
        );
        assert_eq!(
            Discover::parse_success_response(&[0x57, 1, 0, 6, 0x20, 5, 2, 0x14]),
            Err(NmError::Version(6))
        );
        assert_eq!(
            Discover::parse_success_response(&[0xdc, 1, 0, 3, 0, 0, 0, 0]),
            Err(NmError::Vendor([0xdc, 1, 0]))
        );
        assert!(matches!(
            Discover::parse_success_response(&[0x57]),
            Err(NmError::Length { .. })
        ));
    }

    #[test]
    fn capability_fixture_bounds_and_unrecognized_triggers() {
        let nm = NodeManager::opt_in();
        wire(
            nm.capabilities(NmDomain::Cpu, NmTrigger::InletTemperature)
                .unwrap(),
            0xc9,
            &[1, 0x11],
        );
        assert!(matches!(
            nm.capabilities(NmDomain::Cpu, NmTrigger::Other(0xf)),
            Err(NmError::Value(0xf))
        ));
        let caps = GetCapabilities::parse_success_response(&[
            0x57, 1, 0, 4, 0xf4, 1, 10, 0, 0xe8, 3, 0, 0, 0xd0, 7, 0, 0, 1, 0, 60, 0, 0x81,
        ])
        .unwrap();
        assert_eq!(caps.max_value, 500);
        assert_eq!(caps.min_correction_ms, 1000);
        assert_eq!(caps.max_correction_ms, 2000);
        assert_eq!(caps.scope, 0x81);
        let mut invalid = [
            0x57, 1, 0, 4, 0xf4, 1, 10, 0, 0xe8, 3, 0, 0, 0xd0, 7, 0, 0, 1, 0, 60, 0, 0x81,
        ];
        invalid[6] = 0xff;
        invalid[7] = 0xff;
        assert_eq!(
            GetCapabilities::parse_success_response(&invalid),
            Err(NmError::Bounds)
        );
        assert!(matches!(
            GetCapabilities::parse_success_response(&[0x57, 1, 0, 0]),
            Err(NmError::Length { .. })
        ));
    }

    fn policy() -> PolicySettings {
        PolicySettings {
            domain: NmDomain::Platform,
            id: 9,
            enabled: true,
            power_control: true,
            trigger: NmTrigger::Power,
            correction: NmCorrection::Soft,
            volatile: false,
            alert: true,
            shutdown: false,
            limit: 300,
            correction_ms: 5000,
            trigger_limit: 10,
            statistics_seconds: 60,
        }
    }

    #[test]
    fn policy_wire_uses_little_endian_preserves_oem_flags_and_bounds() {
        let nm = NodeManager::opt_in();
        wire(nm.policy(NmDomain::Platform, 9), 0xc2, &[0, 9]);
        wire(
            nm.set_policy(policy()).unwrap(),
            0xc1,
            &[0x10, 9, 0x30, 1, 0x2c, 1, 0x88, 0x13, 0, 0, 10, 0, 60, 0],
        );
        wire(
            nm.remove_policy(NmDomain::Cpu, 1),
            0xc1,
            &[1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        let raw = [
            0x57, 1, 0, 0x80, 0xd5, 0x81, 0x2c, 1, 0x88, 0x13, 0, 0, 10, 0, 60, 0,
        ];
        let got = GetPolicy::parse_success_response(&raw).unwrap();
        assert_eq!(got.domain, Some(NmDomain::Platform));
        assert_eq!(got.domain_flags, 0x80);
        assert_eq!(got.trigger, NmTrigger::Other(5));
        assert_eq!(got.correction, NmCorrection::Aggressive);
        assert_eq!(got.exception_flags, 0x81);
        assert_eq!(got.limit, 300);
        assert_eq!(got.correction_ms, 5000);
        assert!(got.volatile);
        assert!(matches!(
            GetPolicy::parse_success_response(&raw[..15]),
            Err(NmError::Length { .. })
        ));
        // A zero limit has controller-dependent meaning; advertised bounds
        // are the only authority, not a guessed global minimum.
        assert!(nm
            .set_policy(PolicySettings {
                limit: 0,
                ..policy()
            })
            .is_ok());
        assert!(matches!(
            nm.set_policy(PolicySettings {
                trigger: NmTrigger::Other(8),
                ..policy()
            }),
            Err(NmError::Value(8))
        ));
        let mut inlet = PolicySettings {
            trigger: NmTrigger::InletTemperature,
            limit: 0,
            trigger_limit: 35,
            ..policy()
        };
        assert!(nm.set_policy(inlet).is_ok());
        let caps = Capabilities {
            max_policies: 4,
            min_value: 20,
            max_value: 45,
            min_correction_ms: 1000,
            max_correction_ms: 10_000,
            min_statistics_seconds: 30,
            max_statistics_seconds: 120,
            scope: 0,
        };
        assert_eq!(inlet.validate_against(&caps), Ok(()));
        inlet.trigger_limit = 46;
        assert_eq!(inlet.validate_against(&caps), Err(NmError::Bounds));
    }

    #[test]
    fn alert_threshold_control_and_range_fixtures_reject_overflow() {
        let nm = NodeManager::opt_in();
        wire(nm.alert(), 0xcf, &[]);
        let alert = GetAlert::parse_success_response(&[0x57, 1, 0, 0x82, 0x22, 0x81]).unwrap();
        assert_eq!(alert.channel, 2);
        assert!(!alert.registered);
        assert_eq!(alert.string_selector, 1);
        wire(nm.set_alert(alert).unwrap(), 0xce, &[0x82, 0x22, 0x81]);
        assert!(matches!(
            nm.set_alert(AlertDestination {
                channel: 16,
                ..alert
            }),
            Err(NmError::Bounds)
        ));
        assert_eq!(
            GetAlert::parse_success_response(&[0x57, 1, 0, 0x70, 0, 0]),
            Err(NmError::Value(0x70))
        );
        wire(nm.thresholds(NmDomain::Memory, 7), 0xc4, &[2, 7]);
        wire(
            nm.set_thresholds(NmDomain::Memory, 7, &[200, 250, 300])
                .unwrap(),
            0xc3,
            &[2, 7, 3, 200, 0, 250, 0, 44, 1],
        );
        assert_eq!(
            GetThresholds::parse_success_response(&[0x57, 1, 0, 3, 200, 0, 250, 0, 44, 1]),
            Ok(vec![200, 250, 300])
        );
        assert_eq!(
            GetThresholds::parse_success_response(&[0x57, 1, 0, 4]),
            Err(NmError::Bounds)
        );
        assert!(matches!(
            GetThresholds::parse_success_response(&[0x57, 1, 0, 2, 200, 0]),
            Err(NmError::Length { .. })
        ));
        assert!(matches!(
            nm.set_thresholds(NmDomain::Platform, 1, &[1, 2, 3, 4]),
            Err(NmError::Bounds)
        ));
        wire(nm.control(ControlScope::Global(true)), 0xc0, &[1, 0, 0]);
        wire(
            nm.control(ControlScope::Policy(NmDomain::Cpu, 9, false)),
            0xc0,
            &[4, 1, 9],
        );
        wire(
            nm.set_power_range(NmDomain::Platform, 100, 500).unwrap(),
            0xcb,
            &[0, 100, 0, 244, 1],
        );
        assert!(matches!(
            nm.set_power_range(NmDomain::Platform, 501, 500),
            Err(NmError::Bounds)
        ));
        assert_eq!(
            SetThresholds::parse_success_response(&[0x57, 1, 0]),
            Ok(NmMutation::Acknowledged)
        );
        assert_eq!(
            SetThresholds::parse_success_response(&[0x57, 1, 0, 0]),
            Err(NmError::Length {
                expected: 3,
                actual: 4
            })
        );
    }
}
