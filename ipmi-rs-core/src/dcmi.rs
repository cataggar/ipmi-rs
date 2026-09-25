//! Data Center Management Interface (DCMI) group-extension commands.
//!
//! Requests use NetFn 0x2c and group ID 0xdc. No command is sent during
//! discovery or construction; callers explicitly issue each command.
//! Mutations are single requests: a lost response means the outcome is unknown.

use crate::connection::{IpmiCommand, Message, NetFn};

const NETFN: NetFn = NetFn::Reserved(0x2c);
const GROUP: u8 = 0xdc;
const STRING_CHUNK: usize = 16;
const MAX_STRING: usize = 64;
const MAX_CAPABILITY_BYTES: usize = 40;

fn request(command: u8, payload: &[u8]) -> Message {
    let mut data = vec![GROUP];
    data.extend_from_slice(payload);
    Message::new_request(NETFN, command, data)
}

/// Malformed or unsupported DCMI response, or an invalid outgoing value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DcmiError {
    /// Incorrect response length (including truncated and oversized replies).
    Length { expected: usize, actual: usize },
    /// Unexpected group extension ID.
    Group(u8),
    /// Conformance code not defined for DCMI 1.0, 1.1, or 1.5.
    Conformance(u16),
    /// Capability or configuration revision that cannot safely be decoded.
    Revision(u8),
    /// Out-of-range field in the response or request.
    Value(u8),
    /// String or page would exceed the protocol bound.
    Bounds,
    /// Controller returned an inconsistent or non-progressing page.
    Page,
    /// Reserved nonzero wire fields must not be treated as standard fields.
    Reserved,
    /// The DCMI Get Power Limit completion code 0x80 carries an inactive limit.
    InactiveLimit(PowerLimit),
}

fn exact(data: &[u8], len: usize) -> Result<(), DcmiError> {
    if data.len() == len {
        Ok(())
    } else {
        Err(DcmiError::Length {
            expected: len,
            actual: data.len(),
        })
    }
}

fn checked(data: &[u8], len: usize) -> Result<(), DcmiError> {
    if data.len() < len {
        return Err(DcmiError::Length {
            expected: len,
            actual: data.len(),
        });
    }
    if data[0] != GROUP {
        return Err(DcmiError::Group(data[0]));
    }
    Ok(())
}

fn ack(data: &[u8]) -> Result<MutationOutcome, DcmiError> {
    checked(data, 1)?;
    exact(data, 1)?;
    Ok(MutationOutcome::Acknowledged)
}

/// Acknowledgement from the controller, not proof of persistent application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationOutcome {
    /// A matching success response was received.
    Acknowledged,
}

/// DCMI capability page selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilitySelector {
    /// Mandatory/optional platform and manageability capabilities.
    Platform,
    /// SEL, identification and temperature attributes.
    MandatoryAttributes,
    /// Power management device address and channel.
    OptionalAttributes,
    /// Manageability access channels.
    ManagementAccess,
}

impl CapabilitySelector {
    fn value(self) -> u8 {
        match self {
            Self::Platform => 1,
            Self::MandatoryAttributes => 2,
            Self::OptionalAttributes => 3,
            Self::ManagementAccess => 4,
        }
    }

    fn data_len(self) -> usize {
        match self {
            Self::Platform | Self::ManagementAccess => 3,
            Self::MandatoryAttributes => 4,
            Self::OptionalAttributes => 2,
        }
    }
}

/// Get DCMI Capabilities (0x01); an unsupported controller returns a completion error.
#[derive(Clone, Copy, Debug)]
pub struct GetCapabilities(pub CapabilitySelector);

impl From<GetCapabilities> for Message {
    fn from(value: GetCapabilities) -> Self {
        request(0x01, &[value.0.value()])
    }
}

/// A capability page: standard and trailing OEM data remain raw until the
/// original request's selector is supplied to [`CapabilityPage::decode`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityPage {
    /// DCMI conformance code, 0x0001 / 0x0101 / 0x0501 (1.0 / 1.1 / 1.5).
    pub conformance: u16,
    /// Known capability revision, 1 or 2.
    pub revision: u8,
    /// Selector-specific bytes (2–4 standard bytes, possibly followed by OEM data).
    pub data: Vec<u8>,
}

impl CapabilityPage {
    fn standard_data(&self, selector: CapabilitySelector) -> Result<&[u8], DcmiError> {
        let len = selector.data_len();
        if self.data.len() < len {
            return Err(DcmiError::Length {
                expected: 4 + len,
                actual: 4 + self.data.len(),
            });
        }
        Ok(&self.data[..len])
    }

    /// Trailing OEM/future bytes after the requested selector's standard fields.
    pub fn extension(&self, selector: CapabilitySelector) -> Result<&[u8], DcmiError> {
        self.standard_data(selector)?;
        Ok(&self.data[selector.data_len()..])
    }

    /// Interpret the page only if it was requested with `Platform`.
    pub fn platform(
        &self,
        selector: CapabilitySelector,
    ) -> Result<Option<PlatformCapabilities>, DcmiError> {
        if selector != CapabilitySelector::Platform {
            return Ok(None);
        }
        match self.decode(selector)? {
            CapabilityDetails::Platform(platform) => Ok(Some(platform)),
            _ => unreachable!(),
        }
    }

    /// Decode the explicitly requested selector. Raw bytes always remain
    /// available; unrecognized bits and trailing OEM data are not discarded.
    pub fn decode(&self, selector: CapabilitySelector) -> Result<CapabilityDetails, DcmiError> {
        let data = self.standard_data(selector)?;
        Ok(match selector {
            CapabilitySelector::Platform => CapabilityDetails::Platform(PlatformCapabilities {
                identification: data[0] & 1 != 0,
                sel: data[0] & 2 != 0,
                chassis_power: data[0] & 4 != 0,
                temperature: data[0] & 8 != 0,
                power_management: data[1] & 1 != 0,
                unknown_mandatory: data[0] & !0x0f,
                unknown_optional: data[1] & !1,
                management_access: data[2],
            }),
            CapabilitySelector::MandatoryAttributes => {
                let sel_flags = u16::from_le_bytes([data[0], data[1]]);
                CapabilityDetails::Mandatory(MandatoryAttributes {
                    sel_entries: sel_flags & 0x0fff,
                    sel_rollover: data[1] & 0x80 != 0,
                    reserved_sel_flags: sel_flags & 0x7000,
                    identification_flags: data[2],
                    temperature_flags: data[3],
                })
            }
            CapabilitySelector::OptionalAttributes => {
                CapabilityDetails::Optional(OptionalAttributes {
                    power_device_address: data[0],
                    channel: data[1] >> 4,
                    device_revision: data[1] & 0x0f,
                })
            }
            CapabilitySelector::ManagementAccess => {
                CapabilityDetails::Management(ManagementAccess {
                    primary_lan: (data[0] != 0xff).then_some(data[0]),
                    secondary_lan: (data[1] != 0xff).then_some(data[1]),
                    serial: (data[2] != 0xff).then_some(data[2]),
                })
            }
        })
    }
}

/// Typed interpretation of one requested DCMI capability selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityDetails {
    /// Platform feature bits.
    Platform(PlatformCapabilities),
    /// Mandatory platform attributes.
    Mandatory(MandatoryAttributes),
    /// Optional power device attributes.
    Optional(OptionalAttributes),
    /// OOB and serial channels.
    Management(ManagementAccess),
}

/// Mandatory attributes; bit flags for identification and temperature
/// include reserved/OEM bits and must be masked by the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MandatoryAttributes {
    /// Number of SEL entries (lower 12 bits).
    pub sel_entries: u16,
    /// SEL rollover supported.
    pub sel_rollover: bool,
    /// Unknown SEL flags (bits 12-14).
    pub reserved_sel_flags: u16,
    /// Identification capability bits: GUID, DHCP hostname, asset tag.
    pub identification_flags: u8,
    /// Temperature availability bits: inlet, CPU, baseboard.
    pub temperature_flags: u8,
}

/// Optional power management device location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionalAttributes {
    /// Slave address (0x40 indicates local BMC).
    pub power_device_address: u8,
    /// High-nibble channel.
    pub channel: u8,
    /// Low-nibble revision.
    pub device_revision: u8,
}

/// Access channels; 0xff means the respective channel is unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagementAccess {
    /// Primary LAN channel.
    pub primary_lan: Option<u8>,
    /// Secondary LAN channel.
    pub secondary_lan: Option<u8>,
    /// Serial channel.
    pub serial: Option<u8>,
}

/// The standardized platform feature bits; unrecognized bits are not discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformCapabilities {
    /// Identification support.
    pub identification: bool,
    /// SEL logging support.
    pub sel: bool,
    /// Chassis power support.
    pub chassis_power: bool,
    /// Temperature monitoring support.
    pub temperature: bool,
    /// Optional platform power management support.
    pub power_management: bool,
    /// Unrecognized bits in the mandatory capabilities byte.
    pub unknown_mandatory: u8,
    /// Unrecognized bits in the optional capabilities byte.
    pub unknown_optional: u8,
    /// Uninterpreted management access bits.
    pub management_access: u8,
}

impl IpmiCommand for GetCapabilities {
    type Output = CapabilityPage;
    type Error = DcmiError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        checked(data, 4)?;
        if data.len() > MAX_CAPABILITY_BYTES {
            return Err(DcmiError::Bounds);
        }
        let conformance = u16::from_le_bytes([data[1], data[2]]);
        if ![0x0001, 0x0101, 0x0501].contains(&conformance) {
            return Err(DcmiError::Conformance(conformance));
        }
        if ![1, 2].contains(&data[3]) {
            return Err(DcmiError::Revision(data[3]));
        }
        Ok(CapabilityPage {
            conformance,
            revision: data[3],
            data: data[4..].to_vec(),
        })
    }
}

/// DCMI temperature sensor entity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemperatureEntity {
    /// Inlet air.
    Inlet,
    /// CPU.
    Cpu,
    /// Baseboard.
    Baseboard,
}

impl TemperatureEntity {
    /// DCMI entity identifier.
    pub fn value(self) -> u8 {
        match self {
            Self::Inlet => 0x40,
            Self::Cpu => 0x41,
            Self::Baseboard => 0x42,
        }
    }
}

/// Selection of standard instantaneous power or enhanced sampled statistics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerSample {
    /// Standard mode; sampling period is reported in milliseconds.
    Standard,
    /// Enhanced mode; supplied byte is a controller-advertised sampling code.
    Enhanced(u8),
}

/// Get Power Reading (0x02); values are in watts and milliseconds.
#[derive(Clone, Copy, Debug)]
pub struct GetPowerReading(pub PowerSample);

impl From<GetPowerReading> for Message {
    fn from(value: GetPowerReading) -> Self {
        let (mode, sample) = match value.0 {
            PowerSample::Standard => (1, 0),
            PowerSample::Enhanced(sample) => (2, sample),
        };
        request(0x02, &[mode, sample, 0])
    }
}

/// Decoded power statistics. Enhanced sampling codes are preserved verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerReading {
    /// Instantaneous power, watts.
    pub current_watts: u16,
    /// Minimum power over the sampling period, watts.
    pub minimum_watts: u16,
    /// Maximum power over the sampling period, watts.
    pub maximum_watts: u16,
    /// Average power over the sampling period, watts.
    pub average_watts: u16,
    /// Timestamp in seconds since Unix epoch.
    pub timestamp_seconds: u32,
    /// Period in milliseconds in standard mode; an encoded code in enhanced mode.
    pub sample: u32,
    /// Raw state byte; bit 6 indicates power reading activation.
    pub state: u8,
}

impl PowerReading {
    /// Whether the reading is activated.
    pub fn active(&self) -> bool {
        self.state & 0x40 != 0
    }
}

impl IpmiCommand for GetPowerReading {
    type Output = PowerReading;
    type Error = DcmiError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        checked(data, 18)?;
        exact(data, 18)?;
        Ok(PowerReading {
            current_watts: u16::from_le_bytes([data[1], data[2]]),
            minimum_watts: u16::from_le_bytes([data[3], data[4]]),
            maximum_watts: u16::from_le_bytes([data[5], data[6]]),
            average_watts: u16::from_le_bytes([data[7], data[8]]),
            timestamp_seconds: u32::from_le_bytes(data[9..13].try_into().unwrap()),
            sample: u32::from_le_bytes(data[13..17].try_into().unwrap()),
            state: data[17],
        })
    }
}

/// DCMI power limit exception action. OEM values cannot be used for standard writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitAction {
    /// No action on exception.
    None,
    /// Hard power-off and SEL event.
    PowerOff,
    /// SEL logging only.
    LogToSel,
    /// OEM or unrecognized action; preserved on reads only.
    Other(u8),
}

impl LimitAction {
    fn from_byte(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::PowerOff,
            0x11 => Self::LogToSel,
            v => Self::Other(v),
        }
    }

    fn standard(self) -> Result<u8, DcmiError> {
        match self {
            Self::None => Ok(0),
            Self::PowerOff => Ok(1),
            Self::LogToSel => Ok(0x11),
            Self::Other(v) => Err(DcmiError::Value(v)),
        }
    }
}

/// A DCMI limit configuration, independent of whether the limit is active.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerLimit {
    /// Exception action.
    pub action: LimitAction,
    /// Power limit, watts.
    pub watts: u16,
    /// Correction time, milliseconds.
    pub correction_ms: u32,
    /// Sampling period, seconds.
    pub sample_seconds: u16,
}

impl PowerLimit {
    fn parse(data: &[u8]) -> Result<Self, DcmiError> {
        checked(data, 14)?;
        exact(data, 14)?;
        if data[1..3] != [0, 0] || data[10..12] != [0, 0] {
            return Err(DcmiError::Reserved);
        }
        Ok(Self {
            action: LimitAction::from_byte(data[3]),
            watts: u16::from_le_bytes([data[4], data[5]]),
            correction_ms: u32::from_le_bytes(data[6..10].try_into().unwrap()),
            sample_seconds: u16::from_le_bytes([data[12], data[13]]),
        })
    }
}

/// Get Power Limit (0x03).
///
/// An inactive limit is signaled by completion code 0x80. `Ipmi::send_recv`
/// returns `IpmiError::Command { error: DcmiError::InactiveLimit(limit), .. }`
/// if its response includes a valid limit, rather than losing that state.
#[derive(Clone, Copy, Debug)]
pub struct GetPowerLimit;

impl From<GetPowerLimit> for Message {
    fn from(_: GetPowerLimit) -> Self {
        request(0x03, &[0, 0])
    }
}

impl IpmiCommand for GetPowerLimit {
    type Output = PowerLimit;
    type Error = DcmiError;

    fn handle_completion_code(
        code: crate::connection::CompletionErrorCode,
        data: &[u8],
    ) -> Option<Self::Error> {
        if code == crate::connection::CompletionErrorCode::CommandSpecific(0x80) {
            PowerLimit::parse(data).ok().map(DcmiError::InactiveLimit)
        } else {
            None
        }
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        PowerLimit::parse(data)
    }
}

/// Set Power Limit (0x04). Administrator privilege is normally required.
/// Does not activate the limit; no read/modify/write or automatic retries.
#[derive(Clone, Copy, Debug)]
pub struct SetPowerLimit(PowerLimit);

impl SetPowerLimit {
    /// Validate a complete replacement before sending it.
    pub fn new(limit: PowerLimit) -> Result<Self, DcmiError> {
        limit.action.standard()?;
        Ok(Self(limit))
    }
}

impl From<SetPowerLimit> for Message {
    fn from(value: SetPowerLimit) -> Self {
        let limit = value.0;
        let mut bytes = vec![0, 0, 0, limit.action.standard().unwrap()];
        bytes.extend_from_slice(&limit.watts.to_le_bytes());
        bytes.extend_from_slice(&limit.correction_ms.to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&limit.sample_seconds.to_le_bytes());
        request(0x04, &bytes)
    }
}

impl IpmiCommand for SetPowerLimit {
    type Output = MutationOutcome;
    type Error = DcmiError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        ack(data)
    }
}

/// Activate or deactivate a previously configured power limit (0x05).
#[derive(Clone, Copy, Debug)]
pub struct SetPowerLimitActive(pub bool);

impl From<SetPowerLimitActive> for Message {
    fn from(value: SetPowerLimitActive) -> Self {
        request(0x05, &[u8::from(value.0), 0, 0])
    }
}

impl IpmiCommand for SetPowerLimitActive {
    type Output = MutationOutcome;
    type Error = DcmiError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        ack(data)
    }
}

/// Thermal policy in degrees Celsius and seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThermalPolicy {
    /// Survives system power cycles.
    pub persistent: bool,
    /// Hard power-off and SEL event on exception.
    pub power_off: bool,
    /// Log exception to SEL.
    pub log_to_sel: bool,
    /// Unspecialized reserved bits (reads only).
    pub reserved_flags: u8,
    /// Threshold, degrees Celsius.
    pub limit_celsius: u8,
    /// Time above limit before the exception, seconds.
    pub exception_seconds: u16,
}

/// Get Thermal Limit (0x0c).
#[derive(Clone, Copy, Debug)]
pub struct GetThermalPolicy {
    /// Entity with a DCMI temperature sensor.
    pub entity: TemperatureEntity,
    /// Entity instance.
    pub instance: u8,
}

impl From<GetThermalPolicy> for Message {
    fn from(value: GetThermalPolicy) -> Self {
        request(0x0c, &[value.entity.value(), value.instance])
    }
}

impl IpmiCommand for GetThermalPolicy {
    type Output = ThermalPolicy;
    type Error = DcmiError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        checked(data, 5)?;
        exact(data, 5)?;
        Ok(ThermalPolicy {
            persistent: data[1] & 0x80 != 0,
            power_off: data[1] & 0x40 != 0,
            log_to_sel: data[1] & 0x20 != 0,
            reserved_flags: data[1] & 0x1f,
            limit_celsius: data[2],
            exception_seconds: u16::from_le_bytes([data[3], data[4]]),
        })
    }
}

/// Set Thermal Limit (0x0b); administrator privilege and explicit opt-in required.
#[derive(Clone, Copy, Debug)]
pub struct SetThermalPolicy {
    entity: TemperatureEntity,
    instance: u8,
    policy: ThermalPolicy,
}

impl SetThermalPolicy {
    /// Reject an OEM policy readback before writing; a zero threshold can
    /// explicitly disable exception actions on controllers that support it.
    pub fn new(
        entity: TemperatureEntity,
        instance: u8,
        policy: ThermalPolicy,
    ) -> Result<Self, DcmiError> {
        if policy.reserved_flags != 0 {
            return Err(DcmiError::Bounds);
        }
        Ok(Self {
            entity,
            instance,
            policy,
        })
    }
}

impl From<SetThermalPolicy> for Message {
    fn from(value: SetThermalPolicy) -> Self {
        let p = value.policy;
        let flags = (u8::from(p.persistent) << 7)
            | (u8::from(p.power_off) << 6)
            | (u8::from(p.log_to_sel) << 5);
        let [lo, hi] = p.exception_seconds.to_le_bytes();
        request(
            0x0b,
            &[
                value.entity.value(),
                value.instance,
                flags,
                p.limit_celsius,
                lo,
                hi,
            ],
        )
    }
}

impl IpmiCommand for SetThermalPolicy {
    type Output = MutationOutcome;
    type Error = DcmiError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        ack(data)
    }
}

/// A single temperature reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemperatureReading {
    /// Entity instance.
    pub instance: u8,
    /// Signed temperature, degrees Celsius.
    pub celsius: i16,
}

/// Get Temperature Readings (0x10), at most eight samples per response.
#[derive(Clone, Copy, Debug)]
pub struct GetTemperatureReadings {
    /// Inlet, CPU, or baseboard entity.
    pub entity: TemperatureEntity,
    /// Zero selects all entity instances.
    pub instance: u8,
    /// Start offset into the instance list.
    pub offset: u8,
}

impl From<GetTemperatureReadings> for Message {
    fn from(value: GetTemperatureReadings) -> Self {
        request(
            0x10,
            &[1, value.entity.value(), value.instance, value.offset],
        )
    }
}

/// Bounded page of temperature readings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemperaturePage {
    /// Total number of instances, maximum 255.
    pub total: u8,
    /// Up to eight readings in this page.
    pub readings: Vec<TemperatureReading>,
}

impl IpmiCommand for GetTemperatureReadings {
    type Output = TemperaturePage;
    type Error = DcmiError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        checked(data, 3)?;
        let count = usize::from(data[2]);
        if count > 8 || count > usize::from(data[1]) {
            return Err(DcmiError::Page);
        }
        exact(data, 3 + count * 2)?;
        Ok(TemperaturePage {
            total: data[1],
            readings: data[3..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|s| TemperatureReading {
                    instance: s[1],
                    celsius: if s[0] & 0x80 == 0 {
                        i16::from(s[0])
                    } else {
                        -i16::from(s[0] & 0x7f)
                    },
                })
                .collect(),
        })
    }
}

/// Get Sensor Info (0x07), bounded to eight SDR record IDs per response.
#[derive(Clone, Copy, Debug)]
pub struct GetSensorRecords {
    /// Temperature entity.
    pub entity: TemperatureEntity,
    /// Offset into the instance list.
    pub offset: u8,
}

impl From<GetSensorRecords> for Message {
    fn from(value: GetSensorRecords) -> Self {
        request(0x07, &[1, value.entity.value(), 0, value.offset])
    }
}

/// Page of SDR record IDs referring to an entity's temperature sensors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SensorPage {
    /// Total number of sensor instances.
    pub total: u8,
    /// At most eight record IDs.
    pub records: Vec<u16>,
}

impl IpmiCommand for GetSensorRecords {
    type Output = SensorPage;
    type Error = DcmiError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        checked(data, 3)?;
        let count = usize::from(data[2]);
        if count > 8 || count > usize::from(data[1]) {
            return Err(DcmiError::Page);
        }
        exact(data, 3 + 2 * count)?;
        Ok(SensorPage {
            total: data[1],
            records: data[3..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect(),
        })
    }
}

/// Select the asset tag or management-controller identifier (up to 64 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringKind {
    /// DCMI asset tag, arbitrary bytes (not necessarily UTF-8).
    AssetTag,
    /// Management controller ID string, arbitrary bytes.
    ControllerId,
}

impl StringKind {
    fn command(self, set: bool) -> u8 {
        match (self, set) {
            (Self::AssetTag, false) => 0x06,
            (Self::AssetTag, true) => 0x08,
            (Self::ControllerId, false) => 0x09,
            (Self::ControllerId, true) => 0x0a,
        }
    }
}

/// Read one at-most-16-byte chunk of a DCMI string.
#[derive(Clone, Copy, Debug)]
pub struct GetString {
    kind: StringKind,
    offset: u8,
    length: u8,
}

impl GetString {
    /// Check offset, maximum size, and the protocol's per-command limit.
    pub fn new(kind: StringKind, offset: u8, length: u8) -> Result<Self, DcmiError> {
        if usize::from(length) > STRING_CHUNK
            || usize::from(offset) + usize::from(length) > MAX_STRING
            || (length == 0 && offset != 0)
        {
            return Err(DcmiError::Bounds);
        }
        Ok(Self {
            kind,
            offset,
            length,
        })
    }

    /// The requested string.
    pub fn kind(&self) -> StringKind {
        self.kind
    }

    /// Offset of the requested page.
    pub fn offset(&self) -> u8 {
        self.offset
    }

    /// Number of bytes requested, or zero for a length-only query.
    pub fn length(&self) -> u8 {
        self.length
    }
}

impl From<GetString> for Message {
    fn from(value: GetString) -> Self {
        request(value.kind.command(false), &[value.offset, value.length])
    }
}

/// DCMI string page. A reply shorter than requested is rejected by `read_string`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringPage {
    /// Reported total length in bytes.
    pub total: u8,
    /// Up to 16 bytes from the requested offset.
    pub bytes: Vec<u8>,
}

impl IpmiCommand for GetString {
    type Output = StringPage;
    type Error = DcmiError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        checked(data, 2)?;
        if usize::from(data[1]) > MAX_STRING || data.len() > 2 + STRING_CHUNK {
            return Err(DcmiError::Bounds);
        }
        Ok(StringPage {
            total: data[1],
            bytes: data[2..].to_vec(),
        })
    }
}

/// Set a single DCMI string chunk. Construction does not send the command.
#[derive(Clone, Debug)]
pub struct SetString {
    kind: StringKind,
    offset: u8,
    bytes: Vec<u8>,
}

impl SetString {
    /// Validate an individual write; multiple chunks are never retried.
    pub fn new(kind: StringKind, offset: u8, bytes: Vec<u8>) -> Result<Self, DcmiError> {
        if bytes.len() > STRING_CHUNK
            || usize::from(offset) + bytes.len() > MAX_STRING
            || (bytes.is_empty() && offset != 0)
        {
            return Err(DcmiError::Bounds);
        }
        Ok(Self {
            kind,
            offset,
            bytes,
        })
    }

    /// Offset of this particular chunk, for reporting partial writes.
    pub fn offset(&self) -> u8 {
        self.offset
    }
}

impl From<SetString> for Message {
    fn from(value: SetString) -> Self {
        let mut body = vec![value.offset, value.bytes.len() as u8];
        body.extend_from_slice(&value.bytes);
        request(value.kind.command(true), &body)
    }
}

impl IpmiCommand for SetString {
    type Output = MutationOutcome;
    type Error = DcmiError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        ack(data)
    }
}

/// Read all pages of an asset tag or controller ID, at most five requests.
///
/// The callback performs one request and returns its checked response. An
/// inconsistent length or short page fails instead of looping indefinitely.
pub fn read_string<E>(
    kind: StringKind,
    mut send: impl FnMut(GetString) -> Result<StringPage, E>,
) -> Result<Vec<u8>, PageError<E>> {
    let initial_length = u8::from(kind == StringKind::ControllerId);
    let first =
        send(GetString::new(kind, 0, initial_length).unwrap()).map_err(PageError::Transport)?;
    let total = usize::from(first.total);
    let initial_bytes = usize::from(initial_length).min(total);
    if total > MAX_STRING || first.bytes.len() != initial_bytes {
        return Err(PageError::Protocol(DcmiError::Page));
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend(first.bytes);
    while bytes.len() < total {
        let offset = bytes.len();
        let length = (total - offset).min(STRING_CHUNK);
        let page = send(GetString::new(kind, offset as u8, length as u8).unwrap())
            .map_err(PageError::Transport)?;
        if usize::from(page.total) != total || page.bytes.len() != length {
            return Err(PageError::Protocol(DcmiError::Page));
        }
        bytes.extend(page.bytes);
    }
    Ok(bytes)
}

/// Write a string in at most four chunks, without retrying or rollbacks.
/// An error records how many earlier chunks were acknowledged; the failed
/// chunk may also have been applied, so resending it could duplicate a write.
/// Administrator privilege is normally required.
pub fn write_string<E>(
    kind: StringKind,
    bytes: &[u8],
    mut send: impl FnMut(SetString) -> Result<MutationOutcome, E>,
) -> Result<MutationOutcome, StringWriteError<E>> {
    if bytes.len() > MAX_STRING {
        return Err(StringWriteError::Invalid(DcmiError::Bounds));
    }
    if bytes.is_empty() {
        return send(SetString::new(kind, 0, Vec::new()).unwrap()).map_err(|error| {
            StringWriteError::Uncertain {
                confirmed_bytes: 0,
                error,
            }
        });
    }
    let mut confirmed_bytes = 0;
    for chunk in bytes.chunks(STRING_CHUNK) {
        let command = SetString::new(kind, confirmed_bytes as u8, chunk.to_vec()).unwrap();
        send(command).map_err(|error| StringWriteError::Uncertain {
            confirmed_bytes,
            error,
        })?;
        confirmed_bytes += chunk.len();
    }
    Ok(MutationOutcome::Acknowledged)
}

/// Invalid input or a possibly applied, unacknowledged string write.
#[derive(Debug, PartialEq, Eq)]
pub enum StringWriteError<E> {
    /// Invalid length before sending any command.
    Invalid(DcmiError),
    /// The failed chunk may have been applied; preceding chunks were acknowledged.
    Uncertain {
        /// Number of bytes confirmed by earlier responses.
        confirmed_bytes: usize,
        /// Transport or completion-code error from this request.
        error: E,
    },
}

/// A pagination error, keeping transport failure separate from invalid replies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PageError<E> {
    /// Error returned by the caller's single-request transport.
    Transport(E),
    /// Malformed page, inconsistent totals, or offset overflow.
    Protocol(DcmiError),
}

/// Read all available temperatures with at most 256 requests (255 instances).
pub fn read_temperatures<E>(
    entity: TemperatureEntity,
    mut send: impl FnMut(GetTemperatureReadings) -> Result<TemperaturePage, E>,
) -> Result<Vec<TemperatureReading>, PageError<E>> {
    let first = send(GetTemperatureReadings {
        entity,
        instance: 0,
        offset: 0,
    })
    .map_err(PageError::Transport)?;
    let total = usize::from(first.total);
    let mut readings = Vec::with_capacity(total);
    while readings.len() < total {
        let offset = readings.len() + 1;
        let page = send(GetTemperatureReadings {
            entity,
            instance: 0,
            offset: offset as u8,
        })
        .map_err(PageError::Transport)?;
        if usize::from(page.total) != total
            || page.readings.is_empty()
            || page.readings.len() > 8
            || page.readings.len() > total - readings.len()
        {
            return Err(PageError::Protocol(DcmiError::Page));
        }
        readings.extend(page.readings);
    }
    Ok(readings)
}

/// Read all temperature-sensor SDR IDs with at most 256 requests.
pub fn read_sensor_records<E>(
    entity: TemperatureEntity,
    mut send: impl FnMut(GetSensorRecords) -> Result<SensorPage, E>,
) -> Result<Vec<u16>, PageError<E>> {
    let first = send(GetSensorRecords { entity, offset: 0 }).map_err(PageError::Transport)?;
    let total = usize::from(first.total);
    let mut records = Vec::with_capacity(total);
    while records.len() < total {
        let page = send(GetSensorRecords {
            entity,
            offset: records.len() as u8,
        })
        .map_err(PageError::Transport)?;
        if usize::from(page.total) != total
            || page.records.is_empty()
            || page.records.len() > 8
            || page.records.len() > total - records.len()
        {
            return Err(PageError::Protocol(DcmiError::Page));
        }
        records.extend(page.records);
    }
    Ok(records)
}

/// DCMI configuration selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigSelector {
    /// Activate DHCP configuration.
    ActivateDhcp,
    /// DHCP ID and vendor class configuration.
    DhcpConfiguration,
    /// Initial contact timeout (seconds).
    InitialTimeout,
    /// Server contact timeout (seconds).
    ContactTimeout,
    /// Server contact retry interval (seconds).
    RetryInterval,
}

impl ConfigSelector {
    fn value(self) -> u8 {
        match self {
            Self::ActivateDhcp => 1,
            Self::DhcpConfiguration => 2,
            Self::InitialTimeout => 3,
            Self::ContactTimeout => 4,
            Self::RetryInterval => 5,
        }
    }
}

/// Typed configuration value (in seconds for time parameters).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigValue {
    /// Request DHCP configuration activation.
    ActivateDhcp(bool),
    /// Two standard DHCP bits and other uninterpreted bits.
    DhcpConfiguration(u8),
    /// Initial timeout, seconds.
    InitialTimeout(u8),
    /// Contact timeout, seconds.
    ContactTimeout(u16),
    /// Retry interval, seconds.
    RetryInterval(u16),
}

/// Get DCMI Configuration Parameter (0x13).
#[derive(Clone, Copy, Debug)]
pub struct GetConfig(pub ConfigSelector);

impl From<GetConfig> for Message {
    fn from(value: GetConfig) -> Self {
        request(0x13, &[value.0.value(), 0])
    }
}

/// Config response: includes unparsed header bytes instead of assuming an OEM format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigPage {
    /// Parameter revision returned by the controller.
    pub revision: u8,
    /// Two protocol/header bytes, preserved verbatim.
    pub header: [u8; 2],
    /// Raw parameter payload (up to two bytes for these selectors).
    pub bytes: Vec<u8>,
}

impl ConfigPage {
    /// Decode only the selector originally requested.
    pub fn decode(&self, selector: ConfigSelector) -> Result<ConfigValue, DcmiError> {
        let len = if matches!(
            selector,
            ConfigSelector::ContactTimeout | ConfigSelector::RetryInterval
        ) {
            2
        } else {
            1
        };
        exact(&self.bytes, len)?;
        Ok(match selector {
            ConfigSelector::ActivateDhcp => ConfigValue::ActivateDhcp(match self.bytes[0] {
                0 => false,
                1 => true,
                other => return Err(DcmiError::Value(other)),
            }),
            ConfigSelector::DhcpConfiguration => ConfigValue::DhcpConfiguration(self.bytes[0]),
            ConfigSelector::InitialTimeout => ConfigValue::InitialTimeout(self.bytes[0]),
            ConfigSelector::ContactTimeout => {
                ConfigValue::ContactTimeout(u16::from_le_bytes([self.bytes[0], self.bytes[1]]))
            }
            ConfigSelector::RetryInterval => {
                ConfigValue::RetryInterval(u16::from_le_bytes([self.bytes[0], self.bytes[1]]))
            }
        })
    }
}

impl IpmiCommand for GetConfig {
    type Output = ConfigPage;
    type Error = DcmiError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        checked(data, 4)?;
        if data.len() > 6 {
            return Err(DcmiError::Bounds);
        }
        // DCMI config parameter revision 1.1 (bits 7:4 major, 3:0 minor).
        if data[1] != 0x11 {
            return Err(DcmiError::Revision(data[1]));
        }
        Ok(ConfigPage {
            revision: data[1],
            header: [data[2], data[3]],
            bytes: data[4..].to_vec(),
        })
    }
}

/// Set a DCMI Configuration Parameter (0x12), administrator privilege.
#[derive(Clone, Copy, Debug)]
pub struct SetConfig(ConfigValue);

impl SetConfig {
    /// Standard writes must not forward unknown DHCP flags as standard fields.
    pub fn new(value: ConfigValue) -> Result<Self, DcmiError> {
        if let ConfigValue::DhcpConfiguration(flags) = value {
            if flags & !3 != 0 {
                return Err(DcmiError::Value(flags));
            }
        }
        Ok(Self(value))
    }
}

impl From<SetConfig> for Message {
    fn from(value: SetConfig) -> Self {
        let (selector, bytes): (ConfigSelector, Vec<u8>) = match value.0 {
            ConfigValue::ActivateDhcp(b) => (ConfigSelector::ActivateDhcp, vec![u8::from(b)]),
            ConfigValue::DhcpConfiguration(v) => (ConfigSelector::DhcpConfiguration, vec![v]),
            ConfigValue::InitialTimeout(v) => (ConfigSelector::InitialTimeout, vec![v]),
            ConfigValue::ContactTimeout(v) => {
                (ConfigSelector::ContactTimeout, v.to_le_bytes().to_vec())
            }
            ConfigValue::RetryInterval(v) => {
                (ConfigSelector::RetryInterval, v.to_le_bytes().to_vec())
            }
        };
        let mut body = vec![selector.value(), 0];
        body.extend(bytes);
        request(0x12, &body)
    }
}

impl IpmiCommand for SetConfig {
    type Output = MutationOutcome;
    type Error = DcmiError;
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        ack(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(command: impl Into<Message>, code: u8, payload: &[u8]) {
        let message = command.into();
        assert_eq!(message.netfn_raw(), 0x2c);
        assert_eq!(message.cmd(), code);
        assert_eq!(
            message.data(),
            [GROUP]
                .iter()
                .chain(payload.iter())
                .copied()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn capabilities_discovery_decodes_each_selector_without_padding() {
        wire(GetCapabilities(CapabilitySelector::Platform), 1, &[1]);
        let platform =
            GetCapabilities::parse_success_response(&[0xdc, 0x01, 0x05, 2, 0x9f, 0x81, 0x42])
                .unwrap();
        assert_eq!(platform.conformance, 0x0501);
        assert_eq!(
            platform.extension(CapabilitySelector::Platform),
            Ok(&[][..])
        );
        let flags = platform
            .platform(CapabilitySelector::Platform)
            .unwrap()
            .unwrap();
        assert!(flags.identification && flags.power_management && flags.temperature);
        assert_eq!(flags.unknown_mandatory, 0x90);
        assert_eq!(flags.unknown_optional, 0x80);
        assert!(platform
            .platform(CapabilitySelector::MandatoryAttributes)
            .unwrap()
            .is_none());

        let mandatory =
            GetCapabilities::parse_success_response(&[0xdc, 0x01, 0x05, 2, 0x9f, 0x81, 0x42, 0x07])
                .unwrap();
        assert!(matches!(
            mandatory.decode(CapabilitySelector::MandatoryAttributes),
            Ok(CapabilityDetails::Mandatory(MandatoryAttributes {
                sel_entries: 0x19f,
                sel_rollover: true,
                temperature_flags: 7,
                ..
            }))
        ));

        wire(
            GetCapabilities(CapabilitySelector::OptionalAttributes),
            1,
            &[3],
        );
        let optional =
            GetCapabilities::parse_success_response(&[0xdc, 1, 5, 2, 0x40, 0x21]).unwrap();
        assert_eq!(
            optional.decode(CapabilitySelector::OptionalAttributes),
            Ok(CapabilityDetails::Optional(OptionalAttributes {
                power_device_address: 0x40,
                channel: 2,
                device_revision: 1,
            }))
        );
        let optional_oem =
            GetCapabilities::parse_success_response(&[0xdc, 1, 5, 2, 0x40, 0x21, 0xa1, 0xb2])
                .unwrap();
        assert_eq!(
            optional_oem.extension(CapabilitySelector::OptionalAttributes),
            Ok(&[0xa1, 0xb2][..])
        );

        let management =
            GetCapabilities::parse_success_response(&[0xdc, 1, 5, 2, 0xff, 2, 0xff, 0xfe]).unwrap();
        assert!(matches!(
            management.decode(CapabilitySelector::ManagementAccess),
            Ok(CapabilityDetails::Management(ManagementAccess {
                primary_lan: None,
                secondary_lan: Some(2),
                serial: None,
            }))
        ));
        assert_eq!(
            management.extension(CapabilitySelector::ManagementAccess),
            Ok(&[0xfe][..])
        );

        for (selector, expected) in [
            (CapabilitySelector::Platform, 7),
            (CapabilitySelector::MandatoryAttributes, 8),
            (CapabilitySelector::OptionalAttributes, 6),
            (CapabilitySelector::ManagementAccess, 7),
        ] {
            let mut truncated = vec![0xdc, 1, 5, 2];
            truncated.resize(expected - 1, 0);
            let page = GetCapabilities::parse_success_response(&truncated).unwrap();
            assert_eq!(
                page.decode(selector),
                Err(DcmiError::Length {
                    expected,
                    actual: expected - 1,
                })
            );
        }
    }

    #[test]
    fn capability_discovery_rejects_invalid_conformance_revision_and_group() {
        assert_eq!(
            GetCapabilities::parse_success_response(&[0xdc; 41]),
            Err(DcmiError::Bounds)
        );
        assert_eq!(
            GetCapabilities::parse_success_response(&[0xdc, 2, 2, 1, 0, 0, 0, 0]),
            Err(DcmiError::Conformance(0x0202))
        );
        assert_eq!(
            GetCapabilities::parse_success_response(&[0xdc, 1, 0, 3, 0, 0, 0, 0]),
            Err(DcmiError::Revision(3))
        );
        assert_eq!(
            GetCapabilities::parse_success_response(&[0, 1, 0, 1, 0, 0, 0, 0]),
            Err(DcmiError::Group(0))
        );
        assert!(matches!(
            GetCapabilities::parse_success_response(&[0xdc, 1]),
            Err(DcmiError::Length { .. })
        ));
    }

    #[test]
    fn power_reading_and_limit_fixtures_check_units_and_unknown_oem() {
        wire(GetPowerReading(PowerSample::Standard), 2, &[1, 0, 0]);
        wire(
            GetPowerReading(PowerSample::Enhanced(0x41)),
            2,
            &[2, 0x41, 0],
        );
        let power = GetPowerReading::parse_success_response(&[
            0xdc, 0x2c, 1, 50, 0, 0xf4, 1, 75, 0, 1, 2, 3, 4, 0xe8, 3, 0, 0, 0x40,
        ])
        .unwrap();
        assert_eq!(power.current_watts, 300);
        assert_eq!(power.average_watts, 75);
        assert_eq!(power.timestamp_seconds, 0x04030201);
        assert_eq!(power.sample, 1000);
        assert!(power.active());
        assert!(matches!(
            GetPowerReading::parse_success_response(&[0xdc; 19]),
            Err(DcmiError::Length { .. })
        ));
        wire(GetPowerLimit, 3, &[0, 0]);
        let raw = [0xdc, 0, 0, 0x09, 0x2c, 1, 0xe8, 3, 0, 0, 0, 0, 5, 0];
        let limit = GetPowerLimit::parse_success_response(&raw).unwrap();
        assert_eq!(limit.action, LimitAction::Other(0x09));
        assert_eq!(limit.watts, 300);
        assert_eq!(limit.correction_ms, 1000);
        let mut bad_reserved = raw;
        bad_reserved[10] = 1;
        assert_eq!(
            GetPowerLimit::parse_success_response(&bad_reserved),
            Err(DcmiError::Reserved)
        );
        assert_eq!(SetPowerLimit::new(limit).err(), Some(DcmiError::Value(9)));
        assert_eq!(
            GetPowerLimit::handle_completion_code(
                crate::connection::CompletionErrorCode::CommandSpecific(0x80),
                &raw
            ),
            Some(DcmiError::InactiveLimit(limit))
        );
        let write = SetPowerLimit::new(PowerLimit {
            action: LimitAction::LogToSel,
            watts: 300,
            correction_ms: 1000,
            sample_seconds: 5,
        })
        .unwrap();
        wire(
            write,
            4,
            &[0, 0, 0, 0x11, 0x2c, 1, 0xe8, 3, 0, 0, 0, 0, 5, 0],
        );
        wire(SetPowerLimitActive(true), 5, &[1, 0, 0]);
        assert_eq!(
            SetPowerLimit::parse_success_response(&[0xdc]),
            Ok(MutationOutcome::Acknowledged)
        );
        assert!(matches!(
            SetPowerLimit::parse_success_response(&[0xdc, 1]),
            Err(DcmiError::Length { .. })
        ));
    }

    #[test]
    fn thermal_sensor_and_config_fixtures_are_bounded() {
        wire(
            GetThermalPolicy {
                entity: TemperatureEntity::Inlet,
                instance: 2,
            },
            0x0c,
            &[0x40, 2],
        );
        let policy = GetThermalPolicy::parse_success_response(&[0xdc, 0xe0, 42, 30, 0]).unwrap();
        assert_eq!(policy.exception_seconds, 30);
        assert_eq!(
            Message::from(SetThermalPolicy::new(TemperatureEntity::Inlet, 2, policy).unwrap()),
            request(0x0b, &[0x40, 2, 0xe0, 42, 30, 0])
        );
        assert_eq!(
            SetThermalPolicy::new(
                TemperatureEntity::Inlet,
                2,
                ThermalPolicy {
                    reserved_flags: 1,
                    ..policy
                }
            )
            .err(),
            Some(DcmiError::Bounds)
        );
        wire(
            GetTemperatureReadings {
                entity: TemperatureEntity::Cpu,
                instance: 0,
                offset: 1,
            },
            0x10,
            &[1, 0x41, 0, 1],
        );
        let page =
            GetTemperatureReadings::parse_success_response(&[0xdc, 2, 2, 0x85, 1, 27, 2]).unwrap();
        assert_eq!(page.readings[0].celsius, -5);
        assert_eq!(page.readings[1].celsius, 27);
        assert_eq!(
            GetTemperatureReadings::parse_success_response(&[0xdc, 9, 9]),
            Err(DcmiError::Page)
        );
        assert!(matches!(
            GetTemperatureReadings::parse_success_response(&[0xdc, 2, 2, 20, 1]),
            Err(DcmiError::Length { .. })
        ));
        wire(
            GetSensorRecords {
                entity: TemperatureEntity::Baseboard,
                offset: 8,
            },
            7,
            &[1, 0x42, 0, 8],
        );
        assert_eq!(
            GetSensorRecords::parse_success_response(&[0xdc, 1, 1, 0x34, 0x12])
                .unwrap()
                .records,
            [0x1234]
        );
        assert_eq!(
            Message::from(GetConfig(ConfigSelector::ContactTimeout)).cmd(),
            0x13
        );
        let config = GetConfig::parse_success_response(&[0xdc, 0x11, 0, 0, 0x34, 0x12]).unwrap();
        assert_eq!(
            config.decode(ConfigSelector::ContactTimeout),
            Ok(ConfigValue::ContactTimeout(0x1234))
        );
        assert!(matches!(
            config.decode(ConfigSelector::RetryInterval),
            Ok(ConfigValue::RetryInterval(_))
        ));
        assert!(matches!(
            config.decode(ConfigSelector::InitialTimeout),
            Err(DcmiError::Length { .. })
        ));
        assert_eq!(
            GetConfig::parse_success_response(&[0xdc, 0x12, 0, 0, 1]),
            Err(DcmiError::Revision(0x12))
        );
        wire(
            SetConfig::new(ConfigValue::RetryInterval(0x1234)).unwrap(),
            0x12,
            &[5, 0, 0x34, 0x12],
        );
        assert!(matches!(
            SetConfig::new(ConfigValue::DhcpConfiguration(0x80)),
            Err(DcmiError::Value(0x80))
        ));
    }

    #[test]
    fn string_chunks_paginate_without_stalls_or_overflows() {
        assert_eq!(
            GetString::new(StringKind::AssetTag, 60, 5).err(),
            Some(DcmiError::Bounds)
        );
        assert_eq!(
            SetString::new(StringKind::ControllerId, 0, vec![1; 17]).err(),
            Some(DcmiError::Bounds)
        );
        wire(
            GetString::new(StringKind::ControllerId, 16, 8).unwrap(),
            9,
            &[16, 8],
        );
        wire(
            SetString::new(StringKind::AssetTag, 16, b"ab".to_vec()).unwrap(),
            8,
            &[16, 2, b'a', b'b'],
        );
        assert_eq!(
            GetString::parse_success_response(&[0xdc, 65]).err(),
            Some(DcmiError::Bounds)
        );
        let mut calls = Vec::new();
        let bytes = read_string(StringKind::AssetTag, |get| {
            calls.push((get.offset, get.length));
            if get.length == 0 {
                Ok::<_, ()>(StringPage {
                    total: 20,
                    bytes: vec![],
                })
            } else {
                Ok(StringPage {
                    total: 20,
                    bytes: vec![b'x'; usize::from(get.length)],
                })
            }
        })
        .unwrap();
        assert_eq!(bytes, vec![b'x'; 20]);
        assert_eq!(calls, [(0, 0), (0, 16), (16, 4)]);
        let mut calls = Vec::new();
        let controller_id = read_string(StringKind::ControllerId, |get| {
            calls.push((get.offset, get.length));
            Ok::<_, ()>(StringPage {
                total: 2,
                bytes: vec![b'i'; usize::from(get.length)],
            })
        })
        .unwrap();
        assert_eq!(controller_id, b"ii");
        assert_eq!(calls, [(0, 1), (1, 1)]);
        let mut count = 0;
        assert_eq!(
            read_string(StringKind::AssetTag, |_| {
                count += 1;
                Ok::<_, ()>(StringPage {
                    total: 7,
                    bytes: vec![],
                })
            }),
            Err(PageError::Protocol(DcmiError::Page))
        );
        assert_eq!(count, 2);
        let mut sent = Vec::new();
        let result = write_string(StringKind::AssetTag, &[b'a'; 33], |chunk| {
            sent.push(chunk.offset());
            if sent.len() == 3 {
                Err("timeout")
            } else {
                Ok(MutationOutcome::Acknowledged)
            }
        });
        assert_eq!(sent, [0, 16, 32]);
        assert_eq!(
            result,
            Err(StringWriteError::Uncertain {
                confirmed_bytes: 32,
                error: "timeout"
            })
        );
        assert_eq!(
            write_string(StringKind::AssetTag, &[0; 65], |_| -> Result<_, ()> {
                panic!("invalid length must not issue a command")
            }),
            Err(StringWriteError::Invalid(DcmiError::Bounds))
        );
    }

    #[test]
    fn temperature_and_sensor_paging_reject_nonprogress() {
        let readings = read_temperatures(TemperatureEntity::Inlet, |get| {
            Ok::<_, ()>(match get.offset {
                0 => TemperaturePage {
                    total: 2,
                    readings: vec![],
                },
                1 => TemperaturePage {
                    total: 2,
                    readings: vec![TemperatureReading {
                        instance: 1,
                        celsius: 25,
                    }],
                },
                _ => TemperaturePage {
                    total: 2,
                    readings: vec![TemperatureReading {
                        instance: 2,
                        celsius: 26,
                    }],
                },
            })
        })
        .unwrap();
        assert_eq!(readings.len(), 2);
        let mut count = 0;
        assert_eq!(
            read_sensor_records(TemperatureEntity::Cpu, |_| {
                count += 1;
                Ok::<_, ()>(SensorPage {
                    total: 1,
                    records: vec![],
                })
            }),
            Err(PageError::Protocol(DcmiError::Page))
        );
        assert_eq!(count, 2);
        let mut sent = 0;
        let ids = read_sensor_records(TemperatureEntity::Cpu, |get| {
            sent += 1;
            Ok::<_, ()>(SensorPage {
                total: 2,
                records: if sent == 1 {
                    vec![]
                } else {
                    assert_eq!(get.offset, 0);
                    vec![12, 34]
                },
            })
        })
        .unwrap();
        assert_eq!(ids, [12, 34]);
    }
}
