//! Platform Event Filtering (PEF) discovery and explicit configuration.
//!
//! The PEF filter/policy tables belong to the Sensor/Event net function, not
//! to LAN configuration. Alert destinations are configured separately on the
//! channel selected by an alert policy.

use bitflags::bitflags;

use crate::connection::{Channel, CompletionErrorCode, IpmiCommand, Message, NetFn};

/// An invalid PEF response, index, or configuration value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PefError {
    /// Expected and actual response lengths.
    InvalidLength { expected: usize, actual: usize },
    /// Unsupported configuration-parameter revision.
    UnsupportedRevision(u8),
    /// A field contains reserved bits (field and full wire value).
    ReservedBits { field: &'static str, value: u8 },
    /// Invalid enum or field value.
    InvalidValue { field: &'static str, value: u8 },
    /// The controller returned another table entry (expected and actual ID).
    UnexpectedIndex { expected: u8, actual: u8 },
    /// The table has no entries.
    UnsupportedTable(&'static str),
    /// Index is zero or exceeds the discovered table size.
    OutOfRange { index: u8, max: u8 },
    /// A table count exceeds the seven-bit selector range.
    InvalidTableSize(u8),
    /// A command-specific completion code (also retained by `IpmiError`).
    Rejected(PefRejection),
}

/// Known PEF configuration command-specific completion codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PefRejection {
    /// `0x80`: parameter not supported.
    UnsupportedParameter,
    /// `0x81`: cannot start another set-in-progress transaction.
    AlreadyInProgress,
    /// `0x82`: parameter is read-only.
    ReadOnly,
}

fn completion_error(code: CompletionErrorCode) -> Option<PefError> {
    Some(PefError::Rejected(match code {
        CompletionErrorCode::CommandSpecific(0x80) => PefRejection::UnsupportedParameter,
        CompletionErrorCode::CommandSpecific(0x81) => PefRejection::AlreadyInProgress,
        CompletionErrorCode::CommandSpecific(0x82) => PefRejection::ReadOnly,
        _ => return None,
    }))
}

fn length(data: &[u8], expected: usize) -> Result<(), PefError> {
    if data.len() == expected {
        Ok(())
    } else {
        Err(PefError::InvalidLength {
            expected,
            actual: data.len(),
        })
    }
}

fn allowed(value: u8, mask: u8, field: &'static str) -> Result<u8, PefError> {
    if value & !mask != 0 {
        Err(PefError::ReservedBits { field, value })
    } else {
        Ok(value)
    }
}

bitflags! {
    /// Supported or enabled PEF actions; all unassigned bits are rejected.
    pub struct PefActions: u8 {
        /// Send an alert.
        const ALERT = 0x01;
        /// Power the host off.
        const POWER_DOWN = 0x02;
        /// Reset the host.
        const RESET = 0x04;
        /// Power-cycle the host.
        const POWER_CYCLE = 0x08;
        /// OEM-defined action.
        const OEM = 0x10;
        /// Generate a diagnostic interrupt.
        const DIAGNOSTIC_INTERRUPT = 0x20;
    }
}

bitflags! {
    /// PEF control (configuration parameter 1).
    pub struct PefControl: u8 {
        /// Enable PEF processing.
        const ENABLE = 0x01;
        /// Enable PEF event messages.
        const EVENT_MESSAGES = 0x02;
        /// Enable the PEF startup delay.
        const STARTUP_DELAY = 0x04;
        /// Enable the alert startup delay.
        const ALERT_STARTUP_DELAY = 0x08;
    }
}

bitflags! {
    /// Severity bits matched by an event filter.
    pub struct PefSeverity: u8 {
        /// Monitor.
        const MONITOR = 0x01;
        /// Informational.
        const INFORMATION = 0x02;
        /// OK.
        const OK = 0x04;
        /// Warning.
        const WARNING = 0x08;
        /// Critical.
        const CRITICAL = 0x10;
        /// Non-recoverable.
        const NON_RECOVERABLE = 0x20;
    }
}

/// Count of filter or policy table entries, limited by their seven-bit IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PefTableSize(u8);

impl PefTableSize {
    /// Validate a count read from capabilities or a table-size parameter.
    pub fn new(value: u8) -> Result<Self, PefError> {
        if value <= 0x7f {
            Ok(Self(value))
        } else {
            Err(PefError::InvalidTableSize(value))
        }
    }

    /// Number of entries (zero means the table is unsupported).
    pub fn value(self) -> u8 {
        self.0
    }
}

fn index(value: u8, size: PefTableSize, table: &'static str) -> Result<u8, PefError> {
    if size.0 == 0 {
        Err(PefError::UnsupportedTable(table))
    } else if value == 0 || value > size.0 {
        Err(PefError::OutOfRange {
            index: value,
            max: size.0,
        })
    } else {
        Ok(value)
    }
}

/// Filter entry ID validated against a discovered filter table size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PefFilterId(u8);

impl PefFilterId {
    /// Construct an ID after reading `FilterTableSize` or `GetPefCapabilities`.
    pub fn new(value: u8, size: PefTableSize) -> Result<Self, PefError> {
        Ok(Self(index(value, size, "event filter")?))
    }

    /// Seven-bit wire ID.
    pub fn value(self) -> u8 {
        self.0
    }
}

/// Alert policy entry ID validated against a discovered policy table size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PefPolicyId(u8);

impl PefPolicyId {
    /// Construct an ID after reading `PolicyTableSize`.
    pub fn new(value: u8, size: PefTableSize) -> Result<Self, PefError> {
        Ok(Self(index(value, size, "alert policy")?))
    }

    /// Seven-bit wire ID.
    pub fn value(self) -> u8 {
        self.0
    }
}

/// Get PEF Capabilities (Sensor/Event command `0x10`).
#[derive(Clone, Copy, Debug)]
pub struct GetPefCapabilities;

/// Version, supported actions and count reported by the BMC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PefCapabilities {
    /// PEF specification version byte.
    pub version: u8,
    /// Actions implemented by the BMC.
    pub supported_actions: PefActions,
    /// Number of available filter entries.
    pub filter_count: PefTableSize,
}

/// PEF information assembled from capabilities and configuration reads.
///
/// The system GUID parameter is optional; an unsupported parameter (`0x80`)
/// can be represented by `None`. A caller may independently read the BMC
/// system GUID if the optional PEF-specific GUID is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PefInfo {
    /// Controller-reported PEF version, supported actions and filter count.
    pub capabilities: PefCapabilities,
    /// Number of filter entries reported by configuration parameter 5.
    pub filter_table_size: PefTableSize,
    /// Number of alert policies reported by configuration parameter 8.
    pub policy_table_size: PefTableSize,
    /// Optional PEF-specific system GUID.
    pub system_guid: Option<PefSystemGuid>,
}

impl From<GetPefCapabilities> for Message {
    fn from(_: GetPefCapabilities) -> Self {
        Message::new_request(NetFn::SensorEvent, 0x10, vec![])
    }
}

impl IpmiCommand for GetPefCapabilities {
    type Output = PefCapabilities;
    type Error = PefError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        completion_error(code)
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        length(data, 3)?;
        Ok(PefCapabilities {
            version: data[0],
            supported_actions: PefActions::from_bits(data[1]).ok_or(PefError::ReservedBits {
                field: "supported actions",
                value: data[1],
            })?,
            filter_count: PefTableSize::new(data[2])?,
        })
    }
}

/// Get Last Processed Event ID (Sensor/Event command `0x15`).
#[derive(Clone, Copy, Debug)]
pub struct GetPefLastProcessedEventId;

/// PEF processing status from Get Last Processed Event ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PefLastProcessedEvent {
    /// Last SEL addition timestamp (IPMI seconds since 1970, little endian).
    pub last_sel_addition: u32,
    /// Last SEL record ID.
    pub last_sel_record_id: u16,
    /// Last software-processed event ID.
    pub last_software_processed_id: u16,
    /// Last BMC-processed event ID.
    pub last_bmc_processed_id: u16,
}

/// PEF status assembled from Get Last Processed Event ID and parameters 1/2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PefStatus {
    /// Last SEL addition and processed event IDs.
    pub last_processed: PefLastProcessedEvent,
    /// PEF control bits.
    pub control: PefControl,
    /// Currently enabled PEF actions.
    pub enabled_actions: PefActions,
}

impl From<GetPefLastProcessedEventId> for Message {
    fn from(_: GetPefLastProcessedEventId) -> Self {
        Message::new_request(NetFn::SensorEvent, 0x15, vec![])
    }
}

impl IpmiCommand for GetPefLastProcessedEventId {
    type Output = PefLastProcessedEvent;
    type Error = PefError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        completion_error(code)
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        length(data, 10)?;
        Ok(PefLastProcessedEvent {
            last_sel_addition: u32::from_le_bytes(data[..4].try_into().unwrap()),
            last_sel_record_id: u16::from_le_bytes([data[4], data[5]]),
            last_software_processed_id: u16::from_le_bytes([data[6], data[7]]),
            last_bmc_processed_id: u16::from_le_bytes([data[8], data[9]]),
        })
    }
}

/// PEF configuration parameters supported by this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PefConfigParameter {
    /// Parameter 0, set-in-progress state.
    SetInProgress,
    /// Parameter 1, PEF control.
    Control,
    /// Parameter 2, enabled actions.
    EnabledActions,
    /// Parameter 5, number of filter entries.
    FilterTableSize,
    /// Parameter 6, complete filter entry (read-only here).
    FilterEntry(PefFilterId),
    /// Parameter 7, filter enabled state.
    FilterState(PefFilterId),
    /// Parameter 8, number of alert policy entries.
    PolicyTableSize,
    /// Parameter 9, alert policy entry.
    PolicyEntry(PefPolicyId),
    /// Parameter 10, system GUID used for PET.
    SystemGuid,
}

impl PefConfigParameter {
    /// Wire parameter selector (excluding the revision-only bit).
    pub fn value(self) -> u8 {
        match self {
            Self::SetInProgress => 0,
            Self::Control => 1,
            Self::EnabledActions => 2,
            Self::FilterTableSize => 5,
            Self::FilterEntry(_) => 6,
            Self::FilterState(_) => 7,
            Self::PolicyTableSize => 8,
            Self::PolicyEntry(_) => 9,
            Self::SystemGuid => 10,
        }
    }

    fn index(self) -> u8 {
        match self {
            Self::FilterEntry(id) | Self::FilterState(id) => id.value(),
            Self::PolicyEntry(id) => id.value(),
            _ => 0,
        }
    }
}

/// State of a PEF configuration write (parameter 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PefSetInProgress {
    /// No write in progress.
    Complete,
    /// A write is in progress.
    InProgress,
    /// Commit pending writes.
    CommitWrite,
}

impl PefSetInProgress {
    fn value(self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::InProgress => 1,
            Self::CommitWrite => 2,
        }
    }
}

/// An event-data comparison: AND mask followed by the two compare bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PefEventDataComparison {
    /// Mask applied before comparison.
    pub and_mask: u8,
    /// First compare byte.
    pub compare_1: u8,
    /// Second compare byte.
    pub compare_2: u8,
}

/// Complete read-only event filter table entry (parameter 6).
///
/// The reference CLI implements listing and enabling/disabling filters, but
/// *not* creating, deleting, or rewriting complete filter entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PefFilterEntry {
    /// Validated table index.
    pub id: PefFilterId,
    /// Whether the filter is active.
    pub enabled: bool,
    /// Whether it is preconfigured by the BMC.
    pub preconfigured: bool,
    /// Actions when the filter matches.
    pub actions: PefActions,
    /// Policy set number (0..15).
    pub policy_set: PefPolicySet,
    /// Severity match bits.
    pub severity: PefSeverity,
    /// Generator ID address byte.
    pub generator_id_address: u8,
    /// Generator ID LUN byte (including any wildcards).
    pub generator_id_lun: u8,
    /// Sensor type.
    pub sensor_type: u8,
    /// Sensor number (`0xff` matches any).
    pub sensor_number: u8,
    /// Event trigger (`0xff` matches any).
    pub event_trigger: u8,
    /// Event data 1 offset mask (little endian).
    pub event_data_1_offset_mask: u16,
    /// First event-data comparison.
    pub event_data_1: PefEventDataComparison,
    /// Second event-data comparison.
    pub event_data_2: PefEventDataComparison,
    /// Third event-data comparison.
    pub event_data_3: PefEventDataComparison,
}

impl PefFilterEntry {
    fn parse(id: PefFilterId, data: &[u8]) -> Result<Self, PefError> {
        length(data, 21)?;
        check_index(id.value(), data[0])?;
        let config = allowed(data[1], 0xc0, "filter configuration")?;
        let actions = PefActions::from_bits(data[2]).ok_or(PefError::ReservedBits {
            field: "filter actions",
            value: data[2],
        })?;
        let policy_set = PefPolicySet::from_filter_byte(data[3])?;
        let severity = PefSeverity::from_bits(data[4]).ok_or(PefError::ReservedBits {
            field: "filter severity",
            value: data[4],
        })?;
        let comparison = |offset| PefEventDataComparison {
            and_mask: data[offset],
            compare_1: data[offset + 1],
            compare_2: data[offset + 2],
        };
        Ok(Self {
            id,
            enabled: config & 0x80 != 0,
            preconfigured: config & 0x40 != 0,
            actions,
            policy_set,
            severity,
            generator_id_address: data[5],
            generator_id_lun: data[6],
            sensor_type: data[7],
            sensor_number: data[8],
            event_trigger: data[9],
            event_data_1_offset_mask: u16::from_le_bytes([data[10], data[11]]),
            event_data_1: comparison(12),
            event_data_2: comparison(15),
            event_data_3: comparison(18),
        })
    }
}

/// Policy set number (four bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PefPolicySet(u8);

impl PefPolicySet {
    /// Construct a policy set number in `0..=15`.
    pub fn new(value: u8) -> Result<Self, PefError> {
        if value <= 15 {
            Ok(Self(value))
        } else {
            Err(PefError::InvalidValue {
                field: "policy set",
                value,
            })
        }
    }

    fn from_filter_byte(value: u8) -> Result<Self, PefError> {
        Self::new(allowed(value, 0x0f, "filter policy set")?)
    }

    /// Four-bit policy set number.
    pub fn value(self) -> u8 {
        self.0
    }
}

/// Alert policy rule encoded in the low three bits of its policy byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PefPolicyRule {
    /// Match always.
    MatchAlways,
    /// Try next policy entry.
    TryNextEntry,
    /// Try next policy set.
    TryNextSet,
    /// Try next channel within this set.
    TryNextChannel,
    /// Try next destination within this set.
    TryNextDestination,
}

impl PefPolicyRule {
    fn parse(value: u8) -> Result<Self, PefError> {
        match value {
            0 => Ok(Self::MatchAlways),
            1 => Ok(Self::TryNextEntry),
            2 => Ok(Self::TryNextSet),
            3 => Ok(Self::TryNextChannel),
            4 => Ok(Self::TryNextDestination),
            _ => Err(PefError::InvalidValue {
                field: "policy rule",
                value,
            }),
        }
    }

    fn value(self) -> u8 {
        match self {
            Self::MatchAlways => 0,
            Self::TryNextEntry => 1,
            Self::TryNextSet => 2,
            Self::TryNextChannel => 3,
            Self::TryNextDestination => 4,
        }
    }
}

/// Alert destination ID (four bits; zero has its IPMI-defined meaning).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PefDestinationId(u8);

impl PefDestinationId {
    /// Construct a destination ID in `0..=15`.
    pub fn new(value: u8) -> Result<Self, PefError> {
        if value <= 15 {
            Ok(Self(value))
        } else {
            Err(PefError::InvalidValue {
                field: "destination",
                value,
            })
        }
    }

    /// Four-bit destination ID.
    pub fn value(self) -> u8 {
        self.0
    }
}

/// Alert string key, optionally event-specific.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PefAlertStringKey {
    event_specific: bool,
    key: u8,
}

impl PefAlertStringKey {
    /// Construct a key with a seven-bit ID.
    pub fn new(key: u8, event_specific: bool) -> Result<Self, PefError> {
        if key <= 0x7f {
            Ok(Self {
                key,
                event_specific,
            })
        } else {
            Err(PefError::InvalidValue {
                field: "alert string key",
                value: key,
            })
        }
    }

    /// Event-specific string selection.
    pub fn event_specific(self) -> bool {
        self.event_specific
    }

    /// Seven-bit alert string key.
    pub fn key(self) -> u8 {
        self.key
    }

    fn value(self) -> u8 {
        self.key | if self.event_specific { 0x80 } else { 0 }
    }
}

/// Three-byte alert policy entry (parameter 9).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PefAlertPolicy {
    /// Policy set to which this entry belongs.
    pub policy_set: PefPolicySet,
    /// Whether this entry is enabled.
    pub enabled: bool,
    /// Next-entry/set/channel/destination rule.
    pub rule: PefPolicyRule,
    /// Channel used for the alert (configure its destination separately).
    pub channel: Channel,
    /// Destination on that channel.
    pub destination: PefDestinationId,
    /// Alert string key.
    pub alert_string_key: PefAlertStringKey,
}

impl PefAlertPolicy {
    fn parse(data: &[u8]) -> Result<Self, PefError> {
        length(data, 3)?;
        Ok(Self {
            policy_set: PefPolicySet::new(data[0] >> 4)?,
            enabled: data[0] & 0x08 != 0,
            rule: PefPolicyRule::parse(data[0] & 0x07)?,
            channel: Channel::new(data[1] >> 4).ok_or(PefError::InvalidValue {
                field: "policy channel",
                value: data[1] >> 4,
            })?,
            destination: PefDestinationId::new(data[1] & 0x0f)?,
            alert_string_key: PefAlertStringKey::new(data[2] & 0x7f, data[2] & 0x80 != 0)?,
        })
    }

    fn bytes(self) -> [u8; 3] {
        [
            (self.policy_set.value() << 4) | (u8::from(self.enabled) << 3) | self.rule.value(),
            (self.channel.value() << 4) | self.destination.value(),
            self.alert_string_key.value(),
        ]
    }
}

/// Policy table entry and its validated ID.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PefAlertPolicyEntry {
    /// Alert policy table ID.
    pub id: PefPolicyId,
    /// Entire policy value; enabling/disabling should preserve all other fields.
    pub policy: PefAlertPolicy,
}

/// Optional system GUID used in PET messages (parameter 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PefSystemGuid {
    /// Whether the returned GUID is used in PET.
    pub used_in_pet: bool,
    /// GUID in its wire byte order.
    pub guid: [u8; 16],
}

/// A decoded PEF configuration parameter.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PefConfigValue {
    /// Parameter 0.
    SetInProgress(PefSetInProgress),
    /// Parameter 1.
    Control(PefControl),
    /// Parameter 2.
    EnabledActions(PefActions),
    /// Parameter 5.
    FilterTableSize(PefTableSize),
    /// Parameter 6.
    FilterEntry(PefFilterEntry),
    /// Parameter 7.
    FilterState { id: PefFilterId, enabled: bool },
    /// Parameter 8.
    PolicyTableSize(PefTableSize),
    /// Parameter 9.
    PolicyEntry(PefAlertPolicyEntry),
    /// Parameter 10.
    SystemGuid(PefSystemGuid),
}

fn check_index(expected: u8, actual: u8) -> Result<(), PefError> {
    allowed(actual, 0x7f, "table entry ID")?;
    if expected == actual {
        Ok(())
    } else {
        Err(PefError::UnexpectedIndex { expected, actual })
    }
}

/// Get a selected PEF configuration parameter (Sensor/Event `0x13`).
#[derive(Clone, Copy, Debug)]
pub struct GetPefConfig {
    /// Selected parameter; table indices must first be validated against a size.
    pub parameter: PefConfigParameter,
}

impl From<GetPefConfig> for Message {
    fn from(value: GetPefConfig) -> Self {
        Message::new_request(
            NetFn::SensorEvent,
            0x13,
            vec![value.parameter.value(), value.parameter.index(), 0],
        )
    }
}

/// Raw parameter data following the revision byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PefConfigRaw {
    /// Parameter revision (currently `0x11`).
    pub revision: u8,
    /// Parameter data, without its revision.
    pub data: Vec<u8>,
}

impl PefConfigRaw {
    /// Check the exact shape and decode as the parameter requested.
    pub fn parse(&self, parameter: PefConfigParameter) -> Result<PefConfigValue, PefError> {
        let data = &self.data;
        Ok(match parameter {
            PefConfigParameter::SetInProgress => {
                length(data, 1)?;
                PefConfigValue::SetInProgress(match data[0] {
                    0 => PefSetInProgress::Complete,
                    1 => PefSetInProgress::InProgress,
                    2 => PefSetInProgress::CommitWrite,
                    value => {
                        return Err(PefError::InvalidValue {
                            field: "set in progress",
                            value,
                        });
                    }
                })
            }
            PefConfigParameter::Control => {
                length(data, 1)?;
                PefConfigValue::Control(PefControl::from_bits(data[0]).ok_or(
                    PefError::ReservedBits {
                        field: "PEF control",
                        value: data[0],
                    },
                )?)
            }
            PefConfigParameter::EnabledActions => {
                length(data, 1)?;
                PefConfigValue::EnabledActions(PefActions::from_bits(data[0]).ok_or(
                    PefError::ReservedBits {
                        field: "enabled actions",
                        value: data[0],
                    },
                )?)
            }
            PefConfigParameter::FilterTableSize | PefConfigParameter::PolicyTableSize => {
                length(data, 1)?;
                let size = PefTableSize::new(data[0])?;
                if parameter == PefConfigParameter::FilterTableSize {
                    PefConfigValue::FilterTableSize(size)
                } else {
                    PefConfigValue::PolicyTableSize(size)
                }
            }
            PefConfigParameter::FilterEntry(id) => {
                PefConfigValue::FilterEntry(PefFilterEntry::parse(id, data)?)
            }
            PefConfigParameter::FilterState(id) => {
                length(data, 2)?;
                check_index(id.value(), data[0])?;
                PefConfigValue::FilterState {
                    id,
                    enabled: allowed(data[1], 0x80, "filter enabled state")? != 0,
                }
            }
            PefConfigParameter::PolicyEntry(id) => {
                length(data, 4)?;
                check_index(id.value(), data[0])?;
                PefConfigValue::PolicyEntry(PefAlertPolicyEntry {
                    id,
                    policy: PefAlertPolicy::parse(&data[1..])?,
                })
            }
            PefConfigParameter::SystemGuid => {
                length(data, 17)?;
                let used_in_pet = match data[0] {
                    0 => false,
                    1 => true,
                    value => {
                        return Err(PefError::ReservedBits {
                            field: "system GUID selection",
                            value,
                        });
                    }
                };
                PefConfigValue::SystemGuid(PefSystemGuid {
                    used_in_pet,
                    guid: data[1..].try_into().unwrap(),
                })
            }
        })
    }
}

impl IpmiCommand for GetPefConfig {
    type Output = PefConfigRaw;
    type Error = PefError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        completion_error(code)
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let Some((&revision, payload)) = data.split_first() else {
            return Err(PefError::InvalidLength {
                expected: 1,
                actual: 0,
            });
        };
        if revision != 0x11 {
            return Err(PefError::UnsupportedRevision(revision));
        }
        Ok(PefConfigRaw {
            revision,
            data: payload.to_vec(),
        })
    }
}

impl GetPefConfig {
    /// Parse a success response for this exact parameter and table index.
    pub fn parse_response(self, data: &[u8]) -> Result<PefConfigValue, PefError> {
        <Self as IpmiCommand>::parse_success_response(data)?.parse(self.parameter)
    }
}

/// Explicit writable PEF parameter.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PefWrite {
    /// Parameter 0, transaction state.
    SetInProgress(PefSetInProgress),
    /// Parameter 7, enable/disable an existing filter (not full filter creation).
    FilterEnabled { id: PefFilterId, enabled: bool },
    /// Parameter 9, write a complete alert policy entry.
    PolicyEntry(PefAlertPolicyEntry),
}

/// Set PEF Configuration Parameters (Sensor/Event `0x12`).
#[derive(Clone, Copy, Debug)]
pub struct SetPefConfig {
    /// Explicit parameter value to write.
    pub value: PefWrite,
}

impl From<SetPefConfig> for Message {
    fn from(value: SetPefConfig) -> Self {
        let data = match value.value {
            PefWrite::SetInProgress(state) => vec![0, state.value()],
            PefWrite::FilterEnabled { id, enabled } => {
                vec![7, id.value(), if enabled { 0x80 } else { 0 }]
            }
            PefWrite::PolicyEntry(entry) => {
                let mut bytes = vec![9, entry.id.value()];
                bytes.extend(entry.policy.bytes());
                bytes
            }
        };
        Message::new_request(NetFn::SensorEvent, 0x12, data)
    }
}

impl IpmiCommand for SetPefConfig {
    type Output = ();
    type Error = PefError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        completion_error(code)
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        length(data, 0)
    }
}

/// Change to an existing filter or policy, independent of transaction state.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PefChange {
    /// Enable/disable an existing event filter.
    FilterEnabled { id: PefFilterId, enabled: bool },
    /// Set an alert policy entry (preserve unrelated fields on enable/disable).
    PolicyEntry(PefAlertPolicyEntry),
}

impl From<PefChange> for PefWrite {
    fn from(value: PefChange) -> Self {
        match value {
            PefChange::FilterEnabled { id, enabled } => Self::FilterEnabled { id, enabled },
            PefChange::PolicyEntry(entry) => Self::PolicyEntry(entry),
        }
    }
}

/// Start, change, commit, and finish a PEF configuration write.
///
/// This helper makes at most four requests and always attempts Set Complete,
/// including when Begin fails or the write fails. If parameter 0 is unsupported,
/// it returns the error; callers must explicitly decide whether an unguarded
/// [`SetPefConfig`] is appropriate for their controller. No discovery/read
/// operation invokes this helper or writes to the BMC.
pub fn pef_write_guarded<E>(
    mut send: impl FnMut(SetPefConfig) -> Result<(), E>,
    change: PefChange,
) -> Result<(), PefWriteError<E>> {
    let state = |value| SetPefConfig {
        value: PefWrite::SetInProgress(value),
    };
    if let Err(error) = send(state(PefSetInProgress::InProgress)) {
        let cleanup = send(state(PefSetInProgress::Complete)).err();
        return Err(PefWriteError::Begin { error, cleanup });
    }
    let written = send(SetPefConfig {
        value: change.into(),
    });
    let commit = if written.is_ok() {
        Some(send(state(PefSetInProgress::CommitWrite)))
    } else {
        None
    };
    let cleanup = send(state(PefSetInProgress::Complete));
    if written.is_ok() && commit.as_ref().is_some_and(Result::is_ok) && cleanup.is_ok() {
        Ok(())
    } else {
        Err(PefWriteError::Uncertain {
            write: written.err(),
            commit: commit.and_then(Result::err),
            cleanup: cleanup.err(),
        })
    }
}

/// A guarded write may have taken effect even when a response was lost.
#[derive(Debug, PartialEq, Eq)]
pub enum PefWriteError<E> {
    /// Begin failed; Set Complete was still attempted.
    Begin {
        /// Begin error.
        error: E,
        /// Cleanup error, if any.
        cleanup: Option<E>,
    },
    /// Write, commit or cleanup failed; all outcomes are retained.
    Uncertain {
        /// Write failure, if any.
        write: Option<E>,
        /// Commit failure, if any (commit is skipped on write failure).
        commit: Option<E>,
        /// Set Complete failure, if any.
        cleanup: Option<E>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILTER: [u8; 22] = [
        0x11, 3, 0xc0, 0x21, 2, 8, 0x81, 0xff, 1, 0xff, 0x6f, 0x34, 0x12, 0xff, 1, 2, 0xfe, 3, 4,
        0xfd, 5, 6,
    ];
    const POLICY: [u8; 5] = [0x11, 2, 0x29, 0x41, 0x85];

    fn filter_id() -> PefFilterId {
        PefFilterId::new(3, PefTableSize::new(3).unwrap()).unwrap()
    }

    fn policy_id() -> PefPolicyId {
        PefPolicyId::new(2, PefTableSize::new(3).unwrap()).unwrap()
    }

    #[test]
    fn capabilities_status_and_info_fixtures() {
        let message: Message = GetPefCapabilities.into();
        assert_eq!(message.netfn_raw(), 4);
        assert_eq!(message.cmd(), 0x10);
        assert!(message.data().is_empty());
        let capabilities = GetPefCapabilities::parse_success_response(&[0x51, 0x23, 3]).unwrap();
        assert_eq!(capabilities.version, 0x51);
        assert_eq!(
            capabilities.supported_actions,
            PefActions::ALERT | PefActions::POWER_DOWN | PefActions::DIAGNOSTIC_INTERRUPT
        );
        assert_eq!(capabilities.filter_count.value(), 3);
        assert_eq!(
            GetPefCapabilities::parse_success_response(&[0x51, 0x80, 3]),
            Err(PefError::ReservedBits {
                field: "supported actions",
                value: 0x80,
            })
        );
        assert_eq!(
            GetPefCapabilities::parse_success_response(&[0x51, 1, 128]),
            Err(PefError::InvalidTableSize(128))
        );
        assert_eq!(
            GetPefCapabilities::parse_success_response(&[0x51, 1]),
            Err(PefError::InvalidLength {
                expected: 3,
                actual: 2,
            })
        );
        let message: Message = GetPefLastProcessedEventId.into();
        assert_eq!(message.cmd(), 0x15);
        let last_processed = GetPefLastProcessedEventId::parse_success_response(&[
            0x78, 0x56, 0x34, 0x12, 0xcd, 0xab, 0x02, 0x01, 0x04, 0x03,
        ])
        .unwrap();
        assert_eq!(
            last_processed,
            PefLastProcessedEvent {
                last_sel_addition: 0x12345678,
                last_sel_record_id: 0xabcd,
                last_software_processed_id: 0x0102,
                last_bmc_processed_id: 0x0304,
            }
        );
        assert!(matches!(
            GetPefLastProcessedEventId::parse_success_response(&[0; 9]),
            Err(PefError::InvalidLength { .. })
        ));
        for (parameter, byte) in [
            (PefConfigParameter::SetInProgress, 1),
            (PefConfigParameter::Control, 0x0b),
            (PefConfigParameter::EnabledActions, 0x09),
            (PefConfigParameter::FilterTableSize, 3),
            (PefConfigParameter::PolicyTableSize, 2),
        ] {
            let command = GetPefConfig { parameter };
            let message: Message = command.into();
            assert_eq!(message.netfn_raw(), 4);
            assert_eq!(message.cmd(), 0x13);
            assert_eq!(message.data(), [parameter.value(), 0, 0]);
            assert!(command.parse_response(&[0x11, byte]).is_ok());
            assert!(matches!(
                command.parse_response(&[0x11, byte, 0]),
                Err(PefError::InvalidLength { .. })
            ));
        }
        assert_eq!(
            (GetPefConfig {
                parameter: PefConfigParameter::Control
            })
            .parse_response(&[0x11, 0x0b]),
            Ok(PefConfigValue::Control(
                PefControl::ENABLE | PefControl::EVENT_MESSAGES | PefControl::ALERT_STARTUP_DELAY
            ))
        );
        let info = PefInfo {
            capabilities,
            filter_table_size: PefTableSize::new(3).unwrap(),
            policy_table_size: PefTableSize::new(2).unwrap(),
            system_guid: None,
        };
        assert_eq!(info.policy_table_size.value(), 2);
        let status = PefStatus {
            last_processed,
            control: PefControl::ENABLE | PefControl::EVENT_MESSAGES,
            enabled_actions: PefActions::ALERT,
        };
        assert_eq!(status.last_processed.last_sel_record_id, 0xabcd);
        let guid: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut guid_response = vec![0x11, 1];
        guid_response.extend(guid);
        assert_eq!(
            (GetPefConfig {
                parameter: PefConfigParameter::SystemGuid
            })
            .parse_response(&guid_response),
            Ok(PefConfigValue::SystemGuid(PefSystemGuid {
                used_in_pet: true,
                guid,
            }))
        );
        guid_response[1] = 0x80;
        assert!(matches!(
            (GetPefConfig {
                parameter: PefConfigParameter::SystemGuid
            })
            .parse_response(&guid_response),
            Err(PefError::ReservedBits { .. })
        ));
    }

    #[test]
    fn table_indices_are_bounded_before_reads_or_writes() {
        let empty = PefTableSize::new(0).unwrap();
        assert_eq!(
            PefFilterId::new(1, empty),
            Err(PefError::UnsupportedTable("event filter"))
        );
        assert_eq!(
            PefPolicyId::new(1, empty),
            Err(PefError::UnsupportedTable("alert policy"))
        );
        let size = PefTableSize::new(3).unwrap();
        assert_eq!(
            PefFilterId::new(0, size),
            Err(PefError::OutOfRange { index: 0, max: 3 })
        );
        assert_eq!(
            PefPolicyId::new(4, size),
            Err(PefError::OutOfRange { index: 4, max: 3 })
        );
        assert_eq!(PefTableSize::new(128), Err(PefError::InvalidTableSize(128)));
        assert!(PefPolicySet::new(16).is_err());
        assert!(PefDestinationId::new(16).is_err());
        assert!(PefAlertStringKey::new(128, false).is_err());
        assert_eq!(
            (GetPefConfig {
                parameter: PefConfigParameter::FilterTableSize
            })
            .parse_response(&[0x11, 0x80]),
            Err(PefError::InvalidTableSize(128))
        );
    }

    #[test]
    fn filter_fixture_decodes_exact_fields_and_rejects_corruption() {
        let command = GetPefConfig {
            parameter: PefConfigParameter::FilterEntry(filter_id()),
        };
        let message: Message = command.into();
        assert_eq!(message.data(), [6, 3, 0]);
        let PefConfigValue::FilterEntry(entry) = command.parse_response(&FILTER).unwrap() else {
            panic!("expected filter");
        };
        assert!(entry.enabled && entry.preconfigured);
        assert_eq!(
            entry.actions,
            PefActions::ALERT | PefActions::DIAGNOSTIC_INTERRUPT
        );
        assert_eq!(entry.policy_set.value(), 2);
        assert_eq!(entry.severity, PefSeverity::WARNING);
        assert_eq!(entry.generator_id_address, 0x81);
        assert_eq!(entry.generator_id_lun, 0xff);
        assert_eq!(entry.sensor_number, 0xff);
        assert_eq!(entry.event_trigger, 0x6f);
        assert_eq!(entry.event_data_1_offset_mask, 0x1234);
        assert_eq!(entry.event_data_1.compare_2, 2);
        assert_eq!(entry.event_data_3.and_mask, 0xfd);
        assert_eq!(
            command.parse_response(&FILTER[..21]),
            Err(PefError::InvalidLength {
                expected: 21,
                actual: 20,
            })
        );
        assert_eq!(
            command.parse_response(&[0x10]),
            Err(PefError::UnsupportedRevision(0x10))
        );
        for (offset, value, field) in [
            (2, 0x20, "filter configuration"),
            (3, 0x80, "filter actions"),
            (4, 0x10, "filter policy set"),
            (5, 0x40, "filter severity"),
        ] {
            let mut bad = FILTER;
            bad[offset] = value;
            assert_eq!(
                command.parse_response(&bad),
                Err(PefError::ReservedBits { field, value })
            );
        }
        let mut wrong = FILTER;
        wrong[1] = 2;
        assert_eq!(
            command.parse_response(&wrong),
            Err(PefError::UnexpectedIndex {
                expected: 3,
                actual: 2
            })
        );
        wrong[1] = 0x83;
        assert!(matches!(
            command.parse_response(&wrong),
            Err(PefError::ReservedBits { .. })
        ));
        let state = GetPefConfig {
            parameter: PefConfigParameter::FilterState(filter_id()),
        };
        assert_eq!(
            state.parse_response(&[0x11, 3, 0x80]),
            Ok(PefConfigValue::FilterState {
                id: filter_id(),
                enabled: true,
            })
        );
        assert!(matches!(
            state.parse_response(&[0x11, 3, 0x40]),
            Err(PefError::ReservedBits { .. })
        ));
        assert_eq!(Message::from(state).data(), [7, 3, 0]);
        assert_eq!(
            Message::from(SetPefConfig {
                value: PefWrite::FilterEnabled {
                    id: filter_id(),
                    enabled: false,
                }
            })
            .data(),
            [7, 3, 0]
        );
        assert_eq!(
            Message::from(SetPefConfig {
                value: PefWrite::FilterEnabled {
                    id: filter_id(),
                    enabled: true,
                }
            })
            .data(),
            [7, 3, 0x80]
        );
    }

    #[test]
    fn policy_fixture_round_trips_preserving_other_fields() {
        let command = GetPefConfig {
            parameter: PefConfigParameter::PolicyEntry(policy_id()),
        };
        assert_eq!(Message::from(command).data(), [9, 2, 0]);
        let PefConfigValue::PolicyEntry(mut entry) = command.parse_response(&POLICY).unwrap()
        else {
            panic!("expected policy");
        };
        assert_eq!(entry.policy.policy_set.value(), 2);
        assert!(entry.policy.enabled);
        assert_eq!(entry.policy.rule, PefPolicyRule::TryNextEntry);
        assert_eq!(entry.policy.channel, Channel::new(4).unwrap());
        assert_eq!(entry.policy.destination.value(), 1);
        assert_eq!(entry.policy.alert_string_key.key(), 5);
        assert!(entry.policy.alert_string_key.event_specific());
        assert_eq!(
            Message::from(SetPefConfig {
                value: PefWrite::PolicyEntry(entry)
            })
            .data(),
            [9, 2, 0x29, 0x41, 0x85]
        );
        entry.policy.enabled = false;
        assert_eq!(
            Message::from(SetPefConfig {
                value: PefWrite::PolicyEntry(entry)
            })
            .data(),
            [9, 2, 0x21, 0x41, 0x85]
        );
        for (response, error) in [
            (
                [0x11, 1, 0x29, 0x41, 0x85],
                PefError::UnexpectedIndex {
                    expected: 2,
                    actual: 1,
                },
            ),
            (
                [0x11, 2, 0x2f, 0x41, 0x85],
                PefError::InvalidValue {
                    field: "policy rule",
                    value: 7,
                },
            ),
            (
                [0x11, 2, 0x29, 0xc1, 0x85],
                PefError::InvalidValue {
                    field: "policy channel",
                    value: 12,
                },
            ),
        ] {
            assert_eq!(command.parse_response(&response), Err(error));
        }
        assert!(matches!(
            command.parse_response(&POLICY[..4]),
            Err(PefError::InvalidLength { .. })
        ));
    }

    #[test]
    fn completion_codes_and_guarded_partial_failures() {
        for (code, rejection) in [
            (0x80, PefRejection::UnsupportedParameter),
            (0x81, PefRejection::AlreadyInProgress),
            (0x82, PefRejection::ReadOnly),
        ] {
            assert_eq!(
                GetPefConfig::handle_completion_code(
                    CompletionErrorCode::CommandSpecific(code),
                    &[]
                ),
                Some(PefError::Rejected(rejection))
            );
            assert_eq!(
                SetPefConfig::handle_completion_code(
                    CompletionErrorCode::CommandSpecific(code),
                    &[]
                ),
                Some(PefError::Rejected(rejection))
            );
        }
        assert_eq!(
            GetPefConfig::handle_completion_code(CompletionErrorCode::ParameterOutOfRange, &[]),
            None
        );
        assert_eq!(
            SetPefConfig::parse_success_response(&[0]),
            Err(PefError::InvalidLength {
                expected: 0,
                actual: 1
            })
        );

        let change = PefChange::FilterEnabled {
            id: filter_id(),
            enabled: true,
        };
        let mut calls = Vec::new();
        let result = pef_write_guarded(
            |request| {
                calls.push(request.value);
                if matches!(
                    request.value,
                    PefWrite::SetInProgress(
                        PefSetInProgress::InProgress | PefSetInProgress::Complete
                    )
                ) {
                    Err("failed")
                } else {
                    Ok(())
                }
            },
            change,
        );
        assert_eq!(
            result,
            Err(PefWriteError::Begin {
                error: "failed",
                cleanup: Some("failed")
            })
        );
        assert_eq!(calls.len(), 2);
        calls.clear();

        let result = pef_write_guarded(
            |request| {
                calls.push(request.value);
                if matches!(
                    request.value,
                    PefWrite::FilterEnabled { .. }
                        | PefWrite::SetInProgress(PefSetInProgress::Complete)
                ) {
                    Err("failed")
                } else {
                    Ok(())
                }
            },
            change,
        );
        assert_eq!(
            result,
            Err(PefWriteError::Uncertain {
                write: Some("failed"),
                commit: None,
                cleanup: Some("failed"),
            })
        );
        assert_eq!(calls.len(), 3);
        calls.clear();

        let result = pef_write_guarded(
            |request| {
                calls.push(request.value);
                if request.value == PefWrite::SetInProgress(PefSetInProgress::CommitWrite) {
                    Err("commit failed")
                } else {
                    Ok(())
                }
            },
            change,
        );
        assert_eq!(
            result,
            Err(PefWriteError::Uncertain {
                write: None,
                commit: Some("commit failed"),
                cleanup: None,
            })
        );
        assert_eq!(calls.len(), 4);
        calls.clear();
        assert_eq!(
            pef_write_guarded(
                |request| {
                    calls.push(request.value);
                    if request.value == PefWrite::SetInProgress(PefSetInProgress::Complete) {
                        Err("cleanup failed")
                    } else {
                        Ok(())
                    }
                },
                change
            ),
            Err(PefWriteError::Uncertain {
                write: None,
                commit: None,
                cleanup: Some("cleanup failed")
            })
        );
        assert_eq!(calls.len(), 4);
        calls.clear();
        assert_eq!(
            pef_write_guarded(
                |request| {
                    calls.push(request.value);
                    Ok::<_, ()>(())
                },
                change
            ),
            Ok(())
        );
        assert_eq!(
            calls,
            [
                PefWrite::SetInProgress(PefSetInProgress::InProgress),
                PefWrite::FilterEnabled {
                    id: filter_id(),
                    enabled: true
                },
                PefWrite::SetInProgress(PefSetInProgress::CommitWrite),
                PefWrite::SetInProgress(PefSetInProgress::Complete),
            ]
        );
    }
}
