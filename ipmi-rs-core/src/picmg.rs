//! Opt-in PICMG/ATCA group-extension commands (NetFn `0x2c`, identifier `0x00`).
//!
//! Query [`GetPicmgProperties`] before using these commands; callers select the
//! correct BMC or bridged IPMB destination. Writes are explicit, single-shot
//! commands. A lost response leaves the outcome unknown: never retry a write
//! automatically.

use crate::group_extension::{
    ack, address, check, group_command, led_capabilities, led_properties, led_state, PICMG_ID,
};
pub use crate::group_extension::{
    Activation, AddressInfo, FruControl, GroupError, LedCapabilities, LedFunction, LedOverride,
    LedProperties, LedSetting, LedState,
};

/// PICMG extension version and FRU inventory. Unknown version numbers are retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PicmgProperties {
    pub major: u8,
    pub minor: u8,
    pub max_fru_id: u8,
    pub fru_id: u8,
}
impl PicmgProperties {
    /// Refuse commands on an unrecognized PICMG extension version.
    pub fn require_supported(self) -> Result<Self, GroupError> {
        if matches!(self.major, 2 | 4 | 5) {
            Ok(self)
        } else {
            Err(GroupError::UnsupportedOperation)
        }
    }
}

/// Get PICMG properties and extension version (command `0x00`).
#[derive(Clone, Copy, Debug)]
pub struct GetPicmgProperties;
group_command!(GetPicmgProperties => PicmgProperties, PICMG_ID, 0x00,
|_v| vec![PICMG_ID], |data| {
    let b = check(data, PICMG_ID, 4, 4)?;
    Ok(PicmgProperties { major: b[1] & 0xf, minor: b[1] >> 4, max_fru_id: b[2], fru_id: b[3] })
});

/// Read physical FRU location and IPMB-0 address (`0x01`).
#[derive(Clone, Copy, Debug)]
pub struct GetPicmgAddress {
    pub fru_id: u8,
}
group_command!(GetPicmgAddress => AddressInfo, PICMG_ID, 0x01,
    |v| vec![PICMG_ID, v.fru_id], |data| address(data, PICMG_ID, false));

/// Requested FRU activation; affects a specific shelf/slot FRU (`0x0c`).
#[derive(Clone, Copy, Debug)]
pub struct SetPicmgActivation {
    pub fru_id: u8,
    pub action: Activation,
}
group_command!(SetPicmgActivation => (), PICMG_ID, 0x0c,
    |v| vec![PICMG_ID, v.fru_id, v.action.value()], |data| ack(data, PICMG_ID));

/// Read the FRU activation-lock policy (`0x0b`). Bits beyond bit 1 are retained.
#[derive(Clone, Copy, Debug)]
pub struct GetPicmgPolicy {
    pub fru_id: u8,
}
group_command!(GetPicmgPolicy => u8, PICMG_ID, 0x0b,
    |v| vec![PICMG_ID, v.fru_id], |data| Ok(check(data, PICMG_ID, 2, 2)?[1]));

/// Explicitly modify selected FRU policy bits (`0x0a`).
#[derive(Clone, Copy, Debug)]
pub struct SetPicmgPolicy {
    fru_id: u8,
    mask: u8,
    value: u8,
}
impl SetPicmgPolicy {
    /// Bits: 0=activation locked, 1=deactivation locked.
    pub fn new(fru_id: u8, mask: u8, value: u8) -> Result<Self, GroupError> {
        if mask & !3 != 0 || value & !mask != 0 {
            return Err(GroupError::InvalidInput(
                "PICMG policy uses bits 0..1; value must be masked",
            ));
        }
        Ok(Self {
            fru_id,
            mask,
            value,
        })
    }
}
group_command!(SetPicmgPolicy => (), PICMG_ID, 0x0a,
    |v| vec![PICMG_ID, v.fru_id, v.mask, v.value], |data| ack(data, PICMG_ID));

/// Explicit FRU control/reset (`0x04`); quiesce is only valid for an AMC.
#[derive(Clone, Copy, Debug)]
pub struct PicmgFruControl {
    pub fru_id: u8,
    pub action: FruControl,
}
group_command!(PicmgFruControl => (), PICMG_ID, 0x04,
    |v| vec![PICMG_ID, v.fru_id, v.action.value()], |data| ack(data, PICMG_ID));

/// Read FRU LED inventory (`0x05`).
#[derive(Clone, Copy, Debug)]
pub struct GetPicmgLedProperties {
    pub fru_id: u8,
}
group_command!(GetPicmgLedProperties => LedProperties, PICMG_ID, 0x05,
    |v| vec![PICMG_ID, v.fru_id], |data| led_properties(data, PICMG_ID));

/// Read LED color capabilities (`0x06`); colors and OEM flags are raw.
#[derive(Clone, Copy, Debug)]
pub struct GetPicmgLedCapabilities {
    pub fru_id: u8,
    pub led_id: u8,
}
group_command!(GetPicmgLedCapabilities => LedCapabilities, PICMG_ID, 0x06,
    |v| vec![PICMG_ID, v.fru_id, v.led_id], |data| led_capabilities(data, PICMG_ID, false));

/// Read local/override LED state (`0x08`).
#[derive(Clone, Copy, Debug)]
pub struct GetPicmgLedState {
    pub fru_id: u8,
    pub led_id: u8,
}
group_command!(GetPicmgLedState => LedState, PICMG_ID, 0x08,
    |v| vec![PICMG_ID, v.fru_id, v.led_id], |data| led_state(data, PICMG_ID));

/// Explicit LED override (`0x07`); `0xff` LED ID selects all managed LEDs.
#[derive(Clone, Copy, Debug)]
pub struct SetPicmgLedState {
    pub fru_id: u8,
    pub led_id: u8,
    pub setting: LedOverride,
}
group_command!(SetPicmgLedState => (), PICMG_ID, 0x07,
    |v| {
        let [function, duration, color] = v.setting.wire();
        vec![PICMG_ID, v.fru_id, v.led_id, function, duration, color]
    }, |data| ack(data, PICMG_ID));

/// Power draw query type (`0x12`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerType {
    SteadyState,
    DesiredSteadyState,
    Early,
    DesiredEarly,
}
impl PowerType {
    pub const fn value(self) -> u8 {
        self as u8
    }
}

/// PICMG power levels, with draw units preserved as raw bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PowerLevels {
    pub state: u8,
    pub delay_to_stable: u8,
    pub multiplier: u8,
    pub draws: Vec<u8>,
}
/// Read FRU power levels (`0x12`).
#[derive(Clone, Copy, Debug)]
pub struct GetPicmgPower {
    pub fru_id: u8,
    pub power_type: PowerType,
}
group_command!(GetPicmgPower => PowerLevels, PICMG_ID, 0x12,
|v| vec![PICMG_ID, v.fru_id, v.power_type.value()], |data| {
    let b = check(data, PICMG_ID, 4, 24)?;
    Ok(PowerLevels { state: b[1], delay_to_stable: b[2], multiplier: b[3], draws: b[4..].to_vec() })
});

/// Power target: off, a numbered level 1..=20, or unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerLevel {
    Off,
    Level(u8),
    Unchanged,
}
impl PowerLevel {
    pub fn value(self) -> Result<u8, GroupError> {
        match self {
            Self::Off => Ok(0),
            Self::Level(n @ 1..=20) => Ok(n),
            Self::Unchanged => Ok(0xff),
            Self::Level(_) => Err(GroupError::InvalidInput("power level must be 1..=20")),
        }
    }
}
/// Explicitly set power level and optionally copy desired to present (`0x11`).
#[derive(Clone, Copy, Debug)]
pub struct SetPicmgPower {
    fru_id: u8,
    level: u8,
    copy_desired_to_present: bool,
}
impl SetPicmgPower {
    pub fn new(
        fru_id: u8,
        level: PowerLevel,
        copy_desired_to_present: bool,
    ) -> Result<Self, GroupError> {
        Ok(Self {
            fru_id,
            level: level.value()?,
            copy_desired_to_present,
        })
    }
}
group_command!(SetPicmgPower => (), PICMG_ID, 0x11,
    |v| vec![PICMG_ID, v.fru_id, v.level, v.copy_desired_to_present as u8],
    |data| ack(data, PICMG_ID));

/// ATCA port selector; interface 0..=3 and channel 0..=63.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortSelector(u8);
impl PortSelector {
    pub fn new(interface: u8, channel: u8) -> Result<Self, GroupError> {
        if interface > 3 || channel > 63 {
            return Err(GroupError::InvalidInput(
                "interface must be <=3 and channel <=63",
            ));
        }
        Ok(Self(channel | interface << 6))
    }
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// One port link descriptor; unknown/OEM link types and states remain raw.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortLink {
    pub designator: u8,
    pub port: u8,
    pub link_type: u8,
    pub extension: u8,
    pub grouping: u8,
    pub state: u8,
}
/// Get up to four ATCA port link descriptors (`0x0f`).
#[derive(Clone, Copy, Debug)]
pub struct GetPicmgPortState {
    pub selector: PortSelector,
}
group_command!(GetPicmgPortState => Vec<PortLink>, PICMG_ID, 0x0f,
|v| vec![PICMG_ID, v.selector.value()], |data| {
    let b = check(data, PICMG_ID, 6, 21)?;
    if (b.len() - 1) % 5 != 0 {
        return Err(GroupError::InvalidLength { min: 6, max: 21, actual: b.len() });
    }
    let (links, _) = b[1..].as_chunks::<5>();
    Ok(links.iter().map(|link| PortLink {
        designator: link[0],
        port: link[1] & 0xf,
        link_type: (link[1] >> 4) | ((link[2] & 0xf) << 4),
        extension: link[2] >> 4,
        grouping: link[3],
        state: link[4],
    }).collect())
});

/// Validated descriptor for a port-state write. Unknown link types are raw.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortWrite {
    port: u8,
    link_type: u8,
    extension: u8,
    grouping: u8,
    enabled: bool,
}
impl PortWrite {
    pub fn new(
        port: u8,
        link_type: u8,
        extension: u8,
        grouping: u8,
        enabled: bool,
    ) -> Result<Self, GroupError> {
        if port > 15 || extension > 15 {
            return Err(GroupError::InvalidInput(
                "port and extension must fit four bits",
            ));
        }
        Ok(Self {
            port,
            link_type,
            extension,
            grouping,
            enabled,
        })
    }
    fn bytes(self) -> [u8; 4] {
        [
            self.port | (self.link_type << 4),
            (self.link_type >> 4) | (self.extension << 4),
            self.grouping,
            self.enabled as u8,
        ]
    }
}
/// Explicitly enable or disable a selected ATCA port link (`0x0e`).
#[derive(Clone, Copy, Debug)]
pub struct SetPicmgPortState {
    pub selector: PortSelector,
    pub link: PortWrite,
}
group_command!(SetPicmgPortState => (), PICMG_ID, 0x0e,
    |v| {
        let mut payload = vec![PICMG_ID, v.selector.value()];
        payload.extend_from_slice(&v.link.bytes());
        payload
    }, |data| ack(data, PICMG_ID));

/// AMC.0 port link. Unknown link types and enabled values remain raw.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmcPortLink {
    pub port: u8,
    pub link_type: u8,
    pub extension: u8,
    pub grouping: u8,
    pub state: u8,
}
/// Get up to four AMC port links (`0x1a`). `device` is for a carrier.
#[derive(Clone, Copy, Debug)]
pub struct GetAmcPortState {
    pub channel: u8,
    pub device: Option<u8>,
}
group_command!(GetAmcPortState => Vec<AmcPortLink>, PICMG_ID, 0x1a,
|v| {
    let mut payload = vec![PICMG_ID, v.channel];
    payload.extend(v.device);
    payload
}, |data| {
    let b = check(data, PICMG_ID, 5, 17)?;
    if (b.len() - 1) % 4 != 0 {
        return Err(GroupError::InvalidLength { min: 5, max: 17, actual: b.len() });
    }
    let (links, _) = b[1..].as_chunks::<4>();
    Ok(links.iter().map(|link| AmcPortLink {
        port: link[0] & 0xf,
        link_type: (link[0] >> 4) | ((link[1] & 0xf) << 4),
        extension: link[1] >> 4,
        grouping: link[2],
        state: link[3],
    }).collect())
});
/// Explicit AMC port-state write (`0x19`). Carrier requests supply `device`.
#[derive(Clone, Copy, Debug)]
pub struct SetAmcPortState {
    pub channel: u8,
    pub device: Option<u8>,
    pub link: PortWrite,
}
group_command!(SetAmcPortState => (), PICMG_ID, 0x19,
    |v| {
        let mut payload = vec![PICMG_ID, v.channel];
        payload.extend_from_slice(&v.link.bytes());
        payload.extend(v.device);
        payload
    }, |data| ack(data, PICMG_ID));

/// Clock state for AMC.0 (`0x2d`); unrecognized settings and clock families remain raw.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockState {
    pub setting: u8,
    pub index: Option<u8>,
    pub family: Option<u8>,
    pub accuracy: Option<u8>,
    pub frequency: Option<u32>,
}
/// Get clock state; `resource` is for ATCA carriers, omit for AMC modules.
#[derive(Clone, Copy, Debug)]
pub struct GetAmcClockState {
    pub clock_id: u8,
    pub resource: Option<u8>,
}
group_command!(GetAmcClockState => ClockState, PICMG_ID, 0x2d,
|v| {
    let mut payload = vec![PICMG_ID, v.clock_id];
    payload.extend(v.resource);
    payload
}, |data| {
    let b = check(data, PICMG_ID, 2, 9)?;
    let enabled = b[1] & 8 != 0;
    let expected = if enabled { 9 } else { 2 };
    if b.len() != expected {
        return Err(GroupError::InvalidLength { min: expected, max: expected, actual: b.len() });
    }
    Ok(ClockState {
        setting: b[1],
        index: enabled.then(|| b[2]),
        family: enabled.then(|| b[3]),
        accuracy: enabled.then(|| b[4]),
        frequency: enabled.then(|| u32::from_le_bytes(b[5..9].try_into().unwrap())),
    })
});

/// Explicit AMC clock write. `resource` is mandatory on an ATCA carrier.
#[derive(Clone, Copy, Debug)]
pub struct SetAmcClockState {
    clock_id: u8,
    index: u8,
    setting: ClockSetting,
    family: u8,
    accuracy: u8,
    frequency: u32,
    resource: Option<u8>,
}
/// Validated clock control bits: state, direction and PLL control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockSetting(u8);
impl ClockSetting {
    /// Create clock state bits (source=true, PLL control 0..=2).
    pub fn new(enabled: bool, source: bool, pll: u8) -> Result<Self, GroupError> {
        if pll > 2 {
            return Err(GroupError::InvalidInput("PLL setting 3 is reserved"));
        }
        Ok(Self(((enabled as u8) << 3) | ((source as u8) << 2) | pll))
    }
    /// The wire setting (bits 7..4 always zero).
    pub const fn value(self) -> u8 {
        self.0
    }
}
impl SetAmcClockState {
    /// Select the clock setting, frequency and optional carrier resource ID.
    pub fn new(
        clock_id: u8,
        index: u8,
        setting: ClockSetting,
        family: u8,
        accuracy: u8,
        frequency: u32,
        resource: Option<u8>,
    ) -> Self {
        Self {
            clock_id,
            index,
            setting,
            family,
            accuracy,
            frequency,
            resource,
        }
    }
}
group_command!(SetAmcClockState => (), PICMG_ID, 0x2c,
    |v| {
        let mut payload = vec![PICMG_ID, v.clock_id, v.index, v.setting.value(), v.family, v.accuracy];
        payload.extend_from_slice(&v.frequency.to_le_bytes());
        payload.extend(v.resource);
        payload
    }, |data| ack(data, PICMG_ID));

/// Bused resource IDs supported by ipmitool's summary (`0x17`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BusResource {
    MetalTestBus1,
    MetalTestBus2,
    SyncClockGroup1,
    SyncClockGroup2,
    SyncClockGroup3,
}
/// Query one bus resource, never mutate it; repeat explicitly for a summary.
#[derive(Clone, Copy, Debug)]
pub struct GetPicmgBusResource {
    pub resource: BusResource,
}
group_command!(GetPicmgBusResource => u8, PICMG_ID, 0x17,
    |v| vec![PICMG_ID, 0, v.resource as u8],
    |data| Ok(check(data, PICMG_ID, 2, 2)?[1]));
