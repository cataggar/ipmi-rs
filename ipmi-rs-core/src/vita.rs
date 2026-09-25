//! Opt-in VITA 46.11 group-extension commands (NetFn `0x2c`, identifier `0x03`).
//!
//! First query [`GetVitaCapabilities`] and check its version. Select the correct
//! addressed BMC/bridged IPMB destination yourself. Mutations are always
//! explicit; timeout or lost acknowledgement leaves the outcome unknown.

use crate::group_extension::{
    ack, address, check, group_command, led_capabilities, led_properties, led_state, VITA_ID,
};
pub use crate::group_extension::{
    Activation, AddressInfo, FruControl, GroupError, LedCapabilities, LedFunction, LedOverride,
    LedProperties, LedSetting, LedState,
};

/// VSO capabilities, specification revision, and FRU inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VitaCapabilities {
    pub ipmc_identifier: u8,
    pub ipmb_capabilities: u8,
    pub standard: u8,
    pub revision_major: u8,
    pub revision_minor: u8,
    pub max_fru_id: u8,
    pub fru_id: u8,
}
impl VitaCapabilities {
    /// Refuse VSO standards other than VITA 46.11 and unsupported major revisions.
    pub fn require_supported(self) -> Result<Self, GroupError> {
        if self.standard & 3 == 0 && self.revision_major == 1 {
            Ok(self)
        } else {
            Err(GroupError::UnsupportedOperation)
        }
    }
}
/// Get VSO capabilities and version (`0x00`).
#[derive(Clone, Copy, Debug)]
pub struct GetVitaCapabilities;
group_command!(GetVitaCapabilities => VitaCapabilities, VITA_ID, 0x00,
|_v| vec![VITA_ID], |data| {
    let b = check(data, VITA_ID, 7, 7)?;
    Ok(VitaCapabilities {
        ipmc_identifier: b[1], ipmb_capabilities: b[2], standard: b[3],
        revision_major: b[4] & 0xf, revision_minor: b[4] >> 4,
        max_fru_id: b[5], fru_id: b[6],
    })
});

/// Get FRU site and IPMB-0 address (`0x40`); `fru_id=0` requests the default FRU.
#[derive(Clone, Copy, Debug)]
pub struct GetVitaAddress {
    pub fru_id: u8,
}
group_command!(GetVitaAddress => AddressInfo, VITA_ID, 0x40,
    |v| vec![VITA_ID, v.fru_id], |data| address(data, VITA_ID, true));

/// Explicitly activate or deactivate one FRU (`0x0c`).
#[derive(Clone, Copy, Debug)]
pub struct SetVitaActivation {
    pub fru_id: u8,
    pub action: Activation,
}
group_command!(SetVitaActivation => (), VITA_ID, 0x0c,
    |v| vec![VITA_ID, v.fru_id, v.action.value()], |data| ack(data, VITA_ID));

/// Get raw FRU state policy bits (`0x0b`), including unknown/OEM bits.
#[derive(Clone, Copy, Debug)]
pub struct GetVitaPolicy {
    pub fru_id: u8,
}
group_command!(GetVitaPolicy => u8, VITA_ID, 0x0b,
    |v| vec![VITA_ID, v.fru_id], |data| Ok(check(data, VITA_ID, 2, 2)?[1]));

/// Explicitly write selected VITA FRU state policy bits (`0x0a`).
#[derive(Clone, Copy, Debug)]
pub struct SetVitaPolicy {
    fru_id: u8,
    mask: u8,
    value: u8,
}
impl SetVitaPolicy {
    /// Bits: 0=activation locked, 1=deactivation locked,
    /// 2=commanded deactivation ignored, 3=default activation locked.
    pub fn new(fru_id: u8, mask: u8, value: u8) -> Result<Self, GroupError> {
        if mask & !0xf != 0 || value & !mask != 0 {
            return Err(GroupError::InvalidInput(
                "VITA policy uses bits 0..3; value must be masked",
            ));
        }
        Ok(Self {
            fru_id,
            mask,
            value,
        })
    }
}
group_command!(SetVitaPolicy => (), VITA_ID, 0x0a,
    |v| vec![VITA_ID, v.fru_id, v.mask, v.value], |data| ack(data, VITA_ID));

/// Explicit FRU control/reset (`0x04`); quiesce is not valid for VITA.
#[derive(Clone, Copy, Debug)]
pub struct VitaFruControl {
    fru_id: u8,
    action: FruControl,
}
impl VitaFruControl {
    pub fn new(fru_id: u8, action: FruControl) -> Result<Self, GroupError> {
        if action == FruControl::Quiesce {
            return Err(GroupError::UnsupportedOperation);
        }
        Ok(Self { fru_id, action })
    }
}
group_command!(VitaFruControl => (), VITA_ID, 0x04,
    |v| vec![VITA_ID, v.fru_id, v.action.value()], |data| ack(data, VITA_ID));

/// Get FRU LED inventory (`0x05`).
#[derive(Clone, Copy, Debug)]
pub struct GetVitaLedProperties {
    pub fru_id: u8,
}
group_command!(GetVitaLedProperties => LedProperties, VITA_ID, 0x05,
    |v| vec![VITA_ID, v.fru_id], |data| led_properties(data, VITA_ID));

/// Get LED color capabilities, local/override defaults and optional flags (`0x06`).
#[derive(Clone, Copy, Debug)]
pub struct GetVitaLedCapabilities {
    pub fru_id: u8,
    pub led_id: u8,
}
group_command!(GetVitaLedCapabilities => LedCapabilities, VITA_ID, 0x06,
    |v| vec![VITA_ID, v.fru_id, v.led_id], |data| led_capabilities(data, VITA_ID, true));

/// Get LED local, override and lamp-test state (`0x08`).
#[derive(Clone, Copy, Debug)]
pub struct GetVitaLedState {
    pub fru_id: u8,
    pub led_id: u8,
}
group_command!(GetVitaLedState => LedState, VITA_ID, 0x08,
    |v| vec![VITA_ID, v.fru_id, v.led_id], |data| led_state(data, VITA_ID));

/// Explicit LED override (`0x07`).
#[derive(Clone, Copy, Debug)]
pub struct SetVitaLedState {
    pub fru_id: u8,
    pub led_id: u8,
    pub setting: LedOverride,
}
group_command!(SetVitaLedState => (), VITA_ID, 0x07,
    |v| {
        let [function, duration, color] = v.setting.wire();
        vec![VITA_ID, v.fru_id, v.led_id, function, duration, color]
    }, |data| ack(data, VITA_ID));
