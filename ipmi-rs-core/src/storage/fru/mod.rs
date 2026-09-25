//! FRU inventory commands and checked inventory image decoding.
//!
//! SDR FRU locators identify devices; they are not FRU inventory images.
mod commands;
mod inventory;

pub use commands::*;
pub use inventory::*;

use crate::{
    connection::{Address, Channel, LogicalUnit},
    storage::sdr::record::{FruDevice as SdrFruDevice, RecordContents},
    storage::sdr::Record,
};

/// A candidate FRU inventory device. An SDR locator is only an address/ID,
/// not the contents of that device's inventory.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FruDevice {
    /// Inventory ID used by the FRU storage commands.
    pub id: u8,
    /// None for the built-in device; some locators require a bridged target.
    pub target: Option<(Address, Channel)>,
    /// The inventory access logical unit from the SDR locator.
    pub lun: LogicalUnit,
}

impl FruDevice {
    /// The built-in BMC FRU inventory device (ID 0).
    pub const BUILTIN: Self = Self {
        id: 0,
        target: None,
        lun: LogicalUnit::Zero,
    };
}

/// Discover the built-in FRU and logical FRU inventory locators in SDRs.
///
/// This does not query devices or assert that the built-in inventory is
/// supported. Physical EEPROM and non-inventory locators are not IPMI FRU
/// storage-command targets.
pub fn discover_fru_devices<'a>(records: impl IntoIterator<Item = &'a Record>) -> Vec<FruDevice> {
    let mut devices = vec![FruDevice::BUILTIN];
    for record in records {
        let device = match &record.contents {
            RecordContents::FruDeviceLocator(locator) => {
                let SdrFruDevice::Logical(logical) = &locator.record_key.fru_device else {
                    continue;
                };
                if !((locator.device_type == 0x10
                    && matches!(locator.device_type_modifier, 0x00 | 0x02))
                    || ((0x08..=0x0f).contains(&locator.device_type)
                        && locator.device_type_modifier == 0x02))
                {
                    continue;
                }
                let key = &locator.record_key;
                let Some(channel) = Channel::new(key.channel_number & 0x0f) else {
                    continue;
                };
                FruDevice {
                    id: logical.fru_device_id,
                    target: Some((Address(key.device_access_address << 1), channel)),
                    lun: key.lun,
                }
            }
            RecordContents::McDeviceLocator(mc) if mc.device_capabilities.fru_inventory_device => {
                let Some(channel) = Channel::new(mc.key.channel) else {
                    continue;
                };
                FruDevice {
                    id: 0,
                    target: Some((Address(mc.key.i2c_address << 1), channel)),
                    lun: LogicalUnit::Zero,
                }
            }
            _ => continue,
        };
        if !devices.contains(&device) {
            devices.push(device);
        }
    }
    devices
}
