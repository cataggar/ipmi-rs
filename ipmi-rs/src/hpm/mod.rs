//! HPM.1 component inventory and explicit firmware update workflow.
//!
//! Inventory and status reads work without `hpm-update`. Firmware mutation is
//! opt-in and never triggered by inspecting or parsing a package.

use ipmi_rs_core::{
    app::{DeviceId, GetDeviceId},
    connection::{CompletionErrorCode, IpmiConnection, NetFn, NotEnoughData},
    hpm::{
        ComponentId, ComponentProperty, FirmwareVersion, GeneralProperties, GetComponentProperty,
        GetTargetCapabilities, HpmResponseError, TargetCapabilities,
    },
};

use crate::{Ipmi, IpmiError};

#[cfg(feature = "hpm-update")]
pub mod package;
#[cfg(feature = "hpm-update")]
pub mod update;
#[cfg(feature = "hpm-update")]
pub use ipmi_rs_core::hpm::AbortUpgrade;

#[cfg(test)]
mod tests;

/// A single component's reported firmware state.
#[derive(Debug, Clone, PartialEq)]
pub struct ComponentInventory {
    /// Component index.
    pub id: ComponentId,
    /// Raw general component properties.
    pub general: GeneralProperties,
    /// Description bytes; may not be valid text.
    pub description: [u8; 12],
    /// Currently running firmware version.
    pub current: FirmwareVersion,
    /// Reported rollback firmware, or `None` if unsupported or no rollback
    /// image is present (queried only when rollback/backup is advertised).
    pub rollback: Option<FirmwareVersion>,
    /// Reported deferred firmware, or `None` if unsupported or no deferred
    /// image is present (queried only when deferred activation is advertised).
    pub deferred: Option<FirmwareVersion>,
}

/// Read-only device ID, HPM.1 capabilities and all present components.
#[derive(Debug, Clone, PartialEq)]
pub struct Inventory {
    /// Device identity (also used for package compatibility checks).
    pub device: DeviceId,
    /// HPM.1 capabilities.
    pub capabilities: TargetCapabilities,
    /// Properties for the components present in the capabilities response.
    pub components: Vec<ComponentInventory>,
}

/// Error reading device identity or HPM.1 inventory.
#[derive(Debug)]
pub enum InventoryError<E> {
    /// Failed to get the IPMI device ID.
    Device(IpmiError<E, NotEnoughData>),
    /// Failed to get or parse PICMG HPM.1 properties.
    Hpm(IpmiError<E, HpmResponseError>),
}

fn property<CON: IpmiConnection, const S: u8>(
    ipmi: &mut Ipmi<CON>,
    component: ComponentId,
) -> Result<ComponentProperty, InventoryError<CON::Error>> {
    ipmi.send_recv(GetComponentProperty::<S>::new(component))
        .map_err(InventoryError::Hpm)
}

fn optional_version<CON: IpmiConnection, const S: u8>(
    ipmi: &mut Ipmi<CON>,
    component: ComponentId,
) -> Result<Option<ComponentProperty>, InventoryError<CON::Error>> {
    match property::<CON, S>(ipmi, component) {
        Ok(version) => Ok(Some(version)),
        Err(InventoryError::Hpm(IpmiError::Failed {
            netfn: NetFn::Reserved(0x2d),
            cmd: 0x2f,
            completion_code:
                CompletionErrorCode::CommandSpecific(0x81 | 0x83)
                | CompletionErrorCode::RequestedDatapointNotPresent,
            ..
        })) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Fetch a complete typed inventory, including optional rollback/deferred
/// versions when the component advertises support. An optional image slot
/// returning HPM.1 Not Supported (`0x81`), Invalid Component Property (`0x83`)
/// or IPMI Requested Data Not Present (`0xcb`) is represented as `None`; all
/// other errors, including transport and malformed replies, are propagated.
/// Sends only read commands.
pub fn read_inventory<CON: IpmiConnection>(
    ipmi: &mut Ipmi<CON>,
) -> Result<Inventory, InventoryError<CON::Error>> {
    let device = ipmi
        .send_recv(GetDeviceId)
        .map_err(InventoryError::Device)?;
    let capabilities = ipmi
        .send_recv(GetTargetCapabilities)
        .map_err(InventoryError::Hpm)?;
    let mut components = Vec::new();
    for id in 0..8 {
        let id = ComponentId::new(id).expect("HPM component number");
        if capabilities.components & id.bit() == 0 {
            continue;
        }
        let ComponentProperty::General(general) = property::<_, 0>(ipmi, id)? else {
            unreachable!("selector zero");
        };
        let ComponentProperty::Description(description) = property::<_, 2>(ipmi, id)? else {
            unreachable!("selector two");
        };
        let ComponentProperty::Current(current) = property::<_, 1>(ipmi, id)? else {
            unreachable!("selector one");
        };
        let rollback = if general.rollback_backup != 0 {
            optional_version::<_, 3>(ipmi, id)?.map(|property| {
                let ComponentProperty::Rollback(version) = property else {
                    unreachable!("selector three");
                };
                version
            })
        } else {
            None
        };
        let deferred = if general.deferred_activation {
            optional_version::<_, 4>(ipmi, id)?.map(|property| {
                let ComponentProperty::Deferred(version) = property else {
                    unreachable!("selector four");
                };
                version
            })
        } else {
            None
        };
        components.push(ComponentInventory {
            id,
            general,
            description,
            current,
            rollback,
            deferred,
        });
    }
    Ok(Inventory {
        device,
        capabilities,
        components,
    })
}
