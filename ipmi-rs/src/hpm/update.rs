//! Explicit, bounded, non-retrying HPM.1 firmware operations.
//!
//! A confirmed upload block counts only after its complete reply is validated.
//! Lost or ambiguous mutation replies retain a pending operation in the state.
//! No subsequent write is attempted by `upload` on any such error.

use ipmi_rs_core::{
    connection::{IpmiCommand, IpmiConnection},
    hpm::{
        ActivateFirmware, ComponentId, ComponentMask, FinishFirmwareUpload, GetUpgradeStatus,
        HpmResponseError, InitiateUpgradeAction, ManualFirmwareRollback, QueryRollbackStatus,
        QuerySelfTestResult, RollbackStatus, SelfTestResult, UpgradeAction, UpgradeStatus,
        UploadFirmwareBlock,
    },
};

use crate::{Ipmi, IpmiError};

use super::{
    package::{Package, PackageAction},
    Inventory,
};

/// Which update phase has received a confirmed response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Target and package checked; nothing has been written.
    Prepared,
    /// At least one mutation was attempted.
    Uploading,
    /// All upload actions and finish commands were acknowledged.
    Uploaded,
    /// Activation request acknowledged; firmware operation may still be in progress.
    ActivationAcknowledged,
    /// Manual rollback request acknowledged; completion must be queried separately.
    RollbackAcknowledged,
}

/// The precise mutation attempted, whether confirmed or uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Initiation of backup, preparation or upgrade for the given components.
    Initiate(UpgradeAction, u8),
    /// Block number, image offset and length.
    Upload { block: u8, offset: u32, length: u8 },
    /// Finish the given component's upload.
    Finish(ComponentId),
    /// Activate previously uploaded firmware.
    Activate,
    /// Request manual rollback.
    Rollback,
}

/// Snapshot of confirmed progress and any operation whose result is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferState {
    /// Last phase confirmed by the target.
    pub phase: Phase,
    /// Index of the package action being processed.
    pub action_index: usize,
    /// Last selected image component (if one has been started).
    pub component: Option<ComponentId>,
    /// Confirmed bytes of this component's image, not including a pending block.
    pub confirmed_bytes: u32,
    /// Total bytes in the current image.
    pub total_bytes: u32,
    /// Number of images with a confirmed finish command.
    pub finished_images: usize,
    /// A mutation with no validated success response; never retry it automatically.
    pub uncertain: Option<Operation>,
}

/// Explicit transfer limits. LAN-safe block size is at most 23 bytes of image
/// data (25 bytes of total PICMG request data).
#[derive(Debug, Clone, Copy)]
pub struct UpdateOptions {
    /// Bytes per upload block, 1..=23.
    pub chunk_size: u8,
    /// Maximum upload blocks allowed across this package; checked before writes.
    pub max_blocks: u32,
    /// Caller acknowledges that the update may interrupt services.
    pub allow_service_disruption: bool,
}

impl UpdateOptions {
    /// Validate explicit limits and service-disruption policy.
    pub fn new(chunk_size: u8, max_blocks: u32, allow_service_disruption: bool) -> Option<Self> {
        if chunk_size == 0 || chunk_size > 23 || max_blocks == 0 {
            return None;
        }
        Some(Self {
            chunk_size,
            max_blocks,
            allow_service_disruption,
        })
    }
}

/// An update error preserves confirmed progress and ambiguous outcomes.
#[derive(Debug)]
pub enum UpdateError<E> {
    /// The package and target are not compatible, or a required capability is absent.
    Incompatible(&'static str),
    /// The transfer would exceed caller-specified limits.
    Limit,
    /// The operation is not valid in this phase, or unresolved state requires recovery.
    InvalidState(TransferState),
    /// The callback cancelled the operation between mutations; no abort is sent.
    Cancelled(TransferState),
    /// A section directive cannot be honored without skipping or resending bytes.
    UnsupportedSection(TransferState),
    /// A mutation was attempted without a validated success response. The pending
    /// operation may or may not have executed; no further write is attempted.
    Uncertain {
        /// State including the operation with unknown outcome.
        state: TransferState,
        /// The IPMI failure, completion code, or malformed acknowledgement.
        source: IpmiError<E, HpmResponseError>,
    },
    /// A read failed; it does not change confirmed mutation state.
    Read(IpmiError<E, HpmResponseError>),
}

/// A validated, explicitly controlled update session. Construction and
/// `state` perform no IO; `upload`, `activate`, and `rollback` each require a
/// separate caller invocation. Dropping a session never sends an abort.
pub struct Updater<'a, 'c, CON> {
    ipmi: &'c mut Ipmi<CON>,
    package: &'a Package<'a>,
    inventory: &'a Inventory,
    options: UpdateOptions,
    state: TransferState,
}

impl<'a, 'c, CON: IpmiConnection> Updater<'a, 'c, CON> {
    /// Preflight the whole package against a freshly read target inventory,
    /// component properties, device revision and the caller's transfer limits.
    /// No write or implicit inventory read occurs here.
    pub fn new(
        ipmi: &'c mut Ipmi<CON>,
        package: &'a Package<'a>,
        inventory: &'a Inventory,
        options: UpdateOptions,
    ) -> Result<Self, UpdateError<CON::Error>> {
        let h = &package.header;
        let d = &inventory.device;
        if h.device_id != d.device_id
            || u32::from_le_bytes([h.manufacturer[0], h.manufacturer[1], h.manufacturer[2], 0])
                != d.manufacturer_id
            || h.product != d.product_id
        {
            return Err(UpdateError::Incompatible(
                "device/manufacturer/product mismatch",
            ));
        }
        let [major, minor] = h.earliest_revision;
        if minor >> 4 > 9 || minor & 0x0f > 9 {
            return Err(UpdateError::Incompatible("invalid BCD compatible revision"));
        }
        let minor = (minor >> 4) * 10 + (minor & 0x0f);
        if (major, minor) > (d.major_fw_revision, d.minor_fw_revision) {
            return Err(UpdateError::Incompatible("device firmware is too old"));
        }
        let caps = inventory.capabilities;
        if caps.upgrade_undesirable {
            return Err(UpdateError::Incompatible(
                "upgrade is currently undesirable",
            ));
        }
        if h.components.bits() & !caps.components != 0 {
            return Err(UpdateError::Incompatible("component absent from target"));
        }
        if (caps.services_affected || h.capabilities & 0x10 != 0)
            && !options.allow_service_disruption
        {
            return Err(UpdateError::Incompatible(
                "service disruption not acknowledged",
            ));
        }
        if options.chunk_size == 0 || options.chunk_size > 23 || options.max_blocks == 0 {
            return Err(UpdateError::Limit);
        }
        let mut blocks = 0u32;
        for action in package.actions() {
            match action {
                PackageAction::Backup(mask) | PackageAction::Prepare(mask) => {
                    for component in &inventory.components {
                        if mask.bits() & component.id.bit() != 0 {
                            let supported = match action {
                                PackageAction::Backup(_) => component.general.rollback_backup != 0,
                                _ => component.general.preparation,
                            };
                            if !supported {
                                return Err(UpdateError::Incompatible(
                                    "backup or prepare unsupported by component",
                                ));
                            }
                        }
                    }
                }
                PackageAction::Upload {
                    component, data, ..
                } => {
                    if !inventory.components.iter().any(|v| v.id == *component) {
                        return Err(UpdateError::Incompatible("component inventory missing"));
                    }
                    let count = data.len().div_ceil(options.chunk_size as usize) as u32;
                    blocks = blocks.checked_add(count).ok_or(UpdateError::Limit)?;
                    if blocks > options.max_blocks {
                        return Err(UpdateError::Limit);
                    }
                }
            }
        }
        Ok(Self {
            ipmi,
            package,
            inventory,
            options,
            state: TransferState {
                phase: Phase::Prepared,
                action_index: 0,
                component: None,
                confirmed_bytes: 0,
                total_bytes: 0,
                finished_images: 0,
                uncertain: None,
            },
        })
    }

    /// Get the current confirmed and uncertain state without sending a request.
    pub fn state(&self) -> TransferState {
        self.state
    }

    fn send_write<C: IpmiCommand<Output = (), Error = HpmResponseError>>(
        &mut self,
        operation: Operation,
        command: C,
    ) -> Result<(), UpdateError<CON::Error>> {
        if self.state.phase == Phase::Prepared {
            self.state.phase = Phase::Uploading;
        }
        self.state.uncertain = Some(operation);
        match self.ipmi.send_recv(command) {
            Ok(()) => {
                self.state.uncertain = None;
                Ok(())
            }
            Err(source) => Err(UpdateError::Uncertain {
                state: self.state,
                source,
            }),
        }
    }

    fn checkpoint<F: FnMut(TransferState) -> bool>(
        &self,
        progress: &mut F,
    ) -> Result<(), UpdateError<CON::Error>> {
        if progress(self.state) {
            Ok(())
        } else {
            Err(UpdateError::Cancelled(self.state))
        }
    }

    /// Execute all package actions in order; no activation is performed.
    /// `progress` sees confirmed bytes and may cancel *between* commands by
    /// returning false. Cancellation never sends an implicit abort or rollback.
    /// Each action and block is sent at most once. A lost/malformed reply stops
    /// immediately and marks the attempted operation uncertain.
    pub fn upload<F: FnMut(TransferState) -> bool>(
        &mut self,
        mut progress: F,
    ) -> Result<TransferState, UpdateError<CON::Error>> {
        if self.state.phase != Phase::Prepared || self.state.uncertain.is_some() {
            return Err(UpdateError::InvalidState(self.state));
        }
        self.checkpoint(&mut progress)?;
        for (index, action) in self.package.actions().iter().enumerate() {
            self.state.action_index = index;
            match action {
                PackageAction::Backup(mask) | PackageAction::Prepare(mask) => {
                    let action_type = if matches!(action, PackageAction::Backup(_)) {
                        UpgradeAction::Backup
                    } else {
                        UpgradeAction::Prepare
                    };
                    self.checkpoint(&mut progress)?;
                    self.send_write(
                        Operation::Initiate(action_type, mask.bits()),
                        InitiateUpgradeAction {
                            components: *mask,
                            action: action_type,
                        },
                    )?;
                }
                PackageAction::Upload {
                    component, data, ..
                } => {
                    self.state.component = Some(*component);
                    self.state.confirmed_bytes = 0;
                    self.state.total_bytes = data.len() as u32;
                    self.checkpoint(&mut progress)?;
                    self.send_write(
                        Operation::Initiate(UpgradeAction::Upgrade, component.bit()),
                        InitiateUpgradeAction {
                            components: ComponentMask::new(component.bit()).expect("valid bit"),
                            action: UpgradeAction::Upgrade,
                        },
                    )?;
                    for (block_index, chunk) in
                        data.chunks(self.options.chunk_size as usize).enumerate()
                    {
                        self.checkpoint(&mut progress)?;
                        let number = block_index as u8;
                        let op = Operation::Upload {
                            block: number,
                            offset: self.state.confirmed_bytes,
                            length: chunk.len() as u8,
                        };
                        self.state.uncertain = Some(op);
                        let command =
                            UploadFirmwareBlock::new(number, chunk).expect("bounded chunk");
                        let acknowledgement = match self.ipmi.send_recv(command) {
                            Ok(ack) => ack,
                            Err(source) => {
                                return Err(UpdateError::Uncertain {
                                    state: self.state,
                                    source,
                                })
                            }
                        };
                        self.state.uncertain = None;
                        self.state.confirmed_bytes += chunk.len() as u32;
                        if let Some((offset, length)) = acknowledgement.next_section {
                            let remaining = self.state.total_bytes - self.state.confirmed_bytes;
                            if !(offset == 0 && length == 0)
                                && (offset != self.state.confirmed_bytes || length != remaining)
                            {
                                return Err(UpdateError::UnsupportedSection(self.state));
                            }
                        }
                        self.checkpoint(&mut progress)?;
                    }
                    self.checkpoint(&mut progress)?;
                    self.send_write(
                        Operation::Finish(*component),
                        FinishFirmwareUpload {
                            component: *component,
                            length: self.state.confirmed_bytes,
                        },
                    )?;
                    self.state.finished_images += 1;
                }
            }
            if index + 1 == self.package.actions().len() {
                self.state.phase = Phase::Uploaded;
            }
            self.checkpoint(&mut progress)?;
        }
        self.state.phase = Phase::Uploaded;
        Ok(self.state)
    }

    /// Explicitly request activation only after every upload is confirmed.
    /// This does not poll self-test, reset the target, or silently roll back.
    pub fn activate(&mut self) -> Result<TransferState, UpdateError<CON::Error>> {
        if self.state.phase != Phase::Uploaded || self.state.uncertain.is_some() {
            return Err(UpdateError::InvalidState(self.state));
        }
        self.send_write(Operation::Activate, ActivateFirmware)?;
        self.state.phase = Phase::ActivationAcknowledged;
        Ok(self.state)
    }

    /// Explicitly request manual rollback, if the inventory advertises it.
    /// The request acknowledgement is not proof rollback completed; use
    /// `rollback_status` to observe the outcome (including failure code `0x81`).
    pub fn rollback(&mut self) -> Result<TransferState, UpdateError<CON::Error>> {
        if self.state.uncertain.is_some() || self.state.phase == Phase::RollbackAcknowledged {
            return Err(UpdateError::InvalidState(self.state));
        }
        if !self.inventory.capabilities.manual_rollback {
            return Err(UpdateError::Incompatible("manual rollback unsupported"));
        }
        self.send_write(Operation::Rollback, ManualFirmwareRollback)?;
        self.state.phase = Phase::RollbackAcknowledged;
        Ok(self.state)
    }

    /// A single read-only upgrade status request (no automatic polling/retry).
    pub fn upgrade_status(&mut self) -> Result<UpgradeStatus, UpdateError<CON::Error>> {
        self.ipmi
            .send_recv(GetUpgradeStatus)
            .map_err(UpdateError::Read)
    }

    /// A single read-only rollback status request (no automatic polling/retry).
    pub fn rollback_status(&mut self) -> Result<RollbackStatus, UpdateError<CON::Error>> {
        self.ipmi
            .send_recv(QueryRollbackStatus)
            .map_err(UpdateError::Read)
    }

    /// A single read-only self-test result request.
    pub fn self_test_result(&mut self) -> Result<SelfTestResult, UpdateError<CON::Error>> {
        self.ipmi
            .send_recv(QuerySelfTestResult)
            .map_err(UpdateError::Read)
    }
}
