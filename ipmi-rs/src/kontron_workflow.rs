//! Explicit, checked Kontron FRU changes and channel-buffer negotiation.

use std::ops::Range;

use ipmi_rs_core::{
    app::DeviceId,
    connection::{Address, Channel, IpmiConnection, LogicalUnit, NotEnoughData},
    oem::kontron::{
        BootDevice, BufferChannel, GetManufacturingDate, GetSerialNumber, SerialError,
        SetLargeBuffer, SetNextBoot, UnexpectedResponseLength,
    },
    storage::fru::{
        FruCommandError, FruDevice, FruInfo, FruInventory, FruParseError, WriteFruData,
        DEFAULT_CHUNK_BYTES,
    },
};

use crate::{oem::OemError, FruReadError, Ipmi, IpmiError};

/// Explicit acknowledgement that a Kontron command can irreversibly change
/// the device even if its response is lost. Construct only after a maintenance
/// window and, for FRU changes, after persisting [`KontronFruChange::backup`].
#[derive(Debug, Clone, Copy)]
pub struct KontronWriteApproval(());

impl KontronWriteApproval {
    /// Acknowledge the change and accept manual recovery on ambiguous failure.
    pub const fn acknowledge_risk() -> Self {
        Self(())
    }
}

/// One of the two complete, checksum-checked FRU areas preserved before writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KontronArea {
    /// FRU board information area.
    Board,
    /// FRU product information area.
    Product,
}

/// Original complete FRU image, including both board and product area backups.
/// Persist `image()` off-device before applying any change.
#[derive(Debug, Clone)]
pub struct KontronFruBackup {
    image: Vec<u8>,
    board: Range<usize>,
    product: Range<usize>,
}

impl KontronFruBackup {
    /// Original complete image, suitable for independent validated recovery.
    pub fn image(&self) -> &[u8] {
        &self.image
    }

    /// Complete board area, including its length and checksum bytes.
    pub fn board(&self) -> &[u8] {
        &self.image[self.board.clone()]
    }

    /// Complete product area, including its length and checksum bytes.
    pub fn product(&self) -> &[u8] {
        &self.image[self.product.clone()]
    }
}

/// Prepared FRU change. Preparation never writes; this value keeps the
/// destination, identity, validated backup and proposed image together.
#[derive(Debug)]
pub struct KontronFruChange {
    device: FruDevice,
    identity: DeviceId,
    info: FruInfo,
    backup: KontronFruBackup,
    proposed: Vec<u8>,
}

impl KontronFruChange {
    /// Persist both areas (preferably the entire image) before approval.
    pub fn backup(&self) -> &KontronFruBackup {
        &self.backup
    }

    /// Preview the complete proposed image, checksum-checked during preparation.
    pub fn proposed_image(&self) -> &[u8] {
        &self.proposed
    }
}

/// Failure of a single write whose result may be ambiguous.
#[derive(Debug)]
pub enum KontronWriteFailure<E> {
    /// The request, completion code, or response could not confirm the write.
    Command(IpmiError<E, FruCommandError>),
    /// The reported byte/word count did not match this chunk.
    Count(FruCommandError),
}

/// CP6012 boot write rejected before dispatch, or attempted exactly once.
#[derive(Debug)]
pub enum KontronBootError<E> {
    /// Insufficient RMCP session sequences for identity and boot write.
    SequenceBudget {
        /// Sequences needed by the two commands.
        needed: usize,
        /// Available sequences.
        available: usize,
    },
    /// Identity, completion, or transport error; a dispatched write is ambiguous.
    Command(OemError<E, UnexpectedResponseLength>),
}

/// Preparation, identity, transfer or verification failure. On a write
/// failure no area is automatically replayed or restored: keep the change's
/// backup, inspect the observed bytes and decide on manual recovery.
#[derive(Debug)]
pub enum KontronFruError<E> {
    /// Identity failed or the manufacturer is not Kontron; no write was sent.
    Identity(OemError<E, NotEnoughData>),
    /// The OEM serial query failed.
    Serial(OemError<E, SerialError>),
    /// The OEM manufacturing-date query failed.
    Date(OemError<E, NotEnoughData>),
    /// Only FRU ID 0 at LUN 0 on the OEM destination is supported.
    UnsupportedFru,
    /// Either board or product area is absent.
    MissingArea,
    /// Serial field is not eight-bit text, or its length differs from the OEM serial.
    SerialField(KontronArea),
    /// The FRU info command failed.
    Info(IpmiError<E, FruCommandError>),
    /// A complete image could not be read.
    Read(FruReadError<E>),
    /// A complete image did not pass layout/checksum/field validation.
    Inventory(FruParseError),
    /// FRU size/access or the full Get Device ID changed since preparation.
    TargetChanged,
    /// Too few non-reusable transport sequences remain for the complete
    /// checked operation. No FRU write was sent.
    SequenceBudget {
        /// Minimum sequences needed for identity, transfers and readback.
        needed: usize,
        /// Remaining transport sequences.
        available: usize,
    },
    /// The FRU image changed since preparation; no write was sent.
    InventoryChanged,
    /// A transfer failed before it could be sent.
    InvalidTransfer(FruCommandError),
    /// No writes after this chunk: the outcome of this and earlier chunks may
    /// be unknown. `observed` is a best-effort *raw* read, not proof of state.
    Write {
        /// Area being written.
        area: KontronArea,
        /// Byte offset of the affected chunk in the complete image.
        offset: usize,
        /// Bytes acknowledged within this area before this chunk.
        bytes_confirmed: usize,
        /// Write failure; never retry this chunk automatically.
        reason: KontronWriteFailure<E>,
        /// Best-effort post-failure read; may itself fail or race the write.
        observed: Result<Vec<u8>, FruReadError<E>>,
    },
    /// Post-write read failed; outcome requires operator inspection.
    Readback(FruReadError<E>),
    /// Post-write image was not the prepared image; manual recovery required.
    ReadbackMismatch(Vec<u8>),
}

fn area_range(image: &[u8], start: usize) -> Result<Range<usize>, FruParseError> {
    let length = image.get(start + 1).ok_or(FruParseError::Truncated)?;
    let end = start + *length as usize * 8;
    if end > image.len() || end < start + 8 {
        return Err(FruParseError::Layout);
    }
    Ok(start..end)
}

fn backup(image: Vec<u8>) -> Result<Option<KontronFruBackup>, FruParseError> {
    let inventory = FruInventory::parse(&image)?;
    let (Some(board), Some(product)) = (inventory.header.board, inventory.header.product) else {
        return Ok(None);
    };
    Ok(Some(KontronFruBackup {
        board: area_range(&image, board)?,
        product: area_range(&image, product)?,
        image,
    }))
}

fn checksum(image: &mut [u8], area: Range<usize>) {
    let sum = image[area.start..area.end - 1]
        .iter()
        .fold(0u8, |acc, byte| acc.wrapping_add(*byte));
    image[area.end - 1] = sum.wrapping_neg();
}

fn replace_serial(
    image: &mut [u8],
    area: Range<usize>,
    preceding_fields: usize,
    serial: &[u8],
) -> bool {
    let mut pos = area.start + if preceding_fields == 2 { 6 } else { 3 };
    for _ in 0..preceding_fields {
        let Some(&descriptor) = image.get(pos).filter(|_| pos < area.end - 1) else {
            return false;
        };
        pos += 1 + (descriptor & 0x3f) as usize;
        if pos >= area.end {
            return false;
        }
    }
    let Some(&descriptor) = image.get(pos).filter(|_| pos < area.end - 1) else {
        return false;
    };
    let length = (descriptor & 0x3f) as usize;
    if descriptor >> 6 != 3 || length != serial.len() || pos + 1 + length >= area.end {
        return false;
    }
    image[pos + 1..pos + 1 + length].copy_from_slice(serial);
    checksum(image, area);
    true
}

impl<C: IpmiConnection> Ipmi<C> {
    fn reserve_kontron_fru_budget(
        &mut self,
        needed: usize,
    ) -> Result<bool, KontronFruError<C::Error>> {
        let Some(available) = self.inner_mut().ipmb_sequence_budget() else {
            return Ok(false);
        };
        if available < needed || !self.inner_mut().reserve_ipmb_sequences(needed) {
            return Err(KontronFruError::SequenceBudget { needed, available });
        }
        Ok(true)
    }

    fn fru_sequence_cost(
        change: &KontronFruChange,
        before: &[u8],
        desired: &[u8],
        preflight: bool,
        readback_commands: usize,
    ) -> usize {
        let chunks = change.backup.image.len().div_ceil(DEFAULT_CHUNK_BYTES);
        let writes = [&change.backup.board, &change.backup.product]
            .iter()
            .filter(|span| before[span.start..span.end] != desired[span.start..span.end])
            .map(|span| (span.end - span.start).div_ceil(DEFAULT_CHUNK_BYTES))
            .sum::<usize>();
        let commands = writes + readback_commands + usize::from(preflight) * (4 + chunks);
        commands * if change.device.target.is_some() { 2 } else { 1 }
    }

    fn kontron_identity(
        &mut self,
        target: Option<(Address, Channel)>,
        expected: Option<&DeviceId>,
    ) -> Result<DeviceId, KontronFruError<C::Error>> {
        let identity = self
            .oem_device_id(target)
            .map_err(|error| KontronFruError::Identity(OemError::Identity(error)))?;
        if identity.manufacturer_id != 15000 {
            return Err(KontronFruError::Identity(OemError::UnsupportedDevice {
                manufacturer_id: identity.manufacturer_id,
                product_id: identity.product_id,
                expected_manufacturer_id: 15000,
                expected_product_id: None,
            }));
        }
        if expected.is_some_and(|id| *id != identity) {
            return Err(KontronFruError::TargetChanged);
        }
        Ok(identity)
    }

    fn prepare_kontron_fru(
        &mut self,
        device: FruDevice,
        identity: DeviceId,
    ) -> Result<KontronFruChange, KontronFruError<C::Error>> {
        let info = self.fru_info(device).map_err(KontronFruError::Info)?;
        let image = self.read_fru_image(device).map_err(KontronFruError::Read)?;
        if image.len() != info.size as usize {
            return Err(KontronFruError::TargetChanged);
        }
        let original = backup(image)
            .map_err(KontronFruError::Inventory)?
            .ok_or(KontronFruError::MissingArea)?;
        self.kontron_identity(device.target, Some(&identity))?;
        Ok(KontronFruChange {
            device,
            identity,
            info,
            proposed: original.image.clone(),
            backup: original,
        })
    }

    /// Read Kontron's LUN-3 OEM serial and prepare same-length board *and*
    /// product serial replacements on FRU ID 0. No writes are performed.
    /// Both complete areas, their checksums, and the whole image are verified.
    pub fn prepare_kontron_serial(
        &mut self,
        device: FruDevice,
    ) -> Result<KontronFruChange, KontronFruError<C::Error>> {
        if device.id != 0 || device.lun != LogicalUnit::Zero {
            return Err(KontronFruError::UnsupportedFru);
        }
        let identity = self.kontron_identity(device.target, None)?;
        let serial = self
            .send_oem(GetSerialNumber.at(device.target))
            .map_err(KontronFruError::Serial)?;
        let mut change = self.prepare_kontron_fru(device, identity)?;
        for (area, range, skipped) in [
            (KontronArea::Board, change.backup.board.clone(), 2),
            (KontronArea::Product, change.backup.product.clone(), 4),
        ] {
            if !replace_serial(&mut change.proposed, range, skipped, &serial) {
                return Err(KontronFruError::SerialField(area));
            }
        }
        FruInventory::parse(&change.proposed).map_err(KontronFruError::Inventory)?;
        Ok(change)
    }

    /// Read Kontron's LUN-3 OEM manufacturing date and prepare a FRU board
    /// update. The complete product area is also backed up and validated.
    pub fn prepare_kontron_mfg_date(
        &mut self,
        device: FruDevice,
    ) -> Result<KontronFruChange, KontronFruError<C::Error>> {
        if device.id != 0 || device.lun != LogicalUnit::Zero {
            return Err(KontronFruError::UnsupportedFru);
        }
        let identity = self.kontron_identity(device.target, None)?;
        let date = self
            .send_oem(GetManufacturingDate.at(device.target))
            .map_err(KontronFruError::Date)?;
        let mut change = self.prepare_kontron_fru(device, identity)?;
        let range = change.backup.board.clone();
        change.proposed[range.start + 3..range.start + 6].copy_from_slice(&date);
        checksum(&mut change.proposed, range);
        FruInventory::parse(&change.proposed).map_err(KontronFruError::Inventory)?;
        Ok(change)
    }

    /// Apply a prepared, off-device-backed-up Kontron FRU change exactly
    /// once. Rechecks identity, size and the complete original image before
    /// writing only changed areas, then reads back the complete image.
    ///
    /// Never call this again after a write error without independently
    /// diagnosing/recovering the FRU. It does not automatically roll back
    /// partial writes or ambiguous transport failures.
    pub fn apply_kontron_fru_change(
        &mut self,
        change: &KontronFruChange,
        _approval: KontronWriteApproval,
    ) -> Result<(), KontronFruError<C::Error>> {
        let readback = 1 + change.backup.image.len().div_ceil(DEFAULT_CHUNK_BYTES);
        let needed = Self::fru_sequence_cost(
            change,
            change.backup.image(),
            &change.proposed,
            true,
            readback,
        );
        let reserved = self.reserve_kontron_fru_budget(needed)?;
        let result = (|| {
            self.kontron_identity(change.device.target, Some(&change.identity))?;
            let info = self
                .fru_info(change.device)
                .map_err(KontronFruError::Info)?;
            if info != change.info {
                return Err(KontronFruError::TargetChanged);
            }
            let before_read = self.inner_mut().ipmb_sequence_budget();
            let current = self
                .read_fru_image(change.device)
                .map_err(KontronFruError::Read)?;
            if current != change.backup.image {
                return Err(KontronFruError::InventoryChanged);
            }
            let after_read = self.inner_mut().ipmb_sequence_budget();
            let readback_cost = before_read
                .zip(after_read)
                .map_or(readback, |(before, after)| {
                    readback.max(
                        before
                            .saturating_sub(after)
                            .div_ceil(if change.device.target.is_some() { 2 } else { 1 }),
                    )
                });
            let still_needed =
                Self::fru_sequence_cost(change, &current, &change.proposed, false, readback_cost)
                    + if change.device.target.is_some() { 2 } else { 1 };
            if reserved {
                self.inner_mut().release_ipmb_sequences();
                self.reserve_kontron_fru_budget(still_needed)?;
            }
            self.kontron_identity(change.device.target, Some(&change.identity))?;
            self.write_kontron_areas(change, &current, &change.proposed, info)
        })();
        if reserved {
            self.inner_mut().release_ipmb_sequences();
        }
        result
    }

    /// Explicit *manual* restoration after diagnosing an incomplete/ambiguous
    /// write. No restoration is attempted automatically. The original identity,
    /// size and all bytes outside the two backed-up areas must still match;
    /// only differing board/product areas are written and then read back.
    /// A lost restoration response is also ambiguous: do not retry blindly.
    pub fn restore_kontron_fru_backup(
        &mut self,
        change: &KontronFruChange,
        _approval: KontronWriteApproval,
    ) -> Result<(), KontronFruError<C::Error>> {
        self.kontron_identity(change.device.target, Some(&change.identity))?;
        let info = self
            .fru_info(change.device)
            .map_err(KontronFruError::Info)?;
        if info != change.info {
            return Err(KontronFruError::TargetChanged);
        }
        let current = self
            .read_fru_image(change.device)
            .map_err(KontronFruError::Read)?;
        if current.len() != change.backup.image.len()
            || current.iter().zip(&change.backup.image).enumerate().any(
                |(index, (actual, original))| {
                    !change.backup.board.contains(&index)
                        && !change.backup.product.contains(&index)
                        && actual != original
                },
            )
        {
            return Err(KontronFruError::InventoryChanged);
        }
        let readback = 1 + change.backup.image.len().div_ceil(DEFAULT_CHUNK_BYTES);
        let needed =
            Self::fru_sequence_cost(change, &current, &change.backup.image, false, readback)
                + if change.device.target.is_some() { 2 } else { 1 };
        let reserved = self.reserve_kontron_fru_budget(needed)?;
        let result = (|| {
            self.kontron_identity(change.device.target, Some(&change.identity))?;
            self.write_kontron_areas(change, &current, &change.backup.image, info)
        })();
        if reserved {
            self.inner_mut().release_ipmb_sequences();
        }
        result
    }

    fn write_kontron_areas(
        &mut self,
        change: &KontronFruChange,
        before: &[u8],
        desired: &[u8],
        info: FruInfo,
    ) -> Result<(), KontronFruError<C::Error>> {
        for (area, span) in [
            (KontronArea::Board, change.backup.board.clone()),
            (KontronArea::Product, change.backup.product.clone()),
        ] {
            if before[span.clone()] == desired[span.clone()] {
                continue;
            }
            for (index, part) in desired[span.clone()]
                .chunks(DEFAULT_CHUNK_BYTES)
                .enumerate()
            {
                let offset = span.start + index * DEFAULT_CHUNK_BYTES;
                let command = WriteFruData::new(
                    change.device.id,
                    change.device.target,
                    change.device.lun,
                    info,
                    offset as u16,
                    part.to_vec(),
                )
                .map_err(KontronFruError::InvalidTransfer)?;
                let outcome = self
                    .send_recv(command.clone())
                    .map_err(KontronWriteFailure::Command)
                    .and_then(|count| command.verify(count).map_err(KontronWriteFailure::Count));
                if let Err(reason) = outcome {
                    return Err(KontronFruError::Write {
                        area,
                        offset,
                        bytes_confirmed: index * DEFAULT_CHUNK_BYTES,
                        reason,
                        observed: self.read_fru_image(change.device),
                    });
                }
            }
        }
        let readback = self
            .read_fru_image(change.device)
            .map_err(KontronFruError::Readback)?;
        if readback != desired {
            return Err(KontronFruError::ReadbackMismatch(readback));
        }
        FruInventory::parse(&readback).map_err(KontronFruError::Inventory)?;
        Ok(())
    }

    /// Explicit CP6012 LUN-3 nextboot write; the OEM sender checks both IANA
    /// 15000 and product 6012 on this exact target. No ambiguous write is
    /// replayed. `None` targets the session BMC.
    pub fn kontron_set_next_boot(
        &mut self,
        target: Option<(Address, Channel)>,
        device: BootDevice,
        _approval: KontronWriteApproval,
    ) -> Result<(), KontronBootError<C::Error>> {
        let needed = if target.is_some() { 4 } else { 2 };
        let reserved = if let Some(available) = self.inner_mut().ipmb_sequence_budget() {
            if available < needed || !self.inner_mut().reserve_ipmb_sequences(needed) {
                return Err(KontronBootError::SequenceBudget { needed, available });
            }
            true
        } else {
            false
        };
        let result = self
            .send_oem(SetNextBoot(device).at(target))
            .map_err(KontronBootError::Command);
        if reserved {
            self.inner_mut().release_ipmb_sequences();
        }
        result
    }

    /// Negotiate buffer size for a local Kontron or for a Kontron IPMB
    /// destination through a Kontron local controller. A remote setup sends
    /// local current (0x0e), local IPMB (0x00), remote current (0x0e).
    /// On any failure, attempted channels are restored to default size zero;
    /// restoration failures are reported and must be handled by the operator.
    pub fn kontron_set_large_buffer(
        &mut self,
        target: Option<(Address, Channel)>,
        size: u8,
    ) -> Result<(), KontronBufferError<C::Error>> {
        let needed = if target.is_some() { 20 } else { 4 };
        let reserved = if let Some(available) = self.inner_mut().ipmb_sequence_budget() {
            if available < needed || !self.inner_mut().reserve_ipmb_sequences(needed) {
                return Err(KontronBufferError {
                    step: KontronBufferStep::LocalCurrent,
                    source: KontronBufferFailure::SequenceBudget { needed, available },
                    restore: Vec::new(),
                });
            }
            true
        } else {
            false
        };
        let result = self.configure_kontron_buffer(target, size);
        if reserved {
            self.inner_mut().release_ipmb_sequences();
        }
        result
    }

    fn configure_kontron_buffer(
        &mut self,
        target: Option<(Address, Channel)>,
        size: u8,
    ) -> Result<(), KontronBufferError<C::Error>> {
        let remote_identity = if let Some(target) = target {
            let identity =
                self.oem_device_id(Some(target))
                    .map_err(|error| KontronBufferError {
                        step: KontronBufferStep::RemoteCurrent,
                        source: KontronBufferFailure::Identity(OemError::Identity(error)),
                        restore: Vec::new(),
                    })?;
            if identity.manufacturer_id != 15000 {
                return Err(KontronBufferError {
                    step: KontronBufferStep::RemoteCurrent,
                    source: KontronBufferFailure::Identity(OemError::UnsupportedDevice {
                        manufacturer_id: identity.manufacturer_id,
                        product_id: identity.product_id,
                        expected_manufacturer_id: 15000,
                        expected_product_id: None,
                    }),
                    restore: Vec::new(),
                });
            }
            Some(identity)
        } else {
            None
        };
        let steps = [
            (
                KontronBufferStep::LocalCurrent,
                None,
                BufferChannel::Current,
            ),
            (KontronBufferStep::LocalIpmb, None, BufferChannel::Ipmb),
            (
                KontronBufferStep::RemoteCurrent,
                target,
                BufferChannel::Current,
            ),
        ];
        let count = if target.is_some() { 3 } else { 1 };
        for (index, &(step, destination, channel)) in steps[..count].iter().enumerate() {
            let identity_check =
                if let Some(expected) = remote_identity.as_ref().filter(|_| index == 2) {
                    self.oem_device_id(target)
                        .map_err(|error| KontronBufferFailure::Identity(OemError::Identity(error)))
                        .and_then(|current| {
                            if current == *expected {
                                Ok(())
                            } else {
                                Err(KontronBufferFailure::TargetChanged)
                            }
                        })
                } else {
                    Ok(())
                };
            let outcome = identity_check.and_then(|()| {
                self.send_oem(SetLargeBuffer { channel, size }.at(destination))
                    .map_err(KontronBufferFailure::Command)
            });
            if let Err(source) = outcome {
                let mut restore = Vec::new();
                let attempted = index
                    + usize::from(matches!(
                        source,
                        KontronBufferFailure::Command(OemError::Command(_))
                    ));
                for &(restore_step, restore_target, restore_channel) in
                    steps[..attempted].iter().rev()
                {
                    if let Err(error) = self.send_oem(
                        SetLargeBuffer {
                            channel: restore_channel,
                            size: 0,
                        }
                        .at(restore_target),
                    ) {
                        restore.push((restore_step, error));
                    }
                }
                return Err(KontronBufferError {
                    step,
                    source,
                    restore,
                });
            }
        }
        Ok(())
    }
}

/// The location of a buffer negotiation or restoration operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KontronBufferStep {
    /// Local controller, current interface.
    LocalCurrent,
    /// Local controller, IPMB interface.
    LocalIpmb,
    /// Explicit remote IPMB destination, current interface.
    RemoteCurrent,
}

/// Buffer negotiation failure and any subsequent restoration failures.
#[derive(Debug)]
pub struct KontronBufferError<E> {
    /// Failed negotiation step.
    pub step: KontronBufferStep,
    /// Original failure.
    pub source: KontronBufferFailure<E>,
    /// Failed restores in reverse order (remote, local IPMB, local current).
    pub restore: Vec<(KontronBufferStep, OemError<E, UnexpectedResponseLength>)>,
}

/// Reason a buffer negotiation failed before or after dispatch.
#[derive(Debug)]
pub enum KontronBufferFailure<E> {
    /// Insufficient RMCP session sequences to reserve both setup and cleanup.
    SequenceBudget {
        /// Sequences needed for setup and possible cleanup.
        needed: usize,
        /// Available sequences.
        available: usize,
    },
    /// Remote identity query failed or vendor did not match, with no mutations.
    Identity(OemError<E, NotEnoughData>),
    /// The remote Get Device ID changed after the initial check.
    TargetChanged,
    /// The buffer OEM request failed.
    Command(OemError<E, UnexpectedResponseLength>),
}
