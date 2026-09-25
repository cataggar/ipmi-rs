//! Opt-in, one-shot firmware staging, activation, and rollback.
//!
//! All mutations are sent at most once. Even a missing reply from buffer
//! cleanup is not retried. A failed or interrupted session cannot be resumed:
//! inspect banks/trace, restore connectivity, and make a fresh operator decision.

use ipmi_rs_core::{
    connection::IpmiConnection,
    oem::fwum::{
        BankState, BankStatus, BufferChannel, DownloadMode, FinishImage, FirmwareImage, FwumTarget,
        ImageError, Info, ManualRollback, SaveImage, SetChannelBuffer, StartImage, StartUpdate,
        StartedBank,
    },
    oem::OemCommand,
};

use super::{BankInventory, FwumParseError, FwumReadError};
use crate::{oem::OemError, oem::TargetDeviceId, Ipmi, IpmiError};

/// Explicit preconditions required before any FWUM write.
///
/// A maintenance window, an independent matching recovery image, and written
/// interruption/rollback plans must exist before constructing an authorization.
/// These strings describe operator-approved procedures; they do not trigger
/// a recovery image upload automatically.
pub struct UpdateAuthorization<'a> {
    maintenance_window: &'a str,
    recovery_image: FirmwareImage<'a>,
    interruption_plan: &'a str,
    rollback_plan: &'a str,
}

/// Image or maintenance authorization is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepareError {
    /// Invalid main or recovery image.
    Image(ImageError),
    /// Window or documented interruption/rollback procedure is missing.
    MissingProcedure,
    /// Recovery image is identical to the image being staged.
    RecoveryNotAlternative,
    /// Image/recovery IANA, board product or controller ID disagree with target.
    ImageTargetMismatch,
    /// Target has no known-good and spare bank for a reversible update.
    NoRollbackBank,
    /// Firmware already has a new/pending image; do not overwrite it.
    ExistingUpdate,
    /// Payload limit, transport routing or buffer length cannot be represented.
    InvalidTransport,
}

impl<'a> UpdateAuthorization<'a> {
    /// Require nonempty operator procedures and a separately validated image.
    pub fn new(
        maintenance_window: &'a str,
        recovery_bytes: &'a [u8],
        interruption_plan: &'a str,
        rollback_plan: &'a str,
    ) -> Result<Self, PrepareError> {
        if maintenance_window.trim().is_empty()
            || interruption_plan.trim().is_empty()
            || rollback_plan.trim().is_empty()
        {
            return Err(PrepareError::MissingProcedure);
        }
        Ok(Self {
            maintenance_window,
            recovery_image: FirmwareImage::parse(recovery_bytes).map_err(PrepareError::Image)?,
            interruption_plan,
            rollback_plan,
        })
    }
}

/// How the operator reaches the target; not inferred from connection type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    /// Direct KCS/SMI or similar local interface.
    Local,
    /// LAN (including RMCP/RMCP+) to the BMC.
    Network,
    /// IPMB or bridged IPMB target, including over LAN.
    Bridged,
}

/// Explicit upper bound for request data, including FWUM overhead.
#[derive(Clone, Copy, Debug)]
pub struct TransportLimits {
    kind: TransportKind,
    max_request_bytes: u8,
    negotiated_buffer_bytes: Option<u8>,
}

impl TransportLimits {
    /// Default source-safe 32-byte channel buffer, without changing OEM state.
    pub const fn standard(kind: TransportKind) -> Self {
        Self {
            kind,
            max_request_bytes: 32,
            negotiated_buffer_bytes: None,
        }
    }

    /// Opt in to 0x3E/0x82 setup and one-shot reverse-order cleanup.
    ///
    /// The caller must know that the transport supports `max_request_bytes`.
    /// Firmware writes still cap request size at 32 bytes until hardware
    /// validation permits larger packets.
    pub fn negotiated(
        kind: TransportKind,
        max_request_bytes: u8,
        buffer_bytes: u8,
    ) -> Result<Self, PrepareError> {
        if !(8..=32).contains(&buffer_bytes)
            || max_request_bytes < buffer_bytes
            || max_request_bytes > 32
        {
            return Err(PrepareError::InvalidTransport);
        }
        Ok(Self {
            kind,
            max_request_bytes,
            negotiated_buffer_bytes: Some(buffer_bytes),
        })
    }

    fn capacity(self, mode: DownloadMode) -> usize {
        let overhead = match mode {
            DownloadMode::Address => 6,
            DownloadMode::Sequence => 4,
        };
        usize::from(
            self.negotiated_buffer_bytes
                .unwrap_or(32)
                .min(self.max_request_bytes),
        ) - overhead
    }

    fn check(self, target: FwumTarget) -> Result<(), PrepareError> {
        if self.max_request_bytes < 8
            || matches!(self.kind, TransportKind::Bridged) != target.address.is_some()
        {
            return Err(PrepareError::InvalidTransport);
        }
        Ok(())
    }
}

/// One-shot mutation, including OEM buffer setup/cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateAction {
    /// 0x3E/0x82 nonzero buffer setup.
    SetBuffer,
    /// 0x3E/0x82 restore default buffer.
    ClearBuffer,
    /// 0x08/0x0A.
    StartImage,
    /// 0x08/0x0B.
    SaveImage,
    /// 0x08/0x0C.
    FinishImage,
    /// 0x08/0x09.
    Activate,
    /// 0x08/0x0E.
    Rollback,
}

/// The command's outcome, *not* a claim about the whole update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationOutcome {
    /// Identity check prevented dispatch.
    NotSent,
    /// BMC acknowledged rejection with a completion code.
    Rejected,
    /// Transport, unexpected/malformed reply, or lost ACK: never replay.
    Unknown,
}

/// Identity-checked command error with mutation outcome classification.
#[derive(Debug)]
pub struct MutationError<CON> {
    /// Attempted action.
    pub action: UpdateAction,
    /// Whether the BMC definitively rejected, may have acted, or was not sent.
    pub outcome: MutationOutcome,
    /// Underlying identity or command error.
    pub error: OemError<CON, FwumParseError>,
}

fn mutation<CON>(action: UpdateAction, error: OemError<CON, FwumParseError>) -> MutationError<CON> {
    let outcome = match &error {
        OemError::Identity(_) | OemError::UnsupportedDevice { .. } => MutationOutcome::NotSent,
        OemError::Command(
            IpmiError::Failed { .. }
            | IpmiError::Command {
                completion_code: Some(_),
                ..
            },
        ) => MutationOutcome::Rejected,
        _ => MutationOutcome::Unknown,
    };
    MutationError {
        action,
        outcome,
        error,
    }
}

/// State of the local state machine; no state implies hardware activation
/// until verified with a fresh status read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdatePhase {
    /// Verified and ready, no update command sent.
    Prepared,
    /// Start Image acknowledged, bytes through `confirmed_bytes` acknowledged.
    Uploading {
        /// Selected firmware bank.
        bank: u8,
        /// Confirmed prefix length, not an estimate.
        confirmed_bytes: usize,
    },
    /// Finish Image acknowledged and target bank verified as new.
    Staged { bank: u8 },
    /// Start Update acknowledged; reboot/validation may be pending.
    ActivationRequested { bank: u8 },
    /// New image observed as last known good.
    Activated { bank: u8 },
    /// Manual Rollback acknowledged; reboot/validation may be pending.
    RollbackRequested { bank: u8 },
    /// Original good bank observed as last known good again.
    RolledBack { bank: u8 },
    /// Further writes prohibited. Read and decide recovery out-of-band.
    Interrupted,
}

/// Reported only after a Save Image ACK (or the initial Start Image ACK).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadProgress {
    /// Acknowledged image bytes.
    pub confirmed_bytes: usize,
    /// Total verified image bytes.
    pub total_bytes: usize,
    /// Selected bank.
    pub bank: u8,
}

/// Cause of a stopped update.
#[derive(Debug)]
pub enum UpdateCause<CON> {
    /// Invalid authorization, image or transport, before any mutation.
    Preflight(PrepareError),
    /// A command failed (do not replay Unknown outcomes).
    Mutation(MutationError<CON>),
    /// A read-only verification/identity request failed after bounded retries.
    Read(FwumReadError<CON>),
    /// A reply/status did not confirm the required state.
    Verification,
    /// Operator aborted at an acknowledged chunk boundary.
    OperatorInterrupted,
    /// One or more buffer clear commands failed.
    Cleanup,
    /// This method is not legal at the current phase.
    InvalidPhase,
    /// Activation or rollback has not completed yet; poll read-only again.
    Pending,
}

/// Failure plus the last confirmed progress and every failed cleanup action.
#[derive(Debug)]
pub struct UpdateError<CON> {
    /// State after the error; Interrupted permanently blocks this session.
    pub phase: UpdatePhase,
    /// Number of bytes with successful Save Image replies.
    pub confirmed_bytes: usize,
    /// Root cause.
    pub cause: UpdateCause<CON>,
    /// Buffer cleanup errors, each sent only once.
    pub cleanup: Vec<MutationError<CON>>,
}

/// A single authorized, target-bound update; not `Clone`, not resumable after
/// interruption. Dropping an in-progress update does not finish the image.
/// Inspect device state and clear an uncertain buffer only by explicit
/// operator action if the process is interrupted.
pub struct UpdateSession<'ipmi, 'image, CON> {
    ipmi: &'ipmi mut Ipmi<CON>,
    image: FirmwareImage<'image>,
    target: FwumTarget,
    limits: TransportLimits,
    mode: DownloadMode,
    old_good_bank: u8,
    old_good: BankStatus,
    baseline_count: u8,
    baseline_info: Info,
    baseline_banks: Vec<BankStatus>,
    phase: UpdatePhase,
    confirmed_bytes: usize,
    armed_buffers: Vec<(FwumTarget, BufferChannel)>,
}

impl<CON: IpmiConnection> Ipmi<CON> {
    /// Validate both images, the operator's written plan, exact device and
    /// product IDs, transport sizing, and a reversible two-bank baseline.
    ///
    /// Preparation is read-only. No implicit upgrade, rollback, or reset.
    pub fn fwum_prepare_update<'ipmi, 'image>(
        &'ipmi mut self,
        target: FwumTarget,
        bytes: &'image [u8],
        authorization: &UpdateAuthorization<'_>,
        limits: TransportLimits,
    ) -> Result<UpdateSession<'ipmi, 'image, CON>, UpdateError<CON::Error>> {
        let preflight = |error| UpdateError {
            phase: UpdatePhase::Prepared,
            confirmed_bytes: 0,
            cause: UpdateCause::Preflight(error),
            cleanup: Vec::new(),
        };
        if authorization.maintenance_window.trim().is_empty()
            || authorization.interruption_plan.trim().is_empty()
            || authorization.rollback_plan.trim().is_empty()
        {
            return Err(preflight(PrepareError::MissingProcedure));
        }
        let image =
            FirmwareImage::parse(bytes).map_err(|err| preflight(PrepareError::Image(err)))?;
        if image.bytes() == authorization.recovery_image.bytes() {
            return Err(preflight(PrepareError::RecoveryNotAlternative));
        }
        if target.product_id == 0
            || image.iana != 15000
            || image.iana != authorization.recovery_image.iana
            || image.board_id != target.product_id
            || authorization.recovery_image.board_id != target.product_id
            || image.device_id != authorization.recovery_image.device_id
        {
            return Err(preflight(PrepareError::ImageTargetMismatch));
        }
        limits.check(target).map_err(preflight)?;
        let baseline = self.fwum_banks(target).map_err(|error| UpdateError {
            phase: UpdatePhase::Prepared,
            confirmed_bytes: 0,
            cause: UpdateCause::Read(error),
            cleanup: Vec::new(),
        })?;
        if image.device_id != baseline.inventory.device.device_id {
            return Err(preflight(PrepareError::ImageTargetMismatch));
        }
        if baseline.banks.iter().any(|bank| {
            matches!(
                bank.state,
                BankState::NewFirmware | BankState::WaitingForValidation
            )
        }) {
            return Err(preflight(PrepareError::ExistingUpdate));
        }
        let old_good_bank = baseline
            .banks
            .iter()
            .position(|bank| bank.state == BankState::LastKnownGood);
        if baseline.banks.len() < 2
            || baseline
                .banks
                .iter()
                .filter(|bank| bank.state == BankState::LastKnownGood)
                .count()
                != 1
            || old_good_bank.is_none()
            || old_good_bank.is_some_and(|idx| baseline.banks[idx].length == 0)
        {
            return Err(preflight(PrepareError::NoRollbackBank));
        }
        let old_good_bank = old_good_bank.expect("checked known good index") as u8;
        let mode = if baseline.inventory.firmware.sequence_format {
            DownloadMode::Sequence
        } else {
            DownloadMode::Address
        };
        Ok(UpdateSession {
            ipmi: self,
            image,
            target,
            limits,
            mode,
            old_good_bank,
            old_good: baseline.banks[usize::from(old_good_bank)],
            baseline_count: baseline.inventory.firmware.bank_count,
            baseline_info: baseline.inventory.firmware,
            baseline_banks: baseline.banks,
            phase: UpdatePhase::Prepared,
            confirmed_bytes: 0,
            armed_buffers: Vec::new(),
        })
    }
}

impl<'ipmi, 'image, CON: IpmiConnection> UpdateSession<'ipmi, 'image, CON> {
    /// Last locally confirmed phase. Inspect on-device status on interruption.
    pub fn phase(&self) -> UpdatePhase {
        self.phase
    }

    /// Last acknowledged prefix length, even on a failed stage.
    pub fn confirmed_bytes(&self) -> usize {
        self.confirmed_bytes
    }

    fn error(
        &self,
        cause: UpdateCause<CON::Error>,
        cleanup: Vec<MutationError<CON::Error>>,
    ) -> UpdateError<CON::Error> {
        UpdateError {
            phase: self.phase,
            confirmed_bytes: self.confirmed_bytes,
            cause,
            cleanup,
        }
    }

    fn stop(&mut self, cause: UpdateCause<CON::Error>) -> UpdateError<CON::Error> {
        self.phase = UpdatePhase::Interrupted;
        let cleanup = self.clear_buffers();
        self.error(cause, cleanup)
    }

    fn write<C: OemCommand<Error = FwumParseError>>(
        &mut self,
        command: C,
        action: UpdateAction,
    ) -> Result<C::Output, MutationError<CON::Error>> {
        self.ipmi
            .send_oem(command)
            .map_err(|err| mutation(action, err))
    }

    fn set_buffer(
        &mut self,
        target: FwumTarget,
        channel: BufferChannel,
        size: u8,
    ) -> Result<(), MutationError<CON::Error>> {
        let result = self.write(
            SetChannelBuffer {
                target,
                channel,
                size,
            },
            UpdateAction::SetBuffer,
        );
        if result.is_ok()
            || result
                .as_ref()
                .is_err_and(|err| err.outcome == MutationOutcome::Unknown)
        {
            self.armed_buffers.push((target, channel));
        }
        result
    }

    fn setup_buffers(&mut self) -> Result<(), UpdateCause<CON::Error>> {
        let Some(size) = self.limits.negotiated_buffer_bytes else {
            return Ok(());
        };
        let local = if self.target.address.is_some() {
            let device = self
                .ipmi
                .send_recv(TargetDeviceId(None))
                .map_err(|error| UpdateCause::Read(FwumReadError::Device(error)))?;
            if device.manufacturer_id != 15000 || device.product_id == 0 || !device.device_available
            {
                return Err(UpdateCause::Read(FwumReadError::UnsupportedDevice {
                    manufacturer: device.manufacturer_id,
                    product: device.product_id,
                }));
            }
            FwumTarget::new(None, device.product_id)
        } else {
            self.target
        };
        self.set_buffer(local, BufferChannel::Current, size)
            .map_err(UpdateCause::Mutation)?;
        if self.target.address.is_some() {
            self.set_buffer(local, BufferChannel::Ipmb, size)
                .map_err(UpdateCause::Mutation)?;
            self.set_buffer(self.target, BufferChannel::Current, size)
                .map_err(UpdateCause::Mutation)?;
        }
        Ok(())
    }

    fn clear_buffers(&mut self) -> Vec<MutationError<CON::Error>> {
        let mut errors = Vec::new();
        while let Some((target, channel)) = self.armed_buffers.pop() {
            if let Err(err) = self.write(
                SetChannelBuffer {
                    target,
                    channel,
                    size: 0,
                },
                UpdateAction::ClearBuffer,
            ) {
                errors.push(err);
            }
        }
        errors
    }

    fn verify_staged(&mut self, bank: u8) -> Result<bool, FwumReadError<CON::Error>> {
        let status = self.ipmi.fwum_banks(self.target)?;
        Ok(status.inventory.firmware.bank_count == self.baseline_count
            && status.banks.get(usize::from(bank)).is_some_and(|status| {
                status.state == BankState::NewFirmware
                    && status.length as usize == self.image.len()
                    && status.revision == self.image.revision
            }))
    }

    /// Start, upload and finish an image, returning only after the selected
    /// bank reports the matching length/revision and buffers are cleared.
    ///
    /// Callback `false` stops at an acknowledged chunk boundary. Neither a
    /// failure nor cancellation retries a mutation or calls Finish Image.
    pub fn stage(
        &mut self,
        mut on_progress: impl FnMut(UploadProgress) -> bool,
    ) -> Result<u8, UpdateError<CON::Error>> {
        if self.phase != UpdatePhase::Prepared {
            return Err(self.error(UpdateCause::InvalidPhase, Vec::new()));
        }
        let fresh = match self.ipmi.fwum_banks(self.target) {
            Ok(fresh) => fresh,
            Err(err) => return Err(self.stop(UpdateCause::Read(err))),
        };
        if fresh.inventory.firmware != self.baseline_info || fresh.banks != self.baseline_banks {
            return Err(self.stop(UpdateCause::Verification));
        }
        if let Err(cause) = self.setup_buffers() {
            return Err(self.stop(cause));
        }
        let bank = match self.write(
            StartImage {
                target: self.target,
                size: self.image.len() as u32,
                padding: self.image.padding(),
                mode: self.mode,
            },
            UpdateAction::StartImage,
        ) {
            Ok(StartedBank(bank)) => bank,
            Err(err) => return Err(self.stop(UpdateCause::Mutation(err))),
        };
        if bank >= self.baseline_count || bank == self.old_good_bank {
            return Err(self.stop(UpdateCause::Verification));
        }
        self.phase = UpdatePhase::Uploading {
            bank,
            confirmed_bytes: 0,
        };
        if !on_progress(UploadProgress {
            confirmed_bytes: 0,
            total_bytes: self.image.len(),
            bank,
        }) {
            return Err(self.stop(UpdateCause::OperatorInterrupted));
        }
        let mut sequence = 0u8;
        while self.confirmed_bytes < self.image.len() {
            let offset = self.confirmed_bytes;
            let page_remaining = 256 - offset % 256;
            let count = self
                .limits
                .capacity(self.mode)
                .min(page_remaining)
                .min(self.image.len() - offset);
            let part = &self.image.bytes()[offset..offset + count];
            if let Err(err) = self.write(
                SaveImage {
                    target: self.target,
                    offset: offset as u32,
                    sequence,
                    bytes: part,
                    mode: self.mode,
                },
                UpdateAction::SaveImage,
            ) {
                return Err(self.stop(UpdateCause::Mutation(err)));
            }
            self.confirmed_bytes += count;
            sequence = sequence.wrapping_add(1);
            self.phase = UpdatePhase::Uploading {
                bank,
                confirmed_bytes: self.confirmed_bytes,
            };
            if !on_progress(UploadProgress {
                confirmed_bytes: self.confirmed_bytes,
                total_bytes: self.image.len(),
                bank,
            }) {
                return Err(self.stop(UpdateCause::OperatorInterrupted));
            }
        }
        if let Err(err) = self.write(
            FinishImage {
                target: self.target,
                revision: self.image.revision,
            },
            UpdateAction::FinishImage,
        ) {
            return Err(self.stop(UpdateCause::Mutation(err)));
        }
        match self.verify_staged(bank) {
            Ok(true) => {}
            Ok(false) => return Err(self.stop(UpdateCause::Verification)),
            Err(err) => return Err(self.stop(UpdateCause::Read(err))),
        }
        let cleanup = self.clear_buffers();
        if !cleanup.is_empty() {
            self.phase = UpdatePhase::Interrupted;
            return Err(self.error(UpdateCause::Cleanup, cleanup));
        }
        self.phase = UpdatePhase::Staged { bank };
        Ok(bank)
    }

    /// Issue Start Update exactly once after rechecking the staged bank.
    /// An ACK means only that activation was requested, not that it succeeded.
    pub fn activate(&mut self) -> Result<(), UpdateError<CON::Error>> {
        let UpdatePhase::Staged { bank } = self.phase else {
            return Err(self.error(UpdateCause::InvalidPhase, Vec::new()));
        };
        match self.verify_staged(bank) {
            Ok(true) => {}
            Ok(false) => return Err(self.stop(UpdateCause::Verification)),
            Err(err) => return Err(self.stop(UpdateCause::Read(err))),
        }
        if let Err(err) = self.write(StartUpdate(self.target), UpdateAction::Activate) {
            return Err(self.stop(UpdateCause::Mutation(err)));
        }
        self.phase = UpdatePhase::ActivationRequested { bank };
        Ok(())
    }

    /// Read-only activation check; caller may poll again after a pending
    /// status without repeating Start Update.
    pub fn verify_activation(&mut self) -> Result<(), UpdateError<CON::Error>> {
        let UpdatePhase::ActivationRequested { bank } = self.phase else {
            return Err(self.error(UpdateCause::InvalidPhase, Vec::new()));
        };
        let status = self
            .ipmi
            .fwum_banks(self.target)
            .map_err(|err| self.error(UpdateCause::Read(err), Vec::new()))?;
        if status.banks.get(usize::from(bank)).is_some_and(|value| {
            value.state == BankState::LastKnownGood
                && value.length as usize == self.image.len()
                && value.revision == self.image.revision
        }) && status
            .banks
            .get(usize::from(self.old_good_bank))
            .is_some_and(|value| value.state != BankState::LastKnownGood)
        {
            self.phase = UpdatePhase::Activated { bank };
            Ok(())
        } else {
            Err(self.error(UpdateCause::Pending, Vec::new()))
        }
    }

    /// Opt-in Manual Rollback, once, only for a verified activation.
    pub fn rollback(&mut self) -> Result<(), UpdateError<CON::Error>> {
        let UpdatePhase::Activated { bank } = self.phase else {
            return Err(self.error(UpdateCause::InvalidPhase, Vec::new()));
        };
        let status = self
            .ipmi
            .fwum_banks(self.target)
            .map_err(|err| self.error(UpdateCause::Read(err), Vec::new()))?;
        if !status.banks.get(usize::from(bank)).is_some_and(|value| {
            value.state == BankState::LastKnownGood
                && value.length as usize == self.image.len()
                && value.revision == self.image.revision
        }) {
            return Err(self.stop(UpdateCause::Verification));
        }
        if let Err(err) = self.write(ManualRollback(self.target), UpdateAction::Rollback) {
            return Err(self.stop(UpdateCause::Mutation(err)));
        }
        self.phase = UpdatePhase::RollbackRequested { bank };
        Ok(())
    }

    /// Confirm the original bank, version and length became last known good.
    /// A pending status is never interpreted as a successful rollback.
    pub fn verify_rollback(&mut self) -> Result<(), UpdateError<CON::Error>> {
        let UpdatePhase::RollbackRequested { bank } = self.phase else {
            return Err(self.error(UpdateCause::InvalidPhase, Vec::new()));
        };
        let status = self
            .ipmi
            .fwum_banks(self.target)
            .map_err(|err| self.error(UpdateCause::Read(err), Vec::new()))?;
        if status
            .banks
            .get(usize::from(self.old_good_bank))
            .is_some_and(|value| {
                value.state == BankState::LastKnownGood
                    && value.length == self.old_good.length
                    && value.revision == self.old_good.revision
            })
            && status
                .banks
                .get(usize::from(bank))
                .is_some_and(|value| value.state != BankState::LastKnownGood)
        {
            self.phase = UpdatePhase::RolledBack { bank };
            Ok(())
        } else {
            Err(self.error(UpdateCause::Pending, Vec::new()))
        }
    }

    /// Inspect status after an interruption, without changing phase or
    /// allowing further mutations in this session.
    pub fn inspect(&mut self) -> Result<BankInventory, FwumReadError<CON::Error>> {
        self.ipmi.fwum_banks(self.target)
    }
}
