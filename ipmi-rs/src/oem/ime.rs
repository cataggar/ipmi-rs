//! Explicit, identity-checked Intel ME firmware operations.
//!
//! Each request (including every write) checks the same selected IPMB
//! destination immediately before dispatch. A failed mutation response is
//! **not** retried; its outcome must be treated as unknown.

pub use ipmi_rs_core::oem::ime::{
    Capabilities, GetCapabilities, GetStatus, ImageType, ImeTarget, ResponseError, Status,
    UpdateState, Version,
};

use ipmi_rs_core::{
    app::DeviceId,
    connection::{Address, Channel, IpmiConnection, Message, NetFn},
    oem::ime::{self as core_ime, INTEL_IANA, ME_PRODUCT},
};

use super::{OemCommand, OemError, TargetDeviceId};
use crate::{Ipmi, IpmiError};

/// Maximum accepted image size (16 MiB). The wire size is a u32, but this
/// smaller bound limits allocation and the number of 22-byte writes.
pub const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const WRITE_BYTES: usize = 22;
const NETFN: NetFn = NetFn::Reserved(0x30);

/// The image's length or CRC-8 disagrees with independently provided metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageError {
    /// Empty image or larger than the supported safety bound.
    InvalidSize(usize),
    /// Image bytes did not match the expected length.
    SizeMismatch { expected: u32, actual: usize },
    /// CRC-8/ATM (poly 0x07, initial value zero) did not match.
    CrcMismatch { expected: u8, actual: u8 },
}

/// Validated, immutable bytes of a vendor-supplied ME operational image.
///
/// Expected size and CRC-8 must come from an independent, trusted image
/// manifest. CRC-8 is an error-detection checksum, **not** authentication.
#[derive(Debug, Clone)]
pub struct ValidatedImage {
    bytes: Vec<u8>,
    crc8: u8,
}

impl ValidatedImage {
    /// Validate all bytes before constructing a transferable image.
    pub fn new(bytes: Vec<u8>, expected_size: u32, expected_crc8: u8) -> Result<Self, ImageError> {
        if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES {
            return Err(ImageError::InvalidSize(bytes.len()));
        }
        if bytes.len() != expected_size as usize {
            return Err(ImageError::SizeMismatch {
                expected: expected_size,
                actual: bytes.len(),
            });
        }
        let actual = crc8(&bytes);
        if actual != expected_crc8 {
            return Err(ImageError::CrcMismatch {
                expected: expected_crc8,
                actual,
            });
        }
        Ok(Self {
            bytes,
            crc8: actual,
        })
    }

    /// Length in bytes, already bounded to fit in a u32.
    pub fn len(&self) -> u32 {
        self.bytes.len() as u32
    }

    /// A validated image is never empty.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The checksum sent when closing the update area.
    pub fn crc8(&self) -> u8 {
        self.crc8
    }
}

fn crc8(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0, |mut crc, byte| {
        crc ^= byte;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
        crc
    })
}

/// An identity-checked ME inventory snapshot.
#[derive(Debug, Clone)]
pub struct Inventory {
    /// The full Get Device ID reply of the selected ME.
    pub device: DeviceId,
    /// Firmware and SPS command version, and current image.
    pub version: Version,
    /// Current update/image state.
    pub status: Status,
    /// Supported areas and special capabilities.
    pub capabilities: Capabilities,
}

/// The operation at which a checked workflow stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Initial identity lookup.
    Identity,
    /// Read status during inventory or verification.
    Status,
    /// Read capabilities during inventory.
    Capabilities,
    /// Request an update (0xA0).
    Prepare,
    /// Open the operational-code area (0xA1).
    Open,
    /// Write a 22-byte-or-smaller chunk (0xA2), indexed from zero.
    Write(u32),
    /// Close the area with size and CRC (0xA3).
    Close,
    /// Register/activate the new image (0xA4).
    Activate,
    /// Register a manual rollback (0xA4).
    Rollback,
}

/// A checked workflow failure. Never infer that the complete operation
/// failed just because a later read or dispatch failed.
#[derive(Debug)]
pub enum WorkflowError<ConnectionError> {
    /// Identity, status or capability read failed; no action at this stage
    /// was dispatched. Earlier acknowledged mutations may still have occurred.
    Read {
        /// Failed read stage.
        stage: Stage,
        /// Failure with its identity/command distinction.
        error: OemError<ConnectionError, ResponseError>,
    },
    /// A mutation's identity lookup rejected the target before that command.
    NotSent {
        /// Rejected mutation.
        stage: Stage,
        /// Identity failure or unsupported device.
        error: OemError<ConnectionError, ResponseError>,
    },
    /// A mutation was dispatched but its acknowledgement is not trustworthy.
    /// Stop: the command must not be sent again automatically.
    OutcomeUnknown {
        /// Mutation with uncertain outcome.
        stage: Stage,
        /// Connection, completion-code or malformed-response error.
        error: IpmiError<ConnectionError, ResponseError>,
    },
    /// Required auxiliary firmware revision was missing.
    MissingVersion,
    /// Get Device ID reported that the target is not available.
    DeviceUnavailable,
    /// Unknown/recovery firmware or reserved running-area selector.
    UnsafeImageType,
    /// The required operation is not advertised.
    UnsupportedCapability,
    /// No valid rollback image, or an existing staged image prevents a new update.
    InvalidImageStatus,
    /// The operational staging area is too small for this image.
    InsufficientSpace { available: u32, needed: u32 },
    /// The device reported a state other than the one required at this stage.
    UnexpectedState {
        /// Last completed mutation or the preflight.
        stage: Stage,
        /// Required state.
        expected: UpdateState,
        /// Observed state.
        actual: UpdateState,
    },
}

#[derive(Debug)]
enum Action {
    Prepare,
    Open,
    Write { sequence: u8, bytes: Vec<u8> },
    Close { size: u32, crc8: u8 },
    Register { rollback: bool },
}

struct Mutation {
    target: ImeTarget,
    action: Action,
}

impl OemCommand for Mutation {
    type Output = ();
    type Error = ResponseError;
    const MANUFACTURER_ID: u32 = INTEL_IANA;
    const PRODUCT_ID: Option<u16> = Some(ME_PRODUCT);

    fn into_message(self) -> Message {
        let (cmd, data) = match self.action {
            Action::Prepare => (0xA0, vec![]),
            Action::Open => (0xA1, vec![0x01, 0x00]),
            Action::Write {
                sequence,
                mut bytes,
            } => {
                bytes.insert(0, sequence);
                (0xA2, bytes)
            }
            Action::Close { size, crc8 } => {
                let mut data = size.to_le_bytes().to_vec();
                data.extend_from_slice(&[crc8, 0]);
                (0xA3, data)
            }
            Action::Register { rollback } => (0xA4, vec![if rollback { 3 } else { 1 }, 0]),
        };
        Message::new_request(NETFN, cmd, data)
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(ResponseError::InvalidLength(data.len()))
        }
    }

    fn target(&self) -> Option<(Address, Channel)> {
        Some(self.target.route())
    }

    fn supports(&self, device: &DeviceId) -> bool {
        core_ime::is_ime(device)
    }
}

impl<CON: IpmiConnection> Ipmi<CON> {
    /// Read version, image/update status and capabilities of a selected ME.
    /// No OEM command is sent if its exact identity does not match.
    pub fn ime_info(&mut self, target: ImeTarget) -> Result<Inventory, WorkflowError<CON::Error>> {
        let device = self
            .send_recv(TargetDeviceId(Some(target.route())))
            .map_err(|error| WorkflowError::Read {
                stage: Stage::Identity,
                error: OemError::Identity(error),
            })?;
        if !core_ime::is_ime(&device) {
            return Err(WorkflowError::Read {
                stage: Stage::Identity,
                error: OemError::UnsupportedDevice {
                    manufacturer_id: device.manufacturer_id,
                    product_id: device.product_id,
                    expected_manufacturer_id: INTEL_IANA,
                    expected_product_id: Some(ME_PRODUCT),
                },
            });
        }
        let version = Version::from_device_id(&device).ok_or(WorkflowError::MissingVersion)?;
        let status = self.ime_status(target)?;
        let capabilities =
            self.send_oem(GetCapabilities(target))
                .map_err(|error| WorkflowError::Read {
                    stage: Stage::Capabilities,
                    error,
                })?;
        Ok(Inventory {
            device,
            version,
            status,
            capabilities,
        })
    }

    /// Check the selected ME's current status, without mutating it.
    pub fn ime_status(&mut self, target: ImeTarget) -> Result<Status, WorkflowError<CON::Error>> {
        self.send_oem(GetStatus(target))
            .map_err(|error| WorkflowError::Read {
                stage: Stage::Status,
                error,
            })
    }

    fn ime_mutate(
        &mut self,
        target: ImeTarget,
        stage: Stage,
        action: Action,
    ) -> Result<(), WorkflowError<CON::Error>> {
        match self.send_oem(Mutation { target, action }) {
            Ok(()) => Ok(()),
            Err(OemError::Command(error)) => Err(WorkflowError::OutcomeUnknown { stage, error }),
            Err(error) => Err(WorkflowError::NotSent { stage, error }),
        }
    }

    fn ime_expect(
        &mut self,
        target: ImeTarget,
        stage: Stage,
        expected: UpdateState,
    ) -> Result<Status, WorkflowError<CON::Error>> {
        let status = self.ime_status(target)?;
        if status.update_state != expected {
            return Err(WorkflowError::UnexpectedState {
                stage,
                expected,
                actual: status.update_state,
            });
        }
        Ok(status)
    }

    /// Stage and activate a prevalidated vendor image once, without replay.
    ///
    /// Requires an idle, available ME with an operational running image and
    /// enough free area. Checks status after every transition, including
    /// every write. A failure after dispatch needs manual on-device recovery;
    /// calling this function again is **not** a safe continuation.
    pub fn ime_update(
        &mut self,
        target: ImeTarget,
        image: &ValidatedImage,
    ) -> Result<Status, WorkflowError<CON::Error>> {
        let info = self.ime_info(target)?;
        if !info.device.device_available {
            return Err(WorkflowError::DeviceUnavailable);
        }
        if !matches!(
            info.version.image_type,
            ImageType::Operational1 | ImageType::Operational2
        ) || info.status.running_area() == 3
        {
            return Err(WorkflowError::UnsafeImageType);
        }
        if !info.capabilities.operational_area() {
            return Err(WorkflowError::UnsupportedCapability);
        }
        if info.status.update_state != UpdateState::Idle {
            return Err(WorkflowError::UnexpectedState {
                stage: Stage::Status,
                expected: UpdateState::Idle,
                actual: info.status.update_state,
            });
        }
        if info.status.staged_image_valid() {
            return Err(WorkflowError::InvalidImageStatus);
        }
        if info.status.free_area_size < image.len() {
            return Err(WorkflowError::InsufficientSpace {
                available: info.status.free_area_size,
                needed: image.len(),
            });
        }

        self.ime_mutate(target, Stage::Prepare, Action::Prepare)?;
        self.ime_expect(target, Stage::Prepare, UpdateState::Requested)?;
        self.ime_mutate(target, Stage::Open, Action::Open)?;
        self.ime_expect(target, Stage::Open, UpdateState::InProgress)?;

        for (index, chunk) in image.bytes.chunks(WRITE_BYTES).enumerate() {
            let stage = Stage::Write(index as u32);
            self.ime_mutate(
                target,
                stage,
                Action::Write {
                    sequence: index as u8,
                    bytes: chunk.to_vec(),
                },
            )?;
            self.ime_expect(target, stage, UpdateState::InProgress)?;
        }

        self.ime_mutate(
            target,
            Stage::Close,
            Action::Close {
                size: image.len(),
                crc8: image.crc8(),
            },
        )?;
        let status = self.ime_expect(target, Stage::Close, UpdateState::Requested)?;
        if !status.staged_image_valid() {
            return Err(WorkflowError::InvalidImageStatus);
        }
        self.ime_mutate(
            target,
            Stage::Activate,
            Action::Register { rollback: false },
        )?;
        self.ime_expect(target, Stage::Activate, UpdateState::Success)
    }

    /// Register and verify a manual rollback once, without replay.
    ///
    /// Requires an available ME, a valid rollback image, advertised rollback
    /// support and an inactive state. A failed acknowledgement is uncertain.
    pub fn ime_rollback(&mut self, target: ImeTarget) -> Result<Status, WorkflowError<CON::Error>> {
        let info = self.ime_info(target)?;
        if !info.device.device_available {
            return Err(WorkflowError::DeviceUnavailable);
        }
        if info.status.running_area() == 3 || info.version.image_type == ImageType::Unknown {
            return Err(WorkflowError::UnsafeImageType);
        }
        if !info.capabilities.rollback() {
            return Err(WorkflowError::UnsupportedCapability);
        }
        if !matches!(
            info.status.update_state,
            UpdateState::Idle | UpdateState::Success | UpdateState::Failed
        ) {
            return Err(WorkflowError::UnexpectedState {
                stage: Stage::Status,
                expected: UpdateState::Idle,
                actual: info.status.update_state,
            });
        }
        if !info.status.rollback_image_valid() {
            return Err(WorkflowError::InvalidImageStatus);
        }
        self.ime_mutate(target, Stage::Rollback, Action::Register { rollback: true })?;
        self.ime_expect(target, Stage::Rollback, UpdateState::RolledBack)
    }
}
