//! Validation of HPM.1 upgrade image files, before any firmware mutation.

use ipmi_rs_core::hpm::{ComponentId, ComponentMask, FirmwareVersion};

const HEADER_SIZE: usize = 34;
const IMAGE_HEADER_SIZE: usize = 31;
const SIGNATURE_SIZE: usize = 16;
const MAX_IMAGE_SIZE: usize = 64 * 1024 * 1024;
const MAX_ACTIONS: usize = 256;

/// Invalid HPM.1 package. No IPMI request is made by parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageError {
    /// The file is truncated or a length overflows its bounds.
    Bounds,
    /// Files larger than 64 MiB or with more than 256 actions are unsupported.
    Limit,
    /// Invalid PICMG image signature or format version.
    Format,
    /// A header or action-record checksum is invalid.
    Checksum,
    /// The final MD5 image integrity signature is invalid.
    Integrity,
    /// A component mask is empty, refers to an undeclared component, or an
    /// upload action does not specify exactly one component.
    Components,
    /// An unknown action type was encountered.
    Action(u8),
    /// The package has no image for one of its declared components.
    MissingImage,
}

/// HPM.1 image header. Timeout values are in five-second units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageHeader {
    /// Target device identifier.
    pub device_id: u8,
    /// Three-byte manufacturer identifier, in wire order.
    pub manufacturer: [u8; 3],
    /// Product ID (little-endian).
    pub product: u16,
    /// Image capabilities.
    pub capabilities: u8,
    /// Declared component mask.
    pub components: ComponentMask,
    /// Self-test timeout.
    pub self_test_timeout: u8,
    /// Rollback timeout.
    pub rollback_timeout: u8,
    /// Inaccessibility timeout.
    pub inaccessible_timeout: u8,
    /// Earliest compatible firmware revision, major and BCD minor.
    pub earliest_revision: [u8; 2],
    /// Package firmware revision.
    pub firmware_revision: FirmwareVersion,
}

/// One ordered, fully bounded action record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageAction<'a> {
    /// Back up the selected components.
    Backup(ComponentMask),
    /// Prepare the selected components.
    Prepare(ComponentMask),
    /// Upload exactly one component's image bytes.
    Upload {
        /// Target component.
        component: ComponentId,
        /// Firmware version in this record.
        version: FirmwareVersion,
        /// Raw 21-byte description (not necessarily UTF-8).
        description: [u8; 21],
        /// Validated image bytes.
        data: &'a [u8],
    },
}

/// Validated HPM.1 image. Borrowed bytes must remain available during upload.
///
/// Parsing verifies the entire file including record bounds and MD5 before
/// any update action can start. MD5 is the format's integrity check, not an
/// authenticity check; validate the vendor and source of the image separately.
#[derive(Debug)]
pub struct Package<'a> {
    /// Parsed package header.
    pub header: PackageHeader,
    actions: Vec<PackageAction<'a>>,
}

impl<'a> Package<'a> {
    /// Validate an entire HPM.1 package (no disk or network IO).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PackageError> {
        if bytes.len() > MAX_IMAGE_SIZE {
            return Err(PackageError::Limit);
        }
        if bytes.len() < HEADER_SIZE + 1 + SIGNATURE_SIZE {
            return Err(PackageError::Bounds);
        }
        let content_end = bytes.len() - SIGNATURE_SIZE;
        if md5::compute(&bytes[..content_end]).0 != bytes[content_end..] {
            return Err(PackageError::Integrity);
        }
        if &bytes[..8] != b"PICMGFWU" || bytes[8] != 0 || bytes[19] & 0x0f != 0 {
            return Err(PackageError::Format);
        }
        let oem_length = u16::from_le_bytes([bytes[32], bytes[33]]) as usize;
        let offset = HEADER_SIZE
            .checked_add(oem_length)
            .and_then(|n| n.checked_add(1))
            .ok_or(PackageError::Bounds)?;
        if offset > content_end {
            return Err(PackageError::Bounds);
        }
        if bytes[..offset]
            .iter()
            .fold(0u8, |sum, byte| sum.wrapping_add(*byte))
            != 0
        {
            return Err(PackageError::Checksum);
        }
        let components = ComponentMask::new(bytes[20]).ok_or(PackageError::Components)?;
        let header = PackageHeader {
            device_id: bytes[9],
            manufacturer: bytes[10..13].try_into().expect("fixed header"),
            product: u16::from_le_bytes(bytes[13..15].try_into().expect("fixed header")),
            capabilities: bytes[19],
            components,
            self_test_timeout: bytes[21],
            rollback_timeout: bytes[22],
            inaccessible_timeout: bytes[23],
            earliest_revision: bytes[24..26].try_into().expect("fixed header"),
            firmware_revision: FirmwareVersion(bytes[26..32].try_into().expect("fixed header")),
        };
        let mut actions = Vec::new();
        let mut uploaded = 0u8;
        let mut pos = offset;
        while pos < content_end {
            if actions.len() >= MAX_ACTIONS {
                return Err(PackageError::Limit);
            }
            if content_end - pos < 3 {
                return Err(PackageError::Bounds);
            }
            let record = &bytes[pos..pos + 3];
            let action = record[0];
            let bits = record[1];
            let mask = ComponentMask::new(bits).ok_or(PackageError::Components)?;
            if bits & !components.bits() != 0 {
                return Err(PackageError::Components);
            }
            let short_checksum = record.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) == 0;
            match action {
                0 | 1 => {
                    if !short_checksum {
                        return Err(PackageError::Checksum);
                    }
                    actions.push(if action == 0 {
                        PackageAction::Backup(mask)
                    } else {
                        PackageAction::Prepare(mask)
                    });
                    pos += 3;
                }
                2 => {
                    if bits.count_ones() != 1 {
                        return Err(PackageError::Components);
                    }
                    let header_end = pos
                        .checked_add(3 + IMAGE_HEADER_SIZE)
                        .ok_or(PackageError::Bounds)?;
                    if header_end > content_end {
                        return Err(PackageError::Bounds);
                    }
                    let image_header =
                        bytes.get(pos + 3..header_end).ok_or(PackageError::Bounds)?;
                    if !short_checksum
                        && bytes[pos..header_end]
                            .iter()
                            .fold(0u8, |sum, b| sum.wrapping_add(*b))
                            != 0
                    {
                        return Err(PackageError::Checksum);
                    }
                    let image_len =
                        u32::from_le_bytes(image_header[27..31].try_into().expect("fixed header"))
                            as usize;
                    if image_len == 0 {
                        return Err(PackageError::Bounds);
                    }
                    let end = header_end
                        .checked_add(image_len)
                        .ok_or(PackageError::Bounds)?;
                    let data = bytes.get(header_end..end).filter(|_| end <= content_end);
                    let data = data.ok_or(PackageError::Bounds)?;
                    let component = ComponentId::new(bits.trailing_zeros() as u8)
                        .expect("single nonzero bit fits in u8");
                    actions.push(PackageAction::Upload {
                        component,
                        version: FirmwareVersion(
                            image_header[..6].try_into().expect("fixed image header"),
                        ),
                        description: image_header[6..27].try_into().expect("fixed image header"),
                        data,
                    });
                    uploaded |= bits;
                    pos = end;
                }
                _ => return Err(PackageError::Action(action)),
            }
        }
        if uploaded != components.bits() {
            return Err(PackageError::MissingImage);
        }
        Ok(Self { header, actions })
    }

    /// Ordered backup, prepare and image-upload actions.
    pub fn actions(&self) -> &[PackageAction<'a>] {
        &self.actions
    }
}
