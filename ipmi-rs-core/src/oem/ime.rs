//! Intel Manageability Engine (IME) identity, inventory and read-only commands.
//!
//! This is the ME at an explicitly selected IPMB address, **not** a generic
//! Intel BMC. Firmware mutations are available only through the checked
//! workflow in `ipmi_rs::oem::ime`.

use crate::{
    app::DeviceId,
    connection::{Address, Channel, Message, NetFn},
};

use super::OemCommand;

const NETFN: NetFn = NetFn::Reserved(0x30);

/// Intel ME's Get Device ID manufacturer number.
pub const INTEL_IANA: u32 = 343;
/// The ME product ID required by ipmitool's `ime info` implementation.
pub const ME_PRODUCT: u16 = 0x0B00;

/// An explicitly selected, bridged IPMB destination for the ME.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ImeTarget {
    address: Address,
    channel: Channel,
}

impl ImeTarget {
    /// Select an even, nonzero IPMB slave address on a numbered channel.
    /// Direct BMC requests and implicit/current-channel targets are excluded.
    pub fn new(address: Address, channel: Channel) -> Option<Self> {
        if address.0 != 0 && address.0 & 1 == 0 && matches!(channel, Channel::Numbered(_)) {
            Some(Self { address, channel })
        } else {
            None
        }
    }

    /// Address and channel supplied to the identity-checked sender.
    pub fn route(self) -> (Address, Channel) {
        (self.address, self.channel)
    }
}

/// The device's reported active image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageType {
    /// Recovery firmware.
    Recovery,
    /// First operational image.
    Operational1,
    /// Second operational image.
    Operational2,
    /// Reserved image selector.
    Unknown,
}

/// The firmware and command-protocol versions from Get Device ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    /// Firmware major revision.
    pub major: u8,
    /// Firmware minor digits (the first two source-format components).
    pub minor_digits: [u8; 2],
    /// Four hexadecimal digits of the auxiliary firmware build revision.
    pub build_digits: [u8; 4],
    /// The two hexadecimal digits of the SPS IPMI command version.
    pub command_digits: [u8; 2],
    /// Current image type from the low two bits of auxiliary byte 3.
    pub image_type: ImageType,
    /// Uninterpreted auxiliary image flags, including the image selector.
    pub image_flags: u8,
}

impl Version {
    /// Decode the version fields in ipmitool's `ime info` output. An absent
    /// auxiliary revision cannot be used as an inventory or update preflight.
    pub fn from_device_id(device: &DeviceId) -> Option<Self> {
        let aux = device.aux_revision?;
        Some(Self {
            major: device.major_fw_revision,
            minor_digits: [device.minor_fw_revision / 10, device.minor_fw_revision % 10],
            build_digits: [aux[1] >> 4, aux[1] & 15, aux[2] >> 4, aux[2] & 15],
            command_digits: [aux[0] >> 4, aux[0] & 15],
            image_type: match aux[3] & 3 {
                0 => ImageType::Recovery,
                1 => ImageType::Operational1,
                2 => ImageType::Operational2,
                _ => ImageType::Unknown,
            },
            image_flags: aux[3],
        })
    }
}

/// The decoded IME update state (OEM 0x30/0xA6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateState {
    /// No update active.
    Idle,
    /// Update was requested or a staged image is ready.
    Requested,
    /// An update area is open.
    InProgress,
    /// Update succeeded.
    Success,
    /// Update failed.
    Failed,
    /// Rollback succeeded.
    RolledBack,
    /// Update aborted.
    Aborted,
    /// Initialization failed.
    InitFailed,
}

impl TryFrom<u8> for UpdateState {
    type Error = ResponseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Idle),
            1 => Ok(Self::Requested),
            2 => Ok(Self::InProgress),
            3 => Ok(Self::Success),
            4 => Ok(Self::Failed),
            5 => Ok(Self::RolledBack),
            6 => Ok(Self::Aborted),
            7 => Ok(Self::InitFailed),
            _ => Err(ResponseError::UnknownState(value)),
        }
    }
}

/// A malformed or unexpected IME command reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseError {
    /// A reply did not have one of the documented fixed lengths.
    InvalidLength(usize),
    /// The state is not defined in the ipmitool IME implementation.
    UnknownState(u8),
    /// A four-byte C-enum state contained nonzero high bytes.
    InvalidWideState,
}

/// Image and update state decoded from OEM 0x30/0xA6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    /// Raw image-status bits.
    pub image_status: u8,
    /// Update state.
    pub update_state: UpdateState,
    /// Raw update-attempt status.
    pub update_attempt_status: u8,
    /// Raw rollback-attempt status.
    pub rollback_attempt_status: u8,
    /// Raw update-type indicator.
    pub update_type: u8,
    /// Raw dependent-image flag.
    pub dependent_flag: u8,
    /// Available staging-area bytes (little endian on the wire).
    pub free_area_size: u32,
}

impl Status {
    /// Parse the ten-byte protocol layout or the thirteen-byte packed-C-enum
    /// layout used by some builds of the source. Reject all other lengths.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ResponseError> {
        let offset = match data.len() {
            10 => 2,
            13 if data[2..5] == [0, 0, 0] => 5,
            13 => return Err(ResponseError::InvalidWideState),
            n => return Err(ResponseError::InvalidLength(n)),
        };
        Ok(Self {
            image_status: data[0],
            update_state: data[1].try_into()?,
            update_attempt_status: data[offset],
            rollback_attempt_status: data[offset + 1],
            update_type: data[offset + 2],
            dependent_flag: data[offset + 3],
            free_area_size: u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()),
        })
    }

    /// Whether the staging image is reported valid.
    pub fn staged_image_valid(self) -> bool {
        self.image_status & 0x02 != 0
    }

    /// Whether a valid rollback image is available.
    pub fn rollback_image_valid(self) -> bool {
        self.image_status & 0x04 != 0
    }

    /// Currently running CODE image-area selector (0, 1 or 2; 3 is reserved).
    pub fn running_area(self) -> u8 {
        (self.image_status >> 3) & 0x03
    }
}

/// Update capabilities decoded from OEM 0x30/0xA7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Raw supported-area bits.
    pub area_supported: u8,
    /// Raw special-capability bits.
    pub special_caps: u8,
}

impl Capabilities {
    /// Parse an exact, two-byte response.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ResponseError> {
        let [area_supported, special_caps] = data else {
            return Err(ResponseError::InvalidLength(data.len()));
        };
        Ok(Self {
            area_supported: *area_supported,
            special_caps: *special_caps,
        })
    }

    /// Operational-code staging area support.
    pub fn operational_area(self) -> bool {
        self.area_supported & 0x02 != 0
    }

    /// PIA area support.
    pub fn pia_area(self) -> bool {
        self.area_supported & 0x04 != 0
    }

    /// SDR area support.
    pub fn sdr_area(self) -> bool {
        self.area_supported & 0x08 != 0
    }

    /// Manual rollback support.
    pub fn rollback(self) -> bool {
        self.special_caps & 0x01 != 0
    }

    /// Recovery-image support.
    pub fn recovery(self) -> bool {
        self.special_caps & 0x02 != 0
    }
}

/// Check all four ipmitool ME identifiers, not just Intel's manufacturer ID.
pub fn is_ime(device: &DeviceId) -> bool {
    device.manufacturer_id == INTEL_IANA
        && device.product_id == ME_PRODUCT
        && device.device_id == 0
        && device.device_revision == 0
}

/// Read update status from the selected ME.
#[derive(Debug, Clone, Copy)]
pub struct GetStatus(pub ImeTarget);

impl OemCommand for GetStatus {
    type Output = Status;
    type Error = ResponseError;
    const MANUFACTURER_ID: u32 = INTEL_IANA;
    const PRODUCT_ID: Option<u16> = Some(ME_PRODUCT);

    fn into_message(self) -> Message {
        Message::new_request(NETFN, 0xA6, vec![])
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        Status::from_bytes(data)
    }

    fn target(&self) -> Option<(Address, Channel)> {
        Some(self.0.route())
    }

    fn supports(&self, device: &DeviceId) -> bool {
        is_ime(device)
    }
}

/// Read update capabilities from the selected ME.
#[derive(Debug, Clone, Copy)]
pub struct GetCapabilities(pub ImeTarget);

impl OemCommand for GetCapabilities {
    type Output = Capabilities;
    type Error = ResponseError;
    const MANUFACTURER_ID: u32 = INTEL_IANA;
    const PRODUCT_ID: Option<u16> = Some(ME_PRODUCT);

    fn into_message(self) -> Message {
        Message::new_request(NETFN, 0xA7, vec![])
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        Capabilities::from_bytes(data)
    }

    fn target(&self) -> Option<(Address, Channel)> {
        Some(self.0.route())
    }

    fn supports(&self, device: &DeviceId) -> bool {
        is_ime(device)
    }
}
