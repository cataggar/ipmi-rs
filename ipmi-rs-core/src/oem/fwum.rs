//! Kontron Firmware Update Manager wire commands (ipmitool `ipmi_fwum.c`).
//!
//! Reads are available by default. Mutating commands require the
//! `kontron-fwum-update` feature and are intended for the guarded workflow in
//! `ipmi-rs`; sending a command directly does not provide that workflow.

use crate::{
    app::DeviceId,
    connection::{Address, Channel, Message, NetFn},
};

use super::OemCommand;

/// A destination and an explicitly selected board product.
///
/// Every FWUM request rechecks both the Kontron IANA and this product against
/// Get Device ID on the same destination before sending the command.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FwumTarget {
    /// `None` selects the session BMC; otherwise route to this IPMB device.
    pub address: Option<(Address, Channel)>,
    /// Product ID from Get Device ID, not the controller's device ID.
    pub product_id: u16,
}

impl FwumTarget {
    /// Select a board and its BMC or bridged destination.
    pub const fn new(address: Option<(Address, Channel)>, product_id: u16) -> Self {
        Self {
            address,
            product_id,
        }
    }
}

/// Malformed or unsupported FWUM response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FwumParseError {
    /// Fewer bytes than the source command's response structure.
    Truncated { expected: usize, actual: usize },
    /// More bytes than the bounded response allocation permits.
    TooLong(usize),
    /// An undocumented value appeared in a field with known values.
    InvalidValue(u8),
}

fn length(data: &[u8], min: usize, max: usize) -> Result<(), FwumParseError> {
    if data.len() < min {
        Err(FwumParseError::Truncated {
            expected: min,
            actual: data.len(),
        })
    } else if data.len() > max {
        Err(FwumParseError::TooLong(data.len()))
    } else {
        Ok(())
    }
}

fn request(cmd: u8, data: Vec<u8>) -> Message {
    Message::new_request(NetFn::Firmware, cmd, data)
}

/// Firmware revision, with minor and subminor stored as separate nibbles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revision {
    /// Major revision.
    pub major: u8,
    /// High nibble of the second revision byte.
    pub minor: u8,
    /// Low nibble of the second revision byte.
    pub subminor: u8,
    /// SDR revision, where available.
    pub sdr: Option<u8>,
}

fn revision(major: u8, minor: u8, sdr: Option<u8>) -> Revision {
    Revision {
        major,
        minor: minor >> 4,
        subminor: minor & 0x0f,
        sdr,
    }
}

/// Firmware NetFn 0x08 / Get Firmware Info (0x00).
#[derive(Clone, Copy, Debug)]
pub struct GetInfo(pub FwumTarget);

/// The FWUM protocol response (not the App Get Device ID response).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    /// FWUM protocol version; revisions through 5 use addressed writes.
    pub protocol_revision: u8,
    /// Controller's device ID; should agree with Get Device ID.
    pub controller_device_id: u8,
    /// Debug-build bit in the flags byte.
    pub debug_build: bool,
    /// Sequence-address capability bit in the flags byte.
    pub sequence_address: bool,
    /// Running firmware revision (no SDR revision in this response).
    pub revision: Revision,
    /// Number of firmware banks, bounded by the high-level reader.
    pub bank_count: u8,
    /// Whether the source's revision/response-length test permits sequence writes.
    pub sequence_format: bool,
}

impl OemCommand for GetInfo {
    type Output = Info;
    type Error = FwumParseError;
    const MANUFACTURER_ID: u32 = 15000;

    fn into_message(self) -> Message {
        request(0x00, vec![])
    }

    fn parse_success_response(data: &[u8]) -> Result<Info, FwumParseError> {
        length(data, 6, 32)?;
        Ok(Info {
            protocol_revision: data[0],
            controller_device_id: data[1],
            debug_build: data[2] & 1 != 0,
            sequence_address: data[2] & 2 != 0,
            revision: revision(data[3], data[4], None),
            bank_count: data[5],
            sequence_format: data[0] > 5 && data.len() >= 7,
        })
    }

    fn target(&self) -> Option<(Address, Channel)> {
        self.0.address
    }

    fn supports(&self, device: &DeviceId) -> bool {
        device.manufacturer_id == Self::MANUFACTURER_ID && device.product_id == self.0.product_id
    }
}

/// Firmware bank state from command 0x07.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BankState {
    /// Nothing programmed.
    Empty,
    /// Newly downloaded image.
    NewFirmware,
    /// Waiting for firmware validation.
    WaitingForValidation,
    /// Current good image.
    LastKnownGood,
    /// Former good image.
    PreviousGood,
}

impl TryFrom<u8> for BankState {
    type Error = FwumParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Empty),
            1 => Ok(Self::NewFirmware),
            2 => Ok(Self::WaitingForValidation),
            3 => Ok(Self::LastKnownGood),
            4 => Ok(Self::PreviousGood),
            other => Err(FwumParseError::InvalidValue(other)),
        }
    }
}

/// Firmware NetFn / Get Firmware Status (0x07), one bank per request.
#[derive(Clone, Copy, Debug)]
pub struct GetStatus {
    /// Bound destination.
    pub target: FwumTarget,
    /// Zero-based bank number, less than the reported bank count.
    pub bank: u8,
}

/// The status of one numbered bank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BankStatus {
    /// Firmware bank state.
    pub state: BankState,
    /// 24-bit firmware size (zero for empty banks, ignoring unused reply bytes).
    pub length: u32,
    /// Image version including SDR revision.
    pub revision: Revision,
}

impl OemCommand for GetStatus {
    type Output = BankStatus;
    type Error = FwumParseError;
    const MANUFACTURER_ID: u32 = 15000;

    fn into_message(self) -> Message {
        request(0x07, vec![self.bank])
    }

    fn parse_success_response(data: &[u8]) -> Result<BankStatus, FwumParseError> {
        length(data, 7, 32)?;
        let state = BankState::try_from(data[0])?;
        let (size, image_revision) = if state == BankState::Empty {
            (0, revision(0, 0, None))
        } else {
            (
                u32::from_le_bytes([data[1], data[2], data[3], 0]),
                revision(data[4], data[5], Some(data[6])),
            )
        };
        Ok(BankStatus {
            state,
            length: size,
            revision: image_revision,
        })
    }

    fn target(&self) -> Option<(Address, Channel)> {
        self.target.address
    }

    fn supports(&self, device: &DeviceId) -> bool {
        device.manufacturer_id == Self::MANUFACTURER_ID
            && device.product_id == self.target.product_id
    }
}

/// The seven trace chunks each contain seven 3-byte command entries.
pub const TRACE_CHUNKS: u8 = 7;
/// Maximum supported banks, to bound requests even if firmware lies.
pub const MAX_BANKS: u8 = 16;

/// Firmware NetFn / Get Trace Log (0x0F).
#[derive(Clone, Copy, Debug)]
pub struct GetTraceChunk {
    /// Bound destination.
    pub target: FwumTarget,
    /// Index from 0 through 6.
    pub index: u8,
}

/// A valid trace entry: firmware command, state (1–3), and completion code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceEntry {
    /// Standard command IDs 0–15 or extended IDs 0xC0–0xC5.
    pub command_id: u8,
    /// Begin, progress, or completed (1–3).
    pub state: u8,
    /// Raw completion code.
    pub completion_code: u8,
}

impl OemCommand for GetTraceChunk {
    type Output = Vec<TraceEntry>;
    type Error = FwumParseError;
    const MANUFACTURER_ID: u32 = 15000;

    fn into_message(self) -> Message {
        request(0x0f, vec![self.index])
    }

    fn parse_success_response(data: &[u8]) -> Result<Vec<TraceEntry>, FwumParseError> {
        length(data, 21, 32)?;
        let mut entries = Vec::with_capacity(7);
        for item in data[..21].as_chunks::<3>().0 {
            if item[1] == 0 || !(item[0] < 16 || (0xc0..=0xc5).contains(&item[0])) {
                continue;
            }
            if item[1] > 3 {
                return Err(FwumParseError::InvalidValue(item[1]));
            }
            entries.push(TraceEntry {
                command_id: item[0],
                state: item[1],
                completion_code: item[2],
            });
        }
        Ok(entries)
    }

    fn target(&self) -> Option<(Address, Channel)> {
        self.target.address
    }

    fn supports(&self, device: &DeviceId) -> bool {
        device.manufacturer_id == Self::MANUFACTURER_ID
            && device.product_id == self.target.product_id
    }
}

/// Image-header validation error. No on-device writes are made for these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageError {
    /// Header at 0x5A0 or the image data is incomplete.
    Truncated,
    /// The image exceeds the source's 512 KiB image buffer or 24-bit wire size.
    TooLarge,
    /// Big-endian size in the header does not match the actual image length.
    SizeMismatch,
    /// The header's big-endian 16-bit byte checksum is incorrect.
    ChecksumMismatch,
}

/// Parsed, size- and checksum-verified Kontron firmware image.
///
/// The header is at 0x5A0, with big-endian size, checksum, board ID, and
/// little-endian three-byte IANA, as in `ipmi_fwum.h`. The header checksum is
/// the 16-bit additive negative byte sum with its two bytes omitted; the
/// on-wire Start Image padding is the negative byte sum *including* them.
#[derive(Clone)]
pub struct FirmwareImage<'a> {
    bytes: &'a [u8],
    /// Product ID from the image header.
    pub board_id: u16,
    /// Manufacturer IANA from the image header.
    pub iana: u32,
    /// Controller device ID encoded in the image.
    pub device_id: u8,
    /// Image table version (zero-board legacy handling is not accepted here).
    pub table_version: u8,
    /// Implementation revision.
    pub implementation_revision: u8,
    /// Image version for Finish Image.
    pub revision: Revision,
}

impl<'a> FirmwareImage<'a> {
    /// Parse a complete image; reject invalid size or byte checksum before I/O.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ImageError> {
        const HEADER: usize = 0x5a0;
        if bytes.len() < HEADER + 20 {
            return Err(ImageError::Truncated);
        }
        if bytes.len() > 512 * 1024 || bytes.len() > 0x00ff_ffff {
            return Err(ImageError::TooLarge);
        }
        let h = &bytes[HEADER..HEADER + 20];
        let size = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) as usize;
        if size != bytes.len() {
            return Err(ImageError::SizeMismatch);
        }
        let checksum = u16::from_be_bytes([h[4], h[5]]);
        let sum = bytes.iter().enumerate().fold(0u16, |sum, (index, byte)| {
            if index == HEADER + 4 || index == HEADER + 5 {
                sum
            } else {
                sum.wrapping_add(u16::from(*byte))
            }
        });
        if checksum != 0u16.wrapping_sub(sum) {
            return Err(ImageError::ChecksumMismatch);
        }
        Ok(Self {
            bytes,
            board_id: u16::from_be_bytes([h[6], h[7]]),
            iana: u32::from_le_bytes([h[14], h[15], h[16], 0]),
            device_id: h[8],
            table_version: h[9],
            implementation_revision: h[10],
            revision: revision(h[11] & 0x0f, h[12], Some(h[13])),
        })
    }

    /// The complete image length.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the complete image is empty (always false for valid images).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Image bytes for the guarded uploader.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// 16-bit little-endian Start Image padding computed over the whole file.
    pub fn padding(&self) -> u16 {
        0u16.wrapping_sub(
            self.bytes
                .iter()
                .fold(0u16, |sum, byte| sum.wrapping_add(u16::from(*byte))),
        )
    }
}

#[cfg(feature = "kontron-fwum-update")]
mod mutation {
    use super::*;

    /// Address writes are used for old FWUM; sequence writes require protocol >5.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DownloadMode {
        /// 24-bit byte address followed by one-byte length.
        Address,
        /// Wrapping one-byte sequence number.
        Sequence,
    }

    /// Firmware NetFn / Start Firmware Image (0x0A).
    pub struct StartImage {
        /// Bound destination.
        pub target: FwumTarget,
        /// Verified image size (24-bit wire value).
        pub size: u32,
        /// Negative byte sum of the complete image.
        pub padding: u16,
        /// Protocol revision's transfer mode.
        pub mode: DownloadMode,
    }

    /// The bank selected by Start Firmware Image.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct StartedBank(pub u8);

    /// Firmware NetFn / Save Firmware Image (0x0B).
    pub struct SaveImage<'a> {
        /// Bound destination.
        pub target: FwumTarget,
        /// Address mode offset (24-bit) or sequence mode's verified offset.
        pub offset: u32,
        /// Sequence counter (wraps at 256).
        pub sequence: u8,
        /// Payload slice from the verified image.
        pub bytes: &'a [u8],
        /// Protocol revision's transfer mode.
        pub mode: DownloadMode,
    }

    /// Firmware NetFn / Finish Firmware Image (0x0C).
    pub struct FinishImage {
        /// Bound destination.
        pub target: FwumTarget,
        /// Verified image revision.
        pub revision: Revision,
    }

    /// Firmware NetFn / Start Firmware Update (0x09), wait for shutdown.
    pub struct StartUpdate(pub FwumTarget);

    /// Firmware NetFn / Manual Rollback (0x0E), wait for shutdown.
    pub struct ManualRollback(pub FwumTarget);

    /// Kontron OEM Set Channel Buffer Length (0x3E/0x82), on LUN zero.
    pub struct SetChannelBuffer {
        /// Bound destination, local BMC or remote board.
        pub target: FwumTarget,
        /// 0x0E for the running interface, 0x00 for local IPMB.
        pub channel: BufferChannel,
        /// Negotiated size (zero restores the controller default).
        pub size: u8,
    }

    /// The two buffer channels used by ipmitool's Kontron setup.
    #[derive(Clone, Copy, Debug)]
    pub enum BufferChannel {
        /// Running interface (0x0E).
        Current,
        /// IPMB from the local controller (0x00).
        Ipmb,
    }

    macro_rules! destination {
        ($field:tt) => {
            fn target(&self) -> Option<(Address, Channel)> {
                self.$field.address
            }

            fn supports(&self, device: &DeviceId) -> bool {
                device.manufacturer_id == Self::MANUFACTURER_ID
                    && device.product_id == self.$field.product_id
            }
        };
    }

    fn no_data(data: &[u8]) -> Result<(), FwumParseError> {
        length(data, 0, 0)
    }

    impl OemCommand for StartImage {
        type Output = StartedBank;
        type Error = FwumParseError;
        const MANUFACTURER_ID: u32 = 15000;

        fn into_message(self) -> Message {
            let [a, b, c, _] = self.size.to_le_bytes();
            let [lo, hi] = self.padding.to_le_bytes();
            let mut payload = vec![a, b, c, lo, hi];
            if self.mode == DownloadMode::Sequence {
                payload.push(1);
            }
            request(0x0a, payload)
        }

        fn parse_success_response(data: &[u8]) -> Result<StartedBank, FwumParseError> {
            length(data, 1, 1)?;
            Ok(StartedBank(data[0]))
        }

        destination!(target);
    }

    impl OemCommand for SaveImage<'_> {
        type Output = ();
        type Error = FwumParseError;
        const MANUFACTURER_ID: u32 = 15000;

        fn into_message(self) -> Message {
            let mut payload = match self.mode {
                DownloadMode::Address => {
                    let [lo, mid, hi, _] = self.offset.to_le_bytes();
                    vec![lo, mid, hi, self.bytes.len() as u8]
                }
                DownloadMode::Sequence => vec![self.sequence],
            };
            payload.extend_from_slice(self.bytes);
            request(0x0b, payload)
        }

        fn parse_success_response(data: &[u8]) -> Result<(), FwumParseError> {
            no_data(data)
        }

        destination!(target);
    }

    impl OemCommand for FinishImage {
        type Output = ();
        type Error = FwumParseError;
        const MANUFACTURER_ID: u32 = 15000;

        fn into_message(self) -> Message {
            request(
                0x0c,
                vec![
                    self.revision.major,
                    self.revision.minor << 4 | self.revision.subminor,
                    self.revision.sdr.unwrap_or(0),
                    0,
                ],
            )
        }

        fn parse_success_response(data: &[u8]) -> Result<(), FwumParseError> {
            no_data(data)
        }

        destination!(target);
    }

    impl OemCommand for StartUpdate {
        type Output = ();
        type Error = FwumParseError;
        const MANUFACTURER_ID: u32 = 15000;
        fn into_message(self) -> Message {
            request(0x09, vec![0])
        }
        fn parse_success_response(data: &[u8]) -> Result<(), FwumParseError> {
            no_data(data)
        }
        destination!(0);
    }

    impl OemCommand for ManualRollback {
        type Output = ();
        type Error = FwumParseError;
        const MANUFACTURER_ID: u32 = 15000;
        fn into_message(self) -> Message {
            request(0x0e, vec![0])
        }
        fn parse_success_response(data: &[u8]) -> Result<(), FwumParseError> {
            no_data(data)
        }
        destination!(0);
    }

    impl OemCommand for SetChannelBuffer {
        type Output = ();
        type Error = FwumParseError;
        const MANUFACTURER_ID: u32 = 15000;
        fn into_message(self) -> Message {
            let channel = match self.channel {
                BufferChannel::Current => 0x0e,
                BufferChannel::Ipmb => 0,
            };
            Message::new_request(NetFn::Reserved(0x3e), 0x82, vec![channel, self.size])
        }
        fn parse_success_response(data: &[u8]) -> Result<(), FwumParseError> {
            no_data(data)
        }
        destination!(target);
    }
}

#[cfg(feature = "kontron-fwum-update")]
pub use mutation::*;
