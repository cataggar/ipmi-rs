use crate::connection::{Address, Channel, IpmiCommand, LogicalUnit, Message, NetFn};

/// Maximum transfer bytes used by the high-level bounded transfer helpers.
pub const DEFAULT_CHUNK_BYTES: usize = 16;

/// How offsets and returned counts are addressed by a FRU device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FruAccess {
    /// Offsets and returned counts are bytes.
    Byte,
    /// Offsets and returned counts are 16-bit words (the request count is bytes).
    Word,
}

impl FruAccess {
    fn unit(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
        }
    }
}

/// Get FRU Inventory Area Info result. `size` is always in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FruInfo {
    /// Device inventory size, in bytes.
    pub size: u16,
    /// Addressing unit of the device.
    pub access: FruAccess,
}

/// FRU command construction, response, or transfer validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FruCommandError {
    /// A response is too short, has an inconsistent byte count, or has extra data.
    MalformedResponse,
    /// Device reported zero inventory size.
    EmptyInventory,
    /// Empty or overlarge transfer; the count byte cannot encode it.
    InvalidLength,
    /// Offset plus length exceeds the reported inventory size.
    OutOfBounds,
    /// Word-addressed inventory requires even byte offsets and lengths.
    Unaligned,
    /// Device acknowledged fewer or more bytes than requested.
    UnexpectedCount,
}

fn validate(info: FruInfo, offset: u16, len: usize) -> Result<u16, FruCommandError> {
    if len == 0 || len > u8::MAX as usize {
        return Err(FruCommandError::InvalidLength);
    }
    if offset as usize + len > info.size as usize {
        return Err(FruCommandError::OutOfBounds);
    }
    if !(offset as usize).is_multiple_of(info.access.unit())
        || !len.is_multiple_of(info.access.unit())
    {
        return Err(FruCommandError::Unaligned);
    }
    Ok(offset / info.access.unit() as u16)
}

/// Get FRU Inventory Area Info (Storage netfn, command `0x10`).
#[derive(Clone, Copy, Debug)]
pub struct GetFruInventoryAreaInfo {
    /// FRU device ID.
    pub id: u8,
    /// Optional bridged target from a logical SDR FRU locator.
    pub target: Option<(Address, Channel)>,
    /// Target logical unit.
    pub lun: LogicalUnit,
}

impl GetFruInventoryAreaInfo {
    /// Construct the info request.
    pub fn new(id: u8, target: Option<(Address, Channel)>, lun: LogicalUnit) -> Self {
        Self { id, target, lun }
    }
}

impl From<GetFruInventoryAreaInfo> for Message {
    fn from(value: GetFruInventoryAreaInfo) -> Self {
        Message::new_request(NetFn::Storage, 0x10, vec![value.id])
    }
}

impl IpmiCommand for GetFruInventoryAreaInfo {
    type Output = FruInfo;
    type Error = FruCommandError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.len() != 3 {
            return Err(FruCommandError::MalformedResponse);
        }
        let size = u16::from_le_bytes([data[0], data[1]]);
        if size == 0 {
            return Err(FruCommandError::EmptyInventory);
        }
        Ok(FruInfo {
            size,
            access: if data[2] & 1 == 1 {
                FruAccess::Word
            } else {
                FruAccess::Byte
            },
        })
    }

    fn target(&self) -> Option<(Address, Channel)> {
        self.target
    }

    fn target_lun(&self) -> LogicalUnit {
        self.lun
    }
}

/// Read FRU Data (Storage netfn, command `0x11`).
#[derive(Clone, Copy, Debug)]
pub struct ReadFruData {
    /// FRU device ID.
    id: u8,
    /// FRU byte offset.
    offset: u16,
    /// Number of bytes requested.
    count: u8,
    /// FRU access method.
    access: FruAccess,
    /// Optional bridged target.
    target: Option<(Address, Channel)>,
    lun: LogicalUnit,
}

impl ReadFruData {
    /// Construct a bounded read. `count` is bytes even for word-access FRUs;
    /// the wire offset and response count are converted to words as needed.
    pub fn new(
        id: u8,
        target: Option<(Address, Channel)>,
        lun: LogicalUnit,
        info: FruInfo,
        offset: u16,
        count: u8,
    ) -> Result<Self, FruCommandError> {
        validate(info, offset, count as usize)?;
        Ok(Self {
            id,
            offset,
            count,
            access: info.access,
            target,
            lun,
        })
    }

    /// Validate a successful response against this particular request and
    /// return the received inventory bytes. Short reads are not silently filled.
    pub fn verify(self, response: ReadFruDataResponse) -> Result<Vec<u8>, FruCommandError> {
        if response.count as usize * self.access.unit() != self.count as usize {
            return Err(FruCommandError::UnexpectedCount);
        }
        if response.data.len() != self.count as usize {
            return Err(FruCommandError::MalformedResponse);
        }
        Ok(response.data)
    }
}

impl From<ReadFruData> for Message {
    fn from(value: ReadFruData) -> Self {
        let offset = value.offset / value.access.unit() as u16;
        let [low, high] = offset.to_le_bytes();
        Message::new_request(NetFn::Storage, 0x11, vec![value.id, low, high, value.count])
    }
}

/// Raw read result. Call [`ReadFruData::verify`] before using the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadFruDataResponse {
    /// Returned byte or word count according to the device access mode.
    pub count: u8,
    /// Inventory bytes.
    pub data: Vec<u8>,
}

impl IpmiCommand for ReadFruData {
    type Output = ReadFruDataResponse;
    type Error = FruCommandError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let Some((&count, bytes)) = data.split_first() else {
            return Err(FruCommandError::MalformedResponse);
        };
        if count == 0 || bytes.is_empty() {
            return Err(FruCommandError::UnexpectedCount);
        }
        Ok(ReadFruDataResponse {
            count,
            data: bytes.to_vec(),
        })
    }

    fn target(&self) -> Option<(Address, Channel)> {
        self.target
    }

    fn target_lun(&self) -> LogicalUnit {
        self.lun
    }
}

/// An explicit Write FRU Data command (Storage netfn, command `0x12`).
///
/// The constructor checks transfer bounds and alignment, not the checksum of
/// an entire image. Validate the complete image with [`super::FruInventory::parse`]
/// before writing, or use `Ipmi::write_fru_image` from `ipmi-rs`.
///
/// Never retry a write after any failure: the remote device may already have
/// committed it, including when the acknowledgement was lost.
#[derive(Clone, Debug)]
pub struct WriteFruData {
    /// FRU device ID.
    id: u8,
    /// FRU byte offset.
    offset: u16,
    /// Bytes to write.
    data: Vec<u8>,
    /// FRU access method.
    access: FruAccess,
    /// Optional bridged target.
    target: Option<(Address, Channel)>,
    lun: LogicalUnit,
}

impl WriteFruData {
    /// Validate boundaries/alignment and construct one explicit write.
    pub fn new(
        id: u8,
        target: Option<(Address, Channel)>,
        lun: LogicalUnit,
        info: FruInfo,
        offset: u16,
        data: Vec<u8>,
    ) -> Result<Self, FruCommandError> {
        validate(info, offset, data.len())?;
        Ok(Self {
            id,
            offset,
            data,
            access: info.access,
            target,
            lun,
        })
    }

    /// Validate the device-reported byte/word count against this write.
    pub fn verify(&self, count: u8) -> Result<(), FruCommandError> {
        if count as usize * self.access.unit() != self.data.len() {
            return Err(FruCommandError::UnexpectedCount);
        }
        Ok(())
    }
}

impl From<WriteFruData> for Message {
    fn from(value: WriteFruData) -> Self {
        let offset = value.offset / value.access.unit() as u16;
        let mut bytes = vec![value.id];
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend(value.data);
        Message::new_request(NetFn::Storage, 0x12, bytes)
    }
}

impl IpmiCommand for WriteFruData {
    type Output = u8;
    type Error = FruCommandError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.len() != 1 {
            return Err(FruCommandError::MalformedResponse);
        }
        Ok(data[0])
    }

    fn target(&self) -> Option<(Address, Channel)> {
        self.target
    }

    fn target_lun(&self) -> LogicalUnit {
        self.lun
    }
}
