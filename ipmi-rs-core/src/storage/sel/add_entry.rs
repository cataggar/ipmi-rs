use crate::connection::{IpmiCommand, Message, NetFn};

use super::{Entry, ParseEntryError, RecordId, SelMutation};

/// Invalid SEL entry payload or add response.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddSelEntryError {
    /// The request must contain exactly one 16-byte SEL record.
    InvalidLength(usize),
    /// The BMC assigns the record ID; use 0x0000 in the request.
    NonzeroRecordId(u16),
    /// The record's known fields were malformed.
    InvalidEntry(ParseEntryError),
    /// Successful completion must return a real (non-sentinel) record ID.
    InvalidResponse(usize),
}

/// Add a complete SEL record (Storage 0x44); construction validates the payload.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AddSelEntry([u8; 16]);

impl AddSelEntry {
    pub fn new(data: &[u8]) -> Result<Self, AddSelEntryError> {
        let raw: [u8; 16] = data
            .try_into()
            .map_err(|_| AddSelEntryError::InvalidLength(data.len()))?;
        let id = u16::from_le_bytes([raw[0], raw[1]]);
        if id != 0 {
            return Err(AddSelEntryError::NonzeroRecordId(id));
        }
        Entry::parse(&raw).map_err(AddSelEntryError::InvalidEntry)?;
        Ok(Self(raw))
    }
}

impl IpmiCommand for AddSelEntry {
    type Output = RecordId;
    type Error = AddSelEntryError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let bytes: [u8; 2] = data
            .try_into()
            .map_err(|_| AddSelEntryError::InvalidResponse(data.len()))?;
        RecordId::new(u16::from_le_bytes(bytes))
            .ok_or(AddSelEntryError::InvalidResponse(data.len()))
    }
}

impl From<AddSelEntry> for Message {
    fn from(value: AddSelEntry) -> Self {
        Message::new_request(NetFn::Storage, 0x44, value.0.to_vec())
    }
}

impl SelMutation for AddSelEntry {}
