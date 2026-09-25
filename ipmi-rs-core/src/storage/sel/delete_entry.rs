use std::num::NonZeroU16;

use crate::connection::{IpmiCommand, Message, NetFn};

use super::{RecordId, SelMutation};

/// Invalid record ID or malformed delete response.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeleteSelEntryError {
    /// The FIRST and LAST sentinel IDs are not deletable records.
    InvalidRecordId,
    /// Successful completion must return a real (non-sentinel) record ID.
    InvalidResponse(usize),
}

/// Delete a specific SEL record (Storage 0x46). No automatic retries are made.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeleteSelEntry {
    reservation: Option<NonZeroU16>,
    record_id: RecordId,
}

impl DeleteSelEntry {
    /// Pass a reservation ID if supported by the target, or `None` otherwise.
    pub fn new(
        reservation: Option<NonZeroU16>,
        record_id: RecordId,
    ) -> Result<Self, DeleteSelEntryError> {
        if record_id.is_first() || record_id.is_last() {
            return Err(DeleteSelEntryError::InvalidRecordId);
        }
        Ok(Self {
            reservation,
            record_id,
        })
    }
}

impl IpmiCommand for DeleteSelEntry {
    type Output = RecordId;
    type Error = DeleteSelEntryError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let bytes: [u8; 2] = data
            .try_into()
            .map_err(|_| DeleteSelEntryError::InvalidResponse(data.len()))?;
        RecordId::new(u16::from_le_bytes(bytes))
            .ok_or(DeleteSelEntryError::InvalidResponse(data.len()))
    }
}

impl From<DeleteSelEntry> for Message {
    fn from(value: DeleteSelEntry) -> Self {
        let mut data = Vec::with_capacity(4);
        data.extend(value.reservation.map_or(0, NonZeroU16::get).to_le_bytes());
        data.extend(value.record_id.value().to_le_bytes());
        Message::new_request(NetFn::Storage, 0x46, data)
    }
}

impl SelMutation for DeleteSelEntry {}
