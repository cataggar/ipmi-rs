use std::num::NonZeroU16;

use nonmax::NonMaxU8;

use crate::connection::{IpmiCommand, Message, NetFn, NotEnoughData};

use super::{Record, RecordId, RecordParseError};

fn request(
    netfn: NetFn,
    cmd: u8,
    reservation_id: Option<NonZeroU16>,
    record_id: RecordId,
    offset: u8,
    length: u8,
) -> Message {
    let mut data = Vec::with_capacity(6);
    data.extend_from_slice(
        &reservation_id
            .map(NonZeroU16::get)
            .unwrap_or(0)
            .to_le_bytes(),
    );
    data.extend_from_slice(&record_id.value().to_le_bytes());
    data.extend_from_slice(&[offset, length]);
    Message::new_request(netfn, cmd, data)
}

/// Get a complete record from the SDR repository (Storage netfn, command 0x23).
///
/// The `0xFF` length requests the entire record and may exceed the transport
/// limit. For traversal, prefer `Ipmi::sdrs_fallible` in `ipmi-rs`.
#[derive(Debug, Clone, Copy)]
pub struct GetSdr {
    reservation_id: Option<NonZeroU16>,
    record_id: RecordId,
}

impl GetSdr {
    pub fn new(reservation_id: Option<NonZeroU16>, record_id: RecordId) -> Self {
        Self {
            reservation_id,
            record_id,
        }
    }
}

impl From<GetSdr> for Message {
    fn from(value: GetSdr) -> Self {
        request(
            NetFn::Storage,
            0x23,
            value.reservation_id,
            value.record_id,
            0,
            0xFF,
        )
    }
}

impl IpmiCommand for GetSdr {
    type Output = RecordInfo;
    type Error = (RecordParseError, Option<RecordId>);

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        parse_full_record(data)
    }
}

/// Get a complete Device SDR (Sensor/Event netfn, command 0x21).
///
/// Previously this public type erroneously sent Get SDR to the repository.
/// Use [`GetSdr`] for the old wire operation. This constructor and its
/// `RecordInfo` result are retained.
#[derive(Debug, Clone, Copy)]
pub struct GetDeviceSdr {
    reservation_id: Option<NonZeroU16>,
    record_id: RecordId,
}

impl GetDeviceSdr {
    pub fn new(reservation_id: Option<NonZeroU16>, record_id: RecordId) -> Self {
        Self {
            reservation_id,
            record_id,
        }
    }
}

impl From<GetDeviceSdr> for Message {
    fn from(value: GetDeviceSdr) -> Self {
        request(
            NetFn::SensorEvent,
            0x21,
            value.reservation_id,
            value.record_id,
            0,
            0xFF,
        )
    }
}

impl IpmiCommand for GetDeviceSdr {
    type Output = RecordInfo;
    type Error = (RecordParseError, Option<RecordId>);

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        parse_full_record(data)
    }
}

fn parse_full_record(data: &[u8]) -> Result<RecordInfo, (RecordParseError, Option<RecordId>)> {
    let next_id = data
        .get(..2)
        .map(|v| RecordId::new_raw(u16::from_le_bytes([v[0], v[1]])));
    RecordInfo::parse(data).map_err(|e| (e, next_id))
}

/// The next record ID and bytes returned by a partial SDR read.
#[derive(Debug, Clone, PartialEq)]
pub struct SdrChunk {
    pub next_entry: RecordId,
    pub data: Vec<u8>,
}

fn parse_chunk(data: &[u8]) -> Result<SdrChunk, NotEnoughData> {
    if data.len() < 2 {
        return Err(NotEnoughData);
    }
    Ok(SdrChunk {
        next_entry: RecordId::new_raw(u16::from_le_bytes([data[0], data[1]])),
        data: data[2..].to_vec(),
    })
}

/// A nonzero SDR partial-read length, excluding `0xff` (the full-record sentinel).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SdrReadLength(NonMaxU8);

impl SdrReadLength {
    pub fn new(length: u8) -> Option<Self> {
        if length == 0 {
            return None;
        }
        NonMaxU8::new(length).map(Self)
    }

    pub fn get(&self) -> u8 {
        self.0.get()
    }
}

/// Read a bounded range of bytes from an SDR repository record.
///
/// `offset` counts from the start of the five-byte SDR header. Callers must
/// verify the response contains exactly `length` bytes before using it.
#[derive(Debug, Clone, Copy)]
pub struct ReadSdr {
    reservation_id: Option<NonZeroU16>,
    record_id: RecordId,
    offset: u8,
    length: SdrReadLength,
}

impl ReadSdr {
    pub fn new(
        reservation_id: Option<NonZeroU16>,
        record_id: RecordId,
        offset: u8,
        length: SdrReadLength,
    ) -> Self {
        Self {
            reservation_id,
            record_id,
            offset,
            length,
        }
    }
}

impl From<ReadSdr> for Message {
    fn from(value: ReadSdr) -> Self {
        request(
            NetFn::Storage,
            0x23,
            value.reservation_id,
            value.record_id,
            value.offset,
            value.length.get(),
        )
    }
}

impl IpmiCommand for ReadSdr {
    type Output = SdrChunk;
    type Error = NotEnoughData;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        parse_chunk(data)
    }
}

/// Read a bounded range of bytes from a Device SDR.
#[derive(Debug, Clone, Copy)]
pub struct ReadDeviceSdr {
    reservation_id: Option<NonZeroU16>,
    record_id: RecordId,
    offset: u8,
    length: SdrReadLength,
}

impl ReadDeviceSdr {
    pub fn new(
        reservation_id: Option<NonZeroU16>,
        record_id: RecordId,
        offset: u8,
        length: SdrReadLength,
    ) -> Self {
        Self {
            reservation_id,
            record_id,
            offset,
            length,
        }
    }
}

impl From<ReadDeviceSdr> for Message {
    fn from(value: ReadDeviceSdr) -> Self {
        request(
            NetFn::SensorEvent,
            0x21,
            value.reservation_id,
            value.record_id,
            value.offset,
            value.length.get(),
        )
    }
}

impl IpmiCommand for ReadDeviceSdr {
    type Output = SdrChunk;
    type Error = NotEnoughData;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        parse_chunk(data)
    }
}

#[derive(Debug, Clone)]
pub struct RecordInfo {
    pub next_entry: RecordId,
    pub record: Record,
}

impl RecordInfo {
    pub fn parse(data: &[u8]) -> Result<Self, RecordParseError> {
        if data.len() < 2 {
            return Err(RecordParseError::NotEnoughData);
        }
        let next_entry = RecordId::new_raw(u16::from_le_bytes([data[0], data[1]]));
        Record::parse(&data[2..]).map(|record| Self { next_entry, record })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_and_device_use_distinct_wire_commands() {
        let repo: Message = GetSdr::new(None, RecordId::FIRST).into();
        let device: Message = GetDeviceSdr::new(None, RecordId::FIRST).into();
        assert_eq!((repo.netfn(), repo.cmd()), (NetFn::Storage, 0x23));
        assert_eq!((device.netfn(), device.cmd()), (NetFn::SensorEvent, 0x21));
        assert_eq!(repo.data(), [0, 0, 0, 0, 0, 0xff]);
        assert_eq!(device.data(), repo.data());

        let length = SdrReadLength::new(32).unwrap();
        let repo: Message =
            ReadSdr::new(NonZeroU16::new(0x1234), RecordId::new_raw(7), 5, length).into();
        let device: Message =
            ReadDeviceSdr::new(NonZeroU16::new(0x1234), RecordId::new_raw(7), 5, length).into();
        assert_eq!((repo.netfn(), repo.cmd()), (NetFn::Storage, 0x23));
        assert_eq!((device.netfn(), device.cmd()), (NetFn::SensorEvent, 0x21));
        assert_eq!(repo.data(), [0x34, 0x12, 7, 0, 5, 32]);
        assert_eq!(device.data(), repo.data());
    }

    #[test]
    fn short_responses_are_errors_not_panics() {
        assert_eq!(SdrReadLength::new(0), None);
        assert_eq!(SdrReadLength::new(0xff), None);
        for data in [&[][..], &[1][..], &[1, 0, 2][..]] {
            assert!(GetSdr::parse_success_response(data).is_err());
            assert!(GetDeviceSdr::parse_success_response(data).is_err());
            assert!(RecordInfo::parse(data).is_err());
        }
        assert_eq!(ReadSdr::parse_success_response(&[1]), Err(NotEnoughData));
    }
}
