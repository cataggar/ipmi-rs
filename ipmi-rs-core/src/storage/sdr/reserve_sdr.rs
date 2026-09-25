use std::num::NonZeroU16;

use crate::connection::{IpmiCommand, Message, NetFn};

/// A reservation response was truncated or returned the invalid ID zero.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReservationError {
    NotEnoughData,
    InvalidId,
}

fn parse_reservation(data: &[u8]) -> Result<NonZeroU16, ReservationError> {
    let bytes = data.get(..2).ok_or(ReservationError::NotEnoughData)?;
    NonZeroU16::new(u16::from_le_bytes([bytes[0], bytes[1]])).ok_or(ReservationError::InvalidId)
}

/// Reserve the SDR repository (Storage netfn, command 0x22).
pub struct ReserveSdrRepository;

impl From<ReserveSdrRepository> for Message {
    fn from(_: ReserveSdrRepository) -> Self {
        Message::new_request(NetFn::Storage, 0x22, vec![])
    }
}

impl IpmiCommand for ReserveSdrRepository {
    type Output = NonZeroU16;
    type Error = ReservationError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        parse_reservation(data)
    }
}

/// Reserve Device SDRs (Sensor/Event netfn, command 0x22).
pub struct ReserveDeviceSdr;

impl From<ReserveDeviceSdr> for Message {
    fn from(_: ReserveDeviceSdr) -> Self {
        Message::new_request(NetFn::SensorEvent, 0x22, vec![])
    }
}

impl IpmiCommand for ReserveDeviceSdr {
    type Output = NonZeroU16;
    type Error = ReservationError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        parse_reservation(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_commands_use_their_own_netfn() {
        let repo: Message = ReserveSdrRepository.into();
        let device: Message = ReserveDeviceSdr.into();
        assert_eq!(
            (repo.netfn(), repo.cmd(), repo.data()),
            (NetFn::Storage, 0x22, &[][..])
        );
        assert_eq!(
            (device.netfn(), device.cmd(), device.data()),
            (NetFn::SensorEvent, 0x22, &[][..])
        );
    }

    #[test]
    fn reservation_ids_must_be_present_and_nonzero() {
        assert_eq!(
            ReserveSdrRepository::parse_success_response(&[0x34, 0x12])
                .unwrap()
                .get(),
            0x1234
        );
        assert_eq!(
            ReserveDeviceSdr::parse_success_response(&[0, 0]),
            Err(ReservationError::InvalidId)
        );
        assert_eq!(
            ReserveDeviceSdr::parse_success_response(&[1]),
            Err(ReservationError::NotEnoughData)
        );
    }
}
