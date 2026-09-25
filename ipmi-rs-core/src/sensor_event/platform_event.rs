//! Platform Event Message (IPMI 2.0, section 29.3).

use crate::{
    connection::{IpmiCommand, Message, NetFn},
    storage::{sdr::SensorType, sel::EventDirection},
};

/// The wire format differs between a system interface and a LAN/IPMB link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventInterface {
    /// OpenIPMI or another system interface: prefix the SMS generator ID (0x41).
    System,
    /// LAN or IPMB: the interface supplies the generator ID.
    LanOrIpmb,
}

/// Invalid field in an explicitly requested platform event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformEventFieldError {
    /// The sensor type is reserved by the IPMI specification.
    SensorType(u8),
    /// Sensor number 0xff is reserved.
    SensorNumber(u8),
    /// The event/reading type is reserved.
    EventType(u8),
}

/// A platform event injected only when the caller explicitly sends this command.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PlatformEventMessage {
    sensor_type: u8,
    sensor_number: u8,
    event_type: u8,
    direction: EventDirection,
    data: [u8; 3],
    interface: EventInterface,
}

impl PlatformEventMessage {
    /// Validate the sensor and event/reading type before constructing an event.
    ///
    /// Event data is opaque: OEM and sensor-specific formats may use all 24 bits.
    /// The event-message revision is fixed at 0x04 (IPMI 2.0).
    pub fn new(
        sensor_type: SensorType,
        sensor_number: u8,
        event_type: u8,
        direction: EventDirection,
        data: [u8; 3],
        interface: EventInterface,
    ) -> Result<Self, PlatformEventFieldError> {
        let sensor_type = u8::from(sensor_type);
        if matches!(SensorType::from(sensor_type), SensorType::Reserved(_)) {
            return Err(PlatformEventFieldError::SensorType(sensor_type));
        }
        if sensor_number == 0xff {
            return Err(PlatformEventFieldError::SensorNumber(sensor_number));
        }
        if !matches!(event_type, 0x01..=0x0c | 0x6f..=0x7f) {
            return Err(PlatformEventFieldError::EventType(event_type));
        }
        Ok(Self {
            sensor_type,
            sensor_number,
            event_type,
            direction,
            data,
            interface,
        })
    }
}

/// The BMC acknowledged success but supplied unexpected response data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformEventResponseError(pub usize);

impl IpmiCommand for PlatformEventMessage {
    type Output = ();
    type Error = PlatformEventResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(PlatformEventResponseError(data.len()))
        }
    }
}

impl From<PlatformEventMessage> for Message {
    fn from(event: PlatformEventMessage) -> Self {
        let mut data = Vec::with_capacity(if event.interface == EventInterface::System {
            8
        } else {
            7
        });
        if event.interface == EventInterface::System {
            data.push(0x41);
        }
        data.extend([
            0x04,
            event.sensor_type,
            event.sensor_number,
            event.event_type
                | if event.direction == EventDirection::Deassert {
                    0x80
                } else {
                    0
                },
        ]);
        data.extend(event.data);
        Message::new_request(NetFn::SensorEvent, 0x02, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_event_wire_fixtures() {
        for (interface, expected) in [
            (
                EventInterface::LanOrIpmb,
                vec![4, 1, 0x30, 1, 9, 0xff, 0xff],
            ),
            (
                EventInterface::System,
                vec![0x41, 4, 1, 0x30, 1, 9, 0xff, 0xff],
            ),
        ] {
            let event = PlatformEventMessage::new(
                SensorType::Temperature,
                0x30,
                1,
                EventDirection::Assert,
                [9, 0xff, 0xff],
                interface,
            )
            .unwrap();
            let message: Message = event.into();
            assert_eq!(message.netfn_raw(), 4);
            assert_eq!(message.cmd(), 2);
            assert_eq!(message.data(), expected);
        }
        let event = PlatformEventMessage::new(
            SensorType::Memory,
            0x53,
            0x6f,
            EventDirection::Deassert,
            [0, 0xff, 0xff],
            EventInterface::LanOrIpmb,
        )
        .unwrap();
        let message: Message = event.into();
        assert_eq!(message.data(), &[4, 0x0c, 0x53, 0xef, 0, 0xff, 0xff]);
    }

    #[test]
    fn rejects_reserved_fields_and_malformed_ack() {
        let make = |ty, num, event| {
            PlatformEventMessage::new(
                ty,
                num,
                event,
                EventDirection::Assert,
                [0; 3],
                EventInterface::System,
            )
        };
        assert_eq!(
            make(SensorType::Reserved(0x2d), 1, 1),
            Err(PlatformEventFieldError::SensorType(0x2d))
        );
        assert_eq!(
            make(SensorType::Temperature, 0xff, 1),
            Err(PlatformEventFieldError::SensorNumber(0xff))
        );
        assert_eq!(
            make(SensorType::Temperature, 0, 0x0d),
            Err(PlatformEventFieldError::EventType(0x0d))
        );
        assert_eq!(
            PlatformEventMessage::parse_success_response(&[1]),
            Err(PlatformEventResponseError(1))
        );
    }
}
