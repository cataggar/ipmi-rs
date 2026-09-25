mod get;
pub use get::GetSensorReading;

mod thresholds;
pub use thresholds::*;

use crate::storage::sdr::{
    discrete_state_description, event_reading_type_code::EventReadingTypeCodes,
    event_reading_type_code::Threshold, record::WithSensorRecordCommon,
};

pub trait FromSensorReading {
    type Sensor;

    fn from(sensor: &Self::Sensor, reading: &RawSensorReading) -> Self;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSensorReading {
    reading: u8,
    all_event_messages_disabled: bool,
    scanning_disabled: bool,
    reading_or_state_unavailable: bool,
    offset_data_1: Option<u8>,
    offset_data_2: Option<u8>,
}

/// The response's reading/state-unavailable bit; scanning status is separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadingAvailability {
    Available,
    Unavailable,
}

/// Flags reported by Get Sensor Reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadingFlags {
    pub availability: ReadingAvailability,
    pub scanning_enabled: bool,
    pub event_messages_enabled: bool,
}

impl RawSensorReading {
    pub fn flags(&self) -> ReadingFlags {
        ReadingFlags {
            availability: if self.reading_or_state_unavailable {
                ReadingAvailability::Unavailable
            } else {
                ReadingAvailability::Available
            },
            scanning_enabled: !self.scanning_disabled,
            event_messages_enabled: !self.all_event_messages_disabled,
        }
    }

    /// Raw first response byte, even when the availability flag says it is invalid.
    pub fn raw_reading(&self) -> u8 {
        self.reading
    }

    pub fn reading(&self) -> Option<u8> {
        (!self.reading_or_state_unavailable).then_some(self.reading)
    }

    /// Both optional state bytes (offsets 0..=7 and 8..=14, respectively).
    /// Bit 7 of the second byte is reserved but retained verbatim.
    pub fn state_bytes(&self) -> (Option<u8>, Option<u8>) {
        (self.offset_data_1, self.offset_data_2)
    }

    /// Interpret discrete states using full or compact SDR metadata.
    pub fn discrete_for(
        &self,
        sensor: &impl WithSensorRecordCommon,
    ) -> Result<DiscreteReading, DiscreteReadingError> {
        DiscreteReading::from_sensor(sensor, self)
    }
}

/// An asserted offset; unknown or OEM offsets retain their numeric value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscreteState {
    pub offset: u8,
    pub description: Option<&'static str>,
    /// Whether this offset is in the SDR's discrete reading mask.
    pub advertised: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscreteReading {
    pub flags: ReadingFlags,
    pub reading: Option<u8>,
    pub state_bytes: (Option<u8>, Option<u8>),
    pub states: Vec<DiscreteState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscreteReadingError {
    NotDiscrete,
    MissingStateByte(u8),
}

impl DiscreteReading {
    pub fn from_sensor(
        sensor: &impl WithSensorRecordCommon,
        raw: &RawSensorReading,
    ) -> Result<Self, DiscreteReadingError> {
        let common = sensor.common();
        if !matches!(
            common.event_reading_type_code,
            EventReadingTypeCodes::DiscreteGeneric(_)
                | EventReadingTypeCodes::SensorSpecific
                | EventReadingTypeCodes::Oem(_)
        ) {
            return Err(DiscreteReadingError::NotDiscrete);
        }
        let flags = raw.flags();
        let state_bytes = raw.state_bytes();
        let mut states = Vec::new();
        if flags.availability == ReadingAvailability::Available {
            let low = state_bytes
                .0
                .ok_or(DiscreteReadingError::MissingStateByte(1))?;
            if common.discrete_reading_mask & 0x7F00 != 0 && state_bytes.1.is_none() {
                return Err(DiscreteReadingError::MissingStateByte(2));
            }
            let bits = u16::from(low) | (u16::from(state_bytes.1.unwrap_or(0) & 0x7F) << 8);
            for offset in 0..=14 {
                if bits & (1 << offset) != 0 {
                    states.push(DiscreteState {
                        offset,
                        description: discrete_state_description(
                            common.event_reading_type_code,
                            common.ty,
                            offset,
                        ),
                        advertised: common.discrete_reading_mask & (1 << offset) != 0,
                    });
                }
            }
        }
        Ok(Self {
            flags,
            reading: raw.reading(),
            state_bytes,
            states,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ThresholdStatus {
    pub at_or_above_non_recoverable: bool,
    pub at_or_above_upper_critical: bool,
    pub at_or_above_upper_non_critical: bool,
    pub at_or_below_lower_non_recoverable: bool,
    pub at_or_below_lower_critical: bool,
    pub at_or_below_lower_non_critical: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ThresholdReading {
    pub all_event_messages_disabled: bool,
    pub scanning_disabled: bool,
    pub reading: Option<u8>,
    pub threshold_status: Option<ThresholdStatus>,
}

impl From<&RawSensorReading> for ThresholdReading {
    fn from(in_reading: &RawSensorReading) -> Self {
        let threshold_status = if in_reading.reading_or_state_unavailable {
            None
        } else {
            in_reading.offset_data_1.map(|d| ThresholdStatus {
                at_or_above_non_recoverable: (d & 0x20) == 0x20,
                at_or_above_upper_critical: (d & 0x10 == 0x10),
                at_or_above_upper_non_critical: (d & 0x08) == 0x08,
                at_or_below_lower_non_recoverable: (d & 0x04) == 0x04,
                at_or_below_lower_critical: (d & 0x02) == 0x02,
                at_or_below_lower_non_critical: (d & 0x01) == 0x01,
            })
        };

        let reading = if in_reading.reading_or_state_unavailable {
            None
        } else {
            Some(in_reading.reading)
        };

        Self {
            all_event_messages_disabled: in_reading.all_event_messages_disabled,
            scanning_disabled: in_reading.scanning_disabled,
            reading,
            threshold_status,
        }
    }
}

impl FromSensorReading for ThresholdReading {
    type Sensor = Threshold;

    fn from(_: &Self::Sensor, in_reading: &RawSensorReading) -> Self {
        in_reading.into()
    }
}

#[cfg(test)]
mod tests {
    use super::{RawSensorReading, ThresholdReading};

    #[test]
    fn lower_critical_uses_bit_one() {
        let raw_reading = RawSensorReading::parse(&[0x00, 0xC0, 0x02]).unwrap();
        let reading = ThresholdReading::from(&raw_reading);
        let status = reading.threshold_status.unwrap();

        assert!(status.at_or_below_lower_critical);
        assert!(!status.at_or_above_non_recoverable);

        let raw_reading = RawSensorReading::parse(&[0x00, 0xC0, 0x20]).unwrap();
        let reading = ThresholdReading::from(&raw_reading);
        let status = reading.threshold_status.unwrap();

        assert!(!status.at_or_below_lower_critical);
        assert!(status.at_or_above_non_recoverable);
    }
}

#[cfg(test)]
mod command_tests;
