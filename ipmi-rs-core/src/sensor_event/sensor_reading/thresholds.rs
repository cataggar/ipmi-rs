use crate::{
    connection::{Address, Channel, CompletionErrorCode, IpmiCommand, LogicalUnit, Message, NetFn},
    storage::sdr::{
        event_reading_type_code::EventReadingTypeCodes,
        record::{
            FullSensorRecord, SensorKey, SensorNumber, ThresholdKind, ThresholdValueError, Value,
            WithSensorRecordCommon,
        },
    },
};

/// Errors decoding, validating or submitting sensor thresholds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThresholdError {
    InvalidLength {
        expected: usize,
        actual: usize,
    },
    InvalidMask(u8),
    UnsupportedSensor,
    UnsupportedThreshold(ThresholdKind),
    DuplicateThreshold(ThresholdKind),
    NoThresholds,
    Conversion {
        kind: ThresholdKind,
        error: ThresholdValueError,
    },
    InvalidOrder {
        lower: ThresholdKind,
        upper: ThresholdKind,
    },
    /// The BMC returned a nonzero completion code; the code is retained.
    Rejected(CompletionErrorCode),
}

/// The six raw thresholds and their availability mask reported by the BMC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorThresholds {
    mask: u8,
    values: [u8; 6],
}

impl SensorThresholds {
    pub fn mask(&self) -> u8 {
        self.mask
    }

    /// Returns `None` for an unsupported/unreported threshold, ignoring its placeholder byte.
    pub fn raw(&self, kind: ThresholdKind) -> Option<u8> {
        (self.mask & kind.mask() != 0).then_some(self.values[kind.index()])
    }

    /// Convert a reported threshold to the sensor's physical units, if linear/analog.
    pub fn value(&self, kind: ThresholdKind, sensor: &FullSensorRecord) -> Option<Value> {
        sensor.threshold_value(self.raw(kind)?)
    }

    /// Check the BMC's reported mask against a full or compact SDR.
    pub fn validate_for(&self, sensor: &impl WithSensorRecordCommon) -> Result<(), ThresholdError> {
        if sensor.common().event_reading_type_code != EventReadingTypeCodes::Threshold {
            return Err(ThresholdError::UnsupportedSensor);
        }
        for kind in ThresholdKind::variants() {
            if self.raw(kind).is_some() && !sensor.capabilities().threshold_access.readable(kind) {
                return Err(ThresholdError::UnsupportedThreshold(kind));
            }
        }
        Ok(())
    }
}

/// Get Sensor Thresholds (Sensor/Event netfn, command `0x27`).
#[derive(Debug, Clone, Copy)]
pub struct GetSensorThresholds {
    sensor_number: SensorNumber,
    address: Address,
    channel: Channel,
    lun: LogicalUnit,
}

impl GetSensorThresholds {
    pub fn new(sensor_number: SensorNumber, address: Address, channel: Channel) -> Self {
        Self {
            sensor_number,
            address,
            channel,
            lun: LogicalUnit::Zero,
        }
    }

    pub fn for_sensor_key(key: &SensorKey) -> Self {
        let mut command = Self::new(
            key.sensor_number,
            Address(key.owner_id.into()),
            key.owner_channel,
        );
        command.lun = key.owner_lun;
        command
    }
}

impl From<GetSensorThresholds> for Message {
    fn from(command: GetSensorThresholds) -> Self {
        Message::new_request(NetFn::SensorEvent, 0x27, vec![command.sensor_number.get()])
    }
}

impl IpmiCommand for GetSensorThresholds {
    type Output = SensorThresholds;
    type Error = ThresholdError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        Some(ThresholdError::Rejected(code))
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.len() != 7 {
            return Err(ThresholdError::InvalidLength {
                expected: 7,
                actual: data.len(),
            });
        }
        if data[0] & !0x3F != 0 {
            return Err(ThresholdError::InvalidMask(data[0]));
        }
        let mut values = [0; 6];
        values.copy_from_slice(&data[1..]);
        Ok(SensorThresholds {
            mask: data[0],
            values,
        })
    }

    fn target(&self) -> Option<(Address, Channel)> {
        Some((self.address, self.channel))
    }

    fn target_lun(&self) -> LogicalUnit {
        self.lun
    }
}

/// Raw register byte or a physical value in the SDR's sensor units.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThresholdSetting {
    Raw(u8),
    Converted(Value),
}

/// Explicit Set Sensor Thresholds (Sensor/Event netfn, command `0x26`).
///
/// The mask selects only supplied thresholds; all other bytes are zero.
/// Send this command only once. A timeout, lost response or ambiguous failure
/// does not establish whether the write occurred; never automatically retry it.
#[derive(Debug, Clone, Copy)]
pub struct SetSensorThresholds {
    sensor_number: SensorNumber,
    address: Address,
    channel: Channel,
    lun: LogicalUnit,
    mask: u8,
    values: [u8; 6],
}

impl SetSensorThresholds {
    /// Validate a nonempty set of distinct, SDR-settable thresholds before sending.
    /// Supplied linear thresholds must be in physical-value order; thresholds
    /// omitted by a partial write cannot be checked against the BMC's current values.
    pub fn new(
        sensor: &FullSensorRecord,
        settings: &[(ThresholdKind, ThresholdSetting)],
    ) -> Result<Self, ThresholdError> {
        if sensor.common().event_reading_type_code != EventReadingTypeCodes::Threshold {
            return Err(ThresholdError::UnsupportedSensor);
        }
        if settings.is_empty() {
            return Err(ThresholdError::NoThresholds);
        }
        let mut mask = 0u8;
        let mut values = [0u8; 6];
        for &(kind, setting) in settings {
            if mask & kind.mask() != 0 {
                return Err(ThresholdError::DuplicateThreshold(kind));
            }
            if !sensor.capabilities().threshold_access.settable(kind) {
                return Err(ThresholdError::UnsupportedThreshold(kind));
            }
            values[kind.index()] = match setting {
                ThresholdSetting::Raw(raw) => raw,
                ThresholdSetting::Converted(value) => sensor
                    .threshold_raw(value)
                    .map_err(|error| ThresholdError::Conversion { kind, error })?,
            };
            mask |= kind.mask();
        }

        let mut previous: Option<(ThresholdKind, Value)> = None;
        for kind in [
            ThresholdKind::LowerNonRecoverable,
            ThresholdKind::LowerCritical,
            ThresholdKind::LowerNonCritical,
            ThresholdKind::UpperNonCritical,
            ThresholdKind::UpperCritical,
            ThresholdKind::UpperNonRecoverable,
        ] {
            if mask & kind.mask() == 0 {
                continue;
            }
            if let Some(value) = sensor.threshold_value(values[kind.index()]) {
                if let Some((lower, prior)) = previous {
                    if prior.value() > value.value() {
                        return Err(ThresholdError::InvalidOrder { lower, upper: kind });
                    }
                }
                previous = Some((kind, value));
            }
        }

        let key = sensor.common().key;
        Ok(Self {
            sensor_number: key.sensor_number,
            address: Address(key.owner_id.into()),
            channel: key.owner_channel,
            lun: key.owner_lun,
            mask,
            values,
        })
    }

    pub fn mask(&self) -> u8 {
        self.mask
    }
}

impl From<SetSensorThresholds> for Message {
    fn from(command: SetSensorThresholds) -> Self {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&[command.sensor_number.get(), command.mask]);
        data.extend_from_slice(&command.values);
        Message::new_request(NetFn::SensorEvent, 0x26, data)
    }
}

impl IpmiCommand for SetSensorThresholds {
    type Output = ();
    type Error = ThresholdError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        Some(ThresholdError::Rejected(code))
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if !data.is_empty() {
            return Err(ThresholdError::InvalidLength {
                expected: 0,
                actual: data.len(),
            });
        }
        Ok(())
    }

    fn target(&self) -> Option<(Address, Channel)> {
        Some((self.address, self.channel))
    }

    fn target_lun(&self) -> LogicalUnit {
        self.lun
    }
}
