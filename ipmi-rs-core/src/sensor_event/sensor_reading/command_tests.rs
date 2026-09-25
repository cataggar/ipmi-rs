use super::*;
use crate::{
    connection::{Address, Channel, CompletionErrorCode, IpmiCommand, LogicalUnit, Message, NetFn},
    storage::sdr::{
        event_reading_type_code::EventReadingTypeCodes,
        record::{
            CompactSensorRecord, DataFormat, Direction, FullSensorRecord, InstancedSensor,
            Linearization, ParseError, Record, ThresholdKind, ThresholdValueError, Value,
            WithSensorRecordCommon,
        },
    },
};

fn full_record() -> FullSensorRecord {
    full_record_with(0x01, 0x3F, 0x3F)
}

fn full_record_with(event_type: u8, readable: u8, settable: u8) -> FullSensorRecord {
    let mut data = [0u8; 43];
    data[0] = 0x20;
    data[1] = 0x02; // Sensor owner LUN 2.
    data[2] = 0x42;
    data[6] = 0x08; // Readable and settable threshold capability.
    data[7] = 0x01; // Temperature.
    data[8] = event_type;
    data[9] = 0x70; // Three lower threshold-status bits.
    data[11] = 0x70; // Three upper threshold-status bits.
    data[13] = readable;
    data[14] = settable;
    data[16] = 0x01; // Degrees Celsius.
    data[19] = 2; // M=2.
    data[21] = 1; // B=1.
    data[42] = 0; // Empty ID.
    let mut sdr = vec![0, 0, 0x51, 0x01, data.len() as u8];
    sdr.extend_from_slice(&data);
    Record::parse(&sdr).unwrap().full_sensor().unwrap().clone()
}

fn compact_record() -> CompactSensorRecord {
    let mut data = [0u8; 27];
    data[0] = 0x20;
    data[2] = 0x43;
    data[7] = 0x08; // Power Supply.
    data[8] = 0x6F; // Sensor-specific discrete offsets.
    data[13] = 0x01; // Offset 0 is supported.
    data[14] = 0x40; // Offset 14 is supported.
    data[15] = 0xC0; // No analog reading.
    data[18] = 0x40; // Input direction.
    let mut sdr = vec![0, 0, 0x51, 0x02, data.len() as u8];
    sdr.extend_from_slice(&data);
    Record::parse(&sdr)
        .unwrap()
        .compact_sensor()
        .unwrap()
        .clone()
}

#[test]
fn discrete_states_from_compact_and_full_sdr() {
    let compact = compact_record();
    assert_eq!(compact.direction, Direction::Input);
    let raw = RawSensorReading::parse(&[0x55, 0xC0, 0x03, 0xC0]).unwrap();
    let states = raw.discrete_for(&compact).unwrap();
    assert_eq!(raw.flags().availability, ReadingAvailability::Available);
    assert!(states.flags.scanning_enabled);
    assert!(states.flags.event_messages_enabled);
    assert_eq!(raw.raw_reading(), 0x55);
    assert_eq!(states.reading, Some(0x55));
    assert_eq!(states.state_bytes, (Some(0x03), Some(0xC0)));
    assert_eq!(
        states.states,
        vec![
            DiscreteState {
                offset: 0,
                description: Some("Presence detected"),
                advertised: true,
            },
            DiscreteState {
                offset: 1,
                description: Some("Power Supply Failure detected"),
                advertised: false,
            },
            DiscreteState {
                offset: 14,
                description: None,
                advertised: true,
            },
        ]
    );
    assert_eq!(
        raw.discrete_for(&full_record()),
        Err(DiscreteReadingError::NotDiscrete)
    );

    let full = full_record_with(0x08, 0x3F, 0x3F);
    // A full SDR can also describe a generic discrete sensor.
    assert_eq!(
        full.common().event_reading_type_code,
        EventReadingTypeCodes::DiscreteGeneric(0x08)
    );
    let state = raw.discrete_for(&full).unwrap();
    assert_eq!(
        state.states[0].description,
        Some("Device Removed / Device Absent")
    );
    let oem = full_record_with(0x70, 0x01, 0);
    assert_eq!(
        RawSensorReading::parse(&[0, 0xC0, 1])
            .unwrap()
            .discrete_for(&oem)
            .unwrap()
            .states,
        vec![DiscreteState {
            offset: 0,
            description: None,
            advertised: true,
        }]
    );
}

#[test]
fn unavailable_and_truncated_discrete_states() {
    let compact = compact_record();
    let absent = RawSensorReading::parse(&[0x55, 0x20]).unwrap();
    let decoded = absent.discrete_for(&compact).unwrap();
    assert_eq!(decoded.flags.availability, ReadingAvailability::Unavailable);
    assert!(!decoded.flags.scanning_enabled);
    assert!(!decoded.flags.event_messages_enabled);
    assert_eq!(decoded.reading, None);
    assert!(decoded.states.is_empty());
    assert_eq!(decoded.state_bytes, (None, None));
    assert_eq!(
        RawSensorReading::parse(&[0, 0xC0])
            .unwrap()
            .discrete_for(&compact),
        Err(DiscreteReadingError::MissingStateByte(1))
    );
    assert_eq!(
        RawSensorReading::parse(&[0, 0xC0, 1])
            .unwrap()
            .discrete_for(&compact),
        Err(DiscreteReadingError::MissingStateByte(2))
    );
    assert_eq!(
        GetSensorReading::parse_success_response(&[]),
        Err(crate::connection::NotEnoughData)
    );
    assert_eq!(
        GetSensorReading::parse_success_response(&[1]),
        Err(crate::connection::NotEnoughData)
    );
    assert_eq!(
        RawSensorReading::parse(&[0x22, 0x80, 0, 0])
            .unwrap()
            .reading(),
        Some(0x22)
    );
}

#[test]
fn threshold_get_wire_mask_and_readable_capability() {
    let full = full_record();
    let command = GetSensorThresholds::for_sensor_key(full.key_data());
    let target = command.target();
    assert_eq!(target, Some((Address(0x20), Channel::Primary)));
    assert_eq!(command.target_lun(), LogicalUnit::Two);
    assert_eq!(
        GetSensorReading::for_sensor_key(full.key_data()).target_lun(),
        LogicalUnit::Two
    );
    let wire: Message = command.into();
    assert_eq!(wire.netfn_raw(), NetFn::SensorEvent.request_value());
    assert_eq!(wire.cmd(), 0x27);
    assert_eq!(wire.data(), [0x42]);

    let response =
        GetSensorThresholds::parse_success_response(&[0x29, 10, 11, 12, 13, 14, 15]).unwrap();
    assert_eq!(response.mask(), 0x29);
    assert_eq!(response.raw(ThresholdKind::LowerNonCritical), Some(10));
    assert_eq!(response.raw(ThresholdKind::LowerCritical), None);
    assert_eq!(response.raw(ThresholdKind::UpperNonCritical), Some(13));
    assert_eq!(response.raw(ThresholdKind::UpperNonRecoverable), Some(15));
    assert_eq!(
        response
            .value(ThresholdKind::LowerNonCritical, &full)
            .unwrap()
            .value(),
        21.0
    );
    assert!(response
        .value(ThresholdKind::LowerCritical, &full)
        .is_none());
    assert_eq!(response.validate_for(&full), Ok(()));
    assert_eq!(
        response.validate_for(&compact_record()),
        Err(ThresholdError::UnsupportedSensor)
    );

    let none = GetSensorThresholds::parse_success_response(&[0, 1, 2, 3, 4, 5, 6]).unwrap();
    for kind in ThresholdKind::variants() {
        assert_eq!(none.raw(kind), None);
    }
    for len in 0..=8 {
        if len != 7 {
            assert_eq!(
                GetSensorThresholds::parse_success_response(&[0; 8][..len]),
                Err(ThresholdError::InvalidLength {
                    expected: 7,
                    actual: len
                })
            );
        }
    }
    assert_eq!(
        GetSensorThresholds::parse_success_response(&[0x40, 0, 0, 0, 0, 0, 0]),
        Err(ThresholdError::InvalidMask(0x40))
    );
    assert_eq!(
        GetSensorThresholds::handle_completion_code(
            CompletionErrorCode::CommandIllegalForSensorOrRecord,
            &[]
        ),
        Some(ThresholdError::Rejected(
            CompletionErrorCode::CommandIllegalForSensorOrRecord
        ))
    );
}

#[test]
fn threshold_set_wire_validation_and_rejections() {
    let full = full_record();
    let units = full.common().sensor_units;
    let settings = [
        (
            ThresholdKind::LowerNonRecoverable,
            ThresholdSetting::Raw(10),
        ),
        (
            ThresholdKind::UpperCritical,
            ThresholdSetting::Converted(Value::new(units, 61.0)),
        ),
    ];
    let command = SetSensorThresholds::new(&full, &settings).unwrap();
    assert_eq!(command.mask(), 0x14);
    assert_eq!(command.target(), Some((Address(0x20), Channel::Primary)));
    assert_eq!(command.target_lun(), LogicalUnit::Two);
    let wire: Message = command.into();
    assert_eq!(wire.netfn_raw(), NetFn::SensorEvent.request_value());
    assert_eq!(wire.cmd(), 0x26);
    assert_eq!(wire.data(), [0x42, 0x14, 0, 0, 10, 0, 30, 0]);
    let ordered = SetSensorThresholds::new(
        &full,
        &[
            (
                ThresholdKind::LowerNonRecoverable,
                ThresholdSetting::Raw(10),
            ),
            (ThresholdKind::LowerCritical, ThresholdSetting::Raw(20)),
            (ThresholdKind::LowerNonCritical, ThresholdSetting::Raw(30)),
        ],
    )
    .unwrap();
    let ordered_wire: Message = ordered.into();
    assert_eq!(ordered_wire.data(), [0x42, 0x07, 30, 20, 10, 0, 0, 0]);
    assert_eq!(SetSensorThresholds::parse_success_response(&[]), Ok(()));
    assert_eq!(
        SetSensorThresholds::parse_success_response(&[1]),
        Err(ThresholdError::InvalidLength {
            expected: 0,
            actual: 1
        })
    );
    assert_eq!(
        SetSensorThresholds::handle_completion_code(
            CompletionErrorCode::CommandSpecific(0x80),
            &[]
        ),
        Some(ThresholdError::Rejected(
            CompletionErrorCode::CommandSpecific(0x80)
        ))
    );
    assert!(matches!(
        SetSensorThresholds::new(&full_record_with(0x6F, 0x3F, 0x3F), &settings),
        Err(ThresholdError::UnsupportedSensor)
    ));
    assert!(matches!(
        SetSensorThresholds::new(&full, &[]),
        Err(ThresholdError::NoThresholds)
    ));
    assert!(matches!(
        SetSensorThresholds::new(&full, &[settings[0], settings[0]]),
        Err(ThresholdError::DuplicateThreshold(
            ThresholdKind::LowerNonRecoverable
        ))
    ));
    let zero = SetSensorThresholds::new(
        &full,
        &[(ThresholdKind::LowerNonCritical, ThresholdSetting::Raw(0))],
    )
    .unwrap();
    let zero_wire: Message = zero.into();
    assert_eq!(zero_wire.data(), [0x42, 0x01, 0, 0, 0, 0, 0, 0]);
    assert!(matches!(
        SetSensorThresholds::new(
            &full,
            &[
                (ThresholdKind::LowerNonCritical, ThresholdSetting::Raw(60)),
                (ThresholdKind::UpperNonCritical, ThresholdSetting::Raw(20)),
            ]
        ),
        Err(ThresholdError::InvalidOrder {
            lower: ThresholdKind::LowerNonCritical,
            upper: ThresholdKind::UpperNonCritical,
        })
    ));
    assert!(matches!(
        SetSensorThresholds::new(
            &full,
            &[
                (
                    ThresholdKind::LowerNonRecoverable,
                    ThresholdSetting::Raw(20)
                ),
                (ThresholdKind::LowerCritical, ThresholdSetting::Raw(10)),
            ]
        ),
        Err(ThresholdError::InvalidOrder {
            lower: ThresholdKind::LowerNonRecoverable,
            upper: ThresholdKind::LowerCritical,
        })
    ));
}

#[test]
fn conversion_rejects_unsupported_units_range_and_format() {
    let full = full_record();
    let units = full.common().sensor_units;
    assert_eq!(full.threshold_raw(Value::new(units, 11.0)), Ok(5));
    assert_eq!(
        full.threshold_raw(Value::new(units, f32::NAN)),
        Err(ThresholdValueError::NonFinite)
    );
    assert!(matches!(
        SetSensorThresholds::new(
            &full,
            &[(
                ThresholdKind::LowerCritical,
                ThresholdSetting::Converted(Value::new(
                    compact_record().common().sensor_units,
                    11.0,
                )),
            )]
        ),
        Err(ThresholdError::Conversion {
            kind: ThresholdKind::LowerCritical,
            error: ThresholdValueError::WrongUnits
        })
    ));
    assert_eq!(
        full.threshold_raw(Value::new(units, 900.0)),
        Err(ThresholdValueError::OutOfRange)
    );
    assert_eq!(
        full.threshold_raw(Value::new(compact_record().common().sensor_units, 11.0)),
        Err(ThresholdValueError::WrongUnits)
    );
    let mut non_linear = full.clone();
    non_linear.linearization = Linearization::Log10;
    assert_eq!(non_linear.threshold_value(10), None);
    assert_eq!(
        non_linear.threshold_raw(Value::new(units, 10.0)),
        Err(ThresholdValueError::NonLinear)
    );
    let mut no_analog = full.clone();
    no_analog.analog_data_format = None;
    assert_eq!(
        no_analog.threshold_raw(Value::new(units, 10.0)),
        Err(ThresholdValueError::UnsupportedFormat)
    );
    let mut zero_slope = full.clone();
    zero_slope.m = 0;
    assert_eq!(
        zero_slope.threshold_raw(Value::new(units, 10.0)),
        Err(ThresholdValueError::ZeroSlope)
    );
    let mut signed = full.clone();
    signed.m = 1;
    signed.b = 0;
    signed.analog_data_format = Some(DataFormat::OnesComplement);
    assert_eq!(signed.threshold_raw(Value::new(units, -3.0)), Ok(0xFC));
    assert_eq!(signed.threshold_value(0xFC).unwrap().value(), -3.0);
    signed.analog_data_format = Some(DataFormat::TwosComplement);
    assert_eq!(signed.threshold_raw(Value::new(units, -3.0)), Ok(0xFD));
    assert_eq!(signed.threshold_value(0xFD).unwrap().value(), -3.0);
    let mut negative = [0; 43];
    negative[2] = 1;
    negative[6] = 0x08;
    negative[8] = 1;
    negative[14] = 0x03;
    negative[19] = 0xFE;
    negative[20] = 0xFF; // Signed 10-bit M=-2.
    negative[21] = 0xFF;
    negative[22] = 0xFF; // Signed 10-bit B=-1.
    let negative = FullSensorRecord::parse(&negative).unwrap();
    assert_eq!(negative.m, -2);
    assert_eq!(negative.b, -1);
    assert_eq!(negative.threshold_value(1).unwrap().value(), -3.0);
    assert_eq!(
        negative.threshold_raw(Value::new(negative.common().sensor_units, -3.0)),
        Ok(1)
    );
    let descending_raw = SetSensorThresholds::new(
        &negative,
        &[
            (ThresholdKind::LowerCritical, ThresholdSetting::Raw(3)),
            (ThresholdKind::LowerNonCritical, ThresholdSetting::Raw(1)),
        ],
    );
    assert!(descending_raw.is_ok()); // M<0: raw 3 (-7) is below raw 1 (-3).
}

#[test]
fn sdr_masks_and_truncated_records_are_checked() {
    let full = full_record();
    assert!(full
        .capabilities()
        .threshold_access
        .readable(ThresholdKind::UpperCritical));
    assert!(full
        .capabilities()
        .threshold_access
        .settable(ThresholdKind::LowerCritical));
    let caps = crate::storage::sdr::record::SensorCapabilities::new(0x28, 0, 0, 0x0101);
    assert!(matches!(
        caps.hysteresis,
        crate::storage::sdr::record::HysteresisCapability::ReadableAndSettable
    ));
    let caps = crate::storage::sdr::record::SensorCapabilities::new(0x04, 0x1000, 0x2000, 0x0001);
    if let crate::storage::sdr::record::ThresholdAccessCapability::Readable { values, .. } =
        caps.threshold_access
    {
        assert!(values.lower_non_critical);
        assert!(values.upper_critical);
        assert!(!values.upper_non_critical);
        assert!(!values.upper_non_recoverable);
    } else {
        panic!("expected readable thresholds");
    }
    let limited = full_record_with(0x01, 0x01, 0x01);
    assert_eq!(
        SetSensorThresholds::new(
            &limited,
            &[(ThresholdKind::UpperCritical, ThresholdSetting::Raw(5))]
        )
        .err(),
        Some(ThresholdError::UnsupportedThreshold(
            ThresholdKind::UpperCritical
        ))
    );
    assert_eq!(
        GetSensorThresholds::parse_success_response(&[0x10, 0, 0, 0, 0, 0, 0])
            .unwrap()
            .validate_for(&limited),
        Err(ThresholdError::UnsupportedThreshold(
            ThresholdKind::UpperCritical
        ))
    );
    for len in 0..43 {
        assert!(matches!(
            FullSensorRecord::parse(&[0; 43][..len]),
            Err(ParseError::NotEnoughData)
        ));
    }
    for len in 0..27 {
        assert!(matches!(
            CompactSensorRecord::parse(&[0; 27][..len]),
            Err(ParseError::NotEnoughData)
        ));
    }
    let mut compact = [0; 27];
    compact[2] = 1;
    compact[18] = 0x20;
    assert!(matches!(
        CompactSensorRecord::parse(&compact),
        Err(ParseError::InvalidIdStringModifier(2))
    ));
    compact[18] = 0xC0;
    assert!(matches!(
        CompactSensorRecord::parse(&compact),
        Err(ParseError::InvalidSensorDirection)
    ));
    let mut short_id = [0; 43];
    short_id[2] = 1;
    short_id[42] = 0xC1;
    assert!(matches!(
        FullSensorRecord::parse(&short_id),
        Err(ParseError::NotEnoughData)
    ));
}
