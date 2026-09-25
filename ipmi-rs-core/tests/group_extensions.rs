#![cfg(feature = "group-extensions")]

use ipmi_rs_core::{
    connection::{CompletionErrorCode, IpmiCommand, Message, NetFn},
    picmg as p, vita as v,
};

fn hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn exercise<C: IpmiCommand<Error = p::GroupError>>(
    command: C,
    cmd: u8,
    request: &[u8],
    response: &[u8],
    malformed: &[u8],
) {
    let message: Message = command.into();
    assert_eq!(message.netfn_raw(), NetFn::GroupExtension.request_value());
    assert_eq!(message.cmd(), cmd);
    assert_eq!(message.data(), request);
    C::parse_success_response(response)
        .map_err(|e| format!("{e:?}"))
        .unwrap();
    assert!(matches!(
        C::parse_success_response(malformed),
        Err(p::GroupError::InvalidLength { .. })
    ));

    let mut other_extension = response.to_vec();
    other_extension[0] ^= 3;
    assert_eq!(
        C::parse_success_response(&other_extension).err(),
        Some(p::GroupError::WrongExtension {
            expected: response[0],
            actual: other_extension[0]
        })
    );
    assert_eq!(
        C::handle_completion_code(CompletionErrorCode::InvalidCommand, &[]),
        Some(p::GroupError::UnsupportedOperation)
    );
    assert_eq!(
        C::handle_completion_code(CompletionErrorCode::SubFunctionDisabled, &[]),
        Some(p::GroupError::UnsupportedOperation)
    );
    assert_eq!(
        C::handle_completion_code(CompletionErrorCode::NodeBusy, &[]),
        None
    );
    let oversized = vec![response[0]; 256];
    assert!(matches!(
        C::parse_success_response(&oversized),
        Err(p::GroupError::InvalidLength { .. })
    ));
}

fn fixture_lines(text: &str, mut run: impl FnMut(&str, u8, Vec<u8>, Vec<u8>, Vec<u8>)) {
    for line in text
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
    {
        let fields: Vec<_> = line.split('|').collect();
        assert_eq!(fields.len(), 5, "{line}");
        run(
            fields[0],
            hex(fields[1])[0],
            hex(fields[2]),
            hex(fields[3]),
            hex(fields[4]),
        );
    }
}

#[test]
fn picmg_fixtures_cover_each_command_family() {
    assert_eq!(
        include_str!("fixtures/picmg.txt")
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .count(),
        21
    );
    fixture_lines(
        include_str!("fixtures/picmg.txt"),
        |name, cmd, req, ok, bad| {
            macro_rules! case {
                ($command:expr) => {
                    exercise($command, cmd, &req, &ok, &bad)
                };
            }
            let link = p::PortWrite::new(1, 0x31, 2, 2, true).unwrap();
            let selector = p::PortSelector::new(2, 17).unwrap();
            match name {
                "properties" => case!(p::GetPicmgProperties),
                "addrinfo" | "addrinfo_legacy" | "addrinfo_carrier" => {
                    case!(p::GetPicmgAddress { fru_id: 0 })
                }
                "frucontrol" => case!(p::PicmgFruControl {
                    fru_id: 2,
                    action: p::FruControl::WarmReset
                }),
                "activate" => case!(p::SetPicmgActivation {
                    fru_id: 2,
                    action: p::Activation::Activate
                }),
                "policy_get" => case!(p::GetPicmgPolicy { fru_id: 2 }),
                "policy_set" => case!(p::SetPicmgPolicy::new(2, 3, 1).unwrap()),
                "led_prop" => case!(p::GetPicmgLedProperties { fru_id: 2 }),
                "led_cap" => case!(p::GetPicmgLedCapabilities {
                    fru_id: 2,
                    led_id: 1
                }),
                "led_get" => case!(p::GetPicmgLedState {
                    fru_id: 2,
                    led_id: 1
                }),
                "led_set" => case!(p::SetPicmgLedState {
                    fru_id: 2,
                    led_id: 1,
                    setting: p::LedOverride::new(
                        p::LedFunction::Blink {
                            off_duration: 10,
                            on_duration: 7
                        },
                        3
                    )
                    .unwrap()
                }),
                "power_get" => case!(p::GetPicmgPower {
                    fru_id: 2,
                    power_type: p::PowerType::DesiredSteadyState
                }),
                "power_set" => {
                    case!(p::SetPicmgPower::new(2, p::PowerLevel::Level(5), true).unwrap())
                }
                "port_get" => case!(p::GetPicmgPortState { selector }),
                "port_set" => case!(p::SetPicmgPortState { selector, link }),
                "amc_get" => case!(p::GetAmcPortState {
                    channel: 4,
                    device: Some(2)
                }),
                "amc_set" => case!(p::SetAmcPortState {
                    channel: 4,
                    device: Some(2),
                    link
                }),
                "clock_get" => case!(p::GetAmcClockState {
                    clock_id: 3,
                    resource: Some(4)
                }),
                "clock_set" => {
                    case!(p::SetAmcClockState::new(
                        3,
                        2,
                        p::ClockSetting::new(true, true, 1).unwrap(),
                        1,
                        5,
                        0x11223344,
                        Some(4),
                    ))
                }
                "busres" => case!(p::GetPicmgBusResource {
                    resource: p::BusResource::SyncClockGroup1
                }),
                _ => panic!("unhandled fixture {name}"),
            }
        },
    );
}

#[test]
fn vita_fixtures_cover_each_command_family() {
    assert_eq!(
        include_str!("fixtures/vita.txt")
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .count(),
        10
    );
    fixture_lines(
        include_str!("fixtures/vita.txt"),
        |name, cmd, req, ok, bad| {
            macro_rules! case {
                ($command:expr) => {
                    exercise($command, cmd, &req, &ok, &bad)
                };
            }
            match name {
                "properties" => case!(v::GetVitaCapabilities),
                "addrinfo" => case!(v::GetVitaAddress { fru_id: 2 }),
                "frucontrol" => {
                    case!(v::VitaFruControl::new(2, v::FruControl::DiagnosticInterrupt).unwrap())
                }
                "activate" => case!(v::SetVitaActivation {
                    fru_id: 2,
                    action: v::Activation::Activate
                }),
                "policy_get" => case!(v::GetVitaPolicy { fru_id: 2 }),
                "policy_set" => case!(v::SetVitaPolicy::new(2, 15, 5).unwrap()),
                "led_prop" => case!(v::GetVitaLedProperties { fru_id: 2 }),
                "led_cap" => case!(v::GetVitaLedCapabilities {
                    fru_id: 2,
                    led_id: 1
                }),
                "led_get" => case!(v::GetVitaLedState {
                    fru_id: 2,
                    led_id: 1
                }),
                "led_set" => case!(v::SetVitaLedState {
                    fru_id: 2,
                    led_id: 1,
                    setting: v::LedOverride::new(
                        v::LedFunction::Blink {
                            off_duration: 10,
                            on_duration: 7
                        },
                        3
                    )
                    .unwrap()
                }),
                _ => panic!("unhandled fixture {name}"),
            }
        },
    );
}

#[test]
fn parsed_fields_preserve_unknown_values_and_optional_data() {
    let props = p::GetPicmgProperties::parse_success_response(&hex("00220f02")).unwrap();
    assert_eq!(
        (props.major, props.minor, props.max_fru_id, props.fru_id),
        (2, 2, 15, 2)
    );
    assert!(props.require_supported().is_ok());
    assert_eq!(
        p::GetPicmgProperties::parse_success_response(&hex("00260f02"))
            .unwrap()
            .require_supported(),
        Err(p::GroupError::UnsupportedOperation)
    );
    let caps = v::GetVitaCapabilities::parse_success_response(&hex("03211000210f02")).unwrap();
    assert_eq!(
        (caps.revision_major, caps.revision_minor, caps.max_fru_id),
        (1, 2, 15)
    );
    assert!(caps.require_supported().is_ok());
    assert_eq!(
        v::GetVitaCapabilities::parse_success_response(&hex("03211001210f02"))
            .unwrap()
            .require_supported(),
        Err(v::GroupError::UnsupportedOperation)
    );
    let address = v::GetVitaAddress::parse_success_response(&hex("032082000201c00f86")).unwrap();
    assert_eq!(
        (
            address.ipmb_0_address,
            address.site_type,
            address.channel_7_address
        ),
        (0x82, Some(0xc0), Some(0x86))
    );
    assert_eq!(address.optional_bytes, [0x0f, 0x86]);
    let power = p::GetPicmgPower::parse_success_response(&hex("0082070a141e")).unwrap();
    assert_eq!(
        (power.state, power.delay_to_stable, power.multiplier),
        (0x82, 7, 10)
    );
    assert_eq!(power.draws, [20, 30]);
    let port = p::GetPicmgPortState::parse_success_response(&hex("009111230201")).unwrap();
    assert_eq!(
        (
            port[0].designator,
            port[0].link_type,
            port[0].extension,
            port[0].state
        ),
        (0x91, 0x31, 2, 1)
    );
    let clock = p::GetAmcClockState::parse_success_response(&hex("000d02010544332211")).unwrap();
    assert_eq!((clock.setting, clock.frequency), (0x0d, Some(0x11223344)));
    let clock = p::GetAmcClockState::parse_success_response(&hex("0000")).unwrap();
    assert_eq!(
        (clock.index, clock.family, clock.frequency),
        (None, None, None)
    );
    let led = v::GetVitaLedState::parse_success_response(&hex("030700ff0101ff027f")).unwrap();
    assert_eq!(led.lamp_test_duration, Some(127));
    assert_eq!(led.override_setting.unwrap().color, 2);
    assert_eq!(
        v::GetVitaPolicy::parse_success_response(&hex("0383")),
        Ok(0x83)
    );
}

#[test]
fn picmg_address_forms_from_ipmitool_and_carrier_variants() {
    // The seven-byte response matches ipmitool's tests/transcripts/picmg.tr.
    let atca = p::GetPicmgAddress::parse_success_response(&hex("004182ff000100")).unwrap();
    assert_eq!(
        (atca.hardware_address, atca.ipmb_0_address, atca.reserved),
        (0x41, 0x82, 0xff)
    );
    assert_eq!(
        (atca.fru_id, atca.site_id, atca.site_type),
        (Some(0), Some(1), Some(0))
    );
    assert!(atca.optional_bytes.is_empty());

    let legacy = p::GetPicmgAddress::parse_success_response(&hex("004182ff")).unwrap();
    assert_eq!(
        (
            legacy.hardware_address,
            legacy.ipmb_0_address,
            legacy.reserved
        ),
        (0x41, 0x82, 0xff)
    );
    assert_eq!(
        (legacy.fru_id, legacy.site_id, legacy.site_type),
        (None, None, None)
    );
    assert!(legacy.optional_bytes.is_empty());

    let carrier = p::GetPicmgAddress::parse_success_response(&hex("004182ff000100a5")).unwrap();
    assert_eq!(
        (carrier.fru_id, carrier.site_id, carrier.site_type),
        (Some(0), Some(1), Some(0))
    );
    assert_eq!(carrier.optional_bytes, [0xa5]);
    for packet in [
        "",
        "00",
        "004182",
        "004182ff00",
        "004182ff0001",
        "004182ff000100a501",
    ] {
        assert!(
            matches!(
                p::GetPicmgAddress::parse_success_response(&hex(packet)),
                Err(p::GroupError::InvalidLength { .. })
            ),
            "invalid response {packet}"
        );
    }
    for packet in ["034182ff", "034182ff000100", "034182ff000100a5"] {
        assert_eq!(
            p::GetPicmgAddress::parse_success_response(&hex(packet)),
            Err(p::GroupError::WrongExtension {
                expected: 0,
                actual: 3
            })
        );
    }
    assert!(matches!(
        v::GetVitaAddress::parse_success_response(&hex("034182ff")),
        Err(v::GroupError::InvalidLength { .. })
    ));
}

#[test]
fn picmg_fru_control_validates_group_and_bounds_without_rejecting_trailing_data() {
    for (packet, trailing) in [("00", ""), ("000144", "0144"), ("00aabbcc", "aabbcc")] {
        assert_eq!(
            p::PicmgFruControl::parse_success_response(&hex(packet)),
            Ok(p::FruControlAcknowledgement {
                optional_bytes: hex(trailing)
            })
        );
    }
    assert_eq!(
        p::PicmgFruControl::parse_success_response(&vec![0; 255]),
        Ok(p::FruControlAcknowledgement {
            optional_bytes: vec![0; 254]
        })
    );
    assert!(matches!(
        p::PicmgFruControl::parse_success_response(&[]),
        Err(p::GroupError::InvalidLength { .. })
    ));
    assert!(matches!(
        p::PicmgFruControl::parse_success_response(&vec![0; 256]),
        Err(p::GroupError::InvalidLength { .. })
    ));
    assert_eq!(
        p::PicmgFruControl::parse_success_response(&hex("030144")),
        Err(p::GroupError::WrongExtension {
            expected: 0,
            actual: 3
        })
    );
    // Other PICMG setters retain strict acknowledgement parsing.
    assert!(matches!(
        p::SetPicmgActivation::parse_success_response(&hex("0001")),
        Err(p::GroupError::InvalidLength { .. })
    ));
}

#[test]
fn invalid_writes_fail_before_a_message_can_be_built() {
    assert!(p::SetPicmgPolicy::new(2, 4, 0).is_err());
    assert!(p::SetPicmgPolicy::new(2, 1, 2).is_err());
    assert!(v::SetVitaPolicy::new(2, 0x10, 0).is_err());
    assert!(v::VitaFruControl::new(2, v::FruControl::Quiesce).is_err());
    assert!(p::SetPicmgPower::new(2, p::PowerLevel::Level(21), false).is_err());
    assert!(p::PortSelector::new(4, 0).is_err());
    assert!(p::PortSelector::new(0, 64).is_err());
    assert!(p::PortWrite::new(16, 1, 1, 0, true).is_err());
    assert!(p::PortWrite::new(1, 1, 16, 0, true).is_err());
    assert!(p::ClockSetting::new(true, false, 3).is_err());
    assert!(p::LedOverride::new(
        p::LedFunction::Blink {
            off_duration: 0,
            on_duration: 1
        },
        1
    )
    .is_err());
    assert!(p::LedOverride::new(p::LedFunction::LampTest(128), 1).is_err());
    assert!(p::LedOverride::new(p::LedFunction::On, 0).is_err());
}
