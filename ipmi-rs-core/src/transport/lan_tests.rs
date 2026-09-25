use super::*;
use crate::connection::{Channel, CompletionErrorCode, IpmiCommand, Message};

fn hex(input: &str) -> Vec<u8> {
    input
        .split_whitespace()
        .map(|part| u8::from_str_radix(part, 16).unwrap())
        .collect()
}

fn selector(input: &str) -> u8 {
    u8::from_str_radix(input, 16).unwrap()
}

#[test]
fn wire_fixtures_cover_selectors_blocks_revisions_and_completion_codes() {
    for line in include_str!("fixtures/lan_wire.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let (bad, fields) = if let Some(rest) = line.strip_prefix("bad:") {
            (true, rest)
        } else if let Some(rest) = line.strip_prefix("cc:") {
            let fields: Vec<_> = rest.split(':').collect();
            let code = selector(fields[3]);
            assert_eq!(fields.len(), 5);
            let parsed = CompletionErrorCode::try_from(code).unwrap();
            assert!(format!("{parsed:?}").starts_with(fields[4]), "{line}");
            continue;
        } else {
            (false, line)
        };
        let fields: Vec<_> = fields.split(':').collect();
        assert_eq!(fields.len(), 5, "{line}");
        let parameter = LanConfigParameter::Other(selector(fields[0]));
        let request: Message = GetLanConfigParameters::new(Channel::Current, parameter)
            .with_set_selector(selector(fields[1]))
            .with_block_selector(selector(fields[2]))
            .into();
        assert_eq!(request.cmd(), 2);
        assert_eq!(
            request.data(),
            [
                0x0e,
                selector(fields[0]),
                selector(fields[1]),
                selector(fields[2])
            ]
        );
        let parameter = match selector(fields[0]) {
            0 => LanConfigParameter::SetInProgress,
            3 => LanConfigParameter::IpAddress,
            7 => LanConfigParameter::IpHeader,
            8 => LanConfigParameter::PrimaryRmcpPort,
            10 => LanConfigParameter::BmcArpControl,
            16 => LanConfigParameter::SnmpCommunity,
            17 => LanConfigParameter::NumberOfAlertDestinations,
            18 => LanConfigParameter::AlertDestinationType,
            19 => LanConfigParameter::AlertDestinationAddress,
            20 => LanConfigParameter::VlanId,
            23 => LanConfigParameter::CipherSuites,
            26 => LanConfigParameter::BadPasswordThreshold,
            50 => LanConfigParameter::Ipv6Ipv4Support,
            54 => LanConfigParameter::Ipv6HeaderFlowLabel,
            56 => LanConfigParameter::Ipv6StaticAddresses,
            58 => LanConfigParameter::Ipv6StaticDuid,
            59 => LanConfigParameter::Ipv6DynamicAddress,
            62 => LanConfigParameter::Ipv6DhcpTimingSupport,
            63 => LanConfigParameter::Ipv6DhcpTiming,
            64 => LanConfigParameter::Ipv6RouterControl,
            65 => LanConfigParameter::Ipv6StaticRouter1Address,
            67 => LanConfigParameter::Ipv6StaticRouter1PrefixLength,
            74 => LanConfigParameter::Ipv6DynamicRouterAddress,
            76 => LanConfigParameter::Ipv6DynamicRouterPrefixLength,
            79 => LanConfigParameter::Ipv6NeighborDiscoverySlaacTimingSupport,
            80 => LanConfigParameter::Ipv6NeighborDiscoverySlaacTiming,
            _ => parameter,
        };
        let response = GetLanConfigParameters::parse_success_response(&hex(fields[3])).unwrap();
        let result = response.parse_selected(parameter, selector(fields[1]), selector(fields[2]));
        if bad {
            assert!(
                format!("{:?}", result.unwrap_err()).starts_with(fields[4]),
                "{line}"
            );
        } else {
            assert!(
                format!("{:?}", result.unwrap()).starts_with(fields[4]),
                "{line}"
            );
        }
    }
    assert_eq!(
        GetLanConfigParameters::parse_success_response(&[]),
        Err(LanConfigError::MissingRevision)
    );
    let selected = GetLanConfigParameters::parse_success_response(&[0x11, 3, 0, 1]).unwrap();
    assert_eq!(
        selected.parse_selected(LanConfigParameter::Ipv6StaticDuid, 3, 1),
        Err(LanConfigError::SelectorMismatch)
    );
    let cipher = GetLanConfigParameters::parse_success_response(&[0x11, 0, 1, 2, 3]).unwrap();
    assert_eq!(
        cipher.parse(LanConfigParameter::CipherSuites).unwrap(),
        LanConfigParameterData::CipherSuites(vec![0, 1, 2, 3])
    );
    let revision_only: Message =
        GetLanConfigParameters::new(Channel::Current, LanConfigParameter::Other(254))
            .revision_only(true)
            .into();
    assert_eq!(revision_only.data(), [0x8e, 254, 0, 0]);
}

#[test]
fn checked_writes_validate_payloads_and_keep_raw_escape() {
    let channel = Channel::Current;
    let cases = [
        (
            LanConfigParameterRequest::IpAddress(Ipv4Address([192, 0, 2, 1])),
            3,
            vec![192, 0, 2, 1],
        ),
        (
            LanConfigParameterRequest::PrimaryRmcpPort(623),
            8,
            vec![2, 111],
        ),
        (
            LanConfigParameterRequest::VlanId(LanVlanId {
                enabled: true,
                id: 4094,
            }),
            20,
            vec![0xfe, 0x8f],
        ),
        (
            LanConfigParameterRequest::Ipv6HeaderFlowLabel(Ipv6HeaderFlowLabel(0xabcde)),
            54,
            vec![0x0a, 0xbc, 0xde],
        ),
        (
            LanConfigParameterRequest::AlertDestinationType(LanAlertDestinationType {
                set_selector: 2,
                acknowledged: true,
                destination_type: 6,
                timeout: 10,
                retries: 7,
            }),
            18,
            vec![2, 0x86, 10, 7],
        ),
        (
            LanConfigParameterRequest::Ipv6StaticDuid(
                Ipv6LanBlock::new(3, 1, vec![1, 2, 3]).unwrap(),
            ),
            58,
            vec![3, 1, 1, 2, 3],
        ),
    ];
    for (request, selector, bytes) in cases {
        let message: Message = SetLanConfigParameters::checked(channel, request)
            .unwrap()
            .into();
        assert_eq!(message.cmd(), 1);
        assert_eq!(message.data()[..2], [0x0e, selector]);
        assert_eq!(message.data()[2..], bytes);
    }
    assert!(matches!(
        SetLanConfigParameters::checked(channel, LanConfigParameterRequest::VlanPriority(8)),
        Err(LanConfigError::InvalidValue(8))
    ));
    assert!(matches!(
        SetLanConfigParameters::checked(
            channel,
            LanConfigParameterRequest::Ipv6HeaderFlowLabel(Ipv6HeaderFlowLabel(0x100000))
        ),
        Err(LanConfigError::InvalidValue(_))
    ));
    assert!(matches!(
        SetLanConfigParameters::checked(
            channel,
            LanConfigParameterRequest::Ipv6StaticAddress {
                set_selector: 1,
                enabled: true,
                source_type: 0,
                address: Ipv6Address([0; 16]),
                prefix_length: 129,
                status: 0,
            }
        ),
        Err(LanConfigError::InvalidPrefix(129))
    ));
    let raw: Message =
        SetLanConfigParameters::new(channel, LanConfigParameter::Other(230), vec![0xee, 0x11])
            .into();
    assert_eq!(raw.data(), [0x0e, 230, 0xee, 0x11]);
    assert_eq!(
        SetLanConfigParameters::parse_success_response(&[1]),
        Err(LanConfigError::InvalidLength {
            expected: 0,
            actual: 1
        })
    );
}

#[test]
fn duid_and_dhcp_timing_round_trip_multiple_blocks() {
    let duid = Ipv6Duid {
        set_selector: 3,
        bytes: (0..35).collect(),
    };
    let blocks = duid.blocks().unwrap();
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0].bytes[0], 35);
    assert_eq!(blocks[1].block_selector, 1);
    assert_eq!(Ipv6Duid::from_blocks(&blocks).unwrap(), duid);
    let mut missing = blocks.clone();
    missing.remove(1);
    assert_eq!(
        Ipv6Duid::from_blocks(&missing),
        Err(LanConfigError::InvalidBlockSequence)
    );
    assert!(Ipv6Duid {
        set_selector: 1,
        bytes: vec![0; 256]
    }
    .blocks()
    .is_err());

    let timing = Ipv6DhcpTiming {
        set_selector: 2,
        values: [9; 22],
    };
    let [first, second] = timing.blocks();
    assert_eq!(first.wire().len(), 18);
    assert_eq!(second.wire().len(), 18);
    assert_eq!(&second.bytes[..6], &[9; 6]);
    assert_eq!(&second.bytes[6..], &[0; 10]);
    let command: Message = SetLanConfigParameters::checked(
        Channel::Current,
        LanConfigParameterRequest::Ipv6DhcpTiming(second.clone()),
    )
    .unwrap()
    .into();
    assert_eq!(&command.data()[..4], &[14, 63, 2, 1]);
    assert_eq!(command.data().len(), 20);
    assert_eq!(
        Ipv6DhcpTiming::from_blocks(&first, &second).unwrap(),
        timing
    );
    let short = Ipv6LanBlock::new(2, 1, second.bytes[..6].to_vec()).unwrap();
    assert_eq!(Ipv6DhcpTiming::from_blocks(&first, &short).unwrap(), timing);
    assert!(SetLanConfigParameters::checked(
        Channel::Current,
        LanConfigParameterRequest::Ipv6DhcpTiming(short),
    )
    .is_err());
    let padded = Ipv6LanBlock::new(2, 1, {
        let mut value = second.bytes.clone();
        value[15] = 0xff;
        value
    })
    .unwrap();
    assert_eq!(
        Ipv6DhcpTiming::from_blocks(&first, &padded).unwrap(),
        timing
    );
    assert_eq!(
        Ipv6DhcpTiming::from_blocks(&second, &first),
        Err(LanConfigError::InvalidBlockSequence)
    );
    let router = Ipv6Router {
        address: Ipv6Address([1; 16]),
        mac: MacAddress([2; 6]),
        prefix_length: 64,
        prefix: Ipv6Address([3; 16]),
    };
    let writes = ipv6_static_router_writes(2, router).unwrap();
    assert_eq!(
        writes.iter().map(|v| v.0.value()).collect::<Vec<_>>(),
        [69, 70, 71, 72]
    );
    assert!(ipv6_static_router_writes(3, router).is_err());
}

#[test]
fn full_width_dhcp_timing_response_fixture_decodes_only_six_block_one_values() {
    let fixture = include_str!("fixtures/lan_wire.txt");
    let decode = |prefix: &str| {
        let line = fixture
            .lines()
            .find(|line| line.starts_with(prefix))
            .unwrap();
        let response = line.split(':').nth(3).unwrap();
        let raw = GetLanConfigParameters::parse_success_response(&hex(response)).unwrap();
        match raw
            .parse_selected(
                LanConfigParameter::Ipv6DhcpTiming,
                2,
                if prefix.ends_with(":00:") { 0 } else { 1 },
            )
            .unwrap()
        {
            LanConfigParameterData::Ipv6DhcpTiming(block) => block,
            other => panic!("unexpected timing parameter: {other:?}"),
        }
    };
    let block_zero = decode("3F:02:00:");
    let block_one = decode("3F:02:01:11 02 01 11 12 13 14 15 16 00");
    assert_eq!(block_zero.bytes.len(), 16);
    assert_eq!(block_one.bytes.len(), 16);
    let decoded = Ipv6DhcpTiming::from_blocks(&block_zero, &block_one).unwrap();
    assert_eq!(decoded.values[..16], (1..=16).collect::<Vec<_>>());
    assert_eq!(decoded.values[16..], [0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
}

#[test]
fn rejected_begin_completion_code_does_not_emit_set_complete() {
    let mut calls = Vec::new();
    let writes = [(
        LanConfigParameter::IpAddress,
        LanConfigParameterRequest::IpAddress(Ipv4Address([192, 0, 2, 1])),
    )];
    let result = lan_write_guarded(
        |command| {
            calls.push(Message::from(command).data().to_vec());
            Err::<(), _>(CompletionErrorCode::CommandSpecific(0x81))
        },
        Channel::Current,
        &writes,
        |code| match code {
            CompletionErrorCode::CommandSpecific(0x81) => LanBeginFailure::Rejected,
            _ => LanBeginFailure::Uncertain,
        },
    );
    assert!(matches!(
        result,
        Err(LanWriteError::BeginRejected {
            error: CompletionErrorCode::CommandSpecific(0x81),
        })
    ));
    assert_eq!(calls, [vec![14, 0, 1]]);
}

#[test]
fn guarded_writes_attempt_cleanup_and_never_retry_failed_mutations() {
    let channel = Channel::Current;
    let writes = vec![
        (
            LanConfigParameter::IpAddress,
            LanConfigParameterRequest::IpAddress(Ipv4Address([1, 2, 3, 4])),
        ),
        (
            LanConfigParameter::VlanPriority,
            LanConfigParameterRequest::VlanPriority(3),
        ),
    ];
    let mut calls = Vec::new();
    lan_write_guarded(
        |cmd| {
            calls.push(Message::from(cmd).data().to_vec());
            Ok::<_, &str>(())
        },
        channel,
        &writes,
        |_| LanBeginFailure::Uncertain,
    )
    .unwrap();
    assert_eq!(
        calls,
        [
            vec![14, 0, 1],
            vec![14, 3, 1, 2, 3, 4],
            vec![14, 21, 3],
            vec![14, 0, 2],
            vec![14, 0, 0]
        ]
    );
    let mut calls = Vec::new();
    let result = lan_write_guarded(
        |cmd| {
            let message: Message = cmd.into();
            calls.push(message.data().to_vec());
            if message.data()[1] == 3 || message.data() == [14, 0, 0] {
                Err("failed")
            } else {
                Ok(())
            }
        },
        channel,
        &writes,
        |_| LanBeginFailure::Uncertain,
    );
    assert!(matches!(
        result,
        Err(LanWriteError::Uncertain {
            write: Some((0, "failed")),
            commit: None,
            cleanup: Some("failed"),
        })
    ));
    assert_eq!(
        calls,
        [vec![14, 0, 1], vec![14, 3, 1, 2, 3, 4], vec![14, 0, 0]]
    );
    let mut calls = Vec::new();
    let result = lan_write_guarded(
        |cmd| {
            let bytes = Message::from(cmd).data().to_vec();
            calls.push(bytes.clone());
            if bytes[1] == 0 {
                Err("state")
            } else {
                Ok(())
            }
        },
        channel,
        &writes,
        |_| LanBeginFailure::Uncertain,
    );
    assert!(matches!(
        result,
        Err(LanWriteError::BeginUncertain {
            error: "state",
            cleanup: Some("state")
        })
    ));
    assert_eq!(calls, [vec![14, 0, 1], vec![14, 0, 0]]);
    calls.clear();
    let result = lan_write_guarded(
        |cmd| {
            let bytes = Message::from(cmd).data().to_vec();
            calls.push(bytes.clone());
            if bytes == [14, 0, 1] {
                Err("already in progress")
            } else {
                Ok(())
            }
        },
        channel,
        &writes,
        |_| LanBeginFailure::Rejected,
    );
    assert!(matches!(
        result,
        Err(LanWriteError::BeginRejected {
            error: "already in progress"
        })
    ));
    assert_eq!(calls, [vec![14, 0, 1]]);
    calls.clear();
    let result = lan_write_guarded(
        |cmd| {
            let bytes = Message::from(cmd).data().to_vec();
            calls.push(bytes.clone());
            if bytes == [14, 0, 1] {
                Err("lost ACK")
            } else {
                Ok(())
            }
        },
        channel,
        &writes,
        |_| LanBeginFailure::Uncertain,
    );
    assert!(matches!(
        result,
        Err(LanWriteError::BeginUncertain {
            error: "lost ACK",
            cleanup: None
        })
    ));
    assert_eq!(calls, [vec![14, 0, 1], vec![14, 0, 0]]);
    let mut calls = Vec::new();
    let result = lan_write_guarded(
        |cmd| {
            let bytes = Message::from(cmd).data().to_vec();
            calls.push(bytes.clone());
            if bytes == [14, 0, 2] || bytes == [14, 0, 0] {
                Err("commit or cleanup failed")
            } else {
                Ok(())
            }
        },
        channel,
        &writes,
        |_| LanBeginFailure::Uncertain,
    );
    assert!(matches!(
        result,
        Err(LanWriteError::Uncertain {
            write: None,
            commit: Some("commit or cleanup failed"),
            cleanup: Some("commit or cleanup failed")
        })
    ));
    assert_eq!(calls.len(), writes.len() + 3);
    let mut calls = 0;
    let invalid = [(
        LanConfigParameter::IpAddress,
        LanConfigParameterRequest::VlanPriority(9),
    )];
    assert!(matches!(
        lan_write_guarded(
            |_cmd| {
                calls += 1;
                Ok::<_, &str>(())
            },
            channel,
            &invalid,
            |_| LanBeginFailure::Uncertain,
        ),
        Err(LanWriteError::Validation(
            LanConfigError::MismatchedParameter
        ))
    ));
    assert_eq!(calls, 0);
    let mut raw_calls = Vec::new();
    lan_write_guarded(
        |cmd| {
            raw_calls.push(Message::from(cmd).data().to_vec());
            Ok::<_, &str>(())
        },
        channel,
        &[(
            LanConfigParameter::Other(230),
            LanConfigParameterRequest::Raw(vec![0xde, 0xad]),
        )],
        |_| LanBeginFailure::Uncertain,
    )
    .unwrap();
    assert_eq!(raw_calls[1], vec![14, 230, 0xde, 0xad]);
    assert!(lan_write_guarded(
        |_cmd| -> Result<(), &str> { panic!("empty transaction must not send") },
        channel,
        &[],
        |_| LanBeginFailure::Uncertain,
    )
    .is_ok());
}

#[test]
fn statistics_get_and_clear_wire_and_malformed_responses() {
    let channel = Channel::Current;
    let get: Message = GetLanStatistics { channel }.into();
    let clear: Message = ClearLanStatistics { channel }.into();
    assert_eq!((get.cmd(), get.data()), (4, &[14, 0][..]));
    assert_eq!((clear.cmd(), clear.data()), (4, &[14, 1][..]));
    let stats = GetLanStatistics::parse_success_response(&hex(
        "00 01 00 02 00 03 00 04 00 05 00 06 00 07 01 00 FF FF",
    ))
    .unwrap();
    assert_eq!(stats.ip_rx_packets, 1);
    assert_eq!(stats.udp_proxy_rx_packets, 256);
    assert_eq!(stats.udp_proxy_dropped_packets, 65535);
    assert_eq!(ClearLanStatistics::parse_success_response(&[]), Ok(None));
    assert_eq!(
        ClearLanStatistics::parse_success_response(&[0; 18]),
        Ok(Some(LanStatistics {
            ip_rx_packets: 0,
            ip_rx_header_errors: 0,
            ip_rx_address_errors: 0,
            ip_rx_fragmented_packets: 0,
            ip_tx_packets: 0,
            udp_rx_packets: 0,
            rmcp_rx_valid_packets: 0,
            udp_proxy_rx_packets: 0,
            udp_proxy_dropped_packets: 0,
        }))
    );
    assert_eq!(
        GetLanStatistics::parse_success_response(&[0; 17]),
        Err(LanConfigError::InvalidLength {
            expected: 18,
            actual: 17
        })
    );
}
