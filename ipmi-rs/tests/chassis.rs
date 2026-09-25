use ipmi_rs::{
    chassis::{
        BootDevice, BootFlags, BootInfoAcknowledge, BootInfoActors, BootInitiatorInfo,
        BootInitiatorInfoWrite, BootMailboxBlock, BootOptionError, BootOptionRejection,
        BootOptionWrite, BootOverride, BootOverrideDuration, BootValidBitClearing, ChassisControl,
        ChassisIdentify, ChassisResponseLength, ChassisStatusParseError, GetBootMailboxBlock,
        GetChassisStatus, GetPowerOnHours, GetPowerRestorePolicySupport, GetRawBootOption,
        GetSystemBootOptions, GetSystemRestartCause, IdentifyMode, PowerAction,
        PowerRestorePolicySetting, RestartReason, ServicePartitionScan, ServicePartitionSelector,
        SetBootMailboxBlock, SetInProgress, SetPowerRestorePolicy, SetSystemBootOptions,
    },
    connection::{
        CompletionErrorCode, IpmiCommand, IpmiConnection, Message, NetFn, Request, Response,
    },
    Ipmi, IpmiError,
};

#[derive(Debug, PartialEq)]
enum MockError {
    ResponseLost,
}

struct MockConnection {
    requests: Vec<(u8, u8, Vec<u8>)>,
    response: Option<Result<Response, MockError>>,
}

impl MockConnection {
    fn new(response: Result<Response, MockError>) -> Self {
        Self {
            requests: Vec::new(),
            response: Some(response),
        }
    }
}

impl IpmiConnection for MockConnection {
    type SendError = MockError;
    type RecvError = MockError;
    type Error = MockError;

    fn send(&mut self, request: &mut Request) -> Result<(), Self::SendError> {
        self.requests
            .push((request.netfn_raw(), request.cmd(), request.data().to_vec()));
        Ok(())
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        self.response.take().unwrap_or(Err(MockError::ResponseLost))
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.send(request)?;
        self.recv()
    }
}

fn response(command: u8, completion_code: u8, data: &[u8]) -> Response {
    let mut body = vec![completion_code];
    body.extend_from_slice(data);
    Response::new(Message::new_response(NetFn::Chassis, command, body), 0).unwrap()
}

fn fixture<C: IpmiCommand>(
    command: C,
    cmd: u8,
    completion_code: u8,
    data: &[u8],
) -> (
    Result<C::Output, IpmiError<MockError, C::Error>>,
    Vec<(u8, u8, Vec<u8>)>,
) {
    let mut ipmi = Ipmi::new(MockConnection::new(Ok(response(
        cmd,
        completion_code,
        data,
    ))));
    let result = ipmi.send_recv(command);
    (result, ipmi.release().requests)
}

fn lost_mutation<C: IpmiCommand>(command: C, cmd: u8, request: &[u8]) {
    let mut ipmi = Ipmi::new(MockConnection::new(Err(MockError::ResponseLost)));
    assert!(matches!(
        ipmi.send_recv(command),
        Err(IpmiError::Connection(MockError::ResponseLost))
    ));
    assert_eq!(ipmi.release().requests, [(0, cmd, request.to_vec())]);
}

#[test]
fn successful_read_and_control_have_distinct_requests_and_results() {
    let mut ipmi = Ipmi::new(MockConnection::new(Ok(response(0x01, 0, &[0x41, 0x10, 0]))));
    let status = ipmi.send_recv(GetChassisStatus).unwrap();
    assert!(status.system_power_on);
    assert!(status.last_power_event.power_command);
    assert_eq!(status.front_panel_buttons, None);
    assert_eq!(ipmi.release().requests, [(0x00, 0x01, vec![])]);

    let mut ipmi = Ipmi::new(MockConnection::new(Ok(response(0x02, 0, &[]))));
    assert_eq!(ipmi.send_recv(ChassisControl::new(PowerAction::On)), Ok(()));
    assert_eq!(ipmi.release().requests, [(0x00, 0x02, vec![0x01])]);
}

#[test]
fn short_status_response_is_a_typed_command_error() {
    let mut ipmi = Ipmi::new(MockConnection::new(Ok(response(0x01, 0, &[0x01, 0x10]))));
    assert_eq!(
        ipmi.send_recv(GetChassisStatus),
        Err(IpmiError::Command {
            error: ChassisStatusParseError::ShortResponse { actual: 2 },
            netfn: NetFn::Chassis,
            cmd: 0x01,
            completion_code: None,
            data: vec![0x01, 0x10],
        })
    );
}

#[test]
fn nonzero_completions_are_preserved_for_both_commands() {
    for code in [0x80, 0xc0, 0xff] {
        let expected = CompletionErrorCode::try_from(code).unwrap();

        let mut ipmi = Ipmi::new(MockConnection::new(Ok(response(0x01, code, &[0xa5]))));
        assert_eq!(
            ipmi.send_recv(GetChassisStatus),
            Err(IpmiError::Failed {
                netfn: NetFn::Chassis,
                cmd: 0x01,
                completion_code: expected,
                data: vec![0xa5],
            })
        );
        assert_eq!(ipmi.release().requests.len(), 1);

        let mut ipmi = Ipmi::new(MockConnection::new(Ok(response(0x02, code, &[]))));
        assert_eq!(
            ipmi.send_recv(ChassisControl::new(PowerAction::Off)),
            Err(IpmiError::Failed {
                netfn: NetFn::Chassis,
                cmd: 0x02,
                completion_code: expected,
                data: vec![],
            })
        );
        assert_eq!(ipmi.release().requests.len(), 1);
    }
}

#[test]
fn lost_control_response_does_not_resend_mutation() {
    let mut ipmi = Ipmi::new(MockConnection::new(Err(MockError::ResponseLost)));
    assert_eq!(
        ipmi.send_recv(ChassisControl::new(PowerAction::Cycle)),
        Err(IpmiError::Connection(MockError::ResponseLost))
    );
    assert_eq!(ipmi.release().requests, [(0x00, 0x02, vec![0x02])]);
}

#[test]
fn reference_power_identify_policy_restart_and_poh_fixtures() {
    for (action, byte) in [
        (PowerAction::Off, 0),
        (PowerAction::On, 1),
        (PowerAction::Cycle, 2),
        (PowerAction::HardReset, 3),
        (PowerAction::DiagnosticInterrupt, 4),
        (PowerAction::AcpiSoftShutdown, 5),
    ] {
        let (result, requests) = fixture(ChassisControl::new(action), 2, 0, &[]);
        assert_eq!(result, Ok(()));
        assert_eq!(requests, [(0, 2, vec![byte])]);
        lost_mutation(ChassisControl::new(action), 2, &[byte]);
    }
    for (mode, payload) in [
        (IdentifyMode::Default, vec![]),
        (IdentifyMode::ForSeconds(0), vec![0]),
        (IdentifyMode::ForSeconds(42), vec![42]),
        (IdentifyMode::ForceOn, vec![0, 1]),
    ] {
        let (result, requests) = fixture(ChassisIdentify::new(mode), 4, 0, &[]);
        assert_eq!(result, Ok(()));
        assert_eq!(requests, [(0, 4, payload.clone())]);
        lost_mutation(ChassisIdentify::new(mode), 4, &payload);
    }
    let (result, requests) = fixture(GetPowerRestorePolicySupport, 6, 0, &[7]);
    assert_eq!(result.unwrap().raw, 7);
    assert_eq!(requests, [(0, 6, vec![3])]);
    for (policy, byte) in [
        (PowerRestorePolicySetting::AlwaysOff, 0),
        (PowerRestorePolicySetting::RestorePrevious, 1),
        (PowerRestorePolicySetting::AlwaysOn, 2),
    ] {
        let (result, requests) = fixture(SetPowerRestorePolicy::new(policy), 6, 0, &[7]);
        assert!(result.unwrap().supports(policy));
        assert_eq!(requests, [(0, 6, vec![byte])]);
        lost_mutation(SetPowerRestorePolicy::new(policy), 6, &[byte]);
    }
    let (result, requests) = fixture(GetSystemRestartCause, 7, 0, &[0xf1, 0]);
    assert_eq!(result.unwrap().reason, RestartReason::ChassisControl);
    assert_eq!(requests, [(0, 7, vec![])]);
    let (result, requests) = fixture(GetPowerOnHours, 15, 0, &[1, 0x40, 0xe2, 1, 0]);
    assert_eq!(result.unwrap().total_minutes(), 123456);
    assert_eq!(requests, [(0, 15, vec![])]);
}

#[test]
fn reference_boot_selector_and_mailbox_fixtures() {
    let (result, requests) = fixture(
        GetSystemBootOptions::<ServicePartitionSelector>::new(),
        9,
        0,
        &[1, 1, 42],
    );
    assert_eq!(result, Ok(ServicePartitionSelector(42)));
    assert_eq!(requests, [(0, 9, vec![1, 0, 0])]);
    let (result, requests) = fixture(
        GetSystemBootOptions::<ServicePartitionScan>::new(),
        9,
        0,
        &[1, 2, 3],
    );
    assert_eq!(result, Ok(ServicePartitionScan::ScanRequestedAndDiscovered));
    assert_eq!(requests, [(0, 9, vec![2, 0, 0])]);
    let (result, requests) = fixture(
        GetSystemBootOptions::<BootInitiatorInfo>::new(),
        9,
        0,
        &[1, 6, 0x71, 0x78, 0x56, 0x34, 0x12, 0, 0xe1, 0x0b, 0x5e],
    );
    assert_eq!(result.unwrap().session_id, 0x1234_5678);
    assert_eq!(requests, [(0, 9, vec![6, 0, 0])]);
    let (result, requests) = fixture(
        GetSystemBootOptions::<BootFlags>::new(),
        9,
        0,
        &[1, 5, 0x80, 0x28, 0, 0, 0],
    );
    assert_eq!(result, Ok(BootFlags::Unknown([0x80, 0x28, 0, 0, 0])));
    assert_eq!(requests, [(0, 9, vec![5, 0, 0])]);
    let (result, requests) = fixture(
        GetRawBootOption::new(42, 1, 0).unwrap(),
        9,
        0,
        &[2, 0xaa, 1, 2],
    );
    assert_eq!(result.unwrap().data, vec![1, 2]);
    assert_eq!(requests, [(0, 9, vec![42, 1, 0])]);

    let block0 = [
        1, 7, 0, 0x57, 1, 0, 0x69, 0x70, 0x6d, 0x69, 0x74, 0x6f, 0x6f, 0x6c, 0x20, 0x72, 0x6f,
        0x6f, 0x74,
    ];
    let (result, requests) = fixture(GetBootMailboxBlock::<0>::new(), 9, 0, &block0);
    assert_eq!(
        result,
        Ok(BootMailboxBlock {
            block: 0,
            iana: Some(343),
            data: b"ipmitool root".to_vec()
        })
    );
    assert_eq!(requests, [(0, 9, vec![7, 0, 0])]);
    let (result, requests) = fixture(
        GetBootMailboxBlock::<1>::new(),
        9,
        0,
        &[1, 7, 1, 0xaa, 0xbb],
    );
    assert_eq!(
        result,
        Ok(BootMailboxBlock {
            block: 1,
            iana: None,
            data: vec![0xaa, 0xbb]
        })
    );
    assert_eq!(requests, [(0, 9, vec![7, 1, 0])]);

    for (write, wire) in [
        (
            BootOptionWrite::SetInProgress(SetInProgress::InProgress),
            vec![0, 1],
        ),
        (
            BootOptionWrite::ServicePartitionSelector(ServicePartitionSelector(42)),
            vec![1, 42],
        ),
        (
            BootOptionWrite::ServicePartitionScanRequest(true),
            vec![2, 1],
        ),
        (
            BootOptionWrite::ValidBitClearing(BootValidBitClearing::TIMEOUT),
            vec![3, 8],
        ),
        (
            BootOptionWrite::BootInfoAcknowledge(BootInfoAcknowledge::new(
                BootInfoActors::BIOS_POST,
                BootInfoActors::OS_LOADER,
            )),
            vec![4, 1, 2],
        ),
        (
            BootOptionWrite::BootFlags(BootOverride::new(
                BootDevice::Pxe,
                BootOverrideDuration::OneTime,
            )),
            vec![5, 0x80, 4, 0, 0, 0],
        ),
        (
            BootOptionWrite::BootInitiatorInfo(
                BootInitiatorInfoWrite::new(1, 0x1234_5678, 0x5e0b_e100).unwrap(),
            ),
            vec![6, 1, 0x78, 0x56, 0x34, 0x12, 0, 0xe1, 0x0b, 0x5e],
        ),
    ] {
        let (result, requests) = fixture(SetSystemBootOptions::new(write), 8, 0, &[]);
        assert_eq!(result, Ok(()));
        assert_eq!(requests, [(0, 8, wire.clone())]);
        lost_mutation(SetSystemBootOptions::new(write), 8, &wire);
    }
    for (block, iana, data, wire) in [
        (0, Some(343), vec![1, 2, 3], vec![7, 0, 0x57, 1, 0, 1, 2, 3]),
        (1, None, vec![0xff], vec![7, 1, 0xff]),
    ] {
        let write = SetBootMailboxBlock::new(block, iana, data).unwrap();
        let (result, requests) = fixture(write.clone(), 8, 0, &[]);
        assert_eq!(result, Ok(()));
        assert_eq!(requests, [(0, 8, wire.clone())]);
        lost_mutation(write, 8, &wire);
    }
}

#[test]
fn unsupported_codes_and_malformed_responses_do_not_trigger_replays() {
    let (result, requests) = fixture(GetBootMailboxBlock::<1>::new(), 9, 0x80, &[]);
    assert_eq!(
        result,
        Err(IpmiError::Command {
            error: BootOptionError::Rejected(BootOptionRejection::UnsupportedParameter),
            netfn: NetFn::Chassis,
            cmd: 9,
            completion_code: Some(CompletionErrorCode::CommandSpecific(0x80)),
            data: vec![]
        })
    );
    assert_eq!(requests, [(0, 9, vec![7, 1, 0])]);
    let (result, requests) = fixture(GetBootMailboxBlock::<1>::new(), 9, 0xc9, &[]);
    assert_eq!(
        result,
        Err(IpmiError::Failed {
            netfn: NetFn::Chassis,
            cmd: 9,
            completion_code: CompletionErrorCode::ParameterOutOfRange,
            data: vec![],
        })
    );
    assert_eq!(requests.len(), 1);
    let (result, requests) = fixture(
        SetBootMailboxBlock::new(0, Some(1), vec![1]).unwrap(),
        8,
        0x82,
        &[],
    );
    assert_eq!(
        result,
        Err(IpmiError::Command {
            error: BootOptionError::Rejected(BootOptionRejection::ReadOnly),
            netfn: NetFn::Chassis,
            cmd: 8,
            completion_code: Some(CompletionErrorCode::CommandSpecific(0x82)),
            data: vec![],
        })
    );
    assert_eq!(requests, [(0, 8, vec![7, 0, 1, 0, 0, 1])]);
    for (code, rejection) in [
        (0x80, BootOptionRejection::UnsupportedParameter),
        (0x81, BootOptionRejection::AlreadyInProgress),
        (0x82, BootOptionRejection::ReadOnly),
    ] {
        let (result, requests) = fixture(
            SetSystemBootOptions::new(BootOptionWrite::ServicePartitionScanRequest(true)),
            8,
            code,
            &[],
        );
        assert_eq!(
            result,
            Err(IpmiError::Command {
                error: BootOptionError::Rejected(rejection),
                netfn: NetFn::Chassis,
                cmd: 8,
                completion_code: Some(CompletionErrorCode::CommandSpecific(code)),
                data: vec![],
            })
        );
        assert_eq!(requests, [(0, 8, vec![2, 1])]);
    }
    for action in [
        PowerAction::DiagnosticInterrupt,
        PowerAction::AcpiSoftShutdown,
    ] {
        let (result, requests) = fixture(ChassisControl::new(action), 2, 0xc1, &[]);
        assert!(matches!(
            result,
            Err(IpmiError::Failed {
                completion_code: CompletionErrorCode::InvalidCommand,
                ..
            })
        ));
        assert_eq!(requests, [(0, 2, vec![action.value()])]);
    }
    let (result, requests) = fixture(
        SetPowerRestorePolicy::new(PowerRestorePolicySetting::AlwaysOff),
        6,
        0xc1,
        &[],
    );
    assert!(matches!(
        result,
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::InvalidCommand,
            ..
        })
    ));
    assert_eq!(requests, [(0, 6, vec![0])]);
    let (result, requests) = fixture(ChassisIdentify::new(IdentifyMode::ForceOn), 4, 0xc7, &[]);
    assert!(matches!(
        result,
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::RequestDataLenInvalid,
            ..
        })
    ));
    assert_eq!(requests, [(0, 4, vec![0, 1])]);
    let (result, _) = fixture(
        SetPowerRestorePolicy::new(PowerRestorePolicySetting::AlwaysOn),
        6,
        0,
        &[],
    );
    assert!(matches!(
        result,
        Err(IpmiError::Command {
            error: ChassisResponseLength {
                expected: 1,
                actual: 0
            },
            ..
        })
    ));
    let (result, _) = fixture(GetSystemRestartCause, 7, 0, &[1]);
    assert!(matches!(
        result,
        Err(IpmiError::Command {
            error: ChassisResponseLength {
                expected: 2,
                actual: 1
            },
            ..
        })
    ));
    let (result, _) = fixture(GetPowerOnHours, 15, 0, &[1, 0, 0, 0]);
    assert!(matches!(
        result,
        Err(IpmiError::Command {
            error: ChassisResponseLength {
                expected: 5,
                actual: 4
            },
            ..
        })
    ));
    let (result, _) = fixture(GetBootMailboxBlock::<0>::new(), 9, 0, &[1, 7, 0, 0, 0]);
    assert!(matches!(
        result,
        Err(IpmiError::Command {
            error: BootOptionError::InvalidLengthRange {
                minimum: 6,
                actual: 5,
                ..
            },
            ..
        })
    ));
    let (result, _) = fixture(GetBootMailboxBlock::<1>::new(), 9, 0, &[1, 7, 2, 0]);
    assert!(matches!(
        result,
        Err(IpmiError::Command {
            error: BootOptionError::UnexpectedBlock {
                expected: 1,
                actual: 2
            },
            ..
        })
    ));
}
