use ipmi_rs::{
    app::{
        system_info::{
            GetSystemInfoParameter, SetSystemInfoParameter, SystemInfoEncoding, SystemInfoError,
            SystemInfoRejection, SystemInfoSelector, SystemInfoSetInProgress, SystemInfoString,
        },
        watchdog::{
            ResetWatchdogTimer, SetWatchdogTimer, WatchdogAction, WatchdogConfiguration,
            WatchdogError, WatchdogExpirationFlags, WatchdogInterrupt, WatchdogUse,
        },
        BmcGlobalEnables, GetBmcGlobalEnables, GetDeviceGuid, GetSelfTestResults, SelfTestStatus,
        SetBmcGlobalEnables,
    },
    connection::{
        CompletionErrorCode, IpmiCommand, IpmiConnection, LogicalUnit, Message, NetFn, Request,
        RequestTargetAddress, Response,
    },
    Ipmi, IpmiError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MockError {
    LostAcknowledgement,
}

#[derive(Default)]
struct Mock {
    sent: Vec<(u8, u8, Vec<u8>, RequestTargetAddress)>,
    reply: Option<Result<Response, MockError>>,
}

impl Mock {
    fn reply(command: u8, completion: u8, data: &[u8]) -> Self {
        let mut bytes = vec![completion];
        bytes.extend_from_slice(data);
        Self {
            reply: Some(Ok(Response::new(
                Message::new_response(NetFn::App, command, bytes),
                0,
            )
            .unwrap())),
            ..Self::default()
        }
    }
}

impl IpmiConnection for Mock {
    type SendError = MockError;
    type RecvError = MockError;
    type Error = MockError;

    fn send(&mut self, _: &mut Request) -> Result<(), MockError> {
        Err(MockError::LostAcknowledgement)
    }

    fn recv(&mut self) -> Result<Response, MockError> {
        Err(MockError::LostAcknowledgement)
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, MockError> {
        self.sent.push((
            request.netfn_raw(),
            request.cmd(),
            request.data().to_vec(),
            request.target(),
        ));
        self.reply
            .take()
            .unwrap_or(Err(MockError::LostAcknowledgement))
    }
}

fn no_replay<C: IpmiCommand>(command: C, cmd: u8, expected_data: &[u8]) {
    let mut ipmi = Ipmi::new(Mock::default());
    assert!(matches!(
        ipmi.send_recv(command),
        Err(IpmiError::Connection(MockError::LostAcknowledgement))
    ));
    assert_eq!(
        ipmi.release().sent,
        [(
            6,
            cmd,
            expected_data.to_vec(),
            RequestTargetAddress::Bmc(LogicalUnit::Zero)
        )]
    );
}

#[test]
fn mutations_are_explicit_once_only_and_target_the_bmc() {
    no_replay(
        SetBmcGlobalEnables(BmcGlobalEnables::SYSTEM_EVENT_LOG),
        0x2e,
        &[0x08],
    );
    let config = WatchdogConfiguration {
        timer_use: WatchdogUse::SmsOs,
        do_not_stop: false,
        do_not_log: false,
        action: WatchdogAction::HardReset,
        interrupt: WatchdogInterrupt::None,
        pretimeout_seconds: 0,
        clear_expiration_flags: WatchdogExpirationFlags::empty(),
        initial_countdown_deciseconds: 3000,
    };
    no_replay(
        SetWatchdogTimer::new(config).unwrap(),
        0x24,
        &[4, 1, 0, 0, 0xb8, 0x0b],
    );
    no_replay(ResetWatchdogTimer, 0x22, &[]);
    no_replay(
        SetSystemInfoParameter::set_in_progress(SystemInfoSetInProgress::InProgress),
        0x58,
        &[0, 1],
    );
    let string = SystemInfoString::new(
        SystemInfoSelector::OsName,
        SystemInfoEncoding::AsciiLatin1,
        b"example".to_vec(),
    )
    .unwrap();
    no_replay(
        string.to_writes().remove(0),
        0x58,
        &[
            4, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 0, 0, 0, 0, 0,
        ],
    );
}

#[test]
fn typed_reads_and_invalid_responses() {
    let mut ipmi = Ipmi::new(Mock::reply(0x37, 0, &[0; 16]));
    assert_eq!(ipmi.send_recv(GetDeviceGuid).unwrap().raw(), [0; 16]);
    let mut ipmi = Ipmi::new(Mock::reply(0x04, 0, &[0x80, 0xa5]));
    assert_eq!(
        ipmi.send_recv(GetSelfTestResults).unwrap().status,
        SelfTestStatus::Other(0x80)
    );
    let mut ipmi = Ipmi::new(Mock::reply(0x2f, 0, &[0x10]));
    assert!(matches!(
        ipmi.send_recv(GetBmcGlobalEnables),
        Err(IpmiError::Command {
            completion_code: None,
            ..
        })
    ));
    let get = GetSystemInfoParameter::string(SystemInfoSelector::OsName, 0).unwrap();
    let mut ipmi = Ipmi::new(Mock::reply(0x59, 0, &[0x11, 0, 0, 3, b'o', b's', b'!']));
    let raw = ipmi.send_recv(get).unwrap();
    assert!(get.decode(&raw).is_ok());
    let mut ipmi = Ipmi::new(Mock::reply(0x59, 0, &[0x11, 1, 0, 3, b'o', b's', b'!']));
    assert_eq!(
        get.decode(&ipmi.send_recv(get).unwrap()),
        Err(SystemInfoError::UnexpectedSet {
            expected: 0,
            actual: 1
        })
    );
}

#[test]
fn command_specific_and_generic_completion_codes_survive() {
    let mut ipmi = Ipmi::new(Mock::reply(0x22, 0x80, &[]));
    assert!(matches!(
        ipmi.send_recv(ResetWatchdogTimer),
        Err(IpmiError::Command {
            error: WatchdogError::NotInitialized,
            completion_code: Some(CompletionErrorCode::CommandSpecific(0x80)),
            ..
        })
    ));
    let mut ipmi = Ipmi::new(Mock::reply(0x59, 0x80, &[]));
    assert!(matches!(
        ipmi.send_recv(GetSystemInfoParameter::set_in_progress()),
        Err(IpmiError::Command {
            error: SystemInfoError::Rejected(SystemInfoRejection::UnsupportedParameter),
            completion_code: Some(CompletionErrorCode::CommandSpecific(0x80)),
            ..
        })
    ));
    let mut ipmi = Ipmi::new(Mock::reply(0x2e, 0xc9, &[]));
    assert!(matches!(
        ipmi.send_recv(SetBmcGlobalEnables(BmcGlobalEnables::SYSTEM_EVENT_LOG)),
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::ParameterOutOfRange,
            ..
        })
    ));
    let mut ipmi = Ipmi::new(Mock::reply(0x37, 0xc1, &[]));
    assert!(matches!(
        ipmi.send_recv(GetDeviceGuid),
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::InvalidCommand,
            ..
        })
    ));
    let mut ipmi = Ipmi::new(Mock::reply(0x04, 0xc1, &[]));
    assert!(matches!(
        ipmi.send_recv(GetSelfTestResults),
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::InvalidCommand,
            ..
        })
    ));
}
