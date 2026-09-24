use ipmi_rs::{
    app::{ColdReset, WarmReset},
    chassis::{
        BootDevice, BootFlags, BootInfoAcknowledge, BootInfoActors, BootOptionError,
        BootOptionRejection, BootOptionWrite, BootOverride, BootOverrideDuration,
        BootValidBitClearing, GetSystemBootOptions, SetInProgress, SetSystemBootOptions,
    },
    connection::{
        CompletionErrorCode, IpmiCommand, IpmiConnection, LogicalUnit, Message, NetFn, Request,
        RequestTargetAddress, Response,
    },
    Ipmi, IpmiError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MockError {
    Timeout,
}

#[derive(Debug, PartialEq)]
struct Sent {
    netfn: u8,
    cmd: u8,
    data: Vec<u8>,
    target: RequestTargetAddress,
}

#[derive(Default)]
struct MockConnection {
    sent: Vec<Sent>,
    reply: Option<Result<Response, MockError>>,
}

impl MockConnection {
    fn response(netfn: NetFn, command: u8, completion: u8, data: &[u8]) -> Self {
        let mut bytes = vec![completion];
        bytes.extend_from_slice(data);
        Self {
            reply: Some(Ok(Response::new(
                Message::new_response(netfn, command, bytes),
                0,
            )
            .unwrap())),
            ..Self::default()
        }
    }
}

impl IpmiConnection for MockConnection {
    type SendError = MockError;
    type RecvError = MockError;
    type Error = MockError;

    fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
        Err(MockError::Timeout)
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        Err(MockError::Timeout)
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.sent.push(Sent {
            netfn: request.netfn_raw(),
            cmd: request.cmd(),
            data: request.data().to_vec(),
            target: request.target(),
        });
        self.reply.take().unwrap_or(Err(MockError::Timeout))
    }
}

fn assert_timeout_is_not_replayed<C: IpmiCommand>(command: C, netfn: u8, cmd: u8, data: &[u8]) {
    let mut ipmi = Ipmi::new(MockConnection::default());
    assert!(matches!(
        ipmi.send_recv(command),
        Err(IpmiError::Connection(MockError::Timeout))
    ));
    let mock = ipmi.release();
    assert_eq!(
        mock.sent,
        [Sent {
            netfn,
            cmd,
            data: data.to_vec(),
            target: RequestTargetAddress::Bmc(LogicalUnit::Zero),
        }]
    );
    assert!(
        mock.sent
            .iter()
            .all(|sent| sent.netfn != 0x00 || sent.cmd != 0x02),
        "a BMC reset or boot-options write must not become a host power command"
    );
}

#[test]
fn timed_out_bmc_resets_and_boot_mutations_have_unknown_outcomes_without_replay() {
    assert_timeout_is_not_replayed(WarmReset, 0x06, 0x03, &[]);
    assert_timeout_is_not_replayed(ColdReset, 0x06, 0x02, &[]);

    let pxe = BootOverride::new(BootDevice::Pxe, BootOverrideDuration::OneTime);
    for (option, data) in [
        (BootOptionWrite::BootFlags(pxe), vec![5, 0x80, 4, 0, 0, 0]),
        (
            BootOptionWrite::SetInProgress(SetInProgress::InProgress),
            vec![0, 1],
        ),
        (
            BootOptionWrite::ValidBitClearing(BootValidBitClearing::empty()),
            vec![3, 0],
        ),
        (
            BootOptionWrite::BootInfoAcknowledge(BootInfoAcknowledge::new(
                BootInfoActors::BIOS_POST,
                BootInfoActors::BIOS_POST,
            )),
            vec![4, 1, 1],
        ),
    ] {
        assert_timeout_is_not_replayed(SetSystemBootOptions::new(option), 0x00, 0x08, &data);
    }
}

#[test]
fn mock_get_readback_is_typed_and_malformed_readback_is_rejected() {
    let mut ipmi = Ipmi::new(MockConnection::response(
        NetFn::Chassis,
        0x09,
        0,
        &[1, 5, 0xC0, 0x14, 0, 0, 0],
    ));
    assert_eq!(
        ipmi.send_recv(GetSystemBootOptions::<BootFlags>::new()),
        Ok(BootFlags::Valid(BootOverride::new(
            BootDevice::CdRom,
            BootOverrideDuration::Persistent
        )))
    );
    assert_eq!(ipmi.release().sent.len(), 1);

    let mut ipmi = Ipmi::new(MockConnection::response(
        NetFn::Chassis,
        0x09,
        0,
        &[1, 0x85, 0x80, 4, 0, 0, 0],
    ));
    assert!(matches!(
        ipmi.send_recv(GetSystemBootOptions::<BootFlags>::new()),
        Err(IpmiError::Command {
            error: BootOptionError::InvalidOrLocked(5),
            completion_code: None,
            ..
        })
    ));
}

#[test]
fn mock_preserves_boot_rejections_and_other_completion_codes() {
    for (code, rejection) in [
        (0x80, BootOptionRejection::UnsupportedParameter),
        (0x81, BootOptionRejection::AlreadyInProgress),
        (0x82, BootOptionRejection::ReadOnly),
    ] {
        let mut ipmi = Ipmi::new(MockConnection::response(NetFn::Chassis, 0x08, code, &[]));
        assert!(matches!(
            ipmi.send_recv(SetSystemBootOptions::new(BootOptionWrite::BootFlags(
                BootOverride::new(BootDevice::Pxe, BootOverrideDuration::OneTime)
            ))),
            Err(IpmiError::Command {
                error: BootOptionError::Rejected(reason),
                completion_code: Some(CompletionErrorCode::CommandSpecific(cc)),
                ..
            }) if reason == rejection && cc == code
        ));
        assert_eq!(ipmi.release().sent.len(), 1);
    }

    let mut ipmi = Ipmi::new(MockConnection::response(NetFn::Chassis, 0x09, 0x80, &[]));
    assert!(matches!(
        ipmi.send_recv(GetSystemBootOptions::<BootFlags>::new()),
        Err(IpmiError::Command {
            error: BootOptionError::Rejected(BootOptionRejection::UnsupportedParameter),
            completion_code: Some(CompletionErrorCode::CommandSpecific(0x80)),
            ..
        })
    ));
    let mut ipmi = Ipmi::new(MockConnection::response(NetFn::Chassis, 0x08, 0xC9, &[]));
    assert!(matches!(
        ipmi.send_recv(SetSystemBootOptions::new(BootOptionWrite::SetInProgress(
            SetInProgress::InProgress
        ))),
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::ParameterOutOfRange,
            ..
        })
    ));
    let mut ipmi = Ipmi::new(MockConnection::response(NetFn::App, 0x02, 0xC3, &[]));
    assert!(matches!(
        ipmi.send_recv(ColdReset),
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::ProcessingTimeout,
            ..
        })
    ));
}
