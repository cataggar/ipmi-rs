use ipmi_rs::{
    chassis::{ChassisControl, ChassisStatusParseError, GetChassisStatus, PowerAction},
    connection::{CompletionErrorCode, IpmiConnection, Message, NetFn, Request, Response},
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
