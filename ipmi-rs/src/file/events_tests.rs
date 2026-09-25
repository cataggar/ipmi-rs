use super::*;
use std::collections::VecDeque;

#[test]
fn async_receiver_fixtures_and_failures() {
    let mut record = [0u8; 16];
    record[0..2].copy_from_slice(&7u16.to_le_bytes());
    record[2] = 0x02;
    record[7] = 0x41;
    record[9] = 4;
    record[10] = 1;
    record[11] = 0x30;
    record[12] = 1;
    record[13..].copy_from_slice(&[9, 0xff, 0xff]);
    let event = parse_async_event(2, &record).unwrap();
    assert_eq!(event.raw, record);
    assert!(matches!(
        event.entry,
        Entry::System {
            sensor_number: 0x30,
            ..
        }
    ));
    record[2] = 0xc1;
    assert!(matches!(
        parse_async_event(2, &record).unwrap().entry,
        Entry::OemTimestamped { .. }
    ));
    assert!(matches!(
        parse_async_event(1, &record),
        Err(OpenIpmiEventError::UnexpectedType(1))
    ));
    assert!(matches!(
        parse_async_event(2, &record[..15]),
        Err(OpenIpmiEventError::InvalidLength(15))
    ));
    record[2] = 2;
    record[8] = 0xc0;
    assert!(matches!(
        parse_async_event(2, &record),
        Err(OpenIpmiEventError::Malformed(
            ParseEntryError::InvalidChannel(12)
        ))
    ));
}

type SetupStep = (u8, Vec<u8>, Result<Vec<u8>, io::Error>);
struct SetupFixture(VecDeque<SetupStep>);

impl IpmiConnection for SetupFixture {
    type SendError = io::Error;
    type RecvError = io::Error;
    type Error = io::Error;

    fn send(&mut self, _: &mut Request) -> io::Result<()> {
        unreachable!()
    }
    fn recv(&mut self) -> io::Result<Response> {
        unreachable!()
    }
    fn send_recv(&mut self, request: &mut Request) -> io::Result<Response> {
        let (cmd, payload, result) = self.0.pop_front().expect("unexpected command");
        assert_eq!(request.netfn(), NetFn::App);
        assert_eq!(request.cmd(), cmd);
        assert_eq!(request.data(), payload);
        let body = result?;
        let mut data = vec![0];
        data.extend(body);
        Ok(Response::new(Message::new_response(NetFn::App, cmd, data), 0).unwrap())
    }
}

#[test]
fn buffer_setup_preserves_flags_and_exposes_each_failure() {
    let setup = |steps: Vec<SetupStep>| Ipmi::new(SetupFixture(steps.into()));
    let mut ipmi = setup(vec![(0x2f, vec![], Ok(vec![0xa5]))]);
    enable_event_msg_buffer(&mut ipmi).unwrap();
    assert!(ipmi.release().0.is_empty());

    let mut ipmi = setup(vec![
        (0x2f, vec![], Ok(vec![0xa0])),
        (0x2e, vec![0xa4], Ok(vec![])),
    ]);
    enable_event_msg_buffer(&mut ipmi).unwrap();
    assert!(ipmi.release().0.is_empty());

    let mut ipmi = setup(vec![(0x2f, vec![], Err(io::Error::other("read failure")))]);
    assert!(matches!(
        enable_event_msg_buffer(&mut ipmi),
        Err(OpenIpmiEventSetupError::ReadEnables(_))
    ));
    assert!(ipmi.release().0.is_empty());

    let mut ipmi = setup(vec![
        (0x2f, vec![], Ok(vec![0x20])),
        (
            0x2e,
            vec![0x24],
            Err(io::Error::other("write outcome unknown")),
        ),
    ]);
    assert!(matches!(
        enable_event_msg_buffer(&mut ipmi),
        Err(OpenIpmiEventSetupError::EnableBuffer(_))
    ));
    assert!(ipmi.release().0.is_empty());
}

#[test]
fn local_receiver_checks_budget_and_reports_ioctl_errors() {
    let mut file = File {
        inner: std::fs::File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap(),
        recv_timeout: Duration::from_secs(1),
        seq: 0,
        my_addr: Address(0x20),
    };
    let mut receiver = OpenIpmiEventReceiver {
        file: &mut file,
        subscribed: false,
    };
    let token = CancellationToken::default();
    token.cancel();
    assert!(matches!(
        receiver.recv_until(Instant::now() + Duration::from_secs(1), &token),
        Err(OpenIpmiEventError::Cancelled)
    ));
    token.reset();
    assert!(matches!(
        receiver.recv_until(Instant::now() - Duration::from_secs(1), &token),
        Err(OpenIpmiEventError::DeadlineExpired)
    ));
    assert!(matches!(
        receiver.recv_until(Instant::now() + Duration::from_secs(1), &token),
        Err(OpenIpmiEventError::Io(_))
    ));
}

#[test]
fn file_transaction_rejects_expired_or_cancelled_before_dispatch() {
    let mut file = File {
        inner: std::fs::File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap(),
        recv_timeout: Duration::from_secs(2),
        seq: 0,
        my_addr: Address(0x20),
    };
    let mut request = Request::new(
        Message::new_request(NetFn::Storage, 0x40, vec![]),
        RequestTargetAddress::Bmc(crate::connection::LogicalUnit::Zero),
    );
    let token = CancellationToken::default();
    token.cancel();
    assert_eq!(
        file.send_recv_deadline(
            &mut request,
            Instant::now() + Duration::from_secs(1),
            &token
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::Interrupted
    );
    token.reset();
    assert_eq!(
        file.send_recv_deadline(
            &mut request,
            Instant::now() - Duration::from_secs(1),
            &token
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(file.seq, 0);
    assert_eq!(file.recv_timeout, Duration::from_secs(2));
}
