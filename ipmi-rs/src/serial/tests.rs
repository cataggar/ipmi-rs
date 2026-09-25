use super::*;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use crate::{
    chassis::GetChassisStatus,
    connection::{Address, Channel, LogicalUnit, NetFn},
    Ipmi, IpmiError,
};

#[derive(Default)]
struct State {
    incoming: VecDeque<u8>,
    written: Vec<u8>,
    write_size: usize,
}

struct MockPort(Arc<Mutex<State>>);

impl Read for MockPort {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(byte) = self.0.lock().unwrap().incoming.pop_front() else {
            return Err(io::ErrorKind::TimedOut.into());
        };
        buf[0] = byte;
        Ok(1)
    }
}

impl Write for MockPort {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.0.lock().unwrap();
        let n = state.write_size.min(buf.len()).max(1);
        state.written.extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn mock(mode: SerialMode) -> (SerialConnection, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State {
        write_size: 2,
        ..State::default()
    }));
    (
        SerialConnection::with_port(
            Box::new(MockPort(state.clone())),
            mode,
            Duration::from_millis(10),
        ),
        state,
    )
}

fn incoming(state: &Arc<Mutex<State>>, wire: &[u8]) {
    state.lock().unwrap().incoming.extend(wire);
}

fn request() -> Request {
    Request::new(
        Message::new_request(NetFn::Chassis, 1, vec![0xA0, 0xA5, 0xA6, 0xAA, 0x1B]),
        RequestTargetAddress::Bmc(LogicalUnit::Zero),
    )
}

fn response(mode: SerialMode, seq: u8, cc: u8, data: &[u8]) -> Vec<u8> {
    let mut body = vec![cc];
    body.extend_from_slice(data);
    let payload = match mode {
        SerialMode::Basic => ipmb(REQUESTER, 4, BMC, seq, 1, &body),
        SerialMode::Terminal => {
            let mut payload = vec![4, seq << 2, 1];
            payload.extend_from_slice(&body);
            payload
        }
    };
    encode(mode, &payload)
}

#[test]
fn wire_formats_escape_match_and_preserve_completion() {
    for mode in [SerialMode::Basic, SerialMode::Terminal] {
        let (mut serial, state) = mock(mode);
        let mut req = request();
        serial.send(&mut req).unwrap();
        let payload = match mode {
            SerialMode::Basic => ipmb(BMC, 0, REQUESTER, 1, 1, req.data()),
            SerialMode::Terminal => {
                let mut bytes = vec![0, 4, 1];
                bytes.extend_from_slice(req.data());
                bytes
            }
        };
        assert_eq!(state.lock().unwrap().written, encode(mode, &payload));
        incoming(&state, &response(mode, 0, 0, &[0x10]));
        incoming(&state, &response(mode, 1, 0xC1, &[0xA5]));
        let got = serial.recv().unwrap();
        assert_eq!((got.seq(), got.cc(), got.data()), (1, 0xC1, &[0xA5][..]));
        assert!(matches!(
            serial.recv(),
            Err(SerialRecvError::NoPendingRequest)
        ));
    }
}

#[test]
fn typed_command_works_in_both_modes() {
    for mode in [SerialMode::Basic, SerialMode::Terminal] {
        let (serial, state) = mock(mode);
        incoming(&state, &response(mode, 1, 0, &[1, 0, 0]));
        let mut ipmi = Ipmi::new(serial);
        assert!(ipmi.send_recv(GetChassisStatus).unwrap().system_power_on);

        incoming(&state, &response(mode, 2, 0xC1, &[]));
        assert!(matches!(
            ipmi.send_recv(GetChassisStatus),
            Err(IpmiError::Failed { .. })
        ));
    }
}

#[test]
fn basic_bad_checksum_escape_and_unbounded_frames_are_rejected() {
    let (mut serial, state) = mock(SerialMode::Basic);
    serial.send(&mut request()).unwrap();
    let mut corrupt = response(SerialMode::Basic, 1, 0, &[]);
    corrupt[2] ^= 1;
    incoming(&state, &corrupt);
    incoming(&state, &response(SerialMode::Basic, 1, 0, &[]));
    assert_eq!(serial.recv().unwrap().cc(), 0);

    serial.send(&mut request()).unwrap();
    incoming(&state, &[0xA0, 0xAA, 0xFF, 0xA5]);
    assert!(matches!(serial.recv(), Err(SerialRecvError::InvalidFrame)));

    serial.send(&mut request()).unwrap();
    incoming(&state, &encode(SerialMode::Basic, &[0; MAX_FRAME + 1]));
    assert!(matches!(serial.recv(), Err(SerialRecvError::InvalidFrame)));
}

#[test]
fn terminal_whitespace_validation_and_timeouts() {
    let (mut serial, state) = mock(SerialMode::Terminal);
    serial.send(&mut request()).unwrap();
    incoming(&state, b"[ 04 04 01 00 ]\r\n");
    assert_eq!(serial.recv().unwrap().cc(), 0);
    serial.send(&mut request()).unwrap();
    incoming(&state, b"[GG]\r\n");
    assert!(matches!(serial.recv(), Err(SerialRecvError::InvalidFrame)));

    let mut req = request();
    assert!(matches!(
        serial.send_recv(&mut req),
        Err(SerialError::OutcomeUnknown(SerialRecvError::Timeout))
    ));
    serial.cancellation_token().cancel();
    assert!(matches!(
        serial.send(&mut req),
        Err(SerialSendError::Cancelled)
    ));
    serial.cancellation_token().reset();
    assert!(matches!(
        serial.send(&mut Request::new(
            Message::new_request(NetFn::Chassis, 1, vec![0; 38]),
            RequestTargetAddress::Bmc(LogicalUnit::Zero)
        )),
        Err(SerialSendError::RequestTooLong)
    ));
}

#[test]
fn bridged_request_matches_inner_and_preserves_outer_error() {
    let (mut serial, state) = mock(SerialMode::Basic);
    let make_request = || {
        Request::new(
            Message::new_request(NetFn::SensorEvent, 0x2d, vec![0x31]),
            RequestTargetAddress::BmcOrIpmb(
                Address(0x30),
                Channel::new(1).unwrap(),
                LogicalUnit::Zero,
            ),
        )
    };
    serial.send(&mut make_request()).unwrap();
    let bytes = state.lock().unwrap().written.clone();
    let inner_request = ipmb(0x30, 0x10, REQUESTER, 1, 0x2d, &[0x31]);
    let mut outer_data = vec![0x41];
    outer_data.extend_from_slice(&inner_request);
    assert_eq!(
        bytes,
        encode(
            SerialMode::Basic,
            &ipmb(BMC, 0x18, REQUESTER, 1, 0x34, &outer_data)
        )
    );

    incoming(
        &state,
        &encode(
            SerialMode::Basic,
            &ipmb(REQUESTER, 0x1c, BMC, 1, 0x34, &[0]),
        ),
    );
    incoming(
        &state,
        &encode(
            SerialMode::Basic,
            &ipmb(REQUESTER, 0x14, 0x30, 1, 0x2d, &[0, 0x7f]),
        ),
    );
    assert_eq!(serial.recv().unwrap().data(), &[0x7f]);
    serial.send(&mut make_request()).unwrap();
    incoming(
        &state,
        &encode(
            SerialMode::Basic,
            &ipmb(REQUESTER, 0x1c, BMC, 2, 0x34, &[0xc1]),
        ),
    );
    assert_eq!(serial.recv().unwrap().cc(), 0xc1);
}

#[test]
fn terminal_bridging_and_embedded_basic_response() {
    let bridged = || {
        Request::new(
            Message::new_request(NetFn::SensorEvent, 0x2d, vec![]),
            RequestTargetAddress::BmcOrIpmb(
                Address(0x30),
                Channel::new(1).unwrap(),
                LogicalUnit::Zero,
            ),
        )
    };
    let (mut terminal, state) = mock(SerialMode::Terminal);
    terminal.send(&mut bridged()).unwrap();
    incoming(&state, &encode(SerialMode::Terminal, &[0x1c, 4, 0x34, 0]));
    incoming(
        &state,
        &encode(SerialMode::Terminal, &[0x14, 4, 0x2d, 0, 0x55]),
    );
    assert_eq!(terminal.recv().unwrap().data(), &[0x55]);

    let (mut basic, state) = mock(SerialMode::Basic);
    basic.send(&mut bridged()).unwrap();
    let inner = ipmb(REQUESTER, 0x14, 0x30, 1, 0x2d, &[0, 0x22]);
    let mut outer_body = vec![0, 0x41];
    outer_body.extend_from_slice(&inner);
    incoming(
        &state,
        &encode(
            SerialMode::Basic,
            &ipmb(REQUESTER, 0x1c, BMC, 1, 0x34, &outer_body),
        ),
    );
    assert_eq!(basic.recv().unwrap().data(), &[0x22]);
}

#[test]
fn cancellation_after_send_is_uncertain_and_late_response_is_ignored() {
    let (mut serial, state) = mock(SerialMode::Basic);
    serial.send(&mut request()).unwrap();
    serial.cancellation_token().cancel();
    assert!(matches!(serial.recv(), Err(SerialRecvError::Cancelled)));
    serial.cancellation_token().reset();
    serial.send(&mut request()).unwrap();
    incoming(&state, &response(SerialMode::Basic, 1, 0, &[9]));
    incoming(&state, &response(SerialMode::Basic, 2, 0, &[7]));
    assert_eq!(serial.recv().unwrap().data(), &[7]);
}
