use super::*;
use std::sync::{Arc, Mutex};

use crate::{
    chassis::GetChassisStatus,
    connection::{IpmiConnection, LogicalUnit, NetFn},
    Ipmi, IpmiError,
};

#[derive(Default)]
struct MockState {
    calls: Vec<(u8, u8, Vec<u8>)>,
    identity: Option<[u8; 10]>,
    replies: Vec<Vec<u8>>,
}

struct MockSg(Arc<Mutex<MockState>>);

impl ScsiDevice for MockSg {
    fn exchange(
        &mut self,
        cdb: [u8; 10],
        direction: Direction,
        data: &mut [u8],
        _: Duration,
    ) -> io::Result<usize> {
        let mut state = self.0.lock().unwrap();
        if cdb[0] == 0xEE {
            data.copy_from_slice(&state.identity.unwrap_or(*b"$$$AMI$$$\0"));
            return Ok(data.len());
        }
        assert_eq!(&cdb[7..9], &[0, 1]);
        match direction {
            Direction::Write => {
                assert_eq!(cdb[0], 0xE2);
                state.calls.push((cdb[0], cdb[5], data.to_vec()));
            }
            Direction::Read => {
                assert_eq!(cdb[0], 0xE3);
                state.calls.push((cdb[0], cdb[5], vec![]));
                let bytes = state.replies.remove(0);
                assert_eq!(bytes.len(), data.len());
                data.copy_from_slice(&bytes);
            }
        }
        Ok(data.len())
    }
}

fn mock() -> (AmiUsb, Arc<Mutex<MockState>>) {
    let state = Arc::new(Mutex::new(MockState::default()));
    let usb =
        AmiUsb::with_device(Box::new(MockSg(state.clone())), Duration::from_millis(50)).unwrap();
    (usb, state)
}

fn complete(status: u16, length: u32) -> Vec<u8> {
    let mut header = AmiUsb::header(0);
    header[18..20].copy_from_slice(&status.to_le_bytes());
    header[24..28].copy_from_slice(&length.to_le_bytes());
    header.to_vec()
}

fn req() -> Request {
    Request::new(
        Message::new_request(NetFn::Chassis, 1, vec![0xa0]),
        RequestTargetAddress::Bmc(LogicalUnit::Two),
    )
}

#[test]
fn identifies_only_supported_ami_devices() {
    let (usb, _) = mock();
    assert!(!usb.cancellation_token().is_cancelled());
    let state = Arc::new(Mutex::new(MockState {
        identity: Some(*b"UNKNOWN\0\0\0"),
        ..Default::default()
    }));
    assert!(matches!(
        AmiUsb::with_device(Box::new(MockSg(state)), Duration::from_secs(1)),
        Err(AmiUsbError::UnsupportedDevice)
    ));
}

#[test]
fn request_header_status_polling_response_and_completion_code() {
    let (mut usb, state) = mock();
    state.lock().unwrap().replies = vec![
        complete(0x8000, 256),
        complete(0, 5),
        vec![0, 1, 0, 0, 0],
        complete(0, 2),
        vec![0xC1, 0x32],
    ];
    let response = usb.send_recv(&mut req()).unwrap();
    assert_eq!(response.netfn(), NetFn::Chassis);
    assert_eq!(
        (response.cmd(), response.cc(), response.data()),
        (1, 0, &[1, 0, 0, 0][..])
    );
    let calls = state.lock().unwrap().calls.clone();
    assert_eq!((calls[0].0, calls[0].1), (0xE2, 1));
    assert_eq!(calls[0].2.len(), HEADER_LEN);
    assert_eq!(&calls[0].2[..16], SIGNATURE);
    assert_eq!(&calls[0].2[20..28], &[3, 0, 0, 0, 0, 1, 0, 0]);
    assert_eq!(calls[1], (0xE2, 2, vec![2, 1, 0xA0]));
    assert_eq!(usb.send_recv(&mut req()).unwrap().cc(), 0xc1);
}

#[test]
fn typed_core_commands_and_error_codes() {
    let (usb, state) = mock();
    let mut ipmi = Ipmi::new(usb);
    state.lock().unwrap().replies = vec![complete(0, 4), vec![0, 1, 0, 0]];
    assert!(ipmi.send_recv(GetChassisStatus).unwrap().system_power_on);
    state.lock().unwrap().replies = vec![complete(0, 1), vec![0xC1]];
    assert!(matches!(
        ipmi.send_recv(GetChassisStatus),
        Err(IpmiError::Failed { .. })
    ));
}

#[test]
fn invalid_status_and_oversize_poison_connection() {
    for header in [complete(3, 1), complete(0, 257)] {
        let (mut usb, state) = mock();
        state.lock().unwrap().replies = vec![header];
        let result = usb.send_recv(&mut req());
        assert!(matches!(result, Err(AmiUsbError::OutcomeUnknown(_))));
        assert!(matches!(
            usb.send(&mut req()),
            Err(AmiUsbError::ConnectionUncertain)
        ));
    }
}

#[test]
fn preflight_cancel_unsupported_target_and_invalid_data_do_not_dispatch() {
    let (mut usb, state) = mock();
    usb.cancellation_token().cancel();
    assert!(matches!(usb.send(&mut req()), Err(AmiUsbError::Cancelled)));
    usb.cancellation_token().reset();
    let mut unsupported = Request::new(
        Message::new_request(NetFn::Chassis, 1, vec![]),
        RequestTargetAddress::BmcOrIpmb(
            crate::connection::Address(0x30),
            crate::connection::Channel::Primary,
            LogicalUnit::Zero,
        ),
    );
    assert!(matches!(
        usb.send(&mut unsupported),
        Err(AmiUsbError::InvalidRequest)
    ));
    let mut huge = Request::new(
        Message::new_request(NetFn::Chassis, 1, vec![0; 256]),
        RequestTargetAddress::Bmc(LogicalUnit::Zero),
    );
    assert!(matches!(
        usb.send(&mut huge),
        Err(AmiUsbError::RequestTooLong)
    ));
    assert!(state.lock().unwrap().calls.is_empty());
}

#[test]
fn missing_response_is_bounded_and_uncertain() {
    let (mut usb, state) = mock();
    state.lock().unwrap().replies = vec![complete(0x8000, 256); 32];
    usb.timeout = Duration::from_millis(1);
    assert!(matches!(
        usb.send_recv(&mut req()),
        Err(AmiUsbError::OutcomeUnknown(error))
        if matches!(*error, AmiUsbError::Timeout)
    ));
}

#[test]
fn cancellation_after_dispatch_poisoned_until_reopened() {
    let (mut usb, state) = mock();
    usb.send(&mut req()).unwrap();
    usb.cancellation_token().cancel();
    assert!(matches!(
        usb.recv(),
        Err(AmiUsbError::OutcomeUnknown(error))
        if matches!(*error, AmiUsbError::Cancelled)
    ));
    usb.cancellation_token().reset();
    assert!(matches!(
        usb.send(&mut req()),
        Err(AmiUsbError::ConnectionUncertain)
    ));
    assert_eq!(state.lock().unwrap().calls.len(), 2);
}
