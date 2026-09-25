use std::{cell::Cell, io, rc::Rc};

use crate::{
    connection::{
        Address, Channel, CompletionErrorCode, IpmiConnection, LogicalUnit, Message, NetFn,
        Request, RequestTargetAddress, Response,
    },
    sensor_event::{SetSensorThresholds, ThresholdError, ThresholdSetting},
    storage::sdr::record::{FullSensorRecord, ThresholdKind},
    Ipmi, IpmiError,
};

enum Reply {
    Timeout,
    Rejected,
}

struct Connection {
    attempts: Rc<Cell<usize>>,
    reply: Reply,
}

impl IpmiConnection for Connection {
    type SendError = io::Error;
    type RecvError = io::Error;
    type Error = io::Error;

    fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
        unreachable!("send_recv never sends separately")
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        unreachable!("send_recv never receives separately")
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        assert_eq!(request.cmd(), 0x26);
        assert_eq!(request.data(), [1, 1, 4, 0, 0, 0, 0, 0]);
        assert_eq!(
            request.target(),
            RequestTargetAddress::BmcOrIpmb(Address(0x20), Channel::Primary, LogicalUnit::Two)
        );
        self.attempts.set(self.attempts.get() + 1);
        match self.reply {
            Reply::Timeout => Err(io::Error::new(io::ErrorKind::TimedOut, "ambiguous timeout")),
            Reply::Rejected => Ok(Response::new(
                Message::new_response(NetFn::SensorEvent, 0x26, vec![0x80]),
                0,
            )
            .unwrap()),
        }
    }
}

fn fixture() -> FullSensorRecord {
    let mut data = [0u8; 43];
    data[0] = 0x20;
    data[1] = 2;
    data[2] = 1;
    data[6] = 0x08;
    data[8] = 1;
    data[14] = 1;
    FullSensorRecord::parse(&data).unwrap()
}

#[test]
fn threshold_write_is_not_retried_on_timeout_or_completion_error() {
    for reply in [Reply::Timeout, Reply::Rejected] {
        let attempts = Rc::new(Cell::new(0));
        let mut ipmi = Ipmi::new(Connection {
            attempts: attempts.clone(),
            reply,
        });
        let write = SetSensorThresholds::new(
            &fixture(),
            &[(ThresholdKind::LowerNonCritical, ThresholdSetting::Raw(4))],
        )
        .unwrap();
        match ipmi.send_recv(write) {
            Err(IpmiError::Connection(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            }
            Err(IpmiError::Command {
                error: ThresholdError::Rejected(CompletionErrorCode::CommandSpecific(0x80)),
                completion_code: Some(CompletionErrorCode::CommandSpecific(0x80)),
                ..
            }) => {}
            other => panic!("unexpected result: {other:?}"),
        }
        assert_eq!(attempts.get(), 1);
    }
}
