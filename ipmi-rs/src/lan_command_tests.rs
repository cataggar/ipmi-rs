use crate::{
    connection::{CompletionErrorCode, IpmiConnection, Message, NetFn, Request, Response},
    transport::{GetLanConfigParameters, LanConfigParameter, SetLanConfigParameters},
    Ipmi, IpmiError,
};

struct ReplyWithCode {
    code: u8,
    calls: usize,
}

impl IpmiConnection for ReplyWithCode {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;
    type Error = std::io::Error;

    fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
        unreachable!()
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        unreachable!()
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.calls += 1;
        Ok(Response::new(
            Message::new_response(NetFn::Transport, request.cmd(), vec![self.code]),
            0,
        )
        .unwrap())
    }
}

#[test]
fn lan_completion_error_fixtures_are_returned_without_retry_or_success_parsing() {
    for line in include_str!("../../ipmi-rs-core/src/transport/fixtures/lan_wire.txt")
        .lines()
        .filter_map(|line| line.strip_prefix("cc:"))
    {
        let fields: Vec<_> = line.split(':').collect();
        let hex = |index| u8::from_str_radix(fields[index], 16).unwrap();
        let mut ipmi = Ipmi::new(ReplyWithCode {
            code: hex(3),
            calls: 0,
        });
        let result = if hex(3) == 0x81 {
            ipmi.send_recv(SetLanConfigParameters::new(
                crate::connection::Channel::Current,
                LanConfigParameter::Other(hex(0)),
                vec![0],
            ))
            .map(|_| ())
        } else {
            ipmi.send_recv(
                GetLanConfigParameters::new(
                    crate::connection::Channel::Current,
                    LanConfigParameter::Other(hex(0)),
                )
                .with_set_selector(hex(1))
                .with_block_selector(hex(2)),
            )
            .map(|_| ())
        };
        assert!(matches!(
            result,
            Err(IpmiError::Failed {
                completion_code: CompletionErrorCode::CommandSpecific(0x80 | 0x81)
                    | CompletionErrorCode::ParameterOutOfRange,
                ..
            })
        ));
        assert_eq!(ipmi.release().calls, 1, "{line}");
    }
}
