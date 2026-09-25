#![cfg(feature = "group-extensions")]

use ipmi_rs::{
    connection::{
        IpmiConnection, LogicalUnit, Message, NetFn, Request, RequestTargetAddress, Response,
    },
    picmg, vita, Ipmi, IpmiError,
};

#[derive(Debug, PartialEq)]
struct TransportError;

struct Mock {
    reply: Option<Vec<u8>>,
    sends: usize,
    response_netfn: NetFn,
}
impl IpmiConnection for Mock {
    type SendError = TransportError;
    type RecvError = TransportError;
    type Error = TransportError;

    fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
        unreachable!()
    }
    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        unreachable!()
    }
    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.sends += 1;
        assert_eq!(request.netfn_raw(), 0x2c);
        assert_eq!(
            request.target(),
            RequestTargetAddress::Bmc(LogicalUnit::Zero)
        );
        Ok(Response::new(
            Message::new_response(
                self.response_netfn,
                request.cmd(),
                self.reply.take().ok_or(TransportError)?,
            ),
            1,
        )
        .unwrap())
    }
}

#[test]
fn extension_replies_and_errors_traverse_public_ipmi_api() {
    let mut ipmi = Ipmi::new(Mock {
        reply: Some(vec![0, 3, 0x21, 0x10, 0, 0x21, 15, 2]),
        sends: 0,
        response_netfn: NetFn::Reserved(0x2c),
    });
    let caps = ipmi.send_recv(vita::GetVitaCapabilities).unwrap();
    assert_eq!(caps.require_supported().unwrap().fru_id, 2);
    assert_eq!(ipmi.inner_mut().sends, 1);

    ipmi.inner_mut().response_netfn = NetFn::Reserved(0x30);
    ipmi.inner_mut().reply = Some(vec![0, 0, 3]);
    assert!(matches!(
        ipmi.send_recv(picmg::GetPicmgPolicy { fru_id: 2 }),
        Err(IpmiError::UnexpectedResponse {
            netfn_sent: NetFn::Reserved(0x2c),
            netfn_recvd: NetFn::Reserved(0x31),
            ..
        })
    ));
    ipmi.inner_mut().response_netfn = NetFn::Reserved(0x2c);

    ipmi.inner_mut().reply = Some(vec![0, 0]);
    assert!(matches!(
        ipmi.send_recv(picmg::GetPicmgPolicy { fru_id: 2 }),
        Err(IpmiError::Command {
            error: picmg::GroupError::InvalidLength { .. },
            ..
        })
    ));
    ipmi.inner_mut().reply = Some(vec![0, 3]);
    assert!(matches!(
        ipmi.send_recv(picmg::GetPicmgPolicy { fru_id: 2 }),
        Err(IpmiError::Command {
            error: picmg::GroupError::WrongExtension { .. },
            ..
        })
    ));
    ipmi.inner_mut().reply = Some(vec![0xc1, 3]);
    assert!(matches!(
        ipmi.send_recv(vita::GetVitaCapabilities),
        Err(IpmiError::Command {
            error: vita::GroupError::UnsupportedOperation,
            ..
        })
    ));
    ipmi.inner_mut().reply = Some(vec![0xcc, 3]);
    assert!(matches!(
        ipmi.send_recv(vita::GetVitaCapabilities),
        Err(IpmiError::Failed { .. })
    ));
}

#[test]
fn an_ambiguous_activation_result_is_not_retried() {
    let mut ipmi = Ipmi::new(Mock {
        reply: None,
        sends: 0,
        response_netfn: NetFn::Reserved(0x2c),
    });
    assert!(matches!(
        ipmi.send_recv(picmg::SetPicmgActivation {
            fru_id: 2,
            action: picmg::Activation::Deactivate,
        }),
        Err(IpmiError::Connection(TransportError))
    ));
    assert_eq!(ipmi.inner_mut().sends, 1);
}

#[test]
fn fru_control_with_trailing_ack_data_is_not_reported_as_failed_or_retried() {
    let mut ipmi = Ipmi::new(Mock {
        reply: Some(vec![0, 0, 0x01, 0x44]),
        sends: 0,
        response_netfn: NetFn::Reserved(0x2c),
    });
    assert_eq!(
        ipmi.send_recv(picmg::PicmgFruControl {
            fru_id: 2,
            action: picmg::FruControl::WarmReset,
        }),
        Ok(picmg::FruControlAcknowledgement {
            optional_bytes: vec![0x01, 0x44]
        })
    );
    assert_eq!(ipmi.inner_mut().sends, 1);

    ipmi.inner_mut().reply = Some(vec![0, 3, 0x01]);
    assert!(matches!(
        ipmi.send_recv(picmg::PicmgFruControl {
            fru_id: 2,
            action: picmg::FruControl::WarmReset,
        }),
        Err(IpmiError::Command {
            error: picmg::GroupError::WrongExtension { .. },
            ..
        })
    ));
    assert_eq!(ipmi.inner_mut().sends, 2);
}
