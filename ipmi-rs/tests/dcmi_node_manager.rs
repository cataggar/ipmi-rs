use std::collections::VecDeque;

use ipmi_rs::{
    connection::{CompletionErrorCode, IpmiConnection, Message, NetFn, Request, Response},
    dcmi::{
        self, CapabilitySelector, DcmiError, GetCapabilities, GetPowerLimit, LimitAction,
        PowerLimit, SetPowerLimit,
    },
    node_manager::{NmDomain, NmTrigger, NodeManager},
    Ipmi, IpmiError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkError {
    Timeout,
}

struct Scripted {
    replies: VecDeque<Result<(u8, Vec<u8>), LinkError>>,
    sent: Vec<(u8, u8, Vec<u8>)>,
    response_netfn: Option<NetFn>,
}

impl Scripted {
    fn new(replies: impl IntoIterator<Item = Result<(u8, Vec<u8>), LinkError>>) -> Self {
        Self {
            replies: replies.into_iter().collect(),
            sent: Vec::new(),
            response_netfn: None,
        }
    }
}

impl IpmiConnection for Scripted {
    type SendError = LinkError;
    type RecvError = LinkError;
    type Error = LinkError;

    fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
        unreachable!("send_recv is a single request with no automatic resend")
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        unreachable!("send_recv handles its response")
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.sent
            .push((request.netfn_raw(), request.cmd(), request.data().to_vec()));
        let (cc, payload) = self.replies.pop_front().expect("unexpected retry")?;
        let mut response = vec![cc];
        response.extend(payload);
        Response::new(
            Message::new_response(
                self.response_netfn.unwrap_or(request.netfn()),
                request.cmd(),
                response,
            ),
            0,
        )
        .ok_or(LinkError::Timeout)
    }
}

#[test]
fn unsupported_controllers_and_completion_codes_are_not_decoded_as_success() {
    let mut ipmi = Ipmi::new(Scripted::new([Ok((0xc1, vec![]))]));
    assert!(matches!(
        ipmi.send_recv(GetCapabilities(CapabilitySelector::Platform)),
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::InvalidCommand,
            ..
        })
    ));
    assert_eq!(ipmi.inner_mut().sent.len(), 1);

    let nm = NodeManager::opt_in();
    let mut ipmi = Ipmi::new(Scripted::new([Ok((0xd4, vec![]))]));
    assert!(matches!(
        ipmi.send_recv(
            nm.capabilities(NmDomain::Platform, NmTrigger::Power)
                .unwrap()
        ),
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::InsufficientPrivilege,
            ..
        })
    ));
    assert_eq!(
        ipmi.inner_mut().sent,
        [(0x2e, 0xc9, vec![0x57, 1, 0, 0, 0x10])]
    );
}

#[test]
fn inactive_limit_completion_code_exposes_checked_readback() {
    let limit = vec![0xdc, 0, 0, 0, 0xc8, 0, 0xe8, 3, 0, 0, 0, 0, 10, 0];
    let mut ipmi = Ipmi::new(Scripted::new([Ok((0x80, limit))]));
    assert!(matches!(
        ipmi.send_recv(GetPowerLimit),
        Err(IpmiError::Command {
            error: DcmiError::InactiveLimit(PowerLimit { watts: 200, .. }),
            completion_code: Some(CompletionErrorCode::CommandSpecific(0x80)),
            ..
        })
    ));

    let mut ipmi = Ipmi::new(Scripted::new([Ok((0x80, vec![0xdc]))]));
    assert!(matches!(
        ipmi.send_recv(GetPowerLimit),
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::CommandSpecific(0x80),
            ..
        })
    ));
}

#[test]
fn uncertain_mutations_have_single_send_no_retry_and_no_read_modify_write() {
    let mut ipmi = Ipmi::new(Scripted::new([Err(LinkError::Timeout)]));
    let set = SetPowerLimit::new(PowerLimit {
        action: LimitAction::None,
        watts: 300,
        correction_ms: 1000,
        sample_seconds: 5,
    })
    .unwrap();
    assert!(matches!(
        ipmi.send_recv(set),
        Err(IpmiError::Connection(LinkError::Timeout))
    ));
    let sent = &ipmi.inner_mut().sent;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, 0x2c);
    assert_eq!(sent[0].1, 4);
}

#[test]
fn string_paging_fails_closed_on_inconsistent_or_short_pages() {
    let mut ipmi = Ipmi::new(Scripted::new([
        Ok((0, vec![0xdc, 17])),
        Ok((0, [vec![0xdc, 17], vec![b'a'; 16]].concat())),
        Ok((0, vec![0xdc, 18, b'b'])),
    ]));
    assert!(matches!(
        dcmi::read_string(dcmi::StringKind::AssetTag, |cmd| ipmi.send_recv(cmd)),
        Err(dcmi::PageError::Protocol(DcmiError::Page))
    ));
    let sent = &ipmi.inner_mut().sent;
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[0].2, [0xdc, 0, 0]);
    assert_eq!(sent[1].2, [0xdc, 0, 16]);
    assert_eq!(sent[2].2, [0xdc, 16, 1]);
}

#[test]
fn successful_oem_completion_still_requires_matching_vendor_header() {
    let nm = NodeManager::opt_in();
    let mut ipmi = Ipmi::new(Scripted::new([Ok((0, vec![0xdc, 1, 0, 3, 0, 0, 0, 0]))]));
    assert!(matches!(
        ipmi.send_recv(nm.discover()),
        Err(IpmiError::Command {
            error: ipmi_rs::node_manager::NmError::Vendor([0xdc, 1, 0]),
            ..
        })
    ));
    assert_eq!(ipmi.inner_mut().sent, [(0x2e, 0xca, vec![0x57, 1, 0])]);
}

#[test]
fn short_capability_pages_decode_by_original_request_selector() {
    let mut ipmi = Ipmi::new(Scripted::new([
        Ok((0, vec![0xdc, 1, 5, 2, 0x0f, 1, 0x03])),
        Ok((0, vec![0xdc, 1, 5, 2, 0x40, 0x21])),
    ]));
    let platform = ipmi
        .send_recv(GetCapabilities(CapabilitySelector::Platform))
        .unwrap();
    assert!(
        platform
            .platform(CapabilitySelector::Platform)
            .unwrap()
            .unwrap()
            .power_management
    );
    let optional = ipmi
        .send_recv(GetCapabilities(CapabilitySelector::OptionalAttributes))
        .unwrap();
    assert!(matches!(
        optional.decode(CapabilitySelector::OptionalAttributes),
        Ok(dcmi::CapabilityDetails::Optional(
            dcmi::OptionalAttributes {
                power_device_address: 0x40,
                channel: 2,
                device_revision: 1,
            }
        ))
    ));
    assert_eq!(ipmi.inner_mut().sent[0].2, [0xdc, 1]);
    assert_eq!(ipmi.inner_mut().sent[1].2, [0xdc, 3]);
}

#[test]
fn picmg_netfn_identity_checks_actual_response_pair() {
    let mut ipmi = Ipmi::new(Scripted::new([Ok((0, vec![0xdc, 1, 0, 1, 0, 0, 0, 0]))]));
    ipmi.inner_mut().response_netfn = Some(NetFn::Reserved(0x30));
    assert!(matches!(
        ipmi.send_recv(GetCapabilities(CapabilitySelector::Platform)),
        Err(IpmiError::UnexpectedResponse {
            netfn_sent: NetFn::Picmg,
            netfn_recvd: NetFn::Reserved(0x31),
            ..
        })
    ));
}
