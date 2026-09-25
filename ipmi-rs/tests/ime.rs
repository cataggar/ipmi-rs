use std::collections::VecDeque;

use ipmi_rs::{
    connection::{
        Address, Channel, IpmiConnection, LogicalUnit, Message, NetFn, Request,
        RequestTargetAddress, Response,
    },
    oem::{
        ime::{
            Capabilities, GetCapabilities, GetStatus, ImageError, ImageType, ImeTarget,
            ResponseError, Stage, Status, UpdateState, ValidatedImage, WorkflowError,
        },
        OemCommand, OemError,
    },
    Ipmi,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    Timeout,
}

#[derive(Debug, Clone, PartialEq)]
struct Sent {
    netfn: u8,
    cmd: u8,
    data: Vec<u8>,
    target: RequestTargetAddress,
}

#[derive(Clone)]
struct Exchange {
    sent: Sent,
    result: Result<Response, Fault>,
}

#[derive(Default)]
struct Mock {
    steps: VecDeque<Exchange>,
    sent: Vec<Sent>,
}

impl Mock {
    fn add(&mut self, netfn: u8, cmd: u8, payload: &[u8], data: &[u8]) {
        self.add_reply(netfn, cmd, payload, 0, data);
    }

    fn add_reply(&mut self, netfn: u8, cmd: u8, payload: &[u8], cc: u8, data: &[u8]) {
        let mut body = vec![cc];
        body.extend_from_slice(data);
        self.steps.push_back(Exchange {
            sent: sent(netfn, cmd, payload),
            result: Ok(
                Response::new(Message::new_response(NetFn::from(netfn), cmd, body), 0).unwrap(),
            ),
        });
    }

    fn identity(&mut self, id: &[u8]) {
        self.add(0x06, 0x01, &[], id);
    }

    fn status(&mut self, id: &[u8], state: u8, image: u8, space: u32) {
        self.identity(id);
        let mut data = vec![image, state, 0, 0, 0, 0];
        data.extend_from_slice(&space.to_le_bytes());
        self.add(0x30, 0xA6, &[], &data);
    }

    fn caps(&mut self, id: &[u8], area: u8, special: u8) {
        self.identity(id);
        self.add(0x30, 0xA7, &[], &[area, special]);
    }

    fn mutation(&mut self, id: &[u8], cmd: u8, payload: &[u8]) {
        self.identity(id);
        self.add(0x30, cmd, payload, &[]);
    }

    fn inventory(&mut self, id: &[u8], state: u8, image: u8, area: u8, special: u8) {
        self.identity(id);
        self.status(id, state, image, 0x123456);
        self.caps(id, area, special);
    }
}

impl IpmiConnection for Mock {
    type SendError = Fault;
    type RecvError = Fault;
    type Error = Fault;

    fn send(&mut self, _: &mut Request) -> Result<(), Fault> {
        panic!("IME must use one correlated send_recv per request")
    }

    fn recv(&mut self) -> Result<Response, Fault> {
        panic!("IME must use one correlated send_recv per request")
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Fault> {
        let actual = Sent {
            netfn: request.netfn_raw(),
            cmd: request.cmd(),
            data: request.data().to_vec(),
            target: request.target(),
        };
        let exchange = self.steps.pop_front().expect("unexpected packet/replay");
        assert_eq!(actual, exchange.sent, "wrong payload, destination or order");
        self.sent.push(actual);
        exchange.result
    }
}

fn target() -> ImeTarget {
    ImeTarget::new(Address(0x88), Channel::new(8).unwrap()).unwrap()
}

fn sent(netfn: u8, cmd: u8, data: &[u8]) -> Sent {
    Sent {
        netfn,
        cmd,
        data: data.to_vec(),
        target: RequestTargetAddress::BmcOrIpmb(
            Address(0x88),
            Channel::new(8).unwrap(),
            LogicalUnit::Zero,
        ),
    }
}

fn me_id() -> Vec<u8> {
    // Source ipmi_ime.c: device/revision 0, IANA 0x000157, product 0x0B00,
    // SPS version in aux[0], image selector in aux[3].
    vec![
        0x00, 0x00, 0x02, 0x51, 0x51, 0x00, 0x57, 0x01, 0x00, 0x00, 0x0B, 0x12, 0x34, 0x56, 0x01,
    ]
}

fn image() -> ValidatedImage {
    // 23 bytes split into 22 + 1. CRC-8 reference vector "123456789" = F4.
    let bytes = vec![0xA5; 23];
    ValidatedImage::new(bytes.clone(), 23, crc8(&bytes)).unwrap()
}

fn crc8(data: &[u8]) -> u8 {
    data.iter().fold(0, |mut crc, &b| {
        crc ^= b;
        for _ in 0..8 {
            crc = if crc & 0x80 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ 7
            };
        }
        crc
    })
}

fn update_script() -> (Mock, ValidatedImage) {
    let image = image();
    let id = me_id();
    let mut mock = Mock::default();
    mock.inventory(&id, 0, 0x04, 0x02, 0x03);
    mock.mutation(&id, 0xA0, &[]);
    mock.status(&id, 1, 0x04, 0x123456);
    mock.mutation(&id, 0xA1, &[1, 0]);
    mock.status(&id, 2, 0x04, 0x123456);
    mock.mutation(&id, 0xA2, &[&[0][..], &[0xA5; 22][..]].concat());
    mock.status(&id, 2, 0x04, 0x123456);
    mock.mutation(&id, 0xA2, &[1, 0xA5]);
    mock.status(&id, 2, 0x04, 0x123456);
    let mut close = image.len().to_le_bytes().to_vec();
    close.extend_from_slice(&[image.crc8(), 0]);
    mock.mutation(&id, 0xA3, &close);
    mock.status(&id, 1, 0x06, 0x123456);
    mock.mutation(&id, 0xA4, &[1, 0]);
    mock.status(&id, 3, 0x06, 0x123456);
    (mock, image)
}

fn rollback_script() -> Mock {
    let id = me_id();
    let mut mock = Mock::default();
    mock.inventory(&id, 0, 0x04, 0x02, 0x03);
    mock.mutation(&id, 0xA4, &[3, 0]);
    mock.status(&id, 5, 0x04, 0x123456);
    mock
}

#[test]
fn source_derived_inventory_fixtures_decode_versions_states_and_capabilities() {
    let id = me_id();
    let mut mock = Mock::default();
    mock.inventory(&id, 0, 0x14, 0x0E, 0x03);
    let mut ipmi = Ipmi::new(mock);
    let info = ipmi.ime_info(target()).unwrap();
    assert_eq!(info.version.major, 2);
    assert_eq!(info.version.minor_digits, [5, 1]);
    assert_eq!(info.version.build_digits, [3, 4, 5, 6]);
    assert_eq!(info.version.command_digits, [1, 2]);
    assert_eq!(info.version.image_type, ImageType::Operational1);
    assert_eq!(info.status.update_state, UpdateState::Idle);
    assert_eq!(info.status.running_area(), 2);
    assert_eq!(info.status.free_area_size, 0x123456);
    assert!(info.status.rollback_image_valid());
    assert!(info.capabilities.operational_area());
    assert!(info.capabilities.pia_area());
    assert!(info.capabilities.sdr_area());
    assert!(info.capabilities.recovery());
    assert!(info.capabilities.rollback());
    let mock = ipmi.release();
    assert!(mock.steps.is_empty());
    assert_eq!(mock.sent.len(), 5);
    assert!(mock
        .sent
        .iter()
        .all(|packet| packet.target == sent(0, 0, &[]).target));

    assert_eq!(
        Status::from_bytes(&[0, 0, 0, 0, 0, 0, 1, 2, 3, 4])
            .unwrap()
            .free_area_size,
        0x04030201
    );
    assert_eq!(
        Status::from_bytes(&[0x04, 5, 0, 0, 0, 0, 0, 3, 0, 1, 2, 3, 4])
            .unwrap()
            .update_state,
        UpdateState::RolledBack
    );
    assert_eq!(
        Capabilities::from_bytes(&[2, 3]),
        Ok(Capabilities {
            area_supported: 2,
            special_caps: 3
        })
    );
}

#[test]
fn malformed_responses_and_wrong_identity_never_send_a_mutation() {
    for id_byte in [0, 1, 6, 7, 9, 10] {
        let mut id = me_id();
        id[id_byte] ^= 1;
        let mut mock = Mock::default();
        mock.identity(&id);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.ime_rollback(target()),
            Err(WorkflowError::Read {
                stage: Stage::Identity,
                error: OemError::UnsupportedDevice { .. },
            })
        ));
        assert_eq!(ipmi.release().sent, [sent(0x06, 0x01, &[])]);
    }
    let mut wrong_product = me_id();
    wrong_product[10] ^= 1;
    let mut mock = Mock::default();
    mock.identity(&wrong_product);
    let mut ipmi = Ipmi::new(mock);
    let image = image();
    assert!(matches!(
        ipmi.ime_update(target(), &image),
        Err(WorkflowError::Read {
            stage: Stage::Identity,
            error: OemError::UnsupportedDevice { .. }
        })
    ));
    assert_eq!(ipmi.release().sent, [sent(0x06, 0x01, &[])]);
    let mut id = me_id();
    id.pop();
    let mut mock = Mock::default();
    mock.identity(&id);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.ime_info(target()),
        Err(WorkflowError::MissingVersion)
    ));
    assert_eq!(ipmi.release().sent.len(), 1);

    assert!(ImeTarget::new(Address(0), Channel::new(8).unwrap()).is_none());
    assert!(ImeTarget::new(Address(0x89), Channel::new(8).unwrap()).is_none());
    assert!(ImeTarget::new(Address(0x88), Channel::Primary).is_none());

    for bad in [&[][..], &[0; 9], &[0; 11], &[0; 14]] {
        assert!(matches!(
            GetStatus::parse_success_response(bad),
            Err(ResponseError::InvalidLength(_))
        ));
    }
    assert_eq!(
        Status::from_bytes(&[0, 8, 0, 0, 0, 0, 0, 0, 0, 0]),
        Err(ResponseError::UnknownState(8))
    );
    assert_eq!(
        Status::from_bytes(&[0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        Err(ResponseError::InvalidWideState)
    );
    assert_eq!(
        GetCapabilities::parse_success_response(&[2]),
        Err(ResponseError::InvalidLength(1))
    );
    assert_eq!(
        GetCapabilities::parse_success_response(&[2, 3, 4]),
        Err(ResponseError::InvalidLength(3))
    );
}

#[test]
fn update_requires_independently_validated_size_and_crc_then_sends_exact_wire_sequence() {
    assert_eq!(
        ValidatedImage::new(b"123456789".to_vec(), 9, 0xF4)
            .unwrap()
            .crc8(),
        0xF4
    );
    assert!(matches!(
        ValidatedImage::new(vec![], 0, 0),
        Err(ImageError::InvalidSize(0))
    ));
    assert!(matches!(
        ValidatedImage::new(vec![1, 2], 3, 0),
        Err(ImageError::SizeMismatch { .. })
    ));
    assert!(matches!(
        ValidatedImage::new(vec![1, 2], 2, 0),
        Err(ImageError::CrcMismatch { .. })
    ));
    let (mock, image) = update_script();
    let mut ipmi = Ipmi::new(mock);
    assert_eq!(
        ipmi.ime_update(target(), &image).unwrap().update_state,
        UpdateState::Success
    );
    let mock = ipmi.release();
    assert!(mock.steps.is_empty());
    let writes: Vec<_> = mock
        .sent
        .iter()
        .filter(|packet| packet.cmd == 0xA2)
        .collect();
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0].data.len(), 23);
    assert_eq!(writes[1].data, [1, 0xA5]);
    assert_eq!(
        mock.sent.iter().filter(|packet| packet.cmd == 0xA4).count(),
        1
    );
}

#[test]
fn changed_identity_between_steps_prevents_dispatch_even_after_prepare() {
    let (mut mock, image) = update_script();
    let open = mock
        .steps
        .iter()
        .position(|step| step.sent.cmd == 0xA1)
        .unwrap();
    let mut wrong_id = me_id();
    wrong_id[10] ^= 1;
    let check = mock.steps.get_mut(open - 1).unwrap();
    check.result = Ok(Response::new(
        Message::new_response(NetFn::App, 0x01, [&[0], wrong_id.as_slice()].concat()),
        0,
    )
    .unwrap());
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.ime_update(target(), &image),
        Err(WorkflowError::NotSent {
            stage: Stage::Open,
            error: OemError::UnsupportedDevice { .. }
        })
    ));
    assert_eq!(ipmi.release().sent.len(), open);
}

#[test]
fn restart_completion_code_does_not_trigger_ambiguous_chunk_replay() {
    let (mut mock, image) = update_script();
    let first_write = mock
        .steps
        .iter()
        .position(|step| step.sent.cmd == 0xA2)
        .unwrap();
    mock.steps.get_mut(first_write).unwrap().result = Ok(Response::new(
        Message::new_response(NetFn::Reserved(0x30), 0xA2, vec![0x80]),
        0,
    )
    .unwrap());
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.ime_update(target(), &image),
        Err(WorkflowError::OutcomeUnknown {
            stage: Stage::Write(0),
            ..
        })
    ));
    let mock = ipmi.release();
    assert_eq!(mock.sent.len(), first_write + 1);
    assert_eq!(
        mock.sent.iter().filter(|packet| packet.cmd == 0xA2).count(),
        1
    );
}

#[test]
fn rollback_requires_valid_image_and_advertised_capability() {
    let mut ipmi = Ipmi::new(rollback_script());
    assert_eq!(
        ipmi.ime_rollback(target()).unwrap().update_state,
        UpdateState::RolledBack
    );
    assert!(ipmi.release().steps.is_empty());
    for (image, cap, expected) in [(0, 3, 0), (4, 0, 1)] {
        let id = me_id();
        let mut mock = Mock::default();
        mock.inventory(&id, 0, image, 2, cap);
        let mut ipmi = Ipmi::new(mock);
        let result = ipmi.ime_rollback(target());
        if expected == 0 {
            assert!(matches!(result, Err(WorkflowError::InvalidImageStatus)));
        } else {
            assert!(matches!(result, Err(WorkflowError::UnsupportedCapability)));
        }
        assert_eq!(ipmi.release().sent.len(), 5);
    }
}

#[test]
fn failures_at_every_update_transition_stop_without_replaying_a_packet() {
    let (template, image) = update_script();
    let count = template.steps.len();
    for failed in 0..count {
        let mut mock = Mock {
            steps: template.steps.clone(),
            sent: Vec::new(),
        };
        let step = mock.steps.get_mut(failed).unwrap();
        let is_mutation = step.sent.netfn == 0x30 && matches!(step.sent.cmd, 0xA0..=0xA4);
        step.result = Err(Fault::Timeout);
        let mut ipmi = Ipmi::new(mock);
        let result = ipmi.ime_update(target(), &image);
        if is_mutation {
            assert!(
                matches!(result, Err(WorkflowError::OutcomeUnknown { .. })),
                "mutation response {failed}: {result:?}"
            );
        } else {
            assert!(
                matches!(
                    result,
                    Err(WorkflowError::Read { .. }) | Err(WorkflowError::NotSent { .. })
                ),
                "read response {failed}: {result:?}"
            );
        }
        let mock = ipmi.release();
        assert_eq!(mock.sent.len(), failed + 1, "must stop at first fault");
        assert_eq!(mock.steps.len(), count - failed - 1);
    }
}

#[test]
fn failures_at_every_rollback_transition_stop_without_replaying() {
    let template = rollback_script();
    let count = template.steps.len();
    for failed in 0..count {
        let mut mock = Mock {
            steps: template.steps.clone(),
            sent: Vec::new(),
        };
        let step = mock.steps.get_mut(failed).unwrap();
        let is_mutation = step.sent.cmd == 0xA4;
        step.result = Err(Fault::Timeout);
        let mut ipmi = Ipmi::new(mock);
        let result = ipmi.ime_rollback(target());
        if is_mutation {
            assert!(matches!(
                result,
                Err(WorkflowError::OutcomeUnknown {
                    stage: Stage::Rollback,
                    ..
                })
            ));
        } else {
            assert!(matches!(
                result,
                Err(WorkflowError::Read { .. }) | Err(WorkflowError::NotSent { .. })
            ));
        }
        assert_eq!(ipmi.release().sent.len(), failed + 1);
    }
}

#[test]
fn post_action_wrong_state_or_missing_staging_image_prevents_following_write() {
    let (template, image) = update_script();
    for (cmd, wrong_state) in [(0xA0, 2), (0xA1, 1), (0xA2, 4), (0xA3, 2), (0xA4, 4)] {
        let mut mock = Mock {
            steps: template.steps.clone(),
            sent: Vec::new(),
        };
        let action = mock
            .steps
            .iter()
            .position(|step| step.sent.cmd == cmd)
            .unwrap();
        let status = action + 2; // Identity lookup before every status.
        let next = mock.steps.get_mut(status).unwrap();
        assert_eq!(next.sent.cmd, 0xA6);
        let mut response = next.result.clone().unwrap();
        let mut payload = response.data().to_vec();
        payload[1] = wrong_state;
        response = Response::new(
            Message::new_response(
                NetFn::Reserved(0x30),
                0xA6,
                [&[0], payload.as_slice()].concat(),
            ),
            0,
        )
        .unwrap();
        next.result = Ok(response);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.ime_update(target(), &image),
            Err(WorkflowError::UnexpectedState { .. })
        ));
        assert_eq!(ipmi.release().sent.len(), status + 1);
    }
    let (mut mock, image) = update_script();
    let close = mock
        .steps
        .iter()
        .position(|step| step.sent.cmd == 0xA3)
        .unwrap();
    let next = mock.steps.get_mut(close + 2).unwrap();
    next.result = Ok(Response::new(
        Message::new_response(
            NetFn::Reserved(0x30),
            0xA6,
            vec![0, 0x04, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        0,
    )
    .unwrap());
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.ime_update(target(), &image),
        Err(WorkflowError::InvalidImageStatus)
    ));
    assert_eq!(ipmi.release().sent.len(), close + 3);
}

#[test]
fn bad_preflight_cannot_prepare_or_rollback() {
    let (mut mock, image) = update_script();
    mock.steps.get_mut(4).unwrap().result = Ok(Response::new(
        Message::new_response(NetFn::Reserved(0x30), 0xA7, vec![0, 0, 3]),
        0,
    )
    .unwrap());
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.ime_update(target(), &image),
        Err(WorkflowError::UnsupportedCapability)
    ));
    assert_eq!(ipmi.release().sent.len(), 5);

    let id = me_id();
    let mut mock = Mock::default();
    mock.inventory(&id, 1, 0x04, 0x02, 0x03);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.ime_update(target(), &image),
        Err(WorkflowError::UnexpectedState { .. })
    ));
    assert_eq!(ipmi.release().sent.len(), 5);
}
