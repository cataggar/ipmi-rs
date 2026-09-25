use std::collections::VecDeque;

use ipmi_rs::{
    connection::{IpmiConnection, Message, NetFn, Request, Response},
    storage::sdr::{RecordId, RecordParseError},
    Ipmi, IpmiError, SdrError, SdrProtocolError, SdrSource,
};

#[derive(Debug, PartialEq)]
enum MockError {
    Disconnected,
}

struct Step {
    netfn: NetFn,
    cmd: u8,
    request: Vec<u8>,
    reply: Result<(u8, Vec<u8>), MockError>,
}

impl Step {
    fn ok(netfn: NetFn, cmd: u8, request: Vec<u8>, reply: Vec<u8>) -> Self {
        Self {
            netfn,
            cmd,
            request,
            reply: Ok((0, reply)),
        }
    }

    fn completion(netfn: NetFn, cmd: u8, request: Vec<u8>, code: u8) -> Self {
        Self {
            netfn,
            cmd,
            request,
            reply: Ok((code, vec![])),
        }
    }

    fn lost(netfn: NetFn, cmd: u8, request: Vec<u8>) -> Self {
        Self {
            netfn,
            cmd,
            request,
            reply: Err(MockError::Disconnected),
        }
    }
}

struct MockConnection {
    steps: VecDeque<Step>,
}

impl MockConnection {
    fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: steps.into(),
        }
    }
}

impl IpmiConnection for MockConnection {
    type SendError = MockError;
    type RecvError = MockError;
    type Error = MockError;

    fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
        unreachable!()
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        unreachable!()
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let step = self.steps.pop_front().expect("unexpected SDR request");
        assert_eq!(
            (request.netfn(), request.cmd(), request.data()),
            (step.netfn, step.cmd, step.request.as_slice())
        );
        let (cc, data) = step.reply?;
        let mut reply = vec![cc];
        reply.extend_from_slice(&data);
        Ok(Response::new(Message::new_response(step.netfn, step.cmd, reply), 0).unwrap())
    }
}

fn source_wire(source: SdrSource) -> (NetFn, u8) {
    match source {
        SdrSource::Repository => (NetFn::Storage, 0x23),
        SdrSource::Device => (NetFn::SensorEvent, 0x21),
    }
}

fn device_id(repository: bool, device: bool) -> Step {
    let mut data = vec![0; 11];
    if repository {
        data[5] |= 0x02;
    }
    if device {
        data[1] |= 0x80;
    }
    Step::ok(NetFn::App, 0x01, vec![], data)
}

fn info(source: SdrSource, count: u16) -> Step {
    match source {
        SdrSource::Repository => {
            let mut data = vec![0; 14];
            data[0] = 0x51;
            data[1..3].copy_from_slice(&count.to_le_bytes());
            Step::ok(NetFn::Storage, 0x20, vec![], data)
        }
        SdrSource::Device => Step::ok(NetFn::SensorEvent, 0x20, vec![1], vec![count as u8, 1]),
    }
}

fn reserve(source: SdrSource, id: u16) -> Step {
    let (netfn, _) = source_wire(source);
    Step::ok(netfn, 0x22, vec![], id.to_le_bytes().to_vec())
}

fn request(reservation: u16, id: u16, offset: u8, length: u8) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&reservation.to_le_bytes());
    data.extend_from_slice(&id.to_le_bytes());
    data.extend_from_slice(&[offset, length]);
    data
}

fn read(
    source: SdrSource,
    reservation: u16,
    requested_id: u16,
    next_id: u16,
    offset: u8,
    data: &[u8],
) -> Step {
    let (netfn, cmd) = source_wire(source);
    let mut reply = next_id.to_le_bytes().to_vec();
    reply.extend_from_slice(data);
    Step::ok(
        netfn,
        cmd,
        request(reservation, requested_id, offset, data.len() as u8),
        reply,
    )
}

fn read_error(
    source: SdrSource,
    reservation: u16,
    id: u16,
    offset: u8,
    length: u8,
    cc: u8,
) -> Step {
    let (netfn, cmd) = source_wire(source);
    Step::completion(netfn, cmd, request(reservation, id, offset, length), cc)
}

fn header(id: u16, ty: u8, len: u8) -> [u8; 5] {
    let [lo, hi] = id.to_le_bytes();
    [lo, hi, 0x51, ty, len]
}

fn record(
    source: SdrSource,
    reservation: u16,
    requested: u16,
    actual: u16,
    next: u16,
    ty: u8,
    body: &[u8],
    chunk_size: usize,
) -> Vec<Step> {
    let mut steps = vec![read(
        source,
        reservation,
        requested,
        next,
        0,
        &header(actual, ty, body.len() as u8),
    )];
    let body_id = if requested == 0 { actual } else { requested };
    for (part, bytes) in body.chunks(chunk_size).enumerate() {
        let offset = u8::try_from(5 + part * chunk_size).unwrap();
        steps.push(read(source, reservation, body_id, next, offset, bytes));
    }
    steps
}

fn assert_done(ipmi: Ipmi<MockConnection>) {
    assert!(ipmi.release().steps.is_empty(), "fixture steps left unread");
}

#[test]
fn repository_only_long_record_is_fetched_in_bounded_chunks() {
    let body: Vec<u8> = (0..90).collect();
    let mut steps = vec![device_id(true, false), info(SdrSource::Repository, 1)];
    steps.push(reserve(SdrSource::Repository, 0x1234));
    steps.extend(record(
        SdrSource::Repository,
        0x1234,
        0,
        0x0010,
        0xffff,
        0x80,
        &body,
        32,
    ));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    let mut records = ipmi.sdrs_fallible();
    let record = records.next().unwrap().unwrap();
    assert_eq!(record.header.id, RecordId::new_raw(0x10));
    assert!(matches!(
        record.contents,
        ipmi_rs::storage::sdr::record::RecordContents::Unknown { ty: 0x80, data }
            if data == body
    ));
    assert!(records.next().is_none());
    assert_done(ipmi);
}

#[test]
fn maximum_length_record_finishes_with_an_eight_bit_offset() {
    let source = SdrSource::Repository;
    let body: Vec<u8> = (0..=254).collect();
    let mut steps = vec![info(source, 1), reserve(source, 1)];
    steps.extend(record(source, 1, 0, 0x42, 0xffff, 0x80, &body, 32));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    assert!(matches!(
        ipmi.sdrs_from(source).next(),
        Some(Ok(ipmi_rs::storage::sdr::Record {
            contents: ipmi_rs::storage::sdr::record::RecordContents::Unknown { data, .. },
            ..
        })) if data == body
    ));
    assert_done(ipmi);
}

#[test]
fn device_only_uses_sensor_event_for_info_reservation_and_reads() {
    let mut steps = vec![device_id(false, true), info(SdrSource::Device, 1)];
    steps.push(reserve(SdrSource::Device, 7));
    steps.extend(record(
        SdrSource::Device,
        7,
        0,
        9,
        0xffff,
        0x89,
        &[1, 2, 3],
        32,
    ));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    assert_eq!(
        ipmi.sdrs_fallible().next().unwrap().unwrap().header.id,
        RecordId::new_raw(9)
    );
    assert_done(ipmi);
}

#[test]
fn transfer_size_errors_shrink_read_limit_without_dropping_bytes() {
    let source = SdrSource::Repository;
    let body: Vec<u8> = (0..40).collect();
    let mut steps = vec![info(source, 1), reserve(source, 1)];
    steps.push(read(source, 1, 0, 0xffff, 0, &header(3, 0x80, 40)));
    steps.push(read_error(source, 1, 3, 5, 32, 0xca));
    steps.push(read(source, 1, 3, 0xffff, 5, &body[..16]));
    steps.push(read(source, 1, 3, 0xffff, 21, &body[16..32]));
    steps.push(read(source, 1, 3, 0xffff, 37, &body[32..]));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    let record = ipmi.sdrs_from(source).next().unwrap().unwrap();
    assert!(matches!(
        record.contents,
        ipmi_rs::storage::sdr::record::RecordContents::Unknown { data, .. } if data == body
    ));
    assert_done(ipmi);
}

#[test]
fn even_header_read_can_shrink_and_page() {
    let source = SdrSource::Device;
    let mut steps = vec![info(source, 1), reserve(source, 1)];
    steps.push(read_error(source, 1, 0, 0, 5, 0xca));
    steps.push(read(source, 1, 0, 0xffff, 0, &header(3, 0x80, 1)[..2]));
    steps.push(read(source, 1, 0, 0xffff, 2, &header(3, 0x80, 1)[2..4]));
    steps.push(read(source, 1, 0, 0xffff, 4, &header(3, 0x80, 1)[4..]));
    steps.push(read(source, 1, 3, 0xffff, 5, &[0x55]));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    assert!(ipmi.sdrs_from(source).next().unwrap().is_ok());
    assert_done(ipmi);
}

#[test]
fn cancellation_during_body_discards_partial_record_and_renews() {
    let source = SdrSource::Repository;
    let mut steps = vec![info(source, 1), reserve(source, 1)];
    steps.push(read(source, 1, 0, 0xffff, 0, &header(0x10, 0x80, 40)));
    steps.push(read(source, 1, 0x10, 0xffff, 5, &[0x11; 32]));
    steps.push(read_error(source, 1, 0x10, 37, 8, 0xc5));
    steps.push(reserve(source, 2));
    steps.extend(record(source, 2, 0, 0x11, 0xffff, 0x80, &[0x22; 40], 32));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    let record = ipmi.sdrs_from(source).next().unwrap().unwrap();
    assert_eq!(record.header.id, RecordId::new_raw(0x11));
    assert!(matches!(
        record.contents,
        ipmi_rs::storage::sdr::record::RecordContents::Unknown { data, .. }
            if data == [0x22; 40]
    ));
    assert_done(ipmi);
}

#[test]
fn mismatched_header_id_uses_requested_id_for_subsequent_reads() {
    let source = SdrSource::Device;
    let mut steps = vec![info(source, 2), reserve(source, 1)];
    steps.extend(record(source, 1, 0, 0x10, 0x20, 0x80, &[1], 32));
    steps.extend(record(source, 1, 0x20, 0x77, 0xffff, 0x80, &[2], 32));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    let ids: Vec<_> = ipmi
        .sdrs_from(source)
        .map(|r| r.unwrap().header.id.value())
        .collect();
    assert_eq!(ids, [0x10, 0x77]);
    assert_done(ipmi);
}

#[test]
fn malformed_truncated_or_inconsistent_chunks_are_errors_not_completion() {
    let source = SdrSource::Repository;
    let mut steps = vec![info(source, 1), reserve(source, 1)];
    let (netfn, cmd) = source_wire(source);
    steps.push(Step::ok(
        netfn,
        cmd,
        request(1, 0, 0, 5),
        vec![0xff, 0xff, 1, 0x51],
    ));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    let mut iter = ipmi.sdrs_from(source);
    assert!(matches!(
        iter.next(),
        Some(Err(SdrError::Protocol(
            SdrProtocolError::IncorrectChunkLength {
                offset: 0,
                expected: 5,
                actual: 2,
            }
        )))
    ));
    assert!(iter.next().is_none());
    assert_done(ipmi);

    let mut steps = vec![info(source, 1), reserve(source, 1)];
    steps.push(read(source, 1, 0, 0xffff, 0, &header(3, 0x80, 4)));
    steps.push(Step::ok(
        netfn,
        cmd,
        request(1, 3, 5, 4),
        vec![0xff, 0xff, 1, 2],
    ));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    assert!(matches!(
        ipmi.sdrs_from(source).next(),
        Some(Err(SdrError::Protocol(
            SdrProtocolError::IncorrectChunkLength { offset: 5, .. }
        )))
    ));
    assert_done(ipmi);

    let mut steps = vec![info(source, 1), reserve(source, 1)];
    steps.push(read(source, 1, 0, 0xffff, 0, &header(3, 0x80, 2)));
    steps.push(read(source, 1, 3, 9, 5, &[1, 2]));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    assert!(matches!(
        ipmi.sdrs_from(source).next(),
        Some(Err(SdrError::Protocol(SdrProtocolError::NextIdChanged {
            expected: RecordId::LAST,
            actual,
        }))) if actual == RecordId::new_raw(9)
    ));
    assert_done(ipmi);
}

#[test]
fn malformed_record_body_and_info_are_typed_parse_errors() {
    let source = SdrSource::Repository;
    let mut steps = vec![info(source, 1), reserve(source, 1)];
    steps.extend(record(source, 1, 0, 3, 0xffff, 0x01, &[1], 32));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    assert!(matches!(
        ipmi.sdrs_from(source).next(),
        Some(Err(SdrError::Parse {
            record_id: RecordId::FIRST,
            error: RecordParseError::NotEnoughData
        }))
    ));
    assert_done(ipmi);

    let mut ipmi = Ipmi::new(MockConnection::new(vec![Step::ok(
        NetFn::Storage,
        0x20,
        vec![],
        vec![0x51],
    )]));
    assert!(matches!(
        ipmi.sdrs_from(source).next(),
        Some(Err(SdrError::RepositoryInfo(IpmiError::Command { .. })))
    ));
    assert_done(ipmi);
}

#[test]
fn mid_iteration_transport_error_is_yielded_once_and_fused() {
    let source = SdrSource::Repository;
    let mut steps = vec![info(source, 2), reserve(source, 1)];
    steps.extend(record(source, 1, 0, 3, 4, 0x80, &[], 32));
    let (netfn, cmd) = source_wire(source);
    steps.push(Step::lost(netfn, cmd, request(1, 4, 0, 5)));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    let mut records = ipmi.sdrs_from(source);
    assert!(records.next().unwrap().is_ok());
    assert!(matches!(
        records.next(),
        Some(Err(SdrError::Read(IpmiError::Connection(
            MockError::Disconnected
        ))))
    ));
    assert!(records.next().is_none());
    assert_done(ipmi);
}

#[test]
fn repeated_reservation_loss_is_bounded_and_renewal_errors_surface() {
    let source = SdrSource::Device;
    let mut steps = vec![info(source, 1), reserve(source, 1)];
    for reservation in 1..=4 {
        steps.push(read_error(source, reservation, 0, 0, 5, 0xc5));
        if reservation < 4 {
            steps.push(reserve(source, reservation + 1));
        }
    }
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    assert!(matches!(
        ipmi.sdrs_from(source).next(),
        Some(Err(SdrError::ReservationLost(RecordId::FIRST)))
    ));
    assert_done(ipmi);

    let mut ipmi = Ipmi::new(MockConnection::new(vec![
        info(source, 1),
        reserve(source, 1),
        read_error(source, 1, 0, 0, 5, 0xc5),
        Step::ok(NetFn::SensorEvent, 0x22, vec![], vec![0, 0]),
    ]));
    assert!(matches!(
        ipmi.sdrs_from(source).next(),
        Some(Err(SdrError::Reservation(IpmiError::Command { .. })))
    ));
    assert_done(ipmi);
}

#[test]
fn empty_source_ends_normally_and_unsupported_source_is_an_error() {
    for source in [SdrSource::Repository, SdrSource::Device] {
        let mut ipmi = Ipmi::new(MockConnection::new(vec![info(source, 0)]));
        assert!(ipmi.sdrs_from(source).next().is_none());
        assert_done(ipmi);
    }
    let mut ipmi = Ipmi::new(MockConnection::new(vec![device_id(false, false)]));
    assert!(matches!(
        ipmi.sdrs_fallible().next(),
        Some(Err(SdrError::NoSupportedSource))
    ));
    assert_done(ipmi);
}

#[test]
fn repeated_next_id_is_not_an_infinite_loop_and_legacy_api_remains_available() {
    let source = SdrSource::Repository;
    let mut steps = vec![info(source, 1), reserve(source, 1)];
    steps.push(read(source, 1, 0, 0, 0, &header(3, 0x80, 0)));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    assert!(matches!(
        ipmi.sdrs_from(source).next(),
        Some(Err(SdrError::Protocol(SdrProtocolError::RepeatedRecordId(
            RecordId::FIRST
        ))))
    ));
    assert_done(ipmi);

    let mut steps = vec![info(source, 1), reserve(source, 1)];
    steps.extend(record(source, 1, 0, 3, 0xffff, 0x80, &[1], 32));
    let mut ipmi = Ipmi::new(MockConnection::new(steps));
    assert_eq!(ipmi.sdrs().count(), 1);
    assert_done(ipmi);
}
