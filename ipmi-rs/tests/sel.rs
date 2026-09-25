use std::{collections::VecDeque, num::NonZeroU16};

use ipmi_rs::{
    connection::{IpmiConnection, Message, NetFn, Request, Response},
    storage::{
        sel::{
            AddSelEntry, AddSelEntryError, DeleteSelEntry, DeleteSelEntryError, Entry, GetSelTime,
            ParseEntryError, RecordId, SelEntryInfo, SelTimeResponseError, SetSelTime,
        },
        Timestamp,
    },
    Ipmi, IpmiError, SelIterError, SelMutationError,
};

#[derive(Debug, PartialEq)]
struct FixtureError;

struct Step {
    cmd: u8,
    request: Vec<u8>,
    response: Result<(u8, Vec<u8>), FixtureError>,
}

impl Step {
    fn ok(cmd: u8, request: &[u8], data: &[u8]) -> Self {
        Self {
            cmd,
            request: request.to_vec(),
            response: Ok((0, data.to_vec())),
        }
    }

    fn cc(cmd: u8, request: &[u8], code: u8) -> Self {
        Self {
            cmd,
            request: request.to_vec(),
            response: Ok((code, Vec::new())),
        }
    }

    fn lost(cmd: u8, request: &[u8]) -> Self {
        Self {
            cmd,
            request: request.to_vec(),
            response: Err(FixtureError),
        }
    }
}

struct Fixture(VecDeque<Step>);

impl Fixture {
    fn new(steps: Vec<Step>) -> Self {
        Self(steps.into())
    }

    fn exhausted(&self) {
        assert!(
            self.0.is_empty(),
            "{} expected commands not sent",
            self.0.len()
        );
    }
}

impl IpmiConnection for Fixture {
    type SendError = FixtureError;
    type RecvError = FixtureError;
    type Error = FixtureError;

    fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
        unreachable!()
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        unreachable!()
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let step = self.0.pop_front().expect("unexpected command");
        assert_eq!(request.netfn(), NetFn::Storage);
        assert_eq!(request.cmd(), step.cmd);
        assert_eq!(request.data(), step.request);
        let (cc, body) = step.response?;
        let mut data = vec![cc];
        data.extend(body);
        Ok(Response::new(Message::new_response(NetFn::Storage, step.cmd, data), 0).unwrap())
    }
}

fn info(entries: u16, free: u16, reserve: bool) -> Vec<u8> {
    let mut data = vec![0u8; 14];
    data[0] = 0x51;
    data[1..3].copy_from_slice(&entries.to_le_bytes());
    data[3..5].copy_from_slice(&free.to_le_bytes());
    if reserve {
        data[13] = 0x02;
    }
    data
}

fn get(reservation: u16, id: u16) -> [u8; 6] {
    let [r0, r1] = reservation.to_le_bytes();
    let [i0, i1] = id.to_le_bytes();
    [r0, r1, i0, i1, 0, 0xff]
}

fn system_record(id: u16) -> [u8; 16] {
    let mut data = [0u8; 16];
    data[0..2].copy_from_slice(&id.to_le_bytes());
    data[2] = 0x02;
    data[3..7].copy_from_slice(&1_700_000_000u32.to_le_bytes());
    data[7] = 0x20;
    data[9] = 0x04;
    data[10] = 0x01;
    data[11] = 0x10;
    data[12] = 0x6f;
    data
}

fn entry(id: u16, next: u16) -> Vec<u8> {
    let mut data = next.to_le_bytes().to_vec();
    data.extend(system_record(id));
    data
}

fn ids(ipmi: &mut Ipmi<Fixture>, max: usize) -> Vec<u16> {
    ipmi.sel_entries(max)
        .map(|result| result.unwrap().entry.record_id().value())
        .collect()
}

#[test]
fn empty_log_does_not_request_an_entry_even_with_zero_limit() {
    let mut ipmi = Ipmi::new(Fixture::new(vec![Step::ok(
        0x40,
        &[],
        &info(0, 0xffff, false),
    )]));
    assert!(ipmi.sel_entries(0).next().is_none());
    ipmi.release().exhausted();
}

#[test]
fn full_log_with_nonsequential_ids_uses_next_pointers_and_reservation() {
    let mut ipmi = Ipmi::new(Fixture::new(vec![
        Step::ok(0x40, &[], &info(2, 0, true)),
        Step::ok(0x42, &[], &[0x34, 0x12]),
        Step::ok(0x43, &get(0x1234, 0), &entry(7, 0x123)),
        Step::ok(0x43, &get(0x1234, 0x123), &entry(0x123, 0xffff)),
    ]));
    assert_eq!(ids(&mut ipmi, 2), vec![7, 0x123]);
    ipmi.release().exhausted();
}

#[test]
fn cancelled_reservations_are_renewed_only_for_reads() {
    let mut ipmi = Ipmi::new(Fixture::new(vec![
        Step::ok(0x40, &[], &info(2, 0, true)),
        Step::ok(0x42, &[], &[1, 0]),
        Step::cc(0x43, &get(1, 0), 0xc5),
        Step::ok(0x42, &[], &[2, 0]),
        Step::ok(0x43, &get(2, 0), &entry(11, 100)),
        Step::cc(0x43, &get(2, 100), 0xc5),
        Step::ok(0x42, &[], &[3, 0]),
        Step::ok(0x43, &get(3, 100), &entry(100, 0xffff)),
    ]));
    assert_eq!(ids(&mut ipmi, 3), vec![11, 100]);
    ipmi.release().exhausted();
}

#[test]
fn deleted_next_id_causes_bounded_rescan_without_duplicate_records() {
    let mut ipmi = Ipmi::new(Fixture::new(vec![
        Step::ok(0x40, &[], &info(2, 20, false)),
        Step::ok(0x43, &get(0, 0), &entry(11, 20)),
        Step::cc(0x43, &get(0, 20), 0xcb),
        Step::ok(0x40, &[], &info(2, 20, false)),
        Step::ok(0x43, &get(0, 0), &entry(11, 50)),
        Step::ok(0x43, &get(0, 50), &entry(50, 0xffff)),
    ]));
    assert_eq!(ids(&mut ipmi, 3), vec![11, 50]);
    ipmi.release().exhausted();
}

#[test]
fn vanished_log_after_first_record_ends_only_after_info_confirms_empty() {
    let mut ipmi = Ipmi::new(Fixture::new(vec![
        Step::ok(0x40, &[], &info(1, 20, false)),
        Step::ok(0x43, &get(0, 0), &entry(1, 2)),
        Step::cc(0x43, &get(0, 2), 0xcb),
        Step::ok(0x40, &[], &info(0, 40, false)),
    ]));
    assert_eq!(ids(&mut ipmi, 2), vec![1]);
    ipmi.release().exhausted();
}

#[test]
fn short_entries_and_midstream_transport_failure_are_errors_not_end() {
    let mut short = Ipmi::new(Fixture::new(vec![
        Step::ok(0x40, &[], &info(1, 20, false)),
        Step::ok(0x43, &get(0, 0), &[0xff, 0xff, 1, 0, 2, 0]),
    ]));
    let mut iter = short.sel_entries(4);
    assert!(matches!(
        iter.next(),
        Some(Err(SelIterError::Entry(IpmiError::Command {
            error: ParseEntryError::NotEnoughData,
            ..
        })))
    ));
    assert!(iter.next().is_none());
    drop(iter);
    short.release().exhausted();

    let mut failed = Ipmi::new(Fixture::new(vec![
        Step::ok(0x40, &[], &info(2, 20, false)),
        Step::ok(0x43, &get(0, 0), &entry(1, 10)),
        Step::lost(0x43, &get(0, 10)),
    ]));
    let mut iter = failed.sel_entries(4);
    assert_eq!(iter.next().unwrap().unwrap().entry.record_id().value(), 1);
    assert!(matches!(
        iter.next(),
        Some(Err(SelIterError::Entry(IpmiError::Connection(
            FixtureError
        ))))
    ));
    assert!(iter.next().is_none());
    drop(iter);
    failed.release().exhausted();
}

#[test]
fn limits_and_cycles_return_errors_instead_of_truncating() {
    let mut limited = Ipmi::new(Fixture::new(vec![
        Step::ok(0x40, &[], &info(2, 0, false)),
        Step::ok(0x43, &get(0, 0), &entry(2, 100)),
    ]));
    let mut iter = limited.sel_entries(1);
    assert!(iter.next().unwrap().is_ok());
    assert!(matches!(
        iter.next(),
        Some(Err(SelIterError::EntryLimit(1)))
    ));
    assert!(iter.next().is_none());
    drop(iter);
    limited.release().exhausted();

    let mut cyclic = Ipmi::new(Fixture::new(vec![
        Step::ok(0x40, &[], &info(2, 0, false)),
        Step::ok(0x43, &get(0, 0), &entry(2, 3)),
        Step::ok(0x43, &get(0, 3), &entry(3, 2)),
    ]));
    let mut iter = cyclic.sel_entries(3);
    assert!(iter.next().unwrap().is_ok());
    assert!(iter.next().unwrap().is_ok());
    assert!(matches!(
        iter.next(),
        Some(Err(SelIterError::RecordCycle(id))) if id.value() == 2
    ));
    drop(iter);
    cyclic.release().exhausted();
}

#[test]
fn missing_first_record_is_an_error_if_info_still_reports_entries() {
    let mut ipmi = Ipmi::new(Fixture::new(vec![
        Step::ok(0x40, &[], &info(1, 0, false)),
        Step::cc(0x43, &get(0, 0), 0xcb),
        Step::ok(0x40, &[], &info(1, 0, false)),
    ]));
    let mut iter = ipmi.sel_entries(4);
    assert!(matches!(
        iter.next(),
        Some(Err(SelIterError::Entry(IpmiError::Failed { .. })))
    ));
    assert!(iter.next().is_none());
    drop(iter);
    ipmi.release().exhausted();
}

#[test]
fn repeated_deletions_are_bounded_and_reported() {
    let mut steps = vec![
        Step::ok(0x40, &[], &info(2, 20, false)),
        Step::ok(0x43, &get(0, 0), &entry(1, 2)),
    ];
    for restart in 0..3 {
        steps.push(Step::cc(0x43, &get(0, 2), 0xcb));
        steps.push(Step::ok(0x40, &[], &info(2, 20, false)));
        if restart < 2 {
            steps.push(Step::ok(0x43, &get(0, 0), &entry(1, 2)));
        }
    }
    let mut ipmi = Ipmi::new(Fixture::new(steps));
    let mut iter = ipmi.sel_entries(4);
    assert_eq!(iter.next().unwrap().unwrap().entry.record_id().value(), 1);
    assert!(matches!(
        iter.next(),
        Some(Err(SelIterError::Entry(IpmiError::Failed { .. })))
    ));
    assert!(iter.next().is_none());
    drop(iter);
    ipmi.release().exhausted();
}

#[test]
fn repeated_reservation_cancellation_stops_after_two_renewals() {
    let mut ipmi = Ipmi::new(Fixture::new(vec![
        Step::ok(0x40, &[], &info(1, 0, true)),
        Step::ok(0x42, &[], &[1, 0]),
        Step::cc(0x43, &get(1, 0), 0xc5),
        Step::ok(0x42, &[], &[2, 0]),
        Step::cc(0x43, &get(2, 0), 0xc5),
        Step::ok(0x42, &[], &[3, 0]),
        Step::cc(0x43, &get(3, 0), 0xc5),
    ]));
    let mut iter = ipmi.sel_entries(4);
    assert!(matches!(
        iter.next(),
        Some(Err(SelIterError::Entry(IpmiError::Failed { .. })))
    ));
    assert!(iter.next().is_none());
    drop(iter);
    ipmi.release().exhausted();
}

#[test]
fn changed_record_and_invalid_next_id_are_explicit_errors() {
    let mut changed = Ipmi::new(Fixture::new(vec![
        Step::ok(0x40, &[], &info(2, 0, false)),
        Step::ok(0x43, &get(0, 0), &entry(2, 7)),
        Step::ok(0x43, &get(0, 7), &entry(8, 0xffff)),
    ]));
    let mut iter = changed.sel_entries(4);
    assert!(iter.next().unwrap().is_ok());
    assert!(matches!(
        iter.next(),
        Some(Err(SelIterError::RecordChanged {
            requested,
            received
        })) if requested.value() == 7 && received.value() == 8
    ));
    drop(iter);
    changed.release().exhausted();

    let mut bad_pointer = Ipmi::new(Fixture::new(vec![
        Step::ok(0x40, &[], &info(1, 0, false)),
        Step::ok(0x43, &get(0, 0), &entry(2, 0)),
    ]));
    let mut iter = bad_pointer.sel_entries(4);
    assert!(matches!(
        iter.next(),
        Some(Err(SelIterError::InvalidRecordId(id))) if id.is_first()
    ));
    drop(iter);
    bad_pointer.release().exhausted();
}

#[test]
fn sel_timestamps_are_typed_exactly_four_bytes() {
    let mut ipmi = Ipmi::new(Fixture::new(vec![
        Step::ok(0x48, &[], &1_700_000_000u32.to_le_bytes()),
        Step::ok(0x48, &[], &[0, 1, 2]),
        Step::ok(0x49, &1_700_000_000u32.to_le_bytes(), &[]),
    ]));
    assert_eq!(ipmi.send_recv(GetSelTime).unwrap().seconds(), 1_700_000_000);
    assert!(matches!(
        ipmi.send_recv(GetSelTime),
        Err(IpmiError::Command {
            error: SelTimeResponseError(3),
            ..
        })
    ));
    assert!(ipmi
        .sel_mutation(SetSelTime(Timestamp::from(1_700_000_000)))
        .is_ok());
    ipmi.release().exhausted();
}

#[test]
fn add_delete_validate_payload_and_preserve_unknown_oem_data() {
    let raw = system_record(0);
    assert_eq!(
        AddSelEntry::new(&raw[..15]),
        Err(AddSelEntryError::InvalidLength(15))
    );
    assert_eq!(
        AddSelEntry::new(&system_record(3)),
        Err(AddSelEntryError::NonzeroRecordId(3))
    );
    let mut invalid_channel = raw;
    invalid_channel[8] = 0xc0;
    assert_eq!(
        AddSelEntry::new(&invalid_channel),
        Err(AddSelEntryError::InvalidEntry(
            ParseEntryError::InvalidChannel(0xc)
        ))
    );
    assert_eq!(
        DeleteSelEntry::new(None, RecordId::FIRST),
        Err(DeleteSelEntryError::InvalidRecordId)
    );
    assert_eq!(
        DeleteSelEntry::new(None, RecordId::LAST),
        Err(DeleteSelEntryError::InvalidRecordId)
    );

    let mut unknown = [0u8; 16];
    unknown[2] = 0x7f;
    unknown[3..].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    assert!(matches!(
        Entry::parse(&unknown),
        Ok(Entry::Unknown { ty: 0x7f, data, .. }) if data == unknown[3..]
    ));
    assert!(AddSelEntry::new(&unknown).is_ok());

    let mut oem = unknown;
    oem[2] = 0xc0;
    assert!(matches!(
        Entry::parse(&oem),
        Ok(Entry::OemTimestamped { ty: 0xc0, timestamp, data, .. })
            if data == oem[10..16] && timestamp.seconds() == 0x0302_0100
    ));
    oem[2] = 0xe0;
    assert!(matches!(
        Entry::parse(&oem),
        Ok(Entry::OemNotTimestamped { ty: 0xe0, data, .. }) if data == oem[3..16]
    ));

    let id = RecordId::new(7).unwrap();
    let mut read_unknown = unknown;
    read_unknown[0] = 7;
    let mut ipmi = Ipmi::new(Fixture::new(vec![
        Step::ok(0x44, &unknown, &[7, 0]),
        Step::ok(0x46, &[1, 0, 7, 0], &[7, 0]),
        Step::ok(0x40, &[], &info(1, 0, false)),
        Step::ok(
            0x43,
            &get(0, 0),
            &[&[0xff, 0xff], &read_unknown[..]].concat(),
        ),
    ]));
    assert_eq!(
        ipmi.sel_mutation(AddSelEntry::new(&unknown).unwrap())
            .unwrap(),
        id
    );
    assert_eq!(
        ipmi.sel_mutation(DeleteSelEntry::new(NonZeroU16::new(1), id).unwrap())
            .unwrap(),
        id
    );
    let result: SelEntryInfo = ipmi.sel_entries(1).next().unwrap().unwrap();
    assert_eq!(result.raw, read_unknown);
    ipmi.release().exhausted();
}

#[test]
fn writes_are_never_retried_and_report_unknown_outcomes_separately() {
    let raw = system_record(0);
    let mut ipmi = Ipmi::new(Fixture::new(vec![
        Step::lost(0x44, &raw),
        Step::cc(0x44, &raw, 0xc4),
        Step::ok(0x44, &raw, &[0]),
        Step::lost(0x46, &[0, 0, 7, 0]),
        Step::cc(0x46, &[0, 0, 7, 0], 0xc5),
        Step::lost(0x49, &[1, 0, 0, 0]),
        Step::ok(0x49, &[2, 0, 0, 0], &[1]),
    ]));
    let add = || AddSelEntry::new(&raw).unwrap();
    let delete = || DeleteSelEntry::new(None, RecordId::new(7).unwrap()).unwrap();
    assert!(matches!(
        ipmi.sel_mutation(add()),
        Err(SelMutationError::OutcomeUnknown(IpmiError::Connection(
            FixtureError
        )))
    ));
    assert!(matches!(
        ipmi.sel_mutation(add()),
        Err(SelMutationError::Rejected(IpmiError::Failed { .. }))
    ));
    assert!(matches!(
        ipmi.sel_mutation(add()),
        Err(SelMutationError::OutcomeUnknown(IpmiError::Command {
            error: AddSelEntryError::InvalidResponse(1),
            ..
        }))
    ));
    assert!(matches!(
        ipmi.sel_mutation(delete()),
        Err(SelMutationError::OutcomeUnknown(IpmiError::Connection(
            FixtureError
        )))
    ));
    assert!(matches!(
        ipmi.sel_mutation(delete()),
        Err(SelMutationError::Rejected(IpmiError::Failed { .. }))
    ));
    assert!(matches!(
        ipmi.sel_mutation(SetSelTime(Timestamp::from(1))),
        Err(SelMutationError::OutcomeUnknown(IpmiError::Connection(
            FixtureError
        )))
    ));
    assert!(matches!(
        ipmi.sel_mutation(SetSelTime(Timestamp::from(2))),
        Err(SelMutationError::OutcomeUnknown(IpmiError::Command {
            error: SelTimeResponseError(1),
            ..
        }))
    ));
    ipmi.release().exhausted();
}
