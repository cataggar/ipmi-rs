use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use ipmi_rs::{
    connection::{IpmiConnection, Message, NetFn, Request, Response},
    events::{EventInjectionError, EventPollError},
    rmcp::CancellationToken,
    sensor_event::{EventInterface, PlatformEventMessage},
    storage::{sdr::SensorType, sel::EventDirection},
    Ipmi,
};

#[derive(Debug, PartialEq)]
struct FixtureError;

struct Step {
    netfn: NetFn,
    cmd: u8,
    request: Vec<u8>,
    reply: Result<(u8, Vec<u8>), FixtureError>,
    delay: Duration,
    cancel_after_response: Option<CancellationToken>,
}

impl Step {
    fn ok(netfn: NetFn, cmd: u8, request: &[u8], body: &[u8]) -> Self {
        Self {
            netfn,
            cmd,
            request: request.to_vec(),
            reply: Ok((0, body.to_vec())),
            delay: Duration::ZERO,
            cancel_after_response: None,
        }
    }

    fn rejected(netfn: NetFn, cmd: u8, request: &[u8], cc: u8) -> Self {
        Self {
            netfn,
            cmd,
            request: request.to_vec(),
            reply: Ok((cc, vec![])),
            delay: Duration::ZERO,
            cancel_after_response: None,
        }
    }

    fn lost(netfn: NetFn, cmd: u8, request: &[u8]) -> Self {
        Self {
            netfn,
            cmd,
            request: request.to_vec(),
            reply: Err(FixtureError),
            delay: Duration::ZERO,
            cancel_after_response: None,
        }
    }
}

struct Fixture(VecDeque<Step>);

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
        assert_eq!(request.netfn(), step.netfn);
        assert_eq!(request.cmd(), step.cmd);
        assert_eq!(request.data(), step.request);
        std::thread::sleep(step.delay);
        if let Some(token) = step.cancel_after_response {
            token.cancel();
        }
        let (cc, body) = step.reply?;
        let mut data = vec![cc];
        data.extend(body);
        Ok(Response::new(Message::new_response(step.netfn, step.cmd, data), 0).unwrap())
    }

    fn send_recv_deadline(
        &mut self,
        request: &mut Request,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Response, Self::Error> {
        assert!(!cancellation.is_cancelled(), "request after cancellation");
        assert!(Instant::now() < deadline, "request after deadline");
        if let Some(step) = self.0.front_mut() {
            if !step.delay.is_zero() {
                std::thread::sleep(
                    step.delay
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
                if Instant::now() >= deadline {
                    return Err(FixtureError);
                }
                step.delay = Duration::ZERO;
            }
        }
        self.send_recv(request)
    }
}

fn info(entries: usize, deletion_time: u32, overflow: bool) -> Vec<u8> {
    let mut info = vec![0u8; 14];
    info[0] = 0x51;
    info[1..3].copy_from_slice(&(entries as u16).to_le_bytes());
    info[9..13].copy_from_slice(&deletion_time.to_le_bytes());
    if overflow {
        info[13] |= 0x80;
    }
    info
}

fn get(id: u16) -> [u8; 6] {
    let [lo, hi] = id.to_le_bytes();
    [0, 0, lo, hi, 0, 0xff]
}

fn record(id: u16, sensor: u8) -> [u8; 16] {
    let mut data = [0u8; 16];
    data[..2].copy_from_slice(&id.to_le_bytes());
    data[2] = 2;
    data[7] = 0x41;
    data[9] = 4;
    data[10] = 1;
    data[11] = sensor;
    data[12] = 1;
    data
}

fn scan(records: &[(u16, u8)], deletion_time: u32, overflow: bool) -> Vec<Step> {
    let info = info(records.len(), deletion_time, overflow);
    let mut steps = vec![Step::ok(NetFn::Storage, 0x40, &[], &info)];
    let mut next_request = 0;
    for (index, (id, sensor)) in records.iter().enumerate() {
        let next = records.get(index + 1).map(|(id, _)| *id).unwrap_or(0xffff);
        let mut reply = next.to_le_bytes().to_vec();
        reply.extend(record(*id, *sensor));
        steps.push(Step::ok(NetFn::Storage, 0x43, &get(next_request), &reply));
        next_request = next;
    }
    steps.push(Step::ok(NetFn::Storage, 0x40, &[], &info));
    steps
}

fn missing_tail_rescan(records: &[(u16, u8)], first_rescan: Step) -> Vec<Step> {
    let mut steps = scan(records, 0, false);
    steps.truncate(records.len()); // Get Info and all records except the missing tail.
    steps.push(Step::rejected(
        NetFn::Storage,
        0x43,
        &get(records.last().unwrap().0),
        0xcb,
    ));
    steps.push(Step::ok(
        NetFn::Storage,
        0x40,
        &[],
        &info(records.len(), 0, false),
    ));
    steps.push(first_rescan);
    steps
}

fn limit() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[test]
fn baseline_suppresses_duplicates_and_reports_nonconsecutive_ids() {
    let mut steps = scan(&[(10, 1), (20, 1)], 0, false);
    steps.extend(scan(&[(10, 1), (20, 1)], 0, false));
    steps.extend(scan(&[(10, 1), (20, 1), (0x1234, 1)], 0, false));
    let mut ipmi = Ipmi::new(Fixture(steps.into()));
    let token = CancellationToken::default();
    let mut poller = ipmi.sel_poller(4, limit(), &token).unwrap();
    let quiet = poller.poll_once(limit(), &token).unwrap();
    assert!(quiet.entries.is_empty());
    assert!(quiet.missing_ids.is_empty());
    assert!(!quiet.wrapped);
    let batch = poller.poll_once(limit(), &token).unwrap();
    assert_eq!(batch.entries.len(), 1);
    assert_eq!(batch.entries[0].entry.record_id().value(), 0x1234);
    assert!(!batch.continuity_lost);
    drop(poller);
    assert!(ipmi.release().0.is_empty());
}

#[test]
fn missed_poll_wraparound_and_reused_ids_are_visible() {
    let mut steps = scan(&[(7, 1), (0xfffe, 1)], 0, false);
    steps.extend(scan(&[(0xfffe, 1), (1, 1), (3, 1)], 10, true));
    steps.extend(scan(&[(0xfffe, 1), (1, 2), (3, 1)], 11, true));
    let mut ipmi = Ipmi::new(Fixture(steps.into()));
    let token = CancellationToken::default();
    let mut poller = ipmi.sel_poller(4, limit(), &token).unwrap();
    let first = poller.poll_once(limit(), &token).unwrap();
    assert_eq!(
        first
            .entries
            .iter()
            .map(|e| e.entry.record_id().value())
            .collect::<Vec<_>>(),
        [1, 3]
    );
    assert_eq!(
        first
            .missing_ids
            .iter()
            .map(|id| id.value())
            .collect::<Vec<_>>(),
        [7]
    );
    assert!(first.wrapped);
    assert!(first.continuity_lost);
    let second = poller.poll_once(limit(), &token).unwrap();
    assert_eq!(second.entries.len(), 1);
    assert_eq!(second.entries[0].entry.record_id().value(), 1);
    assert!(!second.wrapped);
    assert!(second.continuity_lost);
    drop(poller);
    assert!(ipmi.release().0.is_empty());
}

#[test]
fn deleting_newest_id_does_not_masquerade_as_wraparound() {
    let mut steps = scan(&[(10, 1), (20, 1)], 0, false);
    steps.extend(scan(&[(10, 1)], 10, false));
    let mut ipmi = Ipmi::new(Fixture(steps.into()));
    let token = CancellationToken::default();
    let mut poller = ipmi.sel_poller(3, limit(), &token).unwrap();
    let batch = poller.poll_once(limit(), &token).unwrap();
    assert_eq!(
        batch
            .missing_ids
            .iter()
            .map(|id| id.value())
            .collect::<Vec<_>>(),
        [20]
    );
    assert!(!batch.wrapped);
    assert!(batch.continuity_lost);
    drop(poller);
    assert!(ipmi.release().0.is_empty());
}

#[test]
fn preexisting_overflow_is_exposed_on_baseline_and_quiet_scans() {
    let mut steps = scan(&[(10, 1)], 0, true);
    steps.extend(scan(&[(10, 1)], 0, true));
    steps.extend(scan(&[(10, 1)], 0, true));
    let mut ipmi = Ipmi::new(Fixture(steps.into()));
    let token = CancellationToken::default();
    let mut poller = ipmi.sel_poller(2, limit(), &token).unwrap();
    assert!(poller.overflow());
    let batch = poller.poll_once(limit(), &token).unwrap();
    assert!(batch.entries.is_empty());
    assert!(batch.overflow && batch.continuity_lost);
    let repeat = poller
        .wait_next(Duration::from_secs(1), limit(), &token)
        .unwrap();
    assert!(repeat.entries.is_empty());
    assert!(repeat.overflow && repeat.continuity_lost);
    drop(poller);
    assert!(ipmi.release().0.is_empty());
}

#[test]
fn cancellation_inside_missing_id_rescan_stops_before_next_request() {
    let records: Vec<_> = (1..=48).map(|id| (id, 1)).collect();
    let token = CancellationToken::default();
    let mut steps = scan(&records, 0, false);
    let mut first_rescan = scan(&records, 0, false).remove(1);
    first_rescan.cancel_after_response = Some(token.clone());
    steps.extend(missing_tail_rescan(&records, first_rescan));
    steps.extend(scan(&records, 0, false));

    let mut ipmi = Ipmi::new(Fixture(steps.into()));
    let mut poller = ipmi.sel_poller(48, limit(), &token).unwrap();
    assert!(matches!(
        poller.poll_once(limit(), &token),
        Err(EventPollError::Cancelled)
    ));
    token.reset();
    let batch = poller.poll_once(limit(), &token).unwrap();
    assert!(batch.entries.is_empty());
    assert!(batch.missing_ids.is_empty());
    drop(poller);
    assert!(ipmi.release().0.is_empty());
}

#[test]
fn a_slow_rescan_request_uses_remaining_deadline_not_connection_timeout() {
    let records: Vec<_> = (1..=48).map(|id| (id, 1)).collect();
    let token = CancellationToken::default();
    let mut steps = scan(&records, 0, false);
    let mut first_rescan = scan(&records, 0, false).remove(1);
    first_rescan.delay = Duration::from_millis(500);
    steps.extend(missing_tail_rescan(&records, first_rescan));
    let mut ipmi = Ipmi::new(Fixture(steps.into()));
    let mut poller = ipmi.sel_poller(48, limit(), &token).unwrap();
    let started = Instant::now();
    assert!(matches!(
        poller.poll_once(started + Duration::from_millis(30), &token),
        Err(EventPollError::DeadlineExpired)
    ));
    assert!(started.elapsed() < Duration::from_millis(300));
    drop(poller);
    let fixture = ipmi.release();
    assert_eq!(fixture.0.front().unwrap().request, get(0));
}

#[test]
fn missed_transient_additions_are_reported_as_a_gap() {
    let mut steps = scan(&[(42, 1)], 0, false);
    let mut later = scan(&[(42, 1)], 0, false);
    for step in later.iter_mut().filter(|step| step.cmd == 0x40) {
        let Ok((_, bytes)) = &mut step.reply else {
            unreachable!()
        };
        bytes[5..9].copy_from_slice(&15u32.to_le_bytes());
    }
    steps.extend(later);
    let mut ipmi = Ipmi::new(Fixture(steps.into()));
    let token = CancellationToken::default();
    let mut poller = ipmi.sel_poller(2, limit(), &token).unwrap();
    let batch = poller.poll_once(limit(), &token).unwrap();
    assert!(batch.entries.is_empty());
    assert!(batch.missing_ids.is_empty());
    assert!(batch.continuity_lost);
    drop(poller);
    assert!(ipmi.release().0.is_empty());
}

#[test]
fn malformed_or_missing_read_does_not_advance_baseline() {
    let mut steps = scan(&[(1, 1)], 0, false);
    steps.push(Step::ok(NetFn::Storage, 0x40, &[], &info(2, 0, false)));
    steps.push(Step::ok(NetFn::Storage, 0x43, &get(0), &[0xff, 0xff, 0x01]));
    steps.extend(scan(&[(1, 1), (2, 1)], 0, false));
    let mut ipmi = Ipmi::new(Fixture(steps.into()));
    let token = CancellationToken::default();
    let mut poller = ipmi.sel_poller(3, limit(), &token).unwrap();
    assert!(matches!(
        poller.poll_once(limit(), &token),
        Err(EventPollError::Traverse(_))
    ));
    let batch = poller.poll_once(limit(), &token).unwrap();
    assert_eq!(batch.entries.len(), 1);
    assert_eq!(batch.entries[0].entry.record_id().value(), 2);
    drop(poller);
    assert!(ipmi.release().0.is_empty());
}

#[test]
fn unstable_scan_is_reported_and_does_not_advance_baseline() {
    let mut steps = scan(&[(1, 1)], 0, false);
    let mut unstable = scan(&[(1, 1), (2, 1)], 0, false);
    let last = unstable.last_mut().unwrap();
    last.reply = Ok((0, info(3, 0, false)));
    steps.extend(unstable);
    steps.extend(scan(&[(1, 1), (2, 1)], 0, false));
    let mut ipmi = Ipmi::new(Fixture(steps.into()));
    let token = CancellationToken::default();
    let mut poller = ipmi.sel_poller(4, limit(), &token).unwrap();
    assert!(matches!(
        poller.poll_once(limit(), &token),
        Err(EventPollError::UnstableScan {
            expected: 3,
            observed: 2
        })
    ));
    let batch = poller.poll_once(limit(), &token).unwrap();
    assert_eq!(batch.entries.len(), 1);
    assert_eq!(batch.entries[0].entry.record_id().value(), 2);
    drop(poller);
    assert!(ipmi.release().0.is_empty());
}

#[test]
fn wait_checks_cancellation_and_deadline_during_idle_interval() {
    let mut steps = scan(&[], 0, false);
    steps.extend(scan(&[], 0, false));
    let mut ipmi = Ipmi::new(Fixture(steps.into()));
    let token = CancellationToken::default();
    let mut poller = ipmi.sel_poller(1, limit(), &token).unwrap();
    let signal = token.clone();
    let worker = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(15));
        signal.cancel();
    });
    assert!(matches!(
        poller.wait_next(Duration::from_secs(1), limit(), &token),
        Err(EventPollError::Cancelled)
    ));
    worker.join().unwrap();
    drop(poller);
    assert!(ipmi.release().0.is_empty());

    let mut steps = scan(&[], 0, false);
    steps.extend(scan(&[], 0, false));
    let mut ipmi = Ipmi::new(Fixture(steps.into()));
    let token = CancellationToken::default();
    let mut poller = ipmi.sel_poller(1, limit(), &token).unwrap();
    assert!(matches!(
        poller.wait_next(
            Duration::from_secs(1),
            Instant::now() + Duration::from_millis(20),
            &token
        ),
        Err(EventPollError::DeadlineExpired)
    ));
    drop(poller);
    assert!(ipmi.release().0.is_empty());
}

#[test]
fn deadlines_cancellation_setup_errors_and_scan_limits() {
    let token = CancellationToken::default();
    let mut failed = Ipmi::new(Fixture(vec![Step::lost(NetFn::Storage, 0x40, &[])].into()));
    assert!(matches!(
        failed.sel_poller(4, limit(), &token),
        Err(EventPollError::Traverse(_))
    ));
    assert!(failed.release().0.is_empty());

    let mut ipmi = Ipmi::new(Fixture(scan(&[], 0, false).into()));
    assert!(matches!(
        ipmi.sel_poller(0, limit(), &token),
        Err(EventPollError::InvalidLimit)
    ));
    assert!(matches!(
        ipmi.sel_poller(1, Instant::now() - Duration::from_millis(1), &token),
        Err(EventPollError::DeadlineExpired)
    ));
    let mut poller = ipmi.sel_poller(1, limit(), &token).unwrap();
    assert!(matches!(
        poller.wait_next(Duration::ZERO, limit(), &token),
        Err(EventPollError::InvalidInterval)
    ));
    token.cancel();
    assert!(matches!(
        poller.poll_once(limit(), &token),
        Err(EventPollError::Cancelled)
    ));
    drop(poller);
    assert!(ipmi.release().0.is_empty());
}

#[test]
fn injected_events_are_sent_once_and_unknown_outcome_is_not_retried() {
    let event = PlatformEventMessage::new(
        SensorType::Temperature,
        0x30,
        1,
        EventDirection::Assert,
        [9, 0xff, 0xff],
        EventInterface::LanOrIpmb,
    )
    .unwrap();
    let payload = [4, 1, 0x30, 1, 9, 0xff, 0xff];
    for (step, variant) in [
        (Step::ok(NetFn::SensorEvent, 2, &payload, &[]), 0),
        (Step::rejected(NetFn::SensorEvent, 2, &payload, 0xc1), 1),
        (Step::lost(NetFn::SensorEvent, 2, &payload), 2),
        (Step::ok(NetFn::SensorEvent, 2, &payload, &[0xff]), 2),
    ] {
        let mut ipmi = Ipmi::new(Fixture(vec![step].into()));
        let outcome = ipmi.inject_platform_event(event);
        match variant {
            0 => assert!(outcome.is_ok()),
            1 => assert!(matches!(outcome, Err(EventInjectionError::Rejected(_)))),
            _ => assert!(matches!(
                outcome,
                Err(EventInjectionError::OutcomeUnknown(_))
            )),
        }
        assert!(ipmi.release().0.is_empty());
    }
}
