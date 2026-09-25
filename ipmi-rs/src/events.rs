//! Explicit event injection and transport-independent, bounded SEL polling.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::{
    connection::{IpmiConnection, NotEnoughData},
    rmcp::CancellationToken,
    sensor_event::{PlatformEventMessage, PlatformEventResponseError},
    storage::sel::{GetSelInfo, RecordId, SelEntryInfo, SelInfo},
    Ipmi, IpmiError, SelIter, SelIterError,
};

/// The BMC rejected an injected event, or its delivery cannot be established.
#[derive(Debug)]
pub enum EventInjectionError<CON> {
    /// An acknowledged nonzero completion code: the BMC rejected the command.
    Rejected(IpmiError<CON, PlatformEventResponseError>),
    /// The event may have been recorded; do not automatically send it again.
    OutcomeUnknown(IpmiError<CON, PlatformEventResponseError>),
}

impl<CON: IpmiConnection> Ipmi<CON> {
    /// Send an explicitly constructed platform event once, without retries.
    pub fn inject_platform_event(
        &mut self,
        event: PlatformEventMessage,
    ) -> Result<(), EventInjectionError<CON::Error>> {
        self.send_recv(event).map_err(|error| match error {
            IpmiError::Failed { .. }
            | IpmiError::Command {
                completion_code: Some(_),
                ..
            } => EventInjectionError::Rejected(error),
            _ => EventInjectionError::OutcomeUnknown(error),
        })
    }

    /// Establish a baseline without replaying existing records. Initialization
    /// fails if the first traversal or Get SEL Info fails.
    pub fn sel_poller(
        &mut self,
        max_entries: usize,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<SelPoller<'_, CON>, EventPollError<CON::Error>> {
        SelPoller::new(self, max_entries, deadline, cancellation)
    }
}

/// A SEL polling failure is never represented as an empty event batch.
#[derive(Debug)]
pub enum EventPollError<CON> {
    /// The bound must be in 1..=65,534.
    InvalidLimit,
    /// An interval of zero cannot be used to wait for new events.
    InvalidInterval,
    /// Cooperative cancellation was requested.
    Cancelled,
    /// The monotonic deadline passed.
    DeadlineExpired,
    /// SEL traversal (including malformed records and read failures) failed.
    Traverse(SelIterError<CON>),
    /// Get SEL Info failed after a traversal.
    Info(IpmiError<CON, NotEnoughData>),
    /// Count changed during a scan, or the traversal was incomplete.
    UnstableScan { expected: u16, observed: usize },
}

/// Changes to the SEL detected across successful scans.
#[derive(Debug)]
pub struct SelPollBatch {
    /// New or replaced entries in BMC traversal order, not numeric ID order.
    pub entries: Vec<SelEntryInfo>,
    /// IDs present last scan but absent now (deleted, aged out, or cleared).
    pub missing_ids: Vec<RecordId>,
    /// An ID decreased across a traversal boundary; no ordering assumption is
    /// used for deduplication.
    pub wrapped: bool,
    /// The SEL overflow bit in the most recent Get SEL Info response. An
    /// already-overflowed log stays visible even on a quiet scan.
    pub overflow: bool,
    /// History may have been lost (removed IDs, deletion timestamp changed,
    /// or an overflow bit that is currently set). Identical reused IDs cannot
    /// be disambiguated.
    pub continuity_lost: bool,
}

/// Compare successive complete SEL scans using the existing fallible iterator.
///
/// Each scan is limited by `max_entries` and by `SelIter`'s read budget. Records
/// are deduplicated by (ID, raw bytes); IDs are not assumed consecutive or
/// monotonic. When a record is removed or replaced, the batch reports it.
/// Deadlines/cancellation are checked before and after each transport request
/// including internal rescans. Built-in transports clamp each command's
/// deadline; custom connections should implement `send_recv_deadline`.
pub struct SelPoller<'a, CON> {
    ipmi: &'a mut Ipmi<CON>,
    max_entries: usize,
    previous: Vec<SelEntryInfo>,
    info: SelInfo,
}

impl<'a, CON: IpmiConnection> SelPoller<'a, CON> {
    /// Whether the BMC reported an overflow during the baseline/latest scan.
    pub fn overflow(&self) -> bool {
        self.info.overflow
    }

    /// Establish a baseline; existing records are not reported as new.
    pub fn new(
        ipmi: &'a mut Ipmi<CON>,
        max_entries: usize,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Self, EventPollError<CON::Error>> {
        if max_entries == 0 || max_entries > 65_534 {
            return Err(EventPollError::InvalidLimit);
        }
        let (previous, info) = Self::scan(ipmi, max_entries, deadline, cancellation)?;
        Ok(Self {
            ipmi,
            max_entries,
            previous,
            info,
        })
    }

    fn check(
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<(), EventPollError<CON::Error>> {
        if cancellation.is_cancelled() {
            return Err(EventPollError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(EventPollError::DeadlineExpired);
        }
        Ok(())
    }

    fn scan(
        ipmi: &mut Ipmi<CON>,
        max_entries: usize,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<(Vec<SelEntryInfo>, SelInfo), EventPollError<CON::Error>> {
        let mut entries = Vec::new();
        let mut iter = SelIter::new_bounded(ipmi, max_entries, deadline, cancellation.clone());
        loop {
            Self::check(deadline, cancellation)?;
            match iter.next() {
                Some(Ok(entry)) => {
                    Self::check(deadline, cancellation)?;
                    entries.push(entry);
                }
                Some(Err(SelIterError::Cancelled)) => return Err(EventPollError::Cancelled),
                Some(Err(SelIterError::DeadlineExpired)) => {
                    return Err(EventPollError::DeadlineExpired)
                }
                Some(Err(error)) => return Err(EventPollError::Traverse(error)),
                None => break,
            }
        }
        drop(iter);
        Self::check(deadline, cancellation)?;
        let info = ipmi.send_recv_bounded(GetSelInfo, deadline, cancellation);
        Self::check(deadline, cancellation)?;
        let info = info.map_err(EventPollError::Info)?;
        if info.entries as usize != entries.len() {
            return Err(EventPollError::UnstableScan {
                expected: info.entries,
                observed: entries.len(),
            });
        }
        Ok((entries, info))
    }

    /// Perform one complete scan, preserving the prior baseline on any failure.
    pub fn poll_once(
        &mut self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<SelPollBatch, EventPollError<CON::Error>> {
        let (current, info) = Self::scan(self.ipmi, self.max_entries, deadline, cancellation)?;
        let old: HashMap<_, _> = self
            .previous
            .iter()
            .map(|e| (e.entry.record_id(), &e.raw))
            .collect();
        let now: HashMap<_, _> = current
            .iter()
            .map(|e| (e.entry.record_id(), &e.raw))
            .collect();
        let missing_ids: Vec<_> = self
            .previous
            .iter()
            .map(|e| e.entry.record_id())
            .filter(|id| !now.contains_key(id))
            .collect();
        let entries: Vec<_> = current
            .iter()
            .filter(|e| old.get(&e.entry.record_id()).copied() != Some(&e.raw))
            .cloned()
            .collect();
        let wrapped = self.previous.last().is_some_and(|last| {
            let last_id = last.entry.record_id();
            let first_after_last = current
                .iter()
                .position(|e| e.entry.record_id() == last_id)
                .map(|index| index + 1)
                .unwrap_or(0);
            current[first_after_last..].iter().any(|e| {
                !old.contains_key(&e.entry.record_id())
                    && e.entry.record_id().value() < last_id.value()
            })
        });
        let continuity_lost = !missing_ids.is_empty()
            || self.info.last_del_time != info.last_del_time
            || info.overflow
            || (entries.is_empty() && self.info.last_add_time != info.last_add_time);
        self.previous = current;
        let overflow = info.overflow;
        self.info = info;
        Ok(SelPollBatch {
            entries,
            missing_ids,
            wrapped,
            overflow,
            continuity_lost,
        })
    }

    /// Poll until an entry or continuity gap is observed, or the operation
    /// reaches its deadline/is cancelled. A quiet scan is not a timeout.
    pub fn wait_next(
        &mut self,
        interval: Duration,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<SelPollBatch, EventPollError<CON::Error>> {
        if interval.is_zero() {
            return Err(EventPollError::InvalidInterval);
        }
        loop {
            let batch = self.poll_once(deadline, cancellation)?;
            if !batch.entries.is_empty() || batch.continuity_lost {
                return Ok(batch);
            }
            let wake_at = Instant::now().checked_add(interval).unwrap_or(deadline);
            loop {
                Self::check(deadline, cancellation)?;
                let remaining = deadline.saturating_duration_since(Instant::now());
                let until_wake = wake_at.saturating_duration_since(Instant::now());
                if until_wake.is_zero() {
                    break;
                }
                std::thread::sleep(until_wake.min(remaining).min(Duration::from_millis(50)));
            }
        }
    }
}
