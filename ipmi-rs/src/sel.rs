use std::{collections::HashSet, num::NonZeroU16, time::Instant};

use crate::{
    connection::{CompletionErrorCode, IpmiCommand, IpmiConnection, NotEnoughData},
    rmcp::CancellationToken,
    storage::sel::{
        self, GetSelEntry, GetSelInfo, ReserveSel, SelCommand, SelEntryInfo as EntryInfo,
    },
    Ipmi, IpmiError,
};

type ReadResult<CON, CMD> = Result<
    <CMD as IpmiCommand>::Output,
    IpmiError<<CON as IpmiConnection>::Error, <CMD as IpmiCommand>::Error>,
>;

/// A SEL write failed, with a distinct outcome for an acknowledged BMC error.
///
/// `OutcomeUnknown` includes lost/invalid responses, transport errors after a
/// possible send, and malformed successful replies. Never automatically retry
/// such a write; inspect the SEL/time first and decide manually.
#[derive(Debug)]
pub enum SelMutationError<CON, PARSE> {
    /// The BMC explicitly rejected the command with a completion code.
    Rejected(IpmiError<CON, PARSE>),
    /// The BMC may have executed the command; no safe automatic retry exists.
    OutcomeUnknown(IpmiError<CON, PARSE>),
}

/// Failure to read or traverse the SEL. Only `None` indicates end of log.
#[derive(Debug)]
pub enum SelIterError<CON> {
    /// Could not read the log's entry count and supported operations.
    Info(IpmiError<CON, NotEnoughData>),
    /// Could not obtain or renew an advertised reservation.
    Reservation(IpmiError<CON, NotEnoughData>),
    /// A record read failed, including an exhausted reservation/missing-ID retry.
    Entry(IpmiError<CON, sel::ParseEntryError>),
    /// More records were present than the caller allowed.
    EntryLimit(usize),
    /// Too many reads, including rescans, were needed to make progress.
    ReadLimit,
    /// The BMC returned a reserved ID or an invalid next-record pointer.
    InvalidRecordId(sel::RecordId),
    /// A record changed between requests.
    RecordChanged {
        requested: sel::RecordId,
        received: sel::RecordId,
    },
    /// The BMC returned a cyclic record chain.
    RecordCycle(sel::RecordId),
    /// A bounded traversal was cancelled between transport operations.
    Cancelled,
    /// A bounded traversal reached its absolute deadline.
    DeadlineExpired,
}

/// Bounded, fallible SEL traversal. Follows next-record pointers, not ID
/// arithmetic, and never treats a failed read as end of log.
///
/// Initialization is lazy. An empty log returns `None` after Get SEL Info;
/// all other errors return one `Err` and fuse the iterator. This is a live
/// traversal, not a snapshot: concurrent deletions can cause a limited rescan
/// from FIRST (previously emitted records are not repeated).
pub struct SelIter<'a, CON> {
    ipmi: &'a mut Ipmi<CON>,
    next_id: Option<sel::RecordId>,
    reservation: Option<NonZeroU16>,
    has_reservation: bool,
    seen: HashSet<sel::RecordId>,
    scanned: HashSet<sel::RecordId>,
    max_entries: usize,
    remaining_reads: usize,
    restarts: usize,
    finished: bool,
    budget: Option<(Instant, CancellationToken)>,
}

impl<'a, CON: IpmiConnection> SelIter<'a, CON> {
    pub(crate) fn new(ipmi: &'a mut Ipmi<CON>, max_entries: usize) -> Self {
        Self {
            ipmi,
            next_id: None,
            reservation: None,
            has_reservation: false,
            seen: HashSet::new(),
            scanned: HashSet::new(),
            max_entries,
            // Record IDs are 16-bit; cap even a caller-supplied huge limit.
            remaining_reads: max_entries.saturating_mul(4).saturating_add(4).min(65_536),
            restarts: 0,
            finished: false,
            budget: None,
        }
    }

    pub(crate) fn new_bounded(
        ipmi: &'a mut Ipmi<CON>,
        max_entries: usize,
        deadline: Instant,
        cancellation: CancellationToken,
    ) -> Self {
        let mut iter = Self::new(ipmi, max_entries);
        iter.budget = Some((deadline, cancellation));
        iter
    }

    fn check_budget(&self) -> Result<(), SelIterError<CON::Error>> {
        if let Some((deadline, cancellation)) = &self.budget {
            if cancellation.is_cancelled() {
                return Err(SelIterError::Cancelled);
            }
            if Instant::now() >= *deadline {
                return Err(SelIterError::DeadlineExpired);
            }
        }
        Ok(())
    }

    fn send<CMD: IpmiCommand>(
        &mut self,
        command: CMD,
    ) -> Result<ReadResult<CON, CMD>, SelIterError<CON::Error>> {
        self.check_budget()?;
        let result = match &self.budget {
            Some((deadline, cancellation)) => {
                self.ipmi
                    .send_recv_bounded(command, *deadline, cancellation)
            }
            None => self.ipmi.send_recv(command),
        };
        self.check_budget()?;
        Ok(result)
    }

    fn fail(
        &mut self,
        error: SelIterError<CON::Error>,
    ) -> Option<Result<EntryInfo, SelIterError<CON::Error>>> {
        self.finished = true;
        Some(Err(error))
    }

    fn reserve(&mut self) -> Result<(), SelIterError<CON::Error>> {
        self.reservation = Some(self.send(ReserveSel)?.map_err(SelIterError::Reservation)?);
        Ok(())
    }

    fn info(&mut self) -> Result<sel::SelInfo, SelIterError<CON::Error>> {
        self.send(GetSelInfo)?.map_err(SelIterError::Info)
    }

    fn read(&mut self, id: sel::RecordId) -> Result<EntryInfo, SelIterError<CON::Error>> {
        // Reservation cancellation makes a READ safe to repeat. Mutation
        // commands never use this path.
        for retry in 0..=2 {
            if self.remaining_reads == 0 {
                return Err(SelIterError::ReadLimit);
            }
            self.remaining_reads -= 1;
            match self.send(GetSelEntry::new(self.reservation, id))? {
                Err(IpmiError::Failed {
                    completion_code: CompletionErrorCode::ReservationCancelledOrInvalidId,
                    ..
                }) if self.has_reservation && retry < 2 => self.reserve()?,
                result => return result.map_err(SelIterError::Entry),
            }
        }
        unreachable!("read returns on final attempt")
    }
}

impl<CON: IpmiConnection> Iterator for SelIter<'_, CON> {
    type Item = Result<EntryInfo, SelIterError<CON::Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if self.next_id.is_none() {
            let info = match self.info() {
                Ok(info) => info,
                Err(error) => return self.fail(error),
            };
            if info.entries == 0 {
                self.finished = true;
                return None;
            }
            self.has_reservation = info.supported_cmds.contains(&SelCommand::Reserve);
            if self.has_reservation {
                if let Err(error) = self.reserve() {
                    return self.fail(error);
                }
            }
            self.next_id = Some(sel::RecordId::FIRST);
        }

        loop {
            let id = self.next_id.expect("initialized SEL iterator");
            if id.is_last() {
                self.finished = true;
                return None;
            }
            if self.seen.len() >= self.max_entries {
                return self.fail(SelIterError::EntryLimit(self.max_entries));
            }
            if !id.is_first() && self.scanned.contains(&id) {
                return self.fail(SelIterError::RecordCycle(id));
            }
            let entry = match self.read(id) {
                Ok(entry) => entry,
                Err(SelIterError::Entry(
                    error @ IpmiError::Failed {
                        completion_code: CompletionErrorCode::RequestedDatapointNotPresent,
                        ..
                    },
                )) => {
                    let info = match self.info() {
                        Ok(info) => info,
                        Err(error) => return self.fail(error),
                    };
                    if info.entries == 0 {
                        self.finished = true;
                        return None;
                    }
                    if id.is_first() || self.restarts >= 2 {
                        return self.fail(SelIterError::Entry(error));
                    }
                    self.restarts += 1;
                    self.has_reservation = info.supported_cmds.contains(&SelCommand::Reserve);
                    if self.has_reservation {
                        if let Err(error) = self.reserve() {
                            return self.fail(error);
                        }
                    } else {
                        self.reservation = None;
                    }
                    self.next_id = Some(sel::RecordId::FIRST);
                    self.scanned.clear();
                    continue;
                }
                Err(error) => return self.fail(error),
            };

            let received = entry.entry.record_id();
            if received.is_first() || received.is_last() {
                return self.fail(SelIterError::InvalidRecordId(received));
            }
            if !id.is_first() && received != id {
                return self.fail(SelIterError::RecordChanged {
                    requested: id,
                    received,
                });
            }
            if entry.next_entry.is_first() {
                return self.fail(SelIterError::InvalidRecordId(entry.next_entry));
            }
            if entry.next_entry == received {
                return self.fail(SelIterError::RecordCycle(received));
            }
            if !self.scanned.insert(received) {
                return self.fail(SelIterError::RecordCycle(received));
            }
            self.next_id = Some(entry.next_entry);
            if self.seen.insert(received) {
                return Some(Ok(entry));
            }
        }
    }
}
