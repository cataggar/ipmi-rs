//! Implementations & convenience functions for IPMI.
//!
//! This crate provides unix-file and RMCP protocols, and some convenience functions
//! for interacting with IPMI.

pub use ipmi_rs_core::*;

#[cfg(feature = "unix-file")]
mod file;

#[cfg(feature = "unix-file")]
pub use file::File;

pub mod rmcp;

#[cfg(feature = "serial")]
pub mod serial;

#[cfg(feature = "ami-usb")]
pub mod ami_usb;

/// Opt-in, identity-checked OEM command execution.
pub mod oem;

mod spd;
pub use spd::SpdReadError;

/// Kontron firmware inventory and opt-in guarded update workflow.
pub mod fwum;

mod error;
pub use error::IpmiError;

mod sel;
pub use sel::{SelIter, SelIterError, SelMutationError};

mod fru;
pub use fru::{FruReadError, FruWriteError};

use ipmi_rs_core::{
    connection::{CompletionErrorCode, IpmiCommand, NotEnoughData, Request, RequestTargetAddress},
    storage::sdr::{self, Record as SdrRecord},
};
use std::{collections::HashSet, num::NonZeroU16};

pub struct Ipmi<CON> {
    inner: CON,
}

impl<CON> Ipmi<CON> {
    pub fn release(self) -> CON {
        self.inner
    }
}

impl<CON> From<CON> for Ipmi<CON>
where
    CON: connection::IpmiConnection,
{
    fn from(value: CON) -> Self {
        Self::new(value)
    }
}

impl<CON> Ipmi<CON>
where
    CON: connection::IpmiConnection,
{
    pub fn inner_mut(&mut self) -> &mut CON {
        &mut self.inner
    }

    pub fn new(inner: CON) -> Self {
        Self { inner }
    }

    pub fn sdrs(&mut self) -> SdrIter<'_, CON> {
        SdrIter {
            inner: self.sdrs_from(SdrSource::Repository),
        }
    }

    /// Traverse at most `max_entries` SEL records. The iterator is fallible and
    /// reports changes or truncated traversal rather than silently ending.
    pub fn sel_entries(&mut self, max_entries: usize) -> SelIter<'_, CON> {
        SelIter::new(self, max_entries)
    }

    /// Send an explicitly chosen SEL write exactly once. Only a completion-code
    /// rejection is known to have failed; all other errors have unknown outcome.
    pub fn sel_mutation<CMD>(
        &mut self,
        request: CMD,
    ) -> Result<CMD::Output, SelMutationError<CON::Error, CMD::Error>>
    where
        CMD: storage::sel::SelMutation,
    {
        self.send_recv(request).map_err(|error| match error {
            IpmiError::Failed { .. }
            | IpmiError::Command {
                completion_code: Some(_),
                ..
            } => SelMutationError::Rejected(error),
            _ => SelMutationError::OutcomeUnknown(error),
        })
    }

    /// Traverse the SDR source advertised by Get Device ID, preferring the
    /// repository when both sources are supported. Each item is fallible;
    /// an error is yielded once and terminates the iterator.
    pub fn sdrs_fallible(&mut self) -> FallibleSdrIter<'_, CON> {
        FallibleSdrIter::new(self, None)
    }

    /// Traverse a selected SDR source without querying Get Device ID.
    ///
    /// Use this for a controller which advertises both sources, or whose
    /// Get Device ID capability flags are unreliable.
    pub fn sdrs_from(&mut self, source: SdrSource) -> FallibleSdrIter<'_, CON> {
        FallibleSdrIter::new(self, Some(source))
    }

    pub fn send_recv<CMD>(
        &mut self,
        request: CMD,
    ) -> Result<CMD::Output, IpmiError<CON::Error, CMD::Error>>
    where
        CMD: IpmiCommand,
    {
        let target_lun = request.target_lun();
        let target_address = match request.target() {
            Some((a, c)) => RequestTargetAddress::BmcOrIpmb(a, c, target_lun),
            None => RequestTargetAddress::Bmc(target_lun),
        };

        let message = request.into();
        let (message_netfn, message_cmd) = (message.netfn(), message.cmd());
        let mut request = Request::new(message, target_address);

        let response = self.inner.send_recv(&mut request)?;

        if response.netfn_raw() != message_netfn.response_value() || response.cmd() != message_cmd {
            return Err(IpmiError::UnexpectedResponse {
                netfn_sent: message_netfn,
                netfn_recvd: response.netfn(),
                cmd_sent: message_cmd,
                cmd_recvd: response.cmd(),
            });
        }

        // Password and Sun replies may echo secrets; omit their bytes from errors.
        let error_data = || {
            if (response.netfn() == connection::NetFn::App && response.cmd() == 0x47)
                || response.netfn().request_value() == 0x2E
            {
                Vec::new()
            } else {
                response.data().to_vec()
            }
        };
        let map_error = |completion_code, error| IpmiError::Command {
            error,
            netfn: response.netfn(),
            cmd: response.cmd(),
            completion_code,
            data: error_data(),
        };

        if let Ok(completion_code) = CompletionErrorCode::try_from(response.cc()) {
            let error = CMD::handle_completion_code(completion_code, response.data())
                .map(|e| IpmiError::Command {
                    error: e,
                    netfn: response.netfn(),
                    cmd: response.cmd(),
                    completion_code: Some(completion_code),
                    data: error_data(),
                })
                .unwrap_or_else(|| IpmiError::Failed {
                    netfn: response.netfn(),
                    cmd: response.cmd(),
                    completion_code,
                    data: error_data(),
                });

            return Err(error);
        }

        CMD::parse_success_response_for_request(request.data(), response.data())
            .map_err(|err| map_error(None, err))
    }
}

/// Source of SDR records; each has its own reservation and wire commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdrSource {
    Repository,
    Device,
}

/// A complete record could not be assembled consistently.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SdrProtocolError {
    IncorrectChunkLength {
        offset: u16,
        expected: u8,
        actual: usize,
    },
    NextIdChanged {
        expected: sdr::RecordId,
        actual: sdr::RecordId,
    },
    InvalidFirstRecordId,
    RepeatedRecordId(sdr::RecordId),
    OffsetOutOfRange(u16),
}

/// Failure during fallible SDR traversal.
#[derive(Debug)]
pub enum SdrError<E> {
    DeviceId(IpmiError<E, NotEnoughData>),
    RepositoryInfo(IpmiError<E, NotEnoughData>),
    DeviceInfo(IpmiError<E, NotEnoughData>),
    NoSupportedSource,
    Reservation(IpmiError<E, sdr::ReservationError>),
    ReservationLost(sdr::RecordId),
    Read(IpmiError<E, NotEnoughData>),
    Protocol(SdrProtocolError),
    Parse {
        record_id: sdr::RecordId,
        error: sdr::RecordParseError,
    },
}

/// Fallible iterator over bounded SDR reads. An error is returned once;
/// subsequent calls return `None`. `None` without an error means completion.
pub struct FallibleSdrIter<'ipmi, CON> {
    ipmi: &'ipmi mut Ipmi<CON>,
    source: Option<SdrSource>,
    initialized: bool,
    reservation: Option<NonZeroU16>,
    reservation_supported: bool,
    next_id: Option<sdr::RecordId>,
    seen: HashSet<u16>,
    read_limit: u8,
}

impl<'ipmi, CON: connection::IpmiConnection> FallibleSdrIter<'ipmi, CON> {
    fn new(ipmi: &'ipmi mut Ipmi<CON>, source: Option<SdrSource>) -> Self {
        Self {
            ipmi,
            source,
            initialized: false,
            reservation: None,
            reservation_supported: false,
            next_id: Some(sdr::RecordId::FIRST),
            seen: HashSet::new(),
            read_limit: 32,
        }
    }

    fn reserve(&mut self) -> Result<(), SdrError<CON::Error>> {
        let reservation = match self.source.expect("source initialized") {
            SdrSource::Repository => self.ipmi.send_recv(sdr::ReserveSdrRepository),
            SdrSource::Device => self.ipmi.send_recv(sdr::ReserveDeviceSdr),
        }
        .map_err(SdrError::Reservation)?;
        self.reservation = Some(reservation);
        Ok(())
    }

    fn initialize(&mut self) -> Result<(), SdrError<CON::Error>> {
        if self.source.is_none() {
            let device_id = self
                .ipmi
                .send_recv(ipmi_rs_core::app::GetDeviceId)
                .map_err(SdrError::DeviceId)?;
            self.source = if device_id.sdr_repository_support {
                Some(SdrSource::Repository)
            } else if device_id.provides_device_sdrs {
                Some(SdrSource::Device)
            } else {
                return Err(SdrError::NoSupportedSource);
            };
        }

        let (count, reservation_supported) = match self.source.expect("source initialized") {
            SdrSource::Repository => {
                let info = self
                    .ipmi
                    .send_recv(sdr::GetSdrRepositoryInfo)
                    .map_err(SdrError::RepositoryInfo)?;
                (
                    info.record_count,
                    info.supported_ops.contains(&sdr::SdrOperation::Reserve),
                )
            }
            SdrSource::Device => {
                let info = self
                    .ipmi
                    .send_recv(sdr::GetDeviceSdrInfo::new(sdr::SdrCount))
                    .map_err(SdrError::DeviceInfo)?;
                (u16::from(info.operation_value.0), info.dynamic_population)
            }
        };

        self.reservation_supported = reservation_supported;
        if count == 0 {
            self.next_id = None;
        } else if reservation_supported {
            self.reserve()?;
        }
        self.initialized = true;
        Ok(())
    }

    fn read_bytes(
        &mut self,
        record_id: sdr::RecordId,
        start: u16,
        length: usize,
        expected_next: Option<sdr::RecordId>,
    ) -> Result<(Vec<u8>, sdr::RecordId), SdrError<CON::Error>> {
        let mut data = Vec::with_capacity(length);
        let mut next_id = expected_next;
        while data.len() < length {
            let offset = start + data.len() as u16;
            let offset_u8 = u8::try_from(offset)
                .map_err(|_| SdrError::Protocol(SdrProtocolError::OffsetOutOfRange(offset)))?;
            let requested = (length - data.len()).min(usize::from(self.read_limit)) as u8;
            let count = sdr::SdrReadLength::new(requested).expect("read_limit is always 1..=32");
            let chunk = match self.source.expect("source initialized") {
                SdrSource::Repository => self.ipmi.send_recv(sdr::ReadSdr::new(
                    self.reservation,
                    record_id,
                    offset_u8,
                    count,
                )),
                SdrSource::Device => self.ipmi.send_recv(sdr::ReadDeviceSdr::new(
                    self.reservation,
                    record_id,
                    offset_u8,
                    count,
                )),
            };
            let chunk = match chunk {
                Err(IpmiError::Failed {
                    completion_code, ..
                }) if matches!(
                    completion_code,
                    CompletionErrorCode::CannotReturnNumOfRequestedBytes
                        | CompletionErrorCode::RequestDataLenInvalid
                        | CompletionErrorCode::RequestDataLengthLimitExceeded
                ) && requested > 1 =>
                {
                    self.read_limit = (requested / 2).max(1);
                    continue;
                }
                Err(e) => return Err(SdrError::Read(e)),
                Ok(chunk) => chunk,
            };

            if chunk.data.len() != requested as usize {
                return Err(SdrError::Protocol(SdrProtocolError::IncorrectChunkLength {
                    offset,
                    expected: requested,
                    actual: chunk.data.len(),
                }));
            }
            if let Some(expected) = next_id {
                if chunk.next_entry != expected {
                    return Err(SdrError::Protocol(SdrProtocolError::NextIdChanged {
                        expected,
                        actual: chunk.next_entry,
                    }));
                }
            } else {
                next_id = Some(chunk.next_entry);
            }
            data.extend_from_slice(&chunk.data);
        }
        Ok((data, next_id.expect("SDR header read is nonempty")))
    }

    fn read_record_once(
        &mut self,
        id: sdr::RecordId,
    ) -> Result<(SdrRecord, sdr::RecordId), SdrError<CON::Error>> {
        let (mut header, next_id) = self.read_bytes(id, 0, 5, None)?;
        let header_id = sdr::RecordId::new_raw(u16::from_le_bytes([header[0], header[1]]));
        if id.is_first() && (header_id.is_first() || header_id.is_last()) {
            return Err(SdrError::Protocol(SdrProtocolError::InvalidFirstRecordId));
        }
        if next_id.is_first() || next_id == id || self.seen.contains(&next_id.value()) {
            return Err(SdrError::Protocol(SdrProtocolError::RepeatedRecordId(
                next_id,
            )));
        }

        let body_id = if id.is_first() { header_id } else { id };
        let body_len = usize::from(header[4]);
        if body_len != 0 {
            let (body, _) = self.read_bytes(body_id, 5, body_len, Some(next_id))?;
            header.extend_from_slice(&body);
        }
        if !id.is_first() {
            header[..2].copy_from_slice(&id.value().to_le_bytes());
        }
        let record = SdrRecord::parse(&header).map_err(|error| SdrError::Parse {
            record_id: id,
            error,
        })?;
        Ok((record, next_id))
    }

    fn read_record(
        &mut self,
        id: sdr::RecordId,
    ) -> Result<(SdrRecord, sdr::RecordId), SdrError<CON::Error>> {
        // A cancelled reservation can invalidate a partial record. Discard
        // every byte and reread its header after each successful renewal.
        for attempt in 0..=3 {
            let result = self.read_record_once(id);
            if matches!(
                result,
                Err(SdrError::Read(IpmiError::Failed {
                    completion_code: CompletionErrorCode::ReservationCancelledOrInvalidId,
                    ..
                }))
            ) && self.reservation_supported
            {
                if attempt == 3 {
                    return Err(SdrError::ReservationLost(id));
                }
                self.reserve()?;
                continue;
            }
            return result;
        }
        unreachable!()
    }
}

impl<CON: connection::IpmiConnection> Iterator for FallibleSdrIter<'_, CON> {
    type Item = Result<SdrRecord, SdrError<CON::Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_id?;
        if !self.initialized {
            if let Err(err) = self.initialize() {
                self.next_id = None;
                return Some(Err(err));
            }
        }
        let current_id = self.next_id.take()?;
        if current_id.is_last() {
            return None;
        }
        if !self.seen.insert(current_id.value()) {
            return Some(Err(SdrError::Protocol(SdrProtocolError::RepeatedRecordId(
                current_id,
            ))));
        }
        match self.read_record(current_id) {
            Ok((record, next_id)) => {
                self.next_id = Some(next_id);
                Some(Ok(record))
            }
            Err(err) => Some(Err(err)),
        }
    }
}

/// Legacy infallible repository iterator. Errors are logged and terminate
/// iteration; use [`Ipmi::sdrs_fallible`] to observe them.
pub struct SdrIter<'ipmi, CON> {
    inner: FallibleSdrIter<'ipmi, CON>,
}

impl<T> Iterator for SdrIter<'_, T>
where
    T: connection::IpmiConnection,
{
    type Item = SdrRecord;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next()? {
            Ok(record) => Some(record),
            Err(err) => {
                log::error!("SDR traversal failed: {err:?}");
                None
            }
        }
    }
}

#[cfg(test)]
mod sensor_threshold_tests;
