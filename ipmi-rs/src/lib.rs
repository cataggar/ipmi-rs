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

mod error;
pub use error::IpmiError;

mod sel;
pub use sel::{SelIter, SelIterError, SelMutationError};

use ipmi_rs_core::{
    connection::{CompletionErrorCode, IpmiCommand, LogicalUnit, Request, RequestTargetAddress},
    storage::sdr::{self, Record as SdrRecord},
};

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
            ipmi: self,
            next_id: Some(sdr::RecordId::FIRST),
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

    pub fn send_recv<CMD>(
        &mut self,
        request: CMD,
    ) -> Result<CMD::Output, IpmiError<CON::Error, CMD::Error>>
    where
        CMD: IpmiCommand,
    {
        let target_address = match request.target() {
            Some((a, c)) => RequestTargetAddress::BmcOrIpmb(a, c, LogicalUnit::Zero),
            None => RequestTargetAddress::Bmc(LogicalUnit::Zero),
        };

        let message = request.into();
        let (message_netfn, message_cmd) = (message.netfn(), message.cmd());
        let mut request = Request::new(message, target_address);

        let response = self.inner.send_recv(&mut request)?;

        if response.netfn() != message_netfn || response.cmd() != message_cmd {
            return Err(IpmiError::UnexpectedResponse {
                netfn_sent: message_netfn,
                netfn_recvd: response.netfn(),
                cmd_sent: message_cmd,
                cmd_recvd: response.cmd(),
            });
        }

        // A malformed or hostile password response might echo the secret.
        // Keep its completion code, but never attach response bytes to a
        // Debug-printable error for this command.
        let error_data = || {
            if response.netfn() == connection::NetFn::App && response.cmd() == 0x47 {
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

        CMD::parse_success_response(response.data()).map_err(|err| map_error(None, err))
    }
}

pub struct SdrIter<'ipmi, CON> {
    ipmi: &'ipmi mut Ipmi<CON>,
    next_id: Option<sdr::RecordId>,
}

impl<T> Iterator for SdrIter<'_, T>
where
    T: connection::IpmiConnection,
{
    type Item = SdrRecord;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(current_id) = self.next_id.take() {
            if current_id.is_last() {
                return None;
            }

            let next_record = self
                .ipmi
                .send_recv(sdr::GetDeviceSdr::new(None, current_id));

            match next_record {
                Ok(record) => {
                    let next_record_id = record.next_entry;

                    if next_record_id == current_id {
                        log::error!("Got duplicate SDR record IDs! Stopping iteration.");
                        return None;
                    }

                    self.next_id = Some(next_record_id);
                    return Some(record.record);
                }
                Err(IpmiError::Command {
                    error: (e, Some(next_record_id)),
                    ..
                }) => {
                    log::warn!(
                        "Recoverable error while parsing SDR record 0x{:04X}: {e:?}. Skipping to next.",
                        current_id.value()
                    );
                    self.next_id = Some(next_record_id);
                    continue; // skip the current one
                }
                Err(e) => {
                    log::error!(
                        "Unrecoverable error while parsing SDR record 0x{:04X}: {e:?}",
                        current_id.value()
                    );
                    return None;
                }
            }
        }
        None
    }
}
