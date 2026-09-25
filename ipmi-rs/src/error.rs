use crate::connection::{CompletionErrorCode, NetFn};
use ipmi_rs_core::sensor_event::pef::{PefBeginError, PefError};

#[derive(Clone, Debug, PartialEq)]
pub enum IpmiError<CON, P> {
    NetFnIsResponse(NetFn),
    UnexpectedResponse {
        netfn_sent: NetFn,
        netfn_recvd: NetFn,
        cmd_sent: u8,
        cmd_recvd: u8,
    },
    Failed {
        netfn: NetFn,
        cmd: u8,
        completion_code: CompletionErrorCode,
        data: Vec<u8>,
    },
    Command {
        error: P,
        netfn: NetFn,
        cmd: u8,
        completion_code: Option<CompletionErrorCode>,
        data: Vec<u8>,
    },
    Connection(CON),
}

impl<CON, P> From<CON> for IpmiError<CON, P> {
    fn from(value: CON) -> Self {
        Self::Connection(value)
    }
}

impl<CON, P> IpmiError<CON, P> {
    pub fn map<CON2, F>(self, f: F) -> IpmiError<CON2, P>
    where
        F: FnOnce(CON) -> CON2,
    {
        match self {
            IpmiError::NetFnIsResponse(v) => IpmiError::NetFnIsResponse(v),
            IpmiError::UnexpectedResponse {
                netfn_sent,
                netfn_recvd,
                cmd_sent,
                cmd_recvd,
            } => IpmiError::UnexpectedResponse {
                netfn_sent,
                netfn_recvd,
                cmd_sent,
                cmd_recvd,
            },
            IpmiError::Command {
                error,
                netfn,
                cmd,
                completion_code,
                data,
            } => IpmiError::Command {
                error,
                netfn,
                cmd,
                completion_code,
                data,
            },
            IpmiError::Failed {
                netfn,
                cmd,
                completion_code,
                data,
            } => IpmiError::Failed {
                netfn,
                cmd,
                completion_code,
                data,
            },
            IpmiError::Connection(e) => IpmiError::Connection(f(e)),
        }
    }
}

impl<CON> PefBeginError for IpmiError<CON, PefError> {
    fn confirmed_rejection(&self) -> bool {
        matches!(
            self,
            Self::Failed {
                netfn: NetFn::SensorEvent,
                cmd: 0x12,
                ..
            } | Self::Command {
                netfn: NetFn::SensorEvent,
                cmd: 0x12,
                completion_code: Some(_),
                ..
            }
        )
    }
}

#[cfg(test)]
mod pef_tests {
    use super::*;
    use ipmi_rs_core::sensor_event::pef::{
        pef_write_guarded, PefChange, PefFilterId, PefRejection, PefSetInProgress, PefTableSize,
        PefWrite, PefWriteError,
    };

    #[test]
    fn pef_begin_only_skips_cleanup_for_confirmed_completion_codes() {
        let rejected: IpmiError<(), PefError> = IpmiError::Command {
            error: PefError::Rejected(PefRejection::AlreadyInProgress),
            netfn: NetFn::SensorEvent,
            cmd: 0x12,
            completion_code: Some(CompletionErrorCode::CommandSpecific(0x81)),
            data: vec![],
        };
        assert!(rejected.confirmed_rejection());
        assert!(IpmiError::<(), PefError>::Failed {
            netfn: NetFn::SensorEvent,
            cmd: 0x12,
            completion_code: CompletionErrorCode::ParameterOutOfRange,
            data: vec![],
        }
        .confirmed_rejection());
        assert!(!IpmiError::<(), PefError>::Failed {
            netfn: NetFn::Chassis,
            cmd: 0x12,
            completion_code: CompletionErrorCode::CommandSpecific(0x81),
            data: vec![],
        }
        .confirmed_rejection());
        assert!(!IpmiError::<(), PefError>::Command {
            error: PefError::InvalidLength {
                expected: 0,
                actual: 1,
            },
            netfn: NetFn::SensorEvent,
            cmd: 0x12,
            completion_code: None,
            data: vec![0],
        }
        .confirmed_rejection());
        assert!(!IpmiError::<(), PefError>::Connection(()).confirmed_rejection());
    }

    #[test]
    fn rejected_begin_never_cleans_up_but_lost_begin_preserves_cleanup_error() {
        let change = PefChange::FilterEnabled {
            id: PefFilterId::new(1, PefTableSize::new(1).unwrap()).unwrap(),
            enabled: true,
        };
        let rejected: IpmiError<(), PefError> = IpmiError::Command {
            error: PefError::Rejected(PefRejection::AlreadyInProgress),
            netfn: NetFn::SensorEvent,
            cmd: 0x12,
            completion_code: Some(CompletionErrorCode::CommandSpecific(0x81)),
            data: vec![],
        };
        let mut requests = Vec::new();
        let result = pef_write_guarded(
            |request| {
                requests.push(request.value);
                Err::<(), _>(rejected.clone())
            },
            change,
        );
        assert_eq!(
            result,
            Err(PefWriteError::Begin {
                error: rejected,
                cleanup: None
            })
        );
        assert_eq!(
            requests,
            [PefWrite::SetInProgress(PefSetInProgress::InProgress)]
        );

        requests.clear();
        let result = pef_write_guarded(
            |request| {
                requests.push(request.value);
                Err::<(), IpmiError<(), PefError>>(IpmiError::Connection(()))
            },
            change,
        );
        assert_eq!(
            result,
            Err(PefWriteError::Begin {
                error: IpmiError::Connection(()),
                cleanup: Some(IpmiError::Connection(()))
            })
        );
        assert_eq!(
            requests,
            [
                PefWrite::SetInProgress(PefSetInProgress::InProgress),
                PefWrite::SetInProgress(PefSetInProgress::Complete)
            ]
        );
    }
}
