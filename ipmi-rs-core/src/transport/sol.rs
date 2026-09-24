//! Serial-over-LAN configuration commands (IPMI 2.0, section 26).
//! Configuration writes are explicit and never part of activating a capture.

use crate::{
    app::auth::PrivilegeLevel,
    connection::{Channel, IpmiCommand, Message, NetFn},
};

/// SOL configuration parameter selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolParameter {
    /// Write transaction status.
    SetInProgress,
    /// Whether SOL is enabled.
    Enabled,
    /// Authentication requirements and minimum privilege.
    Authentication,
    /// Character accumulation interval and send threshold.
    CharacterInterval,
    /// Retry count and interval.
    Retry,
    /// Persistent serial bitrate.
    NonVolatileBitRate,
    /// Current serial bitrate.
    VolatileBitRate,
    /// Channel carrying the payload.
    PayloadChannel,
    /// UDP port carrying the payload.
    PayloadPort,
}

impl SolParameter {
    /// Wire selector.
    pub fn value(self) -> u8 {
        match self {
            Self::SetInProgress => 0,
            Self::Enabled => 1,
            Self::Authentication => 2,
            Self::CharacterInterval => 3,
            Self::Retry => 4,
            Self::NonVolatileBitRate => 5,
            Self::VolatileBitRate => 6,
            Self::PayloadChannel => 7,
            Self::PayloadPort => 8,
        }
    }

    fn parse(self, data: &[u8]) -> Result<SolParameterValue, SolConfigError> {
        let expected = match self {
            Self::CharacterInterval | Self::Retry | Self::PayloadPort => 2,
            _ => 1,
        };
        if data.len() != expected {
            return Err(SolConfigError::InvalidLength(data.len()));
        }
        Ok(match self {
            Self::SetInProgress => SolParameterValue::SetInProgress(match data[0] {
                0 => SolSetInProgress::Complete,
                1 => SolSetInProgress::InProgress,
                2 => SolSetInProgress::CommitWrite,
                v => return Err(SolConfigError::InvalidValue(v)),
            }),
            Self::Enabled => SolParameterValue::Enabled(match data[0] {
                0 => false,
                1 => true,
                v => return Err(SolConfigError::InvalidValue(v)),
            }),
            Self::Authentication => SolParameterValue::Authentication {
                force_encryption: data[0] & 0x80 != 0,
                force_authentication: data[0] & 0x40 != 0,
                privilege: PrivilegeLevel::try_from(data[0] & 0x0f)
                    .map_err(|_| SolConfigError::InvalidValue(data[0] & 0x0f))?,
            },
            Self::CharacterInterval => SolParameterValue::CharacterInterval {
                accumulate: data[0],
                threshold: data[1],
            },
            Self::Retry => SolParameterValue::Retry {
                count: SolRetryCount::new(data[0]).ok_or(SolConfigError::InvalidValue(data[0]))?,
                interval: data[1],
            },
            Self::NonVolatileBitRate => {
                SolParameterValue::NonVolatileBitRate(SolBitRate::from(data[0] & 0x0f))
            }
            Self::VolatileBitRate => {
                SolParameterValue::VolatileBitRate(SolBitRate::from(data[0] & 0x0f))
            }
            Self::PayloadChannel => SolParameterValue::PayloadChannel(
                Channel::new(data[0] & 0x0f).ok_or(SolConfigError::InvalidValue(data[0] & 0x0f))?,
            ),
            Self::PayloadPort => {
                SolParameterValue::PayloadPort(u16::from_le_bytes([data[0], data[1]]))
            }
        })
    }
}

/// SOL write transaction state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolSetInProgress {
    /// Transaction finished.
    Complete,
    /// Changes being made.
    InProgress,
    /// Commit the pending changes.
    CommitWrite,
}

/// A SOL retry count (the three-bit parameter accepts values 0 through 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolRetryCount(u8);

impl SolRetryCount {
    /// Construct a valid retry count.
    pub fn new(count: u8) -> Option<Self> {
        (count <= 7).then_some(Self(count))
    }

    /// Get the wire value.
    pub fn value(self) -> u8 {
        self.0
    }
}

/// SOL serial link bitrate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolBitRate {
    /// Reuse the serial port's configured bitrate.
    Serial,
    /// 9600 bps.
    Baud9600,
    /// 19,200 bps.
    Baud19200,
    /// 38,400 bps.
    Baud38400,
    /// 57,600 bps.
    Baud57600,
    /// 115,200 bps.
    Baud115200,
    /// Unknown or vendor-specific bitrate code (explicitly preserved).
    Other(u8),
}

impl From<u8> for SolBitRate {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Serial,
            6 => Self::Baud9600,
            7 => Self::Baud19200,
            8 => Self::Baud38400,
            9 => Self::Baud57600,
            10 => Self::Baud115200,
            value => Self::Other(value),
        }
    }
}

impl SolBitRate {
    /// Return the four-bit SOL bitrate code.
    pub fn value(self) -> u8 {
        match self {
            Self::Serial => 0,
            Self::Baud9600 => 6,
            Self::Baud19200 => 7,
            Self::Baud38400 => 8,
            Self::Baud57600 => 9,
            Self::Baud115200 => 10,
            Self::Other(value) => value,
        }
    }
}

/// A typed SOL parameter value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SolParameterValue {
    /// Transaction state.
    SetInProgress(SolSetInProgress),
    /// Enablement.
    Enabled(bool),
    /// Minimum access requirements.
    Authentication {
        /// Require encrypted SOL.
        force_encryption: bool,
        /// Require authenticated SOL.
        force_authentication: bool,
        /// Minimum privilege.
        privilege: PrivilegeLevel,
    },
    /// Character accumulation (5ms units) and threshold.
    CharacterInterval {
        /// Accumulation interval.
        accumulate: u8,
        /// Send threshold.
        threshold: u8,
    },
    /// Retry count and interval (10ms units).
    Retry {
        /// Retry count.
        count: SolRetryCount,
        /// Retry interval.
        interval: u8,
    },
    /// Persistent serial bitrate.
    NonVolatileBitRate(SolBitRate),
    /// Current serial bitrate.
    VolatileBitRate(SolBitRate),
    /// Channel carrying the SOL payload.
    PayloadChannel(Channel),
    /// UDP port.
    PayloadPort(u16),
}

impl SolParameterValue {
    /// Selector associated with this value.
    pub fn parameter(self) -> SolParameter {
        match self {
            Self::SetInProgress(_) => SolParameter::SetInProgress,
            Self::Enabled(_) => SolParameter::Enabled,
            Self::Authentication { .. } => SolParameter::Authentication,
            Self::CharacterInterval { .. } => SolParameter::CharacterInterval,
            Self::Retry { .. } => SolParameter::Retry,
            Self::NonVolatileBitRate(_) => SolParameter::NonVolatileBitRate,
            Self::VolatileBitRate(_) => SolParameter::VolatileBitRate,
            Self::PayloadChannel(_) => SolParameter::PayloadChannel,
            Self::PayloadPort(_) => SolParameter::PayloadPort,
        }
    }

    fn bytes(self) -> Vec<u8> {
        match self {
            Self::SetInProgress(v) => vec![match v {
                SolSetInProgress::Complete => 0,
                SolSetInProgress::InProgress => 1,
                SolSetInProgress::CommitWrite => 2,
            }],
            Self::Enabled(v) => vec![u8::from(v)],
            Self::Authentication {
                force_encryption,
                force_authentication,
                privilege,
            } => vec![
                (u8::from(force_encryption) << 7)
                    | (u8::from(force_authentication) << 6)
                    | u8::from(privilege),
            ],
            Self::CharacterInterval {
                accumulate,
                threshold,
            } => vec![accumulate, threshold],
            Self::Retry { count, interval } => vec![count.value(), interval],
            Self::NonVolatileBitRate(v) | Self::VolatileBitRate(v) => vec![v.value()],
            Self::PayloadChannel(v) => vec![v.value()],
            Self::PayloadPort(v) => v.to_le_bytes().to_vec(),
        }
    }
}

/// Invalid SOL parameter response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolConfigError {
    /// Unsupported parameter revision.
    InvalidRevision(u8),
    /// Unexpected number of bytes.
    InvalidLength(usize),
    /// Invalid enum or boolean value.
    InvalidValue(u8),
}

/// Get SOL Configuration Parameters (Transport 0x22).
#[derive(Clone, Copy, Debug)]
pub struct GetSolConfig {
    /// Requested LAN channel.
    pub channel: Channel,
    /// Requested parameter.
    pub parameter: SolParameter,
}

impl From<GetSolConfig> for Message {
    fn from(value: GetSolConfig) -> Self {
        Message::new_request(
            NetFn::Transport,
            0x22,
            vec![value.channel.value(), value.parameter.value(), 0, 0],
        )
    }
}

/// Get response with its checked revision and typed value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SolConfigResponse {
    /// Parameter revision (1.1).
    pub revision: u8,
    /// Decoded parameter.
    pub value: SolParameterValue,
}

/// Response before applying the requested parameter's type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolConfigRaw {
    /// Parameter revision.
    pub revision: u8,
    /// Parameter bytes.
    pub data: Vec<u8>,
}

impl SolConfigRaw {
    /// Decode the bytes as a specific parameter.
    pub fn parse(&self, parameter: SolParameter) -> Result<SolConfigResponse, SolConfigError> {
        Ok(SolConfigResponse {
            revision: self.revision,
            value: parameter.parse(&self.data)?,
        })
    }
}

impl IpmiCommand for GetSolConfig {
    type Output = SolConfigRaw;
    type Error = SolConfigError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let Some((&revision, rest)) = data.split_first() else {
            return Err(SolConfigError::InvalidLength(0));
        };
        if revision != 0x11 {
            return Err(SolConfigError::InvalidRevision(revision));
        }
        Ok(SolConfigRaw {
            revision,
            data: rest.to_vec(),
        })
    }
}

impl GetSolConfig {
    /// Decode a response for this specific selector.
    pub fn parse_response(self, data: &[u8]) -> Result<SolConfigResponse, SolConfigError> {
        <Self as IpmiCommand>::parse_success_response(data)?.parse(self.parameter)
    }
}

/// Set SOL Configuration Parameters (Transport 0x21).
///
/// Only call this explicitly; captures never change configuration. For a guarded
/// multi-command write, use [`sol_write_guarded`].
#[derive(Clone, Copy, Debug)]
pub struct SetSolConfig {
    /// Requested LAN channel.
    pub channel: Channel,
    /// Value to write.
    pub value: SolParameterValue,
}

impl From<SetSolConfig> for Message {
    fn from(value: SetSolConfig) -> Self {
        let mut data = vec![value.channel.value(), value.value.parameter().value()];
        data.extend(value.value.bytes());
        Message::new_request(NetFn::Transport, 0x21, data)
    }
}

impl IpmiCommand for SetSolConfig {
    type Output = ();
    type Error = SolConfigError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(SolConfigError::InvalidLength(data.len()))
        }
    }
}

/// Apply a guarded SOL configuration write, bounded to begin, write, commit,
/// and cleanup (at most four requests). The cleanup result is never discarded.
pub fn sol_write_guarded<E: core::fmt::Debug>(
    mut send: impl FnMut(SetSolConfig) -> Result<(), E>,
    channel: Channel,
    value: SolParameterValue,
) -> Result<(), SolWriteError<E>> {
    let status = |status| SetSolConfig {
        channel,
        value: SolParameterValue::SetInProgress(status),
    };
    if let Err(error) = send(status(SolSetInProgress::InProgress)) {
        let cleanup = send(status(SolSetInProgress::Complete)).err();
        return Err(SolWriteError::Begin { error, cleanup });
    }
    let written = send(SetSolConfig { channel, value });
    let commit = if written.is_ok() {
        Some(send(status(SolSetInProgress::CommitWrite)))
    } else {
        None
    };
    let cleanup = send(status(SolSetInProgress::Complete));
    if written.is_ok() && commit.as_ref().is_some_and(Result::is_ok) && cleanup.is_ok() {
        Ok(())
    } else {
        Err(SolWriteError::Uncertain {
            write: written.err(),
            commit: commit.and_then(Result::err),
            cleanup: cleanup.err(),
        })
    }
}

/// Error from a guarded write. A failed request may still have taken effect.
#[derive(Debug)]
pub enum SolWriteError<E> {
    /// Could not confirm the transaction start; cleanup was still attempted.
    Begin {
        /// Begin error.
        error: E,
        /// Set-complete cleanup error, if any.
        cleanup: Option<E>,
    },
    /// Write, commit or cleanup failed; examine all three outcomes.
    Uncertain {
        /// Write failure, if any.
        write: Option<E>,
        /// Commit failure, if any.
        commit: Option<E>,
        /// Set-complete cleanup failure, if any.
        cleanup: Option<E>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_config_parameters_have_checked_lengths_and_wire_selectors() {
        let channel = Channel::Current;
        for (value, bytes) in [
            (
                SolParameterValue::SetInProgress(SolSetInProgress::Complete),
                vec![0x0e, 0, 0],
            ),
            (SolParameterValue::Enabled(true), vec![0x0e, 1, 1]),
            (
                SolParameterValue::Authentication {
                    force_encryption: true,
                    force_authentication: true,
                    privilege: PrivilegeLevel::Administrator,
                },
                vec![0x0e, 2, 0xc4],
            ),
            (
                SolParameterValue::CharacterInterval {
                    accumulate: 5,
                    threshold: 12,
                },
                vec![0x0e, 3, 5, 12],
            ),
            (
                SolParameterValue::Retry {
                    count: SolRetryCount::new(7).unwrap(),
                    interval: 50,
                },
                vec![0x0e, 4, 7, 50],
            ),
            (
                SolParameterValue::NonVolatileBitRate(SolBitRate::Baud115200),
                vec![0x0e, 5, 10],
            ),
            (
                SolParameterValue::VolatileBitRate(SolBitRate::Baud9600),
                vec![0x0e, 6, 6],
            ),
            (
                SolParameterValue::PayloadChannel(Channel::Current),
                vec![0x0e, 7, 0x0e],
            ),
            (SolParameterValue::PayloadPort(623), vec![0x0e, 8, 0x6f, 2]),
        ] {
            let selector = value.parameter();
            let message: Message = SetSolConfig { channel, value }.into();
            assert_eq!(message.cmd(), 0x21);
            assert_eq!(message.data(), bytes);
            let get: Message = GetSolConfig {
                channel,
                parameter: selector,
            }
            .into();
            assert_eq!(get.data(), [0x0e, selector.value(), 0, 0]);
            let mut response = vec![0x11];
            response.extend(&bytes[2..]);
            assert_eq!(
                GetSolConfig {
                    channel,
                    parameter: selector
                }
                .parse_response(&response)
                .unwrap()
                .value,
                value
            );
            assert!(matches!(
                GetSolConfig {
                    channel,
                    parameter: selector
                }
                .parse_response(&response[..response.len() - 1]),
                Err(SolConfigError::InvalidLength(_))
            ));
        }
        assert!(matches!(
            GetSolConfig {
                channel,
                parameter: SolParameter::Enabled
            }
            .parse_response(&[0x10, 1]),
            Err(SolConfigError::InvalidRevision(0x10))
        ));
        assert!(SolRetryCount::new(8).is_none());
        assert!(matches!(
            GetSolConfig {
                channel,
                parameter: SolParameter::Retry
            }
            .parse_response(&[0x11, 8, 1]),
            Err(SolConfigError::InvalidValue(8))
        ));
        assert!(matches!(
            GetSolConfig {
                channel,
                parameter: SolParameter::PayloadChannel
            }
            .parse_response(&[0x11, 0x0c]),
            Err(SolConfigError::InvalidValue(12))
        ));
    }

    #[test]
    fn guarded_write_always_attempts_cleanup() {
        let mut calls = Vec::new();
        let result = sol_write_guarded(
            |command| {
                calls.push(command.value);
                if matches!(command.value, SolParameterValue::Enabled(_))
                    || matches!(
                        command.value,
                        SolParameterValue::SetInProgress(SolSetInProgress::Complete)
                    )
                {
                    Err("failed")
                } else {
                    Ok(())
                }
            },
            Channel::Current,
            SolParameterValue::Enabled(true),
        );
        assert!(matches!(
            result,
            Err(SolWriteError::Uncertain {
                write: Some("failed"),
                commit: None,
                cleanup: Some("failed"),
            })
        ));
        assert_eq!(calls.len(), 3);
    }

    #[test]
    fn guarded_begin_and_commit_failures_report_cleanup() {
        let mut calls = Vec::new();
        let result = sol_write_guarded(
            |command| {
                calls.push(command.value);
                Err::<(), _>("failed")
            },
            Channel::Current,
            SolParameterValue::Enabled(true),
        );
        assert!(matches!(
            result,
            Err(SolWriteError::Begin {
                error: "failed",
                cleanup: Some("failed"),
            })
        ));
        assert_eq!(calls.len(), 2);

        calls.clear();
        let result = sol_write_guarded(
            |command| {
                calls.push(command.value);
                if matches!(
                    command.value,
                    SolParameterValue::SetInProgress(SolSetInProgress::CommitWrite)
                ) {
                    Err("commit failed")
                } else {
                    Ok(())
                }
            },
            Channel::Current,
            SolParameterValue::Enabled(true),
        );
        assert!(matches!(
            result,
            Err(SolWriteError::Uncertain {
                write: None,
                commit: Some("commit failed"),
                cleanup: None
            })
        ));
        assert_eq!(calls.len(), 4);
        let raw = <GetSolConfig as IpmiCommand>::parse_success_response(&[0x11, 1]).unwrap();
        assert_eq!(
            raw.parse(SolParameter::Enabled).unwrap().value,
            SolParameterValue::Enabled(true)
        );
    }
}
