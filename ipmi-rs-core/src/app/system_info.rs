//! Bounded Get/Set System Info Parameters (App `0x59`/`0x58`).
//!
//! String parameters are split into a 14-byte first set and 16-byte later
//! sets. Set-in-progress is parameter zero; transaction changes are explicit.

use crate::connection::{CompletionErrorCode, IpmiCommand, Message, NetFn};

/// Supported standard System Info parameter selectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemInfoSelector {
    /// Set-in-progress transaction state.
    SetInProgress,
    /// System firmware version.
    FirmwareVersion,
    /// System name.
    SystemName,
    /// Primary operating system name.
    PrimaryOsName,
    /// Operating system name.
    OsName,
    /// Operating system version.
    OsVersion,
    /// BMC URL.
    BmcUrl,
    /// Management URL.
    ManagementUrl,
}

impl SystemInfoSelector {
    /// Wire selector.
    pub const fn value(self) -> u8 {
        match self {
            Self::SetInProgress => 0,
            Self::FirmwareVersion => 1,
            Self::SystemName => 2,
            Self::PrimaryOsName => 3,
            Self::OsName => 4,
            Self::OsVersion => 5,
            Self::BmcUrl => 6,
            Self::ManagementUrl => 7,
        }
    }
}

impl TryFrom<u8> for SystemInfoSelector {
    type Error = SystemInfoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SetInProgress),
            1 => Ok(Self::FirmwareVersion),
            2 => Ok(Self::SystemName),
            3 => Ok(Self::PrimaryOsName),
            4 => Ok(Self::OsName),
            5 => Ok(Self::OsVersion),
            6 => Ok(Self::BmcUrl),
            7 => Ok(Self::ManagementUrl),
            _ => Err(SystemInfoError::UnsupportedSelector(value)),
        }
    }
}

/// Status of a System Info write transaction (selector zero).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemInfoSetInProgress {
    /// Set complete.
    Complete,
    /// Set in progress.
    InProgress,
    /// Commit the pending changes.
    CommitWrite,
}

impl SystemInfoSetInProgress {
    /// Wire value.
    pub const fn value(self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::InProgress => 1,
            Self::CommitWrite => 2,
        }
    }
}

impl TryFrom<u8> for SystemInfoSetInProgress {
    type Error = SystemInfoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Complete),
            1 => Ok(Self::InProgress),
            2 => Ok(Self::CommitWrite),
            _ => Err(SystemInfoError::InvalidField("set-in-progress", value)),
        }
    }
}

/// Encoding declared in the first set of a string parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemInfoEncoding {
    /// ASCII plus Latin-1.
    AsciiLatin1,
    /// UTF-8.
    Utf8,
    /// Unicode (UTF-16) bytes, preserved without guessing endianness.
    Unicode,
}

impl SystemInfoEncoding {
    /// Encoding nibble.
    pub const fn value(self) -> u8 {
        match self {
            Self::AsciiLatin1 => 0,
            Self::Utf8 => 1,
            Self::Unicode => 2,
        }
    }
}

impl TryFrom<u8> for SystemInfoEncoding {
    type Error = SystemInfoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::AsciiLatin1),
            1 => Ok(Self::Utf8),
            2 => Ok(Self::Unicode),
            _ => Err(SystemInfoError::InvalidField("string encoding", value)),
        }
    }
}

/// Read a standard System Info parameter, at one set/block selector.
///
/// Readbacks are returned as [`SystemInfoResponse`]; call `decode` with
/// the request's selector and set selector to check the echoed set number
/// and interpret the parameter bytes. Block selector zero is used for the
/// standard string parameters.
#[derive(Clone, Copy, Debug)]
pub struct GetSystemInfoParameter {
    /// Requested parameter.
    selector: SystemInfoSelector,
    /// String set selector (zero for transaction state or first string set).
    set_selector: u8,
    /// Block selector (zero for standard parameters).
    block_selector: u8,
}

impl GetSystemInfoParameter {
    /// Read one set of a standard string parameter (block selector zero).
    pub fn string(selector: SystemInfoSelector, set_selector: u8) -> Result<Self, SystemInfoError> {
        if selector == SystemInfoSelector::SetInProgress || set_selector > 16 {
            return Err(SystemInfoError::InvalidSelector);
        }
        Ok(Self {
            selector,
            set_selector,
            block_selector: 0,
        })
    }

    /// Read the set-in-progress state.
    pub fn set_in_progress() -> Self {
        Self {
            selector: SystemInfoSelector::SetInProgress,
            set_selector: 0,
            block_selector: 0,
        }
    }

    /// Decode a response with this request's expected selector and set.
    pub fn decode(self, response: &SystemInfoResponse) -> Result<SystemInfoValue, SystemInfoError> {
        if self.block_selector != 0 {
            return Err(SystemInfoError::InvalidSelector);
        }
        response.decode(self.selector, self.set_selector)
    }
}

impl From<GetSystemInfoParameter> for Message {
    fn from(value: GetSystemInfoParameter) -> Self {
        Message::new_request(
            NetFn::App,
            0x59,
            vec![
                0,
                value.selector.value(),
                value.set_selector,
                value.block_selector,
            ],
        )
    }
}

impl IpmiCommand for GetSystemInfoParameter {
    type Output = SystemInfoResponse;
    type Error = SystemInfoError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        completion_error(code)
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.len() < 2 {
            return Err(SystemInfoError::Length {
                expected: 2,
                actual: data.len(),
            });
        }
        if data[0] != 0x11 {
            return Err(SystemInfoError::Revision(data[0]));
        }
        Ok(SystemInfoResponse {
            revision: data[0],
            data: data[1..].to_vec(),
        })
    }
}

/// A version-checked Get response. Parameter 0 and string sets have different
/// formats, so decode using the original request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemInfoResponse {
    /// Parameter revision (expected `0x11`).
    pub revision: u8,
    /// Parameter bytes excluding revision.
    pub data: Vec<u8>,
}

impl SystemInfoResponse {
    /// Validate the parameter's structure, reserved bits and echoed set selector.
    pub fn decode(
        &self,
        selector: SystemInfoSelector,
        set_selector: u8,
    ) -> Result<SystemInfoValue, SystemInfoError> {
        if self.revision != 0x11 {
            return Err(SystemInfoError::Revision(self.revision));
        }
        if selector == SystemInfoSelector::SetInProgress {
            if set_selector != 0 {
                return Err(SystemInfoError::InvalidSelector);
            }
            if self.data.len() != 1 {
                return Err(SystemInfoError::Length {
                    expected: 1,
                    actual: self.data.len(),
                });
            }
            return Ok(SystemInfoValue::SetInProgress(self.data[0].try_into()?));
        }
        if set_selector > 16 {
            return Err(SystemInfoError::InvalidSelector);
        }
        let Some((&echo, data)) = self.data.split_first() else {
            return Err(SystemInfoError::Length {
                expected: 1,
                actual: 0,
            });
        };
        if echo != set_selector {
            return Err(SystemInfoError::UnexpectedSet {
                expected: set_selector,
                actual: echo,
            });
        }
        if set_selector == 0 {
            if data.len() < 2 || data.len() > 16 {
                return Err(SystemInfoError::Length {
                    expected: 16,
                    actual: data.len(),
                });
            }
            if data[0] & 0xf0 != 0 {
                return Err(SystemInfoError::InvalidField("string encoding", data[0]));
            }
            let encoding = SystemInfoEncoding::try_from(data[0])?;
            let total_length = data[1] as usize;
            if data.len() - 2 < total_length.min(14) {
                return Err(SystemInfoError::Length {
                    expected: total_length.min(14) + 2,
                    actual: data.len(),
                });
            }
            Ok(SystemInfoValue::StringBlock(SystemInfoStringBlock {
                selector,
                set_selector,
                encoding: Some(encoding),
                total_length: Some(data[1]),
                bytes: data[2..].to_vec(),
            }))
        } else {
            if data.is_empty() || data.len() > 16 {
                return Err(SystemInfoError::Length {
                    expected: 16,
                    actual: data.len(),
                });
            }
            Ok(SystemInfoValue::StringBlock(SystemInfoStringBlock {
                selector,
                set_selector,
                encoding: None,
                total_length: None,
                bytes: data.to_vec(),
            }))
        }
    }
}

/// Validated System Info parameter value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SystemInfoValue {
    /// Parameter zero.
    SetInProgress(SystemInfoSetInProgress),
    /// A string parameter set.
    StringBlock(SystemInfoStringBlock),
}

/// One decoded string set. Padding bytes can be present after the logical end
/// of the string; [`SystemInfoString::assemble`] trims them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemInfoStringBlock {
    /// Which parameter was requested.
    pub selector: SystemInfoSelector,
    /// Echoed set number.
    pub set_selector: u8,
    /// Encoding in the first set.
    pub encoding: Option<SystemInfoEncoding>,
    /// Total string length in bytes, in the first set.
    pub total_length: Option<u8>,
    /// Up to 14 bytes in set zero, up to 16 thereafter.
    pub bytes: Vec<u8>,
}

/// A bounded standard System Info string, in its declared wire encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemInfoString {
    /// Standard parameter selector (not parameter zero).
    selector: SystemInfoSelector,
    /// Declared encoding.
    encoding: SystemInfoEncoding,
    /// Encoded bytes, length at most 255.
    bytes: Vec<u8>,
}

impl SystemInfoString {
    /// Validate a string before generating any write commands.
    pub fn new(
        selector: SystemInfoSelector,
        encoding: SystemInfoEncoding,
        bytes: Vec<u8>,
    ) -> Result<Self, SystemInfoError> {
        if selector == SystemInfoSelector::SetInProgress {
            return Err(SystemInfoError::InvalidSelector);
        }
        if bytes.len() > 255 {
            return Err(SystemInfoError::TooLong(bytes.len()));
        }
        if encoding == SystemInfoEncoding::Utf8 && core::str::from_utf8(&bytes).is_err() {
            return Err(SystemInfoError::InvalidEncoding);
        }
        if encoding == SystemInfoEncoding::Unicode && !bytes.len().is_multiple_of(2) {
            return Err(SystemInfoError::InvalidEncoding);
        }
        Ok(Self {
            selector,
            encoding,
            bytes,
        })
    }

    /// Standard parameter selector for this string.
    pub fn selector(&self) -> SystemInfoSelector {
        self.selector
    }

    /// Declared string encoding.
    pub fn encoding(&self) -> SystemInfoEncoding {
        self.encoding
    }

    /// Encoded string bytes, including any non-UTF-8 Latin-1 or Unicode data.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Assemble checked consecutive sets (set zero followed by sets 1..N).
    pub fn assemble(blocks: &[SystemInfoStringBlock]) -> Result<Self, SystemInfoError> {
        let first = blocks.first().ok_or(SystemInfoError::MissingSet(0))?;
        if first.set_selector != 0 {
            return Err(SystemInfoError::MissingSet(0));
        }
        let encoding = first.encoding.ok_or(SystemInfoError::MissingSet(0))?;
        let total = first.total_length.ok_or(SystemInfoError::MissingSet(0))? as usize;
        let mut bytes = Vec::with_capacity(total);
        let required = 1 + total.saturating_sub(14).div_ceil(16);
        if blocks.len() != required {
            return Err(SystemInfoError::WrongSetCount {
                expected: required,
                actual: blocks.len(),
            });
        }
        for (index, block) in blocks.iter().enumerate() {
            if block.selector != first.selector || block.set_selector != index as u8 {
                return Err(SystemInfoError::UnexpectedSet {
                    expected: index as u8,
                    actual: block.set_selector,
                });
            }
            let needed = if index == 0 {
                total.min(14)
            } else {
                (total - 14 - (index - 1) * 16).min(16)
            };
            if block.bytes.len() < needed
                || block.bytes.len() > if index == 0 { 14 } else { 16 }
                || (index > 0 && (block.encoding.is_some() || block.total_length.is_some()))
            {
                return Err(SystemInfoError::Length {
                    expected: needed,
                    actual: block.bytes.len(),
                });
            }
            bytes.extend_from_slice(&block.bytes[..needed]);
        }
        Self::new(first.selector, encoding, bytes)
    }

    /// Explicit per-set writes, with zero-padded 16-byte data areas.
    ///
    /// Callers should coordinate multi-set writes using parameter zero or
    /// [`system_info_write_guarded`]. No sends or retries are performed here.
    pub fn to_writes(&self) -> Vec<SetSystemInfoParameter> {
        let mut writes = vec![SetSystemInfoParameter::first(
            self.selector,
            self.encoding,
            self.bytes.len() as u8,
            &self.bytes[..self.bytes.len().min(14)],
        )
        .expect("validated string")];
        for (index, chunk) in self.bytes[self.bytes.len().min(14)..]
            .chunks(16)
            .enumerate()
        {
            writes.push(
                SetSystemInfoParameter::next(self.selector, index as u8 + 1, chunk)
                    .expect("validated string"),
            );
        }
        writes
    }
}

/// One explicit Set System Info Parameters (App `0x58`) write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetSystemInfoParameter {
    selector: SystemInfoSelector,
    bytes: Vec<u8>,
}

impl SetSystemInfoParameter {
    /// Write parameter zero's transaction state.
    pub fn set_in_progress(state: SystemInfoSetInProgress) -> Self {
        Self {
            selector: SystemInfoSelector::SetInProgress,
            bytes: vec![state.value()],
        }
    }

    /// Write the first string set; the length is the full encoded byte length.
    pub fn first(
        selector: SystemInfoSelector,
        encoding: SystemInfoEncoding,
        total_length: u8,
        data: &[u8],
    ) -> Result<Self, SystemInfoError> {
        if selector == SystemInfoSelector::SetInProgress {
            return Err(SystemInfoError::InvalidSelector);
        }
        let needed = usize::from(total_length).min(14);
        if data.len() != needed {
            return Err(SystemInfoError::Length {
                expected: needed,
                actual: data.len(),
            });
        }
        let mut bytes = vec![0, encoding.value(), total_length];
        bytes.extend_from_slice(data);
        bytes.resize(17, 0);
        Ok(Self { selector, bytes })
    }

    /// Write a subsequent string set (1..=16); no implicit writes are made.
    pub fn next(
        selector: SystemInfoSelector,
        set_selector: u8,
        data: &[u8],
    ) -> Result<Self, SystemInfoError> {
        if selector == SystemInfoSelector::SetInProgress || !(1..=16).contains(&set_selector) {
            return Err(SystemInfoError::InvalidSelector);
        }
        if data.is_empty() || data.len() > 16 {
            return Err(SystemInfoError::Length {
                expected: 16,
                actual: data.len(),
            });
        }
        let mut bytes = vec![set_selector];
        bytes.extend_from_slice(data);
        bytes.resize(17, 0);
        Ok(Self { selector, bytes })
    }
}

impl From<SetSystemInfoParameter> for Message {
    fn from(value: SetSystemInfoParameter) -> Self {
        let mut data = Vec::with_capacity(1 + value.bytes.len());
        data.push(value.selector.value());
        data.extend(value.bytes);
        Message::new_request(NetFn::App, 0x58, data)
    }
}

impl IpmiCommand for SetSystemInfoParameter {
    type Output = ();
    type Error = SystemInfoError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        completion_error(code)
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(SystemInfoError::Length {
                expected: 0,
                actual: data.len(),
            })
        }
    }
}

/// Command-specific system-info rejection; completion codes remain available
/// in `IpmiError` from `Ipmi::send_recv`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemInfoRejection {
    /// Parameter unsupported (`0x80`).
    UnsupportedParameter,
    /// Cannot start a transaction while another is in progress (`0x81`).
    AlreadyInProgress,
    /// Parameter read-only (`0x82`).
    ReadOnly,
}

fn completion_error(code: CompletionErrorCode) -> Option<SystemInfoError> {
    match code {
        CompletionErrorCode::CommandSpecific(0x80) => Some(SystemInfoError::Rejected(
            SystemInfoRejection::UnsupportedParameter,
        )),
        CompletionErrorCode::CommandSpecific(0x81) => Some(SystemInfoError::Rejected(
            SystemInfoRejection::AlreadyInProgress,
        )),
        CompletionErrorCode::CommandSpecific(0x82) => {
            Some(SystemInfoError::Rejected(SystemInfoRejection::ReadOnly))
        }
        _ => None,
    }
}

/// Invalid System Info request, readback or command-specific rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemInfoError {
    /// Unsupported (including OEM) selector.
    UnsupportedSelector(u8),
    /// Inconsistent selector/set index.
    InvalidSelector,
    /// Unsupported parameter revision.
    Revision(u8),
    /// Invalid value or reserved bits (field name and raw byte).
    InvalidField(&'static str, u8),
    /// Malformed encoding of the declared string.
    InvalidEncoding,
    /// Expected and actual lengths.
    Length { expected: usize, actual: usize },
    /// Declared string is longer than 255 bytes.
    TooLong(usize),
    /// Controller echoed a different set.
    UnexpectedSet { expected: u8, actual: u8 },
    /// First set is missing.
    MissingSet(u8),
    /// Expected and actual number of consecutive sets.
    WrongSetCount { expected: usize, actual: usize },
    /// A controller rejected the command.
    Rejected(SystemInfoRejection),
}

/// At most one begin, each block once, one commit, and one set-complete cleanup.
///
/// A failed write is *not* retried. Even a timeout may mean it was applied.
/// If begin fails, no cleanup is sent: the lock might belong to someone else.
/// The caller must decide how to recover from an ambiguous begin outcome.
/// After an acknowledged begin, this helper reports the first failed block
/// and cleanup/commit outcomes;
/// it cannot make a multi-message operation atomic on an unreliable link.
pub fn system_info_write_guarded<E>(
    mut send: impl FnMut(SetSystemInfoParameter) -> Result<(), E>,
    value: &SystemInfoString,
) -> Result<(), SystemInfoWriteError<E>> {
    let writes = value.to_writes();
    let state = |v| SetSystemInfoParameter::set_in_progress(v);
    if let Err(error) = send(state(SystemInfoSetInProgress::InProgress)) {
        return Err(SystemInfoWriteError::Begin { error });
    }
    let mut failed_block = None;
    for (index, write) in writes.into_iter().enumerate() {
        if let Err(error) = send(write) {
            failed_block = Some((index, error));
            break;
        }
    }
    let commit = if failed_block.is_none() {
        send(state(SystemInfoSetInProgress::CommitWrite)).err()
    } else {
        None
    };
    let cleanup = send(state(SystemInfoSetInProgress::Complete)).err();
    if failed_block.is_none() && commit.is_none() && cleanup.is_none() {
        Ok(())
    } else {
        Err(SystemInfoWriteError::Uncertain {
            failed_block,
            commit,
            cleanup,
        })
    }
}

/// Failed guarded write. A send failure/timeout may mean changes took effect.
#[derive(Debug, PartialEq, Eq)]
pub enum SystemInfoWriteError<E> {
    /// Could not confirm the begin; no cleanup is sent to avoid releasing another writer's lock.
    Begin {
        /// Begin error.
        error: E,
    },
    /// Write, commit, or cleanup failed; state on BMC cannot be inferred.
    Uncertain {
        /// Index of first failed set and its error, if any.
        failed_block: Option<(usize, E)>,
        /// Commit error, if any.
        commit: Option<E>,
        /// Cleanup error, if any.
        cleanup: Option<E>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_and_set_in_progress_fixtures() {
        for (raw, selector) in [
            (0, SystemInfoSelector::SetInProgress),
            (1, SystemInfoSelector::FirmwareVersion),
            (2, SystemInfoSelector::SystemName),
            (3, SystemInfoSelector::PrimaryOsName),
            (4, SystemInfoSelector::OsName),
            (5, SystemInfoSelector::OsVersion),
            (6, SystemInfoSelector::BmcUrl),
            (7, SystemInfoSelector::ManagementUrl),
        ] {
            assert_eq!(SystemInfoSelector::try_from(raw), Ok(selector));
        }
        assert_eq!(
            SystemInfoSelector::try_from(0xe4),
            Err(SystemInfoError::UnsupportedSelector(0xe4))
        );
        let get = GetSystemInfoParameter::set_in_progress();
        let msg: Message = get.into();
        assert_eq!(
            (msg.netfn_raw(), msg.cmd(), msg.data()),
            (6, 0x59, &[0, 0, 0, 0][..])
        );
        let raw = GetSystemInfoParameter::parse_success_response(&[0x11, 1]).unwrap();
        assert_eq!(
            get.decode(&raw),
            Ok(SystemInfoValue::SetInProgress(
                SystemInfoSetInProgress::InProgress
            ))
        );
        for state in [
            SystemInfoSetInProgress::Complete,
            SystemInfoSetInProgress::InProgress,
            SystemInfoSetInProgress::CommitWrite,
        ] {
            let msg: Message = SetSystemInfoParameter::set_in_progress(state).into();
            assert_eq!(
                (msg.netfn_raw(), msg.cmd(), msg.data()),
                (6, 0x58, &[0, state.value()][..])
            );
        }
        assert_eq!(SetSystemInfoParameter::parse_success_response(&[]), Ok(()));
        assert_eq!(
            SetSystemInfoParameter::parse_success_response(&[0]),
            Err(SystemInfoError::Length {
                expected: 0,
                actual: 1
            })
        );
    }

    #[test]
    fn string_blocks_roundtrip_and_wire_fixtures() {
        let value = SystemInfoString::new(
            SystemInfoSelector::SystemName,
            SystemInfoEncoding::Utf8,
            b"abcdefghijklmnopqrst".to_vec(),
        )
        .unwrap();
        let writes = value.to_writes();
        let first: Message = writes[0].clone().into();
        assert_eq!((first.netfn_raw(), first.cmd()), (6, 0x58));
        assert_eq!(
            first.data(),
            &[
                2, 0, 1, 20, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k',
                b'l', b'm', b'n'
            ]
        );
        let next: Message = writes[1].clone().into();
        assert_eq!(
            next.data(),
            &[2, 1, b'o', b'p', b'q', b'r', b's', b't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        let request = GetSystemInfoParameter::string(SystemInfoSelector::SystemName, 1).unwrap();
        let req: Message = request.into();
        assert_eq!(
            (req.netfn_raw(), req.cmd(), req.data()),
            (6, 0x59, &[0, 2, 1, 0][..])
        );
        let first = GetSystemInfoParameter::parse_success_response(&[
            0x11, 0, 1, 20, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l',
            b'm', b'n',
        ])
        .unwrap();
        let next = GetSystemInfoParameter::parse_success_response(&[
            0x11, 1, b'o', b'p', b'q', b'r', b's', b't',
        ])
        .unwrap();
        let SystemInfoValue::StringBlock(first) =
            first.decode(SystemInfoSelector::SystemName, 0).unwrap()
        else {
            panic!("not a string")
        };
        let SystemInfoValue::StringBlock(next) = request.decode(&next).unwrap() else {
            panic!("not a string")
        };
        assert_eq!(SystemInfoString::assemble(&[first, next]), Ok(value));
    }

    #[test]
    fn first_and_last_block_boundaries() {
        for len in [0, 1, 14, 15, 30, 31, 254, 255] {
            let string = SystemInfoString::new(
                SystemInfoSelector::ManagementUrl,
                SystemInfoEncoding::AsciiLatin1,
                vec![b'x'; len],
            )
            .unwrap();
            let writes = string.to_writes();
            assert_eq!(writes.len(), 1 + len.saturating_sub(14).div_ceil(16));
            let mut blocks = Vec::new();
            for (index, write) in writes.into_iter().enumerate() {
                let message: Message = write.into();
                assert_eq!(message.data().len(), 18);
                assert_eq!(message.data()[1], index as u8);
                let mut response = vec![0x11];
                response.extend_from_slice(&message.data()[1..]);
                let get =
                    GetSystemInfoParameter::string(SystemInfoSelector::ManagementUrl, index as u8)
                        .unwrap();
                let raw = GetSystemInfoParameter::parse_success_response(&response).unwrap();
                let SystemInfoValue::StringBlock(block) = get.decode(&raw).unwrap() else {
                    panic!("not a string")
                };
                blocks.push(block);
            }
            assert_eq!(SystemInfoString::assemble(&blocks), Ok(string));
        }
        assert!(SystemInfoString::new(
            SystemInfoSelector::BmcUrl,
            SystemInfoEncoding::Utf8,
            vec![b'x'; 256]
        )
        .is_err());
        assert!(SystemInfoString::new(
            SystemInfoSelector::BmcUrl,
            SystemInfoEncoding::Unicode,
            vec![1]
        )
        .is_err());
        assert!(GetSystemInfoParameter::string(SystemInfoSelector::BmcUrl, 17).is_err());
    }

    #[test]
    fn invalid_unsupported_truncated_and_nonconsecutive_fixtures() {
        for n in 0..2 {
            assert_eq!(
                GetSystemInfoParameter::parse_success_response(&vec![0x11; n]),
                Err(SystemInfoError::Length {
                    expected: 2,
                    actual: n
                })
            );
        }
        assert_eq!(
            GetSystemInfoParameter::parse_success_response(&[0x10, 0]),
            Err(SystemInfoError::Revision(0x10))
        );
        let state = GetSystemInfoParameter::set_in_progress();
        for (bytes, error) in [
            (
                vec![0x11, 3],
                SystemInfoError::InvalidField("set-in-progress", 3),
            ),
            (
                vec![0x11, 1, 0],
                SystemInfoError::Length {
                    expected: 1,
                    actual: 2,
                },
            ),
        ] {
            assert_eq!(
                state.decode(&GetSystemInfoParameter::parse_success_response(&bytes).unwrap()),
                Err(error)
            );
        }
        let get = GetSystemInfoParameter::string(SystemInfoSelector::OsName, 0).unwrap();
        for bytes in [
            &[0x11, 0, 0][..],
            &[0x11, 0, 0, 4, b'a'][..],
            &[0x11, 0, 0x10, 0][..],
        ] {
            assert!(get
                .decode(&GetSystemInfoParameter::parse_success_response(bytes).unwrap())
                .is_err());
        }
        let next = GetSystemInfoParameter::string(SystemInfoSelector::SystemName, 1).unwrap();
        assert_eq!(
            next.decode(&GetSystemInfoParameter::parse_success_response(&[0x11, 2, b'x']).unwrap()),
            Err(SystemInfoError::UnexpectedSet {
                expected: 1,
                actual: 2
            })
        );
        assert!(SetSystemInfoParameter::first(
            SystemInfoSelector::SystemName,
            SystemInfoEncoding::Utf8,
            15,
            b"short"
        )
        .is_err());
        assert!(SetSystemInfoParameter::next(SystemInfoSelector::SetInProgress, 1, b"x").is_err());
        assert!(SystemInfoString::new(
            SystemInfoSelector::SystemName,
            SystemInfoEncoding::Utf8,
            vec![0xff]
        )
        .is_err());
        assert_eq!(
            GetSystemInfoParameter::handle_completion_code(
                CompletionErrorCode::CommandSpecific(0x80),
                &[]
            ),
            Some(SystemInfoError::Rejected(
                SystemInfoRejection::UnsupportedParameter
            ))
        );
        assert_eq!(
            SetSystemInfoParameter::handle_completion_code(
                CompletionErrorCode::CommandSpecific(0x81),
                &[]
            ),
            Some(SystemInfoError::Rejected(
                SystemInfoRejection::AlreadyInProgress
            ))
        );
        assert_eq!(
            SetSystemInfoParameter::handle_completion_code(
                CompletionErrorCode::CommandSpecific(0x82),
                &[]
            ),
            Some(SystemInfoError::Rejected(SystemInfoRejection::ReadOnly))
        );
    }

    #[test]
    fn bounded_guard_preserves_all_errors_and_never_retries() {
        let value = SystemInfoString::new(
            SystemInfoSelector::OsName,
            SystemInfoEncoding::AsciiLatin1,
            vec![b'a'; 30],
        )
        .unwrap();
        let mut sent = Vec::new();
        let failure = system_info_write_guarded(
            |write| {
                let data = Message::from(write).data().to_vec();
                sent.push(data.clone());
                if data[0] == 4 && data[1] == 1 {
                    Err("lost ack")
                } else if data == [0, 0] {
                    Err("cleanup")
                } else {
                    Ok(())
                }
            },
            &value,
        );
        assert_eq!(
            failure,
            Err(SystemInfoWriteError::Uncertain {
                failed_block: Some((1, "lost ack")),
                commit: None,
                cleanup: Some("cleanup")
            })
        );
        assert_eq!(sent.len(), 4); // begin, first, failed second, cleanup; no third or commit
        let mut sent = Vec::new();
        let failure = system_info_write_guarded(
            |write| {
                let data = Message::from(write).data().to_vec();
                sent.push(data);
                Err::<(), _>("not acknowledged")
            },
            &value,
        );
        assert_eq!(
            failure,
            Err(SystemInfoWriteError::Begin {
                error: "not acknowledged"
            })
        );
        assert_eq!(sent, vec![vec![0, 1]]);

        let mut sent = Vec::new();
        let success = system_info_write_guarded(
            |write| {
                sent.push(Message::from(write).data().to_vec());
                Ok::<(), &str>(())
            },
            &value,
        );
        assert_eq!(success, Ok(()));
        assert_eq!(sent.len(), value.to_writes().len() + 3);
        assert_eq!(sent[0], vec![0, 1]);
        assert_eq!(sent[sent.len() - 2], vec![0, 2]);
        assert_eq!(sent[sent.len() - 1], vec![0, 0]);

        let failure = system_info_write_guarded(
            |write| {
                if Message::from(write).data() == [0, 2] {
                    Err("commit")
                } else {
                    Ok(())
                }
            },
            &value,
        );
        assert_eq!(
            failure,
            Err(SystemInfoWriteError::Uncertain {
                failed_block: None,
                commit: Some("commit"),
                cleanup: None
            })
        );
    }
}
