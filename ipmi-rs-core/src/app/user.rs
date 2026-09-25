//! User management commands (IPMI App netfn).
//!
//! These commands only encode/decode messages; sending a mutation is always
//! explicit. A lost acknowledgement leaves the outcome unknown: do not retry
//! a write automatically, including on a busy or timeout completion code.

use crate::connection::{Channel, IpmiCommand, Message, NetFn};

/// A user ID on the BMC (1 through 63).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserId(u8);

impl UserId {
    /// Reject ID zero (reserved) and values that do not fit the six-bit field.
    pub const fn new(value: u8) -> Option<Self> {
        if value >= 1 && value <= 63 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Return the on-wire ID.
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// A privilege that can be assigned to a user or set as a channel limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserPrivilege {
    Callback,
    User,
    Operator,
    Administrator,
    Oem,
    NoAccess,
}

impl UserPrivilege {
    /// Only 1 through 5 and 15 are legal for a requested privilege.
    pub const fn new(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Callback),
            2 => Some(Self::User),
            3 => Some(Self::Operator),
            4 => Some(Self::Administrator),
            5 => Some(Self::Oem),
            15 => Some(Self::NoAccess),
            _ => None,
        }
    }

    /// Return the on-wire privilege nibble.
    pub const fn value(self) -> u8 {
        match self {
            Self::Callback => 1,
            Self::User => 2,
            Self::Operator => 3,
            Self::Administrator => 4,
            Self::Oem => 5,
            Self::NoAccess => 15,
        }
    }
}

/// An invalid length or non-printable/non-ASCII character in user-supplied text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserTextError {
    /// Text exceeded the selected field width.
    TooLong,
    /// Text was not printable US-ASCII (bytes 0x20 through 0x7E).
    InvalidEncoding,
}

/// A fixed-width, 16-byte username returned by the BMC.
///
/// Raw bytes are retained, including unknown encodings and bytes after a NUL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserName([u8; 16]);

impl UserName {
    /// Return all 16 bytes, without altering a BMC's response.
    pub fn raw(&self) -> &[u8; 16] {
        &self.0
    }

    /// Interpret the bytes before the first NUL as UTF-8, if valid.
    pub fn as_str(&self) -> Option<&str> {
        let end = self.0.iter().position(|&v| v == 0).unwrap_or(16);
        core::str::from_utf8(&self.0[..end]).ok()
    }
}

/// Get a user's 16-byte name (App command 0x46).
#[derive(Clone, Copy, Debug)]
pub struct GetUserName {
    user: UserId,
}

impl GetUserName {
    /// Query `user` (the username is shared across channels).
    pub fn new(user: UserId) -> Self {
        Self { user }
    }
}

impl From<GetUserName> for Message {
    fn from(cmd: GetUserName) -> Self {
        Message::new_request(NetFn::App, 0x46, vec![cmd.user.value()])
    }
}

impl IpmiCommand for GetUserName {
    type Output = UserName;
    type Error = UserResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let bytes: [u8; 16] = data.try_into().map_err(|_| UserResponseError::Length {
            expected: 16,
            actual: data.len(),
        })?;
        Ok(UserName(bytes))
    }
}

/// Set a user's name (App command 0x45). An empty name explicitly clears it.
#[derive(Clone, Debug)]
pub struct SetUserName {
    user: UserId,
    name: [u8; 16],
}

impl SetUserName {
    /// Require at most 16 printable US-ASCII bytes; the remaining bytes are NUL padded.
    pub fn new(user: UserId, name: &str) -> Result<Self, UserTextError> {
        let bytes = name.as_bytes();
        check_text(bytes, 16)?;
        let mut padded = [0; 16];
        padded[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { user, name: padded })
    }
}

impl From<SetUserName> for Message {
    fn from(cmd: SetUserName) -> Self {
        let mut data = Vec::with_capacity(17);
        data.push(cmd.user.value());
        data.extend_from_slice(&cmd.name);
        Message::new_request(NetFn::App, 0x45, data)
    }
}

impl IpmiCommand for SetUserName {
    type Output = ();
    type Error = UserResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        empty_response(data)
    }
}

/// A BMC user enable status (bits 7:6 of Get User Access byte 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserEnableStatus {
    Unknown,
    Enabled,
    Disabled,
    Reserved,
}

/// Counts shared across all users of a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserSummary {
    /// Number of supported user IDs (at most 63).
    pub max_user_ids: u8,
    /// Number of currently enabled users.
    pub enabled_user_ids: u8,
    /// Number of names fixed by the BMC.
    pub fixed_user_ids: u8,
    /// Raw two-bit enable status returned for the requested user.
    pub enable_status: UserEnableStatus,
}

/// Per-channel access returned for an individual user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserAccess {
    /// Counts and status from the response.
    pub summary: UserSummary,
    /// Whether this user is restricted to callback (not call-in) access.
    pub callback_only: bool,
    /// Whether link authentication is enabled.
    pub link_auth: bool,
    /// Whether IPMI messaging is enabled.
    pub ipmi_messaging: bool,
    /// Privilege nibble, including reserved and OEM values.
    pub privilege_limit: u8,
}

impl UserAccess {
    /// Interpret a four-byte Get User Access response without losing unknown values.
    pub fn parse(data: &[u8]) -> Result<Self, UserResponseError> {
        if data.len() != 4 {
            return Err(UserResponseError::Length {
                expected: 4,
                actual: data.len(),
            });
        }
        let enable_status = match data[1] >> 6 {
            0 => UserEnableStatus::Unknown,
            1 => UserEnableStatus::Enabled,
            2 => UserEnableStatus::Disabled,
            _ => UserEnableStatus::Reserved,
        };
        Ok(Self {
            summary: UserSummary {
                max_user_ids: data[0] & 0x3F,
                enabled_user_ids: data[1] & 0x3F,
                fixed_user_ids: data[2] & 0x3F,
                enable_status,
            },
            callback_only: data[3] & 0x40 != 0,
            link_auth: data[3] & 0x20 != 0,
            ipmi_messaging: data[3] & 0x10 != 0,
            privilege_limit: data[3] & 0x0F,
        })
    }
}

/// Get a user's per-channel access (App command 0x44).
#[derive(Clone, Copy, Debug)]
pub struct GetUserAccess {
    channel: Channel,
    user: UserId,
}

impl GetUserAccess {
    /// Construct a single-user access query.
    pub fn new(channel: Channel, user: UserId) -> Self {
        Self { channel, user }
    }
}

impl From<GetUserAccess> for Message {
    fn from(cmd: GetUserAccess) -> Self {
        Message::new_request(
            NetFn::App,
            0x44,
            vec![cmd.channel.value(), cmd.user.value()],
        )
    }
}

impl IpmiCommand for GetUserAccess {
    type Output = UserAccess;
    type Error = UserResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        UserAccess::parse(data)
    }
}

/// Query user counts on a channel using user ID 1 (App command 0x44).
#[derive(Clone, Copy, Debug)]
pub struct GetUserSummary {
    channel: Channel,
}

impl GetUserSummary {
    /// Construct a summary query; no users are modified.
    pub fn new(channel: Channel) -> Self {
        Self { channel }
    }
}

impl From<GetUserSummary> for Message {
    fn from(cmd: GetUserSummary) -> Self {
        Message::from(GetUserAccess::new(
            cmd.channel,
            UserId::new(1).expect("user ID 1 is valid"),
        ))
    }
}

impl IpmiCommand for GetUserSummary {
    type Output = UserSummary;
    type Error = UserResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        Ok(UserAccess::parse(data)?.summary)
    }
}

/// A bounded plan for enumerating users after a summary query.
///
/// For each ID, callers send [`GetUserAccess`] and [`GetUserName`] separately.
/// The BMC may reject the latter (e.g. no name); retain its completion code.
pub struct UserList {
    channel: Channel,
    next: u8,
    max: u8,
}

impl UserList {
    /// Enumerate IDs 1 through `summary.max_user_ids` (at most 63).
    pub fn new(channel: Channel, summary: UserSummary) -> Self {
        Self {
            channel,
            next: 1,
            max: summary.max_user_ids.min(63),
        }
    }
}

impl Iterator for UserList {
    type Item = (UserId, GetUserAccess, GetUserName);

    fn next(&mut self) -> Option<Self::Item> {
        if self.next > self.max {
            return None;
        }
        let id = UserId::new(self.next)?;
        self.next += 1;
        Some((
            id,
            GetUserAccess::new(self.channel, id),
            GetUserName::new(id),
        ))
    }
}

/// Replace a user's access flags and privilege on a channel (App command 0x43).
#[derive(Clone, Copy, Debug)]
pub struct SetUserAccess {
    channel: Channel,
    user: UserId,
    callback_only: bool,
    link_auth: bool,
    ipmi_messaging: bool,
    privilege: UserPrivilege,
    session_limit: u8,
}

impl SetUserAccess {
    /// Explicitly replace all flags and the privilege. Session limit must be 0..=15.
    pub fn new(
        channel: Channel,
        user: UserId,
        callback_only: bool,
        link_auth: bool,
        ipmi_messaging: bool,
        privilege: UserPrivilege,
        session_limit: u8,
    ) -> Result<Self, UserRequestError> {
        if session_limit > 15 {
            return Err(UserRequestError::InvalidSessionLimit);
        }
        Ok(Self {
            channel,
            user,
            callback_only,
            link_auth,
            ipmi_messaging,
            privilege,
            session_limit,
        })
    }
}

impl From<SetUserAccess> for Message {
    fn from(cmd: SetUserAccess) -> Self {
        let flags = 0x80
            | (u8::from(cmd.callback_only) << 6)
            | (u8::from(cmd.link_auth) << 5)
            | (u8::from(cmd.ipmi_messaging) << 4)
            | cmd.channel.value();
        Message::new_request(
            NetFn::App,
            0x43,
            vec![
                flags,
                cmd.user.value(),
                cmd.privilege.value(),
                cmd.session_limit,
            ],
        )
    }
}

impl IpmiCommand for SetUserAccess {
    type Output = ();
    type Error = UserResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        empty_response(data)
    }
}

/// Change only a user's privilege limit, leaving all access flags alone.
#[derive(Clone, Copy, Debug)]
pub struct SetUserPrivilege {
    channel: Channel,
    user: UserId,
    privilege: UserPrivilege,
}

impl SetUserPrivilege {
    /// Construct an explicit privilege-only write (App command 0x43).
    pub fn new(channel: Channel, user: UserId, privilege: UserPrivilege) -> Self {
        Self {
            channel,
            user,
            privilege,
        }
    }
}

impl From<SetUserPrivilege> for Message {
    fn from(cmd: SetUserPrivilege) -> Self {
        Message::new_request(
            NetFn::App,
            0x43,
            vec![
                cmd.channel.value(),
                cmd.user.value(),
                cmd.privilege.value(),
                0,
            ],
        )
    }
}

impl IpmiCommand for SetUserPrivilege {
    type Output = ();
    type Error = UserResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        empty_response(data)
    }
}

/// Password field size used by the BMC (IPMI 1.5: 16; IPMI 2.0: 20).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordLength {
    Bytes16,
    Bytes20,
}

impl PasswordLength {
    fn value(self) -> usize {
        match self {
            Self::Bytes16 => 16,
            Self::Bytes20 => 20,
        }
    }
}

/// Validated password for a set or test command. The secret is never printed by Debug.
///
/// The caller owns the source bytes; avoid logging them, and use an authenticated,
/// encrypted transport for remote password changes.
pub struct UserPassword<'a> {
    bytes: &'a [u8],
    length: PasswordLength,
}

impl core::fmt::Debug for UserPassword<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("UserPassword([REDACTED])")
    }
}

impl<'a> UserPassword<'a> {
    /// Require 0..=16 or 0..=20 printable US-ASCII bytes.
    ///
    /// Empty passwords are permitted for BMCs that support them; setting one
    /// can expose the controller and must be an intentional decision.
    pub fn new(password: &'a str, length: PasswordLength) -> Result<Self, UserTextError> {
        let bytes = password.as_bytes();
        check_text(bytes, length.value())?;
        Ok(Self { bytes, length })
    }
}

/// Set User Password operations (App command 0x47).
///
/// Enable/disable uses a 16-byte empty field; set/test always carries an
/// explicitly selected 16- or 20-byte, NUL-padded password field.
pub struct SetUserPassword<'a> {
    user: UserId,
    operation: PasswordOperation<'a>,
}

enum PasswordOperation<'a> {
    Disable,
    Enable,
    Set(UserPassword<'a>),
    Test(UserPassword<'a>),
}

impl core::fmt::Debug for SetUserPassword<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let operation = match self.operation {
            PasswordOperation::Disable => "Disable",
            PasswordOperation::Enable => "Enable",
            PasswordOperation::Set(_) => "Set([REDACTED])",
            PasswordOperation::Test(_) => "Test([REDACTED])",
        };
        f.debug_struct("SetUserPassword")
            .field("user", &self.user)
            .field("operation", &operation)
            .finish()
    }
}

impl<'a> SetUserPassword<'a> {
    /// Disable a user (without altering their password).
    pub fn disable(user: UserId) -> Self {
        Self {
            user,
            operation: PasswordOperation::Disable,
        }
    }

    /// Enable a user (without altering their password).
    pub fn enable(user: UserId) -> Self {
        Self {
            user,
            operation: PasswordOperation::Enable,
        }
    }

    /// Change a user's password; never retry an ambiguous write.
    pub fn set(user: UserId, password: UserPassword<'a>) -> Self {
        Self {
            user,
            operation: PasswordOperation::Set(password),
        }
    }

    /// Test a password; a 0x80 completion code means incorrect, 0x81 wrong size.
    pub fn test(user: UserId, password: UserPassword<'a>) -> Self {
        Self {
            user,
            operation: PasswordOperation::Test(password),
        }
    }
}

impl From<SetUserPassword<'_>> for Message {
    fn from(cmd: SetUserPassword<'_>) -> Self {
        let (op, password) = match cmd.operation {
            PasswordOperation::Disable => (0, None),
            PasswordOperation::Enable => (1, None),
            PasswordOperation::Set(password) => (2, Some(password)),
            PasswordOperation::Test(password) => (3, Some(password)),
        };
        let length = password
            .as_ref()
            .map_or(PasswordLength::Bytes16, |pw| pw.length);
        let mut data = vec![0; length.value() + 2];
        data[0] = cmd.user.value()
            | if length == PasswordLength::Bytes20 {
                0x80
            } else {
                0
            };
        data[1] = op;
        if let Some(password) = password {
            data[2..2 + password.bytes.len()].copy_from_slice(password.bytes);
        }
        Message::new_request(NetFn::App, 0x47, data)
    }
}

impl IpmiCommand for SetUserPassword<'_> {
    type Output = ();
    type Error = UserResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        empty_response(data)
    }
}

/// Invalid Set User Access request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserRequestError {
    /// Session limit exceeds the four-bit field.
    InvalidSessionLimit,
}

/// A successful response with an unexpected number of data bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserResponseError {
    /// Expected an exact number of response bytes.
    Length {
        /// Required response length.
        expected: usize,
        /// Received response length.
        actual: usize,
    },
}

fn empty_response(data: &[u8]) -> Result<(), UserResponseError> {
    if data.is_empty() {
        Ok(())
    } else {
        Err(UserResponseError::Length {
            expected: 0,
            actual: data.len(),
        })
    }
}

fn check_text(bytes: &[u8], limit: usize) -> Result<(), UserTextError> {
    if bytes.len() > limit {
        Err(UserTextError::TooLong)
    } else if !bytes.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        Err(UserTextError::InvalidEncoding)
    } else {
        Ok(())
    }
}
