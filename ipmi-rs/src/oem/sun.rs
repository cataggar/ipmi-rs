//! Checked Sun/Oracle ILOM commands. Responses exclude the IPMI completion code.
//!
//! Each packet (including continuation packets) is identity-checked at its
//! unchanged destination. Mutations are never retransmitted after an uncertain
//! outcome. This API does not implement a terminal or write files.

use std::{collections::HashSet, marker::PhantomData, time::Duration};

use ipmi_rs_core::{
    connection::{Address, Channel, IpmiConnection, LogicalUnit, Message, NetFn},
    storage::sdr::{
        record::{GenericDeviceLocator, RecordContents, SensorId},
        GetDeviceSdr, RecordId, RecordParseError,
    },
};

pub use ipmi_rs_core::oem::sun::{GetVersion, Version, VersionError};

use super::{OemCommand, OemError};
use crate::{Ipmi, IpmiError};

const NETFN: NetFn = NetFn::Reserved(0x2e);
const MAX_REPLY: usize = 1033; // core-tunnel header (9) + 1024 data
const MAX_FILE: usize = 1024 * 1024;

/// Explicit consent for a Sun ILOM write or CLI invocation.
#[derive(Debug, Clone, Copy)]
pub enum WriteIntent {
    /// The caller has approved this operation and its possible unknown outcome.
    Approved,
}

/// Supported Sun LED modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LedMode {
    Off = 0,
    On = 1,
    Standby = 2,
    Slow = 3,
    Fast = 4,
}

impl TryFrom<u8> for LedMode {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Off),
            1 => Ok(Self::On),
            2 => Ok(Self::Standby),
            3 => Ok(Self::Slow),
            4 => Ok(Self::Fast),
            _ => Err(ProtocolError::InvalidValue),
        }
    }
}

/// Sun LED type; `Locator` uses the verified SDR OEM field.
#[derive(Debug, Clone, Copy)]
pub enum LedType {
    OkToRemove,
    Service,
    Activity,
    Locate,
    Locator,
}

/// Malformed or uncorrelated ILOM data (never includes payload bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    Truncated,
    InvalidValue,
    InvalidSequence,
    ExceededLimit,
}

/// Checked Sun workflow failure. After a dispatched mutation times out or
/// fails transport/parsing, its outcome is unknown; never automatically replay it.
#[derive(Debug)]
pub enum SunError<E> {
    InvalidInput(&'static str),
    Protocol(ProtocolError),
    NotFound,
    UnsupportedVersion(Version),
    /// No further packets were sent.
    Limit,
    /// A single, identity-checked OEM packet failed.
    Oem(OemError<E, ProtocolError>),
    /// Version discovery failed before a gated core-tunnel operation.
    Version(OemError<E, VersionError>),
    /// SDR traversal failed before LED dispatch.
    Sdr(IpmiError<E, (RecordParseError, Option<RecordId>)>),
}

impl<E> From<ProtocolError> for SunError<E> {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

#[derive(Clone, Copy)]
struct Destination {
    target: Option<(Address, Channel)>,
    lun: LogicalUnit,
}

impl Default for Destination {
    fn default() -> Self {
        Self {
            target: None,
            lun: LogicalUnit::Zero,
        }
    }
}

// Internal only: callers cannot bypass write validation/locality through send_oem.
struct Packet {
    cmd: u8,
    data: Vec<u8>,
    dest: Destination,
}

impl OemCommand for Packet {
    type Output = Vec<u8>;
    type Error = ProtocolError;
    const MANUFACTURER_ID: u32 = 42;

    fn into_message(self) -> Message {
        Message::new_request(NETFN, self.cmd, self.data)
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.len() > MAX_REPLY {
            return Err(ProtocolError::ExceededLimit);
        }
        Ok(data.to_vec())
    }

    fn target(&self) -> Option<(Address, Channel)> {
        self.dest.target
    }

    fn lun(&self) -> LogicalUnit {
        self.dest.lun
    }
}

struct RoutedVersion {
    dest: Destination,
    _version: PhantomData<GetVersion>,
}

impl OemCommand for RoutedVersion {
    type Output = Version;
    type Error = VersionError;
    const MANUFACTURER_ID: u32 = 42;

    fn into_message(self) -> Message {
        GetVersion.into_message()
    }
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        GetVersion::parse_success_response(data)
    }
    fn target(&self) -> Option<(Address, Channel)> {
        self.dest.target
    }
    fn lun(&self) -> LogicalUnit {
        self.dest.lun
    }
}

fn identifier(input: &str, max: usize) -> Result<&[u8], &'static str> {
    if input.is_empty() || input.len() > max || input.as_bytes().contains(&0) {
        return Err("identifier must be nonempty, bounded and NUL-free");
    }
    Ok(input.as_bytes())
}

fn c_string(data: &[u8]) -> Result<String, ProtocolError> {
    let end = data
        .iter()
        .position(|&b| b == 0)
        .ok_or(ProtocolError::Truncated)?;
    std::str::from_utf8(&data[..end])
        .map(str::to_owned)
        .map_err(|_| ProtocolError::InvalidValue)
}

fn exact(data: &[u8], len: usize) -> Result<(), ProtocolError> {
    if data.len() == len {
        Ok(())
    } else {
        Err(ProtocolError::Truncated)
    }
}

impl<CON: IpmiConnection> Ipmi<CON> {
    fn sun_packet(
        &mut self,
        dest: Destination,
        cmd: u8,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, SunError<CON::Error>> {
        self.send_oem(Packet { cmd, data, dest })
            .map_err(SunError::Oem)
    }

    fn sun_version_at(&mut self, dest: Destination) -> Result<Version, SunError<CON::Error>> {
        self.send_oem(RoutedVersion {
            dest,
            _version: PhantomData,
        })
        .map_err(SunError::Version)
    }

    fn sun_require_3200(&mut self) -> Result<(), SunError<CON::Error>> {
        let version = self.sun_version_at(Destination::default())?;
        if (version.major, version.minor, version.update, version.micro) < (3, 2, 0, 0) {
            return Err(SunError::UnsupportedVersion(version));
        }
        Ok(())
    }

    /// Resolve a short IPMI NAC name into a path (at most 256 bytes).
    pub fn sun_nac_name(&mut self, name: &str) -> Result<String, SunError<CON::Error>> {
        let name = identifier(name, 16).map_err(SunError::InvalidInput)?;
        let mut request = vec![0; 65];
        request[1..1 + name.len()].copy_from_slice(name);
        let mut result = Vec::new();
        for sequence in 0..=4u8 {
            request[0] = sequence;
            let reply = self.sun_packet(Destination::default(), 0x29, request.clone())?;
            exact(&reply, 65)?;
            let next = reply[0];
            let chunk = &reply[1..65];
            let end = chunk.iter().position(|&b| b == 0).unwrap_or(64);
            if next != sequence && (next != sequence + 1 || end != 64) {
                return Err(ProtocolError::InvalidSequence.into());
            }
            if result.len() + end > 256 {
                return Err(ProtocolError::ExceededLimit.into());
            }
            result.extend_from_slice(&chunk[..end]);
            if next == sequence {
                if end == 64 {
                    return Err(ProtocolError::Truncated.into());
                }
                return String::from_utf8(result).map_err(|_| ProtocolError::InvalidValue.into());
            }
        }
        Err(SunError::Limit)
    }

    /// Send one 66-byte sequence-tagged ping packet and verify its echo.
    pub fn sun_ping(&mut self, sequence: u16) -> Result<(), SunError<CON::Error>> {
        let mut request = sequence.to_le_bytes().to_vec();
        request.extend(0..64u8);
        let reply = self.sun_packet(Destination::default(), 0x23, request.clone())?;
        if reply.len() != request.len() {
            return Err(ProtocolError::Truncated.into());
        }
        if reply != request {
            return Err(ProtocolError::InvalidSequence.into());
        }
        Ok(())
    }

    fn sun_locator(&mut self, id: &str) -> Result<GenericDeviceLocator, SunError<CON::Error>> {
        identifier(id, 16).map_err(SunError::InvalidInput)?;
        let mut next = RecordId::FIRST;
        let mut seen = HashSet::new();
        for _ in 0..1024 {
            if next.is_last() {
                return Err(SunError::NotFound);
            }
            if !seen.insert(next.value()) {
                return Err(ProtocolError::InvalidSequence.into());
            }
            let info = self
                .send_recv(GetDeviceSdr::new(None, next))
                .map_err(SunError::Sdr)?;
            if let RecordContents::GenericDeviceLocator(locator) = info.record.contents {
                if matches!(&locator.id_string, SensorId::Unicode(s) | SensorId::Ascii8BAndLatin1(s) if s == id)
                {
                    if locator.entity_instance & 0x80 != 0
                        || locator.record_key.device_access_address == 0
                        || locator.record_key.device_slave_address == 0
                        || Channel::new(locator.record_key.channel_number).is_none()
                    {
                        return Err(SunError::InvalidInput("not a physical LED locator"));
                    }
                    return Ok(locator);
                }
            }
            next = info.next_entry;
        }
        Err(SunError::Limit)
    }

    fn led_packet(
        &mut self,
        id: &str,
        led_type: LedType,
    ) -> Result<(Destination, Vec<u8>), SunError<CON::Error>> {
        let locator = self.sun_locator(id)?;
        let key = &locator.record_key;
        let access = key.device_access_address << 1;
        let slave = (key.device_slave_address << 1) | (key.channel_number >> 3);
        let kind = match led_type {
            LedType::OkToRemove => 0,
            LedType::Service => 1,
            LedType::Activity => 2,
            LedType::Locate => 3,
            LedType::Locator if locator.oem_reserved <= 3 => locator.oem_reserved,
            LedType::Locator => return Err(SunError::InvalidInput("invalid locator LED type")),
        };
        let target = if access == 0x20 && key.channel_number == 0 {
            None
        } else {
            Some((
                Address(access),
                Channel::new(key.channel_number).expect("channel validated"),
            ))
        };
        Ok((
            Destination {
                target,
                lun: key.access_lun,
            },
            vec![
                slave,
                kind,
                access,
                locator.oem_reserved,
                locator.entity_id,
                locator.entity_instance,
                0,
            ],
        ))
    }

    /// Look up a current physical generic SDR locator and read its LED.
    pub fn sun_led(
        &mut self,
        id: &str,
        led_type: LedType,
    ) -> Result<LedMode, SunError<CON::Error>> {
        let (dest, request) = self.led_packet(id, led_type)?;
        let reply = self.sun_packet(dest, 0x21, request)?;
        exact(&reply, 1)?;
        LedMode::try_from(reply[0]).map_err(Into::into)
    }

    /// Verify the current physical locator and readable LED, then set it once.
    pub fn sun_set_led(
        &mut self,
        _intent: WriteIntent,
        id: &str,
        led_type: LedType,
        mode: LedMode,
    ) -> Result<(), SunError<CON::Error>> {
        let (dest, request) = self.led_packet(id, led_type)?;
        let current = self.sun_packet(dest, 0x21, request.clone())?;
        exact(&current, 1)?;
        LedMode::try_from(current[0])?;
        let set = vec![
            request[0], request[1], request[2], request[3], mode as u8, request[4], request[5], 0,
            0,
        ];
        exact(&self.sun_packet(dest, 0x22, set)?, 0)?;
        Ok(())
    }

    /// Delete one validated IPMI user's SSH public key.
    pub fn sun_delete_ssh_key(
        &mut self,
        _intent: WriteIntent,
        user_id: u8,
    ) -> Result<(), SunError<CON::Error>> {
        validate_user(user_id).map_err(SunError::InvalidInput)?;
        exact(
            &self.sun_packet(Destination::default(), 0x02, vec![user_id])?,
            0,
        )?;
        Ok(())
    }

    /// Upload one validated OpenSSH *public* key in 64-byte blocks.
    /// The last block uses marker FF; no block is retried on failure.
    pub fn sun_set_ssh_key(
        &mut self,
        _intent: WriteIntent,
        user_id: u8,
        public_key: &str,
    ) -> Result<(), SunError<CON::Error>> {
        validate_user(user_id).map_err(SunError::InvalidInput)?;
        validate_public_key(public_key).map_err(SunError::InvalidInput)?;
        let bytes = public_key.as_bytes();
        for (i, chunk) in bytes.chunks(64).enumerate() {
            let marker = if i == (bytes.len() - 1) / 64 {
                0xff
            } else {
                i as u8
            };
            let mut request = vec![user_id, marker, chunk.len() as u8];
            request.extend_from_slice(chunk);
            exact(&self.sun_packet(Destination::default(), 0x01, request)?, 0)?;
        }
        Ok(())
    }

    /// Read a LUAPI value with at most five poll packets (maximum 79 bytes).
    pub fn sun_get_value(&mut self, path: &str) -> Result<String, SunError<CON::Error>> {
        let path = identifier(path, 79).map_err(SunError::InvalidInput)?;
        let mut request = vec![0; 80];
        request[0] = 1;
        request[1..1 + path.len()].copy_from_slice(path);
        let ack = self.sun_packet(Destination::default(), 0x2a, request.clone())?;
        if (!ack.is_empty() && ack[0] != 1) || ack.len() > 80 {
            return Err(ProtocolError::InvalidValue.into());
        }
        request[0] = 2;
        for poll in 0..5 {
            let reply = self.sun_packet(Destination::default(), 0x2a, request.clone())?;
            if reply.len() > 80 {
                return Err(ProtocolError::ExceededLimit.into());
            }
            match reply.first().copied() {
                Some(3) => return c_string(&reply[1..]).map_err(Into::into),
                Some(5) => return Err(SunError::NotFound),
                Some(4) if poll < 4 => std::thread::sleep(Duration::from_secs(1)),
                Some(4) => return Err(SunError::Limit),
                _ => return Err(ProtocolError::InvalidValue.into()),
            }
        }
        Err(SunError::Limit)
    }

    /// Get a core-tunnel behavior (requires ILOM 3.2.0.0 or newer).
    pub fn sun_get_behavior(&mut self, id: &str) -> Result<bool, SunError<CON::Error>> {
        let id = identifier(id, 31).map_err(SunError::InvalidInput)?;
        self.sun_require_3200()?;
        let mut request = vec![0; 33];
        request[0] = 15;
        request[1..1 + id.len()].copy_from_slice(id);
        let reply = self.sun_packet(Destination::default(), 0x44, request)?;
        exact(&reply, 1)?;
        match reply[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ProtocolError::InvalidValue.into()),
        }
    }

    /// Read a core-tunnel file into bounded bytes, not a filesystem path.
    /// `max_bytes` must be in 1..=1 MiB. No partial file is returned on error.
    pub fn sun_get_file(
        &mut self,
        id: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, SunError<CON::Error>> {
        let id = identifier(id, 15).map_err(SunError::InvalidInput)?;
        if !(1..=MAX_FILE).contains(&max_bytes) {
            return Err(SunError::InvalidInput("file limit must be 1..=1 MiB"));
        }
        self.sun_require_3200()?;
        let mut request = vec![0; 21];
        request[0] = 11;
        request[1..1 + id.len()].copy_from_slice(id);
        let mut result = Vec::new();
        for block in 0..=1024u32 {
            request[17..21].copy_from_slice(&block.to_be_bytes());
            let reply = self.sun_packet(Destination::default(), 0x44, request.clone())?;
            if reply.len() < 9 || reply[0..4] != request[17..21] || reply[8] > 1 {
                return Err(ProtocolError::InvalidSequence.into());
            }
            let size = u32::from_be_bytes(reply[4..8].try_into().expect("header checked")) as usize;
            if size > 1024 || reply.len() < 9 + size || (size == 0 && reply[8] == 0) {
                return Err(ProtocolError::Truncated.into());
            }
            if result.len() + size > max_bytes {
                return Err(SunError::Limit);
            }
            result.extend_from_slice(&reply[9..9 + size]);
            if reply[8] == 1 {
                return Ok(result);
            }
        }
        Err(SunError::Limit)
    }

    /// Execute one explicitly approved CLI line, returning at most `max_output`
    /// bytes. The session is ended with EOF, without terminal I/O or retries.
    pub fn sun_cli(
        &mut self,
        _intent: WriteIntent,
        line: &str,
        max_output: usize,
    ) -> Result<Vec<u8>, SunError<CON::Error>> {
        identifier(line, 1024).map_err(SunError::InvalidInput)?;
        if line.contains(['\n', '\r']) || !(1..=4096).contains(&max_output) {
            return Err(SunError::InvalidInput(
                "CLI requires one line and a 1..=4096 output limit",
            ));
        }
        let dest = Destination::default();
        let mut version = 2;
        let mut open = vec![version, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut reply = self.sun_packet(dest, 0x19, open.clone())?;
        if reply.len() >= 9 && reply[1] != 0 && reply[8..].starts_with(b"Invalid version\0") {
            version = 1;
            open[0] = version;
            reply = self.sun_packet(dest, 0x19, open)?;
        }
        let (status, handle, _) = cli_response(&reply, version, 0, None)?;
        if status != 0 {
            return Err(ProtocolError::InvalidValue.into());
        }
        let mut sequence = if version == 2 { 1 } else { 0 };
        let mut output = Vec::new();
        let mut chunks = line.as_bytes().chunks(70).peekable();
        let mut steps = 0;
        let mut done = false;
        let mut drain_action = None;
        while !done {
            if steps == 64 {
                return Err(SunError::Limit);
            }
            steps += 1;
            let (action, chunk) = if let Some(action) = drain_action.take() {
                (action, Vec::new())
            } else if let Some(chunk) = chunks.next() {
                let mut payload = chunk.to_vec();
                if chunks.peek().is_none() {
                    payload.push(b'\n');
                }
                (3, payload)
            } else {
                (4, Vec::new())
            };
            let mut packet = vec![version, action, sequence, 0];
            packet.extend_from_slice(&handle);
            packet.extend_from_slice(&chunk);
            packet.push(0);
            let reply = self.sun_packet(dest, 0x19, packet)?;
            let (status, _, data) = cli_response(&reply, version, sequence, Some(handle))?;
            if output.len() + data.len() > max_output {
                return Err(SunError::Limit);
            }
            output.extend_from_slice(data);
            match status {
                0 if !data.is_empty() => drain_action = Some(action),
                0 => (),
                1 if action == 4 => done = true,
                _ => return Err(ProtocolError::InvalidValue.into()),
            }
            if version == 2 {
                sequence ^= 1;
            }
        }
        Ok(output)
    }
}

fn cli_response(
    reply: &[u8],
    version: u8,
    sequence: u8,
    expected_handle: Option<[u8; 4]>,
) -> Result<(u8, [u8; 4], &[u8]), ProtocolError> {
    if !(9..=80).contains(&reply.len())
        || reply[0] != version
        || (version == 2 && reply[2] != sequence)
    {
        return Err(ProtocolError::Truncated);
    }
    let handle: [u8; 4] = reply[4..8].try_into().expect("length checked");
    if expected_handle.is_some_and(|expected| expected != handle) {
        return Err(ProtocolError::InvalidSequence);
    }
    let end = reply[8..]
        .iter()
        .position(|&b| b == 0)
        .ok_or(ProtocolError::Truncated)?;
    Ok((reply[1], handle, &reply[8..8 + end]))
}

fn validate_user(uid: u8) -> Result<(), &'static str> {
    if (1..=63).contains(&uid) {
        Ok(())
    } else {
        Err("IPMI user ID must be 1..=63")
    }
}

fn validate_public_key(key: &str) -> Result<(), &'static str> {
    let key = key.strip_suffix('\n').unwrap_or(key);
    if key.is_empty()
        || key.len() > 16384
        || !key.is_ascii()
        || key.bytes().any(|b| b.is_ascii_control())
    {
        return Err("invalid OpenSSH public key");
    }
    let mut parts = key.split_whitespace();
    let algorithm = parts.next().ok_or("missing public-key algorithm")?;
    if !matches!(
        algorithm,
        "ssh-rsa"
            | "ssh-ed25519"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    ) {
        return Err("unsupported public-key algorithm");
    }
    let encoded = parts.next().ok_or("missing public-key body")?;
    let blob = decode_base64(encoded).ok_or("invalid public-key encoding")?;
    let mut cursor = 0;
    if ssh_field(&blob, &mut cursor) != Some(algorithm.as_bytes()) {
        return Err("public-key algorithm does not match blob");
    }
    let valid = match algorithm {
        "ssh-ed25519" => ssh_field(&blob, &mut cursor).is_some_and(|key| key.len() == 32),
        "ssh-rsa" => {
            ssh_field(&blob, &mut cursor).is_some_and(|exponent| !exponent.is_empty())
                && ssh_field(&blob, &mut cursor).is_some_and(|modulus| modulus.len() >= 32)
        }
        algorithm if algorithm.starts_with("ecdsa-sha2-") => {
            ssh_field(&blob, &mut cursor) == Some(&algorithm.as_bytes()[11..])
                && ssh_field(&blob, &mut cursor).is_some_and(|point| !point.is_empty())
        }
        "sk-ssh-ed25519@openssh.com" => {
            ssh_field(&blob, &mut cursor).is_some_and(|key| key.len() == 32)
                && ssh_field(&blob, &mut cursor).is_some_and(|app| !app.is_empty())
        }
        "sk-ecdsa-sha2-nistp256@openssh.com" => {
            ssh_field(&blob, &mut cursor) == Some(b"nistp256".as_slice())
                && ssh_field(&blob, &mut cursor).is_some_and(|point| !point.is_empty())
                && ssh_field(&blob, &mut cursor).is_some_and(|app| !app.is_empty())
        }
        _ => false,
    };
    if !valid || cursor != blob.len() {
        return Err("invalid public-key encoding");
    }
    Ok(())
}

fn ssh_field<'a>(blob: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let end = cursor.checked_add(4)?;
    let len = u32::from_be_bytes(blob.get(*cursor..end)?.try_into().ok()?) as usize;
    *cursor = end;
    let end = cursor.checked_add(len)?;
    let value = blob.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}

fn decode_base64(encoded: &str) -> Option<Vec<u8>> {
    let bytes = encoded.as_bytes();
    if bytes.len() < 16 || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut result = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, quartet) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let last = index == bytes.len() / 4 - 1;
        let pad = quartet.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 || (pad != 0 && !last) {
            return None;
        }
        let mut value = 0u32;
        for (position, &b) in quartet.iter().enumerate() {
            let digit = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if last && position >= 4 - pad => 0,
                _ => return None,
            };
            value = (value << 6) | u32::from(digit);
        }
        if (pad == 1 && value & 0xff != 0) || (pad == 2 && value & 0xffff != 0) {
            return None;
        }
        let word = value.to_be_bytes();
        result.extend_from_slice(&word[1..4 - pad]);
    }
    Some(result)
}

// Only the Linux device-file transport can satisfy this sealed locality
// guarantee. In particular RMCP, USB and serial cannot opt in externally.
mod local {
    pub trait Sealed {}
    #[cfg(feature = "unix-file")]
    impl Sealed for crate::File {}
}

/// A transport proven to use the host-local IPMI system interface.
pub trait LocalSunTransport: IpmiConnection + local::Sealed {}
#[cfg(feature = "unix-file")]
impl LocalSunTransport for crate::File {}

impl<CON: LocalSunTransport> Ipmi<CON> {
    /// Set a LUAPI property locally. This sends its path chunks, value chunks,
    /// and at most five status polls. A timeout after *any* chunk leaves the
    /// overall mutation outcome unknown; inspect the property before retrying.
    pub fn sun_set_value(
        &mut self,
        _intent: WriteIntent,
        path: &str,
        value: &str,
    ) -> Result<(), SunError<CON::Error>> {
        identifier(path, 256).map_err(SunError::InvalidInput)?;
        identifier(value, 1024).map_err(SunError::InvalidInput)?;
        let mut tid = 0;
        for (kind, bytes) in [(0, path.as_bytes()), (1, value.as_bytes())] {
            for chunk in bytes.chunks(56) {
                let last = kind == 1 && chunk.as_ptr_range().end == bytes.as_ptr_range().end;
                let mut packet = vec![0; 60];
                packet[..4].copy_from_slice(&[3, kind, tid, u8::from(last)]);
                packet[4..4 + chunk.len()].copy_from_slice(chunk);
                let reply = self.sun_packet(Destination::default(), 0x2c, packet)?;
                exact(&reply, 2)?;
                if reply[0] != 1 || reply[1] == 0 || (kind == 1 && reply[1] != tid) {
                    return Err(ProtocolError::InvalidValue.into());
                }
                tid = reply[1];
            }
        }
        self.sun_poll_set_value(tid)
    }

    fn sun_poll_set_value(&mut self, tid: u8) -> Result<(), SunError<CON::Error>> {
        for poll in 0..5 {
            let mut packet = vec![0; 60];
            packet[0] = 4;
            packet[2] = tid;
            let reply = self.sun_packet(Destination::default(), 0x2c, packet)?;
            exact(&reply, 2)?;
            if reply[1] != tid {
                return Err(ProtocolError::InvalidSequence.into());
            }
            match reply[0] {
                3 => return Ok(()),
                4 if poll < 4 => std::thread::sleep(Duration::from_secs(1)),
                4 => return Err(SunError::Limit),
                _ => return Err(ProtocolError::InvalidValue.into()),
            }
        }
        Err(SunError::Limit)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::connection::{Request, RequestTargetAddress, Response};

    #[derive(Debug)]
    struct Timeout;

    #[derive(Debug, PartialEq)]
    struct Sent {
        netfn: u8,
        cmd: u8,
        data: Vec<u8>,
        target: RequestTargetAddress,
    }

    #[derive(Default)]
    struct Mock {
        sent: Vec<Sent>,
        replies: VecDeque<Result<Response, Timeout>>,
    }

    impl Mock {
        fn reply(&mut self, netfn: u8, cmd: u8, cc: u8, bytes: &[u8]) {
            let mut data = vec![cc];
            data.extend_from_slice(bytes);
            self.replies.push_back(Ok(Response::new(
                Message::new_response(NetFn::from(netfn), cmd, data),
                0,
            )
            .unwrap()));
        }

        fn identity(&mut self, manufacturer: u32) {
            let [a, b, c, _] = manufacturer.to_le_bytes();
            self.reply(6, 1, 0, &[1, 1, 1, 0x23, 0x51, 0, a, b, c, 1, 0]);
        }

        fn sun(&mut self, cmd: u8, bytes: &[u8]) {
            self.identity(42);
            self.reply(0x2e, cmd, 0, bytes);
        }

        fn version(&mut self, major: u8, minor: u8) {
            let mut data = vec![0; 65];
            data[1] = major;
            data[2] = minor;
            self.sun(0x24, &data);
        }

        fn locator(&mut self, name: &[u8]) {
            let mut record = vec![
                0xff,
                0xff, // next SDR
                0x01,
                0x00,
                0x51,
                0x10,
                (11 + name.len()) as u8,
                0x40,
                0x42,
                0x58,
                0,
                0,
                0x0c,
                0,
                0x17,
                1,
                3,
                0xc0 | name.len() as u8,
            ];
            record.extend_from_slice(name);
            self.reply(0x0a, 0x23, 0, &record);
        }
    }

    impl IpmiConnection for Mock {
        type SendError = Timeout;
        type RecvError = Timeout;
        type Error = Timeout;

        fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
            Err(Timeout)
        }
        fn recv(&mut self) -> Result<Response, Self::RecvError> {
            Err(Timeout)
        }
        fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
            self.sent.push(Sent {
                netfn: request.netfn_raw(),
                cmd: request.cmd(),
                data: request.data().to_vec(),
                target: request.target(),
            });
            self.replies.pop_front().unwrap_or(Err(Timeout))
        }
    }

    impl local::Sealed for Mock {}
    impl LocalSunTransport for Mock {}

    fn bmc() -> RequestTargetAddress {
        RequestTargetAddress::Bmc(LogicalUnit::Zero)
    }

    fn count(sent: &[Sent], cmd: u8) -> usize {
        sent.iter()
            .filter(|s| s.netfn == 0x2e && s.cmd == cmd)
            .count()
    }

    #[test]
    fn nacname_continuation_and_ping_exact_bytes() {
        let mut mock = Mock::default();
        let mut first = vec![1];
        first.extend([b'a'; 64]);
        let mut second = vec![0; 65];
        second[0] = 1;
        second[1..5].copy_from_slice(b"end\0");
        mock.sun(0x29, &first);
        mock.sun(0x29, &second);
        let mut ping = 0x1234u16.to_le_bytes().to_vec();
        ping.extend(0..64);
        mock.sun(0x23, &ping);
        let mut ipmi = Ipmi::new(mock);
        assert_eq!(
            ipmi.sun_nac_name("LED").unwrap(),
            format!("{}end", "a".repeat(64))
        );
        ipmi.sun_ping(0x1234).unwrap();
        let sent = ipmi.release().sent;
        assert_eq!(sent[1].data.len(), 65);
        assert_eq!(&sent[1].data[..5], &[0, b'L', b'E', b'D', 0]);
        assert_eq!(sent[3].data[0], 1);
        assert_eq!(sent[5].data, ping);

        let mut mock = Mock::default();
        let mut invalid = vec![0; 65];
        invalid[0] = 2;
        mock.sun(0x29, &invalid);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.sun_nac_name("LED"),
            Err(SunError::Protocol(_))
        ));
        assert_eq!(count(&ipmi.release().sent, 0x29), 1);
    }

    #[test]
    fn physical_led_uses_live_locator_channel_lun_and_confirmed_state() {
        let mut mock = Mock::default();
        mock.locator(b"LED0");
        mock.sun(0x21, &[1]);
        mock.sun(0x22, &[]);
        let mut ipmi = Ipmi::new(mock);
        ipmi.sun_set_led(
            WriteIntent::Approved,
            "LED0",
            LedType::Locator,
            LedMode::Fast,
        )
        .unwrap();
        let sent = ipmi.release().sent;
        assert_eq!(sent[0].cmd, 0x23);
        assert_eq!(sent[0].data, [0, 0, 0, 0, 0, 0xff]);
        let channel = Channel::new(2).unwrap();
        assert_eq!(
            sent[1].target,
            RequestTargetAddress::BmcOrIpmb(Address(0x40), channel, LogicalUnit::Zero)
        );
        assert_eq!(
            sent[2].target,
            RequestTargetAddress::BmcOrIpmb(Address(0x40), channel, LogicalUnit::Three)
        );
        assert_eq!(sent[2].data, [0x42, 3, 0x40, 3, 0x17, 1, 0]);
        assert_eq!(sent[4].data, [0x42, 3, 0x40, 3, 4, 0x17, 1, 0, 0]);

        let mut mock = Mock::default();
        mock.locator(b"LED0");
        mock.identity(7);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.sun_set_led(WriteIntent::Approved, "LED0", LedType::Locate, LedMode::On),
            Err(SunError::Oem(OemError::UnsupportedDevice { .. }))
        ));
        assert_eq!(count(&ipmi.release().sent, 0x22), 0);

        let mut mock = Mock::default();
        mock.locator(b"LED0");
        mock.sun(0x21, &[0]);
        mock.identity(42);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.sun_set_led(WriteIntent::Approved, "LED0", LedType::Locate, LedMode::On),
            Err(SunError::Oem(OemError::Command(IpmiError::Connection(
                Timeout
            ))))
        ));
        assert_eq!(count(&ipmi.release().sent, 0x22), 1);
    }

    #[test]
    fn sshkey_blocks_validate_input_and_never_replay_after_timeout() {
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
                .to_owned();
        let mut mock = Mock::default();
        mock.sun(0x01, &[]);
        mock.identity(42);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.sun_set_ssh_key(WriteIntent::Approved, 2, &key),
            Err(SunError::Oem(OemError::Command(IpmiError::Connection(
                Timeout
            ))))
        ));
        let sent = ipmi.release().sent;
        assert_eq!(count(&sent, 0x01), 2);
        assert_eq!(&sent[1].data[..3], &[2, 0, 64]);
        assert_eq!(&sent[3].data[..3], &[2, 0xff, (key.len() - 64) as u8]);

        let mut ipmi = Ipmi::new(Mock::default());
        assert!(matches!(
            ipmi.sun_set_ssh_key(WriteIntent::Approved, 0, &key),
            Err(SunError::InvalidInput(_))
        ));
        assert!(matches!(
            ipmi.sun_set_ssh_key(WriteIntent::Approved, 2, "-----BEGIN PRIVATE KEY-----"),
            Err(SunError::InvalidInput(_))
        ));
        assert!(ipmi.release().sent.is_empty());

        let mut mock = Mock::default();
        mock.sun(0x02, &[]);
        let mut ipmi = Ipmi::new(mock);
        ipmi.sun_delete_ssh_key(WriteIntent::Approved, 63).unwrap();
        assert_eq!(ipmi.release().sent[1].data, [63]);
    }

    #[test]
    fn getval_statuses_and_local_setval_chunks() {
        let mut mock = Mock::default();
        mock.sun(0x2a, &[1]);
        mock.sun(0x2a, &[4]);
        mock.sun(0x2a, b"\x03value\0");
        let mut ipmi = Ipmi::new(mock);
        assert_eq!(ipmi.sun_get_value("/SP/x").unwrap(), "value");
        let sent = ipmi.release().sent;
        assert_eq!(sent[1].data.len(), 80);
        assert_eq!(&sent[1].data[..7], b"\x01/SP/x\0");
        assert_eq!(sent[3].data[0], 2);
        assert_eq!(sent[5].data[0], 2);

        let mut mock = Mock::default();
        for reply in [[1, 7], [1, 7], [1, 7], [1, 7], [3, 7]] {
            mock.sun(0x2c, &reply);
        }
        let path = "p".repeat(57);
        let value = "v".repeat(57);
        let mut ipmi = Ipmi::new(mock);
        ipmi.sun_set_value(WriteIntent::Approved, &path, &value)
            .unwrap();
        let sent = ipmi.release().sent;
        let packets: Vec<_> = sent.iter().filter(|s| s.cmd == 0x2c).collect();
        assert_eq!(packets.len(), 5);
        assert_eq!(&packets[0].data[..5], &[3, 0, 0, 0, b'p']);
        assert_eq!(&packets[1].data[..5], &[3, 0, 7, 0, b'p']);
        assert_eq!(&packets[2].data[..5], &[3, 1, 7, 0, b'v']);
        assert_eq!(&packets[3].data[..5], &[3, 1, 7, 1, b'v']);
        assert_eq!(&packets[4].data[..4], &[4, 0, 7, 0]);
        assert!(packets.iter().all(|s| s.data.len() == 60));

        let mut mock = Mock::default();
        mock.sun(0x2c, &[1, 7]);
        mock.identity(42);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.sun_set_value(WriteIntent::Approved, "path", "value"),
            Err(SunError::Oem(OemError::Command(IpmiError::Connection(
                Timeout
            ))))
        ));
        assert_eq!(count(&ipmi.release().sent, 0x2c), 2);
    }

    #[test]
    fn tunnel_version_gate_network_order_blocks_and_bounds() {
        let mut mock = Mock::default();
        mock.version(3, 1);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.sun_get_file("DIAG_PASSED", 32),
            Err(SunError::UnsupportedVersion(_))
        ));
        assert_eq!(count(&ipmi.release().sent, 0x44), 0);

        let mut mock = Mock::default();
        mock.identity(674);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.sun_get_behavior("SUPPORTS_SIGNED_PACKAGES"),
            Err(SunError::Version(OemError::UnsupportedDevice { .. }))
        ));
        let sent = ipmi.release().sent;
        assert_eq!(count(&sent, 0x24), 0);
        assert_eq!(count(&sent, 0x44), 0);

        let mut mock = Mock::default();
        mock.version(3, 2);
        mock.sun(0x44, &[0, 0, 0, 0, 0, 0, 0, 2, 0, b'a', b'b']);
        mock.sun(0x44, &[0, 0, 0, 1, 0, 0, 0, 1, 1, b'c']);
        let mut ipmi = Ipmi::new(mock);
        assert_eq!(ipmi.sun_get_file("DIAG_PASSED", 32).unwrap(), b"abc");
        let sent = ipmi.release().sent;
        assert_eq!(&sent[3].data[..13], b"\x0bDIAG_PASSED\0");
        assert_eq!(sent[3].data.len(), 21);
        assert_eq!(&sent[5].data[17..21], &[0, 0, 0, 1]);

        let mut mock = Mock::default();
        mock.version(3, 2);
        mock.sun(0x44, &[0, 0, 0, 2, 0, 0, 0, 1, 1, b'x']);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.sun_get_file("X", 10),
            Err(SunError::Protocol(ProtocolError::InvalidSequence))
        ));
        assert_eq!(count(&ipmi.release().sent, 0x44), 1);

        let mut mock = Mock::default();
        mock.version(3, 2);
        mock.sun(0x44, &[0, 0, 0, 0, 0, 0, 4, 0, 0]);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.sun_get_file("X", 1024),
            Err(SunError::Protocol(ProtocolError::Truncated))
        ));
        assert_eq!(count(&ipmi.release().sent, 0x44), 1);

        let mut mock = Mock::default();
        mock.version(3, 2);
        mock.sun(0x44, &[0, 0, 0, 0, 0, 0, 0, 2, 1, b'a', b'b']);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(ipmi.sun_get_file("X", 1), Err(SunError::Limit)));
        assert_eq!(count(&ipmi.release().sent, 0x44), 1);

        let mut mock = Mock::default();
        mock.version(3, 2);
        mock.sun(0x44, &[1]);
        let mut ipmi = Ipmi::new(mock);
        assert!(ipmi.sun_get_behavior("SUPPORTS_SIGNED_PACKAGES").unwrap());
        let sent = ipmi.release().sent;
        assert_eq!(sent[3].data.len(), 33);
        assert_eq!(sent[3].data[0], 15);
    }

    #[test]
    fn cli_open_poll_eof_and_no_mutation_replay() {
        let mut mock = Mock::default();
        mock.sun(0x19, &[2, 0, 0, 0, 1, 2, 3, 4, 0]);
        mock.sun(0x19, &[2, 0, 1, 0, 1, 2, 3, 4, b'o', b'k', 0]);
        mock.sun(0x19, &[2, 0, 0, 0, 1, 2, 3, 4, 0]);
        mock.sun(0x19, &[2, 1, 1, 0, 1, 2, 3, 4, 0]);
        let mut ipmi = Ipmi::new(mock);
        assert_eq!(
            ipmi.sun_cli(WriteIntent::Approved, "ls", 100).unwrap(),
            b"ok"
        );
        let sent = ipmi.release().sent;
        assert_eq!(sent[1].data, [2, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(sent[3].data, b"\x02\x03\x01\0\x01\x02\x03\x04ls\n\0");
        assert_eq!(sent[5].data, [2, 3, 0, 0, 1, 2, 3, 4, 0]);
        assert_eq!(sent[7].data, [2, 4, 1, 0, 1, 2, 3, 4, 0]);

        let mut mock = Mock::default();
        mock.identity(42);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.sun_cli(WriteIntent::Approved, "ls", 100),
            Err(SunError::Oem(OemError::Command(IpmiError::Connection(
                Timeout
            ))))
        ));
        assert_eq!(count(&ipmi.release().sent, 0x19), 1);

        let mut mock = Mock::default();
        mock.identity(674);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.sun_cli(WriteIntent::Approved, "ls", 100),
            Err(SunError::Oem(OemError::UnsupportedDevice { .. }))
        ));
        assert_eq!(count(&ipmi.release().sent, 0x19), 0);

        let mut mock = Mock::default();
        mock.sun(
            0x19,
            &[
                2, 1, 0, 0, 0, 0, 0, 0, b'I', b'n', b'v', b'a', b'l', b'i', b'd', b' ', b'v', b'e',
                b'r', b's', b'i', b'o', b'n', 0,
            ],
        );
        mock.sun(0x19, &[1, 0, 0, 0, 1, 2, 3, 4, 0]);
        mock.sun(0x19, &[1, 0, 0, 0, 1, 2, 3, 4, 0]);
        mock.sun(0x19, &[1, 1, 0, 0, 1, 2, 3, 4, 0]);
        let mut ipmi = Ipmi::new(mock);
        assert_eq!(ipmi.sun_cli(WriteIntent::Approved, "ls", 1).unwrap(), b"");
        let sent = ipmi.release().sent;
        assert_eq!(count(&sent, 0x19), 4);
        assert_eq!(sent[3].data[0], 1);
    }

    #[test]
    fn malformed_status_response_and_sensitive_message_debug() {
        let mut mock = Mock::default();
        mock.sun(0x2a, &[2]);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.sun_get_value("/SP"),
            Err(SunError::Protocol(_))
        ));
        assert_eq!(count(&ipmi.release().sent, 0x2a), 1);
        let secret = b"ssh-ed25519 KEY".to_vec();
        let msg = Message::new_request(NETFN, 0x01, secret.clone());
        assert!(msg.is_sensitive());
        assert!(!format!("{msg:?}").contains("ssh-ed25519"));
        assert!(Message::new_response(NETFN, 0x2c, secret).is_sensitive());
        assert_eq!(bmc(), RequestTargetAddress::Bmc(LogicalUnit::Zero));

        let mut mock = Mock::default();
        mock.identity(42);
        mock.reply(0x2e, 0x02, 0xc1, b"echoed-secret");
        let mut ipmi = Ipmi::new(mock);
        let error = ipmi
            .sun_delete_ssh_key(WriteIntent::Approved, 2)
            .unwrap_err();
        assert!(!format!("{error:?}").contains("echoed-secret"));
        assert!(matches!(
            error,
            SunError::Oem(OemError::Command(IpmiError::Failed { data, .. })) if data.is_empty()
        ));
        assert_eq!(count(&ipmi.release().sent, 0x02), 1);
    }
}
