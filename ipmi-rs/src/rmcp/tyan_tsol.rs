//! Opt-in Tyan IPMI 1.5 TSOL, separate from authenticated RMCP+ SOL.

use std::{
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use crate::{
    app::{
        auth::{
            GetChannelAuthenticationCapabilities, PrivilegeLevel, SetSessionPrivilegeError,
            SetSessionPrivilegeLevel,
        },
        tyan_tsol::{TsolEndpoint, TsolKeystroke, TsolStart, TsolStop, UnexpectedTsolResponse},
        ChannelAccessMode, ChannelMediumType, ChannelPrivilegeLevel, ChannelProtocolType,
        ChannelSessionSupport, GetChannelAccess, GetChannelInfo, GetDeviceId,
    },
    connection::Channel,
    Ipmi, IpmiError,
};

use super::{internal::Active, socket::MAX_DATAGRAM, Rmcp, RmcpIpmiError, RmcpIpmiSendError};

/// ipmitool's default TSOL listener port. Passing zero to `open_tyan_tsol_capture`
/// instead requests an ephemeral port.
pub const TYAN_TSOL_DEFAULT_PORT: u16 = 6230;

const MAX_UNRELATED: usize = 32;
const POLL: Duration = Duration::from_millis(50);
const CLEANUP_WAIT: Duration = Duration::from_millis(250);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

type CommandError = IpmiError<RmcpIpmiError, UnexpectedTsolResponse>;
type ProbeError = IpmiError<RmcpIpmiError, crate::connection::NotEnoughData>;
type PrivilegeError = IpmiError<RmcpIpmiError, SetSessionPrivilegeError>;

/// A bounded receive failure; the session stops on every such failure.
#[derive(Debug)]
pub enum TsolReceiveError {
    Io(std::io::Error),
    Timeout,
    Cancelled,
    TruncatedHeader,
    DatagramTooLarge,
    TooManyUnrelatedDatagrams,
}

/// The reason a TSOL session was interrupted.
#[derive(Debug)]
pub enum TsolInterruptionReason {
    Receive(TsolReceiveError),
    Keepalive(ProbeError),
    Keystroke(CommandError),
    Stop(CommandError),
    ClosedWithBufferedOutput,
}

/// Unread bytes retained on a close/interruption. Debug never logs console data.
#[derive(Default)]
pub struct BufferedTsolOutput(Vec<u8>);

impl BufferedTsolOutput {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Debug for BufferedTsolOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferedTsolOutput")
            .field("len", &self.0.len())
            .finish()
    }
}

/// An interrupted operation never replays input; only an acknowledged command
/// has `confirmed_input > 0`. The outcome of an unacknowledged send is unknown.
#[derive(Debug)]
pub struct TsolInterruption {
    pub reason: TsolInterruptionReason,
    pub confirmed_input: usize,
    pub input_delivery_uncertain: bool,
    pub remote_close_unconfirmed: bool,
    pub buffered_output: BufferedTsolOutput,
}

/// Errors from the opt-in Tyan TSOL lifecycle.
#[derive(Debug)]
pub enum TsolError {
    Ipmi15Required,
    AuthenticatedAdministratorRequired,
    Ipv4LanRequired,
    Io(std::io::Error),
    DeviceId(ProbeError),
    WrongDevice(u32),
    ChannelAuthentication(ProbeError),
    ChannelInfo(ProbeError),
    ChannelAccess(ProbeError),
    UnsupportedChannel,
    SetSessionPrivilege(PrivilegeError),
    ActivePrivilegeMismatch(PrivilegeLevel),
    InvalidInputLength,
    Closed,
    Start {
        source: CommandError,
        remote_close_unconfirmed: bool,
    },
    Interrupted(TsolInterruption),
}

/// Read-only TSOL output. No input/keystroke command is available on this type.
pub struct TsolCapture<'a>(TsolSession<'a>);

/// Explicit interactive TSOL: each input call sends at most one 14-byte command.
pub struct TsolInteractive<'a>(TsolSession<'a>);

struct TsolSession<'a> {
    connection: &'a mut Rmcp,
    listener: UdpSocket,
    endpoint: TsolEndpoint,
    peer: Ipv4Addr,
    active: bool,
    last_control_activity: Instant,
    key_sequence: u8,
    buffer: Box<[u8; MAX_DATAGRAM + 1]>,
    pending: std::ops::Range<usize>,
}

fn eligible_v15(connection: &mut Rmcp) -> Result<&mut super::v1_5::State, TsolError> {
    match connection
        .active_state
        .as_mut()
        .map(|active| active.state_mut())
    {
        Some(Active::V1_5(state)) if state.tsol_eligible() => Ok(state),
        Some(Active::V1_5(_)) => Err(TsolError::AuthenticatedAdministratorRequired),
        _ => Err(TsolError::Ipmi15Required),
    }
}

fn authenticated_v15(connection: &mut Rmcp) -> Result<&mut super::v1_5::State, TsolError> {
    let state = eligible_v15(connection)?;
    if state.tsol_capable() {
        Ok(state)
    } else {
        Err(TsolError::AuthenticatedAdministratorRequired)
    }
}

fn stop_bounded(connection: &mut Rmcp, endpoint: TsolEndpoint) -> Result<(), CommandError> {
    let state = authenticated_v15(connection)
        .map_err(|_| IpmiError::Connection(RmcpIpmiError::NotActive))?;
    let old_policy = state.socket.begin_cleanup(CLEANUP_WAIT);
    let result = Ipmi::new(&mut *connection).send_recv(TsolStop(endpoint));
    if let Ok(state) = authenticated_v15(connection) {
        state.socket.end_cleanup(old_policy);
    }
    result
}

fn may_have_executed(error: &CommandError) -> bool {
    !matches!(
        error,
        IpmiError::Failed { .. }
            | IpmiError::Connection(
                RmcpIpmiError::NotActive
                    | RmcpIpmiError::Send(
                        RmcpIpmiSendError::Cancelled
                            | RmcpIpmiSendError::DeadlineExpired
                            | RmcpIpmiSendError::RequestPending
                            | RmcpIpmiSendError::IpmbSequenceExhausted
                            | RmcpIpmiSendError::SessionSequenceExhausted
                            | RmcpIpmiSendError::UnsupportedTarget
                            | RmcpIpmiSendError::InvalidNetfn(_)
                    )
            )
    )
}

impl Rmcp {
    fn preflight_tyan_tsol(&mut self) -> Result<(Ipv4Addr, Ipv4Addr), TsolError> {
        let remote = match self.unbound_state.address() {
            SocketAddr::V4(remote) => *remote.ip(),
            SocketAddr::V6(_) => return Err(TsolError::Ipv4LanRequired),
        };
        let (local, peer) = eligible_v15(self)?
            .tsol_route()
            .map_err(|_| TsolError::Ipv4LanRequired)?;
        if peer != remote || TsolEndpoint::new(local, 1).is_none() {
            return Err(TsolError::Ipv4LanRequired);
        }

        let mut ipmi = Ipmi::new(&mut *self);
        let device = ipmi.send_recv(GetDeviceId).map_err(TsolError::DeviceId)?;
        if device.manufacturer_id != 6653 {
            return Err(TsolError::WrongDevice(device.manufacturer_id));
        }
        let caps = ipmi
            .send_recv(GetChannelAuthenticationCapabilities::new(
                Channel::Current,
                PrivilegeLevel::Administrator,
            ))
            .map_err(TsolError::ChannelAuthentication)?;
        if !caps.ipmi15_connections_supported
            || !caps.per_message_authentication_enabled
            || !caps.user_level_authentication_enabled
        {
            return Err(TsolError::UnsupportedChannel);
        }
        let info = ipmi
            .send_recv(GetChannelInfo::new(Channel::Current))
            .map_err(TsolError::ChannelInfo)?;
        if info.medium_type != ChannelMediumType::Lan802_3
            || info.protocol_type != ChannelProtocolType::IpmbV1_0
            || matches!(
                info.session_support,
                ChannelSessionSupport::Sessionless | ChannelSessionSupport::Reserved(_)
            )
        {
            return Err(TsolError::UnsupportedChannel);
        }
        let access = ipmi
            .send_recv(GetChannelAccess::volatile(Channel::Current))
            .map_err(TsolError::ChannelAccess)?;
        if !matches!(
            access.access_mode,
            ChannelAccessMode::AlwaysAvailable | ChannelAccessMode::Shared
        ) || !matches!(
            access.privilege_level_limit,
            ChannelPrivilegeLevel::Administrator | ChannelPrivilegeLevel::Oem
        ) || access.per_msg_auth_disabled
            || access.user_level_auth_disabled
        {
            return Err(TsolError::UnsupportedChannel);
        }

        eligible_v15(ipmi.inner_mut())?.set_tsol_active_privilege(None);
        let active = ipmi
            .send_recv(SetSessionPrivilegeLevel {
                privilege: PrivilegeLevel::Administrator,
            })
            .map_err(TsolError::SetSessionPrivilege)?;
        if active != PrivilegeLevel::Administrator {
            return Err(TsolError::ActivePrivilegeMismatch(active));
        }
        eligible_v15(self)?.set_tsol_active_privilege(Some(active));
        Ok((local, remote))
    }

    fn open_tyan_tsol(&mut self, port: u16) -> Result<TsolSession<'_>, TsolError> {
        let (local, peer) = self.preflight_tyan_tsol()?;
        let listener = UdpSocket::bind(SocketAddrV4::new(local, port)).map_err(TsolError::Io)?;
        let local_port = listener.local_addr().map_err(TsolError::Io)?.port();
        let endpoint = TsolEndpoint::new(local, local_port).ok_or(TsolError::Ipv4LanRequired)?;
        if let Err(source) = Ipmi::new(&mut *self).send_recv(TsolStart(endpoint)) {
            let remote_close_unconfirmed =
                may_have_executed(&source) && stop_bounded(self, endpoint).is_err();
            return Err(TsolError::Start {
                source,
                remote_close_unconfirmed,
            });
        }
        Ok(TsolSession {
            connection: self,
            listener,
            endpoint,
            peer,
            active: true,
            last_control_activity: Instant::now(),
            key_sequence: 0,
            buffer: Box::new([0; MAX_DATAGRAM + 1]),
            pending: 0..0,
        })
    }

    /// Opt into Tyan TSOL on an authenticated IPMI 1.5 LAN session. The
    /// receiver binds the connection's IPv4 route; `port == 0` picks an
    /// ephemeral port, otherwise 6230 is ipmitool's conventional default.
    /// Requires a Tyan device, an authenticated IPMI 1.5 session able to
    /// become administrator and an enabled LAN channel. Explicitly sets
    /// and confirms administrator as the active session privilege before
    /// sending Start. Never falls back to RMCP+ SOL.
    pub fn open_tyan_tsol_capture(&mut self, port: u16) -> Result<TsolCapture<'_>, TsolError> {
        self.open_tyan_tsol(port).map(TsolCapture)
    }

    /// As above, but grants access to explicitly sent, never-retried input.
    pub fn open_tyan_tsol_interactive(
        &mut self,
        port: u16,
    ) -> Result<TsolInteractive<'_>, TsolError> {
        self.open_tyan_tsol(port).map(TsolInteractive)
    }
}

impl TsolSession<'_> {
    fn receiver_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.endpoint.address(), self.endpoint.port())
    }

    fn take_pending(&mut self) -> BufferedTsolOutput {
        let output = BufferedTsolOutput(self.buffer[self.pending.clone()].to_vec());
        self.pending = 0..0;
        output
    }

    fn read_pending(&mut self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.pending.len());
        out[..count].copy_from_slice(&self.buffer[self.pending.start..self.pending.start + count]);
        self.pending.start += count;
        count
    }

    fn interrupt(
        &mut self,
        reason: TsolInterruptionReason,
        input_delivery_uncertain: bool,
    ) -> TsolError {
        self.active = false;
        let remote_close_unconfirmed = stop_bounded(self.connection, self.endpoint).is_err();
        TsolError::Interrupted(TsolInterruption {
            reason,
            confirmed_input: 0,
            input_delivery_uncertain,
            remote_close_unconfirmed,
            buffered_output: self.take_pending(),
        })
    }

    fn close_inner(&mut self) -> Result<(), TsolError> {
        if !self.active {
            return Err(TsolError::Closed);
        }
        self.active = false;
        let stopped = stop_bounded(self.connection, self.endpoint);
        let output = self.take_pending();
        if let Err(error) = stopped {
            return Err(TsolError::Interrupted(TsolInterruption {
                reason: TsolInterruptionReason::Stop(error),
                confirmed_input: 0,
                input_delivery_uncertain: false,
                remote_close_unconfirmed: true,
                buffered_output: output,
            }));
        }
        if !output.as_bytes().is_empty() {
            return Err(TsolError::Interrupted(TsolInterruption {
                reason: TsolInterruptionReason::ClosedWithBufferedOutput,
                confirmed_input: 0,
                input_delivery_uncertain: false,
                remote_close_unconfirmed: false,
                buffered_output: output,
            }));
        }
        Ok(())
    }

    fn keepalive_if_due(&mut self, deadline: Instant) -> Result<(), TsolError> {
        if self.last_control_activity.elapsed() < KEEPALIVE_INTERVAL {
            return Ok(());
        }
        if self.connection.cancellation_token().is_cancelled() {
            return Err(self.interrupt(
                TsolInterruptionReason::Receive(TsolReceiveError::Cancelled),
                false,
            ));
        }
        if Instant::now() >= deadline {
            return Err(self.interrupt(
                TsolInterruptionReason::Receive(TsolReceiveError::Timeout),
                false,
            ));
        }
        let previous = authenticated_v15(self.connection)?
            .socket
            .limit_deadline(deadline);
        let result = Ipmi::new(&mut *self.connection).send_recv(GetDeviceId);
        if let Ok(state) = authenticated_v15(self.connection) {
            state.socket.restore_deadline(previous);
        }
        match result {
            Ok(_) => {
                self.last_control_activity = Instant::now();
                Ok(())
            }
            Err(error) => Err(self.interrupt(TsolInterruptionReason::Keepalive(error), false)),
        }
    }

    fn read_until(&mut self, out: &mut [u8], deadline: Instant) -> Result<usize, TsolError> {
        if !self.active {
            return Err(TsolError::Closed);
        }
        if out.is_empty() {
            return Ok(0);
        }
        let deadline = deadline.min(self.connection.unbound_state.policy().deadline());
        let mut unrelated = 0;
        loop {
            if !self.pending.is_empty()
                && (Instant::now() >= deadline
                    || self.connection.cancellation_token().is_cancelled())
            {
                return Ok(self.read_pending(out));
            }
            self.keepalive_if_due(deadline)?;
            if !self.pending.is_empty() {
                return Ok(self.read_pending(out));
            }
            if self.connection.cancellation_token().is_cancelled() {
                return Err(self.interrupt(
                    TsolInterruptionReason::Receive(TsolReceiveError::Cancelled),
                    false,
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(self.interrupt(
                    TsolInterruptionReason::Receive(TsolReceiveError::Timeout),
                    false,
                ));
            }
            if let Err(error) = self.listener.set_read_timeout(Some(remaining.min(POLL))) {
                return Err(self.interrupt(
                    TsolInterruptionReason::Receive(TsolReceiveError::Io(error)),
                    false,
                ));
            }
            match self.listener.recv_from(&mut self.buffer[..]) {
                Ok((len, from)) => {
                    if !matches!(from, SocketAddr::V4(addr) if *addr.ip() == self.peer) {
                        unrelated += 1;
                        if unrelated >= MAX_UNRELATED {
                            return Err(self.interrupt(
                                TsolInterruptionReason::Receive(
                                    TsolReceiveError::TooManyUnrelatedDatagrams,
                                ),
                                false,
                            ));
                        }
                        continue;
                    }
                    if len > MAX_DATAGRAM {
                        return Err(self.interrupt(
                            TsolInterruptionReason::Receive(TsolReceiveError::DatagramTooLarge),
                            false,
                        ));
                    }
                    if len < 4 {
                        return Err(self.interrupt(
                            TsolInterruptionReason::Receive(TsolReceiveError::TruncatedHeader),
                            false,
                        ));
                    }
                    if len == 4 {
                        unrelated += 1;
                        if unrelated >= MAX_UNRELATED {
                            return Err(self.interrupt(
                                TsolInterruptionReason::Receive(
                                    TsolReceiveError::TooManyUnrelatedDatagrams,
                                ),
                                false,
                            ));
                        }
                        continue;
                    }
                    self.pending = 4..len;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(error) => {
                    return Err(self.interrupt(
                        TsolInterruptionReason::Receive(TsolReceiveError::Io(error)),
                        false,
                    ))
                }
            }
        }
    }

    fn send_input(&mut self, bytes: &[u8]) -> Result<usize, TsolError> {
        if !self.active {
            return Err(TsolError::Closed);
        }
        let command =
            TsolKeystroke::new(bytes, self.key_sequence).ok_or(TsolError::InvalidInputLength)?;
        if self.connection.cancellation_token().is_cancelled() {
            return Err(self.interrupt(
                TsolInterruptionReason::Receive(TsolReceiveError::Cancelled),
                false,
            ));
        }
        let deadline = self.connection.unbound_state.policy().deadline();
        self.keepalive_if_due(deadline)?;
        self.key_sequence = self.key_sequence.wrapping_add(1);
        let previous = authenticated_v15(self.connection)?
            .socket
            .limit_deadline(deadline);
        let result = Ipmi::new(&mut *self.connection).send_recv(command);
        if let Ok(state) = authenticated_v15(self.connection) {
            state.socket.restore_deadline(previous);
        }
        match result {
            Ok(()) => {
                self.last_control_activity = Instant::now();
                Ok(bytes.len())
            }
            Err(error) => {
                let uncertain = may_have_executed(&error);
                Err(self.interrupt(TsolInterruptionReason::Keystroke(error), uncertain))
            }
        }
    }
}

impl Drop for TsolSession<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.close_inner();
        }
    }
}

impl TsolCapture<'_> {
    /// The locally bound IPv4 address and port advertised to the BMC.
    pub fn receiver_addr(&self) -> SocketAddrV4 {
        self.0.receiver_addr()
    }

    /// Read at most the supplied output length. A timeout ends the session;
    /// partial datagrams remain buffered until read or returned on close.
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize, TsolError> {
        self.0
            .read_until(out, self.0.connection.unbound_state.policy().deadline())
    }

    /// Read until the earlier of this deadline and the connection timeout.
    pub fn read_until(&mut self, out: &mut [u8], deadline: Instant) -> Result<usize, TsolError> {
        self.0.read_until(out, deadline)
    }

    /// Explicitly stop the BMC stream; inspect failure before discarding it.
    pub fn close(mut self) -> Result<(), TsolError> {
        self.0.close_inner()
    }
}

impl TsolInteractive<'_> {
    pub fn receiver_addr(&self) -> SocketAddrV4 {
        self.0.receiver_addr()
    }

    pub fn read(&mut self, out: &mut [u8]) -> Result<usize, TsolError> {
        self.0
            .read_until(out, self.0.connection.unbound_state.policy().deadline())
    }

    pub fn read_until(&mut self, out: &mut [u8], deadline: Instant) -> Result<usize, TsolError> {
        self.0.read_until(out, deadline)
    }

    /// Send 1..=14 bytes once; an ambiguous response interrupts the session
    /// without resending any keystroke. Never automatically reconnects.
    pub fn send_input(&mut self, bytes: &[u8]) -> Result<usize, TsolError> {
        self.0.send_input(bytes)
    }

    pub fn close(mut self) -> Result<(), TsolError> {
        self.0.close_inner()
    }
}

#[cfg(test)]
mod tests;
