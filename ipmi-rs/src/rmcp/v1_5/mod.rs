use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    num::NonZeroU32,
    time::Instant,
};

use crate::{
    app::auth::{
        ActivateSession, AuthError, AuthType, ChannelAuthenticationCapabilities,
        GetSessionChallenge, PrivilegeLevel,
    },
    connection::{IpmiConnection, Request, Response},
    Ipmi, IpmiError,
};

use super::{
    internal::IpmbState,
    socket::{RmcpIpmiSocket, TransportPolicy},
    RmcpIpmiError, RmcpIpmiReceiveError, RmcpIpmiSendError,
};

pub use message::Message;

mod auth;
mod md2;
#[cfg(feature = "md5")]
mod md5;
mod message;
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum ActivationError {
    Io(std::io::Error),
    PasswordTooLong,
    UsernameTooLong,
    GetSessionChallenge(IpmiError<RmcpIpmiError, AuthError>),
    NoSupportedAuthenticationType,
    ActivateSession(IpmiError<RmcpIpmiError, AuthError>),
}

#[derive(Debug)]
pub enum WriteError {
    Io(std::io::Error),
    /// A request was made to calculate the auth code for a message authenticated
    /// using a method that requires a password, but no password was provided.
    MissingPassword,
    /// The payload length of for the V1_5 packet is larger than the maximum
    /// allowed size (256 bytes).
    PayloadTooLarge(usize),
    /// The requested auth type is not supported.
    UnsupportedAuthType(AuthType),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReadError {
    /// There is not enough data in the packet to form a valid `Message`.
    NotEnoughData,
    /// The auth type provided is not supported.
    UnsupportedAuthType(u8),
    /// There is a mismatch between the payload length field and the
    /// actual length of the payload.
    IncorrectPayloadLen,
    /// The auth code of the message is not correct.
    AuthcodeError,
}

pub struct State {
    pub(super) socket: RmcpIpmiSocket,
    ipmb_state: IpmbState,
    session_id: Option<NonZeroU32>,
    auth_type: crate::app::auth::AuthType,
    password: Option<[u8; 16]>,
    session_sequence: u32,
    last_inbound_sequence: Option<u32>,
    activated: bool,
    maximum_privilege: Option<PrivilegeLevel>,
    active_privilege: Option<PrivilegeLevel>,
    negotiated_auth: Option<AuthType>,
}

impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("socket", &self.socket)
            .field("ipmb_state", &self.ipmb_state)
            .field("session_id", &self.session_id)
            .field("auth_type", &self.auth_type)
            .field("password", &"<redacted>")
            .field("session_sequence", &self.session_sequence)
            .finish()
    }
}

impl State {
    fn send_payload(
        &mut self,
        payload: Vec<u8>,
        deadline: Instant,
    ) -> Result<(), RmcpIpmiSendError> {
        if self.socket.cancellation_token().is_cancelled() {
            return Err(RmcpIpmiSendError::Cancelled);
        }
        if deadline <= Instant::now() {
            return Err(RmcpIpmiSendError::DeadlineExpired);
        }
        if self.session_id.is_some() && self.session_sequence == u32::MAX {
            return Err(RmcpIpmiSendError::SessionSequenceExhausted);
        }
        if self.session_id.is_some() {
            self.session_sequence += 1;
        }
        let message = Message {
            auth_type: self.auth_type,
            session_sequence_number: self.session_sequence,
            session_id: self.session_id.map_or(0, std::num::NonZero::get),
            payload,
        };
        enum Send {
            Ipmi(WriteError),
            Io(std::io::Error),
        }
        impl From<std::io::Error> for Send {
            fn from(value: std::io::Error) -> Self {
                Self::Io(value)
            }
        }
        self.socket
            .send(deadline, |buffer| {
                message
                    .write_data(self.password.as_ref(), buffer)
                    .map_err(Send::Ipmi)
            })
            .map_err(|error| match error {
                Send::Ipmi(ipmi) => RmcpIpmiSendError::V1_5(ipmi),
                Send::Io(io) => RmcpIpmiSendError::V1_5(WriteError::Io(io)),
            })
    }

    pub(crate) fn socket_mut(&mut self) -> &mut RmcpIpmiSocket {
        &mut self.socket
    }

    #[cfg(test)]
    pub(super) fn test_authenticated(
        socket: UdpSocket,
        privilege: PrivilegeLevel,
        auth_type: AuthType,
        timeout: std::time::Duration,
    ) -> Self {
        let mut state = Self::new(socket, TransportPolicy::new(timeout), None);
        state.session_id = NonZeroU32::new(0x1234);
        state.session_sequence = 1;
        state.activated = true;
        state.maximum_privilege = Some(privilege);
        state.active_privilege = None;
        state.negotiated_auth = Some(auth_type);
        state.auth_type = auth_type;
        state.password = Some([9; 16]);
        state
    }

    pub fn new(
        socket: UdpSocket,
        policy: TransportPolicy,
        activation_deadline: Option<Instant>,
    ) -> Self {
        Self {
            socket: RmcpIpmiSocket::new(socket, policy, activation_deadline),
            ipmb_state: IpmbState::default(),
            auth_type: AuthType::None,
            password: None,
            session_id: None,
            session_sequence: 0,
            last_inbound_sequence: None,
            activated: false,
            maximum_privilege: None,
            active_privilege: None,
            negotiated_auth: None,
        }
    }

    pub(super) fn tsol_eligible(&self) -> bool {
        self.activated
            && self.maximum_privilege == Some(PrivilegeLevel::Administrator)
            && self.negotiated_auth == Some(self.auth_type)
            && matches!(self.auth_type, AuthType::MD2 | AuthType::MD5)
            && self.password.is_some()
    }

    pub(super) fn tsol_capable(&self) -> bool {
        self.tsol_eligible() && self.active_privilege == Some(PrivilegeLevel::Administrator)
    }

    pub(super) fn set_tsol_active_privilege(&mut self, privilege: Option<PrivilegeLevel>) {
        self.active_privilege = privilege;
    }

    pub(super) fn tsol_route(&self) -> std::io::Result<(Ipv4Addr, Ipv4Addr)> {
        fn ipv4(address: SocketAddr) -> std::io::Result<Ipv4Addr> {
            let ip = match address {
                SocketAddr::V4(address) => Some(*address.ip()),
                SocketAddr::V6(address) => address.ip().to_ipv4_mapped(),
            };
            ip.ok_or_else(|| std::io::Error::other("Tyan TSOL requires IPv4 LAN"))
        }
        Ok((
            ipv4(self.socket.local_addr()?)?,
            ipv4(self.socket.peer_addr()?)?,
        ))
    }

    pub fn release_socket(self) -> RmcpIpmiSocket {
        self.socket
    }

    pub fn require_rmcp_plus(&self) -> bool {
        self.socket.require_rmcp_plus()
    }

    pub fn activate(
        mut self,
        authentication_caps: &ChannelAuthenticationCapabilities,
        privilege_level: PrivilegeLevel,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<Self, ActivationError> {
        let password = if let Some(password) = password {
            if password.len() > 16 {
                return Err(ActivationError::PasswordTooLong);
            }
            let mut padded = [0u8; 16];
            padded[..password.len()].copy_from_slice(password);
            Some(padded)
        } else {
            None
        };

        self.password = password;

        let mut ipmi = Ipmi::new(self);

        log::debug!("Requesting challenge");

        let challenge_command = match GetSessionChallenge::new(AuthType::None, username) {
            Some(v) => v,
            None => return Err(ActivationError::UsernameTooLong),
        };

        let challenge = match ipmi.send_recv(challenge_command) {
            Ok(v) => v,
            Err(e) => return Err(ActivationError::GetSessionChallenge(e)),
        };

        let activation_auth_type = authentication_caps
            .best_auth()
            .ok_or(ActivationError::NoSupportedAuthenticationType)?;

        let activate_session: ActivateSession = ActivateSession {
            auth_type: activation_auth_type,
            maximum_privilege_level: privilege_level,
            challenge_string: challenge.challenge_string,
            initial_sequence_number: 0xDEAD_BEEF,
        };

        ipmi.inner_mut().session_id = Some(challenge.temporary_session_id);
        ipmi.inner_mut().auth_type = activation_auth_type;

        log::debug!("Activating session");

        let activation_info = match ipmi.send_recv(activate_session.clone()) {
            Ok(v) => v,
            Err(e) => return Err(ActivationError::ActivateSession(e)),
        };

        log::debug!("Successfully started a session ({:?})", activation_info);

        self = ipmi.release();

        self.session_sequence = activation_info.initial_sequence_number;
        self.session_id = Some(activation_info.session_id);
        self.last_inbound_sequence = None;
        self.maximum_privilege = Some(activation_info.maximum_privilege_level);
        self.active_privilege = None;
        self.negotiated_auth = Some(activation_info.auth_type);
        self.activated = true;
        self.socket.clear_activation_deadline();

        assert_eq!(activate_session.auth_type, activation_auth_type);

        Ok(self)
    }
}

impl IpmiConnection for State {
    type SendError = RmcpIpmiSendError;

    type RecvError = RmcpIpmiReceiveError;

    type Error = RmcpIpmiError;

    fn send(&mut self, request: &mut Request) -> Result<(), RmcpIpmiSendError> {
        log::trace!("Sending message with auth type {:?}", self.auth_type);
        if self.socket.cancellation_token().is_cancelled() {
            return Err(RmcpIpmiSendError::Cancelled);
        }
        let deadline = self.socket.deadline();
        if deadline <= Instant::now() {
            return Err(RmcpIpmiSendError::DeadlineExpired);
        }

        if self.session_id.is_some() && self.session_sequence == u32::MAX {
            return Err(RmcpIpmiSendError::SessionSequenceExhausted);
        }
        let final_data = self.ipmb_state.begin(request, deadline)?;
        let sent = self.send_payload(final_data, deadline);
        if sent.is_err() {
            self.ipmb_state.retire_pending();
        }
        sent
    }

    fn recv(&mut self) -> Result<Response, RmcpIpmiReceiveError> {
        let deadline = self
            .ipmb_state
            .pending
            .as_ref()
            .ok_or(RmcpIpmiReceiveError::NoPendingRequest)?
            .deadline;
        let mut seen = Vec::new();
        let result = (|| {
            let mut unrelated = 0;
            let mut first_mismatch = None;
            let mut polls = 0;
            let mut next_probe = None;
            loop {
                let needs_poll = self.ipmb_state.needs_poll();
                let send_poll = if needs_poll && polls > 0 && !self.ipmb_state.queue_available() {
                    let ready = next_probe.get_or_insert_with(|| {
                        Instant::now()
                            .checked_add(std::time::Duration::from_millis(50))
                            .unwrap_or(deadline)
                    });
                    Instant::now() >= *ready
                } else {
                    needs_poll
                };
                if send_poll {
                    next_probe = None;
                    let poll = match self.ipmb_state.poll_message() {
                        Ok(poll) => poll,
                        Err(RmcpIpmiSendError::IpmbSequenceExhausted) => {
                            self.ipmb_state.stop_polling();
                            continue;
                        }
                        Err(error) => return Err(RmcpIpmiReceiveError::BridgePollSend(error)),
                    };
                    self.send_payload(poll, deadline)
                        .map_err(RmcpIpmiReceiveError::BridgePollSend)?;
                    polls += 1;
                } else if !needs_poll {
                    next_probe = None;
                }
                let receive_deadline = next_probe.unwrap_or(deadline).min(deadline);
                let data = match self
                    .socket
                    .recv_until_with_budget(receive_deadline, &mut unrelated)
                {
                    Ok(data) => data,
                    Err(RmcpIpmiReceiveError::Timeout) if receive_deadline < deadline => continue,
                    Err(RmcpIpmiReceiveError::Timeout) => {
                        return Err(first_mismatch.unwrap_or(RmcpIpmiReceiveError::Timeout));
                    }
                    Err(error) => return Err(error),
                };
                let message = Message::from_data(self.password.as_ref(), data).map_err(|e| {
                    RmcpIpmiReceiveError::Session(super::UnwrapSessionError::V1_5(e))
                })?;
                if let Some(session_id) = self.session_id {
                    if message.session_id != session_id.get() || message.auth_type != self.auth_type
                    {
                        super::internal::record_unrelated(
                            RmcpIpmiReceiveError::SessionIdMismatch,
                            &mut first_mismatch,
                            &mut unrelated,
                        )?;
                        continue;
                    }
                    if self.activated
                        && (message.session_sequence_number == 0
                            || self
                                .last_inbound_sequence
                                .is_some_and(|last| message.session_sequence_number <= last)
                            || seen.contains(&message.session_sequence_number))
                    {
                        super::internal::record_unrelated(
                            RmcpIpmiReceiveError::InvalidSessionSequence,
                            &mut first_mismatch,
                            &mut unrelated,
                        )?;
                        continue;
                    }
                }
                match self.ipmb_state.receive(&message.payload) {
                    Err(RmcpIpmiReceiveError::IpmbResponseMismatch) => {
                        super::internal::record_unrelated(
                            RmcpIpmiReceiveError::IpmbResponseMismatch,
                            &mut first_mismatch,
                            &mut unrelated,
                        )?;
                    }
                    Ok(response) => {
                        if self.activated {
                            if seen.len() >= 64 + super::socket::MAX_UNRELATED {
                                return Err(RmcpIpmiReceiveError::TooManyUnrelatedPackets);
                            }
                            seen.push(message.session_sequence_number);
                        }
                        if let Some(response) = response {
                            return Ok(response);
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
        })();
        if let Some(highest) = seen.into_iter().max() {
            self.last_inbound_sequence = Some(highest);
        }
        self.ipmb_state.retire_pending();
        result
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.send(request)
            .map_err(RmcpIpmiSendError::into_operation_error)?;
        let response = self.recv().map_err(RmcpIpmiError::OutcomeUnknown)?;
        Ok(response)
    }
}
