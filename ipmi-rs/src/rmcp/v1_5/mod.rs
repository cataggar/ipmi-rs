use std::{net::UdpSocket, num::NonZeroU32, time::Instant};

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
    socket: RmcpIpmiSocket,
    ipmb_state: IpmbState,
    session_id: Option<NonZeroU32>,
    auth_type: crate::app::auth::AuthType,
    password: Option<[u8; 16]>,
    session_sequence: u32,
    last_inbound_sequence: Option<u32>,
    activated: bool,
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
        }
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

        let request_sequence = &mut self.session_sequence;
        if self.session_id.is_some() && *request_sequence == u32::MAX {
            return Err(RmcpIpmiSendError::SessionSequenceExhausted);
        }
        let final_data = self.ipmb_state.begin(request, deadline)?;

        // Only increment the request sequence once a session has been established
        // successfully.
        if self.session_id.is_some() {
            *request_sequence += 1;
        }

        let message = Message {
            auth_type: self.auth_type,
            session_sequence_number: self.session_sequence,
            session_id: self.session_id.map_or(0, std::num::NonZero::get),
            payload: final_data,
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

        let sent = self.socket.send(deadline, |buffer| {
            message
                .write_data(self.password.as_ref(), buffer)
                .map_err(Send::Ipmi)
        });
        if sent.is_err() {
            self.ipmb_state.retire_pending();
        }
        match sent {
            Ok(()) => Ok(()),
            Err(Send::Ipmi(ipmi)) => Err(RmcpIpmiSendError::V1_5(ipmi)),
            Err(Send::Io(io)) => Err(RmcpIpmiSendError::V1_5(WriteError::Io(io))),
        }
    }

    fn recv(&mut self) -> Result<Response, RmcpIpmiReceiveError> {
        let deadline = self
            .ipmb_state
            .pending
            .ok_or(RmcpIpmiReceiveError::NoPendingRequest)?
            .deadline;
        let result = (|| {
            let mut unrelated = 0;
            let mut first_mismatch = None;
            loop {
                let data = match self.socket.recv_until_with_budget(deadline, &mut unrelated) {
                    Ok(data) => data,
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
                                .is_some_and(|last| message.session_sequence_number <= last))
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
                            self.last_inbound_sequence = Some(message.session_sequence_number);
                        }
                        return Ok(response);
                    }
                    Err(error) => return Err(error),
                }
            }
        })();
        self.ipmb_state.retire_pending();
        result
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.send(request)?;
        let response = self.recv().map_err(RmcpIpmiError::OutcomeUnknown)?;
        Ok(response)
    }
}
