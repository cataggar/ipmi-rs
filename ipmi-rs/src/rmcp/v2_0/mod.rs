use std::num::NonZeroU32;
use zeroize::Zeroize;

use crate::app::auth::PrivilegeLevel;

mod crypto;
use crypto::CryptoState;
pub use crypto::{CryptoBackendError, CryptoProvider};

mod messages;
pub(in crate::rmcp) mod sol;
pub use sol::{SolFlags, SolFrame, SolFrameError};
use sol::{SolFlow, MAX_SOL_DATA};
#[cfg(test)]
mod tests;
use ipmi_rs_core::app::auth::{
    AuthenticationAlgorithm, CipherSuite, ConfidentialityAlgorithm, IntegrityAlgorithm,
};
pub(super) use messages::*;
pub use messages::{
    OpenSessionResponseErrorStatusCode, ParseSessionResponseError, RakpMessage2ErrorStatusCode,
    RakpMessage2ParseError, RakpMessage4ErrorStatusCode, RakpMessage4ParseError,
};

use self::crypto::CryptoUnwrapError;

use super::{
    internal::IpmbState, socket::RmcpIpmiSocket, v1_5, RmcpIpmiError, RmcpIpmiReceiveError,
    RmcpIpmiSendError, UnwrapSessionError,
};

#[derive(Debug)]
pub enum ValidateSessionResponseError {
    MessageTagMismatch,
    RemoteConsoleSessionIdMismatch,
    NegotiatedCipherSuiteMismatch {
        requested: CipherSuite,
        received: [u8; 3],
    },
    PrivilegeLevelMismatch,
    AuthenticationAlgorithmMismatch(AuthenticationAlgorithm),
    IntegrityAlgorithmMismatch(IntegrityAlgorithm),
    ConfidentialityAlgorithmMismatch(ConfidentialityAlgorithm),
}

#[derive(Debug)]
pub enum ValidateRakpMessage2Error {
    MessageTagMismatch,
    RemoteConsoleSessionIdMismatch,
}

#[derive(Debug)]
pub enum ValidateRakpMessage4Error {
    MessageTagMismatch,
    /// The RAKP4 wire field is the console ID, despite its legacy field name.
    RemoteConsoleSessionIdMismatch,
    ManagedSystemSessionIdMismatch,
}

#[derive(Debug)]
pub enum ActivationError {
    Io(std::io::Error),
    InvalidKeyExchangeAuthCodeLen(usize, AuthenticationAlgorithm),
    InvalidRakpMessage4IntegrityCheckValueLen(usize, AuthenticationAlgorithm),
    OpenSessionRequestSend(WriteError),
    OpenSessionResponseReceive(RmcpIpmiReceiveError),
    OpenSessionResponseRead(UnwrapSessionError),
    OpenSessionResponseParse(ParseSessionResponseError),
    OpenSessionResponseValidate(ValidateSessionResponseError),
    SendRakpMessage1(WriteError),
    RakpMessage2Receive(RmcpIpmiReceiveError),
    RakpMessage2Read(UnwrapSessionError),
    RakpMessage2Parse(RakpMessage2ParseError),
    RakpMessage2Validate(ValidateRakpMessage2Error),
    RakpMessage3Send(WriteError),
    RakpMessage4Receive(RmcpIpmiReceiveError),
    RakpMessage4Read(UnwrapSessionError),
    RakpMessage4Parse(RakpMessage4ParseError),
    RakpMessage4Validate(ValidateRakpMessage4Error),
    RakpMessage4InvalidIntegrityCheckValue,
    ServerAuthenticationFailed,
    UnsupportedAuthenticationAlgorithm(AuthenticationAlgorithm),
    UnexpectedPayloadType(PayloadType),
    UnexpectedSessionHeader,
    CryptoBackend(CryptoBackendError),
}

impl From<ParseSessionResponseError> for ActivationError {
    fn from(value: ParseSessionResponseError) -> Self {
        Self::OpenSessionResponseParse(value)
    }
}

impl From<ValidateSessionResponseError> for ActivationError {
    fn from(value: ValidateSessionResponseError) -> Self {
        Self::OpenSessionResponseValidate(value)
    }
}

impl From<ValidateRakpMessage2Error> for ActivationError {
    fn from(value: ValidateRakpMessage2Error) -> Self {
        Self::RakpMessage2Validate(value)
    }
}

impl From<ValidateRakpMessage4Error> for ActivationError {
    fn from(value: ValidateRakpMessage4Error) -> Self {
        Self::RakpMessage4Validate(value)
    }
}

#[derive(Debug)]
pub enum WriteError {
    Io(std::io::Error),
    Random(getrandom::Error),
    PayloadTooLong,
    EncryptedPayloadTooLong,
    InvalidEncryptionLength,
    UnsupportedIntegrityAlgorithm(IntegrityAlgorithm),
    UnsupportedConfidentialityAlgorithm(ConfidentialityAlgorithm),
    Cancelled,
    DeadlineExpired,
    CryptoBackend(CryptoBackendError),
}

impl From<std::io::Error> for WriteError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReadError {
    NotIpmiV2_0,
    NotEnoughData,
    NotRmcpPlus,
    InvalidPayloadType(u8),
    DecryptionError(CryptoUnwrapError),
}

impl From<CryptoUnwrapError> for ReadError {
    fn from(value: CryptoUnwrapError) -> Self {
        Self::DecryptionError(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PayloadType {
    IpmiMessage,
    Sol,
    RmcpPlusOpenSessionRequest,
    RmcpPlusOpenSessionResponse,
    RakpMessage1,
    RakpMessage2,
    RakpMessage3,
    RakpMessage4,
}

#[derive(Clone)]
pub struct Message {
    pub ty: PayloadType,
    pub session_id: u32,
    pub session_sequence_number: u32,
    pub payload: Vec<u8>,
}

impl core::fmt::Debug for Message {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug = f.debug_struct("Message");
        debug
            .field("ty", &self.ty)
            .field("session_id", &self.session_id)
            .field("session_sequence_number", &self.session_sequence_number);
        if self.ty == PayloadType::IpmiMessage && super::is_password_ipmb(&self.payload) {
            debug.field("payload", &"[REDACTED]");
        } else {
            debug.field("payload", &self.payload);
        }
        debug.finish()
    }
}

impl TryFrom<u8> for PayloadType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let ty = match value {
            0x00 => PayloadType::IpmiMessage,
            0x01 => PayloadType::Sol,
            0x10 => PayloadType::RmcpPlusOpenSessionRequest,
            0x11 => PayloadType::RmcpPlusOpenSessionResponse,
            0x12 => PayloadType::RakpMessage1,
            0x13 => PayloadType::RakpMessage2,
            0x14 => PayloadType::RakpMessage3,
            0x15 => PayloadType::RakpMessage4,
            _ => return Err(()),
        };

        Ok(ty)
    }
}

impl From<PayloadType> for u8 {
    fn from(value: PayloadType) -> Self {
        match value {
            PayloadType::IpmiMessage => 0x00,
            PayloadType::Sol => 0x01,
            PayloadType::RmcpPlusOpenSessionRequest => 0x10,
            PayloadType::RmcpPlusOpenSessionResponse => 0x11,
            PayloadType::RakpMessage1 => 0x12,
            PayloadType::RakpMessage2 => 0x13,
            PayloadType::RakpMessage3 => 0x14,
            PayloadType::RakpMessage4 => 0x15,
        }
    }
}

#[derive(Debug)]
pub struct State {
    pub(super) socket: RmcpIpmiSocket,
    session_id: NonZeroU32,
    session_sequence_number: NonZeroU32,
    console_session_id: NonZeroU32,
    last_inbound_sequence: Option<u32>,
    state: CryptoState,
    ipmb_state: IpmbState,
    sol: Option<Box<SolFlow>>,
}

impl State {
    fn validate_rakp4_mac_len(
        algorithm: AuthenticationAlgorithm,
        actual_len: usize,
    ) -> Result<(), ActivationError> {
        let expected_len = match algorithm {
            AuthenticationAlgorithm::RakpHmacSha1 => 12,
            AuthenticationAlgorithm::RakpHmacSha256 => 16,
            AuthenticationAlgorithm::RakpNone => 0,
            AuthenticationAlgorithm::RakpHmacMd5 => 16,
        };
        if actual_len != expected_len {
            Err(ActivationError::InvalidRakpMessage4IntegrityCheckValueLen(
                actual_len, algorithm,
            ))
        } else {
            Ok(())
        }
    }

    fn validate_open_session(
        req: &OpenSessionRequest,
        resp: &OpenSessionResponse,
    ) -> Result<(), ValidateSessionResponseError> {
        if resp.message_tag != req.message_tag {
            return Err(ValidateSessionResponseError::MessageTagMismatch);
        }

        if resp.remote_console_session_id != req.remote_console_session_id {
            return Err(ValidateSessionResponseError::RemoteConsoleSessionIdMismatch);
        }
        if req
            .requested_max_privilege
            .is_some_and(|level| level != resp.maximum_privilege_level)
        {
            return Err(ValidateSessionResponseError::PrivilegeLevelMismatch);
        }
        let requested = [
            u8::from(req.authentication_algorithms),
            u8::from(req.integrity_algorithms),
            u8::from(req.confidentiality_algorithms),
        ];
        let received = [
            u8::from(resp.authentication_payload),
            u8::from(resp.integrity_payload),
            u8::from(resp.confidentiality_payload),
        ];
        if requested == CipherSuite::Id17.into_suite() && received != requested {
            return Err(
                ValidateSessionResponseError::NegotiatedCipherSuiteMismatch {
                    requested: CipherSuite::Id17,
                    received,
                },
            );
        }
        if resp.authentication_payload != req.authentication_algorithms {
            return Err(
                ValidateSessionResponseError::AuthenticationAlgorithmMismatch(
                    resp.authentication_payload,
                ),
            );
        }
        if resp.integrity_payload != req.integrity_algorithms {
            return Err(ValidateSessionResponseError::IntegrityAlgorithmMismatch(
                resp.integrity_payload,
            ));
        }
        if resp.confidentiality_payload != req.confidentiality_algorithms {
            return Err(
                ValidateSessionResponseError::ConfidentialityAlgorithmMismatch(
                    resp.confidentiality_payload,
                ),
            );
        }

        Ok(())
    }

    fn open_session_request(
        requested_max_privilege: Option<PrivilegeLevel>,
        remote_console_session_id: NonZeroU32,
        suite: CipherSuite,
    ) -> OpenSessionRequest {
        OpenSessionRequest {
            message_tag: 0,
            requested_max_privilege,
            remote_console_session_id,
            authentication_algorithms: suite.authentication(),
            integrity_algorithms: suite.integrity(),
            confidentiality_algorithms: suite.confidentiality(),
        }
    }

    fn validate_rm1_rm2(
        remote_console_session_id: NonZeroU32,
        rm1: &RakpMessage1,
        rm2: &RakpMessage2,
    ) -> Result<(), ValidateRakpMessage2Error> {
        if rm1.message_tag != rm2.message_tag {
            return Err(ValidateRakpMessage2Error::MessageTagMismatch);
        }

        if remote_console_session_id != rm2.remote_console_session_id {
            return Err(ValidateRakpMessage2Error::RemoteConsoleSessionIdMismatch);
        }

        Ok(())
    }

    fn validate_rm3_rm4(
        remote_console_session_id: NonZeroU32,
        rm3: &RakpMessage3,
        rm4: &RakpMessage4,
    ) -> Result<(), ValidateRakpMessage4Error> {
        if rm3.message_tag != rm4.message_tag {
            return Err(ValidateRakpMessage4Error::MessageTagMismatch);
        }

        if rm4.managed_system_session_id != remote_console_session_id {
            return Err(ValidateRakpMessage4Error::RemoteConsoleSessionIdMismatch);
        }

        Ok(())
    }

    fn validate_handshake(message: &Message, expected: PayloadType) -> Result<(), ActivationError> {
        if message.ty != expected {
            return Err(ActivationError::UnexpectedPayloadType(message.ty));
        }
        if message.session_id != 0 || message.session_sequence_number != 0 {
            return Err(ActivationError::UnexpectedSessionHeader);
        }
        Ok(())
    }

    pub fn activate(
        state: v1_5::State,
        privilege_level: Option<PrivilegeLevel>,
        username: &Username,
        password: &[u8],
        kg: Option<&[u8]>,
        suite: CipherSuite,
        provider: CryptoProvider,
    ) -> Result<Self, ActivationError> {
        use rand::{CryptoRng, Rng};

        let mut rng = rand::thread_rng();

        // For good measure, add a compile time assert that
        // makes sure thread_rng is a crypto rng.
        fn assert_crypto_rng<T: CryptoRng>(_: &T) {}
        assert_crypto_rng(&rng);

        fn send(
            socket: &mut RmcpIpmiSocket,
            ty: PayloadType,
            payload: Vec<u8>,
        ) -> Result<(), WriteError> {
            if socket.cancellation_token().is_cancelled() {
                return Err(WriteError::Cancelled);
            }
            let deadline = socket.deadline();
            if deadline <= std::time::Instant::now() {
                return Err(WriteError::DeadlineExpired);
            }
            let mut message = Message {
                ty,
                session_id: 0,
                session_sequence_number: 0,
                payload,
            };

            let result = socket.send(deadline, |buffer| {
                CryptoState::write_unencrypted(&message, buffer)
            });
            message.payload.zeroize();
            result
        }

        fn recv(data: &mut [u8]) -> Result<Message, UnwrapSessionError> {
            CryptoState::default()
                .read_payload(data)
                .map_err(UnwrapSessionError::V2_0)
        }

        let mut socket = state.release_socket();

        let remote_console_session_id: NonZeroU32 = rng.gen();

        let open_session_request =
            Self::open_session_request(privilege_level, remote_console_session_id, suite);

        log::debug!("Sending RMCP+ Open Session Request. {open_session_request:X?}");

        let mut payload = Vec::new();
        open_session_request.write_data(&mut payload);
        send(
            &mut socket,
            PayloadType::RmcpPlusOpenSessionRequest,
            payload,
        )
        .map_err(ActivationError::OpenSessionRequestSend)?;

        let data = socket
            .recv()
            .map_err(ActivationError::OpenSessionResponseReceive)?;

        let response_data = recv(data).map_err(ActivationError::OpenSessionResponseRead)?;
        Self::validate_handshake(&response_data, PayloadType::RmcpPlusOpenSessionResponse)?;

        let response = match OpenSessionResponse::from_data(&response_data.payload) {
            Ok(r) => r,
            Err(ParseSessionResponseError::HaveErrorCode(error_code)) => {
                log::warn!("RMCP+ error occurred. Status code: '{error_code:?}'");
                return Err(ParseSessionResponseError::HaveErrorCode(error_code).into());
            }
            Err(e) => return Err(e.into()),
        };

        log::debug!("Received RMCP+ Open Session Response: {response:X?}.");

        Self::validate_open_session(&open_session_request, &response)?;

        let random_data = rng.gen();

        let rm1 = RakpMessage1 {
            message_tag: 0x0D,
            managed_system_session_id: response.managed_system_session_id,
            remote_console_random_number: random_data,
            requested_maximum_privilege_level: privilege_level
                .unwrap_or(response.maximum_privilege_level),
            username,
        };

        let mut payload = Vec::new();
        rm1.write(&mut payload);

        log::debug!("Sending RMCP+ RAKP Message 1");

        send(&mut socket, PayloadType::RakpMessage1, payload)
            .map_err(ActivationError::SendRakpMessage1)?;

        let data = socket
            .recv()
            .map_err(ActivationError::RakpMessage2Receive)?;

        let v2_message = recv(data).map_err(ActivationError::RakpMessage2Read)?;
        Self::validate_handshake(&v2_message, PayloadType::RakpMessage2)?;
        let rm2 = RakpMessage2::from_data(&v2_message.payload)
            .map_err(ActivationError::RakpMessage2Parse)?;

        log::debug!("Received RMCP+ RAKP Message 2");

        Self::validate_rm1_rm2(remote_console_session_id, &rm1, &rm2)?;

        let kex_auth_code = rm2.key_exchange_auth_code;

        let required_kex_auth_code_len = match response.authentication_payload {
            AuthenticationAlgorithm::RakpNone => 0,
            AuthenticationAlgorithm::RakpHmacSha1 => 20,
            AuthenticationAlgorithm::RakpHmacSha256 => 32,
            AuthenticationAlgorithm::RakpHmacMd5 => 16,
        };

        if kex_auth_code.len() != required_kex_auth_code_len {
            return Err(ActivationError::InvalidKeyExchangeAuthCodeLen(
                kex_auth_code.len(),
                response.authentication_payload,
            ));
        }

        let mut crypto_state = CryptoState::new_with_provider(kg, password, provider);
        let message_3_value = crypto_state
            .calculate_rakp3_data(&response, &rm1, &rm2)
            .map_err(ActivationError::CryptoBackend)?
            .map(zeroize::Zeroizing::new);

        let rm3 = if let Some(m3) = message_3_value.as_ref() {
            RakpMessage3 {
                message_tag: 0x0A,
                managed_system_session_id: response.managed_system_session_id,
                contents: RakpMessage3Contents::Success(m3),
            }
        } else {
            log::warn!("Received RAKP message 2 with invalid integrity check value.");

            RakpMessage3 {
                message_tag: 0x0A,
                managed_system_session_id: response.managed_system_session_id,
                contents: RakpMessage3Contents::Failure(
                    RakpMessage3ErrorStatusCode::InvalidIntegrityCheckValue,
                ),
            }
        };

        let mut payload = Vec::new();
        rm3.write(&mut payload);

        log::debug!("Sending RAKP message 3");

        send(&mut socket, PayloadType::RakpMessage3, payload)
            .map_err(ActivationError::RakpMessage3Send)?;

        if rm3.is_failure() {
            return Err(ActivationError::ServerAuthenticationFailed);
        }

        let data = socket
            .recv()
            .map_err(ActivationError::RakpMessage4Receive)?;

        let message = recv(data).map_err(ActivationError::RakpMessage4Read)?;
        Self::validate_handshake(&message, PayloadType::RakpMessage4)?;
        let rm4 = RakpMessage4::from_data(&message.payload)
            .map_err(ActivationError::RakpMessage4Parse)?;

        log::debug!("Received RAKP Message 4");

        Self::validate_rm3_rm4(response.remote_console_session_id, &rm3, &rm4)?;

        Self::validate_rakp4_mac_len(
            response.authentication_payload,
            rm4.integrity_check_value.len(),
        )?;

        if !crypto_state
            .verify(
                response.authentication_payload,
                &rm1.remote_console_random_number,
                rm3.managed_system_session_id.get(),
                &rm2.managed_system_guid,
                rm4.integrity_check_value,
            )
            .map_err(ActivationError::CryptoBackend)?
        {
            log::error!("Received incorrect/invalid integrity check value in RAKP Message 4.");
            return Err(ActivationError::RakpMessage4InvalidIntegrityCheckValue);
        }

        let session_id = rm3.managed_system_session_id;
        let session_sequence_number = NonZeroU32::MIN;
        socket.clear_activation_deadline();

        Ok(Self {
            socket,
            session_id,
            session_sequence_number,
            console_session_id: remote_console_session_id,
            last_inbound_sequence: None,
            state: crypto_state,
            ipmb_state: IpmbState::default(),
            sol: None,
        })
    }

    pub fn send(&mut self, request: &mut crate::connection::Request) -> Result<(), RmcpIpmiError> {
        if self.socket.cancellation_token().is_cancelled() {
            return Err(RmcpIpmiError::Send(super::RmcpIpmiSendError::Cancelled));
        }
        let deadline = self.socket.deadline();
        if deadline <= std::time::Instant::now() {
            return Err(RmcpIpmiError::Send(
                super::RmcpIpmiSendError::DeadlineExpired,
            ));
        }
        if self.session_sequence_number.get() == u32::MAX {
            return Err(RmcpIpmiError::Send(
                super::RmcpIpmiSendError::SessionSequenceExhausted,
            ));
        }

        let payload = self
            .ipmb_state
            .begin(request, deadline)
            .map_err(RmcpIpmiError::Send)?;
        let sent = self.send_payload(payload, deadline);
        if sent.is_err() {
            self.ipmb_state.retire_pending();
        }
        sent.map_err(super::RmcpIpmiSendError::into_operation_error)
    }

    fn send_payload(
        &mut self,
        payload: Vec<u8>,
        deadline: std::time::Instant,
    ) -> Result<(), super::RmcpIpmiSendError> {
        use super::RmcpIpmiSendError;
        if self.socket.cancellation_token().is_cancelled() {
            return Err(RmcpIpmiSendError::Cancelled);
        }
        if deadline <= std::time::Instant::now() {
            return Err(RmcpIpmiSendError::DeadlineExpired);
        }
        let seq = self.session_sequence_number.get();
        if seq == u32::MAX {
            return Err(RmcpIpmiSendError::SessionSequenceExhausted);
        }
        self.session_sequence_number = NonZeroU32::new(seq + 1).expect("checked");
        let message = Message {
            ty: PayloadType::IpmiMessage,
            session_id: self.session_id.get(),
            session_sequence_number: seq,
            payload,
        };
        self.socket
            .send(deadline, |buffer| {
                self.state.write_message(&message, buffer)
            })
            .map_err(Into::into)
    }

    fn receive_one(
        &mut self,
        deadline: std::time::Instant,
        unrelated: &mut usize,
        seen: &mut Vec<u32>,
    ) -> Result<Option<crate::connection::Response>, RmcpIpmiReceiveError> {
        let data = self.socket.recv_until_with_budget(deadline, unrelated)?;
        let message = self
            .state
            .read_payload(data)
            .map_err(|e| RmcpIpmiReceiveError::Session(UnwrapSessionError::V2_0(e)))?;
        if message.session_id != self.console_session_id.get() {
            return Err(RmcpIpmiReceiveError::SessionIdMismatch);
        }
        if message.session_sequence_number == 0
            || self
                .last_inbound_sequence
                .is_some_and(|last| message.session_sequence_number <= last)
            || seen.contains(&message.session_sequence_number)
        {
            return Err(RmcpIpmiReceiveError::InvalidSessionSequence);
        }
        if seen.len() >= 64 + super::socket::MAX_UNRELATED {
            return Err(RmcpIpmiReceiveError::TooManyUnrelatedPackets);
        }
        match message.ty {
            PayloadType::IpmiMessage => {
                if self.ipmb_state.pending.is_none() {
                    return Err(RmcpIpmiReceiveError::UnexpectedPayloadType);
                }
                let response = self.ipmb_state.receive(&message.payload)?;
                seen.push(message.session_sequence_number);
                Ok(response)
            }
            PayloadType::Sol => {
                if self.sol.is_none() {
                    return Err(RmcpIpmiReceiveError::UnexpectedPayloadType);
                }
                seen.push(message.session_sequence_number);
                let frame =
                    SolFrame::decode(&message.payload).map_err(RmcpIpmiReceiveError::Sol)?;
                let flow = self.sol.as_mut().expect("SOL state checked");
                let ack = match flow.accept(&frame) {
                    Ok(ack) => ack,
                    Err(err) => {
                        if frame.sequence != 0 {
                            self.send_sol_frame(&SolFrame::ack(frame.sequence, 0, true), deadline)
                                .map_err(|_| RmcpIpmiReceiveError::SolAckFailed)?;
                        }
                        return Err(RmcpIpmiReceiveError::Sol(err));
                    }
                };
                if let Some(ack) = ack {
                    self.send_sol_frame(&ack, deadline)
                        .map_err(|_| RmcpIpmiReceiveError::SolAckFailed)?;
                }
                if frame.flags.inactive || frame.flags.overrun {
                    return Err(RmcpIpmiReceiveError::Sol(if frame.flags.inactive {
                        SolFrameError::RemoteInactive
                    } else {
                        SolFrameError::OutputOverrun
                    }));
                }
                Ok(None)
            }
            _ => Err(RmcpIpmiReceiveError::UnexpectedPayloadType),
        }
    }

    pub fn recv(&mut self) -> Result<crate::connection::Response, RmcpIpmiReceiveError> {
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
                        std::time::Instant::now()
                            .checked_add(std::time::Duration::from_millis(50))
                            .unwrap_or(deadline)
                    });
                    std::time::Instant::now() >= *ready
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
                match self.receive_one(receive_deadline, &mut unrelated, &mut seen) {
                    Ok(Some(response)) => return Ok(response),
                    Ok(None) => {
                        if !self.ipmb_state.needs_poll() {
                            super::socket::count_unrelated(&mut unrelated)?;
                        }
                    }
                    Err(RmcpIpmiReceiveError::Timeout) if receive_deadline < deadline => continue,
                    Err(RmcpIpmiReceiveError::Timeout) => {
                        return Err(first_mismatch.unwrap_or(RmcpIpmiReceiveError::Timeout));
                    }
                    Err(
                        error @ (RmcpIpmiReceiveError::IpmbResponseMismatch
                        | RmcpIpmiReceiveError::SessionIdMismatch
                        | RmcpIpmiReceiveError::InvalidSessionSequence
                        | RmcpIpmiReceiveError::UnexpectedPayloadType),
                    ) => {
                        super::internal::record_unrelated(
                            error,
                            &mut first_mismatch,
                            &mut unrelated,
                        )?;
                    }
                    Err(error) => return Err(error),
                }
            }
        })();
        self.commit_session_sequences(&mut seen);
        self.ipmb_state.retire_pending();
        result
    }

    fn commit_session_sequences(&mut self, seen: &mut Vec<u32>) {
        if let Some(highest) = seen.iter().copied().max() {
            self.last_inbound_sequence = Some(highest);
        }
        seen.clear();
    }

    pub(super) fn sol_open(&mut self) {
        self.sol = Some(Box::new(SolFlow::new(MAX_SOL_DATA + 4, MAX_SOL_DATA + 4)));
    }

    pub(super) fn sol_limits(&mut self, input: u16, output: u16) {
        if let Some(flow) = self.sol.as_mut() {
            flow.max_input = usize::from(input).min(MAX_SOL_DATA + 4);
            flow.max_output = usize::from(output).min(MAX_SOL_DATA + 4);
        }
    }

    pub(super) fn sol_close(&mut self) {
        self.sol = None;
    }

    pub(super) fn sol_flow(&mut self) -> &mut SolFlow {
        self.sol.as_mut().expect("SOL session established")
    }

    pub(super) fn send_sol_frame(
        &mut self,
        frame: &SolFrame,
        deadline: std::time::Instant,
    ) -> Result<(), RmcpIpmiError> {
        use super::RmcpIpmiSendError;
        if self.socket.cancellation_token().is_cancelled() {
            return Err(RmcpIpmiError::Send(RmcpIpmiSendError::Cancelled));
        }
        if deadline <= std::time::Instant::now() {
            return Err(RmcpIpmiError::Send(RmcpIpmiSendError::DeadlineExpired));
        }
        let seq = self.session_sequence_number.get();
        if seq == u32::MAX {
            return Err(RmcpIpmiError::Send(
                RmcpIpmiSendError::SessionSequenceExhausted,
            ));
        }
        let payload = frame
            .encode()
            .map_err(|_| RmcpIpmiError::Send(RmcpIpmiSendError::SolFrame))?;
        self.session_sequence_number = NonZeroU32::new(seq + 1).expect("sequence checked");
        self.socket
            .send(deadline, |buffer| {
                self.state.write_message(
                    &Message {
                        ty: PayloadType::Sol,
                        session_id: self.session_id.get(),
                        session_sequence_number: seq,
                        payload: payload.clone(),
                    },
                    buffer,
                )
            })
            .map_err(|e| RmcpIpmiError::Send(e.into()))
    }

    pub(super) fn poll_sol(
        &mut self,
        deadline: std::time::Instant,
        wait_ack: bool,
    ) -> Result<(), RmcpIpmiReceiveError> {
        let mut unrelated = 0;
        let mut seen = Vec::new();
        loop {
            let result = self.receive_one(deadline, &mut unrelated, &mut seen);
            self.commit_session_sequences(&mut seen);
            if result?.is_some() {
                return Err(RmcpIpmiReceiveError::UnexpectedPayloadType);
            }
            let flow = self.sol_flow();
            if (wait_ack && flow.input_ack.is_some()) || (!wait_ack && flow.has_output()) {
                return Ok(());
            }
            super::socket::count_unrelated(&mut unrelated)?;
        }
    }

    pub fn send_recv(
        &mut self,
        request: &mut crate::connection::Request,
    ) -> Result<crate::connection::Response, RmcpIpmiError> {
        self.send(request)?;
        self.recv().map_err(RmcpIpmiError::OutcomeUnknown)
    }
}

#[cfg(test)]
mod suite17_tests {
    use super::*;
    use ipmi_rs_core::app::auth::{ConfidentialityAlgorithm, IntegrityAlgorithm};

    #[test]
    fn suite17_open_session_wire_and_negotiation() {
        let req = State::open_session_request(
            Some(PrivilegeLevel::Administrator),
            NonZeroU32::new(0x10203040).unwrap(),
            CipherSuite::Id17,
        );
        let mut actual = Vec::new();
        req.write_data(&mut actual);
        assert_eq!(
            actual,
            hex::decode("0004000040302010000000080300000001000008040000000200000801000000")
                .unwrap()
        );

        let response = OpenSessionResponse::from_data(
            &hex::decode(
                "000004004030201088776655000000080300000001000008040000000200000801000000",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(State::validate_open_session(&req, &response).is_ok());

        for changed in 0..3 {
            let mut substituted = response.clone();
            match changed {
                0 => substituted.authentication_payload = AuthenticationAlgorithm::RakpHmacSha1,
                1 => substituted.integrity_payload = IntegrityAlgorithm::HmacSha1_96,
                _ => substituted.confidentiality_payload = ConfidentialityAlgorithm::None,
            }
            assert!(matches!(
                State::validate_open_session(&req, &substituted),
                Err(
                    ValidateSessionResponseError::NegotiatedCipherSuiteMismatch {
                        requested: CipherSuite::Id17,
                        ..
                    }
                )
            ));
        }

        assert_eq!(
            OpenSessionResponse::from_data(&[0, 0x11]),
            Err(ParseSessionResponseError::HaveErrorCode(Ok(
                OpenSessionResponseErrorStatusCode::NoMatchingCipherSuite
            )))
        );
    }

    #[test]
    fn default_suite_stays_three_and_rakp4_length_is_exact() {
        let req = State::open_session_request(None, NonZeroU32::new(1).unwrap(), CipherSuite::Id3);
        assert_eq!(
            [
                u8::from(req.authentication_algorithms),
                u8::from(req.integrity_algorithms),
                u8::from(req.confidentiality_algorithms)
            ],
            [1, 1, 1]
        );

        for len in [0, 12, 15, 17, 32] {
            assert!(matches!(
                State::validate_rakp4_mac_len(AuthenticationAlgorithm::RakpHmacSha256, len),
                Err(ActivationError::InvalidRakpMessage4IntegrityCheckValueLen(
                    _,
                    _
                ))
            ));
        }
        assert!(State::validate_rakp4_mac_len(AuthenticationAlgorithm::RakpHmacSha256, 16).is_ok());
    }
}
