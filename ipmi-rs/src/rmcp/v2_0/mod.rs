use std::{num::NonZeroU32, ops::Add};

use crate::app::auth::PrivilegeLevel;

mod crypto;
use crypto::CryptoState;

mod messages;
use ipmi_rs_core::{
    app::auth::{AuthenticationAlgorithm, CipherSuite},
    connection::Response,
};
pub(super) use messages::*;
pub use messages::{
    OpenSessionResponseErrorStatusCode, ParseSessionResponseError, RakpMessage2ErrorStatusCode,
    RakpMessage2ParseError, RakpMessage4ErrorStatusCode, RakpMessage4ParseError,
};

use self::crypto::CryptoUnwrapError;

use super::{
    internal::IpmbState, socket::RmcpIpmiSocket, v1_5, RmcpIpmiError, RmcpIpmiReceiveError,
    UnwrapSessionError,
};

#[derive(Debug)]
pub enum ValidateSessionResponseError {
    MessageTagMismatch,
    RemoteConsoleSessionIdMismatch,
    NegotiatedCipherSuiteMismatch {
        requested: CipherSuite,
        received: [u8; 3],
    },
}

#[derive(Debug)]
pub enum ValidateRakpMessage2Error {
    MessageTagMismatch,
    RemoteConsoleSessionIdMismatch,
}

#[derive(Debug)]
pub enum ValidateRakpMessage4Error {
    MessageTagMismatch,
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
    PayloadTooLong,
    EncryptedPayloadTooLong,
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

#[derive(Debug, Clone)]
pub struct Message {
    pub ty: PayloadType,
    pub session_id: u32,
    pub session_sequence_number: u32,
    pub payload: Vec<u8>,
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
    socket: RmcpIpmiSocket,
    session_id: NonZeroU32,
    session_sequence_number: NonZeroU32,
    state: CryptoState,
    ipmb_state: IpmbState,
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
        if received != requested {
            return Err(
                ValidateSessionResponseError::NegotiatedCipherSuiteMismatch {
                    requested: CipherSuite::from_suite(requested)
                        .expect("requested suite is defined"),
                    received,
                },
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
        managed_system_session_id: NonZeroU32,
        rm3: &RakpMessage3,
        rm4: &RakpMessage4,
    ) -> Result<(), ValidateRakpMessage4Error> {
        if rm3.message_tag != rm4.message_tag {
            return Err(ValidateRakpMessage4Error::MessageTagMismatch);
        }

        if rm4.managed_system_session_id != managed_system_session_id {
            return Err(ValidateRakpMessage4Error::ManagedSystemSessionIdMismatch);
        }

        Ok(())
    }

    pub fn activate(
        state: v1_5::State,
        privilege_level: Option<PrivilegeLevel>,
        username: &Username,
        password: &[u8],
        suite: CipherSuite,
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
            let message = Message {
                ty,
                session_id: 0,
                session_sequence_number: 0,
                payload,
            };

            socket.send(|buffer| CryptoState::write_unencrypted(&message, buffer))
        }

        fn recv(data: &mut [u8]) -> Result<Message, UnwrapSessionError> {
            CryptoState::default()
                .read_payload(data)
                .map_err(UnwrapSessionError::V2_0)
        }

        let mut socket = RmcpIpmiSocket::new(state.release_socket());

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
            requested_maximum_privilege_level: PrivilegeLevel::Administrator,
            username,
        };

        let mut payload = Vec::new();
        rm1.write(&mut payload);

        log::debug!("Sending RMCP+ RAKP Message 1. {rm1:X?}");

        send(&mut socket, PayloadType::RakpMessage1, payload)
            .map_err(ActivationError::SendRakpMessage1)?;

        let data = socket
            .recv()
            .map_err(ActivationError::RakpMessage2Receive)?;

        let v2_message = recv(data).map_err(ActivationError::RakpMessage2Read)?;
        let rm2 = RakpMessage2::from_data(&v2_message.payload)
            .map_err(ActivationError::RakpMessage2Parse)?;

        log::debug!("Received RMCP+ RAKP Message 2. {rm2:X?}");

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

        let mut crypto_state = CryptoState::new(None, password);
        let message_3_value = crypto_state.calculate_rakp3_data(&response, &rm1, &rm2);

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

        log::debug!("Sending RAKP message 3. {rm3:X?}");

        send(&mut socket, PayloadType::RakpMessage3, payload)
            .map_err(ActivationError::RakpMessage3Send)?;

        if rm3.is_failure() {
            return Err(ActivationError::ServerAuthenticationFailed);
        }

        let data = socket
            .recv()
            .map_err(ActivationError::RakpMessage4Receive)?;

        let message = recv(data).map_err(ActivationError::RakpMessage4Read)?;
        let rm4 = RakpMessage4::from_data(&message.payload)
            .map_err(ActivationError::RakpMessage4Parse)?;

        log::debug!("Received RAKP Message 4: {rm4:X?}");

        Self::validate_rm3_rm4(response.remote_console_session_id, &rm3, &rm4)?;

        Self::validate_rakp4_mac_len(
            response.authentication_payload,
            rm4.integrity_check_value.len(),
        )?;

        if !crypto_state.verify(
            response.authentication_payload,
            &rm1.remote_console_random_number,
            rm3.managed_system_session_id.get(),
            &rm2.managed_system_guid,
            rm4.integrity_check_value,
        ) {
            log::error!("Received incorrect/invalid integrity check value in RAKP Message 4.");
            return Err(ActivationError::RakpMessage4InvalidIntegrityCheckValue);
        }

        let session_id = rm3.managed_system_session_id;
        let session_sequence_number = NonZeroU32::new(1).unwrap();

        Ok(Self {
            socket,
            session_id,
            session_sequence_number,
            state: crypto_state,
            ipmb_state: IpmbState::default(),
        })
    }

    pub fn send(&mut self, request: &mut crate::connection::Request) -> Result<(), RmcpIpmiError> {
        let session_sequence_number = self.session_sequence_number.get();

        if session_sequence_number == u32::MAX {
            todo!("Handle wrapping session number by re-activating?");
        }

        self.session_sequence_number =
            NonZeroU32::new(self.session_sequence_number.get().add(1)).unwrap();

        let payload = super::internal::next_ipmb_message(request, &mut self.ipmb_state);

        let message = Message {
            ty: PayloadType::IpmiMessage,
            session_id: self.session_id.get(),
            session_sequence_number,
            payload,
        };

        self.socket
            .send(|buffer| self.state.write_message(&message, buffer))
            .unwrap();

        Ok(())
    }

    // TODO: validate session sequence number
    // TODO: Validate session sequence ID
    pub fn recv(&mut self) -> Result<crate::connection::Response, RmcpIpmiReceiveError> {
        let data = self.socket.recv()?;

        let data = self
            .state
            .read_payload(data)
            .map_err(|e| RmcpIpmiReceiveError::Session(UnwrapSessionError::V2_0(e)))?
            .payload;

        if data.len() < 7 {
            return Err(RmcpIpmiReceiveError::NotEnoughData);
        }

        let _req_addr = data[0];
        let netfn = data[1] >> 2;
        let _checksum1 = data[2];
        let _rs_addr = data[3];
        let _rqseq = data[4];
        let cmd = data[5];
        let response_data: Vec<_> = data[6..data.len() - 1].to_vec();
        let _checksum2 = data[data.len() - 1];

        // TODO: validate sequence, checksums, etc.

        let response = if let Some(resp) = Response::new(
            crate::connection::Message::new_raw(netfn, cmd, response_data),
            0,
        ) {
            resp
        } else {
            // TODO: need better message here :)
            return Err(RmcpIpmiReceiveError::EmptyMessage);
        };

        Ok(response)
    }

    pub fn send_recv(
        &mut self,
        request: &mut crate::connection::Request,
    ) -> Result<crate::connection::Response, RmcpIpmiError> {
        self.send(request)?;
        self.recv().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
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
