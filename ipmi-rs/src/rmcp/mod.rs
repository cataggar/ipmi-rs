use crate::{
    connection::{IpmiConnection, NotEnoughData},
    IpmiError,
};
use std::{net::ToSocketAddrs, time::Duration};

mod socket;
pub use socket::CancellationToken;

mod v1_5;
pub use v1_5::{
    ActivationError as V1_5ActivationError, ReadError as V1_5ReadError,
    WriteError as V1_5WriteError,
};

mod v2_0;
pub use v2_0::{
    ActivationError as V2_0ActivationError, ReadError as V2_0ReadError,
    WriteError as V2_0WriteError, *,
};

pub use ipmi_rs_core::app::auth::{
    AuthenticationAlgorithm, CipherSuite, ConfidentialityAlgorithm, IntegrityAlgorithm,
    PrivilegeLevel,
};

mod cipher_policy;
pub use cipher_policy::CipherSuiteListError;

mod sol;
pub use sol::{
    BufferedSolOutput, CaptureGap, SolCapture, SolError, SolInteractive, SolInterruption,
    SolInterruptionReason,
};
mod checksum;

mod header;
pub(crate) use header::*;

mod asf;
pub(crate) use asf::*;

mod internal;
use internal::{Active, RmcpWithState, Unbound};

fn is_password_ipmb(payload: &[u8]) -> bool {
    payload.len() >= 6 && matches!(payload[1] >> 2, 0x06 | 0x07) && payload[5] == 0x47
}

#[cfg(test)]
mod password_debug_tests {
    use super::*;

    #[test]
    fn rmcp_packet_debug_redacts_password_ipmb_payloads() {
        for netfn in [0x06, 0x07] {
            let mut ipmb = vec![0x20, netfn << 2, 0, 0x81, 0, 0x47, 2, 2];
            ipmb.extend_from_slice(b"visible-only-on-wire");
            let rmcp = v2_0::Message {
                ty: v2_0::PayloadType::IpmiMessage,
                session_id: 3,
                session_sequence_number: 4,
                payload: ipmb.clone(),
            };
            assert!(!format!("{rmcp:?}").contains("118, 105, 115"));
            assert!(format!("{rmcp:?}").contains("REDACTED"));
            let legacy = v1_5::Message {
                auth_type: crate::app::auth::AuthType::None,
                session_id: 3,
                session_sequence_number: 4,
                payload: ipmb,
            };
            assert!(format!("{legacy:?}").contains("REDACTED"));
        }
    }
}

#[derive(Debug)]
pub enum RmcpIpmiReceiveError {
    Io(std::io::Error),
    RmcpHeader(RmcpHeaderError),
    Session(UnwrapSessionError),
    NotIpmi,
    NotEnoughData,
    EmptyMessage,
    IpmbChecksumFailed,
    IpmbResponseMismatch,
    BridgeCompletion { hop: u8, code: u8 },
    BridgeQueueCompletion { command: u8, code: u8 },
    BridgePollSend(RmcpIpmiSendError),
    NoPendingRequest,
    SessionIdMismatch,
    InvalidSessionSequence,
    UnexpectedPayloadType,
    Sol(v2_0::SolFrameError),
    SolAckFailed,
    DatagramTooLarge,
    TooManyUnrelatedPackets,
    Timeout,
    Cancelled,
}

#[derive(Debug)]
pub enum RmcpIpmiSendError {
    V1_5(V1_5WriteError),
    V2_0(V2_0WriteError),
    RequestPending,
    UnsupportedTarget,
    InvalidBridgeTarget,
    BridgePayloadTooLarge(usize),
    InvalidNetfn(u8),
    IpmbSequenceExhausted,
    IpmbSequenceReserved,
    SessionSequenceExhausted,
    SolFrame,
    Cancelled,
    DeadlineExpired,
}

impl From<V1_5WriteError> for RmcpIpmiSendError {
    fn from(value: V1_5WriteError) -> Self {
        Self::V1_5(value)
    }
}

impl From<V2_0WriteError> for RmcpIpmiSendError {
    fn from(value: V2_0WriteError) -> Self {
        Self::V2_0(value)
    }
}

impl RmcpIpmiSendError {
    fn into_operation_error(self) -> RmcpIpmiError {
        match self {
            Self::V1_5(V1_5WriteError::Io(_)) | Self::V2_0(V2_0WriteError::Io(_)) => {
                RmcpIpmiError::SendOutcomeUnknown(self)
            }
            _ => RmcpIpmiError::Send(self),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UnwrapSessionError {
    V1_5(V1_5ReadError),
    V2_0(V2_0ReadError),
}

impl From<V1_5ReadError> for UnwrapSessionError {
    fn from(value: V1_5ReadError) -> Self {
        Self::V1_5(value)
    }
}

impl From<V2_0ReadError> for UnwrapSessionError {
    fn from(value: V2_0ReadError) -> Self {
        Self::V2_0(value)
    }
}

#[derive(Debug)]
pub enum RmcpIpmiError {
    NotActive,
    Receive(RmcpIpmiReceiveError),
    Send(RmcpIpmiSendError),
    /// The send may have reached the BMC; do not automatically retry a mutation.
    SendOutcomeUnknown(RmcpIpmiSendError),
    /// A request may have executed; it must not be automatically retried.
    OutcomeUnknown(RmcpIpmiReceiveError),
}

impl From<RmcpIpmiReceiveError> for RmcpIpmiError {
    fn from(value: RmcpIpmiReceiveError) -> Self {
        Self::Receive(value)
    }
}

impl From<RmcpIpmiSendError> for RmcpIpmiError {
    fn from(value: RmcpIpmiSendError) -> Self {
        Self::Send(value)
    }
}

type CommandError<T> = IpmiError<RmcpIpmiError, T>;

#[derive(Debug)]
pub enum ActivationError {
    BindSocket(std::io::Error),
    PingSend(std::io::Error),
    PongReceive(RmcpIpmiReceiveError),
    PongRead,
    /// The contacted host does not support IPMI over RMCP.
    IpmiNotSupported,
    NoSupportedIpmiLANVersions,
    /// A required suite cannot be used because the peer does not support RMCP+.
    RequiredRmcpPlusNotSupported,
    /// Only RMCP+ cipher suites 3 and 17 are implemented.
    UnsupportedCipherSuite(CipherSuite),
    /// Discovery failed; best-available selection never guesses a suite.
    GetChannelCipherSuites(CommandError<crate::app::auth::TooMuchData>),
    /// The advertised cipher-suite records are invalid or incomplete.
    InvalidCipherSuiteList(CipherSuiteListError),
    /// Neither supported secure suite was advertised by the channel.
    NoSupportedCipherSuite,
    RmcpPlusRequired,
    InvalidUsername,
    /// The requested backend cannot be used (e.g. SymCrypt was not compiled in).
    CryptoBackend(CryptoBackendError),
    GetChannelAuthenticationCapabilities(CommandError<NotEnoughData>),
    V1_5(V1_5ActivationError),
    V2_0(V2_0ActivationError),
    RmcpError(RmcpHeaderError),
}

impl From<V1_5ActivationError> for ActivationError {
    fn from(value: V1_5ActivationError) -> Self {
        Self::V1_5(value)
    }
}

impl From<V2_0ActivationError> for ActivationError {
    fn from(value: V2_0ActivationError) -> Self {
        Self::V2_0(value)
    }
}

/// RMCP+ cipher selection. Neither policy accepts an algorithm substitution.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CipherSuitePolicy {
    /// Require exactly this suite (only 3 and 17 are implemented).
    Exact(CipherSuite),
    /// Query the channel and prefer 17, then 3. Never assume support on a failed query.
    BestAvailable,
}

/// Borrowed credentials and negotiation requirements for an RMCP+ session.
///
/// This API always requires RMCP+; the legacy [`Rmcp::activate`] API retains
/// its existing IPMI 1.5 fallback and suite-3 behavior.
pub struct SessionConfig<'a> {
    username: Option<&'a str>,
    password: Option<&'a [u8]>,
    kg: Option<&'a [u8]>,
    privilege: PrivilegeLevel,
    cipher_suite: CipherSuitePolicy,
    provider: CryptoProvider,
}

impl core::fmt::Debug for SessionConfig<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionConfig")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("kg", &"<redacted>")
            .field("privilege", &self.privilege)
            .field("cipher_suite", &self.cipher_suite)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<'a> SessionConfig<'a> {
    /// Create an RMCP+ configuration requiring administrator and suite 3.
    pub fn new(username: Option<&'a str>, password: Option<&'a [u8]>) -> Self {
        Self {
            username,
            password,
            kg: None,
            privilege: PrivilegeLevel::Administrator,
            cipher_suite: CipherSuitePolicy::Exact(CipherSuite::Id3),
            provider: CryptoProvider::RustCrypto,
        }
    }

    /// Request an exact session privilege (including User or Operator).
    pub fn with_privilege(mut self, privilege: PrivilegeLevel) -> Self {
        self.privilege = privilege;
        self
    }

    /// Supply a distinct IPMI 2.0 Kg key. By default the password is used as Kg.
    pub fn with_kg(mut self, kg: &'a [u8]) -> Self {
        self.kg = Some(kg);
        self
    }

    /// Choose an exact suite or opt into discovery of the best supported suite.
    pub fn with_cipher_suite_policy(mut self, policy: CipherSuitePolicy) -> Self {
        self.cipher_suite = policy;
        self
    }

    /// Select the RMCP+ cryptographic implementation.
    pub fn with_provider(mut self, provider: CryptoProvider) -> Self {
        self.provider = provider;
        self
    }
}

#[derive(Debug)]
pub struct Rmcp {
    unbound_state: RmcpWithState<Unbound>,
    active_state: Option<RmcpWithState<Active>>,
}

impl Rmcp {
    pub fn new<R>(remote: R, timeout: Duration) -> Result<Self, std::io::Error>
    where
        R: ToSocketAddrs + std::fmt::Debug,
    {
        let unbound_state = RmcpWithState::new(remote, timeout)?;

        Ok(Self {
            unbound_state,
            active_state: None,
        })
    }

    pub fn inactive_clone(&self) -> Self {
        Self {
            unbound_state: self.unbound_state.clone(),
            active_state: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.active_state.is_some()
    }

    /// Whether the active session uses RMCP+ (IPMI 2.0), rather than IPMI 1.5.
    ///
    /// Returns `false` before activation. Requesting RMCP+ with
    /// [`Self::activate`] does not guarantee it was negotiated.
    pub fn is_rmcp_plus(&self) -> bool {
        self.active_state
            .as_ref()
            .is_some_and(RmcpWithState::is_rmcp_plus)
    }

    /// A cloneable cancellation signal checked at most every 50 ms during receives.
    pub fn cancellation_token(&self) -> CancellationToken {
        self.unbound_state.policy().cancellation.clone()
    }

    /// Refuse IPMI 1.5 fallback when RMCP+ was requested.
    pub fn require_rmcp_plus(&mut self, require: bool) {
        self.unbound_state.policy_mut().require_rmcp_plus = require;
    }

    /// Activate this RMCP connection with the provided username and password.
    ///
    /// If `rmcp_plus` is `true`, upgrade the connection to an RMCP+ connection
    /// using cipher suite 3 if the remote host supports RMCP+. Otherwise,
    /// IPMI 1.5 can be used. Use [`Self::activate_with_cipher_suite`] to
    /// require an exact RMCP+ cipher suite without fallback.
    pub fn activate(
        &mut self,
        rmcp_plus: bool,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<(), ActivationError> {
        self.activate_with_selection(rmcp_plus, None, SessionConfig::new(username, password))
    }

    /// Activate RMCP+ using exactly `suite`, without falling back to another
    /// cipher suite or IPMI 1.5. Currently only suites 3 and 17 are supported.
    pub fn activate_with_cipher_suite(
        &mut self,
        suite: CipherSuite,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<(), ActivationError> {
        self.activate_with_provider(suite, CryptoProvider::RustCrypto, username, password)
    }

    /// Require exactly `suite` (3 or 17) and the selected RMCP+ crypto provider.
    ///
    /// This method never falls back to another provider, cipher suite or IPMI 1.5.
    /// `SymCrypt` requires the `symcrypt-backend` feature and a compatible native
    /// SymCrypt library available to the dynamic loader.
    pub fn activate_with_provider(
        &mut self,
        suite: CipherSuite,
        provider: CryptoProvider,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<(), ActivationError> {
        self.activate_with_selection(
            true,
            Some(CipherSuitePolicy::Exact(suite)),
            SessionConfig::new(username, password).with_provider(provider),
        )
    }

    /// Activate RMCP+ with explicit privilege, optional Kg and cipher policy.
    ///
    /// A best-available query must succeed and advertise suite 17 or 3;
    /// neither query failures nor handshake failures cause a downgrade.
    pub fn activate_with_session_config(
        &mut self,
        config: SessionConfig<'_>,
    ) -> Result<(), ActivationError> {
        self.activate_with_selection(true, Some(config.cipher_suite), config)
    }

    fn activate_with_selection(
        &mut self,
        rmcp_plus: bool,
        suite_policy: Option<CipherSuitePolicy>,
        config: SessionConfig<'_>,
    ) -> Result<(), ActivationError> {
        if let Some(CipherSuitePolicy::Exact(suite)) = suite_policy {
            if !matches!(suite, CipherSuite::Id3 | CipherSuite::Id17) {
                return Err(ActivationError::UnsupportedCipherSuite(suite));
            }
        }

        config
            .provider
            .ensure_available()
            .map_err(ActivationError::CryptoBackend)?;

        if self.active_state.take().is_some() {
            // TODO: shut down currently active state.
            log::info!("De-activating RMCP connection for re-activation");
        }

        let inactive = self
            .unbound_state
            .bind()
            .map_err(ActivationError::BindSocket)?;

        let activated = inactive.activate(rmcp_plus, suite_policy, config)?;
        self.active_state = Some(activated);
        Ok(())
    }
}

impl IpmiConnection for Rmcp {
    type SendError = RmcpIpmiError;

    type RecvError = RmcpIpmiError;

    type Error = RmcpIpmiError;

    fn send(&mut self, request: &mut crate::connection::Request) -> Result<(), Self::SendError> {
        let active = self.active_state.as_mut().ok_or(RmcpIpmiError::NotActive)?;
        active.send(request)
    }

    fn recv(&mut self) -> Result<crate::connection::Response, Self::RecvError> {
        let active = self.active_state.as_mut().ok_or(RmcpIpmiError::NotActive)?;
        active.recv().map_err(|error| match error {
            RmcpIpmiReceiveError::NoPendingRequest => RmcpIpmiError::Receive(error),
            _ => RmcpIpmiError::OutcomeUnknown(error),
        })
    }

    fn send_recv(
        &mut self,
        request: &mut crate::connection::Request,
    ) -> Result<crate::connection::Response, Self::Error> {
        let active = self.active_state.as_mut().ok_or(RmcpIpmiError::NotActive)?;
        active.send_recv(request)
    }

    fn send_recv_deadline(
        &mut self,
        request: &mut crate::connection::Request,
        deadline: std::time::Instant,
        cancellation: &CancellationToken,
    ) -> Result<crate::connection::Response, Self::Error> {
        if cancellation.is_cancelled() {
            return Err(RmcpIpmiError::Send(RmcpIpmiSendError::Cancelled));
        }
        if std::time::Instant::now() >= deadline {
            return Err(RmcpIpmiError::Send(RmcpIpmiSendError::DeadlineExpired));
        }
        let active = self.active_state.as_mut().ok_or(RmcpIpmiError::NotActive)?;
        let previous = active
            .state_mut()
            .socket_mut()
            .begin_bounded(deadline, cancellation.clone());
        let result = active.send_recv(request);
        active.state_mut().socket_mut().end_bounded(previous);
        result
    }

    fn ipmb_sequence_budget(&self) -> Option<usize> {
        Some(
            self.active_state
                .as_ref()
                .map_or(0, RmcpWithState::ipmb_sequence_budget),
        )
    }

    fn reserve_ipmb_sequences(&mut self, minimum: usize) -> bool {
        self.active_state
            .as_mut()
            .is_some_and(|active| active.reserve_ipmb_sequences(minimum))
    }

    fn release_ipmb_sequences(&mut self) {
        if let Some(active) = &mut self.active_state {
            active.release_ipmb_sequences();
        }
    }
}

#[cfg(test)]
mod session_policy_tests;
#[cfg(test)]
mod suite17_tests;

#[cfg(test)]
mod suite17_activation_tests {
    use super::*;
    use std::{net::UdpSocket, thread};

    fn providers() -> &'static [CryptoProvider] {
        #[cfg(feature = "symcrypt-backend")]
        {
            &[CryptoProvider::RustCrypto, CryptoProvider::SymCrypt]
        }
        #[cfg(not(feature = "symcrypt-backend"))]
        {
            &[CryptoProvider::RustCrypto]
        }
    }

    #[derive(Clone, Copy)]
    enum OpenReply {
        NoRmcpPlus,
        RejectSuite,
        SubstituteAlgorithm(usize),
    }

    fn mock_bmc(reply: OpenReply, suite: CipherSuite) -> (String, thread::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let address = socket.local_addr().unwrap().to_string();
        let handle = thread::spawn(move || {
            let mut data = [0u8; 1024];
            let (_, peer) = socket.recv_from(&mut data).unwrap();
            let pong = RmcpHeader::new_asf(0xff).write_infallible(|buffer| {
                ASFMessage {
                    message_tag: 0xc8,
                    message_type: ASFMessageType::Pong {
                        enterprise_number: 4542,
                        oem_data: 0,
                        supported_entities: SupportedEntities { ipmi: true },
                        supported_interactions: SupportedInteractions {
                            rcmp_security: false,
                            dmtf_dash: false,
                        },
                    },
                }
                .write_data(buffer);
            });
            socket.send_to(&pong, peer).unwrap();

            let (_, peer) = socket.recv_from(&mut data).unwrap();
            let mut ipmb = vec![
                0x81, 0x1c, 0, 0x20, 0, 0x38, 0, 0x0e, 0x81, 0, 0x01, 0, 0, 0, 0, 0,
            ];
            if !matches!(reply, OpenReply::NoRmcpPlus) {
                ipmb[10] = 0x03;
            }
            ipmb[2] = checksum::Checksum::from_iter(ipmb[..2].iter().copied());
            let last_checksum = checksum::Checksum::from_iter(ipmb[3..].iter().copied());
            ipmb.push(last_checksum);
            let caps = v1_5::Message {
                auth_type: crate::app::auth::AuthType::None,
                session_sequence_number: 0,
                session_id: 0,
                payload: ipmb,
            };
            let wire = RmcpHeader::new_ipmi()
                .write(|buffer| caps.write_data(None, buffer))
                .unwrap();
            socket.send_to(&wire, peer).unwrap();

            if !matches!(reply, OpenReply::NoRmcpPlus) {
                let (len, peer) = socket.recv_from(&mut data).unwrap();
                assert_eq!(data[5], 0x10);
                assert_eq!(len, 48);
                let [authentication, integrity, confidentiality] = suite.into_suite();
                assert_eq!(data[28], authentication);
                assert_eq!(data[36], integrity);
                assert_eq!(data[44], confidentiality);

                let response = match reply {
                    OpenReply::RejectSuite => vec![0, 0x11],
                    OpenReply::SubstituteAlgorithm(which) => {
                        let mut response = vec![0, 0, 4, 0];
                        response.extend_from_slice(&data[20..24]);
                        response.extend_from_slice(&0x55667788u32.to_le_bytes());
                        response.extend_from_slice(&data[24..48]);
                        response[16 + 8 * which] = 0;
                        response
                    }
                    OpenReply::NoRmcpPlus => unreachable!(),
                };
                let mut wire = vec![6, 0, 0xff, 7, 6, 0x11];
                wire.extend_from_slice(&[0; 8]);
                wire.extend_from_slice(&(response.len() as u16).to_le_bytes());
                wire.extend_from_slice(&response);
                socket.send_to(&wire, peer).unwrap();
            }

            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            assert!(
                socket.recv_from(&mut data).is_err(),
                "sent RAKP1 or fell back"
            );
        });
        (address, handle)
    }

    #[test]
    fn unimplemented_cipher_suite_is_rejected_before_any_network_io() {
        let mut rmcp = Rmcp::new("127.0.0.1:1", Duration::from_millis(100)).unwrap();
        assert!(matches!(
            rmcp.activate_with_cipher_suite(CipherSuite::Id16, None, None),
            Err(ActivationError::UnsupportedCipherSuite(CipherSuite::Id16))
        ));
        assert!(!rmcp.is_active());
    }

    #[cfg(not(feature = "symcrypt-backend"))]
    #[test]
    fn unavailable_symcrypt_is_rejected_before_any_network_io() {
        let mut rmcp = Rmcp::new("127.0.0.1:1", Duration::from_millis(100)).unwrap();
        assert!(matches!(
            rmcp.activate_with_provider(CipherSuite::Id17, CryptoProvider::SymCrypt, None, None),
            Err(ActivationError::CryptoBackend(
                CryptoBackendError::Unavailable
            ))
        ));
        assert!(!rmcp.is_active());
    }

    #[test]
    fn required_suite_does_not_fall_back_to_ipmi_1_5() {
        for &provider in providers() {
            for suite in [CipherSuite::Id3, CipherSuite::Id17] {
                let (address, bmc) = mock_bmc(OpenReply::NoRmcpPlus, suite);
                let mut rmcp = Rmcp::new(address, Duration::from_secs(2)).unwrap();
                let activation = rmcp.activate_with_provider(suite, provider, None, None);
                bmc.join().unwrap();
                assert!(matches!(
                    activation,
                    Err(ActivationError::RequiredRmcpPlusNotSupported)
                ));
                assert!(!rmcp.is_active());
            }
        }
    }

    #[test]
    fn best_available_does_not_fall_back_to_ipmi_1_5() {
        let (address, bmc) = mock_bmc(OpenReply::NoRmcpPlus, CipherSuite::Id3);
        let mut rmcp = Rmcp::new(address, Duration::from_secs(2)).unwrap();
        let activation = rmcp.activate_with_session_config(
            SessionConfig::new(None, None)
                .with_cipher_suite_policy(CipherSuitePolicy::BestAvailable),
        );
        bmc.join().unwrap();
        assert!(matches!(
            activation,
            Err(ActivationError::RequiredRmcpPlusNotSupported)
        ));
        assert!(!rmcp.is_active());
    }

    #[test]
    fn peer_rejection_and_substitutions_stop_before_rakp1() {
        for &provider in providers() {
            for suite in [CipherSuite::Id3, CipherSuite::Id17] {
                for reply in [
                    OpenReply::RejectSuite,
                    OpenReply::SubstituteAlgorithm(0),
                    OpenReply::SubstituteAlgorithm(1),
                    OpenReply::SubstituteAlgorithm(2),
                ] {
                    let (address, bmc) = mock_bmc(reply, suite);
                    let mut rmcp = Rmcp::new(address, Duration::from_secs(2)).unwrap();
                    let activation = rmcp.activate_with_provider(suite, provider, None, None);
                    bmc.join().unwrap();
                    match reply {
                        OpenReply::RejectSuite => assert!(matches!(
                            activation,
                            Err(ActivationError::V2_0(
                                V2_0ActivationError::OpenSessionResponseParse(
                                    ParseSessionResponseError::HaveErrorCode(Ok(
                                        OpenSessionResponseErrorStatusCode::NoMatchingCipherSuite
                                    ))
                                )
                            ))
                        )),
                        OpenReply::SubstituteAlgorithm(which) => {
                            let error = match activation {
                                Err(ActivationError::V2_0(
                                    V2_0ActivationError::OpenSessionResponseValidate(error),
                                )) => error,
                                other => panic!("expected negotiation error, got {other:?}"),
                            };
                            assert!(matches!(
                                (suite, which, error),
                                (
                                    CipherSuite::Id17,
                                    _,
                                    ValidateSessionResponseError::NegotiatedCipherSuiteMismatch {
                                        requested: CipherSuite::Id17,
                                        ..
                                    }
                                ) | (
                                    CipherSuite::Id3,
                                    0,
                                    ValidateSessionResponseError::AuthenticationAlgorithmMismatch(
                                        _
                                    )
                                ) | (
                                    CipherSuite::Id3,
                                    1,
                                    ValidateSessionResponseError::IntegrityAlgorithmMismatch(_)
                                ) | (
                                    CipherSuite::Id3,
                                    2,
                                    ValidateSessionResponseError::ConfidentialityAlgorithmMismatch(
                                        _
                                    )
                                )
                            ));
                        }
                        OpenReply::NoRmcpPlus => unreachable!(),
                    }
                    assert!(!rmcp.is_active());
                }
            }
        }
    }

    #[test]
    fn inactive_connection_is_not_rmcp_plus() {
        let rmcp = Rmcp::new("127.0.0.1:623", Duration::from_secs(1)).unwrap();
        assert!(!rmcp.is_active());
        assert!(!rmcp.is_rmcp_plus());
    }
}
#[cfg(test)]
mod tests;
