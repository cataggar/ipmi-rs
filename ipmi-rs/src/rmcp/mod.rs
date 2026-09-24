use crate::{
    connection::{IpmiConnection, NotEnoughData},
    IpmiError,
};
use std::{net::ToSocketAddrs, time::Duration};

mod socket;

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
};

mod checksum;

mod header;
pub(crate) use header::*;

mod asf;
pub(crate) use asf::*;

mod internal;
use internal::{Active, RmcpWithState, Unbound};

#[derive(Debug)]
pub enum RmcpIpmiReceiveError {
    Io(std::io::Error),
    RmcpHeader(RmcpHeaderError),
    Session(UnwrapSessionError),
    NotIpmi,
    NotEnoughData,
    EmptyMessage,
    IpmbChecksumFailed,
}

#[derive(Debug)]
pub enum RmcpIpmiSendError {
    V1_5(V1_5WriteError),
    V2_0(V2_0WriteError),
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
    PongReceive(std::io::Error),
    PongRead,
    /// The contacted host does not support IPMI over RMCP.
    IpmiNotSupported,
    NoSupportedIpmiLANVersions,
    /// A required suite cannot be used because the peer does not support RMCP+.
    RequiredRmcpPlusNotSupported,
    /// Only RMCP+ cipher suites 3 and 17 are implemented.
    UnsupportedCipherSuite(CipherSuite),
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
        self.activate_with_selection(rmcp_plus, None, username, password)
    }

    /// Activate RMCP+ using exactly `suite`, without falling back to another
    /// cipher suite or IPMI 1.5. Currently only suites 3 and 17 are supported.
    pub fn activate_with_cipher_suite(
        &mut self,
        suite: CipherSuite,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<(), ActivationError> {
        self.activate_with_selection(true, Some(suite), username, password)
    }

    fn activate_with_selection(
        &mut self,
        rmcp_plus: bool,
        required_suite: Option<CipherSuite>,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<(), ActivationError> {
        if let Some(suite) = required_suite {
            if !matches!(suite, CipherSuite::Id3 | CipherSuite::Id17) {
                return Err(ActivationError::UnsupportedCipherSuite(suite));
            }
        }

        if self.active_state.take().is_some() {
            // TODO: shut down currently active state.
            log::info!("De-activating RMCP connection for re-activation");
        }

        let inactive = self
            .unbound_state
            .bind()
            .map_err(ActivationError::BindSocket)?;

        let activated = inactive.activate(rmcp_plus, required_suite, username, password)?;
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
        active.recv().map_err(RmcpIpmiError::Receive)
    }

    fn send_recv(
        &mut self,
        request: &mut crate::connection::Request,
    ) -> Result<crate::connection::Response, Self::Error> {
        let active = self.active_state.as_mut().ok_or(RmcpIpmiError::NotActive)?;
        active.send_recv(request)
    }
}

#[cfg(test)]
mod suite17_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::UdpSocket, thread};

    #[derive(Clone, Copy)]
    enum OpenReply {
        NoRmcpPlus,
        RejectSuite,
        SubstituteAlgorithm(usize),
    }

    fn mock_bmc(reply: OpenReply) -> (String, thread::JoinHandle<()>) {
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
                assert_eq!(data[28], 3);
                assert_eq!(data[36], 4);
                assert_eq!(data[44], 1);

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

    #[test]
    fn required_suite_does_not_fall_back_to_ipmi_1_5() {
        let (address, bmc) = mock_bmc(OpenReply::NoRmcpPlus);
        let mut rmcp = Rmcp::new(address, Duration::from_secs(2)).unwrap();
        let activation = rmcp.activate_with_cipher_suite(CipherSuite::Id17, None, None);
        bmc.join().unwrap();
        assert!(matches!(
            activation,
            Err(ActivationError::RequiredRmcpPlusNotSupported)
        ));
        assert!(!rmcp.is_active());
    }

    #[test]
    fn peer_rejection_and_substitutions_stop_before_rakp1() {
        for reply in [
            OpenReply::RejectSuite,
            OpenReply::SubstituteAlgorithm(0),
            OpenReply::SubstituteAlgorithm(1),
            OpenReply::SubstituteAlgorithm(2),
        ] {
            let (address, bmc) = mock_bmc(reply);
            let mut rmcp = Rmcp::new(address, Duration::from_secs(2)).unwrap();
            let activation = rmcp.activate_with_cipher_suite(CipherSuite::Id17, None, None);
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
                OpenReply::SubstituteAlgorithm(_) => assert!(matches!(
                    activation,
                    Err(ActivationError::V2_0(
                        V2_0ActivationError::OpenSessionResponseValidate(
                            ValidateSessionResponseError::NegotiatedCipherSuiteMismatch {
                                requested: CipherSuite::Id17,
                                ..
                            }
                        )
                    ))
                )),
                OpenReply::NoRmcpPlus => unreachable!(),
            }
            assert!(!rmcp.is_active());
        }
    }

    #[test]
    fn inactive_connection_is_not_rmcp_plus() {
        let rmcp = Rmcp::new("127.0.0.1:623", Duration::from_secs(1)).unwrap();
        assert!(!rmcp.is_active());
        assert!(!rmcp.is_rmcp_plus());
    }
}
