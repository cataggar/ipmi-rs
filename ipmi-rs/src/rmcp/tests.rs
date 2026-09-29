use super::*;
use crate::app::auth::AuthType;
#[cfg(any(feature = "rustcrypto-backend", feature = "symcrypt-backend"))]
use std::time::Instant;
use std::{net::UdpSocket, thread};

#[cfg(any(feature = "rustcrypto-backend", feature = "symcrypt-backend"))]
#[test]
fn activation_deadline_and_cancellation_are_bounded() {
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut client = Rmcp::new(peer.local_addr().unwrap(), Duration::from_millis(90)).unwrap();
    let start = Instant::now();
    assert!(matches!(
        client.activate(true, Some("root"), Some(b"password")),
        Err(ActivationError::PongReceive(RmcpIpmiReceiveError::Timeout))
    ));
    assert!(start.elapsed() < Duration::from_secs(1));

    let mut client = Rmcp::new(peer.local_addr().unwrap(), Duration::from_secs(1)).unwrap();
    let token = client.cancellation_token();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        token.cancel();
    });
    let start = Instant::now();
    assert!(matches!(
        client.activate(true, Some("root"), Some(b"password")),
        Err(ActivationError::PongReceive(
            RmcpIpmiReceiveError::Cancelled
        ))
    ));
    assert!(start.elapsed() < Duration::from_millis(500));
}

#[cfg(any(feature = "rustcrypto-backend", feature = "symcrypt-backend"))]
#[test]
fn operational_activation_refuses_ipmi15_fallback() {
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let address = peer.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut input = [0; 4096];
        let (_, from) = peer.recv_from(&mut input).unwrap();
        let pong = ASFMessage {
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
        };
        let wire = RmcpHeader::new_asf(0xff).write_infallible(|b| pong.write_data(b));
        peer.send_to(&wire, from).unwrap();
        let (len, from) = peer.recv_from(&mut input).unwrap();
        let request = v1_5::Message::from_data(None, &input[4..len]).unwrap();
        let sequence = request.payload[4];
        let mut payload = vec![
            0x81, 0x1c, 0, 0x20, sequence, 0x38, 0, 0x0e, 0x81, 0, 1, 0, 0, 0, 0,
        ];
        payload[2] = checksum::Checksum::from_iter(payload[..2].iter().copied());
        payload.push(checksum::Checksum::from_iter(payload[3..].iter().copied()));
        let response = v1_5::Message {
            auth_type: AuthType::None,
            session_sequence_number: 0,
            session_id: 0,
            payload,
        };
        let wire = RmcpHeader::new_ipmi()
            .write(|b| response.write_data(None, b))
            .unwrap();
        peer.send_to(&wire, from).unwrap();
    });
    let mut client = Rmcp::new(address, Duration::from_secs(1)).unwrap();
    client.require_rmcp_plus(true);
    assert!(matches!(
        client.activate(true, Some("root"), Some(b"password")),
        Err(ActivationError::RmcpPlusRequired)
    ));
    server.join().unwrap();
}

#[test]
fn ambiguous_network_send_is_never_reported_as_safe_to_retry() {
    let io = || std::io::Error::new(std::io::ErrorKind::TimedOut, "send timed out");
    assert!(matches!(
        RmcpIpmiSendError::V1_5(V1_5WriteError::Io(io())).into_operation_error(),
        RmcpIpmiError::SendOutcomeUnknown(_)
    ));
    assert!(matches!(
        RmcpIpmiSendError::V2_0(V2_0WriteError::Io(io())).into_operation_error(),
        RmcpIpmiError::SendOutcomeUnknown(_)
    ));
    assert!(matches!(
        RmcpIpmiSendError::InvalidBridgeTarget.into_operation_error(),
        RmcpIpmiError::Send(RmcpIpmiSendError::InvalidBridgeTarget)
    ));
}

#[test]
fn implicit_provider_tracks_enabled_backends() {
    let expected = if cfg!(all(
        feature = "symcrypt-backend",
        not(feature = "rustcrypto-backend")
    )) {
        CryptoProvider::SymCrypt
    } else {
        CryptoProvider::RustCrypto
    };
    assert_eq!(CryptoProvider::default(), expected);
    assert_eq!(SessionConfig::new(None, None).provider, expected);
    assert_eq!(
        expected.ensure_available(),
        if cfg!(any(
            feature = "rustcrypto-backend",
            feature = "symcrypt-backend"
        )) {
            Ok(())
        } else {
            Err(CryptoBackendError::Unavailable)
        }
    );
}

#[test]
fn unavailable_backend_is_rejected_before_network_io() {
    for provider in [CryptoProvider::RustCrypto, CryptoProvider::SymCrypt] {
        if provider.ensure_available().is_ok() {
            continue;
        }
        let mut rmcp = Rmcp::new("127.0.0.1:1", Duration::from_millis(50)).unwrap();
        assert!(matches!(
            rmcp.activate_with_provider(CipherSuite::Id17, provider, None, None),
            Err(ActivationError::CryptoBackend(
                CryptoBackendError::Unavailable
            ))
        ));
        assert!(matches!(
            rmcp.activate_with_session_config(
                SessionConfig::new(None, None).with_provider(provider)
            ),
            Err(ActivationError::CryptoBackend(
                CryptoBackendError::Unavailable
            ))
        ));
        assert!(!rmcp.is_active());
    }
}

#[cfg(not(any(feature = "rustcrypto-backend", feature = "symcrypt-backend")))]
#[test]
fn no_backend_rejects_implicit_rmcp_plus_before_network_io() {
    let mut rmcp = Rmcp::new("127.0.0.1:1", Duration::from_millis(50)).unwrap();
    assert!(matches!(
        rmcp.activate(true, None, None),
        Err(ActivationError::CryptoBackend(
            CryptoBackendError::Unavailable
        ))
    ));
    assert!(matches!(
        rmcp.activate_with_cipher_suite(CipherSuite::Id3, None, None),
        Err(ActivationError::CryptoBackend(
            CryptoBackendError::Unavailable
        ))
    ));
    assert!(matches!(
        rmcp.activate_with_session_config(SessionConfig::new(None, None)),
        Err(ActivationError::CryptoBackend(
            CryptoBackendError::Unavailable
        ))
    ));
    assert!(!rmcp.is_active());
}

#[cfg(not(any(feature = "rustcrypto-backend", feature = "symcrypt-backend")))]
#[test]
fn no_backend_can_activate_ipmi15_without_crypto() {
    let peer = UdpSocket::bind("[::1]:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let address = peer.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut input = [0; 1024];
        let (_, from) = peer.recv_from(&mut input).unwrap();
        let pong = ASFMessage {
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
        };
        let wire = RmcpHeader::new_asf(0xff).write_infallible(|b| pong.write_data(b));
        peer.send_to(&wire, from).unwrap();

        let challenge = [&[0x34, 0x12, 0, 0][..], &[0x42; 16]].concat();
        for (command, body) in [
            (0x38, &[0x0e, 0x81, 0, 1, 0, 0, 0, 0][..]),
            (0x39, challenge.as_slice()),
            (0x3a, &[0, 0x34, 0x12, 0, 0, 1, 0, 0, 0, 4][..]),
        ] {
            let (len, from) = peer.recv_from(&mut input).unwrap();
            let request = v1_5::Message::from_data(None, &input[4..len]).unwrap();
            assert_eq!(request.payload[5], command);
            let mut payload = vec![0x81, 0x1c, 0, 0x20, request.payload[4], command, 0];
            payload[2] = checksum::Checksum::from_iter(payload[..2].iter().copied());
            payload.extend_from_slice(&body);
            payload.push(checksum::Checksum::from_iter(payload[3..].iter().copied()));
            let response = v1_5::Message {
                auth_type: AuthType::None,
                session_sequence_number: 0,
                session_id: if command == 0x3a { 0x1234 } else { 0 },
                payload,
            };
            let wire = RmcpHeader::new_ipmi()
                .write(|buffer| response.write_data(None, buffer))
                .unwrap();
            peer.send_to(&wire, from).unwrap();
        }
    });
    let mut rmcp = Rmcp::new(address, Duration::from_secs(1)).unwrap();
    rmcp.activate(false, None, None).unwrap();
    assert!(rmcp.is_active());
    assert!(!rmcp.is_rmcp_plus());
    server.join().unwrap();
    assert!(matches!(
        rmcp.activate_with_provider(CipherSuite::Id17, CryptoProvider::RustCrypto, None, None),
        Err(ActivationError::CryptoBackend(
            CryptoBackendError::Unavailable
        ))
    ));
    assert!(rmcp.is_active());
    assert!(!rmcp.is_rmcp_plus());
}
