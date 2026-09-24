use super::*;
use crate::{
    connection::{LogicalUnit, Message as IpmiMessage, NetFn, Request, RequestTargetAddress},
    rmcp::{checksum::Checksum, socket::TransportPolicy, RmcpHeader, RmcpIpmiSendError},
};
use crypto::sha1::Sha1Hmac;
use std::{net::UdpSocket, time::Duration};

fn pair(timeout: Duration) -> (State, UdpSocket, CryptoState) {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.connect(peer.local_addr().unwrap()).unwrap();
    peer.connect(client.local_addr().unwrap()).unwrap();

    let console_id = NonZeroU32::new(0x12345678).unwrap();
    let managed_id = NonZeroU32::new(0x87654321).unwrap();
    let username = Username::new("root").unwrap();
    let console_random = [0x55; 16];
    let managed_random = [0x66; 16];
    let guid = [0x77; 16];
    let rm1 = RakpMessage1 {
        message_tag: 13,
        managed_system_session_id: managed_id,
        remote_console_random_number: console_random,
        requested_maximum_privilege_level: PrivilegeLevel::Administrator,
        username: &username,
    };
    let password = b"local test password";
    let auth = Sha1Hmac::new(password)
        .feed(&console_id.get().to_le_bytes())
        .feed(&managed_id.get().to_le_bytes())
        .feed(&console_random)
        .feed(&managed_random)
        .feed(&guid)
        .feed(&[4, username.len()])
        .feed(&username)
        .finalize();
    let rm2 = RakpMessage2 {
        message_tag: 13,
        remote_console_session_id: console_id,
        managed_system_random_number: managed_random,
        managed_system_guid: guid,
        key_exchange_auth_code: &auth,
    };
    let negotiated = OpenSessionResponse {
        message_tag: 0,
        maximum_privilege_level: PrivilegeLevel::Administrator,
        remote_console_session_id: console_id,
        managed_system_session_id: managed_id,
        authentication_payload: AuthenticationAlgorithm::RakpHmacSha1,
        integrity_payload: IntegrityAlgorithm::HmacSha1_96,
        confidentiality_payload: ConfidentialityAlgorithm::AesCbc128,
    };
    let mut state_crypto = CryptoState::new(None, password);
    assert!(state_crypto
        .calculate_rakp3_data(&negotiated, &rm1, &rm2)
        .unwrap()
        .is_some());
    let mut peer_crypto = CryptoState::new(None, password);
    assert!(peer_crypto
        .calculate_rakp3_data(&negotiated, &rm1, &rm2)
        .unwrap()
        .is_some());
    (
        State {
            socket: RmcpIpmiSocket::new(client, TransportPolicy::new(timeout), None),
            session_id: managed_id,
            console_session_id: console_id,
            session_sequence_number: NonZeroU32::MIN,
            last_inbound_sequence: None,
            state: state_crypto,
            ipmb_state: IpmbState::default(),
        },
        peer,
        peer_crypto,
    )
}

fn request() -> Request {
    Request::new(
        IpmiMessage::new_request(NetFn::Chassis, 2, vec![1]),
        RequestTargetAddress::Bmc(LogicalUnit::Zero),
    )
}

fn response(sequence: u8) -> Vec<u8> {
    let mut data = vec![0x81, 0x04, 0, 0x20, sequence << 2, 2, 0];
    data[2] = Checksum::from_iter(data[..2].iter().copied());
    data.push(Checksum::from_iter(data[3..].iter().copied()));
    data
}

fn send_answer(peer: &UdpSocket, crypto: &mut CryptoState, message: Message) {
    let wire = RmcpHeader::new_ipmi()
        .write(|buffer| crypto.write_message(&message, buffer))
        .unwrap();
    peer.send(&wire).unwrap();
}

#[test]
fn valid_sha1_aes_udp_and_replay_policy() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(250));
    let mut req = request();
    state.send(&mut req).unwrap();
    let mut received = [0; 4096];
    let len = peer.recv(&mut received).unwrap();
    assert_eq!(received[5], 0xc0); // Authenticated AES IPMI payload
    assert_eq!(&received[6..10], &state.session_id.get().to_le_bytes());
    let outbound = crypto.read_payload(&mut received[4..len]).unwrap();
    assert_eq!(outbound.payload[4] >> 2, 0);
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::IpmiMessage,
            session_id: state.console_session_id.get(),
            session_sequence_number: 5,
            payload: response(0),
        },
    );
    assert_eq!(state.recv().unwrap().seq(), 0);

    for sequence in [5, 4, 6] {
        state.send(&mut req).unwrap();
        peer.recv(&mut received).unwrap();
        send_answer(
            &peer,
            &mut crypto,
            Message {
                ty: PayloadType::IpmiMessage,
                session_id: state.console_session_id.get(),
                session_sequence_number: sequence,
                payload: response((state.ipmb_state.ipmb_sequence - 1) & 0x3f),
            },
        );
        if sequence <= 5 {
            assert!(matches!(
                state.recv(),
                Err(RmcpIpmiReceiveError::InvalidSessionSequence)
            ));
        } else {
            assert_eq!(state.recv().unwrap().seq(), 3);
        }
    }
}

#[test]
fn active_session_type_identity_pending_and_exhaustion() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(200));
    let mut req = request();
    let mut received = [0; 4096];
    state.send(&mut req).unwrap();
    assert!(matches!(
        state.send(&mut req),
        Err(RmcpIpmiError::Send(RmcpIpmiSendError::RequestPending))
    ));
    peer.recv(&mut received).unwrap();
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::Sol,
            session_id: state.console_session_id.get(),
            session_sequence_number: 1,
            payload: response(0),
        },
    );
    assert!(matches!(
        state.recv(),
        Err(RmcpIpmiReceiveError::UnexpectedPayloadType)
    ));

    state.send(&mut req).unwrap();
    peer.recv(&mut received).unwrap();
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::IpmiMessage,
            session_id: state.session_id.get(),
            session_sequence_number: 2,
            payload: response(1),
        },
    );
    assert!(matches!(
        state.recv(),
        Err(RmcpIpmiReceiveError::SessionIdMismatch)
    ));
    state.session_sequence_number = NonZeroU32::new(u32::MAX).unwrap();
    assert!(matches!(
        state.send(&mut req),
        Err(RmcpIpmiError::Send(
            RmcpIpmiSendError::SessionSequenceExhausted
        ))
    ));
}

#[test]
fn mutation_response_loss_has_unknown_outcome_and_no_retransmission() {
    let (mut state, peer, _) = pair(Duration::from_millis(70));
    peer.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut req = request();
    let start = std::time::Instant::now();
    assert!(matches!(
        state.send_recv(&mut req),
        Err(RmcpIpmiError::OutcomeUnknown(RmcpIpmiReceiveError::Timeout))
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    let mut data = [0; 4096];
    assert!(peer.recv(&mut data).is_ok());
    assert!(peer.recv(&mut data).is_err()); // No automatic second attempt.
    assert!(state.ipmb_state.pending.is_none());
}

#[test]
fn cancellation_retires_request_and_late_reply_cannot_satisfy_next() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(250));
    let token = state.socket.cancellation_token();
    let mut req = request();
    token.cancel();
    assert!(matches!(
        state.send(&mut req),
        Err(RmcpIpmiError::Send(RmcpIpmiSendError::Cancelled))
    ));
    token.reset();
    state.send(&mut req).unwrap();
    let mut packet = [0; 4096];
    peer.recv(&mut packet).unwrap();
    token.cancel();
    assert!(matches!(state.recv(), Err(RmcpIpmiReceiveError::Cancelled)));
    token.reset();
    state.send(&mut req).unwrap();
    peer.recv(&mut packet).unwrap();
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::IpmiMessage,
            session_id: state.console_session_id.get(),
            session_sequence_number: 1,
            payload: response(0),
        },
    );
    assert!(matches!(
        state.recv(),
        Err(RmcpIpmiReceiveError::IpmbResponseMismatch)
    ));
    state.ipmb_state.ipmb_sequence = 0;
    assert!(matches!(
        state.send(&mut req),
        Err(RmcpIpmiError::Send(
            RmcpIpmiSendError::IpmbSequenceExhausted
        ))
    ));
}

#[test]
fn negotiation_rejects_substituted_algorithms_and_handshake_headers() {
    let req = OpenSessionRequest {
        message_tag: 7,
        requested_max_privilege: Some(PrivilegeLevel::Administrator),
        remote_console_session_id: NonZeroU32::new(1).unwrap(),
        authentication_algorithms: AuthenticationAlgorithm::RakpHmacSha1,
        integrity_algorithms: IntegrityAlgorithm::HmacSha1_96,
        confidentiality_algorithms: ConfidentialityAlgorithm::AesCbc128,
    };
    let mut response = OpenSessionResponse {
        message_tag: 7,
        maximum_privilege_level: PrivilegeLevel::Administrator,
        remote_console_session_id: req.remote_console_session_id,
        managed_system_session_id: NonZeroU32::new(2).unwrap(),
        authentication_payload: req.authentication_algorithms,
        integrity_payload: req.integrity_algorithms,
        confidentiality_payload: req.confidentiality_algorithms,
    };
    response.message_tag ^= 1;
    assert!(matches!(
        State::validate_open_session(&req, &response),
        Err(ValidateSessionResponseError::MessageTagMismatch)
    ));
    response.message_tag = req.message_tag;
    response.remote_console_session_id = NonZeroU32::new(3).unwrap();
    assert!(matches!(
        State::validate_open_session(&req, &response),
        Err(ValidateSessionResponseError::RemoteConsoleSessionIdMismatch)
    ));
    response.remote_console_session_id = req.remote_console_session_id;
    response.maximum_privilege_level = PrivilegeLevel::Operator;
    assert!(matches!(
        State::validate_open_session(&req, &response),
        Err(ValidateSessionResponseError::PrivilegeLevelMismatch)
    ));
    response.maximum_privilege_level = PrivilegeLevel::Administrator;
    response.authentication_payload = AuthenticationAlgorithm::RakpNone;
    assert!(matches!(
        State::validate_open_session(&req, &response),
        Err(ValidateSessionResponseError::AuthenticationAlgorithmMismatch(_))
    ));
    response.authentication_payload = req.authentication_algorithms;
    response.integrity_payload = IntegrityAlgorithm::None;
    assert!(matches!(
        State::validate_open_session(&req, &response),
        Err(ValidateSessionResponseError::IntegrityAlgorithmMismatch(_))
    ));
    response.integrity_payload = req.integrity_algorithms;
    response.confidentiality_payload = ConfidentialityAlgorithm::None;
    assert!(matches!(
        State::validate_open_session(&req, &response),
        Err(ValidateSessionResponseError::ConfidentialityAlgorithmMismatch(_))
    ));
    let mut message = Message {
        ty: PayloadType::RakpMessage2,
        session_id: 0,
        session_sequence_number: 0,
        payload: vec![],
    };
    assert!(State::validate_handshake(&message, PayloadType::RakpMessage2).is_ok());
    assert!(matches!(
        State::validate_handshake(&message, PayloadType::RakpMessage4),
        Err(ActivationError::UnexpectedPayloadType(_))
    ));
    message.session_id = 1;
    assert!(matches!(
        State::validate_handshake(&message, PayloadType::RakpMessage2),
        Err(ActivationError::UnexpectedSessionHeader)
    ));
}

#[test]
fn rakp_tags_and_session_ids_are_bound_at_each_stage() {
    let username = Username::new("root").unwrap();
    let managed_id = NonZeroU32::new(1).unwrap();
    let console_id = NonZeroU32::new(2).unwrap();
    let rm1 = RakpMessage1 {
        message_tag: 3,
        managed_system_session_id: managed_id,
        remote_console_random_number: [1; 16],
        requested_maximum_privilege_level: PrivilegeLevel::Administrator,
        username: &username,
    };
    let mut rm2 = RakpMessage2 {
        message_tag: 4,
        remote_console_session_id: console_id,
        managed_system_random_number: [2; 16],
        managed_system_guid: [3; 16],
        key_exchange_auth_code: &[0; 20],
    };
    assert!(matches!(
        State::validate_rm1_rm2(console_id, &rm1, &rm2),
        Err(ValidateRakpMessage2Error::MessageTagMismatch)
    ));
    rm2.message_tag = rm1.message_tag;
    assert!(State::validate_rm1_rm2(console_id, &rm1, &rm2).is_ok());
    assert!(matches!(
        State::validate_rm1_rm2(managed_id, &rm1, &rm2),
        Err(ValidateRakpMessage2Error::RemoteConsoleSessionIdMismatch)
    ));

    let rm3 = RakpMessage3 {
        message_tag: 5,
        managed_system_session_id: managed_id,
        contents: RakpMessage3Contents::Success(&[]),
    };
    let mut rm4 = RakpMessage4 {
        message_tag: 6,
        managed_system_session_id: console_id,
        integrity_check_value: &[],
    };
    assert!(matches!(
        State::validate_rm3_rm4(console_id, &rm3, &rm4),
        Err(ValidateRakpMessage4Error::MessageTagMismatch)
    ));
    rm4.message_tag = rm3.message_tag;
    assert!(matches!(
        State::validate_rm3_rm4(managed_id, &rm3, &rm4),
        Err(ValidateRakpMessage4Error::RemoteConsoleSessionIdMismatch)
    ));
    assert!(State::validate_rm3_rm4(console_id, &rm3, &rm4).is_ok());
}

fn receive_unencrypted(peer: &UdpSocket) -> Message {
    let mut raw = [0; 4096];
    let len = peer.recv(&mut raw).unwrap();
    CryptoState::default()
        .read_payload(&mut raw[4..len])
        .unwrap()
}

fn send_unencrypted(peer: &UdpSocket, message: Message) {
    let wire = RmcpHeader::new_ipmi()
        .write(|buffer| CryptoState::write_unencrypted(&message, buffer))
        .unwrap();
    peer.send(&wire).unwrap();
}

fn open_session_response(request: &Message, session_id: u32) -> Vec<u8> {
    let mut response = vec![request.payload[0], 0, 4, 0];
    response.extend_from_slice(&request.payload[4..8]);
    response.extend_from_slice(&session_id.to_le_bytes());
    for (ty, algorithm) in [(0, 1), (1, 1), (2, 1)] {
        response.extend_from_slice(&[ty, 0, 0, 8, algorithm, 0, 0, 0]);
    }
    response
}

fn fresh_client(peer: &UdpSocket) -> UdpSocket {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.connect(peer.local_addr().unwrap()).unwrap();
    peer.connect(client.local_addr().unwrap()).unwrap();
    client
}

#[test]
fn complete_rakp_sha1_aes_activation_and_request_over_udp() {
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let client = fresh_client(&peer);
    let server = std::thread::spawn(move || {
        let password = b"local test password";
        let managed_id = NonZeroU32::new(0x87654321).unwrap();
        let managed_random = [0x66; 16];
        let guid = [0x77; 16];
        let open = receive_unencrypted(&peer);
        assert_eq!(open.ty, PayloadType::RmcpPlusOpenSessionRequest);
        let console_id =
            NonZeroU32::new(u32::from_le_bytes(open.payload[4..8].try_into().unwrap())).unwrap();
        send_unencrypted(
            &peer,
            Message {
                ty: PayloadType::RmcpPlusOpenSessionResponse,
                session_id: 0,
                session_sequence_number: 0,
                payload: open_session_response(&open, managed_id.get()),
            },
        );
        let rm1_wire = receive_unencrypted(&peer);
        assert_eq!(rm1_wire.ty, PayloadType::RakpMessage1);
        let console_random: [u8; 16] = rm1_wire.payload[8..24].try_into().unwrap();
        let privilege = rm1_wire.payload[24];
        let username_len = rm1_wire.payload[27];
        let username =
            Username::new(std::str::from_utf8(&rm1_wire.payload[28..]).unwrap()).unwrap();
        let kex = Sha1Hmac::new(password)
            .feed(&console_id.get().to_le_bytes())
            .feed(&managed_id.get().to_le_bytes())
            .feed(&console_random)
            .feed(&managed_random)
            .feed(&guid)
            .feed(&[privilege, username_len])
            .feed(&username)
            .finalize();
        let mut rm2_data = vec![rm1_wire.payload[0], 0, 0, 0];
        rm2_data.extend_from_slice(&console_id.get().to_le_bytes());
        rm2_data.extend_from_slice(&managed_random);
        rm2_data.extend_from_slice(&guid);
        rm2_data.extend_from_slice(&kex);
        send_unencrypted(
            &peer,
            Message {
                ty: PayloadType::RakpMessage2,
                session_id: 0,
                session_sequence_number: 0,
                payload: rm2_data,
            },
        );
        let rm3 = receive_unencrypted(&peer);
        assert_eq!(rm3.ty, PayloadType::RakpMessage3);
        assert_eq!(rm3.payload[1], 0);
        let sik = Sha1Hmac::new(password)
            .feed(&console_random)
            .feed(&managed_random)
            .feed(&[privilege, username_len])
            .feed(&username)
            .finalize();
        let integrity = Sha1Hmac::new(&sik)
            .feed(&console_random)
            .feed(&managed_id.get().to_le_bytes())
            .feed(&guid)
            .finalize();
        let mut rm4_data = vec![rm3.payload[0], 0, 0, 0];
        rm4_data.extend_from_slice(&console_id.get().to_le_bytes());
        rm4_data.extend_from_slice(&integrity[..12]);
        send_unencrypted(
            &peer,
            Message {
                ty: PayloadType::RakpMessage4,
                session_id: 0,
                session_sequence_number: 0,
                payload: rm4_data,
            },
        );
        let osr = OpenSessionResponse::from_data(&open_session_response(&open, managed_id.get()))
            .unwrap();
        let rm1 = RakpMessage1 {
            message_tag: rm1_wire.payload[0],
            managed_system_session_id: managed_id,
            remote_console_random_number: console_random,
            requested_maximum_privilege_level: PrivilegeLevel::Administrator,
            username: &username,
        };
        let rm2 = RakpMessage2 {
            message_tag: rm1.message_tag,
            remote_console_session_id: console_id,
            managed_system_random_number: managed_random,
            managed_system_guid: guid,
            key_exchange_auth_code: &kex,
        };
        let mut crypto = CryptoState::new(None, password);
        assert!(crypto
            .calculate_rakp3_data(&osr, &rm1, &rm2)
            .unwrap()
            .is_some());
        let mut raw = [0; 4096];
        let len = peer.recv(&mut raw).unwrap();
        let outbound = crypto.read_payload(&mut raw[4..len]).unwrap();
        assert_eq!(outbound.ty, PayloadType::IpmiMessage);
        assert_eq!(outbound.session_id, managed_id.get());
        send_answer(
            &peer,
            &mut crypto,
            Message {
                ty: PayloadType::IpmiMessage,
                session_id: console_id.get(),
                session_sequence_number: 1,
                payload: response(outbound.payload[4] >> 2),
            },
        );
    });

    let prior = v1_5::State::new(
        client,
        TransportPolicy::new(Duration::from_secs(2)),
        Some(std::time::Instant::now() + Duration::from_secs(2)),
    );
    let username = Username::new("root").unwrap();
    let mut state = State::activate(
        prior,
        Some(PrivilegeLevel::Administrator),
        &username,
        b"local test password",
        CipherSuite::Id3,
    )
    .unwrap();
    let response = state.send_recv(&mut request()).unwrap();
    assert_eq!(response.seq(), 0);
    server.join().unwrap();
}

#[test]
fn network_activation_rejects_wrong_open_session_payload() {
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let client = fresh_client(&peer);
    let server = std::thread::spawn(move || {
        let open = receive_unencrypted(&peer);
        send_unencrypted(
            &peer,
            Message {
                ty: PayloadType::RakpMessage2,
                session_id: 0,
                session_sequence_number: 0,
                payload: open_session_response(&open, 7),
            },
        );
    });
    let prior = v1_5::State::new(
        client,
        TransportPolicy::new(Duration::from_secs(1)),
        Some(std::time::Instant::now() + Duration::from_secs(1)),
    );
    assert!(matches!(
        State::activate(
            prior,
            Some(PrivilegeLevel::Administrator),
            &Username::new("root").unwrap(),
            b"password",
            CipherSuite::Id3,
        ),
        Err(ActivationError::UnexpectedPayloadType(
            PayloadType::RakpMessage2
        ))
    ));
    server.join().unwrap();
}
