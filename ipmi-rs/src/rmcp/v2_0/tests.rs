use super::*;
use crate::{
    connection::{
        Address, Channel, IpmbTarget, LogicalUnit, Message as IpmiMessage, NetFn, Request,
        RequestTargetAddress,
    },
    rmcp::{checksum::Checksum, socket::TransportPolicy, RmcpHeader, RmcpIpmiSendError},
};
use crypto::sha1::Sha1Hmac;
use std::{net::UdpSocket, time::Duration};

fn pair(timeout: Duration) -> (State, UdpSocket, CryptoState) {
    pair_with_peer(timeout, true)
}

fn pair_with_peer(timeout: Duration, connect_peer: bool) -> (State, UdpSocket, CryptoState) {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.connect(peer.local_addr().unwrap()).unwrap();
    if connect_peer {
        peer.connect(client.local_addr().unwrap()).unwrap();
    }

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
            sol: None,
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

fn bridge_request(transit: Option<IpmbTarget>) -> Request {
    Request::new(
        IpmiMessage::new_request(NetFn::Chassis, 2, vec![1]),
        RequestTargetAddress::Bridged {
            target: IpmbTarget::new(Address(0x52), Channel::Primary, LogicalUnit::One),
            transit,
        },
    )
}

fn bridge_reply(
    requestor: u8,
    responder: u8,
    sequence: u8,
    netfn: u8,
    lun: u8,
    cmd: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut payload = vec![
        requestor,
        netfn << 2,
        0,
        responder,
        sequence << 2 | lun,
        cmd,
    ];
    payload[2] = Checksum::from_iter(payload[..2].iter().copied());
    payload.extend_from_slice(data);
    payload.push(Checksum::from_iter(payload[3..].iter().copied()));
    payload
}

#[test]
fn encrypted_dual_hop_nested_send_message_reply() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(200));
    let mut req = bridge_request(Some(IpmbTarget::new(
        Address(0x30),
        Channel::Primary,
        LogicalUnit::Two,
    )));
    state.send(&mut req).unwrap();
    let outbound = read_secure(&peer, &mut crypto);
    assert_eq!(outbound.ty, PayloadType::IpmiMessage);
    assert_eq!(
        (
            outbound.payload[5],
            outbound.payload[7],
            outbound.payload[12]
        ),
        (0x34, 0x30, 0x34)
    );
    assert_eq!(outbound.payload[17], 0x20);
    let final_reply = bridge_reply(0x20, 0x52, 2, 1, 1, 2, &[0, 0xbe]);
    let transit = bridge_reply(
        0x81,
        0x30,
        1,
        7,
        2,
        0x34,
        &[&[0][..], &final_reply].concat(),
    );
    let outer = bridge_reply(0x81, 0x20, 0, 7, 0, 0x34, &[&[0][..], &transit].concat());
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::IpmiMessage,
            session_id: state.console_session_id.get(),
            session_sequence_number: 1,
            payload: outer,
        },
    );
    assert_eq!(state.recv().unwrap().data(), &[0xbe]);
}

#[test]
fn suite17_bridged_reply_is_authenticated() {
    fn run(provider: CryptoProvider) {
        let (mut state, peer, mut crypto) = pair_suite17(Duration::from_millis(200), provider);
        let mut req = bridge_request(None);
        state.send(&mut req).unwrap();
        let outgoing = read_secure(&peer, &mut crypto);
        assert_eq!(outgoing.payload[5], 0x34);
        let target = bridge_reply(0x81, 0x52, 1, 1, 1, 2, &[0, 0xa5]);
        let outer = bridge_reply(0x81, 0x20, 0, 7, 0, 0x34, &[&[0][..], &target].concat());
        send_answer(
            &peer,
            &mut crypto,
            Message {
                ty: PayloadType::IpmiMessage,
                session_id: state.console_session_id.get(),
                session_sequence_number: 1,
                payload: outer,
            },
        );
        assert_eq!(state.recv().unwrap().data(), &[0xa5]);
    }
    run(CryptoProvider::RustCrypto);
    #[cfg(feature = "symcrypt-backend")]
    run(CryptoProvider::SymCrypt);
}

#[test]
fn encrypted_reordered_hops_keep_session_replay_monotonic() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(150));
    let mut req = bridge_request(Some(IpmbTarget::new(
        Address(0x30),
        Channel::Primary,
        LogicalUnit::Two,
    )));
    state.send(&mut req).unwrap();
    read_secure(&peer, &mut crypto);
    let packets = [
        (3, bridge_reply(0x20, 0x52, 2, 1, 1, 2, &[0, 0x55])),
        (2, bridge_reply(0x81, 0x30, 1, 7, 2, 0x34, &[0])),
        (1, bridge_reply(0x81, 0x20, 0, 7, 0, 0x34, &[0])),
    ];
    for (session_sequence_number, payload) in packets {
        send_answer(
            &peer,
            &mut crypto,
            Message {
                ty: PayloadType::IpmiMessage,
                session_id: state.console_session_id.get(),
                session_sequence_number,
                payload,
            },
        );
    }
    assert_eq!(state.recv().unwrap().data(), &[0x55]);
    assert_eq!(state.last_inbound_sequence, Some(3));
}

#[test]
fn encrypted_single_hop_get_message_filters_identity_replay_and_duplicate() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(240));
    let mut req = bridge_request(None);
    state.send(&mut req).unwrap();
    let outbound = read_secure(&peer, &mut crypto);
    assert_eq!(outbound.payload[7], 0x52);
    let ack = bridge_reply(0x81, 0x20, 0, 7, 0, 0x34, &[0]);
    for (id, seq) in [
        (state.session_id.get(), 1),
        (state.console_session_id.get(), 2),
    ] {
        send_answer(
            &peer,
            &mut crypto,
            Message {
                ty: PayloadType::IpmiMessage,
                session_id: id,
                session_sequence_number: seq,
                payload: ack.clone(),
            },
        );
    }
    let console_id = state.console_session_id.get();
    let handle = std::thread::spawn(move || {
        let get = read_secure(&peer, &mut crypto);
        assert_eq!((get.payload[5], get.payload[4] >> 2), (0x33, 2));
        let mut body = vec![0, 0];
        body.extend(bridge_reply(0x81, 0x52, 1, 1, 1, 2, &[0, 0xaa])[1..].iter());
        let answer = bridge_reply(0x81, 0x20, 2, 7, 0, 0x33, &body);
        for seq in [2, 3] {
            send_answer(
                &peer,
                &mut crypto,
                Message {
                    ty: PayloadType::IpmiMessage,
                    session_id: console_id,
                    session_sequence_number: seq,
                    payload: answer.clone(),
                },
            );
        }
    });
    assert_eq!(state.recv().unwrap().data(), &[0xaa]);
    handle.join().unwrap();
    assert_eq!(state.last_inbound_sequence, Some(3));
}

fn send_answer(peer: &UdpSocket, crypto: &mut CryptoState, message: Message) {
    let wire = RmcpHeader::new_ipmi()
        .write(|buffer| crypto.write_message(&message, buffer))
        .unwrap();
    peer.send(&wire).unwrap();
}

fn pair_suite17(timeout: Duration, provider: CryptoProvider) -> (State, UdpSocket, CryptoState) {
    let (mut state, peer, _) = pair(timeout);
    state.console_session_id = NonZeroU32::new(0x10203040).unwrap();
    state.session_id = NonZeroU32::new(0x55667788).unwrap();
    let username = Username::new("ADMIN").unwrap();
    let request = RakpMessage1 {
        message_tag: 13,
        managed_system_session_id: state.session_id,
        remote_console_random_number: core::array::from_fn(|i| i as u8),
        requested_maximum_privilege_level: PrivilegeLevel::Administrator,
        username: &username,
    };
    let rakp2_wire = hex::decode(concat!(
        "0d00000040302010",
        "101112131415161718191a1b1c1d1e1f",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "897e8b5e6a75f382aea006eff95c210f9f26edd01e5ea38f22fcc749f3ffdb10"
    ))
    .unwrap();
    let response = RakpMessage2::from_data(&rakp2_wire).unwrap();
    let negotiated = OpenSessionResponse {
        message_tag: 0,
        maximum_privilege_level: PrivilegeLevel::Administrator,
        remote_console_session_id: state.console_session_id,
        managed_system_session_id: state.session_id,
        authentication_payload: AuthenticationAlgorithm::RakpHmacSha256,
        integrity_payload: IntegrityAlgorithm::HmacSha256_128,
        confidentiality_payload: ConfidentialityAlgorithm::AesCbc128,
    };
    let make_crypto = || {
        let mut crypto =
            CryptoState::new_with_provider(None, b"correct horse battery staple", provider);
        assert!(crypto
            .calculate_rakp3_data(&negotiated, &request, &response)
            .unwrap()
            .is_some());
        crypto
    };
    state.state = make_crypto();
    (state, peer, make_crypto())
}

fn encrypted_suite17_sol_and_ipmi_for(provider: CryptoProvider) {
    let (mut state, peer, mut crypto) = pair_suite17(Duration::from_millis(250), provider);
    state.sol_open();
    let mut req = request();
    state.send(&mut req).unwrap();
    let outbound = read_secure(&peer, &mut crypto);
    assert_eq!(outbound.ty, PayloadType::IpmiMessage);
    assert_eq!(outbound.session_id, state.session_id.get());

    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::Sol,
            session_id: state.console_session_id.get(),
            session_sequence_number: 1,
            payload: vec![1, 0, 0, 0, b'S'],
        },
    );
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::IpmiMessage,
            session_id: state.console_session_id.get(),
            session_sequence_number: 2,
            payload: response(0),
        },
    );
    assert_eq!(state.recv().unwrap().seq(), 0);
    let ack = read_secure(&peer, &mut crypto);
    assert_eq!(ack.ty, PayloadType::Sol);
    assert_eq!(ack.payload, [0, 1, 1, 0]);
    let mut output = [0];
    assert_eq!(state.sol_flow().read(&mut output), 1);
    assert_eq!(output, [b'S']);

    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::Sol,
            session_id: state.console_session_id.get(),
            session_sequence_number: 2,
            payload: vec![2, 0, 0, 0, b'!'],
        },
    );
    assert!(matches!(
        state.poll_sol(
            std::time::Instant::now() + Duration::from_millis(100),
            false
        ),
        Err(RmcpIpmiReceiveError::InvalidSessionSequence)
    ));
}

#[test]
fn encrypted_suite17_sol_and_ipmi_share_authenticated_session() {
    encrypted_suite17_sol_and_ipmi_for(CryptoProvider::RustCrypto);
    #[cfg(feature = "symcrypt-backend")]
    encrypted_suite17_sol_and_ipmi_for(CryptoProvider::SymCrypt);
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
fn sol_dispatch_keeps_rmcp_identity_and_replay_checks() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(100));
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    state.sol_open();
    let deadline = std::time::Instant::now() + Duration::from_millis(100);
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::Sol,
            session_id: state.session_id.get(),
            session_sequence_number: 1,
            payload: vec![1, 0, 0, 0, b'x'],
        },
    );
    assert!(matches!(
        state.poll_sol(deadline, false),
        Err(RmcpIpmiReceiveError::SessionIdMismatch)
    ));
    assert!(peer.recv(&mut [0; 4096]).is_err()); // no ACK for wrong identity

    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::Sol,
            session_id: state.console_session_id.get(),
            session_sequence_number: 2,
            payload: vec![1, 0, 0, 0, b'y'],
        },
    );
    state
        .poll_sol(
            std::time::Instant::now() + Duration::from_millis(100),
            false,
        )
        .unwrap();
    let mut ack = [0; 4096];
    peer.recv(&mut ack).unwrap();
    state.sol_flow().read(&mut [0; 1]);

    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::Sol,
            session_id: state.console_session_id.get(),
            session_sequence_number: 2, // replay, despite a different SOL seq
            payload: vec![2, 0, 0, 0, b'z'],
        },
    );
    assert!(matches!(
        state.poll_sol(
            std::time::Instant::now() + Duration::from_millis(100),
            false
        ),
        Err(RmcpIpmiReceiveError::InvalidSessionSequence)
    ));
    assert!(peer.recv(&mut [0; 4096]).is_err());
}

#[test]
fn malformed_authenticated_sol_cannot_replay_its_session_sequence() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(100));
    state.sol_open();
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::Sol,
            session_id: state.console_session_id.get(),
            session_sequence_number: 1,
            payload: vec![1, 0, 0, 0x80],
        },
    );
    assert!(matches!(
        state.poll_sol(
            std::time::Instant::now() + Duration::from_millis(100),
            false
        ),
        Err(RmcpIpmiReceiveError::Sol(SolFrameError::InvalidHeader))
    ));
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::Sol,
            session_id: state.console_session_id.get(),
            session_sequence_number: 1,
            payload: vec![1, 0, 0, 0, b'x'],
        },
    );
    assert!(matches!(
        state.poll_sol(
            std::time::Instant::now() + Duration::from_millis(100),
            false
        ),
        Err(RmcpIpmiReceiveError::InvalidSessionSequence)
    ));
    assert!(!state.sol_flow().has_output());
    assert!(peer.recv(&mut [0; 4096]).is_err());
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
fn late_reply_is_drained_before_valid_reply_without_poisoning_next_request() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(70));
    let mut req = request();
    let mut wire = [0; 4096];
    state.send(&mut req).unwrap();
    peer.recv(&mut wire).unwrap();
    assert!(matches!(state.recv(), Err(RmcpIpmiReceiveError::Timeout)));

    state.send(&mut req).unwrap();
    peer.recv(&mut wire).unwrap();
    for (session_sequence_number, ipmb_sequence) in [(10, 0), (9, 1)] {
        send_answer(
            &peer,
            &mut crypto,
            Message {
                ty: PayloadType::IpmiMessage,
                session_id: state.console_session_id.get(),
                session_sequence_number,
                payload: response(ipmb_sequence),
            },
        );
    }
    assert_eq!(state.recv().unwrap().seq(), 1);

    state.send(&mut req).unwrap();
    peer.recv(&mut wire).unwrap();
    for (session_sequence_number, ipmb_sequence) in [(10, 0), (9, 1), (11, 2)] {
        send_answer(
            &peer,
            &mut crypto,
            Message {
                ty: PayloadType::IpmiMessage,
                session_id: state.console_session_id.get(),
                session_sequence_number,
                payload: response(ipmb_sequence),
            },
        );
    }
    assert_eq!(state.recv().unwrap().seq(), 2);
}

#[test]
fn late_reply_and_sol_output_before_correlated_reply() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(90));
    state.sol_open();
    let mut req = request();
    let mut wire = [0; 4096];
    state.send(&mut req).unwrap();
    peer.recv(&mut wire).unwrap();
    assert!(matches!(state.recv(), Err(RmcpIpmiReceiveError::Timeout)));

    state.send(&mut req).unwrap();
    peer.recv(&mut wire).unwrap();
    // The late reply's newer session sequence must not retire the request
    // or suppress an earlier, still-fresh SOL frame and correlated reply.
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::IpmiMessage,
            session_id: state.console_session_id.get(),
            session_sequence_number: 100,
            payload: response(0),
        },
    );
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::Sol,
            session_id: state.console_session_id.get(),
            session_sequence_number: 1,
            payload: vec![1, 0, 0, 0, b'X'],
        },
    );
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::IpmiMessage,
            session_id: state.console_session_id.get(),
            session_sequence_number: 2,
            payload: response(1),
        },
    );
    assert_eq!(state.recv().unwrap().seq(), 1);
    let ack = read_secure(&peer, &mut crypto);
    assert_eq!(ack.ty, PayloadType::Sol);
    assert_eq!(ack.payload, [0, 1, 1, 0]); // no console-input characters
    let mut output = [0; 2];
    assert_eq!(state.sol_flow().read(&mut output), 1);
    assert_eq!(output[0], b'X');
    assert!(state.ipmb_state.pending.is_none());

    state.send(&mut req).unwrap();
    peer.recv(&mut wire).unwrap();
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::IpmiMessage,
            session_id: state.console_session_id.get(),
            session_sequence_number: 3,
            payload: response(2),
        },
    );
    assert_eq!(state.recv().unwrap().seq(), 2);
}

#[test]
fn mismatched_reply_flood_is_bounded_and_pending_is_retired() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(350));
    let mut req = request();
    let mut wire = [0; 4096];
    state.send(&mut req).unwrap();
    peer.recv(&mut wire).unwrap();
    for session_sequence_number in 1..=super::super::socket::MAX_UNRELATED as u32 {
        send_answer(
            &peer,
            &mut crypto,
            Message {
                ty: PayloadType::IpmiMessage,
                session_id: state.console_session_id.get(),
                session_sequence_number,
                payload: response(63),
            },
        );
    }
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::IpmiMessage,
            session_id: state.console_session_id.get(),
            session_sequence_number: 33,
            payload: response(0),
        },
    );
    assert!(matches!(
        state.recv(),
        Err(RmcpIpmiReceiveError::TooManyUnrelatedPackets)
    ));
    assert!(state.ipmb_state.pending.is_none());

    state.send(&mut req).unwrap();
    peer.recv(&mut wire).unwrap();
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::IpmiMessage,
            session_id: state.console_session_id.get(),
            session_sequence_number: 34,
            payload: response(1),
        },
    );
    assert_eq!(state.recv().unwrap().seq(), 1);
}

#[test]
fn mixed_sol_and_ipmi_flood_shares_pending_receive_budget() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(350));
    state.sol_open();
    let mut req = request();
    let mut wire = [0; 4096];
    state.send(&mut req).unwrap();
    peer.recv(&mut wire).unwrap();
    for seq in 1..=super::super::socket::MAX_UNRELATED as u32 {
        send_answer(
            &peer,
            &mut crypto,
            Message {
                ty: if seq % 2 == 0 {
                    PayloadType::Sol
                } else {
                    PayloadType::IpmiMessage
                },
                session_id: state.console_session_id.get(),
                session_sequence_number: seq,
                payload: if seq % 2 == 0 {
                    vec![0, 0, 0, 0] // ACK-only: no output to interrupt the receive
                } else {
                    response(63)
                },
            },
        );
    }
    assert!(matches!(
        state.recv(),
        Err(RmcpIpmiReceiveError::TooManyUnrelatedPackets)
    ));
    assert!(state.ipmb_state.pending.is_none());

    state.send(&mut req).unwrap();
    peer.recv(&mut wire).unwrap();
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::IpmiMessage,
            session_id: state.console_session_id.get(),
            session_sequence_number: 33,
            payload: response(1),
        },
    );
    assert_eq!(state.recv().unwrap().seq(), 1);
}

#[test]
fn sol_poll_shares_budget_between_rmcp_and_ack_only_frames() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(350));
    state.sol_open();
    for seq in 1..=super::super::socket::MAX_UNRELATED as u32 {
        if seq % 2 == 0 {
            send_answer(
                &peer,
                &mut crypto,
                Message {
                    ty: PayloadType::Sol,
                    session_id: state.console_session_id.get(),
                    session_sequence_number: seq,
                    payload: vec![0, 0, 0, 0],
                },
            );
        } else {
            peer.send(&[6, 0, 0xff, 6]).unwrap(); // unrelated ASF datagram
        }
    }
    assert!(matches!(
        state.poll_sol(
            std::time::Instant::now() + Duration::from_millis(350),
            false
        ),
        Err(RmcpIpmiReceiveError::TooManyUnrelatedPackets)
    ));
}

#[test]
fn encrypted_partial_sol_ack_rejects_changed_retransmission_suffix() {
    let (mut state, peer, mut crypto) = pair(Duration::from_millis(350));
    peer.set_read_timeout(Some(Duration::from_millis(350)))
        .unwrap();
    state.sol_open();

    for session_seq in 1..=16u32 {
        let sol_seq = ((session_seq - 1) % 15 + 1) as u8;
        let mut data = vec![sol_seq, 0, 0, 0];
        data.extend([b'x'; 255]);
        send_answer(
            &peer,
            &mut crypto,
            Message {
                ty: PayloadType::Sol,
                session_id: state.console_session_id.get(),
                session_sequence_number: session_seq,
                payload: data,
            },
        );
        state
            .poll_sol(
                std::time::Instant::now() + Duration::from_millis(350),
                false,
            )
            .unwrap();
        assert_eq!(
            read_secure(&peer, &mut crypto).payload,
            [0, sol_seq, 255, 0]
        );
    }

    let mut partial = vec![2, 0, 0, 0];
    partial.extend([b'a'; 17]);
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::Sol,
            session_id: state.console_session_id.get(),
            session_sequence_number: 17,
            payload: partial.clone(),
        },
    );
    state
        .poll_sol(
            std::time::Instant::now() + Duration::from_millis(350),
            false,
        )
        .unwrap();
    assert_eq!(read_secure(&peer, &mut crypto).payload, [0, 2, 16, 0x40]);
    let mut delivered = vec![0; 4096];
    assert_eq!(state.sol_flow().read(&mut delivered), 4096);

    partial[20] = b'z'; // This byte was not accepted, but must still match the retry.
    send_answer(
        &peer,
        &mut crypto,
        Message {
            ty: PayloadType::Sol,
            session_id: state.console_session_id.get(),
            session_sequence_number: 18,
            payload: partial,
        },
    );
    assert!(matches!(
        state.poll_sol(
            std::time::Instant::now() + Duration::from_millis(350),
            false
        ),
        Err(RmcpIpmiReceiveError::Sol(
            SolFrameError::ConflictingRetransmission
        ))
    ));
    assert_eq!(read_secure(&peer, &mut crypto).payload, [0, 2, 0, 0x40]);
    assert!(!state.sol_flow().has_output());
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
        CryptoProvider::RustCrypto,
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
            CryptoProvider::RustCrypto,
        ),
        Err(ActivationError::UnexpectedPayloadType(
            PayloadType::RakpMessage2
        ))
    ));
    server.join().unwrap();
}

fn sol_fixture(timeout: Duration) -> (super::super::Rmcp, UdpSocket, CryptoState) {
    let (state, peer, crypto) = pair(timeout);
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut rmcp = super::super::Rmcp::new(peer.local_addr().unwrap(), timeout).unwrap();
    rmcp.require_rmcp_plus(true);
    rmcp.unbound_state.policy_mut().cancellation = state.socket.cancellation_token();
    rmcp.active_state = Some(crate::rmcp::internal::RmcpWithState::from_active(
        crate::rmcp::internal::Active::V2_0(state),
    ));
    (rmcp, peer, crypto)
}

fn read_secure(peer: &UdpSocket, crypto: &mut CryptoState) -> Message {
    let mut wire = [0; 4096];
    let n = peer.recv(&mut wire).unwrap();
    assert_eq!(&wire[..4], &[6, 0, 0xff, 7]);
    assert_eq!(wire[5] & 0xc0, 0xc0); // authenticated and encrypted
    crypto.read_payload(&mut wire[4..n]).unwrap()
}

fn reply_command(
    peer: &UdpSocket,
    crypto: &mut CryptoState,
    request: &Message,
    session_seq: u32,
    code: u8,
    body: &[u8],
) {
    assert_eq!(request.ty, PayloadType::IpmiMessage);
    let req = &request.payload;
    let mut payload = vec![req[3], req[1] + 4, 0, req[0], req[4], req[5], code];
    payload[2] = Checksum::from_iter(payload[..2].iter().copied());
    payload.extend(body);
    payload.push(Checksum::from_iter(payload[3..].iter().copied()));
    send_answer(
        peer,
        crypto,
        Message {
            ty: PayloadType::IpmiMessage,
            session_id: 0x12345678,
            session_sequence_number: session_seq,
            payload,
        },
    );
}

fn reply_sol(peer: &UdpSocket, crypto: &mut CryptoState, session_seq: u32, payload: &[u8]) {
    send_answer(
        peer,
        crypto,
        Message {
            ty: PayloadType::Sol,
            session_id: 0x12345678,
            session_sequence_number: session_seq,
            payload: payload.to_vec(),
        },
    );
}

fn activate_response(port: u16) -> Vec<u8> {
    let mut data = vec![0, 0, 0, 0, 12, 0, 12, 0];
    data.extend(port.to_le_bytes());
    data.extend([0, 0]); // no VLAN
    data
}

#[test]
fn capture_dispatches_interleaved_sol_and_never_sends_console_input() {
    use crate::app::sol::SolInstance;
    let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(550));
    let server = std::thread::spawn(move || {
        let activation = read_secure(&peer, &mut crypto);
        assert_eq!(activation.payload[5], 0x48);
        assert_eq!(&activation.payload[6..12], &[1, 1, 0xc6, 0, 0, 0]);
        // Data can arrive while waiting for the IPMI Activate Payload response.
        reply_sol(&peer, &mut crypto, 1, &[1, 0, 0, 0, b'A']);
        reply_command(
            &peer,
            &mut crypto,
            &activation,
            2,
            0,
            &activate_response(peer.local_addr().unwrap().port()),
        );
        let ack = read_secure(&peer, &mut crypto);
        assert_eq!(ack.ty, PayloadType::Sol);
        assert_eq!(ack.payload, [0, 1, 1, 0]);
        reply_sol(&peer, &mut crypto, 3, &[2, 0, 0, 0, b'B']);
        let ack = read_secure(&peer, &mut crypto);
        assert_eq!(ack.ty, PayloadType::Sol);
        assert_eq!(ack.payload, [0, 2, 1, 0]);
        let deactivate = read_secure(&peer, &mut crypto);
        assert_eq!(deactivate.payload[5], 0x49);
        assert_eq!(&deactivate.payload[6..12], &[1, 1, 0, 0, 0, 0]);
        reply_command(&peer, &mut crypto, &deactivate, 4, 0, &[]);
    });
    let mut capture = rmcp.open_sol_capture(SolInstance::new(1).unwrap()).unwrap();
    let mut output = [0; 8];
    assert_eq!(capture.read(&mut output).unwrap(), 1);
    assert_eq!(output[0], b'A');
    assert_eq!(capture.read(&mut output).unwrap(), 1);
    assert_eq!(output[0], b'B');
    capture.close().unwrap();
    server.join().unwrap();
}

#[test]
fn cancellation_delivers_acked_activation_output_and_preserves_cleanup_output() {
    use crate::{
        app::sol::SolInstance,
        rmcp::{SolError, SolInterruptionReason},
    };
    let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(500));
    let token = rmcp.cancellation_token();
    let server = std::thread::spawn(move || {
        let activation = read_secure(&peer, &mut crypto);
        reply_sol(&peer, &mut crypto, 1, &[1, 0, 0, 0, b'X']);
        reply_command(
            &peer,
            &mut crypto,
            &activation,
            2,
            0,
            &activate_response(peer.local_addr().unwrap().port()),
        );
        let ack = read_secure(&peer, &mut crypto);
        assert_eq!(ack.payload, [0, 1, 1, 0]); // X was accepted during activation
        let deactivate = read_secure(&peer, &mut crypto);
        assert_eq!(deactivate.payload[5], 0x49);
        // Even output arriving while closing must be returned to the caller.
        reply_sol(
            &peer,
            &mut crypto,
            3,
            &[2, 0, 0, 0, b'M', b'A', b'R', b'K', b'E', b'R'],
        );
        reply_command(&peer, &mut crypto, &deactivate, 4, 0, &[]);
        let ack = read_secure(&peer, &mut crypto);
        assert_eq!(ack.payload, [0, 2, 6, 0]);
    });
    let mut capture = rmcp.open_sol_capture(SolInstance::new(1).unwrap()).unwrap();
    token.cancel();
    assert_eq!(capture.read(&mut []).unwrap(), 0); // zero-length read cannot consume X
    let mut output = [0u8; 1];
    assert_eq!(capture.read(&mut output).unwrap(), 1);
    assert_eq!(output, [b'X']);
    match capture.read(&mut output) {
        Err(SolError::Interrupted(stopped)) => {
            assert!(matches!(
                stopped.reason,
                SolInterruptionReason::Receive(RmcpIpmiReceiveError::Cancelled)
            ));
            assert!(!stopped.remote_close_unconfirmed);
            assert_eq!(stopped.buffered_output.as_bytes(), b"MARKER");
            assert!(!format!("{stopped:?}").contains("MARKER"));
            assert_eq!(stopped.buffered_output.into_bytes(), b"MARKER");
        }
        other => panic!("expected interruption, got {other:?}"),
    }
    capture.close().unwrap();
    server.join().unwrap();
}

#[test]
fn cancellation_during_activation_preserves_already_acked_output() {
    use crate::{app::sol::SolInstance, rmcp::SolError};
    let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(500));
    let token = rmcp.cancellation_token();
    let server = std::thread::spawn(move || {
        let _activation = read_secure(&peer, &mut crypto);
        reply_sol(
            &peer,
            &mut crypto,
            1,
            &[1, 0, 0, 0, b'P', b'H', b'R', b'A', b'S', b'E'],
        );
        assert_eq!(read_secure(&peer, &mut crypto).payload, [0, 1, 6, 0]);
        token.cancel(); // activation response is lost after console output was ACKed
        let deactivate = read_secure(&peer, &mut crypto);
        assert_eq!(deactivate.payload[5], 0x49);
        reply_command(&peer, &mut crypto, &deactivate, 2, 0, &[]);
    });
    match rmcp.open_sol_capture(SolInstance::new(1).unwrap()) {
        Err(SolError::ActivationUncertain {
            remote_close_unconfirmed: false,
            buffered_output,
            ..
        }) => {
            assert_eq!(buffered_output.as_bytes(), b"PHRASE");
            assert!(!format!("{buffered_output:?}").contains("PHRASE"));
        }
        Ok(_) => panic!("activation unexpectedly succeeded"),
        Err(error) => panic!("unexpected activation error: {error:?}"),
    }
    server.join().unwrap();
}

#[test]
fn cancellation_during_input_exposes_buffered_output_without_logging_it() {
    use crate::{
        app::sol::SolInstance,
        rmcp::{SolError, SolInterruptionReason},
    };
    let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(500));
    let token = rmcp.cancellation_token();
    let server = std::thread::spawn(move || {
        let activation = read_secure(&peer, &mut crypto);
        reply_command(
            &peer,
            &mut crypto,
            &activation,
            1,
            0,
            &activate_response(peer.local_addr().unwrap().port()),
        );
        let input = read_secure(&peer, &mut crypto);
        assert_eq!(input.payload, [1, 0, 0, 0, b'?']);
        reply_sol(
            &peer,
            &mut crypto,
            2,
            &[1, 0, 0, 0, b'O', b'P', b'A', b'Q', b'U', b'E'],
        );
        let ack = read_secure(&peer, &mut crypto);
        assert_eq!(ack.payload, [0, 1, 6, 0]);
        token.cancel();
        let deactivate = read_secure(&peer, &mut crypto);
        assert_eq!(deactivate.payload[5], 0x49);
        reply_command(&peer, &mut crypto, &deactivate, 3, 0, &[]);
    });
    let mut interactive = rmcp
        .open_sol_interactive(SolInstance::new(1).unwrap())
        .unwrap();
    match interactive.send_input(b"?") {
        Err(SolError::Interrupted(stopped)) => {
            assert!(matches!(
                stopped.reason,
                SolInterruptionReason::Receive(RmcpIpmiReceiveError::Cancelled)
            ));
            assert!(stopped.input_delivery_uncertain);
            assert_eq!(stopped.buffered_output.as_bytes(), b"OPAQUE");
            assert!(!format!("{stopped:?}").contains("OPAQUE"));
        }
        other => panic!("expected interruption, got {other:?}"),
    }
    interactive.close().unwrap();
    server.join().unwrap();
}

#[test]
fn reconnect_refuses_to_discard_acked_unread_output() {
    use crate::{app::sol::SolInstance, rmcp::SolError};
    let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(500));
    let server = std::thread::spawn(move || {
        let activation = read_secure(&peer, &mut crypto);
        reply_sol(&peer, &mut crypto, 1, &[1, 0, 0, 0, b'R']);
        reply_command(
            &peer,
            &mut crypto,
            &activation,
            2,
            0,
            &activate_response(peer.local_addr().unwrap().port()),
        );
        assert_eq!(read_secure(&peer, &mut crypto).payload, [0, 1, 1, 0]);
        let deactivate = read_secure(&peer, &mut crypto);
        assert_eq!(deactivate.payload[5], 0x49);
        reply_command(&peer, &mut crypto, &deactivate, 3, 0, &[]);
    });
    let mut capture = rmcp.open_sol_capture(SolInstance::new(1).unwrap()).unwrap();
    assert!(matches!(
        capture.reconnect("root", b"local test password", 1),
        Err(SolError::BufferedOutputPending)
    ));
    let mut output = [0; 1];
    assert_eq!(capture.read(&mut output).unwrap(), 1);
    assert_eq!(output, [b'R']);
    capture.close().unwrap();
    server.join().unwrap();
}

#[test]
fn explicit_close_reports_acked_unread_output_even_if_deactivation_succeeds() {
    use crate::{
        app::sol::SolInstance,
        rmcp::{SolError, SolInterruptionReason},
    };
    let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(500));
    let server = std::thread::spawn(move || {
        let activation = read_secure(&peer, &mut crypto);
        reply_sol(
            &peer,
            &mut crypto,
            1,
            &[1, 0, 0, 0, b'U', b'N', b'I', b'Q', b'U', b'E'],
        );
        reply_command(
            &peer,
            &mut crypto,
            &activation,
            2,
            0,
            &activate_response(peer.local_addr().unwrap().port()),
        );
        assert_eq!(read_secure(&peer, &mut crypto).payload, [0, 1, 6, 0]);
        let deactivate = read_secure(&peer, &mut crypto);
        reply_command(&peer, &mut crypto, &deactivate, 3, 0, &[]);
    });
    let capture = rmcp.open_sol_capture(SolInstance::new(1).unwrap()).unwrap();
    match capture.close() {
        Err(SolError::Interrupted(stopped)) => {
            assert!(matches!(
                stopped.reason,
                SolInterruptionReason::ClosedWithBufferedOutput
            ));
            assert!(!stopped.remote_close_unconfirmed);
            assert_eq!(stopped.buffered_output.as_bytes(), b"UNIQUE");
            assert!(!format!("{stopped:?}").contains("UNIQUE"));
        }
        other => panic!("expected unread output, got {other:?}"),
    }
    server.join().unwrap();
}

#[test]
fn negotiated_route_is_rejected_and_deactivated() {
    use crate::{app::sol::SolInstance, rmcp::SolError};
    for vlan in [0, 1] {
        let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(550));
        let server = std::thread::spawn(move || {
            let activation = read_secure(&peer, &mut crypto);
            let port = peer.local_addr().unwrap().port();
            let mut data = activate_response(if vlan == 0 { port + 1 } else { port });
            data[10] = vlan;
            reply_command(&peer, &mut crypto, &activation, 1, 0, &data);
            let deactivate = read_secure(&peer, &mut crypto);
            assert_eq!(deactivate.payload[5], 0x49);
            reply_command(&peer, &mut crypto, &deactivate, 2, 0, &[]);
        });
        assert!(matches!(
            rmcp.open_sol_capture(SolInstance::new(1).unwrap()),
            Err(SolError::UnsupportedRoute {
                remote_close_unconfirmed: false,
                ..
            })
        ));
        server.join().unwrap();
    }
}

#[test]
fn interactive_partial_ack_suffix_and_duplicate_output() {
    use crate::app::sol::SolInstance;
    let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(650));
    let server = std::thread::spawn(move || {
        let activation = read_secure(&peer, &mut crypto);
        reply_command(
            &peer,
            &mut crypto,
            &activation,
            1,
            0,
            &activate_response(peer.local_addr().unwrap().port()),
        );
        let input = read_secure(&peer, &mut crypto);
        assert_eq!(input.ty, PayloadType::Sol);
        assert_eq!(input.payload, [1, 0, 0, 0, b'a', b'b', b'c']);
        // One byte accepted; piggyback output with the partial ACK.
        reply_sol(&peer, &mut crypto, 2, &[1, 1, 1, 0, b'X']);
        let ack = read_secure(&peer, &mut crypto);
        assert_eq!(ack.payload, [0, 1, 1, 0]);
        let suffix = read_secure(&peer, &mut crypto);
        assert_eq!(suffix.payload, [2, 0, 0, 0, b'b', b'c']);
        reply_sol(&peer, &mut crypto, 3, &[0, 2, 2, 0]);
        reply_sol(&peer, &mut crypto, 4, &[1, 0, 0, 0, b'X']);
        reply_sol(&peer, &mut crypto, 5, &[2, 0, 0, 0, b'Y']);
        let duplicate_ack = read_secure(&peer, &mut crypto);
        let new_ack = read_secure(&peer, &mut crypto);
        assert_eq!(duplicate_ack.payload, [0, 1, 1, 0]);
        assert_eq!(new_ack.payload, [0, 2, 1, 0]);
        let deactivate = read_secure(&peer, &mut crypto);
        reply_command(&peer, &mut crypto, &deactivate, 6, 0, &[]);
    });
    let mut interactive = rmcp
        .open_sol_interactive(SolInstance::new(1).unwrap())
        .unwrap();
    assert_eq!(interactive.send_input(b"abc").unwrap(), 3);
    let mut bytes = [0; 4];
    assert_eq!(interactive.read(&mut bytes).unwrap(), 1);
    assert_eq!(bytes[0], b'X');
    assert_eq!(interactive.read(&mut bytes).unwrap(), 1);
    assert_eq!(bytes[0], b'Y');
    interactive.close().unwrap();
    server.join().unwrap();
}

#[test]
fn missing_ack_retransmits_same_sequence_and_reports_uncertainty() {
    use crate::{app::sol::SolInstance, rmcp::SolError};
    let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(850));
    let server = std::thread::spawn(move || {
        let activation = read_secure(&peer, &mut crypto);
        reply_command(
            &peer,
            &mut crypto,
            &activation,
            1,
            0,
            &activate_response(peer.local_addr().unwrap().port()),
        );
        let first = read_secure(&peer, &mut crypto);
        assert_eq!(first.ty, PayloadType::Sol);
        for _ in 0..2 {
            let retry = read_secure(&peer, &mut crypto);
            assert_eq!(retry.payload, first.payload);
            assert!(retry.session_sequence_number > first.session_sequence_number);
        }
        let deactivate = read_secure(&peer, &mut crypto);
        assert_eq!(deactivate.payload[5], 0x49);
        reply_command(&peer, &mut crypto, &deactivate, 2, 0x80, &[]);
    });
    let mut interactive = rmcp
        .open_sol_interactive(SolInstance::new(1).unwrap())
        .unwrap();
    let started = std::time::Instant::now();
    assert!(matches!(
        interactive.send_input(b"?"),
        Err(SolError::Interrupted(ref stopped))
        if stopped.input_delivery_uncertain && stopped.remote_close_unconfirmed
            && stopped.confirmed_input == 0
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    server.join().unwrap();
}

#[test]
fn capture_reconnect_is_bounded_and_requires_a_new_handshake() {
    use crate::{app::sol::SolInstance, rmcp::SolError};
    let (state, peer, mut crypto) = pair_with_peer(Duration::from_millis(85), false);
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut rmcp =
        super::super::Rmcp::new(peer.local_addr().unwrap(), Duration::from_millis(85)).unwrap();
    rmcp.active_state = Some(crate::rmcp::internal::RmcpWithState::from_active(
        crate::rmcp::internal::Active::V2_0(state),
    ));
    let server = std::thread::spawn(move || {
        let mut wire = [0; 4096];
        let (n, from) = peer.recv_from(&mut wire).unwrap();
        let activation = crypto.read_payload(&mut wire[4..n]).unwrap();
        let mut answer = Vec::new();
        let request = &activation.payload;
        answer.extend([
            request[3],
            request[1] + 4,
            0,
            request[0],
            request[4],
            request[5],
            0,
        ]);
        answer[2] = Checksum::from_iter(answer[..2].iter().copied());
        answer.extend(activate_response(peer.local_addr().unwrap().port()));
        answer.push(Checksum::from_iter(answer[3..].iter().copied()));
        let packet = RmcpHeader::new_ipmi()
            .write(|buffer| {
                crypto.write_message(
                    &Message {
                        ty: PayloadType::IpmiMessage,
                        session_id: 0x12345678,
                        session_sequence_number: 1,
                        payload: answer,
                    },
                    buffer,
                )
            })
            .unwrap();
        peer.send_to(&packet, from).unwrap();
        let (n, from) = peer.recv_from(&mut wire).unwrap();
        let deactivate = crypto.read_payload(&mut wire[4..n]).unwrap();
        assert_eq!(deactivate.payload[5], 0x49);
        // Deliberately do not acknowledge deactivation.
        let mut pings = 0;
        while let Ok((n, addr)) = peer.recv_from(&mut wire) {
            if wire[..n].starts_with(&[6, 0, 0xff, 0x06]) {
                assert_ne!(addr, from); // fresh UDP socket, not the old session
                pings += 1;
                if pings == 2 {
                    break;
                }
            }
        }
        pings
    });
    let mut capture = rmcp.open_sol_capture(SolInstance::new(1).unwrap()).unwrap();
    assert!(matches!(
        capture.read(&mut [0; 4]),
        Err(SolError::Interrupted(_))
    ));
    assert!(matches!(
        capture.reconnect("root", b"local test password", 2),
        Err(SolError::Interrupted(_))
    ));
    assert_eq!(server.join().unwrap(), 2);
}

#[test]
fn reordered_and_oversized_authenticated_sol_interrupt_capture() {
    use crate::{
        app::sol::SolInstance,
        rmcp::{SolError, SolFrameError},
    };
    for reordered in [true, false] {
        let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(500));
        let server = std::thread::spawn(move || {
            let activation = read_secure(&peer, &mut crypto);
            reply_command(
                &peer,
                &mut crypto,
                &activation,
                1,
                0,
                &activate_response(peer.local_addr().unwrap().port()),
            );
            if reordered {
                reply_sol(&peer, &mut crypto, 2, &[1, 0, 0, 0, b'1']);
                let ack = read_secure(&peer, &mut crypto);
                assert_eq!(ack.payload, [0, 1, 1, 0]);
                reply_sol(&peer, &mut crypto, 3, &[3, 0, 0, 0, b'3']);
                let nack = read_secure(&peer, &mut crypto);
                assert_eq!(nack.payload, [0, 3, 0, 0x40]);
            } else {
                let mut data = vec![1, 0, 0, 0];
                data.extend(std::iter::repeat_n(b'0', 256));
                reply_sol(&peer, &mut crypto, 2, &data);
            }
            let deactivate = read_secure(&peer, &mut crypto);
            assert_eq!(deactivate.payload[5], 0x49);
            reply_command(&peer, &mut crypto, &deactivate, 4, 0, &[]);
        });
        let mut capture = rmcp.open_sol_capture(SolInstance::new(1).unwrap()).unwrap();
        let mut bytes = [0; 4];
        if reordered {
            assert_eq!(capture.read(&mut bytes).unwrap(), 1);
            assert_eq!(bytes[0], b'1');
        }
        assert!(matches!(
            capture.read(&mut bytes),
            Err(SolError::Interrupted(ref stopped))
                if matches!(
                    stopped.reason,
                    crate::rmcp::SolInterruptionReason::Receive(
                        RmcpIpmiReceiveError::Sol(
                            SolFrameError::OutputGap | SolFrameError::InvalidLength
                        )
                    )
                ) && !stopped.remote_close_unconfirmed
        ));
        capture.close().unwrap(); // already deactivated by interruption
        server.join().unwrap();
    }
}

#[test]
fn cancellation_during_activation_and_capture_closes_boundedly() {
    use crate::{
        app::sol::SolInstance,
        rmcp::{SolError, SolInterruptionReason},
    };
    let (mut rmcp, peer, _) = sol_fixture(Duration::from_millis(350));
    peer.set_read_timeout(Some(Duration::from_millis(120)))
        .unwrap();
    let token = rmcp.cancellation_token();
    token.cancel();
    assert!(matches!(
        rmcp.open_sol_capture(SolInstance::new(1).unwrap()),
        Err(SolError::Activation(crate::IpmiError::Connection(
            RmcpIpmiError::Send(RmcpIpmiSendError::Cancelled)
        )))
    ));
    assert!(peer.recv(&mut [0; 4096]).is_err()); // no activation or stray cleanup
    token.reset();

    let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(350));
    let token = rmcp.cancellation_token();
    let server = std::thread::spawn(move || {
        let activation = read_secure(&peer, &mut crypto);
        reply_command(
            &peer,
            &mut crypto,
            &activation,
            1,
            0,
            &activate_response(peer.local_addr().unwrap().port()),
        );
        let deactivate = read_secure(&peer, &mut crypto);
        assert_eq!(deactivate.payload[5], 0x49);
        reply_command(&peer, &mut crypto, &deactivate, 2, 0, &[]);
    });
    let mut capture = rmcp.open_sol_capture(SolInstance::new(1).unwrap()).unwrap();
    token.cancel();
    assert!(matches!(
        capture.read(&mut [0; 4]),
        Err(SolError::Interrupted(ref stopped))
            if matches!(stopped.reason,
                SolInterruptionReason::Receive(RmcpIpmiReceiveError::Cancelled))
                && !stopped.remote_close_unconfirmed
    ));
    capture.close().unwrap();
    server.join().unwrap();
}

#[test]
fn cancellation_after_activation_send_and_during_input_reports_uncertainty() {
    use crate::{
        app::sol::SolInstance,
        rmcp::{SolError, SolInterruptionReason},
    };
    for cancel_activation in [true, false] {
        let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(600));
        let token = rmcp.cancellation_token();
        let server = std::thread::spawn(move || {
            let activation = read_secure(&peer, &mut crypto);
            if cancel_activation {
                token.cancel(); // activation may have taken effect, but its ACK is lost
            } else {
                reply_command(
                    &peer,
                    &mut crypto,
                    &activation,
                    1,
                    0,
                    &activate_response(peer.local_addr().unwrap().port()),
                );
                let input = read_secure(&peer, &mut crypto);
                assert_eq!(input.payload, [1, 0, 0, 0, b'x']);
                token.cancel(); // sent input with no acknowledgment
            }
            let deactivate = read_secure(&peer, &mut crypto);
            assert_eq!(deactivate.payload[5], 0x49);
            reply_command(
                &peer,
                &mut crypto,
                &deactivate,
                if cancel_activation { 1 } else { 2 },
                0,
                &[],
            );
        });
        if cancel_activation {
            assert!(matches!(
                rmcp.open_sol_capture(SolInstance::new(1).unwrap()),
                Err(SolError::ActivationUncertain {
                    remote_close_unconfirmed: false,
                    ..
                })
            ));
        } else {
            let mut interactive = rmcp
                .open_sol_interactive(SolInstance::new(1).unwrap())
                .unwrap();
            assert!(matches!(
                interactive.send_input(b"x"),
                Err(SolError::Interrupted(ref stopped))
                    if matches!(
                        stopped.reason,
                        SolInterruptionReason::Receive(RmcpIpmiReceiveError::Cancelled)
                    ) && stopped.input_delivery_uncertain && !stopped.remote_close_unconfirmed
            ));
            interactive.close().unwrap();
        }
        server.join().unwrap();
    }
}

#[test]
fn activation_response_rejection_reports_remote_close_failure() {
    use crate::{app::sol::SolInstance, rmcp::SolError};
    let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(400));
    let server = std::thread::spawn(move || {
        let activation = read_secure(&peer, &mut crypto);
        let port = peer.local_addr().unwrap().port();
        let mut invalid = activate_response(port);
        invalid[4] = 0; // remote accepted activation but supplied an invalid limit
        reply_command(&peer, &mut crypto, &activation, 1, 0, &invalid);
        let deactivate = read_secure(&peer, &mut crypto);
        assert_eq!(deactivate.payload[5], 0x49);
        reply_command(&peer, &mut crypto, &deactivate, 2, 0x80, &[]);
    });
    assert!(matches!(
        rmcp.open_sol_capture(SolInstance::new(1).unwrap()),
        Err(SolError::ActivationUncertain {
            remote_close_unconfirmed: true,
            ..
        })
    ));
    server.join().unwrap();
}

#[test]
fn activation_completion_failure_is_typed_and_does_not_deactivate_other_sessions() {
    use crate::{
        app::sol::{SolInstance, SolPayloadError},
        rmcp::SolError,
    };
    let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(300));
    let server = std::thread::spawn(move || {
        let activation = read_secure(&peer, &mut crypto);
        reply_command(&peer, &mut crypto, &activation, 1, 0x80, &[]);
        peer.set_read_timeout(Some(Duration::from_millis(120)))
            .unwrap();
        assert!(peer.recv(&mut [0; 4096]).is_err());
    });
    assert!(matches!(
        rmcp.open_sol_capture(SolInstance::new(1).unwrap()),
        Err(SolError::Activation(crate::IpmiError::Command {
            error: SolPayloadError::AlreadyActive,
            ..
        }))
    ));
    server.join().unwrap();
}

#[test]
fn interactive_serial_controls_are_explicit_and_acknowledged() {
    use crate::app::sol::SolInstance;
    let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(500));
    let server = std::thread::spawn(move || {
        let activation = read_secure(&peer, &mut crypto);
        reply_command(
            &peer,
            &mut crypto,
            &activation,
            1,
            0,
            &activate_response(peer.local_addr().unwrap().port()),
        );
        for (seq, flag) in [(1, 0x10), (2, 0x02), (3, 0x01)] {
            let control = read_secure(&peer, &mut crypto);
            assert_eq!(control.payload, [seq, 0, 0, flag]);
            reply_sol(&peer, &mut crypto, 1 + u32::from(seq), &[0, seq, 0, 0]);
        }
        let deactivate = read_secure(&peer, &mut crypto);
        reply_command(&peer, &mut crypto, &deactivate, 5, 0, &[]);
    });
    let mut interactive = rmcp
        .open_sol_interactive(SolInstance::new(1).unwrap())
        .unwrap();
    interactive.send_break().unwrap();
    interactive.flush_inbound().unwrap();
    interactive.flush_outbound().unwrap();
    assert!(matches!(
        interactive.send_input(&vec![0; 4097]),
        Err(crate::rmcp::SolError::InvalidOperation)
    ));
    interactive.close().unwrap();
    server.join().unwrap();
}

#[test]
fn partial_nack_retries_only_suffix_and_invalid_ack_interrupts() {
    use crate::{
        app::sol::SolInstance,
        rmcp::{SolError, SolFrameError},
    };
    for invalid_ack in [false, true] {
        let (mut rmcp, peer, mut crypto) = sol_fixture(Duration::from_millis(550));
        let server = std::thread::spawn(move || {
            let activation = read_secure(&peer, &mut crypto);
            reply_command(
                &peer,
                &mut crypto,
                &activation,
                1,
                0,
                &activate_response(peer.local_addr().unwrap().port()),
            );
            let input = read_secure(&peer, &mut crypto);
            assert_eq!(input.payload, [1, 0, 0, 0, b'a', b'b']);
            if invalid_ack {
                reply_sol(&peer, &mut crypto, 2, &[0, 1, 3, 0]);
            } else {
                reply_sol(&peer, &mut crypto, 2, &[0, 1, 1, 0x40]);
                let suffix = read_secure(&peer, &mut crypto);
                assert_eq!(suffix.payload, [2, 0, 0, 0, b'b']);
                reply_sol(&peer, &mut crypto, 3, &[0, 2, 1, 0]);
            }
            let deactivate = read_secure(&peer, &mut crypto);
            assert_eq!(deactivate.payload[5], 0x49);
            reply_command(&peer, &mut crypto, &deactivate, 4, 0, &[]);
        });
        let mut interactive = rmcp
            .open_sol_interactive(SolInstance::new(1).unwrap())
            .unwrap();
        if invalid_ack {
            assert!(matches!(
                interactive.send_input(b"ab"),
                Err(SolError::Interrupted(ref stopped))
                    if matches!(
                        stopped.reason,
                        crate::rmcp::SolInterruptionReason::Receive(
                            RmcpIpmiReceiveError::Sol(SolFrameError::InvalidAck)
                        )
                    ) && stopped.input_delivery_uncertain
            ));
        } else {
            assert_eq!(interactive.send_input(b"ab").unwrap(), 2);
        }
        interactive.close().unwrap();
        server.join().unwrap();
    }
}

fn send_to_unencrypted(peer: &UdpSocket, addr: std::net::SocketAddr, message: Message) {
    let wire = RmcpHeader::new_ipmi()
        .write(|buffer| CryptoState::write_unencrypted(&message, buffer))
        .unwrap();
    peer.send_to(&wire, addr).unwrap();
}

fn send_to_secure(
    peer: &UdpSocket,
    addr: std::net::SocketAddr,
    crypto: &mut CryptoState,
    message: Message,
) {
    let wire = RmcpHeader::new_ipmi()
        .write(|buffer| crypto.write_message(&message, buffer))
        .unwrap();
    peer.send_to(&wire, addr).unwrap();
}

fn read_from_secure(peer: &UdpSocket, crypto: &mut CryptoState) -> (Message, std::net::SocketAddr) {
    let mut wire = [0; 4096];
    let (n, from) = peer.recv_from(&mut wire).unwrap();
    assert_eq!(wire[5] & 0xc0, 0xc0);
    (crypto.read_payload(&mut wire[4..n]).unwrap(), from)
}

fn reply_command_to(
    peer: &UdpSocket,
    from: std::net::SocketAddr,
    crypto: &mut CryptoState,
    request: &Message,
    console_id: u32,
    session_sequence_number: u32,
    body: &[u8],
) {
    let req = &request.payload;
    let mut payload = vec![req[3], req[1] + 4, 0, req[0], req[4], req[5], 0];
    payload[2] = Checksum::from_iter(payload[..2].iter().copied());
    payload.extend(body);
    payload.push(Checksum::from_iter(payload[3..].iter().copied()));
    send_to_secure(
        peer,
        from,
        crypto,
        Message {
            ty: PayloadType::IpmiMessage,
            session_id: console_id,
            session_sequence_number,
            payload,
        },
    );
}

fn serve_new_handshake(peer: &UdpSocket) -> (CryptoState, std::net::SocketAddr, u32) {
    use crate::app::auth::AuthType;
    use crate::rmcp::{ASFMessage, ASFMessageType, SupportedEntities, SupportedInteractions};
    let mut wire = [0; 4096];
    let (n, from) = peer.recv_from(&mut wire).unwrap();
    assert_eq!(&wire[..4], &[6, 0, 0xff, 6]);
    assert!(n >= 12);
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
    let pong_wire = RmcpHeader::new_asf(0xff).write_infallible(|buffer| pong.write_data(buffer));
    peer.send_to(&pong_wire, from).unwrap();

    let (n, sender) = peer.recv_from(&mut wire).unwrap();
    assert_eq!(from, sender);
    let req = v1_5::Message::from_data(None, &wire[4..n]).unwrap();
    assert_eq!(req.payload[5], 0x38);
    let mut response = vec![
        0x81,
        0x1c,
        0,
        0x20,
        req.payload[4],
        0x38,
        0,
        0x0e,
        0x81,
        0,
        2,
        0,
        0,
        0,
        0,
    ];
    response[2] = Checksum::from_iter(response[..2].iter().copied());
    response.push(Checksum::from_iter(response[3..].iter().copied()));
    let v15 = v1_5::Message {
        auth_type: AuthType::None,
        session_sequence_number: 0,
        session_id: 0,
        payload: response,
    };
    let v15_wire = RmcpHeader::new_ipmi()
        .write(|buffer| v15.write_data(None, buffer))
        .unwrap();
    peer.send_to(&v15_wire, from).unwrap();

    let (n, sender) = peer.recv_from(&mut wire).unwrap();
    assert_eq!(from, sender);
    let open = CryptoState::default()
        .read_payload(&mut wire[4..n])
        .unwrap();
    assert_eq!(open.ty, PayloadType::RmcpPlusOpenSessionRequest);
    let console_id = u32::from_le_bytes(open.payload[4..8].try_into().unwrap());
    let managed_id = NonZeroU32::new(0x87654322).unwrap();
    send_to_unencrypted(
        peer,
        from,
        Message {
            ty: PayloadType::RmcpPlusOpenSessionResponse,
            session_id: 0,
            session_sequence_number: 0,
            payload: open_session_response(&open, managed_id.get()),
        },
    );

    let (n, sender) = peer.recv_from(&mut wire).unwrap();
    assert_eq!(from, sender);
    let rm1_wire = CryptoState::default()
        .read_payload(&mut wire[4..n])
        .unwrap();
    assert_eq!(rm1_wire.ty, PayloadType::RakpMessage1);
    let console_random: [u8; 16] = rm1_wire.payload[8..24].try_into().unwrap();
    let privilege = rm1_wire.payload[24];
    let username_len = rm1_wire.payload[27];
    let username = Username::new(std::str::from_utf8(&rm1_wire.payload[28..]).unwrap()).unwrap();
    let password = b"local test password";
    let managed_random = [0x66; 16];
    let guid = [0x77; 16];
    let kex = Sha1Hmac::new(password)
        .feed(&console_id.to_le_bytes())
        .feed(&managed_id.get().to_le_bytes())
        .feed(&console_random)
        .feed(&managed_random)
        .feed(&guid)
        .feed(&[privilege, username_len])
        .feed(&username)
        .finalize();
    let mut rm2 = vec![rm1_wire.payload[0], 0, 0, 0];
    rm2.extend(console_id.to_le_bytes());
    rm2.extend(managed_random);
    rm2.extend(guid);
    rm2.extend(kex);
    send_to_unencrypted(
        peer,
        from,
        Message {
            ty: PayloadType::RakpMessage2,
            session_id: 0,
            session_sequence_number: 0,
            payload: rm2,
        },
    );

    let (n, sender) = peer.recv_from(&mut wire).unwrap();
    assert_eq!(from, sender);
    let rm3 = CryptoState::default()
        .read_payload(&mut wire[4..n])
        .unwrap();
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
    let mut rm4 = vec![rm3.payload[0], 0, 0, 0];
    rm4.extend(console_id.to_le_bytes());
    rm4.extend_from_slice(&integrity[..12]);
    send_to_unencrypted(
        peer,
        from,
        Message {
            ty: PayloadType::RakpMessage4,
            session_id: 0,
            session_sequence_number: 0,
            payload: rm4,
        },
    );
    let osr =
        OpenSessionResponse::from_data(&open_session_response(&open, managed_id.get())).unwrap();
    let rm1 = RakpMessage1 {
        message_tag: rm1_wire.payload[0],
        managed_system_session_id: managed_id,
        remote_console_random_number: console_random,
        requested_maximum_privilege_level: PrivilegeLevel::Administrator,
        username: &username,
    };
    let rm2 = RakpMessage2 {
        message_tag: rm1.message_tag,
        remote_console_session_id: NonZeroU32::new(console_id).unwrap(),
        managed_system_random_number: managed_random,
        managed_system_guid: guid,
        key_exchange_auth_code: &kex,
    };
    let mut crypto = CryptoState::new(None, password);
    assert!(crypto
        .calculate_rakp3_data(&osr, &rm1, &rm2)
        .unwrap()
        .is_some());
    (crypto, from, console_id)
}

#[test]
fn successful_capture_reconnect_uses_fresh_authenticated_identity_and_surfaces_gap() {
    use crate::app::sol::SolInstance;
    let (state, peer, mut crypto) = pair_with_peer(Duration::from_millis(650), false);
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut rmcp =
        super::super::Rmcp::new(peer.local_addr().unwrap(), Duration::from_millis(650)).unwrap();
    rmcp.active_state = Some(crate::rmcp::internal::RmcpWithState::from_active(
        crate::rmcp::internal::Active::V2_0(state),
    ));
    let server = std::thread::spawn(move || {
        let (activation, old_addr) = read_from_secure(&peer, &mut crypto);
        reply_command_to(
            &peer,
            old_addr,
            &mut crypto,
            &activation,
            0x12345678,
            1,
            &activate_response(peer.local_addr().unwrap().port()),
        );
        let (deactivate, addr) = read_from_secure(&peer, &mut crypto);
        assert_eq!(addr, old_addr);
        assert_eq!(deactivate.payload[5], 0x49);
        reply_command_to(
            &peer,
            old_addr,
            &mut crypto,
            &deactivate,
            0x12345678,
            2,
            &[],
        );

        let (mut new_crypto, from, console_id) = serve_new_handshake(&peer);
        assert_ne!(old_addr, from);
        let (new_activation, addr) = read_from_secure(&peer, &mut new_crypto);
        assert_eq!(addr, from);
        assert_eq!(new_activation.session_id, 0x87654322);
        reply_command_to(
            &peer,
            from,
            &mut new_crypto,
            &new_activation,
            console_id,
            1,
            &activate_response(peer.local_addr().unwrap().port()),
        );
        send_to_secure(
            &peer,
            from,
            &mut new_crypto,
            Message {
                ty: PayloadType::Sol,
                session_id: console_id,
                session_sequence_number: 2,
                payload: vec![1, 0, 0, 0, b'R'],
            },
        );
        let (ack, addr) = read_from_secure(&peer, &mut new_crypto);
        assert_eq!(addr, from);
        assert_eq!(ack.payload, [0, 1, 1, 0]);
        let (new_deactivate, addr) = read_from_secure(&peer, &mut new_crypto);
        assert_eq!(addr, from);
        reply_command_to(
            &peer,
            from,
            &mut new_crypto,
            &new_deactivate,
            console_id,
            3,
            &[],
        );
    });
    let mut capture = rmcp.open_sol_capture(SolInstance::new(1).unwrap()).unwrap();
    assert!(matches!(
        capture.read_until(
            &mut [0; 4],
            std::time::Instant::now() + Duration::from_millis(35)
        ),
        Err(crate::rmcp::SolError::Interrupted(_))
    ));
    let gap = capture
        .reconnect("root", b"local test password", 2)
        .unwrap();
    assert_eq!(gap.attempts, 1);
    assert!(gap.output_missing);
    assert!(!gap.previous_remote_close_unconfirmed);
    let mut bytes = [0; 4];
    assert_eq!(capture.read(&mut bytes).unwrap(), 1);
    assert_eq!(bytes[0], b'R');
    capture.close().unwrap();
    server.join().unwrap();
}
