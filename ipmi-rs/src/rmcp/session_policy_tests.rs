use std::{
    net::{SocketAddr, UdpSocket},
    thread,
    time::Duration,
};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

use super::{
    checksum::Checksum, v1_5, ActivationError, CipherSuite, CipherSuiteListError,
    CipherSuitePolicy, IpmiConnection, OpenSessionResponseErrorStatusCode,
    ParseSessionResponseError, PrivilegeLevel, Rmcp, RmcpHeader, SessionConfig,
    V2_0ActivationError, ValidateSessionResponseError,
};
use crate::connection::{LogicalUnit, Message, Request, RequestTargetAddress};

const PASSWORD: &[u8] = b"test-password-not-kg";
const KG: &[u8] = b"distinct-test-kg-key";
const USERNAME: &str = "ALICE";
const BMC_ID: [u8; 4] = 0x55667788u32.to_le_bytes();
const BMC_RANDOM: [u8; 16] = [0x33; 16];
const BMC_GUID: [u8; 16] = [0x44; 16];
const THREE: &[u8] = &[0xc0, 3, 1, 1, 1];
const SEVENTEEN: &[u8] = &[0xc0, 17, 3, 4, 1];

#[derive(Clone, Copy, PartialEq)]
enum OpenReply {
    Valid,
    WrongPrivilege,
    WrongAlgorithm,
    WrongSuite,
    RejectSuite,
}

fn mac(suite: CipherSuite, key: &[u8], input: &[u8]) -> Vec<u8> {
    match suite {
        CipherSuite::Id3 => {
            let mut hmac = Hmac::<Sha1>::new_from_slice(key).unwrap();
            hmac.update(input);
            hmac.finalize().into_bytes().to_vec()
        }
        CipherSuite::Id17 => {
            let mut hmac = Hmac::<Sha256>::new_from_slice(key).unwrap();
            hmac.update(input);
            hmac.finalize().into_bytes().to_vec()
        }
        _ => unreachable!(),
    }
}

fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut data = [0u8; 1024];
    let (len, peer) = socket.recv_from(&mut data).unwrap();
    (data[..len].to_vec(), peer)
}

fn send_ipmi(socket: &UdpSocket, peer: SocketAddr, request: &[u8], body: &[u8], cc: u8) {
    let request = v1_5::Message::from_data(None, &request[4..]).unwrap();
    let q = &request.payload;
    let mut payload = vec![q[3], q[1] | 0x04, 0, q[0], q[4], q[5], cc];
    payload[2] = Checksum::from_iter(payload[..2].iter().copied());
    payload.extend_from_slice(body);
    payload.push(Checksum::from_iter(payload[3..].iter().copied()));
    let reply = v1_5::Message {
        auth_type: crate::app::auth::AuthType::None,
        session_sequence_number: 0,
        session_id: 0,
        payload,
    };
    let wire = RmcpHeader::new_ipmi()
        .write(|buffer| reply.write_data(None, buffer))
        .unwrap();
    socket.send_to(&wire, peer).unwrap();
}

fn send_handshake(socket: &UdpSocket, peer: SocketAddr, ty: u8, payload: &[u8]) {
    let mut wire = vec![6, 0, 0xff, 7, 6, ty];
    wire.extend_from_slice(&[0; 8]);
    wire.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    wire.extend_from_slice(payload);
    socket.send_to(&wire, peer).unwrap();
}

fn ensure_no_fallback(socket: &UdpSocket) {
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert!(
        socket.recv_from(&mut [0u8; 1024]).is_err(),
        "unexpected handshake continuation or fallback"
    );
}

fn mock_bmc(
    socket: UdpSocket,
    records: Option<Vec<u8>>,
    probe_error: bool,
    privilege: PrivilegeLevel,
    suite: Option<CipherSuite>,
    reply: OpenReply,
) {
    let (ping, peer) = recv(&socket);
    assert_eq!(&ping[..4], &[6, 0, 0xff, 6]);
    let mut pong = vec![6, 0, 0xff, 6, 0, 0, 0x11, 0xbe, 0x40, ping[9], 0, 16];
    pong.extend_from_slice(&[0; 8]);
    pong.push(0x80);
    pong.extend_from_slice(&[0; 7]);
    socket.send_to(&pong, peer).unwrap();

    let (caps, peer) = recv(&socket);
    let req = v1_5::Message::from_data(None, &caps[4..]).unwrap();
    assert_eq!(req.payload[5], 0x38);
    assert_eq!(&req.payload[6..8], &[0x8e, u8::from(privilege)]);
    send_ipmi(&socket, peer, &caps, &[0x0e, 0x80, 0, 0x02, 0, 0, 0, 0], 0);

    if let Some(records) = records {
        for (index, page) in records.chunks(16).enumerate() {
            let (probe, peer) = recv(&socket);
            let req = v1_5::Message::from_data(None, &probe[4..]).unwrap();
            assert_eq!(req.payload[5], 0x54);
            assert_eq!(&req.payload[6..9], &[0x0e, 0, 0x80 | index as u8]);
            if probe_error {
                send_ipmi(&socket, peer, &probe, &[], 0xc1);
                ensure_no_fallback(&socket);
                return;
            }
            let mut response = vec![1];
            response.extend_from_slice(page);
            send_ipmi(&socket, peer, &probe, &response, 0);
        }
        if records.is_empty() || records.len() % 16 == 0 {
            let (probe, peer) = recv(&socket);
            let req = v1_5::Message::from_data(None, &probe[4..]).unwrap();
            assert_eq!(
                &req.payload[6..9],
                &[0x0e, 0, 0x80 | (records.len() / 16) as u8]
            );
            send_ipmi(&socket, peer, &probe, &[1], 0);
        }
    }
    let Some(suite) = suite else {
        ensure_no_fallback(&socket);
        return;
    };
    let (open, peer) = recv(&socket);
    assert_eq!(&open[..6], &[6, 0, 0xff, 7, 6, 0x10]);
    assert_eq!(open[17], u8::from(privilege));
    let [auth, integrity, confidentiality] = suite.into_suite();
    assert_eq!(
        [open[28], open[36], open[44]],
        [auth, integrity, confidentiality]
    );
    if reply == OpenReply::RejectSuite {
        send_handshake(&socket, peer, 0x11, &[open[16], 0x11]);
        ensure_no_fallback(&socket);
        return;
    }
    let console_id: [u8; 4] = open[20..24].try_into().unwrap();
    let mut open_response = vec![open[16], 0, u8::from(privilege), 0];
    open_response.extend_from_slice(&console_id);
    open_response.extend_from_slice(&BMC_ID);
    open_response.extend_from_slice(&open[24..48]);
    if reply == OpenReply::WrongPrivilege {
        open_response[2] = u8::from(PrivilegeLevel::Administrator);
    } else if reply == OpenReply::WrongAlgorithm {
        open_response[16] = 0;
    } else if reply == OpenReply::WrongSuite {
        let other = if suite == CipherSuite::Id17 {
            CipherSuite::Id3
        } else {
            CipherSuite::Id17
        };
        let algorithms = other.into_suite();
        for (index, algorithm) in algorithms.into_iter().enumerate() {
            open_response[16 + index * 8] = algorithm;
        }
    }
    send_handshake(&socket, peer, 0x11, &open_response);
    if reply != OpenReply::Valid {
        ensure_no_fallback(&socket);
        return;
    }

    let (rakp1, peer) = recv(&socket);
    assert_eq!(rakp1[5], 0x12);
    let rakp1 = &rakp1[16..];
    assert_eq!(rakp1[24], u8::from(privilege));
    assert_eq!(&rakp1[28..], USERNAME.as_bytes());
    let console_random = &rakp1[8..24];
    let role = &rakp1[24..25];
    let user_len_and_name = &rakp1[27..];
    let mut key_exchange_input = Vec::new();
    key_exchange_input.extend_from_slice(&console_id);
    key_exchange_input.extend_from_slice(&BMC_ID);
    key_exchange_input.extend_from_slice(console_random);
    key_exchange_input.extend_from_slice(&BMC_RANDOM);
    key_exchange_input.extend_from_slice(&BMC_GUID);
    key_exchange_input.extend_from_slice(role);
    key_exchange_input.extend_from_slice(user_len_and_name);
    let mut rakp2 = vec![rakp1[0], 0, 0, 0];
    rakp2.extend_from_slice(&console_id);
    rakp2.extend_from_slice(&BMC_RANDOM);
    rakp2.extend_from_slice(&BMC_GUID);
    rakp2.extend_from_slice(&mac(suite, PASSWORD, &key_exchange_input));
    send_handshake(&socket, peer, 0x13, &rakp2);

    let (rakp3, peer) = recv(&socket);
    assert_eq!(rakp3[5], 0x14);
    let rakp3 = &rakp3[16..];
    assert_eq!(&rakp3[4..8], &BMC_ID);
    let mut rakp3_input = Vec::new();
    rakp3_input.extend_from_slice(&BMC_RANDOM);
    rakp3_input.extend_from_slice(&console_id);
    rakp3_input.extend_from_slice(role);
    rakp3_input.extend_from_slice(user_len_and_name);
    assert_eq!(&rakp3[8..], mac(suite, PASSWORD, &rakp3_input));

    let mut sik_input = Vec::new();
    sik_input.extend_from_slice(console_random);
    sik_input.extend_from_slice(&BMC_RANDOM);
    sik_input.extend_from_slice(role);
    sik_input.extend_from_slice(user_len_and_name);
    let sik = mac(suite, KG, &sik_input);
    let mut rakp4_input = Vec::new();
    rakp4_input.extend_from_slice(console_random);
    rakp4_input.extend_from_slice(&BMC_ID);
    rakp4_input.extend_from_slice(&BMC_GUID);
    let mut rakp4 = vec![rakp3[0], 0, 0, 0];
    rakp4.extend_from_slice(&console_id);
    rakp4.extend_from_slice(
        &mac(suite, &sik, &rakp4_input)[..if suite == CipherSuite::Id3 { 12 } else { 16 }],
    );
    send_handshake(&socket, peer, 0x15, &rakp4);

    let (authenticated, _) = recv(&socket);
    assert_eq!(&authenticated[..6], &[6, 0, 0xff, 7, 6, 0xc0]);
    assert_eq!(&authenticated[6..10], &BMC_ID);
    let k1 = mac(suite, &sik, &[1; 20]);
    let tag_len = if suite == CipherSuite::Id3 { 12 } else { 16 };
    let tag_start = authenticated.len() - tag_len;
    assert_eq!(
        &authenticated[tag_start..],
        &mac(suite, &k1, &authenticated[4..tag_start])[..tag_len]
    );
}

fn exercise(
    policy: CipherSuitePolicy,
    records: Option<Vec<u8>>,
    probe_error: bool,
    privilege: PrivilegeLevel,
    suite: Option<CipherSuite>,
    reply: OpenReply,
) -> Result<(), ActivationError> {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    let server =
        thread::spawn(move || mock_bmc(socket, records, probe_error, privilege, suite, reply));
    let mut rmcp = Rmcp::new(address, Duration::from_secs(2)).unwrap();
    let result = rmcp.activate_with_session_config(
        SessionConfig::new(Some(USERNAME), Some(PASSWORD))
            .with_kg(KG)
            .with_privilege(privilege)
            .with_cipher_suite_policy(policy),
    );
    if result.is_ok() {
        assert!(rmcp.is_rmcp_plus());
        let mut request = Request::new(
            Message::new_raw(6, 1, vec![0xa5]),
            RequestTargetAddress::Bmc(LogicalUnit::Zero),
        );
        rmcp.send(&mut request).unwrap();
    } else {
        assert!(!rmcp.is_active());
    }
    server.join().unwrap();
    result
}

#[test]
fn best_available_prefers_17_then_3_with_distinct_kg_and_non_admin_roles() {
    let records = [THREE, SEVENTEEN, THREE, SEVENTEEN].concat();
    assert_eq!(records.len(), 20);
    assert!(exercise(
        CipherSuitePolicy::BestAvailable,
        Some(records),
        false,
        PrivilegeLevel::User,
        Some(CipherSuite::Id17),
        OpenReply::Valid,
    )
    .is_ok());
    assert!(exercise(
        CipherSuitePolicy::BestAvailable,
        Some(THREE.to_vec()),
        false,
        PrivilegeLevel::Operator,
        Some(CipherSuite::Id3),
        OpenReply::Valid,
    )
    .is_ok());
}

#[test]
fn exact_suite_and_privilege_do_not_query_or_downgrade() {
    assert!(exercise(
        CipherSuitePolicy::Exact(CipherSuite::Id3),
        None,
        false,
        PrivilegeLevel::User,
        Some(CipherSuite::Id3),
        OpenReply::Valid,
    )
    .is_ok());
    let mut rmcp = Rmcp::new("127.0.0.1:1", Duration::from_secs(1)).unwrap();
    assert!(matches!(
        rmcp.activate_with_session_config(
            SessionConfig::new(Some(USERNAME), Some(PASSWORD))
                .with_cipher_suite_policy(CipherSuitePolicy::Exact(CipherSuite::Id16))
        ),
        Err(ActivationError::UnsupportedCipherSuite(CipherSuite::Id16))
    ));
}

#[test]
fn best_available_fails_closed_on_unavailable_or_invalid_discovery() {
    for (records, probe_error, expected) in [
        (SEVENTEEN.to_vec(), true, "probe"),
        (vec![0xc0, 1, 1, 0, 0], false, "unsupported"),
        (vec![0xc0, 17, 1, 4, 1], false, "mismatch"),
        (vec![0xc0, 3, 1], false, "truncated"),
    ] {
        let result = exercise(
            CipherSuitePolicy::BestAvailable,
            Some(records),
            probe_error,
            PrivilegeLevel::User,
            None,
            OpenReply::Valid,
        );
        assert!(
            match expected {
                "probe" => matches!(result, Err(ActivationError::GetChannelCipherSuites(_))),
                "unsupported" => matches!(result, Err(ActivationError::NoSupportedCipherSuite)),
                "mismatch" => matches!(
                    result,
                    Err(ActivationError::InvalidCipherSuiteList(
                        CipherSuiteListError::MismatchedAlgorithms(CipherSuite::Id17)
                    ))
                ),
                _ => matches!(
                    result,
                    Err(ActivationError::InvalidCipherSuiteList(
                        CipherSuiteListError::IncompleteRecord
                    ))
                ),
            },
            "unexpected activation result: {result:?}"
        );
    }
}

#[test]
fn peer_privilege_and_algorithm_substitution_rejected_before_rakp() {
    for reply in [
        OpenReply::WrongPrivilege,
        OpenReply::WrongAlgorithm,
        OpenReply::WrongSuite,
    ] {
        let result = exercise(
            CipherSuitePolicy::BestAvailable,
            Some([THREE, SEVENTEEN].concat()),
            false,
            PrivilegeLevel::User,
            Some(CipherSuite::Id17),
            reply,
        );
        assert!(
            matches!(
                (reply, result),
                (
                    OpenReply::WrongPrivilege,
                    Err(ActivationError::V2_0(
                        V2_0ActivationError::OpenSessionResponseValidate(
                            ValidateSessionResponseError::PrivilegeLevelMismatch
                        )
                    ))
                ) | (
                    OpenReply::WrongAlgorithm | OpenReply::WrongSuite,
                    Err(ActivationError::V2_0(
                        V2_0ActivationError::OpenSessionResponseValidate(
                            ValidateSessionResponseError::NegotiatedCipherSuiteMismatch { .. }
                        )
                    ))
                )
            ),
            "peer substitution must be rejected"
        );
    }
}

#[test]
fn rejected_preferred_suite_never_retries_suite_three() {
    let result = exercise(
        CipherSuitePolicy::BestAvailable,
        Some([THREE, SEVENTEEN].concat()),
        false,
        PrivilegeLevel::Operator,
        Some(CipherSuite::Id17),
        OpenReply::RejectSuite,
    );
    assert!(matches!(
        result,
        Err(ActivationError::V2_0(
            V2_0ActivationError::OpenSessionResponseParse(
                ParseSessionResponseError::HaveErrorCode(Ok(
                    OpenSessionResponseErrorStatusCode::NoMatchingCipherSuite
                ))
            )
        ))
    ));
}

#[test]
fn session_config_debug_redacts_both_secrets() {
    let config = SessionConfig::new(Some(USERNAME), Some(PASSWORD)).with_kg(KG);
    let debug = format!("{config:?}");
    assert!(!debug.contains(std::str::from_utf8(PASSWORD).unwrap()));
    assert!(!debug.contains(std::str::from_utf8(KG).unwrap()));
    assert!(debug.contains("<redacted>"));
}
