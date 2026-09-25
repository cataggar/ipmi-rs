use super::*;
use crate::app::auth::AuthType;
use std::{net::UdpSocket, thread, time::Instant};

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
