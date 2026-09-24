use super::*;
use crate::{
    connection::{
        IpmiConnection, LogicalUnit, Message as IpmiMessage, NetFn, RequestTargetAddress,
    },
    rmcp::{checksum::Checksum, socket::TransportPolicy, RmcpHeader},
};
use std::time::Duration;

fn pair(timeout: Duration) -> (State, UdpSocket) {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.connect(peer.local_addr().unwrap()).unwrap();
    peer.connect(client.local_addr().unwrap()).unwrap();
    let mut state = State::new(client, TransportPolicy::new(timeout), None);
    state.session_id = NonZeroU32::new(0x1234);
    state.activated = true;
    (state, peer)
}

fn request() -> Request {
    Request::new(
        IpmiMessage::new_request(NetFn::Chassis, 2, vec![1]),
        RequestTargetAddress::Bmc(LogicalUnit::Zero),
    )
}

fn reply(peer: &UdpSocket, session_sequence_number: u32, ipmb_sequence: u8) {
    let mut payload = vec![0x81, 0x04, 0, 0x20, ipmb_sequence << 2, 2, 0];
    payload[2] = Checksum::from_iter(payload[..2].iter().copied());
    payload.push(Checksum::from_iter(payload[3..].iter().copied()));
    let message = Message {
        auth_type: AuthType::None,
        session_sequence_number,
        session_id: 0x1234,
        payload,
    };
    let wire = RmcpHeader::new_ipmi()
        .write(|buffer| message.write_data(None, buffer))
        .unwrap();
    peer.send(&wire).unwrap();
}

#[test]
fn late_reply_is_drained_without_poisoning_following_transactions() {
    let (mut state, peer) = pair(Duration::from_millis(70));
    let mut req = request();
    let mut received = [0; 4096];
    state.send(&mut req).unwrap();
    peer.recv(&mut received).unwrap();
    assert!(matches!(state.recv(), Err(RmcpIpmiReceiveError::Timeout)));

    state.send(&mut req).unwrap();
    peer.recv(&mut received).unwrap();
    reply(&peer, 10, 0);
    reply(&peer, 9, 1);
    assert_eq!(state.recv().unwrap().seq(), 1);

    state.send(&mut req).unwrap();
    peer.recv(&mut received).unwrap();
    reply(&peer, 10, 0);
    reply(&peer, 9, 1);
    reply(&peer, 11, 2);
    assert_eq!(state.recv().unwrap().seq(), 2);
}

#[test]
fn unrelated_reply_flood_cannot_accept_stale_or_block_indefinitely() {
    let (mut state, peer) = pair(Duration::from_millis(350));
    let mut req = request();
    let mut received = [0; 4096];
    state.send(&mut req).unwrap();
    peer.recv(&mut received).unwrap();
    for sequence in 1..=crate::rmcp::socket::MAX_UNRELATED as u32 {
        reply(&peer, sequence, 63);
    }
    reply(&peer, 33, 0);
    assert!(matches!(
        state.recv(),
        Err(RmcpIpmiReceiveError::TooManyUnrelatedPackets)
    ));
    assert!(state.ipmb_state.pending.is_none());

    state.send(&mut req).unwrap();
    peer.recv(&mut received).unwrap();
    reply(&peer, 34, 1);
    assert_eq!(state.recv().unwrap().seq(), 1);
}

#[test]
fn unmatched_only_reply_reports_mismatch_after_deadline() {
    let (mut state, peer) = pair(Duration::from_millis(65));
    let mut req = request();
    state.send(&mut req).unwrap();
    let mut received = [0; 4096];
    peer.recv(&mut received).unwrap();
    reply(&peer, 1, 63);
    let start = Instant::now();
    assert!(matches!(
        state.recv(),
        Err(RmcpIpmiReceiveError::IpmbResponseMismatch)
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(state.ipmb_state.pending.is_none());

    state.send(&mut req).unwrap();
    peer.recv(&mut received).unwrap();
    reply(&peer, 2, 1);
    assert_eq!(state.recv().unwrap().seq(), 1);
}
