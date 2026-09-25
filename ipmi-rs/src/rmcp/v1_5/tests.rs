use super::*;
use crate::{
    connection::{
        Address, Channel, IpmbTarget, IpmiConnection, LogicalUnit, Message as IpmiMessage, NetFn,
        RequestTargetAddress,
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
    reply_packet(peer, session_sequence_number, payload);
}

fn reply_packet(peer: &UdpSocket, session_sequence_number: u32, payload: Vec<u8>) {
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

fn ipmb_reply(
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

fn target() -> Request {
    Request::new(
        IpmiMessage::new_request(NetFn::Chassis, 2, vec![1]),
        RequestTargetAddress::Bridged {
            target: IpmbTarget::new(Address(0x52), Channel::Primary, LogicalUnit::One),
            transit: None,
        },
    )
}

#[test]
fn bridged_send_ack_get_message_then_target_reply() {
    let (mut state, peer) = pair(Duration::from_millis(250));
    let mut req = target();
    let mut received = [0; 4096];
    state.send(&mut req).unwrap();
    let len = peer.recv(&mut received).unwrap();
    let outgoing = Message::from_data(None, &received[4..len]).unwrap();
    assert_eq!(
        (
            outgoing.payload[5],
            outgoing.payload[6],
            outgoing.payload[7]
        ),
        (0x34, 0x40, 0x52)
    );
    let ack = ipmb_reply(0x81, 0x20, 0, 7, 0, 0x34, &[0]);
    reply_packet(&peer, 1, ack);
    let final_reply = ipmb_reply(0x81, 0x52, 1, 1, 1, 2, &[0, 0xa5]);
    let peer_thread = std::thread::spawn(move || {
        let len = peer.recv(&mut received).unwrap();
        let flags = Message::from_data(None, &received[4..len]).unwrap();
        assert_eq!((flags.payload[5], flags.payload[4] >> 2), (0x31, 2));
        reply_packet(&peer, 2, ipmb_reply(0x81, 0x20, 2, 7, 0, 0x31, &[0, 1]));
        let len = peer.recv(&mut received).unwrap();
        let get = Message::from_data(None, &received[4..len]).unwrap();
        assert_eq!((get.payload[5], get.payload[4] >> 2), (0x33, 3));
        let mut body = vec![0, 0]; // Get Message completion, primary channel
        body.extend_from_slice(&final_reply[1..]);
        reply_packet(&peer, 3, ipmb_reply(0x81, 0x20, 3, 7, 0, 0x33, &body));
    });
    assert_eq!(state.recv().unwrap().data(), &[0xa5]);
    peer_thread.join().unwrap();
}

#[test]
fn rejected_get_message_keeps_waiting_for_pushed_reply() {
    let (mut state, peer) = pair(Duration::from_millis(250));
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut req = target();
    state.send(&mut req).unwrap();
    let mut received = [0; 4096];
    peer.recv(&mut received).unwrap();
    reply_packet(&peer, 1, ipmb_reply(0x81, 0x20, 0, 7, 0, 0x34, &[0]));
    let server = std::thread::spawn(move || {
        let len = peer.recv(&mut received).unwrap();
        let flags = Message::from_data(None, &received[4..len]).unwrap();
        assert_eq!(flags.payload[5], 0x31);
        reply_packet(&peer, 2, ipmb_reply(0x81, 0x20, 2, 7, 0, 0x31, &[0, 1]));
        let len = peer.recv(&mut received).unwrap();
        let get = Message::from_data(None, &received[4..len]).unwrap();
        assert_eq!(get.payload[5], 0x33);
        reply_packet(&peer, 3, ipmb_reply(0x81, 0x20, 3, 7, 0, 0x33, &[0xc1]));
        std::thread::sleep(Duration::from_millis(25));
        reply_packet(&peer, 4, ipmb_reply(0x81, 0x52, 1, 1, 1, 2, &[0, 0xa5]));
        assert!(peer.recv(&mut received).is_err()); // no more queue polling
    });
    assert_eq!(state.recv().unwrap().data(), &[0xa5]);
    server.join().unwrap();
}

#[test]
fn busy_queue_flags_recover_without_replaying_bridged_command() {
    let (mut state, peer) = pair(Duration::from_millis(350));
    peer.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let mut req = target();
    state.send(&mut req).unwrap();
    let mut received = [0; 4096];
    let len = peer.recv(&mut received).unwrap();
    assert_eq!(
        Message::from_data(None, &received[4..len]).unwrap().payload[5],
        0x34
    );
    reply_packet(&peer, 1, ipmb_reply(0x81, 0x20, 0, 7, 0, 0x34, &[0]));
    let server = std::thread::spawn(move || {
        for (seq, code, data) in [(2, 0xc0, &[][..]), (3, 0, &[1][..])] {
            let len = peer.recv(&mut received).unwrap();
            let flags = Message::from_data(None, &received[4..len]).unwrap();
            assert_eq!((flags.payload[5], flags.payload[4] >> 2), (0x31, seq));
            let mut body = vec![code];
            body.extend_from_slice(data);
            reply_packet(
                &peer,
                u32::from(seq),
                ipmb_reply(0x81, 0x20, seq, 7, 0, 0x31, &body),
            );
        }
        let len = peer.recv(&mut received).unwrap();
        let get = Message::from_data(None, &received[4..len]).unwrap();
        assert_eq!((get.payload[5], get.payload[4] >> 2), (0x33, 4));
        let final_reply = ipmb_reply(0x81, 0x52, 1, 1, 1, 2, &[0, 0xa5]);
        let mut body = vec![0, 0];
        body.extend_from_slice(&final_reply[1..]);
        reply_packet(&peer, 4, ipmb_reply(0x81, 0x20, 4, 7, 0, 0x33, &body));
    });
    let start = Instant::now();
    assert_eq!(state.recv().unwrap().data(), &[0xa5]);
    assert!(start.elapsed() < Duration::from_millis(350));
    assert_eq!(state.last_inbound_sequence, Some(4));
    server.join().unwrap();
}

#[test]
fn short_queue_backoff_accepts_pushed_reply_before_deadline() {
    let (mut state, peer) = pair(Duration::from_millis(40));
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut req = target();
    state.send(&mut req).unwrap();
    let mut received = [0; 4096];
    peer.recv(&mut received).unwrap();
    reply_packet(&peer, 1, ipmb_reply(0x81, 0x20, 0, 7, 0, 0x34, &[0]));
    let server = std::thread::spawn(move || {
        let len = peer.recv(&mut received).unwrap();
        let flags = Message::from_data(None, &received[4..len]).unwrap();
        assert_eq!((flags.payload[5], flags.payload[4] >> 2), (0x31, 2));
        reply_packet(&peer, 2, ipmb_reply(0x81, 0x20, 2, 7, 0, 0x31, &[0xc0]));
        std::thread::sleep(Duration::from_millis(5));
        reply_packet(&peer, 3, ipmb_reply(0x81, 0x52, 1, 1, 1, 2, &[0, 0x59]));
        assert!(peer.recv(&mut received).is_err()); // no second probe or original command replay
    });
    assert_eq!(state.recv().unwrap().data(), &[0x59]);
    assert_eq!(state.last_inbound_sequence, Some(3));
    server.join().unwrap();
}

#[test]
fn short_queue_backoff_without_reply_expires_as_timeout() {
    let (mut state, peer) = pair(Duration::from_millis(40));
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut req = target();
    state.send(&mut req).unwrap();
    let mut received = [0; 4096];
    peer.recv(&mut received).unwrap();
    reply_packet(&peer, 1, ipmb_reply(0x81, 0x20, 0, 7, 0, 0x34, &[0]));
    let server = std::thread::spawn(move || {
        let len = peer.recv(&mut received).unwrap();
        let flags = Message::from_data(None, &received[4..len]).unwrap();
        assert_eq!(flags.payload[5], 0x31);
        reply_packet(&peer, 2, ipmb_reply(0x81, 0x20, 2, 7, 0, 0x31, &[0xc0]));
        assert!(peer.recv(&mut received).is_err());
    });
    assert!(matches!(state.recv(), Err(RmcpIpmiReceiveError::Timeout)));
    assert!(state.ipmb_state.pending.is_none());
    server.join().unwrap();
}

#[test]
fn unsupported_queue_timeout_retires_late_reply_without_resending() {
    let (mut state, peer) = pair(Duration::from_millis(130));
    peer.set_read_timeout(Some(Duration::from_millis(60)))
        .unwrap();
    let mut req = target();
    state.send(&mut req).unwrap();
    let mut received = [0; 4096];
    peer.recv(&mut received).unwrap();
    reply_packet(&peer, 1, ipmb_reply(0x81, 0x20, 0, 7, 0, 0x34, &[0]));
    let server = std::thread::spawn(move || {
        let len = peer.recv(&mut received).unwrap();
        let flags = Message::from_data(None, &received[4..len]).unwrap();
        assert_eq!(flags.payload[5], 0x31);
        reply_packet(&peer, 2, ipmb_reply(0x81, 0x20, 2, 7, 0, 0x31, &[0, 1]));
        let len = peer.recv(&mut received).unwrap();
        let get = Message::from_data(None, &received[4..len]).unwrap();
        assert_eq!(get.payload[5], 0x33);
        reply_packet(&peer, 3, ipmb_reply(0x81, 0x20, 3, 7, 0, 0x33, &[0xc1]));
        assert!(peer.recv(&mut received).is_err());
        (peer, received)
    });
    let start = Instant::now();
    assert!(matches!(state.recv(), Err(RmcpIpmiReceiveError::Timeout)));
    assert!(start.elapsed() < Duration::from_millis(300));
    let (peer, mut received) = server.join().unwrap();
    state.send(&mut req).unwrap();
    peer.recv(&mut received).unwrap();
    reply_packet(&peer, 4, ipmb_reply(0x81, 0x52, 1, 1, 1, 2, &[0, 0xff]));
    reply_packet(&peer, 5, ipmb_reply(0x81, 0x20, 4, 7, 0, 0x34, &[0]));
    reply_packet(&peer, 6, ipmb_reply(0x81, 0x52, 5, 1, 1, 2, &[0, 0x55]));
    assert_eq!(state.recv().unwrap().data(), &[0x55]);
    assert!(peer.recv(&mut received).is_err()); // unsupported capability is cached
}

#[test]
fn bridged_out_of_order_session_packets_are_correlated_before_advancing_replay() {
    let (mut state, peer) = pair(Duration::from_millis(100));
    let mut req = target();
    state.send(&mut req).unwrap();
    peer.recv(&mut [0; 4096]).unwrap();
    let final_reply = ipmb_reply(0x81, 0x52, 1, 1, 1, 2, &[0, 0x55]);
    reply_packet(&peer, 2, final_reply.clone());
    reply_packet(&peer, 2, final_reply);
    reply_packet(&peer, 1, ipmb_reply(0x81, 0x20, 0, 7, 0, 0x34, &[0]));
    assert_eq!(state.recv().unwrap().data(), &[0x55]);
    assert_eq!(state.last_inbound_sequence, Some(2));
}

#[test]
fn bridged_timeout_cancellation_and_late_reply_are_not_retried() {
    let (mut state, peer) = pair(Duration::from_millis(90));
    let mut req = target();
    let mut received = [0; 4096];
    state.send(&mut req).unwrap();
    peer.recv(&mut received).unwrap();
    assert!(matches!(state.recv(), Err(RmcpIpmiReceiveError::Timeout)));
    let token = state.socket.cancellation_token();
    state.send(&mut req).unwrap();
    peer.recv(&mut received).unwrap();
    reply_packet(&peer, 1, ipmb_reply(0x81, 0x20, 0, 7, 0, 0x34, &[0]));
    token.cancel();
    assert!(matches!(state.recv(), Err(RmcpIpmiReceiveError::Cancelled)));
    token.reset();
    state.send(&mut req).unwrap();
    peer.recv(&mut received).unwrap();
    reply_packet(&peer, 2, ipmb_reply(0x81, 0x52, 1, 1, 1, 2, &[0]));
    assert!(matches!(
        state.recv(),
        Err(RmcpIpmiReceiveError::IpmbResponseMismatch)
    ));
    assert!(state.ipmb_state.pending.is_none());
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
