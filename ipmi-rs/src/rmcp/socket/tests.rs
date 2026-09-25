use super::*;
use std::thread;

fn pair(timeout: Duration) -> (RmcpIpmiSocket, UdpSocket) {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.connect(peer.local_addr().unwrap()).unwrap();
    peer.connect(client.local_addr().unwrap()).unwrap();
    (
        RmcpIpmiSocket::new(client, TransportPolicy::new(timeout), None),
        peer,
    )
}

#[test]
fn oversized_datagram_is_not_silently_truncated() {
    let (mut client, peer) = pair(Duration::from_millis(250));
    peer.send(&vec![0; MAX_DATAGRAM + 40]).unwrap();
    assert!(matches!(client.recv(), Err(RecvError::DatagramTooLarge)));
}

#[test]
fn bounded_poll_and_cancellation() {
    let (mut client, _peer) = pair(Duration::from_millis(80));
    let start = Instant::now();
    assert!(matches!(client.recv(), Err(RecvError::Timeout)));
    assert!(start.elapsed() < Duration::from_secs(1));

    let (mut client, _peer) = pair(Duration::from_secs(2));
    let token = client.cancellation_token();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        token.cancel();
    });
    let start = Instant::now();
    assert!(matches!(client.recv(), Err(RecvError::Cancelled)));
    assert!(start.elapsed() < Duration::from_millis(500));
    client.cancellation_token().reset();
}

#[test]
fn scoped_event_deadline_and_token_restore_connection_policy() {
    let (mut client, _peer) = pair(Duration::from_secs(2));
    let token = CancellationToken::default();
    let previous = client.begin_bounded(Instant::now() + Duration::from_millis(25), token.clone());
    let start = Instant::now();
    assert!(matches!(client.recv(), Err(RecvError::Timeout)));
    assert!(start.elapsed() < Duration::from_millis(300));
    client.end_bounded(previous);
    assert!(client.deadline() > Instant::now() + Duration::from_secs(1));

    let previous = client.begin_bounded(Instant::now() + Duration::from_secs(1), token.clone());
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(15));
        token.cancel();
    });
    assert!(matches!(client.recv(), Err(RecvError::Cancelled)));
    worker.join().unwrap();
    client.end_bounded(previous);
    assert!(!client.cancellation_token().is_cancelled());

    let (mut client, _peer) = pair(Duration::from_millis(25));
    let previous = client.begin_bounded(
        Instant::now() + Duration::from_secs(3),
        CancellationToken::default(),
    );
    assert!(matches!(client.recv(), Err(RecvError::Timeout)));
    client.end_bounded(previous);
}

#[test]
fn unrelated_packet_flood_is_capped() {
    let (mut client, peer) = pair(Duration::from_secs(1));
    for _ in 0..MAX_UNRELATED {
        peer.send(&[6, 0, 0xff, 6]).unwrap();
    }
    assert!(matches!(
        client.recv(),
        Err(RecvError::TooManyUnrelatedPackets)
    ));
}
