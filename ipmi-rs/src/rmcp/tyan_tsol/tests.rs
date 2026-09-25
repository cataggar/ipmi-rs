use super::*;
use crate::{
    app::auth::{AuthType, PrivilegeLevel},
    rmcp::{
        checksum::Checksum,
        internal::{Active, RmcpWithState},
        v1_5::{Message as V15Message, State as V15State},
        RmcpHeader,
    },
};
use std::{
    sync::{Arc, Mutex},
    thread,
};

const PASSWORD: [u8; 16] = [9; 16];
type Command = (u8, u8, Vec<u8>);
type Commands = Arc<Mutex<Vec<Command>>>;

#[derive(Clone, Copy)]
enum Scenario {
    Output,
    Quiet,
    WrongDevice,
    NoAuthentication,
    WrongChannel,
    DeniedPrivilege,
    LostKeyReply,
    LostStartReply,
    RefusedStart,
    RefusedPrivilege,
    LowerActivePrivilege,
    LostPrivilegeReply,
    LostKeepalive,
    LostKeepaliveWithOutput,
    ShortFrame,
    OversizedFrame,
}

fn pair(privilege: PrivilegeLevel, auth: AuthType) -> (Rmcp, UdpSocket) {
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(600)))
        .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.connect(peer.local_addr().unwrap()).unwrap();
    let mut rmcp = Rmcp::new(peer.local_addr().unwrap(), Duration::from_millis(250)).unwrap();
    rmcp.active_state = Some(RmcpWithState::from_active(Active::V1_5(
        V15State::test_authenticated(client, privilege, auth, Duration::from_millis(250)),
    )));
    (rmcp, peer)
}

fn mock(scenario: Scenario) -> (Rmcp, Commands, thread::JoinHandle<()>) {
    let (rmcp, peer) = pair(PrivilegeLevel::Administrator, AuthType::MD2);
    let received = Arc::new(Mutex::new(Vec::new()));
    let commands = received.clone();
    let worker = thread::spawn(move || {
        let mut buffer = [0; 4097];
        let mut reply_seq = 1;
        let mut device_id_reads = 0;
        while let Ok((len, sender)) = peer.recv_from(&mut buffer) {
            assert_eq!(&buffer[..4], &[6, 0, 0xff, 7]);
            let packet = V15Message::from_data(Some(&PASSWORD), &buffer[4..len]).unwrap();
            let request = packet.payload;
            assert_eq!(request[0], 0x20);
            let netfn = request[1] >> 2;
            let cmd = request[5];
            let payload = request[6..request.len() - 1].to_vec();
            commands.lock().unwrap().push((netfn, cmd, payload.clone()));
            let response = match (netfn, cmd) {
                (0x06, 0x01) => {
                    device_id_reads += 1;
                    if device_id_reads > 1
                        && matches!(
                            scenario,
                            Scenario::LostKeepalive | Scenario::LostKeepaliveWithOutput
                        )
                    {
                        continue;
                    }
                    let vendor = if matches!(scenario, Scenario::WrongDevice) {
                        [0x57, 0x01, 0]
                    } else {
                        [0xfd, 0x19, 0]
                    };
                    vec![
                        1, 0x80, 1, 0, 0x51, 0x01, vendor[0], vendor[1], vendor[2], 2, 0,
                    ]
                }
                (0x06, 0x38) => {
                    let disabled = if matches!(scenario, Scenario::NoAuthentication) {
                        0x10
                    } else {
                        0
                    };
                    vec![1, 0x82, disabled, 0x01, 0xfd, 0x19, 0, 0]
                }
                (0x06, 0x42) => {
                    let medium = if matches!(scenario, Scenario::WrongChannel) {
                        5
                    } else {
                        4
                    };
                    vec![1, medium, 1, 0xc0, 0xfd, 0x19, 0, 0, 0]
                }
                (0x06, 0x41) => {
                    let limit = if matches!(scenario, Scenario::DeniedPrivilege) {
                        2
                    } else {
                        4
                    };
                    vec![2, limit]
                }
                (0x06, 0x3b) => {
                    assert_eq!(payload, [4]);
                    if matches!(scenario, Scenario::LowerActivePrivilege) {
                        vec![2]
                    } else {
                        vec![4]
                    }
                }
                (0x30, 0x06) => {
                    if !matches!(scenario, Scenario::LostStartReply) {
                        let endpoint = SocketAddrV4::new(
                            Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]),
                            u16::from_be_bytes([payload[4], payload[5]]),
                        );
                        let frame: Vec<u8> = match scenario {
                            Scenario::Output | Scenario::LostKeepaliveWithOutput => {
                                vec![0x11, 0x22, 0x33, 0x44, b'h', b'i']
                            }
                            Scenario::ShortFrame => vec![1, 2, 3],
                            Scenario::OversizedFrame => vec![1; MAX_DATAGRAM + 1],
                            _ => Vec::new(),
                        };
                        if !frame.is_empty() {
                            peer.send_to(&frame, endpoint).unwrap();
                        }
                    }
                    Vec::new()
                }
                (0x30, 0x03) if matches!(scenario, Scenario::LostKeyReply) => continue,
                (0x30, 0x03 | 0x02) => Vec::new(),
                _ => panic!("unexpected IPMI command {netfn:02x}:{cmd:02x}"),
            };
            if netfn == 0x30 && cmd == 0x06 && matches!(scenario, Scenario::LostStartReply) {
                continue;
            }
            if netfn == 0x06 && cmd == 0x3b && matches!(scenario, Scenario::LostPrivilegeReply) {
                continue;
            }
            let mut ipmb = vec![0x81, (netfn + 1) << 2, 0, 0x20, request[4], cmd, 0];
            if netfn == 0x30 && cmd == 0x06 && matches!(scenario, Scenario::RefusedStart) {
                ipmb[6] = 0x81;
            }
            if netfn == 0x06 && cmd == 0x3b && matches!(scenario, Scenario::RefusedPrivilege) {
                ipmb[6] = 0x81;
            }
            ipmb[2] = Checksum::from_iter(ipmb[..2].iter().copied());
            ipmb.extend(response);
            ipmb.push(Checksum::from_iter(ipmb[3..].iter().copied()));
            let wire = RmcpHeader::new_ipmi()
                .write(|bytes| {
                    V15Message {
                        auth_type: AuthType::MD2,
                        session_sequence_number: reply_seq,
                        session_id: 0x1234,
                        payload: ipmb,
                    }
                    .write_data(Some(&PASSWORD), bytes)
                })
                .unwrap();
            reply_seq += 1;
            peer.send_to(&wire, sender).unwrap();
        }
    });
    (rmcp, received, worker)
}

fn commands_seen(commands: &Commands) -> Vec<Command> {
    commands.lock().unwrap().clone()
}

#[test]
fn capture_and_interactive_use_only_tyan_commands_with_sequence() {
    let (mut rmcp, commands, worker) = mock(Scenario::Output);
    {
        let mut capture = rmcp.open_tyan_tsol_capture(0).unwrap();
        assert_eq!(capture.receiver_addr().ip(), &Ipv4Addr::LOCALHOST);
        assert_ne!(capture.receiver_addr().port(), 0);
        let mut out = [0; 1];
        assert_eq!(capture.read(&mut out).unwrap(), 1);
        assert_eq!(out[0], b'h');
        assert_eq!(capture.read(&mut out).unwrap(), 1);
        assert_eq!(out[0], b'i');
        capture.close().unwrap();
    }
    {
        let mut interactive = rmcp.open_tyan_tsol_interactive(0).unwrap();
        assert_eq!(interactive.send_input(b"\x1b[C").unwrap(), 3);
        assert_eq!(interactive.send_input(b"d").unwrap(), 1);
        interactive.close().unwrap();
    }
    worker.join().unwrap();
    let requests = commands_seen(&commands);
    let set_privilege: Vec<_> = requests
        .iter()
        .enumerate()
        .filter(|(_, (netfn, cmd, _))| *netfn == 0x06 && *cmd == 0x3b)
        .collect();
    assert_eq!(set_privilege.len(), 2);
    assert!(set_privilege.iter().all(|(_, (_, _, data))| data == &[4]));
    for (index, _) in set_privilege {
        assert_eq!(requests[index - 1].1, 0x41);
        assert_eq!((requests[index + 1].0, requests[index + 1].1), (0x30, 0x06));
    }
    let tyan: Vec<_> = requests
        .iter()
        .filter(|(netfn, _, _)| *netfn == 0x30)
        .collect();
    assert_eq!(
        tyan.iter().map(|(_, cmd, _)| *cmd).collect::<Vec<_>>(),
        [6, 2, 6, 3, 3, 2]
    );
    assert_eq!(tyan[3].2, [4, 0x1b, b'[', b'C', 0]);
    assert_eq!(tyan[4].2, [2, b'd', 1]);
    assert_eq!(tyan[0].2, tyan[1].2);
    assert_eq!(tyan[2].2, tyan[5].2);
    assert_eq!(&tyan[0].2[..4], &[127, 0, 0, 1]);
    assert!(tyan[0].2[4] != 0 || tyan[0].2[5] != 0);
}

#[test]
fn preflight_refuses_wrong_device_or_channel_without_oem_send() {
    for scenario in [
        Scenario::WrongDevice,
        Scenario::NoAuthentication,
        Scenario::WrongChannel,
        Scenario::DeniedPrivilege,
    ] {
        let (mut rmcp, commands, worker) = mock(scenario);
        let result = rmcp.open_tyan_tsol_capture(0);
        assert!(matches!(
            result,
            Err(TsolError::WrongDevice(_) | TsolError::UnsupportedChannel)
        ));
        worker.join().unwrap();
        assert!(commands_seen(&commands)
            .iter()
            .all(|(netfn, _, _)| *netfn != 0x30));
    }
}

#[test]
fn inactive_or_unprivileged_session_sends_nothing() {
    let (mut rmcp, _) = pair(PrivilegeLevel::User, AuthType::MD2);
    assert!(matches!(
        rmcp.open_tyan_tsol_capture(0),
        Err(TsolError::AuthenticatedAdministratorRequired)
    ));
    let (mut rmcp, _) = pair(PrivilegeLevel::Administrator, AuthType::MD2);
    assert!(authenticated_v15(&mut rmcp).is_err());
    let (mut rmcp, _) = pair(PrivilegeLevel::Administrator, AuthType::None);
    assert!(matches!(
        rmcp.open_tyan_tsol_capture(0),
        Err(TsolError::AuthenticatedAdministratorRequired)
    ));
    let mut inactive = Rmcp::new("127.0.0.1:623", Duration::from_millis(100)).unwrap();
    assert!(matches!(
        inactive.open_tyan_tsol_capture(0),
        Err(TsolError::Ipmi15Required)
    ));
}

#[test]
fn active_admin_privilege_must_be_echoed_before_start() {
    for scenario in [
        Scenario::RefusedPrivilege,
        Scenario::LowerActivePrivilege,
        Scenario::LostPrivilegeReply,
    ] {
        let (mut rmcp, commands, worker) = mock(scenario);
        let err = rmcp.open_tyan_tsol_capture(0).err().unwrap();
        assert!(matches!(
            (scenario, err),
            (
                Scenario::RefusedPrivilege,
                TsolError::SetSessionPrivilege(_)
            ) | (
                Scenario::LowerActivePrivilege,
                TsolError::ActivePrivilegeMismatch(PrivilegeLevel::User)
            ) | (
                Scenario::LostPrivilegeReply,
                TsolError::SetSessionPrivilege(IpmiError::Connection(
                    RmcpIpmiError::OutcomeUnknown(_)
                ))
            )
        ));
        assert!(authenticated_v15(&mut rmcp).is_err());
        worker.join().unwrap();
        let requests = commands_seen(&commands);
        assert_eq!(requests.last().unwrap(), &(0x06, 0x3b, vec![4]));
        assert!(requests.iter().all(|(netfn, _, _)| *netfn != 0x30));
    }
}

#[test]
fn keepalive_runs_when_due_during_capture_and_before_input() {
    let (mut rmcp, commands, worker) = mock(Scenario::Output);
    {
        let mut capture = rmcp.open_tyan_tsol_capture(0).unwrap();
        let mut out = [0; 1];
        assert_eq!(capture.read(&mut out).unwrap(), 1);
        assert_eq!(out, [b'h']);
        capture.0.last_control_activity = Instant::now() - KEEPALIVE_INTERVAL;
        assert_eq!(capture.read(&mut out).unwrap(), 1);
        assert_eq!(out, [b'i']);
        capture.close().unwrap();
    }
    {
        let mut interactive = rmcp.open_tyan_tsol_interactive(0).unwrap();
        interactive.0.last_control_activity = Instant::now() - KEEPALIVE_INTERVAL;
        assert_eq!(interactive.send_input(b"x").unwrap(), 1);
        assert_eq!(interactive.send_input(b"y").unwrap(), 1);
        interactive.close().unwrap();
    }
    worker.join().unwrap();
    let requests = commands_seen(&commands);
    assert_eq!(
        requests
            .iter()
            .filter(|(netfn, cmd, _)| *netfn == 0x06 && *cmd == 0x01)
            .count(),
        4
    );
    assert!(requests
        .windows(2)
        .any(|pair| pair[0].1 == 0x01 && pair[1].0 == 0x30 && pair[1].1 == 0x03));
    assert_eq!(
        requests.iter().filter(|(_, cmd, _)| *cmd == 0x03).count(),
        2
    );
}

#[test]
fn lost_keepalive_interrupts_under_read_deadline_and_stops() {
    let (mut rmcp, commands, worker) = mock(Scenario::LostKeepalive);
    let mut capture = rmcp.open_tyan_tsol_capture(0).unwrap();
    capture.0.last_control_activity = Instant::now() - KEEPALIVE_INTERVAL;
    let start = Instant::now();
    let mut out = [0; 1];
    assert!(matches!(
        capture.read_until(&mut out, start + Duration::from_millis(40)),
        Err(TsolError::Interrupted(TsolInterruption {
            reason: TsolInterruptionReason::Keepalive(_),
            remote_close_unconfirmed: false,
            ..
        }))
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    worker.join().unwrap();
    let requests = commands_seen(&commands);
    assert_eq!(
        requests
            .iter()
            .filter(|(netfn, cmd, _)| *netfn == 0x06 && *cmd == 0x01)
            .count(),
        2
    );
    assert_eq!(
        requests
            .iter()
            .filter(|(netfn, cmd, _)| *netfn == 0x30 && *cmd == 2)
            .count(),
        1
    );
}

#[test]
fn failed_keepalive_retains_previously_buffered_console_output() {
    let (mut rmcp, commands, worker) = mock(Scenario::LostKeepaliveWithOutput);
    let mut capture = rmcp.open_tyan_tsol_capture(0).unwrap();
    let mut out = [0; 1];
    assert_eq!(capture.read(&mut out).unwrap(), 1);
    assert_eq!(out, [b'h']);
    capture.0.last_control_activity = Instant::now() - KEEPALIVE_INTERVAL;
    assert!(matches!(
        capture.read(&mut out),
        Err(TsolError::Interrupted(TsolInterruption {
            reason: TsolInterruptionReason::Keepalive(_),
            remote_close_unconfirmed: false,
            buffered_output,
            ..
        })) if buffered_output.as_bytes() == b"i"
    ));
    worker.join().unwrap();
    assert_eq!(
        commands_seen(&commands)
            .iter()
            .filter(|(netfn, cmd, _)| *netfn == 0x30 && *cmd == 2)
            .count(),
        1
    );
}

#[test]
fn lost_keepalive_does_not_send_or_replay_input() {
    let (mut rmcp, commands, worker) = mock(Scenario::LostKeepalive);
    let mut interactive = rmcp.open_tyan_tsol_interactive(0).unwrap();
    interactive.0.last_control_activity = Instant::now() - KEEPALIVE_INTERVAL;
    assert!(matches!(
        interactive.send_input(b"x"),
        Err(TsolError::Interrupted(TsolInterruption {
            reason: TsolInterruptionReason::Keepalive(_),
            input_delivery_uncertain: false,
            remote_close_unconfirmed: false,
            ..
        }))
    ));
    assert!(matches!(
        interactive.send_input(b"x"),
        Err(TsolError::Closed)
    ));
    worker.join().unwrap();
    assert!(commands_seen(&commands)
        .iter()
        .all(|(netfn, cmd, _)| *netfn != 0x30 || *cmd != 3));
}

#[test]
fn lost_reply_never_replays_keystroke_and_attempts_stop_once() {
    let (mut rmcp, commands, worker) = mock(Scenario::LostKeyReply);
    let mut session = rmcp.open_tyan_tsol_interactive(0).unwrap();
    assert!(matches!(
        session.send_input(&[]),
        Err(TsolError::InvalidInputLength)
    ));
    assert!(matches!(
        session.send_input(&[1; 15]),
        Err(TsolError::InvalidInputLength)
    ));
    let interrupted = session.send_input(b"x").unwrap_err();
    assert!(matches!(
        interrupted,
        TsolError::Interrupted(TsolInterruption {
            reason: TsolInterruptionReason::Keystroke(_),
            input_delivery_uncertain: true,
            remote_close_unconfirmed: false,
            ..
        })
    ));
    assert!(matches!(session.send_input(b"x"), Err(TsolError::Closed)));
    drop(session);
    worker.join().unwrap();
    let requests = commands_seen(&commands);
    assert_eq!(requests.iter().filter(|(_, cmd, _)| *cmd == 3).count(), 1);
    assert_eq!(requests.iter().filter(|(_, cmd, _)| *cmd == 2).count(), 1);
}

#[test]
fn unacknowledged_start_attempts_bounded_stop() {
    let (mut rmcp, commands, worker) = mock(Scenario::LostStartReply);
    assert!(matches!(
        rmcp.open_tyan_tsol_capture(0),
        Err(TsolError::Start {
            remote_close_unconfirmed: false,
            ..
        })
    ));
    worker.join().unwrap();
    let requests = commands_seen(&commands);
    assert_eq!(
        requests
            .iter()
            .filter(|(netfn, _, _)| *netfn == 0x30)
            .map(|(_, cmd, _)| *cmd)
            .collect::<Vec<_>>(),
        [6, 2]
    );
}

#[test]
fn rejected_start_does_not_stop_someone_elses_stream() {
    let (mut rmcp, commands, worker) = mock(Scenario::RefusedStart);
    assert!(matches!(
        rmcp.open_tyan_tsol_capture(0),
        Err(TsolError::Start {
            remote_close_unconfirmed: false,
            ..
        })
    ));
    worker.join().unwrap();
    assert_eq!(
        commands_seen(&commands)
            .iter()
            .filter(|(netfn, _, _)| *netfn == 0x30)
            .map(|(_, cmd, _)| *cmd)
            .collect::<Vec<_>>(),
        [6]
    );
}

#[test]
fn malformed_and_oversized_udp_frames_stop_the_stream() {
    for scenario in [Scenario::ShortFrame, Scenario::OversizedFrame] {
        let (mut rmcp, commands, worker) = mock(scenario);
        let mut capture = rmcp.open_tyan_tsol_capture(0).unwrap();
        let mut out = [0; 10];
        let result = capture.read(&mut out);
        assert!(matches!(
            (scenario, result),
            (
                Scenario::ShortFrame,
                Err(TsolError::Interrupted(TsolInterruption {
                    reason: TsolInterruptionReason::Receive(TsolReceiveError::TruncatedHeader),
                    remote_close_unconfirmed: false,
                    ..
                }))
            ) | (
                Scenario::OversizedFrame,
                Err(TsolError::Interrupted(TsolInterruption {
                    reason: TsolInterruptionReason::Receive(TsolReceiveError::DatagramTooLarge),
                    remote_close_unconfirmed: false,
                    ..
                }))
            )
        ));
        worker.join().unwrap();
        assert_eq!(
            commands_seen(&commands)
                .iter()
                .filter(|(netfn, cmd, _)| *netfn == 0x30 && *cmd == 2)
                .count(),
            1
        );
    }
}

#[test]
fn wrong_source_is_ignored_then_deadline_and_cancellation_stop() {
    let (mut rmcp, _, worker) = mock(Scenario::Quiet);
    let mut capture = rmcp.open_tyan_tsol_capture(0).unwrap();
    let forged = UdpSocket::bind("127.0.0.2:0").unwrap();
    forged
        .send_to(b"headforged", capture.receiver_addr())
        .unwrap();
    let mut out = [0; 16];
    let start = Instant::now();
    assert!(matches!(
        capture.read(&mut out),
        Err(TsolError::Interrupted(TsolInterruption {
            reason: TsolInterruptionReason::Receive(TsolReceiveError::Timeout),
            ..
        }))
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    worker.join().unwrap();

    let (mut rmcp, commands, worker) = mock(Scenario::Quiet);
    let token = rmcp.cancellation_token();
    let mut capture = rmcp.open_tyan_tsol_capture(0).unwrap();
    capture.0.last_control_activity = Instant::now() - KEEPALIVE_INTERVAL;
    token.cancel();
    assert!(matches!(
        capture.read(&mut out),
        Err(TsolError::Interrupted(TsolInterruption {
            reason: TsolInterruptionReason::Receive(TsolReceiveError::Cancelled),
            remote_close_unconfirmed: false,
            ..
        }))
    ));
    worker.join().unwrap();
    assert_eq!(
        commands_seen(&commands)
            .iter()
            .filter(|(netfn, cmd, _)| *netfn == 0x06 && *cmd == 0x01)
            .count(),
        1
    );
}

#[test]
fn close_returns_unread_output_without_debug_leaking_it() {
    let (mut rmcp, _, worker) = mock(Scenario::Output);
    let mut capture = rmcp.open_tyan_tsol_capture(0).unwrap();
    let mut out = [0; 1];
    assert_eq!(capture.read(&mut out).unwrap(), 1);
    let err = capture.close().unwrap_err();
    assert!(!format!("{err:?}").contains("105"));
    assert!(matches!(
        err,
        TsolError::Interrupted(TsolInterruption {
            reason: TsolInterruptionReason::ClosedWithBufferedOutput,
            remote_close_unconfirmed: false,
            buffered_output,
            ..
        }) if buffered_output.as_bytes() == b"i"
    ));
    worker.join().unwrap();
}

#[test]
fn untrusted_udp_flood_is_capped_and_drop_stops_once() {
    let (mut rmcp, commands, worker) = mock(Scenario::Quiet);
    let mut capture = rmcp.open_tyan_tsol_capture(0).unwrap();
    let forged = UdpSocket::bind("127.0.0.2:0").unwrap();
    for _ in 0..MAX_UNRELATED {
        forged.send_to(b"headX", capture.receiver_addr()).unwrap();
    }
    let mut out = [0; 1];
    assert!(matches!(
        capture.read(&mut out),
        Err(TsolError::Interrupted(TsolInterruption {
            reason: TsolInterruptionReason::Receive(TsolReceiveError::TooManyUnrelatedDatagrams),
            remote_close_unconfirmed: false,
            ..
        }))
    ));
    drop(capture);
    worker.join().unwrap();
    assert_eq!(
        commands_seen(&commands)
            .iter()
            .filter(|(netfn, cmd, _)| *netfn == 0x30 && *cmd == 2)
            .count(),
        1
    );

    let (mut rmcp, commands, worker) = mock(Scenario::Quiet);
    let capture = rmcp.open_tyan_tsol_capture(0).unwrap();
    drop(capture);
    worker.join().unwrap();
    assert_eq!(
        commands_seen(&commands)
            .iter()
            .filter(|(netfn, cmd, _)| *netfn == 0x30 && *cmd == 2)
            .count(),
        1
    );
}
