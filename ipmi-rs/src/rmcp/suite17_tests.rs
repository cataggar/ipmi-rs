use std::{
    net::{SocketAddr, UdpSocket},
    thread,
    time::Duration,
};

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{CipherSuite, Rmcp};
use crate::connection::{IpmiConnection, LogicalUnit, Message, Request, RequestTargetAddress};

const PASSWORD: &[u8] = b"correct horse battery staple";
const BMC_SESSION_ID: [u8; 4] = 0x55667788u32.to_le_bytes();
const BMC_RANDOM: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const BMC_GUID: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];

fn mac(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    hmac.update(input);
    hmac.finalize().into_bytes().into()
}

fn receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut data = [0u8; 1024];
    let (len, peer) = socket.recv_from(&mut data).unwrap();
    (data[..len].to_vec(), peer)
}

fn send_handshake(socket: &UdpSocket, peer: SocketAddr, ty: u8, payload: &[u8]) {
    let mut packet = vec![6, 0, 0xff, 7, 6, ty];
    packet.extend_from_slice(&[0; 8]);
    packet.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    packet.extend_from_slice(payload);
    socket.send_to(&packet, peer).unwrap();
}

fn run_bmc(socket: UdpSocket) {
    let (ping, peer) = receive(&socket);
    assert_eq!(&ping[..4], &[6, 0, 0xff, 6]);
    assert_eq!(ping[9], 0xc8);
    let mut pong = vec![6, 0, 0xff, 6, 0, 0, 0x11, 0xbe, 0x40, 0xc8, 0, 16];
    pong.extend_from_slice(&[0; 8]);
    pong.push(0x80);
    pong.extend_from_slice(&[0; 7]);
    socket.send_to(&pong, peer).unwrap();

    let (caps_request, peer) = receive(&socket);
    assert_eq!(caps_request[3], 7);
    let mut ipmb = vec![
        0x81, 0x1c, 0x63, 0x20, 0, 0x38, 0, 0x0e, 0x81, 0, 0x03, 0, 0, 0, 0, 0,
    ];
    let checksum = (0u8).wrapping_sub(ipmb[3..].iter().copied().fold(0u8, u8::wrapping_add));
    ipmb.push(checksum);
    let mut caps = vec![6, 0, 0xff, 7, 0];
    caps.extend_from_slice(&[0; 8]);
    caps.push(ipmb.len() as u8);
    caps.extend_from_slice(&ipmb);
    caps.push(0);
    socket.send_to(&caps, peer).unwrap();

    let (open, peer) = receive(&socket);
    assert_eq!(open.len(), 48);
    assert_eq!(&open[..6], &[6, 0, 0xff, 7, 6, 0x10]);
    assert_eq!(&open[14..16], &[32, 0]);
    assert_eq!(
        &open[24..48],
        &hex::decode("000000080300000001000008040000000200000801000000").unwrap()
    );
    let console_session_id: [u8; 4] = open[20..24].try_into().unwrap();
    assert_ne!(console_session_id, [0; 4]);
    let mut open_response = vec![open[16], 0, 4, 0];
    open_response.extend_from_slice(&console_session_id);
    open_response.extend_from_slice(&BMC_SESSION_ID);
    open_response.extend_from_slice(&open[24..48]);
    send_handshake(&socket, peer, 0x11, &open_response);

    let (rakp1, peer) = receive(&socket);
    assert_eq!(rakp1[5], 0x12);
    assert_eq!(&rakp1[14..16], &[33, 0]);
    let rakp1 = &rakp1[16..];
    assert_eq!(rakp1[0], 0x0d);
    assert_eq!(&rakp1[4..8], &BMC_SESSION_ID);
    assert_eq!(&rakp1[24..], b"\x04\x00\x00\x05ADMIN");
    let console_random = &rakp1[8..24];
    let role_and_username = b"\x04\x05ADMIN";

    let mut rakp2_input = Vec::new();
    rakp2_input.extend_from_slice(&console_session_id);
    rakp2_input.extend_from_slice(&BMC_SESSION_ID);
    rakp2_input.extend_from_slice(console_random);
    rakp2_input.extend_from_slice(&BMC_RANDOM);
    rakp2_input.extend_from_slice(&BMC_GUID);
    rakp2_input.extend_from_slice(role_and_username);
    let mut rakp2 = vec![rakp1[0], 0, 0, 0];
    rakp2.extend_from_slice(&console_session_id);
    rakp2.extend_from_slice(&BMC_RANDOM);
    rakp2.extend_from_slice(&BMC_GUID);
    rakp2.extend_from_slice(&mac(PASSWORD, &rakp2_input));
    send_handshake(&socket, peer, 0x13, &rakp2);

    let (rakp3, peer) = receive(&socket);
    assert_eq!(rakp3[5], 0x14);
    let rakp3 = &rakp3[16..];
    assert_eq!(&rakp3[..8], &[0x0a, 0, 0, 0, 0x88, 0x77, 0x66, 0x55]);
    let mut rakp3_input = Vec::new();
    rakp3_input.extend_from_slice(&BMC_RANDOM);
    rakp3_input.extend_from_slice(&console_session_id);
    rakp3_input.extend_from_slice(role_and_username);
    assert_eq!(&rakp3[8..], &mac(PASSWORD, &rakp3_input));

    let mut sik_input = Vec::new();
    sik_input.extend_from_slice(console_random);
    sik_input.extend_from_slice(&BMC_RANDOM);
    sik_input.extend_from_slice(role_and_username);
    let sik = mac(PASSWORD, &sik_input);
    let k1 = mac(&sik, &[1; 20]);
    let k2 = mac(&sik, &[2; 20]);

    let mut rakp4_input = Vec::new();
    rakp4_input.extend_from_slice(console_random);
    rakp4_input.extend_from_slice(&BMC_SESSION_ID);
    rakp4_input.extend_from_slice(&BMC_GUID);
    let mut rakp4 = vec![rakp3[0], 0, 0, 0];
    rakp4.extend_from_slice(&BMC_SESSION_ID);
    rakp4.extend_from_slice(&mac(&sik, &rakp4_input)[..16]);
    send_handshake(&socket, peer, 0x15, &rakp4);

    let (request, peer) = receive(&socket);
    assert_eq!(&request[..6], &[6, 0, 0xff, 7, 6, 0xc0]);
    assert_eq!(&request[6..10], &BMC_SESSION_ID);
    assert_eq!(&request[10..14], &[1, 0, 0, 0]);
    let payload_len = u16::from_le_bytes(request[14..16].try_into().unwrap()) as usize;
    assert_eq!(payload_len, 32);
    let tag_start = request.len() - 16;
    assert_eq!(
        &request[tag_start..],
        &mac(&k1, &request[4..tag_start])[..16]
    );
    let integrity_pad_len = request[tag_start - 2] as usize;
    assert_eq!(request[tag_start - 1], 7);
    assert!(request[16 + payload_len..tag_start - 2]
        .iter()
        .all(|byte| *byte == 0xff));
    assert_eq!(tag_start - 2 - (16 + payload_len), integrity_pad_len);

    let aes_key: [u8; 16] = k2[..16].try_into().unwrap();
    let iv: [u8; 16] = request[16..32].try_into().unwrap();
    let mut ciphertext = request[32..16 + payload_len].to_vec();
    let decrypted = cbc::Decryptor::<aes::Aes128>::new(&aes_key.into(), &iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut ciphertext)
        .unwrap();
    let pad_len = *decrypted.last().unwrap() as usize;
    assert_eq!(
        &decrypted[..decrypted.len() - pad_len - 1],
        b"\x20\x18\xc8\x81\x00\x01\xa5\xd9"
    );
    assert_eq!(
        &decrypted[decrypted.len() - pad_len - 1..],
        &[1, 2, 3, 4, 5, 6, 7, 7]
    );

    let mut reply_plaintext = vec![
        0x81, 0x1c, 0x63, 0x20, 0, 0x01, 0, 0x5a, 0x7b, 0x0a, 1, 2, 3, 4, 5, 5,
    ];
    let reply_iv: [u8; 16] = core::array::from_fn(|i| (0x90 + i) as u8);
    cbc::Encryptor::<aes::Aes128>::new(&aes_key.into(), &reply_iv.into())
        .encrypt_padded_mut::<NoPadding>(&mut reply_plaintext, 16)
        .unwrap();
    let mut reply = vec![6, 0, 0xff, 7, 6, 0xc0];
    reply.extend_from_slice(&console_session_id);
    reply.extend_from_slice(&1u32.to_le_bytes());
    reply.extend_from_slice(&32u16.to_le_bytes());
    reply.extend_from_slice(&reply_iv);
    reply.extend_from_slice(&reply_plaintext);
    let integrity_pad_len = (4 - (reply.len() - 4 + 2) % 4) % 4;
    reply.extend(std::iter::repeat_n(0xff, integrity_pad_len));
    reply.extend_from_slice(&[integrity_pad_len as u8, 7]);
    reply.extend_from_slice(&mac(&k1, &reply[4..])[..16]);
    socket.send_to(&reply, peer).unwrap();
}

#[test]
fn required_suite17_completes_handshake_and_encrypted_exchange() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    let bmc = thread::spawn(move || run_bmc(socket));

    let mut rmcp = Rmcp::new(address, Duration::from_secs(2)).unwrap();
    rmcp.activate_with_cipher_suite(CipherSuite::Id17, Some("ADMIN"), Some(PASSWORD))
        .unwrap();
    assert!(rmcp.is_active());
    let mut request = Request::new(
        Message::new_raw(6, 1, vec![0xa5]),
        RequestTargetAddress::Bmc(LogicalUnit::Zero),
    );
    let response = rmcp.send_recv(&mut request).unwrap();
    assert_eq!(response.netfn_raw(), 7);
    assert_eq!(response.cmd(), 1);
    assert_eq!(response.cc(), 0);
    assert_eq!(response.data(), &[0x5a, 0x7b]);
    bmc.join().unwrap();
}
