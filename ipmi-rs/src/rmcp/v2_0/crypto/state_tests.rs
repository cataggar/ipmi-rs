use std::num::NonZeroU32;

use ipmi_rs_core::app::auth::{ConfidentialityAlgorithm, IntegrityAlgorithm, PrivilegeLevel};

use super::*;
use crate::rmcp::{
    v2_0::{RakpMessage3, RakpMessage3Contents, RakpMessage4, Username},
    CipherSuite,
};

// MACs and key derivations were generated independently with Python's hmac/hashlib.
#[test]
fn suite17_rakp_key_and_mac_vectors() {
    let osr = OSR::from_data(
        &hex::decode("000004004030201088776655000000080300000001000008040000000200000801000000")
            .unwrap(),
    )
    .unwrap();
    let username = Username::new("ADMIN").unwrap();
    let m1 = RM1 {
        message_tag: 0x0d,
        managed_system_session_id: NonZeroU32::new(0x55667788).unwrap(),
        remote_console_random_number: core::array::from_fn(|i| i as u8),
        requested_maximum_privilege_level: PrivilegeLevel::Administrator,
        username: &username,
    };
    let mut m1_wire = Vec::new();
    m1.write(&mut m1_wire);
    assert_eq!(
        m1_wire,
        hex::decode(concat!(
            "0d00000088776655",
            "000102030405060708090a0b0c0d0e0f",
            "0400000541444d494e"
        ))
        .unwrap()
    );
    let m2_wire = hex::decode(concat!(
        "0d00000040302010",
        "101112131415161718191a1b1c1d1e1f",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "897e8b5e6a75f382aea006eff95c210f9f26edd01e5ea38f22fcc749f3ffdb10"
    ))
    .unwrap();
    let m2 = RM2::from_data(&m2_wire).unwrap();
    let mut state = CryptoState::new(None, b"correct horse battery staple");
    let m3_mac = state.calculate_rakp3_data(&osr, &m1, &m2).unwrap();
    assert_eq!(
        m3_mac,
        hex::decode("6d93b76fc673ced17dab8503827c91ea64785c0c519ab815de407b64cbf61681").unwrap()
    );
    assert_eq!(
        state.state.keys.sik,
        hex::decode("ebe2936b4a2cbf0b64ecbd75a5ca848f909e1d84214c428f0f57242bc89709a5").unwrap()
    );
    assert_eq!(
        state.state.keys.k1,
        hex::decode("e9cc8b4ee8157d978cc77271344e843b5479562bcad2461fc501367c45581290").unwrap()
    );
    assert_eq!(
        state.state.keys.k2,
        hex::decode("3eb088e549228ed887ad8e47097cd55d3e911190ef741df3e520aa0727acfdb6").unwrap()
    );
    assert_eq!(
        state.state.keys.k3,
        hex::decode("2bacd1f1bc7ae174e3c06db558edac2ebb1bc5b7205a9708af1b5ce6e718f678").unwrap()
    );
    assert_eq!(
        state.state.keys.aes_key().as_slice(),
        &hex::decode("3eb088e549228ed887ad8e47097cd55d").unwrap()
    );
    assert_eq!(
        state.state.integrity_algorithm,
        IntegrityAlgorithm::HmacSha256_128
    );
    assert_eq!(
        state.state.confidentiality_algorithm,
        ConfidentialityAlgorithm::AesCbc128
    );

    let m3 = RakpMessage3 {
        message_tag: 0x0a,
        managed_system_session_id: m1.managed_system_session_id,
        contents: RakpMessage3Contents::Success(&m3_mac),
    };
    let mut m3_wire = Vec::new();
    m3.write(&mut m3_wire);
    assert_eq!(
        m3_wire,
        hex::decode(concat!(
            "0a00000088776655",
            "6d93b76fc673ced17dab8503827c91ea64785c0c519ab815de407b64cbf61681"
        ))
        .unwrap()
    );

    let m4_wire = hex::decode("0a00000088776655cc7f0f32087eb5777b13f4ee7f7e83d5").unwrap();
    let m4 = RakpMessage4::from_data(&m4_wire).unwrap();
    assert!(state.verify(
        osr.authentication_payload,
        &m1.remote_console_random_number,
        m1.managed_system_session_id.get(),
        &m2.managed_system_guid,
        m4.integrity_check_value
    ));
    let mut wrong_m4 = m4.integrity_check_value.to_vec();
    wrong_m4[0] ^= 1;
    for invalid_mac in [
        &wrong_m4[..],
        &m4.integrity_check_value[..15],
        &hex::decode(concat!(
            "cc7f0f32087eb5777b13f4ee7f7e83d5",
            "00000000000000000000000000000000"
        ))
        .unwrap()[..],
    ] {
        assert!(!state.verify(
            osr.authentication_payload,
            &m1.remote_console_random_number,
            m1.managed_system_session_id.get(),
            &m2.managed_system_guid,
            invalid_mac
        ));
    }

    for invalid_len in [31, 33] {
        let mut corrupted = m2_wire.clone();
        corrupted.truncate(40 + invalid_len);
        if invalid_len > 32 {
            corrupted.push(0);
        }
        let invalid_m2 = RM2::from_data(&corrupted).unwrap();
        assert!(CryptoState::new(None, b"correct horse battery staple")
            .calculate_rakp3_data(&osr, &m1, &invalid_m2)
            .is_none());
    }
    let mut corrupted = m2_wire.clone();
    corrupted[45] ^= 1;
    let invalid_m2 = RM2::from_data(&corrupted).unwrap();
    assert!(CryptoState::new(None, b"correct horse battery staple")
        .calculate_rakp3_data(&osr, &m1, &invalid_m2)
        .is_none());

    let kg: Vec<u8> = (0x20..0x40).collect();
    let mut kg_state = CryptoState::new(Some(&kg), b"correct horse battery staple");
    assert_eq!(
        kg_state.calculate_rakp3_data(&osr, &m1, &m2).unwrap(),
        m3_mac
    );
    assert_eq!(
        kg_state.state.keys.sik,
        hex::decode("108fab5632fe2d1c9c1fa16f3ccb053ab2236f62e365187f04ab36c5c5178133").unwrap()
    );
    assert_ne!(kg_state.state.keys.k1, state.state.keys.k1);
    assert_eq!(CipherSuite::Id17.into_suite(), [3, 4, 1]);
}
