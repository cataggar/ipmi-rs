use super::*;

#[test]
fn pong_requires_exact_declared_and_actual_length() {
    let pong = ASFMessage {
        message_tag: 12,
        message_type: ASFMessageType::Pong {
            enterprise_number: 4542,
            oem_data: 5,
            supported_entities: SupportedEntities { ipmi: true },
            supported_interactions: SupportedInteractions {
                rcmp_security: true,
                dmtf_dash: true,
            },
        },
    };
    let mut wire = Vec::new();
    pong.write_data(&mut wire);
    assert_eq!(ASFMessage::from_bytes(&wire), Some(pong));
    for end in 0..wire.len() {
        assert_eq!(
            ASFMessage::from_bytes(&wire[..end]),
            None,
            "truncated at {end}"
        );
    }
    for length in [0, 9, 15, 17, 255] {
        let mut bad = wire.clone();
        bad[7] = length;
        assert_eq!(ASFMessage::from_bytes(&bad), None);
    }
    wire.push(0);
    assert_eq!(ASFMessage::from_bytes(&wire), None);
}
