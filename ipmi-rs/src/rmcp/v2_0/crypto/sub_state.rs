use ipmi_rs_core::app::auth::{ConfidentialityAlgorithm, IntegrityAlgorithm};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::rmcp::{Message, PayloadType};

use super::{
    super::{ReadError, WriteError},
    keys::Keys,
    CryptoUnwrapError, HashAlgorithm,
};

pub struct SubState {
    pub(crate) keys: Keys,
    pub(crate) confidentiality_algorithm: ConfidentialityAlgorithm,
    pub(crate) integrity_algorithm: IntegrityAlgorithm,
}

impl core::fmt::Debug for SubState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Configured")
            .field("keys", &self.keys)
            .field("confidentiality_algorithm", &self.confidentiality_algorithm)
            .field("integrity_algorithm", &self.integrity_algorithm)
            .finish()
    }
}

impl SubState {
    pub fn empty() -> Self {
        Self {
            keys: Keys::empty(),
            confidentiality_algorithm: ConfidentialityAlgorithm::None,
            integrity_algorithm: IntegrityAlgorithm::None,
        }
    }

    fn encrypted(&self) -> bool {
        self.confidentiality_algorithm != ConfidentialityAlgorithm::None
    }

    fn authenticated(&self) -> bool {
        self.integrity_algorithm != IntegrityAlgorithm::None
    }

    fn write_trailer(&mut self, buffer: &mut Vec<u8>) -> Result<(), WriteError> {
        // IPMI Session Trailer is only present if packets are authenticated.
        if self.authenticated() {
            // + 2 because pad data and pad length are also covered by
            // integrity checksum.
            let auth_code_data_len = buffer[4..].len() + 2;

            // Integrity PAD
            let pad_length = (4 - auth_code_data_len % 4) % 4;

            buffer.extend(std::iter::repeat_n(0xFF, pad_length));

            // Pad length
            buffer.push(pad_length as u8);

            // Next header
            buffer.push(0x07);

            // AuthCode
            let auth_code_data = &buffer[4..];

            let (hash, tag_len) =
                self.integrity_parameters()
                    .ok_or(WriteError::UnsupportedIntegrityAlgorithm(
                        self.integrity_algorithm,
                    ))?;
            let tag = Zeroizing::new(
                self.keys
                    .provider
                    .hmac(hash, &self.keys.k1, &[auth_code_data])
                    .map_err(WriteError::CryptoBackend)?,
            );
            buffer.extend_from_slice(&tag[..tag_len]);
        }

        Ok(())
    }

    fn validate_trailer<'a>(&self, data: &'a mut [u8]) -> Result<&'a mut [u8], CryptoUnwrapError> {
        if !self.authenticated() {
            return Ok(data);
        }
        let (hash, auth_code_len) =
            self.integrity_parameters()
                .ok_or(CryptoUnwrapError::UnsupportedIntegrityAlgorithm(
                    self.integrity_algorithm,
                ))?;
        if data.len() < auth_code_len + 2 {
            return Err(CryptoUnwrapError::IncorrectIntegrityTrailerLen);
        }
        let (authenticated_data, tag) = data.split_at_mut(data.len() - auth_code_len);
        let checksum = Zeroizing::new(
            self.keys
                .provider
                .hmac(hash, &self.keys.k1, &[authenticated_data])
                .map_err(CryptoUnwrapError::CryptoBackend)?,
        );
        if !bool::from(tag.ct_eq(&checksum[..auth_code_len])) {
            return Err(CryptoUnwrapError::AuthCodeMismatch);
        }

        let (data, [pad_len, next_header]) = authenticated_data
            .split_last_chunk_mut()
            .ok_or(CryptoUnwrapError::IncorrectIntegrityTrailerLen)?;

        if *next_header != 0x07 {
            return Err(CryptoUnwrapError::UnknownNextHeader(*next_header));
        }

        let pad_len = *pad_len as usize;
        if data.len() < 12 || pad_len > 3 || pad_len > data.len() - 12 || (data.len() + 2) % 4 != 0
        {
            return Err(CryptoUnwrapError::IncorrectIntegrityTrailerLen);
        }
        let (data, padding) = data.split_at_mut(data.len() - pad_len);
        if padding.iter().any(|b| *b != 0xff) {
            return Err(CryptoUnwrapError::InvalidIntegrityPadding);
        }

        Ok(data)
    }

    fn integrity_parameters(&self) -> Option<(HashAlgorithm, usize)> {
        match (self.integrity_algorithm, self.keys.hash) {
            (IntegrityAlgorithm::HmacSha1_96, HashAlgorithm::Sha1) => {
                Some((HashAlgorithm::Sha1, 12))
            }
            (IntegrityAlgorithm::HmacSha256_128, HashAlgorithm::Sha256) => {
                Some((HashAlgorithm::Sha256, 16))
            }
            _ => None,
        }
    }

    /// Write payload data `data` to `buffer`, potentially encrypting and adding
    /// headers or trailers as necessary.
    fn write_data_encrypted(
        &mut self,
        data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), WriteError> {
        let data_len = data.len();

        if data_len > u16::MAX as usize {
            return Err(WriteError::PayloadTooLong);
        }

        match self.confidentiality_algorithm {
            ConfidentialityAlgorithm::None => {
                // Length
                buffer.extend_from_slice(&(data_len as u16).to_le_bytes());

                // Data
                buffer.extend(data);
            }
            ConfidentialityAlgorithm::AesCbc128 => {
                let mut iv = [0u8; 16];
                if cfg!(test) {
                    iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
                } else {
                    getrandom::fill(&mut iv).map_err(WriteError::Random)?;
                }

                // Length
                // Data + Confidentiality pad length + header
                let non_pad_len = data_len + 1 + 16;
                let pad_len = (16 - (non_pad_len % 16)) % 16;
                let padded_len = non_pad_len + pad_len;

                if padded_len > u16::MAX as usize {
                    return Err(WriteError::EncryptedPayloadTooLong);
                }

                buffer.extend((padded_len as u16).to_le_bytes());

                // Confidentiality header
                buffer.extend(iv);

                let dont_encrypt_len = buffer.len();

                // Data
                buffer.extend(data);

                // Confidentiality trailer
                buffer.extend((1u8..).take(pad_len));
                buffer.push(pad_len as u8);

                let buffer_to_encrypt = &mut buffer[dont_encrypt_len..];

                self.keys
                    .provider
                    .encrypt(self.keys.aes_key(), &iv, buffer_to_encrypt)
                    .map_err(WriteError::CryptoBackend)?;
            }
            unsupported => {
                return Err(WriteError::UnsupportedConfidentialityAlgorithm(unsupported))
            }
        }

        Ok(())
    }

    /// Read the (potentially encrypted) payload data from `data`, and return
    /// a buffer containing the decrypted data.
    fn read_data_encrypted<'a>(
        &self,
        data: &'a mut [u8],
    ) -> Result<&'a mut [u8], CryptoUnwrapError> {
        let (payload, confidentiality_pad) = match self.confidentiality_algorithm {
            ConfidentialityAlgorithm::None => {
                const EMPTY_TRAILER: &[u8] = &[];
                (data, EMPTY_TRAILER)
            }
            ConfidentialityAlgorithm::AesCbc128 => {
                let (iv, data_and_trailer) = data
                    .split_first_chunk_mut::<16>()
                    .ok_or(CryptoUnwrapError::NotEnoughData)?;
                if data_and_trailer.is_empty() || data_and_trailer.len() % 16 != 0 {
                    return Err(CryptoUnwrapError::InvalidCiphertext);
                }

                self.keys
                    .provider
                    .decrypt(self.keys.aes_key(), iv, data_and_trailer)
                    .map_err(CryptoUnwrapError::CryptoBackend)?;

                let (confidentiality_pad_len, payload_and_confidentiality_pad) = data_and_trailer
                    .split_last_mut()
                    .ok_or(CryptoUnwrapError::IncorrectConfidentialityTrailerLen)?;

                let confidentiality_pad_len = *confidentiality_pad_len as usize;
                let data_len = payload_and_confidentiality_pad
                    .len()
                    .saturating_sub(confidentiality_pad_len);

                let (payload, confidentiality_pad) =
                    payload_and_confidentiality_pad.split_at_mut(data_len);

                if confidentiality_pad.len() != confidentiality_pad_len {
                    return Err(CryptoUnwrapError::IncorrectConfidentialityTrailerLen);
                }

                (payload, &*confidentiality_pad)
            }
            unsupported => {
                return Err(CryptoUnwrapError::UnsupportedConfidentialityAlgorithm(
                    unsupported,
                ))
            }
        };

        if confidentiality_pad.iter().zip(1..).any(|(l, r)| *l != r) {
            Err(CryptoUnwrapError::InvalidConfidentialityTrailer)
        } else {
            Ok(payload)
        }
    }

    pub fn read_payload(&mut self, data: &mut [u8]) -> Result<Message, ReadError> {
        if data.len() < 10 {
            return Err(ReadError::NotEnoughData);
        }

        if data[0] != 0x06 {
            return Err(ReadError::NotIpmiV2_0);
        }

        let encrypted = (data[1] & 0x80) == 0x80;
        let authenticated = (data[1] & 0x40) == 0x40;
        let ty = PayloadType::try_from(data[1] & 0x3F)
            .map_err(|_| ReadError::InvalidPayloadType(data[1] & 0x3F))?;

        if self.encrypted() != encrypted {
            return Err(CryptoUnwrapError::MismatchingEncryptionState.into());
        }

        if self.authenticated() != authenticated {
            return Err(CryptoUnwrapError::MismatchingAuthenticationState.into());
        }

        let session_id = u32::from_le_bytes(data[2..6].try_into().unwrap());
        let session_sequence_number = u32::from_le_bytes(data[6..10].try_into().unwrap());

        let data_with_header = self.validate_trailer(data)?;
        let data = data_with_header
            .get_mut(10..)
            .ok_or(CryptoUnwrapError::NotEnoughData)?;

        if data.len() < 2 {
            return Err(CryptoUnwrapError::NotEnoughData.into());
        }

        let data_len = u16::from_le_bytes(data[..2].try_into().unwrap());
        let data = &mut data[2..];

        if data_len as usize != data.len() {
            return Err(CryptoUnwrapError::IncorrectPayloadLen.into());
        }

        let data = self.read_data_encrypted(data)?;

        Ok(Message {
            ty,
            session_id,
            session_sequence_number,
            payload: data.to_vec(),
        })
    }

    pub fn write_payload(
        &mut self,
        message: &Message,
        buffer: &mut Vec<u8>,
    ) -> Result<(), WriteError> {
        assert_eq!(buffer.len(), 4, "Buffer must only contain RMCP header.");

        buffer.push(0x06);

        let encrypted = (self.encrypted() as u8) << 7;
        let authenticated = (self.authenticated() as u8) << 6;
        buffer.push(encrypted | authenticated | u8::from(message.ty));

        // TODO: support OEM IANA and OEM payload ID? Ignore for now: unsupported payload type

        buffer.extend_from_slice(&message.session_id.to_le_bytes());
        buffer.extend_from_slice(&message.session_sequence_number.to_le_bytes());

        self.write_data_encrypted(&message.payload, buffer)?;
        self.write_trailer(buffer)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use ipmi_rs_core::app::auth::{ConfidentialityAlgorithm, IntegrityAlgorithm};

    use crate::rmcp::{
        v2_0::crypto::{
            keys::Keys, sha1::Sha1Hmac, sha256::Sha256Hmac, CryptoProvider, CryptoUnwrapError,
            SubState,
        },
        Message, PayloadType, RmcpHeader, V2_0ReadError, V2_0WriteError,
    };

    #[test]
    fn write_empty() {
        let mut state = SubState {
            keys: Keys::from_sik([1u8; _]),
            confidentiality_algorithm: ConfidentialityAlgorithm::AesCbc128,
            integrity_algorithm: IntegrityAlgorithm::None,
        };

        let empty = &[];

        // Empty as encrypted with the above substate.
        let expected = [
            32, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 201, 89, 142, 89, 209,
            209, 28, 35, 201, 136, 6, 196, 59, 124, 245, 173,
        ];

        let mut buffer = Vec::new();

        state.write_data_encrypted(empty, &mut buffer).unwrap();
        assert_eq!(&expected, buffer.as_slice());
    }

    #[test]
    fn read_pad_aligned() {
        let mut state = SubState {
            keys: Keys::from_sik([1u8; _]),
            confidentiality_algorithm: ConfidentialityAlgorithm::AesCbc128,
            integrity_algorithm: IntegrityAlgorithm::HmacSha1_96,
        };

        // Basic message (excl. RMCP header) encrypted with AesCbc128
        // that previously caused a panic.
        let mut buffer = [
            6, 192, 6, 0, 6, 192, 123, 0, 0, 0, 123, 0, 0, 0, 32, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16, 254, 89, 199, 225, 247, 211, 244, 206, 160, 55, 139, 65, 232,
            35, 220, 55, 255, 255, 2, 7, 154, 132, 72, 23, 223, 37, 194, 215, 243, 74, 161, 168,
        ];

        let result = state.read_payload(&mut buffer[4..]).unwrap();

        assert_eq!(PayloadType::IpmiMessage, result.ty);
        assert_eq!(123, result.session_id);
        assert_eq!(123, result.session_sequence_number);
        assert_eq!(
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].as_slice(),
            result.payload
        );
    }

    #[test]
    fn read_undersized() {
        let state = SubState {
            keys: Keys::from_sik([1u8; _]),
            confidentiality_algorithm: ConfidentialityAlgorithm::AesCbc128,
            integrity_algorithm: IntegrityAlgorithm::HmacSha1_96,
        };

        let mut buffer = [0u8; 15];

        assert_eq!(
            state.read_data_encrypted(&mut buffer),
            Err(CryptoUnwrapError::NotEnoughData)
        );
    }

    #[test]
    fn sha1_hmac_trailer_all_lens() {
        let state = SubState {
            keys: Keys::from_sik([1u8; _]),
            confidentiality_algorithm: ConfidentialityAlgorithm::AesCbc128,
            integrity_algorithm: IntegrityAlgorithm::HmacSha1_96,
        };

        for i in 0..32 {
            assert!(state.validate_trailer(&mut vec![0u8; i]).is_err());
        }
    }

    fn providers() -> &'static [CryptoProvider] {
        #[cfg(feature = "symcrypt-backend")]
        {
            &[CryptoProvider::RustCrypto, CryptoProvider::SymCrypt]
        }
        #[cfg(not(feature = "symcrypt-backend"))]
        {
            &[CryptoProvider::RustCrypto]
        }
    }

    fn suite17_state(provider: CryptoProvider) -> SubState {
        SubState {
            keys: Keys::derive(
                provider,
                super::HashAlgorithm::Sha256,
                &hex::decode("ebe2936b4a2cbf0b64ecbd75a5ca848f909e1d84214c428f0f57242bc89709a5")
                    .unwrap(),
            )
            .unwrap(),
            confidentiality_algorithm: ConfidentialityAlgorithm::AesCbc128,
            integrity_algorithm: IntegrityAlgorithm::HmacSha256_128,
        }
    }

    fn packet_fixture() -> Vec<u8> {
        // AES ciphertext from OpenSSL; keys and tag from Python's hmac/hashlib.
        hex::decode(concat!(
            "0600ff07",
            "06c088776655443322112000",
            "0102030405060708090a0b0c0d0e0f10",
            "152c91626024c15ebd75f58a2a42d713",
            "ffff0207",
            "981c4785e9bdcfc754289ea56be39d34",
        ))
        .unwrap()
    }

    fn resign_packet(packet: &mut [u8], state: &SubState) {
        let tag_offset = packet.len() - 16;
        let tag = Sha256Hmac::new(&state.keys.k1)
            .feed(&packet[4..tag_offset])
            .finalize();
        packet[tag_offset..].copy_from_slice(&tag[..16]);
    }

    #[test]
    fn suite17_independent_encrypted_packet_vector() {
        for &provider in providers() {
            let mut state = suite17_state(provider);
            let message = Message {
                ty: PayloadType::IpmiMessage,
                session_id: 0x55667788,
                session_sequence_number: 0x11223344,
                payload: hex::decode("2018c881000173").unwrap(),
            };
            let mut outbound = vec![0x06, 0x00, 0xff, 0x07];
            state.write_payload(&message, &mut outbound).unwrap();
            assert_eq!(outbound, packet_fixture());

            let mut incoming = packet_fixture();
            let received = state.read_payload(&mut incoming[4..]).unwrap();
            assert_eq!(received.ty, message.ty);
            assert_eq!(received.session_id, message.session_id);
            assert_eq!(
                received.session_sequence_number,
                message.session_sequence_number
            );
            assert_eq!(received.payload, message.payload);
        }
    }

    #[test]
    fn suite17_independent_inbound_packet_vector() {
        for &provider in providers() {
            let mut incoming = hex::decode(concat!(
                "0600ff07",
                "06c040302010040302012000",
                "909192939495969798999a9b9c9d9e9f",
                "5d4f5b4e82d7399eaa1ebd67d9ee3d28",
                "ffff0207",
                "a34d98e803fde1be251e9010c13452e0",
            ))
            .unwrap();
            let received = suite17_state(provider)
                .read_payload(&mut incoming[4..])
                .unwrap();
            assert_eq!(received.ty, PayloadType::IpmiMessage);
            assert_eq!(received.session_id, 0x10203040);
            assert_eq!(received.session_sequence_number, 0x01020304);
            assert_eq!(received.payload, hex::decode("811c6320003800a8").unwrap());
        }
    }

    #[test]
    fn suite17_rejects_modified_authenticated_bytes_before_decryption() {
        for &provider in providers() {
            let mut state = suite17_state(provider);
            for position in [6, 11, 18, 34, 48, 50, 51] {
                let mut incoming = packet_fixture();
                incoming[position] ^= 1;
                assert!(
                    matches!(
                        state.read_payload(&mut incoming[4..]),
                        Err(super::ReadError::DecryptionError(
                            CryptoUnwrapError::AuthCodeMismatch
                        ))
                    ),
                    "position {position}"
                );
            }
            let mut incoming = packet_fixture();
            incoming.pop();
            assert!(state.read_payload(&mut incoming[4..]).is_err());
            for size in 0..18 {
                assert!(state.validate_trailer(&mut vec![0; size]).is_err());
            }

            let mut missing_payload = vec![6, 0xc0, 0x88, 0x77, 0x66, 0x55, 1, 0, 0, 0, 0, 7];
            missing_payload.extend_from_slice(&[0; 16]);
            let mac = Sha256Hmac::new(&state.keys.k1)
                .feed(&missing_payload[..12])
                .finalize();
            missing_payload[12..].copy_from_slice(&mac[..16]);
            assert!(matches!(
                state.read_payload(&mut missing_payload),
                Err(super::ReadError::DecryptionError(
                    CryptoUnwrapError::IncorrectIntegrityTrailerLen
                ))
            ));
        }
    }

    #[test]
    fn suite17_valid_tag_does_not_hide_malformed_ciphertext() {
        for &provider in providers() {
            let mut state = suite17_state(provider);

            let mut incomplete_block = packet_fixture();
            incomplete_block.remove(47);
            incomplete_block[14] = 31;
            let pad_len_index = incomplete_block.len() - 16 - 2;
            incomplete_block.insert(pad_len_index, 0xff);
            incomplete_block[pad_len_index + 1] = 3;
            resign_packet(&mut incomplete_block, &state);
            assert!(matches!(
                state.read_payload(&mut incomplete_block[4..]),
                Err(super::ReadError::DecryptionError(
                    CryptoUnwrapError::InvalidCiphertext
                ))
            ));

            let mut broken_padding = packet_fixture();
            broken_padding[31] ^= 1;
            resign_packet(&mut broken_padding, &state);
            assert!(matches!(
                state.read_payload(&mut broken_padding[4..]),
                Err(super::ReadError::DecryptionError(
                    CryptoUnwrapError::InvalidConfidentialityTrailer
                ))
            ));
        }
    }

    fn suite3_state(provider: CryptoProvider) -> SubState {
        SubState {
            keys: Keys::derive(
                provider,
                super::HashAlgorithm::Sha1,
                &hex::decode("a8e9e0c660a01fc8dcf8349b60d19101a7f2865a").unwrap(),
            )
            .unwrap(),
            confidentiality_algorithm: ConfidentialityAlgorithm::AesCbc128,
            integrity_algorithm: IntegrityAlgorithm::HmacSha1_96,
        }
    }

    fn suite3_packet_fixture() -> Vec<u8> {
        // SHA-1 HMAC from Python hashlib; AES-CBC ciphertext from OpenSSL.
        hex::decode(concat!(
            "0600ff07",
            "06c088776655443322112000",
            "0102030405060708090a0b0c0d0e0f10",
            "cb1816d1cf2b5a7210197cb54d71ac5c",
            "ffff0207",
            "dc0e7fc92416f88ca58629fc",
        ))
        .unwrap()
    }

    #[test]
    fn suite3_independent_packet_and_rejection_vectors() {
        for &provider in providers() {
            let mut state = suite3_state(provider);
            let message = Message {
                ty: PayloadType::IpmiMessage,
                session_id: 0x55667788,
                session_sequence_number: 0x11223344,
                payload: hex::decode("2018c881000173").unwrap(),
            };
            let mut outgoing = vec![6, 0, 0xff, 7];
            state.write_payload(&message, &mut outgoing).unwrap();
            assert_eq!(outgoing, suite3_packet_fixture());
            let mut incoming = suite3_packet_fixture();
            let parsed = state.read_payload(&mut incoming[4..]).unwrap();
            assert_eq!(parsed.payload, message.payload);
            assert_eq!(parsed.session_id, message.session_id);
            assert_eq!(
                parsed.session_sequence_number,
                message.session_sequence_number
            );

            for position in [6, 18, 32, 46, 50] {
                let mut tampered = suite3_packet_fixture();
                tampered[position] ^= 1;
                assert!(matches!(
                    state.read_payload(&mut tampered[4..]),
                    Err(super::ReadError::DecryptionError(
                        CryptoUnwrapError::AuthCodeMismatch
                    ))
                ));
            }
            let mut short_tag = suite3_packet_fixture();
            short_tag.pop();
            assert!(state.read_payload(&mut short_tag[4..]).is_err());

            assert_eq!(
                state.read_data_encrypted(&mut [0u8; 15]),
                Err(CryptoUnwrapError::NotEnoughData)
            );
            assert_eq!(
                state.read_data_encrypted(&mut [0u8; 17]),
                Err(CryptoUnwrapError::InvalidCiphertext)
            );
            let mut bad_block = suite3_packet_fixture();
            bad_block.remove(47);
            bad_block[14] = 31;
            let pad_len_index = bad_block.len() - 12 - 2;
            bad_block.insert(pad_len_index, 0xff);
            bad_block[pad_len_index + 1] = 3;
            let mac = provider
                .hmac(
                    super::HashAlgorithm::Sha1,
                    &state.keys.k1,
                    &[&bad_block[4..bad_block.len() - 12]],
                )
                .unwrap();
            let tag_start = bad_block.len() - 12;
            bad_block[tag_start..].copy_from_slice(&mac[..12]);
            assert!(matches!(
                state.read_payload(&mut bad_block[4..]),
                Err(super::ReadError::DecryptionError(
                    CryptoUnwrapError::InvalidCiphertext
                ))
            ));
            let mut bad_padding = suite3_packet_fixture();
            bad_padding[26] ^= 1;
            let mac = provider
                .hmac(
                    super::HashAlgorithm::Sha1,
                    &state.keys.k1,
                    &[&bad_padding[4..bad_padding.len() - 12]],
                )
                .unwrap();
            let tag_start = bad_padding.len() - 12;
            bad_padding[tag_start..].copy_from_slice(&mac[..12]);
            assert!(matches!(
                state.read_payload(&mut bad_padding[4..]),
                Err(super::ReadError::DecryptionError(
                    CryptoUnwrapError::InvalidConfidentialityTrailer
                ))
            ));
        }
    }

    fn authenticated_state() -> SubState {
        SubState {
            keys: Keys::from_sik([0x59; 20]),
            confidentiality_algorithm: ConfidentialityAlgorithm::AesCbc128,
            integrity_algorithm: IntegrityAlgorithm::HmacSha1_96,
        }
    }

    fn signed_packet(state: &mut SubState) -> Vec<u8> {
        let message = Message {
            ty: PayloadType::IpmiMessage,
            session_id: 5,
            session_sequence_number: 1,
            payload: vec![0x20, 0x18, 0xc8, 0x81, 0, 2, 0, 0x7d],
        };
        RmcpHeader::new_ipmi()
            .write(|b| state.write_payload(&message, b))
            .unwrap()
    }

    fn resign(state: &SubState, packet: &mut [u8]) {
        let end = packet.len() - 12;
        let tag = Sha1Hmac::new(&state.keys.k1)
            .feed(&packet[4..end])
            .finalize();
        packet[end..].copy_from_slice(&tag[..12]);
    }

    #[test]
    fn signed_ciphertext_truncation_tampering_and_invalid_padding() {
        let mut state = authenticated_state();
        let packet = signed_packet(&mut state);
        assert!(state.read_payload(&mut packet[4..].to_vec()).is_ok());
        for end in 0..packet.len() {
            let mut truncated = packet[4..end.max(4)].to_vec();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                state.read_payload(&mut truncated)
            }));
            assert!(
                result.is_ok() && result.unwrap().is_err(),
                "truncated at {end}"
            );
        }
        let mut bad = packet.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(matches!(
            state.read_payload(&mut bad[4..]),
            Err(V2_0ReadError::DecryptionError(
                CryptoUnwrapError::AuthCodeMismatch
            ))
        ));

        let mut bad = packet.clone();
        bad[14] ^= 1; // Declared encrypted payload length
        resign(&state, &mut bad);
        assert!(matches!(
            state.read_payload(&mut bad[4..]),
            Err(V2_0ReadError::DecryptionError(
                CryptoUnwrapError::IncorrectPayloadLen
            ))
        ));

        let mut bad = packet.clone();
        bad[24] ^= 1; // AES IV flips the first plaintext padding byte
        resign(&state, &mut bad);
        assert!(matches!(
            state.read_payload(&mut bad[4..]),
            Err(V2_0ReadError::DecryptionError(
                CryptoUnwrapError::InvalidConfidentialityTrailer
            ))
        ));
    }

    #[test]
    fn malformed_ciphertext_and_unsupported_algorithms_return_errors() {
        let mut state = authenticated_state();
        state.integrity_algorithm = IntegrityAlgorithm::None;
        let mut packet = signed_packet(&mut state);
        packet.pop();
        packet[14] -= 1; // Encrypted payload is no longer a multiple of 16 bytes.
        assert!(matches!(
            state.read_payload(&mut packet[4..]),
            Err(V2_0ReadError::DecryptionError(
                CryptoUnwrapError::InvalidCiphertext
            ))
        ));
        state.confidentiality_algorithm = ConfidentialityAlgorithm::Xrc4_128;
        assert!(matches!(
            state.write_payload(
                &Message {
                    ty: PayloadType::IpmiMessage,
                    session_id: 1,
                    session_sequence_number: 1,
                    payload: vec![],
                },
                &mut vec![6, 0, 0xff, 7]
            ),
            Err(V2_0WriteError::UnsupportedConfidentialityAlgorithm(_))
        ));
    }
}
