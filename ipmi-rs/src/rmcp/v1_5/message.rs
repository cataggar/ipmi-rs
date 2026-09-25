use crate::app::auth::AuthType;

use super::{auth, ReadError, WriteError};

#[derive(Clone, PartialEq)]
pub struct Message {
    pub auth_type: AuthType,
    pub session_sequence_number: u32,
    pub session_id: u32,
    pub payload: Vec<u8>,
}

impl core::fmt::Debug for Message {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug = f.debug_struct("Message");
        debug
            .field("auth_type", &self.auth_type)
            .field("session_sequence_number", &self.session_sequence_number)
            .field("session_id", &self.session_id);
        if super::super::is_password_ipmb(&self.payload) {
            debug.field("payload", &"[REDACTED]");
        } else {
            debug.field("payload", &self.payload);
        }
        debug.finish()
    }
}

impl Message {
    pub fn write_data(
        &self,
        password: Option<&[u8; 16]>,
        buffer: &mut Vec<u8>,
    ) -> Result<(), WriteError> {
        let auth_code = auth::calculate(
            &self.auth_type,
            password,
            self.session_id,
            self.session_sequence_number,
            &self.payload,
        )?;

        buffer.push(self.auth_type.into());
        buffer.extend_from_slice(&self.session_sequence_number.to_le_bytes());
        buffer.extend_from_slice(&self.session_id.to_le_bytes());

        if let Some(auth_code) = auth_code {
            buffer.extend_from_slice(&auth_code);
        }

        if self.payload.len() > u8::MAX as usize {
            return Err(WriteError::PayloadTooLarge(self.payload.len()));
        }

        buffer.push(self.payload.len() as u8);
        buffer.extend_from_slice(&self.payload);

        // Legacy PAD
        buffer.push(0);

        Ok(())
    }

    pub fn from_data(password: Option<&[u8; 16]>, data: &[u8]) -> Result<Self, ReadError> {
        if data.len() < 10 {
            return Err(ReadError::NotEnoughData);
        }

        let session_sequence = u32::from_le_bytes(data[1..5].try_into().unwrap());
        let session_id = u32::from_le_bytes(data[5..9].try_into().unwrap());

        let (auth_type, auth_code, data) = if data[0] == 0x00 {
            (AuthType::None, None, &data[9..])
        } else {
            if data.len() < 26 {
                return Err(ReadError::NotEnoughData);
            }

            let auth_code: [u8; 16] = data[9..25].try_into().unwrap();

            let auth_type = match data[0] {
                0x01 => AuthType::MD2,
                0x02 => AuthType::MD5,
                0x04 => AuthType::Key,
                v => return Err(ReadError::UnsupportedAuthType(v)),
            };

            let data = &data[25..];

            (auth_type, Some(auth_code), data)
        };

        let data_len = data[0];
        let data = &data[1..];

        let empty = data_len == 0 && data.is_empty();
        let only_legacy_pad = data_len == 0 && data.len() == 1;

        let payload = if empty || only_legacy_pad {
            Vec::new()
        } else if data.len() == data_len as usize {
            data.to_vec()
        }
        // Data & legacy PAD
        else if data.len().checked_sub(1) == Some(data_len as usize) && data.last() == Some(&0) {
            data[..data.len() - 1].to_vec()
        } else {
            return Err(ReadError::IncorrectPayloadLen);
        };

        if let Some(auth_code) = auth_code {
            if !auth::verify(
                &auth_type,
                auth_code,
                password,
                session_id,
                session_sequence,
                &payload,
            ) {
                return Err(ReadError::AuthcodeError);
            }
        }

        Ok(Self {
            auth_type,
            session_sequence_number: session_sequence,
            session_id,
            payload,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! test {
        ($name:ident, $data:expr, $then:expr) => {
            #[test]
            pub fn $name() {
                let data = $data;

                let encapsulated = Message::from_data(Some(b"password\0\0\0\0\0\0\0\0"), &data);

                assert_eq!(encapsulated, $then);
            }
        };
    }

    test!(
        empty_noauth,
        [0, 1, 0, 0, 0, 2, 0, 0, 0, 0],
        Ok(Message {
            auth_type: AuthType::None,
            session_sequence_number: 1,
            session_id: 2,
            payload: vec![]
        })
    );

    test!(
        nonempty_noauth,
        [0, 1, 0, 0, 0, 2, 0, 0, 0, 5, 1, 2, 3, 4, 5],
        Ok(Message {
            auth_type: AuthType::None,
            session_sequence_number: 1,
            session_id: 2,
            payload: vec![1, 2, 3, 4, 5]
        })
    );

    test!(
        nonempty_incorrect_len,
        [0, 1, 0, 0, 0, 2, 0, 0, 0, 5, 1, 2, 3, 4],
        Err(ReadError::IncorrectPayloadLen)
    );

    test!(
        declared_payload_with_no_bytes,
        [0, 1, 0, 0, 0, 2, 0, 0, 0, 1],
        Err(ReadError::IncorrectPayloadLen)
    );

    #[cfg(feature = "md5")]
    #[test]
    pub fn empty_md5() {
        let data = [
            2, 1, 0, 0, 0, 2, 0, 0, 0, 195, 79, 254, 176, 78, 164, 164, 224, 87, 31, 152, 197, 2,
            30, 118, 50, 0,
        ];
        let encapsulated = Message::from_data(Some(b"password\0\0\0\0\0\0\0\0"), &data);
        assert_eq!(
            encapsulated,
            Ok(Message {
                auth_type: AuthType::MD5,
                session_sequence_number: 1,
                session_id: 2,
                payload: vec![]
            })
        );
    }

    test!(
        truncated_md5,
        [2, 0, 0, 0, 1, 0, 0, 0, 2, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1],
        Err(ReadError::NotEnoughData)
    );

    #[test]
    fn authenticated_message_round_trip_and_tampering() {
        for auth_type in [AuthType::MD2, AuthType::MD5] {
            if auth_type == AuthType::MD5 && !cfg!(feature = "md5") {
                continue;
            }
            let message = Message {
                auth_type,
                session_sequence_number: 8,
                session_id: 0x1234,
                payload: vec![0x81, 0xc4, 0xbb],
            };
            let password = [9; 16];
            let mut wire = Vec::new();
            message.write_data(Some(&password), &mut wire).unwrap();
            assert_eq!(Message::from_data(Some(&password), &wire), Ok(message));
            wire[26] ^= 1;
            assert_eq!(
                Message::from_data(Some(&password), &wire),
                Err(ReadError::AuthcodeError)
            );
        }
    }
}
