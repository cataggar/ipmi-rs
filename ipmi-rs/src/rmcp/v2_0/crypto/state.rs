use ipmi_rs_core::app::auth::{
    AuthenticationAlgorithm, ConfidentialityAlgorithm, IntegrityAlgorithm,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::rmcp::{
    v2_0::{ReadError, WriteError},
    Message, OpenSessionResponse as OSR, RakpMessage1 as RM1, RakpMessage2 as RM2,
};

use super::{keys::Keys, CryptoBackendError, CryptoProvider, HashAlgorithm, SubState};

pub struct CryptoState {
    password: Vec<u8>,
    kg: Option<Vec<u8>>,
    provider: CryptoProvider,
    state: SubState,
}

impl core::fmt::Debug for CryptoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoState")
            .field("provider", &self.provider)
            .field("state", &self.state)
            .finish()
    }
}

impl Drop for CryptoState {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(kg) = &mut self.kg {
            kg.zeroize();
        }
    }
}

impl Default for CryptoState {
    fn default() -> Self {
        Self::new(None, &[])
    }
}

impl CryptoState {
    pub fn new(kg: Option<&[u8]>, password: &[u8]) -> Self {
        Self::new_with_provider(kg, password, CryptoProvider::RustCrypto)
    }

    pub fn new_with_provider(kg: Option<&[u8]>, password: &[u8], provider: CryptoProvider) -> Self {
        Self {
            kg: kg.map(ToOwned::to_owned),
            password: password.to_vec(),
            provider,
            state: SubState::empty(),
        }
    }

    pub fn calculate_rakp3_data(
        &mut self,
        osr: &OSR,
        m1: &RM1,
        m2: &RM2,
    ) -> Result<Option<Vec<u8>>, CryptoBackendError> {
        let hash = match (
            osr.authentication_payload,
            osr.integrity_payload,
            osr.confidentiality_payload,
        ) {
            (
                AuthenticationAlgorithm::RakpHmacSha1,
                IntegrityAlgorithm::HmacSha1_96,
                ConfidentialityAlgorithm::AesCbc128,
            ) => HashAlgorithm::Sha1,
            (
                AuthenticationAlgorithm::RakpHmacSha256,
                IntegrityAlgorithm::HmacSha256_128,
                ConfidentialityAlgorithm::AesCbc128,
            ) => HashAlgorithm::Sha256,
            _ => return Ok(None),
        };

        let role = [
            u8::from(m1.requested_maximum_privilege_level),
            m1.username.len(),
        ];
        let remote_id = m2.remote_console_session_id.get().to_le_bytes();
        let managed_id = m1.managed_system_session_id.get().to_le_bytes();
        let expected = Zeroizing::new(self.provider.hmac(
            hash,
            &self.password,
            &[
                &remote_id,
                &managed_id,
                &m1.remote_console_random_number,
                &m2.managed_system_random_number,
                &m2.managed_system_guid,
                &role,
                m1.username,
            ],
        )?);

        if m2.key_exchange_auth_code.len() != hash.digest_len()
            || !bool::from(m2.key_exchange_auth_code.ct_eq(expected.as_slice()))
        {
            return Ok(None);
        }

        let sik = Zeroizing::new(self.provider.hmac(
            hash,
            self.kg.as_deref().unwrap_or(&self.password),
            &[
                &m1.remote_console_random_number,
                &m2.managed_system_random_number,
                &role,
                m1.username,
            ],
        )?);

        let output = Zeroizing::new(self.provider.hmac(
            hash,
            &self.password,
            &[
                &m2.managed_system_random_number,
                &remote_id,
                &role,
                m1.username,
            ],
        )?);
        self.state = SubState {
            keys: Keys::derive(self.provider, hash, &sik)?,
            confidentiality_algorithm: osr.confidentiality_payload,
            integrity_algorithm: osr.integrity_payload,
        };
        self.password.zeroize();
        if let Some(kg) = &mut self.kg {
            kg.zeroize();
        }
        Ok(Some(output.to_vec()))
    }

    pub fn verify(
        &self,
        algorithm: AuthenticationAlgorithm,
        remote_console_random_number: &[u8; 16],
        managed_system_session_id: u32,
        managed_system_guid: &[u8; 16],
        integrity_check_value: &[u8],
    ) -> Result<bool, CryptoBackendError> {
        let hash = match algorithm {
            AuthenticationAlgorithm::RakpHmacSha1 => HashAlgorithm::Sha1,
            AuthenticationAlgorithm::RakpHmacSha256 => HashAlgorithm::Sha256,
            _ => return Ok(false),
        };
        if hash != self.state.keys.hash || self.state.keys.sik.is_empty() {
            return Ok(false);
        }
        let session_id = managed_system_session_id.to_le_bytes();
        let integrity = Zeroizing::new(self.provider.hmac(
            hash,
            &self.state.keys.sik,
            &[
                remote_console_random_number,
                &session_id,
                managed_system_guid,
            ],
        )?);
        let tag_len = match hash {
            HashAlgorithm::Sha1 => 12,
            HashAlgorithm::Sha256 => 16,
        };
        Ok(integrity_check_value.len() == tag_len
            && bool::from(integrity_check_value.ct_eq(&integrity[..tag_len])))
    }

    pub fn read_payload(&mut self, data: &mut [u8]) -> Result<Message, ReadError> {
        self.state.read_payload(data)
    }

    pub fn write_unencrypted(message: &Message, buffer: &mut Vec<u8>) -> Result<(), WriteError> {
        SubState::empty().write_payload(message, buffer)
    }

    pub fn write_message(
        &mut self,
        message: &Message,
        buffer: &mut Vec<u8>,
    ) -> Result<(), WriteError> {
        self.state.write_payload(message, buffer)
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
