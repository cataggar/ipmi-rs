use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use super::{sha1::Sha1Hmac, sha256::Sha256Hmac};

/// Cryptographic implementation used by an RMCP+ session.
///
/// Selecting `SymCrypt` without the `symcrypt-backend` feature returns an
/// activation error; it never switches to RustCrypto.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CryptoProvider {
    #[default]
    RustCrypto,
    SymCrypt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashAlgorithm {
    Sha1,
    Sha256,
}

impl HashAlgorithm {
    pub(crate) fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

/// Backend errors contain no key material, input data, or authentication tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoBackendError {
    Unavailable,
    OperationFailed,
}

impl CryptoProvider {
    pub(crate) fn ensure_available(self) -> Result<(), CryptoBackendError> {
        match self {
            Self::RustCrypto => Ok(()),
            Self::SymCrypt if cfg!(feature = "symcrypt-backend") => Ok(()),
            Self::SymCrypt => Err(CryptoBackendError::Unavailable),
        }
    }

    pub(crate) fn hmac(
        self,
        algorithm: HashAlgorithm,
        key: &[u8],
        parts: &[&[u8]],
    ) -> Result<Vec<u8>, CryptoBackendError> {
        match self {
            Self::RustCrypto => Ok(match algorithm {
                HashAlgorithm::Sha1 => {
                    let mut mac = Sha1Hmac::new(key);
                    for part in parts {
                        mac = mac.feed(part);
                    }
                    mac.finalize().to_vec()
                }
                HashAlgorithm::Sha256 => {
                    let mut mac = Sha256Hmac::new(key);
                    for part in parts {
                        mac = mac.feed(part);
                    }
                    mac.finalize().to_vec()
                }
            }),
            #[cfg(feature = "symcrypt-backend")]
            Self::SymCrypt => {
                use symcrypt::hmac::{HmacSha1State, HmacSha256State, HmacState};
                match algorithm {
                    HashAlgorithm::Sha1 => {
                        let mut mac = HmacSha1State::new(key)
                            .map_err(|_| CryptoBackendError::OperationFailed)?;
                        for part in parts {
                            mac.append(part);
                        }
                        Ok(mac.result().to_vec())
                    }
                    HashAlgorithm::Sha256 => {
                        let mut mac = HmacSha256State::new(key)
                            .map_err(|_| CryptoBackendError::OperationFailed)?;
                        for part in parts {
                            mac.append(part);
                        }
                        Ok(mac.result().to_vec())
                    }
                }
            }
            #[cfg(not(feature = "symcrypt-backend"))]
            Self::SymCrypt => Err(CryptoBackendError::Unavailable),
        }
    }

    pub(crate) fn encrypt(
        self,
        key: &[u8; 16],
        iv: &[u8; 16],
        data: &mut [u8],
    ) -> Result<(), CryptoBackendError> {
        if data.is_empty() || !data.len().is_multiple_of(16) {
            return Err(CryptoBackendError::OperationFailed);
        }
        match self {
            Self::RustCrypto => {
                cbc::Encryptor::<aes::Aes128>::new(&(*key).into(), &(*iv).into())
                    .encrypt_padded_mut::<NoPadding>(data, data.len())
                    .map_err(|_| CryptoBackendError::OperationFailed)?;
                Ok(())
            }
            #[cfg(feature = "symcrypt-backend")]
            Self::SymCrypt => {
                let expanded = symcrypt::cipher::AesExpandedKey::new(key)
                    .map_err(|_| CryptoBackendError::OperationFailed)?;
                let mut chaining_value = *iv;
                expanded
                    .aes_cbc_encrypt_in_place(&mut chaining_value, data)
                    .map_err(|_| CryptoBackendError::OperationFailed)
            }
            #[cfg(not(feature = "symcrypt-backend"))]
            Self::SymCrypt => Err(CryptoBackendError::Unavailable),
        }
    }

    pub(crate) fn decrypt(
        self,
        key: &[u8; 16],
        iv: &[u8; 16],
        data: &mut [u8],
    ) -> Result<(), CryptoBackendError> {
        if data.is_empty() || !data.len().is_multiple_of(16) {
            return Err(CryptoBackendError::OperationFailed);
        }
        match self {
            Self::RustCrypto => {
                cbc::Decryptor::<aes::Aes128>::new(&(*key).into(), &(*iv).into())
                    .decrypt_padded_mut::<NoPadding>(data)
                    .map_err(|_| CryptoBackendError::OperationFailed)?;
                Ok(())
            }
            #[cfg(feature = "symcrypt-backend")]
            Self::SymCrypt => {
                let expanded = symcrypt::cipher::AesExpandedKey::new(key)
                    .map_err(|_| CryptoBackendError::OperationFailed)?;
                let mut chaining_value = *iv;
                expanded
                    .aes_cbc_decrypt_in_place(&mut chaining_value, data)
                    .map_err(|_| CryptoBackendError::OperationFailed)
            }
            #[cfg(not(feature = "symcrypt-backend"))]
            Self::SymCrypt => Err(CryptoBackendError::Unavailable),
        }
    }
}
