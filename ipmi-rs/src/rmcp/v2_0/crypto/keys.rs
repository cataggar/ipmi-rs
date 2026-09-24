use zeroize::{Zeroize, Zeroizing};

use super::{CryptoBackendError, CryptoProvider, HashAlgorithm};

pub struct Keys {
    pub(super) sik: Vec<u8>,
    pub(super) k1: Vec<u8>,
    pub(super) k2: Vec<u8>,
    aes_key: [u8; 16],
    pub(super) k3: Vec<u8>,
    pub(super) provider: CryptoProvider,
    pub(super) hash: HashAlgorithm,
}

impl core::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys").finish()
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.sik.zeroize();
        self.k1.zeroize();
        self.k2.zeroize();
        self.k3.zeroize();
        self.aes_key.zeroize();
    }
}

impl Keys {
    pub fn empty() -> Self {
        Self {
            sik: Vec::new(),
            k1: Vec::new(),
            k2: Vec::new(),
            k3: Vec::new(),
            aes_key: [0; 16],
            provider: CryptoProvider::RustCrypto,
            hash: HashAlgorithm::Sha1,
        }
    }

    pub fn derive(
        provider: CryptoProvider,
        hash: HashAlgorithm,
        sik: &[u8],
    ) -> Result<Self, CryptoBackendError> {
        let k1 = Zeroizing::new(provider.hmac(hash, sik, &[&[0x01; 20]])?);
        let k2 = Zeroizing::new(provider.hmac(hash, sik, &[&[0x02; 20]])?);
        let k3 = Zeroizing::new(provider.hmac(hash, sik, &[&[0x03; 20]])?);
        let mut aes_key = [0; 16];
        aes_key.copy_from_slice(&k2[..16]);
        Ok(Self {
            sik: sik.to_vec(),
            k1: k1.to_vec(),
            k2: k2.to_vec(),
            k3: k3.to_vec(),
            aes_key,
            provider,
            hash,
        })
    }

    #[cfg(test)]
    pub fn from_sik(sik: [u8; 20]) -> Self {
        Self::derive(CryptoProvider::RustCrypto, HashAlgorithm::Sha1, &sik).unwrap()
    }

    pub fn aes_key(&self) -> &[u8; 16] {
        &self.aes_key
    }
}
