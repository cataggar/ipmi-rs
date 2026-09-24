use aes::cipher::{consts::U16, generic_array::GenericArray};

use super::{sha1::Sha1Hmac, sha256::Sha256Hmac};

#[allow(unused)]
pub struct Keys {
    pub(super) sik: Vec<u8>,
    pub(super) k1: Vec<u8>,
    pub(super) k2: Vec<u8>,
    aes_key: GenericArray<u8, U16>,
    pub(super) k3: Vec<u8>,
}

impl core::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys").finish()
    }
}

impl Keys {
    pub fn from_sik(sik: [u8; 20]) -> Self {
        let k2 = Sha1Hmac::new(&sik).feed(&[0x02; 20]).finalize().to_vec();
        let aes_key = <[u8; 16]>::try_from(&k2[..16]).unwrap().into();
        Self {
            sik: sik.to_vec(),
            k1: Sha1Hmac::new(&sik).feed(&[0x01; 20]).finalize().to_vec(),
            k2,
            k3: Sha1Hmac::new(&sik).feed(&[0x03; 20]).finalize().to_vec(),
            aes_key,
        }
    }

    pub fn from_sha256_sik(sik: [u8; 32]) -> Self {
        let k2 = Sha256Hmac::new(&sik).feed(&[0x02; 20]).finalize().to_vec();
        let aes_key = <[u8; 16]>::try_from(&k2[..16]).unwrap().into();
        Self {
            sik: sik.to_vec(),
            k1: Sha256Hmac::new(&sik).feed(&[0x01; 20]).finalize().to_vec(),
            k2,
            k3: Sha256Hmac::new(&sik).feed(&[0x03; 20]).finalize().to_vec(),
            aes_key,
        }
    }

    pub fn aes_key(&self) -> &GenericArray<u8, U16> {
        &self.aes_key
    }
}
