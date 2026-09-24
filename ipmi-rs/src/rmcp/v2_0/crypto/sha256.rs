use hmac::{Hmac, Mac};
use sha2::Sha256;

pub struct Sha256Hmac {
    state: Hmac<Sha256>,
}

impl Sha256Hmac {
    pub fn new(key: &[u8]) -> Self {
        Self {
            state: Hmac::new_from_slice(key)
                .expect("SHA256 HMAC initialization from bytes is infallible"),
        }
    }

    pub fn feed(mut self, data: &[u8]) -> Self {
        self.state.update(data);
        self
    }

    pub fn finalize(self) -> [u8; 32] {
        self.state.finalize().into_bytes().into()
    }
}
