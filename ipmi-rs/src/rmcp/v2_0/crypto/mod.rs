pub(crate) mod sha1;
mod sha256;

mod keys;
mod provider;
use provider::HashAlgorithm;
pub use provider::{CryptoBackendError, CryptoProvider};

mod state;
pub use state::CryptoState;

mod sub_state;
pub(crate) use sub_state::SubState;

#[derive(Debug, Clone, PartialEq)]
pub enum CryptoUnwrapError {
    NotEnoughData,
    MismatchingEncryptionState,
    MismatchingAuthenticationState,
    IncorrectPayloadLen,
    IncorrectConfidentialityTrailerLen,
    InvalidConfidentialityTrailer,
    AuthCodeMismatch,
    IncorrectIntegrityTrailerLen,
    UnknownNextHeader(u8),
    InvalidIntegrityPadding,
    InvalidCiphertext,
    UnsupportedIntegrityAlgorithm(IntegrityAlgorithm),
    UnsupportedConfidentialityAlgorithm(ConfidentialityAlgorithm),
    CryptoBackend(CryptoBackendError),
}
use ipmi_rs_core::app::auth::{ConfidentialityAlgorithm, IntegrityAlgorithm};
