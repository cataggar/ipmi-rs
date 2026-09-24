pub(crate) mod sha1;
mod sha256;

mod keys;

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
    InvalidCiphertextLength,
    InvalidConfidentialityTrailer,
    AuthCodeMismatch,
    IncorrectIntegrityTrailerLen,
    UnknownNextHeader(u8),
    InvalidIntegrityPadding,
    InvalidCiphertext,
    UnsupportedIntegrityAlgorithm(IntegrityAlgorithm),
    UnsupportedConfidentialityAlgorithm(ConfidentialityAlgorithm),
}
use ipmi_rs_core::app::auth::{ConfidentialityAlgorithm, IntegrityAlgorithm};
