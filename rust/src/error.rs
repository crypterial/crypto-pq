use core::fmt;

/// The error of every fallible operation, one variant per error code of the specification.
///
/// No variant carries caller or secret data. New variants may be added in a minor version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// A byte input, length argument or output buffer has a length that the operation does not
    /// accept.
    InvalidLength,
    /// DER, PEM, base64 or a tree cache is malformed or not in the required form.
    InvalidEncoding,
    /// A DER or PEM key, a state record or a tree cache belongs to another algorithm.
    AlgorithmMismatch,
    /// A public key fails a validity check of its standard.
    InvalidPublicKey,
    /// A private key or a stateful state record fails a validity check.
    InvalidPrivateKey,
    /// A signature context is longer than 255 bytes.
    InvalidContext,
    /// An option value is not allowed for the operation.
    InvalidOption,
    /// The operating-system entropy source failed or does not exist on the platform.
    RngFailure,
    /// A pairwise consistency test failed, or a stateful signature did not verify: a new one
    /// before its release, or a stored one when its key was loaded.
    SelfTestFailed,
    /// Every signature index of a stateful key has been used.
    KeyExhausted,
    /// The state store of a stateful key reported an error.
    StatePersistFailed,
    /// The stored state changed under the key, the store already holds a state, or the key is
    /// already signing.
    StateConflict,
    /// The algorithm does not have this operation.
    Unsupported,
}

impl Error {
    /// The error code that the specification gives this error, such as `"INVALID_LENGTH"`.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidLength => "INVALID_LENGTH",
            Self::InvalidEncoding => "INVALID_ENCODING",
            Self::AlgorithmMismatch => "ALGORITHM_MISMATCH",
            Self::InvalidPublicKey => "INVALID_PUBLIC_KEY",
            Self::InvalidPrivateKey => "INVALID_PRIVATE_KEY",
            Self::InvalidContext => "INVALID_CONTEXT",
            Self::InvalidOption => "INVALID_OPTION",
            Self::RngFailure => "RNG_FAILURE",
            Self::SelfTestFailed => "SELF_TEST_FAILED",
            Self::KeyExhausted => "KEY_EXHAUSTED",
            Self::StatePersistFailed => "STATE_PERSIST_FAILED",
            Self::StateConflict => "STATE_CONFLICT",
            Self::Unsupported => "UNSUPPORTED",
        }
    }

    // A short English description of the code, which never carries caller or secret data.
    const fn message(&self) -> &'static str {
        match self {
            Self::InvalidLength => "a length is not accepted",
            Self::InvalidEncoding => "the encoding is malformed",
            Self::AlgorithmMismatch => "the encoding names another algorithm",
            Self::InvalidPublicKey => "the public key is not valid",
            Self::InvalidPrivateKey => "the private key is not valid",
            Self::InvalidContext => "the context is longer than 255 bytes",
            Self::InvalidOption => "an option is not accepted",
            Self::RngFailure => "the entropy source failed",
            Self::SelfTestFailed => "a self-test failed",
            Self::KeyExhausted => "every signature of the key has been used",
            Self::StatePersistFailed => "the state store failed",
            Self::StateConflict => "the state changed or the key is in use",
            Self::Unsupported => "the algorithm does not have this operation",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl core::error::Error for Error {}
