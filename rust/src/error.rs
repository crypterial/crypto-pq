use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    InvalidLength,
    InvalidEncoding,
    AlgorithmMismatch,
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidContext,
    InvalidOption,
    RngFailure,
    SelfTestFailed,
    KeyExhausted,
    StatePersistFailed,
    StateConflict,
    Unsupported,
}

impl Error {
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
