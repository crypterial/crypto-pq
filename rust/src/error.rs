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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl core::error::Error for Error {}
