use crate::keccak::Keccak;
use crate::sha2::{IV_256, IV_512, Sha256, Sha512};

const SHA3: u8 = 0x06;

const SHAKE: u8 = 0x1F;

fn absorb(mut engine: Keccak, parts: &[&[u8]]) -> Keccak {
    for part in parts {
        engine.update(part);
    }

    engine
}

pub(crate) fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0; 32];

    absorb(Keccak::new(136, SHA3), parts).read(&mut out);

    out
}

pub(crate) fn sha3_512(parts: &[&[u8]]) -> [u8; 64] {
    let mut out = [0; 64];

    absorb(Keccak::new(72, SHA3), parts).read(&mut out);

    out
}

pub(crate) fn shake256(parts: &[&[u8]]) -> Keccak {
    absorb(Keccak::new(136, SHAKE), parts)
}

pub(crate) fn shake256_into(parts: &[&[u8]], out: &mut [u8]) {
    shake256(parts).read(out);
}

pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut engine = Sha256::new(&IV_256);

    for part in parts {
        engine.update(part);
    }

    engine.digest()
}

pub(crate) fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut engine = Sha512::new(&IV_512);

    for part in parts {
        engine.update(part);
    }

    engine.digest()
}

// SHA-256 truncated to n bytes or SHAKE256 with n bytes of output: the two hash families of LMS
// and XMSS (SP 800-208), fed incrementally.
pub(crate) enum TruncatedHash {
    Sha256(Sha256),
    Shake256(Keccak),
}

impl TruncatedHash {
    pub(crate) fn new(shake: bool) -> Self {
        if shake {
            Self::Shake256(Keccak::new(136, SHAKE))
        } else {
            Self::Sha256(Sha256::new(&IV_256))
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(engine) => engine.update(data),
            Self::Shake256(engine) => engine.update(data),
        }
    }

    pub(crate) fn finish(self, n: usize) -> [u8; 32] {
        let mut out = [0; 32];

        match self {
            Self::Sha256(engine) => out[..n].copy_from_slice(&engine.digest()[..n]),
            Self::Shake256(mut engine) => engine.read(&mut out[..n]),
        }

        out
    }

    pub(crate) fn digest(shake: bool, n: usize, parts: &[&[u8]]) -> [u8; 32] {
        let mut engine = Self::new(shake);

        for part in parts {
            engine.update(part);
        }

        engine.finish(n)
    }
}
