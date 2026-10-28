use crate::keccak::Keccak;
use crate::sha2::{IV_256, IV_512, Sha256, Sha512};

const SHA3: u8 = 0x06;

const SHAKE: u8 = 0x1F;

// The engines absorb in place: an absorbed engine moved by value leaves a copy of its state behind,
// which its Drop does not wipe.
fn digest(mut engine: Keccak, parts: &[&[u8]], out: &mut [u8]) {
    for part in parts {
        engine.update(part);
    }

    engine.read(out);
}

pub(crate) fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0; 32];

    digest(Keccak::new(136, SHA3), parts, &mut out);

    out
}

// Into out, as G of ML-KEM is secret.
pub(crate) fn sha3_512(parts: &[&[u8]], out: &mut [u8; 64]) {
    digest(Keccak::new(72, SHA3), parts, out);
}

// A SHAKE256 sponge that has absorbed nothing yet.
pub(crate) const fn shake256() -> Keccak {
    Keccak::new(136, SHAKE)
}

pub(crate) fn shake256_into(parts: &[&[u8]], out: &mut [u8]) {
    digest(shake256(), parts, out);
}

pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut engine = Sha256::new(&IV_256);

    for part in parts {
        engine.update(part);
    }

    engine.digest()
}

// The leading out.len() bytes, at most 32, of SHA-256 of parts, for a digest that is secret: it
// goes straight into out, with no copy in a frame of its own.
pub(crate) fn sha256_into(parts: &[&[u8]], out: &mut [u8]) {
    let mut engine = Sha256::new(&IV_256);

    for part in parts {
        engine.update(part);
    }

    engine.digest_into(out);
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

    // The n-byte digest into out, zeros after it. Into the caller's buffer, here and in digest:
    // returned by value, the digests of secret chain values were left in this frame.
    // The engine is used in place, where its Drop wipes it: moved out of self, it would leave a
    // copy behind.
    pub(crate) fn finish(mut self, n: usize, out: &mut [u8; 32]) {
        let (digest, rest) = out.split_at_mut(n);

        match &mut self {
            Self::Sha256(engine) => engine.digest_into(digest),
            Self::Shake256(engine) => engine.read(digest),
        }

        rest.fill(0);
    }

    pub(crate) fn digest(shake: bool, n: usize, parts: &[&[u8]], out: &mut [u8; 32]) {
        let mut engine = Self::new(shake);

        for part in parts {
            engine.update(part);
        }

        engine.finish(n, out);
    }
}
