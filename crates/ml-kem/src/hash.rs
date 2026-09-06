//! The hash functions of FIPS 203, section 4.1: H, J, G, PRF and XOF.

use sha3::digest::{Digest, ExtendableOutput, Update, XofReader};
use sha3::{Sha3_256, Sha3_512, Shake128, Shake256};

/// H(s) = SHA3-256(s).
pub(crate) fn h(s: &[u8]) -> [u8; 32] {
    Sha3_256::digest(s).into()
}

/// J(s) = SHAKE256(s, 32 bytes), over the concatenation of `parts`.
pub(crate) fn j(parts: &[&[u8]]) -> [u8; 32] {
    let mut xof = Shake256::default();
    for p in parts {
        Update::update(&mut xof, p);
    }
    let mut out = [0u8; 32];
    xof.finalize_xof().read(&mut out);
    out
}

/// G(c) = SHA3-512(c) split into two 32-byte halves, over the concatenation of `parts`.
pub(crate) fn g(parts: &[&[u8]]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Sha3_512::new();
    for p in parts {
        Digest::update(&mut hasher, p);
    }
    let digest = hasher.finalize();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&digest[..32]);
    b.copy_from_slice(&digest[32..]);
    (a, b)
}

/// PRF_eta(s, b) = SHAKE256(s || b, 64 eta bytes). `out` must be 64 eta bytes long.
pub(crate) fn prf(s: &[u8; 32], b: u8, out: &mut [u8]) {
    let mut xof = Shake256::default();
    Update::update(&mut xof, s);
    Update::update(&mut xof, &[b]);
    xof.finalize_xof().read(out);
}

/// XOF(rho, i, j) = SHAKE128(rho || i || j) as a byte stream.
pub(crate) fn xof(rho: &[u8; 32], i: u8, j: u8) -> impl XofReader {
    let mut xof = Shake128::default();
    Update::update(&mut xof, rho);
    Update::update(&mut xof, &[i, j]);
    xof.finalize_xof()
}
