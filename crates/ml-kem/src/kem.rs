//! ML-KEM key generation, encapsulation and decapsulation (FIPS 203, section 6),
//! plus the input checks of section 7.

use crate::hash::{g, h, j};
use crate::kpke;
use crate::poly::{byte_decode, byte_encode};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const MAX_CIPHERTEXT_LEN: usize = 1568;

/// ML-KEM.KeyGen_internal (algorithm 16). Writes 384K + 32 bytes to `ek` and 768K + 96 bytes to `dk`.
pub(crate) fn keygen<const K: usize>(
    d: &[u8; 32],
    z: &[u8; 32],
    eta1: usize,
    ek: &mut [u8],
    dk: &mut [u8],
) {
    let (dk_pke, rest) = dk.split_at_mut(384 * K);
    kpke::keygen::<K>(d, eta1, ek, dk_pke);
    let (ek_copy, rest) = rest.split_at_mut(384 * K + 32);
    ek_copy.copy_from_slice(ek);
    let (hash, z_copy) = rest.split_at_mut(32);
    hash.copy_from_slice(&h(ek));
    z_copy.copy_from_slice(z);
}

/// Modulus check (section 7.2): every encoded coefficient of t_hat must be below q.
pub(crate) fn modulus_check<const K: usize>(ek: &[u8]) -> bool {
    let mut f = [0u16; 256];
    let mut reencoded = [0u8; 384];
    let mut ok = true;
    for i in 0..K {
        let chunk = &ek[384 * i..384 * (i + 1)];
        byte_decode(12, chunk, &mut f);
        byte_encode(12, &f, &mut reencoded);
        ok &= bool::from(reencoded.ct_eq(chunk));
    }
    ok
}

/// Hash check (section 7.3): the stored H(ek) must match the embedded encapsulation key.
pub(crate) fn hash_check<const K: usize>(dk: &[u8]) -> bool {
    let ek = &dk[384 * K..768 * K + 32];
    let stored = &dk[768 * K + 32..768 * K + 64];
    bool::from(h(ek).ct_eq(stored))
}

/// ML-KEM.Encaps_internal (algorithm 17). Writes the ciphertext to `c` and returns the shared secret.
pub(crate) fn encaps<const K: usize>(
    ek: &[u8],
    m: &[u8; 32],
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
    c: &mut [u8],
) -> [u8; 32] {
    let (k, mut r) = g(&[m, &h(ek)]);
    kpke::encrypt::<K>(ek, m, &r, eta1, eta2, du, dv, c);
    r.zeroize();
    k
}

/// ML-KEM.Decaps_internal (algorithm 18) with implicit rejection selected by a mask,
/// so a mismatching ciphertext costs exactly the same work as a valid one.
pub(crate) fn decaps<const K: usize>(
    dk: &[u8],
    c: &[u8],
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
) -> [u8; 32] {
    let dk_pke = &dk[..384 * K];
    let ek = &dk[384 * K..768 * K + 32];
    let hash = &dk[768 * K + 32..768 * K + 64];
    let z = &dk[768 * K + 64..768 * K + 96];

    let mut m = kpke::decrypt::<K>(dk_pke, c, du, dv);
    let (mut k_prime, mut r_prime) = g(&[&m, hash]);
    let mut k_bar = j(&[z, c]);
    let mut c_prime = [0u8; MAX_CIPHERTEXT_LEN];
    let c_prime = &mut c_prime[..c.len()];
    kpke::encrypt::<K>(ek, &m, &r_prime, eta1, eta2, du, dv, c_prime);

    let equal = c.ct_eq(c_prime).unwrap_u8();
    let reject = equal.wrapping_sub(1);
    let mut k = [0u8; 32];
    for i in 0..32 {
        k[i] = (k_prime[i] & !reject) | (k_bar[i] & reject);
    }

    m.zeroize();
    k_prime.zeroize();
    r_prime.zeroize();
    k_bar.zeroize();
    c_prime.zeroize();
    k
}
