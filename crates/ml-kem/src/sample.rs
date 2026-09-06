//! SampleNTT and SamplePolyCBD (FIPS 203, algorithms 7 and 8).

use crate::field::{csub, Poly, N, Q};
use sha3::digest::XofReader;

/// SampleNTT: rejection-samples a uniform element of T_q from an XOF stream.
///
/// The number of bytes read depends only on the public seed, so the variable
/// running time of this loop leaks nothing secret. Bytes are pulled one SHAKE-128
/// block (168 bytes) at a time, which yields exactly the same samples as reading
/// three bytes per iteration.
pub(crate) fn sample_ntt(reader: &mut impl XofReader, out: &mut Poly) {
    let mut block = [0u8; 168];
    let mut j = 0;
    while j < N {
        reader.read(&mut block);
        for chunk in block.chunks_exact(3) {
            let d1 = chunk[0] as u16 + 256 * (chunk[1] as u16 & 15);
            let d2 = (chunk[1] as u16 >> 4) + 16 * chunk[2] as u16;
            if d1 < Q && j < N {
                out[j] = d1;
                j += 1;
            }
            if d2 < Q && j < N {
                out[j] = d2;
                j += 1;
            }
        }
    }
}

/// SamplePolyCBD_eta: centered binomial distribution from 64 eta bytes of PRF output.
/// Bit positions depend only on the loop indices, never on the secret bits.
pub(crate) fn sample_poly_cbd(eta: usize, bytes: &[u8], out: &mut Poly) {
    debug_assert_eq!(bytes.len(), 64 * eta);
    let bit = |idx: usize| (bytes[idx >> 3] >> (idx & 7)) as u16 & 1;
    for (i, c) in out.iter_mut().enumerate() {
        let mut x = 0u16;
        let mut y = 0u16;
        for k in 0..eta {
            x += bit(2 * i * eta + k);
            y += bit(2 * i * eta + eta + k);
        }
        *c = csub(x + Q - y);
    }
}
