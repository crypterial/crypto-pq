// The Ascon permutation on the scalar pipes built for BMI1 and BMI2: ANDN takes a complement and
// AND in one instruction and RORX rotates into another register, so the linear layer's two
// rotations of a word need no copies of it. The digest keeps the state in registers
// from one block to the next, without a call per permutation.

use crate::sha2::last_bytes;

const CONSTANTS: [u64; 12] = [
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B,
];

// crate::ascon's S-box layer with the output word x2 complemented, which saves the NOT of the
// circuit there: x4 & !x3 is one ANDN. The complement passes through the linear layer, which XORs
// three rotations of a word, and the next round takes it into its constant.
#[inline(always)]
fn sbox(s: &mut [u64; 5]) {
    let [x0, x1, x2, x3, x4] = *s;

    let t0 = x0 ^ x4;

    let t3 = x1 ^ x2;

    let t5 = x3 ^ x4;

    let t8 = (x3 ^ x2) | t3;

    let t12 = (t0 | x1) ^ t5;

    *s = [
        t12 ^ (x2 & t3),
        t0 ^ t8,
        t3 ^ (x4 & !x3),
        t3 ^ (x0 | t5),
        t0 ^ t12,
    ];
}

#[inline(always)]
fn round(s: &mut [u64; 5], constant: u64) {
    s[2] ^= constant;

    sbox(s);

    let [x0, x1, x2, x3, x4] = *s;

    *s = [
        x0 ^ x0.rotate_right(19) ^ x0.rotate_right(28),
        x1 ^ x1.rotate_right(61) ^ x1.rotate_right(39),
        x2 ^ x2.rotate_right(1) ^ x2.rotate_right(6),
        x3 ^ x3.rotate_right(10) ^ x3.rotate_right(17),
        x4 ^ x4.rotate_right(7) ^ x4.rotate_right(41),
    ];
}

// The rounds written out, so that each constant is an immediate (a loop of three rounds per step
// took 3 to 10% more time), on a state whose x2 is complemented before and after: each round
// takes the complement of its constant.
#[inline(always)]
fn permute_complemented(s: &mut [u64; 5]) {
    round(s, !CONSTANTS[0]);

    round(s, !CONSTANTS[1]);

    round(s, !CONSTANTS[2]);

    round(s, !CONSTANTS[3]);

    round(s, !CONSTANTS[4]);

    round(s, !CONSTANTS[5]);

    round(s, !CONSTANTS[6]);

    round(s, !CONSTANTS[7]);

    round(s, !CONSTANTS[8]);

    round(s, !CONSTANTS[9]);

    round(s, !CONSTANTS[10]);

    round(s, !CONSTANTS[11]);
}

#[target_feature(enable = "bmi1,bmi2")]
pub(super) fn ascon_bmi(s: &mut [u64; 5]) {
    s[2] = !s[2];

    permute_complemented(s);

    s[2] = !s[2];
}

// crate::ascon's digest with the state in registers throughout and x2 complemented from the start
// state to the wipe: the whole eight-byte blocks of data, its padded last block, then out.len()
// bytes.
#[target_feature(enable = "bmi1,bmi2")]
pub(super) fn digest_bmi(start: &[u64; 5], data: &[u8], out: &mut [u8]) {
    let mut s = *start;

    s[2] = !s[2];

    let (blocks, tail) = data.as_chunks::<8>();

    for block in blocks {
        s[0] ^= u64::from_le_bytes(*block);

        permute_complemented(&mut s);
    }

    s[0] ^= last_bytes(data, tail.len()) as u64 ^ 1 << (8 * tail.len());

    permute_complemented(&mut s);

    let (words, rest) = out.as_chunks_mut::<8>();

    for (i, word) in words.iter_mut().enumerate() {
        if i > 0 {
            permute_complemented(&mut s);
        }

        *word = s[0].to_le_bytes();
    }

    if !rest.is_empty() {
        if !words.is_empty() {
            permute_complemented(&mut s);
        }

        rest.copy_from_slice(&s[0].to_le_bytes()[..rest.len()]);
    }

    crate::wipe::wipe(&mut s);
}

#[cfg(test)]
mod tests {
    #[test]
    fn sbox_matches_table() {
        crate::ascon::check_sbox(|s| {
            super::sbox(s);

            s[2] = !s[2];
        });
    }
}
