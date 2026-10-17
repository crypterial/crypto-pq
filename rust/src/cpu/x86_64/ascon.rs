// The Ascon permutation on the scalar pipes built for BMI1 and BMI2: ANDN takes the S-box's
// complement and AND in one instruction and RORX rotates into another register, so the linear
// layer's two rotations of a word need no copies of it. The digest keeps the state in registers
// from one block to the next, without a call per permutation.

use crate::sha2::last_bytes;

const CONSTANTS: [u64; 12] = [
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B,
];

#[inline(always)]
fn round(s: &mut [u64; 5], constant: u64) {
    let [mut x0, mut x1, mut x2, mut x3, mut x4] = *s;

    x2 ^= constant;

    x0 ^= x4;

    x4 ^= x3;

    x2 ^= x1;

    let t0 = !x0 & x1;

    let t1 = !x1 & x2;

    let t2 = !x2 & x3;

    let t3 = !x3 & x4;

    let t4 = !x4 & x0;

    x0 ^= t1;

    x1 ^= t2;

    x2 ^= t3;

    x3 ^= t4;

    x4 ^= t0;

    x1 ^= x0;

    x0 ^= x4;

    x3 ^= x2;

    x2 = !x2;

    *s = [
        x0 ^ x0.rotate_right(19) ^ x0.rotate_right(28),
        x1 ^ x1.rotate_right(61) ^ x1.rotate_right(39),
        x2 ^ x2.rotate_right(1) ^ x2.rotate_right(6),
        x3 ^ x3.rotate_right(10) ^ x3.rotate_right(17),
        x4 ^ x4.rotate_right(7) ^ x4.rotate_right(41),
    ];
}

// The rounds written out, so that each constant is an immediate (a loop of three rounds per step
// measured 3 to 10% slower).
#[inline(always)]
fn permute(s: &mut [u64; 5]) {
    round(s, CONSTANTS[0]);

    round(s, CONSTANTS[1]);

    round(s, CONSTANTS[2]);

    round(s, CONSTANTS[3]);

    round(s, CONSTANTS[4]);

    round(s, CONSTANTS[5]);

    round(s, CONSTANTS[6]);

    round(s, CONSTANTS[7]);

    round(s, CONSTANTS[8]);

    round(s, CONSTANTS[9]);

    round(s, CONSTANTS[10]);

    round(s, CONSTANTS[11]);
}

#[target_feature(enable = "bmi1,bmi2")]
pub(super) fn ascon_bmi(s: &mut [u64; 5]) {
    permute(s);
}

// crate::ascon's digest with the state in registers throughout: the whole eight-byte blocks of
// data, its padded last block, then out.len() bytes.
#[target_feature(enable = "bmi1,bmi2")]
pub(super) fn digest_bmi(start: &[u64; 5], data: &[u8], out: &mut [u8]) {
    let mut s = *start;

    let (blocks, tail) = data.as_chunks::<8>();

    for block in blocks {
        s[0] ^= u64::from_le_bytes(*block);

        permute(&mut s);
    }

    s[0] ^= last_bytes(data, tail.len()) as u64 ^ 1 << (8 * tail.len());

    permute(&mut s);

    let (words, rest) = out.as_chunks_mut::<8>();

    for (i, word) in words.iter_mut().enumerate() {
        if i > 0 {
            permute(&mut s);
        }

        *word = s[0].to_le_bytes();
    }

    if !rest.is_empty() {
        if !words.is_empty() {
            permute(&mut s);
        }

        rest.copy_from_slice(&s[0].to_le_bytes()[..rest.len()]);
    }

    crate::wipe::wipe(&mut s);
}
