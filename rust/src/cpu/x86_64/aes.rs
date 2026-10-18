// AES with AES-NI: AESENC, AESENCLAST and AESKEYGENASSIST take a time independent of their
// operands, and the code around them has no branch or address that depends on the key or the data.

use core::arch::x86_64::*;

use super::memory::{load128, store128};

// The key expansion of FIPS 197 by AESKEYGENASSIST: word 3 of its result is
// RotWord(SubWord(w3)) ^ rcon, word 2 SubWord(w3), each spread over a whole key by three
// shifted XORs.
#[target_feature(enable = "aes,sse2")]
#[inline]
fn next(previous: __m128i, assisted: __m128i) -> __m128i {
    let mut key = previous;

    key = _mm_xor_si128(key, _mm_slli_si128::<4>(key));

    key = _mm_xor_si128(key, _mm_slli_si128::<4>(key));

    key = _mm_xor_si128(key, _mm_slli_si128::<4>(key));

    _mm_xor_si128(key, assisted)
}

#[target_feature(enable = "aes,sse2")]
#[inline]
fn assist<const RCON: i32>(key: __m128i) -> __m128i {
    _mm_shuffle_epi32::<0xFF>(_mm_aeskeygenassist_si128::<RCON>(key))
}

#[target_feature(enable = "aes,sse2")]
#[inline]
fn assist_sub(key: __m128i) -> __m128i {
    _mm_shuffle_epi32::<0xAA>(_mm_aeskeygenassist_si128::<0>(key))
}

// Each round key goes straight to its place in round_keys, so that no copy of the key schedule is
// left on the stack.
#[target_feature(enable = "aes,sse2")]
pub(super) fn expand(key: &[u8], round_keys: &mut [[u8; 16]; 15]) {
    if let Ok(key) = <&[u8; 16]>::try_from(key) {
        let mut k = load128(key);

        store128(k, &mut round_keys[0]);

        macro_rules! round {
            ($i:expr, $rcon:expr) => {
                k = next(k, assist::<$rcon>(k));

                store128(k, &mut round_keys[$i]);
            };
        }

        round!(1, 0x01);

        round!(2, 0x02);

        round!(3, 0x04);

        round!(4, 0x08);

        round!(5, 0x10);

        round!(6, 0x20);

        round!(7, 0x40);

        round!(8, 0x80);

        round!(9, 0x1B);

        round!(10, 0x36);

        return;
    }

    let (first, second) = key.split_at(16);

    let mut a = load128(<&[u8; 16]>::try_from(first).unwrap());

    let mut b = load128(<&[u8; 16]>::try_from(second).unwrap());

    store128(a, &mut round_keys[0]);

    store128(b, &mut round_keys[1]);

    macro_rules! pair {
        ($i:expr, $rcon:expr) => {
            a = next(a, assist::<$rcon>(b));

            store128(a, &mut round_keys[2 * $i]);

            b = next(b, assist_sub(a));

            store128(b, &mut round_keys[2 * $i + 1]);
        };
    }

    pair!(1, 0x01);

    pair!(2, 0x02);

    pair!(3, 0x04);

    pair!(4, 0x08);

    pair!(5, 0x10);

    pair!(6, 0x20);

    a = next(a, assist::<0x40>(b));

    store128(a, &mut round_keys[14]);
}

// N blocks under the round keys, interleaved so that the AES unit always has work. The keys are
// read where the caller keeps them, which wipes them, rather than from a copy on the stack.
#[target_feature(enable = "aes,sse2")]
#[inline]
fn encrypt<const N: usize>(keys: &[[u8; 16]], blocks: &mut [__m128i; N]) {
    let (first, rest) = keys.split_first().unwrap();

    let (last, middle) = rest.split_last().unwrap();

    for block in blocks.iter_mut() {
        *block = _mm_xor_si128(*block, load128(first));
    }

    for key in middle {
        let key = load128(key);

        for block in blocks.iter_mut() {
            *block = _mm_aesenc_si128(*block, key);
        }
    }

    let last = load128(last);

    for block in blocks.iter_mut() {
        *block = _mm_aesenclast_si128(*block, last);
    }
}

#[target_feature(enable = "aes,sse2")]
pub(super) fn encrypt_blocks(keys: &[[u8; 16]], blocks: &mut [[u8; 16]]) {
    let (groups, rest) = blocks.as_chunks_mut::<4>();

    for group in groups {
        let mut x: [__m128i; 4] = core::array::from_fn(|i| load128(&group[i]));

        encrypt(keys, &mut x);

        for (vector, block) in x.iter().zip(group.iter_mut()) {
            store128(*vector, block);
        }
    }

    for block in rest {
        let mut x = [load128(block)];

        encrypt(keys, &mut x);

        store128(x[0], block);
    }
}
