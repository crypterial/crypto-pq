// AES with the ARMv8 AES instructions: AESE and AESMC are on Arm's list of data-independent-timing
// instructions, and the code around them has no branch or address that depends on the key or the
// data.

use core::arch::aarch64::*;

use super::memory::{load_u8, store_u8};

// SubWord: AESE with a zero round key on the word in every column, where ShiftRows moves nothing.
#[target_feature(enable = "neon,aes")]
#[inline]
fn sub_word(word: u32) -> u32 {
    let x = vaeseq_u8(vreinterpretq_u8_u32(vdupq_n_u32(word)), vdupq_n_u8(0));

    vgetq_lane_u32::<0>(vreinterpretq_u32_u8(x))
}

// The key expansion of FIPS 197, 5.2, on little-endian words.
#[target_feature(enable = "neon,aes")]
pub(super) fn expand(key: &[u8], round_keys: &mut [[u8; 16]; 15]) {
    let nk = key.len() / 4;

    let total = 4 * (nk + 7);

    let mut w = [0u32; 60];

    for (i, word) in key.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_le_bytes(*word);
    }

    let mut rcon = 1u32;

    for i in nk..total {
        let mut t = w[i - 1];

        if i % nk == 0 {
            t = sub_word(t.rotate_right(8)) ^ rcon;

            rcon = (rcon << 1) ^ (0x11B & (rcon >> 7).wrapping_neg());
        } else if nk > 6 && i % nk == 4 {
            t = sub_word(t);
        }

        w[i] = w[i - nk] ^ t;
    }

    for (r, target) in round_keys.iter_mut().take(total / 4).enumerate() {
        for (j, bytes) in target.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            bytes.copy_from_slice(&w[4 * r + j].to_le_bytes());
        }
    }

    crate::wipe::wipe(&mut w);
}

// N blocks under the round keys: AESE adds the round key before SubBytes and ShiftRows, so the
// last key is added on its own. The keys are read where the caller keeps them, which wipes them,
// rather than from a copy on the stack.
#[target_feature(enable = "neon,aes")]
#[inline]
fn encrypt<const N: usize>(keys: &[[u8; 16]], blocks: &mut [uint8x16_t; N]) {
    let (last, rest) = keys.split_last().unwrap();

    let (second_last, middle) = rest.split_last().unwrap();

    for key in middle {
        let key = load_u8(key);

        for block in blocks.iter_mut() {
            *block = vaesmcq_u8(vaeseq_u8(*block, key));
        }
    }

    let (second_last, last) = (load_u8(second_last), load_u8(last));

    for block in blocks.iter_mut() {
        *block = veorq_u8(vaeseq_u8(*block, second_last), last);
    }
}

#[target_feature(enable = "neon,aes")]
pub(super) fn encrypt_blocks(keys: &[[u8; 16]], blocks: &mut [[u8; 16]]) {
    let (groups, rest) = blocks.as_chunks_mut::<4>();

    for group in groups {
        let mut x: [uint8x16_t; 4] = core::array::from_fn(|i| load_u8(&group[i]));

        encrypt(keys, &mut x);

        for (vector, block) in x.iter().zip(group.iter_mut()) {
            store_u8(*vector, block);
        }
    }

    for block in rest {
        let mut x = [load_u8(block)];

        encrypt(keys, &mut x);

        store_u8(x[0], block);
    }
}
