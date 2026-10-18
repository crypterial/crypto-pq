// AES-128 and AES-256 encryption (FIPS 197). With the AES instructions (AES-NI on x86-64, the
// ARMv8 AES instructions on arm64) the round keys are expanded and the blocks encrypted by them.
// Everywhere else the portable code is constant time all the same: four blocks at once in
// bitsliced form, eight 64-bit words of which word b holds bit b of all 64 bytes, with the S-box
// circuit of Boyar and Peralta (eprint 2009/191), the design of BearSSL's aes_ct64. No table is
// indexed by data and no branch depends on it.

use crate::cpu;
use crate::wipe::wipe;

// The round keys of one key: in FIPS 197 byte order for the AES instructions, or bitsliced, each
// spread over four blocks, for the portable code; only the form in use is filled.
pub(crate) struct Aes {
    rounds: usize,
    round_keys: [[u8; 16]; 15],
    bitsliced: [u64; 120],
    hardware: bool,
}

impl Aes {
    // A key of 16 or 32 bytes; callers check the length before.
    pub(crate) fn new(key: &[u8]) -> Self {
        Self::with(key, true)
    }

    // The portable code alone, for the tests that compare it with the AES instructions.
    #[cfg(any(test, crypto_pq_ct))]
    pub(crate) fn portable(key: &[u8]) -> Self {
        Self::with(key, false)
    }

    fn with(key: &[u8], hardware: bool) -> Self {
        assert!(
            key.len() == 16 || key.len() == 32,
            "AES takes a 16- or 32-byte key"
        );

        let rounds = if key.len() == 16 { 10 } else { 14 };

        let mut aes = Self {
            rounds,
            round_keys: [[0; 16]; 15],
            bitsliced: [0; 120],
            hardware: false,
        };

        if hardware && cpu::aes_expand(key, &mut aes.round_keys) {
            aes.hardware = true;

            return aes;
        }

        let mut words = [0u32; 60];

        expand(key, &mut words[..4 * (rounds + 1)]);

        for (r, keys) in aes.bitsliced[..8 * (rounds + 1)]
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .enumerate()
        {
            let mut q = [0; 8];

            (q[0], q[4]) = interleave_in(&[
                words[4 * r],
                words[4 * r + 1],
                words[4 * r + 2],
                words[4 * r + 3],
            ]);

            (q[1], q[2], q[3]) = (q[0], q[0], q[0]);

            (q[5], q[6], q[7]) = (q[4], q[4], q[4]);

            ortho(&mut q);

            keys.copy_from_slice(&q);

            wipe(&mut q);
        }

        wipe(&mut words);

        aes
    }

    // The round keys in FIPS 197 order, when the AES instructions run this key.
    pub(crate) fn hardware_keys(&self) -> Option<&[[u8; 16]]> {
        self.hardware.then(|| &self.round_keys[..self.rounds + 1])
    }

    #[cfg(test)]
    pub(crate) fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.encrypt_blocks(core::slice::from_mut(block));
    }

    // Encrypts the blocks in place.
    pub(crate) fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        if let Some(keys) = self.hardware_keys()
            && cpu::aes_encrypt(keys, blocks)
        {
            return;
        }

        for group in blocks.chunks_mut(4) {
            let mut four = [[0; 16]; 4];

            four[..group.len()].copy_from_slice(group);

            self.encrypt4(&mut four);

            group.copy_from_slice(&four[..group.len()]);

            wipe(&mut four);
        }
    }

    fn encrypt4(&self, blocks: &mut [[u8; 16]; 4]) {
        let mut q = [0; 8];

        for (i, block) in blocks.iter().enumerate() {
            (q[i], q[i + 4]) = interleave_in(&words_of(block));
        }

        ortho(&mut q);

        add_round_key(&mut q, &self.bitsliced[..8]);

        for r in 1..self.rounds {
            sbox(&mut q);

            shift_rows(&mut q);

            mix_columns(&mut q);

            add_round_key(&mut q, &self.bitsliced[8 * r..8 * r + 8]);
        }

        sbox(&mut q);

        shift_rows(&mut q);

        add_round_key(
            &mut q,
            &self.bitsliced[8 * self.rounds..8 * self.rounds + 8],
        );

        ortho(&mut q);

        for (i, block) in blocks.iter_mut().enumerate() {
            let words = interleave_out(q[i], q[i + 4]);

            for (bytes, word) in block.as_chunks_mut::<4>().0.iter_mut().zip(words) {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
        }

        wipe(&mut q);
    }
}

impl Drop for Aes {
    fn drop(&mut self) {
        wipe(&mut self.round_keys);

        wipe(&mut self.bitsliced);
    }
}

fn words_of(block: &[u8; 16]) -> [u32; 4] {
    core::array::from_fn(|i| u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap()))
}

// The key expansion of FIPS 197, 5.2, on little-endian words, in which RotWord is a rotation right
// by eight bits and Rcon sits in the low byte.
fn expand(key: &[u8], w: &mut [u32]) {
    let nk = key.len() / 4;

    for (i, word) in key.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_le_bytes(*word);
    }

    let mut rcon = 1u32;

    for i in nk..w.len() {
        let mut t = w[i - 1];

        if i % nk == 0 {
            t = sub_word(t.rotate_right(8)) ^ rcon;

            rcon = (rcon << 1) ^ (0x11B & (rcon >> 7).wrapping_neg());
        } else if nk > 6 && i % nk == 4 {
            t = sub_word(t);
        }

        w[i] = w[i - nk] ^ t;
    }
}

// SubWord: the S-box on the word placed as the first column of a block.
fn sub_word(x: u32) -> u32 {
    let mut q = [0; 8];

    q[0] = u64::from(x);

    ortho(&mut q);

    sbox(&mut q);

    ortho(&mut q);

    let out = q[0] as u32;

    wipe(&mut q);

    out
}

// Spreads the four little-endian words of a block over two words, the order ortho expects: byte k
// of word i lands in byte 2k of x[i].
fn interleave_in(w: &[u32; 4]) -> (u64, u64) {
    let x: [u64; 4] = core::array::from_fn(|i| {
        let v = u64::from(w[i]);

        let v = (v | (v << 16)) & 0x0000_FFFF_0000_FFFF;

        (v | (v << 8)) & 0x00FF_00FF_00FF_00FF
    });

    (x[0] | (x[2] << 8), x[1] | (x[3] << 8))
}

fn interleave_out(q0: u64, q1: u64) -> [u32; 4] {
    let x = [
        q0 & 0x00FF_00FF_00FF_00FF,
        q1 & 0x00FF_00FF_00FF_00FF,
        (q0 >> 8) & 0x00FF_00FF_00FF_00FF,
        (q1 >> 8) & 0x00FF_00FF_00FF_00FF,
    ];

    x.map(|v| {
        let v = (v | (v >> 8)) & 0x0000_FFFF_0000_FFFF;

        v as u32 | (v >> 16) as u32
    })
}

// Swaps the bits of x selected by low with those of y selected by low << shift.
#[inline(always)]
fn swap(q: &mut [u64; 8], x: usize, y: usize, low: u64, shift: u32) {
    let (a, b) = (q[x], q[y]);

    q[x] = (a & low) | ((b & low) << shift);

    q[y] = ((a >> shift) & low) | (b & !low);
}

// Converts between four interleaved blocks and the bit planes; the transform is its own inverse.
fn ortho(q: &mut [u64; 8]) {
    for i in [0, 2, 4, 6] {
        swap(q, i, i + 1, 0x5555_5555_5555_5555, 1);
    }

    for i in [0, 1, 4, 5] {
        swap(q, i, i + 2, 0x3333_3333_3333_3333, 2);
    }

    for i in 0..4 {
        swap(q, i, i + 4, 0x0F0F_0F0F_0F0F_0F0F, 4);
    }
}

fn add_round_key(q: &mut [u64; 8], key: &[u64]) {
    for (x, k) in q.iter_mut().zip(key) {
        *x ^= k;
    }
}

fn shift_rows(q: &mut [u64; 8]) {
    for x in q.iter_mut() {
        let v = *x;

        *x = (v & 0x0000_0000_0000_FFFF)
            | ((v & 0x0000_0000_FFF0_0000) >> 4)
            | ((v & 0x0000_0000_000F_0000) << 12)
            | ((v & 0x0000_FF00_0000_0000) >> 8)
            | ((v & 0x0000_00FF_0000_0000) << 8)
            | ((v & 0xF000_0000_0000_0000) >> 12)
            | ((v & 0x0FFF_0000_0000_0000) << 4);
    }
}

fn mix_columns(q: &mut [u64; 8]) {
    let r: [u64; 8] = core::array::from_fn(|i| q[i].rotate_right(16));

    let [q0, q1, q2, q3, q4, q5, q6, q7] = *q;

    let rot = |x: u64| x.rotate_right(32);

    q[0] = q7 ^ r[7] ^ r[0] ^ rot(q0 ^ r[0]);

    q[1] = q0 ^ r[0] ^ q7 ^ r[7] ^ r[1] ^ rot(q1 ^ r[1]);

    q[2] = q1 ^ r[1] ^ r[2] ^ rot(q2 ^ r[2]);

    q[3] = q2 ^ r[2] ^ q7 ^ r[7] ^ r[3] ^ rot(q3 ^ r[3]);

    q[4] = q3 ^ r[3] ^ q7 ^ r[7] ^ r[4] ^ rot(q4 ^ r[4]);

    q[5] = q4 ^ r[4] ^ r[5] ^ rot(q5 ^ r[5]);

    q[6] = q5 ^ r[5] ^ r[6] ^ rot(q6 ^ r[6]);

    q[7] = q6 ^ r[6] ^ r[7] ^ rot(q7 ^ r[7]);
}

// The S-box on the eight bit planes, q[0] the least significant bit: the circuit of Boyar and
// Peralta, 113 gates, which numbers the bits from the most significant one, x0 = q[7].
fn sbox(q: &mut [u64; 8]) {
    let (x0, x1, x2, x3, x4, x5, x6, x7) = (q[7], q[6], q[5], q[4], q[3], q[2], q[1], q[0]);

    let y14 = x3 ^ x5;

    let y13 = x0 ^ x6;

    let y9 = x0 ^ x3;

    let y8 = x0 ^ x5;

    let t0 = x1 ^ x2;

    let y1 = t0 ^ x7;

    let y4 = y1 ^ x3;

    let y12 = y13 ^ y14;

    let y2 = y1 ^ x0;

    let y5 = y1 ^ x6;

    let y3 = y5 ^ y8;

    let t1 = x4 ^ y12;

    let y15 = t1 ^ x5;

    let y20 = t1 ^ x1;

    let y6 = y15 ^ x7;

    let y10 = y15 ^ t0;

    let y11 = y20 ^ y9;

    let y7 = x7 ^ y11;

    let y17 = y10 ^ y11;

    let y19 = y10 ^ y8;

    let y16 = t0 ^ y11;

    let y21 = y13 ^ y16;

    let y18 = x0 ^ y16;

    let t2 = y12 & y15;

    let t3 = y3 & y6;

    let t4 = t3 ^ t2;

    let t5 = y4 & x7;

    let t6 = t5 ^ t2;

    let t7 = y13 & y16;

    let t8 = y5 & y1;

    let t9 = t8 ^ t7;

    let t10 = y2 & y7;

    let t11 = t10 ^ t7;

    let t12 = y9 & y11;

    let t13 = y14 & y17;

    let t14 = t13 ^ t12;

    let t15 = y8 & y10;

    let t16 = t15 ^ t12;

    let t17 = t4 ^ t14;

    let t18 = t6 ^ t16;

    let t19 = t9 ^ t14;

    let t20 = t11 ^ t16;

    let t21 = t17 ^ y20;

    let t22 = t18 ^ y19;

    let t23 = t19 ^ y21;

    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;

    let t26 = t21 & t23;

    let t27 = t24 ^ t26;

    let t28 = t25 & t27;

    let t29 = t28 ^ t22;

    let t30 = t23 ^ t24;

    let t31 = t22 ^ t26;

    let t32 = t31 & t30;

    let t33 = t32 ^ t24;

    let t34 = t23 ^ t33;

    let t35 = t27 ^ t33;

    let t36 = t24 & t35;

    let t37 = t36 ^ t34;

    let t38 = t27 ^ t36;

    let t39 = t29 & t38;

    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;

    let t42 = t29 ^ t33;

    let t43 = t29 ^ t40;

    let t44 = t33 ^ t37;

    let t45 = t42 ^ t41;

    let z0 = t44 & y15;

    let z1 = t37 & y6;

    let z2 = t33 & x7;

    let z3 = t43 & y16;

    let z4 = t40 & y1;

    let z5 = t29 & y7;

    let z6 = t42 & y11;

    let z7 = t45 & y17;

    let z8 = t41 & y10;

    let z9 = t44 & y12;

    let z10 = t37 & y3;

    let z11 = t33 & y4;

    let z12 = t43 & y13;

    let z13 = t40 & y5;

    let z14 = t29 & y2;

    let z15 = t42 & y9;

    let z16 = t45 & y14;

    let z17 = t41 & y8;

    let t46 = z15 ^ z16;

    let t47 = z10 ^ z11;

    let t48 = z5 ^ z13;

    let t49 = z9 ^ z10;

    let t50 = z2 ^ z12;

    let t51 = z2 ^ z5;

    let t52 = z7 ^ z8;

    let t53 = z0 ^ z3;

    let t54 = z6 ^ z7;

    let t55 = z16 ^ z17;

    let t56 = z12 ^ t48;

    let t57 = t50 ^ t53;

    let t58 = z4 ^ t46;

    let t59 = z3 ^ t54;

    let t60 = t46 ^ t57;

    let t61 = z14 ^ t57;

    let t62 = t52 ^ t58;

    let t63 = t49 ^ t58;

    let t64 = z4 ^ t59;

    let t65 = t61 ^ t62;

    let t66 = z1 ^ t63;

    let t67 = t64 ^ t65;

    let s3 = t53 ^ t66;

    q[7] = t59 ^ t63;

    q[6] = !(t64 ^ s3);

    q[5] = !(t55 ^ t67);

    q[4] = s3;

    q[3] = t51 ^ t66;

    q[2] = t47 ^ t65;

    q[1] = !(t56 ^ t62);

    q[0] = !(t48 ^ t60);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }

    // FIPS 197, Appendix C.1 and C.3.
    #[test]
    fn fips197() {
        let plaintext: [u8; 16] = unhex("00112233445566778899aabbccddeeff");

        for (key, expected) in [
            (
                "000102030405060708090a0b0c0d0e0f",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ] {
            let key: alloc::vec::Vec<u8> = (0..key.len() / 2)
                .map(|i| u8::from_str_radix(&key[2 * i..2 * i + 2], 16).unwrap())
                .collect();

            let expected: [u8; 16] = unhex(expected);

            let mut block = plaintext;

            Aes::new(&key).encrypt_block(&mut block);

            assert_eq!(block, expected);

            for aes in [Aes::new(&key), Aes::portable(&key)] {
                let mut blocks = [plaintext; 7];

                aes.encrypt_blocks(&mut blocks);

                assert!(blocks.iter().all(|b| *b == expected));
            }
        }
    }

    // The AESAVS known answers for ECB (KAT_AES.zip): GFSbox, KeySbox, VarKey and VarTxt for both
    // key sizes. Every record of the ENCRYPT and the DECRYPT sections is a key, a plaintext and
    // its ciphertext, checked through the AES instructions and through the portable code.
    #[test]
    fn aesavs() {
        let bytes = |text: &str| -> alloc::vec::Vec<u8> {
            (0..text.len() / 2)
                .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
                .collect()
        };

        let mut checked = 0;

        for kind in ["GFSbox", "KeySbox", "VarKey", "VarTxt"] {
            for bits in [128, 256] {
                let path = std::format!(
                    "{}/../vectors/cavp/ECB{kind}{bits}.rsp",
                    env!("CARGO_MANIFEST_DIR")
                );

                let text = std::fs::read_to_string(&path).unwrap();

                let (mut key, mut plaintext) = (alloc::vec::Vec::new(), alloc::vec::Vec::new());

                let mut ciphertext = alloc::vec::Vec::new();

                for line in text.lines().map(str::trim) {
                    let Some((name, value)) = line.split_once(" = ") else {
                        continue;
                    };

                    match name {
                        "KEY" => key = bytes(value),
                        "PLAINTEXT" => plaintext = bytes(value),
                        "CIPHERTEXT" => ciphertext = bytes(value),
                        _ => continue,
                    }

                    if key.len() * 8 == bits && plaintext.len() == 16 && ciphertext.len() == 16 {
                        for aes in [Aes::new(&key), Aes::portable(&key)] {
                            let mut block: [u8; 16] = plaintext[..].try_into().unwrap();

                            aes.encrypt_block(&mut block);

                            assert_eq!(block[..], ciphertext[..], "{path}");
                        }

                        checked += 1;

                        (plaintext, ciphertext) = (alloc::vec::Vec::new(), alloc::vec::Vec::new());
                    }
                }
            }
        }

        // 568 records for AES-128 and 810 for AES-256.
        assert_eq!(checked, 1378);
    }

    // The AES instructions against the portable code, on random keys and blocks, and the round
    // keys of both expansions.
    #[test]
    fn aes_kernel_matches_portable() {
        let mut inputs = crate::cpu::testing::Inputs::new(0xAE5);

        std::eprintln!(
            "AES instructions: {}",
            Aes::new(&[0; 16]).hardware_keys().is_some()
        );

        for n in 0..2_000 {
            let key: [u8; 32] = inputs.bytes();

            let key = &key[..if n % 2 == 0 { 16 } else { 32 }];

            let (fast, portable) = (Aes::new(key), Aes::portable(key));

            let mut blocks: [[u8; 16]; 9] = core::array::from_fn(|_| inputs.bytes());

            let mut expected = blocks;

            fast.encrypt_blocks(&mut blocks[..n % 10]);

            portable.encrypt_blocks(&mut expected[..n % 10]);

            assert_eq!(blocks, expected, "case {n}");

            if let Some(keys) = fast.hardware_keys() {
                let mut words = [0u32; 60];

                expand(key, &mut words[..keys.len() * 4]);

                for (r, round) in keys.iter().enumerate() {
                    assert_eq!(*round, words_of_bytes(&words[4 * r..4 * r + 4]), "case {n}");
                }
            }
        }
    }

    fn words_of_bytes(words: &[u32]) -> [u8; 16] {
        core::array::from_fn(|i| words[i / 4].to_le_bytes()[i % 4])
    }
}
