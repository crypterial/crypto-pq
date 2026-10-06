// The Ascon permutation on the scalar pipes, with every rotation its own instruction. The
// compiler folds each rotation of the linear layer into the XOR that consumes it, an EOR with a
// rotated operand, which takes two cycles on an Apple M3 and runs on half of the pipes; an XOR
// and a ROR take one cycle each on all of them. Each round also takes the next round's constant
// into its linear layer, off the critical path, and keeps x2 uncomplemented: the S-box's final NOT
// becomes an EON there.

use core::arch::asm;

use crate::sha2::last_bytes;

const CONSTANTS: [u64; 12] = [
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B,
];

#[inline(always)]
#[allow(unsafe_code)]
fn ror<const R: u32>(x: u64) -> u64 {
    let out: u64;

    // SAFETY: one instruction on registers; it reads and writes no memory, stack or flags.
    unsafe {
        asm!(
            "ror {out}, {x}, #{r}",
            out = lateout(reg) out,
            x = in(reg) x,
            r = const R,
            options(pure, nomem, nostack, preserves_flags),
        );
    }

    out
}

// One round on a state whose x2 already holds this round's constant; the result's x2 holds
// `next`, the next round's constant (0 after the last round).
#[inline(always)]
fn round(s: &mut [u64; 5], next: u64) {
    let [mut x0, mut x1, mut x2, mut x3, mut x4] = *s;

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

    // Sigma_2 of the complement of x2: !(x2 ^ ror(x2, 1) ^ ror(x2, 6)), and the next constant.
    *s = [
        x0 ^ ror::<19>(x0) ^ ror::<28>(x0),
        x1 ^ ror::<61>(x1) ^ ror::<39>(x1),
        (x2 ^ ror::<1>(x2)) ^ !(ror::<6>(x2) ^ next),
        x3 ^ ror::<10>(x3) ^ ror::<17>(x3),
        x4 ^ ror::<7>(x4) ^ ror::<41>(x4),
    ];
}

#[inline(always)]
fn permute(s: &mut [u64; 5]) {
    s[2] ^= CONSTANTS[0];

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

    round(s, 0);
}

pub(crate) fn ascon(s: &mut [u64; 5]) -> bool {
    permute(s);

    true
}

// crate::ascon's digest with the state in registers throughout: the whole eight-byte blocks of
// data, its padded last block, then out.len() bytes.
pub(crate) fn ascon_digest(start: &[u64; 5], data: &[u8], out: &mut [u8]) -> bool {
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

    true
}
