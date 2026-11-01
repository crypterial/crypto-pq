// BLAKE2b and BLAKE2s on the general registers, for a core on which an EOR with a rotated operand
// costs a plain EOR (LAZY in aarch64.rs): each (d ^ a) >>> r of a G function is taken as
// (d >>> r) ^ (a >>> r), one ROR of d, which was ready a step before, and one EOR with a rotated
// operand, so the rotation leaves the chain of dependent instructions. LLVM folds the two
// rotations back into one of the XOR, so the rotation of d goes through an empty assembly block.
// The state and the message words stay in registers from block to block, as in the portable
// code. ROR and EOR, shifted or not, are on Arm's data-independent-timing list.

use crate::blake2::{Last, SIGMA, Word};
use crate::wipe::wipe_unless_optimized;

// A value that the compiler cannot see through: its rotation stays one of its own.
pub(super) trait Opaque: Copy {
    fn opaque(self) -> Self;
}

impl Opaque for u64 {
    #[inline(always)]
    #[allow(unsafe_code)]
    fn opaque(self) -> Self {
        let out;

        // SAFETY: an empty template: it reads and writes the one register, no memory, stack or
        // flags.
        unsafe {
            core::arch::asm!(
                "/* {0} */",
                inout(reg) self => out,
                options(pure, nomem, nostack, preserves_flags),
            );
        }

        out
    }
}

impl Opaque for u32 {
    #[inline(always)]
    #[allow(unsafe_code)]
    fn opaque(self) -> Self {
        let out;

        // SAFETY: as for u64.
        unsafe {
            core::arch::asm!(
                "/* {0:w} */",
                inout(reg) self => out,
                options(pure, nomem, nostack, preserves_flags),
            );
        }

        out
    }
}

// (x ^ y) >>> r with the rotation of x off the chain that y is on.
#[inline(always)]
fn xor_rotate<W: Word + Opaque>(x: W, y: W, r: u32) -> W {
    x.rotate(r).opaque() ^ y.rotate(r)
}

#[inline(always)]
fn g<W: Word + Opaque>(v: &mut [W; 16], [a, b, c, d]: [usize; 4], x: W, y: W) {
    let [r1, r2, r3, r4] = W::ROTATIONS;

    v[a] = v[a].add(x).add(v[b]);

    v[d] = xor_rotate(v[d], v[a], r1);

    v[c] = v[c].add(v[d]);

    v[b] = xor_rotate(v[b], v[c], r2);

    v[a] = v[a].add(y).add(v[b]);

    v[d] = xor_rotate(v[d], v[a], r3);

    v[c] = v[c].add(v[d]);

    v[b] = xor_rotate(v[b], v[c], r4);
}

#[inline(always)]
fn round<W: Word + Opaque>(v: &mut [W; 16], m: &[W; 16], s: &[usize; 16]) {
    g(v, [0, 4, 8, 12], m[s[0]], m[s[1]]);

    g(v, [1, 5, 9, 13], m[s[2]], m[s[3]]);

    g(v, [2, 6, 10, 14], m[s[4]], m[s[5]]);

    g(v, [3, 7, 11, 15], m[s[6]], m[s[7]]);

    g(v, [0, 5, 10, 15], m[s[8]], m[s[9]]);

    g(v, [1, 6, 11, 12], m[s[10]], m[s[11]]);

    g(v, [2, 7, 8, 13], m[s[12]], m[s[13]]);

    g(v, [3, 4, 9, 14], m[s[14]], m[s[15]]);
}

// The compression of RFC 7693, 3.2, into h.
#[inline(always)]
fn compress<W: Word + Opaque>(h: &mut [W; 8], m: &[W; 16], counter: u128, last: bool) {
    let iv = W::IV;

    let [t0, t1] = W::counter(counter);

    let mut v = [
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        iv[0],
        iv[1],
        iv[2],
        iv[3],
        iv[4] ^ t0,
        iv[5] ^ t1,
        if last { !iv[6] } else { iv[6] },
        iv[7],
    ];

    round(&mut v, m, &SIGMA[0]);

    round(&mut v, m, &SIGMA[1]);

    round(&mut v, m, &SIGMA[2]);

    round(&mut v, m, &SIGMA[3]);

    round(&mut v, m, &SIGMA[4]);

    round(&mut v, m, &SIGMA[5]);

    round(&mut v, m, &SIGMA[6]);

    round(&mut v, m, &SIGMA[7]);

    round(&mut v, m, &SIGMA[8]);

    round(&mut v, m, &SIGMA[9]);

    if W::ROUNDS == 12 {
        round(&mut v, m, &SIGMA[0]);

        round(&mut v, m, &SIGMA[1]);
    }

    for (i, word) in h.iter_mut().enumerate() {
        *word = *word ^ v[i] ^ v[i + 8];
    }

    wipe_unless_optimized!(&mut v);
}

// The work of blake2.rs's process: first (a MAC's key block), the whole blocks of bytes and the
// final block, into h, counter the number of bytes before the first of them. One loop with one
// compression in it takes all three, so that its code is there once. Out of line, so that the
// portable code that other cores run, from which it is called, keeps its size.
#[inline(never)]
pub(super) fn process<W: Word + Opaque>(
    h: &mut [W; 8],
    first: Option<&[W; 16]>,
    blocks: &[u8],
    counter: u128,
    last: Last<'_, W>,
) {
    let size = 16 * W::BYTES;

    let count = usize::from(first.is_some()) + blocks.len() / size + usize::from(last.is_some());

    let mut state = *h;

    let mut m = [W::default(); 16];

    let mut counter = counter;

    for i in 0..count {
        let k = i.wrapping_sub(usize::from(first.is_some()));

        let final_block = last.is_some() && i + 1 == count;

        match (first, last) {
            (Some(first), _) if i == 0 => m = *first,
            (_, Some((words, _))) if final_block => m = *words,
            _ => {
                let block = &blocks[k * size..(k + 1) * size];

                for (word, bytes) in m.iter_mut().zip(block.chunks_exact(W::BYTES)) {
                    *word = W::from_le(bytes);
                }
            }
        }

        counter = match last {
            Some((_, total)) if final_block => total,
            _ => counter.wrapping_add(size as u128),
        };

        compress(&mut state, &m, counter, final_block);
    }

    *h = state;

    wipe_unless_optimized!(&mut state);

    wipe_unless_optimized!(&mut m);
}
