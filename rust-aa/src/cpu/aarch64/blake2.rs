// BLAKE2b and BLAKE2s on the general registers, for a core on which an EOR with a rotated operand
// costs a plain EOR (LAZY in aarch64.rs): each (d ^ a) >>> r of a G function is taken as
// (d >>> r) ^ (a >>> r), one ROR of d, which was ready a step before, and one EOR with a rotated
// operand, so the rotation leaves the chain of dependent instructions. LLVM folds the two
// rotations back into one of the XOR, so the rotation of d goes through an empty assembly block.
// The state stays in registers from block to block, as in the portable code, and each round loads
// its message words from the block (compress). ROR and EOR, shifted or not, are on Arm's
// data-independent-timing list.

use crate::blake2::{Last, SIGMA, Word};
use crate::wipe::wipe_unless_optimized;

// A value that the compiler cannot see through: its rotation stays one of its own. STATIC_IV is
// the IV in memory, for compress to load.
pub(super) trait Opaque: Copy + 'static {
    const STATIC_IV: &'static [Self; 8];

    fn opaque(self) -> Self;
}

impl Opaque for u64 {
    const STATIC_IV: &'static [Self; 8] = &<Self as Word>::IV;

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
    const STATIC_IV: &'static [Self; 8] = &<Self as Word>::IV;

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

// A reference that the compiler cannot see through, so that what it points to is loaded where it
// is read. The address only passes through the template, which reads no memory: nomem holds.
#[inline(always)]
#[allow(unsafe_code)]
#[allow(clippy::pointers_in_nomem_asm_block)]
fn opaque_ref<T>(value: &T) -> &T {
    let mut address: *const T = value;

    // SAFETY: an empty template: it reads and writes the one register, no memory, stack or flags,
    // so the address that comes out is the one that went in, of a value borrowed for the lifetime
    // of the result. Not pure, so that the compiler keeps it, and the loads after it, in every
    // block.
    unsafe {
        core::arch::asm!(
            "/* {0} */",
            inout(reg) address,
            options(nomem, nostack, preserves_flags),
        );

        &*address
    }
}

// Bytes through an address that the compiler cannot see through, as opaque_ref.
#[inline(always)]
#[allow(unsafe_code)]
#[allow(clippy::pointers_in_nomem_asm_block)]
fn opaque_bytes(bytes: &[u8]) -> &[u8] {
    let mut address = bytes.as_ptr();

    // SAFETY: as in opaque_ref, the address that comes out is the one that went in: the slice is
    // the one borrowed, at its length.
    unsafe {
        core::arch::asm!(
            "/* {0} */",
            inout(reg) address,
            options(nomem, nostack, preserves_flags),
        );

        core::slice::from_raw_parts(address, bytes.len())
    }
}

// The bytes of a block of words, which on these little-endian targets are its encoding.
#[inline(always)]
#[allow(unsafe_code)]
fn bytes_of<W: Word>(words: &[W; 16]) -> &[u8] {
    // SAFETY: the words are u32 or u64 values, with no padding, so every byte of the array is
    // initialized, and a u8 has alignment 1: the slice covers the array and borrows it.
    unsafe {
        core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), core::mem::size_of_val(words))
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

// A round on the message words of a block's bytes, which it reads through an address that the
// compiler cannot see through. It returns that address for the next round: a copy of one address
// for each round took a move each.
#[inline(always)]
fn round<'a, W: Word + Opaque>(v: &mut [W; 16], block: &'a [u8], s: &[usize; 16]) -> &'a [u8] {
    let block = opaque_bytes(block);

    let m = |i: usize| W::from_le(&block[s[i] * W::BYTES..]);

    g(v, [0, 4, 8, 12], m(0), m(1));

    g(v, [1, 5, 9, 13], m(2), m(3));

    g(v, [2, 6, 10, 14], m(4), m(5));

    g(v, [3, 7, 11, 15], m(6), m(7));

    g(v, [0, 5, 10, 15], m(8), m(9));

    g(v, [1, 6, 11, 12], m(10), m(11));

    g(v, [2, 7, 8, 13], m(12), m(13));

    g(v, [3, 4, 9, 14], m(14), m(15));

    block
}

// The compression of RFC 7693, 3.2, of a block's bytes into h. Each round loads the message words
// again (round): held in registers for the whole block, the words left the state too few
// registers, and the moves between registers that followed ran on the integer pipes that bound
// this loop on Neoverse N2, where a load has pipes of its own. The IV is loaded in every block for
// the same reason: as constants, LLVM built each word with four instructions in every block.
#[inline(always)]
fn compress<W: Word + Opaque>(h: &mut [W; 8], block: &[u8], counter: u128, last: bool) {
    let iv = opaque_ref(W::STATIC_IV);

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

    let m = round(&mut v, block, &SIGMA[0]);

    let m = round(&mut v, m, &SIGMA[1]);

    let m = round(&mut v, m, &SIGMA[2]);

    let m = round(&mut v, m, &SIGMA[3]);

    let m = round(&mut v, m, &SIGMA[4]);

    let m = round(&mut v, m, &SIGMA[5]);

    let m = round(&mut v, m, &SIGMA[6]);

    let m = round(&mut v, m, &SIGMA[7]);

    let m = round(&mut v, m, &SIGMA[8]);

    let m = round(&mut v, m, &SIGMA[9]);

    if W::ROUNDS == 12 {
        let m = round(&mut v, m, &SIGMA[0]);

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
// portable code that other cores run, from which it is called, keeps its size. The rounds read
// the message from the caller's blocks, so this function holds no copy of it.
#[inline(never)]
pub(super) fn process<W: Word + Opaque>(
    h: &mut [W; 8],
    first: Option<&[W; 16]>,
    blocks: &[u8],
    counter: u128,
    last: Last<'_, W>,
) {
    let size = 16 * W::BYTES;

    let mut first = first;

    let mut blocks = blocks.chunks_exact(size);

    let mut last = last;

    let mut state = *h;

    let mut counter = counter;

    // The key block, the whole blocks and the final block in turn: a whole block costs a test and
    // the iterator's step, where an index over the three took a dozen instructions on the integer
    // pipes.
    loop {
        let (block, block_counter, final_block) = if let Some(words) = first.take() {
            (bytes_of(words), counter.wrapping_add(size as u128), false)
        } else if let Some(block) = blocks.next() {
            (block, counter.wrapping_add(size as u128), false)
        } else if let Some((words, total)) = last.take() {
            (bytes_of(words), total, true)
        } else {
            break;
        };

        counter = block_counter;

        compress(&mut state, block, counter, final_block);
    }

    *h = state;

    wipe_unless_optimized!(&mut state);
}
