// BLAKE3 with NEON on several inputs at once, as the reference implementation's hash_many: each
// vector holds one state word of four inputs, so a G function of the specification runs on four
// inputs with each instruction. The message words are transposed into the same form as each
// block is loaded. Rotations by 16 and 8 are a REV32 and a TBL, by 12 and 7 a shift and a
// shift-right-insert. GROUPS sets of four inputs run interleaved: a set alone leaves the vector
// pipes idle while each step's chain of dependent instructions completes.
//
// The extended output of the root runs the same way on four consecutive output blocks, which
// share the chaining value and the message and differ in the counter.
//
// Every instruction is on Arm's data-independent-timing list, and no branch or address depends on
// the data.

use core::arch::aarch64::*;

use super::memory::{load_u8, load_u32, store_u8};
#[cfg(not(crypto_pq_optimized))]
use super::vector_lanes;
use crate::blake3::{Many, PERMUTATION};
use crate::sha2::IV_256;
use crate::wipe::wipe_unless_optimized;

// TBL indices that rotate each 32-bit lane right by 8 bits.
const ROTATE8: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];

#[derive(Clone, Copy)]
struct Rotate8(uint8x16_t);

#[target_feature(enable = "neon")]
#[inline]
fn rotate16(x: uint32x4_t) -> uint32x4_t {
    vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))
}

#[target_feature(enable = "neon")]
#[inline]
fn rotate12(x: uint32x4_t) -> uint32x4_t {
    vsriq_n_u32::<12>(vshlq_n_u32::<20>(x), x)
}

#[target_feature(enable = "neon")]
#[inline]
fn rotate8(x: uint32x4_t, table: Rotate8) -> uint32x4_t {
    vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), table.0))
}

#[target_feature(enable = "neon")]
#[inline]
fn rotate7(x: uint32x4_t) -> uint32x4_t {
    vsriq_n_u32::<7>(vshlq_n_u32::<25>(x), x)
}

// One step of four G functions, (a, b, c, d) = (i, 4 + (i + shift) % 4, ...), of every group,
// with the message words in the order s. A macro, so that it is inlined and its indices into v
// are constants: as a function in the loop of rounds it was called, with the state in memory.
macro_rules! step {
    ($v:ident, $m:ident, $s:ident, $shift:literal, $first:literal, $table:ident) => {{
        let index = |i: usize| -> [usize; 4] {
            [
                i,
                4 + (i + $shift) % 4,
                8 + (i + 2 * $shift) % 4,
                12 + (i + 3 * $shift) % 4,
            ]
        };

        for (v, m) in $v.iter_mut().zip($m.iter()) {
            for i in 0..4 {
                let [a, _, _, _] = index(i);

                v[a] = vaddq_u32(v[a], m[$s[$first + 2 * i] % 16]);
            }
        }

        for (v, _) in $v.iter_mut().zip($m.iter()) {
            for i in 0..4 {
                let [a, b, c, d] = index(i);

                v[a] = vaddq_u32(v[a], v[b]);

                v[d] = rotate16(veorq_u32(v[d], v[a]));

                v[c] = vaddq_u32(v[c], v[d]);

                v[b] = rotate12(veorq_u32(v[b], v[c]));
            }
        }

        for (v, m) in $v.iter_mut().zip($m.iter()) {
            for i in 0..4 {
                let [a, b, c, d] = index(i);

                v[a] = vaddq_u32(vaddq_u32(v[a], m[$s[$first + 2 * i + 1] % 16]), v[b]);

                v[d] = rotate8(veorq_u32(v[d], v[a]), $table);

                v[c] = vaddq_u32(v[c], v[d]);

                v[b] = rotate7(veorq_u32(v[b], v[c]));
            }
        }
    }};
}

// The message word order of each round.
const fn schedule() -> [[usize; 16]; 7] {
    let mut rounds = [[0; 16]; 7];

    let mut i = 0;

    while i < 16 {
        rounds[0][i] = i;

        i += 1;
    }

    let mut r = 1;

    while r < 7 {
        let mut i = 0;

        while i < 16 {
            rounds[r][i] = rounds[r - 1][PERMUTATION[i]];

            i += 1;
        }

        r += 1;
    }

    rounds
}

const SCHEDULE: [[usize; 16]; 7] = schedule();

// The words in their own order, for the rounds of two groups.
const IN_ORDER: [usize; 16] = SCHEDULE[0];

// The seven rounds of two groups, each the columns and then the diagonals, with the message words
// permuted between them by renaming. A macro, so that it is inlined: as a function it was called
// at codegen-units 16, and the state and the words of the caller stayed in its frame.
macro_rules! rounds {
    ($v:ident, $m:ident, $table:ident) => {{
        let mut words = $m;

        let s = &IN_ORDER;

        for r in 0..7 {
            step!($v, words, s, 0, 0, $table);

            step!($v, words, s, 1, 8, $table);

            if r < 6 {
                for m in &mut words {
                    *m = core::array::from_fn(|i| m[PERMUTATION[i]]);
                }
            }
        }

        wipe_unless_optimized!(vector_lanes(&mut words));
    }};
}

// The seven rounds of one group, which reads the message words in each round's order where they
// are: permuted in registers from one round to the next, they and the state took more than the 32
// vector registers, and ten of them went through the stack each round. (Two groups spill their
// state as well; reading their words where they are took more loads and stores than the
// permutation of rounds.) The rounds are written out, so that each word's place is a constant: in
// a loop over SCHEDULE, every word took an index load and an AND before its load. With constant
// places only, the words are register values (D-76), which the compiler spills where it needs to,
// so the callers wipe them below opt-level 3 alone, as two groups' words: a wipe at every block
// gave the words an address, and each block stored them twice, sixteen vectors of zeros included.
// A macro, as rounds: as a function it went out of line at codegen-units 16, with the state through
// memory at each call.
macro_rules! rounds_narrow {
    ($v:ident, $m:ident, $table:ident) => {{
        round_narrow!($v, $m, $table, 0);

        round_narrow!($v, $m, $table, 1);

        round_narrow!($v, $m, $table, 2);

        round_narrow!($v, $m, $table, 3);

        round_narrow!($v, $m, $table, 4);

        round_narrow!($v, $m, $table, 5);

        round_narrow!($v, $m, $table, 6);
    }};
}

// Round r of rounds_narrow.
macro_rules! round_narrow {
    ($v:ident, $m:ident, $table:ident, $r:literal) => {{
        let s = &SCHEDULE[$r];

        step!($v, $m, s, 0, 0, $table);

        step!($v, $m, s, 1, 8, $table);
    }};
}

// The 4x4 transposition of 32-bit words: word i of vector j to word j of vector i.
#[target_feature(enable = "neon")]
#[inline]
fn transpose(x: [uint32x4_t; 4]) -> [uint32x4_t; 4] {
    let t0 = vtrn1q_u32(x[0], x[1]);

    let t1 = vtrn2q_u32(x[0], x[1]);

    let t2 = vtrn1q_u32(x[2], x[3]);

    let t3 = vtrn2q_u32(x[2], x[3]);

    let w = |x: uint32x4_t| vreinterpretq_u64_u32(x);

    [
        vreinterpretq_u32_u64(vtrn1q_u64(w(t0), w(t2))),
        vreinterpretq_u32_u64(vtrn1q_u64(w(t1), w(t3))),
        vreinterpretq_u32_u64(vtrn2q_u64(w(t0), w(t2))),
        vreinterpretq_u32_u64(vtrn2q_u64(w(t1), w(t3))),
    ]
}

// The message words of four blocks, word i of block j in lane j of vector i.
#[target_feature(enable = "neon")]
#[inline]
fn message(blocks: [&[u8; 64]; 4]) -> [uint32x4_t; 16] {
    let mut m = [vdupq_n_u32(0); 16];

    for quarter in 0..4 {
        let rows = blocks.map(|block| {
            let (pieces, _) = block.as_chunks::<16>();

            vreinterpretq_u32_u8(load_u8(&pieces[quarter]))
        });

        let columns = transpose(rows);

        m[4 * quarter..4 * quarter + 4].copy_from_slice(&columns);
    }

    m
}

// Inputs `first` to `first + 4 * GROUPS - 1` of hash_many, of `blocks` blocks each; an index past
// the last input repeats the last one, whose result is then dropped.
#[target_feature(enable = "neon")]
fn hash_group<const GROUPS: usize>(
    input: &[[u8; 64]],
    many: &Many,
    first: usize,
    out: &mut [[u8; 32]],
) {
    let blocks = many.blocks;

    let count = out.len();

    let lane = |g: usize, l: usize| (first + 4 * g + l).min(count - 1);

    let table = Rotate8(load_u8(&ROTATE8));

    let mut h = [[vdupq_n_u32(0); 8]; GROUPS];

    let mut low = [[0; 4]; GROUPS];

    let mut high = [[0; 4]; GROUPS];

    for g in 0..GROUPS {
        for (i, word) in many.key.iter().enumerate() {
            h[g][i] = vdupq_n_u32(*word);
        }

        for l in 0..4 {
            let counter = if many.increment {
                many.counter + lane(g, l) as u64
            } else {
                many.counter
            };

            low[g][l] = counter as u32;

            high[g][l] = (counter >> 32) as u32;
        }
    }

    let low = low.map(|words| load_u32(&words));

    let high = high.map(|words| load_u32(&words));

    let iv = IV_256.map(|w| vdupq_n_u32(w));

    let length = vdupq_n_u32(64);

    for b in 0..blocks {
        let mut flags = many.flags;

        if b == 0 {
            flags |= many.start;
        }

        if b + 1 == blocks {
            flags |= many.end;
        }

        let flags = vdupq_n_u32(flags);

        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut m: [[uint32x4_t; 16]; GROUPS] = core::array::from_fn(|g| {
            message(core::array::from_fn(|l| &input[lane(g, l) * blocks + b]))
        });

        let mut v: [[uint32x4_t; 16]; GROUPS] = core::array::from_fn(|g| {
            [
                h[g][0], h[g][1], h[g][2], h[g][3], h[g][4], h[g][5], h[g][6], h[g][7], iv[0],
                iv[1], iv[2], iv[3], low[g], high[g], length, flags,
            ]
        });

        if GROUPS == 1 {
            rounds_narrow!(v, m, table);
        } else {
            rounds!(v, m, table);
        }

        for g in 0..GROUPS {
            for i in 0..8 {
                h[g][i] = veorq_u32(v[g][i], v[g][i + 8]);
            }
        }

        wipe_unless_optimized!(vector_lanes(&mut v));

        wipe_unless_optimized!(vector_lanes(&mut m));
    }

    for (g, h) in h.iter().enumerate() {
        let low = transpose([h[0], h[1], h[2], h[3]]);

        let high = transpose([h[4], h[5], h[6], h[7]]);

        for (l, (low, high)) in low.iter().zip(&high).enumerate() {
            let index = first + 4 * g + l;

            if index >= count {
                break;
            }

            let (pieces, _) = out[index].as_chunks_mut::<16>();

            store_u8(vreinterpretq_u8_u32(*low), &mut pieces[0]);

            store_u8(vreinterpretq_u8_u32(*high), &mut pieces[1]);
        }
    }

    wipe_unless_optimized!(vector_lanes(&mut h));
}

// hash_many for out.len() inputs: eight at a time, a last six or seven as eight, three to five as
// four (eight lanes cost a third more than four, and a scalar chain half of four), or four at a
// time, a last three as four, if not wide; returns how many it hashed, from the first on. The
// scalar code takes one or two left.
#[target_feature(enable = "neon")]
pub(super) fn hash_many(input: &[u8], many: &Many, out: &mut [[u8; 32]], wide: bool) -> usize {
    // One to sixteen blocks per input, as every caller passes; anything else is left to the
    // portable code, as on x86-64.
    if !(1..=16).contains(&many.blocks) {
        return 0;
    }

    let (input, _) = input.as_chunks::<64>();

    let count = out.len();

    let mut done = 0;

    while wide && count - done >= 6 {
        hash_group::<2>(input, many, done, out);

        done = count.min(done + 8);
    }

    while count - done >= 3 {
        hash_group::<1>(input, many, done, out);

        done = count.min(done + 4);
    }

    done
}

// Each word broadcast to a vector, written out as an array expression: array::map was not inlined
// at codegen-units 16, and it copied the root block and built its vectors in memory.
macro_rules! splat {
    ($words:expr; $($i:literal)+) => {
        [$(vdupq_n_u32($words[$i])),+]
    };
}

// Output blocks counter to counter + 4 * GROUPS - 1 of the root.
#[target_feature(enable = "neon")]
fn xof_group<const GROUPS: usize>(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    [length, flags]: [u32; 2],
    out: &mut [[u8; 64]],
) {
    let table = Rotate8(load_u8(&ROTATE8));

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut m = [splat!(block; 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15); GROUPS];

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut h = splat!(cv; 0 1 2 3 4 5 6 7);

    let iv = IV_256.map(|w| vdupq_n_u32(w));

    let mut v: [[uint32x4_t; 16]; GROUPS] = core::array::from_fn(|g| {
        let counters: [u64; 4] = core::array::from_fn(|l| counter.wrapping_add((4 * g + l) as u64));

        [
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
            load_u32(&counters.map(|c| c as u32)),
            load_u32(&counters.map(|c| (c >> 32) as u32)),
            vdupq_n_u32(length),
            vdupq_n_u32(flags),
        ]
    });

    if GROUPS == 1 {
        rounds_narrow!(v, m, table);
    } else {
        rounds!(v, m, table);
    }

    for (g, v) in v.iter().enumerate() {
        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut words: [uint32x4_t; 16] = core::array::from_fn(|i| {
            if i < 8 {
                veorq_u32(v[i], v[i + 8])
            } else {
                veorq_u32(v[i], h[i - 8])
            }
        });

        for quarter in 0..4 {
            let columns = transpose([
                words[4 * quarter],
                words[4 * quarter + 1],
                words[4 * quarter + 2],
                words[4 * quarter + 3],
            ]);

            for (l, column) in columns.iter().enumerate() {
                let (pieces, _) = out[4 * g + l].as_chunks_mut::<16>();

                store_u8(vreinterpretq_u8_u32(*column), &mut pieces[quarter]);
            }
        }

        wipe_unless_optimized!(vector_lanes(&mut words));
    }

    wipe_unless_optimized!(vector_lanes(&mut v));

    wipe_unless_optimized!(vector_lanes(&mut h));

    wipe_unless_optimized!(vector_lanes(&mut m));
}

// Output blocks counter, counter + 1, ... of the root into out, eight and then four at a time;
// returns how many.
#[target_feature(enable = "neon")]
pub(super) fn xof(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    info: [u32; 2],
    out: &mut [[u8; 64]],
    wide: bool,
) -> usize {
    let mut done = 0;

    while wide && out.len() - done >= 8 {
        xof_group::<2>(
            cv,
            block,
            counter.wrapping_add(done as u64),
            info,
            &mut out[done..done + 8],
        );

        done += 8;
    }

    while out.len() - done >= 4 {
        xof_group::<1>(
            cv,
            block,
            counter.wrapping_add(done as u64),
            info,
            &mut out[done..done + 4],
        );

        done += 4;
    }

    done
}

// One message on the general registers, for a core with LAZY, as BLAKE2 there (blake2.rs): each
// (d ^ a) >>> r is a ROR of d and an EOR with a rotated operand, so the rotation leaves the chain.
// The entry points are out of line, as blake2.rs's process.
mod scalar {
    use super::{IV_256, PERMUTATION, wipe_unless_optimized};
    use crate::wipe::wipe;

    // x, behind an empty assembly block, so that LLVM keeps its rotation one of its own.
    #[inline(always)]
    #[allow(unsafe_code)]
    fn opaque(x: u32) -> u32 {
        let out;

        // SAFETY: an empty template: it reads and writes the one register, no memory, stack or
        // flags.
        unsafe {
            core::arch::asm!(
                "/* {0:w} */",
                inout(reg) x => out,
                options(pure, nomem, nostack, preserves_flags),
            );
        }

        out
    }

    #[inline(always)]
    fn xor_rotate(x: u32, y: u32, r: u32) -> u32 {
        opaque(x.rotate_right(r)) ^ y.rotate_right(r)
    }

    #[inline(always)]
    fn g(v: &mut [u32; 16], [a, b, c, d]: [usize; 4], x: u32, y: u32) {
        v[a] = v[a].wrapping_add(x).wrapping_add(v[b]);

        v[d] = xor_rotate(v[d], v[a], 16);

        v[c] = v[c].wrapping_add(v[d]);

        v[b] = xor_rotate(v[b], v[c], 12);

        v[a] = v[a].wrapping_add(y).wrapping_add(v[b]);

        v[d] = xor_rotate(v[d], v[a], 8);

        v[c] = v[c].wrapping_add(v[d]);

        v[b] = xor_rotate(v[b], v[c], 7);
    }

    #[inline(always)]
    fn round(v: &mut [u32; 16], m: &[u32; 16]) {
        g(v, [0, 4, 8, 12], m[0], m[1]);

        g(v, [1, 5, 9, 13], m[2], m[3]);

        g(v, [2, 6, 10, 14], m[4], m[5]);

        g(v, [3, 7, 11, 15], m[6], m[7]);

        g(v, [0, 5, 10, 15], m[8], m[9]);

        g(v, [1, 6, 11, 12], m[10], m[11]);

        g(v, [2, 7, 8, 13], m[12], m[13]);

        g(v, [3, 4, 9, 14], m[14], m[15]);
    }

    // The seven rounds of a block into v, from the chaining value h; the message words of the
    // block go into m, which the caller wipes.
    #[inline(always)]
    fn rounds(
        v: &mut [u32; 16],
        h: &[u32; 8],
        block: &[u8; 64],
        m: &mut [u32; 16],
        [counter, length, flags]: [u64; 3],
    ) {
        for (word, bytes) in m.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }

        *v = [
            h[0],
            h[1],
            h[2],
            h[3],
            h[4],
            h[5],
            h[6],
            h[7],
            IV_256[0],
            IV_256[1],
            IV_256[2],
            IV_256[3],
            counter as u32,
            (counter >> 32) as u32,
            length as u32,
            flags as u32,
        ];

        // Written out, so that the permutation between the rounds is a renaming of registers.
        round(v, m);

        *m = core::array::from_fn(|i| m[PERMUTATION[i]]);

        round(v, m);

        *m = core::array::from_fn(|i| m[PERMUTATION[i]]);

        round(v, m);

        *m = core::array::from_fn(|i| m[PERMUTATION[i]]);

        round(v, m);

        *m = core::array::from_fn(|i| m[PERMUTATION[i]]);

        round(v, m);

        *m = core::array::from_fn(|i| m[PERMUTATION[i]]);

        round(v, m);

        *m = core::array::from_fn(|i| m[PERMUTATION[i]]);

        round(v, m);
    }

    // As the portable chain_blocks: the chaining value after the blocks, the first with `start`
    // added to the flags and the last with `end`, then `last` if there is one, into cv.
    #[inline(never)]
    pub(in crate::cpu) fn chain(
        cv: &mut [u32; 8],
        blocks: &[[u8; 64]],
        counter: u64,
        flags: u32,
        [start, end]: [u32; 2],
        last: crate::blake3::Last,
    ) {
        let mut h = *cv;

        let mut v = [0; 16];

        let mut m = [0; 16];

        let whole = blocks.len();

        let body = blocks.iter().enumerate().map(|(i, block)| {
            let mut f = flags;

            if i == 0 {
                f |= start;
            }

            if i + 1 == whole {
                f |= end;
            }

            (block, 64, f)
        });

        for (block, length, f) in body.chain(last) {
            rounds(
                &mut v,
                &h,
                block,
                &mut m,
                [counter, length.into(), f.into()],
            );

            for (i, word) in h.iter_mut().enumerate() {
                *word = v[i] ^ v[i + 8];
            }
        }

        *cv = h;

        wipe_unless_optimized!(&mut h);

        wipe_unless_optimized!(&mut v);

        wipe_unless_optimized!(&mut m);
    }

    // At most 32 bytes of the root's output for at most a block of input, whose flags the caller
    // gives, into out.
    #[inline(never)]
    pub(in crate::cpu) fn digest1(key: &[u32; 8], flags: u32, data: &[u8], out: &mut [u8]) {
        let mut copy = [0; 64];

        let block = match <&[u8; 64]>::try_from(data) {
            Ok(block) => block,
            Err(_) => {
                copy[..data.len()].copy_from_slice(data);

                &copy
            }
        };

        let mut v = [0; 16];

        let mut m = [0; 16];

        rounds(
            &mut v,
            key,
            block,
            &mut m,
            [0, data.len() as u64, flags.into()],
        );

        let mut bytes = [0; 32];

        for (i, chunk) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            *chunk = (v[i] ^ v[i + 8]).to_le_bytes();
        }

        out.copy_from_slice(&bytes[..out.len()]);

        wipe(&mut copy);

        wipe(&mut bytes);

        wipe_unless_optimized!(&mut v);

        wipe_unless_optimized!(&mut m);
    }

    // All sixteen output words of one compression into out.
    #[inline(never)]
    pub(in crate::cpu) fn compress(
        cv: &[u32; 8],
        block: &[u8; 64],
        counter: u64,
        [length, flags]: [u32; 2],
        out: &mut [u32; 16],
    ) {
        let mut v = [0; 16];

        let mut m = [0; 16];

        rounds(
            &mut v,
            cv,
            block,
            &mut m,
            [counter, length.into(), flags.into()],
        );

        for (i, word) in out.iter_mut().enumerate() {
            *word = if i < 8 {
                v[i] ^ v[i + 8]
            } else {
                v[i] ^ cv[i - 8]
            };
        }

        wipe_unless_optimized!(&mut v);

        wipe_unless_optimized!(&mut m);
    }
}

pub(super) use scalar::{chain, compress, digest1};
