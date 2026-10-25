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
use crate::blake3::{Many, PERMUTATION};
use crate::sha2::IV_256;

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

// One step of four G functions, (a, b, c, d) = (i, 4 + (i + shift) % 4, ...), of every group.
#[target_feature(enable = "neon")]
#[inline]
fn step<const GROUPS: usize>(
    v: &mut [[uint32x4_t; 16]; GROUPS],
    m: &[[uint32x4_t; 16]; GROUPS],
    shift: usize,
    first: usize,
    table: Rotate8,
) {
    let index = |i: usize| -> [usize; 4] {
        [
            i,
            4 + (i + shift) % 4,
            8 + (i + 2 * shift) % 4,
            12 + (i + 3 * shift) % 4,
        ]
    };

    for (v, m) in v.iter_mut().zip(m) {
        for i in 0..4 {
            let [a, _, _, _] = index(i);

            v[a] = vaddq_u32(v[a], m[first + 2 * i]);
        }
    }

    for (v, _) in v.iter_mut().zip(m) {
        for i in 0..4 {
            let [a, b, c, d] = index(i);

            v[a] = vaddq_u32(v[a], v[b]);

            v[d] = rotate16(veorq_u32(v[d], v[a]));

            v[c] = vaddq_u32(v[c], v[d]);

            v[b] = rotate12(veorq_u32(v[b], v[c]));
        }
    }

    for (v, m) in v.iter_mut().zip(m) {
        for i in 0..4 {
            let [a, b, c, d] = index(i);

            v[a] = vaddq_u32(vaddq_u32(v[a], m[first + 2 * i + 1]), v[b]);

            v[d] = rotate8(veorq_u32(v[d], v[a]), table);

            v[c] = vaddq_u32(v[c], v[d]);

            v[b] = rotate7(veorq_u32(v[b], v[c]));
        }
    }
}

// The seven rounds, each the columns and then the diagonals, with the message words permuted
// between them by renaming.
#[target_feature(enable = "neon")]
#[inline]
fn rounds<const GROUPS: usize>(
    v: &mut [[uint32x4_t; 16]; GROUPS],
    m: &[[uint32x4_t; 16]; GROUPS],
    table: Rotate8,
) {
    let mut m = *m;

    for r in 0..7 {
        step(v, &m, 0, 0, table);

        step(v, &m, 1, 8, table);

        if r < 6 {
            for m in &mut m {
                *m = core::array::from_fn(|i| m[PERMUTATION[i]]);
            }
        }
    }
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

        let m: [[uint32x4_t; 16]; GROUPS] = core::array::from_fn(|g| {
            message(core::array::from_fn(|l| &input[lane(g, l) * blocks + b]))
        });

        let mut v: [[uint32x4_t; 16]; GROUPS] = core::array::from_fn(|g| {
            [
                h[g][0], h[g][1], h[g][2], h[g][3], h[g][4], h[g][5], h[g][6], h[g][7], iv[0],
                iv[1], iv[2], iv[3], low[g], high[g], length, flags,
            ]
        });

        rounds(&mut v, &m, table);

        for g in 0..GROUPS {
            for i in 0..8 {
                h[g][i] = veorq_u32(v[g][i], v[g][i + 8]);
            }
        }
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
}

// hash_many for out.len() inputs: eight at a time, a last six or seven as eight, three to five as
// four (eight lanes cost a third more than four, and a scalar chain half of four); returns how
// many it hashed, from the first on. The scalar code takes one or two left.
#[target_feature(enable = "neon")]
pub(super) fn hash_many(input: &[u8], many: &Many, out: &mut [[u8; 32]]) -> usize {
    // One to sixteen blocks per input, as every caller passes; anything else is left to the
    // portable code, as on x86-64.
    if !(1..=16).contains(&many.blocks) {
        return 0;
    }

    let (input, _) = input.as_chunks::<64>();

    let count = out.len();

    let mut done = 0;

    while count - done >= 6 {
        hash_group::<2>(input, many, done, out);

        done = count.min(done + 8);
    }

    if count - done >= 3 {
        hash_group::<1>(input, many, done, out);

        done = count.min(done + 4);
    }

    done
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

    let m = [block.map(|w| vdupq_n_u32(w)); GROUPS];

    let h = cv.map(|w| vdupq_n_u32(w));

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

    rounds(&mut v, &m, table);

    for (g, v) in v.iter().enumerate() {
        let words: [uint32x4_t; 16] = core::array::from_fn(|i| {
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
    }
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
) -> usize {
    let mut done = 0;

    while out.len() - done >= 8 {
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
