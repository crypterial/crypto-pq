// Rejection sampling with NEON on a block of XOF output, given as the 64-bit lanes of the Keccak
// state: the candidates are compared with their bound side by side, and TBL moves the accepted
// ones together, with shuffle indices from a table indexed by the pattern of accepted lanes. Each
// step stores a whole vector at the count of accepted values and advances the count by the number
// accepted, so it overwrites slots after the last accepted value, which later values or the end
// of the polynomial replace; near the end the candidates go one at a time, as in the portable
// code.
//
// The uniform samplers serve the matrix, which is public, so their patterns may index memory.
// The bounded sampler serves ML-DSA's secret s1 and s2. Which of its candidates are rejected is
// public, as the portable code also has it: each half-byte of the SHAKE256 stream is uniform and
// independent of the others, so the positions of the rejected ones, which are discarded, say
// nothing about the accepted values. Its pattern is declassified for the constant-time check
// before it indexes the table; the values never steer a branch or an address.

use core::arch::aarch64::*;

use super::memory::{load_u8, load_u64, store_i32, store_u16};
use crate::ct::declassify_value;

// Shuffle indices that bring the accepted lanes of a vector of LANES lanes, WIDTH bytes each, to
// its start in order, for every pattern of accepted lanes; 0xFF selects zero for the rest.
const fn compaction<const LANES: usize, const WIDTH: usize, const PATTERNS: usize>()
-> [[u8; 16]; PATTERNS] {
    let mut table = [[0xFF; 16]; PATTERNS];

    let mut pattern = 0;

    while pattern < PATTERNS {
        let mut next = 0;

        let mut lane = 0;

        while lane < LANES {
            if pattern & (1 << lane) != 0 {
                let mut byte = 0;

                while byte < WIDTH {
                    table[pattern][WIDTH * next + byte] = (WIDTH * lane + byte) as u8;

                    byte += 1;
                }

                next += 1;
            }

            lane += 1;
        }

        pattern += 1;
    }

    table
}

static COMPACT_32: [[u8; 16]; 16] = compaction::<4, 4, 16>();

static COMPACT_16: [[u8; 16]; 256] = compaction::<8, 2, 256>();

static COMPACT_8: [[u8; 16]; 256] = compaction::<8, 1, 256>();

// The number of accepted lanes of every pattern: a load is quicker than counting the bits, which
// NEON does through a vector register.
static ACCEPTED: [u8; 256] = {
    let mut counts = [0; 256];

    let mut pattern = 0;

    while pattern < 256 {
        counts[pattern] = (pattern as u32).count_ones() as u8;

        pattern += 1;
    }

    counts
};

#[allow(unsafe_code)]
pub(crate) fn uniform12(lanes: &[u64; 21], q: u16, a: &mut [u16; 256], count: &mut usize) -> bool {
    // SAFETY: NEON is part of every target this module is built for.
    unsafe { uniform12_neon(lanes, q, a, count) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn uniform23(lanes: &[u64; 21], q: i32, a: &mut [i32; 256], count: &mut usize) -> bool {
    // SAFETY: as in uniform12.
    unsafe { uniform23_neon(lanes, q, a, count) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn bounded(lanes: &[u64; 17], eta: i32, a: &mut [i32; 256], count: &mut usize) -> bool {
    if eta != 2 && eta != 4 {
        return false;
    }

    // SAFETY: as in uniform12.
    unsafe { bounded_neon(lanes, eta, a, count) };

    true
}

// Lanes i and i + 1 of a group of three, as bytes.
#[target_feature(enable = "neon")]
#[inline]
fn two(lanes: &[u64; 3], i: usize) -> uint8x16_t {
    let pair = lanes[i..i + 2].try_into().expect("two lanes");

    vreinterpretq_u8_u64(load_u64(pair))
}

#[target_feature(enable = "neon")]
#[inline]
fn load_u16_constant(values: [u16; 8]) -> uint16x8_t {
    super::memory::load_u16(&values)
}

// The bytes of three lanes, for the candidates left to the scalar code.
fn bytes24(lanes: &[u64; 3]) -> [u8; 24] {
    let mut bytes = [0; 24];

    for (out, lane) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(lanes) {
        *out = lane.to_le_bytes();
    }

    bytes
}

// ML-KEM (FIPS 203, Algorithm 7): two candidates of 12 bits from every three bytes. Each step
// takes three lanes, 24 bytes, as two vectors of eight candidates in 16-bit lanes: bytes 0 to 11
// of the first sixteen and bytes 4 to 15 of the last sixteen.
#[target_feature(enable = "neon")]
fn uniform12_neon(lanes: &[u64; 21], q: u16, a: &mut [u16; 256], count: &mut usize) {
    const PAIRS: [u8; 16] = [0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11];

    let indices = [load_u8(&PAIRS), load_u8(&PAIRS.map(|i| i + 4))];

    let shifts = vreinterpretq_s16_u64(vdupq_n_u64(0xFFFC_0000_FFFC_0000));

    let (mask, bound) = (vdupq_n_u16(0x0FFF), vdupq_n_u16(q));

    let bits = load_u16_constant([1, 2, 4, 8, 16, 32, 64, 128]);

    let groups = lanes.as_chunks::<3>().0;

    let (mut step, mut filled) = (0, *count);

    while step < groups.len() && filled <= 256 - 16 {
        let group = &groups[step];

        for (bytes, indices) in [two(group, 0), two(group, 1)].into_iter().zip(indices) {
            let pairs = vreinterpretq_u16_u8(vqtbl1q_u8(bytes, indices));

            let candidates = vandq_u16(vshlq_u16(pairs, shifts), mask);

            let accepted = vandq_u16(vcltq_u16(candidates, bound), bits);

            let pattern = usize::from(vaddvq_u16(accepted) as u8);

            let packed = vqtbl1q_u8(
                vreinterpretq_u8_u16(candidates),
                load_u8(&COMPACT_16[pattern]),
            );

            let out = (&mut a[filled..filled + 8]).try_into().expect("eight");

            store_u16(vreinterpretq_u16_u8(packed), out);

            filled += usize::from(ACCEPTED[pattern]);
        }

        step += 1;
    }

    *count = filled;

    for group in &groups[step..] {
        for chunk in bytes24(group).as_chunks::<3>().0 {
            let d1 = u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0F) << 8);

            let d2 = u16::from(chunk[1] >> 4) | (u16::from(chunk[2]) << 4);

            for candidate in [d1, d2] {
                if *count == 256 {
                    return;
                }

                a[*count] = candidate;

                *count += usize::from(candidate < q);
            }
        }
    }
}

// ML-DSA (FIPS 204, Algorithm 30): a candidate of 23 bits from every three bytes. Each step takes
// three lanes, 24 bytes, as two vectors of four candidates in 32-bit lanes.
#[target_feature(enable = "neon")]
fn uniform23_neon(lanes: &[u64; 21], q: i32, a: &mut [i32; 256], count: &mut usize) {
    const TRIPLES: [u8; 16] = [0, 1, 2, 255, 3, 4, 5, 255, 6, 7, 8, 255, 9, 10, 11, 255];

    let indices = [
        load_u8(&TRIPLES),
        load_u8(&TRIPLES.map(|i| i.saturating_add(4))),
    ];

    let (mask, bound) = (vdupq_n_u32(0x7F_FFFF), vdupq_n_u32(q as u32));

    let bits = vreinterpretq_u32_u16(load_u16_constant([1, 0, 2, 0, 4, 0, 8, 0]));

    let groups = lanes.as_chunks::<3>().0;

    let (mut step, mut filled) = (0, *count);

    while step < groups.len() && filled <= 256 - 8 {
        let group = &groups[step];

        let candidates = [
            vandq_u32(
                vreinterpretq_u32_u8(vqtbl1q_u8(two(group, 0), indices[0])),
                mask,
            ),
            vandq_u32(
                vreinterpretq_u32_u8(vqtbl1q_u8(two(group, 1), indices[1])),
                mask,
            ),
        ];

        let accepted = candidates.map(|candidates| vcltq_u32(candidates, bound));

        // All but one candidate in a thousand are accepted, so most steps store all eight; the
        // matrix is public, so this branch may depend on it.
        if vminvq_u32(vandq_u32(accepted[0], accepted[1])) == u32::MAX {
            let out: &mut [i32; 8] = (&mut a[filled..filled + 8]).try_into().expect("eight");

            let [low, high] = out.as_chunks_mut::<4>().0 else {
                unreachable!("eight values are two groups of four")
            };

            store_i32(vreinterpretq_s32_u32(candidates[0]), low);

            store_i32(vreinterpretq_s32_u32(candidates[1]), high);

            filled += 8;
        } else {
            for (candidates, accepted) in candidates.into_iter().zip(accepted) {
                let pattern = (vaddvq_u32(vandq_u32(accepted, bits)) & 15) as usize;

                let packed = vqtbl1q_u8(
                    vreinterpretq_u8_u32(candidates),
                    load_u8(&COMPACT_32[pattern]),
                );

                let out = (&mut a[filled..filled + 4]).try_into().expect("four");

                store_i32(vreinterpretq_s32_u8(packed), out);

                filled += usize::from(ACCEPTED[pattern]);
            }
        }

        step += 1;
    }

    *count = filled;

    for group in &groups[step..] {
        for chunk in bytes24(group).as_chunks::<3>().0 {
            let z = i32::from(chunk[0])
                | (i32::from(chunk[1]) << 8)
                | (i32::from(chunk[2] & 0x7F) << 16);

            if z < q && *count < 256 {
                a[*count] = z;

                *count += 1;
            }
        }
    }
}

// ML-DSA (FIPS 204, Algorithm 31 inside 33): sixteen half-bytes from each lane, in 8-bit lanes in
// stream order, mapped to 2 - x mod 5 for eta = 2 (x below 15; 13 x >> 6 is x / 5 there) or to
// 4 - x for eta = 4 (x below 9), then compacted eight at a time.
#[target_feature(enable = "neon")]
fn bounded_neon(lanes: &[u64; 17], eta: i32, a: &mut [i32; 256], count: &mut usize) {
    let bound = vdup_n_u8(if eta == 2 { 15 } else { 9 });

    let bits = vcreate_u8(0x8040_2010_0804_0201);

    let (mut step, mut filled) = (0, *count);

    while step < lanes.len() && filled <= 256 - 16 {
        let bytes = vcreate_u8(lanes[step]);

        let (low, high) = (vand_u8(bytes, vdup_n_u8(0x0F)), vshr_n_u8::<4>(bytes));

        for half in [vzip1_u8(low, high), vzip2_u8(low, high)] {
            let values = if eta == 2 {
                let fifth = vshr_n_u8::<6>(vmul_u8(half, vdup_n_u8(13)));

                vsub_u8(vdup_n_u8(2), vsub_u8(half, vmul_u8(fifth, vdup_n_u8(5))))
            } else {
                vsub_u8(vdup_n_u8(4), half)
            };

            let accepted = vand_u8(vclt_u8(half, bound), bits);

            let pattern = usize::from(declassify_value(vaddv_u8(accepted)));

            let indices = vcreate_u8(u64::from_le_bytes(COMPACT_8[pattern].as_chunks::<8>().0[0]));

            let packed = vmovl_s8(vreinterpret_s8_u8(vtbl1_u8(values, indices)));

            let wide = [vmovl_s16(vget_low_s16(packed)), vmovl_high_s16(packed)];

            for (i, vector) in wide.into_iter().enumerate() {
                let start = filled + 4 * i;

                store_i32(vector, (&mut a[start..start + 4]).try_into().expect("four"));
            }

            filled += usize::from(ACCEPTED[pattern]);
        }

        step += 1;
    }

    *count = filled;

    for half in lanes[step..]
        .iter()
        .flat_map(|lane| lane.to_le_bytes())
        .flat_map(|byte| [byte & 0x0F, byte >> 4])
    {
        if *count == 256 {
            return;
        }

        let half = i32::from(half);

        let (value, accepted) = if eta == 2 {
            (2 - (half - 5 * ((205 * half) >> 10)), half < 15)
        } else {
            (4 - half, half < 9)
        };

        a[*count] = value;

        *count += usize::from(declassify_value(accepted));
    }
}
