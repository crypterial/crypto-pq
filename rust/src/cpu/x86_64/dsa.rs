// ML-DSA's coefficient-wise steps of signing and its rejection samplers with AVX2, eight 32-bit
// coefficients per vector, value for value what the portable code computes: sums and differences
// modulo q, the norm checks, the hints, Decompose with the encoding of w1, the expansion of the
// mask, and the uniform and bounded rejection sampling. The steps on secret values use
// data-processing instructions only; the checks return their outcome as a mask, which the caller
// declassifies only as the decision to restart. The samplers compact the accepted candidates with
// a permutation chosen by their pattern: the uniform one serves the public matrix, and the bounded
// one's pattern is declassified first, as the portable code does (see sample_bounded_portable).

use core::arch::x86_64::*;

use super::kem::ACCEPTED;
use super::memory::{load128, load256, store128, store256};
use crate::cpu::Pack;
use crate::ct::declassify_value;

// (-q, q) to [0, q).
#[target_feature(enable = "avx2")]
#[inline]
fn freeze(x: __m256i, q: __m256i) -> __m256i {
    _mm256_add_epi32(x, _mm256_and_si256(q, _mm256_srai_epi32::<31>(x)))
}

// out = a + b or a - b modulo q, for canonical a and b.
#[target_feature(enable = "avx2")]
pub(super) fn combine<const ADD: bool>(
    out: &mut [i32; 256],
    a: &[i32; 256],
    b: &[i32; 256],
    q: i32,
) {
    let q = _mm256_set1_epi32(q);

    let operands = a.as_chunks::<8>().0.iter().zip(b.as_chunks::<8>().0);

    for (out, (a, b)) in out.as_chunks_mut::<8>().0.iter_mut().zip(operands) {
        let (a, b) = (load256(a), load256(b));

        let x = if ADD {
            _mm256_sub_epi32(_mm256_add_epi32(a, b), q)
        } else {
            _mm256_sub_epi32(a, b)
        };

        store256(freeze(x, q), out);
    }
}

// FIPS 204, Algorithm 36, branch-free as decompose in mldsa.rs: (r1, r0) for r in [0, q), with
// WIDE for gamma2 = (q - 1) / 32, where 2 gamma2 r1 is (r1 << 19) - (r1 << 9), and otherwise
// gamma2 = (q - 1) / 88.
#[target_feature(enable = "avx2")]
#[inline]
fn decompose<const WIDE: bool>(r: __m256i, gamma2: i32, q: i32) -> (__m256i, __m256i) {
    let r1 = _mm256_srai_epi32::<7>(_mm256_add_epi32(r, _mm256_set1_epi32(127)));

    let (r1, product) = if WIDE {
        let t = _mm256_add_epi32(_mm256_slli_epi32::<10>(r1), r1);

        let r1 = _mm256_and_si256(
            _mm256_srai_epi32::<22>(_mm256_add_epi32(t, _mm256_set1_epi32(1 << 21))),
            _mm256_set1_epi32(15),
        );

        (
            r1,
            _mm256_sub_epi32(_mm256_slli_epi32::<19>(r1), _mm256_slli_epi32::<9>(r1)),
        )
    } else {
        let t = _mm256_mullo_epi32(r1, _mm256_set1_epi32(11275));

        let r1 = _mm256_srai_epi32::<24>(_mm256_add_epi32(t, _mm256_set1_epi32(1 << 23)));

        let r1 = _mm256_xor_si256(
            r1,
            _mm256_and_si256(
                _mm256_srai_epi32::<31>(_mm256_sub_epi32(_mm256_set1_epi32(43), r1)),
                r1,
            ),
        );

        (r1, _mm256_mullo_epi32(r1, _mm256_set1_epi32(2 * gamma2)))
    };

    let r0 = _mm256_sub_epi32(r, product);

    let wrap = _mm256_srai_epi32::<31>(_mm256_sub_epi32(_mm256_set1_epi32((q - 1) / 2), r0));

    (
        r1,
        _mm256_sub_epi32(r0, _mm256_and_si256(wrap, _mm256_set1_epi32(q))),
    )
}

// The OR of the eight lanes, or their sum, in every lane.
#[target_feature(enable = "avx2")]
#[inline]
fn across<const SUM: bool>(x: __m256i) -> i32 {
    let combine = |a: __m256i, b: __m256i| {
        if SUM {
            _mm256_add_epi32(a, b)
        } else {
            _mm256_or_si256(a, b)
        }
    };

    let x = combine(x, _mm256_permute2x128_si256::<0x01>(x, x));

    let x = combine(x, _mm256_shuffle_epi32::<0x4E>(x));

    let x = combine(x, _mm256_shuffle_epi32::<0xB1>(x));

    _mm256_cvtsi256_si32(x)
}

// -1 when some value reaches the bound in absolute value: the centered coefficients, or with
// gamma2 the low bits of Decompose; 0 otherwise.
#[target_feature(enable = "avx2")]
pub(super) fn norm(values: &[i32; 256], bound: i32, gamma2: Option<i32>, q: i32) -> i32 {
    match gamma2 {
        Some(gamma2) if gamma2 == (q - 1) / 32 => norm_with::<true, true>(values, bound, gamma2, q),
        Some(gamma2) => norm_with::<true, false>(values, bound, gamma2, q),
        None => norm_with::<false, false>(values, bound, 0, q),
    }
}

#[target_feature(enable = "avx2")]
#[inline]
fn norm_with<const LOW: bool, const WIDE: bool>(
    values: &[i32; 256],
    bound: i32,
    gamma2: i32,
    q: i32,
) -> i32 {
    let (limit, qv, half) = (
        _mm256_set1_epi32(bound - 1),
        _mm256_set1_epi32(q),
        _mm256_set1_epi32((q - 1) / 2),
    );

    let mut flags = _mm256_setzero_si256();

    for values in values.as_chunks::<8>().0 {
        let x = load256(values);

        let value = if LOW {
            decompose::<WIDE>(x, gamma2, q).1
        } else {
            let wrap = _mm256_srai_epi32::<31>(_mm256_sub_epi32(half, x));

            _mm256_sub_epi32(x, _mm256_and_si256(qv, wrap))
        };

        let reached = _mm256_srai_epi32::<31>(_mm256_sub_epi32(limit, _mm256_abs_epi32(value)));

        flags = _mm256_or_si256(flags, reached);
    }

    across::<false>(flags)
}

// The hints of r and ct0 (FIPS 204, Algorithm 39 on r + ct0 and r), one per coefficient, and how
// many are set.
#[target_feature(enable = "avx2")]
pub(super) fn hints(
    h: &mut [i32; 256],
    r: &[i32; 256],
    ct0: &[i32; 256],
    gamma2: i32,
    q: i32,
) -> i32 {
    if gamma2 == (q - 1) / 32 {
        hints_with::<true>(h, r, ct0, gamma2, q)
    } else {
        hints_with::<false>(h, r, ct0, gamma2, q)
    }
}

#[target_feature(enable = "avx2")]
#[inline]
fn hints_with<const WIDE: bool>(
    h: &mut [i32; 256],
    r: &[i32; 256],
    ct0: &[i32; 256],
    gamma2: i32,
    q: i32,
) -> i32 {
    let (qv, one) = (_mm256_set1_epi32(q), _mm256_set1_epi32(1));

    let mut count = _mm256_setzero_si256();

    let operands = r.as_chunks::<8>().0.iter().zip(ct0.as_chunks::<8>().0);

    for (h, (r, c)) in h.as_chunks_mut::<8>().0.iter_mut().zip(operands) {
        let (x, c) = (load256(r), load256(c));

        let sum = freeze(_mm256_sub_epi32(_mm256_add_epi32(x, c), qv), qv);

        let same = _mm256_cmpeq_epi32(
            decompose::<WIDE>(sum, gamma2, q).0,
            decompose::<WIDE>(x, gamma2, q).0,
        );

        let bits = _mm256_andnot_si256(same, one);

        store256(bits, h);

        count = _mm256_add_epi32(count, bits);
    }

    across::<true>(count)
}

// HighBits of every coefficient packed in four bits (gamma2 = (q - 1) / 32) or six.
#[target_feature(enable = "avx2")]
pub(super) fn encode_w1(out: &mut [u8], w: &[i32; 256], gamma2: i32, q: i32) {
    if gamma2 == (q - 1) / 32 {
        let order = _mm256_setr_epi32(0, 4, 1, 5, 2, 6, 3, 7);

        for (out, w) in out
            .as_chunks_mut::<16>()
            .0
            .iter_mut()
            .zip(w.as_chunks::<32>().0)
        {
            let v: [__m256i; 4] = core::array::from_fn(|i| {
                decompose::<true>(load256(&w.as_chunks::<8>().0[i]), gamma2, q).0
            });

            let bytes = _mm256_packus_epi16(
                _mm256_packs_epi32(v[0], v[1]),
                _mm256_packs_epi32(v[2], v[3]),
            );

            let ordered = _mm256_permutevar8x32_epi32(bytes, order);

            let pairs = _mm256_maddubs_epi16(ordered, _mm256_set1_epi16(0x1001));

            let packed = _mm256_permute4x64_epi64::<0x08>(_mm256_packus_epi16(pairs, pairs));

            store128(_mm256_castsi256_si128(packed), out);
        }

        return;
    }

    let take = _mm256_setr_epi8(
        0, 1, 2, 8, 9, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 8, 9, 10, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1,
    );

    let low = _mm256_set1_epi64x(0xFFF);

    for (out, w) in out
        .as_chunks_mut::<12>()
        .0
        .iter_mut()
        .zip(w.as_chunks::<16>().0)
    {
        let [first, second] = w.as_chunks::<8>().0 else {
            unreachable!("sixteen values are two groups of eight")
        };

        let words = _mm256_packs_epi32(
            decompose::<false>(load256(first), gamma2, q).0,
            decompose::<false>(load256(second), gamma2, q).0,
        );

        let words = _mm256_permute4x64_epi64::<0xD8>(words);

        // Pairs of values to twelve bits, then pairs of those to 24 bits in each 64-bit lane.
        let pairs = _mm256_madd_epi16(words, _mm256_set1_epi32(1 | 64 << 16));

        let lanes = _mm256_or_si256(
            _mm256_and_si256(pairs, low),
            _mm256_andnot_si256(low, _mm256_srli_epi64::<20>(pairs)),
        );

        let bytes = _mm256_shuffle_epi8(lanes, take);

        let (head, tail) = out.split_at_mut(6);

        let first = _mm_cvtsi128_si64(_mm256_castsi256_si128(bytes)) as u64;

        let second = _mm_cvtsi128_si64(_mm256_extracti128_si256::<1>(bytes)) as u64;

        head.copy_from_slice(&first.to_le_bytes()[..6]);

        tail.copy_from_slice(&second.to_le_bytes()[..6]);
    }
}

// gamma1 - x modulo q for the mask's values x of BITS = 18 or 20 bits: each 128-bit half takes
// four values from BITS / 2 bytes, each value's three bytes gathered into a 32-bit lane and
// shifted. The bytes are secret and pass through a padded copy, which is wiped.
#[target_feature(enable = "avx2")]
pub(super) fn unpack_mask<const BITS: usize>(
    out: &mut [i32; 256],
    bytes: &[u8],
    gamma1: i32,
    q: i32,
) {
    let (gather, shifts) = if BITS == 18 {
        (
            _mm_setr_epi8(0, 1, 2, -1, 2, 3, 4, -1, 4, 5, 6, -1, 6, 7, 8, -1),
            _mm256_setr_epi32(0, 2, 4, 6, 0, 2, 4, 6),
        )
    } else {
        (
            _mm_setr_epi8(0, 1, 2, -1, 2, 3, 4, -1, 5, 6, 7, -1, 7, 8, 9, -1),
            _mm256_setr_epi32(0, 4, 0, 4, 0, 4, 0, 4),
        )
    };

    let mut padded = [0u8; 640 + 16];

    padded[..bytes.len()].copy_from_slice(bytes);

    let half = BITS / 2;

    let (mask, gamma1, qv) = (
        _mm256_set1_epi32((1 << BITS) - 1),
        _mm256_set1_epi32(gamma1),
        _mm256_set1_epi32(q),
    );

    for (i, out) in out.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let start = 2 * half * i;

        let low: &[u8; 16] = padded[start..start + 16].try_into().expect("sixteen bytes");

        let high: &[u8; 16] = padded[start + half..start + half + 16]
            .try_into()
            .expect("sixteen bytes");

        let both =
            _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(load128(low)), load128(high));

        let words = _mm256_shuffle_epi8(both, _mm256_broadcastsi128_si256(gather));

        let values = _mm256_and_si256(_mm256_srlv_epi32(words, shifts), mask);

        store256(freeze(_mm256_sub_epi32(gamma1, values), qv), out);
    }

    crate::wipe::wipe(&mut padded);
}

// Shuffle indices that bring the accepted lanes of eight to the start in order, for every pattern
// of accepted lanes: byte lanes for SSSE3's shuffle, and dword lanes for AVX2's permutation, which
// reads only the low three bits; 0xFF selects zero in the shuffle.
const fn compaction() -> [[u8; 8]; 256] {
    let mut table = [[0xFF; 8]; 256];

    let mut pattern = 0;

    while pattern < 256 {
        let mut next = 0;

        let mut lane = 0;

        while lane < 8 {
            if pattern & (1 << lane) != 0 {
                table[pattern][next] = lane as u8;

                next += 1;
            }

            lane += 1;
        }

        pattern += 1;
    }

    table
}

static COMPACT: [[u8; 8]; 256] = compaction();

#[target_feature(enable = "avx2")]
#[inline]
fn compact_indices(pattern: u32) -> __m128i {
    _mm_cvtsi64_si128(i64::from_le_bytes(COMPACT[pattern as usize]))
}

// ML-DSA (FIPS 204, Algorithm 30): a candidate of 23 bits from every three bytes, eight from each
// 24 bytes, the accepted ones moved together by a permutation and stored at the count of values so
// far, which may write slots past it that later values or the end replace.
#[target_feature(enable = "avx2")]
pub(super) fn uniform23(lanes: &[u64; 21], q: i32, a: &mut [i32; 256], count: &mut usize) {
    let mut bytes = [0u8; 168 + 8];

    for (bytes, lane) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(lanes) {
        *bytes = lane.to_le_bytes();
    }

    let spread = _mm256_setr_epi8(
        0, 1, 2, -1, 3, 4, 5, -1, 6, 7, 8, -1, 9, 10, 11, -1, 4, 5, 6, -1, 7, 8, 9, -1, 10, 11, 12,
        -1, 13, 14, 15, -1,
    );

    let (mask, bound) = (_mm256_set1_epi32(0x7F_FFFF), _mm256_set1_epi32(q));

    let (mut step, mut filled) = (0, *count);

    while step < 7 && filled <= 256 - 8 {
        let group: &[u8; 24] = bytes[24 * step..24 * step + 24]
            .try_into()
            .expect("24 bytes");

        let low: &[u8; 16] = group[..16].try_into().expect("sixteen bytes");

        let high: &[u8; 16] = group[8..].try_into().expect("sixteen bytes");

        let both =
            _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(load128(low)), load128(high));

        let candidates = _mm256_and_si256(_mm256_shuffle_epi8(both, spread), mask);

        let accepted = _mm256_cmpgt_epi32(bound, candidates);

        let pattern = _mm256_movemask_ps(_mm256_castsi256_ps(accepted)) as u32;

        let order = _mm256_cvtepu8_epi32(compact_indices(pattern));

        let out: &mut [i32; 8] = (&mut a[filled..filled + 8]).try_into().expect("eight");

        store256(_mm256_permutevar8x32_epi32(candidates, order), out);

        filled += usize::from(ACCEPTED[pattern as usize]);

        step += 1;
    }

    *count = filled;

    for chunk in bytes[24 * step..168].as_chunks::<3>().0 {
        let z =
            i32::from(chunk[0]) | (i32::from(chunk[1]) << 8) | (i32::from(chunk[2] & 0x7F) << 16);

        if z < q && *count < 256 {
            a[*count] = z;

            *count += 1;
        }
    }
}

// ML-DSA (FIPS 204, Algorithm 31 inside 33): sixteen half-bytes from each lane in stream order,
// mapped by a table in a register to 2 - x mod 5 for eta = 2 (x below 15) or to 4 - x for eta = 4
// (x below 9), then compacted eight at a time and widened.
#[target_feature(enable = "avx2")]
pub(super) fn bounded(lanes: &[u64; 17], eta: i32, a: &mut [i32; 256], count: &mut usize) {
    let (table, bound) = if eta == 2 {
        (
            _mm_setr_epi8(2, 1, 0, -1, -2, 2, 1, 0, -1, -2, 2, 1, 0, -1, -2, 0),
            _mm_set1_epi8(15),
        )
    } else {
        (
            _mm_setr_epi8(4, 3, 2, 1, 0, -1, -2, -3, -4, 0, 0, 0, 0, 0, 0, 0),
            _mm_set1_epi8(9),
        )
    };

    let nibble = _mm_set1_epi8(0x0F);

    let (mut step, mut filled) = (0, *count);

    while step < lanes.len() && filled <= 256 - 16 {
        let bytes = _mm_cvtsi64_si128(lanes[step] as i64);

        let halves = _mm_unpacklo_epi8(
            _mm_and_si128(bytes, nibble),
            _mm_and_si128(_mm_srli_epi16::<4>(bytes), nibble),
        );

        let accepted = _mm_movemask_epi8(_mm_cmpgt_epi8(bound, halves)) as u32;

        let accepted = declassify_value(accepted);

        let values = _mm_shuffle_epi8(table, halves);

        for (half, pattern) in [
            (values, accepted & 0xFF),
            (_mm_bsrli_si128::<8>(values), accepted >> 8),
        ] {
            let packed = _mm_shuffle_epi8(half, compact_indices(pattern));

            let out: &mut [i32; 8] = (&mut a[filled..filled + 8]).try_into().expect("eight");

            store256(_mm256_cvtepi8_epi32(packed), out);

            filled += usize::from(ACCEPTED[pattern as usize]);
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

// The coefficients as `map` says: power2round's r1 = (r + 2^12 - 1) >> 13 and r0 = r - (r1 << 13),
// eta - x, or gamma1 - centered(x).
#[target_feature(enable = "avx2")]
#[inline]
fn mapped(x: __m256i, map: Pack, q: i32) -> __m256i {
    match map {
        Pack::High => _mm256_srai_epi32::<13>(_mm256_add_epi32(x, _mm256_set1_epi32(4095))),
        Pack::Low => {
            let high = _mm256_srai_epi32::<13>(_mm256_add_epi32(x, _mm256_set1_epi32(4095)));

            let low = _mm256_sub_epi32(x, _mm256_slli_epi32::<13>(high));

            _mm256_sub_epi32(_mm256_set1_epi32(1 << 12), low)
        }
        Pack::Eta(eta) => _mm256_sub_epi32(_mm256_set1_epi32(eta), x),
        Pack::Gamma1(gamma1) => {
            let wrap = _mm256_srai_epi32::<31>(_mm256_sub_epi32(_mm256_set1_epi32((q - 1) / 2), x));

            let centered = _mm256_sub_epi32(x, _mm256_and_si256(_mm256_set1_epi32(q), wrap));

            _mm256_sub_epi32(_mm256_set1_epi32(gamma1), centered)
        }
    }
}

// The coefficients mapped and packed in BITS bits each: pairs of 32-bit values become 2 BITS bits
// of a 64-bit lane, and pairs of those 4 BITS bits of each 128-bit half; up to sixteen bits the two
// halves join in a 128-bit integer, above they are whole bytes and are stored apart. The packing
// passes through a buffer, which is wiped: t0 and s are secret.
#[target_feature(enable = "avx2")]
pub(super) fn pack(out: &mut [u8], poly: &[i32; 256], bits: u32, map: Pack, q: i32) {
    match bits {
        3 => pack_bits::<3>(out, poly, map, q),
        4 => pack_bits::<4>(out, poly, map, q),
        10 => pack_bits::<10>(out, poly, map, q),
        13 => pack_bits::<13>(out, poly, map, q),
        18 => pack_bits::<18>(out, poly, map, q),
        20 => pack_bits::<20>(out, poly, map, q),
        _ => unreachable!("no ML-DSA encoding uses {bits} bits"),
    }
}

#[target_feature(enable = "avx2")]
#[inline]
fn pack_bits<const BITS: usize>(out: &mut [u8], poly: &[i32; 256], map: Pack, q: i32) {
    let mut buffer = [0u8; 32 * 20 + 16];

    let low = _mm256_set1_epi64x((1 << BITS) - 1);

    let shift = |count: usize| _mm_cvtsi32_si128(count as i32);

    for (i, values) in poly.as_chunks::<8>().0.iter().enumerate() {
        let v = mapped(load256(values), map, q);

        let pairs = _mm256_or_si256(
            _mm256_and_si256(v, low),
            _mm256_andnot_si256(low, _mm256_srl_epi64(v, shift(32 - BITS))),
        );

        let joined = _mm256_or_si256(
            pairs,
            _mm256_sll_epi64(_mm256_bsrli_epi128::<8>(pairs), shift(2 * BITS)),
        );

        let start = BITS * i;

        if BITS <= 16 {
            let first = _mm256_extract_epi64::<0>(joined) as u64;

            let second = _mm256_extract_epi64::<2>(joined) as u64;

            let all = u128::from(first) | u128::from(second) << (4 * BITS);

            buffer[start..start + 16].copy_from_slice(&all.to_le_bytes());
        } else {
            let halves =
                _mm256_blend_epi32::<0xCC>(joined, _mm256_srl_epi64(pairs, shift(64 - 2 * BITS)));

            let first: &mut [u8; 16] = (&mut buffer[start..start + 16])
                .try_into()
                .expect("sixteen");

            store128(_mm256_castsi256_si128(halves), first);

            let middle = start + BITS / 2;

            let second: &mut [u8; 16] = (&mut buffer[middle..middle + 16])
                .try_into()
                .expect("sixteen");

            store128(_mm256_extracti128_si256::<1>(halves), second);
        }
    }

    out.copy_from_slice(&buffer[..32 * BITS]);

    crate::wipe::wipe(&mut buffer);
}
