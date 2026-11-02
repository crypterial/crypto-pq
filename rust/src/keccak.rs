#[cfg(target_family = "wasm")]
use core::cell::Cell;
use core::ops::Deref;

use crate::cpu;
use crate::sha2::low_bytes;
use crate::wipe::{registers, wipe, wipe_unless_optimized};

pub(crate) const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

pub(crate) const ROTATIONS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

// One round from a into e, one output plane at a time: lane x of plane y of the rho-pi output
// comes from lane (x + 3y) % 5 + 5x of a. The column parities that theta needs in the next round
// are summed as the lanes of e are written, so few values stay live and little spills to memory.
// A CPU kernel runs these rounds beside its vector rounds.
#[cfg(all(target_pointer_width = "64", not(target_family = "wasm")))]
#[inline(always)]
pub(crate) fn round(a: &[u64; 25], e: &mut [u64; 25], parities: &mut [u64; 5], constant: u64) {
    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut d: [u64; 5] = registers!(
        |x| parities[(x + 4) % 5] ^ parities[(x + 1) % 5].rotate_left(1);
        0 1 2 3 4
    );

    let mut next = [0; 5];

    for y in 0..5 {
        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut b: [u64; 5] = registers!(
            |x| {
                let source = (x + 3 * y) % 5 + 5 * x;

                (a[source] ^ d[source % 5]).rotate_left(ROTATIONS[source])
            };
            0 1 2 3 4
        );

        for x in 0..5 {
            let lane = b[x] ^ (!b[(x + 1) % 5] & b[(x + 2) % 5]);

            // Iota folds into lane 0 as it is written: patching e[0] afterwards costs a reload.
            let lane = if x == 0 && y == 0 {
                lane ^ constant
            } else {
                lane
            };

            e[x + 5 * y] = lane;

            next[x] ^= lane;
        }

        wipe_unless_optimized!(&mut b);
    }

    *parities = next;

    wipe_unless_optimized!(&mut d);

    wipe_unless_optimized!(&mut next);
}

// The column parities that the first round's theta needs.
#[cfg(all(target_pointer_width = "64", not(target_family = "wasm")))]
pub(crate) fn parities(state: &[u64; 25]) -> [u64; 5] {
    registers!(
        |x| state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        0 1 2 3 4
    )
}

// Keccak-f[1600] as the specification writes it, for states that constants need at compile time.
pub(crate) const fn permute_const(a: &mut [u64; 25]) {
    let mut round = 0;

    while round < 24 {
        let mut c = [0; 5];

        let mut x = 0;

        while x < 5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];

            x += 1;
        }

        let mut i = 0;

        while i < 25 {
            a[i] ^= c[(i + 4) % 5] ^ c[(i + 1) % 5].rotate_left(1);

            i += 1;
        }

        // Rho and pi: lane (x, y) moves to (y, 2x + 3y).
        let mut b = [0; 25];

        i = 0;

        while i < 25 {
            let (x, y) = (i % 5, i / 5);

            b[y + 5 * ((2 * x + 3 * y) % 5)] = a[i].rotate_left(ROTATIONS[i]);

            i += 1;
        }

        i = 0;

        while i < 25 {
            let row = i - i % 5;

            a[i] = b[i] ^ (!b[row + (i + 1) % 5] & b[row + (i + 2) % 5]);

            i += 1;
        }

        a[0] ^= ROUND_CONSTANTS[round];

        round += 1;
    }
}

#[cfg(all(target_pointer_width = "64", not(target_family = "wasm")))]
pub(crate) fn permute(state: &mut [u64; 25]) {
    let mut parities = parities(state);

    let mut e = [0; 25];

    for constants in ROUND_CONSTANTS.as_chunks::<2>().0 {
        round(state, &mut e, &mut parities, constants[0]);

        round(&e, state, &mut parities, constants[1]);
    }

    wipe_unless_optimized!(&mut e);

    wipe_unless_optimized!(&mut parities);
}

// The rounds of wasm keep the lanes in memory (D-81). An engine such as Cranelift allocates the
// locals of wasm to registers, and in locals the 25 lanes outnumber them: on x86-64 about 14 are
// free, and lanes spill and reload in every round. Here black_box gives the addresses of both
// arrays and of pin away and a fence opens each step of a round, so that the step loads the lanes
// it reads, stores the lanes it writes, and holds no more values than the registers of x86-64.
#[cfg(target_family = "wasm")]
pub(crate) fn permute(state: &mut [u64; 25]) {
    let mut e = [0; 25];

    let mut pin = Cell::new(0);

    core::hint::black_box((&mut *state, &mut e, &pin));

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut last: [u64; 5] = registers!(|x| state[x + 20]; 0 1 2 3 4);

    for constants in ROUND_CONSTANTS.as_chunks::<2>().0 {
        round_memory(state, &mut e, &mut last, &pin, constants[0]);

        round_memory(&e, state, &mut last, &pin, constants[1]);
    }

    wipe(&mut e);

    wipe(core::slice::from_mut(pin.get_mut()));

    wipe_unless_optimized!(&mut last);
}

// One round from a into e. Its column parities come from the lanes of a in memory, but for the
// last plane of the round before, which a round leaves in last: summed in registers as the planes
// are written, as the 64-bit form sums them, the parities would stay live through the round beside
// d and the plane, which on x86-64 spills.
#[cfg(target_family = "wasm")]
#[inline(always)]
fn round_memory(
    a: &[u64; 25],
    e: &mut [u64; 25],
    last: &mut [u64; 5],
    pin: &Cell<u64>,
    constant: u64,
) {
    core::hint::black_box(());

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut parities = [
        parity_memory::<0>(a, last, pin),
        parity_memory::<1>(a, last, pin),
        parity_memory::<2>(a, last, pin),
        parity_memory::<3>(a, last, pin),
        parity_memory::<4>(a, last, pin),
    ];

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut d: [u64; 5] = registers!(
        |x| parities[(x + 4) % 5] ^ parities[(x + 1) % 5].rotate_left(1);
        0 1 2 3 4
    );

    wipe_unless_optimized!(&mut parities);

    plane_memory::<0>(a, &d, e, constant);

    plane_memory::<1>(a, &d, e, constant);

    plane_memory::<2>(a, &d, e, constant);

    plane_memory::<3>(a, &d, e, constant);

    plane_memory::<4>(a, &d, e, constant);

    // No fence stands between the stores of the last plane and these loads, so LLVM takes the
    // lanes from the registers that stored them.
    *last = registers!(|x| e[x + 20]; 0 1 2 3 4);

    wipe_unless_optimized!(&mut d);
}

// The parity goes to pin, whose address has been given away, before a fence that the loads of the
// next column cannot pass, so the parity is summed before them: without the store LLVM moves the
// exclusive-ors to their first use in d, and the loads of all five columns stay live together.
#[cfg(target_family = "wasm")]
#[inline(always)]
fn parity_memory<const X: usize>(a: &[u64; 25], last: &[u64; 5], pin: &Cell<u64>) -> u64 {
    let parity = a[X] ^ a[X + 5] ^ a[X + 10] ^ a[X + 15] ^ last[X];

    pin.set(parity);

    core::hint::black_box(());

    parity
}

// The fence is black_box(()), an empty assembly block that may read and write all memory whose
// address has been given away: the loads of the plane cannot move above it, nor its stores below
// the next one. Each plane is a function of its own: a loop over the planes with the fence in it
// stays a loop, which computes the lane indices at run time.
#[cfg(target_family = "wasm")]
#[inline(always)]
fn plane_memory<const Y: usize>(a: &[u64; 25], d: &[u64; 5], e: &mut [u64; 25], constant: u64) {
    core::hint::black_box(());

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut b: [u64; 5] = registers!(
        |x| {
            let source = (x + 3 * Y) % 5 + 5 * x;

            (a[source] ^ d[source % 5]).rotate_left(ROTATIONS[source])
        };
        0 1 2 3 4
    );

    for x in 0..5 {
        let lane = b[x] ^ (!b[(x + 1) % 5] & b[(x + 2) % 5]);

        let lane = if x == 0 && Y == 0 {
            lane ^ constant
        } else {
            lane
        };

        e[x + 5 * Y] = lane;
    }

    wipe_unless_optimized!(&mut b);
}

// Where a lane takes two registers, the state holds each lane bit-interleaved, but for the pairs
// of 32-bit x86 below: the even bits of the lane in its low word and the odd bits in its high
// word, bit j of a word being bit 2j or 2j + 1 of the lane. A rotation of the lane is then one
// 32-bit rotation of each word, the words swapped for an odd amount, where the 64-bit rotation
// took two shifts and an OR a word. Lanes enter the state through to_lane and leave it through
// from_lane, so that a permutation converts none; both are the identity where a lane takes one
// register or a pair holds it whole.
#[cfg(any(
    target_pointer_width = "64",
    target_family = "wasm",
    crypto_pq_keccak_pairs
))]
#[inline(always)]
pub(crate) const fn to_lane(lane: u64) -> u64 {
    lane
}

#[cfg(any(
    target_pointer_width = "64",
    target_family = "wasm",
    crypto_pq_keccak_pairs
))]
#[inline(always)]
pub(crate) const fn from_lane(lane: u64) -> u64 {
    lane
}

#[cfg(not(any(
    target_pointer_width = "64",
    target_family = "wasm",
    crypto_pq_keccak_pairs
)))]
#[inline(always)]
pub(crate) const fn to_lane(lane: u64) -> u64 {
    let low = unzip(lane as u32);

    let high = unzip((lane >> 32) as u32);

    ((low & 0xffff) | (high << 16)) as u64 | (((low >> 16) | (high & 0xffff_0000)) as u64) << 32
}

#[cfg(not(any(
    target_pointer_width = "64",
    target_family = "wasm",
    crypto_pq_keccak_pairs
)))]
#[inline(always)]
pub(crate) const fn from_lane(lane: u64) -> u64 {
    let (even, odd) = (lane as u32, (lane >> 32) as u32);

    let low = zip((even & 0xffff) | (odd << 16));

    let high = zip((even >> 16) | (odd & 0xffff_0000));

    low as u64 | (high as u64) << 32
}

// The even bits of x in its low half, in order, and its odd bits in its high half: four exchanges
// of bit groups, each of the bits of x at the masked positions with the bits a distance above.
#[cfg(not(any(
    target_pointer_width = "64",
    target_family = "wasm",
    crypto_pq_keccak_pairs
)))]
#[inline(always)]
const fn unzip(mut x: u32) -> u32 {
    let mut t = (x ^ (x >> 1)) & 0x2222_2222;

    x ^= t ^ (t << 1);

    t = (x ^ (x >> 2)) & 0x0c0c_0c0c;

    x ^= t ^ (t << 2);

    t = (x ^ (x >> 4)) & 0x00f0_00f0;

    x ^= t ^ (t << 4);

    t = (x ^ (x >> 8)) & 0x0000_ff00;

    x ^ t ^ (t << 8)
}

// The inverse of unzip: the same exchanges in the opposite order, as each is its own inverse.
#[cfg(not(any(
    target_pointer_width = "64",
    target_family = "wasm",
    crypto_pq_keccak_pairs
)))]
#[inline(always)]
const fn zip(mut x: u32) -> u32 {
    let mut t = (x ^ (x >> 8)) & 0x0000_ff00;

    x ^= t ^ (t << 8);

    t = (x ^ (x >> 4)) & 0x00f0_00f0;

    x ^= t ^ (t << 4);

    t = (x ^ (x >> 2)) & 0x0c0c_0c0c;

    x ^= t ^ (t << 2);

    t = (x ^ (x >> 1)) & 0x2222_2222;

    x ^ t ^ (t << 1)
}

// The parities of each round come from its input, and each output plane from its source lanes
// alone, half a plane at a time, so that only those stay live. The words are in memory, where
// the wipe reaches them.
#[cfg(not(any(
    target_pointer_width = "64",
    target_family = "wasm",
    crypto_pq_keccak_pairs
)))]
pub(crate) fn permute(state: &mut [u64; 25]) {
    let mut a = state.map(|lane| [lane as u32, (lane >> 32) as u32]);

    let mut e = [[0; 2]; 25];

    let mut theta = [[0; 2]; 5];

    core::hint::black_box((&mut a, &mut e, &mut theta));

    for constants in INTERLEAVED_CONSTANTS.as_chunks::<2>().0 {
        round_interleaved(&a, &mut e, &mut theta, constants[0]);

        round_interleaved(&e, &mut a, &mut theta, constants[1]);
    }

    *state = a.map(|[even, odd]| u64::from(even) | u64::from(odd) << 32);

    wipe(&mut a);

    wipe(&mut e);

    wipe(&mut theta);
}

#[cfg(not(any(
    target_pointer_width = "64",
    target_family = "wasm",
    crypto_pq_keccak_pairs
)))]
const INTERLEAVED_CONSTANTS: [[u32; 2]; 24] = {
    let mut constants = [[0; 2]; 24];

    let mut i = 0;

    while i < 24 {
        let lane = to_lane(ROUND_CONSTANTS[i]);

        constants[i] = [lane as u32, (lane >> 32) as u32];

        i += 1;
    }

    constants
};

// The parities go to theta one column half at a time, and theta's D values replace them, so that
// each value is stored before the next column is loaded.
#[cfg(not(any(
    target_pointer_width = "64",
    target_family = "wasm",
    crypto_pq_keccak_pairs
)))]
#[inline(always)]
fn round_interleaved(
    a: &[[u32; 2]; 25],
    e: &mut [[u32; 2]; 25],
    theta: &mut [[u32; 2]; 5],
    constant: [u32; 2],
) {
    for x in 0..5 {
        for h in 0..2 {
            order();

            theta[x][h] = a[x][h] ^ a[x + 5][h] ^ a[x + 10][h] ^ a[x + 15][h] ^ a[x + 20][h];
        }
    }

    order();

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut c = *theta;

    for x in 0..5 {
        let (before, after) = (c[(x + 4) % 5], c[(x + 1) % 5]);

        theta[x] = [before[0] ^ after[1].rotate_left(1), before[1] ^ after[0]];
    }

    wipe_unless_optimized!(&mut c);

    half_plane::<0, 0>(a, theta, e, constant[0]);

    half_plane::<0, 1>(a, theta, e, constant[1]);

    half_plane::<1, 0>(a, theta, e, 0);

    half_plane::<1, 1>(a, theta, e, 0);

    half_plane::<2, 0>(a, theta, e, 0);

    half_plane::<2, 1>(a, theta, e, 0);

    half_plane::<3, 0>(a, theta, e, 0);

    half_plane::<3, 1>(a, theta, e, 0);

    half_plane::<4, 0>(a, theta, e, 0);

    half_plane::<4, 1>(a, theta, e, 0);
}

// Word H of plane Y of a round's output, Y and H constants so that every index and rotation
// amount is one. Bit 2j of a lane rotated by 2k + 1 is bit 2(j - k - 1) + 1 of the lane, and bit
// 2j + 1 is bit 2(j - k): the even word of the result is the odd word rotated by k + 1, and the odd
// word the even one rotated by k.
#[cfg(not(any(
    target_pointer_width = "64",
    target_family = "wasm",
    crypto_pq_keccak_pairs
)))]
#[inline(always)]
fn half_plane<const Y: usize, const H: usize>(
    a: &[[u32; 2]; 25],
    d: &[[u32; 2]; 5],
    e: &mut [[u32; 2]; 25],
    constant: u32,
) {
    order();

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut b: [u32; 5] = registers!(
        |x| {
            let source = (x + 3 * Y) % 5 + 5 * x;

            let rotation = ROTATIONS[source];

            let (word, amount) = match (rotation % 2, H) {
                (0, _) => (H, rotation / 2),
                (_, 0) => (1, rotation / 2 + 1),
                _ => (0, rotation / 2),
            };

            (a[source][word] ^ d[source % 5][word]).rotate_left(amount)
        };
        0 1 2 3 4
    );

    for x in 0..5 {
        let word = b[x] ^ (!b[(x + 1) % 5] & b[(x + 2) % 5]);

        e[x + 5 * Y][H] = if x == 0 { word ^ constant } else { word };
    }

    wipe_unless_optimized!(&mut b);
}

// A point that LLVM moves no load or store across, so that it loads the words of a column or a
// plane where they are used: it otherwise loaded them all at the start of a round and spilled
// them, with fourteen registers on 32-bit Arm.
#[cfg(not(any(target_pointer_width = "64", target_family = "wasm")))]
#[inline(always)]
fn order() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// On 32-bit x86 with SSE2 (crypto_pq_keccak_pairs, which build.rs sets), a pair holds the same
// lane of two states, whole: each operation of a round is then one SSE2 instruction on both
// states, which LLVM's SLP vectorizer forms from the two operations of a pair. A state alone runs
// beside the zero state, whose permutation is public.
#[cfg(crypto_pq_keccak_pairs)]
type Pair = [u64; 2];

// Aligned for the SSE2 instructions that take an operand from memory.
#[cfg(crypto_pq_keccak_pairs)]
#[repr(C, align(16))]
struct Pairs([Pair; 25]);

#[cfg(crypto_pq_keccak_pairs)]
#[inline(always)]
fn xor_pair(a: Pair, b: Pair) -> Pair {
    [a[0] ^ b[0], a[1] ^ b[1]]
}

#[cfg(crypto_pq_keccak_pairs)]
#[inline(always)]
fn chi_pair(a: Pair, b: Pair, c: Pair) -> Pair {
    [a[0] ^ (!b[0] & c[0]), a[1] ^ (!b[1] & c[1])]
}

// A rotation as shifts of two values that LLVM cannot prove equal, a and a ^ zero for a zero that
// it cannot see: of one value it forms a funnel shift, which SSE2 lacks, and the vectorizer's cost
// of that kept the whole round scalar.
#[cfg(crypto_pq_keccak_pairs)]
#[inline(always)]
fn rotate_pair(a: Pair, zero: Pair, amount: u32) -> Pair {
    if amount == 0 {
        return a;
    }

    let b = xor_pair(a, zero);

    [
        a[0] << amount | b[0] >> (64 - amount),
        a[1] << amount | b[1] >> (64 - amount),
    ]
}

// Plane Y of a round's output for both states.
#[cfg(crypto_pq_keccak_pairs)]
#[inline(always)]
fn plane_pair<const Y: usize>(a: &Pairs, d: &[Pair; 5], e: &mut Pairs, constant: u64, zero: Pair) {
    order();

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut b: [Pair; 5] = registers!(
        |x| {
            let source = (x + 3 * Y) % 5 + 5 * x;

            rotate_pair(xor_pair(a.0[source], d[source % 5]), zero, ROTATIONS[source])
        };
        0 1 2 3 4
    );

    for x in 0..5 {
        let lane = chi_pair(b[x], b[(x + 1) % 5], b[(x + 2) % 5]);

        let lane = if x == 0 && Y == 0 {
            xor_pair(lane, [constant; 2])
        } else {
            lane
        };

        e.0[x + 5 * Y] = lane;
    }

    wipe_unless_optimized!(&mut b);
}

#[cfg(crypto_pq_keccak_pairs)]
#[inline(always)]
fn round_pair(a: &Pairs, e: &mut Pairs, constant: u64, zero: Pair) {
    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut c: [Pair; 5] = registers!(
        |x| {
            let low = xor_pair(xor_pair(a.0[x], a.0[x + 5]), xor_pair(a.0[x + 10], a.0[x + 15]));

            xor_pair(low, a.0[x + 20])
        };
        0 1 2 3 4
    );

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut d: [Pair; 5] = registers!(
        |x| xor_pair(c[(x + 4) % 5], rotate_pair(c[(x + 1) % 5], zero, 1));
        0 1 2 3 4
    );

    plane_pair::<0>(a, &d, e, constant, zero);

    plane_pair::<1>(a, &d, e, 0, zero);

    plane_pair::<2>(a, &d, e, 0, zero);

    plane_pair::<3>(a, &d, e, 0, zero);

    plane_pair::<4>(a, &d, e, 0, zero);

    wipe_unless_optimized!(&mut c);

    wipe_unless_optimized!(&mut d);
}

// Keccak-f[1600] on two states side by side.
#[cfg(crypto_pq_keccak_pairs)]
fn permute_pair(first: &mut [u64; 25], second: &mut [u64; 25]) {
    let mut a = Pairs(core::array::from_fn(|i| [first[i], second[i]]));

    let mut e = Pairs([[0; 2]; 25]);

    // In memory, where the wipe reaches them: as values, the lanes left the vectorizer no stores
    // to start from, and with order() each plane loads and stores its own lanes.
    core::hint::black_box((&mut a, &mut e));

    let zero = core::hint::black_box([0; 2]);

    for constants in ROUND_CONSTANTS.as_chunks::<2>().0 {
        round_pair(&a, &mut e, constants[0], zero);

        round_pair(&e, &mut a, constants[1], zero);
    }

    for (i, &[x, y]) in a.0.iter().enumerate() {
        first[i] = x;

        second[i] = y;
    }

    wipe(&mut a.0);

    wipe(&mut e.0);
}

#[cfg(crypto_pq_keccak_pairs)]
pub(crate) fn permute(state: &mut [u64; 25]) {
    permute_pair(state, &mut [0; 25]);
}

// One state through a CPU kernel where there is one.
pub(crate) fn permute_one(state: &mut [u64; 25]) {
    if cpu::permute_many(&mut [&mut *state]) == 0 {
        permute(state);
    }
}

// XORs bytes into the rate from position on, whole lanes at a time where they line up. The rate
// is a multiple of 8, so no lane crosses it.
fn xor_bytes(state: &mut [u64; 25], position: &mut usize, mut bytes: &[u8]) {
    while !position.is_multiple_of(8) {
        let Some((&byte, rest)) = bytes.split_first() else {
            return;
        };

        state[*position / 8] ^= to_lane(u64::from(byte) << (8 * (*position % 8)));

        *position += 1;

        bytes = rest;
    }

    let (lanes, tail) = bytes.as_chunks::<8>();

    for (lane, chunk) in state[*position / 8..].iter_mut().zip(lanes) {
        *lane ^= to_lane(u64::from_le_bytes(*chunk));
    }

    *position += 8 * lanes.len();

    for &byte in tail {
        state[*position / 8] ^= to_lane(u64::from(byte) << (8 * (*position % 8)));

        *position += 1;
    }
}

// Every state, side by side where the CPU has a kernel for several at once, and two at a time
// where pairs hold them.
pub(crate) fn permute_all(states: &mut [&mut [u64; 25]]) {
    let done = cpu::permute_many(states);

    #[cfg(crypto_pq_keccak_pairs)]
    let done = {
        let (pairs, _) = states[done..].as_chunks_mut::<2>();

        for [first, second] in pairs.iter_mut() {
            permute_pair(first, second);
        }

        done + 2 * pairs.len()
    };

    for state in &mut states[done..] {
        permute(state);
    }
}

// The most sponges that run side by side; callers with more split them into groups of group().
pub(crate) const MAX_SPONGES: usize = 8;

// Sponges marks its sponges in the bits of a byte, and the vector form holds two groups of four.
const _: () = assert!(MAX_SPONGES <= 8);

// The number of sponges that callers run side by side, at most MAX_SPONGES: a multiple of the
// states that the CPU's widest Keccak kernel permutes in one pass.
pub(crate) fn group() -> usize {
    cpu::keccak_group()
}

// Up to MAX_SPONGES sponges of one rate and suffix, each fed a message shorter than a block and
// then squeezed one block at a time in lockstep, so that their permutations run side by side:
// the independent XOF and PRF calls of matrix and noise sampling and of SLH-DSA's F.
//
// Where the CPU has a kernel for it (cpu::squeeze_wide), the sponges stay in its vector form,
// wide, from one block to the next, and each squeeze writes only the rate of each active sponge
// into its state, which is all that lanes and read return.
pub(crate) struct Sponges {
    states: [[u64; 25]; MAX_SPONGES],
    count: usize,
    rate: usize,
    done: u8,
    wide: cpu::Wide,
}

impl Sponges {
    // No sponges: every state is zero, as start needs them.
    pub(crate) const fn empty() -> Self {
        Self {
            states: [[0; 25]; MAX_SPONGES],
            count: 0,
            rate: 0,
            done: 0,
            wide: cpu::Wide::new(),
        }
    }

    // Starts a sponge on each message, after wiping the sponges started before. A caller keeps
    // one object for all its groups of sponges, whose states are written in place: a new object
    // for each group cost a copy and the zeroing of every state. Each message is given as its
    // parts, which are absorbed one after the other, so that no copy of a secret input is made to
    // concatenate them.
    pub(crate) fn start(&mut self, rate: usize, suffix: u8, messages: &[&[&[u8]]]) {
        assert!(
            messages.len() <= MAX_SPONGES,
            "at most MAX_SPONGES sponges run together"
        );

        wipe(self.states[..self.count].as_flattened_mut());

        self.wide.restart(messages.len());

        self.count = messages.len();

        self.rate = rate;

        self.done = 0;

        for (state, parts) in self.states.iter_mut().zip(messages) {
            let mut position = 0;

            for part in *parts {
                xor_bytes(state, &mut position, part);
            }

            assert!(position < rate, "the message must fit in one block");

            state[position / 8] ^= to_lane(u64::from(suffix) << (8 * (position % 8)));

            // The rate is a multiple of 8, so its last byte is the top byte of a lane.
            state[rate / 8 - 1] ^= to_lane(0x80 << 56);
        }
    }

    // start for messages that the caller writes as whole lanes: fill(i, state) receives the zero
    // state of sponge i and writes its message with the suffix and the padding, which must leave
    // room for the rate's last byte, each lane through to_lane. Callers whose messages are lanes
    // already, such as SLH-DSA's chains, skip the bytes of start.
    pub(crate) fn start_lanes(
        &mut self,
        rate: usize,
        count: usize,
        mut fill: impl FnMut(usize, &mut [u64; 25]),
    ) {
        assert!(
            count <= MAX_SPONGES,
            "at most MAX_SPONGES sponges run together"
        );

        wipe(self.states[..self.count].as_flattened_mut());

        self.wide.restart(count);

        self.count = count;

        self.rate = rate;

        self.done = 0;

        for (i, state) in self.states[..count].iter_mut().enumerate() {
            fill(i, state);
        }
    }

    // Squeezes the sponges marked active, which skips the permutations of those that already
    // have all the output they need. A sponge left out keeps the block it squeezed last and is
    // done: the vector form may permute it beside the others, so it is not squeezed again until
    // the next start, which retire checks on every path.
    pub(crate) fn squeeze(&mut self, active: [bool; MAX_SPONGES]) {
        self.retire(&active);

        if cpu::squeezes_wide() {
            self.squeeze_wide(&active, None);

            return;
        }

        let mut states = self.states.each_mut();

        let mut chosen = 0;

        for (i, &active) in active[..self.count].iter().enumerate() {
            if active {
                states.swap(chosen, i);

                chosen += 1;
            }
        }

        permute_all(&mut states[..chosen]);
    }

    // squeeze, and one more Keccak permutation of other beside those of the sponges, in the slot
    // after them: a state that a kernel permutes in the same call costs less than alone.
    pub(crate) fn squeeze_beside(&mut self, active: [bool; MAX_SPONGES], other: &mut [u64; 25]) {
        let spare = self.count;

        assert!(
            spare < MAX_SPONGES,
            "a free slot is needed beside the sponges"
        );

        self.retire(&active);

        if cpu::squeezes_wide() {
            self.squeeze_wide(&active, Some(other));

            return;
        }

        self.states[spare] = *other;

        {
            let mut states = self.states.each_mut();

            let mut chosen = 0;

            for (i, &active) in active[..self.count].iter().enumerate() {
                if active {
                    states.swap(chosen, i);

                    chosen += 1;
                }
            }

            states.swap(chosen, spare);

            permute_all(&mut states[..chosen + 1]);
        }

        *other = self.states[spare];

        // The slot lies outside the sponges, which are all that drop wipes.
        wipe(&mut self.states[spare]);
    }

    // The kernel's squeeze of the vector form, where the CPU has one: the states then hold only
    // the rate.
    fn squeeze_wide(&mut self, active: &[bool; MAX_SPONGES], other: Option<&mut [u64; 25]>) {
        cpu::squeeze_wide(
            &mut self.wide,
            &mut self.states[..self.count],
            self.rate / 8,
            &active[..self.count],
            other,
        );
    }

    // Marks the sponges left out of a squeeze as done, after checking that none is squeezed again.
    fn retire(&mut self, active: &[bool; MAX_SPONGES]) {
        // Bit i for sponge i: each byte is 0 or 1, and the product gathers byte i into bit 56 + i
        // with no carry, as no two of its 64 terms land on the same bit.
        let bits =
            u64::from_le_bytes(active.map(u8::from)).wrapping_mul(0x0102_0408_1020_4080) >> 56;

        let mask = (bits & ((1 << self.count) - 1)) as u8;

        assert!(
            mask & self.done == 0,
            "a sponge left out is not squeezed again"
        );

        self.done |= !mask;
    }

    // The lanes of the block that sponge i squeezed last, in output order on every target.
    #[cfg(any(
        target_pointer_width = "64",
        target_family = "wasm",
        crypto_pq_keccak_pairs
    ))]
    #[inline(always)]
    pub(crate) fn lanes<const LANES: usize>(&self, i: usize) -> impl Deref<Target = [u64; LANES]> {
        assert!(8 * LANES <= self.rate, "lanes beyond the rate");

        self.states[i]
            .first_chunk::<LANES>()
            .expect("the rate is at most 21 lanes")
    }

    // A copy of the lanes through from_lane, which the state holds bit-interleaved.
    #[cfg(not(any(
        target_pointer_width = "64",
        target_family = "wasm",
        crypto_pq_keccak_pairs
    )))]
    #[inline(always)]
    pub(crate) fn lanes<const LANES: usize>(&self, i: usize) -> impl Deref<Target = [u64; LANES]> {
        assert!(8 * LANES <= self.rate, "lanes beyond the rate");

        Lanes(core::array::from_fn(|j| from_lane(self.states[i][j])))
    }

    // The first out.len() bytes of the block that sponge i squeezed last.
    pub(crate) fn read(&self, i: usize, out: &mut [u8]) {
        assert!(out.len() <= self.rate, "at most one block");

        let (chunks, tail) = out.as_chunks_mut::<8>();

        for (chunk, lane) in chunks.iter_mut().zip(&self.states[i]) {
            *chunk = from_lane(*lane).to_le_bytes();
        }

        if !tail.is_empty() {
            low_bytes(from_lane(self.states[i][chunks.len()]), tail);
        }
    }
}

// Lanes of a squeezed block as Sponges::lanes returns them where the state holds lanes
// bit-interleaved: secret output, wiped when dropped.
#[cfg(not(any(
    target_pointer_width = "64",
    target_family = "wasm",
    crypto_pq_keccak_pairs
)))]
struct Lanes<const LANES: usize>([u64; LANES]);

#[cfg(not(any(
    target_pointer_width = "64",
    target_family = "wasm",
    crypto_pq_keccak_pairs
)))]
impl<const LANES: usize> Deref for Lanes<LANES> {
    type Target = [u64; LANES];

    fn deref(&self) -> &[u64; LANES] {
        &self.0
    }
}

#[cfg(not(any(
    target_pointer_width = "64",
    target_family = "wasm",
    crypto_pq_keccak_pairs
)))]
impl<const LANES: usize> Drop for Lanes<LANES> {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl Drop for Sponges {
    fn drop(&mut self) {
        wipe(self.states[..self.count].as_flattened_mut());

        self.wide.wipe();
    }
}

// The first outs[i].len() bytes of the output of a sponge of one rate and suffix fed messages[i],
// given as its parts and shorter than the rate, for up to group() messages: SLH-DSA's F and PRF.
// A CPU kernel pads, permutes and reads up to four in its vector form where it has one for them
// (cpu::one_block4); otherwise they run through the sponges in spare, made on first use, which a
// caller keeps for all its groups and which wipe their states when dropped. ONE_BLOCK: whether
// the build has a kernel for it; without one, callers keep their own sponges.
#[cfg(feature = "slh-dsa")]
pub(crate) const ONE_BLOCK: bool = cpu::ONE_BLOCK4;

#[cfg(feature = "slh-dsa")]
pub(crate) fn one_block(
    spare: &mut Option<Sponges>,
    rate: usize,
    suffix: u8,
    messages: &[&[&[u8]]],
    outs: &mut [&mut [u8]],
) {
    if cpu::one_block4(rate, suffix, messages, outs) {
        return;
    }

    let sponges = spare.get_or_insert_with(Sponges::empty);

    sponges.start(rate, suffix, messages);

    sponges.squeeze([true; MAX_SPONGES]);

    for (i, out) in outs.iter_mut().enumerate() {
        sponges.read(i, out);
    }
}

#[derive(Clone)]
pub(crate) struct Keccak {
    state: [u64; 25],
    rate: usize,
    suffix: u8,
    position: usize,
    squeezing: bool,
}

impl Keccak {
    pub(crate) const fn new(rate: usize, suffix: u8) -> Self {
        Self::resume([0; 25], rate, suffix)
    }

    // A sponge whose input so far has left `state`, in the form of to_lane, at a block boundary.
    // resume and state move states by value, so they are only for public ones: the cSHAKE and
    // KMAC prefixes.
    pub(crate) const fn resume(state: [u64; 25], rate: usize, suffix: u8) -> Self {
        Self {
            state,
            rate,
            suffix,
            position: 0,
            squeezing: false,
        }
    }

    pub(crate) const fn state(&self) -> [u64; 25] {
        self.state
    }

    // Zero bytes up to the end of the block: bytepad's padding of SP 800-185.
    pub(crate) fn pad_block(&mut self) {
        assert!(!self.squeezing, "UNSUPPORTED: cannot update after read");

        if self.position > 0 {
            permute_one(&mut self.state);

            self.position = 0;
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        assert!(!self.squeezing, "UNSUPPORTED: cannot update after read");

        while !data.is_empty() {
            // Whole blocks from a block boundary go to a CPU kernel in one call, which keeps the
            // state in its registers from one block to the next.
            if self.position == 0 {
                let absorbed = cpu::absorb(&mut self.state, self.rate, data);

                data = &data[absorbed..];

                if data.is_empty() {
                    break;
                }
            }

            let (chunk, rest) = data.split_at((self.rate - self.position).min(data.len()));

            self.xor(chunk);

            data = rest;

            if self.position == self.rate {
                permute_one(&mut self.state);

                self.position = 0;
            }
        }
    }

    fn xor(&mut self, bytes: &[u8]) {
        xor_bytes(&mut self.state, &mut self.position, bytes);
    }

    // update with one whole block at a block boundary, whose permutation permute applies, so that
    // the caller can run it beside other permutations. permute must apply exactly Keccak-f[1600].
    pub(crate) fn update_block_with(&mut self, block: &[u8], permute: impl FnOnce(&mut [u64; 25])) {
        assert!(
            !self.squeezing && self.position == 0 && block.len() == self.rate,
            "a whole block at a block boundary"
        );

        self.xor(block);

        permute(&mut self.state);

        self.position = 0;
    }

    // The padding of the input so far and the first permutation of the output, which permute
    // applies as in update_block_with.
    pub(crate) fn finish_with(&mut self, permute: impl FnOnce(&mut [u64; 25])) {
        assert!(!self.squeezing, "UNSUPPORTED: cannot finish twice");

        let last = self.rate - 1;

        self.state[self.position / 8] ^=
            to_lane(u64::from(self.suffix) << (8 * (self.position % 8)));

        self.state[last / 8] ^= to_lane(0x80 << (8 * (last % 8)));

        permute(&mut self.state);

        self.position = 0;

        self.squeezing = true;
    }

    pub(crate) fn read(&mut self, mut out: &mut [u8]) {
        if !self.squeezing {
            self.finish_with(permute_one);
        }

        while !out.is_empty() {
            if self.position == self.rate {
                permute_one(&mut self.state);

                self.position = 0;
            }

            let take = (self.rate - self.position).min(out.len());

            let (chunk, rest) = core::mem::take(&mut out).split_at_mut(take);

            self.extract(chunk);

            out = rest;
        }
    }

    // The first out.len() bytes of output for data, read once. A kernel absorbs and squeezes in
    // one call with the state in its registers.
    pub(crate) fn digest_into(rate: usize, suffix: u8, data: &[u8], out: &mut [u8]) {
        if cpu::digest(None, rate, suffix, data, out) {
            return;
        }

        let mut engine = Self::new(rate, suffix);

        engine.update(data);

        engine.read(out);
    }

    // digest_into from a state at a block boundary, such as cSHAKE's after its prefix.
    pub(crate) fn digest_from(
        start: &[u64; 25],
        rate: usize,
        suffix: u8,
        data: &[u8],
        out: &mut [u8],
    ) {
        if cpu::digest(Some(start), rate, suffix, data, out) {
            return;
        }

        let mut engine = Self::resume(*start, rate, suffix);

        engine.update(data);

        engine.read(out);
    }

    fn extract(&mut self, mut out: &mut [u8]) {
        while !self.position.is_multiple_of(8) {
            let Some((byte, rest)) = core::mem::take(&mut out).split_first_mut() else {
                return;
            };

            *byte = (from_lane(self.state[self.position / 8]) >> (8 * (self.position % 8))) as u8;

            self.position += 1;

            out = rest;
        }

        let (lanes, tail) = out.as_chunks_mut::<8>();

        for (chunk, lane) in lanes.iter_mut().zip(&self.state[self.position / 8..]) {
            *chunk = from_lane(*lane).to_le_bytes();
        }

        self.position += 8 * lanes.len();

        for byte in tail {
            *byte = (from_lane(self.state[self.position / 8]) >> (8 * (self.position % 8))) as u8;

            self.position += 1;
        }
    }
}

impl Drop for Keccak {
    fn drop(&mut self) {
        wipe(&mut self.state);
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::cpu::testing::{EDGES, Inputs};

    // Batches of one to MAX_SPONGES states, edge patterns first: the kernels permute some
    // leading states, which must equal the portable permutation, and leave the rest untouched.
    #[test]
    fn keccak_kernels_match_portable() {
        let mut inputs = Inputs::new(1600);

        let (mut states_checked, mut accelerated) = (0, 0);

        for n in 0..7_000 {
            let count = 1 + n % MAX_SPONGES;

            let mut states = [[0u64; 25]; MAX_SPONGES];

            for (i, state) in states[..count].iter_mut().enumerate() {
                *state = match EDGES.get(n / MAX_SPONGES) {
                    Some(&edge) => [edge ^ i as u64; 25],
                    None => inputs.words(),
                };
            }

            let mut expected = states;

            for state in &mut expected[..count] {
                permute(state);
            }

            let mut actual = states;

            let done = cpu::permute_many(&mut actual.each_mut()[..count]);

            assert_eq!(actual[..done], expected[..done], "case {n}");

            assert_eq!(actual[done..], states[done..], "case {n}");

            states_checked += count;

            accelerated += done;
        }

        assert!(states_checked >= 20_000);

        let (four, one) = cpu::avx512vl();

        std::eprintln!(
            "Keccak: {accelerated} of {states_checked} states through a CPU kernel \
             (AVX-512VL: {four}, one state: {one})"
        );
    }

    // The absorbing kernel against XOR and the portable permutation block by block, for every
    // rate, one to three blocks and a few bytes after them, which it must leave alone.
    #[test]
    fn absorb_kernel_matches_portable() {
        let mut inputs = Inputs::new(1088);

        let mut accelerated = 0;

        for n in 0..20_000 {
            let rate = [72, 104, 136, 144, 168][n % 5];

            let blocks = 1 + n / 5 % 3;

            let (state, data): ([u64; 25], [u8; 3 * 168 + 8]) = match EDGES.get(n / 15) {
                Some(&edge) => ([edge; 25], [!edge as u8; 3 * 168 + 8]),
                None => (inputs.words(), inputs.bytes()),
            };

            let data = &data[..blocks * rate + n % 8];

            let mut expected = state;

            for block in data.chunks_exact(rate) {
                for (lane, bytes) in expected.iter_mut().zip(block.as_chunks::<8>().0) {
                    *lane ^= u64::from_le_bytes(*bytes);
                }

                permute(&mut expected);
            }

            let mut actual = state;

            let absorbed = cpu::absorb(&mut actual, rate, data);

            if absorbed == 0 {
                assert_eq!(actual, state, "case {n}");
            } else {
                assert_eq!(absorbed, blocks * rate, "case {n}");

                assert_eq!(actual, expected, "case {n}");

                accelerated += 1;
            }
        }

        std::eprintln!("Keccak absorb: {accelerated} of 20000 cases through a CPU kernel");
    }

    // The one-call kernel against a sponge built from XOR and the portable permutation alone, for
    // every rate, three suffixes, from zero and from a given state, message lengths over several
    // blocks and outputs around the block size.
    #[test]
    fn digest_kernel_matches_portable() {
        let mut inputs = Inputs::new(200);

        let mut accelerated = 0;

        for n in 0..6_000 {
            let rate = [72, 104, 136, 144, 168][n % 5];

            let suffix = [0x06, 0x1F, 0x04][n / 5 % 3];

            let data: [u8; 3 * 168 + 9] = inputs.bytes();

            let length = (n / 15 * 37 + n) % data.len();

            let size = [
                0,
                1,
                7,
                8,
                9,
                32,
                64,
                rate - 1,
                rate,
                rate + 1,
                2 * rate + 5,
            ][n % 11];

            let initial: Option<[u64; 25]> = (n % 2 == 1).then(|| inputs.words());

            let mut padded = data[..length].to_vec();

            padded.push(suffix);

            padded.resize(padded.len().next_multiple_of(rate), 0);

            *padded.last_mut().expect("a block") ^= 0x80;

            let mut state = initial.unwrap_or([0; 25]);

            for block in padded.chunks(rate) {
                for (lane, bytes) in state.iter_mut().zip(block.as_chunks::<8>().0) {
                    *lane ^= u64::from_le_bytes(*bytes);
                }

                permute(&mut state);
            }

            let mut expected = vec![0; size];

            for (i, byte) in expected.iter_mut().enumerate() {
                if i > 0 && i % rate == 0 {
                    permute(&mut state);
                }

                *byte = (state[i % rate / 8] >> (8 * (i % 8))) as u8;
            }

            let mut actual = vec![0; size];

            if cpu::digest(initial.as_ref(), rate, suffix, &data[..length], &mut actual) {
                assert_eq!(
                    actual, expected,
                    "rate {rate}, length {length}, size {size}"
                );

                accelerated += 1;
            }
        }

        std::eprintln!("Keccak digest: {accelerated} of 6000 cases through a CPU kernel");
    }

    fn started(rate: usize, suffix: u8, messages: &[&[&[u8]]]) -> Sponges {
        let mut sponges = Sponges::empty();

        sponges.start(rate, suffix, messages);

        sponges
    }

    // Sponges against the one-sponge Keccak, for every rate, both suffixes, every message length
    // that fits in a block and one to MAX_SPONGES sponges, over three squeezed blocks. One object
    // is started again for every case, after squeezes, with more or fewer sponges than before.
    #[test]
    fn sponges_match_keccak() {
        let mut inputs = Inputs::new(4);

        let mut sponges = Sponges::empty();

        for rate in [72, 104, 136, 144, 168] {
            for suffix in [0x06, 0x1F] {
                for length in 0..rate {
                    let count = 1 + length % MAX_SPONGES;

                    let messages: [[u8; 168]; MAX_SPONGES] =
                        core::array::from_fn(|_| inputs.bytes());

                    let parts = messages.each_ref().map(|message| &message[..length]);

                    // Each message in two parts, split at a point that moves with the length.
                    let split = parts.map(|part| part.split_at(length / 3));

                    let lists = split.each_ref().map(|(a, b)| [*a, *b]);

                    let lists = lists.each_ref().map(|list| &list[..]);

                    sponges.start(rate, suffix, &lists[..count]);

                    assert!(
                        sponges.states[count..]
                            .iter()
                            .all(|state| *state == [0; 25])
                    );

                    for (i, part) in parts[..count].iter().enumerate() {
                        let mut engine = Keccak::new(rate, suffix);

                        engine.update(part);

                        let mut expected = [0; 3 * 168];

                        engine.read(&mut expected[..3 * rate]);

                        let mut copy = Sponges {
                            states: sponges.states,
                            count: sponges.count,
                            rate: sponges.rate,
                            done: sponges.done,
                            wide: sponges.wide,
                        };

                        for block in expected[..3 * rate].chunks(rate) {
                            copy.squeeze([true; MAX_SPONGES]);

                            let mut actual = [0; 168];

                            copy.read(i, &mut actual[..rate]);

                            assert_eq!(&actual[..rate], block, "rate {rate}, length {length}");
                        }
                    }

                    sponges.squeeze([true; MAX_SPONGES]);
                }
            }
        }
    }

    // The one-shot digest against update and read, for every rate, both suffixes, message
    // lengths over several blocks and outputs longer than a block.
    #[test]
    fn digest_matches_update_and_read() {
        let mut inputs = Inputs::new(8);

        for rate in [72, 104, 136, 144, 168] {
            for suffix in [0x06, 0x1F] {
                for length in (0..3 * rate + 2).step_by(5) {
                    let data: [u8; 3 * 168 + 2] = inputs.bytes();

                    let size = [32, 64, rate, 2 * rate + 7][length % 4];

                    let mut engine = Keccak::new(rate, suffix);

                    engine.update(&data[..length]);

                    let mut expected = vec![0; size];

                    engine.read(&mut expected);

                    let mut actual = vec![0; size];

                    Keccak::digest_into(rate, suffix, &data[..length], &mut actual);

                    assert_eq!(actual, expected, "rate {rate}, length {length}");

                    // The same from a state after a block, as cSHAKE's prefix leaves it.
                    let start = inputs.words();

                    let mut engine = Keccak::resume(start, rate, suffix);

                    engine.update(&data[..length]);

                    engine.read(&mut expected);

                    Keccak::digest_from(&start, rate, suffix, &data[..length], &mut actual);

                    assert_eq!(
                        actual, expected,
                        "from a state: rate {rate}, length {length}"
                    );
                }
            }
        }
    }

    // The sponge of one_block alone, for the expected output.
    #[cfg(feature = "slh-dsa")]
    fn reference(rate: usize, suffix: u8, parts: &[&[u8]], out: &mut [u8]) {
        let mut engine = Keccak::new(rate, suffix);

        for part in parts {
            engine.update(part);
        }

        engine.read(out);
    }

    // The one-block kernel and one_block against the one-sponge Keccak, for every rate, two
    // suffixes, every message length that fits in a block, one to four messages, outputs of 0 to
    // 64 bytes, and three shapes: one part, three parts of whole words with the first shared by
    // all messages (SLH-DSA's PK.seed), and three parts split anywhere, which the kernel refuses.
    #[test]
    #[cfg(feature = "slh-dsa")]
    fn one_block_kernel_matches_keccak() {
        let mut inputs = Inputs::new(0x1B);

        let (mut cases, mut accelerated) = (0, 0);

        let mut spare = None;

        for rate in [72, 104, 136, 144, 168] {
            for suffix in [0x1F, 0x06] {
                for length in 0..rate {
                    let count = 1 + length % 4;

                    let size = [0, 1, 7, 8, 9, 15, 16, 17, 24, 31, 32, 33, 40, 48, 63, 64]
                        [(length + rate) % 16]
                        .min(rate);

                    let messages: [[u8; 168]; 4] = core::array::from_fn(|_| inputs.bytes());

                    let shape = (length + suffix as usize) % 3;

                    let (first, second) = match shape {
                        0 => (length, length),
                        1 => {
                            let first = length / 3 / 8 * 8;

                            (first, first + (length - first) / 2 / 8 * 8)
                        }
                        _ => (length / 3, length / 3 + (length - length / 3) / 2),
                    };

                    let parts = messages.each_ref().map(|message| {
                        let start = if shape == 1 {
                            &messages[0][..first]
                        } else {
                            &message[..first]
                        };

                        [start, &message[first..second], &message[second..length]]
                    });

                    let lists = parts
                        .each_ref()
                        .map(|list| if shape == 0 { &list[..1] } else { &list[..] });

                    let mut expected = [[0; 64]; 4];

                    for (list, out) in lists[..count].iter().zip(&mut expected) {
                        reference(rate, suffix, list, &mut out[..size]);
                    }

                    // The bytes after each output and the outputs after count stay as they were.
                    let mut actual = [[0xA5; 64]; 4];

                    let mut outs = actual.each_mut().map(|out| &mut out[..size]);

                    if cpu::one_block4(rate, suffix, &lists[..count], &mut outs[..count]) {
                        for (s, out) in actual.iter().enumerate() {
                            let (written, after) = out.split_at(size);

                            if s < count {
                                assert_eq!(written, &expected[s][..size], "{rate} {length}");
                            } else {
                                assert!(written.iter().all(|&byte| byte == 0xA5));
                            }

                            assert!(after.iter().all(|&byte| byte == 0xA5));
                        }

                        accelerated += 1;
                    } else {
                        assert!(actual.iter().all(|out| *out == [0xA5; 64]));
                    }

                    let mut actual = [[0; 64]; 4];

                    let mut outs = actual.each_mut().map(|out| &mut out[..size]);

                    one_block(
                        &mut spare,
                        rate,
                        suffix,
                        &lists[..count],
                        &mut outs[..count],
                    );

                    assert_eq!(actual, expected, "one_block: {rate} {length}");

                    cases += 1;
                }
            }
        }

        std::eprintln!("Keccak one-block: {accelerated} of {cases} cases through a CPU kernel");
    }

    // The CAVP SHAKE128 and SHAKE256 ShortMsg known answers whose message fits in one block, each
    // as four messages through one_block: one slice for all four, which the kernel broadcasts,
    // four copies, which it transposes, and the message alone.
    #[test]
    #[cfg(feature = "slh-dsa")]
    fn one_block_kernel_shake_vectors() {
        let mut checked = 0;

        let mut spare = None;

        for (name, rate) in [("SHAKE128", 168), ("SHAKE256", 136)] {
            let path = std::format!(
                "{}/../vectors/cavp/{name}ShortMsg.rsp",
                env!("CARGO_MANIFEST_DIR")
            );

            let text = std::fs::read_to_string(&path).unwrap();

            let mut length = 0;

            let mut message = vec![];

            for line in text.lines().map(str::trim) {
                let Some((field, value)) = line.split_once(" = ") else {
                    continue;
                };

                let bytes = || {
                    (0..value.len() / 2)
                        .map(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
                        .collect::<alloc::vec::Vec<u8>>()
                };

                match field {
                    "Len" => length = value.parse::<usize>().unwrap() / 8,
                    "Msg" => message = bytes()[..length].to_vec(),
                    "Output" if length < rate => {
                        let expected = bytes();

                        let copies = [message.clone(), message.clone(), message.clone()];

                        let single = [&message[..]];

                        let shared = [&single[..]; 4];

                        let lists = [
                            [&message[..]],
                            [&copies[0][..]],
                            [&copies[1][..]],
                            [&copies[2][..]],
                        ];

                        let apart = lists.each_ref().map(|list| &list[..]);

                        for messages in [&shared[..], &apart, &shared[..1]] {
                            let mut actual = [[0; 64]; 4];

                            let mut outs = actual.each_mut().map(|out| &mut out[..expected.len()]);

                            let count = messages.len();

                            one_block(&mut spare, rate, 0x1F, messages, &mut outs[..count]);

                            for out in &actual[..count] {
                                assert_eq!(out[..expected.len()], expected, "{name} {length}");
                            }
                        }

                        checked += 1;
                    }
                    _ => continue,
                }
            }
        }

        assert_eq!(checked, 168 + 136);
    }

    #[test]
    fn compile_time_permutation_matches() {
        let mut inputs = Inputs::new(25);

        for n in 0..100 {
            let mut state: [u64; 25] = match EDGES.get(n) {
                Some(&edge) => [edge; 25],
                None => inputs.words(),
            };

            let mut expected = state.map(to_lane);

            permute(&mut expected);

            permute_const(&mut state);

            assert_eq!(state, expected.map(from_lane), "case {n}");
        }
    }

    // permute_all, which runs states two at a time where pairs hold them, against permute one
    // state at a time, for one to MAX_SPONGES states.
    #[test]
    fn all_states_match_one_at_a_time() {
        let mut inputs = Inputs::new(1600);

        for n in 0..200 {
            let count = 1 + n % MAX_SPONGES;

            let mut states: [[u64; 25]; MAX_SPONGES] = core::array::from_fn(|_| inputs.words());

            let mut expected = states;

            for state in &mut expected[..count] {
                permute(state);
            }

            permute_all(&mut states.each_mut()[..count]);

            assert_eq!(states, expected, "case {n}");
        }
    }

    // A hash fed whole blocks whose permutations run beside a squeeze of sponges gives the same
    // digest as alone, and the sponges the same blocks, for every count of sponges that leaves a
    // slot free and every pattern of active sponges.
    #[test]
    fn permutations_beside_sponges_match() {
        let mut inputs = Inputs::new(136);

        for count in 1..MAX_SPONGES {
            for pattern in 0..1usize << count {
                let messages: [[u8; 34]; MAX_SPONGES] = core::array::from_fn(|_| inputs.bytes());

                let parts = messages.each_ref().map(|message| [&message[..]]);

                let lists = parts.each_ref().map(|list| &list[..]);

                let mut sponges = started(168, 0x1F, &lists[..count]);

                let mut expected = started(168, 0x1F, &lists[..count]);

                let data: [u8; 3 * 136] = inputs.bytes();

                let mut hash = Keccak::new(136, 0x06);

                let active = core::array::from_fn(|i| pattern & (1 << i) != 0);

                for block in data.chunks(136) {
                    hash.update_block_with(block, |state| sponges.squeeze_beside(active, state));

                    expected.squeeze(active);
                }

                assert_eq!(sponges.states[..count], expected.states[..count]);

                for (i, message) in messages[..count].iter().enumerate() {
                    if active[i] {
                        let mut engine = Keccak::new(168, 0x1F);

                        engine.update(message);

                        let mut stream = [0; 3 * 168];

                        engine.read(&mut stream);

                        let mut block = [0; 168];

                        sponges.read(i, &mut block);

                        assert_eq!(block, stream[2 * 168..], "{count} sponges, sponge {i}");
                    }
                }

                let mut alone = Keccak::new(136, 0x06);

                alone.update(&data);

                let (mut digest, mut reference) = ([0; 32], [0; 32]);

                hash.read(&mut digest);

                alone.read(&mut reference);

                assert_eq!(digest, reference, "{count} sponges, pattern {pattern:b}");
            }
        }
    }

    // A sponge left out of a squeeze keeps its block, and the others advance as they would alone.
    #[test]
    fn inactive_sponges_keep_their_state() {
        let messages: [[u8; 34]; 4] = core::array::from_fn(|i| [i as u8; 34]);

        let parts = messages.each_ref().map(|message| [&message[..]]);

        let lists = parts.each_ref().map(|list| &list[..]);

        let mut sponges = started(168, 0x1F, &lists);

        sponges.squeeze([true; MAX_SPONGES]);

        let before = sponges.states;

        sponges.squeeze(core::array::from_fn(|i| i % 2 == 1));

        for (i, [part]) in parts.iter().enumerate() {
            let mut engine = Keccak::new(168, 0x1F);

            engine.update(part);

            let mut expected = [0; 2 * 168];

            engine.read(&mut expected);

            let mut actual = [0; 168];

            sponges.read(i, &mut actual);

            let block = i % 2;

            assert_eq!(
                actual,
                expected[168 * block..168 * (block + 1)],
                "sponge {i}"
            );

            if i % 2 == 0 {
                assert_eq!(sponges.states[i], before[i]);
            }
        }
    }

    // retire's mask against the sponges it names, for every pattern and count.
    #[test]
    fn retire_marks_exactly_the_left_out() {
        for count in 0..=MAX_SPONGES {
            for pattern in 0..=u8::MAX {
                let active = core::array::from_fn(|i| pattern >> i & 1 == 1);

                let mut sponges = Sponges::empty();

                sponges.count = count;

                sponges.retire(&active);

                let left_out = (0..count).fold(0u8, |m, i| m | u8::from(!active[i]) << i);

                assert_eq!(
                    sponges.done & mask_of(count),
                    left_out,
                    "{count} {pattern:#04x}"
                );

                assert_eq!(
                    sponges.done | mask_of(count),
                    u8::MAX,
                    "{count} {pattern:#04x}"
                );
            }
        }
    }

    fn mask_of(count: usize) -> u8 {
        ((1u16 << count) - 1) as u8
    }

    // A sponge left out of a squeeze is done on every path, so that no caller relies on squeezing
    // it again where the vector form would have permuted it.
    #[test]
    #[should_panic(expected = "a sponge left out is not squeezed again")]
    fn sponges_left_out_are_done() {
        let messages: [[u8; 34]; 4] = core::array::from_fn(|i| [i as u8; 34]);

        let parts = messages.each_ref().map(|message| [&message[..]]);

        let lists = parts.each_ref().map(|list| &list[..]);

        let mut sponges = started(168, 0x1F, &lists);

        sponges.squeeze(core::array::from_fn(|i| i != 2));

        sponges.squeeze([true; MAX_SPONGES]);
    }
}
