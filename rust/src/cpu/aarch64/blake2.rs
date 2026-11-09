// BLAKE2b and BLAKE2s on the general registers, for a core on which an EOR with a rotated operand
// costs a plain EOR (LAZY in aarch64.rs): each (d ^ a) >>> r of a G function is taken as
// (d >>> r) ^ (a >>> r), one ROR of d, which was ready a step before, and one EOR with a rotated
// operand, so the rotation leaves the chain of dependent instructions. ROR, ADD and EOR, shifted
// or not, are on Arm's data-independent-timing list, and no address depends on the data.
//
// BLAKE2b's compressions, in a call with two or more of them, are one loop of assembly (D-101):
// the state takes sixteen registers, words 0 to 8 of the block nine more, and each of the other
// seven words is loaded from the block where a G function adds it. Compiled from Rust, the rounds
// kept the sixteen message words beside the state, more values than there are registers, and
// spilled some of them in every block. A call with one compression and BLAKE2s stay in Rust, in
// which LLVM folds the two rotations back into one of the XOR unless the rotation of d goes
// through an empty assembly block.

use core::mem::MaybeUninit;

use crate::blake2::{Last, SIGMA, Word};
use crate::wipe::wipe_unless_optimized;

// A value that the compiler cannot see through: its rotation stays one of its own.
pub(super) trait Opaque: Copy + 'static {
    fn opaque(self) -> Self;

    fn iv() -> &'static [Self; 8];
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

    // The IV as memory that the compiler cannot see through. As constants in the code its words
    // took 32 MOV and MOVK per block, and BLAKE2b of 16 KiB took 1.1% more time on Neoverse N2. In
    // BLAKE2s, with half of them, it was the loads that took up to 0.8% more time there.
    #[inline(always)]
    #[allow(unsafe_code)]
    fn iv() -> &'static [Self; 8] {
        let table: *const [Self; 8] = &<Self as Word>::IV;

        let mut address = table as usize;

        // SAFETY: as for opaque.
        unsafe {
            core::arch::asm!(
                "/* {0} */",
                inout(reg) address,
                options(pure, nomem, nostack, preserves_flags),
            );
        }

        // SAFETY: the address of the constant above, unchanged.
        unsafe { &*(address as *const [Self; 8]) }
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

    #[inline(always)]
    fn iv() -> &'static [Self; 8] {
        &<Self as Word>::IV
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
    let iv = W::iv();

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

// a += the message word at index $x of the block: one of w0 to w8, which hold words 0 to 8 from
// the start of each block, or the word loaded into t.
macro_rules! add_word {
    ($a:literal, 0) => {
        concat!("add {", $a, "}, {", $a, "}, {w0}\n")
    };
    ($a:literal, 1) => {
        concat!("add {", $a, "}, {", $a, "}, {w1}\n")
    };
    ($a:literal, 2) => {
        concat!("add {", $a, "}, {", $a, "}, {w2}\n")
    };
    ($a:literal, 3) => {
        concat!("add {", $a, "}, {", $a, "}, {w3}\n")
    };
    ($a:literal, 4) => {
        concat!("add {", $a, "}, {", $a, "}, {w4}\n")
    };
    ($a:literal, 5) => {
        concat!("add {", $a, "}, {", $a, "}, {w5}\n")
    };
    ($a:literal, 6) => {
        concat!("add {", $a, "}, {", $a, "}, {w6}\n")
    };
    ($a:literal, 7) => {
        concat!("add {", $a, "}, {", $a, "}, {w7}\n")
    };
    ($a:literal, 8) => {
        concat!("add {", $a, "}, {", $a, "}, {w8}\n")
    };
    ($a:literal, $x:tt) => {
        concat!(
            concat!("ldr {t}, [{m}, #", $x, "*8]\n"),
            concat!("add {", $a, "}, {", $a, "}, {t}\n"),
        )
    };
}

// Half of a G function, in the registers named: a += b + x, with x the message word at index $x
// of the block, then d = (d ^ a) >>> r1, c += d and b = (b ^ c) >>> r2, each rotation as in
// xor_rotate.
macro_rules! half_g {
    ($a:literal, $b:literal, $c:literal, $d:literal, $x:tt, $r1:literal, $r2:literal) => {
        concat!(
            add_word!($a, $x),
            concat!("add {", $a, "}, {", $a, "}, {", $b, "}\n"),
            concat!("ror {", $d, "}, {", $d, "}, #", $r1, "\n"),
            concat!("eor {", $d, "}, {", $d, "}, {", $a, "}, ror #", $r1, "\n"),
            concat!("add {", $c, "}, {", $c, "}, {", $d, "}\n"),
            concat!("ror {", $b, "}, {", $b, "}, #", $r2, "\n"),
            concat!("eor {", $b, "}, {", $b, "}, {", $c, "}, ror #", $r2, "\n"),
        )
    };
}

// The four G functions of a column or a diagonal step, side by side: the first halves of all
// four, then the second halves.
macro_rules! step {
    ($($a:literal $b:literal $c:literal $d:literal $x:tt $y:tt),* $(,)?) => {
        concat!(
            $(half_g!($a, $b, $c, $d, $x, 32, 24),)*
            $(half_g!($a, $b, $c, $d, $y, 16, 63),)*
        )
    };
}

// A round of RFC 7693, 3.2, with its row of SIGMA.
macro_rules! round_b {
    ($s0:tt $s1:tt $s2:tt $s3:tt $s4:tt $s5:tt $s6:tt $s7:tt $s8:tt $s9:tt $s10:tt $s11:tt $s12:tt
     $s13:tt $s14:tt $s15:tt) => {
        concat!(
            step!(
                "v0" "v4" "v8" "v12" $s0 $s1,
                "v1" "v5" "v9" "v13" $s2 $s3,
                "v2" "v6" "v10" "v14" $s4 $s5,
                "v3" "v7" "v11" "v15" $s6 $s7,
            ),
            step!(
                "v0" "v5" "v10" "v15" $s8 $s9,
                "v1" "v6" "v11" "v12" $s10 $s11,
                "v2" "v7" "v8" "v13" $s12 $s13,
                "v3" "v4" "v9" "v14" $s14 $s15,
            ),
        )
    };
}

// Blocks one after another in memory, with the counter and flag word of the first: the
// compression of each block takes count down and the counter up by 128.
#[repr(C)]
#[derive(Clone, Copy)]
struct Run {
    block: *const u8,
    count: u64,
    low: u64,
    high: u64,
    flag: u64,
}

// What compress_runs reads and writes in memory: IV, where the chaining value is, the run being
// compressed, and the runs in order, the one after the last with count 0. process_b writes IV and
// the runs up to that one, and the assembly writes h and run before it reads them.
#[repr(C)]
struct Plan {
    iv: [u64; 8],
    h: MaybeUninit<*mut u64>,
    run: MaybeUninit<*const Run>,
    runs: [MaybeUninit<Run>; 4],
}

// The offsets that the assembly of compress_runs reads and writes at.
const _: () = {
    assert!(core::mem::offset_of!(Plan, h) == 64);

    assert!(core::mem::offset_of!(Plan, run) == 72);

    assert!(core::mem::offset_of!(Plan, runs) == 80);

    assert!(core::mem::size_of::<Run>() == 40);

    assert!(core::mem::offset_of!(Run, count) == 8);

    assert!(core::mem::offset_of!(Run, low) == 16);

    assert!(core::mem::offset_of!(Run, high) == 24);

    assert!(core::mem::offset_of!(Run, flag) == 32);
};

static IV: [u64; 8] = <u64 as Word>::IV;

// The compressions of RFC 7693, 3.2, of BLAKE2b into h, of the blocks of plan's runs in order, the
// first run's block also given in a register (D-101). One loop of assembly, out of line, holds the
// one copy of the rounds: LLVM takes an assembly block for a short one and copies it into each path
// of a loop around it. The chaining value goes from one block to the next in the registers of the
// state, and its copy in h, stored after each block, is read back for the next one's final XOR; the
// counter, the flag word and the run are read from plan at the start of a block and the counter
// written back at its end, so that the registers left over hold words 0 to 8 of the block from its
// start, and only the other seven of each round are loaded from it.
#[inline(never)]
#[allow(unsafe_code)]
fn compress_runs(plan: &mut Plan, h: &mut [u64; 8], block: *const u8) {
    // SAFETY: plan's runs, which process_b fills, are runs of whole blocks that are borrowed for
    // the call, each with count at least 1, then one with count 0, before the end of runs, and no
    // run after that one is read; block is the first run's. The loads read IV, plan, h and the
    // blocks of each run, once for each of its blocks, and the stores write plan's h and run, each
    // before it is read, the counters and counts of its runs, and the 64 bytes of h, all at
    // immediate offsets from their addresses: memory that the call borrows, h and plan exclusively.
    // The other operands are registers, and the stack is not touched. At the start, w8 holds h and
    // w7 IV, each read before the first block's words are loaded into them.
    unsafe {
        core::arch::asm!(
            "str {w8}, [{plan}, #64]",
            "add {t}, {plan}, #80",
            "str {t}, [{plan}, #72]",
            "ldp {v0}, {v1}, [{w8}]",
            "ldp {v2}, {v3}, [{w8}, #16]",
            "ldp {v4}, {v5}, [{w8}, #32]",
            "ldp {v6}, {v7}, [{w8}, #48]",
            "ldp {v8}, {v9}, [{w7}]",
            "ldp {v10}, {v11}, [{w7}, #16]",
            "ldp {v12}, {v13}, [{w7}, #32]",
            "ldp {v14}, {v15}, [{w7}, #48]",
            "ldp {w1}, {w2}, [{plan}, #96]",
            "ldr {w0}, [{plan}, #112]",
            "eor {v12}, {v12}, {w1}",
            "eor {v13}, {v13}, {w2}",
            "eor {v14}, {v14}, {w0}",
            // The first block, which the caller may have just written, is read one word at a time.
            "ldr {w0}, [{m}]",
            "ldr {w1}, [{m}, #8]",
            "ldr {w2}, [{m}, #16]",
            "ldr {w3}, [{m}, #24]",
            "ldr {w4}, [{m}, #32]",
            "ldr {w5}, [{m}, #40]",
            "ldr {w6}, [{m}, #48]",
            "ldr {w7}, [{m}, #56]",
            "ldr {w8}, [{m}, #64]",
            "b 3f",
            "4:",
            "ldp {w1}, {w2}, [{t}, #16]",
            "5:",
            "ldr {w0}, [{t}, #32]",
            "ldp {v8}, {v9}, [{plan}]",
            "ldp {v10}, {v11}, [{plan}, #16]",
            "ldp {v12}, {v13}, [{plan}, #32]",
            "ldp {v14}, {v15}, [{plan}, #48]",
            "eor {v12}, {v12}, {w1}",
            "eor {v13}, {v13}, {w2}",
            "eor {v14}, {v14}, {w0}",
            "ldp {w0}, {w1}, [{m}]",
            "ldp {w2}, {w3}, [{m}, #16]",
            "ldp {w4}, {w5}, [{m}, #32]",
            "ldp {w6}, {w7}, [{m}, #48]",
            "ldr {w8}, [{m}, #64]",
            "3:",
            round_b!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15),
            round_b!(14 10 4 8 9 15 13 6 1 12 0 2 11 7 5 3),
            round_b!(11 8 12 0 5 2 15 13 10 14 3 6 7 1 9 4),
            round_b!(7 9 3 1 13 12 11 14 2 6 5 10 4 0 15 8),
            round_b!(9 0 5 7 2 4 10 15 14 1 11 12 6 8 3 13),
            round_b!(2 12 6 10 0 11 8 3 4 13 7 5 15 14 1 9),
            round_b!(12 5 1 15 14 13 4 10 0 7 6 3 9 2 8 11),
            round_b!(13 11 7 14 12 1 3 9 5 0 15 4 8 6 2 10),
            round_b!(6 15 14 9 11 3 0 8 12 2 13 7 1 4 10 5),
            round_b!(10 2 8 4 7 6 1 5 15 11 9 14 3 12 13 0),
            round_b!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15),
            round_b!(14 10 4 8 9 15 13 6 1 12 0 2 11 7 5 3),
            "eor {v0}, {v0}, {v8}",
            "eor {v1}, {v1}, {v9}",
            "eor {v2}, {v2}, {v10}",
            "eor {v3}, {v3}, {v11}",
            "eor {v4}, {v4}, {v12}",
            "eor {v5}, {v5}, {v13}",
            "eor {v6}, {v6}, {v14}",
            "eor {v7}, {v7}, {v15}",
            "ldr {t}, [{plan}, #64]",
            "ldp {v8}, {v9}, [{t}]",
            "ldp {v10}, {v11}, [{t}, #16]",
            "ldp {v12}, {v13}, [{t}, #32]",
            "ldp {v14}, {v15}, [{t}, #48]",
            "eor {v0}, {v0}, {v8}",
            "eor {v1}, {v1}, {v9}",
            "eor {v2}, {v2}, {v10}",
            "eor {v3}, {v3}, {v11}",
            "eor {v4}, {v4}, {v12}",
            "eor {v5}, {v5}, {v13}",
            "eor {v6}, {v6}, {v14}",
            "eor {v7}, {v7}, {v15}",
            "stp {v0}, {v1}, [{t}]",
            "stp {v2}, {v3}, [{t}, #16]",
            "stp {v4}, {v5}, [{t}, #32]",
            "stp {v6}, {v7}, [{t}, #48]",
            "ldr {t}, [{plan}, #72]",
            "ldp {w0}, {w1}, [{t}, #8]",
            "ldr {w2}, [{t}, #24]",
            "adds {w1}, {w1}, #128",
            "adc {w2}, {w2}, xzr",
            "stp {w1}, {w2}, [{t}, #16]",
            "add {m}, {m}, #128",
            "subs {w0}, {w0}, #1",
            "str {w0}, [{t}, #8]",
            "b.ne 5b",
            "add {t}, {t}, #40",
            "str {t}, [{plan}, #72]",
            "ldp {m}, {w0}, [{t}]",
            "cbnz {w0}, 4b",
            plan = in(reg) &raw mut *plan,
            m = inout(reg) block => _,
            w0 = out(reg) _,
            w1 = out(reg) _,
            w2 = out(reg) _,
            w3 = out(reg) _,
            w4 = out(reg) _,
            w5 = out(reg) _,
            w6 = out(reg) _,
            w7 = inout(reg) IV.as_ptr() => _,
            w8 = inout(reg) h.as_mut_ptr() => _,
            v0 = out(reg) _,
            v1 = out(reg) _,
            v2 = out(reg) _,
            v3 = out(reg) _,
            v4 = out(reg) _,
            v5 = out(reg) _,
            v6 = out(reg) _,
            v7 = out(reg) _,
            v8 = out(reg) _,
            v9 = out(reg) _,
            v10 = out(reg) _,
            v11 = out(reg) _,
            v12 = out(reg) _,
            v13 = out(reg) _,
            v14 = out(reg) _,
            v15 = out(reg) _,
            t = out(reg) _,
            options(nostack),
        );
    }
}

impl Run {
    const END: Self = Self {
        block: core::ptr::null(),
        count: 0,
        low: 0,
        high: 0,
        flag: 0,
    };

    fn new(block: *const u8, count: usize, counter: u128, flag: u64) -> Self {
        let [low, high] = <u64 as Word>::counter(counter);

        Self {
            block,
            count: count as u64,
            low,
            high,
            flag,
        }
    }
}

// process for BLAKE2b with two or more compressions: the key block, the whole blocks and the final
// block, those there are, as the runs of one compress_runs, which reads each block's words where
// they are.
#[inline(never)]
pub(super) fn process_b(
    h: &mut [u64; 8],
    first: Option<&[u64; 16]>,
    blocks: &[[u8; 128]],
    counter: u128,
    last: Last<'_, u64>,
) {
    let key = first.map(|block| Run::new(block.as_ptr().cast(), 1, counter.wrapping_add(128), 0));

    let skip = if first.is_some() { 256 } else { 128 };

    let whole = (!blocks.is_empty()).then(|| {
        Run::new(
            blocks.as_ptr().cast(),
            blocks.len(),
            counter.wrapping_add(skip),
            0,
        )
    });

    let end = last.map(|(words, total)| Run::new(words.as_ptr().cast(), 1, total, u64::MAX));

    // The first run's block also goes to compress_runs in a register, so that the loads of its
    // words do not wait for the store of it into plan.
    let Some(lead) = key.or(whole).or(end) else {
        return;
    };

    let mut plan = Plan {
        iv: IV,
        h: MaybeUninit::uninit(),
        run: MaybeUninit::uninit(),
        runs: [const { MaybeUninit::uninit() }; 4],
    };

    let mut k = 0;

    if let Some(run) = key {
        plan.runs[k].write(run);

        k += 1;
    }

    if let Some(run) = whole {
        plan.runs[k].write(run);

        k += 1;
    }

    if let Some(run) = end {
        plan.runs[k].write(run);

        k += 1;
    }

    plan.runs[k].write(Run::END);

    compress_runs(&mut plan, h, lead.block);
}

// process_b and process against the portable compression on every core, with LAZY or without:
// they use only the base instructions, and LAZY decides only where they run.
#[cfg(test)]
mod tests {
    use super::{process, process_b};
    use crate::blake2::{Word, compress};
    use crate::cpu::testing::{EDGES, Inputs};

    struct Case<W> {
        h: [W; 8],
        first: Option<[W; 16]>,
        bytes: [u8; 3 * 128],
        count: usize,
        counter: u128,
        last: Option<([W; 16], u128)>,
    }

    // Random and edge words, with a key block and without, with a final block and without, zero to
    // three whole blocks, and counters from zero to near 2^128, where they wrap.
    fn random_case<W: Word>(inputs: &mut Inputs, n: usize, word: impl Fn(u64) -> W) -> Case<W> {
        let edge = EDGES.get(n / 16).copied();

        let pick = |inputs: &mut Inputs| word(edge.unwrap_or_else(|| inputs.next()));

        let h = core::array::from_fn(|_| pick(inputs));

        let first: [W; 16] = core::array::from_fn(|_| pick(inputs));

        let last: [W; 16] = core::array::from_fn(|_| pick(inputs));

        let counter = match n % 3 {
            0 => 0,
            1 => u128::from(inputs.next()),
            _ => u128::MAX - 300,
        };

        let total = counter.wrapping_add(u128::from(inputs.next() % 1000));

        Case {
            h,
            first: (n % 2 == 1).then_some(first),
            bytes: inputs.bytes(),
            count: n % 4,
            counter,
            last: (!n.is_multiple_of(5)).then_some((last, total)),
        }
    }

    fn expected<W: Word>(case: &Case<W>) -> [W; 8] {
        let size = 16 * W::BYTES;

        let mut h = case.h;

        let mut t = case.counter;

        if let Some(first) = &case.first {
            t = t.wrapping_add(size as u128);

            compress(&mut h, first, t, false);
        }

        for block in case.bytes[..case.count * size].chunks_exact(size) {
            let m: [W; 16] =
                core::array::from_fn(|i| W::from_le(&block[i * W::BYTES..(i + 1) * W::BYTES]));

            t = t.wrapping_add(size as u128);

            compress(&mut h, &m, t, false);
        }

        if let Some((m, total)) = &case.last {
            compress(&mut h, m, *total, true);
        }

        h
    }

    #[test]
    fn lazy_blake2b_matches_portable() {
        let mut inputs = Inputs::new(26);

        for n in 0..4_000 {
            let case = random_case(&mut inputs, n, |x| x);

            let mut h = case.h;

            process_b(
                &mut h,
                case.first.as_ref(),
                &case.bytes.as_chunks::<128>().0[..case.count],
                case.counter,
                case.last.as_ref().map(|(m, total)| (m, *total)),
            );

            assert_eq!(h, expected(&case), "case {n}");
        }
    }

    #[test]
    fn lazy_blake2s_matches_portable() {
        let mut inputs = Inputs::new(27);

        for n in 0..4_000 {
            let case = random_case(&mut inputs, n, |x| x as u32);

            let mut h = case.h;

            process(
                &mut h,
                case.first.as_ref(),
                &case.bytes[..case.count * 64],
                case.counter,
                case.last.as_ref().map(|(m, total)| (m, *total)),
            );

            assert_eq!(h, expected(&case), "case {n}");
        }
    }
}
