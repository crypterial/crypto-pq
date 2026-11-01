// BLAKE3 on sixteen inputs side by side in 512-bit registers, for hash_many and the extended
// output, on the cores of the table in zmm_lanes() of x86_64.rs (D-44), and on eight in 256-bit
// registers with the AVX-512VL instructions for hash_many's groups of eight there. Each register
// holds one state word of sixteen (or eight) inputs, as each of blake3.rs's eight-lane AVX2
// kernels holds eight: the state is in registers 0 to 15 and the message words in 16 to 31, all
// in registers through the seven rounds, and every rotation is one VPRORD. The blocks of the
// sixteen inputs are loaded in 256-bit halves, inputs i and i + 4 in one register, the high half
// an insert from memory, which leaves the shuffle port free, and transposed into words with
// VPUNPCKLQDQ, VPUNPCKHQDQ, VSHUFPS and VSHUFI32X4: 48 shuffles a block, where whole-block loads
// took 64. The outputs go back with VPUNPCKLDQ, VPUNPCKHDQ, VPUNPCKLQDQ, VPUNPCKHQDQ and
// VSHUFI32X4. The eight-lane kernel loads and stores as the AVX2 kernel does. Every instruction is
// on Intel's list of data-operand-independent timing instructions, or counts as on it by D-75
// (VSHUFPS), and no branch or address depends on the data. The extended output's counters, public
// values, are stepped with VPCMPUD and a VPADDD under its mask.
//
// The three kernels are the only functions built with AVX-512F, and the two of sixteen lanes the
// only code with 512-bit registers, which CI checks. Each is one block of assembly that ends by
// zeroing registers 16 to 31, which no other code uses, and with VZEROUPPER.

use super::blake3::Table;
use crate::sha2::IV_256;

// The values of a call that the assembly reads at fixed offsets: the counters of the sixteen
// lanes, low words at 0 and high words at 64, the flags of each block at 128, the IV's first four
// words at 192 and the block length at 208. Public values only.
#[repr(C, align(64))]
pub(super) struct Table16 {
    pub(super) low: [u32; 16],
    pub(super) high: [u32; 16],
    pub(super) flags: [u32; 16],
    // Read by the assembly only.
    #[allow(dead_code)]
    iv: [u32; 4],
    pub(super) length: u32,
}

impl Table16 {
    pub(super) const fn new() -> Self {
        Self {
            low: [0; 16],
            high: [0; 16],
            flags: [0; 16],
            iv: [IV_256[0], IV_256[1], IV_256[2], IV_256[3]],
            length: 64,
        }
    }
}

// The steps of the extended output's counters, which the assembly reads: each lane's offset from
// the first, at 0, the step from one group to the next, at 64, and the carry into a high word, at
// 68. A constant in memory, where a table built for the call would be read back from its stores.
#[repr(C, align(64))]
#[allow(dead_code)]
struct Steps {
    lanes: [u32; 16],
    group: u32,
    carry: u32,
}

static STEPS: Steps = Steps {
    lanes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    group: 16,
    carry: 1,
};

// Instruction op on registers x, y and z of the width that r names: "zmm" in the sixteen-lane
// kernels, "ymm" in the eight-lane one.
macro_rules! vec_op {
    ($r:literal, $op:literal, $x:literal, $y:literal, $z:literal) => {
        concat!($op, " ", $r, $x, ", ", $r, $y, ", ", $r, $z, "\n")
    };
}

macro_rules! zmm_op {
    ($op:literal, $x:literal, $y:literal, $z:literal) => {
        vec_op!("zmm", $op, $x, $y, $z)
    };
}

macro_rules! vec_ror {
    ($r:literal, $x:literal, $n:literal) => {
        concat!("vprord ", $r, $x, ", ", $r, $x, ", ", $n, "\n")
    };
}

// Half a step of four G functions: a += m + b, d = (d ^ a) >>> dr, c += d, b = (b ^ c) >>> br,
// v_i in register i and the message words in the registers m.
#[rustfmt::skip]
macro_rules! vec_half {
    (
        $r:literal,
        [$a0:literal, $a1:literal, $a2:literal, $a3:literal],
        [$b0:literal, $b1:literal, $b2:literal, $b3:literal],
        [$c0:literal, $c1:literal, $c2:literal, $c3:literal],
        [$d0:literal, $d1:literal, $d2:literal, $d3:literal],
        [$m0:literal, $m1:literal, $m2:literal, $m3:literal],
        $dr:literal, $br:literal
    ) => {
        concat!(
            vec_op!($r, "vpaddd", $a0, $a0, $m0), vec_op!($r, "vpaddd", $a1, $a1, $m1),
            vec_op!($r, "vpaddd", $a2, $a2, $m2), vec_op!($r, "vpaddd", $a3, $a3, $m3),
            vec_op!($r, "vpaddd", $a0, $a0, $b0), vec_op!($r, "vpaddd", $a1, $a1, $b1),
            vec_op!($r, "vpaddd", $a2, $a2, $b2), vec_op!($r, "vpaddd", $a3, $a3, $b3),
            vec_op!($r, "vpxord", $d0, $d0, $a0), vec_op!($r, "vpxord", $d1, $d1, $a1),
            vec_op!($r, "vpxord", $d2, $d2, $a2), vec_op!($r, "vpxord", $d3, $d3, $a3),
            vec_ror!($r, $d0, $dr), vec_ror!($r, $d1, $dr),
            vec_ror!($r, $d2, $dr), vec_ror!($r, $d3, $dr),
            vec_op!($r, "vpaddd", $c0, $c0, $d0), vec_op!($r, "vpaddd", $c1, $c1, $d1),
            vec_op!($r, "vpaddd", $c2, $c2, $d2), vec_op!($r, "vpaddd", $c3, $c3, $d3),
            vec_op!($r, "vpxord", $b0, $b0, $c0), vec_op!($r, "vpxord", $b1, $b1, $c1),
            vec_op!($r, "vpxord", $b2, $b2, $c2), vec_op!($r, "vpxord", $b3, $b3, $c3),
            vec_ror!($r, $b0, $br), vec_ror!($r, $b1, $br),
            vec_ror!($r, $b2, $br), vec_ror!($r, $b3, $br),
        )
    };
}

// A round whose message words are in the registers s, in the round's order: the columns, then
// the diagonals.
#[rustfmt::skip]
macro_rules! vec_round {
    (
        $r:literal,
        $s0:literal, $s1:literal, $s2:literal, $s3:literal, $s4:literal, $s5:literal,
        $s6:literal, $s7:literal, $s8:literal, $s9:literal, $s10:literal, $s11:literal,
        $s12:literal, $s13:literal, $s14:literal, $s15:literal
    ) => {
        concat!(
            vec_half!(
                $r, [0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15],
                [$s0, $s2, $s4, $s6], 16, 12
            ),
            vec_half!(
                $r, [0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15],
                [$s1, $s3, $s5, $s7], 8, 7
            ),
            vec_half!(
                $r, [0, 1, 2, 3], [5, 6, 7, 4], [10, 11, 8, 9], [15, 12, 13, 14],
                [$s8, $s10, $s12, $s14], 16, 12
            ),
            vec_half!(
                $r, [0, 1, 2, 3], [5, 6, 7, 4], [10, 11, 8, 9], [15, 12, 13, 14],
                [$s9, $s11, $s13, $s15], 8, 7
            ),
        )
    };
}

// The seven rounds, message word j in register 16 + j: each round's order is the specification's
// message schedule plus 16.
#[rustfmt::skip]
macro_rules! vec_seven {
    ($r:literal) => {
        concat!(
            vec_round!($r, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31),
            vec_round!($r, 18, 22, 19, 26, 23, 16, 20, 29, 17, 27, 28, 21, 25, 30, 31, 24),
            vec_round!($r, 19, 20, 26, 28, 29, 18, 23, 30, 22, 21, 25, 16, 27, 31, 24, 17),
            vec_round!($r, 26, 23, 28, 25, 30, 19, 29, 31, 20, 16, 27, 18, 21, 24, 17, 22),
            vec_round!($r, 28, 29, 25, 27, 31, 26, 30, 24, 23, 18, 21, 19, 16, 17, 22, 20),
            vec_round!($r, 25, 30, 27, 21, 24, 28, 31, 17, 29, 19, 16, 26, 18, 22, 20, 23),
            vec_round!($r, 27, 31, 21, 16, 17, 25, 24, 22, 30, 26, 18, 28, 19, 20, 23, 29),
        )
    };
}

// The four-word transposition of registers x within each 128-bit quarter, through t: word i of
// quarter q of x_j to word j of quarter q of x_i.
#[rustfmt::skip]
macro_rules! vec_four {
    (
        $r:literal,
        $x0:literal, $x1:literal, $x2:literal, $x3:literal,
        $t0:literal, $t1:literal, $t2:literal, $t3:literal
    ) => {
        concat!(
            vec_op!($r, "vpunpckldq", $t0, $x0, $x1), vec_op!($r, "vpunpckhdq", $t1, $x0, $x1),
            vec_op!($r, "vpunpckldq", $t2, $x2, $x3), vec_op!($r, "vpunpckhdq", $t3, $x2, $x3),
            vec_op!($r, "vpunpcklqdq", $x0, $t0, $t2), vec_op!($r, "vpunpckhqdq", $x1, $t0, $t2),
            vec_op!($r, "vpunpcklqdq", $x2, $t1, $t3), vec_op!($r, "vpunpckhqdq", $x3, $t1, $t3),
        )
    };
}

macro_rules! zmm_shuffle {
    ($x:literal, $y:literal, $z:literal, $control:literal) => {
        concat!(
            "vshufi32x4 zmm",
            $x,
            ", zmm",
            $y,
            ", zmm",
            $z,
            ", ",
            $control,
            "\n"
        )
    };
}

// The transposition of the 128-bit quarters of registers y, through t: quarter q of y_k to
// quarter k of y_q.
#[rustfmt::skip]
macro_rules! zmm_quarters {
    (
        $y0:literal, $y1:literal, $y2:literal, $y3:literal,
        $t0:literal, $t1:literal, $t2:literal, $t3:literal
    ) => {
        concat!(
            zmm_shuffle!($t0, $y0, $y1, "0x44"), zmm_shuffle!($t1, $y0, $y1, "0xEE"),
            zmm_shuffle!($t2, $y2, $y3, "0x44"), zmm_shuffle!($t3, $y2, $y3, "0xEE"),
            zmm_shuffle!($y0, $t0, $t2, "0x88"), zmm_shuffle!($y1, $t0, $t2, "0xDD"),
            zmm_shuffle!($y2, $t1, $t3, "0x88"), zmm_shuffle!($y3, $t1, $t3, "0xDD"),
        )
    };
}

// The transposition of the 16 by 16 words in zmm16 to zmm31, in place, through the registers t:
// word i of zmm 16 + j to word j of zmm 16 + i.
#[rustfmt::skip]
macro_rules! zmm_transpose {
    ($t0:literal, $t1:literal, $t2:literal, $t3:literal) => {
        concat!(
            vec_four!("zmm", 16, 17, 18, 19, $t0, $t1, $t2, $t3),
            vec_four!("zmm", 20, 21, 22, 23, $t0, $t1, $t2, $t3),
            vec_four!("zmm", 24, 25, 26, 27, $t0, $t1, $t2, $t3),
            vec_four!("zmm", 28, 29, 30, 31, $t0, $t1, $t2, $t3),
            zmm_quarters!(16, 20, 24, 28, $t0, $t1, $t2, $t3),
            zmm_quarters!(17, 21, 25, 29, $t0, $t1, $t2, $t3),
            zmm_quarters!(18, 22, 26, 30, $t0, $t1, $t2, $t3),
            zmm_quarters!(19, 23, 27, 31, $t0, $t1, $t2, $t3),
        )
    };
}

// Words 8h to 8h + 7 of the current block of lanes i and j, at x and z, into the low halves of
// registers t0 and t1, and of lanes i + 4 and j + 4, at y and w, into their high halves; then the
// 64-bit unpacks of the two into lo and hi.
#[rustfmt::skip]
macro_rules! zmm_load4 {
    (
        $x:literal, $y:literal, $z:literal, $w:literal,
        $t0:literal, $t1:literal, $lo:literal, $hi:literal
    ) => {
        concat!(
            "vmovdqu32 ymm", $t0, ", ymmword ptr [", $x, "]\n",
            "vinserti64x4 zmm", $t0, ", zmm", $t0, ", ymmword ptr [", $y, "], 1\n",
            "vmovdqu32 ymm", $t1, ", ymmword ptr [", $z, "]\n",
            "vinserti64x4 zmm", $t1, ", zmm", $t1, ", ymmword ptr [", $w, "], 1\n",
            zmm_op!("vpunpcklqdq", $lo, $t0, $t1), zmm_op!("vpunpckhqdq", $hi, $t0, $t1),
        )
    };
}

// Words k and k + 4 of the sixteen lanes into registers u and v. The 32-bit shuffles by s of p0
// and p1 (lanes 0 to 7) and of q0 and q1 (lanes 8 to 15) take word k of four lanes to quarters 0
// and 2 of a and b, and word k + 4 to quarters 1 and 3; two 128-bit shuffles put them in lane
// order.
#[rustfmt::skip]
macro_rules! zmm_words {
    (
        $p0:literal, $p1:literal, $q0:literal, $q1:literal, $s:literal,
        $a:literal, $b:literal, $u:literal, $v:literal
    ) => {
        concat!(
            "vshufps zmm", $a, ", zmm", $p0, ", zmm", $p1, ", ", $s, "\n",
            "vshufps zmm", $b, ", zmm", $q0, ", zmm", $q1, ", ", $s, "\n",
            zmm_shuffle!($u, $a, $b, "0x88"), zmm_shuffle!($v, $a, $b, "0xDD"),
        )
    };
}

// The current block of each lane, lane i < 8 at r8 + i and lane 8 + i at r8 + i + rsi, as message
// word j in zmm 16 + j, lane l in its word l, through zmm8 to zmm15: words 0 to 7 from the first
// 32 bytes of the blocks, then words 8 to 15 from the next 32.
#[rustfmt::skip]
macro_rules! zmm_message {
    () => {
        concat!(
            zmm_load4!("r8", "r12", "r9", "r13", 24, 25, 8, 9),
            zmm_load4!("r10", "r14", "r11", "r15", 24, 25, 10, 11),
            zmm_load4!("r8 + rsi", "r12 + rsi", "r9 + rsi", "r13 + rsi", 24, 25, 12, 13),
            zmm_load4!("r10 + rsi", "r14 + rsi", "r11 + rsi", "r15 + rsi", 24, 25, 14, 15),
            zmm_words!(8, 10, 12, 14, "0x88", 26, 27, 16, 20),
            zmm_words!(8, 10, 12, 14, "0xDD", 26, 27, 17, 21),
            zmm_words!(9, 11, 13, 15, "0x88", 26, 27, 18, 22),
            zmm_words!(9, 11, 13, 15, "0xDD", 26, 27, 19, 23),
            zmm_load4!("r8 + 32", "r12 + 32", "r9 + 32", "r13 + 32", 28, 29, 8, 9),
            zmm_load4!("r10 + 32", "r14 + 32", "r11 + 32", "r15 + 32", 28, 29, 10, 11),
            zmm_load4!(
                "r8 + rsi + 32", "r12 + rsi + 32", "r9 + rsi + 32", "r13 + rsi + 32",
                28, 29, 12, 13
            ),
            zmm_load4!(
                "r10 + rsi + 32", "r14 + rsi + 32", "r11 + rsi + 32", "r15 + rsi + 32",
                28, 29, 14, 15
            ),
            zmm_words!(8, 10, 12, 14, "0x88", 30, 31, 24, 28),
            zmm_words!(8, 10, 12, 14, "0xDD", 30, 31, 25, 29),
            zmm_words!(9, 11, 13, 15, "0x88", 30, 31, 26, 30),
            zmm_words!(9, 11, 13, 15, "0xDD", 8, 31, 27, 31),
        )
    };
}

// The chaining values of lanes w, 4 + w, 8 + w and 12 + w into their 32 bytes at rdx, from words
// 0 to 3 and 4 to 7 of those lanes in quarters 0 to 3 of zmm w and zmm 4 + w.
#[rustfmt::skip]
macro_rules! zmm_cvs {
    ($w:literal, $x:literal, $low:literal, $second:literal, $third:literal, $high:literal) => {
        concat!(
            zmm_shuffle!(8, $w, $x, "0x44"), zmm_shuffle!(8, 8, 8, "0xD8"),
            zmm_shuffle!(9, $w, $x, "0xEE"), zmm_shuffle!(9, 9, 9, "0xD8"),
            "vmovdqu ymmword ptr [rdx + ", $low, "], ymm8\n",
            "vextracti64x4 ymmword ptr [rdx + ", $second, "], zmm8, 1\n",
            "vmovdqu ymmword ptr [rdx + ", $third, "], ymm9\n",
            "vextracti64x4 ymmword ptr [rdx + ", $high, "], zmm9, 1\n",
        )
    };
}

// The 512 bits of registers 16 to 31 zeroed (a write to an EVEX ymm register zeroes its upper
// half), then the upper halves of the others.
#[rustfmt::skip]
macro_rules! vec_clear {
    ($r:literal) => {
        concat!(
            vec_op!($r, "vpxord", 16, 16, 16), vec_op!($r, "vpxord", 17, 17, 17),
            vec_op!($r, "vpxord", 18, 18, 18), vec_op!($r, "vpxord", 19, 19, 19),
            vec_op!($r, "vpxord", 20, 20, 20), vec_op!($r, "vpxord", 21, 21, 21),
            vec_op!($r, "vpxord", 22, 22, 22), vec_op!($r, "vpxord", 23, 23, 23),
            vec_op!($r, "vpxord", 24, 24, 24), vec_op!($r, "vpxord", 25, 25, 25),
            vec_op!($r, "vpxord", 26, 26, 26), vec_op!($r, "vpxord", 27, 27, 27),
            vec_op!($r, "vpxord", 28, 28, 28), vec_op!($r, "vpxord", 29, 29, 29),
            vec_op!($r, "vpxord", 30, 30, 30), vec_op!($r, "vpxord", 31, 31, 31),
            "vzeroupper\n",
        )
    };
}

// Words 4q to 4q + 3 of the current block of lane i at offset o (16q) in the low half of ymm
// 8 + i, of lane i + 4 in its high half, transposed into message words w0 to w3: the eight
// lanes' inputs at r8 to r15, the block's offset in each rax.
#[rustfmt::skip]
macro_rules! ymm_quarter {
    ($o:literal, $w0:literal, $w1:literal, $w2:literal, $w3:literal) => {
        concat!(
            "vmovdqu xmm8, xmmword ptr [r8 + rax + ", $o, "]\n",
            "vmovdqu xmm9, xmmword ptr [r9 + rax + ", $o, "]\n",
            "vmovdqu xmm10, xmmword ptr [r10 + rax + ", $o, "]\n",
            "vmovdqu xmm11, xmmword ptr [r11 + rax + ", $o, "]\n",
            "vinserti128 ymm8, ymm8, xmmword ptr [r12 + rax + ", $o, "], 1\n",
            "vinserti128 ymm9, ymm9, xmmword ptr [r13 + rax + ", $o, "], 1\n",
            "vinserti128 ymm10, ymm10, xmmword ptr [r14 + rax + ", $o, "], 1\n",
            "vinserti128 ymm11, ymm11, xmmword ptr [r15 + rax + ", $o, "], 1\n",
            vec_op!("ymm", "vpunpckldq", 12, 8, 9), vec_op!("ymm", "vpunpckhdq", 13, 8, 9),
            vec_op!("ymm", "vpunpckldq", 14, 10, 11), vec_op!("ymm", "vpunpckhdq", 15, 10, 11),
            vec_op!("ymm", "vpunpcklqdq", $w0, 12, 14), vec_op!("ymm", "vpunpckhqdq", $w1, 12, 14),
            vec_op!("ymm", "vpunpcklqdq", $w2, 13, 15), vec_op!("ymm", "vpunpckhqdq", $w3, 13, 15),
        )
    };
}

// The chaining values of lanes w and 4 + w into their 32 bytes at rsi, from words 0 to 3 and 4 to
// 7 of lane w in the low halves of ymm w and ymm 4 + w, and of lane 4 + w in their high halves.
#[rustfmt::skip]
macro_rules! ymm_cvs {
    ($w:literal, $x:literal, $low:literal, $high:literal) => {
        concat!(
            "vperm2i128 ymm8, ymm", $w, ", ymm", $x, ", 0x20\n",
            "vperm2i128 ymm9, ymm", $w, ", ymm", $x, ", 0x31\n",
            "vmovdqu ymmword ptr [rsi + ", $low, "], ymm8\n",
            "vmovdqu ymmword ptr [rsi + ", $high, "], ymm9\n",
        )
    };
}

// The assembly with all 32 vector registers declared clobbered.
macro_rules! zmm_asm {
    ($($operand:tt)*) => {
        core::arch::asm!(
            $($operand)*
            out("zmm0") _, out("zmm1") _, out("zmm2") _, out("zmm3") _,
            out("zmm4") _, out("zmm5") _, out("zmm6") _, out("zmm7") _,
            out("zmm8") _, out("zmm9") _, out("zmm10") _, out("zmm11") _,
            out("zmm12") _, out("zmm13") _, out("zmm14") _, out("zmm15") _,
            out("zmm16") _, out("zmm17") _, out("zmm18") _, out("zmm19") _,
            out("zmm20") _, out("zmm21") _, out("zmm22") _, out("zmm23") _,
            out("zmm24") _, out("zmm25") _, out("zmm26") _, out("zmm27") _,
            out("zmm28") _, out("zmm29") _, out("zmm30") _, out("zmm31") _,
            options(nostack),
        )
    };
}

/// The chaining values of sixteen inputs of `blocks` blocks each into out: input i starts at
/// `first + i * stride` bytes, stride = 64 blocks, and its counter and its blocks' flags are in
/// table.
///
/// # Safety
///
/// The CPU has AVX-512F and AVX-512VL and the operating system saves their registers; 1 <=
/// blocks <= 16; the sixteen inputs lie in one allocation that `first` points into.
#[target_feature(enable = "avx512f,avx512vl")]
#[inline(never)]
#[allow(unsafe_code)]
pub(super) unsafe fn hash16_zmm(
    first: *const u8,
    blocks: usize,
    key: &[u32; 8],
    table: &Table16,
    out: &mut [[u8; 32]; 16],
) {
    let stride = 64 * blocks;

    let lane = |i: usize| first.wrapping_add(i * stride);

    // SAFETY: AVX-512F instructions, which the caller's CPU has, on the vector registers, all
    // declared clobbered, and on the registers named below. The loop runs `blocks` times, at
    // least once, and reads block b's flags from table.flags[b], so it needs 1 <= blocks <= 16,
    // as the caller ensures. For each block it reads 64 bytes of each of the sixteen inputs: of
    // input i < 8 at r8 + i (then r8 + i + rsi for input i + 8, rsi = 8 * stride), each pointer
    // moving on by 64 bytes; the caller's inputs hold `blocks` blocks each. It reads the 32 bytes
    // of key and the 212 of table, writes the 512 bytes of out, and uses no stack.
    unsafe {
        zmm_asm!(
            "vpbroadcastd zmm0, dword ptr [rax]",
            "vpbroadcastd zmm1, dword ptr [rax + 4]",
            "vpbroadcastd zmm2, dword ptr [rax + 8]",
            "vpbroadcastd zmm3, dword ptr [rax + 12]",
            "vpbroadcastd zmm4, dword ptr [rax + 16]",
            "vpbroadcastd zmm5, dword ptr [rax + 20]",
            "vpbroadcastd zmm6, dword ptr [rax + 24]",
            "vpbroadcastd zmm7, dword ptr [rax + 28]",
            "xor eax, eax",
            ".p2align 5",
            "2:",
            zmm_message!(),
            "vpbroadcastd zmm8, dword ptr [rdi + 192]",
            "vpbroadcastd zmm9, dword ptr [rdi + 196]",
            "vpbroadcastd zmm10, dword ptr [rdi + 200]",
            "vpbroadcastd zmm11, dword ptr [rdi + 204]",
            "vmovdqa32 zmm12, zmmword ptr [rdi]",
            "vmovdqa32 zmm13, zmmword ptr [rdi + 64]",
            "vpbroadcastd zmm14, dword ptr [rdi + 208]",
            "vpbroadcastd zmm15, dword ptr [rdi + rax + 128]",
            vec_seven!("zmm"),
            "vpxord zmm0, zmm0, zmm8",
            "vpxord zmm1, zmm1, zmm9",
            "vpxord zmm2, zmm2, zmm10",
            "vpxord zmm3, zmm3, zmm11",
            "vpxord zmm4, zmm4, zmm12",
            "vpxord zmm5, zmm5, zmm13",
            "vpxord zmm6, zmm6, zmm14",
            "vpxord zmm7, zmm7, zmm15",
            "add r8, 64",
            "add r9, 64",
            "add r10, 64",
            "add r11, 64",
            "add r12, 64",
            "add r13, 64",
            "add r14, 64",
            "add r15, 64",
            "add rax, 4",
            "cmp rax, rcx",
            "jne 2b",
            vec_four!("zmm", 0, 1, 2, 3, 8, 9, 10, 11),
            vec_four!("zmm", 4, 5, 6, 7, 8, 9, 10, 11),
            zmm_cvs!(0, 4, 0, 128, 256, 384),
            zmm_cvs!(1, 5, 32, 160, 288, 416),
            zmm_cvs!(2, 6, 64, 192, 320, 448),
            zmm_cvs!(3, 7, 96, 224, 352, 480),
            vec_clear!("zmm"),
            inout("rax") key.as_ptr() => _,
            in("rcx") 4 * blocks,
            in("rdx") out.as_mut_ptr(),
            in("rsi") 8 * stride,
            in("rdi") &raw const *table,
            inout("r8") lane(0) => _, inout("r9") lane(1) => _,
            inout("r10") lane(2) => _, inout("r11") lane(3) => _,
            inout("r12") lane(4) => _, inout("r13") lane(5) => _,
            inout("r14") lane(6) => _, inout("r15") lane(7) => _,
        )
    };
}

/// The chaining values of eight inputs of `blocks` blocks each into out, input i from lanes[i]
/// on, with the counters, the IV, the block length and the flags of the blocks in table, as
/// blake3.rs's eight-lane AVX2 kernel reads them. The state is in ymm0 to ymm15 and the message
/// words in ymm16 to ymm31, and every rotation is one VPRORD, where the AVX2 kernel keeps the
/// message and v8 in memory and rotates with VPSHUFB or two shifts and an OR.
///
/// # Safety
///
/// The CPU has AVX-512F and AVX-512VL and the operating system saves their registers; 1 <=
/// blocks <= 16; each of the eight pointers has `blocks` blocks of input behind it.
#[target_feature(enable = "avx512f,avx512vl")]
#[inline(never)]
#[allow(unsafe_code)]
pub(super) unsafe fn hash8_ymm(
    lanes: &[*const [u8; 64]; 8],
    blocks: usize,
    key: &[u32; 8],
    table: &Table,
    out: &mut [[u8; 32]; 8],
) {
    let [l0, l1, l2, l3, l4, l5, l6, l7] = *lanes;

    // SAFETY: AVX-512F and AVX-512VL instructions on registers of at most 256 bits, which the
    // caller's CPU has, on the vector registers, all declared clobbered, and on the registers
    // named below. The loop runs `blocks` times, at least once, and reads block b's flags at byte
    // 320 + 64 b of table, so it needs 1 <= blocks <= 16, as the caller ensures. For each block
    // offset below rcx = 64 blocks it reads the 64 bytes there of each lane's input, which has
    // `blocks` blocks behind its pointer. It reads the 32 bytes of key and table up to its last
    // block's flags, writes the 256 bytes of out, and uses no stack.
    unsafe {
        zmm_asm!(
            "vpbroadcastd ymm0, dword ptr [rdx]",
            "vpbroadcastd ymm1, dword ptr [rdx + 4]",
            "vpbroadcastd ymm2, dword ptr [rdx + 8]",
            "vpbroadcastd ymm3, dword ptr [rdx + 12]",
            "vpbroadcastd ymm4, dword ptr [rdx + 16]",
            "vpbroadcastd ymm5, dword ptr [rdx + 20]",
            "vpbroadcastd ymm6, dword ptr [rdx + 24]",
            "vpbroadcastd ymm7, dword ptr [rdx + 28]",
            "xor eax, eax",
            ".p2align 5",
            "2:",
            ymm_quarter!("0", 16, 17, 18, 19),
            ymm_quarter!("16", 20, 21, 22, 23),
            ymm_quarter!("32", 24, 25, 26, 27),
            ymm_quarter!("48", 28, 29, 30, 31),
            "vmovdqu ymm8, ymmword ptr [rdi + 64]",
            "vmovdqu ymm9, ymmword ptr [rdi + 96]",
            "vmovdqu ymm10, ymmword ptr [rdi + 128]",
            "vmovdqu ymm11, ymmword ptr [rdi + 160]",
            "vmovdqu ymm12, ymmword ptr [rdi + 192]",
            "vmovdqu ymm13, ymmword ptr [rdi + 224]",
            "vmovdqu ymm14, ymmword ptr [rdi + 256]",
            "vmovdqu ymm15, ymmword ptr [rdi + rax + 320]",
            vec_seven!("ymm"),
            "vpxor ymm0, ymm0, ymm8",
            "vpxor ymm1, ymm1, ymm9",
            "vpxor ymm2, ymm2, ymm10",
            "vpxor ymm3, ymm3, ymm11",
            "vpxor ymm4, ymm4, ymm12",
            "vpxor ymm5, ymm5, ymm13",
            "vpxor ymm6, ymm6, ymm14",
            "vpxor ymm7, ymm7, ymm15",
            "add rax, 64",
            "cmp rax, rcx",
            "jne 2b",
            vec_four!("ymm", 0, 1, 2, 3, 8, 9, 10, 11),
            vec_four!("ymm", 4, 5, 6, 7, 8, 9, 10, 11),
            ymm_cvs!(0, 4, 0, 128),
            ymm_cvs!(1, 5, 32, 160),
            ymm_cvs!(2, 6, 64, 192),
            ymm_cvs!(3, 7, 96, 224),
            vec_clear!("ymm"),
            out("rax") _,
            in("rcx") 64 * blocks,
            in("rdx") key.as_ptr(),
            in("rsi") out.as_mut_ptr(),
            in("rdi") &raw const *table,
            in("r8") l0, in("r9") l1, in("r10") l2, in("r11") l3,
            in("r12") l4, in("r13") l5, in("r14") l6, in("r15") l7,
        )
    };
}

/// Output blocks of the root for the counters from `counter` on, sixteen to each group of out,
/// from its chaining value cv and its message words block, with the length and flags of
/// table.length and table.flags[0]. Each group's counters are stored in table.low and table.high
/// and loaded back whole, with the stores' width, so that the load takes them from the stores.
///
/// # Safety
///
/// The CPU has AVX-512F and AVX-512VL and the operating system saves their registers; out holds
/// at least one group.
#[target_feature(enable = "avx512f,avx512vl")]
#[inline(never)]
#[allow(unsafe_code)]
pub(super) unsafe fn xof16_zmm(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    table: &mut Table16,
    out: &mut [[[u8; 64]; 16]],
) {
    // SAFETY: AVX-512F instructions, which the caller's CPU has, on the vector registers and k1,
    // all declared clobbered. The loop runs out.len() times, at least once, as the caller
    // ensures, and writes the 1024 bytes of one group of out each time. They read the 32 bytes of
    // cv, the 64 of block and the 72 of STEPS, read and write the 212 of table, and use no stack.
    unsafe {
        zmm_asm!(
            "vpbroadcastd zmm0, r8d",
            "shr r8, 32",
            "vpbroadcastd zmm1, r8d",
            "vpaddd zmm2, zmm0, zmmword ptr [r9]",
            "vpcmpud k1, zmm2, zmm0, 1",
            "vpaddd zmm1 {{k1}}, zmm1, dword ptr [r9 + 68]{{1to16}}",
            "vmovdqa32 zmmword ptr [rdi], zmm2",
            "vmovdqa32 zmmword ptr [rdi + 64], zmm1",
            ".p2align 5",
            "2:",
            "vpbroadcastd zmm0, dword ptr [rax]",
            "vpbroadcastd zmm1, dword ptr [rax + 4]",
            "vpbroadcastd zmm2, dword ptr [rax + 8]",
            "vpbroadcastd zmm3, dword ptr [rax + 12]",
            "vpbroadcastd zmm4, dword ptr [rax + 16]",
            "vpbroadcastd zmm5, dword ptr [rax + 20]",
            "vpbroadcastd zmm6, dword ptr [rax + 24]",
            "vpbroadcastd zmm7, dword ptr [rax + 28]",
            "vpbroadcastd zmm8, dword ptr [rdi + 192]",
            "vpbroadcastd zmm9, dword ptr [rdi + 196]",
            "vpbroadcastd zmm10, dword ptr [rdi + 200]",
            "vpbroadcastd zmm11, dword ptr [rdi + 204]",
            "vmovdqa32 zmm12, zmmword ptr [rdi]",
            "vmovdqa32 zmm13, zmmword ptr [rdi + 64]",
            "vpbroadcastd zmm14, dword ptr [rdi + 208]",
            "vpbroadcastd zmm15, dword ptr [rdi + 128]",
            "vpbroadcastd zmm16, dword ptr [rcx]",
            "vpbroadcastd zmm17, dword ptr [rcx + 4]",
            "vpbroadcastd zmm18, dword ptr [rcx + 8]",
            "vpbroadcastd zmm19, dword ptr [rcx + 12]",
            "vpbroadcastd zmm20, dword ptr [rcx + 16]",
            "vpbroadcastd zmm21, dword ptr [rcx + 20]",
            "vpbroadcastd zmm22, dword ptr [rcx + 24]",
            "vpbroadcastd zmm23, dword ptr [rcx + 28]",
            "vpbroadcastd zmm24, dword ptr [rcx + 32]",
            "vpbroadcastd zmm25, dword ptr [rcx + 36]",
            "vpbroadcastd zmm26, dword ptr [rcx + 40]",
            "vpbroadcastd zmm27, dword ptr [rcx + 44]",
            "vpbroadcastd zmm28, dword ptr [rcx + 48]",
            "vpbroadcastd zmm29, dword ptr [rcx + 52]",
            "vpbroadcastd zmm30, dword ptr [rcx + 56]",
            "vpbroadcastd zmm31, dword ptr [rcx + 60]",
            vec_seven!("zmm"),
            "vpxord zmm16, zmm0, zmm8",
            "vpxord zmm17, zmm1, zmm9",
            "vpxord zmm18, zmm2, zmm10",
            "vpxord zmm19, zmm3, zmm11",
            "vpxord zmm20, zmm4, zmm12",
            "vpxord zmm21, zmm5, zmm13",
            "vpxord zmm22, zmm6, zmm14",
            "vpxord zmm23, zmm7, zmm15",
            "vpxord zmm24, zmm8, dword ptr [rax]{{1to16}}",
            "vpxord zmm25, zmm9, dword ptr [rax + 4]{{1to16}}",
            "vpxord zmm26, zmm10, dword ptr [rax + 8]{{1to16}}",
            "vpxord zmm27, zmm11, dword ptr [rax + 12]{{1to16}}",
            "vpxord zmm28, zmm12, dword ptr [rax + 16]{{1to16}}",
            "vpxord zmm29, zmm13, dword ptr [rax + 20]{{1to16}}",
            "vpxord zmm30, zmm14, dword ptr [rax + 24]{{1to16}}",
            "vpxord zmm31, zmm15, dword ptr [rax + 28]{{1to16}}",
            zmm_transpose!(0, 1, 2, 3),
            "vmovdqu32 zmmword ptr [rdx], zmm16",
            "vmovdqu32 zmmword ptr [rdx + 64], zmm17",
            "vmovdqu32 zmmword ptr [rdx + 128], zmm18",
            "vmovdqu32 zmmword ptr [rdx + 192], zmm19",
            "vmovdqu32 zmmword ptr [rdx + 256], zmm20",
            "vmovdqu32 zmmword ptr [rdx + 320], zmm21",
            "vmovdqu32 zmmword ptr [rdx + 384], zmm22",
            "vmovdqu32 zmmword ptr [rdx + 448], zmm23",
            "vmovdqu32 zmmword ptr [rdx + 512], zmm24",
            "vmovdqu32 zmmword ptr [rdx + 576], zmm25",
            "vmovdqu32 zmmword ptr [rdx + 640], zmm26",
            "vmovdqu32 zmmword ptr [rdx + 704], zmm27",
            "vmovdqu32 zmmword ptr [rdx + 768], zmm28",
            "vmovdqu32 zmmword ptr [rdx + 832], zmm29",
            "vmovdqu32 zmmword ptr [rdx + 896], zmm30",
            "vmovdqu32 zmmword ptr [rdx + 960], zmm31",
            "vmovdqa32 zmm0, zmmword ptr [rdi]",
            "vmovdqa32 zmm1, zmmword ptr [rdi + 64]",
            "vpaddd zmm2, zmm0, dword ptr [r9 + 64]{{1to16}}",
            "vpcmpud k1, zmm2, zmm0, 1",
            "vpaddd zmm1 {{k1}}, zmm1, dword ptr [r9 + 68]{{1to16}}",
            "vmovdqa32 zmmword ptr [rdi], zmm2",
            "vmovdqa32 zmmword ptr [rdi + 64], zmm1",
            "add rdx, 1024",
            "dec rsi",
            "jnz 2b",
            vec_clear!("zmm"),
            in("rax") cv.as_ptr(),
            in("rcx") block.as_ptr(),
            inout("rdx") out.as_mut_ptr() => _,
            inout("rsi") out.len() => _,
            in("rdi") &raw mut *table,
            inout("r8") counter => _,
            in("r9") &raw const STEPS,
            out("k1") _,
        )
    };
}
