// BLAKE3 with AVX-512F and AVX-512VL, on the cores of the table in zmm_lanes() of x86_64.rs (D-44,
// D-84), in two forms.
//
// On sixteen inputs side by side in 512-bit registers, for hash_many and the extended output, and
// on eight in 256-bit registers for their groups of eight there, each register holds one state
// word of sixteen (or eight) inputs, as each of blake3.rs's eight-lane AVX2 kernels holds eight:
// the state is in registers 0 to 15 and the message words in 16 to 31, all in registers through
// the seven rounds, and every rotation is one VPRORD. The blocks of the sixteen inputs are loaded
// in 256-bit halves, inputs i and i + 4 in one register, the high half an insert from memory,
// which leaves the shuffle port free, and transposed into words with VPUNPCKLQDQ, VPUNPCKHQDQ,
// VSHUFPS and VSHUFI32X4: 48 shuffles a block, where whole-block loads took 64. The outputs go back
// with VPUNPCKLDQ, VPUNPCKHDQ, VPUNPCKLQDQ, VPUNPCKHQDQ and VSHUFI32X4. The eight-lane kernel
// loads and stores as the AVX2 kernel does. The extended output's counters, public values, are
// stepped with VPCMPUD and a VPADDD under its mask.
//
// On two to four inputs or output blocks, in the row form, each 128-bit lane holds one row of one
// input: the rows are in registers 0 to 3, the message in 16 to 23, and the words move to the next
// round's order with VSHUFPS, VPSHUFD, VPUNPCKLDQ, VPUNPCKHDQ, VPUNPCKLQDQ and VPBLENDMD, which
// takes those registers where VPBLENDD does not. KMOVW loads the blends' masks, which are constants,
// and VPBROADCASTQ and VPADDQ the public counters.
//
// Every instruction is on Intel's list of data-operand-independent timing instructions, or counts
// as on it by D-75 (VSHUFPS), and no branch or address depends on the data. These kernels are the
// only functions built with AVX-512F, and those on sixteen and on four inputs or blocks the only
// code with 512-bit registers, which CI checks. Each is one block of assembly that ends by zeroing
// registers 16 to 31, which no other code uses, and with VZEROUPPER.

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

// Instruction op on registers x and y of the width that r names, with immediate imm.
macro_rules! vec_imm {
    ($r:literal, $op:literal, $x:literal, $y:literal, $imm:literal) => {
        concat!($op, " ", $r, $x, ", ", $r, $y, ", ", $imm, "\n")
    };
}

// Half a step of the row form: a += m + b, d = (d ^ a) >>> dr, c += d, b = (b ^ c) >>> br, the
// rows a, b, c and d in registers 0 to 3 and the message words in register m.
#[rustfmt::skip]
macro_rules! rows_half {
    ($r:literal, $m:literal, $dr:literal, $br:literal) => {
        concat!(
            vec_op!($r, "vpaddd", 0, 0, $m), vec_op!($r, "vpaddd", 0, 0, 1),
            vec_op!($r, "vpxord", 3, 3, 0), vec_ror!($r, 3, $dr),
            vec_op!($r, "vpaddd", 2, 2, 3),
            vec_op!($r, "vpxord", 1, 1, 2), vec_ror!($r, 1, $br),
        )
    };
}

// One round of the row form. Rows a, c and d turn to the diagonals and b stays: b is the last
// value of each half step, so a shuffle of it would lengthen the chain of the next.
#[rustfmt::skip]
macro_rules! rows_round {
    ($r:literal, $m0:literal, $m1:literal, $m2:literal, $m3:literal) => {
        concat!(
            rows_half!($r, $m0, 16, 12), rows_half!($r, $m1, 8, 7),
            vec_imm!($r, "vpshufd", 0, 0, "0x93"), vec_imm!($r, "vpshufd", 3, 3, "0x4E"),
            vec_imm!($r, "vpshufd", 2, 2, "0x39"),
            rows_half!($r, $m2, 16, 12), rows_half!($r, $m3, 8, 7),
            vec_imm!($r, "vpshufd", 0, 0, "0x39"), vec_imm!($r, "vpshufd", 3, 3, "0x4E"),
            vec_imm!($r, "vpshufd", 2, 2, "0x93"),
        )
    };
}

// The message registers a to d of one round into e to h in the next round's order, with shuffles
// inside each 128-bit lane, so that the same instructions serve both widths. Register 24 is
// scratch, k1 selects the even words' neighbours (0xAAAA) and k2 each lane's last word (0x8888).
#[rustfmt::skip]
macro_rules! rows_next {
    (
        $r:literal,
        $a:literal, $b:literal, $c:literal, $d:literal,
        $e:literal, $f:literal, $g:literal, $h:literal
    ) => {
        concat!(
            "vshufps ", $r, $e, ", ", $r, $a, ", ", $r, $b, ", 0xD6\n",
            vec_imm!($r, "vpshufd", $f, $a, "0x0F"),
            vec_imm!($r, "vpshufd", $e, $e, "0x39"),
            "vshufps ", $r, "24, ", $r, $c, ", ", $r, $d, ", 0xFA\n",
            "vpblendmd ", $r, $f, " {{k1}}, ", $r, $f, ", ", $r, "24\n",
            vec_op!($r, "vpunpcklqdq", $g, $d, $b),
            "vpblendmd ", $r, $g, " {{k2}}, ", $r, $g, ", ", $r, $c, "\n",
            vec_imm!($r, "vpshufd", $g, $g, "0x78"),
            vec_op!($r, "vpunpckhdq", 24, $b, $d),
            vec_op!($r, "vpunpckldq", $h, $c, 24),
            vec_imm!($r, "vpshufd", $h, $h, "0x1E"),
        )
    };
}

#[rustfmt::skip]
macro_rules! rows_seven {
    ($r:literal) => {
        concat!(
            rows_round!($r, 16, 17, 18, 19), rows_next!($r, 16, 17, 18, 19, 20, 21, 22, 23),
            rows_round!($r, 20, 21, 22, 23), rows_next!($r, 20, 21, 22, 23, 16, 17, 18, 19),
            rows_round!($r, 16, 17, 18, 19), rows_next!($r, 16, 17, 18, 19, 20, 21, 22, 23),
            rows_round!($r, 20, 21, 22, 23), rows_next!($r, 20, 21, 22, 23, 16, 17, 18, 19),
            rows_round!($r, 16, 17, 18, 19), rows_next!($r, 16, 17, 18, 19, 20, 21, 22, 23),
            rows_round!($r, 20, 21, 22, 23), rows_next!($r, 20, 21, 22, 23, 16, 17, 18, 19),
            rows_round!($r, 16, 17, 18, 19),
        )
    };
}

// The message words in registers 8 to 11, four to a lane in block order, into 16 to 19, the
// vectors of the first round's four half steps.
#[rustfmt::skip]
macro_rules! rows_split {
    ($r:literal) => {
        concat!(
            "vshufps ", $r, "16, ", $r, "8, ", $r, "9, 0x88\n",
            "vshufps ", $r, "17, ", $r, "8, ", $r, "9, 0xDD\n",
            "vshufps ", $r, "18, ", $r, "10, ", $r, "11, 0x88\n",
            "vshufps ", $r, "19, ", $r, "10, ", $r, "11, 0xDD\n",
            vec_imm!($r, "vpshufd", 18, 18, "0x93"), vec_imm!($r, "vpshufd", 19, 19, "0x93"),
        )
    };
}

// The two masks of rows_next.
macro_rules! rows_masks {
    () => {
        concat!(
            "mov eax, 0xAAAA\n",
            "kmovw k1, eax\n",
            "mov eax, 0x8888\n",
            "kmovw k2, eax\n",
        )
    };
}

// Row d of each lane into register 5 ahead of a loop over blocks: the 64-bit counters from r14 on
// by the steps at r15, and the block length of 64. The flags come per block.
#[rustfmt::skip]
macro_rules! rows_counters {
    ($r:literal, $width:literal) => {
        concat!(
            "vpbroadcastq ", $r, "5, r14\n",
            "vpaddq ", $r, "5, ", $r, "5, ", $width, " ptr [r15]\n",
            "mov eax, 64\n",
            "vpbroadcastq ", $r, "5 {{k1}}, rax\n",
        )
    };
}

// The rows of a block: the chaining value stays in registers 0 and 1, the IV in register 4; the
// flags at rdi go into row d.
#[rustfmt::skip]
macro_rules! rows_start {
    ($r:literal) => {
        concat!(
            "vmovdqa32 ", $r, "2, ", $r, "4\n",
            "vpbroadcastd ", $r, "5 {{k2}}, dword ptr [rdi]\n",
            "vmovdqa32 ", $r, "3, ", $r, "5\n",
        )
    };
}

// The next chaining value, and the loop over the blocks.
#[rustfmt::skip]
macro_rules! rows_end {
    ($r:literal) => {
        concat!(
            vec_op!($r, "vpxord", 0, 0, 2), vec_op!($r, "vpxord", 1, 1, 3),
            "add rdi, 4\n",
            "add rax, 64\n",
            "cmp rax, rcx\n",
            "jne 2b\n",
        )
    };
}

// Bytes o to o + 15 of the current block of lanes 0 to 3 (r8 to r11) into zmm x.
#[rustfmt::skip]
macro_rules! rows_load4 {
    ($o:literal, $x:literal) => {
        concat!(
            "vmovdqu xmm", $x, ", xmmword ptr [r8 + rax + ", $o, "]\n",
            "vinserti128 ymm", $x, ", ymm", $x, ", xmmword ptr [r9 + rax + ", $o, "], 1\n",
            "vinserti32x4 zmm", $x, ", zmm", $x, ", xmmword ptr [r10 + rax + ", $o, "], 2\n",
            "vinserti32x4 zmm", $x, ", zmm", $x, ", xmmword ptr [r11 + rax + ", $o, "], 3\n",
        )
    };
}

// Bytes o to o + 15 of the current block of lanes 0 and 1 (r8 and r9) into ymm x.
#[rustfmt::skip]
macro_rules! rows_load2 {
    ($o:literal, $x:literal) => {
        concat!(
            "vmovdqu xmm", $x, ", xmmword ptr [r8 + rax + ", $o, "]\n",
            "vinserti128 ymm", $x, ", ymm", $x, ", xmmword ptr [r9 + rax + ", $o, "], 1\n",
        )
    };
}

// An output block's four rows from a lane: register 8's at o, 9's at o + 16 and so on, for the
// extended output, whose rows are in registers 8 to 11.
#[rustfmt::skip]
macro_rules! rows_output {
    ($r:literal, $lane:literal, $o0:literal, $o1:literal, $o2:literal, $o3:literal) => {
        concat!(
            "vextracti32x4 xmmword ptr [rdx + ", $o0, "], ", $r, "8, ", $lane, "\n",
            "vextracti32x4 xmmword ptr [rdx + ", $o1, "], ", $r, "9, ", $lane, "\n",
            "vextracti32x4 xmmword ptr [rdx + ", $o2, "], ", $r, "10, ", $lane, "\n",
            "vextracti32x4 xmmword ptr [rdx + ", $o3, "], ", $r, "11, ", $lane, "\n",
        )
    };
}

// The start of the extended output's kernels: the chaining value at rax into registers 0 and 1 and
// a copy in 6 and 7, the IV at r13 into row c, the counters from r8 by the steps at r15 with the
// length and the flags of r9 into row d, and the block's words at rcx into 16 to 19.
#[rustfmt::skip]
macro_rules! rows_xof_start {
    ($r:literal, $width:literal) => {
        concat!(
            "vbroadcasti32x4 ", $r, "0, xmmword ptr [rax]\n",
            "vbroadcasti32x4 ", $r, "1, xmmword ptr [rax + 16]\n",
            "vmovdqa32 ", $r, "6, ", $r, "0\n",
            "vmovdqa32 ", $r, "7, ", $r, "1\n",
            "vbroadcasti32x4 ", $r, "2, xmmword ptr [r13]\n",
            rows_masks!(),
            "vpbroadcastq ", $r, "3, r8\n",
            "vpaddq ", $r, "3, ", $r, "3, ", $width, " ptr [r15]\n",
            "vpbroadcastq ", $r, "3 {{k1}}, r9\n",
            "vbroadcasti32x4 ", $r, "8, xmmword ptr [rcx]\n",
            "vbroadcasti32x4 ", $r, "9, xmmword ptr [rcx + 16]\n",
            "vbroadcasti32x4 ", $r, "10, xmmword ptr [rcx + 32]\n",
            "vbroadcasti32x4 ", $r, "11, xmmword ptr [rcx + 48]\n",
            rows_split!($r),
            rows_seven!($r),
            vec_op!($r, "vpxord", 8, 0, 2), vec_op!($r, "vpxord", 9, 1, 3),
            vec_op!($r, "vpxord", 10, 2, 6), vec_op!($r, "vpxord", 11, 3, 7),
            "vmovdqu xmmword ptr [rdx], xmm8\n",
            "vmovdqu xmmword ptr [rdx + 16], xmm9\n",
            "vmovdqu xmmword ptr [rdx + 32], xmm10\n",
            "vmovdqu xmmword ptr [rdx + 48], xmm11\n",
        )
    };
}

// The output block of a lane from registers a to d, each with four of its words in its low half.
#[rustfmt::skip]
macro_rules! xof8_low {
    (
        $a:literal, $b:literal, $c:literal, $d:literal,
        $o0:literal, $o1:literal, $o2:literal, $o3:literal
    ) => {
        concat!(
            "vmovdqu32 xmmword ptr [rdx + ", $o0, "], xmm", $a, "\n",
            "vmovdqu32 xmmword ptr [rdx + ", $o1, "], xmm", $b, "\n",
            "vmovdqu32 xmmword ptr [rdx + ", $o2, "], xmm", $c, "\n",
            "vmovdqu32 xmmword ptr [rdx + ", $o3, "], xmm", $d, "\n",
        )
    };
}

// As xof8_low, from the registers' high halves.
#[rustfmt::skip]
macro_rules! xof8_high {
    (
        $a:literal, $b:literal, $c:literal, $d:literal,
        $o0:literal, $o1:literal, $o2:literal, $o3:literal
    ) => {
        concat!(
            "vextracti32x4 xmmword ptr [rdx + ", $o0, "], ymm", $a, ", 1\n",
            "vextracti32x4 xmmword ptr [rdx + ", $o1, "], ymm", $b, ", 1\n",
            "vextracti32x4 xmmword ptr [rdx + ", $o2, "], ymm", $c, ", 1\n",
            "vextracti32x4 xmmword ptr [rdx + ", $o3, "], ymm", $d, ", 1\n",
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

// The steps of the row form's 64-bit counters, by lane, every other word: the words between them
// hold the block length and the flags, which the kernels write over the sum.
#[repr(C, align(64))]
pub(super) struct RowSteps([u64; 8]);

pub(super) static ROW_STEPS: RowSteps = RowSteps([0, 0, 1, 0, 2, 0, 3, 0]);

pub(super) static NO_STEPS: RowSteps = RowSteps([0; 8]);

/// The chaining values of the three or four inputs of out's length, `blocks` blocks each from
/// lanes[i] on, in the row form on 512-bit registers: each 128-bit lane holds a row of one input.
/// The counters run from `counter` by steps, and flags holds each block's flags.
///
/// # Safety
///
/// The CPU has AVX-512F and AVX-512VL and the operating system saves their registers; 1 <=
/// blocks <= 16; each of the four pointers has `blocks` blocks of input behind it; out holds three
/// or four values.
#[target_feature(enable = "avx512f,avx512vl")]
#[inline(never)]
#[allow(unsafe_code)]
pub(super) unsafe fn hash4_zmm(
    lanes: &[*const [u8; 64]; 4],
    blocks: usize,
    key: &[u32; 8],
    counter: u64,
    steps: &RowSteps,
    flags: &[u32; 16],
    out: &mut [[u8; 32]],
) {
    let [l0, l1, l2, l3] = *lanes;

    // SAFETY: AVX-512F and AVX-512VL instructions, which the caller's CPU has, on the vector
    // registers, k1 and k2, all declared clobbered, and on the registers named below. The loop
    // runs `blocks` times, at least once, as the caller ensures, and reads the flags of each block
    // from flags, which holds sixteen, and the 64 bytes of that block of each lane. It reads the
    // 32 bytes of key, the first 16 of the IV and the 64 of steps, writes the 32 bytes of each of
    // out's values, three or four as the comparison picks, and uses no stack.
    unsafe {
        zmm_asm!(
            "vbroadcasti32x4 zmm0, xmmword ptr [r12]",
            "vbroadcasti32x4 zmm1, xmmword ptr [r12 + 16]",
            "vbroadcasti32x4 zmm4, xmmword ptr [r13]",
            rows_masks!(),
            rows_counters!("zmm", "zmmword"),
            "xor eax, eax",
            ".p2align 5",
            "2:",
            rows_load4!("0", 8),
            rows_load4!("16", 9),
            rows_load4!("32", 10),
            rows_load4!("48", 11),
            rows_split!("zmm"),
            rows_start!("zmm"),
            rows_seven!("zmm"),
            rows_end!("zmm"),
            "vmovdqu xmmword ptr [rsi], xmm0",
            "vmovdqu xmmword ptr [rsi + 16], xmm1",
            "vextracti128 xmmword ptr [rsi + 32], ymm0, 1",
            "vextracti128 xmmword ptr [rsi + 48], ymm1, 1",
            "vextracti32x4 xmmword ptr [rsi + 64], zmm0, 2",
            "vextracti32x4 xmmword ptr [rsi + 80], zmm1, 2",
            "cmp rdx, 4",
            "jne 3f",
            "vextracti32x4 xmmword ptr [rsi + 96], zmm0, 3",
            "vextracti32x4 xmmword ptr [rsi + 112], zmm1, 3",
            "3:",
            vec_clear!("zmm"),
            out("rax") _,
            in("rcx") 64 * blocks,
            in("rdx") out.len(),
            in("rsi") out.as_mut_ptr(),
            inout("rdi") flags.as_ptr() => _,
            in("r8") l0, in("r9") l1, in("r10") l2, in("r11") l3,
            in("r12") key.as_ptr(),
            in("r13") IV_256.as_ptr(),
            in("r14") counter,
            in("r15") &raw const *steps,
            out("k1") _, out("k2") _,
        )
    };
}

/// hash4_zmm on two inputs and 256-bit registers.
///
/// # Safety
///
/// As for hash4_zmm, with two pointers.
#[target_feature(enable = "avx512f,avx512vl")]
#[inline(never)]
#[allow(unsafe_code)]
pub(super) unsafe fn hash2_ymm(
    lanes: &[*const [u8; 64]; 2],
    blocks: usize,
    key: &[u32; 8],
    counter: u64,
    steps: &RowSteps,
    flags: &[u32; 16],
    out: &mut [[u8; 32]; 2],
) {
    let [l0, l1] = *lanes;

    // SAFETY: as in hash4_zmm, on registers of at most 256 bits, with two inputs and two values of
    // out, and the first 32 bytes of steps.
    unsafe {
        zmm_asm!(
            "vbroadcasti32x4 ymm0, xmmword ptr [r12]",
            "vbroadcasti32x4 ymm1, xmmword ptr [r12 + 16]",
            "vbroadcasti32x4 ymm4, xmmword ptr [r13]",
            rows_masks!(),
            rows_counters!("ymm", "ymmword"),
            "xor eax, eax",
            ".p2align 5",
            "2:",
            rows_load2!("0", 8),
            rows_load2!("16", 9),
            rows_load2!("32", 10),
            rows_load2!("48", 11),
            rows_split!("ymm"),
            rows_start!("ymm"),
            rows_seven!("ymm"),
            rows_end!("ymm"),
            "vmovdqu xmmword ptr [rsi], xmm0",
            "vmovdqu xmmword ptr [rsi + 16], xmm1",
            "vextracti128 xmmword ptr [rsi + 32], ymm0, 1",
            "vextracti128 xmmword ptr [rsi + 48], ymm1, 1",
            vec_clear!("ymm"),
            out("rax") _,
            in("rcx") 64 * blocks,
            in("rsi") out.as_mut_ptr(),
            inout("rdi") flags.as_ptr() => _,
            in("r8") l0, in("r9") l1,
            in("r12") key.as_ptr(),
            in("r13") IV_256.as_ptr(),
            in("r14") counter,
            in("r15") &raw const *steps,
            out("k1") _, out("k2") _,
        )
    };
}

/// The three or four output blocks of out's length from the root's chaining value cv and message
/// words block, at the counters from `counter` on, in the row form on 512-bit registers. tail
/// holds the block length in its low half and the flags in its high half.
///
/// # Safety
///
/// The CPU has AVX-512F and AVX-512VL and the operating system saves their registers; out holds
/// three or four blocks.
#[target_feature(enable = "avx512f,avx512vl")]
#[inline(never)]
#[allow(unsafe_code)]
pub(super) unsafe fn xof4_zmm(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    tail: u64,
    out: &mut [[u8; 64]],
) {
    // SAFETY: AVX-512F and AVX-512VL instructions, which the caller's CPU has, on the vector
    // registers, k1 and k2, all declared clobbered, and on the registers named below. It reads the
    // 32 bytes of cv, the 64 of block, the first 16 of the IV and the 64 of ROW_STEPS, writes the
    // 64 bytes of each of out's blocks, three or four as the comparison picks, and uses no stack.
    unsafe {
        zmm_asm!(
            rows_xof_start!("zmm", "zmmword"),
            rows_output!("ymm", 1, 64, 80, 96, 112),
            rows_output!("zmm", 2, 128, 144, 160, 176),
            "cmp rsi, 4",
            "jne 3f",
            rows_output!("zmm", 3, 192, 208, 224, 240),
            "3:",
            vec_clear!("zmm"),
            inout("rax") cv.as_ptr() => _,
            in("rcx") block.as_ptr(),
            in("rdx") out.as_mut_ptr(),
            in("rsi") out.len(),
            in("r8") counter,
            in("r9") tail,
            in("r13") IV_256.as_ptr(),
            in("r15") &raw const ROW_STEPS,
            out("k1") _, out("k2") _,
        )
    };
}

/// xof4_zmm on two output blocks and 256-bit registers.
///
/// # Safety
///
/// The CPU has AVX-512F and AVX-512VL and the operating system saves their registers.
#[target_feature(enable = "avx512f,avx512vl")]
#[inline(never)]
#[allow(unsafe_code)]
pub(super) unsafe fn xof2_ymm(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    tail: u64,
    out: &mut [[u8; 64]; 2],
) {
    // SAFETY: as in xof4_zmm, on registers of at most 256 bits, with the two blocks of out and the
    // first 32 bytes of ROW_STEPS.
    unsafe {
        zmm_asm!(
            rows_xof_start!("ymm", "ymmword"),
            rows_output!("ymm", 1, 64, 80, 96, 112),
            vec_clear!("ymm"),
            inout("rax") cv.as_ptr() => _,
            in("rcx") block.as_ptr(),
            in("rdx") out.as_mut_ptr(),
            in("r8") counter,
            in("r9") tail,
            in("r13") IV_256.as_ptr(),
            in("r15") &raw const ROW_STEPS,
            out("k1") _, out("k2") _,
        )
    };
}

/// The five to eight output blocks of out's length from the root's chaining value cv and message
/// words block, at the counters from `counter` on, as xof16_zmm computes sixteen, on eight lanes
/// in 256-bit registers. tail holds the block length in its low half and the flags in its high
/// half.
///
/// # Safety
///
/// The CPU has AVX-512F and AVX-512VL and the operating system saves their registers; out holds
/// five to eight blocks.
#[target_feature(enable = "avx512f,avx512vl")]
#[inline(never)]
#[allow(unsafe_code)]
pub(super) unsafe fn xof8_ymm(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    tail: u64,
    out: &mut [[u8; 64]],
) {
    // SAFETY: AVX-512F and AVX-512VL instructions on registers of at most 256 bits, which the
    // caller's CPU has, on the vector registers and k1, all declared clobbered, and on the
    // registers named below. It reads the 32 bytes of cv, the 64 of block, the first 16 of the IV
    // and the first 32 and the last 4 of STEPS, writes the 64 bytes of each of out's blocks, five
    // to eight as the comparisons pick, and uses no stack.
    unsafe {
        zmm_asm!(
            "vpbroadcastd ymm0, dword ptr [rax]",
            "vpbroadcastd ymm1, dword ptr [rax + 4]",
            "vpbroadcastd ymm2, dword ptr [rax + 8]",
            "vpbroadcastd ymm3, dword ptr [rax + 12]",
            "vpbroadcastd ymm4, dword ptr [rax + 16]",
            "vpbroadcastd ymm5, dword ptr [rax + 20]",
            "vpbroadcastd ymm6, dword ptr [rax + 24]",
            "vpbroadcastd ymm7, dword ptr [rax + 28]",
            "vpbroadcastd ymm8, dword ptr [r13]",
            "vpbroadcastd ymm9, dword ptr [r13 + 4]",
            "vpbroadcastd ymm10, dword ptr [r13 + 8]",
            "vpbroadcastd ymm11, dword ptr [r13 + 12]",
            "vpbroadcastd ymm16, r8d",
            "shr r8, 32",
            "vpbroadcastd ymm13, r8d",
            "vpaddd ymm12, ymm16, ymmword ptr [r15]",
            "vpcmpud k1, ymm12, ymm16, 1",
            "vpaddd ymm13 {{k1}}, ymm13, dword ptr [r15 + 68]{{1to8}}",
            "vpbroadcastd ymm14, r9d",
            "shr r9, 32",
            "vpbroadcastd ymm15, r9d",
            "vpbroadcastd ymm16, dword ptr [rcx]",
            "vpbroadcastd ymm17, dword ptr [rcx + 4]",
            "vpbroadcastd ymm18, dword ptr [rcx + 8]",
            "vpbroadcastd ymm19, dword ptr [rcx + 12]",
            "vpbroadcastd ymm20, dword ptr [rcx + 16]",
            "vpbroadcastd ymm21, dword ptr [rcx + 20]",
            "vpbroadcastd ymm22, dword ptr [rcx + 24]",
            "vpbroadcastd ymm23, dword ptr [rcx + 28]",
            "vpbroadcastd ymm24, dword ptr [rcx + 32]",
            "vpbroadcastd ymm25, dword ptr [rcx + 36]",
            "vpbroadcastd ymm26, dword ptr [rcx + 40]",
            "vpbroadcastd ymm27, dword ptr [rcx + 44]",
            "vpbroadcastd ymm28, dword ptr [rcx + 48]",
            "vpbroadcastd ymm29, dword ptr [rcx + 52]",
            "vpbroadcastd ymm30, dword ptr [rcx + 56]",
            "vpbroadcastd ymm31, dword ptr [rcx + 60]",
            vec_seven!("ymm"),
            "vpxord ymm16, ymm0, ymm8",
            "vpxord ymm17, ymm1, ymm9",
            "vpxord ymm18, ymm2, ymm10",
            "vpxord ymm19, ymm3, ymm11",
            "vpxord ymm20, ymm4, ymm12",
            "vpxord ymm21, ymm5, ymm13",
            "vpxord ymm22, ymm6, ymm14",
            "vpxord ymm23, ymm7, ymm15",
            "vpxord ymm24, ymm8, dword ptr [rax]{{1to8}}",
            "vpxord ymm25, ymm9, dword ptr [rax + 4]{{1to8}}",
            "vpxord ymm26, ymm10, dword ptr [rax + 8]{{1to8}}",
            "vpxord ymm27, ymm11, dword ptr [rax + 12]{{1to8}}",
            "vpxord ymm28, ymm12, dword ptr [rax + 16]{{1to8}}",
            "vpxord ymm29, ymm13, dword ptr [rax + 20]{{1to8}}",
            "vpxord ymm30, ymm14, dword ptr [rax + 24]{{1to8}}",
            "vpxord ymm31, ymm15, dword ptr [rax + 28]{{1to8}}",
            vec_four!("ymm", 16, 17, 18, 19, 0, 1, 2, 3),
            vec_four!("ymm", 20, 21, 22, 23, 0, 1, 2, 3),
            vec_four!("ymm", 24, 25, 26, 27, 0, 1, 2, 3),
            vec_four!("ymm", 28, 29, 30, 31, 0, 1, 2, 3),
            xof8_low!(16, 20, 24, 28, 0, 16, 32, 48),
            xof8_low!(17, 21, 25, 29, 64, 80, 96, 112),
            xof8_low!(18, 22, 26, 30, 128, 144, 160, 176),
            xof8_low!(19, 23, 27, 31, 192, 208, 224, 240),
            xof8_high!(16, 20, 24, 28, 256, 272, 288, 304),
            "cmp rsi, 6",
            "jb 3f",
            xof8_high!(17, 21, 25, 29, 320, 336, 352, 368),
            "cmp rsi, 7",
            "jb 3f",
            xof8_high!(18, 22, 26, 30, 384, 400, 416, 432),
            "cmp rsi, 8",
            "jb 3f",
            xof8_high!(19, 23, 27, 31, 448, 464, 480, 496),
            "3:",
            vec_clear!("ymm"),
            in("rax") cv.as_ptr(),
            in("rcx") block.as_ptr(),
            in("rdx") out.as_mut_ptr(),
            in("rsi") out.len(),
            inout("r8") counter => _,
            inout("r9") tail => _,
            in("r13") IV_256.as_ptr(),
            in("r15") &raw const STEPS,
            out("k1") _,
        )
    };
}
