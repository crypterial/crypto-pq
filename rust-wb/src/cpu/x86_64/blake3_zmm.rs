// BLAKE3 on sixteen inputs side by side in 512-bit registers, for hash_many and the extended
// output, on the cores of the table in zmm_lanes() of x86_64.rs (D-44). Each register holds one
// state word of sixteen inputs, as each of blake3.rs's eight-lane AVX2 kernels holds eight: the
// state is in zmm0 to zmm15 and the message words in zmm16 to zmm31, all in registers through
// the seven rounds, and every rotation is one VPRORD. The blocks of the sixteen inputs are
// transposed into words with VPUNPCKLDQ, VPUNPCKHDQ, VPUNPCKLQDQ, VPUNPCKHQDQ and VSHUFI32X4, and
// the outputs back the same way. Every instruction is on Intel's list of data-operand-independent
// timing instructions, and no branch or address depends on the data.
//
// The two kernels are the only functions built with AVX-512F, and so the only code with 512-bit
// registers, which CI checks. Each is one block of assembly that ends by zeroing zmm16 to zmm31,
// which no other code uses, and with VZEROUPPER.

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

macro_rules! zmm_op {
    ($op:literal, $x:literal, $y:literal, $z:literal) => {
        concat!($op, " zmm", $x, ", zmm", $y, ", zmm", $z, "\n")
    };
}

macro_rules! zmm_ror {
    ($x:literal, $n:literal) => {
        concat!("vprord zmm", $x, ", zmm", $x, ", ", $n, "\n")
    };
}

// Half a step of four G functions: a += m + b, d = (d ^ a) >>> dr, c += d, b = (b ^ c) >>> br,
// v_i in zmm i and the message words in the registers m.
#[rustfmt::skip]
macro_rules! zmm_half {
    (
        [$a0:literal, $a1:literal, $a2:literal, $a3:literal],
        [$b0:literal, $b1:literal, $b2:literal, $b3:literal],
        [$c0:literal, $c1:literal, $c2:literal, $c3:literal],
        [$d0:literal, $d1:literal, $d2:literal, $d3:literal],
        [$m0:literal, $m1:literal, $m2:literal, $m3:literal],
        $dr:literal, $br:literal
    ) => {
        concat!(
            zmm_op!("vpaddd", $a0, $a0, $m0), zmm_op!("vpaddd", $a1, $a1, $m1),
            zmm_op!("vpaddd", $a2, $a2, $m2), zmm_op!("vpaddd", $a3, $a3, $m3),
            zmm_op!("vpaddd", $a0, $a0, $b0), zmm_op!("vpaddd", $a1, $a1, $b1),
            zmm_op!("vpaddd", $a2, $a2, $b2), zmm_op!("vpaddd", $a3, $a3, $b3),
            zmm_op!("vpxord", $d0, $d0, $a0), zmm_op!("vpxord", $d1, $d1, $a1),
            zmm_op!("vpxord", $d2, $d2, $a2), zmm_op!("vpxord", $d3, $d3, $a3),
            zmm_ror!($d0, $dr), zmm_ror!($d1, $dr), zmm_ror!($d2, $dr), zmm_ror!($d3, $dr),
            zmm_op!("vpaddd", $c0, $c0, $d0), zmm_op!("vpaddd", $c1, $c1, $d1),
            zmm_op!("vpaddd", $c2, $c2, $d2), zmm_op!("vpaddd", $c3, $c3, $d3),
            zmm_op!("vpxord", $b0, $b0, $c0), zmm_op!("vpxord", $b1, $b1, $c1),
            zmm_op!("vpxord", $b2, $b2, $c2), zmm_op!("vpxord", $b3, $b3, $c3),
            zmm_ror!($b0, $br), zmm_ror!($b1, $br), zmm_ror!($b2, $br), zmm_ror!($b3, $br),
        )
    };
}

// A round whose message words are in the registers s, in the round's order: the columns, then
// the diagonals.
#[rustfmt::skip]
macro_rules! zmm_round {
    (
        $s0:literal, $s1:literal, $s2:literal, $s3:literal, $s4:literal, $s5:literal,
        $s6:literal, $s7:literal, $s8:literal, $s9:literal, $s10:literal, $s11:literal,
        $s12:literal, $s13:literal, $s14:literal, $s15:literal
    ) => {
        concat!(
            zmm_half!(
                [0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15],
                [$s0, $s2, $s4, $s6], 16, 12
            ),
            zmm_half!(
                [0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15],
                [$s1, $s3, $s5, $s7], 8, 7
            ),
            zmm_half!(
                [0, 1, 2, 3], [5, 6, 7, 4], [10, 11, 8, 9], [15, 12, 13, 14],
                [$s8, $s10, $s12, $s14], 16, 12
            ),
            zmm_half!(
                [0, 1, 2, 3], [5, 6, 7, 4], [10, 11, 8, 9], [15, 12, 13, 14],
                [$s9, $s11, $s13, $s15], 8, 7
            ),
        )
    };
}

// The seven rounds, message word j in zmm 16 + j: each round's order is the specification's
// message schedule plus 16.
#[rustfmt::skip]
macro_rules! zmm_seven {
    () => {
        concat!(
            zmm_round!(16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31),
            zmm_round!(18, 22, 19, 26, 23, 16, 20, 29, 17, 27, 28, 21, 25, 30, 31, 24),
            zmm_round!(19, 20, 26, 28, 29, 18, 23, 30, 22, 21, 25, 16, 27, 31, 24, 17),
            zmm_round!(26, 23, 28, 25, 30, 19, 29, 31, 20, 16, 27, 18, 21, 24, 17, 22),
            zmm_round!(28, 29, 25, 27, 31, 26, 30, 24, 23, 18, 21, 19, 16, 17, 22, 20),
            zmm_round!(25, 30, 27, 21, 24, 28, 31, 17, 29, 19, 16, 26, 18, 22, 20, 23),
            zmm_round!(27, 31, 21, 16, 17, 25, 24, 22, 30, 26, 18, 28, 19, 20, 23, 29),
        )
    };
}

// The four-word transposition of registers x within each 128-bit quarter, through t: word i of
// quarter q of x_j to word j of quarter q of x_i.
#[rustfmt::skip]
macro_rules! zmm_four {
    (
        $x0:literal, $x1:literal, $x2:literal, $x3:literal,
        $t0:literal, $t1:literal, $t2:literal, $t3:literal
    ) => {
        concat!(
            zmm_op!("vpunpckldq", $t0, $x0, $x1), zmm_op!("vpunpckhdq", $t1, $x0, $x1),
            zmm_op!("vpunpckldq", $t2, $x2, $x3), zmm_op!("vpunpckhdq", $t3, $x2, $x3),
            zmm_op!("vpunpcklqdq", $x0, $t0, $t2), zmm_op!("vpunpckhqdq", $x1, $t0, $t2),
            zmm_op!("vpunpcklqdq", $x2, $t1, $t3), zmm_op!("vpunpckhqdq", $x3, $t1, $t3),
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
            zmm_four!(16, 17, 18, 19, $t0, $t1, $t2, $t3),
            zmm_four!(20, 21, 22, 23, $t0, $t1, $t2, $t3),
            zmm_four!(24, 25, 26, 27, $t0, $t1, $t2, $t3),
            zmm_four!(28, 29, 30, 31, $t0, $t1, $t2, $t3),
            zmm_quarters!(16, 20, 24, 28, $t0, $t1, $t2, $t3),
            zmm_quarters!(17, 21, 25, 29, $t0, $t1, $t2, $t3),
            zmm_quarters!(18, 22, 26, 30, $t0, $t1, $t2, $t3),
            zmm_quarters!(19, 23, 27, 31, $t0, $t1, $t2, $t3),
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

// zmm16 to zmm31 zeroed, then the upper halves of the others.
#[rustfmt::skip]
macro_rules! zmm_clear {
    () => {
        concat!(
            zmm_op!("vpxord", 16, 16, 16), zmm_op!("vpxord", 17, 17, 17),
            zmm_op!("vpxord", 18, 18, 18), zmm_op!("vpxord", 19, 19, 19),
            zmm_op!("vpxord", 20, 20, 20), zmm_op!("vpxord", 21, 21, 21),
            zmm_op!("vpxord", 22, 22, 22), zmm_op!("vpxord", 23, 23, 23),
            zmm_op!("vpxord", 24, 24, 24), zmm_op!("vpxord", 25, 25, 25),
            zmm_op!("vpxord", 26, 26, 26), zmm_op!("vpxord", 27, 27, 27),
            zmm_op!("vpxord", 28, 28, 28), zmm_op!("vpxord", 29, 29, 29),
            zmm_op!("vpxord", 30, 30, 30), zmm_op!("vpxord", 31, 31, 31),
            "vzeroupper\n",
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
            "vmovdqu32 zmm16, zmmword ptr [r8]",
            "vmovdqu32 zmm17, zmmword ptr [r9]",
            "vmovdqu32 zmm18, zmmword ptr [r10]",
            "vmovdqu32 zmm19, zmmword ptr [r11]",
            "vmovdqu32 zmm20, zmmword ptr [r12]",
            "vmovdqu32 zmm21, zmmword ptr [r13]",
            "vmovdqu32 zmm22, zmmword ptr [r14]",
            "vmovdqu32 zmm23, zmmword ptr [r15]",
            "vmovdqu32 zmm24, zmmword ptr [r8 + rsi]",
            "vmovdqu32 zmm25, zmmword ptr [r9 + rsi]",
            "vmovdqu32 zmm26, zmmword ptr [r10 + rsi]",
            "vmovdqu32 zmm27, zmmword ptr [r11 + rsi]",
            "vmovdqu32 zmm28, zmmword ptr [r12 + rsi]",
            "vmovdqu32 zmm29, zmmword ptr [r13 + rsi]",
            "vmovdqu32 zmm30, zmmword ptr [r14 + rsi]",
            "vmovdqu32 zmm31, zmmword ptr [r15 + rsi]",
            zmm_transpose!(8, 9, 10, 11),
            "vpbroadcastd zmm8, dword ptr [rdi + 192]",
            "vpbroadcastd zmm9, dword ptr [rdi + 196]",
            "vpbroadcastd zmm10, dword ptr [rdi + 200]",
            "vpbroadcastd zmm11, dword ptr [rdi + 204]",
            "vmovdqa32 zmm12, zmmword ptr [rdi]",
            "vmovdqa32 zmm13, zmmword ptr [rdi + 64]",
            "vpbroadcastd zmm14, dword ptr [rdi + 208]",
            "vpbroadcastd zmm15, dword ptr [rdi + rax + 128]",
            zmm_seven!(),
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
            zmm_four!(0, 1, 2, 3, 8, 9, 10, 11),
            zmm_four!(4, 5, 6, 7, 8, 9, 10, 11),
            zmm_cvs!(0, 4, 0, 128, 256, 384),
            zmm_cvs!(1, 5, 32, 160, 288, 416),
            zmm_cvs!(2, 6, 64, 192, 320, 448),
            zmm_cvs!(3, 7, 96, 224, 352, 480),
            zmm_clear!(),
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

/// Output blocks of the root for the sixteen counters of table, from its chaining value cv and
/// its message words block, with the length and flags of table.length and table.flags[0].
///
/// # Safety
///
/// The CPU has AVX-512F and AVX-512VL and the operating system saves their registers.
#[target_feature(enable = "avx512f,avx512vl")]
#[inline(never)]
#[allow(unsafe_code)]
pub(super) unsafe fn xof16_zmm(
    cv: &[u32; 8],
    block: &[u32; 16],
    table: &Table16,
    out: &mut [[u8; 64]; 16],
) {
    // SAFETY: AVX-512F instructions, which the caller's CPU has, on the vector registers, all
    // declared clobbered. They read the 32 bytes of cv, the 64 of block and the 212 of table,
    // write the 1024 bytes of out, and use no stack.
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
            zmm_seven!(),
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
            zmm_clear!(),
            in("rax") cv.as_ptr(),
            in("rcx") block.as_ptr(),
            in("rdx") out.as_mut_ptr(),
            in("rdi") &raw const *table,
        )
    };
}
