// Latency probe: dependent chains of one instruction, 100 per loop pass, timed; each line gives ns
// per instruction and that over a scalar ADD chain's (cycles, if an ADD takes one). The 100 copies
// are written out, not .rept: LLVM sizes inline assembly by its lines, and a .rept made it place
// branches of the caller out of range. Every row is timed twice; the second pass is printed.
use std::arch::asm;
use std::time::Instant;

const PASSES: u64 = 200_000;

fn time(f: &dyn Fn(u64)) -> f64 {
    f(PASSES / 10);

    let mut best = f64::MAX;

    for _ in 0..7 {
        let start = Instant::now();

        f(PASSES);

        best = best.min(start.elapsed().as_nanos() as f64 / (PASSES * 100) as f64);
    }

    best
}

macro_rules! x10 {
    ($s:expr) => {
        concat!($s, "\n", $s, "\n", $s, "\n", $s, "\n", $s, "\n", $s, "\n", $s, "\n", $s, "\n", $s, "\n", $s, "\n")
    };
}

macro_rules! x100 {
    ($s:expr) => {
        concat!(x10!($s), x10!($s), x10!($s), x10!($s), x10!($s), x10!($s), x10!($s), x10!($s), x10!($s), x10!($s))
    };
}

#[cfg(target_arch = "aarch64")]
macro_rules! chain {
    ($body:literal $(, $reg:ident = $kind:ident)*) => {
        |passes: u64| unsafe {
            asm!(
                "2:",
                x100!($body),
                "sub {n}, {n}, 1",
                "cmp {n}, 0",
                "b.ne 2b",
                n = inout(reg) passes => _,
                $($reg = out($kind) _,)*
                options(nostack),
            );
        }
    };
}

#[cfg(target_arch = "x86_64")]
macro_rules! chain_x86 {
    ($body:literal $(, $reg:ident = $kind:ident)*) => {
        |passes: u64| unsafe {
            asm!(
                "2:",
                x100!($body),
                "dec {n}",
                "jnz 2b",
                "vzeroupper",
                n = inout(reg) passes => _,
                $($reg = out($kind) _,)*
                out("xmm0") _,
                out("xmm1") _,
                options(nostack),
            );
        }
    };
}

fn report(rows: Vec<(&str, f64)>) {
    let base = rows[0].1;

    for (name, ns) in rows {
        println!("PROBE\t{name}\t{ns:.4} ns\t{:.2}", ns / base);
    }
}

#[cfg(target_arch = "aarch64")]
pub fn run() {
    rows();

    report(rows());
}

#[cfg(target_arch = "aarch64")]
fn rows() -> Vec<(&'static str, f64)> {
    vec![
        ("add", time(&chain!("add {a}, {a}, {b}", a = reg, b = reg))),
        ("ror", time(&chain!("ror {a}, {a}, #7", a = reg))),
        ("eor", time(&chain!("eor {a}, {a}, {b}", a = reg, b = reg))),
        ("eor-ror (rotated operand)", time(&chain!("eor {a}, {b}, {a}, ror #7", a = reg, b = reg))),
        ("neon add", time(&chain!("add {a:v}.4s, {a:v}.4s, {b:v}.4s", a = vreg, b = vreg))),
        ("neon eor", time(&chain!("eor {a:v}.16b, {a:v}.16b, {b:v}.16b", a = vreg, b = vreg))),
        ("neon rev32 (ror 16)", time(&chain!("rev32 {a:v}.8h, {a:v}.8h", a = vreg))),
        ("neon tbl (ror 8)", time(&chain!("tbl {a:v}.16b, {{{a:v}.16b}}, {b:v}.16b", a = vreg, b = vreg))),
        ("neon usra", time(&chain!("usra {a:v}.4s, {b:v}.4s, #7", a = vreg, b = vreg))),
        ("neon sri", time(&chain!("sri {a:v}.4s, {b:v}.4s, #7", a = vreg, b = vreg))),
    ]
}

#[cfg(target_arch = "x86_64")]
pub fn run() {
    rows();

    report(rows());

    clock();
}

// D-44's clock probe: whether a core runs scalar code at a lower clock right after BLAKE3's 512-bit
// kernels. Each sample runs the ADD chain alone for about 5 ms, longer than a core keeps a lower
// clock after its last 512-bit instruction, then hashes 16 KiB 512 times through one copy, then
// times 100 000 dependent ADDs. crypto-pq new takes the 512-bit kernels on the processors of
// D-44's third table and the eight-lane AVX2 kernel elsewhere, main the AVX2 kernel everywhere.
// Each turn samples new, main and main again (the A/A); a line gives the median ns per ADD and the
// median, minimum and maximum over turns of its ratio to main's sample of the same turn.
#[cfg(target_arch = "x86_64")]
fn clock() {
    let input = crate::data(16384, 6);

    let add = chain_x86!("add {a}, {b}", a = reg, b = reg);

    let sample = |hash: &dyn Fn(&[u8], &mut [u8])| {
        let mut out = [0u8; 32];

        add(200_000);

        for _ in 0..512 {
            hash(std::hint::black_box(&input), &mut out);
        }

        std::hint::black_box(&out);

        let start = Instant::now();

        add(1000);

        start.elapsed().as_nanos() as f64 / 100_000.0
    };

    let new = |d: &[u8], o: &mut [u8]| cpq::BLAKE3_256.digest_into(d, o).unwrap();

    let main = |d: &[u8], o: &mut [u8]| cpq_main::BLAKE3_256.digest_into(d, o).unwrap();

    let mut turns = Vec::new();

    for _ in 0..100 {
        turns.push([sample(&new), sample(&main), sample(&main)]);
    }

    for (i, name) in ["after new", "after main", "after main again"].iter().enumerate() {
        let mut ns: Vec<f64> = turns.iter().map(|t| t[i]).collect();

        let mut ratios: Vec<f64> = turns.iter().map(|t| t[i] / t[1]).collect();

        let low = ratios.iter().copied().fold(f64::MAX, f64::min);

        let high = ratios.iter().copied().fold(0.0, f64::max);

        println!(
            "CLOCK\t{name}\t{:.4} ns per add\t{:.4}\t{low:.4}\t{high:.4}",
            crate::median(&mut ns),
            crate::median(&mut ratios)
        );
    }
}

#[cfg(target_arch = "x86_64")]
fn rows() -> Vec<(&'static str, f64)> {
    let mut rows = vec![
        ("add", time(&chain_x86!("add {a}, {b}", a = reg, b = reg))),
        ("ror", time(&chain_x86!("ror {a:e}, 7", a = reg))),
        ("xor", time(&chain_x86!("xor {a}, {b}", a = reg, b = reg))),
    ];

    if std::arch::is_x86_feature_detected!("avx2") {
        rows.push(("vpaddd xmm", time(&chain_x86!("vpaddd xmm0, xmm0, xmm1"))));

        rows.push(("vpaddq ymm", time(&chain_x86!("vpaddq ymm0, ymm0, ymm1"))));

        rows.push(("vpxor xmm", time(&chain_x86!("vpxor xmm0, xmm0, xmm1"))));

        rows.push(("vpshufb xmm", time(&chain_x86!("vpshufb xmm0, xmm0, xmm1"))));

        rows.push(("vpshufd xmm", time(&chain_x86!("vpshufd xmm0, xmm0, 0x93"))));

        rows.push(("vpsrld xmm", time(&chain_x86!("vpsrld xmm0, xmm0, 7"))));

        rows.push(("vpermq ymm", time(&chain_x86!("vpermq ymm0, ymm0, 0x93"))));
    }

    if std::arch::is_x86_feature_detected!("avx512vl") {
        rows.push(("vprord xmm", time(&chain_x86!("vprord xmm0, xmm0, 7"))));

        rows.push(("vprorq ymm", time(&chain_x86!("vprorq ymm0, ymm0, 24"))));

        rows.push(("vpermi2d ymm", time(&chain_x86!("vpermi2d ymm0, ymm1, ymm1"))));
    }

    rows
}
