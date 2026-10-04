// CPU-specific instructions with a portable fallback. A kernel runs when the build guarantees its
// instructions (cfg(target_feature)), or when the operating system or CPUID reports them; that
// answer is found once, without allocating or blocking, and kept in an atomic, so a check costs
// one load. Each function here returns whether it did the work (permute_many, how many states it
// permuted), and the caller runs the portable code for the rest. --cfg crypto_pq_portable
// compiles every kernel out, which is how CI tests the fallback on machines that have the
// instructions.
//
// The constant-time check (--cfg crypto_pq_ct) runs under valgrind, which cannot execute every
// instruction: its build leaves out SHA3, SHA512 and DIT on arm64 and the SHA extensions on
// x86-64, ignores what the build guarantees, and detects the rest at run time, so that it checks
// the SHA-256 instructions and NEON on arm64 and AVX2 on x86-64. The portable build checks the
// fallback.

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    not(crypto_pq_portable)
))]
mod aarch64;

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    not(crypto_pq_portable)
))]
use aarch64 as arch;

// Inside an SGX enclave CPUID faults, so the enclave target keeps the portable code.
#[cfg(all(
    target_arch = "x86_64",
    not(target_env = "sgx"),
    not(crypto_pq_portable)
))]
mod x86_64;

#[cfg(all(
    target_arch = "x86_64",
    not(target_env = "sgx"),
    not(crypto_pq_portable)
))]
use x86_64 as arch;

#[cfg(not(any(
    all(
        target_arch = "aarch64",
        target_endian = "little",
        target_feature = "neon",
        not(crypto_pq_portable)
    ),
    all(
        target_arch = "x86_64",
        not(target_env = "sgx"),
        not(crypto_pq_portable)
    ),
)))]
mod arch {
    // Nothing is accelerated: the portable build, and every other architecture.
    #[inline(always)]
    pub(crate) fn compress256(_: &mut [u32; 8], _: &[[u8; 64]]) -> bool {
        false
    }

    #[inline(always)]
    pub(crate) fn compress256_lanes<const LANES: usize>(
        _: &mut [[u32; LANES]; 8],
        _: &mut [[u32; LANES]; 16],
    ) -> bool {
        false
    }

    #[inline(always)]
    pub(crate) fn compress512(_: &mut [u64; 8], _: &[[u8; 128]]) -> bool {
        false
    }

    #[inline(always)]
    pub(crate) fn permute_many(_: &mut [&mut [u64; 25]]) -> usize {
        0
    }

    #[inline(always)]
    pub(crate) fn ntt(_: &mut [i32; 256], _: &super::Field) -> bool {
        false
    }

    #[inline(always)]
    pub(crate) fn inverse_ntt(_: &mut [i32; 256], _: &super::Field) -> bool {
        false
    }

    #[inline(always)]
    pub(crate) fn multiply(
        _: &mut [i32; 256],
        _: &[i32; 256],
        _: &[i32; 256],
        _: &super::Field,
    ) -> bool {
        false
    }

    #[inline(always)]
    pub(crate) fn multiply_add(
        _: &mut [i32; 256],
        _: &[i32; 256],
        _: &[i32; 256],
        _: &super::Field,
    ) -> bool {
        false
    }

    #[inline(always)]
    pub(crate) fn base_multiply_add(
        _: &mut [i32; 256],
        _: &[u16; 256],
        _: &[u16; 256],
        _: &[i32; 128],
        _: &super::Field,
    ) -> bool {
        false
    }

    #[inline(always)]
    pub(crate) fn ntt16(_: &mut [u16; 256], _: &super::Field16) -> bool {
        false
    }

    #[inline(always)]
    pub(crate) fn inverse_ntt16(_: &[i32; 256], _: &mut [u16; 256], _: &super::Field16) -> bool {
        false
    }

    #[inline(always)]
    pub(crate) fn binomial(_: usize, _: &[u8], _: u16, _: &mut [u16; 256]) -> bool {
        false
    }
}

pub(crate) use arch::{
    base_multiply_add, binomial, compress256, compress256_lanes, compress512, inverse_ntt,
    inverse_ntt16, multiply, multiply_add, ntt, ntt16, permute_many,
};

// What the transform kernels need of the field of ML-KEM or ML-DSA, so that they compute exactly
// what the portable code computes. Products are Montgomery products in the portable form,
// high(a, b) - high(a * (b * q^-1 mod 2^32), q). The twiddle factors are in Montgomery form, in
// the order in which the forward and the inverse transform take them, each with its product by
// q^-1. The fields are read only by the kernels, which some targets do not have.
#[allow(dead_code)]
pub(crate) struct Field {
    pub(crate) q: i32,
    pub(crate) qinv: i32,
    pub(crate) layers: usize,
    pub(crate) forward: [i32; 256],
    pub(crate) forward_qinv: [i32; 256],
    pub(crate) inverse: [i32; 256],
    pub(crate) inverse_qinv: [i32; 256],
    pub(crate) prepare: Prepare,
    pub(crate) forward_scale: Option<i32>,
    pub(crate) inverse_scale: i32,
}

// The first step of the inverse transform: ML-DSA's x - ((x + 2^22) >> 23) q, or ML-KEM's
// Montgomery product with a constant.
#[allow(dead_code)]
pub(crate) enum Prepare {
    Reduce,
    Montgomery(i32),
}

impl Field {
    // zetas[m] multiplies butterfly group m of the forward transform, counted from 1 across the
    // layers; the inverse takes them in the reverse order. After its layers the forward transform
    // ends with freeze(montgomery(x, forward_scale)) if there is one, and the inverse always with
    // freeze(montgomery(x, inverse_scale)).
    pub(crate) const fn new(
        q: i32,
        qinv: i32,
        layers: usize,
        zetas: [i32; 256],
        prepare: Prepare,
        forward_scale: Option<i32>,
        inverse_scale: i32,
    ) -> Self {
        let mut field = Self {
            q,
            qinv,
            layers,
            forward: zetas,
            forward_qinv: [0; 256],
            inverse: [0; 256],
            inverse_qinv: [0; 256],
            prepare,
            forward_scale,
            inverse_scale,
        };

        let mut m = 0;

        while m < 256 {
            field.forward_qinv[m] = zetas[m].wrapping_mul(qinv);

            field.inverse[m] = zetas[255 - m];

            field.inverse_qinv[m] = zetas[255 - m].wrapping_mul(qinv);

            m += 1;
        }

        field
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    not(crypto_pq_portable)
))]
pub(crate) use aarch64::Dit;

// Data-independent timing is an arm64 mode; elsewhere the guard does nothing.
#[cfg(not(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    not(crypto_pq_portable)
)))]
pub(crate) struct Dit;

#[cfg(not(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    not(crypto_pq_portable)
)))]
impl Dit {
    #[inline(always)]
    pub(crate) fn new() -> Self {
        Self
    }
}

// ML-KEM's transforms on 16-bit lanes, twice as many coefficients per vector: q < 2^12, so the
// forward sums stay below 8q < 2^15. The products are Montgomery products modulo 2^16, so these
// kernels keep their own twiddle factors, in Montgomery form for 2^16, and compute only the same
// canonical results as the portable code, not its intermediate values. The layers that pair
// coefficients 4 and 2 apart take their factors as whole vectors, one factor per lane.
#[allow(dead_code)]
pub(crate) struct Field16 {
    pub(crate) q: i16,
    pub(crate) qinv: i16,
    pub(crate) forward: [i16; 128],
    pub(crate) forward_qinv: [i16; 128],
    pub(crate) inverse: [i16; 128],
    pub(crate) inverse_qinv: [i16; 128],
    pub(crate) forward_lanes: [[[i16; 8]; 16]; 4],
    pub(crate) inverse_lanes: [[[i16; 8]; 16]; 4],
    pub(crate) canonical: i16,
    pub(crate) inverse_scale: i16,
    pub(crate) barrett: i16,
    pub(crate) reduce32: i32,
    pub(crate) qinv32: i32,
}

impl Field16 {
    // zetas[m] in Montgomery form for 2^16 multiplies forward group m; canonical is 2^16 mod q,
    // inverse_scale is 2^16 / 128 mod q, and reduce32 is 2^32 mod q, whose 32-bit Montgomery
    // product with the sums of the base multiplication brings them below q first.
    pub(crate) const fn new(
        q: i16,
        zetas: [i16; 128],
        canonical: i16,
        inverse_scale: i16,
        reduce32: i32,
        qinv32: i32,
    ) -> Self {
        let mut qinv = 1i16;

        let mut i = 0;

        while i < 4 {
            qinv = qinv.wrapping_mul(2i16.wrapping_sub(q.wrapping_mul(qinv)));

            i += 1;
        }

        let mut field = Self {
            q,
            qinv,
            forward: zetas,
            forward_qinv: [0; 128],
            inverse: [0; 128],
            inverse_qinv: [0; 128],
            forward_lanes: [[[0; 8]; 16]; 4],
            inverse_lanes: [[[0; 8]; 16]; 4],
            canonical,
            inverse_scale,
            barrett: (((1 << 26) + q as i32 / 2) / q as i32) as i16,
            reduce32,
            qinv32,
        };

        let mut m = 0;

        while m < 128 {
            field.forward_qinv[m] = zetas[m].wrapping_mul(qinv);

            field.inverse[m] = zetas[127 - m];

            field.inverse_qinv[m] = field.inverse[m].wrapping_mul(qinv);

            m += 1;
        }

        // Vector p of a layer covers 16 coefficients. Pairing 4 apart, its lanes hold two groups
        // of four lanes; pairing 2 apart, after the transposition, four groups of two lanes.
        let mut p = 0;

        while p < 16 {
            let mut lane = 0;

            while lane < 8 {
                let (four, two) = (32 + 2 * p + lane / 4, 64 + 4 * p + lane / 2);

                let (four_inverse, two_inverse) = (64 + 2 * p + lane / 4, 4 * p + lane / 2);

                field.forward_lanes[0][p][lane] = zetas[four];

                field.forward_lanes[1][p][lane] = field.forward_qinv[four];

                field.forward_lanes[2][p][lane] = zetas[two];

                field.forward_lanes[3][p][lane] = field.forward_qinv[two];

                field.inverse_lanes[0][p][lane] = field.inverse[four_inverse];

                field.inverse_lanes[1][p][lane] = field.inverse_qinv[four_inverse];

                field.inverse_lanes[2][p][lane] = field.inverse[two_inverse];

                field.inverse_lanes[3][p][lane] = field.inverse_qinv[two_inverse];

                lane += 1;
            }

            p += 1;
        }

        field
    }
}

// Inputs for the differential tests, which run each kernel and the portable code on the same
// random and edge inputs: SplitMix64, the same sequence on every run.
#[cfg(test)]
pub(crate) mod testing {
    pub(crate) struct Inputs(u64);

    impl Inputs {
        pub(crate) const fn new(seed: u64) -> Self {
            Self(seed)
        }

        pub(crate) fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);

            let mut z = self.0;

            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);

            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);

            z ^ (z >> 31)
        }

        pub(crate) fn words<const N: usize>(&mut self) -> [u64; N] {
            core::array::from_fn(|_| self.next())
        }

        pub(crate) fn bytes<const N: usize>(&mut self) -> [u8; N] {
            core::array::from_fn(|_| self.next() as u8)
        }
    }

    // Every bit clear, every bit set and the two alternating patterns, which drive the carries
    // and rotations of the kernels to their extremes.
    pub(crate) const EDGES: [u64; 4] = [0, u64::MAX, 0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_5555];
}
