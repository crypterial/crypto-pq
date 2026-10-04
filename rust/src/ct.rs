use core::hint::black_box;

pub(crate) fn equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut difference = 0u8;

    for (x, y) in a.iter().zip(b) {
        difference = black_box(difference | (x ^ y));
    }

    difference == 0
}

// 0xFF when the equally long inputs match, 0 otherwise, without a branch on their contents.
pub(crate) fn equal_mask(a: &[u8], b: &[u8]) -> u8 {
    let mut difference = 0u8;

    for (x, y) in a.iter().zip(b) {
        difference = black_box(difference | (x ^ y));
    }

    (u16::from(difference).wrapping_sub(1) >> 8) as u8
}

// out = a where mask is 0xFF, b where it is 0.
pub(crate) fn select(mask: u8, a: &[u8], b: &[u8], out: &mut [u8]) {
    let mask = black_box(mask);

    for ((target, x), y) in out.iter_mut().zip(a).zip(b) {
        *target = (x & mask) | (y & !mask);
    }
}

// With RUSTFLAGS="--cfg crypto_pq_ct", tests/ct.rs runs the library under valgrind's memcheck
// with every secret marked uninitialised, so that a branch or a memory index that depends on a
// secret is reported. A value derived from secrets is declassified where the specification makes
// it public. Without the cfg these hooks compile to nothing.
#[cfg(crypto_pq_ct)]
pub fn secret<T>(values: &[T]) {
    valgrind::request(
        valgrind::MAKE_MEM_UNDEFINED,
        values.as_ptr().cast(),
        size_of_val(values),
    );
}

#[cfg(crypto_pq_ct)]
pub fn declassify<T>(values: &[T]) {
    valgrind::request(
        valgrind::MAKE_MEM_DEFINED,
        values.as_ptr().cast(),
        size_of_val(values),
    );
}

#[cfg(not(crypto_pq_ct))]
#[inline(always)]
pub(crate) fn secret<T>(_: &[T]) {}

#[cfg(not(crypto_pq_ct))]
#[inline(always)]
pub(crate) fn declassify<T>(_: &[T]) {}

// declassify for a value held in registers. Under the cfg it passes through memory, which the
// request may change as far as the compiler knows, so it is read back after it.
#[cfg(crypto_pq_ct)]
pub(crate) fn declassify_value<T: Copy>(value: T) -> T {
    let mut copy = [value];

    valgrind::request(
        valgrind::MAKE_MEM_DEFINED,
        copy.as_mut_ptr().cast_const().cast(),
        size_of::<T>(),
    );

    copy[0]
}

#[cfg(not(crypto_pq_ct))]
#[inline(always)]
pub(crate) const fn declassify_value<T: Copy>(value: T) -> T {
    value
}

#[cfg(crypto_pq_ct)]
#[allow(unsafe_code)]
mod valgrind {
    // VG_USERREQ__MAKE_MEM_UNDEFINED and VG_USERREQ__MAKE_MEM_DEFINED of valgrind's memcheck.h:
    // the tool base ('M' << 24) | ('C' << 16), plus 1 and 2.
    pub(super) const MAKE_MEM_UNDEFINED: usize = 0x4D43_0001;

    pub(super) const MAKE_MEM_DEFINED: usize = 0x4D43_0002;

    // The client request sequence of valgrind.h. The four rotations add up to 128 bits, so run
    // natively it changes no register; valgrind recognises it and serves the request whose six
    // words the address register points to.
    pub(super) fn request(code: usize, address: *const u8, length: usize) {
        let arguments = [code, address as usize, length, 0, 0, 0];

        #[cfg(target_arch = "x86_64")]
        // SAFETY: rdi ends as it started and rbx is exchanged with itself; the request reads the
        // six words at rax and writes its result to rdx.
        unsafe {
            core::arch::asm!(
                "rol rdi, 3",
                "rol rdi, 13",
                "rol rdi, 61",
                "rol rdi, 51",
                "xchg rbx, rbx",
                in("rax") arguments.as_ptr(),
                inout("rdx") 0usize => _,
                options(nostack),
            );
        }

        #[cfg(target_arch = "aarch64")]
        // SAFETY: x12 ends as it started and x10 is ORed with itself; the request reads the six
        // words at x4 and writes its result to x3.
        unsafe {
            core::arch::asm!(
                "ror x12, x12, #3",
                "ror x12, x12, #13",
                "ror x12, x12, #51",
                "ror x12, x12, #61",
                "orr x10, x10, x10",
                in("x4") arguments.as_ptr(),
                inout("x3") 0usize => _,
                options(nostack),
            );
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("the constant-time check runs on x86_64 and aarch64");
}
