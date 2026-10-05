use core::hint::black_box;

// The OR of the XORs of two equally long inputs, eight bytes at a time. The sum passes through
// black_box after every 64 bytes and at the end, so the compiler can neither stop the loop early
// nor see the result before every byte has been read; a barrier after every byte cost
// microseconds per kilobyte.
fn difference(a: &[u8], b: &[u8]) -> u64 {
    let mut difference = 0;

    let (a_blocks, a_rest) = a.as_chunks::<64>();

    let (b_blocks, b_rest) = b.as_chunks::<64>();

    for (x, y) in a_blocks.iter().zip(b_blocks) {
        for (x, y) in x.as_chunks::<8>().0.iter().zip(y.as_chunks::<8>().0) {
            difference |= u64::from_ne_bytes(*x) ^ u64::from_ne_bytes(*y);
        }

        difference = black_box(difference);
    }

    let (a_words, a_rest) = a_rest.as_chunks::<8>();

    let (b_words, b_rest) = b_rest.as_chunks::<8>();

    for (x, y) in a_words.iter().zip(b_words) {
        difference |= u64::from_ne_bytes(*x) ^ u64::from_ne_bytes(*y);
    }

    for (x, y) in a_rest.iter().zip(b_rest) {
        difference |= u64::from(x ^ y);
    }

    black_box(difference)
}

pub(crate) fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && difference(a, b) == 0
}

// 0xFF when the equally long inputs match, 0 otherwise, without a branch on their contents.
pub(crate) fn equal_mask(a: &[u8], b: &[u8]) -> u8 {
    let difference = difference(a, b);

    let nonzero = (difference | difference.wrapping_neg()) >> 63;

    (nonzero as u8).wrapping_sub(1)
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

#[cfg(test)]
mod tests {
    use super::*;

    // Every length up to three blocks of 64 bytes, equal and with one bit flipped at each
    // position in turn, against a byte-by-byte comparison.
    #[test]
    fn comparisons_find_every_difference() {
        let a: [u8; 200] = core::array::from_fn(|i| (i * 37 + 11) as u8);

        for length in 0..a.len() {
            let a = &a[..length];

            assert!(equal(a, a));

            assert_eq!(equal_mask(a, a), 0xFF);

            for position in 0..length {
                let mut b = a.to_vec();

                b[position] ^= 1 << (position % 8);

                assert!(!equal(a, &b), "length {length}, position {position}");

                assert_eq!(equal_mask(a, &b), 0, "length {length}, position {position}");
            }
        }

        assert!(!equal(&a[..3], &a[..4]));
    }
}
