use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{Ordering, compiler_fence};

// Secrets are overwritten with zeros that the compiler must keep, even when the memory is never
// read again. The zeros are written with ordinary stores, as wide as the target has, and then the
// buffer's address goes into an empty assembly block, which for all the compiler knows reads the
// buffer, so no store can be dropped as dead. (Volatile stores of whole arrays were each built in
// a temporary first and copied, a store-to-load dependency per sixteen bytes.) Up to eight values
// of at most a word get a volatile store each instead: an address given to the assembly pins a
// variable to memory for its whole life, which slows the loops that would keep it in registers.
#[cfg(all(
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "loongarch64",
    ),
    not(miri)
))]
#[allow(unsafe_code)]
pub(crate) fn wipe<T: Copy + Default>(values: &mut [T]) {
    if size_of::<T>() <= 8 && values.len() <= 8 {
        for value in values {
            // SAFETY: `value` comes from a mutable slice, so it is valid, aligned and exclusive.
            unsafe { core::ptr::write_volatile(value, T::default()) };
        }

        compiler_fence(Ordering::SeqCst);

        return;
    }

    values.fill(T::default());

    // SAFETY: the assembly is empty: it reads no register but the address, writes nothing and
    // leaves the stack and the flags alone.
    unsafe {
        core::arch::asm!(
            "/* {0} */",
            in(reg) values.as_ptr(),
            options(nostack, preserves_flags, readonly),
        );
    }

    compiler_fence(Ordering::SeqCst);
}

// Targets without stable inline assembly in Rust, and Miri, which cannot run it: volatile writes,
// which survive dead-store elimination, in groups of sixteen and then eight values.
#[cfg(any(
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "loongarch64",
    )),
    miri
))]
#[allow(unsafe_code)]
pub(crate) fn wipe<T: Copy + Default>(values: &mut [T]) {
    let (wide, rest) = values.as_chunks_mut::<16>();

    for group in wide {
        // SAFETY: `group` comes from a mutable slice, so it is valid, aligned and exclusive.
        unsafe { core::ptr::write_volatile(group, [T::default(); 16]) };
    }

    let (groups, rest) = rest.as_chunks_mut::<8>();

    for group in groups {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(group, [T::default(); 8]) };
    }

    for value in rest {
        // SAFETY: `value` comes from a mutable slice, so it is valid, aligned and exclusive.
        unsafe { core::ptr::write_volatile(value, T::default()) };
    }

    compiler_fence(Ordering::SeqCst);
}

// wipe for an array that holds secrets and that LLVM keeps in registers at opt-level 3: there the
// wipe would give the array an address, and so the very memory copy it then clears, while at the
// other levels the array is in memory and has to be wiped (D-76). build.rs sets
// crypto_pq_optimized only at 3, so builds whose level it cannot read keep the wipe. A macro, so
// that at 3 not even a borrow of the array is left: an unused one still changed the code of the
// SHA-512 kernels on Apple targets.
macro_rules! wipe_unless_optimized {
    ($values:expr) => {
        #[cfg(not(crypto_pq_optimized))]
        $crate::wipe::wipe($values);
    };
}

pub(crate) use wipe_unless_optimized;

// An array of secret register values, built by a closure over the indices listed: at opt-level 3
// by core::array::from_fn, the code that was measured; below it as an array expression with the
// closure's body written out for each index, which builds the array where it lives, so that
// wipe_unless_optimized reaches it, while from_fn builds it in a temporary of its own and a call
// of the closure that is not inlined returns a vector through one (D-76). Each form at its level
// only, so that the code at 3 is the same as without the macro.
#[cfg(crypto_pq_optimized)]
#[allow(unused_macros)]
macro_rules! registers {
    (|$x:ident| $body:expr; $($i:literal)+) => {
        core::array::from_fn(|$x| $body)
    };
}

#[cfg(not(crypto_pq_optimized))]
#[allow(unused_macros)]
macro_rules! registers {
    (|$x:ident| $body:expr; $($i:literal)+) => {
        [$({
            let $x: usize = $i;

            $body
        }),+]
    };
}

#[allow(unused_imports)]
pub(crate) use registers;

// The values of an array of secret register values, for a loop: at opt-level 3 its into_iter(),
// with the array in registers; below it an iterator over a reference, as an iterator that owns
// the array is a copy of it in memory, which no wipe reaches, while the array itself is wiped
// (D-76).
#[cfg(crypto_pq_optimized)]
#[allow(unused_macros)]
macro_rules! values {
    ($array:expr) => {
        $array.into_iter()
    };
}

#[cfg(not(crypto_pq_optimized))]
#[allow(unused_macros)]
macro_rules! values {
    ($array:expr) => {
        $array.iter().copied()
    };
}

#[allow(unused_imports)]
pub(crate) use values;

/// Secret bytes on the heap, wiped when dropped: the type of every secret output, such as shared
/// secrets, derived keys and exported private keys.
///
/// It dereferences to `[u8]` and prints as redacted. It implements neither `Clone`, so that every
/// copy is one the caller makes, nor `PartialEq`. Copies that the compiler makes in registers or on
/// the stack cannot be wiped, and copies that the caller makes are the caller's to wipe.
///
/// # Comparing secrets
///
/// The crate offers no constant-time equality, and `==` on the bytes is not constant time, so
/// never compare secrets with it. To check that two parties hold the same secret, use each copy
/// as a MAC key over the same data and verify the tag from one with the other (key
/// confirmation): MAC verification, such as `HMAC_SHA_256.verify`, compares in constant time.
// The buffer never grows after creation, so no reallocation leaves an unwiped copy behind.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub(crate) fn zeroed(length: usize) -> Self {
        Self(vec![0; length])
    }

    pub(crate) fn concat(parts: &[&[u8]]) -> Self {
        let mut bytes = Vec::with_capacity(parts.iter().map(|part| part.len()).sum());

        for part in parts {
            bytes.extend_from_slice(part);
        }

        Self(bytes)
    }

    pub(crate) const fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({} bytes, redacted)", self.0.len())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every length around the grouping of each path, for elements of one to sixteen bytes.
    #[test]
    fn wipes_every_element() {
        for length in [0, 1, 7, 8, 9, 15, 16, 17, 24, 33, 100] {
            let mut bytes = vec![0xA5u8; length];

            wipe(&mut bytes);

            assert!(bytes.iter().all(|&b| b == 0));

            let mut words = vec![u64::MAX; length];

            wipe(&mut words);

            assert!(words.iter().all(|&w| w == 0));

            let mut wide = vec![u128::MAX; length];

            wipe(&mut wide);

            assert!(wide.iter().all(|&w| w == 0));
        }
    }

    #[test]
    fn secret_bytes() {
        let secret = SecretBytes::concat(&[b"abc", b"", b"de"]);

        assert_eq!(&*secret, b"abcde");

        assert_eq!(secret.as_ref(), b"abcde");

        assert_eq!(
            alloc::format!("{secret:?}"),
            "SecretBytes(5 bytes, redacted)"
        );

        assert_eq!(&*SecretBytes::zeroed(3), &[0; 3]);
    }
}
