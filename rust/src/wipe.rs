use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{Ordering, compiler_fence};

// Secrets are overwritten with zeros that the compiler must keep, even when the memory is never
// read again. The zeros are written with ordinary stores, as wide as the target has, and then the
// buffer's address goes into an empty assembly block, which for all the compiler knows reads the
// buffer, so no store can be dropped as dead. (Volatile stores of whole arrays were each built in
// a temporary first and copied, a store-to-load dependency per sixteen bytes.) Up to eight values
// of at most a word get a volatile store each instead: an address given to the assembly pins a
// variable to memory for its whole life, and the X25519 ladder's, kept there, made X-Wing 2.5%
// slower.
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "riscv32",
    target_arch = "riscv64",
    target_arch = "loongarch64",
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

// Targets without stable inline assembly in Rust: volatile writes, which survive dead-store
// elimination, in groups of sixteen and then eight values.
#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "riscv32",
    target_arch = "riscv64",
    target_arch = "loongarch64",
)))]
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

// Secret bytes on the heap, wiped when dropped. The buffer never grows after creation, so no
// reallocation leaves an unwiped copy behind.
pub(crate) struct SecretBytes(Vec<u8>);

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

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}
