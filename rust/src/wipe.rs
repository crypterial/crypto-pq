use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{Ordering, compiler_fence};

// Volatile writes survive dead-store elimination, so secrets are gone even when the memory is
// never read again.
#[allow(unsafe_code)]
pub(crate) fn wipe<T: Copy + Default>(values: &mut [T]) {
    for value in values.iter_mut() {
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
