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
