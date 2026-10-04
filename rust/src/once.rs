// The lazy caches of the ML-KEM and ML-DSA keys. A key that is imported but never used should cost
// no more than its bytes, so its expanded forms are computed on first use and kept.
//
// OnceBox is the whole mechanism: one atomic pointer, set once by compare_exchange. A caller that
// loses the race frees the value it computed and reads the winner's, so nothing ever waits or
// blocks and the worst case is a value computed twice. A value is freed only when its OnceBox is
// dropped, and its own Drop runs first, which wipes the secret caches. All of this crate's unsafe
// code for the caches is in this module.
//
// A target without pointer-width compare_exchange has no lock-free way to fill a value through a
// shared reference, and a lock would need the same instruction. There the value is computed when
// the OnceBox is made, as before the caches were lazy, and Shared copies instead of sharing,
// because Arc does not exist either.

#[cfg(target_has_atomic = "ptr")]
pub(crate) type Shared<T> = alloc::sync::Arc<T>;

#[cfg(not(target_has_atomic = "ptr"))]
pub(crate) type Shared<T> = alloc::boxed::Box<T>;

#[cfg(target_has_atomic = "ptr")]
pub(crate) use lazy::OnceBox;

#[cfg(not(target_has_atomic = "ptr"))]
pub(crate) use eager::OnceBox;

#[cfg(target_has_atomic = "ptr")]
#[allow(unsafe_code)]
mod lazy {
    use alloc::boxed::Box;
    use core::marker::PhantomData;
    use core::ptr;
    use core::sync::atomic::{AtomicPtr, Ordering};

    // The pointer is null or comes from Box::into_raw, and the OnceBox owns that box: it is
    // published once and freed only by drop. The marker makes OnceBox neither Send nor Sync by
    // itself; the impls below state what owning a T requires.
    pub(crate) struct OnceBox<T> {
        pointer: AtomicPtr<T>,
        owner: PhantomData<*mut T>,
    }

    // SAFETY: a OnceBox owns its T, so moving it to another thread moves the T.
    unsafe impl<T: Send> Send for OnceBox<T> {}

    // SAFETY: a shared OnceBox gives every thread a &T, so T must be Sync, and a T made by one
    // thread in get_or_init is dropped by whichever thread drops the OnceBox, so T must be Send.
    unsafe impl<T: Send + Sync> Sync for OnceBox<T> {}

    impl<T> OnceBox<T> {
        // Empty: get_or_init computes the value on first use, so `init` does not run here.
        pub(crate) fn new(_: impl FnOnce() -> T) -> Self {
            Self {
                pointer: AtomicPtr::new(ptr::null_mut()),
                owner: PhantomData,
            }
        }

        pub(crate) fn get(&self) -> Option<&T> {
            let pointer = self.pointer.load(Ordering::Acquire);

            // SAFETY: a non-null pointer is a box this OnceBox owns, and the acquire load
            // synchronizes with the release that published it, so the value is fully written.
            // Only drop frees it, and drop needs exclusive access, so it outlives &self.
            unsafe { pointer.as_ref() }
        }

        pub(crate) fn get_or_init(&self, init: impl FnOnce() -> T) -> &T {
            if let Some(value) = self.get() {
                return value;
            }

            let new = Box::into_raw(Box::new(init()));

            match self.pointer.compare_exchange(
                ptr::null_mut(),
                new,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                // SAFETY: the release half published `new`, which this OnceBox now owns and
                // frees only in drop, as in get.
                Ok(_) => unsafe { &*new },
                Err(existing) => {
                    // SAFETY: `new` came from Box::into_raw above and was never published, so
                    // this is its only owner; its Drop wipes it if it is secret.
                    drop(unsafe { Box::from_raw(new) });

                    // SAFETY: another call published `existing` with release ordering, which the
                    // acquire on failure synchronizes with; it lives as long as self, as in get.
                    unsafe { &*existing }
                }
            }
        }
    }

    impl<T> Drop for OnceBox<T> {
        fn drop(&mut self) {
            let pointer = *self.pointer.get_mut();

            if !pointer.is_null() {
                // SAFETY: drop has exclusive access, and a non-null pointer is a box this
                // OnceBox owns. The value's own Drop runs before the memory is freed.
                drop(unsafe { Box::from_raw(pointer) });
            }
        }
    }

    // A copy with its own box, filled if this one is.
    impl<T: Clone> Clone for OnceBox<T> {
        fn clone(&self) -> Self {
            let pointer = self.get().map_or(ptr::null_mut(), |value| {
                Box::into_raw(Box::new(value.clone()))
            });

            Self {
                pointer: AtomicPtr::new(pointer),
                owner: PhantomData,
            }
        }
    }
}

#[cfg(any(test, not(target_has_atomic = "ptr")))]
mod eager {
    use alloc::boxed::Box;

    #[derive(Clone)]
    pub(crate) struct OnceBox<T>(Box<T>);

    impl<T> OnceBox<T> {
        pub(crate) fn new(init: impl FnOnce() -> T) -> Self {
            Self(Box::new(init()))
        }

        #[cfg(test)]
        pub(crate) fn get(&self) -> Option<&T> {
            Some(&self.0)
        }

        pub(crate) fn get_or_init(&self, _: impl FnOnce() -> T) -> &T {
            &self.0
        }
    }
}

#[cfg(all(test, target_has_atomic = "ptr"))]
mod tests {
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;

    use super::{eager, lazy};

    // Counts the values dropped, so that a lost race that leaks or frees twice shows.
    struct Counted<'a> {
        thread: usize,
        drops: &'a AtomicUsize,
    }

    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn computes_on_first_use_and_keeps_the_value() {
        let calls = AtomicUsize::new(0);

        let compute = || {
            calls.fetch_add(1, Ordering::SeqCst);

            [7u8; 64]
        };

        let cell = lazy::OnceBox::new(compute);

        assert!(cell.get().is_none());

        assert!(cell.clone().get().is_none());

        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let first: *const [u8; 64] = cell.get_or_init(compute);

        let second: *const [u8; 64] = cell.get_or_init(compute);

        assert_eq!(first, second);

        assert_eq!(cell.get(), Some(&[7; 64]));

        assert_eq!(cell.clone().get(), Some(&[7; 64]));

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_fallback_computes_when_made() {
        let calls = AtomicUsize::new(0);

        let compute = || {
            calls.fetch_add(1, Ordering::SeqCst);

            3u16
        };

        let cell = eager::OnceBox::new(compute);

        assert_eq!(calls.load(Ordering::SeqCst), 1);

        assert_eq!(*cell.get_or_init(compute), 3);

        assert_eq!(cell.clone().get(), Some(&3));

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_panicking_first_use_leaves_it_empty() {
        let cell = lazy::OnceBox::new(|| 1u32);

        let result = std::panic::catch_unwind(|| *cell.get_or_init(|| panic!("no value")));

        assert!(result.is_err());

        assert!(cell.get().is_none());

        assert_eq!(*cell.get_or_init(|| 2), 2);
    }

    #[test]
    fn values_are_dropped_with_the_box() {
        let drops = AtomicUsize::new(0);

        let cell = lazy::OnceBox::new(|| unreachable!());

        cell.get_or_init(|| Counted {
            thread: 0,
            drops: &drops,
        });

        let empty = lazy::OnceBox::new(|| Counted {
            thread: 1,
            drops: &drops,
        });

        drop(empty);

        assert_eq!(drops.load(Ordering::SeqCst), 0);

        drop(cell);

        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    // The threads ask for the value at the same moment. They must all get the same one, and
    // every value computed by a losing thread must be dropped exactly once.
    #[test]
    fn concurrent_first_use_agrees_and_frees_the_losers() {
        let threads = 8;

        for _ in 0..50 {
            let made = AtomicUsize::new(0);

            let drops = AtomicUsize::new(0);

            let barrier = Barrier::new(threads);

            let cell = lazy::OnceBox::new(|| unreachable!());

            let seen: Vec<(usize, usize)> = std::thread::scope(|scope| {
                let workers: Vec<_> = (0..threads)
                    .map(|thread| {
                        let (cell, made, drops, barrier) = (&cell, &made, &drops, &barrier);

                        scope.spawn(move || {
                            barrier.wait();

                            let value = cell.get_or_init(|| {
                                made.fetch_add(1, Ordering::SeqCst);

                                Counted { thread, drops }
                            });

                            (core::ptr::from_ref(value).addr(), value.thread)
                        })
                    })
                    .collect();

                workers
                    .into_iter()
                    .map(|worker| worker.join().unwrap())
                    .collect()
            });

            assert!(seen.iter().all(|&value| value == seen[0]));

            let made = made.load(Ordering::SeqCst);

            assert!((1..=threads).contains(&made));

            assert_eq!(drops.load(Ordering::SeqCst), made - 1);

            drop(cell);

            assert_eq!(drops.load(Ordering::SeqCst), made);
        }
    }
}
