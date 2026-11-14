use crate::ct::secret;
use crate::error::Error;
use crate::wipe::SecretBytes;

// The constant-time check treats random bytes as secret until the library declassifies them.
pub(crate) fn random_bytes(length: usize) -> Result<SecretBytes, Error> {
    let mut bytes = SecretBytes::zeroed(length);

    fill(&mut bytes)?;

    secret(&bytes);

    Ok(bytes)
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "illumos",
    target_os = "solaris",
))]
#[allow(unsafe_code)]
fn fill(mut out: &mut [u8]) -> Result<(), Error> {
    unsafe extern "C" {
        fn getrandom(buffer: *mut u8, length: usize, flags: u32) -> isize;

        #[cfg_attr(
            any(target_os = "linux", target_os = "dragonfly"),
            link_name = "__errno_location"
        )]
        #[cfg_attr(
            any(target_os = "android", target_os = "netbsd"),
            link_name = "__errno"
        )]
        #[cfg_attr(target_os = "freebsd", link_name = "__error")]
        #[cfg_attr(
            any(target_os = "illumos", target_os = "solaris"),
            link_name = "___errno"
        )]
        fn errno_location() -> *mut i32;
    }

    const EINTR: i32 = 4;

    while !out.is_empty() {
        // SAFETY: the pointer and length describe the writable slice `out`.
        let written = unsafe { getrandom(out.as_mut_ptr(), out.len(), 0) };

        match usize::try_from(written) {
            Ok(count) if count > 0 && count <= out.len() => out = &mut out[count..],
            // SAFETY: errno_location returns the address of this thread's errno.
            Err(_) if unsafe { *errno_location() } == EINTR => {}
            _ => return Err(Error::RngFailure),
        }
    }

    Ok(())
}

#[cfg(any(target_vendor = "apple", target_os = "openbsd"))]
#[allow(unsafe_code)]
fn fill(out: &mut [u8]) -> Result<(), Error> {
    unsafe extern "C" {
        fn getentropy(buffer: *mut u8, length: usize) -> i32;
    }

    // getentropy refuses requests above 256 bytes.
    for chunk in out.chunks_mut(256) {
        // SAFETY: the pointer and length describe the writable slice `chunk`.
        if unsafe { getentropy(chunk.as_mut_ptr(), chunk.len()) } != 0 {
            return Err(Error::RngFailure);
        }
    }

    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn fill(out: &mut [u8]) -> Result<(), Error> {
    #[link(name = "bcryptprimitives", kind = "raw-dylib")]
    unsafe extern "system" {
        fn ProcessPrng(buffer: *mut u8, length: usize) -> i32;
    }

    // SAFETY: the pointer and length describe the writable slice `out`.
    if unsafe { ProcessPrng(out.as_mut_ptr(), out.len()) } == 0 {
        return Err(Error::RngFailure);
    }

    Ok(())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "illumos",
    target_os = "solaris",
    target_vendor = "apple",
    target_os = "openbsd",
    windows,
)))]
fn fill(_: &mut [u8]) -> Result<(), Error> {
    Err(Error::RngFailure)
}

#[cfg(test)]
mod tests {
    use super::random_bytes;

    #[test]
    fn fills_distinct_buffers() {
        let first = random_bytes(1000).expect("random bytes");

        let second = random_bytes(1000).expect("random bytes");

        assert_eq!(first.len(), 1000);

        assert_ne!(&first[..], &second[..]);

        assert!(random_bytes(0).expect("empty request").is_empty());
    }
}
