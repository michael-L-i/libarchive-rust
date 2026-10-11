//! The libc calls the front-ends make that std has no wrapper for. This is
//! the only `unsafe` code in the front-ends; every function here is safe
//! to call.

use std::ffi::{CStr, c_int};

/// `strerror(code)`: the system's message for an errno value.
pub fn strerror(code: c_int) -> Vec<u8> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is writable for its length, and strerror_r writes a
    // NUL-terminated message (truncated if need be) into it. An unknown
    // code still gets one ("Unknown error: 99").
    unsafe { libc::strerror_r(code, buf.as_mut_ptr().cast(), buf.len()) };
    CStr::from_bytes_until_nul(&buf).map_or_else(|_| buf.to_vec(), |m| m.to_bytes().to_vec())
}

/// The file mode creation mask. `umask(2)` reads it only by replacing it,
/// so it is set to 0 and back.
pub fn umask() -> libc::mode_t {
    // SAFETY: umask has no memory-safety requirements.
    unsafe {
        let mask = libc::umask(0);
        libc::umask(mask);
        mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strerror_is_the_bare_message() {
        assert_eq!(strerror(libc::ENOENT), b"No such file or directory");
        assert!(strerror(99999).starts_with(b"Unknown error"));
    }
}
