//! Safe wrappers over the platform's locale, multibyte and `iconv` functions.
//!
//! `archive_string` converts text with the same libc entry points upstream
//! uses, so results match the C library on each platform. All `unsafe` for
//! that lives here.
//!
//! On macOS `iconv` lives in libiconv, hence the `link` attribute. glibc
//! provides it in libc and needs nothing extra.

use libc::{c_char, c_int, c_void, size_t, wchar_t};
use std::ffi::{CStr, CString};

/// Large and aligned enough for any platform's `mbstate_t` (macOS: 128
/// bytes, glibc: 8). The all-zero value is the initial conversion state.
#[repr(C, align(8))]
struct MbState([u8; 128]);

impl MbState {
    fn new() -> MbState {
        MbState([0; 128])
    }
}

type IconvT = *mut c_void;

#[cfg_attr(target_vendor = "apple", link(name = "iconv"))]
unsafe extern "C" {
    fn iconv_open(tocode: *const c_char, fromcode: *const c_char) -> IconvT;
    fn iconv(
        cd: IconvT,
        inbuf: *mut *mut c_char,
        inbytesleft: *mut size_t,
        outbuf: *mut *mut c_char,
        outbytesleft: *mut size_t,
    ) -> size_t;
    fn iconv_close(cd: IconvT) -> c_int;
}

unsafe extern "C" {
    fn mbrtowc(pwc: *mut wchar_t, s: *const c_char, n: size_t, ps: *mut MbState) -> size_t;
    fn wcrtomb(s: *mut c_char, wc: wchar_t, ps: *mut MbState) -> size_t;
}

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// The character set name of the current locale (`nl_langinfo(CODESET)`).
pub fn locale_codeset() -> Vec<u8> {
    // SAFETY: nl_langinfo returns a NUL-terminated string valid until the
    // next setlocale/nl_langinfo call; it is copied immediately.
    unsafe {
        let p = libc::nl_langinfo(libc::CODESET);
        if p.is_null() {
            Vec::new()
        } else {
            CStr::from_ptr(p).to_bytes().to_vec()
        }
    }
}

/// `setlocale(LC_ALL, name)`; false if the locale is unavailable.
#[cfg(test)]
pub fn set_locale_all(name: &str) -> bool {
    let Ok(name) = CString::new(name) else {
        return false;
    };
    // SAFETY: `name` is a valid NUL-terminated string.
    !unsafe { libc::setlocale(libc::LC_ALL, name.as_ptr()) }.is_null()
}

/// Appends the current-locale multibyte string `mbs` to `out` as wide
/// characters, stopping at the first NUL. Returns false if it holds an
/// invalid or truncated sequence; what was converted before it stays in `out`.
pub fn mb_to_wide(mbs: &[u8], out: &mut Vec<wchar_t>) -> bool {
    let mut state = MbState::new();
    let mut rest = mbs;
    while let Some(&first) = rest.first() {
        if first == 0 {
            break;
        }
        let mut wc: wchar_t = 0;
        // SAFETY: `rest` is valid for `rest.len()` bytes, `wc` and `state`
        // are valid for writes.
        let r = unsafe { mbrtowc(&mut wc, rest.as_ptr().cast(), rest.len(), &mut state) };
        if r == size_t::MAX || r == size_t::MAX - 1 {
            return false;
        }
        if r == 0 || r > rest.len() {
            break;
        }
        out.push(wc);
        rest = &rest[r..];
    }
    true
}

/// Encodes wide characters into the current locale's multibyte encoding,
/// keeping the shift state between calls.
pub struct WideEncoder(MbState);

impl WideEncoder {
    pub fn new() -> WideEncoder {
        WideEncoder(MbState::new())
    }

    /// Appends the encoding of `wc` to `out`. On failure returns `errno`.
    pub fn encode(&mut self, wc: wchar_t, out: &mut Vec<u8>) -> Result<(), c_int> {
        let mut buf = [0u8; 32];
        // SAFETY: `buf` exceeds MB_LEN_MAX on every supported platform.
        let n = unsafe { wcrtomb(buf.as_mut_ptr().cast(), wc, &mut self.0) };
        if n == size_t::MAX {
            return Err(errno());
        }
        out.extend_from_slice(buf.get(..n).unwrap_or(&[]));
        Ok(())
    }
}

/// Appends the wide string `w` (up to the first NUL) to `out` in the current
/// locale's multibyte encoding. A character that cannot be encoded becomes
/// `?` and makes the result false; any other error stops the conversion.
pub fn wide_to_mb(w: &[wchar_t], out: &mut Vec<u8>) -> bool {
    let mut enc = WideEncoder::new();
    let mut ok = true;
    for &wc in w.iter().take_while(|&&wc| wc != 0) {
        match enc.encode(wc, out) {
            Ok(()) => {}
            Err(libc::EILSEQ) => {
                out.push(b'?');
                ok = false;
            }
            Err(_) => return false,
        }
    }
    ok
}

/// An open `iconv` conversion descriptor.
pub struct Iconv(IconvT);

// SAFETY: the descriptor is owned exclusively by this value and is only used
// through `&mut self`.
unsafe impl Send for Iconv {}

/// How one `iconv` call ended.
#[derive(Debug, PartialEq, Eq)]
pub enum IconvStatus {
    /// All input converted.
    Done,
    /// All input converted, but some characters were replaced by
    /// implementation-defined substitutes.
    Irreversible,
    /// Stopped early; carries `errno` (`EILSEQ`, `EINVAL`, `E2BIG`, ...).
    Error(c_int),
}

impl Iconv {
    /// `iconv_open(to, from)`; `None` if the pair is unsupported.
    pub fn open(to: &[u8], from: &[u8]) -> Option<Iconv> {
        let to = CString::new(to).ok()?;
        let from = CString::new(from).ok()?;
        // SAFETY: both arguments are valid NUL-terminated strings.
        let cd = unsafe { iconv_open(to.as_ptr(), from.as_ptr()) };
        if cd as isize == -1 {
            None
        } else {
            Some(Iconv(cd))
        }
    }

    /// Converts from `input` into `out`, advancing `input` past what was
    /// consumed. Returns the status and the number of bytes written to `out`.
    pub fn convert(&mut self, input: &mut &[u8], out: &mut [u8]) -> (IconvStatus, usize) {
        let mut inp = input.as_ptr() as *mut c_char;
        let mut inleft = input.len();
        let mut outp = out.as_mut_ptr().cast::<c_char>();
        let mut outleft = out.len();
        // SAFETY: the pointers and lengths describe `input` and `out`;
        // iconv only reads through `inp` and advances the cursors within
        // those bounds.
        let r = unsafe { iconv(self.0, &mut inp, &mut inleft, &mut outp, &mut outleft) };
        let err = errno();
        *input = input
            .get(input.len().saturating_sub(inleft)..)
            .unwrap_or(&[]);
        let written = out.len().saturating_sub(outleft);
        let status = if r == 0 {
            IconvStatus::Done
        } else if r == size_t::MAX {
            IconvStatus::Error(err)
        } else {
            IconvStatus::Irreversible
        };
        (status, written)
    }
}

impl Drop for Iconv {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful iconv_open and is closed
        // exactly once.
        unsafe { iconv_close(self.0) };
    }
}
