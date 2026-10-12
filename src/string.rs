/*-
 * Copyright (c) 2003-2011 Tim Kientzle
 * Copyright (c) 2011-2012 Michihiro NAKAJIMA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Ported from libarchive/archive_string.c and archive_string_sprintf.c.
//
// Not ported: the `archive_string`/`archive_wstring` buffer ceremony
// (`Vec<u8>` and `Vec<wchar_t>` here), `archive_string_sprintf` (callers use
// `format!`), the Windows code-page paths, and the libarchive-2.x UTF-8
// compatibility converter (its option is a no-op wherever `wchar_t` is
// Unicode: macOS and glibc; musl is not supported for this).

use crate::ffi::charset::{self, Iconv, IconvStatus};
use crate::string_composition::{
    CCC_INDEX, CCC_VAL, CCC_VAL_INDEX, U_COMPOSITION_TABLE, U_DECOMPOSABLE_BLOCKS,
    U_DECOMPOSITION_TABLE,
};
use libc::wchar_t;
use std::ffi::CStr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// `ARCHIVE_ERRNO_MISC`.
pub(crate) const ARCHIVE_ERRNO_MISC: i32 = -1;

const SCONV_TO_CHARSET: u32 = 1; // MBS is being converted to specified charset.
const SCONV_FROM_CHARSET: u32 = 1 << 1; // MBS is being converted from specified charset.
const SCONV_BEST_EFFORT: u32 = 1 << 2; // Copy at least ASCII code.
const SCONV_NORMALIZATION_C: u32 = 1 << 6; // Need normalization to be Form C.
const SCONV_NORMALIZATION_D: u32 = 1 << 7; // Need normalization to be Form D (Mac OS X).
const SCONV_TO_UTF8: u32 = 1 << 8;
const SCONV_FROM_UTF8: u32 = 1 << 9;
const SCONV_TO_UTF16BE: u32 = 1 << 10;
const SCONV_FROM_UTF16BE: u32 = 1 << 11;
const SCONV_TO_UTF16LE: u32 = 1 << 12;
const SCONV_FROM_UTF16LE: u32 = 1 << 13;
const SCONV_TO_UTF16: u32 = SCONV_TO_UTF16BE | SCONV_TO_UTF16LE;
const SCONV_FROM_UTF16: u32 = SCONV_FROM_UTF16BE | SCONV_FROM_UTF16LE;

#[allow(dead_code)] // for `set_opt`'s callers, the tar reader (phase 4)
pub(crate) const SCONV_SET_OPT_UTF8_LIBARCHIVE2X: i32 = 1;
#[allow(dead_code)] // for `set_opt`'s callers, the tar reader (phase 4)
pub(crate) const SCONV_SET_OPT_NORMALIZATION_C: i32 = 2;
#[allow(dead_code)] // for `set_opt`'s callers, the tar reader (phase 4)
pub(crate) const SCONV_SET_OPT_NORMALIZATION_D: i32 = 4;

const UNICODE_MAX: u32 = 0x10FFFF;
const UNICODE_R_CHAR: u32 = 0xFFFD; // Replacement character.
/// U+FFFD in UTF-8.
const UTF8_REPLACEMENT_CHAR: [u8; 3] = [0xef, 0xbf, 0xbd];

fn is_high_surrogate(uc: u32) -> bool {
    (0xD800..=0xDBFF).contains(&uc)
}

fn is_low_surrogate(uc: u32) -> bool {
    (0xDC00..=0xDFFF).contains(&uc)
}

fn is_surrogate_pair(uc: u32) -> bool {
    (0xD800..=0xDFFF).contains(&uc)
}

/// A conversion failed, in whole or in part. Whatever was converted is still
/// in the output buffer (upstream's `-1` with partial output).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConvFailed;

/// What upstream passes to `archive_set_error(a, errno, "%s", message)` when
/// it cannot create a conversion. The caller owns the archive handle and
/// makes that call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConvError {
    pub errno: i32,
    pub message: Vec<u8>,
}

/// Like `strlen(p)` bounded by the slice: the part before the first NUL.
pub(crate) fn until_nul(s: &[u8]) -> &[u8] {
    s.split(|&b| b == 0).next().unwrap_or(&[])
}

/// Byte length of the UTF-16 string at the start of `s`, which ends at the
/// first all-zero code unit or the last whole unit.
fn utf16nbytes(s: &[u8]) -> usize {
    s.chunks_exact(2)
        .take_while(|c| c.iter().any(|&b| b != 0))
        .count()
        * 2
}

fn skip(s: &[u8], n: i32) -> &[u8] {
    s.get(n.unsigned_abs() as usize..).unwrap_or(&[])
}

/// Equivalent to dirname(3).
#[allow(dead_code)] // used by the mtree reader (phase 3) and the disk code (phase 5)
pub(crate) fn string_dirname(s: &mut Vec<u8>) {
    // strip trailing separators
    while s.len() > 1 && s.last() == Some(&b'/') {
        s.pop();
    }
    // strip final component
    while s.last().is_some_and(|&c| c != b'/') {
        s.pop();
    }
    // empty path -> cwd
    if s.is_empty() {
        s.push(b'.');
        return;
    }
    // strip separator(s)
    while s.len() > 1 && s.last() == Some(&b'/') {
        s.pop();
    }
}

/*
 * Unicode conversion functions.
 *   - UTF-8 <===> UTF-8 in removing surrogate pairs.
 *   - UTF-8 NFD ===> UTF-8 NFC in removing surrogate pairs.
 *   - UTF-16BE <===> UTF-8.
 *
 * The parsers return `(n, uc)`: usually the used bytes, or the used bytes
 * negated when a Unicode character was replaced with U+FFFD, or 0 at the end
 * of the string.
 */

fn utf8_sequence_len(ch: u32) -> usize {
    match ch {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    }
}

/// Utility to convert a single UTF-8 sequence.
///
/// See also http://unicode.org/review/pr-121.html Public Review Issue #121
/// Recommended Practice for Replacement Characters.
fn utf8_to_unicode_raw(s: &[u8]) -> (i32, u32) {
    let n = s.len();
    let b = |i: usize| u32::from(s.get(i).copied().unwrap_or(0));
    let cont = |i: usize| b(i) & 0xc0 == 0x80;
    let invalid = |cnt: usize| (-(cnt as i32), UNICODE_R_CHAR);
    // Trim a (possibly overlong) invalid sequence to the bytes that belong
    // to it.
    let truncate = |mut cnt: usize| {
        cnt = cnt.min(n);
        for i in 1..cnt {
            if !cont(i) {
                return i;
            }
        }
        cnt
    };

    if n == 0 {
        return (0, 0);
    }
    let ch = b(0);
    if ch == 0 {
        return (0, 0); // Standard: return 0 for end-of-string.
    }
    let cnt = utf8_sequence_len(ch);

    // Invalid sequence or there are not plenty bytes.
    if n < cnt {
        return invalid(truncate(n));
    }

    let wc = match cnt {
        1 => return (1, ch & 0x7f),
        2 => {
            if !cont(1) {
                return invalid(1);
            }
            return (2, ((ch & 0x1f) << 6) | (b(1) & 0x3f));
        }
        3 => {
            if !cont(1) {
                return invalid(1);
            }
            if !cont(2) {
                return invalid(2);
            }
            let wc = ((ch & 0x0f) << 12) | ((b(1) & 0x3f) << 6) | (b(2) & 0x3f);
            if wc < 0x800 {
                return invalid(3); // Overlong sequence.
            }
            wc
        }
        4 => {
            if !cont(1) {
                return invalid(1);
            }
            if !cont(2) {
                return invalid(2);
            }
            if !cont(3) {
                return invalid(3);
            }
            let wc =
                ((ch & 0x07) << 18) | ((b(1) & 0x3f) << 12) | ((b(2) & 0x3f) << 6) | (b(3) & 0x3f);
            if wc < 0x10000 {
                return invalid(4); // Overlong sequence.
            }
            wc
        }
        _ => {
            // Others are all invalid sequence.
            let cnt = match ch {
                0xc0 | 0xc1 => 2,
                0xf5..=0xf7 => 4,
                0xf8..=0xfb => 5,
                0xfc | 0xfd => 6,
                _ => 1,
            };
            return invalid(truncate(cnt));
        }
    };

    // The code point larger than 0x10FFFF is not legal Unicode values.
    if wc > UNICODE_MAX {
        return invalid(cnt);
    }
    (cnt as i32, wc)
}

fn utf8_to_unicode(s: &[u8]) -> (i32, u32) {
    let (cnt, uc) = utf8_to_unicode_raw(s);
    // Any of Surrogate pair is not legal Unicode values.
    if cnt == 3 && is_surrogate_pair(uc) {
        return (-3, uc);
    }
    (cnt, uc)
}

fn combine_surrogate_pair(uc: u32, uc2: u32) -> u32 {
    (uc.wrapping_sub(0xD800))
        .wrapping_mul(0x400)
        .wrapping_add(uc2.wrapping_sub(0xDC00))
        .wrapping_add(0x10000)
}

/// Convert a single UTF-8/CESU-8 sequence to a Unicode code point in
/// removing surrogate pairs.
///
/// CESU-8: The Compatibility Encoding Scheme for UTF-16.
fn cesu8_to_unicode(s: &[u8]) -> (i32, u32) {
    let (cnt, wc) = utf8_to_unicode_raw(s);
    if cnt == 3 && is_high_surrogate(wc) {
        let invalid = |cnt: i32| (if cnt > 0 { -cnt } else { cnt }, UNICODE_R_CHAR);
        if s.len() < 6 {
            return invalid(cnt);
        }
        let (cnt2, wc2) = utf8_to_unicode_raw(skip(s, 3));
        if cnt2 != 3 || !is_low_surrogate(wc2) {
            // Upstream reports the length of the second sequence here.
            return invalid(cnt2);
        }
        return (6, combine_surrogate_pair(wc, wc2));
    }
    if cnt == 3 && is_low_surrogate(wc) {
        return (-cnt, UNICODE_R_CHAR);
    }
    (cnt, wc)
}

fn utf16_to_unicode(s: &[u8], be: bool) -> (i32, u32) {
    let n = s.len();
    if n == 0 {
        return (0, 0);
    }
    if n == 1 {
        return (-1, UNICODE_R_CHAR);
    }
    let unit = |i: usize| -> u32 {
        let pair = [
            s.get(i).copied().unwrap_or(0),
            s.get(i + 1).copied().unwrap_or(0),
        ];
        u32::from(if be {
            u16::from_be_bytes(pair)
        } else {
            u16::from_le_bytes(pair)
        })
    };

    let mut uc = unit(0);
    let mut used = 2;

    // If this is a surrogate pair, assemble the full code point.
    if is_high_surrogate(uc) {
        let uc2 = if n >= 4 { unit(2) } else { 0 };
        if is_low_surrogate(uc2) {
            uc = combine_surrogate_pair(uc, uc2);
            used = 4;
        } else {
            // Undescribed code point should be U+FFFD (replacement character).
            return (-2, UNICODE_R_CHAR);
        }
    }

    // Surrogate pair values(0xd800 through 0xdfff) are only used by UTF-16,
    // so, after above calculation, the code must not be surrogate values,
    // and Unicode has no codes larger than 0x10ffff. Thus, those are not
    // legal Unicode values.
    if is_surrogate_pair(uc) || uc > UNICODE_MAX {
        return (-used, UNICODE_R_CHAR);
    }
    (used, uc)
}

/// The character encodings the Unicode converters read and write.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Enc {
    Utf8,
    Utf16Be,
    Utf16Le,
}

impl Enc {
    /// What the converter reads: UTF-16 as flagged, else UTF-8/CESU-8.
    fn input(flag: u32) -> Enc {
        if flag & SCONV_FROM_UTF16BE != 0 {
            Enc::Utf16Be
        } else if flag & SCONV_FROM_UTF16LE != 0 {
            Enc::Utf16Le
        } else {
            Enc::Utf8
        }
    }

    /// What the converter writes. When the result goes through iconv next,
    /// that is the encoding of the input.
    fn output(flag: u32) -> Enc {
        if flag & SCONV_TO_UTF16BE != 0 {
            Enc::Utf16Be
        } else if flag & SCONV_TO_UTF16LE != 0 {
            Enc::Utf16Le
        } else if flag & SCONV_TO_UTF8 != 0 {
            Enc::Utf8
        } else {
            Enc::input(flag)
        }
    }

    fn parse(self, s: &[u8]) -> (i32, u32) {
        match self {
            Enc::Utf8 => cesu8_to_unicode(s),
            Enc::Utf16Be => utf16_to_unicode(s, true),
            Enc::Utf16Le => utf16_to_unicode(s, false),
        }
    }

    /// Convert a Unicode code point to a single sequence.
    ///
    /// NOTE: This function does not check if the Unicode is legal or not,
    /// except that code points above U+10FFFF become U+FFFD in UTF-8.
    fn push(self, out: &mut Vec<u8>, mut uc: u32) {
        match self {
            Enc::Utf8 => {
                // Invalid Unicode char maps to Replacement character
                if uc > UNICODE_MAX {
                    uc = UNICODE_R_CHAR;
                }
                if uc <= 0x7f {
                    out.push(uc as u8);
                } else if uc <= 0x7ff {
                    out.push(0xc0 | ((uc >> 6) & 0x1f) as u8);
                    out.push(0x80 | (uc & 0x3f) as u8);
                } else if uc <= 0xffff {
                    out.push(0xe0 | ((uc >> 12) & 0x0f) as u8);
                    out.push(0x80 | ((uc >> 6) & 0x3f) as u8);
                    out.push(0x80 | (uc & 0x3f) as u8);
                } else {
                    out.push(0xf0 | ((uc >> 18) & 0x07) as u8);
                    out.push(0x80 | ((uc >> 12) & 0x3f) as u8);
                    out.push(0x80 | ((uc >> 6) & 0x3f) as u8);
                    out.push(0x80 | (uc & 0x3f) as u8);
                }
            }
            Enc::Utf16Be | Enc::Utf16Le => {
                let be = self == Enc::Utf16Be;
                let mut unit = |u: u32| {
                    let u = u as u16;
                    out.extend_from_slice(&if be { u.to_be_bytes() } else { u.to_le_bytes() });
                };
                if uc > 0xffff {
                    // We have a code point that won't fit into a wchar_t;
                    // convert it to a surrogate pair.
                    uc -= 0x10000;
                    unit(((uc >> 10) & 0x3ff) + 0xD800);
                    unit((uc & 0x3ff) + 0xDC00);
                } else {
                    unit(uc);
                }
            }
        }
    }
}

/// Which conversion step a `StringConv` runs, in order (at most two).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Converter {
    Utf8ToUtf8,
    AppendUnicode,
    NormalizeC,
    NormalizeD,
    Iconv,
    BestEffortFromUtf16Be,
    BestEffortFromUtf16Le,
    BestEffortToUtf16Be,
    BestEffortToUtf16Le,
    BestEffortInLocale,
}

struct State {
    flag: u32,
    converters: Vec<Converter>,
    cd: Option<Iconv>,
}

impl State {
    fn add_converter(&mut self, c: Converter) {
        if self.converters.len() < 2 {
            self.converters.push(c);
        }
    }

    fn setup_converter(&mut self, same: bool) {
        use Converter::*;
        let f = self.flag;
        let has_cd = self.cd.is_some();
        self.converters.clear();

        // Convert a string to UTF-16BE/LE.
        if f & SCONV_TO_UTF16 != 0 {
            // If the current locale is UTF-8, we can translate a UTF-8
            // string into a UTF-16BE string.
            if f & SCONV_FROM_UTF8 != 0 {
                self.add_converter(AppendUnicode);
            } else if has_cd {
                self.add_converter(Iconv);
            } else if f & SCONV_BEST_EFFORT != 0 {
                self.add_converter(if f & SCONV_TO_UTF16BE != 0 {
                    BestEffortToUtf16Be
                } else {
                    BestEffortToUtf16Le
                });
            }
            return;
        }

        // Convert a string from UTF-16BE/LE.
        if f & SCONV_FROM_UTF16 != 0 {
            // At least we should normalize a UTF-16BE string.
            if f & SCONV_NORMALIZATION_D != 0 {
                self.add_converter(NormalizeD);
            } else if f & SCONV_NORMALIZATION_C != 0 {
                self.add_converter(NormalizeC);
            }

            if f & SCONV_TO_UTF8 != 0 {
                // If the current locale is UTF-8, we can translate a
                // UTF-16BE/LE string into a UTF-8 string directly.
                if f & (SCONV_NORMALIZATION_D | SCONV_NORMALIZATION_C) == 0 {
                    self.add_converter(AppendUnicode);
                }
                return;
            }

            if has_cd {
                self.add_converter(Iconv);
            } else if f & SCONV_BEST_EFFORT != 0 && f & SCONV_FROM_UTF16BE != 0 {
                self.add_converter(BestEffortFromUtf16Be);
            } else if f & SCONV_BEST_EFFORT != 0 && f & SCONV_FROM_UTF16LE != 0 {
                self.add_converter(BestEffortFromUtf16Le);
            } else {
                // Make sure we have no converter.
                self.converters.clear();
            }
            return;
        }

        if f & SCONV_FROM_UTF8 != 0 {
            // At least we should normalize a UTF-8 string.
            if f & SCONV_NORMALIZATION_D != 0 {
                self.add_converter(NormalizeD);
            } else if f & SCONV_NORMALIZATION_C != 0 {
                self.add_converter(NormalizeC);
            }

            // Copy UTF-8 string with a check of CESU-8.
            // Apparently, iconv does not check surrogate pairs in UTF-8
            // when both from-charset and to-charset are UTF-8, and then
            // we use our UTF-8 copy code.
            if f & SCONV_TO_UTF8 != 0 {
                if f & (SCONV_NORMALIZATION_D | SCONV_NORMALIZATION_C) == 0 {
                    self.add_converter(Utf8ToUtf8);
                }
                return;
            }
        }

        if has_cd {
            self.add_converter(Iconv);
            // iconv generally does not support UTF-8-MAC and so we have to
            // the output of iconv from NFC to NFD if need.
            if f & SCONV_FROM_CHARSET != 0
                && f & SCONV_TO_UTF8 != 0
                && f & SCONV_NORMALIZATION_D != 0
            {
                self.add_converter(NormalizeD);
            }
            return;
        }

        // Try conversion in the best effort or no conversion.
        if f & SCONV_BEST_EFFORT != 0 || same {
            self.add_converter(BestEffortInLocale);
        } else {
            // Make sure we have no converter.
            self.converters.clear();
        }
    }

    fn run(&mut self, c: Converter, out: &mut Vec<u8>, src: &[u8], same: bool) -> i32 {
        match c {
            Converter::Utf8ToUtf8 => strncat_from_utf8_to_utf8(out, src),
            Converter::AppendUnicode => append_unicode(out, src, self.flag),
            Converter::NormalizeC => normalize_c(out, src, self.flag),
            Converter::NormalizeD => normalize_d(out, src, self.flag),
            Converter::Iconv => self.iconv_strncat_in_locale(out, src),
            Converter::BestEffortFromUtf16Be => best_effort_from_utf16(out, src, true),
            Converter::BestEffortFromUtf16Le => best_effort_from_utf16(out, src, false),
            Converter::BestEffortToUtf16Be => best_effort_to_utf16(out, src, true),
            Converter::BestEffortToUtf16Le => best_effort_to_utf16(out, src, false),
            Converter::BestEffortInLocale => {
                best_effort_strncat_in_locale(out, src, self.flag, same)
            }
        }
    }

    /// Returns -1 if conversion fails.
    fn iconv_strncat_in_locale(&mut self, out: &mut Vec<u8>, src: &[u8]) -> i32 {
        let flag = self.flag;
        let from_size = if flag & SCONV_FROM_UTF16 != 0 { 2 } else { 1 };
        let Some(cd) = self.cd.as_mut() else {
            return -1;
        };
        let mut buf = [0u8; 4096];
        let mut return_value = 0; // success
        let mut input = src;
        while input.len() >= from_size {
            let before = input.len();
            let (status, written) = cd.convert(&mut input, &mut buf);
            out.extend_from_slice(buf.get(..written).unwrap_or(&[]));
            match status {
                IconvStatus::Done => break, // Conversion completed.
                IconvStatus::Irreversible => {
                    // Conversion did not fail, but it performed some
                    // non-identical character substitutions.
                    return_value = -1;
                    break;
                }
                IconvStatus::Error(e) if e == libc::EILSEQ || e == libc::EINVAL => {
                    // If an output charset is UTF-8 or UTF-16BE/LE, unknown
                    // character should be U+FFFD (replacement character).
                    if flag & SCONV_TO_UTF8 != 0 {
                        out.extend_from_slice(&UTF8_REPLACEMENT_CHAR);
                    } else if flag & SCONV_TO_UTF16BE != 0 {
                        Enc::Utf16Be.push(out, UNICODE_R_CHAR);
                    } else if flag & SCONV_TO_UTF16LE != 0 {
                        Enc::Utf16Le.push(out, UNICODE_R_CHAR);
                    } else {
                        // Skip the illegal input bytes.
                        out.push(b'?');
                    }
                    input = input.get(from_size..).unwrap_or(&[]);
                    return_value = -1; // failure
                }
                // E2BIG: no room in the output chunk; flush it and go on.
                // (Upstream retries on any other errno forever; stop.)
                IconvStatus::Error(e)
                    if e == libc::E2BIG && (written > 0 || input.len() < before) => {}
                IconvStatus::Error(_) => return -1,
            }
        }
        return_value
    }
}

/// Convert a UTF-8 string to UTF-8, replacing invalid sequences and
/// canonicalizing surrogate pairs.
///
/// Existing string is assumed to already be in proper form.
fn strncat_from_utf8_to_utf8(out: &mut Vec<u8>, src: &[u8]) -> i32 {
    let mut ret = 0;
    let mut s = src;
    // Invariant: `s` starts at the first UTF-8 byte that hasn't been copied.
    loop {
        // Skip UTF-8 sequences until we reach end-of-string or a code point
        // that needs conversion.
        let mut e = s;
        let (mut n, mut uc);
        loop {
            (n, uc) = utf8_to_unicode(e);
            if n <= 0 {
                break;
            }
            e = skip(e, n);
        }
        // Copy the part that doesn't need conversion
        out.extend_from_slice(s.get(..s.len() - e.len()).unwrap_or(&[]));
        s = e;

        if n == 0 {
            // We reached end-of-string
            return ret;
        }
        // Next code point needs conversion; try decoding a surrogate pair.
        if n == -3 && is_surrogate_pair(uc) {
            (n, uc) = cesu8_to_unicode(s);
        }
        if n == 0 {
            return ret;
        }
        // Not a (valid) surrogate, so use a replacement char
        if n < 0 {
            ret = -1; // Return -1 if we used any replacement
        }
        s = skip(s, n);
        Enc::Utf8.push(out, uc);
    }
}

fn append_unicode(out: &mut Vec<u8>, src: &[u8], flag: u32) -> i32 {
    let (inp, outp) = (Enc::input(flag), Enc::output(flag));
    let mut ret = 0;
    let mut s = src;
    loop {
        let (n, uc) = inp.parse(s);
        if n == 0 {
            return ret;
        }
        if n < 0 {
            // Use a replaced unicode character.
            ret = -1;
        }
        s = skip(s, n);
        outp.push(out, uc);
    }
}

// Following Constants for Hangul compositions this information comes from
// Unicode Standard Annex #15  http://unicode.org/reports/tr15/
const HC_SBASE: i32 = 0xAC00;
const HC_LBASE: i32 = 0x1100;
const HC_VBASE: i32 = 0x1161;
const HC_TBASE: i32 = 0x11A7;
const HC_LCOUNT: i32 = 19;
const HC_VCOUNT: i32 = 21;
const HC_TCOUNT: i32 = 28;
const HC_NCOUNT: i32 = HC_VCOUNT * HC_TCOUNT;
const HC_SCOUNT: i32 = HC_LCOUNT * HC_NCOUNT;

/// The maximum number of Following Decomposable Characters.
const FDC_MAX: usize = 10;

fn get_nfc(uc: u32, uc2: u32) -> u32 {
    let mut t = 0isize;
    let mut b = U_COMPOSITION_TABLE.len() as isize - 1;
    while b >= t {
        let m = (t + b) / 2;
        let Some(&(cp1, cp2, nfc)) = U_COMPOSITION_TABLE.get(m as usize) else {
            return 0;
        };
        if cp1 < uc {
            t = m + 1;
        } else if cp1 > uc {
            b = m - 1;
        } else if cp2 < uc2 {
            t = m + 1;
        } else if cp2 > uc2 {
            b = m - 1;
        } else {
            return nfc;
        }
    }
    0
}

fn get_nfd(uc: u32) -> Option<(u32, u32)> {
    // These are not converted to NFD on Mac OS.
    if (0x2000..=0x2FFF).contains(&uc)
        || (0xF900..=0xFAFF).contains(&uc)
        || (0x2F800..=0x2FAFF).contains(&uc)
    {
        return None;
    }
    // Those code points are not converted to NFD on Mac OS.
    // I do not know the reason because it is undocumented.
    //   NFC        NFD
    //   1109A  ==> 11099 110BA
    //   1109C  ==> 1109B 110BA
    //   110AB  ==> 110A5 110BA
    if uc == 0x1109A || uc == 0x1109C || uc == 0x110AB {
        return None;
    }

    let mut t = 0isize;
    let mut b = U_DECOMPOSITION_TABLE.len() as isize - 1;
    while b >= t {
        let m = (t + b) / 2;
        let &(nfc, cp1, cp2) = U_DECOMPOSITION_TABLE.get(m as usize)?;
        if nfc < uc {
            t = m + 1;
        } else if nfc > uc {
            b = m - 1;
        } else {
            return Some((cp1, cp2));
        }
    }
    None
}

/// Canonical Combining Class.
fn ccc(uc: u32) -> i32 {
    if uc > 0x1D244 {
        return 0;
    }
    let idx = CCC_INDEX.get((uc >> 8) as usize).copied().unwrap_or(0);
    let vi = CCC_VAL_INDEX
        .get(usize::from(idx))
        .and_then(|row| row.get(((uc >> 4) & 0x0F) as usize))
        .copied()
        .unwrap_or(0);
    CCC_VAL
        .get(usize::from(vi))
        .and_then(|row| row.get((uc & 0x0F) as usize))
        .copied()
        .map_or(0, i32::from)
}

fn is_decomposable_block(uc: u32) -> bool {
    U_DECOMPOSABLE_BLOCKS
        .get((uc >> 8) as usize)
        .is_some_and(|&b| b != 0)
}

/// The code points collected after the current one while looking for a
/// composition, with the state `COLLECT_CPS` leaves behind.
struct Collected {
    ucx: [u32; FDC_MAX],
    ccx: [i32; FDC_MAX],
    /// Class of the last collected code point.
    cl: i32,
    /// Class of the code point that stopped the collection.
    cx: i32,
    /// Result of the last parse.
    nx: i32,
}

impl Collected {
    /// Collect following decomposable code points, starting at slot `start`.
    /// Returns how many are held.
    fn collect(&mut self, inp: Enc, s: &mut &[u8], start: usize, ret: &mut i32) -> usize {
        let mut i = start;
        while i < FDC_MAX {
            let (nx, uc) = inp.parse(s);
            self.nx = nx;
            if let Some(slot) = self.ucx.get_mut(i) {
                *slot = uc;
            }
            if nx <= 0 {
                break;
            }
            self.cx = ccc(uc);
            if self.cl >= self.cx && self.cl != 228 && self.cx != 228 {
                break;
            }
            *s = skip(s, nx);
            self.cl = self.cx;
            if let Some(slot) = self.ccx.get_mut(i) {
                *slot = self.cx;
            }
            i += 1;
        }
        if i >= FDC_MAX {
            *ret = -1;
            FDC_MAX
        } else {
            i
        }
    }
}

/// Normalize UTF-8/UTF-16BE characters to Form C and copy the result.
///
/// TODO: Convert composition exclusions, which are never converted from
/// NFC,NFD,NFKC and NFKD, to Form C.
fn normalize_c(out: &mut Vec<u8>, src: &[u8], flag: u32) -> i32 {
    let (inp, outp) = (Enc::input(flag), Enc::output(flag));
    let mut s = src;
    let mut ret = 0;

    loop {
        let (n, mut uc) = inp.parse(s);
        if n == 0 {
            break;
        }
        if n < 0 {
            // Use a replaced unicode character.
            outp.push(out, uc);
            s = skip(s, n);
            ret = -1;
            continue;
        }
        s = skip(s, n);

        // Read second code point.
        let (mut n2, mut uc2);
        loop {
            (n2, uc2) = inp.parse(s);
            if n2 <= 0 {
                break;
            }
            s = skip(s, n2);

            // If current second code point is out of decomposable code
            // points, finding compositions is unneeded.
            if !is_decomposable_block(uc2) {
                outp.push(out, uc);
                uc = uc2;
                continue;
            }

            // Try to combine current code points.
            // We have to combine Hangul characters according to
            // http://uniicode.org/reports/tr15/#Hangul
            let l_index = uc.wrapping_sub(HC_LBASE as u32) as i32;
            let s_index = uc.wrapping_sub(HC_SBASE as u32) as i32;
            if (0..HC_LCOUNT).contains(&l_index) {
                // Hangul Composition.
                // 1. Two current code points are L and V.
                let v_index = uc2.wrapping_sub(HC_VBASE as u32) as i32;
                if (0..HC_VCOUNT).contains(&v_index) {
                    // Make syllable of form LV.
                    uc = (HC_SBASE + (l_index * HC_VCOUNT + v_index) * HC_TCOUNT) as u32;
                } else {
                    outp.push(out, uc);
                    uc = uc2;
                }
                continue;
            } else if (0..HC_SCOUNT).contains(&s_index) && s_index % HC_TCOUNT == 0 {
                // Hangul Composition.
                // 2. Two current code points are LV and T.
                let t_index = uc2.wrapping_sub(HC_TBASE as u32) as i32;
                if 0 < t_index && t_index < HC_TCOUNT {
                    // Make syllable of form LVT.
                    uc = uc.wrapping_add(t_index as u32);
                } else {
                    outp.push(out, uc);
                    uc = uc2;
                }
                continue;
            }
            let nfc = get_nfc(uc, uc2);
            if nfc != 0 {
                // A composition to current code points is found.
                uc = nfc;
                continue;
            }
            let cl = ccc(uc2);
            if cl == 0 {
                // Clearly 'uc2' the second code point is not a decomposable
                // code.
                outp.push(out, uc);
                uc = uc2;
                continue;
            }

            // Collect following decomposable code points.
            let mut c = Collected {
                ucx: [0; FDC_MAX],
                ccx: [0; FDC_MAX],
                cl,
                cx: 0,
                nx: 0,
            };
            c.ucx[0] = uc2;
            c.ccx[0] = cl;
            let mut ucx_size = c.collect(inp, &mut s, 1, &mut ret);

            // Find a composed code in the collected code points.
            let mut i = 1;
            while i < ucx_size {
                let nfc = get_nfc(uc, c.ucx.get(i).copied().unwrap_or(0));
                if nfc == 0 {
                    i += 1;
                    continue;
                }

                // nfc is composed of uc and ucx[i].
                uc = nfc;

                // Remove ucx[i] by shifting following code points.
                c.ucx.copy_within(i + 1..ucx_size, i);
                c.ccx.copy_within(i + 1..ucx_size, i);
                ucx_size -= 1;

                // Collect following code points blocked by ucx[i] the
                // removed code point.
                if ucx_size > 0 && i == ucx_size && c.nx > 0 && c.cx == c.cl {
                    c.cl = c.ccx.get(ucx_size - 1).copied().unwrap_or(0);
                    ucx_size = c.collect(inp, &mut s, ucx_size, &mut ret);
                }
                // Restart finding a composed code with the updated uc from
                // the top of the collected code points.
                i = 0;
            }

            // Apparently the current code points are not decomposed
            // characters or already composed.
            outp.push(out, uc);
            for &u in c.ucx.iter().take(ucx_size) {
                outp.push(out, u);
            }

            // Flush out remaining canonical combining characters.
            if c.nx > 0 && c.cx == c.cl && !s.is_empty() {
                loop {
                    let (nx, u) = inp.parse(s);
                    if nx <= 0 {
                        break;
                    }
                    let cx = ccc(u);
                    if c.cl > cx {
                        break;
                    }
                    s = skip(s, nx);
                    c.cl = cx;
                    outp.push(out, u);
                }
            }
            break;
        }
        if n2 < 0 {
            outp.push(out, uc);
            // Use a replaced unicode character.
            outp.push(out, uc2);
            s = skip(s, n2);
            ret = -1;
        } else if n2 == 0 {
            outp.push(out, uc);
            break;
        }
    }
    ret
}

/// Normalize UTF-8 characters to Form D and copy the result.
fn normalize_d(out: &mut Vec<u8>, src: &[u8], flag: u32) -> i32 {
    let (inp, outp) = (Enc::input(flag), Enc::output(flag));
    let mut s = src;
    let mut ret = 0;

    'next: loop {
        let (mut n, mut uc) = inp.parse(s);
        if n == 0 {
            break;
        }
        loop {
            // check_first_code
            if n < 0 {
                // Use a replaced unicode character.
                outp.push(out, uc);
                s = skip(s, n);
                ret = -1;
                continue 'next;
            }
            s = skip(s, n);

            // Hangul Decomposition.
            let s_index = uc.wrapping_sub(HC_SBASE as u32) as i32;
            if (0..HC_SCOUNT).contains(&s_index) {
                let l = HC_LBASE + s_index / HC_NCOUNT;
                let v = HC_VBASE + (s_index % HC_NCOUNT) / HC_TCOUNT;
                let t = HC_TBASE + s_index % HC_TCOUNT;
                outp.push(out, l as u32);
                outp.push(out, v as u32);
                if t != HC_TBASE {
                    outp.push(out, t as u32);
                }
                continue 'next;
            }
            if is_decomposable_block(uc) && ccc(uc) != 0 {
                outp.push(out, uc);
                continue 'next;
            }

            // (code point, class) of the trailing characters, in class order.
            let mut fdc = [(0u32, 0i32); FDC_MAX];
            let mut fdi = 0;
            while let Some((cp1, cp2)) = get_nfd(uc) {
                if fdi >= FDC_MAX {
                    break;
                }
                fdc.copy_within(0..fdi, 1);
                fdc[0] = (cp2, ccc(cp2));
                fdi += 1;
                uc = cp1;
            }

            // Read following code points.
            let (mut n2, mut uc2);
            loop {
                (n2, uc2) = inp.parse(s);
                if n2 <= 0 {
                    break;
                }
                let class = ccc(uc2);
                if class == 0 || fdi >= FDC_MAX {
                    break;
                }
                s = skip(s, n2);
                match fdc.iter().take(fdi).position(|&(_, c)| c > class) {
                    Some(j) => {
                        fdc.copy_within(j..fdi, j + 1);
                        fdc[j] = (uc2, class);
                    }
                    None => fdc[fdi] = (uc2, class),
                }
                fdi += 1;
            }

            outp.push(out, uc);
            for &(u, _) in fdc.iter().take(fdi) {
                outp.push(out, u);
            }

            if n2 == 0 {
                break 'next;
            }
            uc = uc2;
            n = n2;
        }
    }
    ret
}

/// Convert a UTF-16BE/LE string to the ASCII subset of the current locale.
/// Return -1 if conversion fails.
///
/// Other case, we should do the best effort. If all character are
/// ASCII(<0x7f), we can convert it. if not, we set a alternative character
/// and return -1.
fn best_effort_from_utf16(out: &mut Vec<u8>, src: &[u8], be: bool) -> i32 {
    let mut ret = 0;
    let mut s = src;
    loop {
        let (n, uc) = utf16_to_unicode(s, be);
        if n == 0 {
            return ret;
        }
        if n < 0 {
            ret = -1;
        }
        s = skip(s, n);
        if uc > 127 {
            // We cannot handle it.
            out.push(b'?');
            ret = -1;
        } else {
            out.push(uc as u8);
        }
    }
}

/// Convert a current locale string to UTF-16BE/LE, ASCII only. Return -1 if
/// conversion fails.
fn best_effort_to_utf16(out: &mut Vec<u8>, src: &[u8], bigendian: bool) -> i32 {
    let enc = if bigendian {
        Enc::Utf16Be
    } else {
        Enc::Utf16Le
    };
    let mut ret = 0;
    for &b in src {
        let mut c = u32::from(b);
        if c > 127 {
            // We cannot handle it.
            c = UNICODE_R_CHAR;
            ret = -1;
        }
        enc.push(out, c);
    }
    ret
}

/// Basically returns -1 because we cannot make a conversion of charset
/// without iconv but in some cases this would return 0.
/// Returns 0 if all copied characters are ASCII.
/// Returns 0 if both from-locale and to-locale are the same and those can be
/// WCS with no error.
fn best_effort_strncat_in_locale(out: &mut Vec<u8>, src: &[u8], flag: u32, same: bool) -> i32 {
    // If both from-locale and to-locale is the same, this makes a copy. And
    // then this checks all copied MBS can be WCS if so returns 0.
    if same {
        out.extend_from_slice(src);
        return if charset::mb_to_wide(src, &mut Vec::new()) {
            0
        } else {
            -1
        };
    }

    // If a character is ASCII, this just copies it. If not, this assigns
    // '?' character instead but in UTF-8 locale this assigns byte sequence
    // 0xEF 0xBD 0xBD, which are code point U+FFFD, a Replacement Character
    // in Unicode.
    let mut return_value = 0;
    for &b in src.iter().take_while(|&&b| b != 0) {
        if b > 127 {
            // Non-ASCII: Substitute with suitable replacement
            if flag & SCONV_TO_UTF8 != 0 {
                out.extend_from_slice(&UTF8_REPLACEMENT_CHAR);
            } else {
                out.push(b'?');
            }
            return_value = -1;
        } else {
            out.push(b);
        }
    }
    return_value
}

/// A string conversion object.
pub(crate) struct StringConv {
    from_charset: Vec<u8>,
    to_charset: Vec<u8>,
    /// Set 1 if from_charset and to_charset are the same.
    same: bool,
    state: Mutex<State>,
}

impl StringConv {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Change the behavior of a string conversion.
    #[allow(dead_code)] // used by the tar reader (phase 4)
    pub(crate) fn set_opt(&self, opt: i32) {
        let mut st = self.state();
        match opt {
            // A filename in UTF-8 was made with libarchive 2.x in a wrong
            // assumption that wchar_t was Unicode. Nothing to do for it
            // since wchar_t on every supported platform is really Unicode.
            SCONV_SET_OPT_UTF8_LIBARCHIVE2X => {}
            SCONV_SET_OPT_NORMALIZATION_C => {
                if st.flag & SCONV_NORMALIZATION_C == 0 {
                    st.flag |= SCONV_NORMALIZATION_C;
                    st.flag &= !SCONV_NORMALIZATION_D;
                    st.setup_converter(self.same);
                }
            }
            SCONV_SET_OPT_NORMALIZATION_D => {
                // If iconv will take the string, do not change the setting
                // of the normalization.
                if st.flag & (SCONV_FROM_UTF16 | SCONV_FROM_UTF8) != 0
                    && st.flag & (SCONV_TO_UTF16 | SCONV_TO_UTF8) == 0
                {
                    return;
                }
                if st.flag & SCONV_NORMALIZATION_D == 0 {
                    st.flag |= SCONV_NORMALIZATION_D;
                    st.flag &= !SCONV_NORMALIZATION_C;
                    st.setup_converter(self.same);
                }
            }
            _ => {}
        }
    }
}

/// The name of the charset a conversion goes to or from, for messages.
#[allow(dead_code)] // used by the format readers and writers (phases 3-5)
pub(crate) fn conversion_charset_name(sc: Option<&StringConv>) -> &[u8] {
    match sc {
        None => b"current locale",
        Some(sc) if sc.state().flag & SCONV_TO_CHARSET != 0 => &sc.to_charset,
        Some(sc) => &sc.from_charset,
    }
}

/// Return canonicalized charset-name but this supports just UTF-8,
/// UTF-16BE/LE and CP932 which are referenced in create_sconv_object().
fn canonical_charset_name(charset: &[u8]) -> &[u8] {
    if charset.is_empty() || charset.len() > 15 {
        return charset;
    }
    match charset.to_ascii_uppercase().as_slice() {
        b"UTF-8" | b"UTF8" => b"UTF-8",
        b"UTF-16BE" | b"UTF16BE" => b"UTF-16BE",
        b"UTF-16LE" | b"UTF16LE" => b"UTF-16LE",
        b"CP932" => b"CP932",
        _ => charset,
    }
}

/// Create a string conversion object.
fn create_sconv_object(fc: &[u8], tc: &[u8], mut flag: u32) -> StringConv {
    let apple = cfg!(target_vendor = "apple");

    // Check if "from charset" and "to charset" are the same.
    let same = fc == tc;

    // Mark if "from charset" or "to charset" are UTF-8 or UTF-16BE/LE.
    match tc {
        b"UTF-8" => flag |= SCONV_TO_UTF8,
        b"UTF-16BE" => flag |= SCONV_TO_UTF16BE,
        b"UTF-16LE" => flag |= SCONV_TO_UTF16LE,
        _ => {}
    }
    match fc {
        b"UTF-8" => flag |= SCONV_FROM_UTF8,
        b"UTF-16BE" => flag |= SCONV_FROM_UTF16BE,
        b"UTF-16LE" => flag |= SCONV_FROM_UTF16LE,
        _ => {}
    }

    // Set a flag for Unicode NFD. Usually iconv cannot correctly handle it.
    // So we have to translate NFD characters to NFC ones ourselves before
    // iconv handles. Another reason is to prevent that the same sight of
    // two filenames, one is NFC and other is NFD, would be in its
    // directory. On Mac OS X, although its filesystem layer automatically
    // convert filenames to NFD, it would be useful for filename comparing
    // to find out the same filenames that we normalize that to be NFD
    // ourselves.
    if flag & SCONV_FROM_CHARSET != 0 && flag & (SCONV_FROM_UTF16 | SCONV_FROM_UTF8) != 0 {
        if apple && flag & SCONV_TO_UTF8 != 0 {
            flag |= SCONV_NORMALIZATION_D;
        } else {
            flag |= SCONV_NORMALIZATION_C;
        }
    }
    if apple {
        // In case writing an archive file, make sure that a filename going
        // to be passed to iconv is a Unicode NFC string since a filename in
        // HFS Plus filesystem is a Unicode NFD one and iconv cannot handle
        // it with "UTF-8" charset. It is simpler than a use of "UTF-8-MAC"
        // charset.
        if flag & SCONV_TO_CHARSET != 0
            && flag & (SCONV_FROM_UTF16 | SCONV_FROM_UTF8) != 0
            && flag & (SCONV_TO_UTF16 | SCONV_TO_UTF8) == 0
        {
            flag |= SCONV_NORMALIZATION_C;
        }
        // In case reading an archive file. make sure that a filename will
        // be passed to users is a Unicode NFD string in order to correctly
        // compare the filename with other one which comes from HFS Plus
        // filesystem.
        if flag & SCONV_FROM_CHARSET != 0
            && flag & (SCONV_FROM_UTF16 | SCONV_FROM_UTF8) == 0
            && flag & SCONV_TO_UTF8 != 0
        {
            flag |= SCONV_NORMALIZATION_D;
        }
    }

    // Create an iconv object, unless both sides are Unicode we convert
    // ourselves.
    let cd = if flag & (SCONV_TO_UTF8 | SCONV_TO_UTF16) != 0
        && flag & (SCONV_FROM_UTF8 | SCONV_FROM_UTF16) != 0
    {
        None
    } else {
        Iconv::open(tc, fc)
    };

    let mut state = State {
        flag,
        converters: Vec::new(),
        cd,
    };
    state.setup_converter(same);
    StringConv {
        from_charset: fc.to_vec(),
        to_charset: tc.to_vec(),
        same,
        state: Mutex::new(state),
    }
}

/// The string conversion objects of one archive handle (upstream's
/// `a->sconv` list and `a->current_code`). Conversions made through it are
/// kept for the life of the handle; passing `None` instead makes a
/// throwaway conversion, as upstream does for a NULL archive.
#[derive(Default)]
pub(crate) struct ConvCache {
    convs: Vec<Arc<StringConv>>,
    /// The locale's charset name, fixed at first use.
    current_code: Option<Vec<u8>>,
}

/// Return a string conversion object.
fn get_sconv_object(
    a: Option<&mut ConvCache>,
    fc: &[u8],
    tc: &[u8],
    flag: u32,
) -> Result<Arc<StringConv>, ConvError> {
    // Check if we have made the sconv object.
    if let Some(found) = a.as_deref().and_then(|a| {
        a.convs
            .iter()
            .find(|sc| sc.from_charset == fc && sc.to_charset == tc)
    }) {
        return Ok(found.clone());
    }

    let sc = create_sconv_object(canonical_charset_name(fc), canonical_charset_name(tc), flag);

    // If there is no converter for current string conversion object, we
    // cannot handle this conversion.
    if sc.state().converters.is_empty() {
        let name = if flag & SCONV_TO_CHARSET != 0 { tc } else { fc };
        let mut message = b"iconv_open failed: Cannot handle ``".to_vec();
        message.extend_from_slice(name);
        message.extend_from_slice(b"''");
        return Err(ConvError {
            errno: ARCHIVE_ERRNO_MISC,
            message,
        });
    }

    let sc = Arc::new(sc);
    if let Some(a) = a {
        a.convs.push(sc.clone());
    }
    Ok(sc)
}

fn get_current_charset(a: Option<&mut ConvCache>) -> Vec<u8> {
    match a {
        None => charset::locale_codeset(),
        Some(a) => match &a.current_code {
            Some(code) if !code.is_empty() => code.clone(),
            _ => {
                let code = charset::locale_codeset();
                a.current_code.get_or_insert_with(|| code.clone());
                code
            }
        },
    }
}

/// Make and return a string conversion object.
/// Return an error if the platform does not support the specified
/// conversion and best_effort is false.
/// If best_effort is set, a string conversion object is returned, but the
/// conversion might fail when non-ASCII code is found.
///
/// The error is what upstream hands to `archive_set_error` on the archive.
pub(crate) fn conversion_to_charset(
    mut a: Option<&mut ConvCache>,
    charset: &[u8],
    best_effort: bool,
) -> Result<Arc<StringConv>, ConvError> {
    let flag = SCONV_TO_CHARSET | if best_effort { SCONV_BEST_EFFORT } else { 0 };
    let current = get_current_charset(a.as_deref_mut());
    get_sconv_object(a, &current, charset, flag)
}

pub(crate) fn conversion_from_charset(
    mut a: Option<&mut ConvCache>,
    charset: &[u8],
    best_effort: bool,
) -> Result<Arc<StringConv>, ConvError> {
    let flag = SCONV_FROM_CHARSET | if best_effort { SCONV_BEST_EFFORT } else { 0 };
    let current = get_current_charset(a.as_deref_mut());
    get_sconv_object(a, charset, &current, flag)
}

/// Copy `src` to `out` (replacing its contents) in locale conversion.
/// On failure `out` holds the partial output.
pub(crate) fn strncpy_l(
    out: &mut Vec<u8>,
    src: &[u8],
    sc: Option<&StringConv>,
) -> Result<(), ConvFailed> {
    out.clear();
    strncat_l(out, src, sc)
}

/// Append `src` to `out` in locale conversion. `src` ends at its first NUL
/// (first all-zero unit for UTF-16 input) or at the end of the slice.
/// On failure `out` holds the partial output.
pub(crate) fn strncat_l(
    out: &mut Vec<u8>,
    src: &[u8],
    sc: Option<&StringConv>,
) -> Result<(), ConvFailed> {
    let Some(sc) = sc else {
        // If sc is NULL, we just make a copy.
        out.extend_from_slice(until_nul(src));
        return Ok(());
    };
    let mut st = sc.state();
    let length = if st.flag & SCONV_FROM_UTF16 != 0 {
        utf16nbytes(src)
    } else {
        until_nul(src).len()
    };
    let src = src.get(..length).unwrap_or(&[]);
    if src.is_empty() {
        return Ok(());
    }

    let r = match (
        st.converters.first().copied(),
        st.converters.get(1).copied(),
    ) {
        (None, _) => return Err(ConvFailed),
        (Some(only), None) => st.run(only, out, src, sc.same),
        (Some(first), Some(second)) => {
            let mut tmp = Vec::new();
            let r = st.run(first, &mut tmp, src, sc.same);
            r.min(st.run(second, out, &tmp, sc.same))
        }
    };
    if r == 0 { Ok(()) } else { Err(ConvFailed) }
}

/// A multistring: a value held as some subset of locale multibyte, UTF-8
/// and wide-character forms. If you set and read the same form, no
/// translation is done. If you set and read different forms, the library
/// will attempt to transparently convert.
///
/// `set` says which forms are valid; the others are stale buffers. Setting
/// one form clears the rest, and a conversion adds a form only when it
/// succeeded.
///
/// Every stored form keeps a trailing NUL, so the `_z` and `_c` getters hand
/// out C-string views. A view stays valid until the next `&mut` use of this
/// `MString`: a getter never rewrites a form that is already set. Only
/// `get_mbs_l` with a charset rewrites its scratch buffer.
#[derive(Clone, Default)]
pub(crate) struct MString {
    mbs: Vec<u8>,
    utf8: Vec<u8>,
    wcs: Vec<wchar_t>,
    mbs_in_locale: Vec<u8>,
    pub(crate) set: u8,
}

pub(crate) const AES_SET_MBS: u8 = 1;
pub(crate) const AES_SET_UTF8: u8 = 2;
pub(crate) const AES_SET_WCS: u8 = 4;

/// Empty `v`, let `f` fill it, and terminate it with a NUL.
fn fill<T: Default, R>(v: &mut Vec<T>, f: impl FnOnce(&mut Vec<T>) -> R) -> R {
    v.clear();
    let r = f(v);
    v.push(T::default());
    r
}

/// A stored form without its terminator.
fn unterminated<T>(z: &[T]) -> &[T] {
    z.split_last().map_or(z, |(_, s)| s)
}

fn as_cstr(z: &[u8]) -> &CStr {
    CStr::from_bytes_until_nul(z).unwrap_or_default()
}

impl MString {
    pub(crate) fn resource_metadata_size(&self) -> Option<usize> {
        self.mbs
            .len()
            .checked_add(self.utf8.len())?
            .checked_add(self.wcs.len().checked_mul(std::mem::size_of::<wchar_t>())?)?
            .checked_add(self.mbs_in_locale.len())
    }

    /// Mark the string as not set (upstream's copy of a NULL pointer).
    pub(crate) fn clear(&mut self) {
        self.set = 0;
    }

    /// Set from a locale multibyte string; only that form is set.
    pub(crate) fn copy_mbs(&mut self, mbs: &[u8]) {
        self.set = AES_SET_MBS;
        fill(&mut self.mbs, |v| v.extend_from_slice(until_nul(mbs)));
        self.utf8.clear();
        self.wcs.clear();
    }

    /// Set from a UTF-8 string; only that form is set. Returns its length.
    pub(crate) fn copy_utf8(&mut self, utf8: &[u8]) -> usize {
        self.set = AES_SET_UTF8;
        self.mbs.clear();
        self.wcs.clear();
        fill(&mut self.utf8, |v| v.extend_from_slice(until_nul(utf8)));
        self.utf8.len() - 1
    }

    /// Set from a wide string; only that form is set.
    pub(crate) fn copy_wcs(&mut self, wcs: &[wchar_t]) {
        self.set = AES_SET_WCS;
        self.mbs.clear();
        self.utf8.clear();
        fill(&mut self.wcs, |v| {
            v.extend(wcs.iter().copied().take_while(|&w| w != 0))
        });
    }

    /// Set from a multibyte string in the charset of `sc`, converted to the
    /// locale's. On failure the string is left unset.
    pub(crate) fn copy_mbs_len_l(
        &mut self,
        mbs: &[u8],
        sc: Option<&StringConv>,
    ) -> Result<(), ConvFailed> {
        self.wcs.clear();
        self.utf8.clear();
        let r = fill(&mut self.mbs, |v| strncpy_l(v, mbs, sc));
        self.set = if r.is_ok() { AES_SET_MBS } else { 0 };
        r
    }

    /// The 'update' form tries to proactively update all forms of this
    /// string (WCS and MBS) and returns an error if any of them fail. This
    /// is used by the 'pax' handler, for instance, to detect and report
    /// character-conversion failures early while still allowing clients to
    /// get potentially useful values from the more tolerant lazy
    /// conversions. (get_mbs and get_wcs will strive to give the user
    /// something useful, so you can get hopefully usable values even if
    /// some of the character conversions are failing.)
    pub(crate) fn update_utf8(
        &mut self,
        a: Option<&mut ConvCache>,
        utf8: &[u8],
    ) -> Result<(), ConvFailed> {
        // Save the UTF8 string.
        fill(&mut self.utf8, |v| v.extend_from_slice(until_nul(utf8)));
        // Empty the mbs and wcs strings.
        self.mbs.clear();
        self.wcs.clear();
        self.set = AES_SET_UTF8; // Only UTF8 is set now.

        let sc = conversion_from_charset(a, b"UTF-8", true).map_err(|_| ConvFailed)?;

        // Try converting UTF-8 to MBS, return false on failure.
        fill(&mut self.mbs, |v| strncpy_l(v, &self.utf8, Some(&sc)))?;
        self.set = AES_SET_UTF8 | AES_SET_MBS; // Both UTF8 and MBS set.

        // Try converting MBS to WCS, return false on failure.
        if !fill(&mut self.wcs, |v| charset::mb_to_wide(&self.mbs, v)) {
            return Err(ConvFailed);
        }

        // All conversions succeeded.
        self.set = AES_SET_UTF8 | AES_SET_WCS | AES_SET_MBS;
        Ok(())
    }

    /// Make the MBS form valid if it can be, from WCS or else UTF-8.
    /// False means a conversion failed.
    fn ensure_mbs(&mut self, a: Option<&mut ConvCache>) -> bool {
        // If we already have an MBS form, return that immediately.
        if self.set & AES_SET_MBS != 0 {
            return true;
        }
        let mut ok = true;
        // If there's a WCS form, try converting with the native locale.
        if self.set & AES_SET_WCS != 0 {
            if fill(&mut self.mbs, |v| charset::wide_to_mb(&self.wcs, v)) {
                self.set |= AES_SET_MBS;
                return true;
            }
            ok = false;
        }

        // If there's a UTF-8 form, try converting with the native locale.
        if self.set & AES_SET_UTF8 != 0 {
            self.mbs.clear();
            let Ok(sc) = conversion_from_charset(a, b"UTF-8", true) else {
                return false;
            };
            ok = fill(&mut self.mbs, |v| strncpy_l(v, &self.utf8, Some(&sc))).is_ok();
            if ok {
                self.set |= AES_SET_MBS;
            }
        }
        ok
    }

    /// The locale multibyte form with its trailing NUL. `Ok(None)` if the
    /// string is not set; an error if the string could not be converted.
    ///
    /// Callers that fall back to `get_utf8_z` on failure, as
    /// `archive_entry_pathname` does for EILSEQ, should do so on any error:
    /// conversion failures here are all EILSEQ-like.
    pub(crate) fn get_mbs_z(
        &mut self,
        a: Option<&mut ConvCache>,
    ) -> Result<Option<&[u8]>, ConvFailed> {
        if !self.ensure_mbs(a) {
            return Err(ConvFailed);
        }
        Ok((self.set & AES_SET_MBS != 0).then_some(self.mbs.as_slice()))
    }

    /// The UTF-8 form with its trailing NUL. `Ok(None)` if the string is
    /// not set.
    pub(crate) fn get_utf8_z(
        &mut self,
        mut a: Option<&mut ConvCache>,
    ) -> Result<Option<&[u8]>, ConvFailed> {
        // If we already have a UTF8 form, return that immediately.
        if self.set & AES_SET_UTF8 != 0 {
            return Ok(Some(&self.utf8));
        }
        // Try converting WCS to MBS first if MBS does not exist yet.
        if self.set & AES_SET_MBS == 0 {
            // ignore errors, we'll handle it later
            self.ensure_mbs(a.as_deref_mut());
        }
        if self.set & AES_SET_MBS != 0 {
            let sc = conversion_to_charset(a, b"UTF-8", true).map_err(|_| ConvFailed)?;
            fill(&mut self.utf8, |v| strncpy_l(v, &self.mbs, Some(&sc)))?;
            self.set |= AES_SET_UTF8;
            return Ok(Some(&self.utf8));
        }
        Ok(None)
    }

    /// The wide-character form with its trailing NUL. `Ok(None)` if the
    /// string is not set.
    pub(crate) fn get_wcs_z(
        &mut self,
        a: Option<&mut ConvCache>,
    ) -> Result<Option<&[wchar_t]>, ConvFailed> {
        // Return WCS form if we already have it.
        if self.set & AES_SET_WCS != 0 {
            return Ok(Some(&self.wcs));
        }
        // Try converting UTF8 to MBS first if MBS does not exist yet.
        if self.set & AES_SET_MBS == 0 {
            // ignore errors, we'll handle it later
            self.ensure_mbs(a);
        }
        // Try converting MBS to WCS using native locale.
        if self.set & AES_SET_MBS != 0 {
            if !fill(&mut self.wcs, |v| charset::mb_to_wide(&self.mbs, v)) {
                return Err(ConvFailed);
            }
            self.set |= AES_SET_WCS;
            return Ok(Some(&self.wcs));
        }
        Ok(None)
    }

    /// The string in the charset of `sc` (the locale's if `None`) with its
    /// trailing NUL. Returns the string, if any, and whether everything
    /// converted. On failure the string is the partial result with
    /// substitutions, as upstream returns it alongside -1. With a charset
    /// the result lives in a scratch buffer that the next call rewrites.
    pub(crate) fn get_mbs_l_z(
        &mut self,
        a: Option<&mut ConvCache>,
        sc: Option<&StringConv>,
    ) -> (Option<&[u8]>, bool) {
        let mut ok = true;
        // If there is not an MBS form but there is a WCS or UTF8 form, try
        // converting with the native locale to be used for translating it
        // to specified character-set.
        if self.set & AES_SET_MBS == 0 && !self.ensure_mbs(a) {
            // We have another form, but failed to convert it to the native
            // locale. Transitively, we've failed to convert it to the
            // specified character set.
            ok = false;
        }
        // If we already have an MBS form, use it to be translated to
        // specified character-set.
        if self.set & AES_SET_MBS != 0 {
            if sc.is_none() {
                // Conversion is unneeded.
                return (Some(&self.mbs), true);
            }
            ok = fill(&mut self.mbs_in_locale, |v| strncpy_l(v, &self.mbs, sc)).is_ok();
            (Some(&self.mbs_in_locale), ok)
        } else {
            // Either we have no string in any form, or conversion failed.
            (None, ok)
        }
    }

    /// `get_mbs_z` as a C string.
    pub(crate) fn get_mbs_c(
        &mut self,
        a: Option<&mut ConvCache>,
    ) -> Result<Option<&CStr>, ConvFailed> {
        Ok(self.get_mbs_z(a)?.map(as_cstr))
    }

    /// `get_utf8_z` as a C string.
    pub(crate) fn get_utf8_c(
        &mut self,
        a: Option<&mut ConvCache>,
    ) -> Result<Option<&CStr>, ConvFailed> {
        Ok(self.get_utf8_z(a)?.map(as_cstr))
    }

    /// The locale multibyte form without the terminator.
    pub(crate) fn get_mbs(
        &mut self,
        a: Option<&mut ConvCache>,
    ) -> Result<Option<&[u8]>, ConvFailed> {
        Ok(self.get_mbs_z(a)?.map(unterminated))
    }

    /// The wide-character form without the terminator.
    pub(crate) fn get_wcs(
        &mut self,
        a: Option<&mut ConvCache>,
    ) -> Result<Option<&[wchar_t]>, ConvFailed> {
        Ok(self.get_wcs_z(a)?.map(unterminated))
    }

    /// `get_mbs_l_z` without the terminator.
    pub(crate) fn get_mbs_l(
        &mut self,
        a: Option<&mut ConvCache>,
        sc: Option<&StringConv>,
    ) -> (Option<&[u8]>, bool) {
        let (s, ok) = self.get_mbs_l_z(a, sc);
        (s.map(unterminated), ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::charset::{lock_locale, set_locale_all};
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    fn skipping(msg: &str) {
        eprintln!("SKIPPED: {msg}");
    }

    fn wide(s: &str) -> Vec<wchar_t> {
        s.chars().map(|c| c as u32 as wchar_t).collect()
    }

    /// Like upstream's `setCheckedLocale`: the locale must exist and decode
    /// the given multibyte character to the expected wide character.
    fn set_checked_locale(locale: &str, mbc: &[u8], expected: u32) -> bool {
        if !set_locale_all(locale) {
            return false;
        }
        let mut w = Vec::new();
        charset::mb_to_wide(mbc, &mut w) && w == [expected as wchar_t]
    }

    fn cache() -> ConvCache {
        ConvCache::default()
    }

    #[test]
    fn test_archive_string() {
        // The buffer-extent assertions of upstream's test_archive_string
        // (archive_string_ensure, sprintf growth, ...) test C buffer
        // management that is `Vec` here. What remains is the NUL-bounded
        // copy behind archive_strncat/archive_strncpy.
        assert_eq!(until_nul(b"snafu"), b"snafu");
        assert_eq!(until_nul(&b"barbazqux"[..3]), b"bar");
        assert_eq!(until_nul(b"snafu\0bar"), b"snafu");
        assert_eq!(until_nul(b""), b"");

        let pairs: [(&str, &str); 20] = [
            ("", "."),
            ("/", "/"),
            ("//", "/"),
            ("///", "/"),
            ("./", "."),
            (".", "."),
            ("..", "."),
            ("foo", "."),
            ("foo/", "."),
            ("foo//", "."),
            ("foo/bar", "foo"),
            ("foo/bar/", "foo"),
            ("foo/bar//", "foo"),
            ("foo//bar", "foo"),
            ("foo//bar/", "foo"),
            ("foo//bar//", "foo"),
            ("/foo", "/"),
            ("//foo", "/"),
            ("//foo/", "/"),
            ("//foo//", "/"),
        ];
        for (s, exp) in pairs {
            let mut v = s.as_bytes().to_vec();
            string_dirname(&mut v);
            assert_eq!(v, exp.as_bytes(), "dirname({s:?})");
        }
    }

    // -- test_archive_string_conversion.c ---------------------------------

    fn uudecode(text: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut lines = text.split(|&b| b == b'\n');
        lines.find(|l| l.starts_with(b"begin "))?;
        for line in lines {
            let Some(&first) = line.first() else { continue };
            let len = usize::from(first.wrapping_sub(32) & 0x3f);
            if len == 0 {
                break;
            }
            let mut decoded = Vec::new();
            for g in line[1..].chunks(4) {
                let c: Vec<u8> = (0..4)
                    .map(|i| g.get(i).copied().unwrap_or(b' ').wrapping_sub(32) & 0x3f)
                    .collect();
                decoded.push(c[0] << 2 | c[1] >> 4);
                decoded.push(c[1] << 4 | c[2] >> 2);
                decoded.push(c[2] << 6 | c[3]);
            }
            out.extend_from_slice(&decoded[..len.min(decoded.len())]);
        }
        Some(out)
    }

    /// Decompress Unix `compress` (.Z) data. The LZW filter is not ported
    /// yet (phase 2), so this borrows the system's `gzip -dc` (or
    /// `uncompress -c`), which read .Z.
    fn uncompress(data: &[u8]) -> Option<Vec<u8>> {
        for (prog, args) in [("gzip", &["-dc"][..]), ("uncompress", &["-c"][..])] {
            let Ok(mut child) = Command::new(prog)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            else {
                continue;
            };
            let mut stdin = child.stdin.take()?;
            let input = data.to_vec();
            let writer = std::thread::spawn(move || stdin.write_all(&input));
            let output = child.wait_with_output().ok()?;
            let _ = writer.join();
            if output.status.success() {
                return Some(output.stdout);
            }
        }
        None
    }

    /// The NFC/NFD pattern file that upstream extracts from
    /// test_archive_string_conversion.txt.Z.uu.
    ///
    /// Looked up in `$LIBARCHIVE_TEST_DIR`, else the checkout's submodule,
    /// else (in a worktree under `.claude/worktrees/`) the main checkout's.
    fn load_normalization_data() -> String {
        const NAME: &str = "test_archive_string_conversion.txt.Z.uu";
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let rel = "upstream/libarchive/libarchive/test";
        let mut dirs: Vec<PathBuf> = std::env::var_os("LIBARCHIVE_TEST_DIR")
            .map(PathBuf::from)
            .into_iter()
            .collect();
        dirs.push(manifest.join(rel));
        dirs.extend(manifest.ancestors().nth(3).map(|root| root.join(rel)));
        let uu = dirs
            .iter()
            .find_map(|d| std::fs::read(d.join(NAME)).ok())
            .unwrap_or_else(|| {
                panic!("fixture {NAME} not found in {dirs:?}; set LIBARCHIVE_TEST_DIR")
            });
        let z = uudecode(&uu).expect("fixture is not valid uuencode");
        let text = uncompress(&z).expect("neither gzip nor uncompress could decompress the .Z");
        String::from_utf8(text).expect("fixture is not UTF-8")
    }

    /// One `<code points>` pattern of the data file in every form the tests
    /// compare against.
    struct Pattern {
        utf8: Vec<u8>,
        wc: Vec<wchar_t>,
        utf16be: Vec<u8>,
        utf16le: Vec<u8>,
        /// The first code point is one that Mac OS does not convert to NFD.
        mac_keeps_nfc: bool,
    }

    /// Note: U+2000 - U+2FFF, U+F900 - U+FAFF and U+2F800 - U+2FAFF are not
    /// converted to NFD on Mac OS.
    /// see also http://developer.apple.com/library/mac/#qa/qa2001/qa1173.html
    fn scan_unicode_pattern(pattern: &str) -> Pattern {
        let mut p = Pattern {
            utf8: Vec::new(),
            wc: Vec::new(),
            utf16be: Vec::new(),
            utf16le: Vec::new(),
            mac_keeps_nfc: false,
        };
        for (i, tok) in pattern.split(' ').enumerate() {
            let uc = u32::from_str_radix(tok, 16).unwrap();
            if i == 0 {
                p.mac_keeps_nfc = matches!(
                    uc,
                    0x2194 | 0x219A | 0x219B | 0x21AE | 0x21CD | 0x21CE | 0x21CF | 0x2204
                        | 0x2209 | 0x220C | 0x2224 | 0x2226 | 0x2241 | 0x2244 | 0x2247
                        | 0x2249 | 0x2260 | 0x2262 | 0x226D | 0x226E | 0x226F | 0x2270
                        | 0x2271 | 0x2274 | 0x2275 | 0x2276 | 0x2278 | 0x2279 | 0x227A
                        | 0x227B | 0x2280 | 0x2281 | 0x2284 | 0x2285 | 0x2288 | 0x2289
                        | 0x22AC | 0x22AD | 0x22AE | 0x22AF | 0x22E0 | 0x22E1 | 0x22E2
                        | 0x22E3 | 0x22EA | 0x22EB | 0x22EC | 0x22ED
                        // Those code points are not converted to NFD on
                        // Mac OS. I do not know the reason because it is
                        // undocumented.
                        //   NFC        NFD
                        //   1109A  ==> 11099 110BA
                        //   1109C  ==> 1109B 110BA
                        //   110AB  ==> 110A5 110BA
                        | 0x1109A | 0x1109C | 0x110AB
                );
            }
            Enc::Utf8.push(&mut p.utf8, uc);
            Enc::Utf16Be.push(&mut p.utf16be, uc);
            Enc::Utf16Le.push(&mut p.utf16le, uc);
            p.wc.push(uc as wchar_t);
        }
        p
    }

    /// The data file's lines, as `(line number, NFC pattern, NFD pattern)`.
    fn pattern_lines(data: &str) -> Vec<(usize, &str, &str)> {
        data.lines()
            .enumerate()
            .filter(|(_, l)| !l.starts_with('#'))
            .filter_map(|(i, l)| l.split_once(';').map(|(c, d)| (i + 1, c, d)))
            .collect()
    }

    struct Convs {
        a: ConvCache,
        f8: Arc<StringConv>,
        f16be: Arc<StringConv>,
        f16le: Arc<StringConv>,
        t8: Arc<StringConv>,
    }

    fn make_convs(opt: i32) -> Convs {
        let (mut a, mut a2) = (cache(), cache());
        let f8 = conversion_from_charset(Some(&mut a), b"UTF-8", false).unwrap();
        let f16be = conversion_from_charset(Some(&mut a), b"UTF-16BE", false).unwrap();
        let f16le = conversion_from_charset(Some(&mut a), b"UTF-16LE", false).unwrap();
        let t8 = conversion_to_charset(Some(&mut a2), b"UTF-8", false).unwrap();
        for sc in [&f8, &f16be, &f16le, &t8] {
            sc.set_opt(opt);
        }
        Convs {
            a,
            f8,
            f16be,
            f16le,
            t8,
        }
    }

    fn convert(src: &[u8], sc: &StringConv) -> Vec<u8> {
        let mut out = Vec::new();
        assert!(strncpy_l(&mut out, src, Some(sc)).is_ok());
        out
    }

    /// A conversion test that we correctly normalize UTF-8 and UTF-16BE
    /// characters. On Mac OS, the characters to be Form D. On other
    /// platforms, the characters to be Form C.
    fn test_archive_string_normalization_nfc(data: &str) {
        if !set_checked_locale("en_US.UTF-8", b"\xC3\xA4", 0xE4) {
            skipping(
                "A test of string normalization for NFC requires a suitable \
                 locale; en_US.UTF-8 not available on this system",
            );
            return;
        }
        let mut c = make_convs(SCONV_SET_OPT_NORMALIZATION_C);
        let mut mstr = MString::default();

        for (line, nfc, nfd) in pattern_lines(data) {
            let (pc, pd) = (scan_unicode_pattern(nfc), scan_unicode_pattern(nfd));
            let ctx = format!("NFC({nfc}) NFD({nfd}):{line}");

            // Normalize an NFD string for import.
            assert_eq!(convert(&pd.utf8, &c.f8), pc.utf8, "NFD to NFC {ctx}");
            // Normalize an NFC string for import.
            assert_eq!(convert(&pc.utf8, &c.f8), pc.utf8, "NFC unchanged {ctx}");
            // Copy an NFC string for export.
            assert_eq!(convert(&pc.utf8, &c.t8), pc.utf8, "NFC export {ctx}");
            // Normalize an NFD string in UTF-16BE for import.
            assert_eq!(convert(&pd.utf16be, &c.f16be), pc.utf8, "UTF-16BE {ctx}");
            // Normalize an NFD string in UTF-16LE for import.
            assert_eq!(convert(&pd.utf16le, &c.f16le), pc.utf8, "UTF-16LE {ctx}");

            // Test for archive_mstring interface.
            for (src, sc) in [
                (&pd.utf8, &c.f8),
                (&pd.utf16be, &c.f16be),
                (&pd.utf16le, &c.f16le),
            ] {
                assert!(mstr.copy_mbs_len_l(src, Some(sc)).is_ok());
                let wp = mstr.get_wcs(Some(&mut c.a)).unwrap().unwrap();
                assert_eq!(wp, pc.wc, "to WCS NFC {ctx}");
            }
            // Copy an NFC wide-string for export.
            mstr.copy_wcs(&pc.wc);
            let (mp, ok) = mstr.get_mbs_l(Some(&mut c.a), Some(&c.t8));
            assert!(ok);
            assert_eq!(mp, Some(&pc.utf8[..]), "WCS NFC to UTF-8 {ctx}");
        }
    }

    fn test_archive_string_normalization_mac_nfd(data: &str) {
        if !set_checked_locale("en_US.UTF-8", b"\xC3\xA4", 0xE4) {
            skipping(
                "A test of string normalization for NFD requires a suitable \
                 locale; en_US.UTF-8 not available on this system",
            );
            return;
        }
        let mut c = make_convs(SCONV_SET_OPT_NORMALIZATION_D);
        let mut mstr = MString::default();

        for (line, nfc, nfd) in pattern_lines(data) {
            let (pc, pd) = (scan_unicode_pattern(nfc), scan_unicode_pattern(nfd));
            let should_be_nfc = pc.mac_keeps_nfc;
            let ctx = format!("NFC({nfc}) NFD({nfd}):{line}");
            let (exp_utf8, exp_wc) = if should_be_nfc {
                (&pc.utf8, &pc.wc)
            } else {
                (&pd.utf8, &pd.wc)
            };

            // Normalize an NFC string for import.
            assert_eq!(&convert(&pc.utf8, &c.f8), exp_utf8, "NFC import {ctx}");
            // Normalize an NFD string for import.
            assert_eq!(convert(&pd.utf8, &c.f8), pd.utf8, "NFD unchanged {ctx}");
            // Copy an NFD string for export.
            assert_eq!(convert(&pd.utf8, &c.t8), pd.utf8, "NFD export {ctx}");
            // Normalize an NFC string in UTF-16BE/LE for import.
            assert_eq!(&convert(&pc.utf16be, &c.f16be), exp_utf8, "UTF-16BE {ctx}");
            assert_eq!(&convert(&pc.utf16le, &c.f16le), exp_utf8, "UTF-16LE {ctx}");

            // Test for archive_mstring interface.
            for (src, sc) in [
                (&pc.utf8, &c.f8),
                (&pc.utf16be, &c.f16be),
                (&pc.utf16le, &c.f16le),
            ] {
                assert!(mstr.copy_mbs_len_l(src, Some(sc)).is_ok());
                let wp = mstr.get_wcs(Some(&mut c.a)).unwrap().unwrap();
                assert_eq!(wp, &exp_wc[..], "to WCS {ctx}");
            }
            // Copy an NFD wide-string for export.
            mstr.copy_wcs(&pd.wc);
            let (mp, ok) = mstr.get_mbs_l(Some(&mut c.a), Some(&c.t8));
            assert!(ok);
            assert_eq!(mp, Some(&pd.utf8[..]), "WCS NFD to UTF-8 {ctx}");
        }
    }

    fn test_archive_string_canonicalization() {
        let _ = set_locale_all("en_US.UTF-8");
        let mut a = cache();
        for (name, exp) in [
            ("UTF-8", "UTF-8"),
            ("UTF8", "UTF-8"),
            ("utf8", "UTF-8"),
            ("UTF-16BE", "UTF-16BE"),
            ("UTF16BE", "UTF-16BE"),
            ("utf16be", "UTF-16BE"),
            ("UTF-16LE", "UTF-16LE"),
            ("UTF16LE", "UTF-16LE"),
            ("utf16le", "UTF-16LE"),
        ] {
            let sc = conversion_to_charset(Some(&mut a), name.as_bytes(), true).unwrap();
            assert_eq!(
                conversion_charset_name(Some(&sc)),
                exp.as_bytes(),
                "Charset name should be {exp}"
            );
        }
    }

    fn check_string(
        a: &mut ConvCache,
        mstr: &MString,
        sc: &StringConv,
        exp: &str,
        wexp: &[wchar_t],
    ) {
        // Do all the tests on a copy so that we can have a clear initial
        // state every time.
        let mut m = mstr.clone();
        assert_eq!(m.get_mbs(Some(a)).unwrap(), Some(exp.as_bytes()));
        let mut m = mstr.clone();
        assert_eq!(
            m.get_utf8_c(Some(a)).unwrap().map(CStr::to_bytes),
            Some(exp.as_bytes())
        );
        let mut m = mstr.clone();
        assert_eq!(m.get_wcs(Some(a)).unwrap(), Some(wexp));
        let mut m = mstr.clone();
        assert_eq!(m.get_mbs_l(Some(a), Some(sc)), (Some(exp.as_bytes()), true));
    }

    /// Make sure no matter what the input encoding is, the string can be
    /// converted too all the output encodings.
    fn test_archive_string_set_get() {
        let _ = set_locale_all("en_US.UTF-8");
        let mut a = cache();
        let mut mstr = MString::default();
        let sc = conversion_to_charset(Some(&mut a), b"UTF-8", true).unwrap();
        assert_eq!(conversion_charset_name(Some(&sc)), b"UTF-8");

        mstr.copy_mbs(b"AAA");
        check_string(&mut a, &mstr, &sc, "AAA", &wide("AAA"));
        assert_eq!(mstr.copy_utf8(b"BBBB"), 4);
        check_string(&mut a, &mstr, &sc, "BBBB", &wide("BBBB"));
        mstr.copy_wcs(&wide("CCC12"));
        check_string(&mut a, &mstr, &sc, "CCC12", &wide("CCC12"));
        assert!(mstr.copy_mbs_len_l(b"DDDD-l", Some(&sc)).is_ok());
        check_string(&mut a, &mstr, &sc, "DDDD-l", &wide("DDDD-l"));
        assert!(mstr.update_utf8(None, b"EEEEE---H").is_ok());
        check_string(&mut a, &mstr, &sc, "EEEEE---H", &wide("EEEEE---H"));
    }

    #[test]
    fn test_archive_string_conversion() {
        let _g = lock_locale();
        // Upstream extracts test_archive_string_conversion.txt.Z with its
        // own reader; here the .uu is decoded and the .Z decompressed by
        // the system gzip.
        let data = load_normalization_data();
        assert!(data.lines().count() > 18000, "pattern file truncated");
        test_archive_string_normalization_nfc(&data);
        test_archive_string_normalization_mac_nfd(&data);
        test_archive_string_canonicalization();
        test_archive_string_set_get();
    }

    #[test]
    fn test_archive_string_conversion_fail_charset() {
        // Conversion error message construction may use the charset name.
        assert_eq!(conversion_charset_name(None), b"current locale");

        let _g = lock_locale();
        let _ = set_locale_all("C");
        let mut a = cache();
        let err = conversion_to_charset(Some(&mut a), b"NO-SUCH-CHARSET", false)
            .err()
            .unwrap();
        assert_eq!(err.errno, ARCHIVE_ERRNO_MISC);
        assert_eq!(
            err.message,
            b"iconv_open failed: Cannot handle ``NO-SUCH-CHARSET''"
        );
    }

    fn test_archive_string_conversion_fail_utf16_mbs(
        a: &mut ConvCache,
        sconv: Option<&StringConv>,
    ) {
        // "\U0000043f\U00000440\U00000438"
        let wcs_string = wide("\u{43f}\u{440}\u{438}");

        // WCS to MBS should fail.
        assert!(!charset::wide_to_mb(&wcs_string, &mut Vec::new()));
        for sc in [None, sconv] {
            let mut mstr = MString::default();
            mstr.copy_wcs(&wcs_string);
            let (_, ok) = mstr.get_mbs_l(Some(a), sc);
            assert!(!ok);
            assert_eq!(mstr.set & AES_SET_MBS, 0);
        }
    }

    fn test_archive_string_conversion_fail_utf8_mbs(a: &mut ConvCache, sconv: Option<&StringConv>) {
        let utf8_string = b"\xD0\xBF\xD1\x80\xD0\xB8";
        // UTF-8 to MBS should fail.
        for sc in [None, sconv] {
            let mut mstr = MString::default();
            assert_eq!(mstr.copy_utf8(utf8_string), 6);
            let (_, ok) = mstr.get_mbs_l(Some(a), sc);
            assert!(!ok);
            assert_eq!(mstr.set & AES_SET_MBS, 0);
        }
    }

    #[test]
    fn test_archive_string_conversion_fail_c() {
        let _g = lock_locale();
        // Test the C locale.
        let _ = set_locale_all("C");
        let mut a = cache();
        test_archive_string_conversion_fail_utf16_mbs(&mut a, None);
        test_archive_string_conversion_fail_utf8_mbs(&mut a, None);
    }

    #[test]
    fn test_archive_string_conversion_fail_latin1() {
        let _g = lock_locale();
        // Test a Latin-1 locale.
        if !set_checked_locale("en_US.ISO8859-1", b"\xA0", 0xA0) {
            skipping("No Latin-1 locale found on this system.");
            return;
        }
        let mut a = cache();
        let mut name = &b"ISO8859-1"[..];
        let mut sconv = conversion_to_charset(Some(&mut a), name, false);
        if sconv.is_err() {
            name = b"ISO-8859-1";
            sconv = conversion_to_charset(Some(&mut a), name, false);
        }
        let sconv = sconv.unwrap();
        assert_eq!(conversion_charset_name(Some(&sconv)), name);
        test_archive_string_conversion_fail_utf16_mbs(&mut a, Some(&sconv));
        test_archive_string_conversion_fail_utf8_mbs(&mut a, Some(&sconv));
    }

    // test_archive_string_conversion_utf16_utf8, _utf8_utf16 and
    // test_archive_string_update_utf8_win only run on Windows; upstream
    // skips them elsewhere with "This test is meant to verify unicode
    // string handling on Windows".

    #[test]
    fn test_archive_string_update_utf8_utf8() {
        let _g = lock_locale();
        let utf8_string = b"\xD0\xBF\xD1\x80\xD0\xB8";
        let wcs_string = wide("\u{43f}\u{440}\u{438}");
        if !set_checked_locale("en_US.UTF-8", b"\xC3\xA4", 0xE4) {
            skipping("UTF-8 not supported on this system.");
            return;
        }
        let mut mstr = MString::default();
        // All conversions should have succeeded
        assert!(mstr.update_utf8(None, utf8_string).is_ok());
        assert_eq!(mstr.set, AES_SET_MBS | AES_SET_WCS | AES_SET_UTF8);
        assert_eq!(unterminated(&mstr.utf8), utf8_string);
        assert_eq!(unterminated(&mstr.mbs), utf8_string);
        assert_eq!(unterminated(&mstr.wcs), wcs_string);
    }

    #[test]
    fn test_archive_string_update_utf8_koi8() {
        let _g = lock_locale();
        let utf8_string = b"\xD0\xBF\xD1\x80\xD0\xB8";
        let koi8_string = b"\xD0\xD2\xC9";
        if !set_checked_locale("ru_RU.KOI8-R", b"\xE1", 0x0410) {
            skipping("KOI8-R locale not available on this system.");
            return;
        }
        if conversion_to_charset(Some(&mut cache()), b"UTF-8", false).is_err() {
            skipping("This system cannot convert character-set from KOI8-R to UTF-8.");
            return;
        }
        let mut mstr = MString::default();
        // All conversions should have succeeded
        assert!(mstr.update_utf8(None, utf8_string).is_ok());
        assert_eq!(mstr.set, AES_SET_MBS | AES_SET_WCS | AES_SET_UTF8);
        assert_eq!(unterminated(&mstr.utf8), utf8_string);
        assert_eq!(unterminated(&mstr.mbs), koi8_string);
        // No guarantee of how WCS strings behave, however this test is
        // primarily meant for Windows.
    }

    /// The part of test_archive_string_update_utf8_koi8 that does not
    /// depend on wchar_t being Unicode in a KOI8-R locale (it is not on
    /// macOS, where upstream skips the whole test).
    #[test]
    fn test_archive_string_update_utf8_koi8_iconv() {
        let _g = lock_locale();
        if !set_locale_all("ru_RU.KOI8-R") {
            skipping("KOI8-R locale not available on this system.");
            return;
        }
        let mut mstr = MString::default();
        assert!(mstr.update_utf8(None, b"\xD0\xBF\xD1\x80\xD0\xB8").is_ok());
        assert_eq!(unterminated(&mstr.mbs), b"\xD0\xD2\xC9");
        let sc = conversion_to_charset(None, b"UTF-8", true).unwrap();
        let (utf8, ok) = mstr.get_mbs_l(None, Some(&sc));
        assert!(ok);
        assert_eq!(utf8, Some(&b"\xD0\xBF\xD1\x80\xD0\xB8"[..]));
    }

    // -- test_archive_string_conversion_overread.c ------------------------

    /// archive_strncpy_l() passes a pointer and a byte count to the string
    /// conversion converter and does not require the buffer to be NUL
    /// terminated. The best-effort converter must therefore stop after the
    /// declared number of bytes.
    ///
    /// Requesting a conversion from a charset iconv cannot open selects
    /// best_effort_strncat_in_locale() with sc.same == false. If a
    /// platform's iconv unexpectedly accepts the name the conversion still
    /// succeeds and the assertions hold, so this never yields a false
    /// failure.
    #[test]
    fn test_archive_string_conversion_overread() {
        let _g = lock_locale();
        let mut a = cache();
        let sc = conversion_from_charset(Some(&mut a), b"NO-SUCH-CHARSET-8859", true).unwrap();

        // The buffer declares 8 bytes but is followed by 4 more non-NUL
        // bytes and then a NUL. A converter that honors the declared length
        // copies 8 bytes; the over-read walks on to the NUL and copies 12.
        let data = b"AAAAAAAABBBB\0";
        let mut out = Vec::new();
        assert!(strncpy_l(&mut out, &data[..8], Some(&sc)).is_ok());
        assert_eq!(out, b"AAAAAAAA");

        // Exact-length buffer with no trailing NUL.
        let buf = vec![b'A'; 8];
        assert!(strncpy_l(&mut out, &buf, Some(&sc)).is_ok());
        assert_eq!(out.len(), 8);
    }

    // -- ports of upstream behavior not covered by upstream's tests ---------

    #[test]
    fn utf8_to_utf8_replaces_invalid_and_pairs_surrogates() {
        let _g = lock_locale();
        let _ = set_locale_all("en_US.UTF-8");
        let sc = conversion_to_charset(None, b"UTF-8", true).unwrap();
        let mut out = Vec::new();
        // A CESU-8 surrogate pair becomes one 4-byte sequence.
        assert!(strncpy_l(&mut out, b"a\xED\xA0\x80\xED\xB0\x80b", Some(&sc)).is_ok());
        assert_eq!(out, b"a\xF0\x90\x80\x80b");
        // Invalid bytes become U+FFFD and the result is a failure.
        assert!(strncpy_l(&mut out, b"a\xFFb\xC3", Some(&sc)).is_err());
        assert_eq!(out, b"a\xEF\xBF\xBDb\xEF\xBF\xBD");
        // A lone surrogate is replaced.
        assert!(strncpy_l(&mut out, b"\xED\xA0\x80", Some(&sc)).is_err());
        assert_eq!(out, b"\xEF\xBF\xBD");
    }

    #[test]
    fn utf16_helpers() {
        assert_eq!(utf16_to_unicode(b"\xD8\x3D\xDE\x00", true), (4, 0x1F600));
        assert_eq!(utf16_to_unicode(b"\x3D\xD8\x00\xDE", false), (4, 0x1F600));
        assert_eq!(utf16_to_unicode(b"\xD8\x3D", true), (-2, UNICODE_R_CHAR));
        assert_eq!(
            utf16_to_unicode(b"\xDC\x00\x00\x41", true),
            (-2, UNICODE_R_CHAR)
        );
        assert_eq!(utf16_to_unicode(b"\x00", true), (-1, UNICODE_R_CHAR));
        assert_eq!(utf16_to_unicode(b"", true), (0, 0));
        assert_eq!(utf16nbytes(b"\x00A\x00B\x00\x00\x00C"), 4);
        assert_eq!(utf16nbytes(b"\x00A\x00"), 2);

        let _g = lock_locale();
        let _ = set_locale_all("en_US.UTF-8");
        let mut a = cache();
        let to = conversion_to_charset(Some(&mut a), b"UTF-16BE", true).unwrap();
        let mut out = Vec::new();
        assert!(strncpy_l(&mut out, "a\u{1F600}".as_bytes(), Some(&to)).is_ok());
        assert_eq!(out, b"\x00a\xD8\x3D\xDE\x00");
    }

    #[test]
    fn hangul_and_combining_marks() {
        let _g = lock_locale();
        let _ = set_locale_all("en_US.UTF-8");
        let mut out = Vec::new();
        let mut run = |converter: Converter, src: &str| {
            out.clear();
            let flag = SCONV_FROM_UTF8 | SCONV_TO_UTF8;
            let r = match converter {
                Converter::NormalizeC => normalize_c(&mut out, src.as_bytes(), flag),
                _ => normalize_d(&mut out, src.as_bytes(), flag),
            };
            assert_eq!(r, 0);
            String::from_utf8(out.clone()).unwrap()
        };
        assert_eq!(
            run(Converter::NormalizeC, "\u{1100}\u{1161}\u{11A8}"),
            "\u{AC01}"
        );
        assert_eq!(
            run(Converter::NormalizeD, "\u{AC01}"),
            "\u{1100}\u{1161}\u{11A8}"
        );
        assert_eq!(run(Converter::NormalizeC, "e\u{301}"), "\u{E9}");
        assert_eq!(run(Converter::NormalizeD, "\u{E9}"), "e\u{301}");
        // Canonical ordering of combining marks.
        assert_eq!(
            run(Converter::NormalizeD, "a\u{301}\u{323}"),
            "a\u{323}\u{301}"
        );
    }

    #[test]
    fn utf16_best_effort_keeps_normalization() {
        // Without iconv, the best-effort converter must still run after the
        // normalizer: "e" + U+0301 composes to U+00E9, which becomes '?'.
        let flag =
            SCONV_FROM_CHARSET | SCONV_BEST_EFFORT | SCONV_FROM_UTF16BE | SCONV_NORMALIZATION_C;
        let mut st = State {
            flag,
            converters: Vec::new(),
            cd: None,
        };
        st.setup_converter(false);
        assert_eq!(
            st.converters,
            [Converter::NormalizeC, Converter::BestEffortFromUtf16Be]
        );
        let mut tmp = Vec::new();
        assert_eq!(
            st.run(st.converters[0], &mut tmp, b"\x00e\x03\x01", false),
            0
        );
        let mut out = Vec::new();
        assert_eq!(st.run(st.converters[1], &mut out, &tmp, false), -1);
        assert_eq!(out, b"?");
    }

    #[test]
    fn mstring_forms_are_nul_terminated() {
        let _g = lock_locale();
        let _ = set_locale_all("en_US.UTF-8");
        let mut m = MString::default();
        m.copy_utf8(b"hi");
        assert_eq!(m.get_utf8_z(None).unwrap(), Some(&b"hi\0"[..]));
        assert_eq!(m.get_utf8_c(None).unwrap().unwrap().to_bytes(), b"hi");
        assert_eq!(m.get_mbs_c(None).unwrap().unwrap().to_bytes(), b"hi");
        assert_eq!(m.get_wcs_z(None).unwrap(), Some(&[0x68, 0x69, 0][..]));
        assert_eq!(m.get_mbs_l_z(None, None), (Some(&b"hi\0"[..]), true));
        // An already-set form is not rewritten by a getter.
        let before = m.get_utf8_z(None).unwrap().unwrap().as_ptr();
        let _ = m.get_wcs_z(None);
        assert_eq!(m.get_utf8_z(None).unwrap().unwrap().as_ptr(), before);
        let mut e = MString::default();
        assert_eq!(e.get_mbs_c(None).unwrap(), None);
        e.copy_mbs(b"");
        assert_eq!(e.get_mbs_z(None).unwrap(), Some(&b"\0"[..]));
    }

    /// Malformed input must never panic or hang, whatever the converter.
    #[test]
    fn malformed_input_does_not_panic() {
        let _g = lock_locale();
        let _ = set_locale_all("en_US.UTF-8");
        let mut a = cache();
        let mut convs: Vec<Arc<StringConv>> = Vec::new();
        for name in [
            &b"UTF-8"[..],
            b"UTF-16BE",
            b"UTF-16LE",
            b"ISO-8859-1",
            b"NO-SUCH-1",
        ] {
            convs.extend(conversion_from_charset(Some(&mut a), name, true));
            convs.extend(conversion_to_charset(Some(&mut a), name, true));
        }
        const BYTES: [u8; 24] = [
            0x00, 0x41, 0x7f, 0x80, 0xBF, 0xC0, 0xC2, 0xE0, 0xE1, 0xED, 0xA0, 0xB0, 0xEF, 0xF0,
            0xF4, 0xF5, 0xFF, 0x03, 0x11, 0x61, 0xD8, 0xDC, 0x09, 0xAC,
        ];
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut out = Vec::new();
        for opt in [
            0,
            SCONV_SET_OPT_NORMALIZATION_C,
            SCONV_SET_OPT_NORMALIZATION_D,
        ] {
            for sc in &convs {
                sc.set_opt(opt);
            }
            for _ in 0..7000 {
                let len = (next() % 24) as usize;
                let src: Vec<u8> = (0..len)
                    .map(|_| BYTES[(next() % BYTES.len() as u64) as usize])
                    .collect();
                for sc in &convs {
                    let _ = strncpy_l(&mut out, &src, Some(sc));
                }
                let mut m = MString::default();
                m.copy_utf8(&src);
                let _ = m.get_mbs(Some(&mut a));
                let _ = m.get_wcs(Some(&mut a));
                let _ = m.get_mbs_l(Some(&mut a), convs.first().map(|c| &**c));
            }
        }
    }
}
