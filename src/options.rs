/*-
 * Copyright (c) 2011 Tim Kientzle
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

// Ported from libarchive/archive_options.c.

//! Parsing and dispatch of `module:option=value` option strings, shared by
//! the read and write sides.
//!
//! The caller has already checked the handle's magic and state (they must be
//! `ARCHIVE_STATE_NEW`). A handler applies one option and answers with an
//! `ARCHIVE_*` code, or `UNKNOWN_MODULE` if no module has the requested name.

use crate::archive::*;
use crate::util::Error;
use std::ffi::c_int;

/// What a handler returns when the module name matched nothing:
/// `ARCHIVE_WARN - 1`.
pub const UNKNOWN_MODULE: c_int = ARCHIVE_WARN - 1;

/// Applies one option: `(module, option, value)`. A `None` value switches
/// the option off (`!option`).
pub type Handler<'a> = dyn FnMut(Option<&[u8]>, &[u8], Option<&[u8]>) -> c_int + 'a;

/// A message built from byte strings (names may not be UTF-8).
fn message(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `_archive_set_option`: one option, with module, option and value given
/// separately. Empty strings are the same as missing ones.
pub fn set_option(
    a: &Base,
    m: Option<&[u8]>,
    o: Option<&[u8]>,
    v: Option<&[u8]>,
    use_option: &mut Handler<'_>,
) -> c_int {
    fn non_empty(s: Option<&[u8]>) -> Option<&[u8]> {
        s.filter(|s| !s.is_empty())
    }
    let (mp, op, vp) = (non_empty(m), non_empty(o), non_empty(v));

    let Some(op) = op else {
        if vp.is_none() {
            return ARCHIVE_OK;
        }
        return a.raise(Error::new(ARCHIVE_FAILED, ARCHIVE_ERRNO_MISC, "Empty option"));
    };

    match use_option(mp, op, vp) {
        UNKNOWN_MODULE => a.raise(Error::new(
            ARCHIVE_FAILED,
            ARCHIVE_ERRNO_MISC,
            message(&[b"Unknown module name: `", mp.unwrap_or(b"(null)"), b"'"]),
        )),
        ARCHIVE_WARN => a.raise(Error::new(
            ARCHIVE_FAILED,
            ARCHIVE_ERRNO_MISC,
            message(&[
                b"Undefined option: `",
                if vp.is_some() { b"" } else { b"!" },
                mp.unwrap_or_default(),
                if mp.is_some() { b":" } else { b"" },
                op,
                if vp.is_some() { b"=" } else { b"" },
                vp.unwrap_or_default(),
                b"'",
            ]),
        )),
        r => r,
    }
}

/// `_archive_set_either_option`: offers the option to the format handler and
/// the filter handler, and combines their answers.
pub fn set_either_option(
    m: Option<&[u8]>,
    o: &[u8],
    v: Option<&[u8]>,
    use_format_option: &mut Handler<'_>,
    use_filter_option: &mut Handler<'_>,
) -> c_int {
    let r1 = use_format_option(m, o, v);
    if r1 == ARCHIVE_FATAL {
        return ARCHIVE_FATAL;
    }
    let r2 = use_filter_option(m, o, v);
    if r2 == ARCHIVE_FATAL {
        return ARCHIVE_FATAL;
    }
    if r1 == UNKNOWN_MODULE {
        return r2;
    }
    if r2 == UNKNOWN_MODULE {
        return r1;
    }
    r1.max(r2)
}

/// (module, option, value) of one item.
type Item<'a> = (Option<&'a [u8]>, &'a [u8], Option<&'a [u8]>);

/// One `[module:]option[=value]` or `[module:]!option` item. An item with
/// no text yields nothing.
fn parse_option(item: &[u8]) -> Option<Item<'_>> {
    if item.is_empty() {
        return None;
    }
    let (module, rest) = match item.iter().position(|&b| b == b':') {
        Some(i) => (Some(&item[..i]), &item[i + 1..]),
        None => (None, item),
    };
    Some(match rest.iter().position(|&b| b == b'=') {
        Some(i) => (module, &rest[..i], Some(&rest[i + 1..])),
        None => match rest.strip_prefix(b"!") {
            Some(opt) => (module, opt, None),
            None => (module, rest, Some(b"1".as_slice())),
        },
    })
}

/// `_archive_set_options`: a comma-separated list of options.
pub fn set_options(a: &Base, options: &[u8], use_option: &mut Handler<'_>) -> c_int {
    let (mut allok, mut anyok, mut ignore_mod_err) = (true, false, false);

    for item in options.split(|&b| b == b',') {
        let Some((mod_, opt, val)) = parse_option(item) else {
            // An empty item (",," or a trailing comma) reaches the handler
            // as an option with no name and no value, which
            // `set_either_option` answers with OK: it counts as one that
            // worked.
            anyok = true;
            continue;
        };
        if mod_.is_none() && opt == b"__ignore_wrong_module_name__" {
            // Ignore module name error.
            if val.is_some() {
                ignore_mod_err = true;
                anyok = true;
            }
            continue;
        }

        match use_option(mod_, opt, val) {
            ARCHIVE_FATAL => return ARCHIVE_FATAL,
            ARCHIVE_FAILED if mod_.is_some() => return ARCHIVE_FAILED,
            UNKNOWN_MODULE => {
                if ignore_mod_err {
                    continue;
                }
                // The module name is wrong.
                return a.raise(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    message(&[b"Unknown module name: `", mod_.unwrap_or(b"(null)"), b"'"]),
                ));
            }
            ARCHIVE_WARN => {
                // The option name is wrong. No-one used this.
                return a.raise(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    message(&[
                        b"Undefined option: `",
                        mod_.unwrap_or_default(),
                        if mod_.is_some() { b":" } else { b"" },
                        opt,
                        b"'",
                    ]),
                ));
            }
            ARCHIVE_OK => anyok = true,
            _ => allok = false,
        }
    }

    if allok {
        ARCHIVE_OK
    } else if anyok {
        ARCHIVE_WARN
    } else {
        ARCHIVE_FAILED
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    type Call = (Option<String>, String, Option<String>);

    fn s(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    /// A handler that records its calls and answers from `answers` (OK when
    /// they run out).
    fn recording(
        calls: &Rc<RefCell<Vec<Call>>>,
        answers: Vec<c_int>,
    ) -> Box<Handler<'static>> {
        let (calls, mut answers) = (Rc::clone(calls), answers.into_iter());
        Box::new(move |m, o, v| {
            calls.borrow_mut().push((m.map(s), s(o), v.map(s)));
            answers.next().unwrap_or(ARCHIVE_OK)
        })
    }

    fn error(a: &Base) -> String {
        a.error_string().map_or_else(String::new, |m| s(&m))
    }

    fn call(m: &str, o: &str, v: &str) -> Call {
        let opt = |x: &str| (!x.is_empty()).then(|| x.to_string());
        (opt(m), o.to_string(), opt(v))
    }

    #[test]
    fn single_option_arguments() {
        let a = Base::new(READ_MAGIC);
        let calls = Rc::default();
        let mut h = recording(&calls, vec![]);
        // Nothing to do; empty strings are missing.
        assert_eq!(set_option(&a, None, None, None, &mut h), ARCHIVE_OK);
        assert_eq!(set_option(&a, Some(b""), Some(b""), Some(b""), &mut h), ARCHIVE_OK);
        // A value without an option.
        assert_eq!(set_option(&a, None, None, Some(b"v"), &mut h), ARCHIVE_FAILED);
        assert_eq!((error(&a), a.errno.get()), ("Empty option".into(), ARCHIVE_ERRNO_MISC));
        assert_eq!(set_option(&a, Some(b"tar"), Some(b"x"), Some(b"y"), &mut h), ARCHIVE_OK);
        assert_eq!(set_option(&a, None, Some(b"x"), None, &mut h), ARCHIVE_OK);
        assert_eq!(*calls.borrow(), [call("tar", "x", "y"), call("", "x", "")]);
    }

    #[test]
    fn single_option_errors() {
        let a = Base::new(READ_MAGIC);
        let calls = Rc::default();
        let mut h = recording(&calls, vec![UNKNOWN_MODULE, ARCHIVE_WARN, ARCHIVE_WARN, ARCHIVE_FATAL]);
        assert_eq!(set_option(&a, Some(b"nomod"), Some(b"o"), None, &mut h), ARCHIVE_FAILED);
        assert_eq!(error(&a), "Unknown module name: `nomod'");
        assert_eq!(set_option(&a, Some(b"m"), Some(b"o"), Some(b"v"), &mut h), ARCHIVE_FAILED);
        assert_eq!(error(&a), "Undefined option: `m:o=v'");
        assert_eq!(set_option(&a, None, Some(b"o"), None, &mut h), ARCHIVE_FAILED);
        assert_eq!(error(&a), "Undefined option: `!o'");
        assert_eq!(set_option(&a, None, Some(b"o"), Some(b"v"), &mut h), ARCHIVE_FATAL);
    }

    #[test]
    fn options_string_is_split_into_items() {
        let a = Base::new(READ_MAGIC);
        let calls = Rc::default();
        let mut h = recording(&calls, vec![]);
        assert_eq!(
            set_options(&a, b"a,m:b=2,!c,m:!d,e=,=f,:g", &mut h),
            ARCHIVE_OK
        );
        let some = |s: &str| Some(s.to_string());
        assert_eq!(
            *calls.borrow(),
            [
                (None, "a".to_string(), some("1")),
                (some("m"), "b".to_string(), some("2")),
                (None, "c".to_string(), None),
                (some("m"), "d".to_string(), None),
                // `e=` is an empty value, `=f` an empty name, `:g` an empty
                // module.
                (None, "e".to_string(), some("")),
                (None, String::new(), some("f")),
                (some(""), "g".to_string(), some("1")),
            ]
        );
        // Empty items never reach the handler.
        calls.borrow_mut().clear();
        let mut h = recording(&calls, vec![]);
        assert_eq!(set_options(&a, b",a,,b,", &mut h), ARCHIVE_OK);
        assert_eq!(calls.borrow().len(), 2);
        // But they count as an option that worked: "a," with a failing
        // "a" is a warning, not a failure.
        assert_eq!(set_options(&a, b"a,", &mut recording(&calls, vec![ARCHIVE_FAILED])), ARCHIVE_WARN);
        assert_eq!(set_options(&a, b"a", &mut recording(&calls, vec![ARCHIVE_FAILED])), ARCHIVE_FAILED);
    }

    #[test]
    fn options_string_results() {
        let a = Base::new(READ_MAGIC);
        let run = |answers: Vec<c_int>, opts: &[u8]| {
            let calls = Rc::default();
            let r = set_options(&a, opts, &mut recording(&calls, answers));
            (r, calls.borrow().len())
        };
        assert_eq!(run(vec![], b""), (ARCHIVE_OK, 0));
        // Some failed, some did not.
        assert_eq!(run(vec![ARCHIVE_OK, ARCHIVE_FAILED], b"a,b"), (ARCHIVE_WARN, 2));
        assert_eq!(run(vec![ARCHIVE_FAILED, ARCHIVE_FAILED], b"a,b"), (ARCHIVE_FAILED, 2));
        // A failure for a named module is final.
        assert_eq!(run(vec![ARCHIVE_FAILED], b"m:a,b"), (ARCHIVE_FAILED, 1));
        assert_eq!(run(vec![ARCHIVE_FATAL], b"a,b"), (ARCHIVE_FATAL, 1));
        // Unknown option and unknown module.
        assert_eq!(run(vec![ARCHIVE_WARN], b"m:a,b"), (ARCHIVE_FAILED, 1));
        assert_eq!(error(&a), "Undefined option: `m:a'");
        assert_eq!(run(vec![UNKNOWN_MODULE], b"m:a,b"), (ARCHIVE_FAILED, 1));
        assert_eq!(error(&a), "Unknown module name: `m'");
        // The pseudo-option that makes unknown modules harmless.
        assert_eq!(
            run(vec![UNKNOWN_MODULE, ARCHIVE_OK], b"__ignore_wrong_module_name__,m:a,b"),
            (ARCHIVE_OK, 2)
        );
        // Only with a value.
        assert_eq!(
            run(vec![], b"!__ignore_wrong_module_name__"),
            (ARCHIVE_OK, 0)
        );
    }

    #[test]
    fn either_handler_combines_answers() {
        let mut ok = |_: Option<&[u8]>, _: &[u8], _: Option<&[u8]>| ARCHIVE_OK;
        let mut warn = |_: Option<&[u8]>, _: &[u8], _: Option<&[u8]>| ARCHIVE_WARN;
        let mut unknown = |_: Option<&[u8]>, _: &[u8], _: Option<&[u8]>| UNKNOWN_MODULE;
        let mut unknown2 = |_: Option<&[u8]>, _: &[u8], _: Option<&[u8]>| UNKNOWN_MODULE;
        let mut fatal = |_: Option<&[u8]>, _: &[u8], _: Option<&[u8]>| ARCHIVE_FATAL;
        assert_eq!(set_either_option(None, b"o", None, &mut ok, &mut warn), ARCHIVE_OK);
        assert_eq!(set_either_option(None, b"o", None, &mut warn, &mut ok), ARCHIVE_OK);
        assert_eq!(set_either_option(None, b"o", None, &mut unknown, &mut warn), ARCHIVE_WARN);
        assert_eq!(set_either_option(None, b"o", None, &mut ok, &mut unknown), ARCHIVE_OK);
        assert_eq!(set_either_option(None, b"o", None, &mut unknown, &mut unknown2), UNKNOWN_MODULE);
        assert_eq!(set_either_option(None, b"o", None, &mut fatal, &mut ok), ARCHIVE_FATAL);
        assert_eq!(set_either_option(None, b"o", None, &mut ok, &mut fatal), ARCHIVE_FATAL);
    }
}
