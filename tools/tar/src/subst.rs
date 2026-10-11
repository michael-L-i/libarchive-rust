/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2008 Joerg Sonnenberger
 * All rights reserved.
 */

// Ported from tar/subst.c.

//! -s rewrites of pathnames, with POSIX basic regular expressions as libc
//! has them.

use crate::Bsdtar;
use libarchive_fe::lafe_err::lafe_errc;
use libarchive_fe::sys::Regex;
use std::ffi::{CStr, CString};
use std::io::Write;

/// The compile flags: basic regular expressions, macOS's `REG_BASIC`.
const REG_BASIC: i32 = 0;

struct SubstRule {
    re: Regex,
    result: Vec<u8>,
    global: bool,
    print: bool,
    regular: bool,
    symlink: bool,
    hardlink: bool,
    from_begin: bool,
}

/// `struct substitution`: the rules, in the order given.
#[derive(Default)]
pub struct Substitution {
    rules: Vec<SubstRule>,
}

/// Whether `s[delim]` is escaped by the backslashes before it, back to
/// `start`.
fn is_escaped(s: &[u8], start: usize, delim: usize) -> bool {
    if s[delim] == b'\\' {
        return false;
    }
    let backslashes = s[start..delim]
        .iter()
        .rev()
        .take_while(|&&c| c == b'\\')
        .count();
    backslashes % 2 == 1
}

pub fn add_substitution(bsdtar: &mut Bsdtar, rule_text: &[u8]) {
    let Some(&delim) = rule_text.first() else {
        lafe_errc(1, 0, "Empty replacement string");
    };
    let missing = |after: &str| -> ! {
        let msg = [
            b"Invalid replacement string \"".as_slice(),
            rule_text,
            b"\": missing closing delimiter '",
            &[delim],
            b"' after ",
            after.as_bytes(),
        ];
        lafe_errc(1, 0, msg.concat())
    };
    let find = |from: usize| {
        let at = rule_text[from..].iter().position(|&c| c == delim);
        at.map(|at| from + at)
    };
    let Some(mut end_pattern) = find(1) else {
        missing("pattern");
    };

    let re = match Regex::new(&rule_text[1..end_pattern], REG_BASIC) {
        Ok(re) => re,
        Err(mut msg) => {
            // regerror into an 80-byte buffer.
            msg.truncate(79);
            lafe_errc(
                1,
                0,
                [b"Invalid regular expression: ".as_slice(), &msg].concat(),
            )
        }
    };

    let start_subst = end_pattern + 1;
    loop {
        end_pattern = find(end_pattern + 1).unwrap_or_else(|| missing("replacement"));
        if !is_escaped(rule_text, start_subst, end_pattern) {
            break;
        }
    }

    let mut result = Vec::new();
    let mut q = start_subst;
    while q < end_pattern {
        if rule_text[q] == b'\\' && delim != b'\\' {
            q += 1;
        }
        if q == end_pattern {
            missing("replacement");
        }
        result.push(rule_text[q]);
        q += 1;
    }

    let mut rule = SubstRule {
        re,
        result,
        global: false,     // Don't do multiple replacements.
        print: false,      // Don't print.
        regular: true,     // Rewrite regular filenames.
        symlink: true,     // Rewrite symlink targets.
        hardlink: true,    // Rewrite hardlink targets.
        from_begin: false, // Don't match from start.
    };

    for &flag in &rule_text[end_pattern + 1..] {
        match flag {
            b'b' | b'B' => rule.from_begin = true,
            b'g' | b'G' => rule.global = true,
            b'h' => rule.hardlink = true,
            b'H' => rule.hardlink = false,
            b'p' | b'P' => rule.print = true,
            b'r' => rule.regular = true,
            b'R' => rule.regular = false,
            b's' => rule.symlink = true,
            b'S' => rule.symlink = false,
            _ => lafe_errc(
                1,
                0,
                [b"Invalid replacement flag ".as_slice(), &[flag]].concat(),
            ),
        }
    }
    let subst = bsdtar
        .substitution
        .get_or_insert_with(Substitution::default);
    subst.rules.push(rule);
}

/// `name` with the rules for its kind applied: `None` if none matched,
/// `Err` if a rule refers to a subexpression its pattern lacks.
pub fn apply_substitution(
    bsdtar: &Bsdtar,
    name: &[u8],
    symlink_target: bool,
    hardlink_target: bool,
) -> Result<Option<Vec<u8>>, ()> {
    let Some(subst) = &bsdtar.substitution else {
        return Ok(None);
    };
    let path = name;
    let mut result: Option<Vec<u8>> = None;
    // The text the rules match, as a C string, and where the next match
    // starts in it.
    let mut buffer = CString::new(name).unwrap_or_default().into_bytes_with_nul();
    let mut name = 0;
    let mut got_match = false;
    let mut print_match = false;

    for rule in &subst.rules {
        let wanted = if symlink_target {
            rule.symlink
        } else if hardlink_target {
            rule.hardlink
        } else {
            // Regular filename.
            rule.regular
        };
        if !wanted {
            continue;
        }

        if rule.from_begin
            && let Some(result) = &mut result
        {
            result.extend_from_slice(&buffer[name..buffer.len() - 1]);
            buffer = [result.as_slice(), b"\0"].concat();
            name = 0;
            result.clear();
        }

        loop {
            let rest = &buffer[name..];
            let is_end = rest == b"\0";
            let Some(matches) = CStr::from_bytes_with_nul(rest)
                .ok()
                .and_then(|s| rule.re.exec::<10>(s))
            else {
                break;
            };
            // The text of a match or subexpression: empty for one that
            // matched nothing.
            let text = |(so, eo): (isize, isize)| match (usize::try_from(so), usize::try_from(eo)) {
                (Ok(so), Ok(eo)) => rest.get(so..eo).unwrap_or_default(),
                _ => &[],
            };
            let (so, eo) = matches[0];

            got_match = true;
            print_match |= rule.print;
            let out = result.get_or_insert_with(Vec::new);
            out.extend_from_slice(&rest[..so.max(0) as usize]);

            let r = &rule.result;
            let (mut i, mut j) = (0, 0);
            while i < r.len() {
                if r[i] == b'~' {
                    out.extend_from_slice(&r[j..i]);
                    out.extend_from_slice(text(matches[0]));
                    j = i + 1;
                    i += 1;
                    continue;
                }
                if r[i] != b'\\' {
                    i += 1;
                    continue;
                }

                i += 1;
                let Some(&c) = r.get(i) else {
                    break;
                };
                match c {
                    b'~' | b'\\' => {
                        out.extend_from_slice(&r[j..i - 1]);
                        j = i;
                    }
                    b'1'..=b'9' => {
                        out.extend_from_slice(&r[j..i - 1]);
                        let n = usize::from(c - b'0');
                        if n > rule.re.nsub() {
                            return Err(());
                        }
                        out.extend_from_slice(text(matches[n]));
                        j = i + 1;
                    }
                    // Just continue.
                    _ => {}
                }
                i += 1;
            }

            out.extend_from_slice(&r[j..]);
            if eo > 0 {
                name += eo as usize;
            } else if !is_end {
                // We skip a character because the match is 0-length so we
                // need to add it to the output.
                out.push(rest[0]);
                name += 1;
            }
            // Testing one step after because sed et al. run 0-length
            // patterns a last time on the empty string at the end.
            if !rule.global || is_end {
                break;
            }
        }
    }

    if !got_match {
        return Ok(None);
    }
    let mut result = result.unwrap_or_default();
    result.extend_from_slice(&buffer[name..buffer.len() - 1]);

    if print_match {
        let line = [path, b" >> ", &result, b"\n"].concat();
        let _ = std::io::stderr().write_all(&line);
    }
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(rules: &[&str], name: &str) -> Result<Option<String>, ()> {
        let mut bsdtar = Bsdtar::default();
        for rule in rules {
            add_substitution(&mut bsdtar, rule.as_bytes());
        }
        let r = apply_substitution(&bsdtar, name.as_bytes(), false, false)?;
        Ok(r.map(|r| String::from_utf8(r).unwrap()))
    }

    #[test]
    fn rules_rewrite_as_upstream_does() {
        // The results of C bsdtar -s at the pin.
        let some = |s: &str| Ok(Some(s.to_string()));
        assert_eq!(rewrite(&[], "in/abc"), Ok(None));
        assert_eq!(rewrite(&["/x/y/"], "in/abc"), Ok(None));
        assert_eq!(rewrite(&["/b/[~]/"], "in/abc"), some("in/a[b]c"));
        assert_eq!(rewrite(&["/[a-c]/&/g"], "in/abc"), some("in/&&&"));
        assert_eq!(rewrite(&[",x*,-,g"], "in/abc"), some("-i-n-/-a-b-c-"));
        assert_eq!(rewrite(&["/c$//"], "in/abc"), some("in/ab"));
        assert_eq!(rewrite(&["/.*//"], "in/abc"), some(""));
        // Copying the replacement drops a backslash, so it takes two to
        // escape.
        assert_eq!(
            rewrite(&["/\\(a\\)\\(b\\)/\\2\\1/"], "in/abc"),
            some("in/21c")
        );
        assert_eq!(
            rewrite(&["/\\(a\\)\\(b\\)/\\\\2\\\\1/"], "in/abc"),
            some("in/bac")
        );
        assert_eq!(rewrite(&["/b/\\~\\\\/"], "in/abc"), some("in/ab\\c"));
        assert_eq!(rewrite(&["/b/\\\\1/"], "in/abc"), Err(()));
        // A rule from the beginning sees what the rules before made.
        assert_eq!(rewrite(&["/n/N/", "/^iN/X/"], "in/abc"), some("iN/abc"));
        assert_eq!(rewrite(&["/n/N/", "/^iN/X/b"], "in/abc"), some("X/abc"));
    }
}
