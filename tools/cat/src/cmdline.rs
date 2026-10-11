/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2003-2008 Tim Kientzle
 * All rights reserved.
 */

// Ported from cat/cmdline.c.

//! Command line parser for bsdcat.
//!
//! Apart from the "-W option=argument" GNU convention, an obscure
//! alternative to long options that early bsdtar supported and bsdcat
//! inherited, this is a straightforward option parser.

use crate::{Bsdcat, OPTION_VERSION};
use libarchive_fe::lafe_err::lafe_warnc;
use std::ffi::c_int;

/// Short options for bsdcat. Please keep this sorted.
const SHORT_OPTIONS: &[u8] = b"h";

/// A long option and the short option it is.
struct BsdcatOption {
    name: &'static [u8],
    /// Whether this option requires an argument.
    required: bool,
    /// Equivalent short option.
    equivalent: c_int,
}

/// Long options for bsdcat. Please keep this list sorted.
///
/// The symbolic names for options that lack a short equivalent are defined
/// in bsdcat.rs. Also note that so far I've found no need to support
/// optional arguments to long options. That would be a small change to the
/// code below.
const BSDCAT_LONGOPTS: &[BsdcatOption] = &[
    BsdcatOption {
        name: b"help",
        required: false,
        equivalent: b'h' as c_int,
    },
    BsdcatOption {
        name: b"version",
        required: false,
        equivalent: OPTION_VERSION,
    },
];

/// Where `bsdcat_getopt` is in the command line.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    Start,
    NextWord,
    Short,
    Long,
}

impl Bsdcat {
    /// `bsdcat_getopt`: the next option, as its short option or `OPTION_*`
    /// code, or `'?'` for one that isn't valid. `None` at the end of the
    /// options; the words left in `argv` are the file names.
    pub fn getopt(&mut self) -> Option<c_int> {
        loop {
            let mut long_prefix: &[u8] = b"--";
            self.argument = None;

            // First time through, initialize everything.
            if self.getopt_state == State::Start {
                // Skip program name.
                self.argv.pop_front();
                if self.argv.is_empty() {
                    return None;
                }
                self.getopt_state = State::NextWord;
            }

            // We're ready to look at the next word in argv.
            if self.getopt_state == State::NextWord {
                // No more arguments, so no more options.
                let word = self.argv.front()?;
                // Doesn't start with '-', so no more options.
                if word.first() != Some(&b'-') {
                    return None;
                }
                // "--" marks end of options; consume it and return.
                if word == b"--" {
                    self.argv.pop_front();
                    return None;
                }
                // Get next word for parsing.
                let mut word = self.argv.pop_front()?;
                if word.get(1) == Some(&b'-') {
                    // Set up long option parser.
                    self.getopt_state = State::Long;
                    self.getopt_word = word.split_off(2); // Skip leading '--'
                } else {
                    // Set up short option parser.
                    self.getopt_state = State::Short;
                    self.getopt_word = word.split_off(1); // Skip leading '-'
                }
            }

            // We're parsing a group of POSIX-style single-character options.
            if self.getopt_state == State::Short {
                // Peel next option off of a group of short options.
                if self.getopt_word.is_empty() {
                    // End of this group; recurse to get next option.
                    self.getopt_state = State::NextWord;
                    continue;
                }
                let opt = self.getopt_word.remove(0);

                // Does this option take an argument?
                let Some(p) = SHORT_OPTIONS.iter().position(|&c| c == opt) else {
                    return Some(c_int::from(b'?'));
                };
                if SHORT_OPTIONS.get(p + 1) != Some(&b':') {
                    return Some(c_int::from(opt));
                }

                // It does, so parse that. If it is run in, it is what is
                // left of the word; otherwise, pick up the next word.
                if self.getopt_word.is_empty() {
                    let Some(word) = self.argv.pop_front() else {
                        let msg = [b"Option -".as_slice(), &[opt], b" requires an argument"];
                        lafe_warnc(0, msg.concat());
                        return Some(c_int::from(b'?'));
                    };
                    self.getopt_word = word;
                }
                if opt != b'W' {
                    self.getopt_state = State::NextWord;
                    self.argument = Some(std::mem::take(&mut self.getopt_word));
                    return Some(c_int::from(opt));
                }
                self.getopt_state = State::Long;
                long_prefix = b"-W "; // For clearer errors.
            }

            // We're reading a long option, including -W long=arg convention.
            if self.getopt_state == State::Long {
                // After this long option, we'll be starting a new word.
                self.getopt_state = State::NextWord;

                // Option name ends at '=' if there is one.
                let word = &self.getopt_word;
                let optlength = match word.iter().position(|&c| c == b'=') {
                    Some(eq) => {
                        self.argument = word.get(eq + 1..).map(<[u8]>::to_vec);
                        eq
                    }
                    None => word.len(),
                };
                let name = word.get(..optlength).unwrap_or_default();

                // Search the table for an unambiguous match.
                let mut found = None;
                let mut found2 = None;
                for popt in BSDCAT_LONGOPTS {
                    // Short-circuit if first chars don't match.
                    if popt.name.first() != word.first() {
                        continue;
                    }
                    // If option is a prefix of name in table, record it.
                    if popt.name.starts_with(name) {
                        found2 = found; // Record up to two matches.
                        found = Some(popt);
                        // If it's an exact match, we're done.
                        if popt.name.len() == optlength {
                            found2 = None; // Forget the others.
                            break;
                        }
                    }
                }

                // Fail if there wasn't a unique match.
                let Some(found) = found else {
                    let msg = [b"Option ", long_prefix, word, b" is not supported"];
                    lafe_warnc(0, msg.concat());
                    return Some(c_int::from(b'?'));
                };
                if let Some(found2) = found2 {
                    let msg = [
                        b"Ambiguous option ".as_slice(),
                        long_prefix,
                        word,
                        b" (matches --",
                        found.name,
                        b" and --",
                        found2.name,
                        b")",
                    ];
                    lafe_warnc(0, msg.concat());
                    return Some(c_int::from(b'?'));
                }

                // We've found a unique match; does it need an argument?
                if found.required {
                    // Argument required: get next word if necessary.
                    if self.argument.is_none() {
                        self.argument = self.argv.pop_front();
                        if self.argument.is_none() {
                            let msg = [
                                b"Option ",
                                long_prefix,
                                found.name,
                                b" requires an argument",
                            ];
                            lafe_warnc(0, msg.concat());
                            return Some(c_int::from(b'?'));
                        }
                    }
                } else if self.argument.is_some() {
                    // Argument forbidden: fail if there is one.
                    let msg = [
                        b"Option ",
                        long_prefix,
                        found.name,
                        b" does not allow an argument",
                    ];
                    lafe_warnc(0, msg.concat());
                    return Some(c_int::from(b'?'));
                }
                return Some(found.equivalent);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The options `getopt` returns for `args`, and the file names left.
    fn parse(args: &[&str]) -> (Vec<c_int>, Vec<Vec<u8>>) {
        let words = std::iter::once("bsdcat").chain(args.iter().copied());
        let mut bsdcat = Bsdcat {
            getopt_state: State::Start,
            getopt_word: Vec::new(),
            argv: words.map(|w| w.as_bytes().to_vec()).collect(),
            argument: None,
        };
        let opts = std::iter::from_fn(|| bsdcat.getopt()).collect();
        (opts, bsdcat.argv.into())
    }

    const H: c_int = b'h' as c_int;
    const BAD: c_int = b'?' as c_int;

    #[test]
    fn options_end_at_the_first_name_or_dashdash() {
        assert_eq!(parse(&[]), (vec![], vec![]));
        assert_eq!(
            parse(&["-h", "f", "-h"]),
            (vec![H], vec![b"f".to_vec(), b"-h".to_vec()])
        );
        assert_eq!(parse(&["--", "-h"]), (vec![], vec![b"-h".to_vec()]));
        // A lone "-" is an empty group of short options.
        assert_eq!(parse(&["-", "f"]), (vec![], vec![b"f".to_vec()]));
    }

    #[test]
    fn short_options_group_and_unknown_ones_are_bad() {
        assert_eq!(parse(&["-hh"]).0, [H, H]);
        assert_eq!(parse(&["-hx"]).0, [H, BAD]);
        assert_eq!(parse(&["-W"]).0, [BAD]);
    }

    #[test]
    fn long_options_match_unambiguous_prefixes() {
        assert_eq!(parse(&["--help"]).0, [H]);
        assert_eq!(parse(&["--he"]).0, [H]);
        assert_eq!(parse(&["--v"]).0, [OPTION_VERSION]);
        assert_eq!(parse(&["--helpme"]).0, [BAD]);
        assert_eq!(parse(&["--help=yes"]).0, [BAD]);
        assert_eq!(parse(&["--=x"]).0, [BAD]);
    }
}
