/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2003-2008 Tim Kientzle
 * All rights reserved.
 */

// Ported from unzip/cmdline.c.

//! Command line parser for bsdunzip.

use crate::{Bsdunzip, OPTION_VERSION};
use libarchive_fe::lafe_err::lafe_warnc;
use std::ffi::c_int;

/// Short options for bsdunzip. Please keep this sorted.
const SHORT_OPTIONS: &[u8] = b"aCcd:fI:jLlnO:opP:qtuvx:yZ:";

/// A long option and the short option it is.
struct BsdunzipOption {
    name: &'static [u8],
    /// Whether this option requires an argument.
    required: bool,
    /// Equivalent short option.
    equivalent: c_int,
}

/// Long options for bsdunzip. Please keep this list sorted.
///
/// The symbolic names for options that lack a short equivalent are defined
/// in bsdunzip.rs. Also note that so far I've found no need to support
/// optional arguments to long options. That would be a small change to the
/// code below.
const BSDUNZIP_LONGOPTS: &[BsdunzipOption] = &[BsdunzipOption {
    name: b"version",
    required: false,
    equivalent: OPTION_VERSION,
}];

/// Where `bsdunzip_getopt` is in the command line.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    Start,
    NextWord,
    Short,
    Long,
}

impl Bsdunzip {
    /// `bsdunzip_getopt`: the next option, as its short option or
    /// `OPTION_VERSION`, or `'?'` for one that isn't valid. `None` at the
    /// end of the options; the words left in `argv` are what follows them.
    pub fn getopt(&mut self) -> Option<c_int> {
        loop {
            const LONG_PREFIX: &[u8] = b"--";
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
                self.getopt_state = State::NextWord;
                self.argument = Some(std::mem::take(&mut self.getopt_word));
                return Some(c_int::from(opt));
            }

            // We're reading a long option.
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
                for popt in BSDUNZIP_LONGOPTS {
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
                    let msg = [b"Option ", LONG_PREFIX, word, b" is not supported"];
                    lafe_warnc(0, msg.concat());
                    return Some(c_int::from(b'?'));
                };
                if let Some(found2) = found2 {
                    let msg = [
                        b"Ambiguous option ".as_slice(),
                        LONG_PREFIX,
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
                                LONG_PREFIX,
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
                        LONG_PREFIX,
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

    /// The options `getopt` returns for `args`, their arguments, and the
    /// words left.
    #[allow(clippy::type_complexity)]
    fn parse(args: &[&str]) -> (Vec<(c_int, Option<Vec<u8>>)>, Vec<Vec<u8>>) {
        let words = std::iter::once("bsdunzip").chain(args.iter().copied());
        let mut bsdunzip = Bsdunzip {
            getopt_state: State::Start,
            getopt_word: Vec::new(),
            argv: words.map(|w| w.as_bytes().to_vec()).collect(),
            argument: None,
        };
        let mut opts = Vec::new();
        while let Some(c) = bsdunzip.getopt() {
            opts.push((c, bsdunzip.argument.clone()));
        }
        (opts, bsdunzip.argv.into())
    }

    fn arg(c: u8, a: &str) -> (c_int, Option<Vec<u8>>) {
        (c_int::from(c), Some(a.as_bytes().to_vec()))
    }

    fn flag(c: u8) -> (c_int, Option<Vec<u8>>) {
        (c_int::from(c), None)
    }

    #[test]
    fn options_end_at_the_first_name_or_dashdash() {
        assert_eq!(parse(&[]), (vec![], vec![]));
        assert_eq!(
            parse(&["-q", "f.zip", "-l"]),
            (vec![flag(b'q')], vec![b"f.zip".to_vec(), b"-l".to_vec()])
        );
        assert_eq!(parse(&["--", "-l"]), (vec![], vec![b"-l".to_vec()]));
    }

    #[test]
    fn short_options_group_and_take_run_in_or_next_arguments() {
        assert_eq!(parse(&["-qo"]).0, [flag(b'q'), flag(b'o')]);
        assert_eq!(parse(&["-qdout"]).0, [flag(b'q'), arg(b'd', "out")]);
        assert_eq!(
            parse(&["-d", "out", "-x"]).0,
            [arg(b'd', "out"), flag(b'?')]
        );
        assert_eq!(parse(&["-Z1"]).0, [arg(b'Z', "1")]);
        assert_eq!(parse(&["-Z", "-1"]).0, [arg(b'Z', "-1")]);
    }

    #[test]
    fn bad_short_options_are_questionable() {
        assert_eq!(parse(&["-qk"]).0, [flag(b'q'), flag(b'?')]);
        assert_eq!(parse(&["-:"]).0, [flag(b':')]);
        assert_eq!(parse(&["-d"]).0, [flag(b'?')]);
    }

    #[test]
    fn long_options_match_unambiguous_prefixes() {
        assert_eq!(parse(&["--version"]).0, [(OPTION_VERSION, None)]);
        assert_eq!(parse(&["--v"]).0, [(OPTION_VERSION, None)]);
        assert_eq!(parse(&["--versions"]).0, [flag(b'?')]);
        assert_eq!(parse(&["--version=1"]).0, [arg(b'?', "1")]);
        assert_eq!(parse(&["--help"]).0, [flag(b'?')]);
    }
}
