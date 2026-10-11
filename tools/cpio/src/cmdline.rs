/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2003-2007 Tim Kientzle
 * All rights reserved.
 */

// Ported from cpio/cmdline.c.

//! Command line parser for bsdcpio, and the parser of the `-R` argument.
//!
//! Apart from the "-W option=argument" GNU convention, an obscure
//! alternative to long options that early bsdtar supported and bsdcpio
//! inherited, this is a straightforward option parser.

use crate::{
    Cpio, OPTION_B64ENCODE, OPTION_GRZIP, OPTION_INSECURE, OPTION_LRZIP, OPTION_LZ4, OPTION_LZMA,
    OPTION_LZOP, OPTION_NO_PRESERVE_OWNER, OPTION_PASSPHRASE, OPTION_PRESERVE_OWNER, OPTION_QUIET,
    OPTION_UUENCODE, OPTION_VERSION, OPTION_ZSTD,
};
use libarchive_fe::lafe_err::lafe_warnc;
use libarchive_fe::sys;

/// Short options for cpio. Please keep this sorted.
const SHORT_OPTIONS: &[u8] = b"067AaBC:cdE:F:f:H:hI:iJjLlmnO:opR:rtuVvW:yZz";

/// A long option and the short option it is.
struct CpioOption {
    name: &'static [u8],
    /// Whether this option requires an argument.
    required: bool,
    /// Equivalent short option.
    equivalent: u8,
}

const fn opt(name: &'static [u8], required: bool, equivalent: u8) -> CpioOption {
    CpioOption {
        name,
        required,
        equivalent,
    }
}

/// Long options for cpio. Please keep this list sorted.
const CPIO_LONGOPTS: &[CpioOption] = &[
    opt(b"b64encode", false, OPTION_B64ENCODE),
    opt(b"binary", false, b'7'),
    opt(b"create", false, b'o'),
    opt(b"dereference", false, b'L'),
    opt(b"dot", false, b'V'),
    opt(b"extract", false, b'i'),
    opt(b"file", true, b'F'),
    opt(b"format", true, b'H'),
    opt(b"grzip", false, OPTION_GRZIP),
    opt(b"help", false, b'h'),
    opt(b"insecure", false, OPTION_INSECURE),
    opt(b"link", false, b'l'),
    opt(b"list", false, b't'),
    opt(b"lrzip", false, OPTION_LRZIP),
    opt(b"lz4", false, OPTION_LZ4),
    opt(b"lzma", false, OPTION_LZMA),
    opt(b"lzop", false, OPTION_LZOP),
    opt(b"make-directories", false, b'd'),
    opt(b"no-preserve-owner", false, OPTION_NO_PRESERVE_OWNER),
    opt(b"null", false, b'0'),
    opt(b"numeric-uid-gid", false, b'n'),
    opt(b"owner", true, b'R'),
    opt(b"passphrase", true, OPTION_PASSPHRASE),
    opt(b"pass-through", false, b'p'),
    opt(b"preserve-modification-time", false, b'm'),
    opt(b"preserve-owner", false, OPTION_PRESERVE_OWNER),
    opt(b"pwb", false, b'6'),
    opt(b"quiet", false, OPTION_QUIET),
    opt(b"unconditional", false, b'u'),
    opt(b"uuencode", false, OPTION_UUENCODE),
    opt(b"verbose", false, b'v'),
    opt(b"version", false, OPTION_VERSION),
    opt(b"xz", false, b'J'),
    opt(b"zstd", false, OPTION_ZSTD),
];

/// Where `cpio_getopt` is in the command line.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    Start,
    NextWord,
    Short,
    Long,
}

impl Cpio {
    /// I used to try to select platform-provided getopt() or
    /// getopt_long(), but that caused a lot of headaches. In particular,
    /// I couldn't consistently use long options in the test harness
    /// because not all platforms have getopt_long(). That in turn led to
    /// overuse of the -W hack in the test harness, which made it rough to
    /// run the test harness against GNU cpio. (I periodically run the
    /// test harness here against GNU cpio as a sanity-check. Yes, I've
    /// found a couple of bugs in GNU cpio that way.)
    ///
    /// `cpio_getopt`: the next option, as its short option or `OPTION_*`
    /// code, or `'?'` for one that isn't valid. `None` at the end of the
    /// options; the words left in `argv` are the arguments.
    pub fn getopt(&mut self) -> Option<u8> {
        loop {
            let mut long_prefix: &[u8] = b"--";
            self.argument = None;

            // First time through, initialize everything.
            if self.getopt_state == State::Start {
                // Skip program name.
                self.argv.pop_front();
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
                    return Some(b'?');
                };
                if SHORT_OPTIONS.get(p + 1) == Some(&b':') {
                    // It does, so parse that. If arg is run-in, it is what
                    // is left of the word; otherwise, pick up the next word.
                    if self.getopt_word.is_empty() {
                        let Some(word) = self.argv.pop_front() else {
                            let msg = [b"Option -".as_slice(), &[opt], b" requires an argument"];
                            lafe_warnc(0, msg.concat());
                            return Some(b'?');
                        };
                        self.getopt_word = word;
                    }
                    if opt == b'W' {
                        self.getopt_state = State::Long;
                        long_prefix = b"-W "; // For clearer errors.
                    } else {
                        self.getopt_state = State::NextWord;
                        self.argument = Some(std::mem::take(&mut self.getopt_word));
                        return Some(opt);
                    }
                } else {
                    return Some(opt);
                }
            }

            // We're reading a long option, including -W long=arg convention.
            if self.getopt_state == State::Long {
                // After this long option, we'll be starting a new word.
                self.getopt_state = State::NextWord;

                // Option name ends at '=' if there is one.
                let word = &self.getopt_word;
                let optlength = match word.iter().position(|&c| c == b'=') {
                    Some(eq) => {
                        self.argument = Some(word[eq + 1..].to_vec());
                        eq
                    }
                    None => word.len(),
                };
                let name = &word[..optlength];

                // Search the table for an unambiguous match.
                let mut found = None;
                let mut found2 = None;
                for popt in CPIO_LONGOPTS {
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
                    return Some(b'?');
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
                    return Some(b'?');
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
                            return Some(b'?');
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
                    return Some(b'?');
                }
                return Some(found.equivalent);
            }
        }
    }
}

/// `struct cpio_owner`: what a `-R` argument sets.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CpioOwner {
    pub uid: Option<i32>,
    pub gid: Option<i32>,
    pub uname: Option<Vec<u8>>,
    pub gname: Option<Vec<u8>>,
}

/// `strtoul(s, &end, 10)` as `owner_parse` and `-C` check it: the value if
/// `s` is all one decimal number that fits in an `int`. Negative numbers
/// are refused, though `strtoul` wraps them (to values the check refuses
/// too, bar -2^64+1 and the like).
pub fn parse_int(s: &[u8]) -> Option<i32> {
    let s = s.trim_ascii_start();
    let (negative, digits) = match s.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let value = digits.iter().try_fold(0u64, |v, &d| {
        v.checked_mul(10)?.checked_add(u64::from(d - b'0'))
    })?;
    if negative && value != 0 {
        return None;
    }
    i32::try_from(value).ok()
}

/// The message for a name that isn't one, which upstream formats into a
/// 128 byte buffer.
fn lookup_error(what: &[u8], name: &[u8]) -> Vec<u8> {
    let mut msg = [b"Couldn't lookup ", what, b" ``", name, b"''"].concat();
    msg.truncate(127);
    msg
}

/// Parse the argument to the -R or --owner flag.
///
/// The format is one of the following:
///   <username|uid>    - Override user but not group
///   <username>:   - Override both, group is user's default group
///   <uid>:    - Override user but not group
///   <username|uid>:<groupname|gid> - Override both
///   :<groupname|gid>  - Override group but not user
///
/// Where uid/gid are decimal representations and groupname/username
/// are names to be looked up in system database. Note that we try
/// to look up an argument as a name first, then try numeric parsing.
///
/// A period can be used instead of the colon.
///
/// Sets uid/gid return as appropriate, `None` indicates uid/gid not
/// specified.
/// TODO: If the spec uses uname/gname, then return those to the caller
/// as well. If the spec provides uid/gid, just return names as `None`.
///
/// Returns the error string for display if there is an error.
pub fn owner_parse(spec: &[u8]) -> Result<CpioOwner, Vec<u8>> {
    let mut owner = CpioOwner::default();

    if spec.is_empty() {
        return Err(b"Invalid empty user/group spec".to_vec());
    }

    // Split spec into [user][:.][group]
    //  user -> the username, None if no username
    //  g -> the group name
    let (user, ue, g) = if matches!(spec[0], b':' | b'.') {
        // If spec starts with ':' or '.', then just group.
        (None, 0, &spec[1..])
    } else {
        // Otherwise, [user] or [user][:] or [user][:][group]
        let ue = spec
            .iter()
            .position(|&c| matches!(c, b':' | b'.'))
            .unwrap_or(spec.len());
        // Skip : or . to find first char of group.
        (
            Some(&spec[..ue]),
            ue,
            spec.get(ue + 1..).unwrap_or_default(),
        )
    };

    if let Some(user) = user {
        if let Some((name, uid, gid)) = sys::getpwnam(user) {
            owner.uid = Some(uid as i32);
            owner.uname = Some(name);
            if ue < spec.len() {
                owner.gid = Some(gid as i32);
            }
        } else if let Some(uid) = parse_int(user) {
            owner.uid = Some(uid);
        } else {
            return Err(lookup_error(b"user", user));
        }
    }

    if !g.is_empty() {
        if let Some((name, gid)) = sys::getgrnam(g) {
            owner.gid = Some(gid as i32);
            owner.gname = Some(name);
        } else if let Some(gid) = parse_int(g) {
            owner.gid = Some(gid);
        } else {
            return Err(lookup_error(b"group", g));
        }
    }
    Ok(owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An option and its argument.
    type Parsed = (u8, Option<Vec<u8>>);

    /// The options `getopt` returns for `args`, with their arguments, and
    /// the words left.
    fn parse(args: &[&str]) -> (Vec<Parsed>, Vec<Vec<u8>>) {
        let words = std::iter::once("bsdcpio").chain(args.iter().copied());
        let mut cpio = Cpio::new(words.map(|w| w.as_bytes().to_vec()).collect());
        let opts =
            std::iter::from_fn(|| cpio.getopt().map(|o| (o, cpio.argument.take()))).collect();
        (opts, cpio.argv.into())
    }

    fn opts(args: &[&str]) -> Vec<u8> {
        parse(args).0.into_iter().map(|(o, _)| o).collect()
    }

    fn with(o: u8, arg: &str) -> Parsed {
        (o, Some(arg.as_bytes().to_vec()))
    }

    #[test]
    fn options_end_at_the_first_word_or_dashdash() {
        assert_eq!(parse(&[]), (vec![], vec![]));
        assert_eq!(
            parse(&["-i", "p", "-t"]),
            (vec![(b'i', None)], vec![b"p".to_vec(), b"-t".to_vec()])
        );
        assert_eq!(parse(&["--", "-i"]), (vec![], vec![b"-i".to_vec()]));
    }

    #[test]
    fn short_options_group_and_take_run_in_or_next_word_arguments() {
        assert_eq!(opts(&["-itv"]), [b'i', b't', b'v']);
        assert_eq!(opts(&["-iQ"]), [b'i', b'?']);
        assert_eq!(parse(&["-Hnewc"]).0, [with(b'H', "newc")]);
        assert_eq!(parse(&["-H", "newc"]).0, [with(b'H', "newc")]);
        assert_eq!(parse(&["-vC", "10", "x"]).1, [b"x".to_vec()]);
        assert_eq!(opts(&["-C"]), [b'?']);
    }

    #[test]
    fn long_options_match_unambiguous_prefixes() {
        assert_eq!(opts(&["--create", "--vers"]), [b'o', OPTION_VERSION]);
        assert_eq!(parse(&["--format=odc"]).0, [with(b'H', "odc")]);
        assert_eq!(parse(&["--format", "odc"]).0, [with(b'H', "odc")]);
        assert_eq!(opts(&["--l"]), [b'?'], "--link, --list, --lrzip, ... match");
        assert_eq!(opts(&["--li"]), [b'?']);
        assert_eq!(opts(&["--lin"]), [b'l']);
        assert_eq!(opts(&["--lz"]), [b'?']);
        assert_eq!(opts(&["--lzma"]), [OPTION_LZMA], "an exact match wins");
        assert_eq!(opts(&["--nope"]), [b'?']);
        assert_eq!(opts(&["--format"]), [b'?']);
        assert_eq!(opts(&["--null=1"]), [b'?']);
    }

    #[test]
    fn dash_w_takes_a_long_option() {
        assert_eq!(opts(&["-W", "create"]), [b'o']);
        assert_eq!(parse(&["-Wformat=odc"]).0, [with(b'H', "odc")]);
        assert_eq!(opts(&["-W", "nope"]), [b'?']);
    }

    #[test]
    fn numbers_are_decimal_ints() {
        assert_eq!(parse_int(b"512"), Some(512));
        assert_eq!(parse_int(b" +7"), Some(7));
        assert_eq!(parse_int(b"-0"), Some(0));
        assert_eq!(parse_int(b"2147483647"), Some(i32::MAX));
        assert_eq!(parse_int(b"2147483648"), None);
        assert_eq!(parse_int(b"99999999999999999999"), None);
        assert_eq!(parse_int(b"-1"), None);
        for bad in [&b""[..], b"+", b"0x10", b"1k", b"1 ", b"- 1"] {
            assert_eq!(parse_int(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn owners_are_ids_or_names() {
        let owner = |uid, gid| CpioOwner {
            uid,
            gid,
            ..CpioOwner::default()
        };
        assert_eq!(owner_parse(b"12"), Ok(owner(Some(12), None)));
        assert_eq!(owner_parse(b"12:"), Ok(owner(Some(12), None)));
        assert_eq!(owner_parse(b"12.34"), Ok(owner(Some(12), Some(34))));
        assert_eq!(owner_parse(b":34"), Ok(owner(None, Some(34))));
        assert_eq!(owner_parse(b".34"), Ok(owner(None, Some(34))));
        assert_eq!(
            owner_parse(b"").unwrap_err(),
            b"Invalid empty user/group spec"
        );
        assert_eq!(
            owner_parse(b"no such user").unwrap_err(),
            b"Couldn't lookup user ``no such user''"
        );
        assert_eq!(
            owner_parse(b"1:no such group").unwrap_err(),
            b"Couldn't lookup group ``no such group''"
        );
        // The message is cut to upstream's 128 byte buffer.
        let long = [b"1:".as_slice(), &[b'x'; 200]].concat();
        assert_eq!(owner_parse(&long).unwrap_err().len(), 127);
        let root = owner_parse(b"root").unwrap();
        assert_eq!((root.uid, root.uname), (Some(0), Some(b"root".to_vec())));
        assert_eq!(root.gid, None, "no colon, no group");
        let root = owner_parse(b"root:").unwrap();
        assert!(root.gid.is_some(), "a colon takes the user's group");
    }
}
