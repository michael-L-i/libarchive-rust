/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2003-2008 Tim Kientzle
 * All rights reserved.
 */

// Ported from tar/cmdline.c.

//! Command line parser for tar.

use crate::*;
use libarchive_fe::lafe_err::lafe_warnc;

/// Short options for tar. Please keep this sorted.
const SHORT_OPTIONS: &[u8] = b"aBb:C:cf:HhI:JjkLlmnOoPpqrSs:T:tUuvW:wX:xyZz";

/// A long option and the short option it is.
struct BsdtarOption {
    name: &'static [u8],
    /// Whether this option requires an argument.
    required: bool,
    /// Equivalent short option.
    equivalent: char,
}

/// Long options for tar. Please keep this list sorted.
///
/// The symbolic names for options that lack a short equivalent are defined
/// in bsdtar.rs. Also note that so far I've found no need to support
/// optional arguments to long options. That would be a small change to the
/// code below.
const TAR_LONGOPTS: &[BsdtarOption] = {
    macro_rules! opts {
        ($($name:literal, $required:literal, $equivalent:expr;)*) => {
            &[$(BsdtarOption {
                name: $name,
                required: $required,
                equivalent: $equivalent,
            }),*]
        };
    }
    opts! {
        b"absolute-paths", false, 'P';
        b"append", false, 'r';
        b"acls", false, OPTION_ACLS;
        b"auto-compress", false, 'a';
        b"b64encode", false, OPTION_B64ENCODE;
        b"block-size", true, 'b';
        b"blocking-factor", true, 'b';
        b"bunzip2", false, 'j';
        b"bzip", false, 'j';
        b"bzip2", false, 'j';
        b"cd", true, 'C';
        b"check-links", false, OPTION_CHECK_LINKS;
        b"chroot", false, OPTION_CHROOT;
        b"clamp-mtime", false, OPTION_CLAMP_MTIME;
        b"clear-nochange-fflags", false, OPTION_CLEAR_NOCHANGE_FFLAGS;
        b"compress", false, 'Z';
        b"confirmation", false, 'w';
        b"create", false, 'c';
        b"dereference", false, 'L';
        b"directory", true, 'C';
        b"disable-copyfile", false, OPTION_NO_MAC_METADATA;
        b"exclude", true, OPTION_EXCLUDE;
        b"exclude-from", true, 'X';
        b"exclude-vcs", false, OPTION_EXCLUDE_VCS;
        b"extract", false, 'x';
        b"fast-read", false, 'q';
        b"fflags", false, OPTION_FFLAGS;
        b"file", true, 'f';
        b"files-from", true, 'T';
        b"format", true, OPTION_FORMAT;
        b"gid", true, OPTION_GID;
        b"gname", true, OPTION_GNAME;
        b"group", true, OPTION_GROUP;
        b"grzip", false, OPTION_GRZIP;
        b"gunzip", false, 'z';
        b"gzip", false, 'z';
        b"help", false, OPTION_HELP;
        b"hfsCompression", false, OPTION_HFS_COMPRESSION;
        b"ignore-zeros", false, OPTION_IGNORE_ZEROS;
        b"include", true, OPTION_INCLUDE;
        b"insecure", false, 'P';
        b"interactive", false, 'w';
        b"keep-newer-files", false, OPTION_KEEP_NEWER_FILES;
        b"keep-old-files", false, 'k';
        b"list", false, 't';
        b"lrzip", false, OPTION_LRZIP;
        b"lz4", false, OPTION_LZ4;
        b"lzip", false, OPTION_LZIP;
        b"lzma", false, OPTION_LZMA;
        b"lzop", false, OPTION_LZOP;
        b"mac-metadata", false, OPTION_MAC_METADATA;
        b"mode", true, OPTION_MODE;
        b"modification-time", false, 'm';
        b"mtime", true, OPTION_MTIME;
        b"newer", true, OPTION_NEWER_CTIME;
        b"newer-ctime", true, OPTION_NEWER_CTIME;
        b"newer-ctime-than", true, OPTION_NEWER_CTIME_THAN;
        b"newer-mtime", true, OPTION_NEWER_MTIME;
        b"newer-mtime-than", true, OPTION_NEWER_MTIME_THAN;
        b"newer-than", true, OPTION_NEWER_CTIME_THAN;
        b"no-acls", false, OPTION_NO_ACLS;
        b"no-fflags", false, OPTION_NO_FFLAGS;
        b"no-mac-metadata", false, OPTION_NO_MAC_METADATA;
        b"no-read-sparse", false, OPTION_NO_READ_SPARSE;
        b"no-recursion", false, 'n';
        b"no-safe-writes", false, OPTION_NO_SAFE_WRITES;
        b"no-same-owner", false, OPTION_NO_SAME_OWNER;
        b"no-same-permissions", false, OPTION_NO_SAME_PERMISSIONS;
        b"no-xattr", false, OPTION_NO_XATTRS;
        b"no-xattrs", false, OPTION_NO_XATTRS;
        b"nodump", false, OPTION_NODUMP;
        b"nopreserveHFSCompression", false, OPTION_NOPRESERVE_HFS_COMPRESSION;
        b"norecurse", false, 'n';
        b"null", false, OPTION_NULL;
        b"numeric-owner", false, OPTION_NUMERIC_OWNER;
        b"older", true, OPTION_OLDER_CTIME;
        b"older-ctime", true, OPTION_OLDER_CTIME;
        b"older-ctime-than", true, OPTION_OLDER_CTIME_THAN;
        b"older-mtime", true, OPTION_OLDER_MTIME;
        b"older-mtime-than", true, OPTION_OLDER_MTIME_THAN;
        b"older-than", true, OPTION_OLDER_CTIME_THAN;
        b"one-file-system", false, OPTION_ONE_FILE_SYSTEM;
        b"options", true, OPTION_OPTIONS;
        b"owner", true, OPTION_OWNER;
        b"passphrase", true, OPTION_PASSPHRASE;
        b"posix", false, OPTION_POSIX;
        b"preserve-permissions", false, 'p';
        b"read-full-blocks", false, 'B';
        b"read-sparse", false, OPTION_READ_SPARSE;
        b"safe-writes", false, OPTION_SAFE_WRITES;
        b"same-owner", false, OPTION_SAME_OWNER;
        b"same-permissions", false, 'p';
        b"strip-components", true, OPTION_STRIP_COMPONENTS;
        b"to-stdout", false, 'O';
        b"totals", false, OPTION_TOTALS;
        b"uid", true, OPTION_UID;
        b"uname", true, OPTION_UNAME;
        b"uncompress", false, 'Z';
        b"unlink", false, 'U';
        b"unlink-first", false, 'U';
        b"update", false, 'u';
        b"use-compress-program", true, OPTION_USE_COMPRESS_PROGRAM;
        b"uuencode", false, OPTION_UUENCODE;
        b"verbose", false, 'v';
        b"version", false, OPTION_VERSION;
        b"xattrs", false, OPTION_XATTRS;
        b"xz", false, 'J';
        b"zstd", false, OPTION_ZSTD;
    }
};

/// Where `bsdtar_getopt` is in the command line.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum State {
    #[default]
    Start,
    OldTar,
    NextWord,
    Short,
    Long,
}

impl Bsdtar {
    /// `bsdtar_getopt`: the next option, as its short option or `OPTION_*`
    /// code, or `'?'` for one that isn't valid. `None` at the end of the
    /// options; the words left in `argv` are the operands.
    ///
    /// This getopt implementation has two key features that common
    /// getopt_long() implementations lack. Apart from those, it's a
    /// straightforward option parser, considerably simplified by not
    /// needing to support the wealth of exotic getopt_long() features. It
    /// has, of course, been shamelessly tailored for bsdtar. The two
    /// additional features are:
    ///
    /// Old-style tar arguments: The original tar implementation treated the
    /// first argument word as a list of single-character option letters.
    /// All arguments follow as separate words. For example,
    ///    tar xbf 32 /dev/tape
    /// Here, the "xbf" is three option letters, "32" is the argument for
    /// "b" and "/dev/tape" is the argument for "f". We support this usage
    /// if the first command-line argument does not begin with '-'. We also
    /// allow regular short and long options to follow, e.g.,
    ///    tar xbf 32 /dev/tape -P --format=pax
    ///
    /// -W long options: There's an obscure GNU convention (only rarely
    /// supported even there) that allows "-W option=argument" as an
    /// alternative way to support long options. This was supported in early
    /// bsdtar as a way to access long options on platforms that did not
    /// support getopt_long() and is preserved here for backwards
    /// compatibility.
    pub fn getopt(&mut self) -> Option<char> {
        loop {
            let mut long_prefix: &[u8] = b"--";
            let mut opt = '?';
            self.argument = None;

            // First time through, initialize everything.
            if self.getopt_state == State::Start {
                // Skip program name.
                self.argv.pop_front();
                // Decide between "new style" and "old style" arguments.
                if self.argv.front()?.first() == Some(&b'-') {
                    self.getopt_state = State::NextWord;
                } else {
                    self.getopt_state = State::OldTar;
                    self.getopt_word = self.argv.pop_front()?;
                }
            }

            // We're parsing old-style tar arguments.
            if self.getopt_state == State::OldTar {
                // Get the next option character.
                if self.getopt_word.is_empty() {
                    // New-style args can follow old-style.
                    self.getopt_state = State::NextWord;
                } else {
                    let c = self.getopt_word.remove(0);
                    opt = char::from(c);
                    // See if it takes an argument.
                    let Some(p) = SHORT_OPTIONS.iter().position(|&o| o == c) else {
                        return Some('?');
                    };
                    if SHORT_OPTIONS.get(p + 1) == Some(&b':') {
                        self.argument = self.argv.pop_front();
                        if self.argument.is_none() {
                            let msg = [b"Option ".as_slice(), &[c], b" requires an argument"];
                            lafe_warnc(0, msg.concat());
                            return Some('?');
                        }
                    }
                }
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
                let c = self.getopt_word.remove(0);
                opt = char::from(c);

                // Does this option take an argument?
                let Some(p) = SHORT_OPTIONS.iter().position(|&o| o == c) else {
                    return Some('?');
                };

                // If it takes an argument, parse that.
                if SHORT_OPTIONS.get(p + 1) == Some(&b':') {
                    // If arg is run-in, getopt_word already holds it.
                    if self.getopt_word.is_empty() {
                        // Otherwise, pick up the next word.
                        let Some(word) = self.argv.pop_front() else {
                            let msg = [b"Option -".as_slice(), &[c], b" requires an argument"];
                            lafe_warnc(0, msg.concat());
                            return Some('?');
                        };
                        self.getopt_word = word;
                    }
                    if c == b'W' {
                        self.getopt_state = State::Long;
                        long_prefix = b"-W "; // For clearer errors.
                    } else {
                        self.getopt_state = State::NextWord;
                        self.argument = Some(std::mem::take(&mut self.getopt_word));
                    }
                }
            }

            // We're reading a long option, including -W long=arg convention.
            if self.getopt_state == State::Long {
                // After this long option, we'll be starting a new word.
                self.getopt_state = State::NextWord;

                // Option name ends at '=' if there is one.
                let word = std::mem::take(&mut self.getopt_word);
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
                for popt in TAR_LONGOPTS {
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
                    let msg = [b"Option ", long_prefix, &word, b" is not supported"];
                    lafe_warnc(0, msg.concat());
                    return Some('?');
                };
                if let Some(found2) = found2 {
                    let msg = [
                        b"Ambiguous option ".as_slice(),
                        long_prefix,
                        &word,
                        b" (matches --",
                        found.name,
                        b" and --",
                        found2.name,
                        b")",
                    ];
                    lafe_warnc(0, msg.concat());
                    return Some('?');
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
                            return Some('?');
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
                    return Some('?');
                }
                return Some(found.equivalent);
            }

            return Some(opt);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The options `getopt` returns for `args`, with their arguments, and
    /// the operands left.
    fn parse(args: &[&str]) -> (Vec<(char, Option<String>)>, Vec<String>) {
        let words = std::iter::once("bsdtar").chain(args.iter().copied());
        let mut bsdtar = Bsdtar {
            argv: words.map(|w| w.as_bytes().to_vec()).collect(),
            ..Bsdtar::default()
        };
        let mut opts = Vec::new();
        while let Some(opt) = bsdtar.getopt() {
            let arg = bsdtar.argument.take();
            opts.push((opt, arg.map(|a| String::from_utf8(a).unwrap())));
        }
        let rest = bsdtar.argv.into_iter();
        (opts, rest.map(|w| String::from_utf8(w).unwrap()).collect())
    }

    fn o(c: char) -> (char, Option<String>) {
        (c, None)
    }

    fn a(c: char, arg: &str) -> (char, Option<String>) {
        (c, Some(arg.to_string()))
    }

    #[test]
    fn old_style_letters_take_the_following_words() {
        assert_eq!(
            parse(&["xbf", "32", "/dev/tape", "-P", "--format=pax", "file"]),
            (
                vec![
                    o('x'),
                    a('b', "32"),
                    a('f', "/dev/tape"),
                    o('P'),
                    a(OPTION_FORMAT, "pax")
                ],
                vec!["file".into()]
            )
        );
        assert_eq!(parse(&["tf"]).0, [o('t'), o('?')]);
        assert_eq!(
            parse(&["t!", "x"]),
            (vec![o('t'), o('?')], vec!["x".into()])
        );
    }

    #[test]
    fn short_options_group_and_take_run_in_arguments() {
        assert_eq!(
            parse(&["-cvf", "out.tar", "-C/tmp", "dir"]),
            (
                vec![o('c'), o('v'), a('f', "out.tar"), a('C', "/tmp")],
                vec!["dir".into()]
            )
        );
        assert_eq!(parse(&["-t", "--", "-x"]).1, ["-x"]);
        assert_eq!(parse(&["-f"]).0, [o('?')]);
        assert_eq!(parse(&["-W", "exclude=*.o"]).0, [a(OPTION_EXCLUDE, "*.o")]);
    }

    #[test]
    fn long_options_match_unambiguous_prefixes() {
        assert_eq!(parse(&["--verb"]).0, [o('v')]);
        assert_eq!(parse(&["--gz"]).0, [o('z')]);
        assert_eq!(parse(&["--exclude", "x"]).0, [a(OPTION_EXCLUDE, "x")]);
        assert_eq!(parse(&["--no"]).0, [o('?')]);
        assert_eq!(parse(&["--lzma"]).0, [o(OPTION_LZMA)]);
        assert_eq!(parse(&["--list=x"]).0, [a('?', "x")]);
        assert_eq!(parse(&["--nonsense"]).0, [o('?')]);
        assert_eq!(parse(&["--file"]).0, [o('?')]);
    }
}
