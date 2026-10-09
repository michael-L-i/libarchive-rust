/*-
 * Copyright (c) 2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_cmdline.c.

//! Splitting a command line into the program and its arguments. Upstream
//! does it itself, with its own quoting rules, rather than through a shell:
//! a backslash quotes the next byte, and a double-quoted part (in which
//! only a backslash is special) joins the argument around it.

/// A parsed command line.
#[derive(Debug, PartialEq, Eq)]
pub struct Cmdline {
    /// The program, as written.
    pub path: Vec<u8>,
    /// `argv[0]`: the program without its directory.
    pub name: Vec<u8>,
    /// The arguments after the program.
    pub args: Vec<Vec<u8>>,
}

/// Appends the quoted part `s` starts (at its opening quote) to `out` and
/// returns its length, or `None` if the closing quote is missing.
fn extract_quotation(out: &mut Vec<u8>, s: &[u8]) -> Option<usize> {
    let mut i = 1;
    loop {
        match s.get(i)? {
            b'\\' => match s.get(i + 1) {
                Some(&c) => {
                    out.push(c);
                    i += 2;
                }
                None => i += 1,
            },
            b'"' => return Some(i + 1),
            &c => {
                out.push(c);
                i += 1;
            }
        }
    }
}

/// Replaces `out` with the next argument in `p` and returns how many bytes
/// it took, spaces before it included, or `None` for a missing closing quote.
fn get_argument(out: &mut Vec<u8>, p: &[u8]) -> Option<usize> {
    out.clear();
    let mut i = p.iter().take_while(|&&c| c == b' ').count();
    while let Some(&c) = p.get(i) {
        match c {
            b' ' => break,
            b'\\' => match p.get(i + 1) {
                Some(&c) => {
                    out.push(c);
                    i += 2;
                }
                // Ignore this character.
                None => return Some(i + 1),
            },
            b'"' => i += extract_quotation(out, p.get(i..)?)?,
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(i)
}

/// `__archive_cmdline_parse`. `None` if there is a lack of the `"`
/// terminator or an empty command line.
pub fn parse(cmd: &[u8]) -> Option<Cmdline> {
    let mut arg = Vec::new();
    // Get first argument as a command path.
    let mut rest = cmd.get(get_argument(&mut arg, cmd)?..)?;
    if arg.is_empty() {
        return None;
    }
    let name = arg
        .rsplit(|&c| c == b'/')
        .next()
        .unwrap_or_default()
        .to_vec();
    let mut line = Cmdline {
        path: std::mem::take(&mut arg),
        name,
        args: Vec::new(),
    };
    loop {
        let len = get_argument(&mut arg, rest)?;
        if len == 0 {
            break;
        }
        rest = rest.get(len..)?;
        if arg.is_empty() && rest.is_empty() {
            break;
        }
        line.args.push(std::mem::take(&mut arg));
    }
    Some(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(cmd: &str, path: &str, name: &str, args: &[&str]) {
        let line = parse(cmd.as_bytes()).expect(cmd);
        assert_eq!(line.path, path.as_bytes(), "{cmd}");
        assert_eq!(line.name, name.as_bytes(), "{cmd}");
        assert_eq!(
            line.args,
            args.iter().map(|a| a.as_bytes()).collect::<Vec<_>>(),
            "{cmd}"
        );
    }

    #[test]
    fn command_name_only() {
        check("gzip", "gzip", "gzip", &[]);
        // Neither the path nor arg0 includes the trailing space.
        check("gzip ", "gzip", "gzip", &[]);
        // The path is a full path; arg0 is not.
        check("/usr/bin/gzip ", "/usr/bin/gzip", "gzip", &[]);
    }

    #[test]
    fn quotes_keep_spaces() {
        check("\"gzip \"", "gzip ", "gzip ", &[]);
        check("\"gzip \"x", "gzip x", "gzip x", &[]);
        check("\"gzip \"x\" s \"", "gzip x s ", "gzip x s ", &[]);
        check("\"gzip\\\" \"", "gzip\" ", "gzip\" ", &[]);
    }

    #[test]
    fn arguments() {
        check("gzip -d", "gzip", "gzip", &["-d"]);
        check("gzip -d -q", "gzip", "gzip", &["-d", "-q"]);
        check("  gzip   -d  ", "gzip", "gzip", &["-d"]);
        check(r"gzip a\ b \\ c\", "gzip", "gzip", &["a b", "\\", "c"]);
        // An empty argument is kept, except at the very end.
        check("gzip \"\" x \"\"", "gzip", "gzip", &["", "x"]);
    }

    #[test]
    fn invalid_command_lines() {
        assert_eq!(parse(b""), None);
        assert_eq!(parse(b"   "), None);
        assert_eq!(parse(b"\"\""), None);
        assert_eq!(parse(b"\"gzip"), None);
        assert_eq!(parse(b"gzip \"-d"), None);
        assert_eq!(parse(b"gzip \"-d\\"), None);
    }
}
