/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1989, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Dave Borman at Cray Research, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

// Ported from libarchive_fe/lafe_setmode.c.

//! `setmode(3)` and `getmode(3)`: chmod-style mode strings, absolute
//! ("644") or symbolic ("u+w,go-x").

use crate::sys;
use libc::mode_t;
use libc::{S_IFDIR, S_IWGRP, S_IWOTH, S_IWUSR, S_IXGRP, S_IXOTH, S_IXUSR};
use libc::{S_IRGRP, S_IROTH, S_IRUSR, S_IRWXG, S_IRWXO, S_IRWXU, S_ISGID, S_ISUID, S_ISVTX};

/// One step of a mode change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BitCmd {
    cmd: u8,
    cmd2: u8,
    bits: mode_t,
}

const CMD2_CLR: u8 = 0x01;
const CMD2_SET: u8 = 0x02;
const CMD2_GBITS: u8 = 0x04;
const CMD2_OBITS: u8 = 0x08;
const CMD2_UBITS: u8 = 0x10;

const STANDARD_BITS: mode_t = S_ISUID | S_ISGID | S_IRWXU | S_IRWXG | S_IRWXO;

/// A parsed mode string, for `lafe_getmode`.
#[derive(Debug, PartialEq, Eq)]
pub struct SetMode(Vec<BitCmd>);

/// Given the old mode and the commands, apply the operations described in
/// the commands to the old mode, and return the new mode. Note that there
/// is no '=' command; a strict assignment is just a '-' (clear bits)
/// followed by a '+' (set bits).
pub fn lafe_getmode(set: &SetMode, omode: mode_t) -> mode_t {
    let mut newmode = omode;
    for set in &set.0 {
        match set.cmd {
            // When copying the user, group or other bits around, we "know"
            // where the bits are in the mode so that we can do shifts to
            // copy them around. If we don't use shifts, it gets real
            // grundgy with lots of single bit checks and bit sets.
            b'u' | b'g' | b'o' => {
                let value = match set.cmd {
                    b'u' => (newmode & S_IRWXU) >> 6,
                    b'g' => (newmode & S_IRWXG) >> 3,
                    _ => newmode & S_IRWXO,
                };
                if set.cmd2 & CMD2_CLR != 0 {
                    let clrval = if set.cmd2 & CMD2_SET != 0 {
                        S_IRWXO
                    } else {
                        value
                    };
                    if set.cmd2 & CMD2_UBITS != 0 {
                        newmode &= !((clrval << 6) & set.bits);
                    }
                    if set.cmd2 & CMD2_GBITS != 0 {
                        newmode &= !((clrval << 3) & set.bits);
                    }
                    if set.cmd2 & CMD2_OBITS != 0 {
                        newmode &= !(clrval & set.bits);
                    }
                }
                if set.cmd2 & CMD2_SET != 0 {
                    if set.cmd2 & CMD2_UBITS != 0 {
                        newmode |= (value << 6) & set.bits;
                    }
                    if set.cmd2 & CMD2_GBITS != 0 {
                        newmode |= (value << 3) & set.bits;
                    }
                    if set.cmd2 & CMD2_OBITS != 0 {
                        newmode |= value & set.bits;
                    }
                }
            }
            b'+' => newmode |= set.bits,
            b'-' => newmode &= !set.bits,
            b'X' => {
                if omode & (S_IFDIR | S_IXUSR | S_IXGRP | S_IXOTH) != 0 {
                    newmode |= set.bits;
                }
            }
            _ => break,
        }
    }
    newmode
}

/// `addcmd`: the commands for operation `op` (or the copy of who's bits,
/// for 'u', 'g' and 'o', with `oparg` the operator).
fn addcmd(set: &mut Vec<BitCmd>, op: u8, who: mode_t, oparg: mode_t, mask: mode_t) {
    match op {
        b'=' | b'+' | b'-' | b'X' => {
            let op = if op == b'=' {
                set.push(BitCmd {
                    cmd: b'-',
                    cmd2: 0,
                    bits: if who != 0 { who } else { STANDARD_BITS },
                });
                b'+'
            } else {
                op
            };
            set.push(BitCmd {
                cmd: op,
                cmd2: 0,
                bits: (if who != 0 { who } else { mask }) & oparg,
            });
        }
        _ => {
            let (mut cmd2, bits) = if who != 0 {
                let ubits = if who & S_IRUSR != 0 { CMD2_UBITS } else { 0 };
                let gbits = if who & S_IRGRP != 0 { CMD2_GBITS } else { 0 };
                let obits = if who & S_IROTH != 0 { CMD2_OBITS } else { 0 };
                (ubits | gbits | obits, !0)
            } else {
                (CMD2_UBITS | CMD2_GBITS | CMD2_OBITS, mask)
            };
            cmd2 |= match u8::try_from(oparg) {
                Ok(b'+') => CMD2_SET,
                Ok(b'-') => CMD2_CLR,
                Ok(b'=') => CMD2_SET | CMD2_CLR,
                _ => 0,
            };
            set.push(BitCmd {
                cmd: op,
                cmd2,
                bits,
            });
        }
    }
}

/// `strtol(p, &ep, 8)` for a string of octal digits: `None` if anything
/// follows them (EINVAL) or the value overflows a `long` (ERANGE).
fn octal(p: &[u8]) -> Option<i64> {
    p.iter().try_fold(0i64, |n, &c| match c {
        b'0'..=b'7' => n.checked_mul(8)?.checked_add(i64::from(c - b'0')),
        _ => None,
    })
}

/// `lafe_setmode`: parses `p`, a mode as chmod(1) takes it. `None` if it
/// is not one.
pub fn lafe_setmode(p: &[u8]) -> Option<SetMode> {
    // Get a copy of the mask for the permissions that are mask relative.
    // Flip the bits, we want what's not set.
    setmode(p, !sys::umask())
}

/// `lafe_setmode` with the complement of the umask.
fn setmode(p: &[u8], mask: mode_t) -> Option<SetMode> {
    let p = p.split(|&c| c == 0).next().unwrap_or_default();
    if p.is_empty() {
        return None;
    }

    let mut set = Vec::new();

    // If an absolute number, get it and return; disallow non-octal digits
    // or illegal bits.
    if p[0].is_ascii_digit() {
        let perm = octal(p)?;
        if perm & !i64::from(STANDARD_BITS | S_ISVTX) != 0 {
            return None;
        }
        let perm = mode_t::try_from(perm).ok()?;
        addcmd(&mut set, b'=', STANDARD_BITS | S_ISVTX, perm, mask);
        return Some(SetMode(set));
    }

    // Build list of structures to set/clear/copy bits as described by
    // each clause of the symbolic mode.
    let at = |i: usize| p.get(i).copied().unwrap_or(0);
    let mut i = 0;
    let mut equalopdone = false;
    'clause: loop {
        // First, find out which bits might be modified.
        let mut who: mode_t = 0;
        loop {
            who |= match at(i) {
                b'a' => STANDARD_BITS,
                b'u' => S_ISUID | S_IRWXU,
                b'g' => S_ISGID | S_IRWXG,
                b'o' => S_IRWXO,
                _ => break,
            };
            i += 1;
        }

        loop {
            let op = at(i);
            i += 1;
            if !matches!(op, b'+' | b'-' | b'=') {
                return None;
            }
            if op == b'=' {
                equalopdone = false;
            }

            who &= !S_ISVTX;
            let mut perm: mode_t = 0;
            let mut perm_xbits: mode_t = 0;
            loop {
                match at(i) {
                    b'r' => perm |= S_IRUSR | S_IRGRP | S_IROTH,
                    b's' => {
                        // If only "other" bits ignore set-id.
                        if who == 0 || who & !S_IRWXO != 0 {
                            perm |= S_ISUID | S_ISGID;
                        }
                    }
                    b't' => {
                        // If only "other" bits ignore sticky.
                        if who == 0 || who & !S_IRWXO != 0 {
                            who |= S_ISVTX;
                            perm |= S_ISVTX;
                        }
                    }
                    b'w' => perm |= S_IWUSR | S_IWGRP | S_IWOTH,
                    b'X' => perm_xbits = S_IXUSR | S_IXGRP | S_IXOTH,
                    b'x' => perm |= S_IXUSR | S_IXGRP | S_IXOTH,
                    c @ (b'u' | b'g' | b'o') => {
                        // When ever we hit 'u', 'g', or 'o', we have to
                        // flush out any partial mode that we have, and then
                        // do the copying of the mode bits.
                        if perm != 0 {
                            addcmd(&mut set, op, who, perm, mask);
                            perm = 0;
                        }
                        if op == b'=' {
                            equalopdone = true;
                        }
                        if op == b'+' && perm_xbits != 0 {
                            addcmd(&mut set, b'X', who, perm_xbits, mask);
                            perm_xbits = 0;
                        }
                        addcmd(&mut set, c, who, mode_t::from(op), mask);
                    }
                    _ => {
                        // Add any permissions that we haven't already done.
                        if perm != 0 || (op == b'=' && !equalopdone) {
                            if op == b'=' {
                                equalopdone = true;
                            }
                            addcmd(&mut set, op, who, perm, mask);
                        }
                        if perm_xbits != 0 {
                            addcmd(&mut set, b'X', who, perm_xbits, mask);
                        }
                        break;
                    }
                }
                i += 1;
            }

            // Another operator for the same `who`, the next clause, or the
            // end.
            match at(i) {
                0 => break 'clause,
                b',' => {
                    i += 1;
                    continue 'clause;
                }
                _ => {}
            }
        }
    }
    Some(SetMode(compress_mode(&set)))
}

/// Given a list of commands, compress by compacting consecutive '+', '-'
/// and 'X' commands into at most 3 commands, one of each. The 'u', 'g' and
/// 'o' commands continue to be separate. They could probably be compacted,
/// but it's not worth the effort.
fn compress_mode(set: &[BitCmd]) -> Vec<BitCmd> {
    let is_bits = |c: &BitCmd| matches!(c.cmd, b'+' | b'-' | b'X');
    let mut out = Vec::new();
    let mut rest = set;
    while !rest.is_empty() {
        // Copy over any 'u', 'g' and 'o' commands.
        let copies = rest.iter().take_while(|c| !is_bits(c)).count();
        out.extend_from_slice(&rest[..copies]);
        rest = &rest[copies..];

        let run = rest.iter().take_while(|c| is_bits(c)).count();
        let (mut setbits, mut clrbits, mut xbits): (mode_t, mode_t, mode_t) = (0, 0, 0);
        for c in &rest[..run] {
            match c.cmd {
                b'-' => {
                    clrbits |= c.bits;
                    setbits &= !c.bits;
                    xbits &= !c.bits;
                }
                b'+' => {
                    setbits |= c.bits;
                    clrbits &= !c.bits;
                    xbits &= !c.bits;
                }
                _ => xbits |= c.bits & !setbits,
            }
        }
        rest = &rest[run..];
        for (cmd, bits) in [(b'-', clrbits), (b'+', setbits), (b'X', xbits)] {
            if bits != 0 {
                out.push(BitCmd { cmd, cmd2: 0, bits });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upstream's lafe_setmode and lafe_getmode with umask 022: a mode
    /// string, then the result for each of `OMODES`, NULL where setmode
    /// fails.
    const UPSTREAM: &str = r"
|NULL NULL NULL NULL NULL NULL
0|0 0 0 40000 0 0
644|644 644 644 40644 644 644
0755|755 755 755 40755 755 755
4755|4755 4755 4755 44755 4755 4755
7777|7777 7777 7777 47777 7777 7777
17777|NULL NULL NULL NULL NULL NULL
8|NULL NULL NULL NULL NULL NULL
64a|NULL NULL NULL NULL NULL NULL
999999999999999999999999|NULL NULL NULL NULL NULL NULL
u+w|200 644 755 40700 4751 7777
go-x|0 644 744 40700 4740 7766
a=r|444 444 444 40444 444 1444
=|0 0 0 40000 0 1000
=r|444 444 444 40444 444 1444
+x|111 755 755 40711 4751 7777
-w|0 444 555 40500 4551 7577
u=rwx,g=rx,o=|750 750 750 40750 750 1750
ug+s|6000 6644 6755 46700 6751 7777
o+s|0 644 755 40700 4751 7777
+t|1000 1644 1755 41700 5751 7777
o+t|0 644 755 40700 4751 7777
a+X|0 644 755 40711 4751 7777
u+X,g-w|0 644 755 40700 4751 7757
g=u|0 664 775 40770 4771 7777
o=g|0 644 755 40700 4755 7777
u+g|0 644 755 40700 4751 7777
go-u|0 600 700 40700 4700 7700
a=rw,u+x|766 766 766 40766 766 1766
u+x-w|100 544 555 40500 4551 7577
ugo+rw|666 666 777 40766 4777 7777
x|NULL NULL NULL NULL NULL NULL
u|NULL NULL NULL NULL NULL NULL
u+r,|NULL NULL NULL NULL NULL NULL
,|NULL NULL NULL NULL NULL NULL
u+r,g|NULL NULL NULL NULL NULL NULL
+rwxst|1000 1644 1755 41700 5751 7777
a-rwxst|0 0 0 40000 0 0
u=g,g=o,o=u|0 444 555 40000 4515 7777
u+rX,go+X|400 644 755 40711 4751 7777
=X|0 0 111 40111 111 1111
-X|0 644 755 40711 4751 7777
+w,o-w|200 644 755 40700 4751 7775
g+w=r|40 644 745 40740 4741 5747
u=,g=|0 4 5 40000 1 1007
a+rw|666 666 777 40766 4777 7777
o-t|0 644 755 40700 4751 7777
uo+s|4000 4644 4755 44700 4751 7777
a=,u+x|100 100 100 40100 100 1100
";
    const OMODES: [mode_t; 6] = [0, 0o644, 0o755, S_IFDIR | 0o700, 0o4751, 0o7777];

    #[test]
    fn matches_upstream() {
        for line in UPSTREAM.lines().skip(1) {
            let (mode, results) = line.split_once('|').unwrap();
            let set = setmode(mode.as_bytes(), !0o022);
            for (omode, want) in OMODES.iter().zip(results.split(' ')) {
                let got = set
                    .as_ref()
                    .map(|s| format!("{:o}", lafe_getmode(s, *omode)));
                assert_eq!(
                    got.as_deref().unwrap_or("NULL"),
                    want,
                    "{mode:?} on {omode:o}"
                );
            }
        }
    }

    #[test]
    fn a_c_string_ends_at_its_nul() {
        assert_eq!(setmode(b"a+rw\0junk", !0o022), setmode(b"a+rw", !0o022));
    }
}
