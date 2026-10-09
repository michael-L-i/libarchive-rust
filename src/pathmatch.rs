/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
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

// Ported from libarchive/archive_pathmatch.c.

pub const NO_ANCHOR_START: u8 = 1;
pub const NO_ANCHOR_END: u8 = 2;

fn skip(mut s: &[u8]) -> &[u8] {
    while s.first() == Some(&b'/')
        || (s.first() == Some(&b'.') && (s.len() == 1 || s.get(1) == Some(&b'/')))
    {
        s = &s[1..];
    }
    s
}

fn class(mut p: &[u8], c: u8) -> bool {
    let negate = matches!(p.first(), Some(b'!' | b'^'));
    if negate {
        p = &p[1..];
    }
    let mut range = None;
    while let Some((&ch, rest)) = p.split_first() {
        p = rest;
        match ch {
            b'-' if range.is_some() && !p.is_empty() => {
                let mut end = p[0];
                p = &p[1..];
                if end == b'\\' && !p.is_empty() {
                    end = p[0];
                    p = &p[1..];
                }
                if (range.unwrap_or(0) as i8) <= c as i8 && c as i8 <= end as i8 {
                    return !negate;
                }
                range = None;
            }
            b'\\' if !p.is_empty() => {
                let ch = p[0];
                p = &p[1..];
                if ch == c {
                    return !negate;
                }
                range = Some(ch);
            }
            _ => {
                if ch == c {
                    return !negate;
                }
                range = if ch == b'-' { None } else { Some(ch) };
            }
        }
    }
    negate
}

fn pm(mut p: &[u8], mut s: &[u8], flags: u8, depth: u8) -> Result<bool, ()> {
    if depth > 100 {
        return Err(());
    }
    if s.starts_with(b"./") {
        s = skip(&s[1..]);
    }
    if p.starts_with(b"./") {
        p = skip(&p[1..]);
    }
    loop {
        let Some((&ch, rest)) = p.split_first() else {
            if s.first() == Some(&b'/') {
                if flags & NO_ANCHOR_END != 0 {
                    return Ok(true);
                }
                s = skip(s);
            }
            return Ok(s.is_empty());
        };
        p = rest;
        match ch {
            b'?' => {
                if s.is_empty() {
                    return Ok(false);
                }
            }
            b'*' => {
                while p.first() == Some(&b'*') {
                    p = &p[1..];
                }
                if p.is_empty() {
                    return Ok(true);
                }
                while !s.is_empty() {
                    if pm(p, s, flags, depth + 1)? {
                        return Ok(true);
                    }
                    s = &s[1..];
                }
                return Ok(false);
            }
            b'[' => {
                let mut end = 0;
                while let Some(&v) = p.get(end) {
                    if v == b']' {
                        break;
                    }
                    if v == b'\\' && p.get(end + 1).is_some() {
                        end += 1;
                    }
                    end += 1;
                }
                if p.get(end) == Some(&b']') {
                    if !s.first().is_some_and(|&c| class(&p[..end], c)) {
                        return Ok(false);
                    }
                    p = &p[end + 1..];
                } else if s.first() != Some(&b'[') {
                    return Ok(false);
                }
            }
            b'\\' => {
                let literal = p.first().copied().unwrap_or(b'\\');
                if !p.is_empty() {
                    p = &p[1..];
                }
                if s.first() != Some(&literal) {
                    return Ok(false);
                }
            }
            b'/' => {
                if !s.is_empty() && s.first() != Some(&b'/') {
                    return Ok(false);
                }
                p = skip(p);
                s = skip(s);
                if p.is_empty() && flags & NO_ANCHOR_END != 0 {
                    return Ok(true);
                }
                continue;
            }
            b'$' if p.is_empty() && flags & NO_ANCHOR_END != 0 => return Ok(skip(s).is_empty()),
            _ => {
                if s.first() != Some(&ch) {
                    return Ok(false);
                }
            }
        }
        if !s.is_empty() {
            s = &s[1..];
        }
    }
}

pub fn matches(mut p: &[u8], mut s: &[u8], mut flags: u8) -> Result<bool, ()> {
    if p.is_empty() {
        return Ok(s.is_empty());
    }
    if flags & NO_ANCHOR_START != 0 && p.first() == Some(&b'^') {
        p = &p[1..];
        flags &= !NO_ANCHOR_START;
    }
    if p.first() == Some(&b'/') && s.first() != Some(&b'/') {
        return Ok(false);
    }
    if matches!(p.first(), Some(b'*' | b'/')) {
        while p.first() == Some(&b'/') {
            p = &p[1..];
        }
        while s.first() == Some(&b'/') {
            s = &s[1..];
        }
        return pm(p, s, flags, 0);
    }
    loop {
        if pm(p, s, flags, 0)? {
            return Ok(true);
        }
        if flags & NO_ANCHOR_START == 0 {
            return Ok(false);
        }
        let Some(at) = s.iter().position(|&b| b == b'/') else {
            return Ok(false);
        };
        s = &s[at + 1..];
    }
}
