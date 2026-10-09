/*-
 * Copyright (c) 2009-2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_write_set_format_iso9660.c.

use crate::ffi::sys::{self, Tm};
use crate::util::Error;

const KEYS: &[&[u8]] = &[
    b"abstract-file",
    b"application-id",
    b"allow-vernum",
    b"biblio-file",
    b"boot",
    b"boot-catalog",
    b"boot-info-table",
    b"boot-load-seg",
    b"boot-load-size",
    b"boot-type",
    b"compression-level",
    b"copyright-file",
    b"iso-level",
    b"joliet",
    b"limit-depth",
    b"limit-dirs",
    b"pad",
    b"publisher",
    b"rockridge",
    b"volume-id",
    b"zisofs",
];

fn ctime(t: &Tm) -> Result<String, Error> {
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month = usize::try_from(t.mon)
        .ok()
        .and_then(|m| months.get(m))
        .ok_or_else(|| Error::fatal(libc::EINVAL, "Invalid ISO creation time"))?;
    let year = i64::from(t.year) + 1900;
    // Gregorian civil days relative to 1970-01-01, including negative years.
    let y = year - i64::from(t.mon < 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(t.mon) + if t.mon > 1 { -2 } else { 10 };
    let doy = (153 * m + 2) / 5 + i64::from(t.mday) - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    let weekday = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
        .get((days + 4).rem_euclid(7) as usize)
        .ok_or_else(|| Error::fatal(libc::EINVAL, "Invalid ISO creation time"))?;
    Ok(format!(
        "{weekday} {month} {:2} {:02}:{:02}:{:02} {year}\n",
        t.mday, t.hour, t.min, t.sec
    ))
}

/// Options contain resolved states differing from defaults, in arbitrary order.
/// A flag is disabled by None; numeric and string values are already canonical.
pub(super) fn block(
    timestamp: i64,
    options: &[(Vec<u8>, Option<Vec<u8>>)],
) -> Result<[u8; 2048], Error> {
    let time = sys::localtime(timestamp)
        .ok_or_else(|| Error::fatal(libc::EINVAL, "Invalid ISO creation time"))?;
    block_at(&time, options)
}

fn block_at(time: &Tm, options: &[(Vec<u8>, Option<Vec<u8>>)]) -> Result<[u8; 2048], Error> {
    let mut out = [0; 2048];
    let mut offset = 0;
    // Upstream copies only the first information sector even for long options.
    let mut append = |bytes: &[u8]| {
        let count = bytes.len().min(out.len() - offset);
        out[offset..offset + count].copy_from_slice(&bytes[..count]);
        offset += count;
    };
    append(b"INFO ");
    append(ctime(time)?.as_bytes());
    append(b"libarchive 3.9.0dev");
    let mut first = true;
    for &key in KEYS {
        let Some((_, value)) = options.iter().find(|(k, _)| k == key) else {
            continue;
        };
        append(if first { b" " } else { b"," });
        first = false;
        let flag = matches!(
            key,
            b"allow-vernum"
                | b"boot-info-table"
                | b"limit-depth"
                | b"limit-dirs"
                | b"pad"
                | b"zisofs"
        ) || key == b"joliet" && value.as_deref() != Some(b"long")
            || key == b"rockridge" && value.is_none();
        if flag && value.is_none() {
            append(b"!");
        }
        append(key);
        if !flag {
            append(b"=");
            append(value.as_deref().unwrap_or_default());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn information_matches_ctime_order_flags_and_hex() {
        let time = Tm {
            year: 70,
            mon: 0,
            mday: 1,
            hour: 0,
            min: 0,
            sec: 0,
        };
        let options = vec![
            (b"zisofs".to_vec(), Some(b"1".to_vec())),
            (b"rockridge".to_vec(), Some(b"strict".to_vec())),
            (b"joliet".to_vec(), Some(b"long".to_vec())),
            (b"boot-load-seg".to_vec(), Some(b"1a2b".to_vec())),
            (b"boot-load-size".to_vec(), Some(b"8".to_vec())),
            (b"allow-vernum".to_vec(), None),
        ];
        let expected = b"INFO Thu Jan  1 00:00:00 1970\nlibarchive 3.9.0dev !allow-vernum,boot-load-seg=1a2b,boot-load-size=8,joliet=long,rockridge=strict,zisofs";
        let out = block_at(&time, &options).unwrap();
        assert_eq!(&out[..expected.len()], expected);
        assert!(out[expected.len()..].iter().all(|&b| b == 0));
        let leap = Tm {
            year: 100,
            mon: 1,
            mday: 29,
            hour: 23,
            min: 59,
            sec: 58,
        };
        assert_eq!(ctime(&leap).unwrap(), "Tue Feb 29 23:59:58 2000\n");
    }
    #[test]
    fn long_information_is_bounded_to_one_sector() {
        let time = Tm {
            year: 70,
            mon: 0,
            mday: 1,
            hour: 0,
            min: 0,
            sec: 0,
        };
        let options = vec![(b"publisher".to_vec(), Some(vec![b'x'; 4096]))];
        let out = block_at(&time, &options).unwrap();
        assert_eq!(out.len(), 2048);
        assert_eq!(out[2047], b'x');
    }
}
