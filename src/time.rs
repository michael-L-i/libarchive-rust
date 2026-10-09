/*-
 * Copyright © 2025 ARJANEN Loïc Jean David
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

// Ported from libarchive/archive_time.c.

//! Conversions between Unix, MS-DOS and NTFS timestamps.

use crate::ffi::sys::{self, Tm};

const NTFS_EPOC_TIME: u64 = 11_644_473_600;
const NTFS_TICKS: u64 = 10_000_000;
const NTFS_EPOC_TICKS: u64 = NTFS_EPOC_TIME * NTFS_TICKS;
const DOS_MIN_TIME: u32 = 0x0021_0000;
const DOS_MAX_TIME: u32 = 0xff9f_bf7d;

/// Convert an MSDOS-style date/time into Unix-style time (local time).
pub(crate) fn dos_to_unix(dos_time: u32) -> i64 {
    let ms_time = dos_time & 0xFFFF;
    let ms_date = dos_time >> 16;
    let tm = Tm {
        year: ((ms_date >> 9) & 0x7f) as i32 + 80, // Years since 1900.
        mon: ((ms_date >> 5) & 0x0f) as i32 - 1,   // Month number.
        mday: (ms_date & 0x1f) as i32,             // Day of month.
        hour: ((ms_time >> 11) & 0x1f) as i32,
        min: ((ms_time >> 5) & 0x3f) as i32,
        sec: ((ms_time << 1) & 0x3e) as i32,
    };
    sys::mktime(tm).unwrap_or(i64::from(i32::MAX))
}

/// Convert into MSDOS-style date/time (local time).
pub(crate) fn unix_to_dos(unix_time: i64) -> u32 {
    let mut dt = 0u32;
    if let Some(t) = sys::localtime(unix_time)
        && let Some(year) = t.year.checked_sub(80)
    {
        if year & !0x7f != 0 {
            dt = if year > 0 { DOS_MAX_TIME } else { DOS_MIN_TIME };
        } else {
            dt += ((year & 0x7f) as u32) << 9;
            dt += (((t.mon + 1) & 0x0f) as u32) << 5;
            dt += (t.mday & 0x1f) as u32;
            dt <<= 16;
            dt += ((t.hour & 0x1f) as u32) << 11;
            dt += ((t.min & 0x3f) as u32) << 5;
            // Only counting every 2 seconds.
            dt += ((t.sec & 0x3e) as u32) >> 1;
        }
    }
    dt.clamp(DOS_MIN_TIME, DOS_MAX_TIME)
}

/// Convert NTFS time to Unix sec/nsec.
pub(crate) fn ntfs_to_unix(ntfs: u64) -> (i64, u32) {
    if ntfs > i64::MAX as u64 {
        let ntfs = ntfs - NTFS_EPOC_TICKS;
        (
            (ntfs / NTFS_TICKS) as i64,
            (100 * (ntfs % NTFS_TICKS)) as u32,
        )
    } else {
        // Floor division, so the nanoseconds are never negative and the
        // sign is folded entirely into the seconds.
        let value = ntfs as i64 - NTFS_EPOC_TICKS as i64;
        let ticks = NTFS_TICKS as i64;
        (
            value.div_euclid(ticks),
            (value.rem_euclid(ticks) * 100) as u32,
        )
    }
}

/// Convert Unix sec/nsec to NTFS time.
pub(crate) fn unix_to_ntfs(secs: i64, nsecs: u32) -> u64 {
    if secs < -(NTFS_EPOC_TIME as i64) {
        return 0;
    }
    // (secs + NTFS_EPOC_TIME) * NTFS_TICKS + nsecs / 100. Upstream adds the
    // unsigned reinterpretation of `secs`, so a negative one overflows.
    (secs as u64)
        .checked_add(NTFS_EPOC_TIME)
        .and_then(|s| s.checked_mul(NTFS_TICKS))
        .and_then(|t| t.checked_add(u64::from(nsecs / 100)))
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH_SECS: u64 = NTFS_EPOC_TIME;
    const TICKS: u64 = NTFS_TICKS;

    /// Upstream's test_archive_ntfs_to_unix.
    #[test]
    fn ntfs_to_unix_cases() {
        // Exactly the Unix epoch.
        assert_eq!(ntfs_to_unix(EPOCH_SECS * TICKS), (0, 0));
        // A normal post-1970, second-aligned date.
        assert_eq!(
            ntfs_to_unix((EPOCH_SECS + 1_000_000_000) * TICKS),
            (1_000_000_000, 0)
        );
        // Sub-second precision.
        assert_eq!(
            ntfs_to_unix((EPOCH_SECS + 1_000_000_000) * TICKS + 1_234_567),
            (1_000_000_000, 123_456_700)
        );
        // Pre-1970, second-aligned.
        assert_eq!(ntfs_to_unix(EPOCH_SECS * TICKS - 2 * TICKS), (-2, 0));
        // Pre-1970, not second-aligned: nsecs stays in [0, 999999999].
        assert_eq!(ntfs_to_unix(EPOCH_SECS * TICKS - 15), (-1, 999_998_500));
        assert_eq!(
            ntfs_to_unix(EPOCH_SECS * TICKS - TICKS - 15),
            (-2, 999_998_500)
        );
        // Beyond i64::MAX ticks.
        assert_eq!(
            ntfs_to_unix(u64::MAX),
            (
                ((u64::MAX - EPOCH_SECS * TICKS) / TICKS) as i64,
                955_161_500
            )
        );
    }

    #[test]
    fn unix_to_ntfs_cases() {
        assert_eq!(unix_to_ntfs(0, 0), EPOCH_SECS * TICKS);
        assert_eq!(unix_to_ntfs(1, 250), (EPOCH_SECS + 1) * TICKS + 2);
        assert_eq!(unix_to_ntfs(-(EPOCH_SECS as i64) - 1, 0), 0);
        assert_eq!(unix_to_ntfs(i64::MAX, 0), u64::MAX);
        // Ported as-is: a negative `secs` is added as unsigned and overflows.
        assert_eq!(unix_to_ntfs(-1, 0), u64::MAX);
    }

    #[test]
    fn dos_time_round_trips_and_clamps() {
        // 2001-02-03 04:05:06 local time.
        let dos = ((2001 - 1980) << 25) | (2 << 21) | (3 << 16) | (4 << 11) | (5 << 5) | 3;
        assert_eq!(unix_to_dos(dos_to_unix(dos)), dos);
        assert_eq!(unix_to_dos(i64::MIN), DOS_MIN_TIME);
        assert_eq!(unix_to_dos(i64::MAX), DOS_MIN_TIME);
        assert_eq!(unix_to_dos(1 << 40), DOS_MAX_TIME);
        assert_eq!(unix_to_dos(0), DOS_MIN_TIME);
        // An impossible date still converts, via mktime's normalization.
        assert_ne!(dos_to_unix(0), 0);
    }
}
