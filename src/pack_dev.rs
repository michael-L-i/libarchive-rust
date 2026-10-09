/*	$NetBSD: pack_dev.c,v 1.12 2013/06/14 16:28:20 tsutsui Exp $	*/

/*-
 * Copyright (c) 1998, 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Charles M. Hannum.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// Ported from libarchive/archive_pack_dev.c.

//! Packing a device number from the major and minor numbers (and sometimes a
//! subunit) of a named operating system's format. Originally from NetBSD's
//! mknod(8) source.

use crate::entry::{Dev, dev_major, dev_minor, make_dev};

/// Packs the numbers into a device number. The error is the message of the
/// last check that failed.
pub type Pack = fn(&[u64]) -> (Dev, Option<&'static str>);

const MAJOR_ERROR: &str = "invalid major number";
const MINOR_ERROR: &str = "invalid minor number";
const TOO_MANY_FIELDS: &str = "too many fields for format";

fn pack_native(n: &[u64]) -> (Dev, Option<&'static str>) {
    let &[major, minor] = n else {
        return (0, Some(TOO_MANY_FIELDS));
    };
    let dev = make_dev(major as Dev, minor as Dev);
    let error = if dev_major(dev) as u64 != major {
        Some(MAJOR_ERROR)
    } else if dev_minor(dev) as u64 != minor {
        Some(MINOR_ERROR)
    } else {
        None
    };
    (dev, error)
}

fn pack_netbsd(n: &[u64]) -> (Dev, Option<&'static str>) {
    let &[major, minor] = n else {
        return (0, Some(TOO_MANY_FIELDS));
    };
    let dev = ((major << 8) & 0x000f_ff00) | ((minor << 12) & 0xfff0_0000) | (minor & 0x0000_00ff);
    let dev = dev as u32;
    let error = if u64::from((dev & 0x000f_ff00) >> 8) != major {
        Some(MAJOR_ERROR)
    } else if u64::from(((dev & 0xfff0_0000) >> 12) | (dev & 0x0000_00ff)) != minor {
        Some(MINOR_ERROR)
    } else {
        None
    };
    (dev as Dev, error)
}

/// A device number of a major number in the `MAJOR` bits, `SHIFT` up, and a
/// minor number in the `MINOR` bits.
fn pack_split<const SHIFT: u32, const MAJOR: u32, const MINOR: u32>(
    n: &[u64],
) -> (Dev, Option<&'static str>) {
    let &[major, minor] = n else {
        return (0, Some(TOO_MANY_FIELDS));
    };
    let dev = (((major << SHIFT) & u64::from(MAJOR)) | (minor & u64::from(MINOR))) as u32;
    // Unlike the native and NetBSD formats, a bad minor number hides a bad
    // major number.
    let mut error = None;
    if u64::from((dev & MAJOR) >> SHIFT) != major {
        error = Some(MAJOR_ERROR);
    }
    if u64::from(dev & MINOR) != minor {
        error = Some(MINOR_ERROR);
    }
    (dev as Dev, error)
}

fn pack_bsdos(n: &[u64]) -> (Dev, Option<&'static str>) {
    let &[major, unit, subunit] = n else {
        return pack_split::<20, 0xfff0_0000, 0x000f_ffff>(n);
    };
    let dev = (((major << 20) & 0xfff0_0000)
        | ((unit << 8) & 0x000f_ff00)
        | (subunit & 0x0000_00ff)) as u32;
    let mut error = None;
    if u64::from((dev & 0xfff0_0000) >> 20) != major {
        error = Some(MAJOR_ERROR);
    }
    if u64::from((dev & 0x000f_ff00) >> 8) != unit {
        error = Some("invalid unit number");
    }
    if u64::from(dev & 0x0000_00ff) != subunit {
        error = Some("invalid subunit number");
    }
    (dev as Dev, error)
}

/// `__archive_pack_find`: the packing function of a format by name.
pub fn pack_find(name: &[u8]) -> Option<Pack> {
    Some(match name {
        b"386bsd" | b"4bsd" | b"isc" | b"linux" | b"sco" | b"sunos" | b"svr3" | b"ultrix" => {
            pack_split::<8, 0x0000_ff00, 0x0000_00ff>
        }
        b"bsdos" => pack_bsdos,
        b"freebsd" => pack_split::<8, 0x0000_ff00, 0xffff_00ff>,
        b"hpux" => pack_split::<24, 0xff00_0000, 0x00ff_ffff>,
        b"native" => pack_native,
        b"netbsd" => pack_netbsd,
        b"osf1" => pack_split::<20, 0xfff0_0000, 0x000f_ffff>,
        b"solaris" | b"svr4" => pack_split::<18, 0xfffc_0000, 0x0003_ffff>,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(format: &[u8], n: &[u64]) -> (Dev, Option<&'static str>) {
        pack_find(format).map_or((0, Some("unknown")), |f| f(n))
    }

    #[test]
    fn packs_known_formats() {
        assert_eq!(pack(b"linux", &[12, 34]), (0x0c22, None));
        assert_eq!(pack(b"netbsd", &[1, 0x123]), (0x0010_0123, None));
        assert_eq!(pack(b"bsdos", &[1, 2, 3]), (0x0010_0203, None));
        assert_eq!(pack(b"solaris", &[1, 2]), (0x0004_0002, None));
        assert!(pack_find(b"nonesuch").is_none());
    }

    #[test]
    fn rejects_numbers_that_do_not_fit() {
        assert_eq!(pack(b"linux", &[256, 1]).1, Some(MAJOR_ERROR));
        assert_eq!(pack(b"linux", &[1, 256]).1, Some(MINOR_ERROR));
        // A bad minor number hides a bad major number, except in netbsd.
        assert_eq!(pack(b"linux", &[256, 256]).1, Some(MINOR_ERROR));
        assert_eq!(pack(b"netbsd", &[0x1000, 1 << 20]).1, Some(MAJOR_ERROR));
        assert_eq!(
            pack(b"bsdos", &[1, 0x1000, 3]).1,
            Some("invalid unit number")
        );
        assert_eq!(pack(b"linux", &[1]).1, Some(TOO_MANY_FIELDS));
    }
}
