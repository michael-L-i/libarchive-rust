/*-
 * Copyright (c) 2014 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_hmac.c.

//! HMAC-SHA1, for the authentication code of WinZip AES entries.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

pub const HMAC_SHA1_LEN: usize = 20;

pub struct HmacSha1(Hmac<Sha1>);

impl HmacSha1 {
    /// Any key length is valid, so this returns `None` only where upstream's
    /// `__hmac_sha1_init` would fail in its backend. Dropping the value is
    /// `__hmac_sha1_cleanup`.
    pub fn new(key: &[u8]) -> Option<HmacSha1> {
        Hmac::<Sha1>::new_from_slice(key).ok().map(HmacSha1)
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(self) -> [u8; HMAC_SHA1_LEN] {
        self.0.finalize().into_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hmac(key: &[u8], pieces: &[&[u8]]) -> String {
        let mut h = HmacSha1::new(key).expect("any key length is valid");
        for p in pieces {
            h.update(p);
        }
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn rfc2202() {
        assert_eq!(
            hmac(&[0x0b; 20], &[b"Hi There"]),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hmac(b"Jefe", &[b"what do ya want ", b"for nothing?"]),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        assert_eq!(
            hmac(&[0xaa; 20], &[&[0xdd; 50]]),
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        );
        // Keys longer than the block size are hashed first.
        assert_eq!(
            hmac(
                &[0xaa; 80],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            ),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
    }
}
