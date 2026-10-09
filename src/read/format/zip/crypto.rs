/*-
 * Copyright (c) 2004-2013 Tim Kientzle
 * Copyright (c) 2011-2012,2014 Michihiro NAKAJIMA
 * Copyright (c) 2013 Konrad Kleine
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

// Ported from libarchive/archive_read_support_format_zip.c.

//! Decryption of zip entries: traditional PKWARE and WinZip AES, and the
//! buffer that holds the decrypted bytes the decompressors read from.

use crate::archive::*;
use crate::crc32::crc32;
use crate::cryptor::AesCtr;
use crate::hmac::HmacSha1;
use crate::read::{ARCHIVE_ERRNO_FILE_FORMAT, Reader, Status};
use crate::util::Error;

/// Authentication code size.
pub(super) const AUTH_CODE_SIZE: usize = 10;

/// The size of the decryption buffer.
const BUFFER_SIZE: usize = 256 * 1024;

/// `struct trad_enc_ctx`: the state of traditional PKWARE decryption.
pub(super) struct Trad {
    keys: [u32; 3],
}

/// One step of the CRC-32 register, as `trad_enc_update_keys` takes it.
fn crc_step(c: u32, b: u8) -> u32 {
    !crc32(!c, &[b])
}

impl Trad {
    fn update_keys(&mut self, c: u8) {
        self.keys[0] = crc_step(self.keys[0], c);
        self.keys[1] = self.keys[1]
            .wrapping_add(self.keys[0] & 0xff)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        let t = (self.keys[1] >> 24) as u8;
        self.keys[2] = crc_step(self.keys[2], t);
    }

    fn decrypt_byte(&self) -> u8 {
        let temp = self.keys[2] | 2;
        (temp.wrapping_mul(temp ^ 1) >> 8) as u8
    }

    /// `trad_enc_decrypt_update`: decrypts the shorter of the two lengths.
    pub fn decrypt_update(&mut self, input: &[u8], out: &mut [u8]) -> usize {
        let mut n = 0;
        for (i, o) in input.iter().zip(out.iter_mut()) {
            let t = i ^ self.decrypt_byte();
            *o = t;
            self.update_keys(t);
            n += 1;
        }
        n
    }

    /// `trad_enc_init`: the state after the passphrase and the 12 byte
    /// encryption header, and the last byte of the decrypted header, for the
    /// CRC check.
    pub fn new(pw: &[u8], key: &[u8; 12]) -> (Trad, u8) {
        let mut ctx = Trad {
            keys: [305_419_896, 591_751_049, 878_082_192],
        };
        for &c in pw {
            ctx.update_keys(c);
        }
        let mut header = [0u8; 12];
        ctx.decrypt_update(key, &mut header);
        (ctx, header[11])
    }
}

/// Decrypts with whichever cipher is active.
fn decrypt_update(
    trad: &mut Option<Trad>,
    aes: &mut Option<AesCtr>,
    input: &[u8],
    out: &mut [u8],
) -> usize {
    match (trad, aes) {
        (Some(t), _) => t.decrypt_update(input, out),
        (None, Some(c)) => c.update(input, out),
        (None, None) => 0,
    }
}

/// The decryption state of the entry being read, and the decryption buffer.
///
/// The decrypted data starts at `ptr` and extends for `remaining`.
/// Decryption adds new data to the end of this block, data is returned to
/// the decompressors from the beginning. When the block hits the end of the
/// buffer, it has to be shuffled back to the beginning of the buffer.
#[derive(Default)]
pub(super) struct Crypto {
    /// Traditional PKWARE decryption.
    pub trad: Option<Trad>,
    /// WinZip AES decryption.
    pub aes: Option<AesCtr>,
    pub hmac: Option<HmacSha1>,
    /// `hctx_valid`: stays set after the HMAC is finished.
    pub hmac_valid: bool,
    buf: Vec<u8>,
    ptr: usize,
    remaining: usize,
}

impl Crypto {
    /// Forgets the decryption of the previous entry.
    pub fn reset(&mut self) {
        self.trad = None;
        self.aes = None;
        self.hmac = None;
        self.hmac_valid = false;
    }

    /// `tctx_valid || cctx_valid`.
    pub fn active(&self) -> bool {
        self.trad.is_some() || self.aes.is_some()
    }

    /// Decrypts stored data into the start of the buffer, as much as fits.
    /// Returns how many bytes of `raw` that was. The HMAC covers the raw
    /// bytes.
    pub fn decrypt_stored(&mut self, raw: &[u8]) -> usize {
        let n = raw.len().min(self.buf.len());
        if let (Some(from), Some(to)) = (raw.get(..n), self.buf.get_mut(..n)) {
            if self.hmac_valid
                && let Some(h) = &mut self.hmac
            {
                h.update(from);
            }
            decrypt_update(&mut self.trad, &mut self.aes, from, to);
        }
        n
    }

    /// The first `n` bytes of the buffer.
    pub fn decrypted(&self, n: usize) -> &[u8] {
        self.buf.get(..n).unwrap_or_default()
    }

    /// Decrypts bytes that are consumed as they are read, with no
    /// buffering, and updates the HMAC (zstd).
    pub fn decrypt_into(&mut self, raw: &[u8], out: &mut [u8]) -> usize {
        if self.hmac_valid
            && let Some(h) = &mut self.hmac
        {
            h.update(raw);
        }
        if self.active() {
            decrypt_update(&mut self.trad, &mut self.aes, raw, out)
        } else {
            let n = raw.len().min(out.len());
            if let (Some(from), Some(to)) = (raw.get(..n), out.get_mut(..n)) {
                to.copy_from_slice(from);
            }
            n
        }
    }

    /// `zip_alloc_decryption_buffer`. A buffer of at least `min` bytes is
    /// kept, which only bzip2 needs more than the usual size of.
    pub fn alloc_buffer(&mut self, min: usize) -> Result<(), Error> {
        let want = BUFFER_SIZE.max(min);
        if self.buf.len() < want {
            let extra = want - self.buf.len();
            if self.buf.try_reserve_exact(extra).is_err() {
                return Err(Error::fatal(libc::ENOMEM, "No memory for ZIP decryption"));
            }
            self.buf.resize(want, 0);
        }
        self.ptr = 0;
        Ok(())
    }

    /// Makes sure the buffer can hold `min` bytes.
    pub fn ensure_buffer(&mut self, min: usize) -> Result<(), Error> {
        if self.buf.len() >= min {
            return Ok(());
        }
        let ptr = self.ptr;
        self.alloc_buffer(min)?;
        self.ptr = ptr;
        Ok(())
    }

    /// Sets the buffer up for a new entry's encryption.
    pub fn start(&mut self) -> Result<(), Error> {
        self.remaining = 0;
        self.alloc_buffer(0)
    }

    /// `zip_read_decrypt`: decrypts bulk compressed data for zipx
    /// decompression. `comp` is what the stream has, `bytes_avail` of it
    /// usable. Manages the decryption buffer, handles partial fills, and
    /// returns the bytes the decompressor reads from. `limit` is the number
    /// of compressed bytes the entry has left, when it is known.
    pub fn prepare<'a>(
        &'a mut self,
        comp: &'a [u8],
        bytes_avail: usize,
        limit: Option<i64>,
    ) -> &'a [u8] {
        let avail = comp.get(..bytes_avail).unwrap_or(comp);
        if !self.active() {
            return avail;
        }
        let Crypto {
            trad,
            aes,
            buf,
            ptr,
            remaining,
            ..
        } = self;
        if *remaining < avail.len() {
            let mut buff_remaining = buf.len().saturating_sub(ptr.saturating_add(*remaining));
            // The new bytes to decrypt start after the bytes that were
            // already decrypted on a previous call but have not yet been
            // consumed.
            let new_bytes = avail.len() - *remaining;
            buff_remaining = buff_remaining.min(new_bytes);

            if let Some(entry_bytes_remaining) = limit
                && i64::try_from(remaining.saturating_add(buff_remaining))
                    .map_or(true, |n| n > entry_bytes_remaining)
            {
                buff_remaining = usize::try_from(entry_bytes_remaining)
                    .ok()
                    .and_then(|e| e.checked_sub(*remaining))
                    .unwrap_or(0);
            }
            if buff_remaining > 0 {
                let from = avail.get(*remaining..*remaining + buff_remaining);
                let start = *ptr + *remaining;
                let to = buf.get_mut(start..start + buff_remaining);
                if let (Some(from), Some(to)) = (from, to) {
                    decrypt_update(trad, aes, from, to);
                    *remaining += buff_remaining;
                }
            }
        }
        buf.get(*ptr..*ptr + *remaining).unwrap_or_default()
    }

    /// `zip_read_decrypt_update`: after the decompressor has consumed
    /// `to_consume` bytes of what `prepare` gave, updates the buffer and the
    /// HMAC, which covers the raw bytes `raw`.
    pub fn finish(&mut self, to_consume: usize, raw: &[u8]) {
        if self.active() {
            self.remaining = self.remaining.saturating_sub(to_consume);
            if self.remaining == 0 {
                self.ptr = 0;
            } else {
                self.ptr += to_consume;
            }
        }
        if self.hmac_valid
            && let Some(h) = &mut self.hmac
        {
            h.update(raw.get(..to_consume).unwrap_or(raw));
        }
    }

    /// `zipx_read_header_and_decrypt`: reads and decrypts bytes for the init
    /// headers of formats that need a small header from the compressed
    /// stream (lzma, ppmd). The bytes are not consumed.
    pub fn read_header(&mut self, r: &mut Reader<'_>, in_len: usize) -> Result<Vec<u8>, Error> {
        let truncated = || Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated ZIP file data");
        let raw = match r.read_ahead(in_len) {
            Ok(Some(raw)) => raw.get(..in_len).unwrap_or_default(),
            _ => return Err(truncated()),
        };
        if !self.active() {
            return Ok(raw.to_vec());
        }
        let n = in_len.min(self.buf.len());
        let (from, to) = (raw.get(..n), self.buf.get_mut(..n));
        let (Some(from), Some(to)) = (from, to) else {
            return Err(truncated());
        };
        decrypt_update(&mut self.trad, &mut self.aes, from, to);
        if self.hmac_valid
            && let Some(h) = &mut self.hmac
        {
            h.update(from);
        }
        Ok(to.to_vec())
    }

    /// `check_authentication_code`. `code` is the code, if the caller has it
    /// already; else it is read from the stream. The code is consumed.
    pub fn check_authentication_code(
        &mut self,
        r: &mut Reader<'_>,
        code: Option<&[u8]>,
    ) -> Result<Status, Error> {
        if !self.hmac_valid {
            return Ok(Status::Ok);
        }
        let hmac = self.hmac.take().map(HmacSha1::finalize).unwrap_or_default();
        let code = match code {
            Some(c) => c.to_vec(),
            None => match r.read_ahead(AUTH_CODE_SIZE) {
                Ok(Some(p)) => p.get(..AUTH_CODE_SIZE).unwrap_or_default().to_vec(),
                _ => {
                    return Err(Error::fatal(
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        "Truncated ZIP file data",
                    ));
                }
            },
        };
        let equal = hmac.get(..AUTH_CODE_SIZE) == code.get(..AUTH_CODE_SIZE);
        r.consume(AUTH_CODE_SIZE)?;
        if !equal {
            return Ok(r.warn(ARCHIVE_ERRNO_MISC, "ZIP bad Authentication code"));
        }
        Ok(Status::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encrypts like PKWARE's `zipcrypto`, for the round trip.
    fn encrypt(pw: &[u8], plain: &[u8]) -> Vec<u8> {
        let (mut t, _) = Trad::new(pw, &[0; 12]);
        // Re-derive the keys from the passphrase alone.
        t.keys = [305_419_896, 591_751_049, 878_082_192];
        for &c in pw {
            t.update_keys(c);
        }
        plain
            .iter()
            .map(|&p| {
                let c = p ^ t.decrypt_byte();
                t.update_keys(p);
                c
            })
            .collect()
    }

    #[test]
    fn traditional_round_trip() {
        let mut data = vec![7u8; 12];
        data.extend_from_slice(b"hello, zip");
        let enc = encrypt(b"pw", &data);
        let header: [u8; 12] = enc[..12].try_into().unwrap();
        let (mut t, check) = Trad::new(b"pw", &header);
        assert_eq!(check, 7);
        let mut out = vec![0; 10];
        assert_eq!(t.decrypt_update(&enc[12..], &mut out), 10);
        assert_eq!(out, b"hello, zip");
    }
}
