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

// Ported from libarchive/archive_read_add_passphrase.c.

//! Decryption passphrases: the list `archive_read_add_passphrase` builds, the
//! callback of last resort, and the candidate iteration format readers drive
//! with `reset` and `next`.

use crate::archive::{ARCHIVE_ERRNO_MISC, ARCHIVE_FAILED};
use crate::util::Error;
use std::collections::VecDeque;

/// Asks the client for a passphrase; `None` if it has none to offer.
pub type PassphraseCallback = Box<dyn FnMut() -> Option<Vec<u8>>>;

#[derive(Default)]
pub struct Passphrases {
    /// Candidates, rotated while a reader tries them out.
    list: VecDeque<Vec<u8>>,
    /// How many candidates are left to try for the current entry; negative
    /// before the first `next` after a `reset`.
    candidate: i32,
    callback: Option<PassphraseCallback>,
}

impl Passphrases {
    fn rotate(&mut self) {
        if self.list.len() > 1 {
            self.list.rotate_left(1);
        }
    }

    /// `archive_read_add_passphrase`, after the state check.
    pub fn add(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        if passphrase.is_empty() {
            return Err(Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_MISC,
                "Empty passphrase is unacceptable",
            ));
        }
        self.list.push_back(passphrase.to_vec());
        Ok(())
    }

    /// `archive_read_set_passphrase_callback`, after the state check.
    pub fn set_callback(&mut self, callback: Option<PassphraseCallback>) {
        self.callback = callback;
    }

    /// `__archive_read_reset_passphrase`: call in advance when you start to
    /// get a passphrase for decryption for an entry.
    pub fn reset(&mut self) {
        self.candidate = -1;
    }

    /// `__archive_read_next_passphrase`: the next passphrase to try, or `None`
    /// once every one has failed and the callback has nothing new. A
    /// passphrase the callback supplies joins the list as the head.
    pub fn next(&mut self) -> Option<Vec<u8>> {
        let found = if self.candidate < 0 {
            // Count out how many passphrases we have.
            self.candidate = i32::try_from(self.list.len()).unwrap_or(i32::MAX);
            self.list.front().cloned()
        } else if self.candidate > 1 {
            // Rotate the list and pick a new candidate.
            self.candidate -= 1;
            self.rotate();
            self.list.front().cloned()
        } else if self.candidate == 1 {
            // All candidates failed to decrypt.
            self.candidate = 0;
            self.rotate();
            None
        } else {
            None
        };
        if found.is_some() {
            return found;
        }
        // We tried all passphrases out, or we don't have any.
        let passphrase = self.callback.as_mut()?();
        if let Some(p) = &passphrase {
            self.list.push_front(p.clone());
            self.candidate = 1;
        }
        passphrase
    }
}

impl Drop for Passphrases {
    /// A passphrase should be cleaned.
    fn drop(&mut self) {
        for p in &mut self.list {
            p.fill(0);
            std::hint::black_box(&p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next(p: &mut Passphrases) -> Option<String> {
        p.next().map(|v| String::from_utf8_lossy(&v).into_owned())
    }

    #[test]
    fn empty_passphrase_is_refused() {
        let mut p = Passphrases::default();
        let e = p.add(b"").unwrap_err();
        assert_eq!((e.code, e.errno), (ARCHIVE_FAILED, ARCHIVE_ERRNO_MISC));
        assert_eq!(e.msg, b"Empty passphrase is unacceptable");
    }

    #[test]
    fn candidates_come_in_order_and_the_winner_stays_in_front() {
        let mut p = Passphrases::default();
        for s in ["a", "b", "c"] {
            p.add(s.as_bytes()).unwrap();
        }
        // Trying every candidate rotates the list a full turn.
        p.reset();
        let all = [next(&mut p), next(&mut p), next(&mut p), next(&mut p)];
        assert_eq!(
            all,
            [Some("a".into()), Some("b".into()), Some("c".into()), None]
        );
        // If the second one decrypts, the next entry starts with it.
        p.reset();
        assert_eq!(next(&mut p).as_deref(), Some("a"));
        assert_eq!(next(&mut p).as_deref(), Some("b"));
        p.reset();
        assert_eq!(next(&mut p).as_deref(), Some("b"));
        assert_eq!(next(&mut p).as_deref(), Some("c"));
        assert_eq!(next(&mut p).as_deref(), Some("a"));
        assert_eq!(next(&mut p), None);
        // Without a reset there is nothing more to offer.
        assert_eq!(next(&mut p), None);
    }

    #[test]
    fn callback_supplies_a_head_candidate_when_the_list_runs_out() {
        let mut p = Passphrases::default();
        let mut offers = vec!["from-callback".to_string()];
        p.set_callback(Some(Box::new(move || offers.pop().map(String::into_bytes))));
        p.add(b"first").unwrap();
        p.reset();
        assert_eq!(next(&mut p).as_deref(), Some("first"));
        assert_eq!(next(&mut p).as_deref(), Some("from-callback"));
        // The callback has nothing more; the list was rotated.
        assert_eq!(next(&mut p), None);
        p.reset();
        assert_eq!(next(&mut p).as_deref(), Some("first"));
        assert_eq!(next(&mut p).as_deref(), Some("from-callback"));
        assert_eq!(next(&mut p), None);
    }

    #[test]
    fn callback_alone_serves_an_empty_list() {
        let mut p = Passphrases::default();
        let mut once = Some(b"secret".to_vec());
        p.set_callback(Some(Box::new(move || once.take())));
        p.reset();
        assert_eq!(next(&mut p).as_deref(), Some("secret"));
        assert_eq!(next(&mut p), None);
        p.reset();
        assert_eq!(next(&mut p).as_deref(), Some("secret"));
    }
}
