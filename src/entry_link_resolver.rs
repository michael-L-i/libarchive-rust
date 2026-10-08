/*-
 * Copyright (c) 2003-2007 Tim Kientzle
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

// Ported from libarchive/archive_entry_link_resolver.c.

//! Hard link matching for archive writers. The resolver remembers entries by
//! (dev, ino) and decides, per format, which later links become hard links
//! to an earlier entry, which entries are held back until their last link
//! arrives, and which are returned once every link has been seen.
//!
//! The table is a chained hash table with upstream's initial size, growth
//! and chain order. The order in which held-back entries come back is
//! observable through `archive_entry_linkify(NULL)` and
//! `archive_entry_partial_links`, so it must not change.

use crate::entry::{AE_IFBLK, AE_IFCHR, AE_IFDIR, Dev, Entry};
use std::ffi::{CStr, c_int};

// Format codes from archive.h, by base format and for the two new-cpio
// variants.
const FORMAT_BASE_MASK: c_int = 0xff0000;
const FORMAT_CPIO: c_int = 0x10000;
const FORMAT_SHAR: c_int = 0x20000;
const FORMAT_TAR: c_int = 0x30000;
const FORMAT_ISO9660: c_int = 0x40000;
const FORMAT_ZIP: c_int = 0x50000;
const FORMAT_AR: c_int = 0x70000;
const FORMAT_MTREE: c_int = 0x80000;
const FORMAT_XAR: c_int = 0xa0000;
const FORMAT_7ZIP: c_int = 0xe0000;
const FORMAT_CPIO_SVR4_NOCRC: c_int = 0x10004;
const FORMAT_CPIO_SVR4_CRC: c_int = 0x10005;

/// Initial size of the link table, a power of two.
const INITIAL_BUCKETS: usize = 1024;

/// How matching links are chosen. The default, before `set_strategy`, is
/// tar: upstream's table is zeroed, and tar is strategy 0.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
enum Strategy {
    /// Content is stored with the first link; the others refer back to it.
    #[default]
    Tar,
    /// Like tar, but the size of the later links is kept.
    Mtree,
    /// Every link carries its own content: nothing to match.
    OldCpio,
    /// Only the last link carries content, so earlier links are held back
    /// and handed out once it arrives.
    NewCpio,
}

impl Strategy {
    fn for_format(fmt: c_int) -> Strategy {
        match fmt & FORMAT_BASE_MASK {
            FORMAT_7ZIP | FORMAT_AR | FORMAT_ZIP => Strategy::OldCpio,
            FORMAT_CPIO => match fmt {
                FORMAT_CPIO_SVR4_NOCRC | FORMAT_CPIO_SVR4_CRC => Strategy::NewCpio,
                _ => Strategy::OldCpio,
            },
            FORMAT_MTREE => Strategy::Mtree,
            FORMAT_ISO9660 | FORMAT_SHAR | FORMAT_TAR | FORMAT_XAR => Strategy::Tar,
            _ => Strategy::OldCpio,
        }
    }
}

/// Which links `next_entry` takes: those holding an entry, or those without
/// one.
#[derive(Clone, Copy)]
enum Pick {
    Deferred,
    Partial,
}

impl Pick {
    fn matches(self, held: bool) -> bool {
        match self {
            Pick::Deferred => held,
            Pick::Partial => !held,
        }
    }
}

/// One remembered file.
struct Link {
    /// A clone of the first entry seen for this (dev, ino). `partial_links`
    /// takes it.
    canonical: Option<Box<Entry>>,
    /// The entry held back until the last link arrives (new cpio only).
    entry: Option<Box<Entry>>,
    hash: usize,
    /// Links not yet seen.
    links: u32,
}

pub(crate) struct LinkResolver {
    /// Chains of links. The head of each chain is its last element.
    buckets: Vec<Vec<Link>>,
    /// The link last taken out of the table. It is kept until the next call,
    /// as upstream keeps it, so the entry returned from it stays valid.
    spare: Option<Link>,
    number_entries: usize,
    strategy: Strategy,
}

/// The hash of (dev, ino) as upstream computes it: dev widened to 64 bits,
/// then xored with ino.
fn hash_of(dev: Dev, ino: i64) -> usize {
    ((dev as i64) ^ ino) as usize
}

/// The bucket of `hash`. The table size is always a power of two, so the
/// mask is in range.
fn bucket_of(hash: usize, buckets: usize) -> usize {
    hash & buckets.wrapping_sub(1)
}

fn same_file(le: &Link, dev: Dev, ino: i64) -> bool {
    le.canonical
        .as_deref()
        .is_some_and(|c| c.dev() == dev && c.ino() == ino)
}

impl LinkResolver {
    pub(crate) fn new() -> LinkResolver {
        LinkResolver {
            buckets: (0..INITIAL_BUCKETS).map(|_| Vec::new()).collect(),
            spare: None,
            number_entries: 0,
            strategy: Strategy::default(),
        }
    }

    pub(crate) fn set_strategy(&mut self, fmt: c_int) {
        self.strategy = Strategy::for_format(fmt);
    }

    /// `archive_entry_linkify`. Takes the entry the caller passes in and
    /// returns the entries it now owns: the first is the entry to write, the
    /// second an extra one that was held back.
    pub(crate) fn linkify(
        &mut self,
        entry: Option<Box<Entry>>,
    ) -> (Option<Box<Entry>>, Option<Box<Entry>>) {
        let Some(mut entry) = entry else {
            // The end of the stream: the next held-back entry, if any.
            let deferred = self
                .next_entry(Pick::Deferred)
                .and_then(|le| le.entry.take());
            return (deferred, None);
        };
        // If it has only one link, there is nothing to match.
        if entry.nlink() == 1 {
            return (Some(entry), None);
        }
        // Directories and devices never have hard links.
        if matches!(entry.filetype(), AE_IFDIR | AE_IFBLK | AE_IFCHR) {
            return (Some(entry), None);
        }

        match self.strategy {
            Strategy::Tar => {
                self.link_to_first(&mut entry, true);
                (Some(entry), None)
            }
            Strategy::Mtree => {
                self.link_to_first(&mut entry, false);
                (Some(entry), None)
            }
            Strategy::OldCpio => (Some(entry), None),
            Strategy::NewCpio => match self.find_entry(&entry) {
                Some(le) => {
                    // Put the new entry in the table and return the one it
                    // replaces, now a hard link to the first.
                    let mut old = le.entry.replace(entry);
                    if let Some(old) = old.as_deref_mut() {
                        old.unset_size();
                        let target = le.canonical.as_deref_mut().and_then(|c| c.pathname());
                        old.copy_hardlink(target.map(CStr::to_bytes));
                    }
                    // On the last link, the table gives up the new entry too.
                    let last = if le.links == 0 { le.entry.take() } else { None };
                    (old, last)
                }
                None => match self.insert_entry(&entry) {
                    Some(le) => {
                        // Not seen before: hold it back for the next link.
                        le.entry = Some(entry);
                        (None, None)
                    }
                    None => (Some(entry), None),
                },
            },
        }
    }

    /// The tar and mtree strategies: a later link becomes a hard link to the
    /// first entry seen for the same file. Tar also drops the size, because
    /// the content lives with the first link.
    fn link_to_first(&mut self, entry: &mut Entry, unset_size: bool) {
        match self.find_entry(entry) {
            Some(le) => {
                if unset_size {
                    entry.unset_size();
                }
                let target = le.canonical.as_deref_mut().and_then(|c| c.pathname());
                entry.copy_hardlink(target.map(CStr::to_bytes));
            }
            None => {
                self.insert_entry(entry);
            }
        }
    }

    /// Finds the link for `entry`, counting this link as seen. When it is the
    /// last one, the link leaves the table and is kept as the spare.
    fn find_entry(&mut self, entry: &Entry) -> Option<&mut Link> {
        if !entry.ino_is_set() || !entry.dev_is_set() {
            return None;
        }
        self.spare = None;

        let (dev, ino) = (entry.dev(), entry.ino());
        let hash = hash_of(dev, ino);
        let bucket = bucket_of(hash, self.buckets.len());
        let chain = &mut self.buckets[bucket];
        // The head of the chain is found first.
        let pos = chain
            .iter()
            .rposition(|le| le.hash == hash && same_file(le, dev, ino))?;
        let le = &mut chain[pos];
        le.links = le.links.wrapping_sub(1);
        if le.links == 0 {
            let removed = chain.remove(pos);
            self.number_entries -= 1;
            self.spare = Some(removed);
            return self.spare.as_mut();
        }
        Some(&mut chain[pos])
    }

    /// The first link of `pick` in bucket order, head of chain first. It is
    /// removed from the table and kept as the spare.
    fn next_entry(&mut self, pick: Pick) -> Option<&mut Link> {
        self.spare = None;
        for chain in &mut self.buckets {
            let Some(pos) = chain
                .iter()
                .rposition(|le| pick.matches(le.entry.is_some()))
            else {
                continue;
            };
            let removed = chain.remove(pos);
            self.number_entries -= 1;
            self.spare = Some(removed);
            return self.spare.as_mut();
        }
        None
    }

    /// Adds `entry` to the table with a clone of it as the canonical entry.
    fn insert_entry(&mut self, entry: &Entry) -> Option<&mut Link> {
        if !entry.ino_is_set() || !entry.dev_is_set() {
            return None;
        }
        let canonical = Box::new(entry.clone_entry());

        // Grow before the table gets too full.
        if self.number_entries / 2 > self.buckets.len() {
            self.grow();
        }

        let hash = hash_of(entry.dev(), entry.ino());
        let bucket = bucket_of(hash, self.buckets.len());
        let chain = &mut self.buckets[bucket];
        chain.push(Link {
            canonical: Some(canonical),
            entry: None,
            hash,
            // Upstream's unsigned count: nlink 0 wraps.
            links: entry.nlink().wrapping_sub(1),
        });
        self.number_entries += 1;
        chain.last_mut()
    }

    /// Doubles the table. Chains are walked head first, as upstream does, so
    /// each chain keeps its order.
    fn grow(&mut self) {
        let Some(new_size) = self.buckets.len().checked_mul(2) else {
            return;
        };
        let mut new: Vec<Vec<Link>> = Vec::new();
        if new.try_reserve_exact(new_size).is_err() {
            return;
        }
        new.resize_with(new_size, Vec::new);
        for chain in std::mem::take(&mut self.buckets) {
            for le in chain.into_iter().rev() {
                new[bucket_of(le.hash, new_size)].push(le);
            }
        }
        self.buckets = new;
    }

    /// `archive_entry_partial_links`: the next link that has not yet been
    /// seen all the way, with the number of links still to come.
    pub(crate) fn partial_links(&mut self) -> (Option<Box<Entry>>, u32) {
        self.spare = None;
        match self.next_entry(Pick::Partial) {
            Some(le) => (le.canonical.take(), le.links),
            None => (None, 0),
        }
    }
}
