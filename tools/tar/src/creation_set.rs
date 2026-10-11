/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2012 Michihiro NAKAJIMA
 * All rights reserved.
 */

// Ported from tar/creation_set.c.

//! The format and filters to write, from options or the archive's name.

use libarchive_rust::{ArchiveRead, ArchiveWrite, Status};

struct FilterSet {
    /// Whether the filter is a program name.
    program: bool,
    filter_name: Vec<u8>,
}

/// `struct creation_set`.
#[derive(Default)]
pub struct CreationSet {
    create_format: Option<Vec<u8>>,
    filters: Vec<FilterSet>,
}

/// The form `suffix` stands for in `tbl`.
fn get_suffix_code<'a>(tbl: &[(&[u8], &'a [u8])], suffix: &[u8]) -> Option<&'a [u8]> {
    tbl.iter()
        .find(|(s, _)| *s == suffix)
        .map(|&(_, form)| form)
}

fn get_filter_code(suffix: &[u8]) -> Option<&'static [u8]> {
    // A pair of suffix and compression/filter.
    const FILTERS: &[(&[u8], &[u8])] = &[
        (b".Z", b"compress"),
        (b".bz2", b"bzip2"),
        (b".gz", b"gzip"),
        (b".grz", b"grzip"),
        (b".lrz", b"lrzip"),
        (b".lz", b"lzip"),
        (b".lz4", b"lz4"),
        (b".lzo", b"lzop"),
        (b".lzma", b"lzma"),
        (b".uu", b"uuencode"),
        (b".xz", b"xz"),
        (b".zst", b"zstd"),
    ];
    get_suffix_code(FILTERS, suffix)
}

fn get_format_code(suffix: &[u8]) -> Option<&'static [u8]> {
    // A pair of suffix and format.
    const FORMATS: &[(&[u8], &[u8])] = &[
        (b".7z", b"7zip"),
        (b".ar", b"arbsd"),
        (b".cpio", b"cpio"),
        (b".iso", b"iso9660"),
        (b".mtree", b"mtree"),
        (b".shar", b"shar"),
        (b".tar", b"paxr"),
        (b".warc", b"warc"),
        (b".xar", b"xar"),
        (b".zip", b"zip"),
    ];
    get_suffix_code(FORMATS, suffix)
}

fn decompose_alias(suffix: &[u8]) -> Option<&'static [u8]> {
    const ALIAS: &[(&[u8], &[u8])] = &[
        (b".taz", b".tar.gz"),
        (b".tgz", b".tar.gz"),
        (b".tbz", b".tar.bz2"),
        (b".tbz2", b".tar.bz2"),
        (b".tz2", b".tar.bz2"),
        (b".tlz", b".tar.lzma"),
        (b".txz", b".tar.xz"),
        (b".tzo", b".tar.lzo"),
        (b".taZ", b".tar.Z"),
        (b".tZ", b".tar.Z"),
        (b".tzst", b".tar.zst"),
    ];
    get_suffix_code(ALIAS, suffix)
}

impl CreationSet {
    fn add(&mut self, program: bool, filter: &[u8]) {
        let filter_name = filter.to_vec();
        self.filters.push(FilterSet {
            program,
            filter_name,
        });
    }

    pub fn add_filter(&mut self, filter: &[u8]) {
        self.add(false, filter);
    }

    pub fn add_filter_program(&mut self, filter: &[u8]) {
        self.add(true, filter);
    }

    /// Registers the program filters to read with: how many there are.
    pub fn read_support_filter_program(&self, a: &mut ArchiveRead) -> usize {
        let mut cnt = 0;
        for f in self.filters.iter().filter(|f| f.program) {
            a.support_filter_program(&f.filter_name);
            cnt += 1;
        }
        cnt
    }

    /// Adds the filters to write with, or gives the name of the first one
    /// that fails.
    pub fn write_add_filters(&self, a: &mut ArchiveWrite) -> Result<(), &[u8]> {
        for f in &self.filters {
            let r = if f.program {
                a.add_filter_program(&f.filter_name)
            } else {
                a.add_filter_by_name(&f.filter_name)
            };
            if r < Status::Warn {
                return Err(&f.filter_name);
            }
        }
        Ok(())
    }

    pub fn set_format(&mut self, format: &[u8]) {
        self.create_format = Some(format.to_vec());
    }

    pub fn get_format(&self) -> Option<&[u8]> {
        self.create_format.as_deref()
    }

    /// Build a creation set by a file name suffix: whether it names filters.
    pub fn auto_compress(&mut self, filename: &[u8]) -> bool {
        let mut name = filename.to_vec();
        // Save previous filters.
        let old_filters = std::mem::take(&mut self.filters);

        // Get the suffix.
        while let Some(p) = name.iter().rposition(|&c| c == b'.') {
            // Suppose it indicates compression/filter type such as ".gz".
            if let Some(code) = get_filter_code(&name[p..]) {
                self.add_filter(code);
                name.truncate(p);
                continue;
            }
            // Suppose it indicates format type such as ".tar".
            if let Some(code) = get_format_code(&name[p..]) {
                self.set_format(code);
                break;
            }
            // Suppose it indicates alias such as ".tgz".
            let Some(code) = decompose_alias(&name[p..]) else {
                break;
            };
            // Replace the suffix.
            name.truncate(p);
            name.extend_from_slice(code);
        }
        if self.filters.is_empty() {
            // Put previous filters back.
            self.filters = old_filters;
            return false;
        }
        // Reverse filter sequence.
        self.filters.reverse();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(cset: &CreationSet) -> Vec<&[u8]> {
        cset.filters
            .iter()
            .map(|f| f.filter_name.as_slice())
            .collect()
    }

    #[test]
    fn auto_compress_reads_suffixes_and_aliases() {
        let mut cset = CreationSet::default();
        assert!(cset.auto_compress(b"x.tar.gz.uu"));
        assert_eq!(names(&cset), [b"gzip".as_slice(), b"uuencode"]);
        assert_eq!(cset.get_format(), Some(b"paxr".as_slice()));

        let mut cset = CreationSet::default();
        assert!(cset.auto_compress(b"x.tbz2"));
        assert_eq!(names(&cset), [b"bzip2"]);

        // Without filters, the previous ones stay, but a format is set.
        let mut cset = CreationSet::default();
        cset.add_filter(b"xz");
        assert!(!cset.auto_compress(b"x.zip"));
        assert_eq!(names(&cset), [b"xz"]);
        assert_eq!(cset.get_format(), Some(b"zip".as_slice()));
        assert!(!cset.auto_compress(b"noext"));
    }
}
