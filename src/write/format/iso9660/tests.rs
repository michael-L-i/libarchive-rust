//! The writer through the archive_write machinery: what upstream does where
//! its tests don't look, and the places where it would read or write out of
//! bounds, which fail cleanly here.

use super::*;
use crate::archive::{WRITE_MAGIC, state};
use crate::entry::AE_IFDIR;
use crate::write::Write;
use std::cell::RefCell;
use std::rc::Rc;

struct Collect(Rc<RefCell<Vec<u8>>>);
impl Sink for Collect {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.0.borrow_mut().extend_from_slice(data);
        Ok(())
    }
}

struct Iso {
    base: Base,
    writer: Write,
    out: Rc<RefCell<Vec<u8>>>,
}

impl Iso {
    fn new(options: &[(&str, Option<&str>)]) -> Self {
        let base = Base::new(WRITE_MAGIC);
        let mut writer = Write::default();
        writer.set_format(&base, Box::new(Iso9660::default()));
        for (key, value) in options {
            let r = writer.option(
                &base,
                Some(b"iso9660"),
                key.as_bytes(),
                value.map(str::as_bytes),
                true,
                true,
            );
            assert_eq!(r, ARCHIVE_OK, "option {key}");
        }
        let out = Rc::new(RefCell::new(Vec::new()));
        assert_eq!(
            writer.open(&base, Box::new(Collect(out.clone()))),
            ARCHIVE_OK
        );
        Iso { base, writer, out }
    }

    fn add(&mut self, path: &str, mode: u32, data: &[u8]) -> c_int {
        let mut e = Entry::new(None);
        e.set_pathname(path.as_bytes());
        e.set_mode(mode as _);
        e.set_size(data.len() as i64);
        e.set_mtime(1_700_000_000, 0);
        let r = self.writer.header(&self.base, &mut e);
        if r >= ARCHIVE_WARN && !data.is_empty() {
            assert_eq!(self.writer.data(&self.base, data), data.len() as isize);
        }
        r
    }

    fn symlink(&mut self, path: &str, target: &str) -> c_int {
        let mut e = Entry::new(None);
        e.set_pathname(path.as_bytes());
        e.set_mode((AE_IFLNK | 0o777) as _);
        e.set_symlink(target.as_bytes());
        self.writer.header(&self.base, &mut e)
    }

    fn dir(&mut self, path: &str) -> c_int {
        self.add(path, AE_IFDIR as u32 | 0o755, b"")
    }

    fn close(&mut self) -> (c_int, Vec<u8>) {
        let r = self.writer.close(&self.base);
        let msg = self
            .base
            .error_string()
            .map(|s| s.to_vec())
            .unwrap_or_default();
        (r, msg)
    }
}

fn file() -> u32 {
    AE_IFREG as u32 | 0o644
}

#[test]
fn a_string_option_switched_off_is_refused() {
    // Upstream takes strlen() of the NULL value of "!volume-id".
    let base = Base::new(WRITE_MAGIC);
    let mut writer = Write::default();
    writer.set_format(&base, Box::new(Iso9660::default()));
    for key in ["volume-id", "publisher", "boot-catalog", "abstract-file"] {
        let r = writer.option(&base, Some(b"iso9660"), key.as_bytes(), None, true, false);
        assert_eq!(r, ARCHIVE_FATAL);
        let expect = format!("Invalid value(empty) for option ``{key}''");
        assert_eq!(base.error_string().as_deref(), Some(expect.as_bytes()));
    }
    // "Rockridge" sits under upstream's case 'r' but starts with 'R'.
    assert_eq!(
        writer.option(
            &base,
            Some(b"iso9660"),
            b"Rockridge",
            Some(b"1"),
            true,
            false
        ),
        ARCHIVE_WARN
    );
}

#[test]
fn a_symbolic_link_continuing_with_no_room_fails() {
    // Two long names fill the directory's continuation area so that the
    // link's "SL" entries continue with 11 bytes left, where upstream sets
    // the continue flag of a component it never started.
    let mut iso = Iso::new(&[]);
    for i in 0..2 {
        assert_eq!(
            iso.add(&format!("d/a{i:03}{}", "x".repeat(240)), file(), b""),
            ARCHIVE_OK
        );
    }
    let target: String = "abcd/".repeat(2000).chars().take(2600).collect();
    assert_eq!(iso.symlink("d/zzz", &target), ARCHIVE_OK);
    let (r, msg) = iso.close();
    assert_eq!(r, ARCHIVE_FATAL);
    assert_eq!(msg, b"No room for a symbolic link component");
}

/// A chain of directories `depth` deep under `name`, with a file at the
/// bottom.
fn chain(iso: &mut Iso, name: &str, depth: usize) {
    let mut path = name.to_string();
    for level in 1..=depth {
        path.push_str(&format!("/l{level}"));
    }
    assert_eq!(iso.add(&format!("{path}/f"), file(), b"f"), ARCHIVE_OK);
}

#[test]
fn relocation_works_to_depth_thirteen_and_fails_past_it() {
    let mut iso = Iso::new(&[]);
    chain(&mut iso, "d", 12);
    let (r, _) = iso.close();
    assert_eq!(r, ARCHIVE_OK);
    let image = iso.out.borrow();
    assert!(image.windows(8).any(|w| w == b"RR_MOVED"));

    // The second pass over level 8 relocates the first pass's work again,
    // and the copy collides with the first in rr_moved.
    let mut iso = Iso::new(&[]);
    chain(&mut iso, "d", 13);
    assert_eq!(
        iso.close(),
        (ARCHIVE_FATAL, b"Unable to insert rr_moved entry".to_vec())
    );
}

#[test]
fn relocation_without_the_depth_limit_fails_at_the_left_behind_entry() {
    // With more than eight levels kept, the walks also visit the entry a
    // relocated directory left behind, a file with no contents.
    let mut iso = Iso::new(&[("limit-depth", None)]);
    chain(&mut iso, "d", 9);
    assert_eq!(
        iso.close(),
        (ARCHIVE_FATAL, b"No current file content".to_vec())
    );
}

#[test]
fn moving_an_rr_moved_that_heads_only_the_subdirectories_fails() {
    // Upstream looks for the entry after the head of each chain.
    let mut iso = Iso::new(&[]);
    assert_eq!(iso.add("aaa", file(), b"a"), ARCHIVE_OK);
    assert_eq!(iso.dir("rr_moved"), ARCHIVE_OK);
    assert_eq!(iso.dir("zz"), ARCHIVE_OK);
    chain(&mut iso, "r", 8);
    assert_eq!(
        iso.close(),
        (
            ARCHIVE_FATAL,
            b"Can't remove an entry from its directory".to_vec()
        )
    );
}

#[test]
fn a_path_table_filling_its_block_fails_without_a_message() {
    // write_path_table() returns the size of its deepest level when the
    // table ends on a block boundary, and close takes that for a failure.
    let mut iso = Iso::new(&[]);
    assert_eq!(iso.dir("D1/D2/D3/D4/D5/D6/D7"), ARCHIVE_OK);
    for i in 0..251 {
        assert_eq!(iso.dir(&format!("DIR{i:05}")), ARCHIVE_OK);
    }
    let r = iso.writer.close(&iso.base);
    assert_eq!(r, ARCHIVE_FATAL);
    assert_eq!(iso.base.error_string().as_deref(), None);
    assert_eq!(iso.base.state.get(), state::CLOSED);
}

#[test]
fn the_boot_table_checksum_reuses_the_last_read() {
    // The image is 64 + 4096 + 2 bytes: the second read of the checksum
    // fills two bytes of the buffer, and the word it sums ends with the
    // two the first read left there.
    let boot: Vec<u8> = (0..64 + 4096 + 2)
        .map(|i: u32| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let mut iso = Iso::new(&[("boot", Some("boot.img")), ("boot-info-table", Some("1"))]);
    assert_eq!(iso.add("boot.img", file(), &boot), ARCHIVE_OK);
    assert_eq!(iso.close().0, ARCHIVE_OK);
    let le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let mut sum = boot[64..64 + 4096]
        .chunks(4)
        .fold(0u32, |s, w| s.wrapping_add(le(w)));
    sum = sum.wrapping_add(le(&[boot[4160], boot[4161], boot[66], boot[67]]));

    // The table replaces bytes 8 to 64 of the image.
    let image = iso.out.borrow();
    let at = image.windows(32).position(|w| w == &boot[64..96]).unwrap();
    assert_eq!(&image[at - 64..at - 56], &boot[..8]);
    let table = &image[at - 56..at];
    assert_eq!(le(&table[0..4]), 16);
    assert_eq!(le(&table[8..12]), boot.len() as u32);
    assert_eq!(le(&table[12..16]), sum);
    assert!(table[16..56].iter().all(|&b| b == 0));
}

#[test]
fn a_boot_file_too_small_for_its_table_fails() {
    let mut iso = Iso::new(&[("boot", Some("boot.img")), ("boot-info-table", Some("1"))]);
    assert_eq!(iso.add("boot.img", file(), &[1; 64]), ARCHIVE_OK);
    assert_eq!(
        iso.close(),
        (ARCHIVE_FATAL, b"Boot file(64) is too small".to_vec())
    );
}

#[test]
fn header_failures_keep_upstreams_codes() {
    let mut iso = Iso::new(&[("rockridge", None)]);
    assert_eq!(iso.symlink("link", "x"), ARCHIVE_WARN);
    assert_eq!(
        iso.base.error_string().as_deref(),
        Some(&b"Ignore symlink file"[..])
    );
    assert_eq!(iso.add("f", file(), b"x"), ARCHIVE_OK);
    assert_eq!(iso.dir("f"), ARCHIVE_FAILED);
    assert_eq!(
        iso.base.error_string().as_deref(),
        Some(&b"Found duplicate entries `f' and its file type is different"[..])
    );
    assert_eq!(iso.add("f/g", file(), b"x"), ARCHIVE_FAILED);
    assert_eq!(
        iso.base.error_string().as_deref(),
        Some(&b"`f' is not directory, we cannot insert `f/g' "[..])
    );
    assert_eq!(
        iso.add(&format!("{}/f", "x".repeat(256)), file(), b"x"),
        ARCHIVE_FATAL
    );
    assert_eq!(
        iso.base.error_string().as_deref(),
        Some(&b"A name buffer is too small"[..])
    );
}

#[test]
fn an_unwritten_file_is_not_padded() {
    // A file whose declared data never comes keeps no contents, and one
    // with part of it is filled with zeros to its size.
    let mut iso = Iso::new(&[]);
    let mut e = Entry::new(None);
    e.set_pathname(b"none");
    e.set_mode(file() as _);
    e.set_size(5000);
    assert_eq!(iso.writer.header(&iso.base, &mut e), ARCHIVE_OK);
    let mut e = Entry::new(None);
    e.set_pathname(b"half");
    e.set_mode(file() as _);
    e.set_size(5000);
    assert_eq!(iso.writer.header(&iso.base, &mut e), ARCHIVE_OK);
    assert_eq!(iso.writer.data(&iso.base, &[7; 100]), 100);
    assert_eq!(iso.close().0, ARCHIVE_OK);
    let image = iso.out.borrow();
    // 16 system blocks, the PVD, SVD, terminator and information blocks,
    // 4 x 2 path table blocks, two root directories, the ER block and the 3
    // blocks of "half", then 150 blocks of padding.
    let pvd = 16 * LOGICAL_BLOCK_SIZE;
    assert_eq!(&image[pvd + 80..pvd + 84], &184u32.to_le_bytes());
    assert!(image.windows(100).any(|w| w == [7; 100]));
}

#[test]
fn information_block_records_options_and_zero_padding() {
    let mut iso = Iso::new(&[
        ("iso-level", Some("3")),
        ("joliet", Some("long")),
        ("pad", None),
    ]);
    assert_eq!(iso.close().0, ARCHIVE_OK);
    let image = iso.out.borrow();
    let info = &image[19 * LOGICAL_BLOCK_SIZE..20 * LOGICAL_BLOCK_SIZE];
    assert!(info.starts_with(b"INFO "));
    assert!(
        info.windows(crate::util::VERSION_STRING.to_bytes().len())
            .any(|w| w == crate::util::VERSION_STRING.to_bytes())
    );
    let end = info.iter().position(|&b| b == 0).unwrap();
    assert!(info[..end].ends_with(b" iso-level=3,joliet=long,!pad"));
    assert!(info[end..].iter().all(|&b| b == 0));
}

#[test]
fn option_validation_keeps_upstreams_boundaries_and_messages() {
    let base = Base::new(WRITE_MAGIC);
    let mut format = Iso9660::default();
    for (key, value, message) in [
        (
            "boot-load-seg",
            "10000",
            "Invalid value(over 0xffff) for option ``boot-load-seg''",
        ),
        (
            "boot-load-seg",
            "0xg",
            "Invalid value for option ``boot-load-seg''",
        ),
        (
            "boot-load-size",
            "0",
            "Invalid value(under 1) for option ``boot-load-size''",
        ),
        (
            "boot-load-size",
            "65536",
            "Invalid value(over 65535) for option ``boot-load-size''",
        ),
        (
            "compression-level",
            "10",
            "Invalid value for option ``compression-level''",
        ),
        (
            "compression-level",
            "-1",
            "Invalid value for option ``compression-level''",
        ),
        ("joliet", "0", "Invalid value for option ``joliet''"),
        ("rockridge", "0", "Invalid value for option ``rockridge''"),
    ] {
        let error = format
            .options(&base, key.as_bytes(), Some(value.as_bytes()))
            .unwrap_err();
        assert_eq!(
            error.code,
            if message.contains("value for") {
                ARCHIVE_FAILED
            } else {
                ARCHIVE_FATAL
            },
            "{key}={value}"
        );
        assert_eq!(error.msg.as_slice(), message.as_bytes(), "{key}={value}");
    }
    for (key, value) in [
        ("boot-load-seg", "0xFfFf"),
        ("boot-load-seg", ""),
        ("boot-load-size", "65535"),
        ("boot-load-size", "1"),
        ("compression-level", "0"),
        ("compression-level", "9"),
        ("joliet", "long"),
        ("joliet", "1"),
        ("rockridge", "strict"),
        ("rockridge", "useful"),
        ("rockridge", "1"),
    ] {
        assert_eq!(
            format
                .options(&base, key.as_bytes(), Some(value.as_bytes()))
                .unwrap(),
            ARCHIVE_OK
        );
    }
    for key in [b"joliet".as_slice(), b"rockridge"] {
        assert_eq!(format.options(&base, key, None).unwrap(), ARCHIVE_OK);
    }
    for (key, limit) in [
        ("volume-id", 32),
        ("publisher", 128),
        ("application-id", 128),
        ("boot-catalog", 1024),
    ] {
        assert_eq!(
            format
                .options(&base, key.as_bytes(), Some(&vec![b'x'; limit]))
                .unwrap(),
            ARCHIVE_OK
        );
        let error = format
            .options(&base, key.as_bytes(), Some(&vec![b'x'; limit + 1]))
            .unwrap_err();
        assert_eq!(
            error.msg.as_slice(),
            format!("Value is longer than {limit} characters for option ``{key}''").as_bytes()
        );
    }
}

#[test]
fn joliet_rejects_paths_over_240_bytes() {
    let parent = "x".repeat(80);
    let name = "y".repeat(80);
    let mut iso = Iso::new(&[("joliet", Some("long"))]);
    let path = format!("{parent}/{parent}/{name}");
    assert_eq!(iso.add(&path, file(), b"f"), ARCHIVE_OK);
    assert_eq!(iso.close(), (ARCHIVE_FATAL,
        format!("The regulation of Joliet extensions; A length of a full-pathname of `{path}' is longer than 240 bytes, (p=163, b=80)").into_bytes()));
}

#[test]
fn directories_too_deep_warns_after_writing_a_truncated_image() {
    let mut iso = Iso::new(&[("rockridge", None), ("joliet", None)]);
    chain(&mut iso, "d", 9);
    let (status, message) = iso.close();
    assert_eq!(status, ARCHIVE_WARN);
    assert!(message.ends_with(b": Directories too deep"));
    let image = iso.out.borrow();
    assert!(image.len() >= WB_BUFFMAX);
    assert_eq!(image.len() % WB_BUFFMAX, 0);
    let blocks = u32::from_le_bytes(
        image[16 * LOGICAL_BLOCK_SIZE + 80..16 * LOGICAL_BLOCK_SIZE + 84]
            .try_into()
            .unwrap(),
    );
    assert!(image.len() < blocks as usize * LOGICAL_BLOCK_SIZE);
}

#[test]
fn joliet_keeps_original_tree_after_rockridge_relocation() {
    let mut iso = Iso::new(&[]);
    chain(&mut iso, "d", 9);
    assert_eq!(iso.close().0, ARCHIVE_OK);
    let image = iso.out.borrow().clone();
    assert!(image.windows(8).any(|w| w == b"RR_MOVED"));
    let mut reader = crate::ArchiveRead::new();
    assert_eq!(reader.support_format_all(), crate::Status::Ok);
    assert_eq!(
        reader.set_option(Some(b"iso9660"), Some(b"rockridge"), None),
        crate::Status::Ok
    );
    assert_eq!(reader.open_memory(image), crate::Status::Ok);
    let mut paths = Vec::new();
    while reader.next_header() == crate::Status::Ok {
        paths.push(reader.entry().pathname().unwrap().to_vec());
    }
    assert!(paths.iter().any(|p| p == b"d/l1/l2/l3/l4/l5/l6/l7/l8/l9/f"));
    assert!(!paths.iter().any(|p| p.windows(8).any(|s| s == b"rr_moved")));
}

#[test]
fn unconvertible_names_warn_with_the_utf16be_message() {
    let mut iso = Iso::new(&[]);
    let mut entry = Entry::new(None);
    entry.set_pathname_utf8(b"invalid\xff");
    entry.set_mode(file() as _);
    entry.set_size(0);
    assert_eq!(iso.writer.header(&iso.base, &mut entry), ARCHIVE_WARN);
    assert_eq!(iso.base.error_string().as_deref(), Some(b"A filename cannot be converted to UTF-16BE;You should disable making Joliet extension".as_slice()));
}

#[test]
#[ignore = "writes a 4 GiB temporary file; run alongside the sparse ISO harness"]
fn level_three_writes_multi_extent_records_from_a_declared_size() {
    struct Prefix(Rc<RefCell<Vec<u8>>>);
    impl Sink for Prefix {
        fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            let mut prefix = self.0.borrow_mut();
            let n = data.len().min(65536usize.saturating_sub(prefix.len()));
            prefix.extend_from_slice(&data[..n]);
            Ok(())
        }
    }
    let base = Base::new(WRITE_MAGIC);
    let mut writer = Write::default();
    writer.set_format(&base, Box::new(Iso9660::default()));
    for (key, value) in [
        (b"iso-level".as_slice(), Some(b"3".as_slice())),
        (b"joliet", None),
        (b"rockridge", None),
    ] {
        assert_eq!(
            writer.option(&base, Some(b"iso9660"), key, value, true, false),
            ARCHIVE_OK
        );
    }
    let prefix = Rc::new(RefCell::new(Vec::new()));
    assert_eq!(
        writer.open(&base, Box::new(Prefix(prefix.clone()))),
        ARCHIVE_OK
    );
    let mut entry = Entry::new(None);
    entry.set_pathname(b"huge");
    entry.set_mode(file() as _);
    entry.set_size(MULTI_EXTENT_SIZE + 4096);
    assert_eq!(writer.header(&base, &mut entry), ARCHIVE_OK);
    assert_eq!(writer.data(&base, b"x"), 1);
    assert_eq!(writer.close(&base), ARCHIVE_OK);
    let image = prefix.borrow();
    let le = |bytes: &[u8]| u32::from_le_bytes(bytes.try_into().unwrap());
    let root = le(&image[16 * LOGICAL_BLOCK_SIZE + 158..16 * LOGICAL_BLOCK_SIZE + 162]) as usize
        * LOGICAL_BLOCK_SIZE;
    let mut at = root;
    let mut records = Vec::new();
    while image[at] != 0 {
        let len = image[at] as usize;
        let record = &image[at..at + len];
        if &record[33..33 + record[32] as usize] == b"HUGE;1" {
            records.push((le(&record[2..6]), le(&record[10..14]), record[25]));
        }
        at += len;
    }
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].1, 0xfffff800);
    assert_eq!(records[0].2, 0x80);
    assert_eq!(records[1].1, 6144);
    assert_eq!(records[1].2, 0);
    assert_eq!(records[1].0 - records[0].0, 2097151);
}
