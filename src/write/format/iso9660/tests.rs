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
