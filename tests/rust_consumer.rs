#![forbid(unsafe_code)]

use libarchive_rust::{ArchiveEntry, ArchiveRead, ArchiveWrite, Status};
use std::cell::RefCell;
use std::rc::Rc;

fn main() {
    let payload: Vec<u8> = (0..98_317).map(|i| (i * 31 % 251) as u8).collect();
    for filter in [b"gzip".as_slice(), b"xz".as_slice(), b"zstd".as_slice()] {
        let output = Rc::new(RefCell::new(Vec::new()));
        let mut writer = ArchiveWrite::new();
        assert_eq!(writer.set_format_by_name(b"ustar"), Status::Ok);
        assert_eq!(writer.add_filter_by_name(filter), Status::Ok);
        assert_eq!(writer.open_memory(output.clone(), 1 << 20), Status::Ok);
        let mut entry = ArchiveEntry::new();
        entry.set_pathname(Some(b"payload.bin"));
        entry.set_mode(0o100644);
        entry.set_size(payload.len() as i64);
        assert_eq!(writer.header(&mut entry), Status::Ok);
        assert_eq!(writer.data(&payload), Ok(payload.len()));
        assert_eq!(writer.close(), Status::Ok);
        drop(writer);

        let archive = std::mem::take(&mut *output.borrow_mut());
        let mut reader = ArchiveRead::new();
        assert_eq!(reader.support_format_all(), Status::Ok);
        assert_eq!(reader.support_filter_all(), Status::Ok);
        assert_eq!(reader.open_memory(archive), Status::Ok);
        assert_eq!(reader.next_header(), Status::Ok);
        let mut recovered = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let count = reader.data(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            assert!(recovered.len() + count <= payload.len());
            recovered.extend_from_slice(&buffer[..count]);
        }
        assert_eq!(recovered, payload);
        assert_eq!(reader.next_header(), Status::Eof);
        assert_eq!(reader.close(), Status::Ok);
    }
}
