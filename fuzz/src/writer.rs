//! Bounded valid-archive round trips through the safe Rust API.
#![forbid(unsafe_code)]

use libarchive_rust::{AE_IFREG, ArchiveEntry, ArchiveRead, ArchiveWrite, ReadLimits, Status};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

const MAX_OUTPUT: usize = 4 << 20;

#[derive(Clone, Copy, Debug)]
pub enum Format {
    Tar,
    Zip,
    Cpio,
    Ar,
    SevenZip,
    Xar,
    Iso,
}

pub const FORMATS: [Format; 7] = [
    Format::Tar,
    Format::Zip,
    Format::Cpio,
    Format::Ar,
    Format::SevenZip,
    Format::Xar,
    Format::Iso,
];

struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&b, tail)) => {
                self.0 = tail;
                b
            }
            None => 0,
        }
    }

    fn bytes(&mut self, n: usize) -> &'a [u8] {
        let (data, tail) = self.0.split_at(n.min(self.0.len()));
        self.0 = tail;
        data
    }
}

fn files(data: &[u8]) -> (BTreeMap<Vec<u8>, Vec<u8>>, usize, u8) {
    let mut input = Input(data);
    let count = usize::from(input.byte() % 5) + 1;
    let chunk = usize::from(input.byte()) + 1;
    let mode = input.byte();
    let mut files = BTreeMap::new();
    for i in 0..count {
        let len = usize::from(u16::from_le_bytes([input.byte(), input.byte()])) % 8193;
        let pattern = input.bytes(len.min(1024));
        let payload = (0..len)
            .map(|i| {
                pattern
                    .get(i % pattern.len().max(1))
                    .copied()
                    .unwrap_or(i as u8)
            })
            .collect();
        files.insert(format!("f{i}").into_bytes(), payload);
    }
    (files, chunk, mode)
}

fn encode(format: Format, files: &BTreeMap<Vec<u8>, Vec<u8>>, chunk: usize, mode: u8) -> Vec<u8> {
    let mut writer = ArchiveWrite::new();
    let name: &[u8] = match format {
        Format::Tar => match mode % 4 {
            0 => b"ustar",
            1 => b"pax",
            2 => b"paxr",
            _ => b"gnutar",
        },
        Format::Zip => b"zip",
        Format::Cpio => b"newc",
        Format::Ar => b"arbsd",
        Format::SevenZip => b"7zip",
        Format::Xar => b"xar",
        Format::Iso => b"iso9660",
    };
    assert_eq!(writer.set_format_by_name(name), Status::Ok);
    match format {
        Format::SevenZip => assert_eq!(
            writer.set_options(b"7zip:compression=lzma2,7zip:compression-level=1"),
            Status::Ok
        ),
        Format::Iso => assert_eq!(
            writer.set_options(b"iso9660:rockridge=1,iso9660:joliet=1"),
            Status::Ok
        ),
        _ => {}
    }
    assert_eq!(writer.set_bytes_per_block(0), Status::Ok);
    let output = Rc::new(RefCell::new(Vec::new()));
    assert_eq!(writer.open_memory(output.clone(), MAX_OUTPUT), Status::Ok);
    for (name, payload) in files {
        let mut entry = ArchiveEntry::new();
        entry.set_pathname(Some(name));
        entry.set_mode(AE_IFREG | 0o644);
        entry.set_mtime(0, 0);
        entry.set_size(payload.len() as i64);
        assert_eq!(writer.header(&mut entry), Status::Ok);
        for part in payload.chunks(chunk) {
            assert_eq!(writer.data(part), Ok(part.len()));
        }
        assert_eq!(writer.finish_entry(), Status::Ok);
    }
    assert_eq!(writer.close(), Status::Ok);
    drop(writer);
    Rc::try_unwrap(output).unwrap().into_inner()
}

fn reader(archive: Vec<u8>, limits: ReadLimits) -> (ArchiveRead, Status) {
    let mut reader = ArchiveRead::new();
    assert_eq!(reader.support_format_all(), Status::Ok);
    assert_eq!(reader.support_filter_all(), Status::Ok);
    assert_eq!(reader.set_limits(limits), Status::Ok);
    let status = reader.open_memory(archive);
    (reader, status)
}

fn normal_limits() -> ReadLimits {
    ReadLimits {
        decoded_bytes: Some(16 << 20),
        metadata_bytes: Some(2 << 20),
        entries: Some(16),
        filter_depth: Some(25),
        decoder_memory: Some(64 << 20),
    }
}

fn verify(archive: &[u8], expected: &BTreeMap<Vec<u8>, Vec<u8>>, chunk: usize, blocks: bool) {
    let (mut reader, status) = reader(archive.to_vec(), normal_limits());
    assert_eq!(status, Status::Ok);
    let mut actual = BTreeMap::new();
    let mut headers = 0;
    loop {
        match reader.next_header() {
            Status::Eof => break,
            Status::Ok => {}
            other => panic!("valid round-trip header failed: {other:?}"),
        }
        headers += 1;
        assert!(headers <= 16);
        if reader.entry().filetype() != AE_IFREG {
            assert_eq!(reader.data_skip(), Status::Ok);
            continue;
        }
        let name = reader.entry().pathname().unwrap_or_default().to_vec();
        let wanted = expected.get(&name).expect("unexpected regular file");
        let mut payload = Vec::new();
        if blocks {
            let mut calls = 0;
            loop {
                calls += 1;
                assert!(calls <= wanted.len() + 16, "data blocks made no progress");
                let (status, data, offset) = reader.data_block();
                if status == Status::Eof {
                    break;
                }
                assert_eq!(status, Status::Ok);
                assert_eq!(offset, payload.len() as i64);
                assert!(payload.len() + data.len() <= wanted.len());
                payload.extend_from_slice(data);
            }
        } else {
            let mut buffer = vec![0; chunk];
            loop {
                let n = reader
                    .data(&mut buffer)
                    .expect("valid round-trip data failed");
                if n == 0 {
                    break;
                }
                assert!(payload.len() + n <= wanted.len());
                payload.extend_from_slice(&buffer[..n]);
            }
        }
        assert!(
            actual.insert(name, payload).is_none(),
            "duplicate regular file"
        );
    }
    assert_eq!(&actual, expected);
    assert_eq!(reader.close(), Status::Ok);
}

fn verify_skips(archive: &[u8], expected: &BTreeMap<Vec<u8>, Vec<u8>>) {
    let (mut reader, status) = reader(archive.to_vec(), normal_limits());
    assert_eq!(status, Status::Ok);
    let mut names = BTreeMap::new();
    let mut count = 0;
    loop {
        match reader.next_header() {
            Status::Eof => break,
            Status::Ok => {}
            other => panic!("valid skip header failed: {other:?}"),
        }
        count += 1;
        assert!(count <= 16);
        if reader.entry().filetype() == AE_IFREG {
            let name = reader.entry().pathname().unwrap_or_default().to_vec();
            let wanted = expected.get(&name).expect("unexpected skip entry");
            let mut byte = [0];
            let n = reader.data(&mut byte).expect("valid partial data failed");
            assert_eq!(n, usize::from(!wanted.is_empty()));
            if n != 0 {
                assert_eq!(byte[0], wanted[0]);
            }
            assert!(names.insert(name, ()).is_none());
        }
        assert_eq!(reader.data_skip(), Status::Ok);
    }
    assert_eq!(names.len(), expected.len());
    assert_eq!(reader.close(), Status::Ok);
}

pub fn roundtrip(data: &[u8], format: Format) {
    super::abort_on_panic();
    let (files, chunk, mode) = files(data);
    let archive = encode(format, &files, chunk, mode);
    verify(&archive, &files, chunk, mode & 1 != 0);
    verify_skips(&archive, &files);
}

pub fn all(data: &[u8]) {
    let (format, rest) = data.split_first().unwrap_or((&0, &[]));
    roundtrip(rest, FORMATS[usize::from(*format) % FORMATS.len()]);
}

fn expect_limit(archive: &[u8], limits: ReadLimits) {
    let (mut reader, status) = reader(archive.to_vec(), limits);
    let mut status = status;
    if status == Status::Ok {
        for _ in 0..16 {
            status = reader.next_header();
            if status != Status::Ok {
                break;
            }
            let skipped = reader.data_skip();
            if skipped != Status::Ok {
                status = skipped;
                break;
            }
        }
    }
    assert_eq!(status, Status::Fatal);
    assert_eq!(reader.errno(), libc::EFBIG);
    assert!(
        reader
            .error_string()
            .unwrap()
            .starts_with(b"Archive resource limit exceeded:")
    );
    assert_eq!(reader.close(), Status::Ok);
}

/// Ordinary valid archives must obey explicitly configured small budgets.
pub fn limits(data: &[u8]) {
    super::abort_on_panic();
    let (files, chunk, mode) = files(data);
    let archive = encode(Format::Tar, &files, chunk, mode);
    for limits in [
        ReadLimits {
            entries: Some(files.len() as u64 - 1),
            ..ReadLimits::default()
        },
        ReadLimits {
            metadata_bytes: Some(0),
            ..ReadLimits::default()
        },
        ReadLimits {
            decoded_bytes: Some(archive.len() as u64 - 1),
            ..ReadLimits::default()
        },
    ] {
        expect_limit(&archive, limits);
    }
    let (mut reader, status) = reader(
        archive.clone(),
        ReadLimits {
            decoded_bytes: Some(archive.len() as u64),
            entries: Some(files.len() as u64),
            ..ReadLimits::default()
        },
    );
    assert_eq!(status, Status::Ok);
    let mut count = 0;
    loop {
        match reader.next_header() {
            Status::Eof => break,
            Status::Ok => {
                count += 1;
                assert!(count <= files.len());
                assert_eq!(reader.data_skip(), Status::Ok);
            }
            other => panic!("exact budget rejected valid archive: {other:?}"),
        }
    }
    assert_eq!(count, files.len());
    assert_eq!(reader.close(), Status::Ok);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_format_recovers_empty_text_and_binary_files() {
        // Three entries; both buffer/block reads and partial-entry skipping.
        for mode in 0..4 {
            let mut input = vec![2, 30, mode, 0, 0, 5, 0];
            input.extend_from_slice(b"hello");
            input.extend_from_slice(&[4, 0, 0, 255, 10, 128]);
            for format in FORMATS {
                roundtrip(&input, format);
            }
            limits(&input);
        }
    }

    #[test]
    fn maximum_generated_files_remain_bounded() {
        let mut input = vec![4, 255, 1];
        for _ in 0..5 {
            input.extend_from_slice(&8192u16.to_le_bytes());
            input.extend_from_slice(&[127; 1024]);
        }
        for format in FORMATS {
            roundtrip(&input, format);
        }
        limits(&input);
    }
}
