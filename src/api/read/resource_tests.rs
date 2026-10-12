use super::*;
use crate::ReadLimits;

fn reader(limits: ReadLimits) -> ArchiveRead {
    let mut a = ArchiveRead::new();
    assert_eq!(a.support_filter_all(), Status::Ok);
    assert_eq!(a.support_format_all(), Status::Ok);
    assert_eq!(a.set_limits(limits), Status::Ok);
    a
}

fn error(a: &ArchiveRead) -> String {
    a.error_string()
        .map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned())
}

fn assert_limit(a: &ArchiveRead, category: &str) {
    assert_eq!(a.errno(), libc::EFBIG);
    assert_eq!(
        error(a),
        format!("Archive resource limit exceeded: {category}")
    );
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    out.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
    out.extend(crc32fast::hash(data).to_le_bytes());
    out.extend((data.len() as u32).to_le_bytes());
    out
}

fn zip(data: &[u8], symlink: bool, descriptor: bool) -> Vec<u8> {
    let packed = miniz_oxide::deflate::compress_to_vec(data, 6);
    let crc = crc32fast::hash(data);
    let flags: u16 = if descriptor { 8 } else { 0 };
    let mut out = Vec::new();
    out.extend(0x04034b50u32.to_le_bytes());
    for n in [20u16, flags, 8, 0, 0] {
        out.extend(n.to_le_bytes());
    }
    for n in [crc, packed.len() as u32, data.len() as u32] {
        out.extend(if descriptor { 0u32 } else { n }.to_le_bytes());
    }
    out.extend(1u16.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.push(b'a');
    out.extend(&packed);
    if descriptor {
        out.extend(0x08074b50u32.to_le_bytes());
        for n in [crc, packed.len() as u32, data.len() as u32] {
            out.extend(n.to_le_bytes());
        }
    }
    let directory = out.len();
    out.extend(0x02014b50u32.to_le_bytes());
    for n in [0x314u16, 20, flags, 8, 0, 0] {
        out.extend(n.to_le_bytes());
    }
    for n in [crc, packed.len() as u32, data.len() as u32] {
        out.extend(n.to_le_bytes());
    }
    for n in [1u16, 0, 0, 0, 0] {
        out.extend(n.to_le_bytes());
    }
    out.extend((if symlink { 0o120777u32 } else { 0o100644u32 } << 16).to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.push(b'a');
    let directory_size = out.len() - directory;
    out.extend(0x06054b50u32.to_le_bytes());
    for n in [0u16, 0, 1, 1] {
        out.extend(n.to_le_bytes());
    }
    out.extend((directory_size as u32).to_le_bytes());
    out.extend((directory as u32).to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

#[test]
fn limits_zip_compressed_symlinks_fail_during_header_read() {
    let input = zip(&[b't'; 4096], true, false);
    assert!(input.len() < 256);
    let mut normal = reader(ReadLimits::default());
    assert_eq!(normal.open_memory(input.clone()), Status::Ok);
    assert_eq!(normal.next_header(), Status::Ok);
    assert_eq!(normal.entry().symlink().unwrap().len(), 4096);
    let mut a = reader(ReadLimits {
        decoded_bytes: Some(1024),
        ..ReadLimits::default()
    });
    assert_eq!(a.open_memory(input), Status::Ok);
    assert_eq!(a.next_header(), Status::Fatal);
    assert_limit(&a, "decoded bytes");
    assert_eq!(a.close(), Status::Ok);
}

#[test]
fn limits_zip_unknown_size_skips_cannot_bypass_decoder_budget() {
    use crate::archive::{ARCHIVE_FATAL, ARCHIVE_OK, Base, READ_MAGIC};
    use crate::entry::Entry;
    use crate::read_open_memory::Memory;
    let input = zip(&[0; 128 * 1024], false, true);
    assert!(input.len() < 512);
    let mut r = read::Read::default();
    let a = Base::new(READ_MAGIC);
    assert_eq!(
        crate::read::format::zip::support_streamable(&mut r).unwrap(),
        read::Status::Ok
    );
    assert_eq!(
        r.set_limits(
            &a,
            ReadLimits {
                decoded_bytes: Some(1024),
                ..ReadLimits::default()
            }
        ),
        ARCHIVE_OK
    );
    assert_eq!(r.open(&a, Box::new(Memory::new(input, 64))), ARCHIVE_OK);
    assert_eq!(r.next_header2(&a, &mut Entry::new(None)), ARCHIVE_OK);
    assert_eq!(r.read_data_skip(&a, None), ARCHIVE_FATAL);
    assert_eq!(a.errno.get(), libc::EFBIG);
    assert_eq!(r.close(&a), ARCHIVE_OK);
}

fn sevenzip(entries: usize, name_padding: usize) -> Vec<u8> {
    use crate::{AE_IFREG, ArchiveEntry, ArchiveWrite};
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "limits-7zip-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let mut writer = ArchiveWrite::new();
    assert_eq!(writer.set_format_7zip(), Status::Ok);
    assert_eq!(writer.set_options(b"compression=deflate"), Status::Ok);
    assert_eq!(writer.set_bytes_per_block(0), Status::Ok);
    assert_eq!(writer.open_fd(file), Status::Ok);
    for i in 0..entries {
        let mut name = format!("entry{i}-").into_bytes();
        name.extend(std::iter::repeat_n(b'n', name_padding));
        let mut entry = ArchiveEntry::new();
        entry.set_pathname(Some(&name));
        entry.set_mode(AE_IFREG | 0o644);
        entry.set_size(0);
        assert_eq!(writer.header(&mut entry), Status::Ok);
    }
    assert_eq!(writer.close(), Status::Ok);
    drop(writer);
    let out = std::fs::read(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    out
}

#[test]
fn limits_sevenzip_encoded_headers_obey_output_budget() {
    let input = sevenzip(20, 512);
    assert!(input.len() < 4096);
    let mut normal = reader(ReadLimits::default());
    assert_eq!(normal.open_memory(input.clone()), Status::Ok);
    assert_eq!(normal.next_header(), Status::Ok);
    let mut a = reader(ReadLimits {
        decoded_bytes: Some(4096),
        ..ReadLimits::default()
    });
    let opened = a.open_memory(input);
    assert!(opened == Status::Fatal || a.next_header() == Status::Fatal);
    assert_limit(&a, "decoded bytes");
    assert_eq!(a.close(), Status::Ok);
}

#[test]
fn limits_sevenzip_entries_fail_before_eager_allocation() {
    let input = sevenzip(3, 0);
    let mut a = reader(ReadLimits {
        entries: Some(2),
        ..ReadLimits::default()
    });
    assert_eq!(a.open_memory(input), Status::Ok);
    assert_eq!(a.next_header(), Status::Fatal);
    assert_limit(&a, "entries");
    assert_eq!(a.close(), Status::Ok);
}

fn xar(xml: &[u8]) -> Vec<u8> {
    let packed = miniz_oxide::deflate::compress_to_vec_zlib(xml, 6);
    let mut input = b"xar!".to_vec();
    input.extend(28u16.to_be_bytes());
    input.extend(1u16.to_be_bytes());
    input.extend((packed.len() as u64).to_be_bytes());
    input.extend((xml.len() as u64).to_be_bytes());
    input.extend(0u32.to_be_bytes());
    input.extend(packed);
    input
}

#[test]
fn limits_xar_toc_and_eager_entries_obey_budgets() {
    let mut xml = b"<xar><toc>".to_vec();
    for i in 0..3 {
        xml.extend(
            format!("<file id=\"{i}\"><name>f{i}</name><type>file</type></file>").as_bytes(),
        );
    }
    xml.extend(b"</toc></xar>");
    let input = xar(&xml);
    let mut normal = reader(ReadLimits::default());
    assert_eq!(normal.open_memory(input.clone()), Status::Ok);
    assert_eq!(normal.next_header(), Status::Ok);
    let mut a = reader(ReadLimits {
        entries: Some(2),
        ..ReadLimits::default()
    });
    assert_eq!(a.open_memory(input), Status::Ok);
    assert_eq!(a.next_header(), Status::Fatal);
    assert_limit(&a, "entries");
    let mut xml = b"<xar><toc>".to_vec();
    xml.extend([b' '; 8192]);
    xml.extend(b"</toc></xar>");
    let input = xar(&xml);
    for limits in [
        ReadLimits {
            decoded_bytes: Some(1024),
            ..ReadLimits::default()
        },
        ReadLimits {
            metadata_bytes: Some(1024),
            ..ReadLimits::default()
        },
    ] {
        let mut a = reader(limits);
        assert_eq!(a.open_memory(input.clone()), Status::Ok);
        assert_eq!(a.next_header(), Status::Fatal);
        assert_limit(
            &a,
            if limits.decoded_bytes.is_some() {
                "decoded bytes"
            } else {
                "metadata bytes"
            },
        );
        assert_eq!(a.close(), Status::Ok);
    }
}

fn tar_entry(name: &[u8], kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 512];
    out[..name.len()].copy_from_slice(name);
    out[100..108].copy_from_slice(b"0000644\0");
    out[108..116].copy_from_slice(b"0000000\0");
    out[116..124].copy_from_slice(b"0000000\0");
    out[124..136].copy_from_slice(format!("{:011o}\0", body.len()).as_bytes());
    out[136..148].copy_from_slice(b"00000000000\0");
    out[148..156].fill(b' ');
    out[156] = kind;
    let sum: usize = out.iter().map(|&b| usize::from(b)).sum();
    out[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    out.extend(body);
    out.resize(out.len().div_ceil(512) * 512, 0);
    out
}

#[test]
fn limits_tar_auto_skips_preserve_budget_across_entry_resets() {
    use crate::archive::{ARCHIVE_FATAL, ARCHIVE_OK, Base, READ_MAGIC};
    use crate::entry::Entry;
    use crate::read_open_memory::Memory;
    let mut input = tar_entry(b"a", b'0', &[0; 512]);
    input.extend(tar_entry(b"b", b'0', &[0; 512]));
    input.extend([0; 1024]);
    let mut r = read::Read::default();
    let a = Base::new(READ_MAGIC);
    assert_eq!(
        crate::read::format::tar::support(&mut r).unwrap(),
        read::Status::Ok
    );
    assert_eq!(
        r.set_limits(
            &a,
            ReadLimits {
                decoded_bytes: Some(1536),
                ..ReadLimits::default()
            }
        ),
        ARCHIVE_OK
    );
    assert_eq!(r.open(&a, Box::new(Memory::new(input, 512))), ARCHIVE_OK);
    let mut entry = Entry::new(None);
    assert_eq!(r.next_header2(&a, &mut entry), ARCHIVE_OK);
    assert_eq!(r.next_header2(&a, &mut entry), ARCHIVE_OK);
    assert_eq!(r.next_header2(&a, &mut entry), ARCHIVE_FATAL);
    assert_eq!(a.errno.get(), libc::EFBIG);
    assert_eq!(r.close(&a), ARCHIVE_OK);
}

#[test]
fn limits_tar_special_headers_check_metadata_before_allocating_body() {
    let mut input = tar_entry(b"long-name", b'L', &[b'p'; 8192]);
    input.extend(tar_entry(b"a", b'0', b""));
    input.extend([0; 1024]);
    let mut a = reader(ReadLimits {
        metadata_bytes: Some(1024),
        ..ReadLimits::default()
    });
    assert_eq!(a.open_memory(input), Status::Ok);
    assert_eq!(a.next_header(), Status::Fatal);
    assert_limit(&a, "metadata bytes");
    assert_eq!(a.close(), Status::Ok);
}

#[test]
fn limits_options_validate_numbers_and_unlimited() {
    for value in [b"-1".as_slice(), b"+1", b"1x", b"18446744073709551616"] {
        let mut a = reader(ReadLimits::default());
        let option = [b"limits:decoded-bytes=".as_slice(), value].concat();
        assert_eq!(a.set_options(&option), Status::Failed, "{value:?}");
        assert_eq!(a.errno(), libc::EINVAL);
    }
    let mut a = reader(ReadLimits::default());
    assert_eq!(
        a.set_options(b"limits:decoded-bytes=0,limits:entries=0,limits:metadata-bytes=0"),
        Status::Ok
    );
    assert_eq!(a.set_options(b"limits:decoded-bytes=unlimited,limits:entries=unlimited,limits:metadata-bytes=unlimited"), Status::Ok);
    assert_eq!(a.open_memory(b"#mtree\na type=file\n"), Status::Ok);
    assert_eq!(a.next_header(), Status::Ok);
    assert_eq!(a.set_limits(ReadLimits::default()), Status::Fatal);
    assert_eq!(a.close(), Status::Ok);
    assert_eq!(a.close(), Status::Ok);
}

#[test]
fn limits_bound_nested_bombs_before_any_public_data_read() {
    let mut data = vec![0; 128 * 1024];
    for _ in 0..4 {
        data = gzip(&data);
    }
    assert!(data.len() < 1024);
    let mut a = reader(ReadLimits {
        decoded_bytes: Some(4096),
        ..ReadLimits::default()
    });
    assert_eq!(a.open_memory(data), Status::Fatal);
    assert_limit(&a, "decoded bytes");
    assert_eq!(a.next_header(), Status::Fatal);
    assert_eq!(a.close(), Status::Ok);
}

#[test]
fn limits_filter_depth_counts_nested_and_explicit_filters() {
    let data = gzip(&gzip(b"#mtree\na type=file\n"));
    let mut a = reader(ReadLimits {
        filter_depth: Some(1),
        ..ReadLimits::default()
    });
    assert_eq!(a.open_memory(data), Status::Fatal);
    assert_limit(&a, "filter depth");
    let mut a = reader(ReadLimits {
        filter_depth: Some(0),
        ..ReadLimits::default()
    });
    assert_eq!(a.append_filter(read::filter_code::GZIP), Status::Fatal);
    assert_limit(&a, "filter depth");
    assert_eq!(a.close(), Status::Ok);
}

#[test]
fn limits_decoder_memory_cannot_change_after_filters_are_initialized() {
    for filter in [read::filter_code::XZ, read::filter_code::ZSTD] {
        let limits = ReadLimits {
            decoder_memory: Some(4096),
            ..ReadLimits::default()
        };
        let mut a = reader(limits);
        assert_eq!(a.append_filter(filter), Status::Ok);
        assert_eq!(
            a.set_limits(ReadLimits {
                decoder_memory: Some(8192),
                ..limits
            }),
            Status::Failed
        );
        assert_eq!(a.errno(), libc::EINVAL);
        assert!(error(&a).contains("before appending filters"));
        assert_eq!(
            a.set_options(b"limits:decoder-memory=unlimited"),
            Status::Failed
        );
        assert_eq!(
            a.set_limits(ReadLimits {
                entries: Some(2),
                ..limits
            }),
            Status::Ok
        );
        assert_eq!(
            a.set_limits(ReadLimits {
                filter_depth: Some(0),
                ..limits
            }),
            Status::Failed
        );
        assert_eq!(a.close(), Status::Ok);
    }
}

#[test]
fn limits_mtree_entries_are_checked_during_eager_parsing() {
    let input = b"#mtree\n/set type=file\na\nb\nc\n";
    let mut a = reader(ReadLimits {
        entries: Some(2),
        ..ReadLimits::default()
    });
    assert_eq!(a.open_memory(input), Status::Ok);
    assert_eq!(a.next_header(), Status::Fatal);
    assert_limit(&a, "entries");
    assert_eq!(a.close(), Status::Ok);
    let mut a = reader(ReadLimits {
        entries: Some(3),
        ..ReadLimits::default()
    });
    assert_eq!(a.open_memory(input), Status::Ok);
    for _ in 0..3 {
        assert_eq!(a.next_header(), Status::Ok);
    }
    assert_eq!(a.next_header(), Status::Eof);
}

#[test]
fn limits_mtree_metadata_includes_aggregate_entries_and_defaults() {
    let mut input = b"#mtree\n/set type=file uname=".to_vec();
    input.extend([b'u'; 200]);
    for i in 0..20 {
        input.extend(format!("\nf{i}\n/set uid={i}").as_bytes());
    }
    input.push(b'\n');
    assert!(input.len() < 1024);
    let mut a = reader(ReadLimits {
        metadata_bytes: Some(2048),
        ..ReadLimits::default()
    });
    assert_eq!(a.open_memory(input), Status::Ok);
    assert_eq!(a.next_header(), Status::Fatal);
    assert_limit(&a, "metadata bytes");
    assert_eq!(a.close(), Status::Ok);
}

#[test]
fn limits_are_per_handle_and_zero_is_predictable() {
    let input = b"#mtree\na type=file\n";
    let mut zero = reader(ReadLimits {
        decoded_bytes: Some(0),
        ..ReadLimits::default()
    });
    let mut normal = reader(ReadLimits::default());
    assert_eq!(zero.open_memory(input), Status::Fatal);
    assert_limit(&zero, "decoded bytes");
    assert_eq!(normal.open_memory(input), Status::Ok);
    assert_eq!(normal.next_header(), Status::Ok);
    assert_eq!(zero.close(), Status::Ok);
    let mut zero = reader(ReadLimits {
        entries: Some(0),
        ..ReadLimits::default()
    });
    assert_eq!(zero.open_memory(input), Status::Ok);
    assert_eq!(zero.next_header(), Status::Fatal);
    assert_limit(&zero, "entries");
}

#[test]
fn limits_decoder_memory_rejects_lzma_dictionary_before_decoding() {
    // A valid lzma-alone header declaring a 1 MiB dictionary and empty stream.
    let mut input = vec![0x5d];
    input.extend((1u32 << 20).to_le_bytes());
    input.extend(0u64.to_le_bytes());
    input.extend([0; 5]);
    let mut a = reader(ReadLimits {
        decoder_memory: Some(4096),
        ..ReadLimits::default()
    });
    assert_eq!(a.open_memory(input), Status::Fatal);
    assert_eq!(a.errno(), libc::ENOMEM);
    assert!(error(&a).contains("memory"), "{}", error(&a));
    assert_eq!(a.close(), Status::Ok);
}
