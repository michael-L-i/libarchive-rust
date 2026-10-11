use deflate::{Deflate, Error, Flush, Status};
use miniz_oxide::inflate::{decompress_to_vec, decompress_to_vec_zlib};

/// Text-like input with literals, words and copies of earlier data.
fn sample(len: usize, mut x: u64) -> Vec<u8> {
    const WORDS: [&[u8]; 8] = [
        b"the ", b"quick ", b"brown ", b"fox\n", b"jumps ", b"over ", b"lazy ", b"dog. ",
    ];
    let mut v = Vec::with_capacity(len + 300);
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        match x % 4 {
            0 => v.push((x >> 8) as u8),
            1 | 2 => v.extend_from_slice(WORDS[(x >> 8) as usize % 8]),
            _ if v.is_empty() => {}
            _ => {
                let start = v.len() - 1 - (x >> 8) as usize % v.len().min(40000);
                for i in 0..(x >> 24) as usize % 300 {
                    v.push(v[start + i]);
                }
            }
        }
    }
    v.truncate(len);
    v
}

/// Random bytes.
fn noise(len: usize, mut x: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// Feed `data` in `inchunk` pieces, cycling through `flushes`, then finish,
/// with `outchunk`-byte output buffers.
fn driven(
    d: &mut Deflate,
    data: &[u8],
    inchunk: usize,
    outchunk: usize,
    flushes: &[Flush],
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; outchunk];
    for (i, mut chunk) in data.chunks(inchunk).enumerate() {
        let flush = flushes[i % flushes.len()];
        // Z_BUF_ERROR: no progress possible, which is not fatal.
        while let Ok((_, used, n)) = d.deflate(chunk, &mut buf, flush) {
            out.extend_from_slice(&buf[..n]);
            chunk = &chunk[used..];
            if chunk.is_empty() && n < buf.len() {
                break;
            }
        }
    }
    loop {
        let (status, _, n) = d.deflate(&[], &mut buf, Flush::Finish).unwrap();
        out.extend_from_slice(&buf[..n]);
        if status == Status::StreamEnd {
            return out;
        }
    }
}

fn fnv(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf29ce484222325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x100000001b3)
    })
}

fn compress(level: i32, window_bits: i32, data: &[u8]) -> Vec<u8> {
    let mut d = Deflate::new(level, window_bits, 8).unwrap();
    driven(&mut d, data, 10240, 65536, &[Flush::None])
}

fn inflate(window_bits: i32, data: &[u8]) -> Vec<u8> {
    if window_bits < 0 {
        decompress_to_vec(data).unwrap()
    } else {
        decompress_to_vec_zlib(data).unwrap()
    }
}

/// FNV-1a hashes of zlib 1.2.12's streams for levels 0-9 in the cases of
/// `matches_zlib`, from the same inputs and calls with the system zlib.
const ZLIB: [[u64; 10]; 5] = [
    [
        0x0e1a916baa29c7bb,
        0xcb279eef514ff86f,
        0xbe74aaac52bc12f3,
        0x59751d4fa1fe5ad6,
        0xfd7fc581e2e52bd0,
        0x629b2f92b46072f3,
        0x01ad7957fc435138,
        0x8e963b7765d16a30,
        0x4272fc2a5363d4fd,
        0x3f60672f2fbf622d,
    ],
    [
        0xdef3e4ad8ed9385e,
        0x29c8929be50c1586,
        0x8ef175ffea22c57f,
        0x321a8455cdc71d92,
        0xd556f4e4032dced4,
        0x164b671a5648cba3,
        0x7b61df5a3559e23e,
        0xca12244967a5e2a8,
        0x85539f586ee7ebed,
        0x5c694ac40264740d,
    ],
    [
        0x10231deb902f3661,
        0x9329f367ba30ea52,
        0x80cf0a18e0faa6fc,
        0x55bcc703a7eb0924,
        0xf8186f9cbb65a4d1,
        0x5b74f1a8c4d2e786,
        0x0e0d51528c691190,
        0x7655fa958de4e786,
        0xb0c2333612285112,
        0xb0c2333612285112,
    ],
    [
        0x9c259d9b626ec3c7,
        0x02a85560e80456f9,
        0x41515a383e167275,
        0x15675f5166879aad,
        0x2593750a92e58bd5,
        0x16445064c42bc265,
        0xa83f58e12a2cbb0d,
        0x98febe7972ec748b,
        0xa03490b4c0318b59,
        0x8a971f227ccb7404,
    ],
    [
        0x2734d5112fa9ad72,
        0xfd497101281f3ae2,
        0xa68f7de4a9d415ca,
        0xa68f7de4a9d415ca,
        0x6da9d1fac6ccb6f0,
        0x6da9d1fac6ccb6f0,
        0x6da9d1fac6ccb6f0,
        0x6da9d1fac6ccb6f0,
        0x6da9d1fac6ccb6f0,
        0x6da9d1fac6ccb6f0,
    ],
];

#[test]
fn matches_zlib() {
    use Flush::*;
    const FLUSHES: &[Flush] = &[None, Sync, None, Full, Partial, Block];
    let cases = [
        ("raw", sample(200_000, 1), -15, 8, 10240, 65536, &[None][..]),
        ("zlib", sample(200_000, 1), 15, 8, 10240, 65536, &[None]),
        ("small", sample(100_000, 2), -9, 1, 4096, 333, &[None]),
        ("flushes", sample(150_000, 3), 15, 8, 3001, 1000, FLUSHES),
        ("noise", noise(100_000, 4), -15, 8, 10240, 65536, &[None]),
    ];
    for ((name, data, wbits, mem, inchunk, outchunk, flushes), hashes) in
        cases.into_iter().zip(ZLIB)
    {
        for (level, hash) in hashes.into_iter().enumerate() {
            let mut d = Deflate::new(level as i32, wbits, mem).unwrap();
            let out = driven(&mut d, &data, inchunk, outchunk, flushes);
            assert_eq!(fnv(&out), hash, "{name} level {level}");
            assert_eq!(inflate(wbits, &out), data, "{name} level {level}");
        }
    }
}

#[test]
fn round_trips_edge_sizes() {
    let sizes = [
        0, 1, 2, 3, 4, 257, 258, 259, 260, 32767, 32768, 32769, 65535, 65536, 65537, 140_000,
    ];
    for len in sizes {
        for data in [sample(len, 5), noise(len, 6), vec![0; len]] {
            for level in 0..=9 {
                for wbits in [-15, 15, -9] {
                    let out = compress(level, wbits, &data);
                    assert_eq!(
                        inflate(wbits, &out),
                        data,
                        "len {len} level {level} wbits {wbits}"
                    );
                }
            }
        }
    }
}

#[test]
fn stores_incompressible_data() {
    let data = noise(100_000, 7);
    for level in 0..=9 {
        let out = compress(level, -15, &data);
        // Stored blocks cost five bytes; levels 1-9 end a block every 16383
        // symbols.
        assert!(
            out.len() <= data.len() + 5 * 7,
            "level {level}: {}",
            out.len()
        );
        assert_eq!(inflate(-15, &out), data);
    }
}

#[test]
fn sync_flush_ends_on_an_empty_stored_block() {
    let data = sample(50_000, 8);
    for level in 0..=9 {
        let mut d = Deflate::new(level, -15, 8).unwrap();
        let mut buf = vec![0u8; 100_000];
        let (status, used, n) = d.deflate(&data, &mut buf, Flush::Sync).unwrap();
        assert_eq!((status, used), (Status::Ok, data.len()));
        assert_eq!(buf[n - 4..n], [0, 0, 0xff, 0xff], "level {level}");
        // Everything up to the flush point decodes without the rest.
        let mut decoder =
            miniz_oxide::inflate::stream::InflateState::new_boxed(miniz_oxide::DataFormat::Raw);
        let mut plain = vec![0u8; data.len() + 1];
        let r = miniz_oxide::inflate::stream::inflate(
            &mut decoder,
            &buf[..n],
            &mut plain,
            miniz_oxide::MZFlush::None,
        );
        assert_eq!(r.bytes_written, data.len(), "level {level}");
        assert_eq!(plain[..data.len()], data[..]);
    }
}

#[test]
fn reset_starts_a_new_stream() {
    let (a, b) = (sample(70_000, 9), sample(90_000, 10));
    for level in 0..=9 {
        let mut d = Deflate::new(level, 15, 8).unwrap();
        driven(&mut d, &a, 10240, 65536, &[Flush::None]);
        d.reset();
        let out = driven(&mut d, &b, 10240, 65536, &[Flush::None]);
        assert_eq!(out, compress(level, 15, &b), "level {level}");
    }
}

#[test]
fn reports_zlib_errors() {
    for (level, wbits, mem) in [
        (10, -15, 8),
        (-2, -15, 8),
        (6, -8, 8),
        (6, 16, 8),
        (6, -16, 8),
        (6, 15, 0),
        (6, 15, 10),
    ] {
        assert!(
            Deflate::new(level, wbits, mem).is_none(),
            "{level} {wbits} {mem}"
        );
    }
    let mut d = Deflate::new(-1, 15, 8).unwrap();
    let mut buf = [0u8; 64];
    assert_eq!(d.deflate(b"abc", &mut [], Flush::None), Err(Error::Buf));
    let (_, used, n) = d.deflate(b"abc", &mut buf, Flush::None).unwrap();
    assert_eq!(used, 3);
    // Level -1 is level 6: FLEVEL 2 in the zlib header.
    assert_eq!(buf[..n], [0x78, 0x9c]);
    // Nothing to do and no new flush.
    assert_eq!(d.deflate(&[], &mut buf[n..], Flush::None), Err(Error::Buf));
    let (status, _, m) = d.deflate(&[], &mut buf[n..], Flush::Finish).unwrap();
    assert_eq!(status, Status::StreamEnd);
    assert_eq!(decompress_to_vec_zlib(&buf[..n + m]).unwrap(), b"abc");
    assert_eq!(d.deflate(&[], &mut buf, Flush::None), Err(Error::Stream));
    assert_eq!(d.deflate(b"x", &mut buf, Flush::Finish), Err(Error::Buf));
    assert_eq!(
        d.deflate(&[], &mut buf, Flush::Finish),
        Ok((Status::StreamEnd, 0, 0))
    );
    assert_eq!(Error::Stream.code(), -2);
    assert_eq!(Error::Buf.code(), -5);
}
