# libarchive-rust

A memory-safe Rust port of [libarchive](https://github.com/libarchive/libarchive),
the archive and compression library behind `bsdtar`, `bsdcpio` and many
package managers, together with its command-line tools. It is a drop-in
replacement: the same C ABI and headers, the same behavior, checked against
upstream's own test suite.

## Status

- **Library:** all 454 public functions, in Rust. `unsafe` is confined to the C
  ABI layer (`src/ffi/`); the rest of the crate denies it.
- **Upstream tests:** 926 of upstream's tests pass against this library and
  its tools, and none fail. Of the 184 that skip, 73 reach into libarchive's
  internals, which a public ABI can't link (their checks are ported as Rust
  tests); the rest skip on this platform for upstream too.
- **Tools:** `bsdtar`, `bsdcpio`, `bsdcat` and `bsdunzip` are Rust programs
  with upstream's options, output, messages and exit codes.
- **Codecs:** pure Rust. DEFLATE and LZMA/XZ compression are ports of zlib
  1.2.12 and liblzma 5.8.4 that reproduce their output byte for byte, so
  `bsdtar` writes the same `.tar.gz`, `.zip`, `.tar.xz` and `.7z` archives as
  the C build. Zstandard compression ports libzstd 1.5.7's strategies.
- **Fidelity:** in a byte-for-byte comparison of every writer against C
  `bsdtar`, 64 of 68 format and input cases are identical; the other four
  are mtree digests the macOS C build lacks. The ISO9660 writer also
  matches C on 3,459 of 3,493 differential cases on macOS and 3,457 on
  Linux; C crashes on the rest. Listing and
  extracting upstream's 562 test archives matches upstream's own `bsdtar` on
  all but one, a damaged bzip2 stream the safe decoder reports differently.
  `NOTES.md` records each remaining difference and every intended one.
- **Extraction safety:** the disk writer follows upstream's checks for
  absolute paths, `..`, symlinks and hardlinks, verified with a 169-case
  malicious-archive suite against upstream. Where they differ, this port
  leaves files outside the extraction directory alone where upstream would
  change them.
- **Fuzzing:** a `cargo fuzz` target for every reader and filter (`fuzz/`).

## Performance

`bench/compare.py` times C and Rust `bsdtar` on 8 datasets, 6 formats,
creation and extraction: 96 cases, whole-process time including startup,
warm cache, 5 rotating repeats. A win is a median more than 5% below C. On
an Apple M5 Pro (macOS 26.6), against upstream bsdtar built with its usual
C libraries (Apple zlib, liblzma 5.8.4, libzstd 1.5.7):

| | Wins | Ties | Losses |
|---|---:|---:|---:|
| This version (two runs) | 59–61 | 32–34 | 3 |
| This version, with `scripts/build-pgo` | 63 | 31 | 2 |
| Previous version | 24 | 22 | 50 |

Across all 96 cases the geometric mean of Rust/C time is 0.90. Close cases
move by a few percent between runs. The remaining losses are Zstandard
creation of two datasets (1.05–1.08x) and one 7-Zip extraction
(1.06–1.09x). `scripts/build-pgo` trains on data other than the
benchmark's; it changes no output byte.

## What is Rust

| Part | Language |
|---|---|
| Library (`src/`) and its Rust API (`src/api/`) | Rust |
| Codecs (`deflate/`, patched crates in `vendor/`) | Rust |
| Command-line tools (`tools/`) | Rust |
| C library for C programs (`capi/`) | Rust, plus one 56-line C file: `archive_set_error` takes printf-style varargs, which stable Rust can't define |
| Test oracle (`upstream/libarchive`, a submodule) | upstream's C tests, unchanged |

Rust programs, including the tools, link only the Rust crate and contain no
C. At run time they use the system's libc and iconv, as upstream does.

## Layout

```
src/            the library: one module per upstream file
src/api/        the safe Rust API (typed handles mirroring the C API)
src/ffi/        the C ABI exports; the library's only unsafe code
capi/           builds libarchive.{so,dylib,a} for C programs
deflate/        zlib 1.2.12's compressor, ported
tools/          bsdtar, bsdcpio, bsdcat, bsdunzip and their shared helpers
vendor/         patched miniz_oxide, lzma-rust2 and ruzstd
fuzz/           cargo-fuzz targets, one per reader and filter
bench/          C-versus-Rust benchmark harness and dataset generator
scripts/        oracle build, port build, test runner, PGO build
upstream/       upstream libarchive at the pinned commit (submodule)
```

## Build

```sh
git submodule update --init
cargo build --release                         # the library and the tools
cargo build --release -p libarchive-capi      # target/release/libarchive.{a,dylib,so}
```

The tools are `target/release/bsdtar` and so on. C programs compile against
upstream's `archive.h` and `archive_entry.h` (`upstream/libarchive/libarchive/`)
and link `libarchive` from `target/release`. Rust programs depend on the
`libarchive-rust` crate; `src/api/mod.rs` documents the API.

## Test

```sh
scripts/build-oracle                  # upstream's C build, the reference (CMake)
scripts/build-port --release          # our library and tools, upstream's tests relinked
scripts/run-tests --suite all         # upstream's tests against ours
cargo test --workspace --release      # Rust tests
```

`AGENTS.md` describes the rules (memory safety, never trusting archive bytes,
faithfulness to upstream) and the validation layers in detail. Development
and validation happen on macOS; the code builds and lints cleanly on Linux,
but its tests have not been run there yet.

## License

BSD-2-Clause, like upstream; see `LICENSE`. `COPYING` lists the files under
other terms (UC Regents, public domain, CC0/OpenSSL/Apache-2.0, zlib) and the
vendored crates' licenses. This is an independent port, not affiliated with
the libarchive project.
