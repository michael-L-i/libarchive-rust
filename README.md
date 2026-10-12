# libarchive-rust

A memory-safe Rust port of [libarchive](https://github.com/libarchive/libarchive),
the archive and compression library behind `bsdtar`, `bsdcpio` and many
package managers, together with its command-line tools. It is a drop-in
replacement: the same C ABI and headers, the same behavior, checked against
upstream's own test suite.

## Status

- **Library:** all 454 public functions, in Rust. `unsafe` is confined to the C
  ABI layer (`src/ffi/`); the rest of the crate denies it.
- **Upstream tests:** 926 pass on macOS and 969 on Linux against this library
  and its tools, with no failures or baseline regressions. There are 184
  macOS skips and 141 Linux skips. Of those, 73 need libarchive's internal
  layout, which a public ABI can't link; the others reflect platform support.
- **Tools:** `bsdtar`, `bsdcpio`, `bsdcat` and `bsdunzip` are Rust programs
  with upstream's options, output, messages and exit codes.
- **Codecs:** pure Rust. DEFLATE and LZMA/XZ compression are ports of zlib
  1.2.12 and liblzma 5.8.4 that reproduce their output byte for byte, so
  `bsdtar` writes the same `.tar.gz`, `.zip`, `.tar.xz` and `.7z` archives as
  the C build. Zstandard compression ports libzstd 1.5.7's strategies.
- **Fidelity:** in a byte-for-byte comparison of every writer against C
  `bsdtar`, 64 of 68 format and input cases are identical; the four differences
  are RIPEMD-160 absent from the macOS C build. A previous comparison of 562
  test archives differed only on a damaged bzip2 stream the safe decoder
  reports differently. The ISO writer uses platform libc ordering and fixes
  six documented upstream output corruptions. Eight regression images
  recover their original bytes with upstream's reader on both platforms.
  `NOTES.md` records the remaining and intended differences.
- **Extraction safety:** the disk writer follows upstream's checks for
  absolute paths, `..`, symlinks and hardlinks, verified with a 169-case
  malicious-archive suite against upstream. Where they differ, this port
  leaves files outside the extraction directory alone where upstream would
  change them. A further 240 Linux comparisons check ACLs, xattrs, flags,
  symlinks and hardlinks; Rust adds no outside mutation where C preserves
  the target. Explicit `-P` can still permit paths through symlinks.
- **Fuzzing:** a `cargo fuzz` target for every reader and filter (`fuzz/`).

## Performance

The last benchmark round used `bench/compare.py` to time C and Rust `bsdtar`
on 8 datasets and 6 formats for creation and extraction: 96 cases,
whole-process time including startup,
warm cache, 5 rotating repeats. A win is a median more than 5% below C. On
an Apple M5 Pro (macOS 26.6), against upstream bsdtar built with its usual
C libraries (Apple zlib, liblzma 5.8.4, libzstd 1.5.7):

| | Wins | Ties | Losses |
|---|---:|---:|---:|
| Current, after disk and ISO fixes (Oct 12) | 57 | 37 | 2 |
| Round 13 (two runs) | 59–61 | 32–34 | 3 |
| Round 13, with `scripts/build-pgo` | 63 | 31 | 2 |
| Previous version | 24 | 22 | 50 |

The current run uses the same frozen inputs and C executable as round 13.
Across all 96 cases the geometric mean of Rust/C time is 0.899, about 10%
less elapsed time. All 192 cross-reader checks pass with no run failures.
Close cases move by a few percent between runs. The remaining losses are
Zstandard creation of the records dataset (1.055x C's time) and 7-Zip
extraction of the compiled dataset (1.081x). Several small 7-Zip creation
cases use about 97 MiB peak RSS versus 55 MiB for C; memory use is a further
optimization target. These results measure regular-file contents with
metadata disabled, not the ISO or privileged metadata paths.

The PGO result is historical; the current fixes have not been rebuilt with
PGO. `scripts/build-pgo` trains on data other than the benchmark's; it
changes no output byte.

## Security limits

Passing tests and safe Rust do not establish resistance to resource
exhaustion. As documented in `NOTES.md`, decompression output is unbounded;
the mtree reader also loads all entries before returning its first header.
Some decoder dictionaries have memory caps, but there is no archive-wide
output or metadata budget. The fuzz harness stops entry data after 1 MiB
and currently exercises readers and filters, leaving writer fuzzing and
aggregate resource limits as improvement areas.

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
scripts/test-iso-zisofs --library target/release --reader build/oracle/bin/bsdtar
```

`AGENTS.md` describes the rules (memory safety, never trusting archive bytes,
faithfulness to upstream) and the validation layers in detail. Full upstream
suites, release and dev Rust tests, formatting and strict Clippy have run on
macOS and Linux. `scripts/run-tests` enforces separate platform baselines.
CI requires both platforms and checks corrected zisofs images with the C
reader; the hosted workflow will first run after publication.

## License

BSD-2-Clause, like upstream; see `LICENSE`. `COPYING` lists the files under
other terms (UC Regents, public domain, CC0/OpenSSL/Apache-2.0, zlib) and the
vendored crates' licenses. This is an independent port, not affiliated with
the libarchive project.
