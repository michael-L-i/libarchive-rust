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
- **Disk traversal:** directory operations retain open parents across renames;
  delayed file opens verify identity. Synchronized replacement tests cover
  macOS and Linux. Isolated Linux tests also compare successful immutable,
  append-only and `trusted.*` metadata operations with C.
- **Fuzzing:** 39 targets cover readers, filters, deeper reads, bounded writer
  round trips and processing-limit properties (`fuzz/`).

## Performance

The final round used `bench/compare.py` to time C and Rust `bsdtar`
on 8 datasets and 6 formats for creation and extraction: 96 cases,
whole-process time including startup,
warm cache, 5 rotating repeats. A win is a median more than 5% below C. On
an Apple M5 Pro (macOS 26.6), against upstream bsdtar built with its usual
C libraries (Apple zlib, liblzma 5.8.4, libzstd 1.5.7):

| | Wins | Ties | Losses |
|---|---:|---:|---:|
| Current, after reviewed limits and race hardening (Oct 12) | 56 | 38 | 2 |
| Previous Rust, measured in the same final run | 54 | 39 | 3 |
| Round 14, after disk and ISO fixes (Oct 12) | 57 | 37 | 2 |
| Round 13 (two runs) | 59–61 | 32–34 | 3 |
| Round 13, with `scripts/build-pgo` | 63 | 31 | 2 |
| Previous version | 24 | 22 | 50 |

The final run uses the same frozen inputs and C executable as round 13.
Across all 96 cases the geometric mean of Rust/C time is 0.902, about 10%
less elapsed time. All 336 content/byte checks pass, including identical
output from all 48 writers against the previous Rust build. There are no
run failures. Overall time is comparable to previous Rust (1.002x).
The remaining losses are compiled-data Zstandard creation (1.054x C's
time) and 7-Zip extraction (1.078x). Close cases move between runs.

Small 7-Zip creation cases now peak at about 56–57 MiB, down from 97 MiB
and close to C's 55 MiB; large-stream RSS is unchanged. A 15-repeat
many-file tar confirmation measures 50.0 ms versus previous Rust's 48.2 ms
and C's 60.7 ms. The extra permission/identity checks retain a small cost
after redundant calls were removed. These results measure regular-file
contents with metadata disabled; ISO and privileged metadata have separate
correctness checks.

The PGO result is historical; the current fixes have not been rebuilt with
PGO. `scripts/build-pgo` trains on data other than the benchmark's; it
changes no output byte.

## Security limits

Readers accept opt-in `ReadLimits` for decoded processing work, entry counts,
metadata work, filter depth and supported decoder dictionaries/models. Set
them before opening input; set decoder memory before appending explicit
filters. C callers and `bsdtar` can use existing options such as
`--options 'limits:decoded-bytes=67108864,limits:entries=10000'`.
Exceeded work, count or depth limits return a sticky fatal error with `EFBIG`;
decoder-memory rejection uses the codec's existing error.

Defaults preserve upstream behavior and do not impose aggregate budgets.
These limits are conservative processing checks, not total heap or CPU-time
quotas; a bounded block can finish before a limit is detected. Applications
handling untrusted archives still need appropriate process limits.
`NOTES.md` explains the accounting and supported decoder coverage.

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
fuzz/           reader/filter and bounded archive-property fuzz targets
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
