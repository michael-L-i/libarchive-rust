# libarchive-rust

A Rust implementation of [libarchive](https://github.com/libarchive/libarchive),
with its archive library and four command-line tools: `bsdtar`, `bsdcpio`,
`bsdcat` and `bsdunzip`.

The project provides a Rust API and a C-compatible shared/static library using
the pinned upstream public headers. It aims to let existing applications use
the Rust implementation without changing their source. Compatibility is tested
against upstream and selected downstream applications; documented differences
and platform limits still apply. This is an independent port, not affiliated
with the libarchive project.

## Build and use

Builds support macOS and Linux with glibc, using Rust **1.95 or newer** and a
platform linker. The C interface also requires a C compiler for a small
`archive_set_error` variadic formatting shim. Installed tools and libraries
require platform runtime libraries, without a Rust installation.

```sh
git clone https://github.com/michael-L-i/libarchive-rust.git
cd libarchive-rust
cargo build --workspace --release --locked
target/release/bsdtar --version
```

This builds the library, C interface and all four tools. The upstream C
submodule is unnecessary for this build. To build only the Rust library and
tools, without compiling the C shim:

```sh
cargo build --release --locked \
  -p libarchive-rust -p bsdtar -p bsdcpio -p bsdcat -p bsdunzip
```

The tools are in `target/release/`. The C build produces `libarchive.a` and
`libarchive.so` or `libarchive.dylib`. Use the installer for versioned libraries,
headers, pkg-config/CMake metadata and license notices:

```sh
scripts/install --prefix /usr --destdir "$PWD/build/package"
```

The installer needs Python 3 and stages a package tree without changing the
running system. See [installation](docs/install.md) for C/C++ consumers and
[source releases](docs/releases.md) for offline builds. The Rust API is
documented in [src/api/mod.rs](src/api/mod.rs); run
`cargo doc --no-deps -p libarchive-rust --open` to browse it locally.

## One repository, one Cargo workspace

The library and tools are separate Cargo crates sharing one Git history and
lockfile. They do not need separate repositories.

```text
src/                    Archive library, Rust API and C ABI exports
capi/                   Shared/static C library and variadic formatting shim
deflate/                Rust port of the zlib compressor
tools/libarchive_fe/    Shared command-line helpers
tools/tar/              bsdtar
tools/cpio/             bsdcpio
tools/cat/              bsdcat
tools/unzip/            bsdunzip
include/                Pinned upstream public headers
vendor/                 Patched Rust codec dependencies and provenance
tests/                  Compatibility tests and platform baselines
scripts/                Build, install, test and source-release helpers
fuzz/                   Separate nightly-only fuzz package
bench/                  Benchmark harnesses and reproducible data generator
docs/                   Installation, compatibility and validation reports
upstream/libarchive/    Read-only C reference submodule, for development tests
```

The Rust library and tools compile no C codec code. They use the platform's
libc and iconv where needed. Unsafe operations are confined to the library's
C/system interface and shared tool system wrappers; the remaining project
modules deny unsafe code. The only project C source compiled for distribution
is `capi/variadic.c`, retained to support Rust 1.95.

## Compatibility and validation

The reference is upstream libarchive **3.9.0dev**, commit
`8bb3bbdc7b117a1e22086a2260f2087aafa90687`. All 454 public functions are
implemented. The current native ARM64 validation records:

| Upstream suite against Rust library and tools | Passed | Skipped | Failed |
|---|---:|---:|---:|
| macOS | 926 | 184 | 0 |
| Linux | 969 | 141 | 0 |

These are platform-specific results, not a promise that every upstream test
runs through the public ABI. Internal-layout tests and unavailable platform
features account for skips. See [installation validation](docs/install-validation.md)
for environments and [adoption validation](docs/adoption-validation.md) for
installed consumers, package transactions and extended fuzz campaigns.

Local x86_64 Linux testing used Rosetta translation: downstream checks passed,
but three process-spawning development tests failed and were reproduced with
standalone Rust and C programs. [The x86 report](docs/downstream-testing.md)
records those results. Native x86_64 GitHub Actions jobs are configured; their
first hosted results are pending publication. Windows and musl are unvalidated.

Read [compatibility](docs/compatibility.md) before evaluating a replacement for
an existing libarchive installation. [NOTES.md](NOTES.md) contains detailed
format, codec and filesystem differences. Reader processing limits are opt-in
and do not replace application memory or time limits.

## Performance

Two separate measurements on an Apple M5 Pro used 96 warm-cache create/extract
cases with metadata disabled. A win or loss means a median difference greater
than 5%; cases are equally weighted in the geometric mean.

| Comparison | Rust wins | Ties | Losses | Rust/C time |
|---|---:|---:|---:|---:|
| C vs Rust command-line executables | 56 | 38 | 2 | 0.902 |
| Same C executable, C vs installed Rust shared library | 49 | 45 | 2 | 0.910324 |

These correspond to about 9.8% and 9.0% less elapsed time on their respective
matrices. They are separate runs and do not establish performance on Linux,
other hardware, cold storage or concurrent applications. See the
[CLI results](STATUS.md#final-96-case-benchmark-2026-10-12),
[benchmark method](bench/README.md),
[shared-library report](docs/shared-library-performance.md) and
[final optimization screen](docs/final-performance-screen.md).

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and validation commands.
The project uses BSD-2-Clause; see [LICENSE](LICENSE) and [COPYING](COPYING)
for retained upstream notices and the components under other licenses.
