# Installation validation, 2026-10-12

Validated source: main `aeb72b1`. Its tracked files are identical to the
integration revision `03e64332cb8f` used to generate the tested source archive.
Upstream remains pinned at `8bb3bbdc7b117a1e22086a2260f2087aafa90687`.

| Check | macOS arm64 | Linux arm64 |
|---|---:|---:|
| Rust 1.95 workspace tests, dev | 632 pass, 5 ignored | 628 pass, 5 ignored |
| Rust 1.95 workspace tests, release | 631 pass, 5 ignored | 627 pass, 5 ignored |
| Full upstream suite against port | 926 pass, 184 skip | 969 pass, 141 skip |
| Python harness/installer tests | 17 pass | 17 pass |
| Installed C/C++ shared/static consumers | pass | pass |
| CMake imported shared/static consumers | pass | pass |
| Relocated four-tool runtime checks | pass | pass |
| Public shared-library exports | 454 | 454 |

There were no failures, crashes, timeouts or upstream baseline regressions.
Formatting and strict workspace all-target Clippy passed on both platforms
with Rust 1.97.1. Upstream-suite Linux validation used the existing Debian 13
environment; installed-package and minimum-compiler tests used Debian 12,
glibc 2.36, Rust 1.95, and an unprivileged user. macOS validation used the
local Apple Silicon environment. Hosted x86_64 and current-stable CI jobs
are configured but have not run locally or remotely in this pass.

Installed consumers compile against the bundled pinned headers and verify
the actual relocated library using `dladdr`, not merely a successful link.
They exercise archive round trips, callbacks and reentry, cloned and
handle-independent entries, error formatting and clearing, and loader
metadata. Runtime processes run with a PATH that excludes Rust tooling.
Linux records SONAME `libarchive.so.13`; macOS records
`@rpath/libarchive.13.dylib`. Linux's shared dependencies are `libgcc_s.so.1`
and `libc.so.6`, without the upstream C compression libraries.

Two source archives generated from the same revision matched byte for byte:
SHA-256 `dffbbc73406172b452083daa4004a2d11487a88f1d697b57a01319eab1639227`.
Both platforms built and tested the extracted source with fresh Cargo homes,
locked vendored dependencies and `--frozen`, without the upstream submodule.
The final Linux build/test/install/consumer sequence ran with no container
network attached. The archive excludes project Git state, agent configuration,
oracle sources, build caches, fuzz corpora and benchmark data; registry crate
contents are preserved intact for Cargo checksum verification.

Fresh independent reviews covered cleanup, installation, source releases
and consumer tests. Review regressions include unsafe metadata directory
characters, symlink and hardlink staging, and Cargo target configuration
selecting stale artifacts. The cleanup retains safety/provenance comments
and makes the normalization fixture portable, with its Unicode notices.

This validates the package mechanism and these consumers. It does not certify
every downstream application, older libc, architecture or filesystem. The
documented codec, format and filesystem limitations in `NOTES.md` still apply.
No codec or optimization-profile changes were made; the previous 96-case
performance results remain the latest benchmark, rather than a new measurement
of installed C consumers. Distribution adoption should next test the intended
package's real downstream clients in its own build and runtime environments.

## Distribution binary smoke test

A follow-up tested the installed release from source `8d9309c` on Debian 12
arm64, glibc 2.36 and Rust 1.95. The distribution's CMake 3.25.1 and
bsdtar/bsdcpio/bsdcat 3.6.2 binaries were left unchanged. Runs compared the
distribution C libarchive 3.6.2 with the staged Rust library selected by
`LD_LIBRARY_PATH`, as an unprivileged user with no container network attached.
Loader traces verified initialization of the staged library for all four
binaries; an additional binding trace verified 68 CMake archive symbols
resolved to that library. Eager binding was enabled with `LD_BIND_NOW=1`.

All 23 grouped smoke checks passed, covering:

- CMake `file(ARCHIVE_CREATE)` and the distribution bsdtar writer for tar,
  gzip, bzip2, xz, zstd, zip and 7zip, with C/Rust cross-extraction and matching
  recovered file bytes, filenames and directory trees. CMake listings matched.
- Distribution bsdcpio newc cross-roundtrips and bsdcat decompression.
- Tar symlink targets and recovered hardlink identity.
- Rejection of one truncated ZIP by CMake and bsdtar without a crash.
- CMake FetchContent extraction of a local archived dependency, configuration,
  compilation and execution of an application returning the expected result.

Fixtures included UTF-8 and spaced filenames, nested directories, empty files
and binary contents. This small integration run found no defect; it does not
extend the result to every downstream workflow or measure performance. The CMake
binding trace, the scratch harness and JSON results are retained outside the
source tree in `../diagnostics/downstream-smoke-2026-10-12/`.
