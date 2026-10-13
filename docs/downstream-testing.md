# Existing Linux applications

`tests/downstream/existing-binaries.py` exercises unchanged distribution CMake,
bsdtar, bsdcpio and bsdcat binaries twice: once with the system C library and once
with a staged Rust library. It changes the loader environment for child processes;
it does not replace the system library. Run it in a disposable container or VM.

```sh
scripts/install --prefix /opt/libarchive-rust --destdir build/downstream-stage
scripts/test-installed --prefix build/downstream-stage/opt/libarchive-rust --tools
python3 tests/downstream/existing-binaries.py \
  --library-dir build/downstream-stage/opt/libarchive-rust/lib \
  --report-dir build/downstream-report
```

The host needs Python 3.10 or later, a glibc loader, CMake 3.18 or later, a C
compiler, and distribution `libarchive-tools` binaries at `/usr/bin`. The installed
consumer test additionally needs a C++ compiler, pkg-config and binutils. No
network access is needed during the checks.

The harness verifies loader traces for both libraries and uses eager symbol
binding. Its 23 checks cover seven archive formats, cross-extraction, recovered
file bytes, empty/binary/Unicode/spaced filenames, hardlinks and symlinks,
decompression, truncated ZIP rejection, and a local CMake FetchContent build.
Every check remains active with Python optimization enabled. Temporary workloads
are removed; JSON results and loader traces are retained in the report directory.

These checks exercise binary compatibility with the selected application versions.
They do not certify every C ABI function, metadata policy, filesystem, or Linux
distribution. Native x86_64 CI repeats the installed-consumer and downstream
checks on Ubuntu 22.04 and 24.04 using the minimum Rust 1.95 compiler. Local
emulated x86_64 execution is useful for compatibility checks, but must not be used
as native performance evidence.

## Local x86_64 results, 2026-10-12

Source `2161711` was built with Rust 1.95.0 and GCC 12.2 in a Debian 12 x86_64
container using Docker's Rosetta translation on an ARM64 host. Dependencies were
fetched before the container network was disconnected; builds and validation ran
as an unprivileged user. The runtime was glibc 2.36, CMake 3.25.1 and unchanged
Debian libarchive-tools 3.6.2.

| Check | Result |
|---|---|
| Release installed C/C++ shared/static and CMake consumers | Passed |
| All four installed Rust tools | Passed |
| Existing distribution binaries | 23 checks passed, 190 commands |
| Pinned upstream C suite | 1,044 passed, 66 skipped, zero failures/crashes/timeouts |
| Rust-linked upstream suite and Rust tools | 974 passed, 136 skipped, zero failures/crashes/timeouts |
| Workspace development tests, including separately run tools and doctests | 625 passed, 3 failed, 5 ignored |

The shared Linux ratchets reported one previously passing test skipped in **both**
upstream and Rust suites: `test_read_format_7zip_lzma2_riscv`. The C test is compiled
to skip when its liblzma headers lack `LZMA_FILTER_RISCV`; Debian's liblzma 5.4.1
does not supply it. This is a test-harness dependency difference from the recorded
Linux environment. Neither ratchet was changed. There were six additional passes
in each suite, keeping the same 70-test difference for public-ABI/internal tests.

The three development failures are missing-program initialization checks:
`ffi::filter_fork::tests::missing_program_fails_to_start`,
`read::filter::program::tests::a_missing_program_fails_the_open`, and
`read_append_filter::tests::appends_a_program`. A standalone Rust `Command::spawn`
and a standalone C `posix_spawnp` both reproduced the emulator behavior: starting
a nonexistent command returns a child that exits 127, instead of reporting
`ENOENT` when spawning. No library behavior was changed to accommodate it, and
the full workspace result is recorded as failed. Native x86_64 CI is needed to
validate these checks without translation; those newly added CI jobs have not
been executed locally.

The tested installed shared library has SHA-256
`c192d920a92fe18ca203978e5ba7a7881f71b4e5611345d57c8246820eb50ac3`.
Loader traces confirm the C runs used `/lib/x86_64-linux-gnu/libarchive.so.13`
and the Rust runs used the staged library. Raw logs, exact test results and minimal
spawn reproduction sources are retained outside the source release in
`diagnostics/adoption-validation/x86_64/`. No x86_64 performance claim is made.
