# Publication validation, October 13, 2026

The first public repository is one Cargo workspace containing the Rust library,
C interface and four tools. The upstream C submodule remains a pinned test
reference. These checks do not establish universal compatibility or change the
previous performance measurements.

The hosted results below were recorded at `6cdddcc5fa8308f248896ee8cb52f9ba3c9d2a93`.

| Check | Native Ubuntu 24.04 x86_64 | macOS 15 ARM64 |
|---|---:|---:|
| Rust 1.97.1 workspace tests | 628 passed, 5 ignored | 632 passed, 5 ignored |
| Strict Clippy and formatting | passed | passed |
| Upstream suites against the Rust port | 976 passed, 134 skipped | 926 passed, 184 skipped |
| Upstream suites against the C reference | 1046 passed, 64 skipped | 991 passed, 119 skipped |
| Installed C/C++ shared/static, CMake and four-tool consumers, Rust 1.95 and stable | passed | passed |

Both upstream suites recorded zero failures, crashes, timeouts or baseline
regressions. The overall [CI run at this revision](https://github.com/michael-L-i/libarchive-rust/actions/runs/38365370923)
still failed: the subsequent zisofs regression fixture loaded the wrong
library on Linux and could not load the versioned library on macOS, so that
separate check reported zero of eight cases passing on each platform.
The corrected fixture stages the selected library privately and verifies all
16 function providers before writing. Subsequent local checks passed all eight
cases on both platforms and rejected deliberately selected system libraries.
Hosted validation of the corrected fixture is a separate run. Native Linux workspace tests passed the process-spawning cases
that failed under Rosetta. The Linux oracle uses checksum-pinned, privately
built XZ 5.8.4; Ubuntu's older system headers otherwise skip the RISC-V fixture.
The seven additional Linux passes are environment-dependent results; the
existing platform ratchets were retained.

The [installed-package run](https://github.com/michael-L-i/libarchive-rust/actions/runs/38365370976)
also produced identical source archives, built and tested the workspace offline
with Rust 1.95 and a fresh Cargo home, and passed independent Rust, C/C++,
CMake and tool consumers. Independent Rust gzip, xz and Zstd round trips also
passed through the public Git dependency. Direct paths to patched codecs make
this work without downstream workspace patches.

The [native downstream run](https://github.com/michael-L-i/libarchive-rust/actions/runs/38365371073)
passed 23 checks and 190 commands on each of Ubuntu 22.04 and 24.04, using
unchanged distribution applications and checking the selected library provider.
This run does not repeat the separately documented pacman transaction campaign.
The [property run](https://github.com/michael-L-i/libarchive-rust/actions/runs/38365370897)
passed the harness checks and bounded 100-run smoke campaigns for ten targets;
the extended fuzz campaign remains a separate result.

Initial hosted checks exposed build/test setup defects: ANSI color in cached
native linker flags, legacy pkg-config spacing, a nightly formatter changing
preserved license whitespace, and missing versioned shared-library names in the
zisofs fixture. The linker and consumer fixes retain compiler and loader
verification. Formatting uses Rust 1.97.1 while fuzz compilation uses pinned
nightly. Reference dependencies and test staging stay outside shipped runtime
code. Current run status is available in
[GitHub Actions](https://github.com/michael-L-i/libarchive-rust/actions).

Generated Cargo artifacts containing local build paths were removed from
unpublished history without changing the source tree. The original branches
were bundled before cleanup; [the revision map](history.md) preserves report
provenance. Only `main` was pushed.
