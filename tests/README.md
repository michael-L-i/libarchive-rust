# Upstream test baselines

`scripts/run-tests` chooses `passing-linux.txt` and `upstream-linux.txt`
on Linux, and the existing `passing.txt` and `upstream.txt` on macOS.
The port and oracle each enforce their own baseline: a recorded pass that
fails or skips is a regression. Any failure, crash or timeout also fails
the run, including tests not yet in a baseline. Unrecorded skips are allowed.

Run the full suites as an unprivileged user; root bypasses the permission
checks in the disk tests. For example:

```
scripts/build-oracle
scripts/build-port --release
scripts/run-tests --oracle --suite all --timeout 120
scripts/run-tests --suite all --timeout 120
```

`--update` adds new port passes without removing old ones. After a
successful full oracle run, `--oracle --baseline` records passes for the
selected suites while keeping other suites. A failing oracle run never
rewrites its baseline. These commands only update the current platform's
files. Front-end names carry a suite prefix such as `tar/test_basic`.

The initial Linux baselines contain 969 port passes and 1039 oracle passes,
from the unprivileged `tester` runs in
`diagnostics/round14-linux-disk/suite/after-{port,oracle}.tsv` in the local
parent project. The port's 70 additional skips are upstream internal tests
that cannot link through the public C ABI. Those results used the Linux
disk fixes, which are now integrated.

The required Ubuntu CI jobs run Rust checks and both full upstream suites.
Both jobs use `scripts/setup-linux-tests` to install the development packages from
`diagnostics/round14-linux-env/run.sh`, plus `libattr1-dev`, and generate
the seven locales from `setup-user.sh`. Its locale setup suppresses only
the expected ASCII compatibility warning for SHIFT_JIS. Builds and tests
run as the GitHub runner user; only dependency and locale installation use
`sudo`. The setup script contains the reproducible package and locale lists.
GitHub CI itself has not been run before publication.

The oracle jobs also run `scripts/test-iso-zisofs --library target/debug
--reader build/oracle/bin/bsdtar`. It drives public-API chunk boundaries with
a C test helper and checks eight corrected images with upstream's reader.
Only the test helper uses C; the writer under test is the Rust C-ABI library.

The runner's Python checks exercise platform selection, failure exit codes,
skip regressions and baseline updates without building the C test programs:

```
python3 -m unittest discover -s tests -p 'test_*.py'
```

The optional privileged Linux checks require Docker and successful native
operations, rather than treating missing capabilities as passes:

```
scripts/test-linux-privileged build/linux-privileged
```

The script snapshots source into an isolated container with no host mounts,
no runtime network and only its listed capabilities. It compares the two
public ABIs as root and uid 65534 with cleared capabilities: immutable and
append-only enforcement/clearing, trusted and user xattrs, mode-000 metadata,
and secure link behavior. It requires real immutable, append and trusted.*
operations and writes `report.json` plus logs before removing the container.
The final October 12 run passed on Docker overlayfs with exact oracle/port
records for both users. This establishes overlayfs coverage; other Linux
filesystems and kernels still need their own runs. GitHub CI has not run it.

Synchronized Rust disk tests replace parents or leaves across callbacks and
verify inode identity, symlink text, data reads and directory time restoration.
Read-limit tests cover header work, hidden decoder output, eager records,
metadata allocations, sparse holes, sticky failure and configuration ordering.
These remain separate from uncapped upstream compatibility tests:

```
cargo test --release -p libarchive-rust read_disk::tests
cargo test --release -p libarchive-rust limits
cargo test --manifest-path fuzz/Cargo.toml --lib
```

`ReadLimits` measures charged processing and selected per-decoder storage,
not a process memory or CPU ceiling. Its precise accounting, defaults and
ordering restrictions are documented in `src/read/limits.rs` and `NOTES.md`.
The owned writer-memory tests also check exhaustion, borrow conflicts, close
errors and bounded geometric growth; their sink does not cap codec workspaces.
