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
disk fixes; the baseline must be merged with those fixes.

The required Ubuntu CI jobs run Rust checks and both full upstream suites.
Both jobs use `scripts/setup-linux-tests` to install the development packages from
`diagnostics/round14-linux-env/run.sh`, plus `libattr1-dev`, and generates
the seven locales from `setup-user.sh`. Its locale setup suppresses only
the expected ASCII compatibility warning for SHIFT_JIS. Builds and tests
run as the GitHub runner user; only dependency and locale installation use
`sudo`. The setup script contains the reproducible package and locale lists.
GitHub CI itself has not been run before publication.

The runner's Python checks exercise platform selection, failure exit codes,
skip regressions and baseline updates without building the C test programs:

```
python3 -m unittest discover -s tests -p 'test_*.py'
```
