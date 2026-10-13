# Contributing

Changes should preserve compatibility with the pinned upstream libarchive
version while keeping the implementation maintainable and safe. Report a bug
with the platform, compiler version, source revision, command, expected
behavior and observed behavior. A small reproducible archive is helpful when
it can be shared without exposing private data.

## Development setup

```sh
git clone --recurse-submodules https://github.com/michael-L-i/libarchive-rust.git
cd libarchive-rust
cargo build --workspace --locked
```

For an existing checkout, initialize the C reference with
`git submodule update --init upstream/libarchive`. Ordinary builds need
Rust 1.95 or newer and a platform linker; the C interface needs a C compiler.
The upstream oracle additionally needs CMake and its platform dependencies.

On Ubuntu, `scripts/setup-linux-tests` installs development dependencies and
test locales using sudo. Read it before running; builds and tests themselves
run as an unprivileged user. On macOS, the CI setup uses:

```sh
brew install cmake xz zstd lz4 libb2 libiconv
```

## Checks

Run the narrowest meaningful tests during development, then the relevant
integration checks before submitting:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 -m unittest discover -s tests -p 'test_*.py'
```

Use the compiler pinned in CI for formatting and Clippy, and the minimum
compiler for minimum-version builds. Platform-dependent tests need the locales
and operating-system capabilities documented by the setup scripts and CI jobs.
Do not treat unavailable tests as passes.

For library behavior or command-line changes, build the pinned C reference and
run upstream's tests against both implementations:

```sh
scripts/build-oracle
scripts/run-tests --oracle --suite all
scripts/build-port --release
scripts/run-tests --suite all
```

Use `scripts/run-tests PATTERN` for a library subset or
`scripts/run-tests --suite tar PATTERN` for a tool subset (`tar`, `cpio`,
`cat`, `unzip`). The runner enforces separate platform baselines. Do not
remove a baseline pass or convert it to a skip to conceal a regression.
Update a baseline only with evidence explaining the changed result.

For install or packaging changes, stage into a fresh directory and test the
installed files:

```sh
scripts/install --prefix /usr --destdir "$PWD/build/package"
scripts/test-installed --prefix "$PWD/build/package/usr" --tools
```

The [downstream harness](docs/downstream-testing.md) and
`scripts/test-package-manager` exercise existing applications in disposable
environments. The [fuzz guide](fuzz/README.md) describes the separate nightly
package. The [benchmark guide](bench/README.md) documents fair comparisons;
avoid competing builds or fuzzing while collecting timings.

## Implementation conventions

- Keep input-derived arithmetic and allocations checked. Invalid archive data
  should produce an error rather than panic.
- Keep unsafe code inside the existing C/system interface modules and explain
  each unsafe operation's safety requirements.
- Preserve path and archive strings as bytes where the format/API permits
  non-UTF-8 data.
- Match upstream return values, messages, metadata and output. Document
  deliberate differences in `NOTES.md`, including fixes for upstream bugs
  that corrupt output. Add focused regression evidence for such fixes.
- Retain copyright and license headers. Record upstream source provenance and
  document local dependency patches in their `PATCHES.md` files.
- Keep changes focused. Prefer comments explaining format quirks or invariants
  over comments restating the code.

Use small commits with a subject such as `tar: Handle ...` or
`tests: Verify ...`, at most 72 characters. Explain significant tradeoffs and
new dependencies in the commit body. Porting commits record their upstream
file and revision in a `Ported-from:` trailer. Pull requests should describe
the resulting behavior, relevant validation and any remaining limitations.

The upstream submodule is a read-only reference. An upstream update is a
separate compatibility change: review the delta, port the affected behavior,
then update the pin and baselines with evidence. Avoid committing generated
build outputs, raw benchmark data, private archives or temporary worktrees.
