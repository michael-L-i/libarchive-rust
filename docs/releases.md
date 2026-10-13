# Source releases and compiler support

Builds require Rust 1.95 or newer, a platform linker, and a C compiler for
the C interface's variadic formatting shim. Rust tools and the Rust library
do not compile C. Installed applications require neither Cargo nor rustc.
The minimum compiler is recorded in every first-party Cargo manifest and
tested in the installed-package CI matrix alongside the current stable
compiler. Keeping this baseline avoids requiring a newer compiler solely
to replace the small `archive_set_error` shim.

The installation path supports macOS and Linux with glibc. Native builds
inherit their builder's architecture, libc and macOS deployment target;
this does not make binaries compatible with every older distribution.
Build distribution packages in that distribution's supported build
environment. Windows, musl and kernel use are not validated targets.
The library uses `std`; C applications consume the compiled C ABI directly.

## Create an offline source archive

Run from a checkout containing committed changes, using Python 3.11 or newer:

```sh
scripts/source-release --revision HEAD --output /tmp/libarchive-rust-0.1.0.tar.gz
```

The selected commit, rather than uncommitted files, supplies the source.
The archive contains the public headers, Rust sources, installation and
test scripts, pinned local codec patches, and all locked registry
dependencies and their license files. Fetching dependencies may require
network access when creating the archive. It includes a Cargo configuration
that replaces crates.io with `third-party/` and disables network access.
`SOURCE-REVISION` identifies the source commit. The upstream C test oracle,
Git metadata, agent configuration, build outputs and benchmark data are
excluded. Full oracle and fuzz campaigns still use the development checkout.

File ordering, ownership, modes, timestamps and gzip headers are normalized.
The timestamp defaults to the source commit's timestamp; set
`SOURCE_DATE_EPOCH` explicitly when a packaging system supplies one.
The command refuses to replace an existing output. Repeated archives of
the same revision and dependency sources should have identical bytes;
this is separate from reproducibility of compiled machine code.

Extract and build without a populated Cargo cache:

```sh
tar -xzf /tmp/libarchive-rust-0.1.0.tar.gz
cd libarchive-rust-0.1.0
CARGO_HOME=/tmp/empty-libarchive-cargo cargo build --workspace --release --frozen
cargo test --workspace --frozen
scripts/install --prefix /usr --destdir /tmp/libarchive-package --profile release
scripts/test-installed --prefix /tmp/libarchive-package/usr --tools
```

Use a fresh directory for `CARGO_HOME`. The source archive includes the
normalization fixture needed by Rust unit tests. Platform-dependent tests
still require the locales and operating-system capabilities described by
the development test setup. Binary packages must carry the installed
license notices. Split runtime libraries, development headers/static
libraries/metadata, and optional tools using the staged paths documented
in `install.md`; package-manager manifests decide ownership and upgrades.
