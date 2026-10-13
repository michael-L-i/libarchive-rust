# Build and stage an installation

The C library and command-line tools support Linux and macOS. Building needs
Rust 1.95 or newer, Cargo, a C compiler for `archive_set_error`'s variadic shim,
and Python 3. Runtime consumers need the platform system libraries, without a
Rust compiler or Rust installation. The Rust library and Rust tools do not
compile the shim.

Use the standalone installer without building the upstream C oracle:

```sh
scripts/install --prefix /usr --destdir "$PWD/build/package"
```

This builds the C shared and static libraries and all four Rust tools in the
release profile, using the locked dependencies. `--without-tools` stages only
the library and development files. `--profile dev` selects a development build.
`--libdir lib64` or `--libdir lib/x86_64-linux-gnu` selects a directory relative
to the prefix. Library-directory components accept ASCII letters, digits,
`_`, `.`, `+` and `-`; spaces and other punctuation are rejected because this
path is also embedded in pkg-config and CMake metadata. The prefix and staging
directory may contain spaces. `--target-dir PATH` overrides the dedicated `build/install-target`
Cargo cache. Ordinary Cargo environment variables, such as `CARGO_HOME`, are
supported. The installer selects the compiler named by `RUSTC` (default
`rustc`) and explicitly builds for that compiler's host target, overriding
Cargo's `build.target` configuration. Cross compilation is not supported;
a differing `CARGO_BUILD_TARGET` environment variable is rejected.

`--destdir` is required. The script stages files for a package manager or a
separate deployment step; it does not modify the running system. The installed
prefix is `$DESTDIR$PREFIX`. The installer refuses symlink directories inside
staging and does not follow existing symlink files. Use an empty staging tree
when preparing a package with a different prefix, library directory or tool
selection; the installer does not remove files from previous selections.

The staged files are:

- Runtime library: Linux `libarchive.so.13.9.0`, with a `libarchive.so.13` link;
  macOS `libarchive.13.9.0.dylib`, with a `libarchive.13.dylib` link.
- Development files: `include/archive.h`, `include/archive_entry.h`,
  `libarchive.a`, the unversioned shared-library link, `libarchive.pc` and CMake
  package files under the selected library directory.
- Optional tools: `bin/bsdtar`, `bin/bsdcpio`, `bin/bsdcat`, `bin/bsdunzip`.
- License and copyright notices: `share/licenses/libarchive-rust/`.

The headers are unchanged copies from the pinned upstream version, 3.9.0dev.
The library uses upstream's ABI major 13 and libtool file version 13.9.0;
these are distinct from the Rust crate's 0.1.0 version. The macOS compatibility
and current versions are 23.0.0, matching the pinned upstream libtool metadata.
Linux records `libarchive.so.13` as its SONAME. macOS records
`@rpath/libarchive.13.dylib`; applications should supply an appropriate runtime
search path, for example `-Wl,-rpath,/opt/libarchive/lib` for a private prefix.
Linux applications using a private prefix likewise need a runtime search path.
Distribution packages should use their normal loader configuration.

For C or C++ applications, use pkg-config:

```sh
export PKG_CONFIG_PATH=/opt/libarchive/lib/pkgconfig
cc example.c $(pkg-config --cflags --libs libarchive) -o example
```

For paths containing spaces, consume pkg-config output with a build system
that parses its shell escapes, such as CMake or Meson; unquoted command
substitution in the example above does not preserve those paths. The original
pkg-config 0.29.2 also leaves spaces in its built-in `pcfiledir` variable
unescaped when expanding relocatable metadata. Consumers using that version
can pass `--define-variable=pcfiledir=PATH` with spaces in `PATH` escaped as
`\ ` before querying compiler and linker flags. `scripts/test-installed`
checks the unmodified relocation variables and retries this override only
when the emitted flags exhibit that exact legacy spacing defect. Newer
pkgconf implementations handle the unmodified metadata directly.

For a fully static libarchive dependency, request `pkg-config --static --libs
libarchive` and select `libarchive.a` explicitly instead of the shared library.
`Libs.private` is generated from the building Rust compiler's reported native
link dependencies, preserving their order. It does not list unused C compression
libraries. The archive still depends on platform system libraries; it is not a
freestanding executable or a `no_std` library.

CMake config consumers can use:

```cmake
find_package(LibArchive 3.9 CONFIG REQUIRED)
target_link_libraries(example PRIVATE LibArchive::LibArchive)
# Or LibArchive::LibArchiveStatic for the static archive and its dependencies.
```

Set `CMAKE_PREFIX_PATH` to the installed prefix. pkg-config and CMake metadata
are relative to their own installed locations so the staged tree can be moved.
For pkg-config against a staged `/usr` installation, use `PKG_CONFIG_LIBDIR` to
restrict discovery and `PKG_CONFIG_SYSROOT_DIR` to apply the staging root.

Matching SONAME, headers and public exports enables compatibility testing;
it does not prove every downstream application or distribution ABI contract.
Before replacing a distribution's libarchive package, test its downstream
clients, architecture, libc baseline and packaging conventions. Keep the
recorded behavior differences in `NOTES.md` in that evaluation. This installer
does not change the compression code or optimization profile.
