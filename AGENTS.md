# libarchive-rust

A Rust port of [libarchive](https://github.com/libarchive/libarchive) and its
command-line tools. It targets the pinned upstream public C ABI and headers.
Document supported platforms and behavior differences in `NOTES.md`; do not
claim compatibility beyond validated configurations.

## Rules

- **Memory safe.** `unsafe` is allowed only in `src/ffi/`, the C ABI layer,
  and in `tools/libarchive_fe/src/sys.rs` (see Front-ends). The library and
  the tools have `#![deny(unsafe_code)]` at their roots; only those modules
  opt out. Every `unsafe` block has a `// SAFETY:` comment.
- **Never trust archive bytes.** Sizes, offsets and counts read from input use
  checked arithmetic and are bounded before allocating or reading ahead.
  Malformed input returns `ARCHIVE_WARN`/`ARCHIVE_FATAL` with upstream's error
  message. It never panics: no `unwrap`, `expect`, indexing or slicing that can
  fail on input-derived values. Every exported function wraps its body in
  `catch_unwind`.
- **Concise.** Port behavior, not C ceremony: `goto cleanup` becomes `?` and
  `Drop`, manual buffers become `Vec` and slices, hand-rolled lists become std
  collections. No speculative abstractions, no dead code, no wrappers with one
  caller. Keep upstream comments that explain format quirks; don't add comments
  that restate the code.
- **Faithful.** Match upstream at the pinned commit: return codes, errno values,
  error strings, entry metadata and output bytes. Port behavior that looks wrong
  as-is and record it in `NOTES.md`, except bugs that corrupt output data:
  fix those and document the behavior difference and regression evidence.
  Input that makes upstream read or write out of bounds fails cleanly here.
  Reviewed descriptor-based disk hardening may retain an observed inode,
  fail on replacement or refuse unanchored metadata fallbacks; document its
  errors and remaining race limitations in `NOTES.md`.
- **Safe Rust dependencies.** No C, and prefer crates with no or minimal
  `unsafe`. When a backend can't be both memory-safe and byte-identical to
  upstream, safe wins: use the safe crate and record how its behavior differs
  (usually only on corrupt input) in `NOTES.md`. A machine-translated (c2rust)
  backend is allowed only when no safe option exists, and is tracked for
  replacement. A new dependency needs one line in the commit body saying why.
  The one C file is `capi/variadic.c`, which formats `archive_set_error`'s
  varargs and calls into Rust, to support the minimum Rust 1.95 compiler. Only the C library (`capi/`) compiles it; the Rust crate and
  everything built on it contain no C.

## Processing limits

Default reads retain upstream behavior and existing hard safety caps.
`ReadLimits` and `limits:*` read options are opt-in extensions configured
before open; configure decoder memory before explicitly appending filters.
New covered decoder output, entry-table records and retained metadata must
share the handle's processing budget, including hidden work and skips.
Keep allocation checks before covered retained allocations. Work limits
are not CPU deadlines or total heap/RSS limits: producer blocks, callback
work, external programs and unsupported decoder allocations need external
resource controls. Preserve uncapped compatibility and document actual
coverage and error behavior in `src/read/limits.rs` and `NOTES.md`.

## Layout

The library, C interface and tools share one Cargo workspace and Git repository.

```
upstream/libarchive/  pinned C reference for oracle tests; read-only, never shipped.
include/              archive.h, archive_entry.h copied unchanged from upstream
src/ffi/              archive_* exports and operating-system wrappers
src/                  one module per upstream file (naming rule below)
src/api/              the Rust API: typed handles over the C API's behavior
capi/                 builds libarchive.{so,dylib,a} for C programs, + variadic.c
tools/libarchive_fe/  the front-ends' shared helpers (libarchive_fe/)
tools/<dir>/          bsdtar, bsdcpio, bsdcat, bsdunzip (tar/, cpio/, cat/, unzip/)
scripts/              oracle build, port build, test runner
tests/passing.txt     the ratchet: upstream tests that pass against our library
tests/upstream.txt    upstream tests that pass against upstream on this machine
build/                gitignored: build/oracle (upstream), build/port (ours)
STATUS.md             oracle pass counts, per-unit state, unsafe count
NOTES.md              suspected upstream bugs, ported as-is
```

Naming rule, so upstream diffs map to modules mechanically:

| Upstream file | Module |
|---|---|
| `archive_read_support_format_X.c` | `src/read/format/X.rs` |
| `archive_read_support_filter_X.c` | `src/read/filter/X.rs` |
| `archive_write_set_format_X.c` | `src/write/format/X.rs` |
| `archive_write_add_filter_X.c` | `src/write/filter/X.rs` |
| other `archive_X.c` | `src/X.rs` |

The workspace root is the Rust library, `libarchive-rust` (an rlib, pure
Rust). `capi/` (`libarchive-capi`, `[lib] name = "archive"`,
`crate-type = ["cdylib", "staticlib"]`) links its exported functions into
`libarchive.{so,dylib,a}`.

## FFI conventions

- A `struct archive *` is a leaked `Box<Handle>` (`src/archive.rs`): the state
  every kind shares (magic, state, error, format) plus a `Kind` enum for read,
  write, write-disk, read-disk and match. A `struct archive_entry *` is a
  leaked `Box<Entry>`. The `*_free` functions reclaim them.
- Exported functions borrow the handle as `&Handle`, never `&mut`: client
  callbacks (open, read, skip, close, passphrase) can call back into the same
  handle, and two live `&mut` would be undefined behavior. State that changes
  is a `Cell`/`RefCell` in `Base`, or sits in the kind's own `RefCell`. A
  re-entrant borrow of the same kind panics, and `guard` turns that into
  `ARCHIVE_FATAL`; calls that touch only `Base` (`archive_set_error`,
  `archive_errno`) always work. Never hold a `Base` borrow across a
  callback; the kind's borrow is held across callbacks by design.
- An entry a handle hands to C (e.g. from `archive_read_next_header`) is kept
  by the handle as the raw pointer from `Box::into_raw`, not as a `Box`, so
  the `&mut Entry` an exported `archive_entry_*` call derives never aliases a
  live `Box`. The handle frees it with `Box::from_raw` when it is freed.
- The locale conversion cache lives in `Base` as a shared
  `Arc<Mutex<ConvCache>>`; `archive_entry_new2(a)` clones it into the entry,
  so an entry never points at a freed handle.
- Exported functions are thin: check the handle with the port of
  `__archive_check_magic` (same messages, same state machine), run the body
  under `guard`, convert arguments, call safe Rust, convert the result back.
- Archive strings are bytes (`Vec<u8>`, `&[u8]`), never `String`; pathnames
  aren't UTF-8.
- A returned `const char *` points into a NUL-terminated buffer owned by the
  handle or entry, valid until that field changes or the object is freed, as
  upstream promises. Clear and refill the buffer in place (upstream's
  `archive_string` model); never drop or replace it while the handle lives.
- libc (locale, iconv, file descriptors, stat) is reached only through safe
  wrappers in `src/ffi/`.

## Oracle

Upstream decides correctness, not tests we write.

```
scripts/build-oracle            once: CMake build of upstream into build/oracle
scripts/build-port              cargo build, relink upstream's tests against ours; the
                                Rust front-ends go to build/port/bin, the relinked C
                                ones to build/port/c-bin (and bin, until ported)
scripts/run-tests [PATTERN...]  one process per test, parallel; checks the ratchet
scripts/run-tests --update      add newly passing tests to tests/passing.txt
scripts/run-tests --suite cat [PATTERN...]  front-end suite: cat, tar, cpio, unzip, or all
scripts/diff-cat [GLOB...]      upstream vs our bsdcat over upstream's fixtures
```

`diff-cat` is the main oracle for filters: it compares exit status, stdout and stderr
per fixture and tags each with the filter it exercises, so a filter agent can filter on it.

1. **Upstream test suite.** `libarchive/test/` holds 934 tests and 491 `.uu`
   fixtures, compiled unchanged and linked against our library. This is the
   primary oracle; its pass count is the headline number in `STATUS.md`.
   Use the current per-platform counts in `STATUS.md` and the oracle
   baselines, including platform and internal-test skips. A recorded pass
   that fails or skips is a regression and blocks the commit. Newly passing
   tests go into the selected platform baseline in the same
   commit as the code that fixed them. 17 files (73 tests) call libarchive
   internals and can't link against the public ABI; `build-port` detects them
   with `nm` and turns them into skips, and their checks are ported as Rust
   `#[test]`s next to the module they cover.
   Upstream's tests reach most readers through the `all` tables, so a
   per-format export that is still the stub goes unnoticed there. When a
   unit registers a format or filter, add its export to
   `every_ported_format_and_filter_has_a_working_export` in
   `src/ffi/read.rs`.
2. **Differential runs.** Build upstream `bsdtar` against upstream libarchive
   and against ours. Diff `bsdtar -tvf` output, extracted trees and exit codes
   over the corpus: upstream's `*.uu` test archives plus oss-fuzz corpora.
3. **Fuzzing.** The nightly-only `fuzz/` crate stays outside the workspace.
   Its 39 targets cover formats/filters/all, a deeper reader, seven writer
   formats plus `writer_roundtrip`, and `read_limits`. Reader targets apply
   opt-in budgets before open, touch entry metadata and abort on swallowed
   ABI panics. Valid writer properties compare exact recovered contents and
   partial-read/skip behavior through bounded owned memory output. A crash,
   panic, hang or uncontrolled allocation in these bounded harnesses is a
   bug; processing limits do not replace libFuzzer timeout/RSS controls.

   ```
   scripts/fuzz-seeds                  # upstream .uu reader fixtures
   scripts/fuzz-writer-seeds           # valid writer and deeper-reader seeds
   cd fuzz
   cargo +nightly fuzz run format_zip -- -timeout=10 -rss_limit_mb=2048 -malloc_limit_mb=1024 -max_total_time=300
   cargo +nightly fuzz build && for t in $(cargo +nightly fuzz list); do   # all targets, 30 s each
     cargo +nightly fuzz run $t -- -max_total_time=30 -timeout=10 -rss_limit_mb=2048 -malloc_limit_mb=1024 || break
   done
   ```

   Corpora and crash artifacts are gitignored. Minimize a crash with
   `cargo +nightly fuzz tmin <target> <artifact>`, check what upstream's
   `bsdtar`/`bsdcat` does with it, fix the library, and keep the input as a
   Rust `#[test]` next to the module.

Run the narrowest check that covers the change. Keep harness output terse: pass
and fail counts plus the first failure.

## Front-ends

Upstream's command-line tools are Rust programs built on the library's Rust
API, with upstream's options, output bytes, messages and exit codes. Their
test programs (`bsdcat_test` and so on, from `build/oracle`) are the oracle.

Layout: upstream `<dir>/<file>.c` is `tools/<dir>/src/<file>.rs`; a header's
declarations go in the module of the `.c` that uses them (`struct bsdcat` is
in `bsdcat.rs`). The package is named after the binary (`bsdcat`, with
`[[bin]] path = "src/bsdcat.rs"`) and depends on `libarchive-rust` and
`libarchive-fe`, never on `libarchive-capi`: the tools contain no C, and
`build-port` fails if anything they build from compiles C. License headers
and `Ported-from:` trailers work as for the library, with the upstream path
(`// Ported from cat/bsdcat.c.`).

`libarchive_fe` keeps upstream's names: `lafe_warnc(code, msg)` and
`lafe_errc(eval, code, msg)` take the formatted message as bytes
(`[path, b": ", err].concat()` or `format!`), `LineReader` is
`lafe_line_reader`, and so on. `lafe_fnmatch.c` and `lafe_getline.c` are not
ported (fallbacks for libcs without them); use `BufRead::read_until` for
getline and add a `sys` wrapper for `fnmatch(3)`.

**The unsafe exception.** The tool crates are `#![deny(unsafe_code)]`. The
libc calls std lacks (signal dispositions, termios, umask, strerror, the
locale, regex, the user and group databases and so on) are safe wrappers in
`libarchive_fe::sys`, the only module that opts out; add yours there, each
`unsafe` block with a `// SAFETY:` comment. Prefer std wherever it can do
the job.

**Using the API.** `use libarchive_rust::{ArchiveRead, ArchiveEntry, Status};`
The module doc of `src/api/mod.rs` has the mapping; in short:

- `archive_read_X(a, ...)` is `a.X(...)` on `ArchiveRead`; likewise
  `ArchiveWrite`, `ArchiveWriteDisk`, `ArchiveReadDisk`, `ArchiveMatch`,
  `ArchiveEntry` and `ArchiveEntryLinkresolver`. `archive_errno`,
  `archive_error_string`, `archive_filter_*` and friends are methods of
  `Archive`, which every handle dereferences to. `archive_X_new` is `new`;
  `archive_X_free` is dropping the handle.
- `Status` mirrors the return codes and is ordered like them (`r < Status::Ok`,
  `r <= Status::Warn`). A `ssize_t` result is `Result<usize, Status>`. The
  error message stays on the handle: `a.error_string()` is
  `Option<Ref<[u8]>>`, and printf prints a NULL `%s` as `(null)`, so C's
  `"%s", archive_error_string(a)` is `.as_deref().unwrap_or(b"(null)")`.
- Strings are `&[u8]` (truncated at a NUL as C would see them), NULL-able
  ones `Option<&[u8]>`; file names are `&Path`; descriptors are `AsFd`
  (`open_fd` keeps its argument open while it reads: pass a `File`, or an
  `Rc<File>` you keep using). Callbacks are closures; one can't reach the
  handle it is set on, so it captures what it needs.
- `next_header` reads into the handle's own entry, `a.entry()`. A call that
  takes an entry back (`extract2`, a writer's `header`) can't borrow the
  handle's own one; read with `next_header2` into an `ArchiveEntry` of your
  own instead. Entry getters take `&mut self` (text converts lazily), so copy
  one string before asking for the next if you need both.
- A Rust program starts with `SIGPIPE` ignored; call
  `sys::default_signal(libc::SIGPIPE)` first in `main`, as `bsdcat` does.

**Adding a function the API lacks.** Each C function's behavior after
argument conversion (its `archive_check_magic`, with upstream's function name
and states, and the call into the library) is one `pub(crate)` method on
`Handle` in `src/api/<kind>.rs`, named after the C function without
`archive_` (`read_set_format`, `match_include_date`). The export in `ffi`
converts pointers and calls it; the typed method converts types and calls
it. So:

1. Move the export's body, minus pointer handling, into such a method. Use
   the helpers there: `Handle::checked` (the check alone), `read_checked`,
   `write_checked`, `match_operation`, `with_write_disk`, `with_read_disk`.
   Return the C code.
2. Make the export `with(a, ARCHIVE_FATAL, |h| h.read_set_format(code))`.
3. Add the typed method, named after the C function without the kind's
   prefix, returning `Status::from_code(...)` (or `Status::from_size` for a
   `ssize_t`). A callback becomes a closure type stored in the library state
   (`Box<dyn FnMut ...>`, or `Rc<dyn Fn()>` when it must run while the state
   is not borrowed, as `Handle::read_extract_progress` does); the export
   wraps the C function and its data into the same type.
4. Add a unit test next to it. The oracle suites cover the C path: their
   pass count must not move.

The API has every library function the front-ends call. The disk
reader's callbacks (the metadata filter and `set_matching`'s excluded
callback) get the entry as an `ArchiveEntry` and the walk as a
`ReadDiskView`, which has `can_descend` and `descend`. The reader owns
the `ArchiveMatch` `set_matching` gives it; `matching()` lends it back.

**Checklist for a tool.**

1. Add `tools/<dir>` to the workspace's `members` and `default-members`, and
   the binary to `RUST_TOOLS` in `scripts/build-port`.
2. Port each file mechanically: same control flow, messages through
   `lafe_*`, same exit codes; upstream's signal and locale setup in `main`
   through `sys`. Unit-test the option parser.
3. `scripts/build-port --release`, then `scripts/run-tests --suite <tool>`:
   no regressions against `tests/passing.txt`. Compare with the relinked C
   tool in `build/port/c-bin/` on cases the suite misses; it uses the same
   library, so outputs must be byte-identical. For bsdcat,
   `scripts/diff-cat` also compares against upstream.
4. `otool -L` (or `ldd`) on the binary lists only the system libraries
   (libSystem and libiconv on macOS).

## Review and parallel work

Use separate worktrees for concurrent changes with different file ownership.
Keep performance measurements free of competing builds or test campaigns.
Before merging a functional change, obtain an independent review of safety,
fidelity and concision, run the applicable oracle tests, and update `STATUS.md`.
Resolve blocking review findings before integration. Remove temporary worktrees
once their changes have been integrated or their experiments archived.

## Commits

Small, incremental commits in upstream libarchive's style:

- Subject `component: Imperative summary`, at most 72 characters. Components
  follow upstream areas: `core`, `ffi`, `tar`, `zip`, `7zip`, `rar5`, `xz`,
  `tests`, `ci`. Examples: `tar: Port pax extended header parsing`,
  `ffi: Export archive_read_next_header`.
- Body only when needed, wrapped at 72, saying why rather than what.
- Porting commits end with `Ported-from: libarchive/<file> @ 8bb3bbd`.
- One logical change per commit. Each commit builds, passes
  `cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo fmt --all --check`, and doesn't lower the oracle pass count.

## Upstream

Pinned at `8bb3bbdc7b117a1e22086a2260f2087aafa90687` (2026-10-06). Never edit
`upstream/`. To bump: list changes with
`git -C upstream/libarchive diff --stat OLD NEW -- libarchive/`, map each file
to its module by the naming rule, port the deltas, then move the pin and this
file together in one `upstream: Bump to <sha>` commit.

## License

BSD-2-Clause, like upstream. Each ported module starts with the upstream file's
copyright header unchanged (upstream requires it "in this position and
unchanged"), then `// Ported from libarchive/<file>.` Per upstream `COPYING`,
`archive_read_support_filter_compress.c` and
`archive_write_add_filter_compress.c` also carry a UC Regents notice, `archive_parse_date.c` is public domain, and the BLAKE2 files are
CC0/OpenSSL/Apache-2.0. Keep those notices on the modules ported from them.
