# libarchive-rust

A memory-safe Rust port of [libarchive](https://github.com/libarchive/libarchive)
that is a drop-in replacement: same C ABI, same headers, same behavior. Existing
C programs (bsdtar, package managers) link it in place of `libarchive.so`.

## Rules

- **Memory safe.** `unsafe` is allowed only in `src/ffi/`, the C ABI layer. The
  crate root has `#![deny(unsafe_code)]`; only `ffi` opts out. Every `unsafe`
  block has a `// SAFETY:` comment.
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
  as-is and record it in `NOTES.md`. The one intended difference: input that
  makes upstream read or write out of bounds fails cleanly here.
- **Safe Rust dependencies.** No C, and prefer crates with no or minimal
  `unsafe`. When a backend can't be both memory-safe and byte-identical to
  upstream, safe wins: use the safe crate and record how its behavior differs
  (usually only on corrupt input) in `NOTES.md`. A machine-translated (c2rust)
  backend is allowed only when no safe option exists, and is tracked for
  replacement. A new dependency needs one line in the commit body saying why.
  The one C file is `src/ffi/variadic.c`, which formats `archive_set_error`'s
  varargs and calls into Rust, because stable Rust can't define C variadic
  functions.

## Layout

Target layout; create directories as units land.

```
upstream/libarchive/  submodule pinned at 8bb3bbd (3.9.0dev). Read-only.
include/              archive.h, archive_entry.h copied unchanged from upstream
src/ffi/              exported archive_* functions; the only unsafe code
src/ffi/stubs.rs      generated stubs for unported functions (scripts/gen-stubs)
src/                  one module per upstream file (naming rule below)
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

The crate builds `libarchive.{so,dylib,a}`: `[lib] name = "archive"`,
`crate-type = ["cdylib", "staticlib", "rlib"]`.

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
scripts/build-port              cargo build, relink upstream's tests against ours
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
   Upstream itself passes 829 here (the rest skip for platform reasons), so 829
   is the target. A test in `tests/passing.txt` that fails is a regression and
   blocks the commit. Newly passing tests go into `passing.txt` in the same
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
3. **Fuzzing.** One `cargo fuzz` target per reader. A crash, panic, hang or
   unbounded allocation is a bug.

Run the narrowest check that covers the change. Keep harness output terse: pass
and fail counts plus the first failure.

## Port order

Sizes are code lines (no comments or blanks) at the pin. The library is 103k
lines; the read side (phases 1–4) is about 67k.

| Phase | Units | Lines |
|---|---|---|
| 0 | Harness: oracle build, stubs for the 454 public functions, relinked test binary, runner, ratchet | — |
| 1 | Core read path: `archive_read`, `archive_entry`, `archive_string` (+ composition table), `archive_acl`, `archive_util`, `archive_rb`, `archive_read_open_*` | 12k |
| 2 | Read filters: gzip, bzip2, xz, zstd, lz4, compress, uu, lzop, rpm, program | 4k |
| 3 | Small readers: raw, empty, ar, cpio, warc, mtree | 4k |
| 4 | Large readers: tar, iso9660, cab, lha, zip, xar, rar, rar5, 7zip (+ `archive_ppmd7`/`8`, digest, cryptor) | 30k |
| 5 | Writers, `archive_write_disk`, `archive_read_disk`, `archive_match` | 34k |

Each unit comes with its test list: the upstream tests it should turn green,
by name pattern (`test_read_format_cpio*`). The read side alone can pass 540
tests; writers, disk and match tests (338) wait for phase 5.

**Checkpoint:** after phase 1, stop for human review of the core internal API
(read-ahead and consume, entries, errors) before the readers fan out.

Not ported: `tar/`, `cpio/`, `cat/`, `unzip/`. The upstream front-ends link our
library unchanged and serve as integration tests. Windows-only files come last.

## Agents and models

**Orchestrator: Sonnet 5.5** (`claude-sonnet-5-5`, set in
`.claude/settings.json`). It picks units, dispatches subagents, runs the
oracle, merges and updates `STATUS.md`. It does not write large ports itself.

**Subagents: Haiku 5.5** (`claude-haiku-5-5`) by default. Use **Sonnet 5.5**
when a unit is:

- over ~1,500 lines, or one function group of such a file
- a decompressor: PPMd, RAR/RAR5 LZSS and filters, LHA, CAB LZX, 7-Zip coders
- `archive_read`, `archive_string` charset conversion, `src/ffi/`, or the disk
  readers and writers (path traversal and symlink safety)
- a Haiku attempt that failed twice on the same oracle failures

Escalate to **Opus 5.5** (`claude-opus-5-5`) when a unit is really stuck:
Sonnet has failed twice on the same oracle failures, or a divergence from
upstream persists that no one can explain. Hand Opus the failing tests, what
was tried, and the evidence so far; drop back to the default model for the
next unit.

In Claude Code, `porter` and `reviewer` in `.claude/agents/` default to Haiku.
Pass `model: "sonnet"` or `model: "opus"` on the Agent call to escalate.

Per unit:

1. `porter` ports one unit (one upstream file, or one function group of a large
   file) until its oracle tests pass, committing incrementally as it goes.
2. `reviewer`, in a fresh context with only the unit's commit range and the
   upstream file, checks memory safety, fidelity and concision. Use the
   porter's model or higher. `STOP` means the porter fixes it in follow-up
   commits before the unit is merged.
3. The orchestrator runs the full oracle, merges and updates `STATUS.md`.

Parallel units run in separate git worktrees, one branch per unit, and touch
different files. Phase 1 is mostly serial; the readers in phases 3–4
parallelize well.

## Commits

Small, incremental commits in upstream libarchive's style:

- Subject `component: Imperative summary`, at most 72 characters. Components
  follow upstream areas: `core`, `ffi`, `tar`, `zip`, `7zip`, `rar5`, `xz`,
  `tests`, `ci`. Examples: `tar: Port pax extended header parsing`,
  `ffi: Export archive_read_next_header`.
- Body only when needed, wrapped at 72, saying why rather than what.
- Porting commits end with `Ported-from: libarchive/<file> @ 8bb3bbd`.
- One logical change per commit. Each commit builds, passes
  `cargo clippy -- -D warnings` and `cargo fmt --check`, and doesn't lower
  the oracle pass count.

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
`archive_read_support_filter_compress.c` also carries a UC Regents 3-clause
notice, `archive_parse_date.c` is public domain, and the BLAKE2 files are
CC0/OpenSSL/Apache-2.0. Keep those notices on the modules ported from them.
