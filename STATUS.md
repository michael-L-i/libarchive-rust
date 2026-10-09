# libarchive-rust status

Date 2026-10-09. Upstream pin `8bb3bbdc`. Run: port.

**All suites: 926 passed, 184 skipped; zero failures, crashes or timeouts.**

Libarchive: 764 passed / upstream baseline 829 / 934 total.

| Area | Ours | Upstream | Total |
|---|---:|---:|---:|
| acl | 18 | 19 | 21 |
| archive | 90 | 123 | 134 |
| cat | 18 | 18 | 18 |
| compat | 29 | 29 | 30 |
| cpio | 43 | 43 | 49 |
| entry | 3 | 3 | 3 |
| fuzz | 9 | 9 | 9 |
| read_filter | 14 | 15 | 19 |
| read_format_7zip | 56 | 56 | 56 |
| read_format_ar | 1 | 1 | 1 |
| read_format_cab | 9 | 9 | 10 |
| read_format_cpio | 24 | 24 | 35 |
| read_format_empty | 1 | 1 | 1 |
| read_format_huge | 1 | 1 | 1 |
| read_format_iso | 19 | 19 | 19 |
| read_format_lha | 6 | 6 | 7 |
| read_format_mtree | 13 | 13 | 13 |
| read_format_rar | 37 | 37 | 42 |
| read_format_rar5 | 77 | 77 | 78 |
| read_format_raw | 1 | 1 | 1 |
| read_format_tar | 33 | 33 | 41 |
| read_format_warc | 6 | 6 | 6 |
| read_format_xar | 10 | 10 | 10 |
| read_format_zip | 98 | 98 | 110 |
| tar | 72 | 72 | 79 |
| unzip | 29 | 29 | 30 |
| write_filter | 19 | 19 | 21 |
| write_format_7zip | 9 | 18 | 18 |
| write_format_ar | 1 | 1 | 1 |
| write_format_cpio | 5 | 5 | 5 |
| write_format_iso | 17 | 17 | 17 |
| write_format_mtree | 14 | 32 | 35 |
| write_format_raw | 2 | 2 | 2 |
| write_format_shar | 2 | 2 | 2 |
| write_format_tar | 13 | 13 | 13 |
| write_format_warc | 6 | 6 | 6 |
| write_format_xar | 4 | 7 | 7 |
| write_format_zip | 21 | 21 | 21 |
| other | 96 | 96 | 139 |

Remaining stubs (`src/ffi/stubs.rs`): 0
`unsafe` in `src/` (excluding stubs.rs): 258

## Phase 5 checkpoint

Complete on macOS under the safe-backend policy. All archive writers and
compression write filters, output clients, format selectors, matching,
disk traversal and extraction are implemented. All 454 public ABI functions
are exported and no generated stubs remain.

Verification: 366 Rust tests; strict all-target Clippy, rustfmt and diff checks;
926 upstream/front-end tests passed, 184 skipped, zero failures, crashes,
timeouts or ratchet regressions. The full run used one worker and 15-second
process-group timeouts and finished in 71 seconds. All passing cases are
recorded in tests/passing.txt. The harness excludes 73 internal-layout C tests;
native writer round trips, metadata checks and safety regressions cover the
corresponding public behavior. Other skips reflect platform/backend support.

Independent reviews covered matching/date rules, XAR metadata and allocation
bounds, compression cleanup, 7zip and PPMd. Integration fixes include encrypted
ZIP-LZMA headers, tar numeric padding, archive self-overwrite protection,
mode-000 file/directory ACL restoration and Zstd worker cleanup. Encoder output
differences and memory limits are documented in NOTES.md. Work is committed
locally; no test or encoder process remains running.

## Zstandard performance checkpoint

The write adapter batches small input writes and uses channel notifications
instead of 1 ms polling. The matcher reuses a fixed hash table, input buffers
and a bounded 1 MiB history across blocks. No dependency or C backend was added.

Five-run creation medians on the retained diagnostic corpus improved 18.3x
for 256 small files and 4.4x for 2 MiB text and random data. Text archives are
74% smaller; small-file archives are 38% smaller. Random-data peak RSS fell
from 9.0 to 6.3 MiB; repetitive-data RSS increased by about 1 MiB. The original
C implementation remains faster and compresses repetitive inputs better.
Measurements and limitations are in `../diagnostics/results/ZSTD.md`.

Verification: 371 native Rust tests passed; the opt-in independent C decoder
test also passed, including 128 KiB blocks with long periodic matches. Strict
all-target Clippy, rustfmt, diff and all 454 public-symbol checks passed.
The full upstream/front-end suite passed 926 tests, skipped 184, and had zero
failures, crashes, timeouts or ratchet regressions in 100 seconds with one
worker and 30-second timeouts. All 60 benchmark commands and 24 content-manifest
cross-reader checks passed. No build, test or benchmark process remains running.

## Earlier checkpoints (historical)

### Phase 2 checkpoint

Complete under the safe-backend policy. All planned read filters are registered;
XZ/LZMA/lzip and bzip2 use safe builds of lzma-rust2 and crabz2. LZ4 block-ending
validation matches the oracle. Backend limits and damaged-input differences are
recorded in NOTES.md; optional external filters still require their programs.

### Phase 3 checkpoint

Complete. The six small readers are registered: raw, empty, ar, cpio, warc and
mtree (with `archive_pack_dev`). Every `read_format_{ar,cpio,mtree,warc}` test
that passes upstream passes here; the cpio charset tests skip as they do
upstream. `test_compat_cpio`, `test_ar_mode` and `test_read_set_wrong_format`
also pass. Each unit was reviewed in a fresh context; quirks ported as-is and
the few differences (mtree shares `/set` options between entries, so memory
stays bounded) are in NOTES.md.

At this checkpoint, the bsdtar and bsdcpio front-end suites failed at startup:
both called `archive_match_new`, which was still a stub.

Verification: 246 Rust tests, strict Clippy and rustfmt; all suites 133 pass,
0 regressions.

### Phase 4 checkpoint

Complete under the safe-backend policy. The nine large readers (tar, ISO9660,
CAB, LHA, ZIP, XAR, RAR, RAR5 and 7zip), PPMd decoders and crypto helpers are
merged and registered. Decoder limits and upstream/backend differences are
documented in NOTES.md. Embedded ZIP and 7zip LZMA/XZ dictionaries and 7zip
PPMd models are capped at 256 MiB before allocation.

Verification: 332 Rust tests, strict all-target Clippy, rustfmt, and all 454
public ABI symbols. Full upstream/front-end run: 539 pass (491 libarchive),
276 fail, 177 skip, 117 crash, 1 timeout; zero ratchet regressions. All 539
passing tests are recorded in tests/passing.txt. Both RAR multivolume tests
pass after ZIP integration; bsdcat passes 18/18 and bsdunzip passes 29/29
applicable tests.

At this checkpoint, ZIP/extraction failures and the truncated-PAX timeout
still depended on Phase 5 writer and disk APIs. Those dependencies are now
implemented. The suite ran sequentially with 15-second process-group timeouts.
