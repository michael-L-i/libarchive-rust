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

## 7zip and LZMA performance checkpoint

Compared with c06c7a3 under identical Rust compiler settings, 7zip creation is
3.4–4.0x faster on repetitive text and 1.8x faster on small files. Creation RSS
falls from about 97 MiB to 24 MiB for 2 MiB text, 27 MiB for random data and
10 MiB for 256 small files. Listing RSS falls from about 12 MiB to 4 MiB.
At 16 MiB random input, peak RSS remains about 97 MiB. Incompressible creation
has little speed improvement and some cases are 1–5% slower.

The 7zip encoder sizes dictionaries to complete small streams, stages at most
8 MiB on an anonymous temporary file, and replays through 64 KiB buffers.
The decoder bounds validated LZMA2 history by known output size. A pinned local
lzma-rust2 patch accelerates binary-tree match extension in safe Rust, improving
repetitive XZ creation 3.1–3.8x without changing measured compressed bytes.
Zstandard default blocks increase to 96 KiB, reducing text archive sizes a
further 15–16% while preserving compression-level ordering.

Final verification: 375 native tests passed; strict all-target Clippy, rustfmt,
diff and all 454 ABI symbols passed. Full upstream/front-end suite: 926 passed,
184 skipped, zero failures, crashes, timeouts or ratchet regressions in 68s,
one worker with 30-second timeouts. Independent Astra reviews passed. Backend
differential validation produced 1,440 byte-identical XZ/LZMA/lzip streams.
The consolidated benchmark contains 702 successful timed commands, 234 content
extraction checks and 156 cross-reader checks. 7zip was remeasured after its
final staging adjustment; other measured format code was unchanged.

Results, remaining gaps, compiler settings and IO tradeoffs are recorded in
`../diagnostics/results/REPORT.md`; raw measurements identify source runs and
binary hashes. Code is committed locally; no tests or benchmarks remain running.

## Optimization round 3 checkpoint

Baseline `7139c72` to code `25ac9ea`: Zstandard uses five-byte hashing,
adaptive search skipping and amortized history compaction. XZ/LZMA2 defers
initialization of unused dictionary pages. Disk extraction omits redundant
contiguous seeks and final file resizing while retaining sparse/error behavior.
Independent Astra reviews passed for each change. No C codec, dependency or
unsafe backend feature was added; original C and pinned upstream are unchanged.

Same-profile release medians: 16 MiB random Zstd creation 72.0 -> 52.5 ms
(27% less time), mixed 87.9 -> 76.2 ms (13% less). Source archives are 4.6%
smaller. Matcher history capacity increases about 1 MiB; some archives grow
slightly. Small-files XZ listing RSS falls 11.7 -> 4.3 MiB; 2 MiB input falls
11.7 -> 5.7 MiB. Reserved virtual capacity is unchanged. Focused contiguous
disk writes fall 50.7 -> 47.4 ms; small-file writes change little.

Release and development comparisons are recorded separately. Current 16 MiB
random 7zip creation is 2797 ms Rust versus 2952 ms C; the baseline release
already had that advantage. Repetitive 16 MiB 7zip remains slower, 156 ms Rust
versus 92 ms C. No new 7zip encoder algorithm or blanket C-parity claim is made.
The normal release profile, not a Cargo profile change, is used for delivery.

Validation: 379 native tests passed, 1 opt-in test ignored; strict all-target
Clippy, rustfmt, diff and all 454 public symbols passed. Focused dev oracle:
117 passed, 13 skipped. Final release full upstream/front-end run: 926 passed,
184 skipped, zero failures, crashes, timeouts or ratchet regressions in 71s
(one worker, 30-second per-test timeout). All 25 self-contained vendor tests
pass; 6,790 decoder differential records match statuses, errors, consumption,
output lengths and hashes across fragmented, damaged and large-dictionary input.

Release benchmarks: 756 timed operations, 252 extraction manifest checks and
168 cross-reader checks passed. Dev benchmarks: 540 operations, 180 manifests
and 120 cross-reader checks passed. Five-repeat disk benchmarks completed 30
API runs. Sequential execution avoids benchmark/build contention.

The current absolute C/Rust tables, sizes, memory, compiler profiles, limitations
and raw binary hashes are in `../diagnostics/results/REPORT.md`. The previous
report is retained in `../diagnostics/results/before-round3/`. The current
`diagnostics/bin/rust-bsdtar` alias is the verified release snapshot; named
before/after snapshots preserve both profiles. Work is committed locally.

## Optimization round 4 checkpoint

Baseline `916ee2b` to final code `497ebb8`. Seven focused units, implemented in
separate worktrees and independently reviewed by Astra: exact rejection of Zstd
Huffman output that would be discarded, direct FSE encoder state lookup, inline
FSE decoder state updates, safe doubling of initialized overlapping matches,
slicing-by-eight XZ/LZIP checksums, overlapping LZMA match-tail comparison, and
skipping ordinary-permission ownership stats. Presets, parsing decisions and
checksum validation are preserved. No new unsafe code; one unsafe copy loop is
replaced by the existing safe buffer API. Original C/upstream remain unchanged.

Same-profile release medians: 16 MiB random Zstd creation 52.0 -> 23.6 ms
(C 14.2), mixed 72.9 -> 49.3 ms (C 32.9), source 91.5 -> 74.1 ms (C 41.5).
16 MiB text XZ creation 176.0 -> 134.1 ms and extraction 38.4 -> 17.1 ms
(C extraction 22.1); random XZ extraction 41.0 -> 19.8 ms (C 23.5).
16 MiB repetitive 7zip creation 158.7 -> 142.8 ms, still above C's 94.8 ms.
Added zero-heavy Zstd extraction 25.0 -> 6.5 ms, close to C's 5.7 ms.

The overlap fix is generic across distances and content; the held-out case
exposed one-byte-at-a-time expansion and then guided the general fix; its final
result is not an untouched holdout. Seven-run confirmation finds random
2 MiB 7zip and structured-record XZ creation effectively unchanged; compiled
XZ creation has a 2.6% higher median with overlapping ranges. Not every case
gets faster. Memory is broadly unchanged; CRC tables add 21 KiB read-only.
All 37 checked before/after Rust archive pairs are byte-identical. The already
used ruzstd version is vendored with license/hash provenance for five changed
source files; no codec version or C backend was added.

Final validation: 380 native tests passed, 1 opt-in ignored; strict all-target
Clippy, rustfmt, diff and 454 public ABI symbols passed. Release upstream/front-
end suite: 926 passed, 184 skipped, zero failures, crashes, timeouts or ratchet
regressions in 66s (one worker, 30-second per-test timeout). Backend validation
includes 6,790 exact decoder records, 1,440 exact encoded LZMA-family streams,
533 exact Zstd encoded cases, exhaustive FSE state comparisons, 175 damaged/
valid Zstd archive comparisons and 768 overlap/wrap/growth cases. Independent
C decoding and bitwise/scalar references validate changed operations.

Consolidated archive matrix: 999 timed operations, 333 extraction manifests,
222 cross-reader checks. Same-C-archive matrix: 1,110 timed reader operations,
555 extraction manifests. Another 63 targeted creation timings resolve noise.
Every check passed. Only Zstd decoding changed after the initial full matrix;
affected Zstd cases were rerun on final code, with each row's original binary
hash and source run retained. Unchanged formats were not needlessly rerun.

Current report and full separate C/Rust tables: `../diagnostics/results/REPORT.md`.
Prior report: `../diagnostics/results/before-round4/REPORT.md`. Both builds use
ordinary release settings; no profile/PGO/target-CPU tuning. Work is committed
locally. Current `diagnostics/bin/rust-bsdtar` is the verified final release.

## Optimization round 5 checkpoint

Baseline `c1dc8b7` to code `de50d58`: three reviewed Zstandard optimizations.
The matcher bounds its hash load once and stores relative `u32` positions,
rebasing only when retained history compacts. Its table shrinks from 512 to
256 KiB without changing match decisions. Two hot decoder ring appends replace
runtime division with one bounded subtraction; memory accesses are unchanged.

Release archive creation medians, C / previous Rust / current Rust in ms:
source 16 MiB 41.8 / 74.8 / 64.8; mixed 16 MiB 32.5 / 49.1 / 44.5;
random 16 MiB 14.0 / 23.4 / 21.5; compiled 16.2 / 24.6 / 22.0;
fresh numeric telemetry 20.9 / 30.4 / 27.4. These are roughly 8–13% reductions
in Rust creation time. Same-input isolated decoding improves about 2%; full
archive decoding changes are small and often within noise. C remains faster
on these larger Zstandard workloads and usually compresses them better.

Five LZMA/7zip alternatives were measured and rejected for regressions across
varied inputs. Existing XZ/7zip code and prior gains remain unchanged. FSE sort,
hash inlining, bit-refill and batched state-read trials were also reverted.
Independent agents reviewed each accepted unit; no new unsafe code or C codec
was added. Original C and pinned upstream remain clean.

Final validation: 380 native tests passed, 1 ignored; strict all-target Clippy,
rustfmt, diff checks and all 454 public ABI symbols passed. Full release suite:
926 passed, 184 skipped, zero failures/crashes/timeouts or ratchet regressions
in 67s, one worker with 30-second process timeouts. Backend checks cover 545
byte-identical encoded cases, independent C decoding, 175 exact valid/damaged
decode records, and six buffer tests including 768 overlap/wrap/growth cases.

Twelve Zstandard archive cases include two new inputs withheld from tuning.
All 12 previous/current Rust archive pairs are byte-identical. The matrix has
324 timed commands, 108 verified extraction manifests and 72 cross-reader
checks; the same-C-input matrix adds 360 reader commands and 180 extraction
manifests. Every check passed. All compute was sequential, builds used one job.

Current separate C/Rust tables and raw-data links: `../diagnostics/results/REPORT.md`.
Prior comprehensive six-format report: `../diagnostics/results/before-round5/REPORT.md`.
The final release snapshot is `../diagnostics/bin/rust-round5-final-bsdtar`;
`rust-bsdtar` points to identical bytes. Work is committed locally, with no
build, test, benchmark or worker process left running.

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
