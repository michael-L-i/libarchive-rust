# libarchive-rust status

Date 2026-10-11. Upstream pin `8bb3bbdc`. Run: port.

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
`unsafe` in `src/` (excluding stubs.rs): 248; in the tools: 39, all in
`tools/libarchive_fe/src/sys.rs`

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

Compared with 6dc2f00 under identical Rust compiler settings, 7zip creation is
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

Baseline `4a7a5de` to code `84a0406`: Zstandard uses five-byte hashing,
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

Baseline `80cfc52` to final code `18d1b64`. Seven focused units, implemented in
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

Baseline `c31ba8d` to code `3bc5500`: three reviewed Zstandard optimizations.
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

## Optimization round 6 checkpoint

Baseline `e999b15` to code `d48411c`: BT4 skip reuses the proved suffix of
earlier same-distance matches, preserving exact tree and match decisions.
The three-integer cache is invalidated at position normalization. Zstandard
batches three bounded FSE state fields into one bit write and inlines match
repetition into sequence execution. Each unit received independent review.

Release creation medians, C / previous Rust / current Rust in ms:
16 MiB repetitive 7zip 91.9 / 136.1 / 112.4 (17.4% Rust improvement);
16 MiB repetitive XZ 104.4 / 135.9 / 109.6 (19.3%). Rust is within about 5%
of C on the latter case. Separate document input 7zip improves 122.6 to
111.7 ms (C 118.5), and zero-heavy 7zip 83.8 to 71.0 ms (C 65.3).
Random and source LZMA microbenchmarks are essentially unchanged.

Seven-run confirmation resolves noisy creation results: structured-record
7zip 968.6 to 973.6 ms and telemetry 910.4 to 917.4 ms, both with overlapping
ranges. No gain is claimed for noisy random 2 MiB 7zip. Source/mixed Zstandard
encoding improves 4–6% in isolation, but full archive creation changes are
small/noise-level this round. Isolated decoding improves about 2.5%; all
end-to-end values and unchanged or slower individual cases are reported.

Validation: 380 native tests passed, 1 ignored; strict all-target Clippy,
rustfmt, diff and 454 public ABI symbols passed. Full release suite: 926 passed,
184 skipped, zero failures/crashes/timeouts or ratchet regressions in 67s.
The run used one worker with 30-second process deadlines. LZMA checks include
1,440 byte-identical encoded streams, 27 self-contained vendor tests, and an
exact 2,147,614,720-byte streaming comparison crossing position normalization.
Zstandard checks include 545 exact encoded cases, independent C decoding,
15 FSE/bit-writer tests, 175 exact valid/damaged ABI cases and six buffer tests.

The 34-case archive matrix has 918 timed commands, 306 verified extractions,
204 cross-reader checks and 34 byte-identical retained archive pairs. The same-
C-input matrix adds 1,020 reader commands and 510 extraction checks. Four
targeted seven-run confirmations add 84 creation timings; every Rust output
hash matches across all their repetitions. All checks passed. Original raw
samples and per-row confirmation provenance are retained. Rejected trials
were reverted, with evidence preserved outside the packages.

Current tables: `../diagnostics/results/REPORT.md`; previous report:
`../diagnostics/results/before-round6/REPORT.md`. The current release is
`../diagnostics/bin/rust-round6-final-bsdtar`, identical to `rust-bsdtar`.
No new dependency, C codec or unsafe code was added. Original C/upstream remain
clean. Work is committed locally; no build, test or benchmark remains running.

## Optimization round 7 checkpoint

Baseline `b9b8c7e` -> final code `8df7b41`. Three isolated specialists used
actual Claude Opus 5.5 for design and fresh independent review. The accepted
changes mask range updates for normal LZMA literals, share a direct Zstandard
frame encoder with the existing pull compressor, and predecode Zstandard
sequence-length FSE states. Matched LZMA literals and explicit Zstandard framing
retain their previous paths. No preset, match policy, checksum, dependency or
unsafe-code policy changed. All rejected trials remain outside the package.

Five rotating release-run archive medians, milliseconds (C / previous Rust /
current Rust): random 16 MiB 7zip 2636.5 / 2507.9 / 2338.2; random XZ
2642.0 / 2486.1 / 2329.6; source Zstandard 41.1 / 64.0 / 60.1; mixed Zstandard
32.5 / 43.8 / 41.1. Default random 7zip/XZ improve 6-7% and are about 11% faster
than C on these inputs. Repetitive 7zip is unchanged and still trails C.

Separate preset-1 checks preserve the same preset in every variant: random
7zip 1189.6 / 1072.0 / 857.0 and XZ 1214.3 / 1077.4 / 862.9, about 20% less
Rust time and 28-29% faster than C. Source/compiled LZMA backend checks are
neutral. Zstandard decoding improves about 1.5-2% in isolation; end-to-end
reader changes are smaller. C still leads many workloads; all results remain
visible in the report. No universal parity claim is made.

Combined validation: 384 native tests passed, 1 ignored; strict all-target
Clippy, formatting/diff checks and all 454 ABI symbols passed. Full release
compatibility/front-end suite: 926 passed, 184 skipped, zero failures, crashes,
timeouts or ratchet regressions in 66 seconds, one worker and 30-second deadlines.
LZMA checks include 1,656 exact streams, 381,504 arithmetic/error states and
27 self-contained vendor tests. Zstandard checks include 650 byte-exact encoder
comparisons, 13 focused lifecycle/error tests, 175 exact valid/damaged decoder
ABI records and 84 short-input checks against baseline and independent C.

The default 34-case matrix has 1,530 timed commands, 510 verified extractions
and 204 cross-reader checks. The same-C-input matrix adds 1,020 reader commands
and 510 verified extractions. Six preset-1 cases add 90 creation timings and
36 cross-reader extractions. All 40 cases retain identical Rust output across
all five repetitions. No operation in the final archive matrices has a median regression above 5%;
smaller neutral/slower measurements remain in the tables. Raw samples, source
and binary identities, transient timing inflation and rejected trials are retained.

Current report: `../diagnostics/results/REPORT.md`; previous report:
`../diagnostics/results/before-round7/REPORT.md`. Frozen current release:
`../diagnostics/bin/rust-round7-final-bsdtar`, identical to `rust-bsdtar`.
Original C/upstream remain clean. Work is committed locally; no test, build
or benchmark remains running.

## Optimization round 8 checkpoint

Eight reviewed performance changes are committed through `980b748`: standard
name/filesystem caches, runtime bulk CRC32 dispatch, Zstandard sequence decoding,
AArch64 DEFLATE bulk copies, bounded Zstandard sequence bit output, fresh-file
metadata work, bounded LZMA skips/distance prices, and exact short DEFLATE copies.
No compression preset was relaxed; all 48 Rust archive byte streams remain
identical to round 7. No local unsafe code was added. Existing `crc32fast` was
promoted from a development dependency to runtime; its CPU-dispatched backend
has a portable fallback and a little-endian gate. The exact published
`miniz_oxide` 0.9.1 source is vendored with two small local changes.

The fixed six-format, eight-dataset creation/common-C-input extraction matrix
has 96 equally weighted cases, five rotating repetitions, 1,440 timed commands,
720 verified timed extractions, 288 cross-reader checks and 48 byte identities.
Current Rust wins 17, ties 20 and loses 59 against C; prior Rust wins 15, ties 13
and loses 68 in the same run. Wins require over 5% lower median time. The majority
win goal is not met. ZIP extraction improves 13-39%, many-file extraction 13-14%
(rounded), text 7zip creation 17%, and source Zstandard creation 10% versus prior
Rust. No corrected-matrix case has a median regression above 5%; smaller
regressions and compression-size differences from C remain in the report.

An initial matrix exposed output-path allocation/cache timing bias in creation.
A shared-path diagnostic removed the apparent tar/Zstandard regressions. The
same full matrix was rerun using one timed output path for every executable,
with verification copies outside timing. Both complete raw matrices and the
confirmation are retained. No cases were removed or reweighted.

Validation: 390 native tests passed, one opt-in test ignored; strict all-target
Clippy, formatting, no-default-feature Zstandard checks and all 454 ABI symbols
passed. The full upstream/front-end suite passed 926 tests, skipped 184, with
zero failures, crashes, timeouts or ratchet regressions (61 seconds, one worker).
Additional exact-stream/error-state tests and fresh actual Claude Opus 5.5
reviews are retained with each unit. LZMA includes 1,656 exact streams and a
real 2.147 GB normalization crossing. DEFLATE includes 1,760 exact
output/status/consumption traces and 39 unchanged encoder streams.

Report: `../diagnostics/results/REPORT.md`; corrected raw matrix:
`../diagnostics/results/round8-shared-output.json`. Frozen release:
`../diagnostics/bin/rust-round8-final-bsdtar`. The initial matrix is retained
as `round8-final.json`; it is not the final scorecard. Rejected experiments and
remaining leads are isolated in diagnostics, including `round8-next-work.txt`.
Original C and pinned upstream remain clean. No work was pushed.

## Optimization round 9 checkpoint

Three accepted changes: exact wide DEFLATE overlap copies, complete Zstandard
sequence bit windows, and one secure parent-path lookup on ARM macOS with a
cached Darwin 21+ capability gate. Unknown/older kernels and lookup failures
retain the component walker. The two new documented unsafe blocks are in the
uname OS wrapper; codec changes remain safe Rust.

The unchanged 96-case matrix now gives Rust 21 wins, 19 ties and 56 losses.
Prior Rust in the same run gives 16 wins, 22 ties and 58 losses. A win requires
more than 5% lower median time than C. The majority-win goal remains unmet.
Many-file extraction improves 12–15% across all six formats; source/mixed
Zstandard extraction improves 4–5%. All 48 Rust archive streams remain
byte-identical. No compression settings, input datasets or weights changed.

Two short-command medians regressed by 5–6% in the full matrix. A scoped
15-rotation check did not reproduce either regression: text Zstandard
extraction was unchanged and records tar creation improved 5.1%. The original
matrix and score remain unchanged; raw follow-up samples are retained.

Validation: 393 native tests passed, one opt-in test ignored; strict all-target
Clippy, formatting, no-default-feature Zstandard check and all 454 public ABI
symbols passed. The upstream/front-end suite passed 926 tests, skipped 184,
with zero failures, crashes, timeouts or ratchet regressions (64 seconds,
one worker). All 720 timed extractions and 288 cross-reader checks passed.
Fresh actual Claude Opus 5.5 reviews and focused valid/damaged input,
stream-state and filesystem-security checks are retained per accepted unit.

Five trials were rejected as slower or neutral: derived DEFLATE tables,
fused Zstandard decode/copy, contiguous writer match windows, retained writer
hash state and forced match inlining. They remain isolated in diagnostics.
No speculative writer change was merged.

Report: `../diagnostics/results/REPORT.md`; raw results:
`../diagnostics/results/round9-final.json`; validation and confirmation:
`../diagnostics/round9-integration/`. Frozen binary:
`../diagnostics/bin/rust-round9-final-bsdtar`. Code checkpoint: 78fd146.
Original C and pinned upstream remain clean. No work was pushed.

## Performance round 10 checkpoint

Five reviewed optimization units are integrated at `1704441`: bounded BT4
hash-head pipelining, a tagged next-head hint across match-finder calls,
exact 64/32-byte DEFLATE history copies, stable DEFLATE insertion-array
borrows, and medium-sized Zstandard literal/match copies. All codec code
remains safe Rust; no compression settings, encoded bytes or ABI changed.

Focused confirmation shows an 8% source encoder gain from BT4 pipelining.
The additional hint improves random/mixed/compiled encoding by 24/12/5%.
DEFLATE repetitive decoding improves 43% for gzip and 37% for ZIP;
document data improves 3-5%. Zstandard varied-data decoding improves 3-6%.
Stable insertion borrows improve repetitive DEFLATE encoding 5%. These
backend results are separate from complete archive-operation timings.

The unchanged 96-case, five-rotation matrix records 23 wins, 20 ties and
53 losses against C. Prior Rust in the same run records 20 wins, 23 ties
and 53 losses. Majority wins remain unachieved. Complete XZ/7zip creation
improves 25% for random, 12-13% for mixed and about 6% for source data;
repetitive gzip/ZIP extraction improves 11-14%. No full-matrix case is more
than 5% slower than prior Rust. All 48 writer streams remain byte-identical,
all 720 timed extractions and 288 cross-reader checks match manifests.

Measurements and full C/Rust timing, size and RSS tables are in sibling
`diagnostics/results/REPORT.md`; raw data is `round10-final.json` and
combined logs are in `round10-integration/`. The frozen round-nine binaries
are the before baseline. Case weights, compression presets and the common
C-input extraction policy remain unchanged.

Combined verification: 393 native tests pass, one opt-in test ignored;
strict all-target Clippy, formatting, no-default Zstandard and all 454 ABI
symbols pass. All upstream/front-end suites: 926 pass, 184 skip, zero
failures, crashes, timeouts or ratchet regressions, 65 seconds with one worker.
Unit checks include exact damaged-stream traces, level-switch/reset traces,
1,656 frozen LZMA streams in release and assertion-enabled builds, and a real
2.147 GB normalization stream. Fresh actual Claude Opus 5.5 design and final
reviews are retained alongside specialist results.

Mirrored and scaled-interleaved DEFLATE chain tables were rejected for
regressions. Extra Zstandard periodic-copy/repcode branches were removed
because the smaller accepted copy change performed better. Original C and
pinned upstream remain clean. No work was pushed.

## Performance round 11 checkpoint

Four reviewed units are integrated at `a4cd19b`: fixed eight-step LZMA
literal loops, exact short DEFLATE matches inside the fast decoder,
sixteen-byte CRC64 checksum steps, and guarded four-stream Huffman literal
decoding with inline transitions. All codec code remains safe Rust;
compression presets, output bytes and ABI are unchanged. The CRC64
read-only table grows by 16 KiB; other CPU-cache behavior is unmeasured.

Focused in-memory archive checks show XZ text/random/source decoding gains
of 34/29/15% from CRC64; many files improve 13%. Zstandard compiled/records/
source gains are 24/16/8%. Native DEFLATE gains 4-6% on varied data with text
unchanged. Literal-loop LZMA gains are 10% records, 5% documents, 3% mixed;
source/compiled native medians varied and were slightly slower in final
confirmation. These results are separate from full archive operations.

The unchanged 96-case, five-rotation matrix records 24 wins, 25 ties and
47 losses against C. Prior Rust in the same run records 22 wins, 20 ties
and 54 losses. Majority wins remain unachieved. Complete XZ extraction
improves 11-19% for text, random, source and records, and 6% for mixed and
documents. 7zip records improve 8%; Zstandard compiled extraction improves
14%. The equal-weight geometric mean across all 96 Rust times improves 1.7%.
All 48 writer streams remain byte-identical; all 720 timed extractions and
288 cross-reader checks match manifests.

One full-matrix case is more than 5% slower: text gzip extraction (+5.9%).
A scoped 15-rotation confirmation measures a smaller 3.0% slowdown (0.24 ms);
text ZIP is 1.1% slower and random gzip 1.1% faster. This small tradeoff is
documented, with the original table and score preserved.

Full C/Rust timing, size and RSS tables are in sibling
`diagnostics/results/REPORT.md`, raw data in `round11-final.json`, and logs
in `round11-integration/`. Frozen round-ten binaries are the before baseline.
The single-worker full benchmark completed in 349 seconds.

Combined verification: 393 native tests pass, one opt-in test ignored;
strict all-target Clippy, formatting, no-default Zstandard and all 454 ABI
symbols pass. Upstream/front-end suites: 926 pass, 184 skip, zero failures,
crashes, timeouts or ratchet regressions, 69 seconds with one worker.
Unit checks include 14,400 exact XZ/LZMA1 records spanning over 31 million
process calls; 1,760 exact DEFLATE traces and 39 encoder identities; 51
Zstandard vendor tests and 175 ABI records; independent bitwise CRC
references, 48 valid/damaged ABI records and eighteen exact writer runs.
All four units have fresh actual Claude Opus 5.5 final review.

Fixed-tree LZMA inlining and standalone DEFLATE leaf inlining were rejected
for marginal gains. The first short kernel slowed text; the retained simpler
slice structure resolves it. Interleaved Huffman decoding needed explicit
transition inlining to keep lanes independent. One high-effort Opus call
timed out; a narrower consultation succeeded and final reviews passed.

During this round the workspace moved from `port-rs-lib` to
`port-rs-libarchive`. Worktree and generated compile-command paths were
repaired. An interrupted CRC screen was repeated with full raw samples;
source and benchmark artifacts were preserved. Original C and pinned
upstream remain clean. No work was pushed.

### Workspace cleanup (October 11, 2026)

Retired all 45 experimental worktrees after the round-eleven validation
checkpoint `e5315b4`. Only the main Rust checkout remains. All branches
are retained, with a verified all-ref Git bundle, staged/unstaged patches
and local file backups in sibling
`diagnostics/archive/worktrees-2026-10-11/`. Six uncommitted experiments
and seven local lockfiles are recoverable; all six patches apply to their
recorded HEADs. Fifty standalone native harness binaries are archived.

Removed retired worktree caches, standalone Cargo targets, Python bytecode
and the main debug target, reclaiming about 14 GiB. Current release binaries,
the C oracle, benchmark inputs, profiles, independent reviews and reports
remain. All 181 retained evidence fingerprints match; repository connectivity
checks pass. Original C and pinned upstream remain clean. The workspace and
diagnostics guides now identify the current checkpoint and reproduction paths.
No compiler, compatibility test or benchmark was rerun for this cleanup.

## Round 12 checkpoint: an all-Rust distribution

The command-line tools are Rust programs on a new safe Rust API
(`src/api/`): bsdtar, bsdcpio, bsdcat and bsdunzip, each compared with the
relinked C tool, and bsdtar with upstream's own, on created archives,
listings, extracted trees, messages and exit codes. The Rust crate contains
no C; `capi/` builds the C library with the one varargs shim.

Codecs: DEFLATE compression is a port of zlib 1.2.12 (`deflate/`) and
LZMA/XZ compression a port of liblzma 5.8.4, both reproducing C's bytes;
Zstandard compression ports libzstd 1.5.7's level strategies; inflate and
the Zstandard decoder have new hot loops. Fidelity fixes: the disk walker
follows upstream's tree order, stat and metadata errors; a writer sweep
makes 62 of 68 format cases byte-identical to C; restoring a FIFO no longer
hangs. Tools load no C codec libraries. Fuzzing: 29 targets, one bug fixed.

The 96-case matrix (`bench/compare.py`, five rotations, frozen round-8
corpus) records 57 wins, 34 ties and 5 losses against C, and 60/32/4 in a
second run; with `scripts/build-pgo`, 61/31/4. Round 11 in the same run:
24/22/50. Geometric-mean Rust/C time 0.91 (0.90 with PGO). All 288
cross-reader checks pass. Raw data: `diagnostics/results/round12/`.

Verification: 926 upstream and front-end tests pass, 184 skip, none fail;
468 Rust tests pass; strict clippy and formatting pass on macOS and, for
everything but `capi/`, on Linux, where the tests have not been run.

## Round 13 checkpoint: fidelity, safety and the last LZMA gap

A differential run of upstream's 562 test archives through our and
upstream's bsdtar found 20 differences, 19 in the disk writer; all are fixed
but one (a damaged bzip2 stream, documented). A follow-up ported the
writer's remaining paths (symlink checks, what is in the way, metadata order
and messages, deferred fixups). An independent review with a 169-case
malicious-archive suite stopped it once, for metadata applied through a
symlink, descriptor exhaustion and a FIFO hang (the last two already on
main); after the fixes it matches upstream in 154 cases and is stricter in
the rest. Metadata now goes through the verified descriptor.

The LZMA encoder no longer re-compares long repeats, and its output stays
byte-identical to liblzma's: text creation is 0.70x C (was 1.22x). Debug-profile
tests caught a warning raised as a failure in read_disk; CI now tests the
dev profile.

Benchmark: 61/32/3 and 59/34/3 against C in two runs, 63/31/2 with PGO;
geometric-mean Rust/C 0.90. All 336 checks pass, and archives are
byte-identical to round 12's. Raw data: `diagnostics/results/round12/round13-*`.

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
