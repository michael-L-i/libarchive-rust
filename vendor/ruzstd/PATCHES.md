# Local ruzstd patch

Source: crates.io `ruzstd` 0.9.0, MIT (see LICENSE).
Published crate SHA-256:
`a252f5e20f038fe7b4ea53e073e65398d652c864cc162fc77c56c2f13717b888`.
Repository: https://github.com/KillingSpark/zstd-rs

The manifest retains upstream package/features/dependencies and omits its
examples, benchmarks and development dependencies. Fixture assets are not
vendored. The ring buffer's existing unsafe memory accesses are unchanged. The local
patches add no unsafe code. Decoder changes include inlining, safe growth of
overlapping copies and bounded ring-index arithmetic, described below; one
unsafe call is removed.

Before writing Huffman literals, count the exact payload bits for the selected
new or reused table. If the payload alone is at least as large as the raw
literals, skip encoding it: the old encoder would discard that stream after
adding headers, table descriptions, jump tables and padding. This is a
conservative lower bound, not a sampling heuristic; table selection and
compression decisions remain identical. Returning no new table preserves
exactly the old fallback's table-reuse state. The histogram replaces the one
previously computed while building the new table, avoiding a second input scan.

The literal-size changes are confined to `src/encoding/blocks/compressed.rs` and
`src/huff0/huff0_encoder.rs`. Compression levels and the archive matcher's
leading-literal and maximum-match-length workarounds are unchanged.

Validation on Apple Silicon, 2026-10-09:

- Five 16 MiB inputs (random, source, mixed, periodic and repeated binary)
  produce byte-identical output versus the unmodified registry crate.
  All 80 MiB decode successfully with both ruzstd and independent C zstd.
- Another 528 cases vary alphabet sizes 1, 2, 7, 16, 63, 127, 255, 256;
  input lengths from empty through 524289, including block/length edges;
  and 16, 96, 128 KiB blocks. All match the registry output byte for byte
  and decode to the original input.
- Nine alternating in-process release runs yield median milliseconds:
  random 41.024 -> 13.031; source 80.365 -> 80.175; mixed 63.609 -> 48.119;
  periodic 2.773 -> 2.694; repeated binary 3.022 -> 2.745. Small differences
  should be treated as noise. No ratio or compression-level tradeoff.
- Sampling attributes most baseline random-input CPU to literal encoding
  that is discarded afterward. Source remains dominated by matching and
  FSE sequence encoding. Project integration checks run on the combined
  branch; the standalone experiment and profiles are retained in sibling
  `diagnostics/round4-zstd`.

## Direct FSE encoder state lookup

`src/fse/fse_encoder.rs` replaces the per-symbol estimated-position linear
search with an exact range calculation. For a normalized symbol frequency,
the builder creates short power-of-two spans followed by spans twice as long,
then sorts them by baseline. In short-span units, the total covered range is
`table_size >> shortest_bits`; subtracting it from twice the state count gives
the number of short states. Indexing the short prefix and halving positions
in the doubled suffix selects the same state without a search or division.
No table layout, probability, public structure or encoded bit changes.

- Exhaustive tests compare with the previous linear search for every state
  index at every normalized frequency for accuracy logs 5 through 10,
  including zero-bit spans, low-probability (-1) entries, absent symbols,
  and the default literal-length, match-length and offset tables.
- All 15 standalone FSE/bit-writer unit tests pass with optimization and debug
  assertions enabled. The wrapper in `diagnostics/round4-zstd/fse-tests.rs`
  allows running these self-contained tests without upstream's omitted
  corpus fixtures and C-codec test dependency.
- The same 533 corpus cases remain byte-identical to registry ruzstd, and C
  zstd again decodes all five 16 MiB outputs. Nine alternating release-run
  medians versus registry, with both patches: random 41.086 -> 13.143 ms,
  source 79.961 -> 62.725, mixed 62.699 -> 39.255, periodic 2.738 -> 2.762,
  repeated binary 2.849 -> 2.802. Relative to the literal-only patch, this
  targets the previously sampled source/mixed FSE cost; tiny differences
  on other workloads are noise.

## Inline FSE decoder updates

`src/fse/fse_decoder.rs` marks the small `FSEDecoder::update_state` method
`#[inline]`. Its arithmetic, bounds checks and state transitions are unchanged.
This lets optimized callers keep decoder and bit-reader state across the three
updates made for each sequence, without introducing new decoding logic.

- Profiling source-data decoding identified this call as a substantial cost.
- Seven rotating in-memory decode medians on identical C-produced archives:
  16 MiB source 26.06 -> 23.62 ms; mixed 13.94 -> 12.78 ms. Other measured
  text, random and small-file cases are essentially unchanged.
- 125 valid, truncated and mutated inputs match baseline status, errno,
  error text, header count, decoded length and output SHA-256 exactly.
- The harness, samples and profile are in sibling
  `diagnostics/round4-zstd-read`. Final archive measurements and the full
  compatibility suite use the combined integration build.

## Expand overlapping matches through the initialized prefix

`src/decoding/decode_buffer.rs` previously expanded a match in chunks no larger
than its distance, copying one byte per iteration at distance one. It now keeps
the logical source start fixed and copies the available initialized prefix,
doubling the next chunk until the final partial copy. This uses the existing
safe ring-buffer API and removes the helper's unsafe block. The whole match is
still reserved once before copying; window rules, allocation requirements,
error handling and decoded bytes are unchanged. No extra buffer is allocated.

- A profile of a held-out Rust-produced zero-heavy archive attributed about
  80% of decode time to repeated ring-buffer copies. Same-archive in-memory
  decode medians improve 19.46 -> 0.94 ms; C-produced data with the same
  contents improves 1.84 -> 0.96 ms. The optimization uses only match length
  and distance, not byte values or dataset recognition.
- Five tests of the actual ring/decode-buffer modules pass in the standalone
  `diagnostics/round4-zstd-read/buffer-tests.rs` harness. The new reference
  test covers 768 cases: distances 1 through 64, three lengths including
  128 KiB, and four drained-prefix positions exercising source/destination
  wrapping and capacity growth. Other existing module tests also pass.
- 175 valid, truncated and mutated archive cases match prior status, errno,
  error message, header count, output length and SHA-256 exactly. This includes
  both C- and Rust-produced held-out zero-heavy archives.
- Raw results and the profile are in sibling `diagnostics/round4-zstd-read`.
  The published crate omits assets/dev dependencies used by its full vendor
  suite; the standalone harness tests the real modules without replacing the
  algorithm. Full project oracle validation uses the combined final build.

## Bound the archive matcher's hash load once

The archive integration's `src/write/filter/zstd.rs` now loads the hash word
through `first_chunk::<8>()` instead of eight separately indexed bytes. All
callers already require eight available bytes. This makes the bounds check
explicit once and exposes one little-endian word load to the optimizer. The
five-byte hash, probe order, match lengths, compression settings and bytes
are unchanged. No vendor codec algorithm changes or unsafe code are needed.

- A fresh profile of the accepted c1dc8b7 baseline attributes about 55% of
  source encoding CPU to matching, including out-of-line hash loads.
- Nine alternating release-run medians on 16 MiB inputs, in milliseconds:
  random 13.01 -> 11.39, source 68.01 -> 58.71, mixed 40.34 -> 36.97,
  periodic 2.71 -> 2.70, repeated binary 2.83 -> 2.88. Tiny differences
  on the latter cases are noise. A plain inline hint was measured first
  and rejected because it did not improve performance.
- All 545 inputs match the frozen accepted baseline byte for byte and
  decode with ruzstd: five 16 MiB workloads, 528 length/alphabet/block
  cases, and 12 compaction/RLE/history cases exceeding 2 MiB. Independent
  C zstd validates all five 16 MiB streams. The new harness and profiles
  are in sibling `diagnostics/round5-zstd`; prior artifacts are unchanged.

## Store matcher positions relative to retained history

The archive matcher's table now stores buffer-relative `u32` positions plus
one, instead of absolute `u64` stream positions. The history buffer is bounded
by two 1 MiB windows plus a block of at most 128 KiB. When history compacts,
saturating subtraction rebases all table entries and expires discarded
positions to the existing zero sentinel. Matching still rejects positions
beyond the 1 MiB distance limit. This halves the table from 512 to 256 KiB
and removes the absolute-base arithmetic and overflow reset branch.

- Nine alternating release-run medians versus the chunk-load-only matcher,
  in milliseconds: random 11.23 -> 11.01, source 58.38 -> 55.80,
  mixed 35.19 -> 34.07, periodic 2.73 -> 2.54, repeated binary 2.74 -> 2.54.
  Against the original accepted baseline the combined changes improve
  source 65.14 -> 55.78 and mixed 43.30 -> 37.82 in a separate paired run.
- All 545 corpus and boundary inputs remain byte-identical both to the
  chunk-load-only matcher and the frozen original baseline. This includes
  repeated history across multiple compactions and skipped RLE blocks.
  Independent C zstd validates all five large streams.
- Five existing matcher/Huffman-state tests pass in an isolated harness
  using the real matcher source, including reset, expiry, overlap and
  skipped RLE blocks. Full archive integration checks use the combined
  branch. No compression settings or match-selection rules change.

## Bound ring-buffer tail wrapping to one subtraction

`src/decoding/ringbuffer.rs` replaces the runtime remainder when advancing the
append tail in `extend` and `extend_from_within_unchecked`. Both operations
already reserve (or require) enough space for the entire append, including the
unused sentinel byte. Thus the append length and old tail are each strictly
less than capacity, and their sum wraps at most once. A conditional subtraction
produces the same tail without integer division. Existing memory accesses,
allocation, window and error handling are unchanged; no unsafe code is added.

- A fresh source-data decode profile identified ring-buffer match appends as
  a substantial part of sequence execution. A seven-run alternating ABI
  comparison improved 16 MiB source 23.364 -> 22.944 ms and mixed data
  12.582 -> 12.405 ms. A separate 21-run confirmation yielded
  23.188 -> 22.646 ms and 12.469 -> 12.195 ms respectively (about 2%).
  Text, random, small-file and two sparse cases were essentially unchanged.
- All seven inputs have matching output SHA-256 with both the baseline and
  independent C libarchive. All 175 valid, truncated and mutated archives
  match baseline status, errno, error text, headers, length and SHA-256.
- Six tests of the actual ring/decode-buffer modules pass with debug
  assertions, including 768 overlap, wrap and growth reference cases, plus
  append tests immediately before, at and after the tail wrap boundary.
- Profiles, ABI comparisons, rejected bit-reader/FSE batching trials and the
  standalone actual-module tests are in sibling `diagnostics/round5-zstd-read`.
  Final integration validation runs on the combined branch.

## Inline match repetition into sequence execution

`src/decoding/decode_buffer.rs` marks `DecodeBuffer::repeat` with `#[inline]`.
A fresh profile attributes substantial source-data decoding time to calls from
sequence execution into this helper. Inlining lets the caller retain buffer
state across the per-match checks; the dictionary fallback stays cold. All
arithmetic, allocation, copying, bounds, window and error handling are unchanged.

- Seven alternating ABI runs improved 16 MiB source 23.092 -> 22.600 ms and
  mixed 12.530 -> 12.064 ms. A separate 21-run confirmation yielded
  22.967 -> 22.445 ms and 12.347 -> 12.034 ms (about 2.3-2.5%). Text, random,
  small-file and two sparse cases were essentially unchanged.
- All seven outputs match the baseline and independent C libarchive by
  SHA-256. All 175 valid, truncated and mutated archives match baseline
  status, errno, error text, header count, output length and SHA-256.
- All six actual-module buffer tests pass with debug assertions, including
  wrap boundaries and 768 overlap/growth reference cases.
- Profiles, timings and the rejected packed length-code lookup experiment
  are retained in sibling `diagnostics/round6-zstd-read`. Final integration
  validation runs on the combined branch.

## Batch the three sequence-state fields into one write

`src/encoding/blocks/compressed.rs` computes the independent offset,
match-length and literal-length FSE transitions before writing their bits.
Their table accuracy logs bound the combined fields to 8 + 9 + 9 bits, so
one `u64` carries all three in the original low-bit-first order. This replaces
three bit-writer buffer/flush checks with one. Extra bits, table construction,
state transitions, match choices, compression settings and output are unchanged.

- A fresh a0fbedb source profile still identifies sequence encoding and the
  bit writer's cold flush path as substantial costs after matcher improvements.
- Nine alternating release-run medians on 16 MiB inputs, milliseconds:
  source 55.50 -> 51.77, mixed 34.21 -> 32.56; random, periodic and repeated
  binary are essentially unchanged. A second nine-run confirmation gives
  source 55.11 -> 52.03 and mixed 34.29 -> 32.77 (about 6% and 4.5%).
- All 545 corpus, alphabet, block-boundary, compaction and RLE-history cases
  remain byte-identical to the frozen a0fbedb baseline and decode with ruzstd.
  Independent C zstd validates all five 16 MiB streams. All 15 standalone
  FSE/bit-writer tests pass with optimization and debug assertions enabled.
- Raw profiles and measurements are in sibling `diagnostics/round6-zstd`.
  A separate matcher slice-bounding trial regressed mixed data and was
  discarded. Full integration validation runs on the combined branch.

## Predecode sequence length FSE states

`src/decoding/sequence_section_decoder.rs` resolves literal/match length codes
into their base lengths and extra-bit widths once per decoded block. Each
8-byte derived state also keeps the original FSE transition base and bit count,
removing the dependent symbol-to-length lookup from the per-sequence loop.
Offsets, bit-reader calls and error checks keep their original order. The RLE
loop is specialized at compile time for small non-RLE batches, avoiding derived
tables when the sequence count is below the combined table entry count.

Two vectors in `FSEScratch` retain capacity between blocks. Derived states are
rebuilt after the original LL/OF/ML initialization, so dictionary copies, table
reuse and frame resets cannot leave a stale derived table. Raw and dictionary
length tables enforce accuracy logs at most 9 and maximum symbols 35/52 before
building entries; predefined tables use log 6. Consequently every entry's code
has a valid length mapping, and every transition base is below 512 and fits
exactly in `u16`. The added table storage is at most 8 KiB per decoder, plus two
vector headers; small/RLE paths do not allocate derived tables.

- Authenticated Claude Opus 5.5 independently proposed this state-table design
  and analyzed its dependency-chain benefit. Design prompts and actual model
  usage are retained in sibling `diagnostics/round7-zstd-read`. A fresh
  Claude Opus 5.5 review of the final code returned PASS with no defects.
- Twenty-one rotating in-memory ABI runs: 16 MiB source 21.952 -> 21.528 ms,
  mixed 11.922 -> 11.742 ms (about 2% and 1.5%); small files
  0.41929 -> 0.41933 ms. Other four inputs are essentially unchanged.
- Another 84 short inputs span 0 through 128 KiB, four alphabet sizes, and
  C zstd levels 1/3/9. All output hashes match the baseline and independent
  C libarchive. Nine rotating batch medians are 7.229 -> 7.175 ms.
- All 175 valid, truncated and mutated archive cases retain exact status,
  errno, error text, header count, output length and SHA-256. The initial
  unspecialized small-batch fallback was slower and was discarded.
- Raw samples, timing records, ABI checks and the focused Opus review are in
  `diagnostics/round7-zstd-read`; full oracle validation uses the combined
  integration build.

## Share a push encoder with the pull frame compressor

`src/encoding/frame_compressor.rs` exposes `StreamCompressor` and uses the same
block/frame implementation from `FrameCompressor`. Callers can fill blocks
incrementally and receive encoded bytes through a fallible callback. The archive
writer uses this path for default framing, removing its worker thread, channels
and queued input/output copies. Explicit framing options retain the existing
worker and its output-count timing. Matching, compression levels, block sizes,
checksum writes and full-block empty terminators are unchanged.

- Claude Opus 5.5 designed and authored the shared streaming core. A fresh
  independent Opus review passed; the root bridge and independent validation
  were implemented locally. Prompts and raw model responses are retained in
  sibling `diagnostics/round7-zstd`, including an unsuccessful tool-use review
  attempt and the corrected final review.
- All 545 frozen fafa7a5 baseline corpus/boundary/history comparisons remain
  byte-identical for both pull and push, plus 105 push fragmentation cases.
  Thirteen filter tests pass, covering reset/reuse, first-block and checksum
  emit errors, original sink panic payload, custom-matcher Uncompressed output,
  direct/threaded equivalence at levels 1/3/9 and legacy framing. Clippy passes
  with warnings denied; the vendored no-default-features build also passes.
  Standalone vendor tests require omitted upstream fixtures and C test support,
  so validation uses the root and isolated baseline harness instead.
- Five alternating archive pairs give medians in milliseconds: source
  64.04 -> 59.98, mixed 43.60 -> 41.24, text 10.18 -> 9.38, random
  21.11 -> 20.93, small-files 11.29 -> 11.21. All archive bytes match.
  Median peak RSS falls by about 0.30-0.53 MiB across these inputs. Recorded
  CPU times have 10 ms precision and do not resolve the small differences.
- Earlier seven-pair screens experienced unexplained timing inflation; all
  their raw results remain available as `archive-screen-slow.*` and
  `archive-screen.*`, alongside the stable `archive-confirm.*` confirmation.
  Packed and split prefix-table matcher trials were rejected because repeated
  inputs regressed. No matcher changes from those trials are included.

## Stage decoded blocks and guard the sequence bitstream fast region

Larger sequence batches execute into a reusable, initialized 128 KiB + 16 byte
buffer, reading previous output through the ring's immutable history slices.
The block is appended to the ring once, replacing per-match reserve/wrap work.
Explicit constant-size copies handle short literals and nonoverlapping matches;
overlapping matches retain geometric copying. Small batches keep the previous
executor. Dictionary references, invalid lengths/offsets and oversized blocks
replay the unchanged executor before any history or offset state is committed,
preserving error precedence and partial output. Speculative extra bytes remain
inside initialized scratch and are never included in committed output.

The derived-state sequence decoder uses an inline bit-reader path only while
at least 32 source bytes remain. A sequence needs at most three eight-byte
refills; extra values consume at most 31 + 16 + 16 bits and FSE transitions at
most 9 + 9 + 8 bits. The original reader handles the tail and final sequence,
including exhaustion and extra-bit checks. Offset codes are still checked before
reading extra bits; a checked code at most 31 yields an offset in 1..=u32::MAX.
No new unsafe code, dependencies, checksums or compression behavior are involved.

- Actual Claude Opus 5.5 proposed both structural changes and independently
  reviewed the production diff with PASS. Prompts, results and actual model
  usage are retained in sibling `diagnostics/round8-read`.
- Twenty-one rotating confirmation runs on identical C archives:
  source 21.539 -> 20.495 ms, mixed 11.609 -> 11.154 ms,
  compiled 10.710 -> 9.332 ms, records 6.017 -> 5.622 ms,
  telemetry 9.773 -> 8.108 ms. Sparse C input regresses about 2% (19 us);
  other smaller workloads fluctuate around baseline;
  no claim of C parity is made. The block-only intermediate improves compiled
  and telemetry about 11%; both isolated stages and the unsuccessful first
  block-copy formulation remain recorded.
- All 175 valid/truncated/mutated ABI records retain identical status, errno,
  error text, header count, length and SHA-256. All 11 screening corpus output
  hashes also match independent C libarchive.
- Forty-five self-contained vendor tests pass with debug assertions and
  overflow checks enabled. New checks compare 5,976 sequence decodes against
  the general decoder, 24,768 reader groups across the guarded/tail boundary,
  256 generated sequence blocks with wrapped history and repeat offsets, and
  50 malformed/dictionary/oversized fallback cases including partial state.
  Existing omitted-fixture and C-zstd-dependent tests are excluded only in
  the diagnostic copied-source harness; production sources remain intact.

Root all-target and vendor Clippy pass with warnings denied, as do the vendor
no-default-features build, rustfmt and diff checks. A second fresh final Opus
review returned PASS; broader archive/oracle validation uses the integration build.

## Round 8: bounded sequence bit output

Sequence encoding batches the existing ordered bit fields into two bounded
accumulator writes per sequence. It writes into initialized, checked storage
with eight-byte stores and truncates the final padding. Table logs bound each
accumulator to fewer than 64 bits. The original writer remains the fallback
for misalignment and custom matchers reaching the existing code-52 defect;
compressed bytes, match selection, table selection and compression levels stay
unchanged. No unsafe code is added.

Actual Claude Opus 5.5 supplied the design and independently approved the final
implementation after a review found the need to preserve the legacy fallback.
Artifacts are retained in sibling `diagnostics/round8-encoder`. Validation:
256 sequence-field comparisons (including maximal table logs, extra bits,
markers and legacy fallback), 650 frozen encoder/fragmentation comparisons,
seven archive corpora with exact bytes, and strict root/vendor Clippy.
Two seven-pair archive screens agree on improvements. Confirmation medians
(before -> after, ms): source 60.37 -> 55.67, mixed 41.54 -> 39.18, compiled
20.87 -> 19.78, records 18.69 -> 18.08, text 9.36 -> 8.99. Random is 21.42 ->
21.63 and documents 9.22 -> 9.02. Full integration results belong in STATUS.md.

## Complete sequence bit windows

For a guarded sequence whose six extra/state fields total at most 56 bits,
read a single window and split it into independent fields before the three
FSE transitions. Wider sequences retain the prior refill path; final
sequences and input tails retain the general reader. The existing 32-byte
guard bounds every refill, and bit order, final-state rules and error
precedence are unchanged. No new allocation, unsafe code or format changes.

Fresh actual Claude Opus 5.5 final review: PASS, with pending checks now
complete. All 47 self-contained vendor tests pass with debug assertions
and overflow checks. New field tests compare six values, remaining bits
and subsequent tail reads against the scalar reader; existing generated
state/error comparisons exercise both wide branches. All 175 damaged/valid
ABI records retain exact status, errno, messages and decoded hashes. Strict
release all-target Clippy passes.

Twenty-one rotating same-C-input confirmations show raw decoding gains of
7.5% source, 7.1% mixed, 5.5% records and 4.2% compiled data; remaining
cases range from 0.7% slower to 2% faster. All eight decoded hashes agree
with C. These are backend timings, not complete archive extraction.
Evidence, prompts and raw samples: sibling diagnostics/round9-zstd.

## Medium sequence copies

Extend the staged executor's fixed 16-byte copy path to literal and match
runs of at most 64 bytes. Literal reads require enough real source slack;
match chunks require a distance of at least 16 bytes. The existing staging
padding absorbs at most 15 extra written bytes, which are overwritten or
excluded from the committed output. Long runs, short offsets, repeat-offset
resolution, dictionary fallback and error/partial-state behavior are unchanged.
No new allocation, unsafe code or public API changes.

Actual Claude Opus 5.5 designed the initial candidate and independently
reviewed the final trimmed diff: PASS. Separate rotating measurements rejected
its additional periodic-offset kernel and repeat-offset rewrite; the small
medium-copy subset retained the gains. All 49 self-contained vendor tests
pass with debug assertions and overflow checks, including new copy/slack
boundaries, history-to-staging crossings and terminal 131072/131073-byte
blocks compared with the general executor. All 175 valid/damaged ABI records
retain exact status, errno, messages and output hashes. Release all-target
Clippy with warnings denied and formatting checks pass.

Twenty-one rotating same-C-input raw-decode confirmations show improvements
of 6.2% source, 6.1% mixed, 4.5% compiled and 3.0% records; the remaining four
cases range from 1.6% slower to 0.9% faster. All eight decoded hashes match C.
These timings exclude filesystem extraction. Prompts, actual model usage,
rejected variants, raw samples and validation logs: sibling
diagnostics/round10-zstd.

## Interleaved Huffman literal streams

Decode canonical four-stream Huffman literals in parallel lanes, with inlined
state transitions so independent table lookups can overlap. The guarded path
uses initialized, disjoint output slices and validates each lane's terminal
bit count. Empty initial output, bounded stream/output sizes and a consistent
Huffman table are required. Any mismatch clears the speculative output and
runs the original serial decoder, preserving malformed-input error precedence,
partial output and public scratch state. Noncanonical accepted streams retain
the serial behavior, at the cost of bounded speculative work. No new unsafe
code, dependencies or public API changes.

Actual Claude Opus 5.5 supplied the lane design and independently reviewed the
final implementation: PASS with minor nits. The suggested div_ceil cleanup is
applied. All 51 self-contained vendor tests pass with debug assertions and
overflow checks, including serial comparisons of valid, truncated, mutated,
noncanonical and prepopulated literal targets, exact errors, bytes and capacity.
All 175 valid/damaged ABI records match. Strict root release all-target Clippy,
standalone vendor Clippy and formatting checks pass.

Twenty-one rotating before/after/C runs on the same eight C archives show raw
in-memory decoding gains of 24.2% compiled, 15.5% records and 7.5% source;
remaining cases range from 0.4% slower to 2.3% faster. All decoded hashes match C.
These timings exclude filesystem extraction. The frozen unit binary predates
only the equivalent bounded div_ceil syntax cleanup; final-source vendor tests
and Clippy passed afterward. The combined integration rebuild and matrix use
the final source. Evidence, actual model usage, initial timeout, profiles,
attribution runs and raw validation logs: sibling diagnostics/round11-zstd.

## Round 12: reserve the decode window when a frame starts

Only `DecodeBuffer::reset` reserved the window, and a decoder's first frame is
built by `new`, so its ring grew from 128 KiB by power-of-two doubling to 4 MiB
for a 2 MiB window, copying at every step. Both now reserve exactly the window
plus one block (`RingBuffer::reserve_exact`): collecting keeps at most a
window, and a block adds at most 128 KiB, so the ring no longer grows while a
caller collects after each block. Bytes, errors and partial output are
unchanged: 2256 valid, truncated, bit-flipped and overwritten archive cases
match the baseline through the ABI (sibling `diagnostics/round12-zstd-dec`).
`bsdtar -xOf` of the eight common C tar.zst archives touches about 340 fewer
pages (~940 to ~600 page reclaims) and peak RSS falls from ~11.7 to ~6.4 MiB.

## Round 12: decode sequences straight into the window

The decoder's output buffer (`decode_buffer.rs`) is now a ring of blocks over
a safe `Vec<u8>`, replacing `ringbuffer.rs` and its unsafe code. It is sized
once per frame, from the window: the window, one block of collectable output
and two blocks of room (`ZSTD_decodingBufferSize_min` plus one block), and is
touched lazily, so a small stream touches only what it decodes. Each block is
decoded into contiguous memory followed by 64 bytes of slack; when the next
block does not fit before the end, decoding continues at the start, and the
data is two segments, as libzstd's prefix and `extDict`. Callers that let more
than a window plus a block accumulate make it grow, copying once.

Sequences are decoded and executed in one loop, after
`ZSTD_decompressSequences_body`: no `Vec<Sequence>`, no staging block, no
second pass. Per-mode tables pack each state's value base, extra bits and FSE
transition into 8 bytes (`ZSTD_seqSymbol`); they are rebuilt only when a mode
changes them, RLE modes are one-entry tables, and states are masked to the
table size. The bit reader, states and repeat offsets stay in registers: the
stream start and the tail reader take and return them by value. A sequence
refills once, and once more only when its extra bits exceed 30. Literal and
match copies move 16-byte chunks, then 64-byte steps, into the slack; matches
closer than 16 bytes spread their period over a chunk first. A match reaching
past the segment continues in the older one or the dictionary, out of line.

Behavior, for libarchive's callers, which collect after each block:

- Output bytes, offsets accepted, error classes and partial output are
  unchanged, with one exception: a block that decompresses to more than
  128 KiB (literals or sequences) now fails as corrupt. ruzstd accepted it and
  grew its buffer without bound; the format forbids it and libzstd rejects it.
- Matches may reach back the window from a block's start, plus the block, as
  before; for callers that collect later the reach is now capped at the
  window instead of everything uncollected. Only invalid offsets differ.
- An error leaves the block's output and the offsets uncommitted.
- The checksum is hashed as each block is decoded instead of as it is
  collected; it is read only after everything is collected, so it is equal.

Validation: 2256 valid, truncated, bit-flipped and overwritten archive cases
through the ABI match the baseline except 8 whose blocks exceed 128 KiB (all
`BlockTooLarge`; libzstd rejects them as well). 49 self-contained vendor tests
pass with debug assertions and overflow checks, including chunked copies
against byte-at-a-time LZ77, joins of the older segment and the dictionary,
repeat offsets, and ring wrapping without growth. Upstream zstd, zip and 7zip
tests and `diff-cat` agree. Evidence: sibling `diagnostics/round12-zstd-dec`.

## Round 12: collect whole blocks in place

`FrameDecoder::collect_in_place` drains collectable bytes without copying
when they are contiguous in the window and returns where they lie;
`FrameDecoder::collected` reads them until the next block is decoded. The
archive filter decodes until a whole 128 KiB output block is collectable and
hands out that slice of the window, copying only a frame's last partial block
or one that straddles the ring's wrap. Output blocks, their boundaries, input
consumption, error precedence and partial output are unchanged: all 2256
archive cases match the previous commit, including a digest of every block's
offset and size. Because the window caps match history, decoding up to a
block ahead of collection accepts exactly the same offsets.

## Round 12: decode Huffman literals a word at a time

The four-stream fast path now starts with libzstd's
`HUF_decompress4X1_usingDTable_internal_fast_c_loop`: each lane keeps its
next bits on top of a word with a sentinel bit below them, looks up the top
11 bits in a table expanded to 2048 entries, and reloads a whole word after
five symbols (at most 55 bits; a reloaded word holds 56). Lanes run while
every word starts at least 7 bytes into its stream, then hand their exact
reader position to the existing per-symbol lanes, which decode the rest and
make the serial decoder's terminal checks. A lane whose stream is shorter
than 8 bytes or whose padding takes more than a byte skips the word loop.
Output, errors and the serial fallback are unchanged: the vendor tests that
compare the fast path with the serial decoder on valid, truncated, mutated
and irregular streams pass, and all 2256 archive cases match the previous
commit. On the compiled corpus (1.36 M Huffman literals) in-process decoding
fell from 117 M to 77 M instructions.

## Round 12: build FSE decoding tables without divisions

`FSETable::build_decoding_table` numbered each symbol's states with a
power-of-two slice computation that divided per table entry. It now uses
`ZSTD_buildFSETable`'s formula: a symbol of probability p numbers its states
p, p+1, ... in table order, and state n reads `log + 1 - highbit(n)` bits from
`(n << bits) - size`. An exhaustive test compares both formulas for every
accuracy log up to 9, probability and state. Predefined distributions are no
longer copied into new vectors per block. All 2256 archive cases match.

## Round 12: port of libzstd 1.5.7's compressor

The encoder in `src/encoding/` is replaced by a safe port of libzstd 1.5.7's
compressor, as used for streams of unknown size:

- `params.rs`: `ZSTD_defaultCParameters` row 0 (sources over 256 KiB or of
  unknown size) and negative-level acceleration. Levels 13-22 keep their
  window, hash and search parameters but use lazy2: the binary-tree and
  optimal parsers are not ported.
- `fast.rs`, `double_fast.rs`, `lazy.rs`: `ZSTD_compressBlock_fast`,
  `_doubleFast` and `_lazy_generic` (greedy, lazy, lazy2 with the row match
  finder and libzstd's hash salt) for a contiguous window.
- `fse.rs`, `huf.rs`, `literals.rs`, `sequences.rs`: histograms, FSE
  normalization, table descriptions and encoding, Huffman tree building with
  libzstd's sort and height limit, table reuse and validation, raw and RLE
  literals, `ZSTD_selectEncodingType` (predefined, RLE, repeat or new FSE
  tables) and the sequence bit stream.
- `pre_split.rs`: `ZSTD_optimalBlockSize` / `ZSTD_splitBlock`.
- `frame_compressor.rs`: the streaming frame layer: 128 KiB blocks (or the
  window, if smaller), `ZSTD_compressBlock_internal`'s raw and RLE fallbacks,
  index overflow correction past 3500 MiB, the frame header and checksum.

Repeat codes are assigned while entropy coding from the decoder's exact
repeat-offset history, so a match finder's own bookkeeping can never yield
a wrong offset. Entropy tables and repeat offsets are committed only when a
compressed block is emitted, as in libzstd; raw and RLE blocks leave both as
the decoder has them. This resolves two defects of the old encoder: it
replaced its Huffman table even when the frame layer then stored the block
raw, so a later block could reuse a table the decoder never saw, and it
encoded match length code 52 with the wrong baseline (its matcher split
matches at 65538 bytes to avoid it). Neither workaround remains.

Public API: `CompressionLevel::Default`, `Better` and `Best` now work (levels
3, 7, 11) and `CompressionLevel::Level(i32)` takes any zstd level.
`StreamCompressor`/`FrameCompressor` no longer take a `Matcher`, and
`set_window_log` overrides the window like `ZSTD_c_windowLog`. The `Matcher`
trait, `Sequence` and `MatchGeneratorDriver` are removed. The old
`fse_encoder`, `huff0_encoder` and `BitWriter` remain only for the decoder's
round-trip tests and `fuzz_exports`; helpers only the old block encoder used
are deleted. The sections above about the old encoder (literal size checks,
direct FSE state lookup, the archive matcher, batched and bounded sequence
bits) no longer apply; the push `StreamCompressor` API is kept.

No unsafe code is added. Validation (2026-10-11): `zstd -d` (libzstd 1.5.7)
and ruzstd decode every level from -5 to 22 and -131072 on two inputs, 528
edge cases (sizes 0 through 393221 around block boundaries, zeros, random,
periodic and text data at levels -3, 1, 3, 5, 6 and 8), and window logs 10,
12, 17 and 23, byte for byte. A 4.5 GiB stream exercises overflow correction
(opt-in root test). Sizes at level 3 on the eight benchmark tars are within
-0.72% to 0% of libzstd's streaming output (text and random are equal).
Evidence: sibling `diagnostics/round12-zstd-enc`.

## Round 13: compressor speed

Speed-only changes to the compressor port; the output stays the same byte
for byte. Every commit reproduces the SHA-256 of the output for the eight
benchmark tars and 49 edge inputs (empty, 1 to 4096 bytes, 128 KiB +-1 to
384 KiB around block boundaries, zeros, random, periodic and mixed data) at
levels -5, 1, 2, 3, 4, 5, 9, 12 and 19, plus window logs 10 and 17 and
777-byte writes, in release builds with and without debug assertions.
Instruction counts are per compression of the benchmark tars in
10240-byte writes, as libarchive writes (`/usr/bin/time -l`).

- `count()` compares 8 bytes at a time through `chunks_exact`, so its
  loop has no bounds checks: -3% instructions at level 1, -1% at level 5.
