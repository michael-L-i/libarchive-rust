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
