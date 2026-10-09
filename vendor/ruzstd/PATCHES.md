# Local ruzstd patch

Source: crates.io `ruzstd` 0.9.0, MIT (see LICENSE).
Published crate SHA-256:
`a252f5e20f038fe7b4ea53e073e65398d652c864cc162fc77c56c2f13717b888`.
Repository: https://github.com/KillingSpark/zstd-rs

The manifest retains upstream package/features/dependencies and omits its
examples, benchmarks and development dependencies. Fixture assets are not
vendored. Upstream's existing unsafe ring-buffer implementation is unchanged.
The local patches add no unsafe code. Decoder changes are an inlining hint and
safe growth of overlapping copies, described below; one unsafe call is removed.

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
