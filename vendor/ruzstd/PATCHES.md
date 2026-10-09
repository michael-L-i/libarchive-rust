# Local ruzstd patch

Source: crates.io `ruzstd` 0.9.0, MIT (see LICENSE).
Published crate SHA-256:
`a252f5e20f038fe7b4ea53e073e65398d652c864cc162fc77c56c2f13717b888`.
Repository: https://github.com/KillingSpark/zstd-rs

The manifest retains upstream package/features/dependencies and omits its
examples, benchmarks and development dependencies. Fixture assets are not
vendored. Decoder sources, including upstream's existing unsafe ring-buffer
implementation, are unchanged. The encoding patch adds no unsafe code.

Before writing Huffman literals, count the exact payload bits for the selected
new or reused table. If the payload alone is at least as large as the raw
literals, skip encoding it: the old encoder would discard that stream after
adding headers, table descriptions, jump tables and padding. This is a
conservative lower bound, not a sampling heuristic; table selection and
compression decisions remain identical. Returning no new table preserves
exactly the old fallback's table-reuse state. The histogram replaces the one
previously computed while building the new table, avoiding a second input scan.

Local changes are confined to `src/encoding/blocks/compressed.rs` and
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
