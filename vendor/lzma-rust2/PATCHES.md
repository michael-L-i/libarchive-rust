# Local lzma-rust2 patch

Source: crates.io `lzma-rust2` 0.21.0, Apache-2.0 (see LICENSE).
Published crate SHA-256:
`fde178a3caf126c440fa15628147772d8ee590a39477d711353fbe2e58a73a5b`.
Repository: https://github.com/hasenbanck/lzma-rust2/

The source tree is unchanged except for `src/lz/bt4.rs`, `Bt4::skip`.
The manifest retains upstream package/features/dependencies and omits its
examples, benchmarks, development dependencies and documentation metadata.
Tests and fixture assets are not vendored. The root disables default features,
including `optimization`; the enabled implementation remains safe Rust.

`Bt4::skip` previously extended binary-tree matches one byte at a time. It now
calls the existing `extend_match` helper, already used by `find_matches`, which
compares native words in safe Rust. The first byte was already tested equal,
so extension starts at `len + 1` and retains exactly the previous limit and
binary-tree updates. No preset, match depth, dictionary, or parsing policy
changes. Keep this patch until the equivalent change is available upstream.

Validation on Apple Silicon, 2026-10-09:

- 1,440 compressed streams are byte-identical to the unmodified crate: XZ,
  LZMA and LZIP; presets 0 through 9; random, repetitive and mixed data;
  sizes 0, 1, 7, 8, 9, 63, 64, 65, 273, 274, 4095, 4096, 65535, 65536,
  65537, 131100; write chunks 1, 63 or 65536 selected by preset. These
  cases cap the dictionary at 64 KiB to exercise match-finder wraparound.
  Length-prefixed concatenated output is 11,308,770 bytes, SHA-256
  `230abc013cf9f0d83bd9c063b7078deaa357df7e723bfe3c3a93be345a922059`.
- At unchanged default preset 6, all three diagnostic tar corpora produce
  byte-identical XZ output. Six in-process compression runs (opt-level 3)
  give median text 66.303 -> 23.134 ms, random 178.678 -> 172.281 ms,
  small-files 28.076 -> 17.666 ms. Random timings are noisy; do not infer
  a random-data improvement. End-to-end archive measurements are separate.
- The experiment source, outputs and raw timings are retained under the
  sibling `diagnostics/lzma-micro` directory. Project oracle validation is
  performed on the combined integration branch.
