# Local miniz_oxide patch

Vendored from the published miniz_oxide 0.9.1 crate, upstream revision
`4e582392df3a739d2b0dfd2c537dc33e8942be38` (repository path `miniz_oxide`).
Original crate SHA-256:
`b63fbc4a50860e98e7b2aa7804ded1db5cbc3aff9193adaff57a6931bf7c4b4c`.
All package files match the published crate except `src/inflate/core.rs` and
this note; packaging metadata and the library's standalone lockfile are omitted.
The existing version, features, dependencies and license files are preserved.

## Enable existing bulk match copies on AArch64

`apply_match` previously sent every non-x86 target through four-byte copying,
based on an old ARMv7 performance observation. AArch64 now uses the existing
safe x86 path: contiguous, nonoverlapping matches use `copy_from_slice`;
overlapping or wrapping matches retain `transfer`. Both callers retain their
original distance and output bounds checks. The crate still forbids unsafe
code. Other targets, decompression state, error handling, checksum handling,
compression settings and encoded bytes are unchanged. No buffers are added.

- Actual authenticated Claude Opus 5.5 reviewed the design and a fresh final
  diff. Final review returned PASS after inspecting both caller guards and
  overlap/wrap proofs. Prompts, results and model usage are retained under
  sibling `diagnostics/round8-miniz`.
- Twenty-one rotating in-memory ABI confirmation runs use identical C-produced
  archives. Gzip source improves 26.563 -> 25.103 ms (5.5%), records 4.5%,
  mixed 3.5%, many files 9.4%, and compiled 2.2%. ZIP source improves 3.2%,
  mixed 2.1% and records 1.3%; other ZIP cases range from 0.9% slower to 0.8%
  faster. The earlier thirteen-run screen is also retained; it showed larger
  gains. No claim of C parity is made.
- All 16 archive output hashes match baseline Rust and independent C.
  Thirty vendor tests pass, including byte-by-byte reference comparisons for
  both bulk and scalar matches with wrapping/nonwrapping buffers, overlaps,
  initial-history reads and boundary lengths. Another 1,760 bounded streaming
  and core comparisons preserve exact output, consumed/written counts and
  status traces for valid, truncated and mutated streams across four input/
  output fragment sizes. All 39 encoded streams remain byte-identical.
- Root all-target Clippy passes with warnings denied. Vendor no-default-
  features, rustfmt and diff checks pass. Standalone vendor Clippy reports
  six pre-existing style findings in unmodified upstream lines; it passes
  with only those lint categories allowed on the command line. No lint
  suppression or unrelated cleanup is added to the vendored source.
