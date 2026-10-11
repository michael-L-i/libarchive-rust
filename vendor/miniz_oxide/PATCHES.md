# Local miniz_oxide patch

Vendored from the published miniz_oxide 0.9.1 crate, upstream revision
`4e582392df3a739d2b0dfd2c537dc33e8942be38` (repository path `miniz_oxide`).
Original crate SHA-256:
`b63fbc4a50860e98e7b2aa7804ded1db5cbc3aff9193adaff57a6931bf7c4b4c`.
All package files match the published crate except `src/inflate/core.rs`
and this note; packaging metadata and the library's standalone lockfile are omitted.
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

## Exact short disjoint match copies

The disjoint branch of `apply_match` copies lengths 4-32 with fixed-width
head/tail slices. Overlapping head/tail writes agree byte for byte; source
and destination are disjoint `split_at_mut` halves. Other lengths keep
`copy_from_slice`. No speculative writes, overcopy, distance checks, refill
points, consumed-byte counts or history semantics change. No unsafe added.

Fresh actual Claude Opus 5.5 final review: PASS. All 30 vendor tests pass,
including the expanded independent byte-reference ring/overlap test. All
1,760 valid/truncated/mutated output/status/consumption traces match the
published baseline, as do 39 encoder byte streams. No-default builds pass.
Twenty-one rotating common-C-input confirmations show raw decoding gains
of 18.5% for source gzip, 15.6% source ZIP, 10-13% mixed and 7-10%
records/compiled data. Tiny cases vary; documents gzip is 3% slower in
this run. These are backend measurements, not complete extraction times.
All 16 decoded archive hashes agree with C. Raw samples and review
records are in sibling diagnostics/round8-miniz-next.

## Exact wide overlapping match copies

For contiguous backward matches whose distance is at least 16 bytes,
`transfer` copies complete 16-byte chunks before its existing four-byte and
byte-tail loops. Each chunk reads only completed history because its width
never exceeds the distance. Every write stays within the requested match;
wrapping, forward-source, distance-one and short-distance paths retain their
original behavior. The saturated loop bound also handles partial matches of
zero to two bytes at the buffer end. No state, refill, checksum, encoder,
allocation, or unsafe-code changes are introduced.

The expanded byte-reference test exercises distance and chunk boundaries,
partial matches, wrapping and invalid initial history. All 30 vendor tests,
1,760 exact valid/truncated/mutated stream/core output/status/consumption
comparisons and 39 identical encoded streams pass. Root release all-target
Clippy with warnings denied and vendor no-default-features checks pass.
All 16 decoded archive hashes match baseline and independent C.

Twenty-one rotating in-memory runs against the frozen round-eight final
binary show text gzip 2.215 -> 1.499 ms (32.3%) and text ZIP 2.598 -> 1.852 ms
(28.7%). Documents gain 3.4-3.9%; the other twelve cases range from 0.5% slower
to 1.4% faster. These are backend measurements, not full extraction times.
Both attempted macOS sampling profiles were denied by the OS; their logs,
raw measurements, frozen baseline hash, and actual Claude Opus 5.5 design
and fresh final reviews are retained in sibling `diagnostics/round9-deflate`.

## Wider exact overlapping match copies

Extend the contiguous backward-match path with guarded 64- and 32-byte
chunks before its existing 16-byte loop. Chunk widths never exceed the
match distance, so each copy reads completed history and preserves byte-
serial LZ77 semantics. All copies stay within the existing clamped bound;
the four-byte loop and tail preserve partial-buffer behavior. No state,
allocation, encoder, refill, checksum, or unsafe-code changes are added.

Bounded macOS sampling identified match transfer as roughly 55% of the
repetitive gzip decode samples. Thirteen rotating four-way measurements
compare the frozen round-nine decoder, 32-byte and 64-byte variants, and C
on identical C archives. The retained 64-byte variant improves repetitive
gzip/ZIP decoding by 42%/36% and documents by 4-5%; the other twelve cases
vary within 2.1%. Against 32-byte chunks alone, the additional 64-byte path
saves 3.5-4.7% on repetitive data with other cases within 1.2%. These are
backend measurements, not complete extraction times.

Fresh actual Claude Opus 5.5 review returns PASS. The byte-reference test
now includes non-power-of-two output lengths and distance 65, retaining
full-buffer comparisons around chunk, wrap and tail boundaries. Design,
review, sampling and timing artifacts are retained under sibling
`diagnostics/round10-copy` and `diagnostics/round10-adapter`.

Acceptance checks pass: 30 vendor tests, 1,760 exact valid/truncated/mutated
stream/core output/status/consumption traces, 39 unchanged encoder streams,
root release all-target strict Clippy, vendor no-default build and rustfmt.
All 16 decoded archive hashes agree with baseline and C. The subsequent
21-rotation confirmation shows text gzip 2.216 -> 1.265 ms (42.9%), text
ZIP 2.577 -> 1.620 ms (37.1%), and documents 3.4-4.6% faster. Other cases
range from 0.6% slower to 1.6% faster.

## Compression is not patched

libarchive-rust compresses with its `deflate` crate, a port of zlib's
deflate, so the round-ten encoder patch ("Stable Deflate insertion buffer
borrows" in `compress_normal`) was removed and `src/deflate/core.rs` is the
published file again. Only tests still use miniz_oxide's compressor. The
patch's records remain in sibling `diagnostics/round10-deflate`.

## Inline exact short disjoint decoding matches

The fast decoder handles backward, contiguous, disjoint matches of 3-32
bytes with a small inline head/tail copy. The existing distance validation
runs first. Splitting output at its current position makes the history tail
length equal to the distance, exposing the bounds relationship to LLVM.
The helper reads and writes only the requested bytes; overlapping head/tail
writes agree. Forward-source ring matches, overlapping matches and longer
matches retain `apply_match`. Refills, state updates, error handling, public
serialized fields, allocation and compression settings are unchanged.

Fresh actual Claude Opus 5.5 design and independent final reviews cover the
copy bounds, ring equivalence, output limits and malformed-stream behavior;
the final review returned PASS. All 1,760 exact valid/truncated/mutated
stream/core comparisons preserve output, statuses and consumption; 39
encoder streams remain byte-identical. All 31 vendor tests pass, including
900 byte-reference cases covering every short length, alignments, adjacent
and separated sources, and preservation of surrounding bytes. No-default
features, formatting and diff checks pass. Standalone all-target Clippy
passes with warnings denied and only pre-existing upstream lint categories
allowed on the command line: the five previously documented library
categories plus `unnecessary_cast` and `useless_vec` in unchanged stream
tests. No source lint suppression or unsafe code is added.

Seventeen rotating native confirmation pairs use the same C-produced gzip
payloads and a frozen round-ten decoder. Source improves 19.283 -> 18.597 ms
(3.6%), mixed 3.7%, compiled 4.2% and records 5.8%. Text and documents are
unchanged; random is 0.7% slower and many-files 1.0% faster. These are raw
streaming decoder timings, not end-to-end archive results. Profiles, frozen
baseline, assembly, exact-trace harness, raw samples and actual Opus records
are retained in sibling `diagnostics/round11-inflate`. The marginal leaf-only
inlining trial and the earlier, slower long-match guard are preserved there
as separate experiments.
