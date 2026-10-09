# Local lzma-rust2 patch

Source: crates.io `lzma-rust2` 0.21.0, Apache-2.0 (see LICENSE).
Published crate SHA-256:
`fde178a3caf126c440fa15628147772d8ee590a39477d711353fbe2e58a73a5b`.
Repository: https://github.com/hasenbanck/lzma-rust2/

The local source changes are described below.
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

## LZMA2 decoder resident dictionary pages

`src/lz/lz_decoder.rs` and `src/lzma2_reader.rs` defer initialization of
unused dictionary pages in the sans-I/O `Lzma2Stream` used by XZ and 7zip.
The decoder still reserves the full declared dictionary capacity and checks
its original memory limit. Before each decode pass it initializes enough
history/output space for the remaining LZMA2 chunk (at most 2 MiB), with a
64 KiB minimum. The logical dictionary size, wrap positions, valid distances,
chunk limits and speculative rollback rules are unchanged. LZMA1 and pull
readers retain full initialization. No unsafe code or feature change.

Validation on Apple Silicon, 2026-10-09:

- 6,720 baseline/patched records match byte for byte: 480 XZ streams from
  the encoder corpus above, input/output chunks (1,31), (17,97), and
  (8192,65536), five truncations and six byte mutations per stream. Records
  include returned errors, consumed/produced counts and output hashes.
  The 64 KiB dictionaries wrap on the larger cases. Another 70 records
  match across the small-files, 2 MiB text/random, and 16 MiB text/random
  C-produced XZ archives with larger dictionaries; these exercise partial
  initialization, growth between chunks and eventual dictionary wrap.
- A decoder unit test compares lazy and fully initialized dictionaries
  through 72,000 match/literal/pending operations, dictionary wrap and resets.
  All 25 self-contained vendor unit tests pass. Eight upstream BCJ fixture
  tests require assets omitted from this vendor tree and are excluded.
- Small-files XZ stream decoding maximum resident set is 11,681,792 bytes
  before and 3,964,928 bytes after, measured with `/usr/bin/time -l`.
  This is a resident-page improvement; reserved virtual capacity is unchanged.
- Decode timing is effectively unchanged. Three alternating 21-run medians
  for 2 MiB text are 4.080/4.099, 3.954/3.939 and 3.930/3.842 ms before/after.
  A separate 16 MiB text pair is 31.955/31.857 ms. Timing is noisy; no speed
  improvement is claimed. Experiments and raw output are retained in sibling
  `diagnostics/lzma-decode-micro`. Integration oracle remains the root task.

## XZ and LZIP checksum slicing

`src/crc.rs` computes CRC32 and CRC64 eight bytes at a time using constant
slicing tables. The reflected polynomials, initial/final XOR values, and
incremental state are unchanged. Short tails use the original byte loop;
word loads use safe byte arrays and work at every alignment and endianness.
The additional read-only tables occupy 21 KiB. No new dependency or unsafe
feature is needed. This affects XZ checks and LZIP CRC32, including writers.

Validation on Apple Silicon, 2026-10-09:

- A one-second sample of the baseline 16 MiB text XZ decoder attributes
  570 of 631 main-thread samples to checksum updates.
- Independent bitwise CRC32/CRC64 reference checks cover eight alignments,
  lengths 0 through 513, and up to 18 streaming splits per input, including
  empty parts and every tail length.
- Isolated release XZ stream decoding, 21-run medians: 16 MiB text
  31.425 -> 9.987 ms; 2 MiB random 6.413 -> 3.531 ms; small-files
  1.315 -> 0.423 ms. These are backend measurements, not archive timings.
- All 6,790 baseline decoder differential records match exactly, including
  errors, consumption, output length/hash, truncations, mutations, dictionary
  wrapping and larger dictionaries. All 1,440 XZ/LZMA/LZIP encoded streams
  match the baseline byte for byte across presets 0 through 9.
- All 26 self-contained vendor unit tests pass; eight BCJ tests need omitted
  upstream fixture files. Vendor clippy passes with warnings denied; the
  changed Rust file passes rustfmt.
- Raw samples, differential records, and timings are retained in sibling
  `diagnostics/round4-lzma-micro`. Integration oracle remains the root task.
