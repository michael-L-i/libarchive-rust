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

## Encoder ported from liblzma 5.8.4

The xz-for-Java encoder (`src/enc/encoder*.rs`, `src/enc/range_enc.rs`,
`src/lz/lz_encoder.rs`, `src/lz/bt4.rs`, `src/lz/hc4.rs`,
`src/lz/hash234.rs`) is replaced by a safe Rust port of liblzma 5.8.4's
encoder (0BSD; Igor Pavlov, Lasse Collin): the LZ window and HC3/HC4/BT4
match finders (`lz/lz_encoder.c`, `lz_encoder_mf.c`, `lz_encoder_hash.h`,
`common/memcmplen.h`), the LZMA encoder with its normal and fast optimum
parsers and price tables (`lzma/lzma_encoder*.c`), the range encoder and
prices (`rangecoder/`), LZMA2 chunking (`lzma/lzma2_encoder.c`) and the
presets (`lzma/lzma_encoder_presets.c`, so preset 0 uses HC3 and `MfType`
gains `Hc3`). BT2 and BT3, which no preset uses, are not ported. The
public writers and options keep their API and container framing, except
that the unused `get_extra_size_before()` helper is gone.

liblzma updates the dictionary and alignment price tables in batches
(`match_price_count`, `align_price_count`), length prices every
`nice_len - 1` encodings per position state, and splits LZMA2 chunks at
61,439 compressed bytes. xz for Java did each of these slightly
differently, so its output differed from liblzma's by a few hundred bytes
per archive even though both did the same match-finder and parser work.

Differences from liblzma, none visible in the output:

- liblzma queues the bits of a symbol and encodes them once output space
  is available; here they are encoded at once into a `Vec`. Normalization
  still precedes each bit, so LZMA2's chunk-size checks see the same
  range-coder state. Because the queued bits update probabilities only
  after the symbol, a length price table is recomputed before, not after,
  the length's own bits are encoded.
- Out-of-range options are clamped instead of rejected (dictionary to
  4 KiB-1.5 GiB, `nice_len` to the match finder's minimum-273, `lc` <= 8,
  `lp` and `pb` <= 4); `lc + lp` above liblzma's limit of 4 remains
  available to LZMA1. LZMA2's `chunk_size` independent chunks re-create
  the encoder after a sync flush.
- liblzma's quirk is kept: after an LZMA2 chunk stored uncompressed with
  read-ahead bytes, the encoder's position lags by those bytes. All
  position contexts were just reset, so the shift relabels them
  consistently and decoders are unaffected.

The earlier xz-for-Java encoder patches (BT4 skip match extension,
overlapping-word tails, proved skip prefixes, masked literal updates,
bounded skips and distance prices, hash-head pipelining and the find
hint) went away with that code; their evidence remains in sibling
`diagnostics/lzma-micro` and `diagnostics/round{4..10}-lzma*`.

Validation on Apple Silicon, 2026-10-11, against liblzma 5.8.4 (Homebrew
`xz`, `diagnostics/round12-lzma-enc/harness/cenc`):

- All eight benchmark tar inputs produce byte-identical `.xz` at preset 6
  (these equal the C bsdtar archives in `diagnostics/round8-suite`), and
  records and compiled at presets 0-9.
- 1,200 streams are byte-identical: `.xz`, raw LZMA2, raw LZMA1 with end
  marker and `.lzma`, at presets 0-9 and their extreme variants, over 15
  inputs: empty, 1-5 bytes, 273/274, 4 KiB and 64 KiB + 1 random, 1 MiB of
  zeros, a period-3 pattern, 300 KiB random (beyond preset 0's
  dictionary), 3 MiB of text with long-range repeats and 2.4 MiB of mixed
  random and text that produces uncompressed LZMA2 chunks.
- Sync flushes every 1,000, 65,536 and 100,000 bytes (xz and LZMA2, six
  presets) and preset dictionaries of 1 byte, 100 KB and 2 MB (raw LZMA1
  and LZMA2) are byte-identical, as is a flush with a preset dictionary.
- Every `.xz` and `.lzma` output decodes with `xz -d`.

### Encoder speed changes

Output stays byte-identical to liblzma; each change was checked against
the liblzma harness. Instruction counts are single `/usr/bin/time -l`
runs of the preset-6 `.xz` harness on a 4 MiB slice of the source corpus
and on the records corpus (the machine was shared with other jobs, so
instructions retired, not time, judge these).

- `memcmplen()` slices both inputs once, so its word loads need no
  per-load bounds checks: 6.635 -> 6.394 G instructions on the source
  slice, 11.14 -> 11.01 G on records.

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

## Expose the fixed eight-bit literal decode count

Both normal and matched literals decode exactly eight bits: `symbol` starts
at one and every range-decoded bit is zero or one, so after `k` iterations
it lies in `[2^k, 2^(k+1)-1]`. Replace the symbol-dependent exit with an
eight-iteration loop. Probability indices, update order, input reads,
normalization, dictionary writes and errors are unchanged for valid and
malformed input. No new unsafe code, dependency, allocation or format change.

Validation on Apple Silicon, 2026-10-11, versus `3bd88f0`:

- Current source/mixed/records profiles identify the main range decoder and
  length decoder as the relevant hot paths. A separate fixed-array tree and
  inlined-length experiment produces mostly 0-3% changes and is omitted.
  The literal-only change retains the material gains with two loop edits.
- ARM64 release assembly expands both literal paths into eight range-bit
  steps, removing their loop backedges. The main slice-reader decoder grows
  from 683 to 1,045 instructions; the rejected combined tree/literal trial
  had 1,971. One bounds-panic call site disappears through compiler proof;
  the source retains checked probability indexing.
- Five alternating pairs, each timing a five-run XZ stream median:
  records 35.555 -> 31.887 ms (10.3% faster), documents 33.370 -> 31.838 ms
  (4.6%), mixed 220.929 -> 213.495 ms (3.4%). Text is 0.2% faster; random
  and many-files 1.4% faster. Source is 1.5% slower and compiled 2.4% slower.
  The earlier three-pair attribution screen improves mixed/records/documents
  by 6.9%/9.2%/6.3% and compiled by 3.5%. Retain this variation rather than
  claiming a uniform improvement. These 80 final medians cover 400 decodes;
  archive-level validation and timing are separate.
- All 14,400 baseline/candidate XZ and LZMA1 trace records match exactly,
  covering 31,234,337 process calls. Records include the hash of every
  consumed/produced/status tuple, output hash, final counts and exact error
  text. Presets 0-9, dictionary wraps, fragmented input, one-byte output,
  five truncations and six mutations per stream produce 3,948 successes
  and 10,452 errors, with no stalls or harness limits reached. Trace SHA-256:
  `2dcce229980605cf030e63fa365061360d3e29def4b53fa6a01f9cd9d9f49dd7`.
- All 28 available vendor tests, strict all-target Clippy, changed-file
  rustfmt and diff checks pass; eight BCJ tests need omitted fixture assets.
- Fresh actual Claude Opus 5.5 provided architecture ideas and an independent
  final review returned PASS on the exact literal-only diff. Both resolved
  to `claude-opus-5-5`, provider `firstParty`. Design `modelUsage`: 31,715
  cache-creation input tokens, 2 uncached input tokens and 6,475 output
  tokens (3,164 thinking). Final review: 14,294 cache-creation input tokens,
  2 uncached input tokens and 1,644 output tokens (396 thinking). Neither
  used cached reads or web searches.
- All samples, rejected variants, complete assembly, trace harness/results,
  validation logs and authenticated review JSON are retained in sibling
  `diagnostics/round11-lzma`. During the round the workspace was externally
  renamed from `port-rs-lib` to `port-rs-libarchive`; source was preserved.

## Sixteen-byte CRC64 checksum steps

`Crc64::update` folds 16 bytes with a slicing-by-sixteen table. The incoming
state contributes only to the first eight bytes; the remaining eight
lookups can proceed independently. Its existing eight-byte and byte tails
remain intact. CRC32 production code, streaming state, initialization and
finalization are unchanged. No new allocations, dependencies or unsafe
code are added. The read-only CRC64 table grows from 16 to 32 KiB.

An independent bitwise reference now covers every length through 513, all
16 byte offsets and split points through 33. Baseline and candidate CRC
tests pass. Five rotating checksum pairs show 44.6-44.9% lower time for
16-byte through full 16 MiB chunks; one- and seven-byte chunks are neutral.

Twenty-one rotating whole-archive in-memory ABI checks against frozen
round-ten Rust show XZ text 9.490 -> 6.286 ms (33.8%), random
11.521 -> 8.242 ms (28.5%), source 21.272 -> 17.966 ms (15.5%), and many
files 7.568 -> 6.557 ms (13.4%). Other cases improve 0.8-2.4%. All eight
decoded archive hashes match independent C and baseline Rust. These are
in-memory archive-reader measurements, not filesystem extraction times.

Three rotating writer pairs on text, documents and source produce exact
baseline bytes; C and Rust decode all resulting streams to the expected
SHA-256. Another 48 valid, truncated and mutated ABI records preserve
output, error text, errno and input positions. Strict root release
all-target Clippy and formatting pass. Fresh actual Claude Opus 5.5 design
and independent final reviews pass after their requested whole-XZ and
expanded split checks. All artifacts are in sibling `diagnostics/round11-crc`.

Performance was measured on this Mac. The extra 16 KiB of read-only tables
may affect smaller CPU caches; performance on other CPUs is unmeasured.
