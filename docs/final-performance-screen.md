# Final performance screen, October 12, 2026

Eight focused experiments were screened from source `e2d80ca` on native
ARM64 macOS with Rust 1.95 release builds. None established a repeatable
performance improvement sufficient to retain. Runtime code, compression
settings and release configuration remain unchanged. The latest full-matrix
result is still the [installed-library measurement](shared-library-performance.md):
49 Rust wins, 45 ties, two losses and geometric mean Rust/C time 0.910324.

## Codec profiles and trials

Sampling the current installed library during source-data XZ creation
identified match-finder skipping as the main sampled work. A separate
encoder sample put 2,170 of 2,528 samples in `skip_raw`. An initial capture
started during dynamic-loader initialization and is not a codec profile.
The compiled-data Zstd screen sample placed approximately 70% of sampled
work in double-fast matching and 25% in entropy coding. These samples
identify where to investigate; their counts are not timing improvements.

| Experiment | Decision and evidence |
|---|---|
| Counted LZMA probability-price loops | Rejected: approximately 0.5–1.1% elapsed reduction in a three-input screen, insufficient evidence of a material gain |
| Extend BT4 cached repeat proof to 4 KiB | Rejected: source, mixed and random screens were neutral or slightly slower |
| Derive BT4 mismatch order from already loaded words | Rejected: fewer retired instructions, but source elapsed time regressed 6.6% in the eight-dataset confirmation; substantial run variance prevented selecting isolated wins |
| Compare big-endian words for BT4 mismatch order | Rejected: source −0.5%, mixed +0.5%, random −2% elapsed; no material broad gain |
| Skip Zstd empty-literal overcopies | Rejected: geometric mean candidate/baseline time 1.0027 across eight datasets |
| Use reversed slices for Zstd backward match extension | Rejected: geometric mean candidate/baseline time 1.0071 across eight datasets |

The LZMA comparison prototypes passed independent bytewise comparison and
original match-finder state tests, including refills, dictionary wrapping,
window moves, flushes and normalization. They were rejected before full
installed-library and C byte-oracle validation; passing these focused tests
does not make the preserved patches ready to merge.

Each Zstd screen used eight datasets, seven alternating pairs and ten
encodes per process. Encoded output bytes matched the baseline throughout;
the reversed-slice trial also matched 2,109 valid boundary states. These
are isolated codec screens, not full application measurements.

## Compiler configuration trials

Two installed-library configurations used the same unchanged C client,
archived C/Rust libraries, frozen inputs and release installer. Actual
client bindings and independent read/write/disk/variadic-error providers
were verified before timing. Only compiler configuration changed.

The focused matrix used source, random and compiled datasets with XZ,
Zstd and 7zip creation/extraction: 18 cases. Variants rotated over one
output path; extraction used common C-written archives. Repeated writes
had to preserve exact before/after Rust archive bytes. Every final writer
was read by C and the candidate, and truncated ZIP/gzip rejection was
checked for all three variants.

| Configuration | Paired rotations | Timed runs | Checks passed | Geometric mean candidate/baseline time |
|---|---:|---:|---:|---:|
| ThinLTO, one code-generation unit | 3 | 162 | 69 | 1.009224 |
| ThinLTO, default 16 code-generation units | 5 | 270 | 69 | 0.997828 |

Both runs had zero run/check failures. The first configuration recorded
a 27% source XZ creation slowdown in its three-repeat screen, with substantial
sample variance. The second was effectively neutral overall: approximately
0.2% less elapsed time. Neither justifies changing the release configuration.
These focused screens do not replace the 96-case benchmark or establish
Linux/x86 performance, cold-cache behavior or broader compatibility.

## Retained evidence

Raw samples, assembly, prototype source/patches, focused tests, compiler
metadata, build logs and timing results are retained outside the source
distribution in:

- `../diagnostics/final-performance-lzma/`
- `../diagnostics/final-performance-zstd/`
- `../diagnostics/final-performance/`

The last directory includes `compare-revisions.py`, both compiler-trial
installations and `thin-screen`/`thin16-screen` JSON, Markdown and logs.
The JSON records the exact client/library hashes, loaded providers, input
digests, configurations and each timed sample. Rejected prototypes remain
experimental artifacts and are excluded from the shipped source.
