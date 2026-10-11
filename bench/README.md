# bsdtar benchmark

Compares upstream's C `bsdtar` with the Rust port's `bsdtar` over a fixed matrix:
8 datasets x 6 formats x {create, extract} = 96 cases. Python 3 stdlib only;
macOS only (it reads peak RSS from `/usr/bin/time -l`).

## Build both executables

```sh
scripts/build-oracle           # C: build/oracle/bin/bsdtar, upstream built against upstream libarchive
scripts/build-port --release   # Rust: build/port/bin/bsdtar
```

Compare release builds: the C oracle is a RelWithDebInfo build, the port should
use `--release`. Both are self-contained for this purpose; keep any older Rust
snapshot you want as a third column (`--rust-before`).

## Run

```sh
bench/compare.py --c build/oracle/bin/bsdtar --rust build/port/bin/bsdtar
bench/compare.py ... --rust-before old/bsdtar          # three-way
bench/compare.py ... --formats tar.zst 7zip --datasets records --ops extract --repeats 2   # subset
bench/compare.py ... --inputs /path/to/corpus           # existing corpus, one directory per dataset
```

Options: `--work` (scratch, default `bench/work`), `--out` (results, default
`bench/out`), `--label`, `--repeats` (default 5). Without `--inputs`, datasets
are generated into `<work>/inputs`. Generate them separately with
`bench/datasets.py DEST [--datasets ...]`, or copy another corpus with
`--from DIR`. A full run takes about six minutes; run it with nothing else
loading the machine.

## What is measured

- Formats and presets: ustar, ustar+gzip (level 6, no timestamp), zip (deflate 6), ustar+xz (6), ustar+zstd (3), 7zip (lzma2, 6). Metadata options (ACLs, xattrs, Mac metadata, fflags) are disabled.
- Per case, the executables run in rotating order for each repeat, over the same output path.
- Extraction: every executable reads the identical C-produced archive. Each extracted tree is checked (path, size, SHA-256) against the input.
- Cross-reader checks: each executable's archive is extracted by C and by the last executable. With `--rust-before`, the two Rust builds' archives must also be byte-identical.
- Warm cache, wall-clock time of the whole process including startup, median of the repeats. Peak RSS is the median of `maximum resident set size`.
- Win: median more than 5% below C. Loss: more than 5% above. Tie: within 5%. Each case has equal weight.

## Reading the results

`bench/out/<label>.md` has the scorecard, a per-case table (milliseconds, ratio to C with outcome, peak MiB, archive size relative to C) and the check counts. `<label>.json` has every raw run, hashes, tool versions and input digests. Ratios below 1 mean Rust is faster. The exit status is non-zero if any run or check fails.

## Datasets

`bench/datasets.py` regenerates the corpus from fixed seeds. Compared by SHA-256 with the frozen corpus used for the published report:

| Dataset | Content | Frozen corpus |
|---|---|---|
| text | 4 x 4 MiB repeated JSON log line | identical |
| random | 4 x 4 MiB seeded random | identical |
| records | 4 MiB seeded JSON records | identical |
| documents | 4 MiB multilingual text with random islands | identical |
| source | 16 MiB tiled source text | approximate |
| mixed | 16 MiB alternating 64 KiB noise and source blocks | approximate |
| many-files | 2048 files of 2 KiB cut from the source text | approximate |
| compiled | 4.9 MB executable-like file | approximate |

The approximate ones depend on inputs that cannot be reproduced. The frozen source text is a 2.8 MB concatenation whose file list was not recorded; here it is upstream's `libarchive/*.[ch]` from the pinned submodule, sorted by name (3.8 MB). `compiled` was a copy of an old bsdtar binary; here it is synthetic opcode-like words, symbol strings, zero runs and noise from a fixed seed, sized like the original and compressing to a similar ratio (gzip 0.47 vs 0.38, xz 0.31 vs 0.27). Absolute times for these four therefore differ from the published ones; use `--inputs` with the frozen corpus to reproduce them exactly.

## Caveats

- Results depend on the machine, OS version, filesystem, background load and thermal state.
- Warm cache only; cold-cache and slow-disk behavior are not measured.
- Startup is included, so small cases (a few milliseconds) are dominated by process launch and filesystem noise; one repeat is a smoke test, not a statistic.
- Only regular-file content is compared, with metadata disabled. This is not a compatibility or security test.
- Identical preset numbers do not imply identical compression strategy; check archive size alongside time.
