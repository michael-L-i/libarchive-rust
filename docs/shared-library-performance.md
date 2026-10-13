# Installed shared-library performance validation

Measured on October 12, 2026, on an Apple M5 Pro, native ARM64 macOS 26.6.2.
One unchanged pinned-upstream C `bsdtar` executable selected either the C
libarchive 3.9.0dev shared library or the installed Rust release library.
The Rust installation used Rust 1.95.0 and source revision `2161711`, whose
runtime code matches the production packaging validation.

This exercises an existing C consumer's public ABI. It is separate from the
earlier benchmark comparing the C and Rust front-end executables.

## Method and correctness

The frozen eight datasets and six formats produce 96 create/extract cases.
Each case uses five paired repeats with alternating implementation order.
Both variants use the same output path. Extraction reads the same C-written
archive; extracted regular-file paths, sizes and SHA-256 hashes must match
the input. Every final C/Rust archive is additionally extracted by each
implementation. Four checks require clean rejection of truncated ZIP/gzip
inputs; a crash or timeout fails the check.

The exact timing wrapper verifies all 111 client `archive_*` bindings and an
independent probe's read, write, disk and variadic error providers before
measurement. macOS clears loader variables when launching protected
`/usr/bin/time`, so assignments are applied inside its child `env` process.
Both variants use this same wrapper. No competing builds or fuzz campaigns
ran during the measurement.

All **196 checks passed**, with **zero run failures** across 960 timed
create/extract invocations and 50 startup invocations. The 48 Rust-written
archives were readable by both implementations. Archive sizes matched C in
42 cases; six zstd archives were 0.019–0.717% smaller.

## Results

A win/loss means the median time differs from C by more than 5%; otherwise
the case is a tie. Cases have equal weight in the geometric mean.

| Operation | Rust wins | Ties | Losses | Geometric mean Rust/C time |
|---|---:|---:|---:|---:|
| Create | 30 | 17 | 1 | 0.878920 |
| Extract | 19 | 28 | 1 | 0.942851 |
| Combined | 49 | 45 | 2 | 0.910324 |

Rust used about **9.0% less elapsed time** by the combined geometric mean
on this matrix. This is a workload-specific result, not a general promise.

Startup (`--version`), measured in 25 paired rotations, had median elapsed
times of **7.181 ms for C** and **6.547 ms for Rust**. These include the
Python process-launch interval and time/env wrapper overhead. Median peak
RSS was 1.953 MiB for C and 1.938 MiB for Rust.

The two slower cases were confirmed separately with 15 paired repeats,
without replacing the original full-matrix results:

| Confirmed case | C median | Rust median | Rust/C |
|---|---:|---:|---:|
| Compiled dataset, zstd create | 21.413 ms | 22.488 ms | 1.05020 |
| Compiled dataset, 7zip extract | 46.640 ms | 50.186 ms | 1.07603 |

All 12 confirmation checks passed. These remain useful optimization targets;
the zstd case is close to the classification threshold and its difference
is about 1.1 ms.

Median peak RSS across full-matrix cases ranged from 2.266–95.703 MiB for C
and 2.609–96.531 MiB for Rust. Small 7zip creation remained close to C:
records used 55.20/55.94 MiB and many-files used 55.66/56.97 MiB for C/Rust.
These ranges do not describe total allocations or a memory limit.

## Evidence and reproduction

Use `bench/build-shared-client` and `bench/compare-shared.py` as described
in `bench/README.md`. Raw JSON preserves every run, per-case medians/ranges,
peak RSS, input digests, provider/binding verification and these SHA-256s:

| Artifact | SHA-256 |
|---|---|
| Same C client | `8281d8ccf776b9ae3fc33a762b872c133e887ab7a1098dbc9a15623c454b806a` |
| C shared library | `e704b9cf4c9acd75332a87ec1996acd13aaaa63d0429ef6e135040996379ef54` |
| Installed Rust shared library | `8ceb3de51f864946044fdf03d0fcfd50fb093c5eadc878fcf5b6bd7803405fd7` |

Local raw evidence is retained outside the source distribution under
`../diagnostics/adoption-shared-performance/shared-final.{json,md,log}`,
with `shared-confirm-losses.{json,md,log}` for the confirmation and copies
of both measured libraries. Initial harness-development `smoke` reports
are explicitly invalidated because they predated the protected-timer fix;
corrected smoke reports validate the harness but are not performance results.

This measures warm-cache regular-file workloads with ACLs, xattrs, file flags
and Mac metadata disabled. It does not measure cold storage, concurrent
applications, package-manager transactions, other operating systems or
architectures, or establish general compatibility or security guarantees.
