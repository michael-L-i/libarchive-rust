# Archive property fuzzing

The crate contains 39 targets: 29 original format/filter/all readers,
`all_deep`, seven format writers, `writer_roundtrip`, and `read_limits`.

The reader/filter targets exercise the C ABI, abort on swallowed Rust panics,
and use per-handle processing limits before opening input. Their usual data
loop stops after 1 MiB, with 8 MiB decoded-work and 2 MiB metadata budgets,
16,384 entries, depth 25 and a 256 MiB per-decoder cap. `all_deep` reads up
to 16 MiB, with 64 MiB decoded-work, 8 MiB metadata and 65,536-entry budgets;
its depth and decoder caps are unchanged. These limits also cover header
work. They do not bound every CPU instruction, callback, external process
or total resident memory; libFuzzer's
timeout and RSS limits remain necessary. A bounded producer block may finish
before a processing limit is detected. Normal library reads are uncapped by
these optional budgets unless the caller configures them; decoder memory
must be configured before explicitly appending filters.

The seven format-specific writer targets generate one to five regular files
with
ordinary names and at most 8 KiB each. They write into a safe, bounded memory
sink with geometric growth, verify exact recovered file contents using
buffered or block reads, then check partial-read/skip traversal.
`writer_roundtrip` selects a format from its first input byte. It covers ustar/pax/gnutar, ZIP, newc cpio, BSD ar,
LZMA2 7-Zip, XAR and ISO9660 with Rock Ridge/Joliet names. These are bounded
valid-archive properties, not exhaustive writer option or filesystem tests.

`read_limits` constructs valid tar archives and checks undersized entry,
metadata and decoded-work budgets fail with the documented status. An exact
source-byte/entry-count budget must succeed through EOF.

```sh
scripts/fuzz-seeds
scripts/fuzz-writer-seeds
cargo test --manifest-path fuzz/Cargo.toml --lib
cd fuzz
cargo +nightly fuzz build
cargo +nightly fuzz run writer_roundtrip -- -max_total_time=60 -timeout=10 -rss_limit_mb=1024 -malloc_limit_mb=257
cargo +nightly fuzz run read_limits -- -max_total_time=60 -timeout=10 -rss_limit_mb=1024 -malloc_limit_mb=257
cargo +nightly fuzz run all_deep -- -max_total_time=60 -timeout=10 -rss_limit_mb=1024 -malloc_limit_mb=257
```

The reader decoder allowance is 256 MiB. libFuzzer stops allocations at
its `malloc_limit_mb` threshold, so use 257 MiB to permit that boundary
while retaining the independent RSS and timeout controls. The lzip decoder can allocate and initialize its full dictionary allowance
before a short malformed input is rejected. A 15-byte lzip input found
this threshold mismatch during an extended campaign and is included in the
deterministic seeds. The original guard failure is retained as evidence.

Corpora and failure artifacts are ignored by Git. The deterministic writer
seeds cover empty and binary members, each tar variant, small chunks and
maximum generated file sizes. The deeper reader seeds include a valid 3 MiB
tar member and its gzip wrapper. A short campaign checks that targets run;
it does not establish the absence of bugs.

The ten new targets completed short ASan campaigns of ten seconds each with
no reported failures, using the commands' 1,024 MiB RSS limit and default ASan
quarantine. Observed peaks ranged from 154 to 491 MiB. These are campaign
measurements, not library memory bounds or exhaustive security results.
