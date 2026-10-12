# Archive property fuzzing

The reader/filter targets exercise the C ABI, abort on swallowed Rust panics,
and use per-handle processing limits before opening input. Their usual data
loop stops after 1 MiB; `all_deep` reads up to 16 MiB with larger processing
budgets. These limits also cover header work. They do not bound every CPU
instruction, callback, external process or total resident memory; libFuzzer's
timeout and RSS limits remain necessary.

The seven `writer_*` format targets generate one to five regular files with
ordinary names and at most 8 KiB each. They write into a safe, bounded memory
sink, verify exact recovered file contents using buffered or block reads,
then check partial-read/skip traversal. `writer_roundtrip` selects a format
from its first input byte. It covers ustar/pax/gnutar, ZIP, newc cpio, BSD ar,
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
cargo +nightly fuzz run writer_roundtrip -- -max_total_time=60 -timeout=10 -rss_limit_mb=1024 -malloc_limit_mb=256
cargo +nightly fuzz run read_limits -- -max_total_time=60 -timeout=10 -rss_limit_mb=1024 -malloc_limit_mb=256
cargo +nightly fuzz run all_deep -- -max_total_time=60 -timeout=10 -rss_limit_mb=1024 -malloc_limit_mb=256
```

Corpora and failure artifacts are ignored by Git. The deterministic writer
seeds cover empty and binary members, each tar variant, small chunks and
maximum generated file sizes. The deeper reader seeds include a valid 3 MiB
tar member and its gzip wrapper. A short campaign checks that targets run;
it does not establish the absence of bugs.
