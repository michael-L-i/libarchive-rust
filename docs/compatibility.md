# Compatibility scope

This implementation targets the public C API and behavior of libarchive
3.9.0dev at `8bb3bbdc7b117a1e22086a2260f2087aafa90687`. The bundled
headers are unchanged copies from that revision, and the C library exports
all 454 public functions. The installer uses ABI major 13. Rust callers and
the four Rust tools use the Rust API directly.

Matching headers, exports and SONAME enables replacement testing; it does not
establish compatibility with every downstream distribution or application.
Evaluate the intended application's formats, metadata requirements and error
handling in a staged installation before replacing its system library.

## Platforms and dependencies

The supported installation path is macOS and Linux with glibc. Native ARM64
builds, installed consumers and upstream suites have been exercised on both.
Debian 12 x86_64 has also been exercised under Rosetta translation, with three
development-test failures reproduced in standalone process-spawning programs.
Native x86_64 CI is configured; hosted results are pending publication.

Windows, musl, kernel use and cross compilation through `scripts/install`
are unvalidated. The library uses `std` and platform system libraries. Build
on a suitable target baseline: the builder's libc and deployment target affect
the resulting binary's requirements. See [installation](install.md),
[installation validation](install-validation.md) and the
[x86 results](downstream-testing.md).

The C interface retains `capi/variadic.c` to format printf-style
`archive_set_error` arguments with the minimum supported Rust 1.95 compiler.
It does not contain archive or compression logic. The Rust library and tools
compile no C source. Some format filters use external programs as upstream
fallbacks: grzip, lrzip and lzop require their corresponding executables.
In particular, lzop does not have a built-in liblzo2-equivalent decoder here.

## Current differences requiring attention

This is a focused source audit, not an exhaustive new corpus comparison.
[NOTES.md](../NOTES.md) retains the detailed per-module record. The following
points were checked against the current implementation during publication
preparation:

| Area | Current behavior | Practical consequence |
|---|---|---|
| XZ filter chains | The streaming XZ decoder rejects multiple delta/BCJ prefilters before LZMA2; one prefilter is supported. | Some valid XZ streams that liblzma reads are rejected. |
| Decoder dictionaries/models | Existing hard caps reject oversized allocations; XZ/LZMA/lzip dictionaries are capped at 256 MiB. | Some unusually large valid streams accepted by uncapped upstream builds are rejected. |
| Compression threads | XZ and Zstd validate the `threads` option but do not use its value to select multiple encoding workers. | Applications requesting parallel compression should not expect upstream's scaling. |
| Compressed bytes | Safe codec backends do not universally reproduce upstream compressed output. | Successful round trips need not yield identical compressed bytes or ratios. |
| Malformed compressed input | Backend error classification, partial output and rejection points can differ from liblzma, libbz2 and zlib. | Applications comparing exact corrupt-input messages or recovered prefixes need their own differential checks. |
| Filesystem metadata | Support follows the tested platform's ACL, xattr, flag and permission facilities. Descriptor-based checks can refuse replacements or unanchored metadata operations. | Extraction into concurrently modified trees can fail where upstream proceeds; neither testing nor identity checks remove every race. |

The XZ chain check is in
[`vendor/lzma-rust2/src/xz/reader.rs`](../vendor/lzma-rust2/src/xz/reader.rs).
Thread-option handling is in
[`src/write/filter/xz.rs`](../src/write/filter/xz.rs) and
[`src/write/filter/zstd.rs`](../src/write/filter/zstd.rs).
The Zstd implementation can use a bounded worker pipeline, but the accepted
`threads` value does not change the number of codec workers.

The historical `.lzma` zero-padding acceptance note has been corrected.
The current
[`LzmaStream` implementation](../vendor/lzma-rust2/src/lzma_reader.rs)
tracks padding use and rejects an EOF finish that consumes synthetic padding.
The upstream truncation regression test passes, and focused one-to-seven-byte
cuts from a roughly 17 KiB binary payload compressed as .lzma were rejected by both implementations.
These checks resolve the old claim that the decoder cannot detect padding;
they do not establish identical behavior for every malformed LZMA stream.

## Deliberate differences and limits

The ISO writer fixes documented upstream output-corruption bugs. Those
affected images intentionally differ from upstream's corrupt output;
`scripts/test-iso-zisofs` verifies recovery with upstream's reader.
Disk extraction hardening also deliberately refuses some operations that
would mutate paths outside the intended extraction tree. These are described
with regression evidence in `NOTES.md`.

Default reader settings retain compatibility behavior and existing hard caps.
Optional `ReadLimits`/`limits:*` options budget covered decoded processing,
entries, metadata, filter depth and decoder memory. Coverage is documented in
[`src/read/limits.rs`](../src/read/limits.rs). They are not whole-process heap
limits or CPU deadlines, and they do not constrain every external program or
callback. Applications should choose extraction policy and resource controls
for their own environment.

## Evidence and remaining validation

[Adoption validation](adoption-validation.md) records unchanged downstream
applications, selected package transactions and extended fuzzing.
[Shared-library performance](shared-library-performance.md) measures a C
consumer on macOS; its timing result is independent of compatibility and
does not establish Linux performance.

The next compatibility work should reproduce specific documented differences
with minimized valid and malformed fixtures, preserving both implementations'
results. Native x86_64 execution and the intended distribution's actual
downstream clients remain necessary before making broader replacement claims.
