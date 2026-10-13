# Adoption validation, October 12, 2026

This round added repeatable downstream, package-manager and shared-library
benchmark harnesses and corrected a fuzz allocation-guard boundary. Library
and tool runtime code is unchanged from `2161711`. Builds used Rust 1.95.0;
the fuzz binaries used nightly 1.101.0 with AddressSanitizer.

| Area | Observed result |
|---|---|
| Debian 12 existing applications, ARM64 and translated x86_64 | 23 checks and 190 commands passed per architecture |
| Debian 12 pacman/libalpm transactions, ARM64 and translated x86_64 | 14 checks passed per architecture |
| Extended fuzz campaigns | 27,938,849 executions; original allocation-guard failure corrected and rerun |
| Native ARM64 macOS installed-library benchmark | 196 checks passed; 49 Rust wins, 45 ties, 2 losses in 96 cases |
| Final macOS upstream integration | 926 passed, 184 skipped, zero failures/crashes/timeouts or ratchet regressions |
| Final harness regression tests | 20 passed, including resource-warning checks |

## Existing applications and package transactions

Unchanged distribution applications selected either their system C library or
the staged Rust library through a child-process loader environment. Loader
traces verified the selected provider. See [downstream testing](downstream-testing.md)
for the x86 results, including three development-test failures reproduced by
standalone Rust and C spawning under Rosetta. Native x86 CI is configured but
has not run. Debian's older liblzma headers also caused one previously passing
RISC-V test to skip in both C and Rust; neither ratchet was relaxed.

`scripts/test-package-manager` runs isolated pacman 6.0.2/libalpm 13.0.2
transactions against both libraries. Checks cover install, conflicts, upgrade,
downgrade, configuration-file handling, query/verify, removal, corrupt and
truncated inputs, and interruption followed by retry. Comparisons include file
contents, ownership, modes, links, Unicode names and user xattrs. All 27 libalpm
archive bindings were verified for each implementation.

SIGINT during extraction was acknowledged while the first 512 MiB payload
was incomplete; both implementations subsequently finished the files and
registered the package. Retry/reinstall and removal converged. This does not
establish rollback, power-loss recovery or crash consistency. Unsigned local
fixtures use an isolated container package root; the host package database and
system library are not changed.

## Extended fuzz campaigns

All 39 existing targets ran for up to 120 seconds each with two workers,
a 10-second input timeout, 2,048 MiB RSS guard and default ASan quarantine.
The original campaign completed 38 targets; `filter_lzip` hit the 256 MiB
allocation guard. It performed 27,537,919 executions with 77.39 minutes of
aggregate target wall time and a 749 MiB peak RSS.

A short rejected lzip stream can allocate and initialize the full allowed
256 MiB dictionary. libFuzzer rejects allocations at its threshold, so that
guard prevented an allocation the harness explicitly allowed. The guard is
now 257 MiB, with the decoder allowance, timeout and RSS controls retained.
The input is included in deterministic seeds and the original failure retained.

The focused `filter_lzip`, `all` and `all_deep` reruns completed 400,930
executions without reported failures, with 6.06 minutes of aggregate target
wall time and peak RSS of 1,038 MiB. Combined execution count is 27,938,849;
83.45 minutes is aggregate target wall time, not measured CPU time.

Fresh deterministic-seed smoke runs also passed all ten CI targets and
`filter_lzip` using 100 requested runs each, the 1,024 MiB RSS guard and
257 MiB allocation guard; observed peaks were 87–438 MiB. These results do
not establish the absence of bugs or bound total application memory.

## Performance and integration

One unchanged C client selecting either installed library used about 9.0%
less elapsed time with Rust by the geometric mean of 96 macOS cases. Confirmed
remaining losses were compiled-data zstd creation (5.02%) and 7zip extraction
(7.60%). See [shared-library performance](shared-library-performance.md) for
methods, memory, startup, hashes and workload limits. No native Linux or
x86 performance measurement was made.

Formatting passed with Rust 1.95.0 and strict workspace Clippy passed with
Rust 1.97.1, matching the existing lint setup. Clippy 1.95.0 reported 24
pre-existing style diagnostics in unchanged runtime code; this is not a
successful minimum-version lint run. Minimum-version builds and runtime
tests are documented separately in [installation validation](install-validation.md).

Raw logs, library copies, seeds' hashes, compiler metadata and the local
campaign runner are retained outside the source distribution under
`../diagnostics/adoption-{validation,package-validation,fuzz-validation,shared-performance}/`.
Final formatting, lint, harness and upstream integration logs are retained in
`../diagnostics/adoption-integration-validation/`.
The evidence supports these selected deployments and workloads; broader
distribution testing and native x86 execution remain necessary before
claiming universal replacement compatibility.
