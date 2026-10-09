# libarchive-rust status

Date 2026-10-08. Upstream pin `8bb3bbdc`. Run: port; ISO fuzz rechecked with a 60s timeout.

**Passing 64 / upstream 829 / 934 total**

| Area | Ours | Upstream | Total |
|---|---:|---:|---:|
| acl | 15 | 19 | 21 |
| archive | 10 | 123 | 134 |
| cat | 18 | 18 | 18 |
| compat | 0 | 29 | 30 |
| cpio | 1 | 43 | 49 |
| entry | 3 | 3 | 3 |
| fuzz | 9 | 9 | 9 |
| read_filter | 10 | 15 | 19 |
| read_format_7zip | 2 | 56 | 56 |
| read_format_ar | 0 | 1 | 1 |
| read_format_cab | 0 | 9 | 10 |
| read_format_cpio | 0 | 24 | 35 |
| read_format_empty | 1 | 1 | 1 |
| read_format_huge | 1 | 1 | 1 |
| read_format_iso | 0 | 19 | 19 |
| read_format_lha | 0 | 6 | 7 |
| read_format_mtree | 0 | 13 | 13 |
| read_format_rar | 0 | 37 | 42 |
| read_format_rar5 | 0 | 77 | 78 |
| read_format_raw | 1 | 1 | 1 |
| read_format_tar | 0 | 33 | 41 |
| read_format_warc | 0 | 6 | 6 |
| read_format_xar | 0 | 10 | 10 |
| read_format_zip | 0 | 98 | 110 |
| tar | 0 | 72 | 79 |
| unzip | 3 | 29 | 30 |
| write_filter | 0 | 19 | 21 |
| write_format_7zip | 0 | 18 | 18 |
| write_format_ar | 0 | 1 | 1 |
| write_format_cpio | 0 | 5 | 5 |
| write_format_iso | 0 | 17 | 17 |
| write_format_mtree | 0 | 32 | 35 |
| write_format_raw | 0 | 2 | 2 |
| write_format_shar | 0 | 2 | 2 |
| write_format_tar | 0 | 13 | 13 |
| write_format_warc | 0 | 6 | 6 |
| write_format_xar | 0 | 7 | 7 |
| write_format_zip | 0 | 21 | 21 |
| other | 12 | 96 | 139 |

Remaining stubs (`src/ffi/stubs.rs`): 157
`unsafe` in `src/` (excluding stubs.rs): 104

## Phase 2 checkpoint

Complete under the safe-backend policy. All planned read filters are registered;
XZ/LZMA/lzip and bzip2 use safe builds of lzma-rust2 and crabz2. LZ4 block-ending
validation matches the oracle. Backend limits and damaged-input differences are
recorded in NOTES.md; optional external filters still require their programs.

Verification: 242 Rust tests, strict Clippy and rustfmt; 86/86 ratchet tests;
18/18 bsdcat tests. Selected filter fixtures: 77/78 byte-identical; the remaining
corrupt bzip2 fixture fails in both libraries with different partial output.
Tests ran sequentially. The ISO fuzz timeout in the initial 5s run passed its
60s recheck. The full suite is not green: most archive readers and writers remain unported.
