# libarchive-rust status

Date 2026-10-08. Upstream pin `8bb3bbdc`. Run: port.

**Passing 491 / upstream 829 / 934 total**

| Area | Ours | Upstream | Total |
|---|---:|---:|---:|
| acl | 15 | 19 | 21 |
| archive | 18 | 123 | 134 |
| cat | 18 | 18 | 18 |
| compat | 28 | 29 | 30 |
| cpio | 1 | 43 | 49 |
| entry | 3 | 3 | 3 |
| fuzz | 9 | 9 | 9 |
| read_filter | 14 | 15 | 19 |
| read_format_7zip | 56 | 56 | 56 |
| read_format_ar | 1 | 1 | 1 |
| read_format_cab | 9 | 9 | 10 |
| read_format_cpio | 24 | 24 | 35 |
| read_format_empty | 1 | 1 | 1 |
| read_format_huge | 1 | 1 | 1 |
| read_format_iso | 19 | 19 | 19 |
| read_format_lha | 6 | 6 | 7 |
| read_format_mtree | 13 | 13 | 13 |
| read_format_rar | 37 | 37 | 42 |
| read_format_rar5 | 77 | 77 | 78 |
| read_format_raw | 1 | 1 | 1 |
| read_format_tar | 33 | 33 | 41 |
| read_format_warc | 6 | 6 | 6 |
| read_format_xar | 10 | 10 | 10 |
| read_format_zip | 75 | 98 | 110 |
| tar | 0 | 72 | 79 |
| unzip | 29 | 29 | 30 |
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
| other | 35 | 96 | 139 |

Remaining stubs (`src/ffi/stubs.rs`): 141
`unsafe` in `src/` (excluding stubs.rs): 112

## Phase 2 checkpoint

Complete under the safe-backend policy. All planned read filters are registered;
XZ/LZMA/lzip and bzip2 use safe builds of lzma-rust2 and crabz2. LZ4 block-ending
validation matches the oracle. Backend limits and damaged-input differences are
recorded in NOTES.md; optional external filters still require their programs.

## Phase 3 checkpoint

Complete. The six small readers are registered: raw, empty, ar, cpio, warc and
mtree (with `archive_pack_dev`). Every `read_format_{ar,cpio,mtree,warc}` test
that passes upstream passes here; the cpio charset tests skip as they do
upstream. `test_compat_cpio`, `test_ar_mode` and `test_read_set_wrong_format`
also pass. Each unit was reviewed in a fresh context; quirks ported as-is and
the few differences (mtree shares `/set` options between entries, so memory
stays bounded) are in NOTES.md.

The bsdtar and bsdcpio front-end suites still fail at startup: both call
`archive_match_new`, a stub until phase 5.

Verification: 246 Rust tests, strict Clippy and rustfmt; all suites 133 pass,
0 regressions.

## Phase 4 checkpoint

Complete under the safe-backend policy. The nine large readers (tar, ISO9660,
CAB, LHA, ZIP, XAR, RAR, RAR5 and 7zip), PPMd decoders and crypto helpers are
merged and registered. Decoder limits and upstream/backend differences are
documented in NOTES.md. Embedded ZIP and 7zip LZMA/XZ dictionaries and 7zip
PPMd models are capped at 256 MiB before allocation.

Verification: 332 Rust tests, strict all-target Clippy, rustfmt, and all 454
public ABI symbols. Full upstream/front-end run: 539 pass (491 libarchive),
276 fail, 177 skip, 117 crash, 1 timeout; zero ratchet regressions. All 539
passing tests are recorded in tests/passing.txt. Both RAR multivolume tests
pass after ZIP integration; bsdcat passes 18/18 and bsdunzip passes 29/29
applicable tests.

The full suite is not green. ZIP's 23 failing format tests depend on Phase 5
writers or extraction; NOTES.md lists them. The test_read_pax_truncated timeout
also depends on writer stubs: its archive size remains uninitialized after
writer setup fails, so its loop has no valid bound. Phase 5 remains unported.
The final suite ran sequentially with 15-second process-group timeouts.
