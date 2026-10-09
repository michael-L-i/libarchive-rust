# Notes

Suspected upstream bugs ported as-is, and deliberate divergences, per unit.

## Core (`archive_util`, `archive_check_magic`, `archive_virtual`)

### Ported as-is

- `archive_write_fail` returns the new state (`ARCHIVE_STATE_FATAL`, 0x8000),
  not `ARCHIVE_FATAL` (archive_virtual.c).
- `__archive_check_magic` lists unknown bits of a state mask as `??`, so a
  check against `ARCHIVE_STATE_ANY` prints `.../closed/??/??/...`
  (archive_check_magic.c).

### Differences

- `archive_version_details` always ends its backend list with
  `libb2/bundled`, because BLAKE2 is built in. No C XML, regex or crypto
  library is linked, so those sections never appear. The compression
  backends are Rust crates, so each `archive_*_version` reports the crate,
  not the C library: the backend's own version string where it has a
  meaningful one (`BZ2_bzlibVersion`), otherwise `<crate> <version>` read
  from `Cargo.lock` by `build.rs`, e.g. `zlib/miniz_oxide 0.9.1`. ACL
  backends are absent until phase 5 (archive_version_details.c).
- NULL handles: upstream dereferences them and crashes (except
  `archive_free(NULL)`, which returns `ARCHIVE_OK`). Ours return a fallback
  (`ARCHIVE_FATAL`, 0 or NULL) without touching anything.
- Calling a function on the wrong kind of handle: upstream calls through the
  handle's vtable, so an operation the kind lacks (`archive_write_data` or
  `archive_read_next_header` on the wrong handle) is a call through a NULL
  pointer and crashes, except `archive_write_data_block`, which checks and
  fails with "archive_write_data_block not supported". Ours fail with
  `ARCHIVE_FATAL` for the same operations and keep that one message.
  `archive_read_close` on a write handle closes it upstream (the vtable
  entry is the write one); ours checks the magic and fails with the
  PROGRAMMER ERROR message. `archive_read_free` and `archive_write_free`
  both remain aliases of `archive_free`.
- `archive_write_data` and `archive_write_data_block` reject a size above
  `isize::MAX`, or a NULL buffer with a non-zero size, with `ARCHIVE_FATAL`
  (no message) instead of reading out of bounds.
- `archive_set_error` (`src/ffi/variadic.c`) formats with libc `vsnprintf`,
  not upstream's `archive_string_vsprintf`. Upstream supports only `%%`, `%c`,
  `%s`, `%d`, `%o`, `%u`, `%x`, `%X` and `%S`, with the length modifiers `l`,
  `ll`, `j` and `z`; anything else (including width, precision, flags, `%i`
  and `%p`) it prints literally from the `%`. libc handles all of those
  (`%jd`, `%ju`, `%zd`, `%llu` identically), so a message that relies on
  upstream printing an unsupported conversion verbatim would differ.
  A NULL `%s` prints `(null)` in both (glibc and macOS libc do the same).
  `%S` and `%ls` are converted to multibyte by the C locale in libc, but to the archive's charset by
  `archive_string_append_from_wcs`, replacing unconvertible characters with
  `?`. If libc fails to format (`vsnprintf` returns a negative value, for
  example on an unconvertible wide character) or `malloc` fails, upstream
  would still have produced text; we store the unformatted `fmt` rather
  than clearing the message.
- `__archive_rs_set_error` is an exported dylib symbol. Upstream's dylib
  also exports its internal `__archive_*` functions, so this is not a new
  kind of leak.

## archive_string (`src/string.rs`)

Suspected upstream bugs, ported as-is:

- `create_sconv_object` tries `iconv_open("SJIS", ...)` as a fallback for
  `CP932` only `if (sc->flag & SCONV_BEST_EFFORT)`, but `sc->flag` is still
  zero there (`sc->flag = flag` is assigned later). The fallback is
  unreachable, so a missing `CP932` in iconv is never retried as `SJIS`. Not
  ported (it would be dead code).
- `find_sconv_object` compares the caller's raw charset names with the
  canonicalized names stored in the cache. A request for `"utf8"` never
  finds the `"UTF-8"` object it created before, so each such request makes
  a new object and adds it to the list.
- `cesu8_to_unicode`: for a lone high surrogate (`ED A0..AF xx`) followed by
  at least three more bytes that are not a low surrogate, the invalid-sequence
  path returns the length of the second sequence (`cnt` was overwritten by
  the second `_utf8_to_unicode` call) instead of 3. A following ASCII byte
  makes it consume only 1 byte, so the surrogate yields three U+FFFD
  instead of one. If the second sequence starts with NUL it returns 0 (the
  end-of-string value); `strncat_from_utf8_to_utf8` then loops forever
  appending U+FFFD. That cannot happen through `archive_strncat_l`, which
  stops at the first NUL, and the port ends the string there instead.
- `iconv_strncat_in_locale` treats any `iconv` error other than
  `EILSEQ`/`EINVAL` like `E2BIG` and retries forever; for UTF-16 input it
  does `remaining -= from_size` with no check that `remaining >= from_size`.
  The port stops with failure on other errors and cannot underflow.
- `archive_mstring_get_mbs` and friends report conversion failure only through
  `-1` and `errno`; `archive_entry_pathname` then tests `errno == EILSEQ`.
  There is no errno here: every failure is `Err(ConvFailed)`, and the entry
  port should fall back to the UTF-8 form on any error (a failure that is not
  EILSEQ-like can't happen: the only other errno is ENOMEM).

Divergences:

- Windows code (`_WIN32` paths, code pages, `cd_w`) is not ported.
- The libarchive-2.x UTF-8 converter (`SCONV_UTF8_LIBARCHIVE_2`,
  `strncat_from_utf8_libarchive2`) is not ported: `set_opt` ignores that
  option wherever upstream's guard (`__STDC_ISO_10646__ || __APPLE__`)
  holds: macOS and glibc. musl defines neither, so on musl upstream would
  enable it; musl is not a supported target for this option here.
- `archive_string_sprintf` is not ported; callers use `format!`.
- `archive_string_default_conversion_for_read` and `_for_write` are not
  ported: only Windows has one, so the readers and writers pass no
  conversion.
- Output is not NUL-terminated and buffers are `Vec`s, so the buffer-extent
  assertions of `test_archive_string` have no equivalent.
- A string conversion error is returned as `ConvError { errno, message }`
  where upstream calls `archive_set_error(a, ...)`; the caller sets it.
- On macOS the `ru_RU.KOI8-R` locale fails upstream's `setCheckedLocale`
  check (0xE1 does not decode to U+0410), so upstream's
  `test_archive_string_update_utf8_koi8` skips there; a variant that checks
  only the multibyte forms runs instead.

## archive_entry and archive_acl (`src/entry*.rs`, `src/acl.rs`)

Suspected upstream bugs, ported as-is:

- `archive_entry_clear` ends in `memset(entry, 0, ...)`, which also zeroes
  `entry->archive`. The reader clears the entry before every header, so an
  entry made by `archive_entry_new2(a)` loses its conversion cache (and with
  it the place where conversion errors would be reported) after the first
  `archive_read_next_header`. Ours forgets the cache the same way.
- `archive_entry_xattr_add_entry` prepends, so `archive_entry_clone`, which
  adds the attributes in list order, reverses them. Ours does too.
- `archive_entry_clone` does not copy `mset_digest` (the bitmap of digests
  set, which the mtree writer reads), so a clone has digest bytes but no
  record that they are set. Ours does the same.
- `isint`/`isint_w` reject `INT_MAX` itself: the overflow test uses
  `digit >= INT_MAX % 10` where `>` would be exact, so a numeric ACL id of
  2147483647 makes the entry invalid.
- `ismode`, `is_nfs4_perms` and `is_nfs4_flags` leave the bits they found so
  far in `permset` when they fail. For a Solaris-style `other:rw?` entry the
  failed `ismode` leaves a non-zero `permset`, which makes the later
  `permset == 0` test skip the mode check, so the entry is accepted with the
  partial permissions.
- The narrow (`archive_acl_from_text_nl`) and wide (`archive_acl_from_text_w`)
  parsers differ: the narrow `next_field` ends a field at the first
  whitespace (`user:big bob:r-x` names `big`), the wide one keeps internal
  whitespace in the name. Both are ported as they are.
- NFSv4 text `user:100:...` passes `100` on as the entry's name as well as
  its id.
- `archive_acl_next` leaves `*type`, `*permset` and `*tag` untouched when it
  returns `ARCHIVE_WARN`; ours does too.
- `archive_acl_to_text_w` leaves out an entry whose name does not convert to
  wide characters, but `archive_acl_to_text_l` fails as a whole.
- `FIX_NS` overflows (undefined behavior in C) for a huge `t`; ours wraps.

Differences:

- `archive_entry_pathname` falls back to the UTF-8 form on any conversion
  error, where upstream does so only for `EILSEQ`; the other error it can
  see is `ENOMEM`, which aborts there.
- A NULL entry: upstream dereferences it (except `archive_entry_free(NULL)`
  and `archive_entry_clear(NULL)`, which return). Ours return 0 or NULL.
  `archive_entry_xattr_add_entry` with a NULL name or value, and
  `archive_entry_set_digest` with a NULL digest, do nothing (the latter
  returns `ARCHIVE_WARN`) instead of crashing.
- `archive_entry_acl_to_text` and `archive_entry_acl_to_text_w` return
  `malloc`ed memory that the caller frees, as upstream does; only the
  deprecated `archive_entry_acl_text` and `archive_entry_acl_text_w` keep
  their text in the ACL until the next call or change.
- The file flag tables cover macOS (`SF_*`, `UF_*`) and Linux (`FS_*_FL`,
  with the `linux/fs.h` values); other platforms have no flags, where
  upstream would use the BSD or Windows lists.
- `archive_entry_copy_bhfi` (Windows) and the deprecated, unexported
  `archive_entry_acl_text_l` are not ported. The `_l` locale variants of the
  setters and getters are methods on `Entry` for the readers and writers, not
  exports, as in upstream.
- `st_birthtime` is filled and read only where `struct stat` has it (macOS);
  elsewhere `archive_entry_copy_stat` unsets the birth time as upstream's
  fallback does.

## archive_entry_link_resolver (`src/entry_link_resolver.rs`)

Suspected upstream quirks, ported as-is:

- `archive_entry_linkresolver_new` callocs the strategy, so a resolver that
  never had `set_strategy` called matches like tar (strategy 0), not like old
  cpio. Ours does the same.
- An entry with `nlink` 0 gets `links = nlink - 1`, which wraps to `UINT_MAX`
  as an unsigned int. Under the new-cpio strategy such an entry is held until
  the resolver is freed, and `archive_entry_partial_links` reports that huge
  count.

Differences:

- NULL resolver: upstream crashes. `archive_entry_linkify` leaves `*e` alone
  and sets `*f` to NULL; `set_strategy` and `free` do nothing;
  `archive_entry_partial_links` returns NULL with `*links` set to 0.
- NULL `e` or `f` pointer in `archive_entry_linkify`: upstream crashes. Ours
  skips the output that is missing.
- The Windows `archive_entry_copy_hardlink_w` path (`_WIN32` without Cygwin)
  is not ported. The narrow hardlink copy is used everywhere.
- The held-back entries and the canonical clones are owned by the resolver as
  `Box<Entry>`, not as raw pointers. C never holds a pointer to them, because
  `archive_entry_linkify` swaps the pointers it hands out, so no pointer is
  aliased.

## Read core (`archive_read`, `archive_read_open_*`, options, passphrases)

### Ported as-is

- A read error or fatal state met while consuming (`__archive_read_consume`)
  replaces the error with "Truncated input file (needed N bytes, only 0
  available)" (archive_read.c).
- When a client has a seeker but no skipper, a skip of over 64k uses the raw
  client seek with `SEEK_CUR` and compares the node-relative offset it returns
  with the stream position, so it fails on any volume but the first of a
  multi-volume client (archive_read.c).
- Without a switch callback, a multi-volume client's closer is called on a
  volume when the reader moves on and again for every volume at close, so a
  closer that frees its data frees it twice (archive_read.c).
- `archive_read_set_format` for a format that failed to register leaves the
  active format unchanged; upstream leaves it pointing at an empty slot.
- `archive_read_data_into_fd` compares the absolute offset `lseek` returns
  with the entry offset when seeking over a hole, so it reports "Seek error"
  if the file was not at offset 0 when it started
  (archive_read_data_into_fd.c).

### Differences

- Client data: upstream dereferences a NULL dataset if `archive_read_open1` is
  called with a reader but no `archive_read_set_callback_data`. Ours reads
  one node with NULL data. `archive_read_open_memory` with a NULL buffer and a
  size, and `archive_read_open_FILE(NULL)`, fail with `ARCHIVE_FATAL` and
  EINVAL instead of crashing.
- `archive_read_extract_set_skip_file`'s device and inode are also provided by
  the filename client for its current file (`Client::skip_file`), where
  upstream's open callback sets them as a side effect.
- Format cleanup is `Drop`; there is no `cleanup` callback. Formats and
  bidders are dropped with the handle, after the client callbacks have run.
- `Format::read_data` that fails with `ARCHIVE_WARN` hands no data to
  `archive_read_data_block`; upstream leaves whatever the format stored in the
  out parameters (no in-library caller looks at it).
- `data_start_node` and `data_end_node` are not kept; nothing reads them.
  `read_data_is_posix_read` and `read_data_requested` are not kept either;
  only the rar reader uses them, and it will get them through `Reader` when
  it is ported.
- Disk-like device detection for FreeBSD, NetBSD, OpenBSD and DragonFly
  ioctls (archive_read_open_filename.c) is not ported; only regular files
  and, on Linux, block devices count.
- Passphrases are zeroed before they are freed (behind `black_box`), as
  upstream does with `memset`.
- `archive_read_data_into_fd`: a `write` that returns 0 for a non-empty
  buffer is a "Write error" (EIO); upstream loops forever. Offsets use
  checked subtraction; one that overflows is an overrun.
- A C open or switch callback that returns `ARCHIVE_WARN` is a failure and
  reports `ARCHIVE_FATAL`; upstream returns the warning from
  `archive_read_open1` (the archive is fatal either way). A close callback's
  warning during a volume switch is ignored; upstream treats it as a failed
  switch and the read ends there (archive_read.c).
- A C read callback that returns bytes with a NULL buffer fails with EINVAL
  ("Read callback returned a NULL buffer"); upstream copies from NULL.
- A read error during a format bid aborts the open with the client's recorded
  message. Upstream's `__archive_read_ahead` returns NULL there, so the bid
  returns 0 and "Unrecognized archive format" overwrites the message. The
  final code is `ARCHIVE_FATAL` either way (archive_read.c).

## Read filter uu (`src/read/filter/uu.rs`)

### Ported as-is

- The base64 bid accepts any first line made only of base64 characters,
  `=` included, and an empty line too. Upstream's `====` score after that
  test can never be reached, because the loop has already consumed the line,
  so it is not ported (archive_read_support_filter_uu.c).
- A body line that would take one `read` past 64k (`total + 2 * len`, so a
  line over 32k when it is the first of the block) ends that `read`. When
  nothing was decoded before it, the `read` returns nothing, which the core
  takes as end of stream, so the rest of the input is dropped without an
  error.
- Lines end at the first LF in the window, and a CR is a line end only when
  no LF is found in the window: `a\rb\nc` is the line `a\rb`. A lone CR that
  is the last byte in the window waits for one more byte (CR LF), and at the
  end of the input it ends the line.
- A final line without a newline is never a line, so `end` with no newline
  at the end of the input is "Insufficient compressed data".
- A header name of one byte is dropped (`namelen > 1`), and a name ends at
  a NUL.

### Differences

- The bidder's MINIX padding test (`if (len == 1 && ...) ++p; --len;`) is a
  no-op upstream: the next line read overwrites both `p` and `len`. It is not
  ported.
- Upstream's `read_line_ahead` computes `avail - offset` as a `size_t` for a
  line that starts past the 128k window, and its `memchr` then reads on past
  the buffered data. We search only the bytes buffered, so a line that
  upstream finds within its buffer is found the same way, and a line it
  would only find by reading out of bounds is not found. A line starting
  exactly at the window's end gets an empty window, as upstream.

## Gzip filter (`src/read/filter/gzip.rs`)

### Ported as-is

- The trailer's CRC32 and ISIZE are read and not checked (upstream's
  `XXX TODO: Verify`), and so is the optional header CRC. A member with a bad
  checksum decodes without error (archive_read_support_filter_gzip.c).
- Each header sets the mtime, but only a header with a file name sets the
  name. A later member without FNAME leaves the earlier name, which
  `read_header` then reports (`gzip_read_header` after `peek_at_header`).
- A truncated trailer fails with `ARCHIVE_FATAL` and no message, because
  upstream's `__archive_read_filter_ahead` sets none at end of input.
- A read error met while reading a header is a missing header, so the stream
  ends cleanly there, as upstream's NULL from `__archive_read_filter_ahead`
  does. A read error met in the deflate data reports "truncated gzip input".
- The 1 MiB limit on a file name or comment is checked against the bytes
  buffered so far, as upstream checks its buffer. Where a too-long field is
  rejected therefore depends on the read block size, in upstream too.

### Differences

- `archive_zlib_version()` reports `miniz_oxide <version>`, not
  `ZLIB_VERSION` (see Core).
- Decompression is miniz_oxide's streaming inflater in raw mode, called
  directly; flate2 is not a dependency. flate2 always enables miniz_oxide's
  `simd` feature, which pulls in simd-adler32 (SIMD intrinsics, `unsafe`).
  Raw deflate needs no Adler-32, and the gzip trailer's CRC32 is not checked,
  as upstream. miniz_oxide has `#![forbid(unsafe_code)]`, and its one other
  dependency, adler2, forbids `unsafe` too. On valid input the output is
  byte-identical: `diff-cat '*.gz*' '*tgz*'` shows 12 same, 0 differ, and the
  one timeout (`test_read_filter_gzip_recursive.gz`) is the oracle's too.
- Corrupt deflate data is the one place the output can differ. Every
  difference found has one cause: a back-reference whose distance reaches
  before the start of the member's output. zlib rejects it ("invalid distance
  too far back"). miniz_oxide's streaming decoder checks the distance only
  against its 32 KiB window, which starts zeroed, so the copy yields zero
  bytes and decoding goes on. Its strict check runs only on a first call with
  `MZFlush::Finish` that gets the whole member at once, which a streaming
  reader can't use. This accepts corrupt input, never unsafe, and only that
  input; the cost is the fidelity of this one class, traded for the safe
  backend under the safe-dependency rule.
- Differential run: 969 inputs, oracle vs port `bsdcat` on stdout, stderr and
  status. 639 truncations of 11 base streams (8 one-member, 3 two-member),
  all identical. 330 files with 1-3 random byte changes: 270
  identical, 60 differ, all on corrupt input the oracle rejects:
  - 58: upstream fails with "gzip decompression failed" and no output (status
    1); the port exits 0 with output. 50 are in the first member of a file
    and 8 in the second member of a two-member file. zlib (checked with
    Python's zlib on the same deflate data) reports "invalid distance too far
    back" for all 58. Example: a one-member file of 300 bytes at level 1 with
    a few bytes of its deflate data changed gives 324 bytes here and no output
    upstream.
  - 2: both fail with status 1. The port accepts the invalid back-reference,
    so its data ends before the 8-byte trailer and the trailer read fails with
    no message. Upstream says "gzip decompression failed". Minimized example,
    a 20-byte member, with the deflate data `03 61`, then eight zero trailer
    bytes:
    `1f 8b 08 00 00 00 00 00 00 03 03 61 00 00 00 00 00 00 00 00`.
    Upstream reports "gzip decompression failed"; here the error has no
    message. Test: `a_back_reference_before_the_start_is_accepted`.
  - No case where the port fails and upstream succeeds.
- The `inflateInit2` and `inflateEnd` failures upstream reports ("Internal
  error initializing compression library", "Failed to clean up gzip
  decompressor") cannot happen with miniz_oxide, so they are not ported.

## xz, lzma and lzip filters (`src/read/filter/xz.rs`)

### Differences

- liblzma is replaced by the pure Rust `xz` crate (a port of liblzma
  5.8.3; the oracle links 5.8.4; `archive_liblzma_version` reports
  `xz <version>`, see Core). The crate has the same stream API, so
  the error messages and which input is rejected match; a bug fix between
  5.8.3 and 5.8.4 could differ on unusual damaged input. `LZMA_MEMLIMIT` is
  disabled as upstream does for liblzma 5.
- The "Using external xz program" fallback is not ported: the decoder is
  always built in.
- A read error while a filter bids is passed up as a failure where
  upstream's bid returns 0 (see the read core notes). The same goes for the
  `lzip_has_member` call in `lzip_tail`: a read error right after a lzip
  trailer is fatal here, but upstream reads it as a clean end of input.
- The `xz` crate's `xz-core` is a c2rust translation of liblzma with about
  1,000 `unsafe` blocks. It is pure Rust but not safe Rust, so this path
  does not yet meet the project's memory-safety goal. A safe Rust decoder
  with liblzma's stream semantics is a tracked follow-up.
- `lzip_init` does not re-check the dictionary size: `lzip_has_member` has
  already validated every header it reads.

## Read filters: compress (.Z) and rpm (`src/read/filter/compress.rs`, `rpm.rs`)

Ported as-is:

- The first code is decoded in `compress_filter_init` and its result is
  ignored, so an invalid first code does not stop decoding: the second code
  decodes from the stream. The error it set ("Invalid compressed data",
  errno -1) stays on the handle until the first header read clears it, so
  the handle reports it after `archive_read_open` succeeds
  (archive_read_support_filter_compress.c).
- A reset clears only `bits_avail`, so the bits left in `bit_buffer` are
  ORed under the next byte. This matters only when the padding count is zero.
- Truncated compress input is the end of the input, not an error: the output
  so far is returned. A cut inside a code or inside the reset padding ends
  the stream the same way.
- An rpm whose payload is shorter than 16 bytes after the last header fails
  with `ARCHIVE_FATAL` and no message (`(null)` from bsdcat), because upstream
  reads 16 bytes to look for another header before it reaches the payload.
  `skip_padding` at end of input fails the same way.

Differences:

- The compress stack is a `Vec` rather than a fixed 65300-byte array. Its
  length is bounded by the 65536-entry dictionary (at most 65282 bytes), so
  it cannot grow past upstream's bound.
- The rpm filter copies each payload block into its own block, the one copy
  the `Filter` API needs for a pass-through. Upstream returns the stage's
  bytes in place.
- The bidders propagate a read error with `?`, so the open fails with the
  client's message. Upstream's bid returns 0 there, the same divergence the
  read core records for format bids above.

## External program filter (`archive_cmdline`, `filter_fork_posix`, `program`)

### Ported as-is

- A signature bidder does not inhibit itself: a program whose output still
  starts with the signature is bid on again, until the filter limit.
- A child that exits non-zero (or dies of a signal other than SIGPIPE) makes
  the read fail with `ARCHIVE_FATAL` and loses the block being filled; the
  same warning is reported again at close (archive_read_support_filter_program.c).
- Writing to a child that has exited raises SIGPIPE in the caller unless the
  application ignores it, as upstream does.

### Differences

- The child is started with `std::process::Command` (`posix_spawn` or
  `fork`+`exec`, as std chooses). A program that cannot be found fails at
  open with "unable to run program". That matches upstream on macOS, which
  uses `posix_spawnp`; upstream's Linux `fork` path instead starts the child
  and sees exit status 254 on the first read.
  Descriptors the application left inheritable are not closed in the child
  (upstream closes all above 2 on the `fork` path); std's own pipes are
  close-on-exec.
- A NULL command, which crashes upstream, fails with `ARCHIVE_FATAL`. A
  signature longer than `INT_MAX/8` fails with FATAL "Signature too large", as
  upstream does; only a length above `isize::MAX`, which no slice can have,
  is ignored.

## grzip, lrzip and lzop filters

### Differences

- lzop: upstream decodes with liblzo2 when it is compiled in. The oracle
  build has none, so the port mirrors that configuration: it always runs
  `lzop -d` and `archive_read_support_filter_lzop` returns `ARCHIVE_WARN`
  ("Using external lzop program for lzop decompression"). The liblzo2 path
  (`lzop_filter_read` and its block and checksum handling) is not ported.

## lz4 filter (`src/read/filter/lz4.rs`)

Upstream's frame parsing is ported. The block decoder is `lz4_flex` 0.14.0
with `safe-decode` and `safe-encode`, and the frame header and block checksums
use `xxhash-rust` 0.8.19 (`xxh32`). That build compiles four `unsafe` blocks
inside `xxhash-rust` (three in `utils.rs`, one in `xxh32.rs`); none is in this
crate.

### Ported as-is

- An empty frame, or a block that decodes to zero bytes, ends the stream: the
  frames after it are never read. This holds for any frame, the first or a
  later one.
- A block header of `0x80000000` (stored flag, size zero) is decoded as a
  compressed block of zero bytes, which fails with `lz4 decompression failed`.
  The legacy format has no stored flag, and its zero-length block fails the
  same way.
- A zero-length legacy block is a decompression failure
  (`lz4 decompression failed`), where a zero-length LZ4 block is the end of
  the stream.
- Bytes after the last frame that are not a frame are ignored silently; so is
  a trailing 1 to 3 bytes.
- A linked block refers back to the previous block only, not the output
  before it. A previous block shorter than 64 KiB leaves the rest of the
  window zero-filled, so the back-references see zeros, not the older output.
- The preset dictionary flag is read and ignored; the frame is decoded with no
  dictionary, as upstream does.
- `Malformed lz4 data` (capital M) is upstream's message for a bad skippable
  frame; the other malformed messages are lowercase.

### Differences

- `archive_liblz4_version` reports `lz4_flex <version>`, not the LZ4 library
  version: the oracle links Homebrew liblz4 1.10.0, and the backend here is a
  Rust crate (see Core).
- The adapter enforces liblz4's block-ending rules (five final literal
  bytes and twelve decoded bytes after the last match starts), which
  lz4_flex does not enforce. The malformed `hello` / `10 x 05 00 20 zz`
  linked-block example now fails with `lz4 decompression failed` as upstream
  does. The dependency remains built with `safe-decode` and `safe-encode`.
- Frame and block parsing and every checksum follow upstream
  (`DONT_FAIL_ON_CRC_ERROR` is not defined there, so checksum errors fail).

Oracle notes:

- All 5,838 generated truncations and mutations of the 17 upstream lz4 fixtures
  match the oracle: stdout, exit status and stderr. An earlier run showed 553
  stdout differences where the oracle emitted nothing. They came from the uu
  bidder's search window (fixed on main by `0c8ecb6`), not from this filter.

Phase 5 look-ahead: `lz4_flex` (feature `frame`) has a frame writer with
linked or independent blocks and block and content checksums, which is the
frame format `archive_write_filter_lz4` needs. It does not write the legacy
format, so that part would need our own encoder.

## Read filters: bzip2 and zstd (`src/read/filter/bzip2.rs`, `zstd.rs`)

Backends, and why:

- bzip2 is `bzip2` 0.6.1 over libbz2-rs-sys 0.2.5. libbz2-rs-sys is a
  c2rust translation (142 mentions of `unsafe` in 8 files) and is tracked for
  replacement. The safe candidate, `bzip2-rs` 0.1.2 (`#![forbid(unsafe_code)]`),
  was tested and rejected. Over our 726 bzip2 inputs it agrees with the
  oracle on 504 and differs on 222: 144 of 150 mutated streams, 76 of 495
  truncated prefixes, the concatenated pair (780 bytes against 1480, because
  `DecoderReader` stops at the first stream), and empty input (upstream
  outputs nothing; `bzip2-rs` errors). Its `Decoder` buffers a whole block
  before decoding it. The `bzip2` wrapper has 18 mentions of `unsafe` of its
  own (`mem.rs`).
- zstd is `ruzstd` 0.9.0, a safe decoder with 41 mentions of `unsafe` in its
  ring buffer and decode buffer, and no crate-level `forbid`. Its checksum
  comes from twox-hash (84 mentions). `libzstd-rs-sys` was tried and dropped:
  it is a c2rust translation of a libzstd dev snapshot, and it is not what
  upstream links.

Differences:

- `archive_bzlib_version` reports the backend's `BZ2_bzlibVersion` string
  ("1.1.0-libbz2-rs-sys-<version>"), not "1.0.8, 13-Jul-2019".
- `archive_libzstd_version` reports `ruzstd <version>`. ruzstd has no libzstd
  version, so this is not a libzstd number.
- zstd output on truncated or corrupt input. ruzstd keeps the last window of
  decoded output inside the frame until the frame finishes
  (`decode_buffer.rs`: `read` returns only bytes beyond the window while the
  frame is open). A failed frame never finishes, so that window is never
  delivered, and libzstd delivers it. Measured on one zstd frame of a
  3,000,226-byte text (1.8 MB compressed, window 256 KiB): 160 corrupt or
  truncated files, all of which error. The port delivers fewer bytes in 70 of
  them: 55 of 60 truncations and 15 of 100 single-bit flips in the second half
  of the frame. In total 9,437,184 bytes; the other 90 files are identical.
  The shortfall is at most the frame's window, or everything decoded so far
  for a frame smaller than its window: a truncated 720 KB frame with a 2 MiB
  window gives libzstd's 262,144 bytes against the port's 0, and 97 of 107
  truncations in a second corpus of small frames show this. The same test on
  bzip2 (`libbz2-rs-sys`) is identical on all 160 files. The public ruzstd API
  has no way to drain the open window, so this can only be fixed in ruzstd.
- zstd error text. Where a ruzstd error class has a libzstd equivalent, the
  filter reports libzstd's text ("Unknown frame descriptor",
  "Frame requires too much memory for decoding", "Dictionary mismatch",
  "Restored data doesn't match checksum"). Otherwise it reports "Data
  corruption detected". Measured on 1359 zstd inputs (truncations, mutations,
  skippable frames, reserved bit, trailing bytes): stdout and exit status
  match in all of them, and 11 differ only on stderr. Random mutations of
  block contents differ more: of 1,500, stdout differs in 203, stderr in 195
  and exit status in 47 (42 mutants of a checksum-free stream that libzstd
  accepts and ruzstd rejects; 5 corrupt empty frames that libzstd rejects and
  ruzstd accepts with empty output). Of the 11, seven are a corrupt
  block that ruzstd decodes and then fails the checksum, where libzstd
  reports "Data corruption detected". Four are malformed blocks that libzstd
  calls "Dictionary is corrupted", which ruzstd does not separate from other
  corruption.
- The filter checks the frame header's reserved bit (0x08) itself, and
  reports "Unsupported frame parameter", as libzstd does. Ruzstd does not
  check it.
- A window log above 31 is refused as "Frame requires too much memory for
  decoding". This is what libzstd reports for the frames in the corpus.
- One to three trailing bytes after a frame are "Unknown frame descriptor"
  unless they are a prefix of a magic number (a regular or skippable one),
  which is "Truncated zstd input". The filter checks this itself.
- The filter skips skippable frames and checks each frame's content checksum,
  since ruzstd does neither. The window limit is libzstd's default, 128 MiB.

Phase 5 needs:

- zstd writing. ruzstd's encoder implements only the Uncompressed and Fastest
  levels. Default, Better and Best hit `unimplemented!()`, so phase 5 needs
  another encoder for the default levels.
- bzip2 writing. The safe `bzip2-rs` has no encoder, so bzip2 writing stays on
  `bzip2`'s encoder over libbz2-rs-sys unless a safe encoder is found.
