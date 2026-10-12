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
  not the C library: `<crate> <version>` read from `Cargo.lock` by
  `build.rs`, e.g. `zlib/miniz_oxide 0.9.1`. Darwin ACL support uses
  native system APIs and has no separate linked-library version.
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
- On macOS the port converts with the system `iconv` (libc), while the
  oracle build links Homebrew's GNU libiconv. They differ on some legacy
  charsets: under `ru_RU.KOI8-R`, `ja_JP.eucJP` or `ja_JP.SJIS` with
  `hdrcharset=CP932` or ISO-8859-1, the system `iconv` transliterates or
  accepts bytes GNU libiconv rejects (`café` reads as `caf'e`; `\xff\xfe`
  converts from CP932 instead of failing with "... can't be converted").
  The conversion code is the same; only the library differs. Seen in the
  tar reader's differential runs; all other locale and charset
  combinations matched.

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
  `read_data_is_posix_read` and `read_data_requested` are one `Option` in
  `Base` (`Reader::read_data_requested`), set while `archive_read_data` asks
  the format for a block; only the rar reader looks at it. Its `seek_data`
  asks for `__archive_reset_read_data` with `Reader::reset_read_data`, which
  the core does after the call returns.
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

- liblzma is replaced by the safe Rust `lzma-rust2` crate (default features
  off, so `forbid(unsafe_code)` holds; its `optimization` feature is the only
  `unsafe`). Its sans-I/O `XzStream` and `LzmaStream` take `lzma_code`'s
  place: `XzStream` for xz (concatenated streams, padding, CRC32, CRC64,
  SHA-256 and no check), `LzmaStream` for lzma_alone (known size or end
  marker) and for the raw LZMA1 of a lzip member. The one dependency with
  `unsafe` is `sha2` (via `cpufeatures`), for the xz SHA-256 check.
  Decoder memory is capped at 256 MiB before dictionary allocation; oversized
  xz, lzma and lzip dictionaries fail with ENOMEM. Upstream disables its
  memory limit, so unusually large valid dictionaries are rejected here.
  The earlier backend review compared about 100,000 truncated and mutated
  streams; this integration also checks the pinned fixtures. The differences:
  - The error text is chosen from the `io::ErrorKind` of the failure, not
    from liblzma's status: corrupt input of any kind reads "Lzma library
    error: Corrupted input data" (liblzma says "format not recognized" for a
    bad magic number), input that ends too soon reads "No progress is
    possible", and "Invalid options" is kept for an unsupported filter.
    Every failure is fatal, as liblzma's are.
  - A .lzma stream with an end marker whose input is cut inside the last
    bytes of the range coder is accepted with its complete output, when the
    missing bytes are zero: `LzmaStream` decodes the last bytes of input
    against zero padding, and cannot say whether it did. liblzma fails with
    "No progress is possible". It turned up twice in the corpus; a cut
    lzip member is still caught by its trailer.
  - `XzStream` takes at most one delta or branch (BCJ) filter before LZMA2
    in a block. A block that chains several fails as unsupported where
    liblzma decodes it. (The ARM64 and RISC-V filters are supported.)
- The "Using external xz program" fallback is not ported: the decoder is
  always built in.
- A read error while a filter bids is passed up as a failure where
  upstream's bid returns 0 (see the read core notes). The same goes for the
  `lzip_has_member` call in `lzip_tail`: a read error right after a lzip
  trailer is fatal here, but upstream reads it as a clean end of input.
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
  bidder's search window (fixed on main by `62baf89`), not from this filter.

Phase 5 look-ahead: `lz4_flex` (feature `frame`) has a frame writer with
linked or independent blocks and block and content checksums, which is the
frame format `archive_write_filter_lz4` needs. It does not write the legacy
format, so that part would need our own encoder.

## Read filters: bzip2 and zstd (`src/read/filter/bzip2.rs`, `zstd.rs`)

Backends, and why:

- bzip2 is `crabz2` 0.7.0, built without default features, parallel decoding,
  or `unsafe-fast`; the crate enforces `forbid(unsafe_code)` and has no
  runtime dependencies. Its `BlockDecoder` supplies bounded bzip2 blocks,
  drained in 64 KiB output pieces. Compressed read-ahead is capped at 3 MiB
  per block, including Huffman tables. Concatenated members and trailing
  non-member bytes are supported. This replaces the c2rust libbz2 backend.
- `bzip2::Decoder` gives the zip, 7zip and xar readers a `BZ2_bzDecompress`
  step over crabz2's whole-block decoder: `decompress(input, output, last)`.
  It holds the compressed bytes of an unfinished block (at most 3 MiB) and
  decodes that block again when more input arrives. To keep that linear it
  enforces the input size: unless `last`, a call with fewer than `wanted()`
  bytes of input (the held bytes, at least 4096) consumes nothing and
  returns `Progress::default()`. Callers present `peek_available(wanted())`
  and set `last` when the read comes back short, from EOF or the packed-size
  limit. It consumes input only up to the end marker, as libbz2's
  `total_in` does, so `used` is exact and a zip data descriptor is not
  swallowed.
- zstd is `ruzstd` 0.9.0, a safe decoder with 41 mentions of `unsafe` in its
  ring buffer and decode buffer, and no crate-level `forbid`. Its checksum
  comes from twox-hash (84 mentions). `libzstd-rs-sys` was tried and dropped:
  it is a c2rust translation of a libzstd dev snapshot, and it is not what
  upstream links.

Differences:

- libbz2 accepts some corrupt streams that crabz2 rejects. In 100k fuzz
  cases every divergence was a single-bit flip in a tiny stream where libbz2
  returned `BZ_STREAM_END` with the right output length and this port
  returned an error (`InvalidHuffman`, `InvalidMagic`, ...).
- A truncated multi-block stream can deliver a different number of bytes
  before the error than libbz2 does: a reviewer saw `bsdcat` print 0 bytes
  for the oracle and 196608 for this port when a stream was cut at byte
  201578. The previous filter (main) behaves the same, so this predates the
  `Decoder`; truncations of two fixtures built here agree with the oracle.
- `archive_bzlib_version` reports `crabz2 <version>`, not libbz2's version.
- crabz2 checks a complete block's CRC before returning that block. A
  damaged block therefore delivers no partial bytes, where libbz2 can
  deliver some. The pinned `test_read_format_mtree_crash747.mtree.bz2`
  fixture errors in both libraries, but upstream delivers 131072 bytes and
  this port delivers none, so format detection fails differently: bsdtar
  reports "Unrecognized archive format" upstream and "bzip decompression
  failed" here. Legacy randomized bzip2 blocks are rejected by
  the safe backend. Valid ordinary and concatenated bzip2 fixtures match.
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

Round 12 decoder (`vendor/ruzstd/src/decoding`, see its `PATCHES.md`):

- A zstd block that decompresses to more than 128 KiB fails as "Data
  corruption detected". The format forbids such blocks and libzstd rejects
  them; ruzstd used to decode them, growing its buffer without bound. Of 2256
  valid and damaged archive cases, 8 changed, all bit flips: the old decoder
  went on to deliver garbage until tar failed, and the port now stops at the
  block, as upstream does (same status and message as upstream in 5 of them).
- The decoder no longer has a ring buffer with unsafe code: the vendored
  ruzstd decoder is safe Rust.

Phase 5 write adapters use crabz2 and a bounded ruzstd matcher; their
streaming behavior and encoder differences are recorded below.

## mtree reader (src/read/format/mtree.rs)

### Ported as-is

- A line with a non-printable character sets "Non-printable character
  0x%02X", but the reader then gives up as it does for any line it can't
  parse, and "Can't parse line N" replaces the message. Only the latter is
  ever seen, so ours sets only that.
- The printable check skips the last byte of the line, so a NUL or control
  character right before the end of the file is accepted.
- Read-ahead requests round up with `& ~1023U`, an `unsigned int` mask, so
  they are also cut to 32 bits.
- A read error while reading lines is the same as the end of the input
  (`__archive_read_ahead` returns NULL for both). The error stays recorded
  on the handle.
- An escape `\0` that isn't followed by an octal digit ends the name, `link`
  or `contents` value (the string is NUL-terminated there).
- Options are kept in a list that new ones are prepended to, and an entry
  starts with a copy of the `/set` options in the opposite order. Keywords
  are parsed in list order, so the order (and which of two keywords that
  set the same field wins) follows from that. Kept.
- An entry skipped as optional (`use_next`) leaves its fields in the entry
  for the next one, which resets only the file type and size, so a later
  entry that doesn't set uid, mtime and so on inherits the skipped one's.
- `mtree_atol` stops where an overflow is detected, so in `time=<huge>.5`
  the fraction isn't parsed.
- The bidder never consumes, so an input of nothing but comments is read
  ahead whole before it is rejected (a 64 MB input takes about 136 MB in both
  builds).
- A file with no entries is parsed again, with a new link resolver, on
  every `read_header`, because "entries is NULL" is what says the file has
  not been read.
- The type check against the file system compares `st_mode & S_IFSOCK`
  bitwise for sockets. The mtree keywords can't name a socket, so it never
  matches anything the plain comparison wouldn't.
- The `time` clamp to `TIME_MAX`/`TIME_MIN` does nothing with a 64-bit
  `time_t`; there it is omitted.

### Differences

- The bidder reads bytes past the end of the data it was given (`p[1]`
  after a `\`, `p[len-nl-1]`, `pb[1]`) where upstream reads whatever is
  next in the buffer, or outside of it. Ours reads NUL there.
- The file system is reached with `std::fs` (`File::open`, `metadata`,
  `symlink_metadata`), which opens with `O_CLOEXEC` like
  `__archive_ensure_cloexec_flag`.
- The `/set` options are a shared snapshot that entries point to, copied
  only when a `/set` or `/unset` changes them, and an entry keeps only the
  options of its own line. Upstream copies the whole list into every entry,
  which grows without bound with the input (a `/set` of 6000 keywords and
  30000 plain lines needs several GB). The options are merged when the
  entry is parsed, in upstream's order; the output is the same.

## warc reader (`src/read/format/warc.rs`)

### Ported as-is

- `time_t` -1 is the error value, so a time of exactly
  1969-12-31T23:59:59Z is an error too: a WARC-Date of that value fails with
  "Bad record time", and a Last-Modified of that value falls back to
  WARC-Date (archive_read_support_format_warc.c).
- The scheme is matched as a prefix: `filex:///p` is taken as `file`,
  `httpsx://h/p` as `http` and `ftpx://h/p` as `ftp`. For http and ftp the
  name is the path after the first slash following the host, so `ftp://host`
  has no name and the record is skipped.
- Field values are not trimmed at the end. `Content-Length: 12 ` (trailing
  blank) is "Bad content length", and `WARC-Type: resource ` is not a resource
  record. Leading blanks and tabs are accepted.
- Dates are not validated beyond their ranges: day 31 in February becomes
  March 3 and second 60 rolls into the next minute, as `timegm` does. Single
  digits are accepted in every field (`2014-1-2T3:4:5Z`).
- The four bytes after a record's content (its CRLFCRLF separator) are
  consumed without checking them, so a corrupt separator is skipped silently
  and the next header is read from wherever that lands.

### Differences

- `pver` and `sver` (the formatted WARC version) are set but never read
  upstream, so they are not ported.
- The `fname` scratch buffer is a per-entry `Vec` rather than state kept on
  the reader.
- The `time_from_tm` path for platforms without `timegm` (mktime and
  `tm_yday`) is not ported. Days are computed from the civil date, which is
  what `timegm` returns.

## cpio reader (`src/read/format/cpio.rs`)

### Ported as-is

- The TRAILER check compares only the first 10 bytes of the name, so a name
  of 11 bytes with any eleventh byte counts as the trailer
  (`archive_read_support_format_cpio.c`, `read_header`).
- `read_header` ignores the result of consuming the name's padding. A
  truncated input that ends inside that padding is recorded as "Truncated
  input file" but the header still returns `ARCHIVE_OK`; the next header read
  fails.
- The "Skipped N bytes before finding valid header" warning is not given when
  the header is at the start of a later search pass: the usual-case check
  returns `ARCHIVE_OK` before the skipped count is looked at. Bytes skipped
  in earlier passes go unreported in that case.
- afio large headers take the inode as `u & INT64_MAX`, because the code
  tests `ARCHIVE_VERSION_NUMBER < 4000000` and this tree is 3.9.0dev. A 4.0
  build keeps all 64 bits.
- `bid` returns `ARCHIVE_WARN` (-20) for input it does not recognize, not 0.
  The core only takes bids above the best so far, so this is harmless.

### Differences

- `compat-2x` is accepted and changes nothing. Upstream's default name
  conversion is `NULL` outside Windows, so there is no conversion for
  `compat-2x` to switch off.
- Name and symlink conversion failures are always the "can't be converted"
  warning. The string layer reports a failed conversion without an errno, so
  the `ENOMEM` branch upstream takes for a failed allocation cannot be told
  apart here.
- Hard links are kept in a `HashMap` keyed by device and inode, not a list.
  Upstream searches its list most-recent first, but each key is in the list
  at most once, so the result is the same. An entry is kept until its last
  link arrives, so the table holds one name per unfinished multiply-linked
  file, each at most 1 MiB, and grows with the archive as upstream's does.

## ar reader (`src/read/format/ar.rs`)

### Ported as-is

- `_ar_read_header` skips a `/` or `//` entry's data before consuming the 60
  header bytes. The total consumed is the same, so the order is harmless.
- `archive_read_format_ar_read_header` ignores a failed consume of the 8-byte
  global header. A truncated global header therefore reads as end of archive
  (ARCHIVE_EOF) with the consume's "Truncated input file" message left set.
- A GNU long name `/N` points into the filename table without checking that
  the characters after `/` are digits (the source has a TODO). `/9xyz` is
  entry 9.
- A GNU long name that points at an empty string (a table entry that starts
  with its NUL) gives an empty pathname, not NULL, so it is accepted as a name.

### Differences

- Upstream sets `ar->strtab` to the `malloc`ed table before reading it, so a
  failed read leaves a non-NULL table of uninitialized bytes. The port stores
  the table only after it is read and checked. After a fatal error the archive
  accepts no more headers, so the state is not observable.
- The table and BSD names are copied from what the archive actually holds,
  not allocated up front at the claimed size. The 1 GiB table limit and the
  1 MiB BSD name limit are the upstream ones.
- The BSD name check's `SIZE_MAX - 1` bound is implied by the 1 MiB bound and
  is not repeated.

## PPMd decoders (`src/ppmd7.rs`, `src/ppmd8.rs`, shared `src/ppmd.rs`)

The readers keep one long-lived `Ppmd7` / `Ppmd8` and call `free` where
upstream calls `Ppmd*_Free` and `Ppmd*_Construct`, instead of making a new
one; see the first entry.

### Ported as-is

- `InitEsc` survives `Free` and `Construct`. The RAR reader stores the
  block header's escape byte in `ppmd7_context.InitEsc` before it frees and
  re-creates the model, and the model reads it when a one-state context
  grows. The zip reader's `ppmd8` is part of the `calloc`ed `struct zip`, so
  the second PPMd8 entry of an archive starts with the escape estimate the
  first one ended with. `Ppmd7::init_esc` is public for RAR; the readers
  must not replace the `Ppmd7` / `Ppmd8` between streams.
- `Ppmd8_Init` accepts restore method 2 (upstream's FREEZE, which is not
  compiled in) and treats it like method 1, cut-off. The zip reader allows
  it.
- The PPMd7 range decoder in RAR mode never checks `Code` at the end, and
  the 7z one doesn't need to: `is_finished_ok` is only meaningful for 7z.

### Differences

- The arena reads as zero. Upstream leaves the `malloc`ed memory
  uninitialized, so a read of it (for example the stamp of a block the model
  never wrote) is undefined. The decoders never depend on the initial
  contents: upstream's C decodes the same symbols with the arena filled with
  0x00, 0xFF, 0xA5 or 0x01. The memory comes from `alloc_zeroed`, so large
  models commit pages lazily, like `malloc`.
- Anything upstream would do outside the arena (a read, a write, a search
  for a symbol that is not there, a free list that loops) marks the model
  bad, and `decode_symbol` returns -2 ("invalid data") from then on. A model
  the decoder built itself never does this; it is a guard, not a code path.
- The range decoders would divide by zero (`Range /= total` giving 0) or
  spin forever in `Normalize` (`Range == 0`) on some corrupt streams, and
  upstream crashes or hangs. We return -2 instead.
- `Ppmd8` `RestoreModel` in cut-off mode loops `CutOff` and `ExpandTextArea`
  until enough memory is free. With a tiny arena (a few KiB; the zip reader
  allocates at least 1 MiB) upstream can loop forever; ours gives up after
  1000 rounds and restarts the model.
- `Ppmd7::alloc` and `Ppmd8::alloc` take the size as `u32` like upstream and
  fail the same way (`false`) if it is below `UNIT_SIZE` (PPMd7 only) or the
  memory is not available.
- PPMd7 includes `Ppmd7z_RangeEnc_*` and `Ppmd7_EncodeSymbol` for the
  7zip writer. Encoding shares the checked arena and model update paths
  with decoding. PPMd8 encoding is not used by upstream writers.

## cab reader (src/read/format/cab.rs)

Suspected upstream bugs, ported as-is:

- `read_data_invoked` is set by the first `read_data` and never cleared, so
  once any entry has been read, skipping a later entry decompresses it
  (`cab_consume_cfdata`) instead of just counting `bytes_skipped`
  (archive_read_support_format_cab.c).
- A name longer than 255 bytes is "Invalid CAB header": the name is read
  with `cab_read_ahead_remaining(a, 256)` and must end inside that window.
- `cab_dos_time` hands the CFFILE date and time to `mktime` unchecked in the
  local time zone, so a month or day of 0 is normalized (month 0 is
  December of the year before) and the result depends on `TZ`.
- A failed CFDATA checksum is `ARCHIVE_FAILED` in `cab_checksum_finish`, but
  every caller turns any negative result into `ARCHIVE_FATAL`.
- `cab_read_data` returns `ARCHIVE_OK` with no data when the read-ahead of a
  non-empty CFDATA is empty, instead of an error.
- `lzx_decode_init` keeps the old window size in a `uint16_t`, so windows of
  64 KiB and more are reallocated for every folder. Here each folder gets a
  fresh decoder, which is the same thing.

Differences:

- `archive_format_name` is formatted ("CAB 1.3 (LZX)"), kept with
  `Base::set_format_name` in a buffer that is rewritten in place.
- MSZIP is inflated with miniz_oxide instead of zlib. `inflateSetDictionary`
  after each block is reproduced by decoding into a contiguous buffer that
  holds the previous block (the dictionary) in front of the new output, in
  non-wrapping mode, so valid data decodes identically. On corrupt data the
  `(%d)` in "Deflate decompression failed (%d)" is -3 (Z_DATA_ERROR) for
  any invalid data and -5 (Z_BUF_ERROR) when the CFDATA's compressed bytes
  run out; the exact point where a corrupt stream is noticed can differ
  from zlib's, as with the gzip filter.
- Every LZX table, window and position-slot access is bounds-checked; where
  upstream's invariants would be broken by corrupt input (a position slot
  or a table index out of range) the decoder fails with "LZX decompression
  failed (-25)". Huffman table writes that would leave the table fail the
  same way.

## iso9660 reader (src/read/format/iso9660.rs)

### Scope

- The pinned `archive_read_support_format_iso9660.c` has no path table
  reading, no El Torito boot catalog and no boot image entries. It scans
  directory records from the root, and a Boot Record descriptor is only
  recognized while bidding. The port has the same scope.

### Ported as-is (suspected upstream bugs)

- `bid` asks for 48 KiB (32 KiB reserved area and 8 descriptors) and gives up
  if the input is shorter, so a smaller image is never recognized.
- `parse_rockridge` returns `ARCHIVE_WARN` ("Tried to parse Rockridge
  extensions, but none found") for a record whose system use area has no
  SUSP entry, but both callers treat any non-OK result as failure, so one
  such record in an image with SUSP makes the whole read fail with
  `ARCHIVE_FATAL`. The port fails with that message.
- Looking for the "RE" directory of a "CL" file (`next_cache_entry`) pops
  entries from the RE list and puts the non-matching ones back, and stops
  when it pops the first one again. That last pop is not put back, so a "CL"
  file with no matching "RE" drops the first RE directory from the list.
- A "CE" entry stores its offset and length in the file, so a record with two
  of them, or a continuation area with more, reads every request with the
  values of the last one.
- `previous_number` starts at 0. A first entry with file number 0 (extent 0,
  or PX inode 0 on every entry) takes the hard link branch before any entry
  has been returned. `previous_pathname.s` is still NULL, so upstream sets no
  hard link, but the entry still gets no size and no data.
- `archive_string_empty` only zeroes the length. The name and symlink buffers
  are read as C strings in places (`strcmp` for `rr_moved`, the "beyond
  end-of-media" and out-of-order warnings, the symlink target), so after an
  NM or SL entry empties them those places still see the old bytes, and a
  symlink target can be stale. The port keeps the bytes and the length apart.
- An out-of-order file warning prints `pathname.s`, which is NULL when
  Joliet names are in use; it is printed as "(null)".
- A zisofs block of zero length (a hole) is returned as a whole block of
  zeros, even past the end of the declared size.
- Empty files and symbolic links get the offset `-1`, which `offset << 16`
  turns into the largest key but one, so they come out of the heap last.
- The heap key is `offset << 16` plus the heap's length, which is not a
  counter: after entries come out, keys of different entries can be equal,
  and for 65536 or more pending entries they are not unique at all. Which of
  two equal keys comes first is therefore part of the output, and the heaps
  are ported as written rather than replaced with `BinaryHeap`.
- `SL` and `NM` entries cut at the first NUL (`archive_strncat`), and a
  Joliet name of odd length loses its last byte; a one-byte name becomes the
  empty name.

### Differences

- A chain of parents that loops (a malformed image can make one with "CL"
  and "RE" entries that point at each other) hangs upstream in the duplicate
  directory check and the "CL" ancestor check, and overflows the stack in the
  Joliet pathname builder. The port stops after as many steps as there are
  records: the first two fail with "Directory structure contains loop" and
  "Invalid Rockridge CL", the last with "Pathname is too long". Plain
  pathnames keep upstream's depth limit of 1000.
- A zisofs block whose zlib stream ends before the block's data is used up
  makes upstream return empty blocks for ever, without consuming input. The
  port fails with "zisofs decompression failed (-5)" when a decompression
  step consumes and produces nothing.
- The number in "zisofs decompression failed (%d)" is zlib's return code;
  miniz_oxide gives its equivalent (`MZError` values are zlib's) for the
  errors it has, and which corrupt streams are errors, and at which byte,
  can differ from zlib.
- The pending-file and continuation heaps hold indexes into one vector of
  records, and the lists upstream threads through the records (`next`,
  `re_next`) are separate queues. Upstream's lists share the `next` field
  between the cache and the empty-file list, and `re_next` between the RE
  and descendant lists; where an image makes one record be on two lists at
  once, upstream corrupts them and the port does not.
- A directory is read whole with one read-ahead of its size, as upstream
  does; the size is bounded by the volume size from the descriptor, and a
  size beyond the input fails once the input ends.
- Name conversion failures are always "can't be converted" warnings; the
  string layer does not report the `ENOMEM` case upstream tells apart.

## Time and CRC helpers (`src/time.rs`, `src/crc32.rs`)

### Ported as-is

- `__archive_unix_to_ntfs` passes a signed `secs` to `archive_ckd_add_u64`,
  which takes `uint64_t`. A negative `secs` (pre-1970, down to the NTFS
  epoch) becomes a huge unsigned value, the addition overflows and the result
  is `UINT64_MAX`. Only `secs < -11644473600` returns 0 as intended
  (archive_time.c).
- `__archive_dos_to_unix` returns `INT32_MAX` when `mktime` fails, which also
  swallows a genuine 1969-12-31 23:59:59 UTC result of `-1` (archive_time.c).

### Differences

- `__archive_crc32` uses the safe `crc32fast` 1.5.2 API for updates of at least
  64 bytes on little-endian targets. The already locked test dependency is
  promoted to a runtime dependency for its runtime-detected ARM CRC and x86
  carryless-multiply backends; its isolated intrinsic code is unsafe, while
  this crate adds no unsafe code. Smaller updates (including ZipCrypto) and
  big-endian targets retain the local slicing-by-eight implementation. The
  big-endian guard avoids native-word ordering assumptions in the ARM backend.
  Seeded and incremental results remain identical to zlib; there is no
  NULL-pointer case because a slice is never null. Independent bitwise tests,
  actual Opus 5.5 design/final review and separate micro/in-memory archive
  measurements are retained in `../diagnostics/round8-system`.

## Crypto (`src/digest.rs`, `src/hmac.rs`, `src/cryptor.rs`)

### Differences

- One backend replaces upstream's CommonCrypto, CNG, mbed TLS, Nettle, OpenSSL,
  libmd and libc glue, and the "unsupported" stubs: RustCrypto `md-5` 0.11,
  `ripemd` 0.2, `sha1` 0.11, `sha2` 0.11, `hmac` 0.13, `pbkdf2` 0.13 and `aes`
  0.9, all with default features off (`alloc` on for the hashes, so a `Digest`
  can hold any of them). Nothing is ever "unsupported": MD5, RIPEMD-160,
  SHA-1/256/384/512, HMAC-SHA1, PBKDF2 and AES-CTR always exist. The oracle
  here (macOS) has no RIPEMD-160 at all (`archive_rmd160_init` fails), so that
  one is checked against the paper's vectors only. The readers' "Decryption is
  unsupported due to lack of crypto library" paths can only be reached by an
  AES key of a wrong length, which they never pass.
- AES-CTR is ported from upstream, not taken from the `ctr` crate (one fewer
  dependency, and the counter handling is exactly upstream's). The counter is
  the low 8 bytes of a block that starts at zero, little-endian, incremented
  before each block is encrypted, so the first block of key stream is for
  counter 1; it wraps within those 8 bytes and never carries into the rest.
  A partial block's key stream carries over to the next `update`, which
  processes the shorter of the input and output lengths. Encrypt and decrypt
  are the same operation. Upstream's doubled function groups (`decrypto_*` and
  `encrypto_*`) are one `AesCtr`.
- `AesCtr::new` fails only for a key that is not 16, 24 or 32 bytes (the
  OpenSSL and CNG backends fail the same way). `HmacSha1::new` takes any key and returns `Option` only to keep
  the callers' error path. `pbkdf2_sha1` cannot fail, so it returns nothing
  where upstream returns 0 or -1. A digest, HMAC or AES context is consumed by
  `finalize` or dropped; there are no `release`/`cleanup` calls. Keys are not
  zeroed on drop (the `zeroize` features are off), where the C backends
  clear theirs in `release`.
- `archive_version_details` has no crypto section. Upstream names one
  platform library (`CommonCrypto/system`, `openssl/3.x`, ...); the port has
  seven crates and none of the upstream keys, so there is nothing honest to
  put under them. The compression backends keep upstream's key because each
  replaces exactly one library (see Core).

### Backend choice and unsafe footprint

- Candidates were these crates against hand-rolled hashes (rejected: the
  hashes are the hot path of the mtree and xar writers, and hand-rolled
  crypto is the wrong thing to maintain) and `openssl` or `ring` (C or
  assembly, ruled out). RustCrypto is pure Rust with a portable fallback in
  every crate.
- `unsafe` is only in the CPU-intrinsic backends, chosen at run time by
  `cpufeatures`, with the portable code as the fallback: `sha1` (x86 SHA-NI,
  aarch64 SHA-2), `sha2` (the same, plus AVX2 and aarch64 SHA-3), `aes` (AES-NI
  and aarch64), `cpufeatures`, and `md-5` only on loongarch64 (an assembly
  block). `ripemd`, `hmac`, `pbkdf2`, `digest`, `cipher`, `crypto-common` and
  `ctutils` forbid `unsafe` or have none. `inout` (via `cipher`) and `cmov`
  (constant-time moves, via `ctutils`) carry a few `unsafe` blocks, and so
  do `block-buffer` and `hybrid-array`. `sha2` and `cpufeatures` were already
  in the tree through `lzma-rust2`'s xz SHA-256 check.
- These crates pick their backend with `--cfg` flags (`sha1_backend="soft"`,
  `sha2_backend="soft"`, `aes_backend="soft"`), not Cargo features, so the
  intrinsics cannot be turned off from `Cargo.toml`. Forcing them through
  `.cargo/config.toml` was rejected: `RUSTFLAGS` in the environment replaces
  it, and the portable code is slower than the intrinsics on the mtree, xar and
  zip paths (not measured). The footprint is accepted; set those cfgs to remove it.

### Verification

- Vectors: RFC 1321 (MD5), the RIPEMD-160 paper, FIPS 180 (SHA-1, 256, 384,
  512, and a million `a`), RFC 2202 (HMAC-SHA1), RFC 6070 (PBKDF2-HMAC-SHA1),
  and NIST SP 800-38A F.5 (the first block of AES-128, 192 and 256 CTR key
  stream, which is the encrypted counter block).
- Against upstream: a C probe linked against `build/oracle/libarchive.a`
  (`__archive_digest`, `__archive_hmac`, `__archive_cryptor`; CommonCrypto and
  libSystem here) generated 400 random cases of 0 to 4000 bytes with random
  chunking: MD5 and SHA-1/256/384/512, HMAC-SHA1 with keys of 0 to 150 bytes,
  PBKDF2 with 100 random passwords, salts, round counts and output lengths,
  and AES-CTR in all three key sizes updated in pieces of 0 to 70 bytes (every
  partial-block case). All 2,900 outputs matched. The probe is not in the
  repository.

## zip reader (`src/read/format/zip.rs`)

The streamable and seekable readers are one type, `Zip<SEEKABLE>`, so both
register (`register_format` tells formats apart by type). `zip/extra.rs` has
the entry record and the extra fields, `zip/crypto.rs` the decryption, and
`zip/zipx.rs` the compression methods other than stored and deflate.

### Ported as-is

- `process_extra` compares the central directory's `local_header_offset`
  with 0xffffffff after `slurp_central_directory` has added the correction for
  data before the archive. With such data a zip64 offset is never read from
  the extra field.
- The extra fields of the central directory are given the archive entry, so
  an Info-ZIP Unicode Path field there sets its pathname (the next local
  header sets it again). With several entries the CRC check of the field is
  made against the name the previous one left.
- `consume_end_of_file_marker` tests the second word of the descriptor for
  zero (AE-1 may write a zero CRC32) in the two layouts that have no PK78
  marker, where that word is not the CRC32.
- A compressed symlink target is read by the deflate or lzma reader, which
  consumes its data, and then `zip_read_local_file_header` consumes
  `compressed_size` bytes again. The streamable reader then skips that much
  of what follows.
- A zstd entry whose frame ends with the 128 KiB output buffer exactly full
  does not end: the next read finds no input left and fails with "Truncated
  zstd file body".
- PPMd's entry bytes remaining do not count the 2 header bytes and what the
  range decoder reads at the start, so skipping a half-read streamed PPMd
  entry consumes that much too few.
- Strong encryption: `read_decryption_header` masks the flags with 0xf000 and
  compares them with 1, 2 and 3, so every entry fails with "Unknown
  encryption flag". The rest of that function never runs and is not ported.
- An archive with no entries has no `zip_entries`, so the seekable reader
  reads the central directory again at each header.
- `mac-ext` is on by default only where upstream has `copyfile.h` (Apple);
  the streamable reader ignores it.
- The version byte in the format name ("ZIP 2.0 (deflation)") is a `char`:
  signed here, as on x86 and Apple arm.
- A mac metadata entry whose local header can't be sized passes the failure
  code to `__archive_read_consume`, which fails and is ignored; the data is
  then read from the wrong place.

### Differences

- Deflate is miniz_oxide in raw mode (see the gzip filter). Corrupt data it
  accepts and zlib rejects ("invalid distance too far back") is read as zeros
  instead of "ZIP decompression failed (-3)"; the entry then fails its CRC or
  size check, or its AES authentication code. zlib's `Z_BUF_ERROR` (no
  progress possible) is rebuilt from the byte counts. This is the cause of
  almost all differences found on damaged archives.
- Differential run against upstream (`bsdcat`-style probe, entries, data
  hashes, return codes and messages, streamable, seekable and `all`, block
  sizes 7 and 10240, right and wrong passphrases): all 72 zip fixtures of the
  test suite, then 2232 mutated or truncated copies. Valid archives are
  identical except the two noted below. On damaged ones, the differences
  found are all in the decompressors:
  - deflate, as above;
  - bzip2: upstream hands out the part of a corrupt block that it has
    decoded before failing; the block decoder here fails the whole block;
  - zstd: libzstd fails after the blocks before the damage were handed out,
    and sometimes has the CRC check find damage that ruzstd's parser rejects
    (or the other way round);
  - lzma and xz: with damaged data the decoders stop at different places
    (see below).
- Of the valid archives, `test_read_format_zip_lzma_alone_leak.zipx`, a fuzzed
  file, differs: the LZMA data is 12 bytes that liblzma decodes to 57
  bytes of garbage with no end marker, and lzma-rust2 produces none because
  it holds back the end of the input.
- LZMA (method 14) is lzma-rust2's `LzmaStream`, which needs the input after
  the last symbol to decode it. Given the uncompressed size liblzma never
  gets, it stops there. So when the compressed size is known the decoder is
  told the declared uncompressed size, an end marker is not read, and after
  all the entry's data has been taken the decoder is called once with no
  input to drain what it holds. With the size unknown (length at end), the
  stream needs its end marker. The `avail_out` cap upstream computes as
  `uncompressed_size - read` can be negative (after a size error) and is
  then cast to a huge `size_t`, which writes past the buffer; here it is
  zero. liblzma's `LZMA_BUF_ERROR` (a second call with no progress) is
  rebuilt, and a 256 MiB safety limit (upstream: 576 MiB) is checked on
  the dictionary size from the header, plus 32 KiB for the tables.
- xz (method 95): the limit is 256 MiB instead of none, so a block header
  can't ask for 4 GiB. A stream over it fails with "xz unknown error (6)".
- zstd (method 93): ruzstd pulls the compressed bytes it needs through the
  decryption and the entry's limit, instead of being pushed a buffer. It
  consumes whole blocks, so the data may all be consumed while output is
  still held, which upstream's checks for an empty input have to allow. A
  skippable frame inside the entry is an error here, which libzstd skips,
  and a frame header with the reserved bit set is accepted, which libzstd
  rejects. The window limit is libzstd's 128 MiB.
- bzip2 (method 12) is `crabz2` through the shared streaming decoder, which
  asks for more input than the stream has when it is cut short; the
  decryption buffer grows to hold what it asks for (3 MiB at most), and
  `last` is given when the entry's data or the file ends.
- PPMd: one `Ppmd8` lives as long as the reader, as upstream's `struct zip`
  does, so the escape estimate carries from entry to entry. The memory
  (up to 256 MiB) is allocated fallibly.
- `archive_read_data_block` sets `size` to the data of a failed block
  (a wrong CRC, a size over the declared one) upstream, and 0 here; the
  data is not returned with the error.
- A negative number of compressed bytes left (a PPMd entry, say) makes
  upstream's stored reader compute a negative length; here the read fails
  with "Truncated ZIP file data". The decryption buffer is allocated
  fallibly.
- `compat-2x` does nothing: upstream only sets a flag that, off Windows,
  changes nothing (there is no default name conversion to switch).
- Not ported: the `DEBUG` prints, the `#if 0` key derivation, and
  `zip_read_decryption_header`'s tail (see above). The cryptor errors "lack
  of crypto library" cannot happen, and the messages for the `None` cases
  are kept.
- ZIP writer/extraction integration tests, including all encrypted ZIPX
  methods and streaming forms, pass after Phase 5 integration.

## xar reader (`src/read/format/xar.rs`, `xar/toc.rs`)

### Ported as-is

- The checksum algorithms of an extended attribute's `archived-checksum` and
  `extracted-checksum` are never recorded (`xml_start` only changes state for
  the `ea` children, unlike `data`), so only the digits are stored and an
  xattr's data is never verified.
- An xattr is decoded with the decoder that the entry's `entry_encoding`
  picks (xz stream or lzma alone) and named in its errors, whatever the
  xattr's own `encoding` says. The upstream single-call attribute decoding
  restriction is replaced by bounded incremental collection; see the XAR
  writer/attribute notes below.
- `xar_read_header` returns a conversion warning (name, user, group or link
  text that cannot be converted from UTF-8) before it moves to the file's
  data, if the file has no xattrs (an xattr's own result replaces the
  warning). The data then reads from wherever the previous entry left off.
  Entries read in order hide it.
- `xar_read_data_skip` adds the bytes of the last block to `xar->offset`
  again (they were added when the block was read), so skipping the rest of
  an entry that was read in part leaves `xar->offset` too far ahead and the
  next move to a file's data comes up short.
- The `Undelete` ext2 flag is `nouunlink`, the BSD user flag's name.
- The header size field is checked by the bid and not when the TOC is read.
- A checksum with a digit that is not hexadecimal has the length -1: it
  never matches. An odd digit at the end is ignored, and more than 64 bytes
  of digits are cut off.
- Numbers stop at the first byte that is not a digit (`12ab` is 12); only an
  overflow is an error, with no message. A time is 20 bytes exactly and its
  last byte (the `Z`) is not checked. Seconds up to 60 and days up to 31 in
  any month are accepted and normalized, like `timegm()`.
- After the end of a zlib stream another call returns the end again without
  progress, so a TOC or an entry whose packed length goes past the end of
  its stream fails with "XAR decompressor made no progress"; after the end of
  an xz or bzip2 stream, with "xz decompression failed (11)" or "bzip
  decompression failed".
- Hardlinks: a `type` element with more than one `link` attribute, or a file
  that is already an original or a link, is "File with multiple link
  attributes". Links are counted by the id in `link`, which must fit 32 bits,
  and joined to the original with that id; a link 0 is no link.
- A directory that has only a name and a type is not an entry. A name is
  taken from the first `name` element only, and a nested file's pathname is
  its parent's, a `/` and its own.
- A directory's `nlink` is its subdirectories plus 2.
- Only archived and extracted SHA-1, MD5, SHA-256 and SHA-512 checksums
  exist (the style is read with the first three letters in any case); the
  entry's checksums are checked when its last byte of packed data is read,
  and a mismatch loses that last block.

### Differences

- The XML parser is the `xml` crate 1.4.0 (xml-rs, renamed), where upstream
  uses libxml2's `xmlTextReader` (expat elsewhere). It has
  `#![forbid(unsafe_code)]` and no dependencies, reads a stream, resolves
  namespaces and checks well-formedness strictly. quick-xml (also
  `forbid(unsafe_code)`, no dependencies) is a pull parser too, but checks
  far less of the document (names, characters, prefixes) than libxml2 does;
  roxmltree builds a whole tree, which would report a malformed ending
  before any file. Upstream's callbacks are mapped onto its events: element
  start with the local names and values of the attributes, element end, and
  the text of a text node that is not blank, with the same states. Comments
  and processing instructions split text as in libxml2; CDATA and blank text
  are ignored, as upstream's reader ignores their node types.
- Where the XML is malformed, both fail with `ARCHIVE_FATAL`, errno
  `ARCHIVE_ERRNO_MISC`, and "XML Parsing error: " and a message, but the text
  is the crate's, with a position (`1:61 Unexpected token: <`), not
  libxml2's (`Extra content at the end of the document\n`). The depth limit is
  libxml2's: 257 nested elements are accepted and the 258th is an error (the
  message is its text). libxml2's limits on a text node, an attribute value
  and a name are not mirrored.
- What the two parsers accept differs, and the fixtures and a differential
  run of 7,300 mutated archives found these (all else on the same path, in
  error codes and entries, matched):
  - Unbound namespace prefixes (`<x:file>`, `a:b="c"`) are a warning in
    libxml2 (the message is left in the archive error and the read goes on)
    and an error here. `xml` as an element prefix is accepted by libxml2 and
    rejected here.
  - Namespace declarations are not attributes here; libxml2's reader lists
    `xmlns` and `xmlns:p` among them, so a declaration `xmlns:id="u"` on a
    `file` would be its id attribute upstream.
  - Internal entities of a DOCTYPE are expanded here; libxml2's reader
    gives an entity reference node, which upstream ignores. An encoding
    declaration that the bytes contradict (UTF-8 declared, UTF-16 found) is
    an error here.
  - libxml2's reader parses ahead (4096 bytes at a time) before it hands out
    a node, so with an error in the XML and an error from a callback in a TOC
    that small, upstream reports the XML error. This streams: the callback
    error comes first, as it would for a longer TOC. Likewise a TOC that
    cannot be read to the end (truncated file, data past a zlib stream) reports
    the read error ("Truncated archive file", "XAR decompressor made no
    progress") here, and libxml2's syntax error ("Extra content at the end of
    the document") upstream when the XML is incomplete at that point. When
    the XML was complete, upstream reports the read error too.
- zlib is miniz_oxide's streaming inflater (zlib wrapper, Adler-32 checked).
  The one difference is corrupt data: a back-reference reaching before the
  start of the output is accepted (see the gzip filter), so an entry with
  such data fails in the size or checksum check ("Decompressed size error",
  "Checksum error") where upstream says "File decompression failed (-3)". The
  zlib error numbers are mapped from the crate's errors (-3 data, -5 no
  progress); xz and lzma failures have liblzma's numbers by kind (8 options,
  10 no progress, 5 memory, 9 for the rest, 11 for a decoder already
  ended). xz and lzma limit the decoder's memory to 256 MiB like the xz
  filter (upstream has none).
- bzip2 is the streaming `Decoder` of the bzip2 filter, with `last` set when
  the packed size or the end of the file cut the read short. bzlib returns
  empty blocks while it reads the start of a block; the decoder does not, so
  the number and the sizes of the blocks that `archive_read_data_block`
  returns differ from upstream for bzip2, xz, lzma and (a little) gzip
  entries. The bytes and the sizes in total are the same.
- lzma-rust2's streams can hold decoded bytes back after they have taken the
  last of the packed bytes (liblzma decodes only as far as the output goes,
  and zlib and libbz2 deliver everything they have decoded). Upstream would
  stop when the packed bytes are used up, so here the held output is read out
  and handed on first, by the entry or the TOC, before the end is decided.
  With it gzip, bzip2 and xz entries are unchanged and lzma-alone entries
  match upstream.
- Corrupt xz and lzma data differs from liblzma, as in the xz filter. xz with 8
  bytes of garbage after the stream succeeds upstream and fails here with
  code 9, losing the entry's output. lzma with 2 bytes of garbage fails
  upstream with code 11 after the data is delivered and succeeds here. An lzma
  stream cut short by one byte or more delivers everything upstream and fails
  here with "Decompressed size error". A cut xz stream delivers 1580 bytes
  upstream and 1561 here in the case tried. A stream of the wrong format gives
  code 9 or 5 here and 7 in liblzma. Dictionaries of 256 MiB or more decode
  upstream (no limit) and fail here with code 5.
- xml-rs accepts `<?xml version="1.1"?>`, which libxml2 rejects with
  "Unsupported version '1.1'".
- A read callback that returns no bytes but used some input is the end of the
  TOC to libxml2, which stops reading it. The TOC is read on here until
  bytes arrive.
- Bounds (upstream has none): the TOC may be at most 1 GiB uncompressed
  ("Rejecting malformed xar archive: TOC exceeds 1 gigabyte", `ARCHIVE_ERRNO_MISC`).
  Its job is to bound what xml-rs buffers, which it does not limit itself (a
  CDATA section, say); the memory for files and xattrs is in proportion to the
  TOC bytes present, so it is bounded by this too. A pathname is at most 1 MiB
  (`ENOMEM`). Each file keeps its own name and its parent, and the pathname is
  put together when the entry is returned (and so is a hardlink's target), so
  deep nesting does not copy a parent's pathname into every file; the length
  check is made then, and not while the TOC is read. A checksum size over 64
  in the TOC is a read of that length and "Checksum error". The declared
  uncompressed size of the TOC is only compared with what was read, at the
  end, as upstream.
- Offsets: a seek back that the input cannot do is "Cannot seek"
  (`ARCHIVE_FAILED`), as upstream; any other failure of the seek (upstream
  goes on with the offset set to the error code) fails with it.
- A file with no `name` element has no pathname in the entry (upstream's
  string is NULL and the entry's is cleared); one whose name decodes to nothing
  has the empty pathname, as upstream. Entry fields are set where upstream sets
  them, and the format and its name only when the TOC has been read.
- `xmlCleanupParser()` after every TOC has no counterpart.
- The unsafe footprint of what the reader adds is nil: `xml` forbids
  `unsafe` and has no dependencies. The digests are RustCrypto's (see Core).
- The archives of the upstream tests and nine more files of the fixtures
  (`test_read_format_xar*`) read the same entries, data and errors through
  upstream and through this reader. The reader is also checked against
  generated archives with the gzip, bzip2, xz, lzma and no encoding and files
  of up to 300,000 bytes in blocks of 13, 4096 and 100,000 bytes (the data,
  sizes and hashes are equal), and 7,300 mutated fixtures, each in two
  block sizes (TOC XML edits with the archive repaired, header edits,
  truncations, heap edits).

## rar reader (src/read/format/rar.rs)

RAR 1.5 to 4.x. `rar/huffman.rs` and `rar/filters.rs` hold the Huffman codes
and the filters. The PPMd model is `ppmd7`, reached through `Ppmd7` and
`Ppmd7RangeDec`; everything else of it the 7zip reader needs too.

### Ported as-is

- Every solid file is refused: a file header with `FHD_SOLID` fails with
  "RAR solid archive support unavailable" (the pinned source clears the
  per-file state in the other branch and gives up in this one).
- `read_exttime` sets the nanoseconds to the broken-down time's *seconds*
  plus `rem / 10000000` (`nsec = tm->tm_sec + rem / NS_UNIT`).
- A file header with `FHD_PASSWORD` sets "RAR encryption support
  unavailable" and goes on, so a successful header can leave that message on
  the handle; the entry is flagged as having encrypted data. The same goes
  for the sub-block (`NEWSUB_HEAD`) variant, which flags the entry the
  reader is not even filling in.
- The parts of a split file are matched by name alone; the part's own header
  replaces the sizes, flags, method and CRC, so the CRC checked at the end is
  the last part's, and its `unp_size` ends the file.
- `parse_filter` copies `globaldatalen` bytes from the start of a buffer
  whose first 0x40 bytes were never written (the data is stored after
  them), and `compile_program` reads the program's static data into memory
  nothing uses. We read both for their length and EOF checks only.
- A PPMd escape followed by a code other than 0, 2, 3, 4 or 5 (so 1, and 6
  to 255) emits the escape byte itself as a literal.
- `filters.lastend`, the filter stack, the programs and `lastfilternum` are
  not reset by a new file header; only `filterstart` is. The PPMd model is
  freed (and `start_new_table` set) every time `read_data` fails *or hits the
  end of the file*.
- An incomplete Huffman code (a node with an unset branch) fails
  `make_table` for the whole table, so none of its symbols can be read, even
  though the table is kept for the next lookup.
- Reading the four parts of `test_read_format_rar_multivolume` with
  `archive_read_support_filter_all` (the uu bidder alone is enough:
  `archive_read_support_filter_uu`) and no zip bidder returns wrong data at
  the 128 KiB boundary of the filter's buffer, so the rar reader fails with
  "Invalid symbol". The corruption is upstream's own and the port reproduces
  it byte for byte: the raw format over the same four parts gives 320323
  bytes of a 189201-byte stream in both. The suspect is the roll-back in
  `__archive_read_filter_ahead` (archive_read.c, "Roll back to client
  buffer"), which assumes the copy-buffer bytes precede `client_next` in the
  current block. Upstream's zip bidder masks it for rar, so
  `test_read_format_rar_multivolume` and `_multivolume_skip` both pass here
  with ZIP merged, as confirmed by the Phase 4 integration run. It is not a
  bug in the rar read path.

### Differences

- The bit reader consumes the bytes it takes into its cache as it takes them.
  Upstream keeps a pointer into the read-ahead buffer and consumes what it
  used at the next call; nothing can tell the two apart.
- The header reads upstream makes with `a->entry` in the middle of reading
  data (the next part of a multivolume file, `read_data_skip`, `seek_data`)
  get the handle's own entry through `Reader::with_entry`, which the ffi
  layer fills for `archive_read_data*`, `archive_read_data_skip`,
  `archive_seek_data` and `archive_read_data_into_fd`. When
  `archive_read_next_header2` skips the rest of the previous entry the entry
  is the one it was given (cleared first, as upstream does); upstream passes
  `a->entry`, so with a caller-owned entry that is not the handle's own,
  upstream fills the handle's entry and we fill the caller's.
- `read_data_skip` ending at the end of the archive in the middle of a
  multivolume file returns `ARCHIVE_OK`; upstream passes `ARCHIVE_EOF` on to
  `archive_read_data_skip`.
- `read_exttime` fails the header ("Invalid header size") when `localtime`
  fails; upstream dereferences NULL.
- The window, the output buffer and the VM's memory are allocated with
  `try_reserve_exact`; a failure is `ARCHIVE_FATAL` "Unable to allocate
  memory for uncompressed data". The PPMd model is allocated by `Ppmd7::alloc`
  ("Out of memory", also fatal), which can ask for up to 256 MiB.
- Names are decoded into a buffer of the exact size; the "Invalid filename"
  check of the Unicode decoder (the decoded name longer than twice the
  stored one) can't fail and is not ported, nor can the `src >= dst` checks
  of the delta, RGB and audio filters, which count the same bytes as the
  loops. Out-of-range window offsets, Huffman nodes, the data-block table
  `dbo` in `seek_data` ("Invalid RAR seek cursor state"), and filter output
  ranges fail instead of reading outside the buffers. The "Invalid zero
  dictionary size" check in `parse_codes` is not ported either: flag 0x20
  always sets a dictionary of at least 1 MiB just before it.
- The filter stack finds its first filter again after `expand` by a serial
  number; upstream compares pointers after freeing it.
- `read_data_compressed`'s recursion on PPMd code 0 is a loop with the same
  limit (`MAX_COMPRESS_DEPTH`, "failed" without a message).
- `salt`, `encryptver`, `reserved1/2` and `arctime`, which upstream stores
  and never reads, are not kept; the header size checks on them are.
- Only the filters upstream recognizes run: delta, E8, E8E9, RGB and audio.
  (There is no Itanium filter in the pinned source.)

## tar reader (src/read/format/tar.rs)

### Ported as-is

- The hard link size heuristic calls `archive_read_format_tar_bid(a, 50)`,
  which looks at the stream position. The record of the hard link entry itself
  has not been consumed yet at that point (`unconsumed`), so it bids on the
  entry's own header, not on the one that follows as the comment says. The
  port bids on the entry's own header too.
- `header_gnutar` assigns the result of `header_common` to `err`, which drops
  the warnings of the name conversions before it (their messages stay).
- `gnu_add_sparse_entry` links the new block before checking it, so a
  rejected block stays in the list as an empty one. `GNU.sparse.map` turns the
  resulting `ARCHIVE_FATAL` into `ARCHIVE_WARN`, and the entry then carries
  that empty block.
- A sparse entry whose only data block covers the whole file is
  `ARCHIVE_FATAL` ("Malformed sparse map data"): `archive_entry_sparse_count`
  drops such a block, so its count differs from the number added. Adjacent
  blocks merged by `archive_entry_sparse_add_entry` and blocks past the end
  of the file are fatal for the same reason.
- `sparse_offset`, `sparse_numbytes` and the GNU sparse major/minor numbers
  are not reset between entries.
- `pax_attribute_read_number` returns `ARCHIVE_FATAL` without a message for a
  value over 64 bytes, and `ARCHIVE_WARN` without a message for a negative or
  overflowing number. A malformed time sets "Ignoring malformed pax X" even
  when the call failed fatally.
- `SCHILY.xattr.` takes values below 16 MiB but `LIBARCHIVE.xattr.` and
  `RHT.security.selinux` take values up to it. `LIBARCHIVE.xattr.` skips an
  oversized value with a warning and no message. `SCHILY.xattr.` and
  `LIBARCHIVE.xattr.` names end at their first NUL, which `%00` can produce.
- `pax_attribute_SUN_holesdata` tests for a `\n` at the end of a field, which
  cannot be there (the value excludes the newline), so the test is dead.
- `read_body_to_string` and `header_pax_records` consume an oversized body
  before the pending record of the header has been consumed. The total is the
  same.
- The `X` header is the Sun variant of `x` and is refused when repeated with
  either, but a repeated `K`, `L` or `V` only warns.
- `process_mac_extensions` defaults to on only where upstream was built with
  `copyfile.h` (macOS); here that is Apple targets.

### Differences

- `entry_offset` is not kept: upstream sets it and never reads it.
- `compat-2x` only passes `SCONV_SET_OPT_UTF8_LIBARCHIVE2X` to the
  conversion, which does nothing on this platform (see archive_string).
- The sparse list is a `VecDeque`, and the 1.0 map's lines are read one at a
  time (at most 100 bytes each, as upstream limits them) instead of through
  the shared `line` buffer.
- No allocation is bounded beyond upstream's limits: names and values are
  copied from bytes the archive holds, so memory use is at most the size of the
  input, as upstream's is. An attribute name can be as long as the buffered
  part of its line (up to 100 million characters).
- A failed `read_ahead` (not only a short archive) is reported with the
  "Truncated ..." message of the call site, as upstream does for its `NULL`.

## lha reader (src/read/format/lha.rs)

### Ported as-is

- `lha_check_header_format` compares the level byte as a `char`, which is
  signed on the platforms we target: a "-lh?-" header with level 0x80 to
  0xff bids 30 and is accepted as a header, then `read_header` fails with
  "Unsupported LHa header level -N". (On unsigned-char platforms it would not
  bid.)
- `uname`, `gname`, `crc` and `header_crc` are not reset between entries, so
  an entry without a user name, group name or header CRC extended header
  inherits the previous entry's (a level 2 or 3 header without a CRC
  extended header compares against the previous, or initial zero, value).
- Header level 3 never skips the padding between the extended headers and
  `header_size`; header level 2 does.
- `lha_read_data_*` ask for one byte of look-ahead even when the compressed
  data is used up: an archive whose last entry ends exactly at the end of
  the file, after the decoder consumed everything, fails the next
  `read_data` call with "Truncated LHa file body" if that call is made.
- A directory (`-lhd-`) whose header carries a non-zero file CRC reports
  "LHa data CRC error" at its end.
- A read error while peeking at a header is treated as a short input (EOF
  or "Truncated LHa header"), as upstream's `__archive_read_ahead` returning
  NULL is.

### Differences

- The decoder window is zero filled (upstream mallocs it and fills only the
  last 8/32/64 KiB with spaces; no valid distance reaches the rest).
  The decoder is created per entry rather than reused, so no table state
  carries over.
- Every Huffman table, tree and window index is checked; corrupt tables fail
  with "Bad lzh data" instead of reading or writing out of bounds. The
  Huffman code lengths are 0 to 16 by construction, so valid streams are
  unaffected.

## rar5 reader (src/read/format/rar5.rs)

### Ported as-is

- Stored (method 0) entries are never checksum-verified. `rar5_read_data`
  runs the CRC32 and BLAKE2sp check once `bytes_remaining == 0` and
  `last_write_ptr == unpacked_size`, but unstoring advances
  `last_unstore_ptr` and leaves `last_write_ptr` at 0. Only an empty stored
  file is verified, so a stored file with a wrong CRC extracts without error.
- A block that is merged from several volumes and needs more than one decode
  pass (it produces more than half a window of output) is consumed twice.
  `merge_block` already consumed the block and left it in `push_buf`, but
  `process_block` clears `switch_multivolume` after the first pass, so when a
  later pass finishes the block it consumes `cur_block_size` bytes again and
  subtracts them from `bytes_remaining`. The data stream then loses its place:
  a two-volume archive whose first block spans the volumes and unpacks to
  300000 bytes yields 65537 bytes and no error. Only the small merged blocks
  of the upstream test archives decode in one pass.
- `file.solid_window_size` is in `struct file_header`, which
  `reset_file_context` zeroes for every file, so the "Window size for this
  solid file doesn't match" check can only fire on the continuation header of
  a multivolume file, where the context is not reset.
- `HEAD_ENDARC` of a volume treats `scan_for_signature` finding no next
  volume (`ARCHIVE_EOF`) like finding one: only `ARCHIVE_FATAL` is tested, so
  it sets `expected_vol_no` and returns `ARCHIVE_OK`, and the header loop ends
  on the failed read of the next header.
- `create_decode_tables` updates the table as it goes and fails when the code
  lengths are over-subscribed, leaving it half built. The block is then
  resumable (`block_parsing_finished` is already 0), and a later
  `archive_read_data` decodes with the half-built table.
- `push_data` ignores `push_data_ready`'s result. A range that cannot be
  queued ("output stream is not continuous", full stack) leaves its message on
  the handle and carries on; `last_write_ptr` still advances and the range is
  never returned.
- A negative `extra_data_size` compares as a huge unsigned number against an
  extra record's size, so an unknown record is skipped (and consumed) without
  the "exceeds remaining extra-field data" check once the size has gone
  negative.
- A compressed entry's first `archive_read_data_block` calls return
  `ARCHIVE_OK` with an empty block (at `last_write_ptr`): the decoder queues
  the unpacked range and the next call hands it out.
- `rar5_read_data_skip` returns `ARCHIVE_EOF` if the data ends inside a solid
  skip; `archive_read_data_skip` maps that to `ARCHIVE_OK`, while header
  reading (`skip_unprocessed_bytes`) passes it on as the end of the archive.
- The pathname, link target and owner names stop at the first NUL byte, as C
  strings do.

### Differences

- `rar5_skip_remaining_block` finds how much of a header body the sub-parser
  consumed by subtracting a read-ahead pointer from the body start. If a
  `read_ahead` in between moved the buffer (a sub-parser asking for more than
  was buffered), that difference is garbage. The port compares stream
  positions.
- The block being decoded is not kept as a pointer into the read-ahead
  buffer between `read_data` calls (the buffer may have moved). A block that
  needs several passes is read ahead again at the same position; a merged
  block stays in `push_buf`.
- Pending output is queued as a range of the window or filter buffer rather
  than as pointers, and the 4 bytes after a block that the bit reader looks
  at are the read-ahead's own bytes, as upstream. Reads past the end of any
  buffer give 0 instead of undefined bytes.
- The window is allocated fallibly, and zero filled when it grows (upstream
  `realloc` leaves the added bytes uninitialized). `init_unpack` does not
  allocate the `filtered_buf` that `run_filter` replaces before anything reads
  it.
- The merge buffer and filter output are allocated fallibly. They stay
  bounded by the 16 MiB block size and the 4 MiB filter limit, and a failure
  is `ARCHIVE_FATAL` with upstream's message.
- Window, filter and distance arithmetic is masked or checked everywhere an
  archive value is used as an index. Where upstream's would index outside the
  window or a buffer (a corrupt filter range, a window that does not match the
  allocation) the port fails with `ARCHIVE_FAILED`/`FATAL` or reads 0.
- The signature is stored as is, not XORed with 0xA1 to keep the magic out of
  the binary.
- The QuickOpen and recovery offsets of the main header's locator record are
  parsed and dropped; upstream stores them and never reads them.

## 7zip reader (src/read/format/sevenzip/)

The module is the directory `src/read/format/sevenzip/` (a Rust identifier
can't start with a digit): `mod.rs` (entries, `read_data`), `parse.rs`
(header), `stream.rs` (the folder/stream reader), `codec.rs`, `filters.rs`
(BCJ, BCJ2, Delta) and `sfx.rs`.

### Ported as-is

- `read_SubStreamsInfo` only copies a folder's CRC to its one substream if a
  kCRC section follows; without one, a folder whose only file has a known
  CRC is checked against nothing.
- `Bcj2_Decode` with an empty output buffer returns before it saves how
  much of the range coder's stream the initialisation read, so a later call
  would read those five bytes again as data. The copy of the stashed odd
  bytes (here and in `decompress`) always starts at index 0 and doesn't
  move the rest down, so a partial copy would repeat bytes. Neither can
  happen with the buffer sizes the reader uses.
- `x86_Convert` stores `prevPosT` as a position in the buffer it just
  converted, and the next buffer starts at the unconverted tail, so a
  branch opcode within three bytes of the end of a buffer is forgotten:
  whether an x86 stream converts correctly depends on where the calls
  happened to cut it. (7-Zip's Bra86.c turns the position into a distance
  before it saves it.) The other converters are position-independent. Only
  the converters upstream runs itself have this; the x86 filter of an LZMA2
  coder is liblzma's upstream, and is correct (here lzma-rust2's).
- A symlink entry's contents are read while the header is read. A bad CRC
  there only sets the error message; the status stays `ARCHIVE_OK`.
- `read_Times` and kAttributes read the "external" byte and ignore it (only
  `dataIndex` is parsed for times); external data is not supported.
- `get_pe_sfx_offset` only checks for the "PE" signature when it had to
  read more than the first 64 bytes to get the COFF header.
- `bid` leaves the error it set (for example "Couldn't find out 7-Zip
  header") on the handle when it bids 0, and ours does the same.
- The range decoder's final state (`Ppmd7z_RangeDec_IsFinishedOK`) is never
  checked, so trailing garbage after a PPMd stream is not noticed.
- The `UMAX_ENTRY` limit of 100 million is the only limit on files,
  folders' substreams and sizes, as upstream. Memory for entries is about
  100 bytes each.

### Differences

- **Bad CRC.** Upstream returns `ARCHIVE_WARN` together with the entry's
  last block. `Data::Block` can't carry a status, and `Data::Warn` has no
  block, so the block is returned first and the next `read_data` returns
  `Data::Warn` (with the "7-Zip bad CRC" message), then end of data.
  `archive_read_data` therefore delivers the last block's bytes and then
  reports the warning; upstream reports the warning first and delivers the
  bytes on the call after it.
- **Encrypted entries.** Upstream sets "metadata encrypted" on `a->entry`
  whenever a folder is found to be encrypted, also when that is first noticed
  in `read_data`. `Format::read_data` has no entry, so this is only done
  while a header is read (an encrypted header, an encrypted symlink). Both
  flags are set by `read_header` for an entry whose folder has a crypto
  coder, as upstream.
- **liblzma, zlib, libbz2 and libzstd** are `lzma-rust2`, `miniz_oxide`,
  the bzip2 filter's `Decoder` (crabz2) and `ruzstd`. On valid data the output
  is the same. On corrupt data they differ in which errors they find, what
  they say and how much they output before the error: liblzma's raw LZMA
  decoder happily decodes garbage that lzma-rust2 rejects ("dist overflow",
  a missing final range coder byte), miniz_oxide accepts distances that
  zlib calls too far back, and a failed call outputs nothing from that call
  (upstream delivers what the library had written). lzma-rust2 also decodes
  ahead into its dictionary, as far as the input it was given goes, so a
  corrupt stream can fail a read long before the data it damages. Error messages are
  `Decompression failed (9)` for any lzma-rust2 failure (8 for options, 5 for
  memory), `File decompression failed (n)` with zlib's numbers for
  miniz_oxide, and libzstd's names for ruzstd's errors where there is a
  match.
- **LZMA is given the size.** Upstream starts liblzma's raw LZMA1 decoder
  without a size; 7-Zip writes no end marker, so liblzma returns every byte
  that the range coder can still decode. lzma-rust2 keeps the last bytes back
  until it knows the stream is over, so it is given the folder's size (the
  main stream's, for BCJ2). It is always called with `Action::Run`, and the
  stream is finished by the reader's counts: once an LZMA1 stream has all its
  data the rest of its packed stream counts as used, because liblzma would
  decode it as output that the reader then clips. LZMA2 with a missing end
  marker is therefore accepted, as upstream does. A decoder that has taken
  all its input but still holds output (`pending_output`) is called with no
  input to get it, where liblzma leaves the input it doesn't need.
- **BCJ filters.** Upstream hands the branch filters of an LZMA2 coder to
  liblzma and runs its own converters for every other coder. Here lzma-rust2's
  `StreamFilter` stands in for liblzma's, with the same protocol as the
  converters (the unconverted tail is carried to the next call), and Delta is
  always the reader's own (liblzma's and upstream's are the same
  algorithm). A unit test checks that the two sets of converters agree. The
  chunking of the calls is the decoders', so where upstream's x86 converter
  depends on it (see above) the output can differ from upstream's.
- **ZSTD.** libzstd skips skippable frames, which 7-Zip-zstd writes in front
  of its frame, and checks the frame content size, the reserved bit and the
  checksum. ruzstd does none of that, so these are done in the reader (as in
  the zstd filter). ruzstd holds a window of output back until the frame
  ends or the window is passed, so a corrupt frame fails before any of its
  output is delivered. A frame that the packed stream ends in the middle of
  is "Damaged 7-Zip archive", as upstream's no-progress check says. A
  dictionary frame is an error.
- **Bounds.** Counts from the header are checked against what is left of the
  header before they size an allocation: pack streams, folders (as
  upstream), the bind pairs of a folder, substreams and the entries
  (`files_info_numfiles_is_sane`, as upstream). Upstream's check that a
  one-packed-stream folder has an unbound input is quadratic in the number
  of bind pairs; here it is a bitmap. Properties, names and skipped
  properties are read in pieces of 64 KiB, so a size in the header can't
  size a buffer (upstream asks `header_bytes` for all of it at once). The
  three decoded BCJ2 side streams grow with the data instead of being
  allocated at the size the header gives; the decoded streams are the same.
  Every allocation is fallible.
- **Decoder memory.** LZMA1/LZMA2 dictionaries and PPMd models are capped
  at 256 MiB before allocation, like the XZ filter. Oversized dictionaries
  fail with "Decompression failed (5)"; oversized PPMd models fail with
  ENOMEM. Upstream has no such limit, so unusually large valid models are
  rejected here. PPMd arenas use lazily zeroed pages (see the PPMd section).
  Within that limit, LZMA2 history is bounded by the known decoded stream
  length (at least 4 KiB), including encoded headers and BCJ2 substreams.
  No valid back-reference can require more history than the whole stream.
- Where upstream would index outside a vector with a bad index (an entry
  with data but no folder, a pack stream index outside the table), the
  reader fails with "Damaged 7-Zip archive".

## Matching (`src/matching.rs`, `pathmatch.rs`, `parse_date.rs`)

- Inclusion patterns are anchored and optionally recursive; exclusions match
  each pathname component. Inclusion hits are recorded before exclusions so
  an explicitly excluded pathname is not reported as missing.
- Date tokenization retains upstream's 250-token and 9999-number bounds;
  Unix epoch strings bypass that tokenizer. The conversion retains upstream's
  every-fourth-year leap count (including century years).
- File-time exclusions overwrite previous conditions for the same pathname.
  Missing ctime uses mtime for inclusion filters, as upstream does.
- Lists and trees use owned strings and standard collections. Pattern-file
  contents are read through Rust's file API, with CR/LF or NUL separation;
  no compression or charset conversion is applied to file contents.

- Bare `HHMM` date tokens set hour/minute fields without incrementing
  upstream's `HaveTime`: alone they resolve to midnight; with a date they
  supply its time, and a following explicit time can override them.

## Write compression filters

- Deflate (gzip, zip, xar, zisofs) and XZ/LZMA/lzip compress with safe
  ports of zlib 1.2.12 and liblzma 5.8.4 and reproduce those libraries'
  bytes (see "Deflate compressor" and "LZMA encoding"). bzip2 (crabz2), LZ4
  (lz4_flex) and Zstandard (ruzstd) use other safe Rust encoders: their
  output decompresses to the same archive bytes, but compressed bytes,
  ratios and timing differ from the upstream C libraries. No C codec
  dependency is added.
- lzma-rust2 0.21.0 is vendored. The LZMA2 decoder initializes dictionary
  pages as chunks need them, reducing resident memory for short XZ streams;
  declared virtual capacity, logical history and memory limits are
  unchanged, and LZMA1 and pull readers retain full initialization.
  Provenance and validation are in `vendor/lzma-rust2/PATCHES.md`; its
  unsafe `optimization` feature stays off.
  CRC32/CRC64 updates use safe slicing-by-eight tables, retaining exact checksum
  and incremental semantics while adding 21 KiB of read-only tables.
- XZ and Zstandard accept and validate `threads` but encode on one worker.
  XZ uses a single-thread stream header/index. LZ4 high compression levels
  use the safe block encoder, and linked blocks can be independently coded;
  these are valid linked streams but compression ratios differ.
- ruzstd has only its fastest compression strategy; this adapter provides a
  bounded native matcher whose block search size increases with the level.
  Levels 2–3 use 96 KiB blocks and higher levels use 128 KiB blocks to
  amortize block headers and tables while retaining level-dependent output.
  It reuses a fixed hash table and a 1 MiB history window across blocks,
  including with the `long` option. Five-byte hashing and adaptive skipping
  reduce searches on incompressible input; skipping can miss short matches
  and slightly enlarge some archives. History compaction is amortized over
  1 MiB of new data, adding about 1 MiB of capacity. Matcher storage is bounded
  at about 2.75 MiB. A bounded encoder thread batches small writes and uses
  channel notifications for backpressure, allowing the synchronous backend to
  stream without buffering the archive or polling with sleeps.
  Frame sizes and frame-per-file flushing are honored at encoder block
  boundaries; compressed-output thresholds remain approximate and can be
  exceeded by the bounded pipeline and trailer. The matcher emits a leading
  literal and splits matches above 65,538 bytes to avoid ruzstd 0.9's
  single-symbol FSE and match-length-code-52 encoding bugs.
  The existing ruzstd 0.9.0 dependency is vendored with narrow encoder patches:
  an exact Huffman payload-size lower bound skips output that would have been
  discarded, and FSE encoder state selection uses exact range arithmetic in
  place of a linear search. Measured encoded bytes remain identical. Its small
  FSE decoder update has an inlining hint. Overlapping matches expand through
  the growing initialized prefix using the existing safe ring-buffer API,
  replacing one unsafe loop and avoiding distance-sized repeated copies. No
  extra allocation or new unsafe code; ring-buffer internals are unchanged. License,
  source hash and differential validation are in `vendor/ruzstd/PATCHES.md`.
- grzip, lrzip and lzop use upstream's external-program fallback. Missing
  programs fail when the archive is opened. Explicit program filters parse
  argv using the existing command parser and never invoke a shell. Pipes
  are nonblocking and both directions are drained to avoid deadlocks;
  dropping a filter kills and reaps its child.
- Unix compress, uuencode and base64 encoding are native ports. Base64
  reports the UU filter code, as upstream does; it has its own filter name.

## XAR writing and attribute streaming

- XAR data and attributes are spooled in private, immediately unlinked files;
  the compressed XML table is emitted at close. SHA-1, MD5, SHA-256 and SHA-512
  checksums and none/zlib/bzip2/LZMA/XZ data encodings are supported. Safe codec
  output is valid but need not match the C encoders byte for byte.
- Upstream checks an attribute's entire decompressed size after one decoder
  call, so small input blocks can fail even for a valid archive. The Rust
  reader collects incremental attribute output, checks decoded sizes,
  and bounds the combined owned attribute values per entry at 64 MiB before allocating. This permits
  writer round trips through small callback blocks without uncontrolled
  allocation from the XML size field.

## Disk traversal and extraction (`src/read_disk.rs`, `src/write_disk.rs`)

- Standard read-side uid/gid names use upstream's bounded 127-slot cache,
  including missing names; custom lookup callbacks remain uncached. Filesystem
  remote/synthetic flags are cached by the existing device ID, as upstream's
  filesystem table does. A failed filesystem probe is retried on later entries.
  Numeric filesystem IDs, symlink handling and write-side owner lookup fallback
  behavior are unchanged. Real Opus 5.5 design/review and byte-identical
  six-format many-file measurements are retained in `../diagnostics/round8-system`.
- On ARM macOS with Darwin kernel major 21 or later, parent directories are
  opened in one lookup with O_NOFOLLOW_ANY when secure symlink handling is
  requested. The resulting descriptor remains pinned for child operations.
  Any failed lookup uses the original component walker, including its symlink
  unlinking and automatic-directory behavior. A cached uname query gates this
  path conservatively; old/unknown kernels and other targets keep the walker.
  The query adds two documented unsafe blocks in the OS FFI layer; directory
  opening uses safe std APIs. Parents are opened with O_SEARCH, so like
  upstream's paths they need only search permission, the last one included.
  Actual Opus 5.5 design/final review, primary kernel sources, filesystem
  differential checks and rotating six-format measurements are retained in
  `../diagnostics/round9-system`.
- `SECURE_SYMLINKS` runs upstream's check_symlinks walk (its openat variant)
  before anything is created, with its messages and errnos, and still opens
  each parent with O_NOFOLLOW afterwards, so a symlink swapped in after the
  walk can't redirect the write. Missing parents are made by a port of
  create_dir that works relative to each opened parent rather than by path;
  it follows symlinks as upstream's stat() does, except under
  SECURE_SYMLINKS, where the walk has already removed or refused them.
- Ordinary non-atomic regular files first attempt exclusive creation after all
  path/security checks, like upstream. Success proves the destination was absent
  and avoids its pre-create stat; any error follows the original existing-file
  checks. On Apple, new non-PERM files already have their final mode from the
  kernel's creation-time umask, so permission restoration needs neither another
  umask query nor chmod. This follows upstream when the caller changes umask
  between header and finish. Other platforms retain chmod because inherited
  default ACLs can alter creation modes. Existing files, atomic writes, special
  permissions, links and deferred directories retain their previous handling.
  Actual Opus 5.5 design/final review, C ABI mode/status checks and five-rotation
  six-format extraction results are retained in `../diagnostics/round8-system`.
- Kept: when NO_OVERWRITE (or NO_OVERWRITE_NEWER) keeps what is in the way
  of a non-directory entry, upstream still restores the entry's metadata onto
  it by path, a directory included, and its chmod follows a symlink there
  (without SECURE_SYMLINKS, which removes one). Here what was kept is left
  alone. Data writes
  to it fail with "Attempt to write to an empty file" as upstream's do.
- Kept: where upstream restores a non-directory's metadata by path, its
  chmod() follows a symlink in the entry's place, e.g. for a hardlink entry
  with data whose target is a symlink; here the mode goes on the link itself,
  as all its other calls do. A directory's extended attributes, Mac metadata
  and ACLs are set by the entry's own pathname, so a trailing slash makes them
  follow a symlink to a directory in its place (`d/` over `d -> ../outside`);
  here they go on the link itself.
- Kept: an AppleDouble entry `._name` that is a symlink with data (cpio keeps
  the target as data) is opened by upstream through the link, to merge
  whatever it points to; here it isn't followed, so the merge fails with
  "Failed to open a restoring file" and ELOOP rather than the target's errno.
- Disk writes keep each parent directory open and create/open/link children
  relative to its descriptor. `SECURE_SYMLINKS` opens every ancestor with
  `O_NOFOLLOW`; replacing an ancestor after the check cannot redirect a write.
  `SECURE_NODOTDOT` and `SECURE_NOABSOLUTEPATHS` check both destination and
  hardlink source. Symlink targets remain literal, as upstream permits.
- Metadata is restored in upstream's order and with its messages. As
  upstream, a new directory's times and mode, any directory's ACLs and Mac
  metadata, and immutable or append-only flags wait for close, which applies
  them deepest path first to what still has the entry's type; data-less
  hardlinks leave the target's metadata alone. Like upstream, the waiting
  entries hold names, not descriptors. Close walks the parents again as the
  entry was made and opens the entry with O_NOFOLLOW. Kept, stricter than
  upstream: under SECURE_SYMLINKS a parent swapped for a symlink before close
  is not followed, and an entry that is no longer the file (device and inode)
  finish_entry saw is skipped, where upstream fixes up whatever has its name. Kept: upstream's close-time
  flags fixup starts from the flags of the last entry's path (its stat cache
  is filled from `a->name`), and skips the fixup if that path is gone; here
  each file's own flags are used. "Can't set UID=%jd" carries whatever errno
  upstream last saw, which isn't meaningful; here it is EPERM. A SAFE_WRITES
  temporary file is renamed into place before its metadata is restored rather
  than after; the result is the same. A failure to build an ACL warns "Failed
  to set acl..." rather than with upstream's ARCHIVE_FAILED messages for
  acl_create_entry and the like, which only fail on ENOMEM.
- Ported as-is: upstream makes a missing parent directory with mode
  (0777 & ~umask | 0700) & 0775 and records a fixup to 0777 & ~umask, but the
  fixup never applies because create_dir doesn't set its file type, so under a
  umask such as 0 parents end up 0775, not 0777.
  Short writes are extended to the entry size and block writes seek to their
  explicit offsets. Cached physical position and length avoid seeks for
  contiguous writes and resizing files already at their target length. Sparse
  holes still require extension; write errors invalidate both cached values.
  Ordinary permission restoration skips the ownership stat needed only when
  set-ID bits might require clearing. Ownership/permission failures are warnings.
- Logical and hybrid disk walks fall back to the symlink for a broken target
  or a directory ancestor cycle. Matching queries use the live match handle
  so unmatched inclusion counts reflect the walk. Descend requests made from
  callbacks are recorded without reborrowing the active disk state.
- Platform calls and client callbacks live only in `src/ffi/disk*.rs`.
  Extended attribute lists are bounded to 1 MiB and individual values to
  16 MiB before allocating. Darwin ACLs are translated through native ACL
  APIs. Mac metadata uses native `fcopyfile` packing/unpacking; AppleDouble
  entries are merged into their sibling using the same anchored directory.
- HFS compression uses safe miniz_oxide zlib blocks. Resource-fork headers,
  inline attributes and compression flags match upstream; compressed block
  bytes can differ from zlib. Optional compression is limited to files of
  256 MiB, with larger files retaining an ordinary data fork to bound the
  resource buffer. Failure to enable compression restores the data fork.
- `SAFE_WRITES` creates a fresh sibling with `O_EXCL` and renames it on entry
  completion. A failed/abandoned write removes only its owned temporary.
  Sparse metadata is discovered through `SEEK_DATA`/`SEEK_HOLE`; block reads
  skip holes, while ordinary reads preserve zero bytes. Sparse maps are
  bounded to one million extents. Remote filesystem detection uses native
  `statfs`; synthetic status is unknown (-1) on macOS, as upstream's build.

## Archive writers

- Writer lifecycle, callback/file/fd/FILE/memory outputs, format/filter options,
  selectors and passphrase callbacks are implemented at the public ABI boundary.
  Caller-owned fds and FILE streams remain open. Callback close return values
  are ignored, matching upstream; failed client opens release their free callback.
- Tar variants stream data and preserve pax sparse maps, ACLs, flags, extended
  attributes and AppleDouble metadata. GNU long names, charset conversion and
  pax binary fallbacks follow upstream. Pax alignment is bounded to 1 MiB.
- ar and cpio variants, raw, shar, mtree and WARC writers are native safe ports.
  Mtree hashes are computed incrementally, including replacement of preset
  entry digests when data is supplied. Its directory tree is walked without
  recursion.
- ZIP streams stored and compressed entries, ZIP64 records, traditional
  encryption and WinZip AES. Compression uses the safe filter backends described
  above; compressed bytes can differ from upstream. Passphrase copies are
  cleared on writer destruction.
- ZIP LZMA properties use the safe encoder's actual preset dictionary size.
  Encryption covers the ZIP-LZMA prefix as well as compressed bytes, including
  the AES authentication checksum.
## Writer byte-identity sweep

Upstream bsdtar was compared with upstream bsdtar over this library, both
writing every format from the same tree and from a tar of entries a disk
can't hold (invalid UTF-8, big ids, devices, pathological names), in a
UTF-8 and the C locale, plus xattr, ACL and mac-metadata runs. All
outputs match byte for byte, with the same messages and exit codes,
except the ones listed under "Still different".

Kept on purpose:

- A negative entry size is no data. Upstream's gnutar and pax writers take
  it as about 2^64 bytes still to write and pad toward that forever.
- mtree's `rmd160digest`: the macOS oracle is built without RIPEMD-160 and
  omits the keyword; this library always has it (see Crypto).
- The cpio trailer is written by `close`, which has no handle, so a
  `hdrcharset` that can't convert `TRAILER!!!` doesn't warn as upstream's
  close does.
- WARC dates print the year as `{:04}`, as macOS `strftime("%Y")` does;
  glibc doesn't zero-pad years before 1000.

Upstream quirks ported as-is:

- pax: each ACL attribute's result replaces the header's return code, so a
  charset warning before it is lost. The main ustar header's format errors
  are ignored but their messages stay on the handle. The GNU sparse map is
  written by the first data call, so a sparse entry with no data written
  lacks it.
- gnutar: a symlink target that won't convert is reported under the
  hardlink's name, `(null)`.
- shar: a `.` directory or an unsupported type returns before the entry
  state resets, so the next entry repeats the previous file's `SHAR_END`
  (and shardump its last partial line).
- ar: a member rejected with `ARCHIVE_WARN` pads again for the odd-sized
  member before it.
- xar: the heap is copied for its whole length starting after the TOC
  checksum slot, so archives end with the first checksum-size bytes of the
  compressed TOC. fflags are written as empty `<flags/>` and `<ext2/>`.
- 7zip: the first non-empty file's encoder setup replaces the return code
  of a pathname-conversion warning. zip sets the UTF-8 flag on non-ASCII
  names that aren't valid UTF-8. ISO9660's Joliet name for `dir/.` is `.`;
  the ISO9660 writer's other quirks are listed under "ISO9660 writer".

Still different:

- xar in a non-UTF-8 locale escapes a non-ASCII symlink target differently.
- 7zip compression names are matched in any case, and invalid levels have
  other messages than upstream's.

## 7zip writer

- The 7zip writer uses a seekable anonymous temporary file for encoded data
  and native solid stream headers. Copy, deflate, BZip2, LZMA1, LZMA2,
  Zstandard and the native PPMd7 encoder are supported. BZip2 and Zstandard
  output differs from the C codecs' bytes. PPMd has checked model accesses and a bounded
  model arena; its encoded bytes follow the upstream range coder.

## ISO9660 writer (`src/write/format/iso9660/`)

- A function-by-function port of `archive_write_set_format_iso9660.c`,
  under upstream's function names, split along its sections: `tree`,
  `idr`, `record`, `descriptor`, `boot` and `zisofs`. Linked lists are
  vectors of indices, except the path tables' `ptnext` chains, which
  deep-directory relocation shares between levels. Everything goes through
  upstream's 64 KiB write buffer and an unlinked temporary file, so where
  upstream misplaces bytes in that buffer, so does this.
- Images match upstream's byte for byte, with the same messages and exit
  codes, in the 3,493 cases of `../diagnostics/round14-iso9660` (every
  option, every level, Joliet and Rock Ridge variants, zisofs, El Torito,
  deep trees, 3,000 random archives and an API probe): 3,459 on macOS, and
  3,457 on Linux (glibc 2.41, aarch64) against upstream built there. The
  others are inputs upstream crashes on, listed below.
- The identifier resolver keeps upstream's red-black tree (`src/rb.rs`,
  insertion and lookup from `archive_rb.c`). Its comparison is not a total
  order: `FOO` and `FOO.` each sort before the other, so the tree's shape
  decides which names collide and how they sort.
- Path tables are sorted the way upstream's `qsort` sorts them on each
  platform. Upstream's comparison only looks at the part of a directory
  name before its last dot, so `A.B` and `A.C` compare equal and their
  order is whatever libc leaves: on Apple platforms that of Apple Libc's
  unstable `qsort`, ported in `qsort.rs`; elsewhere that of a stable merge
  sort, which glibc's `qsort` is (checked against upstream on glibc 2.41).
  Other libcs (musl, the BSDs) may order such entries differently and are
  not matched.
- Sizes from entries use checked or wrapping arithmetic as upstream's
  types do; the block pointer table (up to 128 MiB for a 4 GiB file with
  128-byte zisofs blocks), path tables and resolver pools allocate
  fallibly. Unmaking a zisofs boot image streams through a 32 KiB buffer
  as upstream does, so it needs no size cap; it inflates with miniz_oxide,
  whose consumption can differ from zlib's only after output space runs
  out, which upstream's dropped input (below) has already broken.

Where upstream reads or writes through a null or wild pointer, this fails
with `ARCHIVE_FATAL` (bsdtar exits 1 where upstream's dies of SIGSEGV):

- `!volume-id`, `!publisher`, `!application-id`, `!copyright-file`,
  `!abstract-file`, `!biblio-file` and `!boot-catalog` reach `strlen(NULL)`;
  here they fail with "Invalid value(empty) for option ``KEY''".
- A Rock Ridge "SL" entry that continues with exactly 11 bytes left in its
  continuation area sets the continue flag of a component it never
  started: "No room for a symbolic link component".
- With more than eight levels kept (`!limit-depth`, or `iso-level=4` with
  a tree deeper than 8) and Rock Ridge on, relocation leaves an entry
  behind that the walks then treat as a directory, and upstream
  dereferences its file's exhausted extent list: "No current file
  content".
- An existing `rr_moved` directory that heads the root's subdirectory
  chain but not its children: `isoent_remove_child()` runs off the chain.
  "Can't remove an entry from its directory".
- A path table chain whose length disagrees with its count would overrun
  upstream's array or leave it partly unset; it fails here. A buffer
  position `wb_set_offset()` would put past the buffer fails too.

Where upstream reads uninitialized memory this uses zeros: the boot
table checksum's last word when the first read ends inside it (after a
later read, upstream sums the bytes the previous read left, and so does
this); the `struct tm` of a time `localtime_r()` can't convert; the bytes
a level-1 name copies from past its end, which never reach the image; and
a path component longer than NAME_MAX in an option's file name, which is
not found here where upstream looks up an unset name and steps back a
byte before the string.

Upstream bugs ported as-is:

- zisofs truncates a block's zlib stream when its output doesn't fit the
  write buffer: zisofs_write_to_temp() stops calling deflate() once the
  input is consumed and then resets the stream. Incompressible blocks
  usually hit it.
- zisofs_finish_entry() moves back to the file's start to write its header
  and block pointers. If that start has been flushed, the partial block
  still buffered is dropped and the header lands on it, so the file's last
  bytes are replaced. Files whose compressed data outgrows the buffer hit
  it.
- After an all-zero zisofs block moves the write position back,
  deflate() keeps writing where the position was, so a later block in
  the same call lands off by the bytes the zero block had produced (its
  zlib header when its data came in more than one call).
- A file holding an mkzftree image is detected after its zisofs header has
  been reserved: its own header goes into the 'ZF' entry but its data
  follows the zeros reserved for a new one, so readers reject it ("Illegal
  zisofs file body"). Detected only once compression has begun (data in
  pieces under 64 bytes), it keeps the compressed start and the rest
  follows raw.
- Unmaking a zisofs boot image hands each 32 KiB read to zisofs_extract()
  once and drops what it leaves, so only single-block images survive;
  others fail with "Can't read temporary file(0)" or "Illegal zisofs block
  pointers(cannot seek)".

  Together these corrupt zisofs files that upstream's own reader then
  rejects ("zisofs decompression failed (-3)"); the reimplementation this
  replaces wrote them correctly.
- Relocation runs its second pass over level 8 on entries the first pass
  already relocated, so a tree deeper than 13 levels fails with "Unable to
  insert rr_moved entry"; so do two relocated directories of one name.
- A path table that fills its last 4 KiB block exactly makes
  write_path_table() return the size of its deepest level, which close
  takes for a failure: `ARCHIVE_FATAL` with no message (bsdtar prints
  "(null)").
- "Directories too deep" returns before the last write-out, so the image
  lacks what was still buffered, up to 64 KiB of its end: padding, or with
  `!pad` directory records and file data.
- `Rockridge` is checked under the switch's `case 'r'`, so it is an
  undefined option.
- Symbolic links and empty files get extent numbers counting down from
  0xFFFFFFF0. A hardlink target added again under the same name keeps the
  first one's link group.
- `limit-dirs` checks the Joliet directory count when Joliet is on.
- An entry with a declared body but no bytes written is not zero-filled or
  registered as file content (with zisofs it is, since its reserved header
  counts as content). An unwritten boot image therefore fails while
  emitting the image, after the volume descriptors.

## Deflate compressor (`deflate/`)

- Writers compress with the `deflate` crate, a safe port of zlib 1.2.12's
  deflate.c and trees.c, instead of miniz_oxide (the "gzip (miniz_oxide)"
  line under Write compression filters predates it); miniz_oxide still
  inflates. Apple's /usr/lib/libz.1.dylib (1.2.12) emits the same bytes as
  vanilla zlib 1.2.12 for the benchmark datasets at levels 0-9, so C
  bsdtar's tar.gz and ZIP data is reproduced byte for byte.
- Not ported, since libarchive does not use them: the gzip wrapper,
  strategies other than the default, deflateSetDictionary, deflateParams,
  deflatePrime, deflateBound, deflateCopy and detect_data_type (it only sets
  strm->data_type). zlib's high_water zeroing is unnecessary: the window
  starts zeroed, and bytes past the input never change the output.
- The hash key is computed from each string's three bytes instead of
  zlib's running ins_h; with hash_shift * MIN_MATCH >= hash_bits the keys
  are the same.
- zisofs output is byte-identical to upstream's, including the blocks whose
  zlib streams upstream truncates (see "ISO9660 writer").
- Unchanged here: the gzip filter writes any original-filename, where
  upstream ignores one of 32K or more with a warning.

## Rust API and front-ends (`src/api/`, `tools/`)

- bsdcat restores `SIGPIPE`'s default action first thing: Rust's runtime
  starts every program with it ignored, so `bsdcat big.gz | head` would
  otherwise report "Write error" instead of dying of the signal as C bsdcat
  does. Unlike C, a `SIGPIPE` the parent ignored is not inherited; stable
  Rust has no way to keep it.
- `lafe_warnc` writes its message with one `write`, where upstream's
  unbuffered stderr makes one per `fprintf`; the bytes are the same.
- `lafe_explicit_bzero` zeroes and then hands the buffer to
  `std::hint::black_box`, the barrier glibc's `explicit_bzero` uses, instead
  of upstream's volatile-pointer loop, which needs `unsafe`.
- `lafe_readpassphrase` is upstream's `readpassphrase` fallback (Linux's);
  macOS builds of upstream use libc's, which is the same OpenBSD code. Only
  `RPP_ECHO_OFF`, the flag front-ends pass, is ported.
- `archive_read_extract2` on a NULL entry fails (`ARCHIVE_FATAL`) where
  upstream crashes, and the progress callback is called through a shared
  closure, so the callback can call back into the handle as before.
- `ArchiveRead::data_block` copies each block (the reader's block borrows a
  `Reader` local to the call); the C export and `data_into_fd` don't.

## LZMA encoding (`vendor/lzma-rust2/src/enc`, `src/lz`)

- The xz, lzma, lzip, 7zip LZMA1/LZMA2 and zip LZMA writers encode with a
  safe Rust port of liblzma 5.8.4's encoder, vendored into lzma-rust2
  (provenance and validation in `vendor/lzma-rust2/PATCHES.md`). Given the
  same input bytes and options, the compressed bytes equal upstream's
  built with liblzma 5.8.4, including all presets. Other liblzma versions
  may differ.
- 7zip LZMA1/LZMA2 streams and encoded headers use the preset dictionary,
  as upstream does, without staging the input to bound the dictionary by
  its size: that changed liblzma's
  hash table size and so the encoded bytes.
- Ported as-is: after an LZMA2 chunk is stored uncompressed while the
  parser had read ahead, liblzma's encoder position lags the stream by the
  read-ahead bytes. Every position context was just reset, so the lag only
  relabels them and decoders are unaffected; the bytes match upstream.
- Archives of directory trees can still differ from upstream: Rust
  `read_disk` visits a directory's entries in a different order than C, so
  the encoder sees different input (the many-files benchmark).

## Zstd writer encoder (`src/write/filter/zstd.rs`, vendored ruzstd)

The filter compresses with a safe port of libzstd 1.5.7's compressor in the
vendored ruzstd (`vendor/ruzstd/PATCHES.md`), replacing the earlier bounded
single-hash matcher. Levels and options keep libarchive's meaning.

### Differences

- Compressed bytes differ from libzstd's; sizes are within about 1% (level
  3: 0.72% smaller to equal on the benchmark tars). libzstd's streaming
  buffer wraps and matches across the wrap with its external-dictionary
  variants; the port keeps one contiguous window, so candidates near the
  wrap differ. A new offset equal to a repeat offset is coded as a repeat
  code, which libzstd's matchers do not do.
- Levels 13-22 do not use libzstd's binary-tree or optimal parsers: they
  keep libzstd's windows and table sizes and search with lazy2 (at most 64
  candidates). They compress about like level 12, not like libzstd's
  levels 13-22.
- The row match finder computes hashes when used rather than eight positions
  ahead (libzstd uses that cache to prefetch); the positions searched are the
  same. Its hash salt is the one a fresh libzstd context uses for its first
  frame; libzstd changes it on each reuse.
- `threads` is still accepted and ignored: compression is single threaded.
- `long=N` now sets the window log as libarchive's `ZSTD_c_windowLog` call
  does (it was accepted and ignored). As with libzstd, frames with a window
  above 2^27 are refused by default decoders, including this port's reader.
- A frame ended before any input has the usual window descriptor and no
  content size; libzstd, given only `ZSTD_e_end`, writes a single-segment
  header with content size 0. Both decode to nothing.

## Fuzzing (`fuzz/`)

- Decompression bombs are unbounded, as upstream. A 293-byte gzip found by
  `filter_gzip` stores gzip headers whose content is again such a gzip, so
  each of the (up to 25) nested filter layers multiplies the output; upstream
  `bsdcat` writes gigabytes from it too. The harness stops reading entry data
  after 1 MiB per input instead of the library imposing a limit.

## bsdunzip (`tools/unzip/`)

- Not ported: `bsdunzip_windows.c` and the `_WIN32` branches of
  `bsdunzip.c`; the `lutimes`/`futimes` fallbacks for libcs without
  `utimensat`/`futimens`; the glibc-only `setenv("POSIXLY_CORRECT")`, which
  only matters to GNU `getopt(3)` and the port has its own parser; and
  `OPTION_NONE`, which the parser never returns.
- A zip file named `-` (reachable as `bsdunzip -- -`; `-` alone is an empty
  option group) is standard input in intent, but upstream calls
  `strlen(NULL)` on it and crashes (SIGSEGV). The port reads standard input
  and prints the name as `(null)`, which is what upstream's printf would
  print.
- Standard output is Rust's line-buffered `Stdout`, where C's is fully
  buffered unless it is a terminal. The bytes are the same, and every
  message to standard error flushes it first, as upstream's do, so only the
  interleaving of the "replace ...?" prompt (which does not flush) with
  earlier output differs when both streams go to one file.
- `error()` after a short or failed `write(2)` reports the failure's errno;
  after a short write with no error, upstream reports a stale `errno` and
  the port reports 0.
- The passphrase buffer is allocated and zeroed for each prompt, not once
  and zeroed at the end; the bytes handed to the library are a copy either
  way. `lafe_readpassphrase` exits on every error but `EINTR`, so the
  callback's own `error("Error reading password")` can't be reached.
- `close(2)` of an extracted file goes through `sys::close`, since std's drop
  would hide the error upstream reports.

## bsdcpio (`tools/cpio/`)

- Not ported: `cpio_windows.c` and the `_WIN32` branches; the
  `HAVE_UTIMES` fallback of `restore_time`; and the members of `struct cpio`
  nothing reads (`fd`, `compress_program`, the name caches' `probes` and
  `hits`) or nothing sets (`day_first`, so `-tv` always formats dates
  month first). `file_to_archive` and `entry_to_archive` return nothing:
  upstream's callers ignore the first's value, and the second's is always 0.
- An option is a `u8`, the short option's byte or an `OPTION_*` code, so the
  codes (1 to 14) can be match patterns. `cpio->argc` is `argv.len()`.
- `strtol` for `-C` and `strtoul` for `-R` are one decimal parser,
  `parse_int`. It refuses what `strtoul` would wrap from a negative number
  (bar `-0`), where upstream accepts only the few wrapped values that land
  in `int`'s range (-2^64+1 and the like).
- `getpwnam` and the other lookups are the `_r` functions, in `sys`. Upstream
  warns `getpwuid(%lld) failed` when `errno` is set and not `ENOENT`; the
  port warns when the `_r` function returns an error other than `ENOENT`.
- The `-tv` listing goes through a `BufWriter`, as C's standard output is
  fully buffered, and is flushed before every exit. Other standard output
  (`--help`, `--version`) is Rust's line-buffered `Stdout`. With both
  streams in one file, upstream's "N blocks" comes before the listing (the
  listing is flushed on exit) and the port's after it.
- `SIGPIPE` stays ignored, which is Rust's start-up state and what upstream
  sets; `SIGCHLD` is reset to its default, as upstream does.
- `-i`, `-o` and `-p` share one match arm: their bodies are the same bar
  `-p`'s two flag changes.
- `list_item_verbose` writes each field into one buffer in order, so the
  names are not copied out of the entry and the name cache; the output is
  the same. A date `strftime` returns nothing for (as for a time
  `localtime` rejects) prints as "invalid mtime".
- The passphrase buffer is allocated and zeroed for each prompt, as in
  bsdunzip.
- `cpio_rename` reads `/dev/tty` with `read_until`, cutting the line at a NUL
  as `getline` plus C string handling does.
- `-p` of a FIFO hangs in the port and in the relinked C tool alike, in
  the library's disk writer, after it creates the FIFO.
- `Output` is `cpio->archive`, which is a `struct archive` that is a writer
  in `-o` mode and a disk writer in `-p` mode.

## bsdtar (`tools/tar/`) and the write and read-disk API

### Ported as-is

- `add_substitution` copies the replacement of a `-s` rule dropping one
  backslash before each character, and `apply_substitution` then looks for
  `\1`..`\9`, `\~` and `\\` in what is left, so a single backslash escapes
  nothing: `-s '/\(a\)\(b\)/\2\1/'` rewrites "abc" to "21c", and a
  back-reference takes two backslashes (`\\2`). C bsdtar does the same at
  the pin.
- `read_archive` reports a failed `--fast-read` count with the reader's
  error message, not the match handle's; and "Unexpected end of filename
  list" after a trailing `-C` in a `-T` list prints whatever errno holds.

### Differences

- `pathcmp` is not ported: nothing in tar/ calls it at the pin.
- `-tv`'s `strftime` buffer is 64 bytes, where upstream's is 100; a longer
  date (no locale makes one) would print as "-- -- ----".
- The SIGINFO/SIGUSR1 progress report during `-x` divides by the bytes
  read, as upstream does; with none read yet it reports 0% where upstream
  would divide by zero.
- `-x`, `-t` and `@archive` read headers into an entry of their own
  (`next_header2` with `ArchiveEntry::new2`) instead of the reader's
  `a->entry`, as the Rust API must to hand the entry back to the reader
  (`extract2`) or read data while it is borrowed. The only format that
  writes `a->entry` while reading data, multivolume RAR, updates the
  reader's entry instead of the one bsdtar holds, which bsdtar only uses
  afterwards for an error message.
- The typed `ArchiveRead::extract_set_progress_callback` closure gets the
  reader and the entry being extracted (what C's client data points to),
  since a closure can't hold either while `extract2` borrows them.
- `ArchiveReadDisk`'s metadata filter and excluded callback get the entry
  as an `ArchiveEntry` by moving the reader's `Entry` into one for the
  call and back.
