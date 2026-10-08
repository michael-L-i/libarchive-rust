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
  library is linked, so those sections never appear. Compression and ACL
  backends are absent until phase 2 reports them (archive_version_details.c).
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
- Output is not NUL-terminated and buffers are `Vec`s, so the buffer-extent
  assertions of `test_archive_string` have no equivalent.
- A string conversion error is returned as `ConvError { errno, message }`
  where upstream calls `archive_set_error(a, ...)`; the caller sets it.
- On macOS the `ru_RU.KOI8-R` locale fails upstream's `setCheckedLocale`
  check (0xE1 does not decode to U+0410), so upstream's
  `test_archive_string_update_utf8_koi8` skips there; a variant that checks
  only the multibyte forms runs instead.
