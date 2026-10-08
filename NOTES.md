# Notes

Upstream behavior that looks wrong and is ported as-is, and intended
differences.

## Ported as-is

- `archive_write_fail` returns the new state (`ARCHIVE_STATE_FATAL`, 0x8000),
  not `ARCHIVE_FATAL` (archive_virtual.c).
- `__archive_check_magic` lists unknown bits of a state mask as `??`, so a
  check against `ARCHIVE_STATE_ANY` prints `.../closed/??/??/...`
  (archive_check_magic.c).

## Differences

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
