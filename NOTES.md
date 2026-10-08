# Notes

Suspected upstream bugs ported as-is, and deliberate divergences, per unit.

## archive_string (`src/archive_string.rs`)

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
