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
- Functions that dispatch through the vtable on a NULL handle return an
  error (`ARCHIVE_FATAL`, 0 or NULL) instead of crashing, and a call on the
  wrong kind of handle reports the check_magic error instead of jumping
  through a NULL vtable slot.
