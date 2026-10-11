//! The helpers libarchive's front-ends share, ported from upstream's
//! `libarchive_fe/`: messages prefixed with the program's name, reading
//! lists of names, passphrase prompts and chmod-style modes.
//!
//! Upstream's `lafe_fnmatch.c` and `lafe_getline.c` are fallbacks for libcs
//! without `fnmatch(3)` and `getline(3)`, which macOS and Linux have, so
//! they are not ported.

#![deny(unsafe_code)]

pub mod lafe_err;
pub mod lafe_setmode;
pub mod line_reader;
#[allow(unsafe_code)]
pub mod sys;
