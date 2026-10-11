/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011-2014, Mike Kazantsev
 * All rights reserved.
 */

// Ported from cat/bsdcat.c and cat/bsdcat.h.

//! bsdcat: writes each file, or standard input, to standard output,
//! decompressed by whatever filters libarchive has.

#![deny(unsafe_code)]

mod cmdline;

use libarchive_fe::lafe_err::{lafe_getprogname, lafe_setprogname, lafe_warnc};
use libarchive_fe::sys;
use libarchive_rust::{ArchiveRead, Status, version_details};
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString, c_int};
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::process::exit;

const BYTES_PER_BLOCK: usize = 20 * 512;

/// config.h's, which upstream's CMakeLists.txt makes from build/version.
const BSDCAT_VERSION_STRING: &str = "3.9.0";

/// `struct bsdcat`: the option parser's state.
pub struct Bsdcat {
    getopt_state: cmdline::State,
    /// What is left of the word being parsed.
    getopt_word: Vec<u8>,
    /// The words of the command line not parsed yet, the program name
    /// first.
    argv: VecDeque<Vec<u8>>,
    argument: Option<Vec<u8>>,
}

pub const OPTION_VERSION: c_int = 0;

fn usage(stream: &mut dyn Write, eval: c_int) -> ! {
    let p = lafe_getprogname();
    let msg = [
        b"Usage: ".as_slice(),
        &p,
        b" [-h] [--help] [--version] [--] [filenames...]\n",
    ];
    let _ = stream.write_all(&msg.concat());
    exit(eval)
}

fn version() -> ! {
    let details = version_details();
    let _ = writeln!(io::stdout(), "bsdcat {BSDCAT_VERSION_STRING} - {details} ");
    exit(0)
}

fn bsdcat_print_error(a: &ArchiveRead, current_path: &[u8]) {
    let error = a.error_string();
    // printf prints a NULL string as "(null)".
    let error = error.as_deref().unwrap_or(b"(null)");
    lafe_warnc(0, [current_path, b": ", error].concat());
}

fn bsdcat_next() -> ArchiveRead {
    let mut a = ArchiveRead::new();
    a.support_filter_all();
    a.support_format_empty();
    a.support_format_raw();
    a
}

/// Copies `filename` (standard input for `None`), decompressed, to
/// standard output. False if there was an error, which it reports.
fn bsdcat_read_to_stdout(filename: Option<&[u8]>, current_path: &[u8]) -> bool {
    let mut a = bsdcat_next();
    let mut ok = true;
    let mut print_error = |a: &ArchiveRead| {
        bsdcat_print_error(a, current_path);
        ok = false;
    };
    let filename = filename.map(|f| Path::new(OsStr::from_bytes(f)));
    if a.open_filename(filename, BYTES_PER_BLOCK) != Status::Ok {
        print_error(&a);
    } else {
        match a.next_header() {
            Status::Ok => {
                if a.data_into_fd(io::stdout().as_fd()) != Status::Ok {
                    print_error(&a);
                }
            }
            // For empty payloads don't try and read data.
            Status::Eof => {}
            _ => print_error(&a),
        }
    }
    if a.close() != Status::Ok {
        print_error(&a);
    }
    ok
}

fn main() {
    // Rust programs start with SIGPIPE ignored; C programs don't.
    sys::default_signal(libc::SIGPIPE);
    // Do not ignore SIGCHLD.
    sys::default_signal(libc::SIGCHLD);

    let argv: VecDeque<_> = std::env::args_os().map(OsString::into_vec).collect();
    lafe_setprogname(argv.front().map(|a| OsStr::from_bytes(a)), "bsdcat");

    let mut bsdcat = Bsdcat {
        getopt_state: cmdline::State::Start,
        getopt_word: Vec::new(),
        argv,
        argument: None,
    };

    // Each option ends the program.
    if let Some(c) = bsdcat.getopt() {
        match c {
            c if c == c_int::from(b'h') => usage(&mut io::stdout(), 0),
            OPTION_VERSION => version(),
            _ => usage(&mut io::stderr(), 1),
        }
    }

    let mut exit_status = 0;
    if bsdcat.argv.is_empty() {
        if !bsdcat_read_to_stdout(None, b"<stdin>") {
            exit_status = 1;
        }
    } else {
        for f in &bsdcat.argv {
            if !bsdcat_read_to_stdout(Some(f), f) {
                exit_status = 1;
            }
        }
    }
    exit(exit_status);
}
