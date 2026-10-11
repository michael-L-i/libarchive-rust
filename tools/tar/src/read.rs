/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2003-2007 Tim Kientzle
 * All rights reserved.
 */

// Ported from tar/read.c.

//! The -t and -x modes.

use crate::util::{
    Stdout, do_chdir, edit_pathname, error_string, list_item_verbose, passphrase_callback, path,
    safe_fputs, yes,
};
use crate::*;
use libarchive_fe::lafe_err::{lafe_errc, lafe_warnc};
use libarchive_fe::lafe_setmode::lafe_getmode;
use libarchive_fe::sys;
use libarchive_rust::{Archive, ArchiveEntry, ArchiveMatch, ArchiveRead, ArchiveWriteDisk, Status};
use std::io::{self, Write};

pub fn tar_mode_t(bsdtar: &mut Bsdtar) {
    read_archive(bsdtar, b't', None);
    if unmatched_inclusions_warn(&mut bsdtar.matching, b"Not found in archive") {
        bsdtar.return_value = 1;
    }
}

pub fn tar_mode_x(bsdtar: &mut Bsdtar) {
    let mut writer = ArchiveWriteDisk::new();
    if bsdtar.flags & OPTFLAG_NUMERIC_OWNER == 0 {
        writer.set_standard_lookup();
    }
    writer.set_options(bsdtar.extract_flags);

    read_archive(bsdtar, b'x', Some(&mut writer));

    if unmatched_inclusions_warn(&mut bsdtar.matching, b"Not found in archive") {
        bsdtar.return_value = 1;
    }
}

fn progress_func(verbose: i32, a: &Archive, entry: &mut ArchiveEntry) {
    if !need_report() {
        return;
    }

    let mut stderr = io::stderr();
    if verbose != 0 {
        let _ = stderr.write_all(b"\n");
    }
    let comp = a.filter_bytes(-1) as u64;
    let uncomp = a.filter_bytes(0) as u64;
    let compression = if comp > uncomp {
        0
    } else {
        // Upstream divides by zero when nothing is read yet.
        ((uncomp - comp)
            .wrapping_mul(100)
            .checked_div(uncomp)
            .unwrap_or(0)) as i32
    };
    let _ = write!(stderr, "In: {comp} bytes, compression {compression}%;");
    let _ = writeln!(stderr, "  Out: {} files, {uncomp} bytes", a.file_count());
    let _ = stderr.write_all(b"Current: ");
    safe_fputs(entry.pathname(), &mut stderr);
    let _ = writeln!(stderr, " ({} bytes)", entry.size());
}

/// Handle 'x' and 't' modes.
fn read_archive(bsdtar: &mut Bsdtar, mode: u8, mut writer: Option<&mut ArchiveWriteDisk>) {
    while let Some(arg) = bsdtar.argv.pop_front() {
        if bsdtar.matching.include_pattern(&arg) != Status::Ok {
            let msg = [
                b"Error inclusion pattern: ".as_slice(),
                &error_string(&bsdtar.matching),
            ];
            lafe_errc(1, 0, msg.concat());
        }
    }

    if let Some(names) = &bsdtar.names_from_file {
        let null = bsdtar.flags & OPTFLAG_NULL != 0;
        if bsdtar.matching.include_pattern_from_file(path(names), null) != Status::Ok {
            let msg = [
                b"Error inclusion pattern: ".as_slice(),
                &error_string(&bsdtar.matching),
            ];
            lafe_errc(1, 0, msg.concat());
        }
    }

    let mut a = ArchiveRead::new();
    if bsdtar.cset.read_support_filter_program(&mut a) == 0 {
        a.support_filter_all();
    }
    a.support_format_all();

    if let Some(reader_options) = std::env::var_os(ENV_READER_OPTIONS) {
        // Prepend magic code to ignore options for a format or modules
        // which are not added to the archive read object.
        let p = [IGNORE_WRONG_MODULE_NAME, reader_options.as_bytes()].concat();
        if a.set_options(&p) == Status::Fatal {
            lafe_errc(1, 0, error_string(&a));
        }
        a.clear_error();
    }
    if a.set_options(bsdtar.option_options.as_deref().unwrap_or_default()) != Status::Ok {
        lafe_errc(1, 0, error_string(&a));
    }
    if bsdtar.flags & OPTFLAG_IGNORE_ZEROS != 0
        && a.set_options(b"read_concatenated_archives") != Status::Ok
    {
        lafe_errc(1, 0, error_string(&a));
    }
    let r = match &bsdtar.passphrase {
        Some(passphrase) => a.add_passphrase(passphrase),
        None => a.set_passphrase_callback(passphrase_callback),
    };
    if r != Status::Ok {
        lafe_errc(1, 0, error_string(&a));
    }
    let filename = bsdtar.filename.as_deref().map(path);
    if a.open_filename(filename, bsdtar.bytes_per_block as usize) != Status::Ok {
        let msg = [b"Error opening archive: ".as_slice(), &error_string(&a)];
        lafe_errc(1, 0, msg.concat());
    }

    do_chdir(bsdtar);

    if mode == b'x' {
        // Set an extract callback so that we can handle SIGINFO.
        let verbose = bsdtar.verbose;
        a.extract_set_progress_callback(move |a, entry| progress_func(verbose, a, entry));
    }

    if mode == b'x'
        && bsdtar.flags & OPTFLAG_CHROOT != 0
        && let Err(e) = sys::chroot(path(b"."))
    {
        lafe_errc(1, e, "Can't chroot to \".\"");
    }

    let mut entry = ArchiveEntry::new2(&a);
    loop {
        // Support --fast-read option
        if bsdtar.flags & OPTFLAG_FAST_READ != 0 {
            match bsdtar.matching.path_unmatched_inclusions() {
                Err(_) => lafe_errc(1, 0, error_string(&a)),
                Ok(0) => break,
                Ok(_) => {}
            }
        }

        let r = a.next_header2(&mut entry);
        if r == Status::Eof {
            break;
        }
        if r < Status::Ok {
            lafe_warnc(0, error_string(&a));
        }
        if r <= Status::Warn {
            bsdtar.return_value = 1;
        }
        if r == Status::Retry {
            // Retryable error: try again
            lafe_warnc(0, "Retrying...");
            continue;
        }
        if r == Status::Fatal {
            break;
        }
        if entry.pathname().is_none_or(<[u8]>::is_empty) {
            lafe_warnc(
                0,
                "Archive entry has empty or unreadable filename ... skipping",
            );
            bsdtar.return_value = 1;
            continue;
        }

        if bsdtar.uid >= 0 {
            entry.set_uid(i64::from(bsdtar.uid));
            entry.set_uname(None);
        }
        if bsdtar.gid >= 0 {
            entry.set_gid(i64::from(bsdtar.gid));
            entry.set_gname(None);
        }
        if let Some(uname) = &bsdtar.uname {
            entry.set_uname(Some(uname));
        }
        if let Some(gname) = &bsdtar.gname {
            entry.set_gname(Some(gname));
        }

        if let Some(file_mode) = &bsdtar.file_mode {
            entry.set_mode(lafe_getmode(file_mode, entry.mode()));
        }

        // Note that pattern exclusions are checked before pathname
        // rewrites are handled. This gives more control over exclusions,
        // since rewrites always lose information. (For example, consider a
        // rewrite s/foo[0-9]/foo/. If we check exclusions after the
        // rewrite, there would be no way to exclude foo1/bar while allowing
        // foo2/bar.)
        match bsdtar.matching.excluded(&mut entry) {
            Err(Status::Fatal) => lafe_errc(1, 0, error_string(&bsdtar.matching)),
            // Excluded by a pattern test.
            Err(_) | Ok(true) => continue,
            Ok(false) => {}
        }

        if mode == b't' {
            // Perversely, gtar uses -O to mean "send to stderr" when used
            // with -t.
            let (mut stdout, mut stderr) = (Stdout, io::stderr());
            let out: &mut dyn Write = if bsdtar.flags & OPTFLAG_STDOUT != 0 {
                &mut stderr
            } else {
                &mut stdout
            };

            // TODO: Provide some reasonable way to preview rewrites. gtar
            // always displays the unedited path in -t output, which means
            // you cannot easily preview rewrites.
            if bsdtar.verbose < 2 {
                safe_fputs(entry.pathname(), out);
            } else {
                list_item_verbose(bsdtar, out, &mut entry);
            }
            let _ = out.flush();
            let r = a.data_skip();
            if matches!(r, Status::Warn | Status::Retry) {
                let _ = out.write_all(b"\n");
                lafe_warnc(0, error_string(&a));
            }
            if r == Status::Fatal {
                let _ = out.write_all(b"\n");
                lafe_warnc(0, error_string(&a));
                bsdtar.return_value = 1;
                break;
            }
            let _ = out.write_all(b"\n");
        } else {
            // Note: some rewrite failures prevent extraction.
            if edit_pathname(bsdtar, &mut entry) != 0 {
                continue; // Excluded by a rewrite failure.
            }

            if bsdtar.flags & OPTFLAG_INTERACTIVE != 0 {
                let name = entry.pathname().unwrap_or_default();
                if !yes(&[b"extract '", name, b"'"].concat()) {
                    continue;
                }
            }

            let mut stderr = io::stderr();
            if bsdtar.verbose > 1 {
                // GNU tar uses -tv format with -xvv
                let _ = stderr.write_all(b"x ");
                list_item_verbose(bsdtar, &mut stderr, &mut entry);
            } else if bsdtar.verbose > 0 {
                // Format follows SUSv2, including the deferred '\n'.
                let _ = stderr.write_all(b"x ");
                safe_fputs(entry.pathname(), &mut stderr);
            }

            let r = match &mut writer {
                Some(writer) if bsdtar.flags & OPTFLAG_STDOUT == 0 => {
                    a.extract2(&mut entry, writer)
                }
                _ => a.data_into_fd(io::stdout()),
            };
            if r != Status::Ok {
                if bsdtar.verbose == 0 {
                    safe_fputs(entry.pathname(), &mut stderr);
                }
                let _ = stderr.write_all(b": ");
                safe_fputs(a.error_string().as_deref(), &mut stderr);
                let msg = [b": ".as_slice(), &sys::strerror(a.errno())].concat();
                let _ = stderr.write_all(&msg);
                if bsdtar.verbose == 0 {
                    let _ = stderr.write_all(b"\n");
                }
                bsdtar.return_value = 1;
            }
            if bsdtar.verbose != 0 {
                let _ = stderr.write_all(b"\n");
            }
            if r == Status::Fatal {
                break;
            }
        }
    }

    let r = a.close();
    if r != Status::Ok {
        lafe_warnc(0, error_string(&a));
    }
    if r <= Status::Warn {
        bsdtar.return_value = 1;
    }

    if bsdtar.verbose > 2 {
        let (format, filter) = (a.format_name(), a.filter_name(0));
        let line = [
            b"Archive Format: ".as_slice(),
            format.as_deref().unwrap_or(b"(null)"),
            b",  Compression: ",
            filter.as_deref().unwrap_or(b"(null)"),
            b"\n",
        ];
        let _ = Stdout.write_all(&line.concat());
    }
}

/// Warns of each inclusion pattern nothing matched: whether there are any
/// (or the count failed).
fn unmatched_inclusions_warn(matching: &mut ArchiveMatch, msg: &[u8]) -> bool {
    loop {
        match matching.path_unmatched_inclusions_next() {
            (Status::Ok, p) => {
                let p = p.unwrap_or_default();
                lafe_warnc(0, [p.as_slice(), b": ", msg].concat());
            }
            (Status::Fatal, _) => lafe_errc(1, 0, error_string(matching)),
            _ => break,
        }
    }
    matching.path_unmatched_inclusions() != Ok(0)
}
