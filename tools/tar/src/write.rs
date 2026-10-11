/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2012 Michihiro NAKAJIMA
 * All rights reserved.
 */

// Ported from tar/write.c.

//! The -c, -r and -u modes.

use crate::util::{
    do_chdir, edit_mtime, edit_pathname, error_string, list_item_verbose, passphrase_callback,
    path, safe_fputs, set_chdir, yes,
};
use crate::*;
use libarchive_fe::lafe_err::{lafe_errc, lafe_warnc};
use libarchive_fe::lafe_setmode::lafe_getmode;
use libarchive_fe::line_reader::LineReader;
use libarchive_rust::{
    AE_IFREG, ARCHIVE_FILTER_NONE, ARCHIVE_FORMAT_BASE_MASK, ARCHIVE_FORMAT_EMPTY,
    ARCHIVE_FORMAT_TAR_PAX_RESTRICTED, ARCHIVE_MATCH_EQUAL, ARCHIVE_MATCH_MTIME,
    ARCHIVE_MATCH_OLDER, Archive, ArchiveEntry, ArchiveEntryLinkresolver, ArchiveRead,
    ArchiveReadDisk, ArchiveWrite, ReadDiskView, Status,
};
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::ops::DerefMut;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::process::exit;
use std::rc::Rc;

/// What write_archive() sets up for the functions it calls.
struct Disk {
    diskreader: ArchiveReadDisk,
    resolver: ArchiveEntryLinkresolver,
    /// Zeros, for the holes of sparse files.
    buff: Vec<u8>,
}

/// What copy_file_data_block() reads from: an archive or the disk.
trait DataBlocks: DerefMut<Target = Archive> {
    fn data_block(&mut self) -> (Status, &[u8], i64);
}

impl DataBlocks for ArchiveRead {
    fn data_block(&mut self) -> (Status, &[u8], i64) {
        ArchiveRead::data_block(self)
    }
}

impl DataBlocks for ArchiveReadDisk {
    fn data_block(&mut self) -> (Status, &[u8], i64) {
        ArchiveReadDisk::data_block(self)
    }
}

fn set_writer_options(bsdtar: &Bsdtar, a: &mut ArchiveWrite) {
    if let Some(writer_options) = std::env::var_os(ENV_WRITER_OPTIONS) {
        // Prepend magic code to ignore options for a format or filters
        // which are not added to the archive write object.
        let p = [IGNORE_WRONG_MODULE_NAME, writer_options.as_bytes()].concat();
        if a.set_options(&p) < Status::Warn {
            lafe_errc(1, 0, error_string(a));
        }
        a.clear_error();
    }
    if a.set_options(bsdtar.option_options.as_deref().unwrap_or_default()) != Status::Ok {
        lafe_errc(1, 0, error_string(a));
    }
}

fn set_reader_options(bsdtar: &Bsdtar, a: &mut ArchiveRead) {
    if let Some(reader_options) = std::env::var_os(ENV_READER_OPTIONS) {
        // Prepend magic code to ignore options for a format or filters
        // which are not added to the archive write object.
        let p = [IGNORE_WRONG_MODULE_NAME, reader_options.as_bytes()].concat();
        if a.set_options(&p) < Status::Warn {
            lafe_errc(1, 0, error_string(a));
        }
        a.clear_error();
    }
    if bsdtar.flags & OPTFLAG_IGNORE_ZEROS != 0
        && a.set_options(b"read_concatenated_archives") != Status::Ok
    {
        lafe_errc(1, 0, error_string(a));
    }
}

pub fn tar_mode_c(bsdtar: &mut Bsdtar) {
    if bsdtar.argv.is_empty() && bsdtar.names_from_file.is_none() {
        lafe_errc(1, 0, "no files or directories specified");
    }

    let mut a = ArchiveWrite::new();

    // Support any format that the library supports.
    let r = match bsdtar.cset.get_format() {
        None => {
            let r = a.set_format_pax_restricted();
            bsdtar.cset.set_format(b"pax restricted");
            r
        }
        Some(format) => a.set_format_by_name(format),
    };
    if r != Status::Ok {
        let format = bsdtar.cset.get_format().unwrap_or_default();
        let msg = [
            b"Can't use format ",
            format,
            b": ",
            &error_string(&a),
            b"\n",
        ];
        let _ = io::stderr().write_all(&msg.concat());
        usage();
    }

    a.set_bytes_per_block(bsdtar.bytes_per_block);
    a.set_bytes_in_last_block(bsdtar.bytes_in_last_block);

    if let Err(filter_name) = bsdtar.cset.write_add_filters(&mut a) {
        let msg = [b"Unsupported compression option --", filter_name];
        lafe_errc(1, 0, msg.concat());
    }

    set_writer_options(bsdtar, &mut a);
    let r = match &bsdtar.passphrase {
        Some(passphrase) => a.set_passphrase(passphrase),
        None => a.set_passphrase_callback(passphrase_callback),
    };
    if r != Status::Ok {
        lafe_errc(1, 0, error_string(&a));
    }
    if a.open_filename(bsdtar.filename.as_deref().map(path)) != Status::Ok {
        lafe_errc(1, 0, error_string(&a));
    }
    write_archive(a, bsdtar);
}

/// The archive file of -r and -u, opened with `options`.
fn open_archive(bsdtar: &Bsdtar, options: &OpenOptions) -> Rc<File> {
    let filename = bsdtar.filename.as_deref().unwrap_or_default();
    match options.open(path(filename)) {
        Ok(f) => Rc::new(f),
        Err(e) => {
            let msg = [b"Cannot open ", filename].concat();
            lafe_errc(1, e.raw_os_error().unwrap_or(0), msg)
        }
    }
}

/// Seeks to `end_offset`, where the appended entries go.
fn seek_to_end(fd: &File, end_offset: i64) {
    let r = u64::try_from(end_offset).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL));
    if let Err(e) = r.and_then(|offset| (&*fd).seek(SeekFrom::Start(offset))) {
        let errno = e.raw_os_error().unwrap_or(0);
        lafe_errc(1, errno, "Could not seek to archive end");
    }
}

/// Same as 'c', except we only support tar or empty formats in
/// uncompressed files on disk.
pub fn tar_mode_r(bsdtar: &mut Bsdtar) {
    // Sanity-test some arguments and the file.
    test_for_append(bsdtar);

    let mut format = ARCHIVE_FORMAT_TAR_PAX_RESTRICTED;

    let fd = open_archive(
        bsdtar,
        OpenOptions::new().read(true).write(true).create(true),
    );
    let filename = bsdtar.filename.clone().unwrap_or_default();

    let mut a = ArchiveRead::new();
    a.support_filter_all();
    a.support_format_empty();
    a.support_format_tar();
    a.support_format_gnutar();
    set_reader_options(bsdtar, &mut a);
    if a.open_fd(Rc::clone(&fd), 10240) != Status::Ok {
        let msg = [
            b"Can't read archive ",
            filename.as_slice(),
            b": ",
            &error_string(&a),
        ];
        lafe_errc(1, a.errno(), msg.concat());
    }
    if a.filter_code(0) != ARCHIVE_FILTER_NONE {
        lafe_errc(1, 0, "Cannot append to compressed archive");
    }
    while a.next_header() == Status::Ok {
        // Keep going until we hit end-of-archive
        format = a.format();
    }

    let end_offset = a.header_position();
    drop(a);

    // Re-open archive for writing
    let mut a = ArchiveWrite::new();
    // Set the format to be used for writing. To allow people to extend
    // empty files, we need to allow them to specify the format, which opens
    // the possibility that they will specify a format that doesn't match
    // the existing format. Hence, the following bit of arcane ugliness.
    if let Some(cset_format) = bsdtar.cset.get_format() {
        // If the user requested a format, use that, but ...
        a.set_format_by_name(cset_format);
        // ... complain if it's not compatible.
        format &= ARCHIVE_FORMAT_BASE_MASK;
        if format != a.format() & ARCHIVE_FORMAT_BASE_MASK && format != ARCHIVE_FORMAT_EMPTY {
            let msg = [
                b"Format ".as_slice(),
                cset_format,
                b" is incompatible with the archive ",
                &filename,
            ];
            lafe_errc(1, 0, msg.concat());
        }
    } else {
        // Just preserve the current format, with a little care for formats
        // that libarchive can't write.
        if format == ARCHIVE_FORMAT_EMPTY {
            format = ARCHIVE_FORMAT_TAR_PAX_RESTRICTED;
        }
        a.set_format(format);
    }
    seek_to_end(&fd, end_offset);
    set_writer_options(bsdtar, &mut a);
    if a.open_fd(Rc::clone(&fd)) != Status::Ok {
        lafe_errc(1, 0, error_string(&a));
    }

    write_archive(a, bsdtar); // XXX check return val XXX
}

pub fn tar_mode_u(bsdtar: &mut Bsdtar) {
    let mut format = ARCHIVE_FORMAT_TAR_PAX_RESTRICTED;

    // Sanity-test some arguments and the file.
    test_for_append(bsdtar);

    let fd = open_archive(bsdtar, OpenOptions::new().read(true).write(true));
    let filename = bsdtar.filename.clone().unwrap_or_default();

    let mut a = ArchiveRead::new();
    a.support_filter_all();
    a.support_format_tar();
    a.support_format_gnutar();
    set_reader_options(bsdtar, &mut a);
    if a.open_fd(Rc::clone(&fd), bsdtar.bytes_per_block as usize) != Status::Ok {
        let msg = [
            b"Can't open ",
            filename.as_slice(),
            b": ",
            &error_string(&a),
        ];
        lafe_errc(1, 0, msg.concat());
    }

    // Build a list of all entries and their recorded mod times.
    while a.next_header() == Status::Ok {
        if a.filter_code(0) != ARCHIVE_FILTER_NONE {
            lafe_errc(1, 0, "Cannot append to compressed archive");
        }
        let flag = ARCHIVE_MATCH_MTIME | ARCHIVE_MATCH_OLDER | ARCHIVE_MATCH_EQUAL;
        if bsdtar.matching.exclude_entry(flag, a.entry()) != Status::Ok {
            lafe_errc(1, 0, error_string(&bsdtar.matching));
        }
        // Record the last format determination we see
        format = a.format();
        // Keep going until we hit end-of-archive
    }

    let end_offset = a.header_position();
    drop(a);

    // Re-open archive for writing.
    let mut a = ArchiveWrite::new();
    // Set format to same one auto-detected above.
    a.set_format(format);
    a.set_bytes_per_block(bsdtar.bytes_per_block);
    a.set_bytes_in_last_block(bsdtar.bytes_in_last_block);

    seek_to_end(&fd, end_offset);
    set_writer_options(bsdtar, &mut a);
    if a.open_fd(Rc::clone(&fd)) != Status::Ok {
        lafe_errc(1, 0, error_string(&a));
    }

    write_archive(a, bsdtar);
}

/// Write user-specified files/dirs to opened archive.
fn write_archive(mut a: ArchiveWrite, bsdtar: &mut Bsdtar) {
    // Choose a suitable copy buffer size
    let mut buff_size = 64 * 1024;
    while buff_size < bsdtar.bytes_per_block as usize {
        buff_size *= 2;
    }
    // Try to compensate for space we'll lose to alignment.
    buff_size += 16 * 1024;

    let mut resolver = ArchiveEntryLinkresolver::new();
    resolver.set_strategy(a.format());

    // Create a read_disk object.
    let mut diskreader = ArchiveReadDisk::new();
    // Tell the read_disk how handle symlink.
    match bsdtar.symlink_mode {
        b'H' => diskreader.set_symlink_hybrid(),
        b'L' => diskreader.set_symlink_logical(),
        _ => diskreader.set_symlink_physical(),
    };
    // Register entry filters.
    let flags = bsdtar.flags;
    let matching = std::mem::take(&mut bsdtar.matching);
    let excluded = move |d: &ReadDiskView<'_>, e: &mut ArchiveEntry| excluded_callback(flags, d, e);
    diskreader.set_matching(Some(matching), Some(Box::new(excluded)));
    let filter = move |d: &ReadDiskView<'_>, e: &mut ArchiveEntry| metadata_filter(flags, d, e);
    diskreader.set_metadata_filter_callback(Some(Box::new(filter)));
    // Set the behavior of archive_read_disk.
    diskreader.set_behavior(bsdtar.readdisk_flags);
    diskreader.set_standard_lookup();
    let mut disk = Disk {
        diskreader,
        resolver,
        buff: vec![0; buff_size],
    };

    'cleanup: {
        if bsdtar.names_from_file.is_some() {
            archive_names_from_file(bsdtar, &mut a, &mut disk);
        }

        while let Some(arg) = bsdtar.argv.pop_front() {
            if let Some(dir) = arg.strip_prefix(b"-C") {
                let dir = if dir.is_empty() {
                    match bsdtar.argv.pop_front() {
                        None => {
                            lafe_warnc(0, "Missing argument for -C");
                            bsdtar.return_value = 1;
                            break 'cleanup;
                        }
                        Some(dir) if dir.is_empty() => {
                            lafe_warnc(0, "Meaningless argument for -C: ''");
                            bsdtar.return_value = 1;
                            break 'cleanup;
                        }
                        Some(dir) => dir,
                    }
                } else {
                    dir.to_vec()
                };
                set_chdir(bsdtar, &dir);
            } else {
                if arg.first() != Some(&b'/') {
                    do_chdir(bsdtar); // Handle a deferred -C
                }
                if let Some(name) = arg.strip_prefix(b"@") {
                    if append_archive_filename(bsdtar, &mut a, &mut disk, name) != Status::Ok {
                        break;
                    }
                } else {
                    write_hierarchy(bsdtar, &mut a, &mut disk, &arg);
                }
            }
        }

        disk.diskreader.set_matching(None, None);
        disk.diskreader.set_metadata_filter_callback(None);
        let mut entry = None;
        disk.resolver.linkify(&mut entry);
        while let Some(mut e) = entry.take() {
            // This tricky code here is to correctly read the contents of
            // the entry because the disk reader bsdtar->diskreader is
            // pointing at does not have any information about the entry by
            // this time and using archive_read_data_block() with the disk
            // reader consequently must fail. And we have to re-open the
            // entry to read the contents.
            // TODO: Work with -C option as well.
            let sourcepath = e.sourcepath().unwrap_or_default().to_vec();
            let disk_r = &mut disk.diskreader;
            if disk_r.open(path(&sourcepath)) != Status::Ok {
                lafe_warnc(disk_r.errno(), error_string(disk_r));
                bsdtar.return_value = 1;
            } else {
                // Invoke archive_read_next_header2() to work
                // archive_read_data_block(), which is called via
                // write_file(), without failure.
                let r = disk_r.next_header2(&mut ArchiveEntry::new());
                if r != Status::Ok {
                    lafe_warnc(disk_r.errno(), error_string(disk_r));
                    if r == Status::Fatal {
                        bsdtar.return_value = 1;
                    }
                } else {
                    write_entry(bsdtar, &mut a, &mut disk, &mut e);
                }
                disk.diskreader.close();
            }
            disk.resolver.linkify(&mut entry);
        }

        if a.close() != Status::Ok {
            lafe_warnc(0, error_string(&a));
            bsdtar.return_value = 1;
        }
    }

    drop(disk);

    if bsdtar.flags & OPTFLAG_TOTALS != 0 {
        let msg = format!("Total bytes written: {}\n", a.filter_bytes(-1));
        let _ = io::stderr().write_all(msg.as_bytes());
    }
}

/// Archive names specified in file.
///
/// Unless --null was specified, a line containing exactly "-C" will cause
/// the next line to be a directory to pass to chdir(). If --null is
/// specified, then a line "-C" is just another filename.
fn archive_names_from_file(bsdtar: &mut Bsdtar, a: &mut ArchiveWrite, disk: &mut Disk) {
    let mut next_line_is_dir = false;

    let null = bsdtar.flags & OPTFLAG_NULL != 0;
    let names_from_file = bsdtar.names_from_file.clone().unwrap_or_default();
    let mut lr = LineReader::new(path(&names_from_file), null);
    while let Some(line) = lr.next() {
        if next_line_is_dir {
            if !line.is_empty() {
                set_chdir(bsdtar, line);
            } else {
                lafe_warnc(0, "Meaningless argument for -C: ''");
                bsdtar.return_value = 1;
            }
            next_line_is_dir = false;
        } else if !null && line == b"-C" {
            next_line_is_dir = true;
        } else {
            if line.first() != Some(&b'/') {
                do_chdir(bsdtar); // Handle a deferred -C
            }
            write_hierarchy(bsdtar, a, disk, line);
        }
    }
    if next_line_is_dir {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        lafe_errc(
            1,
            errno,
            "Unexpected end of filename list; directory expected after -C",
        );
    }
}

/// Copy from specified archive to current archive. Returns non-Ok for
/// write errors (which force us to terminate the entire archiving
/// operation). If there are errors reading the input archive, we set
/// bsdtar->return_value but return Ok, so the overall archiving operation
/// will complete and return non-zero.
fn append_archive_filename(
    bsdtar: &mut Bsdtar,
    a: &mut ArchiveWrite,
    disk: &mut Disk,
    raw_filename: &[u8],
) -> Status {
    // Library uses NULL for stdio.
    let filename = (raw_filename != b"-").then(|| path(raw_filename));

    let mut ina = ArchiveRead::new();
    ina.support_format_all();
    ina.support_filter_all();
    set_reader_options(bsdtar, &mut ina);
    ina.set_options(b"mtree:checkfs");
    let r = match &bsdtar.passphrase {
        Some(passphrase) => ina.add_passphrase(passphrase),
        None => ina.set_passphrase_callback(passphrase_callback),
    };
    if r != Status::Ok {
        lafe_errc(1, 0, error_string(&ina));
    }
    if ina.open_filename(filename, bsdtar.bytes_per_block as usize) != Status::Ok {
        lafe_warnc(0, error_string(&ina));
        bsdtar.return_value = 1;
        return Status::Ok;
    }

    let rc = append_archive(bsdtar, a, disk, &mut ina);

    if rc != Status::Ok {
        let msg = [
            b"Error reading archive ",
            raw_filename,
            b": ",
            &error_string(&ina),
        ];
        lafe_warnc(0, msg.concat());
        bsdtar.return_value = 1;
    }
    rc
}

/// Apply --uid, --gid, --uname and --gname options.
fn edit_owner(bsdtar: &Bsdtar, diskreader: &mut ArchiveReadDisk, entry: &mut ArchiveEntry) {
    if bsdtar.uid >= 0 {
        entry.set_uid(i64::from(bsdtar.uid));
        if bsdtar.uname.is_none() {
            entry.set_uname(diskreader.uname(i64::from(bsdtar.uid)));
        }
    }
    if bsdtar.gid >= 0 {
        entry.set_gid(i64::from(bsdtar.gid));
        if bsdtar.gname.is_none() {
            entry.set_gname(diskreader.gname(i64::from(bsdtar.gid)));
        }
    }
    if let Some(uname) = &bsdtar.uname {
        entry.set_uname(Some(uname));
    }
    if let Some(gname) = &bsdtar.gname {
        entry.set_gname(Some(gname));
    }
}

fn append_archive(
    bsdtar: &mut Bsdtar,
    a: &mut ArchiveWrite,
    disk: &mut Disk,
    ina: &mut ArchiveRead,
) -> Status {
    let mut in_entry = ArchiveEntry::new2(ina);
    let mut stderr = io::stderr();
    let e = loop {
        let e = ina.next_header2(&mut in_entry);
        if e != Status::Ok {
            break e;
        }
        let matching = disk.diskreader.matching();
        match matching.map_or(Ok(false), |m| m.excluded(&mut in_entry)) {
            Err(_) => {
                let matching = disk.diskreader.matching();
                let msg = matching.map(|m| error_string(m)).unwrap_or_default();
                if bsdtar.verbose == 0 {
                    lafe_errc(1, 0, msg);
                } else {
                    let _ = stderr.write_all(&[b": ".as_slice(), &msg].concat());
                    exit(1);
                }
            }
            Ok(true) => continue,
            Ok(false) => {}
        }
        if edit_pathname(bsdtar, &mut in_entry) != 0 {
            continue;
        }
        if bsdtar.flags & OPTFLAG_INTERACTIVE != 0 {
            let name = in_entry.pathname().unwrap_or_default();
            if !yes(&[b"copy '", name, b"'"].concat()) {
                continue;
            }
        }
        edit_owner(bsdtar, &mut disk.diskreader, &mut in_entry);
        edit_mtime(bsdtar, &mut in_entry);
        if bsdtar.verbose > 1 {
            let _ = stderr.write_all(b"a ");
            list_item_verbose(bsdtar, &mut stderr, &mut in_entry);
        } else if bsdtar.verbose > 0 {
            let _ = stderr.write_all(b"a ");
            safe_fputs(in_entry.pathname(), &mut stderr);
        }
        if need_report() {
            report_write(bsdtar, a, &mut in_entry, 0);
        }

        let e = a.header(&mut in_entry);
        if e != Status::Ok {
            if bsdtar.verbose == 0 {
                let name = in_entry.pathname().unwrap_or(b"(null)");
                lafe_warnc(0, [name, b": ", &error_string(a)].concat());
            } else {
                let _ = stderr.write_all(&[b": ".as_slice(), &error_string(a)].concat());
            }
        }
        if e == Status::Fatal {
            exit(1);
        }

        if e >= Status::Warn {
            if in_entry.size() == 0 {
                ina.data_skip();
            } else if copy_file_data_block(bsdtar, a, ina, &mut in_entry, &disk.buff) != 0 {
                exit(1);
            }
        }

        if bsdtar.verbose != 0 {
            let _ = stderr.write_all(b"\n");
        }
    };

    if e == Status::Eof { Status::Ok } else { e }
}

/// Helper function to copy file to archive.
fn copy_file_data_block(
    bsdtar: &Bsdtar,
    a: &mut ArchiveWrite,
    in_a: &mut impl DataBlocks,
    entry: &mut ArchiveEntry,
    null_buff: &[u8],
) -> i32 {
    let mut progress: i64 = 0;
    let truncated = |entry: &mut ArchiveEntry| {
        let name = entry.pathname().unwrap_or(b"(null)");
        let msg = b": Truncated write; file may have grown while being archived";
        lafe_warnc(0, [name, msg].concat());
    };

    let r = loop {
        let (r, buff, offset) = in_a.data_block();
        if r != Status::Ok {
            break r;
        }
        if need_report() {
            report_write(bsdtar, a, entry, progress);
        }

        if offset > progress {
            let mut sparse = offset - progress;
            while sparse > 0 {
                let ns = sparse.min(null_buff.len() as i64) as usize;
                match a.data(&null_buff[..ns]) {
                    // Write failed; this is bad
                    Err(_) => {
                        lafe_warnc(0, error_string(a));
                        return -1;
                    }
                    // Write was truncated; warn but continue.
                    Ok(n) if n < ns => {
                        truncated(entry);
                        return 0;
                    }
                    Ok(n) => {
                        progress += n as i64;
                        sparse -= n as i64;
                    }
                }
            }
        }

        match a.data(buff) {
            // Write failed; this is bad
            Err(_) => {
                lafe_warnc(0, error_string(a));
                return -1;
            }
            // Write was truncated; warn but continue.
            Ok(n) if n < buff.len() => {
                truncated(entry);
                return 0;
            }
            Ok(n) => progress += n as i64,
        }
    };
    if r < Status::Warn {
        lafe_warnc(in_a.errno(), error_string(in_a));
        return -1;
    }
    0
}

fn excluded_callback(flags: u32, d: &ReadDiskView<'_>, entry: &mut ArchiveEntry) {
    if flags & OPTFLAG_NO_SUBDIRS != 0 {
        return;
    }
    if !d.can_descend() {
        return;
    }
    if flags & OPTFLAG_INTERACTIVE != 0 {
        let name = entry.pathname().unwrap_or_default();
        if !yes(&[b"add '", name, b"'"].concat()) {
            return;
        }
    }
    d.descend();
}

fn metadata_filter(flags: u32, d: &ReadDiskView<'_>, entry: &mut ArchiveEntry) -> bool {
    // XXX TODO: check whether this filesystem is synthetic and/or local.
    // Add a new --local-only option to skip non-local filesystems. Skip
    // synthetic filesystems regardless.
    //
    // The results should be cached, since tree.c doesn't usually visit a
    // directory and the directory contents together. A simple
    // move-to-front list should perform quite well.
    //
    // Use archive_read_disk_current_filesystem_is_remote().

    // If the user vetoes this file/directory, skip it. We want this to be
    // fairly late; if some other check would veto this file, we shouldn't
    // bother the user with it.
    if flags & OPTFLAG_INTERACTIVE != 0 {
        let name = entry.pathname().unwrap_or_default();
        if !yes(&[b"add '", name, b"'"].concat()) {
            return false;
        }
    }

    // Note: if user vetoes, we won't descend.
    if flags & OPTFLAG_NO_SUBDIRS == 0 && d.can_descend() {
        d.descend();
    }

    true
}

/// Add the file or dir hierarchy named by 'path' to the archive
fn write_hierarchy(bsdtar: &mut Bsdtar, a: &mut ArchiveWrite, disk: &mut Disk, name: &[u8]) {
    let mut stderr = io::stderr();
    let diskreader = &mut disk.diskreader;
    if diskreader.open(path(name)) != Status::Ok {
        lafe_warnc(diskreader.errno(), error_string(diskreader));
        bsdtar.return_value = 1;
        return;
    }

    loop {
        let mut entry = ArchiveEntry::new();
        let r = disk.diskreader.next_header2(&mut entry);
        if r == Status::Eof {
            break;
        } else if r != Status::Ok {
            let diskreader = &disk.diskreader;
            lafe_warnc(diskreader.errno(), error_string(diskreader));
            if r == Status::Fatal || r == Status::Failed {
                bsdtar.return_value = 1;
                disk.diskreader.close();
                return;
            } else if r < Status::Warn {
                continue;
            }
        }

        edit_owner(bsdtar, &mut disk.diskreader, &mut entry);

        if let Some(file_mode) = &bsdtar.file_mode {
            entry.set_mode(lafe_getmode(file_mode, entry.mode()));
        }

        // Rewrite the pathname to be archived. If rewrite fails, skip the
        // entry.
        if edit_pathname(bsdtar, &mut entry) != 0 {
            continue;
        }

        // Rewrite the mtime.
        edit_mtime(bsdtar, &mut entry);

        // Display entry as we process it.
        if bsdtar.verbose > 1 {
            let _ = stderr.write_all(b"a ");
            list_item_verbose(bsdtar, &mut stderr, &mut entry);
        } else if bsdtar.verbose > 0 {
            // This format is required by SUSv2.
            let _ = stderr.write_all(b"a ");
            safe_fputs(entry.pathname(), &mut stderr);
        }

        // Non-regular files get archived with zero size.
        if entry.filetype() != AE_IFREG {
            entry.set_size(0);
        }

        let mut entry = Some(entry);
        let spare_entry = disk.resolver.linkify(&mut entry);
        for mut entry in [entry, spare_entry].into_iter().flatten() {
            write_entry(bsdtar, a, disk, &mut entry);
        }

        if bsdtar.verbose != 0 {
            let _ = stderr.write_all(b"\n");
        }
    }
    disk.diskreader.close();
}

/// Write a single entry to the archive.
fn write_entry(
    bsdtar: &mut Bsdtar,
    a: &mut ArchiveWrite,
    disk: &mut Disk,
    entry: &mut ArchiveEntry,
) {
    let e = a.header(entry);
    if e != Status::Ok {
        if bsdtar.verbose > 1 {
            let mut stderr = io::stderr();
            let _ = stderr.write_all(b"a ");
            list_item_verbose(bsdtar, &mut stderr, entry);
            lafe_warnc(0, [b": ".as_slice(), &error_string(a)].concat());
        } else {
            let name = entry.pathname().unwrap_or(b"(null)");
            lafe_warnc(0, [name, b": ", &error_string(a)].concat());
        }
    }

    if e == Status::Fatal {
        exit(1);
    }

    // If we opened a file earlier, write it out now. Note that the format
    // handler might have reset the size field to zero to inform us that the
    // archive body won't get stored. In that case, just skip the write.
    if e >= Status::Warn
        && entry.size() > 0
        && copy_file_data_block(bsdtar, a, &mut disk.diskreader, entry, &disk.buff) != 0
    {
        exit(1);
    }
}

fn report_write(bsdtar: &Bsdtar, a: &ArchiveWrite, entry: &mut ArchiveEntry, progress: i64) {
    let mut stderr = io::stderr();
    if bsdtar.verbose != 0 {
        let _ = stderr.write_all(b"\n");
    }
    let comp = a.filter_bytes(-1) as u64;
    let uncomp = a.filter_bytes(0) as u64;
    let _ = write!(stderr, "In: {} files, {uncomp} bytes;", a.file_count());
    let compression = if comp >= uncomp {
        0
    } else {
        ((uncomp - comp).wrapping_mul(100) / uncomp) as i32
    };
    let _ = write!(
        stderr,
        " Out: {comp} bytes, compression {compression}%\nCurrent: "
    );
    safe_fputs(entry.pathname(), &mut stderr);
    let _ = writeln!(stderr, " ({progress}/{} bytes)", entry.size());
}

fn test_for_append(bsdtar: &Bsdtar) {
    if bsdtar.argv.is_empty() && bsdtar.names_from_file.is_none() {
        lafe_errc(1, 0, "no files or directories specified");
    }
    let Some(filename) = &bsdtar.filename else {
        lafe_errc(1, 0, "Cannot append to stdout");
    };

    let Ok(s) = std::fs::metadata(path(filename)) else {
        return;
    };

    if !s.is_file() && !s.file_type().is_block_device() {
        let msg = [
            b"Cannot append to ",
            filename.as_slice(),
            b": not a regular file",
        ];
        lafe_errc(1, 0, msg.concat());
    }
}
