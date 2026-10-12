/*-
 * Copyright (c) 2009-2012,2014 Michihiro NAKAJIMA
 * Copyright (c) 2003-2007 Tim Kientzle
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
// Ported from libarchive/archive_util.c.

use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// Upstream's __archive_issetugid: errors also prevent trusting TMPDIR.
fn issetugid() -> libc::c_int {
    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "haiku"
    ))]
    {
        // SAFETY: issetugid has no arguments and only queries process state.
        unsafe { libc::issetugid() }
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let (mut ruid, mut euid, mut suid) = (0, 0, 0);
        // SAFETY: getresuid writes to three distinct, valid uid_t variables.
        if unsafe { libc::getresuid(&mut ruid, &mut euid, &mut suid) } != 0 {
            return -1;
        }
        if ruid != euid || ruid != suid {
            return 1;
        }
        let (mut rgid, mut egid, mut sgid) = (0, 0, 0);
        // SAFETY: getresgid writes to three distinct, valid gid_t variables.
        if unsafe { libc::getresgid(&mut rgid, &mut egid, &mut sgid) } != 0 {
            return -1;
        }
        i32::from(rgid != egid || rgid != sgid)
    }
    #[cfg(not(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "haiku",
        target_os = "linux",
        target_os = "android"
    )))]
    {
        // SAFETY: the identity getters have no arguments and cannot fail.
        unsafe { i32::from(libc::geteuid() != libc::getuid() || libc::getegid() != libc::getgid()) }
    }
}

/// Upstream's __archive_get_tempdir, including the slash for an empty TMPDIR.
pub(crate) fn get_tempdir() -> PathBuf {
    let mut directory = if issetugid() == 0 {
        std::env::var_os("TMPDIR")
    } else {
        None
    }
    .unwrap_or_else(|| "/tmp".into());
    if !directory.as_bytes().ends_with(b"/") {
        directory.push("/");
    }
    directory.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;

    const MODE: &str = "LIBARCHIVE_TEMP_TEST_MODE";
    const EXPECTED: &str = "LIBARCHIVE_TEMP_TEST_EXPECTED";

    fn child(tmpdir: Option<&OsStr>, expected: &OsStr, mode: &str) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--ignored",
            "--exact",
            "ffi::util::tests::tempdir_child",
            "--test-threads=1",
        ]);
        command
            .env_remove("TMPDIR")
            .env(MODE, mode)
            .env(EXPECTED, expected);
        if let Some(tmpdir) = tmpdir {
            command.env("TMPDIR", tmpdir);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }

    #[test]
    fn tempdir_selection_in_subprocesses() {
        child(None, OsStr::new("/tmp/"), "selection");
        child(Some(OsStr::new("")), OsStr::new("/"), "selection");
        for path in ["/tmp/custom", "/tmp/custom/", "relative", "relative/", "//"] {
            let expected = if path.ends_with('/') {
                path.to_owned()
            } else {
                format!("{path}/")
            };
            child(Some(OsStr::new(path)), OsStr::new(&expected), "selection");
        }
        let tmpdir = std::ffi::OsString::from_vec(b"/tmp/non-utf8-\xff".to_vec());
        let expected = std::ffi::OsString::from_vec(b"/tmp/non-utf8-\xff/".to_vec());
        child(Some(&tmpdir), &expected, "selection");
    }

    #[test]
    fn spool_honors_tmpdir_and_unlinks_the_file() {
        let directory =
            std::env::temp_dir().join(format!("libarchive-tempdir-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let mut expected = directory.as_os_str().to_owned();
        expected.push("/");
        child(Some(directory.as_os_str()), &expected, "spool");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        std::fs::remove_dir(&directory).unwrap();
        child(Some(directory.as_os_str()), &expected, "missing");
    }

    // Only the single-test child changes credentials; the parallel parent never does.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_changed_ids_ignore_tmpdir_when_run_as_root() {
        if crate::ffi::disk_sys::euid() != 0 {
            return;
        }
        for mode in [
            "real-uid",
            "effective-uid",
            "saved-uid",
            "real-gid",
            "effective-gid",
            "saved-gid",
        ] {
            child(
                Some(OsStr::new("/nonexistent-libarchive-tempdir")),
                OsStr::new("/tmp/"),
                mode,
            );
        }
    }

    #[test]
    #[ignore = "launched by the tempdir tests with an isolated environment"]
    fn tempdir_child() {
        let mode = std::env::var(MODE).unwrap();
        #[cfg(target_os = "linux")]
        match mode.as_str() {
            "real-uid" | "effective-uid" | "saved-uid" => {
                let ids = match mode.as_str() {
                    "real-uid" => (65534, 0, 0),
                    "effective-uid" => (0, 65534, 0),
                    _ => (0, 0, 65534),
                };
                // SAFETY: scalar credential arguments; this isolated child exits after the test.
                assert_eq!(unsafe { libc::setresuid(ids.0, ids.1, ids.2) }, 0);
            }
            "real-gid" | "effective-gid" | "saved-gid" => {
                let ids = match mode.as_str() {
                    "real-gid" => (65534, 0, 0),
                    "effective-gid" => (0, 65534, 0),
                    _ => (0, 0, 65534),
                };
                // SAFETY: scalar credential arguments; this isolated child exits after the test.
                assert_eq!(unsafe { libc::setresgid(ids.0, ids.1, ids.2) }, 0);
            }
            _ => {}
        }
        assert_eq!(
            get_tempdir().as_os_str(),
            std::env::var_os(EXPECTED).unwrap()
        );
        if mode == "selection" {
            return;
        }
        if mode == "missing" {
            assert_eq!(crate::write::temp_file().unwrap_err().errno, libc::ENOENT);
            return;
        }
        let mut file = crate::write::temp_file().unwrap();
        assert_eq!(file.metadata().unwrap().nlink(), 0);
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
        file.write_all(b"seekable spool").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"seekable spool");
    }
}
