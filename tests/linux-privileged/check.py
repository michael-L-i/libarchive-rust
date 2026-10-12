"""Require successful privileged operations, then compare both public C ABIs."""
import argparse
import array
import ctypes as C
import errno
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

IMMUTABLE, APPEND = 0x10, 0x20
GETFLAGS, SETFLAGS = 0x80086601, 0x40086602
PAYLOAD = b"privileged disk payload\x00\xff"


def flags(path, value=None):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        data = array.array("L", [0 if value is None else value])
        fcntl.ioctl(fd, GETFLAGS if value is None else SETFLAGS, data, True)
        return data[0]
    finally:
        os.close(fd)


def cleanup(root):
    if not root.exists():
        return
    for directory, dirs, files in os.walk(root):
        for path in [Path(directory), *(Path(directory) / n for n in dirs + files)]:
            if path.is_symlink():
                continue
            try:
                flags(path, flags(path) & ~(IMMUTABLE | APPEND))
            except OSError:
                pass
    shutil.rmtree(root)


class Library:
    def __init__(self, path):
        self.lib = C.CDLL(path)
        p, i, ul, size = C.c_void_p, C.c_int, C.c_ulong, C.c_size_t
        signatures = {
            "archive_write_disk_new": (p, []),
            "archive_read_disk_new": (p, []),
            "archive_entry_new": (p, []),
            "archive_entry_free": (None, [p]),
            "archive_entry_set_pathname": (None, [p, C.c_char_p]),
            "archive_entry_set_mode": (None, [p, C.c_uint]),
            "archive_entry_set_size": (None, [p, C.c_int64]),
            "archive_entry_set_hardlink": (None, [p, C.c_char_p]),
            "archive_entry_set_symlink": (None, [p, C.c_char_p]),
            "archive_entry_set_fflags": (None, [p, ul, ul]),
            "archive_entry_fflags": (None, [p, C.POINTER(ul), C.POINTER(ul)]),
            "archive_entry_xattr_add_entry": (None, [p, C.c_char_p, p, size]),
            "archive_entry_xattr_reset": (i, [p]),
            "archive_entry_xattr_next": (i, [p, C.POINTER(C.c_char_p), C.POINTER(p), C.POINTER(size)]),
            "archive_write_disk_set_options": (i, [p, i]),
            "archive_write_header": (i, [p, p]),
            "archive_write_data": (C.c_ssize_t, [p, p, size]),
            "archive_write_finish_entry": (i, [p]),
            "archive_write_close": (i, [p]),
            "archive_write_free": (i, [p]),
            "archive_read_disk_entry_from_file": (i, [p, p, i, p]),
            "archive_read_free": (i, [p]),
            "archive_errno": (i, [p]),
            "archive_error_string": (C.c_char_p, [p]),
        }
        for name, (result, args) in signatures.items():
            fn = getattr(self.lib, name)
            fn.restype, fn.argtypes = result, args

    def status(self, handle, code):
        message = self.lib.archive_error_string(handle)
        return [code, self.lib.archive_errno(handle), message.decode().replace(self.root, "<root>") if message else None]

    def write(self, path, options, flag=0, xattrs=False, directory=False, hardlink=None, symlink=None):
        a, e = self.lib.archive_write_disk_new(), self.lib.archive_entry_new()
        result = {}
        try:
            self.lib.archive_entry_set_pathname(e, os.fsencode(path))
            mode = (0o040000 | 0o755) if directory else (0o100000 | 0o644)
            self.lib.archive_entry_set_mode(e, (0o120000 | 0o777) if symlink else mode)
            has_data = not (directory or hardlink or symlink)
            self.lib.archive_entry_set_size(e, len(PAYLOAD) if has_data else 0)
            if hardlink:
                self.lib.archive_entry_set_hardlink(e, os.fsencode(hardlink))
            if symlink:
                self.lib.archive_entry_set_symlink(e, os.fsencode(symlink))
            self.lib.archive_entry_set_fflags(e, flag, 0)
            if xattrs:
                for name, value in [(b"trusted.libarchive-test", b"trusted\x00\xff"), (b"user.libarchive-test", b"user\x00\xff")]:
                    self.lib.archive_entry_xattr_add_entry(e, name, value, len(value))
            assert self.lib.archive_write_disk_set_options(a, options) == 0
            header = self.lib.archive_write_header(a, e)
            result["header"] = self.status(a, header)
            if header >= -20:
                if has_data:
                    result["data"] = self.lib.archive_write_data(a, PAYLOAD, len(PAYLOAD))
                result["finish"] = self.status(a, self.lib.archive_write_finish_entry(a))
                result["before_close_flags"] = None if path.is_symlink() else flags(path) & (IMMUTABLE | APPEND)
                if directory:
                    (path / "child").write_bytes(PAYLOAD)
            result["close"] = self.status(a, self.lib.archive_write_close(a))
            result["flags"] = flags(path) & (IMMUTABLE | APPEND) if path.exists() and not path.is_symlink() else None
            result["content"] = path.read_bytes().hex() if path.is_file() else None
            result["xattrs"] = {name: os.getxattr(path, name, follow_symlinks=False).hex() for name in os.listxattr(path, follow_symlinks=False)} if path.exists() else {}
            if directory:
                result["child_content"] = (path / "child").read_bytes().hex()
            return result
        finally:
            self.lib.archive_entry_free(e)
            self.lib.archive_write_free(a)

    def read(self, path):
        a, e = self.lib.archive_read_disk_new(), self.lib.archive_entry_new()
        try:
            self.lib.archive_entry_set_pathname(e, os.fsencode(path))
            result = {"status": self.status(a, self.lib.archive_read_disk_entry_from_file(a, e, -1, None))}
            setbits, clearbits = C.c_ulong(), C.c_ulong()
            self.lib.archive_entry_fflags(e, C.byref(setbits), C.byref(clearbits))
            result["flags"] = setbits.value & (IMMUTABLE | APPEND)
            attrs = {}
            self.lib.archive_entry_xattr_reset(e)
            name, value, length = C.c_char_p(), C.c_void_p(), C.c_size_t()
            while self.lib.archive_entry_xattr_next(e, C.byref(name), C.byref(value), C.byref(length)) == 0:
                attrs[name.value.decode()] = C.string_at(value, length.value).hex()
            result["xattrs"] = attrs
            return result
        finally:
            self.lib.archive_entry_free(e)
            self.lib.archive_read_free(a)


def worker(args):
    lib, root = Library(args.library), Path(args.root)
    lib.root = str(root)
    results = {}
    for name, bit in [("immutable", IMMUTABLE), ("append", APPEND)]:
        results[name + "_restore"] = lib.write(root / (name + "-new"), 0x40, bit)
        results[name + "_dir_restore"] = lib.write(root / (name + "-dir"), 0x40, bit, directory=True)
        results[name + "_read"] = lib.read(root / (name + "-blocked"))
        results[name + "_blocked"] = lib.write(root / (name + "-blocked"), 0)
        results[name + "_clear"] = lib.write(root / (name + "-clear"), 0x20000)
        if os.getuid() == 0:
            try:
                fd = os.open(root / (name + "-new"), os.O_WRONLY | os.O_TRUNC)
                os.close(fd)
                results[name + "_truncate_errno"] = 0
            except OSError as error:
                results[name + "_truncate_errno"] = error.errno
            try:
                (root / (name + "-dir/child")).unlink()
                results[name + "_unlink_child_errno"] = 0
            except OSError as error:
                results[name + "_unlink_child_errno"] = error.errno
    if os.getuid() == 0:
        fd = os.open(root / "append-new", os.O_WRONLY | os.O_APPEND)
        try:
            assert os.write(fd, b"tail") == 4
        finally:
            os.close(fd)
        results["append_after_restore"] = (root / "append-new").read_bytes().hex()
    results["xattr_restore"] = lib.write(root / "attrs-new", 0x80, xattrs=True)
    results["xattr_read"] = lib.read(root / "attrs-read")
    results["mode000_read"] = lib.read(root / "mode000")
    outside = root / "outside"
    def snapshot(path):
        return {"content": path.read_bytes().hex(), "flags": flags(path) & (IMMUTABLE | APPEND), "xattrs": {name: os.getxattr(path, name).hex() for name in os.listxattr(path)}}
    before = snapshot(outside)
    results["hardlink_restore"] = lib.write(root / "hardlink-new", 0xc0, IMMUTABLE, xattrs=True, hardlink=outside)
    results["hardlink_same_inode"] = (root / "hardlink-new").stat().st_ino == outside.stat().st_ino
    results["hardlink_read"] = lib.read(root / "hardlink-new")
    results["symlink_restore"] = lib.write(root / "symlink-new", 0xc0, IMMUTABLE, xattrs=True, symlink=outside)
    results["symlink_read"] = lib.read(root / "symlink-new")
    results["secure_target"] = lib.write(root / "extract/destination", 0x1c0, IMMUTABLE, xattrs=True)
    results["secure_parent"] = lib.write(root / "extract/parent/new", 0x1c0, IMMUTABLE, xattrs=True)
    results["secure_hardlink"] = lib.write(root / "extract/hardlink", 0x1c0, IMMUTABLE, xattrs=True, hardlink=root / "source-symlink")
    results["outside_unchanged"] = before == snapshot(outside) and not (root / "outside-dir/new").exists()
    try:
        os.setxattr(root / "attrs-new", "trusted.direct", b"probe")
        results["direct_trusted_errno"] = 0
    except OSError as error:
        results["direct_trusted_errno"] = error.errno
    results["uid"] = os.getuid()
    results["cap_eff"] = next(line.split()[1] for line in Path("/proc/self/status").read_text().splitlines() if line.startswith("CapEff:"))
    print(json.dumps(results, sort_keys=True))


def check_expected(results, privileged):
    for name, bit in [("immutable", IMMUTABLE), ("append", APPEND)]:
        for kind in ["_restore", "_dir_restore"]:
            item = results[name + kind]
            assert item["header"][0] == item["finish"][0] == 0, (name, item)
            assert item["before_close_flags"] == 0, (name, item)
            assert item["flags"] == (bit if privileged else 0), (name, item)
            assert item["close"][0] == 0, (name, item)
            if kind == "_dir_restore":
                assert item["child_content"] == PAYLOAD.hex(), item
        assert results[name + "_restore"]["content"] == PAYLOAD.hex()
        assert results[name + "_read"]["flags"] == bit
        blocked = results[name + "_blocked"]
        assert blocked["header"][0] < 0 and blocked["content"] == b"original".hex(), blocked
        cleared = results[name + "_clear"]
        if privileged:
            assert cleared["header"][0] == cleared["finish"][0] == cleared["close"][0] == 0, cleared
            assert cleared["flags"] == 0 and cleared["content"] == PAYLOAD.hex(), cleared
        else:
            assert cleared["header"][0] < 0 and cleared["content"] == b"original".hex(), cleared
        if privileged:
            assert results[name + "_truncate_errno"] == errno.EPERM
            assert results[name + "_unlink_child_errno"] == errno.EPERM
    attrs = results["xattr_restore"]
    assert attrs["content"] == PAYLOAD.hex() and attrs["xattrs"]["user.libarchive-test"] == b"user\x00\xff".hex(), attrs
    assert attrs["finish"][0] == (0 if privileged else -20), attrs
    assert ("trusted.libarchive-test" in attrs["xattrs"]) == privileged, attrs
    assert ("trusted.libarchive-test" in results["xattr_read"]["xattrs"]) == privileged
    assert results["direct_trusted_errno"] == (0 if privileged else errno.EPERM)
    required = (1 << 9) | (1 << 21)  # CAP_LINUX_IMMUTABLE and CAP_SYS_ADMIN
    assert int(results["cap_eff"], 16) & required == (required if privileged else 0)
    if not privileged:
        assert int(results["cap_eff"], 16) == 0
    else:
        assert results["append_after_restore"] == (PAYLOAD + b"tail").hex()
    assert results["outside_unchanged"] and results["hardlink_same_inode"]
    assert results["hardlink_restore"]["flags"] == 0
    assert results["symlink_read"]["flags"] == 0
    assert results["secure_target"]["content"] == PAYLOAD.hex()
    assert results["secure_parent"]["header"][0] < 0
    if privileged:
        assert results["mode000_read"]["status"][0] == 0
        assert results["mode000_read"]["xattrs"]["trusted.libarchive-test"] == b"trusted\x00\xff".hex()


def main(args):
    root = Path(args.root)
    report = {"pin": "8bb3bbdc7b117a1e22086a2260f2087aafa90687", "filesystem": subprocess.check_output(["stat", "-f", "-c", "%T", str(root)], text=True).strip(), "results": {}}
    root.chmod(0o755)
    try:
        for uid in [0, 65534]:
            pairs = {}
            for label, library in [("oracle", args.oracle), ("port", args.port)]:
                case = root / f"{label}-{uid}"
                case.mkdir()
                os.chown(case, uid, uid)
                for name, bit in [("immutable", IMMUTABLE), ("append", APPEND)]:
                    for suffix in ["blocked", "clear"]:
                        path = case / f"{name}-{suffix}"
                        path.write_bytes(b"original")
                        os.chown(path, uid, uid)
                        flags(path, flags(path) | bit)
                        assert flags(path) & bit
                path = case / "attrs-read"
                path.write_bytes(PAYLOAD)
                os.chown(path, uid, uid)
                os.setxattr(path, "trusted.libarchive-test", b"trusted\x00\xff")
                os.setxattr(path, "user.libarchive-test", b"user\x00\xff")
                mode000 = case / "mode000"
                mode000.write_bytes(PAYLOAD)
                os.chown(mode000, uid, uid)
                os.setxattr(mode000, "trusted.libarchive-test", b"trusted\x00\xff")
                mode000.chmod(0)
                outside = case / "outside"
                outside.write_bytes(b"outside sentinel")
                os.chown(outside, uid, uid)
                os.setxattr(outside, "trusted.sentinel", b"untouched")
                os.setxattr(outside, "user.sentinel", b"untouched")
                for directory in [case / "extract", case / "outside-dir"]:
                    directory.mkdir()
                    os.chown(directory, uid, uid)
                (case / "extract/destination").symlink_to(outside)
                (case / "extract/parent").symlink_to(case / "outside-dir")
                (case / "source-symlink").symlink_to(outside)
                command = [sys.executable, __file__, "--worker", "--library", library, "--root", str(case)]
                if uid:
                    command = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", *command]
                pairs[label] = json.loads(subprocess.check_output(command, text=True))
                report["results"][str(uid)] = pairs
                check_expected(pairs[label], uid == 0)
            assert pairs["oracle"] == pairs["port"], json.dumps(pairs, indent=2, sort_keys=True)
            report["results"][str(uid)] = pairs
        print("PASS: privileged and unprivileged flag, xattr, mode-000 and secure link comparisons; successful immutable, append and trusted.* operations required")
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        Path(args.output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        cleanup(root)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--cleanup", type=Path)
    for argument in ["oracle", "port", "library", "root", "output"]:
        parser.add_argument("--" + argument)
    args = parser.parse_args()
    if args.cleanup:
        cleanup(args.cleanup)
    elif args.worker:
        worker(args)
    else:
        main(args)
