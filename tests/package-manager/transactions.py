#!/usr/bin/env python3
"""Compare Debian pacman/libalpm transactions in disposable container roots."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import tarfile
import tempfile
import time


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def package(directory, version, *, name="archive-adoption", collision=False):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        def add(path, content=None, mode=0o644, uid=0, gid=0, kind=None, link="", xattrs=None):
            item = tarfile.TarInfo(path)
            item.mode, item.uid, item.gid, item.mtime = mode, uid, gid, 1700000000
            if kind is not None:
                item.type, item.linkname = kind, link
            if xattrs:
                item.pax_headers = {"SCHILY.xattr." + key: value for key, value in xattrs.items()}
            if content is not None:
                item.size = len(content)
            archive.addfile(item, io.BytesIO(content) if content is not None else None)

        info = (f"pkgname = {name}\npkgver = {version}\npkgdesc = archive fixture\n"
                "url = https://example.invalid/\nbuilddate = 1700000000\n"
                "packager = archive tests\nsize = 8192\narch = any\n"
                "license = BSD\nbackup = etc/adoption.conf\n")
        add(".PKGINFO", info.encode())
        for path in ("usr/", "usr/share/", "usr/share/adoption/", "etc/"):
            add(path, mode=0o755, kind=tarfile.DIRTYPE)
        add("usr/share/adoption/data", f"payload {version}\n".encode())
        if not collision:
            add("usr/share/adoption/hard", kind=tarfile.LNKTYPE,
                link="usr/share/adoption/data")
            add("usr/share/adoption/link", kind=tarfile.SYMTYPE, link="data")
            add("usr/share/adoption/run", b"#!/bin/sh\nexit 0\n", mode=0o755)
            add("usr/share/adoption/owner", b"numeric owner\n", mode=0o640, uid=123, gid=456)
            add("usr/share/adoption/spaced unicode \u00e9", b"\0\xff\n")
            add("etc/adoption.conf", f"configuration {version}\n".encode(), mode=0o600)
        add("usr/share/adoption/xattr", b"attribute\n", xattrs={"user.adoption": "fixture attribute"})
    output = directory / f"{name}-{version}-any.pkg.tar.zst"
    result = subprocess.run(["zstd", "-q", "-c"], input=raw.getvalue(),
                            capture_output=True, check=True)
    output.write_bytes(result.stdout)
    return output


def snapshot(root):
    result, hardlinks = {}, {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        item = path.lstat()
        record = {"mode": stat.S_IMODE(item.st_mode), "uid": item.st_uid, "gid": item.st_gid}
        if path.is_symlink():
            record.update(type="symlink", target=os.readlink(path))
        elif path.is_dir():
            record.update(type="directory")
        else:
            content = path.read_bytes()
            if relative.startswith("var/lib/pacman/local/") and path.name == "desc":
                content = re.sub(rb"%INSTALLDATE%\n\d+", b"%INSTALLDATE%\n<TIME>", content)
            record.update(type="file", sha256=hashlib.sha256(content).hexdigest())
            if item.st_nlink > 1:
                hardlinks.setdefault((item.st_dev, item.st_ino), []).append(relative)
        record["xattrs"] = {name: os.getxattr(path, name, follow_symlinks=False).hex()
                            for name in sorted(os.listxattr(path, follow_symlinks=False))}
        result[relative] = record
    return {"files": result, "hardlinks": sorted(sorted(group) for group in hardlinks.values())}


class Transactions:
    def __init__(self, directory, library_dir, report):
        self.directory, self.report = directory, report
        self.roots, self.environments, self.commands = {}, {}, []
        for implementation in ("c", "rust"):
            root = directory / implementation
            for relative in ("var/lib/pacman", "var/cache/pacman/pkg", "hooks"):
                (root / relative).mkdir(parents=True)
            config = root / "pacman.conf"
            config.write_text("[options]\nArchitecture = auto\nSigLevel = Never\n")
            self.roots[implementation] = root
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith("LD_")}
            environment.update(LC_ALL="C.UTF-8", LD_BIND_NOW="1")
            if implementation == "rust":
                environment["LD_LIBRARY_PATH"] = str(library_dir)
            self.environments[implementation] = environment

    def command(self, implementation, args, *, confirm=True):
        root = self.roots[implementation]
        return ["pacman", "--config", str(root / "pacman.conf"), "--root", str(root),
                "--dbpath", str(root / "var/lib/pacman"), "--cachedir", str(root / "var/cache/pacman/pkg"),
                "--logfile", str(self.directory / f"{implementation}.log"),
                "--hookdir", str(root / "hooks"),
                *(["--noscriptlet"] if args[0] in ("-U", "-R") else []),
                *(["--noconfirm"] if confirm else []), *map(str, args)]

    def compare(self, label, args, expected=0):
        states, statuses = {}, {}
        for implementation in ("c", "rust"):
            command = self.command(implementation, args)
            before = snapshot(self.roots[implementation])
            process = subprocess.run(command, env=self.environments[implementation],
                                     capture_output=True, timeout=30)
            statuses[implementation] = process.returncode
            (self.report / f"{len(self.commands):02}-{label}-{implementation}.log").write_bytes(
                process.stdout + process.stderr)
            states[implementation] = snapshot(self.roots[implementation])
            if expected != 0 and states[implementation] != before:
                raise AssertionError(f"{label}: rejected transaction changed {implementation} root")
        if statuses != {"c": expected, "rust": expected}:
            raise AssertionError(f"{label}: unexpected statuses {statuses}, expected {expected}")
        if states["c"] != states["rust"]:
            (self.report / f"{label}-states.json").write_text(json.dumps(states, indent=2) + "\n")
            raise AssertionError(f"{label}: extracted files or package database differ")
        self.commands.append({"case": label, "statuses": statuses, "state_equal": True})

    def verify_loaded(self, package_path, library_dir):
        result = {}
        for implementation in ("c", "rust"):
            environment = dict(self.environments[implementation], LD_DEBUG="libs,bindings")
            process = subprocess.run(self.command(implementation, ["-Qip", package_path]), env=environment,
                                     capture_output=True, timeout=30)
            trace = process.stderr.decode(errors="replace")
            (self.report / f"libalpm-{implementation}-loader.log").write_text(trace)
            bindings = [line for line in trace.splitlines()
                        if "binding file" in line and "libalpm.so" in line
                        and "libarchive.so.13" in line and "archive_" in line]
            require(process.returncode == 0 and bool(bindings), f"{implementation}: libalpm loader verification failed")
            libraries = {re.search(r" to (\S+) \[", line).group(1) for line in bindings}
            require(len(libraries) == 1, "libalpm resolved multiple archive libraries")
            library = Path(libraries.pop())
            require((library == library_dir / "libarchive.so.13") == (implementation == "rust"),
                    f"{implementation}: libalpm selected an unexpected archive library")
            result[implementation] = {"path": str(library), "bindings": len(bindings),
                                      "sha256": hashlib.sha256(library.read_bytes()).hexdigest()}
        return result

    def interrupt_confirmation(self, package_path):
        statuses = {}
        for implementation in ("c", "rust"):
            before = snapshot(self.roots[implementation])
            process = subprocess.Popen(self.command(implementation, ["-U", package_path], confirm=False),
                                       env=self.environments[implementation], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            transcript = bytearray()
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    deadline = time.monotonic() + 15
                    while b"Proceed with installation?" not in transcript:
                        if time.monotonic() > deadline or process.poll() is not None:
                            raise AssertionError("pacman did not reach its transaction confirmation")
                        for key, _ in selector.select(timeout=0.2):
                            chunk = os.read(key.fileobj.fileno(), 4096)
                            if not chunk:
                                raise AssertionError("pacman closed output before confirmation")
                            transcript.extend(chunk)
                process.send_signal(signal.SIGINT)
                remaining, _ = process.communicate(timeout=15)
                transcript.extend(remaining)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            (self.report / f"interrupted-{implementation}.log").write_bytes(transcript)
            statuses[implementation] = process.returncode
            if process.returncode == 0 or snapshot(self.roots[implementation]) != before:
                raise AssertionError("interrupted confirmation changed the package root or left a lock")
        if statuses["c"] != statuses["rust"]:
            raise AssertionError(f"interrupt statuses differ: {statuses}")
        self.commands.append({"case": "interrupt-before-commit", "statuses": statuses, "state_equal": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library-dir", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args()
    if not Path("/.dockerenv").is_file() or os.geteuid() != 0:
        parser.error("run inside the disposable root container through scripts/test-package-manager")
    args.report_dir.mkdir(parents=True, exist_ok=True)
    library = args.library_dir / "libarchive.so.13"
    if not library.is_file():
        parser.error("library directory must contain libarchive.so.13")
    summary = {"architecture": platform.machine(), "library_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
               "pacman_version": subprocess.check_output(["pacman", "--version"], text=True).strip(),
               "distribution": Path("/etc/os-release").read_text(), "cases": [],
               "packages": subprocess.check_output(["dpkg-query", "-W", "pacman-package-manager", "libalpm13", "libarchive13"], text=True),
               "pacman_sha256": hashlib.sha256(Path("/usr/bin/pacman").read_bytes()).hexdigest(),
               "limitations": ["Local unsigned fixtures; no remote repositories or signature verification",
                               "Package scripts and hooks disabled",
                               "Interruption is SIGINT at confirmation, before transaction commit; no crash-consistency claim"]}
    try:
        with tempfile.TemporaryDirectory(prefix="archive-pacman-") as temporary:
            directory = Path(temporary)
            first, second = package(directory, "1.0-1"), package(directory, "2.0-1")
            conflict = package(directory, "1.0-1", name="archive-collision", collision=True)
            truncated = directory / "truncated.pkg.tar.zst"
            truncated.write_bytes(first.read_bytes()[:len(first.read_bytes()) // 2])
            corrupt = directory / "corrupt.pkg.tar.zst"
            corrupt.write_bytes(b"invalid archive\0" + first.read_bytes()[16:])
            transactions = Transactions(directory, args.library_dir, args.report_dir)
            summary["cases"] = transactions.commands
            summary["loader"] = transactions.verify_loaded(first, args.library_dir)
            summary["fixture_sha256"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                         for path in (first, second, conflict, truncated, corrupt)}
            transactions.compare("install", ["-U", first])
            summary["user_xattr_preserved"] = "user.adoption" in os.listxattr(
                transactions.roots["c"] / "usr/share/adoption/xattr")
            for root in transactions.roots.values():
                require((root / "usr/share/adoption/data").read_bytes() == b"payload 1.0-1\n", "installed payload differs")
                require((root / "usr/share/adoption/data").samefile(root / "usr/share/adoption/hard"), "hardlink identity lost")
                require(os.readlink(root / "usr/share/adoption/link") == "data", "symlink target differs")
                require(stat.S_IMODE((root / "usr/share/adoption/run").stat().st_mode) == 0o755, "executable mode lost")
                owner = (root / "usr/share/adoption/owner").stat()
                require((owner.st_uid, owner.st_gid, stat.S_IMODE(owner.st_mode)) == (123, 456, 0o640), "owner or mode differs")
                if summary["user_xattr_preserved"]:
                    require(os.getxattr(root / "usr/share/adoption/xattr", "user.adoption") == b"fixture attribute", "user xattr differs")
                (root / "etc/adoption.conf").write_text("local configuration\n")
            transactions.compare("file-conflict", ["-U", conflict], expected=1)
            transactions.compare("upgrade", ["-U", second])
            for root in transactions.roots.values():
                require((root / "usr/share/adoption/data").read_bytes() == b"payload 2.0-1\n", "upgrade payload differs")
                require((root / "etc/adoption.conf").read_text() == "local configuration\n", "local config overwritten")
                require((root / "etc/adoption.conf.pacnew").read_text() == "configuration 2.0-1\n", "pacnew differs")
            transactions.compare("installed-query", ["-Q", "archive-adoption"])
            transactions.compare("file-verification", ["-Qk", "archive-adoption"])
            transactions.compare("downgrade", ["-U", first])
            for root in transactions.roots.values():
                require((root / "usr/share/adoption/data").read_bytes() == b"payload 1.0-1\n", "downgrade payload differs")
            transactions.compare("truncated-rejection", ["-U", truncated], expected=1)
            transactions.compare("corrupt-rejection", ["-U", corrupt], expected=1)
            transactions.compare("remove", ["-R", "archive-adoption"])
            for root in transactions.roots.values():
                require(not (root / "usr/share/adoption/data").exists(), "removed payload remains")
                require((root / "etc/adoption.conf.pacsave").read_text() == "local configuration\n", "pacsave differs")
            transactions.interrupt_confirmation(second)
            transactions.compare("retry-after-interrupt", ["-U", second])
            for root in transactions.roots.values():
                require((root / "usr/share/adoption/data").read_bytes() == b"payload 2.0-1\n", "retry payload differs")
            summary["cases"] = transactions.commands
            summary["passed"] = len(transactions.commands)
    except Exception as error:
        summary["error"] = str(error)
        raise
    finally:
        (args.report_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Package transactions: {summary['passed']} passed; libalpm Rust bindings: {summary['loader']['rust']['bindings']}")


if __name__ == "__main__":
    main()
