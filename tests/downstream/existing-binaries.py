#!/usr/bin/env python3
"""Compare unchanged Linux applications with system C and installed Rust libarchive."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


def require(condition, detail):
    if not condition:
        raise RuntimeError(str(detail))


def exercise(root, library, report):
    base = dict(
        os.environ,
        PATH="/usr/bin:/bin",
        LANG="C.UTF-8",
        LC_ALL="C.UTF-8",
        LD_BIND_NOW="1",
    )
    for variable in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT", "LD_DEBUG"):
        base.pop(variable, None)
    environments = {"C": base, "Rust": dict(base, LD_LIBRARY_PATH=str(library))}
    records = []
    commands = 0

    def run(args, backend, cwd=root, data=None, ok=True):
        nonlocal commands
        commands += 1
        p = subprocess.run(
            list(map(str, args)),
            cwd=cwd,
            env=environments[backend],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        if ok and p.returncode:
            raise RuntimeError(
                f'{backend} {args}: {p.returncode}\n{p.stderr.decode(errors="replace")}'
            )
        return p

    def record(name):
        records.append(name)
        print("PASS", name, flush=True)

    def snapshot(directory):
        result = {}
        for path in sorted(directory.rglob("*")):
            info = path.lstat()
            key = str(path.relative_to(directory))
            if stat.S_ISLNK(info.st_mode):
                result[key] = ("link", os.readlink(path))
            elif stat.S_ISREG(info.st_mode):
                result[key] = (
                    "file",
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    info.st_size,
                )
            elif stat.S_ISDIR(info.st_mode):
                result[key] = ("dir",)
            else:
                raise RuntimeError(f"unexpected extracted object {path}")
        return result

    fixture = root / "fixture"
    (fixture / "input/nested").mkdir(parents=True)
    for name, data in {
        "input/plain.txt": b"downstream archive check\n" * 30,
        "input/space name.txt": b"space pathname\n",
        "input/nested/caf\u00e9.txt": b"UTF-8 path\n",
        "input/empty": b"",
        "input/binary.dat": bytes(range(256)) * 2048,
    }.items():
        path = fixture / name
        path.write_bytes(data)
        path.chmod(0o640)
        os.utime(path, (1700000000, 1700000000))
    expected = snapshot(fixture)

    # Loader traces demonstrate the unchanged distribution binaries initialize our
    # installed library. LD_BIND_NOW also rejects missing eager relocations.
    loaded_libraries = {}
    for binary in ["cmake", "bsdtar", "bsdcpio", "bsdcat"]:
        loaded_libraries[binary] = {}
        for backend, environment in environments.items():
            commands += 1
            p = subprocess.run(
                ["/usr/bin/" + binary, "--version"],
                env=dict(environment, LD_DEBUG="libs"),
                capture_output=True,
                timeout=30,
            )
            trace = p.stderr.decode(errors="replace")
            require(p.returncode == 0, (binary, backend, trace))
            paths = [
                line.split("calling init:", 1)[1].strip()
                for line in trace.splitlines()
                if "calling init:" in line and "libarchive.so.13" in line
            ]
            require(len(paths) == 1, (binary, backend, paths, trace))
            require(
                (Path(paths[0]).resolve() == (library / "libarchive.so.13").resolve())
                == (backend == "Rust"),
                (binary, backend, paths),
            )
            loaded_libraries[binary][backend] = paths[0]
            (report / (binary + "-" + backend + "-loader.log")).write_text(trace)
        record(binary + " loads installed Rust library without recompilation")

    formats = [
        ("tar", "paxr", None),
        ("tar.gz", "paxr", "GZip"),
        ("tar.bz2", "paxr", "BZip2"),
        ("tar.xz", "paxr", "XZ"),
        ("tar.zst", "paxr", "Zstd"),
        ("zip", "zip", None),
        ("7z", "7zip", None),
    ]
    for suffix, fmt, compression in formats:
        for producer in environments:
            archive = root / (producer + "." + suffix)
            script = root / "create.cmake"
            comp = f" COMPRESSION {compression}" if compression else ""
            script.write_text(
                f'file(ARCHIVE_CREATE OUTPUT "{archive}" PATHS input FORMAT {fmt}{comp})\n'
            )
            run(["/usr/bin/cmake", "-P", script], producer, fixture)
            listings = []
            for consumer in environments:
                listings.append(
                    run(["/usr/bin/cmake", "-E", "tar", "tf", archive], consumer).stdout
                )
                for api in ["cmake", "bsdtar"]:
                    output = root / f"extract-{suffix}-{producer}-{consumer}-{api}"
                    output.mkdir()
                    cmd = (
                        ["/usr/bin/cmake", "-E", "tar", "xf", archive]
                        if api == "cmake"
                        else ["/usr/bin/bsdtar", "-xf", archive]
                    )
                    run(cmd, consumer, output)
                    require(
                        snapshot(output) == expected,
                        (suffix, producer, consumer, api, snapshot(output)),
                    )
            require(listings[0] == listings[1], (suffix, producer, listings))
        record(
            "CMake file(ARCHIVE_CREATE), listings and C/Rust cross-extraction: "
            + suffix
        )
        # Exercise the distribution C bsdtar's writer independently as well.
        for producer in environments:
            archive = root / ("bsdtar-" + producer + "." + suffix)
            cmd = ["/usr/bin/bsdtar", "-cf", archive, "--format=" + fmt]
            option = {
                "tar.gz": "-z",
                "tar.bz2": "-j",
                "tar.xz": "-J",
                "tar.zst": "--zstd",
            }.get(suffix)
            if option:
                cmd.append(option)
            cmd.append("input")
            run(cmd, producer, fixture)
            for consumer in environments:
                output = root / f"bsdtar-extract-{suffix}-{producer}-{consumer}"
                output.mkdir()
                run(["/usr/bin/bsdtar", "-xf", archive], consumer, output)
                require(
                    snapshot(output) == expected,
                    (suffix, producer, consumer, "bsdtar writer"),
                )
        record("distribution bsdtar C/Rust writer and cross-reader: " + suffix)

    # cpio producers and readers must preserve recovered regular file bytes.
    paths = b"input/plain.txt\ninput/space name.txt\ninput/nested/caf\xc3\xa9.txt\ninput/empty\ninput/binary.dat\n"
    for producer in environments:
        archive = root / ("data-" + producer + ".cpio")
        archive.write_bytes(
            run(
                ["/usr/bin/bsdcpio", "-o", "--format=newc"], producer, fixture, paths
            ).stdout
        )
        for consumer in environments:
            output = root / f"cpio-extract-{producer}-{consumer}"
            output.mkdir()
            run(["/usr/bin/bsdcpio", "-id"], consumer, output, archive.read_bytes())
            require(snapshot(output) == expected, (producer, consumer, "cpio"))
    record("distribution bsdcpio newc cross-writer/readers")

    for suffix, _, _ in formats:
        if suffix not in ("tar.gz", "tar.bz2", "tar.xz", "tar.zst"):
            continue
        for producer in environments:
            a = root / (producer + "." + suffix)
            decoded = [
                run(["/usr/bin/bsdcat", a], backend).stdout for backend in environments
            ]
            require(decoded[0] == decoded[1], (suffix, producer, "bsdcat bytes"))
    record("distribution bsdcat gzip/bzip2/xz/zstd decoded bytes")

    # Keep link fidelity separate from formats that cannot encode hardlinks.
    links = root / "links"
    links.mkdir()
    (links / "target").write_bytes(b"link payload\n")
    (links / "symbolic").symlink_to("target")
    os.link(links / "target", links / "hard")
    for producer in environments:
        archive = root / ("links-" + producer + ".tar")
        run(
            [
                "/usr/bin/bsdtar",
                "-cf",
                archive,
                "--format=paxr",
                "target",
                "symbolic",
                "hard",
            ],
            producer,
            links,
        )
        for consumer in environments:
            output = root / f"links-extract-{producer}-{consumer}"
            output.mkdir()
            run(["/usr/bin/bsdtar", "-xf", archive], consumer, output)
            require(
                snapshot(output) == snapshot(links), "link archive contents changed"
            )
            require(
                (output / "target").stat().st_ino == (output / "hard").stat().st_ino,
                "extraction did not preserve hardlink identity",
            )
    record("distribution bsdtar symlink/hardlink cross-roundtrips")

    # Corrupt ZIP must be rejected, rather than silently extracted, by both clients.
    corrupt = root / "corrupt.zip"
    corrupt.write_bytes(b"PK\x03\x04" + b"\0" * 20)
    for client, args in [("cmake", ["-E", "tar", "tf"]), ("bsdtar", ["-tf"])]:
        results = [
            run(["/usr/bin/" + client, *args, corrupt], b, ok=False).returncode
            for b in environments
        ]
        require(all((r > 0 for r in results)), (client, results))
    record("cmake and bsdtar reject truncated ZIP without crash")

    # FetchContent exercises CMake's real dependency extraction followed by a build.
    dep = root / "dep"
    dep.mkdir()
    (dep / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.18)\nproject(dep C)\nadd_library(dep STATIC dep.c)\n"
    )
    (dep / "dep.c").write_text("int answer(void) { return 42; }\n")
    package = root / "dep.tar.gz"
    run(["/usr/bin/bsdtar", "-czf", package, "dep"], "C")
    project = root / "project"
    project.mkdir()
    (project / "CMakeLists.txt").write_text(
        f"cmake_minimum_required(VERSION 3.18)\nproject(downstream C)\n"
        "if(POLICY CMP0135)\n  cmake_policy(SET CMP0135 NEW)\nendif()\n"
        "include(FetchContent)\n"
        f'FetchContent_Declare(dep URL "file://{package}")\n'
        "FetchContent_MakeAvailable(dep)\nadd_executable(check main.c)\n"
        "target_link_libraries(check PRIVATE dep)\n"
    )
    (project / "main.c").write_text(
        '#include <stdio.h>\nint answer(void);\nint main(void) { printf("%d\\n", answer()); return answer() != 42; }\n'
    )
    for backend in environments:
        build = root / ("fetch-build-" + backend)
        run(["/usr/bin/cmake", "-S", project, "-B", build], backend)
        run(["/usr/bin/cmake", "--build", build], backend)
        require(
            run([build / "check"], backend).stdout == b"42\n",
            "FetchContent consumer returned unexpected output",
        )
        require(
            (build / "_deps/dep-src/dep.c").read_bytes()
            == (dep / "dep.c").read_bytes(),
            "FetchContent changed dependency contents",
        )
    record("CMake FetchContent local dependency extraction/configure/build/run")

    versions = {
        name: run(["/usr/bin/" + name, "--version"], "C")
        .stdout.decode(errors="replace")
        .splitlines()[0]
        for name in ["cmake", "bsdtar", "bsdcpio"]
    }
    summary = {
        "checks_passed": len(records),
        "commands_executed": commands,
        "checks": records,
        "architecture": os.uname().machine,
        "rust_library": str(library / "libarchive.so.13"),
        "rust_library_sha256": hashlib.sha256(
            (library / "libarchive.so.13").read_bytes()
        ).hexdigest(),
        "loaded_libraries": loaded_libraries,
        "versions": versions,
    }
    (report / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--library-dir",
        type=Path,
        required=True,
        help="installed Rust library directory containing libarchive.so.13",
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        required=True,
        help="directory for summary and loader traces",
    )
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("this test requires Linux and the glibc loader trace")
    library = args.library_dir.resolve()
    if not (library / "libarchive.so.13").is_file():
        parser.error("--library-dir has no libarchive.so.13")
    report = args.report_dir.resolve()
    report.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="libarchive downstream ") as directory:
        exercise(Path(directory), library, report)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
