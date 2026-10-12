"""Copy tracked worktree files without following fixture or submodule symlinks."""
import pathlib
import subprocess
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
with tarfile.open(sys.argv[2], "w", dereference=False) as archive:
    names = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
    for raw in names.split(b"\0"):
        if not raw:
            continue
        name = raw.decode("utf-8")
        if name == "upstream/libarchive" or name.startswith("upstream/libarchive/"):
            continue
        archive.add(root / name, arcname=name, recursive=False)
