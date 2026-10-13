"""Installer path validation and confinement checks without a compiler build."""

import argparse
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
LOADER = importlib.machinery.SourceFileLoader("installer", str(ROOT / "scripts/install"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
INSTALL = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(INSTALL)


class InstallerPaths(unittest.TestCase):
    def test_rejects_metadata_unsafe_library_directories_before_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            for libdir in ("lib space", "lib#comment", 'lib"quote', "lib'quote", "lib\ttab"):
                with self.subTest(libdir=libdir):
                    result = subprocess.run(
                        [str(ROOT / "scripts/install"), "--destdir", temporary, "--libdir", libdir],
                        env=dict(os.environ, CARGO=str(Path(temporary) / "missing-cargo")),
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("argument --libdir", result.stderr)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_rejects_absolute_and_parent_library_directories(self):
        for libdir in ("/lib", "../lib", "lib/../outside", ".", ""):
            with self.subTest(libdir=libdir):
                with self.assertRaises(argparse.ArgumentTypeError):
                    INSTALL.relative_directory(libdir)

    def test_accepts_conventional_multiarch_directories(self):
        for libdir in ("lib", "lib64", "lib/x86_64-linux-gnu", "lib/aarch64-linux-gnu", "lib/pkg+abi_1.0"):
            with self.subTest(libdir=libdir):
                self.assertEqual(INSTALL.relative_directory(libdir), Path(libdir))

    def stage(self, directory, libdir="lib"):
        directory = Path(directory)
        output = directory / "output"
        output.mkdir(exist_ok=True)
        (output / "libarchive.dylib").write_bytes(b"new shared archive")
        (output / "libarchive.a").write_bytes(b"new static archive")
        args = SimpleNamespace(
            destdir=directory / "stage", prefix=Path("/usr/prefix space"),
            libdir=INSTALL.relative_directory(libdir), without_tools=True,
        )
        with patch.object(INSTALL, "license_notices", return_value="test notices\n"):
            INSTALL.stage(args, output, ["-lc"], "Darwin")
        return args.destdir / args.prefix.relative_to("/")

    def test_stages_multiarch_metadata_under_spaced_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = self.stage(temporary, "lib/x86_64-linux-gnu")
            lib = prefix / "lib/x86_64-linux-gnu"
            self.assertEqual((lib / "libarchive.a").read_bytes(), b"new static archive")
            self.assertEqual((lib / "libarchive.dylib").readlink(), Path("libarchive.13.dylib"))
            self.assertIn("prefix=${pcfiledir}/../../..", (lib / "pkgconfig/libarchive.pc").read_text())
            self.assertIn("${prefix}/lib/x86_64-linux-gnu", (lib / "pkgconfig/libarchive.pc").read_text())

    def test_refuses_staging_directory_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            prefix = directory / "stage/usr/prefix space"
            prefix.mkdir(parents=True)
            outside = directory / "outside"
            outside.mkdir()
            (prefix / "lib").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "symlink directory"):
                self.stage(temporary)
            self.assertEqual(list(outside.iterdir()), [])
            self.assertFalse((prefix / "include").exists())

    def test_refuses_existing_file_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            lib = directory / "stage/usr/prefix space/lib"
            lib.mkdir(parents=True)
            outside = directory / "outside.a"
            outside.write_bytes(b"keep me")
            (lib / "libarchive.a").symlink_to(outside)
            with self.assertRaisesRegex(RuntimeError, "overwrite symlink"):
                self.stage(temporary)
            self.assertEqual(outside.read_bytes(), b"keep me")

    def test_replacement_does_not_modify_external_hardlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            lib = directory / "stage/usr/prefix space/lib"
            lib.mkdir(parents=True)
            outside = directory / "outside.a"
            outside.write_bytes(b"keep me")
            os.link(outside, lib / "libarchive.a")
            self.stage(temporary)
            self.assertEqual(outside.read_bytes(), b"keep me")
            self.assertEqual((lib / "libarchive.a").read_bytes(), b"new static archive")


if __name__ == "__main__":
    unittest.main()
