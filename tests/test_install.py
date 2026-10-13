"""Installer path validation and confinement checks without a compiler build."""

import argparse
import contextlib
import importlib.machinery
import importlib.util
import io
import json
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
CONSUMER_LOADER = importlib.machinery.SourceFileLoader("installed_tests", str(ROOT / "scripts/test-installed"))
CONSUMER_SPEC = importlib.util.spec_from_loader(CONSUMER_LOADER.name, CONSUMER_LOADER)
CONSUMER = importlib.util.module_from_spec(CONSUMER_SPEC)
CONSUMER_LOADER.exec_module(CONSUMER)


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

    def test_pkg_config_preserves_relocated_paths_and_static_dependencies(self):
        with tempfile.TemporaryDirectory(prefix="pkg config space ") as temporary:
            libdir = Path(temporary) / "relocated prefix/lib"
            pcdir = libdir / "pkgconfig"
            pcdir.mkdir(parents=True)
            pc = INSTALL.metadata(Path("lib"), "libarchive.so.13", ["-lm", "-lc"])[0]
            (pcdir / "libarchive.pc").write_text(pc)
            env = dict(os.environ, PKG_CONFIG_LIBDIR=str(pcdir))
            for variable in ("PKG_CONFIG_PATH", "PKG_CONFIG_SYSROOT_DIR"):
                env.pop(variable, None)
            command = os.environ.get("PKG_CONFIG", "pkg-config")
            pkg = lambda *options: CONSUMER.run([command, *options, "libarchive"], env=env).strip()
            values = {name: pkg(f"--variable={name}") for name in ("prefix", "libdir", "includedir")}
            cflags, dynamic, static = CONSUMER.pkg_config_flags(pkg, values, libdir, libdir.parent / "include")
            self.assertEqual(len(cflags), 1)
            self.assertEqual(dynamic[1:], ["-larchive"])
            self.assertEqual(static[1:], ["-larchive", "-lm", "-lc"])

    def test_pkg_config_does_not_repair_arbitrary_wrong_flags(self):
        values = {"libdir": "/prefix space/lib", "includedir": "/prefix space/include"}
        outputs = {("--cflags",): "-I/wrong include", ("--libs",): "-L/prefix space/lib -larchive",
                   ("--libs", "--static"): "-L/prefix space/lib -larchive -lc"}
        with self.assertRaisesRegex(RuntimeError, "installed include directory"):
            CONSUMER.pkg_config_flags(lambda *options: outputs[options], values,
                                      Path(values["libdir"]), Path(values["includedir"]))

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

    def test_configured_cargo_target_cannot_select_stale_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "src").mkdir()
            (directory / "src/lib.rs").write_text(
                '#[no_mangle]\npub extern "C" fn fixture() -> i32 { 42 }\n'
            )
            (directory / "Cargo.toml").write_text(
                '[package]\nname="libarchive-capi"\nversion="0.1.0"\nedition="2021"\n'
                '[lib]\nname="archive"\ncrate-type=["staticlib", "cdylib"]\n'
            )
            (directory / "Cargo.lock").write_text(
                'version = 4\n[[package]]\nname = "libarchive-capi"\nversion = "0.1.0"\n'
            )
            (directory / ".cargo").mkdir()
            (directory / ".cargo/config.toml").write_text(
                '[build]\ntarget="wasm32-unknown-unknown"\n'
            )
            target = directory / "target"
            stale = target / "debug/libarchive.a"
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b"stale archive")
            args = SimpleNamespace(profile="dev", without_tools=True)
            env = dict(os.environ)
            env.pop("CARGO_BUILD_TARGET", None)
            env["CARGO_TERM_COLOR"] = "always"
            with patch.object(INSTALL, "ROOT", directory), patch.dict(os.environ, env, clear=True):
                with contextlib.redirect_stdout(io.StringIO()):
                    output, native = INSTALL.build(args, target)
                    self.assertTrue(all("\x1b" not in flag for flag in native), native)
                    report = output / "libarchive-native-libs.json"
                    cached = json.loads(report.read_text())
                    cached["libs"][-1] += "\x1b[0m"
                    report.write_text(json.dumps(cached))
                    _, recovered = INSTALL.build(args, target)
                    self.assertEqual(recovered, native)
                    self.assertEqual(json.loads(report.read_text())["libs"], native)
            self.assertNotEqual(output, stale.parent)
            self.assertNotEqual((output / "libarchive.a").read_bytes(), stale.read_bytes())
            self.assertEqual(stale.read_bytes(), b"stale archive")
            self.assertTrue(native)


if __name__ == "__main__":
    unittest.main()
