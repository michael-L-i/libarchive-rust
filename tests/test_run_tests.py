"""Exercise the runner's CLI contract without building the upstream binaries."""

import contextlib
import importlib.machinery
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run-tests"
LOADER = importlib.machinery.SourceFileLoader("run_tests", str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
RUNNER = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(RUNNER)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root_patch = mock.patch.object(RUNNER, "ROOT", str(self.root))
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        (self.root / "tests").mkdir()

    def names(self, filename, names):
        path = self.root / "tests" / filename
        RUNNER.write_names(str(path), names, "# baseline\n")
        return path

    def run_cli(self, states, *args, platform="linux"):
        passing, upstream = RUNNER.baseline_paths(platform)
        stdout = io.StringIO()
        with mock.patch.object(RUNNER, "PASSING", passing), \
                mock.patch.object(RUNNER, "UPSTREAM", upstream), \
                mock.patch.object(RUNNER, "suite_cmd", return_value=(["fake"], [])), \
                mock.patch.object(RUNNER, "list_tests", return_value=list(states)), \
                mock.patch.object(RUNNER, "run_one", side_effect=lambda cmd, name, out, timeout:
                                  (name, states[name], 0.01)), \
                mock.patch("sys.argv", [str(SCRIPT), "-j", "1", *args]), \
                contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as result:
            RUNNER.main()
        return result.exception.code, stdout.getvalue()

    def test_platform_paths(self):
        for platform, suffix in (("linux", "-linux"), ("linux2", "-linux"), ("darwin", "")):
            with self.subTest(platform=platform):
                paths = RUNNER.baseline_paths(platform)
                self.assertEqual([Path(p).name for p in paths],
                                 [f"passing{suffix}.txt", f"upstream{suffix}.txt"])

    def test_platform_ratchets_are_independent(self):
        self.names("passing-linux.txt", ["test_linux"])
        self.names("passing.txt", ["test_mac"])
        states = {"test_linux": "pass", "test_mac": "skip"}
        self.assertEqual(self.run_cli(states)[0], 0)
        self.assertEqual(self.run_cli(states, platform="darwin")[0], 1)

    def test_baseline_pass_becoming_skip_is_a_regression_in_both_modes(self):
        for args, filename in (((), "passing-linux.txt"), (("--oracle",), "upstream-linux.txt")):
            with self.subTest(args=args):
                self.names(filename, ["test_old"])
                code, output = self.run_cli({"test_old": "skip"}, *args)
                self.assertEqual(code, 1)
                self.assertIn("1 regressions", output)
                self.assertIn(filename, output)

    def test_unratcheted_failures_also_fail_in_both_modes(self):
        for args in ((), ("--oracle",)):
            for status in ("fail", "crash:SIGSEGV", "timeout"):
                with self.subTest(args=args, status=status):
                    self.assertEqual(self.run_cli({"test_new": status}, *args)[0], 1)

    def test_update_preserves_existing_names_and_mac_baseline(self):
        linux = self.names("passing-linux.txt", ["test_old", "tar/test_unselected"])
        mac = self.names("passing.txt", ["test_mac"])
        before = mac.read_bytes()
        code, _ = self.run_cli({"test_old": "pass", "test_new": "pass", "test_skip": "skip"},
                               "--update")
        self.assertEqual(code, 0)
        self.assertEqual(set(RUNNER.read_names(linux)),
                         {"test_old", "test_new", "tar/test_unselected"})
        self.assertEqual(mac.read_bytes(), before)

    def test_update_can_create_missing_platform_baseline(self):
        self.assertEqual(self.run_cli({"test_new": "pass"}, "--update")[0], 0)
        self.assertEqual(RUNNER.read_names(self.root / "tests/passing-linux.txt"), ["test_new"])

    def test_oracle_baseline_preserves_unselected_suites(self):
        path = self.names("upstream-linux.txt", ["test_old", "cat/test_existing"])
        self.assertEqual(self.run_cli({"test_old": "pass", "test_new": "pass"},
                                      "--oracle", "--baseline")[0], 0)
        self.assertEqual(set(RUNNER.read_names(path)),
                         {"test_old", "test_new", "cat/test_existing"})

    def test_failed_oracle_baseline_does_not_erase_passes(self):
        for status in ("skip", "fail"):
            with self.subTest(status=status):
                path = self.names("upstream-linux.txt", ["test_old"])
                before = path.read_bytes()
                self.assertEqual(self.run_cli({"test_old": status}, "--oracle", "--baseline")[0], 1)
                self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
