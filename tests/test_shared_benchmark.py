"""Failures in measured programs must survive into benchmark evidence."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

BENCH = Path(__file__).resolve().parents[1] / 'bench'
sys.path.insert(0, str(BENCH))
SPEC = importlib.util.spec_from_file_location('compare_shared', BENCH / 'compare-shared.py')
shared = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shared)


class SharedBenchmarkFailures(unittest.TestCase):
    def test_crash_is_not_malformed_input_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            for status, valid in [(-11, False), (0, False), (1, True)]:
                with self.subTest(status=status), patch.object(shared.subprocess, 'run', return_value=
                        subprocess.CompletedProcess([], status, b'', b'error')):
                    checks = shared.reject_truncated(Path('client'), {'Rust': {}}, Path(directory))
                self.assertEqual([check['valid'] for check in checks], [valid, valid])

    def test_malformed_input_timeout_is_invalid_and_recorded(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(shared.subprocess, 'run',
                side_effect=subprocess.TimeoutExpired(['client'], 30, stderr=b'hung')):
            checks = shared.reject_truncated(Path('client'), {'Rust': {}}, Path(directory))
        self.assertTrue(all(not check['valid'] and check['status'] == 'timeout' for check in checks))
        self.assertTrue(all(check['stderr'] == 'hung' for check in checks))

    def test_failed_startup_writes_failure_report_with_null_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('client', 'probe', 'c.dylib', 'rust.dylib'):
                (root / name).write_bytes(b'fixture')
            (root / 'inputs/records').mkdir(parents=True)
            argv = ['compare-shared', '--binary', str(root / 'client'), '--binding-probe', str(root / 'probe'),
                    '--c-library', str(root / 'c.dylib'), '--rust-library', str(root / 'rust.dylib'),
                    '--rust-build', 'test fixture', '--inputs', str(root / 'inputs'),
                    '--work', str(root / 'work'), '--out', str(root / 'out'), '--label', 'failed',
                    '--datasets', 'records', '--formats', 'tar', '--startup-repeats', '1']
            with patch.object(sys, 'argv', argv), patch.object(shared.platform, 'system', return_value='Darwin'), \
                    patch.object(shared.platform, 'platform', return_value='fixture'), \
                    patch.object(shared, 'verify_provider', return_value={'version': 'fixture'}), \
                    patch.object(shared.compare, 'measure', return_value=([], [], ['matrix timeout'])), \
                    patch.object(shared, 'reject_truncated', return_value=[]), \
                    patch.object(shared.compare, 'run', side_effect=[
                        {'status': 'timeout', 'wall_s': 30, 'error': 'timeout'},
                        {'status': 'error', 'wall_s': 1, 'peak_rss_bytes': None, 'error': 'crash'}]), \
                    patch.object(shared.subprocess, 'check_output', return_value='fixture'), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(shared.main(), 1)
            report = json.loads((root / 'out/failed.json').read_text())
            self.assertEqual(len(report['failures']), 3)
            for variant in ('C', 'Rust'):
                self.assertIsNone(report['startup_summary'][variant]['median_s'])
                self.assertIsNone(report['startup_summary'][variant]['peak_mib'])
            self.assertIn('| Median ms | unavailable | unavailable |', (root / 'out/failed.md').read_text())


if __name__ == '__main__':
    unittest.main()
