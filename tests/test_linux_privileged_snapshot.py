"""The privileged runner's source export must not dereference fixture links."""
import pathlib
import subprocess
import tarfile
import tempfile
import unittest


class PrivilegedSourceSnapshot(unittest.TestCase):
    def test_symlinks_are_preserved_and_upstream_is_exported_separately(self):
        script = pathlib.Path(__file__).parent / "linux-privileged/snapshot.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repo"
            root.mkdir()
            external = pathlib.Path(temporary) / "outside"
            external.write_text("must never be included")
            (root / "fixture").symlink_to(external)
            (root / "ordinary").write_text("source")
            (root / "upstream").mkdir()
            (root / "upstream/libarchive").symlink_to(external)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            output = pathlib.Path(temporary) / "source.tar"
            subprocess.run(["python3", str(script), str(root), str(output)], check=True)
            with tarfile.open(output) as archive:
                self.assertEqual(set(archive.getnames()), {"fixture", "ordinary"})
                fixture = archive.getmember("fixture")
                self.assertTrue(fixture.issym())
                self.assertEqual(fixture.linkname, str(external))
                self.assertEqual(archive.extractfile("ordinary").read(), b"source")


if __name__ == "__main__":
    unittest.main()
