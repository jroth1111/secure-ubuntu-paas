import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('native', ROOT / 'overlays/dokploy/maintenance/rebuild-esbuild.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class NativeDiscoveryTests(unittest.TestCase):
    def test_discovers_elf_copies_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            binary = root / 'package/bin/esbuild'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'\x7fELFtest')
            alias = root / 'alias'
            alias.mkdir()
            (alias / 'esbuild').symlink_to(binary)
            with mock.patch('subprocess.check_output', return_value='0.20.2\n'):
                self.assertEqual(native.discover(root), {'0.20.2': [binary]})

    def test_nonstable_version_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            (root / 'esbuild').write_bytes(b'\x7fELFtest')
            with mock.patch('subprocess.check_output', return_value='0.20.2-beta\n'):
                with self.assertRaises(RuntimeError):
                    native.discover(root)


if __name__ == '__main__':
    unittest.main()
