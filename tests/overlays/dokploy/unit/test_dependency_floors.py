import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]
HELPERS = ROOT / 'overlays/dokploy/maintenance'


class FloorsTests(unittest.TestCase):
    def test_rejects_vulnerable_version_and_accepts_newer_without_downgrade(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            modules = root / 'node_modules/pkg'
            modules.mkdir(parents=True)
            manifest = root / 'floors.json'
            manifest.write_text(json.dumps({'vite@>=7.0.0 <7.3.5': '7.3.5'}))
            for version, success in [('7.3.1', False), ('7.3.5', True), ('7.4.0', True)]:
                (modules / 'package.json').write_text(json.dumps({'name': 'vite', 'version': version}))
                result = subprocess.run(['node', str(HELPERS / 'verify-floors.cjs'),
                    str(root / 'node_modules'), str(manifest)], capture_output=True)
                self.assertEqual(result.returncode == 0, success)

    def test_updates_workspace_and_project_manager_pins_preserving_settings(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            manifest = root / 'floors.json'
            manifest.write_text(json.dumps({'vite@>=7.0.0 <7.3.5': '7.3.5'}))
            (root / 'package.json').write_text(json.dumps({'packageManager': 'pnpm@10.22.0'}))
            (root / 'pnpm-workspace.yaml').write_text('packages: [apps/*]\n')
            project = root / 'apps/test'
            project.mkdir(parents=True)
            (project / 'package.json').write_text(json.dumps({'packageManager': 'pnpm@10.22.0'}))
            script = root / 'apply.cjs'
            script.write_text((HELPERS / 'apply-overrides.cjs').read_text().replace(
                '/tmp/security-overrides.json', str(manifest)))
            import os
            subprocess.run(['node', str(script)], cwd=root,
                env={**os.environ, 'PNPM_VERSION': '10.34.5'}, check=True)
            self.assertEqual(json.loads((project / 'package.json').read_text())['packageManager'], 'pnpm@10.34.5')
            import yaml
            workspace = yaml.safe_load((root / 'pnpm-workspace.yaml').read_text())
            self.assertEqual(workspace['packages'], ['apps/*'])
            self.assertEqual(workspace['overrides']['vite@>=7.0.0 <7.3.5'], '7.3.5')


if __name__ == '__main__':
    unittest.main()
