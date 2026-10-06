import ast
import copy
import json
import pathlib
import unittest
import yaml

ROOT=pathlib.Path(__file__).resolve().parents[4]
SOURCE=ROOT/'overlays/dokploy/maintenance/hermes/updater.py'
tree=ast.parse(SOURCE.read_text())
names={'ROOTLESS_USER','ROOTLESS_TMPFS','UniqueKeyLoader','rootless_compose'}
selected=[]
for node in tree.body:
    if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in names:
        selected.append(node)
    elif isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id in names for target in node.targets):
        selected.append(node)
scope={'yaml':yaml,'copy':copy,'json':json}
exec(compile(ast.Module(body=selected,type_ignores=[]),str(SOURCE),'exec'),scope)
apply_policy=scope['rootless_compose']


class RuntimePolicyTests(unittest.TestCase):
    def test_preserves_all_unmanaged_content_and_is_idempotent(self):
        original='''services:
  hermes:
    image: old-image
    environment:
      SECRET: "synthetic-test-value"
      KEEP: "${UNCHANGED}"
    volumes: [hermes_data:/opt/data]
    ports: ["100.102.237.110:9119:9119"]
  other:
    image: untouched-image
volumes:
  hermes_data:
    external: true
'''
        observed=apply_policy(original,'new-image')
        self.assertIn('      SECRET: "synthetic-test-value"\n',observed)
        self.assertIn('    volumes: [hermes_data:/opt/data]\n',observed)
        before=yaml.safe_load(original)
        after=yaml.safe_load(observed)
        self.assertEqual(before['services']['other'],after['services']['other'])
        self.assertEqual(before['volumes'],after['volumes'])
        self.assertEqual(before['services']['hermes']['environment'],after['services']['hermes']['environment'])
        self.assertEqual(observed,apply_policy(observed,'new-image'))

    def test_replaces_existing_managed_fields_without_duplicates(self):
        original='services:\n  hermes:\n    user: root\n    image: old\n    read_only: false\n    cap_drop: []'
        observed=yaml.safe_load(apply_policy(original,'new'))['services']['hermes']
        self.assertEqual(observed['user'],'10000:10000')
        self.assertTrue(observed['read_only'])
        self.assertEqual(observed['cap_drop'],['ALL'])

    def test_refuses_duplicate_keys_extra_capabilities_and_unmanaged_mounts(self):
        for extra in ['    image: duplicate\n','    cap_add: [SYS_ADMIN]\n','    tmpfs: [/unmanaged]\n',
                      '    environment: {S6_READ_ONLY_ROOT: "0"}\n','    environment: {PUID: "1234"}\n']:
            with self.subTest(extra=extra),self.assertRaises(RuntimeError):
                apply_policy('services:\n  hermes:\n    image: old\n'+extra,'new')


if __name__=='__main__':
    unittest.main()
