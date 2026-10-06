import importlib.util
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[4]
spec=importlib.util.spec_from_file_location('go_floors',ROOT/'overlays/dokploy/maintenance/patch-go-deps.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class GoSecurityFloorTests(unittest.TestCase):
    def test_updates_older_stable_modules_without_downgrade_or_new_dependencies(self):
        current={'crypto':'v0.31.0','grpc':'v1.84.0','other':'v5.1.0'}
        changes,blocked=module.choose_updates(current,{'crypto':'v0.55.0','grpc':'v1.83.2','missing':'v1.1.0'})
        self.assertEqual(changes,{'crypto':'v0.55.0'})
        self.assertEqual(blocked,[])

    def test_major_import_jump_is_left_for_compatibility_review(self):
        changes,blocked=module.choose_updates({'cli':'v27.5.0+incompatible'},{'cli':'v29.2.0+incompatible'})
        self.assertEqual(changes,{})
        self.assertEqual(blocked[0]['reason'],'import-major compatibility review required')

    def test_prerelease_floor_is_refused_and_newer_prerelease_is_not_downgraded(self):
        with self.assertRaises(RuntimeError):module.choose_updates({'grpc':'v1.68.1'},{'grpc':'v1.84.0-dev.123'})
        changes,blocked=module.choose_updates({'grpc':'v1.84.0-dev.123'},{'grpc':'v1.83.2'})
        self.assertEqual(changes,{})


if __name__=='__main__':unittest.main()
