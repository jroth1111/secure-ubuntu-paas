import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('autoheal', ROOT / 'overlays/dokploy/maintenance/autoheal.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RecoveryBudgetTests(unittest.TestCase):
    def test_first_attempt_allowed(self):
        self.assertTrue(module.permitted([], 100000))

    def test_cooldown_blocks_repeated_attempt(self):
        self.assertFalse(module.permitted([99999], 100000))
        self.assertTrue(module.permitted([98200], 100000))

    def test_three_attempts_per_rolling_day(self):
        self.assertFalse(module.permitted([90000, 93000, 96000], 100000))
        self.assertTrue(module.permitted([1000, 93000, 96000], 100000))


if __name__ == '__main__':
    unittest.main()
