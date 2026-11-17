import unittest
from experiments.run_behavior_hybrid import combine


class HybridTests(unittest.TestCase):
    def test_denial_then_different_family(self):
        self.assertTrue(combine([{'status': 401}, {'status': 200}], ['sql', 'html']))
        self.assertFalse(combine([{'status': 200}, {'status': 401}], ['html', 'sql']))
        self.assertFalse(combine([{'status': 401}, {'status': 401}], ['sql', 'sql']))
        self.assertFalse(combine([{'status': 401}, {'status': 200}], ['none', 'none']))

    def test_failure_is_not_a_benign_prediction(self):
        self.assertIsNone(combine([{'status': 401}, {'status': 200}], [None, 'html']))


if __name__ == '__main__':
    unittest.main()
