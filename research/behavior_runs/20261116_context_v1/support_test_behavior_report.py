import unittest
from experiments.build_behavior_report import evaluate


class BehaviorReportTests(unittest.TestCase):
    def setUp(self):
        self.episodes = [dict(id='p', pair='pair', adaptive=True, kind='adaptive'),
                         dict(id='n', pair='pair', adaptive=False, kind='benign')]

    def test_abstention_is_not_a_correct_negative(self):
        result = evaluate(self.episodes, [dict(id='p', mode='m', status='completed', prediction=True),
                                         dict(id='n', mode='m', status='failed', prediction=None)], 'm')
        self.assertEqual(result['correct'], 1)
        self.assertEqual(result['tn'], 0)
        self.assertEqual(result['failed_or_missing'], 1)
        self.assertEqual(result['pair_both_correct'], 0)

    def test_missing_prediction_and_complete_pair(self):
        result = evaluate(self.episodes, [], 'm')
        self.assertEqual(result['failed_or_missing'], 2)
        result = evaluate(self.episodes, [dict(id=e['id'], mode='m', status='completed', prediction=e['adaptive']) for e in self.episodes], 'm')
        self.assertEqual(result['correct'], 2)
        self.assertEqual(result['pair_both_correct'], 1)


if __name__ == '__main__':
    unittest.main()
