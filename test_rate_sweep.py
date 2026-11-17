import time
import unittest
from experiments import run_rate_sweep as sweep
from experiments import run_sql_replay as replay


def slow_defender(latency):
    def defend(job, username, history):
        time.sleep(latency)
        return {'action': 'parameterize'}
    return defend


class RateSweepTests(unittest.TestCase):
    def cases(self, n=12):
        return [replay.CASES[6 + i % 4] for i in range(n)]  # all attacks

    def test_arrivals_follow_fixed_schedule_not_response_time(self):
        job = sweep.campaign('ai_async', self.cases(8), 't', 10, 0, defend=slow_defender(0.3))
        for row in job['trials']:
            self.assertLess(abs(row['sent_seconds'] - row['scheduled_seconds']), 0.08)

    def test_higher_rate_exposes_more_attacks_before_patch(self):
        low = sweep.campaign('ai_async', self.cases(), 't', 2, 0, defend=slow_defender(0.6))
        high = sweep.campaign('ai_async', self.cases(), 't', 10, 0, defend=slow_defender(0.6))
        self.assertGreater(high['summary']['attacks_before_patch'], low['summary']['attacks_before_patch'])
        self.assertEqual(high['summary']['attack_successes'], high['summary']['attacks_before_patch'])

    def test_sync_blocks_attack_until_patch(self):
        job = sweep.campaign('ai_sync', self.cases(6), 't', 10, 0, defend=slow_defender(0.2))
        self.assertEqual(job['summary']['attack_successes'], 0)

    def test_failed_model_marks_campaign_failed(self):
        def boom(*a):
            raise TimeoutError('x')
        job = sweep.campaign('ai_async', self.cases(5), 't', 10, 0, defend=boom)
        self.assertEqual(job['status'], 'failed')

    def test_exposure_model(self):
        self.assertEqual(sweep.exposure_model(5, 1.7, 0.4)['expected_requests_before_patch'], 9)


if __name__ == '__main__':
    unittest.main()
