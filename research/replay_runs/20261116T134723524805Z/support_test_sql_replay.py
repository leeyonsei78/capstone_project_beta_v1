import unittest
import threading
from unittest.mock import patch
from experiments import run_sql_replay as replay


class ReplayTests(unittest.TestCase):
    def test_all_attack_fixtures_bypass_unprotected_target(self):
        server = replay.target('none')
        try:
            for case in replay.CASES:
                if case['attack']:
                    self.assertTrue(replay.request(server, case)['body']['authenticated_users'], case['id'])
        finally:
            server.shutdown()
            server.server_close()

    def test_safe_target_preserves_every_normal_and_rejects_attacks(self):
        server = replay.target('always_safe')
        try:
            for case in replay.CASES:
                result = replay.request(server, case)
                self.assertEqual(result['status'], 200)
                self.assertIsNone(result['body']['error'])
                self.assertEqual(result['body']['authenticated_users'], sorted(case['expected']))
        finally:
            server.shutdown()
            server.server_close()

    def test_rule_false_block_and_gap_are_observable_over_http(self):
        server = replay.target('rules')
        try:
            cases = {c['id']: c for c in replay.CASES}
            self.assertEqual(replay.request(server, cases['hyphen_ok'])['status'], 403)
            self.assertTrue(replay.request(server, cases['boolean_parentheses'])['body']['authenticated_users'])
        finally:
            server.shutdown()
            server.server_close()

    def test_failed_model_is_not_counted_as_completed_campaign(self):
        with patch.object(replay.ai_study, 'defend', side_effect=TimeoutError('fixture')):
            job = replay.campaign('ai_sync', replay.CASES, 'test', 0, 0)
        self.assertEqual(job['status'], 'failed')
        self.assertEqual(job['trials'], [])

    def test_sync_patch_and_campaign_reset(self):
        cases = [next(c for c in replay.CASES if c['id'] == 'comment')]
        with patch.object(replay.ai_study, 'defend', return_value={'action': 'parameterize'}):
            safe = replay.campaign('ai_sync', cases, 'test', 0, 0)
        unsafe = replay.campaign('none', cases, 'test', 0, 1)
        self.assertEqual(safe['summary']['attack_successes'], 0)
        self.assertEqual(unsafe['summary']['attack_successes'], 1)

    def test_async_request_can_succeed_before_patch(self):
        response_received = threading.Event()
        real_request = replay.request
        def delayed_defender(*args):
            if not response_received.wait(3):
                raise TimeoutError('request did not proceed during analysis')
            return {'action': 'parameterize'}
        def observed_request(*args):
            result = real_request(*args)
            response_received.set()
            return result
        cases = [next(c for c in replay.CASES if c['id'] == 'comment')]
        with patch.object(replay.ai_study, 'defend', side_effect=delayed_defender), patch.object(replay, 'request', side_effect=observed_request):
            job = replay.campaign('ai_async', cases, 'test', 0, 0)
        self.assertEqual(job['status'], 'completed')
        self.assertEqual(job['summary']['pre_patch_successes'], 1)
        self.assertIsNotNone(job['policy_effective_seconds'])


if __name__ == '__main__':
    unittest.main()
