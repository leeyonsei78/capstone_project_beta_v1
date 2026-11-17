import unittest
import threading
import time
import uuid
from unittest.mock import patch
import ai_study
from ai_study import make_target, request


class TargetTests(unittest.TestCase):
    def run_fixture(self, mode):
        job = {'id': str(uuid.uuid4()), '_start': time.monotonic(), 'model': 'fixture-no-model-call', 'mode': mode, 'rounds': 2, 'events': [], 'calls': [], 'trials': []}
        with patch.object(ai_study, 'attack', return_value={'payload': "admin' -- "}), patch.object(ai_study, 'defend', return_value={'action': 'parameterize'}), patch.object(ai_study, 'ARTIFACTS') as folder:
            ai_study.run(job)
        return job

    def test_sync_fixture_really_changes_next_http_execution(self):
        job = self.run_fixture('ai_sync')
        self.assertEqual(job['status'], 'completed')
        self.assertEqual(job['summary']['authentication_bypasses'], 0)
        self.assertEqual(job['summary']['negative_auth_controls_rejected'], 2)
        self.assertTrue(all(t['policy_active_at_server'] for t in job['trials']))

    def test_none_fixture_does_not_silently_apply_defense(self):
        job = self.run_fixture('none')
        self.assertEqual(job['summary']['authentication_bypasses'], 2)
        self.assertIsNone(job['summary']['policy_effective_seconds'])

    def test_model_failure_is_not_reported_as_success(self):
        job = {'id': str(uuid.uuid4()), '_start': time.monotonic(), 'mode': 'none', 'rounds': 1, 'events': [], 'calls': [], 'trials': []}
        with patch.object(ai_study, 'attack', side_effect=TimeoutError('fixture timeout')), patch.object(ai_study, 'ARTIFACTS'):
            ai_study.run(job)
        self.assertEqual(job['status'], 'failed')
        self.assertNotIn('summary', job)
        self.assertEqual(job['trials'], [])

    def test_isolation_and_patch(self):
        a, b = make_target(), make_target()
        try:
            self.assertTrue(request(a, "admin' -- ")['success'])
            a.secure = True
            self.assertFalse(request(a, "admin' -- ")['success'])
            self.assertTrue(request(b, "admin' -- ")['success'])
            self.assertFalse(request(a, 'student')['success'])
        finally:
            for server in [a, b]:
                server.shutdown()
                server.server_close()

    def test_rules_block_without_faking_ai(self):
        server = make_target()
        try:
            result = request(server, "admin' -- ", rule=True)
            self.assertEqual(result['status'], 403)
            self.assertFalse(result['success'])
        finally:
            server.shutdown()
            server.server_close()
