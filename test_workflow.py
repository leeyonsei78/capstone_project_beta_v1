import unittest
import workflow
from workflow import STATE, route, start_target, validate_target


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_target = workflow.TARGET
        cls.server = start_target(0)
        workflow.TARGET = 'http://127.0.0.1:' + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        workflow.TARGET = cls.old_target

    def test_http_attack_defend_and_retest(self):
        route('/api/workflow/reset', {})
        before = route('/api/workflow/scan', {'target': '127.0.0.1'})
        self.assertEqual(sum(f['vulnerable'] for f in before['findings']), 3)
        after = route('/api/workflow/quick-apply', {'scan_id': before['id']})['report']
        self.assertFalse(any(f['vulnerable'] for f in after['findings']))
        rescan = route('/api/workflow/scan', {'target': workflow.TARGET})
        repeated = route('/api/workflow/quick-apply', {'scan_id': rescan['id']})['report']
        self.assertFalse(any(f['vulnerable'] for f in repeated['findings']))
        route('/api/workflow/reset', {})

    def test_no_external_targets(self):
        for url in ['http://example.com', 'http://127.0.0.1:11434', 'http://127.0.0.1:8766@evil.com', 'http://127.0.0.1:8766/redirect']:
            with self.assertRaises(ValueError):
                validate_target(url)

    def test_apply_requires_real_plan(self):
        route('/api/workflow/reset', {})
        with self.assertRaises(ValueError):
            route('/api/workflow/apply', {'plan_id': 'fake'})
