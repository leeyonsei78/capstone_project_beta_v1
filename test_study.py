import unittest
from experiments.run_study import Tracker, event


class BehaviorTests(unittest.TestCase):
    def test_requires_prior_evidence(self):
        tracker = Tracker(True)
        self.assertFalse(tracker.observe(event('a', 'p', 0, 'plain', True, 403)))
        self.assertTrue(tracker.observe(event('a', 'p', 1, 'url', True)))

    def test_normal_retries_are_not_adaptation(self):
        draft, causal = Tracker(), Tracker(True)
        for hour in range(3):
            e = event('a', 'p', hour, 'plain', False, 403)
            draft.observe(e)
            causal.observe(e)
        e = event('a', 'p', 3, 'plain')
        self.assertTrue(draft.observe(e))
        self.assertFalse(causal.observe(e))

    def test_twenty_four_hour_expiration(self):
        t = Tracker(True)
        t.observe(event('a', 'p', 0, 'plain', True, 403))
        self.assertFalse(t.observe(event('a', 'p', 25, 'url', True)))

    def test_session_history_survives_ip_change(self):
        ip, session = Tracker(True), Tracker(True, 'actor')
        e = event('a', 'p', 0, 'plain', True, 403)
        ip.observe(e)
        session.observe(e)
        changed = event('a', 'q', 1, 'url', True)
        self.assertFalse(ip.observe(changed))
        self.assertTrue(session.observe(changed))
