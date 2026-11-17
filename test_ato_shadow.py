import unittest
import ato_shadow as sh


class ShadowTests(unittest.TestCase):
    def test_p_confirm_bounds(self):
        self.assertEqual(sh.p_confirm(0, 5), 0)
        self.assertEqual(sh.p_confirm(1, 5), 1)
        self.assertAlmostEqual(sh.p_confirm(0.5, 2), 0.75)
        with self.assertRaises(ValueError):
            sh.p_confirm(1.5, 3)

    def test_no_lure_means_full_takeover(self):
        a = sh.attacker_session(0, 6)
        self.assertEqual(a['real_takeover'], 1)
        self.assertEqual(a['real_actions'], 6)

    def test_always_touch_confirms_on_first_action(self):
        a = sh.attacker_session(1, 6)
        self.assertEqual(a['deflected'], 1)
        self.assertEqual(a['real_actions'], 1)   # first action is the touch; counted as 1 exposed step at most

    def test_evaluate_matches_lock_when_no_lure(self):
        camps = [dict(reached_session=True)] * 3 + [dict(reached_session=False)] * 9
        e = sh.evaluate(camps, 10, 0, 0.05, 6)
        self.assertEqual(e['real_takeover_rate_shadow'], e['real_takeover_rate_lock'])
        self.assertEqual(e['deflected_rate_shadow'], 0)

    def test_benign_trap_grows_with_q(self):
        lo = sh.benign_session(0.01, 6)['friction']
        hi = sh.benign_session(0.1, 6)['friction']
        self.assertLess(lo, hi)


if __name__ == '__main__':
    unittest.main()
