import unittest

import ato_fixtures as fx
import ato_stateful as st


def prof(home='KR', hours=(8, 22)):
    return dict(home_geo=home, usual_hours=list(hours), known_devices=1)


class Rules3Tests(unittest.TestCase):
    def test_shared_ip_known_device_not_locked(self):
        # office CGNAT benign: known device, home geo, high ip, cred ok -> not lock
        e = fx.ev(ipacc=28, hour=10)
        self.assertEqual(fx.rules2(e, prof()), 'lock')      # old rule over-locks
        self.assertEqual(st.rules3(e, prof()), 'allow')     # corrected

    def test_vpn_known_device_abroad_challenge_not_lock(self):
        e = fx.ev(geo='NL', ipacc=6, hour=11)               # known device, geo mismatch
        self.assertEqual(st.rules3(e, prof(home='US', hours=(8, 20))), 'challenge')

    def test_cred_stuffing_still_locked(self):
        e = fx.ev(ok=True, geo='RU', dev=False, hour=4, ipacc=74)
        self.assertEqual(st.rules3(e, prof()), 'lock')

    def test_high_fail_locked(self):
        self.assertEqual(st.rules3(fx.ev(ok=False, fails=5), prof()), 'lock')

    def test_moderate_fail_not_locked(self):
        # 3-4 fails on a known home device is a human fumble, not a lock (rules2 locks at 3)
        e = fx.ev(ok=False, fails=3, hour=12)
        self.assertEqual(fx.rules2(e, prof()), 'lock')
        self.assertEqual(st.rules3(e, prof()), 'allow')


class StatefulTests(unittest.TestCase):
    def test_sequence_catches_known_device_impossible_travel(self):
        # a KNOWN-device event that single-event rules3 would allow, but the episode
        # shows impossible travel -> stateful escalates to at least challenge
        events = [fx.ev(hour=9), dict(fx.ev(hour=9), impossible_travel=True)]
        self.assertEqual(st.rules3(events[1], prof()), 'allow')      # stateless allows
        self.assertEqual(st.rules_stateful(events, prof())[1], 'challenge')

    def test_geo_jump_escalates(self):
        events = [fx.ev(geo='KR', hour=9), fx.ev(geo='CN', dev=True, hour=9)]
        # second event alone (geo mismatch) is already challenge; ensure not downgraded
        self.assertIn(st.rules_stateful(events, prof())[1], ('challenge', 'lock'))

    def test_benign_multi_event_stays_clean(self):
        # typos then success on a known home device -> no lock across the episode
        events = [fx.ev(ok=False, fails=1, hour=20), fx.ev(ok=False, fails=2, hour=20), fx.ev(hour=20)]
        acts = st.rules_stateful(events, prof())
        self.assertNotIn('lock', acts)


class ScoringTests(unittest.TestCase):
    def test_case_level_counts(self):
        benign = fx.case('b', 'benign', 'r', [fx.ev()], ('allow', 'challenge'))
        attack = fx.case('a', 'attack', 's', [fx.ev(geo='RU', dev=False, ipacc=50)], ('challenge', 'lock'))
        s, rows = st.score_case_level([benign, attack], st.stateless(st.rules3))
        self.assertEqual(s['benign_clean'], 1)
        self.assertEqual(s['attack_caught'], 1)
        self.assertEqual(len(rows), 2)

    def test_per_event_friction_only_benign(self):
        attack = fx.case('a', 'attack', 's', [fx.ev(geo='RU', dev=False, ipacc=50)], ('challenge', 'lock'))
        s = st.score_per_event([attack], st.rules3)
        self.assertEqual(s['benign_friction'], 0)
        self.assertEqual(s['attack_misses'], 0)

    def test_rules3_cuts_holdout_friction_vs_rules2(self):
        import ato_holdout
        cases = ato_holdout.load_holdout()
        f2 = st.score_per_event(cases, fx.rules2)['benign_friction']
        f3 = st.score_per_event(cases, st.rules3)['benign_friction']
        self.assertLess(f3, f2)   # corrected rule has strictly lower benign friction


if __name__ == '__main__':
    unittest.main()
