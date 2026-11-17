import unittest

import ato_fixtures as fx
import ato_holdout as ho
from experiments import run_ato_holdout as run


def allow_defender(*a, **k):
    return {'action': 'allow'}


class LoaderTests(unittest.TestCase):
    def test_norm_event_fills_missing_keys_and_keeps_given(self):
        e, filled = ho._norm_event({'event_type': 'login', 'geo': 'RU', 'local_hour': 4})
        self.assertEqual(e['geo'], 'RU')          # author value kept
        self.assertEqual(e['local_hour'], 4)
        self.assertIn('user_agent', e)            # missing key filled
        self.assertIn('user_agent', filled)
        self.assertEqual(set(e), set(ho.EVENT_KEYS))

    def test_norm_event_rejects_bad_type(self):
        with self.assertRaises(ValueError):
            ho._norm_event({'event_type': 'logout'})

    def test_norm_case_validates_label_and_allowed(self):
        good = dict(id='x', label='attack', events=[{'event_type': 'login'}], allowed=['challenge', 'lock'])
        c = ho._norm_case(good)
        self.assertEqual(c['allowed'], ['challenge', 'lock'])
        with self.assertRaises(ValueError):
            ho._norm_case(dict(good, label='maybe'))
        with self.assertRaises(ValueError):
            ho._norm_case(dict(good, allowed=['permit']))
        with self.assertRaises(ValueError):
            ho._norm_case(dict(good, events=[]))

    def test_real_holdout_file_loads(self):
        cases = ho.load_holdout()
        self.assertGreaterEqual(len(cases), 20)
        labels = {c['label'] for c in cases}
        self.assertEqual(labels, {'benign', 'attack'})
        for c in cases:
            self.assertTrue(c['events'])
            for e in c['events']:
                self.assertEqual(set(e), set(ho.EVENT_KEYS))  # every field present for rules/llm
            self.assertTrue(set(c['allowed']) <= set(fx.ACTIONS))
        self.assertEqual(len({c['id'] for c in cases}), len(cases))  # unique ids


class ScoreTests(unittest.TestCase):
    def test_score_rules_on_known_cases(self):
        # one obvious benign (known device, home geo, day) and one obvious attack (ipacc huge)
        benign = fx.case('b', 'benign', 'r', [fx.ev()], ('allow', 'challenge'))
        attack = fx.case('a', 'attack', 's', [fx.ev(geo='RU', dev=False, ipacc=50)], ('challenge', 'lock'))
        s, rows = run.score('t', [benign, attack], 'rules', allow_defender, {})
        self.assertEqual(s['events'], 2)
        self.assertEqual(s['benign_events'], 1)
        self.assertEqual(s['attack_events'], 1)
        self.assertEqual(s['attack_misses'], 0)      # rules lock the stuffing case
        self.assertEqual(len(rows), 2)

    def test_llm_mode_uses_injected_defender(self):
        attack = fx.case('a', 'attack', 's', [fx.ev(geo='RU', dev=False, ipacc=50)], ('challenge', 'lock'))
        s, _ = run.score('t', [attack], 'llm', allow_defender, {'model': 'm', 'calls': [], 'events': []})
        self.assertEqual(s['attack_misses'], 1)      # the stub always allows -> missed
        self.assertEqual(s['accuracy'], 0.0)

    def test_friction_counts_only_benign(self):
        attack = fx.case('a', 'attack', 's', [fx.ev(geo='RU', dev=False, ipacc=50)], ('challenge', 'lock'))
        s, _ = run.score('t', [attack], 'rules', allow_defender, {})
        self.assertEqual(s['benign_friction'], 0)    # no benign events

    def test_wilson_matches_adaptive(self):
        self.assertEqual(run.wilson(0, 0), (0.0, 1.0))
        lo, hi = run.wilson(10, 10)
        self.assertGreater(lo, 0.6)
        self.assertEqual(hi, 1.0)


if __name__ == '__main__':
    unittest.main()
