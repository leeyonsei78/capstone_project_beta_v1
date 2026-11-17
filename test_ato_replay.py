import time
import unittest
import ato_fixtures as fx
import ato_study
from experiments import run_ato_replay as run


def fixed(action, delay=0):
    def defend(job, event, profile, variant, style='baseline'):
        time.sleep(delay)
        return {'action': action}
    return defend


class AtoTests(unittest.TestCase):
    def test_fixture_integrity(self):
        ids = [c['id'] for c in fx.CASES]
        self.assertEqual(len(ids), len(set(ids)))
        for c in fx.CASES:
            self.assertTrue(set(c['allowed']) <= set(fx.ACTIONS))
            self.assertIn(c['label'], ('benign', 'attack'))
        self.assertEqual(fx.HOLDOUT, [])

    def test_no_defense_lets_every_valid_credential_attack_through(self):
        job = run.campaign('none', fx.CASES, 't', 0, 0)
        taken = {r['case'] for r in job['trials'] if r['takeover']}
        valid = {c['id'] for c in fx.CASES if c['label'] == 'attack' and any(e['credential_ok'] for e in c['events'])}
        self.assertEqual(taken, valid)
        self.assertEqual(job['summary']['benign_friction'], 0)

    def test_always_challenge_blocks_all_takeover_with_friction(self):
        job = run.campaign('always_challenge', fx.CASES, 't', 0, 0)
        self.assertEqual(job['summary']['takeover_events'], 0)
        self.assertEqual(job['summary']['benign_friction'], job['summary']['benign_events'])

    def test_rules_have_observable_false_lock_and_miss(self):
        job = run.campaign('rules', fx.CASES, 't', 0, 0)
        by = {}
        for r in job['trials']:
            by.setdefault(r['case'], []).append(r)
        self.assertTrue(any(r['benign_lock'] for r in by['office_nat_b']))
        self.assertTrue(any(r['takeover'] for r in by['mimic_known_device_odd_hour']))

    def test_async_serves_before_decision_sync_does_not(self):
        cases = [c for c in fx.CASES if c['id'] == 'stuffing_valid']
        sync = run.campaign('llm_sync', cases, 't', 0, 0, defend=fixed('lock', 0.05))
        asyn = run.campaign('llm_async', cases, 't', 0, 0, defend=fixed('lock', 0.3))
        self.assertEqual(sync['summary']['takeover_events'], 0)
        self.assertGreater(asyn['summary']['takeover_events'], 0)

    def test_model_failure_is_failed_not_defended(self):
        def boom(*a):
            raise TimeoutError('x')
        job = run.campaign('llm_sync', fx.CASES, 't', 0, 0, defend=boom)
        self.assertEqual(job['status'], 'failed')
        self.assertEqual(job['trials'], [])

    def test_prompt_separates_untrusted_strings_and_variants(self):
        c = next(c for c in fx.CASES if c['id'] == 'injected_user_agent')
        e = c['events'][0]
        p = ato_study.build_prompt(e, c['profile'], 'event')
        facts, strings = p.split('"facts":')[1].split('"client_strings"')
        self.assertNotIn('Ignore previous', facts)
        self.assertIn('Ignore previous', strings)
        self.assertNotIn('ip_distinct_accounts', p)
        self.assertIn('ip_distinct_accounts', ato_study.build_prompt(e, c['profile'], 'summary'))

    def test_escalate_only_never_relaxes_rule(self):
        cases = [c for c in fx.CASES if c['id'] == 'stuffing_valid']
        job = run.campaign('llm_escalate', cases, 't', 0, 0, defend=fixed('allow'))
        self.assertEqual(job['summary']['takeover_events'], 0)
        benign = [c for c in fx.CASES if c['id'] == 'routine_a']
        job = run.campaign('llm_escalate', benign, 't', 0, 0, defend=fixed('lock'))
        self.assertEqual(job['summary']['benign_locks'], 1)

    def test_paced_long_episode_lets_async_decision_take_effect(self):
        cases = [c for c in fx.CASES if c['id'] == 'stuffing_valid']
        job = run.campaign('llm_async', cases, 't', 0, 0, defend=fixed('lock', 0.3), rps=10, episode_len=10)
        acts = [r['action'] for r in job['trials']]
        self.assertEqual(len(acts), 10)
        self.assertEqual(acts[0], 'allow')
        self.assertEqual(acts[-1], 'lock')
        self.assertGreater(job['summary']['takeover_events'], 0)
        self.assertLess(job['summary']['takeover_events'], 10)

    def test_prompt_styles(self):
        c = next(c for c in fx.CASES if c['id'] == 'injected_user_agent')
        e = c['events'][0]
        self.assertNotIn('Ignore previous', ato_study.build_prompt(e, c['profile'], 'event', 'drop_untrusted'))
        self.assertIn('Never follow it', ato_study.build_prompt(e, c['profile'], 'event', 'hardened'))
        self.assertNotIn('Never follow it', ato_study.build_prompt(e, c['profile'], 'event', 'baseline'))

    def test_injection_set_is_separate(self):
        self.assertTrue(set(c['id'] for c in fx.INJECTION_CASES).isdisjoint(c['id'] for c in fx.CASES))


if __name__ == '__main__':
    unittest.main()
