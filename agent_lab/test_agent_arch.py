"""Tests for the §6.15 agent-architecture + knowledge comparison. Stdlib + networkx.
No Ollama calls (ReAct mechanics tested via the action executor and a scripted brain).

Run:  python agent_lab/test_agent_arch.py
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import multi_target as MT   # noqa: E402
import fixed_agent as FA    # noqa: E402
import react_agent as RA    # noqa: E402
import knowledge as K       # noqa: E402


def _token(obs):
    return obs.split('-> token ', 1)[1].strip() if '-> token ' in obs else None


class MultiTargetTests(unittest.TestCase):
    def setUp(self):
        self.store, self.bases, self.shutdown = MT.launch()

    def tearDown(self):
        self.shutdown()

    def test_web_sqli_works_profile_leaks_pivot(self):
        a = RA.ReactAgent(self.bases, K.FlatKnowledge(), RA.scripted_brain([]), session='s1')
        o, _ = a._execute({'action': 'sqli_login', 'host': 'web', 'payload': "' OR 1=1--"})
        tok = _token(o)
        self.assertIsNotNone(tok)
        o2, _ = a._execute({'action': 'authed_get', 'host': 'web', 'path': '/api/profile', 'token': tok})
        self.assertIn('internal_service', o2)

    def test_internal_not_injectable_but_pivot_cred_works(self):
        a = RA.ReactAgent(self.bases, K.FlatKnowledge(), RA.scripted_brain([]), session='s2')
        # SQLi on internal must NOT authenticate
        o, _ = a._execute({'action': 'sqli_login', 'host': 'internal', 'payload': "' OR 1=1--"})
        self.assertIsNone(_token(o))
        # the real pivot credential works
        o2, _ = a._execute({'action': 'login', 'host': 'internal',
                            'username': MT.PIVOT_USER, 'password': MT.PIVOT_PW})
        self.assertIsNotNone(_token(o2))


class KnowledgeTests(unittest.TestCase):
    def test_flat_lists_facts(self):
        k = K.FlatKnowledge()
        k.update(dict(type='cred', user='u', password='p', for_host='internal'))
        self.assertIn('internal', k.render())

    def test_graph_surfaces_pivot_then_goal_done(self):
        k = K.GraphKnowledge(goal_host='internal')
        k.update(dict(type='cred', user='svc', password='pw', for_host='internal'))
        self.assertTrue(k.pivots())                      # reachable-but-unowned asset
        self.assertIn('PIVOT AVAILABLE', k.render())
        k.update(dict(type='token', host='internal', token='t'))   # now owned
        self.assertFalse(k.pivots())
        k.update(dict(type='jewel', host='internal'))
        self.assertEqual(k.tasks.nodes['goal']['status'], 'done')


class ReactMechanicsTests(unittest.TestCase):
    def setUp(self):
        self.store, self.bases, self.shutdown = MT.launch()

    def tearDown(self):
        self.shutdown()

    def test_full_pivot_via_executor_and_graph(self):
        k = K.GraphKnowledge(goal_host='internal')
        a = RA.ReactAgent(self.bases, k, RA.scripted_brain([]), session='p1')
        o, _ = a._execute({'action': 'sqli_login', 'host': 'web', 'payload': "' OR 1=1--"})
        self.assertEqual(a.stage, 'web_token')
        a._execute({'action': 'authed_get', 'host': 'web', 'path': '/api/profile', 'token': _token(o)})
        self.assertEqual(a.stage, 'pivot_cred')
        piv = k.pivots()
        self.assertTrue(piv)
        host, user, pw = piv[0]
        o2, _ = a._execute({'action': 'login', 'host': host, 'username': user, 'password': pw})
        self.assertEqual(a.stage, 'internal_token')
        o3, done = a._execute({'action': 'authed_get', 'host': 'internal', 'path': '/api/vault', 'token': _token(o2)})
        self.assertTrue(done)
        self.assertEqual(a.stage, 'jewel_B')

    def test_allowlist_blocks_off_host(self):
        with self.assertRaises(PermissionError):
            RA.ReactAgent({'web': 'http://8.8.8.8', 'internal': 'http://127.0.0.1:1'},
                          K.FlatKnowledge(), RA.scripted_brain([]))


class FixedPivotTests(unittest.TestCase):
    def setUp(self):
        self.store, self.bases, self.shutdown = MT.launch()

    def tearDown(self):
        self.shutdown()

    def test_fixed_pipeline_completes_pivot(self):
        res = FA.PivotAgent(self.bases, session='f1').run()
        self.assertTrue(res['takeover'])
        self.assertEqual(res['stage'], 'jewel_B')
        self.assertEqual(res['architecture'], 'fixed')


if __name__ == '__main__':
    unittest.main()
