import unittest
from experiments import run_behavior_study as study


class BehaviorStudyTests(unittest.TestCase):
    def test_safe_server_and_controls(self):
        episode = study.scenarios()[0]
        trace = study.collect(episode)
        self.assertEqual(trace['observations'][0]['status'], 401)
        self.assertNotIn('<script>', trace['observations'][1]['response']['rendered'])
        self.assertEqual(trace['controls'][0]['response']['authenticated_users'], ['student'])

    def test_order_and_repeated_technique(self):
        sql = dict(path='/login', input=dict(username="admin' -- "), status=401)
        xss = dict(path='/search', input=dict(q='<script>void(0)</script>'), status=200)
        self.assertTrue(study.history_rule([sql, xss], True))
        self.assertFalse(study.history_rule([xss, sql], True))
        self.assertFalse(study.history_rule([sql, sql], True))
        self.assertFalse(study.history_rule([{**sql, 'status': 200}, xss], True))

    def test_normal_denial_is_not_suspicious_sql(self):
        typo = dict(path='/login', input=dict(username='student'), status=401)
        own = dict(path='/document', input=dict(id='1001'), status=200)
        self.assertFalse(study.history_rule([typo, own], True))

    def test_labels_and_metadata_never_enter_observations(self):
        row = dict(method='POST', path='/search', input={'q': 'course overview'}, status=200,
                   response={'rendered': 'course overview'}, http_ms=1, response_sha256='x')
        trace = dict(id='positive-test', adaptive=True, observations=[row])
        self.assertEqual(set(study.observable(trace)[0]), {'method', 'path', 'input', 'status', 'response'})
        self.assertEqual(study.observable(trace), study.observable({**trace, 'adaptive': False, 'id': 'negative'}))

    def test_dataset_pairs_balanced_and_final_inputs_identical(self):
        episodes = study.scenarios()
        self.assertEqual(len(episodes), 24)
        self.assertEqual(sum(e['adaptive'] for e in episodes), 12)
        for pair in {e['pair'] for e in episodes}:
            a, b = [e for e in episodes if e['pair'] == pair]
            self.assertNotEqual(a['adaptive'], b['adaptive'])
            self.assertEqual(a['requests'][-1], b['requests'][-1])

    def test_rule_strength_is_explicit(self):
        row = dict(path='/login', input=dict(username="' OR(1=1) OR name='"), status=401)
        self.assertIsNone(study.family(row, False))
        self.assertEqual(study.family(row, True), 'sql')


if __name__ == '__main__':
    unittest.main()
