import unittest
from app import lab


class LabTests(unittest.TestCase):
    def test_sql_bypass_and_defense(self):
        self.assertTrue(lab(dict(scenario='sql', payload="admin' -- ", secure=False))['success'])
        self.assertFalse(lab(dict(scenario='sql', payload="admin' -- ", secure=True))['success'])
        self.assertFalse(lab(dict(scenario='sql', payload='admin'))['success'])

    def test_xss_encoding(self):
        payload = '<img src=x onerror=alert(1)>'
        self.assertEqual(lab(dict(scenario='xss', payload=payload))['preview'], payload)
        self.assertNotIn('<', lab(dict(scenario='xss', payload=payload, secure=True))['preview'])

    def test_ownership(self):
        self.assertTrue(lab(dict(scenario='idor', payload='1002'))['success'])
        result = lab(dict(scenario='idor', payload='1002', secure=True))
        self.assertFalse(result['success'])
        self.assertNotIsInstance(result['detail'], dict)
        self.assertEqual(lab(dict(scenario='idor', payload='1001', secure=True))['detail']['owner'], 'student')


if __name__ == '__main__':
    unittest.main()
