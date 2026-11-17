"""Fixed SQL fixture replay. Local HTTP only; optional real Qwen defender."""
import argparse
import csv
import hashlib
import http.client
import json
import platform
import random
import re
import sqlite3
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ai_study

MODES = ('none', 'rules', 'always_safe', 'ai_sync', 'ai_async')
RULE = re.compile(r"--|/\*|\bor\b\s+['\d]", re.I)
USERS = [('student', 'practice123'), ('admin', 'lab-only-secret'),
         ("O'Reilly", 'fixture-pass'), ('team--blue', 'fixture-pass')]
# Deliberately constructed development fixtures, not held-out or natural traffic.
CASES = [
    dict(id='student_ok', username='student', password='practice123', attack=False, expected=['student']),
    dict(id='admin_ok', username='admin', password='lab-only-secret', attack=False, expected=['admin']),
    dict(id='apostrophe_ok', username="O'Reilly", password='fixture-pass', attack=False, expected=["O'Reilly"]),
    dict(id='hyphen_ok', username='team--blue', password='fixture-pass', attack=False, expected=['team--blue']),
    dict(id='wrong_password', username='student', password='wrong', attack=False, expected=[]),
    dict(id='missing_user', username='missing', password='wrong', attack=False, expected=[]),
    dict(id='comment', username="admin' -- ", password='wrong', attack=True, expected=[]),
    dict(id='boolean_comment', username="' OR 1=1 -- ", password='wrong', attack=True, expected=[]),
    dict(id='boolean_no_comment', username="' OR '1'='1' OR 'a'='b", password='wrong', attack=True, expected=[]),
    dict(id='boolean_parentheses', username="' OR(1=1) OR name='", password='wrong', attack=True, expected=[]),
]


def target(mode):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get('Content-Length', '0'))
            if self.path != '/login' or not 0 < length <= 4096:
                self.send_error(400)
                return
            data = json.loads(self.rfile.read(length))
            secure = self.server.secure
            blocked = mode == 'rules' and bool(RULE.search(data['username']))
            names, error = [], None
            if not blocked:
                with closing(sqlite3.connect(':memory:')) as db:
                    db.execute('CREATE TABLE users (name TEXT, password TEXT)')
                    db.executemany('INSERT INTO users VALUES (?, ?)', USERS)
                    try:
                        if secure:
                            rows = db.execute('SELECT name FROM users WHERE name=? AND password=?',
                                              (data['username'], data['password'])).fetchall()
                        else:
                            rows = db.execute("SELECT name FROM users WHERE name='" + data['username']
                                              + "' AND password='" + data['password'] + "'").fetchall()
                        names = sorted(row[0] for row in rows)
                    except sqlite3.Error as exc:
                        error = str(exc)
            body = json.dumps(dict(authenticated_users=names, error=error)).encode()
            self.send_response(403 if blocked else 200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('X-Lab-Defense-Active', str(int(secure)))
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.secure = mode == 'always_safe'
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def request(server, case):
    start = time.monotonic()
    conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
    try:
        conn.request('POST', '/login', json.dumps({k: case[k] for k in ('username', 'password')}),
                     {'Content-Type': 'application/json'})
        response = conn.getresponse()
        raw = response.read()
        return dict(status=response.status, body=json.loads(raw),
                    policy_active=response.getheader('X-Lab-Defense-Active') == '1',
                    http_ms=(time.monotonic() - start) * 1000,
                    response_sha256=hashlib.sha256(raw).hexdigest())
    finally:
        conn.close()


def campaign(mode, cases, model, gap, repeat):
    server = target(mode)
    start = time.monotonic()
    job = dict(id=f'{repeat}-{mode}', model=model, mode=mode, repeat=repeat,
               calls=[], events=[], trials=[], _start=start, status='running')
    history, pending = [], None
    pool = ThreadPoolExecutor(max_workers=1)
    job['policy_effective_seconds'] = 0.0 if mode == 'always_safe' else None

    def analyze(username, previous):
        decision = ai_study.defend(job, username, previous)
        elapsed = time.monotonic() - start
        job['events'].append(dict(seconds=elapsed, **decision))
        if decision['action'] == 'parameterize':
            server.secure = True
            job['policy_effective_seconds'] = elapsed

    try:
        for index, case in enumerate(cases):
            if pending is not None and pending.done():
                pending.result()
                pending = None
            decision_start = time.monotonic()
            # Both AI policies stop analysis after the permanent patch is applied.
            if not server.secure and mode == 'ai_sync':
                analyze(case['username'], list(history))
            elif not server.secure and mode == 'ai_async' and pending is None:
                pending = pool.submit(analyze, case['username'], list(history))
            result = request(server, case)
            row = dict(index=index, case=case['id'], attack=case['attack'],
                       username=case['username'], expected=case['expected'], **result,
                       decision_to_response_ms=(time.monotonic() - decision_start) * 1000,
                       response_seconds=time.monotonic() - start)
            row['attack_success'] = case['attack'] and bool(result['body']['authenticated_users'])
            row['normal_preserved'] = not case['attack'] and result['status'] == 200 and result['body']['error'] is None and result['body']['authenticated_users'] == sorted(case['expected'])
            job['trials'].append(row)
            history.append(dict(username=case['username'], http_status=result['status'], public_response=result['body']))
            if index + 1 < len(cases):
                time.sleep(gap)
        if pending is not None:
            pending.result()
        job['status'] = 'completed'
    except Exception as exc:
        job.update(status='failed', error=str(exc))
    finally:
        pool.shutdown(wait=True)
        job['wall_seconds'] = time.monotonic() - start
        server.shutdown()
        server.server_close()
    job.pop('_start')
    rows = job['trials']
    job['summary'] = dict(attack_requests=sum(r['attack'] for r in rows),
                         attack_successes=sum(r['attack_success'] for r in rows),
                         normal_requests=sum(not r['attack'] for r in rows),
                         normal_preserved=sum(r['normal_preserved'] for r in rows),
                         normal_rule_blocks=sum(not r['attack'] and r['status'] == 403 for r in rows),
                         pre_patch_successes=sum(r['attack_success'] and not r['policy_active'] for r in rows),
                         llm_calls=len(job['calls']))
    return job


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', default='qwen2.5-coder:14b')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--gap', type=float, default=0.5)
    parser.add_argument('--seed', type=int, default=20261116)
    parser.add_argument('--modes', nargs='+', choices=MODES, default=list(MODES))
    args = parser.parse_args()
    if not 1 <= args.repeats <= 30 or not 0 <= args.gap <= 10:
        parser.error('repeats must be 1..30 and gap 0..10 seconds')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'research' / 'replay_runs' / stamp
    out.mkdir(parents=True)
    rng = random.Random(args.seed)
    schedule = []
    for repeat in range(args.repeats):
        cases, modes = list(CASES), list(args.modes)
        rng.shuffle(cases)
        rng.shuffle(modes)
        schedule.append(dict(repeat=repeat, modes=modes, cases=[c['id'] for c in cases]))
    sources = ['experiments/run_sql_replay.py', 'ai_study.py']
    for name in sources:
        (out / name.replace('/', '_')).write_bytes((ROOT / name).read_bytes())
    manifest = dict(created_at=datetime.now(timezone.utc).isoformat(), config=vars(args),
                    scope='development fixture replay; real Qwen defender; no AI attacker; not independent held-out evaluation',
                    os=platform.platform(), python=sys.version, options=ai_study.OPTIONS,
                    schedule=schedule, cases=CASES, users=USERS,
                    source_sha256={n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in sources})
    if any(m.startswith('ai_') for m in args.modes):
        for endpoint in ('tags', 'version', 'ps'):
            with urllib.request.urlopen('http://127.0.0.1:11434/api/' + endpoint, timeout=5) as response:
                manifest['ollama_' + endpoint] = json.load(response)
        if args.model not in [m['name'] for m in manifest['ollama_tags']['models']]:
            parser.error('Requested model is not installed')
    dump(out / 'manifest.json', manifest)  # Saved before execution, after fixture development.
    print('Artifacts:', out, flush=True)
    jobs = []
    for block in schedule:
        cases = [next(c for c in CASES if c['id'] == ident) for ident in block['cases']]
        for mode in block['modes']:
            job = campaign(mode, cases, args.model, args.gap, block['repeat'])
            dump(out / (job['id'] + '.json'), job)
            jobs.append(job)
            dump(out / 'results.json', jobs)
            print(job['id'], job['status'], job['summary'], flush=True)
    rows = [dict(id=j['id'], mode=j['mode'], repeat=j['repeat'], status=j['status'],
                 policy_effective_seconds=j['policy_effective_seconds'], wall_seconds=j['wall_seconds'], **j['summary']) for j in jobs]
    with (out / 'summary.csv').open('w', newline='', encoding='utf-8-sig') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    if any(j['status'] != 'completed' for j in jobs):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
