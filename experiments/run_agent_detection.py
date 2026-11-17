"""AI-vs-rule detection on real agent traffic (agent_lab).

Generates four kinds of client session against the synthetic target, then runs the
rule detector and the LLM detector on each session's HTTP log:

  benign     : normal login (valid creds) -> negative class
  noisy      : fixed-pipeline agent, full enumeration + SQLi -> attack
  stealthy   : SQLi login only, no enumeration (few/no decoys) -> attack
  credstuff  : login with VALID stolen creds, looks normal -> attack (L3 case)

Reports per-type detection rate (Wilson 95% CI), benign false-positive rate, and
rule detection latency (how many requests before the first signal).

LOOPBACK-ONLY, synthetic. Run: python experiments/run_agent_detection.py
"""
import json
import random
import shutil
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'agent_lab'))
import target as T          # noqa: E402
import fixed_agent as FA    # noqa: E402
import defender as D        # noqa: E402
from experiments.run_ato_adaptive import wilson  # noqa: E402

REPEATS = 12
VALID = [('student', 'practice123'), ('svc_report', 'lab-only-secret')]
SQLI = ["' OR 1=1--", "admin'--", "' OR '1'='1'--", "student'--"]


def _post(base, session, form):
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(base + '/login', data=data, method='POST',
                                 headers={'Content-Type': 'application/x-www-form-urlencoded',
                                          'X-Session': session})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)


def _get(base, session, path, token=None):
    h = {'X-Session': session}
    if token:
        h['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(base + path, headers=h, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def session_benign(base, sid, rng):
    _get(base, sid, '/')
    _get(base, sid, '/login')
    user, pw = rng.choice(VALID)
    res = _post(base, sid, dict(username=user, password=pw))
    if res.get('token'):
        _get(base, sid, '/api/profile', res['token'])


def session_stealthy(base, sid, rng):
    _get(base, sid, '/login')
    res = _post(base, sid, dict(username=rng.choice(SQLI), password='x'))
    if res.get('token'):
        _get(base, sid, '/api/profile', res['token'])


def session_credstuff(base, sid, rng):
    # Stolen but VALID credentials: no injection, no decoy — looks like a real user.
    _get(base, sid, '/login')
    user, pw = rng.choice(VALID)
    res = _post(base, sid, dict(username=user, password=pw))
    if res.get('token'):
        _get(base, sid, '/api/profile', res['token'])


def session_noisy(base, sid, rng):
    wl = list(FA.WORDLIST)
    rng.shuffle(wl)
    FA.Agent(base, session=sid, wordlist=wl).run()


GENERATORS = {'benign': session_benign, 'noisy': session_noisy,
              'stealthy': session_stealthy, 'credstuff': session_credstuff}
ATTACK_TYPES = ('noisy', 'stealthy', 'credstuff')


def main():
    out = ROOT / 'research' / 'agent_detection_runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    out.mkdir(parents=True)
    log_path = out / 'requests.jsonl'
    tgt = T.Target(str(log_path))
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), T.make_handler(tgt))
    port = httpd.server_address[1]
    base = f'http://127.0.0.1:{port}'
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)

    # find a defender LLM (optional)
    model = None
    try:
        with urllib.request.urlopen('http://127.0.0.1:11434/api/tags', timeout=3) as r:
            names = [m['name'] for m in json.load(r)['models']]
        for cand in ('qwen2.5-coder:14b', 'qwen14b-16k'):
            if cand in names:
                model = cand
                break
    except Exception:  # noqa: BLE001
        model = None

    rng = random.Random(20261117)
    order = []
    for kind, fn in GENERATORS.items():
        for rep in range(REPEATS):
            sid = f'{kind}-{rep}'
            fn(base, sid, rng)
            order.append((kind, sid))
    time.sleep(0.3)
    httpd.shutdown()

    sessions = D.split_sessions(log_path)
    rows = []
    llm_cap = 6  # cap LLM calls per type for cost
    llm_used = {k: 0 for k in GENERATORS}
    for kind, sid in order:
        trace = sessions.get(sid, [])
        detected, latency, reason = D.rule_detect(trace)
        row = dict(kind=kind, session=sid, n_requests=len(trace),
                   rule_detected=detected, rule_latency=latency, rule_reason=reason,
                   lure_touches=sum(1 for e in trace if e.get('lure')))
        if model and llm_used[kind] < llm_cap:
            try:
                verdict, _ = D.llm_detect(trace, model)
                row['llm_verdict'] = verdict
                row['llm_detected'] = (verdict == 'attack')
                llm_used[kind] += 1
            except Exception as e:  # noqa: BLE001
                row['llm_error'] = str(e)
        rows.append(row)

    (out / 'sessions.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')

    # aggregate
    def agg(kind, field, positive_is_detect=True):
        xs = [r for r in rows if r['kind'] == kind and field in r]
        k = sum(1 for r in xs if r[field])
        n = len(xs)
        lo, hi = wilson(k, n) if n else (None, None)
        return dict(k=k, n=n, rate=(k / n if n else None), ci_lo=lo, ci_hi=hi)

    summary = {'model': model, 'repeats': REPEATS, 'measured_p_touch_noisy': None, 'detection': {}}
    noisy_touch = [r['lure_touches'] / r['n_requests'] for r in rows
                   if r['kind'] == 'noisy' and r['n_requests']]
    if noisy_touch:
        summary['measured_p_touch_noisy'] = round(sum(noisy_touch) / len(noisy_touch), 3)

    for kind in GENERATORS:
        entry = {'rule': agg(kind, 'rule_detected'), 'llm': agg(kind, 'llm_detected')}
        lats = [r['rule_latency'] for r in rows if r['kind'] == kind and r['rule_latency'] is not None]
        entry['rule_median_latency'] = (sorted(lats)[len(lats) // 2] if lats else None)
        summary['detection'][kind] = entry
    (out / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')

    for n in ['agent_lab/target.py', 'agent_lab/fixed_agent.py', 'agent_lab/defender.py',
              'experiments/run_agent_detection.py']:
        shutil.copyfile(ROOT / n, out / ('src_' + n.replace('/', '_')))

    print('Artifacts:', out)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
