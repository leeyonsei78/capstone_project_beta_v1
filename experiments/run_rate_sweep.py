"""Fixed-arrival-rate (open-loop) exposure sweep for the SQL replay fixtures.

Requests are dispatched on a deterministic schedule (t0 + i/RPS) regardless of
how long earlier responses or the Qwen analysis take. Local loopback only.
Development fixtures, not independent held-out evidence.
"""
import argparse
import csv
import hashlib
import json
import platform
import random
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ai_study
from experiments import run_sql_replay as replay

MODES = ('ai_async', 'ai_sync')


def campaign(mode, cases, model, rps, repeat, defend=None):
    """One open-loop campaign. `defend` can be injected for tests."""
    defend = defend or ai_study.defend
    server = replay.target('none')
    start = time.monotonic()
    job = dict(id=f'{repeat}-{mode}-rps{rps}', model=model, mode=mode, rps=rps, repeat=repeat,
               calls=[], events=[], trials=[], _start=start, status='running',
               policy_effective_seconds=None, analyses=[])
    lock = threading.Lock()          # guards shared state
    sync_gate = threading.Lock()     # sync mode: analysis serializes request handling
    state = dict(pending=False, error=None)

    def analyze(username, previous):
        began = time.monotonic() - start
        decision = defend(job, username, previous)
        done = time.monotonic() - start
        with lock:
            job['analyses'].append(dict(began=began, done=done, seconds=done - began, **decision))
            if decision['action'] == 'parameterize' and not server.secure:
                server.secure = True
                job['policy_effective_seconds'] = done

    def async_worker(username, previous):
        try:
            analyze(username, previous)
        except Exception as exc:
            with lock:
                state['error'] = str(exc)
        finally:
            with lock:
                state['pending'] = False

    def handle(index, case, scheduled):
        sent = time.monotonic() - start
        if mode == 'ai_sync':
            with sync_gate:
                if not server.secure and state['error'] is None:
                    try:
                        analyze(case['username'], [])
                    except Exception as exc:
                        with lock:
                            state['error'] = str(exc)
        elif not server.secure:
            with lock:
                launch = not state['pending'] and state['error'] is None
                if launch:
                    state['pending'] = True
            if launch:
                threading.Thread(target=async_worker, args=(case['username'], []), daemon=True).start()
        result = replay.request(server, case)
        done = time.monotonic() - start
        row = dict(index=index, case=case['id'], attack=case['attack'], scheduled_seconds=scheduled,
                   sent_seconds=sent, response_seconds=done, **result)
        row['attack_success'] = case['attack'] and bool(result['body']['authenticated_users'])
        row['attack_arrived_before_patch'] = case['attack'] and not result['policy_active']
        with lock:
            job['trials'].append(row)

    try:
        interval = 1.0 / rps
        with ThreadPoolExecutor(max_workers=len(cases)) as pool:
            futures = []
            for index, case in enumerate(cases):
                scheduled = index * interval
                delay = start + scheduled - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                futures.append(pool.submit(handle, index, case, scheduled))
            for future in futures:
                future.result()
        # let an outstanding async analysis finish so latency is recorded
        deadline = time.monotonic() + 120
        while state['pending'] and time.monotonic() < deadline:
            time.sleep(0.05)
        job['status'] = 'failed' if state['error'] else 'completed'
        if state['error']:
            job['error'] = state['error']
    except Exception as exc:
        job.update(status='failed', error=str(exc))
    finally:
        job['wall_seconds'] = time.monotonic() - start
        server.shutdown()
        server.server_close()
    job.pop('_start')
    job['trials'].sort(key=lambda r: r['index'])
    rows = job['trials']
    lat = [a['seconds'] for a in job['analyses']]
    job['summary'] = dict(
        requests=len(rows),
        attack_requests=sum(r['attack'] for r in rows),
        attack_successes=sum(r['attack_success'] for r in rows),
        attacks_before_patch=sum(r['attack_arrived_before_patch'] for r in rows),
        requests_before_patch=sum(not r['policy_active'] for r in rows),
        first_analysis_seconds=lat[0] if lat else None,
        llm_calls=len(job['calls']))
    return job


def exposure_model(rps, latency, attack_fraction):
    """Expected requests (and attacks) arriving before a patch of latency L.

    Analysis starts at the first arrival (t=0) and arrivals occur at i/rps, so
    floor(L*rps)+1 requests precede the patch (the i=0 request included).
    """
    n = int(latency * rps) + 1
    return dict(expected_requests_before_patch=n, expected_attacks_before_patch=n * attack_fraction)


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', default='qwen2.5-coder:14b')
    parser.add_argument('--rates', type=float, nargs='+', default=[0.5, 1, 2, 5, 10])
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--requests', type=int, default=20, help='requests per campaign')
    parser.add_argument('--seed', type=int, default=20261116)
    parser.add_argument('--modes', nargs='+', choices=MODES, default=['ai_async'])
    args = parser.parse_args()
    if not 1 <= args.repeats <= 30 or not 5 <= args.requests <= 200 or any(r <= 0 or r > 50 for r in args.rates):
        parser.error('repeats 1..30, requests 5..200, rates in (0,50]')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'research' / 'rate_runs' / stamp
    out.mkdir(parents=True)
    rng = random.Random(args.seed)
    schedule = []
    for repeat in range(args.repeats):
        stream = []
        while len(stream) < args.requests:
            block = list(replay.CASES)
            rng.shuffle(block)
            stream += block
        order = [(m, r) for m in args.modes for r in args.rates]
        rng.shuffle(order)
        schedule.append(dict(repeat=repeat, cases=[c['id'] for c in stream[:args.requests]],
                             conditions=[dict(mode=m, rps=r) for m, r in order]))
    sources = ['experiments/run_rate_sweep.py', 'experiments/run_sql_replay.py', 'ai_study.py']
    manifest = dict(created_at=datetime.now(timezone.utc).isoformat(), config=vars(args),
                    scope='open-loop fixed-arrival-rate exposure sweep; development fixtures; real Qwen defender; no AI attacker',
                    os=platform.platform(), python=sys.version, options=ai_study.OPTIONS, schedule=schedule,
                    source_sha256={n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in sources})
    for endpoint in ('tags', 'version', 'ps'):
        with urllib.request.urlopen('http://127.0.0.1:11434/api/' + endpoint, timeout=5) as response:
            manifest['ollama_' + endpoint] = json.load(response)
    if args.model not in [m['name'] for m in manifest['ollama_tags']['models']]:
        parser.error('Requested model is not installed')
    dump(out / 'manifest.json', manifest)
    print('Artifacts:', out, flush=True)
    # Warm-up (model load) so first campaign latency is not cold-start; logged separately.
    warm = dict(model=args.model, calls=[], events=[], _start=time.monotonic())
    ai_study.defend(warm, 'student', [])
    dump(out / 'warmup.json', {k: v for k, v in warm.items() if not k.startswith('_')})
    by_id = {c['id']: c for c in replay.CASES}
    jobs = []
    for block in schedule:
        cases = [by_id[i] for i in block['cases']]
        for cond in block['conditions']:
            job = campaign(cond['mode'], cases, args.model, cond['rps'], block['repeat'])
            dump(out / (job['id'] + '.json'), job)
            jobs.append(job)
            print(job['id'], job['status'], job['summary'], flush=True)
    frac = sum(c['attack'] for c in replay.CASES) / len(replay.CASES)
    rows = []
    for j in jobs:
        s = j['summary']
        lat = s['first_analysis_seconds']
        model = exposure_model(j['rps'], lat, frac) if lat is not None else {}
        rows.append(dict(id=j['id'], mode=j['mode'], rps=j['rps'], repeat=j['repeat'], status=j['status'],
                         policy_effective_seconds=j['policy_effective_seconds'], wall_seconds=j['wall_seconds'],
                         **s, **model))
    with (out / 'summary.csv').open('w', newline='', encoding='utf-8-sig') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    dump(out / 'results.json', jobs)
    if any(j['status'] != 'completed' for j in jobs):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
