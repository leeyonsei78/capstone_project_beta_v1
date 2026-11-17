"""Fixed ATO fixture replay with real Qwen defender (in-process, synthetic events).
Development fixtures; not independent held-out evaluation."""
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
import ato_fixtures as fx
import ato_study

MODES = ('none', 'rules', 'always_challenge', 'llm_sync', 'llm_async', 'llm_plus_rules', 'llm_escalate')
SEVERITY = {a: i for i, a in enumerate(fx.ACTIONS)}


def campaign(mode, cases, model, gap, repeat, variant='event', defend=None, style='baseline', rps=None, episode_len=None):
    """rps: pace events at a fixed rate inside each episode; episode_len pads an episode by repeating its last event."""
    defend = defend or ato_study.defend
    start = time.monotonic()
    job = dict(id=f'{repeat}-{mode}-{variant}-{style}' + (f'-rps{rps}' if rps else ''), model=model, mode=mode, variant=variant, style=style,
               rps=rps, episode_len=episode_len, repeat=repeat,
               calls=[], events=[], trials=[], status='running', _start=start)
    pool = ThreadPoolExecutor(max_workers=1)
    lock = threading.Lock()
    pending = None
    try:
        for case in cases:
            state = dict(action='allow')   # per-episode (account) enforced action
            events = list(case['events'])
            while episode_len and len(events) < episode_len:
                events.append(events[-1])
            ep_start = time.monotonic()
            for i, event in enumerate(events):
                if rps:
                    wait = ep_start + i / rps - time.monotonic()
                    if wait > 0:
                        time.sleep(wait)
                began = time.monotonic()
                analysis_ms = None
                if mode == 'none':
                    action = 'allow'
                elif mode == 'rules':
                    action = fx.rules(event, case['profile'])
                elif mode == 'always_challenge':
                    action = 'challenge'
                elif mode == 'llm_sync':
                    action = defend(job, event, case['profile'], variant, style)['action']
                    analysis_ms = (time.monotonic() - began) * 1000
                elif mode == 'llm_plus_rules':
                    rule = fx.rules(event, case['profile'])
                    if rule == 'lock':
                        action = 'lock'
                    elif rule == 'allow':
                        action = 'allow'
                    else:
                        action = defend(job, event, case['profile'], variant, style)['action']
                        analysis_ms = (time.monotonic() - began) * 1000
                elif mode == 'llm_escalate':
                    # LLM may only escalate beyond the fixed rule, never relax it
                    rule = fx.rules(event, case['profile'])
                    llm = defend(job, event, case['profile'], variant, style)['action']
                    action = max(rule, llm, key=SEVERITY.get)
                    analysis_ms = (time.monotonic() - began) * 1000
                else:  # llm_async: serve with enforced state, decide in background
                    if pending is not None and pending.done():
                        pending.result()
                        pending = None
                    action = state['action']
                    if pending is None:
                        def work(ev=event, pr=case['profile'], st=state):
                            decision = defend(job, ev, pr, variant, style)
                            with lock:
                                st['action'] = decision['action']
                        pending = pool.submit(work)
                served_at = time.monotonic() - start
                granted = event['credential_ok'] and action == 'allow'
                job['trials'].append(dict(
                    case=case['id'], label=case['label'], category=case['category'], event_index=i,
                    action=action, credential_ok=event['credential_ok'], served_seconds=served_at,
                    analysis_ms=analysis_ms,
                    takeover=case['label'] == 'attack' and granted,
                    in_allowed=action in case['allowed'],
                    friction=fx.friction(case['label'], action),
                    benign_lock=case['label'] == 'benign' and action == 'lock'))
                if not rps:
                    time.sleep(gap)
            if mode == 'llm_async' and pending is not None:
                pending.result()   # episode boundary: decision state must not leak across accounts
                pending = None
        job['status'] = 'completed'
    except Exception as exc:
        job.update(status='failed', error=str(exc))
    finally:
        pool.shutdown(wait=True)
        job['wall_seconds'] = time.monotonic() - start
        job.pop('_start')
    rows = job['trials']
    benign = [r for r in rows if r['label'] == 'benign']
    attack = [r for r in rows if r['label'] == 'attack']
    job['summary'] = dict(
        events=len(rows), attack_events=len(attack), benign_events=len(benign),
        takeover_events=sum(r['takeover'] for r in attack),
        attack_cases_taken_over=len({r['case'] for r in attack if r['takeover']}),
        attack_cases=len({r['case'] for r in attack}),
        benign_challenges=sum(r['action'] == 'challenge' for r in benign),
        benign_locks=sum(r['benign_lock'] for r in benign),
        benign_friction=sum(r['friction'] for r in benign),
        in_allowed=sum(r['in_allowed'] for r in rows), llm_calls=len(job['calls']))
    return job


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', default='qwen2.5-coder:14b')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--gap', type=float, default=0.2)
    parser.add_argument('--seed', type=int, default=20261116)
    parser.add_argument('--modes', nargs='+', choices=MODES, default=list(MODES))
    parser.add_argument('--variants', nargs='+', choices=ato_study.VARIANTS, default=list(ato_study.VARIANTS))
    args = parser.parse_args()
    if not 1 <= args.repeats <= 30 or not 0 <= args.gap <= 10:
        parser.error('repeats 1..30, gap 0..10')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'research' / 'ato_runs' / stamp
    out.mkdir(parents=True)
    rng = random.Random(args.seed)
    schedule = []
    for repeat in range(args.repeats):
        cases = list(fx.CASES)
        rng.shuffle(cases)
        conds = [(m, v) for m in args.modes for v in (args.variants if m.startswith('llm') else ['event'])]
        rng.shuffle(conds)
        schedule.append(dict(repeat=repeat, cases=[c['id'] for c in cases], conditions=conds))
    sources = ['experiments/run_ato_replay.py', 'ato_fixtures.py', 'ato_study.py', 'ai_study.py']
    manifest = dict(created_at=datetime.now(timezone.utc).isoformat(), config=vars(args),
                    scope='development fixture replay; synthetic events authored by the developer; not held-out',
                    os=platform.platform(), python=sys.version, options=ai_study.OPTIONS,
                    friction_weights=fx.FRICTION, schedule=schedule, cases=fx.CASES,
                    source_sha256={n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in sources})
    if any(m.startswith('llm') for m in args.modes):
        for endpoint in ('tags', 'version', 'ps'):
            with urllib.request.urlopen('http://127.0.0.1:11434/api/' + endpoint, timeout=5) as r:
                manifest['ollama_' + endpoint] = json.load(r)
        if args.model not in [m['name'] for m in manifest['ollama_tags']['models']]:
            parser.error('Requested model is not installed')
    dump(out / 'manifest.json', manifest)
    print('Artifacts:', out, flush=True)
    by_id = {c['id']: c for c in fx.CASES}
    jobs = []
    for block in schedule:
        cases = [by_id[i] for i in block['cases']]
        for mode, variant in block['conditions']:
            job = campaign(mode, cases, args.model, args.gap, block['repeat'], variant)
            dump(out / (job['id'] + '.json'), job)
            jobs.append(job)
            print(job['id'], job['status'], job['summary'], flush=True)
    rows = [dict(id=j['id'], mode=j['mode'], variant=j['variant'], repeat=j['repeat'], status=j['status'],
                 wall_seconds=j['wall_seconds'], **j['summary']) for j in jobs]
    with (out / 'summary.csv').open('w', newline='', encoding='utf-8-sig') as h:
        w = csv.DictWriter(h, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    dump(out / 'results.json', jobs)
    if any(j['status'] != 'completed' for j in jobs):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
