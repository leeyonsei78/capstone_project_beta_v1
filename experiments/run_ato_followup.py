"""ATO follow-ups on the fixed fixtures.
  rate:      paced long episodes; async vs sync exposure (RPS sweep)
  injection: prompt-injection defenses on a separate injection set
Development fixtures authored by the developer; not held-out evidence."""
import argparse
import csv
import hashlib
import json
import random
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ai_study
import ato_fixtures as fx
from experiments import run_ato_replay as run


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('task', choices=['rate', 'injection'])
    ap.add_argument('--model', default='qwen2.5-coder:14b')
    ap.add_argument('--repeats', type=int, default=2)
    ap.add_argument('--rates', type=float, nargs='+', default=[2, 5, 10])
    ap.add_argument('--episode-len', type=int, default=6)
    ap.add_argument('--seed', type=int, default=20261116)
    args = ap.parse_args()
    out = ROOT / 'research' / 'ato_followup' / (args.task + '_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S'))
    out.mkdir(parents=True)
    with urllib.request.urlopen('http://127.0.0.1:11434/api/tags', timeout=5) as r:
        tags = json.load(r)
    if args.model not in [m['name'] for m in tags['models']]:
        ap.error('Requested model is not installed')
    rng = random.Random(args.seed)
    conds = []
    if args.task == 'rate':
        cases = list(fx.CASES)
        for rep in range(args.repeats):
            for rps in args.rates:
                conds.append(dict(mode='llm_async', style='baseline', variant='event', rps=rps, repeat=rep))
        conds.append(dict(mode='llm_sync', style='baseline', variant='event', rps=args.rates[-1], repeat=0))
        conds.append(dict(mode='none', style='baseline', variant='event', rps=args.rates[-1], repeat=0))
    else:
        cases = [c for c in fx.CASES if c['id'] == 'injected_user_agent'] + list(fx.INJECTION_CASES)
        for rep in range(args.repeats):
            for style in ('baseline', 'hardened', 'drop_untrusted'):
                conds.append(dict(mode='llm_sync', style=style, variant='event', rps=None, repeat=rep))
                conds.append(dict(mode='llm_escalate', style=style, variant='event', rps=None, repeat=rep))
            conds.append(dict(mode='rules', style='baseline', variant='event', rps=None, repeat=rep))
    rng.shuffle(cases)
    dump(out / 'manifest.json', dict(created_at=datetime.now(timezone.utc).isoformat(), args=vars(args),
         scope='development fixtures authored by the developer; not held-out', options=ai_study.OPTIONS,
         cases=[c['id'] for c in cases], conditions=conds, friction_weights=fx.FRICTION,
         source_sha256={n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in
                        ['experiments/run_ato_followup.py', 'experiments/run_ato_replay.py', 'ato_fixtures.py', 'ato_study.py']}))
    print('Artifacts:', out, flush=True)
    jobs = []
    for c in conds:
        job = run.campaign(c['mode'], cases, args.model, 0, c['repeat'], c['variant'], style=c['style'],
                           rps=c['rps'], episode_len=args.episode_len if args.task == 'rate' else None)
        dump(out / (job['id'] + '.json'), job)
        jobs.append(job)
        print(job['id'], job['status'], job['summary'], flush=True)
    rows = [dict(id=j['id'], mode=j['mode'], style=j['style'], rps=j['rps'], repeat=j['repeat'], status=j['status'],
                 wall_seconds=j['wall_seconds'], **j['summary']) for j in jobs]
    with (out / 'summary.csv').open('w', newline='', encoding='utf-8-sig') as h:
        w = csv.DictWriter(h, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    if any(j['status'] != 'completed' for j in jobs):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
