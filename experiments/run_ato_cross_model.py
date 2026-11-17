"""Cross-model capability-ladder run: attacker and defender from different model families.
Reuses run_ato_adaptive.campaign/wilson/benign_friction. Two directions:
  deepseek attacks, qwen defends
  qwen attacks, deepseek defends
Smaller repeats than the same-family ladder run (cross-model inference is slower; this is a
focused follow-up, not the main ladder). Modes limited to the ones that differed in the ladder:
none (baseline), rules2 (strongest rule baseline), llm_sync, llm_escalate.
"""
import csv
import hashlib
import json
import shutil
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ai_study
from experiments.run_ato_adaptive import MODES, campaign, benign_friction, wilson
import ato_adaptive as ad

PAIRS = [
    ('deepseek-coder-v2:16b', 'qwen2.5-coder:14b'),
    ('qwen2.5-coder:14b', 'deepseek-coder-v2:16b'),
]
CROSS_MODES = ('none', 'rules2', 'llm_sync', 'llm_escalate')
ROUNDS = 8
REPEATS = 6


def main():
    with urllib.request.urlopen('http://127.0.0.1:11434/api/tags', timeout=5) as r:
        names = [m['name'] for m in json.load(r)['models']]
    for atk, dfn in PAIRS:
        for m in (atk, dfn):
            if m not in names:
                raise SystemExit('Model not installed: ' + m)

    out = ROOT / 'research' / 'ato_cross_model_runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    out.mkdir(parents=True)
    src = ['experiments/run_ato_cross_model.py', 'experiments/run_ato_adaptive.py', 'ato_adaptive.py',
           'ato_study.py', 'ato_fixtures.py', 'ai_study.py']
    for n in src:
        shutil.copyfile(ROOT / n, out / ('src_' + n.replace('/', '_')))
    (out / 'manifest.json').write_text(json.dumps(dict(
        created_at=datetime.now(timezone.utc).isoformat(), pairs=PAIRS, modes=list(CROSS_MODES),
        rounds=ROUNDS, repeats=REPEATS, levels=list(ad.LEVELS),
        scope='cross-model-family capability-ladder follow-up; synthetic; fewer repeats than the same-family run',
        source_sha256={n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in src}), indent=2),
        encoding='utf-8')
    print('Artifacts:', out, flush=True)

    jobs, timings = [], []
    for atk, dfn in PAIRS:
        tag = f'{atk}->{dfn}'
        fstag = tag.replace(':', '_').replace('/', '_').replace('>', '_to_')
        for rep in range(REPEATS):
            for level in ad.LEVELS:
                for mode in CROSS_MODES:
                    t0 = time.monotonic()
                    job = campaign(mode, level, atk, dfn, ROUNDS, rep)
                    dt = time.monotonic() - t0
                    job['pair'] = tag
                    job['id'] = f'{fstag}-{rep}-{mode}-{level}'
                    (out / (job['id'] + '.json')).write_text(json.dumps(job, ensure_ascii=False, indent=2),
                                                              encoding='utf-8')
                    jobs.append(job)
                    timings.append(dict(pair=tag, mode=mode, level=level, wall_seconds=dt,
                                        calls=len(job['calls'])))
                    print(job['id'], job['status'], job['outcome'], job['rounds_used'], f'{dt:.1f}s', flush=True)

    rows = [{k: j[k] for k in ('id', 'pair', 'mode', 'level', 'repeat', 'status', 'outcome', 'rounds_used',
                               'injection_attempts')} for j in jobs]
    with (out / 'summary.csv').open('w', newline='', encoding='utf-8-sig') as h:
        w = csv.DictWriter(h, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    with (out / 'timings.csv').open('w', newline='', encoding='utf-8-sig') as h:
        w = csv.DictWriter(h, fieldnames=list(timings[0]))
        w.writeheader()
        w.writerows(timings)

    agg = []
    for atk, dfn in PAIRS:
        tag = f'{atk}->{dfn}'
        for mode in CROSS_MODES:
            for level in ad.LEVELS:
                js = [j for j in jobs if j['pair'] == tag and j['mode'] == mode and j['level'] == level]
                ok = [j for j in js if j['status'] == 'completed']
                k = sum(j['takeover'] for j in ok)
                lo, hi = wilson(k, len(ok))
                agg.append(dict(pair=tag, mode=mode, level=level, n=len(ok), takeovers=k,
                                rate=k / len(ok) if ok else None, ci_lo=lo, ci_hi=hi))
    (out / 'aggregate.json').write_text(json.dumps(agg, indent=2), encoding='utf-8')

    friction = []
    for atk, dfn in PAIRS:
        for mode in CROSS_MODES:
            if mode != 'none':
                friction.append(dict(pair=f'{atk}->{dfn}', **benign_friction(mode, dfn)))
    (out / 'benign_friction.json').write_text(json.dumps(friction, indent=2), encoding='utf-8')

    if any(j['status'] != 'completed' for j in jobs):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
