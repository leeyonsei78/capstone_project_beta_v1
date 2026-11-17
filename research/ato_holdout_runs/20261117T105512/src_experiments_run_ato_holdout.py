"""Independent (rules-blind) holdout re-validation of the ATO defenders.

Scores the fixed rule baselines (fx.rules, fx.rules2) and the LLM defender
(ato_study.defend) on BOTH the development set (ato_fixtures.CASES) and an
independent holdout authored by a separate agent that never saw the detection
rules or the dev cases (ato_holdout.load_holdout). The headline number is the
dev-vs-holdout delta: if accuracy/friction hold on the independent set, the
study's circularity concern is reduced; if they drop, over-fitting is exposed.

Scoring is per-event and STATELESS for every mode (no history passed), so rules,
rules2 and the LLM are compared apples-to-apples. All data are synthetic; no
network egress except the local Ollama endpoint for the llm mode.

Honest limitation: the holdout author is itself an AI subagent, not a human third
party. This is rules-blind, separate-context independence, not full third-party
independence.
"""
import argparse
import csv
import hashlib
import json
import math
import shutil
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ai_study
import ato_fixtures as fx
import ato_holdout
import ato_study

MODES = ('rules', 'rules2', 'llm')
SRC = ['experiments/run_ato_holdout.py', 'ato_holdout.py', 'ato_fixtures.py', 'ato_study.py', 'ai_study.py']


def wilson(k, n, z=1.96):  # matches experiments/run_ato_adaptive.wilson
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(max(0.0, c - h), 4), round(min(1.0, c + h), 4))


def decide_event(mode, event, profile, defend, djob):
    if mode == 'rules':
        return fx.rules(event, profile)
    if mode == 'rules2':
        return fx.rules2(event, profile)
    if mode == 'llm':
        return defend(djob, event, profile, variant='summary')['action']
    raise ValueError(mode)


def score(split_name, cases, mode, defend, djob):
    """Per-event stateless scoring over a list of cases. Returns (summary, rows)."""
    rows = []
    tot = corr = 0
    b_ev = b_corr = b_fric = b_chal = b_lock = 0
    a_ev = a_caught = a_miss = 0
    for c in cases:
        for i, e in enumerate(c['events']):
            action = decide_event(mode, e, c['profile'], defend, djob)
            ok = action in c['allowed']
            tot += 1
            corr += ok
            if c['label'] == 'benign':
                b_ev += 1
                b_corr += ok
                b_fric += fx.FRICTION[action]
                b_chal += action == 'challenge'
                b_lock += action == 'lock'
            else:
                a_ev += 1
                a_caught += ok
                a_miss += action == 'allow'
            rows.append(dict(split=split_name, mode=mode, case_id=c['id'], label=c['label'],
                             category=c.get('category', ''), event_index=i, action=action,
                             allowed=c['allowed'], correct=ok))
    lo, hi = wilson(corr, tot)
    summary = dict(split=split_name, mode=mode, cases=len(cases), events=tot,
                   accuracy=round(corr / tot, 4) if tot else None, acc_ci_lo=lo, acc_ci_hi=hi,
                   benign_events=b_ev, benign_correct=b_corr, benign_friction=b_fric,
                   benign_challenges=b_chal, benign_locks=b_lock,
                   attack_events=a_ev, attack_caught=a_caught, attack_misses=a_miss,
                   attack_miss_rate=round(a_miss / a_ev, 4) if a_ev else None)
    return summary, rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--defender-model', default='qwen2.5-coder:14b')
    ap.add_argument('--modes', nargs='+', choices=MODES, default=list(MODES))
    ap.add_argument('--holdout', default=str(ato_holdout.CASES_PATH))
    args = ap.parse_args()

    holdout = ato_holdout.load_holdout(args.holdout)   # raises if not yet authored
    dev = fx.CASES
    defend = ato_study.defend

    if 'llm' in args.modes:
        with urllib.request.urlopen('http://127.0.0.1:11434/api/tags', timeout=5) as r:
            names = [m['name'] for m in json.load(r)['models']]
        if args.defender_model not in names:
            ap.error('Model not installed: ' + args.defender_model)

    out = ROOT / 'research' / 'ato_holdout_runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    out.mkdir(parents=True)
    for n in SRC:
        shutil.copyfile(ROOT / n, out / ('src_' + n.replace('/', '_')))
    # provenance: the author's raw cases file and (if present) the authoring prompt
    shutil.copyfile(args.holdout, out / 'ato_holdout_cases.json')
    prompt_path = ROOT / 'ato_holdout_authoring_prompt.txt'
    if prompt_path.exists():
        shutil.copyfile(prompt_path, out / 'ato_holdout_authoring_prompt.txt')

    summaries, all_rows = [], []
    for mode in args.modes:
        djob = dict(model=args.defender_model, calls=[], events=[])
        for split_name, cases in (('dev', dev), ('holdout', holdout)):
            s, rows = score(split_name, cases, mode, defend, djob)
            summaries.append(s)
            all_rows.extend(rows)
            print(mode, split_name, 'acc=%s' % s['accuracy'], 'miss=%s' % s['attack_miss_rate'],
                  'friction=%s' % s['benign_friction'], flush=True)
        if mode == 'llm':
            (out / 'llm_calls.json').write_text(json.dumps(djob['calls'], ensure_ascii=False, indent=2), encoding='utf-8')

    # deltas (holdout - dev) per mode
    by = {(s['mode'], s['split']): s for s in summaries}
    deltas = []
    for mode in args.modes:
        d, h = by.get((mode, 'dev')), by.get((mode, 'holdout'))
        if d and h and d['accuracy'] is not None and h['accuracy'] is not None:
            deltas.append(dict(mode=mode, dev_accuracy=d['accuracy'], holdout_accuracy=h['accuracy'],
                               accuracy_delta=round(h['accuracy'] - d['accuracy'], 4),
                               dev_attack_miss=d['attack_miss_rate'], holdout_attack_miss=h['attack_miss_rate'],
                               dev_friction=d['benign_friction'], holdout_friction=h['benign_friction']))

    with (out / 'summary.csv').open('w', newline='', encoding='utf-8-sig') as fh:
        w = csv.DictWriter(fh, fieldnames=list(summaries[0].keys()))
        w.writeheader()
        w.writerows(summaries)
    (out / 'detail.json').write_text(json.dumps(all_rows, ensure_ascii=False, indent=2), encoding='utf-8')
    (out / 'deltas.json').write_text(json.dumps(deltas, indent=2), encoding='utf-8')
    (out / 'manifest.json').write_text(json.dumps(dict(
        created_at=datetime.now(timezone.utc).isoformat(), args=vars(args),
        scope='rules-blind holdout re-validation; per-event stateless scoring; synthetic; '
              'dev=ato_fixtures.CASES vs independent holdout',
        holdout_authored_by=ato_holdout.authored_by(args.holdout),
        holdout_cases=len(holdout), dev_cases=len(dev),
        defender_options=ai_study.OPTIONS,
        limitation='holdout author is an AI subagent, rules-blind + separate context, not a human third party',
        holdout_sha256=hashlib.sha256(Path(args.holdout).read_bytes()).hexdigest(),
        source_sha256={n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in SRC}), indent=2),
        encoding='utf-8')
    print('Artifacts:', out, flush=True)
    print('Deltas:', json.dumps(deltas), flush=True)


if __name__ == '__main__':
    main()
