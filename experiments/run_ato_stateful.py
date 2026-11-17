"""Corrective re-validation of the two weaknesses the independent holdout exposed
(paper §6.13 -> §6.14). All rule-based: deterministic, no model, no network.

  Part A (per-event): rules / rules2 / rules3 on dev (ato_fixtures.CASES) and the
    independent holdout (ato_holdout) -> does rules3's IP corroboration cut benign
    friction and over-locks while keeping attack detection?
  Part B (case-level): stateless rules2 / rules3 vs rules_stateful -> benign cases
    stay 'clean' (no lock) and attack cases are 'caught' (>=1 challenge/lock). Shows
    the per-event "miss" on a multi-event takeover's benign-looking first event was a
    scoring artifact, and where the sequence signal adds coverage.

The corrective rules are author-designed (new circularity for the rules themselves),
but re-validated on the SAME rules-blind holdout, so holdout numbers stay independent.
"""
import csv
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ato_fixtures as fx
import ato_holdout
import ato_stateful as st
from experiments.run_ato_holdout import wilson

SRC = ['experiments/run_ato_stateful.py', 'ato_stateful.py', 'ato_fixtures.py', 'ato_holdout.py']
PER_EVENT = {'rules': fx.rules, 'rules2': fx.rules2, 'rules3': st.rules3}


def main():
    holdout = ato_holdout.load_holdout()
    splits = (('dev', fx.CASES), ('holdout', holdout))

    out = ROOT / 'research' / 'ato_stateful_runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    out.mkdir(parents=True)
    for n in SRC:
        shutil.copyfile(ROOT / n, out / ('src_' + n.replace('/', '_')))
    shutil.copyfile(ato_holdout.CASES_PATH, out / 'ato_holdout_cases.json')

    # Part A: per-event
    per_rows = []
    for name, fn in PER_EVENT.items():
        for split, cases in splits:
            s = st.score_per_event(cases, fn)
            lo, hi = wilson(s['attack_events'] - s['attack_misses'], s['attack_events'])
            per_rows.append(dict(detector=name, split=split, accuracy=s['accuracy'],
                                 benign_friction=s['benign_friction'], benign_locks=s['benign_locks'],
                                 attack_miss_rate=s['attack_miss_rate'],
                                 attack_caught_ci_lo=lo, attack_caught_ci_hi=hi))
            print('PER-EVENT', name, split, 'acc=%s' % s['accuracy'],
                  'friction=%s' % s['benign_friction'], 'benign_locks=%s' % s['benign_locks'],
                  'attack_miss=%s' % s['attack_miss_rate'], flush=True)

    # Part B: case-level
    case_detectors = {
        'rules2_stateless': st.stateless(fx.rules2),
        'rules3_stateless': st.stateless(st.rules3),
        'rules_stateful': st.rules_stateful,
    }
    case_rows, detail = [], []
    for name, fn in case_detectors.items():
        for split, cases in splits:
            s, rows = st.score_case_level(cases, fn)
            case_rows.append(dict(detector=name, split=split, **s))
            for r in rows:
                detail.append(dict(detector=name, split=split, **r))
            print('CASE-LEVEL', name, split,
                  'benign_clean=%d/%d' % (s['benign_clean'], s['benign_cases']),
                  'attack_caught=%d/%d' % (s['attack_caught'], s['attack_cases']), flush=True)

    with (out / 'per_event.csv').open('w', newline='', encoding='utf-8-sig') as fh:
        w = csv.DictWriter(fh, fieldnames=list(per_rows[0].keys()))
        w.writeheader()
        w.writerows(per_rows)
    with (out / 'case_level.csv').open('w', newline='', encoding='utf-8-sig') as fh:
        w = csv.DictWriter(fh, fieldnames=list(case_rows[0].keys()))
        w.writeheader()
        w.writerows(case_rows)
    (out / 'case_detail.json').write_text(json.dumps(detail, ensure_ascii=False, indent=2), encoding='utf-8')
    (out / 'manifest.json').write_text(json.dumps(dict(
        created_at=datetime.now(timezone.utc).isoformat(),
        scope='corrective re-validation of §6.13 weaknesses; rules-based; per-event + case-level; '
              'dev=ato_fixtures.CASES vs independent holdout',
        ip_thresh=st.IP_THRESH, holdout_authored_by=ato_holdout.authored_by(),
        holdout_cases=len(holdout), dev_cases=len(fx.CASES),
        limitation='corrective rules are author-designed; re-validated on the same rules-blind holdout',
        source_sha256={n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in SRC}), indent=2),
        encoding='utf-8')
    print('Artifacts:', out, flush=True)


if __name__ == '__main__':
    main()
