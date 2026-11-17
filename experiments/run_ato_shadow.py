"""Sensitivity analysis of the deception ('shadow') arm vs the lock arm, by capability level.
Replays which attacker campaigns reached a logged-in session under the rules2 risk function
(from a ladder run), then applies the analytic lure model in ato_shadow.py. No LLM call.
The lure-touch probabilities are ASSUMPTIONS (swept), to be measured later with real agents."""
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ato_adaptive as ad
import ato_fixtures as fx
import ato_shadow as sh

P_TOUCH = (0, 0.05, 0.1, 0.2, 0.3, 0.5)
Q_BENIGN = (0, 0.005, 0.01, 0.02, 0.05)
N_ACTIONS = (3, 6, 10)


def ladder_campaigns(run_dir, mode='rules2'):
    out = {}
    for p in Path(run_dir).glob('*-*-*.json'):
        if not p.name[0].isdigit():
            continue
        j = json.loads(p.read_text(encoding='utf-8'))
        if j['mode'] == mode and j['status'] == 'completed':
            out.setdefault(j['level'], []).append(dict(reached_session=j['takeover']))
    return out


def benign_allowed(risk=fx.rules2):
    n = 0
    for c in fx.CASES:
        if c['label'] == 'benign':
            n += sum(risk(e, c['profile']) == 'allow' for e in c['events'])
    return n


def main():
    base = ROOT / 'research' / 'ato_ladder_runs'
    run = Path(sys.argv[1]) if len(sys.argv) > 1 else sorted(base.iterdir())[-1]
    camps = ladder_campaigns(run)
    ba = benign_allowed()
    out = ROOT / 'research' / 'ato_shadow_runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    out.mkdir(parents=True)
    rows = []
    for level in ad.LEVELS:
        for n in N_ACTIONS:
            for p in P_TOUCH:
                for q in Q_BENIGN:
                    e = sh.evaluate(camps.get(level, []), ba, p, q, n)
                    rows.append(dict(level=level, n_actions=n, p_touch=p, q_benign=q, **e))
    with (out / 'shadow_sensitivity.csv').open('w', newline='', encoding='utf-8-sig') as h:
        w = csv.DictWriter(h, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    (out / 'manifest.json').write_text(json.dumps(dict(
        created_at=datetime.now(timezone.utc).isoformat(), source_ladder_run=str(run.name), risk='rules2',
        scope='analytic lure model; touch probabilities are assumptions, not measurements',
        benign_allowed_events=ba, trap_cost=sh.TRAP_COST), indent=2), encoding='utf-8')
    print('Artifacts:', out)
    print('level        n  p_touch q_benign  takeover(lock) takeover(shadow) deflected  benign_trapped')
    for r in rows:
        if r['n_actions'] == 6 and r['q_benign'] in (0.01, 0.05) and r['p_touch'] in (0, 0.1, 0.3, 0.5):
            print(f"{r['level']:<12} {r['n_actions']:>2} {r['p_touch']:>7} {r['q_benign']:>8}  "
                  f"{r['real_takeover_rate_lock']!s:>14.14} {r['real_takeover_rate_shadow']!s:>15.15} "
                  f"{r['deflected_rate_shadow']!s:>9.9} {r['benign_trapped_expected']:.2f}/{r['campaigns'] and ba}")


if __name__ == '__main__':
    main()
