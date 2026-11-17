"""Aggregate a capability-ladder run: takeover rate with Wilson 95% CI per (mode, level)."""
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.run_ato_adaptive import MODES, wilson
import ato_adaptive as ad


def aggregate(run_dir):
    run_dir = Path(run_dir)
    jobs = [json.loads(p.read_text(encoding='utf-8')) for p in run_dir.glob('*-*-*.json')
            if p.name[0].isdigit()]
    rows = []
    for mode in MODES:
        for level in ad.LEVELS:
            js = [j for j in jobs if j['mode'] == mode and j['level'] == level]
            ok = [j for j in js if j['status'] == 'completed']
            k = sum(j['takeover'] for j in ok)
            lo, hi = wilson(k, len(ok))
            tk = [j['rounds_used'] for j in ok if j['takeover']]
            rows.append(dict(mode=mode, level=level, n=len(ok), failed=len(js) - len(ok), takeovers=k,
                             rate=k / len(ok) if ok else None, ci_lo=lo, ci_hi=hi,
                             locked=sum(j['outcome'] == 'locked' for j in ok),
                             exhausted=sum(j['outcome'] == 'exhausted' for j in ok),
                             median_rounds_to_takeover=statistics.median(tk) if tk else None,
                             injection_attempts=sum(j['injection_attempts'] for j in ok)))
    return rows


def main():
    base = ROOT / 'research' / 'ato_ladder_runs'
    run = Path(sys.argv[1]) if len(sys.argv) > 1 else sorted(base.iterdir())[-1]
    rows = aggregate(run)
    print('run', run.name)
    print('mode           level        n  take  rate [95% CI]        lock exh  med_rounds inj')
    for r in rows:
        rate = '-' if r['rate'] is None else f"{r['rate']:.2f} [{r['ci_lo']:.2f},{r['ci_hi']:.2f}]"
        print(f"{r['mode']:<14} {r['level']:<12} {r['n']:>2} {r['takeovers']:>4}  {rate:<19} {r['locked']:>4} {r['exhausted']:>3}"
              f"  {r['median_rounds_to_takeover']!s:>9} {r['injection_attempts']:>3}")
    f = run / 'benign_friction.json'
    if f.exists():
        print('benign friction (20 benign dev cases):')
        for x in json.loads(f.read_text(encoding='utf-8')):
            print(' ', x)
    (run / 'aggregate.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
