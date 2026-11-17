"""Agent architecture + knowledge-representation comparison on the synthetic
two-asset pivot (paper §6.15). Docker-free: loopback targets, local Ollama brain,
code-enforced host allowlist.

Configs:
  fixed     : architecture A, deterministic pivot (fixed_agent.PivotAgent)
  react-flat: architecture B (ReAct LLM brain) with flat working memory
  react-graph: architecture B with the networkx dual-graph working memory

Per config x N repeats, records: takeover (reached crown jewel B), stage reached,
HTTP requests, agent steps, wasted actions, and the defender's rule/LLM detection on
that session's traffic. Reports rates with Wilson 95% CI.

Run:  python experiments/run_agent_arch.py --repeats 5
      python experiments/run_agent_arch.py --repeats 1 --configs fixed react-graph   # smoke
"""
import argparse
import json
import shutil
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'agent_lab'))
import multi_target as MT        # noqa: E402
import fixed_agent as FA         # noqa: E402
import react_agent as RA         # noqa: E402
import knowledge as K            # noqa: E402
import defender as D             # noqa: E402
from experiments.run_ato_adaptive import wilson  # noqa: E402

CONFIGS = ('fixed', 'react-flat', 'react-graph')
SRC = ['agent_lab/multi_target.py', 'agent_lab/react_agent.py', 'agent_lab/knowledge.py',
       'agent_lab/fixed_agent.py', 'agent_lab/defender.py', 'experiments/run_agent_arch.py']


def find_model():
    try:
        with urllib.request.urlopen('http://127.0.0.1:11434/api/tags', timeout=3) as r:
            names = [m['name'] for m in json.load(r)['models']]
    except Exception:  # noqa: BLE001
        return None
    for cand in ('qwen2.5-coder:14b', 'qwen14b-16k:latest', 'deepseek-coder-v2:16b'):
        if cand in names:
            return cand
    return names[0] if names else None


def run_one(config, bases, model, max_steps, session):
    if config == 'fixed':
        return FA.PivotAgent(bases, session=session).run()
    name = 'graph' if config == 'react-graph' else 'flat'
    agent = RA.ReactAgent(bases, K.make(name, goal_host='internal'),
                          RA.ollama_brain(model), max_steps=max_steps, session=session)
    return agent.run()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repeats', type=int, default=5)
    ap.add_argument('--configs', nargs='+', choices=CONFIGS, default=list(CONFIGS))
    ap.add_argument('--max-steps', type=int, default=12)
    ap.add_argument('--llm-cap', type=int, default=6, help='max defender-LLM detections per config')
    args = ap.parse_args()

    needs_model = any(c.startswith('react') for c in args.configs)
    model = find_model()
    if needs_model and not model:
        ap.error('no Ollama model available for the ReAct brain')

    out = ROOT / 'research' / 'agent_arch_runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    out.mkdir(parents=True)
    log_path = out / 'requests.jsonl'
    store, bases, shutdown = MT.launch(str(log_path))
    time.sleep(0.2)

    rows = []
    try:
        for config in args.configs:
            for rep in range(args.repeats):
                sid = f'{config}-{rep}'
                t = time.monotonic()
                res = run_one(config, bases, model, args.max_steps, sid)
                res.update(config=config, repeat=rep, session=sid)
                res.pop('trace', None)  # keep summary light; full traces in per-run files
                rows.append(res)
                print(sid, res['outcome'], 'stage=%s' % res['stage'],
                      'req=%d' % res['requests'], 'wasted=%d' % res.get('wasted_actions', 0),
                      '%.1fs' % (time.monotonic() - t), flush=True)
        time.sleep(0.3)
    finally:
        shutdown()

    # defender detection per session (over the whole web+internal trace of that session)
    sessions = D.split_sessions(log_path)
    llm_used = {c: 0 for c in args.configs}
    for r in rows:
        trace = sessions.get(r['session'], [])
        detected, latency, reason = D.rule_detect(trace)
        r['n_requests_logged'] = len(trace)
        r['rule_detected'] = detected
        r['rule_latency'] = latency
        r['lure_touches'] = sum(1 for e in trace if e.get('lure'))
        if model and llm_used[r['config']] < args.llm_cap:
            try:
                verdict, _ = D.llm_detect(trace, model)
                r['llm_detected'] = (verdict == 'attack')
                llm_used[r['config']] += 1
            except Exception as e:  # noqa: BLE001
                r['llm_error'] = str(e)

    (out / 'sessions.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')

    def rate(subset, field):
        xs = [r for r in subset if field in r and r[field] is not None]
        k = sum(1 for r in xs if r[field])
        n = len(xs)
        lo, hi = wilson(k, n) if n else (None, None)
        return dict(k=k, n=n, rate=(round(k / n, 3) if n else None), ci_lo=lo, ci_hi=hi)

    def mean(subset, field):
        xs = [r[field] for r in subset if r.get(field) is not None]
        return round(sum(xs) / len(xs), 2) if xs else None

    summary = {'model': model, 'repeats': args.repeats, 'configs': {}}
    for config in args.configs:
        sub = [r for r in rows if r['config'] == config]
        summary['configs'][config] = dict(
            takeover=rate(sub, 'takeover'),
            mean_stage_num=mean(sub, 'stage_num'),
            reached_pivot_cred={'k': sum(1 for r in sub if r['stage_num'] >= 3), 'n': len(sub)},
            mean_requests=mean(sub, 'requests'),
            mean_steps=mean(sub, 'steps'),
            mean_wasted=mean(sub, 'wasted_actions'),
            mean_lure_touches=mean(sub, 'lure_touches'),
            rule_detected=rate(sub, 'rule_detected'),
            llm_detected=rate(sub, 'llm_detected'))
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
    (out / 'manifest.json').write_text(json.dumps(dict(
        created_at=datetime.now(timezone.utc).isoformat(), args=vars(args), model=model,
        scope='agent architecture (fixed vs ReAct) x knowledge (flat vs networkx dual-graph) on a '
              'synthetic two-asset pivot; loopback; local model; Docker-free',
        bases_note='ephemeral loopback ports', source_sha256={}), indent=2), encoding='utf-8')
    for n in SRC:
        shutil.copyfile(ROOT / n, out / ('src_' + n.replace('/', '_')))

    print('Artifacts:', out, flush=True)
    print(json.dumps(summary, indent=2, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
