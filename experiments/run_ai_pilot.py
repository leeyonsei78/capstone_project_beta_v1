"""Real model smoke campaigns, not a statistically powered efficacy study."""
import argparse
import json
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ai_study

parser = argparse.ArgumentParser()
parser.add_argument('--model', default='qwen2.5-coder:14b')
parser.add_argument('--rounds', type=int, default=2)
parser.add_argument('--modes', nargs='+', choices=ai_study.MODES, default=list(ai_study.MODES))
args = parser.parse_args()
results = []
for mode in args.modes:
    job = ai_study.start({'model': args.model, 'mode': mode, 'rounds': args.rounds})
    print('Started', mode, job['id'], flush=True)
    while job['status'] in ('queued', 'running'):
        time.sleep(1)
        job = ai_study.get(job['id'])
    # Wait until the worker persists its result and releases campaign resources.
    artifact = ai_study.ARTIFACTS / (job['id'] + '.json')
    while not artifact.exists():
        time.sleep(.1)
    results.append({'id': job['id'], 'mode': mode, 'status': job['status'], 'error': job.get('error'), 'summary': job.get('summary')})
    print(json.dumps(results[-1], ensure_ascii=True), flush=True)
path = ai_study.ARTIFACTS / 'smoke_summary.json'
path.write_text(json.dumps({'scope': 'one campaign per condition; not comparative efficacy evidence', 'campaigns': results}, indent=2), encoding='utf-8')
print('Saved', path, flush=True)
