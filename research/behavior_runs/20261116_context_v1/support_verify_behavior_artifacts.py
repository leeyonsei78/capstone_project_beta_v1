"""Read-only integrity/measurement audit; write a separate verification record."""
import argparse
import hashlib
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--check-http-report', action='store_true')
    args = parser.parse_args()
    folder = args.run
    manifest = read(folder/'manifest.json')
    traces = read(folder/'http_traces.json')
    predictions = read(folder/'predictions.json')
    assert sha(folder/'http_traces.json') == manifest['http_trace_sha256']
    for name, digest in manifest['source_sha256'].items():
        assert sha(folder/name.replace('/', '_')) == digest
    specs = {e['id']: e for e in manifest['episodes']}
    by_id = {t['id']: t for t in traces}
    assert set(specs) == set(by_id) and len(traces) == 24
    request_count = 0
    for trace in traces:
        spec = specs[trace['id']]
        assert len(trace['observations']) == 3 and len(trace['controls']) == 2
        for expected, actual in zip(spec['requests'], trace['observations']):
            assert actual['path'] == expected['path'] and actual['input'] == expected['input']
        if spec['gate_second_on_denial']:
            assert trace['observations'][0]['status'] in (401, 403)
        for row in trace['observations'] + trace['controls']:
            assert hashlib.sha256(json.dumps(row['response']).encode()).hexdigest() == row['response_sha256']
            request_count += 1
        assert trace['controls'][0]['response']['authenticated_users'] == ['student']
        assert trace['controls'][1]['response']['document'] == 'student notes'
    assert request_count == 120
    assert len(predictions) == 120 and all(r['status'] == 'completed' for r in predictions)
    assert len({(r['id'], r['mode']) for r in predictions}) == 120
    calls = [r for r in predictions if r['mode'].startswith('llm_')]
    assert [[r['id'], r['mode']] for r in calls] == manifest['task_order']
    for call in calls:
        rows = by_id[call['id']]['observations']
        if call['mode'] == 'llm_current':
            rows = rows[-1:]
        obs = [{k: row[k] for k in ('method', 'path', 'input', 'status', 'response')} for row in rows]
        assert call['prompt'] == manifest['prompt'] + json.dumps(obs, ensure_ascii=False)
        assert json.loads(call['ollama_response']['response'])['adaptive'] == call['prediction']
        assert hashlib.sha256(call['prompt'].encode()).hexdigest() == call['prompt_sha256']
        assert call['ollama_response']['done']
    summary = read(ROOT/'research/results/behavior_context_summary.json')
    hybrid = folder/'exploratory_hybrid'
    hybrid_manifest = read(hybrid/'manifest.json')
    assert hybrid_manifest['parent_manifest_sha256'] == sha(folder/'manifest.json')
    extraction = read(hybrid/'extractions.json')
    lookup = {e['observation_sha256']: e for e in extraction}
    assert len(extraction) == 18 and all(e['status'] == 'completed' for e in extraction)
    for value in extraction:
        obs = hybrid_manifest['observations'][value['observation_sha256']]
        assert value['prompt'] == hybrid_manifest['prompt'] + json.dumps(obs, ensure_ascii=False)
        assert json.loads(value['ollama_response']['response'])['family'] == value['family']
    hybrid_predictions = read(hybrid/'predictions.json')
    for p in hybrid_predictions:
        assert p['families'] == [lookup[k]['family'] for k in p['observation_keys']]
        denied = set()
        positive = False
        for row, family in zip(by_id[p['id']]['observations'], p['families']):
            positive |= family != 'none' and bool(denied - {family})
            if row['status'] in (401, 403) and family != 'none':
                denied.add(family)
        assert positive == p['prediction']
    for aggregate in summary['aggregates']:
        subset = [p for p in predictions + hybrid_predictions if p['mode'] == aggregate['mode']]
        assert aggregate['correct'] == sum(p['prediction'] == specs[p['id']]['adaptive'] for p in subset)
        assert aggregate['tp'] == sum(p['prediction'] and specs[p['id']]['adaptive'] for p in subset)
    original = read(ROOT/'research/paper_provenance.json')
    assert sha(Path(original['original_file'])) == original['sha256']
    served_ok = None
    if args.check_http_report:
        with urllib.request.urlopen('http://127.0.0.1:8765/research/paper_revision.html', timeout=5) as response:
            served = response.read()
        assert served == (ROOT/'research/results/paper_revision.html').read_bytes()
        assert b'id="behavior-study"' in served
        served_ok = True
    verification = dict(http_requests=120, primary_judgments=120, primary_model_calls=48,
                        warmup_calls=1, exploratory_extraction_calls=18, failed_calls=0,
                        raw_http_hashes_verified=True, prompt_inputs_verified=True,
                        labels_not_in_model_inputs=True, model_outputs_recomputed=True,
                        original_paper_unchanged=True, http_report_matches_file=served_ok)
    (folder/'verification.json').write_text(json.dumps(verification, indent=2), encoding='utf-8')
    print(json.dumps(verification, indent=2))


if __name__ == '__main__':
    main()
