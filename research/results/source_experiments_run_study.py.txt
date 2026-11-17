"""Reproducible local pilot; no LLM or external target is contacted."""
import csv
import hashlib
import html
import http.client
import itertools
import json
import platform
import random
import statistics
import sys
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import workflow

OUT = ROOT / 'research' / 'results'
CASES = [
    ('sql_admin_comment', 'sql', "admin' -- ", True),
    ('sql_boolean', 'sql', "' OR 1=1 -- ", True),
    ('sql_caps', 'sql', "' oR 'a'='a' -- ", True),
    ('sql_block_comment', 'sql', "admin'/*", True),
    ('sql_normal_admin', 'sql', 'admin', False),
    ('sql_normal_student', 'sql', 'student', False),
    ('sql_apostrophe', 'sql', "O'Reilly", False),
    ('xss_script', 'xss', '<script>document.body.dataset.probe="1"</script>', True),
    ('xss_handler', 'xss', '<img src=x onerror="document.body.dataset.probe=1">', True),
    ('xss_svg', 'xss', '<svg onload="document.body.dataset.probe=1"></svg>', True),
    ('xss_normal_text', 'xss', 'hello student', False),
    ('xss_comparison', 'xss', 'price < 3 & quantity > 1', False),
    ('xss_unicode', 'xss', '\uc548\ub155\ud558\uc138\uc694', False),
    ('idor_other_owner', 'idor', '1002', True),
    ('idor_own', 'idor', '1001', False),
    ('idor_missing', 'idor', '9999', False),
]


def write_csv(name, rows):
    with (OUT / name).open('w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def percentile(values, p):
    ordered = sorted(values)
    return ordered[max(0, int(len(ordered) * p + .999999) - 1)]


def http_study():
    server = workflow.start_target(0)
    rows = []
    configs = list(itertools.product([False, True], repeat=3))
    rng = random.Random(20261115)
    order = [(rep, config) for rep in range(10) for config in configs]
    rng.shuffle(order)
    try:
        for rep, config in order:
            defenses = [fix for enabled, fix in zip(config, workflow.FIXES.values()) if enabled]
            workflow.STATE['defenses'] = defenses
            cases = list(CASES)
            rng.shuffle(cases)
            for case_id, kind, payload, attack in cases:
                path = '/' + kind + '?' + urllib.parse.urlencode({'input': payload})
                conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                start = time.perf_counter_ns()
                try:
                    conn.request('GET', path)
                    response = conn.getresponse()
                    body = response.read().decode()
                    assert response.status == 200
                finally:
                    conn.close()
                ms = (time.perf_counter_ns() - start) / 1e6
                if kind == 'xss':
                    outcome = payload in body if attack else payload in html.unescape(body)
                else:
                    result = json.loads(body)
                    outcome = result['success'] if attack else (
                        isinstance(result['detail'], dict) and result['detail'].get('owner') == 'student'
                        if case_id == 'idor_own' else not result['success'])
                rows.append({'repeat': rep, 'config': ''.join(str(int(x)) for x in config),
                             'case': case_id, 'family': kind, 'attack': attack,
                             'payload': payload, 'outcome': bool(outcome), 'latency_ms': round(ms, 6),
                             'response_sha256': hashlib.sha256(body.encode()).hexdigest(), 'response': body})
    finally:
        server.shutdown()
        server.server_close()
    summaries = []
    for config in sorted({r['config'] for r in rows}):
        selected = [r for r in rows if r['config'] == config]
        attacks = [r for r in selected if r['attack']]
        controls = [r for r in selected if not r['attack']]
        summaries.append({'config_sql_xss_idor': config, 'attack_trials': len(attacks),
                          'attack_success_or_raw_xss_reflection': sum(r['outcome'] for r in attacks),
                          'attack_success_rate': sum(r['outcome'] for r in attacks) / len(attacks),
                          'control_trials': len(controls), 'control_preserved': sum(r['outcome'] for r in controls),
                          'p50_http_ms': percentile([r['latency_ms'] for r in selected], .5),
                          'p95_http_ms': percentile([r['latency_ms'] for r in selected], .95)})
    write_csv('http_trials.csv', rows)
    write_csv('http_summary.csv', summaries)
    return summaries


def event(actor, ip, hour, technique, suspicious=False, prior_outcome=200):
    # Parsed telemetry features, not raw attack execution. Labels never enter detector.
    return {'actor': actor, 'ip': ip, 'hour': hour, 'technique': technique,
            'suspicious': suspicious, 'response_status': prior_outcome}


def make_episodes():
    episodes = []
    # Seven counterexample families. Replicas change virtual timing and endpoint IDs,
    # not payload/semantic diversity; inference is restricted to this synthetic generator.
    for seed in range(30):
        rng = random.Random(seed)
        offset = rng.random() * .25
        templates = [
            ('adaptive_single_ip', True, 1, [event('a', 'p', 0, 'plain', True, 403), event('a', 'p', 1, 'url', True), event('a', 'p', 2, 'comment', True)]),
            ('adaptive_rotating_ip', True, 1, [event('a', 'p', 0, 'plain', True, 403), event('a', 'q', 1, 'url', True), event('a', 'r', 2, 'comment', True)]),
            ('adaptive_slow', True, 1, [event('a', 'p', 0, 'plain', True, 403), event('a', 'p', 10, 'url', True), event('a', 'p', 20, 'comment', True)]),
            ('benign_encoding_diversity', False, None, [event('a', 'p', 0, 'url'), event('a', 'p', 1, 'html'), event('a', 'p', 2, 'plain')]),
            ('benign_authorization_retries', False, None, [event('a', 'p', h, 'plain', False, 403) for h in range(5)]),
            ('benign_shared_nat', False, None, [event('other', 'p', 0, 'plain', True, 403), event('other', 'p', 1, 'url', True, 403), event('a', 'p', 2, 'plain'), event('a', 'p', 3, 'html')]),
            ('benign_expired_history', False, None, [event('a', 'p', 0, 'url'), event('a', 'p', 25, 'html')]),
        ]
        for kind, positive, onset, events in templates:
            for e in events:
                e['hour'] += offset
            episodes.append({'id': f'{kind}-{seed}', 'seed': seed, 'kind': kind,
                             'positive': positive, 'onset': onset, 'events': events})
    return episodes


class Tracker:
    def __init__(self, causal=False, entity='ip', current_only=False):
        self.causal = causal
        self.entity = entity
        self.current_only = current_only
        self.history = defaultdict(list)

    def observe(self, e):
        if self.current_only:
            return bool(e['suspicious'])
        key = e[self.entity]
        history = [x for x in self.history[key] if 0 <= e['hour'] - x['hour'] <= 24]
        if self.causal:
            # Must have a previous *suspicious* block and a current suspicious
            # technique change. A normal 403 or benign encoding change is insufficient.
            alarm = e['suspicious'] and any(x['response_status'] == 403 and x['suspicious'] and x['technique'] != e['technique'] for x in history)
        else:
            # Operationalization of draft 4.3, using only prior response feedback.
            techniques = {x['technique'] for x in history} | {e['technique']}
            alarm = len(techniques) >= 2 or sum(x['response_status'] == 403 for x in history) >= 3
        self.history[key] = history + [e]
        return bool(alarm)


def evaluate_episodes(episodes, causal=False, entity='ip', current_only=False):
    rows = []
    for episode in episodes:
        tracker = Tracker(causal, entity, current_only)
        first = None
        timings = []
        pre_onset = False
        for i, e in enumerate(episode['events']):
            start = time.perf_counter_ns()
            alarm = tracker.observe(e)
            timings.append((time.perf_counter_ns() - start) / 1e3)
            if e['actor'] != 'a':
                continue
            if alarm:
                if episode['positive'] and i < episode['onset']:
                    pre_onset = True
                elif first is None:
                    first = i
        rows.append({'episode': episode['id'], 'seed': episode['seed'], 'kind': episode['kind'],
                     'positive': episode['positive'], 'predicted': first is not None,
                     'atd_inclusive_attempts': first - episode['onset'] + 1 if first is not None and episode['positive'] else '',
                     'pre_onset_alarm': pre_onset, 'p95_cpu_us': percentile(timings, .95)})
    return rows


def metrics(rows):
    tp = sum(r['positive'] and r['predicted'] for r in rows)
    fn = sum(r['positive'] and not r['predicted'] for r in rows)
    fp = sum(not r['positive'] and r['predicted'] for r in rows)
    tn = sum(not r['positive'] and not r['predicted'] for r in rows)
    delay = [r['atd_inclusive_attempts'] for r in rows if r['positive'] and r['predicted']]
    return {'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn, 'adaptive_episode_recall': tp / (tp + fn),
            'benign_episode_fpr': fp / (fp + tn), 'f1': 2 * tp / (2 * tp + fp + fn),
            'mean_atd_detected_only': statistics.mean(delay) if delay else None,
            'episodes_with_pre_onset_alarm': sum(r['pre_onset_alarm'] for r in rows),
            'undetected_episodes': fn, 'p95_cpu_us': percentile([r['p95_cpu_us'] for r in rows], .95)}


def behavior_study():
    episodes = make_episodes()
    (OUT / 'behavior_episodes.json').write_text(json.dumps(episodes, indent=2), encoding='utf-8')
    summaries = []
    all_rows = []
    for name, causal, entity, current_only in [('draft_heuristic_ip', False, 'ip', False), ('causal_evidence_ip', True, 'ip', False), ('causal_evidence_trusted_session', True, 'actor', False), ('suspicion_only_no_history', False, 'ip', True)]:
        rows = evaluate_episodes(episodes, causal, entity, current_only)
        all_rows.extend({'policy': name, **r} for r in rows)
        summary = {'policy': name, **metrics(rows)}
        summary['strata'] = {kind: {'episodes': sum(r['kind'] == kind for r in rows), 'alarms': sum(r['kind'] == kind and r['predicted'] for r in rows)} for kind in sorted({r['kind'] for r in rows})}
        summaries.append(summary)
    write_csv('behavior_trials.csv', all_rows)
    return summaries


def plot(http, behavior):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.8))
    axes[0].bar([r['config_sql_xss_idor'] for r in http], [100 * r['attack_success_rate'] for r in http], color='#337d68')
    axes[0].set(xlabel='Defenses on/off: SQL / XSS / IDOR', ylabel='Attack outcome rate (%)', ylim=(0, 105), title='Local HTTP pilot: 8 defense combinations')
    labels = ['Draft IP', 'Causal + IP', 'Causal + session', 'Suspicion only']
    for i, r in enumerate(behavior):
        axes[1].bar(i - .18, 100 * r['adaptive_episode_recall'], width=.36, color='#337d68', label='Adaptive recall' if i == 0 else None)
        axes[1].bar(i + .18, 100 * r['benign_episode_fpr'], width=.36, color='#c46a53', label='Benign false-alarm rate' if i == 0 else None)
    axes[1].set(xticks=range(len(labels)), xticklabels=labels, ylim=(0, 110), ylabel='Synthetic episode rate (%)', title='Ideal-feature counterexamples (no LLM)')
    axes[1].tick_params(axis='x', labelsize=8)
    axes[1].legend(fontsize=8)
    fig.text(.5, .01, 'Pilot only: repeated fixtures, synthetic features; not NSL-KDD / CIC-IDS2018, Snort, or Qwen results.', ha='center', fontsize=9)
    fig.tight_layout(rect=(0, .05, 1, 1))
    for ext in ['png', 'svg']:
        fig.savefig(OUT / ('pilot_results.' + ext), dpi=180)
    plt.close(fig)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    http, behavior = http_study(), behavior_study()
    result = {'created_at': datetime.now(timezone.utc).isoformat(),
              'environment': {'os': platform.platform(), 'python': sys.version, 'llm_calls': 0, 'http_target': 'loopback ephemeral port, own training server'},
              'seeds': {'http': 20261115, 'behavior': list(range(30))},
              'scope': 'local synthetic pilot, not full LBADS reproduction',
              'http': http, 'behavior': behavior,
              'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in ['app.py', 'workflow.py', 'experiments/run_study.py']}}
    (OUT / 'summary.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    plot(http, behavior)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
