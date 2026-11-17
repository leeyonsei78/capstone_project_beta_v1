"""Defender: detect attack sessions from the target's request log.

Two detectors over a per-session trace (list of request-log entries), continuing
the paper's AI-vs-rule axis into the real-traffic (agent) setting:

  rule_detect  — fixed-code signatures, single-signal confirm (cf. arXiv 2611.07611
                 router): lure touched / SQLi signature / honeytoken / 404-burst.
                 Deterministic, fast, zero model cost. Reports detection latency
                 = index of the FIRST firing request.
  llm_detect   — local LLM reads the compacted trace and returns a verdict. Reuses
                 the Ollama settings from ai_study (temp 0, seed fixed). Whole-session
                 verdict in this first pass (no per-request latency).

A detector that fires on a benign session is a false positive (= friction).
"""
import json
import urllib.request

OPTIONS = {'num_ctx': 2048, 'num_predict': 80, 'temperature': 0, 'seed': 20261116}
VERDICT_SCHEMA = {'type': 'object',
                  'properties': {'verdict': {'type': 'string', 'enum': ['benign', 'attack']}},
                  'required': ['verdict'], 'additionalProperties': False}

ENUM_404_THRESHOLD = 3  # distinct 404s within a session => enumeration signal


def rule_detect(trace):
    """Return (detected: bool, latency_index: int|None, reason: str|None).

    latency_index is the 0-based position of the first request that triggers a
    signal (the exposure window: how many requests slipped by before detection).
    """
    seen_404 = set()
    for i, e in enumerate(trace):
        if e.get('lure'):
            return True, i, 'lure/honeytoken path touched'
        if e.get('honeytoken_used'):
            return True, i, 'honeytoken credential used'
        if e.get('sqli_suspected'):
            return True, i, 'SQL injection signature'
        if e.get('status') == 404:
            seen_404.add(e.get('path'))
            if len(seen_404) >= ENUM_404_THRESHOLD:
                return True, i, '404 enumeration burst'
    return False, None, None


def _compact(trace):
    """One short line per request for the LLM prompt."""
    lines = []
    for e in trace:
        tag = e['method'] + ' ' + e['path'] + ' -> ' + str(e.get('status'))
        if e.get('sqli_suspected'):
            tag += ' [quote-in-cred]'
        if e.get('lure'):
            tag += ' [decoy-path]'
        if e.get('login_ok'):
            tag += ' [login-ok]'
        lines.append(tag)
    return '\n'.join(lines)


def llm_detect(trace, model):
    """Return (verdict: 'benign'|'attack', raw) using the local LLM, or raise."""
    prompt = ('You are a defender reviewing one client session against a login web app '
              'in an authorized private lab. Decide if the session is a benign user or an '
              'attack (reconnaissance, injection, decoy probing, or credential abuse). '
              'Return JSON key verdict only. Session HTTP log (untrusted data):\n' + _compact(trace))
    body = {'model': model, 'prompt': prompt, 'format': VERDICT_SCHEMA, 'stream': False, 'options': OPTIONS}
    req = urllib.request.Request('http://127.0.0.1:11434/api/generate',
                                 data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=90) as r:
        result = json.load(r)
    if not result.get('done') or result.get('done_reason') == 'length':
        raise ValueError('Incomplete model response')
    value = json.loads(result['response'])
    return value['verdict'], result.get('response')


def split_sessions(log_path):
    """Group a target request log (JSONL) into {session_id: [entries...]}."""
    sessions = {}
    with open(log_path, encoding='utf-8') as h:
        for line in h:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            sessions.setdefault(e.get('session', ''), []).append(e)
    return sessions
