"""Loader for the independent (rules-blind) ATO holdout set.

Breaks the study's circularity: the holdout cases in ato_holdout_cases.json were
authored by a separate agent that never saw the detection rules (fx.rules /
fx.rules2 / defender.rule_detect) nor the development cases (fx.CASES). This
module only LOADS and NORMALIZES that author's output into the same case shape
used by ato_fixtures; it must never relabel a case or change an author's
`allowed` set (doing so would re-contaminate the holdout).

Normalization is limited to filling fields the author omitted with the neutral
defaults from ato_fixtures.ev()/case() so that fx.rules and ato_study.build_prompt
can index every event; author-provided values are never overwritten. Each fill is
recorded in the returned case under '_filled' for auditability.
"""
import json
from pathlib import Path

import ato_fixtures as fx

ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / 'ato_holdout_cases.json'

EVENT_KEYS = ('event_type', 'credential_ok', 'geo', 'device_known', 'local_hour',
              'recent_fail_count', 'ip_distinct_accounts', 'impossible_travel', 'user_agent')
EVENT_TYPES = ('login', 'session_use', 'password_reset')
PROFILE_DEFAULTS = dict(home_geo='KR', usual_hours=[8, 23], known_devices=1)


def _norm_event(raw):
    """Merge one author event onto ev() defaults; return (event, filled_keys)."""
    base = fx.ev()  # full default event with all EVENT_KEYS present
    filled = [k for k in EVENT_KEYS if k not in raw]
    event = dict(base)
    for k in EVENT_KEYS:
        if k in raw:
            event[k] = raw[k]
    if event['event_type'] not in EVENT_TYPES:
        raise ValueError('bad event_type: %r' % event['event_type'])
    return event, filled


def _norm_profile(raw):
    raw = raw or {}
    prof = dict(PROFILE_DEFAULTS)
    for k in PROFILE_DEFAULTS:
        if k in raw and raw[k] is not None:
            prof[k] = raw[k]
    prof['usual_hours'] = list(prof['usual_hours'])
    return prof


def _norm_case(raw):
    if raw.get('label') not in ('benign', 'attack'):
        raise ValueError('bad label for case %r' % raw.get('id'))
    events = raw.get('events') or []
    if not events:
        raise ValueError('empty events for case %r' % raw.get('id'))
    allowed = [a for a in (raw.get('allowed') or [])]
    if not allowed or any(a not in fx.ACTIONS for a in allowed):
        raise ValueError('bad allowed set for case %r: %r' % (raw.get('id'), allowed))
    norm_events, filled = [], []
    for e in events:
        ne, fk = _norm_event(e)
        norm_events.append(ne)
        filled.append(fk)
    return dict(id=raw['id'], label=raw['label'], category=raw.get('category', ''),
                events=norm_events, allowed=list(allowed), profile=_norm_profile(raw.get('profile')),
                rationale=raw.get('rationale', ''), _filled=filled)


def load_raw(path=CASES_PATH):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError('Holdout cases not yet authored: %s' % path)
    return json.loads(path.read_text(encoding='utf-8'))


def load_holdout(path=CASES_PATH):
    """Return list of normalized case dicts (same shape as ato_fixtures.CASES)."""
    doc = load_raw(path)
    cases = doc['cases'] if isinstance(doc, dict) else doc
    out = [_norm_case(c) for c in cases]
    ids = [c['id'] for c in out]
    if len(set(ids)) != len(ids):
        raise ValueError('duplicate holdout case ids')
    return out


def authored_by(path=CASES_PATH):
    doc = load_raw(path)
    return doc.get('authored_by', 'unknown') if isinstance(doc, dict) else 'unknown'
