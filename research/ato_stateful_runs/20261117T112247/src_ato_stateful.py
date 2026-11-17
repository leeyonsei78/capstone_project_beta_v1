"""Corrective ATO detectors motivated by the weaknesses the independent holdout
(see ato_holdout / paper §6.13) exposed:

  rules3         — the shared-IP signal now requires corroboration, so legitimate
                   CGNAT/VPN users on a known device are no longer locked.
  rules_stateful — per-episode history adds a sequence signal (impossible travel,
                   geo jump within the episode, or a reset followed by a new device)
                   on top of rules3, catching known-device session hijacks that a
                   single-event rule allows.

These detectors are author-designed, so the RULES themselves are not independent;
but they are re-validated on the SAME rules-blind holdout (ato_holdout), so the
holdout numbers remain independent evidence. All rule-based: deterministic, no
model, no network. Scoring helpers (per-event and case-level) live here too.
"""
import ato_fixtures as fx

IP_THRESH = 5  # matches ato_fixtures.rules; here it locks only when corroborated
SEVERITY = {a: i for i, a in enumerate(fx.ACTIONS)}  # allow < challenge < lock


def _in_hours(event, profile):
    lo, hi = profile['usual_hours']
    h = event['local_hour']
    return (lo <= h <= hi) if lo <= hi else (h >= lo or h <= hi)


def rules3(event, profile):
    """IP-corroboration baseline. A high shared-IP count locks ONLY together with
    another risk signal (unknown device or a failed credential); the fail-count lock
    threshold is 5 (vs rules2's 3). Legitimate shared-IP users on a known device at
    home therefore stay out of lock."""
    high_ip = event['ip_distinct_accounts'] >= IP_THRESH
    if event['recent_fail_count'] >= 5 or (high_ip and (not event['device_known'] or not event['credential_ok'])):
        return 'lock'
    if (not event['device_known'] or event['geo'] != profile['home_geo']
            or not _in_hours(event, profile) or event['event_type'] != 'login'):
        return 'challenge'
    return 'allow'


def _seq_signal(event, prior):
    """True if the episode-so-far makes this event suspicious regardless of its own
    single-event attributes: the impossible-travel flag, a geo change from the
    previous event, or a password_reset earlier in the episode now followed by an
    unknown device."""
    if event.get('impossible_travel'):
        return True
    if prior and event['geo'] != prior[-1]['geo']:
        return True
    if any(e['event_type'] == 'password_reset' for e in prior) and not event['device_known']:
        return True
    return False


def rules_stateful(events, profile):
    """Return one action per event: rules3 escalated to at least 'challenge' when a
    sequence signal is present in the episode so far."""
    actions, prior = [], []
    for e in events:
        a = rules3(e, profile)
        if _seq_signal(e, prior) and SEVERITY[a] < SEVERITY['challenge']:
            a = 'challenge'
        actions.append(a)
        prior.append(e)
    return actions


# ---- scoring helpers -------------------------------------------------------

def score_per_event(cases, action_of):
    """action_of(event, profile) -> action. Returns a per-event aggregate dict
    (same metric family as experiments/run_ato_holdout.score)."""
    tot = corr = b_ev = b_corr = b_fric = b_lock = a_ev = a_miss = 0
    for c in cases:
        for e in c['events']:
            a = action_of(e, c['profile'])
            ok = a in c['allowed']
            tot += 1
            corr += ok
            if c['label'] == 'benign':
                b_ev += 1
                b_corr += ok
                b_fric += fx.FRICTION[a]
                b_lock += a == 'lock'
            else:
                a_ev += 1
                a_miss += a == 'allow'
    return dict(events=tot, correct=corr, accuracy=round(corr / tot, 4) if tot else None,
                benign_events=b_ev, benign_friction=b_fric, benign_locks=b_lock,
                attack_events=a_ev, attack_misses=a_miss,
                attack_miss_rate=round(a_miss / a_ev, 4) if a_ev else None)


def score_case_level(cases, actions_of):
    """actions_of(events, profile) -> [action per event]. Case-level metric: a benign
    case is 'clean' if no event is locked; an attack case is 'caught' if at least one
    event is challenged or locked (a single challenge stops the takeover). Returns
    (summary, rows)."""
    b = b_clean = a = a_caught = 0
    rows = []
    for c in cases:
        acts = actions_of(c['events'], c['profile'])
        multi = len(c['events']) > 1
        if c['label'] == 'benign':
            b += 1
            clean = all(x != 'lock' for x in acts)
            b_clean += clean
            rows.append(dict(id=c['id'], label='benign', multi_event=multi, clean=clean, actions=acts))
        else:
            a += 1
            caught = any(x in ('challenge', 'lock') for x in acts)
            a_caught += caught
            rows.append(dict(id=c['id'], label='attack', multi_event=multi, caught=caught, actions=acts))
    return dict(benign_cases=b, benign_clean=b_clean, attack_cases=a, attack_caught=a_caught), rows


def stateless(action_of):
    """Wrap a per-event detector into an actions_of(events, profile) callable."""
    return lambda events, profile: [action_of(e, profile) for e in events]
