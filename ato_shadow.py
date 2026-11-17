"""Deception ('shadow') arm for the ATO simulation. Synthetic and analytic; no LLM call, no network.

Router (per client, never relaxed automatically once confirmed):
  normal -> suspect   : risk function says challenge (client may retry with more verification)
  any    -> locked    : risk function says lock (same as the lock arm)
  allow  -> session   : the client gets the account page, which contains decoys (fake security
                        question, fake API-key menu, fake recovery contact). Touching any decoy
                        CONFIRMS the client and moves it to a shadow account with fake data.
Assumptions to state in the paper (they drive the result):
  * p_touch  : probability that an attacker touches a decoy at each post-login action (swept, not measured)
  * q_benign : probability that a benign user touches a decoy at each action (swept, not measured)
  * n_actions: post-login actions in a session before the attacker would finish
  * a benign user trapped on the shadow costs TRAP_COST friction units (assumption, = lock weight)
"""
import ato_fixtures as fx

TRAP_COST = fx.FRICTION['lock']


def p_confirm(p, n_actions):
    """P(at least one decoy touch within n_actions independent actions)."""
    if not 0 <= p <= 1 or n_actions < 1:
        raise ValueError('p in [0,1], n_actions >= 1')
    return 1 - (1 - p) ** n_actions


def expected_real_actions(p, n_actions):
    """Expected number of actions executed on the REAL account before confirmation
    (the action that touches the decoy is already on the decoy, not the real data)."""
    if p == 0:
        return float(n_actions)
    return sum((1 - p) ** k for k in range(n_actions))


def attacker_session(p_touch, n_actions):
    c = p_confirm(p_touch, n_actions)
    return dict(deflected=c, real_takeover=1 - c, real_actions=expected_real_actions(p_touch, n_actions))


def benign_session(q_benign, n_actions):
    c = p_confirm(q_benign, n_actions)
    return dict(trapped=c, friction=c * TRAP_COST)


def evaluate(campaigns, benign_allowed_sessions, p_touch, q_benign, n_actions):
    """campaigns: list of dicts with 'reached_session' (the defender allowed the login).
    benign_allowed_sessions: number of benign dev-case logins the risk function lets in."""
    reached = [c for c in campaigns if c['reached_session']]
    a = attacker_session(p_touch, n_actions)
    n = len(campaigns)
    k = len(reached)
    b = benign_session(q_benign, n_actions)
    return dict(
        campaigns=n, reached_session=k,
        real_takeover_rate_lock=k / n if n else None,                    # lock arm: a reached session is a takeover
        real_takeover_rate_shadow=k * a['real_takeover'] / n if n else None,
        deflected_rate_shadow=k * a['deflected'] / n if n else None,
        mean_real_actions_before_confirm=a['real_actions'] if k else None,
        benign_trapped_expected=benign_allowed_sessions * b['trapped'],
        benign_trap_friction_expected=benign_allowed_sessions * b['friction'])
