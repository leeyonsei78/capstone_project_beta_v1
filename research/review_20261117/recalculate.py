"""Read-only audit of saved experiments; no HTTP or model calls.

Run from any directory. Writes only review_metrics.json beside this script.
All tests below are exploratory diagnostics, not preregistered inference.
"""
import collections
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent


def read(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8-sig"))


def exact_p(b, c):
    n = b + c
    return min(1.0, 2 * sum(math.comb(n, j) for j in range(min(b, c) + 1)) / 2**n)


def paired_summary(pairs):
    b = sum(a and not b for a, b in pairs)
    c = sum(b and not a for a, b in pairs)
    return dict(n=len(pairs), llm_correct=sum(a for a, _ in pairs),
                comparator_correct=sum(b for _, b in pairs),
                llm_only_correct=b, comparator_only_correct=c,
                exact_mcnemar_two_sided_p=exact_p(b, c))


def main():
    run = "research/ato_holdout_runs/20261117T105512"
    detail = read(run + "/detail.json")
    index = {(x["split"], x["mode"], x["case_id"], x["event_index"]): x for x in detail}
    comparisons = {}
    for mode in ("rules", "rules2"):
        pairs = [(x, index[("holdout", mode, x["case_id"], x["event_index"])])
                 for x in detail if x["split"] == "holdout" and x["mode"] == "llm"]
        groups = collections.defaultdict(list)
        for x, y in pairs:
            groups[x["case_id"]].append((x["correct"], y["correct"]))
        comparisons[mode] = dict(
            events_diagnostic_only=paired_summary([(x["correct"], y["correct"]) for x, y in pairs]),
            cases_all_events_correct=paired_summary([
                (all(a for a, _ in v), all(b for _, b in v)) for v in groups.values()]),
        )

    arch_run = "research/agent_arch_runs/20261117T120319"
    sessions = collections.defaultdict(list)
    for line in (ROOT / arch_run / "requests.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        sessions[row["session"]].append({k: v for k, v in row.items() if k not in ("ts", "session")})
    traces = {}
    for config in ("fixed", "react-flat", "react-graph"):
        values = [v for k, v in sessions.items() if k.startswith(config + "-")]
        hashes = [hashlib.sha256(json.dumps(v, sort_keys=True).encode()).hexdigest() for v in values]
        traces[config] = dict(sessions=len(values), distinct_traces=len(set(hashes)), hashes=hashes)

    # Compare the rule correction's 'any alarm' metric to the earlier definition
    # of takeover: any credential-valid attack event allowed. This is a scoring
    # consistency check, not a claim that every labelled event is malicious.
    state_run = "research/ato_stateful_runs/20261117T112247"
    raw_cases = read(state_run + "/ato_holdout_cases.json")
    cases = raw_cases["cases"] if isinstance(raw_cases, dict) else raw_cases
    cases = {x["id"]: x for x in cases}
    conflicts = []
    for r in read(state_run + "/case_detail.json"):
        if r["split"] != "holdout" or r["label"] != "attack" or not r["caught"]:
            continue
        events = cases[r["id"]]["events"]
        positions = [i for i, (e, a) in enumerate(zip(events, r["actions"]))
                     if a == "allow" and e.get("credential_ok") is True]
        if positions:
            conflicts.append(dict(detector=r["detector"], case_id=r["id"],
                                  allowed_credential_valid_positions=positions, actions=r["actions"]))

    result = dict(
        scope="Saved artifacts only; exploratory reanalysis; no new experiment or model inference",
        inference_limits="Purposive synthetic cases; event dependence; case grouping does not establish population sampling; no confirmatory significance claim",
        holdout_comparisons=comparisons,
        architecture_normalized_trace_counts=traces,
        any_alarm_vs_allow_metric_conflicts=conflicts,
        sources={p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in (
            run + "/detail.json", arch_run + "/requests.jsonl", state_run + "/case_detail.json")},
    )
    (OUT / "review_metrics.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
