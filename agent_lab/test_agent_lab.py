"""Smoke + safety tests for the recon->exploit agent lab. Stdlib only.

Run:  python agent_lab/test_agent_lab.py   (or: pytest agent_lab/test_agent_lab.py)
"""
import json
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import target as T  # noqa: E402
import fixed_agent as A  # noqa: E402


def _start_target(log_path):
    tgt = T.Target(log_path)
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), T.make_handler(tgt))
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    return httpd, port


def test_allowlist_blocks_off_host():
    """The agent must physically refuse any non-loopback target."""
    for bad in ('http://example.com', 'http://10.0.0.5:80', 'https://evil.test'):
        try:
            A.Agent(bad)
        except PermissionError:
            continue
        raise AssertionError(f'allowlist failed to block {bad}')


def test_end_to_end_takeover(tmp_path_log='_agentlab_test.jsonl'):
    log = Path(tmp_path_log)
    if log.exists():
        log.unlink()
    httpd, port = _start_target(str(log))
    try:
        time.sleep(0.2)
        report = A.Agent(f'http://127.0.0.1:{port}').run()
        assert report['outcome'] == 'takeover', report['outcome']
        assert report['phases']['probe']['vulnerable'] is True
        assert report['phases']['exploit']['takeover'] is True
        # measured lure-touch rate from the target's own request log
        rows = [json.loads(l) for l in log.read_text(encoding='utf-8').splitlines() if l.strip()]
        lures = sum(r['lure'] for r in rows)
        assert lures > 0, 'fixed agent enumerates decoys, expected lure touches'
        p_touch = lures / len(rows)
        assert 0 < p_touch < 1
        print(f'end-to-end: outcome={report["outcome"]} requests={len(rows)} '
              f'lure_touches={lures} measured_p_touch={p_touch:.3f}')
    finally:
        httpd.shutdown()
        if log.exists():
            log.unlink()


if __name__ == '__main__':
    test_allowlist_blocks_off_host()
    print('allowlist test: PASS')
    test_end_to_end_takeover()
    print('all tests: PASS')
