"""Synthetic vulnerable web target for the recon->exploit agent experiment.

SELF-BUILT, SYNTHETIC, LOOPBACK-ONLY. Binds 127.0.0.1 by default. No real PII,
no real services, no real CVEs. This exists only so an attack agent can generate
*real HTTP traffic* against something we control, and so the defender can observe
request logs. It is intentionally insecure (string-concatenated SQL) FOR THE LAB.

Honeytoken / decoy endpoints are flagged lure=True in the request log so we can
*measure* the lure-touch rate that research/ato_shadow currently only assumes.

Run:  python agent_lab/target.py --port 8700 --log run.jsonl
"""
import argparse
import json
import sqlite3
import time
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Synthetic accounts only. No real person, no real credential.
USERS = [('student', 'practice123', 'student'), ('svc_report', 'lab-only-secret', 'admin')]

# Endpoints that are decoys / honeytokens. Touching any of these is a "lure touch".
# A real user/app never requests these; only someone enumerating does.
LURE_PATHS = {'/admin', '/api/admin', '/backup.sql', '/.git/config', '/.env', '/wp-login.php'}
# A honeytoken credential planted in an HTML comment on '/'. Using it = caught.
HONEYTOKEN_USER = 'backup_admin'


class Target:
    """Holds state + the (intentionally vulnerable) auth logic. One sqlite per request."""

    def __init__(self, log_path):
        self.log_path = Path(log_path) if log_path else None
        self.sessions = {}  # token -> username
        self._tok = 0

    def log(self, entry):
        entry['ts'] = datetime.now(timezone.utc).isoformat()
        if self.log_path:
            with self.log_path.open('a', encoding='utf-8') as h:
                h.write(json.dumps(entry, ensure_ascii=False) + '\n')

    def login(self, username, password):
        """INTENTIONALLY VULNERABLE: string-concatenated SQL (lab only)."""
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE users (name TEXT, password TEXT, role TEXT)')
            db.executemany('INSERT INTO users VALUES (?,?,?)', USERS)
            query = ("SELECT name, role FROM users WHERE name = '" + username +
                     "' AND password = '" + password + "'")
            try:
                rows = db.execute(query).fetchall()
            except sqlite3.Error as e:
                return None, query, str(e)
        if rows:
            self._tok += 1
            token = f'sess-{self._tok}'
            self.sessions[token] = rows[0][0]
            return token, query, None
        return None, query, None


LANDING = (
    "<!doctype html><title>Lab Portal</title>"
    "<h1>Synthetic Lab Portal</h1>"
    "<p>Login at <a href='/login'>/login</a>. Profile at <a href='/api/profile'>/api/profile</a>.</p>"
    "<!-- TODO remove before prod: temp cred backup_admin / see /backup.sql -->"
)


def make_handler(target):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def _send(self, status, body, ctype='application/json; charset=utf-8'):
            raw = body if isinstance(body, bytes) else body.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(raw)

        def _record(self, method, status, extra=None):
            path = self.path.split('?', 1)[0]
            entry = dict(method=method, path=path, status=status,
                         lure=path in LURE_PATHS, client=self.client_address[0],
                         session=self.headers.get('X-Session', ''))
            if extra:
                entry.update(extra)
            target.log(entry)

        def log_message(self, *a):  # silence default stderr logging
            pass

        def do_GET(self):
            path = self.path.split('?', 1)[0]
            if path == '/':
                self._record('GET', 200)
                return self._send(200, LANDING, 'text/html; charset=utf-8')
            if path == '/login':
                self._record('GET', 200)
                return self._send(200, "<form method=post action=/login>"
                                  "<input name=username><input name=password type=password>"
                                  "<button>login</button></form>", 'text/html; charset=utf-8')
            if path == '/api/profile':
                token = (self.headers.get('Authorization') or '').replace('Bearer ', '')
                if token in target.sessions:
                    user = target.sessions[token]
                    self._record('GET', 200, dict(crown_jewel=True, user=user))
                    return self._send(200, json.dumps(dict(user=user, email=f'{user}@lab.invalid',
                                                           note='SYNTHETIC profile, no real PII')))
                self._record('GET', 401)
                return self._send(401, json.dumps(dict(error='auth required')))
            if path in LURE_PATHS:
                # Decoys: look plausible, return something, but are traps.
                self._record('GET', 200)
                return self._send(200, "# synthetic decoy — not a real asset\n", 'text/plain; charset=utf-8')
            self._record('GET', 404)
            return self._send(404, json.dumps(dict(error='not found')))

        def do_POST(self):
            path = self.path.split('?', 1)[0]
            length = int(self.headers.get('Content-Length', 0) or 0)
            body = self.rfile.read(length).decode('utf-8', 'replace') if length else ''
            form = {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}
            if path == '/login':
                username = form.get('username', '')
                password = form.get('password', '')
                token, query, err = target.login(username, password)
                caught = HONEYTOKEN_USER in username
                sqli = ("'" in username or "'" in password)
                extra = dict(login_ok=bool(token), sqli_suspected=sqli,
                             honeytoken_used=caught, query=query[:300])
                if err:
                    extra['sql_error'] = err
                self._record('POST', 200, extra)
                return self._send(200, json.dumps(dict(authenticated=bool(token),
                                  token=token, detail=err or 'ok')))
            self._record('POST', 404)
            return self._send(404, json.dumps(dict(error='not found')))

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1', help='loopback only by default')
    ap.add_argument('--port', type=int, default=8700)
    ap.add_argument('--log', default='')
    args = ap.parse_args()
    if args.host not in ('127.0.0.1', 'localhost', '::1'):
        # Guard against accidentally exposing the vulnerable target off-host.
        raise SystemExit('refusing non-loopback bind: ' + args.host)
    target = Target(args.log)
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(target))
    print(f'target listening on http://{args.host}:{args.port}  log={args.log or "(none)"}', flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
