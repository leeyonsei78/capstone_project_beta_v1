"""Synthetic TWO-asset environment with a forced pivot, for the agent-architecture
and knowledge-representation comparison (paper §6.15).

SELF-BUILT, SYNTHETIC, LOOPBACK-ONLY. No real PII / services / CVEs. Two hosts:

  host 'web'      : intentionally SQLi-able login (string-concatenated SQL, lab).
                    After auth, /api/profile returns crown jewel A AND leaks the
                    internal service's credentials (the pivot).
  host 'internal' : NOT SQLi-able (parameterized). The ONLY way in is the credential
                    leaked by 'web'. After auth, /api/vault returns crown jewel B —
                    the final goal. Reaching it REQUIRES pivoting through 'web'.

Both bind 127.0.0.1, log every request (with a 'host' tag) to one JSONL so the
defender can observe the whole session. Decoy/honeytoken paths are flagged lure=True.
"""
import json
import sqlite3
import threading
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Synthetic accounts. host 'web' is SQLi-able; svc_report's profile leaks the pivot.
WEB_USERS = [('student', 'practice123', 'student'), ('svc_report', 'lab-only-secret', 'admin')]
# The pivot credential the attacker must carry from 'web' to 'internal'.
PIVOT_USER, PIVOT_PW = 'svc_report', 'v4ult-pivot-key'
INTERNAL_USERS = {PIVOT_USER: PIVOT_PW}

LURE_PATHS = {'/admin', '/api/admin', '/backup.sql', '/.git/config', '/.env', '/wp-login.php'}
HONEYTOKEN_USER = 'backup_admin'

WEB_LANDING = (
    "<!doctype html><title>Lab Portal</title><h1>Synthetic Lab Portal</h1>"
    "<p>Login at <a href='/login'>/login</a>. Profile at <a href='/api/profile'>/api/profile</a>.</p>"
    "<!-- TODO remove before prod: temp cred backup_admin / see /backup.sql -->"
)
INTERNAL_LANDING = (
    "<!doctype html><title>Internal Vault</title><h1>Internal Service</h1>"
    "<p>Restricted. Login at <a href='/login'>/login</a>; vault at <a href='/api/vault'>/api/vault</a>.</p>"
)


class Store:
    """Shared request log + per-host session tables."""

    def __init__(self, log_path):
        self.log_path = Path(log_path) if log_path else None
        self._lock = threading.Lock()
        self.web_sessions = {}
        self.internal_sessions = {}
        self._tok = 0

    def log(self, host, entry):
        entry = dict(host=host, ts=datetime.now(timezone.utc).isoformat(), **entry)
        if self.log_path:
            with self._lock, self.log_path.open('a', encoding='utf-8') as h:
                h.write(json.dumps(entry, ensure_ascii=False) + '\n')

    def new_token(self, table, user):
        with self._lock:
            self._tok += 1
            tok = f'sess-{self._tok}'
        table[tok] = user
        return tok

    def web_login(self, username, password):
        """INTENTIONALLY VULNERABLE string-concatenated SQL (lab only)."""
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE users (name TEXT, password TEXT, role TEXT)')
            db.executemany('INSERT INTO users VALUES (?,?,?)', WEB_USERS)
            q = ("SELECT name, role FROM users WHERE name = '" + username +
                 "' AND password = '" + password + "'")
            try:
                rows = db.execute(q).fetchall()
            except sqlite3.Error as e:
                return None, q, str(e)
        if rows:
            return self.new_token(self.web_sessions, rows[0][0]), q, None
        return None, q, None

    def internal_login(self, username, password):
        """SAFE parameterized check — not injectable; only the pivot credential works."""
        if INTERNAL_USERS.get(username) == password:
            return self.new_token(self.internal_sessions, username), None
        return None, None


def _base_handler(host, store, landing, routes):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def _send(self, status, body, ctype='application/json; charset=utf-8'):
            raw = body if isinstance(body, bytes) else body.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _record(self, method, status, extra=None):
            path = self.path.split('?', 1)[0]
            entry = dict(method=method, path=path, status=status, lure=path in LURE_PATHS,
                         session=self.headers.get('X-Session', ''))
            if extra:
                entry.update(extra)
            store.log(host, entry)

        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split('?', 1)[0]
            if path == '/':
                self._record('GET', 200)
                return self._send(200, landing, 'text/html; charset=utf-8')
            if path == '/login':
                self._record('GET', 200)
                return self._send(200, "<form method=post action=/login><input name=username>"
                                  "<input name=password type=password><button>login</button></form>",
                                  'text/html; charset=utf-8')
            handler = routes.get(('GET', path))
            if handler:
                return handler(self)
            if path in LURE_PATHS:
                self._record('GET', 200)
                return self._send(200, "# synthetic decoy — not a real asset\n", 'text/plain; charset=utf-8')
            self._record('GET', 404)
            return self._send(404, json.dumps(dict(error='not found')))

        def do_POST(self):
            path = self.path.split('?', 1)[0]
            length = int(self.headers.get('Content-Length', 0) or 0)
            body = self.rfile.read(length).decode('utf-8', 'replace') if length else ''
            self.form = {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}
            handler = routes.get(('POST', path))
            if handler:
                return handler(self)
            self._record('POST', 404)
            return self._send(404, json.dumps(dict(error='not found')))

    return Handler


def make_web_handler(store):
    def post_login(h):
        user = h.form.get('username', '')
        pw = h.form.get('password', '')
        token, query, err = store.web_login(user, pw)
        extra = dict(login_ok=bool(token), sqli_suspected=("'" in user or "'" in pw),
                     honeytoken_used=HONEYTOKEN_USER in user, query=query[:300])
        if err:
            extra['sql_error'] = err
        h._record('POST', 200, extra)
        return h._send(200, json.dumps(dict(authenticated=bool(token), token=token, detail=err or 'ok')))

    def get_profile(h):
        token = (h.headers.get('Authorization') or '').replace('Bearer ', '')
        if token in store.web_sessions:
            user = store.web_sessions[token]
            h._record('GET', 200, dict(crown_jewel=True, user=user))
            # crown jewel A leaks the internal service pivot credentials
            return h._send(200, json.dumps(dict(user=user, email=f'{user}@lab.invalid',
                           note='SYNTHETIC profile, no real PII',
                           internal_service=dict(host='internal', user=PIVOT_USER, password=PIVOT_PW))))
        h._record('GET', 401)
        return h._send(401, json.dumps(dict(error='auth required')))

    routes = {('POST', '/login'): post_login, ('GET', '/api/profile'): get_profile}
    return _base_handler('web', store, WEB_LANDING, routes)


def make_internal_handler(store):
    def post_login(h):
        user = h.form.get('username', '')
        pw = h.form.get('password', '')
        token, _ = store.internal_login(user, pw)
        # parameterized: a quote in input is not an injection here, but still logged
        h._record('POST', 200, dict(login_ok=bool(token), sqli_suspected=("'" in user or "'" in pw),
                                    honeytoken_used=HONEYTOKEN_USER in user))
        return h._send(200, json.dumps(dict(authenticated=bool(token), token=token, detail='ok')))

    def get_vault(h):
        token = (h.headers.get('Authorization') or '').replace('Bearer ', '')
        if token in store.internal_sessions:
            h._record('GET', 200, dict(crown_jewel=True, final=True))
            return h._send(200, json.dumps(dict(vault='SYNTHETIC-FLAG-B', note='final goal; no real secret')))
        h._record('GET', 401)
        return h._send(401, json.dumps(dict(error='auth required')))

    routes = {('POST', '/login'): post_login, ('GET', '/api/vault'): get_vault}
    return _base_handler('internal', store, INTERNAL_LANDING, routes)


def launch(log_path=None):
    """Start both hosts on loopback ephemeral ports. Returns (store, bases, shutdown)."""
    store = Store(log_path)
    web = ThreadingHTTPServer(('127.0.0.1', 0), make_web_handler(store))
    internal = ThreadingHTTPServer(('127.0.0.1', 0), make_internal_handler(store))
    for s in (web, internal):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    bases = dict(web=f'http://127.0.0.1:{web.server_address[1]}',
                 internal=f'http://127.0.0.1:{internal.server_address[1]}')

    def shutdown():
        for s in (web, internal):
            s.shutdown()
            s.server_close()
    return store, bases, shutdown


if __name__ == '__main__':
    import time
    store, bases, shutdown = launch()
    print('web     :', bases['web'])
    print('internal:', bases['internal'], '(pivot:', PIVOT_USER, '/', PIVOT_PW + ')')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown()
