"""Fixed-target HTTP lab with prewritten Codex defenses."""
import json
import html
import threading
import uuid
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TARGET = 'http://127.0.0.1:8766'
LOCK = threading.RLock()
STATE = {'defenses': [], 'scan': None, 'plan': None, 'generation': 0}
FIXES = {'sql': 'parameterized_queries', 'xss': 'html_output_encoding', 'idor': 'document_owner_check'}
GUIDES = {
    'sql': {'title': 'SQL 인젝션', 'explanation': '사용자 입력을 SQL 문자열에 연결하면 따옴표와 주석으로 비밀번호 검사를 우회할 수 있습니다. 매개변수 바인딩으로 입력을 데이터로 처리합니다.', 'code': 'db.execute("SELECT name, role FROM users WHERE name = ? AND password = ?", (name, password))'},
    'xss': {'title': '반사형 XSS', 'explanation': '검색어가 인코딩 없이 HTML에 반사됩니다. HTML 본문 출력 전에 html.escape를 적용해 태그가 실행되지 않고 글자로 표시되도록 합니다. 자동 진단은 미인코딩 반사를 검사하며 브라우저 실행을 직접 판정하지 않습니다.', 'code': 'rendered = html.escape(user_input)'},
    'idor': {'title': '객체 접근 권한 누락', 'explanation': 'student가 관리자 문서 1002를 열 수 있습니다. 서버에서 문서 소유자와 현재 사용자를 비교하고 다르면 접근을 거부합니다.', 'code': 'if document["owner"] != session_user:\n    return "Forbidden", 403'}
}
PAYLOAD = '<script>document.body.dataset.xss="executed"</script>'


def validate_target(value):
    value = str(value).strip().rstrip('/')
    if value in ('127.0.0.1', '127.0.0.1:8766', 'localhost:8766', 'http://localhost:8766'):
        value = TARGET
    if value != TARGET:
        raise ValueError('이 앱이 만든 실습 사이트 http://127.0.0.1:8766 만 진단할 수 있습니다.')
    return value


class TargetHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        from app import lab
        parsed = urllib.parse.urlsplit(self.path)
        args = urllib.parse.parse_qs(parsed.query)
        key = parsed.path.removeprefix('/')
        # Lists are replaced atomically; do not acquire the controller lock here:
        # its scan waits synchronously for this HTTP response.
        secure = FIXES.get(key) in STATE['defenses']
        if key in FIXES:
            result = lab({'scenario': key, 'payload': args.get('input', [''])[0], 'secure': secure})
            if key == 'xss':
                body = '<!doctype html><meta charset="utf-8"><h1>검색 결과</h1>' + result['preview']
                kind = 'text/html; charset=utf-8'
            else:
                body = json.dumps(result, ensure_ascii=False)
                kind = 'application/json; charset=utf-8'
                if args.get('view') == ['1']:
                    allowed = bool(result['detail'].get('authenticated_users')) if key == 'sql' and isinstance(result['detail'], dict) else key == 'idor' and isinstance(result['detail'], dict)
                    title = ('로그인 성공' if allowed else '로그인 실패') if key == 'sql' else ('문서 열기 성공' if allowed else '접근 거부')
                    body = '<!doctype html><meta charset="utf-8"><style>body{font:16px/1.7 system-ui;padding:12px;color:#24352f}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h2>' + title + '</h2><pre>' + html.escape(json.dumps(result['detail'], ensure_ascii=False, indent=2)) + '</pre>'
                    kind = 'text/html; charset=utf-8'
        elif key == 'health':
            body, kind = json.dumps({'lab': 'qwen-training-target', 'defenses': STATE['defenses']}), 'application/json'
        elif key == '':
            body = (Path(__file__).parent / 'target.html').read_text(encoding='utf-8').replace('__DEFENSE_STATUS__', '방어 적용됨 · 같은 공격 값으로 다시 확인하세요' if STATE['defenses'] else '취약 상태 · 정상 값부터 입력해 보세요')
            kind = 'text/html; charset=utf-8'
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body.encode())))
        self.send_header('Cache-Control', 'no-store')
        # Script execution is isolated from all same-origin resources, even when opened directly.
        policy = "default-src 'none'; style-src 'unsafe-inline'; form-action http://127.0.0.1:8766; base-uri 'none'"
        if key == '':
            policy += '; frame-src http://127.0.0.1:8766'
        else:
            policy += "; sandbox allow-scripts; script-src 'unsafe-inline'"
        self.send_header('Content-Security-Policy', policy)
        self.end_headers()
        self.wfile.write(body.encode())


def start_target(port=8766):
    server = ThreadingHTTPServer(('127.0.0.1', port), TargetHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def scan(target):
    validate_target(target)
    findings = []
    # Fixed host, fixed paths, no redirects, no user-controlled network destinations.
    for key, payload in [('sql', "admin' -- "), ('xss', PAYLOAD), ('idor', '1002')]:
        path = '/' + key + '?' + urllib.parse.urlencode({'input': payload})
        conn = __import__('http.client', fromlist=['HTTPConnection']).HTTPConnection('127.0.0.1', urllib.parse.urlsplit(TARGET).port, timeout=5)
        try:
            conn.request('GET', path)
            response = conn.getresponse()
            status, body = response.status, response.read(20000).decode()
        finally:
            conn.close()
        if status != 200:
            raise ValueError('실습 대상 응답 오류: ' + str(status))
        vulnerable = PAYLOAD in body if key == 'xss' else json.loads(body)['success'] is True
        findings.append({'type': key, 'vulnerable': vulnerable, 'request': 'GET ' + path,
                         'http_status': status, 'response': body, 'fix': FIXES[key],
                         'guide': GUIDES[key],
                         'evidence': '실행 가능한 script 태그의 미인코딩 반사 확인 (브라우저 실행은 별도 확인)' if key == 'xss' else '가상 관리자 데이터 접근 여부 확인'})
    return {'id': str(uuid.uuid4()), 'target': TARGET, 'at': datetime.now(timezone.utc).isoformat(), 'findings': findings}


def route(path, data):
    if path == '/api/workflow/scan':
        with LOCK:
            report = scan(data.get('target'))
            STATE['scan'], STATE['plan'] = report, None
            return report
    if path == '/api/workflow/reset':
        with LOCK:
            STATE.update(defenses=[], scan=None, plan=None, generation=STATE['generation'] + 1)
        return {'ok': True}
    if path == '/api/workflow/quick-apply':
        with LOCK:
            if not STATE['scan'] or data.get('scan_id') != STATE['scan']['id']:
                raise ValueError('먼저 진단을 실행하세요.')
            STATE['defenses'] = sorted(set(STATE['defenses']) | {f['fix'] for f in STATE['scan']['findings'] if f['vulnerable']})
            return {'applied': STATE['defenses'], 'report': scan(TARGET), 'source': 'Codex가 미리 구현한 방어 코드 (실시간 AI 호출 없음)'}
    raise ValueError('지원하지 않는 작업입니다. Codex 방어안 적용을 사용하세요.')
