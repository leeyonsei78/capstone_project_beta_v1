import html
import json
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parent


def lab(data):
    scenario = data.get('scenario')
    value = str(data.get('payload', ''))[:2000]
    secure = data.get('secure', False) is True
    if scenario == 'sql':
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE users (name TEXT, password TEXT, role TEXT)')
            db.executemany('INSERT INTO users VALUES (?, ?, ?)', [('student', 'practice123', 'student'), ('admin', 'lab-only-secret', 'admin')])
            if secure:
                query = 'SELECT name, role FROM users WHERE name = ? AND password = ?'
                rows = db.execute(query, (value, 'wrong-password')).fetchall()
            else:
                query = "SELECT name, role FROM users WHERE name = '" + value + "' AND password = 'wrong-password'"
                try:
                    rows = db.execute(query).fetchall()
                except sqlite3.Error as e:
                    return dict(success=False, detail=str(e), code=query)
            return dict(success=bool(rows), detail={'authenticated_users': rows}, code=query,
                        lesson='매개변수 바인딩은 입력을 SQL 문법이 아닌 데이터로 처리합니다.')
    if scenario == 'xss':
        rendered = html.escape(value) if secure else value
        return dict(success=None, detail='아래 격리된 미리보기에서 실행 여부를 확인하세요. 빨간 XSS EXECUTED 표시가 공격 실행 증거입니다.',
                    preview=rendered, code='html.escape(user_input)' if secure else 'HTML에 사용자 입력을 그대로 삽입',
                    lesson='출력 문맥에 맞게 인코딩하세요. 미리보기는 sandbox iframe 안에서만 실행됩니다.')
    if scenario == 'idor':
        documents = {'1001': {'owner': 'student', 'title': '나의 실습 노트'}, '1002': {'owner': 'admin', 'title': '관리자 전용 가상 보고서'}}
        doc = documents.get(value)
        allowed = bool(doc) and (not secure or doc['owner'] == 'student')
        return dict(success=bool(allowed and doc['owner'] != 'student'), detail=doc if allowed else '접근 거부 또는 문서 없음',
                    code='document.owner == session.user' if secure else 'documents.get(request.document_id)',
                    lesson='현재 로그인 사용자는 student입니다. 서버에서 객체 소유권을 검사해야 합니다.')
    raise ValueError('알 수 없는 실습')


class Handler(BaseHTTPRequestHandler):
    def send(self, status, body, content_type='application/json; charset=utf-8'):
        raw = body if isinstance(body, bytes) else body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == '/':
            self.send(200, (ROOT / 'dashboard.html').read_text(encoding='utf-8'), 'text/html; charset=utf-8')
        elif self.path == '/ai':
            self.send(200, (ROOT / 'ai.html').read_text(encoding='utf-8'), 'text/html; charset=utf-8')
        elif self.path in ('/api/ai/models', '/api/ai/runs') or self.path.startswith('/api/ai/job?'):
            try:
                import ai_study
                if self.path == '/api/ai/models':
                    result = {'models': ai_study.available_models()}
                elif self.path == '/api/ai/runs':
                    result = {'runs': ai_study.list_runs()}
                else:
                    result = ai_study.get(urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get('id', [''])[0])
                self.send(200, json.dumps(result, ensure_ascii=False))
            except Exception as e:
                self.send(400, json.dumps({'error': str(e)}))
        elif self.path == '/research':
            self.send_response(302)
            self.send_header('Location', '/research/')
            self.end_headers()
        elif self.path.startswith('/research/'):
            name = self.path[len('/research/'):] or 'index.html'
            allowed = {'index.html', 'paper_revision.html', 'summary.json', 'http_trials.csv', 'http_summary.csv', 'behavior_trials.csv', 'behavior_episodes.json', 'pilot_results.png', 'pilot_results.svg'}
            if name not in allowed:
                self.send(404, '{}')
                return
            mime = {'.html': 'text/html; charset=utf-8', '.json': 'application/json; charset=utf-8', '.csv': 'text/csv; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml'}
            artifact = ROOT / 'research' / 'results' / name
            if not artifact.is_file():
                self.send(404, '{}')
                return
            self.send(200, artifact.read_bytes(), mime[artifact.suffix])
        elif self.path == '/practice':
            self.send(200, (ROOT / 'index.html').read_text(encoding='utf-8'), 'text/html; charset=utf-8')
        elif self.path == '/api/health':
            self.send(200, json.dumps({'app': 'qwen-security-lab', 'version': 4}))
        else:
            self.send(404, '{}')

    def do_POST(self):
        # Reject cross-origin form and fetch requests to the local lab.
        if self.headers.get('Host') != '127.0.0.1:8765' or self.headers.get('Origin') not in (None, 'http://127.0.0.1:8765'):
            self.send(403, '{}')
            return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 16384:
                raise ValueError('요청 크기 제한')
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                raise ValueError('JSON 요청만 허용합니다')
            data = json.loads(self.rfile.read(size))
            if self.path == '/api/ai/start':
                import ai_study
                result = ai_study.start(data)
            elif self.path.startswith('/api/workflow/'):
                from workflow import route
                result = route(self.path, data)
            elif self.path == '/api/run':
                result = lab(data)
            else:
                self.send(404, '{}')
                return
            self.send(200, json.dumps(result, ensure_ascii=False))
        except Exception as e:
            self.send(400, json.dumps({'error': str(e)}, ensure_ascii=False))


if __name__ == '__main__':
    from workflow import start_target
    start_target()
    print('QWEN SECURITY LAB → http://127.0.0.1:8765', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 8765), Handler).serve_forever()
