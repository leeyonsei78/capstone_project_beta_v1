"""Build a paper-ready local-study supplement from preserved measured artifacts."""
import argparse
import base64
import csv
import hashlib
import html
import json
import math
import shutil
import statistics
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
R = ROOT / 'research'
LABELS = dict(none='방어 없음', rules='고정 규칙', always_safe='항상 안전한 구현',
              ai_sync='동기 AI 방어', ai_async='비동기 AI 방어')


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def quantile(values, p):
    return sorted(values)[max(0, math.ceil(len(values) * p) - 1)] if values else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    args = parser.parse_args()
    folder = args.run.resolve()
    manifest = read(folder / 'manifest.json')
    jobs = read(folder / 'results.json')
    if set(manifest['config']['modes']) != set(LABELS) or manifest['config']['repeats'] != 3 or manifest['config']['gap'] != 0.5 or len(manifest['cases']) != 10:
        parser.error('This paper template requires the documented 5-condition, 3-repeat, 10-case, 0.5-second protocol')
    expected = {(b['repeat'], m) for b in manifest['schedule'] for m in b['modes']}
    assert {(j['repeat'], j['mode']) for j in jobs} == expected, 'Incomplete schedule'
    assert len(jobs) == len(expected), 'Duplicate campaigns'
    for name, digest in manifest['source_sha256'].items():
        assert hashlib.sha256((folder / name.replace('/', '_')).read_bytes()).hexdigest() == digest
    originals = []
    for path in sorted((R / 'ai_runs').glob('*.json')):
        value = read(path)
        if 'id' in value:
            originals.append((path, value))
    originals.sort(key=lambda item: item[1]['created_at'])
    manual = [(p, j) for p, j in originals if j['created_at'].startswith('2026-11-16') and j['status'] == 'completed' and j['rounds'] == 3]
    old_failures = [(p, j) for p, j in originals if j['status'] == 'failed']
    smoke = [(p, j) for p, j in originals if j['status'] == 'completed' and j['rounds'] != 3]
    aggregates = []
    for mode in LABELS:
        selected = [j for j in jobs if j['mode'] == mode]
        completed = [j for j in selected if j['status'] == 'completed']
        rows = [r for j in completed for r in j['trials']]
        calls = [c for j in completed for c in j['calls']]
        a = dict(mode=mode, completed=len(completed), failed=len(selected) - len(completed),
                 attack_requests=sum(r['attack'] for r in rows),
                 attack_successes=sum(r['attack_success'] for r in rows),
                 normal_requests=sum(not r['attack'] for r in rows),
                 normal_preserved=sum(r['normal_preserved'] for r in rows),
                 positive_logins=sum(not r['attack'] and bool(r['expected']) for r in rows),
                 positive_logins_preserved=sum(r['normal_preserved'] and bool(r['expected']) for r in rows),
                 normal_rule_blocks=sum(not r['attack'] and r['status'] == 403 for r in rows),
                 pre_patch_successes=sum(r['attack_success'] and not r['policy_active'] for r in rows),
                 compromised_campaigns=sum(any(r['attack_success'] for r in j['trials']) for j in completed),
                 llm_calls=len(calls),
                 inference_seconds=sum(c.get('inference_seconds', 0) for c in calls),
                 queue_seconds=sum(c.get('queue_seconds', 0) for c in calls),
                 prompt_tokens=sum(c.get('prompt_eval_count') or 0 for c in calls),
                 output_tokens=sum(c.get('eval_count') or 0 for c in calls),
                 http_p50_ms=quantile([r['http_ms'] for r in rows], .5),
                 http_p95_ms=quantile([r['http_ms'] for r in rows], .95),
                 decision_p95_ms=quantile([r['decision_to_response_ms'] for r in rows], .95),
                 mean_wall_seconds=statistics.mean(j['wall_seconds'] for j in completed) if completed else None)
        aggregates.append(a)
    out = R / 'results'
    out.mkdir(exist_ok=True)
    archive = R / 'archive' / 'before_local_ai_update'
    archive.mkdir(parents=True, exist_ok=True)
    for path in [R / 'REPORT.md', out / 'index.html', out / 'paper_revision.html']:
        if path.exists() and not (archive / path.name).exists():
            shutil.copyfile(path, archive / path.name)
    provenance = dict(built_at=datetime.now(timezone.utc).isoformat(), replay_folder=str(folder.relative_to(ROOT)),
                      replay_manifest_sha256=hashlib.sha256((folder / 'manifest.json').read_bytes()).hexdigest(),
                      replay_files={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.glob('*.json')},
                      manual_files=[dict(file=str(p.relative_to(ROOT)), id=j['id'], sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p, j in originals],
                      original_paper=read(R / 'paper_provenance.json'), aggregates=aggregates)
    for name in ('app.py', 'ai_study.py'):
        raw = (ROOT / name).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        assert all(j['source_sha256'][name] == digest for _, j in manual), 'Manual source not available'
        (folder / ('manual_source_' + name)).write_bytes(raw)
    (out / 'local_study_summary.json').write_text(json.dumps(provenance, ensure_ascii=False, indent=2), encoding='utf-8')
    with (out / 'local_study_summary.csv').open('w', newline='', encoding='utf-8-sig') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(aggregates[0]))
        writer.writeheader()
        writer.writerows(aggregates)
    md, web = [], []
    def heading(level, text):
        md.append('#' * level + ' ' + text)
        web.append(f'<h{level}>{html.escape(text)}</h{level}>')
    def paragraph(text):
        md.append(text)
        web.append('<p>' + html.escape(text) + '</p>')
    def table(headers, rows):
        md.append('| ' + ' | '.join(headers) + ' |\n| ' + ' | '.join('---' for _ in headers) + ' |\n' + '\n'.join('| ' + ' | '.join(str(c) for c in row) + ' |' for row in rows))
        web.append('<table><thead><tr>' + ''.join('<th>' + html.escape(h) + '</th>' for h in headers) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + html.escape(str(c)) + '</td>' for c in row) + '</tr>' for row in rows) + '</tbody></table>')
    by_mode = {a['mode']: a for a in aggregates}
    def fraction(mode, success, total):
        a = by_mode[mode]
        return f"{a[success]}/{a[total]}"
    heading(1, '로컬 SQL 인증 테스트베드에서 LLM 방어 정책 적용 시점의 예비 평가')
    paragraph('논문 반영용 실험·결과 보완본 | 2026-11-16 | 원본 논문은 보존. 이 문서는 문헌 검토를 대체하는 최종 투고본이 아니라 실제 측정에 근거한 초록·방법·결과·논의 초안이다.')
    heading(2, '초록')
    paragraph('Docker 없이 Windows 로컬 HTTP 서버와 SQLite를 구성하여 Qwen 기반 SQL 인증 공격·방어의 실행 가능성과 정책 적용 시점을 평가하였다. 수동 AI 공격 캠페인에서는 방어 없음에서 인증 우회가 2/3회 발생했고 고정 규칙과 동기·비동기 AI 방어에서는 관측되지 않았다. 이후 공격 4종과 정상 대조 6종을 동일 순서로 재생하는 5조건·3반복 실험을 수행하였다. 재생 실험의 공격 성공은 방어 없음 ' + fraction('none', 'attack_successes', 'attack_requests') + ', 고정 규칙 ' + fraction('rules', 'attack_successes', 'attack_requests') + ', 항상 안전한 구현 ' + fraction('always_safe', 'attack_successes', 'attack_requests') + ', 동기 AI ' + fraction('ai_sync', 'attack_successes', 'attack_requests') + ', 비동기 AI ' + fraction('ai_async', 'attack_successes', 'attack_requests') + '였다. 이 결과는 사전 적용된 안전한 구현의 효과와 비동기 패치 전 노출 가능성을 보여주지만, AI의 추가 탐지 효과나 운영 환경 성능을 입증하지 않는다. 입력은 의도적으로 구성한 개발 사례이며 독립 보류 평가가 아니다.')
    heading(2, '1. 연구 질문과 실험 범위')
    paragraph('RQ1: 자체 취약 로그인에서 실제 모델이 생성한 입력으로 인증 우회와 방어 적용을 관찰할 수 있는가? RQ2: 동일한 고정 입력에서 규칙 차단·항상 안전한 구현·동기/비동기 정책 선택은 인증 우회와 정상 기능 유지에 어떤 차이를 보이는가? RQ3: 비동기 분석이 완료되기 전 요청이 처리될 때 피해가 발생하는가? AI는 검증된 monitor/parameterize 중 하나를 선택하며 새 방어 코드를 생성하지 않는다.')
    heading(2, '2. 환경 및 재현 방법')
    paragraph(f"실행 환경: {manifest['os']}, Python {manifest['python'].split()[0]}, Ollama {manifest.get('ollama_version', {}).get('version', '기록 없음')}, 모델 {manifest['config']['model']}. 모든 공격 대상은 127.0.0.1의 캠페인별 임시 포트이며 외부 서버를 사용하지 않았다. HTTP 서버·SQLite는 Python 표준 라이브러리다. Docker/WSL/microVM 격리 성능을 평가하지 않았다.")
    model = next(m for m in manifest['ollama_tags']['models'] if m['name'] == manifest['config']['model'])
    paragraph(f"모델 식별값: {model['digest']}. 양자화: {model['details']['quantization_level']}. 추론 설정: {json.dumps(manifest['options'])}. GPU 종류·점유율은 이번 manifest에서 별도 측정하지 않았으므로 과거 GPU 스냅샷을 현재 실측값으로 기재하지 않는다. 모델과 자원을 공유하는 다른 프로세스의 영향을 완전히 배제했다고 주장하지 않는다.")
    paragraph('재현 명령: python -m unittest -v → python experiments/run_sql_replay.py --repeats 3 --gap 0.5 → python experiments/build_local_paper.py --run research/replay_runs/<실행ID>. 실행마다 새 디렉터리를 만들며 실행 전 manifest, 소스 사본·해시, 요청/응답, 정책 이벤트, 모델 입출력·토큰·대기·추론 시간을 저장한다. Ollama 호출 실패는 대체 답변 없이 failed로 저장한다. 기존 추론 코드의 타임아웃은 서버 측 생성 취소를 보장하지 않는다.')
    heading(2, '3. 실험 A: 실제 AI 공격·방어 예비 캠페인')
    paragraph('공격자는 직전 HTTP 응답을 포함한 제한된 이력을 보고 사용자명 입력을 생성했다. 비밀번호는 고정 오답이다. 방어 없음과 규칙 조건에서도 공격자 Qwen을 호출했다. 같은 모델을 별도 문맥으로 공격·방어에 사용하며 추론은 직렬화되었다. SQL 패치는 한 번 적용되면 유지된다. 동기 방어는 매 시도 분석하고 비동기는 적용 후 분석을 생략한다. 정상 대조는 잘못된 비밀번호 두 건으로 정상 로그인 성공률이나 FPR을 측정하지 않는다.')
    table(['조건', '캠페인 ID', '인증 우회/시도', '시작→패치(초)', '전체(초)', '모델 호출'],
          [[LABELS[j['mode']], j['id'], f"{j['summary']['authentication_bypasses']}/{j['summary']['attack_attempts']}", j['summary']['policy_effective_seconds'], j['summary']['wall_seconds'], j['summary']['llm_calls']] for _, j in manual])
    paragraph(f'표에는 2026-11-16의 완료된 3시도 캠페인 {len(manual)}개를 모두 포함했다. 고정 규칙 중복 실행도 제외하지 않았다. 별도 1시도 기능 확인 {len(smoke)}개는 주 비교표에서 분리했으며 이전 타임아웃 실패 {len(old_failures)}개는 실패 목록에 보존했다. 실패를 차단 성공으로 세거나 성공 캠페인과 합쳐 성능을 계산하지 않았다. 실패 원인은 타임아웃이며 환경·모델 차이가 있어 이번 재생 실험의 실패율과 합치지 않는다.')
    paragraph('수동 비동기 캠페인에서는 첫 일반 사용자명 요청 후 두 번째 요청 전에 SQL 패치가 적용되었다. 따라서 우회가 없었다는 사실은 첫 요청부터 방어가 준비되었다는 뜻이 아니다. 동기 6회 대 비동기 4회의 호출 수 차이도 있어 전체 시간 차이를 비동기 실행만의 효과로 해석할 수 없다. rules 조건의 HTTP 403은 기존 실행기 내부 차단이며 서버 왕복 시간이 0으로 기록된다. 새 재생 실험은 실제 HTTP 핸들러에서 차단하므로 두 실험의 HTTP 시간을 직접 비교하지 않는다.')
    heading(2, '4. 실험 B: 동일 입력 재생 설계')
    paragraph('10개 사례는 공격 4개, 올바른 비밀번호 로그인 4개, 틀린 비밀번호와 없는 계정 각 1개로 구성했다. 정상 계정 O\'Reilly와 team--blue 및 규칙이 놓치는 공격 문법은 SQL 문자열 조합과 정규식의 한계를 드러내기 위해 의도적으로 작성했다. 개발 중 테스트를 통해 취약 구현의 공격 성공과 안전 구현의 정상 동작을 확인했다. 규칙에 맞춰 구성한 사례이므로 일반적 공격 분포나 자연 트래픽을 대표하지 않는다.')
    paragraph('5조건을 각각 3회 실행했다. 반복마다 입력 순서와 조건 순서를 seed로 섞되 같은 반복의 모든 조건에 동일한 입력 순서를 사용했다. 총 150 HTTP 요청이며 독립 사례 150종이 아니다. 요청마다 같은 초기 DB를 만들고 캠페인마다 방어 상태와 이력을 초기화했다. 응답 후 0.5초 간격의 순차 요청이므로 일정 도착률 부하가 아니며 동기 분석은 다음 요청 시각도 늦춘다. AI 공격자는 사용하지 않고 Qwen 방어자만 호출한다. 두 AI 조건 모두 영구 패치 후에는 추가 분석을 생략한다. 수동 실험과 정책 구현이 달라 별도로 보고한다.')
    paragraph('공격 성공은 공격 레이블 요청의 비인가 인증, 정상 기능 유지는 HTTP 200·SQL 오류 없음·기대 인증 사용자 집합 일치로 정의했다. 잘못된 비밀번호 거부와 올바른 비밀번호 인증을 모두 포함한다. 정상 규칙 차단은 정상 레이블의 HTTP 403이며 전체 시스템의 운영 FPR이 아니다. AI의 parameterize는 안전한 구현 선택이므로 그 자체를 악성 판정이나 오탐으로 세지 않는다. 평균·백분위수는 이 개발 입력의 기술 통계이며 신뢰구간이나 유의성 검정을 제시하지 않는다.')
    heading(2, '5. 동일 입력 재생 결과')
    table(['조건', '완료/실패 캠페인', '공격 성공/요청', '성공 발생 캠페인', '정상 유지/요청', '정상 로그인 성공', '정상 규칙 차단', '모델 호출'],
          [[LABELS[a['mode']], f"{a['completed']}/{a['failed']}", f"{a['attack_successes']}/{a['attack_requests']}", f"{a['compromised_campaigns']}/{a['completed']}", f"{a['normal_preserved']}/{a['normal_requests']}", f"{a['positive_logins_preserved']}/{a['positive_logins']}", a['normal_rule_blocks'], a['llm_calls']] for a in aggregates])
    paragraph('표의 요청 분모는 completed 캠페인만 집계하며 실패 캠페인의 부분 기록은 원시 JSON에 남긴다. 공격 요청과 정상 요청은 혼합되어 있으며 탐지 정확도나 일반적인 공격 차단율로 환산하지 않는다.')
    table(['조건', 'HTTP p50(ms)', 'HTTP p95(ms)', '판단→응답 p95(ms)', '평균 캠페인(초)', '추론 합계(초)', '대기 합계(초)', '입력/출력 토큰'],
          [[LABELS[a['mode']], *[f"{a[k]:.3f}" if a[k] is not None else 'NA' for k in ['http_p50_ms', 'http_p95_ms', 'decision_p95_ms', 'mean_wall_seconds', 'inference_seconds', 'queue_seconds']], f"{a['prompt_tokens']}/{a['output_tokens']}"] for a in aggregates])
    paragraph('HTTP 시간은 서버 요청·응답만 포함하며 동기 AI 판단 시간은 포함하지 않는다. 판단→응답 시간은 방어 처리를 포함한다. 비동기 대기 중 후속 요청이 진행되므로 짧은 응답 시간만으로 안전성을 판단할 수 없다. 캠페인 시간은 요청 사이 인위적 대기와 마지막 분석 완료 대기를 포함한다. 토큰은 Ollama 반환 필드이며 비용 추정은 하지 않았다.')
    timings = [(j['mode'], c['inference_seconds']) for j in jobs for c in j['calls'] if c['status'] == 'completed']
    timing_note = ''
    if len(timings) > 1:
        timing_note = f'첫 호출({LABELS[timings[0][0]]})은 {timings[0][1]:.2f}초였고 나머지 호출은 {min(t[1] for t in timings[1:]):.2f}~{max(t[1] for t in timings[1:]):.2f}초였다. '
    paragraph('별도 워밍업이나 캐시 초기화를 하지 않았다. ' + timing_note + '모델 로딩 시간과 생성 시간을 분리 저장하지 않아 차이의 원인을 확정할 수 없다. 따라서 평균 캠페인 시간 차이는 정책 방식만의 효과가 아니며 속도 우월성으로 해석하지 않는다. 백분위수는 완료 캠페인의 요청에 대한 nearest-rank 방식이다.')
    table(['반복', '조건', '패치 시점(초)', '패치 전 공격 성공', '전체 공격 성공'],
          [[j['repeat'] + 1, LABELS[j['mode']], f"{j['policy_effective_seconds']:.4f}" if j['policy_effective_seconds'] is not None else 'NA', j['summary']['pre_patch_successes'], j['summary']['attack_successes']] for j in jobs if j['mode'].startswith('ai_')])
    heading(2, '6. 논의 및 타당성 위협')
    paragraph('첫째, 항상 안전한 구현과 동기 AI 조건이 비슷한 보안 결과를 보이더라도 AI의 필요성이 입증되는 것은 아니다. 동일한 SQL 바인딩을 처음부터 적용하는 비교군은 모델 호출을 요구하지 않는다. AI 정책은 첫 정상 요청에서도 패치를 선택할 수 있으므로 이 결과는 악성 입력 탐지 능력의 증거가 아니다. 본 환경은 정책 선택의 적용 시점을 평가하며 복잡한 대응 선택의 이점은 후속 과제다.')
    first_normal_patch = [j for j in jobs if j['mode'].startswith('ai_') and j['trials'] and not j['trials'][0]['attack'] and len(j['calls']) == 1 and j['events'] and j['events'][0]['action'] == 'parameterize']
    paragraph(f'이번 재생 실험에서 첫 정상 요청을 분석한 뒤 parameterize를 선택하고 추가 분석을 하지 않은 AI 캠페인은 {len(first_normal_patch)}개였다. 해당 동기 캠페인의 좋은 결과는 공격을 식별한 뒤 대응한 결과가 아니라 첫 요청부터 안전한 구현으로 전환한 결과다.')
    losses = [(j, row) for j in jobs if j['mode'] == 'ai_async' for row in j['trials'] if not row['attack'] and not row['normal_preserved']]
    if losses:
        table(['비동기 정상 기능 실패: 반복', '사례', 'SQL 오류', '패치 적용 상태'], [[j['repeat'] + 1, row['case'], row['body']['error'], row['policy_active']] for j, row in losses])
    paragraph('둘째, 단순 규칙의 정상 계정 차단과 공격 누락은 의도적으로 만든 반례다. 이 수치로 상용 WAF나 다른 규칙 기반 시스템보다 우월하다고 주장할 수 없다. 취약 구현의 apostrophe 계정 오류는 정상 기능 결함으로, team--blue의 403은 규칙의 정상 요청 차단으로 구분한다.')
    paragraph('셋째, 비동기 정책은 패치 전 노출 구간을 가진다. 수동 AI 공격 실험에서는 공격 생성 시간이 방어에 시간을 제공했지만 고정 재생에서는 더 빠르게 후속 입력이 도착한다. 두 실험의 차이는 공격 생성 유무·요청 순서·정책 호출 규칙·스케줄링이 함께 달라진 결과이므로 비동기 효과의 단일 인과 추정으로 해석하지 않는다. 후속 실험에서 도착률과 초기 안전 정책을 통제해야 한다.')
    paragraph('넷째, 사례 작성자와 구현 작성자가 같고 표본은 작으며 모델·프롬프트·seed도 제한적이다. 반복은 실행 순서 변동을 확인할 뿐 독립 공격의 다양성을 늘리지 않는다. SQL 인증만 평가했고 XSS 실행·IDOR·행동 적응 탐지·세션 회전·공개 IDS 데이터·실시간 Codex 방어를 검증하지 않았다. 탐지율 94.2%, FPR 3.8%, 11.3%p 개선, ATD 2.3회 등 원 초안의 예정 수치를 실측 성과로 유지해서는 안 된다.')
    heading(2, '7. 결론 및 논문 반영 지침')
    paragraph('Windows 로컬 환경에서 실제 Qwen 공격 및 정책 선택, HTTP 인증 결과, 정책 적용 시점의 기록을 완료하였다. 동일 입력 재생은 사전 적용한 SQL 바인딩의 효과, 단순 규칙의 제한, 비동기 패치 전 노출을 구분해 관찰할 수 있게 했다. 현재 근거는 소규모 개발 테스트베드의 기능·기전 검증이며 AI 방어의 일반적 우월성을 입증하지 않는다. 독립 작성한 보류 사례, 정상 업무 트래픽, 여러 모델·반복 캠페인, 도착률 통제를 통해 추가 검증해야 한다.')
    table(['원고 위치', '반영 내용'], [['초록', '본 문서 초록으로 실측 범위와 한계를 명시'], ['구현/방법', 'Windows·SQLite·Ollama, 제한된 정책 선택, 두 실험의 차이를 명시'], ['결과', '수동 캠페인 표와 동일 입력 재생 표를 별도로 삽입'], ['논의', '항상 안전한 구현 비교군, 비동기 노출, 개발 사례 편향을 설명'], ['결론', '기능·기전 검증으로 한정하고 예정 성능 수치를 삭제'], ['기존 2026-11-15 실험', 'LLM 없는 HTTP/XSS 반사·합성 행동 규칙 실험으로 별도 보존']])
    heading(2, '부록: 추적 가능한 산출물')
    paragraph('실행 디렉터리: ' + str(folder.relative_to(ROOT)) + '. 계획: research/SQL_REPLAY_PROTOCOL.md. 수동 원시 결과: research/ai_runs/. 집계: research/results/local_study_summary.json 및 CSV. 이전 보고서 보존: research/archive/before_local_ai_update/. 원본 논문 식별값은 research/paper_provenance.json에 보존되어 있다.')
    table(['이전 실패 캠페인', '모델', '조건', '상태/원인'], [[j['id'], j['model'], j['mode'], j.get('error', j['status'])] for _, j in old_failures])
    paragraph('검증: 실제 HTTP 기반 정상 인증·공격·규칙 반례·상태 초기화·동기 패치·비동기 패치 전 성공·모델 실패 처리를 단위/통합 테스트로 확인한다. 테스트의 모델 모의 응답은 측정 결과에 포함하지 않는다. 기존 앱의 SQLite 연결 정리 ResourceWarning은 별도 잔여 사항이며 새 재생 서버는 연결을 명시적으로 닫는다.')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    figure, axes = plt.subplots(1, 2, figsize=(11, 4.6))
    labels = ['None', 'Rules', 'Always safe', 'AI sync', 'AI async']
    for ax, key, denom, title in [(axes[0], 'attack_successes', 'attack_requests', 'Unauthorized authentication'), (axes[1], 'normal_preserved', 'normal_requests', 'Normal behavior preserved')]:
        values = [a[key] / a[denom] * 100 if a[denom] else 0 for a in aggregates]
        bars = ax.bar(labels, values, color=['#8a8d93', '#c88740', '#24826b', '#376eb5', '#8650a3'])
        ax.set_ylim(0, 116)
        ax.set_ylabel('Observed fixture requests (%)')
        ax.set_title(title)
        ax.tick_params(axis='x', labelsize=9)
        for bar, a in zip(bars, aggregates):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 2, f"{a[key]}/{a[denom]}", ha='center', fontsize=9)
    figure.text(.5, .02, 'Development fixtures only: 10 cases x 5 policies x 3 repeats; not independent population samples.', ha='center', fontsize=8)
    figure.tight_layout(rect=(0, .05, 1, 1))
    for ext in ['png', 'svg']:
        figure.savefig(out / ('sql_replay_results.' + ext), dpi=180)
    plt.close(figure)
    web.append('<img alt="Fixed replay development fixture results" style="width:100%" src="data:image/png;base64,' + base64.b64encode((out / 'sql_replay_results.png').read_bytes()).decode() + '">')
    md.append('![동일 입력 재생 결과](results/sql_replay_results.png)')
    (R / 'PAPER_LOCAL_STUDY.md').write_text('\n\n'.join(md) + '\n', encoding='utf-8')
    style = 'body{font:16px/1.85 system-ui;max-width:1150px;margin:36px auto;padding:24px;color:#192d3e;background:#fafbf9}table{border-collapse:collapse;display:block;overflow:auto;font-size:13px}th,td{border:1px solid #bccbd0;padding:9px;text-align:left}th{background:#e2eee9}h1{font-size:30px}h2{margin-top:36px}p{overflow-wrap:anywhere} @media print{body{margin:0;padding:0;font-size:11pt}table{font-size:9pt}h2{break-after:avoid}}'
    document = '<!doctype html><html lang="ko"><meta charset="utf-8"><title>로컬 AI 방어 예비 실험 논문 보완본</title><style>' + style + '</style><body>' + '\n'.join(web) + '</body></html>'
    (out / 'paper_revision.html').write_text(document, encoding='utf-8')
    (out / 'index.html').write_text(document, encoding='utf-8')
    (R / 'REPORT.md').write_text('# 로컬 AI 공격·방어 후속 예비 실험\n\n최신 논문 반영본: [PAPER_LOCAL_STUDY.md](PAPER_LOCAL_STUDY.md). 브라우저: http://127.0.0.1:8765/research/paper_revision.html\n\n수동 Qwen 캠페인과 5조건 동일 입력 재생을 분리해 보고한다. 이전 LLM 없는 실험 보고서는 archive/before_local_ai_update/에 보존했다.\n\n' + '\n\n'.join(md[:6]) + '\n', encoding='utf-8')
    print(json.dumps(aggregates, ensure_ascii=True, indent=2))
    print('Paper:', out / 'paper_revision.html')


if __name__ == '__main__':
    main()
