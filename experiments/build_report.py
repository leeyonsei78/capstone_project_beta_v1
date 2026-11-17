"""Render measured results and a clearly scoped revision of the supplied draft."""
import argparse
import hashlib
import html
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
R = ROOT / 'research'
RESULTS = R / 'results'


def table(headers, rows):
    return '<table><thead><tr>' + ''.join('<th>' + html.escape(str(c)) + '</th>' for c in headers) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + html.escape(str(c)) + '</td>' for c in row) + '</tr>' for row in rows) + '</tbody></table>'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--paper', type=Path, required=True)
    args = parser.parse_args()
    source = args.paper.read_text(encoding='utf-8')
    data = json.loads((RESULTS / 'summary.json').read_text(encoding='utf-8'))
    for name, digest in data['source_sha256'].items():
        archived = RESULTS / ('source_' + name.replace('/', '_') + '.txt')
        if archived.exists() and hashlib.sha256(archived.read_bytes()).hexdigest() == digest:
            continue
        raw = (ROOT / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError('Measured source changed before archiving: ' + name)
        archived.write_bytes(raw)
    audit = {'original_file': str(args.paper), 'sha256': hashlib.sha256(args.paper.read_bytes()).hexdigest(),
             'scope': 'Original Downloads file left unchanged', 'results_created_at': data['created_at']}
    (R / 'paper_provenance.json').write_text(json.dumps(audit, ensure_ascii=False, indent=2), encoding='utf-8')
    names = {'draft_heuristic_ip': '초안형 IP 규칙', 'causal_evidence_ip': '차단 증거 + 기법 변경 / IP', 'causal_evidence_trusted_session': '차단 증거 + 기법 변경 / 신뢰 세션', 'suspicion_only_no_history': '현재 의심 특징만 / 이력 없음'}
    hrows = [[r['config_sql_xss_idor'], f"{r['attack_success_or_raw_xss_reflection']}/{r['attack_trials']}", f"{r['control_preserved']}/{r['control_trials']}", f"{r['p50_http_ms']:.3f}", f"{r['p95_http_ms']:.3f}"] for r in data['http']]
    brows = [[names[r['policy']], f"{r['tp']}/90", f"{r['fp']}/120", r['undetected_episodes'], r['mean_atd_detected_only'], r['episodes_with_pre_onset_alarm']] for r in data['behavior']]
    http_table = table(['SQL/XSS/IDOR 방어', '공격 성공·XSS 반사', '정상 대조 유지', 'HTTP p50 ms', 'HTTP p95 ms'], hrows)
    behavior_table = table(['후보 분석 트리거', '적응형 경보 발생', '정상 경보 발생', '적응형 미탐', '탐지 건 ATD', '기법 변경 전 경보'], brows)
    caveat = '<p><strong>해석 한계:</strong> HTTP는 고정 사례 16개를 8개 방어 구성에서 10회 반복했다. 1,280개의 독립 공격이 아니다. XSS는 미인코딩 태그 반사 지표이며 브라우저 실행 성공률이 아니다. 행동 재생은 7개 고정 특징 시나리오에 시작 시간만 바꾼 30개 seed를 적용한 것이다. 의심 여부와 기법 특징을 이상적으로 공급하므로 완벽한 결과도 현실 탐지 정확도의 증거가 아니다. 이력 없는 의심 특징 비교군도 경보 발생 지표에서 동일한 결과를 내므로, 이 데이터만으로 행동 이력의 추가 탐지 효과를 입증할 수 없다. 해당 비교군은 기법 변경 전에도 경보가 나므로 악성 요청 판별과 적응행위 판별을 분리해야 한다. Qwen, Snort, RF, Docker, NSL-KDD, CSE-CIC-IDS2018은 이번에 실행하지 않았다.</p>'
    results_html = '<h3>6.1 실제 HTTP 구성요소 제거 실험</h3><p>가상 관리자 인증·타인 문서 조회·XSS 미인코딩 반사 8종과 정상 대조 8종을 자체 loopback 서버에서 실행했다. 000은 방어 없음, 111은 세 방어 모두 적용이다. 각 비트는 SQL 바인딩, 출력 인코딩, 문서 소유권 검사 순서다.</p>' + http_table + '<h3>6.2 행동 규칙 반례 재생</h3><p>적응형 3종과 정상 반례 4종을 평가했다. 현재 요청의 결과를 사전에 쓰지 않고 이전 요청의 차단 결과만 참조한다. ATD는 최초 기법 변경 요청을 1로 세며 미탐은 별도 표시한다. 초안형 규칙은 최종 LLM 판단이 아니라 분석 후보를 만드는 규칙이다.</p>' + behavior_table + caveat + '<img src="pilot_results.png" alt="실측 HTTP 방어 조합과 합성 행동 반례 비교" style="width:100%">'
    audit_html = '''<h2>초안에서 우선 수정할 사항</h2><ol>
<li><b>예상 결과와 실측 결과 혼용:</b> 초록·결론의 DR 94.2%, FPR 3.8%, 11.3%p 향상, ATD 2.3회를 실측 성과로 쓸 근거가 없다. 초안 6절도 예정치라고 명시한다.</li>
<li><b>IP ≠ 행위자:</b> 공유 NAT와 IP 회전을 별도 시험해야 한다. 세션 기반도 공격자가 세션을 새로 만들면 끊기므로 만능 해법이 아니다.</li>
<li><b>기법 다양성 ≠ 악의적 적응:</b> 이전의 의심 차단 증거, 이후의 의심 기법 변경, 시간 순서를 함께 검사한다. 이번 반례는 개선 필요성을 보여주며 특징 추출기의 실제 성능은 검증하지 않는다.</li>
<li><b>Risk의 단위 미정:</b> 비율 E, 횟수 S, 요청률 R, 이진 A를 같은 가중합에 넣는 정규화와 창 크기가 없다. 모두 0~1이면 최대 1이어서 θ=70과 비교할 수 없다. Risk=100·Σwᵢzᵢ, zᵢ∈[0,1]로 범위를 정의하고 별도 검증 세트에서 임계값을 정해야 한다.</li>
<li><b>LLM 지연과 confidence:</b> 자기 보고 confidence 80은 보정된 공격 확률이 아니다. 이번에는 Qwen을 실행하지 않았으므로 1~3초 지연 주장도 검증하지 않는다. 정규화·권한 검사·패치를 요청 경로에 두고 LLM은 비동기 분석 경로로 분리하는 설계를 제안한다.</li>
<li><b>데이터셋의 평가 단위:</b> 공개 IDS 데이터의 레이블만으로 차단 피드백에 따른 HTTP 기법 변경의 인과 순서를 입증할 수 없다. 원시 요청·응답·세션·공격자 정책 로그가 있는 폐루프 데이터가 별도로 필요하다.</li>
</ol>'''
    future_html = '''<h2>후속 본 실험 계획</h2><p>현재는 논문 주장의 전제와 방어 패치를 확인한 예비 실험이다. 다음 단계는 아래와 같다.</p>
<ol><li>고정 재생 공격과 차단 응답에 따라 다음 행동을 바꾸는 정책 공격자를 동일 예산으로 비교한다. 정책은 결정 규칙부터 시작하고, LLM 공격자 여부를 별도 조건으로 둔다. AI가 공격을 생성했다고 가정하지 않는다.</li>
<li>무상태 정규화 룰, 시간 이력 룰, 증거 기반 이력, 동기 LLM, 비동기 LLM을 같은 요청 로그와 동일 예산으로 비교한다. 현재 미구현 조건을 결과 표에 실측으로 넣지 않는다.</li>
<li>공격 템플릿·행위자·캠페인 단위로 개발/검증/최종 평가를 분리한다. 별도 작성자가 만든 정상 트래픽과 보류 공격 템플릿을 포함해 데이터 누출을 줄인다.</li>
<li>정확한 탐지 레이블과 공격 성공 여부를 분리하여 DR/FPR/F1, 미탐 포함 ATD, 시간 지연, 정상 요청 p50/p95/p99, LLM 호출률·타임아웃·큐 대기·토큰 비용·정상 기능 손상을 함께 평가한다. 캠페인 단위 신뢰구간을 사용한다.</li>
<li>기법 특징 오염, 세션 회전, 동일 IP 다중 사용자, 24시간 경계, 모델 출력 오류, 로그 안의 프롬프트 인젝션을 평가한다. LLM 출력은 검증된 대응 식별자만 허용한다.</li></ol>'''
    refs_html = '''<h2>원문과 참고문헌 점검</h2><p>다운로드 폴더의 원본은 수정하지 않았다. 아래 네 참고문헌의 제목·저자와 초록을 원 출처에서 확인했으나, 초안의 모든 주장과 수치를 검증한 것은 아니다.</p>
<ul><li><a href="https://arxiv.org/abs/2606.05567">ZERO-APT</a>: Windows Server 2022 post-exploitation 실험이다. 웹 방어 실험의 직접 비교 수치로 합치면 안 된다.</li>
<li><a href="https://arxiv.org/abs/2507.07413">Hybrid LLM-Enhanced IDS</a>: 초록의 6.3% 정확도 개선·9.0% false positive 감소를 확인했으며, 본 환경에서 재현하지 않았다.</li>
<li><a href="https://arxiv.org/abs/2507.10873">SHIELD</a>: 호스트 로그 평가이다. LBADS 웹 환경과 평가 단위가 다르다.</li>
<li><a href="https://arxiv.org/abs/2603.00859">AMDS</a>: 두 가지 adaptive white-box 변형에 국한된 결과라는 원문의 제한을 함께 적어야 한다.</li>
<li><a href="https://www.unb.ca/cic/datasets/nsl.html">NSL-KDD 공식 안내</a>와 <a href="https://www.unb.ca/cic/datasets/ids-2018.html">CSE-CIC-IDS2018 공식 안내</a>: 이번에 다운로드·실행하지 않았다. CIC-IDS2018은 네트워크 캡처·시스템 로그·흐름 특징을 제공하므로 실제로 사용할 아티팩트와 파서를 구체적으로 지정해야 한다.</li></ul>
<p>초안 [1], [6], [8]은 이번 작업에서 원문 검증하지 않았다. 특히 [6] DOI는 <code>10.1016/j.eswa.2025</code>로만 기재되어 식별 정보 보완이 필요하다.</p>'''
    body = '<small>MEASURED LOCAL PILOT · NO LLM CALLS</small><h1>LBADS 논문 보완 실험 보고서</h1><p>실행 시각(UTC): ' + data['created_at'] + '</p><p>원본 초안의 예정 성능을 실측 결과와 분리하고, 방어 패치 효과와 행동 규칙의 반례를 검증했다.</p>' + audit_html + '<h2>실측 결과</h2>' + results_html + future_html + refs_html
    style = 'body{font:16px/1.8 system-ui;background:#f5f6f8;color:#172a3c;max-width:1150px;margin:35px auto;padding:24px}h1{font-size:34px}h2{margin-top:36px}h3{margin-top:28px}table{border-collapse:collapse;width:100%;font-size:14px;display:block;overflow:auto}th,td{border:1px solid #ced7e0;padding:10px;text-align:left}th{background:#dce8e2}li{margin:12px 0}a{color:#225b8e}small{color:#376e57}code,pre{background:#e5ebee;padding:3px;overflow-wrap:anywhere}img{border:1px solid #ccd6df;margin:20px 0}'
    links = '<p><a href="paper_revision.html">논문 보완본</a> · <a href="summary.json">실측 JSON</a> · <a href="http_trials.csv">HTTP 원시 CSV</a> · <a href="behavior_trials.csv">행동 CSV</a> · <a href="pilot_results.svg">그림 SVG</a></p>'
    page = '<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LBADS 예비 실험 보고서</title><style>' + style + '</style><main>' + body + links + '</main></html>'
    (RESULTS / 'index.html').write_text(page, encoding='utf-8')
    # Reuse draft styling/navigation, but replace all claims about implementation/results.
    revised = source
    replacements = {
        's1': '<h2>1. 서론 — 예비 검증의 연구 질문</h2><p>원 초안의 Qwen 기반 행동 분석 설계를 발전시키기 위해 (RQ1) 요청 경로에서 검증된 방어 패치가 공격 결과를 바꾸는가, (RQ2) 차단 피드백의 인과 순서를 요구하면 정상 기법 변경의 오경보를 줄일 수 있는가, (RQ3) IP와 행위자 식별 단위의 차이가 탐지 이력을 어떻게 끊는가를 검토한다.</p><p>이번 공헌은 재현 가능한 로컬 예비 실험과 설계 반례이다. LLM의 추가 성능, 공개 데이터셋 우위, 운영 수준 강건성은 향후 검증 대상이다.</p>',
        's2': '<h2>2. 관련 연구 — 비교 범위</h2><p>원문을 확인한 ZERO-APT [2]는 Windows Server 2022 post-exploitation 환경에서의 폐루프 공격자·방어자·판정자 프레임워크이다. Hybrid LLM-IDS [3]는 GPT-2를 결합한 IDS이며, SHIELD [5]는 호스트 로그 기반 분석이다. AMDS [7]는 앙상블 기반 공격 유형별 탐지 전략과 제한된 적응형 white-box 변형을 다룬다. 이 결과를 본 로컬 웹 실험의 직접 비교군 실측치로 합산하지 않는다.</p><p>본 예비 검증의 차별점은 공격 성능 우월성의 입증이 아니라, 이전 차단과 기법 변경의 인과 조건 및 식별 단위를 분리해 설계 반례를 재현하고 요청 경로의 실제 방어 패치를 조합별로 확인한다는 데 있다. [1], [6], [8]은 원문 미검증 상태이며 관련 수치를 확정 주장으로 유지하지 않는다.</p>',
        's3': '<h2>3. 위협 모델과 평가 범위</h2><p>HTTP 실험은 소유한 loopback 가상 사이트의 SQL 인젝션, XSS 미인코딩 반사, IDOR만 포함한다. 공격 입력은 고정되어 있으며 LLM이 생성하지 않았다. 행동 실험은 생성기가 제공한 의심 여부·기법·차단 결과·가상 시간·IP·신뢰 세션 특징의 상태 기계 재생이다.</p><p>분산 IP는 실제 인터넷 호스트가 아니라 재생 특징이다. 시간 기반 시나리오도 24시간 실운영이 아니다. DoS, 경로 탐색, 무차별 대입의 실제 공격 실험은 포함하지 않는다.</p>',
        's4': '<h2>4. 설계 보완안</h2><h3 id="s4-1">4.1 저지연 실행 경로와 비동기 분석 경로</h3><p>현재 구현은 SQL 바인딩·문맥별 출력 인코딩·객체 소유권 검사를 즉시 적용한다. 선택적 LLM은 이후 로그를 분석하는 비동기 경로로 분리하는 설계를 제안한다. 비동기 LLM 자체의 효과는 이번에 구현·측정하지 않았다.</p><h3 id="s4-2">4.2 식별 단위와 위험도</h3><p>IP 이력과 서버가 검증한 세션 이력을 구분한다. 세션 회전·로그인 전 사용자·NAT의 불확실성을 별도 기록해야 한다. 기존 Risk의 입력 단위가 정해지지 않아 θ=70을 재현할 수 없다. 개선식 Risk=100·Σwᵢzᵢ, zᵢ∈[0,1]는 후속 제안이며 정규화·가중치·임계값을 검증 세트에서 확정해야 한다.</p><h3 id="s4-3">4.3 차단 증거와 기법 변경의 인과 조건</h3><p>이전 의심 요청의 차단 기록과 현재 의심 요청의 다른 기법을 함께 요구한다. 단순 인코딩 다양성이나 정상 권한 오류 반복만으로 적응형 공격을 단정하지 않는다. 요청 결과는 해당 요청 판단 이후에 이력에 추가한다.</p><h3 id="s4-4">4.4 LLM 역할과 미검증 사항</h3><p>Qwen 및 실시간 Codex API 호출은 0회이다. 코드·해설은 Codex가 미리 작성했다. 따라서 이번 결과로 Qwen의 추론 지연이나 탐지 향상을 주장하지 않는다. LLM 자체 보고 confidence는 보정 확률이 아니며 후속 검증이 필요하다.</p>',
        's5': '<h2>5. 실험 설계 — 실제 실행 환경</h2><h3 id="s5-1">5.1 환경</h3><p>Windows 11, Python 3.13.3 표준 HTTP 서버·SQLite 메모리 DB를 사용했다. 그래프는 matplotlib으로 생성했다. Ubuntu, Docker, Nginx, DVWA 또는 GPU 추론 환경을 이번 결과의 환경으로 기재하지 않는다.</p><h3 id="s5-2">5.2 입력과 반복</h3><p>HTTP 고정 사례 16개(공격 8·정상 대조 8), 방어 8조합, 10회 반복이다. 행동 재생은 7개 고정 시나리오에 시작 시간만 바꾼 30 seed를 적용했다. 반복을 독립 표본으로 해석하지 않는다. 공개 IDS 데이터셋과 10,000건 자체 데이터셋은 이번에 사용하지 않았다.</p><h3 id="s5-3">5.3 지표</h3><p>HTTP 공격 결과, 정상 대조 유지, 로컬 응답 p50/p95와 시나리오 단위 후보 경보를 측정했다. ATD는 기법 변경 요청을 1로 세며 미탐 수를 함께 보고한다. 전체 LBADS의 DR/FPR/F1, 운영 처리량과 LLM 지연은 측정하지 않았다.</p>',
        's6': '<h2>6. 실측 예비 결과</h2>' + results_html,
        's7': '<h2>7. 논의와 한계</h2>' + caveat + future_html,
        's8': '<h2>8. 결론 — 확인한 범위</h2><p>세 방어가 모두 적용된 구성에서 고정 공격 사례 8종을 각 10회 반복했을 때 SQL·IDOR 성공 및 XSS 미인코딩 반사는 0/80이었고 정상 대조는 80/80 유지됐다. 이는 교육용 가상 대상의 제한된 예비 검증이며 공격 전체의 차단 성능이 아니다.</p><p>행동 규칙 반례는 기법 다양성만으로는 악의적 적응을 구분하기 어렵고 IP만으로는 행위자 이력이 단절될 수 있음을 보여준다. 인과 증거·세션 식별을 보완한 규칙의 이상화된 성공을 현실 성능으로 일반화할 수 없다. LLM 추가 효과와 공개 데이터셋 평가를 수행하기 전에는 기존 예정치 94.2%, 3.8%, 11.3%p, ATD 2.3회를 성과로 주장하지 않는다.</p>',
    }
    for sid, content in replacements.items():
        pattern = r'<div class="section" id="' + sid + r'">.*?(?=<!-- (?:[2-8]\.|참고문헌))'
        revised, count = re.subn(pattern, lambda m: '<div class="section" id="' + sid + '">' + content + '</div>\n\n', revised, count=1, flags=re.S)
        if count != 1:
            raise RuntimeError('Could not replace section ' + sid)
    abstract = '<div class="abstract-box" id="abstract"><h2>Abstract — 실측 예비 검증</h2><p>LLM 행동 기반 방어 시스템 초안의 근거를 보완하기 위해, 자체 가상 웹사이트의 방어 구성요소 제거 실험과 행동 규칙의 반례 재생을 수행했다. 실제 HTTP 요청 1,280건은 고정 사례 16개를 8개 방어 조합에서 10회 반복한 것이다. 모든 방어를 적용하면 공격 결과 0/80, 정상 대조 유지 80/80이 관측됐다. XSS는 미인코딩 반사를 검사했으며 브라우저 실행을 측정하지 않았다. 별도 합성 특징 재생에서는 정상 인코딩 변경·권한 오류 반복·공유 IP의 오경보와 IP 회전의 이력 단절을 확인했다. Qwen 등 LLM은 호출하지 않았으며 본 결과는 전체 LBADS나 공개 IDS 데이터셋의 성능 검증이 아니다.</p></div>'
    revised, count = re.subn(r'<div class="abstract-box" id="abstract">.*?(?=<!-- 1\. 서론)', lambda m: abstract + '\n\n', revised, count=1, flags=re.S)
    if count != 1:
        raise RuntimeError('Could not replace abstract')
    revised = revised.replace('진화하는 AI 기반 사이버 공격에 대한<br>LLM 행동 분석 방어 시스템의 효과성 연구', '행동 증거 기반 적응형 방어 설계의<br>로컬 예비 검증과 반례 분석')
    revised = revised.replace('Effectiveness of LLM-Based Behavioral Defense Against Evolving AI-Driven Cyberattacks', 'A Local Pilot and Counterexample Analysis of Evidence-Grounded Adaptive Defense')
    revised = revised.replace('초안 (Draft)', '실측 예비 검증 반영 보완본')
    revised = revised.replace('<h2>참고문헌 (References)</h2>', '<h2>참고문헌 (원 초안 목록 · 부분 확인)</h2>' + refs_html)
    (RESULTS / 'paper_revision.html').write_text(revised, encoding='utf-8')
    shutil.copyfile(ROOT / 'experiments' / 'run_study.py', RESULTS / 'reproduce_study.py.txt')
    report = f'''# LBADS 초안 보완 실험 보고서

원본: `{args.paper.name}`. 원본 파일은 수정하지 않았다. 실행 시각: {data['created_at']}.

## 핵심 결과

- HTTP 1,280건 = 고정 사례 16종 × 방어 8조합 × 10회. 독립 공격 1,280종이 아니다.
- 방어 없음: 공격 성공 또는 XSS 미인코딩 반사 80/80. 모든 방어 적용: 0/80.
- 모든 방어 적용 시 정상 대조 유지 80/80. 정상 비밀번호 로그인까지 확인한 전체 기능 검사는 아니다.
- 행동 규칙 재생: 정상 인코딩 변경, 권한 오류 반복, NAT 공유를 초안형 규칙이 후보 경보로 표시했다. IP 회전 시 IP 이력이 끊겼다.
- Qwen/실시간 Codex API/공개 IDS 데이터셋/Snort/RF 실행은 0회. 이 결과는 전체 LBADS의 DR/FPR이 아니다.

## 해석

초안 6절은 예정치라고 적었으나 초록·결론은 완료된 성과로 서술한다. 기존 94.2%, 3.8%, 11.3%p, ATD 2.3회를 실측 성과로 유지해서는 안 된다.

현재 연구 발전 방향은 `이전의 의심 차단 증거 → 이후의 의심 기법 변경`이라는 인과 조건과 신뢰 가능한 식별 단위, 저지연 패치 경로와 비동기 분석 경로의 분리다. 후자는 설계 제안이며 LLM 효과를 측정한 구현이 아니다.

행동 데이터는 7개 특징 시나리오를 시작 시간만 달리해 반복했다. 이상적인 의심 특징과 신뢰 세션을 공급했으므로 개선 규칙의 좋은 수치는 현실 탐지 성능의 증거가 아니다. ATD는 미탐 수와 함께 해석해야 한다. 같은 작성자가 만든 코드와 입력이므로 독립 검증도 아니다.

## 산출물

- results/index.html: 상세 보고서, 전체 실측 표, 논문 개선 방향, 참고문헌 점검.
- results/paper_revision.html: 원 초안 구조를 유지하면서 초록·1/3/4/5/6/7/8절을 실측 범위에 맞춘 보완본.
- PROTOCOL.md: 실행 범위와 평가 규칙.
- results/http_trials.csv, http_summary.csv, behavior_trials.csv, behavior_episodes.json, summary.json: 원시 결과와 요약.
- results/pilot_results.png, pilot_results.svg: 실측 그림.
- paper_provenance.json: 원본 SHA-256.

재실행: `python experiments/run_study.py` 후 `python experiments/build_report.py --paper "원본 HTML 경로"`.

## 후속 평가

원시 HTTP·차단 피드백·행위자 정책 로그를 수집하고, 캠페인 및 템플릿을 분리한 보류 평가 세트에서 무상태 룰/시간 이력/증거 기반 이력/동기 LLM/비동기 LLM을 비교해야 한다. 정상 기능 손상, 미탐, timeout, queue delay, p95/p99, LLM 호출률과 비용까지 함께 측정한다.
'''
    report += '\n이력 없는 의심 특징 비교군도 제공된 이상적 특징만으로 변경 후 모든 공격 에피소드에 경보를 냈다. 따라서 이번 데이터로 이력의 추가 탐지 효과를 주장할 수 없다. 이 비교군은 변경 전에도 경보를 내어 적응행위와 일반 악성 요청의 지표를 분리할 필요성을 보여준다.\n'
    (R / 'REPORT.md').write_text(report, encoding='utf-8')
    print('Generated report and revised manuscript under research/results/')


if __name__ == '__main__':
    main()
