# agent_lab — recon→exploit 에이전트 실험 (Docker 전 단계)

자작 **합성 취약 웹 표적**과 **고정 파이프라인 공격 에이전트**로, 공격자를 "속성 선택기"에서
**실제 HTTP 트래픽을 보내는 행위자**로 끌어올린다. 지금은 Docker 없이 Windows 루프백에서 바로 돌아가고,
저녁에 Docker가 뜨면 네트워크 격리(`internal: true`)만 씌우면 된다.

## 파일
- `target.py` — 합성 취약 웹 표적. 127.0.0.1 전용 바인딩. 의도적 SQLi 로그인(랩 전용).
  디코이/허니토큰 엔드포인트를 요청 로그에 `lure=true`로 표시 → **미끼 접촉률 실측용**.
- `fixed_agent.py` — 고정 파이프라인 공격자: `정찰 → 열거 → 탐침 → 익스플로잇 → JSON 보고`.
  결정적 순서(ReAct가 아님). Cochise(ReAct)와의 **아키텍처 비교 기준선**.
- `test_agent_lab.py` — allowlist 격리 + end-to-end 스모크 테스트.

## 실행
```bash
# 1) 표적 기동 (요청 로그를 파일로)
python agent_lab/target.py --port 8700 --log run.jsonl
# 2) 다른 셸에서 공격자 실행
python agent_lab/fixed_agent.py --base http://127.0.0.1:8700 --out report.json
# 테스트
python agent_lab/test_agent_lab.py
```

## 안전·격리 (코드로 강제)
- **표적**: `--host`는 루프백(127.0.0.1/localhost/::1)만 허용. 그 외는 기동 거부.
- **공격자**: 모든 요청 URL의 호스트를 파싱해 `ALLOWED_HOSTS`(루프백)만 통과. 그 외는 `PermissionError`.
  → 이 에이전트는 **물리적으로 외부로 트래픽을 보낼 수 없다.**
- 표적은 **우리가 만든 합성 앱만**. 실제 서비스·실제 CVE·실제 PII 없음. 합성 계정만 사용.
- 실제 익스플로잇 프레임워크(Metasploit 등) 없음 — 자작 표적에 대한 HTTP만.

## 지금까지의 측정 결과
- 고정 파이프라인 1회 실행: 20요청 중 디코이 6개 접촉 → **측정 p_touch ≈ 0.30**.
  워드리스트를 무차별 열거하기 때문. research/ato_shadow(§6.10)가 **가정**하던 값을 **실측**으로 대체.
- 비교 가설: LLM/ReAct 에이전트는 디코이를 더 잘 회피 → p_touch가 낮아질 것. 이 차이가 아키텍처 비교 포인트.

## 저녁(Docker) 이후 추가할 것
1. `docker compose`로 표적 컨테이너 + 공격자 컨테이너를 **`internal: true` 네트워크**에 격리(외부 차단).
2. **방어자가 요청 로그를 관측**하도록 연결 — 규칙 탐지기 + LLM 탐지기(논문의 AI-vs-규칙 축 연장).
3. Cochise(ReAct) 에이전트를 같은 표적에 붙여 고정 파이프라인과 비교.
4. 탐지율·미끼 접촉률·지연을 반복 측정 → 아티팩트 §6.10/§6.11/§7.5 반영.

> CVE 표적(AutoPenBench)은 인터넷에서 이미지를 당겨오므로, 검증 후에만 격리망에 투입한다.
