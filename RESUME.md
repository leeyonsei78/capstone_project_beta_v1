# 재부팅 후 이어서 진행

## 이력/LLM 기여 분리 후속 실험 완료 (최신)

- 사용자 요청: 논문의 기여도를 높이기 위한 후속 실험 진행. 안전한 기본 방어 위에 관찰 전용 판별기를 비교했다.
- 동결된 주 실험: `research/behavior_runs/20261116_context_v1/`. 24개 설계 에피소드, 12대조쌍, 6가족, 고유 전체 이력 21개. 관찰 72건 + 정상 대조 48건 = 120 HTTP. 현재 요청/응답은 전부 동일하여 결정적인 현재 요청 전용 판별의 정확도 상한 50%는 설계적 제약이다.
- 주 결과(정답): 현재 규칙 12/24, 단순 이력 규칙 20/24, 강화 이력 규칙 24/24, Qwen 현재 요청 12/24, Qwen 전체 이력 14/24. Qwen 전체 이력의 양성 탐지는 2/12. 정상 오경보는 모든 조건 0/6. 모델 48회 + 별도 워밍업 1회 모두 완료.
- 주 결과 확인 후 별도로 동결한 사후 탐색: `exploratory_hybrid/`. Qwen이 18개 고유 관찰의 기법을 분류하고 코드가 시간 규칙을 판정: 24/24. 같은 자료 재사용, 프롬프트 변경·과제 분해가 함께 변하므로 독립 확인이나 AI 우월성의 증거가 아님. 주 실험은 재조정하지 않음.
- 최신 후속 원고 `research/BEHAVIOR_STUDY.md`, 통합 HTML http://127.0.0.1:8765/research/paper_revision.html#behavior-study . 선행 SQL HTML은 `research/archive/before_behavior_update/` 보존. 원본 논문은 그대로 유지.
- 실행코드 `experiments/run_behavior_study.py`, `run_behavior_hybrid.py`, `build_behavior_report.py`. 프로토콜 `research/BEHAVIOR_PROTOCOL.md`, `BEHAVIOR_HYBRID_PROTOCOL.md`.
- 후속은 독립 작성한 새 시나리오, 자연스러운 마지막 요청, 긴 이력·혼합 세션·정상 보안 검색에서 동결된 직접 판정/구조화 추출/강화 규칙을 검증해야 함. 현재 결과로 논문 기여도·출판 가능성 또는 운영 성능을 보장하지 않는다.

## 2026-11-16 로컬 실험 완료 (최신, 아래 설치 계획보다 우선)

- 사용자 결정: Docker 설치를 보류하고 Windows 로컬 취약 서버에서 논문 실험 진행.
- 8765/8766 서버 정상 실행. 실제 qwen2.5-coder:14b 수동 캠페인 완료: 방어 없음 2/3, 규칙 0/3(2회), 동기 0/3, 비동기 0/3 인증 우회.
- 후속 고정 입력 재생 구현/실행: `experiments/run_sql_replay.py`, 5조건 × 3반복 × 10사례 = 150 HTTP 요청. 원시 결과 `research/replay_runs/20261116T134723524805Z/`.
- 방어 없음/규칙/항상 안전/동기 AI/비동기 AI 공격 성공: 12/12, 3/12, 0/12, 0/12, 3/12. 정상 기능 유지: 15/18, 12/18, 18/18, 18/18, 16/18. AI 방어만 호출한 고정 재생이며 수동 AI 공격 결과와 합치지 않는다.
- AI 캠페인 6개 모두 첫 정상 입력에서 SQL 바인딩을 선택. 탐지 능력이나 AI 필요성 입증이 아니다. 비동기 성공 3건은 패치 전 발생. 입력은 규칙의 한계를 드러내도록 구성한 개발 사례이며 독립 평가 아님.
- 최신 원고: `research/PAPER_LOCAL_STUDY.md`, `research/results/paper_revision.html`. http://127.0.0.1:8765/research/paper_revision.html 에서 서버 재시작 없이 확인 가능.
- 원본 Downloads 논문 보존. 이전 생성 보고서는 `research/archive/before_local_ai_update/`에 보관. 최신 빌더 `experiments/build_local_paper.py` 사용. 기존 build_report.py는 과거 LLM 없는 보고서를 생성한다.
- 다음 연구: 독립 보류 사례, 도착률 통제, 워밍업/모델 로딩 분리, 실제 탐지·정책 선택 과제 확대. 현재 결과로 본 실험 완료나 일반적인 AI 우월성을 주장하지 않는다.

기록일: 2026-11-15. 사용자가 Windows 재부팅 후 작업을 재개하기로 함.

## 2026-11-16 재개 확인 (아래 이전 기록보다 우선)

- 사용자가 일반 PowerShell에서 `wsl --list --verbose`를 실행한 결과: 설치된 배포판 없음.
- 다음 단계는 `wsl --install -d Ubuntu-24.04` 실행 후 최초 Linux 사용자/비밀번호 생성. 설치 완료 및 WSL VERSION 2는 아직 미확인.
- 에이전트 환경의 WSL 조회는 `Wsl/E_ACCESSDENIED`로 실패. 이 오류로 사용자 PC의 WSL 장애를 단정하지 않는다. 시스템 설치는 사용자 PowerShell에서 이어간다.
- Docker CLI는 에이전트 PATH에서 발견되지 않았고, 기본 시스템/사용자 설치 경로의 Docker Desktop 실행 파일도 발견되지 않음. 다른 경로 설치 여부는 미확인.
- Ollama 프로세스가 실행 중이며 GPU 스냅샷은 RTX 3050, 6144 MiB 중 4999 MiB 사용, 사용률 11%. `run_terms.py` 실행 여부는 프로세스 조회 제한으로 확인하지 못함. Qwen 실험은 재시작하지 않았음.
- 로컬 앱 `127.0.0.1:8765/api/health` 연결 실패. 이번 점검에서 앱 서버를 재시작하지 않았음.
- 설치 후 점검 도구: `python experiments/check_environment.py`. WSL/Docker/KVM/GPU/Ollama 상태를 `research/environment/preflight-*.json`에 저장. 등록된 Ubuntu를 점검하며 중지 상태라면 시작될 수 있음. 소프트웨어 설치, 컨테이너 실행, AI 호출은 하지 않음.
- Docker hello-world 및 Firecracker 부팅 검증, 실험 격리 구성은 여전히 미완료. KVM 읽기/쓰기 확인만으로 microVM 실행 성공으로 간주하지 않는다.

## 목표와 범위

- 논문 준비: AI 공격에 대한 AI 방어를 소유한 로컬 실험 대상에서 평가.
- Docker와 Firecracker microVM 환경을 준비한 후 동일 조건의 실험을 이어간다.
- 현재는 설치 준비 단계이며, Docker/microVM 실험을 수행했다고 주장하지 않는다.
- 일반 학습 화면의 설명/방어안은 Codex가 작성한 즉시 응답 자료. 실제 AI 실험은 로컬 Qwen을 사용하며 두 가지를 구분한다.

## 사용자가 제공한 설치 상태

- 관리자 PowerShell에서 `wsl --install -d Ubuntu-24.04` 실행.
- WSL 3.0.5.0 설치 완료, VirtualMachinePlatform 활성화 완료. Windows 재부팅 필요 메시지 출력.
- `wsl --update`: 최신 버전.
- 커널 버전 6.18.58.1-1, Windows 버전 10.0.26200.9711.
- `wsl --list --verbose`: 설치된 배포판 없음.
- `wsl --set-version Ubuntu-24.04 2`: WSL_E_DISTRO_NOT_FOUND. Ubuntu 미설치 상태이므로 발생한 오류.
- 사용자가 이제 재부팅 예정. 재개 시 재부팅 및 Ubuntu 설치 상태부터 확인한다.

## 바로 다음 단계

1. 재부팅 후 PowerShell에서 `wsl --list --verbose`로 상태 확인. 배포판이 여전히 없으면 `wsl --install -d Ubuntu-24.04` 실행 안내.
2. Ubuntu 최초 실행에서 Linux 사용자/비밀번호 생성. 필요 시 `wsl -d Ubuntu-24.04`로 실행.
3. `wsl --list --verbose`에서 Ubuntu-24.04와 VERSION 2 확인. 이미 2이면 변환 명령 불필요.
4. Docker Desktop 설치 및 WSL 2 backend / Ubuntu integration 설정 안내. `docker version`, `docker compose version`, `docker run --rm hello-world`로 검증.
5. Ubuntu에서 아키텍처/커널과 `/dev/kvm` 존재 및 읽기/쓰기 권한 확인. WSL 설치만으로 Firecracker 지원을 확정하지 않는다. KVM 미지원이면 원인 조사 및 별도 Linux/KVM 환경 대안 제시.
6. 지원 확인 후 Firecracker/jailer, 호환 guest kernel/rootfs의 버전과 체크섬을 고정하고 무해한 부팅부터 검증.
7. Docker와 microVM 격리 구성 및 실험 실행 파일을 만들고 검증한 후 논문 실험 재개. 아직 저장소에 Docker/microVM 실행 구성은 작성되지 않았음.

## 기존 앱과 결과

- 작업 폴더: `C:\codex_qwen_pentest`.
- `start.ps1` 또는 `start.bat`로 로컬 앱 시작. 재부팅 후 서버 재시작 필요.
- 웹 UI: http://127.0.0.1:8765/ ; 연습 `/practice`, 실제 Qwen 실험 `/ai`, 연구 보고서 `/research/`.
- 로컬 취약 대상: 127.0.0.1:8766. 외부 대상 공격을 진행하지 않는다.
- 연구 코드: `experiments/run_study.py`, `experiments/build_report.py`, `ai_study.py`, `experiments/run_ai_pilot.py`.
- 보고서: `research/REPORT.md`, `research/PROTOCOL.md`, `research/results/`.
- 실제 Qwen 시도 로그: `research/ai_runs/`. 지금까지 실제 AI 캠페인은 timeout으로 실패했으며 AI 방어 효능 결과로 해석할 수 없음.
- 기존 고정 테스트/방어 패치 결과는 실제 LLM 공격/방어 결과와 구분해야 한다.
- 별도 `run_terms.py` 작업이 Ollama를 사용하던 상태였음. 임의 중단하지 말고 재부팅 후 실행 상태와 GPU 경쟁을 확인. 비용 큰 Qwen 실험을 자동 재시작하지 않는다.
- 원본 논문 `C:\Users\user\Downloads\LLM 기반 적응형 공격 방어 시스템 논문 초안.html`은 보존.

## 참고 공식 문서

- https://learn.microsoft.com/en-us/windows/wsl/install
- https://docs.docker.com/desktop/setup/install/windows-install/
- https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md

재개 시 사용자가 제공하는 새 로그를 우선하고, 설치 완료나 실험 성공을 추정하지 않는다.
