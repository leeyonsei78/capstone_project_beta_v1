# VirtualBox 단계 런북 (실 CVE/Metasploit/AutoPenBench용 격리 VM)

목적: Docker/WSL2가 Windows 서비싱 손상으로 막혔으므로, **VirtualBox VM 안에서 Docker를 돌려**
실 CVE·실 Metasploit·AutoPenBench + 더 큰 모델로 에이전트 실험의 외적 타당성을 보강한다.
VirtualBox는 자체 하이퍼바이저를 써서 그 손상된 "가상 머신 플랫폼" 기능에 **의존하지 않으므로**
Docker가 못 깔리는 이 PC에서도 깔릴 가능성이 높다.

환경 확인됨(2026-11-17): winget 사용 가능, C: 581GB 여유, 12 logical cores, 32GB RAM, VBS=Running.
→ VBS가 켜져 있어 VirtualBox 7은 **Hyper-V 백엔드로 느리지만 작동**한다(VBS 끄지 말 것).

---

## A. Windows 쪽 (사용자가 관리자로 실행 — Claude는 elevated 차단됨)

세션에서 `! <명령>` 접두로 실행하면 출력이 대화에 들어옵니다. 관리자 권한을 물으면 승인하세요.

1. **VirtualBox 설치**
   ```
   winget install --id Oracle.VirtualBox -e
   ```
   (설치 후 `VBoxManage --version` 확인. 선택: 확장팩 `winget install Oracle.VirtualBoxExtensionPack`)

2. **Ubuntu Server 24.04 LTS ISO 다운로드** (약 2.5GB)
   - https://releases.ubuntu.com/24.04/ → `ubuntu-24.04.x-live-server-amd64.iso`
   - ISO는 **새 빈 폴더**(예: `C:\vm_iso\`)에 둘 것(다운로드 자료 격리 원칙).

3. **VM 생성** (GUI 또는 아래 VBoxManage). 권장 스펙: 4 vCPU / 8192MB / 60GB VDI(동적).
   - GUI: New → Type=Linux, Version=Ubuntu(64-bit), RAM 8192, CPU 4, 디스크 60GB.
   - 네트워크: **설치 동안은 어댑터1=NAT**(apt·docker·git용 인터넷). 실험 단계에서 격리로 전환(아래 C).
   - EFI 활성화(Settings→System→Enable EFI).

4. **Ubuntu 설치**: ISO로 부팅 → 기본값으로 설치, 사용자 생성, "Install OpenSSH server" 체크(선택, 편리).
   설치 후 ISO 꺼내고 재부팅.

## B. VM 내부 (Ubuntu 게스트에서 실행) — Docker 자동 설치

`provision_vm.sh`를 게스트로 복사(공유폴더/scp/붙여넣기) 후:
```
chmod +x provision_vm.sh && ./provision_vm.sh
```
→ Docker CE 설치, docker 그룹 추가, `docker run hello-world` 검증, **외부 차단 격리 네트워크**(`pentest-lab`,
internal) 생성까지 수행. (재로그인 후 docker 그룹 적용.)

## C. 실험 격리 (중요, 불변 전제)
- 공격 트래픽·표적은 **`pentest-lab` internal 도커 네트워크** 안에서만(외부 egress 없음).
- 설치가 끝나면 VM 어댑터를 **Host-only 또는 Internal Network**로 바꿔 VM 자체의 외부망도 끊는다
  (LLM API를 쓸 때만 제한적으로 NAT 복구 — "두뇌는 API, 손은 격리 안" 원칙).
- API 키는 **환경변수만**(코드·로그·이미지·아티팩트 금지). 합성/실험용 데이터만. 실험 중 재부팅 금지.

## D. 다음 (VM 준비 후)
1. AutoPenBench(MIT, arXiv:2410.03225) · Cochise(MIT, arXiv:2605.11671) 저장소를 **각각 새 빈 디렉터리**에
   클론(다운로드 자료 격리). 코드 감사 후 `pentest-lab` 안에서만 구동.
2. 로컬(Ollama in VM 또는 호스트 Ollama 접근) → DeepSeek API → (비용 승인 후) Claude API 티어로 공격자 능력 사다리와 결합.
3. 결과는 기존 합성 결과(§6.15)와 나란히 보고.
