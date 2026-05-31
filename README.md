# breach-check — 내 서버·PC 털렸는지 30초 자가점검

> **"털렸을 때 가장 먼저 보는 곳"을, OS 몰라도 한 번에.**
> 리눅스(`check_breach.sh`) · 윈도우(`check_breach.ps1`) 자가점검 스크립트.
> [보안하는 개발자](https://youtube.com/@%EB%B3%B4%EC%95%88%ED%95%98%EB%8A%94%EA%B0%9C%EB%B0%9C%EC%9E%90) 유튜브에서 만든 오픈소스입니다.

---

## ⚠️ 먼저 읽으세요 — 이건 "기초" 점검입니다

이 스크립트는 **기초 중의 기초** 1차 스크리닝입니다. 침해의 흔한 흔적(비정상 로그인·백도어 계정·지속성·역쉘·웹쉘·로그삭제 등)을 **현재 상태에서 빠르게 훑습니다.**

본격 **디지털 포렌식** — `$MFT` 타임라인, USN 저널, Prefetch/Amcache 실행흔적, SRUM, 메모리 덤프 분석 — 은 이 스크립트 범위 **밖**이며, 전용 도구([KAPE](https://www.kroll.com/kape) · [MFTECmd](https://ericzimmerman.github.io/) · [Plaso/log2timeline](https://plaso.readthedocs.io/) · [Volatility](https://volatilityfoundation.org/)) 영역입니다.

> 포렌식 심화 버전(`check_forensic`)은 요청(이슈)이 있으면 별도로 제공할 예정입니다.

그리고 **결과는 "확정"이 아니라 "의심 후보"입니다.** 각 항목에 오탐(정상인데 떠도 되는 것) 설명을 달아두었으니, 읽고 **사람이 판단**하세요.

### 결과는 이렇게 나옵니다 (v3)

맨 끝에 **신호등 한 줄 판정**(🔴 위험 / 🟡 주의 / 🟢 안전)과 등급별 건수가 나오고, 위험 시 **"먼저 볼 것 TOP3"**에 30초 확인 명령까지 같이 줍니다.

- `⛔ 확정형` — 거의 침해 (root 외 UID0, 로그삭제, 웹쉘 등) → **지금 확인**
- `🔎 확인필요` — 침해일 수도/정상일 수도 → 내 환경인지 대조
- `⚠️ 주의` — 알면 대부분 정상 (외부연결, 시작프로그램 등)
- `✅ 정상`

각 줄은 **"무엇이 문제 → 그래서 뭘 하면 되는지"** 한 줄로, 결과는 `~/breach-check_호스트_날짜.txt`에 자동 저장됩니다. `--help`로 사용법을 봅니다.

---

## 🔒 안전 원칙

- **읽기 전용**입니다. 무엇도 바꾸거나 지우지 않습니다. (직접 코드를 읽고 확인하세요)
- 우리가 "받아서 돌려라"라고 해도 **믿지 말고 코드부터 읽는 것**이 보안의 시작입니다. 그래서 전부 공개합니다.
- `curl | bash` 같은 "묻지마 실행"은 권하지 않습니다. **내려받아 → 코드 확인 → 실행**하세요.

---

## 🐧 리눅스

```bash
# 1) 내려받기 + 무결성 검증 (받은 파일이 진짜인지)
curl -fsSLO https://raw.githubusercontent.com/jin7744/breach-check/main/check_breach.sh
curl -fsSLO https://raw.githubusercontent.com/jin7744/breach-check/main/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing      # check_breach.sh: OK 떠야 함
# 2) 코드 읽기 (필수!)
less check_breach.sh
# 3) 실행 (일부 항목은 sudo 권장)
sudo bash check_breach.sh
# 더 깊게 (SUID·웹쉘·무결성 전수 스캔, 느림)
sudo bash check_breach.sh --deep
```

**점검 8영역:** 계정·권한 / 지속성(cron·systemd·PAM·.bashrc) / SSH 백도어 / 루트킷·은폐(ld.so.preload·숨은프로세스·eBPF) / 네트워크(역쉘·promisc) / 파일·웹쉘·SUID / 로그변조 / 컨테이너

---

## 🪟 윈도우 (PowerShell)

```powershell
# 1) 내려받기 (또는 repo에서 직접)
# 2) 관리자 PowerShell 열기 (Security 이벤트로그 점검에 필요)
# 3) 이 창에서만 실행 허용 후 실행
Set-ExecutionPolicy -Scope Process Bypass
.\check_breach.ps1
```

**점검 5영역:** 계정·인증(이벤트로그 4624/4625/4720) / 지속성(Run키·예약작업·WMI·Winlogon) / 네트워크·프로세스 / 방어무력화·로그삭제(1102·Defender·섀도삭제) / 웹쉘·접근성 백도어

> ⚠️ **반드시 관리자 권한으로.** 일반 권한이면 Security 이벤트로그(로그온·신규계정·로그삭제)를 못 읽고 빈 결과가 나오는데, 이걸 "안전"으로 오해하면 안 됩니다.
>
> ⚠️ **백신이 이 스크립트를 막을 수 있습니다.** 탐지용 키워드(Mimikatz 등)가 들어 있어 일부 백신/AMSI가 과민 반응할 수 있습니다. 코드는 전부 읽기 전용이며 키워드는 문자열 매칭용입니다. 차단되면 코드를 확인한 뒤 예외 처리하세요.

---

## 털린 게 확실하다면 — 대응 순서

명령어 암기보다 **순서**가 중요합니다. (전원 끄면 메모리 증거가 사라집니다)

1. **격리** — 전원은 켠 채로 네트워크만 차단 (`iptables -P INPUT DROP` / 클라우드 보안그룹)
2. **보존** — 메모리·디스크 스냅샷 (`avml`, 클라우드 스냅샷)
3. **회수** — 토큰·키·비밀번호 전부 폐기·재발급
4. **복구** — 그 다음에야 클린 백업에서 복구

▶ 대응 순서 영상: https://youtube.com/shorts/PzLP5GkN_8E

---

## 면책

이 스크립트는 교육·1차 점검 목적입니다. 결과는 의심 후보일 뿐 침해 여부를 단정하지 않으며, 사용은 본인 책임입니다. 정식 침해 대응이 필요하면 전문 인력/기관에 의뢰하세요.

## License

MIT
