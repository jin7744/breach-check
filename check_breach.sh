#!/usr/bin/env bash
# ============================================================
#  check_breach.sh  v3 — 내 리눅스 서버 '털렸는지' 자가점검 (IR 기초)
#  보안하는 개발자 (youtube @보안하는개발자) · github.com/jin7744/breach-check
#
#  ✅ 읽기 전용입니다. 무엇도 바꾸거나 지우지 않습니다.
#     믿지 말고 코드를 먼저 읽어보세요 — 그게 보안의 시작입니다.
#
#  사용법:
#     bash check_breach.sh            # 빠른 점검 (수 초)
#     sudo bash check_breach.sh       # 권장 (shadow·root 영역까지)
#     sudo bash check_breach.sh --deep   # 전체 파일시스템 정밀 스캔 포함(느림)
#     bash check_breach.sh --help
#
#  ※ 이건 '기초' 점검입니다. 본격 포렌식($MFT 타임라인·USN저널·Prefetch·메모리)은
#     전용 도구(KAPE·MFTECmd·Plaso·Volatility) 영역이며, 요청 시 check_forensic 별도 제공.
#  ※ 결과는 '확정'이 아니라 '의심 후보'입니다. 각 항목 설명을 읽고 사람이 판단하세요.
# ============================================================
VERSION="v3.0.0"
set -u

# ── 옵션 ──
DEEP=0; for a in "$@"; do
  case "$a" in
    --deep) DEEP=1;;
    -h|--help) cat <<'H'
check_breach.sh — 리눅스 침해 자가점검 (읽기 전용)
  bash check_breach.sh           빠른 점검
  sudo bash check_breach.sh      권장(시스템 영역까지)
  sudo bash check_breach.sh --deep   전체 SUID/웹쉘/무결성/공급망 스캔(느림)
점검 영역: 계정·권한 / 지속성 / SSH / 루트킷 / 네트워크 / 파일·웹쉘 / 로그변조 / 컨테이너 / 공급망
결과 등급: ⛔확정형 침해신호  🔎확인필요  ⚠️주의  ✅정상
H
      exit 0;;
    --version) echo "check_breach.sh $VERSION"; exit 0;;
  esac
done

# ── 색/TTY 가드 (NO_COLOR·비TTY면 색·이모지 끔) ──
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYA=$'\e[36m'; MAG=$'\e[35m'; BLD=$'\e[1m'; DIM=$'\e[2m'; RST=$'\e[0m'
  I_CRIT='⛔'; I_SUS='🔎'; I_MED='⚠️'; I_OK='✅'; I_R='🔴'; I_Y='🟡'; I_G='🟢'
else
  RED=''; GRN=''; YEL=''; CYA=''; MAG=''; BLD=''; DIM=''; RST=''
  I_CRIT='[!!]'; I_SUS='[?]'; I_MED='[!]'; I_OK='[ok]'; I_R='[RISK]'; I_Y='[WARN]'; I_G='[SAFE]'
fi

ROOT=0; [ "$(id -u)" = "0" ] && ROOT=1
CRIT=0; SUS=0; MED=0          # 전역 카운터
A_CRIT=0; A_SUS=0; A_MED=0    # 섹션 카운터
FIND=""                       # TOP3 누적 (확정형)
LOG=""                        # 무색 리포트 누적
HOST="$(hostname 2>/dev/null)"
REPORT="$HOME/breach-check_${HOST}_$(date +%Y%m%d-%H%M%S 2>/dev/null).txt"
T(){ timeout "${1}s" bash -c "$2" 2>/dev/null; }
have(){ command -v "$1" >/dev/null 2>&1; }

# ── 출력 함수 (화면=색 / LOG=무색) ──
say(){ printf '%s\n' "$1"; LOG="${LOG}$(printf '%s' "$1" | sed 's/\x1b\[[0-9;]*m//g')
"; }
sec(){ A_CRIT=0; A_SUS=0; A_MED=0; CUR="$1"; say ""; say "${BLD}${MAG}━━ $1 ━━${RST}"; }
sub(){ say "${CYA}· $1${RST}"; }
note(){ say "     ${DIM}$1${RST}"; }
# crit/sus/med: (문제, 조치)
crit(){ say "   ${RED}${I_CRIT} $1${RST} → $2"; CRIT=$((CRIT+1)); A_CRIT=$((A_CRIT+1)); FIND="${FIND}$1‖$2
"; }
sus(){  say "   ${YEL}${I_SUS} $1${RST} → $2"; SUS=$((SUS+1)); A_SUS=$((A_SUS+1)); }
med(){  say "   ${YEL}${I_MED} $1${RST} → $2"; MED=$((MED+1)); A_MED=$((A_MED+1)); }
ok(){   say "   ${GRN}${I_OK} $1${RST}"; }
mini(){ # 섹션 끝 미니요약
  if [ $A_CRIT -gt 0 ]; then say "   ${DIM}└ ${CUR}: ${RED}${I_R} 확정 ${A_CRIT}${RST}${DIM}, 확인필요 ${A_SUS}, 주의 ${A_MED}${RST}";
  elif [ $A_SUS -gt 0 ] || [ $A_MED -gt 0 ]; then say "   ${DIM}└ ${CUR}: ${YEL}확인필요 ${A_SUS}, 주의 ${A_MED}${RST}";
  else say "   ${DIM}└ ${CUR}: ${GRN}이상 없음${RST}"; fi; }

# ── 헤더 + preflight ──
say "${BLD}== check_breach.sh ${VERSION} · 침해 자가점검 (기초/읽기전용) ==${RST}"
say "호스트 ${HOST} · 커널 $(uname -r 2>/dev/null) · $([ $ROOT = 1 ] && echo root || echo 'user') · $(date '+%F %T' 2>/dev/null)"
say "${GRN}이 스크립트는 읽기 전용입니다 — 아무것도 바꾸거나 지우지 않습니다.${RST}"
[ $ROOT = 0 ] && say "${YEL}일반 권한: shadow·일부 로그를 못 봅니다. 빈 결과를 '안전'으로 오해 금지 → sudo 권장.${RST}"
[ $DEEP = 1 ] && say "${YEL}[--deep] 전체 파일시스템 정밀 스캔 포함 (시간 걸립니다).${RST}"
sub "preflight — 점검 도구 가용성"
pf=""; for t in ss ip last awk find systemctl lsattr getcap bpftool debsums docker; do
  if have "$t"; then pf="$pf ${GRN}✓$t${RST}"; else pf="$pf ${DIM}✗$t${RST}"; fi; done
say "    $pf"
note "✗ 표시 도구가 보는 항목은 건너뜁니다(거짓 음성 주의). bpftool/debsums는 옵션."

# ════════ 1. 계정·권한 ════════
sec "1. 계정·권한 백도어"
u0=$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd 2>/dev/null)
[ -n "$u0" ] && crit "root 외 UID 0 계정: $(echo $u0)" "거의 100% 백도어. 'id $(echo $u0|awk "{print \$1}")'로 확인, 모르면 침해" || ok "UID 0 계정은 root 뿐"
if [ $ROOT = 1 ]; then
  empty=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)
  [ -n "$empty" ] && crit "빈 패스워드 계정: $(echo $empty)" "비번 없이 로그인 가능. passwd로 잠그거나 삭제" || ok "빈 패스워드 계정 없음"
else note "shadow는 sudo 필요 — 빈 패스워드 미확인"; fi
sh1=$(awk -F: '($3<1000 && $3!=0 && $7 ~ /(bash|sh|zsh)$/){print $1}' /etc/passwd 2>/dev/null)
[ -n "$sh1" ] && sus "로그인 셸 가진 시스템계정: $(echo $sh1)" "sync 외엔 의심. 서비스계정에 셸은 백도어 가능" || ok "시스템계정에 로그인 셸 없음"
sub "특권 그룹 멤버 (모르는 사용자 끼었나)"
for g in sudo wheel docker lxd adm shadow disk; do m=$(getent group $g 2>/dev/null | cut -d: -f4); [ -n "$m" ] && note "[$g] $m"; done
note "docker·lxd 멤버는 사실상 root — 반드시 확인"
if [ $ROOT = 1 ]; then
  nop=$(grep -rEn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -vE '#')
  [ -n "$nop" ] && sus "sudoers NOPASSWD 항목 존재" "낯선 사용자명이면 의심. 'sudo cat /etc/sudoers.d/*'로 확인" || ok "sudoers NOPASSWD 없음"
fi
AUTH=$(ls /var/log/auth.log /var/log/secure 2>/dev/null | head -1)
if [ -n "$AUTH" ] && [ -r "$AUTH" ]; then
  topf=$(grep 'Failed password' "$AUTH" 2>/dev/null | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head -1 | awk '{print $3" ("$1"회)"}')
  acc=$(grep -c 'Accepted ' "$AUTH" 2>/dev/null); acc=${acc//[^0-9]/}
  [ -n "$topf" ] && note "실패 최다 IP: $topf · 성공 로그인 ${acc:-0}건 → 실패폭주 IP가 '성공'에도 있으면 뚫림(grep Accepted $AUTH)"
fi
sub "최근 로그인 (낯선 IP·시간 확인)"; last -aiF 2>/dev/null | head -5 | sed 's/^/     /'
mini

# ════════ 2. 지속성 ════════
sec "2. 지속성(persistence) 백도어"
EVIL='/dev/tcp/|bash -i|nc -e|ncat -e|base64 -d|base64 --d|python -c|perl -e|socat .*exec|\| ?sh\b|(bash|sh|source|\.) +/tmp/|(bash|sh) +/dev/shm/|/tmp/[^ ]*\.(sh|py|pl|elf|bin)\b'
cron=$( { for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/[$u] /"; done; cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/* 2>/dev/null; } | grep -vE '^\s*#|^\s*$' | sed 's/>>\?[^|]*//' | grep -Ei "$EVIL" )
[ -n "$cron" ] && crit "cron에 의심 패턴: $(echo "$cron" | head -1 | cut -c1-70)" "리버스쉘/임시경로 실행. crontab -l 로 전체 확인" || ok "cron 의심 패턴 없음"
sysd=$(find /etc/systemd/system /run/systemd/system -maxdepth 2 -name '*.service' 2>/dev/null | xargs -r grep -lEi "$EVIL" 2>/dev/null)
[ -n "$sysd" ] && crit "systemd .service ExecStart 의심: $(basename $(echo $sysd|head -1))" "ExecStart에 외부다운/임시경로. cat 으로 확인" || ok "systemd .service 의심 없음"
# 신규: .socket / .path / drop-in 확장
sockp=$(find /etc/systemd/system /run/systemd/system -name '*.socket' -o -name '*.path' 2>/dev/null | xargs -r grep -lEi "$EVIL" 2>/dev/null)
[ -n "$sockp" ] && crit "systemd .socket/.path 트리거 백도어: $(basename $(echo $sockp|head -1))" "소켓·파일변화로 악성 실행. 짝 .service 확인" || ok ".socket/.path 의심 없음"
dropin=$(find /etc/systemd/system -name '*.conf' -path '*.d/*' 2>/dev/null | xargs -r grep -lEi "ExecStartPost|ExecStartPre" 2>/dev/null | xargs -r grep -lEi "$EVIL" 2>/dev/null)
[ -n "$dropin" ] && crit "systemd drop-in에 몰래 추가된 실행: $(echo $dropin|head -1)" "정상 유닛에 ExecStartPost 삽입. 내용 확인" || true
gen=$(ls -A /etc/systemd/system-generators/ 2>/dev/null | grep -vE '^systemd-')
[ -n "$gen" ] && crit "systemd generator 비표준 스크립트: $gen" "부팅 극초기 실행. 거의 확실 의심" || ok "비표준 generator 없음"
rc=$(grep -rEnI "$EVIL" /etc/profile /etc/bash.bashrc /etc/profile.d/ /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile /home/*/.zshrc 2>/dev/null | grep -viE 'nvm|conda|pyenv|rbenv|sdkman|starship|direnv|cargo|\.cache' )
[ -n "$rc" ] && crit "셸 RC/프로필 백도어: $(echo "$rc"|head -1|cut -c1-60)" "로그인마다 실행. 해당 줄 삭제 검토(정상 nvm/conda는 제외됨)" || ok "셸 RC 백도어 패턴 없음"
pam=$(grep -rEn 'pam_exec|pam_python|/tmp/|/dev/shm' /etc/pam.d/ 2>/dev/null)
[ -n "$pam" ] && crit "PAM 설정 의심 항목" "인증 우회/실행 백도어. /etc/pam.d 확인" || ok "PAM 백도어 패턴 없음"
mini

# ════════ 3. SSH ════════
sec "3. SSH 백도어"
for kf in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -r "$kf" ] || continue
  n=$(grep -vcE '^\s*#|^\s*$' "$kf" 2>/dev/null)
  [ "${n:-0}" -gt 0 ] && note "$kf : 등록키 ${n}개 → 내가 등록한 키만 있나 확인"
  cmd=$(grep -c 'command=' "$kf" 2>/dev/null)
  [ "${cmd:-0}" -gt 0 ] && sus "$kf 에 command= 강제실행 키 ${cmd}개" "접속 시 특정 명령 실행하는 백도어 키. 줄 확인"
done
SCFG=/etc/ssh/sshd_config
if [ -r "$SCFG" ]; then
  grep -qiE '^\s*PermitEmptyPasswords\s+yes' "$SCFG" && crit "sshd PermitEmptyPasswords yes" "빈 비번 SSH 허용. no로 변경" || true
  grep -qiE '^\s*PermitRootLogin\s+yes' "$SCFG" && med "sshd PermitRootLogin yes" "root 직접 SSH 허용. prohibit-password 권장" || true
fi
rcssh=$(ls /root/.ssh/rc /home/*/.ssh/rc 2>/dev/null)
[ -n "$rcssh" ] && sus "~/.ssh/rc 존재(로그인시 실행): $rcssh" "드문 파일. 내용 확인" || true
[ $A_CRIT -eq 0 ] && [ $A_SUS -eq 0 ] && ok "SSH 백도어 흔적 없음"
mini

# ════════ 4. 루트킷·은폐 ════════
sec "4. 루트킷·은폐"
if [ -e /etc/ld.so.preload ]; then crit "/etc/ld.so.preload 존재" "라이브러리 후킹 루트킷 단골. 내용: $(cat /etc/ld.so.preload 2>/dev/null|tr '\n' ' ')"; else ok "/etc/ld.so.preload 없음"; fi
[ -n "${LD_PRELOAD:-}" ] && sus "현재 LD_PRELOAD 설정됨: $LD_PRELOAD" "정상 도구일 수 있으나 확인" || true
_hsnap(){ comm -13 <(ps -eo pid= 2>/dev/null|tr -d ' '|sort -u) <(ls -d /proc/[0-9]* 2>/dev/null|sed 's|/proc/||'|sort -u); }
hs1=$(_hsnap); sleep 0.4; hs2=$(_hsnap)
hid=$(comm -12 <(echo "$hs1"|sort -u) <(echo "$hs2"|sort -u) | head)
[ -n "$hid" ] && crit "ps에 계속 안 보이는 /proc PID: $(echo $hid)" "프로세스 은폐 루트킷 의심. cat /proc/PID/cmdline 확인" || ok "숨은 프로세스 없음(ps↔/proc 일치)"
# memfd fileless (ROOT 가드)
if [ $ROOT = 1 ]; then
  memfd=$(ls -la /proc/[0-9]*/exe 2>/dev/null | grep -E 'memfd:' | head)
  [ -n "$memfd" ] && sus "memfd(디스크에 없는) 실행 프로세스 존재" "fileless 악성 가능. 단 snap/Go/JIT 정상도 있음 — 외부연결 동반이면 위험" || ok "memfd fileless 프로세스 없음"
else note "memfd/타 사용자 fd 스캔은 sudo 필요"; fi
if have debsums && [ $DEEP = 1 ]; then
  bad=$(T 60 "debsums -ec 2>/dev/null" | head)
  [ -n "$bad" ] && crit "변조된 패키지 파일: $(echo "$bad"|head -1)" "시스템 바이너리/설정 변조. 재설치 검토" || ok "debsums 무결성 이상 없음"
else note "바이너리 무결성: --deep + debsums 필요(apt install debsums)"; fi
mini

# ════════ 5. 네트워크 ════════
sec "5. 네트워크 (나가는 연결·역쉘·변조)"
if have ss; then
  ext=$(ss -tnp 2>/dev/null | grep ESTAB | grep -vE '127\.0\.0\.1|::1|[ :]10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|\[::ffff:10')
  if [ -n "$ext" ]; then say "$(echo "$ext"|head -5|sed 's/^/     /')"; med "외부로 나가는 연결 존재" "프로세스/IP가 내가 띄운 것인지 확인(CDN·미러·모니터링은 정상)"; else ok "사설망 외 연결 없음"; fi
fi
rsh=$(ps -eo cmd 2>/dev/null | grep -iE 'bash -i|nc -e|ncat -e|/dev/tcp/|socat .*exec|python.*pty.spawn|sh -i' | grep -v grep | head)
[ -n "$rsh" ] && crit "역방향 쉘 패턴 프로세스: $(echo "$rsh"|head -1|cut -c1-50)" "공격자가 띄운 셸. PID 확인 후 차단" || ok "역쉘 프로세스 패턴 없음"
have ip && ip link 2>/dev/null | grep -q PROMISC && sus "네트워크 카드 PROMISC 모드" "스니핑 의심. 정상 모니터링도 있음" || true
# IMDS 도용 흔적 (클라우드 환경만)
if T 2 "exec 3<>/dev/tcp/169.254.169.254/80" 2>/dev/null; then
  imds=$(grep -rE '169\.254\.169\.254|iam/security-credentials|computeMetadata' /root/.bash_history /home/*/.bash_history 2>/dev/null | head -1)
  [ -n "$imds" ] && sus "클라우드 메타데이터 자격증명 경로 친 흔적" "키 탈취 시도 가능. 정상 SDK도 호출함 — 누가 쳤나 확인" || ok "IMDS 자격증명 접근 흔적 없음(history)"
fi
mini

# ════════ 6. 파일·웹쉘·SUID·공급망 ════════
sec "6. 파일·웹쉘·SUID·공급망"
SELFD=$(dirname "$(realpath "$0" 2>/dev/null)" 2>/dev/null)
ex=$(find /tmp /dev/shm /var/tmp -maxdepth 2 -type f -executable 2>/dev/null | grep -vF "${SELFD:-/nonexistent_xyz}")
elf=""; scr=""
for f in $ex; do
  if [ "$(head -c4 "$f" 2>/dev/null | tr -d '\0')" = "$(printf 'ELF')" ] || head -c4 "$f" 2>/dev/null | grep -qa ELF; then elf="$elf $f"; else scr="$scr $f"; fi
done
[ -n "$elf" ] && crit "임시경로 ELF 실행바이너리:$(echo "$elf"|cut -c1-60)" "fileless 악성 단골. 파일 정체 확인" || true
[ -n "$scr" ] && sus "임시경로 실행 스크립트:$(echo "$scr"|cut -c1-60)" "설치/빌드 스크립트면 정상, 모르는 거면 내용 확인" || true
[ -z "$elf$scr" ] && ok "임시경로 실행파일 없음"
# 공급망 IoC (Shai-Hulud 등) — 빠른 제한경로 + --deep 전체
SC_PATHS="/home /var/www /srv /opt /root"
[ $DEEP = 1 ] && SC_PATHS="/"
sc=$(T 30 "find $SC_PATHS -xdev \( -name bun_environment.js -o -name setup_bun.js -o -name truffleSecrets.json -o -name shai-hulud-workflow.yml \) 2>/dev/null" | head)
[ -n "$sc" ] && crit "공급망 공격 IoC 파일 발견: $(echo "$sc"|head -1)" "Shai-Hulud 등 npm 웜 흔적. 즉시 격리+토큰 회수" || ok "알려진 공급망 IoC 파일 없음"
pi=$(grep -rlE '"(pre|post)install"' /home/*/*/package.json /var/www/*/package.json 2>/dev/null | xargs -r grep -lE 'curl|webhook|trufflehog|//[0-9]' 2>/dev/null | head)
[ -n "$pi" ] && sus "package.json install훅에 외부호출: $(echo $pi|head -1)" "악성 postinstall 가능. 스크립트 내용 확인" || true
if [ $DEEP = 1 ]; then
  suid=$(T 30 "find / -xdev -perm -4000 -type f 2>/dev/null | grep -vE '^/(usr/bin|usr/sbin|bin|sbin|usr/lib|usr/libexec)/'")
  [ -n "$suid" ] && crit "비표준 위치 SUID: $(echo "$suid"|head -2|tr '\n' ' ')" "권한상승 백도어 가능" || ok "비표준 SUID 없음"
  # GTFOBins: 인터프리터가 SUID면 한 줄로 root
  gtfo=$(T 30 "find / -xdev -perm -4000 -type f 2>/dev/null" | grep -E '/(find|vim|nano|less|awk|gawk|tar|zip|env|python[0-9.]*|perl|ruby|nmap|gdb|bash|cp|dd|xxd|sed|socat|ed|man|more|view|rsync)$')
  [ -n "$gtfo" ] && crit "GTFOBins SUID 바이너리: $(echo "$gtfo"|head -2|tr '\n' ' ')" "이 SUID는 한 줄로 root 셸 가능. 즉시 chmod -s 검토" || ok "GTFOBins SUID 악용 대상 없음"
  ws=$(T 30 "grep -rlE '(eval|assert|system|passthru|shell_exec|base64_decode).*\\\$_(GET|POST|REQUEST|COOKIE)' /var/www /srv/www /usr/share/nginx 2>/dev/null --include='*.php' --exclude-dir=vendor --exclude-dir=node_modules")
  [ -n "$ws" ] && crit "웹쉘 의심 파일: $(echo "$ws"|head -2|tr '\n' ' ')" "원격 명령실행 백도어. 파일 격리" || ok "웹쉘 패턴 없음"
else note "SUID·GTFOBins·웹쉘 전수 스캔은 --deep (전체 find라 느림)"; fi
for h in /root/.bash_history /home/*/.bash_history; do
  [ -L "$h" ] && crit "$h 가 심볼릭링크($(readlink $h))" "history 은폐. 공격자 단골"
done
mini

# ════════ 7. 로그 변조 ════════
sec "7. 로그 변조·안티포렌식"
for L in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages; do
  [ -e "$L" ] || continue; sz=$(stat -c%s "$L" 2>/dev/null || echo 0)
  [ "${sz:-0}" -lt 5 ] && crit "$L 가 비어있음(${sz}B)" "정상 운영에 로그 0 불가 = 삭제 의심"
done
if have journalctl && [ $ROOT = 1 ]; then
  vf=$(T 20 "journalctl --verify 2>&1 | grep -i fail | head -1")
  [ -n "$vf" ] && sus "journald 무결성 검증 실패" "로그 변조 가능. journalctl --verify 재실행" || ok "journald 무결성 OK"
fi
hz=$(grep -rEn 'HISTSIZE=0|HISTFILE=/dev/null|unset HISTFILE|set \+o history' /root/.bashrc /home/*/.bashrc /etc/profile 2>/dev/null)
[ -n "$hz" ] && sus "history 비활성화 설정 발견" "명령 기록 은폐. 누가 설정했나 확인" || true
[ $A_CRIT -eq 0 ] && [ $A_SUS -eq 0 ] && ok "로그 변조 흔적 없음"
mini

# ════════ 8. 컨테이너 ════════
sec "8. 컨테이너"
INCON=0; { [ -e /.dockerenv ] || grep -qa 'docker\|kubepods\|containerd' /proc/1/cgroup 2>/dev/null; } && INCON=1
if [ $INCON = 1 ]; then
  note "이 시스템은 컨테이너 '안'입니다 — 탈출 발판 점검"
  cap=$(grep CapEff /proc/self/status 2>/dev/null | awk '{print $2}')
  case "$cap" in *[!0]*) echo "$cap" | grep -qiE 'ffff' && sus "위험 capability 보유(CapEff=$cap)" "SYS_ADMIN 등 탈출 발판 가능. CI 러너는 정상";; esac
  [ -L /dev/null ] && crit "/dev/null 이 심볼릭링크" "runC maskedPaths 우회 흔적. 호스트 침해 의심"
  ra=$(ls -la /sys/fs/cgroup/*/release_agent 2>/dev/null | head -1)
  [ -n "$ra" ] && [ -w "$(echo $ra|awk '{print $NF}')" ] 2>/dev/null && crit "cgroup release_agent 쓰기 가능" "컨테이너 탈출 고전 기법" || true
elif have docker && docker info >/dev/null 2>&1; then
  priv=$(docker ps -q 2>/dev/null | while read id; do docker inspect "$id" --format '{{.Name}} {{.HostConfig.Privileged}}' 2>/dev/null; done | grep ' true')
  [ -n "$priv" ] && crit "특권(privileged) 컨테이너 실행: $(echo "$priv"|head -1|awk '{print $1}')" "호스트 장악 가능. 필요 없으면 끄기" || ok "특권 컨테이너 없음"
  hm=$(docker ps -q 2>/dev/null | while read id; do docker inspect "$id" --format '{{.Name}} {{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null; done | grep -E ' /($| |etc|root)| docker.sock')
  [ -n "$hm" ] && crit "호스트 민감경로 마운트 컨테이너" "탈출/호스트침해 가능. -v 확인" || true
else note "docker 미사용 또는 권한 없음 — N/A"; fi
mini

# ════════ 결과 화면 ════════
TC=$((CRIT+SUS+MED))
say ""; say "${BLD}════════════════════════════════════════════${RST}"
if [ $CRIT -gt 0 ]; then LIGHT="${RED}${I_R} 위험${RST}"; VERDICT="침해 의심 강함 — 아래 '먼저 볼 것'부터 확인하세요";
elif [ $((SUS+MED)) -gt 0 ]; then LIGHT="${YEL}${I_Y} 주의${RST}"; VERDICT="확정 신호는 없으나 확인할 항목이 있습니다";
else LIGHT="${GRN}${I_G} 안전${RST}"; VERDICT="1차 스크리닝상 뚜렷한 침해 신호 없음 (정교한 공격은 흔적을 지웁니다)"; fi
say " 판정:  ${BLD}${LIGHT}${RST}    ${I_CRIT} 확정형 ${CRIT}건 · ${I_SUS} 확인필요 ${SUS}건 · ${I_MED} 주의 ${MED}건"
say " ${VERDICT}"
if [ $CRIT -gt 0 ]; then
  say ""; say " ${BLD}▼ 먼저 볼 것 (확정형 침해신호 TOP3)${RST}"
  i=0; printf '%s' "$FIND" | while IFS='‖' read -r problem action; do
    [ -z "$problem" ] && continue; i=$((i+1)); [ $i -gt 3 ] && break
    say "  ${RED}${i}) ${problem}${RST}"; say "     → ${action}"
  done
  say ""; say " ${YEL}털린 게 확실하면 → ①네트워크 격리(전원X) ②스냅샷 ③토큰·키 회수 ④복구${RST}"
  say " 대응 영상: youtube.com/shorts/PzLP5GkN_8E"
fi
[ $DEEP = 0 ] && say " ${DIM}더 깊게: sudo bash $(basename "$0") --deep${RST}"
say " ${DIM}이건 '기초' 점검입니다. 본격 포렌식(MFT·USN·Prefetch)은 전용도구(KAPE 등) 영역.${RST}"
# 리포트 저장
printf '%s\n' "$LOG" > "$REPORT" 2>/dev/null && say " ${CYA}📄 리포트 저장: ${REPORT}${RST}"
say " ${CYA}코드를 다 읽으셨나요? 그게 보안의 시작입니다. — @보안하는개발자${RST}"
