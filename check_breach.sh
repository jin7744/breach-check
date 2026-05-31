#!/usr/bin/env bash
# ============================================================
#  check_breach.sh  —  내 리눅스 서버 '털렸는지' 자가점검 (IR 수준)
#  보안하는 개발자 (youtube @보안하는개발자)
#
#  ⚠️ 이 스크립트는 "읽기"만 합니다. 무엇도 바꾸거나 지우지 않습니다.
#     믿지 말고 코드를 먼저 읽어보세요 — 그게 보안의 시작입니다.
#
#  사용법:
#     bash check_breach.sh            # 빠른 점검 (수 초)
#     sudo bash check_breach.sh       # 권장 (shadow·root 영역까지)
#     sudo bash check_breach.sh --deep   # 전체 파일시스템 정밀 스캔 포함(느림)
#
#  탐지 8영역: 계정 · 지속성 · SSH · 루트킷 · 네트워크 · 파일/웹쉘 · 로그변조 · 컨테이너
#  결과는 '확정'이 아니라 '의심 후보'입니다. 마지막에 사람이 판단하세요.
#  오탐(정상인데 ⚠로 뜨는 것)이 있을 수 있어 각 항목에 설명을 답니다.
#
#  ※ 이건 '기초 자가점검'입니다 (기초 중의 기초).
#     현재 상태(이벤트·계정·연결·파일)를 빠르게 훑는 1차 스크리닝이에요.
#     본격 디지털 포렌식 — $MFT 타임라인, USN 저널, Prefetch/Amcache 실행흔적,
#     SRUM, 메모리 덤프 분석 — 은 이 스크립트 범위 밖이며 전용 도구
#     (KAPE · MFTECmd · Plaso/log2timeline · Volatility) 영역입니다.
#     포렌식 심화 버전(check_forensic)은 요청이 있으면 별도로 제공합니다.
# ============================================================
set -u
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYA=$'\e[36m'; MAG=$'\e[35m'; BLD=$'\e[1m'; DIM=$'\e[2m'; RST=$'\e[0m'
DEEP=0; [ "${1:-}" = "--deep" ] && DEEP=1
HIGH=0; MED=0
sec(){ printf '\n%s%s%s\n' "$BLD$MAG" "━━ $1 ━━" "$RST"; }
sub(){ printf '%s· %s%s\n' "$CYA" "$1" "$RST"; }
ok(){  printf '   %s✅ %s%s\n' "$GRN" "$1" "$RST"; }
hi(){  printf '   %s⛔ [HIGH] %s%s\n' "$RED" "$1" "$RST"; HIGH=$((HIGH+1)); }
med(){ printf '   %s⚠️  [MED]  %s%s\n' "$YEL" "$1" "$RST"; MED=$((MED+1)); }
note(){ printf '     %s%s%s\n' "$DIM" "$1" "$RST"; }
have(){ command -v "$1" >/dev/null 2>&1; }
ROOT=0; [ "$(id -u)" = "0" ] && ROOT=1
# 빠른 timeout 래퍼 (무거운 명령 폭주 방지)
T(){ timeout "${1}s" bash -c "$2" 2>/dev/null; }

printf '%s== check_breach.sh · 침해 자가점검 (IR) ==%s\n' "$BLD" "$RST"
printf '호스트 %s · 커널 %s · %s · %s\n' "$(hostname)" "$(uname -r)" "$([ $ROOT = 1 ] && echo root || echo 'user(일부 항목은 sudo 권장)')" "$(date '+%F %T')"
[ $DEEP = 1 ] && printf '%s[--deep] 전체 파일시스템 정밀 스캔 포함 (시간 걸립니다)%s\n' "$YEL" "$RST"

# ════════ 1. 계정·권한 백도어 ════════
sec "1. 계정·권한 백도어"
u0=$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd 2>/dev/null)
[ -n "$u0" ] && hi "root 외 UID 0 계정: $(echo $u0) — 거의 100% 백도어" || ok "UID 0 계정은 root 뿐"
if [ $ROOT = 1 ]; then
  empty=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)
  [ -n "$empty" ] && hi "빈 패스워드 계정: $(echo $empty)" || ok "빈 패스워드 계정 없음"
  svc=$(awk -F: '($2!~/^[*!]/ && $2!="" && $3<1000 && $1!="root"){print $1}' /etc/shadow 2>/dev/null)
  [ -n "$svc" ] && med "해시 붙은 시스템계정(로그인 가능): $(echo $svc)" || true
else
  note "shadow는 sudo 필요 — 빈 패스워드 점검 건너뜀"
fi
sh1=$(awk -F: '($3<1000 && $3!=0 && $7 ~ /(bash|sh|zsh)$/){print $1"("$7")"}' /etc/passwd 2>/dev/null)
[ -n "$sh1" ] && med "로그인 셸 가진 시스템계정: $(echo $sh1) — sync 외엔 의심" || ok "시스템계정에 로그인 셸 없음"
sub "특권 그룹 멤버 (모르는 사용자 끼었나)"
for g in sudo wheel docker lxd adm shadow disk; do m=$(getent group $g 2>/dev/null | cut -d: -f4); [ -n "$m" ] && note "[$g] $m"; done
note "docker·lxd 멤버는 사실상 root 권한 — 반드시 확인"
if [ $ROOT = 1 ]; then
  nop=$(grep -rEn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -vE '#')
  [ -n "$nop" ] && med "sudoers NOPASSWD 항목: $(echo "$nop" | head -1) ..." || ok "sudoers NOPASSWD 없음"
fi
note "passwd/shadow/sudoers 최근 변경:"; stat -c '     %y  %n' /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null
sub "최근 성공 로그인 (낯선 IP·시간 확인)"; last -aiF 2>/dev/null | head -6 | sed 's/^/     /'
AUTH=$(ls /var/log/auth.log /var/log/secure 2>/dev/null | head -1)
if [ -n "$AUTH" ] && [ -r "$AUTH" ]; then
  topf=$(grep 'Failed password' "$AUTH" 2>/dev/null | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head -1)
  acc=$(grep -c 'Accepted ' "$AUTH" 2>/dev/null); acc=${acc//[^0-9]/}
  note "실패 최다 IP: ${topf:-없음} · 성공 로그인 ${acc:-0}건"
  note "→ 실패 폭주한 IP가 '성공'에도 있으면 = 뚫림. grep Accepted $AUTH 로 교차확인"
fi

# ════════ 2. 지속성 백도어 ════════
sec "2. 지속성(persistence) 백도어"
# 실행 맥락만 — /dev/tcp 리버스쉘, base64|bash, 임시경로 '실행'. (로그를 /tmp에 쓰는 정상 cron 제외 위해 리다이렉트 우측은 잘라냄)
EVIL='/dev/tcp/|bash -i|nc -e|ncat -e|base64 -d|base64 --d|python -c|perl -e|socat .*exec|\| ?sh\b|(bash|sh|source|\.) +/tmp/|(bash|sh) +/dev/shm/|/tmp/[^ ]*\.(sh|py|pl|elf|bin)\b'
cron=$( { for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/[$u] /"; done; cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/* 2>/dev/null; } | grep -vE '^\s*#|^\s*$' | sed 's/>>\?[^|]*//' | grep -Ei "$EVIL" )
[ -n "$cron" ] && hi "cron에 의심 패턴: $(echo "$cron" | head -1)" || ok "cron 의심 패턴 없음"
[ -n "$cron" ] && note "전체: $(echo "$cron" | wc -l)건 — certbot/백업의 curl은 정상, /tmp·base64|bash·@reboot 리버스쉘이 진짜"
# 시스템 유닛(.service만, .bak 제외)에서 ExecStart 악성 패턴
sysd=$(find /etc/systemd/system /run/systemd/system -maxdepth 2 -name '*.service' 2>/dev/null | xargs -r grep -lEi "$EVIL" 2>/dev/null)
[ -n "$sysd" ] && hi "systemd 유닛 ExecStart 의심: $(echo $sysd | head -1)" || ok "systemd ExecStart 의심 없음"
# 사용자 유닛은 개발용 정상 다수 → 참고로만
usysd=$(find /home/*/.config/systemd /root/.config/systemd -name '*.service' 2>/dev/null | xargs -r grep -lEi "$EVIL" 2>/dev/null)
[ -n "$usysd" ] && note "사용자 systemd 유닛에 패턴(대개 정상 개발서비스): $(echo $usysd|head -1)"
gen=$(ls -A /etc/systemd/system-generators/ 2>/dev/null | grep -vE '^systemd-')
[ -n "$gen" ] && hi "systemd generator(부팅초기 실행)에 비표준 스크립트: $gen" || ok "비표준 systemd generator 없음"
rcl=$(grep -vE '^\s*#|^\s*$|^exit 0' /etc/rc.local 2>/dev/null)
[ -n "$rcl" ] && med "rc.local에 명령 존재: $(echo "$rcl" | head -1)" || true
rc=$(grep -rEnI "$EVIL" /etc/profile /etc/bash.bashrc /etc/profile.d/ /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile /home/*/.zshrc 2>/dev/null | grep -viE 'nvm|conda|pyenv|rbenv|sdkman|starship|direnv|cargo|\.cache' )
[ -n "$rc" ] && hi "셸 RC/프로필 백도어 의심: $(echo "$rc" | head -1)" || ok "셸 RC 백도어 패턴 없음 (nvm/conda 등 정상 eval 제외)"
pc=$(grep -rEn 'PROMPT_COMMAND' /etc/profile /etc/bash.bashrc /etc/profile.d/ /root/.bashrc /home/*/.bashrc 2>/dev/null | grep -Ei "$EVIL")
[ -n "$pc" ] && hi "PROMPT_COMMAND 후킹: $(echo "$pc" | head -1)" || true
pam=$(grep -rEn 'pam_exec|pam_python|/tmp/|/dev/shm' /etc/pam.d/ 2>/dev/null)
[ -n "$pam" ] && hi "PAM 설정에 의심 항목: $(echo "$pam" | head -1)" || ok "PAM 백도어 패턴 없음"
nmd=$(ls -A /etc/NetworkManager/dispatcher.d/ /etc/network/if-up.d/ 2>/dev/null | grep -vE '^(00-|01-|hooks)' )
[ $DEEP = 1 ] && [ -n "$nmd" ] && note "NetworkManager/if-up.d 스크립트: $nmd (모르는 것만 의심)"
ato=$( (have atq && atq) 2>/dev/null)
[ -n "$ato" ] && med "at 예약작업 큐: $(echo "$ato" | head -1) — at -c 로 내용 확인" || true
sub "최근 30일 추가된 cron.d/systemd 유닛"; find /etc/cron.d /etc/systemd/system -type f -mtime -30 2>/dev/null | head -6 | sed 's/^/     /'

# ════════ 3. SSH 백도어 ════════
sec "3. SSH 백도어"
for kf in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -r "$kf" ] || continue
  n=$(grep -vcE '^\s*#|^\s*$' "$kf" 2>/dev/null)
  [ "${n:-0}" -gt 0 ] && note "$kf : 등록키 ${n}개 → 내가 등록한 키만 있나 확인"
  cmd=$(grep -c 'command=' "$kf" 2>/dev/null)
  [ "${cmd:-0}" -gt 0 ] && med "$kf 에 command= 강제실행 키 ${cmd}개 (백도어 가능)"
done
SCFG=/etc/ssh/sshd_config
if [ -r "$SCFG" ]; then
  grep -qiE '^\s*PermitRootLogin\s+yes' "$SCFG" && med "sshd: PermitRootLogin yes"
  grep -qiE '^\s*PermitEmptyPasswords\s+yes' "$SCFG" && hi "sshd: PermitEmptyPasswords yes — 빈 비번 로그인 허용"
  ports=$(grep -iE '^\s*Port\s' "$SCFG" | awk '{print $2}' | tr '\n' ' ')
  [ -n "$ports" ] && note "sshd Port: $ports (22 외 포트는 의도한 것인지 확인)"
fi
rcssh=$(ls /root/.ssh/rc /home/*/.ssh/rc 2>/dev/null)
[ -n "$rcssh" ] && med "~/.ssh/rc 존재(로그인시 실행): $rcssh — 드문 파일, 내용 확인" || true

# ════════ 4. 루트킷·은폐 ════════
sec "4. 루트킷·은폐"
if [ -e /etc/ld.so.preload ]; then hi "/etc/ld.so.preload 존재 — 라이브러리 후킹 루트킷 단골: $(cat /etc/ld.so.preload 2>/dev/null|tr '\n' ' ')"; else ok "/etc/ld.so.preload 없음(정상)"; fi
[ -n "${LD_PRELOAD:-}" ] && med "현재 LD_PRELOAD 환경변수 설정됨: $LD_PRELOAD" || true
# 숨은 프로세스: /proc엔 있는데 ps엔 없는 PID. race(스캔 중 생멸) 제거 위해 2회 스냅샷 교집합
_hsnap(){ comm -13 <(ps -eo pid= 2>/dev/null|tr -d ' '|sort -u) <(ls -d /proc/[0-9]* 2>/dev/null|sed 's|/proc/||'|sort -u); }
hs1=$(_hsnap); sleep 0.4; hs2=$(_hsnap)
hid=$(comm -12 <(echo "$hs1"|sort -u) <(echo "$hs2"|sort -u) | head)
[ -n "$hid" ] && hi "ps에 계속 안 보이는 /proc PID: $(echo $hid) — 프로세스 은폐 루트킷 의심 (cat /proc/PID/cmdline 확인)" || ok "숨은 프로세스 없음(ps↔/proc 일치)"
if have bpftool && [ $ROOT = 1 ]; then
  bp=$(bpftool prog show 2>/dev/null | grep -ciE 'kprobe|xdp|tracepoint|cgroup')
  [ "${bp:-0}" -gt 0 ] && note "적재된 eBPF 프로그램 ${bp}개(kprobe/xdp 등) — Cilium/falco 등 정상도 많으나 모르면 'bpftool prog show'로 확인"
fi
susm=$(lsmod 2>/dev/null | awk 'NR>1 && $3==0 && $1!~/^(nvidia|vbox|vmw|hv_|wsl)/{print $1}' | head)
[ $DEEP = 1 ] && [ -n "$susm" ] && note "사용처(refcount) 0인 커널모듈: $(echo $susm) (대부분 정상, signer 확인용)"
# 바이너리 무결성
if have debsums && [ $DEEP = 1 ]; then
  bad=$(T 60 "debsums -ec 2>/dev/null" | head)
  [ -n "$bad" ] && hi "변조된 패키지 설정/바이너리: $(echo "$bad"|head -1)" || ok "debsums 무결성 이상 없음"
elif have rpm && [ $DEEP = 1 ]; then
  bad=$(T 60 "rpm -Va 2>/dev/null | grep '^..5' | grep -vE '/etc/' " | head)
  [ -n "$bad" ] && hi "rpm 무결성 변조(해시 불일치): $(echo "$bad"|head -1)" || ok "rpm 무결성 이상 없음"
else
  note "바이너리 무결성: --deep + debsums/rpm 필요 (sudo apt install debsums)"
fi
imm=$(lsattr -R /etc/ /usr/bin/ /usr/sbin/ 2>/dev/null | grep -E '^[a-z-]*i[a-z-]* ' | head)
[ $DEEP = 1 ] && [ -n "$imm" ] && med "immutable(+i) 잠긴 파일 — 악성파일 보호용일 수 있음: $(echo "$imm"|head -1|awk '{print $2}')"

# ════════ 5. 네트워크 ════════
sec "5. 네트워크 (나가는 연결·역쉘·변조)"
if have ss; then
  ext=$(ss -tnp 2>/dev/null | grep ESTAB | grep -vE '127\.0\.0\.1|::1|[ :]10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|\[::ffff:10')
  if [ -n "$ext" ]; then note "외부 ESTABLISHED 연결:"; echo "$ext" | head -6 | sed 's/^/     /'; med "외부로 나가는 연결 존재 — 프로세스/IP가 내가 띄운 것인지 확인(CDN·미러·모니터링은 정상)"; else ok "사설망 외 연결 없음"; fi
  lis=$(ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | grep -vE '127\.0\.0\.1|::1' | grep -oE ':[0-9]+$' | tr -d ':' | awk '$1>1024 && $1!=8080' | sort -un | tr '\n' ' ')
  [ -n "$lis" ] && note "외부 노출 LISTEN 고포트: $lis (모르는 포트는 프로세스 확인 ss -tlnp)"
fi
rsh=$(ps -eo cmd 2>/dev/null | grep -iE 'bash -i|nc -e|ncat -e|/dev/tcp/|socat .*exec|python.*pty.spawn|sh -i' | grep -v grep | head)
[ -n "$rsh" ] && hi "역방향 쉘 패턴 프로세스: $(echo "$rsh"|head -1)" || ok "역쉘 프로세스 패턴 없음"
have ip && ip link 2>/dev/null | grep -q PROMISC && med "네트워크 카드 PROMISC 모드 — 스니핑 의심" || true
hosts=$(grep -vE '^\s*#|^\s*$|localhost|127\.0\.0\.1|::1|ip6-' /etc/hosts 2>/dev/null | head)
[ -n "$hosts" ] && note "/etc/hosts 커스텀 항목: $(echo "$hosts"|head -1) (내가 넣은 것만 정상)"
grep -qE '^\s*nameserver' /etc/resolv.conf 2>/dev/null && note "DNS: $(grep nameserver /etc/resolv.conf|awk '{print $2}'|tr '\n' ' ') (모르는 DNS면 변조 의심)"

# ════════ 6. 파일·웹쉘·SUID ════════
sec "6. 파일·웹쉘·SUID"
sub "/tmp·/dev/shm·/var/tmp 실행파일 (fileless 단골)"
ex=$(find /tmp /dev/shm /var/tmp -maxdepth 2 -type f -executable 2>/dev/null | head)
[ -n "$ex" ] && hi "임시경로 실행파일: $(echo "$ex"|head -3|tr '\n' ' ')" || ok "임시경로 실행파일 없음"
# 임시경로에서 '실행 중'인 프로세스
runtmp=$(ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E '/tmp/|/dev/shm|/var/tmp' | sed 's|.*-> ||' | sort -u | head)
[ -n "$runtmp" ] && hi "임시경로에서 실행 중인 프로세스: $(echo $runtmp)" || true
delc=$(ls -l /proc/[0-9]*/exe 2>/dev/null | grep -c '(deleted)')
[ "${delc:-0}" -gt 0 ] && note "삭제된 바이너리로 실행 중 ${delc}개 — 업데이트 잔존이 대부분이나 모르는 건 확인"
if [ $DEEP = 1 ]; then
  sub "비표준 위치 SUID (--deep)"
  suid=$(T 30 "find / -xdev -perm -4000 -type f 2>/dev/null | grep -vE '^/(usr/bin|usr/sbin|bin|sbin|usr/lib|usr/libexec)/'")
  [ -n "$suid" ] && hi "비표준 SUID 바이너리: $(echo "$suid"|head -3|tr '\n' ' ')" || ok "비표준 위치 SUID 없음"
  sub "최근 7일 새 SUID (--deep)"
  nsuid=$(T 30 "find / -xdev -perm -4000 -type f -mtime -7 2>/dev/null")
  [ -n "$nsuid" ] && hi "최근 생성/변경 SUID: $(echo "$nsuid"|head -3|tr '\n' ' ')" || true
  sub "웹디렉토리 최근 웹쉘 패턴 (--deep, node_modules/vendor 제외)"
  ws=$(T 30 "grep -rlE '(eval|assert|system|passthru|shell_exec|base64_decode).*\\\$_(GET|POST|REQUEST|COOKIE)' /var/www /srv/www /usr/share/nginx 2>/dev/null --include='*.php' --exclude-dir=vendor --exclude-dir=node_modules")
  [ -n "$ws" ] && hi "웹쉘 의심 파일: $(echo "$ws"|head -3|tr '\n' ' ')" || ok "웹쉘 패턴 없음(vendor/node_modules 제외)"
else
  note "SUID 전수·웹쉘 스캔은 --deep 옵션 (전체 find라 느림)"
fi
# orphan 바이너리 (패키지 미소속) — 빠른 핵심 경로만
if [ $DEEP = 1 ] && (have dpkg || have rpm); then
  sub "패키지에 안 속한 바이너리 (orphan, --deep)"
  orph=""
  for f in $(ls /usr/bin /usr/sbin 2>/dev/null | head -400); do
    p=/usr/bin/$f; [ -f "$p" ] || p=/usr/sbin/$f; [ -f "$p" ] || continue
    if have dpkg; then dpkg -S "$p" >/dev/null 2>&1 || orph="$orph $f"; fi
  done
  [ -n "$orph" ] && med "패키지 미소속 바이너리(직접 설치/이식 의심): $(echo $orph | head -c 200)" || ok "표준 경로 orphan 바이너리 없음"
fi
# bash history 무력화
for h in /root/.bash_history /home/*/.bash_history; do
  [ -L "$h" ] && hi "$h 가 심볼릭링크(/dev/null 등)로 — history 은폐: $(readlink $h)"
done
hz=$(grep -rEn 'HISTSIZE=0|HISTFILE=/dev/null|unset HISTFILE|set \+o history' /root/.bashrc /home/*/.bashrc /etc/profile 2>/dev/null)
[ -n "$hz" ] && med "history 비활성화 설정: $(echo "$hz"|head -1)" || true

# ════════ 7. 로그 변조·안티포렌식 ════════
sec "7. 로그 변조·안티포렌식"
for L in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages; do
  [ -e "$L" ] || continue
  sz=$(stat -c%s "$L" 2>/dev/null || echo 0)
  [ "${sz:-0}" -lt 5 ] && hi "$L 가 비어있음(${sz}B) — 정상 운영에 로그 0은 삭제 의심" || true
done
if have journalctl && [ $ROOT = 1 ]; then
  vf=$(T 20 "journalctl --verify 2>&1 | grep -i fail | head -1")
  [ -n "$vf" ] && med "journald 무결성 검증 실패: $vf" || ok "journald 무결성 OK"
fi
# wtmp 공백 (last 와 파일 mtime 비교)
if [ -r /var/log/wtmp ]; then
  lc=$(last 2>/dev/null | grep -vcE '^$|wtmp begins'); note "wtmp 로그인 레코드 ${lc}건 ($([ "${lc:-0}" -lt 2 ] && echo '너무 적으면 변조 의심' || echo '참고'))"
fi
have auditctl && { astat=$(auditctl -s 2>/dev/null | grep -oE 'enabled [0-9]'); [ "$astat" = "enabled 0" ] && med "auditd 비활성화됨(enabled 0) — 공격자가 끈 것일 수 있음"; } || true

# ════════ 8. 컨테이너 ════════
sec "8. 컨테이너 (있으면)"
if have docker && (docker info >/dev/null 2>&1); then
  priv=$(docker ps --quiet 2>/dev/null | while read id; do docker inspect "$id" --format '{{.Name}} priv={{.HostConfig.Privileged}}' 2>/dev/null; done | grep 'priv=true')
  [ -n "$priv" ] && hi "특권(privileged) 컨테이너 실행 중: $(echo "$priv"|head -1) — 호스트 장악 가능" || ok "특권 컨테이너 없음"
  hm=$(docker ps -q 2>/dev/null | while read id; do docker inspect "$id" --format '{{.Name}} {{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' 2>/dev/null; done | grep -E ' /:| /etc| /root| /var/run/docker.sock')
  [ -n "$hm" ] && hi "호스트 민감경로 마운트 컨테이너: $(echo "$hm"|head -1)" || true
else
  note "docker 미사용 또는 권한 없음 — 건너뜀"
fi

# ════════ 결과 ════════
printf '\n%s════════════════════════════════════════════%s\n' "$BLD" "$RST"
if [ $((HIGH+MED)) -eq 0 ]; then
  printf '%s✅ 뚜렷한 침해 신호 없음.%s 정교한 공격은 흔적을 지웁니다 — 정기 점검 권장.\n' "$GRN$BLD" "$RST"
else
  printf '%s⛔ HIGH %s건  ⚠️ MED %s건%s — 위 항목을 확인하세요.\n' "$BLD" "$HIGH" "$MED" "$RST"
  printf '   각 항목 옆 설명(오탐 여부)을 먼저 읽고, 모르는 것만 파고드세요.\n'
  printf '   %s털린 게 확실하면 → 대응 순서: ①네트워크 격리(전원X) ②스냅샷 ③토큰·키 회수 ④복구%s\n' "$YEL" "$RST"
  printf '   대응 영상: youtube.com/shorts/PzLP5GkN_8E\n'
fi
[ $DEEP = 0 ] && printf '   %s더 깊게: sudo bash %s --deep (SUID·웹쉘·무결성 전수 스캔)%s\n' "$DIM" "$(basename "$0")" "$RST"
printf '%s코드를 다 읽으셨나요? 그게 보안의 시작입니다. — @보안하는개발자%s\n' "$CYA" "$RST"
