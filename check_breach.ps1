<#
============================================================
  check_breach.ps1  v3 — 내 윈도우 '털렸는지' 자가점검 (IR 기초)
  보안하는 개발자 (youtube @보안하는개발자) · github.com/jin7744/breach-check

  [OK] 읽기 전용입니다. 무엇도 바꾸거나 지우지 않습니다.
       믿지 말고 코드를 먼저 읽어보세요 — 그게 보안의 시작입니다.

  사용법 (관리자 PowerShell 권장):
     Set-ExecutionPolicy -Scope Process Bypass
     .\check_breach.ps1            # 점검
     .\check_breach.ps1 -Help

  ※ 이건 '기초' 점검입니다. 본격 포렌식($MFT·USN저널·Prefetch·메모리)은 전용 도구
     (KAPE·MFTECmd·Plaso·Volatility) 영역이며, 요청 시 check_forensic 별도 제공.
  ※ 관리자 권한이어야 Security 이벤트로그(로그온·신규계정·로그삭제)까지 봅니다.
     일반 권한이면 그 항목은 '권한 없어 미확인'이며, 빈 결과를 '안전'으로 오해하면 안 됩니다.
  ※ 결과는 '확정'이 아니라 '의심 후보'입니다. 각 항목 설명을 읽고 사람이 판단하세요.
============================================================
#>
param([switch]$Help, [switch]$Version)
$VER = "v3.0.0"
if ($Version) { "check_breach.ps1 $VER"; exit 0 }
if ($Help) {
@"
check_breach.ps1 — 윈도우 침해 자가점검 (읽기 전용)
  .\check_breach.ps1        점검 (관리자 권장)
점검 영역: 계정·인증 / 지속성 / 네트워크·프로세스 / 방어무력화·로그 / 웹쉘·접근성 / 심화(ASEP)
등급: [확정형] 침해신호  [확인필요]  [주의]  [정상]
"@; exit 0
}
$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
$script:CRIT=0; $script:SUS=0; $script:MED=0
$script:AC=0; $script:AS=0; $script:AM=0
$script:FIND=@(); $script:LOG=@(); $script:CUR=""
$priv='^127\.|^::1|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^169\.254\.|^fe80|^0\.0\.0\.0'

function Say($t){ Write-Host $t; $script:LOG += ($t -replace '\x1b\[[0-9;]*m','') }
function Sec($t){ $script:AC=0;$script:AS=0;$script:AM=0;$script:CUR=$t; Say ""; Say "━━ $t ━━" }
function Sub($t){ Say "· $t" }
function Note($t){ Say "     $t" }
function Crit($p,$a){ Say "   [확정형] $p"; Say "        → $a"; $script:CRIT++;$script:AC++; $script:FIND+=,@($p,$a) }
function Sus($p,$a){ Say "   [확인필요] $p"; Say "        → $a"; $script:SUS++;$script:AS++ }
function Med($p,$a){ Say "   [주의] $p"; Say "        → $a"; $script:MED++;$script:AM++ }
function Ok($t){ Say "   [정상] $t" }
function Mini(){ if($script:AC){Say "   └ $($script:CUR): 위험 확정 $($script:AC), 확인필요 $($script:AS), 주의 $($script:AM)"} elseif($script:AS -or $script:AM){Say "   └ $($script:CUR): 확인필요 $($script:AS), 주의 $($script:AM)"} else {Say "   └ $($script:CUR): 이상 없음"} }
# 색상은 콘솔에서만(가독), 로그/캡처는 무색. Write-Host 색은 등급 텍스트로 대체(redirect 호환)

Say "== check_breach.ps1 $VER · 침해 자가점검 (기초/읽기전용) =="
Say ("호스트 {0} · {1} · {2}" -f $env:COMPUTERNAME, $(if($IsAdmin){'관리자'}else{'일반(관리자 권장)'}), (Get-Date -Format 'yyyy-MM-dd HH:mm'))
Say "이 스크립트는 읽기 전용입니다 — 아무것도 바꾸거나 지우지 않습니다."
if(-not $IsAdmin){ Say "[!] 일반 권한: Security 이벤트로그(로그온·신규계정·로그삭제)를 못 봅니다. 빈 결과를 '안전'으로 오해 금지 → 관리자로 다시 실행 권장." }
# preflight + 명령줄 감사 상태
$cmdAudit = (auditpol /get /subcategory:"Process Creation" 2>$null | Select-String 'Success')
Sub "preflight"
Note ("관리자 {0} · 명령줄감사(4688) {1}" -f $(if($IsAdmin){'O'}else{'X'}), $(if($cmdAudit){'켜짐'}else{'꺼짐 → LSASS/vssadmin 일부 항목 거짓음성 가능'}))

# ════════ 1. 계정·인증 ════════
Sec "1. 계정·인증"
Sub "로컬 Administrators 멤버"
Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { Note ("{0}  ({1})" -f $_.Name,$_.PrincipalSource) }
$na = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} -MaxEvents 50 2>$null
if($na){ Crit ("최근 계정 생성 이벤트(4720) {0}건" -f $na.Count) "내가 만든 계정인지 확인. net user 로 목록 대조" } else { Ok "최근 신규계정 이벤트 없음" }
$pf = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 500 2>$null
if($pf){ if($pf.Count -ge 50){ Sus ("로그온 실패(4625) {0}건" -f $pf.Count) "무차별 대입 흔적. 성공(4624) 시각·계정 교차확인" } else { Note ("로그온 실패 {0}건 (노출 시 봇 스캔 정상)" -f $pf.Count) } }
$priv2 = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4732,4728,4756} -MaxEvents 50 2>$null
if($priv2){ Sus ("특권그룹 추가 이벤트 {0}건" -f $priv2.Count) "관리자/원격 그룹에 누가 추가됐나 확인" }
Sub "RDP 원격 로그인 (낯선 IP·시간)"
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';Id=21,25} -MaxEvents 5 2>$null | ForEach-Object { Note ("{0}  {1}" -f $_.TimeCreated, (($_.Message -split "`n")[0])) }
if($script:AC -eq 0 -and $script:AS -eq 0){ Ok "계정·인증 뚜렷한 이상 없음" }
Mini

# ════════ 2. 지속성 ════════
Sec "2. 지속성(자동시작)"
$evil = 'powershell|cmd /c|-enc|-e |frombase64|downloadstring|iwr |curl |certutil|mshta|wscript|cscript|\.tmp|\\temp\\|appdata|bitsadmin|regsvr32'
Sub "레지스트리 Run/RunOnce"
$runKeys='HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
foreach($k in $runKeys){ $p=Get-ItemProperty $k 2>$null; if($p){ $p.PSObject.Properties | ? {$_.Name -notmatch '^PS'} | ForEach-Object { if($_.Value -match $evil){ Crit ("Run키 의심: {0}" -f $_.Name) "값에 인코딩/임시경로 실행. 레지스트리에서 값 확인" } else { Note ("{0} = {1}" -f $_.Name, ($_.Value -replace '\s+',' ')) } } } }
Sub "예약 작업 의심 액션"
Get-ScheduledTask | ? {$_.State -ne 'Disabled' -and $_.TaskPath -notmatch '\\Microsoft\\'} | ForEach-Object { $a=($_.Actions|%{"$($_.Execute) $($_.Arguments)"}) -join '; '; if($a -match $evil){ Crit ("예약작업 의심: {0}" -f $_.TaskName) "powershell/temp/encoded 액션. schtasks /query /tn 로 확인" } }
if($script:AC -eq 0){ Ok "예약작업 의심 없음 (Microsoft 기본 제외)" }
$svc = Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} -MaxEvents 30 2>$null
$svcImgs = ($svc | ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data[1].'#text' } | Sort-Object -Unique)
($svcImgs | ? {$_ -match $evil}) | ForEach-Object { Med ("신규 서비스 임시경로(7045): {0}" -f $_) "HWiNFO·드라이버툴 등 정상도 TEMP 사용. 모르는 것만 의심" }
$wmiOk='SCM Event Log Filter','BVTFilter','RmAssistEventFilter','NTEventLogConsumer','SCM Event Log Consumer','TSLogonEvents','TSLogoffEvents'
$wmi = Get-WmiObject -Namespace root\Subscription -Class __EventFilter 2>$null | ? { $_.Name -notin $wmiOk }
if($wmi){ Crit ("비표준 WMI 영구 구독: {0}" -f ($wmi.Name -join ',')) "은밀 백도어 단골. Get-WmiObject root\Subscription 로 확인" } else { Ok "WMI 영구 구독은 윈도우 기본만" }
$wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 2>$null
if($wl){ if($wl.Shell -ne 'explorer.exe'){ Crit ("Winlogon Shell 변조: {0}" -f $wl.Shell) "로그인 시 악성 실행. explorer.exe로 복구 검토" } else { Ok "Winlogon Shell 정상" } }
$pp = netsh interface portproxy show all 2>$null | Select-String '\d'
if($pp){ Med ("netsh portproxy 포워딩 {0}개" -f $pp.Count) "WSL·SSH 포워딩이면 정상, 모르면 측면이동 의심" }
Mini

# ════════ 3. 네트워크·프로세스 ════════
Sec "3. 네트워크·프로세스"
Sub "외부 ESTABLISHED 연결 (C2 의심)"
$ext = Get-NetTCPConnection -State Established 2>$null | ? {$_.RemoteAddress -notmatch $priv}
if($ext){ $ext | Select -First 6 | ForEach-Object { $pr=(Get-Process -Id $_.OwningProcess 2>$null).Name; Note ("{0}:{1}  <- {2}" -f $_.RemoteAddress,$_.RemotePort,$pr) }; Med "외부 연결 존재" "프로세스가 내가 띄운 것인지 확인(브라우저·업데이트·클라우드 정상)" } else { Ok "외부 연결 없음" }
$proc = Get-Process | ? {$_.Path} | ForEach-Object { [pscustomobject]@{N=$_.Name;P=$_.Path;S=(Get-AuthenticodeSignature $_.Path 2>$null).Status} }
$hot = $proc | ? { $_.P -match '\\Temp\\|\\Downloads\\|\\Windows\\Temp\\' } | Sort-Object P -Unique
if($hot){ $hot | Select -First 5 | ForEach-Object { Crit ("Temp/Downloads 실행: {0}" -f $_.P) "임시경로 실행 = 악성 단골. 프로세스 정체 확인" } } else { Ok "Temp/Downloads 실행 프로세스 없음" }
$nosig = $proc | ? { $_.S -eq 'NotSigned' -and $_.P -notmatch '\\AppData\\|\\Program Files' } | Sort-Object P -Unique
if($nosig){ $nosig | Select -First 4 | ForEach-Object { Sus ("서명 없는 프로세스: {0}" -f $_.P) "개발도구면 정상, 모르면 출처 확인" } }
$hosts = Get-Content "$env:windir\System32\drivers\etc\hosts" 2>$null | ? {$_ -notmatch '^\s*#' -and $_.Trim() -ne ''}
if($hosts){ Med ("hosts 커스텀 항목 {0}줄" -f $hosts.Count) "DNS 하이재킹 가능. 내가 넣은 것만 정상" } else { Ok "hosts 파일 깨끗" }
Mini

# ════════ 4. 방어 무력화·로그 ════════
Sec "4. 방어 무력화·로그삭제"
$cl = Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 10 2>$null
if($cl){ Crit ("보안 로그 삭제(1102) {0}건" -f $cl.Count) "공격자 은폐 강력 신호. 시각 확인" } else { Ok "보안 로그 삭제 흔적 없음" }
$mp = Get-MpPreference 2>$null
if($mp){ if($mp.DisableRealtimeMonitoring){ Crit "Defender 실시간 보호 꺼짐" "공격자가 끈 것일 수 있음. 즉시 켜기" } else { Ok "Defender 실시간 보호 켜짐" }; $exc=$mp.ExclusionPath | ? {$_ -and $_ -notmatch 'Must be an administrator'}; if($exc){ Med ("Defender 제외 경로: {0}" -f ($exc -join ', ')) "모르는 경로면 악성 은닉 가능" } }
# AMSI 키워드 분할(AMSI 자가차단 방지)
$sig=@(('Mimi'+'katz'),('amsi'+'InitFailed'),('Amsi'+'ScanBuffer'),('Invoke-Shel'+'lcode'),('Virtual'+'Alloc')) -join '|'
$sig+='|-enc [A-Za-z0-9+/]{40}|FromBase64String\(.{0,40}(IEX|Invoke-Expression)'
$ps = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 500 2>$null | ? {$_.Message -match $sig}
if($ps){ Crit ("악성 PowerShell(4104) {0}건" -f $ps.Count) "인코딩 셸코드/자격증명 덤프 패턴. 스크립트블록 확인" } else { Ok "악성 PowerShell 강한 패턴 없음" }
$vss = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 1000 2>$null | ForEach-Object { $c=([xml]$_.ToXml()).Event.EventData.Data[8].'#text'; if($c -match 'vssadmin.*delete|wbadmin.*delete|wmic.*shadowcopy.*delete'){$c} } | Select -First 1
if($vss){ Crit ("Shadow Copy 삭제: {0}" -f $vss) "랜섬웨어 전조. 백업 상태 확인" } else { Ok "섀도카피 삭제 흔적 없음" }
Mini

# ════════ 5. 웹쉘·접근성 ════════
Sec "5. 웹쉘·접근성 백도어"
foreach($r in @('C:\inetpub\wwwroot','C:\inetpub')){ if(Test-Path $r){ $ws=Get-ChildItem $r -Include *.aspx,*.asp,*.ashx,*.php,*.jsp -Recurse 2>$null | Select-String -Pattern 'eval\(|Request\[|cmd\.exe|ProcessStartInfo|FromBase64' -List 2>$null; if($ws){ Crit ("웹쉘 의심: {0}" -f (($ws.Path|Select -First 2) -join ', ')) "원격 명령실행 백도어. 파일 격리" } else { Ok "$r 웹쉘 패턴 없음" } } }
foreach($a in @('sethc.exe','utilman.exe','osk.exe')){ $f="C:\Windows\System32\$a"; if(Test-Path $f){ if((Get-AuthenticodeSignature $f 2>$null).Status -ne 'Valid'){ Crit "$a 서명 비정상" "cmd.exe로 교체된 로그인화면 백도어 의심" }; $ifeo=Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$a" 2>$null; if($ifeo.Debugger){ Crit "$a IFEO Debugger: $($ifeo.Debugger)" "접근성 백도어" } } }
if($script:AC -eq 0){ Ok "웹쉘·접근성 백도어 없음" }
Mini

# ════════ 6. 심화(고급 ASEP) ════════ — 초보는 1~5만 봐도 됨
Sec "6. 심화 — 고급 백도어 (초보는 건너뛰어도 됨)"
# COR_PROFILER (.NET 인젝션)
$cp=@(); foreach($k in 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment','HKCU:\Environment'){ $e=Get-ItemProperty $k 2>$null; if($e.COR_PROFILER -or $e.CORECLR_PROFILER){ $cp+="$k : $($e.COR_PROFILER)$($e.CORECLR_PROFILER)" } }
if($cp){ Sus ("COR_PROFILER 환경변수 설정: {0}" -f ($cp -join '; ')) ".NET에 DLL 끼우는 통로. APM(NewRelic 등) 깔았으면 정상, 아니면 의심" } else { Ok "COR_PROFILER 인젝션 없음" }
# LSA 패키지 변조
$lsaOk='""','msv1_0','scecli','rassfm','kerberos','schannel','wdigest','tspkg','pku2u','cloudAP','negoexts','rsaenh','livessp','tsbypass','kdcsvc'
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 2>$null
$bad=@(); foreach($v in @('Authentication Packages','Notification Packages','Security Packages')){ foreach($p in $lsa.$v){ if($p -and ($p -replace '\.dll$','') -notin $lsaOk){ $bad+="$v=$p" } } }
if($bad){ Crit ("LSA 패키지 변조: {0}" -f ($bad -join ', ')) "System32에 짝 DLL 강제로드(자격증명 탈취). 알수없는 이름이면 의심" } else { Ok "LSA 인증 패키지 정상" }
# AMSI 레지스트리 우회
$amsi = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows Script\Settings' 2>$null
if($amsi.AmsiEnable -eq 0){ Crit "AmsiEnable=0 (AMSI 끔)" "스크립트 검사 비활성. 공격자가 끈 것" } else { Ok "AMSI 레지스트리 우회 없음" }
# COM 하이재킹 (HKCU CLSID, AppData/Temp 경로)
# 정상앱(Python Launcher·VSCode 등)도 AppData\Local\Programs에 COM 등록 → Temp/scrobj.dll(스크립틀릿)만 확정형
$com = Get-ChildItem 'HKCU:\Software\Classes\CLSID' 2>$null | ForEach-Object { $i=Get-ItemProperty "$($_.PSPath)\InprocServer32" 2>$null; if($i.'(default)' -match '\\Temp\\|\\AppData\\Local\\Temp\\|scrobj\.dll|\\Downloads\\'){ $i.'(default)' } } | Select -First 3
if($com){ Crit ("COM 하이재킹 의심: {0}" -f ($com -join '; ')) "시스템 COM을 임시경로/스크립틀릿으로 덮어씀. 거의 악성" } else { Ok "COM 하이재킹 흔적 없음" }
# BYOVD (악성/취약 커널 드라이버)
$drv = Get-CimInstance Win32_SystemDriver 2>$null | ? {$_.State -eq 'Running' -and $_.PathName -match 'Temp|Downloads|AppData|Users'}
if($drv){ $drv | Select -First 3 | ForEach-Object { Crit ("비표준 경로 커널 드라이버: {0}" -f $_.PathName) "BYOVD(취약/악성 드라이버) 의심. 서명·벤더 확인" } } else { Ok "비표준 경로 커널 드라이버 없음" }
Mini

# ════════ 결과 ════════
Say ""; Say "════════════════════════════════════════════"
if($script:CRIT -gt 0){ $light="[위험 RISK]"; $verdict="침해 의심 강함 — 아래 '먼저 볼 것'부터 확인하세요" }
elseif(($script:SUS+$script:MED) -gt 0){ $light="[주의 WARN]"; $verdict="확정 신호는 없으나 확인할 항목이 있습니다" }
else { $light="[안전 SAFE]"; $verdict="1차 스크리닝상 뚜렷한 침해 신호 없음 (정교한 공격은 흔적을 지웁니다)" }
Say (" 판정:  {0}    [확정형] {1}건 · [확인필요] {2}건 · [주의] {3}건" -f $light,$script:CRIT,$script:SUS,$script:MED)
Say " $verdict"
if($script:CRIT -gt 0){
  Say ""; Say " ▼ 먼저 볼 것 (확정형 침해신호 TOP3)"
  $i=0; foreach($f in $script:FIND){ $i++; if($i -gt 3){break}; Say ("  {0}) {1}" -f $i,$f[0]); Say ("     → {1}" -f $i,$f[1]) }
  Say ""; Say " 털린 게 확실하면 → (1)네트워크 격리 (2)스냅샷 (3)비번·토큰 회수 (4)복구"
  Say " 대응 영상: youtube.com/shorts/PzLP5GkN_8E"
}
if(-not $IsAdmin){ Say " [!] 일반 권한 실행 — Security 항목 일부 미확인. 관리자로 다시 권장." }
Say " 이건 '기초' 점검입니다. 본격 포렌식(MFT·USN·Prefetch)은 전용도구(KAPE 등) 영역."
$rep = "$env:USERPROFILE\breach-check_$($env:COMPUTERNAME)_$(Get-Date -Format yyyyMMdd-HHmmss).txt"
try { $script:LOG | Out-File -FilePath $rep -Encoding UTF8; Say " [리포트 저장] $rep" } catch {}
Say " 코드를 다 읽으셨나요? 그게 보안의 시작입니다. — @보안하는개발자"
