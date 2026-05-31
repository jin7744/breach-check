<#
============================================================
  check_breach.ps1  —  내 윈도우 '털렸는지' 자가점검 (IR 수준)
  보안하는 개발자 (youtube @보안하는개발자)

  이 스크립트는 "읽기"만 합니다. 무엇도 바꾸거나 지우지 않습니다.
  믿지 말고 코드를 먼저 읽어보세요 — 그게 보안의 시작입니다.

  사용법 (PowerShell 관리자 권한 권장):
    1) 관리자 PowerShell 열기
    2) Set-ExecutionPolicy -Scope Process Bypass     (이 창에서만 허용)
    3) .\check_breach.ps1

  탐지 5영역: 계정·인증 / 지속성(ASEP) / 네트워크·프로세스 / 방어무력화·로그 / 웹쉘·접근성백도어
  결과는 '확정'이 아니라 '의심 후보'입니다. 각 항목 설명(오탐 여부)을 읽고 사람이 판단하세요.

  ※ 이건 '기초 자가점검'입니다 (기초 중의 기초). 현재 상태를 빠르게 훑는 1차 스크리닝.
     본격 디지털 포렌식 — $MFT 타임라인, USN 저널, Prefetch/Amcache 실행흔적, SRUM, 메모리 분석 —
     은 범위 밖이며 전용 도구(KAPE · MFTECmd · Plaso · Volatility) 영역입니다.
     포렌식 심화 버전(check_forensic)은 요청 시 별도 제공합니다.
  ※ 관리자 권한으로 실행해야 Security 이벤트로그(로그온·신규계정·로그삭제)까지 봅니다.
     일반 권한이면 그 항목들은 '권한 없어 미확인'이며, 빈 결과를 '안전'으로 오해하면 안 됩니다.
============================================================
#>
$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}  # 한글 출력·리다이렉트 깨짐 방지
$script:HIGH = 0; $script:MED = 0
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

function Sec($t){ Write-Host "`n━━ $t ━━" -ForegroundColor Magenta }
function Sub($t){ Write-Host "· $t" -ForegroundColor Cyan }
function Ok($t){ Write-Host "   [OK]  $t" -ForegroundColor Green }
function Hi($t){ Write-Host "   [HIGH] $t" -ForegroundColor Red; $script:HIGH++ }
function Med($t){ Write-Host "   [MED]  $t" -ForegroundColor Yellow; $script:MED++ }
function Note($t){ Write-Host "     $t" -ForegroundColor DarkGray }
$priv = '^127\.|^::1|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^169\.254\.|^fe80|^0\.0\.0\.0'

Write-Host "== check_breach.ps1 · 침해 자가점검 (IR) ==" -ForegroundColor White
Write-Host ("호스트 {0} · {1} · {2}" -f $env:COMPUTERNAME, $(if($IsAdmin){'관리자'}else{'일반(관리자 권한 권장 — 보안로그 접근)'}), (Get-Date -Format 'yyyy-MM-dd HH:mm'))
if(-not $IsAdmin){ Note "관리자가 아니면 Security 이벤트로그·일부 항목이 비어 보일 수 있습니다(거짓 음성)." }
Note "참고: 4688(명령줄) 체크는 'Audit Process Creation' + 'Include command line' GPO가 켜져 있어야 채워집니다."

# ════════ 1. 계정·인증 ════════
Sec "1. 계정·인증"
Sub "로컬 Administrators 멤버 (모르는 계정 끼었나)"
Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { Note ("{0}  ({1})" -f $_.Name, $_.PrincipalSource) }
$newAcct = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} -MaxEvents 50 2>$null
if($newAcct){ Hi ("최근 생성된 계정 이벤트(4720) {0}건 — 내가 만든 계정인지 확인" -f $newAcct.Count); $newAcct | Select-Object -First 3 | ForEach-Object { Note $_.TimeCreated } } else { Ok "최근 신규계정 이벤트 없음" }
$priv2 = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4732,4728,4756} -MaxEvents 50 2>$null
if($priv2){ Med ("특권그룹 추가 이벤트(4732/4728/4756) {0}건" -f $priv2.Count) }
$fails = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 500 2>$null
if($fails){ $cnt=$fails.Count; if($cnt -ge 50){ Hi ("로그온 실패(4625) {0}건 — 무차별 대입 흔적. 성공(4624) 시각·계정 교차확인" -f $cnt) } else { Note ("로그온 실패 {0}건 (인터넷 노출 시 봇 스캔으로 정상 다수)" -f $cnt) } }
Sub "RDP 원격 로그인 기록 (낯선 IP·시간)"
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';Id=21,25} -MaxEvents 8 2>$null | ForEach-Object { Note ("{0}  {1}" -f $_.TimeCreated, ($_.Message -split "`n")[0]) }

# ════════ 2. 지속성 (ASEP) ════════
Sec "2. 지속성(자동시작) 백도어"
$evil = 'powershell|cmd /c|-enc|-e |frombase64|downloadstring|iwr |curl |certutil|mshta|wscript|cscript|\.tmp|\\temp\\|appdata|/dev/tcp|bitsadmin|regsvr32'
Sub "레지스트리 Run/RunOnce 자동시작"
$runKeys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
foreach($k in $runKeys){ $p=Get-ItemProperty $k 2>$null; if($p){ $p.PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'} | ForEach-Object { if($_.Value -match $evil){ Hi ("Run키 의심: {0} = {1}" -f $_.Name, $_.Value) } else { Note ("{0} = {1}" -f $_.Name, $_.Value) } } } }
Sub "예약 작업 — 의심 액션(powershell/temp/encoded)"
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | ForEach-Object { $a=($_.Actions | ForEach-Object {"$($_.Execute) $($_.Arguments)"}) -join '; '; if($a -match $evil -and $_.TaskPath -notmatch '\\Microsoft\\'){ Hi ("예약작업 의심: {0} -> {1}" -f $_.TaskName, $a.Substring(0,[Math]::Min(120,$a.Length))) } }
Ok "예약작업 스캔 완료 (Microsoft 기본 작업 제외)"
$svc = Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} -MaxEvents 30 2>$null
$svcImgs = $svc | ForEach-Object { $x=[xml]$_.ToXml(); $x.Event.EventData.Data[1].'#text' } | Sort-Object -Unique
$badSvc = $svcImgs | Where-Object { $_ -match $evil }
if($badSvc){ $badSvc | ForEach-Object { Med ("신규 서비스 임시/의심 경로(7045): {0} — HWiNFO·드라이버설치툴 등 정상도 TEMP 사용, 모르는 것만 의심" -f $_) } } else { Ok "신규 서비스 의심 경로 없음" }
Sub "WMI 영구 이벤트 구독 (은밀 백도어 단골)"
$wmiOk = 'SCM Event Log Filter','BVTFilter','RmAssistEventFilter','NTEventLogConsumer','SCM Event Log Consumer','TSLogonEvents','TSLogoffEvents'
$wmi = Get-WmiObject -Namespace root\Subscription -Class __EventFilter 2>$null | Where-Object { $_.Name -notin $wmiOk }
if($wmi){ Hi ("비표준 WMI 영구 구독 — 백도어 의심: {0}" -f ($wmi.Name -join ',')) } else { Ok "WMI 영구 구독은 윈도우 기본만(정상)" }
Sub "Winlogon Shell/Userinit 하이재킹"
$wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 2>$null
if($wl){ if($wl.Shell -ne 'explorer.exe'){ Hi ("Winlogon Shell 변조: $($wl.Shell)") } else { Ok "Winlogon Shell 정상(explorer.exe)" }; if($wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$'){ Hi ("Winlogon Userinit 변조: $($wl.Userinit)") } }
$startup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
foreach($s in $startup){ $f=Get-ChildItem $s -File 2>$null | Where-Object {$_.Name -ne 'desktop.ini'}; if($f){ Med ("시작 폴더 자동실행 파일: {0}" -f ($f.Name -join ', ')) } }
$pp = netsh interface portproxy show all 2>$null | Select-String '\d'
if($pp){ Med ("netsh portproxy 포워딩 설정 존재 ({0}개) — WSL·SSH 포트포워딩이면 정상, 모르는 것이면 측면이동 의심" -f $pp.Count) }

# ════════ 3. 네트워크·프로세스 ════════
Sec "3. 네트워크·프로세스"
Sub "외부 ESTABLISHED 연결 (C2 의심)"
$ext = Get-NetTCPConnection -State Established 2>$null | Where-Object {$_.RemoteAddress -notmatch $priv}
if($ext){ $ext | Select-Object -First 8 | ForEach-Object { $pr=(Get-Process -Id $_.OwningProcess 2>$null).Name; Note ("{0}:{1}  <- {2}" -f $_.RemoteAddress, $_.RemotePort, $pr) }; Med "외부 연결 존재 — 프로세스가 내가 띄운 것인지 확인(브라우저·업데이트·클라우드는 정상)" } else { Ok "외부 연결 없음" }
Sub "서명 없는 / 임시경로 실행 프로세스"
# 서명 안 된 프로세스 중 진짜 임시경로(Temp/Downloads)만 HIGH. AppData는 정상 앱(전자앱·node·winget) 다수라 제외
$proc = Get-Process | Where-Object {$_.Path} | ForEach-Object { $sig=(Get-AuthenticodeSignature $_.Path 2>$null).Status; [pscustomobject]@{N=$_.Name;P=$_.Path;S=$sig} }
$hot = $proc | Where-Object { $_.P -match '\\Temp\\|\\Downloads\\|\\Windows\\Temp\\' } | Sort-Object P -Unique
if($hot){ $hot | Select-Object -First 6 | ForEach-Object { Hi ("Temp/Downloads에서 실행 중: {0} ({1}, 서명 {2})" -f $_.N,$_.P,$_.S) } } else { Ok "Temp/Downloads 실행 프로세스 없음" }
$nosig = $proc | Where-Object { $_.S -eq 'NotSigned' -and $_.P -notmatch '\\AppData\\|\\Program Files' } | Sort-Object P -Unique
if($nosig){ $nosig | Select-Object -First 5 | ForEach-Object { Med ("서명 없는 프로세스: {0} — 출처 확인" -f $_.P) } }
$hosts = Get-Content "$env:windir\System32\drivers\etc\hosts" 2>$null | Where-Object {$_ -notmatch '^\s*#' -and $_.Trim() -ne ''}
if($hosts){ Med ("hosts 파일 커스텀 항목 {0}줄 — 내가 넣은 것만 정상: {1}" -f $hosts.Count, ($hosts | Select-Object -First 1)) } else { Ok "hosts 파일 깨끗" }
$bits = Get-BitsTransfer -AllUsers 2>$null | Where-Object {$_.JobState -ne 'Transferred'}
if($bits){ Med ("진행 중 BITS 다운로드 작업(지속화 악용 가능): {0}" -f ($bits.DisplayName -join ',')) }

# ════════ 4. 방어 무력화·로그삭제 ════════
Sec "4. 방어 무력화·로그삭제"
$cleared = Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 10 2>$null
if($cleared){ Hi ("보안 로그 삭제 이벤트(1102) {0}건 — 공격자 은폐 강력 신호" -f $cleared.Count); $cleared | Select-Object -First 2 | ForEach-Object { Note $_.TimeCreated } } else { Ok "보안 로그 삭제 흔적 없음" }
$mp = Get-MpPreference 2>$null
if($mp){ if($mp.DisableRealtimeMonitoring){ Hi "Defender 실시간 보호 꺼짐 — 공격자가 끈 것일 수 있음" } else { Ok "Defender 실시간 보호 켜짐" }; $exc=$mp.ExclusionPath | Where-Object {$_ -and $_ -notmatch 'Must be an administrator'}; if($exc){ Med ("Defender 검사 제외 경로: {0} — 모르는 경로면 의심" -f ($exc -join ', ')) } elseif(-not $IsAdmin){ Note "Defender 제외경로는 관리자 권한 필요 — 건너뜀" } }
$threat = Get-MpThreatDetection 2>$null | Select-Object -First 3
if($threat){ Med ("Defender 위협 탐지 이력 있음: {0}" -f ($threat.Resources -join ',')) }
# 강한 지표만. ※ 악성 키워드를 통문자로 쓰면 AMSI가 이 스크립트 자체를 차단하므로 분할 조립
$sig = @(('Mimi'+'katz'),('amsi'+'InitFailed'),('Amsi'+'ScanBuffer'),('Invoke-Shel'+'lcode'),('Get-Key'+'strokes'),('Virtual'+'Alloc')) -join '|'
$sig += '|-enc [A-Za-z0-9+/]{40}|FromBase64String\(.{0,40}(IEX|Invoke-Expression)|DownloadString\(.{0,40}(IEX|\| ?iex)'
$ps4104 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 500 2>$null | Where-Object {$_.Message -match $sig}
if($ps4104){ Hi ("악성 PowerShell 스크립트블록(4104) {0}건 — 인코딩 셸코드/자격증명 덤프/AMSI 우회 패턴" -f $ps4104.Count) } else { Ok "악성 PowerShell 강한 패턴 없음" }
$vss = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 1000 2>$null | ForEach-Object { $x=[xml]$_.ToXml(); $cl=$x.Event.EventData.Data[8].'#text'; if($cl -match 'vssadmin.*delete|wbadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled'){ $cl } } | Select-Object -First 1
if($vss){ Hi ("Shadow Copy/백업 삭제 명령(랜섬웨어 전조): {0}" -f $vss) } else { Ok "섀도카피 삭제 흔적 없음" }
$lsass = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 1000 2>$null | ForEach-Object { $x=[xml]$_.ToXml(); $cl=$x.Event.EventData.Data[8].'#text'; if($cl -match 'lsass.*\.dmp|procdump.*lsass|comsvcs.*MiniDump|rundll32.*comsvcs'){ $cl } } | Select-Object -First 1
if($lsass){ Hi ("LSASS 자격증명 덤프 흔적: {0}" -f $lsass) }
$audit = auditpol /get /category:* 2>$null | Select-String 'No Auditing'
if($audit){ Med ("감사정책 일부 'No Auditing' — 로그가 안 남는 영역 존재 ({0}개)" -f $audit.Count) }

# ════════ 5. 웹쉘·접근성 백도어 ════════
Sec "5. 웹쉘·접근성(sticky keys) 백도어"
$webroots = 'C:\inetpub\wwwroot','C:\inetpub'
foreach($r in $webroots){ if(Test-Path $r){ $ws=Get-ChildItem $r -Include *.aspx,*.asp,*.ashx,*.php,*.jsp -Recurse 2>$null | Select-String -Pattern 'eval\(|Request\[|cmd\.exe|ProcessStartInfo|Server\.CreateObject|FromBase64' -List 2>$null; if($ws){ Hi ("웹쉘 의심 파일: {0}" -f (($ws.Path | Select-Object -First 3) -join ', ')) } else { Ok "$r 웹쉘 패턴 없음" } } }
Sub "접근성 기능 하이재킹 (로그인 화면 백도어)"
$acc = 'sethc.exe','utilman.exe','osk.exe','Magnify.exe'
foreach($a in $acc){ $f="C:\Windows\System32\$a"; if(Test-Path $f){ $sig=(Get-AuthenticodeSignature $f 2>$null).Status; $ifeo=Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$a" 2>$null; if($sig -ne 'Valid'){ Hi ("$a 서명 비정상($sig) — cmd.exe로 교체된 백도어 의심") }; if($ifeo.Debugger){ Hi ("$a IFEO Debugger 설정됨: $($ifeo.Debugger) — 접근성 백도어") } } }
Ok "접근성 백도어 점검 완료"

# ════════ 결과 ════════
Write-Host "`n════════════════════════════════════════════" -ForegroundColor White
if(($script:HIGH + $script:MED) -eq 0){
  Write-Host "[OK] 뚜렷한 침해 신호 없음. 정교한 공격은 흔적을 지웁니다 — 정기 점검 권장." -ForegroundColor Green
}else{
  Write-Host ("[!] HIGH {0}건  MED {1}건 — 위 항목을 확인하세요." -f $script:HIGH, $script:MED) -ForegroundColor Yellow
  Write-Host "    각 항목 설명(오탐 여부)을 먼저 읽고 모르는 것만 파고드세요." -ForegroundColor Yellow
  Write-Host "    털린 게 확실하면 → 대응: (1)네트워크 격리 (2)스냅샷 (3)비번·토큰 회수 (4)복구"
  Write-Host "    대응 영상: youtube.com/shorts/PzLP5GkN_8E"
}
Write-Host "코드를 다 읽으셨나요? 그게 보안의 시작입니다. — @보안하는개발자" -ForegroundColor Cyan
