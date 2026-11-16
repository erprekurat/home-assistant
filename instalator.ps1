# Instalator monitoringu: go2rtc + apka Kamery + Tailscale
# Uruchamiaj przez ZAINSTALUJ.bat (sam poprosi o uprawnienia administratora)
$ErrorActionPreference = 'Stop'
$src = $PSScriptRoot
$dst = $src   # dziala z folderu, w ktorym lezy instalator (Dropbox)
$exe = Join-Path $dst 'go2rtc.exe'
$pxe = Join-Path $dst 'kamery-proxy.exe'
$cfgFile = Join-Path $dst 'go2rtc.yaml'
$url = 'http://localhost:1984/dom.html'
function Step($t) { Write-Host "`n== $t" -ForegroundColor Cyan }

try {
  Step 'Zatrzymuje stara wersje (jesli jest)'
  foreach ($t in 'go2rtc', 'kamery-proxy', 'klima') { Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue }
  Get-Process go2rtc, kamery-proxy, klima -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep 2
  # nowa wersja kamery-proxy (podmieniana dopiero po zatrzymaniu starej)
  $pxNew = Join-Path $dst 'kamery-proxy.new.exe'
  if (Test-Path $pxNew) { Move-Item -Force $pxNew $pxe }
  # nowa wersja uslugi klima (klimatyzator + nastawy pompy Ariston)
  $kNew = Join-Path $dst 'klima.new.exe'
  if (Test-Path $kNew) { Move-Item -Force $kNew (Join-Path $dst 'klima.exe') }

  Step "Folder: $dst"
  # pliki musza byc fizycznie na dysku (nie 'tylko online' w Dropboxie)
  Get-ChildItem $dst -Recurse -File | ForEach-Object { $null = [IO.File]::ReadAllBytes($_.FullName).Length }
  cmd /c "attrib +P `"$dst\*`" /S /D >nul 2>&1"
  if (-not (Test-Path $exe)) { throw "Brak $exe" }

  Step 'Konfiguracja: go2rtc lokalnie na 1985, apka przez kamery-proxy na 1984'
  $y = [IO.File]::ReadAllText($cfgFile)
  $y2 = $y -replace 'listen:\s*"?:1984"?', 'listen: "127.0.0.1:1985"'
  if ($y2 -ne $y) { [IO.File]::WriteAllText($cfgFile, $y2) }

  Step 'Autostart go2rtc i kamery-proxy (przy starcie Windows, bez logowania, auto-restart)'
  $a = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $dst
  $t = New-ScheduledTaskTrigger -AtStartup
  $t.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)).Repetition
  $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $s = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
       -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -MultipleInstances IgnoreNew `
       -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskName 'go2rtc' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
  $a2 = New-ScheduledTaskAction -Execute $pxe -Argument '-listen :1984 -config go2rtc.yaml' -WorkingDirectory $dst
  Register-ScheduledTask -TaskName 'kamery-proxy' -Action $a2 -Trigger $t -Principal $p -Settings $s -Force | Out-Null
  Start-ScheduledTask -TaskName 'go2rtc'
  Start-ScheduledTask -TaskName 'kamery-proxy'
  # klimatyzator (Tuya, lokalnie) - osobna usluga na 1986, konfiguracja w klima.json
  $kxe = Join-Path $dst 'klima.exe'
  if (Test-Path $kxe) {
    $a3 = New-ScheduledTaskAction -Execute $kxe -Argument '-listen :1986 -config klima.json' -WorkingDirectory $dst
    Register-ScheduledTask -TaskName 'klima' -Action $a3 -Trigger $t -Principal $p -Settings $s -Force | Out-Null
    Start-ScheduledTask -TaskName 'klima'
    Get-NetFirewallRule -DisplayName 'klima' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName 'klima' -Direction Inbound -Program $kxe -Action Allow -Profile Any -RemoteAddress LocalSubnet | Out-Null
  }

  Step 'Zapora Windows'
  Get-NetFirewallRule -DisplayName 'go2rtc' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  New-NetFirewallRule -DisplayName 'go2rtc' -Direction Inbound -Program $exe -Action Allow -Profile Any | Out-Null
  Get-NetFirewallRule -DisplayName 'kamery-proxy' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  New-NetFirewallRule -DisplayName 'kamery-proxy' -Direction Inbound -Program $pxe -Action Allow -Profile Any | Out-Null

  Step 'Wylaczam usypianie komputera (na zasilaniu)'
  cmd /c "powercfg /change standby-timeout-ac 0 & powercfg /change hibernate-timeout-ac 0"

  Step 'Sprawdzam czy go2rtc dziala'
  $ok = $false
  foreach ($i in 1..20) {
    try { Invoke-WebRequest 'http://localhost:1984/api/streams' -UseBasicParsing -TimeoutSec 2 | Out-Null; $ok = $true; break } catch { Start-Sleep 1 }
  }
  if ($ok) { Write-Host 'go2rtc dziala' -ForegroundColor Green } else { Write-Host "go2rtc nie odpowiada - sprawdz go2rtc.yaml w $dst" -ForegroundColor Red }

  Step 'Folder z nagraniami i przycisk Folder w apce'
  $media = if (Test-Path 'D:\') { 'D:\Frigate' } else { 'C:\Frigate' }
  New-Item -ItemType Directory -Force (Join-Path $media 'recordings') | Out-Null
  $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\Classes\kamery-folder')
  $k.SetValue('', 'URL:Kamery folder'); $k.SetValue('URL Protocol', '')
  $k.CreateSubKey('shell\open\command').SetValue('', "explorer.exe `"$(Join-Path $media 'recordings')`"")
  Write-Host "Nagrania: $media\recordings"

  Step 'Frigate (rozpoznawanie obiektow, klipy zdarzen)'
  $ErrorActionPreference = 'Continue'   # docker/tailscale pisza komunikaty na stderr
  foreach ($d in @("$env:ProgramFiles\Docker\Docker\resources\bin", "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin")) {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue) -and (Test-Path "$d\docker.exe")) { $env:Path += ";$d" }
  }
  if (Get-Command docker -ErrorAction SilentlyContinue) {
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
      foreach ($dd in @("$env:ProgramFiles\Docker\Docker\Docker Desktop.exe", "$env:LOCALAPPDATA\Programs\DockerDesktop\Docker Desktop.exe")) {
        if (Test-Path $dd) { Start-Process $dd; break }
      }
      Write-Host 'Czekam, az Docker wystartuje...'
      foreach ($i in 1..60) { Start-Sleep 3; docker info *> $null; if ($LASTEXITCODE -eq 0) { break } }
    }
    $env:FRIGATE_MEDIA = $media.Replace('\', '/')
    Write-Host 'Pobieram/uruchamiam Frigate (pierwszy raz kilka GB, moze potrwac)...'
    docker compose -f (Join-Path $dst 'frigate\docker-compose.yml') up -d
    if ($LASTEXITCODE -eq 0) { Write-Host "Frigate dziala: http://localhost:5000  (klipy: $media)" -ForegroundColor Green }
    else { Write-Host 'Frigate nie wystartowal - sprawdz, czy Docker Desktop dziala' -ForegroundColor Red }
  } else {
    Write-Host 'Brak Dockera - pomijam Frigate (zainstaluj Docker Desktop i uruchom instalator ponownie)' -ForegroundColor Yellow
  }

  Step 'Tailscale (dostep spoza domu)'
  $ans = Read-Host 'Wlaczyc dostep spoza domu przez Tailscale? (t/N)'
  if ($ans -match '^[tTyY]') {
  $ts = 'C:\Program Files\Tailscale\tailscale.exe'
  if (-not (Test-Path $ts)) {
    $done = $false
    if (Get-Command winget -ErrorAction SilentlyContinue) {
      cmd /c "winget install --id Tailscale.Tailscale -e --silent --accept-package-agreements --accept-source-agreements"
      $done = Test-Path $ts
    }
    if (-not $done) {
      $msi = Join-Path $env:TEMP 'tailscale.msi'
      Invoke-WebRequest 'https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi' -OutFile $msi -UseBasicParsing
      Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /quiet /norestart" -Wait
    }
    Start-Sleep 5
  }
  & $ts status *> $null
  if ($LASTEXITCODE -ne 0) {
    Write-Host 'Zaloguj sie do Tailscale tym samym kontem co na iPhonie (otworzy sie link):' -ForegroundColor Yellow
    & $ts up
  }
  Write-Host 'Wlaczam HTTPS (jesli pokaze link - otworz go i zatwierdz, potem wroc tutaj):' -ForegroundColor Yellow
  & $ts serve --bg http://localhost:1984
  if (Test-Path (Join-Path $dst 'klima.exe')) { & $ts serve --bg --set-path /klima http://localhost:1986 }
  & $ts serve status
  } else { Write-Host 'Pomijam Tailscale.' }

  Step 'Gotowe'
  Write-Host "Apka na tym PC: $url" -ForegroundColor Green
  Write-Host 'W Chrome kliknij ikone "Zainstaluj" w pasku adresu, potem przypnij do paska zadan.'
  Write-Host 'Na iPhonie: adres https://...ts.net z linii wyzej + /dom.html'
  Start-Process explorer.exe $url
}
catch {
  Write-Host "`nBLAD: $($_.Exception.Message)" -ForegroundColor Red
}
Read-Host "`nEnter zamyka okno"
