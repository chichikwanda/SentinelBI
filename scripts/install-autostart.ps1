<#
.SYNOPSIS
  Brings the SentinelBI stack up by itself whenever you sign in to Windows.

.DESCRIPTION
  The containers already restart with Docker (restart: unless-stopped). This adds the missing
  piece: a scheduled task that, at sign-in, waits for Docker Desktop (starting it if needed) and
  runs `docker compose up -d`, so nobody has to open a terminal. Run once, from the project folder:

    powershell -ExecutionPolicy Bypass -File scripts\install-autostart.ps1

  Remove with:  scripts\install-autostart.ps1 -Remove

  Also tick Docker Desktop > Settings > General > "Start Docker Desktop when you sign in".
#>
[CmdletBinding()]
param(
  [string]$ProjectDir = (Split-Path -Parent $PSScriptRoot),
  [switch]$Remove
)

$ErrorActionPreference = "Stop"
$TaskName = "SentinelBI stack"

if ($Remove) {
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  }
  Write-Host "Removed the '$TaskName' task."
  return
}

if (-not (Test-Path (Join-Path $ProjectDir "docker-compose.yml"))) { throw "No docker-compose.yml in $ProjectDir" }

$logDir = Join-Path $env:LOCALAPPDATA "SentinelBI"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$runner = Join-Path $logDir "start-stack.ps1"
Set-Content -Path $runner -Encoding UTF8 -Value @"
`$log = Join-Path '$logDir' 'stack.log'
function Say(`$m) { "`$(Get-Date -Format s) `$m" | Add-Content `$log }
if ((Test-Path `$log) -and (Get-Item `$log).Length -gt 1MB) { Move-Item -Force `$log "`$log.old" }
`$exe = Join-Path `$env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
for (`$i = 0; `$i -lt 60; `$i++) {                      # up to about 10 minutes
  docker info *> `$null
  if (`$LASTEXITCODE -eq 0) { break }
  if (`$i -eq 0 -and (Test-Path `$exe) -and -not (Get-Process 'Docker Desktop' -ErrorAction SilentlyContinue)) {
    Say 'starting Docker Desktop'; Start-Process `$exe
  }
  Start-Sleep -Seconds 10
}
if (`$LASTEXITCODE -ne 0) { Say 'Docker did not come up; giving up'; exit 1 }
Set-Location '$ProjectDir'
Say 'docker compose up -d'
docker compose up -d --wait *>> `$log
Say "done (exit `$LASTEXITCODE)"
exit `$LASTEXITCODE
"@

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$runner`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
  -Description "Starts the SentinelBI Docker stack at sign-in" | Out-Null

Write-Host "Installed. The stack now starts when you sign in. Log: $logDir\stack.log"
Write-Host "Start it right now: Start-ScheduledTask -TaskName '$TaskName'"
