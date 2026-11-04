<#
.SYNOPSIS
  Runs the SentinelBI sensor in the background on Windows, starting at boot, with no terminal.

.DESCRIPTION
  Run once, in an ADMINISTRATOR PowerShell, on the machine to watch. It copies the sensor to
  C:\ProgramData\SentinelBI, stores the server address and API key in a file only SYSTEM and
  Administrators can read, and registers a scheduled task that starts the sensor when Windows
  starts and restarts it if it stops. Nothing is left running in your terminal.

  Python must be installed for ALL users (python.org installer, "Install for all users"): the
  background task runs as SYSTEM and cannot use a Python that lives inside your user profile.
  Install Npcap first (https://npcap.com) if you want IPv6 traffic as well.

.EXAMPLE
  .\install-service.ps1 -ApiUrl http://192.168.1.10:8000 -ApiKey sbi_... -Ip 192.168.1.20

.EXAMPLE
  .\install-service.ps1 -Remove
#>
[CmdletBinding()]
param(
  [string]$ApiUrl,
  [string]$ApiKey,
  # address or network to watch (passed to the sensor as --ip); leave out to report everything seen
  [string]$Ip,
  # the sensor script to install; defaults to the one next to this file
  [string]$SensorPath = (Join-Path $PSScriptRoot "sentinelbi_sensor.py"),
  [string]$PythonPath,
  # also block quarantined addresses in this machine's firewall (the sensor's --enforce)
  [switch]$Enforce,
  [switch]$Remove
)

$ErrorActionPreference = "Stop"
$TaskName = "SentinelBI sensor"
$Dir = Join-Path $env:ProgramData "SentinelBI"

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Run this in an ADMINISTRATOR PowerShell (right-click PowerShell, Run as administrator)." }

if ($Remove) {
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  }
  Get-CimInstance Win32_Process -Filter "Name like 'python%'" |
    Where-Object { $_.CommandLine -like "*$Dir*sentinelbi_sensor.py*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
  Write-Host "Removed the '$TaskName' task. Files in $Dir were kept (they hold the log); delete the folder to remove them."
  return
}

if (-not $ApiUrl -or -not $ApiKey) { throw "-ApiUrl and -ApiKey are required (the wizard fills them in)." }
if ($ApiUrl -notmatch '^https?://') { throw "-ApiUrl must start with http:// or https://" }
if (-not (Test-Path $SensorPath)) { throw "Cannot find the sensor script at $SensorPath. Download it first, or pass -SensorPath." }

if (-not $PythonPath) {
  $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
  if (-not $cmd) { throw "Python was not found. Install Python 3.9+ for all users from https://www.python.org/downloads/ and run this again." }
  $PythonPath = $cmd.Source
}
if ($PythonPath -like "$env:SystemDrive\Users\*" -or $PythonPath -like "*\WindowsApps\*") {
  throw "Python at $PythonPath lives in a user profile, which the background task (running as SYSTEM) cannot use. Install Python for ALL users (python.org installer, 'Install for all users'), or pass -PythonPath."
}

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item -Force $SensorPath (Join-Path $Dir "sentinelbi_sensor.py")

# Settings in one file that only SYSTEM and Administrators can read: the API key is not left on the command line.
$conf = Join-Path $Dir "sensor.conf.ps1"
$extra = @()
if ($Ip) { $extra += "'--ip'", ("'" + $Ip.Replace("'", "''") + "'") }
if ($Enforce) { $extra += "'--enforce'" }
$lines = @(
  "`$env:SENTINELBI_API_URL = '$($ApiUrl.Replace("'", "''"))'",
  "`$env:SENTINELBI_API_KEY = '$($ApiKey.Replace("'", "''"))'",
  "`$SensorArgs = @($($extra -join ', '))"
)
Set-Content -Path $conf -Value $lines -Encoding UTF8
icacls $conf /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)" | Out-Null

# The wrapper the task runs: load settings, keep a size-limited log, run the sensor.
$wrapper = Join-Path $Dir "run-sensor.ps1"
Set-Content -Path $wrapper -Encoding UTF8 -Value @"
`$ErrorActionPreference = 'Continue'
Set-Location '$Dir'
. '$conf'
`$log = Join-Path '$Dir' 'sensor.log'
if ((Test-Path `$log) -and (Get-Item `$log).Length -gt 5MB) { Move-Item -Force `$log "`$log.old" }
& '$PythonPath' (Join-Path '$Dir' 'sentinelbi_sensor.py') --api-url `$env:SENTINELBI_API_URL --api-key `$env:SENTINELBI_API_KEY @SensorArgs 2>&1 | ForEach-Object { "`$_" } | Out-File -FilePath `$log -Append -Encoding utf8
exit `$LASTEXITCODE
"@

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$wrapper`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) `
  -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
  -Settings $settings -Description "SentinelBI sensor: reports packet headers and devices to $ApiUrl" | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "Installed. The sensor now runs in the background and starts with Windows."
Write-Host "  Log:     $Dir\sensor.log"
Write-Host "  Status:  Get-ScheduledTask -TaskName '$TaskName' | Get-ScheduledTaskInfo"
Write-Host "  Remove:  .\install-service.ps1 -Remove"
