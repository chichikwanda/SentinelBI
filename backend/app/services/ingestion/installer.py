# ruff: noqa: E501 - the embedded PowerShell has long literal lines
"""The one-file Windows installer a person downloads from the app and double-clicks.

It is a batch file with a PowerShell script appended. The batch part asks Windows for administrator
rights (the usual "Do you want to allow this app" prompt) and hands the rest to PowerShell. That
script downloads the sensor from this server, checks its SHA-256 against the value baked in here,
makes sure a system-wide Python exists (installing it with winget when it does not), and registers
the sensor to start with Windows. The API key is inside the file: treat the file like a password.
"""

from __future__ import annotations

import re

# The batch part finds the script with LastIndexOf: the marker also appears in the batch's own
# command line, and only the last one starts the script.
MARKER = "#PS-BEGIN"

_BATCH = """@echo off
setlocal
title SentinelBI sensor setup
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Asking Windows for permission to install the sensor...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$t = [IO.File]::ReadAllText('%~f0'); Invoke-Expression $t.Substring($t.LastIndexOf('#PS-BEGIN') + 9)"
echo.
pause
exit /b
"""

_POWERSHELL = r"""
$ErrorActionPreference = 'Stop'
$Api = '__API__'
$Key = '__KEY__'
$Network = '__NETWORK__'
$Enforce = __ENFORCE__
$ExpectedSha = '__SHA__'

function Step($m) { Write-Host ""; Write-Host "== $m" -ForegroundColor Cyan }

try {
  $work = Join-Path $env:TEMP 'sentinelbi-setup'
  New-Item -ItemType Directory -Force -Path $work | Out-Null

  Step 'Downloading the sensor from your SentinelBI server'
  $sensor = Join-Path $work 'sentinelbi_sensor.py'
  $installer = Join-Path $work 'install-service.ps1'
  Invoke-WebRequest -UseBasicParsing "$Api/api/v1/sensor/sentinelbi_sensor.py" -OutFile $sensor
  Invoke-WebRequest -UseBasicParsing "$Api/api/v1/sensor/install-service.ps1" -OutFile $installer
  $sha = (Get-FileHash $sensor -Algorithm SHA256).Hash.ToLower()
  if ($ExpectedSha -and $sha -ne $ExpectedSha) {
    throw "The downloaded sensor does not match the expected checksum. Nothing was installed."
  }
  Write-Host "Checksum matches."

  Step 'Looking for Python'
  function Find-Python {
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }
    foreach ($r in $roots) {
      $hit = Get-ChildItem -Path $r -Filter 'Python3*' -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName 'python.exe' } |
        Where-Object { Test-Path $_ } | Select-Object -First 1
      if ($hit) { return $hit }
    }
    return $null
  }
  $py = Find-Python
  if (-not $py) {
    Write-Host 'Python for all users was not found. Installing it with winget (about 1 minute)...'
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
      throw 'winget is not available. Install Python 3.9+ for ALL users from https://www.python.org/downloads/ and run this file again.'
    }
    winget install -e --id Python.Python.3.12 --scope machine --silent --accept-package-agreements --accept-source-agreements | Out-Host
    $py = Find-Python
    if (-not $py) { throw 'Python was installed but could not be found. Restart Windows and run this file again.' }
  }
  Write-Host "Using $py"

  if (-not (Test-Path (Join-Path $env:SystemRoot 'System32\Npcap'))) {
    Write-Host ''
    Write-Host 'Optional: Npcap is not installed, so only IPv4 traffic will be counted.' -ForegroundColor Yellow
    Write-Host 'Its licence forbids installing it for you. Get it from https://npcap.com if you want IPv6 too.' -ForegroundColor Yellow
  }

  Step 'Installing the sensor so it starts with Windows'
  $args2 = @{ ApiUrl = $Api; ApiKey = $Key; SensorPath = $sensor; PythonPath = $py }
  if ($Network) { $args2.Ip = $Network }
  if ($Enforce) { $args2.Enforce = $true }
  & $installer @args2

  Write-Host ''
  Write-Host 'Done. You can close this window and go back to SentinelBI: this source turns green within a minute.' -ForegroundColor Green
} catch {
  Write-Host ''
  Write-Host "Setup stopped: $($_.Exception.Message)" -ForegroundColor Red
}
"""


def _quote(value: str) -> str:
    """A PowerShell single-quoted literal body."""
    return value.replace("'", "''")


def build_windows_installer(
    *, api_url: str, api_key: str, network: str, enforce: bool, sensor_sha256: str | None
) -> bytes:
    """The installer file's bytes (CRLF line endings, which batch files need)."""
    if not re.fullmatch(r"https?://[A-Za-z0-9.\-_:\[\]]+(/[A-Za-z0-9._~/-]*)?", api_url):
        raise ValueError("api_url is not a plain http(s) address")
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", api_key):
        raise ValueError("api_key has unexpected characters")
    if network and not re.fullmatch(r"[0-9A-Fa-f:.]+(/\d{1,3})?", network):
        raise ValueError("network is not an address or CIDR")
    script = (
        _POWERSHELL.replace("__API__", _quote(api_url.rstrip("/")))
        .replace("__KEY__", _quote(api_key))
        .replace("__NETWORK__", _quote(network))
        .replace("__ENFORCE__", "$true" if enforce else "$false")
        .replace("__SHA__", _quote(sensor_sha256 or ""))
    )
    text = _BATCH + MARKER + "\n" + script.lstrip("\n")
    return text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")
