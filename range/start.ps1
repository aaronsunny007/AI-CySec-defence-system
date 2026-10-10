# Start the AEGIS range natively on Windows (no Docker/WSL needed).
#
#   client --> gateway (Go + Coraza + CRS) 127.0.0.1:8080 --> Juice Shop :3000
#
# Usage:  .\range\start.ps1 [-Mode enforce|detect] [-JuiceShop C:\path\to\juice-shop]
# Stop:   .\range\stop.ps1

param(
    [ValidateSet("enforce", "detect")] [string]$Mode = "enforce",
    [string]$JuiceShop = "$env:USERPROFILE\tools\juice-shop",
    [string]$Rules = "",      # optional extra candidate rule file loaded after CRS
    [string]$RateRules = ""   # optional AEGIS rate-limit rules JSON
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$logs = Join-Path $root "logs"
New-Item -ItemType Directory -Force $logs, "$logs\gateway" | Out-Null
$pidFile = Join-Path $logs "range.pids"

function Wait-Http($url, $seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        try { Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 2 | Out-Null; return $true } catch { Start-Sleep 1 }
    }
    return $false
}

if (Test-Path $pidFile) { Write-Host "range.pids exists - run .\range\stop.ps1 first"; exit 1 }

$gw = Join-Path $root "bin\gateway.exe"
if (-not (Test-Path $gw)) { Write-Host "bin\gateway.exe missing - build it: cd gateway; go build -o ..\bin\gateway.exe ."; exit 1 }

Write-Host "Starting Juice Shop from $JuiceShop ..."
$js = Start-Process node -ArgumentList "build/app" -WorkingDirectory $JuiceShop -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$logs\juiceshop.out.log" -RedirectStandardError "$logs\juiceshop.err.log"
if (-not (Wait-Http "http://127.0.0.1:3000" 120)) { Stop-Process -Id $js.Id -Force; Write-Host "Juice Shop did not come up - see logs\juiceshop.*.log"; exit 1 }

$gwArgs = "-mode $Mode -log logs/gateway/requests.jsonl"
if ($Rules -ne "") {
    if (-not (Test-Path $Rules)) { Stop-Process -Id $js.Id -Force; Write-Host "rules file not found: $Rules"; exit 1 }
    $gwArgs += " -rules `"$Rules`""
    Write-Host "Starting gateway (mode=$Mode, +candidate rules $Rules) ..."
} else {
    Write-Host "Starting gateway (mode=$Mode) ..."
}
if ($RateRules -ne "") {
    if (-not (Test-Path $RateRules)) { Stop-Process -Id $js.Id -Force; Write-Host "rate rules file not found: $RateRules"; exit 1 }
    $gwArgs += " -raterules `"$RateRules`""
    Write-Host "  + rate-limit rules: $RateRules"
}
$g = Start-Process $gw -ArgumentList $gwArgs -WorkingDirectory $root -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$logs\gateway.out.log" -RedirectStandardError "$logs\gateway.err.log"
if (-not (Wait-Http "http://127.0.0.1:8080" 30)) { Stop-Process -Id $g.Id, $js.Id -Force; Write-Host "Gateway did not come up - see logs\gateway.err.log"; exit 1 }

"$($js.Id) $($g.Id)" | Set-Content $pidFile
Write-Host "Range up:  http://localhost:8080  (Juice Shop behind AEGIS gateway, mode=$Mode)"
Write-Host "Requests:  logs\gateway\requests.jsonl"
