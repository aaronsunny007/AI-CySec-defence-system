# Stop the native AEGIS range started by range\start.ps1.
$root = Split-Path -Parent $PSScriptRoot
$pidFile = Join-Path $root "logs\range.pids"
if (-not (Test-Path $pidFile)) { Write-Host "Range not running (no logs\range.pids)."; exit 0 }
foreach ($p in (Get-Content $pidFile) -split '\s+') {
    if ($p) { Stop-Process -Id ([int]$p) -Force -ErrorAction SilentlyContinue }
}
Remove-Item $pidFile
Write-Host "Range stopped."
