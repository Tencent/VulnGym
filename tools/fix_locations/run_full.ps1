# Overnight / full-dataset run for VulnGym issue #4
# GREEN only: no --repo-wide, no push, no PR. See NIGHT_RUN.md
#
# Detaches python so git stderr cannot kill the PowerShell host.
# Usage: powershell -File tools/fix_locations/run_full.ps1

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root

$Out = Join-Path $PSScriptRoot "out"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Log = Join-Path $Out "full_run_$stamp.log"
$Err = "$Log.err"

Write-Host "=== VulnGym #4 Night Run (GREEN) ===" -ForegroundColor Cyan
Write-Host "ROOT=$Root"
Write-Host "LOG=$Log"
Write-Host "ERR=$Err"
Write-Host "RISK_CEILING=GREEN  REPO_WIDE=false  NO_PR=true"
Write-Host ""

$p = Start-Process -FilePath "python" `
  -ArgumentList @("-u", "tools/fix_locations/fix_code_locations.py", "--all", "--apply") `
  -WorkingDirectory $Root `
  -RedirectStandardOutput $Log `
  -RedirectStandardError $Err `
  -NoNewWindow `
  -PassThru

Set-Content -Path (Join-Path $Out "night_run.pid") -Value $p.Id
Write-Host "Started PID=$($p.Id)"
Write-Host "Waiting for process to finish (overnight OK)..."
Wait-Process -Id $p.Id
$code = $p.ExitCode
Write-Host ""
Write-Host "----- stdout tail -----"
Get-Content $Log -Tail 30 -ErrorAction SilentlyContinue
Write-Host "----- stderr tail -----"
Get-Content $Err -Tail 30 -ErrorAction SilentlyContinue
Write-Host "Exit code: $code"
exit $code
