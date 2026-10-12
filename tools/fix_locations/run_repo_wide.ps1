# Overnight repo-wide run for VulnGym issue #4 PR2
# YELLOW_SCOPED: --repo-wide ON; isolated out; no push/PR.
# See REPO_WIDE_NIGHT_PLAN.md and NIGHT_CONTRACT_REPO_WIDE.md
#
# Usage:
#   powershell -File tools/fix_locations/run_repo_wide.ps1
#   powershell -File tools/fix_locations/run_repo_wide.ps1 -Sample
#   powershell -File tools/fix_locations/run_repo_wide.ps1 -OutDir tools/fix_locations/out/repo_wide

param(
  [switch]$Sample,
  [string]$OutDir = ""
)

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root

if (-not $OutDir) {
  if ($Sample) {
    $OutDir = Join-Path $PSScriptRoot "out\repo_wide_sample"
  } else {
    $OutDir = Join-Path $PSScriptRoot "out\repo_wide"
  }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Log = Join-Path $OutDir "repo_wide_run_$stamp.log"
$Err = "$Log.err"

$pyArgs = @(
  "-u", "tools/fix_locations/fix_code_locations.py",
  "--repo-wide", "--apply",
  "--out", $OutDir
)

if ($Sample) {
  $pyArgs += @(
    "--only", "entry-00164", "entry-00193", "entry-00298"
  )
  $mode = "SAMPLE"
} else {
  $pyArgs += @("--all")
  $mode = "FULL"
}

Write-Host "=== VulnGym #4 Repo-wide ($mode) ===" -ForegroundColor Cyan
Write-Host "ROOT=$Root"
Write-Host "OUT=$OutDir"
Write-Host "LOG=$Log"
Write-Host "RISK_CEILING=YELLOW_SCOPED  REPO_WIDE=true  NO_PR=true  NO_PUSH=true"
Write-Host ""

$p = Start-Process -FilePath "python" `
  -ArgumentList $pyArgs `
  -WorkingDirectory $Root `
  -RedirectStandardOutput $Log `
  -RedirectStandardError $Err `
  -NoNewWindow `
  -PassThru

Set-Content -Path (Join-Path $OutDir "night_run.pid") -Value $p.Id
Write-Host "Started PID=$($p.Id)"
Write-Host "Waiting (overnight OK for FULL)..."
Wait-Process -Id $p.Id
$code = $p.ExitCode
Write-Host ""
Write-Host "----- stdout tail -----"
Get-Content $Log -Tail 40 -ErrorAction SilentlyContinue
Write-Host "----- stderr tail -----"
Get-Content $Err -Tail 40 -ErrorAction SilentlyContinue
Write-Host "Exit code: $code"
exit $code
