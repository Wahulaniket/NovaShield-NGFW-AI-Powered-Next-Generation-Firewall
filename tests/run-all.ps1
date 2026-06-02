param(
    [string]$Gateway = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scripts = @(
    "01-health.ps1",
    "02-login.ps1",
    "03-auth-flow.ps1",
    "04-security.ps1",
    "05-rate-limit.ps1",
    "07-metrics.ps1"
)

foreach ($script in $scripts) {
    Write-Host ""
    Write-Host "Running $script" -ForegroundColor Yellow
    & (Join-Path $PSScriptRoot $script) -Gateway $Gateway
}

Write-Host ""
Write-Host "Core test suite finished successfully." -ForegroundColor Green
