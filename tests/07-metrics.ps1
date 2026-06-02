param(
    [string]$Gateway = ""
)

. "$PSScriptRoot/common.ps1"

Write-Section "Metrics and Snapshot"
$gatewayUrl = Get-GatewayUrl -Gateway $Gateway

$snapshot = Invoke-NovaRequest -Method GET -Uri "$gatewayUrl/api/admin/snapshot"
Show-Result -Label "snapshot" -Result $snapshot
Assert-Status -Actual $snapshot.status -Expected 200 -Label "Snapshot"

$metrics = Invoke-NovaRequest -Method GET -Uri "$gatewayUrl/api/admin/metrics"
if ($metrics.status -ne 200) {
    throw "Metrics endpoint failed with status $($metrics.status)."
}

Write-Host "metrics -> status $($metrics.status)"
if ($metrics.body) {
    $metrics.body
}
