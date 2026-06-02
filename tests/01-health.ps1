param(
    [string]$Gateway = ""
)

. "$PSScriptRoot/common.ps1"

Write-Section "Health Check"
$gatewayUrl = Get-GatewayUrl -Gateway $Gateway
$result = Invoke-NovaRequest -Method GET -Uri "$gatewayUrl/api/admin/health"
Show-Result -Label "health" -Result $result
Assert-Status -Actual $result.status -Expected 200 -Label "Health endpoint"
