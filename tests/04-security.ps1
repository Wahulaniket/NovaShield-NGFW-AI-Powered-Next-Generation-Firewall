param(
    [string]$Gateway = ""
)

. "$PSScriptRoot/common.ps1"

$gatewayUrl = Get-GatewayUrl -Gateway $Gateway

Write-Section "Missing JWT"
$missingJwt = Invoke-NovaRequest -Method GET -Uri "$gatewayUrl/api/balance"
Show-Result -Label "missing-jwt" -Result $missingJwt
Assert-Status -Actual $missingJwt.status -Expected 401 -Label "Missing JWT"

Write-Section "SQL Injection Block"
$sqlHeaders = Get-JsonHeaders
$sqlBody = @{
    username = "admin OR 1=1"
    password = "x"
} | ConvertTo-Json
$sqlResult = Invoke-NovaRequest -Method POST -Uri "$gatewayUrl/api/login" -Headers $sqlHeaders -Body $sqlBody
Show-Result -Label "sql-injection" -Result $sqlResult
Assert-Status -Actual $sqlResult.status -Expected 403 -Label "SQL injection protection"

Write-Section "XSS Block"
$xssResult = Invoke-NovaRequest -Method GET -Uri "$gatewayUrl/api/balance?q=<script>alert(1)</script>"
Show-Result -Label "xss" -Result $xssResult
Assert-Status -Actual $xssResult.status -Expected 403 -Label "XSS protection"

Write-Section "Traversal Block"
$traversalResult = Invoke-NovaRequest -Method GET -Uri "$gatewayUrl/api/balance?file=../../../../etc/passwd"
Show-Result -Label "traversal" -Result $traversalResult
Assert-Status -Actual $traversalResult.status -Expected 403 -Label "Path traversal protection"

Write-Section "Blacklist Block"
$blacklistHeaders = @{
    "Content-Type" = "application/json"
    "X-Real-IP" = "203.0.113.10"
}
$blacklistBody = @{
    username = "eve"
    password = "x"
} | ConvertTo-Json
$blacklistResult = Invoke-NovaRequest -Method POST -Uri "$gatewayUrl/api/login" -Headers $blacklistHeaders -Body $blacklistBody
Show-Result -Label "blacklist" -Result $blacklistResult
Assert-Status -Actual $blacklistResult.status -Expected 403 -Label "Blacklist protection"
