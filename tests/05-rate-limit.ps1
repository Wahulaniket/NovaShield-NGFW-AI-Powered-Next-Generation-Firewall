param(
    [string]$Gateway = "",
    [int]$Attempts = 8,
    [string]$ClientIp = "198.18.0.50",
    [switch]$WaitForReset = $true
)

. "$PSScriptRoot/common.ps1"

Write-Section "Rate Limit Test"
$hits200 = 0
$hits429 = 0
$gatewayUrl = Get-GatewayUrl -Gateway $Gateway

for ($i = 1; $i -le $Attempts; $i++) {
    $result = Get-LoginResponse -Gateway $Gateway -Username "rate-test-user" -Password "secret" -ExtraHeaders @{
        "X-Real-IP" = $ClientIp
    }
    Write-Host ("attempt {0} from {1} -> {2}" -f $i, $ClientIp, $result.status)
    if ($result.status -eq 200) {
        $hits200++
    }
    if ($result.status -eq 429) {
        $hits429++
    }
}

if ($hits200 -ne 5) {
    throw "Rate limit test failed. Expected exactly 5 successful login requests before limiting, but got $hits200."
}

if ($hits429 -lt 1) {
    throw "Rate limit test failed. No 429 responses were returned after the first 5 requests."
}

Write-Host "Observed $hits200 successful requests followed by $hits429 rate-limited requests." -ForegroundColor Green

$lastAttempt = Get-LoginResponse -Gateway $Gateway -Username "rate-test-user" -Password "secret" -ExtraHeaders @{
    "X-Real-IP" = $ClientIp
}
Write-Host "last response status -> $($lastAttempt.status)"
Write-Host "retry-after -> $($lastAttempt.headers['Retry-After'])"
Write-Host "x-ratelimit-limit -> $($lastAttempt.headers['X-RateLimit-Limit'])"
Write-Host "x-ratelimit-remaining -> $($lastAttempt.headers['X-RateLimit-Remaining'])"

if (-not $WaitForReset) {
    return
}

Write-Host "Waiting 61 seconds to verify automatic renewal..." -ForegroundColor Yellow
Start-Sleep -Seconds 61

$renewed = Get-LoginResponse -Gateway $Gateway -Username "rate-test-user" -Password "secret" -ExtraHeaders @{
    "X-Real-IP" = $ClientIp
}
Show-Result -Label "renewed-login" -Result $renewed
Assert-Status -Actual $renewed.status -Expected 200 -Label "Rate limit renewal after 60 seconds"
