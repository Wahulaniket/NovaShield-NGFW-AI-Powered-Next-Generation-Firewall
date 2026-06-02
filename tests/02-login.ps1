param(
    [string]$Gateway = "",
    [string]$Username = "alice",
    [string]$Password = "secret"
)

. "$PSScriptRoot/common.ps1"

Write-Section "Login"
$result = Get-LoginResponse -Gateway $Gateway -Username $Username -Password $Password
Show-Result -Label "login" -Result $result
Assert-Status -Actual $result.status -Expected 200 -Label "Login"

if (-not $result.data.token) {
    throw "Login succeeded but no token was returned."
}

Write-Host "Token received for account $($result.data.account_id)" -ForegroundColor Green
