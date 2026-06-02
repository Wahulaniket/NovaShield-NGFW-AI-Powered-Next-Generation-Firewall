param(
    [string]$Gateway = "",
    [string]$Username = "alice",
    [string]$Password = "secret"
)

. "$PSScriptRoot/common.ps1"

Write-Section "Authenticated Flow"
$login = Get-LoginResponse -Gateway $Gateway -Username $Username -Password $Password
Assert-Status -Actual $login.status -Expected 200 -Label "Login for auth flow"

$authHeaders = Get-AuthHeaders -Token $login.data.token
$gatewayUrl = Get-GatewayUrl -Gateway $Gateway

$balance = Invoke-NovaRequest -Method GET -Uri "$gatewayUrl/api/balance" -Headers $authHeaders
Show-Result -Label "balance" -Result $balance
Assert-Status -Actual $balance.status -Expected 200 -Label "Balance"

$transferBody = @{
    to_account = "acct-bob"
    amount = 1500
    reference = "auth-flow-test"
} | ConvertTo-Json

$transfer = Invoke-NovaRequest -Method POST -Uri "$gatewayUrl/api/transfer" -Headers $authHeaders -Body $transferBody
Show-Result -Label "transfer" -Result $transfer
Assert-Status -Actual $transfer.status -Expected 200 -Label "Transfer"
