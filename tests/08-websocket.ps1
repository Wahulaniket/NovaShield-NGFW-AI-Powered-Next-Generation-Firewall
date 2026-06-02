param(
    [string]$Gateway = "",
    [int]$MessagesToRead = 3
)

. "$PSScriptRoot/common.ps1"

$client = [System.Net.WebSockets.ClientWebSocket]::new()
$gatewayUrl = Get-WebSocketGatewayUrl -Gateway $Gateway
$uri = [Uri]::new("$($gatewayUrl.TrimEnd('/'))/ws/live")
$buffer = New-Object byte[] 8192

Write-Host ""
Write-Host "==== WebSocket Live Feed ====" -ForegroundColor Cyan
$client.ConnectAsync($uri, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
Write-Host "Connected to $uri"

for ($i = 1; $i -le $MessagesToRead; $i++) {
    $segment = [ArraySegment[byte]]::new($buffer)
    $result = $client.ReceiveAsync($segment, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
    $text = [Text.Encoding]::UTF8.GetString($buffer, 0, $result.Count)
    Write-Host ""
    Write-Host "message $i"
    Write-Host $text
}

$client.Dispose()
