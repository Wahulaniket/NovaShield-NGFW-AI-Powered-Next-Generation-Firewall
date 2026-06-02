Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$script:SelfSignedHttpsEnabled = $false

function Get-GatewayUrl {
    param(
        [string]$Gateway = ""
    )

    if ($Gateway) {
        return $Gateway.TrimEnd("/")
    }

    return "http://127.0.0.1:8080"
}

function Get-WebSocketGatewayUrl {
    param(
        [string]$Gateway = ""
    )

    $gatewayUrl = Get-GatewayUrl -Gateway $Gateway
    if ($gatewayUrl -like "https://*") {
        return $gatewayUrl -replace "^https://", "wss://"
    }

    return $gatewayUrl -replace "^http://", "ws://"
}

function Write-Section {
    param(
        [string]$Title
    )

    Write-Host ""
    Write-Host "==== $Title ====" -ForegroundColor Cyan
}

function Get-JsonHeaders {
    return @{
        "Content-Type" = "application/json"
    }
}

function Read-ErrorResponse {
    param(
        [Parameter(Mandatory = $true)]
        $Exception
    )

    $hasResponse = $Exception.PSObject.Properties.Name -contains "Response"
    if (-not $hasResponse -or -not $Exception.Response) {
        return @{
            status = -1
            body = $Exception.Message
            headers = $null
        }
    }

    $status = [int]$Exception.Response.StatusCode
    $stream = $Exception.Response.GetResponseStream()
    if (-not $stream) {
        return @{
            status = $status
            body = ""
            headers = $Exception.Response.Headers
        }
    }

    $reader = New-Object System.IO.StreamReader($stream)
    $body = $reader.ReadToEnd()
    $reader.Dispose()
    $stream.Dispose()

    return @{
        status = $status
        body = $body
        headers = $Exception.Response.Headers
    }
}

function Enable-SelfSignedHttpsSupport {
    if (-not $script:SelfSignedHttpsEnabled) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $script:SelfSignedHttpsEnabled = $true
    }
}

function Invoke-NovaRequest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [hashtable]$Headers,
        [string]$Body
    )

    try {
        if ($Uri -like "https://*") {
            Enable-SelfSignedHttpsSupport
        }

        if ($Method -eq "GET") {
            $response = Invoke-WebRequest -Method GET -Uri $Uri -Headers $Headers
        }
        else {
            $response = Invoke-WebRequest -Method POST -Uri $Uri -Headers $Headers -Body $Body
        }

        $parsed = $null
        if ($response.Content) {
            try {
                $parsed = $response.Content | ConvertFrom-Json
            }
            catch {
                $parsed = $response.Content
            }
        }

        return @{
            ok = $true
            status = [int]$response.StatusCode
            raw = $response
            data = $parsed
            body = $response.Content
            headers = $response.Headers
        }
    }
    catch {
        $errorInfo = Read-ErrorResponse -Exception $_.Exception
        $parsed = $null
        if ($errorInfo.body) {
            try {
                $parsed = $errorInfo.body | ConvertFrom-Json
            }
            catch {
                $parsed = $errorInfo.body
            }
        }

        return @{
            ok = $false
            status = $errorInfo.status
            raw = $null
            data = $parsed
            body = $errorInfo.body
            headers = $errorInfo.headers
        }
    }
}

function Get-LoginResponse {
    param(
        [string]$Gateway = "",
        [string]$Username = "alice",
        [string]$Password = "secret",
        [hashtable]$ExtraHeaders = @{}
    )

    $gatewayUrl = Get-GatewayUrl -Gateway $Gateway
    $headers = Get-JsonHeaders
    foreach ($key in $ExtraHeaders.Keys) {
        $headers[$key] = $ExtraHeaders[$key]
    }

    $body = @{
        username = $Username
        password = $Password
    } | ConvertTo-Json

    return Invoke-NovaRequest -Method POST -Uri "$gatewayUrl/api/login" -Headers $headers -Body $body
}

function Get-AuthHeaders {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    return @{
        "Content-Type" = "application/json"
        "Authorization" = "Bearer $Token"
    }
}

function Assert-Status {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Actual,

        [Parameter(Mandatory = $true)]
        [int]$Expected,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if ($Actual -ne $Expected) {
        throw "$Label failed. Expected status $Expected but got $Actual."
    }

    Write-Host "$Label passed with status $Actual" -ForegroundColor Green
}

function Show-Result {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [hashtable]$Result
    )

    Write-Host "$Label -> status $($Result.status)"
    if ($null -ne $Result.data) {
        $Result.data | ConvertTo-Json -Depth 6
    }
    elseif ($Result.body) {
        $Result.body
    }
}
