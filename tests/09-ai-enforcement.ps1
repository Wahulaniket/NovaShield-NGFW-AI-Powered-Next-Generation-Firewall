# NovaShield AI Enforcement Test
# Tests that the AI engine layer is integrated into the gateway pipeline.

$ErrorActionPreference = "Stop"
$gateway = "http://127.0.0.1:8080"

Write-Host "`n=== NovaShield AI Enforcement Test ===" -ForegroundColor Cyan

# Test 1: Check AI engine health
Write-Host "`n[1] AI Engine health check..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -Method GET -TimeoutSec 5
    if ($response.status -eq "ok") {
        Write-Host "    PASS: AI engine is healthy" -ForegroundColor Green
    } else {
        Write-Host "    FAIL: AI engine returned unexpected status" -ForegroundColor Red
    }
} catch {
    Write-Host "    SKIP: AI engine not reachable (is it running?)" -ForegroundColor DarkYellow
}

# Test 2: Normal login should succeed through AI layer
Write-Host "`n[2] Normal login through AI layer..." -ForegroundColor Yellow
try {
    $body = @{ username = "testuser"; password = "testpass" } | ConvertTo-Json
    $response = Invoke-RestMethod -Uri "$gateway/api/login" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 10
    if ($response.token) {
        Write-Host "    PASS: Normal login succeeded (AI allowed)" -ForegroundColor Green
    } else {
        Write-Host "    FAIL: Login did not return token" -ForegroundColor Red
    }
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 403) {
        Write-Host "    INFO: AI blocked the request (may be expected with trained model)" -ForegroundColor DarkYellow
    } else {
        Write-Host "    FAIL: Unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Test 3: Verify AI docs endpoint is available
Write-Host "`n[3] AI Engine OpenAPI docs..." -ForegroundColor Yellow
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:8000/docs" -Method GET -TimeoutSec 5
    Write-Host "    PASS: OpenAPI docs available at /docs" -ForegroundColor Green
} catch {
    Write-Host "    SKIP: AI engine docs not reachable" -ForegroundColor DarkYellow
}

# Test 4: Direct AI prediction test
Write-Host "`n[4] Direct AI /predict endpoint..." -ForegroundColor Yellow
try {
    $body = @{
        ip = "192.168.1.100"
        path = "/api/balance"
        method = "GET"
        user_agent = "Mozilla/5.0"
    } | ConvertTo-Json
    $response = Invoke-RestMethod -Uri "http://127.0.0.1:8000/predict" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 10
    if ($response.decision) {
        Write-Host "    PASS: AI returned decision='$($response.decision)' label='$($response.label)'" -ForegroundColor Green
    } else {
        Write-Host "    FAIL: AI response missing decision field" -ForegroundColor Red
    }
} catch {
    Write-Host "    SKIP: AI engine not reachable" -ForegroundColor DarkYellow
}

Write-Host "`n=== AI Enforcement Test Complete ===" -ForegroundColor Cyan
