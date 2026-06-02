@echo off
setlocal EnableDelayedExpansion
title NovaShield NGFW - Launcher
color 0B

:: ─────────────────────────────────────────────────────────────
::  Get the project root directory (where this .bat file lives)
:: ─────────────────────────────────────────────────────────────
set "ROOT=%~dp0"
cd /d "%ROOT%"
for /f %%i in ('powershell -NoProfile -Command "(Get-NetIPAddress -AddressFamily IPv4 ^| Where-Object { $_.IPAddress -notlike '127.*' -and $_.InterfaceOperationalStatus -eq 'Up' } ^| Sort-Object InterfaceMetric ^| Select-Object -First 1 -ExpandProperty IPAddress)"') do set "LAN_IP=%%i"
if not defined LAN_IP set "LAN_IP=127.0.0.1"

:: ─────────────────────────────────────────────────────────────
::  Banner
:: ─────────────────────────────────────────────────────────────
cls
echo.
echo    ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗
echo    ████╗  ██║██╔═══██╗██║   ██║██╔══██╗██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
echo    ██╔██╗ ██║██║   ██║██║   ██║███████║███████╗███████║██║█████╗  ██║     ██║  ██║
echo    ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
echo    ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║███████║██║  ██║██║███████╗███████╗██████╔╝
echo    ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
echo.
echo    ╔══════════════════════════════════════════════════════════════════╗
echo    ║           AI-Powered Next-Generation Firewall                  ║
echo    ╚══════════════════════════════════════════════════════════════════╝
echo.
echo    Starting all services...
echo.

:: ─────────────────────────────────────────────────────────────
::  1. Start Backend (Rust - port 8081)
:: ─────────────────────────────────────────────────────────────
echo    [1/4] Starting Backend Server (port 8081)...
start "NovaShield Backend [8081]" cmd /k "title NovaShield Backend [8081] && color 0A && cd /d "%ROOT%" && echo. && echo ══════════════════════════════════════════ && echo   NovaShield Backend - Port 8081 && echo ══════════════════════════════════════════ && echo. && cargo run -p backend"
timeout /t 6 /nobreak > nul

:: Check if backend is up
powershell -Command "try { $null = Invoke-WebRequest -Uri http://127.0.0.1:8081/health -UseBasicParsing -TimeoutSec 3; Write-Host '   [OK] Backend is running' -Fore Green } catch { Write-Host '   [..] Backend starting (may need to compile)' -Fore Yellow }"
echo.

:: ─────────────────────────────────────────────────────────────
::  2. Start AI Engine (Python/FastAPI - port 8000)
:: ─────────────────────────────────────────────────────────────
echo    [2/4] Starting AI Engine (port 8000)...
start "NovaShield AI Engine [8000]" cmd /k "title NovaShield AI Engine [8000] && color 0D && cd /d "%ROOT%ai_engine" && echo. && echo ══════════════════════════════════════════ && echo   NovaShield AI Engine - Port 8000 && echo   ML Model: Random Forest (CICIDS2017) && echo ══════════════════════════════════════════ && echo. && python -m uvicorn main:app --host 0.0.0.0 --port 8000"
timeout /t 8 /nobreak > nul

:: Check if AI engine is up
powershell -Command "try { $null = Invoke-WebRequest -Uri http://127.0.0.1:8000/health -UseBasicParsing -TimeoutSec 3; Write-Host '   [OK] AI Engine is running (model loaded)' -Fore Green } catch { Write-Host '   [..] AI Engine starting (loading model)' -Fore Yellow }"
echo.

:: ─────────────────────────────────────────────────────────────
::  3. Start Gateway (Rust - port 8080)
:: ─────────────────────────────────────────────────────────────
echo    [3/4] Starting Gateway Firewall (port 8080)...
start "NovaShield Gateway [8080]" cmd /k "title NovaShield Gateway [8080] && color 0E && cd /d "%ROOT%" && echo. && echo ══════════════════════════════════════════ && echo   NovaShield Gateway Firewall - Port 8080 && echo   WAF + AI + Rate Limiting + Blacklist && echo ══════════════════════════════════════════ && echo. && cargo run -p gateway"
timeout /t 6 /nobreak > nul

:: Check if gateway is up
powershell -Command "try { $null = Invoke-WebRequest -Uri http://127.0.0.1:8080/api/admin/health -UseBasicParsing -TimeoutSec 3; Write-Host '   [OK] Gateway is running' -Fore Green } catch { Write-Host '   [..] Gateway starting (may need to compile)' -Fore Yellow }"
echo.

:: ─────────────────────────────────────────────────────────────
::  4. Start Dashboard (Vite/React - port 5173)
:: ─────────────────────────────────────────────────────────────
echo    [4/4] Starting Dashboard UI (port 5173)...
start "NovaShield Dashboard [5173]" cmd /k "title NovaShield Dashboard [5173] && color 0B && cd /d "%ROOT%dashboard" && echo. && echo ══════════════════════════════════════════ && echo   NovaShield Dashboard - Port 5173 && echo ══════════════════════════════════════════ && echo. && npm run dev"
timeout /t 5 /nobreak > nul
echo.

:: ─────────────────────────────────────────────────────────────
::  Final Status
:: ─────────────────────────────────────────────────────────────
cls
echo.
echo    ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗
echo    ████╗  ██║██╔═══██╗██║   ██║██╔══██╗██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
echo    ██╔██╗ ██║██║   ██║██║   ██║███████║███████╗███████║██║█████╗  ██║     ██║  ██║
echo    ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
echo    ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║███████║██║  ██║██║███████╗███████╗██████╔╝
echo    ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
echo.
echo    ╔══════════════════════════════════════════════════════════════════╗
echo    ║              All Services Launched!                            ║
echo    ╠══════════════════════════════════════════════════════════════════╣
echo    ║                                                                ║
echo    ║   Backend:      http://127.0.0.1:8081        [Rust/Axum]      ║
echo    ║   AI Engine:    http://127.0.0.1:8000        [Python/FastAPI] ║
echo    ║   Gateway:      http://127.0.0.1:8080        [Rust/Axum]      ║
echo    ║   Dashboard:    http://localhost:5173         [React/Vite]     ║
echo    ║                                                                ║
echo    ║   API Docs:     http://127.0.0.1:8000/docs   [Swagger UI]     ║
echo    ║                                                                ║
echo    ╠══════════════════════════════════════════════════════════════════╣
echo    ║                                                                ║
echo    ║   Security Layers Active:                                      ║
echo    ║     [x] WAF      - SQL Injection, XSS, Traversal, CmdInj     ║
echo    ║     [x] WAF      - Null Byte, CRLF, SSRF Detection           ║
echo    ║     [x] WAF      - URL Encoding Bypass Prevention             ║
echo    ║     [x] WAF      - Header Injection Detection                 ║
echo    ║     [x] AI       - Attack Tool Scanner Detection              ║
echo    ║     [x] AI       - ML Threat Classification (CICIDS2017)      ║
echo    ║     [x] Rate     - Login/Transfer/Balance Rate Limiting       ║
echo    ║     [x] Blacklist- IP Blacklist + Auto-Blacklist on WAF Match ║
echo    ║     [x] JWT      - Token Authentication + Admin RBAC          ║
echo    ║                                                                ║
echo    ╚══════════════════════════════════════════════════════════════════╝
echo.

:: ─────────────────────────────────────────────────────────────
::  Open Dashboard in Browser
:: ─────────────────────────────────────────────────────────────
echo    LAN Health Check: http://%LAN_IP%:8080/api/admin/health
echo    LAN Dashboard:    http://%LAN_IP%:5173
echo.
echo    Opening dashboard in browser...
timeout /t 3 /nobreak > nul
start http://localhost:5173
echo.
echo    ════════════════════════════════════════════════════════════════
echo    Press any key to STOP all NovaShield services...
echo    ════════════════════════════════════════════════════════════════
pause > nul

:: ─────────────────────────────────────────────────────────────
::  Shutdown all services
:: ─────────────────────────────────────────────────────────────
echo.
echo    Stopping all services...
taskkill /FI "WINDOWTITLE eq NovaShield Backend*" /F > nul 2>&1
taskkill /FI "WINDOWTITLE eq NovaShield AI Engine*" /F > nul 2>&1
taskkill /FI "WINDOWTITLE eq NovaShield Gateway*" /F > nul 2>&1
taskkill /FI "WINDOWTITLE eq NovaShield Dashboard*" /F > nul 2>&1

:: Also kill the actual processes
taskkill /IM "backend.exe" /F > nul 2>&1
taskkill /IM "gateway.exe" /F > nul 2>&1

echo.
echo    All services stopped. Goodbye!
echo.
timeout /t 3 /nobreak > nul
exit
