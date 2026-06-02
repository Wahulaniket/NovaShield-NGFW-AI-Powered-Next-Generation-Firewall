@echo off
title NovaShield - Stopping All Services
color 0C
echo.
echo    Stopping all NovaShield services...
echo.

taskkill /FI "WINDOWTITLE eq NovaShield Backend*" /F > nul 2>&1
taskkill /FI "WINDOWTITLE eq NovaShield AI Engine*" /F > nul 2>&1
taskkill /FI "WINDOWTITLE eq NovaShield Gateway*" /F > nul 2>&1
taskkill /FI "WINDOWTITLE eq NovaShield Dashboard*" /F > nul 2>&1
taskkill /IM "backend.exe" /F > nul 2>&1
taskkill /IM "gateway.exe" /F > nul 2>&1

echo    All services stopped!
echo.
timeout /t 2 /nobreak > nul
