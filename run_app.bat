@echo off
title SecureVault LAN - Cyber Defense Suite
cd /d "%~dp0"
echo =====================================================================
echo  [+] SECUREVAULT LAN - ENCRYPTED TRANSPORT SUITE
echo  [+] Starting Python Backend and Hardware-Accelerated Cyber UI...
echo =====================================================================
python app.py
if %ERRORLEVEL% neq 0 (
    echo.
    echo =====================================================================
    echo  [!] Application stopped with exit code %ERRORLEVEL%.
    echo =====================================================================
)
pause
