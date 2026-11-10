@echo off
title SecureVault LAN - Native Desktop Launcher
cd /d "%~dp0"
echo =====================================================================
echo  [+] SECUREVAULT LAN - PURE NATIVE DESKTOP SUITE
echo  [+] Running 100%% Native Python GUI (Zero Browser Dependencies)...
echo =====================================================================
python desktop_app.py
if %ERRORLEVEL% neq 0 (
    echo.
    echo =====================================================================
    echo  [!] Application stopped with exit code %ERRORLEVEL%.
    echo =====================================================================
    pause
)
