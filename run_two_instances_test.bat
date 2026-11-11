@echo off
title SecureVault LAN - Dual Instance Local Test
cd /d "%~dp0"
echo =====================================================================
echo  [+] SECUREVAULT LAN - AUTOMATED DUAL INSTANCE TEST HARNESS
echo =====================================================================
echo.
echo  [1/2] Launching Server Instance (LAN Port: 5500, UI: 8082)...
start "SecureVault - Server Node" python app.py --web-port 8082 --lan-port 5500 --auto-server

echo  Waiting 3 seconds for Server RSA key generation and socket bind...
timeout /t 3 /nobreak >nul

echo.
echo  [2/2] Launching Client Instance (Connecting to 127.0.0.1:5500, UI: 8083)...
start "SecureVault - Client Node" python app.py --web-port 8083 --lan-port 5500 --auto-client 127.0.0.1

echo.
echo =====================================================================
echo  Both instances launched in native windows!
echo  Handshake will execute automatically.
echo =====================================================================
