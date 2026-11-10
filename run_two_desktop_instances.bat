@echo off
title SecureVault LAN - Dual Desktop Instance Test
cd /d "%~dp0"
echo =====================================================================
echo  [+] SECUREVAULT LAN - DUAL NATIVE DESKTOP TEST
echo =====================================================================
echo.
echo  [1/2] Launching Instance 1: Server Mode (Listening on Port 5500)...
start "SecureVault Server" python desktop_app.py --lan-port 5500 --auto-server

echo  Waiting 2 seconds for Server RSA key generation and socket bind...
timeout /t 2 /nobreak >nul

echo.
echo  [2/2] Launching Instance 2: Client Mode (Connecting to 127.0.0.1:5500)...
start "SecureVault Client" python desktop_app.py --lan-port 5500 --auto-client 127.0.0.1

echo.
echo =====================================================================
echo  Both Native Desktop Windows are launched!
echo  Handshake and encrypted session are established automatically.
echo =====================================================================
