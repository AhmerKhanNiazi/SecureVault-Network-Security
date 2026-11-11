@echo off
title SecureVault LAN - PyInstaller Standalone Executable Builder
cd /d "%~dp0"
echo =====================================================================
echo  [+] SECUREVAULT LAN - BUILDING NATIVE WINDOWS EXECUTABLE (v3.0)
echo =====================================================================
echo.
echo  Step 1: Cleaning previous build caches...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"

echo.
echo  Step 2: Compiling app.py with PyInstaller (including v3.0 Frontend)...
echo.

python -m PyInstaller --noconfirm --onedir --windowed --name "SecureVault_LAN" --add-data "frontend;frontend" --hidden-import "uvicorn" --hidden-import "uvicorn.logging" --hidden-import "uvicorn.loops" --hidden-import "uvicorn.loops.auto" --hidden-import "uvicorn.protocols" --hidden-import "uvicorn.protocols.http" --hidden-import "uvicorn.protocols.http.auto" --hidden-import "uvicorn.protocols.websockets" --hidden-import "uvicorn.protocols.websockets.auto" --hidden-import "uvicorn.lifespans" --hidden-import "uvicorn.lifespans.on" --hidden-import "fastapi" --hidden-import "websockets" --hidden-import "backend.threat_scanner" --hidden-import "backend.lan_discovery" app.py

if %ERRORLEVEL% equ 0 (
    echo.
    echo =====================================================================
    echo  [SUCCESS] Build Complete!
    echo  Your standalone Windows app is ready in:
    echo  dist\SecureVault_LAN\SecureVault_LAN.exe
    echo.
    echo  You can copy the whole 'SecureVault_LAN' folder to a USB drive
    echo  or send it to any other PC on the LAN!
    echo =====================================================================
) else (
    echo.
    echo =====================================================================
    echo  [FAILURE] Build failed. Check errors above.
    echo =====================================================================
)
pause
