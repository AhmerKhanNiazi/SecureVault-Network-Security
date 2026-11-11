@echo off
title SecureVault Cyber Liquid - Standalone Executable Builder
cd /d "%~dp0"
echo =====================================================================
echo  [+] SECUREVAULT LAN - BUILDING CYBER LIQUIDMORPHISM STANDALONE .EXE
echo =====================================================================
echo.
echo  Step 1: Compiling app.py with PyInstaller (including Liquidmorphism Frontend)...
echo.

python -m PyInstaller --noconfirm --onedir --windowed --name "SecureVault_Cyber_Liquid" --add-data "frontend;frontend" --hidden-import "uvicorn" --hidden-import "uvicorn.logging" --hidden-import "uvicorn.loops" --hidden-import "uvicorn.loops.auto" --hidden-import "uvicorn.protocols" --hidden-import "uvicorn.protocols.http" --hidden-import "uvicorn.protocols.http.auto" --hidden-import "uvicorn.protocols.websockets" --hidden-import "uvicorn.protocols.websockets.auto" --hidden-import "uvicorn.lifespans" --hidden-import "uvicorn.lifespans.on" --hidden-import "fastapi" --hidden-import "websockets" --hidden-import "backend.threat_scanner" --hidden-import "backend.lan_discovery" app.py

if %ERRORLEVEL% equ 0 (
    echo.
    echo =====================================================================
    echo  [SUCCESS] Build Complete!
    echo  Your standalone Cyber Liquidmorphism App is ready in:
    echo  dist\SecureVault_Cyber_Liquid\SecureVault_Cyber_Liquid.exe
    echo.
    echo  You can copy the whole 'SecureVault_Cyber_Liquid' folder to any PC!
    echo =====================================================================
) else (
    echo.
    echo =====================================================================
    echo  [FAILURE] Build failed. Check errors above.
    echo =====================================================================
)
pause
