@echo off
title SecureVault LAN - PyInstaller Standalone Executable Builder
cd /d "%~dp0"
echo =====================================================================
echo  [+] SECUREVAULT LAN - BUILDING NATIVE WINDOWS EXECUTABLE
echo =====================================================================
echo.
echo  Step 1: Cleaning previous build caches...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"

echo.
echo  Step 2: Compiling desktop_app.py with PyInstaller...
echo  (Including CustomTkinter themes, Cryptography binaries and assets)
echo.

python -m PyInstaller --noconfirm --onedir --windowed --name "SecureVault_LAN" --collect-all customtkinter desktop_app.py

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
