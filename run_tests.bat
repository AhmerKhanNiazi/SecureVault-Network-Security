@echo off
title SecureVault LAN - Automated Test Suite
cd /d "%~dp0"
echo =====================================================================
echo  [+] Executing SecureVault LAN Automated Crypto & E2E Test Suite...
echo =====================================================================
python -c "import sys; sys.path.insert(0, '.'); import unittest; suite = unittest.defaultTestLoader.discover('tests'); runner = unittest.TextTestRunner(verbosity=2); res = runner.run(suite); sys.exit(0 if res.wasSuccessful() else 1)"
if %ERRORLEVEL% equ 0 (
    echo.
    echo =====================================================================
    echo  [SUCCESS] All Cryptographic and Network E2E Tests Passed 100%!
    echo =====================================================================
) else (
    echo.
    echo =====================================================================
    echo  [FAILURE] Tests encountered an error. Check logs above.
    echo =====================================================================
)
pause
