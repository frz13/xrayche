@echo off
setlocal
cd /d "%~dp0"
title XrayHub - Local developer build

echo ========================================
echo       XRAYHUB - LOCAL BUILD ONLY
echo ========================================
echo.
where dotnet >nul 2>&1
if errorlevel 1 (
    echo This script is only for developers building from source locally.
    echo You do NOT need to install .NET SDK just to use XrayHub.
    echo.
    echo To obtain a ready-to-run package without installing SDK,
    echo follow BUILD_WITHOUT_INSTALLING.md and use GitHub Actions.
    echo.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1"
if errorlevel 1 (
    echo.
    echo Local build failed. See the error above.
    pause
    exit /b 1
)

echo.
echo Build completed.
pause
