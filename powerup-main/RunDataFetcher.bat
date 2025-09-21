@echo off
echo Microsoft Tenant Data Fetcher
echo ============================
echo.

REM Check if PowerShell is available
powershell -Command "Get-Host" >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: PowerShell is not available or not in PATH
    pause
    exit /b 1
)

REM Run the PowerShell script
echo Starting data fetch...
powershell -ExecutionPolicy Bypass -File "MicrosoftTenantDataFetcher.ps1" %*

echo.
echo Data fetch completed. Check the output directory for results.
pause
