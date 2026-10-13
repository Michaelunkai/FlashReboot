@echo off
rem ============================================================
rem  FlashReboot launcher - self-elevating, double-click ready.
rem  After every run it VERIFIES the taskbar and auto-repairs it
rem  if anything went wrong (permanent taskbar guarantee).
rem ============================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

title FlashReboot v1.0.1 (taskbar-safe)
cd /d "%~dp0"
echo.
echo   FlashReboot - every effect of a reboot, ready in seconds.
echo   (close this window to abort before it finishes)
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0FlashReboot.ps1" %*
set FR_EXIT=%errorlevel%

rem ---- TASKBAR VERIFY + AUTO-REPAIR (always runs) ----
echo.
echo   Verifying taskbar...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Verify-Taskbar.ps1"
set TB_EXIT=%errorlevel%

echo.
if "%FR_EXIT%"=="0" (
    echo   [READY] Flash reboot complete. Report: logs\report-*.txt
) else (
    echo   [EXIT %FR_EXIT%] see logs\ for the contained-failure details.
)
echo   [TASKBAR EXIT %TB_EXIT%]
echo.
pause
exit /b %FR_EXIT%
