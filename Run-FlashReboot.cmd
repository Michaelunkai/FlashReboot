@echo off
setlocal
rem ============================================================
rem  FlashReboot launcher - self-elevating, silent finish.
rem  Flow: engine -> taskbar verify+repair -> dddesk (desktop
rem  reset via DesktopOrganizer) -> straight back to the shell.
rem ============================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" >nul 2>&1
    exit /b
)

title FlashReboot
cd /d "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0FlashReboot.ps1" %*
set FR_EXIT=%errorlevel%

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Verify-Taskbar.ps1"

rem very last command before going back to the shell: dddesk
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ddesk.ps1"

exit /b %FR_EXIT%
