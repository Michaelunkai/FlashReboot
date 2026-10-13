<#
.SYNOPSIS
    Taskbar verify + auto-repair. Exit 0 = taskbar (Shell_TrayWnd) alive.
    Called by Run-FlashReboot.cmd after every engine run; also safe standalone.
.DESCRIPTION
    If the taskbar window is missing, this script:
      1. guarantees Windows' shell auto-recovery (AutoRestartShell=1),
      2. kills any stray half-shell explorer instances,
      3. relaunches the shell via a one-shot Scheduled Task with the logged-on
         user's normal (non-elevated) token - never elevated,
      4. re-checks the taskbar window, up to 3 attempts.
#>
$ErrorActionPreference = 'SilentlyContinue'

function Test-Taskbar {
    try {
        Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class FrTbCheck {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindowW(string cls, string title);
}
'@ -ErrorAction SilentlyContinue
    } catch { }
    return ([FrTbCheck]::FindWindowW('Shell_TrayWnd', $null) -ne [IntPtr]::Zero)
}

if (Test-Taskbar) { Write-Host '   [TASKBAR OK]'; exit 0 }

Write-Host '   [TASKBAR MISSING - auto-repairing...]'
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $wl -Name AutoRestartShell -Value 1

$tn = 'FlashRebootTaskbarRepair'
for ($i = 1; $i -le 3; $i++) {
    Get-Process explorer | Stop-Process -Force
    Start-Sleep -Milliseconds 600
    & "$env:WINDIR\System32\schtasks.exe" /Create /TN $tn /TR "`"$env:WINDIR\explorer.exe`"" /SC ONCE /ST 00:00 /IT /F /RL LIMITED | Out-Null
    & "$env:WINDIR\System32\schtasks.exe" /Run /TN $tn | Out-Null
    & "$env:WINDIR\System32\schtasks.exe" /Delete /TN $tn /F | Out-Null
    $deadline = [DateTime]::UtcNow.AddSeconds(8)
    while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Taskbar)) { Start-Sleep -Milliseconds 300 }
    if (Test-Taskbar) { Write-Host "   [TASKBAR REPAIRED] (attempt $i)"; exit 0 }
}

Write-Host '   [TASKBAR REPAIR FAILED] - open Task Manager > File > Run new task > explorer.exe'
exit 1
