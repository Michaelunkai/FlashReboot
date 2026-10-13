<#
.SYNOPSIS
    Deep taskbar verify + auto-repair. Exit 0 = taskbar genuinely healthy:
    window exists, ANSWERS messages (not hung), Start menu host running.
    Called by Run-FlashReboot.cmd after every engine run; also safe standalone.
.DESCRIPTION
    Repair ladder:
      1. Broadcast TaskbarCreated -> every app re-registers its tray icon.
      2. If still unhealthy: guarantee AutoRestartShell=1, kill stray
         half-shell explorers, relaunch the shell via a one-shot Scheduled
         Task with the logged-on user's normal (non-elevated) token,
         re-check, up to 3 attempts.
#>
$ErrorActionPreference = 'SilentlyContinue'

try {
    Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class FrTbVerify {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindowW(string cls, string title);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(IntPtr h, uint msg, UIntPtr w, IntPtr l, uint flags, uint timeout, out UIntPtr result);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern uint RegisterWindowMessageW(string name);
}
'@ -ErrorAction SilentlyContinue
} catch { }

function Test-Taskbar {
    $tb = [FrTbVerify]::FindWindowW('Shell_TrayWnd', $null)
    if ($tb -eq [IntPtr]::Zero) { return $false }
    $res = [UIntPtr]::Zero
    $answered = ([FrTbVerify]::SendMessageTimeout($tb, 0, [UIntPtr]::Zero, [IntPtr]::Zero, 0x0008, 2000, [ref]$res) -ne [IntPtr]::Zero)
    $startHost = [bool](Get-Process -Name StartMenuExperienceHost)
    return ($answered -and $startHost)
}

function Restore-Tray {
    $msg = [FrTbVerify]::RegisterWindowMessageW('TaskbarCreated')
    foreach ($pass in 1..2) {
        $res = [UIntPtr]::Zero
        [void][FrTbVerify]::SendMessageTimeout([IntPtr]0xFFFF, $msg, [UIntPtr]::Zero, [IntPtr]::Zero, 0x0008, 2000, [ref]$res)
        Start-Sleep -Milliseconds 300
    }
}

if (Test-Taskbar) {
    Restore-Tray
    if (Test-Taskbar) { Write-Host '   [TASKBAR OK]'; exit 0 }
}

Write-Host '   [TASKBAR NOT HEALTHY - repairing...]'
Restore-Tray
$deadline = [DateTime]::UtcNow.AddSeconds(5)
while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Taskbar)) { Start-Sleep -Milliseconds 300 }
if (Test-Taskbar) { Write-Host '   [TASKBAR RESTORED] (tray re-registration)'; exit 0 }

$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $wl -Name AutoRestartShell -Value 1

$tn = 'FlashRebootTaskbarRepair'
for ($i = 1; $i -le 3; $i++) {
    Get-Process explorer | Stop-Process -Force
    Start-Sleep -Milliseconds 600
    & "$env:WINDIR\System32\schtasks.exe" /Create /TN $tn /TR "`"$env:WINDIR\explorer.exe`"" /SC ONCE /ST 00:00 /IT /F /RL LIMITED | Out-Null
    & "$env:WINDIR\System32\schtasks.exe" /Run /TN $tn | Out-Null
    & "$env:WINDIR\System32\schtasks.exe" /Delete /TN $tn /F | Out-Null
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Taskbar)) { Start-Sleep -Milliseconds 300 }
    if (Test-Taskbar) {
        Restore-Tray
        if (Test-Taskbar) { Write-Host "   [TASKBAR REPAIRED] (attempt $i)"; exit 0 }
    }
}

Write-Host '   [TASKBAR REPAIR FAILED] - open Task Manager > File > Run new task > explorer.exe'
exit 1
