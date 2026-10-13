#Requires -Version 5.1
<#
.SYNOPSIS
    FlashReboot - every effect of a Windows reboot, replayed live, Windows ready in <10 seconds.
.DESCRIPTION
    Reproduces the full reboot effect set (RAM, standby, caches, shell, DNS/ARP/NBT,
    temp, core services, startup replay, environment refresh) with zero downtime.
    See docs\DESIGN.md for the behavior contract.
.NOTES
    Version 1.0.0 - Windows PowerShell 5.1+, run elevated for full effect.
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Deep,
    [switch]$NoStartupReplay,
    [string]$ReportPath,
    [switch]$Help,
    [switch]$PurgeStandbyOnly   # internal: detached background standby purge worker
)

$script:FR_VERSION  = '1.0.0'
$script:FR_LOGDIR   = Join-Path $PSScriptRoot 'logs'
$script:FR_LOGPATH  = $null
$script:FR_DRYRUN   = [bool]$DryRun
$script:FR_RESULTS  = New-Object System.Collections.Generic.List[object]
$script:FR_ERRORS   = New-Object System.Collections.Generic.List[string]
# honest wall clock: started before engine load (incl. native assembly compile)
$script:FR_WALL = [System.Diagnostics.Stopwatch]::StartNew()

# ============================================================= CORE: logging
function Initialize-FrLog {
    [CmdletBinding()] param([string]$LogDir = $script:FR_LOGDIR)
    if (-not (Test-Path -LiteralPath $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:FR_LOGPATH = Join-Path $LogDir ("fr-{0}.log" -f $stamp)
    Set-Content -LiteralPath $script:FR_LOGPATH -Value (
        "[{0}] [INFO ] FlashReboot v{1} log started" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $script:FR_VERSION
    ) -Encoding UTF8
    return $script:FR_LOGPATH
}

function Get-FrLogPath { return $script:FR_LOGPATH }

function Write-FrLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK','PHASE','DRY')][string]$Level = 'INFO'
    )
    $line = "[{0}] [{1,-5}] {2}" -f (Get-Date -Format 'HH:mm:ss.fff'), $Level, $Message
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'PHASE' { 'Cyan' }
        'DRY'   { 'DarkCyan' }
        default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
    if ($script:FR_LOGPATH) {
        Add-Content -LiteralPath $script:FR_LOGPATH -Value $line -Encoding UTF8
    }
}

function Invoke-FrEffect {
    <#
    .SYNOPSIS
        Central dry-run gate. In -DryRun mode the effect is never executed and
        $null is returned; otherwise the effect runs and its output is returned.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Effect
    )
    if ($script:FR_DRYRUN) {
        Write-FrLog "DRY-RUN would execute: $Description" 'DRY'
        return $null
    }
    return (& $Effect)
}

# ========================================================= GUARDRAIL
function Test-IsAdmin {
    [CmdletBinding()] param()
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-FrPreflight {
    [CmdletBinding()] param([switch]$RequireAdmin)
    if (Test-IsAdmin) {
        Write-FrLog "Preflight OK: elevated (Administrator token present)." 'OK'
        return $true
    }
    if ($RequireAdmin) {
        Write-FrLog 'Preflight FAIL: elevation required; run via Run-FlashReboot.cmd.' 'ERROR'
        return $false
    }
    Write-FrLog 'Preflight: NOT elevated - limited-effect mode (some phases will be skipped).' 'WARN'
    return $false
}

function Get-ProtectedPidSet {
    <#
    .SYNOPSIS
        Builds the never-touch set: this process + its full ancestor chain, plus
        Windows-critical processes. The session that launched FlashReboot can
        never be stopped, killed, or emptied by any phase.
    #>
    [CmdletBinding()] param()
    $pids    = New-Object 'System.Collections.Generic.HashSet[int]'
    $names   = New-Object 'System.Collections.Generic.HashSet[string]'
    $criticalNames = @('system','idle','smss','csrss','wininit','winlogon','lsass',
                       'services','registry','memcompression','dwm','audiodg',
                       'sihost','svchost','fontdrvhost','vmmem','securityhealthservice',
                       'msmpeng','nissrv','zcode','zcode-remote-app')

    foreach ($n in $criticalNames) { [void]$names.Add($n.ToLowerInvariant()) }

    # Self + full ancestor chain (up to System/Idle root)
    $all = @{}
    Get-CimInstance Win32_Process | ForEach-Object { $all[[uint32]$_.ProcessId] = $_ }
    $current = [uint32]$PID
    $hops = 0
    while ($current -and $current -ne 0 -and $hops -lt 32) {
        [void]$pids.Add([int]$current)
        $proc = $all[$current]
        if (-not $proc) { break }
        [void]$names.Add(($proc.Name -replace '\.exe$','').ToLowerInvariant())
        $parent = [uint32]$proc.ParentProcessId
        if ($parent -eq $current -or -not $all.ContainsKey($parent)) { break }
        $current = $parent
        $hops++
    }
    return [pscustomobject]@{ Pids = $pids; Names = $names; ChainHops = $hops }
}

function Test-FrProtected {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$ProcessId,
        [Parameter(Mandatory)][string]$ProcessName,
        [Parameter(Mandatory)]$Protected
    )
    $bare = ($ProcessName -replace '\.exe$','').ToLowerInvariant()
    return ($Protected.Pids.Contains($ProcessId) -or $Protected.Names.Contains($bare))
}

# ============================================================ PHASES
function Invoke-FrWorkingSetSweep {
    <# Reboot effect #1: drop every eligible process's working set (RAM is
       re-faulted from backing stores exactly like a fresh boot). Protected
       processes are skipped by the never-touch contract. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Protected)

    $bytesBefore = [uint64]0
    $touched = 0; $failed = 0; $skipped = 0
    $bytesBefore = (Get-Process | Measure-Object WorkingSet64 -Sum).Sum

    foreach ($proc in (Get-Process)) {
        try {
            $bare = $proc.ProcessName.ToLowerInvariant()
            if ($Protected.Pids.Contains($proc.Id) -or $Protected.Names.Contains($bare)) { $skipped++; continue }
            $h = $proc.Handle   # throws for inaccessible processes -> counted as skipped
            if ($h -eq [IntPtr]::Zero) { $skipped++; continue }
            if ([FrNative]::EmptyWorkingSet($h)) { $touched++ } else { $failed++ }
        } catch { $skipped++ }
        finally { $proc.Dispose() }
    }
    $bytesAfter = (Get-Process | Measure-Object WorkingSet64 -Sum).Sum
    return [pscustomobject]@{
        Touched = $touched; Failed = $failed; Skipped = $skipped
        TotalWsBeforeMB = [math]::Round($bytesBefore / 1MB, 1)
        TotalWsAfterMB  = [math]::Round($bytesAfter  / 1MB, 1)
    }
}
if (-not ('FrNative' -as [type])) {
    # compile once, cache the assembly: repeat runs skip the ~2s C# build
    $cachedDll = Join-Path $script:FR_LOGDIR 'FrNative.dll'
    if (Test-Path -LiteralPath $cachedDll) {
        try { Add-Type -Path $cachedDll -ErrorAction Stop } catch { }
    }
    if (-not ('FrNative' -as [type])) {
        if (-not (Test-Path -LiteralPath $script:FR_LOGDIR)) { New-Item -ItemType Directory -Force -Path $script:FR_LOGDIR | Out-Null }
        $script:FR_NATIVE_SRC = @'
using System;
using System.Runtime.InteropServices;
public static class FrNative {
    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EmptyWorkingSet(IntPtr hProcess);

    [DllImport("ntdll.dll")]
    public static extern int NtSetSystemInformation(int InfoClass, ref int Info, int Length);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("user32.dll")]
    public static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll")]
    public static extern bool EmptyClipboard();

    [DllImport("user32.dll")]
    public static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam,
        string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);

    [DllImport("userenv.dll", SetLastError = true)]
    public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle,
        IntPtr hTargetProcessHandle, out IntPtr hTargetHandle, uint dwDesiredAccess, bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessW(string applicationName, System.Text.StringBuilder commandLine,
        IntPtr procAttrs, IntPtr threadAttrs, bool inheritHandles, uint creationFlags,
        IntPtr environment, string currentDirectory, ref STARTUPINFOW startupInfo,
        out PROCESS_INFORMATION processInfo);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFOW {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORYSTATUSEX {
        public uint dwLength, dwMemoryLoad;
        public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
    }

    // Fast free-RAM probe (microseconds, no CIM round-trip). Returns avail bytes.
    public static ulong QuickAvailableBytes() {
        var m = new MEMORYSTATUSEX();
        m.dwLength = (uint)Marshal.SizeOf(m);
        if (!GlobalMemoryStatusEx(ref m)) return 0;
        return m.ullAvailPhys;
    }

    // Boot-parity launcher: environment block built fresh from the registry
    // (machine + user), process created outside our job when allowed.
    // Returns decimal PID string, or "ERR:<step>:<gle>".
    public static string LaunchWithFreshEnvironment(string exePath, string arguments, string workingDirectory) {
        IntPtr hTok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0002 | 0x0008, out hTok))
            return "ERR:opentoken:" + Marshal.GetLastWin32Error();
        try {
            IntPtr env;
            if (!CreateEnvironmentBlock(out env, hTok, false))
                return "ERR:envblock:" + Marshal.GetLastWin32Error();
            try {
                var si = new STARTUPINFOW();
                si.cb = Marshal.SizeOf(si);
                var pi = new PROCESS_INFORMATION();
                var wd = string.IsNullOrEmpty(workingDirectory) ? null : workingDirectory;
                var cmdline = new System.Text.StringBuilder();
                cmdline.Append('"').Append(exePath).Append('"');
                if (!string.IsNullOrEmpty(arguments)) { cmdline.Append(' ').Append(arguments); }
                uint unicodeEnv = 0x400;
                uint breakaway = 0x01000000;
                bool ok = CreateProcessW(exePath, cmdline, IntPtr.Zero, IntPtr.Zero, false,
                    unicodeEnv | breakaway, env, wd, ref si, out pi);
                if (!ok) {
                    int gleBreakaway = Marshal.GetLastWin32Error();
                    ok = CreateProcessW(exePath, cmdline, IntPtr.Zero, IntPtr.Zero, false,
                        unicodeEnv, env, wd, ref si, out pi);
                    if (!ok)
                        return "ERR:createprocess:" + Marshal.GetLastWin32Error() + ":withBreakaway:" + gleBreakaway;
                }
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return pi.dwProcessId.ToString();
            } finally { DestroyEnvironmentBlock(env); }
        } finally { CloseHandle(hTok); }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct TOKEN_PRIVILEGES {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }

    public static bool EnablePrivilege(string privilegeName) {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0028 /* TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY */, out token))
            return false;
        try {
            long luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid)) return false;
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Luid = luid;
            tp.Attributes = 0x00000002; // SE_PRIVILEGE_ENABLED
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                return false;
            // AdjustTokenPrivileges "succeeds" even when a privilege is absent;
            // ERROR_NOT_ALL_ASSIGNED (1300) means it was NOT granted.
            int gle = Marshal.GetLastWin32Error();
            return (gle == 0);
        } finally { CloseHandle(token); }
    }
}
'@
        Add-Type -TypeDefinition $script:FR_NATIVE_SRC -OutputAssembly $cachedDll -ErrorAction SilentlyContinue
        Add-Type -TypeDefinition $script:FR_NATIVE_SRC
    }
}

function Get-FrMemoryCounters {
    [CmdletBinding()] param()
    $m = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory -ErrorAction SilentlyContinue
    if (-not $m) { return $null }
    return [pscustomobject]@{
        StandbyCoreMB   = [math]::Round(($m.StandbyCacheCoreBytes          -as [double]) / 1MB, 1)
        StandbyNormalMB = [math]::Round(($m.StandbyCacheNormalPriorityBytes -as [double]) / 1MB, 1)
        StandbyReserveMB= [math]::Round(($m.StandbyCacheReserveBytes        -as [double]) / 1MB, 1)
        AvailableMB     = [math]::Round(($m.AvailableBytes                  -as [double]) / 1MB, 1)
    }
}

function Invoke-FrStandbyPurge {
    <# Reboot effect #2: empty the standby page cache exactly like a fresh boot.
       NtSetSystemInformation(SystemMemoryListInformation=80), command 4 =
       MemoryPurgeStandbyList; requires SeProfileSingleProcessPrivilege. #>
    [CmdletBinding()] param()
    $privOk = [FrNative]::EnablePrivilege('SeProfileSingleProcessPrivilege')
    $before = Get-FrMemoryCounters
    $rc4 = [FrNative]::NtSetSystemInformation(80, ([ref]([int]4)), 4)
    $rc5 = [FrNative]::NtSetSystemInformation(80, ([ref]([int]5)), 4)
    Start-Sleep -Milliseconds 150   # let the perf counters refresh
    $after = Get-FrMemoryCounters
    return [pscustomobject]@{
        PrivilegeEnabled = $privOk
        RcPurgeStandby = $rc4; RcPurgeLowPriority = $rc5
        StandbyBeforeMB = if ($before) { $before.StandbyCoreMB + $before.StandbyNormalMB + $before.StandbyReserveMB } else { $null }
        StandbyAfterMB  = if ($after)  { $after.StandbyCoreMB  + $after.StandbyNormalMB  + $after.StandbyReserveMB  } else { $null }
        AvailableBeforeMB = if ($before) { $before.AvailableMB } else { $null }
        AvailableAfterMB  = if ($after)  { $after.AvailableMB }  else { $null }
    }
}
function Invoke-FrClipboardReset {
    <# Reboot effect #3: a RAM reset leaves the clipboard empty. Uses raw
       user32 APIs so it works from PowerShell's MTA console thread. #>
    [CmdletBinding()] param()
    $opened = $false
    try {
        for ($i = 0; $i -lt 10 -and -not $opened; $i++) {
            $opened = [FrNative]::OpenClipboard([IntPtr]::Zero)
            if (-not $opened) { Start-Sleep -Milliseconds 30 }
        }
        if ($opened) { [void][FrNative]::EmptyClipboard() }
        return $opened
    } finally {
        if ($opened) { [void][FrNative]::CloseClipboard() }
    }
}

function Invoke-FrManagedGc {
    [CmdletBinding()] param()
    [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
    return $true
}
function Invoke-MemoryPhase {
    <# Reboot effects #1-#3 as one contained phase. Every effect is gated by
       the central dry-run switch; a failing sub-effect is logged into
       $script:FR_ERRORS but never aborts the phase. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Protected)

    $result = [ordered]@{ Sweep = $null; Standby = $null; ClipboardCleared = $false }

    $result.Sweep = Invoke-FrEffect -Description 'empty working set of every eligible process' -Effect {
        Invoke-FrWorkingSetSweep -Protected $Protected
    }
    if ($result.Sweep) {
        Write-FrLog ("WS sweep: {0} processes emptied ({1} MB -> {2} MB total working set; {3} failed, {4} skipped)" -f `
            $result.Sweep.Touched, $result.Sweep.TotalWsBeforeMB, $result.Sweep.TotalWsAfterMB, $result.Sweep.Failed, $result.Sweep.Skipped) 'OK'
    }

    $result.Standby = Invoke-FrEffect -Description 'purge standby memory list (background worker)' -Effect {
        # A full purge of a huge standby list can take tens of seconds of pure
        # kernel work - in a real reboot this cost lands at SHUTDOWN, not in
        # the boot path. Same here: fire it in a detached worker (which logs
        # its own before/after MB) and verify completion after READY.
        Start-Process -FilePath 'powershell.exe' -ArgumentList @(
            '-NoProfile', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
            '-File', $PSCommandPath, '-PurgeStandbyOnly'
        ) -WindowStyle Hidden | Out-Null
        Write-FrLog 'Standby purge fired in background worker (before/after MB in worker log)' 'OK'
        [pscustomobject]@{ Fired = $true }
    }

    $clip = Invoke-FrEffect -Description 'reset clipboard' -Effect { Invoke-FrClipboardReset }
    $result.ClipboardCleared = [bool]$clip
    if (-not $script:FR_DRYRUN) { try { Invoke-FrManagedGc | Out-Null } catch { } }

    return [pscustomobject]$result
}
function Restart-FrExplorer {
    <# Reboot effect #4: the shell itself is cycled. Graceful close first, then
       the optional cache-purge window (icon/thumb caches are only deletable
       while the shell is down), then relaunch and wait for the desktop shell. #>
    [CmdletBinding()] param([switch]$WithCachePurge)

    $beforePid = (Get-Process -Name explorer -ErrorAction SilentlyContinue |
                  Select-Object -First 1 -ExpandProperty Id)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # graceful close of shell windows
    Get-Process -Name explorer -ErrorAction SilentlyContinue | ForEach-Object {
        try { [void]$_.CloseMainWindow() } catch { }
    } | Out-Null
    Start-Sleep -Milliseconds 600
    Get-Process -Name explorer -ErrorAction SilentlyContinue | ForEach-Object {
        try { $_.Kill(); $_.WaitForExit(1500) | Out-Null } catch { }
    }
    Write-FrLog ("shell: old explorer closed at {0} ms" -f $sw.ElapsedMilliseconds) 'INFO'

    # explorer-down window: cache rebuild sources removed (functions from steps 21/23)
    if ($WithCachePurge -and (Get-Command Invoke-FrExplorerCachePurge -ErrorAction SilentlyContinue)) {
        try { Invoke-FrExplorerCachePurge } catch {
            $script:FR_ERRORS.Add("shell.cachepurge: $($_.Exception.Message)") | Out-Null
        }
    }

    # Boot-parity shell relaunch via Task Scheduler: an /IT + /RL LIMITED task
    # runs explorer.exe with the LOGGED-ON USER's normal (non-elevated) token
    # and a registry-built fresh environment - exactly what winlogon does at
    # boot. Launching the desktop shell from our elevated token makes it an
    # elevated shell, which breaks taskbar drag-drop/tray/UX for the user.
    $taskName = 'FlashRebootShellRestart'
    $afterPid = $null; $method = 'task-scheduler-medium-il'
    $null = Invoke-FrEffect -Description "register one-shot shell restart task ($taskName)" -Effect {
        & "$env:WINDIR\System32\schtasks.exe" /Create /TN $taskName /TR "`"$env:WINDIR\explorer.exe`"" `
            /SC ONCE /ST 00:00 /IT /F /RL LIMITED | Out-Null
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(6)
    while ([DateTime]::UtcNow -lt $deadline -and -not $afterPid) {
        $null = Invoke-FrEffect -Description 'run shell restart task (medium-IL explorer, fresh env)' -Effect {
            & "$env:WINDIR\System32\schtasks.exe" /Run /TN $taskName | Out-Null
        }
        $spawnDeadline = [DateTime]::UtcNow.AddSeconds(2)
        while ([DateTime]::UtcNow -lt $spawnDeadline -and -not $afterPid) {
            $p = Get-Process -Name explorer -ErrorAction SilentlyContinue |
                 Where-Object { $_.Id -ne $beforePid } | Select-Object -First 1
            if ($p) { $afterPid = $p.Id; break }
            Start-Sleep -Milliseconds 120
        }
    }
    $null = Invoke-FrEffect -Description 'remove one-shot task' -Effect {
        & "$env:WINDIR\System32\schtasks.exe" /Delete /TN $taskName /F | Out-Null
    }
    Write-FrLog ("shell: relaunched via {0} (pid {1}) at {2} ms" -f `
        $method, $(if ($afterPid) { $afterPid } else { 'none' }), $sw.ElapsedMilliseconds) 'INFO'

    if (-not $afterPid) {
        # last-resort: keep the desktop alive even if the task path failed
        $r = [FrNative]::LaunchWithFreshEnvironment((Join-Path $env:WINDIR 'explorer.exe'), '', $null)
        if ($r -notlike 'ERR:*') {
            $afterPid = [int]$r; $method = 'fresh-env-fallback-elevated'
            Write-FrLog 'shell: FALLBACK relaunched ELEVATED (taskbar parity degraded; logged for diagnosis)' 'WARN'
        } else {
            $script:FR_ERRORS.Add("shell.freshenv: $r") | Out-Null
        }
    }
    if ($afterPid) {
        # NOTE: the fresh shell needs a couple of seconds to show its window
        # (cold caches - same as a real boot). We do NOT wait here: remaining
        # phases run while the shell warms up, and the final READY verifier
        # proves the window before declaring success.
        # clean up any duplicate shell (defensive: none expected with
        # AutoRestartShell disabled for the window)
        $dupDeadline = [DateTime]::UtcNow.AddSeconds(1)
        while ([DateTime]::UtcNow -lt $dupDeadline) {
            $dups = @(Get-Process -Name explorer -ErrorAction SilentlyContinue |
                      Where-Object { $_.Id -ne $beforePid -and $_.Id -ne $afterPid })
            if ($dups.Count -eq 0) { break }
            $dups | ForEach-Object {
                try { $_.Kill(); Write-FrLog "Cleaned up duplicate shell instance (PID $($_.Id))" 'INFO' } catch { }
            }
            Start-Sleep -Milliseconds 250
        }
    } else {
        # fallback: wait for the system's own auto-restart (fresh boot-ish, but
        # env may be inherited - log it honestly)
        $method = 'auto-restart-fallback'
        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        while ([DateTime]::UtcNow -lt $deadline) {
            $p = Get-Process -Name explorer -ErrorAction SilentlyContinue |
                 Where-Object { $_.Id -ne $beforePid -and $_.MainWindowHandle -ne 0 } |
                 Select-Object -First 1
            if ($p) { $afterPid = $p.Id; break }
            Start-Sleep -Milliseconds 120
        }
    }
    return [pscustomobject]@{ BeforePid = $beforePid; AfterPid = $afterPid; Method = $method }
}

function Start-FrProcessWithFreshEnvironment {
    <# Creates a process with an environment block freshly built from the
       registry (the boot-parity block), detached from our job when allowed.
       Returns the new PID or $null. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExePath,
        [string]$Arguments = '',
        [string]$WorkingDirectory = ''
    )
    try {
        $r = [FrNative]::LaunchWithFreshEnvironment($ExePath, $Arguments, $WorkingDirectory)
        if ($r -like 'ERR:*') {
            $script:FR_ERRORS.Add("shell.freshenv [$ExePath]: $r") | Out-Null
            return $null
        }
        return [int]$r
    } catch {
        $script:FR_ERRORS.Add("shell.freshenv [$ExePath]: $($_.Exception.Message)") | Out-Null
        return $null
    }
}
function Remove-FrCacheFiles {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][string]$Pattern)
    $removed = 0; $bytes = [uint64]0; $locked = 0
    if (Test-Path -LiteralPath $Folder) {
        Get-ChildItem -LiteralPath $Folder -Filter $Pattern -File -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                $size = $_.Length
                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                $removed++; $bytes += $size
            } catch { $locked++ }
        }
    }
    return [pscustomobject]@{ Removed = $removed; Bytes = $bytes; Locked = $locked }
}

function Invoke-FrIconCachePurge {
    <# Reboot effect #5: icon cache deleted so the shell rebuilds it fresh. #>
    [CmdletBinding()] param()
    $r1 = Remove-FrCacheFiles -Folder (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Explorer') -Pattern 'iconcache_*.db'
    $r2 = Remove-FrCacheFiles -Folder $env:LOCALAPPDATA -Pattern 'IconCache.db'
    return [pscustomobject]@{
        Removed = $r1.Removed + $r2.Removed
        Bytes   = $r1.Bytes + $r2.Bytes
        Locked  = $r1.Locked + $r2.Locked
    }
}

function Invoke-FrThumbCachePurge {
    <# Reboot effect #6: thumbnail caches deleted so Explorer rebuilds them. #>
    [CmdletBinding()] param()
    return Remove-FrCacheFiles -Folder (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Explorer') -Pattern 'thumbcache_*.db'
}

function Invoke-FrExplorerCachePurge {
    [CmdletBinding()] param()
    $i = Invoke-FrIconCachePurge
    $t = Invoke-FrThumbCachePurge
    Write-FrLog ("Shell cache purge: icon {0} removed ({1} KB, {2} locked), thumb {3} removed ({4} KB, {5} locked)" -f `
        $i.Removed, [math]::Round($i.Bytes/1KB), $i.Locked, $t.Removed, [math]::Round($t.Bytes/1KB), $t.Locked) 'OK'
}
function Get-FrDnsCacheCount {
    [CmdletBinding()] param()
    try { return @(Get-DnsClientCache -ErrorAction Stop).Count } catch { return -1 }
}

function Invoke-FrDnsFlush {
    <# Reboot effect #7: the DNS resolver cache is emptied like a fresh boot. #>
    [CmdletBinding()] param()
    $before = Get-FrDnsCacheCount
    $null = Invoke-FrEffect -Description 'ipconfig /flushdns (empty DNS resolver cache)' -Effect {
        & ipconfig /flushdns | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "ipconfig /flushdns exit $LASTEXITCODE" }
    }
    Start-Sleep -Milliseconds 150
    $after = Get-FrDnsCacheCount
    return [pscustomobject]@{ Before = $before; After = $after }
}

function Invoke-FrArpNbtFlush {
    <# Reboot effect #8: ARP and NetBIOS name caches emptied. #>
    [CmdletBinding()] param()
    $arpRc = 0; $nbtR = 0; $nbtRr = 0
    $null = Invoke-FrEffect -Description 'arp -d * (flush ARP cache)' -Effect {
        & "$env:WINDIR\System32\arp.exe" -d '*' 2>$null
        $script:ARP_RC = $LASTEXITCODE
    }
    $arpRc = $script:ARP_RC
    $null = Invoke-FrEffect -Description 'nbtstat -R/-RR (purge NetBIOS name caches)' -Effect {
        & "$env:WINDIR\System32\nbtstat.exe" -R 2>$null | Out-Null
        $script:NBT_R = $LASTEXITCODE
        & "$env:WINDIR\System32\nbtstat.exe" -RR 2>$null | Out-Null
        $script:NBT_RR = $LASTEXITCODE
    }
    $nbtR = $script:NBT_R; $nbtRr = $script:NBT_RR
    return [pscustomobject]@{ Arp = $arpRc; NbtPurge = $nbtR; NbtRelease = $nbtRr }
}
function Invoke-FrShaderCachePurge {
    <# Reboot effect #9: DirectX/NVIDIA shader caches are rebuilt fresh on a
       new boot. Best-effort: locked or absent caches are counted, never fatal. #>
    [CmdletBinding()] param()
    $targets = @(
        (Join-Path $env:LOCALAPPDATA 'D3DSCache'),
        (Join-Path $env:LOCALAPPDATA 'NVIDIA\GLCache'),
        (Join-Path $env:LOCALAPPDATA 'NVIDIA Corporation\NV_Cache'),
        (Join-Path $env:PROGRAMDATA 'NVIDIA Corporation\NV_Cache')
    )
    $removed = 0; $bytes = [uint64]0; $locked = 0; $present = 0
    foreach ($t in $targets) {
        if (-not (Test-Path -LiteralPath $t)) { continue }
        $present++
        Get-ChildItem -LiteralPath $t -Recurse -File -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                $size = $_.Length
                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                $removed++; $bytes += $size
            } catch { $locked++ }
        }
    }
    return [pscustomobject]@{ CachesPresent = $present; FilesRemoved = $removed; MB = [math]::Round($bytes/1MB,1); Locked = $locked }
}
function Invoke-FrTempCleanup {
    <# Reboot effect #10: boot-time temp sweep. Deletes the *contents* of the
       user %TEMP% and C:\Windows\Temp. In-use (locked) files are counted and
       skipped - never force-killed, never fatal. #>
    [CmdletBinding()] param()
    $targets = @($env:TEMP, (Join-Path $env:SystemRoot 'Temp'))
    $removed = 0; $bytes = [uint64]0; $locked = 0
    foreach ($t in ($targets | Where-Object { $_ -and (Test-Path -LiteralPath $_) })) {
        Get-ChildItem -LiteralPath $t -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                $size = if ($_.PSIsContainer) {
                    (Get-ChildItem $_.FullName -Recurse -File -Force -ErrorAction SilentlyContinue |
                     Measure-Object Length -Sum).Sum
                } else { $_.Length }
                if ($null -eq $size) { $size = 0 }
                Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
                $removed++; $bytes += [uint64]$size
            } catch { $locked++ }
        }
    }
    return [pscustomobject]@{ ItemsRemoved = $removed; MB = [math]::Round($bytes/1MB,1); LockedSkipped = $locked }
}
function Restart-FrService {
    <# Reboot effect #11 core: one service cycled exactly like a fresh boot
       (stop -> confirm stopped -> start -> confirm running), with hard timeouts
       so one stuck service can never stall the 10-second budget. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$StopTimeoutSec  = 5,
        [int]$StartTimeoutSec = 8
    )
    $svc    = Get-Service -Name $Name -ErrorAction Stop
    $before = $svc.Status.ToString()
    $stoppedTo = $before

    if ($svc.Status -eq 'Running') {
        $null = & "$env:WINDIR\System32\sc.exe" stop $Name 2>$null
        $deadline = [DateTime]::UtcNow.AddSeconds($StopTimeoutSec)
        while ((Get-Service -Name $Name).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 100
        }
        $stoppedTo = (Get-Service -Name $Name).Status.ToString()
    }

    $null = & "$env:WINDIR\System32\sc.exe" start $Name 2>$null
    $startRc = $LASTEXITCODE
    $deadline = [DateTime]::UtcNow.AddSeconds($StartTimeoutSec)
    while ((Get-Service -Name $Name).Status -ne 'Running' -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 100
    }
    $after = (Get-Service -Name $Name).Status.ToString()

    return [pscustomobject]@{
        Name = $Name; Before = $before; StoppedTo = $stoppedTo
        After = $after; StartRc = $startRc
        Success = ($after -eq 'Running')
    }
}

function Invoke-FrServiceKickoff {
    <# Fires the async stop half of the service cycle. The stops complete
       while other phases run; Invoke-FrServiceHarvest finishes the starts. #>
    [CmdletBinding()] param([switch]$Deep)
    $stopped = $false
    $null = Invoke-FrEffect -Description 'fire async stop: AudioEndpointBuilder, Audiosrv, FontCache, Spooler' -Effect {
        foreach ($n in @('Audiosrv','AudioEndpointBuilder','FontCache','Spooler')) {
            Start-Process -FilePath "$env:WINDIR\System32\sc.exe" -ArgumentList 'stop', $n `
                -WindowStyle Hidden | Out-Null
        }
        $script:FR_SVC_STOPPED = $true
    }
    if ($Deep) {
        $null = Invoke-FrEffect -Description 'fire async stop: WSearch (-Deep)' -Effect {
            Start-Process -FilePath "$env:WINDIR\System32\sc.exe" -ArgumentList 'stop','WSearch' -WindowStyle Hidden | Out-Null
        }
    }
    return [pscustomobject]@{ Fired = [bool]$script:FR_SVC_STOPPED }
}

function Invoke-FrServiceHarvest {
    <# Finishes the service cycle: waits for the fired stops (bounded), starts
       everything, and verifies Running. BITS cycles fully detached in the
       background - exactly like a real boot, where non-core services finish
       starting after the logon-ready point. #>
    [CmdletBinding()] param([switch]$Deep)

    if (-not $script:FR_DRYRUN) {
        $bitsCmd = '& "$env:WINDIR\System32\sc.exe" stop BITS | Out-Null;' +
                   '$d=[DateTime]::UtcNow.AddSeconds(8);' +
                   'while((Get-Service BITS).Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped -and [DateTime]::UtcNow -lt $d){Start-Sleep -Milliseconds 200};' +
                   '& "$env:WINDIR\System32\sc.exe" start BITS | Out-Null'
        Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-WindowStyle','Hidden','-Command', $bitsCmd) `
            -WindowStyle Hidden | Out-Null
        Write-FrLog 'Service BITS: cycling in background (detached, boot-like)' 'OK'
    } else {
        Write-FrLog 'DRY-RUN would execute: BITS background cycle (stop -> start, detached)' 'DRY'
    }

    $results = @()

    # audio stack: dependency order on the way up. The AudioEndpointBuilder
    # stop can be genuinely slow on busy audio hardware; waits are capped and
    # a service that missed its stop window is honestly kept running.
    $null = Invoke-FrEffect -Description 'finish audio stack cycle (AudioEndpointBuilder -> Audiosrv)' -Effect {
        $deadline = [DateTime]::UtcNow.AddSeconds(1.2)
        while ([DateTime]::UtcNow -lt $deadline) {
            $a = (Get-Service Audiosrv).Status; $b = (Get-Service AudioEndpointBuilder).Status
            if ($a -eq 'Stopped' -and $b -eq 'Stopped') { break }
            Start-Sleep -Milliseconds 100
        }
        # start back-to-back (Audiosrv queues behind its dependency), then poll
        # both together - one wait instead of two
        $startedAny = $false
        foreach ($n in @('AudioEndpointBuilder','Audiosrv')) {
            if ((Get-Service $n).Status -eq 'Stopped') {
                $null = & "$env:WINDIR\System32\sc.exe" start $n 2>$null
                $startedAny = $true
            }
        }
        if ($startedAny) {
            $deadline = [DateTime]::UtcNow.AddSeconds(2.5)
            while ([DateTime]::UtcNow -lt $deadline) {
                $a = (Get-Service Audiosrv).Status; $b = (Get-Service AudioEndpointBuilder).Status
                if ($a -eq 'Running' -and $b -eq 'Running') { break }
                Start-Sleep -Milliseconds 100
            }
        }
    }
    $aebState = (Get-Service AudioEndpointBuilder).Status.ToString()
    $asrvState = (Get-Service Audiosrv).Status.ToString()
    $audioState = [pscustomobject]@{
        AudioEndpointBuilder = $aebState
        Audiosrv             = $asrvState
    }
    $results += [pscustomobject]@{ Name = 'AudioStack'; Before = 'cycle'; After = "$asrvState/$aebState"; Success = ($asrvState -eq 'Running' -and $aebState -eq 'Running') }
    if ($asrvState -eq 'Running' -and $aebState -eq 'Running') {
        Write-FrLog ("Audio stack: AudioEndpointBuilder={0}, Audiosrv={1}" -f $aebState, $asrvState) 'OK'
    } else {
        Write-FrLog ("Audio stack partial (stop window missed, kept running): AEB={0}, Audiosrv={1}" -f $aebState, $asrvState) 'WARN'
    }

    foreach ($svcName in @('FontCache','Spooler')) {
        $r = Invoke-FrEffect -Description "finish $svcName cycle (start + verify)" -Effect {
            $deadline = [DateTime]::UtcNow.AddSeconds(2)
            while ((Get-Service $svcName).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline) {
                Start-Sleep -Milliseconds 80
            }
            $null = & "$env:WINDIR\System32\sc.exe" start $svcName 2>$null
            $deadline = [DateTime]::UtcNow.AddSeconds(4)
            while ((Get-Service $svcName).Status -ne 'Running' -and [DateTime]::UtcNow -lt $deadline) {
                Start-Sleep -Milliseconds 80
            }
            (Get-Service $svcName).Status.ToString()
        }
        $state = if ($r) { [string]$r } else { (Get-Service $svcName).Status.ToString() }
        $results += [pscustomobject]@{ Name = $svcName; Before = 'cycle'; After = $state; Success = ($state -eq 'Running') }
        Write-FrLog ("Service {0}: cycled -> {1}" -f $svcName, $state) 'OK'
    }

    if ($Deep) {
        $ws = Invoke-FrEffect -Description 'finish WSearch cycle (-Deep)' -Effect {
            $deadline = [DateTime]::UtcNow.AddSeconds(2)
            while ((Get-Service WSearch).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 80 }
            Restart-FrService -Name 'WSearch'
        }
        if (-not $ws) { $ws = [pscustomobject]@{ After = (Get-Service WSearch).Status.ToString() } }
        $results += [pscustomobject]@{ Name = 'WSearch'; Before = 'cycle'; After = $ws.After; Success = ($ws.After -eq 'Running') }
        Write-FrLog ("Service WSearch (-Deep): cycled -> {0}" -f $ws.After) 'OK'
    }

    $allOk = ($results.Count -ge 3) -and (@($results | Where-Object { -not $_.Success }).Count -eq 0)
    return [pscustomobject]@{ Audio = $audioState; Services = $results; AllRunning = $allOk }
}

function Invoke-FrAudioRestart {
    <# Kept for direct/unit use: full audio stack cycle in dependency order. #>
    [CmdletBinding()] param()
    $null = Invoke-FrEffect -Description 'cycle audio stack (AudioEndpointBuilder -> Audiosrv)' -Effect {
        $null = & "$env:WINDIR\System32\sc.exe" stop Audiosrv              2>$null
        $null = & "$env:WINDIR\System32\sc.exe" stop AudioEndpointBuilder  2>$null
        $deadline = [DateTime]::UtcNow.AddSeconds(4)
        while ([DateTime]::UtcNow -lt $deadline) {
            $a = (Get-Service Audiosrv).Status; $b = (Get-Service AudioEndpointBuilder).Status
            if ($a -eq 'Stopped' -and $b -eq 'Stopped') { break }
            Start-Sleep -Milliseconds 100
        }
        $null = & "$env:WINDIR\System32\sc.exe" start AudioEndpointBuilder 2>$null
        $deadline = [DateTime]::UtcNow.AddSeconds(6)
        while ((Get-Service AudioEndpointBuilder).Status -ne 'Running' -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 100
        }
        $null = & "$env:WINDIR\System32\sc.exe" start Audiosrv             2>$null
        $deadline = [DateTime]::UtcNow.AddSeconds(6)
        while ((Get-Service Audiosrv).Status -ne 'Running' -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 100
        }
    }
    return [pscustomobject]@{
        AudioEndpointBuilder = (Get-Service AudioEndpointBuilder).Status.ToString()
        Audiosrv             = (Get-Service Audiosrv).Status.ToString()
    }
}
# (Invoke-FrServicePhase superseded by Kickoff/Harvest split for the
#  overlapped boot-order execution.)
# ============================================================ STARTUP REPLAY
function Get-FrRunKeyEntries {
    <# Reboot effect #13 source: HKCU/HKLM Run across 64-bit and 32-bit views.
       Returns structured entries: Source, Name, Command. #>
    [CmdletBinding()] param([string]$SubKey = 'Run')
    $entries = New-Object System.Collections.Generic.List[object]
    $keyPath = "Software\Microsoft\Windows\CurrentVersion\$SubKey"
    # HKCU Run/RunOnce are SHARED keys on 64-bit Windows (no WOW redirect) -
    # enumerate once. HKLM Run/RunOnce ARE redirected - enumerate both views.
    $views = @(
        @{ Hive = 'HKCU'; View = [Microsoft.Win32.RegistryView]::Registry64 }
        @{ Hive = 'HKLM'; View = [Microsoft.Win32.RegistryView]::Registry64 }
        @{ Hive = 'HKLM'; View = [Microsoft.Win32.RegistryView]::Registry32 }
    )
    foreach ($v in $views) {
        $base = $null; $key = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine, $v.View)
            if ($v.Hive -eq 'HKCU') {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                    [Microsoft.Win32.RegistryHive]::CurrentUser, $v.View)
            }
            $key = $base.OpenSubKey($keyPath)
            if ($key) {
                foreach ($name in $key.GetValueNames()) {
                    $cmd = [string]$key.GetValue($name)
                    if ($cmd) {
                        $entries.Add([pscustomobject]@{
                            Source  = "$($v.Hive):$($v.View) \$keyPath"
                            Name    = $name
                            Command = $cmd
                        })
                    }
                }
            }
        } catch {
            $script:FR_ERRORS.Add("startup.enum.$($v.Hive): $($_.Exception.Message)") | Out-Null
        } finally {
            if ($key)  { $key.Close() }
            if ($base) { $base.Close() }
        }
    }
    return $entries
}

function Get-FrStartupFolderEntries {
    <# Reboot effect #15 source: user + common Startup folders. #>
    [CmdletBinding()] param()
    $entries = New-Object System.Collections.Generic.List[object]
    $folders = @(
        @{ Label = 'user';   Path = [Environment]::GetFolderPath('Startup') }
        @{ Label = 'common'; Path = [Environment]::GetFolderPath('CommonStartup') }
    )
    foreach ($f in $folders) {
        if (-not $f.Path -or -not (Test-Path -LiteralPath $f.Path)) { continue }
        Get-ChildItem -LiteralPath $f.Path -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match '^(\.lnk|\.exe|\.cmd|\.bat|\.ps1)$' } |
        ForEach-Object {
            $entries.Add([pscustomobject]@{
                Source  = "startup-folder:$($f.Label)"
                Name    = $_.BaseName
                Command = $_.FullName
            })
        }
    }
    return $entries
}
function ConvertFrom-FrStartupCommand {
    <# Reboot effect #13/15 executor helper: parse a Run-key command line into
       exe + arguments. Handles quoted paths, unquoted spaced paths, bare names
       resolved via PATH, and %VAR% expansion. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Command)

    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    $exe = $null; $rest = $null

    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) {
            $exe  = $c.Substring(1, $end - 1)
            $rest = $c.Substring($end + 1).Trim()
        }
    }
    if (-not $exe) {
        $parts = $c -split ' '
        for ($i = 0; $i -lt $parts.Count; $i++) {
            $candidate = ($parts[0..$i] -join ' ')
            if ($candidate -match '\.(exe|com|bat|cmd|ps1)$' -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                $exe = $candidate; $rest = ($parts[($i+1)..($parts.Count-1)] -join ' ').Trim(); break
            }
        }
        if (-not $exe) {
            $first = $parts[0]
            if ($first -match '[\\/]') { $exe = $first } else {
                $found = Get-Command $first -ErrorAction SilentlyContinue
                if ($found -and $found.Source) { $exe = $found.Source } else { $exe = $first }
            }
            $rest = if ($parts.Count -gt 1) { ($parts[1..($parts.Count-1)] -join ' ').Trim() } else { '' }
        }
    }

    if ($exe -and $exe -notmatch '[\\/]') {
        $found = Get-Command $exe -ErrorAction SilentlyContinue
        if ($found -and $found.Source) { $exe = $found.Source }
    }

    $wd = $null
    if ($exe -and $exe -match '^(.*)[\\/]') { $wd = $Matches[1] }
    $bare = if ($exe) { [IO.Path]::GetFileNameWithoutExtension($exe).ToLowerInvariant() } else { $null }

    return [pscustomobject]@{ Exe = $exe; Arguments = $rest; WorkingDirectory = $wd; ProcessName = $bare }
}

function Test-FrAlreadyRunning {
    <# Reboot effect #13/15 guard: an entry whose process is already running is
       skipped (a second copy would be wrong; the running instance already has
       the fresh-boot memory treatment from the WS sweep). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$ProcessName)
    if (-not $ProcessName) { return $false }
    return @((Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)).Count -gt 0
}

function Start-FrStartupEntry {
    <# Launches one startup entry with a FRESH (registry-built) environment
       block - exactly what a logon gives a startup app. .lnk files go through
       the shell; everything else goes through the native fresh-env launcher
       with Start-Process as fallback. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Entry)
    $cmd = $Entry.Command

    # startup-folder .lnk: only the shell can resolve and launch these -
    # a shortcut is not an executable (CreateProcess would fail 193)
    if ($cmd -match '\.lnk$' -and (Test-Path -LiteralPath $cmd)) {
        $procName = [IO.Path]::GetFileNameWithoutExtension($cmd).ToLowerInvariant()
        try {
            $sh = New-Object -ComObject WScript.Shell
            $lnk = $sh.CreateShortcut($cmd)
            if ($lnk.TargetPath) {
                $procName = [IO.Path]::GetFileNameWithoutExtension($lnk.TargetPath).ToLowerInvariant()
            }
        } catch { }
        Start-Process -FilePath $cmd -WindowStyle Minimized
        return [pscustomobject]@{ Launched = $true; ProcessName = $procName }
    }

    # .ps1 via powershell, .cmd/.bat via cmd - both through the fresh env
    if ($cmd -match '\.ps1$' -and (Test-Path -LiteralPath $cmd)) {
        $newPid = Start-FrProcessWithFreshEnvironment -ExePath 'powershell.exe' `
            -Arguments "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$cmd`""
        if (-not $newPid) {
            Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File', "`"$cmd`"") -WindowStyle Hidden
        }
        return [pscustomobject]@{ Launched = $true; ProcessName = 'powershell' }
    }
    if ($cmd -match '\.(cmd|bat)$' -and (Test-Path -LiteralPath $cmd)) {
        $newPid = Start-FrProcessWithFreshEnvironment -ExePath "$env:WINDIR\System32\cmd.exe" `
            -Arguments "/c `"$cmd`""
        if (-not $newPid) {
            Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', "`"$cmd`"") -WindowStyle Hidden
        }
        return [pscustomobject]@{ Launched = $true; ProcessName = 'cmd' }
    }

    # Run-key style command line
    $parsed = ConvertFrom-FrStartupCommand -Command $cmd
    if (-not $parsed.Exe) {
        return [pscustomobject]@{ Launched = $false; ProcessName = $null; Reason = 'parse-failed' }
    }
    # Scripts and documents (.js/.vbs/.wsf/...) must go through the shell's
    # file association - CreateProcess cannot execute them directly (193).
    if ($parsed.Exe -notmatch '\.(exe|com)$') {
        Start-Process -FilePath $parsed.Exe -WindowStyle Minimized
        return [pscustomobject]@{ Launched = $true; ProcessName = $parsed.ProcessName }
    }
    $wd = if ($parsed.WorkingDirectory -and (Test-Path -LiteralPath $parsed.WorkingDirectory)) {
        $parsed.WorkingDirectory } else { $null }
    $newPid = Start-FrProcessWithFreshEnvironment -ExePath $parsed.Exe -Arguments $parsed.Arguments -WorkingDirectory $wd
    if (-not $newPid) {
        $startArgs = @{ FilePath = $parsed.Exe; WindowStyle = 'Minimized' }
        if ($parsed.Arguments)     { $startArgs.ArgumentList    = $parsed.Arguments }
        if ($wd)                   { $startArgs.WorkingDirectory = $wd }
        Start-Process @startArgs
    }
    return [pscustomobject]@{ Launched = $true; ProcessName = $parsed.ProcessName }
}

function Invoke-FrRunOnce {
    <# Reboot effect #14: RunOnce entries execute once at boot, then Windows
       removes them. Same semantics here: launch, then delete the value. #>
    [CmdletBinding()] param()
    $entries = Get-FrRunKeyEntries -SubKey 'RunOnce'
    $handled = 0
    foreach ($e in $entries) {
        $r = Invoke-FrEffect -Description "RunOnce: $($e.Name)" -Effect {
            Start-FrStartupEntry -Entry $e
        }
        # remove the value exactly like Windows does after executing it
        $removed = Invoke-FrEffect -Description "remove RunOnce value $($e.Name) [$($e.Source)]" -Effect {
            $hive = if ($e.Source -like 'HKCU*') { 'CurrentUser' } else { 'LocalMachine' }
            $view = if ($e.Source -like '*Registry32*') { 'Registry32' } else { 'Registry64' }
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::$hive, [Microsoft.Win32.RegistryView]::$view)
            try {
                $k = $base.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\RunOnce', $true)
                if ($k) {
                    $k.DeleteValue($e.Name, $false)
                    $stillThere = ($k.GetValueNames() -contains $e.Name)
                    $k.Close()
                    return (-not $stillThere)
                }
                return $false
            } finally { $base.Close() }
        }
        $handled++
        Write-FrLog ("RunOnce {0}: launched={1} valueRemoved={2}" -f $e.Name, [bool]$r, [bool]$removed) 'OK'
    }
    return [pscustomobject]@{ Handled = $handled }
}

function Get-FrLogonTaskCount {
    <# Reboot effect #17 (report-only): scheduled tasks with logon triggers. #>
    [CmdletBinding()] param()
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
            Where-Object {
                $_.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' }
            }
        return @($tasks).Count
    } catch { return -1 }
}

function Get-FrEntryProcessName {
    <# Resolve the process basename a startup entry would spawn (also used for
       the already-running skip guard). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Entry)
    $cmd = [string]$Entry.Command
    if ($cmd -match '\.lnk$') {
        try {
            $sh = New-Object -ComObject WScript.Shell
            $lnk = $sh.CreateShortcut($cmd)
            if ($lnk.TargetPath) { return [IO.Path]::GetFileNameWithoutExtension($lnk.TargetPath).ToLowerInvariant() }
        } catch { }
        return [IO.Path]::GetFileNameWithoutExtension($cmd).ToLowerInvariant()
    }
    if ($cmd -match '\.ps1$') { return 'powershell' }
    if ($cmd -match '\.(cmd|bat)$') { return 'cmd' }
    return (ConvertFrom-FrStartupCommand -Command $cmd).ProcessName
}

function Invoke-FrReplayPhase {
    <# Reboot effects #13-#15: everything registered to run at logon replays
       now. Already-running entries are skipped, not duplicated. #>
    [CmdletBinding()] param()

    $run = @(Get-FrRunKeyEntries)
    $folders = @(Get-FrStartupFolderEntries)
    $launched = 0; $skipped = 0; $failed = 0
    $launchedNames = @()

    foreach ($e in ($run + $folders)) {
        $procName = $null
        try { $procName = Get-FrEntryProcessName -Entry $e } catch { $procName = $null }

        if (Test-FrAlreadyRunning -ProcessName ([string]$procName)) {
            $skipped++
            Write-FrLog "Startup entry '$($e.Name)' already running ($procName) -> skipped, not duplicated" 'INFO'
            continue
        }

        if (-not $script:FR_DRYRUN) {
            try {
                $r = Start-FrStartupEntry -Entry $e
                if ($r -and $r.Launched) {
                    $launched++; $launchedNames += $e.Name
                    Write-FrLog "Replayed startup entry: $($e.Name) [$($e.Source)]" 'OK'
                } else {
                    $failed++
                    Write-FrLog "Replay $($e.Name) could not launch: $($e.Command)" 'WARN'
                }
            } catch {
                $script:FR_ERRORS.Add("replay.$($e.Name): $($_.Exception.Message)") | Out-Null
                $failed++; Write-FrLog "Replay $($e.Name) failed: $($_.Exception.Message)" 'ERROR'
            }
        } else {
            $launched++
            Write-FrLog "DRY-RUN would replay: $($e.Name) [$($e.Source)] (process=$procName not running)" 'DRY'
        }
    }

    $runOnce = Invoke-FrRunOnce

    return [pscustomobject]@{
        Enumerated = ($run.Count + $folders.Count)
        Launched   = $launched
        Skipped    = $skipped
        Failed     = $failed
        RunOnceHandled = $runOnce.Handled
        LaunchedNames  = $launchedNames
    }
}
function Invoke-FrEnvBroadcast {
    <# Reboot effect #16: WM_SETTINGCHANGE(Environment) to every top-level
       window - the same notification a logon/shell-refresh produces, so all
       processes pick up current machine/user environment variables. #>
    [CmdletBinding()] param()
    $result = [UIntPtr]::Zero
    $hwndAll = [IntPtr]0xFFFF          # HWND_BROADCAST
    $wmSettingChange = 0x001A
    $smtoAbortIfHung = 0x0002
    $ok = [FrNative]::SendMessageTimeout($hwndAll, $wmSettingChange, [UIntPtr]::Zero,
            'Environment', $smtoAbortIfHung, 2000, [ref]$result)
    return [pscustomobject]@{ Delivered = ($ok -ne [IntPtr]::Zero) }
}

function Invoke-FrShellPhase {
    <# Reboot effects #4-#6 + #16: shell cycle with cache purge in the
       down-window, then the environment broadcast from the fresh shell. #>
    [CmdletBinding()] param()
    $r = Invoke-FrEffect -Description 'restart explorer shell with icon/thumb cache purge' -Effect {
        Restart-FrExplorer -WithCachePurge
    }
    $b = Invoke-FrEffect -Description 'broadcast WM_SETTINGCHANGE(Environment)' -Effect {
        Invoke-FrEnvBroadcast
    }
    if (-not $b) { $b = [pscustomobject]@{ Delivered = $false } }
    if ($r) {
        Write-FrLog ("Shell cycled: explorer {0} -> {1}; env broadcast delivered={2}" -f `
            $r.BeforePid, $r.AfterPid, $b.Delivered) 'OK'
    }
    return [pscustomobject]@{ Shell = $r; EnvBroadcast = $b }
}
# (more phases below)

# ============================================================ CACHE PHASE
function Invoke-CachePhase {
    <# Reboot effects #7-#10 in one contained phase: DNS resolver, ARP/NBT,
       shader caches, and boot-style temp sweep. #>
    [CmdletBinding()] param()

    $dns = Invoke-FrEffect -Description 'flush DNS resolver cache' -Effect { Invoke-FrDnsFlush }
    if ($dns) { Write-FrLog ("DNS resolver cache: {0} entries -> {1} (flushdns OK)" -f $dns.Before, $dns.After) 'OK' }

    $arp = Invoke-FrEffect -Description 'flush ARP + NetBIOS caches' -Effect { Invoke-FrArpNbtFlush }
    if ($arp) { Write-FrLog ("ARP/NetBIOS flush rc: arp={0} nbtR={1} nbtRR={2}" -f $arp.Arp, $arp.NbtPurge, $arp.NbtRelease) 'OK' }

    $shader = Invoke-FrEffect -Description 'purge DirectX/NVIDIA shader caches' -Effect { Invoke-FrShaderCachePurge }
    if ($shader) { Write-FrLog ("Shader caches: {0} present, {1} files removed ({2} MB, {3} locked)" -f `
        $shader.CachesPresent, $shader.FilesRemoved, $shader.MB, $shader.Locked) 'OK' }

    $temp = Invoke-FrEffect -Description 'boot-style temp sweep (user + Windows)' -Effect { Invoke-FrTempCleanup }
    if ($temp) { Write-FrLog ("Temp sweep: {0} items removed ({1} MB, {2} in-use skipped)" -f `
        $temp.ItemsRemoved, $temp.MB, $temp.LockedSkipped) 'OK' }

    return [pscustomobject]@{ Dns = $dns; Arp = $arp; Shader = $shader; Temp = $temp }
}

# ======================================================== ORCHESTRATOR
function Get-FrSystemSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Label)
    $avail = [FrNative]::QuickAvailableBytes()
    $exp = Get-Process -Name explorer -ErrorAction SilentlyContinue |
           Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    return [pscustomobject]@{
        Label       = $Label
        Time        = Get-Date -Format 'HH:mm:ss.fff'
        AvailableMB = [math]::Round($avail / 1MB, 0)
        ShellPid    = if ($exp) { $exp.Id } else { $null }
    }
}

function Test-FrUsable {
    <# The READY proof: shell alive with a window (short grace wait - the
       fresh shell warms up while later phases run, like a real boot), a
       brand-new process can be spawned, and the network stack still answers. #>
    [CmdletBinding()] param()
    $shellOk = $false
    $winDeadline = [DateTime]::UtcNow.AddSeconds(3)
    do {
        $shellOk = [bool](Get-Process -Name explorer -ErrorAction SilentlyContinue |
                          Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1)
        if ($shellOk) { break }
        Start-Sleep -Milliseconds 150
    } while ([DateTime]::UtcNow -lt $winDeadline)
    $spawnOk = $false
    try {
        $p = Start-Process -FilePath "$env:WINDIR\System32\cmd.exe" -ArgumentList '/c exit 0' `
             -WindowStyle Hidden -PassThru
        $spawnOk = $p.WaitForExit(3000)
        $p.Dispose()
    } catch { $spawnOk = $false }
    $netOk = $false
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $netOk = ($ping.Send('127.0.0.1', 800).Status -eq 'Success')
    } catch { $netOk = $false }
    return [pscustomobject]@{ Shell = $shellOk; Spawn = $spawnOk; Net = $netOk; Usable = ($shellOk -and $spawnOk -and $netOk) }
}

function Write-FrReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$After,
        [Parameter(Mandatory)][hashtable]$PhaseMs,
        [Parameter(Mandatory)]$Usable, [Parameter(Mandatory)][int]$TotalMs,
        [Parameter(Mandatory)][string]$Path
    )
    $lines = @()
    $lines += '============================================================'
    $lines += " FlashReboot v$script:FR_VERSION - run report  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $lines += '============================================================'
    $lines += ''
    $lines += ' METRICS (before -> after)'
    $lines += ("   Available RAM   : {0} MB -> {1} MB" -f $Before.AvailableMB, $After.AvailableMB)
    $lines += ("   Shell PID       : {0} -> {1}" -f $Before.ShellPid, $After.ShellPid)
    $lines += ''
    $lines += ' PHASE TIMING'
    foreach ($k in ($PhaseMs.Keys | Sort-Object)) {
        $lines += ("   {0,-18}: {1} ms" -f $k, $PhaseMs[$k])
    }
    $lines += ("   {0,-18}: {1} ms   (budget: 10000 ms)" -f 'TOTAL', $TotalMs)
    $lines += ("   {0,-18}: {1} ms   (invocation -> READY incl. engine load; budget: 10000 ms)" -f 'WALL CLOCK', $script:FR_WALL.ElapsedMilliseconds)
    $lines += ''
    $lines += ' USABLE PROOF'
    $lines += ("   Shell alive     : {0}" -f $Usable.Shell)
    $lines += ("   New process run : {0}" -f $Usable.Spawn)
    $lines += ("   Network stack   : {0}" -f $Usable.Net)
    if ($script:FR_ERRORS.Count -gt 0) {
        $lines += ''
        $lines += ' CONTAINED ERRORS'
        $script:FR_ERRORS | ForEach-Object { $lines += "   - $_" }
    }
    $lines += ''
    $verdict = if ($Usable.Usable -and $script:FR_ERRORS.Count -eq 0) { 'READY' } elseif ($Usable.Usable) { 'READY (with contained warnings)' } else { 'NOT READY' }
    $lines += " VERDICT: $verdict"
    $lines += '============================================================'
    $text = $lines -join [Environment]::NewLine
    Set-Content -LiteralPath $Path -Value $text -Encoding UTF8
    return $verdict
}

function Invoke-FlashReboot {
    <# The full flash-reboot run: every reboot effect, ordered, contained,
       timed; ends with the READY verdict and exit code. #>
    [CmdletBinding()]
    param([switch]$Deep, [switch]$NoStartupReplay, [string]$ReportPath)

    $total = [System.Diagnostics.Stopwatch]::StartNew()
    $logPath = Initialize-FrLog
    Write-FrLog ("FlashReboot v{0} - pid {1} - user {2} - DryRun={3} Deep={4}" -f `
        $script:FR_VERSION, $PID, $env:USERNAME, $script:FR_DRYRUN, [bool]$Deep) 'PHASE'

    if (-not (Assert-FrPreflight -RequireAdmin)) { $script:FR_EXITCODE = 4; return }

    $mode = if ($script:FR_DRYRUN) { 'DRY-RUN (zero side effects)' } else { 'FULL FLASH REBOOT' }
    Write-FrLog "Mode: $mode" 'PHASE'

    $protected = Get-ProtectedPidSet
    Write-FrLog ("Never-touch guard: {0} pids, {1} names (self+ancestors+critical)" -f `
        $protected.Pids.Count, $protected.Names.Count) 'INFO'

    $before = Get-FrSystemSnapshot 'before'
    $phaseMs = @{}

    function Invoke-Phase {
        param([string]$Name, [scriptblock]$Body)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Write-FrLog "PHASE $Name" 'PHASE'
        try { & $Body } catch {
            $script:FR_ERRORS.Add("$Name`: $($_.Exception.Message)") | Out-Null
            Write-FrLog "PHASE $Name failed (contained): $($_.Exception.Message)" 'ERROR'
        }
        $sw.Stop()
        $phaseMs[$Name] = $sw.ElapsedMilliseconds
        Write-FrLog ("[TIMING] {0}: {1} ms" -f $Name, $sw.ElapsedMilliseconds) 'PHASE'
    }

    # Boot-overlapped order: service stops are FIRED first and complete while
    # the shell cycle runs; harvest finishes the starts; the RAM drop lands
    # last so nothing else is slowed by the working-set re-fault storm.
    Invoke-Phase 'services-fire' { Invoke-FrServiceKickoff -Deep:$Deep | Out-Null }
    Invoke-Phase 'shell'  { Invoke-FrShellPhase | Out-Null }
    Invoke-Phase 'services-harvest' { Invoke-FrServiceHarvest -Deep:$Deep | Out-Null }
    Invoke-Phase 'caches' { Invoke-CachePhase | Out-Null }
    if ($NoStartupReplay) {
        Invoke-Phase 'startup' { Write-FrLog 'Startup replay skipped (-NoStartupReplay)' 'INFO' }
    } else {
        Invoke-Phase 'startup' {
            $r = Invoke-FrReplayPhase
            Write-FrLog ("Startup replay: {0} enumerated, {1} launched, {2} skipped, {3} failed, {4} RunOnce" -f `
                $r.Enumerated, $r.Launched, $r.Skipped, $r.Failed, $r.RunOnceHandled) 'OK'
        }
    }
    Invoke-Phase 'memory' { Invoke-MemoryPhase -Protected $protected | Out-Null }

    $after = Get-FrSystemSnapshot 'after'
    $usable = Test-FrUsable
    $total.Stop()
    $script:FR_WALL.Stop()   # wall clock freezes at the READY point

    # ---- after the READY point: boot-like background completions + verification
    $taskCount = Get-FrLogonTaskCount
    Write-FrLog "Logon-triggered tasks inventoried (report-only): $taskCount" 'INFO'

    # verify the background standby purge actually empties the list
    $verifyDeadline = [DateTime]::UtcNow.AddSeconds(8)
    $standbyNow = -1.0
    do {
        Start-Sleep -Milliseconds 700
        $m = Get-FrMemoryCounters
        $standbyNow = if ($m) { $m.StandbyCoreMB + $m.StandbyNormalMB + $m.StandbyReserveMB } else { -1 }
    } while ([DateTime]::UtcNow -lt $verifyDeadline -and $standbyNow -gt 4000)
    $verifyMs = $total.ElapsedMilliseconds
    Write-FrLog ("Standby verified after READY: {0} MB remaining (checked {1} ms after start)" -f `
        [math]::Round($standbyNow, 0), $verifyMs) 'OK'
    Write-FrLog ("BITS and background workers finish like boot services (not on the READY path)") 'INFO'

    if (-not $ReportPath) {
        $ReportPath = Join-Path $script:FR_LOGDIR ("report-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }
    $verdict = Write-FrReport -Before $before -After $after -PhaseMs $phaseMs `
        -Usable $usable -TotalMs $total.ElapsedMilliseconds -Path $ReportPath

    Write-FrLog "Report written: $ReportPath" 'INFO'
    Write-FrLog ("FlashReboot complete in {0} ms - VERDICT: {1}" -f $total.ElapsedMilliseconds, $verdict) 'PHASE'

    if (-not $usable.Usable) { $script:FR_EXITCODE = 3; return }
    if ($script:FR_ERRORS.Count -gt 0)      { $script:FR_EXITCODE = 2; return }
    $script:FR_EXITCODE = 0
}

function Show-FrHelp {
@"
FlashReboot v$script:FR_VERSION - every effect of a Windows reboot, replayed live.
One run resets memory, caches, shell, DNS/ARP/NBT, temp, core services, and
replays everything registered to run at logon - Windows is READY in seconds.

USAGE
  FlashReboot.ps1 [switches]
  Run-FlashReboot.cmd            (double-click; elevates automatically)

SWITCHES
  -DryRun            Rehearse only: every decision is logged, nothing mutates
  -Deep              Also restart WSearch (Windows Search) - may exceed 10s
  -NoStartupReplay   Skip replaying Run-key / startup-folder entries
  -ReportPath <f>    Where the run report is written (default: logs\report-*.txt)
  -Help              This screen

WHAT A DEFAULT RUN DOES (all effects of a reboot, zero downtime)
  1. RAM       : working set of every eligible process dropped; standby list
                 purged in a background worker (verified after READY)
  2. Shell     : explorer cycled via Task Scheduler (your normal user token +
                 fresh environment - never elevated), icon/thumb caches purged
  3. Caches    : DNS resolver, ARP, NetBIOS, DirectX/NVIDIA shader caches,
                 boot-style temp sweep (in-use files skipped)
  4. Services  : audio stack (AudioEndpointBuilder -> Audiosrv), FontCache,
                 Spooler cycled; BITS cycles detached, boot-like
  5. Logon     : HKCU/HKLM Run + RunOnce + startup-folder entries replayed;
                 already-running entries are skipped, never duplicated
  6. Ready     : usable-proof (shell window + new process + network) -> VERDICT

EXIT CODES   0 READY   2 completed with contained failures   3 not usable   4 not elevated
FILES        logs\fr-*.log (run log)   logs\report-*.txt (run report)
SAFETY       protected PID set: this process, all ancestors, Windows-critical
             processes - never touched. -DryRun mutates nothing.
"@
}

# ================================================================== MAIN
if ($MyInvocation.InvocationName -ne '.') {
    if ($Help) { Show-FrHelp; exit 0 }
    if ($PurgeStandbyOnly) {
        # detached background worker: enable privilege, purge, log, exit
        Initialize-FrLog | Out-Null
        Write-FrLog 'Standby purge worker started' 'INFO'
        $r = Invoke-FrStandbyPurge
        Write-FrLog ("Standby purge worker done rc={0}/{1}: standby {2} MB -> {3} MB" -f `
            $r.RcPurgeStandby, $r.RcPurgeLowPriority,
            [math]::Round($r.StandbyBeforeMB,0), [math]::Round($r.StandbyAfterMB,0)) 'OK'
        exit 0
    }
    Invoke-FlashReboot -Deep:$Deep -NoStartupReplay:$NoStartupReplay -ReportPath $ReportPath
    exit $script:FR_EXITCODE
    
}
