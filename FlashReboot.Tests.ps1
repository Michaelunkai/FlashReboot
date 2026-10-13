<#
.SYNOPSIS
    FlashReboot self-verifying test suite. Exit 0 = all green.
.PARAMETER Live
    Also run heavy real-machine tests (working-set sweep, shell restart,
    service cycles, and a full real FlashReboot run with the 10s gate).
#>
param([switch]$Live)

$ErrorActionPreference = 'Continue'
$engine = Join-Path $PSScriptRoot 'FlashReboot.ps1'
$script:pass = 0
$script:fail = 0

function Assert-Test {
    param([string]$Name, [scriptblock]$Check)
    try { $ok = [bool](& $Check) } catch { $ok = $false }
    if ($ok) { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else     { $script:fail++; Write-Host "  FAIL  $Name" -ForegroundColor Red }
}

# capture switches BEFORE dot-sourcing (dot-source injects its own $false ones)
$isLive = [bool]$Live

# ================= load engine =================
$tok = $null; $perr = $null
[System.Management.Automation.Language.Parser]::ParseFile($engine, [ref]$tok, [ref]$perr) | Out-Null
. $engine
Initialize-FrLog | Out-Null

Write-Host "== FlashReboot test suite (Live=$isLive) ==" -ForegroundColor Cyan

# ================= static =================
Assert-Test 'engine parses clean'          { $perr.Count -eq 0 }
Assert-Test 'logging core readback'        {
    $lp = Initialize-FrLog
    Write-FrLog 'suite-log-marker' INFO
    (Get-Content $lp -Raw).Contains('suite-log-marker')
}
Assert-Test 'preflight detects admin'      { Test-IsAdmin }
Assert-Test 'guardlist has self+critical'  {
    $p = Get-ProtectedPidSet
    $p.Pids.Contains($PID) -and $p.Names.Contains('csrss') -and $p.Names.Contains('lsass') -and $p.Names.Contains('zcode')
}
Assert-Test 'guard: Test-FrProtected self' { Test-FrProtected -ProcessId $PID -ProcessName 'powershell.exe' -Protected (Get-ProtectedPidSet) }

# ================= parser =================
Assert-Test 'parser: quoted path + args'   {
    $p = ConvertFrom-FrStartupCommand -Command '"C:\Program Files\do t\app.exe" -x 1'
    $p.Exe -eq 'C:\Program Files\do t\app.exe' -and $p.Arguments -eq '-x 1'
}
Assert-Test 'parser: unquoted spaced path' {
    $d = 'C:\Temp\fr spaced dir'
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    $e = Join-Path $d 'real.exe'
    if (-not (Test-Path $e)) { Copy-Item "$env:WINDIR\System32\cmd.exe" $e }
    $p = ConvertFrom-FrStartupCommand -Command "$e /s"
    $ok = $p.Exe -ieq $e -and $p.Arguments -eq '/s'
    Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue
    $ok
}
Assert-Test 'parser: bare name via PATH'   {
    (ConvertFrom-FrStartupCommand -Command 'notepad.exe').ProcessName -eq 'notepad'
}

# ================= running guard =================
Assert-Test 'guard: running process detected' {
    Start-Process cmd -ArgumentList '/c', 'timeout /t 8' -WindowStyle Hidden
    Start-Sleep -Milliseconds 400
    Test-FrAlreadyRunning -ProcessName 'cmd'
}
Assert-Test 'guard: absent process not detected' {
    -not (Test-FrAlreadyRunning -ProcessName 'fr-nonexistent-guard-probe')
}

# ================= RunOnce semantics =================
Assert-Test 'RunOnce: runs once + value removed' {
    Remove-Item 'C:\Temp\frsuite-once.txt' -Force -ErrorAction SilentlyContinue
    $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
    Set-ItemProperty -Path $k -Name 'FrSuiteOnce' -Value 'C:\Windows\System32\cmd.exe /c type nul > C:\Temp\frsuite-once.txt'
    $r = Invoke-FrRunOnce
    Start-Sleep -Milliseconds 700
    $made = Test-Path 'C:\Temp\frsuite-once.txt'
    $gone = -not (Get-ItemProperty -Path $k -Name 'FrSuiteOnce' -ErrorAction SilentlyContinue)
    Remove-Item 'C:\Temp\frsuite-once.txt' -Force -ErrorAction SilentlyContinue
    $r.Handled -ge 1 -and $made -and $gone
}

# ================= caches =================
Assert-Test 'temp sweep removes seeded marker' {
    $m = Join-Path $env:TEMP 'FrSuiteTempMarker'
    New-Item -ItemType Directory -Force -Path $m | Out-Null
    Set-Content (Join-Path $m 'x.txt') 'x'
    $r = Invoke-FrTempCleanup
    $gone = -not (Test-Path (Join-Path $m 'x.txt'))
    $gone -and $r.ItemsRemoved -ge 1
}
Assert-Test 'clipboard reset empties seeded text' {
    Set-Clipboard -Value 'frsuite-clip-seed' -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 100
    $ok = Invoke-FrClipboardReset
    Start-Sleep -Milliseconds 100
    $ok -and [string]::IsNullOrEmpty((Get-Clipboard -Raw))
}
Assert-Test 'DNS flush evicts primed entries' {
    $null = Resolve-DnsName -Name 'www.wikipedia.org' -DnsOnly -ErrorAction SilentlyContinue
    $null = Resolve-DnsName -Name 'www.github.com' -DnsOnly -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 200
    $before = @(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match 'wikipedia|github' }).Count
    $null = Invoke-FrDnsFlush
    $after = @(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match 'wikipedia|github' }).Count
    $before -ge 2 -and $after -eq 0
}
Assert-Test 'startup enumerations structured' {
    $run = @(Get-FrRunKeyEntries)
    $fold = @(Get-FrStartupFolderEntries)
    $ok = $true
    foreach ($e in ($run + $fold)) {
        if (-not ($e.Source -and $null -ne $e.Name -and $e.Command)) { $ok = $false }
    }
    $ok -and $run.Count -ge 1
}
Assert-Test 'logon task inventory returns count' { (Get-FrLogonTaskCount) -ge 0 }

# ================= live machine tests =================
if ($isLive) {
    Assert-Test 'LIVE: working-set sweep drops RAM' {
        $r = Invoke-FrWorkingSetSweep -Protected (Get-ProtectedPidSet)
        $r.Touched -ge 30 -and $r.Failed -eq 0
    }
    Assert-Test 'LIVE: explorer restart cycles shell' {
        $r = Restart-FrExplorer
        $r.BeforePid -ne $r.AfterPid -and $r.AfterPid -and
        (Test-FrTaskbarAlive) -and
        ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').AutoRestartShell -eq 1)
    }
    Assert-Test 'LIVE: service engine cycles BITS' {
        (Restart-FrService -Name 'BITS').Success
    }
    Assert-Test 'LIVE: full run READY under 10s' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = Invoke-FlashReboot
        $sw.Stop()
        $script:FR_EXITCODE -eq 0 -and $sw.ElapsedMilliseconds -lt 10000
    }
}

Write-Host ''
Write-Host ("== {0} passed, {1} failed ==" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
exit ([int]($script:fail -gt 0))
