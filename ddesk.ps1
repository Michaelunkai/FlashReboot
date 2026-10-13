function dddesk {
    $DesktopOrganizerScript = 'F:\study\shells\powershell\scripts\DesktopOrganizer\a.ps1'
    if (-not (Test-Path $DesktopOrganizerScript)) {
        Write-Host "SKIP dddesk: DesktopOrganizer script not found at $DesktopOrganizerScript" -ForegroundColor DarkYellow
        return
    }

    $IsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $IsAdministrator) {
        Write-Host "SKIP dddesk: run PowerShell as Administrator before resetting the desktop and taskbar." -ForegroundColor DarkYellow
        return
    }

    $DesktopRoots = @(
        [Environment]::GetFolderPath("Desktop"),
        [Environment]::GetFolderPath("CommonDesktopDirectory")
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    Get-ChildItem -LiteralPath $DesktopRoots -Force -Recurse -ErrorAction SilentlyContinue |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

    $oldDddeskEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $DesktopOrganizerScript 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                Write-Host ("dddesk: DesktopOrganizer reported nonfatal error output after being invoked: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
            } else {
                $_
            }
        }
    } catch {
        Write-Host ("dddesk: DesktopOrganizer command reported a nonfatal error after being invoked: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    } finally {
        $ErrorActionPreference = $oldDddeskEap
        $global:LASTEXITCODE = 0
    }
}

ddesk
