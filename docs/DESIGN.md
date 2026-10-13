# FlashReboot — Design & Behavior Contract

**Version:** 1.0.0 · **Platform:** Windows 11 (build 26200, PS 5.1+ tested) · **License:** MIT

## Mission

A reboot has two halves: (1) everything in RAM, caches, services, and the shell gets
reset to a fresh state, and (2) everything registered to run at boot/logon gets
launched fresh. A real reboot pays for that with 30–90 seconds of downtime.

**FlashReboot reproduces half (1) and half (2) completely — the exact effects, with no
downtime.** One run: every subsystem that a reboot resets is reset, every startup
entry replays, and Windows is fully usable again in **under 10 seconds**.

## The reboot-effect ledger (what a real reboot does → what FlashReboot does)

| # | Reboot effect | FlashReboot mechanism | Default |
|---|---------------|----------------------|---------|
| 1 | All process RAM dropped and re-faulted | `EmptyWorkingSet` sweep across every eligible process | on |
| 2 | Standby memory cache emptied | `NtSetSystemInformation(SystemMemoryListInformation)` purge | on |
| 3 | Clipboard reset (RAM reset) | `Clear-Clipboard` (empty + format listeners dropped) | on |
| 4 | Explorer (shell) restarted | graceful stop → cache purge window → relaunch → wait for shell | on |
| 5 | Icon cache rebuilt | `iconcache_*.db` deleted in the explorer-down window | on |
| 6 | Thumbnail cache rebuilt | `thumbcache_*.db` deleted in the explorer-down window | on |
| 7 | DNS resolver cache emptied | `ipconfig /flushdns` + Dnscache entry-count probe | on |
| 8 | ARP / NetBIOS name caches emptied | `arp -d *`, `nbtstat -R`/`-RR` | on |
| 9 | Shader/DirectX cache reset | `%LOCALAPPDATA%\D3DSCache` + NVIDIA GLCache best-effort purge | on |
| 10 | Temp storage cleared at boot (cleanmgr/BootExecute style) | user `%TEMP%` + `C:\Windows\Temp`, locked files skipped | on |
| 11 | Core services cycled fresh | AudioEndpointBuilder → Audiosrv, FontCache, Spooler, BITS | on |
| 12 | (Deep clean) Search index service restarts | WSearch restart | `-Deep` only |
| 13 | HKCU/HKLM `Run` entries launch at logon | enumerate → replay each not-yet-running entry | on |
| 14 | HKLM/HKCU `RunOnce` executes then self-removes | execute → delete key (same semantics Windows uses) | on |
| 15 | Startup-folder items launch (user + common) | enumerate `.lnk`/scripts → replay | on |
| 16 | Environment variables re-read by shell | `WM_SETTINGCHANGE(Environment)` broadcast + fresh shell | on |
| 17 | Logon-triggered scheduled tasks run | inventoried + reported (report-only by design) | report |
| 18 | Windows reports "ready" quickly | READY verdict + usable-proof (spawn + resolve + shell alive) | gate |

Hard-timeout total: **≤ 10 s** wall clock for a default run, enforced and measured.

## Never-harm contract (guardrails)

- **Protected process list** is built at runtime: this process, all ancestors, the
  interactive agent/session processes, and Windows-critical processes (`System`,
  `Idle`, `smss`, `csrss`, `wininit`, `lsass`, `services`, `Registry`,
  `MemCompression`, `dwm`, `audiodg`). The working-set sweep and every stop/restart
  skip anything on this list — **the session that launched FlashReboot can never be
  killed or touched by it.**
- Every phase runs inside its own `try/catch` containment: one failing subsystem can
  never abort the run; it is logged, counted, and the run continues.
- User application windows are **never force-killed** — only the shell and the
  services listed above are restarted; user apps are left running (the reboot
  *effect* — fresh memory, fresh caches — is applied to them in place).
- `-DryRun` performs every enumeration, measurement, and log line but zero mutations
  (no explorer restart, no service stop, no deletes, no replay launches).
- All output is written to a timestamped log under `logs\` plus a final report block.

## CLI contract

```
FlashReboot.ps1 [-DryRun] [-Deep] [-NoStartupReplay] [-ReportPath <file>] [-Help]
```

| Switch | Meaning |
|--------|---------|
| *(none)* | Full default flash-reboot, target ≤10 s |
| `-DryRun` | Zero-mutation rehearsal; prints exactly what would happen |
| `-Deep` | Adds WSearch restart (slower than 10 s is possible) |
| `-NoStartupReplay` | Skips phase 5 (startup replay) |
| `-ReportPath` | Where the final report lands (default `logs\report-<ts>.txt`) |
| `-Help` | Usage |

**Exit codes:** `0` READY (all gates green) · `2` completed with contained phase
failures (details in log) · `3` usability gate failed · `4` not elevated.

## Architecture (single file by design)

```
FlashReboot.ps1
  ├─ Write-Log            logging core (console + file)
  ├─ Test-IsAdmin         preflight
  ├─ Get-ProtectedPidSet  guardrail
  ├─ Invoke-MemoryPhase   1–3
  ├─ Invoke-ShellPhase    4–6 (+ env broadcast 16)
  ├─ Invoke-CachePhase    7–10
  ├─ Invoke-ServicePhase  11–12
  ├─ Get-StartupEntries   13–15 (Run ×4 views, RunOnce, folders)
  ├─ Invoke-ReplayPhase   13–15 execution
  ├─ Get-SystemSnapshot   metrics before/after
  ├─ Test-Usable          READY proof
  └─ Main                 ordered orchestrator, per-phase timing, report
```

Windows PowerShell 5.1 native only — zero dependencies, zero installs.
