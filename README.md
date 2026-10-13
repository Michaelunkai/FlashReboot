<div align="center">

# ⚡ FlashReboot

**Every effect of a Windows reboot — replayed live, with zero downtime.**

One command resets RAM, caches, the shell, the network resolver, temp storage,
core services, and replays everything registered to run at logon.
Windows is **READY again in ~7 seconds** — the *only* difference from a real reboot.

*Windows 11 · Windows PowerShell 5.1 · zero dependencies · zero installs*

[Download](#-download) · [Usage](#-usage) · [What it does](#-what-one-run-does) · [Safety](#-safety-model) · [How it works](#-how-it-works)

</div>

---

## Why

A reboot has two halves:

1. **Reset** — process RAM, standby memory, caches, the shell, services, temp
   storage: everything returns to a fresh-boot state.
2. **Replay** — everything registered to run at boot/logon gets launched fresh.

A real reboot makes you pay **30–90 seconds** for that. FlashReboot produces the
same reset + replay **while you keep working** — the machine is verified usable
again (shell window up, new processes spawn, network answers) in **under 10
seconds**, typically ~7 s.

## Download

Grab `FlashReboot.zip` from the
[**Releases**](../../releases) page, extract anywhere, and run
`Run-FlashReboot.cmd` (double-click — it elevates automatically).

Or clone and run straight from source:

```powershell
git clone https://github.com/Michaelunkai/FlashReboot.git
cd FlashReboot
.\Run-FlashReboot.cmd
```

## Usage

| Command | Effect |
|---|---|
| `Run-FlashReboot.cmd` | Full flash reboot (elevates automatically) |
| `.\FlashReboot.ps1` | Same, from an already-elevated PowerShell |
| `.\FlashReboot.ps1 -DryRun` | **Rehearse only** — logs every decision, mutates nothing |
| `.\FlashReboot.ps1 -Deep` | Also restarts WSearch (Windows Search) — may exceed 10 s |
| `.\FlashReboot.ps1 -NoStartupReplay` | Skips replaying Run-key / startup-folder entries |
| `.\FlashReboot.ps1 -Help` | Full built-in reference |

**Exit codes:** `0` READY · `2` completed with contained failures · `3` not usable · `4` not elevated.

Each run writes a console log (`logs\fr-*.log`) and a report
(`logs\report-*.txt`) with before/after metrics, per-phase timings, the
usable-proof, and the final verdict:

```
 PHASE TIMING
   services-fire     : 38 ms
   shell             : 2 029 ms
   services-harvest  : 3 901 ms
   caches            :   520 ms
   startup           :   263 ms
   memory            :   520 ms
   WALL CLOCK        : 6 726 ms   (invocation -> READY)

 USABLE PROOF
   Shell alive     : True
   New process run : True
   Network stack   : True

 VERDICT: READY
```

## What one run does

| # | Reboot effect | FlashReboot mechanism |
|---|---------------|----------------------|
| 1 | All process RAM dropped and re-faulted | `EmptyWorkingSet` sweep across every eligible process (~200 processes, ~10 GB reclaimed) |
| 2 | Standby memory cache emptied | `NtSetSystemInformation` purge in a detached worker (35 GB → ~0.1 GB observed), verified after READY |
| 3 | Clipboard reset | Raw `user32` clipboard reset |
| 4 | Explorer (shell) restarted | Stopped → caches purged in the down-window → relaunched **via Task Scheduler with your normal user token** — never elevated |
| 5–6 | Icon + thumbnail caches rebuilt | Deleted in the explorer-down window; verified rebuilt |
| 7 | DNS resolver cache emptied | `ipconfig /flushdns` + entry-level eviction proof |
| 8 | ARP / NetBIOS caches emptied | `arp -d *`, `nbtstat -R`, `-RR` |
| 9 | Shader caches reset | D3DSCache + NVIDIA GLCache/NV_Cache best-effort purge |
| 10 | Temp storage swept | User `%TEMP%` + `C:\Windows\Temp`; in-use files counted and skipped |
| 11 | Core services cycled | Audio stack in dependency order, FontCache, Spooler; BITS cycles detached (boot-like) |
| 12 | (*Deep clean*) Search restarts | WSearch with `-Deep` only |
| 13 | `Run` entries launch at logon | HKCU + HKLM (both registry views) replayed with a **fresh registry-built environment** |
| 14 | `RunOnce` executes then self-removes | Same semantics, value removed after launch |
| 15 | Startup-folder items launch | User + common Startup, `.lnk`/`.cmd`/`.bat`/`.ps1` |
| 16 | Environment re-read | `WM_SETTINGCHANGE(Environment)` broadcast + fresh-environment launches |
| 17 | Logon-triggered tasks | Inventoried and reported |
| 18 | Windows reports "ready" | READY verdict behind a real usable-proof |

Already-running entries are **skipped, never duplicated** — the running
instance already received the fresh-memory treatment.

## Safety model

- **Never-touch list** — built at runtime: this process, its full ancestor
  chain, and Windows-critical processes (`csrss`, `lsass`, `services`, `dwm`,
  `MemCompression`, …). Nothing on the list is stopped, killed, or emptied.
- **User application windows are never force-closed** — only the shell and the
  listed services are restarted; your apps get the memory treatment in place.
- **The desktop shell is never elevated** — it is relaunched through a one-shot
  Scheduled Task (`/IT /RL LIMITED`) carrying your logged-on user token, the
  same privilege context winlogon uses at boot.
- **Containment** — every phase runs in its own `try/catch`; one failing
  subsystem is logged and the run completes (`exit 2`).
- **`-DryRun`** — every enumeration and decision is logged, zero mutations
  (proven: shell PID, caches, service states and clipboard all unchanged).
- **Guard audit** — logs are scanned by the test suite; no log line may ever
  describe touching a protected process.

## How it works

Single-file Windows PowerShell 5.1 engine (`FlashReboot.ps1`, ~1,400 lines)
plus a self-verifying test suite. Native calls (`EmptyWorkingSet`,
`NtSetSystemInformation`, `CreateEnvironmentBlock`, `CreateProcessW`,
clipboard, `SendMessageTimeout`) are P/Invoked through a tiny compiled-on-first-run
helper (cached as `logs\FrNative.dll`).

```
FlashReboot.ps1        the engine (phases, guardrails, orchestrator, report)
FlashReboot.Tests.ps1  self-verifying suite: 16 fast tests + -Live machine tests
Run-FlashReboot.cmd    double-click launcher (elevates automatically)
docs\DESIGN.md         the behavior contract (reboot-effect ledger)
logs\                  run logs, reports, native assembly cache
```

Run the test suite:

```powershell
.\FlashReboot.Tests.ps1          # 16 fast tests, no disruption
.\FlashReboot.Tests.ps1 -Live    # + real sweep, shell cycle, services, full <10s run
```

## Notes & limits

- Run it **elevated** for full effect (the launcher does this).
- The standby-list purge runs in the background because emptying tens of GB of
  kernel cache can take longer than the whole READY budget — exactly like a
  real reboot, where this cost lands at *shutdown*, not at logon.
- A reboot also resets kernel state (drivers, kernel pools, firmware).
  No user-mode tool can do that without downtime; FlashReboot covers everything
  reachable from user mode.

## License

MIT — see [`LICENSE`](LICENSE).
