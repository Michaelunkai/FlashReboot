# Release Notes

## v1.0.0 — 2026-10-13 — initial release

The complete reboot-effect engine:

- **Memory**: working-set sweep (~200 processes), background standby-list purge
  with post-READY verification (35 GB → 0.1 GB observed), clipboard reset, GC.
- **Shell**: explorer cycled via one-shot Scheduled Task — your normal user
  token, fresh registry-built environment, never elevated; icon + thumbnail
  caches purged in the explorer-down window and verified rebuilt.
- **Caches**: DNS resolver (eviction-proven), ARP, NetBIOS, D3DSCache +
  NVIDIA shader caches, boot-style temp sweep (locked files skipped).
- **Services**: audio stack in dependency order, FontCache, Spooler — fired
  early and overlapped with the shell cycle; BITS cycles detached.
- **Startup replay**: HKCU/HKLM Run (both registry views, WOW64-aware),
  RunOnce (execute + self-remove semantics), user + common Startup folders;
  already-running entries skipped, never duplicated; everything launched with
  a fresh environment block; scripts and shortcuts routed correctly.
- **Orchestration**: boot-overlapped phase order, per-phase + wall-clock
  timing, contained failures (exit 2), usable-proof (shell + spawn + network),
  READY verdict, report file per run.
- **Safety**: runtime never-touch PID set (self + ancestors + criticals),
  `-DryRun` proven zero-side-effect, protected-process guard audited in logs.
- **Packaging**: self-elevating `Run-FlashReboot.cmd`, 16-test fast suite +
  `-Live` machine tests, release zip, full README and design contract.

Measured on the reference machine (Windows 11 build 26200): **READY in
6.0–7.7 s** across consecutive runs (budget 10 s), every reboot effect
verified by log or report evidence.
