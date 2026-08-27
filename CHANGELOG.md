# Changelog

## 0.4.0 — 2026-08-27

Crash evidence analysis + resilient event reading (patterns adopted from the field-tested RemoteDiagnostics kit).

- **Resilient event reader (`Get-EventsSafe`)**: replaces `Get-WinEvent -FilterHashtable` for the System log. Get-WinEvent silently returns **zero events for the entire log** if even one record's provider has an unrenderable message-resource DLL; the new record-by-record .NET reader skips just the bad record and keeps everything else. `skippedUnrenderableCount` is reported in the manifest.
- **Crash analysis (`Get-CrashAnalysis`)**: decodes BugCheck 1001 events into bugcheck codes and flags **unexplained abrupt shutdowns** — Kernel-Power 41 events with no bugcheck within 5 minutes (typically hard freeze / power loss / thermal cutout, not a Windows-detected crash). Emitted as `crashAnalysis` in the manifest (`bugchecks` / `unexplainedShutdowns`).
- **Log availability pre-check**: `Get-WinEvent -ListLog System` before the pull — the manifest's `systemEventLog` block now carries `enabled`, `recordCount`, `pulledCount`, `skippedUnrenderableCount`, so an empty result is distinguishable from a failed read.
- Plan mode advertises `analyze-crash-evidence-after-explicit-consent`; report schema covers `systemEventLog` and `crashAnalysis`; unit tests exercise `Get-CrashAnalysis` on Linux; windows-verify exercises the safe reader end-to-end on windows-2022/2025.
- **WPR profile fix (caught by the WPD-10 live gate)**: the built-in WPR profile is `GeneralProfile`, not `General` — `wpr -start General` fails and the old code trusted the exit code and reported `completed` with no ETL. Now: profile defaults to `GeneralProfile` (with `CPU`/`DiskIO`/`FileIO`/`Network`/`Power`/`GPU`/`Registry` selectable), non-zero `wpr -start` exit codes are treated as failure, and `wpr-trace.etl` existence + size are verified before `completed` is reported. A failed start also means an already-running trace is left untouched.
- Safety contract unchanged: read-only, local-only, no auto-elevation, no remediation.

## 0.3.1 — 2026-08-27

START-HERE.bat rebuilt as a console menu (the "GUI" of the toolkit) and now tested in GitHub VMs.

- `START-HERE.bat` now presents a numbered menu (1 Full+WPR / 2 Basic / 3 Full+WPR+Defender / 4 Plan preview / 5 Exit) after the UAC self-elevation prompt, instead of a bare single run.
- Pre-flight check: if `src\Invoke-WindowsPerformanceDiagnostics.ps1` is missing (Defender Mark-of-the-Web can strip downloaded `.ps1` files), the bat prints the Unblock/Protection-history recovery steps instead of failing silently.
- Every run is tee'd to `C:\Temp\WPD-Case\diagnostics-run.log` so results are always visible; the bat verifies `diagnostic-manifest.json` was produced and reports the artifact list.
- CI-safe: menu supports auto-args (`START-HERE.bat 2`, `START-HERE.bat 4`), UAC elevation is guarded under CI, pause is skipped under CI.
- GitHub VM testing: `windows-verify` now executes the START-HERE menu in auto mode (options 2 and 4) on windows-2022/2025 and asserts both the manifest and the plan JSON.
- Safety contract unchanged.

## 0.3.0 — 2026-08-27

Consent-gated Microsoft Defender performance capture.

- Added `-CaptureDefender` with its own `-ConfirmDefenderCapture` consent gate: a time-bounded
  Defender performance recording via the official `DefenderPerformance` module cmdlet
  `New-MpPerformanceRecording -RecordTo <etl> -Seconds <duration>` (Microsoft-Antimalware-Engine
  and NT kernel process events), elevation-required (never auto-elevates; skips with a recorded
  error on non-elevated consoles), and a `defender` status block in the manifest
  (`completed` / `skipped-defender-module-not-found` / `skipped-elevation-required` / `failed`).
- Plan mode advertises the Defender capture in `plannedActions` and the plan `defender` scope
  without invoking anything. Both consent-gated captures (WPR and Defender) can be planned in the
  same run.
- Documented the `defender` manifest object and the `defender-performance.etl` artifact in
  `docs/report-schema.md`, and added live test cases WPD-12..14 to
  `docs/windows-live-test-matrix.md`.
- Safety contract unchanged: read-only collection, local-only, no auto-elevation, no scans or
  exclusion changes, no remediation, no upload, no log clearing.

## 0.2.1 — 2026-08-27

Bug fix release: `Run-Diagnostics.bat` failed on real Windows with `Exception calling "GetFullPath" ... "Illegal characters in path."`

- **Root cause:** the launcher passed `-OutputDirectory "C:\Temp\WPD-Case\"` — a trailing backslash immediately before the closing quote of a `powershell.exe -File` argument is parsed as an escaped quote, so the script received a path ending in a literal `"`, which is illegal in Windows paths.
- Fixed the launcher argument (no trailing backslash) and added a CI-safe `if not "%CI%"=="true" pause` guard so GitHub runners do not hang on the interactive pause.
- Hardened the collector: an invalid `-OutputDirectory` now fails with a clear message (`OutputDirectory '<path>' is not a valid local path: ...`) instead of a cryptic `MethodInvocationException`.
- **GitHub VM testing:** `windows-verify` now executes the real `Run-Diagnostics.bat` via `cmd` on windows-2022/2025 and asserts `C:\Temp\WPD-Case\diagnostic-manifest.json` is produced, plus a clear-error check for invalid paths. Regression test locks the bat to quote-safe/CI-safe form.
- Safety contract unchanged.

## 0.2.0 — 2026-08-27

Consent-gated WPR capture, machine-readable report schema, and hardened packaging.

- Added `-CaptureWpr` with its own `-ConfirmWprCapture` consent gate: bounded `wpr.exe -start General -filemode` / `-stop` capture writing `wpr-trace.etl`, elevation-required (never auto-elevates; skips with a recorded error on non-elevated consoles), and a `wpr` status block in the manifest (`completed` / `skipped-wpr-not-found` / `skipped-elevation-required` / `failed`).
- Plan mode advertises the WPR capture in `plannedActions` and the plan `wpr` scope without invoking anything.
- Added `schema/diagnostic-report.schema.json` (draft-07) covering Plan and Collect manifests, plus `docs/report-schema.md` documenting the machine-readable contract and versioning policy.
- Added `make-deploy-bundle.sh` (deterministic zip + SHA-256 from a verified clean tree), a Defender-safe `Run-Diagnostics.bat` launcher, and `README-FIRST.txt` with Mark-of-the-Web / Unblock-File recovery steps for `.ps1` files stripped by Windows Security.
- Added GitHub Actions CI (`linux-verify` parse + pytest gate; `windows-verify` on windows-2022/2025 exercising parse under PowerShell 5.1 and pwsh, Plan mode, and both consent refusals).
- Safety contract unchanged: read-only collection, local-only, no auto-elevation, no remediation, no upload, no log clearing.

## 0.1.0 — 2026-08-27

Initial read-only MVP release.

- Added `Invoke-WindowsPerformanceDiagnostics.ps1`, a PowerShell 5.1-compatible local diagnostic collector.
- Collection is explicit-consent only via `-ConfirmLocalCollection` and refuses to run off Windows.
- Added bounded CPU/memory/disk samples, top-process snapshot, System-event summary, per-artifact SHA-256 manifest, and collection-error reporting.
- Added Linux-verifiable plan/consent/non-Windows safety tests plus a Windows live test matrix.
- Defined a Microsoft-official source map and evidence-first safety boundaries.
- No executable repair/remediation, WPR/Procmon/Defender trace, upload, policy change, startup modification, DISM, or SFC capability is included.
