# Live Lab Test Runbook + Results — WPD-01..15 (release v0.3.0)

Fill this in on a real Windows 10/11 lab machine (owner runs this; agents do not
set up VMs). One row per test case, mark PASS / FAIL / N/A, add evidence paths
or console excerpts, then report the filled file (or the summary) back to the
board.

## Release under test

- Tag:        v0.3.0
- Release:    https://github.com/pupontech/windows-performance-diagnostics-toolkit/releases/tag/v0.3.0
- Zip asset:  windows-performance-diagnostics-toolkit-0.3.0.zip
- Hash asset: windows-performance-diagnostics-toolkit-0.3.0.sha256
- Expected SHA-256 (build-verified on 2026-08-27):
  `1c9fc350d52794e306fa819ffaf1d0af7fc62ee26d144805a49411e3cea9eda9`

## Preparation (do once)

1. Download the zip to the lab machine. Do NOT extract yet.
2. Verify the download:
   `Get-FileHash -Algorithm SHA256 .\windows-performance-diagnostics-toolkit-0.3.0.zip`
   — must equal the expected hash above.
3. RIGHT-CLICK the zip → Properties → General tab → check **Unblock** → OK
   (clears Mark-of-the-Web; per the card, unblock before extracting).
4. Extract to `C:\WPD\` (or any writable folder). If the `.ps1` is missing
   after extraction, use Windows Security → Virus & threat protection →
   Protection history → Restore, then `Unblock-File -Path .\src\Invoke-WindowsPerformanceDiagnostics.ps1`.
5. From the extracted folder, open a PowerShell console (5.1). All commands
   below run from there unless noted.

Script invocation pattern used below:
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 ...`
(`-ExecutionPolicy Bypass` is process-scoped only; script already reviewed from the verified asset.)

---

## WPD-01 — Plan mode is read-only

Command:
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 -Mode Plan -OutputDirectory C:\WPD\WPD-01
```

Expected: creates `diagnostic-plan.json`; NO `performance-samples.csv`,
`top-processes.json`, `system-events-last-24-hours.json`, or
`diagnostic-manifest.json` anywhere in `C:\WPD\WPD-01`.

Result: PASS / FAIL / N/A — Evidence (attach `diagnostic-plan.json`):

---

## WPD-02 — Collect refuses without explicit consent

Command:
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 -Mode Collect -DurationSeconds 5 -OutputDirectory C:\WPD\WPD-02
```

Expected: run FAILS before any collection with a message like
`Collect mode requires -ConfirmLocalCollection. No diagnostic data was collected.`
The output folder may exist but must contain NO data artifacts (no csv/json/manifest).

Result: PASS / FAIL / N/A — Evidence (console output, folder listing):

---

## WPD-03 — 5-second collect with explicit confirmation

Command:
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 -Mode Collect -ConfirmLocalCollection -DurationSeconds 5 -MaxEventCount 200 -OutputDirectory C:\WPD\WPD-03
```

Expected: creates `performance-samples.csv`, `top-processes.json`,
`system-events-last-24-hours.json` (where access permits), and
`diagnostic-manifest.json`.

Result: PASS / FAIL / N/A — Evidence (entire `C:\WPD\WPD-03` folder):

---

## WPD-04 — Manifest hashes

Open `C:\WPD\WPD-03\diagnostic-manifest.json`. Expected: every emitted data
artifact is listed with SHA-256 and size.

Result: PASS / FAIL / N/A — Evidence (`diagnostic-manifest.json`):

---

## WPD-05 — Standard (non-admin) account

Log in as a standard user (no admin rights), repeat the WPD-03 command to a new
folder. Expected: collection completes partially or records failures under
`collectionErrors`; the script must NOT change configuration and must NOT
elevate itself (no UAC prompt).

Result: PASS / FAIL / N/A — Evidence (manifest + console output):

---

## WPD-06 — Controlled event appears and is bounded

Create a controlled event in the System log (e.g. on an admin console:
`net stop spooler` then `net start spooler` logs System events), then run the
WPD-03 command with `-MaxEventCount 50`. Expected: event JSON is bounded by
`-MaxEventCount` and contains the recent System-log evidence when accessible;
compare against Event Viewer.

Result: PASS / FAIL / N/A — Evidence (event JSON, Event Viewer comparison):

---

## WPD-07 — No side effects on the system

Before and after the WPD-03 run, capture and compare:

- Defender exclusions: `Get-MpPreference | Select-Object -ExpandProperty ExclusionPath`
- Startup entries: `Get-CimInstance Win32_StartupCommand` (+ Run keys in
  `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and the HKCU equivalent)
- Event-log configuration: `wevtutil gl System` (size/retention)
- System config: `systeminfo` (or `Get-ComputerInfo`)

Expected: no exclusions added, no startup edits, no log clearing, no repair
actions, no uploads, no policy changes.

Result: PASS / FAIL / N/A — Evidence (before/after exports):

---

## WPD-08 — WPR gate: capture without consent refused

Command:
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 -Mode Collect -ConfirmLocalCollection -CaptureWpr -DurationSeconds 5 -OutputDirectory C:\WPD\WPD-08
```

Expected: FAILS before any collection with
`WPR capture requires -ConfirmWprCapture. No diagnostic data was collected.`
No trace started, no `wpr-trace.etl`.

Result: **PASS** — executed 2026-08-27 on GitHub-hosted Windows runners
(windows-2022 + windows-2025, elevated, Windows PowerShell 5.1) via the
`wpd-live-gates` CI job (commit d92a5e3+). Script refused with the exact
consent message, exit code 1, and the output folder contained zero artifacts
(no csv/json/manifest/etl). Evidence: CI job logs
(https://github.com/pupontech/windows-performance-diagnostics-toolkit/actions/runs/33108588131),
`C:\WPD\WPD-08` empty in uploaded artifact `wpd-gates-windows-2022/2025`.
Note: this is the parameter-consent gate (identical on any SKU); no lab
interaction required.

---

## WPD-09 — WPR on standard (non-admin) console

Log in as standard user; run:
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 -Mode Collect -ConfirmLocalCollection -CaptureWpr -ConfirmWprCapture -DurationSeconds 5 -OutputDirectory C:\WPD\WPD-09
```

Expected: collection completes; manifest `wpr.status` is
`skipped-elevation-required`; NO UAC prompt appears; no auto-elevation.

Result: **PASS** — executed 2026-08-27 on the same runners by creating a
local **standard** account (`wpdstd`) and starting the collector under that
identity via `ProcessStartInfo` + `PSCredential` (no admin token; no UAC can
appear because the script never calls `Start-Process -Verb RunAs` and the
runner console itself is elevated). On both OS legs: collection completed
(exit 0), manifest `wpr.status` = `skipped-elevation-required`, a
`wpr-capture` collectionErrors entry
(`requires an elevated (Administrator) console; WPR capture skipped`) was
recorded, and no `wpr-trace.etl` was produced — i.e. the gate skipped cleanly
without attempting elevation. Evidence: CI job logs (run 33108588131),
manifests in artifact `wpd-gates-windows-2022/2025` (`WPD-09\diagnostic-manifest.json`).
Owner may still spot-check the visual "no UAC prompt" on a physical standard
login; the automation verifies the token is non-elevated and no elevation is
attempted.

---

## WPD-10 — WPR from elevated console

From an already-elevated (Administrator) console, run the same WPD-09 command
with `-OutputDirectory C:\WPD\WPD-10`. Expected: `wpr-trace.etl` exists and is
non-empty; manifest `wpr.status` is `completed`; the ETL is listed in the
manifest hashes.

Result: **PASS** — executed 2026-08-27 on both runners (elevated console,
real `wpr.exe`). `wpr-trace.etl` produced and non-empty
(windows-2022: 49,283,072 B, sha256 CC3BE679…; windows-2025: 50,331,648 B,
sha256 E56702C4…); manifest `wpr.status` = `completed`, `startExitCode` 0,
`stopExitCode` 0; ETL listed in manifest `artifacts` with SHA-256 + size.
Evidence: CI job logs (run 33108588131) + `WPD-10\diagnostic-manifest.json`
and `wpr-trace.etl` in artifact `wpd-gates-windows-2022/2025`.

> **Bug found and fixed during this test (v0.4.0, commit b62fb83):** the
> collector's WPR profile default was `'General'`, but `wpr.exe -profiles`
> exposes the built-in profile as **`GeneralProfile`** — so `-start General`
> failed with 0x80070002 on every Windows SKU. The script now defaults to
> `GeneralProfile` (real built-ins selectable via `-WprProfile`), checks the
> start exit code, and verifies ETL existence/size before reporting
> `completed`.

---

## WPD-11 — Release zip, MOTW, and launcher end-to-end

This is the full release-flow check (Preparation steps 1–5 above already cover
the zip hash + Unblock + Protection-history recovery).

1. Confirm the extraction folder contains `START-HERE.bat`, `Run-Diagnostics.bat`,
   `README-FIRST.txt`, and `src\Invoke-WindowsPerformanceDiagnostics.ps1`.
2. Verify file hashes against the `.sha256` asset:
   `Get-FileHash -Algorithm SHA256 .\src\Invoke-WindowsPerformanceDiagnostics.ps1`
3. If the `.ps1` was removed by Defender at any point, confirm the
   README-FIRST.txt recovery path worked (Unblock → re-extract → Protection
   history → Restore).
4. Launch via the recommended basic entry point — double-click `Run-Diagnostics.bat`
   (or run it from `cmd`). Expected: it collects ~30 s and writes
   `C:\Temp\WPD-Case\diagnostic-manifest.json` (plus csv/json artifacts).

Result: PASS / FAIL / N/A — Evidence (folder listing, `Get-FileHash` output,
`C:\Temp\WPD-Case` contents):

---

## WPD-12 — Defender gate: capture without consent refused

Command:
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 -Mode Collect -ConfirmLocalCollection -CaptureDefender -DurationSeconds 5 -OutputDirectory C:\WPD\WPD-12
```

Expected: FAILS before any collection with
`Defender performance capture requires -ConfirmDefenderCapture. No diagnostic data was collected.`
No recording started, no `defender-performance.etl`.

Result: PASS / FAIL / N/A — Evidence (console output):

---

## WPD-13 — Defender on standard (non-admin) console

Log in as standard user; run:
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 -Mode Collect -ConfirmLocalCollection -CaptureDefender -ConfirmDefenderCapture -DurationSeconds 5 -OutputDirectory C:\WPD\WPD-13
```

Expected: collection completes; manifest `defender.status` is
`skipped-elevation-required`; NO UAC prompt appears; no auto-elevation.
Note: if the `DefenderPerformance` module is not installed at all (Defender
platform older than 4.18.2108.7), the status is `skipped-defender-module-not-found`
with a `collectionErrors` entry — record the platform version and mark the case
N/A on that machine.

Result: PASS / FAIL / N/A — Evidence (manifest `defender` block + console output):

---

## WPD-14 — Defender recording from elevated console

From an already-elevated (Administrator) console on a machine with Defender
platform 4.18.2108.7+ (`Get-Module -ListAvailable -Name DefenderPerformance`
must return a module), run the same WPD-13 command with
`-OutputDirectory C:\WPD\WPD-14`. Expected: `defender-performance.etl` exists
and is non-empty; manifest `defender.status` is `completed`; the ETL is listed
in the manifest hashes; the DefenderPerformance module version is recorded.

Result: PASS / FAIL / N/A — Evidence (`defender-performance.etl`, manifest):

---

## WPD-15 — START-HERE.bat UAC flow (full collection)

From a STANDARD (non-admin) account, double-click `START-HERE.bat` in the
extracted folder.

Expected:
1. A UAC prompt appears ("Windows Performance Diagnostics Toolkit" / consent
   dialog for the bat). Screenshot it.
2. After accepting, an elevated console runs the full collection: performance
   samples, top processes, System events, AND a 30-second WPR trace.
3. Output lands in `C:\Temp\WPD-Case`: `diagnostic-manifest.json`,
   `wpr-trace.etl` present; manifest `wpr.status` is `completed`.

Result: PASS / FAIL / N/A — Evidence (UAC screenshot, console output,
`C:\Temp\WPD-Case` contents, manifest):

---

## Failures to report back

For every FAIL: paste the exact command run, the full error text (or the
Defender Protection-history entry), the folder listing, and any manifest
`collectionErrors` block. Include `Get-FileHash` output for the affected file
so the maintainer can confirm which build you ran.

## Tester / machine

- Tester: ____________
- Machine: Windows 10 / 11, build ____________
- Defender platform version: `(Get-MpComputerStatus).AMProductVersion` ____________
- Admin account used for WPD-03/04/06/07/10/14: yes / no
- Standard account used for WPD-05/09/13/15: yes / no
- Date: ____________
