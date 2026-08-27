# Windows Live Test Matrix

This project is verified on Linux only for PowerShell parsing and safety-mode behavior. Run these tests on a disposable or approved Windows lab machine before using collection mode on a user endpoint.

## Preconditions

- Windows PowerShell 5.1 installed (default on supported Windows client systems)
- A writable local folder for artifacts
- No production workload should be disrupted; the collector is read-only but samples CPU, memory, disks, processes, and the System event log
- Verify the script hash against the release asset before testing

## Test cases

| ID | Action | Expected result | Evidence to preserve |
|---|---|---|---|
| WPD-01 | Run `-Mode Plan` | Creates `diagnostic-plan.json`; no Windows event/process/performance artifacts are collected. | Plan JSON |
| WPD-02 | Run `-Mode Collect` without `-ConfirmLocalCollection` | Fails before collection with explicit-consent message. | Console output; empty/no collection folder |
| WPD-03 | Run a 5-second collection with explicit confirmation | Creates `performance-samples.csv`, `top-processes.json`, `system-events-last-24-hours.json` where access permits, and `diagnostic-manifest.json`. | Entire output folder |
| WPD-04 | Inspect manifest hashes | Every emitted data artifact is listed with SHA-256 and size. | `diagnostic-manifest.json` |
| WPD-05 | Run on a standard (non-admin) account | Collection completes partially or records failures under `collectionErrors`; script must not change configuration or elevate itself. | Manifest and console output |
| WPD-06 | Create a controlled application error/event, then run collection | Event summary should be bounded by `-MaxEventCount` and contain the recent System-log evidence when accessible. | Event JSON and Event Viewer comparison |
| WPD-07 | Watch Defender, startup entries, event-log sizes, and system configuration before/after | No exclusions, startup edits, log clearing, repair actions, uploads, or policy changes occur. | Before/after screenshots or exports |
| WPD-08 | Run `-Mode Collect -ConfirmLocalCollection -CaptureWpr` **without** `-ConfirmWprCapture` | Fails before any collection with the WPR consent message; no trace started. | Console output |
| WPD-09 | Run `-Mode Collect -ConfirmLocalCollection -CaptureWpr -ConfirmWprCapture` on a **standard (non-admin)** console | Collection completes; manifest `wpr.status` is `skipped-elevation-required`; no UAC prompt appears; no auto-elevation. | Manifest `wpr` block and console output |
| WPD-10 | Run the WPD-09 command from an **elevated** console | `wpr-trace.etl` exists with the manifest `wpr.status` `completed`; ETL is listed in manifest hashes. | `wpr-trace.etl`, manifest |
| WPD-11 | Download the release zip, extract, inspect `src\Invoke-WindowsPerformanceDiagnostics.ps1` and `Run-Diagnostics.bat` | If the `.ps1` was removed by Defender, follow `README-FIRST.txt` (Unblock / Protection history) and confirm the launcher runs. Verify file hashes against the `.sha256` asset. | Extraction folder listing, `Get-FileHash` output |
| WPD-15 | Double-click `START-HERE.bat` from a standard (non-admin) account | A UAC prompt appears; after accepting, an elevated console runs the full collection: samples + events + `wpr-trace.etl`; manifest `wpr.status` is `completed`. | UAC screenshot, console output, manifest + ETL |
| WPD-12 | Run `-Mode Collect -ConfirmLocalCollection -CaptureDefender` **without** `-ConfirmDefenderCapture` | Fails before any collection with the Defender consent message; no recording started. | Console output |
| WPD-13 | Run `-Mode Collect -ConfirmLocalCollection -CaptureDefender -ConfirmDefenderCapture` on a **standard (non-admin)** console | Collection completes; manifest `defender.status` is `skipped-elevation-required`; no UAC prompt appears; no auto-elevation. | Manifest `defender` block and console output |
| WPD-14 | Run the WPD-13 command from an **elevated** console with Defender platform 4.18.2108.7+ installed | `defender-performance.etl` exists with the manifest `defender.status` `completed`; ETL is listed in manifest hashes. | `defender-performance.etl`, manifest |

## Approved collection example

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Collect `
  -ConfirmLocalCollection `
  -DurationSeconds 30 `
  -MaxEventCount 200 `
  -OutputDirectory C:\Temp\WPD-Case-001
```

Consent-gated Defender performance recording (elevated console required):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Collect `
  -ConfirmLocalCollection `
  -CaptureDefender `
  -ConfirmDefenderCapture `
  -DurationSeconds 30 `
  -OutputDirectory C:\Temp\WPD-Case-002
```

`-ExecutionPolicy Bypass` affects only the process invocation; it does not change machine policy. Do not use it unless the technician has reviewed the script from the verified release asset.

## Explicitly out of scope

This release does not start Procmon, DISM, SFC, scans, remediation, log clearing, remote transfer, or automatic upload. WPR capture is available only behind the separate `-ConfirmWprCapture` gate (WPD-08/09/10), and Defender performance recording only behind the separate `-ConfirmDefenderCapture` gate (WPD-12/13/14). Everything else on this list requires separate designs, explicit consent, and their own test cases.
