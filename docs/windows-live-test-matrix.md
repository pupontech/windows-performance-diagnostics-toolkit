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

## Approved collection example

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Collect `
  -ConfirmLocalCollection `
  -DurationSeconds 30 `
  -MaxEventCount 200 `
  -OutputDirectory C:\Temp\WPD-Case-001
```

`-ExecutionPolicy Bypass` affects only the process invocation; it does not change machine policy. Do not use it unless the technician has reviewed the script from the verified release asset.

## Explicitly out of scope

This MVP does not start WPR, Procmon, Defender performance recording, DISM, SFC, scans, remediation, log clearing, remote transfer, or automatic upload. Those require separate designs, explicit consent, and their own test cases.
