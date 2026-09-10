# Windows Live Test Matrix

This project is verified in hosted CI for PowerShell parsing (5.1 + pwsh),
fixture/behavioral tests, and a controlled Windows smoke collection. The
raw-disk/in-window telemetry, findings/report paths, and the incident-capture
surface still need an **owner-live Windows client run** (WPD-19..WPD-31 below);
hosted runners only prove the code paths execute, not real device counter values.
Run these tests on a disposable or approved Windows lab machine before using
collection mode on a user endpoint.

The incident-capture rows (WPD-24..WPD-31) are the ones that matter most after a
speed report: they check that the WPR trace actually covers the counter window,
that the trace is bounded, and that per-process commit, GPU, UDP, and
drive-to-disk evidence are present rather than merely plausible.

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
| WPD-15 | Double-click `START-HERE.bat` from a standard (non-admin) account | The console menu shows Plan, Collect, Verify, and Exit. Run Collect: a UAC prompt appears only for collection; samples + events + `wpr-trace.etl` are produced when WPR is available; `diagnostics-run.log` contains the run output. | UAC screenshot, menu screenshot, console output, manifest + ETL + log |
| WPD-16 | Run a collection on a machine with a crash in the last 24h (or create one: `Stop-Computer -Force` during a busy run is NOT advised — instead check an existing machine with Kernel-Power 41 history) | Manifest contains `crashAnalysis` with `bugchecks` (BugCheck 1001 decoded to `0x…` codes) and/or `unexplainedShutdowns` (Kernel-Power 41 without a nearby bugcheck); `systemEventLog` block shows `enabled`/`recordCount`/`pulledCount`/`skippedUnrenderableCount`. | Manifest `crashAnalysis` + `systemEventLog` blocks |
| WPD-12 | Run `-Mode Collect -ConfirmLocalCollection -CaptureDefender` **without** `-ConfirmDefenderCapture` | Fails before any collection with the Defender consent message; no recording started. | Console output |
| WPD-13 | Run `-Mode Collect -ConfirmLocalCollection -CaptureDefender -ConfirmDefenderCapture` on a **standard (non-admin)** console | Collection completes; manifest `defender.status` is `skipped-elevation-required`; no UAC prompt appears; no auto-elevation. | Manifest `defender` block and console output |
| WPD-14 | Run the WPD-13 command from an **elevated** console with Defender platform 4.18.2108.7+ installed | `defender-performance.etl` exists with the manifest `defender.status` `completed`; ETL is listed in manifest hashes. | `defender-performance.etl`, manifest |
| WPD-17 | Run a collection on a machine with a network problem (no internet, slow browsing, or DNS failure — or simulate by breaking DNS resolution or adding a hosts-file redirect) | `network-state.json` is produced and listed in manifest hashes; the manifest `network` block carries `status` `completed`, a `dnsVsPing.verdict` matching the fault (e.g. `dns-failure` when raw IPs ping but names do not resolve, `connectivity-failure` when neither works), and `securitySoftwareMatches` counts; per-section failures (if any) appear in `collectionErrors` with `network-state-<section>` stages. Verify on a standard (non-admin) account that collection still works (WPD-05). | Manifest `network` block, `network-state.json` |
| WPD-18 | Run `-Mode Verify -InputDirectory <case>` on an intact Collect case, then modify a listed artifact and run it again | Intact case returns exit code 0 and report `status: "verified"`; tampered case returns exit code 1 with an artifact or package integrity error. The case directory is unchanged by verification. | JSON verification reports, before/after case listing |
| WPD-19 | Run Collect with `-SymptomContext "Freeze at 12:30 — user typed <b>text</b> & punctuation"` and `-Preset cpu-heavy`, then run a second Collect with only `-Preset storage-io` | `manifest.symptom.reported` preserves the exact punctuation/injection text; `preset` recorded in both; the preset-only run records `symptom.preset` with no `symptom.reported`. | `diagnostic-manifest.json` (or `diagnostic-plan.json`) |
| WPD-20 | Start a controlled low-impact CPU workload (e.g. a short PowerShell busy loop) and run a 10 s collection | `top-processes.json` is non-empty; at least one process has a finite `ProcessCpuPercent`; protected/new processes may be `unknown`; no `process-snapshot` entry in `collectionErrors`. | `top-processes.json`, manifest `collectionErrors` |
| WPD-21 | Generate controlled disk I/O (copy a large file) during a 10 s collection, then run an idle 10 s collection | Under load, `disk-samples.json` has paired intervals with non-null read/write latency or throughput for the active disk and a queue reading. When idle/no I/O, latency is `null` with a coverage reason (never `0`), and no disk finding is fabricated from one reading. | `disk-samples.json`, `findings.json` |
| WPD-22 | Inspect `findings.json` and `report.html` from a collection with a symptom | Findings cite `sourceArtifact`, `metric` and a real `windowStart`/`windowEnd` for sustained rules; report is standalone (no `<script>`, no external URLs), `SizeBytes` is entity-encoded, `report.html` is listed in manifest artifacts but omitted from its own index; insufficient/coverage data is clearly stated. | `findings.json`, `report.html`, manifest |
| WPD-23 | Run `-Mode Verify` on the intact WPD-20/21 case, then append a byte to `report.html` and re-run | Intact case: exit 0, `status: "verified"`. Tampered report: exit 1, `status: "failed"` with a size/hash mismatch. Restore the report and confirm verification passes again. | JSON verification reports |
| WPD-24 | Run an incident capture (`-PerformanceMode -MarkerMode -CaptureWpr -ConfirmWprCapture`, `-DurationSeconds 120`) and press Enter in the console about 40 s in | Manifest `captureWindow` shows `wprStartUtc` at or before `startedAtUtc` and `wprStopUtc` at or after `completedAtUtc`; `findings.json` contains an `evidence-coverage` finding with rule `covers-window` (not a missing/partial trace). `incident.windowStartUtc`/`windowEndUtc` are 60 s before and 30 s after the marked time, and `incident.droppedSampleCount` matches the samples outside that window. | `diagnostic-manifest.json` (`captureWindow`, `incident`), `findings.json` |
| WPD-25 | Inspect the same case's `wpr` block and the case folder size | `wpr.loggingMode` is `memory`, `wpr.actualDurationSeconds` is a measured value close to (not equal to) the requested window, and no multi-GB ETL or `NGenPdb` symbol directory ships when the trace exceeds `-WprMaxFileMB` (`wpr.status` `removed-oversized`, `wpr.traceRemovedOversized` true). | Manifest `wpr` block, case folder listing |
| WPD-26 | On a machine with the reported 80 GiB commit pressure (or any heavy memory user), run an incident capture and inspect the commit artifacts | `process-memory-samples.csv` has one row per tracked process per sample with non-null `PrivateBytes`/`PageFileBytes`; `process-memory-top.json` names the top consumers with a `PrivateBytesGrowth` value; `pagefile-metrics.json` reports `AllocatedBaseSizeMB`/`CurrentUsageMB`/`PeakUsageMB`/`Name`; `kernel-pool-samples.json` carries a paged/nonpaged series; `findings.json` has a `commit-attribution` finding whose `topFivePercentOfCommitLimit` is computed, not fabricated. | The four artifacts + `findings.json` |
| WPD-27 | On an NVIDIA machine that has logged TDR/`nvlddmkm` errors, open `gpu-metrics.json` | `adapters` lists the GPU with driver version; `engines` has per-process `UtilizationPercentage` rows while a GPU workload runs; `processMemory` has dedicated/shared usage per process; `gpu.temperature.available`/`clocks.available` are `false` with a reason (Windows exposes no reliable consumer counter set) rather than a fabricated reading. | `gpu-metrics.json`, manifest `gpu` block |
| WPD-28 | Reproduce UDP-port pressure (or inspect the warning source) and compare `network-state.json` with the live `netstat -ano` output | `network-state.json` is a small file (hundreds of KB at most, not hundreds of MB), `hostsFile.activeEntries` are plain strings, `udpEndpoints`/`udpEndpointCountByProcess` match `netstat -ano`, `dynamicUdpPortRanges` matches `netsh int ipv4 show dynamicport udp`, and `udp-samples.json` shows the per-process endpoint counts over the window. | `network-state.json`, `udp-samples.json`, live `netstat`/`netsh` output |
| WPD-29 | Run an incident capture on a machine with a recent warning, then inspect `incident-events.json` | Events come from `System`/`Application` plus whichever WER/driver/PnP logs exist, each row carries `RawXml` and an `IncidentWindow` of `in-window` or `out-of-window`; events outside the window are still present (labelled) and the manifest `incidentEvents.inWindowEventCount`/`pulledEventCount` match the rows. Confirm at least one event whose message Windows cannot render still exposes readable `RawXml` EventData. | `incident-events.json`, manifest `incidentEvents`, Event Viewer comparison |
| WPD-30 | On a machine with a separate archive/backup drive, inspect `storageMapping` and the report's Volumes row | Every drive letter names its backing physical disk; the drive hosting the pagefile is flagged `HostsPageFile` true; the report's Volume Relevance note makes clear that free space on a non-pagefile archive volume is not a performance cause. | Manifest `storageMapping`, `report.html` |
| WPD-31 | Run `START-HERE.bat` → option 3 from a standard account | The incident-capture text explains the shared window and the Enter-to-mark behavior, a UAC prompt appears only for the collection step, a 120 s window runs with WPR, and the manifest records `performanceMode` in `scope` plus the marker block when Enter was pressed. | Menu screenshot, console output, manifest |

## Approved collection example

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Collect `
  -ConfirmLocalCollection `
  -DurationSeconds 30 `
  -MaxEventCount 200 `
  -OutputDirectory C:\Temp\WPD-Case-001
```

Verify the resulting case:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Verify `
  -InputDirectory C:\Temp\WPD-Case-001
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

This release does not start Procmon, DISM, SFC, scans, remediation, log clearing, or automatic upload. Remote transfer is supported only through the separate `-ConfirmRemoteCollection` gate documented in [docs/remote-mode.md](remote-mode.md). WPR capture is available only behind the separate `-ConfirmWprCapture` gate (WPD-08/09/10), and Defender performance recording only behind the separate `-ConfirmDefenderCapture` gate (WPD-12/13/14). Everything else on this list requires separate designs, explicit consent, and their own test cases.
