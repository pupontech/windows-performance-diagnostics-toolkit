# Windows Performance Diagnostics Toolkit

> A safety-first, documentation-led foundation for diagnosing Windows slowness and stability issues.

**Version:** 0.5.0

**Status:** Read-only collection MVP plus consent-gated WPR and Defender performance captures, and a built-in read-only network-state snapshot (DNS-vs-ping split test, hosts file, proxy, security-software inventory). It collects local diagnostics only after explicit consent; it performs no repair, upload, policy change, or remediation.

[![CI](https://github.com/pupontech/windows-performance-diagnostics-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/pupontech/windows-performance-diagnostics-toolkit/actions/workflows/ci.yml)

## Purpose

This project defines a conservative Windows diagnostic toolkit that helps a technician gather evidence before changing a machine. It focuses on Microsoft-supported diagnostic surfaces:

- Windows Performance Recorder (WPR) and Windows Performance Analyzer (WPA)
- Performance Monitor and Data Collector Sets
- Event Viewer, Reliability Monitor, and Windows Error Reporting (WER)
- Sysinternals Process Monitor and Autoruns
- Microsoft Defender performance and support diagnostics
- DISM and System File Checker (SFC)

The detailed official-source map is in [docs/official-microsoft-source-map.md](docs/official-microsoft-source-map.md).

## Safety contract

1. **Observe first.** Inventory, counters, event exports, and bounded traces are the default.
2. **Capture narrowly.** Every capture should name its target, duration, output path, and expected artifact.
3. **Keep evidence local by default.** Trace files, logs, crash dumps, and Defender support CABs may contain sensitive data.
4. **No silent remediation.** Startup changes, Defender exclusions or scans, WER policy changes, DISM repair, and SFC require explicit approval.
5. **Preserve chronology.** Never clear Windows event logs or delete diagnostic evidence as part of a normal run.
6. **Report uncertainty.** Correlation (for example, an event near a slowdown) is not proof of causation.

See [SECURITY.md](SECURITY.md) for data-handling and approval boundaries.

## Initial operator workflow

| Phase | Objective | Example artifacts |
|---|---|---|
| 1. Triage | Establish the symptom window and change history | Reliability history, filtered Event Viewer export |
| 2. Low-impact baseline | Measure CPU, memory, disk, and process pressure | PerfMon counter log / report |
| 3. Targeted reproduction | Capture only the affected action or process | WPR ETL, Procmon PML, Defender ETL |
| 4. Analysis | Compare time-correlated evidence | WPA tables/graphs, event timeline, CSV/JSON reports |
| 5. Approval-gated repair | Apply a reviewed remedy only when evidence warrants it | Consent record, command output, CBS/DISM logs |

## Non-goals for v0.1.0

- No automated repair or registry changes
- No automatic event-log clearing
- No automatic startup disablement/deletion
- No automatic Defender exclusions, protection changes, or cloud upload
- No unattended collection of full memory dumps

## MVP usage

Start with a **non-collecting safety plan** (works on the Linux verification host too):

```powershell
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Plan `
  -OutputDirectory C:\Temp\WPD-Plan
```

Run a **local, read-only, explicitly consented** collection on Windows:

```powershell
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Collect `
  -ConfirmLocalCollection `
  -DurationSeconds 30 `
  -MaxEventCount 200 `
  -OutputDirectory C:\Temp\WPD-Case-001
```

Capture a **bounded WPR trace** (requires an elevated console, its own consent gate):

```powershell
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Collect `
  -ConfirmLocalCollection `
  -CaptureWpr `
  -ConfirmWprCapture `
  -DurationSeconds 30 `
  -OutputDirectory C:\Temp\WPD-Case-001
```

Capture a **bounded Microsoft Defender performance recording** (elevated console + Defender platform 4.18.2108.7 or later, its own consent gate):

```powershell
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Collect `
  -ConfirmLocalCollection `
  -CaptureDefender `
  -ConfirmDefenderCapture `
  -DurationSeconds 30 `
  -OutputDirectory C:\Temp\WPD-Case-001
```

The collector writes a timestamped CPU/memory/disk sample CSV, a top-process snapshot, a bounded System-event summary, optional `wpr-trace.etl` / `defender-performance.etl`, optional consent-gated crash evidence (`minidumps\` dumps + `bootfailure\` SRT/boot/CBS logs), and a manifest with SHA-256 hashes. It does **not** start Procmon recordings, invoke DISM/SFC, alter startup items, change policy, transfer artifacts, or remediate anything. On a non-elevated console, WPR and Defender captures are skipped and recorded in the manifest rather than auto-elevating.

## Deployment bundle

`make-deploy-bundle.sh` builds `dist/windows-performance-diagnostics-toolkit-<version>.zip` plus a SHA-256 file from a verified clean git tree. The bundle ships:

- `src\Invoke-WindowsPerformanceDiagnostics.ps1` — the collector
- `START-HERE.bat` — double-click console menu: UAC self-elevation, then 1) Full+WPR trace + crash evidence, 2) Basic, 3) Full+WPR+Defender + crash evidence, 4) Plan preview, 5) Crash evidence only (minidumps + boot-failure logs), 6) Exit; every run logged to `C:\Temp\WPD-Case\diagnostics-run.log`
- `Run-Diagnostics.bat` — double-click launcher for a basic, non-elevated collection (no WPR trace; includes minidumps + boot-failure evidence)
- `README-FIRST.txt` — quick start plus recovery steps when Windows Security removes downloaded unsigned scripts (right-click Properties → Unblock, or `Unblock-File`, and check Protection history if the `.ps1` vanishes after extraction)
- `schema\`, `docs\`, `tests\` — report contract, source map, live test matrix

## Planned deliverables

- ✅ Machine-readable report schema (`schema/diagnostic-report.schema.json`, `docs/report-schema.md`)
- ✅ Consent-gated, time-bounded WPR capture (`-CaptureWpr` + `-ConfirmWprCapture`, `GeneralProfile` or `CPU`/`DiskIO`/`FileIO`/`Network`/`Power`/`GPU`/`Registry`)
- ✅ Consent-gated, time-bounded Defender performance capture (`-CaptureDefender` + `-ConfirmDefenderCapture`, official `New-MpPerformanceRecording`)
- ✅ Consent-gated crash-evidence stages (`-CollectMinidumps` + `-ConfirmMinidumpCollection`, `-CollectBootFailureLogs` + `-ConfirmBootFailureLogCollection`; WinRE runbook in `docs/winre-boot-failure-runbook.md`)
- ✅ Reproducible packaging and artifact verification (`make-deploy-bundle.sh`, SHA-256, release asset verification)
- ✅ WPA-oriented analysis guidance (`docs/wpa-analysis-guide.md`)
- 🔜 Windows lab test matrix execution before any live remediation capability

## Development workflow

Every change flows through the Kanban board (`wpd-toolkit`) → implementation →
GitHub VM CI (Linux pytest/parse + real `Run-Diagnostics.bat` execution on
windows-2022/2025) → release with byte-verified zip. Full pipeline in
[docs/development-workflow.md](docs/development-workflow.md).

## Repository layout

```text
README.md                         project overview and safety contract
SECURITY.md                       consent, privacy, retention, approval model
src/Invoke-WindowsPerformanceDiagnostics.ps1   the collector
schema/diagnostic-report.schema.json          machine-readable report contract
docs/official-microsoft-source-map.md  official Microsoft capability map
docs/report-schema.md             report schema documentation
docs/windows-live-test-matrix.md  Windows lab test matrix
CHANGELOG.md                      release notes
VERSION                           semantic project version
Run-Diagnostics.bat               Defender-safe double-click launcher
README-FIRST.txt                  quick start + Mark-of-the-Web recovery
make-deploy-bundle.sh             reproducible release zip builder
```

## License

MIT — see [LICENSE](LICENSE).
