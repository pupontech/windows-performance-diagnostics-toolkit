# Windows Performance Diagnostics Toolkit

> A safety-first, documentation-led foundation for diagnosing Windows slowness and stability issues.

**Version:** 0.1.0

**Status:** Initial research/specification release — no executable collector is included.

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

## Planned deliverables

- A schema for a consented, machine-readable diagnostic report
- Read-only PowerShell collection wrappers with explicit scope and retention controls
- Reproducible packaging and artifact verification
- Windows lab test matrix before any live remediation capability

## Repository layout

```text
README.md                         project overview and safety contract
SECURITY.md                       consent, privacy, retention, approval model
docs/official-microsoft-source-map.md  official Microsoft capability map
CHANGELOG.md                      release notes
VERSION                           semantic project version
```

## License

MIT — see [LICENSE](LICENSE).
