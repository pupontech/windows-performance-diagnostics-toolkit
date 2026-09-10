# Roadmap

## Completed Milestones

### M1: Slowdown Diagnosis (v0.9.0)

- Symptom context and collection presets (`-SymptomContext`, `-Preset`),
  recorded separately from the UTC collection window; a preset is recorded even
  without symptom text.
- Interval process CPU percentage paired by PID+StartTime over a monotonic
  stopwatch window; unknown/new/reused/protected processes and unknown logical
  processor counts report `unknown` (never a guessed or clamped value).
- In-window telemetry series: per-sample memory committed/limit/available and
  paging indicators (`Win32_PerfFormattedData_PerfOS_Memory`); paired raw
  physical-disk counters (`Win32_PerfRawData_PerfDisk_PhysicalDisk`) for
  read/write latency, throughput and instantaneous queue depth; per-volume free
  space (`Win32_Volume`) with null guards.
- Findings engine with sustained-pressure rules that find the qualifying run
  anywhere in the series, cite start/end/source artifact/metric, count only
  finite readings (nulls break a streak) and never infer from a single
  post-run read.
- Standalone offline `report.html` (all data HTML-encoded, fixed relative
  links, no scripts/external assets) and machine-readable `findings.json`.
- `findings.json`, `report.html`, `disk-samples.json` and `volume-metrics.json`
  registered in the manifest before hashing, so they are in the case ZIP,
  Verify and remote pull.
- Automated fixture/behavioral tests including a fixture-driven Collect tail
  that is verified and then refused after report tampering.

**Known limitations (tracked, not user-visible defects):** sustained-window
selection cites the longest qualifying run and, for two runs of equal length,
always the earlier one (deterministic, documented, but a later equal run is not
reported); a transient raw-disk poll failure is recorded in `collectionErrors`
and in the interval series the next successful poll spans the gap, so a run of
"N consecutive intervals" can silently bridge a failed poll.

**Not yet owner-verified:** the raw disk counter math, the in-window series and
the report generation have only been exercised by fixture tests and a hosted
Windows smoke collection. A run on an owner Windows client is required before
remediation planning (see `docs/windows-live-test-matrix.md`).

### M0: Foundation (v0.1.0 - v0.8.2)

- Read-only local collection with explicit consent gates
- Consent-gated WPR and Defender performance captures
- Crash evidence (minidumps, boot-failure logs)
- Network state snapshot with DNS-vs-ping split test
- Remote collection over WinRM with SHA-256 verification
- Case packaging with artifact hash certification
- Three-mode workflow: Plan, Collect, Verify
- Read-only case verification

## Planned (P2)

- Baseline comparison: compare current collection against a known-good baseline
- Boot/login diagnostics: measure logon duration, startup item impact
- Application diagnostics: per-application resource usage tracking
- Storage health: S.M.A.R.T. attributes, disk lifecycle indicators
- Power diagnostics: battery health, power plan impact on performance

## Planned (P3)

- Cancellation and deadline support for long-running collections
- Sanitized export for sharing cases without sensitive data
- Targeted WPR profiles driven by symptom presets
- Reviewed remediation (behind explicit consent, after evidence review)
- Owner-live Windows matrix execution for the new telemetry, findings and
  report paths (hosted CI runs a controlled smoke collection only)

## Windows evidence: hosted vs owner-live

| Area | Hosted Windows CI | Owner-live client |
| --- | --- | --- |
| Parser (PS 5.1 + pwsh) | yes | - |
| Consent/elevation gates, launchers | yes | - |
| Controlled Collect smoke, findings/report/manifest | yes | - |
| Remote collection over loopback WinRM | yes | - |
| Real hardware disk latency/queue values | no (SMOKE only) | **required** |
| MOTW / Defender quarantine behavior | N/A on runners | **required** |
| Raw disk counter math on real devices | no | **required** |

## Non-Goals (unchanged)

- No automated repair or registry changes
- No automatic event-log clearing
- No automatic startup disablement/deletion
- No automatic Defender exclusions, protection changes, or cloud upload
- No unattended collection of full memory dumps
