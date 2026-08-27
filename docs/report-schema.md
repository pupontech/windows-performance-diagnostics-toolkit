# Diagnostic Report Schema

## Overview

The Windows Performance Diagnostics Toolkit emits machine-readable JSON manifests
that describe what the tool plans to collect or what it has collected. This
document defines the contract for those JSON files and their companion artifacts.

## Artifact Inventory

| File | Description |
|------|-------------|
| `diagnostic-plan.json` | Emitted in Plan mode. Lists planned actions and safety guarantees before any data is collected. |
| `diagnostic-manifest.json` | Emitted in Collect mode. Records what was collected, when, where, and any errors encountered. |
| `performance-samples.csv` | Time-series samples of CPU load, available memory, and free disk space collected once per second. |
| `top-processes.json` | Snapshot of the top 20 processes sorted by CPU usage, including PID, memory, and handle count. |
| `system-events-last-24-hours.json` | System event log entries from the preceding 24 hours (up to MaxEventCount). |
| `wpr-trace.etl` | Windows Performance Recorder ETL trace, only present when `-CaptureWpr` and `-ConfirmWprCapture` are used. |
| `defender-performance.etl` | Microsoft Defender Antivirus performance recording (Microsoft-Antimalware-Engine and NT kernel process events), only present when `-CaptureDefender` and `-ConfirmDefenderCapture` are used. |

## Schema Versioning

The `schemaVersion` field is independent of the `toolVersion` field.

- **`schemaVersion`** — Bump when emitted fields change incompatibly (field removed,
  renamed, or type changed). Patch releases must not alter `schemaVersion`.
- **`toolVersion`** — Tracks the PowerShell script version from `VERSION` or the
  script's own `$ScriptVersion` variable. Increments with every release regardless
  of schema changes.

Current schema version: `1.0`.

When a new schema version is introduced, both versions remain valid during a
transition window. Consumers should accept any `schemaVersion` present in the
enum list.

## WPR Object

The optional `wpr` object appears in Plan mode manifests when `-CaptureWpr` is
specified. It describes the Windows Performance Recorder configuration that will
be used during collection.

| Field | Type | Notes |
|-------|------|-------|
| `profile` | string enum | `GeneralProfile` (default) or a built-in WPR profile (`CPU`, `DiskIO`, `FileIO`, `Network`, `Power`, `GPU`, `Registry`). |
| `durationSeconds` | integer | Range 5–300. Default is 30. |
| `etlFilePath` | string | Populated after collection completes. |
| `startedAtUtc` | string (date-time) | ISO 8601 timestamp of trace start. |
| `completedAtUtc` | string (date-time) | ISO 8601 timestamp of trace stop. |
| `startExitCode` | integer | WPR process exit code on start. |
| `stopExitCode` | integer | WPR process exit code on stop. |
| `status` | string enum | One of `completed`, `skipped-wpr-not-found`, `skipped-elevation-required`, `failed`. |

In Plan mode the `wpr` object may contain only `profile` and `durationSeconds`.
After collection the remaining fields are populated.

## Defender Object

The optional `defender` object appears when `-CaptureDefender` is specified. It
describes the Microsoft Defender Antivirus performance recording requested via
the `DefenderPerformance` module's `New-MpPerformanceRecording` cmdlet
(`-RecordTo` with the timed `-Seconds` parameter set).

| Field | Type | Notes |
|-------|------|-------|
| `durationSeconds` | integer | Range 5-300. Default is 30. |
| `etlFilePath` | string | Populated after collection completes. |
| `startedAtUtc` | string (date-time) | ISO 8601 timestamp of recording start. |
| `completedAtUtc` | string (date-time) | ISO 8601 timestamp of recording end. |
| `moduleVersion` | string | `DefenderPerformance` module version used, populated after collection. |
| `status` | string enum | One of `completed`, `skipped-defender-module-not-found`, `skipped-elevation-required`, `failed`. |

In Plan mode the `defender` object contains only `durationSeconds`. After
collection the remaining fields are populated. Recording requires an elevated
console and the `DefenderPerformance` module (Defender platform 4.18.2108.7 or
later, per the performance analyzer prerequisites).

## Safety Object

Every manifest includes a `safety` object that declares the tool's runtime
constraints. These fields are never silently changed between versions.

| Field | Meaning |
|-------|---------|
| `localOnly` | All operations stay on the local machine. No remote calls. |
| `readOnly` | Plan mode performs no mutations. |
| `requiresExplicitCollectionConsent` | Collect mode requires `-ConfirmLocalCollection`. |
| `automaticUpload` | Always `false`. Data never leaves the machine automatically. |
| `automaticRemediation` | Always `false`. The tool never modifies system state. |
| `automaticLogClearing` | Always `false`. The tool never deletes logs. |

## SHA-256 Manifest Guarantee

Every data artifact listed in `diagnostic-manifest.json` (excluding the manifest
itself) has a corresponding entry in the `artifacts` array with a SHA-256 hash.
The manifest file is never self-referenced. This allows consumers to verify
integrity of all collected files by recomputing hashes and comparing against the
manifest.

## System Event Log Block

The `systemEventLog` object reports the System log's availability and the pull
result so an empty result is never mistaken for "nothing happened":

| Field | Meaning |
|-------|---------|
| `enabled` | Whether the System log is enabled on the target. |
| `recordCount` | Total records on the target at pull time (from `Get-WinEvent -ListLog`). |
| `pulledCount` | Records actually written to `system-events-last-24-hours.json` (bounded by `-MaxEventCount`). |
| `skippedUnrenderableCount` | Records skipped because their provider's message-resource DLL could not be rendered (the record-by-record reader keeps everything else). |

## Crash Analysis Block

The `crashAnalysis` object summarizes crash evidence from the pulled System
events:

| Field | Meaning |
|-------|---------|
| `bugchecks` | BugCheck 1001 events decoded to their `0x…` bugcheck codes (e.g. `0x0000001A`). |
| `unexplainedShutdowns` | Kernel-Power 41 events with **no** bugcheck within 5 minutes — typically a hard freeze, power loss, or thermal cutout rather than a Windows-detected crash. |

Both arrays are empty when no matching evidence is in the window. Correlation
is evidence, not causation: a bugcheck code names the crash *type*, but naming
the exact driver usually needs WinDbg `!analyze -v` against the matching
minidump.
