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
| `profile` | string enum | Only `"General"` is currently supported. |
| `durationSeconds` | integer | Range 5–300. Default is 30. |
| `etlFilePath` | string | Populated after collection completes. |
| `startedAtUtc` | string (date-time) | ISO 8601 timestamp of trace start. |
| `completedAtUtc` | string (date-time) | ISO 8601 timestamp of trace stop. |
| `startExitCode` | integer | WPR process exit code on start. |
| `stopExitCode` | integer | WPR process exit code on stop. |
| `status` | string enum | One of `completed`, `skipped-wpr-not-found`, `skipped-elevation-required`, `failed`. |

In Plan mode the `wpr` object may contain only `profile` and `durationSeconds`.
After collection the remaining fields are populated.

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
