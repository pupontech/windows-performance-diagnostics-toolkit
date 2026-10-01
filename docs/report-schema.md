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
| `case-verification.schema.json` | Schema for the machine-readable report emitted by Verify mode. |
| `performance-samples.csv` | Time-series samples of CPU load, available memory, free disk space, and memory committed/limit/paging indicators collected once per second inside the sample window. |
| `top-processes.json` | Snapshot of the top 20 processes sorted by interval CPU percentage, including PID, cumulative CPU seconds, memory, and handle count. |
| `system-events-last-24-hours.json` | System event log entries from the preceding 24 hours (up to MaxEventCount). |
| `livekernelreports.json` | Bounded metadata for the newest LiveKernelReports files; raw dump contents are not copied by this artifact. |
| `servicing-log-analysis.json` | Bounded aggregate signatures, counts and line ranges from copied CBS, DISM, setup and boot logs; raw lines remain in `bootfailure\`. |
| `network-state.json` | Read-only network-state snapshot: IP configuration, adapter status, DNS servers/cache, routes, ARP table, a DNS-vs-ping split test, hosts-file entries, proxy settings, active TCP connections, and a security/VPN/filtering software inventory. |
| `disk-samples.json` | Per-interval, per-disk derived metrics from paired raw `Win32_PerfRawData_PerfDisk_PhysicalDisk` snapshots: read/write latency, throughput and instantaneous queue depth, with coverage reasons for unavailable counters. |
| `volume-metrics.json` | Per-volume capacity/free space with null guards (missing free space is `null`, never `0`). |
| `findings.json` | Machine-readable findings: category, source artifact, metric, window, measured values, rule condition, uncertainty, next steps and suggested WPR profile, plus coverage warnings. |
| `report.html` | Standalone offline HTML report (no scripts/external assets, all data HTML-encoded, fixed relative evidence links). |
| `wpr-trace.etl` | Windows Performance Recorder ETL trace, only present when `-CaptureWpr` and `-ConfirmWprCapture` are used. |
| `defender-performance.etl` | Microsoft Defender Antivirus performance recording (Microsoft-Antimalware-Engine and NT kernel process events), only present when `-CaptureDefender` and `-ConfirmDefenderCapture` are used. |

## Schema Versioning

The `schemaVersion` field is independent of the `toolVersion` field.

- **`schemaVersion`** — Bump when emitted fields change incompatibly (field removed,
  renamed, or type changed). Patch releases must not alter `schemaVersion`.
- **`toolVersion`** — Tracks the PowerShell script version from `VERSION` or the
  script's own `$ScriptVersion` variable. Increments with every release regardless
  of schema changes.

Current emitted schema versions are `1.0`, `1.1`, `1.2`, and `1.3`. The
legacy path remains `1.0` unless symptom or preset context requires `1.1`; the
incident-capture path uses `1.2`. The tiered path uses additive `1.3` fields.
The 1.3 surface does not remove or rename the 1.0-1.2 fields, and Verify accepts
all four versions. Consumers should ignore optional fields they do not use and
accept any schema version present in the enum list.

When a new schema version is introduced, both versions remain valid during a
transition window. Consumers should accept any `schemaVersion` present in the
enum list.

## Tiered 1.3 Surface

Schema 1.3 is an additive contract for the planner, collector, and verifier
layers. It is present when the tiered layer is engaged by a preset, `-Repro`,
`-FlightRecorder`, an explicit Tier 1 interval, or a Tier 3 selection. A plain
legacy invocation keeps its earlier schema version and fields.

The top-level `tiers` object has two related shapes:

| Mode | Required v2 information |
|------|-------------------------|
| Plan | `schemaSurface`, `model`, `collectedTiers`, four projected `tiers` rows, `moduleSurface`, `preset`, `capturePolicy`, `captureMode`, `tier1Cadence`, `privacy`, `escalation`, `coveragePlan`, `dataQualityPlan`, `evidenceIndexPlan`, `healthClaim`, and `neverHealthy`. |
| Collect | `schemaSurface`, `model`, `moduleSurface`, `tier0`, `tier1`, `tier2`, `tier3`, `coverage`, `dataQuality`, `evidenceIndex`, `healthClaim`, and `neverHealthy`. |

The four collection tiers are deliberately different:

| Tier | Name | Collection rule | Missing-data rule |
|------|------|-----------------|-------------------|
| 0 | `static-inventory` | Read static operating-system, hardware, driver, power, storage, network, service, security, startup, filter, pagefile, virtualization, encryption, and recent-change capabilities once per run. The session cache is keyed by host, preset, and privacy level. | The capability remains visible with `unavailable` coverage and a reason. It is not re-queried in the sampling loop. |
| 1 | `interval-counters` | Sample performance counters at the resolved interval. The floor is 1 second. CPU time and utility, user/kernel/DPC/interrupt, scheduler, memory, and storage values are counter data, not Tier 0 snapshots. | A missing counter is `null` and is accompanied by a reason and a coverage state. The collector never substitutes zero or stale inventory. |
| 2 | `etw-wpr-recording` | Run one WPR recording over the same wall-clock window as the counter series when selected. `wpr -marker` entries belong to that window. | An absent WPR executable, unsupported profile, failed preflight, or failed stop is recorded as unavailable or failed with command evidence; it is not presented as a successful trace. |
| 3 | `optional-escalation` | Run only explicitly selected escalation adapters after explicit consent. Examples include wait-chain, pool-tag, Search, and minifilter evidence. | Without both selection and consent the tier is `not-collected`. An absent optional tool is `unsupported`, not healthy and not an unexplained collector failure. |

The Plan shape is a description, not a collection result. `projectedState` is
`not-collected` for every projected tier. Plan mode writes only
`diagnostic-plan.json`; it does not create collector output, invoke WPR, invoke
optional tools, or claim that a capability is present.

### Preset selection and capture policy

`tiers.preset` records `requested`, `effective`, `isAlias`, `displayName`,
`tier1Counters`, `tier1SampleIntervalSeconds`, `expectedDurationSeconds`,
`analysisModules`, `eventChannels`, `escalationOptions`, `traceSizeBudget`,
`privacyLevel`, `automaticRemediation`, `source`, `canonicalNames`, and
`reasons`. An alias is recorded as an alias; it is not silently treated as a
different preset. `tiers.capturePolicy` records the resolved WPR profile,
qualifier, profile specification, memory/file mode, boundedness, buffer
semantics, trace budget, duration limit, analysis tables, source, and reasons.

The `Wpd.Etw` module is the policy owner when it is loaded. The configuration
fallback is intentionally conservative: a profile name that the entry point
does not accept becomes `unsupported-profile-name` and is not silently replaced.
The network configuration label `NetworkProfile` therefore must be resolved by
the module's verified profile table to the accepted WPR profile `Network`; a
fallback refusal is an inspectable Plan result.

`tiers.tier1Cadence` records the requested or preset interval, the 1 second
floor, the source of the value, and reasons. A sub-second request is refused
with `refused-sub-second`, not rounded up. `tiers.captureMode` records mutually
exclusive `Repro` or `FlightRecorder` selection and its strategy. Supplying
both modes is a fail-closed `conflicting-modes` result.

### Coverage states

The shared vocabulary is:

* `complete`: the requested bounded input was read and transformed.
* `partial`: some requested inputs or samples are usable, but the result has a
  declared gap, truncation, or failed sub-query.
* `unavailable`: the provider or source could not supply usable data.
* `not-collected`: the tier or capability was not requested or has only been
  described in Plan mode.
* `unsupported`: the host, provider, profile, or optional tool does not support
  the requested operation.
* `no-data`: a provider returned no usable records; it is never a health claim.

Each `coverage` record can carry `collector`, `tier`, `status`, `coverage`,
`recordCount`, `startedUtc`, `completedUtc`, `durationMs`, `reason`, and
`reasons`. The plan's `coveragePlan.states` lists the allowed values and sets
`noDataIsNeverHealth` to `true`.

### Data quality

Each `dataQuality` record describes whether a metric can support a conclusion.
It can carry `collector`, `metric`, `sampleCount`, `expectedSampleCount`,
`coverage`, `intervals`, `gaps`, and `reasons`. Gaps are explicit; they are not
filled by interpolation unless a consumer performs that analysis itself. A
missing metric remains `null`. The plan's `dataQualityPlan` names the fields
and sets `noDataIsNeverHealth` to `true`.

Data quality is separate from severity and confidence. A finding may be
interesting while still being `partial`; a failed or empty provider does not
produce a healthy, normal, or zero-pressure conclusion. The existing crash,
servicing, network, disk, and boot artifacts retain their own detailed status
blocks and are summarized by these v2 records when they participate in the
tiered run.

### Evidence index

`evidenceIndex` is the join between an interpretation and the bytes that support
it. An index contains bounded `records` and may contain artifact metadata. A
record can carry:

| Field | Meaning |
|-------|---------|
| `id` | Stable identifier referenced by a finding or report section. |
| `artifact` | Artifact name from the manifest whitelist. |
| `path` | Safe relative path; absolute paths and traversal are not evidence links. |
| `metric` | Field or derived metric used by the interpretation. |
| `value` | Measured or summarized value, including `null` when unavailable. |
| `windowStart` / `windowEnd` | UTC bounds for the contributing observation. |
| `sha256` | Optional hash that binds the record to the artifact version. |

The plan's `evidenceIndexPlan` declares these fields and sets
`everyConclusionNeedsEvidence` to `true`. A finding without a resolvable
evidence id is withheld or downgraded to a coverage record by the report layer.
The manifest `artifacts` list remains authoritative for file size and SHA-256;
the evidence index does not replace the artifact whitelist.

### Findings, incidents, inventory, telemetry, and escalation

The schema definitions are intentionally additive and permissive inside each
new envelope so a consumer can preserve provider-specific detail while still
checking the shared invariants.

* `findings` is an array of `finding` objects. A finding may include `id`,
  `category`, `title`, `status`, `severity`, `confidence`, `sourceArtifact`,
  `metric`, `measuredValues`, `windowStart`, `windowEnd`, `ruleCondition`,
  `uncertainty`, `nextSteps`, `suggestedWprProfile`, `coverage`, `evidence`,
  and `possibleCauses`. It does not include a health score. Existing
  `findings.json` entries for CPU, memory, paging, disk, crash, servicing, and
  coverage remain valid.
* `incidentMarkers` records the `wpr -marker` mechanism, marker count, each
  marker name and status, the tool and documented arguments, whether the
  marker switch was resolved, and the shared-window note. The marker names are
  `CAPTURE_START`, `REPRO_START`, `INCIDENT_START`, `INCIDENT_PEAK`,
  `INCIDENT_END`, and `CAPTURE_STOP`. The existing singular `incident` block
  continues to describe observed sample-window counts; `incidents` is the
  additive collection for incident records or a container.
* `inventory` describes Tier 0 capabilities and can contain capability records,
  status, coverage, cache information, reasons, and privacy metadata. It is a
  snapshot, not a time-series health signal.
* `telemetry` describes Tier 1 records or series. It can contain counter names,
  sample timestamps, values, process identity, gaps, status, and coverage.
  Process identity uses PID plus start time when available so PID reuse is not
  silently merged.
* `escalation` describes Tier 3 selection. It records requested adapters,
  consent required/given, adapter descriptors, privacy level, reasons, and
  `automaticRemediation: false`. A missing WCT, ProcDump, PoolMon, Defender,
  Search, or filter utility is an optional-tool limitation with an explicit
  unsupported state.
* `reportHandoff` records whether `case/technician-report.html` was written,
  its relative artifact path, finding count, outcome, or the reason a report
  could not be generated. A missing report module is unavailable, not an empty
  successful report.

All new definitions are available under `schema/diagnostic-report.schema.json`:
`manifest`, `moduleSurface`, `presetSelection`, `capturePolicy`, `captureMode`,
`tierCadence`, `privacy`, `coverage`, `dataQuality`, `evidenceIndex`,
`incidentMarkers`, `incidents`, `inventory`, `telemetry`, `finding`,
`escalation`, and `escalationArtifact`. The definitions accept `null` for
optional values and preserve `no-data`, `unavailable`, `not-collected`, and
`unsupported` states rather than making those values required to be numeric.

## WPR Object

The optional `wpr` object appears in Plan mode manifests when `-CaptureWpr` is
specified. It describes the Windows Performance Recorder configuration that will
be used during collection.

| Field | Type | Notes |
|-------|------|-------|
| `profile` | string enum | `GeneralProfile` (default) or a built-in WPR profile (`CPU`, `DiskIO`, `FileIO`, `Network`, `Power`, `GPU`, `Registry`). |
| `durationSeconds` | integer | Range 5-600. The default is auto-sized for the selected capture window. |
| `etlFilePath` | string | Populated after collection completes. |
| `startedAtUtc` | string (date-time) | ISO 8601 timestamp of trace start. |
| `completedAtUtc` | string (date-time) | ISO 8601 timestamp of trace stop. |
| `startExitCode` | integer | WPR process exit code on start. |
| `stopExitCode` | integer | WPR process exit code on stop. |
| `status` | string enum | One of `completed`, `skipped-wpr-not-found`, `skipped-elevation-required`, `failed`. |

In Plan mode the `wpr` object may contain only `profile` and `durationSeconds`.
After collection the remaining fields are populated.

## WPR Capture Semantics

WPR is optional and consent-gated. `-CaptureWpr` selects a trace and
`-ConfirmWprCapture` is required in Collect mode. The accepted profile names are
`GeneralProfile`, `CPU`, `DiskIO`, `FileIO`, `Network`, `Power`, `GPU`, and
`Registry`; an unsupported profile is described in Plan mode and refused in
Collect mode rather than substituted.

Memory mode is the default. It uses the documented bounded circular-buffer
semantics and is the safe default for a diagnostic window. The tool's trace
budget is a preflight and post-stop guard; it is not a claim that a WPR memory
buffer is a disk-size limit.

File mode is unbounded by design. It is reachable only when the operator opts
into `-AllowWprFileMode` and accepts the risk with `-AcceptUnboundedFileMode`.
The Plan record must show `mode: file`, `unbounded: true`, and
`bufferSemantics: unbounded-file`; preflight can still refuse when duration,
free space, or budget checks fail. No invented WPR switch is used to emulate a
file-size or maximum-duration option.

`-Repro` selects a bounded reproduction strategy. `-FlightRecorder` selects a
circular flight-recorder strategy. They are mutually exclusive and a request
containing both is refused before collection. These strategy names do not make
the tool reboot, suspend, or otherwise change the host.

When incident markers are selected, the marker plan uses the documented
`wpr -marker` command and records these names: `CAPTURE_START`, `REPRO_START`,
`INCIDENT_START`, `INCIDENT_PEAK`, `INCIDENT_END`, and `CAPTURE_STOP`. Marker
commands are planned or executed inside the same capture window as the Tier 1
series. The plan records each command resolution and does not claim an observed
marker when WPR is unavailable.

The on/off and boot-trace surfaces are descriptors only unless a separate
operator-approved workflow runs them. A boot trace requires the documented
reboot/boot-cycle action; this toolkit does not reboot the machine as part of a
normal collection. WPAExporter table analysis is bounded by the selected
preset's table plan and is optional; a missing WPA/WPAExporter installation is
reported as unavailable or unsupported.

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

## Minidumps Object

The optional `minidumps` object appears when `-CollectMinidumps` is specified.
It describes crash-dump collection: source dumps under `%SystemRoot%\Minidump`
are copied **read-only** into the output `minidumps\` folder; the kernel dump
`%SystemRoot%\MEMORY.DMP` is recorded as metadata only and never copied.

| Field | Type | Notes |
|-------|------|-------|
| `sourcePath` | string | `%SystemRoot%\Minidump` (plan + collect). |
| `maxTotalBytes` | integer | Hard cap on copied dump bytes (512 MB). |
| `memoryDumpRecordedNotCopied` | boolean | Plan-mode declaration: MEMORY.DMP is metadata only. |
| `enabled` | boolean | Collect mode only. |
| `status` | string enum | Collect mode only: `completed`, `failed`, `skipped-no-minidumps`. |
| `memoryDump` | object | `{ exists, sizeBytes, lastWriteTimeUtc }` — metadata only. |
| `copiedCount` | integer | Dumps copied this run. |
| `skippedCount` | integer | Dumps skipped (cumulative cap would be exceeded). |
| `totalBytes` | integer | Bytes copied this run. |
| `files` | array | Per-dump `{ Name, SizeBytes, SourceLastWriteTimeUtc }`. |

Each copied dump is certified in the `artifacts` list as `minidumps\<name>`.

## Boot-Failure Logs Object

The optional `bootFailureLogs` object appears when `-CollectBootFailureLogs` is
specified. It covers evidence a non-booting machine leaves behind: the Startup
Repair trail, the boot log (present only when boot logging was enabled), and
component-servicing/setup logs. Oversized logs are recorded with
`skippedReason: "oversized"` — never truncated.

| Field | Type | Notes |
|-------|------|-------|
| `maxBytesPerFile` | integer | Per-file cap (100 MB). |
| `sources` | array of string | Plan-mode source names: `srt-trail`, `boot-log`, `cbs-log`, `setupapi-panther`, `setupapi-error`, `dism-log`. |
| `enabled` | boolean | Collect mode only. |
| `status` | string enum | Collect mode only: `completed`, `failed`. |
| `copiedCount` | integer | Logs copied this run. |
| `skippedOversizedCount` | integer | Logs present but over cap. |
| `sourceEntries` | array of object | Collect mode per-source `{ name, sourcePath, found, sizeBytes, copied, copiedTo, skippedReason }`. |

Each copied log is certified in the `artifacts` list as `bootfailure\<leaf>`.

## Package Object

The optional `package` object appears when `-ZipOutput` is specified. It
describes the case zip produced after collection: a wrapper containing **only
this run's whitelisted artifacts plus the manifest** (stale files in a reused
output folder are never included — the zip certifies only this run's evidence).

| Field | Type | Notes |
|-------|------|-------|
| `destination` | string | Plan mode: parent directory of the output folder. |
| `namePattern` | string | Plan mode: `<output-leaf>-<UTC-stamp>.zip`. |
| `includesManifest` | boolean | The zip always contains `diagnostic-manifest.json`. |
| `enabled` | boolean | Collect mode only. |
| `status` | string enum | Collect mode only: `completed`, `failed`. |
| `zipPath` | string | Full path of the produced zip (Collect mode). |
| `sizeBytes` | integer | Zip size (Collect mode). |
| `sha256` | string (64 hex) | Zip hash (Collect mode). |

The `package` block is written back into the manifest **on disk** after the zip
is produced; the copy of the manifest inside the zip is the pre-package version
(the wrapper is described by the manifest, not vice versa). A failed packaging
attempt still records `status: "failed"` with a `case-package` entry in
`collectionErrors`.

## Case Verification Report

Verify mode is the third and final top-level operating mode:

```powershell
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Verify -InputDirectory C:\Temp\WPD-Case-001
```

It is deliberately read-only. It reads `diagnostic-manifest.json`, verifies the
manifest's safety contract, checks every listed artifact's safe relative path,
existence, byte count, and SHA-256, and validates a recorded case ZIP when one
is present. ZIP validation requires the recorded size and hash, the exact
artifact-plus-manifest whitelist, matching ZIP entry hashes, and agreement
between the outer and in-ZIP artifact metadata.

The verifier resolves a package by its recorded **filename beside the case
directory**, so a case folder and ZIP can be moved together. It does not open an
arbitrary absolute path from an untrusted manifest. Reparse-point input,
artifact, and package paths are rejected. A successful report has
`status: "verified"` and exit code `0`; any integrity or contract failure has
`status: "failed"` and exit code `1`.

The report is emitted to stdout and is described by
`schema/case-verification.schema.json`. It is not a diagnostic manifest, so the
manifest schema's `mode` enum remains limited to `Plan` and `Collect`.

| Field | Meaning |
|-------|---------|
| `reportType` | Always `case-verification`. |
| `status` | `verified` or `failed`. |
| `artifactCount` | Number of artifact entries in the Collect manifest. |
| `verifiedArtifactCount` | Number whose path, size, and SHA-256 matched. |
| `package.status` | `not-present`, `not-verified`, `failed`, or `verified`. |
| `errors` | Integrity or contract failures. Any entry causes exit code `1`. |
| `warnings` | Reserved for non-fatal verifier notices. |

## Safety Object

Every manifest includes a `safety` object that declares the tool's runtime
constraints. These fields are never silently changed between versions.

| Field | Meaning |
|-------|---------|
| `localOnly` | `true` for local runs; `false` when `-RemoteComputer` is used (the collector runs on the target over WinRM and the case folder is pulled back with explicit `-ConfirmRemoteCollection` consent). |
| `readOnly` | Plan mode performs no mutations. |
| `requiresExplicitCollectionConsent` | Collect mode requires `-ConfirmLocalCollection`. |
| `automaticUpload` | Always `false`. Data never leaves the machine automatically. |
| `automaticRemediation` | Always `false`. The tool never modifies system state. |
| `automaticLogClearing` | Always `false`. The tool never deletes logs. |
| `remoteTarget` | Present only in remote mode: the computer the collection runs on. |
| `remoteTransport` | Present only in remote mode: `winrm`. |

## Remote Object

The optional `remote` object appears when `-RemoteComputer` is specified. Plan
mode advertises the target and transport; Collect mode reports the pull-back
result. The tool **never enables WinRM** on the target — `winrmStatus` only
reports availability.

| Field | Type | Notes |
|-------|------|-------|
| `computerName` | string | Target computer. |
| `transport` | string enum | `winrm`. |
| `winrmStatus` | string enum | `ok` or `failed-winrm-unavailable`. |
| `remoteOutputDirectory` | string | Staging directory on the target (removed after the pull). |
| `status` | string enum | Collect mode only: `completed`, `failed`. |
| `pulledFileCount` | integer | Artifacts copied back. |
| `verifiedSha256Count` | integer | Pulled files whose hash matched the remote manifest. |
| `hashVerificationFailed` | boolean | True if any pulled file did not match. |
| `pulledAtUtc` | string (date-time) | When the pull-back finished. |

In Collect mode the local `diagnostic-manifest.json` is the **remote** manifest
(the collection record produced on the target) plus this `remote` block.

## SHA-256 Manifest Guarantee

Every data artifact listed in `diagnostic-manifest.json` (excluding the manifest
itself) has a corresponding entry in the `artifacts` array with a SHA-256 hash.
The manifest file is never self-referenced. This allows consumers to verify
integrity of all collected files by recomputing hashes and comparing against the
manifest.

The following artifacts are written and registered **before** the final manifest
artifact index is computed: `findings.json`, `report.html`, `disk-samples.json`,
`volume-metrics.json` and, when boot-failure collection is requested,
`servicing-log-analysis.json`.
so they are hashed, included in the case ZIP and covered by Verify and remote
pull. `report.html` is generated before its own hash exists, so its artifact
index intentionally omits itself (a file cannot contain its own SHA-256); the
final manifest still lists `report.html` and Verify recomputes it.

## Findings and Report

`findings.json` is an array of finding objects:

| Field | Meaning |
|-------|---------|
| `category` | `cpu-pressure`, `memory-pressure`, `memory-paging`, `disk-pressure`, `disk-latency`, `disk-space`, `crash-evidence`, `servicing-failure`, or `coverage`. |
| `sourceArtifact` | The artifact the metric came from, such as `performance-samples.csv`, `livekernelreports.json`, `servicing-log-analysis.json`, or `diagnostic-manifest.json`. |
| `metric` | The measured field (for example `AverageCpuLoadPercent`, `ReadLatencySeconds`). |
| `windowStart` / `windowEnd` | UTC timestamps of the first/last contributing sample. Sustained findings cite a real window; state/coverage findings may be `null`. |
| `measuredValues` | The measured numbers behind the finding. |
| `ruleCondition` | The human-readable rule that fired. |
| `uncertainty` | What the metric does **not** prove (correlation is not causation). |
| `nextSteps` | Suggested next evidence-gathering step. |
| `suggestedWprProfile` | A profile from the `-WprProfile` ValidateSet, or `null`. |

Sustained rules require a minimum number of consecutive finite readings, search
the whole series (a burst followed by recovery is found), treat a null reading as
breaking the streak and never infer from a single post-run reading.
`PagesInputPersec` is documented as pages read to resolve hard page faults, not
an exact hard-fault count.

`report.html` renders the same findings with all interpolated data
HTML-encoded, fixed relative evidence links and no scripts or external assets.

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

The `crashAnalysis` object joins crash evidence from the bounded System event
query with the minidumps and LiveKernelReports collected into the case:

| Field | Meaning |
|-------|---------|
| `bugchecks` | BugCheck 1001 events decoded to their `0x…` bugcheck codes (e.g. `0x0000001A`). |
| `unexplainedShutdowns` | Kernel-Power 41 events with **no** bugcheck within 5 minutes — typically a hard freeze, power loss, or thermal cutout rather than a Windows-detected crash. |
| `eventLookbackStartUtc` / `eventLookbackEndUtc` | The bounded event-query interval used for event correlation. A dump outside this interval is retained and labelled, not discarded. |
| `eventCorrelationWindowMinutes` | The maximum time distance used to associate a dump's source write time with a BugCheck event. |
| `minidumps` | Per-dump metadata with parsed filename date, optional event-correlated bugcheck code, correlation status, and a problem signature. This does not decode the dump binary. |
| `minidumpSignatures` | Dedupe summary of minidumps by problem signature, with a bounded sample of filenames. |
| `liveKernelReports` | Per-file LiveKernelReports metadata with a filename-derived class such as `livekernel:watchdog` or `livekernel:whea`. The class is a hint only. |
| `liveKernelSignatures` | Dedupe summary of LiveKernelReports by filename-derived problem signature. |

The minidump `eventCorrelationStatus` values are `matched-bugcheck`,
`no-matching-bugcheck`, `outside-event-lookback`, and `ambiguous-bugcheck`.
When `SourceLastWriteTimeUtc` is available, it is authoritative for the event
lookback; a stale filename date cannot suppress an in-window match, and a source
time after the lookback end is outside even if a nearby event was queried.
Filename dates are used as an outside-lookback hint only when source time is
unavailable. Correlation is evidence, not causation: a bugcheck code names the crash *type*,
but naming the exact driver usually needs WinDbg `!analyze -v` against the
matching minidump. LiveKernelReports filename classes do not prove a WHEA,
watchdog, or TDR cause.

## Servicing Analysis Block

When `-CollectBootFailureLogs` is requested and consented, the collector scans
the copied `bootfailure\` files with a bounded byte-window reader. It emits
`servicing-log-analysis.json` and stores the same object as `servicingAnalysis`
in the manifest. The analysis artifact contains no raw log lines.

| Field | Meaning |
|-------|---------|
| `status` | `completed` when all analyzed inputs are complete, `partial` when one or more requested logs are unavailable or truncated, or `failed` only when the analyzer stage itself throws. |
| `maxScanBytes` | Per-file scan bound. Files over the bound are reported as `oversized`, never truncated. |
| `truncatedLogCount` | Number of readable log prefixes that reached the byte bound; these make the aggregate result `partial`. |
| `unavailableLogCount` | Number of requested sources that were not copied or otherwise unavailable to the analyzer. |
| `error` | Top-level analyzer error when `status` is `failed`; otherwise omitted or null. |
| `logs` | Per-source status, copied artifact, line counts, matched-line counts, bounded bytes scanned, and normalized signatures. Non-copied sources remain visible as `not-copied`. |
| `logs[].scanStatus` | `not-copied`, `invalid-metadata`, `missing`, `oversized`, `reparse-point`, `hardlink`, `identity-unavailable`, `completed`, or `failed`. Reparse-point and multi-link entries are refused rather than followed. |
| `logs[].bytesScanned` / `logs[].scanTruncated` | Actual bytes fed to the analyzer and whether the configured byte bound was reached; these remain bounded even if the source grows while it is read. |
| `logs[].signatures` | A normalized token such as `CBS_E_INVALID_PACKAGE`, `ERROR_SXS_COMPONENT_STORE_CORRUPT`, an HRESULT such as `0x800F081F`, or `generic-error`, with count and first/last line numbers. |

Text signatures are evidence for review, not a package-health verdict. The
collector does not run DISM/SFC, repair servicing state, or claim complete
coverage of every CBS/DISM grammar. Raw copied logs remain the source of truth
for context around a reported line range. The findings engine emits
`servicingEvidencePartial` when at least one requested log was scanned and
another was unavailable; it emits `servicingEvidenceUnavailable` when none was
scanned, and `servicingAnalysisFailed` when the analysis stage itself failed.

## Network State Block

The `network` object appears in both manifest modes. In Plan mode it lists the
planned read-only sub-collections. In Collect mode it summarizes the captured
`network-state.json` artifact so the technician can see the connectivity
verdict without opening the file.

| Field | Meaning |
|-------|---------|
| `subCollections` | (Plan mode) The read-only network-state sub-collections that will be captured after consent: IP configuration, adapter status, connection profiles, DNS server configuration, DNS client cache, IPv4 routing table, ARP table, DNS-vs-ping split test, hosts file, proxy settings, TCP connections, and security-software inventory. |
| `status` | (Collect mode) `completed` when `network-state.json` was written, `failed` otherwise. |
| `artifact` | (Collect mode) Always `network-state.json`. |
| `dnsVsPing.rawIpReachable` | Whether at least one raw-IP ping (`8.8.8.8`, `1.1.1.1`) succeeded — link/routing works without DNS. |
| `dnsVsPing.dnsResolutionOk` | Whether at least one public name (`google.com`, `cloudflare.com`, `microsoft.com`) resolved. |
| `dnsVsPing.verdict` | `dns-and-connectivity-ok` (both work), `dns-failure` (raw IPs reachable but names do not resolve — hosts file, proxy, or DNS-server issue), `icmp-blocked-or-partial` (names resolve but ICMP to public IPs fails), `connectivity-failure` (neither works), or `inconclusive`. |
| `securitySoftwareMatches.processMatches` | (Collect mode) Number of running processes matching the EDR/AV/DNS-filter/firewall/proxy/VPN keyword inventory. |
| `securitySoftwareMatches.installedSoftwareMatches` | (Collect mode) Number of installed programs (from both 64-bit and WOW6432Node Uninstall keys) matching the same inventory. |
| `sectionErrorCount` | (Collect mode) Number of network-state sub-collections that failed individually; each failure is also recorded in `collectionErrors` with a `network-state-<section>` stage. |

`network-state.json` carries the full detail: raw `ipconfig /all` and `arp -a`
output, per-adapter/per-interface tables, the complete DNS-vs-ping results with
the resolved addresses, every active hosts-file entry, `netsh winhttp` and
Internet Settings proxy values, established/listening TCP connections, and the
full security-software matches with the keyword list used. All of it is
read-only and collectible from a standard (non-admin) account.
