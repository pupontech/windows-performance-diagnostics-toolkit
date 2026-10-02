# Audit: v1.0.0 repository vs. the evidence-driven specification

Scope: read-only audit of `/root/Projects/windows-performance-diagnostics-toolkit/main` at
branch `feat/crash-servicing-findings`, including the staged (uncommitted)
crash-servicing WIP. No source, test, doc, workflow, or git state was modified;
this file is the only artifact written. Version audited: `VERSION` = 1.0.0
(`src/Invoke-WindowsPerformanceDiagnostics.ps1:91` fallback constant, kept in
sync by `tests/test_plan_mode.py:820`).

Legend for status: IMPLEMENTED / PARTIAL / MISSING / MISLEADING / UNVERIFIED
(UNVERIFIED = code exists but cannot be exercised on this Linux host without a
Windows run).

Reference document: the user specification pasted at session start (100
sections). Section numbers below are the specification's section numbers.

---

## 1. Entry points (spec 2, 94)

| Item | Status | Evidence |
| --- | --- | --- |
| Single script entry point, three modes | IMPLEMENTED | `src/...ps1:1-83` `param()`; `:3` `ValidateSet('Plan','Collect','Verify')`, default `Plan` |
| Collect requires explicit consent | IMPLEMENTED | `:16` `-ConfirmLocalCollection`; refusal covered by `tests/test_plan_mode.py:81` |
| Windows-only refusal before collection | IMPLEMENTED | `:4583` `[Environment]::OSVersion.Platform -ne Win32NT`; test `tests/test_plan_mode.py:91` |
| Launchers | IMPLEMENTED | `Run-Diagnostics.bat`, `START-HERE.bat`, `Pull-BootFailureLogs.bat` (tests `:854`, `:1262`, `:741`) |
| Remote collection (extra, not in spec) | IMPLEMENTED | `:39-45` remote params; `:162-237`, `:282-653`; read-only + hash-verified |
| Tier 0/1/2/3 layer split (spec 3) | MISSING | No tier concept anywhere; one monolithic Collect path from `:4535` to `:6101` |
| REPRO mode (spec 4) | PARTIAL | `-PerformanceMode` (`:56`) gives one shared window (counters + WPR), not the 10-step Repro workflow |
| FLIGHT RECORDER mode (spec 4, 63) | MISSING | `grep -c logman` = 0, no circular BLG, no size-capped counter ring buffer |
| `-Preset` functional dispatch (spec 61) | MISSING (misleading) | see section 10 |

## 2. Collectors (spec 2, 83)

Implemented collectors and their real data sources:

- `Get-MemoryMetrics` `:3229` (read `Win32_PerfFormattedData_PerfOS_Memory` `:3253`)
- `Get-KernelPoolMetrics` `:2629` (`PerfOS_Memory` `:2638`)
- `Get-PageFileMetrics` `:2653` (`Win32_PageFileUsage` `:2663`)
- `Get-PerProcessMemorySample` `:2593` (`Win32_PerfFormattedData_PerfProc_Process` `:2607`)
- `Get-DiskMetrics` `:2978` (formatted `PerfDisk_PhysicalDisk` `:2990`), `Get-RawDiskMetrics` `:3017` (raw `:3031`), latency/throughput/queue built in `Get-DiskCounterDeltas` `:3135`
- `Get-GpuMetrics` `:2712` (`Get-Counter` GPU Engine `:2754`, GPU Process Memory `:2777`; `Win32_VideoController` `:2735`)
- `Get-VolumeMetrics` `:3274` (`Win32_Volume` `:3282`), `Get-StorageTopology` `:1135`, `Get-VolumeStorageMapping` `:1193`
- `Get-NetworkState` `:2209` with bounded DNS `:2179`, `Get-UdpEndpointSample` `:1379`
- `Get-EventsSafe` `:908`, `Get-EventsWithRawXml` `:1019`, `Add-IncidentWindowLabels` `:1099`
- `Get-CrashAnalysis` `:1896`, `Get-ServicingLogAnalysis` `:1692` (staged WIP)
- Defender: `Invoke-ConsentedCapture` `:5755-5770`, `New-MpPerformanceRecording` `:5769` (staged WIP adds the crash/servicing pair)

Collector framework (spec 83) - MISSING. There is no per-collector record with
`status/start/end/duration_ms/records/warnings/errors`. Failures land in a flat
list `Add-CollectionError` `:123` / `Add-CollectionErrorText` `:132`, emitted as
`manifest.collectionErrors` `:5915`. Independent failure is respected (each
stage is wrapped in try/catch, e.g. `:4989-5032`), but there is no uniformity,
no duration, and no records count.

Collectors the specification names that are MISSING entirely (zero hits in
source): `Get-WinEvent` beyond System/Application, `Get-StorageReliabilityCounter`,
`Get-PhysicalDisk`, `Get-Disk`, `Get-PnpDevice`, `Win32_PnPSignedDriver`,
`fltmc`, `powercfg`, `wpr -boottrace`, `WaitChain`/WCT, `procdump`, `poolmon`,
`Get-MpPerformanceReport`, `Win32_ReliabilityRecords`, `Get-Win32_StartupCommand`,
`Get-StorageFirmwareInformation`, perflib health.

## 3. Sampling (spec 3, 7, 64)

- Sample loop `:4971-5180`; interval `-SampleIntervalSeconds` default 1, range
  1..30 (`:68`); cadence scheduled against the original start to avoid drift
  (`:5174-5178`). Sub-second sampling is impossible by construction, so the
  spec's "do not query below 1 s" rule is satisfied trivially.
- **Repeated full CIM scans per sample (spec 64 violation).** Every iteration
  re-queries `Win32_OperatingSystem`, `Win32_Processor` and `Win32_LogicalDisk`
  (`:4973-4975`), plus `PerfOS_Memory` via `Get-MemoryMetrics` `:4983`, plus
  the whole process perf class via `Get-PerProcessMemorySample` `:4990`. Static
  inventory is not hoisted out of the loop.
- No batched PDH collection: no PDH API use; counters come from the formatted
  WMI perf provider classes (`Win32_PerfFormattedData_*`), which are per-query
  formatted snapshots. `Get-Counter` is used only for GPU (`:2754`, `:2777`).
- Long-interval black-box modes (5/10/15 s) are expressible via the parameter
  but no preset selects them (presets are metadata only, section 10).
- Perflib health check (spec 7) - MISSING, no `perflib-health.json` producer.
  Practical effect: when the WMI perf classes are unavailable, `Get-MemoryMetrics`
  returns `$null` `:3268-3270` and callers record coverage/errors, which is the
  correct no-data-as-not-healthy behavior, but nothing reports
  `healthy/partial/unavailable/corrupted-suspected`.

## 4. Process identity and process telemetry (spec 8, 9, 10, 23)

- PID+StartTime identity IS implemented for the interval CPU path:
  `Get-ProcessSnapshotKey` `:2832-2853` (key = Id + StartTime.Ticks),
  `New-ProcessCpuSnapshot` `:2855`, `Compare-ProcessCpuSnapshots` `:2877`,
  `Get-ProcessCpuPercentage` `:2920`; start/end snapshots at `:4873` and
  `:5432`. Reused PIDs and protected processes yield `unknown`, not zero
  (`:2945-2953`); tests `:1795` (PID reuse), `:1727`, `:1777`.
- Process V2 - MISSING (no `Process V2`/`% Processor Utility` usage).
- Continuous process telemetry (spec 9) - PARTIAL/MISSING. Process CPU is a
  two-point delta (start vs end of the whole window), so a short-lived CPU spike
  between endpoints is invisible; `Compare-ProcessCpuSnapshots` `:2907-2915`
  emits name, Id, CPU, percent, WorkingSet64, Handles, Path - no user/kernel
  split, no I/O bytes, no page faults, no thread count, no parent PID, no
  session, no executable path guarantee, no per-sample history.
- Per-sample process memory DOES run continuously (`:4985-5005`, artifact
  `process-memory-samples.csv`) and carries PrivateBytes/WorkingSet/
  PageFileBytes/VirtualBytes/pool/HandleCount/ThreadCount (`:2611-2626`),
  but keyed by `Name` + `IDProcess` only (`:2613-2614`) - no StartTime - so
  duplicate names (svchost, chrome, RuntimeBroker) can be conflated across
  samples. This is the spec 8 concern and it is only half-fixed.
- Service-host attribution (spec 10) - MISSING (no service-name-to-PID map).
- Handle/thread leak analysis (spec 23) - MISSING as a rule; counts are
  collected, no growth detection or baseline.

## 5. CPU model (spec 11, 12, 13, 14, 15)

- CPU value = average of `Win32_Processor.LoadPercentage` (`:4977-4981`).
  IMPLEMENTED but coarse. `% Processor Utility`, `% Privileged Utility`,
  user vs privileged split, `% DPC Time`, `% Interrupt Time`,
  `Interrupts/sec`, `DPCs Queued/sec`, `Processor Queue Length`,
  `Context Switches/sec` - all MISSING (0 hits).
- Per-core analysis (spec 12) - MISSING. `LoadPercentage` is per-socket, and
  the loop averages it (`:4980`), so "one logical processor saturated while
  total is 18%" cannot be produced. Contradicts the definition of done.
- Scheduler analysis (spec 13) - MISSING (no queue length, no ETW ReadyThread).
- Kernel/DPC/ISR analysis (spec 14) - MISSING.
- Application CPU classification (spec 15) - PARTIAL via findings
  `cpu-pressure` + `commit-attribution` (`:3534`, `:3558`); no user/kernel
  classification, no scheduling-starvation class.

## 6. WPR (spec 2, 47, 48, 49, 50, 51, 52, 53)

- Bounded memory-mode capture: `Start-WprBoundedCaptureJob` `:1241-1378`;
  profile chosen by `-WprProfile` ValidateSet `GeneralProfile|CPU|DiskIO|FileIO|
  Network|Power|GPU|Registry` (`:22-23`); deliberately no `-filemode`
  (`:1248-1252`); stop signalled by sentinel written when sampling ends
  (`:5188-5192`); measured duration recorded, not requested
  (`:5822-5838`); exit-code gates `:5276-5292`; oversized ETL removed and
  reported (`:5256`); advisory `MaxFileMB` cap (`:1258-1261`). Tests:
  `tests/test_wpr_bounded_capture.py` (4), `tests/test_plan_mode.py:883`.
- WPR markers (spec 5) - MISSING. The "marker" is a toolkit-internal file/Enter
  poll (`:4927-4950`, detection `:5139-5154`, retention
  `Select-MarkerRetainedSeries` `:1441`). `wpr -marker` is never invoked (0
  hits), so nothing aligns the PerfMon window to the ETL by an in-trace marker;
  `manifest.incident.markerSource` is `file-or-enter` (`:5147`).
- On/Off boot tracing (spec 39, 40) - MISSING (`-boottrace` 0 hits).
- File-mode / circular BLG flight recorder (spec 4, 48, 63) - MISSING.
- WPAExporter automation (spec 51) - MISSING (0 hits). No `wpr-analysis/*.csv`
  is produced, and no CPU Sampled vs Precise distinction exists (spec 53).
- Incident-window WPA analysis with baseline comparison (spec 52, 59) -
  MISSING. `Get-SustainedWindow` `:3346` finds a sustained run anywhere in the
  series; there is no pre/in/post comparison.
- Trace validation (spec 91) - PARTIAL: ETL existence `:5292`, zero/oversize
  handling `:5256`, exit codes `:5276-5280`, `Test-CaptureWindowCoverage`
  `:1505`. No provider presence check, no ETW lost-event detection, no
  WPAExporter validation.
- Cleanup/recovery (spec 50) - PARTIAL. WPR is stopped on the normal path
  (`:5188-5200`, `Wait-Job -Timeout 180` + `Stop-Job`) and oversized traces are
  removed. There is NO `trap`/`CancelKeyPress` handler (0 hits) and no startup
  detection of abandoned sessions from a previous failed run, so Ctrl+C or a
  host kill during `-PerformanceMode` can leave a WPR session behind. `finally`
  usage exists inside helper functions (`:403`, `:730`, `:969`, `:1084` etc.) but
  not around the top-level capture in a way that survives host termination.

## 7. Event log engine (spec 69, 70)

- Queried logs: `System` (24 h lookback `:5474-5475`) and `System`+`Application`
  around the incident window (`:5498`). Implementation uses
  `EventLogQuery`/`EventLogReader` with per-log XPath and a bounded count
  (`:930-983`, `:1019-1098`); newest-first and unrenderable-record handling are
  tested (`tests/test_plan_mode.py:1116`).
- MISSING providers compared with spec 69: Diagnostics-Performance, WHEA-Logger,
  Disk, StorPort, StorNVMe, NTFS, Display, Kernel-Power, Kernel-Processor-Power,
  Kernel-PnP, Resource-Exhaustion-Detector, Windows Error Reporting,
  Application Error/Hang, Service Control Manager, WLAN, Defender, Windows
  Update, Search. `WHEA` appears only as a LiveKernelReports filename
  classification hint (`:2028`), i.e. not as a WHEA-Logger query.
- Grouping/dedup of repetitive events (spec 70): PARTIAL - `Get-CrashAnalysis`
  deduplicates LiveKernel signatures (`:1928-1960`) and in/out-of-window labels
  are kept (`:1099`), but there is no first/last/count/proximity grouping for
  repeated provider events.

## 8. Memory, storage, network, GPU, power, boot, reliability (spec 19-46)

| Spec area | Status | Evidence / gap |
| --- | --- | --- |
| Memory model, not Pages/sec-only (19) | PARTIAL | `Get-MemoryMetrics` `:3229-3272` reads committed/limit/available + page reads/writes/input/output; `memory-paging` finding `:3646` uses paging input; no `Pages/sec` misuse found. Missing: `% Committed Bytes In Use`, explicit commit/physical/pagefile pressure taxonomy, hard-fault vs file-backed distinction |
| Pagefile analysis (20) | PARTIAL | `Get-PageFileMetrics` `:2653`; no automatic/system-managed state, no peak usage trend, no crash-dump requirement context |
| Kernel pool leak detection (21) | PARTIAL | series collected `:5011-5027` into `kernel-pool-samples.json`; no sustained-growth rule, no pool-tag mapping, no `pool-analysis.json`, no PoolMon/WPR Pool escalation |
| User-mode leak escalation (22) | MISSING | no Heap/VirtualAlloc/Resident Set/Handle WPR profiles, no original-state save/restore |
| Process memory growth / handles / threads (23) | PARTIAL | data present (`:2593`), growth rules absent (findings only cover `commit-attribution`, `memory-pressure`, `memory-paging`) |
| Storage latency (24) | IMPLEMENTED (core) | raw disk deltas `:3017-3228`, `disk-latency` `:3710`, `disk-pressure` `:3691`, `disk-space` `:3765`; percentiles p95/p99 are NOT computed (only sustained-run peak) |
| File I/O attribution (25) | MISSING | no ETW File I/O, no privacy modes |
| Storage health / reliability counters (26) | MISSING | no `Get-StorageReliabilityCounter`, no temperature/wear/errors; the data will silently be absent with no `UNSUPPORTED / NOT EXPOSED` status |
| Volume context (27) | PARTIAL | `Get-VolumeMetrics` `:3274`, `Get-VolumeStorageMapping` `:1193` (pagefile host + backing disk); no BitLocker/TRIM |
| Filesystem filters (28) | MISSING | no `fltmc filters/instances` |
| Defender performance analysis (29) | PARTIAL | consent-gated `New-MpPerformanceRecording` `:5769` (staged); no `Get-MpPerformanceReport` parsing, so no top scans/files/processes |
| Search/indexer context (30) | MISSING | 0 hits |
| Network performance (31) | PARTIAL | `Get-NetworkState` `:2209` covers adapters, link speed, errors, UDP endpoints, DNS vs ping; no TCP retransmissions/resets/failed connections counters, no utilization-vs-link-speed math |
| Optional network ETW (32) | PARTIAL | `-WprProfile Network` exists; not tied to a network preset |
| GPU (33) | PARTIAL | `Get-Counter` GPU engine/process memory `:2754`,`:2777`, `gpu-metrics.json`; `Win32_VideoController` `:2735`; no GPU resets/TDR events, no DWM/composition, no frame timing |
| ui-stutter preset (34) / audio-glitch preset (35) | MISSING | no such presets, no Desktop Composition / Audio Glitches profiles |
| Power and CPU performance state (36) | MISSING | 0 hits for `powercfg`, no power scheme/AC/battery/processor state, no `Processor Utility` |
| Thermal limitations (37) | MISSING | nothing collected; the conservative wording requirement is therefore vacuously met but unverifiable |
| Optional power analysis (38) | MISSING | no `-PowerAnalysis` |
| Boot quick / boot deep (39, 40) | MISSING | no Diagnostics-Performance events, no startup inventory, no WPR On/Off; `boot-slowdown` preset is metadata only |
| Startup inventory (41) | MISSING | 0 hits |
| Reliability/change history (42) | MISSING | no `Win32_ReliabilityRecords`, no change timeline; only the 24 h System view |
| WER / LiveKernel (43) | PARTIAL | LiveKernelReports filename classes with explicit hint-only uncertainty `:3911`; no WER report/bucket metadata, no dump path listing beyond minidump collection |
| WHEA (44) | MISSING | no WHEA-Logger analysis, no recurrence weighting |
| Driver/device health (45) | MISSING | no `Get-PnpDevice`, no `Win32_PnPSignedDriver` |
| Symbols (46) | MISSING | no symbol path/cache detection, no `-AllowSymbolDownload`, no `MODULE-LEVEL ATTRIBUTION ONLY` marker (only WPR's own managed-symbol side files, `:1260`, `:1338`) |
| VBS/virtualization context (67) | MISSING | 0 hits |
| Integrity checks (68) | MISSING | no `-IntegrityChecks` (also correct: no restore path exists, `-RestoreHealth`/`sfc /scannow` absent) |
| Hardware inventory (66) | PARTIAL | `:4836-4873` `Win32_OperatingSystem`/`Win32_ComputerSystem`/`Win32_Processor`; no SMBIOS/DIMM/BIOS/board/battery/NIC inventory, no source attribution |

## 9. Findings, data quality, evidence provenance (spec 54-59, 71-74)

- Engine: `Evaluate-Findings` `:3418-4003` plus HTML rendering `:4004-4286`.
  Categories produced: `evidence-coverage` `:3476`, `coverage` `:3495`,
  `commit-attribution` `:3534`, `cpu-pressure` `:3558`, `memory-pressure`
  `:3624`, `memory-paging` `:3646`, `disk-pressure` `:3691`, `disk-latency`
  `:3710`, `disk-space` `:3765`, `crash-evidence` `:3836`-`:3900`,
  `servicing-failure` `:3962`.
- Finding shape: `sourceArtifact`, `metric`, `windowStart`, `windowEnd`,
  `measuredValues`, `ruleCondition`, `uncertainty`, `nextSteps`,
  `suggestedWprProfile` (e.g. `:3558-3576`). This partially satisfies spec 55
  (provenance to a file) but there is NO `evidence[]` array with per-value
  citations, NO `evidence-index.json`, NO `id`, `severity`, `confidence`,
  `title`, `summary`, `correlations`, `possible_causes`, `limitations`.
  `grep -c confidence` = 0, so the spec's High/Medium/Low confidence model is
  absent (and no fake percentages were invented - that requirement is met).
- Finding types from spec 71 covered: only 6 of ~45. Missing CPU
  (`single-core-saturation`, `dpc-pressure`, `long-dpc`, `interrupt-pressure`,
  `scheduler-pressure`, `short-process-cpu-spike`), all Responsiveness types,
  `hard-fault-pressure`, `pagefile-pressure`, `paged/nonpaged-pool-growth`,
  `handle-growth`, `thread-growth`, `sustained-disk-latency`,
  `disk-queue-pressure`, `excessive-process-io`, `storage-health-warning`,
  `storage-controller-reset`, all GPU/Network/Boot/Power/Hardware/Reliability
  types.
- Data quality engine (54) - MISSING (`data-quality.json` absent; "collector
  success / sample gaps / dropped ETW / truncated trace / overhead" are not
  aggregated). Some quality signals exist ad hoc: `coverage` findings for
  no/insufficient samples `:3578-3600`, `Get-FiniteNumericCount` `:3323`,
  `Get-SustainedWindow` `:3346` requiring 5 consecutive samples `:3463`.
- Threshold centralization (57) - MISSING/misleading: thresholds are inline
  magic numbers (`80` at `:3553`, `5` consecutive at `:3463`, per-rule literals
  inside `:3600-4000`). No `config/diagnostic-rules.json`.
- Duration/percentile model (58) - PARTIAL: sustained-run detection with peak
  and count; no p95/p99, no percent-of-incident-above-threshold.
- Baseline vs incident (59) - MISSING; `Get-SustainedWindow` searches the whole
  series instead.
- No-data-is-not-healthy (74) - IMPLEMENTED as a design rule and tested
  (`tests/test_plan_mode.py:1974`, `:1997`, `:2089`, `:2111`); findings use
  `uncertainty` text and coverage findings instead of an "all healthy" claim.
  NO EVIDENCE OF section - PARTIAL: `ConvertTo-FindingsHtml` renders coverage
  and evidence-coverage sections (`:4183-4210`) and only states a result when
  attribution findings exist (`:4251`), but there is no first-class
  "No strong evidence of" checklist gated on collector quality.
- ROOT CAUSE NOT IDENTIFIED (72) - MISSING as an explicit classification.

## 10. Presets (spec 61, 62, 63)

- Declared: `baseline|cpu-heavy|memory-pressure|storage-io|network-io|
  boot-slowdown|application-freeze` `:49-50`. The spec's list is different:
  `general|cpu-heavy|memory-pressure|memory-leak|storage-io|network|gpu|
  ui-hang|ui-stutter|boot-slowdown|audio-glitch|power|intermittent`.
- MISSING (`ui-stutter`, `audio-glitch`, `intermittent`, `gpu`, `power`,
  `memory-leak`) and absent (`general` is only the implicit default).
- **MISLEADING: presets only change metadata.** Every use of `$Preset` is
  `symptom.preset` recording or remote forwarding: `:4535`, `:4542`,
  `:4663-4664`, `:5801`, `:6064-6075`; the HTML echoes it `:4133-4135`. No
  branch selects counters, WPR profile, detail level, logging mode, duration,
  analysis modules, event channels, escalation options or trace budget. Test
  `tests/test_plan_mode.py:1538` and `:1710` verify recording, not behavior.
  This is exactly the spec 2 anti-pattern "presets that only change metadata".

## 11. Report, manifest, schemas, machine-readable output (spec 75-77, 84-87)

- HTML report: `ConvertTo-FindingsHtml` `:4004`; self-contained offline and
  XSS-escaped (tests `:2026`, `:2059`); no health score (tests `:2089`, `:2111`).
  Order is not the spec's 19-section order (no technician summary block, no
  visual timeline, no incident-window process rankings).
- Technician summary (spec 75) - PARTIAL: an incident/marker table exists
  (`:4083-4090`) and findings are grouped, but there is no
  PRIMARY/SECONDARY/confidence/NO-STRONG-EVIDENCE/RECOMMENDED NEXT summary.
- Report timeline (spec 76) - MISSING.
- Process tables (spec 77) - PARTIAL: top-process snapshot (`top-processes.json`
  `:5440`) and process-memory top (`:5383`); rankings are whole-capture, not
  incident-window.
- Recommendations (spec 78) - PARTIAL: `nextSteps` + `suggestedWprProfile` per
  finding (`:3571`, `:3574`); not evidence-linked in the spec's sense (no
  evidence references).
- Output structure (spec 84) - PARTIAL/MISLEADING vs the documented tree. The
  real output directory is flat: `diagnostic-manifest.json`, `diagnostic-plan.json`,
  `performance-samples.csv` `:5339`, `process-memory-samples.csv` `:5350`,
  `process-memory-top.json` `:5383`, `kernel-pool-samples.json` `:5391`,
  `udp-samples.json` `:5400`, `gpu-metrics.json` `:5410`, `pagefile-metrics.json`
  `:5420`, `top-processes.json` `:5440`, `network-state.json` `:5459`,
  `system-events-last-24-hours.json` `:5478`, `incident-events.json` `:5545`,
  `livekernelreports.json` `:5570`, `disk-samples.json` `:4334`,
  `volume-metrics.json` `:4346`, `servicing-log-analysis.json` `:4355` (staged),
  `findings.json` `:4366`, `report.html` `:4378`, `wpr-trace.etl`,
  `incident-marker.txt` `:4930`. There is no `case/` tree, no `inventory/`,
  `telemetry/`, `events/`, `wpr-analysis/`, `escalation/` directories, and none
  of `case.json`, `incidents.json`, `collection-coverage.json`,
  `data-quality.json`, `evidence-index.json`. Empty artifacts are correctly
  avoided (`:4342`) - that spec rule is met.
- Case manifest (spec 85) - PARTIAL. Present `:5804-5917`: `schemaVersion`
  `:5805`, `toolName`, `toolVersion` `:5807`, `mode`, `startedAtUtc`,
  `completedAtUtc`, `outputDirectory`, `scope` `:5812`, `captureWindow` `:5822`,
  `incident` `:5839`, `safety` `:5850`, `system` `:5851`, `processMemory`,
  `gpu`, `pageFile`, `kernelPool`, `storageMapping`, `systemEventLog`,
  `crashAnalysis`, `network` `:5884`, `incidentEvents` `:5904`,
  `liveKernelReports`, `collectionErrors` `:5915`, `artifacts` `:5916`, plus
  `wpr` `:5951` only when requested. MISSING from the spec list: elevation
  status, enabled collectors, collector results, optional tooling detected,
  privacy mode. File hashes exist via `Get-ArtifactMetadata` `:654` and are
  verified by `Verify` mode, but are not part of the manifest's own field set.
- Schema versioning (spec 96) - IMPLEMENTED conservatively: `1.0` -> `1.1`
  (symptom/preset) -> `1.2` (performance/marker) `:5800-5802`; the staged diff
  widens `schema/diagnostic-report.schema.json` by 292 lines for the
  incident-crash surface. `schema/case-verification.schema.json` (86 lines)
  covers Verify mode. Version string stays 1.0.0; the staged WIP does not bump
  `VERSION` or add a new schema-version branch.
- Machine-readable conclusions (spec 86) - IMPLEMENTED: findings/report are
  derived from `findings.json` `:4366`, not HTML-only.

## 12. Privacy (spec 80)

MISSING. `grep -c PrivacyMode` = 0, no `-PrivacyMode Standard|Redacted|Full`, no
path hashing, no IP/user redaction, no command-line suppression flag. Privacy is
only prose (`README.md:28`, `:249`, `SECURITY.md`). Paths and process names ARE
written (`:5482-5540` event/process artifacts), so the collector's actual
behavior is closest to the spec's `Full` mode with no way to downgrade. Positive:
no password/token/browser-history collection was found.

## 13. Error handling and cleanup (spec 50, 83)

- Errors: `Add-CollectionError`/`Add-CollectionErrorText` `:123`,`:132`; the
  accumulator is an ArrayList deliberately so late errors still reach the
  manifest (`:116-122`, `:5915`); three consecutive sample failures break the
  loop `:5129-5131`; per-stage try/catch throughout. IMPLEMENTED but not
  framework-shaped (spec 2).
- Cleanup: WPR stop/sentinel/Wait-Job/Stop-Job `:5188-5230`; marker job cleanup
  `:5304`; oversized trace + symbol side files removed `:5256`. MISSING: Ctrl+C
  handler, abandoned-session detection at startup, logman cleanup (none exist),
  restoration verification step.

## 14. Tests and CI (spec 88-93)

- Tests: 144 Python tests in 4 files - `tests/test_plan_mode.py` (117),
  `tests/test_incident_capture.py` (11), `tests/test_crash_servicing_findings.py`
  (12; 9 at the time of the staged diff, see spec 16a), `tests/test_wpr_bounded_capture.py`
  (4). They exercise PowerShell
  purity by shelling out to `pwsh` (`tests/test_crash_servicing_findings.py:22`,
  `tests/test_incident_capture.py:33`) plus subprocess runs of the real script.
- Pester (spec 88 names Pester) - MISSING: no `*.Tests.ps1` anywhere.
- Covered from the spec 88 list: process identity/PID reuse (`:1795`),
  short-lived-process handling is NOT covered, sampling gaps
  (`:1997`, `:1128`), thresholds/duration (`:1946`, `:1974`), confidence logic
  (absent by design), incident windows (`test_incident_capture.py:210`,`:247`),
  missing counters (`:1860`, `:1878`, `:1895`), collector failures,
  corrupted/partial input, event correlation (`:1140`), findings, report
  rendering (`:2026`-`:2111`), evidence links (not applicable - no evidence
  index), coverage statuses, cleanup (`:1128` only), schema validation (`:836`,
  `:1233`, `:1490`).
- Fixture scenarios (spec 89): only a handful of synthetic fixtures exist
  (unavailable CIM, CPU pressure, insufficient samples, crash/servicing). The
  30-scenario matrix has no representation.
- Windows VM testing (spec 90) - PARTIAL: GitHub-hosted Windows runners run
  Plan/Collect/Verify smoke plus real launcher runs
  (`.github/workflows/ci.yml:10` linux-verify, `:42` windows-verify matrix
  2022/2025, `:363` wpd-live-gates, `:603` wpd-release-flow). No VM, no
  scenario presets, no ui-hang/intermittent/boot runs.
- Output validation (spec 92) - PARTIAL: JSON/schema validation in tests
  (`tests/test_plan_mode.py:1233`, `tests/test_incident_capture.py:494`,
  `tests/test_crash_servicing_findings.py:485`) and `Verify` mode re-hashes
  artifacts (`:282-653`). No CSV/HTML/evidence-ref validation gate, no
  manifest-hash gate inside Collect.
- Overhead measurement (spec 64, 65, 93) - MISSING: 0 hits for
  `overhead`/`collector-performance`/`eventsLost`; `collector-performance.json`
  does not exist and no test measures the toolkit's own CPU/memory/skipped
  samples. CI has a "controlled low-impact workload" job (`ci.yml:329`) but it
  tests that the collector's CPU interval pipeline tracks a known workload - it
  does not measure toolkit overhead.
- CI gates for PowerShell runtime behavior: IMPLEMENTED (PS 5.1 and pwsh parse
  gates + real collect runs, `ci.yml:50`, `:65`, `:80`).

## 15. Specification conformance summary

IMPLEMENTED (as specified, verified by code+tests): consent gating and
no-remediation posture; non-Windows refusal; bounded memory-mode WPR with
measured duration and exit-code gating; WPR stop on the normal path; read-only
Verify with hashes; bounded event reads with unrenderable-record handling;
PID+StartTime process CPU identity; raw-disk latency/throughput/queue deltas;
memory committed/limit/paging (no Pages/sec misuse); kernel pool series; volume
to physical-disk/pagefile mapping; UDP endpoint visibility; offline
self-contained HTML; machine-readable findings; schema versioning 1.0/1.1/1.2;
no-data-is-not-healthy rules; no automatic remediation anywhere.

PARTIAL (exists but does not meet the clause): tiering; Repro mode;
continuous process telemetry; per-sample CIM hoisting; commit/paging taxonomy;
storage latency duration/percentiles; process tables (whole-capture not
incident-window); report structure/summary; manifest completeness; coverage
model (ad hoc, no `collection-coverage.json`); trace validation; cleanup
(cooperative stop only).

MISSING (no implementation): flight recorder / logman circular BLG; ETW
`wpr -marker` markers; WPAExporter and `wpr-analysis/*`; incident-vs-baseline
comparison; CPU Sampled vs Precise; ReadyThread/scheduling/wait analysis; UI
hang/critical path (spec 16 is entirely absent: no `ui-delay`,
`ui-thread-hang`, `foreground-app-unresponsive`, `thread-wait-bottleneck`,
`scheduling-starvation`, `lock-contention-suspected`); Wait Chain Traversal;
ProcDump; Defender report parsing; Search context; filesystem filters; storage
reliability; driver/device health; WHEA; WER metadata; reliability/change
history; startup inventory; boot quick/deep; power/thermal; symbols; VBS;
integrity checks; privacy modes; data-quality engine; evidence index; findings
data model (id/severity/confidence/evidence/correlations/possible_causes/
limitations); rule configuration file; collector framework; overhead self
monitoring; perflib health; Pester; fixture matrix.

MISLEADING: `-Preset` changes only metadata (spec 10); README `:231` lists
"Symptom context and collection presets" in the implemented-features list
without saying the preset only records metadata, so a reader can reasonably
expect `-cpu-heavy` to change what is collected; README `:207` describes the
collector output as complete telemetry without stating that WPR is the only ETW
path and that no ETW analysis (WPAExporter tables, DPC/ISR, ReadyThread) is
automated anywhere.

UNVERIFIED on this host: all Windows-only code paths (WMI perf classes, wpr.exe,
Defender module, EventLogReader behavior, launcher .bat runs) - they are
exercised only by GitHub-hosted Windows CI and by owner live runs.

## 16. Existing uncommitted work - preservation notes (binding)

Staged/untracked files that MUST NOT be reverted by any follow-up task; they are
the current state of the branch:

- `src/Invoke-WindowsPerformanceDiagnostics.ps1` (+837/-64 staged): adds
  `ConvertFrom-ServicingLogLines` `:1569`, `Get-ServicingLogAnalysis` `:1692`,
  `ConvertTo-CrashDateTime` `:1868`, `Get-CrashFilenameDate` `:1875`,
  `Get-CrashAnalysis` `:1896`, and wires `crash-evidence`/`servicing-failure`
  findings + `servicing-log-analysis.json` `:4355`.
- `tests/test_crash_servicing_findings.py` (new, 492 lines, 9 tests),
  `tests/test_plan_mode.py` (+1).
- `schema/diagnostic-report.schema.json` (+292): incident/crash/servicing surface.
- Docs: `CHANGELOG.md` (+21), `README.md`, `docs/ROADMAP.md` (M2 section),
  `docs/minidump-boot-failure-collection.md`, `docs/report-schema.md`,
  `docs/windows-live-test-matrix.md`, `START-HERE.bat`, `.github/workflows/ci.yml`.
- Untracked: `docs/authoritative-sources-core.md`,
  `docs/authoritative-sources-platform.md` (research deliverables).
- Never run `git clean`, `git reset`, `git checkout`, `git stash`, `git commit`,
  or `git push` against this tree from an audit/plan task. Any refactor must
  build on the staged content: `GeneratePlan`-side and Collect-side crash paths
  are already referenced by tests and by the schema, so reverting or rewriting
  them wholesale breaks `tests/test_crash_servicing_findings.py:247`, `:338`,
  `:388`.

### 16a. Concurrent-writer observation (important for the next worker)

`tests/test_crash_servicing_findings.py` changed on disk DURING this audit:
it was 492 lines / 9 tests when the staged diff was read (14:47 local) and
590 lines / 12 tests at 14:53:23 local (98 unstaged insertions on top of the
staged `A` entry, so `git status` now reports `AM`). This audit did not write
that file; the shared workspace directory has at least one other active writer.
The file parses cleanly (`ast.parse` OK). Before any task edits this file or the
crash/servicing code path, re-read it and coordinate - the content is a moving
target, and the staged-vs-worktree versions now differ.

## 17. Proposed implementation order (P0/P1/P2)

P0 - foundation/correctness (do first; each item is a prerequisite for later
attribution work):

1. Collector framework + `collection-coverage.json` + `data-quality.json`
   (spec 83, 73, 54). Standardize the existing stages (`:4836-5570`) behind one
   record shape and emit per-stage status/duration/records/errors; derive
   coverage statuses from those records.
2. Findings data model with `id`, `severity`, `confidence` (High/Medium/Low),
   `evidence[]`, `limitations[]` (spec 55, 56), keeping the existing
   `sourceArtifact`/`ruleCondition`/`uncertainty` fields for backward
   compatibility, plus `evidence-index.json`.
3. Hoist static inventory out of the sampling loop and batch the counters
   (`:4973-4990`), one query per sample instead of five classes; add perflib
   health (`perflib-health.json`, statuses healthy/partial/unavailable/
   corrupted-suspected) (spec 7, 64).
4. CPU correctness: `% Processor Utility`/`% Privileged Utility`, user vs
   privileged, per-logical-processor series, plus DPC/ISR counters; keep
   `LoadPercentage` only as a fallback (spec 11-14).
5. Continuous per-sample process series keyed by PID+StartTime (extend
   `Get-PerProcessMemorySample` `:2593` to carry StartTime and I/O/handle/
   thread fields) so short-lived processes and duplicate names stop colliding
   (spec 8, 9, 23).
6. Functional presets: a real preset table driving counters, WPR profile,
   detail level, logging mode, duration, analysis modules, event channels,
   escalation and trace budget (spec 61, 62) - the fix for the metadata-only
   preset defect.
7. Central rule configuration (`config/diagnostic-rules.json`) replacing inline
   thresholds (`:3463`, `:3553`), including duration, minimum samples,
   correlations, severity and confidence logic (spec 57, 58).
8. Incident model completion: ETW `wpr -marker` for CAPTURE_START/REPRO_START/
   INCIDENT_START/INCIDENT_PEAK/INCIDENT_END/CAPTURE_STOP while keeping the
   file/Enter path as a fallback; keep the same timestamp in the toolkit
   timeline (spec 5, 6, 52).
9. Cleanup robustness: Ctrl+C/exception handler, startup detection of abandoned
   WPR sessions with safe cleanup, restore-and-verify (spec 50, 22).
10. Trace validation (ETL non-zero/not truncated, expected providers, no
    abandoned sessions, ETW loss where detectable) and output validation gates
    (spec 91, 92).

P0 - attribution:

11. WPAExporter adapter producing `wpr-analysis/*.csv` with profile-specific
    tables and the CPU Sampled vs Precise distinction preserved (spec 51, 53).
12. Incident-window vs nearby-baseline comparison as a first-class analysis
    input (spec 52, 59).
13. Responsiveness/UI-hang category with the spec 16 finding types, ReadyThread/
    scheduling evidence, and graceful "cannot attribute without symbols" output
    (spec 16, 46).
14. Technician summary + coverage section + "No strong evidence of" gated on
    collector quality + report section order (spec 73-77, 87).

P1: storage reliability counters with explicit `UNSUPPORTED / NOT EXPOSED`
(spec 26); volume/BitLocker/TRIM context (27); filesystem filters via `fltmc`
(28); reliability/change history timeline (42); drivers/devices (45); WHEA
recurrence (44); WER/LiveKernel metadata (43); boot quick then deep On/Off (39,
40); network errors/retransmissions (31); GPU resets/composition (33); power
state and `powercfg` (36, 38); flight-recorder mode with `logman` BLG ring +
WPR memory-mode circular (4, 48, 63).

P1 - targeted escalation: Wait Chain Traversal (17); Defender
`Get-MpPerformanceReport` analysis on top of the existing recording (29); pool
tag attribution (21); heap/VirtualAlloc/handle WPR profiles with saved/restored
state (22, 23); consent-gated ProcDump (18).

P2: Search context (30); audio-glitch preset (35); deep boot automation (40);
long-term baselines and machine fingerprint (60); integrity checks (68);
advanced symbol management (46); privacy modes `-PrivacyMode`
Standard/Redacted/Full (80); overhead self-monitoring `collector-performance.json`
(65, 93); Pester suite + 30-scenario fixture matrix (88, 89).

Sequencing constraint from spec 97: do not start P2 work while P0 items
(especially 1-7) are unreliable; every item above maps to at least one Kanban
card already on this board, and cards that depend on the crash-servicing WIP
must keep that WIP intact (spec 16).

## 18. Method and limits

Every claim above was read from the working tree at audit time
(`git status --short` recorded 10 modified + 1 added tracked files and 2
untracked docs). No Windows host was available, so no collector was executed;
"the code does X" statements are static-read statements from the cited lines, and
every Windows-runtime behavior is marked UNVERIFIED. Repository, tests, docs,
workflows and git state were left untouched.
