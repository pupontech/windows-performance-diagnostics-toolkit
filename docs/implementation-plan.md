# Implementation Plan: v1.0.0 to evidence-driven v2

Status: plan only. This file is the sole artifact written by task t_96101ac6.
No source, test, schema, workflow, doc, or git state was modified by this task.

Purpose: turn the four parent artifacts into one buildable plan - what to
change, in which file, by which Kanban card, in what order, with which gates,
and with the rejected shortcuts written down so no later worker re-introduces
them.

## 0. Inputs, snapshot, and reading conventions

Inputs read in full for this synthesis:

- `docs/audit-v1-to-spec.md` (t_a2c2dffe) - status of the v1.0.0 checkout
  against the user specification, with line references.
- `docs/authoritative-sources-core.md` (t_5a515ecd) - Microsoft semantics for
  WPT/WPR/WPA/WPAExporter, ETW, PerfMon/PDH, TSS, WCT, WER, WHEA, storage
  reliability, ProcDump, PoolMon, minifilters, Defender analyzer.
- `docs/authoritative-sources-platform.md` (t_1c800f5c) - platform domains:
  storage latency/health, filters, Defender, Search, networking, GPU/DWM,
  power, thermal, boot/logon, startup, drivers/devices, VBS, privacy,
  integrity, cross-cutting tracing and threshold references.
- `docs/test-and-live-gap-audit.md` (t_21089bf6) - what the 148 tests and the
  workflows actually prove, the proposed 30-row fixture matrix, hosted gates,
  owner-live gates and the overhead protocol.

Snapshot this plan was verified against (2026-09-15, 15:21-15:29 local):

| Item | Value |
| --- | --- |
| Branch / HEAD | `feat/crash-servicing-findings` / `678e47d ci: pin release flow to v1.0.0 (#10)` |
| Index state | 12 staged paths, `+2144/-67` vs HEAD; worktree equal to index at read time |
| Untracked docs | `audit-v1-to-spec.md`, `authoritative-sources-core.md`, `authoritative-sources-platform.md`, `test-and-live-gap-audit.md` |
| `src/Invoke-WindowsPerformanceDiagnostics.ps1` | 6239 lines, sha256 `215b7c6dcce5fc5d06dcce7f903a4825e4ed7954bbb9194301f493b8878d2487` |
| `tests/test_crash_servicing_findings.py` | 744 lines, 16 tests, sha256 `1b6d147da36a93be74cf076d6381aca5a514284ac3bd743311a2ac6e01b04fdc` |
| `tests/test_plan_mode.py` | 2824 lines, 117 tests |
| `tests/test_incident_capture.py` | 645 lines, 11 tests |
| `tests/test_wpr_bounded_capture.py` | 176 lines, 4 tests |
| `schema/diagnostic-report.schema.json` | 1925 lines, sha256 `b4035c78d36a96105d64b2e48fa281f365918a30cee43dfe97ed88ad76b0cac9` |
| `.github/workflows/ci.yml` | 1048 lines, jobs at `:10`, `:42`, `:370`, `:610` |
| `VERSION` | `1.0.0`; release pin `WPD11_PIN_TAG: v1.0.0` at `ci.yml:620-621` |
| Full suite at quiesce | **148 passed in 117.53s** (15:27 local) |
| `config/` | does not exist (no rule or preset configuration file) |

Reading conventions:

- "spec N" is a section number of the user specification as referenced by
  `docs/audit-v1-to-spec.md` and `docs/test-and-live-gap-audit.md`. Section 0.4
  states what this plan could and could not reconstruct of that specification.
- File references use the symbol or artifact name first, then a line anchor,
  because the tree is a moving target. A line number is a read-time anchor, not
  a stable contract.
- Microsoft semantics are attributed to the parent research artifact and its
  `[n]` source, for example "core section 2 [4]" is the WPR command-line page.
  No URL is invented here; the research artifacts already carry the fetched
  URLs and their verification method.
- "MUST NOT" marks a binding constraint on every later card.

### 0.4 Specification coverage limitation (recorded, not hidden)

The user specification (100 sections) was pasted in the audit session and never
persisted into the repository or onto the board. This plan therefore
reconstructs the specification's shape from the two parent artifacts that cite
it: `docs/audit-v1-to-spec.md` (individual section numbers) and
`docs/test-and-live-gap-audit.md:462-480` (section ranges). Section 13 is the
resulting coverage matrix.

Sections 1-93 and 94 are covered by those citations. Sections 81, 82, 95, 98,
99 and 100 are not individually enumerated by either parent artifact, so their
requirements cannot be claimed as verified from this plan. Consequence and
required action:

- Gate G0 (owner action): the verbatim specification MUST be committed to the
  repository (suggested: `docs/user-specification.md`) before any card claims
  "complete specification coverage", and before t_1558e552 updates
  `README.md`/`CHANGELOG.md` claims. Gate G0 does not block P0/P1 module work;
  it blocks release claims and traceability sign-off (G10).
- This limitation is recorded on the board (comment on t_96101ac6) and is
  re-checked by t_c7351169, which MUST treat an unresolved G0 as an explicit
  confirmed gap rather than a pass.

## 1. Verification of parent claims against the current checkout

Every material claim below was re-read in the working tree for this plan, not
copied from the parent docs. "Confirmed" means observed at the snapshot above.

### 1.1 Claims that changed since the parents were written (drift)

| Claim in a parent artifact | Re-verified at this snapshot | Verdict |
| --- | --- | --- |
| Source is 6101 lines (`audit` section 16a) | 6239 lines at read time, then 6246 during the run, then 6239 | DRIFT: size is not stable for a whole run |
| Staged diff is 12 files `+1713/-64` (`audit`), later `+793/-44`, `+116/-8` unstaged (`gap audit` section 1) | 12 staged paths `+2144/-67`; unstaged diff empty because the concurrent writer staged its edits | DRIFT: the WIP is now larger and was re-staged mid-session |
| `tests/test_crash_servicing_findings.py` is 9 tests (staged), 12 tests (mid-audit), 16 tests (gap audit) | 16 tests, 744 lines | DRIFT: use 16; the file was edited during this very task |
| Untracked docs are 2 research docs (`audit` section 16) | 4 untracked docs (adds `audit-v1-to-spec.md` and `test-and-live-gap-audit.md`) | DRIFT: expected, the audits created them |
| CI has 4 jobs; `python -m pytest` in `windows-verify` | `linux-verify:10`, `windows-verify:42`, `wpd-live-gates:370`, `wpd-release-flow:610`; Windows matrix runs one test file (`ci.yml:85`) | CONFIRMED with detail |

### 1.2 Claims confirmed at this snapshot

| Claim (source) | Verified evidence at this snapshot | Verdict |
| --- | --- | --- |
| Presets are metadata only (audit section 10, spec 61) | `param()` `:49-50` declares 7 legacy names; every `$Preset` use is recording/forwarding: `:4671`, `:4678`, `:4799-4800`, `:5946`, `:6211-6220`. No branch selects counters, profile, detail, duration, channels or budget | CONFIRMED |
| CPU comes from averaged `Win32_Processor.LoadPercentage` (spec 11-14) | sample loop `:5109-5111` re-queries `Win32_OperatingSystem`, `Win32_Processor`, `Win32_LogicalDisk`; `LoadPercentage` collected at `:5113` | CONFIRMED |
| No per-core / Utility / DPC / ISR / queue / context-switch data | zero hits for `% Processor Utility`, `Processor Utility`, `DPC`, `Interrupts/sec`, `ReadyThread` | CONFIRMED |
| Static inventory is re-queried inside the sampling loop (spec 64) | `Get-CimInstance Win32_OperatingSystem` at `:4972` (pre-loop) and again at `:5109-5111` per sample | CONFIRMED |
| Marker is toolkit-internal, not `wpr -marker` (spec 5) | `incident-marker.txt` `:5066`; marker read errors `:5288`; marker job `:5440`; `wpr -marker` zero hits | CONFIRMED |
| No flight recorder, WPAExporter, logman, privacy mode, storage reliability, PnP, powercfg, ProcDump, WCT | zero hits each in the source | CONFIRMED |
| WPR capture is bounded memory mode with documented flags only | `Start-WprBoundedCaptureJob` `:1280`; `wpr.exe` resolved from `SystemRoot` `:5034`; `-start`/`-stop` only, `-stop` at `:1355`; exit-code gates `:5412-5428` | CONFIRMED |
| Schema versioning is 1.0/1.1/1.2, widenable | `:5946-5948`; enum at `schema/diagnostic-report.schema.json` property `schemaVersion` | CONFIRMED |
| Thresholds are inline magic numbers (spec 57) | `MinimumConsecutive = 5` `:3437` and `:3541`; CPU 80 `:3633`; commit 90 `:3696`; paging 100 `:3721`; queue 2 `:3766`; latency 0.02s `:3785`; no `config/` directory | CONFIRMED |
| Findings keep provenance but lack the spec data model (spec 55, 56) | categories emitted: `evidence-coverage` `:3554`, `coverage` `:3573/3656/3670/3743/3808/3827/3864/3879`, `commit-attribution` `:3612`, `cpu-pressure` `:3636`, `memory-pressure` `:3702`, `memory-paging` `:3724`, `disk-pressure` `:3769`, `disk-latency` `:3788`, `disk-space` `:3843`, `crash-evidence` `:3924+`, `servicing-failure` `:4054`; no `id`, `severity`, `confidence`, `evidence[]`, `limitations[]`, no `evidence-index.json` | CONFIRMED |
| No automatic remediation anywhere | zero hits for `RestoreHealth`, `sfc`, `chkdsk`, `bcdedit`, `Set-MpPreference`, `Start-Service`, `Stop-Service`, `Set-ItemProperty`, `New-ItemProperty` | CONFIRMED |
| Machine-readable output and offline report exist | `findings.json` write `:4502`, artifact registration `:4510`/`:4522`, `Get-ArtifactMetadata` `:693` | CONFIRMED |
| Test inventory | 117 + 11 + 16 + 4 = 148; full suite green at quiesce | CONFIRMED |

### 1.3 Defects found by this synthesis (not in the parent docs)

1. **`memory-paging` fires on one metric alone (spec 19, spec 71).** The rule at
   `:3721-3738` emits a finding when `PagesInputPersec > 100` runs for 5
   consecutive samples. Nothing in the rule requires corroboration that
   physical memory or the commit charge was under pressure, so a machine with
   ample RAM doing legitimate file I/O can produce a paging finding. The
   `uncertainty` text is honest, but the finding category itself is the
   Pages/sec-only conclusion the specification rejects. Fix is P0 (section 6,
   P0-4) and MUST NOT be a threshold tweak: the rule has to require a second
   independent channel, or degrade to a coverage/uncertainty record.
2. **Full-suite results are not reproducible while another writer is active.**
   At 15:24 the suite was `3 failed, 145 passed`
   (`test_servicing_file_analysis_scans_copied_logs_and_preserves_collection_shape`,
   `..._hard_bounds_a_growing_input_stream`,
   `..._merges_signature_ranges_across_chunks`); at 15:25 the same three tests
   passed 16/16, and at 15:27 the full suite was 148 passed. The tree was
   edited by a concurrent writer during the first run (source size and staged
   diff changed between reads). Any gate in this plan MUST be run against a
   quiesced revision, and a red suite MUST be re-run once before being treated
   as a regression.
3. **Line-anchored citations in the parent artifacts are already stale** (for
   example the audit's sampling-loop anchors `:4973-4990` are now
   `:5109-5113`). All later docs and comments MUST anchor on symbols
   (`Get-SustainedWindow`, `Start-WprBoundedCaptureJob`, the `$Preset` uses).

### 1.4 Where the parent artifacts disagree

- `docs/test-and-live-gap-audit.md` recommends Pester as the natural
  PowerShell-native harness; decision D13 below deliberately does not adopt
  Pester. Rationale and the compensating gate are recorded so the difference is
  not read as an omission.
- The audit's P0 list (audit section 17) is broader than the card set on the
  board: spec 60 (long-term baselines, machine fingerprint), spec 68 (integrity
  checks), the release-pin bump, `README-FIRST.txt`/`docs/development-workflow.md`
  reconciliation and the WPD-12 naming conflict have no dedicated card. Section
  14 lists each with a recommended owner.

## 2. Binding compatibility decisions

These are decisions, not options. Later cards inherit them.

- **D1 - Entry point stays single-script.** `src/Invoke-WindowsPerformanceDiagnostics.ps1`
  remains the only production entry point and keeps Plan/Collect/Verify, all
  consent gates and the non-Windows refusal. New capability ships as modules
  imported from `$PSScriptRoot`: `Wpd.Common.psm1`, `Wpd.Telemetry.psm1`,
  `Wpd.Etw.psm1`, `Wpd.Report.psm1`, `Wpd.Inventory.psm1`, `Wpd.Events.psm1`,
  `Wpd.Escalation.psm1`, `Wpd.Collectors.psm1`. Modules MUST be Windows
  PowerShell 5.1 compatible: no `class`, no PS7-only operators, no
  `using namespace`.
- **D2 - Preset names are a union, not a rename.** Canonical names are the
  specification's 13: `general`, `cpu-heavy`, `memory-pressure`, `memory-leak`,
  `storage-io`, `network`, `gpu`, `ui-hang`, `ui-stutter`, `boot-slowdown`,
  `audio-glitch`, `power`, `intermittent`. The three current names that do not
  appear in that list are kept as deprecated aliases so existing manifests,
  remote forwarding and tests keep working: `baseline` -> `general`,
  `network-io` -> `network`, `application-freeze` -> `ui-hang`. The manifest
  records both the requested and the effective name, and the alias map lives in
  `config/diagnostic-presets.json`, not in code.
- **D3 - Tier model.** Tier 0 = static inventory, collected once per run from a
  session cache; Tier 1 = interval counters at a 1 s floor or a preset-selected
  long interval; Tier 2 = ETW/WPR recording; Tier 3 = opt-in escalation
  (dumps, WCT, pool, Defender report). Tier 1 MUST NOT re-query Tier 0
  classes inside the sampling loop.
- **D4 - Sampling floor stays 1 s.** Microsoft states performance counters are
  not designed to be collected more than once per second (core section 5 [19]).
  No sub-second default, no sub-second preset, no `-SampleIntervalSeconds`
  value below 1.
- **D5 - Process identity.** Prefer the `Process V2` counterset where it exists
  (core section 5 [19]); otherwise pair by PID + `StartTime`. Every continuous
  per-sample process series MUST carry `StartTime`; name-keyed aggregation
  remains only as a legacy column set, never as the identity key.
- **D6 - Target versions.** Explicit: no machine-specific number becomes a
  hard-coded pass/fail line in code. Every threshold, minimum duration, minimum
  sample count and correlation requirement comes from
  `config/diagnostic-rules.json`, and the emitted finding records the rule id
  and the threshold used.
- **D7 - Findings compatibility.** Existing keys (`category`,
  `sourceArtifact`, `metric`, `windowStart`, `windowEnd`, `measuredValues`,
  `ruleCondition`, `uncertainty`, `nextSteps`, `suggestedWprProfile`) are
  preserved. New keys (`id`, `severity`, `confidence`, `title`, `summary`,
  `evidence[]`, `correlations`, `possibleCauses`, `limitations`) are additive.
  `confidence` is the enum `High|Medium|Low` with stated conditions, never a
  numeric percentage.
- **D8 - Output layout is additive.** Existing flat artifact names
  (`performance-samples.csv`, `findings.json`, `report.html`, `wpr-trace.etl`,
  `incident-marker.txt`, and the rest of the current whitelist) keep their names
  and locations, because Verify mode, the ZIP whitelist and the existing tests
  depend on them. New artifacts go to new subdirectories (`inventory/`,
  `telemetry/`, `events/`, `wpr-analysis/`, `escalation/`, `case/`). The ZIP
  whitelist and manifest artifact list are extended by explicit names, never by
  glob.
- **D9 - Verify accepts the union.** Verify mode MUST accept manifest schema
  1.0, 1.1, 1.2 and 1.3 and the new artifact set, MUST remain read-only, and
  MUST NOT fail on an artifact it does not know (record it as unverified
  instead).
- **D10 - Privacy default is Standard, and it is opt-down.** `Standard` is the
  default; `Redacted` hashes user names and paths and suppresses command lines;
  `Full` requires an explicit flag and a consent prompt mirroring the existing
  `-ConfirmLocalCollection` pattern. No secret, token, cookie, browser history,
  document content or credential is ever collected in any mode.
- **D11 - Escalation is opt-in, absent-tool tolerant, never auto-remediating.**
  Every Tier 3 adapter is off unless its own switch plus consent is supplied.
  An absent tool or module is reported as `unsupported`/`not-present`, never as
  healthy and never as an error that aborts the run. Nothing is downloaded, no
  Defender exclusion is proposed, and ProcDump defaults to `-mm` (mini), never
  `-ma` (core section 11 [49]).
- **D12 - One writer per file.** `t_b5e3e5a3` is the only card allowed to edit
  `src/Invoke-WindowsPerformanceDiagnostics.ps1`. `t_1f568c63` is the only card
  allowed to edit `.github/workflows/ci.yml`. `t_1558e552` is the only card
  allowed to edit `SCHEMA`, `VERSION`, `CHANGELOG.md` and the shared docs.
  `config/` belongs to `t_0bc4950d`. Every card re-reads its target file
  immediately before editing it, because the shared directory has had
  concurrent writers (section 1.3, defect 2).
- **D13 - Test runner stays pytest; Pester is not adopted.** Rationale: one
  runner already executes 148 tests and drives real `pwsh`/`powershell.exe`
  processes, CI already parses under both engines, and a second runner doubles
  the maintenance surface for the same assertions. PS 5.1 runtime coverage is
  added as a pytest-driven harness that invokes `powershell.exe -File` (section
  10, gate H02). If a PS 5.1-only runtime defect is found that the harness
  cannot express, Pester becomes a new decision at that point, not a silent
  addition now.
- **D14 - Documentation anchors on symbols.** No delivery document may cite a
  bare line number as a contract; every reference is `symbol` or `artifact`
  first (section 1.3, defect 3).

## 3. Target component map and file ownership

| Component | New file(s) | Test file | Card | Owner profile |
| --- | --- | --- | --- | --- |
| Time, envelopes, coverage states, evidence records, privacy helpers, confidence logic | `src/Wpd.Common.psm1` | `tests/test_common.py` | t_91d4e281 | luna |
| Rules and functional presets | `config/diagnostic-rules.json`, `config/diagnostic-presets.json` | `tests/test_rules_presets.py` | t_0bc4950d | dsflash2 |
| Tier 1 telemetry: identity, CPU, memory, storage, network, GPU | `src/Wpd.Telemetry.psm1` | `tests/test_telemetry.py` | t_2c7b6fda | luna2 |
| ETW/WPR: markers, circular capture, boot descriptors, WPAExporter adapter | `src/Wpd.Etw.psm1` | `tests/test_etw.py` | t_645856ef | dsflash2 |
| Findings, evidence index, data quality, technician report | `src/Wpd.Report.psm1` | `tests/test_report.py` | t_4d184c2a | luna2 |
| Tier 0 inventory, capability map, privacy modes | `src/Wpd.Inventory.psm1` | `tests/test_inventory.py` | t_91d8010d | dsflash |
| Events: reliability, WHEA, WER, change timeline | `src/Wpd.Events.psm1` | `tests/test_events.py` | t_564f783d | dsflash |
| Tier 3 escalation adapters | `src/Wpd.Escalation.psm1` | `tests/test_escalation.py` | t_29345eda | luna |
| Collector orchestration/composition | `src/Wpd.Collectors.psm1` | `tests/test_collectors.py` | t_eef69ce4 | dsflash |
| Integration into the entry point | `src/Invoke-WindowsPerformanceDiagnostics.ps1` | existing suites | t_b5e3e5a3 | luna |
| Schema and docs alignment | schema and doc list in D12 | - | t_1558e552 | luna2 |
| Windows/pwsh/PS 5.1 CI gates | `.github/workflows/ci.yml`, `tests/test_windows_contracts.py` | same | t_1f568c63 | luna2 |
| Fixture matrix | `tests/fixtures/diagnostic-scenarios/`, `tests/test_diagnostic_scenarios.py` | same | t_bad9a6f6 | dsflash2 |
| Overhead and budgets | `tests/test_overhead_and_budgets.py`, `docs/performance-overhead.md` | same | t_ed91c6e3 | dsflash2 |
| Review | `docs/v2-fresh-eyes-review.md` | - | t_c7351169 | luna2 |
| Owner-live validation | `docs/windows-live-v2-results.md` | - | t_5e6e4a21 | human |

Missing artifact that the integration card will need: `docs/diagnostic-architecture.md`
and `docs/technician-workflows.md` are named as t_1558e552 deliverables but do
not exist yet; they are new files, not edits (section 14, U6).

## 4. Schema and versioning policy

Current state: manifest `schemaVersion` is `1.0`/`1.1`/`1.2` selected at
`:5946-5948`; one report schema file (1925 lines) and one verification schema
(86 lines).

Policy (binding):

1. `1.0`, `1.1` and `1.2` stay valid and stay tested. The new tiered/evidence
   surface adds `1.3`; nothing is renamed or removed inside `1.x`.
2. A new `1.x` version is added only when a consumer-visible block is added
   (new top-level manifest block or a new artifact family). Adding fields to an
   existing block does not need a bump.
3. `toolVersion` and `schemaVersion` stay separate: `toolVersion` tracks
   `VERSION`; `schemaVersion` tracks the contract.
4. New artifact-level schemas are additive files in `schema/`:
   case/manifest, coverage, data-quality, evidence-index, incidents,
   inventory, telemetry, findings, and optional escalation - each with the
   explicit unavailable/unsupported/not-collected states, never a healthy
   default (t_1558e552 owns this list).
5. Removal or rename requires a 2.0 contract plus a Verify fallback that still
   reads the old shape; no such change is in scope for v2.
6. `VERSION` moves to `2.0.0` only in t_1558e552, only after integration
   (P0-7) and the Windows gates (P1-6) pass, and the release flow pin
   `WPD11_PIN_TAG`/`WPD11_PIN_SHA256` at `ci.yml:620-621` MUST be bumped in the
   same change: the workflow throws when the latest tag does not match
   `VERSION` (`ci.yml:648`, `:756`). A version bump without the pin fails the
   release job by design.
7. Every schema change ships with a fixture that validates a good document and
   a negative fixture that must fail validation (t_bad9a6f6), plus a
   cross-version test proving a `1.2` manifest still validates under the `1.3`
   schema file.

## 5. Findings and evidence model (spec 54-59, 71-77, 86)

Shape (additive to D7):

```
id                  stable string, rule id plus window index
category            one of the rule-file categories
severity            informational | low | medium | high
confidence          High | Medium | Low (enum, with stated conditions)
title, summary      technician-facing, no invented percentages
incident            incident id/window reference when the finding is in-window
evidence[]          {artifact, path, metric, value, windowStart, windowEnd}
correlations[]      {with, kind, note} - correlation is never causation
possibleCauses[]    each linked to at least one evidence entry
limitations[]       what the evidence cannot establish
nextSteps[]         advisory only (R4)
rule                {id, threshold, minimumSamples, minimumDurationSeconds}
```

Every conclusion MUST reference an existing evidence record; the evidence index
(`evidence-index.json`) maps evidence ids to artifact paths and value ranges,
and the report renders a link only when the artifact is registered and hashed.
A finding with no evidence entry is a defect, not a style issue.

Outcome rules:

- `ROOT CAUSE NOT IDENTIFIED` is a first-class outcome when no rule fires with
  sufficient evidence quality (spec 72). It is not the same as healthy.
- "No strong evidence of X" is allowed only when the collectors that would
  supply X reported `success`/`partial` with sufficient samples; when the
  collectors reported `unavailable`, the line is omitted and the coverage block
  explains why (spec 73, 74).
- A "clear measured window" statement is allowed only for metrics that were
  actually measured across the required duration.

## 6. P0 plan (foundation, correctness, integration)

P0 items map one-to-one onto cards that already exist on the board. "Gate" is
the acceptance test that proves the item.

- **P0-1 - Time, collector envelopes, coverage, data-quality and evidence
  records. Card t_91d4e281 (luna). New files only: `src/Wpd.Common.psm1`,
  `tests/test_common.py`.**
  Provides: local/UTC/ISO timestamps, timezone, uptime/boot time when
  available, incident windows, collector result envelopes
  (`status|start|end|duration_ms|records|warnings|errors`), coverage states
  (`complete|partial|unavailable|not-collected|unsupported`), data-quality
  records, evidence provenance records, path/privacy redaction helpers,
  confidence logic and the `Healthy`-forbidding default.
  Decisions that belong to this card: D3 (tier vocabulary), D10 (privacy
  helper contract), D7 (confidence enum functions), and the status vocabulary
  every other module must return. Missing data stays `unavailable`.
  Gate: unit tests with synthetic inputs proving malformed timestamps, gaps,
  failure results and a missing measurement never produce `healthy`.

- **P0-2 - Rules and functional presets. Card t_0bc4950d (dsflash2).
  New files only: `config/diagnostic-rules.json`,
  `config/diagnostic-presets.json`, `tests/test_rules_presets.py`.**
  Implements D2 (13 canonical names plus the 3 aliases), D6 (all thresholds and
  durations in the rule file) and the spec 61/62 preset contract: Tier 1
  counters, WPR profile and mode, detail level, expected duration, analysis
  modules, event channels, escalation options, trace-size budget, privacy
  level, no-remediation behaviour. A validator MUST fail any preset that only
  changes metadata.
  Gate: JSON validity, name uniqueness, alias resolution, "no preset is
  metadata-only", and a negative test that a preset missing an analysis module
  or a trace budget fails.

- **P0-3 - Tier 1 telemetry. Card t_2c7b6fda (luna2). New files only:
  `src/Wpd.Telemetry.psm1`, `tests/test_telemetry.py`.**
  Implements D4, D5 and the spec 8-15/19-27/31-33 surface: PID+StartTime
  identity and reuse, short-lived processes, interval CPU with user/kernel
  split, CPU Time versus Utility (utility may exceed 100 on boost-capable
  systems; that is documented behaviour, core section 7 [25], not an error),
  per-core and CPU-group summaries, queue/context-switch counters, DPC/ISR
  metrics, continuous process CPU/memory/I/O/handle/thread sampling with gap
  accounting, commit/physical/pagefile/hard-fault taxonomy with the
  `% Committed Bytes In Use` view, pool growth series, disk latency from paired
  raw counters with operation bases and percentiles, network rates/retransmits/
  errors from the TCPv4/TCPv6 lists (platform section 5 [16]), GPU values with
  explicit unavailable states, and the perflib health probe
  (`healthy|partial|unavailable|corrupted-suspected`).
  Injectability is a hard requirement: providers/rows are injected so Linux
  tests never pretend to be Windows.
  Gate: synthetic-row tests for every metric including null, zero, negative,
  duplicate-name and PID-reuse cases; a test proving no static Tier 0 class is
  queried inside a sampling loop; a test proving 1 s is the floor.

- **P0-4 - Paging and memory conclusions need two channels. Same card as
  P0-3, plus the report rule in P0-6.** Fix for defect 1.3-1: a paging finding
  MUST require both a paging-rate condition and at least one independent
  pressure condition (commit ratio or available/physical memory or working-set
  growth), otherwise emit a coverage/uncertainty record whose text says the
  paging rate was elevated without measured memory pressure.
  Gate: two fixtures - one with high paging plus memory pressure (finding,
  confidence Medium or High), one with high paging and ample memory (no paging
  finding; coverage record instead). The second fixture is the direct
  rejection of a Pages/sec-only conclusion.

- **P0-5 - ETW/WPR, markers, circular capture, WPAExporter adapter. Card
  t_645856ef (dsflash2). New files only: `src/Wpd.Etw.psm1`,
  `tests/test_etw.py`.**
  Implements D8 plus: preset-to-profile selection (light/verbose), memory
  versus file circular semantics with the file mode explicitly unbounded and
  therefore opt-in, free-space/size/duration preflight, start/stop/cancel with
  `finally` and abandoned-session detection, `wpr -marker` command construction
  for CAPTURE_START / REPRO_START / INCIDENT_START / INCIDENT_PEAK /
  INCIDENT_END / CAPTURE_STOP, On/Off boot descriptors (never executed and
  never rebooting), WPR/WPA/WPAExporter discovery, and bounded exporter table
  selection by preset. Tests assert exact documented argv and MUST fail on any
  invented switch.
  Gate: argv assertions for every documented command; a test that the invented
  `-maxduration` and `-filesize` forms are rejected; a test that `-filemode` is
  not used as a bound; a test that an abandoned session is detected and cleaned
  only when this toolkit created it.

- **P0-6 - Findings, evidence index, data quality and technician report. Card
  t_4d184c2a (luna2). New files only: `src/Wpd.Report.psm1`,
  `tests/test_report.py`.**
  Implements section 5 and the spec 73-78/87 report order: technician summary
  first, coverage block, timeline, incident-window process tables (not
  whole-capture rankings), duration-aware baseline versus incident comparison,
  "no strong evidence of" gated on collector quality, `ROOT CAUSE NOT
  IDENTIFIED`, all finding categories including the UI-hang/responsiveness set
  with an explicit "cannot attribute without symbols" path, and self-contained
  XSS-safe HTML with raw artifact links.
  Gate: evidence-link validation (a finding with a dangling evidence entry
  fails), HTML escaping, unknown-category fallback rendering, no health score,
  no fake percentage confidence, and a test that a nulls-only series yields
  `unavailable`, never healthy.

- **P0-7 - Integration into the entry point. Card t_b5e3e5a3 (luna), single
  writer for `src/Invoke-WindowsPerformanceDiagnostics.ps1`.**
  Wires D1-D11 into the production script without discarding the staged
  crash/servicing WIP: functional preset dispatch, Repro and Flight Recorder
  modes, cached Tier 0 inventory, Tier 1 cadence, process identity, incident
  markers and the common time model, WPR/WPA/exporter integration, cleanup with
  `finally` plus a console cancel handler plus abandoned-session recovery,
  optional escalations, coverage/data-quality/evidence manifest blocks and
  report handoff. Plan mode must describe the new modes without creating
  artifacts; Verify must accept 1.0-1.3 (D9).
  Gate: parser gates under PS 5.1 and pwsh, ASCII/no-BOM, focused module tests,
  full pytest, and the existing Plan/refusal/Verify tests unchanged and green.
  Integration MUST run when no other card is writing the script (D12, and
  section 1.3 defect 2).

- **P0-8 - Crash/servicing WIP preservation.** Not a separate card; a
  constraint on P0-7 and on every docs change. The staged crash/servicing
  surface (`ConvertFrom-ServicingLogLines`, `Get-ServicingLogAnalysis`,
  `ConvertTo-CrashDateTime`, `Get-CrashFilenameDate`, `Get-CrashAnalysis`,
  `servicing-log-analysis.json`, the crash/servicing findings, the 306-line
  schema widening) MUST survive refactoring: `tests/test_crash_servicing_findings.py`
  (16 tests) is the regression contract. No card may revert, rewrite or
  re-stage it.

## 7. P1 plan (coverage, composition, evidence)

- **P1-1 - Static inventory and capability map. Card t_91d8010d (dsflash).
  New files only: `src/Wpd.Inventory.psm1`, `tests/test_inventory.py`.**
  Tier 0 collectors with independent failure envelopes: OS, hardware/topology/
  BIOS, drivers/devices (`Get-PnpDevice`, platform section 11 [41]),
  power configuration and processor state (`powercfg`, platform section 7
  [26]), storage topology and reliability (`Get-PhysicalDisk`,
  `Get-StorageReliabilityCounter`, platform sections 1 and 10 [2][45]),
  NIC, services, security products, startup inventory (registry/folders/
  services/tasks, platform section 10 [39]), filesystem filters (`fltmc`,
  platform section 2 [5]), pagefiles, virtualization/VBS (platform section 12
  [46]), BitLocker/TRIM context, recent changes, and a per-capability
  elevation map. Unsupported devices report `unsupported`/`not-exposed`, never
  healthy (platform section 10, R2).
  Gate: synthetic provider seams, one failing provider must not abort the
  others, unsupported/absent states asserted, no secret collection, case-insensitive
  command presence detection.

- **P1-2 - Reliability events, WHEA, WER and change correlation. Card
  t_564f783d (dsflash). New files only: `src/Wpd.Events.psm1`,
  `tests/test_events.py`.**
  Bounded targeted event collection with raw XML preservation when rendering
  fails, repetitive-event grouping with first/last/count and incident
  proximity, WER application crash/hang/LiveKernel metadata, WHEA corrected
  versus uncorrected recurrence (`Microsoft-Windows-WHEA-Logger`, platform
  section 11 [41][43]), Diagnostics-Performance and Kernel-Power context,
  driver/update/software change timeline, symptom-date boundary support, and
  correlation-not-causation confidence wording. WHEA absence is not health.
  Gate: synthetic unrenderable providers, out-of-window events, repeated Wi-Fi
  resets, WHEA recurrence, malformed timestamps, and a failed query producing
  `unavailable` rather than an empty-but-healthy log.

- **P1-3 - Targeted escalation adapters. Card t_29345eda (luna). New files
  only: `src/Wpd.Escalation.psm1`, `tests/test_escalation.py`.**
  Implements D11: WCT chains/cycles (core section 7 [33]), ProcDump only when
  present or explicitly enabled and default `-mm`, PoolMon/WPR pool analysis
  with the legacy GFlags step treated as obsolete (core section 12 [51][53]),
  Defender `New-MpPerformanceRecording`/`Get-MpPerformanceReport` with `-Raw`
  (core section 14 [58][59]), Search service/index context (platform section 4
  [14]), `fltmc` filter/instance parsing with altitude-based ordering
  (core section 13 [57]), heap/VirtualAlloc/resident/handle tracing
  descriptors and deep GPU/audio/UI descriptors.
  Gate: absent-tool detection, exact argv for documented commands, no download
  path, no exclusion recommendation, cleanup of every adapter, consent refusal
  has no side effects.

- **P1-4 - Collector composition. Card t_eef69ce4 (dsflash). New files only:
  `src/Wpd.Collectors.psm1`, `tests/test_collectors.py`.**
  Composes Common/Inventory/Telemetry/Etw/Events/Escalation into orchestrated
  Tier 0/1/2 collection with caching, cadence validation, Repro versus Flight
  Recorder bounded storage, static capability map application, timestamps,
  cleanup and result envelopes. Storage reliability unsupported handling,
  filters, Defender/Search, WCT/ProcDump consent, boot quick/deep descriptors,
  network/GPU/power context and self-monitoring live here.
  Gate: envelope contract tests, a Tier 0 class queried exactly once per run,
  a Tier 1 interval below 1 s rejected, cleanup on failure, and no write to the
  production entry point.

- **P1-5 - Schema and documentation alignment. Card t_1558e552 (luna2).**
  Section 4 plus the spec 75-87 claims: actual modes, all 13 presets, tier
  architecture, evidence-first rules, privacy/admin/optional-tooling limits,
  WPR marker/memory/file/on-off semantics, artifacts, version/schema
  rationale, hosted-versus-owner Windows proof. It also owns the `2.0.0`
  `VERSION` bump and the `ci.yml` pin coordinate (section 4, item 6) - with
  `ci.yml` edited by t_1f568c63 under D12, the pin bump is a two-card
  handshake that MUST be recorded in both cards' completion metadata, or the
  release job fails by design.
  Gate: `todo`-free doc claims, ASCII/no-BOM, schema validation of a
  `1.2` manifest under the `1.3` file, and a diff review proving the
  crash/servicing WIP docs were reconciled rather than reverted.

- **P1-6 - Windows CI gates. Card t_1f568c63 (luna2). Only
  `.github/workflows/ci.yml` and `tests/test_windows_contracts.py`.**
  Section 10. MUST preserve the staged workflow WIP and the existing four jobs.

- **P1-7 - Fixture matrix. Card t_bad9a6f6 (dsflash2). Only
  `tests/fixtures/diagnostic-scenarios/` and
  `tests/test_diagnostic_scenarios.py`.** Drives production functions (not
  source regexes) across the 30-row matrix in
  `docs/test-and-live-gap-audit.md:572-603`, including "high Pages/sec without
  RAM shortage", "unsupported SMART", "corrupted Perflib", "non-admin",
  "interrupted WPR" and "insufficient disk".

## 8. P2 plan (cost, honesty, hardening)

- **P2-1 - Overhead and trace-size safety. Card t_ed91c6e3 (dsflash2).**
  `tests/test_overhead_and_budgets.py` and `docs/performance-overhead.md`:
  deterministic synthetic timing, Tier 1 never sub-second, Tier 0 cached,
  circular recorder hard bound, WPR preflight rejects insufficient space,
  duration and size limits enforced, sample gaps/skips and ETW loss reported,
  self-monitoring emits collector CPU/memory/duration. Thresholds remain an
  owner decision and results stay informational until approved
  (`docs/test-and-live-gap-audit.md:692-695`).
- **P2-2 - Review. Card t_c7351169 (luna2).** `docs/v2-fresh-eyes-review.md`
  only. Must also rule on G0 (spec traceability) and on every claim in this
  plan that has no automated proof.
- **P2-3 - Owner-live validation. Card t_5e6e4a21 (human, currently blocked).**
  `docs/windows-live-v2-results.md`. A hosted runner cannot close this gate
  (`docs/test-and-live-gap-audit.md:634-654`).

## 9. Integration order

The board's dependency edges already encode most of this; the plan states the
order explicitly so a worker can verify it before starting.

```
Stage 0 (parallel, new files only, no shared writer)
  t_91d4e281 (common)  t_0bc4950d (rules/presets)  t_2c7b6fda (telemetry)
  t_645856ef (etw)     t_4d184c2a (report)

Stage 1 (parallel, depends on common vocabulary)
  t_91d8010d (inventory)   t_564f783d (events)   t_29345eda (escalation)

Stage 2 (composition)
  t_eef69ce4 (collectors; needs telemetry, etw, events, inventory)

Stage 3 (single-writer integration; requires stages 0-2 complete and the tree
quiesced)
  t_b5e3e5a3 (entry point)

Stage 4 (contract + docs; requires stage 3)
  t_1558e552 (schemas, docs, VERSION 2.0.0, release pin handshake)

Stage 5 (parallel, requires stage 3; fixtures also benefit from stage 4
schemas)
  t_1f568c63 (CI gates)   t_bad9a6f6 (fixtures)   t_ed91c6e3 (overhead)

Stage 6
  t_c7351169 (fresh-eyes review; requires stages 3-5)

Stage 7 (human)
  t_5e6e4a21 (owner-live v2)  +  t_f7cfeaa4 / t_e61b9111 (owner lab WPD-01..11)
```

Stop conditions attached to the order:

- Stage 3 MUST NOT start while any stage 0-2 card is still running; the shared
  directory had a concurrent writer during this synthesis (section 1.3).
- Stage 4 MUST NOT claim the release pin is updated until
  `ci.yml:620-621` matches `VERSION`; the workflow fails by design otherwise.
- Stage 6 MUST NOT pass while G0 is unresolved or while a windowed claim in
  this plan has no fixture.

## 10. Test and CI gates

Existing gates (keep, do not weaken): `linux-verify` (`ci.yml:10`) runs the
full suite plus a `pwsh` parse gate; `windows-verify` (`:42`) parses under
PS 5.1 (`:50`) and pwsh (`:65`), runs Plan/refusal paths (`:80`), one crash/
servicing test file (`:85`), the launchers (`:157-171`), artifact assertions
(`:173-327`) and a controlled CPU workload (`:329-355`); `wpd-live-gates`
(`:370`) covers real WPR and identity gates; `wpd-release-flow` (`:610`)
reconstructs the tagged bundle and checks hashes and the pinned asset.

Gates this plan requires on top (owner: t_1f568c63 unless noted):

| Gate | Requirement |
| --- | --- |
| H00 contract | Parser + ASCII/no-BOM checks cover every new `.psm1` and `.ps1` under `src/` and every new test file. A non-ASCII byte or a BOM fails. |
| H02 engines | The full Python suite runs on the Windows matrix, and a new harness runs extracted/real module functions under `powershell.exe -File` (PS 5.1) as well as `pwsh`. A pwsh-only pass is not PS 5.1 coverage (D13). |
| H03 fixtures | The 30-row fixture matrix runs under both engines through provider/command seams; each fixture emits one JSON result and fails on artifact/status/hash mismatch. |
| H04 output contract | Every emitted artifact validates against its schema or its documented CSV header set; manifest hash registration covers all whitelisted artifacts; cross-file references resolve; Verify accepts a `1.0`, `1.1`, `1.2` and `1.3` case. |
| H05 WPR | Start/stop exit codes, empty-ETL detection, oversize policy, abandoned-session recovery, `wpr -status` reconciliation, and an argv assertion that no undocumented switch is used. |
| H06 optional tools | Defender present/absent, WCT absent, ProcDump absent, `fltmc` absent, PoolMon absent, WPAExporter absent - each must produce `unsupported`/`not-present`, and the run must still complete (D11). |
| H07 safety invariants | Automated checks that no source file contains a remediation command (`RestoreHealth`, `sfc`, `chkdsk`, `bcdedit`, `Set-MpPreference`, service start/stop, registry write), that a missing measurement never renders as healthy, and that no finding is emitted from a single-channel paging rule. |
| H08 launchers | START-HERE options 1-5, invalid input, missing script, child failure and `Run-Diagnostics.bat` failure branch (gap audit section 4.2). |
| H09 release pin | `wpd-release-flow` must fail loudly when `VERSION` and the pin diverge, and the bump is proven in the same change (section 4, item 6). |
| O01-O13 (owner) | Baseline no-side-effects, MOTW/Defender recovery, standard-user UAC, real disk latency, real memory/commit, GPU/TDR, UDP/network faults, unrenderable event XML, storage/pagefile mapping, crash/dump history, boot/WinRE/servicing, marker interaction, hardware overhead (gap audit section 8). |
| G0 (owner) | Verbatim specification committed before any coverage claim (section 0.4). |
| G10 (t_c7351169) | Traceability sign-off: every specification section either has a gate or is recorded as deferred with a reason. |

Local verification available on this Linux host today: the full pytest suite
(148 tests), PowerShell parsing only if `pwsh` is present, schema validation
with the repo venv, and ASCII/BOM/source-invariant greps. Nothing else is
evidence of Windows behaviour.

## 11. Windows-only limitations and honesty rules

1. Every Windows-only code path is UNVERIFIED until it runs on Windows:
   WMI/CIM providers, PDH/GUI counters, EventLog/`Get-WinEvent`, `wpr.exe`,
   `wpaexporter.exe`, the Defender module, `fltmc`, `powercfg`, `poolmon`,
   `procdump`, WinRM and the `.bat` launchers. Linux tests prove logic,
   contracts and failure handling, never provider behaviour.
2. Hosted Windows runners cannot prove: MOTW/Defender quarantine behaviour,
   standard-user UAC interaction, physical disk latency, real GPU/TDR,
   client-specific UDP/dynamic-range behaviour, provider message rendering
   failures, the owner's storage/pagefile topology, real dump history,
   WinRE/PE drive letters, an operator pressing Enter at the symptom, or
   collector overhead on representative hardware (gap audit section 8).
3. No agent may induce a crash, reboot, suspend, or change Defender, boot or
   policy state to produce evidence. Boot tracing remains a descriptor until a
   human authorises it (platform section 9 [35]).
4. Thermal throttling has no Microsoft-documented counter API for a per-zone
   percentage (platform section 8, known gaps); the only documented channel is
   thermal events, so the report MUST NOT present a throttling percentage as a
   measurement.
5. VBS/memory-integrity overhead is documented as generation-dependent with no
   published percentage (platform section 12 [46]); the report states the
   configuration and refuses a performance figure.
6. WHEA has no documented generic user-mode API for raw error records
   (core section 9 [40]); only the event provider and the management interface
   are available, and an empty log is not health.
7. Storage reliability counters are device-provided and can be blank; the
   prediction IOCTL returns `STATUS_INVALID_DEVICE_REQUEST` when unsupported,
   which MUST be reported as not reported, never healthy (core section 10
   [44][47]).
8. Symbols: without a symbol path the toolkit can only produce module-level
   attribution, and the report MUST say so rather than guessing a function.
9. PerfMon/counter semantics: counters are interval samples, not traces, are
   not designed for sub-second collection, and PerfMon summarizes beyond 1000
   graph points (core section 5 [19][27]). The report MUST record the counter
   path, the interval and the log format rather than a display label.
10. Launch-time honesty: until the owner gates close, README/release text may
    claim hosted-CI proof and must label hardware, Defender/MOTW, interactive
    incident, WinRE, provider-fixture and overhead behaviour as partial or
    owner-live-only (gap audit section 10).

## 12. Explicit rejections (binding)

Each rejection names the mistake, the reason, and where the rule applies.

- **R1 - Unsupported or invented WPR flags and modes.** Rejected: any
  `-maxduration`, `-filesize` or similar bound the tool does not document;
  `-markerflush` (documented obsolete, core section 2 [4]); treating
  `-filemode` as bounded (it is unbounded until the disk fills, core section 2
  [4]); assuming file mode is the default (memory mode is the default);
  expecting a boot trace to record without a reboot between `-addboot` and
  `-stopboot` (core section 3 [4]); using TSS profile names such as `BootGeneral`
  in a raw `wpr.exe` command line (they are TSS argument values, core section 6
  [30]); assuming an on/off recording is a single boot (three reboots by
  default, core section 3 [4][10]); Xperfview as an analysis path (retired,
  core section 1 [1]); `wpaexporter` output file names being predictable (they
  are generated - glob, do not construct; Comparative Analysis Views cannot be
  exported, core section 1.1 [5]).
  Applies to: t_645856ef, t_eef69ce4, t_b5e3e5a3, t_1558e552, t_1f568c63, and
  every doc claim.
- **R2 - No data is never health.** Rejected: an absent, empty, unrenderable,
  unsupported or failed measurement being rendered as healthy, OK, zero or a
  normal value. Required: an explicit state from
  `complete|partial|unavailable|not-collected|unsupported` plus a reason.
  Specific cases: WHEA-Logger absence is not hardware health (platform section
  11 [41]); an unsupported SMART/prediction IOCTL is "not reported" (core
  section 10 [47]); `PagesInputPersec` unavailable is not "no paging"; a device
  with no PnP status is not a healthy device; perflib
  `unavailable|corrupted-suspected` is not zero counters.
  Applies to: t_91d4e281, t_2c7b6fda, t_91d8010d, t_564f783d, t_4d184c2a,
  t_bad9a6f6, t_1f568c63 (gate H07).
- **R3 - No Pages/sec-only conclusions.** Rejected: a paging or memory-pressure
  finding derived from a single paging-rate metric. `Pages/sec` (and
  `PagesInputPersec`) counts pages read to resolve hard faults and is a volume
  indicator, not proof of a memory shortage. Required: a paging conclusion
  needs the rate plus an independent pressure channel, otherwise it downgrades
  to coverage/uncertainty (defect 1.3-1, P0-4). The same rule forbids
  "high hard-fault count therefore more RAM" reasoning.
  Applies to: t_2c7b6fda, t_0bc4950d (rule definition), t_4d184c2a,
  t_bad9a6f6 (the dedicated fixture), t_1558e552 (docs).
- **R4 - No automatic remediation, ever.** Rejected: `DISM /RestoreHealth`,
  `sfc /scannow`, `chkdsk`, `bcdedit` changes, service start/stop, startup-item
  enable/disable, Defender exclusion changes or preference writes, registry
  writes, driver changes, disk/TRIM operations, reboot or suspend, and
  automatic elevation. Recommendations are advisory `nextSteps` with evidence
  links; any state change is a separate, explicitly approved human action
  (platform sections 2, 10, 14 [6][40][52]). A scan-only integrity mode is
  still not in scope for v2 (section 14, U2).
  Applies to: every card; automated source checks in gate H07.
- **R5 - No health score, no synthetic confidence.** Rejected: an aggregate
  health score, an invented percentage confidence, or a "healthy" verdict from
  a partial collection. `confidence` remains a stated enum (D7), and the
  existing tests that assert the absence of a health score MUST keep passing.
- **R6 - No sub-second counter sampling and no counter/trace conflation.**
  Counters are not designed for more than one collection per second (core
  section 5 [19]); PDH is unavailable to OneCore/UWP consumers (core section 5
  [21]); a counter log is not a trace (platform section 15 [61][64]).
- **R7 - No capability claimed from a wrong API class.** WCT reports waits only
  for its documented primitives (core section 7 [33]); per-zone thermal
  percentage has no documented counter API (platform section 8); Defender
  analyzer output is not justification for an exclusion (core section 14 [58]);
  a minifilter callback count is informational with no remediation (core
  section 13 [55]); a bug check code is not a root cause (platform section 11
  [45]).
- **R8 - No silent reversions.** Rejected: `git clean`, `git reset`,
  `git checkout`, `git stash`, or overwriting staged files, and equally the
  quiet deletion of the crash/servicing WIP or of the four untracked research
  and audit documents. No card commits or pushes.

## 13. Specification coverage matrix

Reconstructed section mapping (section 0.4). "Cards" are the cards that own
the work; "Gate" is the proof.

| Spec sections | Area | Owning cards | Gate |
| --- | --- | --- | --- |
| 1-8 | Entry points, consent, read-only safety, process identity, sampling | t_91d4e281, t_2c7b6fda, t_b5e3e5a3 | H00, H02, existing Plan/refusal tests, D5 identity tests |
| 9-15 | Process/CPU sampling, per-core, Utility, scheduler, DPC/ISR | t_2c7b6fda, t_0bc4950d | Telemetry unit tests, fixture rows F18/F19, no-sub-second test |
| 16-23 | Responsiveness/UI hang, WCT, memory, pagefile, pool, leaks, handles | t_2c7b6fda, t_29345eda, t_4d184c2a | Fixture rows (UI hang, wait chain, pool growth, user-mode leak), P0-4 two-channel paging test |
| 24-30 | Storage latency/health, filesystem filters, Defender, Search, volumes | t_2c7b6fda, t_91d8010d, t_29345eda | Unsupported SMART/controller-reset fixtures, `fltmc` parsing tests, Defender report tests |
| 31-46 | Network, GPU, power, thermal, boot, WER/WHEA, drivers, symbols, VBS | t_2c7b6fda, t_91d8010d, t_564f783d, t_645856ef | Network retransmit tests, GPU unavailable-state tests, WHEA recurrence fixture, boot descriptors |
| 47-53 | WPR, Repro, Flight Recorder, trace validation, WPAExporter, sampled vs precise | t_645856ef, t_eef69ce4, t_b5e3e5a3 | H05 argv/ETL gates, exporter table tests, preflight tests |
| 54-60 | Findings, evidence provenance, quality, thresholds, durations, baseline | t_0bc4950d, t_4d184c2a, t_91d4e281 | Evidence-link validation, rule-file validation, baseline-vs-incident tests; spec 60 deferred (U1) |
| 61-63 | Presets, flight recorder | t_0bc4950d, t_645856ef, t_eef69ce4 | "No metadata-only preset" validator, circular bound test |
| 64-70 | Sampling efficiency, event engine, grouping/dedup | t_2c7b6fda, t_91d8010d, t_564f783d | Tier 0 once-per-run test, event grouping tests |
| 71-80 | Finding taxonomy, privacy, no-data behaviour, no health score | t_4d184c2a, t_91d8010d, t_0bc4950d | Category rendering tests, privacy mode tests, H07 invariants |
| 81-82 | Not enumerated by either parent artifact | unassigned | G0 plus G10 traceability sign-off |
| 83-87 | Collector framework, output tree, manifest, machine-readable report | t_91d4e281, t_4d184c2a, t_1558e552 | Envelope tests, H04 output contract, schema validation |
| 88 | Test framework | t_1f568c63 | H02 (pytest plus PS 5.1 harness; Pester not adopted, D13) |
| 89 | Deterministic fixtures / 30 scenarios | t_bad9a6f6 | H03 |
| 90 | Windows VM/hosted gates | t_1f568c63 | H02-H08 |
| 91 | Trace validation | t_645856ef | H05 |
| 92 | Output validation | t_1558e552, t_1f568c63 | H04 |
| 93 | Overhead | t_ed91c6e3 | P2-1 (informational until thresholds are approved) |
| 94 | Entry-point/launcher behaviour | t_1f568c63, existing launcher tests | H08 |
| 95 | Not enumerated by either parent artifact | unassigned | G0 plus G10 |
| 96 | Schema versioning | t_1558e552, t_b5e3e5a3 | Section 4 items 1-7 |
| 97 | Sequencing (do not start P2 while P0 is unreliable) | all | Section 9 order and stop conditions |
| 98-100 | Not enumerated by either parent artifact | unassigned | G0 plus G10 |

## 14. Items with no card (owner decision required)

| # | Item | Evidence | Recommendation |
| --- | --- | --- | --- |
| U1 | Spec 60 - long-term baselines and machine fingerprint | audit section 17 P2 | Defer out of v2: a baseline store needs a retention and privacy decision that does not exist yet. Record the deferral in t_1558e552 docs and in the G10 traceability list. Re-open as a new card only with an explicit retention policy. |
| U2 | Spec 68 - integrity checks | audit section 8 and 17 P2 | Keep out of scope: `DISM /ScanHealth` and `sfc /verifyonly` are read-only, but a scan result is not a performance verdict, and `RestoreHealth` is R4. If introduced later it needs its own consent gate and a clear "not a performance verdict" statement. |
| U3 | Release artifact for v2.0.0 (bundle, tag, pinned SHA-256) | `ci.yml:618-621`, `:648`, `:756` | No card owns it. Fold into t_1558e552's VERSION change plus a release card created by the owner; the pin bump and the artifact hash are a single atomic change. |
| U4 | WPD-12 naming conflict (Defender consent vs remote WinRM) | gap audit section 4.1 | Add a distinct remote ID in the workflow (t_1f568c63) and update the matrix (t_1558e552); until then matrix results are ambiguous. |
| U5 | `docs/development-workflow.md` still says WPD-01..31; `README-FIRST.txt` describes four menu options while START-HERE has five | gap audit sections 4.1-4.2 | Neither file is in t_1558e552's list. Extend that card's file list (owner edit) or create a docs-fixup card. This is a user-visible contradiction, not cosmetic. |
| U6 | `docs/diagnostic-architecture.md` and `docs/technician-workflows.md` | t_1558e552 body | They are new files, not edits; the card should state that explicitly so a worker does not look for them. |
| U7 | Overhead thresholds and the `collector-performance.json` manifest slot | gap audit section 9 | Owner/product decision; until then t_ed91c6e3 results stay informational and the artifact is not added to the manifest. |
| U8 | Perflib health ownership | audit section 17 P0 item 3 | Assigned here to t_2c7b6fda (probe) with the status vocabulary from t_91d4e281 and the data-quality surface from t_4d184c2a; recorded as a comment on both cards. |

## 15. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Shared working directory with concurrent writers corrupts a module or a gate result | High (observed twice) | High | D12 single-writer per file; re-read before edit; Stage 3 only after stages 0-2 stop; re-run any red gate once before treating it as a regression |
| The staged crash/servicing WIP is reverted or rewritten during integration | Medium | High | P0-8; `tests/test_crash_servicing_findings.py` (16 tests) is the regression contract; R8 forbids destructive git commands |
| New modules silently require PS 7 syntax | Medium | High | H00/H02 parser and runtime gates under PS 5.1; no `class`, no PS7 operators (D1) |
| Schema growth breaks Verify or the ZIP whitelist | Medium | Medium | Additive-only policy, cross-version validation test, explicit artifact names (D8, section 4) |
| Thresholds are re-hard-coded inside the new modules | Medium | Medium | D6 plus a test that no numeric threshold literal exists outside the rule file |
| Windows-only work is presented as verified | Medium | High | Section 11 honesty rules; UNVERIFIED labels; owner gate t_5e6e4a21 |
| CI runtime grows past practical limits on the Windows matrix | Medium | Medium | Keep the heavy 30-row matrix in one job, reuse one artifact set per run, do not duplicate the full suite per engine beyond H02 |
| The v2.0.0 release job fails because `VERSION` and the pin diverge | High if forgotten | Medium | Section 4 item 6 and U3 |
| G0 (spec traceability) is never closed and coverage claims ship unverified | Medium | Medium | G0/G10 gates; t_c7351169 must record an unresolved G0 as a confirmed gap |

## 16. Definition of done for this plan

The plan is executed when, at a quiesced revision:

1. Every P0 card is complete and `src/Invoke-WindowsPerformanceDiagnostics.ps1`
   contains the integrated tiered architecture with the crash/servicing WIP
   intact and all pre-existing tests green.
2. `config/diagnostic-rules.json` and `config/diagnostic-presets.json` exist,
   validate, and no numeric threshold remains inline in the production script.
3. Manifest schema `1.3` validates alongside `1.0`-`1.2` cases, and Verify
   accepts all four.
4. Gates H00-H09 pass on the Windows matrix, and the fixture matrix (H03)
   passes under both engines.
5. Rejections R1-R4 are enforced by automated checks, not by prose: no
   undocumented WPR switch, no healthy-from-missing-data path, no
   single-channel paging finding, no remediation command in the source.
6. Owner gate t_5e6e4a21 is PASS or an explicit N/A with a reason per check,
   and G0 is closed before any "complete specification coverage" claim.
7. Release claims match evidence: hosted CI proof stated as such, owner-live
   behaviour stated as partial where it is partial.

## 17. Self-verification of this document

- Scope: `docs/implementation-plan.md` is the only file written by t_96101ac6;
  no source, test, schema, workflow, doc or git state was modified, and no
  `git clean`/`reset`/`checkout`/`stash`/`commit`/`push` was run.
- ASCII/no BOM: verified byte-wise after writing. `LC_ALL=C grep -c '[^ -~]'`
  returns 0 (no byte outside printable ASCII plus newline), `grep -c $'\r'`
  returns 0 (LF-only), and the first three bytes are `23 20 49` (no BOM). The
  byte count, line count and sha256 of the delivered revision are recorded in
  the task completion metadata rather than in this file, because writing them
  here would change them. `git status --short` shows the pre-existing
  staged/untracked set plus this file only; the unstaged diff is empty.
- Coverage: sections 1-100 of the user specification are addressed in section
  13, with sections 81, 82, 95 and 98-100 explicitly recorded as not
  individually enumerated by the parent artifacts and routed to gate G0 rather
  than assumed (section 0.4).
- Rejections required by the task are present and labelled: unsupported WPR
  flags (R1), no-data-as-health (R2), Pages/sec-only conclusions (R3),
  automatic remediation (R4).
- Every P0/P1/P2 item names a card, an owning profile, exact file paths and a
  gate; items without a card are listed in section 14 instead of being hidden.
