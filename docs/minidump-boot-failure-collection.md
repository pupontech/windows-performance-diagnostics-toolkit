# Minidump + Boot-Failure Evidence Collection — Design Spec

Status: collection stages implemented in v0.6.0; bounded analysis added in the
unreleased crash/servicing findings milestone.
Scope: two consent-gated, read-only Collect-mode stages; Plan-mode advertising;
schema + manifest sections; launcher options; bounded findings analysis; tests.

## 1. Safety contract (unchanged, extended)

Both stages are **read-only against the source system** (copy-out only, never delete/modify
source files, never change boot configuration) and are gated by **explicit per-capability
consent flags**, following the WPR/Defender pattern exactly. Refusal = zero side effects
(gates precede output-directory creation). No automatic upload; artifacts are hashed into
the manifest only if written during this run (existing whitelist).

## 2. New parameters

| Parameter | Purpose |
|---|---|
| `-CollectMinidumps` | Request crash-dump (`.dmp`) collection |
| `-ConfirmMinidumpCollection` | Consent gate for minidump collection |
| `-CollectBootFailureLogs` | Request boot-failure evidence collection |
| `-ConfirmBootFailureLogCollection` | Consent gate for boot-failure evidence |

Consent-refusal messages (exact, asserted by tests):

- `Minidump collection requires -ConfirmMinidumpCollection. No diagnostic data was collected.`
- `Boot-failure log collection requires -ConfirmBootFailureLogCollection. No diagnostic data was collected.`

## 3. Plan-mode advertising

Only when the corresponding `-Collect*` switch is set:

- `plannedActions += 'collect-minidumps-after-explicit-consent'`
- `plannedActions += 'collect-boot-failure-evidence-after-explicit-consent'`
- `plannedActions += 'analyze-servicing-logs-after-explicit-consent'`
- `planManifest.minidumps = { sourcePath, maxTotalBytes, memoryDumpRecordedNotCopied }`
  (`maxTotalBytes` = 512 MB, `memoryDumpRecordedNotCopied` = true)
- `planManifest.bootFailureLogs = { maxBytesPerFile (100 MB), sources: [srt-trail, boot-log,
  cbs-log, setupapi-panther, setupapi-error, dism-log] }`

## 4. Collect-mode behavior

### 4.1 Minidump stage (`minidumps\` output subdirectory)

1. Source: `%SystemRoot%\Minidump` (fallback literal `C:\Windows\Minidump` when `$env:SystemRoot`
   is unset — Linux Plan-mode tests).
2. Record `%SystemRoot%\MEMORY.DMP` metadata (exists / size / last-write) **without copying**
   (kernel dumps can be GBs).
3. Copy each `*.dmp` (top-level only, newest-first) into `<out>\minidumps\<original name>`,
   stopping when the cumulative total would exceed `maxTotalBytes` (skipped ones counted).
4. Each copied file is added to the artifact whitelist as `minidumps\<name>`.
5. Status values: `completed` | `failed` | `skipped-no-minidumps` (no dumps AND no MEMORY.DMP —
   not an error; healthy machines commonly have none).

Manifest section (collect):

```json
"minidumps": {
  "enabled": true, "status": "completed",
  "sourcePath": "C:\\Windows\\Minidump", "maxTotalBytes": 536870912,
  "memoryDump": {"exists": false, "sizeBytes": null, "lastWriteTimeUtc": null},
  "copiedCount": 2, "skippedCount": 0, "totalBytes": 1048576,
  "files": [{"Name": "082826-12345-01.dmp", "SizeBytes": 524288,
             "SourceLastWriteTimeUtc": "2026-08-28T05:00:00.0000000Z"}]
}
```

### 4.2 Boot-failure evidence stage (`bootfailure\` output subdirectory)

| source name | source path (under `%SystemRoot%`) | cap |
|---|---|---|
| `srt-trail` | `System32\LogFiles\Srt\SrtTrail.txt` | — |
| `boot-log` | `ntbtlog.txt` | — |
| `cbs-log` | `Logs\CBS\CBS.log` | 100 MB |
| `setupapi-panther` | `Panther\setupact.log` | 100 MB |
| `setupapi-error` | `Panther\setuperr.log` | 100 MB |
| `dism-log` | `Logs\DISM\dism.log` | 100 MB |

Per source: if present and ≤ cap, copy to `<out>\bootfailure\<original leaf name>`, whitelist as
`bootfailure\<leaf>`, count as copied. Present but over cap → `skippedReason: "oversized"`.
Absent → `found: false` (normal for boot-log unless logging was enabled).

Manifest section (collect):

```json
"bootFailureLogs": {
  "enabled": true, "status": "completed", "maxBytesPerFile": 104857600,
  "copiedCount": 3, "skippedOversizedCount": 1,
  "sourceEntries": [{"name": "srt-trail", "sourcePath": "C:\\Windows\\System32\\LogFiles\\Srt\\SrtTrail.txt",
               "found": true, "sizeBytes": 4096, "copied": true,
               "copiedTo": "bootfailure\\SrtTrail.txt", "skippedReason": null}]
}
```

Plan scope uses `sources` (array of names); Collect scope uses `sourceEntries` (array of
per-source result objects).

Stage error stage-names: `minidump-collection`, `boot-failure-log-collection`.

### 4.3 Bounded analysis

After the copy stages, `Get-CrashAnalysis` joins the bounded System event view
to copied minidumps and LiveKernelReports. A dump whose source mtime is older
than the event lookback is retained with
`eventCorrelationStatus: "outside-event-lookback"`; a source mtime after the
lookback end is treated the same way. Nearby BugCheck 1001 events may provide a
correlated code only when the source mtime is inside the event interval. A
filename date is a fallback hint when source mtime is unavailable; it cannot
override an in-window source timestamp. Minidump and LiveKernelReports rows are
deduplicated by explicit problem signatures. Filename dates/classes are hints
only and the dump binary is not decoded.

`Get-ServicingLogAnalysis` reads at most the configured per-file byte bound,
then parses that bounded window in chunks and writes normalized signatures,
counts and line ranges to `servicing-log-analysis.json`. A growing source cannot
extend the read past the bound, and a file or parent directory that is a
reparse point is refused. The analysis has no raw log lines. The shared tail
registers the artifact, forwards both analysis objects to `Evaluate-Findings`,
and renders `crash-evidence` / `servicing-failure` findings plus explicit
partial/unavailable/failed coverage findings. It does not run DISM/SFC or
perform repair.

### 4.4 Placement

The copy stages run after the shared performance capture window. Crash/servicing
analysis runs after the copies have established their final artifact paths, before
manifest/report generation. These are read-only file operations and do not extend
the performance capture window.

## 5. Schema changes (`schema/diagnostic-report.schema.json`)

Add two optional top-level properties `minidumps` and `bootFailureLogs` (objects,
`additionalProperties: false`, union of Plan-scope and Collect-scope fields so one schema covers
both modes). Widen `crashAnalysis` with artifact rows/signature summaries and add the optional
`servicingAnalysis` object for bounded log-scan results. `plannedActions` items are unenumerated
(no change). `safety` unchanged.

## 6. Launcher changes

- `START-HERE.bat`: the three-mode menu keeps crash evidence inside the single
  Collect flow (alongside the four consent flags); Verify is available as mode 3.
  The manifest-completion echo lists the `minidumps\` / `bootfailure\` folders.
- `Run-Diagnostics.bat`: gains the four new flags.

## 7. Tests (`tests/test_plan_mode.py`)

- Plan advertises `collect-minidumps-after-explicit-consent` + scope; absent without switch.
- Plan advertises `collect-boot-failure-evidence-after-explicit-consent` + scope; absent without.
- Collect refuses without `-ConfirmMinidumpCollection` (exact message).
- Collect refuses without `-ConfirmBootFailureLogCollection` (exact message).
- Both pass consent still refuse non-Windows hosts.
- START-HERE mode test: the three-mode menu and the new flag strings.
- Schema test: `minidumps` / `bootFailureLogs` present.

## 8. WinRE runbook (documentation only)

`docs/winre-boot-failure-runbook.md` — adapted from the RemoteDiagnostics
`Pull-BootFailureLogs.bat`: collect SRT/CBS/DISM/ntbtlog evidence to a timestamped folder on a
PE drive for machines that will not boot. **No automatic `bcdedit /set {default} bootlog yes`** —
turning boot logging on is an explicit, user-confirmed manual step (persistent system change,
outside the collector's no-mutation contract). The runbook is the WinRE complement to the live
boot-failure stage; no new `.bat` ships with the release.

## 9. Version

`VERSION` → 0.6.0, `$ScriptVersion` → '0.6.0' (minor bump: new features). WPD-11 pin in
ci.yml is untouched — the release-flow gate trips on the new tag until the pin is bumped at
release time (existing designed tripwire).
