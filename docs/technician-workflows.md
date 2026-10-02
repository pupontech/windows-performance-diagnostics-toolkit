# Technician workflows

This runbook is for a read-only Windows performance case. It keeps planning,
collection, interpretation, escalation, and verification separate. Do not skip a
consent switch, invent a WPR argument, or treat an unavailable provider as a
healthy result.

## 1. Preflight

1. Copy the toolkit to a local case workspace. Do not collect to a network share.
2. Confirm the target, operator, symptom window, and whether the machine can be
   restarted. Record the symptom text exactly; do not place credentials or
   secrets in it.
3. Select one preset from the canonical list in `config/diagnostic-presets.json`.
   Use an alias only for compatibility and confirm the recorded `effective`
   preset in the plan.
4. Decide whether Standard or Redacted privacy is sufficient. Use Full only when
   the operator has approval and can use `-ConfirmFullPrivacy`.
5. Decide whether the run needs WPR, an incident marker, or optional escalation.
   Each adds its own consent or administrator requirement.
6. Keep a local destination with enough space for the selected trace budget and
   any requested artifacts. File-mode WPR is unbounded and is not a default.

## 2. Make and review a plan

A basic plan does no collection and writes one file:

```powershell
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Plan `
  -Preset general `
  -OutputDirectory C:\Temp\WPD-Case-001
```

For a reproduction plan with a one-second counter cadence:

```powershell
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Plan `
  -Preset ui-hang `
  -Repro `
  -Tier1IntervalSeconds 1 `
  -OutputDirectory C:\Temp\WPD-Case-001
```

Review `diagnostic-plan.json` before collecting. Confirm:

* `schemaVersion` is `1.3` when the tiered surface is engaged.
* `tiers.preset.requested` and `tiers.preset.effective` match the case.
* `tiers.capturePolicy` shows the accepted profile, duration, mode, budget, and
  source. A refusal such as `unsupported-profile-name` must be resolved before
  Collect; the tool does not silently substitute a profile.
* `tiers.tier1Cadence.intervalSeconds` is at least 1 and the source is clear.
* `tiers.captureMode` contains only `Repro` or `FlightRecorder`, never both.
* `tiers.privacy` reflects the approved level and has no secret collection.
* `tiers.escalation` lists the requested adapters and states consent status.
* `tiers.coveragePlan`, `tiers.dataQualityPlan`, and
  `tiers.evidenceIndexPlan` are present; `healthClaim` is `none` and
  `neverHealthy` is `true`.
* `safety.readOnly`, `safety.automaticUpload`,
  `safety.automaticRemediation`, and `safety.automaticLogClearing` are true,
  false, false, and false respectively.

If the plan is refused, fix the stated input and make a new plan. Do not bypass
fail-closed validation by editing the JSON.

## 3. Collect a bounded case

Collect requires explicit local consent. A general case without WPR is:

```powershell
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Collect `
  -Preset general `
  -ConfirmLocalCollection `
  -OutputDirectory C:\Temp\WPD-Case-001
```

A CPU case with a WPR trace requires both local and WPR consent:

```powershell
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Collect `
  -Preset cpu-heavy `
  -CaptureWpr `
  -ConfirmLocalCollection `
  -ConfirmWprCapture `
  -OutputDirectory C:\Temp\WPD-Case-002
```

Keep the process running for the planned window. Do not reboot, suspend, stop,
clear logs, or repair the host as part of a normal collection. If the symptom
occurs, use the approved marker workflow rather than changing the system.

The collect manifest records the actual tier status. Tier 0 is cached once;
Tier 1 samples are counter rows; Tier 2 is the WPR window; Tier 3 is absent
unless selected and consented. A missing counter remains null. A missing event,
WPR executable, symbol, or optional tool remains an explicit limitation.

## 4. Repro and Flight Recorder choices

Use `-Repro` when the operator can reproduce the symptom during a bounded
window. Use `-FlightRecorder` when the symptom is intermittent and a circular
history is more useful. Never pass both. Neither option performs a reboot or
modifies the target.

Use the preset's expected duration unless the plan explains an override. An
explicit sub-second Tier 1 interval is refused. If a profile or duration cannot
be resolved, stop and review the plan rather than collecting an unbounded or
misaligned trace.

## 5. WPR and markers

Memory mode is the normal WPR path: bounded circular buffer, explicit duration,
and the selected built-in profile. File mode is an exception for cases that need
long retention. It is unbounded, requires `-AllowWprFileMode`, and also requires
`-AcceptUnboundedFileMode`; review free space before consenting.

The marker names are fixed:

* `CAPTURE_START`
* `REPRO_START`
* `INCIDENT_START`
* `INCIDENT_PEAK`
* `INCIDENT_END`
* `CAPTURE_STOP`

Markers are evidence of placement in the shared capture window, not proof of a
cause. If WPR is not present or marker resolution fails, the manifest must show
the reason. Do not add undocumented switches such as a made-up max-duration,
file-size, or marker-flush option.

For boot slowdown, the WPR boot-trace and On/Off descriptors require an
operator-approved boot cycle. The normal collector does not reboot the machine.
WPAExporter table extraction is optional and uses the bounded table plan from
the selected preset; it is not a prerequisite for a valid non-WPA case.

## 6. Optional escalation

Tier 3 adapters require both a selection switch and
`-ConfirmEscalationCollection`. Select only what the case justifies:

| Switch | Evidence target | Typical limitation |
|--------|-----------------|--------------------|
| `-CollectWaitChains` | Wait-chain traversal | Requires an interactive/elevated Windows surface and may have no usable chain. |
| `-CollectPoolEscalation` | Pool-tag attribution | PoolMon or the required provider may be absent. |
| `-CollectSearchContext` | Search service context | Search tooling or service data may be unavailable. |
| `-CollectMinifilters` | Minifilter enumeration | Administrator access is required; filter data may be unsupported. |

Example:

```powershell
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Collect `
  -Preset storage-io `
  -CollectMinifilters `
  -ConfirmEscalationCollection `
  -ConfirmLocalCollection `
  -OutputDirectory C:\Temp\WPD-Case-003
```

Escalation can produce bounded adapter artifacts or an unsupported/not-collected
record. It never downloads a tool, runs remediation, deletes evidence, or
silently upgrades privacy.

## 7. Privacy, admin, and remote collection

Use `-PrivacyLevel Redacted` for a stricter local case. Full privacy requires
both the requested level and `-ConfirmFullPrivacy`; otherwise the run is
refused. Standard and Redacted projections suppress forbidden fields including
passwords, secrets, tokens, cookies, credentials, browser history, document
content, and session keys.

Run the filter and encryption inventory stages elevated when their plan says
administrator is required. A standard-user result is still useful: the manifest
must identify the unavailable capability and its elevation reason.

Remote collection is a separate, explicit path:

```powershell
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Collect `
  -RemoteComputer PC-042 `
  -ConfirmRemoteCollection `
  -ConfirmLocalCollection `
  -Preset general `
  -OutputDirectory C:\Temp\WPD-Remote-PC-042
```

The tool uses WinRM only when requested, never enables WinRM, stages in an
owned temporary directory on the target, pulls the case back, and verifies
SHA-256 values. Review `safety.localOnly`, `remote`, and the hash counts before
sharing the case.

## 8. Review findings and report

Start with the manifest and evidence index, then open `findings.json` and the
offline report. For each finding check:

1. `sourceArtifact` is in the manifest artifact whitelist.
2. `metric`, measured value, and time window are present or explicitly null.
3. Every `evidence.id` resolves in `evidenceIndex`.
4. Coverage and data-quality records do not contradict the conclusion.
5. The `uncertainty`, `limitations`, and `nextSteps` are retained.
6. A WPR profile is a suggested next evidence step, not a diagnosis.

The technician report is normally `case/technician-report.html`. It is
self-contained, offline, HTML-escaped, and linked only to safe relative
artifacts. A report-generation failure is recorded as unavailable; do not
replace it with a manually typed healthy statement.

Interpretation rules:

* no data is not health;
* one sample is not a sustained condition;
* a null or gap breaks the corresponding run unless the rule says otherwise;
* `PagesInputPersec` alone is not proof of paging pressure;
* event proximity is correlation, not causation;
* a minidump filename class does not prove the responsible driver;
* no symbols means the report cannot safely attribute a UI hang to a module;
* optional-tool absence is a coverage limitation.

## 9. Verify and hand off

Run the read-only verifier after collection:

```powershell
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Verify `
  -InputDirectory C:\Temp\WPD-Case-001
```

A successful verification checks the manifest contract, safe paths, artifact
existence, byte counts, SHA-256 values, and any recorded ZIP package. Preserve
the verifier output with the case. If verification fails, retain the original
case, record the error, and do not hand off a partial package as certified.

## 10. Owner-live proof checklist

Hosted tests use injected providers and command seams. They prove shape,
privacy, refusal behavior, path safety, and deterministic transforms, but they
do not prove that a real Windows host exposes every CIM class, event provider,
WPR profile, WPA table, elevation boundary, or launcher behavior.

The owner-live operator must record:

* Windows PowerShell 5.1 parser and runtime result;
* Windows 2022 and Windows 2025 Plan results for every canonical preset and the
  three aliases;
* non-admin and admin Tier 0 capability outcomes;
* a bounded WPR memory-mode start/body/stop with marker evidence;
* a refused WPR file-mode run without the opt-in and a bounded accepted plan
  with both opt-ins;
* Repro and Flight Recorder mutual exclusion;
* one real Tier 1 series with a one-second cadence and visible gaps when a
  provider is unavailable;
* consent refusal for local collection, WPR, Full privacy, and Tier 3;
* absent WPR/WPA/WPAExporter and optional-tool behavior;
* report artifact generation, manifest SHA-256 registration, and Verify output;
* no reboot, repair, log clearing, automatic upload, or automatic remediation.

Record each result in `docs/windows-live-test-matrix.md` with the case folder,
manifest hash, command line excluding credentials, and the exact limitation when
a case is unavailable. A hosted pass must never be copied into the owner-live
column.
