# Diagnostic architecture

## Purpose and boundary

The toolkit is a read-only evidence collector for Windows performance and
reliability investigations. Its contract is a planner, a collector, and a
verifier, not an automatic repair system. It records observations, gaps, and
safe next steps; it does not claim that missing data is healthy and it never
changes system state, clears logs, uploads a case, or applies remediation.

The v2 layer is additive to the existing crash, servicing, network, disk, boot,
Defender, minidump, remote, and package surfaces. The default invocation stays
on the legacy path. A preset, a capture strategy, an explicit Tier 1 cadence,
or an escalation selection engages the four-tier surface and emits schema 1.3.

## Execution flow

1. Resolve command parameters, the selected preset, module availability, WPR
   policy, cadence, capture strategy, privacy level, and escalation consent.
2. In Plan mode, write exactly `diagnostic-plan.json`. Describe projected work
   as `not-collected`; do not create collector artifacts or run providers.
3. In Collect mode, require local collection consent and any selected stage
   consent before creating the case directory or invoking a provider.
4. Collect Tier 0 once, sample Tier 1 at or above the 1 second floor, and run
   Tier 2 in the same wall-clock window when selected.
5. Run Tier 3 only after explicit adapter selection and explicit escalation
   consent. Missing optional tools are recorded as unsupported.
6. Normalize coverage and data quality, create evidence records, generate
   findings only when their evidence links resolve, and write the technician
   report when the report module is available.
7. In Verify mode, read the case and check the manifest contract, safe relative
   paths, byte counts, SHA-256 values, and optional package integrity. Verify is
   read-only.

## Module ownership

| Module or file | Responsibility | Failure contract |
|---------------|----------------|------------------|
| `src/Invoke-WindowsPerformanceDiagnostics.ps1` | Parameter validation, mode dispatch, shared resolution, tier orchestration, legacy artifact compatibility, manifest assembly, and consent gates. | Fail closed for conflicting modes, unknown presets, sub-second cadence, missing required consent, unsafe paths, and unsupported collecting profiles. |
| `src/Wpd.Common.psm1` | UTC/time helpers, collector result envelopes, coverage/data-quality records, evidence records, path validation, privacy projection, and confidence helpers. | Empty or malformed input is unavailable or partial with reasons; it is never healthy. |
| `src/Wpd.Collectors.psm1` | Provider-neutral collection composition and Tier 0/Tier 1 integration points. | Each capability can fail independently; one provider failure does not erase other evidence. |
| `src/Wpd.Inventory.psm1` | Tier 0 static inventory: OS, hardware, drivers, power, storage, NIC, services, security, startup, filters, pagefiles, virtualization, encryption, and recent changes. | Administrator-only capabilities expose an elevation reason; unsupported or empty providers remain visible with explicit status. |
| `src/Wpd.Telemetry.psm1` | Tier 1 counter transforms and identity-aware process, CPU, memory, storage, network, and GPU series. | Missing counters are null with coverage reasons. Sampling does not re-query static inventory. |
| `src/Wpd.Etw.psm1` | WPR profile policy, bounded memory recording, explicitly accepted unbounded file mode, markers, abandoned-session ownership, cleanup, WPAExporter planning, boot descriptors, and symbol policy. | Missing tools and unsupported profiles are unavailable or unsupported; only documented command arguments are constructed. |
| `src/Wpd.Events.psm1` | Bounded reliability-event queries and analysis for WER, WHEA, boot/shutdown, Kernel-Power, and change timelines. | Empty successful queries are `no-events-observed` and not evidence of health; unrenderable records retain bounded XML when available. |
| `src/Wpd.Escalation.psm1` | Consent-gated Tier 3 descriptors and adapters for wait chains, ProcDump mini dumps, PoolMon/WPR, Defender, Search, and minifilters. | No adapter runs without consent. Absent utilities are unsupported and no automatic download or repair occurs. |
| `src/Wpd.Report.psm1` | Evidence-linked findings, coverage findings, technician report ordering, safe relative links, and escaped offline HTML. | Findings without evidence are withheld or represented as coverage; report generation failure is unavailable. |

The entry point imports the modules with a local scope so legacy helper names in
the script remain stable for dot-sourced compatibility tests. The entry point
uses explicit module-call seams for module-owned policy and reporting; the
module surface status is retained in every v2 plan/collect block.

## Four-tier model

Tier 0 is static and cached. A cache key includes the host, effective preset,
and privacy level; `-Refresh` is the explicit escape hatch. Tier 1 is a
counter-only time series with a minimum one-second cadence. It must not turn a
static class query into a repeated live measurement. Tier 2 is a bounded WPR
recording aligned with the counter window. Tier 3 is optional escalation and is
never implied by a finding.

The tiers are not four levels of severity. They are collection scopes. A Tier 0
or Tier 1 result can be partial or unavailable, and a Tier 3 result can be
unsupported. No tier exports a health score or a `healthy` status.

## Evidence and report boundary

Every interpretation has a source artifact, metric or observation, time window
when applicable, and one or more evidence ids. The manifest artifact whitelist
contains the relative path, size, and SHA-256 for files written by the run. The
evidence index joins finding ids to those artifacts but does not replace the
whitelist. HTML report links are fixed relative paths and are escaped before
rendering.

The report layer uses coverage findings when a rule lacks required independent
evidence. For example, a paging metric alone cannot establish memory paging
pressure; a second pressure channel is required. A missing event log, missing
symbol, absent WPR tool, or empty provider is a limitation, not a normal or
healthy result. Correlation is reported as correlation and not as causation.

## Privacy and elevation

`Standard` is the default privacy level. `Redacted` is stricter and hashes or
suppresses configured identifiers, paths, users, and command lines. `Full` is
an explicit opt-in and requires `-ConfirmFullPrivacy`. Forbidden fields such as
passwords, tokens, secrets, cookies, credentials, browser history, document
content, and session keys are not retained by the privacy projection.

Most inventory capabilities can run as a standard user. Filter inventory and
encryption status require administrator access. WPR, Defender performance
recording, crash-dump stages, boot-failure stages, remote WinRM collection, and
Tier 3 adapters each have their own explicit consent or elevation limitation.
The report records that limitation instead of implying that the capability was
checked successfully.

## WPR and boot boundaries

Memory mode is the default bounded circular buffer. File mode is unbounded and
requires both the file-mode opt-in and acceptance of the free-space risk. Repro
and Flight Recorder are mutually exclusive capture strategies; neither causes
a reboot or suspension. The `wpr -marker` names are part of the evidence
contract, and markers share the Tier 1 window.

The WPR On/Off and boot-trace commands are descriptors unless an operator runs
the separately approved boot workflow. Boot capture requires a real boot cycle;
the normal collector does not initiate one. WPAExporter table extraction is
optional and bounded by the preset table plan. A missing WPR, WPA, or
WPAExporter executable is visible in the plan and manifest.

## Compatibility and proof status

The JSON schema keeps 1.0, 1.1, and 1.2 manifests valid and adds 1.3 for the
v2 surface. The script remains PowerShell 5.1-compatible by construction; the
hosted Linux checks use the available PowerShell parser and injected providers.
The owner-live matrix is the proof for Windows PowerShell 5.1, real Win32/CIM
providers, real WPR/WPA tools, elevation, launcher behavior, and actual ETL
output. Hosted green tests do not claim those owner-live properties.

The implementation plan, source modules, preset/rule JSON, and test-and-live
gap audit are the source artifacts for this architecture:

* `docs/implementation-plan.md`
* `docs/test-and-live-gap-audit.md`
* `config/diagnostic-presets.json`
* `config/diagnostic-rules.json`
* `schema/diagnostic-report.schema.json`
* `tests/`
* `docs/windows-live-test-matrix.md`
