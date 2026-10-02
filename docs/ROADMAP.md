# Roadmap

This roadmap separates shipped implementation, hosted proof, and owner-live Windows
proof. A green fixture or Linux-hosted test does not certify real Win32, WPR,
WPA, elevation, launcher, or Windows PowerShell 5.1 behavior.

## Completed milestones

### M0: Foundation (v0.1.0-v0.8.2)

* Read-only local collection with explicit consent gates.
* Consent-gated WPR and Defender performance captures.
* Crash evidence: minidumps and boot-failure logs.
* Network state snapshot with DNS-vs-ping split test.
* Remote collection over WinRM with SHA-256 verification.
* Case packaging with artifact hash certification.
* Plan, Collect, and Verify modes.
* Read-only case verification.

### M1: Slowdown diagnosis (v0.9.0-v1.0.0)

* Symptom context and collection presets are recorded separately from UTC
  collection windows. A preset is retained even without symptom text.
* Interval process CPU percentages use PID plus start time when available;
  unknown, new, reused, and protected processes remain unknown rather than being
  guessed or clamped.
* In-window memory, paging, physical-disk, throughput, latency, queue, and
  per-volume free-space series are bounded and preserve null coverage.
* Sustained-pressure rules search the whole series, count finite readings, break
  streaks on nulls, and cite a real source artifact and time window.
* Offline `report.html` is HTML-encoded, uses fixed relative links, and has no
  scripts or external assets. `findings.json` carries the machine-readable
  findings.
* Findings, report, disk, volume, and servicing artifacts are registered before
  final manifest hashing so Verify, packaging, and remote pull can certify them.
* Crash and servicing analysis keeps bounded signatures and line ranges while
  leaving raw copied logs as the source of truth. It does not decode dump
  binaries, run repair tools, or claim complete CBS/DISM grammar coverage.

### M2: Tiered evidence contract (v2 implementation)

* Thirteen canonical diagnostic presets and three compatibility aliases are
  resolved from `config/diagnostic-presets.json`.
* Tier 0 static inventory is collected once per run and served from a session
  cache. Tier 1 counter sampling has an explicit one-second floor. Tier 2 WPR
  policy distinguishes bounded memory mode from opt-in unbounded file mode.
* Repro and Flight Recorder strategies are mutually exclusive. Tier 3 optional
  escalation requires explicit selection and consent; absent tools remain
  unsupported.
* Coverage, data quality, evidence index, findings, incidents, inventory,
  telemetry, escalation, privacy, and technician-report handoff are additive
  schema 1.3 surfaces. No-data is never health and no health score is emitted.
* WPR profile selection, marker planning, cleanup, abandoned-session ownership,
  WPAExporter planning, event analysis, privacy projection, and report rendering
  have provider-neutral or injected seams and focused tests.

The v2 source and tests are implemented, but Windows execution remains an
owner-live gate. The owner must verify the real APIs, tools, permissions, and
launchers before declaring the Windows collection path complete.

## In progress: P1 owner-live and release gates

* Run the Windows PowerShell 5.1 parser/runtime matrix on Windows Server 2022
  and Windows Server 2025.
* Run every canonical preset and each alias through Plan; verify requested and
  effective names, profile policy, cadence, privacy, and evidence plans.
* Run standard-user and administrator cases, including inventory elevation
  boundaries, absent providers, empty event logs, and no-data semantics.
* Run bounded WPR memory capture with markers, failed-stop cleanup, abandoned
  session ownership, and optional WPAExporter tables.
* Exercise the explicit refusal paths for file mode, Full privacy, Tier 3,
  WPR consent, and local collection consent.
* Verify real report artifacts, SHA-256 registration, case ZIPs, and Verify
  after an intentional tamper.
* Publish the v2 release only after `VERSION` and the CI release pin are updated
  as one handshake. The unpersisted 100-section source specification remains a
  traceability gap; do not claim complete specification coverage until it is
  stored or the missing sections are owner-reviewed.

## Planned P2 work

* Baseline comparison against a known-good machine or collection, with explicit
  machine identity and retention policy.
* Boot and login diagnostics that measure logon duration and startup impact.
* Application-specific resource and responsiveness tracking.
* Storage reliability and device-lifecycle evidence beyond the existing
  capacity, latency, and queue measurements.
* Power and battery evidence beyond the current power-plan and throttling
  surfaces.
* Reviewed remediation, only after evidence review and a separate explicit
  consent contract. Automatic remediation remains a non-goal.

## Hosted vs owner-live proof

| Area | Hosted fixture or Linux CI | Owner-live Windows |
|------|----------------------------|--------------------|
| PowerShell parse and ASCII/LF/no-BOM checks | Proves syntax accepted by the available pwsh parser and file hygiene. | Required for Windows PowerShell 5.1 runtime. |
| Preset resolution, aliases, schema and refusal paths | Proves deterministic transforms and contract shape with injected inputs. | Required on Windows for real Plan invocation. |
| Tier 0/Tier 1 provider transforms and cache | Proves provider-neutral math, nulls, gaps, and cache behavior. | Required against real CIM, performance counter, storage, NIC, and GPU providers. |
| WPR command construction and cleanup seams | Proves documented argv, bounded policy, and cleanup logic without invoking Windows tools. | Required with real `wpr.exe`, profiles, markers, ETL output, and permissions. |
| Optional escalation seams | Proves consent, privacy, absent-tool, and bounded-output behavior. | Required with real WCT, PoolMon, ProcDump, Defender, Search, and filter surfaces. |
| Findings and technician report | Proves evidence links, safe HTML, and coverage fallback. | Required with real generated artifacts and an owner-reviewed case. |
| Launcher, UAC, MOTW, Defender quarantine | Not proven by hosted provider fixtures. | Required on an owner-managed Windows machine. |
| Remote loopback and package integrity | Synthetic/loopback checks can be hosted. | Required against the supported WinRM setup and a real target. |

## Non-goals

* No automated repair or registry changes.
* No automatic event-log clearing.
* No automatic startup disablement or deletion.
* No automatic Defender exclusions, protection changes, or cloud upload.
* No unattended collection of full memory dumps.
* No health score, no-data-as-health conclusion, or correlation-as-causation
  claim.
* No reboot or suspension as part of normal collection.
