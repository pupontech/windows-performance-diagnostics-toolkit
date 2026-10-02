# Optional read-only Tier 3 snapshots (v2 test build)

These features are implemented in the v2 integration branch, not in published
v1.0.0. They do not repair Search, rebuild an index, load/unload filters, or
change services. No external tool is downloaded.

## Run locally on Windows

Open an elevated Windows PowerShell 5.1 or PowerShell 7 console in the extracted
bundle. Choose a fresh case directory, then run:

```powershell
.\src\Invoke-WindowsPerformanceDiagnostics.ps1 -Mode Collect -Preset general `
  -DurationSeconds 30 -ConfirmLocalCollection `
  -CollectSearchContext -CollectMinifilters -ConfirmEscalationCollection `
  -OutputDirectory C:\Temp\WPD-Tier3-Case -ZipOutput
```

The independent `-ConfirmEscalationCollection` gate is required in addition to
local collection consent. Omit the two collection switches to leave Tier 3
uncollected. Plan mode describes selection but runs neither provider.

## Evidence and limits

- `escalation/search-service-context.json`: actual WSearch service state.
  The default index-status provider is not registered; service-only evidence
  is **partial**, never a claim that the index is healthy or complete.
- `escalation/minifilter-enumeration.json`: parsed `fltmc filters` and `fltmc
  instances` snapshots, with numeric altitude ordering. Altitude is inventory,
  not proof that a filter caused a performance problem. Administrative access
  may be required; a command failure is an error, not a zero-filter result.
- `diagnostic-manifest.json`: `tiers.tier3.adapters` identifies each execution's
  status, coverage, reason and artifact. `recordCount` counts filter rows plus
  available Search service/index records, **not** selected descriptors or
  minifilter instance rows. Optional adapters not wired for execution (WCT and
  PoolMon) explicitly remain unsupported when selected.
- Both evidence files are registered before SHA-256/evidence indexing and are
  included in the case ZIP. Provider/publication exceptions remain unavailable
  and do not contribute successful evidence counts.

Snapshots execute **after** the shared incident capture window, not within the
counter sample loop. Their own started/completed timestamps identify snapshot
provenance; they do not prove filter or service state during a past incident.

## Privacy and sharing

All case output is sensitive. The privacy level affects selected module fields
only and does not sanitize raw event logs, crash dumps, ETL or every case member.
Collect sets `redactionApplied: false`, `wholeCaseRedaction: not-implemented`,
`sensitiveDataWarning: true` and `secretsCollected: null`. Null means unknown:
there is no whole-case secret scan. Full is **not** a redaction mode.

Inspect/redact a copy manually before sharing. Retain originals privately for
integrity verification; changing evidence bytes invalidates their recorded hash.

## Verification boundary

Linux fixtures exercise dispatch, consent, failure handling, serialization and
production caller ordering. GitHub Actions Windows runners exercise real fltmc
and WSearch under both engines, validate schema 1.3 and verify the packaged case.
Those checks do not prove behavior on the owner's Windows endpoint; owner-live
validation is still required. Repro/FlightRecorder and WPA export execution are
outside this implementation slice.
