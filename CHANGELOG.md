# Changelog

## 0.1.0 — 2026-08-27

Initial read-only MVP release.

- Added `Invoke-WindowsPerformanceDiagnostics.ps1`, a PowerShell 5.1-compatible local diagnostic collector.
- Collection is explicit-consent only via `-ConfirmLocalCollection` and refuses to run off Windows.
- Added bounded CPU/memory/disk samples, top-process snapshot, System-event summary, per-artifact SHA-256 manifest, and collection-error reporting.
- Added Linux-verifiable plan/consent/non-Windows safety tests plus a Windows live test matrix.
- Defined a Microsoft-official source map and evidence-first safety boundaries.
- No executable repair/remediation, WPR/Procmon/Defender trace, upload, policy change, startup modification, DISM, or SFC capability is included.
