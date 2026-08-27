# Changelog

## 0.2.0 — 2026-08-27

Consent-gated WPR capture, machine-readable report schema, and hardened packaging.

- Added `-CaptureWpr` with its own `-ConfirmWprCapture` consent gate: bounded `wpr.exe -start General -filemode` / `-stop` capture writing `wpr-trace.etl`, elevation-required (never auto-elevates; skips with a recorded error on non-elevated consoles), and a `wpr` status block in the manifest (`completed` / `skipped-wpr-not-found` / `skipped-elevation-required` / `failed`).
- Plan mode advertises the WPR capture in `plannedActions` and the plan `wpr` scope without invoking anything.
- Added `schema/diagnostic-report.schema.json` (draft-07) covering Plan and Collect manifests, plus `docs/report-schema.md` documenting the machine-readable contract and versioning policy.
- Added `make-deploy-bundle.sh` (deterministic zip + SHA-256 from a verified clean tree), a Defender-safe `Run-Diagnostics.bat` launcher, and `README-FIRST.txt` with Mark-of-the-Web / Unblock-File recovery steps for `.ps1` files stripped by Windows Security.
- Added GitHub Actions CI (`linux-verify` parse + pytest gate; `windows-verify` on windows-2022/2025 exercising parse under PowerShell 5.1 and pwsh, Plan mode, and both consent refusals).
- Safety contract unchanged: read-only collection, local-only, no auto-elevation, no remediation, no upload, no log clearing.

## 0.1.0 — 2026-08-27

Initial read-only MVP release.

- Added `Invoke-WindowsPerformanceDiagnostics.ps1`, a PowerShell 5.1-compatible local diagnostic collector.
- Collection is explicit-consent only via `-ConfirmLocalCollection` and refuses to run off Windows.
- Added bounded CPU/memory/disk samples, top-process snapshot, System-event summary, per-artifact SHA-256 manifest, and collection-error reporting.
- Added Linux-verifiable plan/consent/non-Windows safety tests plus a Windows live test matrix.
- Defined a Microsoft-official source map and evidence-first safety boundaries.
- No executable repair/remediation, WPR/Procmon/Defender trace, upload, policy change, startup modification, DISM, or SFC capability is included.
