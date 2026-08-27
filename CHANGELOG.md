# Changelog

## 0.2.1 — 2026-08-27

Bug fix release: `Run-Diagnostics.bat` failed on real Windows with `Exception calling "GetFullPath" ... "Illegal characters in path."`

- **Root cause:** the launcher passed `-OutputDirectory "C:\Temp\WPD-Case\"` — a trailing backslash immediately before the closing quote of a `powershell.exe -File` argument is parsed as an escaped quote, so the script received a path ending in a literal `"`, which is illegal in Windows paths.
- Fixed the launcher argument (no trailing backslash) and added a CI-safe `if not "%CI%"=="true" pause` guard so GitHub runners do not hang on the interactive pause.
- Hardened the collector: an invalid `-OutputDirectory` now fails with a clear message (`OutputDirectory '<path>' is not a valid local path: ...`) instead of a cryptic `MethodInvocationException`.
- **GitHub VM testing:** `windows-verify` now executes the real `Run-Diagnostics.bat` via `cmd` on windows-2022/2025 and asserts `C:\Temp\WPD-Case\diagnostic-manifest.json` is produced, plus a clear-error check for invalid paths. Regression test locks the bat to quote-safe/CI-safe form.
- Safety contract unchanged.

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
