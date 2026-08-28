# Changelog

## Unreleased

- **Case packaging (`-ZipOutput`)**: after Collect, this run's certified evidence (whitelisted artifacts + `diagnostic-manifest.json`) is zipped into `<output-leaf>-<UTC-stamp>.zip` next to the output folder (pattern from the RemoteDiagnostics `pull-local-logs.ps1` zip-to-desktop behavior). Only files written this run are packaged — stale files in a reused `C:\Temp\WPD-Case` never leak into the zip. The `package` block (path, size, SHA-256) is written back into the manifest on disk; a failed packaging attempt records `status: "failed"` and a `case-package` entry in `collectionErrors`. Plan mode advertises `package-local-case-folder-into-zip` with the destination and name pattern. No separate consent gate (packaging is a local file operation on already-collected evidence). START-HERE options 1/2/3/5 and Run-Diagnostics.bat pass `-ZipOutput`.
- **Remote collection (`-RemoteComputer` + `-ConfirmRemoteCollection`)**: the existing collector runs ON the target over WinRM (remote-exec; stages, consent gates, and skip semantics unchanged), then the case folder is pulled back to this machine and every pulled file's SHA-256 is verified against the remote manifest (`remote.verifiedSha256Count`, `hashVerificationFailed`). The tool **never enables WinRM** — `Test-WSMan` only reports availability (`winrmStatus: ok | failed-winrm-unavailable`), and a failure writes an inspectable minimal manifest. Plan mode advertises `collect-remotely-after-explicit-consent` and switches the safety block (`localOnly: false`, `remoteTarget`, `remoteTransport: winrm`); `readOnly`/`automaticUpload`/`automaticRemediation`/`automaticLogClearing` are unchanged. The remote staging directory and session are removed after the pull (documented in the plan). WPD-12 live gate: loopback WinRM collect on windows-2022/2025 runners.

## 0.6.0 — 2026-08-28

Consent-gated crash-evidence stages (patterns adopted from the field-tested RemoteDiagnostics kit: `pull-minidumps.ps1` + `Pull-BootFailureLogs.bat`).

- **Minidump collection (`-CollectMinidumps` + `-ConfirmMinidumpCollection`)**: crash dumps under `%SystemRoot%\Minidump` are copied read-only into the output `minidumps\` folder (newest first, 512 MB cumulative cap, oversized skipped and counted); the kernel dump `MEMORY.DMP` is recorded as metadata only, never copied. Status `completed` / `failed` / `skipped-no-minidumps` (healthy machines commonly have none — not an error). Each copied dump is certified in the `artifacts` whitelist.
- **Boot-failure evidence (`-CollectBootFailureLogs` + `-ConfirmBootFailureLogCollection`)**: Startup-Repair trail (`SrtTrail.txt`), boot log (`ntbtlog.txt`), CBS, Panther setup, and DISM logs are copied read-only into the output `bootfailure\` folder. Logs over the 100 MB per-file cap are recorded with `skippedReason: "oversized"` — never truncated. Per-source `sourceEntries` report found/copied/skipped so a missing boot log is visible, not silent.
- Both stages: separate consent gates checked before any side effect, Plan-mode advertising (`collect-minidumps-after-explicit-consent`, `collect-boot-failure-evidence-after-explicit-consent`), schema + report-schema coverage, START-HERE option 5 (crash evidence only), Run-Diagnostics.bat includes both.
- **WinRE runbook** (`docs/winre-boot-failure-runbook.md`): for machines that will not boot — collect SRT/CBS/DISM/ntbtlog evidence to a PE drive. Boot logging is **not** enabled automatically; `bcdedit /set {default} bootlog yes` is an explicit, user-confirmed manual step (persistent system change, outside the collector's no-mutation contract).
- Safety contract unchanged: read-only, local-only, no auto-elevation, no remediation.

## 0.5.1 — 2026-08-28

Stability release (found by the Matt-Pocock review + live CI gates).

- **Manifest integrity**: `artifacts` now hashes **only files written this run** — a stale `wpr-trace.etl` from a reused `C:\Temp\WPD-Case` can no longer be certified as evidence of this run.
- **Consent gates before side effects**: a consent-refusing Collect (or a non-Windows host) no longer creates the output directory at all; invalid `-OutputDirectory` again yields the clear error message in every mode (regression from the 0.5.0 consent reorder, fixed).
- **Bounded network probes**: `Test-Connection -Count 3`, `Resolve-DnsName`, and `Get-NetTCPConnection` can block for minutes when ICMP/DNS is silently dropped or the token is restricted (observed as a 120s+ hang for a standard-user batch-logon session). Replaced with `.NET Ping` (2s timeout), `[System.Net.Dns]::GetHostAddresses`, and a native `netstat -ano` parse — network-state collection now completes in seconds everywhere.
- **Sampling resilience**: transient CIM failures `continue` (break only after 3 consecutive); `wpr.exe` exit-code reads are sentinel-initialized so a stale `$LASTEXITCODE` can't leak into the manifest.
- **CI hygiene**: WPD-09 creates its standard user via ADSI with a per-run random password (net.exe rejected the interpolated password; no reusable credential committed), excludes `sec.cfg`/ETLs/NGENPDB from artifacts; WPD-11 auth probes use the real `GITHUB_TOKEN`; the release-flow pin derives from `VERSION`.
- Safety contract unchanged: read-only, local-only, no auto-elevation, no remediation.

## 0.5.0 — 2026-08-28

Read-only network-state snapshot (next pattern adopted from the field-tested RemoteDiagnostics kit: `capture-network-state.ps1`).

- **Network state stage (`Get-NetworkState`)**: every collection now writes `network-state.json` — IP configuration (`ipconfig /all`), adapter status, connection profiles, DNS server configuration and client cache, IPv4 routing table, ARP table, hosts-file active entries, proxy settings (`netsh winhttp` + Internet Settings), established/listening TCP connections, and a security/VPN/filtering software inventory. Read-only and collectible from a standard (non-admin) account; no new consent flag (covered by the existing `-ConfirmLocalCollection` gate).
- **DNS-vs-ping split test**: raw-IP pings (`8.8.8.8`, `1.1.1.1`) versus public-name resolution (`google.com`, `cloudflare.com`, `microsoft.com`) produce a manifest verdict — `dns-and-connectivity-ok`, `dns-failure` (reachable by IP but names do not resolve → hosts file/proxy/DNS-server issue), `icmp-blocked-or-partial`, `connectivity-failure`, or `inconclusive`.
- **Security-software inventory**: running processes and installed programs (64-bit + WOW6432Node Uninstall keys) are matched against a grouped EDR/AV, DNS-filter, firewall/proxy/VPN keyword list (the CrowdStrike+McAfee lesson from 2026-08-19 is baked in); `securitySoftwareMatches` counts land in the manifest, full detail in the artifact. The matcher (`Test-SecuritySoftwareMatch`) is a pure function unit-tested on Linux; `Get-PropertyValue` keeps registry reads StrictMode-safe on sparse Uninstall keys.
- **Resilience**: every network sub-collection is independently guarded — one failing section records a `network-state-<section>` entry in `collectionErrors` and never loses the rest; `network.status`/`sectionErrorCount` in the manifest make partial captures visible.
- Plan mode advertises `collect-network-state-after-explicit-consent` and the `network.subCollections` list; report schema covers the `network` block; live test case WPD-17 added to the matrix; windows-verify asserts the network block and artifact on windows-2022/2025.
- **Matt-Pocock-style review hardening (Standards + Spec axes)**: the manifest's `artifacts` list now hashes **only files written this run** (a stale `wpr-trace.etl` from a reused `C:\Temp\WPD-Case` can no longer be certified); consent gates and the platform check now run **before** the output directory is created (a consent-refusing Collect leaves zero side effects); the sampling loop `continue`s past transient CIM failures instead of breaking to an empty CSV (gives up only after 3 consecutive failures); `wpr.exe` exit-code reads are sentinel-initialized so a stale `$LASTEXITCODE` can't leak into the manifest; CI no longer commits a reusable password (per-run random), no longer ships `sec.cfg`/ETLs in artifacts, the WPD-11 auth probes use the real `GITHUB_TOKEN` (Basic `x-access-token`), and the release-flow pin now derives from `VERSION` so the gate can't silently re-test an old release.
- Safety contract unchanged: read-only, local-only, no auto-elevation, no remediation.

## 0.4.0 — 2026-08-27

Crash evidence analysis + resilient event reading (patterns adopted from the field-tested RemoteDiagnostics kit).

- **Resilient event reader (`Get-EventsSafe`)**: replaces `Get-WinEvent -FilterHashtable` for the System log. Get-WinEvent silently returns **zero events for the entire log** if even one record's provider has an unrenderable message-resource DLL; the new record-by-record .NET reader skips just the bad record and keeps everything else. `skippedUnrenderableCount` is reported in the manifest.
- **Crash analysis (`Get-CrashAnalysis`)**: decodes BugCheck 1001 events into bugcheck codes and flags **unexplained abrupt shutdowns** — Kernel-Power 41 events with no bugcheck within 5 minutes (typically hard freeze / power loss / thermal cutout, not a Windows-detected crash). Emitted as `crashAnalysis` in the manifest (`bugchecks` / `unexplainedShutdowns`).
- **Log availability pre-check**: `Get-WinEvent -ListLog System` before the pull — the manifest's `systemEventLog` block now carries `enabled`, `recordCount`, `pulledCount`, `skippedUnrenderableCount`, so an empty result is distinguishable from a failed read.
- Plan mode advertises `analyze-crash-evidence-after-explicit-consent`; report schema covers `systemEventLog` and `crashAnalysis`; unit tests exercise `Get-CrashAnalysis` on Linux; windows-verify exercises the safe reader end-to-end on windows-2022/2025.
- **WPR profile fix (caught by the WPD-10 live gate)**: the built-in WPR profile is `GeneralProfile`, not `General` — `wpr -start General` fails and the old code trusted the exit code and reported `completed` with no ETL. Now: profile defaults to `GeneralProfile` (with `CPU`/`DiskIO`/`FileIO`/`Network`/`Power`/`GPU`/`Registry` selectable), non-zero `wpr -start` exit codes are treated as failure, and `wpr-trace.etl` existence + size are verified before `completed` is reported. A failed start also means an already-running trace is left untouched.
- Safety contract unchanged: read-only, local-only, no auto-elevation, no remediation.

## 0.3.1 — 2026-08-27

START-HERE.bat rebuilt as a console menu (the "GUI" of the toolkit) and now tested in GitHub VMs.

- `START-HERE.bat` now presents a numbered menu (1 Full+WPR / 2 Basic / 3 Full+WPR+Defender / 4 Plan preview / 5 Exit) after the UAC self-elevation prompt, instead of a bare single run.
- Pre-flight check: if `src\Invoke-WindowsPerformanceDiagnostics.ps1` is missing (Defender Mark-of-the-Web can strip downloaded `.ps1` files), the bat prints the Unblock/Protection-history recovery steps instead of failing silently.
- Every run is tee'd to `C:\Temp\WPD-Case\diagnostics-run.log` so results are always visible; the bat verifies `diagnostic-manifest.json` was produced and reports the artifact list.
- CI-safe: menu supports auto-args (`START-HERE.bat 2`, `START-HERE.bat 4`), UAC elevation is guarded under CI, pause is skipped under CI.
- GitHub VM testing: `windows-verify` now executes the START-HERE menu in auto mode (options 2 and 4) on windows-2022/2025 and asserts both the manifest and the plan JSON.
- Safety contract unchanged.

## 0.3.0 — 2026-08-27

Consent-gated Microsoft Defender performance capture.

- Added `-CaptureDefender` with its own `-ConfirmDefenderCapture` consent gate: a time-bounded
  Defender performance recording via the official `DefenderPerformance` module cmdlet
  `New-MpPerformanceRecording -RecordTo <etl> -Seconds <duration>` (Microsoft-Antimalware-Engine
  and NT kernel process events), elevation-required (never auto-elevates; skips with a recorded
  error on non-elevated consoles), and a `defender` status block in the manifest
  (`completed` / `skipped-defender-module-not-found` / `skipped-elevation-required` / `failed`).
- Plan mode advertises the Defender capture in `plannedActions` and the plan `defender` scope
  without invoking anything. Both consent-gated captures (WPR and Defender) can be planned in the
  same run.
- Documented the `defender` manifest object and the `defender-performance.etl` artifact in
  `docs/report-schema.md`, and added live test cases WPD-12..14 to
  `docs/windows-live-test-matrix.md`.
- Safety contract unchanged: read-only collection, local-only, no auto-elevation, no scans or
  exclusion changes, no remediation, no upload, no log clearing.

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
