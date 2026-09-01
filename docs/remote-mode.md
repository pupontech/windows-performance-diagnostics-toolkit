# Remote Mode — Design Spec

Status: **implemented and released in v0.7.0**. Owner-approved contract change
(`localOnly: false` in remote mode only).

## 1. Problem

A technician sits at machine A; the broken machine B is on the network. Today
the toolkit only collects on the machine it runs on. Remote mode lets a
consented collection run on B and pulls the case folder to A over WinRM —
without ever shipping the enable-remote-diag.ps1 approach (Enable-PSRemoting +
48h auto-revert scheduled task) into the toolkit.

## 2. Architecture: remote-exec collector (not local-query)

Run the **existing collector on the target** and pull the results:

1. `-RemoteComputer <name>` + `-Credential` (or integrated auth) +
   `-ConfirmRemoteCollection` (new consent gate).
2. Reachability + capability check: `Test-WSMan` (WinRM must already be
   enabled on B; if not, the tool says exactly that — it does NOT enable it).
3. `New-PSSession` → `Copy-Item -ToSession` the collector → `Invoke-Command`
   the collector in Collect mode with the same flags (minus remote-specific
   ones) into a remote output dir.
4. `Copy-Item -FromSession` the whole case folder (incl. manifest) to a local
   output dir; verify the manifest parses, `mode == Collect`, and every
   artifact's SHA-256 matches (the existing whitelist contract).
5. Cleanup: remove the remote output dir + session (removal of **our own**
   temp artifacts, documented in the plan).

Why remote-exec beats local-query: every stage runs on the real machine
(Get-CimInstance, Get-NetAdapter, WinRM-free network probes, minidump reads),
the consent gates and elevation checks work unchanged, and the manifest is
produced by the same code path — the remote run is byte-equivalent to a local
run.

## 3. Safety contract changes

Plan manifest `safety` block for remote mode:

| Field | Local (today) | Remote (new) |
|---|---|---|
| `localOnly` | true | **false** |
| `remoteTarget` | — | `<computer>` |
| `remoteTransport` | — | `winrm` |
| `readOnly` | true | true (unchanged — still no mutation on B) |
| `automaticUpload` | false | false (pull is local-directed, consent-gated) |
| `automaticRemediation` | false | false |
| `automaticLogClearing` | false | false |

Consent: a remote collection requires `-ConfirmRemoteCollection` IN ADDITION
to `-ConfirmLocalCollection` (the pull writes to the local disk). Refusal =
zero side effects, same as today. WPR/Defender on the remote follow the
existing per-capability gates and skip if the remote console is not elevated.

WinRM enablement is **never** performed by the tool. If `Test-WSMan` fails,
the plan/manifest says `status: 'skipped-winrm-unavailable'` with the exact
service/firewall guidance — the tech enables WinRM out-of-band (documented,
consent-owned).

## 4. Implemented scope (v0.7.0)

- Remote Collect of the full existing stage set (samples, processes, network,
  events, crash analysis, minidumps, boot-failure logs) — WPR/Defender only if
  the remote console is elevated (their existing skip semantics).
- Remote Plan mode (`-Mode Plan -RemoteComputer X`) advertises the same plan
  without running anything.
- Same schema contract; new optional `remote` block in the manifest
  (`{ computerName, transport, winrmStatus, sessionDurationSeconds,
  pulledFileCount, verifiedSha256Count }`).
- `.bat` launchers unchanged (remote mode is a technician CLI path, not a
  double-click path) — remote usage documented in README + a
  `docs/remote-mode.md` operator guide.

## 5. Deliberately NOT in v1

- WinRM/firewall enablement or auto-revert (the kit's `enable-remote-diag.ps1`
  is explicitly rejected — 48h exposed WinRM violates the toolkit's contract).
- `-ZipOutput` on the remote (packaging happens locally after the pull).
- Credential caching, jump hosts, or multi-hop.

## 6. Tests (Linux-verifiable)

- Plan mode advertises `collect-remotely-after-explicit-consent` + the remote
  safety block; absent without `-RemoteComputer`.
- Collect refuses without `-ConfirmRemoteCollection` (before any network I/O).
- Refuses non-Windows hosts (WinRM is Windows-only).
- Manifest validation: schema gains the `remote` block.
- Live gates (windows-verify/wpd-live-gates): loopback WinRM test —
  enable WinRM on the runner, run remote collect against `localhost`, assert
  the pulled manifest verifies. (Runner self-enable is CI-only and does not
  ship enablement behavior in the tool.)

## 7. Operator guide

Prerequisites on the target (operator-owned, never performed by the tool):

- WinRM listening: `Enable-PSRemoting -Force -SkipNetworkProfileCheck` from an
  elevated console on the target (or WinRM already enabled by policy).
- The operator's account must be a WinRM user on the target
  (`Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI`
  or the default admin/`Remote Management Users` membership).

Usage (from the technician machine, Windows only):

```powershell
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Plan -RemoteComputer SRV-DIAG-01 -OutputDirectory C:\Temp\WPD-Remote   # advertise first
powershell.exe -NoProfile -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
  -Mode Collect -ConfirmLocalCollection -ConfirmRemoteCollection `
  -RemoteComputer SRV-DIAG-01 -Credential (Get-Credential) `
  -OutputDirectory C:\Temp\WPD-Remote -ZipOutput
```

What happens: the collector is staged to `%TEMP%\WPD-Remote-Case` on the target,
runs there with the same consent gates (WPR/Defender skip if the remote console
is not elevated), the case folder is pulled back, every pulled file's SHA-256 is
compared to the remote manifest, the local manifest is the remote manifest plus
the `remote` block, and the staging directory + session are removed. If WinRM is
unreachable the manifest records `winrmStatus: failed-winrm-unavailable` — no
artifacts, no side effects on the target.
