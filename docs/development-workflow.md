# Development Workflow

This document is the canonical change pipeline for this project. Every change —
bug fix, feature, doc — follows the same path so that nothing ships without
being exercised on real Windows (GitHub-hosted VMs) first.

## 1. Work intake (Kanban)

- The project board is `wpd-toolkit` (`hermes kanban boards switch wpd-toolkit`).
- New work is a card with a self-contained body: absolute paths, house rules
  (PS 5.1 compatible, pure ASCII, no BOM, `Set-StrictMode -Version Latest`,
  `$ErrorActionPreference = 'Stop'`, never invent CLI flags), scope limits
  ("touch only X"), and what counts as done + how to verify.
- Assignees: `default` (orchestrator/integration), free worker lanes for
  feature work (`dsflash`, `nim`, `terra`). GPT-family lanes are reserved for
  the primary orchestrator only — never for worker lanes.
- One active writer per file at a time; use `--parent` to serialize dependent
  work. Lanes are banned from destructive git (`git clean` / `git checkout .` /
  `git reset --hard`) — a lane may never wipe sibling work to satisfy its own
  clean-tree gate.

## 2. Implement

- Worker (or orchestrator for small fixes) edits only its assigned files.
- Every lane verifies before reporting: `pwsh` parse gate, `pytest`, ASCII/BOM
  scan, and the specific checks in its card.

## 3. Gate: GitHub VM testing (CI)

`.github/workflows/ci.yml` runs on every push to `main` and every PR:

| Job | Runner | Verifies |
|---|---|---|
| `linux-verify` | ubuntu-latest | pytest suite (plan mode, consent gates, WPR gates, schema, packaging) + pwsh parse gate |
| `windows-verify` | windows-2022 **and** windows-2025 | Parse gates under Windows PowerShell 5.1 and pwsh 7; Plan mode; Collect-without-consent refusal; WPR-without-consent refusal; **invalid-`-OutputDirectory` clear error**; **executes the real `Run-Diagnostics.bat` via `cmd`** and asserts `C:\Temp\WPD-Case\diagnostic-manifest.json` |

A change is not releasable until both jobs are green on both Windows OS
versions. This is what catches the class of bug that Linux-only checks miss
(for example v0.2.1: a trailing backslash before a closing quote in a
`powershell.exe -File` argument becomes a literal quote character, which threw
`GetFullPath ... Illegal characters in path.` on real Windows).

## 4. Release discipline

Every release, without exception:

1. Bump `VERSION` and `$ScriptVersion` in `src/Invoke-WindowsPerformanceDiagnostics.ps1` (semantic versioning).
2. Add a real `CHANGELOG.md` entry describing the change and the root cause for fixes.
3. Push to `main` and wait for CI to be green.
4. Tag `v<semver>`; create the GitHub Release with notes **mirrored from CHANGELOG.md** — never a bare tag or one-line note.
5. Check out the exact `v<semver>` tag and build the zip from that verified clean tree: `bash make-deploy-bundle.sh` (refuses dirty trees and same-version non-tag commits).
6. Attach the zip **and** the `.sha256` asset; then byte-verify: download the published asset and confirm `sha256sum` matches the local build exactly.

## 5. Live handoff (owner)

Per project policy the owner performs live Windows testing themselves (agents
never set up VMs or run live installs). Track it as a board card per
`docs/windows-live-test-matrix.md` (WPD-01..11). The release is considered
"shipped, pending owner live validation", never "validated on real Windows",
until the owner records results back on the board.

## House rules (apply to every file)

- PowerShell 5.1 compatible (no `??`, no ternary, no `::new()` where it breaks 5.1, no pipeline-chain assignment).
- Pure ASCII, no BOM — verify with a Python byte scan.
- Never invent CLI flags: only documented switches for Microsoft tools.
- `.bat` launchers: CRLF line endings, no `\"` before a closing quote, explicit consent flags, CI-safe pause (`if not "%CI%"=="true" pause`).
- Windows-only code paths get Linux-verifiable tests where possible; everything else is documented for the owner's live matrix.
