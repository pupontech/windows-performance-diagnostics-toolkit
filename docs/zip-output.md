# Case Packaging (`-ZipOutput`) — Design Spec

Status: implemented and released in v0.7.0
Scope: optional packaging of a Collect run's certified evidence into a timestamped
zip; Plan-mode advertising; schema `package` block; launcher integration.

## 1. Contract

- `-ZipOutput` is a plain switch — **no separate consent gate**. Packaging is a
  local file operation on evidence the user already consented to collect; it
  adds no data exposure and never touches the source system.
- The zip contains **exactly this run's whitelisted artifacts plus
  `diagnostic-manifest.json`**. Stale files in a reused output folder are never
  included — the package certifies only this run's evidence (same guarantee as
  the `artifacts` whitelist).
- The zip is written **outside** the output folder (its parent), so packaging is
  not recursive: `<output-leaf>-<UTC-stamp>.zip`.
- Read-only against the source system; safety contract unchanged.

## 2. Plan mode

- `plannedActions += 'package-local-case-folder-into-zip'`
- `package = { destination: <parent of output dir>, namePattern: '<output-leaf>-<UTC-stamp>.zip', includesManifest: true }`

## 3. Collect mode

After the manifest is written:

1. `New-CasePackage` (pure file function, Linux-testable) opens the zip in the
   destination directory and copies each whitelisted relative name (backslash
   paths become `/` zip entries; missing files skipped).
2. The `package` block is appended to the manifest **on disk**:
   `{ enabled, status, zipPath, sizeBytes, sha256, includesManifest }`.
3. Failure: `status: "failed"` + `collectionErrors` entry `case-package`; the
   manifest is still re-written so the failure is visible.

Note: the manifest copy **inside** the zip is the pre-package version (written
before the zip was created). The wrapper describes itself; the evidence inside
is certified by the in-zip manifest's `artifacts` block.

## 4. Schema

Top-level optional `package` object (union of Plan-scope and Collect-scope
fields, `additionalProperties: false`, `sha256` pattern `^[A-Fa-f0-9]{64}$`).

## 5. Launchers

START-HERE options 1/2/3/5 and Run-Diagnostics.bat pass `-ZipOutput`; the
completion echo lists the zip.

## 6. Tests

- Plan advertises the action + scope; absent without the switch.
- `New-CasePackage` Linux test: zips exactly the named files (subdir entry uses
  `/`), excludes an unlisted stale file, bytes intact.
- Schema test asserts the `package` property; both .bat tests assert `-ZipOutput`.
