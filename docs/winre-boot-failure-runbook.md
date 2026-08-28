# WinRE Boot-Failure Runbook

Collecting boot-failure evidence from a machine that **will not boot**, run from
Windows Recovery Environment (WinRE) or a WinPE USB. This is the offline
complement to the collector's live `-CollectBootFailureLogs` stage
(see [minidump-boot-failure-collection.md](minidump-boot-failure-collection.md)).

Adapted from the field-tested RemoteDiagnostics `Pull-BootFailureLogs.bat`,
with one deliberate change: **boot logging is never enabled automatically.**
`bcdedit /set {default} bootlog yes` is a persistent system change, and the
toolkit's safety contract is read-only — so it is an explicit, user-confirmed
manual step below.

## When to use this

- The machine fails to boot (black screen, boot loop, Startup Repair loop).
- You have bootable media: the machine's own WinRE (Advanced options → Command
  Prompt) or a WinPE USB.
- You already have (or can later collect) the live-system evidence; this runbook
  captures what only the offline environment can reach.

## What is collected

| Evidence | Path (on the system drive) | Notes |
|---|---|---|
| Startup Repair trail | `X:\Windows\System32\LogFiles\Srt\SrtTrail.txt` | Present after Startup Repair ran; the single most useful file. |
| Boot log | `X:\Windows\ntbtlog.txt` | Only exists if boot logging was enabled *before* the failures. |
| Component servicing | `X:\Windows\Logs\CBS\CBS.log` (+ `CBS.persist.log`) | Can be GBs — copy only if reasonably sized, or copy with robocopy `/MAX:104857600` (100 MB). |
| Setup logs | `X:\Windows\Panther\setupact.log`, `setuperr.log` | Present after setup/upgrade. |
| DISM log | `X:\Windows\Logs\DISM\dism.log` | Present after DISM/offline servicing. |
| Crash dumps | `X:\Windows\Minidump\*.dmp`, `X:\Windows\MEMORY.DMP` | Minidumps are small and worth copying; MEMORY.DMP may be GBs — record size/date instead of copying. |

`X:` is the drive letter of the **system** partition as seen from WinRE — this
is frequently not `C:`. Find it with `diskpart` → `list volume`, or run
`bcdedit` and read the `osdevice` line.

## Procedure

1. Boot the machine to WinRE / WinPE and open Command Prompt.
2. Identify the system drive (above). Example below assumes `X:`.
3. Create a timestamped output folder on the **PE drive** (the USB/RE media —
   the system drive may be the one that is broken):

   ```bat
   mkdir D:\bootfailure-20260828
   ```

4. Copy the evidence:

   ```bat
   copy "X:\Windows\System32\LogFiles\Srt\SrtTrail.txt"   D:\bootfailure-20260828\ 2>nul
   copy "X:\Windows\ntbtlog.txt"                           D:\bootfailure-20260828\ 2>nul
   robocopy "X:\Windows\Logs\CBS"       D:\bootfailure-20260828\CBS  /MAX:104857600
   robocopy "X:\Windows\Panther"        D:\bootfailure-20260828\Panther /MAX:104857600
   robocopy "X:\Windows\Logs\DISM"      D:\bootfailure-20260828\DISM /MAX:104857600
   dir  "X:\Windows\Minidump"                                > D:\bootfailure-20260828\minidump-listing.txt 2>nul
   dir  "X:\Windows\MEMORY.DMP"                              >> D:\bootfailure-20260828\minidump-listing.txt 2>nul
   ```

5. (Optional, **user-confirmed**) Enable boot logging for the next boot attempt,
   so the next failure leaves an `ntbtlog.txt`:

   ```bat
   bcdedit /set {default} bootlog yes
   ```

   This is a persistent BCD change. Confirm with the machine's owner first; to
   revert later: `bcdedit /deletevalue {default} bootlog`.

6. Note the failure symptoms and the last-observed boot stage, then zip the
   output folder and hand it over with the live-system case folder.

## Analysis hints

- `SrtTrail.txt` states whether Startup Repair found a root cause; a missing
  `SrtTrail.txt` after a Repair loop means the SR session itself never completed.
- A missing `ntbtlog.txt` means boot logging was never on — step 5 for the next
  attempt.
- Cross-reference the CBS/setup logs with the live system's `system-events-last-24-hours.json`
  and `crashAnalysis` from the collector for the full picture.
