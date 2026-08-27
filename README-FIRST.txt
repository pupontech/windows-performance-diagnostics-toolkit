WINDOWS PERFORMANCE DIAGNOSTICS TOOLKIT
=======================================
Read-Only Diagnostics Collector for Windows 10/11
Version 0.2.0

This toolkit collects read-only Windows performance diagnostics to help
troubleshoot performance issues. It does NOT upload data, remediate problems,
clear logs, or auto-elevate privileges.

WHAT THIS TOOL COLLECTS
-----------------------
- CPU, memory, and disk performance samples (counters)
- Top processes by resource usage
- System event log entries (recent)
- Optional WPR (Windows Performance Recorder) trace
  (requires explicit consent and elevated console)

All collection is gated by explicit consent prompts. Nothing runs silently.

QUICK START
-----------
Option A (easiest):
  Double-click Run-Diagnostics.bat in the extracted folder.
  The script will ask for explicit consent before collecting anything.

Option B (manual):
  Open PowerShell and run:

    powershell.exe -NoProfile -ExecutionPolicy Bypass `
      -File .\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
      -Mode Plan

  Review the plan, then switch -Mode Plan to -Mode Collect to begin.

THE ZIP OR SCRIPT DISAPPEARED - FIX THIS FIRST
-----------------------------------------------
Windows SmartScreen and Windows Defender may silently block or remove
downloaded unsigned .ps1 files. This is caused by the "Mark of the Web"
(MOTW) alternate data stream that Internet Explorer, Edge, Chrome, and
other browsers attach to files downloaded from the internet.

If you extract the zip and the .ps1 file is missing or silently deleted:

  1. RIGHT-CLICK the zip file in Explorer.
  2. Select PROPERTIES.
  3. At the bottom of the General tab, check the UNBLOCK box.
  4. Click OK, then re-extract.

If the .ps1 still vanishes after extraction:

  1. Open Windows Security (defender icon in system tray).
  2. Go to Virus & threat protection.
  3. Click Protection history.
  4. Find the quarantined item and click Restore.

After extraction, always run this one-time unblock command in PowerShell:

    Unblock-File -Path .\src\Invoke-WindowsPerformanceDiagnostics.ps1

The Run-Diagnostics.bat launcher is far less likely to be removed by
Defender, which is why it exists as the recommended entry point.

HASH VERIFICATION
-----------------
Verify the downloaded zip against the published SHA-256 hash:

    Get-FileHash -Algorithm SHA256 .\windows-performance-diagnostics-toolkit-0.2.0.zip

Compare the output hash to the value in the .sha256 file published alongside
the release. They must match exactly.

SAFETY SUMMARY
--------------
- READ-ONLY: No system changes, no uploads, no remediation.
- NO LOG CLEARING: Event logs and diagnostics are preserved as-is.
- NO AUTO-ELEVATION: The script never requests admin rights on its own.
- WPR TRACE: Only collected when you pass -CaptureWpr AND confirm with
  -ConfirmWprCapture from an already-elevated PowerShell console.
- OUTPUT: All results are written to the directory you specify via
  -OutputDirectory (default: C:\Temp\WPD-Case\).

FILE LAYOUT
-----------
  Run-Diagnostics.bat            - Double-click launcher (safe from Defender)
  src/
    Invoke-WindowsPerformanceDiagnostics.ps1  - Main diagnostics script
  docs/
    official-microsoft-source-map.md          - Reference documentation
    report-schema.md                         - Report JSON contract
    windows-live-test-matrix.md              - Test coverage matrix
  schema/
    diagnostic-report.schema.json            - Machine-readable report schema
  tests/
    test_plan_mode.py                        - Unit tests
  README-FIRST.txt                            - This file
  VERSION                                     - Release version

ISSUES AND FEEDBACK
-------------------
Report bugs, feature requests, or questions at:

    https://github.com/pupontech/windows-performance-diagnostics-toolkit

Include the output of:

    Get-FileHash -Algorithm SHA256 .\src\Invoke-WindowsPerformanceDiagnostics.ps1

when reporting issues so we can verify you are running a known-good version.
