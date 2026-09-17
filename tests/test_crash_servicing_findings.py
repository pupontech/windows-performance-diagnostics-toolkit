"""Behavioral tests for crash and servicing evidence findings.

These tests extract the real PowerShell functions from the collector and drive
synthetic evidence through them. They deliberately avoid Windows-only event-log
and filesystem providers while proving the parser, bounded file scan, artifact
correlation, and findings/report wiring.
"""

import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "src" / "Invoke-WindowsPerformanceDiagnostics.ps1"


SUPPORT_FUNCTIONS = [
    "Get-SafeObjectProperty",
    "Get-CaseJsonProperty",
    "Get-CaseFileLinkCount",
]


def run_pwsh(body: str, functions: list[str]) -> str:
    """Extract real functions from the collector and execute a test body."""
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    assert shutil.which(powershell), f"{powershell} is required for the PowerShell verification gate"
    names = ", ".join(f"'{name}'" for name in functions)
    script_path = str(SCRIPT).replace("'", "''")
    harness = f"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{script_path}', [ref]$null, [ref]$null)
foreach ($name in @({names})) {{
    $found = @($ast.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }}, $true))
    if ($found.Count -eq 0) {{ throw "function $name not found in the collector" }}
    Invoke-Expression $found[0].Extent.Text
}}
Set-StrictMode -Version Latest
{body}
"""
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-Command", harness],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, (
        f"pwsh failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    return result.stdout


def test_servicing_parser_deduplicates_cbs_and_hresult_signatures():
    """Known CBS/DISM error grammars become bounded aggregate signatures, not raw
    log text or provider objects."""
    body = r"""
$lines = @(
    '[SR] Error: CBS_E_INVALID_PACKAGE while processing package',
    '[SR] Error: CBS_E_INVALID_PACKAGE while processing package',
    'DISM Error: 0x800F081F - The source files could not be found',
    'The operation completed successfully.'
)
$analysis = ConvertFrom-ServicingLogLines -SourceName 'cbs-log' -Lines $lines
[pscustomobject]@{
    Status = $analysis.status
    LineCount = $analysis.lineCount
    MatchedLineCount = $analysis.matchedLineCount
    Signatures = @($analysis.signatures | ForEach-Object {
        "$($_.signature)|$($_.kind)|$($_.count)|$($_.firstLineNumber)|$($_.lastLineNumber)"
    })
    ContainsRawLineText = (($analysis | ConvertTo-Json -Depth 8) -match 'source files could not be found')
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(body, ["ConvertFrom-ServicingLogLines"] + SUPPORT_FUNCTIONS)
    )

    assert payload["Status"] == "completed"
    assert payload["LineCount"] == 4
    assert payload["MatchedLineCount"] == 3
    assert payload["Signatures"] == [
        "CBS_E_INVALID_PACKAGE|cbs-error|2|1|2",
        "0x800F081F|hresult|1|3|3",
    ]
    assert payload["ContainsRawLineText"] is False


def test_servicing_parser_ignores_success_status_codes():
    """Success return codes must not become ERROR_* or generic failure
    signatures merely because a line contains the word Error."""
    body = r"""
$analysis = ConvertFrom-ServicingLogLines -SourceName 'dism-log' -Lines @(
    'CBS operation returned ERROR_SUCCESS',
    'Error: ERROR_SUCCESS_REBOOT_REQUIRED',
    'Error: ERROR_SUCCESS (0x00000000)'
)
[pscustomobject]@{
    LineCount = $analysis.lineCount
    MatchedLineCount = $analysis.matchedLineCount
    SignatureCount = @($analysis.signatures).Count
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(body, ["ConvertFrom-ServicingLogLines"] + SUPPORT_FUNCTIONS)
    )

    assert payload == {"LineCount": 3, "MatchedLineCount": 0, "SignatureCount": 0}


def test_servicing_file_analysis_scans_copied_logs_and_preserves_collection_shape(
    tmp_path,
):
    """The integration helper reads only copied, bounded evidence and reports
    non-copied sources instead of pretending they were analyzed."""
    log_dir = tmp_path / "bootfailure"
    log_dir.mkdir()
    log_path = log_dir / "CBS.log"
    log_path.write_text(
        "header\n"
        "Error CBS_E_INVALID_PACKAGE\n"
        "Error CBS_E_INVALID_PACKAGE\n",
        encoding="utf-8",
    )
    output = str(tmp_path).replace("'", "''")
    body = f"""
$entries = @(
    [pscustomobject]@{{ name='cbs-log'; found=$true; copied=$true; copiedTo='bootfailure\\CBS.log'; sizeBytes={log_path.stat().st_size}; skippedReason=$null }},
    [pscustomobject]@{{ name='dism-log'; found=$true; copied=$false; copiedTo=$null; sizeBytes=999; skippedReason='oversized' }}
)
$result = Get-ServicingLogAnalysis -SourceEntries $entries -OutputDirectory '{output}'
[pscustomobject]@{{
    Status = $result.status
    LogCount = @($result.logs).Count
    ScannedLogCount = $result.scannedLogCount
    CbsStatus = @($result.logs)[0].scanStatus
    CbsLines = @($result.logs)[0].lineCount
    CbsSignatures = @(@($result.logs)[0].signatures | ForEach-Object {{ "$($_.signature)|$($_.count)" }})
    DismStatus = @($result.logs)[1].scanStatus
    UnavailableLogCount = $result.unavailableLogCount
}} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            ["Get-ServicingLogAnalysis", "ConvertFrom-ServicingLogLines", "Test-CasePathHasReparsePoint"]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {
        "Status": "partial",
        "LogCount": 2,
        "ScannedLogCount": 1,
        "CbsStatus": "completed",
        "CbsLines": 3,
        "CbsSignatures": ["CBS_E_INVALID_PACKAGE|2"],
        "DismStatus": "not-copied",
        "UnavailableLogCount": 1,
    }


def test_servicing_file_analysis_rejects_reparse_point_logs(tmp_path):
    """A copied-log path must not follow a symlink/junction outside the case
    directory while scanning evidence."""
    log_dir = tmp_path / "bootfailure"
    log_dir.mkdir()
    outside = tmp_path / "outside.log"
    outside.write_text("Error CBS_E_INVALID_PACKAGE\n", encoding="utf-8")
    log_path = log_dir / "CBS.log"
    try:
        log_path.symlink_to(outside)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlink creation unavailable: {error}")

    output = str(tmp_path).replace("'", "''")
    body = f"""
$entry = [pscustomobject]@{{ name='cbs-log'; found=$true; copied=$true; copiedTo='bootfailure\\CBS.log'; sizeBytes=1; skippedReason=$null }}
$result = Get-ServicingLogAnalysis -SourceEntries @($entry) -OutputDirectory '{output}'
$log = @($result.logs)[0]
[pscustomobject]@{{ Status=$result.status; Scanned=$result.scannedLogCount; ScanStatus=$log.scanStatus; SignatureCount=@($log.signatures).Count }} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            [
                "Get-ServicingLogAnalysis",
                "ConvertFrom-ServicingLogLines",
                "Test-CasePathHasReparsePoint",
            ]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {
        "Status": "partial",
        "Scanned": 0,
        "ScanStatus": "reparse-point",
        "SignatureCount": 0,
    }


def test_servicing_file_analysis_accepts_production_ordered_dictionary_entries(tmp_path):
    """Collection emits OrderedDictionary entries; the analyzer must read
    their keys just like deserialized PSCustomObject properties."""
    log_dir = tmp_path / "bootfailure"
    log_dir.mkdir()
    log_path = log_dir / "CBS.log"
    log_path.write_text("Error CBS_E_INVALID_PACKAGE\n", encoding="utf-8")
    output = str(tmp_path).replace("'", "''")
    body = f"""
$entry = [ordered]@{{ name='cbs-log'; found=$true; copied=$true; copiedTo='bootfailure\\CBS.log'; sizeBytes={log_path.stat().st_size}; skippedReason=$null }}
$result = Get-ServicingLogAnalysis -SourceEntries @($entry) -OutputDirectory '{output}'
$log = @($result.logs)[0]
[pscustomobject]@{{ Status=$result.status; Name=$log.name; ScanStatus=$log.scanStatus; Signature=@($log.signatures)[0].signature }} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            ["Get-ServicingLogAnalysis", "ConvertFrom-ServicingLogLines", "Test-CasePathHasReparsePoint"]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {
        "Status": "completed",
        "Name": "cbs-log",
        "ScanStatus": "completed",
        "Signature": "CBS_E_INVALID_PACKAGE",
    }


def test_servicing_file_analysis_rejects_hardlink_logs(tmp_path):
    """A hardlink under the case directory can expose an outside file without
    being a reparse point, so it must be refused too."""
    log_dir = tmp_path / "bootfailure"
    log_dir.mkdir()
    outside = tmp_path / "outside.log"
    outside.write_text("Error CBS_E_INVALID_PACKAGE\n", encoding="utf-8")
    log_path = log_dir / "CBS.log"
    try:
        os.link(outside, log_path)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"hardlink creation unavailable: {error}")

    output = str(tmp_path).replace("'", "''")
    body = f"""
$entry = [pscustomobject]@{{ name='cbs-log'; found=$true; copied=$true; copiedTo='bootfailure\\CBS.log'; sizeBytes=1; skippedReason=$null }}
$result = Get-ServicingLogAnalysis -SourceEntries @($entry) -OutputDirectory '{output}'
$log = @($result.logs)[0]
[pscustomobject]@{{ Status=$result.status; ScanStatus=$log.scanStatus; SignatureCount=@($log.signatures).Count }} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            ["Get-ServicingLogAnalysis", "ConvertFrom-ServicingLogLines", "Test-CasePathHasReparsePoint"]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {
        "Status": "partial",
        "ScanStatus": "hardlink",
        "SignatureCount": 0,
    }


def test_servicing_file_analysis_hard_bounds_a_growing_input_stream(tmp_path):
    """A file-like input that grows after its initial length check must still
    be limited to MaxScanBytes rather than read until EOF."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("named pipes unavailable on this platform")

    log_dir = tmp_path / "bootfailure"
    log_dir.mkdir()
    fifo_path = log_dir / "CBS.log"
    os.mkfifo(fifo_path)
    output = str(tmp_path).replace("'", "''")
    body = f"""
$entry = [pscustomobject]@{{ name='cbs-log'; found=$true; copied=$true; copiedTo='bootfailure\\CBS.log'; sizeBytes=0; skippedReason=$null }}
$result = Get-ServicingLogAnalysis -SourceEntries @($entry) -OutputDirectory '{output}' -MaxScanBytes 128
$log = @($result.logs)[0]
[pscustomobject]@{{ Status=$result.status; Lines=$log.lineCount; Bytes=$log.bytesScanned; Truncated=$log.scanTruncated; TopTruncated=$result.truncatedLogCount }} | ConvertTo-Json -Depth 8 -Compress
"""

    def write_growing_input():
        try:
            with fifo_path.open("wb") as handle:
                handle.write((b"Error CBS_E_INVALID_PACKAGE\n" * 2000))
        except BrokenPipeError:
            pass

    writer = threading.Thread(target=write_growing_input, daemon=True)
    writer.start()
    payload = json.loads(
        run_pwsh(
            body,
            ["Get-ServicingLogAnalysis", "ConvertFrom-ServicingLogLines", "Test-CasePathHasReparsePoint"]
            + SUPPORT_FUNCTIONS,
        )
    )
    writer.join(timeout=5)

    assert payload["Status"] == "partial"
    assert payload["Bytes"] <= 128
    assert payload["Truncated"] is True
    assert payload["TopTruncated"] == 1
    assert payload["Lines"] < 2000


def test_servicing_file_analysis_skips_a_file_over_the_scan_bound(tmp_path):
    """A reused or unexpectedly large copied log must be reported as bounded
    evidence, not read into memory or treated as successfully analyzed."""
    log_dir = tmp_path / "bootfailure"
    log_dir.mkdir()
    log_path = log_dir / "CBS.log"
    log_path.write_text("Error CBS_E_INVALID_PACKAGE\n", encoding="utf-8")
    output = str(tmp_path).replace("'", "''")
    body = f"""
$entry = [pscustomobject]@{{ name='cbs-log'; found=$true; copied=$true; copiedTo='bootfailure\\CBS.log'; sizeBytes={log_path.stat().st_size}; skippedReason=$null }}
$result = Get-ServicingLogAnalysis -SourceEntries @($entry) -OutputDirectory '{output}' -MaxScanBytes 1
$log = @($result.logs)[0]
[pscustomobject]@{{ Status=$result.status; Scanned=$result.scannedLogCount; ScanStatus=$log.scanStatus; SignatureCount=@($log.signatures).Count }} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            ["Get-ServicingLogAnalysis", "ConvertFrom-ServicingLogLines", "Test-CasePathHasReparsePoint"]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {
        "Status": "partial",
        "Scanned": 0,
        "ScanStatus": "oversized",
        "SignatureCount": 0,
    }


def test_servicing_file_analysis_does_not_mark_a_stable_exact_bound_truncated(tmp_path):
    """A stable regular file whose full length equals the bound is complete,
    not a truncated prefix."""
    log_dir = tmp_path / "bootfailure"
    log_dir.mkdir()
    log_path = log_dir / "CBS.log"
    log_path.write_bytes(b"x" * 128)
    output = str(tmp_path).replace("'", "''")
    body = f"""
$entry = [pscustomobject]@{{ name='cbs-log'; found=$true; copied=$true; copiedTo='bootfailure\\CBS.log'; sizeBytes=128; skippedReason=$null }}
$result = Get-ServicingLogAnalysis -SourceEntries @($entry) -OutputDirectory '{output}' -MaxScanBytes 128
$log = @($result.logs)[0]
[pscustomobject]@{{ Status=$result.status; Truncated=$log.scanTruncated; TopTruncated=$result.truncatedLogCount }} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            ["Get-ServicingLogAnalysis", "ConvertFrom-ServicingLogLines", "Test-CasePathHasReparsePoint"]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {"Status": "completed", "Truncated": False, "TopTruncated": 0}


def test_all_unreadable_servicing_logs_report_unavailable_evidence(tmp_path):
    """Per-log read failures are evidence coverage gaps, not top-level analyzer
    failures, even when no requested log could be scanned."""
    log_dir = tmp_path / "bootfailure"
    log_dir.mkdir()
    log_path = log_dir / "CBS.log"
    log_path.write_text("Error CBS_E_INVALID_PACKAGE\n", encoding="utf-8")
    output = str(tmp_path).replace("'", "''")
    body = f"""
$entries = @(
    [ordered]@{{ name='cbs-log'; found=$true; copied=$true; copiedTo='bootfailure\\CBS.log'; sizeBytes={log_path.stat().st_size}; skippedReason=$null }},
    [ordered]@{{ name='dism-log'; found=$true; copied=$false; copiedTo=$null; sizeBytes=999; skippedReason='oversized' }}
)
$analysis = Get-ServicingLogAnalysis -SourceEntries $entries -OutputDirectory '{output}' -MaxScanBytes 1
$findings = @(Evaluate-Findings -Samples @() -DiskSeries @() -VolumeMetrics @() -MemoryMetrics ([pscustomobject]@{{ pageFaultsPerSec = $null }}) -ServicingAnalysis $analysis)
[pscustomobject]@{{
    AnalysisStatus = $analysis.status
    UnavailableCount = @($findings | Where-Object {{ $_.metric -eq 'servicingEvidenceUnavailable' }}).Count
    FailedCount = @($findings | Where-Object {{ $_.metric -eq 'servicingAnalysisFailed' }}).Count
}} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            [
                "Get-ServicingLogAnalysis",
                "ConvertFrom-ServicingLogLines",
                "Test-CasePathHasReparsePoint",
                "Evaluate-Findings",
                "Test-CaptureWindowCoverage",
                "Get-FiniteNumericCount",
                "Get-SustainedWindow",
                "Get-SampleTimestamp",
            ]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {
        "AnalysisStatus": "partial",
        "UnavailableCount": 1,
        "FailedCount": 0,
    }


def test_servicing_file_analysis_merges_signature_ranges_across_chunks(tmp_path):
    """The streaming reader must preserve counts and line numbers when a
    signature crosses its 1000-line processing chunk."""
    log_dir = tmp_path / "bootfailure"
    log_dir.mkdir()
    log_path = log_dir / "CBS.log"
    lines = ["ordinary line"] * 1000
    lines.extend(["Error CBS_E_INVALID_PACKAGE", "Error CBS_E_INVALID_PACKAGE"])
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    output = str(tmp_path).replace("'", "''")
    body = f"""
$entry = [pscustomobject]@{{ name='cbs-log'; found=$true; copied=$true; copiedTo='bootfailure\\CBS.log'; sizeBytes={log_path.stat().st_size}; skippedReason=$null }}
$result = Get-ServicingLogAnalysis -SourceEntries @($entry) -OutputDirectory '{output}'
$signature = @(@($result.logs)[0].signatures)[0]
[pscustomobject]@{{ Lines=@($result.logs)[0].lineCount; Count=$signature.count; First=$signature.firstLineNumber; Last=$signature.lastLineNumber }} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            ["Get-ServicingLogAnalysis", "ConvertFrom-ServicingLogLines", "Test-CasePathHasReparsePoint"]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {"Lines": 1002, "Count": 2, "First": 1001, "Last": 1002}


def test_crash_analysis_correlates_dumps_and_deduplicates_live_kernel_signatures():
    """Dump evidence survives the event lookback boundary, while a nearby
    bugcheck supplies a code and repeated LiveKernelReports collapse to one
    filename-derived problem signature."""
    body = r"""
$events = @(
    [pscustomobject]@{ Id=1001; ProviderName='BugCheck'; TimeCreated=[datetime]::Parse('2026-05-15T12:00:00Z').ToUniversalTime(); Message='The bugcheck was: 0x0000001A' },
    [pscustomobject]@{ Id=41; ProviderName='Microsoft-Windows-Kernel-Power'; TimeCreated=[datetime]::Parse('2026-05-15T12:10:00Z').ToUniversalTime(); Message='The system rebooted without cleanly shutting down.' }
)
$dumps = @(
    [pscustomobject]@{ Name='051526-12345-01.dmp'; SizeBytes=100; SourceLastWriteTimeUtc='2026-05-15T12:00:20.0000000Z' },
    [pscustomobject]@{ Name='051526-54321-01.dmp'; SizeBytes=150; SourceLastWriteTimeUtc='2026-05-15T12:01:20.0000000Z' },
    [pscustomobject]@{ Name='050126-99999-01.dmp'; SizeBytes=200; SourceLastWriteTimeUtc='2026-05-15T12:30:00.0000000Z' }
)
$live = @(
    [pscustomobject]@{ Name='WATCHDOG-20260515-1200.dmp'; FullPath='C:\Windows\LiveKernelReports\WATCHDOG\WATCHDOG-20260515-1200.dmp'; SizeBytes=300; LastWriteTimeUtc='2026-05-15T12:00:30.0000000Z'; Directory='C:\Windows\LiveKernelReports\WATCHDOG' },
    [pscustomobject]@{ Name='WATCHDOG-20260515-1201.dmp'; FullPath='C:\Windows\LiveKernelReports\WATCHDOG\WATCHDOG-20260515-1201.dmp'; SizeBytes=400; LastWriteTimeUtc='2026-05-15T12:01:30.0000000Z'; Directory='C:\Windows\LiveKernelReports\WATCHDOG' }
)
$analysis = Get-CrashAnalysis -Events $events -MinidumpFiles $dumps -LiveKernelReports $live -EventWindowStartUtc '2026-05-15T11:00:00Z' -EventWindowEndUtc '2026-05-15T13:00:00Z'
$firstDump = @($analysis.minidumps)[0]
$oldDump = @($analysis.minidumps)[2]
$liveSignature = @($analysis.liveKernelSignatures)[0]
$dumpSignature = @($analysis.minidumpSignatures)[0]
[pscustomobject]@{
    Bugcheck = @($analysis.bugchecks)[0].BugcheckCode
    UnexplainedCount = @($analysis.unexplainedShutdowns).Count
    DumpCode = $firstDump.bugcheckCode
    DumpCorrelation = $firstDump.eventCorrelationStatus
    DumpFilenameDate = $firstDump.filenameDate
    OldDumpCorrelation = $oldDump.eventCorrelationStatus
    DumpSignature = "$($dumpSignature.problemSignature)|$($dumpSignature.count)"
    LiveSignature = "$($liveSignature.problemSignature)|$($liveSignature.count)|$($liveSignature.signatureSource)"
    LiveFileCount = @($analysis.liveKernelReports).Count
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            ["Get-CrashAnalysis", "ConvertTo-CrashDateTime", "ConvertTo-CrashIsoTimestamp", "Get-CrashFilenameDate"] + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {
        "Bugcheck": "0x0000001A",
        "UnexplainedCount": 1,
        "DumpCode": "0x0000001A",
        "DumpCorrelation": "matched-bugcheck",
        "DumpFilenameDate": "2026-05-15",
        "OldDumpCorrelation": "no-matching-bugcheck",
        "DumpSignature": "bugcheck:0x0000001A|2",
        "LiveSignature": "livekernel:watchdog|2|filename-hint",
        "LiveFileCount": 2,
    }


def test_crash_analysis_rejects_bugcheck_correlation_after_lookback_end():
    """A dump after the bounded event interval must not borrow a nearby event
    code even when its mtime is within the five-minute correlation window."""
    body = r"""
$events = @(
    [pscustomobject]@{ Id=1001; ProviderName='BugCheck'; TimeCreated=[datetime]::Parse('2026-05-15T12:59:00Z').ToUniversalTime(); Message='The bugcheck was: 0x0000007E' }
)
$dumps = @(
    [pscustomobject]@{ Name='051526-77777-01.dmp'; SizeBytes=100; SourceLastWriteTimeUtc='2026-05-15T13:02:00Z' }
)
$analysis = Get-CrashAnalysis -Events $events -MinidumpFiles $dumps -EventWindowStartUtc '2026-05-15T11:00:00Z' -EventWindowEndUtc '2026-05-15T13:00:00Z'
$row = @($analysis.minidumps)[0]
[pscustomobject]@{ Status=$row.eventCorrelationStatus; Code=$row.bugcheckCode } | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            ["Get-CrashAnalysis", "ConvertTo-CrashDateTime", "ConvertTo-CrashIsoTimestamp", "Get-CrashFilenameDate"]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {"Status": "outside-event-lookback", "Code": None}


def test_crash_analysis_prefers_source_time_over_stale_filename_date():
    """A stale filename date is only a hint; an in-window source timestamp
    remains eligible for event correlation."""
    body = r"""
$events = @(
    [pscustomobject]@{ Id=1001; ProviderName='BugCheck'; TimeCreated=[datetime]::Parse('2026-05-15T12:00:00Z').ToUniversalTime(); Message='The bugcheck was: 0x0000001A' }
)
$dumps = @(
    [pscustomobject]@{ Name='050126-99999-01.dmp'; SizeBytes=100; SourceLastWriteTimeUtc='2026-05-15T12:00:20Z' }
)
$analysis = Get-CrashAnalysis -Events $events -MinidumpFiles $dumps -EventWindowStartUtc '2026-05-15T11:00:00Z' -EventWindowEndUtc '2026-05-15T13:00:00Z'
$row = @($analysis.minidumps)[0]
[pscustomobject]@{ Status=$row.eventCorrelationStatus; Code=$row.bugcheckCode } | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            ["Get-CrashAnalysis", "ConvertTo-CrashDateTime", "ConvertTo-CrashIsoTimestamp", "Get-CrashFilenameDate"]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {"Status": "matched-bugcheck", "Code": "0x0000001A"}


def test_crash_analysis_labels_future_filename_date_outside_when_source_time_missing():
    """Filename fallback classification must handle both sides of the bounded
    event interval when no source timestamp is available."""
    body = r"""
$analysis = Get-CrashAnalysis -Events @([pscustomobject]@{ Id=999; ProviderName='Other'; TimeCreated='2026-05-15T12:00:00Z'; Message='not a crash' }) -MinidumpFiles @(
    [pscustomobject]@{ Name='123126-99999-01.dmp'; SizeBytes=100; SourceLastWriteTimeUtc=$null }
) -EventWindowStartUtc '2026-05-15T11:00:00Z' -EventWindowEndUtc '2026-05-16T13:00:00Z'
$row = @($analysis.minidumps)[0]
[pscustomobject]@{ Status=$row.eventCorrelationStatus; FilenameDate=$row.filenameDate } | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            ["Get-CrashAnalysis", "ConvertTo-CrashDateTime", "ConvertTo-CrashIsoTimestamp", "Get-CrashFilenameDate"]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {"Status": "outside-event-lookback", "FilenameDate": "2026-12-31"}


def test_crash_analysis_normalizes_datetime_fields_before_json_serialization():
    """Crash output must use ISO strings before ConvertTo-Json so Windows
    PowerShell 5.1 cannot emit its legacy Microsoft date wrapper."""
    body = r"""
$eventTime = [datetime]::Parse('2026-05-15T12:00:00Z').ToUniversalTime()
$sourceTime = [datetime]::Parse('2026-05-15T12:00:20Z').ToUniversalTime()
$events = @([pscustomobject]@{ Id=1001; ProviderName='BugCheck'; TimeCreated=$eventTime; Message='The bugcheck was: 0x0000001A' })
$dumps = @([pscustomobject]@{ Name='051526-12345-01.dmp'; SizeBytes=100; SourceLastWriteTimeUtc=$sourceTime })
$analysis = Get-CrashAnalysis -Events $events -MinidumpFiles $dumps -EventWindowStartUtc $eventTime.AddHours(-1) -EventWindowEndUtc $eventTime.AddHours(1)
$json = $analysis | ConvertTo-Json -Depth 10 -Compress
[pscustomobject]@{
    LookbackType = $analysis.eventLookbackStartUtc.GetType().Name
    BugcheckType = @($analysis.bugchecks)[0].TimeCreated.GetType().Name
    DumpSourceType = @($analysis.minidumps)[0].SourceLastWriteTimeUtc.GetType().Name
    BugcheckTimeType = @($analysis.minidumps)[0].bugcheckTimeUtc.GetType().Name
    HasLegacyWrapper = $json -match '/Date\('
    SerializedAnalysis = $json
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            [
                "Get-CrashAnalysis",
                "ConvertTo-CrashDateTime",
                "ConvertTo-CrashIsoTimestamp",
                "Get-CrashFilenameDate",
            ]
            + SUPPORT_FUNCTIONS,
        )
    )

    serialized_analysis = json.loads(payload.pop("SerializedAnalysis"))
    assert payload == {
        "LookbackType": "String",
        "BugcheckType": "String",
        "DumpSourceType": "String",
        "BugcheckTimeType": "String",
        "HasLegacyWrapper": False,
    }

    import jsonschema

    schema = json.loads(
        (REPO_ROOT / "schema" / "diagnostic-report.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.validate(
        serialized_analysis,
        schema["properties"]["crashAnalysis"],
        format_checker=jsonschema.FormatChecker(),
    )


def test_crash_analysis_filters_events_outside_its_declared_lookback():
    """The analyzer must not trust an accidentally over-broad event input."""
    body = r"""
$events = @(
    [pscustomobject]@{ Id=1001; ProviderName='BugCheck'; TimeCreated='2026-05-15T14:00:00Z'; Message='The bugcheck was: 0x0000001A' }
)
$analysis = Get-CrashAnalysis -Events $events -MinidumpFiles @(
    [pscustomobject]@{ Name='051526-12345-01.dmp'; SizeBytes=100; SourceLastWriteTimeUtc='2026-05-15T12:00:00Z' }
) -EventWindowStartUtc '2026-05-15T11:00:00Z' -EventWindowEndUtc '2026-05-15T13:00:00Z'
[pscustomobject]@{
    BugcheckCount = @($analysis.bugchecks).Count
    DumpStatus = @($analysis.minidumps)[0].eventCorrelationStatus
    DumpCode = @($analysis.minidumps)[0].bugcheckCode
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            [
                "Get-CrashAnalysis",
                "ConvertTo-CrashDateTime",
                "ConvertTo-CrashIsoTimestamp",
                "Get-CrashFilenameDate",
            ]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {
        "BugcheckCount": 0,
        "DumpStatus": "no-matching-bugcheck",
        "DumpCode": None,
    }


def test_findings_engine_publishes_crash_and_servicing_evidence():
    """The new evidence blocks reach findings.json's same report contract as
    telemetry findings, including the recurring CBS failure."""
    body = r"""
$crash = [ordered]@{
    bugchecks = @([pscustomobject]@{ TimeCreated='2026-05-15T12:00:00Z'; BugcheckCode='0x0000001A'; Message='bugcheck' })
    unexplainedShutdowns = @([pscustomobject]@{ TimeCreated='2026-05-15T12:10:00Z'; Message='power' })
    minidumps = @([pscustomobject]@{ Name='051526-12345-01.dmp'; SizeBytes=100; SourceLastWriteTimeUtc='2026-05-15T12:00:20Z'; bugcheckCode='0x0000001A'; eventCorrelationStatus='matched-bugcheck'; filenameDate='2026-05-15' })
    liveKernelReports = @([pscustomobject]@{ Name='WATCHDOG-20260515-1200.dmp'; SizeBytes=300; LastWriteTimeUtc='2026-05-15T12:00:30Z' })
    liveKernelSignatures = @([pscustomobject]@{ problemSignature='livekernel:watchdog'; count=1; signatureSource='filename-hint' })
}
$servicing = [ordered]@{
    status = 'completed'
    logs = @([pscustomobject]@{
        name='cbs-log'; artifact='bootfailure/CBS.log'; scanStatus='completed'
        signatures=@([pscustomobject]@{ signature='CBS_E_INVALID_PACKAGE'; kind='cbs-error'; count=2; firstLineNumber=2; lastLineNumber=3 })
    })
}
$findings = @(Evaluate-Findings -Samples @() -DiskSeries @() -VolumeMetrics @() -MemoryMetrics ([pscustomobject]@{ pageFaultsPerSec = $null }) -WindowStart '2026-05-15T11:00:00Z' -WindowEnd '2026-05-15T13:00:00Z' -CrashAnalysis $crash -ServicingAnalysis $servicing)
$selected = @($findings | Where-Object { $_.category -in @('crash-evidence','servicing-failure') })
[pscustomobject]@{
    Categories = @($selected | ForEach-Object { $_.category } | Sort-Object -Unique)
    Metrics = @($selected | ForEach-Object { $_.metric } | Sort-Object)
    CbsCount = @($selected | Where-Object { $_.metric -eq 'CBS_E_INVALID_PACKAGE' })[0].measuredValues.count
    CbsSource = @($selected | Where-Object { $_.metric -eq 'CBS_E_INVALID_PACKAGE' })[0].sourceArtifact
    CrashDumpCount = @($selected | Where-Object { $_.metric -eq 'minidumpEvidence' })[0].measuredValues.count
    LiveCount = @($selected | Where-Object { $_.metric -eq 'liveKernelReportEvidence' })[0].measuredValues.count
} | ConvertTo-Json -Depth 10 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            [
                "Evaluate-Findings",
                "Test-CaptureWindowCoverage",
                "Get-FiniteNumericCount",
                "Get-SustainedWindow",
                "Get-SampleTimestamp",
            ]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload["Categories"] == ["crash-evidence", "servicing-failure"]
    assert set(payload["Metrics"]) == {
        "CBS_E_INVALID_PACKAGE",
        "bugcheckEvents",
        "liveKernelReportEvidence",
        "minidumpEvidence",
        "unexplainedShutdowns",
    }
    assert len(payload["Metrics"]) == 5
    assert payload["CbsCount"] == 2
    assert payload["CbsSource"] == "servicing-log-analysis.json"
    assert payload["CrashDumpCount"] == 1
    assert payload["LiveCount"] == 1


def test_findings_engine_ignores_missing_optional_crash_arrays():
    """A legacy/minimal crash-analysis object without dump arrays must not turn
    missing values into one-element evidence findings."""
    body = r"""
$crash = [ordered]@{
    bugchecks = @()
    unexplainedShutdowns = @()
    eventCorrelationWindowMinutes = 5
}
$findings = @(Evaluate-Findings -Samples @() -DiskSeries @() -VolumeMetrics @() -MemoryMetrics ([pscustomobject]@{ pageFaultsPerSec = $null }) -CrashAnalysis $crash)
[pscustomobject]@{
    CrashEvidenceCount = @($findings | Where-Object { $_.category -eq 'crash-evidence' }).Count
    Metrics = @($findings | Where-Object { $_.category -eq 'crash-evidence' } | ForEach-Object { $_.metric })
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            [
                "Evaluate-Findings",
                "Test-CaptureWindowCoverage",
                "Get-FiniteNumericCount",
                "Get-SustainedWindow",
                "Get-SampleTimestamp",
            ]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {"CrashEvidenceCount": 0, "Metrics": []}


def test_findings_engine_reports_partial_servicing_log_coverage():
    """One readable servicing log must not hide another requested log that was
    oversized or otherwise unavailable."""
    body = r"""
$servicing = [ordered]@{
    status = 'partial'
    logs = @(
        [pscustomobject]@{ name='cbs-log'; scanStatus='completed'; signatures=@() },
        [pscustomobject]@{ name='dism-log'; scanStatus='oversized'; signatures=@() }
    )
}
$findings = @(Evaluate-Findings -Samples @() -DiskSeries @() -VolumeMetrics @() -MemoryMetrics ([pscustomobject]@{ pageFaultsPerSec = $null }) -ServicingAnalysis $servicing)
$partial = @($findings | Where-Object { $_.metric -eq 'servicingEvidencePartial' })[0]
[pscustomobject]@{
    Count = @($findings | Where-Object { $_.metric -eq 'servicingEvidencePartial' }).Count
    Incomplete = $partial.measuredValues.incompleteLogCount
    Completed = $partial.measuredValues.completedLogCount
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            [
                "Evaluate-Findings",
                "Test-CaptureWindowCoverage",
                "Get-FiniteNumericCount",
                "Get-SustainedWindow",
                "Get-SampleTimestamp",
            ]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {"Count": 1, "Incomplete": 1, "Completed": 1}


def test_findings_engine_reports_truncated_servicing_prefix_as_partial():
    """A readable but truncated log prefix is not complete evidence."""
    body = r"""
$servicing = [ordered]@{
    status = 'completed'
    logs = @(
        [pscustomobject]@{ name='cbs-log'; scanStatus='completed'; scanTruncated=$true; signatures=@() }
    )
}
$findings = @(Evaluate-Findings -Samples @() -DiskSeries @() -VolumeMetrics @() -MemoryMetrics ([pscustomobject]@{ pageFaultsPerSec = $null }) -ServicingAnalysis $servicing)
$partial = @($findings | Where-Object { $_.metric -eq 'servicingEvidencePartial' })[0]
[pscustomobject]@{
    Count = @($findings | Where-Object { $_.metric -eq 'servicingEvidencePartial' }).Count
    Incomplete = $partial.measuredValues.incompleteLogCount
    Truncated = $partial.measuredValues.truncatedLogCount
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            [
                "Evaluate-Findings",
                "Test-CaptureWindowCoverage",
                "Get-FiniteNumericCount",
                "Get-SustainedWindow",
                "Get-SampleTimestamp",
            ]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {"Count": 1, "Incomplete": 1, "Truncated": 1}


def test_findings_engine_surfaces_failed_servicing_analysis():
    """A top-level analyzer failure must remain distinguishable from a normal
    no-log coverage gap in the report findings."""
    body = r"""
$servicing = [ordered]@{
    status = 'failed'
    error = 'synthetic analyzer failure'
    logs = @()
}
$findings = @(Evaluate-Findings -Samples @() -DiskSeries @() -VolumeMetrics @() -MemoryMetrics ([pscustomobject]@{ pageFaultsPerSec = $null }) -ServicingAnalysis $servicing)
$failure = @($findings | Where-Object { $_.metric -eq 'servicingAnalysisFailed' })[0]
[pscustomobject]@{
    Count = @($findings | Where-Object { $_.metric -eq 'servicingAnalysisFailed' }).Count
    Error = $failure.measuredValues.error
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            [
                "Evaluate-Findings",
                "Test-CaptureWindowCoverage",
                "Get-FiniteNumericCount",
                "Get-SustainedWindow",
                "Get-SampleTimestamp",
            ]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {"Count": 1, "Error": "synthetic analyzer failure"}


def test_report_renders_crash_and_servicing_finding_metrics():
    """New evidence categories cannot disappear from the offline report."""
    body = r"""
$findings = @(
    [pscustomobject]@{ category='crash-evidence'; sourceArtifact='system-events-last-24-hours.json'; metric='bugcheckEvents'; windowStart=$null; windowEnd=$null; measuredValues=[ordered]@{ count=1; bugcheckCodes='0x0000001A' }; ruleCondition='bugcheck'; uncertainty='u'; nextSteps='n'; suggestedWprProfile=$null },
    [pscustomobject]@{ category='servicing-failure'; sourceArtifact='servicing-log-analysis.json'; metric='CBS_E_INVALID_PACKAGE'; windowStart=$null; windowEnd=$null; measuredValues=[ordered]@{ count=2; kind='cbs-error'; logs='cbs-log' }; ruleCondition='servicing'; uncertainty='u'; nextSteps='n'; suggestedWprProfile=$null },
    [pscustomobject]@{ category='coverage'; sourceArtifact='servicing-log-analysis.json'; metric='servicingEvidencePartial'; windowStart=$null; windowEnd=$null; measuredValues=[ordered]@{ incompleteLogCount=1; error='unavailable log' }; ruleCondition='partial'; uncertainty='u'; nextSteps='n'; suggestedWprProfile=$null }
)
$html = ConvertTo-FindingsHtml -Findings $findings -Manifest $null -SymptomContext $null
[pscustomobject]@{
    HasCrash = $html.Contains('crash-evidence')
    HasServicing = $html.Contains('servicing-failure')
    HasEvidenceHeading = $html.Contains('Crash, Servicing And Supporting Evidence')
    HasBugcheck = $html.Contains('bugcheckEvents')
    HasCbs = $html.Contains('CBS_E_INVALID_PACKAGE')
    HasCountLabel = $html.Contains('<th>count</th>')
    HasKindLabel = $html.Contains('<th>kind</th>')
    HasIncompleteLabel = $html.Contains('<th>incompleteLogCount</th>')
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            ["ConvertTo-FindingsHtml", "ConvertTo-HtmlEncoded", "Get-CaseJsonProperty"]
            + SUPPORT_FUNCTIONS,
        )
    )

    assert payload == {
        "HasCrash": True,
        "HasServicing": True,
        "HasEvidenceHeading": True,
        "HasBugcheck": True,
        "HasCbs": True,
        "HasCountLabel": True,
        "HasKindLabel": True,
        "HasIncompleteLabel": True,
    }


def test_collection_tail_writes_and_forwards_servicing_analysis(tmp_path):
    """The shared Collect tail must persist the analysis artifact and pass both
    evidence blocks into Evaluate-Findings."""
    output = tmp_path / "collect-tail"
    output.mkdir()
    plan = tmp_path / "plan"
    script = str(SCRIPT).replace("\\", "/")
    body = f"""
$ErrorActionPreference = 'Stop'
$null = . '{script}' -Mode Plan -OutputDirectory '{str(plan).replace("'", "''")}'
$collected = New-Object System.Collections.ArrayList
Set-Content -LiteralPath (Join-Path '{str(output).replace("'", "''")}' 'performance-samples.csv') -Value 'a,b' -Encoding Ascii
[void]$collected.Add('performance-samples.csv')
$manifest = [ordered]@{{
  schemaVersion = '1.2'; toolName = 'Windows Performance Diagnostics Toolkit'; toolVersion = '1.0.0'; mode = 'Collect'
  startedAtUtc = '2026-05-15T11:00:00Z'; completedAtUtc = '2026-05-15T13:00:00Z'
  safety = [ordered]@{{ localOnly=$true; readOnly=$true; requiresExplicitCollectionConsent=$true; automaticUpload=$false; automaticRemediation=$false; automaticLogClearing=$false }}
  collectionErrors = @(); artifacts = @()
}}
$crash = [ordered]@{{
  bugchecks = @([pscustomobject]@{{ TimeCreated='2026-05-15T12:00:00Z'; BugcheckCode='0x0000001A'; Message='bugcheck' }})
  unexplainedShutdowns = @(); minidumps = @(); liveKernelReports = @(); liveKernelSignatures = @()
}}
$servicing = [ordered]@{{
  status = 'completed'
  logs = @([pscustomobject]@{{ name='cbs-log'; artifact='bootfailure/CBS.log'; scanStatus='completed'; signatures=@([pscustomobject]@{{ signature='CBS_E_INVALID_PACKAGE'; kind='cbs-error'; count=2; firstLineNumber=1; lastLineNumber=2 }}) }})
}}
$result = Write-CollectionOutputs -OutputDirectory '{str(output).replace("'", "''")}' -CollectionManifest $manifest -CollectedArtifacts $collected -Samples @() -DiskSeries @() -VolumeMetrics $null -MemoryMetrics $null -CrashAnalysis $crash -ServicingAnalysis $servicing
$findings = @(Get-Content -LiteralPath (Join-Path '{str(output).replace("'", "''")}' 'findings.json') -Raw | ConvertFrom-Json)
[ordered]@{{
  analysisExists = Test-Path -LiteralPath (Join-Path '{str(output).replace("'", "''")}' 'servicing-log-analysis.json')
  analysisRegistered = @($result.artifacts | Where-Object {{ $_.Name -eq 'servicing-log-analysis.json' }}).Count
  manifestCrash = ($null -ne $result.crashAnalysis)
  manifestServicing = ($null -ne $result.servicingAnalysis)
  hasBugcheck = @($findings | Where-Object {{ $_.metric -eq 'bugcheckEvents' }}).Count
  hasCbs = @($findings | Where-Object {{ $_.metric -eq 'CBS_E_INVALID_PACKAGE' }}).Count
}} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(run_pwsh(body, []))

    assert payload == {
        "analysisExists": True,
        "analysisRegistered": 1,
        "manifestCrash": True,
        "manifestServicing": True,
        "hasBugcheck": 1,
        "hasCbs": 1,
    }

    import jsonschema

    generated_manifest = json.loads(
        (output / "diagnostic-manifest.json").read_text(encoding="utf-8")
    )
    schema = json.loads(
        (REPO_ROOT / "schema" / "diagnostic-report.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.validate(generated_manifest, schema)


@pytest.mark.skipif(os.name == "nt", reason="Hosted Windows PowerShell 5.1 cannot complete direct hardlink destination replacement probe")
def test_json_writer_refuses_a_hardlink_destination(tmp_path):
    """JSON artifact writes must not overwrite a hardlink target outside the
    case directory."""
    destination = tmp_path / "servicing-log-analysis.json"
    sentinel = tmp_path / "outside-sentinel.txt"
    sentinel.write_text("do-not-overwrite", encoding="utf-8")
    try:
        os.link(sentinel, destination)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"hardlink creation unavailable: {error}")

    plan = tmp_path / "plan"
    script = str(SCRIPT).replace("\\", "/")
    body = f"""
$status = 'completed'
try {{ Write-JsonFile -InputObject ([ordered]@{{ status='replacement' }}) -Path '{str(destination).replace("'", "''")}' }}
catch {{ $status = 'refused' }}
[pscustomobject]@{{ Status=$status; Sentinel=Get-Content -LiteralPath '{str(sentinel).replace("'", "''")}' -Raw }} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            [
                "Write-JsonFile",
                "Write-CaseFileAtomically",
                "Assert-CaseFileDestinationSafe",
                "Move-CaseTemporaryFileIntoPlace",
                "Test-CasePathHasReparsePoint",
                "Get-CaseFileLinkCount",
            ],
        )
    )

    assert payload == {"Status": "refused", "Sentinel": "do-not-overwrite"}


@pytest.mark.skipif(os.name == "nt", reason="Hosted Windows PowerShell 5.1 cannot complete direct hardlink destination replacement probe")
def test_bounded_copy_refuses_a_hardlink_destination(tmp_path):
    """Consent-gated evidence copies must not overwrite a hardlink target."""
    source = tmp_path / "source.log"
    source.write_text("safe-source", encoding="utf-8")
    destination = tmp_path / "copied.log"
    sentinel = tmp_path / "outside-sentinel.txt"
    sentinel.write_text("do-not-overwrite", encoding="utf-8")
    try:
        os.link(sentinel, destination)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"hardlink creation unavailable: {error}")

    plan = tmp_path / "plan"
    script = str(SCRIPT).replace("\\", "/")
    body = f"""
$status = 'completed'
try {{ Copy-CaseFileBounded -SourcePath '{str(source).replace("'", "''")}' -DestinationPath '{str(destination).replace("'", "''")}' -MaxBytes 100 | Out-Null }}
catch {{ $status = 'refused' }}
[pscustomobject]@{{ Status=$status; Sentinel=Get-Content -LiteralPath '{str(sentinel).replace("'", "''")}' -Raw }} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            [
                "Copy-CaseFileBounded",
                "Write-CaseFileAtomically",
                "Assert-CaseFileDestinationSafe",
                "Move-CaseTemporaryFileIntoPlace",
                "Test-CasePathHasReparsePoint",
                "Get-CaseFileLinkCount",
            ],
        )
    )

    assert payload == {"Status": "refused", "Sentinel": "do-not-overwrite"}


def test_bounded_copy_copies_a_stable_source_atomically(tmp_path):
    """A normal bounded copy writes the exact source bytes and reports their
    count without leaving a temporary file behind."""
    source = tmp_path / "source.log"
    destination = tmp_path / "copied.log"
    source.write_bytes(b"safe-source\n")
    plan = tmp_path / "plan"
    script = str(SCRIPT).replace("\\", "/")
    body = f"""
$copied = Copy-CaseFileBounded -SourcePath '{str(source).replace("'", "''")}' -DestinationPath '{str(destination).replace("'", "''")}' -MaxBytes 100
[pscustomobject]@{{ Bytes=$copied; Exists=[System.IO.File]::Exists('{str(destination).replace("'", "''")}'); Length=([System.IO.FileInfo]::new('{str(destination).replace("'", "''")}')).Length }} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            [
                "Copy-CaseFileBounded",
                "Write-CaseFileAtomically",
                "Assert-CaseFileDestinationSafe",
                "Move-CaseTemporaryFileIntoPlace",
                "Test-CasePathHasReparsePoint",
                "Get-CaseFileLinkCount",
            ],
        )
    )

    assert payload == {"Bytes": 12, "Exists": True, "Length": 12}
    assert destination.read_bytes() == b"safe-source\n"


def test_schema_accepts_extended_crash_and_servicing_analysis():
    """The published manifest schema must cover the new structured evidence,
    including filename-derived classifications and bounded log scan records."""
    import jsonschema

    schema = json.loads(
        (REPO_ROOT / "schema" / "diagnostic-report.schema.json").read_text(
            encoding="utf-8"
        )
    )
    manifest = {
        "schemaVersion": "1.2",
        "toolName": "Windows Performance Diagnostics Toolkit",
        "toolVersion": "1.0.0",
        "mode": "Collect",
        "safety": {
            "localOnly": True,
            "readOnly": True,
            "requiresExplicitCollectionConsent": True,
            "automaticUpload": False,
            "automaticRemediation": False,
            "automaticLogClearing": False,
        },
        "crashAnalysis": {
            "eventLookbackStartUtc": "2026-05-15T11:00:00Z",
            "eventLookbackEndUtc": "2026-05-15T13:00:00Z",
            "eventCorrelationWindowMinutes": 5,
            "bugchecks": [],
            "unexplainedShutdowns": [],
            "minidumps": [
                {
                    "Name": "051526-12345-01.dmp",
                    "SizeBytes": 100,
                    "SourceLastWriteTimeUtc": "2026-05-15T12:00:20Z",
                    "filenameDate": "2026-05-15",
                    "bugcheckCode": "0x0000001A",
                    "bugcheckTimeUtc": "2026-05-15T12:00:00Z",
                    "eventCorrelationStatus": "matched-bugcheck",
                    "problemSignature": "bugcheck:0x0000001A",
                    "signatureSource": "event-bugcheck-correlation",
                }
            ],
            "minidumpSignatures": [
                {
                    "problemSignature": "bugcheck:0x0000001A",
                    "signatureSource": "event-bugcheck-correlation",
                    "count": 1,
                    "files": ["051526-12345-01.dmp"],
                }
            ],
            "liveKernelReports": [
                {
                    "Name": "WATCHDOG-20260515-1200.dmp",
                    "FullPath": "C:\\Windows\\LiveKernelReports\\WATCHDOG\\WATCHDOG-20260515-1200.dmp",
                    "SizeBytes": 300,
                    "LastWriteTimeUtc": "2026-05-15T12:00:30Z",
                    "Directory": "C:\\Windows\\LiveKernelReports\\WATCHDOG",
                    "filenameDate": "2026-05-15",
                    "problemSignature": "livekernel:watchdog",
                    "signatureSource": "filename-hint",
                }
            ],
            "liveKernelSignatures": [
                {
                    "problemSignature": "livekernel:watchdog",
                    "signatureSource": "filename-hint",
                    "count": 1,
                    "files": ["WATCHDOG-20260515-1200.dmp"],
                }
            ],
        },
        "servicingAnalysis": {
            "status": "completed",
            "maxScanBytes": 104857600,
            "logCount": 1,
            "scannedLogCount": 1,
            "failedLogCount": 0,
            "truncatedLogCount": 0,
            "unavailableLogCount": 0,
            "error": None,
            "logs": [
                {
                    "name": "cbs-log",
                    "artifact": "bootfailure/CBS.log",
                    "found": True,
                    "copied": True,
                    "sizeBytes": 120,
                    "scanStatus": "completed",
                    "lineCount": 3,
                    "matchedLineCount": 2,
                    "bytesScanned": 120,
                    "scanTruncated": False,
                    "signatures": [
                        {
                            "signature": "CBS_E_INVALID_PACKAGE",
                            "kind": "cbs-error",
                            "count": 2,
                            "firstLineNumber": 2,
                            "lastLineNumber": 3,
                        }
                    ],
                    "error": None,
                }
            ],
        },
    }
    errors = sorted(
        jsonschema.Draft7Validator(schema).iter_errors(manifest),
        key=lambda error: list(error.path),
    )
    assert not errors, [(list(error.path), error.message) for error in errors]
