"""Behavioral test of the bounded WPR trace lifecycle using a fake wpr.exe.

Proves on Linux what the Windows live gates prove on Windows:
- the trace is started with ONLY documented wpr.exe arguments,
- the trace stops when the caller signals (so trace and counters share a window)
  instead of sleeping its whole maximum window,
- an oversized ETL and the managed-symbol files WPR writes beside it are removed
  and reported instead of shipping gigabytes.
"""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "src" / "Invoke-WindowsPerformanceDiagnostics.ps1"

RUNNER = r"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{script}', [ref]$null, [ref]$null)
foreach ($name in @('Start-WprBoundedCaptureJob')) {{
    $found = @($ast.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }}, $true))
    if ($found.Count -eq 0) {{ throw "function $name not found" }}
    Invoke-Expression $found[0].Extent.Text
}}
Set-StrictMode -Version Latest

$work = Join-Path $env:WPD_WPR_TEST 'work'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$etl = Join-Path $work 'wpr-trace.etl'
$sentinel = Join-Path $work 'stop.signal'

$job = Start-WprBoundedCaptureJob `
    -WprExePath $env:WPD_WPR_TEST/fake-wpr.sh `
    -Profile 'GeneralProfile' `
    -EtlPath $etl `
    -DurationSeconds {seconds} `
    -MaxFileMB {maxmb} `
    -StopSentinelPath $sentinel

# Simulate counter sampling finishing quickly, then signal the trace to stop.
Start-Sleep -Milliseconds {signal_after_ms}
Set-Content -LiteralPath $sentinel -Value 'sampling-complete' -Encoding Ascii

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$finished = Wait-Job -Job $job -Timeout 120
$waitSeconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
$record = if ($null -ne $finished) {{ @(Receive-Job -Job $job) | Where-Object {{ $_ -is [psobject] -and $null -ne $_.PSObject.Properties['StartExitCode'] }} | Select-Object -Last 1 }} else {{ $null }}
Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

$etlExists = Test-Path -LiteralPath $etl -PathType Leaf
$symbolDir = Join-Path $work 'wpr-trace.NGenPdb'
[pscustomobject]@{{
    Finished = ($null -ne $finished)
    WaitSeconds = $waitSeconds
    StartExitCode = if ($record) {{ $record.StartExitCode }} else {{ $null }}
    StopExitCode = if ($record) {{ $record.StopExitCode }} else {{ $null }}
    EtlBytes = if ($record) {{ $record.EtlBytes }} else {{ $null }}
    SizeLimitExceeded = if ($record) {{ $record.SizeLimitExceeded }} else {{ $null }}
    TraceRemoved = if ($record) {{ $record.TraceRemoved }} else {{ $null }}
    ElapsedSeconds = if ($record) {{ $record.ElapsedSeconds }} else {{ $null }}
    EtlStillOnDisk = $etlExists
    SymbolDirStillOnDisk = (Test-Path -LiteralPath $symbolDir)
}} | ConvertTo-Json -Compress
"""


def _write_fake_wpr(root: Path) -> Path:
    """A fake wpr.exe that logs its argv and creates an ETL sized by $PADDING_MB."""
    fake = root / "fake-wpr.sh"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        "# fake wpr.exe: record argv, and create/oversize the ETL on -stop\n"
        'printf "%s\\n" "$*" >> "$WPD_WPR_TEST/argv.log"\n'
        "if [ \"$1\" = \"-stop\" ]; then\n"
        '  head -c $((PADDING_MB * 1024 * 1024)) /dev/zero > "$2"\n'
        "  mkdir -p \"${2%.etl}.NGenPdb\"\n"
        '  head -c 1024 /dev/zero > "${2%.etl}.NGenPdb/symbols.bin"\n'
        "fi\n"
        "exit 0\n",
        encoding="ascii",
    )
    fake.chmod(0o755)
    return fake


def _run(work_root: Path, seconds: int, maxmb: int, signal_after_ms: int, padding_mb: int):
    if not shutil.which("pwsh"):
        pytest.skip("pwsh is required for the Linux verification gate")
    _write_fake_wpr(work_root)
    body = RUNNER.format(
        script=SCRIPT,
        seconds=seconds,
        maxmb=maxmb,
        signal_after_ms=signal_after_ms,
    )
    env = dict(os.environ)
    env["WPD_WPR_TEST"] = str(work_root)
    env["PADDING_MB"] = str(padding_mb)
    started = time.monotonic()
    result = subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-Command", body],
        capture_output=True,
        check=False,
        text=True,
        env=env,
    )
    wall = time.monotonic() - started
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    payload = json.loads(result.stdout)
    payload["wall_seconds"] = round(wall, 2)
    return payload


def test_trace_stops_on_the_caller_signal_instead_of_its_full_window(tmp_path):
    """The trace must end with the counters, not sleep its whole maximum window.

    DurationSeconds is deliberately longer than the signal delay: if the job
    slept the full window the wall clock would be >= 30 s.
    """
    payload = _run(tmp_path, seconds=30, maxmb=0, signal_after_ms=300, padding_mb=1)

    assert payload["Finished"] is True
    assert payload["StartExitCode"] == 0
    assert payload["StopExitCode"] == 0
    # signalled at ~0.3 s; a full-window sleep would take >= 30 s
    assert payload["wall_seconds"] < 20, payload
    assert payload["WaitSeconds"] < 20, payload
    assert payload["EtlStillOnDisk"] is True
    assert payload["SizeLimitExceeded"] is False
    assert payload["TraceRemoved"] is False
    assert payload["ElapsedSeconds"] is not None


def test_trace_is_started_with_only_documented_wpr_arguments(tmp_path):
    """No invented wpr.exe switches: memory mode, profile only, then -stop."""
    payload = _run(tmp_path, seconds=30, maxmb=0, signal_after_ms=300, padding_mb=1)
    assert payload["StartExitCode"] == 0

    argv = (tmp_path / "argv.log").read_text(encoding="ascii").splitlines()
    assert len(argv) == 2, argv
    assert argv[0] == "-start GeneralProfile", argv[0]
    assert argv[1].startswith("-stop "), argv[1]
    assert argv[1].endswith("wpr-trace.etl"), argv[1]

    joined = " ".join(argv)
    for invented in ("-filemode", "-maxduration", "-filesize", "-maxfile"):
        assert invented not in joined, f"undocumented wpr.exe switch used: {invented}"


def test_oversized_trace_and_its_symbol_files_are_removed(tmp_path):
    """A multi-GB trace plus its managed-symbol directory must not ship."""
    payload = _run(tmp_path, seconds=30, maxmb=8, signal_after_ms=300, padding_mb=24)

    assert payload["SizeLimitExceeded"] is True
    assert payload["TraceRemoved"] is True
    assert payload["EtlStillOnDisk"] is False
    assert payload["SymbolDirStillOnDisk"] is False
    # the reported size is the real one, kept for the manifest even though the
    # file was removed
    assert payload["EtlBytes"] >= 24 * 1024 * 1024


def test_trace_within_the_cap_is_kept(tmp_path):
    """Under the cap the trace stays on disk and is hashed with the case."""
    payload = _run(tmp_path, seconds=30, maxmb=64, signal_after_ms=300, padding_mb=2)

    assert payload["SizeLimitExceeded"] is False
    assert payload["TraceRemoved"] is False
    assert payload["EtlStillOnDisk"] is True
    assert payload["EtlBytes"] >= 2 * 1024 * 1024
