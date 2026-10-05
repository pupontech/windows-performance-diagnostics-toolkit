"""Production wiring for unique cases, completion, and launcher handoffs."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
POWERSHELL_EXE = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")


def ps_quote(value: Path | str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def run_ps(tmp_path: Path, script: Path, *args: str, env: dict | None = None):
    if not shutil.which(POWERSHELL_EXE):
        pytest.skip(f"{POWERSHELL_EXE} is required for PowerShell integration tests")
    return subprocess.run(
        [POWERSHELL_EXE, "-NoLogo", "-NoProfile", "-File", str(script), *args],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        check=False,
        text=True,
    )


def test_completion_runs_after_package_transcript_stop_and_production_verify():
    source = (SRC / "Invoke-WindowsPerformanceDiagnostics.ps1").read_text(encoding="utf-8")
    zip_at = source.rindex("Add-CasePackageBlock -CollectionManifest")
    stop_at = source.rindex("Stop-Transcript | Out-Null")
    verify_at = source.rindex("-Mode Verify -InputDirectory")
    completion_at = source.rindex("Get-WpdRunCompletion")
    show_at = source.rindex("Show-WpdRunCompletion")
    assert zip_at < stop_at < verify_at < completion_at < show_at
    assert "[switch]$OpenOutputs" in source
    assert "[scriptblock]$PresentationRunner" in source
    assert "[string]$CompletionEnvelopePath" in source
    assert "CollectorExitCode" in source[completion_at:]


def test_launcher_passes_open_outputs_and_retains_caller_owned_receipt():
    launcher = (SRC / "Invoke-WpdLauncher.ps1").read_text(encoding="utf-8")
    assert "WPD_RUN_RECEIPT_PATH" in launcher
    assert "WPD_COMPLETION_ENVELOPE_PATH" in launcher
    assert "WPD_PRESENTATION_ARGV_RECEIPT_PATH" in launcher
    assert "OpenOutputs = $true" in launcher
    assert "RunReceiptPath = $receiptPath" in launcher
    assert "callerOwnedReceipt" in launcher
    assert "-not $callerOwnedReceipt -and" in launcher


def test_copied_plan_with_explicit_output_does_not_require_casepath(tmp_path):
    staged = tmp_path / "staged"
    shutil.copytree(SRC, staged, ignore=shutil.ignore_patterns("Wpd.CasePath.psm1"))
    script = staged / "Invoke-WindowsPerformanceDiagnostics.ps1"
    output = tmp_path / "plan-output"
    result = run_ps(tmp_path, script, "-Mode", "Plan", "-OutputDirectory", str(output))
    assert result.returncode == 0, result.stdout + result.stderr
    assert (output / "diagnostic-plan.json").is_file()
    assert "Wpd.CasePath.psm1" not in result.stdout + result.stderr


def test_two_launcher_runs_keep_exact_caller_receipts_and_prior_case(tmp_path):
    staged = tmp_path / "toolkit"
    (staged / "src").mkdir(parents=True)
    shutil.copy2(SRC / "Wpd.CasePath.psm1", staged / "src" / "Wpd.CasePath.psm1")
    shutil.copy2(SRC / "Invoke-WpdLauncher.ps1", staged / "src" / "Invoke-WpdLauncher.ps1")
    fake_collector = staged / "src" / "Invoke-WindowsPerformanceDiagnostics.ps1"
    fake_collector.write_text(
        """[CmdletBinding()]\nparam([string]$Mode,[switch]$ConfirmLocalCollection,[string]$CaseBaseDirectory,[string]$RunReceiptPath,[int]$DurationSeconds,[switch]$OpenOutputs,[string]$CompletionEnvelopePath,[scriptblock]$PresentationRunner,[switch]$CollectSearchContext,[switch]$CollectMinifilters,[switch]$ConfirmEscalationCollection,[switch]$CollectMinidumps,[switch]$ConfirmMinidumpCollection,[switch]$CollectBootFailureLogs,[switch]$ConfirmBootFailureLogCollection,[switch]$ZipOutput)\nImport-Module (Join-Path $PSScriptRoot 'Wpd.CasePath.psm1') -Force\n$case = New-WpdCaseDirectory -BaseDirectory $CaseBaseDirectory\n$runId = [IO.Path]::GetFileName($case).Split('-')[-1]\n[IO.File]::WriteAllText((Join-Path $case ('diagnostics-run-' + $runId + '.log')), 'run log')\n[IO.File]::WriteAllText((Join-Path $case 'diagnostic-manifest.json'), '{\"mode\":\"Collect\"}')\n$receipt = @{ casePath = $case; runId = $runId } | ConvertTo-Json -Compress\n$stream = [IO.File]::Open($RunReceiptPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)\ntry { $bytes = [Text.Encoding]::UTF8.GetBytes($receipt); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }\n""",
        encoding="utf-8",
    )
    launcher = staged / "src" / "Invoke-WpdLauncher.ps1"
    receipt_one = tmp_path / "run-one.json"
    receipt_two = tmp_path / "run-two.json"

    def invoke(receipt):
        env = os.environ.copy()
        env["WPD_RUN_RECEIPT_PATH"] = str(receipt)
        result = run_ps(tmp_path, launcher, "-LaunchMode", "StandaloneCollect", env=env)
        assert result.returncode == 0, result.stdout + result.stderr

    invoke(receipt_one)
    first_receipt = json.loads(receipt_one.read_text(encoding="utf-8"))
    first_case = Path(first_receipt["casePath"])
    (first_case / 'preserve-first-run.txt').write_text('First run sentinel', encoding='ascii')
    first_snapshot = {p.relative_to(first_case): p.read_bytes() for p in first_case.rglob("*") if p.is_file()}
    invoke(receipt_two)
    second_receipt = json.loads(receipt_two.read_text(encoding="utf-8"))
    second_case = Path(second_receipt["casePath"])
    assert first_case != second_case
    assert first_case.parent == second_case.parent
    expected_base_name = 'WPD-Case' if os.name == 'nt' else 'windows-performance-diagnostics'
    assert first_case.parent.name == expected_base_name
    assert (first_case / "diagnostic-manifest.json").read_bytes() == first_snapshot[Path("diagnostic-manifest.json")]
    assert {p.relative_to(first_case): p.read_bytes() for p in first_case.rglob("*") if p.is_file()} == first_snapshot
    assert receipt_one.is_file() and receipt_two.is_file()


def test_batch_files_quote_documented_child_engine_override_and_keep_crlf_ascii():
    for name in ("Run-Diagnostics.bat", "START-HERE.bat"):
        data = (ROOT / name).read_bytes()
        text = data.decode("ascii")
        assert data.isascii()
        assert data.count(b"\n") == data.count(b"\r\n")
        assert "WPD_POWERSHELL_EXE" in text
        assert '"%WPD_POWERSHELL_EXE%"' in text
        assert "powershell.exe" in text


def test_native_verify_exit_code_is_captured_immediately_without_pipeline():
    source = (SRC / "Invoke-WindowsPerformanceDiagnostics.ps1").read_text(encoding="utf-8")
    assert "-Mode Verify -InputDirectory $resolvedOutputDirectory" in source
    verify_call = source.rindex("-Mode Verify -InputDirectory $resolvedOutputDirectory")
    captured = source.find("$verificationExitCode = $LASTEXITCODE", verify_call)
    assert captured > verify_call
    assert source[verify_call:captured].count("$LASTEXITCODE") == 0
    assert "Tee-Object" not in source


def test_missing_casepath_default_collect_has_pre_io_clear_failure():
    source = (SRC / "Invoke-WindowsPerformanceDiagnostics.ps1").read_text(encoding="utf-8")
    assert "Wpd.CasePath.psm1 is required for default Collect" in source
    assert source.index("if (-not $ConfirmLocalCollection)") < source.index(
        "Wpd.CasePath.psm1 is required for default Collect"
    ) < source.index("New-WpdCaseDirectory")
