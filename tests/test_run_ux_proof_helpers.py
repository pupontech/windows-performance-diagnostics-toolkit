"""Pure-helper coverage for the WPD run-UX proof harness.

The tests extract helper functions from the live PowerShell harness and execute
synthetic inputs only. They never run a collector, touch Windows state, or claim
that a GUI was displayed.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HARNESS = REPO_ROOT / "tests" / "live" / "Invoke-WpdRunUxProof.ps1"
HELPERS = [
    "Get-WpdProperty",
    "Test-WpdCaseLeafName",
    "Get-WpdSummaryEnvelopeErrors",
    "Assert-WpdPresentationArgvReceipt",
]


def _ps_literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def run_pwsh_json(body: str) -> dict:
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    if not shutil.which(powershell):
        pytest.skip(f"{powershell} is required for the live-helper gate")
    assert HARNESS.is_file(), f"live harness is missing: {HARNESS}"
    harness_path = str(HARNESS).replace("'", "''")
    names = ", ".join(_ps_literal(name) for name in HELPERS)
    command = f"""
$ErrorActionPreference = 'Stop'
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{harness_path}', [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {{ throw "harness parse failed: $($parseErrors.Count) error(s)" }}
foreach ($name in @({names})) {{
    $found = @($ast.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }}, $true))
    if ($found.Count -ne 1) {{ throw "expected exactly one function named $name, found $($found.Count)" }}
    Invoke-Expression $found[0].Extent.Text
}}
Set-StrictMode -Version Latest
{body}
"""
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-Command", command],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, (
        f"pwsh failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    output = result.stdout.strip()
    assert output, "PowerShell helper body emitted no JSON"
    return json.loads(output.splitlines()[-1])


def test_case_leaf_name_requires_a_real_utc_timestamp_and_random_suffix():
    payload = run_pwsh_json(
        r"""
[pscustomobject]@{
    valid = Test-WpdCaseLeafName -LeafName '20261004T123456Z-4a62ec81'
    fractional = Test-WpdCaseLeafName -LeafName '20261004T123456.123Z-a73e9c10'
    invalidDate = Test-WpdCaseLeafName -LeafName '20261340T256199Z-4a62ec81'
    noRunId = Test-WpdCaseLeafName -LeafName '20261004T123456Z'
    tooShort = Test-WpdCaseLeafName -LeafName '20261004T123456Z-a'
} | ConvertTo-Json -Compress
"""
    )
    assert payload == {
        "valid": True,
        "fractional": True,
        "invalidDate": False,
        "noRunId": False,
        "tooShort": False,
    }


def test_summary_envelope_accepts_truthful_search_partial_and_rejects_false_success():
    payload = run_pwsh_json(
        r"""
$good = [pscustomobject]@{
    status = 'partial'
    exitCode = 0
    caseDirectory = 'C:\WPD-Case\20261004T123456Z-4a62ec81'
    manifestPath = 'C:\WPD-Case\20261004T123456Z-4a62ec81\diagnostic-manifest.json'
    reportPath = 'C:\WPD-Case\20261004T123456Z-4a62ec81\report.html'
    errors = @()
    missingJson = @()
    stages = @(
        [pscustomobject]@{ name = 'search'; status = 'partial'; reason = 'index provider unavailable' }
        [pscustomobject]@{ name = 'wpr'; status = 'skipped-consent-not-granted'; reason = 'not requested' }
    )
    renderedText = 'Status: partial; case C:\WPD-Case\20261004T123456Z-4a62ec81; report C:\WPD-Case\20261004T123456Z-4a62ec81\report.html'
}
$falseSuccess = $good.PSObject.Copy()
$falseSuccess.status = 'completed'
$falseSuccess.exitCode = 5
$cleanFalseSuccess = $good.PSObject.Copy()
$cleanFalseSuccess.status = 'completed'
$cleanFalseSuccess.exitCode = 0
$missing = $good.PSObject.Copy()
$missing.status = 'completed'
$missing.exitCode = 0
$missing.missingJson = @('diagnostic-manifest.json')
$wrongPath = $good.PSObject.Copy()
$wrongPath.reportPath = 'C:\WPD-Case\other\report.html'
$badStages = $good.PSObject.Copy()
$badStages.stages = @([pscustomobject]@{ name = 'wpr'; status = 'skipped'; reason = '' })
[pscustomobject]@{
    good = @(Get-WpdSummaryEnvelopeErrors -Envelope $good -CaseDirectory $good.caseDirectory -ManifestPath $good.manifestPath -ReportPath $good.reportPath -SearchStatus 'partial').Count
    nonzero = @(Get-WpdSummaryEnvelopeErrors -Envelope $falseSuccess -CaseDirectory $good.caseDirectory -ManifestPath $good.manifestPath -ReportPath $good.reportPath -SearchStatus 'partial').Count
    falseCompleted = @(Get-WpdSummaryEnvelopeErrors -Envelope $cleanFalseSuccess -CaseDirectory $good.caseDirectory -ManifestPath $good.manifestPath -ReportPath $good.reportPath -SearchStatus 'partial').Count
    missingJson = @(Get-WpdSummaryEnvelopeErrors -Envelope $missing -CaseDirectory $good.caseDirectory -ManifestPath $good.manifestPath -ReportPath $good.reportPath -SearchStatus 'partial').Count
    wrongPath = @(Get-WpdSummaryEnvelopeErrors -Envelope $wrongPath -CaseDirectory $good.caseDirectory -ManifestPath $good.manifestPath -ReportPath $good.reportPath -SearchStatus 'partial').Count
    missingSkipReason = @(Get-WpdSummaryEnvelopeErrors -Envelope $badStages -CaseDirectory $good.caseDirectory -ManifestPath $good.manifestPath -ReportPath $good.reportPath -SearchStatus 'partial').Count
} | ConvertTo-Json -Compress
"""
    )
    assert payload["good"] == 0, payload
    assert payload["nonzero"] > 0
    assert payload["falseCompleted"] > 0
    assert payload["missingJson"] > 0
    assert payload["wrongPath"] > 0
    assert payload["missingSkipReason"] > 0


def test_live_harness_refuses_non_windows_before_touching_proof_paths(tmp_path):
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    if not shutil.which(powershell):
        pytest.skip(f"{powershell} is required for the live-harness guard")
    root = tmp_path / "must-not-be-created"
    result = subprocess.run(
        [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-File",
            str(HARNESS),
            "-FirstCaseDirectory",
            str(root / "20261004T123456Z-4a62ec81"),
            "-SecondCaseDirectory",
            str(root / "20261004T123457Z-a73e9c10"),
            "-BaselineReceiptPath",
            str(tmp_path / "baseline.json"),
            "-FirstRunLogPath",
            str(root / "first" / "diagnostics-run.log"),
            "-SecondRunLogPath",
            str(root / "second" / "diagnostics-run.log"),
            "-ToolkitScriptPath",
            str(root / "collector.ps1"),
            "-PresentationArgvReceiptPath",
            str(tmp_path / "presentation.json"),
            "-RootDirectory",
            str(root),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode != 0
    assert "real-Windows proof harness" in (result.stdout + result.stderr)
    assert not root.exists(), "a Linux proof attempt must not create a Windows case root"


def test_presentation_receipt_rejects_failed_runner_and_nonzero_exit(tmp_path):
    case = str(tmp_path / "20261004T123456Z-4a62ec81")
    report = str(Path(case) / "report.html")
    receipt_path = tmp_path / "presentation.json"
    body = f"""
$receiptPath = {_ps_literal(receipt_path)}
$good = [pscustomobject]@{{
    runnerInjected = $true
    guiOpened = $false
    presentationStatus = 'accepted'
    runnerExitCode = 0
    caseDirectory = {_ps_literal(case)}
    reportPath = {_ps_literal(report)}
    argv = @({_ps_literal(case)}, {_ps_literal(report)})
}}
$good | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $receiptPath
$goodAccepted = $true
try {{ Assert-WpdPresentationArgvReceipt -ReceiptPath $receiptPath -CaseDirectory {_ps_literal(case)} -ReportPath {_ps_literal(report)} }}
catch {{ $goodAccepted = $false }}
$failed = $good.PSObject.Copy()
$failed.presentationStatus = 'failed'
$failed | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $receiptPath
$failedRejected = $false
try {{ Assert-WpdPresentationArgvReceipt -ReceiptPath $receiptPath -CaseDirectory {_ps_literal(case)} -ReportPath {_ps_literal(report)} }}
catch {{ $failedRejected = $true }}
$nonzero = $good.PSObject.Copy()
$nonzero.runnerExitCode = 7
$nonzero | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $receiptPath
$nonzeroRejected = $false
try {{ Assert-WpdPresentationArgvReceipt -ReceiptPath $receiptPath -CaseDirectory {_ps_literal(case)} -ReportPath {_ps_literal(report)} }}
catch {{ $nonzeroRejected = $true }}
[pscustomobject]@{{ goodAccepted = $goodAccepted; failedRejected = $failedRejected; nonzeroRejected = $nonzeroRejected }} | ConvertTo-Json -Compress
"""
    payload = run_pwsh_json(body)
    assert payload == {
        "goodAccepted": True,
        "failedRejected": True,
        "nonzeroRejected": True,
    }
