"""Pure-helper coverage for the WPD-04/05 live-case harness.

The tests extract the real helper function bodies from the harness AST and run
those bodies against synthetic case folders. No live collection or Windows-only
provider is invoked here.
"""

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HARNESS = REPO_ROOT / "tests" / "live" / "Invoke-WpdLiveCase0405.ps1"

MANIFEST_FUNCTIONS = ["Get-WpdSha256", "Get-WpdManifestEvidence"]
UNLISTED_FUNCTIONS = ["Get-WpdUnlistedFiles"]
FINGERPRINT_FUNCTIONS = ["Compare-WpdFingerprint"]
SAFETY_FUNCTIONS = ["Get-WpdSafetyDeclarationCheck"]


def _ps_literal(value: str | Path) -> str:
    """Return a PowerShell single-quoted literal for a test value."""
    return "'" + str(value).replace("'", "''") + "'"


def run_pwsh(body: str, functions: list[str]) -> str:
    """Extract functions from the harness by AST and execute a test body."""
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    if not shutil.which(powershell):
        pytest.skip(f"{powershell} is required for the live-helper gate")
    assert HARNESS.is_file(), f"live harness is missing: {HARNESS}"
    names = ", ".join(_ps_literal(name) for name in functions)
    harness_path = str(HARNESS).replace("'", "''")
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
    return result.stdout.strip()


def run_pwsh_json(body: str, functions: list[str]) -> dict:
    output = run_pwsh(body, functions)
    assert output, "PowerShell helper body emitted no JSON"
    return json.loads(output.splitlines()[-1])


def _entry(name: str, content: bytes) -> dict[str, object]:
    return {
        "Name": name,
        "Sha256": hashlib.sha256(content).hexdigest().upper(),
        "SizeBytes": len(content),
    }


def _write_file(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_manifest_evidence_accepts_intact_files_and_matches_hashes_and_sizes(tmp_path):
    case = tmp_path / "intact"
    first = b"timestamp,cpu\n1,2\n"
    second = b'{"process":"pwsh","cpu":1}\n'
    _write_file(case / "performance-samples.csv", first)
    _write_file(case / "nested" / "top-processes.json", second)
    manifest = {"artifacts": [_entry("performance-samples.csv", first), _entry(r"nested\top-processes.json", second)]}
    manifest_json = json.dumps(manifest).replace("'", "''")

    payload = run_pwsh_json(
        f"""
$manifest = ConvertFrom-Json -InputObject '{manifest_json}'
$rows = @(Get-WpdManifestEvidence -OutputDirectory {_ps_literal(case)} -Manifest $manifest)
[pscustomobject]@{{
    count = $rows.Count
    allFilesExist = (@($rows | Where-Object {{ -not $_.fileExists }}).Count -eq 0)
    allHashesMatch = (@($rows | Where-Object {{ -not $_.hashMatches }}).Count -eq 0)
    allSizesMatch = (@($rows | Where-Object {{ -not $_.sizeMatches }}).Count -eq 0)
    names = (@($rows | ForEach-Object {{ $_.name }}) -join '|')
}} | ConvertTo-Json -Compress
""",
        MANIFEST_FUNCTIONS,
    )

    assert payload == {
        "count": 2,
        "allFilesExist": True,
        "allHashesMatch": True,
        "allSizesMatch": True,
        "names": "performance-samples.csv|nested\\top-processes.json",
    }


def test_manifest_evidence_detects_a_same_size_tampered_artifact(tmp_path):
    case = tmp_path / "tampered"
    original = b"stable"
    tampered = b"broken"
    artifact = case / "performance-samples.csv"
    _write_file(artifact, original)
    manifest_json = json.dumps({"artifacts": [_entry("performance-samples.csv", original)]}).replace("'", "''")
    artifact.write_bytes(tampered)

    payload = run_pwsh_json(
        f"""
$manifest = ConvertFrom-Json -InputObject '{manifest_json}'
$row = @(Get-WpdManifestEvidence -OutputDirectory {_ps_literal(case)} -Manifest $manifest)[0]
[pscustomobject]@{{
    fileExists = $row.fileExists
    hashMatches = $row.hashMatches
    sizeMatches = $row.sizeMatches
    declaredSha256 = $row.declaredSha256
    actualSha256 = $row.actualSha256
}} | ConvertTo-Json -Compress
""",
        MANIFEST_FUNCTIONS,
    )

    assert payload["fileExists"] is True
    assert payload["hashMatches"] is False
    assert payload["sizeMatches"] is True
    assert payload["declaredSha256"] != payload["actualSha256"]


def test_unlisted_file_check_ignores_manifest_and_reports_extra_artifacts(tmp_path):
    case = tmp_path / "completeness"
    _write_file(case / "listed.txt", b"listed")
    _write_file(case / "extra.txt", b"not in manifest")
    _write_file(case / "diagnostic-manifest.json", b"{}")
    manifest_json = json.dumps({"artifacts": [_entry("listed.txt", b"listed")]}).replace("'", "''")

    payload = run_pwsh_json(
        f"""
$manifest = ConvertFrom-Json -InputObject '{manifest_json}'
$unlisted = @(Get-WpdUnlistedFiles -OutputDirectory {_ps_literal(case)} -Manifest $manifest)
[pscustomobject]@{{ count = $unlisted.Count; names = ($unlisted -join '|') }} | ConvertTo-Json -Compress
""",
        UNLISTED_FUNCTIONS,
    )

    assert payload == {"count": 1, "names": "extra.txt"}


def test_fingerprint_comparison_reports_only_changed_strict_surfaces():
    payload = run_pwsh_json(
        r"""
$before = [ordered]@{
    strict = [ordered]@{
        administrators = @('BUILTIN\Administrators')
        runKeys = @('HKCU|One|old')
        startupFolder = @('stable.lnk')
    }
}
$after = [ordered]@{
    strict = [ordered]@{
        administrators = @('BUILTIN\Administrators')
        runKeys = @('HKCU|One|new')
        startupFolder = @('stable.lnk')
    }
}
$deltas = @(Compare-WpdFingerprint -Before $before -After $after)
$unchanged = @(Compare-WpdFingerprint -Before $before -After $before)
[pscustomobject]@{
    changedCount = $deltas.Count
    changedSurface = [string]$deltas[0].surface
    beforeValue = [string]$deltas[0].before
    afterValue = [string]$deltas[0].after
    unchangedCount = $unchanged.Count
} | ConvertTo-Json -Compress
""",
        FINGERPRINT_FUNCTIONS,
    )

    assert payload["changedCount"] == 1
    assert payload["changedSurface"] == "runKeys"
    assert "old" in payload["beforeValue"]
    assert "new" in payload["afterValue"]
    assert payload["unchangedCount"] == 0


def test_safety_declaration_check_accepts_safe_manifest_and_rejects_missing_blocks():
    payload = run_pwsh_json(
        r"""
$good = [pscustomobject]@{
    safety = [pscustomobject]@{
        localOnly = $true
        readOnly = $true
        requiresExplicitCollectionConsent = $true
        automaticUpload = $false
        automaticRemediation = $false
        automaticLogClearing = $false
    }
    privacy = [pscustomobject]@{
        secretsCollected = $false
        redactionApplied = $true
        level = 'standard'
        requestedLevel = 'standard'
    }
}
$negative = [pscustomobject]@{ mode = 'Collect'; artifacts = @() }
$goodResult = Get-WpdSafetyDeclarationCheck -Manifest $good
$negativeResult = Get-WpdSafetyDeclarationCheck -Manifest $negative
[pscustomobject]@{
    good = $goodResult.ok
    negative = $negativeResult.ok
    negativeObserved = [string]$negativeResult.observed
} | ConvertTo-Json -Compress
""",
        SAFETY_FUNCTIONS,
    )

    assert payload["good"] is True
    assert payload["negative"] is False
    assert "no safety or privacy declaration block present" in payload["negativeObserved"]
