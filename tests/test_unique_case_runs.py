"""Unique per-run case-directory policy and consent-bound path selection."""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src" / "Wpd.CasePath.psm1"
SCRIPT = ROOT / "src" / "Invoke-WindowsPerformanceDiagnostics.ps1"
POWERSHELL_EXE = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")


def ps_quote(value: Path | str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def run_pwsh(tmp_path: Path, body: str) -> subprocess.CompletedProcess[str]:
    if not shutil.which(POWERSHELL_EXE):
        pytest.skip("PowerShell is required for the case-path module tests")
    harness = "$ErrorActionPreference = 'Stop'\n" + body
    script = tmp_path / "case-path-harness.ps1"
    script.write_text(harness, encoding="utf-8")
    return subprocess.run(
        [POWERSHELL_EXE, "-NoLogo", "-NoProfile", "-File", str(script)],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        text=True,
    )


def import_case_module() -> str:
    return f"Import-Module -Name {ps_quote(MODULE)} -Force\n"


def test_two_runs_get_distinct_children_and_preserve_first_run_artifacts(tmp_path):
    base = tmp_path / "cases"
    body = import_case_module() + f"""
$first = New-WpdCaseDirectory -BaseDirectory {ps_quote(base)}
Set-Content -LiteralPath (Join-Path $first 'sentinel.txt') -Value 'first-run'
$second = New-WpdCaseDirectory -BaseDirectory {ps_quote(base)}
@{{ first = $first; second = $second }} | ConvertTo-Json -Compress
"""
    result = run_pwsh(tmp_path, body)
    assert result.returncode == 0, result.stderr
    paths = json.loads(result.stdout.strip().splitlines()[-1])
    first = Path(paths["first"])
    second = Path(paths["second"])
    assert first.parent == base and second.parent == base
    assert first != second
    assert re.fullmatch(r"\d{8}T\d{9}Z-[0-9a-f]{32}", first.name)
    assert re.fullmatch(r"\d{8}T\d{9}Z-[0-9a-f]{32}", second.name)
    assert (first / "sentinel.txt").read_text(encoding="utf-8").strip() == "first-run"
    assert sorted(p.name for p in base.iterdir()) == [first.name, second.name]


def test_existing_run_name_is_refused_without_overwriting(tmp_path):
    base = tmp_path / "cases"
    body = import_case_module() + f"""
$stamp = [DateTime]::Parse('2026-10-04T12:34:56Z').ToUniversalTime()
$first = New-WpdCaseDirectory -BaseDirectory {ps_quote(base)} -TimestampUtc $stamp -RunId 'same-id'
Set-Content -LiteralPath (Join-Path $first 'sentinel.txt') -Value 'keep-me'
try {{
    New-WpdCaseDirectory -BaseDirectory {ps_quote(base)} -TimestampUtc $stamp -RunId 'same-id' | Out-Null
    throw 'collision was silently accepted'
}} catch {{ if ($_.Exception.Message -notmatch 'already exists|collision') {{ throw }} }}
Get-Content -LiteralPath (Join-Path $first 'sentinel.txt') -Raw
"""
    result = run_pwsh(tmp_path, body)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("keep-me")
    assert len(list(base.iterdir())) == 1


def test_existing_file_at_base_is_refused(tmp_path):
    base_file = tmp_path / "not-a-directory"
    base_file.write_text("untouched", encoding="utf-8")
    result = run_pwsh(
        tmp_path,
        import_case_module()
        + f"New-WpdCaseDirectory -BaseDirectory {ps_quote(base_file)} | Out-Null\n",
    )
    assert result.returncode != 0
    assert base_file.read_text(encoding="utf-8") == "untouched"


def test_default_base_policy_without_reserving_a_run(tmp_path):
    result = run_pwsh(tmp_path, import_case_module() + "Get-WpdDefaultCaseBaseDirectory\n")
    assert result.returncode == 0, result.stderr
    if os.name == "nt":
        assert Path(result.stdout.strip()) == Path(r"C:\WPD-Case")
    else:
        assert Path(result.stdout.strip()) == tmp_path / "windows-performance-diagnostics"
        assert not (tmp_path / "windows-performance-diagnostics").exists()


def test_invalid_run_id_cannot_escape_or_create_the_base(tmp_path):
    base = tmp_path / "cases"
    result = run_pwsh(
        tmp_path,
        import_case_module()
        + f"New-WpdCaseDirectory -BaseDirectory {ps_quote(base)} -RunId '../outside' | Out-Null\n",
    )
    assert result.returncode != 0
    assert not base.exists()


def test_reparse_point_in_base_path_is_refused(tmp_path):
    target = tmp_path / "real-base"
    target.mkdir()
    link = tmp_path / "linked-base"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks unavailable: {error}")
    result = run_pwsh(
        tmp_path,
        import_case_module()
        + f"New-WpdCaseDirectory -BaseDirectory {ps_quote(link)} | Out-Null\n",
    )
    assert result.returncode != 0
    assert list(target.iterdir()) == []


def test_default_collect_selection_is_after_consent_and_platform_gates():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "[string]$CaseBaseDirectory" in text
    assert re.search(r"\[string\]\$OutputDirectory\s*[,\n]", text)
    assert "New-WpdCaseDirectory" in text
    call_at = text.index("New-WpdCaseDirectory")
    consent_at = text.index("if (-not $ConfirmLocalCollection)")
    platform_at = text.index("Collect mode is supported only on Windows")
    assert call_at > consent_at
    assert call_at > platform_at
    assert "$PSBoundParameters.ContainsKey('OutputDirectory')" in text
    platform_at = text.index("Collect mode is supported only on Windows")
    selection_at = text.index("# Consent and platform gates passed", platform_at)
    collection_errors_at = text.index("$script:collectionErrors = New-Object System.Collections.ArrayList", selection_at)
    selection = text[selection_at:collection_errors_at]
    assert "if (-not $script:WpdOutputDirectoryWasExplicit)" in selection
    assert "New-WpdCaseDirectory -BaseDirectory $resolvedOutputDirectory" in selection
    assert "New-Item -ItemType Directory -Force -Path $resolvedOutputDirectory" in selection


def test_run_receipt_is_created_after_gates_and_uses_create_new(tmp_path):
    text = SCRIPT.read_text(encoding="utf-8")
    collect_start = text.index("if (-not $ConfirmLocalCollection)")
    platform_at = text.index("Collect mode is supported only on Windows", collect_start)
    collection_errors_at = text.index("$script:collectionErrors = New-Object System.Collections.ArrayList", platform_at)
    collect = text[collect_start:collection_errors_at]
    assert collect.index("Collect mode is supported only on Windows") < collect.index("RunReceiptPath")
    assert "[System.IO.FileMode]::CreateNew" in collect
    assert "casePath = $resolvedOutputDirectory" in collect
    assert "runId = $script:WpdRunId" in collect


def test_consent_and_platform_refusals_do_not_create_a_case_base(tmp_path):
    base = tmp_path / "must-not-exist"
    if not shutil.which(POWERSHELL_EXE):
        pytest.skip("PowerShell is required for entry-point refusal tests")
    consent = subprocess.run(
        [
            POWERSHELL_EXE,
            "-NoLogo",
            "-NoProfile",
            "-File",
            str(SCRIPT),
            "-Mode",
            "Collect",
            "-CaseBaseDirectory",
            str(base),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert consent.returncode != 0
    assert "ConfirmLocalCollection" in consent.stdout + consent.stderr
    assert not base.exists()

    if os.name == "nt":
        pytest.skip("Windows passes the platform gate; do not invoke live providers in this refusal test")

    platform = subprocess.run(
        [
            POWERSHELL_EXE,
            "-NoLogo",
            "-NoProfile",
            "-File",
            str(SCRIPT),
            "-Mode",
            "Collect",
            "-ConfirmLocalCollection",
            "-CaseBaseDirectory",
            str(base),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert platform.returncode != 0
    assert "supported only on Windows" in platform.stdout + platform.stderr
    assert not base.exists()


def test_plan_and_verify_keep_caller_selected_case_exact_and_read_only(tmp_path):
    if not shutil.which(POWERSHELL_EXE):
        pytest.skip("PowerShell is required for Plan/Verify contract tests")
    case = tmp_path / "exact-case"
    planned = subprocess.run(
        [
            POWERSHELL_EXE,
            "-NoLogo",
            "-NoProfile",
            "-File",
            str(SCRIPT),
            "-Mode",
            "Plan",
            "-OutputDirectory",
            str(case),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert planned.returncode == 0, planned.stderr
    plan = case / "diagnostic-plan.json"
    assert plan.is_file()
    assert not (case / "20261004T123456789Z-run-id").exists()
    before = {path.relative_to(case): path.read_bytes() for path in case.rglob("*") if path.is_file()}

    verified = subprocess.run(
        [
            POWERSHELL_EXE,
            "-NoLogo",
            "-NoProfile",
            "-File",
            str(SCRIPT),
            "-Mode",
            "Verify",
            "-InputDirectory",
            str(case),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    # A plan is not a Collect case manifest, so verification refuses it; the
    # important path contract is that Verify reads the exact supplied folder
    # and does not create, nest, or rewrite anything there.
    assert verified.returncode != 0
    after = {path.relative_to(case): path.read_bytes() for path in case.rglob("*") if path.is_file()}
    assert after == before
