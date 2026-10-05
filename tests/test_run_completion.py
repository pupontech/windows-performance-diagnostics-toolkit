"""End-of-run completion summary tests using persisted case files and real pwsh."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "src" / "Wpd.Completion.psm1"
POWERSHELL_EXE = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")


def _write_case(case: Path, manifest: dict, files: dict[str, bytes]) -> None:
    case.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        target = case / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    (case / "diagnostic-manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )


def _registered(name: str, content: bytes) -> dict:
    return {
        "Name": name,
        "Sha256": hashlib.sha256(content).hexdigest().upper(),
        "SizeBytes": len(content),
    }


def _valid_case(case: Path) -> dict:
    files = {
        "report.html": b"<!doctype html><title>Local report</title>",
        "findings.json": b"[]\n",
        "escalation/minifilter-enumeration.json": b'{"status":"success"}\n',
    }
    manifest = {
        "schemaVersion": "1.3",
        "mode": "Collect",
        "collectionErrors": [],
        "artifacts": [_registered(name, content) for name, content in files.items()],
        "tiers": {
            "coverage": [
                {
                    "collector": "tier0-static-inventory",
                    "status": "success",
                    "coverage": "complete",
                },
                {
                    "collector": "tier1-performance-counters",
                    "status": "partial",
                    "coverage": "partial",
                },
            ],
            "tier3": {
                "status": "success",
                "adapters": [
                    {
                        "id": "minifilter-enumeration",
                        "status": "success",
                        "artifact": "escalation/minifilter-enumeration.json",
                    }
                ],
            },
        },
        "wpr": {"status": "skipped-wpr-not-found"},
        "minidumps": {"status": "skipped-no-minidumps"},
        "bootFailureLogs": {"status": "completed"},
        "package": {"status": "completed", "zipPath": "outside-case.zip"},
    }
    _write_case(case, manifest, files)
    return manifest


def _ps_quote(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def run_pwsh_json(tmp_path: Path, body: str) -> dict:
    assert shutil.which(POWERSHELL_EXE), f"{POWERSHELL_EXE} is required for completion tests"
    harness = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"Import-Module -Name {_ps_quote(MODULE_PATH)} -Force",
            "Set-StrictMode -Version Latest",
            body,
        ]
    )
    harness_path = tmp_path / "completion-harness.ps1"
    harness_path.write_text(harness, encoding="ascii", newline="\n")
    result = subprocess.run(
        [POWERSHELL_EXE, "-NoLogo", "-NoProfile", "-File", str(harness_path)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, (
        f"pwsh failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    output = result.stdout.strip()
    assert output, "PowerShell harness emitted no JSON"
    return json.loads(output)


def test_valid_persisted_case_reports_real_stages_and_verified_files(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "partial"
    assert result["caseDirectory"] == str(case.resolve())
    assert result["reportPath"] == str((case / "report.html").resolve())
    stages = {stage["collector"]: stage for stage in result["stages"]}
    assert stages["tier0-static-inventory"]["status"] == "success"
    assert stages["tier1-performance-counters"]["outcome"] == "partial"
    assert stages["minifilter-enumeration"]["status"] == "success"
    assert stages["wpr"]["outcome"] == "skipped"
    assert stages["minidumps"]["outcome"] == "skipped"
    assert stages["package"]["status"] == "completed"
    assert all(item["exists"] for item in result["artifacts"])
    assert all(
        item["hashCheckStatus"] == "match"
        for item in result["artifacts"]
        if item["name"] != "diagnostic-manifest.json"
    )
    assert next(
        item["hashCheckStatus"]
        for item in result["artifacts"]
        if item["name"] == "diagnostic-manifest.json"
    ) == "not-applicable"
    assert result["missingArtifacts"] == []
    assert not any("health" in reason.lower() or "clean" in reason.lower() for reason in result["reasons"])


def test_missing_caller_requested_escalation_artifact_fails_closed(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)} "
        "-RequiredArtifacts @('escalation/search-service-context.json', "
        "'escalation/minifilter-enumeration.json'); "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "failed"
    assert "escalation/search-service-context.json" in result["missingArtifacts"]
    artifacts = {item["name"]: item for item in result["artifacts"]}
    assert artifacts["escalation/minifilter-enumeration.json"]["hashCheckStatus"] == "match"
    assert artifacts["escalation/search-service-context.json"]["hashCheckStatus"] == "missing"


def test_tampered_registered_artifact_fails_and_case_files_are_read_only(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    manifest_before = (case / "diagnostic-manifest.json").read_bytes()
    (case / "findings.json").write_bytes(b"tampered\n")
    before = {path.relative_to(case).as_posix() for path in case.rglob("*") if path.is_file()}
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "failed"
    artifacts = {item["name"]: item for item in result["artifacts"]}
    assert artifacts["findings.json"]["hashCheckStatus"] == "mismatch"
    after = {path.relative_to(case).as_posix() for path in case.rglob("*") if path.is_file()}
    assert after == before
    assert (case / "diagnostic-manifest.json").read_bytes() == manifest_before


@pytest.mark.parametrize("manifest_text", [None, "{"])
def test_missing_or_malformed_manifest_returns_failed_envelope(tmp_path, manifest_text):
    case = tmp_path / "case"
    case.mkdir()
    (case / "report.html").write_text("report", encoding="utf-8")
    if manifest_text is not None:
        (case / "diagnostic-manifest.json").write_text(manifest_text, encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "failed"
    assert result["reportPath"] == str((case / "report.html").resolve())
    assert result["stages"] == []
    if manifest_text is None:
        assert "diagnostic-manifest.json" in result["missingArtifacts"]
        assert "manifest-missing" in result["reasons"]
    else:
        assert "manifest-malformed" in result["reasons"]


def test_collection_errors_and_partial_search_adapter_cannot_be_hidden(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for coverage in manifest["tiers"]["coverage"]:
        coverage["status"] = "success"
        coverage["coverage"] = "complete"
    manifest["tiers"]["tier3"]["status"] = "partial"
    manifest["tiers"]["tier3"]["adapters"] = [
        {"id": "search-service-context", "status": "partial", "artifact": "escalation/search-service-context.json"}
    ]
    manifest["collectionErrors"] = [{"Stage": "disk-series-export", "Message": "controlled export error"}]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "partial"
    stages = {stage["collector"]: stage for stage in result["stages"]}
    assert stages["search-service-context"]["status"] == "partial"
    assert stages["search-service-context"]["outcome"] == "partial"
    assert stages["disk-series-export"]["status"] == "error"
    assert stages["disk-series-export"]["outcome"] == "failed"
    assert "collection-errors:1" in result["reasons"]


@pytest.mark.parametrize(
    "collection_error_stages",
    [
        [],
        ["disk-series-export"],
        ["disk-series-export", "memory-series-export", "event-log-export"],
    ],
)
def test_collection_error_stage_identity_is_preserved_for_zero_one_and_many(
    tmp_path, collection_error_stages
):
    case = tmp_path / "case"
    _valid_case(case)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["collectionErrors"] = [
        {"Stage": stage, "Message": f"controlled {stage} error"}
        for stage in collection_error_stages
    ]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    error_stages = [
        stage["collector"] for stage in result["stages"] if stage["status"] == "error"
    ]
    assert error_stages == collection_error_stages
    if collection_error_stages:
        assert f"collection-errors:{len(collection_error_stages)}" in result["reasons"]
    else:
        assert not any(reason.startswith("collection-errors:") for reason in result["reasons"])


def test_traversal_and_arbitrary_required_paths_are_refused(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("do not inspect", encoding="utf-8")
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for coverage in manifest["tiers"]["coverage"]:
        coverage["status"] = "success"
        coverage["coverage"] = "complete"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)} "
        "-RequiredArtifacts @('../outside-secret.txt', 'C:/Windows/win.ini', 'file://host/path'); "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "failed"
    names = [item["name"] for item in result["artifacts"]]
    assert not any(".." in name or ":" in name or "file:" in name for name in names)
    assert "unsafe-required-artifact-name" in result["reasons"]


def test_nonzero_collector_exit_code_fails_even_with_verified_outputs(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for coverage in manifest["tiers"]["coverage"]:
        coverage["status"] = "success"
        coverage["coverage"] = "complete"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)} -CollectorExitCode 7; "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "failed"
    assert "collector-exit-code:7" in result["reasons"]
    assert result["reportPath"] == str((case / "report.html").resolve())


def test_missing_final_report_is_failed_and_never_returns_report_path(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    (case / "report.html").unlink()
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "failed"
    assert result["reportPath"] is None
    assert "report.html" in result["missingArtifacts"]


def test_expected_optional_skips_do_not_reduce_completed_collection(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for coverage in manifest["tiers"]["coverage"]:
        coverage["status"] = "success"
        coverage["coverage"] = "complete"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "completed"
    stages = {stage["collector"]: stage for stage in result["stages"]}
    assert stages["wpr"]["status"] == "skipped-wpr-not-found"
    assert stages["wpr"]["outcome"] == "skipped"
    assert stages["minidumps"]["status"] == "skipped-no-minidumps"
    assert stages["minidumps"]["outcome"] == "skipped"


def test_show_prints_local_summary_and_suppresses_opening_in_ci(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for coverage in manifest["tiers"]["coverage"]:
        coverage["status"] = "success"
        coverage["coverage"] = "complete"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        "$env:CI = 'true'; "
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$shown = @(Show-WpdRunCompletion -Completion $completion -OpenOutputs 6>&1); "
        "$presentation = $shown[-1]; "
        "$lines = @($shown | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } "
        "| ForEach-Object { [string]$_.MessageData }); "
        "[pscustomobject]@{ presentation = $presentation; lines = $lines } "
        "| ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["presentation"]["status"] == "suppressed"
    assert result["presentation"]["reason"] == "ci-environment"
    printed = "\n".join(result["lines"])
    assert "Run summary: completed" in printed
    assert str(case.resolve()) in printed
    assert str((case / "report.html").resolve()) in printed
    assert "minifilter-enumeration" in printed


def test_presentation_runner_seam_overrides_ci_and_opens_only_verified_outputs(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for coverage in manifest["tiers"]["coverage"]:
        coverage["status"] = "success"
        coverage["coverage"] = "complete"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        "$env:CI = 'true'; $seen = New-Object System.Collections.ArrayList; "
        "$runner = { param($Action, $Path) [void]$seen.Add([pscustomobject]@{ action=$Action; path=$Path }); $true }.GetNewClosure(); "
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$presentation = Show-WpdRunCompletion -Completion $completion -OpenOutputs "
        "-PresentationRunner $runner 6>&1 | Select-Object -Last 1; "
        "[pscustomobject]@{ presentation=$presentation; calls=@($seen) } "
        "| ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["presentation"]["status"] == "opened"
    assert [call["action"] for call in result["calls"]] == ["open-case", "open-report"]
    assert [call["path"] for call in result["calls"]] == [
        str(case.resolve()),
        str((case / "report.html").resolve()),
    ]


def test_show_refuses_to_open_if_a_registered_file_changed_after_summary(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for coverage in manifest["tiers"]["coverage"]:
        coverage["status"] = "success"
        coverage["coverage"] = "complete"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        "$env:CI = 'true'; $seen = New-Object System.Collections.ArrayList; "
        "$runner = { param($Action, $Path) [void]$seen.Add($Action); $true }.GetNewClosure(); "
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        f"[System.IO.File]::WriteAllText({_ps_quote(case / 'findings.json')}, 'tampered'); "
        "$presentation = Show-WpdRunCompletion -Completion $completion -OpenOutputs "
        "-PresentationRunner $runner 6>&1 | Select-Object -Last 1; "
        "[pscustomobject]@{ presentation=$presentation; calls=@($seen) } "
        "| ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["presentation"]["status"] == "refused"
    assert result["presentation"]["reason"] == "completion-not-verified"
    assert result["calls"] == []


def test_failed_presentation_is_reported_without_changing_collection_success(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for coverage in manifest["tiers"]["coverage"]:
        coverage["status"] = "success"
        coverage["coverage"] = "complete"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        "$env:CI = 'true'; "
        "$runner = { param($Action, $Path) if ($Action -eq 'open-report') { throw 'controlled GUI failure' }; $true }; "
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$presentation = Show-WpdRunCompletion -Completion $completion -OpenOutputs "
        "-PresentationRunner $runner 6>&1 | Select-Object -Last 1; "
        "[pscustomobject]@{ completionStatus=$completion.status; presentation=$presentation } "
        "| ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["completionStatus"] == "completed"
    assert result["presentation"]["status"] == "failed"
    assert result["presentation"]["reason"] == "presentation-runner-failed"
    assert result["presentation"]["failures"] == ["presentation-runner-failed"]


def test_plan_descriptors_are_not_reported_as_collected_stages(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    manifest = {
        "mode": "Plan",
        "plannedActions": ["collect-search-service-context"],
        "tiers": {
            "tiers": [
                {
                    "tier": 3,
                    "name": "optional-escalation",
                    "projectedState": "not-collected",
                    "adapters": [{"id": "search-service-context", "status": "planned"}],
                }
            ],
            "coveragePlan": {"fields": ["collector", "status", "coverage"]},
        },
    }
    (case / "diagnostic-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["stages"] == []
    assert result["status"] == "failed"
    assert "report.html" in result["missingArtifacts"]


def test_missing_manifest_still_lists_caller_required_artifacts(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)} "
        "-RequiredArtifacts @('escalation/search-service-context.json'); "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "failed"
    assert "diagnostic-manifest.json" in result["missingArtifacts"]
    assert "report.html" in result["missingArtifacts"]
    assert "escalation/search-service-context.json" in result["missingArtifacts"]


def test_registered_file_without_hash_fails_as_unverifiable(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    findings = next(item for item in manifest["artifacts"] if item["Name"] == "findings.json")
    del findings["Sha256"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "failed"
    artifacts = {item["name"]: item for item in result["artifacts"]}
    assert artifacts["findings.json"]["hashCheckStatus"] == "not-registered"


def test_requested_tier3_artifacts_are_verified_and_search_partial_is_visible(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    search_content = b'{"status":"partial","data":{"service":{"name":"WSearch"},"index":null}}\n'
    search_path = case / "escalation" / "search-service-context.json"
    search_path.write_bytes(search_content)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"].append(_registered("escalation/search-service-context.json", search_content))
    manifest["tiers"]["tier3"]["status"] = "partial"
    manifest["tiers"]["tier3"]["adapters"] = [
        {"id": "search-service-context", "status": "partial", "artifact": "escalation/search-service-context.json"},
        {"id": "minifilter-enumeration", "status": "success", "artifact": "escalation/minifilter-enumeration.json"},
    ]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)} "
        "-RequiredArtifacts @('escalation/search-service-context.json', "
        "'escalation/minifilter-enumeration.json'); "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "partial"
    stages = {stage["collector"]: stage for stage in result["stages"]}
    assert stages["search-service-context"]["status"] == "partial"
    assert stages["search-service-context"]["outcome"] == "partial"
    artifacts = {item["name"]: item for item in result["artifacts"]}
    assert artifacts["escalation/search-service-context.json"]["hashCheckStatus"] == "match"
    assert artifacts["escalation/minifilter-enumeration.json"]["hashCheckStatus"] == "match"
    assert result["missingArtifacts"] == []


@pytest.mark.skipif(os.name == "nt", reason="host-gating assertion is Linux-only")
def test_open_outputs_never_launches_a_gui_on_non_windows_host(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for coverage in manifest["tiers"]["coverage"]:
        coverage["status"] = "success"
        coverage["coverage"] = "complete"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        "$env:CI = ''; "
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$presentation = Show-WpdRunCompletion -Completion $completion -OpenOutputs 6>&1 "
        "| Select-Object -Last 1; "
        "$presentation | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "suppressed"
    assert result["reason"] == "non-windows-host"


def test_plan_manifest_with_registered_outputs_fails_and_is_not_presented(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["mode"] = "Plan"
    for coverage in manifest["tiers"]["coverage"]:
        coverage["status"] = "success"
        coverage["coverage"] = "complete"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = run_pwsh_json(
        tmp_path,
        "$env:CI = 'true'; $seen = New-Object System.Collections.ArrayList; "
        "$runner = { param($Action, $Path) [void]$seen.Add($Action); $true }.GetNewClosure(); "
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$presentation = Show-WpdRunCompletion -Completion $completion -OpenOutputs "
        "-PresentationRunner $runner 6>&1 | Select-Object -Last 1; "
        "[pscustomobject]@{ completion=$completion; presentation=$presentation; calls=@($seen) } "
        "| ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["completion"]["status"] == "failed"
    assert "manifest-mode-not-collect" in result["completion"]["reasons"]
    assert result["presentation"]["status"] == "refused"
    assert result["calls"] == []


@pytest.mark.skipif(os.name == "nt", reason="Linux symlink reproduction")
@pytest.mark.parametrize(
    "unsafe_path",
    ["registered-file", "nested-directory", "report", "case-directory", "ancestor"],
)
def test_reparse_paths_fail_closed_before_presentation(tmp_path, unsafe_path):
    case = tmp_path / "real" / "case" if unsafe_path == "ancestor" else tmp_path / "case"
    _valid_case(case)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for coverage in manifest["tiers"]["coverage"]:
        coverage["status"] = "success"
        coverage["coverage"] = "complete"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    call_case = case

    if unsafe_path == "registered-file":
        outside = tmp_path / "outside-findings.json"
        outside.write_bytes((case / "findings.json").read_bytes())
        (case / "findings.json").unlink()
        (case / "findings.json").symlink_to(outside)
    elif unsafe_path == "nested-directory":
        outside = tmp_path / "outside-escalation"
        outside.mkdir()
        (outside / "minifilter-enumeration.json").write_bytes(
            (case / "escalation" / "minifilter-enumeration.json").read_bytes()
        )
        shutil.rmtree(case / "escalation")
        (case / "escalation").symlink_to(outside, target_is_directory=True)
    elif unsafe_path == "report":
        outside = tmp_path / "outside-report.html"
        outside.write_bytes((case / "report.html").read_bytes())
        (case / "report.html").unlink()
        (case / "report.html").symlink_to(outside)
    elif unsafe_path == "case-directory":
        call_case = tmp_path / "case-link"
        call_case.symlink_to(case, target_is_directory=True)
    else:
        linked_root = tmp_path / "linked-root"
        linked_root.symlink_to(case.parent, target_is_directory=True)
        call_case = linked_root / "case"

    result = run_pwsh_json(
        tmp_path,
        "$env:CI = 'true'; $seen = New-Object System.Collections.ArrayList; "
        "$runner = { param($Action, $Path) [void]$seen.Add($Action); $true }.GetNewClosure(); "
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(call_case)}; "
        "$presentation = Show-WpdRunCompletion -Completion $completion -OpenOutputs "
        "-PresentationRunner $runner 6>&1 | Select-Object -Last 1; "
        "[pscustomobject]@{ completion=$completion; presentation=$presentation; calls=@($seen) } "
        "| ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["completion"]["status"] == "failed"
    assert result["presentation"]["status"] == "refused"
    assert result["calls"] == []


def test_invalid_case_path_returns_failed_envelope_instead_of_throwing(tmp_path):
    result = run_pwsh_json(
        tmp_path,
        "$invalidPath = [string][char]0; "
        "$completion = Get-WpdRunCompletion -CaseDirectory $invalidPath; "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "failed"
    assert "case-directory-invalid-path" in result["reasons"]


@pytest.mark.skipif(os.name != "nt", reason="Windows-native symlink fixture")
def test_windows_native_symlink_artifact_fails_closed_when_available(tmp_path):
    case = tmp_path / "case"
    _valid_case(case)
    outside = tmp_path / "outside-findings.json"
    outside.write_bytes((case / "findings.json").read_bytes())
    (case / "findings.json").unlink()
    try:
        (case / "findings.json").symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"Windows symlink creation unavailable: {exc}")
    result = run_pwsh_json(
        tmp_path,
        f"$completion = Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)}; "
        "$completion | ConvertTo-Json -Depth 20 -Compress",
    )

    assert result["status"] == "failed"
