import json
import platform
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "src" / "Invoke-WindowsPerformanceDiagnostics.ps1"


def run_tool(*arguments: str) -> subprocess.CompletedProcess[str]:
    assert shutil.which("pwsh"), "pwsh is required for the Linux verification gate"
    return subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-File", str(SCRIPT), *arguments],
        capture_output=True,
        check=False,
        text=True,
    )


def test_plan_mode_writes_a_local_only_read_only_manifest(tmp_path):
    """Plan mode must work without touching Windows-only collection APIs."""
    output_directory = tmp_path / "diagnostic-plan"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert manifest["schemaVersion"] == "1.0"
    assert manifest["mode"] == "Plan"
    assert manifest["safety"]["localOnly"] is True
    assert manifest["safety"]["readOnly"] is True
    assert manifest["safety"]["requiresExplicitCollectionConsent"] is True
    assert "repair" not in manifest["plannedActions"]
    assert "registry-change" not in manifest["plannedActions"]


def test_collect_mode_refuses_to_collect_without_explicit_consent(tmp_path):
    result = run_tool("-Mode", "Collect", "-OutputDirectory", str(tmp_path / "no-consent"))

    assert result.returncode != 0
    assert "requires -ConfirmLocalCollection" in result.stderr


def test_collect_mode_refuses_non_windows_hosts_before_any_collection(tmp_path):
    if platform.system() == "Windows":
        return

    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-OutputDirectory",
        str(tmp_path / "linux-host"),
    )

    assert result.returncode != 0
    assert "supported only on Windows" in result.stderr
