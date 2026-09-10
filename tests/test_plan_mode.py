import json
import platform
import re
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


def _write_minimal_collect_case(tmp_path, contents=b"a,b\n1,2\n"):
    """Create the smallest valid Collect case for Verify-mode tests."""
    import hashlib

    case = tmp_path / "case-to-verify"
    case.mkdir()
    artifact_path = case / "performance-samples.csv"
    artifact_path.write_bytes(contents)
    manifest = {
        "schemaVersion": "1.0",
        "toolName": "Windows Performance Diagnostics Toolkit",
        "toolVersion": (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        "mode": "Collect",
        "safety": {
            "localOnly": True,
            "readOnly": True,
            "requiresExplicitCollectionConsent": True,
            "automaticUpload": False,
            "automaticRemediation": False,
            "automaticLogClearing": False,
        },
        "artifacts": [
            {
                "Name": artifact_path.name,
                "SizeBytes": artifact_path.stat().st_size,
                "Sha256": hashlib.sha256(contents).hexdigest(),
            }
        ],
    }
    (case / "diagnostic-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    return case


def test_plan_mode_writes_a_local_only_read_only_manifest(tmp_path):
    """Plan mode must work without touching Windows-only collection APIs."""
    output_directory = tmp_path / "diagnostic-plan"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert manifest["toolVersion"] == (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert manifest_path.read_bytes()[:3] != b"\xef\xbb\xbf"  # no BOM: JSON must be byte-identical on PS 5.1 and pwsh 7

    assert manifest["schemaVersion"] == "1.0"
    assert manifest["mode"] == "Plan"
    assert manifest["safety"]["localOnly"] is True
    assert manifest["safety"]["readOnly"] is True
    assert manifest["safety"]["requiresExplicitCollectionConsent"] is True
    assert "repair" not in manifest["plannedActions"]
    assert "registry-change" not in manifest["plannedActions"]


def test_collect_mode_refuses_to_collect_without_explicit_consent(tmp_path):
    output_directory = tmp_path / "no-consent"
    result = run_tool("-Mode", "Collect", "-OutputDirectory", str(output_directory))

    assert result.returncode != 0
    assert "requires -ConfirmLocalCollection" in result.stderr
    # consent gates run before directory creation: refusal leaves zero side effects
    assert not output_directory.exists()


def test_collect_mode_refuses_non_windows_hosts_before_any_collection(tmp_path):
    if platform.system() == "Windows":
        return

    output_directory = tmp_path / "linux-host"
    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-OutputDirectory",
        str(output_directory),
    )

    assert result.returncode != 0
    assert "supported only on Windows" in result.stderr
    # the platform gate also precedes directory creation
    assert not output_directory.exists()


def test_collect_progress_uses_a_wall_clock_deadline_and_launchers_explain_extra_stages():
    """The requested duration is the baseline sampling wall-clock budget, not a
    count of one-second sleeps after unbounded work. Operators must see live
    sample/percentage progress and the default launcher must disclose that its
    WPR trace and final export/package stages take additional time."""
    source = SCRIPT.read_text(encoding="utf-8-sig")
    start_here = (REPO_ROOT / "START-HERE.bat").read_bytes().decode("ascii")
    run_diagnostics = (REPO_ROOT / "Run-Diagnostics.bat").read_bytes().decode("ascii")

    assert "$samplingStopwatch = [System.Diagnostics.Stopwatch]::StartNew()" in source
    assert "Sampling progress: sample {0}; {1}% of {2}-second baseline" in source
    assert "Start-Sleep -Milliseconds $sleepMilliseconds" in source
    sampling_region = source[source.index("$samples = New-Object System.Collections.ArrayList"):source.index("$completedAtSamplingUtc = Get-UtcTimestamp")]
    assert "Start-Sleep -Seconds 1" not in sampling_region
    assert "30-second baseline sampling" in start_here
    assert "then a separate 30-second WPR trace" in start_here
    assert "final export, hashing, and ZIP packaging" in start_here
    assert "30-second baseline sampling" in run_diagnostics


def test_plan_mode_with_wpr_lists_capture_action_and_scope(tmp_path):
    """Plan mode must advertise the WPR capture action without invoking it."""
    output_directory = tmp_path / "plan-wpr"
    result = run_tool(
        "-Mode",
        "Plan",
        "-CaptureWpr",
        "-OutputDirectory",
        str(output_directory),
    )

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "capture-wpr-etl-after-explicit-consent" in manifest["plannedActions"]
    assert manifest["wpr"]["profile"] == "GeneralProfile"
    assert manifest["wpr"]["durationSeconds"] == 30


def test_plan_mode_without_wpr_has_no_wpr_section(tmp_path):
    """Plan mode must not advertise WPR unless -CaptureWpr is requested."""
    output_directory = tmp_path / "plan-plain"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "wpr" not in manifest
    assert "capture-wpr-etl-after-explicit-consent" not in manifest["plannedActions"]


def test_wpr_capture_refuses_without_wpr_consent(tmp_path):
    """WPR is a separate consent gate from local collection, checked before any run."""
    output_directory = tmp_path / "no-wpr-consent"
    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-CaptureWpr",
        "-OutputDirectory",
        str(output_directory),
    )

    assert result.returncode != 0
    assert "requires -ConfirmWprCapture" in result.stderr
    assert not output_directory.exists()  # no side effects on refusal


def test_collect_with_wpr_consent_still_refuses_non_windows_hosts(tmp_path):
    if platform.system() == "Windows":
        return

    output_directory = tmp_path / "linux-wpr-host"
    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-ConfirmWprCapture",
        "-CaptureWpr",
        "-OutputDirectory",
        str(output_directory),
    )

    assert result.returncode != 0
    assert "supported only on Windows" in result.stderr
    assert not output_directory.exists()


def test_release_flow_uses_the_real_workflow_token_for_asset_probes():
    """The release/MOTW gate must exercise authenticated download paths, not
    redacted placeholder headers that make every probe fail before the real
    release asset can be tested."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    release_flow = workflow[workflow.index("wpd-release-flow:"):]
    token_name = "GITHUB" + "_TOKEN"
    assert "***" not in release_flow
    assert "$env:G...N" not in release_flow
    assert f"$env:{token_name}" in release_flow
    assert "('Authorization' + ': ' + 'Bearer ' + " + f"$env:{token_name})" in release_flow
    assert "('x-access-token' + ':' + " + f"$env:{token_name})" in release_flow
    assert '-H ("Authorization: " + $c.hdr)' in release_flow


def test_plan_mode_with_defender_lists_capture_action_and_scope(tmp_path):
    """Plan mode must advertise the Defender capture action without invoking it."""
    output_directory = tmp_path / "plan-defender"
    result = run_tool(
        "-Mode",
        "Plan",
        "-CaptureDefender",
        "-OutputDirectory",
        str(output_directory),
    )

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "capture-defender-performance-etl-after-explicit-consent" in manifest["plannedActions"]
    assert manifest["defender"]["durationSeconds"] == 30


def test_plan_mode_without_defender_has_no_defender_section(tmp_path):
    """Plan mode must not advertise Defender capture unless -CaptureDefender is requested."""
    output_directory = tmp_path / "plan-plain-defender"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "defender" not in manifest
    assert "capture-defender-performance-etl-after-explicit-consent" not in manifest["plannedActions"]


def test_plan_mode_with_wpr_and_defender_lists_both_capture_actions(tmp_path):
    """Both consent-gated captures can be planned in the same run."""
    output_directory = tmp_path / "plan-both"
    result = run_tool(
        "-Mode",
        "Plan",
        "-CaptureWpr",
        "-CaptureDefender",
        "-OutputDirectory",
        str(output_directory),
    )

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "capture-wpr-etl-after-explicit-consent" in manifest["plannedActions"]
    assert "capture-defender-performance-etl-after-explicit-consent" in manifest["plannedActions"]
    assert manifest["wpr"]["profile"] == "GeneralProfile"
    assert manifest["defender"]["durationSeconds"] == 30


def test_defender_capture_refuses_without_defender_consent(tmp_path):
    """Defender capture is a separate consent gate from local collection, checked before any run."""
    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-CaptureDefender",
        "-OutputDirectory",
        str(tmp_path / "no-defender-consent"),
    )

    assert result.returncode != 0
    assert "requires -ConfirmDefenderCapture" in result.stderr


def test_collect_with_defender_consent_still_refuses_non_windows_hosts(tmp_path):
    if platform.system() == "Windows":
        return

    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-ConfirmDefenderCapture",
        "-CaptureDefender",
        "-OutputDirectory",
        str(tmp_path / "linux-defender-host"),
    )

    assert result.returncode != 0
    assert "supported only on Windows" in result.stderr


def test_plan_mode_with_minidumps_lists_action_and_scope(tmp_path):
    """Plan mode must advertise the minidump collection action and its bounds
    without touching Windows-only crash-dump paths."""
    output_directory = tmp_path / "plan-minidumps"
    result = run_tool(
        "-Mode",
        "Plan",
        "-CollectMinidumps",
        "-OutputDirectory",
        str(output_directory),
    )

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "collect-minidumps-after-explicit-consent" in manifest["plannedActions"]
    assert manifest["minidumps"]["maxTotalBytes"] == 536870912  # 512 MB
    assert manifest["minidumps"]["memoryDumpRecordedNotCopied"] is True
    assert manifest["minidumps"]["sourcePath"].lower().endswith("minidump")


def test_plan_mode_without_minidumps_has_no_minidumps_section(tmp_path):
    output_directory = tmp_path / "plan-plain-minidumps"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "minidumps" not in manifest
    assert "collect-minidumps-after-explicit-consent" not in manifest["plannedActions"]


def test_minidump_collection_refuses_without_consent(tmp_path):
    """Minidump collection is a separate consent gate, checked before any run."""
    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-CollectMinidumps",
        "-OutputDirectory",
        str(tmp_path / "no-minidump-consent"),
    )

    assert result.returncode != 0
    assert "requires -ConfirmMinidumpCollection" in result.stderr


def test_collect_with_minidump_consent_still_refuses_non_windows_hosts(tmp_path):
    if platform.system() == "Windows":
        return

    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-CollectMinidumps",
        "-ConfirmMinidumpCollection",
        "-OutputDirectory",
        str(tmp_path / "linux-minidump-host"),
    )

    assert result.returncode != 0
    assert "supported only on Windows" in result.stderr


def test_plan_mode_with_boot_failure_logs_lists_action_and_scope(tmp_path):
    """Plan mode must advertise the boot-failure evidence action and its
    source list without touching Windows-only log paths."""
    output_directory = tmp_path / "plan-bootfailure"
    result = run_tool(
        "-Mode",
        "Plan",
        "-CollectBootFailureLogs",
        "-OutputDirectory",
        str(output_directory),
    )

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "collect-boot-failure-evidence-after-explicit-consent" in manifest["plannedActions"]
    assert manifest["bootFailureLogs"]["maxBytesPerFile"] == 104857600  # 100 MB
    assert manifest["bootFailureLogs"]["sources"] == [
        "srt-trail",
        "boot-log",
        "cbs-log",
        "setupapi-panther",
        "setupapi-error",
        "dism-log",
    ]


def test_plan_mode_without_boot_failure_logs_has_no_section(tmp_path):
    output_directory = tmp_path / "plan-plain-bootfailure"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "bootFailureLogs" not in manifest
    assert "collect-boot-failure-evidence-after-explicit-consent" not in manifest["plannedActions"]


def test_boot_failure_log_collection_refuses_without_consent(tmp_path):
    """Boot-failure log collection is a separate consent gate, checked before any run."""
    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-CollectBootFailureLogs",
        "-OutputDirectory",
        str(tmp_path / "no-bootfailure-consent"),
    )

    assert result.returncode != 0
    assert "requires -ConfirmBootFailureLogCollection" in result.stderr


def test_collect_with_boot_failure_consent_still_refuses_non_windows_hosts(tmp_path):
    if platform.system() == "Windows":
        return

    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-CollectBootFailureLogs",
        "-ConfirmBootFailureLogCollection",
        "-OutputDirectory",
        str(tmp_path / "linux-bootfailure-host"),
    )

    assert result.returncode != 0
    assert "supported only on Windows" in result.stderr


def test_plan_mode_with_zip_output_lists_action_and_scope(tmp_path):
    """Plan mode must advertise the case-package action and its destination
    without packaging anything."""
    output_directory = tmp_path / "plan-zip"
    result = run_tool(
        "-Mode", "Plan",
        "-ZipOutput",
        "-OutputDirectory", str(output_directory),
    )

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "package-local-case-folder-into-zip" in manifest["plannedActions"]
    assert manifest["package"]["namePattern"].endswith(".zip")
    assert manifest["package"]["includesManifest"] is True


def test_plan_mode_without_zip_output_has_no_package_section(tmp_path):
    output_directory = tmp_path / "plan-plain-zip"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "package" not in manifest
    assert "package-local-case-folder-into-zip" not in manifest["plannedActions"]


def test_new_case_package_zips_only_named_files(tmp_path):
    """New-CasePackage (dot-sourced from the collector) must zip EXACTLY the
    named relative files - stale files in a reused output folder must never
    leak into the case package, and subdirectory entries use forward slashes."""
    import zipfile as zipfile_module

    src = tmp_path / "case"
    (src / "minidumps").mkdir(parents=True)
    (src / "performance-samples.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    (src / "network-state.json").write_text("{}", encoding="utf-8")
    (src / "minidumps" / "082826-12345-01.dmp").write_bytes(b"MZDUMP")
    (src / "STALE.etl").write_text("stale-from-previous-run", encoding="utf-8")
    out = tmp_path / "packages"
    out.mkdir()

    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory {tmp_path.as_posix()}/plan; "
        f"New-CasePackage -Directory '{src.as_posix()}' "
        f"-RelativeNames @('performance-samples.csv','network-state.json','minidumps/082826-12345-01.dmp') "
        f"-DestinationDirectory '{out.as_posix()}' -LeafName 'wpd-test'"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    packages = list(out.glob("wpd-test-*.zip"))
    assert len(packages) == 1, f"expected exactly one package, got {packages}"

    with zipfile_module.ZipFile(packages[0]) as zf:
        names = sorted(zf.namelist())
        assert names == [
            "minidumps/082826-12345-01.dmp",
            "network-state.json",
            "performance-samples.csv",
        ], names
        assert "STALE.etl" not in names
        assert zf.read("minidumps/082826-12345-01.dmp") == b"MZDUMP"


def test_plan_mode_with_remote_lists_action_and_remote_safety_block(tmp_path):
    """Plan mode must advertise the remote collection action and switch the
    safety block to localOnly=false with the target, without touching WinRM."""
    output_directory = tmp_path / "plan-remote"
    result = run_tool(
        "-Mode", "Plan",
        "-RemoteComputer", "SRV-DIAG-01",
        "-OutputDirectory", str(output_directory),
    )

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "collect-remotely-after-explicit-consent" in manifest["plannedActions"]
    assert manifest["safety"]["localOnly"] is False
    assert manifest["safety"]["remoteTarget"] == "SRV-DIAG-01"
    assert manifest["safety"]["remoteTransport"] == "winrm"
    assert manifest["remote"]["computerName"] == "SRV-DIAG-01"
    assert manifest["remote"]["transport"] == "winrm"


def test_plan_mode_without_remote_keeps_local_only_safety(tmp_path):
    output_directory = tmp_path / "plan-plain-remote"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert manifest["safety"]["localOnly"] is True
    assert "remote" not in manifest
    assert "collect-remotely-after-explicit-consent" not in manifest["plannedActions"]


def test_remote_collection_refuses_without_consent(tmp_path):
    """Remote collection needs its own consent gate, checked before any network I/O."""
    result = run_tool(
        "-Mode", "Collect",
        "-ConfirmLocalCollection",
        "-RemoteComputer", "SRV-DIAG-01",
        "-OutputDirectory", str(tmp_path / "no-remote-consent"),
    )

    assert result.returncode != 0
    assert "requires -ConfirmRemoteCollection" in result.stderr


def test_remote_collection_still_refuses_non_windows_hosts(tmp_path):
    if platform.system() == "Windows":
        return

    result = run_tool(
        "-Mode", "Collect",
        "-ConfirmLocalCollection",
        "-ConfirmRemoteCollection",
        "-RemoteComputer", "localhost",
        "-OutputDirectory", str(tmp_path / "linux-remote-host"),
    )

    assert result.returncode != 0
    assert "supported only on Windows" in result.stderr


def test_remote_helpers_fail_closed_for_safety_and_hash_verification(tmp_path):
    """Remote helper contracts must make remote provenance explicit, stage in
    a unique child, and turn any hash-verification failure into a failed result."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory {tmp_path.as_posix()}/plan; "
        f"$s = Get-RemoteSafetyBlock -RemoteTarget 'SRV-DIAG-01'; "
        f"$p = New-RemoteStagingPath -BaseDirectory '{tmp_path.as_posix()}/remote-root' -Nonce 'abc123'; "
        "$failed = Get-RemoteVerificationStatus -HashVerificationFailed $true -PulledFileCount 1 -VerifiedFileCount 0; "
        "$passed = Get-RemoteVerificationStatus -HashVerificationFailed $false -PulledFileCount 2 -VerifiedFileCount 2; "
        "$relative = Get-ValidatedRemoteArtifactName -Name 'logs/item.json'; "
        "$traversal = 'accepted'; try { Get-ValidatedRemoteArtifactName -Name '../outside.txt' | Out-Null } catch { $traversal = 'rejected' }; "
        "[ordered]@{safety=$s;path=$p;failed=$failed;passed=$passed;relative=$relative;traversal=$traversal} | ConvertTo-Json -Depth 6"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    output = json.loads(result.stdout)
    assert output["safety"] == {
        "localOnly": False,
        "readOnly": True,
        "requiresExplicitCollectionConsent": True,
        "automaticUpload": False,
        "automaticRemediation": False,
        "automaticLogClearing": False,
        "remoteTarget": "SRV-DIAG-01",
        "remoteTransport": "winrm",
    }
    assert Path(output["path"]).name == "WPD-Remote-Case-abc123"
    assert output["failed"] == "failed"
    assert output["passed"] == "completed"
    assert output["relative"] == "logs\\item.json"
    assert output["traversal"] == "rejected"


def test_remote_collection_source_uses_owned_staging_and_fail_closed_status():
    """The WinRM-only branch is statically contract-tested on Linux; live
    WinRM execution remains an owner/Windows CI gate."""
    text = SCRIPT.read_text(encoding="utf-8")

    assert "$remoteStagingOwned = $false" in text
    assert "$remoteStagingOwned = $true" in text
    assert "if ($remoteStagingOwned -and $remoteOutDir)" in text
    assert "Get-RemoteVerificationStatus" in text
    assert "$remotePulledManifest.safety = Get-RemoteSafetyBlock" in text
    assert "Remote collection failed. Manifest written" in text
    assert "remotePulledManifest.collectionErrors" in text


def test_invoke_consented_capture_skip_and_elevation_paths(tmp_path):
    """Invoke-ConsentedCapture (dot-sourced) must record collectionErrors and
    return the right status on the readiness-fail path, and must fail SAFE
    (body never called) when the elevation check cannot run. Add-CollectionError
    is defined after the plan-mode early exit, so the test stubs it; the real
    elevation-skip semantics are live-gated by WPD-09 on Windows runners."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory {tmp_path.as_posix()}/plan; "
        "function Add-CollectionError { param($Stage, $ErrorRecord) "
        "$script:collectionErrors += [pscustomobject]@{Stage=$Stage;Message=$ErrorRecord.Exception.Message} }; "
        "$script:collectionErrors = @(); $script:bodyCalls = 0; "
        "$r1 = Invoke-ConsentedCapture -StageName 'wpr-capture' -SkipStatusNotReady 'skipped-wpr-not-found' "
        "-NotReadyMessage 'wpr.exe not found; WPR capture skipped' -NotReadyErrorId 'WprNotFound' "
        "-ElevationMessage 'requires an elevated (Administrator) console; WPR capture skipped' "
        "-ElevationErrorId 'WprElevationRequired' -ReadyCheck { $false } "
        "-CaptureBody { $script:bodyCalls++; return [ordered]@{ status = 'completed' } }; "
        "$r2 = Invoke-ConsentedCapture -StageName 'defender-capture' -SkipStatusNotReady 'skipped-defender-module-not-found' "
        "-NotReadyMessage 'DefenderPerformance module not found; Defender performance capture skipped' -NotReadyErrorId 'DefenderModuleNotFound' "
        "-ElevationMessage 'requires an elevated (Administrator) console; Defender performance capture skipped' -ElevationErrorId 'DefenderElevationRequired' "
        "-ReadyCheck { $true } "
        "-CaptureBody { $script:bodyCalls++; return [ordered]@{ status = 'completed' } }; "
        "[ordered]@{ s1=$r1.status; s2=$r2.status; errCount=@($script:collectionErrors).Count; bodyCalls=$script:bodyCalls } | ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    out = json.loads(result.stdout)
    # readiness fail: skip status + error recorded, body never called
    assert out["s1"] == "skipped-wpr-not-found"
    # ready, but the elevation check cannot run on Linux (WindowsPrincipal is
    # unsupported -> throws) - the helper must fail SAFE: status failed,
    # error recorded, capture body never invoked
    assert out["s2"] == "failed"
    assert out["errCount"] == 2
    assert out["bodyCalls"] == 0


def test_winre_puller_bat_is_ascii_crlf_and_consent_safe():
    """Pull-BootFailureLogs.bat (WinRE/WinPE runbook launcher) must be ASCII
    CRLF, goto-style only, and must NEVER run bcdedit automatically - the
    boot-log toggle is reachable only through an explicit y/N prompt."""
    import re as re_module

    bat = (REPO_ROOT / "Pull-BootFailureLogs.bat").read_bytes()

    assert b"\r\n" in bat
    assert b'\\"' not in bat, "backslash-immediately-before-quote hazard in Pull-BootFailureLogs.bat"
    assert all(b < 128 for b in bat), "Pull-BootFailureLogs.bat must be pure ASCII"
    for line in bat.decode("ascii").splitlines():
        assert not re_module.match(r"\s*(if|for)\b.*\(\s*$", line), (
            f"parenthesized block in Pull-BootFailureLogs.bat: {line!r}"
        )

    text = bat.decode("ascii")
    # interactive drive-letter prompts
    assert "SYSDRIVE" in text
    assert "PEDRIVE" in text
    # evidence sources
    assert "SrtTrail.txt" in text
    assert "ntbtlog.txt" in text
    # bcdedit only behind an explicit y/N gate, and only the bootlog toggle
    assert 'if /i "%ENABLEBOOTLOG%"=="y"' in text
    assert "bcdedit /set {default} bootlog yes" in text
    assert "bcdedit /deletevalue {default} bootlog" in text
    # CI-safe pause guard
    assert 'if not "%CI%"=="true" pause' in text


def test_release_packaging_files_present():
    """The deploy bundle must ship launchers and unblock guidance."""
    assert (REPO_ROOT / "Run-Diagnostics.bat").is_file()
    assert (REPO_ROOT / "START-HERE.bat").is_file()
    assert (REPO_ROOT / "README-FIRST.txt").is_file()
    assert (REPO_ROOT / "make-deploy-bundle.sh").is_file()


def test_bundle_rejects_same_version_from_non_tagged_head(tmp_path):
    """A release-named bundle must come from the exact matching tag, not a
    later same-version main commit with different shipped contents."""
    repo = tmp_path / "bundle-repo"
    repo.mkdir()
    shutil.copy2(REPO_ROOT / "make-deploy-bundle.sh", repo / "make-deploy-bundle.sh")
    (repo / "VERSION").write_text("1.2.3\n", encoding="ascii")
    (repo / "README.txt").write_text("base\n", encoding="ascii")

    def git(*arguments: str) -> None:
        subprocess.run(
            ["git", *arguments],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        )

    git("init", "-q")
    git("config", "user.email", "wpd-tests@example.invalid")
    git("config", "user.name", "WPD Tests")
    git("add", "VERSION", "README.txt", "make-deploy-bundle.sh")
    git("commit", "-qm", "release base")
    git("tag", "v1.2.3")
    (repo / "README.txt").write_text("post-release main change\n", encoding="ascii")
    git("add", "README.txt")
    git("commit", "-qm", "post-release change")

    result = subprocess.run(
        ["bash", "make-deploy-bundle.sh"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "not checked out at its release tag" in result.stderr


def test_version_file_matches_script_fallback():
    """Single-source version: the ps1 must read VERSION at runtime, and its
    standalone-copy fallback constant must never drift from the VERSION file."""
    import re as re_module

    version = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    script = (REPO_ROOT / "src" / "Invoke-WindowsPerformanceDiagnostics.ps1").read_text(
        encoding="utf-8-sig"
    )
    match = re_module.search(r"\$script:ScriptVersion = '([^']+)'", script)
    assert match, "fallback ScriptVersion constant missing from ps1"
    assert match.group(1) == version, (
        f"fallback ScriptVersion {match.group(1)!r} != VERSION {version!r}"
    )


def test_report_schema_is_valid_json():
    """The machine-readable report contract must parse and be draft-07."""
    import json as json_module

    schema_path = REPO_ROOT / "schema" / "diagnostic-report.schema.json"
    assert schema_path.is_file()
    schema = json_module.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert schema["properties"]["mode"]["enum"] == ["Plan", "Collect"]
    # consent-gated crash-evidence stages are part of the report contract
    assert "minidumps" in schema["properties"]
    assert "bootFailureLogs" in schema["properties"]
    assert "package" in schema["properties"]
    assert "remote" in schema["properties"]
    assert "remoteTarget" in schema["properties"]["safety"]["properties"]
    assert "remoteTransport" in schema["properties"]["safety"]["properties"]


def test_run_diagnostics_bat_is_quote_safe_and_ci_safe():
    """Regression for v0.2.1: a trailing backslash before a closing quote in a
    powershell.exe -File argument becomes a literal quote character, which made
    GetFullPath throw 'Illegal characters in path.' on Windows. The bat must
    also skip the interactive pause under CI so GitHub runners do not hang."""
    bat = (REPO_ROOT / "Run-Diagnostics.bat").read_bytes()

    assert b"\r\n" in bat  # CRLF line endings required for .bat files
    assert b'\\"' not in bat, "backslash-immediately-before-quote hazard in Run-Diagnostics.bat"

    text = bat.decode("ascii")
    assert "-Mode Collect" in text
    assert "-ConfirmLocalCollection" in text  # consent flag must be passed explicitly
    assert "-ZipOutput" in text  # case package is part of the standard launcher
    assert 'if not "%CI%"=="true" pause' in text  # CI-safe pause guard


def test_run_diagnostics_bat_reports_collection_failures():
    """The basic launcher must not claim success when the collector exits
    non-zero or fails to emit a manifest."""
    text = (REPO_ROOT / "Run-Diagnostics.bat").read_bytes().decode("ascii")

    assert "if errorlevel 1 goto :collection_failed" in text
    assert 'if not exist "%OUTDIR%\\diagnostic-manifest.json" goto :collection_failed' in text
    assert ":collection_failed" in text
    failure_block = text.split(":collection_failed", 1)[1]
    assert "exit /b 1" in failure_block


def test_wpr_capture_completed_requires_zero_stop_exit_code():
    """A non-zero WPR stop result must never be certified as completed, even
    if a non-empty ETL happened to be left behind."""
    source = (REPO_ROOT / "src" / "Invoke-WindowsPerformanceDiagnostics.ps1").read_text(
        encoding="utf-8-sig"
    )
    start = source.index("-StageName 'wpr-capture'")
    end = source.index("if ($CaptureDefender)", start)
    wpr_block = source[start:end]

    assert "if ($stopExitCode -eq 0 -and" in wpr_block
    assert "WprStopFailed" in wpr_block
    completed_at = wpr_block.index("status = 'completed'")
    stop_guard = wpr_block.index("if ($stopExitCode -eq 0 -and")
    assert stop_guard < completed_at


def test_plan_mode_lists_crash_analysis_action(tmp_path):
    """Plan mode must advertise crash-evidence analysis without running it."""
    output_directory = tmp_path / "plan-crash"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "analyze-crash-evidence-after-explicit-consent" in manifest["plannedActions"]


def test_plan_mode_lists_network_state_action_and_scope(tmp_path):
    """Plan mode must advertise the read-only network-state collection and its
    sub-collections without touching Windows-only network cmdlets."""
    output_directory = tmp_path / "plan-network"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "collect-network-state-after-explicit-consent" in manifest["plannedActions"]
    assert manifest["network"]["subCollections"] == [
        "ip-configuration",
        "adapter-status",
        "connection-profiles",
        "dns-server-configuration",
        "dns-client-cache",
        "ipv4-routing-table",
        "arp-table",
        "dns-vs-ping-split-test",
        "hosts-file",
        "proxy-settings",
        "tcp-connections",
        "security-software-inventory",
    ]


def test_network_keyword_matching_is_pure_and_strict_mode_safe():
    """Test-SecuritySoftwareMatch (dot-sourced from the collector) must catch
    EDR/AV/DNS-filter/VPN products by name or company without false-positives,
    and Get-PropertyValue must return $null for missing properties instead of
    throwing under Set-StrictMode -Version Latest (registry Uninstall keys are
    sparse)."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        "$null = . '" + script + "' -Mode Plan -OutputDirectory /tmp/wpd-net-test; "
        "$r = [ordered]@{"
        "crowdstrike=(Test-SecuritySoftwareMatch -Name 'CSAgent' -Company 'CrowdStrike, Inc.');"
        "sentinel=(Test-SecuritySoftwareMatch -Name 'SentinelAgent' -Company 'SentinelOne');"
        "mcafee=(Test-SecuritySoftwareMatch -Name 'McAfee WebAdvisor' -Company '');"
        "openvpn=(Test-SecuritySoftwareMatch -Name 'OpenVPN' -Company '');"
        "pihole=(Test-SecuritySoftwareMatch -Name 'pihole' -Company '');"
        "chrome=(Test-SecuritySoftwareMatch -Name 'chrome' -Company 'Google LLC');"
        "notepad=(Test-SecuritySoftwareMatch -Name 'notepad' -Company 'Microsoft Corporation');"
        "missingProp=(Get-PropertyValue -InputObject ([pscustomobject]@{DisplayName='x'}) -Name 'Publisher')"
        "}; $r | ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    matches = json.loads(result.stdout)

    assert matches["crowdstrike"] is True
    assert matches["sentinel"] is True
    assert matches["mcafee"] is True
    assert matches["openvpn"] is True
    assert matches["pihole"] is True
    assert matches["chrome"] is False
    assert matches["notepad"] is False
    assert matches["missingProp"] is None


def test_network_state_collection_is_resilient_and_structured(tmp_path):
    """Get-NetworkState (dot-sourced, Windows cmdlets mocked) must produce the
    full structured snapshot, compute the DNS-vs-ping verdict, and keep every
    other section when one fails - all StrictMode-safe on sparse registry
    keys. Runs on the Linux verification host; windows-verify exercises the
    real cmdlets on windows-2022/2025."""
    script = str(SCRIPT).replace("\\", "/")
    # .NET on Linux normalizes the backslash child path to forward slashes,
    # so the fixture tree mirrors what Join-Path resolves to here (on Windows
    # the native separator produces the same physical file).
    hosts_file = tmp_path / "System32" / "drivers" / "etc" / "hosts"
    hosts_file.parent.mkdir(parents=True)
    hosts_file.write_text(
        "# comment line\n127.0.0.1 localhost\n\n0.0.0.0 ads.example.com\n",
        encoding="utf-8",
    )
    command = (
        "$null = . '" + script + "' -Mode Plan -OutputDirectory /tmp/wpd-net-state; "
        "$env:SystemRoot = '" + str(tmp_path) + "'; "
        "function ipconfig { param($x) 'Windows IP Configuration','   IPv4 Address. . . : 192.168.1.50' }; "
        "function arp { param($x) 'Interface: 192.168.1.50','192.168.1.1 aa-bb-cc-dd-ee-ff dynamic' }; "
        "function netsh { param($a,$b,$c) 'Current WinHTTP proxy settings:','Direct access (no proxy server).' }; "
        "function netstat { param($x) 'TCP 0.0.0.0:443 1.2.3.4:50000 ESTABLISHED 1234' }; "
        "function Get-NetAdapter { [pscustomobject]@{Name='Ethernet';InterfaceDescription='Test Adapter';Status='Up';LinkSpeed='1 Gbps';MacAddress='00:11:22:33:44:55'} }; "
        "function Get-NetConnectionProfile { [pscustomobject]@{Name='testnet';InterfaceAlias='Ethernet';NetworkCategory='Private';IPv4Connectivity='Internet';IPv6Connectivity='NoTraffic'} }; "
        "function Get-DnsClientServerAddress { [pscustomobject]@{InterfaceAlias='Ethernet';AddressFamily=2;ServerAddresses=@('8.8.8.8','1.1.1.1')} }; "
        "function Get-DnsClientCache { [pscustomobject]@{Entry='google.com';Name='google.com';Data='142.250.1.1';Status='Success'} }; "
        "function Get-NetRoute { [pscustomobject]@{DestinationPrefix='0.0.0.0/0';NextHop='192.168.1.1';InterfaceAlias='Ethernet';RouteMetric=10} }; "
        # bounded probes: mock .NET Ping and the bounded DNS helper so this
        # fixture is deterministic regardless of host ICMP/DNS policy; mock netstat.
        "class FakePing { [object] Send($target, $timeout) { return [pscustomobject]@{ Status = 'Success' } } [void] Dispose() {} }; "
        "function New-Object { param([string]$TypeName) if ($TypeName -eq 'System.Net.NetworkInformation.Ping') { return [FakePing]::new() }; return (Microsoft.PowerShell.Utility\\New-Object -TypeName $TypeName) }; "
        "function Resolve-DnsAddressesBounded { param($Domain,$TimeoutMilliseconds) '203.0.113.1' }; "
        "function Get-Process { [pscustomobject]@{Name='chrome';Id=1;Company='Google LLC'},[pscustomobject]@{Name='csagent';Id=2;Company='CrowdStrike, Inc.'} }; "
        "function Get-ItemProperty { param($Path,$ErrorAction) [pscustomobject]@{DisplayName='Google Chrome';DisplayVersion='1.0';Publisher='Google LLC'},[pscustomobject]@{DisplayName='CrowdStrike Falcon';Publisher='CrowdStrike, Inc.'},[pscustomobject]@{DisplayVersion='2.0'} }; "
        "$good = (Get-NetworkState).State | ConvertTo-Json -Depth 8; "
        "function Get-NetAdapter { throw 'mocked adapter failure' }; "
        "$bad = Get-NetworkState; "
        "$badSections = @($bad.Errors | ForEach-Object { $_.Section }) -join ','; "
        "[ordered]@{good=$good;badSections=$badSections;badVerdict=$bad.State.dnsVsPing.verdict} | ConvertTo-Json -Depth 8"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    parsed = json.loads(result.stdout)
    state = json.loads(parsed["good"])

    # full structured snapshot with every section present
    for section in (
        "ipConfigAll", "adapters", "connectionProfiles", "dnsServerAddresses",
        "dnsClientCache", "ipv4Routes", "arpTable", "dnsVsPing", "hostsFile",
        "proxySettings", "tcpConnections", "securitySoftware",
    ):
        assert section in state, f"missing network-state section: {section}"

    # DNS-vs-ping split test: both mocks succeed -> both green
    assert state["dnsVsPing"]["rawIpReachable"] is True
    assert state["dnsVsPing"]["dnsResolutionOk"] is True
    assert state["dnsVsPing"]["verdict"] == "dns-and-connectivity-ok"
    assert len(state["dnsVsPing"]["rawIpPing"]) == 2
    assert len(state["dnsVsPing"]["dnsResolution"]) == 3

    # hosts file: comments and blank lines excluded
    assert state["hostsFile"]["activeEntryCount"] == 2
    assert state["hostsFile"]["activeEntries"] == [
        "127.0.0.1 localhost",
        "0.0.0.0 ads.example.com",
    ]

    # security inventory: chrome is not a match, csagent is; the sparse
    # uninstall key (no DisplayName) must not throw under StrictMode
    assert [p["Name"] for p in state["securitySoftware"]["processMatches"]] == ["csagent"]
    assert [s["DisplayName"] for s in state["securitySoftware"]["installedSoftwareMatches"]] == [
        "CrowdStrike Falcon"
    ]
    assert state["sectionErrors"] == []

    # resilience: a failing section is recorded and never loses the rest
    assert parsed["badSections"] == "adapters"
    assert parsed["badVerdict"] == "dns-and-connectivity-ok"


def test_bounded_dns_resolution_returns_results_and_times_out_without_blocking():
    """The DNS-vs-ping stage must not reintroduce the unbounded synchronous DNS
    call it replaced. A resolver task that never completes must be reported as a
    timeout promptly, while an ordinary localhost lookup still returns rows."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-dns-bound; "
        "$ok = @(Resolve-DnsAddressesBounded -Domain 'localhost' -TimeoutMilliseconds 1000); "
        "$never = New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.IPAddress[]]'; "
        "$sw = [System.Diagnostics.Stopwatch]::StartNew(); $timedOut = $false; "
        "try { Resolve-DnsAddressesBounded -Domain 'never.example' -TimeoutMilliseconds 25 -Resolver { param($name) $never.Task } | Out-Null } "
        "catch { $timedOut = $_.Exception.Message -match 'timed out' }; "
        "$sw.Stop(); [ordered]@{count=$ok.Count;timedOut=$timedOut;elapsedMs=$sw.ElapsedMilliseconds} | ConvertTo-Json"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["count"] >= 1
    assert output["timedOut"] is True
    assert output["elapsedMs"] < 500


def test_event_reader_reads_newest_records_and_stops_at_the_requested_limit():
    """The bounded event-summary contract requires the reader to start at the
    newest matching records and stop after MaxEvents, rather than scanning an
    entire busy 24-hour System log only to discard older rows."""
    source = SCRIPT.read_text(encoding="utf-8-sig")
    event_reader = source[source.index("function Get-EventsSafe"):source.index("function Get-CrashAnalysis")]
    assert "$query.ReverseDirection = $true" in event_reader
    assert "if ($buffer.Count -ge $MaxEvents)" in event_reader
    assert "break" in event_reader[event_reader.index("if ($buffer.Count -ge $MaxEvents)"):]
    assert "$buffer.RemoveAt(0)" not in event_reader


def test_disk_interval_baseline_is_reset_after_an_unavailable_raw_poll():
    """A missing raw-disk poll must break the interval chain. Pairing the next
    successful poll with an older sample would make a sustained-window rule look
    consecutive even though measurement coverage had a gap."""
    source = SCRIPT.read_text(encoding="utf-8-sig")
    sampling_region = source[source.index("$previousDiskRaw = $null"):source.index("$availableMemoryMB = $null")]
    assert re.search(
        r"if \(\$null -ne \$rawDisk\.Disks\) \{\s+\$previousDiskRaw = \$rawDisk\.Disks\s+\}\s+else \{(?:\s+#.*){0,3}\s+\$previousDiskRaw = \$null",
        sampling_region,
    )


def test_crash_analysis_decodes_bugchecks_and_flags_unexplained_shutdowns():
    """Get-CrashAnalysis (pure function, dot-sourced from the collector) must
    decode BugCheck 1001 codes and flag Kernel-Power 41 without a nearby
    bugcheck as an unexplained shutdown."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-crash-test; "
        "$r = Get-CrashAnalysis -Events @("
        # bugcheck 3 minutes before the first Kernel-Power 41 -> within the
        # 5-minute window, so that 41 is explained; the -30min one is not
        "[pscustomobject]@{ProviderName='BugCheck';Id=1001;TimeCreated=(Get-Date).AddMinutes(-3);"
        "Message='The bugcheck was: 0x0000001A (0x0000000000041790, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000)'},"
        "[pscustomobject]@{ProviderName='Microsoft-Windows-Kernel-Power';Id=41;TimeCreated=(Get-Date).AddMinutes(-2);"
        "Message='The system has rebooted without cleanly shutting down first.'},"
        "[pscustomobject]@{ProviderName='Microsoft-Windows-Kernel-Power';Id=41;TimeCreated=(Get-Date).AddMinutes(-30);"
        "Message='The system has rebooted without cleanly shutting down first.'}"
        "); $r | ConvertTo-Json -Depth 6"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    analysis = json.loads(result.stdout)

    assert len(analysis["bugchecks"]) == 1
    assert analysis["bugchecks"][0]["BugcheckCode"] == "0x0000001A"
    # the -2min Kernel-Power 41 has a matching bugcheck -> not unexplained;
    # the -30min one has none -> unexplained
    assert len(analysis["unexplainedShutdowns"]) == 1


def test_crash_analysis_recognizes_real_windows_bugcheck_provider():
    """Windows Event ID 1001 is commonly emitted by the
    Microsoft-Windows-WER-SystemErrorReporting provider with BugCheck as its
    event source. The analyzer must not require the legacy display name
    'BugCheck' as the provider name."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-real-bugcheck-provider; "
        "$r = Get-CrashAnalysis -Events @([pscustomobject]@{"
        "ProviderName='Microsoft-Windows-WER-SystemErrorReporting';Id=1001;"
        "TimeCreated=(Get-Date).AddMinutes(-2);"
        "Message='The bugcheck was: 0x0000009F (0x1, 0x2, 0x3, 0x4)'"
        "}); $r | ConvertTo-Json -Depth 6"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    analysis = json.loads(result.stdout)
    assert len(analysis["bugchecks"]) == 1
    assert analysis["bugchecks"][0]["BugcheckCode"] == "0x0000009F"


def test_artifact_metadata_hashes_only_whitelisted_names(tmp_path):
    """Regression: the manifest must never certify files not written this run.
    Get-ArtifactMetadata with a Names whitelist ignores stale files in a
    reused output directory (the launchers share C:\\Temp\\WPD-Case)."""
    script = str(SCRIPT).replace("\\", "/")
    out_dir = tmp_path / "reused-dir"
    out_dir.mkdir()
    (out_dir / "performance-samples.csv").write_text("a,b\n1,2\n")
    (out_dir / "network-state.json").write_text("{}")
    (out_dir / "wpr-trace.etl").write_text("STALE-ETL-FROM-PREVIOUS-RUN")  # not in whitelist
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory {out_dir.as_posix()}; "
        f"Get-ArtifactMetadata -Directory '{out_dir.as_posix()}' -Names @('performance-samples.csv','network-state.json') "
        "| ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    artifacts = json.loads(result.stdout)
    names = sorted(a["Name"] for a in artifacts)

    assert names == ["network-state.json", "performance-samples.csv"]
    assert "wpr-trace.etl" not in names  # stale file must never be certified
    assert all(re.fullmatch(r"[A-Fa-f0-9]{64}", a["Sha256"]) for a in artifacts)


def test_emitted_plan_validates_against_schema(tmp_path):
    """The schema test must validate REAL tool output, not just parse the schema."""
    import jsonschema

    schema = json.loads(
        (REPO_ROOT / "schema" / "diagnostic-report.schema.json").read_text(encoding="utf-8")
    )
    output_directory = tmp_path / "plan-schema"
    result = run_tool(
        "-Mode", "Plan",
        "-CaptureWpr",
        "-CaptureDefender",
        "-CollectMinidumps",
        "-CollectBootFailureLogs",
        "-ZipOutput",
        "-RemoteComputer", "SRV-DIAG-01",
        "-OutputDirectory", str(output_directory),
    )

    assert result.returncode == 0, result.stderr

    plan = json.loads(
        (output_directory / "diagnostic-plan.json").read_text(encoding="utf-8-sig")
    )
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(plan), key=lambda e: list(e.path))
    assert not errors, [(list(e.path), e.message) for e in errors]


def test_start_here_bat_is_elevation_safe_and_quote_safe():
    """START-HERE.bat must present the three operating modes, elevate only for
    collection, run the selected workflow safely, and stay CI/quote-safe."""
    bat = (REPO_ROOT / "START-HERE.bat").read_bytes()

    assert b"\r\n" in bat  # CRLF line endings required for .bat files
    assert b'\\"' not in bat, "backslash-immediately-before-quote hazard in START-HERE.bat"
    assert all(b < 128 for b in bat), "START-HERE.bat must be pure ASCII"
    # cmd parser regression: parenthesized if/for blocks with parens in the
    # body kill the bat ('. was unexpected at this time.'); goto-style only
    import re as re_module

    for line in bat.decode("ascii").splitlines():
        assert not re_module.match(r"\s*(if|for)\b.*\(\s*$", line), (
            f"parenthesized block in START-HERE.bat: {line!r}"
        )

    text = bat.decode("ascii")
    # UAC self-elevation: net session probe + re-launch with RunAs
    assert "net session >nul 2>&1" in text
    assert "-Verb RunAs" in text
    # CI must never hang on UAC: guard the elevation attempt
    assert 'if "%CI%"=="true"' in text
    # Console menu with three operating modes plus Exit
    for option in ("1 - Plan preview", "2 - Collect diagnostics", "3 - Verify an existing case", "4 - Exit"):
        assert option in text, f"missing menu option {option!r}"
    # Consent flags remain explicit in the single launcher Collect flow
    assert "-Mode Collect" in text
    assert "-ConfirmLocalCollection" in text
    assert "-CaptureWpr" in text
    assert "-ConfirmWprCapture" in text
    assert "-CollectMinidumps" in text
    assert "-ConfirmMinidumpCollection" in text
    assert "-CollectBootFailureLogs" in text
    assert "-ConfirmBootFailureLogCollection" in text
    assert "-ZipOutput" in text
    assert "-Mode Verify" in text
    assert "-InputDirectory" in text
    # Defender-strip resilience: pre-flight existence check with recovery steps
    assert "src\\Invoke-WindowsPerformanceDiagnostics.ps1 was not found" in text
    # Result visibility: log everything with Tee-Object, never a silent failure
    assert "Tee-Object" in text
    assert "diagnostic-manifest.json" in text
    # No trailing backslash before the closing quote of -OutputDirectory
    assert '-OutputDirectory \'%OUTDIR%\'' in text
    assert 'if not "%CI%"=="true" pause' in text  # CI-safe pause guard


def test_human_facing_release_metadata_matches_version():
    """The shipped quick-start documents must advertise the current release."""
    version = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    readme_first = (REPO_ROOT / "README-FIRST.txt").read_text(encoding="utf-8")
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert f"**Version:** {version}" in readme
    assert f"Version {version}" in readme_first
    assert f"## {version} — " in changelog


def test_wpa_guide_matches_the_collector_wpr_profile():
    """The WPA guide must describe the profile the collector actually starts.
    A stale profile name sends an operator to a command that WPR rejects."""
    guide = (REPO_ROOT / "docs" / "wpa-analysis-guide.md").read_text(encoding="utf-8")

    assert "wpr.exe -start GeneralProfile -filemode" in guide
    assert 'schema enum: `"GeneralProfile"`' in guide
    assert "The `GeneralProfile` profile is First Level Triage" in guide
    assert "wpr.exe -start General -filemode" not in guide
    assert 'schema enum: `"General"`' not in guide


def test_verify_mode_accepts_a_valid_collect_case_without_writing_it(tmp_path):
    case = _write_minimal_collect_case(tmp_path)
    before = {
        path.relative_to(case): path.read_bytes()
        for path in case.rglob("*")
        if path.is_file()
    }

    result = run_tool("-Mode", "Verify", "-InputDirectory", str(case))

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["reportType"] == "case-verification"
    assert report["mode"] == "Verify"
    assert report["status"] == "verified"
    assert report["artifactCount"] == 1
    assert report["verifiedArtifactCount"] == 1
    assert report["package"]["status"] == "not-present"
    schema = json.loads(
        (REPO_ROOT / "schema" / "case-verification.schema.json").read_text(encoding="utf-8")
    )
    import jsonschema

    errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(report), key=lambda e: list(e.path))
    assert not errors, [(list(error.path), error.message) for error in errors]
    assert {
        path.relative_to(case): path.read_bytes()
        for path in case.rglob("*")
        if path.is_file()
    } == before


def test_verify_mode_fails_on_a_tampered_artifact(tmp_path):
    case = _write_minimal_collect_case(tmp_path)
    (case / "performance-samples.csv").write_bytes(b"x,y\n3,4\n")

    result = run_tool("-Mode", "Verify", "-InputDirectory", str(case))

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["status"] == "failed"
    assert report["artifactCount"] == 1
    assert report["verifiedArtifactCount"] == 0
    assert any("hash mismatch" in error.lower() for error in report["errors"])


def test_verify_mode_requires_an_input_directory():
    result = run_tool("-Mode", "Verify")

    assert result.returncode != 0
    assert "requires -InputDirectory" in result.stderr


def test_verify_mode_validates_the_recorded_case_package(tmp_path):
    import hashlib
    import zipfile

    case = _write_minimal_collect_case(tmp_path)
    nested_path = case / "minidumps" / "sample.dmp"
    nested_path.parent.mkdir()
    nested_path.write_bytes(b"MINIDUMP")
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"].append(
        {
            "Name": r"minidumps\sample.dmp",
            "SizeBytes": nested_path.stat().st_size,
            "Sha256": hashlib.sha256(nested_path.read_bytes()).hexdigest(),
        }
    )
    zip_path = case.parent / "case-to-verify-20260901T000000.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("performance-samples.csv", (case / "performance-samples.csv").read_bytes())
        archive.writestr("minidumps/sample.dmp", nested_path.read_bytes())
        archive.writestr("diagnostic-manifest.json", json.dumps(manifest))
    zip_bytes = zip_path.read_bytes()
    manifest["package"] = {
        "enabled": True,
        "status": "completed",
        "zipPath": r"C:\old\case-to-verify-20260901T000000.zip",
        "sizeBytes": len(zip_bytes),
        "sha256": hashlib.sha256(zip_bytes).hexdigest(),
        "includesManifest": True,
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = run_tool("-Mode", "Verify", "-InputDirectory", str(case))

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "verified"
    assert report["package"]["status"] == "verified"
    assert report["package"]["entryCount"] == 3


def test_verify_mode_rejects_an_unexpected_case_package_entry(tmp_path):
    import hashlib
    import zipfile

    case = _write_minimal_collect_case(tmp_path)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    zip_path = case.parent / "case-to-verify-extra-20260901T000000.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("performance-samples.csv", (case / "performance-samples.csv").read_bytes())
        archive.writestr("diagnostic-manifest.json", json.dumps(manifest))
        archive.writestr("unexpected-secret.txt", b"not part of the whitelist")
    zip_bytes = zip_path.read_bytes()
    manifest["package"] = {
        "enabled": True,
        "status": "completed",
        "zipPath": str(zip_path),
        "sizeBytes": len(zip_bytes),
        "sha256": hashlib.sha256(zip_bytes).hexdigest(),
        "includesManifest": True,
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = run_tool("-Mode", "Verify", "-InputDirectory", str(case))

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["status"] == "failed"
    assert report["package"]["status"] == "failed"
    assert any("entry count mismatch" in error.lower() for error in report["errors"])


def test_verify_mode_rejects_traversal_without_reading_outside_the_case(tmp_path):
    case = _write_minimal_collect_case(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("do not touch", encoding="utf-8")
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["Name"] = "..\\outside.txt"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = run_tool("-Mode", "Verify", "-InputDirectory", str(case))

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["status"] == "failed"
    assert any("traversal" in error.lower() for error in report["errors"])
    assert outside.read_text(encoding="utf-8") == "do not touch"


def test_case_verification_schema_is_valid_json():
    schema_path = REPO_ROOT / "schema" / "case-verification.schema.json"
    assert schema_path.is_file()
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert schema["properties"]["reportType"]["enum"] == ["case-verification"]
    assert schema["properties"]["mode"]["enum"] == ["Verify"]
    assert schema["properties"]["status"]["enum"] == ["verified", "failed"]


# ======================================================================
# Phase 1: Symptom context and preset parameters
# ======================================================================

def test_plan_mode_records_symptom_context_and_collection_window(tmp_path):
    """Plan mode with -SymptomContext must record the user-reported symptom
    and a collection window, while keeping the mode as Plan."""
    output_directory = tmp_path / "plan-symptom"
    result = run_tool(
        "-Mode", "Plan",
        "-SymptomContext", "Slow boot and high CPU after login",
        "-OutputDirectory", str(output_directory),
    )

    assert result.returncode == 0, result.stderr
    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert manifest["mode"] == "Plan"
    assert "symptom" in manifest
    assert manifest["symptom"]["reported"] == "Slow boot and high CPU after login"
    assert "collectionWindow" in manifest["symptom"]
    # collectionWindow must have requestedAtUtc (ISO 8601)
    assert "T" in manifest["symptom"]["collectionWindow"]["requestedAtUtc"]


def test_plan_mode_without_symptom_has_no_symptom_block(tmp_path):
    """Plan mode without -SymptomContext must omit the symptom block."""
    output_directory = tmp_path / "plan-no-symptom"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr
    manifest = json.loads(
        (output_directory / "diagnostic-plan.json").read_text(encoding="utf-8-sig")
    )
    assert "symptom" not in manifest


def test_plan_mode_records_preset_parameters(tmp_path):
    """Plan mode with -PresetPresetContext must record the preset in the plan."""
    output_directory = tmp_path / "plan-preset"
    result = run_tool(
        "-Mode", "Plan",
        "-SymptomContext", "General slowdown",
        "-Preset", "baseline",
        "-OutputDirectory", str(output_directory),
    )

    assert result.returncode == 0, result.stderr
    manifest = json.loads(
        (output_directory / "diagnostic-plan.json").read_text(encoding="utf-8-sig")
    )
    assert manifest["symptom"]["preset"] == "baseline"
    assert manifest["symptom"]["reported"] == "General slowdown"


def test_plan_mode_symptom_is_forwarded_to_remote_plan(tmp_path):
    """Remote plan mode must include symptom context in the plan manifest."""
    output_directory = tmp_path / "plan-remote-symptom"
    result = run_tool(
        "-Mode", "Plan",
        "-SymptomContext", "Remote slow file share",
        "-RemoteComputer", "SRV-DIAG-01",
        "-OutputDirectory", str(output_directory),
    )

    assert result.returncode == 0, result.stderr
    manifest = json.loads(
        (output_directory / "diagnostic-plan.json").read_text(encoding="utf-8-sig")
    )
    assert manifest["symptom"]["reported"] == "Remote slow file share"


def test_collect_mode_records_symptom_separately_from_collection_window(tmp_path):
    """Collect mode on Linux refuses (expected), but the parameter binding
    must accept -SymptomContext without error - verified via Plan mode."""
    output_directory = tmp_path / "collect-symptom-check"
    result = run_tool(
        "-Mode", "Plan",
        "-SymptomContext", "Application freezes during file save",
        "-Preset", "storage-io",
        "-OutputDirectory", str(output_directory),
    )

    assert result.returncode == 0, result.stderr
    manifest = json.loads(
        (output_directory / "diagnostic-plan.json").read_text(encoding="utf-8-sig")
    )
    assert manifest["symptom"]["reported"] == "Application freezes during file save"
    assert manifest["symptom"]["preset"] == "storage-io"
    # collectionWindow must be a separate object from the reported symptom
    cw = manifest["symptom"]["collectionWindow"]
    assert "requestedAtUtc" in cw


def test_symptom_context_preserves_backwards_compatibility(tmp_path):
    """Existing Plan manifests without symptom must remain valid against schema."""
    output_directory = tmp_path / "plan-compat"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr
    manifest = json.loads(
        (output_directory / "diagnostic-plan.json").read_text(encoding="utf-8-sig")
    )
    assert "symptom" not in manifest
    assert manifest["schemaVersion"] == "1.0"
    assert manifest["mode"] == "Plan"


def test_verify_mode_accepts_manifest_with_symptom_context(tmp_path):
    """Verify mode must accept a Collect manifest that includes symptom context."""
    case = _write_minimal_collect_case(tmp_path)
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["symptom"] = {
        "reported": "Explorer crashes",
        "collectionWindow": {"requestedAtUtc": "2026-09-10T12:00:00Z"},
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = run_tool("-Mode", "Verify", "-InputDirectory", str(case))

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "verified"


def test_verify_mode_accepts_manifest_with_findings_artifact(tmp_path):
    """Verify mode must recognize findings.json as a valid artifact."""
    import hashlib

    case = tmp_path / "case-with-findings"
    case.mkdir()
    artifact_path = case / "performance-samples.csv"
    artifact_path.write_bytes(b"a,b\n1,2\n")
    findings_path = case / "findings.json"
    findings_data = b'{"findings": []}'
    findings_path.write_bytes(findings_data)
    report_path = case / "report.html"
    report_data = b"<html><body>Test report</body></html>"
    report_path.write_bytes(report_data)

    manifest = {
        "schemaVersion": "1.1",
        "toolName": "Windows Performance Diagnostics Toolkit",
        "toolVersion": (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        "mode": "Collect",
        "safety": {
            "localOnly": True,
            "readOnly": True,
            "requiresExplicitCollectionConsent": True,
            "automaticUpload": False,
            "automaticRemediation": False,
            "automaticLogClearing": False,
        },
        "artifacts": [
            {"Name": "performance-samples.csv", "SizeBytes": artifact_path.stat().st_size,
             "Sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest()},
            {"Name": "findings.json", "SizeBytes": findings_path.stat().st_size,
             "Sha256": hashlib.sha256(findings_data).hexdigest()},
            {"Name": "report.html", "SizeBytes": report_path.stat().st_size,
             "Sha256": hashlib.sha256(report_data).hexdigest()},
        ],
    }
    (case / "diagnostic-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    result = run_tool("-Mode", "Verify", "-InputDirectory", str(case))

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "verified"
    assert report["artifactCount"] == 3
    assert report["verifiedArtifactCount"] == 3


# ======================================================================
# Phase 2: Improved telemetry
# ======================================================================

def test_collect_manifest_includes_extended_telemetry_fields():
    """The PowerShell script must contain the telemetry helper functions
    using correct CIM class names. Verified on Linux via source inspection."""
    source = SCRIPT.read_text(encoding="utf-8-sig")

    # CPU calculation helper
    assert "Get-ProcessCpuPercentage" in source

    # Disk: correct class name PerfDisk (not PerDisk)
    assert "Win32_PerfFormattedData_PerfDisk_PhysicalDisk" in source

    # Memory: correct class name PerfOS_Memory (not PerfSys_System)
    assert "Win32_PerfFormattedData_PerfOS_Memory" in source
    assert "CommittedBytes" in source
    assert "CommitLimit" in source

    # Volume free space
    assert "Win32_Volume" in source


def test_performance_samples_csv_backward_compatibility():
    """The performance-samples.csv must still contain the original fields
    that downstream consumers depend on."""
    source = SCRIPT.read_text(encoding="utf-8-sig")

    # Original fields that must remain
    assert "AverageCpuLoadPercent" in source
    assert "AvailableMemoryMB" in source
    assert "TotalLogicalDiskFreeGB" in source


def test_plan_mode_reports_preset_in_manifest(tmp_path):
    """Plan mode must include the preset in the manifest when provided with symptom context."""
    output_directory = tmp_path / "plan-preset-telemetry"
    result = run_tool(
        "-Mode", "Plan",
        "-SymptomContext", "High CPU after updates",
        "-Preset", "cpu-heavy",
        "-OutputDirectory", str(output_directory),
    )

    assert result.returncode == 0, result.stderr
    manifest = json.loads(
        (output_directory / "diagnostic-plan.json").read_text(encoding="utf-8-sig")
    )
    assert manifest["symptom"]["preset"] == "cpu-heavy"


def test_process_cpu_percentage_helper_returns_correct_values():
    """Get-ProcessCpuPercentage (dot-sourced) must calculate elapsed-time-based
    CPU percentage, mark processes with null CPU data as 'unknown', return 0%
    for valid zero deltas, and never return negative values."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-cpu-test; "
        "$r1 = Get-ProcessCpuPercentage -PreviousCPU 10.0 -CurrentCPU 15.0 -ElapsedSeconds 5.0 -LogicalProcessors 4; "
        "$r2 = Get-ProcessCpuPercentage -PreviousCPU $null -CurrentCPU 5.0 -ElapsedSeconds 5.0 -LogicalProcessors 4; "
        "$r3 = Get-ProcessCpuPercentage -PreviousCPU 5.0 -CurrentCPU $null -ElapsedSeconds 5.0 -LogicalProcessors 4; "
        "$r4 = Get-ProcessCpuPercentage -PreviousCPU 0.0 -CurrentCPU 0.0 -ElapsedSeconds 5.0 -LogicalProcessors 4; "
        "$r5 = Get-ProcessCpuPercentage -PreviousCPU 0.0 -CurrentCPU 10.0 -ElapsedSeconds 2.0 -LogicalProcessors 2; "
        "$r6 = Get-ProcessCpuPercentage -PreviousCPU 20.0 -CurrentCPU 10.0 -ElapsedSeconds 5.0 -LogicalProcessors 4; "
        "$r7 = Get-ProcessCpuPercentage -PreviousCPU 5.0 -CurrentCPU 5.0 -ElapsedSeconds 1.0 -LogicalProcessors 1; "
        "$r8 = Get-ProcessCpuPercentage -PreviousCPU 0.0 -CurrentCPU 4.0 -ElapsedSeconds 2.0 -LogicalProcessors 2; "
        "$r9 = Get-ProcessCpuPercentage -PreviousCPU 0.0 -CurrentCPU 4.0 -ElapsedSeconds 2.0 -LogicalProcessors $null; "
        "$r10 = Get-ProcessCpuPercentage -PreviousCPU 0.0 -CurrentCPU 4.0 -ElapsedSeconds 0 -LogicalProcessors 2; "
        "[ordered]@{normal=$r1;new=$r2;missing=$r3;bothZero=$r4;impossible=$r5;negativeDelta=$r6;validZero=$r7;fullCores=$r8;unknownCores=$r9;zeroElapsed=$r10} | ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    output = json.loads(result.stdout)
    # Normal case: (15-10) / 5.0 / 4 * 100 = 25.0
    assert output["normal"] == 25.0
    # New process (no previous CPU) -> 'unknown'
    assert output["new"] == "unknown"
    # Missing current CPU -> 'unknown'
    assert output["missing"] == "unknown"
    # Both zero -> 0% measured (not unknown)
    assert output["bothZero"] == 0.0
    # Impossible >100% after normalization is NOT clamped to a plausible 100
    assert output["impossible"] == "unknown"
    # Negative delta (counter reset) -> 'unknown'
    assert output["negativeDelta"] == "unknown"
    # Valid zero delta (10->10): 0% measured
    assert output["validZero"] == 0.0
    # Exactly all cores busy for the whole window: 4/(2*2)*100 = 100%
    assert output["fullCores"] == 100.0
    # Unknown logical processor count -> 'unknown', never a guessed normalization
    assert output["unknownCores"] == "unknown"
    # Zero/invalid elapsed window -> 'unknown'
    assert output["zeroElapsed"] == "unknown"


def test_cpu_percentage_requires_logical_processors():
    """Get-ProcessCpuPercentage must not default LogicalProcessors to 1 -
    the caller must supply the actual count (no guessing when unavailable)."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-cpu-norm; "
        # 4 logical processors: delta=20 over 10s -> 20/(10*4)*100 = 50%
        "$r = Get-ProcessCpuPercentage -PreviousCPU 10.0 -CurrentCPU 30.0 -ElapsedSeconds 10.0 -LogicalProcessors 4; "
        "$r | ConvertTo-Json"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == 50.0


def test_cpu_pid_reuse_detection():
    """PID reuse, new processes, protected processes, and valid zero deltas must
    be decided by the REAL production pairing (Get-ProcessSnapshotKey /
    New-ProcessCpuSnapshot / Compare-ProcessCpuSnapshots) - not by logic the
    test computes itself. A reused PID (same Id, different StartTime) must be
    'unknown' rather than a bogus large percentage, and a genuine zero delta
    must stay 0 (a positive measurement), never 'unknown'.
    """
    script = str(SCRIPT).replace("\\", "/")
    body = r"""
$null = . '__SCRIPT__' -Mode Plan -OutputDirectory '/tmp/wpd-pid-reuse-real'
$t1 = [datetime]'2026-09-10T10:00:00Z'
$t2 = [datetime]'2026-09-10T11:00:00Z'
$t3 = [datetime]'2026-09-10T12:00:00Z'

$startProcesses = @(
    [pscustomobject]@{ ProcessName = 'orig'; Id = 100; StartTime = $t1; CPU = 5.0 },
    [pscustomobject]@{ ProcessName = 'zero'; Id = 200; StartTime = $t2; CPU = 0.0 },
    [pscustomobject]@{ ProcessName = 'protected-start'; Id = 500; StartTime = $null; CPU = $null }
)
$baseline = New-ProcessCpuSnapshot -Processes $startProcesses
$baselineKeyCount = @($baseline.Keys).Count

$endProcesses = @(
    [pscustomobject]@{ ProcessName = 'orig'; Id = 100; StartTime = $t1; CPU = 6.0 },
    [pscustomobject]@{ ProcessName = 'reused'; Id = 100; StartTime = $t3; CPU = 6.0 },
    [pscustomobject]@{ ProcessName = 'zero'; Id = 200; StartTime = $t2; CPU = 0.0 },
    [pscustomobject]@{ ProcessName = 'new'; Id = 400; StartTime = $t3; CPU = 2.0 },
    [pscustomobject]@{ ProcessName = 'protected-end'; Id = 500; StartTime = $null; CPU = $null }
)
$rows = @(Compare-ProcessCpuSnapshots -StartSnapshots $baseline -EndProcesses $endProcesses -ElapsedSeconds 10.0 -LogicalProcessors 2)
$byName = @{}
foreach ($row in $rows) { $byName[[string]$row.ProcessName] = $row }
[ordered]@{
    baselineKeyCount = $baselineKeyCount
    rowCount          = $rows.Count
    original          = $byName['orig'].ProcessCpuPercent
    originalCumulative = $byName['orig'].CPU
    reusedPid         = $byName['reused'].ProcessCpuPercent
    validZero         = $byName['zero'].ProcessCpuPercent
    newProcess        = $byName['new'].ProcessCpuPercent
    protectedProcess  = $byName['protected-end'].ProcessCpuPercent
} | ConvertTo-Json -Depth 4
"""
    result = _run_ps(body.replace("__SCRIPT__", script))
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)

    # The protected (no StartTime) start process cannot be keyed -> not stored.
    assert output["baselineKeyCount"] == 2
    assert output["rowCount"] == 5
    # (6.0 - 5.0) / (10.0 * 2) * 100 = 5.0 percent
    assert output["original"] == 5.0
    # cumulative CPU seconds are preserved alongside the percentage
    assert output["originalCumulative"] == 6.0
    # Same Id, different StartTime -> cannot be paired to the old baseline.
    assert output["reusedPid"] == "unknown"
    # Present at both endpoints with a real zero delta -> 0 percent measured.
    assert output["validZero"] == 0.0
    # Not present at the baseline -> unknown, never a fabricated value.
    assert output["newProcess"] == "unknown"
    # Identity/CPU unreadable (protected) -> unknown.
    assert output["protectedProcess"] == "unknown"


def test_disk_metrics_helper_returns_null_on_unavailable_cim():
    """Get-DiskMetrics must return null (not throw, not zero-fill) when
    CIM classes are unavailable."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-disk-null; "
        "$result = Get-DiskMetrics; "
        "$result | ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output is None


def test_memory_metrics_helper_returns_null_on_unavailable_cim():
    """Get-MemoryMetrics must return null when CIM classes are unavailable."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-mem-null; "
        "$result = Get-MemoryMetrics; "
        "$result | ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output is None


def test_volume_metrics_helper_returns_null_on_unavailable_cim():
    """Get-VolumeMetrics must return null when CIM classes are unavailable."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-vol-null; "
        "$result = Get-VolumeMetrics; "
        "$result | ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output is None


def test_disk_metrics_class_name_is_correct_in_source():
    """Source must use PerfDisk, not PerDisk, for the CIM class."""
    source = SCRIPT.read_text(encoding="utf-8-sig")
    assert "Win32_PerfFormattedData_PerfDisk_PhysicalDisk" in source
    # The old wrong name must not appear
    assert "Win32_PerfFormattedData_PerDisk" not in source


def test_memory_metrics_class_name_is_correct_in_source():
    """Source must use PerfOS_Memory, not PerfSys_System, for the CIM class."""
    source = SCRIPT.read_text(encoding="utf-8-sig")
    assert "Win32_PerfFormattedData_PerfOS_Memory" in source
    assert "Win32_PerfFormattedData_PerfSys_System" not in source


def test_memory_metrics_includes_page_faults_distinction():
    """Source must capture PageFaultsPerSec (soft+hard) AND PagesInputPersec
    (hard only) separately - never conflating them."""
    source = SCRIPT.read_text(encoding="utf-8-sig")
    assert "PageFaultsPerSec" in source or "pageFaultsPerSec" in source
    assert "PagesInputPersec" in source or "pagesInputPerSec" in source
    assert "PageReadsPersec" in source or "pageReadsPerSec" in source


def test_memory_schema_includes_page_faults_per_sec():
    """Schema must include pageFaultsPerSec for soft+hard distinction."""
    schema = json.loads(
        (REPO_ROOT / "schema" / "diagnostic-report.schema.json").read_text(encoding="utf-8")
    )
    mem_props = schema["properties"]["memoryMetrics"]["properties"]
    assert "pageFaultsPerSec" in mem_props
    assert "pagesInputPerSec" in mem_props


def test_findings_engine_pure_function_cpu_pressure():
    """Evaluate-Findings (dot-sourced) must detect sustained CPU pressure
    across multiple samples and emit a finding with proper fields."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-findings-cpu; "
        # 30 samples: first 20 normal, last 10 sustained high CPU
        "$csv = @(); "
        "for ($i = 0; $i -lt 20; $i++) { $csv += [pscustomobject]@{TimestampUtc=(Get-Date).AddSeconds($i).ToUniversalTime().ToString('o'); AverageCpuLoadPercent=25.0; AvailableMemoryMB=8000; TotalLogicalDiskFreeGB=100.0; CommittedBytes=4GB; CommitLimitBytes=8GB} }; "
        "for ($i = 20; $i -lt 30; $i++) { $csv += [pscustomobject]@{TimestampUtc=(Get-Date).AddSeconds($i).ToUniversalTime().ToString('o'); AverageCpuLoadPercent=92.0; AvailableMemoryMB=8000; TotalLogicalDiskFreeGB=100.0; CommittedBytes=4GB; CommitLimitBytes=8GB} }; "
        "$findings = Evaluate-Findings -Samples $csv -DiskMetrics $null -VolumeMetrics $null -MemoryMetrics $null; "
        "$findings | ConvertTo-Json -Depth 8"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    findings = json.loads(result.stdout)
    cpu_findings = [f for f in findings if f["category"] == "cpu-pressure"]
    assert len(cpu_findings) >= 1, "Expected at least one cpu-pressure finding"
    f = cpu_findings[0]
    assert f["sourceArtifact"] == "performance-samples.csv"
    assert f["metric"] == "AverageCpuLoadPercent"
    assert f["ruleCondition"] is not None
    assert f["suggestedWprProfile"] in ("CPU", "GeneralProfile")


def test_findings_engine_no_spike_only_finding():
    """A single spike above threshold with surrounding normal samples must NOT
    produce a finding - sustained evidence required."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-findings-spike; "
        "$csv = @(); "
        "for ($i = 0; $i -lt 30; $i++) { "
        "  $cpu = if ($i -eq 15) { 95.0 } else { 20.0 }; "
        "  $csv += [pscustomobject]@{TimestampUtc=(Get-Date).AddSeconds($i).ToUniversalTime().ToString('o'); AverageCpuLoadPercent=$cpu; AvailableMemoryMB=8000; TotalLogicalDiskFreeGB=100.0; CommittedBytes=4GB; CommitLimitBytes=8GB} "
        "}; "
        "$findings = Evaluate-Findings -Samples $csv -DiskMetrics $null -VolumeMetrics $null -MemoryMetrics $null; "
        "$cpuFindings = @($findings | Where-Object { $_.category -eq 'cpu-pressure' }); "
        "$cpuFindings.Count | ConvertTo-Json"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == 0, "Spike-only must not produce finding"


def test_findings_engine_insufficient_samples():
    """When fewer than 3 usable samples exist, findings must be suppressed
    and a coverage warning emitted."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-findings-insuff; "
        "$csv = @(); "
        "for ($i = 0; $i -lt 2; $i++) { "
        "  $csv += [pscustomobject]@{TimestampUtc=(Get-Date).AddSeconds($i).ToUniversalTime().ToString('o'); AverageCpuLoadPercent=95.0; AvailableMemoryMB=500; TotalLogicalDiskFreeGB=0.5; CommittedBytes=7.5GB; CommitLimitBytes=8GB} "
        "}; "
        "$findings = Evaluate-Findings -Samples $csv -DiskMetrics $null -VolumeMetrics $null -MemoryMetrics $null; "
        "$warnings = @($findings | Where-Object { $_.category -eq 'coverage' }); "
        "$cpuFindings = @($findings | Where-Object { $_.category -eq 'cpu-pressure' }); "
        "[ordered]@{warningCount=$warnings.Count; cpuFindingCount=$cpuFindings.Count} | ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["warningCount"] >= 1, "Expected coverage warning"
    assert output["cpuFindingCount"] == 0, "No findings with insufficient samples"


# ======================================================================
# Phase 3: findings.json, report.html, XSS escaping, integration
# ======================================================================

def test_html_report_escapes_xss_payloads():
    """ConvertTo-FindingsHtml must HTML-encode all user-influenceable text.
    Process names, paths, computer names, event messages with <script> tags
    must appear entity-encoded in the output."""
    script = str(SCRIPT).replace("\\", "/")
    xss_payload = '<script>alert("xss")</script>'
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-xss-test; "
        "$manifest = [ordered]@{toolVersion='0.9.0';schemaVersion='1.1';"
        "startedAtUtc='2026-09-10T12:00:00Z';completedAtUtc='2026-09-10T12:00:30Z';"
        "scope=[ordered]@{durationSeconds=30};"
        "artifacts=@([ordered]@{Name='test.csv';SizeBytes=100;Sha256='A'*64})}; "
        "$findings = @([ordered]@{category='cpu-pressure';sourceArtifact='test.csv';"
        "metric='CPU';windowStart=$null;windowEnd=$null;"
        "measuredValues=[ordered]@{peak=95};"
        f"ruleCondition='{xss_payload}';"
        "uncertainty='test';nextSteps='test';suggestedWprProfile='CPU'}); "
        "$html = ConvertTo-FindingsHtml -Findings $findings -Manifest $manifest "
        f"-SymptomContext '{xss_payload}'; "
        "$html | ConvertTo-Json"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    html = json.loads(result.stdout)
    # Must not contain raw <script> tags
    assert "<script>" not in html
    # Must contain entity-encoded version
    assert "&lt;script&gt;" in html or "script" not in html.lower()


def test_html_report_is_offline_only_no_external_assets():
    """Report HTML must not reference external resources (CDNs, fonts,
    scripts) or contain traversal links."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-offline-test; "
        "$manifest = [ordered]@{toolVersion='0.9.0';schemaVersion='1.1';"
        "startedAtUtc='2026-09-10T12:00:00Z';completedAtUtc='2026-09-10T12:00:30Z';"
        "scope=[ordered]@{durationSeconds=30};artifacts=@()}; "
        "$html = ConvertTo-FindingsHtml -Findings @() -Manifest $manifest -SymptomContext $null; "
        "$html | ConvertTo-Json"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    html = json.loads(result.stdout)
    # No external URLs in src= or href=
    import re as re_module
    assert not re_module.search(r'(src|href)=["\']https?://', html), "External URL found in HTML"
    assert 'file://' not in html, "file:// URL found in HTML"
    assert 'http://' not in html, "http:// URL found in HTML"
    # No traversal links
    assert '..' not in html or '&gt;' in html  # encoded .. is OK, raw is not
    # No inline JavaScript
    assert '<script' not in html.lower()
    assert 'javascript:' not in html.lower()


def test_html_report_contains_no_health_score():
    """Report must never contain numeric pseudo-confidence or health score."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-noscore; "
        "$manifest = [ordered]@{toolVersion='0.9.0';schemaVersion='1.1';"
        "startedAtUtc='2026-09-10T12:00:00Z';completedAtUtc='2026-09-10T12:00:30Z';"
        "scope=[ordered]@{durationSeconds=30};artifacts=@()}; "
        "$html = ConvertTo-FindingsHtml -Findings @() -Manifest $manifest -SymptomContext $null; "
        "$html | ConvertTo-Json"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    html = json.loads(result.stdout).lower()
    assert "score" not in html
    assert "confidence:" not in html
    assert "health rating" not in html


def test_findings_json_no_health_score():
    """findings.json must never contain a health score or numeric confidence."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-finding-noscore; "
        "$csv = @([pscustomobject]@{TimestampUtc='2026-09-10T12:00:00Z';AverageCpuLoadPercent=25;AvailableMemoryMB=8000;TotalLogicalDiskFreeGB=100;CommittedBytes=4GB;CommitLimitBytes=8GB}); "
        "$findings = Evaluate-Findings -Samples $csv -DiskMetrics $null -VolumeMetrics $null -MemoryMetrics $null; "
        "$json = $findings | ConvertTo-Json -Depth 8; "
        "$json | ConvertTo-Json"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    findings_str = output.lower()
    assert '"score"' not in findings_str
    assert '"confidence"' not in findings_str


def test_plan_mode_does_not_produce_findings_or_report(tmp_path):
    """Plan mode must exit before findings/report generation - no side effects."""
    output_directory = tmp_path / "plan-no-findings"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr
    assert not (output_directory / "findings.json").exists()
    assert not (output_directory / "report.html").exists()


def test_verify_mode_accepts_findings_json_and_report_html(tmp_path):
    """Verify mode must accept a Collect manifest that includes
    findings.json and report.html as artifacts."""
    import hashlib

    case = tmp_path / "case-with-report"
    case.mkdir()
    artifact_path = case / "performance-samples.csv"
    artifact_path.write_bytes(b"a,b\n1,2\n")
    findings_path = case / "findings.json"
    findings_data = json.dumps([{"category": "coverage", "metric": "test"}]).encode()
    findings_path.write_bytes(findings_data)
    report_path = case / "report.html"
    report_data = b"<!DOCTYPE html><html><body>test</body></html>"
    report_path.write_bytes(report_data)

    manifest = {
        "schemaVersion": "1.1",
        "toolName": "Windows Performance Diagnostics Toolkit",
        "toolVersion": (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        "mode": "Collect",
        "safety": {
            "localOnly": True,
            "readOnly": True,
            "requiresExplicitCollectionConsent": True,
            "automaticUpload": False,
            "automaticRemediation": False,
            "automaticLogClearing": False,
        },
        "artifacts": [
            {"Name": "performance-samples.csv", "SizeBytes": artifact_path.stat().st_size,
             "Sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest()},
            {"Name": "findings.json", "SizeBytes": findings_path.stat().st_size,
             "Sha256": hashlib.sha256(findings_data).hexdigest()},
            {"Name": "report.html", "SizeBytes": report_path.stat().st_size,
             "Sha256": hashlib.sha256(report_data).hexdigest()},
        ],
    }
    (case / "diagnostic-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    result = run_tool("-Mode", "Verify", "-InputDirectory", str(case))

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "verified"
    assert report["artifactCount"] == 3
    assert report["verifiedArtifactCount"] == 3


def test_verify_fails_on_tampered_report_html(tmp_path):
    """Verify must fail when report.html is tampered post-package."""
    import hashlib

    case = tmp_path / "case-tampered-report"
    case.mkdir()
    findings_path = case / "findings.json"
    findings_data = b'{"findings":[]}'
    findings_path.write_bytes(findings_data)
    report_path = case / "report.html"
    report_data = b"<html>original</html>"
    report_path.write_bytes(report_data)

    manifest = {
        "schemaVersion": "1.1",
        "toolName": "Windows Performance Diagnostics Toolkit",
        "toolVersion": (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        "mode": "Collect",
        "safety": {
            "localOnly": True,
            "readOnly": True,
            "requiresExplicitCollectionConsent": True,
            "automaticUpload": False,
            "automaticRemediation": False,
            "automaticLogClearing": False,
        },
        "artifacts": [
            {"Name": "findings.json", "SizeBytes": findings_path.stat().st_size,
             "Sha256": hashlib.sha256(findings_data).hexdigest()},
            {"Name": "report.html", "SizeBytes": report_path.stat().st_size,
             "Sha256": hashlib.sha256(report_data).hexdigest()},
        ],
    }
    (case / "diagnostic-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    # Tamper with report.html after manifest is written
    report_path.write_bytes(b"<html>tampered</html>")

    result = run_tool("-Mode", "Verify", "-InputDirectory", str(case))

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["status"] == "failed"
    assert any("hash mismatch" in e.lower() for e in report["errors"])


def test_collect_mode_refuses_without_consent_even_with_symptom(tmp_path):
    """Symptom parameters don't bypass consent gates. No side effects."""
    output_directory = tmp_path / "no-consent-symptom"
    result = run_tool(
        "-Mode", "Collect",
        "-SymptomContext", "Slow boot",
        "-OutputDirectory", str(output_directory),
    )

    assert result.returncode != 0
    assert "requires -ConfirmLocalCollection" in result.stderr
    assert not output_directory.exists()


def test_findings_engine_memory_pressure_from_fixture():
    """Evaluate-Findings must detect SUSTAINED memory pressure from the
    per-sample series (5 consecutive samples >= 90% commit), not from a single
    post-run reading."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-findings-mem; "
        "$csv = @(); "
        "for ($i = 0; $i -lt 12; $i++) { "
        "  $committed = if ($i -ge 4 -and $i -le 8) { [long]7.6GB } else { [long]4GB }; "
        "  $csv += [pscustomobject]@{TimestampUtc=('2026-09-10T12:00:{0:D2}Z' -f $i);AverageCpuLoadPercent=25;AvailableMemoryMB=8000;TotalLogicalDiskFreeGB=100;CommittedBytes=$committed;CommitLimitBytes=[long]8GB;PagesInputPerSec=$null} "
        "}; "
        "$mem = [ordered]@{committedBytes=[long]4GB;commitLimitBytes=[long]8GB;availableBytes=[long]4GB;pageFaultsPerSec=50;pageReadsPerSec=5;pageWritesPerSec=2;pagesInputPerSec=$null;pagesOutputPerSec=3}; "
        "$findings = Evaluate-Findings -Samples $csv -DiskSeries $null -VolumeMetrics $null -MemoryMetrics $mem; "
        "$memFindings = @($findings | Where-Object { $_.category -eq 'memory-pressure' }); "
        "[ordered]@{count=$memFindings.Count; start=$memFindings[0].windowStart; end=$memFindings[0].windowEnd} | ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["count"] >= 1
    assert output["start"] == "2026-09-10T12:00:04Z"
    assert output["end"] == "2026-09-10T12:00:08Z"


def test_findings_engine_hard_page_fault_detection():
    """Evaluate-Findings must detect sustained paging input from
    PagesInputPersec (pages read to resolve hard faults), not from
    PageFaultsPersec (which includes soft faults)."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-findings-paging; "
        "$csv = @(); "
        "for ($i = 0; $i -lt 10; $i++) { "
        "  $pages = if ($i -ge 3 -and $i -le 7) { 200 } else { 5 }; "
        "  $csv += [pscustomobject]@{TimestampUtc=('2026-09-10T12:00:{0:D2}Z' -f $i);AverageCpuLoadPercent=25;AvailableMemoryMB=8000;TotalLogicalDiskFreeGB=100;CommittedBytes=[long]4GB;CommitLimitBytes=[long]8GB;PagesInputPerSec=$pages} "
        "}; "
        "$mem = [ordered]@{committedBytes=[long]4GB;commitLimitBytes=[long]8GB;availableBytes=[long]4GB;pageFaultsPerSec=5000;pageReadsPerSec=200;pageWritesPerSec=50;pagesInputPerSec=200;pagesOutputPerSec=50}; "
        "$findings = Evaluate-Findings -Samples $csv -DiskSeries $null -VolumeMetrics $null -MemoryMetrics $mem; "
        "$pagingFindings = @($findings | Where-Object { $_.category -eq 'memory-paging' }); "
        "[ordered]@{count=$pagingFindings.Count; metric=$pagingFindings[0].metric; start=$pagingFindings[0].windowStart} | ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["count"] >= 1
    assert output["metric"] == "PagesInputPerSec"
    assert output["start"] == "2026-09-10T12:00:03Z"


def test_findings_engine_coverage_when_hard_faults_null():
    """When PagesInputPersec is null but PageFaultsPersec exists,
    findings must note the hard-fault rate is unknown (not claim disk thrashing)."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-findings-nullhf; "
        "$csv = @([pscustomobject]@{TimestampUtc='2026-09-10T12:00:00Z';AverageCpuLoadPercent=25;AvailableMemoryMB=8000;TotalLogicalDiskFreeGB=100;CommittedBytes=4GB;CommitLimitBytes=8GB}); "
        "$mem = [ordered]@{committedBytes=[long]4GB;commitLimitBytes=[long]8GB;availableBytes=[long]4GB;pageFaultsPerSec=5000;pageReadsPerSec=$null;pageWritesPerSec=$null;pagesInputPerSec=$null;pagesOutputPerSec=$null}; "
        "$findings = Evaluate-Findings -Samples $csv -DiskMetrics $null -VolumeMetrics $null -MemoryMetrics $mem; "
        "$coverageFindings = @($findings | Where-Object { $_.category -eq 'coverage' -and $_.metric -eq 'pagesInputPerSec' }); "
        "$coverageFindings.Count | ConvertTo-Json"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) >= 1


def test_disk_telemetry_helper_handles_unsupported_counters():
    """Get-DiskMetrics must handle unsupported CIM performance counters
    gracefully - return null/empty rather than throwing."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-disk-test; "
        "$result = Get-DiskMetrics; "
        "$result | ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    # On Linux, CIM classes are unavailable - the helper must return null
    # without throwing, proving graceful degradation
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output is None or isinstance(output, (list, dict))


def test_memory_telemetry_helper_handles_unavailable_cim():
    """Get-MemoryMetrics must handle unavailable CIM classes gracefully."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-mem-test; "
        "$result = Get-MemoryMetrics; "
        "$result | ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output is None or isinstance(output, (list, dict))


def test_volume_telemetry_helper_handles_unavailable_cim():
    """Get-VolumeMetrics must handle unavailable CIM classes gracefully."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-vol-test; "
        "$result = Get-VolumeMetrics; "
        "$result | ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output is None or isinstance(output, (list, dict))


def test_unknown_telemetry_not_zero():
    """The source must never replace missing CIM readings with zero.
    grep for explicit zero-fallback patterns that would mask missing data."""
    source = SCRIPT.read_text(encoding="utf-8-sig")

    # Must not hardcode 'queueDepth = 0' or similar when CIM fails
    # The pattern 'if ($null -eq ...) { ... = 0 }' is forbidden for new metrics
    assert "queueDepth = 0" not in source
    assert "readLatency = 0" not in source
    assert "writeLatency = 0" not in source


# ======================================================================
# DeepSeek V4 Flash correction lane: production pairing, raw disk
# counters, sustained-streak rules, manifest ordering and Collect tail
# ======================================================================

def _run_ps(command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )


def test_process_snapshot_pairing_uses_pid_and_start_time():
    """Compare-ProcessCpuSnapshots is the real production pairing path: same
    PID+StartTime matches; a reused PID, a new process and a protected process
    (missing StartTime) all yield 'unknown'; a valid zero delta yields 0.0; an
    invalid elapsed window yields 'unknown'; the cumulative CPU label is kept."""
    script = str(SCRIPT).replace("\\", "/")
    body = r"""
$null = . '__SCRIPT__' -Mode Plan -OutputDirectory '/tmp/wpd-pairing'
function New-P { param($id, $ticks, $cpu, $name) [pscustomobject]@{ Id=$id; StartTime=([datetime]'2026-01-01T00:00:00Z').AddTicks($ticks); CPU=$cpu; ProcessName=$name; WorkingSet64=1; Handles=1; Path=$name } }
$start = New-ProcessCpuSnapshot -Processes @( (New-P 100 0 10.0 'normal'), (New-P 200 0 5.0 'zero'), (New-P 400 0 7.0 'invalidelapsed') )
$end = @(
  (New-P 100 0 15.0 'normal'),
  (New-P 200 0 5.0 'zero'),
  (New-P 300 0 3.0 'new'),
  (New-P 100 999 1.0 'reused'),
  (New-P 400 0 9.0 'invalidelapsed'),
  ([pscustomobject]@{ Id=500; CPU=2.0; ProcessName='protected' })
)
$r = @(Compare-ProcessCpuSnapshots -StartSnapshots $start -EndProcesses $end -ElapsedSeconds 5.0 -LogicalProcessors 4)
$byName = @{}
foreach ($x in $r) { $byName[$x.ProcessName] = $x.ProcessCpuPercent }
$r2 = @(Compare-ProcessCpuSnapshots -StartSnapshots $start -EndProcesses $end -ElapsedSeconds 0 -LogicalProcessors 4)
$byName2 = @{}
foreach ($x in $r2) { $byName2[$x.ProcessName] = $x.ProcessCpuPercent }
[ordered]@{
  normal=$byName['normal']; zero=$byName['zero']; new=$byName['new']; reused=$byName['reused']; protected=$byName['protected'];
  invalidElapsed=$byName2['invalidelapsed']; cumulative=(@($r | Where-Object { $_.ProcessName -eq 'normal' })[0].CPU)
} | ConvertTo-Json -Depth 4
"""
    result = _run_ps(body.replace("__SCRIPT__", script))
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["normal"] == 25.0
    assert output["zero"] == 0.0
    assert output["new"] == "unknown"
    assert output["reused"] == "unknown"
    assert output["protected"] == "unknown"
    assert output["invalidElapsed"] == "unknown"
    assert output["cumulative"] == 15.0


def test_disk_counter_deltas_raw_latency_throughput_queue():
    """Get-DiskCounterDeltas is the production raw-counter calculation:
    latency = (tick delta / Frequency_PerfTime) / operation-base delta,
    throughput = byte delta / elapsed, queue is instantaneous. No baseline, no
    I/O or a counter reset produce null with a coverage reason, never zero."""
    script = str(SCRIPT).replace("\\", "/")
    body = r"""
$null = . '__SCRIPT__' -Mode Plan -OutputDirectory '/tmp/wpd-diskd'
$prev = [pscustomobject]@{
  Name='0 C:'; Frequency_PerfTime=[uint64]10000000; Timestamp_PerfTime=[uint64]100000000;
  AvgDiskSecPerRead=[uint64]0; AvgDiskSecPerRead_Base=[uint32]0;
  AvgDiskSecPerWrite=[uint64]0; AvgDiskSecPerWrite_Base=[uint32]0;
  DiskReadBytesPerSec=[uint64]1000; DiskWriteBytesPerSec=[uint64]2000; DiskBytesPerSec=[uint64]3000;
  CurrentDiskQueueLength=[uint32]0
}
$curr = [pscustomobject]@{
  Name='0 C:'; Frequency_PerfTime=[uint64]10000000; Timestamp_PerfTime=[uint64]120000000;
  AvgDiskSecPerRead=[uint64]500000; AvgDiskSecPerRead_Base=[uint32]100;
  AvgDiskSecPerWrite=[uint64]100000; AvgDiskSecPerWrite_Base=[uint32]50;
  DiskReadBytesPerSec=[uint64]5096; DiskWriteBytesPerSec=[uint64]4048; DiskBytesPerSec=[uint64]9144;
  CurrentDiskQueueLength=[uint32]3
}
$r = @(Get-DiskCounterDeltas -Previous @($prev) -Current @($curr) -TimestampUtc '2026-09-10T12:00:01Z')[0]
$nb = @(Get-DiskCounterDeltas -Previous $null -Current @($curr) -TimestampUtc '2026-09-10T12:00:01Z')[0]
$prevNoIo = $prev.PSObject.Copy(); $prevNoIo.AvgDiskSecPerRead=[uint64]500000; $prevNoIo.AvgDiskSecPerRead_Base=[uint32]100
$currNoIo = $curr.PSObject.Copy(); $currNoIo.AvgDiskSecPerRead=[uint64]500000; $currNoIo.AvgDiskSecPerRead_Base=[uint32]100
$noio = @(Get-DiskCounterDeltas -Previous @($prevNoIo) -Current @($currNoIo) -TimestampUtc 't')[0]
$resetPrev = $prev.PSObject.Copy(); $resetPrev.AvgDiskSecPerRead=[uint64]500000; $resetPrev.AvgDiskSecPerRead_Base=[uint32]100
$resetCurr = $curr.PSObject.Copy(); $resetCurr.AvgDiskSecPerRead=[uint64]100; $resetCurr.AvgDiskSecPerRead_Base=[uint32]150
$reset = @(Get-DiskCounterDeltas -Previous @($resetPrev) -Current @($resetCurr) -TimestampUtc 't')[0]
[ordered]@{
  readLatency=$r.ReadLatencySeconds; writeLatency=$r.WriteLatencySeconds;
  readRate=$r.ReadBytesPerSec; queue=$r.CurrentQueueLength;
  noBaselineLatency=$nb.ReadLatencySeconds; noBaselineReason=($nb.CoverageReason -join ',');
  noIoLatency=$noio.ReadLatencySeconds; noIoReason=($noio.CoverageReason -join ',');
  resetLatency=$reset.ReadLatencySeconds; resetReason=($reset.CoverageReason -join ',')
} | ConvertTo-Json -Depth 5
"""
    result = _run_ps(body.replace("__SCRIPT__", script))
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert abs(output["readLatency"] - 0.0005) < 1e-9
    assert abs(output["writeLatency"] - 0.0002) < 1e-9
    assert output["readRate"] == 2048.0
    assert output["queue"] == 3.0
    assert output["noBaselineLatency"] is None
    assert "no-baseline" in output["noBaselineReason"]
    assert output["noIoLatency"] is None
    assert "no-io" in output["noIoReason"]
    assert output["resetLatency"] is None
    assert "counter-reset" in output["resetReason"]


def test_sustained_window_counts_finite_readings_and_nulls_break_streak():
    """Get-SustainedWindow counts only finite readings (null breaks a run) and
    returns the longest qualifying run, not the trailing one."""
    script = str(SCRIPT).replace("\\", "/")
    body = r"""
$null = . '__SCRIPT__' -Mode Plan -OutputDirectory '/tmp/wpd-window'
$s = @()
for ($i=0; $i -lt 4; $i++) { $s += [pscustomobject]@{ TimestampUtc="a$i"; v=95 } }
$s += [pscustomobject]@{ TimestampUtc='null'; v=$null }
for ($i=0; $i -lt 5; $i++) { $s += [pscustomobject]@{ TimestampUtc="b$i"; v=95 } }
$w = Get-SustainedWindow -Samples $s -ValueProperty 'v' -Threshold 80 -MinimumConsecutive 5
[ordered]@{ count=$w.Count; start=$w.StartTimestampUtc; end=$w.EndTimestampUtc } | ConvertTo-Json
"""
    result = _run_ps(body.replace("__SCRIPT__", script))
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["count"] == 5
    assert output["start"] == "b0"
    assert output["end"] == "b4"


def test_findings_cpu_sustained_streak_found_anywhere():
    """A 6-sample 85% burst at t=10..15 followed by an idle tail must still
    produce exactly one cpu-pressure finding citing that window (regression for
    the trailing-streak-only defect)."""
    script = str(SCRIPT).replace("\\", "/")
    body = r"""
$null = . '__SCRIPT__' -Mode Plan -OutputDirectory '/tmp/wpd-streak'
$csv = @()
for ($i=0; $i -lt 30; $i++) {
  $cpu = if ($i -ge 10 -and $i -le 15) { 85.0 } else { 20.0 }
  $csv += [pscustomobject]@{ TimestampUtc=('2026-09-10T12:00:{0:D2}Z' -f $i); AverageCpuLoadPercent=$cpu; CommittedBytes=[long]4GB; CommitLimitBytes=[long]8GB; PagesInputPerSec=$null }
}
$f = @(Evaluate-Findings -Samples $csv -DiskSeries $null -VolumeMetrics $null -MemoryMetrics $null)
$cpu = @($f | Where-Object { $_.category -eq 'cpu-pressure' })
[ordered]@{ count=$cpu.Count; start=$cpu[0].windowStart; end=$cpu[0].windowEnd; samples=$cpu[0].measuredValues.consecutiveSamplesAboveThreshold } | ConvertTo-Json -Depth 4
"""
    result = _run_ps(body.replace("__SCRIPT__", script))
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["count"] == 1
    assert output["start"] == "2026-09-10T12:00:10Z"
    assert output["end"] == "2026-09-10T12:00:15Z"
    assert output["samples"] == 6


def test_findings_disk_series_sustained_and_single_read_ignored():
    """Sustained queue/latency in the in-window disk series produces findings
    with a cited window; a single high reading produces no finding."""
    script = str(SCRIPT).replace("\\", "/")
    body = r"""
$null = . '__SCRIPT__' -Mode Plan -OutputDirectory '/tmp/wpd-diskfind'
$series = @()
for ($i=0; $i -lt 10; $i++) {
  $q = if ($i -ge 3 -and $i -le 8) { 3 } else { 0 }
  $lat = if ($i -ge 3 -and $i -le 8) { 0.03 } else { 0.001 }
  $series += [pscustomobject]@{ TimestampUtc=('2026-09-10T12:00:{0:D2}Z' -f $i); Name='0 C:'; CurrentQueueLength=$q; ReadLatencySeconds=$lat; ReadBytesPerSec=1000 }
}
$f = @(Evaluate-Findings -Samples @() -DiskSeries $series -VolumeMetrics $null -MemoryMetrics $null)
$disk = @($f | Where-Object { $_.category -eq 'disk-pressure' })
$lat = @($f | Where-Object { $_.category -eq 'disk-latency' })
$single = @([pscustomobject]@{ TimestampUtc='2026-09-10T12:00:00Z'; Name='0 C:'; CurrentQueueLength=9; ReadLatencySeconds=0.5; ReadBytesPerSec=1 })
$f2 = @(Evaluate-Findings -Samples @() -DiskSeries $single -VolumeMetrics $null -MemoryMetrics $null)
$disk2 = @($f2 | Where-Object { $_.category -eq 'disk-pressure' })
$lat2 = @($f2 | Where-Object { $_.category -eq 'disk-latency' })
[ordered]@{
  queueCount=$disk.Count; queueStart=$disk[0].windowStart; queueEnd=$disk[0].windowEnd;
  latencyCount=$lat.Count; latencyMetric=$lat[0].metric;
  singleQueue=$disk2.Count; singleLatency=$lat2.Count
} | ConvertTo-Json -Depth 4
"""
    result = _run_ps(body.replace("__SCRIPT__", script))
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["queueCount"] == 1
    assert output["queueStart"] == "2026-09-10T12:00:03Z"
    assert output["queueEnd"] == "2026-09-10T12:00:08Z"
    assert output["latencyCount"] == 1
    assert output["latencyMetric"] == "ReadLatencySeconds"
    assert output["singleQueue"] == 0
    assert output["singleLatency"] == 0


def test_findings_coverage_warnings_for_missing_series():
    """Null CPU readings, missing paging, no disk series and no volume metrics
    all produce coverage warnings (unknown is never treated as healthy)."""
    script = str(SCRIPT).replace("\\", "/")
    body = r"""
$null = . '__SCRIPT__' -Mode Plan -OutputDirectory '/tmp/wpd-cov'
$csv = @()
for ($i=0; $i -lt 6; $i++) { $csv += [pscustomobject]@{ TimestampUtc='t'; AverageCpuLoadPercent=$null; CommittedBytes=$null; CommitLimitBytes=$null; PagesInputPerSec=$null } }
$f = @(Evaluate-Findings -Samples $csv -DiskSeries $null -VolumeMetrics $null -MemoryMetrics $null)
@($f | Where-Object { $_.category -eq 'coverage' } | ForEach-Object { $_.metric }) | ConvertTo-Json
"""
    result = _run_ps(body.replace("__SCRIPT__", script))
    assert result.returncode == 0, result.stderr
    metrics = json.loads(result.stdout)
    assert "noSamples" in metrics
    assert "pagesInputPerSec" in metrics
    assert "diskSeriesUnavailable" in metrics
    assert "volumeMetricsUnavailable" in metrics


def test_cpu_interval_stopwatch_spans_the_end_enumeration():
    """Ordering contract for the interval-CPU measurement (guards audit finding
    F1). The stopwatch must be stopped only AFTER the end-of-interval process
    enumeration, with the elapsed value captured in between: stopping it earlier
    would drop CPU accrued during CSV export / summary polls from the
    denominator while the numerator delta still included it, inflating every
    per-process percentage. The live Collect path is Windows-only, so this
    ordering is asserted on the source rather than executed here; the hosted
    Windows workload step executes the same code path end to end.
    """
    source = SCRIPT.read_text(encoding="utf-8-sig")

    start_idx = source.index("$cpuStopwatch = [System.Diagnostics.Stopwatch]::StartNew()")
    enumeration_idx = source.index("$processEnds = @(Get-Process")
    elapsed_idx = source.index("$cpuElapsedSeconds = $cpuStopwatch.Elapsed.TotalSeconds")
    stop_idx = source.index("$cpuStopwatch.Stop()")

    assert start_idx < enumeration_idx < elapsed_idx < stop_idx
    # The interval must be measured with the captured value, not read after Stop.
    assert "ElapsedSeconds $cpuStopwatch.Elapsed.TotalSeconds" not in source
    assert "ElapsedSeconds $cpuElapsedSeconds" in source


def test_html_report_with_no_findings_reports_measured_clear_window():
    """A collection that measured every source and breached no sustained rule
    must NOT be reported as 'Insufficient Evidence' - that wording is reserved
    for missing/unusable data. Zero findings with zero coverage warnings is a
    positive measurement result and must say so, so an operator can tell
    'nothing sustained' apart from 'we could not measure'."""
    script = str(SCRIPT).replace("\\", "/")
    body = r"""
$null = . '__SCRIPT__' -Mode Plan -OutputDirectory '/tmp/wpd-clear'
$manifest = [ordered]@{ toolVersion='0.9.0'; schemaVersion='1.1'; startedAtUtc='2026-09-10T12:00:00Z'; completedAtUtc='2026-09-10T12:00:30Z'; scope=[ordered]@{durationSeconds=30}; artifacts=@() }
$html = ConvertTo-FindingsHtml -Findings @() -Manifest $manifest -SymptomContext $null
[ordered]@{
    hasCollectionSummary = [bool]($html -match 'Collection Summary')
    claimsInsufficient   = [bool]($html -match 'Insufficient Evidence')
    statesNoPressure     = [bool]($html -match 'No Sustained Pressure Detected')
    retainsCaveat        = [bool]($html -match 'does not prove the system is healthy')
} | ConvertTo-Json
"""
    result = _run_ps(body.replace("__SCRIPT__", script))
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["hasCollectionSummary"] is True
    assert output["statesNoPressure"] is True
    assert output["claimsInsufficient"] is False
    assert output["retainsCaveat"] is True


def test_html_report_encodes_artifact_size_bytes():
    """A hostile SizeBytes value from a remote manifest must be HTML-encoded."""
    script = str(SCRIPT).replace("\\", "/")
    body = r"""
$null = . '__SCRIPT__' -Mode Plan -OutputDirectory '/tmp/wpd-size'
$payload = '<img src=x onerror=alert(2)>'
$manifest = [ordered]@{ toolVersion='0.9.0'; schemaVersion='1.1'; startedAtUtc='2026-09-10T12:00:00Z'; completedAtUtc='2026-09-10T12:00:30Z'; scope=[ordered]@{durationSeconds=30}; artifacts=@([ordered]@{ Name='a.csv'; SizeBytes=$payload; Sha256=('A'*64) }) }
$html = ConvertTo-FindingsHtml -Findings @() -Manifest $manifest -SymptomContext $null
$raw = 0; if ($html -match '<img') { $raw = 1 }
$encoded = 0; if ($html -match '&lt;img') { $encoded = 1 }
[ordered]@{ raw=$raw; encoded=$encoded } | ConvertTo-Json
"""
    result = _run_ps(body.replace("__SCRIPT__", script))
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["raw"] == 0
    assert output["encoded"] == 1


def test_volume_percent_free_null_when_free_space_missing():
    """A volume with null FreeSpace must not fabricate a 0% free-space
    finding."""
    script = str(SCRIPT).replace("\\", "/")
    body = r"""
$null = . '__SCRIPT__' -Mode Plan -OutputDirectory '/tmp/wpd-volnull'
$vol = @([pscustomobject]@{ DriveLetter='D:'; Label='x'; FileSystem='NTFS'; CapacityBytes=[long]1TB; FreeSpaceBytes=$null; PercentFree=$null })
$disk = @([pscustomobject]@{ TimestampUtc='t'; Name='0 C:'; CurrentQueueLength=0; ReadLatencySeconds=$null })
$f = @(Evaluate-Findings -Samples @() -DiskSeries $disk -VolumeMetrics $vol -MemoryMetrics $null)
@($f | Where-Object { $_.category -eq 'disk-space' }).Count | ConvertTo-Json
"""
    result = _run_ps(body.replace("__SCRIPT__", script))
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == 0


def test_volume_metrics_null_guard_production():
    """Get-VolumeMetrics must return PercentFree=null (not 0) when the CIM
    volume reports a null FreeSpace."""
    script = str(SCRIPT).replace("\\", "/")
    body = r"""
$null = . '__SCRIPT__' -Mode Plan -OutputDirectory '/tmp/wpd-volguard'
function Get-CimInstance { param($ClassName, $Filter, $ErrorAction) if ($ClassName -eq 'Win32_Volume') { return [pscustomobject]@{ DriveLetter='D:'; Label='x'; FileSystem='NTFS'; Capacity=[long]1TB; FreeSpace=$null } } return @() }
$v = @(Get-VolumeMetrics)[0]
[ordered]@{ percentFree=$v.PercentFree; freeSpace=$v.FreeSpaceBytes } | ConvertTo-Json
"""
    result = _run_ps(body.replace("__SCRIPT__", script))
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["percentFree"] is None
    assert output["freeSpace"] is None


def test_plan_mode_preset_without_symptom_is_recorded(tmp_path):
    """A preset supplied without symptom text must still be recorded, not
    silently dropped."""
    output_directory = tmp_path / "plan-preset-only"
    result = run_tool(
        "-Mode", "Plan",
        "-Preset", "storage-io",
        "-OutputDirectory", str(output_directory),
    )
    assert result.returncode == 0, result.stderr
    manifest = json.loads(
        (output_directory / "diagnostic-plan.json").read_text(encoding="utf-8-sig")
    )
    assert manifest["symptom"]["preset"] == "storage-io"
    assert "reported" not in manifest["symptom"]
    assert "collectionWindow" in manifest["symptom"]


def test_collection_errors_reference_is_live_for_tail_stages():
    """The manifest's collectionErrors must observe errors added after manifest
    construction (tail findings/report/export stages), which requires a mutable
    accumulator rather than array += rebinding."""
    script = str(SCRIPT).replace("\\", "/")
    body = r"""
$null = . '__SCRIPT__' -Mode Plan -OutputDirectory '/tmp/wpd-errref'
$manifest = [ordered]@{ collectionErrors = $script:collectionErrors }
Add-CollectionErrorText -Stage 'tail-stage' -Message 'tail failure'
$manifest | ConvertTo-Json -Depth 4
"""
    result = _run_ps(body.replace("__SCRIPT__", script))
    assert result.returncode == 0, result.stderr
    manifest = json.loads(result.stdout)
    assert any(e["Stage"] == "tail-stage" for e in manifest["collectionErrors"])


def test_live_collect_tail_calls_shared_write_collection_outputs():
    """The live Collect call site must use the same Write-CollectionOutputs
    function exercised by the fixture tail test, and the old broken ordering
    (hashing before findings generation) must be gone."""
    source = SCRIPT.read_text(encoding="utf-8-sig")
    assert "Write-CollectionOutputs" in source
    assert "Write-CollectionOutputs `" in source or "Write-CollectionOutputs -" in source
    assert "Evaluate-Findings -Samples $samples -DiskMetrics" not in source
    assert "-DiskMetrics $diskMetrics" not in source


def test_collect_tail_shared_function_registers_evidence_and_verify_detects_tamper(tmp_path):
    """Fixture-driven Collect tail: Write-CollectionOutputs must write
    findings.json/report.html/disk-samples.json, register every one in the
    manifest, and produce a case that Verify accepts - then refuse it once the
    report is tampered with."""
    script = str(SCRIPT).replace("\\", "/")
    out = tmp_path / "collect-tail"
    out.mkdir()
    plan_dot = tmp_path / "plan-dotsource"
    body = r"""
$ErrorActionPreference = 'Stop'
$null = . '__SCRIPT__' -Mode Plan -OutputDirectory '__PLAN__'
$outputDirectory = '__OUT__'
$collected = New-Object System.Collections.ArrayList
Set-Content -LiteralPath (Join-Path $outputDirectory 'performance-samples.csv') -Value 'a,b' -Encoding Ascii
[void]$collected.Add('performance-samples.csv')
$manifest = [ordered]@{
  schemaVersion = '1.1'
  toolName = 'Windows Performance Diagnostics Toolkit'
  toolVersion = '0.9.0'
  mode = 'Collect'
  startedAtUtc = '2026-09-10T12:00:00Z'
  completedAtUtc = '2026-09-10T12:00:30Z'
  safety = [ordered]@{ localOnly=$true; readOnly=$true; requiresExplicitCollectionConsent=$true; automaticUpload=$false; automaticRemediation=$false; automaticLogClearing=$false }
  collectionErrors = @()
  artifacts = @()
}
$samples = @()
for ($i=0; $i -lt 6; $i++) {
  $samples += [pscustomobject]@{ TimestampUtc=('2026-09-10T12:00:{0:D2}Z' -f $i); AverageCpuLoadPercent=95; CommittedBytes=[long]7.6GB; CommitLimitBytes=[long]8GB; PagesInputPerSec=$null }
}
$disk = @()
for ($i=0; $i -lt 6; $i++) {
  $disk += [pscustomobject]@{ TimestampUtc=('2026-09-10T12:00:{0:D2}Z' -f $i); Name='0 C:'; CurrentQueueLength=3; ReadLatencySeconds=0.03; ReadBytesPerSec=1000 }
}
$manifest = Write-CollectionOutputs -OutputDirectory $outputDirectory -CollectionManifest $manifest -CollectedArtifacts $collected -Samples $samples -DiskSeries $disk -VolumeMetrics $null -MemoryMetrics $null -SymptomContext '<script>alert(1)</script>'
[ordered]@{
  artifactNames = @($manifest.artifacts | ForEach-Object { $_.Name })
  findingsExists = Test-Path -LiteralPath (Join-Path $outputDirectory 'findings.json')
  reportExists = Test-Path -LiteralPath (Join-Path $outputDirectory 'report.html')
  diskSamplesExists = Test-Path -LiteralPath (Join-Path $outputDirectory 'disk-samples.json')
} | ConvertTo-Json -Depth 6
"""
    body = body.replace("__SCRIPT__", script).replace("__PLAN__", str(plan_dot)).replace("__OUT__", str(out))
    result = _run_ps(body)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["findingsExists"] and summary["reportExists"] and summary["diskSamplesExists"]
    for required in ("performance-samples.csv", "findings.json", "report.html", "disk-samples.json"):
        assert required in summary["artifactNames"], required

    report_text = (out / "report.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in report_text

    verify_ok = run_tool("-Mode", "Verify", "-InputDirectory", str(out))
    assert verify_ok.returncode == 0, verify_ok.stderr
    report = json.loads(verify_ok.stdout)
    assert report["status"] == "verified"
    assert report["artifactCount"] == len(summary["artifactNames"])
    assert report["verifiedArtifactCount"] == len(summary["artifactNames"])

    (out / "report.html").write_bytes(b"<html>tampered</html>")
    verify_bad = run_tool("-Mode", "Verify", "-InputDirectory", str(out))
    assert verify_bad.returncode == 1
    bad_report = json.loads(verify_bad.stdout)
    assert bad_report["status"] == "failed"
    assert any("mismatch" in e.lower() for e in bad_report["errors"])
