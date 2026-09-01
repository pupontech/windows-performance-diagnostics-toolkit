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
        # bounded probes: mock New-Object for the .NET Ping (deterministic
        # Success regardless of host ICMP policy) and mock netstat; DNS uses
        # the real resolver (GitHub runners resolve public names)
        "class FakePing { [object] Send($target, $timeout) { return [pscustomobject]@{ Status = 'Success' } } [void] Dispose() {} }; "
        "function New-Object { param([string]$TypeName) if ($TypeName -eq 'System.Net.NetworkInformation.Ping') { return [FakePing]::new() }; return (Microsoft.PowerShell.Utility\\New-Object -TypeName $TypeName) }; "
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
    manifest_path = case / "diagnostic-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    zip_path = case.parent / "case-to-verify-20260901T000000.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("performance-samples.csv", (case / "performance-samples.csv").read_bytes())
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
    assert report["package"]["entryCount"] == 2


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
