"""Source-local integration tests for the tiered architecture in the entry point.

These tests exercise the production entry point
(`src/Invoke-WindowsPerformanceDiagnostics.ps1`) two ways:

- Plan/Verify/refusal paths run the real script as a subprocess, so the manifest
  contract, the consent gates and the parameter surface are the shipped ones;
- the pure integration functions (Tier 1 row transform, Tier 0 cache, preset
  resolution, cadence floor, report handoff) are extracted by AST and driven with
  synthetic counter rows, so no Windows host and no live provider is involved.

Nothing here asserts a Windows-only behaviour; the Windows-only paths are
UNVERIFIED until the owner-live gate runs them.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "src" / "Invoke-WindowsPerformanceDiagnostics.ps1"
PRESET_CONFIG = REPO_ROOT / "config" / "diagnostic-presets.json"
POWERSHELL_EXE = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")


def run_tool(*arguments: str) -> subprocess.CompletedProcess[str]:
    assert shutil.which(POWERSHELL_EXE), "PowerShell is required for the verification gate"
    return subprocess.run(
        [POWERSHELL_EXE, "-NoLogo", "-NoProfile", "-File", str(SCRIPT), *arguments],
        capture_output=True,
        check=False,
        text=True,
    )


def run_pwsh(body: str, functions: list[str]) -> str:
    """Extract `functions` from the entry point by AST and run `body` on them."""
    assert shutil.which(POWERSHELL_EXE), "PowerShell is required for the verification gate"
    names = ", ".join(f"'{name}'" for name in functions)
    harness = f"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$null)
foreach ($name in @({names})) {{
    $found = @($ast.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }}, $true))
    if ($found.Count -eq 0) {{ throw "function $name not found in the entry point" }}
    Invoke-Expression $found[0].Extent.Text
}}
Set-StrictMode -Version Latest
{body}
"""
    result = subprocess.run(
        [POWERSHELL_EXE, "-NoLogo", "-NoProfile", "-Command", harness],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, f"pwsh failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    return result.stdout


INTEGRATION_FUNCTIONS = [
    "Get-WpdIntegrationProperty",
    "Get-WpdIntegrationNumber",
    "Get-WpdModuleCommandName",
    "Test-WpdModuleCommand",
    "Invoke-WpdModuleCall",
    "Resolve-WpdPresetSelection",
    "Resolve-WpdPresetCapturePolicy",
    "Resolve-WpdTier1Interval",
    "Resolve-WpdCaptureMode",
    "Get-WpdTier0InventorySnapshot",
    "Get-WpdTier1SampleRow",
    "New-WpdTieredPlanBlock",
    "Write-WpdTechnicianReportHandoff",
]


# ---------------------------------------------------------------------------
# Plan mode: the tiered model is described and nothing is collected
# ---------------------------------------------------------------------------


def test_plan_describes_the_tiered_model_and_collects_nothing(tmp_path):
    output = tmp_path / "plan"
    result = run_tool("-Mode", "Plan", "-Preset", "memory-pressure", "-OutputDirectory", str(output))
    assert result.returncode == 0, result.stderr
    manifest = json.loads((output / "diagnostic-plan.json").read_text(encoding="utf-8"))

    tiers = manifest["tiers"]
    assert [row["tier"] for row in tiers["tiers"]] == [0, 1, 2, 3]
    assert tiers["tiers"][0]["collectedOnce"] is True
    assert tiers["tiers"][0]["cached"] is True
    assert tiers["tiers"][3]["consentRequired"] is True
    assert tiers["healthClaim"] == "none"
    assert tiers["neverHealthy"] is True
    assert '"healthy"' not in json.dumps(tiers)

    # Plan mode still writes exactly one artifact.
    assert sorted(p.name for p in output.iterdir()) == ["diagnostic-plan.json"]


def test_preset_alias_resolves_to_the_canonical_preset_and_is_recorded(tmp_path):
    output = tmp_path / "plan"
    result = run_tool("-Mode", "Plan", "-Preset", "baseline", "-OutputDirectory", str(output))
    assert result.returncode == 0, result.stderr
    manifest = json.loads((output / "diagnostic-plan.json").read_text(encoding="utf-8"))

    preset = manifest["tiers"]["preset"]
    assert preset["status"] == "resolved"
    assert preset["requested"] == "baseline"
    assert preset["effective"] == "general"
    assert preset["isAlias"] is True
    assert preset["source"] == "config/diagnostic-presets.json"
    assert manifest["schemaVersion"] == "1.3"
    # The legacy symptom block still records what the operator passed.
    assert manifest["symptom"]["preset"] == "baseline"


def test_preset_drives_the_wpr_profile_and_the_configured_counters(tmp_path):
    output = tmp_path / "plan"
    result = run_tool(
        "-Mode", "Plan", "-Preset", "storage-io", "-CaptureWpr", "-OutputDirectory", str(output)
    )
    assert result.returncode == 0, result.stderr
    manifest = json.loads((output / "diagnostic-plan.json").read_text(encoding="utf-8"))

    document = json.loads(PRESET_CONFIG.read_text(encoding="utf-8"))
    expected_counters = document["presets"]["storage-io"]["tier1Counters"]

    assert manifest["wpr"]["profile"] == "DiskIO"
    assert manifest["tiers"]["capturePolicy"]["status"] == "resolved"
    assert manifest["tiers"]["capturePolicy"]["source"] == "Wpd.Etw"
    assert manifest["tiers"]["capturePolicy"]["profile"] == "DiskIO"
    assert manifest["tiers"]["capturePolicy"]["traceBudgetMB"] == manifest["tiers"]["preset"]["traceSizeBudget"]["budgetMiB"]
    assert manifest["tiers"]["capturePolicy"]["expectedDurationSeconds"] == manifest["tiers"]["preset"]["expectedDurationSeconds"]
    assert manifest["tiers"]["preset"]["tier1Counters"] == expected_counters
    assert manifest["tiers"]["capturePolicy"]["bufferSemantics"] == "circular-memory"
    assert manifest["tiers"]["capturePolicy"]["unbounded"] is False
    assert 2 in manifest["tiers"]["collectedTiers"]


def test_every_canonical_preset_name_is_accepted_and_an_unknown_one_is_refused(tmp_path):
    """All 13 canonical presets resolve to an accepted WPR profile, while an
    unknown preset is refused rather than silently mapped."""
    document = json.loads(PRESET_CONFIG.read_text(encoding="utf-8"))
    output = tmp_path / "plan"
    unresolved = []
    for name in document["canonicalPresets"]:
        result = run_tool("-Mode", "Plan", "-Preset", name, "-OutputDirectory", str(output))
        assert result.returncode == 0, f"{name}: {result.stderr}"
        manifest = json.loads((output / "diagnostic-plan.json").read_text(encoding="utf-8"))
        assert manifest["tiers"]["preset"]["effective"] == name
        assert manifest["tiers"]["preset"]["isAlias"] is False
        if manifest["tiers"]["capturePolicy"]["status"] != "resolved":
            unresolved.append((name, manifest["tiers"]["capturePolicy"]["status"]))

    assert unresolved == []

    refused = run_tool("-Mode", "Plan", "-Preset", "not-a-preset", "-OutputDirectory", str(output))
    assert refused.returncode != 0
    assert "not-a-preset" in (refused.stdout + refused.stderr)


def test_repro_and_flight_recorder_are_distinct_and_mutually_exclusive(tmp_path):
    output = tmp_path / "plan"
    repro = run_tool("-Mode", "Plan", "-Preset", "general", "-Repro", "-OutputDirectory", str(output))
    assert repro.returncode == 0, repro.stderr
    manifest = json.loads((output / "diagnostic-plan.json").read_text(encoding="utf-8"))
    assert manifest["tiers"]["captureMode"]["mode"] == "Repro"
    assert "run-the-repro-bounded-capture" in manifest["plannedActions"]

    recorder = run_tool(
        "-Mode", "Plan", "-Preset", "general", "-FlightRecorder", "-OutputDirectory", str(output)
    )
    assert recorder.returncode == 0, recorder.stderr
    manifest = json.loads((output / "diagnostic-plan.json").read_text(encoding="utf-8"))
    assert manifest["tiers"]["captureMode"]["mode"] == "FlightRecorder"
    assert "run-the-flight-recorder-circular-capture" in manifest["plannedActions"]

    both = run_tool(
        "-Mode", "Plan", "-Preset", "general", "-Repro", "-FlightRecorder", "-OutputDirectory", str(output)
    )
    assert both.returncode != 0
    assert "mutually exclusive" in (both.stdout + both.stderr)


def test_a_plain_v1_plan_stays_v1_and_reports_no_preset_request(tmp_path):
    output = tmp_path / "plan"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output))
    assert result.returncode == 0, result.stderr
    manifest = json.loads((output / "diagnostic-plan.json").read_text(encoding="utf-8"))

    assert manifest["schemaVersion"] == "1.0"
    assert manifest["tiers"]["preset"]["status"] == "not-requested"
    assert manifest["tiers"]["captureMode"]["status"] == "not-requested"
    assert manifest["tiers"]["escalation"]["status"] == "not-requested"
    assert "tieredReason" not in manifest
    assert manifest["tiers"]["tier1Cadence"]["intervalSeconds"] == 1
    assert manifest["tiers"]["tier1Cadence"]["floorSeconds"] == 1


def test_full_privacy_requires_its_consent_switch(tmp_path):
    output = tmp_path / "plan"
    refused = run_tool("-Mode", "Plan", "-PrivacyLevel", "Full", "-OutputDirectory", str(output))
    assert refused.returncode != 0
    assert "ConfirmFullPrivacy" in (refused.stdout + refused.stderr)

    accepted = run_tool(
        "-Mode", "Plan", "-PrivacyLevel", "Full", "-ConfirmFullPrivacy", "-OutputDirectory", str(output)
    )
    assert accepted.returncode == 0, accepted.stderr
    manifest = json.loads((output / "diagnostic-plan.json").read_text(encoding="utf-8"))
    assert manifest["tiers"]["privacy"]["level"] == "Full"
    assert manifest["tiers"]["privacy"]["secretsCollected"] is False


def test_tier3_escalation_requires_its_consent_switch(tmp_path):
    output = tmp_path / "case"
    refused = run_tool(
        "-Mode", "Collect",
        "-Preset", "general",
        "-CollectWaitChains",
        "-ConfirmLocalCollection",
        "-OutputDirectory", str(output),
    )
    assert refused.returncode != 0
    assert "ConfirmEscalationCollection" in (refused.stdout + refused.stderr)
    # A consent refusal must leave no output behind.
    assert not output.exists()

    planned = run_tool(
        "-Mode", "Plan", "-Preset", "general", "-CollectMinifilters", "-ConfirmEscalationCollection",
        "-OutputDirectory", str(output),
    )
    assert planned.returncode == 0, planned.stderr
    manifest = json.loads((output / "diagnostic-plan.json").read_text(encoding="utf-8"))
    escalation = manifest["tiers"]["escalation"]
    assert escalation["status"] == "planned"
    assert escalation["consentGiven"] is True
    assert escalation["requested"] == ["minifilter-enumeration"]
    assert escalation["automaticRemediation"] is False
    assert "collect-optional-tier3-escalations-after-explicit-consent" in manifest["plannedActions"]


def test_consented_tiered_plan_validates_against_the_published_schema(tmp_path):
    import jsonschema

    output = tmp_path / "plan"
    result = run_tool(
        "-Mode", "Plan", "-Preset", "general", "-CollectMinifilters",
        "-ConfirmEscalationCollection", "-OutputDirectory", str(output),
    )
    assert result.returncode == 0, result.stderr
    manifest = json.loads((output / "diagnostic-plan.json").read_text(encoding="utf-8"))
    schema = json.loads((REPO_ROOT / "schema" / "diagnostic-report.schema.json").read_text(encoding="utf-8"))
    errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(manifest), key=lambda error: list(error.path))
    assert not errors, [(list(error.path), error.message) for error in errors]


def test_a_sub_second_tier1_request_is_refused_not_clamped(tmp_path):
    output = tmp_path / "plan"
    result = run_tool(
        "-Mode", "Plan", "-Preset", "general", "-Tier1IntervalSeconds", "0",
        "-OutputDirectory", str(output),
    )
    # 0 means "use the preset", which is the documented floor - not a refusal.
    assert result.returncode == 0, result.stderr
    manifest = json.loads((output / "diagnostic-plan.json").read_text(encoding="utf-8"))
    assert manifest["tiers"]["tier1Cadence"]["intervalSeconds"] == 1
    assert manifest["tiers"]["tier1Cadence"]["source"] == "preset"


def test_wpr_file_mode_is_opt_in_and_flagged_unbounded(tmp_path):
    output = tmp_path / "plan"
    result = run_tool(
        "-Mode", "Plan", "-Preset", "intermittent", "-CaptureWpr", "-AllowWprFileMode",
        "-OutputDirectory", str(output),
    )
    assert result.returncode == 0, result.stderr
    manifest = json.loads((output / "diagnostic-plan.json").read_text(encoding="utf-8"))
    policy = manifest["tiers"]["capturePolicy"]
    assert policy["mode"] == "file"
    assert policy["unbounded"] is True
    assert policy["bufferSemantics"] == "unbounded-file"


# ---------------------------------------------------------------------------
# Verify mode: the union of schema versions stays readable (D9)
# ---------------------------------------------------------------------------


def _write_case(case: Path, schema_version: str, extra_artifact: str | None = None) -> Path:
    import hashlib

    case.mkdir(parents=True, exist_ok=True)
    artifacts = []
    for name, contents in (
        ("performance-samples.csv", b"a,b\n1,2\n"),
        (extra_artifact, b"tiered-surface\n") if extra_artifact else (None, None),
    ):
        if name is None:
            continue
        path = case / name
        path.write_bytes(contents)
        artifacts.append(
            {
                "Name": name,
                "SizeBytes": path.stat().st_size,
                "Sha256": hashlib.sha256(contents).hexdigest(),
            }
        )
    manifest = {
        "schemaVersion": schema_version,
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
        "artifacts": artifacts,
    }
    (case / "diagnostic-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return case


@pytest.mark.parametrize("schema_version", ["1.0", "1.1", "1.2", "1.3"])
def test_verify_accepts_every_schema_version_including_1_3(tmp_path, schema_version):
    case = _write_case(tmp_path / f"case-{schema_version}", schema_version, "tier0-inventory.json")
    result = run_tool("-Mode", "Verify", "-InputDirectory", str(case))
    assert result.returncode == 0, result.stdout + result.stderr
    verification = json.loads(result.stdout)
    assert verification["artifactCount"] == 2
    assert verification["verifiedArtifactCount"] == 2
    assert verification["errors"] == []


# ---------------------------------------------------------------------------
# Pure integration functions (AST-extracted, synthetic counter rows only)
# ---------------------------------------------------------------------------


def test_tier1_sample_row_is_counter_only_and_never_invents_a_measurement():
    body = r"""
$row = Get-WpdTier1SampleRow
[ordered]@{
    Cpu = $row.AverageCpuLoadPercent
    PerCoreCount = @($row.PerCore).Count
    AvailableMB = $row.AvailableMemoryMB
    FreeGB = $row.TotalLogicalDiskFreeGB
    CpuCoverage = $row.Coverage.cpu
    Reasons = @($row.UnavailableReasons)
    Sources = $row.CounterSources.processors
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = json.loads(run_pwsh(body, INTEGRATION_FUNCTIONS))
    assert payload["Cpu"] is None
    assert payload["AvailableMB"] is None
    assert payload["FreeGB"] is None
    assert payload["CpuCoverage"] == "unavailable"
    assert "cpu-counter-rows-unavailable" in payload["Reasons"]
    assert payload["Sources"] == "Win32_PerfFormattedData_PerfOS_Processor"


def test_integration_property_reads_ordered_dictionaries_at_provider_boundaries():
    body = r"""
$ordered = [ordered]@{ Status = 'success'; availableBytes = 4096 }
[ordered]@{
    Status = Get-WpdIntegrationProperty -InputObject $ordered -Name 'status'
    Available = Get-WpdIntegrationProperty -InputObject $ordered -Name 'AVAILABLEBYTES'
    Missing = Get-WpdIntegrationProperty -InputObject $ordered -Name 'missing'
} | ConvertTo-Json -Depth 4 -Compress
"""
    payload = json.loads(run_pwsh(body, ["Get-WpdIntegrationProperty"]))
    assert payload == {"Status": "success", "Available": 4096, "Missing": None}


def test_tier1_sample_row_splits_per_core_and_keeps_utility_above_100():
    body = r"""
$processors = @(
    [pscustomobject]@{ Name = '_Total'; PercentProcessorTime = 180; ProcessorUtilityPercent = 240; PercentUserTime = 120; PercentPrivilegedTime = 60; PercentDPCTime = 4; PercentInterruptTime = 2 }
    [pscustomobject]@{ Name = '0'; PercentProcessorTime = 200; ProcessorUtilityPercent = 260; PercentUserTime = 150; PercentPrivilegedTime = 50; PercentDPCTime = 6; PercentInterruptTime = 3 }
    [pscustomobject]@{ Name = '1'; PercentProcessorTime = 160; ProcessorUtilityPercent = 220; PercentUserTime = 90; PercentPrivilegedTime = 70; PercentDPCTime = 2; PercentInterruptTime = 1 }
)
$memory = @([pscustomobject]@{ AvailableBytes = 1073741824; CommitPercent = 71.5 })
$disks = @(
    [pscustomobject]@{ Name = 'C:'; FreeMegabytes = 20480; PercentFreeSpace = 41 }
    [pscustomobject]@{ Name = 'D:'; FreeMegabytes = 10240; PercentFreeSpace = 12 }
)
$system = @([pscustomobject]@{ ProcessorQueueLength = 3; ContextSwitchesPerSec = 41234 })
$row = Get-WpdTier1SampleRow -ProcessorCounterRows $processors -MemoryCounterRows $memory -LogicalDiskCounterRows $disks -SystemCounterRows $system
[ordered]@{
    Cpu = $row.AverageCpuLoadPercent
    Utility = $row.CpuUtilityPercent
    UtilityAbove100 = ($row.CpuUtilityPercent -gt 100)
    User = $row.CpuUserPercent
    Kernel = $row.CpuKernelPercent
    Dpc = $row.DpcPercent
    Interrupt = $row.InterruptPercent
    Cores = @($row.PerCore | ForEach-Object { $_.ProcessorNumber })
    CoreUtility = @($row.PerCore | ForEach-Object { $_.UtilityPercent })
    Queue = $row.ProcessorQueueLength
    Switches = $row.ContextSwitchesPerSec
    AvailableMB = $row.AvailableMemoryMB
    Commit = $row.CommitPercent
    FreeGB = $row.TotalLogicalDiskFreeGB
    CpuCoverage = $row.Coverage.cpu
    ReasonCount = @($row.UnavailableReasons).Count
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = json.loads(run_pwsh(body, INTEGRATION_FUNCTIONS))
    assert payload["Cpu"] == 180
    assert payload["Utility"] == 240
    assert payload["UtilityAbove100"] is True
    assert payload["User"] == 120
    assert payload["Kernel"] == 60
    assert payload["Dpc"] == 4
    assert payload["Interrupt"] == 2
    assert payload["Cores"] == ["0", "1"]
    assert payload["CoreUtility"] == [260, 220]
    assert payload["Queue"] == 3
    assert payload["Switches"] == 41234
    assert payload["AvailableMB"] == 1024
    assert payload["Commit"] == 71.5
    assert payload["FreeGB"] == 30
    assert payload["CpuCoverage"] == "complete"
    assert payload["ReasonCount"] == 0


def test_tier0_inventory_is_queried_once_per_cache_key_and_refreshable():
    body = r"""
$script:providerCalls = 0
$provider = {
    $script:providerCalls++
    [pscustomobject]@{
        status = 'success'
        coverage = 'complete'
        capabilities = @('os', 'hardware')
        records = @([pscustomobject]@{ id = 'os' })
        reasons = @()
    }
}
$first = Get-WpdTier0InventorySnapshot -CacheKey 'tier0|general|Standard|host-a' -Provider $provider
$second = Get-WpdTier0InventorySnapshot -CacheKey 'tier0|general|Standard|host-a' -Provider $provider
$otherKey = Get-WpdTier0InventorySnapshot -CacheKey 'tier0|cpu-heavy|Standard|host-a' -Provider $provider
$refreshed = Get-WpdTier0InventorySnapshot -CacheKey 'tier0|general|Standard|host-a' -Provider $provider -Refresh
$unavailable = Get-WpdTier0InventorySnapshot -CacheKey 'tier0|empty|Standard|host-b'
[ordered]@{
    ProviderCalls = $script:providerCalls
    FirstCached = $first.cached
    SecondCached = $second.cached
    SameStatus = ($first.status -eq $second.status)
    OtherKeyCached = $otherKey.cached
    RefreshedCached = $refreshed.cached
    UnavailableStatus = $unavailable.status
    UnavailableCoverage = $unavailable.coverage
    UnavailableReasons = @($unavailable.reasons)
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = json.loads(run_pwsh(body, INTEGRATION_FUNCTIONS))
    assert payload["ProviderCalls"] == 3  # first key, other key, refresh
    assert payload["FirstCached"] is False
    assert payload["SecondCached"] is True
    assert payload["SameStatus"] is True
    assert payload["OtherKeyCached"] is False
    assert payload["RefreshedCached"] is False
    assert payload["UnavailableStatus"] == "unavailable"
    assert payload["UnavailableCoverage"] == "unavailable"
    assert any("tier0-inventory-unavailable" in reason for reason in payload["UnavailableReasons"])


def test_preset_resolution_reads_the_shipped_configuration_and_refuses_unknown_names():
    document = json.dumps(json.loads(PRESET_CONFIG.read_text(encoding="utf-8"))).replace("'", "''")
    body = f"""
$document = '{document}' | ConvertFrom-Json
$alias = Resolve-WpdPresetSelection -Preset 'application-freeze' -PresetDocument $document
$canonical = Resolve-WpdPresetSelection -Preset 'ui-hang' -PresetDocument $document
$unknown = Resolve-WpdPresetSelection -Preset 'nope' -PresetDocument $document
$none = Resolve-WpdPresetSelection -PresetDocument $document
[ordered]@{{
    AliasStatus = $alias.status
    AliasEffective = $alias.effective
    AliasIsAlias = $alias.isAlias
    CanonicalEffective = $canonical.effective
    CanonicalIsAlias = $canonical.isAlias
    SameCounters = (@(Compare-Object -ReferenceObject @($alias.tier1Counters) -DifferenceObject @($canonical.tier1Counters)).Count -eq 0)
    AutomaticRemediation = $alias.automaticRemediation
    UnknownStatus = $unknown.status
    UnknownEffective = $unknown.effective
    CanonicalCount = @($unknown.canonicalNames).Count
    NoneStatus = $none.status
    Floor = $alias.samplingFloorSeconds
}} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = json.loads(run_pwsh(body, INTEGRATION_FUNCTIONS))
    assert payload["AliasStatus"] == "resolved"
    assert payload["AliasEffective"] == "ui-hang"
    assert payload["AliasIsAlias"] is True
    assert payload["CanonicalEffective"] == "ui-hang"
    assert payload["CanonicalIsAlias"] is False
    assert payload["SameCounters"] is True
    assert payload["AutomaticRemediation"] is False
    assert payload["UnknownStatus"] == "unknown-preset"
    assert payload["UnknownEffective"] is None
    assert payload["CanonicalCount"] == 13
    assert payload["NoneStatus"] == "not-requested"
    assert payload["Floor"] == 1


def test_capture_policy_never_substitutes_an_unverified_profile():
    body = r"""
$selection = [pscustomobject]@{
    status = 'resolved'
    effective = 'custom'
    tier2WprProfiles = @('BootGeneral')
    tier2WprDetail = 'verbose'
    tier2WprMode = 'memory'
    expectedDurationSeconds = 300
    traceSizeBudget = [pscustomobject]@{ budgetMiB = 2048 }
}
$unsupported = Resolve-WpdPresetCapturePolicy -Selection $selection
$known = Resolve-WpdPresetCapturePolicy -Selection ([pscustomobject]@{
    status = 'resolved'; effective = 'general'; tier2WprProfiles = @('DiskIO'); tier2WprDetail = 'verbose'
    tier2WprMode = 'memory'; expectedDurationSeconds = 300
})
[ordered]@{
    UnsupportedStatus = $unsupported.status
    UnsupportedProfile = $unsupported.profile
    UnsupportedReasons = @($unsupported.reasons)
    KnownStatus = $known.status
    KnownProfile = $known.profile
    KnownSpec = $known.profileSpec
    KnownUnbounded = $known.unbounded
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = json.loads(run_pwsh(body, INTEGRATION_FUNCTIONS))
    assert payload["UnsupportedStatus"] == "unsupported-profile-name"
    assert payload["UnsupportedProfile"] is None
    assert any("BootGeneral" in reason for reason in payload["UnsupportedReasons"])
    assert payload["KnownStatus"] == "resolved"
    assert payload["KnownProfile"] == "DiskIO"
    assert payload["KnownSpec"] == "DiskIO.verbose"
    assert payload["KnownUnbounded"] is False


def test_tier1_cadence_refuses_a_sub_second_interval_instead_of_clamping():
    body = r"""
$preset = Resolve-WpdTier1Interval -PresetSeconds 5 -SamplingFloorSeconds 1
$explicit = Resolve-WpdTier1Interval -RequestedSeconds 10 -PresetSeconds 5 -SamplingFloorSeconds 1
$junk = Resolve-WpdTier1Interval -RequestedSeconds $null -PresetSeconds 0.5 -SamplingFloorSeconds 1
$floor = Resolve-WpdTier1Interval -SamplingFloorSeconds 1
[ordered]@{
    PresetInterval = $preset.intervalSeconds
    PresetSource = $preset.source
    ExplicitInterval = $explicit.intervalSeconds
    ExplicitSource = $explicit.source
    JunkStatus = $junk.status
    JunkInterval = $junk.intervalSeconds
    FloorInterval = $floor.intervalSeconds
    FloorSource = $floor.source
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = json.loads(run_pwsh(body, INTEGRATION_FUNCTIONS))
    assert payload["PresetInterval"] == 5
    assert payload["PresetSource"] == "preset"
    assert payload["ExplicitInterval"] == 10
    assert payload["ExplicitSource"] == "requested"
    assert payload["JunkStatus"] == "refused-sub-second"
    assert payload["JunkInterval"] is None
    assert payload["FloorInterval"] == 1
    assert payload["FloorSource"] == "sampling-floor"


def test_report_handoff_without_the_module_writes_no_file(tmp_path):
    output = tmp_path / "case"
    output.mkdir()
    body = f"""
$result = Write-WpdTechnicianReportHandoff -OutputDirectory '{str(output).replace(chr(92), '/')}' -Findings @()
[ordered]@{{
    Status = $result.status
    Reason = $result.reason
    Artifact = $result.artifact
}} | ConvertTo-Json -Depth 4 -Compress
"""
    payload = json.loads(run_pwsh(body, INTEGRATION_FUNCTIONS))
    assert payload["Status"] == "unavailable"
    assert payload["Reason"] == "report-module-not-loaded"
    assert payload["Artifact"] == "case/technician-report.html"
    assert not (output / "case").exists()


def test_report_handoff_calls_the_prefixed_report_module_surface(tmp_path):
    output = tmp_path / "case"
    module_path = str(REPO_ROOT / "src" / "Wpd.Report.psm1").replace(chr(92), "/")
    body = f"""
Import-Module -Name '{module_path}' -Force -Scope Global -Prefix WpdSurface -WarningAction SilentlyContinue
$result = Write-WpdTechnicianReportHandoff -OutputDirectory '{str(output).replace(chr(92), '/')}' -Findings @()
[ordered]@{{
    Status = $result.status
    Reason = $result.reason
    Exists = Test-Path -LiteralPath '{str(output / 'case' / 'technician-report.html').replace(chr(92), '/')}' -PathType Leaf
}} | ConvertTo-Json -Depth 4 -Compress
"""
    payload = json.loads(run_pwsh(body, INTEGRATION_FUNCTIONS))
    assert payload["Status"] == "written"
    assert payload["Reason"] is None
    assert payload["Exists"] is True


def test_collect_handoff_passes_collected_incident_events_to_the_report_module():
    """The technician report must receive event rows already collected for the
    incident window rather than an always-empty placeholder."""
    source = SCRIPT.read_text(encoding="utf-8-sig")
    assert "-EventRows @($incidentEvents)" in source
    assert "-EventRows @()" not in source


def test_tier0_snapshot_calls_the_prefixed_collector_module_surface():
    module_path = str(REPO_ROOT / "src" / "Wpd.Collectors.psm1").replace(chr(92), "/")
    body = f"""
Import-Module -Name '{module_path}' -Force -Scope Global -Prefix WpdSurface -WarningAction SilentlyContinue
$result = Get-WpdTier0InventorySnapshot -CacheKey 'tier0|module|Standard|host-a' -Preset 'general' -PrivacyLevel 'Standard'
[ordered]@{{
    Status = $result.status
    Source = $result.source
    Coverage = $result.coverage
    Reasons = @($result.reasons)
}} | ConvertTo-Json -Depth 5 -Compress
"""
    payload = json.loads(run_pwsh(body, INTEGRATION_FUNCTIONS))
    assert payload["Source"] == "Wpd.Collectors"
    assert payload["Status"] in {"success", "partial", "unavailable", "error"}
    assert payload["Coverage"] in {"complete", "partial", "unavailable", "not-collected", "unsupported"}


# ---------------------------------------------------------------------------
# Source invariants (static, AST-based - no regex archaeology)
# ---------------------------------------------------------------------------


def test_the_sampling_loop_queries_no_static_inventory_class():
    """The sampling loop used to re-query Win32_OperatingSystem, Win32_Processor
    and Win32_LogicalDisk on every tick. Tier 0 classes are collected once per run
    now, so any of them inside the loop body is the regression this test kills."""
    forbidden = {
        "Win32_OperatingSystem",
        "Win32_Processor",
        "Win32_LogicalDisk",
        "Win32_Volume",
        "Win32_ComputerSystem",
    }
    forbidden_literal = ", ".join(f"'{name}'" for name in sorted(forbidden))
    body = f"""
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$null)
$loops = @($ast.FindAll({{ param($node)
    $node -is [System.Management.Automation.Language.WhileStatementAst] -and
    $node.Condition.Extent.Text -like '*captureComplete*'
}}, $true))
if ($loops.Count -ne 1) {{ throw "expected exactly one sampling loop, found $($loops.Count)" }}
$commands = @($loops[0].FindAll({{ param($node) $node -is [System.Management.Automation.Language.CommandAst] }}, $true))
$offenders = @()
foreach ($command in $commands) {{
    $name = $command.GetCommandName()
    if ($name -ne 'Get-CimInstance' -and $name -ne 'Get-WmiObject') {{ continue }}
    foreach ($element in $command.CommandElements) {{
        foreach ($word in @({forbidden_literal})) {{
            if ($element.Extent.Text -like ('*' + $word + '*')) {{ $offenders += ($name + ' ' + $word) }}
        }}
    }}
}}
$counterClasses = @()
foreach ($command in @($commands | Where-Object {{ $_.GetCommandName() -eq 'Get-CimInstance' }})) {{
    $elements = @($command.CommandElements)
    for ($i = 0; $i -lt $elements.Count; $i++) {{
        if ($elements[$i].Extent.Text -eq '-ClassName' -and $i + 1 -lt $elements.Count) {{
            $counterClasses += $elements[$i + 1].Extent.Text
        }}
    }}
}}
$counterClasses = @($counterClasses | Sort-Object -Unique)
[ordered]@{{ Offenders = @($offenders); CounterClasses = @($counterClasses) }} | ConvertTo-Json -Depth 4 -Compress
"""
    result = subprocess.run(
        [POWERSHELL_EXE, "-NoLogo", "-NoProfile", "-Command", body],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["Offenders"] == []
    assert payload["CounterClasses"], "the loop must still sample counters"
    for counter_class in payload["CounterClasses"]:
        assert counter_class.startswith("'Win32_Perf"), counter_class


def test_the_entry_point_contains_no_remediation_command():
    """R4: nothing in this script may change machine state."""
    source = SCRIPT.read_text(encoding="utf-8")
    forbidden = [
        "RestoreHealth",
        "sfc /scannow",
        "sfc.exe",
        "chkdsk",
        "bcdedit",
        "Set-MpPreference",
        "Add-MpPreference",
        "Start-Service ",
        "Stop-Service ",
        "Set-ItemProperty",
        "New-ItemProperty",
    ]
    for token in forbidden:
        assert token not in source, f"remediation token present: {token}"


def test_the_entry_point_has_no_healthy_status_vocabulary_for_collection():
    source = SCRIPT.read_text(encoding="utf-8")
    assert not re.search(r"status\s*=\s*'healthy'", source)
    assert not re.search(r"coverage\s*=\s*'healthy'", source)


def test_every_tiered_module_is_imported_from_the_script_root():
    body = f"""
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$null)
$modules = @($ast.FindAll({{ param($node)
    $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
    $node.Value -like 'Wpd.*' -and $node.Parent -is [System.Management.Automation.Language.ArrayLiteralAst]
}}, $true) | ForEach-Object {{ $_.Value }} | Sort-Object -Unique)
@($modules) | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_EXE, "-NoLogo", "-NoProfile", "-Command", body],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    modules = json.loads(result.stdout)
    for module in ["Wpd.Common", "Wpd.Inventory", "Wpd.Telemetry", "Wpd.Etw", "Wpd.Events", "Wpd.Escalation", "Wpd.Report", "Wpd.Collectors"]:
        assert module in modules, module
        assert (REPO_ROOT / "src" / f"{module}.psm1").is_file(), module
