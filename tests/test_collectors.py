"""Behavioral tests for the WPD collector orchestration module.

The module is imported into pwsh and every provider, clock, command runner and
filesystem root is injected. Linux runs therefore exercise the composition
contract - ordering, caching, cadence validation, bounded storage, consent,
envelopes, cleanup and self-monitoring - without touching a Windows collector.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE = REPO_ROOT / "src" / "Wpd.Collectors.psm1"


def run_pwsh(body: str, modules: list[str] | None = None) -> str:
    """Import the real collector module and execute a PowerShell test body.

    By default only ``Wpd.Collectors`` is imported, so a test that succeeds
    proves the module composed its own dependencies.
    """
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    if not shutil.which(powershell):
        pytest.skip(f"{powershell} is required for the collector module tests")
    names = list(modules or [])
    imports = ["Import-Module -Name '{0}' -Force".format(str(MODULE).replace("'", "''"))]
    for name in names:
        path = str(REPO_ROOT / "src" / name).replace("'", "''")
        imports.insert(0, "Import-Module -Name '{0}' -Force".format(path))
    harness = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            *imports,
            "Set-StrictMode -Version Latest",
            body,
        ]
    )
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-Command", harness],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, (
        f"pwsh failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    return result.stdout.strip()


def run_json(body: str, modules: list[str] | None = None):
    output = run_pwsh(body, modules=modules)
    assert output, "PowerShell body did not emit JSON"
    return json.loads(output)


def run_text(body: str, modules: list[str] | None = None) -> str:
    return run_pwsh(body, modules=modules)


REQUIRED_COMMANDS = [
    "Clear-WpdCollectorTier0Cache",
    "Get-WpdCaptureStrategy",
    "Get-WpdCollectorPerformanceReport",
    "Get-WpdCollectorTier0CacheKey",
    "Get-WpdCollectorTierMap",
    "Get-WpdDefenderSearchContext",
    "Get-WpdFilterContext",
    "Get-WpdGpuContext",
    "Get-WpdNetworkContext",
    "Get-WpdPowerContext",
    "Get-WpdStorageReliabilityContext",
    "Invoke-WpdCollectorPlan",
    "Invoke-WpdTier0Collection",
    "Invoke-WpdTier1Collection",
    "Invoke-WpdTier2Collection",
    "Invoke-WpdTier3Collection",
    "New-WpdBootCollectionDescriptor",
    "New-WpdCollectorEnvelope",
    "New-WpdCollectorPlan",
    "New-WpdCollectorSelfMonitoring",
    "Remove-WpdCollectorArtifact",
    "Test-WpdCaptureStorageBound",
]

INVENTORY_CAPABILITIES = [
    "drivers",
    "encryption",
    "filters",
    "hardware",
    "nic",
    "os",
    "pagefiles",
    "power",
    "recentChanges",
    "security",
    "services",
    "startup",
    "storage",
    "virtualization",
]


def test_importing_only_the_collector_module_exports_the_documented_surface():
    """The module loads on a non-Windows host, imports its own dependencies and
    exports exactly the documented command surface."""
    body = """
$exported = @((Get-Command -Module 'Wpd.Collectors' -CommandType Function).Name)
[pscustomobject]@{
    Loaded = $true
    Exported = $exported
    Count = $exported.Count
    TierMapReachable = (@(Get-WpdCollectorTierMap).Count -gt 0)
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_json(body)

    exported = set(payload["Exported"])
    missing = sorted(set(REQUIRED_COMMANDS) - exported)
    extras = sorted(exported - set(REQUIRED_COMMANDS))
    assert missing == [], f"module does not export: {missing}"
    assert extras == [], f"module exports undocumented commands: {extras}"
    assert payload["Count"] == len(exported)
    assert payload["TierMapReachable"] is True


def test_tier_map_covers_every_tier_and_reuses_the_tier0_capability_map():
    """Tier 0 rows are the inventory capability map, Tier 1 rows are the
    interval counter families, Tier 2 is the trace and Tier 3 is the consented
    escalation set - with elevation, source and privacy shape on every row."""
    body = """
$map = @(Get-WpdCollectorTierMap)
[pscustomobject]@{
    Rows = @($map | ForEach-Object {
        "{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f $_.id, $_.tier, $_.source, $_.requiredElevation, $_.cached, $_.consentRequired, $_.windowsOnly
    })
    Tier0Ids = @($map | Where-Object { $_.tier -eq 0 } | ForEach-Object { $_.id }) | Sort-Object
    Tier1Ids = @($map | Where-Object { $_.tier -eq 1 } | ForEach-Object { $_.id }) | Sort-Object
    Tier3Ids = @($map | Where-Object { $_.tier -eq 3 } | ForEach-Object { $_.id }) | Sort-Object
    Ordered = (@($map | ForEach-Object { $_.tier }) -join ',')
    UniqueIds = @($map | Group-Object id | Where-Object { $_.Count -gt 1 }).Count
    Tier0Uncached = @($map | Where-Object { $_.tier -eq 0 -and -not $_.cached }).Count
    Tier0Consent = @($map | Where-Object { $_.tier -eq 0 -and $_.consentRequired }).Count
    Tier1Cached = @($map | Where-Object { $_.tier -eq 1 -and $_.cached }).Count
    Tier1Consent = @($map | Where-Object { $_.tier -eq 1 -and $_.consentRequired }).Count
    Tier2Rows = @($map | Where-Object { $_.tier -eq 2 }).Count
    Tier3Unconsented = @($map | Where-Object { $_.tier -eq 3 -and -not $_.consentRequired }).Count
    MissingSource = @($map | Where-Object { [string]::IsNullOrWhiteSpace($_.source) }).Count
    MissingReason = @($map | Where-Object { [string]::IsNullOrWhiteSpace($_.elevationReason) }).Count
    MissingShape = @($map | Where-Object { [string]::IsNullOrWhiteSpace($_.dataShape) }).Count
    BadElevation = @($map | Where-Object { $_.tier -lt 3 -and $_.requiredElevation -notin @('standard', 'administrator') }).Count
    UnstatedTier3Elevation = @($map | Where-Object { $_.tier -eq 3 -and $_.requiredElevation -ne 'not-stated' }).Count
    NonWindows = @($map | Where-Object { $_.windowsOnly -ne $true }).Count
    HealthyClaims = @($map | Where-Object { $null -ne $_.PSObject.Properties['status'] -or $null -ne $_.PSObject.Properties['coverage'] }).Count
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body, modules=["Wpd.Inventory.psm1", "Wpd.Escalation.psm1"])

    assert payload["Tier0Ids"] == INVENTORY_CAPABILITIES
    assert payload["Tier0Uncached"] == 0
    assert payload["Tier0Consent"] == 0
    assert payload["Tier1Cached"] == 0
    assert payload["Tier1Consent"] == 0
    assert payload["Tier3Unconsented"] == 0
    assert payload["Tier2Rows"] == 1
    assert payload["UniqueIds"] == 0
    assert payload["MissingSource"] == 0
    assert payload["MissingReason"] == 0
    assert payload["MissingShape"] == 0
    assert payload["BadElevation"] == 0
    assert payload["UnstatedTier3Elevation"] == 0
    assert payload["NonWindows"] == 0
    assert payload["HealthyClaims"] == 0
    assert payload["Tier1Ids"] == [
        "cpu",
        "gpu-engines",
        "kernel-pool",
        "memory",
        "network",
        "pagefile",
        "perflib",
        "process",
        "storage-io",
    ]
    # Tier 3 is the escalation descriptor set, so every documented adapter id is present.
    assert set(payload["Tier3Ids"]) >= {
        "defender",
        "minifilter",
        "procdump",
        "search",
        "wct",
    }
    tiers = [int(value) for value in payload["Ordered"].split(",")]
    assert tiers == sorted(tiers), "the tier map must be ordered by tier"


def test_tier_map_marks_only_tier0_as_cacheable_and_tier2_as_an_elevated_trace():
    """Caching and elevation are per-row facts: the trace needs administrator,
    Tier 0 is cached once per run, and the interval collectors are neither."""
    body = """
$map = @(Get-WpdCollectorTierMap)
[pscustomobject]@{
    TraceElevation = ($map | Where-Object { $_.id -eq 'trace' }).requiredElevation
    TraceCached = ($map | Where-Object { $_.id -eq 'trace' }).cached
    TraceShape = ($map | Where-Object { $_.id -eq 'trace' }).dataShape
    OsShape = ($map | Where-Object { $_.id -eq 'os' }).dataShape
    CpuShape = ($map | Where-Object { $_.id -eq 'cpu' }).dataShape
    FilterElevation = ($map | Where-Object { $_.id -eq 'filters' }).requiredElevation
    CachedIds = @($map | Where-Object { $_.cached } | ForEach-Object { $_.id }) | Sort-Object
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_json(body, modules=["Wpd.Inventory.psm1", "Wpd.Escalation.psm1"])

    assert payload["TraceElevation"] == "administrator"
    assert payload["TraceCached"] is False
    assert payload["TraceShape"] == "trace"
    assert payload["OsShape"] == "inventory"
    assert payload["CpuShape"] == "interval-counters"
    assert payload["FilterElevation"] == "administrator"
    assert payload["CachedIds"] == INVENTORY_CAPABILITIES


def test_tier0_cache_key_is_deterministic_and_privacy_bound():
    """One run key per preset/privacy/host: the same run resolves to the same
    key, and a different privacy level is a different key."""
    body = """
$first = Get-WpdCollectorTier0CacheKey -Preset 'general' -PrivacyLevel 'Standard' -HostFingerprint 'host-a'
$second = Get-WpdCollectorTier0CacheKey -Preset 'general' -PrivacyLevel 'Standard' -HostFingerprint 'host-a'
$redacted = Get-WpdCollectorTier0CacheKey -Preset 'general' -PrivacyLevel 'Redacted' -HostFingerprint 'host-a'
$otherPreset = Get-WpdCollectorTier0CacheKey -Preset 'cpu-heavy' -PrivacyLevel 'Standard' -HostFingerprint 'host-a'
[pscustomobject]@{
    First = $first
    Second = $second
    Redacted = $redacted
    OtherPreset = $otherPreset
    Explicit = (Get-WpdCollectorTier0CacheKey -CacheKey 'run-42')
} | ConvertTo-Json -Depth 4 -Compress
"""
    payload = run_json(body)

    assert payload["First"] == payload["Second"]
    assert payload["First"].startswith("tier0|")
    assert "preset=general" in payload["First"]
    assert "privacy=Standard" in payload["First"]
    assert payload["Redacted"] != payload["First"]
    assert payload["OtherPreset"] != payload["First"]
    assert payload["Explicit"] == "run-42"


def test_envelope_never_turns_an_empty_or_healthy_label_into_a_measurement():
    """The envelope inherits the common no-data-is-not-health rule: an empty
    successful collector, or one labelled healthy, is unavailable with an
    explicit reason - the tier and the collector id are always recorded."""
    body = """
$empty = New-WpdCollectorEnvelope -Collector 'memory' -Tier 1 -Status 'success' -Records @() `
    -StartedUtc '2026-09-15T12:00:00Z' -CompletedUtc '2026-09-15T12:00:05Z'
$healthy = New-WpdCollectorEnvelope -Collector 'cpu' -Tier 1 -Status 'healthy' -Coverage 'healthy' -Records @([pscustomobject]@{ id = 1 })
$measured = New-WpdCollectorEnvelope -Collector 'cpu' -Tier 1 -Status 'success' -Records @([pscustomobject]@{ id = 1 }, [pscustomobject]@{ id = 2 }) `
    -StartedUtc '2026-09-15T12:00:00Z' -CompletedUtc '2026-09-15T12:00:03Z' -Reasons @('two-samples')
[pscustomobject]@{
    EmptyStatus = $empty.status
    EmptyCoverage = $empty.coverage
    EmptyTier = $empty.tier
    EmptyReason = $empty.reason
    EmptyCount = $empty.recordCount
    EmptyDuration = $empty.durationMs
    HealthyStatus = $healthy.status
    HealthyCoverage = $healthy.coverage
    MeasuredStatus = $measured.status
    MeasuredCoverage = $measured.coverage
    MeasuredCount = $measured.recordCount
    MeasuredDuration = $measured.durationMs
    MeasuredReasons = @($measured.reasons)
    MeasuredCollector = $measured.collector
    HealthyVocabulary = @($empty, $healthy, $measured | Where-Object { $_.status -eq 'healthy' -or $_.coverage -eq 'healthy' }).Count
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_json(body)

    assert payload["EmptyStatus"] == "unavailable"
    assert payload["EmptyCoverage"] == "unavailable"
    assert payload["EmptyTier"] == 1
    assert payload["EmptyReason"] == "no-records-returned"
    assert payload["EmptyCount"] == 0
    assert payload["EmptyDuration"] == 5000
    assert payload["HealthyStatus"] == "unavailable"
    assert payload["HealthyCoverage"] == "unavailable"
    assert payload["MeasuredStatus"] == "success"
    assert payload["MeasuredCoverage"] == "complete"
    assert payload["MeasuredCount"] == 2
    assert payload["MeasuredDuration"] == 3000
    assert payload["MeasuredReasons"] == ["two-samples"]
    assert payload["MeasuredCollector"] == "cpu"
    assert payload["HealthyVocabulary"] == 0


def test_envelope_carries_self_monitoring_and_cleanup_state():
    """An envelope is the unit the report consumes: it carries the tier, the
    cache flag, the self-monitoring record and the cleanup outcome."""
    body = """
$monitoring = New-WpdCollectorSelfMonitoring -Collector 'cpu' -Tier 1 -DurationMs 1500 -CpuSeconds 0.25 -WorkingSetBytes 104857600 -SampleCount 30
$envelope = New-WpdCollectorEnvelope -Collector 'cpu' -Tier 1 -Status 'success' -Records @([pscustomobject]@{ id = 1 }) `
    -Cached -SelfMonitoring $monitoring -CleanupStatus 'not-needed'
[pscustomobject]@{
    Cached = $envelope.cached
    SelfMonitoringCollector = $envelope.selfMonitoring.collector
    SelfMonitoringDuration = $envelope.selfMonitoring.durationMs
    CleanupStatus = $envelope.cleanup.status
    RunRecord = ($envelope.PSObject.Properties.Name -contains 'collector')
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_json(body)

    assert payload["Cached"] is True
    assert payload["SelfMonitoringCollector"] == "cpu"
    assert payload["SelfMonitoringDuration"] == 1500
    assert payload["CleanupStatus"] == "not-needed"
    assert payload["RunRecord"] is True


def test_collector_plan_selects_requested_tiers_with_a_bounded_capture_and_cadence():
    """A plan is the ordered contract for a run: the requested tiers, the
    resolved preset, the 1 s cadence floor and the bounded capture policy."""
    body = """
$plan = New-WpdCollectorPlan -Preset 'general' -Tier @(0, 1, 2) -PrivacyLevel 'Standard' -CaptureMode 'Repro'
[pscustomobject]@{
    Status = $plan.status
    Preset = $plan.preset
    EffectivePreset = $plan.effectivePreset
    IsAlias = $plan.isAlias
    Tiers = @($plan.tiers)
    CollectorCount = @($plan.collectors).Count
    PlanOrder = (@($plan.collectors | ForEach-Object { $_.tier }) -join ',')
    Tier0Count = @($plan.collectors | Where-Object { $_.tier -eq 0 }).Count
    CaptureMode = $plan.captureMode
    CaptureBounded = $plan.captureStrategy.Bounded
    CaptureMarkers = ($plan.captureStrategy.MarkerPair -join '/')
    CaptureStorage = $plan.captureStrategy.StoragePolicy
    SamplingFloor = $plan.sampling.FloorSeconds
    SamplingEffective = $plan.sampling.EffectiveIntervalSeconds
    SamplingStatus = $plan.sampling.Status
    RequiresWindows = $plan.requiresWindows
    RequiresConsent = $plan.requiresConsent
    GeneratedUtc = $plan.generatedUtc
    IdPrefix = $plan.id.StartsWith('plan-')
    Privacy = $plan.privacyLevel
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "success"
    assert payload["Preset"] == "general"
    assert payload["EffectivePreset"] == "general"
    assert payload["IsAlias"] is False
    assert payload["Tiers"] == [0, 1, 2]
    assert payload["Tier0Count"] == len(INVENTORY_CAPABILITIES)
    assert payload["PlanOrder"] == ",".join(["0"] * len(INVENTORY_CAPABILITIES) + ["1"] * 9 + ["2"])
    assert payload["CollectorCount"] == len(INVENTORY_CAPABILITIES) + 9 + 1
    assert payload["CaptureMode"] == "Repro"
    assert payload["CaptureBounded"] is True
    assert payload["CaptureMarkers"] == "REPRO_START/CAPTURE_STOP"
    assert payload["CaptureStorage"] == "circular-memory"
    assert payload["SamplingFloor"] == 1.0
    assert payload["SamplingEffective"] == 1.0
    assert payload["SamplingStatus"] == "accepted"
    assert payload["RequiresWindows"] is True
    assert payload["RequiresConsent"] is False
    assert payload["GeneratedUtc"].endswith("Z")
    assert payload["IdPrefix"] is True
    assert payload["Privacy"] == "Standard"


def test_collector_plan_records_alias_resolution_consent_and_preset_errors():
    """A deprecated alias resolves to its canonical preset and is recorded as an
    alias; escalation tiers are consent gated; an unknown preset is a stated
    unavailable plan and an unknown tier is rejected outright."""
    body = """
$alias = New-WpdCollectorPlan -Preset 'baseline' -Tier @(0)
$escalation = New-WpdCollectorPlan -Preset 'memory-leak' -Tier @(2, 3)
$unknown = New-WpdCollectorPlan -Preset 'not-a-preset' -Tier @(0)
$tierError = ''
try { $null = New-WpdCollectorPlan -Preset 'general' -Tier @(0, 9) } catch { $tierError = $_.Exception.Message }
[pscustomobject]@{
    AliasRequested = $alias.preset
    AliasEffective = $alias.effectivePreset
    AliasFlag = $alias.isAlias
    EscalationConsent = $escalation.requiresConsent
    EscalationConsentedIds = @($escalation.consentRequiredCollectors) | Sort-Object
    EscalationCaptureStrategy = ($null -ne $escalation.captureStrategy)
    EscalationSampling = ($null -ne $escalation.sampling)
    UnknownStatus = $unknown.status
    UnknownReason = $unknown.reason
    UnknownCollectors = @($unknown.collectors).Count
    TierError = $tierError
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body, modules=["Wpd.Escalation.psm1"])

    assert payload["AliasRequested"] == "baseline"
    assert payload["AliasEffective"] == "general"
    assert payload["AliasFlag"] is True
    assert payload["EscalationConsent"] is True
    assert set(payload["EscalationConsentedIds"]) >= {"wct", "procdump", "defender", "search"}
    assert payload["EscalationCaptureStrategy"] is True
    assert payload["EscalationSampling"] is False
    assert payload["UnknownStatus"] == "unavailable"
    assert payload["UnknownReason"] == "unknown-preset"
    assert payload["UnknownCollectors"] == 0
    assert "tier" in payload["TierError"].lower()


def test_collector_plan_skips_the_capture_policy_when_no_trace_is_requested():
    """Tier selection is a contract: a plan without the trace tier carries no
    capture strategy, and a plan without interval counters carries no cadence."""
    body = """
$inventoryOnly = New-WpdCollectorPlan -Preset 'general' -Tier @(0)
$countersOnly = New-WpdCollectorPlan -Preset 'general' -Tier @(1)
[pscustomobject]@{
    InventoryCapture = ($null -ne $inventoryOnly.captureStrategy)
    InventorySampling = ($null -ne $inventoryOnly.sampling)
    InventoryCollectors = @($inventoryOnly.collectors).Count
    CountersCapture = ($null -ne $countersOnly.captureStrategy)
    CountersSampling = ($null -ne $countersOnly.sampling)
    CountersCollectors = @($countersOnly.collectors).Count
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_json(body)

    assert payload["InventoryCapture"] is False
    assert payload["InventorySampling"] is False
    assert payload["InventoryCollectors"] == len(INVENTORY_CAPABILITIES)
    assert payload["CountersCapture"] is False
    assert payload["CountersSampling"] is True
    assert payload["CountersCollectors"] == 9


TIER0_PROVIDER = r"""
$script:probeCounter = @{ provider = 0; requested = @(); refreshValues = @() }
$script:probeProvider = {
    param($request)
    $script:probeCounter.provider++
    $script:probeCounter.requested += (@($request.capability) -join ',')
    $script:probeCounter.refreshValues += [bool]$request.refresh
    [pscustomobject]@{
        capabilities = @{
            'os' = [pscustomobject]@{ capability = 'os'; status = 'success'; coverage = 'complete'; recordCount = 1; items = @([pscustomobject]@{ id = 'os-1' }); reasons = @(); warnings = @(); errors = @() }
            'storage' = [pscustomobject]@{ capability = 'storage'; status = 'success'; coverage = 'complete'; recordCount = 2; items = @([pscustomobject]@{ disk = 'c:' }, [pscustomobject]@{ disk = 'd:' }); reasons = @(); warnings = @(); errors = @() }
        }
        capabilityOrder = @('os', 'storage')
        counts = @{ success = 2; total = 2 }
        recordCount = 3
    }
}
"""


def test_tier0_collection_queries_the_provider_once_per_run_and_serves_the_cache():
    """Tier 0 is static inventory collected once per run (plan D3): a second
    Tier 0 collector in the same run is served from the cache, a different run
    key re-queries, and -Refresh explicitly re-queries."""
    body = TIER0_PROVIDER + """
$first = Invoke-WpdTier0Collection -CacheKey 'run-1' -InventoryProvider $script:probeProvider -Capability @('os', 'storage')
$second = Invoke-WpdTier0Collection -CacheKey 'run-1' -InventoryProvider $script:probeProvider -Capability @('os', 'storage')
$other = Invoke-WpdTier0Collection -CacheKey 'run-2' -InventoryProvider $script:probeProvider -Capability @('os')
$refreshed = Invoke-WpdTier0Collection -CacheKey 'run-1' -InventoryProvider $script:probeProvider -Capability @('os', 'storage') -Refresh
$null = Clear-WpdCollectorTier0Cache -CacheKey 'run-1'
$afterClear = Invoke-WpdTier0Collection -CacheKey 'run-1' -InventoryProvider $script:probeProvider -Capability @('os', 'storage')
[pscustomobject]@{
    ProviderCalls = $script:probeCounter.provider
    RequestedCapabilities = @($script:probeCounter.requested)
    RefreshValues = @($script:probeCounter.refreshValues)
    FirstCached = $first.cached
    FirstCacheHit = $first.cacheHit
    FirstProviderCalls = $first.providerCallCount
    FirstStatus = $first.status
    SecondCached = $second.cached
    SecondCacheHit = $second.cacheHit
    SecondProviderCalls = $second.providerCallCount
    SecondRecords = @($second.records).Count
    SecondStatus = $second.status
    OtherKeyCacheHit = $other.cacheHit
    RefreshedCacheHit = $refreshed.cacheHit
    RefreshedCached = $refreshed.cached
    AfterClearCacheHit = $afterClear.cacheHit
    AfterClearProviderCalls = $afterClear.providerCallCount
    FirstCacheKey = $first.cacheKey
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["ProviderCalls"] == 4, "run-1, run-2, the explicit refresh and the post-clear query"
    assert payload["RequestedCapabilities"] == ["os,storage", "os", "os,storage", "os,storage"]
    assert payload["RefreshValues"] == [False, False, True, False]
    assert payload["FirstCached"] is False
    assert payload["FirstCacheHit"] is False
    assert payload["FirstProviderCalls"] == 1
    assert payload["FirstStatus"] == "success"
    assert payload["SecondCached"] is True
    assert payload["SecondCacheHit"] is True
    assert payload["SecondProviderCalls"] == 0
    assert payload["SecondRecords"] == 2
    assert payload["SecondStatus"] == "success"
    assert payload["OtherKeyCacheHit"] is False
    assert payload["RefreshedCacheHit"] is False
    assert payload["RefreshedCached"] is False
    assert payload["AfterClearCacheHit"] is False, "clearing the run key forces a re-query"
    assert payload["AfterClearProviderCalls"] == 1
    assert payload["FirstCacheKey"] == "run-1"


def test_tier0_envelope_keeps_each_capability_status_and_unsupported_reasons():
    """One capability can be unsupported without hiding the others: each
    capability keeps its own envelope inside the Tier 0 result, an unsupported
    storage reliability counter stays unsupported, and a capability the
    provider did not return is stated as unavailable - never as healthy."""
    body = """
$provider = {
    param($request)
    [pscustomobject]@{
        capabilities = @{
            'os' = [pscustomobject]@{ capability = 'os'; status = 'success'; coverage = 'complete'; recordCount = 1; items = @([pscustomobject]@{ id = 'os-1' }); reasons = @(); warnings = @(); errors = @() }
            'storage' = [pscustomobject]@{ capability = 'storage'; status = 'unsupported'; coverage = 'unsupported'; recordCount = 0; items = @(); reasons = @('reliability-counter-unsupported'); warnings = @(); errors = @() }
            'nic' = [pscustomobject]@{ capability = 'nic'; status = 'unavailable'; coverage = 'unavailable'; recordCount = 0; items = @(); reasons = @('no-data-returned:Get-NetAdapter'); warnings = @(); errors = @() }
        }
        capabilityOrder = @('os', 'storage', 'nic')
        recordCount = 1
    }
}
$envelope = Invoke-WpdTier0Collection -CacheKey 'run-partial' -InventoryProvider $provider -Capability @('os', 'storage', 'nic', 'encryption')
$byCapability = @{}
foreach ($record in @($envelope.records)) { $byCapability[$record.capability] = $record }
[pscustomobject]@{
    Status = $envelope.status
    Coverage = $envelope.coverage
    CapabilityCount = $envelope.capabilityCount
    ItemRecordCount = $envelope.itemRecordCount
    Capabilities = @($envelope.records | ForEach-Object { $_.capability }) | Sort-Object
    OsStatus = $byCapability['os'].status
    StorageStatus = $byCapability['storage'].status
    StorageCoverage = $byCapability['storage'].coverage
    EncryptionStatus = $byCapability['encryption'].status
    EncryptionReason = $byCapability['encryption'].reason
    Reasons = @($envelope.reasons)
    NeverHealthy = @($envelope.records | Where-Object { $_.status -eq 'healthy' -or $_.coverage -eq 'healthy' }).Count
    HealthClaim = $envelope.healthClaim
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "partial"
    assert payload["Coverage"] == "partial"
    assert payload["CapabilityCount"] == 4
    assert payload["ItemRecordCount"] == 1
    assert payload["Capabilities"] == ["encryption", "nic", "os", "storage"]
    assert payload["OsStatus"] == "success"
    assert payload["StorageStatus"] == "unsupported"
    assert payload["StorageCoverage"] == "unsupported"
    assert payload["EncryptionStatus"] == "unavailable"
    assert payload["EncryptionReason"] == "capability-not-returned"
    assert "reliability-counter-unsupported" in payload["Reasons"]
    assert payload["NeverHealthy"] == 0
    assert payload["HealthClaim"] == "none"


def test_tier0_collection_rejects_an_unknown_capability_and_reports_the_host():
    """A capability that is not in the tier map is rejected, and the default
    provider path states the host it ran on while claiming no health."""
    body = """
$capabilityError = ''
try { $null = Invoke-WpdTier0Collection -CacheKey 'bad' -Capability @('os', 'not-a-capability') } catch { $capabilityError = $_.Exception.Message }
$envelope = Invoke-WpdTier0Collection -CacheKey 'default-run' -PrivacyLevel 'Standard' -Capability @('os', 'storage')
[pscustomobject]@{
    Error = $capabilityError
    Status = $envelope.status
    Coverage = $envelope.coverage
    HostWindows = $envelope.hostWindows
    CapabilityCount = $envelope.capabilityCount
    SuccessCapabilities = @($envelope.records | Where-Object { $_.status -eq 'success' }).Count
    HealthClaim = $envelope.healthClaim
    NeverHealthy = $envelope.neverHealthy
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert "not-a-capability" in payload["Error"]
    assert payload["Status"] != "success"
    assert payload["Coverage"] != "complete"
    assert payload["HostWindows"] is False
    assert payload["CapabilityCount"] == 2
    assert payload["SuccessCapabilities"] == 0
    assert payload["HealthClaim"] == "none"
    assert payload["NeverHealthy"] is True


TIER1_PROVIDER = r"""
$script:tier1Counter = @{ calls = 0; sleeps = 0 }
$script:tier1Provider = {
    param($index)
    $script:tier1Counter.calls++
    [pscustomobject]@{
        ProcessId = 4242
        ProcessName = 'synthetic'
        StartTimeTicks = 638000000000000000
        WorkingSetBytes = 104857600
        IoReadBytes = 4096
        IoWriteBytes = 2048
    }
}
"""


def test_tier1_rejects_an_interval_below_the_one_second_floor_without_sampling():
    """The documented floor is 1 s: a below-floor interval is rejected before
    any counter is read, and the effective floor is stated instead."""
    body = TIER1_PROVIDER + """
$rejected = Invoke-WpdTier1Collection -Family 'cpu' -SampleIntervalSeconds 0.5 -SampleCount 3 -Provider $script:tier1Provider
$invalid = Invoke-WpdTier1Collection -Family 'cpu' -SampleIntervalSeconds 0 -SampleCount 3 -Provider $script:tier1Provider
$familyError = ''
try { $null = Invoke-WpdTier1Collection -Family 'gpu' -SampleIntervalSeconds 1 -Provider $script:tier1Provider } catch { $familyError = $_.Exception.Message }
[pscustomobject]@{
    Status = $rejected.status
    Coverage = $rejected.coverage
    Reason = $rejected.reason
    ProviderCalls = $script:tier1Counter.calls
    CadenceValidated = $rejected.cadenceValidated
    RequestedInterval = $rejected.sampleIntervalSeconds
    EffectiveInterval = $rejected.effectiveIntervalSeconds
    FloorSeconds = $rejected.floorSeconds
    RecordCount = $rejected.recordCount
    InvalidStatus = $invalid.status
    InvalidReason = $invalid.reason
    FamilyError = $familyError
    HealthClaim = $rejected.healthClaim
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "unavailable"
    assert payload["Coverage"] == "unavailable"
    assert payload["Reason"] == "sampling-interval-below-floor"
    assert payload["ProviderCalls"] == 0, "a rejected cadence must not read a counter"
    assert payload["CadenceValidated"] is False
    assert payload["RequestedInterval"] == 0.5
    assert payload["EffectiveInterval"] == 1.0
    assert payload["FloorSeconds"] == 1.0
    assert payload["RecordCount"] == 0
    assert payload["InvalidStatus"] == "unavailable"
    assert payload["InvalidReason"] == "sampling-interval-invalid"
    assert "gpu" in payload["FamilyError"]
    assert payload["HealthClaim"] == "none"


def test_tier1_sampling_at_the_floor_reports_samples_coverage_and_series():
    """A valid cadence samples once per interval, sleeps between samples only,
    and turns the observed samples into a per-process series with stated
    coverage instead of a verdict."""
    body = TIER1_PROVIDER + """
$result = Invoke-WpdTier1Collection -Family 'process' -SampleIntervalSeconds 1 -SampleCount 3 `
    -Provider $script:tier1Provider -LogicalProcessorCount 4 `
    -SleepProvider { param($seconds) $script:tier1Counter.sleeps++ }
[pscustomobject]@{
    Status = $result.status
    Coverage = $result.coverage
    CadenceValidated = $result.cadenceValidated
    EffectiveInterval = $result.effectiveIntervalSeconds
    ExpectedSamples = $result.expectedSamples
    ObservedSamples = $result.observedSamples
    GapCount = $result.gapCount
    ProviderCalls = $script:tier1Counter.calls
    Sleeps = $script:tier1Counter.sleeps
    SeriesCount = @($result.records).Count
    SeriesIndexes = @($result.records | ForEach-Object { $_.SampleIndex })
    SeriesIdentity = @($result.records | ForEach-Object { $_.ProcessId } | Sort-Object -Unique)
    Family = $result.family
    Tier = $result.tier
    SelfMonitoring = @($result.selfMonitoring | ForEach-Object { $_.collector })
    HealthClaim = $result.healthClaim
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "success"
    assert payload["Coverage"] == "complete"
    assert payload["CadenceValidated"] is True
    assert payload["EffectiveInterval"] == 1.0
    assert payload["ExpectedSamples"] == 3
    assert payload["ObservedSamples"] == 3
    assert payload["GapCount"] == 0
    assert payload["ProviderCalls"] == 3
    assert payload["Sleeps"] == 2
    assert payload["SeriesCount"] == 3
    assert payload["SeriesIndexes"] == [0, 1, 2]
    assert payload["SeriesIdentity"] == [4242]
    assert payload["Family"] == "process"
    assert payload["Tier"] == 1
    assert payload["SelfMonitoring"] == ["process"]
    assert payload["HealthClaim"] == "none"


def test_tier1_reports_a_sampling_gap_as_partial_coverage():
    """A missed interval is evidence, not something to hide: the gap is counted,
    coverage drops to partial, and the requested interval is still 2 s."""
    body = TIER1_PROVIDER + """
$result = Invoke-WpdTier1Collection -Family 'cpu' -SampleIntervalSeconds 2 -SampleCount 4 `
    -Provider $script:tier1Provider -LogicalProcessorCount 8 `
    -ClockProvider { param($index) if ($index -ge 2) { ($index * 2) + 10 } else { $index * 2 } }
[pscustomobject]@{
    Status = $result.status
    Coverage = $result.coverage
    EffectiveInterval = $result.effectiveIntervalSeconds
    ObservedSamples = $result.observedSamples
    GapCount = $result.gapCount
    Gaps = @($result.gaps | ForEach-Object { $_.MissingIntervals })
    Reasons = @($result.reasons)
    HealthClaim = $result.healthClaim
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "partial"
    assert payload["Coverage"] == "partial"
    assert payload["EffectiveInterval"] == 2.0
    assert payload["ObservedSamples"] == 4
    assert payload["GapCount"] == 1
    assert payload["Gaps"] == [4]
    assert "sampling-gap" in payload["Reasons"]
    assert payload["HealthClaim"] == "none"


def test_capture_strategy_bounds_repro_and_flight_recorder_differently():
    """Both capture modes are bounded, but differently: a Repro recording is
    bounded by the preset maximum duration and stops when the operator has
    reproduced the issue, while Flight Recorder is a continuous circular-buffer
    recording that refuses file mode outright."""
    body = """
$repro = Get-WpdCaptureStrategy -CaptureMode 'Repro' -Preset 'general'
$reproFile = Get-WpdCaptureStrategy -CaptureMode 'Repro' -Preset 'general' -AcceptUnboundedFileMode
$recorder = Get-WpdCaptureStrategy -CaptureMode 'FlightRecorder' -Preset 'cpu-heavy'
[pscustomobject]@{
    ReproMode = $repro.Mode
    ReproBounded = $repro.Bounded
    ReproMarkers = ($repro.MarkerPair -join '/')
    ReproInteractive = $repro.InteractiveStop
    ReproContinuous = $repro.Continuous
    ReproStorage = $repro.StoragePolicy
    ReproFileMode = $repro.FileModePermitted
    ReproDurationBoundedBy = $repro.DurationBoundedBy
    ReproBudget = $repro.TraceBudgetMB
    ReproMaxDuration = $repro.MaxDurationSeconds
    ReproProfileSpec = $repro.ProfileSpec
    ReproStatus = $repro.Status
    ReproFileStorage = $reproFile.StoragePolicy
    ReproFileBounded = $reproFile.Bounded
    ReproFileStatus = $reproFile.Status
    ReproFileReasons = @($reproFile.Reasons)
    RecorderMode = $recorder.Mode
    RecorderBounded = $recorder.Bounded
    RecorderMarkers = ($recorder.MarkerPair -join '/')
    RecorderInteractive = $recorder.InteractiveStop
    RecorderContinuous = $recorder.Continuous
    RecorderStorage = $recorder.StoragePolicy
    RecorderFileMode = $recorder.FileModePermitted
    RecorderRefused = $recorder.UnboundedFileRefused
    RecorderDurationBoundedBy = $recorder.DurationBoundedBy
    RecorderStatus = $recorder.Status
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["ReproMode"] == "memory"
    assert payload["ReproBounded"] is True
    assert payload["ReproMarkers"] == "REPRO_START/CAPTURE_STOP"
    assert payload["ReproInteractive"] is True
    assert payload["ReproContinuous"] is False
    assert payload["ReproStorage"] == "circular-memory"
    assert payload["ReproFileMode"] is False
    assert payload["ReproDurationBoundedBy"] == "preset-max-duration"
    assert payload["ReproBudget"] > 0
    assert payload["ReproMaxDuration"] > 0
    assert payload["ReproProfileSpec"] == "GeneralProfile.light"
    assert payload["ReproStatus"] == "success"

    assert payload["ReproFileStorage"] == "unbounded-file"
    assert payload["ReproFileBounded"] is False
    assert payload["ReproFileStatus"] == "partial"
    assert "unbounded-file-mode-accepted-explicitly" in payload["ReproFileReasons"]

    assert payload["RecorderMode"] == "memory"
    assert payload["RecorderBounded"] is True
    assert payload["RecorderMarkers"] == "CAPTURE_START/CAPTURE_STOP"
    assert payload["RecorderInteractive"] is False
    assert payload["RecorderContinuous"] is True
    assert payload["RecorderStorage"] == "circular-memory"
    assert payload["RecorderFileMode"] is False
    assert payload["RecorderRefused"] is True
    assert payload["RecorderDurationBoundedBy"] == "circular-buffer-and-preset-max-duration"
    assert payload["RecorderStatus"] == "success"


def test_capture_storage_bound_refuses_an_unbounded_file_mode_and_reports_a_deficit():
    """An unbounded file recording is refused unless it is explicitly accepted,
    an unmeasured free space is never a pass, and a real deficit is reported
    with the bytes that are missing."""
    body = """
$repro = Get-WpdCaptureStrategy -CaptureMode 'Repro' -Preset 'cpu-heavy'
$unbounded = Get-WpdCaptureStrategy -CaptureMode 'Repro' -Preset 'cpu-heavy' -AcceptUnboundedFileMode
$refused = Test-WpdCaptureStorageBound -Strategy $unbounded
$accepted = Test-WpdCaptureStorageBound -Strategy $unbounded -AcceptUnboundedFileMode -FreeSpaceBytes 20000000000
$unmeasured = Test-WpdCaptureStorageBound -Strategy $repro
$deficit = Test-WpdCaptureStorageBound -Strategy $repro -FreeSpaceBytes 1048576
$ready = Test-WpdCaptureStorageBound -Strategy $repro -FreeSpaceBytes 20000000000
$tooLong = Test-WpdCaptureStorageBound -Strategy $repro -FreeSpaceBytes 20000000000 -RequestedDurationSeconds 100000
[pscustomobject]@{
    RefusedStatus = $refused.Status
    RefusedReady = $refused.Ready
    RefusedBounded = $refused.Bounded
    RefusedStorage = $refused.StoragePolicy
    AcceptedStatus = $accepted.Status
    AcceptedReady = $accepted.Ready
    AcceptedBounded = $accepted.Bounded
    UnmeasuredStatus = $unmeasured.Status
    UnmeasuredReady = $unmeasured.Ready
    UnmeasuredFreeSpace = $unmeasured.FreeSpaceBytes
    UnmeasuredReason = $unmeasured.Reason
    DeficitStatus = $deficit.Status
    DeficitReady = $deficit.Ready
    DeficitBytes = $deficit.DeficitBytes
    DeficitRequired = $deficit.RequiredBytes
    ReadyStatus = $ready.Status
    ReadyReady = $ready.Ready
    ReadyDeficit = $ready.DeficitBytes
    TooLongStatus = $tooLong.Status
    TooLongReason = $tooLong.Reason
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["RefusedStatus"] == "unbounded-file-mode"
    assert payload["RefusedReady"] is False
    assert payload["RefusedBounded"] is False
    assert payload["RefusedStorage"] == "unbounded-file"
    assert payload["AcceptedStatus"] == "ready"
    assert payload["AcceptedReady"] is True
    assert payload["AcceptedBounded"] is False
    assert payload["UnmeasuredStatus"] == "unavailable"
    assert payload["UnmeasuredReady"] is False
    assert payload["UnmeasuredFreeSpace"] is None
    assert "could not be measured" in payload["UnmeasuredReason"]
    assert payload["DeficitStatus"] == "insufficient-space"
    assert payload["DeficitReady"] is False
    assert payload["DeficitBytes"] > 0
    assert payload["DeficitRequired"] > payload["DeficitBytes"]
    assert payload["ReadyStatus"] == "ready"
    assert payload["ReadyReady"] is True
    assert payload["ReadyDeficit"] == 0
    assert payload["TooLongStatus"] == "duration-exceeds-preset"
    assert "exceeds the preset maximum" in payload["TooLongReason"]


TIER2_RUNNER = r"""
$script:tier2 = @{ commands = @(); cancelled = $false }
$script:tier2Runner = {
    param($toolPath, $arguments)
    $script:tier2.commands += (@($arguments) -join ' ')
    return 0
}
"""


def test_tier2_capture_runs_the_documented_start_body_stop_with_bounded_storage():
    """A Tier 2 capture is started, bracketed by the incident markers, stopped
    and validated - with only documented switches, memory mode, and the preset
    budget stated instead of an invented size flag."""
    body = TIER2_RUNNER + """
$result = Invoke-WpdTier2Collection -Preset 'general' -CaptureMode 'Repro' `
    -EtlPath '/tmp/case/repro.etl' -Runner $script:tier2Runner -FreeSpaceBytes 20000000000 `
    -SizeBytes 10485760 -ProblemDescription 'synthetic reproduction'
[pscustomobject]@{
    Status = $result.status
    Coverage = $result.coverage
    Reason = $result.reason
    Tier = $result.tier
    CaptureMode = $result.captureMode
    Bounded = $result.storageBound.Bounded
    BoundReady = $result.storageBound.Ready
    StoragePolicy = $result.strategy.StoragePolicy
    Markers = ($result.strategy.MarkerPair -join '/')
    TraceBudgetMB = $result.strategy.TraceBudgetMB
    CaptureStatus = $result.capture.Status
    Started = $result.capture.Started
    StopAttempted = $result.capture.StopAttempted
    CancelAttempted = $result.capture.CancelAttempted
    CleanupGuaranteed = $result.capture.CleanupGuaranteed
    ValidationStatus = $result.traceValidation.Status
    ValidationKept = $result.traceValidation.Kept
    EtlBytes = $result.traceValidation.EtlBytes
    Commands = @($result.commands)
    RecordKinds = @($result.records | ForEach-Object { $_.kind })
    CleanupStatus = $result.cleanup.status
    HealthClaim = $result.healthClaim
    RunnerCommands = @($script:tier2.commands)
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "success"
    assert payload["Coverage"] == "complete"
    assert payload["Tier"] == 2
    assert payload["CaptureMode"] == "Repro"
    assert payload["Bounded"] is True
    assert payload["BoundReady"] is True
    assert payload["StoragePolicy"] == "circular-memory"
    assert payload["Markers"] == "REPRO_START/CAPTURE_STOP"
    assert payload["TraceBudgetMB"] > 0
    assert payload["CaptureStatus"] == "success"
    assert payload["Started"] is True
    assert payload["StopAttempted"] is True
    assert payload["CancelAttempted"] is False
    assert payload["CleanupGuaranteed"] is True
    assert payload["ValidationStatus"] == "success"
    assert payload["ValidationKept"] is True
    assert payload["EtlBytes"] == 10485760
    assert payload["CleanupStatus"] == "complete"
    assert payload["HealthClaim"] == "none"
    assert sorted(payload["RecordKinds"]) == ["capture", "trace-validation"]

    runner_commands = payload["RunnerCommands"]
    assert len(runner_commands) == 4
    assert runner_commands[0].startswith("-start GeneralProfile.light")
    assert "-marker REPRO_START" in runner_commands[1]
    assert "-marker CAPTURE_STOP" in runner_commands[2]
    assert runner_commands[3].startswith("-stop /tmp/case/repro.etl synthetic reproduction")
    assert payload["Commands"] == runner_commands
    for command in runner_commands:
        for forbidden in ("-maxduration", "-filesize", "-markerflush", "-filemode"):
            assert forbidden not in command, f"invented switch {forbidden} in {command}"


def test_tier2_capture_refuses_unbounded_file_mode_before_starting_anything():
    """Flight Recorder refuses to start on an unbounded file profile: no command
    is executed, the refusal is stated, and the run is not failed."""
    body = TIER2_RUNNER + """
$result = Invoke-WpdTier2Collection -Preset 'cpu-heavy' -CaptureMode 'FlightRecorder' `
    -EtlPath '/tmp/case/recorder.etl' -Runner $script:tier2Runner -AllowFileMode `
    -FreeSpaceBytes 20000000000
[pscustomobject]@{
    Status = $result.status
    Coverage = $result.coverage
    Reason = $result.reason
    Bounded = $result.storageBound.Bounded
    BoundStatus = $result.storageBound.Status
    StoragePolicy = $result.storageBound.StoragePolicy
    StrategyReasons = @($result.strategy.Reasons)
    CaptureIsNull = ($null -eq $result.capture)
    RunnerCommands = @($script:tier2.commands)
    RecordCount = $result.recordCount
    HealthClaim = $result.healthClaim
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "unavailable"
    assert payload["Coverage"] == "unavailable"
    assert payload["Reason"] == "capture-preflight-unbounded-file-mode"
    assert payload["Bounded"] is False
    assert payload["BoundStatus"] == "unbounded-file-mode"
    assert payload["StoragePolicy"] == "unbounded-file"
    assert "flight-recorder-refuses-unbounded-file-mode" in payload["StrategyReasons"]
    assert payload["CaptureIsNull"] is True
    assert payload["RunnerCommands"] == [], "no wpr command may run for a refused capture"
    assert payload["RecordCount"] == 0
    assert payload["HealthClaim"] == "none"


def test_tier2_capture_keeps_cleanup_when_the_capture_body_throws():
    """Cleanup is not optional: when the capture body throws, the recording is
    still stopped, the failure is stated, and the commands that ran are kept as
    evidence."""
    body = TIER2_RUNNER + """
$result = Invoke-WpdTier2Collection -Preset 'general' -CaptureMode 'Repro' `
    -EtlPath '/tmp/case/failed.etl' -Runner $script:tier2Runner -FreeSpaceBytes 20000000000 `
    -SizeBytes 4096 -Body { param($context) throw 'operator cancelled the reproduction' }
[pscustomobject]@{
    Status = $result.status
    Coverage = $result.coverage
    Reason = $result.reason
    ErrorMessages = @($result.errors | ForEach-Object { $_.message })
    RunnerCommands = @($script:tier2.commands)
    EnvelopeCommands = @($result.commands)
    CleanupStatus = $result.cleanup.status
    CleanupPaths = @($result.cleanup.paths)
    HealthClaim = $result.healthClaim
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "error"
    assert payload["Coverage"] == "unavailable"
    assert payload["Reason"] == "capture-body-failed"
    assert any("operator cancelled" in message for message in payload["ErrorMessages"])
    runner_commands = payload["RunnerCommands"]
    assert runner_commands[0].startswith("-start ")
    assert runner_commands[-1].startswith("-stop "), "the stop must still have run"
    assert not any("-cancel" in command for command in runner_commands)
    assert payload["EnvelopeCommands"] == runner_commands
    assert payload["CleanupStatus"] == "attempted-after-failure"
    assert payload["CleanupPaths"] == ["/tmp/case/failed.etl"]
    assert payload["HealthClaim"] == "none"


def test_tier2_capture_reports_a_non_windows_host_as_unsupported():
    """A host that is not Windows cannot record a trace: the collector says so
    without starting anything, and without failing the run."""
    body = TIER2_RUNNER + """
$result = Invoke-WpdTier2Collection -Preset 'general' -CaptureMode 'Repro' `
    -EtlPath '/tmp/case/repro.etl' -FreeSpaceBytes 20000000000 -HostIsWindows $false
[pscustomobject]@{
    Status = $result.status
    Coverage = $result.coverage
    Reason = $result.reason
    HostWindows = $result.hostWindows
    RunnerCommands = @($script:tier2.commands)
    StrategyPresent = ($null -ne $result.strategy)
    Bounded = $result.storageBound.Bounded
    HealthClaim = $result.healthClaim
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "unsupported"
    assert payload["Coverage"] == "unsupported"
    assert payload["Reason"] == "host-not-windows"
    assert payload["HostWindows"] is False
    assert payload["RunnerCommands"] == []
    assert payload["StrategyPresent"] is True
    assert payload["Bounded"] is True
    assert payload["HealthClaim"] == "none"


TIER3_SEAMS = r"""
$script:tier3 = @{ wctCalls = 0; runnerCalls = 0 }
$script:tier3ChainProvider = {
    param($processId, $threadId)
    $script:tier3.wctCalls++
    @([pscustomobject]@{
        ProcessId = 4242
        ThreadId = 11
        Nodes = @(
            [pscustomobject]@{ ObjectType = 'Thread'; ObjectName = '4242.11'; WaitTimeMs = 0 },
            [pscustomobject]@{ ObjectType = 'CriticalSection'; ObjectName = '0x1f4'; WaitTimeMs = 3200 }
        )
    })
}
$script:tier3Runner = {
    param($toolPath, $arguments)
    $script:tier3.runnerCalls++
    return 0
}
$script:tier3SearchService = { [pscustomobject]@{ Name = 'WSearch'; Status = 'Running'; StartType = 'Automatic' } }
$script:tier3SearchIndex = { [pscustomobject]@{ Status = 'Ready'; IndexedItems = 184320 } }
"""


def test_tier3_without_consent_collects_nothing_and_calls_no_adapter():
    """Tier 3 is opt-in: without consent every requested adapter is
    not-collected with the reason stated, and neither the provider nor the
    command runner seam is invoked."""
    body = TIER3_SEAMS + """
$result = Invoke-WpdTier3Collection -Adapter @('wct', 'procdump', 'minifilter', 'pool', 'search', 'defender') `
    -ChainProvider $script:tier3ChainProvider -CommandRunner $script:tier3Runner `
    -CommandTable @{ 'procdump.exe' = 'C:\\tools\\procdump.exe'; 'fltmc.exe' = 'C:\\Windows\\System32\\fltmc.exe'; 'poolmon.exe' = 'C:\\tools\\poolmon.exe' } `
    -ServiceProvider $script:tier3SearchService -IndexProvider $script:tier3SearchIndex -ProcessId 4242
[pscustomobject]@{
    Status = $result.status
    Coverage = $result.coverage
    Tier = $result.tier
    AdapterCount = $result.adapterCount
    AdapterStatuses = @($result.records | ForEach-Object { $_.adapter + '=' + $_.status })
    AdapterReasons = @(@($result.records | ForEach-Object { $_.reason }) | Sort-Object -Unique)
    ConsentGiven = @($result.records | Where-Object { $_.consentGiven }).Count
    ConsentRequired = @($result.records | Where-Object { $_.consentRequired }).Count
    WctProviderCalls = $script:tier3.wctCalls
    RunnerCalls = $script:tier3.runnerCalls
    ConsentedAdapters = @($result.consentedAdapters).Count
    HealthClaim = $result.healthClaim
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "not-collected"
    assert payload["Coverage"] == "not-collected"
    assert payload["Tier"] == 3
    assert payload["AdapterCount"] == 6
    assert payload["AdapterStatuses"] == [
        "wct=not-collected",
        "procdump=not-collected",
        "minifilter=not-collected",
        "pool=not-collected",
        "search=not-collected",
        "defender=not-collected",
    ]
    assert payload["AdapterReasons"] == ["consent-required"]
    assert payload["ConsentGiven"] == 0
    assert payload["ConsentRequired"] == 6
    assert payload["WctProviderCalls"] == 0
    assert payload["RunnerCalls"] == 0
    assert payload["ConsentedAdapters"] == 0
    assert payload["HealthClaim"] == "none"


def test_tier3_consent_is_per_adapter_and_absent_tools_stay_unsupported():
    """Consent is granted per adapter: only the consented adapter runs, and an
    adapter whose tool or module is absent reports that absence instead of a
    failure or a clean result."""
    body = TIER3_SEAMS + """
$result = Invoke-WpdTier3Collection -Adapter @('wct', 'procdump', 'defender', 'search') `
    -AdapterConsent @{ 'wct' = $true; 'procdump' = $true; 'defender' = $true; 'search' = $true } `
    -ChainProvider $script:tier3ChainProvider -CommandRunner $script:tier3Runner `
    -CommandTable @{ 'fltmc.exe' = 'C:\\Windows\\System32\\fltmc.exe' } `
    -ModuleAvailable $false -ServiceProvider $script:tier3SearchService -IndexProvider $script:tier3SearchIndex `
    -ProcessId 4242
$byAdapter = @{}
foreach ($record in @($result.records)) { $byAdapter[$record.adapter] = $record }
[pscustomobject]@{
    Status = $result.status
    Coverage = $result.coverage
    WctStatus = $byAdapter['wct'].status
    WctItemCount = $byAdapter['wct'].itemCount
    WctReason = $byAdapter['wct'].reason
    ProcdumpStatus = $byAdapter['procdump'].status
    ProcdumpReason = $byAdapter['procdump'].reason
    DefenderStatus = $byAdapter['defender'].status
    DefenderReason = $byAdapter['defender'].reason
    SearchStatus = $byAdapter['search'].status
    SearchServiceStatus = $byAdapter['search'].service.status
    SearchIndexedItems = $byAdapter['search'].index.indexedItems
    WctProviderCalls = $script:tier3.wctCalls
    ConsentedAdapters = @($result.consentedAdapters) | Sort-Object
    UnconsentedRuns = @($result.records | Where-Object { -not $_.consentGiven }).Count
    AutoRemediation = @($result.records | Where-Object { $_.automaticRemediation }).Count
    Recommendations = @($result.records | ForEach-Object { @($_.recommendations).Count } | Measure-Object -Sum).Sum
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "partial"
    assert payload["Coverage"] == "partial"
    assert payload["WctStatus"] == "success"
    assert payload["WctProviderCalls"] == 1
    assert payload["ProcdumpStatus"] == "unavailable"
    assert payload["ProcdumpReason"] == "tool-not-found"
    assert payload["DefenderStatus"] == "unavailable"
    assert payload["DefenderReason"] == "module-not-found"
    assert payload["SearchStatus"] == "success"
    assert payload["SearchServiceStatus"] == "Running"
    assert payload["SearchIndexedItems"] == 184320
    assert payload["ConsentedAdapters"] == ["defender", "procdump", "search", "wct"]
    assert payload["UnconsentedRuns"] == 0
    assert payload["AutoRemediation"] == 0
    assert payload["Recommendations"] == 0


def test_tier3_failing_adapter_is_reported_without_hiding_its_siblings():
    """Each Tier 3 adapter has its own failure envelope: a failing command seam
    becomes an error on that adapter, its message is kept, and the sibling
    adapters still report their own results."""
    body = TIER3_SEAMS + """
$script:tier3Runner = { param($toolPath, $arguments) $script:tier3.runnerCalls++; throw 'command runner refused' }
$result = Invoke-WpdTier3Collection -Adapter @('wct', 'minifilter', 'pool') -Consent `
    -ChainProvider $script:tier3ChainProvider -CommandRunner $script:tier3Runner `
    -CommandTable @{ 'fltmc.exe' = 'C:\\Windows\\System32\\fltmc.exe'; 'poolmon.exe' = 'C:\\tools\\poolmon.exe' } `
    -ProcessId 4242
$byAdapter = @{}
foreach ($record in @($result.records)) { $byAdapter[$record.adapter] = $record }
[pscustomobject]@{
    Status = $result.status
    Coverage = $result.coverage
    WctStatus = $byAdapter['wct'].status
    MinifilterStatus = $byAdapter['minifilter'].status
    MinifilterReason = $byAdapter['minifilter'].reason
    MinifilterErrors = @($byAdapter['minifilter'].errors).Count
    PoolStatus = $byAdapter['pool'].status
    PoolReason = $byAdapter['pool'].reason
    Statuses = @($result.records | ForEach-Object { $_.status })
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "partial"
    assert payload["Coverage"] == "partial"
    assert payload["WctStatus"] == "success"
    assert payload["MinifilterStatus"] == "error"
    assert payload["MinifilterReason"] == "fltmc-query-failed"
    assert payload["MinifilterErrors"] >= 1
    assert payload["PoolStatus"] == "error"
    assert payload["PoolReason"] == "capture-failed"
    assert sorted(payload["Statuses"]) == ["error", "error", "success"]


def test_storage_reliability_unsupported_device_is_never_health():
    """Storage reliability is per device: a device that exposes counters is
    complete, a device with no counter is unsupported, a capability that was
    never collected stays unavailable - and no device ever becomes healthy."""
    body = """
$storageRecord = [pscustomobject]@{
    capability = 'storage'
    status = 'success'
    coverage = 'complete'
    recordCount = 2
    items = @(
        [pscustomobject]@{ DeviceId = 'nvme0'; FriendlyName = 'NVMe SSD'; MediaType = 'SSD'; Size = 512110190592 }
        [pscustomobject]@{ DeviceId = 'usb1'; FriendlyName = 'USB bridge'; MediaType = 'Unspecified'; Size = 32000000000 }
    )
    reasons = @()
    warnings = @()
    errors = @()
}
$reliability = @(
    [pscustomobject]@{ DeviceId = 'nvme0'; Wear = 12; Temperature = 41; ReadErrorsTotal = 0; WriteErrorsTotal = 0; PowerOnHours = 4200 }
)
$context = Get-WpdStorageReliabilityContext -StorageRecord $storageRecord -ReliabilityRecord $reliability

$unsupportedCapability = [pscustomobject]@{
    capability = 'storage'
    status = 'unsupported'
    coverage = 'unsupported'
    recordCount = 0
    items = @()
    reasons = @('reliability-counter-unsupported')
    warnings = @()
    errors = @()
}
$unsupported = Get-WpdStorageReliabilityContext -StorageRecord $unsupportedCapability
$nothing = Get-WpdStorageReliabilityContext
$devices = @{}
foreach ($device in @($context.devices)) { $devices[$device.deviceId] = $device }
[pscustomobject]@{
    Status = $context.status
    Coverage = $context.coverage
    DeviceCount = $context.deviceCount
    SupportedCount = $context.supportedCount
    UnsupportedCount = $context.unsupportedCount
    NvmeStatus = $devices['nvme0'].status
    NvmeWear = $devices['nvme0'].reliability.wear
    NvmeTemperature = $devices['nvme0'].reliability.temperature
    NvmeReason = $devices['nvme0'].reason
    UsbStatus = $devices['usb1'].status
    UsbReason = $devices['usb1'].reason
    UsbReliability = ($null -eq $devices['usb1'].reliability)
    UnsupportedStatus = $unsupported.status
    UnsupportedReason = $unsupported.reason
    UnsupportedDeviceCount = $unsupported.deviceCount
    NothingStatus = $nothing.status
    NothingReason = $nothing.reason
    HealthyClaims = @($context.devices + $unsupported.devices | Where-Object { $_.status -eq 'healthy' -or $_.coverage -eq 'healthy' }).Count
    Attribution = $context.assessment
    HealthClaim = $context.healthClaim
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "partial"
    assert payload["Coverage"] == "partial"
    assert payload["DeviceCount"] == 2
    assert payload["SupportedCount"] == 1
    assert payload["UnsupportedCount"] == 1
    assert payload["NvmeStatus"] == "complete"
    assert payload["NvmeWear"] == 12
    assert payload["NvmeTemperature"] == 41
    assert payload["UsbStatus"] == "unsupported"
    assert payload["UsbReason"] == "reliability-counter-not-reported"
    assert payload["UsbReliability"] is True
    assert payload["UnsupportedStatus"] == "unsupported"
    assert payload["UnsupportedReason"] == "storage-reliability-unsupported"
    assert payload["UnsupportedDeviceCount"] == 0
    assert payload["NothingStatus"] == "unavailable"
    assert payload["NothingReason"] == "storage-capability-not-collected"
    assert payload["HealthyClaims"] == 0
    assert payload["Attribution"] == "analysis-only"
    assert payload["HealthClaim"] == "none"


def test_filter_context_states_the_elevation_gate_and_orders_by_altitude():
    """Minifilter evidence is altitude ordered and read-only: an unelevated run
    reports the administrator requirement instead of an empty filter list, and a
    collected snapshot is never turned into an attribution."""
    body = """
$gated = [pscustomobject]@{
    capability = 'filters'; status = 'unavailable'; coverage = 'unavailable'; recordCount = 0
    items = @(); reasons = @('requires-administrator'); warnings = @(); errors = @()
}
$collected = [pscustomobject]@{
    capability = 'filters'; status = 'success'; coverage = 'complete'; recordCount = 2
    items = @(
        [pscustomobject]@{ name = 'WdFilter'; instances = 4; altitude = 328010; frame = 0 }
        [pscustomobject]@{ name = 'FileInfo'; instances = 6; altitude = 40500; frame = 0 }
    )
    reasons = @(); warnings = @(); errors = @()
}
$minifilter = [pscustomobject]@{
    adapter = 'minifilter'; status = 'success'; coverage = 'complete'; reason = 'fltmc-filter-instance-snapshot'
    items = @(
        [pscustomobject]@{ filterName = 'FileInfo'; volume = 'C:'; altitude = 40500; instanceName = 'FileInfo' }
        [pscustomobject]@{ filterName = 'WdFilter'; volume = 'C:'; altitude = 328010; instanceName = 'WdFilter' }
    )
    warnings = @(); errors = @(); consentGiven = $true; automaticRemediation = $false; recommendations = @()
}
$gatedContext = Get-WpdFilterContext -FilterRecord $gated
$context = Get-WpdFilterContext -FilterRecord $collected -MinifilterResult $minifilter
[pscustomobject]@{
    GatedStatus = $gatedContext.status
    GatedReason = $gatedContext.reason
    GatedElevation = $gatedContext.elevationRequired
    GatedCount = $gatedContext.filterCount
    Status = $context.status
    Coverage = $context.coverage
    FilterCount = $context.filterCount
    FilterOrder = (@($context.filters | ForEach-Object { $_.name }) -join '>')
    InstanceOrder = (@($context.instances | ForEach-Object { $_.filterName }) -join '>')
    Elevation = $context.elevationRequired
    ReadOnly = $context.readOnly
    Assessment = $context.assessment
    Recommendations = @($context.recommendations).Count
    HealthClaim = $context.healthClaim
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["GatedStatus"] == "unavailable"
    assert payload["GatedReason"] == "requires-administrator"
    assert payload["GatedElevation"] is True
    assert payload["GatedCount"] == 0
    assert payload["Status"] == "success"
    assert payload["Coverage"] == "complete"
    assert payload["FilterCount"] == 2
    assert payload["FilterOrder"] == "FileInfo>WdFilter"
    assert payload["InstanceOrder"] == "FileInfo>WdFilter"
    assert payload["Elevation"] is True
    assert payload["ReadOnly"] is True
    assert payload["Assessment"] == "analysis-only"
    assert payload["Recommendations"] == 0
    assert payload["HealthClaim"] == "none"


def test_defender_and_search_context_are_consent_gated_and_never_remediate():
    """The Defender analyzer and the Search context are collected together
    behind consent: a missing Defender module is stated as unavailable, the
    Search context is read-only, and nothing recommends a remediation or an
    exclusion."""
    body = TIER3_SEAMS + """
$refused = Get-WpdDefenderSearchContext -ModuleAvailable $false
$collected = Get-WpdDefenderSearchContext -Consent -ModuleAvailable $false `
    -ServiceProvider $script:tier3SearchService -IndexProvider $script:tier3SearchIndex
[pscustomobject]@{
    RefusedStatus = $refused.status
    RefusedCoverage = $refused.coverage
    RefusedDefender = $refused.defender.status
    RefusedDefenderReason = $refused.defender.reason
    RefusedSearch = $refused.search.status
    Status = $collected.status
    Coverage = $collected.coverage
    DefenderStatus = $collected.defender.status
    DefenderReason = $collected.defender.reason
    SearchStatus = $collected.search.status
    SearchServiceStatus = $collected.search.service.status
    SearchIndexedItems = $collected.search.index.indexedItems
    Recommendations = @($collected.recommendations).Count
    AutoRemediation = $collected.automaticRemediation
    Exclusions = $collected.defenderExclusionProposed
    HealthClaim = $collected.healthClaim
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["RefusedStatus"] == "not-collected"
    assert payload["RefusedCoverage"] == "not-collected"
    assert payload["RefusedDefender"] == "not-collected"
    assert payload["RefusedDefenderReason"] == "consent-required"
    assert payload["RefusedSearch"] == "not-collected"
    assert payload["Status"] == "partial"
    assert payload["Coverage"] == "partial"
    assert payload["DefenderStatus"] == "unavailable"
    assert payload["DefenderReason"] == "module-not-found"
    assert payload["SearchStatus"] == "success"
    assert payload["SearchServiceStatus"] == "Running"
    assert payload["SearchIndexedItems"] == 184320
    assert payload["Recommendations"] == 0
    assert payload["AutoRemediation"] is False
    assert payload["Exclusions"] is False
    assert payload["HealthClaim"] == "none"


NETWORK_RECORD = r"""
$script:nicRecord = [pscustomobject]@{
    capability = 'nic'; status = 'success'; coverage = 'complete'; recordCount = 2
    items = @(
        [pscustomobject]@{ Name = 'Ethernet'; Status = 'Up'; LinkSpeedBps = 1000000000; MacAddress = 'AA-BB-CC-DD-EE-FF'; MediaType = '802.3' }
        [pscustomobject]@{ Name = 'Wi-Fi'; Status = 'Disconnected'; LinkSpeedBps = 100000000; MacAddress = 'AA-BB-CC-DD-EE-00'; MediaType = 'Native 802.11' }
    )
    reasons = @(); warnings = @(); errors = @()
}
$script:networkTelemetry = [pscustomobject]@{
    collector = 'network'; tier = 1; status = 'success'; coverage = 'complete'
    records = @([pscustomobject]@{ Name = 'Ethernet'; BytesTotalPersec = 1200000 }, [pscustomobject]@{ Name = 'Ethernet'; BytesTotalPersec = 1300000 })
    reasons = @(); warnings = @(); errors = @(); healthClaim = 'none'
}
$script:powerRecord = [pscustomobject]@{
    capability = 'power'; status = 'success'; coverage = 'complete'; recordCount = 2
    items = @(
        [pscustomobject]@{ kind = 'power-active-scheme'; guid = '381b4222-f694-41f0-9685-ff5bb260df2e'; name = 'Balanced'; source = 'powercfg /getactivescheme'; schemeCount = 1 }
        [pscustomobject]@{ kind = 'power-sleep-states'; source = 'powercfg /a'; available = @('Standby (S3)', 'Hibernate'); unavailable = @([pscustomobject]@{ state = 'Standby (S0 Low Power Idle)'; reason = 'not supported' }); parseWarnings = @() }
    )
    reasons = @(); warnings = @(); errors = @()
}
$script:gpuTelemetry = [pscustomobject]@{
    collector = 'gpu-engines'; tier = 1; status = 'success'; coverage = 'complete'
    records = @(
        [pscustomobject]@{ Adapter = 'Contoso GPU'; EngineType = '3D'; ProcessId = 4242; UtilizationPercentage = 37.5; DedicatedUsageBytes = 536870912; TemperatureCelsius = 61; ClockMHz = 1500 }
        [pscustomobject]@{ Adapter = 'Contoso GPU'; EngineType = 'Copy'; ProcessId = 4242; UtilizationPercentage = 4; DedicatedUsageBytes = 0 }
    )
    reasons = @(); warnings = @(); errors = @(); healthClaim = 'none'
}
"""


def test_network_power_and_gpu_context_come_from_tier0_and_tier1_without_a_verdict():
    """Network, power and GPU context are read from the Tier 0 capability
    records and the Tier 1 series: present sources are reported with their
    values, an absent source is unavailable rather than empty, and nothing is
    promoted to a verdict."""
    body = NETWORK_RECORD + """
$network = Get-WpdNetworkContext -NicRecord $script:nicRecord -TelemetryEnvelope $script:networkTelemetry
$networkMissing = Get-WpdNetworkContext -NicRecord ([pscustomobject]@{ capability = 'nic'; status = 'unavailable'; coverage = 'unavailable'; recordCount = 0; items = @(); reasons = @('no-data-returned:Get-NetAdapter'); warnings = @(); errors = @() })
$networkNothing = Get-WpdNetworkContext
$power = Get-WpdPowerContext -PowerRecord $script:powerRecord -TelemetryEnvelope ([pscustomobject]@{
    collector = 'cpu'; tier = 1; status = 'partial'; coverage = 'partial'
    records = @([pscustomobject]@{ UtilityPercent = 92.5 }, [pscustomobject]@{ UtilityPercent = 41 })
    reasons = @('sampling-gap'); warnings = @(); errors = @(); healthClaim = 'none'
})
$gpu = Get-WpdGpuContext -TelemetryEnvelope $script:gpuTelemetry -DeepDescriptor ([pscustomobject]@{ id = 'gpu'; analysisQuestion = 'Do GPU timelines overlap the symptom window?' })
[pscustomobject]@{
    NetworkStatus = $network.status
    NetworkCoverage = $network.coverage
    NetworkAdapterCount = $network.adapterCount
    NetworkUpAdapters = $network.upAdapterCount
    NetworkLinkSpeed = $network.linkSpeedBps
    NetworkTelemetryStatus = $network.telemetryStatus
    NetworkThroughputRows = $network.throughputRowCount
    NetworkMediaTypes = @($network.mediaTypes) | Sort-Object
    MissingStatus = $networkMissing.status
    MissingReason = $networkMissing.reason
    MissingAdapterCount = $networkMissing.adapterCount
    NothingStatus = $networkNothing.status
    NothingReason = $networkNothing.reason
    PowerStatus = $power.status
    PowerCoverage = $power.coverage
    PowerSchemeName = $power.activeScheme.name
    PowerSleepAvailable = @($power.sleepStates.available).Count
    PowerTelemetryStatus = $power.telemetryStatus
    PowerMaxUtility = $power.maxUtilityPercent
    PowerUtilityRows = $power.utilityRowCount
    PowerThermalClaim = $power.thermalThrottleClaim
    GpuStatus = $gpu.status
    GpuEngineCount = $gpu.engineCount
    GpuAdapterCount = $gpu.adapterCount
    GpuMaxUtilization = $gpu.maxUtilizationPercent
    GpuTemperatureCelsius = $gpu.temperatureCelsius
    GpuProcessMemoryRows = $gpu.processMemoryRowCount
    GpuDeepTracing = $gpu.deepTracingAvailable
    GpuDeepQuestion = $gpu.deepDescriptor.analysisQuestion
    Assessments = @(@($network.assessment, $power.assessment, $gpu.assessment) | Sort-Object -Unique)
    HealthClaims = @($network, $power, $gpu | Where-Object { $_.healthClaim -ne 'none' }).Count
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["NetworkStatus"] == "success"
    assert payload["NetworkCoverage"] == "complete"
    assert payload["NetworkAdapterCount"] == 2
    assert payload["NetworkUpAdapters"] == 1
    assert payload["NetworkLinkSpeed"] == 1000000000
    assert payload["NetworkTelemetryStatus"] == "success"
    assert payload["NetworkThroughputRows"] == 2
    assert payload["NetworkMediaTypes"] == ["802.3", "Native 802.11"]
    assert payload["MissingStatus"] == "unavailable"
    assert payload["MissingReason"] == "no-data-returned:Get-NetAdapter"
    assert payload["MissingAdapterCount"] == 0
    assert payload["NothingStatus"] == "unavailable"
    assert payload["NothingReason"] == "nic-capability-not-collected"

    assert payload["PowerStatus"] == "partial"
    assert payload["PowerCoverage"] == "partial"
    assert payload["PowerSchemeName"] == "Balanced"
    assert payload["PowerSleepAvailable"] == 2
    assert payload["PowerTelemetryStatus"] == "partial"
    assert payload["PowerMaxUtility"] == 92.5
    assert payload["PowerUtilityRows"] == 2
    assert payload["PowerThermalClaim"] is False

    assert payload["GpuStatus"] == "success"
    assert payload["GpuEngineCount"] == 2
    assert payload["GpuAdapterCount"] == 1
    assert payload["GpuMaxUtilization"] == 37.5
    assert payload["GpuTemperatureCelsius"] == 61
    assert payload["GpuProcessMemoryRows"] == 2
    assert payload["GpuDeepTracing"] is True
    assert payload["GpuDeepQuestion"] == "Do GPU timelines overlap the symptom window?"
    assert payload["Assessments"] == ["analysis-only"]
    assert payload["HealthClaims"] == 0


def test_boot_quick_is_one_boot_and_deep_is_a_multi_reboot_scenario_neither_executed():
    """Boot collection is described, never executed: the quick descriptor is a
    single autologger boot, the deep descriptor is the documented on/off
    scenario with its reboot iterations, and both require operator approval."""
    body = """
$quick = New-WpdBootCollectionDescriptor -Depth 'quick' -Preset 'boot-slowdown' -ResultsPath 'C:\\case\\boot.etl' -ProblemDescription 'slow boot'
$deep = New-WpdBootCollectionDescriptor -Depth 'deep' -Preset 'boot-slowdown' -ResultsPath 'C:\\case\\boot-onoff.etl' -ProblemDescription 'slow boot'
$injectedProfile = [pscustomobject]@{ Profile = 'CPU'; Qualifier = 'light'; EffectivePreset = 'cpu-heavy'; OnOffScenario = $null }
$injected = New-WpdBootCollectionDescriptor -Depth 'quick' -PresetProfile $injectedProfile -ResultsPath 'C:\\case\\injected.etl'
[pscustomobject]@{
    QuickDepth = $quick.depth
    QuickMechanism = $quick.mechanism
    QuickRebootCount = $quick.rebootCount
    QuickExecuted = $quick.executed
    QuickApproval = $quick.requiresOperatorApproval
    QuickRequiresReboot = $quick.requiresReboot
    QuickFileBacked = $quick.fileBacked
    QuickMemoryMode = $quick.memoryMode
    QuickProfileSpec = $quick.profileSpec
    QuickProfileSpecShape = ($quick.profileSpec -match '^[A-Za-z]+[.](light|verbose)$')
    QuickScenario = $quick.scenario
    InjectedProfileSpec = $injected.profileSpec
    InjectedScenario = $injected.scenario
    InjectedArtifact = $injected.expectedArtifact
    QuickAssignment = ($quick.assignment.Arguments -join ' ')
    QuickCompletion = ($quick.completion.Arguments -join ' ')
    QuickCleanup = ($quick.cleanup.Arguments -join ' ')
    QuickArtifact = $quick.expectedArtifact
    QuickWarnings = @($quick.warnings).Count
    DeepDepth = $deep.depth
    DeepMechanism = $deep.mechanism
    DeepRebootCount = $deep.rebootCount
    DeepIterations = $deep.numIterations
    DeepScenario = $deep.scenario
    DeepExecuted = $deep.executed
    DeepApproval = $deep.requiresOperatorApproval
    DeepAssignment = ($deep.assignment.Arguments -join ' ')
    DeepCompletion = ($deep.completion.Arguments -join ' ')
    DeepCleanup = ($deep.cleanup.Arguments -join ' ')
    DeepAnalysisRequired = $deep.analysisRequired
    Error = $(try { $null = New-WpdBootCollectionDescriptor -Depth 'sideways'; 'none' } catch { $_.Exception.Message })
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["QuickDepth"] == "quick"
    assert payload["QuickMechanism"] == "boottrace"
    assert payload["QuickRebootCount"] == 1
    assert payload["QuickExecuted"] is False
    assert payload["QuickApproval"] is True
    assert payload["QuickRequiresReboot"] is True
    assert payload["QuickFileBacked"] is True
    assert payload["QuickMemoryMode"] is False
    assert payload["QuickProfileSpec"] == "GeneralProfile.verbose"
    assert payload["QuickProfileSpecShape"] is True
    assert payload["QuickScenario"] == "Boot"
    assert payload["InjectedProfileSpec"] == "CPU.light"
    assert payload["InjectedScenario"] == "Boot"
    assert payload["InjectedArtifact"] == "C:\\case\\injected.etl"
    assert payload["QuickAssignment"].startswith("-boottrace -addboot ")
    assert "-stopboot C:\\case\\boot.etl slow boot" in payload["QuickCompletion"]
    assert payload["QuickCleanup"] == "-boottrace -cancelboot"
    assert payload["QuickArtifact"] == "C:\\case\\boot.etl"
    assert payload["QuickWarnings"] >= 1

    assert payload["DeepDepth"] == "deep"
    assert payload["DeepMechanism"] == "onoff"
    assert payload["DeepRebootCount"] >= 3
    assert payload["DeepIterations"] == payload["DeepRebootCount"]
    assert payload["DeepScenario"] == "Boot"
    assert payload["DeepExecuted"] is False
    assert payload["DeepApproval"] is True
    assert "-onoffscenario Boot" in payload["DeepAssignment"]
    assert "-numiterations" in payload["DeepAssignment"]
    assert "-onoffresultspath C:\\case\\boot-onoff.etl" in payload["DeepAssignment"]
    assert payload["DeepCompletion"].startswith("-stop C:\\case\\boot-onoff.etl")
    assert payload["DeepCleanup"] == "-cancel"
    assert payload["DeepAnalysisRequired"] is True
    assert "sideways" in payload["Error"]


def test_self_monitoring_keeps_an_absent_measurement_unavailable_and_thresholds_informational():
    """Overhead is reported honestly: a collector that was not measured is
    unavailable (not zero), a partial measurement says which part is missing,
    and thresholds stay an owner decision instead of a pass/fail line."""
    body = """
$unmeasured = New-WpdCollectorSelfMonitoring -Collector 'tier1-cpu' -Tier 1
$partial = New-WpdCollectorSelfMonitoring -Collector 'tier1-cpu' -Tier 1 -DurationMs 0
$measured = New-WpdCollectorSelfMonitoring -Collector 'tier1-cpu' -Tier 1 -DurationMs 1500 -CpuSeconds 0.25 -WorkingSetBytes 104857600 -SampleCount 30
[pscustomobject]@{
    UnmeasuredStatus = $unmeasured.measurementStatus
    UnmeasuredCoverage = $unmeasured.coverage
    UnmeasuredDuration = $unmeasured.durationMs
    UnmeasuredCpu = $unmeasured.cpuSeconds
    UnmeasuredRecordStatus = $unmeasured.status
    PartialStatus = $partial.measurementStatus
    PartialDuration = $partial.durationMs
    PartialCpu = $partial.cpuSeconds
    MeasuredStatus = $measured.measurementStatus
    MeasuredCoverage = $measured.coverage
    MeasuredCpuPercent = $measured.cpuPercentOfCollector
    MeasuredSamples = $measured.sampleCount
    Thresholds = @($unmeasured.thresholdsEvaluated, $measured.thresholdsEvaluated)
    Notes = @($measured.notes)
    HealthClaims = @($unmeasured, $partial, $measured | Where-Object { $_.status -eq 'healthy' -or $_.coverage -eq 'healthy' }).Count
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["UnmeasuredStatus"] == "unavailable"
    assert payload["UnmeasuredCoverage"] == "unavailable"
    assert payload["UnmeasuredDuration"] is None
    assert payload["UnmeasuredCpu"] is None
    assert payload["UnmeasuredRecordStatus"] == "informational"
    assert payload["PartialStatus"] == "partial"
    assert payload["PartialDuration"] == 0
    assert payload["PartialCpu"] is None
    assert payload["MeasuredStatus"] == "complete"
    assert payload["MeasuredCoverage"] == "complete"
    assert payload["MeasuredCpuPercent"] == 16.667
    assert payload["MeasuredSamples"] == 30
    assert payload["Thresholds"] == [False, False]
    assert any("owner decision" in note for note in payload["Notes"])
    assert payload["HealthClaims"] == 0


def test_performance_report_summarises_collector_overhead_without_a_verdict():
    """The run-level overhead report totals what was measured, counts what was
    not, and stays explicitly informational."""
    body = """
$measured = New-WpdCollectorSelfMonitoring -Collector 'cpu' -Tier 1 -DurationMs 1500 -CpuSeconds 0.25 -WorkingSetBytes 104857600 -SampleCount 30
$unmeasured = New-WpdCollectorSelfMonitoring -Collector 'trace' -Tier 2 -MeasurementSource 'not-measured'
$first = New-WpdCollectorEnvelope -Collector 'cpu' -Tier 1 -Status 'success' -Records @([pscustomobject]@{ id = 1 }) -SelfMonitoring $measured
$second = New-WpdCollectorEnvelope -Collector 'trace' -Tier 2 -Status 'success' -Records @([pscustomobject]@{ id = 2 }) -SelfMonitoring $unmeasured
$report = Get-WpdCollectorPerformanceReport -Envelope @($first, $second)
[pscustomobject]@{
    Informational = $report.informational
    ThresholdsEvaluated = $report.thresholdsEvaluated
    CollectorCount = $report.collectorCount
    MeasuredCount = $report.measuredCount
    PartialCount = $report.partialCount
    UnmeasuredCount = $report.unmeasuredCount
    TotalDurationMs = $report.totalDurationMs
    TotalCpuSeconds = $report.totalCpuSeconds
    Collectors = @($report.rows | ForEach-Object { $_.collector }) | Sort-Object
    Statuses = @($report.rows | ForEach-Object { $_.status }) | Sort-Object
    MeasurementStates = @($report.rows | ForEach-Object { $_.measurementStatus }) | Sort-Object
    UnmeasuredDuration = @(@($report.rows | Where-Object { $_.collector -eq 'trace' }).durationMs)
    HealthClaim = $report.healthClaim
    NeverHealthy = $report.neverHealthy
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Informational"] is True
    assert payload["ThresholdsEvaluated"] is False
    assert payload["CollectorCount"] == 2
    assert payload["MeasuredCount"] == 1
    assert payload["PartialCount"] == 0
    assert payload["UnmeasuredCount"] == 1
    assert payload["TotalDurationMs"] == 1500
    assert payload["TotalCpuSeconds"] == 0.25
    assert payload["Collectors"] == ["cpu", "trace"]
    assert payload["Statuses"] == ["success", "success"]
    assert payload["MeasurementStates"] == ["complete", "unavailable"]
    assert payload["UnmeasuredDuration"] == [None]
    assert payload["HealthClaim"] == "none"
    assert payload["NeverHealthy"] is True


CLEANUP_BODY = r"""
$created = Remove-WpdCollectorArtifact -Path '@CREATED@' -CaseRoot '@ROOT@' -CreatedByToolkit
$preserved = Remove-WpdCollectorArtifact -Path '@PRESERVED@' -CaseRoot '@ROOT@'
$again = Remove-WpdCollectorArtifact -Path '@CREATED@' -CaseRoot '@ROOT@' -CreatedByToolkit
$outside = Remove-WpdCollectorArtifact -Path '@OUTSIDE@' -CaseRoot '@ROOT@' -CreatedByToolkit
$none = Remove-WpdCollectorArtifact -Path '' -CaseRoot '@ROOT@' -CreatedByToolkit
[pscustomobject]@{
    CreatedStatus = $created.status
    CreatedRemoved = @($created.removed)
    CreatedReason = $created.reason
    PreservedStatus = $preserved.status
    PreservedReason = $preserved.reason
    PreservedRemoved = @($preserved.removed).Count
    AgainStatus = $again.status
    AgainReason = $again.reason
    AgainRemoved = @($again.removed).Count
    OutsideStatus = $outside.status
    OutsideReason = $outside.reason
    OutsideRemoved = @($outside.removed).Count
    NoneStatus = $none.status
    NoneReason = $none.reason
} | ConvertTo-Json -Depth 6 -Compress
"""


def test_cleanup_removes_only_toolkit_created_artifacts_and_is_idempotent(tmp_path):
    """Cleanup is scoped: it removes only a path the toolkit created inside the
    case root, leaves a pre-existing artifact and an out-of-root path alone, is
    idempotent, and states a reason for every outcome."""
    case_root = tmp_path / "case"
    case_root.mkdir()
    created = case_root / "procdump-mini.dmp"
    created.write_text("partial dump", encoding="ascii")
    preserved = case_root / "user-notes.txt"
    preserved.write_text("operator notes", encoding="ascii")
    outside = tmp_path / "outside.txt"
    outside.write_text("not ours", encoding="ascii")

    body = (
        CLEANUP_BODY.replace("@CREATED@", str(created))
        .replace("@PRESERVED@", str(preserved))
        .replace("@OUTSIDE@", str(outside))
        .replace("@ROOT@", str(case_root))
    )
    payload = run_json(body)

    assert payload["CreatedStatus"] == "removed"
    assert payload["CreatedRemoved"] == [str(created)]
    assert not created.exists()
    assert payload["PreservedStatus"] == "preserved"
    assert payload["PreservedReason"] == "not-created-by-toolkit"
    assert payload["PreservedRemoved"] == 0
    assert preserved.exists(), "a pre-existing artifact must not be removed"
    assert payload["AgainStatus"] == "not-present"
    assert payload["AgainReason"] == "already-absent"
    assert payload["AgainRemoved"] == 0
    assert payload["OutsideStatus"] == "failed"
    assert payload["OutsideReason"] == "outside-case-root"
    assert payload["OutsideRemoved"] == 0
    assert outside.exists(), "a path outside the case root must never be removed"
    assert payload["NoneStatus"] == "not-needed"
    assert payload["NoneReason"] == "no-path"


PLAN_SEAMS = r"""
$script:planCounter = @{ tier0 = 0 }
$script:planInventoryProvider = {
    param($request)
    $script:planCounter.tier0++
    [pscustomobject]@{
        capabilities = @{
            'os' = [pscustomobject]@{ capability = 'os'; status = 'success'; coverage = 'complete'; recordCount = 1; items = @([pscustomobject]@{ id = 'os-1' }); reasons = @(); warnings = @(); errors = @() }
            'storage' = [pscustomobject]@{ capability = 'storage'; status = 'unsupported'; coverage = 'unsupported'; recordCount = 0; items = @(); reasons = @('reliability-counter-unsupported'); warnings = @(); errors = @() }
        }
        capabilityOrder = @('os', 'storage')
        recordCount = 1
    }
}
$script:planProcessProvider = {
    param($index)
    [pscustomobject]@{ ProcessId = 4242; ProcessName = 'synthetic'; StartTimeTicks = 638000000000000000; WorkingSetBytes = 104857600 }
}
$script:planEmptyProvider = { param($index) @() }
"""


def test_collector_plan_run_orders_tiers_queries_tier0_once_and_keeps_failures_isolated():
    """A run produces one envelope per collector in plan order: Tier 0 is
    queried once for the whole run, an individual Tier 1 family that produced no
    series is unavailable without failing its siblings, and the aggregate is a
    stated partial instead of a verdict."""
    body = PLAN_SEAMS + """
$plan = New-WpdCollectorPlan -Preset 'general' -Tier @(0, 1) -PrivacyLevel 'Standard'
$result = Invoke-WpdCollectorPlan -Plan $plan `
    -Tier0Arguments @{ CacheKey = 'run-plan-1'; InventoryProvider = $script:planInventoryProvider; Capability = @('os', 'storage') } `
    -Tier1Family @('cpu', 'memory') `
    -Tier1Arguments @{ SampleCount = 3; SampleIntervalSeconds = 1 } `
    -Tier1Provider @{ cpu = $script:planProcessProvider; memory = $script:planEmptyProvider }
$byCollector = @{}
foreach ($envelope in @($result.envelopes)) { $byCollector[$envelope.collector] = $envelope }
[pscustomobject]@{
    Status = $result.status
    Coverage = $result.coverage
    EnvelopeCount = $result.envelopeCount
    Order = (@($result.envelopes | ForEach-Object { $_.collector }) -join '>')
    Tiers = @($result.plan.tiers)
    Tier0Status = $byCollector['tier0-inventory'].status
    Tier0QueryCount = $script:planCounter.tier0
    Tier0ProviderCalls = $byCollector['tier0-inventory'].providerCallCount
    Tier0Capabilities = @($byCollector['tier0-inventory'].records).Count
    CpuStatus = $byCollector['cpu'].status
    CpuObserved = $byCollector['cpu'].observedSamples
    MemoryStatus = $byCollector['memory'].status
    MemoryReason = $byCollector['memory'].reason
    MemoryCadenceClamped = $byCollector['memory'].samplingPlan.WasClamped
    Tier1Count = @($result.tier1).Count
    Tier2 = ($null -eq $result.tier2)
    Tier3 = ($null -eq $result.tier3)
    QualityStatus = $result.quality.status
    QualityCoverage = $result.quality.coverage
    ReportCount = $result.performanceReport.collectorCount
    Informational = $result.performanceReport.informational
    CleanupStatus = $result.cleanup.status
    HealthClaims = @($result.envelopes | Where-Object { $_.healthClaim -ne 'none' }).Count
    CompletedUtc = $result.completedUtc
    GeneratedUtc = $result.generatedUtc
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["Status"] == "partial"
    assert payload["Coverage"] == "partial"
    assert payload["EnvelopeCount"] == 3
    assert payload["Order"] == "tier0-inventory>cpu>memory"
    assert payload["Tiers"] == [0, 1]
    assert payload["Tier0Status"] == "partial"
    assert payload["Tier0QueryCount"] == 1, "Tier 0 is collected once per run"
    assert payload["Tier0ProviderCalls"] == 1
    assert payload["Tier0Capabilities"] == 2
    assert payload["CpuStatus"] == "success"
    assert payload["CpuObserved"] == 3
    assert payload["MemoryStatus"] == "unavailable"
    assert payload["MemoryReason"] == "no-process-rows-observed"
    assert payload["MemoryCadenceClamped"] is False
    assert payload["Tier1Count"] == 2
    assert payload["Tier2"] is True
    assert payload["Tier3"] is True
    assert payload["QualityStatus"] == "partial"
    assert payload["QualityCoverage"] == "partial"
    assert payload["ReportCount"] == 3
    assert payload["Informational"] is True
    assert payload["CleanupStatus"] == "not-needed"
    assert payload["HealthClaims"] == 0
    assert payload["CompletedUtc"].endswith("Z")
    assert payload["GeneratedUtc"].endswith("Z")


def test_collector_module_source_is_ascii_lf_without_bom_and_avoids_ps7_and_invented_switches():
    """Static gates on the module source: ASCII, LF only, no BOM, PS 5.1
    compatible constructs only, no invented WPR switch, no artifact write of its
    own, and no reference to the production entry point."""
    raw = MODULE.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf"), "the module must not start with a UTF-8 BOM"
    assert b"\r" not in raw, "the module must use LF line endings only"
    non_ascii = [index for index, byte in enumerate(raw) if byte > 0x7F]
    assert non_ascii == [], f"non-ASCII bytes at {non_ascii[:10]}"

    source = raw.decode("ascii")
    forbidden = {
        "class declaration": r"(?m)^\s*class\s+\w+",
        "PS7 null-coalescing": r"\?\?",
        "PS7 pipeline chain": r"&&",
        "using namespace": r"\busing\s+namespace\b",
        "PS7 -AsUTC": r"-AsUTC\b",
        "PS7 -AsHashtable": r"-AsHashtable\b",
        "sub-second sleep": r"Start-Sleep\s+-Milliseconds",
        "invented -maxduration": r"-maxduration",
        "invented -filesize": r"-filesize",
        "obsolete -markerflush": r"-markerflush",
        "artifact write": r"\b(Set-Content|Add-Content|Out-File|New-Item)\b",
        "entry point reference": r"Invoke-WindowsPerformanceDiagnostics\.ps1",
        "automatic remediation": r"\b(Remove-ItemProperty|Set-Service|Start-Service|Stop-Service|Set-MpPreference|Add-MpPreference|bcdedit)\b",
    }
    for label, pattern in forbidden.items():
        assert re.search(pattern, source) is None, f"module source contains {label}"

    assert source.count("Export-ModuleMember") == 1, "the module must export exactly once"
    assert "#Requires -Version 5.1" in source
