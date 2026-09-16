"""Overhead and trace-size safety tests for the WPD toolkit (P2-1).

Every assertion here drives a production seam with deterministic synthetic
input: injected providers, injected clocks that return values instead of
sleeping, and injected free-space/ETL sizes. No wall-clock time, no counter
query and no wpr.exe is involved, so the numbers below are reproducible on a
non-Windows host.

The card's contract is that the toolkit stays inside its declared budgets
before and after a capture:

- Tier 1 interval sampling is never sub-second by default (1 s floor);
- Tier 0 static inventory is collected once per run and then cached;
- the circular recorder has a hard bound, and unbounded file mode is refused
  unless the caller explicitly accepts it;
- the WPR preflight refuses an insufficient free space, an over-long duration
  and an over-budget trace size, and an unmeasured free space is never a pass;
- sample gaps/skips and ETW event loss are reported rather than smoothed;
- self-monitoring emits collector CPU, memory and duration as informational
  data with no threshold verdict (thresholds remain an owner decision).

Overrides: ``WPD_POWERSHELL_EXE`` selects the PowerShell host.
``WPD_OVERHEAD_MODULE_DIR`` is honoured only so the RED (mutation) evidence for
this card can point at a mutated copy of ``src/`` outside the repository; the
default is the repository's own ``src/`` directory, and the override is not
used by any assertion.
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
MODULE_DIR = Path(os.environ.get("WPD_OVERHEAD_MODULE_DIR", str(REPO_ROOT / "src")))
RULES_CONFIG = REPO_ROOT / "config" / "diagnostic-rules.json"
PRESETS_CONFIG = REPO_ROOT / "config" / "diagnostic-presets.json"
OVERHEAD_DOC = REPO_ROOT / "docs" / "performance-overhead.md"

# Wpd.Collectors is imported first: it loads its own dependencies as nested
# modules, and the explicit global imports that follow lift each dependency into
# the session so a test body can call the ETW/telemetry seam directly. Importing
# the dependencies first would leave them nested inside Wpd.Collectors and
# therefore invisible to the test body.
MODULE_IMPORTS = [
    "Wpd.Collectors.psm1",
    "Wpd.Common.psm1",
    "Wpd.Inventory.psm1",
    "Wpd.Telemetry.psm1",
    "Wpd.Etw.psm1",
    "Wpd.Events.psm1",
    "Wpd.Escalation.psm1",
]


def _ps_quote(value: object) -> str:
    """Single-quote a value for a PowerShell command line."""
    return "'" + str(value).replace("'", "''") + "'"


def run_pwsh(body: str) -> str:
    """Import the real modules and execute a test body."""
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    if not shutil.which(powershell):
        pytest.skip(f"{powershell} is required for the overhead gate")
    for name in MODULE_IMPORTS:
        module_path = MODULE_DIR / name
        assert module_path.is_file(), f"missing module: {module_path}"
    imports = "\n".join(
        "Import-Module -Name {0} -Force".format(_ps_quote(MODULE_DIR / name))
        for name in MODULE_IMPORTS
    )
    harness = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            imports,
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
    return result.stdout


def run_json(body: str) -> dict:
    output = run_pwsh(body).strip()
    assert output, "PowerShell body emitted no JSON"
    return json.loads(output)


def as_list(value) -> list:
    """Normalize a possibly-unwrapped JSON value into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def rules_config() -> dict:
    return json.loads(RULES_CONFIG.read_text(encoding="utf-8"))


def read_overhead_doc() -> str:
    assert OVERHEAD_DOC.is_file(), f"missing deliverable: {OVERHEAD_DOC}"
    return OVERHEAD_DOC.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. The declared sampling floor
# ---------------------------------------------------------------------------


def test_the_declared_sampling_floor_is_one_second_in_both_configs():
    """The 1 s floor is declared in the central configuration, not only in
    code, so it is an approved policy rather than a local constant."""
    rules = rules_config()
    presets = json.loads(PRESETS_CONFIG.read_text(encoding="utf-8"))

    assert rules["samplingFloorSeconds"] == 1
    assert presets["samplingFloorSeconds"] == 1
    assert re.search(r"not designed to be collected more than once per second", rules["samplingFloorBasis"])


def test_the_sampling_plan_clamps_every_sub_second_request_to_the_floor():
    """Any requested interval below the 1 s floor is clamped and reported as
    clamped; 1 s and above are accepted; an absent or non-positive request is
    unavailable instead of silently becoming a default."""
    body = """
$config = Get-Content -LiteralPath __RULES__ -Raw | ConvertFrom-Json
$rows = @()
foreach ($requested in @(0.001, 0.1, 0.5, 0.999, 1, 1.0, 2, 0, -3)) {
    foreach ($useConfig in @($false, $true)) {
        $effectiveConfig = $null
        if ($useConfig) { $effectiveConfig = $config }
        $plan = New-TelemetrySamplingPlan -RequestedIntervalSeconds $requested -Config $effectiveConfig
        $rows += [pscustomobject]@{
            requested = [double]$requested
            withConfig = $useConfig
            status = [string]$plan.Status
            effective = $plan.EffectiveIntervalSeconds
            floor = $plan.FloorSeconds
            clamped = [bool]$plan.WasClamped
        }
    }
}
$absent = New-TelemetrySamplingPlan
[pscustomobject]@{
    Rows = $rows
    AbsentStatus = [string]$absent.Status
    AbsentEffective = $absent.EffectiveIntervalSeconds
    AbsentFloor = $absent.FloorSeconds
} | ConvertTo-Json -Depth 6 -Compress
""".replace("__RULES__", _ps_quote(RULES_CONFIG))
    payload = run_json(body)
    rows = as_list(payload["Rows"])
    assert len(rows) == 18

    for row in rows:
        assert row["floor"] == 1.0, row
        if row["requested"] in (0.001, 0.1, 0.5, 0.999):
            assert row["status"] == "clamped", row
            assert row["effective"] == 1.0, row
            assert row["clamped"] is True, row
        elif row["requested"] in (1, 1.0):
            assert row["status"] == "accepted", row
            assert row["effective"] == 1.0, row
            assert row["clamped"] is False, row
        elif row["requested"] == 2:
            assert row["status"] == "accepted", row
            assert row["effective"] == 2.0, row
        else:
            assert row["status"] == "unavailable", row
            assert row["effective"] is None, row

    assert payload["AbsentStatus"] == "unavailable"
    assert payload["AbsentEffective"] is None
    assert payload["AbsentFloor"] == 1.0


def test_every_tier_one_family_rejects_a_sub_second_interval_without_sampling():
    """No Tier 1 family can be driven below the floor, and the provider seam is
    never invoked for a rejected cadence."""
    body = """
$global:WpdProviderCalls = 0
$provider = {
    param($index)
    $global:WpdProviderCalls = $global:WpdProviderCalls + 1
    return @([pscustomobject]@{
        ProcessId = 4242
        StartTimeTicks = 638900000000000000
        CpuTimeSeconds = [double]$index
        WorkingSetBytes = 1048576
        ProcessName = 'fixture'
    })
}
$rows = @()
foreach ($family in @(Get-WpdCollectorTierMap | Where-Object { $_.tier -eq 1 } | Sort-Object id)) {
    $envelope = Invoke-WpdTier1Collection -Family $family.id -SampleIntervalSeconds 0.5 -SampleCount 3 -Provider $provider
    $rows += [pscustomobject]@{
        family = [string]$family.id
        status = [string]$envelope.status
        coverage = [string]$envelope.coverage
        cadenceValidated = [bool]$envelope.cadenceValidated
        effective = $envelope.effectiveIntervalSeconds
        floor = $envelope.floorSeconds
        planStatus = [string]$envelope.samplingPlan.Status
        series = @($envelope.series).Count
        reasons = @($envelope.reasons)
        windows = [bool]$envelope.hostWindows
    }
}
[pscustomobject]@{
    Rows = $rows
    FamilyCount = @($rows).Count
    ProviderCalls = [int]$global:WpdProviderCalls
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)
    rows = as_list(payload["Rows"])

    assert payload["FamilyCount"] >= 8, payload["FamilyCount"]
    assert payload["ProviderCalls"] == 0, "a rejected cadence still sampled"
    for row in rows:
        assert row["status"] == "unavailable", row
        assert row["cadenceValidated"] is False, row
        assert row["effective"] == 1.0, row
        assert row["floor"] == 1.0, row
        assert row["planStatus"] == "clamped", row
        assert row["series"] == 0, row
        reasons = as_list(row["reasons"])
        assert "sampling-interval-below-floor" in reasons, row
        assert "no-sampling-performed" in reasons, row


def test_tier_one_sampling_paces_the_floored_interval_and_never_sleeps_sub_second():
    """The sampling loop asks for the floored interval and nothing shorter: the
    injected sleep seam records exactly the effective interval, and a paused
    request never sleeps at all."""
    body = """
function New-FxRow {
    param([double]$Cpu)
    return [pscustomobject]@{
        ProcessId = 4242
        StartTimeTicks = 638900000000000000
        CpuTimeSeconds = $Cpu
        WorkingSetBytes = 1048576
        ProcessName = 'fixture'
    }
}
$global:WpdSleepLog = New-Object System.Collections.ArrayList
$global:WpdSampleCalls = 0
$provider = {
    param($index)
    $global:WpdSampleCalls = $global:WpdSampleCalls + 1
    return @([pscustomobject]@{
        ProcessId = 4242
        StartTimeTicks = 638900000000000000
        CpuTimeSeconds = [double]$index
        WorkingSetBytes = 1048576
        ProcessName = 'fixture'
    })
}
$clock = { param($index) return ([double]$index * 1.0) }
$sleep = { param($seconds) [void]$global:WpdSleepLog.Add([double]$seconds) }

$paced = Invoke-WpdTier1Collection -Family 'cpu' -SampleCount 3 -SampleIntervalSeconds 1 `
    -Provider $provider -ClockProvider $clock -SleepProvider $sleep
$pacedSleeps = @($global:WpdSleepLog | ForEach-Object { [double]$_ })

$global:WpdSleepLog = New-Object System.Collections.ArrayList
$global:WpdSampleCalls = 0
$subSecond = Invoke-WpdTier1Collection -Family 'cpu' -SampleCount 3 -SampleIntervalSeconds 0.25 `
    -Provider $provider -ClockProvider $clock -SleepProvider $sleep
$subSecondSleeps = @($global:WpdSleepLog).Count

$global:WpdSleepLog = New-Object System.Collections.ArrayList
$absent = Invoke-WpdTier1Collection -Family 'cpu' -SampleCount 3 `
    -Provider $provider -ClockProvider $clock -SleepProvider $sleep
$absentSleeps = @($global:WpdSleepLog).Count
$sampleCalls = [int]$global:WpdSampleCalls

[pscustomobject]@{
    PacedStatus = [string]$paced.status
    PacedCoverage = [string]$paced.coverage
    PacedObserved = [int]$paced.observedSamples
    PacedExpected = [int]$paced.expectedSamples
    PacedGaps = [int]$paced.gapCount
    PacedSeries = @($paced.series).Count
    PacedEffective = $paced.effectiveIntervalSeconds
    PacedPacing = $paced.effectiveIntervalSeconds
    PacedSleeps = $pacedSleeps
    SubSecondStatus = [string]$subSecond.status
    SubSecondEffective = $subSecond.effectiveIntervalSeconds
    SubSecondPlanStatus = [string]$subSecond.samplingPlan.Status
    SubSecondSleeps = $subSecondSleeps
    AbsentStatus = [string]$absent.status
    AbsentSleeps = $absentSleeps
    SampleCalls = $sampleCalls
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_json(body)

    assert payload["PacedStatus"] == "success", payload
    assert payload["PacedCoverage"] == "complete", payload
    assert payload["PacedObserved"] == 3
    assert payload["PacedExpected"] == 3
    assert payload["PacedGaps"] == 0
    assert payload["PacedSeries"] == 3
    assert payload["PacedEffective"] == 1.0

    sleeps = [float(value) for value in as_list(payload["PacedSleeps"])]
    assert sleeps == [1.0, 1.0], sleeps
    assert all(value >= 1.0 for value in sleeps), sleeps

    assert payload["SubSecondStatus"] == "unavailable"
    assert payload["SubSecondPlanStatus"] == "clamped"
    assert payload["SubSecondSleeps"] == 0
    assert payload["AbsentStatus"] == "unavailable"
    assert payload["AbsentSleeps"] == 0
    assert payload["SampleCalls"] == 0, "no sample was expected from a rejected cadence"


# ---------------------------------------------------------------------------
# 2. Static inventory is cached
# ---------------------------------------------------------------------------


def test_static_inventory_is_collected_once_per_run_and_served_from_cache():
    """Tier 0 queries its provider once per run key; a second collector-level
    call is served from the cache, -Refresh re-queries, a different privacy
    level has its own projection, and the inventory module's own session cache
    is separate and equally sticky."""
    body = """
$global:WpdTier0ProviderCalls = 0
$tier0Provider = {
    param($request)
    $global:WpdTier0ProviderCalls = $global:WpdTier0ProviderCalls + 1
    $capabilities = @{}
    foreach ($id in @($request.capability)) {
        $capabilities[[string]$id] = [pscustomobject]@{
            id = [string]$id
            status = 'success'
            coverage = 'complete'
            recordCount = 1
            items = @([pscustomobject]@{ Name = [string]$id })
            reasons = @()
            warnings = @()
            errors = @()
            source = 'injected-tier0'
        }
    }
    return [pscustomobject]@{ capabilities = $capabilities; capabilityOrder = @($request.capability) }
}
$tier0Ids = @(Get-WpdCollectorTierMap | Where-Object { $_.tier -eq 0 } | ForEach-Object { $_.id })
Clear-WpdCollectorTier0Cache
$first = Invoke-WpdTier0Collection -Preset 'cpu-heavy' -PrivacyLevel 'Standard' -HostFingerprint 'fixture-host' -InventoryProvider $tier0Provider
$callsAfterFirst = [int]$global:WpdTier0ProviderCalls
$second = Invoke-WpdTier0Collection -Preset 'cpu-heavy' -PrivacyLevel 'Standard' -HostFingerprint 'fixture-host' -InventoryProvider $tier0Provider
$callsAfterSecond = [int]$global:WpdTier0ProviderCalls
$refresh = Invoke-WpdTier0Collection -Preset 'cpu-heavy' -PrivacyLevel 'Standard' -HostFingerprint 'fixture-host' -InventoryProvider $tier0Provider -Refresh
$callsAfterRefresh = [int]$global:WpdTier0ProviderCalls
$otherPrivacy = Invoke-WpdTier0Collection -Preset 'cpu-heavy' -PrivacyLevel 'Redacted' -HostFingerprint 'fixture-host' -InventoryProvider $tier0Provider
$callsAfterPrivacy = [int]$global:WpdTier0ProviderCalls
Clear-WpdCollectorTier0Cache
$afterClear = Invoke-WpdTier0Collection -Preset 'cpu-heavy' -PrivacyLevel 'Standard' -HostFingerprint 'fixture-host' -InventoryProvider $tier0Provider
$callsAfterClear = [int]$global:WpdTier0ProviderCalls

$global:WpdInventoryProviderCalls = 0
$inventoryProviders = @{
    os = {
        $global:WpdInventoryProviderCalls = $global:WpdInventoryProviderCalls + 1
        return [pscustomobject]@{ Caption = 'Fixture OS'; Version = '10.0.0' }
    }
}
$capabilityMapCount = @(Get-WpdInventoryCapabilityMap).Count
Clear-WpdInventoryCache
$inventoryFirst = Get-WpdInventory -Providers $inventoryProviders -CacheKey 'overhead-fixture'
$inventoryCallsFirst = [int]$global:WpdInventoryProviderCalls
$inventorySecond = Get-WpdInventory -Providers $inventoryProviders -CacheKey 'overhead-fixture'
$inventoryCallsSecond = [int]$global:WpdInventoryProviderCalls
$listing = @(Get-WpdInventoryCache | ForEach-Object {
    [pscustomobject]@{ key = [string]$_.key; complete = [bool]$_.complete; capabilityCount = [int]$_.capabilityCount }
})
Clear-WpdInventoryCache -CacheKey 'overhead-fixture'
$listingAfterClear = @(Get-WpdInventoryCache).Count

[pscustomobject]@{
    Tier0Ids = $tier0Ids.Count
    CallsAfterFirst = $callsAfterFirst
    CallsAfterSecond = $callsAfterSecond
    CallsAfterRefresh = $callsAfterRefresh
    CallsAfterPrivacy = $callsAfterPrivacy
    CallsAfterClear = $callsAfterClear
    FirstCacheHit = [bool]$first.cacheHit
    FirstProviderCalls = [int]$first.providerCallCount
    FirstCapabilities = [int]$first.capabilityCount
    SecondCacheHit = [bool]$second.cacheHit
    SecondProviderCalls = [int]$second.providerCallCount
    SecondCapabilities = [int]$second.capabilityCount
    SecondReasons = @($second.reasons)
    RefreshCacheHit = [bool]$refresh.cacheHit
    PrivacyCacheHit = [bool]$otherPrivacy.cacheHit
    AfterClearCacheHit = [bool]$afterClear.cacheHit
    InventoryCallsFirst = $inventoryCallsFirst
    InventoryCallsSecond = $inventoryCallsSecond
    InventoryFirstCached = [bool]$inventoryFirst.cached
    InventorySecondCached = [bool]$inventorySecond.cached
    InventoryFirstCachedAfterSecondCall = [bool]$inventoryFirst.cached
    CapabilityMapCount = $capabilityMapCount
    Listing = $listing
    ListingAfterClear = $listingAfterClear
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_json(body)

    tier0_count = int(payload["Tier0Ids"])
    assert tier0_count >= 10, tier0_count

    assert payload["CallsAfterFirst"] == 1
    assert payload["CallsAfterSecond"] == 1, "the second Tier 0 run call re-queried the provider"
    assert payload["CallsAfterRefresh"] == 2, "-Refresh must re-query"
    assert payload["CallsAfterPrivacy"] == 3, "a different privacy level needs its own projection"
    assert payload["CallsAfterClear"] == 4, "an explicitly cleared cache must re-query"

    assert payload["FirstCacheHit"] is False
    assert payload["FirstProviderCalls"] == 1
    assert payload["FirstCapabilities"] == tier0_count
    assert payload["SecondCacheHit"] is True
    assert payload["SecondProviderCalls"] == 0
    assert payload["SecondCapabilities"] == tier0_count
    assert "served-from-tier0-cache" in as_list(payload["SecondReasons"])
    assert payload["RefreshCacheHit"] is False
    assert payload["PrivacyCacheHit"] is False
    assert payload["AfterClearCacheHit"] is False

    assert payload["InventoryCallsFirst"] == 1
    assert payload["InventoryCallsSecond"] == 1, "the inventory session cache was not reused"
    assert payload["InventoryFirstCached"] is False
    assert payload["InventorySecondCached"] is True
    assert payload["InventoryFirstCachedAfterSecondCall"] is False, "a cache hit mutated an earlier caller's result"

    listing = as_list(payload["Listing"])
    assert len(listing) == 1, listing
    assert listing[0]["key"] == "overhead-fixture"
    assert listing[0]["capabilityCount"] == int(payload["CapabilityMapCount"])
    assert listing[0]["complete"] is True
    assert payload["ListingAfterClear"] == 0


# ---------------------------------------------------------------------------
# 3. The circular recorder and its hard bound
# ---------------------------------------------------------------------------


def test_the_circular_recorder_is_hard_bounded_for_every_preset():
    """Every canonical preset resolves to a memory-mode recording with a
    positive trace budget and duration bound; file mode is reachable only
    through an explicit acceptance, and the Flight Recorder refuses it."""
    body = """
$rows = @()
foreach ($presetRow in @(Get-WpdEtwPresetTable | Where-Object { $null -eq $_.aliasOf } | Sort-Object preset)) {
    $profile = Get-WpdEtwPresetProfile -Preset $presetRow.preset
    $rows += [pscustomobject]@{
        preset = [string]$presetRow.preset
        mode = [string]$profile.Mode
        unbounded = [bool]$profile.Unbounded
        circular = [bool]$profile.CircularBuffer
        boundedOnDisk = [bool]$profile.BoundedOnDisk
        fileModeRequested = [bool]$profile.FileModeRequested
        budgetMB = [int]$profile.TraceBudgetMB
        maxDurationSeconds = [int]$profile.MaxDurationSeconds
    }
}
$memoryStrategy = Get-WpdCaptureStrategy -CaptureMode Repro -Preset 'cpu-heavy'
$fileStrategy = Get-WpdCaptureStrategy -CaptureMode Repro -Preset 'cpu-heavy' -AcceptUnboundedFileMode
$recorder = Get-WpdCaptureStrategy -CaptureMode FlightRecorder -Preset 'intermittent'
$recorderFile = Get-WpdCaptureStrategy -CaptureMode FlightRecorder `
    -PresetProfile (Get-WpdEtwPresetProfile -Preset 'intermittent' -AllowFileMode)
$refused = Test-WpdCaptureStorageBound -Strategy $fileStrategy -FreeSpaceBytes 1099511627776
$acceptedFile = Test-WpdCaptureStorageBound -Strategy $fileStrategy -FreeSpaceBytes 1099511627776 -AcceptUnboundedFileMode
$refusedPreflightStatus = $null
if ($null -ne $refused.Preflight) { $refusedPreflightStatus = [string]$refused.Preflight.Status }
$memoryStart = New-WpdEtwWprStartCommand -PresetProfile (Get-WpdEtwPresetProfile -Preset 'cpu-heavy')
$fileStart = New-WpdEtwWprStartCommand -PresetProfile (Get-WpdEtwPresetProfile -Preset 'intermittent' -AllowFileMode)

[pscustomobject]@{
    Rows = $rows
    MemoryStrategy = [pscustomobject]@{
        bounded = [bool]$memoryStrategy.Bounded
        storagePolicy = [string]$memoryStrategy.StoragePolicy
        mode = [string]$memoryStrategy.Mode
        fileModePermitted = [bool]$memoryStrategy.FileModePermitted
        budgetMB = [int]$memoryStrategy.TraceBudgetMB
        maxDurationSeconds = [int]$memoryStrategy.MaxDurationSeconds
        durationBoundedBy = [string]$memoryStrategy.DurationBoundedBy
        status = [string]$memoryStrategy.Status
    }
    FileStrategy = [pscustomobject]@{
        bounded = [bool]$fileStrategy.Bounded
        storagePolicy = [string]$fileStrategy.StoragePolicy
        fileModePermitted = [bool]$fileStrategy.FileModePermitted
        status = [string]$fileStrategy.Status
        reasons = @($fileStrategy.Reasons)
    }
    Recorder = [pscustomobject]@{
        bounded = [bool]$recorder.Bounded
        storagePolicy = [string]$recorder.StoragePolicy
        mode = [string]$recorder.Mode
        fileModePermitted = [bool]$recorder.FileModePermitted
        unboundedFileRefused = [bool]$recorder.UnboundedFileRefused
        continuous = [bool]$recorder.Continuous
        durationBoundedBy = [string]$recorder.DurationBoundedBy
        status = [string]$recorder.Status
    }
    RecorderFile = [pscustomobject]@{
        bounded = [bool]$recorderFile.Bounded
        storagePolicy = [string]$recorderFile.StoragePolicy
        mode = [string]$recorderFile.Mode
        fileModePermitted = [bool]$recorderFile.FileModePermitted
        unboundedFileRefused = [bool]$recorderFile.UnboundedFileRefused
        status = [string]$recorderFile.Status
    }
    Refused = [pscustomobject]@{
        status = [string]$refused.Status
        ready = [bool]$refused.Ready
        bounded = [bool]$refused.Bounded
        preflightStatus = $refusedPreflightStatus
    }
    AcceptedFile = [pscustomobject]@{
        status = [string]$acceptedFile.Status
        ready = [bool]$acceptedFile.Ready
        bounded = [bool]$acceptedFile.Bounded
        policy = [string]$acceptedFile.StoragePolicy
        preflightStatus = [string]$acceptedFile.Preflight.Status
    }
    MemoryStartArgs = @($memoryStart.Arguments)
    FileStartArgs = @($fileStart.Arguments)
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)
    rows = as_list(payload["Rows"])
    assert len(rows) == 13, len(rows)

    for row in rows:
        assert row["mode"] == "memory", row
        assert row["unbounded"] is False, row
        assert row["circular"] is True, row
        assert row["boundedOnDisk"] is True, row
        assert row["fileModeRequested"] is False, row
        assert row["budgetMB"] > 0, row
        assert row["maxDurationSeconds"] > 0, row

    cpu_heavy = next(row for row in rows if row["preset"] == "cpu-heavy")
    memory = payload["MemoryStrategy"]
    assert memory["bounded"] is True
    assert memory["storagePolicy"] == "circular-memory"
    assert memory["mode"] == "memory"
    assert memory["fileModePermitted"] is False
    assert memory["budgetMB"] == cpu_heavy["budgetMB"]
    assert memory["maxDurationSeconds"] == cpu_heavy["maxDurationSeconds"]
    assert memory["durationBoundedBy"] == "preset-max-duration"
    assert memory["status"] == "success"

    file_strategy = payload["FileStrategy"]
    assert file_strategy["bounded"] is False
    assert file_strategy["storagePolicy"] == "unbounded-file"
    assert file_strategy["fileModePermitted"] is True
    assert file_strategy["status"] == "partial"
    assert "unbounded-file-mode-accepted-explicitly" in as_list(file_strategy["reasons"])

    recorder = payload["Recorder"]
    assert recorder["bounded"] is True
    assert recorder["storagePolicy"] == "circular-memory"
    assert recorder["mode"] == "memory"
    assert recorder["fileModePermitted"] is False
    assert recorder["unboundedFileRefused"] is True
    assert recorder["continuous"] is True
    assert recorder["durationBoundedBy"] == "circular-buffer-and-preset-max-duration"
    assert recorder["status"] == "success"

    recorder_file = payload["RecorderFile"]
    assert recorder_file["bounded"] is False
    assert recorder_file["storagePolicy"] == "unbounded-file"
    assert recorder_file["fileModePermitted"] is False, "a Flight Recorder must refuse file mode"
    assert recorder_file["unboundedFileRefused"] is True
    assert recorder_file["status"] == "partial"

    refused = payload["Refused"]
    assert refused["ready"] is False
    assert refused["status"] == "unbounded-file-mode"
    assert refused["bounded"] is False
    assert refused["preflightStatus"] is None, "the free-space preflight must not run for a refused mode"

    accepted_file = payload["AcceptedFile"]
    assert accepted_file["status"] == "ready"
    assert accepted_file["ready"] is True
    assert accepted_file["bounded"] is False, "an explicitly accepted file mode is still unbounded"
    assert accepted_file["policy"] == "unbounded-file"
    assert accepted_file["preflightStatus"] == "ready", "an accepted file mode still passes the free-space gate"

    memory_args = [str(value) for value in as_list(payload["MemoryStartArgs"])]
    file_args = [str(value) for value in as_list(payload["FileStartArgs"])]
    invented = re.compile(r"(?i)^-(maxduration|filesize|maxfilesize|markerflush|filenamemax)$")
    assert not any(invented.match(arg) for arg in memory_args), memory_args
    assert not any(invented.match(arg) for arg in file_args), file_args
    assert memory_args[:2] == ["-start", "CPU.verbose"], memory_args
    assert "-filemode" not in memory_args, memory_args
    assert "-filemode" in file_args, file_args


# ---------------------------------------------------------------------------
# 4. The WPR preflight: free space, duration, trace size
# ---------------------------------------------------------------------------


def test_the_wpr_preflight_refuses_insufficient_space_and_never_assumes_room():
    """The free-space gate uses the preset budget plus headroom, reports a real
    deficit, passes exactly at the required byte count, and reports an
    unmeasured volume as unavailable rather than as room."""
    body = """
function Get-PreflightSummary {
    param($Preflight)
    return [pscustomobject]@{
        status = [string]$Preflight.Status
        ready = [bool]$Preflight.Ready
        budgetMB = [int]$Preflight.TraceBudgetMB
        maxDurationSeconds = [int]$Preflight.MaxDurationSeconds
        requestedDurationSeconds = [int]$Preflight.RequestedDurationSeconds
        requiredBytes = [long]$Preflight.RequiredBytes
        freeSpaceBytes = $Preflight.FreeSpaceBytes
        deficitBytes = $Preflight.DeficitBytes
        durationBounded = [bool]$Preflight.DurationBounded
        reason = [string]$Preflight.Reason
    }
}
$oneByteShort = Get-PreflightSummary (Test-WpdEtwCapturePreflight -FreeSpaceBytes 805306367)
$tiny = Get-PreflightSummary (Test-WpdEtwCapturePreflight -FreeSpaceBytes 1024)
$exact = Get-PreflightSummary (Test-WpdEtwCapturePreflight -FreeSpaceBytes 805306368)
$profile = Get-WpdEtwPresetProfile -Preset 'cpu-heavy'
$withProfile = Get-PreflightSummary (Test-WpdEtwCapturePreflight -PresetProfile $profile -FreeSpaceBytes 805306368)
$profileReady = Get-PreflightSummary (Test-WpdEtwCapturePreflight -PresetProfile $profile -FreeSpaceBytes 1073741824)
$unmeasured = Get-PreflightSummary (Test-WpdEtwCapturePreflight)
$unresolvableVolume = Get-PreflightSummary (Test-WpdEtwCapturePreflight -OutputDirectory 'Z:\\WPD\\cases')

[pscustomobject]@{
    OneByteShort = $oneByteShort
    Tiny = $tiny
    Exact = $exact
    WithProfile = $withProfile
    ProfileReady = $profileReady
    Unmeasured = $unmeasured
    UnresolvableVolume = $unresolvableVolume
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_json(body)

    # Default contract when no preset policy is supplied: 512 MB budget with a
    # 256 MB floor on the headroom -> 768 MB required.
    required_default = 768 * 1024 * 1024
    short = payload["OneByteShort"]
    assert short["status"] == "insufficient-space"
    assert short["ready"] is False
    assert short["budgetMB"] == 512
    assert short["maxDurationSeconds"] == 600
    assert short["requiredBytes"] == required_default
    assert short["freeSpaceBytes"] == required_default - 1
    assert short["deficitBytes"] == 1

    tiny = payload["Tiny"]
    assert tiny["status"] == "insufficient-space"
    assert tiny["deficitBytes"] == required_default - 1024

    exact = payload["Exact"]
    assert exact["status"] == "ready"
    assert exact["ready"] is True
    assert exact["deficitBytes"] == 0

    # cpu-heavy: 768 MB budget, headroom max(256 MB, 768/4 MB) = 256 MB.
    with_profile = payload["WithProfile"]
    assert with_profile["budgetMB"] == 768
    assert with_profile["requiredBytes"] == 1024 * 1024 * 1024
    assert with_profile["status"] == "insufficient-space"
    assert with_profile["deficitBytes"] == (1024 * 1024 * 1024) - (768 * 1024 * 1024)
    assert payload["ProfileReady"]["status"] == "ready"
    assert payload["ProfileReady"]["ready"] is True

    unmeasured = payload["Unmeasured"]
    assert unmeasured["status"] == "unavailable"
    assert unmeasured["ready"] is False
    assert unmeasured["freeSpaceBytes"] is None
    assert unmeasured["requiredBytes"] == required_default
    assert unmeasured["deficitBytes"] is None

    unresolvable = payload["UnresolvableVolume"]
    assert unresolvable["ready"] is False
    assert unresolvable["status"] == "unavailable", unresolvable
    assert unresolvable["freeSpaceBytes"] is None


def test_the_capture_duration_and_trace_size_limits_are_enforced():
    """A duration above the preset maximum is refused before anything starts, a
    requested size cap can only lower the preset budget, the post-stop ETL check
    removes an oversized trace, and the Tier 2 seam carries both limits through
    to the produced artifact."""
    body = """
function Get-PreflightSummary {
    param($Preflight)
    return [pscustomobject]@{
        status = [string]$Preflight.Status
        ready = [bool]$Preflight.Ready
        budgetMB = [int]$Preflight.TraceBudgetMB
        maxDurationSeconds = [int]$Preflight.MaxDurationSeconds
        requiredBytes = [long]$Preflight.RequiredBytes
        durationBounded = [bool]$Preflight.DurationBounded
        warnings = @($Preflight.Warnings)
    }
}
function Get-TraceSummary {
    param($Validation)
    return [pscustomobject]@{
        exists = [bool]$Validation.Exists
        etlBytes = $Validation.EtlBytes
        maxTraceSizeMB = [int]$Validation.MaxTraceSizeMB
        empty = [bool]$Validation.Empty
        oversized = [bool]$Validation.Oversized
        kept = [bool]$Validation.Kept
        traceRemoved = [bool]$Validation.TraceRemoved
        status = [string]$Validation.Status
        reason = [string]$Validation.Reason
        warnings = @($Validation.Warnings)
    }
}
$profile = Get-WpdEtwPresetProfile -Preset 'cpu-heavy'
$overDuration = Get-PreflightSummary (Test-WpdEtwCapturePreflight -PresetProfile $profile -FreeSpaceBytes 107374182400 -RequestedDurationSeconds 301)
$atDuration = Get-PreflightSummary (Test-WpdEtwCapturePreflight -PresetProfile $profile -FreeSpaceBytes 107374182400 -RequestedDurationSeconds 300)
$smallerCap = Get-PreflightSummary (Test-WpdEtwCapturePreflight -PresetProfile $profile -FreeSpaceBytes 107374182400 -MaxTraceSizeMB 256)
$largerCap = Get-PreflightSummary (Test-WpdEtwCapturePreflight -PresetProfile $profile -FreeSpaceBytes 107374182400 -MaxTraceSizeMB 4096)

$capExact = Get-TraceSummary (Get-WpdEtwTraceValidation -EtlPath 'case\\cpu.etl' -SizeBytes 536870912)
$capOver = Get-TraceSummary (Get-WpdEtwTraceValidation -EtlPath 'case\\cpu.etl' -SizeBytes 629145600)
$raisedCap = Get-TraceSummary (Get-WpdEtwTraceValidation -EtlPath 'case\\cpu.etl' -SizeBytes 629145600 -MaxTraceSizeMB 1024)
$emptyTrace = Get-TraceSummary (Get-WpdEtwTraceValidation -EtlPath 'case\\cpu.etl' -SizeBytes 0)
$absentTrace = Get-TraceSummary (Get-WpdEtwTraceValidation -EtlPath 'case\\missing.etl')
$failedStop = Get-TraceSummary (Get-WpdEtwTraceValidation -EtlPath 'case\\cpu.etl' -SizeBytes 1048576 -StopExitCode 5)

$runner = { param($toolPath, $arguments) return 0 }
$tier2DefaultCap = Invoke-WpdTier2Collection -Preset 'cpu-heavy' -EtlPath 'case\\cpu.etl' -Runner $runner `
    -FreeSpaceBytes 107374182400 -SizeBytes 629145600
$tier2PresetCap = Invoke-WpdTier2Collection -Preset 'cpu-heavy' -EtlPath 'case\\cpu.etl' -Runner $runner `
    -FreeSpaceBytes 107374182400 -SizeBytes 629145600 -MaxTraceSizeMB 768
$tier2TooLong = Invoke-WpdTier2Collection -Preset 'cpu-heavy' -EtlPath 'case\\cpu.etl' -Runner $runner `
    -FreeSpaceBytes 107374182400 -RequestedDurationSeconds 3600

[pscustomobject]@{
    OverDuration = $overDuration
    AtDuration = $atDuration
    SmallerCap = $smallerCap
    LargerCap = $largerCap
    CapExact = $capExact
    CapOver = $capOver
    RaisedCap = $raisedCap
    EmptyTrace = $emptyTrace
    AbsentTrace = $absentTrace
    FailedStop = $failedStop
    Tier2DefaultCapStatus = [string]$tier2DefaultCap.status
    Tier2DefaultCapReasons = @($tier2DefaultCap.reasons)
    Tier2DefaultCapOversized = [bool]$tier2DefaultCap.traceValidation.Oversized
    Tier2DefaultCapKept = [bool]$tier2DefaultCap.traceValidation.Kept
    Tier2DefaultCapRemoved = [bool]$tier2DefaultCap.traceValidation.TraceRemoved
    Tier2DefaultCapSize = [int]$tier2DefaultCap.traceValidation.MaxTraceSizeMB
    Tier2PresetCapStatus = [string]$tier2PresetCap.status
    Tier2PresetCapOversized = [bool]$tier2PresetCap.traceValidation.Oversized
    Tier2PresetCapSize = [int]$tier2PresetCap.traceValidation.MaxTraceSizeMB
    Tier2TooLongStatus = [string]$tier2TooLong.status
    Tier2TooLongReason = [string]$tier2TooLong.reason
    Tier2TooLongBound = [string]$tier2TooLong.storageBound.Status
    Tier2TooLongCommands = @($tier2TooLong.commands).Count
    Tier2Commands = @($tier2DefaultCap.commands)
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    over_duration = payload["OverDuration"]
    assert over_duration["status"] == "duration-exceeds-preset"
    assert over_duration["ready"] is False
    assert over_duration["durationBounded"] is False
    assert over_duration["maxDurationSeconds"] == 300

    at_duration = payload["AtDuration"]
    assert at_duration["status"] == "ready", at_duration
    assert at_duration["durationBounded"] is True

    smaller = payload["SmallerCap"]
    assert smaller["budgetMB"] == 256
    assert smaller["requiredBytes"] == 512 * 1024 * 1024, "256 MB budget plus a 256 MB headroom floor"
    assert smaller["status"] == "ready"

    larger = payload["LargerCap"]
    assert larger["budgetMB"] == 768, "a requested size cap must not raise the preset budget"
    assert any("exceeds the preset budget" in str(w) for w in as_list(larger["warnings"])), larger

    cap_exact = payload["CapExact"]
    assert cap_exact["maxTraceSizeMB"] == 512, "documented default advisory cap"
    assert cap_exact["oversized"] is False
    assert cap_exact["kept"] is True
    assert cap_exact["status"] == "success"

    cap_over = payload["CapOver"]
    assert cap_over["etlBytes"] == 629145600
    assert cap_over["oversized"] is True
    assert cap_over["kept"] is False
    assert cap_over["traceRemoved"] is True
    assert cap_over["status"] == "partial"
    assert "advisory cap" in cap_over["reason"], cap_over

    raised = payload["RaisedCap"]
    assert raised["maxTraceSizeMB"] == 1024
    assert raised["oversized"] is False
    assert raised["kept"] is True

    empty = payload["EmptyTrace"]
    assert empty["exists"] is True
    assert empty["etlBytes"] == 0
    assert empty["empty"] is True
    assert empty["status"] == "partial"

    absent = payload["AbsentTrace"]
    assert absent["exists"] is False
    assert absent["etlBytes"] is None
    assert absent["status"] == "unavailable"

    failed = payload["FailedStop"]
    assert failed["status"] == "partial"
    assert any("wpr -stop" in str(w) for w in as_list(failed["warnings"])), failed

    assert payload["Tier2DefaultCapOversized"] is True
    assert payload["Tier2DefaultCapKept"] is False
    assert payload["Tier2DefaultCapRemoved"] is True
    assert payload["Tier2DefaultCapSize"] == 512
    assert payload["Tier2DefaultCapStatus"] == "partial"
    assert "trace-partial" in as_list(payload["Tier2DefaultCapReasons"])

    assert payload["Tier2PresetCapSize"] == 768
    assert payload["Tier2PresetCapOversized"] is False
    assert payload["Tier2PresetCapStatus"] == "success"

    assert payload["Tier2TooLongBound"] == "duration-exceeds-preset"
    assert payload["Tier2TooLongStatus"] == "unavailable"
    assert payload["Tier2TooLongReason"] == "capture-preflight-duration-exceeds-preset"
    assert payload["Tier2TooLongCommands"] == 0, "a refused duration still executed a command"

    invented = re.compile(r"(?i)^-(maxduration|filesize|maxfilesize|markerflush)$")
    for command in as_list(payload["Tier2Commands"]):
        for token in str(command).split():
            assert not invented.match(token), command


# ---------------------------------------------------------------------------
# 5. Sample gaps, skips and ETW loss
# ---------------------------------------------------------------------------


def test_sample_gaps_and_skips_are_reported_and_never_smoothed():
    """A skipped interval appears as a gap with its real size, the series keeps
    only the samples that were observed, and invalid timestamps/values are
    counted as dropped instead of disappearing."""
    body = """
$samples = @(
    [pscustomobject]@{ MonotonicSeconds = 0.0; Rows = @([pscustomobject]@{ ProcessId = 4242; StartTimeTicks = 638900000000000000; CpuTimeSeconds = 1.0; ProcessName = 'fixture' }) }
    [pscustomobject]@{ MonotonicSeconds = 1.0; Rows = @([pscustomobject]@{ ProcessId = 4242; StartTimeTicks = 638900000000000000; CpuTimeSeconds = 2.0; ProcessName = 'fixture' }) }
    [pscustomobject]@{ MonotonicSeconds = 4.0; Rows = @([pscustomobject]@{ ProcessId = 4242; StartTimeTicks = 638900000000000000; CpuTimeSeconds = 3.0; ProcessName = 'fixture' }) }
)
$series = Measure-ProcessTelemetrySeries -Samples $samples -ExpectedIntervalSeconds 1.0 -LogicalProcessorCount 4

$qualitySamples = @(
    [pscustomobject]@{ TimestampUtc = '2026-01-01T00:00:00Z'; Value = 1 }
    [pscustomobject]@{ TimestampUtc = '2026-01-01T00:00:02Z'; Value = 2 }
    [pscustomobject]@{ TimestampUtc = 'not-a-timestamp'; Value = 3 }
    [pscustomobject]@{ TimestampUtc = '2026-01-01T00:00:04Z'; Value = 'not-a-number' }
)
$quality = Measure-WpdSampleQuality -Samples $qualitySamples -ValueProperty 'Value' `
    -ExpectedStartUtc '2026-01-01T00:00:00Z' -ExpectedEndUtc '2026-01-01T00:00:04Z' `
    -IntervalSeconds 1 -Collector 'cpu' -SourceArtifact 'cpu-series.json'
$noSamples = Measure-WpdSampleQuality -Samples @() -ValueProperty 'Value' `
    -ExpectedStartUtc '2026-01-01T00:00:00Z' -ExpectedEndUtc '2026-01-01T00:00:04Z' `
    -IntervalSeconds 1 -Collector 'cpu'

$global:WpdGapCalls = 0
$provider = {
    param($index)
    $global:WpdGapCalls = $global:WpdGapCalls + 1
    return @([pscustomobject]@{
        ProcessId = 4242
        StartTimeTicks = 638900000000000000
        CpuTimeSeconds = [double]$index
        WorkingSetBytes = 1048576
        ProcessName = 'fixture'
    })
}
$clock = {
    param($index)
    if ($index -eq 0) { return 0.0 }
    if ($index -eq 1) { return 1.0 }
    return 4.0
}
$tier1 = Invoke-WpdTier1Collection -Family 'cpu' -SampleCount 3 -SampleIntervalSeconds 1 `
    -Provider $provider -ClockProvider $clock

[pscustomobject]@{
    SeriesStatus = [string]$series.Status
    SampleCount = [int]$series.SampleCount
    GapCount = [int]$series.GapCount
    Gaps = @($series.Gaps)
    SeriesRows = @($series.Series).Count
    LastIntervalStatus = [string]$series.Series[-1].IntervalStatus
    LastGapSeconds = [double]$series.Series[-1].GapSeconds
    QualityExpected = [int]$quality.expectedSamples
    QualityObserved = [int]$quality.observedSamples
    QualityMissing = [int]$quality.missingSamples
    QualityGapCount = [int]$quality.gapCount
    QualityDropped = [int]$quality.droppedCount
    QualityInvalidTimestamps = [int]$quality.invalidTimestampCount
    QualityInvalidValues = [int]$quality.invalidValueCount
    QualityCoverage = [string]$quality.coverage
    QualityStatus = [string]$quality.status
    QualityReasons = @($quality.reasons)
    QualityUsable = [bool]$quality.isUsable
    NoSamplesObserved = [int]$noSamples.observedSamples
    NoSamplesCoverage = [string]$noSamples.coverage
    NoSamplesReasons = @($noSamples.reasons)
    Tier1Status = [string]$tier1.status
    Tier1Coverage = [string]$tier1.coverage
    Tier1Gaps = [int]$tier1.gapCount
    Tier1Observed = [int]$tier1.observedSamples
    Tier1Expected = [int]$tier1.expectedSamples
    Tier1Reasons = @($tier1.reasons)
    Tier1Series = @($tier1.series).Count
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["SeriesStatus"] == "partial"
    assert payload["SampleCount"] == 3
    assert payload["SeriesRows"] == 3, "the series must not interpolate a missing sample"
    gaps = as_list(payload["Gaps"])
    assert len(gaps) == 1, gaps
    # The gap is reported with its real elapsed time and the time that is
    # missing from the series: a three-second delta at a one-second cadence.
    assert gaps[0]["ElapsedSeconds"] == 3.0, gaps
    assert gaps[0]["MissingIntervals"] == 1, gaps
    assert float(gaps[0]["MissingSeconds"]) == 2.0, gaps
    assert payload["LastIntervalStatus"] == "gap"
    assert float(payload["LastGapSeconds"]) == 2.0

    assert payload["QualityExpected"] == 5
    assert payload["QualityObserved"] == 2
    assert payload["QualityMissing"] == 3
    assert payload["QualityGapCount"] == 3
    assert payload["QualityDropped"] == 2
    assert payload["QualityInvalidTimestamps"] == 1
    assert payload["QualityInvalidValues"] == 1
    assert payload["QualityCoverage"] == "partial"
    assert payload["QualityStatus"] == "partial"
    assert payload["QualityUsable"] is True
    reasons = as_list(payload["QualityReasons"])
    assert "sample-gap" in reasons
    assert "invalid-timestamp" in reasons
    assert "missing-value" in reasons

    assert payload["NoSamplesObserved"] == 0
    assert payload["NoSamplesCoverage"] == "unavailable"
    assert "no-measurements" in as_list(payload["NoSamplesReasons"])

    assert payload["Tier1Status"] == "partial"
    assert payload["Tier1Coverage"] == "partial"
    assert payload["Tier1Gaps"] == 1
    assert payload["Tier1Observed"] == 3
    assert payload["Tier1Expected"] == 3
    assert payload["Tier1Series"] == 3
    tier1_reasons = as_list(payload["Tier1Reasons"])
    assert "sampling-gap" in tier1_reasons
    assert "partial-sampling-coverage" in tier1_reasons


def test_etw_loss_is_reported_and_a_foreign_recording_is_never_cancelled():
    """The documented `wpr -status` output is reconciled: a dropped-event count
    is reported as measured (and absent means unknown, not zero), a recording
    this toolkit did not start is never cancelled, and a still-running recording
    downgrades the capture result."""
    body = """
$ownedText = @'
Windows Performance Recorder
============================

A recording is in progress.

        Instance name : wpd-collect
        Logging mode : Memory
        Dropped event : 1234
'@
$quietText = @'
A recording is in progress.

        Instance name : wpd-collect
        Logging mode : Memory
'@
$foreignText = @'
A recording is in progress.

        Instance name : contoso-recorder
        Logging mode : Memory
        Dropped event : 7
'@
$noSessionText = 'There are no trace profiles running.'

$owned = Test-WpdEtwAbandonedSession -StatusOutput $ownedText -ExpectedInstanceName 'wpd-collect' -OwnerTag 'wpd-collectors'
$quiet = Test-WpdEtwAbandonedSession -StatusOutput $quietText -ExpectedInstanceName 'wpd-collect' -OwnerTag 'wpd-collectors'
$foreign = Test-WpdEtwAbandonedSession -StatusOutput $foreignText -ExpectedInstanceName 'wpd-collect' -OwnerTag 'wpd-collectors'
$noSession = Test-WpdEtwAbandonedSession -StatusOutput $noSessionText -OwnerTag 'wpd-collectors'
$unreadable = Test-WpdEtwAbandonedSession -StatusOutput ''
$collectors = New-WpdEtwWprStatusCommand -Collectors -Details

$global:WpdLeakyStatus = $ownedText
$runner = { param($toolPath, $arguments) return 0 }
$leaky = Invoke-WpdTier2Collection -Preset 'cpu-heavy' -EtlPath 'case\\cpu.etl' -Runner $runner `
    -FreeSpaceBytes 107374182400 -SizeBytes 1048576 -StatusProbe { param($context) return $global:WpdLeakyStatus }

[pscustomobject]@{
    OwnedState = [string]$owned.State
    OwnedOwnerProven = [bool]$owned.OwnerProven
    OwnedAbandoned = [bool]$owned.Abandoned
    OwnedCleanupRequired = [bool]$owned.CleanupRequired
    OwnedDroppedEvents = $owned.DroppedEvents
    OwnedLoggingMode = [string]$owned.LoggingMode
    OwnedInstanceName = [string]$owned.InstanceName
    OwnedCancelArgs = @($owned.CleanupCommand.Arguments)
    OwnedStopKind = [string]$owned.StopSaveCommand.Kind
    QuietDroppedEvents = $quiet.DroppedEvents
    QuietState = [string]$quiet.State
    ForeignState = [string]$foreign.State
    ForeignForeign = [bool]$foreign.Foreign
    ForeignAbandoned = [bool]$foreign.Abandoned
    ForeignCleanupRequired = [bool]$foreign.CleanupRequired
    ForeignCleanupCommand = $foreign.CleanupCommand
    ForeignStopSaveCommand = $foreign.StopSaveCommand
    ForeignInstanceName = [string]$foreign.InstanceName
    NoSessionState = [string]$noSession.State
    NoSessionAbandoned = [bool]$noSession.Abandoned
    NoSessionReason = [string]$noSession.Reason
    UnreadableState = [string]$unreadable.State
    UnreadableReason = [string]$unreadable.Reason
    CollectorArgs = @($collectors.Arguments)
    LeakyStatus = [string]$leaky.status
    LeakyReasons = @($leaky.reasons)
    LeakySessionState = [string]$leaky.capture.SessionState
    LeakyCaptureWarnings = @($leaky.capture.Warnings)
    LeakyStopped = [bool]$leaky.capture.StopAttempted
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["OwnedState"] == "in-progress"
    assert payload["OwnedOwnerProven"] is True
    assert payload["OwnedAbandoned"] is True
    assert payload["OwnedCleanupRequired"] is True
    assert payload["OwnedDroppedEvents"] == 1234, "the measured event loss must be reported"
    assert payload["OwnedLoggingMode"] == "Memory"
    assert payload["OwnedInstanceName"] == "wpd-collect"
    assert as_list(payload["OwnedCancelArgs"])[0] == "-cancel"
    assert payload["OwnedStopKind"] == "stop"

    assert payload["QuietState"] == "in-progress"
    assert payload["QuietDroppedEvents"] is None, "an unreadable loss count is unknown, never zero"

    assert payload["ForeignForeign"] is True
    assert payload["ForeignAbandoned"] is False
    assert payload["ForeignCleanupRequired"] is False
    assert payload["ForeignCleanupCommand"] is None
    assert payload["ForeignStopSaveCommand"] is None
    assert payload["ForeignInstanceName"] == "contoso-recorder"

    assert payload["NoSessionState"] == "none"
    assert payload["NoSessionAbandoned"] is False

    assert payload["UnreadableState"] == "unavailable", "an unreadable status is never 'clean'"
    assert payload["UnreadableReason"]

    assert [str(value) for value in as_list(payload["CollectorArgs"])] == [
        "-status",
        "collectors",
        "-details",
    ]

    assert payload["LeakySessionState"] == "in-progress"
    assert payload["LeakyStatus"] == "partial"
    assert "recording-still-running" in as_list(payload["LeakyReasons"])
    capture_warnings = " ".join(str(w) for w in as_list(payload["LeakyCaptureWarnings"]))
    assert "still in progress" in capture_warnings, payload["LeakyCaptureWarnings"]
    assert payload["LeakyStopped"] is True, "a lossy session must still be stopped"


# ---------------------------------------------------------------------------
# 6. Self-monitoring
# ---------------------------------------------------------------------------


def test_self_monitoring_emits_collector_cpu_memory_and_duration():
    """The overhead record carries collector duration, CPU time and working set
    when they are measured, stays unavailable when they are not, and the
    portfolio report sums only what was measured without any verdict."""
    body = """
$complete = New-WpdCollectorSelfMonitoring -Collector 'cpu' -Tier 1 -DurationMs 2500 -CpuSeconds 1.25 `
    -WorkingSetBytes 104857600 -PeakWorkingSetBytes 125829120 -SampleCount 3 -MeasurementSource 'injected'
$partial = New-WpdCollectorSelfMonitoring -Collector 'gpu-engines' -Tier 1 -DurationMs 1000 -MeasurementSource 'injected'
$unmeasured = New-WpdCollectorSelfMonitoring -Collector 'trace' -Tier 2 -MeasurementSource 'not-measured'
$probe = New-WpdCollectorSelfMonitoring -Collector 'cpu' -Tier 1 -MeasureProcess

$global:WpdSampleCalls = 0
$provider = {
    param($index)
    $global:WpdSampleCalls = $global:WpdSampleCalls + 1
    return @([pscustomobject]@{
        ProcessId = 4242
        StartTimeTicks = 638900000000000000
        CpuTimeSeconds = [double]$index
        WorkingSetBytes = 1048576
        ProcessName = 'fixture'
    })
}
$tier1 = Invoke-WpdTier1Collection -Family 'cpu' -SampleCount 2 -SampleIntervalSeconds 1 -Provider $provider
$tier0 = Invoke-WpdTier0Collection -Preset 'general' -PrivacyLevel 'Standard' -HostFingerprint 'fixture-host'

$envelopeA = New-WpdCollectorEnvelope -Collector 'cpu' -Tier 1 -Status 'success' -Coverage 'complete' `
    -Records @([pscustomobject]@{ kind = 'series' }) -SelfMonitoring $complete
$envelopeB = New-WpdCollectorEnvelope -Collector 'gpu-engines' -Tier 1 -Status 'partial' -Coverage 'partial' `
    -Records @([pscustomobject]@{ kind = 'series' }) -SelfMonitoring $partial
$envelopeC = New-WpdCollectorEnvelope -Collector 'trace' -Tier 2 -Status 'success' -Coverage 'complete' `
    -Records @([pscustomobject]@{ kind = 'capture' }) -SelfMonitoring $unmeasured
$envelopeD = New-WpdCollectorEnvelope -Collector 'unmeasured-context' -Tier 1 -Status 'success' -Coverage 'complete' `
    -Records @([pscustomobject]@{ kind = 'series' })
$report = Get-WpdCollectorPerformanceReport -Envelope @($envelopeA, $envelopeB, $envelopeC, $envelopeD)

[pscustomobject]@{
    CompleteStatus = [string]$complete.measurementStatus
    CompleteCoverage = [string]$complete.coverage
    CompleteCollectorStatus = [string]$complete.status
    CompleteDurationMs = $complete.durationMs
    CompleteCpuSeconds = $complete.cpuSeconds
    CompleteWorkingSetBytes = $complete.workingSetBytes
    CompleteCpuPercent = $complete.cpuPercentOfCollector
    CompleteThresholds = [bool]$complete.thresholdsEvaluated
    PartialStatus = [string]$partial.measurementStatus
    PartialDurationMs = $partial.durationMs
    PartialCpuSeconds = $partial.cpuSeconds
    PartialWorkingSetBytes = $partial.workingSetBytes
    UnmeasuredStatus = [string]$unmeasured.measurementStatus
    UnmeasuredDurationMs = $unmeasured.durationMs
    UnmeasuredNotes = @($unmeasured.notes)
    ProbeSource = [string]$probe.measurementSource
    ProbeCpuSeconds = $probe.cpuSeconds
    ProbeWorkingSetBytes = $probe.workingSetBytes
    ProbeStatus = [string]$probe.measurementStatus
    ProbeThresholds = [bool]$probe.thresholdsEvaluated
    Tier1Source = [string]$tier1.selfMonitoring.measurementSource
    Tier1Status = [string]$tier1.selfMonitoring.measurementStatus
    Tier1DurationMs = $tier1.selfMonitoring.durationMs
    Tier1CpuSeconds = $tier1.selfMonitoring.cpuSeconds
    Tier1WorkingSet = $tier1.selfMonitoring.workingSetBytes
    Tier1SampleCount = [int]$tier1.selfMonitoring.sampleCount
    Tier0Source = [string]$tier0.selfMonitoring.measurementSource
    Tier0Status = [string]$tier0.selfMonitoring.measurementStatus
    Tier0DurationMs = $tier0.selfMonitoring.durationMs
    ReportCount = [int]$report.collectorCount
    ReportMeasured = [int]$report.measuredCount
    ReportPartial = [int]$report.partialCount
    ReportUnmeasured = [int]$report.unmeasuredCount
    ReportDurationMs = [long]$report.totalDurationMs
    ReportCpuSeconds = $report.totalCpuSeconds
    ReportRows = @($report.rows).Count
    ReportThresholds = [bool]$report.thresholdsEvaluated
    ReportInformational = [bool]$report.informational
    ReportHealthClaim = [string]$report.healthClaim
    ReportNeverHealthy = [bool]$report.neverHealthy
    ReportRowNames = @($report.rows | ForEach-Object { [string]$_.collector })
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_json(body)

    assert payload["CompleteStatus"] == "complete"
    assert payload["CompleteCoverage"] == "complete"
    assert payload["CompleteCollectorStatus"] == "informational"
    assert payload["CompleteDurationMs"] == 2500
    assert float(payload["CompleteCpuSeconds"]) == 1.25
    assert payload["CompleteWorkingSetBytes"] == 104857600
    assert float(payload["CompleteCpuPercent"]) == 50.0
    assert payload["CompleteThresholds"] is False

    assert payload["PartialStatus"] == "partial"
    assert payload["PartialDurationMs"] == 1000
    assert payload["PartialCpuSeconds"] is None
    assert payload["PartialWorkingSetBytes"] is None

    assert payload["UnmeasuredStatus"] == "unavailable"
    assert payload["UnmeasuredDurationMs"] is None
    notes = " ".join(str(note) for note in as_list(payload["UnmeasuredNotes"]))
    assert "unavailable, not as zero overhead" in notes
    assert "owner decision" in notes

    assert payload["ProbeSource"] == "process-probe"
    assert payload["ProbeCpuSeconds"] is not None
    assert float(payload["ProbeCpuSeconds"]) >= 0.0
    assert payload["ProbeWorkingSetBytes"] is not None
    assert int(payload["ProbeWorkingSetBytes"]) > 0
    assert payload["ProbeThresholds"] is False

    assert payload["Tier1Source"] == "collector-stopwatch"
    # The collector measured its own wall time only, so the record is partial:
    # a missing CPU time or working set must never be reported as zero.
    assert payload["Tier1Status"] == "partial", payload["Tier1Status"]
    assert payload["Tier1DurationMs"] is not None
    assert int(payload["Tier1DurationMs"]) >= 0
    assert payload["Tier1CpuSeconds"] is None, "the collector did not measure its own CPU time here"
    assert payload["Tier1WorkingSet"] is None
    assert payload["Tier1SampleCount"] == 2

    assert payload["Tier0Source"] == "not-measured"
    assert payload["Tier0Status"] == "unavailable"
    assert payload["Tier0DurationMs"] is None

    assert payload["ReportCount"] == 3, payload["ReportRowNames"]
    assert payload["ReportMeasured"] == 1
    assert payload["ReportPartial"] == 1
    assert payload["ReportUnmeasured"] == 1
    assert payload["ReportDurationMs"] == 3500
    assert float(payload["ReportCpuSeconds"]) == 1.25
    assert payload["ReportRows"] == 3
    assert payload["ReportThresholds"] is False
    assert payload["ReportInformational"] is True
    assert payload["ReportHealthClaim"] == "none"
    assert payload["ReportNeverHealthy"] is True


# ---------------------------------------------------------------------------
# 7. The overhead document
# ---------------------------------------------------------------------------


def test_the_overhead_document_is_ascii_and_separates_linux_from_windows_work():
    """The deliverable documents what is measurable on a non-Windows host, what
    needs Windows, and that no live overhead was fabricated."""
    text = read_overhead_doc()
    raw = OVERHEAD_DOC.read_bytes()

    assert not raw.startswith(b"\xef\xbb\xbf"), "document must not carry a UTF-8 BOM"
    assert b"\r\n" not in raw, "document must be LF-only"
    assert all(byte < 0x80 for byte in raw), "document must be ASCII"
    assert text.endswith("\n")

    lowered = text.lower()
    assert "measurable on linux" in lowered
    assert "requires windows" in lowered
    assert "no live windows overhead measurement" in lowered
    assert "owner decision" in lowered
    assert "informational" in lowered
    assert "sampling floor" in lowered
    assert "wpr.exe" in lowered
    assert "tasklist" not in lowered and "typeperf" not in lowered


def test_the_overhead_document_budget_lines_match_the_enforced_preset_policy():
    """The budgets printed in the document are read back out of the modules, so
    a changed preset budget fails this test instead of silently falsifying the
    document."""
    body = """
$presets = @(Get-WpdEtwPresetTable | Where-Object { $null -eq $_.aliasOf })
$budgets = @($presets | ForEach-Object { [int]$_.traceBudgetMB })
$durations = @($presets | ForEach-Object { [int]$_.maxDurationSeconds })
$defaultCap = [int](Get-WpdEtwTraceValidation -EtlPath 'case\\cpu.etl').MaxTraceSizeMB
[pscustomobject]@{
    MinBudget = [int]($budgets | Measure-Object -Minimum).Minimum
    MaxBudget = [int]($budgets | Measure-Object -Maximum).Maximum
    MinDuration = [int]($durations | Measure-Object -Minimum).Minimum
    MaxDuration = [int]($durations | Measure-Object -Maximum).Maximum
    DefaultCap = $defaultCap
    PresetCount = $budgets.Count
} | ConvertTo-Json -Compress
"""
    payload = run_json(body)
    text = read_overhead_doc()

    assert payload["PresetCount"] == 13
    assert payload["DefaultCap"] == 512

    expected_lines = [
        f"- Trace budget: {payload['MinBudget']} MB to {payload['MaxBudget']} MB",
        f"- Maximum capture duration: {payload['MinDuration']} s to {payload['MaxDuration']} s",
        f"- Post-stop ETL size cap: {payload['DefaultCap']} MB",
        "- Free-space headroom: max(256 MB, budget / 4)",
        "- Tier 1 sampling floor: 1 s",
    ]
    for line in expected_lines:
        assert line in text, f"document is missing the enforced budget line: {line!r}"
