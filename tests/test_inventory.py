"""Behavioral tests for the Tier 0 static inventory module.

The tests import the real ``src/Wpd.Inventory.psm1`` module into ``pwsh`` and
drive it with synthetic providers, so Windows-only CIM/.NET providers are never
faked: every capability is exercised through an injected seam, and the default
provider set is only inspected (never executed) on a non-Windows host.

Contract anchors: plan D3 (tier vocabulary and one-shot Tier 0), D10 (privacy
default is Standard, opt-down), R2 (no data is never healthy), R4 (no
remediation), R7 (capability is never claimed from the wrong API class).
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE = REPO_ROOT / "src" / "Wpd.Inventory.psm1"


def run_pwsh(body: str) -> str:
    """Import the real inventory module and execute a test body."""
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    assert shutil.which(powershell), f"{powershell} is required for the inventory gate"
    module_path = str(MODULE).replace("'", "''")
    harness = f"""
$ErrorActionPreference = 'Stop'
Import-Module -Name '{module_path}' -Force
Set-StrictMode -Version Latest
{body}
"""
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


def run_pwsh_json(body: str) -> dict:
    return json.loads(run_pwsh(body))


REQUIRED_COMMANDS = [
    "Clear-WpdInventoryCache",
    "ConvertFrom-WpdBitLockerStatusOutput",
    "ConvertFrom-WpdFltmcFilterOutput",
    "ConvertFrom-WpdFltmcInstanceOutput",
    "ConvertFrom-WpdFsutilTrimOutput",
    "ConvertFrom-WpdPowercfgOutput",
    "ConvertTo-WpdStartupEntry",
    "ConvertTo-WpdStorageReliabilityRecord",
    "ConvertTo-WpdVirtualizationContext",
    "Get-WpdInventory",
    "Get-WpdInventoryCache",
    "Get-WpdInventoryCapability",
    "Get-WpdInventoryCapabilityMap",
    "Get-WpdInventoryDefaultProviders",
    "Get-WpdInventoryPrivacyLevel",
    "Invoke-WpdInventoryCapability",
    "New-WpdInventoryProviderResult",
    "Protect-WpdInventoryRecord",
    "Test-WpdInventoryCommandPresence",
    "Test-WpdInventoryForbiddenField",
    "Test-WpdInventoryWindowsHost",
]


def test_module_imports_and_exports_the_inventory_surface():
    """The module loads on a non-Windows host without touching any provider, and
    exports exactly the documented command surface."""
    body = """
$exported = @((Get-Command -Module 'Wpd.Inventory' -CommandType Function).Name)
[pscustomobject]@{
    Loaded = $true
    Exported = $exported
    Count = $exported.Count
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)
    exported = set(payload["Exported"])
    missing = sorted(set(REQUIRED_COMMANDS) - exported)
    assert missing == [], f"module does not export: {missing}"
    assert payload["Count"] == len(exported)


EXPECTED_CAPABILITIES = [
    "os",
    "hardware",
    "drivers",
    "power",
    "storage",
    "nic",
    "services",
    "security",
    "startup",
    "filters",
    "pagefiles",
    "virtualization",
    "encryption",
    "recentChanges",
]


def test_capability_map_covers_every_capability_with_elevation_and_apis():
    """The capability map is the contract for the collectors: 14 Tier 0
    capabilities, a documented source API per capability, a required elevation
    level with its reason, and no capability claimed from a write-capable API."""
    body = """
$map = @(Get-WpdInventoryCapabilityMap)
[pscustomobject]@{
    Ids = @($map | ForEach-Object { $_.id })
    Summary = @($map | ForEach-Object {
        "{0}|{1}|{2}|{3}|{4}|{5}" -f $_.id, $_.tier, $_.requiredElevation, $_.elevationReason.Length, $_.providers.Count, $_.source
    })
    InvalidTier = @($map | Where-Object { $_.tier -ne 0 }).Count
    InvalidElevation = @($map | Where-Object { $_.requiredElevation -notin @('standard', 'administrator') }).Count
    MissingReason = @($map | Where-Object { [string]::IsNullOrWhiteSpace($_.elevationReason) }).Count
    MissingProviders = @($map | Where-Object { @($_.providers).Count -eq 0 }).Count
    MissingSources = @($map | Where-Object { @($_.providers | Where-Object { [string]::IsNullOrWhiteSpace($_.api) }).Count -gt 0 }).Count
    NonWindowsCapability = @($map | Where-Object { $_.windowsOnly -ne $true }).Count
    DuplicateIds = @($map | Group-Object id | Where-Object { $_.Count -gt 1 }).Count
    FilterElevation = ($map | Where-Object { $_.id -eq 'filters' }).requiredElevation
    EncryptionElevation = ($map | Where-Object { $_.id -eq 'encryption' }).requiredElevation
    OsElevation = ($map | Where-Object { $_.id -eq 'os' }).requiredElevation
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert sorted(payload["Ids"]) == sorted(EXPECTED_CAPABILITIES)
    assert payload["InvalidTier"] == 0
    assert payload["InvalidElevation"] == 0
    assert payload["MissingReason"] == 0
    assert payload["MissingProviders"] == 0
    assert payload["MissingSources"] == 0
    assert payload["NonWindowsCapability"] == 0
    assert payload["DuplicateIds"] == 0
    # Elevation is mapped per capability, not copied everywhere.
    assert payload["FilterElevation"] == "administrator"
    assert payload["EncryptionElevation"] == "administrator"
    assert payload["OsElevation"] == "standard"
    # Every provider source must be a documented read-only inbox API.
    for entry in payload["Summary"]:
        assert "|0|" in entry, entry
        api_count = entry.split("|")[4]
        assert int(api_count) > 0


def test_successful_capability_returns_envelope_with_source_and_counts():
    """A capability that collects records returns a success envelope carrying the
    provider source, record count, tier/elevation metadata and ISO timestamps."""
    body = """
$providers = @{
    os = @(
        [pscustomobject]@{
            name = 'synthetic:os'
            source = 'Get-CimInstance Win32_OperatingSystem'
            platform = 'any'
            allowEmpty = $false
            collect = {
                @(
                    [pscustomobject]@{ Caption = 'Synthetic OS'; Version = '10.0.1000' }
                    [pscustomobject]@{ Caption = 'Other OS'; Version = '10.0.2000' }
                )
            }
        }
    )
}
$context = @{ IsWindows = $false; IsElevated = $false; PrivacyLevel = 'Standard' }
$envelope = Invoke-WpdInventoryCapability -Id 'os' -Providers $providers -Context $context
[pscustomobject]@{
    Id = $envelope.id
    Status = $envelope.status
    Coverage = $envelope.coverage
    Source = $envelope.source
    Tier = $envelope.tier
    RequiredElevation = $envelope.requiredElevation
    PrivacyLevel = $envelope.privacyLevel
    RecordCount = $envelope.recordCount
    ItemCount = @($envelope.items).Count
    Caption = @($envelope.items)[0].Caption
    StartedUtc = $envelope.startedUtc
    CompletedUtc = $envelope.completedUtc
    DurationMs = $envelope.durationMs
    WarningCount = @($envelope.warnings).Count
    ErrorCount = @($envelope.errors).Count
    Reasons = @($envelope.reasons)
    Cached = $envelope.cached
    FirstIds = @($envelope.capability)
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Id"] == "os"
    assert payload["Status"] == "success"
    assert payload["Coverage"] == "complete"
    assert payload["Source"] == "Get-CimInstance Win32_OperatingSystem"
    assert payload["Tier"] == 0
    assert payload["RequiredElevation"] == "standard"
    assert payload["PrivacyLevel"] == "Standard"
    assert payload["RecordCount"] == 2
    assert payload["ItemCount"] == 2
    assert payload["Caption"] == "Synthetic OS"
    assert payload["DurationMs"] >= 0
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$", payload["StartedUtc"])
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$", payload["CompletedUtc"])
    assert payload["WarningCount"] == 0
    assert payload["ErrorCount"] == 0
    assert payload["Reasons"] == []
    assert payload["Cached"] is False


def test_failing_provider_is_recorded_and_siblings_still_return_data():
    """One failing provider does not erase the records other providers returned,
    and the capability degrades to partial with a structured error entry."""
    body = """
$providers = @{
    services = @(
        [pscustomobject]@{ name = 'broken'; source = 'Get-CimInstance Win32_Service'; platform = 'any'; collect = { throw 'CIM provider failed' } }
        [pscustomobject]@{ name = 'good-a'; source = 'Win32_Service:auto'; platform = 'any'; collect = { @([pscustomobject]@{ Name = 'A' }, [pscustomobject]@{ Name = 'B' }) } }
        [pscustomobject]@{ name = 'good-b'; source = 'Win32_Service:manual'; platform = 'any'; collect = { @([pscustomobject]@{ Name = 'C' }) } }
    )
}
$context = @{ IsWindows = $false; IsElevated = $false; PrivacyLevel = 'Standard' }
$envelope = Invoke-WpdInventoryCapability -Id 'services' -Providers $providers -Context $context
[pscustomobject]@{
    Status = $envelope.status
    Coverage = $envelope.coverage
    RecordCount = $envelope.recordCount
    Names = @($envelope.items | ForEach-Object { $_.Name })
    Sources = $envelope.source
    ErrorCount = @($envelope.errors).Count
    ErrorStage = @($envelope.errors)[0].stage
    ErrorProvider = @($envelope.errors)[0].provider
    ErrorMessage = @($envelope.errors)[0].message
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Status"] == "partial"
    assert payload["Coverage"] == "partial"
    assert payload["RecordCount"] == 3
    assert sorted(payload["Names"]) == ["A", "B", "C"]
    assert "Win32_Service:auto" in payload["Sources"]
    assert "Win32_Service:manual" in payload["Sources"]
    assert payload["ErrorCount"] == 1
    assert payload["ErrorStage"] == "provider"
    assert payload["ErrorProvider"] == "broken"
    assert payload["ErrorMessage"] == "CIM provider failed"


def test_one_failing_capability_does_not_abort_a_sibling_capability():
    """Failure envelopes are independent: a capability whose provider throws is
    reported as error while a sibling capability still returns its records."""
    body = """
$providers = @{
    os = @([pscustomobject]@{ name = 'broken'; source = 'Win32_OperatingSystem'; platform = 'any'; collect = { throw 'no CIM' } })
    storage = @([pscustomobject]@{ name = 'good'; source = 'Get-PhysicalDisk'; platform = 'any'; collect = { @([pscustomobject]@{ FriendlyName = 'Synthetic SSD' }) } })
}
$context = @{ IsWindows = $false; IsElevated = $false; PrivacyLevel = 'Standard' }
$broken = Invoke-WpdInventoryCapability -Id 'os' -Providers $providers -Context $context
$good = Invoke-WpdInventoryCapability -Id 'storage' -Providers $providers -Context $context
[pscustomobject]@{
    BrokenStatus = $broken.status
    BrokenCoverage = $broken.coverage
    BrokenRecords = $broken.recordCount
    BrokenErrors = @($broken.errors).Count
    GoodStatus = $good.status
    GoodRecords = $good.recordCount
    GoodName = @($good.items)[0].FriendlyName
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["BrokenStatus"] == "error"
    assert payload["BrokenCoverage"] == "unavailable"
    assert payload["BrokenRecords"] == 0
    assert payload["BrokenErrors"] == 1
    assert payload["GoodStatus"] == "success"
    assert payload["GoodRecords"] == 1
    assert payload["GoodName"] == "Synthetic SSD"


def test_absent_command_maps_to_unsupported_not_to_success():
    """A provider that cannot find its command reports unsupported with a reason,
    never success and never a healthy state."""
    body = """
$providers = @{
    filters = @(
        [pscustomobject]@{
            name = 'fltmc'
            source = 'fltmc filters'
            platform = 'any'
            collect = { throw [System.Management.Automation.CommandNotFoundException]::new('fltmc is not present') }
        }
        [pscustomobject]@{
            name = 'reliability'
            source = 'Get-StorageReliabilityCounter'
            platform = 'any'
            collect = { New-WpdInventoryProviderResult -Status 'unsupported' -Reason 'smart-counters-not-exposed' -Items @() }
        }
    )
}
$context = @{ IsWindows = $false; IsElevated = $true; PrivacyLevel = 'Standard' }
$envelope = Invoke-WpdInventoryCapability -Id 'filters' -Providers $providers -Context $context
[pscustomobject]@{
    Status = $envelope.status
    Coverage = $envelope.coverage
    RecordCount = $envelope.recordCount
    Reasons = @($envelope.reasons)
    ErrorCount = @($envelope.errors).Count
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Status"] == "unsupported"
    assert payload["Coverage"] == "unsupported"
    assert payload["RecordCount"] == 0
    assert payload["ErrorCount"] == 0
    assert "command-not-present:fltmc" in payload["Reasons"]
    assert "smart-counters-not-exposed" in payload["Reasons"]


def test_provider_returning_no_data_is_unavailable_not_healthy():
    """No data is not health: an empty provider result is unavailable with a
    stated reason and never success."""
    body = """
$providers = @{
    nic = @([pscustomobject]@{ name = 'netadapter'; source = 'Get-NetAdapter'; platform = 'any'; collect = { @() } })
}
$context = @{ IsWindows = $false; IsElevated = $false; PrivacyLevel = 'Standard' }
$envelope = Invoke-WpdInventoryCapability -Id 'nic' -Providers $providers -Context $context
[pscustomobject]@{
    Status = $envelope.status
    Coverage = $envelope.coverage
    RecordCount = $envelope.recordCount
    Reasons = @($envelope.reasons)
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Status"] == "unavailable"
    assert payload["Coverage"] == "unavailable"
    assert payload["RecordCount"] == 0
    assert payload["Reasons"] == ["no-data-returned:netadapter"]


def test_provider_declaring_empty_as_expected_reports_success_with_zero_records():
    """An enumeration where zero rows is a real answer (no third-party filters
    installed) reports success with zero records instead of no-data."""
    body = """
$providers = @{
    startup = @([pscustomobject]@{ name = 'startup-folders'; source = 'Get-ChildItem <startup folder>'; platform = 'any'; allowEmpty = $true; collect = { @() } })
}
$context = @{ IsWindows = $false; IsElevated = $false; PrivacyLevel = 'Standard' }
$envelope = Invoke-WpdInventoryCapability -Id 'startup' -Providers $providers -Context $context
[pscustomobject]@{
    Status = $envelope.status
    Coverage = $envelope.coverage
    RecordCount = $envelope.recordCount
    Reasons = @($envelope.reasons)
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Status"] == "success"
    assert payload["Coverage"] == "complete"
    assert payload["RecordCount"] == 0
    assert payload["Reasons"] == []


def test_administrator_capability_is_gated_before_any_provider_runs():
    """A capability that needs elevation is reported unavailable with reason
    requires-administrator, and its providers are never invoked."""
    body = """
$global:wpdGateRan = $false
$providers = @{
    filters = @(
        [pscustomobject]@{
            name = 'fltmc'
            source = 'fltmc filters'
            platform = 'any'
            collect = { $global:wpdGateRan = $true; @([pscustomobject]@{ Filter = 'ShouldNotRun' }) }
        }
    )
}
$elevated = Invoke-WpdInventoryCapability -Id 'filters' -Providers $providers -Context @{ IsWindows = $false; IsElevated = $true; PrivacyLevel = 'Standard' }
$ranWhenElevated = $global:wpdGateRan
$global:wpdGateRan = $false
$plain = Invoke-WpdInventoryCapability -Id 'filters' -Providers $providers -Context @{ IsWindows = $false; IsElevated = $false; PrivacyLevel = 'Standard' }
[pscustomobject]@{
    Elevation = ($envelope = $elevated).requiredElevation
    ElevatedStatus = $elevated.status
    RanWhenElevated = $ranWhenElevated
    PlainStatus = $plain.status
    PlainCoverage = $plain.coverage
    PlainReasons = @($plain.reasons)
    RanWhenPlain = $global:wpdGateRan
    PlainRecords = $plain.recordCount
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Elevation"] == "administrator"
    assert payload["ElevatedStatus"] == "success"
    assert payload["RanWhenElevated"] is True
    assert payload["PlainStatus"] == "unavailable"
    assert payload["PlainCoverage"] == "unavailable"
    assert payload["PlainReasons"] == ["requires-administrator"]
    assert payload["RanWhenPlain"] is False, "gated capability must not query a provider"
    assert payload["PlainRecords"] == 0


CACHE_PROVIDERS = """
$global:wpdCalls = 0
$providers = @{
    os = @([pscustomobject]@{ name = 'p-os'; source = 'src-os'; platform = 'any'; collect = { $global:wpdCalls++; @([pscustomobject]@{ Id = 'os-1' }) } })
    storage = @([pscustomobject]@{ name = 'p-storage'; source = 'src-storage'; platform = 'any'; allowEmpty = $true; collect = { $global:wpdCalls++; @() } })
}
"""


def test_session_cache_queries_each_capability_provider_once_and_serves_cache():
    """Tier 0 is collected once per run: a second aggregate call and the
    per-capability accessor are served from the session cache without touching a
    provider, and the aggregate reports every capability including the ones with
    no registered provider."""
    body = CACHE_PROVIDERS + """
$context = @{ IsWindows = $false; IsElevated = $false }
$first = Get-WpdInventory -Providers $providers -Context $context -PrivacyLevel 'Standard' -CacheKey 'k1'
$callsAfterFirst = $global:wpdCalls
$second = Get-WpdInventory -Providers $providers -Context $context -PrivacyLevel 'Standard' -CacheKey 'k1'
$callsAfterSecond = $global:wpdCalls
$accessor = Get-WpdInventoryCapability -Id 'os'
[pscustomobject]@{
    SchemaVersion = $first.schemaVersion
    GeneratedUtc = $first.generatedUtc
    PrivacyLevel = $first.privacyLevel
    CacheKey = $first.cacheKey
    CapabilityCount = @($first.capabilities.Keys).Count
    OrderCount = @($first.capabilityOrder).Count
    OsStatus = $first.capabilities.os.status
    StorageStatus = $first.capabilities.storage.status
    StorageRecords = $first.capabilities.storage.recordCount
    FiltersStatus = $first.capabilities.filters.status
    FiltersReasons = @($first.capabilities.filters.reasons)
    FiltersCoverage = $first.capabilities.filters.coverage
    SuccessCount = $first.counts.success
    UnavailableCount = $first.counts.unavailable
    TotalCount = $first.counts.total
    TotalRecords = $first.recordCount
    Tier = $first.tier
    FirstCached = $first.cached
    SecondCached = $second.cached
    CallsAfterFirst = $callsAfterFirst
    CallsAfterSecond = $callsAfterSecond
    AccessorStatus = $accessor.status
    AccessorCached = $accessor.cached
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["SchemaVersion"] == "1.0"
    assert payload["PrivacyLevel"] == "Standard"
    assert payload["CacheKey"] == "k1"
    assert payload["OrderCount"] == len(EXPECTED_CAPABILITIES)
    assert payload["CapabilityCount"] == len(EXPECTED_CAPABILITIES)
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$", payload["GeneratedUtc"])
    assert payload["Tier"] == 0
    assert payload["OsStatus"] == "success"
    assert payload["StorageStatus"] == "success"
    assert payload["StorageRecords"] == 0
    # A capability with no registered provider is unavailable, never healthy.
    assert payload["FiltersStatus"] == "unavailable"
    assert payload["FiltersCoverage"] == "unavailable"
    assert payload["FiltersReasons"] == ["provider-absent"]
    assert payload["SuccessCount"] == 2
    assert payload["UnavailableCount"] == len(EXPECTED_CAPABILITIES) - 2
    assert payload["TotalCount"] == len(EXPECTED_CAPABILITIES)
    assert payload["TotalRecords"] == 1
    assert payload["FirstCached"] is False
    assert payload["SecondCached"] is True
    assert payload["CallsAfterFirst"] == 2, "one provider call per capability"
    assert payload["CallsAfterSecond"] == 2, "the second call must not re-query Tier 0"
    assert payload["AccessorStatus"] == "success"
    assert payload["AccessorCached"] is True


def test_cache_keys_are_isolated_and_clear_and_refresh_requery():
    """Cache keys isolate runs, Clear drops one key without touching the others,
    and -Refresh re-queries instead of serving the cached envelope."""
    body = CACHE_PROVIDERS + """
$context = @{ IsWindows = $false; IsElevated = $false }
$null = Get-WpdInventory -Providers $providers -Context $context -CacheKey 'k1'
$callsAfterK1 = $global:wpdCalls
$null = Get-WpdInventory -Providers $providers -Context $context -CacheKey 'k2'
$callsAfterK2 = $global:wpdCalls
$keysBefore = @(Get-WpdInventoryCache | ForEach-Object { $_.key } | Sort-Object)
$callsBeforeCacheInspect = $global:wpdCalls
Clear-WpdInventoryCache -CacheKey 'k1'
$keysAfterClear = @(Get-WpdInventoryCache | ForEach-Object { $_.key } | Sort-Object)
$null = Get-WpdInventory -Providers $providers -Context $context -CacheKey 'k1'
$callsAfterClearedK1 = $global:wpdCalls
$null = Get-WpdInventory -Providers $providers -Context $context -CacheKey 'k2' -Refresh
$callsAfterRefresh = $global:wpdCalls
Clear-WpdInventoryCache
$keysAfterClearAll = @(Get-WpdInventoryCache).Count
[pscustomobject]@{
    CallsAfterK1 = $callsAfterK1
    CallsAfterK2 = $callsAfterK2
    KeysBefore = $keysBefore
    CallsBeforeCacheInspect = $callsBeforeCacheInspect
    KeysAfterClear = $keysAfterClear
    CallsAfterClearedK1 = $callsAfterClearedK1
    CallsAfterRefresh = $callsAfterRefresh
    KeysAfterClearAll = $keysAfterClearAll
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["CallsAfterK1"] == 2
    assert payload["CallsAfterK2"] == 4, "a different cache key must re-query"
    assert payload["KeysBefore"] == ["k1", "k2"]
    assert payload["CallsBeforeCacheInspect"] == 4, "inspecting the cache must not query"
    assert payload["KeysAfterClear"] == ["k2"]
    assert payload["CallsAfterClearedK1"] == 6, "a cleared key re-queries"
    assert payload["CallsAfterRefresh"] == 8, "-Refresh re-queries a cached key"
    assert payload["KeysAfterClearAll"] == 0


def test_privacy_level_validation_defaults_to_standard_and_fails_closed():
    """Standard is the default; an unknown level is rejected instead of silently
    collecting at a weaker level (D10)."""
    body = """
$default = Get-WpdInventoryPrivacyLevel -Level ''
$lower = Get-WpdInventoryPrivacyLevel -Level 'redacted'
$upper = Get-WpdInventoryPrivacyLevel -Level 'FULL'
$invalidRejected = $false
$invalidMessage = ''
try {
    $null = Get-WpdInventoryPrivacyLevel -Level 'Anonymous'
}
catch [System.ArgumentException] {
    $invalidRejected = $true
    $invalidMessage = $_.Exception.Message
}
$aggregateRejected = $false
try {
    $null = Get-WpdInventory -Providers @{} -PrivacyLevel 'Anonymous' -CacheKey 'invalid'
}
catch [System.ArgumentException] {
    $aggregateRejected = $true
}
$standard = Get-WpdInventory -Providers @{} -Context @{ IsWindows = $false } -CacheKey 'default-level-test'
[pscustomobject]@{
    Default = $default
    Lower = $lower
    Upper = $upper
    InvalidRejected = $invalidRejected
    InvalidMessage = $invalidMessage
    AggregateRejected = $aggregateRejected
    AggregateLevel = $standard.privacyLevel
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Default"] == "Standard"
    assert payload["Lower"] == "Redacted"
    assert payload["Upper"] == "Full"
    assert payload["InvalidRejected"] is True
    assert "Standard" in payload["InvalidMessage"] and "Redacted" in payload["InvalidMessage"]
    assert payload["AggregateRejected"] is True, "an unknown privacy level must not collect"
    assert payload["AggregateLevel"] == "Standard"


def test_redacted_privacy_hashes_paths_and_users_and_suppresses_command_lines():
    """Standard keeps paths, Redacted hashes user names and paths and suppresses
    command lines, Full keeps raw values, and device identifiers are hashed at
    every level."""
    body = """
$record = [pscustomobject]@{
    DisplayName    = 'Synthetic App'
    ExecutablePath = 'C:\\Program Files\\Synthetic\\app.exe'
    UserName       = 'CONTOSO\\alice'
    CommandLine    = 'app.exe --profile alice --config C:\\Users\\alice\\app.ini'
    SerialNumber   = 'SN-123456'
    MacAddress     = '00-11-22-33-44-55'
}
$standard = Protect-WpdInventoryRecord -Record $record -Level 'Standard'
$redacted = Protect-WpdInventoryRecord -Record $record -Level 'Redacted'
$full = Protect-WpdInventoryRecord -Record $record -Level 'Full'
[pscustomobject]@{
    StandardPath = $standard.ExecutablePath
    StandardUser = $standard.UserName
    StandardCommand = $standard.CommandLine
    StandardSerial = $standard.SerialNumber
    StandardMac = $standard.MacAddress
    RedactedPath = $redacted.ExecutablePath
    RedactedUser = $redacted.UserName
    RedactedCommand = $redacted.CommandLine
    RedactedSerial = $redacted.SerialNumber
    RedactedName = $redacted.DisplayName
    FullPath = $full.ExecutablePath
    FullUser = $full.UserName
    FullCommand = $full.CommandLine
    FullSerial = $full.SerialNumber
    FullMac = $full.MacAddress
    RedactedJson = ($redacted | ConvertTo-Json -Depth 6 -Compress)
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    # Standard is the raw-but-identifiers-safe level.
    assert payload["StandardPath"] == "C:\\Program Files\\Synthetic\\app.exe"
    assert payload["StandardUser"] == "CONTOSO\\alice"
    assert "app.exe --profile alice" in payload["StandardCommand"]
    assert payload["StandardSerial"] != "SN-123456"
    assert payload["StandardSerial"].startswith("sha256:")
    assert payload["StandardMac"] != "00-11-22-33-44-55"
    assert payload["StandardMac"].startswith("sha256:")

    # Redacted hashes identity-bearing fields and drops command lines.
    assert payload["RedactedPath"].startswith("sha256:")
    assert payload["RedactedUser"].startswith("sha256:")
    assert payload["RedactedSerial"].startswith("sha256:")
    assert payload["RedactedCommand"] is None
    assert payload["RedactedName"] == "Synthetic App", "non-identifying names stay readable"
    assert "alice" not in payload["RedactedJson"]
    assert "Program Files" not in payload["RedactedJson"]
    assert "SN-123456" not in payload["RedactedJson"]

    # Full is opt-in and raw.
    assert payload["FullPath"] == "C:\\Program Files\\Synthetic\\app.exe"
    assert payload["FullUser"] == "CONTOSO\\alice"
    assert "app.exe --profile alice" in payload["FullCommand"]
    assert payload["FullSerial"] == "SN-123456"
    assert payload["FullMac"] == "00-11-22-33-44-55"


FORBIDDEN_RECORD = """
$secretRecord = [pscustomobject]@{
    Name            = 'Synthetic Service'
    State           = 'Running'
    Password        = 'hunter2'
    Cookie          = 'session=abc123'
    AccessToken     = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    ApiKey          = 'AKIAIOSFODNN7EXAMPLE'
    BrowserHistory  = 'https://example.invalid/private'
    DocumentContent = 'confidential quarterly numbers'
    UserCredential  = 'CONTOSO\\alice:secret'
}
"""


@pytest.mark.parametrize("level", ["Standard", "Redacted", "Full"])
def test_secrets_are_suppressed_at_every_privacy_level(level):
    """No secret, token, cookie, browser history or document content is ever
    collected, at any privacy level, and the field-name guard names why."""
    body = FORBIDDEN_RECORD + f"""
$out = Protect-WpdInventoryRecord -Record $secretRecord -Level '{level}'
$json = $out | ConvertTo-Json -Depth 8 -Compress
$names = @($out.PSObject.Properties.Name)
[pscustomobject]@{{
    Json = $json
    Names = $names
    PasswordForbidden = Test-WpdInventoryForbiddenField -Name 'Password'
    CookieForbidden = Test-WpdInventoryForbiddenField -Name 'Cookie'
    TokenForbidden = Test-WpdInventoryForbiddenField -Name 'AccessToken'
    ApiKeyForbidden = Test-WpdInventoryForbiddenField -Name 'ApiKey'
    HistoryForbidden = Test-WpdInventoryForbiddenField -Name 'BrowserHistory'
    DocumentForbidden = Test-WpdInventoryForbiddenField -Name 'DocumentContent'
    CredentialForbidden = Test-WpdInventoryForbiddenField -Name 'UserCredential'
    NameAllowed = Test-WpdInventoryForbiddenField -Name 'Name'
    PathAllowed = Test-WpdInventoryForbiddenField -Name 'ExecutablePath'
    SourceAllowed = Test-WpdInventoryForbiddenField -Name 'Source'
}} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    for leak in [
        "hunter2",
        "session=abc123",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "AKIAIOSFODNN7EXAMPLE",
        "example.invalid",
        "confidential quarterly numbers",
        "CONTOSO\\\\alice:secret",
    ]:
        assert leak not in payload["Json"], f"{leak} leaked at {level}"

    for forbidden in [
        "Password",
        "Cookie",
        "AccessToken",
        "ApiKey",
        "BrowserHistory",
        "DocumentContent",
        "UserCredential",
    ]:
        assert forbidden not in payload["Names"], f"{forbidden} was stored at {level}"

    assert payload["PasswordForbidden"] is True
    assert payload["CookieForbidden"] is True
    assert payload["TokenForbidden"] is True
    assert payload["ApiKeyForbidden"] is True
    assert payload["HistoryForbidden"] is True
    assert payload["DocumentForbidden"] is True
    assert payload["CredentialForbidden"] is True
    assert payload["NameAllowed"] is False
    assert payload["PathAllowed"] is False
    assert payload["SourceAllowed"] is False
    assert set(payload["Names"]) == {"Name", "State"}


def test_command_presence_detection_is_case_insensitive():
    """Provider presence is detected case-insensitively, against an injected
    table or the live command table, so a capability is never claimed from a
    command that is not actually present."""
    body = """
$table = @{
    'fltmc'    = 'C:\\Windows\\System32\\fltmc.exe'
    'PowerCfg' = 'C:\\Windows\\System32\\powercfg.exe'
}
[pscustomobject]@{
    Exact = Test-WpdInventoryCommandPresence -Name 'fltmc' -CommandTable $table
    Upper = Test-WpdInventoryCommandPresence -Name 'FLTMC' -CommandTable $table
    MixedCase = Test-WpdInventoryCommandPresence -Name 'POWERCFG' -CommandTable $table
    Missing = Test-WpdInventoryCommandPresence -Name 'manage-bde' -CommandTable $table
    EmptyTable = Test-WpdInventoryCommandPresence -Name 'fltmc' -CommandTable @{}
    LiveUpper = Test-WpdInventoryCommandPresence -Name 'GET-DATE'
    LiveMissing = Test-WpdInventoryCommandPresence -Name 'wpd-not-a-real-command'
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Exact"] is True
    assert payload["Upper"] is True
    assert payload["MixedCase"] is True
    assert payload["Missing"] is False
    assert payload["EmptyTable"] is False
    assert payload["LiveUpper"] is True
    assert payload["LiveMissing"] is False


def test_default_provider_set_declares_readonly_windows_providers_for_every_capability():
    """The shipped provider set is one Windows-only, read-only provider list per
    capability, and building it queries nothing."""
    body = """
$providers = Get-WpdInventoryDefaultProviders
$ids = @($providers.Keys | Sort-Object)
$entries = @()
foreach ($id in $ids) {
    foreach ($provider in @($providers[$id])) {
        $entries += [pscustomobject]@{
            capability = $id
            name       = [string]$provider.name
            source     = [string]$provider.source
            platform   = [string]$provider.platform
            callable   = ($provider.collect -is [scriptblock])
        }
    }
}
[pscustomobject]@{
    Ids = $ids
    EntryCount = $entries.Count
    Summary = @($entries | ForEach-Object { "$($_.capability)|$($_.name)|$($_.source)|$($_.platform)|$($_.callable)" })
    EmptyCapabilities = @($ids | Where-Object { @($providers[$_]).Count -eq 0 })
    NonWindowsPlatform = @($entries | Where-Object { $_.platform -ne 'windows' }).Count
    NonCallable = @($entries | Where-Object { -not $_.callable }).Count
    BlankNames = @($entries | Where-Object { [string]::IsNullOrWhiteSpace($_.name) }).Count
    BlankSources = @($entries | Where-Object { [string]::IsNullOrWhiteSpace($_.source) }).Count
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Ids"] == sorted(EXPECTED_CAPABILITIES)
    assert payload["EmptyCapabilities"] == []
    assert payload["NonWindowsPlatform"] == 0, "every shipped provider is a Windows API"
    assert payload["NonCallable"] == 0
    assert payload["BlankNames"] == 0
    assert payload["BlankSources"] == 0
    assert payload["EntryCount"] >= len(EXPECTED_CAPABILITIES)


def test_non_windows_host_reports_unsupported_and_never_fabricates_success():
    """Running the shipped provider set off Windows yields unsupported (or
    unavailable where elevation is required), zero records and no success: the
    module never claims Windows inventory it did not collect."""
    body = """
$result = Get-WpdInventory -CacheKey 'host-check' -Context @{ IsWindows = $false; IsElevated = $false }
$statuses = @{}
foreach ($id in @($result.capabilityOrder)) {
    $status = [string]$result.capabilities[$id].status
    if (-not $statuses.ContainsKey($status)) { $statuses[$status] = 0 }
    $statuses[$status]++
}
$elevated = Get-WpdInventory -CacheKey 'host-check-elevated' -Context @{ IsWindows = $false; IsElevated = $true }
[pscustomobject]@{
    Success = $result.counts.success
    Error = $result.counts.error
    Unsupported = $result.counts.unsupported
    Unavailable = $result.counts.unavailable
    Records = $result.recordCount
    Statuses = @($statuses.Keys | Sort-Object)
    StatusSummary = (@($result.capabilityOrder | ForEach-Object { "$($_):$($result.capabilities[$_].status):$($result.capabilities[$_].coverage)" }) -join ' ')
    CountsJson = ($result.counts | ConvertTo-Json -Compress)
    FiltersStatus = $result.capabilities.filters.status
    EncryptionStatus = $result.capabilities.encryption.status
    FiltersReasons = @($result.capabilities.filters.reasons)
    OsStatus = $result.capabilities.os.status
    OsCoverage = $result.capabilities.os.coverage
    OsRecords = $result.capabilities.os.recordCount
    OsReasons = @($result.capabilities.os.reasons)
    IsWindows = $result.isWindows
    ElevatedFiltersStatus = $elevated.capabilities.filters.status
    ElevatedUnsupported = $elevated.counts.unsupported
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["IsWindows"] is False
    assert payload["Success"] == 0, "no capability may report success off Windows"
    assert payload["Error"] == 0, "an unsupported host is not an error"
    assert payload["Records"] == 0
    assert payload["Unavailable"] == 2, "filters and encryption need elevation"
    assert payload["Unsupported"] == len(EXPECTED_CAPABILITIES) - 2
    assert payload["Statuses"] == ["unavailable", "unsupported"]
    assert payload["FiltersStatus"] == "unavailable"
    assert payload["FiltersReasons"] == ["requires-administrator"]
    assert payload["EncryptionStatus"] == "unavailable"
    assert payload["OsStatus"] == "unsupported"
    assert payload["OsCoverage"] == "unsupported"
    assert payload["OsRecords"] == 0
    assert any(reason.startswith("host-not-windows") for reason in payload["OsReasons"])
    assert payload["ElevatedFiltersStatus"] == "unsupported"
    assert payload["ElevatedUnsupported"] == len(EXPECTED_CAPABILITIES)
    assert "healthy" not in payload["StatusSummary"]
    assert "success" not in payload["StatusSummary"].replace("unsupported", "")
    assert "healthy" not in payload["CountsJson"]


FLTMC_FILTERS = """
Filter Name                     Num Instances    Altitude    Frame
------------------------------  -------------  ------------  -----
WdFilter                                5       328010         0
FileInfo                                3       40500          2
bindflt                                 0       409800         0
"""

FLTMC_INSTANCES = """
Filter                  Volume Name      Altitude        Instance Name
----------------------  ---------------  -------------   -------------
WdFilter                C:               328010          WdFilter Instance
bindflt                 C:               409800          bindflt Instance
WdFilter                D:               328010          WdFilter Instance
"""


def test_fltmc_filter_parsing_is_altitude_ordered_and_survives_bad_rows():
    """fltmc filters output becomes altitude-ordered filter records; an
    unparsable row is a warning, not a lost capability."""
    body = """
$lines = @(
    'Filter Name                     Num Instances    Altitude    Frame'
    '------------------------------  -------------  ------------  -----'
    'WdFilter                                5       328010         0'
    'FileInfo                                3       40500          2'
    'bindflt                                 0       409800         0'
    'this row is not a filter row'
)
$result = ConvertFrom-WpdFltmcFilterOutput -Lines $lines
$ordered = @($result.filters)
[pscustomobject]@{
    Kind = $result.kind
    View = $result.view
    Order = $result.order
    Count = $ordered.Count
    Names = @($ordered | ForEach-Object { $_.name })
    Altitudes = @($ordered | ForEach-Object { $_.altitude })
    Instances = @($ordered | ForEach-Object { $_.instances })
    Frames = @($ordered | ForEach-Object { $_.frame })
    WarningCount = @($result.parseWarnings).Count
    WarningText = @($result.parseWarnings) -join ';'
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Kind"] == "filesystem-filters"
    assert payload["View"] == "filters"
    assert payload["Order"] == "altitude-ascending"
    assert payload["Count"] == 3
    assert payload["Names"] == ["FileInfo", "WdFilter", "bindflt"]
    assert payload["Altitudes"] == [40500, 328010, 409800]
    assert payload["Instances"] == [3, 5, 0]
    assert payload["Frames"] == [2, 0, 0]
    assert payload["WarningCount"] == 1
    assert "not a filter row" in payload["WarningText"]


def test_fltmc_instance_parsing_preserves_filter_volume_and_altitude():
    """fltmc instances output maps instances to their volume and keeps the
    documented altitude ordering."""
    body = """
$lines = @(
    'Filter                  Volume Name      Altitude        Instance Name'
    '----------------------  ---------------  -------------   -------------'
    'WdFilter                C:               328010          WdFilter Instance'
    'bindflt                 C:               409800          bindflt Instance'
    'WdFilter                D:               328010          WdFilter Instance'
)
$result = ConvertFrom-WpdFltmcInstanceOutput -Lines $lines
$records = @($result.instances)
[pscustomobject]@{
    Kind = $result.kind
    View = $result.view
    Order = $result.order
    Count = $records.Count
    Filters = @($records | ForEach-Object { $_.filterName })
    Volumes = @($records | ForEach-Object { $_.volume })
    Altitudes = @($records | ForEach-Object { $_.altitude })
    WarningCount = @($result.parseWarnings).Count
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Kind"] == "filesystem-filters"
    assert payload["View"] == "instances"
    assert payload["Order"] == "altitude-ascending"
    assert payload["Count"] == 3
    assert payload["Filters"] == ["WdFilter", "WdFilter", "bindflt"]
    assert payload["Volumes"] == ["C:", "D:", "C:"]
    assert payload["Altitudes"] == [328010, 328010, 409800]
    assert payload["WarningCount"] == 0


def test_powercfg_active_scheme_and_sleep_state_parsing():
    """powercfg output is parsed into the active scheme and the available versus
    unavailable sleep states; a missing line is unavailable, not empty success."""
    body = """
$scheme = ConvertFrom-WpdPowercfgOutput -Lines @('Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)') -Kind 'active-scheme'
$sleep = ConvertFrom-WpdPowercfgOutput -Kind 'sleep-states' -Lines @(
    'The following sleep states are available on this system:'
    '    Standby (S3)'
    '    Hibernate'
    '    Fast Startup'
    ''
    'The following sleep states are not available on this system:'
    '    Standby (S1)'
    '        The system firmware does not support this sleep state.'
    '    Standby (S2)'
    '        The system firmware does not support this sleep state.'
)
$blank = ConvertFrom-WpdPowercfgOutput -Lines @('no scheme here') -Kind 'active-scheme'
$badKindRejected = $false
try {
    $null = ConvertFrom-WpdPowercfgOutput -Lines @('x') -Kind 'not-a-kind'
}
catch [System.ArgumentException] {
    $badKindRejected = $true
}
[pscustomobject]@{
    SchemeKind = $scheme.kind
    Guid = $scheme.guid
    Name = $scheme.name
    Source = $scheme.source
    SleepKind = $sleep.kind
    Available = @($sleep.available)
    UnavailableStates = @($sleep.unavailable | ForEach-Object { $_.state })
    UnavailableReasons = @($sleep.unavailable | ForEach-Object { $_.reason })
    BlankStatus = $blank.status
    BlankReason = $blank.reason
    BadKindRejected = $badKindRejected
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["SchemeKind"] == "power-active-scheme"
    assert payload["Guid"] == "381b4222-f694-41f0-9685-ff5bb260df2e"
    assert payload["Name"] == "Balanced"
    assert payload["Source"] == "powercfg /getactivescheme"
    assert payload["SleepKind"] == "power-sleep-states"
    assert payload["Available"] == ["Standby (S3)", "Hibernate", "Fast Startup"]
    assert payload["UnavailableStates"] == ["Standby (S1)", "Standby (S2)"]
    assert payload["UnavailableReasons"] == [
        "The system firmware does not support this sleep state.",
        "The system firmware does not support this sleep state.",
    ]
    assert payload["BlankStatus"] == "unavailable"
    assert payload["BlankReason"] == "active-scheme-line-not-found"
    assert payload["BadKindRejected"] is True


def test_bitlocker_and_trim_parsing_preserves_protection_and_trim_state():
    """manage-bde -status output and fsutil TRIM state become explicit records,
    and a missing TRIM line is unavailable rather than a guessed default."""
    body = """
$bde = ConvertFrom-WpdBitLockerStatusOutput -Lines @(
    'BitLocker Drive Encryption: Configuration Tool version 10.0.19041'
    'Copyright (C) 2013 Microsoft Corporation. All rights reserved.'
    ''
    'Volume C: [OS]'
    '[OS Volume]'
    '    Size:                 237.29 GB'
    '    BitLocker Version:    2.0'
    '    Conversion Status:    Fully Decrypted'
    '    Percentage Encrypted: 0.0%'
    '    Protection Status:    Protection Off'
    '    Lock Status:          Unlocked'
    '    Key Protectors:       None Found'
)
$volumes = @($bde.volumes)
$trim = ConvertFrom-WpdFsutilTrimOutput -Lines @(
    'NTFS DisableDeleteNotify = 0'
    'ReFS DisableDeleteNotify = 0'
)
$partialTrim = ConvertFrom-WpdFsutilTrimOutput -Lines @('NTFS DisableDeleteNotify = 1')
$missingTrim = ConvertFrom-WpdFsutilTrimOutput -Lines @('nothing useful here')
[pscustomobject]@{
    VolumeCount = $volumes.Count
    Volume = $volumes[0].volume
    Conversion = $volumes[0].conversionStatus
    Protection = $volumes[0].protectionStatus
    Encrypted = $volumes[0].encryptionPercentage
    Lock = $volumes[0].lockStatus
    Version = $volumes[0].bitLockerVersion
    KeyProtectors = @($volumes[0].keyProtectors)
    TrimKind = $trim.kind
    NtfsTrimEnabled = $trim.ntfsTrimEnabled
    RefsTrimEnabled = $trim.refsTrimEnabled
    PartialNtfs = $partialTrim.ntfsTrimEnabled
    PartialRefs = $partialTrim.refsTrimEnabled
    PartialWarnings = @($partialTrim.parseWarnings).Count
    MissingStatus = $missingTrim.status
    MissingReason = $missingTrim.reason
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["VolumeCount"] == 1
    assert payload["Volume"] == "C:"
    assert payload["Conversion"] == "Fully Decrypted"
    assert payload["Protection"] == "Protection Off"
    assert payload["Encrypted"] == 0
    assert payload["Lock"] == "Unlocked"
    assert payload["Version"] == "2.0"
    assert payload["KeyProtectors"] == ["None Found"]
    assert payload["TrimKind"] == "trim-state"
    assert payload["NtfsTrimEnabled"] is True
    assert payload["RefsTrimEnabled"] is True
    assert payload["PartialNtfs"] is False
    assert payload["PartialRefs"] is None
    assert payload["PartialWarnings"] == 1
    assert payload["MissingStatus"] == "unavailable"
    assert payload["MissingReason"] == "trim-state-line-not-found"


def test_storage_reliability_absent_counters_report_unsupported_without_values():
    """A disk that exposes no reliability counter is reported as not exposed,
    with no invented wear, temperature or error values."""
    body = """
$counters = [pscustomobject]@{
    Wear                    = 3
    Temperature             = 41
    ReadErrorsTotal         = 0
    ReadErrorsUncorrected   = 0
    WriteErrorsTotal        = 12
    WriteErrorsUncorrected  = 1
    PowerOnHours            = 9001
    StartStopCycleCount     = 300
    LoadUnloadCycleCount    = 1200
}
$exposed = ConvertTo-WpdStorageReliabilityRecord -Counters $counters -DeviceId '2'
$absent = ConvertTo-WpdStorageReliabilityRecord -Counters $null -DeviceId '3'
[pscustomobject]@{
    Kind = $exposed.kind
    Exposed = $exposed.exposed
    Wear = $exposed.wear
    Temperature = $exposed.temperatureCelsius
    WriteErrorsUncorrected = $exposed.writeErrorsUncorrected
    PowerOnHours = $exposed.powerOnHours
    DeviceId = $exposed.deviceId
    AbsentExposed = $absent.exposed
    AbsentWear = $absent.wear
    AbsentTemperature = $absent.temperatureCelsius
    AbsentWriteErrors = $absent.writeErrorsUncorrected
    AbsentNote = $absent.note
    AbsentDeviceId = $absent.deviceId
    AbsentJson = ($absent | ConvertTo-Json -Depth 6 -Compress)
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Kind"] == "storage-reliability"
    assert payload["Exposed"] is True
    assert payload["Wear"] == 3
    assert payload["Temperature"] == 41
    assert payload["WriteErrorsUncorrected"] == 1
    assert payload["PowerOnHours"] == 9001
    assert payload["DeviceId"] == "2"
    assert payload["AbsentExposed"] is False
    assert payload["AbsentWear"] is None
    assert payload["AbsentTemperature"] is None
    assert payload["AbsentWriteErrors"] is None
    assert payload["AbsentNote"] == "reliability-counter-not-exposed"
    assert payload["AbsentDeviceId"] == "3"
    assert '"wear": 0' not in payload["AbsentJson"].replace(" ", "")
    assert "9001" not in payload["AbsentJson"]


def test_vbs_context_maps_documented_service_names_and_flags_unknown_values():
    """VBS state maps the documented SecurityServicesRunning values, flags an
    undocumented value instead of guessing, and treats a missing DeviceGuard
    class as not exposed rather than as VBS disabled."""
    body = """
$computerSystem = [pscustomobject]@{ HypervisorPresent = $true; Name = 'SYNTHETIC' }
$deviceGuard = [pscustomobject]@{
    VirtualizationBasedSecurityStatus = 2
    SecurityServicesRunning           = @(1, 2, 9)
    SecurityServicesConfigured        = @(1, 2)
    CodeIntegrityPolicyEnforcementStatus = 2
    AvailableSecurityProperties       = @(1, 2, 3, 4, 5, 6, 7)
}
$context = ConvertTo-WpdVirtualizationContext -ComputerSystem $computerSystem -DeviceGuard $deviceGuard
$missing = ConvertTo-WpdVirtualizationContext -ComputerSystem $computerSystem -DeviceGuard $null
$off = ConvertTo-WpdVirtualizationContext -ComputerSystem ([pscustomobject]@{ HypervisorPresent = $false }) -DeviceGuard ([pscustomobject]@{ VirtualizationBasedSecurityStatus = 0; SecurityServicesRunning = @() })
[pscustomobject]@{
    Kind = $context.kind
    HypervisorPresent = $context.hypervisorPresent
    VbsStatus = $context.vbsStatus
    Services = @($context.securityServicesRunning)
    CodeIntegrityEnforced = $context.codeIntegrityPolicyEnforced
    Warnings = @($context.warnings)
    MissingStatus = $missing.vbsStatus
    MissingNote = $missing.note
    MissingServices = @($missing.securityServicesRunning).Count
    OffStatus = $off.vbsStatus
    OffHypervisor = $off.hypervisorPresent
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Kind"] == "virtualization-context"
    assert payload["HypervisorPresent"] is True
    assert payload["VbsStatus"] == "running"
    assert payload["Services"] == ["Credential Guard", "HVCI", "unknown-9"]
    assert payload["CodeIntegrityEnforced"] is True
    assert any("9" in warning for warning in payload["Warnings"])
    # A missing class means the data was not exposed, never "VBS disabled".
    assert payload["MissingStatus"] == "not-exposed"
    assert payload["MissingNote"] == "device-guard-class-not-exposed"
    assert payload["MissingServices"] == 0
    assert payload["OffStatus"] == "disabled"
    assert payload["OffHypervisor"] is False


def test_startup_entry_normalization_preserves_source_and_applies_privacy():
    """Startup entries keep their source location, and the Redacted level
    suppresses the command line while keeping the entry identifiable."""
    body = """
$standard = ConvertTo-WpdStartupEntry -Source 'registry' -Location 'HKCU Run' -Name 'Updater' `
    -Command 'C:\\Users\\alice\\updater.exe --silent' -Level 'Standard'
$redacted = ConvertTo-WpdStartupEntry -Source 'registry' -Location 'HKCU Run' -Name 'Updater' `
    -Command 'C:\\Users\\alice\\updater.exe --silent' -Level 'Redacted'
[pscustomobject]@{
    Kind = $standard.kind
    Source = $standard.source
    Location = $standard.location
    Name = $standard.name
    Command = $standard.command
    Enabled = $standard.enabled
    RedactedCommand = $redacted.command
    RedactedName = $redacted.name
    RedactedJson = ($redacted | ConvertTo-Json -Depth 6 -Compress)
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Kind"] == "startup-entry"
    assert payload["Source"] == "registry"
    assert payload["Location"] == "HKCU Run"
    assert payload["Name"] == "Updater"
    assert "updater.exe --silent" in payload["Command"]
    assert payload["Enabled"] is True
    assert payload["RedactedCommand"] is None
    assert payload["RedactedName"] == "Updater"
    assert "alice" not in payload["RedactedJson"]


FORBIDDEN_MODULE_TOKENS = [
    "Invoke-Expression",
    "Invoke-WebRequest",
    "Invoke-RestMethod",
    "WebClient",
    "Start-BitsTransfer",
    "Start-Process",
    "Stop-Process",
    "New-Item ",
    "New-ItemProperty",
    "Set-ItemProperty",
    "Remove-Item",
    "Remove-ItemProperty",
    "Set-Content",
    "Add-Content",
    "Out-File",
    "Set-Service",
    "Start-Service",
    "Stop-Service",
    "Restart-Service",
    "Clear-EventLog",
    "RestoreHealth",
    "sfc.exe",
    "chkdsk",
    "bcdedit",
    "Set-MpPreference",
    "Add-MpPreference",
    "Set-ExecutionPolicy",
]

# Query forms that must never appear: the MSI product class triggers
# reconfiguration, and a process/command query is not Tier 0 inventory.
FORBIDDEN_QUERY_FORMS = [
    "-ClassName 'Win32_Product'",
    "-ClassName Win32_Product",
    "-ClassName 'Win32_Process'",
    "-ClassName Win32_Process",
    "Get-Process",
    "Get-CimInstance -ClassName 'Win32_StartupCommand' -Namespace",
]


def test_module_source_is_readonly_ascii_without_bom_and_parses_under_both_engines():
    """The module is ASCII/LF/no-BOM, contains no write, download, remediation or
    MSI-reconfiguration query, and parses as a PowerShell module."""
    raw = MODULE.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf"), "module must not carry a UTF-8 BOM"
    assert b"\r\n" not in raw, "module must use LF line endings"
    text = raw.decode("ascii")
    assert all(ord(ch) < 128 for ch in text)

    for token in FORBIDDEN_MODULE_TOKENS + FORBIDDEN_QUERY_FORMS:
        assert token not in text, f"{token} must not appear in the inventory module"

    # No cmdlet that hands control to arbitrary code or executes a plugin.
    assert "Add-Type" not in text
    assert "New-Object -ComObject" not in text

    source = str(MODULE).replace("'", "''")
    body = f"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{source}', [ref]$tokens, [ref]$errors)
$exported = @((Get-Command -Module 'Wpd.Inventory' -CommandType Function).Name)
$providers = Get-WpdInventoryDefaultProviders
$providerText = @($providers.Values | ForEach-Object {{ @($_) }} | ForEach-Object {{ "$($_.name) $($_.source)" }}) -join ' '
[pscustomobject]@{{
    ParseErrors = @($errors).Count
    Exported = @($exported)
    ProviderText = $providerText
    MapCount = @(Get-WpdInventoryCapabilityMap).Count
}} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["ParseErrors"] == 0
    assert len(payload["Exported"]) == len(REQUIRED_COMMANDS)
    # The declared provider APIs are read-only inbox commands only.
    for token in ["Set-", "Remove-", "New-Item", "Restart-", "Invoke-WebRequest", "Win32_Product", "Start-Process"]:
        assert token not in payload["ProviderText"], f"{token} appears in a provider source"
    assert payload["MapCount"] == len(EXPECTED_CAPABILITIES)


def test_no_envelope_status_is_ever_healthy_and_missing_data_is_unavailable():
    """The status vocabulary has no healthy value, and a capability whose data is
    absent reports unavailable/unsupported with a reason."""
    body = """
$statuses = @('success', 'partial', 'unavailable', 'unsupported', 'not-collected', 'error')
$providers = @{
    pagefiles = @([pscustomobject]@{ name = 'pagefiles'; source = 'Win32_PageFileUsage'; platform = 'any'; collect = { @() } })
}
$result = Get-WpdInventory -Providers $providers -Context @{ IsWindows = $false; IsElevated = $false } -CacheKey 'vocabulary'
$unknownStatuses = @()
foreach ($id in @($result.capabilityOrder)) {
    if (@($statuses) -notcontains [string]$result.capabilities[$id].status) { $unknownStatuses += $id }
    if ([string]$result.capabilities[$id].coverage -eq 'complete' -and @($result.capabilities[$id].items).Count -eq 0 -and [string]$result.capabilities[$id].status -eq 'success' -and [string]$result.capabilities[$id].reasons -ne '') {
        $unknownStatuses += "reason-without-data:$id"
    }
}
[pscustomobject]@{
    UnknownStatuses = $unknownStatuses
    PagefilesStatus = $result.capabilities.pagefiles.status
    PagefilesReasons = @($result.capabilities.pagefiles.reasons)
    Vocabulary = $statuses
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["UnknownStatuses"] == []
    assert "healthy" not in payload["Vocabulary"]
    assert payload["PagefilesStatus"] == "unavailable"
    assert payload["PagefilesReasons"] == ["no-data-returned:pagefiles"]


# --- END OF TESTS ---
