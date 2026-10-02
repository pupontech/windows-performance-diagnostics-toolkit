"""Deterministic synthetic fixture matrix for every diagnostic scenario.

The fixtures under ``tests/fixtures/diagnostic-scenarios/`` are synthetic input
data only (counter rows, rules, event records, tool status output).  Every
scenario is driven through the real production modules in ``src/`` with pwsh;
no Windows provider, event log, trace reader or network endpoint is queried and
no source regex is asserted.

What each scenario declares and this file checks:

* ``driver``      - which production entry point receives the synthetic input;
* ``expect``      - the severity, confidence, evidence link, duration and
                    baseline facts the production code must report;
* ``allowHealthy`` - whether the word ``healthy`` may legitimately appear in
                    that scenario's payload (counter-set health only).

Cross-cutting rules asserted for every scenario: an unavailable measurement is
never reported as a health verdict, a coverage record is never a finding, and
no remediation is proposed anywhere.
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
SRC_DIR = REPO_ROOT / "src"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "diagnostic-scenarios"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"

BASE_MODULES = ("Wpd.Common", "Wpd.Telemetry", "Wpd.Report")

DRIVER_MODULES = {
    "report": ("Wpd.Common", "Wpd.Telemetry", "Wpd.Report"),
    "cpu": ("Wpd.Common", "Wpd.Telemetry"),
    "dpc": ("Wpd.Common", "Wpd.Telemetry"),
    "memory": ("Wpd.Common", "Wpd.Telemetry"),
    "pool": ("Wpd.Common", "Wpd.Telemetry"),
    "disk": ("Wpd.Common", "Wpd.Telemetry"),
    "disk-deltas": ("Wpd.Common", "Wpd.Telemetry"),
    "network": ("Wpd.Common", "Wpd.Telemetry"),
    "gpu": ("Wpd.Common", "Wpd.Telemetry"),
    "perflib": ("Wpd.Common", "Wpd.Telemetry"),
    "baseline": ("Wpd.Common", "Wpd.Report"),
    "whea": ("Wpd.Common", "Wpd.Events"),
    "repetitive-events": ("Wpd.Common", "Wpd.Events"),
    "waitchain": ("Wpd.Common", "Wpd.Escalation"),
    "defender": ("Wpd.Common", "Wpd.Escalation", "Wpd.Collectors"),
    "storage-reliability": ("Wpd.Common", "Wpd.Inventory"),
    "inventory": ("Wpd.Common", "Wpd.Inventory"),
    "symbols": ("Wpd.Common", "Wpd.Etw"),
    "tool": ("Wpd.Common", "Wpd.Etw"),
    "trace-validation": ("Wpd.Common", "Wpd.Etw"),
    "abandoned-session": ("Wpd.Common", "Wpd.Etw"),
    "storage-bound": ("Wpd.Common", "Wpd.Etw", "Wpd.Collectors"),
}

# Every scenario the card requires, mapped to the fixture that proves it.
REQUIRED_SCENARIOS = {
    "healthy": "healthy-window",
    "cpu-saturation": "cpu-saturation",
    "cpu-saturation-escalated": "cpu-saturation-escalated",
    "single-core": "single-core-saturation",
    "kernel-cpu": "kernel-cpu-share",
    "dpc-isr": "dpc-isr-share",
    "long-dpc": "long-dpc-execution",
    "commit-pressure": "commit-pressure",
    "true-paging": "true-paging-with-pressure",
    "high-pages-without-ram-shortage": "paging-without-pressure",
    "user-mode-leak": "user-mode-leak",
    "pool-growth": "kernel-pool-growth",
    "disk-latency": "disk-read-latency",
    "storage-warning-controller-reset": "storage-controller-warning-recurrence",
    "network-saturation-retransmits": "network-retransmit-pressure",
    "ui-hang-low-cpu": "ui-hang-low-cpu",
    "wait-chain-dependency": "wait-chain-dependency",
    "gpu-saturation": "gpu-saturation",
    "gpu-reset": "gpu-adapter-reset",
    "slow-boot": "slow-boot-degradation",
    "whea-recurrence": "whea-uncorrected-recurrence",
    "defender-overhead": "defender-scan-impact",
    "missing-wpa-symbols": "missing-wpa-tooling",
    "unsupported-smart": "unsupported-smart",
    "corrupted-perflib": "corrupted-perflib",
    "non-admin": "non-admin-capability",
    "interrupted-wpr": "interrupted-wpr-session",
    "insufficient-disk": "insufficient-disk-space",
}

# Operator words that would describe doing something to the machine.
REMEDIATION_PATTERNS = (
    r"\bsc\s+config\b",
    r"\breg\s+add\b",
    r"\breg\s+delete\b",
    r"\bnet\s+stop\b",
    r"\bRemove-Item\b",
    r"\bDisable-",
    r"\bUninstall-",
)

HEALTHY_TOKEN = re.compile(r"\bhealthy\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _load_manifest():
    if not MANIFEST_PATH.is_file():
        return None
    return _read_json(MANIFEST_PATH)


_MANIFEST = _load_manifest()
_SCENARIO_IDS = [entry["id"] for entry in (_MANIFEST or {}).get("scenarios", [])]


def _scenario_entry(scenario_id: str) -> dict:
    if _MANIFEST is None:
        pytest.fail("fixture manifest is missing: " + str(MANIFEST_PATH))
    for entry in _MANIFEST["scenarios"]:
        if entry["id"] == scenario_id:
            return entry
    pytest.fail("unknown scenario id: " + scenario_id)


def _scenario_path(scenario_id: str) -> Path:
    return FIXTURE_DIR / (scenario_id + ".json")


# ---------------------------------------------------------------------------
# PowerShell driver harness
# ---------------------------------------------------------------------------


def _ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _module_imports(kind: str) -> str:
    names = DRIVER_MODULES[kind]
    lines = [
        "Import-Module -Name " + _ps_quote(str(SRC_DIR / (name + ".psm1"))) + " -Force -DisableNameChecking"
        for name in names
    ]
    return "\n".join(lines)


PS_PRELUDE = """
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
{imports}
Set-StrictMode -Version Latest

function Get-FxProp {{
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) {{ return $Default }}
    if ($Object -is [System.Collections.IDictionary]) {{
        if ($Object.Contains($Name)) {{ return $Object[$Name] }}
        return $Default
    }}
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {{ return $Default }}
    return $property.Value
}}

function Get-FxArray {{
    # An empty JSON array comes back from a function as no output; this keeps
    # "empty" distinct from "absent" for the production [object[]] parameters.
    param($Object, [string]$Name)
    $value = Get-FxProp -Object $Object -Name $Name
    if ($null -eq $value) {{ return ,@() }}
    if ($value -is [System.Array]) {{ return ,$value }}
    return @($value)
}}

function Get-Num {{
    param($Value)
    if ($null -eq $Value) {{ return $null }}
    try {{ return [double]$Value }} catch {{ return $null }}
}}

$fx = Get-Content -LiteralPath {fixture} -Raw | ConvertFrom-Json
$driverArgs = Get-FxProp -Object $fx.driver -Name 'args'
"""

REPORT_DRIVER = r"""
$splat = @{}
$names = @{
    samples = 'Samples'; diskSeries = 'DiskSeries'; processSamples = 'ProcessSamples'
    eventRows = 'EventRows'; rules = 'Rules'; dataQuality = 'DataQuality'
    timeline = 'Timeline'; artifacts = 'Artifacts'; baselineRows = 'BaselineRows'
    incidentRows = 'IncidentRows'; noEvidenceCandidates = 'NoEvidenceCandidates'
    valueProperty = 'ValueProperty'; percentiles = 'Percentiles'
    incident = 'Incident'; manifest = 'Manifest'
}
foreach ($key in @($names.Keys)) {
    $value = Get-FxProp -Object $driverArgs -Name $key
    if ($null -ne $value) { $splat[$names[$key]] = $value }
}
$report = Invoke-WpdReportAnalysis @splat
$findings = @(Get-FxProp -Object $report -Name 'findings' -Default @())
$projected = @()
foreach ($finding in $findings) {
    $measured = Get-FxProp -Object $finding -Name 'measuredValues'
    $rule = Get-FxProp -Object $finding -Name 'rule'
    $evidenceIds = @()
    foreach ($item in @(Get-FxProp -Object $finding -Name 'evidence' -Default @())) {
        $evidenceIds += [string](Get-FxProp -Object $item -Name 'id')
    }
    $projected += [pscustomobject]@{
        id = [string](Get-FxProp -Object $finding -Name 'id')
        category = [string](Get-FxProp -Object $finding -Name 'category')
        severity = [string](Get-FxProp -Object $finding -Name 'severity')
        confidence = [string](Get-FxProp -Object $finding -Name 'confidence')
        title = [string](Get-FxProp -Object $finding -Name 'title')
        ruleId = [string](Get-FxProp -Object $rule -Name 'id')
        evidenceIds = @($evidenceIds)
        evidenceCount = @($evidenceIds).Count
        windowStart = [string](Get-FxProp -Object $finding -Name 'windowStart')
        windowEnd = [string](Get-FxProp -Object $finding -Name 'windowEnd')
        peak = Get-Num (Get-FxProp -Object $measured -Name 'peak')
        count = Get-Num (Get-FxProp -Object $measured -Name 'count')
        consecutiveSamples = Get-Num (Get-FxProp -Object $measured -Name 'consecutiveSamples')
        durationSeconds = Get-Num (Get-FxProp -Object $measured -Name 'durationSeconds')
        ruleCondition = [string](Get-FxProp -Object $finding -Name 'ruleCondition')
        uncertainty = [string](Get-FxProp -Object $finding -Name 'uncertainty')
        severityReason = [string](Get-FxProp -Object $finding -Name 'severityReason')
        confidenceReason = [string](Get-FxProp -Object $finding -Name 'confidenceReason')
        nextSteps = @(Get-FxProp -Object $finding -Name 'nextSteps' -Default @())
        hasRemediationField = (
            $null -ne (Get-FxProp -Object $finding -Name 'remediation') -or
            $null -ne (Get-FxProp -Object $finding -Name 'fix') -or
            $null -ne (Get-FxProp -Object $finding -Name 'actions')
        )
    }
}
$validation = Test-WpdEvidenceLinks -Findings $findings -EvidenceIndex $report.evidenceIndex
$quality = $report.dataQuality
$html = ConvertTo-WpdHtmlReport -Report $report
$noEvidence = @()
foreach ($item in @(Get-FxProp -Object $report -Name 'noEvidenceOf' -Default @())) {
    $noEvidence += [pscustomobject]@{
        topic = [string](Get-FxProp -Object $item -Name 'topic')
        collector = [string](Get-FxProp -Object $item -Name 'collector')
        text = [string](Get-FxProp -Object $item -Name 'text')
    }
}
$baseline = @()
foreach ($item in @(Get-FxProp -Object $report -Name 'baselineComparisons' -Default @())) {
    $baselinePart = Get-FxProp -Object $item -Name 'baseline'
    $incidentPart = Get-FxProp -Object $item -Name 'incident'
    $baseline += [pscustomobject]@{
        status = [string](Get-FxProp -Object $item -Name 'status')
        baselineDurationSeconds = Get-Num (Get-FxProp -Object $item -Name 'BaselineDurationSeconds')
        incidentDurationSeconds = Get-Num (Get-FxProp -Object $item -Name 'IncidentDurationSeconds')
        baselineP50 = Get-Num (Get-FxProp -Object $baselinePart -Name 'P50')
        baselineP95 = Get-Num (Get-FxProp -Object $baselinePart -Name 'P95')
        baselineP99 = Get-Num (Get-FxProp -Object $baselinePart -Name 'P99')
        p50 = Get-Num (Get-FxProp -Object $incidentPart -Name 'P50')
        p95 = Get-Num (Get-FxProp -Object $incidentPart -Name 'P95')
        p99 = Get-Num (Get-FxProp -Object $incidentPart -Name 'P99')
        deltaP95 = Get-Num (Get-FxProp -Object $item -Name 'DeltaP95')
        deltaP99 = Get-Num (Get-FxProp -Object $item -Name 'DeltaP99')
    }
}
$result = [pscustomobject]@{
    status = [string](Get-FxProp -Object $report -Name 'status')
    outcome = [string](Get-FxProp -Object $report -Name 'outcome')
    technicianSummary = [string](Get-FxProp -Object $report -Name 'technicianSummary')
    sections = @(Get-FxProp -Object $report -Name 'sections' -Default @())
    findingCount = $findings.Count
    findings = @($projected)
    evidence = [pscustomobject]@{
        valid = [bool](Get-FxProp -Object $validation -Name 'valid')
        status = [string](Get-FxProp -Object $validation -Name 'status')
        checkedCount = [int](Get-FxProp -Object $validation -Name 'checkedCount')
        missingEvidenceIds = @(Get-FxProp -Object $validation -Name 'missingEvidenceIds' -Default @())
        unregisteredArtifacts = @(Get-FxProp -Object $validation -Name 'unregisteredArtifacts' -Default @())
        invalidFindings = @(Get-FxProp -Object $validation -Name 'invalidFindings' -Default @())
        errors = @(Get-FxProp -Object $validation -Name 'errors' -Default @())
    }
    coverage = [pscustomobject]@{
        status = [string](Get-FxProp -Object $quality -Name 'status')
        coverage = [string](Get-FxProp -Object $quality -Name 'coverage')
        totalCollectors = [int](Get-FxProp -Object $quality -Name 'totalCollectors')
        completeCount = [int](Get-FxProp -Object $quality -Name 'completeCount')
        partialCount = [int](Get-FxProp -Object $quality -Name 'partialCount')
        unavailableCount = [int](Get-FxProp -Object $quality -Name 'unavailableCount')
        notCollectedCount = [int](Get-FxProp -Object $quality -Name 'notCollectedCount')
        unsupportedCount = [int](Get-FxProp -Object $quality -Name 'unsupportedCount')
        sufficient = [bool](Get-FxProp -Object $quality -Name 'sufficient')
        reasons = @(Get-FxProp -Object $quality -Name 'reasons' -Default @())
    }
    noEvidence = @($noEvidence)
    noEvidenceCount = $noEvidence.Count
    baselineComparisons = @($baseline)
    baselineComparisonCount = $baseline.Count
    htmlHasNoRemediationNotice = [bool]$html.Contains('no remediation is performed')
    htmlContainsHealthyToken = [bool]($html -match '(?i)healthy')
    htmlLength = $html.Length
}
$result | ConvertTo-Json -Depth 14 -Compress
"""

CPU_DRIVER = r"""
$result = Get-CpuSummary -Rows (Get-FxProp -Object $driverArgs -Name 'rows') `
    -LogicalProcessorCount (Get-FxProp -Object $driverArgs -Name 'logicalProcessorCount')
$result | ConvertTo-Json -Depth 12 -Compress
"""

DPC_DRIVER = r"""
$result = Get-DpcIsrMetrics -Rows (Get-FxProp -Object $driverArgs -Name 'rows') `
    -Config (Get-FxProp -Object $driverArgs -Name 'config')
$result | ConvertTo-Json -Depth 12 -Compress
"""

MEMORY_DRIVER = r"""
$result = Get-MemoryAnalysis -Rows (Get-FxProp -Object $driverArgs -Name 'rows') `
    -Config (Get-FxProp -Object $driverArgs -Name 'config')
$result | ConvertTo-Json -Depth 12 -Compress
"""

POOL_DRIVER = r"""
$result = Measure-PoolGrowth -Rows (Get-FxProp -Object $driverArgs -Name 'rows') `
    -Config (Get-FxProp -Object $driverArgs -Name 'config')
$result | ConvertTo-Json -Depth 12 -Compress
"""

DISK_DRIVER = r"""
$result = Measure-DiskLatency -PreviousRows (Get-FxProp -Object $driverArgs -Name 'previousRows') `
    -CurrentRows (Get-FxProp -Object $driverArgs -Name 'currentRows') `
    -ElapsedSeconds (Get-FxProp -Object $driverArgs -Name 'elapsedSeconds') `
    -FrequencyPerfTime (Get-FxProp -Object $driverArgs -Name 'frequencyPerfTime')
[pscustomobject]@{ result = @($result) } | ConvertTo-Json -Depth 12 -Compress
"""

DISK_DELTA_DRIVER = r"""
$result = Get-DiskCounterDeltas -Previous (Get-FxProp -Object $driverArgs -Name 'previous') `
    -Current (Get-FxProp -Object $driverArgs -Name 'current') `
    -TimestampUtc (Get-FxProp -Object $driverArgs -Name 'timestampUtc')
[pscustomobject]@{ result = @($result) } | ConvertTo-Json -Depth 12 -Compress
"""

NETWORK_DRIVER = r"""
$result = Get-NetworkSummary -PreviousRows (Get-FxProp -Object $driverArgs -Name 'previousRows') `
    -CurrentRows (Get-FxProp -Object $driverArgs -Name 'currentRows') `
    -ElapsedSeconds (Get-FxProp -Object $driverArgs -Name 'elapsedSeconds') `
    -Config (Get-FxProp -Object $driverArgs -Name 'config')
$result | ConvertTo-Json -Depth 12 -Compress
"""

GPU_DRIVER = r"""
$gpu = Get-GpuTelemetry -Rows (Get-FxArray -Object $driverArgs -Name 'rows')
$engines = @(Get-FxProp -Object $gpu -Name 'Engines' -Default @())
$memory = @(Get-FxProp -Object $gpu -Name 'ProcessMemory' -Default @())
$adapters = @(Get-FxProp -Object $gpu -Name 'Adapters' -Default @())
$projectedEngines = @()
$maxUtilization = $null
foreach ($engine in $engines) {
    $utilization = Get-Num (Get-FxProp -Object $engine -Name 'UtilizationPercentage')
    if ($null -ne $utilization -and ($null -eq $maxUtilization -or $utilization -gt $maxUtilization)) { $maxUtilization = $utilization }
    $projectedEngines += [pscustomobject]@{
        processId = Get-Num (Get-FxProp -Object $engine -Name 'ProcessId')
        adapter = [string](Get-FxProp -Object $engine -Name 'Adapter')
        engineType = [string](Get-FxProp -Object $engine -Name 'EngineType')
        utilizationPercentage = $utilization
    }
}
$temperature = Get-FxProp -Object $gpu -Name 'Temperature'
$clocks = Get-FxProp -Object $gpu -Name 'Clocks'
$result = [pscustomobject]@{
    status = [string](Get-FxProp -Object $gpu -Name 'Status')
    available = [bool](Get-FxProp -Object $gpu -Name 'Available')
    adapterCount = $adapters.Count
    engineCount = $engines.Count
    engines = @($projectedEngines)
    memoryCount = $memory.Count
    maxEngineUtilization = $maxUtilization
    temperatureAvailable = [bool](Get-FxProp -Object $temperature -Name 'Available')
    temperatureValueCelsius = Get-Num (Get-FxProp -Object $temperature -Name 'ValueCelsius')
    temperatureReason = [string](Get-FxProp -Object $temperature -Name 'Reason')
    clocksAvailable = [bool](Get-FxProp -Object $clocks -Name 'Available')
    clockMHz = Get-Num (Get-FxProp -Object $clocks -Name 'ValueMHz')
    clocksReason = [string](Get-FxProp -Object $clocks -Name 'Reason')
}
$result | ConvertTo-Json -Depth 12 -Compress
"""

PERFLIB_DRIVER = r"""
$result = Get-PerflibHealth -Rows (Get-FxProp -Object $driverArgs -Name 'rows')
$result | ConvertTo-Json -Depth 12 -Compress
"""

BASELINE_DRIVER = r"""
$result = Compare-WpdBaselineIncident -BaselineRows (Get-FxProp -Object $driverArgs -Name 'baselineRows') `
    -IncidentRows (Get-FxProp -Object $driverArgs -Name 'incidentRows') `
    -ValueProperty ([string](Get-FxProp -Object $driverArgs -Name 'valueProperty')) `
    -Percentiles @(50, 95, 99)
$result | ConvertTo-Json -Depth 12 -Compress
"""

WHEA_DRIVER = r"""
$records = @()
foreach ($entry in @(Get-FxProp -Object $driverArgs -Name 'records' -Default @())) {
    $eventData = @{}
    $dataObject = Get-FxProp -Object $entry -Name 'eventData'
    if ($null -ne $dataObject) {
        foreach ($property in @($dataObject.PSObject.Properties)) {
            $eventData[$property.Name] = [string]$property.Value
        }
    }
    $records += [pscustomobject]@{
        provider = [string](Get-FxProp -Object $entry -Name 'provider')
        eventId = Get-FxProp -Object $entry -Name 'eventId'
        timeCreatedUtc = [string](Get-FxProp -Object $entry -Name 'timeCreatedUtc')
        message = Get-FxProp -Object $entry -Name 'message'
        eventData = $eventData
    }
}
$envelope = Get-FxProp -Object $driverArgs -Name 'envelope'
$result = Get-WpdWheaAnalysis -Records $records `
    -WindowStart (Get-FxProp -Object $driverArgs -Name 'windowStart') `
    -WindowEnd (Get-FxProp -Object $driverArgs -Name 'windowEnd') `
    -Envelope $envelope
$result | ConvertTo-Json -Depth 12 -Compress
"""

REPETITIVE_DRIVER = r"""
$records = @(Get-FxProp -Object $driverArgs -Name 'records' -Default @())
$result = Group-WpdRepetitiveEvent -Records $records `
    -WindowStart (Get-FxProp -Object $driverArgs -Name 'windowStart') `
    -WindowEnd (Get-FxProp -Object $driverArgs -Name 'windowEnd') `
    -MinimumCount ([int](Get-FxProp -Object $driverArgs -Name 'minimumCount' -Default 3))
[pscustomobject]@{ result = @($result) } | ConvertTo-Json -Depth 12 -Compress
"""

WAITCHAIN_DRIVER = r"""
$result = Get-WpdWaitChainAnalysis -Chains @(Get-FxProp -Object $driverArgs -Name 'chains' -Default @())
$result | ConvertTo-Json -Depth 12 -Compress
"""

DEFENDER_DRIVER = r"""
$consent = [bool](Get-FxProp -Object $driverArgs -Name 'consent' -Default $false)
$moduleAvailable = Get-FxProp -Object $driverArgs -Name 'moduleAvailable'
$splat = @{
    Consent = $consent
    PrivacyLevel = 'Standard'
    ModuleAvailable = $moduleAvailable
    ModuleTable = @{}
    CommandTable = @{}
}
$result = Get-WpdDefenderSearchContext @splat
$result | ConvertTo-Json -Depth 12 -Compress
"""

STORAGE_RELIABILITY_DRIVER = r"""
$counters = Get-FxProp -Object $driverArgs -Name 'counters'
$result = ConvertTo-WpdStorageReliabilityRecord -Counters $counters `
    -DeviceId ([string](Get-FxProp -Object $driverArgs -Name 'deviceId'))
$result | ConvertTo-Json -Depth 12 -Compress
"""

INVENTORY_DRIVER = r"""
$capabilityId = [string](Get-FxProp -Object $driverArgs -Name 'capabilityId')
$counter = @{ called = 0 }
$providers = @{}
foreach ($id in @(Get-FxProp -Object $driverArgs -Name 'providerIds' -Default @())) {
    $providers[[string]$id] = @{
        name = 'fixture-provider'
        source = 'fixture-provider'
        collect = { param() $counter['called'] = $counter['called'] + 1; return @([pscustomobject]@{ id = 'fixture' }) }
    }
}
$context = @{
    IsWindows = $true
    IsElevated = [bool](Get-FxProp -Object $driverArgs -Name 'elevated' -Default $false)
    CommandTable = @{}
}
$envelope = Get-WpdInventoryCapability -Id $capabilityId -Providers $providers -Context $context -CacheKey 'fixture'
[pscustomobject]@{
    result = $envelope
    providerCallCount = [int]$counter['called']
} | ConvertTo-Json -Depth 12 -Compress
"""

SYMBOLS_DRIVER = r"""
$result = Get-WpdEtwSymbolPolicy -TracePath ([string](Get-FxProp -Object $driverArgs -Name 'tracePath')) `
    -PathProbe { param($candidate) return $false }
$result | ConvertTo-Json -Depth 12 -Compress
"""

TOOL_DRIVER = r"""
$result = Find-WpdEtwTool -SearchPaths @([string](Get-FxProp -Object $driverArgs -Name 'searchPath')) `
    -PathProbe { param($candidate) return $false }
[pscustomobject]@{ result = @($result) } | ConvertTo-Json -Depth 12 -Compress
"""

TRACE_VALIDATION_DRIVER = r"""
$result = Get-WpdEtwTraceValidation -EtlPath ([string](Get-FxProp -Object $driverArgs -Name 'etlPath')) `
    -SizeBytes ([long](Get-FxProp -Object $driverArgs -Name 'sizeBytes')) `
    -StartExitCode ([int](Get-FxProp -Object $driverArgs -Name 'startExitCode' -Default 0)) `
    -StopExitCode ([int](Get-FxProp -Object $driverArgs -Name 'stopExitCode' -Default 0))
$result | ConvertTo-Json -Depth 12 -Compress
"""

ABANDONED_SESSION_DRIVER = r"""
$result = Test-WpdEtwAbandonedSession -StatusOutput ([string](Get-FxProp -Object $driverArgs -Name 'statusOutput')) `
    -OwnerTag ([string](Get-FxProp -Object $driverArgs -Name 'ownerTag')) `
    -ExpectedInstanceName ([string](Get-FxProp -Object $driverArgs -Name 'expectedInstanceName'))
$result | ConvertTo-Json -Depth 12 -Compress
"""

STORAGE_BOUND_DRIVER = r"""
$strategy = [pscustomobject]@{
    StoragePolicy = [string](Get-FxProp -Object $driverArgs -Name 'storagePolicy')
    Bounded = [bool](Get-FxProp -Object $driverArgs -Name 'bounded' -Default $true)
    TraceBudgetMB = [int](Get-FxProp -Object $driverArgs -Name 'traceBudgetMB')
    MaxDurationSeconds = [int](Get-FxProp -Object $driverArgs -Name 'maxDurationSeconds')
    Mode = [string](Get-FxProp -Object $driverArgs -Name 'mode' -Default 'memory')
}
$result = Test-WpdCaptureStorageBound -Strategy $strategy `
    -FreeSpaceBytes ([long](Get-FxProp -Object $driverArgs -Name 'freeSpaceBytes')) `
    -OutputDirectory ([string](Get-FxProp -Object $driverArgs -Name 'outputDirectory')) `
    -RequestedDurationSeconds ([int](Get-FxProp -Object $driverArgs -Name 'requestedDurationSeconds'))
$result | ConvertTo-Json -Depth 12 -Compress
"""

DRIVER_BODIES = {
    "report": REPORT_DRIVER,
    "cpu": CPU_DRIVER,
    "dpc": DPC_DRIVER,
    "memory": MEMORY_DRIVER,
    "pool": POOL_DRIVER,
    "disk": DISK_DRIVER,
    "disk-deltas": DISK_DELTA_DRIVER,
    "network": NETWORK_DRIVER,
    "gpu": GPU_DRIVER,
    "perflib": PERFLIB_DRIVER,
    "baseline": BASELINE_DRIVER,
    "whea": WHEA_DRIVER,
    "repetitive-events": REPETITIVE_DRIVER,
    "waitchain": WAITCHAIN_DRIVER,
    "defender": DEFENDER_DRIVER,
    "storage-reliability": STORAGE_RELIABILITY_DRIVER,
    "inventory": INVENTORY_DRIVER,
    "symbols": SYMBOLS_DRIVER,
    "tool": TOOL_DRIVER,
    "trace-validation": TRACE_VALIDATION_DRIVER,
    "abandoned-session": ABANDONED_SESSION_DRIVER,
    "storage-bound": STORAGE_BOUND_DRIVER,
}


def _build_harness(scenario: dict) -> str:
    kind = scenario["driver"]["kind"]
    assert kind in DRIVER_BODIES, f"unknown driver kind {kind!r}"
    prelude = PS_PRELUDE.format(
        imports=_module_imports(kind),
        fixture=_ps_quote(str(_scenario_path(scenario["id"]))),
    )
    return prelude + "\n" + DRIVER_BODIES[kind]


def run_scenario(scenario: dict):
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    if not shutil.which(powershell):
        pytest.skip(f"{powershell} is required for the scenario fixture matrix")
    harness = _build_harness(scenario)
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-Command", harness],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, (
        "pwsh failed for scenario "
        + scenario["id"]
        + "\nSTDOUT:\n"
        + result.stdout
        + "\nSTDERR:\n"
        + result.stderr
    )
    output = result.stdout.strip()
    assert output, "scenario " + scenario["id"] + " produced no JSON"
    return json.loads(output)


# ---------------------------------------------------------------------------
# Expectation checking
# ---------------------------------------------------------------------------


def _lookup(container, token: str):  # pragma: no cover - replaced by resolve_path_flat
    raise NotImplementedError


def resolve_path_flat(payload, path: str):
    """Resolve with single-element-array collapsing: findings.0 == findings."""
    current = payload
    tokens = [token for token in path.split(".") if token != ""]
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if isinstance(current, dict):
            matched = None
            found = False
            for key, value in current.items():
                if str(key).lower() == token.lower():
                    matched = value
                    found = True
                    break
            if found:
                current = matched
                index += 1
                continue
            if token.isdigit():
                keys_lower = {str(key).lower() for key in current}
                next_token = tokens[index + 1].lower() if index + 1 < len(tokens) else None
                if next_token is not None and next_token in keys_lower:
                    # The index addresses a collapsed one-element array: this
                    # object IS the element.
                    index += 1
                    continue
                candidates = [
                    value
                    for value in current.values()
                    if isinstance(value, dict)
                    and (next_token in {str(key).lower() for key in value} or next_token is None)
                ]
                if len(candidates) == 1:
                    current = candidates[0]
                    index += 1
                    continue
            raise KeyError(token)
        if isinstance(current, list):
            if token.isdigit():
                current = current[int(token)]
                index += 1
                continue
            # Collapsed single-element array: skip the index token.
            if len(current) == 1 and index + 1 < len(tokens) and tokens[index + 1].isdigit():
                current = current[0]
                index += 1
                continue
            raise KeyError(token)
        raise KeyError(token)
    return current


def _stringify(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def matches(actual, expected) -> bool:
    if isinstance(expected, dict):
        for operator, operand in expected.items():
            if operator == "oneOf":
                if not any(matches(actual, item) for item in operand):
                    return False
            elif operator == "notOneOf":
                if any(matches(actual, item) for item in operand):
                    return False
            elif operator == "gte":
                if actual is None or float(actual) < float(operand):
                    return False
            elif operator == "lte":
                if actual is None or float(actual) > float(operand):
                    return False
            elif operator == "gt":
                if actual is None or float(actual) <= float(operand):
                    return False
            elif operator == "lt":
                if actual is None or float(actual) >= float(operand):
                    return False
            elif operator == "contains":
                if actual is None or _stringify(operand).lower() not in _stringify(actual).lower():
                    return False
            elif operator == "notContains":
                if actual is not None and _stringify(operand).lower() in _stringify(actual).lower():
                    return False
            elif operator == "regex":
                if actual is None or re.search(_stringify(operand), _stringify(actual)) is None:
                    return False
            elif operator == "present":
                if (actual is None) == bool(operand):
                    return False
            elif operator == "anyElement":
                if not isinstance(actual, list):
                    return False
                operand_path = operand["path"]
                expected = operand["value"]
                for element in actual:
                    try:
                        inner = resolve_path_flat(element, operand_path)
                    except (KeyError, IndexError):
                        continue
                    if matches(inner, expected):
                        return True
                return False
            elif operator == "includes":
                if actual is None:
                    return False
                values = actual if isinstance(actual, list) else [actual]
                rendered = {_stringify(item).lower() for item in values}
                if not all(_stringify(item).lower() in rendered for item in operand):
                    return False
            elif operator == "excludes":
                if actual is None:
                    return True
                values = actual if isinstance(actual, list) else [actual]
                rendered = {_stringify(item).lower() for item in values}
                if any(_stringify(item).lower() in rendered for item in operand):
                    return False
            elif operator == "count":
                values = actual if isinstance(actual, list) else ([actual] if actual is not None else [])
                if len(values) != int(operand):
                    return False
            elif operator == "countGte":
                values = actual if isinstance(actual, list) else ([actual] if actual is not None else [])
                if len(values) < int(operand):
                    return False
            elif operator == "absent":
                if (actual is not None) == bool(operand):
                    return False
            else:  # pragma: no cover - guards a typo in a fixture
                raise AssertionError("unknown expectation operator: " + operator)
        return True
    if isinstance(actual, bool) or isinstance(expected, bool):
        return bool(actual) == bool(expected)
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        if actual is None:
            return False
        try:
            return abs(float(actual) - float(expected)) < 1e-9
        except (TypeError, ValueError):
            return False
    return _stringify(actual).lower() == _stringify(expected).lower()


def check_expectations(payload, scenario: dict) -> list:
    failures = []
    for path, expected in sorted(scenario["expect"].items()):
        try:
            actual = resolve_path_flat(payload, path)
        except (KeyError, IndexError):
            failures.append(f"{path}: path not present in payload (expected {expected!r})")
            continue
        if not matches(actual, expected):
            failures.append(f"{path}: expected {expected!r}, got {actual!r}")
    return failures


def walk_strings(node, prefix=""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk_strings(value, prefix + "." + str(key) if prefix else str(key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk_strings(value, f"{prefix}.{index}")
    elif isinstance(node, str):
        yield prefix, node


# ---------------------------------------------------------------------------
# Manifest and fixture integrity
# ---------------------------------------------------------------------------


def test_fixture_directory_and_manifest_exist():
    assert FIXTURE_DIR.is_dir(), f"fixture directory is missing: {FIXTURE_DIR}"
    assert MANIFEST_PATH.is_file(), f"fixture manifest is missing: {MANIFEST_PATH}"


def test_manifest_covers_every_required_scenario():
    assert _MANIFEST is not None, "fixture manifest could not be read"
    declared = {entry["id"]: entry for entry in _MANIFEST["scenarios"]}
    missing = sorted(set(REQUIRED_SCENARIOS.values()) - set(declared))
    assert not missing, "required scenario fixtures are missing: " + ", ".join(missing)
    for scenario_id, entry in declared.items():
        assert entry.get("title"), f"{scenario_id}: every scenario states a title"
        assert entry.get("driver", {}).get("kind"), f"{scenario_id}: no driver kind"
        assert entry["driver"]["kind"] in DRIVER_BODIES, f"{scenario_id}: unknown driver kind"
        assert entry.get("expect"), f"{scenario_id}: every scenario declares expectations"
        assert _scenario_path(scenario_id).is_file(), f"{scenario_id}: fixture file is missing"
        fixture = _read_json(_scenario_path(scenario_id))
        assert fixture.get("driver", {}).get("kind") == entry["driver"]["kind"], (
            scenario_id + ": manifest and fixture disagree about the driver kind"
        )
        assert fixture["id"] == scenario_id, scenario_id + ": fixture id mismatch"


def test_required_scenario_map_points_at_declared_fixtures():
    declared = {entry["id"] for entry in (_MANIFEST or {}).get("scenarios", [])}
    for requirement, fixture_id in sorted(REQUIRED_SCENARIOS.items()):
        assert fixture_id in declared, f"requirement {requirement} -> unknown fixture {fixture_id}"


def test_fixture_files_are_ascii_and_have_no_bom():
    offenders = []
    for path in sorted(FIXTURE_DIR.glob("*.json")):
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            offenders.append(f"{path.name}: UTF-8 BOM")
        try:
            raw.decode("ascii")
        except UnicodeDecodeError as error:
            offenders.append(f"{path.name}: non-ASCII byte at {error.start}")
    assert not offenders, "fixture encoding violations: " + "; ".join(offenders)
    harness = Path(__file__).read_bytes()
    assert not harness.startswith(b"\xef\xbb\xbf"), "test file has a BOM"
    harness.decode("ascii")


def test_expectation_checker_detects_a_wrong_value():
    payload = {"findings": [{"severity": "medium"}]}
    good = check_expectations(payload, {"id": "self", "expect": {"findings.0.severity": "medium"}})
    bad = check_expectations(payload, {"id": "self", "expect": {"findings.0.severity": "high"}})
    absent = check_expectations(payload, {"id": "self", "expect": {"findings.0.confidence": "low"}})
    assert good == []
    assert bad and "severity" in bad[0]
    assert absent and "not present" in absent[0]


# ---------------------------------------------------------------------------
# Scenario execution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario_id", _SCENARIO_IDS)
def test_scenario_drives_production_code_and_matches_expectations(scenario_id):
    """A window with no finding must stay a coverage statement, never a verdict."""
    entry = _scenario_entry(scenario_id)
    if entry.get("knownDefect"):
        pytest.xfail(entry["knownDefect"])
    payload = run_scenario(entry)
    failures = check_expectations(payload, entry)
    assert not failures, scenario_id + " expectation failures:\n  " + "\n  ".join(failures)


@pytest.mark.parametrize("scenario_id", _SCENARIO_IDS)
def test_scenario_never_reports_health_and_never_proposes_remediation(scenario_id):
    entry = _scenario_entry(scenario_id)
    if entry.get("knownDefect"):
        pytest.xfail(entry["knownDefect"])
    payload = run_scenario(entry)
    allowed = {path.lower() for path in entry.get("allowHealthyPaths", [])}

    for path, value in walk_strings(payload):
        if not HEALTHY_TOKEN.search(value):
            continue
        assert path.lower() in allowed, (
            scenario_id
            + ": a health verdict token appears at "
            + path
            + " ("
            + value
            + ") without being declared in allowHealthyPaths"
        )

    for path, value in walk_strings(payload):
        for pattern in REMEDIATION_PATTERNS:
            assert re.search(pattern, value) is None, (
                scenario_id + ": remediation-shaped text at " + path + ": " + value
            )

    for finding in payload.get("findings", []) or []:
        assert not finding.get("hasRemediationField"), (
            scenario_id + ": finding " + finding.get("id", "?") + " carries a remediation field"
        )
    if entry["driver"]["kind"] == "report":
        assert payload["htmlHasNoRemediationNotice"] is True, (
            scenario_id + ": the technician HTML does not state that no remediation is performed"
        )


def test_healthy_window_produces_no_finding_and_no_health_verdict():
    """The healthy fixture is the contract test for 'no finding' itself."""
    entry = _scenario_entry(REQUIRED_SCENARIOS["healthy"])
    payload = run_scenario(entry)
    assert payload["findingCount"] == 0
    assert payload["outcome"] == "ROOT CAUSE NOT IDENTIFIED"
    assert payload["coverage"]["coverage"] in ("complete", "partial")
    assert payload["htmlContainsHealthyToken"] is False


def test_unavailable_source_is_never_reported_as_healthy():
    """A scenario whose source is absent must be unavailable, never healthy."""
    entry = _scenario_entry("gpu-unavailable-counters")
    payload = run_scenario(entry)
    assert payload["status"] == "unavailable"
    assert payload["available"] is False
    assert payload["engineCount"] == 0
    assert payload["maxEngineUtilization"] is None

    reset_entry = _scenario_entry(REQUIRED_SCENARIOS["gpu-reset"])
    reset_payload = run_scenario(reset_entry)
    assert reset_payload["engineCount"] == 0
    assert reset_payload["maxEngineUtilization"] is None
    assert reset_payload["adapterCount"] == 1
