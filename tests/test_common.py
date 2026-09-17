"""Behavioral tests for the shared WPD common contract.

These tests import the real PowerShell module and exercise exported functions with
synthetic values. Windows-only providers are never queried by this suite.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE = REPO_ROOT / "src" / "Wpd.Common.psm1"


def run_pwsh(body: str) -> str:
    """Import the real common module and execute a PowerShell test body."""
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    if not shutil.which(powershell):
        pytest.skip(f"{powershell} is required for the common module tests")
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
    return result.stdout.strip()


def run_json(body: str):
    output = run_pwsh(body)
    assert output, "PowerShell body did not emit JSON"
    return json.loads(output)


def test_missing_measurement_stays_unavailable_in_collector_result():
    """An empty successful-looking measurement must not become a healthy result."""
    payload = run_json(
        r"""
$result = New-WpdCollectorResult `
    -Collector 'memory' `
    -Status 'success' `
    -Records @() `
    -StartedUtc '2026-09-10T12:00:00Z' `
    -CompletedUtc '2026-09-10T12:00:01Z'
[pscustomobject]@{
    Status = $result.status
    Coverage = $result.coverage
    RecordCount = $result.recordCount
    Healthy = ($result.status -eq 'healthy' -or $result.coverage -eq 'healthy')
} | ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert payload == {
        "Status": "unavailable",
        "Coverage": "unavailable",
        "RecordCount": 0,
        "Healthy": False,
    }


def test_time_context_exposes_local_utc_iso_and_timezone_for_an_injected_time():
    """Time output is deterministic when the clock and timezone are injected."""
    payload = run_json(
        r"""
$time = Get-WpdTimeContext `
    -Now '2026-09-10T14:00:00+02:00' `
    -TimeZoneId 'UTC'
[pscustomobject]@{
    Status = $time.status
    Utc = $time.utcTimestamp
    Iso = $time.isoTimestamp
    Local = $time.localTimestamp
    TimeZone = $time.timeZoneId
    OffsetMinutes = $time.utcOffsetMinutes
} | ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert payload == {
        "Status": "complete",
        "Utc": "2026-09-10T12:00:00.0000000Z",
        "Iso": "2026-09-10T12:00:00.0000000Z",
        "Local": "2026-09-10T12:00:00.0000000+00:00",
        "TimeZone": "UTC",
        "OffsetMinutes": 0,
    }


def test_incident_window_uses_marker_padding_and_rejects_malformed_time():
    """Incident boundaries are derived from valid UTC input and bad input stays unavailable."""
    payload = run_json(
        r"""
$window = New-WpdIncidentWindow `
    -MarkerTimeUtc '2026-09-10T12:00:00Z' `
    -PreSeconds 60 `
    -PostSeconds 30
$invalid = New-WpdIncidentWindow `
    -MarkerTimeUtc 'not-a-timestamp' `
    -PreSeconds 60 `
    -PostSeconds 30
[pscustomobject]@{
    Status = $window.status
    Coverage = $window.coverage
    Start = $window.windowStartUtc
    End = $window.windowEndUtc
    Duration = $window.durationSeconds
    InvalidStatus = $invalid.status
    InvalidCoverage = $invalid.coverage
    InvalidReason = $invalid.reason
} | ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert payload == {
        "Status": "complete",
        "Coverage": "complete",
        "Start": "2026-09-10T11:59:00.0000000Z",
        "End": "2026-09-10T12:00:30.0000000Z",
        "Duration": 90,
        "InvalidStatus": "unavailable",
        "InvalidCoverage": "unavailable",
        "InvalidReason": "invalid-marker-time",
    }


def test_incident_window_membership_is_inclusive_and_unknown_for_bad_times():
    """Boundary events are retained as in-window; malformed values are unknown."""
    payload = run_json(
        r"""
$in = Test-WpdIncidentWindowMembership `
    -EventTime '2026-09-10T12:00:00Z' `
    -WindowStart '2026-09-10T12:00:00Z' `
    -WindowEnd '2026-09-10T12:00:30Z'
$out = Test-WpdIncidentWindowMembership `
    -EventTime '2026-09-10T12:00:31Z' `
    -WindowStart '2026-09-10T12:00:00Z' `
    -WindowEnd '2026-09-10T12:00:30Z'
$bad = Test-WpdIncidentWindowMembership `
    -EventTime 'not-a-time' `
    -WindowStart '2026-09-10T12:00:00Z' `
    -WindowEnd '2026-09-10T12:00:30Z'
[pscustomobject]@{ In = $in; Out = $out; Bad = $bad } | ConvertTo-Json -Depth 4 -Compress
"""
    )

    assert payload == {"In": "in-window", "Out": "out-of-window", "Bad": "unavailable"}


def test_sample_quality_counts_timestamp_gaps_and_malformed_rows():
    """Sample quality counts only finite timestamped readings and records gaps."""
    payload = run_json(
        r"""
$samples = @(
    [pscustomobject]@{ TimestampUtc = '2026-09-10T12:00:00Z'; Value = 10 }
    [pscustomobject]@{ TimestampUtc = '2026-09-10T12:00:01Z'; Value = $null }
    [pscustomobject]@{ TimestampUtc = '2026-09-10T12:00:03Z'; Value = 30 }
    [pscustomobject]@{ TimestampUtc = 'not-a-time'; Value = 40 }
)
$quality = Measure-WpdSampleQuality `
    -Samples $samples `
    -ValueProperty 'Value' `
    -ExpectedStartUtc '2026-09-10T12:00:00Z' `
    -ExpectedEndUtc '2026-09-10T12:00:03Z' `
    -IntervalSeconds 1
[pscustomobject]@{
    Status = $quality.status
    Coverage = $quality.coverage
    Expected = $quality.expectedSamples
    Observed = $quality.observedSamples
    Missing = $quality.missingSamples
    Gaps = $quality.gapCount
    Dropped = $quality.droppedCount
    InvalidTimes = $quality.invalidTimestampCount
    Usable = $quality.isUsable
    Reasons = @($quality.reasons)
} | ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert payload == {
        "Status": "partial",
        "Coverage": "partial",
        "Expected": 4,
        "Observed": 2,
        "Missing": 2,
        "Gaps": 2,
        "Dropped": 2,
        "InvalidTimes": 1,
        "Usable": True,
        "Reasons": ["sample-gap", "invalid-timestamp", "missing-value"],
    }


def test_coverage_state_distinguishes_complete_partial_and_missing_data():
    """Coverage is explicit and missing or unsupported data never becomes normal."""
    payload = run_json(
        r"""
$complete = Resolve-WpdCoverageState -Status 'success' -ExpectedSamples 3 -ObservedSamples 3 -GapCount 0
$partial = Resolve-WpdCoverageState -Status 'success' -ExpectedSamples 3 -ObservedSamples 2 -GapCount 1
$missing = Resolve-WpdCoverageState -Status 'success' -ExpectedSamples 3 -ObservedSamples 0 -GapCount 0
$notCollected = Resolve-WpdCoverageState -Status 'not-collected' -ExpectedSamples 3 -ObservedSamples 0 -GapCount 0
$unsupported = Resolve-WpdCoverageState -Status 'unsupported' -ExpectedSamples 3 -ObservedSamples 0 -GapCount 0
[pscustomobject]@{
    States = @(Get-WpdCoverageStates)
    Complete = $complete
    Partial = $partial
    Missing = $missing
    NotCollected = $notCollected
    Unsupported = $unsupported
} | ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert payload["States"] == [
        "complete",
        "partial",
        "unavailable",
        "not-collected",
        "unsupported",
    ]
    assert payload["Complete"] == "complete"
    assert payload["Partial"] == "partial"
    assert payload["Missing"] == "unavailable"
    assert payload["NotCollected"] == "not-collected"
    assert payload["Unsupported"] == "unsupported"


def test_collector_failure_result_preserves_errors_and_computes_duration():
    """Failure envelopes retain diagnostics and never look like a partial success."""
    payload = run_json(
        r"""
$result = New-WpdCollectorResult `
    -Collector 'disk' `
    -Status 'failed' `
    -Records @([pscustomobject]@{ Name = 'ignored-after-failure' }) `
    -Warnings @('counter gap') `
    -Errors @([pscustomobject]@{ Code = 'E_IO'; Message = 'provider failed' }) `
    -StartedUtc '2026-09-10T12:00:00Z' `
    -CompletedUtc '2026-09-10T12:00:01.500Z'
[pscustomobject]@{
    Status = $result.status
    Coverage = $result.coverage
    DurationMs = $result.durationMs
    DurationSnake = $result.duration_ms
    RecordCount = $result.recordCount
    Warning = @($result.warnings)[0]
    ErrorCode = @($result.errors)[0].Code
    ErrorMessage = @($result.errors)[0].Message
} | ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert payload == {
        "Status": "error",
        "Coverage": "unavailable",
        "DurationMs": 1500,
        "DurationSnake": 1500,
        "RecordCount": 1,
        "Warning": "counter gap",
        "ErrorCode": "E_IO",
        "ErrorMessage": "provider failed",
    }


def test_collector_result_downgrades_when_envelope_timestamps_are_malformed():
    """Usable records with an invalid collection window are partial, not complete."""
    payload = run_json(
        r"""
$result = New-WpdCollectorResult `
    -Collector 'cpu' `
    -Status 'success' `
    -Records @([pscustomobject]@{ Value = 42 }) `
    -StartedUtc 'not-a-time' `
    -CompletedUtc '2026-09-10T12:00:01Z'
[pscustomobject]@{
    Status = $result.status
    Coverage = $result.coverage
    RecordCount = $result.recordCount
    Start = $result.startedUtc
    End = $result.completedUtc
    Reason = $result.reason
} | ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert payload == {
        "Status": "partial",
        "Coverage": "partial",
        "RecordCount": 1,
        "Start": None,
        "End": "2026-09-10T12:00:01.0000000Z",
        "Reason": "invalid-window-time",
    }


def test_data_quality_records_account_for_gaps_and_null_only_series():
    """Quality records expose missing samples instead of treating gaps as zeros."""
    payload = run_json(
        r"""
$partial = New-WpdDataQualityRecord `
    -Collector 'cpu' `
    -ExpectedSamples 5 `
    -ObservedSamples 3 `
    -GapCount 2 `
    -DroppedCount 1 `
    -WindowStartUtc '2026-09-10T12:00:00Z' `
    -WindowEndUtc '2026-09-10T12:00:05Z' `
    -Reasons @('sample-gap')
$missing = New-WpdDataQualityRecord `
    -Collector 'memory' `
    -ExpectedSamples 5 `
    -ObservedSamples 0 `
    -GapCount 5
[pscustomobject]@{
    PartialStatus = $partial.status
    PartialCoverage = $partial.coverage
    PartialMissing = $partial.missingSamples
    PartialUsable = $partial.isUsable
    PartialGapCount = $partial.gapCount
    PartialDropped = $partial.droppedCount
    PartialReason = @($partial.reasons)[0]
    MissingStatus = $missing.status
    MissingCoverage = $missing.coverage
    MissingUsable = $missing.isUsable
    MissingSamples = $missing.missingSamples
} | ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert payload == {
        "PartialStatus": "partial",
        "PartialCoverage": "partial",
        "PartialMissing": 2,
        "PartialUsable": True,
        "PartialGapCount": 2,
        "PartialDropped": 1,
        "PartialReason": "sample-gap",
        "MissingStatus": "unavailable",
        "MissingCoverage": "unavailable",
        "MissingUsable": False,
        "MissingSamples": 5,
    }


def test_data_quality_summary_keeps_partial_collection_explicit():
    """An aggregate quality block reports counts and does not invent an all-clear state."""
    payload = run_json(
        r"""
$records = @(
    (New-WpdDataQualityRecord -Collector 'cpu' -Status 'success' -ExpectedSamples 2 -ObservedSamples 2)
    (New-WpdDataQualityRecord -Collector 'memory' -Status 'success' -ExpectedSamples 2 -ObservedSamples 1 -GapCount 1)
)
$summary = Get-WpdDataQualitySummary -Records $records
[pscustomobject]@{
    Status = $summary.status
    Coverage = $summary.coverage
    Total = $summary.totalCollectors
    Complete = $summary.completeCount
    Partial = $summary.partialCount
    Unavailable = $summary.unavailableCount
    Usable = $summary.usableCollectorCount
    Healthy = ($summary.status -eq 'healthy' -or $summary.coverage -eq 'healthy')
} | ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert payload == {
        "Status": "partial",
        "Coverage": "partial",
        "Total": 2,
        "Complete": 1,
        "Partial": 1,
        "Unavailable": 0,
        "Usable": 2,
        "Healthy": False,
    }


def test_uptime_info_uses_injected_boot_time_and_marks_missing_boot_time_unavailable():
    """Boot time is derived only from an available provider value."""
    payload = run_json(
        r"""
$available = Get-WpdUptimeInfo `
    -OperatingSystem ([pscustomobject]@{ LastBootUpTime = '2026-09-10T11:00:00Z' }) `
    -NowUtc '2026-09-10T12:00:00Z'
$missing = Get-WpdUptimeInfo `
    -OperatingSystem ([pscustomobject]@{}) `
    -NowUtc '2026-09-10T12:00:00Z'
[pscustomobject]@{
    Status = $available.status
    Coverage = $available.coverage
    Boot = $available.bootTimeUtc
    Uptime = $available.uptimeSeconds
    Source = $available.source
    MissingStatus = $missing.status
    MissingCoverage = $missing.coverage
    MissingBoot = $missing.bootTimeUtc
    MissingUptime = $missing.uptimeSeconds
    MissingReason = $missing.reason
} | ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert payload == {
        "Status": "complete",
        "Coverage": "complete",
        "Boot": "2026-09-10T11:00:00.0000000Z",
        "Uptime": 3600,
        "Source": "provider",
        "MissingStatus": "unavailable",
        "MissingCoverage": "unavailable",
        "MissingBoot": None,
        "MissingUptime": None,
        "MissingReason": "boot-time-unavailable",
    }


def test_evidence_record_carries_provenance_and_rejects_traversal_paths():
    """Evidence references are stable and cannot point outside the case tree."""
    payload = run_json(
        r"""
$one = New-WpdEvidenceRecord `
    -Artifact 'performance-samples.csv' `
    -Path 'telemetry/performance-samples.csv' `
    -Metric 'AverageCpuLoadPercent' `
    -Value 95 `
    -WindowStartUtc '2026-09-10T12:00:00Z' `
    -WindowEndUtc '2026-09-10T12:00:05Z' `
    -Collector 'cpu' `
    -Quality 'complete'
$two = New-WpdEvidenceRecord `
    -Artifact 'performance-samples.csv' `
    -Path 'telemetry/performance-samples.csv' `
    -Metric 'AverageCpuLoadPercent' `
    -Value 95 `
    -WindowStartUtc '2026-09-10T12:00:00Z' `
    -WindowEndUtc '2026-09-10T12:00:05Z' `
    -Collector 'cpu' `
    -Quality 'complete'
$bad = New-WpdEvidenceRecord `
    -Artifact 'secret.txt' `
    -Path '../secret.txt' `
    -Metric 'contents' `
    -Value 'should not escape'
[pscustomobject]@{
    Status = $one.status
    IdStable = ($one.id -eq $two.id)
    Artifact = $one.artifact
    Path = $one.path
    Metric = $one.metric
    Value = $one.value
    Start = $one.windowStartUtc
    End = $one.windowEndUtc
    Collector = $one.collector
    Quality = $one.quality
    BadStatus = $bad.status
    BadCoverage = $bad.coverage
    BadReason = $bad.reason
    BadPath = $bad.path
} | ConvertTo-Json -Depth 8 -Compress
"""
    )

    assert payload == {
        "Status": "complete",
        "IdStable": True,
        "Artifact": "performance-samples.csv",
        "Path": "telemetry/performance-samples.csv",
        "Metric": "AverageCpuLoadPercent",
        "Value": 95,
        "Start": "2026-09-10T12:00:00.0000000Z",
        "End": "2026-09-10T12:00:05.0000000Z",
        "Collector": "cpu",
        "Quality": "complete",
        "BadStatus": "unavailable",
        "BadCoverage": "unavailable",
        "BadReason": "unsafe-path",
        "BadPath": None,
    }


def test_privacy_helpers_hash_paths_and_remove_secret_fields():
    """Redacted records hide identities and commands while every level drops secrets."""
    payload = run_json(
        r"""
$record = [ordered]@{
    UserName = 'Alice'
    Path = 'C:\Users\Alice\secret.txt'
    CommandLine = 'tool.exe --token abc123'
    Token = 'abc123'
    Password = 'not-for-collection'
    ApiKey = 'api-key-value'
    ConnectionString = 'Server=db;Password=secret'
    SessionKey = 'session-key-value'
    Mailbox = 'mailbox-content'
    DocumentContent = 'document-content'
    BrowserHistory = 'history-entry'
    Nested = [ordered]@{ Path = 'C:\Users\Alice\nested.log'; Cookie = 'cookie-value' }
}
$redacted = Protect-WpdPrivacyRecord -Record $record -PrivacyLevel 'Redacted'
$standard = Protect-WpdPrivacyRecord -Record $record -PrivacyLevel 'Standard'
$full = Protect-WpdPrivacyRecord -Record $record -PrivacyLevel 'Full' -AllowFull
$fullDenied = $false
try {
    Protect-WpdPrivacyRecord -Record $record -PrivacyLevel 'Full' | Out-Null
}
catch {
    $fullDenied = $true
}
$redactedNames = @($redacted.PSObject.Properties.Name)
$standardNames = @($standard.PSObject.Properties.Name)
$fullNames = @($full.PSObject.Properties.Name)
[pscustomobject]@{
    RedactedPath = $redacted.Path
    RedactedPathStable = ($redacted.Path -eq (Protect-WpdPath -Path 'C:\Users\Alice\secret.txt' -PrivacyLevel 'Redacted'))
    RedactedUserHashed = ($redacted.UserName -like 'sha256:*')
    RedactedCommand = ($redactedNames -contains 'CommandLine')
    RedactedSecret = (($redactedNames -contains 'Token') -or ($redactedNames -contains 'Password'))
    RedactedNestedPathHashed = ($redacted.Nested.Path -like 'sha256:*')
    StandardPath = $standard.Path
    StandardCommand = ($standardNames -contains 'CommandLine')
    StandardSecret = (($standardNames -contains 'Token') -or ($standardNames -contains 'Password'))
    FullPath = $full.Path
    FullCommand = ($fullNames -contains 'CommandLine')
    FullSecret = (($fullNames -contains 'Token') -or ($fullNames -contains 'Password'))
    FullDeniedWithoutOptIn = $fullDenied
    StandardForbiddenSurvivors = @($standardNames | Where-Object { $_ -in @('ApiKey', 'ConnectionString', 'SessionKey', 'Mailbox', 'DocumentContent', 'BrowserHistory') }).Count
    FullForbiddenSurvivors = @($fullNames | Where-Object { $_ -in @('ApiKey', 'ConnectionString', 'SessionKey', 'Mailbox', 'DocumentContent', 'BrowserHistory') }).Count
    StandardLevel = Get-WpdPrivacyLevel -Level ''
} | ConvertTo-Json -Depth 8 -Compress
"""
    )

    assert payload["RedactedPath"].startswith("sha256:")
    assert len(payload["RedactedPath"]) == 71
    assert "Alice" not in payload["RedactedPath"]
    assert {
        "RedactedUserHashed": True,
        "RedactedCommand": False,
        "RedactedSecret": False,
        "RedactedNestedPathHashed": True,
        "StandardPath": "C:\\Users\\Alice\\secret.txt",
        "StandardCommand": True,
        "StandardSecret": False,
        "FullPath": "C:\\Users\\Alice\\secret.txt",
        "FullCommand": True,
        "FullSecret": False,
        "FullDeniedWithoutOptIn": True,
        "StandardForbiddenSurvivors": 0,
        "FullForbiddenSurvivors": 0,
        "StandardLevel": "Standard",
    }.items() <= payload.items()


def test_confidence_logic_is_an_enum_gated_by_coverage_and_sample_quality():
    """Confidence is stated text, not a numeric score or a missing-data claim."""
    payload = run_json(
        r"""
$high = Get-WpdConfidence -Coverage 'complete' -SampleCount 10 -MinimumSamples 3 -EvidenceCount 1
$medium = Get-WpdConfidence -Coverage 'partial' -SampleCount 10 -MinimumSamples 3 -EvidenceCount 1
$low = Get-WpdConfidence -Coverage 'unavailable' -SampleCount 0 -MinimumSamples 3 -EvidenceCount 0
$tooShort = Get-WpdConfidence -Coverage 'complete' -SampleCount 2 -MinimumSamples 3 -EvidenceCount 1
[pscustomobject]@{
    Values = @(Get-WpdConfidenceValues)
    High = $high
    Medium = $medium
    Low = $low
    TooShort = $tooShort
    Numeric = ($high -match '^\d')
} | ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert payload == {
        "Values": ["High", "Medium", "Low"],
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "TooShort": "Low",
        "Numeric": False,
    }
