"""Behavioral tests for the reliability event module (WHEA, WER, change timeline).

The tests import the real ``src/Wpd.Events.psm1`` module into ``pwsh`` and drive
every collector through an injected provider seam, so no Windows event log is
ever queried: the default provider table is only inspected (never executed) on a
non-Windows host.

Contract anchors: plan D7 (confidence enum, never a percentage), D11 (bounded
targeted collection), R2 (no data is never healthy, absence is not health),
R4 (advisory only, no remediation), R7 (no classification claimed from a source
that does not carry it).
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE = REPO_ROOT / "src" / "Wpd.Events.psm1"


def run_pwsh(body: str) -> str:
    """Import the real events module and execute a test body."""
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    assert shutil.which(powershell), f"{powershell} is required for the events gate"
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
    "ConvertTo-WpdEventRecord",
    "ConvertTo-WpdChangeEntry",
    "Get-WpdBootShutdownContext",
    "Get-WpdChangeTimeline",
    "Get-WpdEventConfidence",
    "Get-WpdEventCoverageStates",
    "Get-WpdEventMaximumEvents",
    "Get-WpdEventOutcomeValues",
    "Get-WpdEventFirstProperty",
    "Get-WpdEventObjectProperty",
    "Get-WpdEventProviderTable",
    "Get-WpdEventStatusValues",
    "Get-WpdWheaAnalysis",
    "Get-WpdWheaClassification",
    "Get-WpdWerAnalysis",
    "Group-WpdRepetitiveEvent",
    "Invoke-WpdEventQuery",
    "New-WpdEventProviderResult",
    "New-WpdEventQuery",
    "Resolve-WpdSymptomBoundary",
    "Test-WpdEventWindowMembership",
    "Test-WpdEventWindowsHost",
]


def test_module_imports_and_exports_the_event_surface():
    """The module loads on a non-Windows host without touching any provider and
    exports the documented vocabulary and query surface."""
    body = """
$exported = @((Get-Command -Module 'Wpd.Events' -CommandType Function).Name)
[pscustomobject]@{
    Loaded = $true
    Exported = $exported
    Count = $exported.Count
    WindowsHost = (Test-WpdEventWindowsHost)
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)
    exported = set(payload["Exported"])
    missing = sorted(set(REQUIRED_COMMANDS) - exported)
    assert missing == [], f"module does not export: {missing}"
    assert payload["Count"] == len(exported)


def test_coverage_and_status_vocabulary_forbids_healthy():
    """Event coverage reuses the shared coverage vocabulary and never offers a
    healthy verdict: a failed or empty query must stay unavailable."""
    body = """
[pscustomobject]@{
    Coverage = @(Get-WpdEventCoverageStates)
    Status = @(Get-WpdEventStatusValues)
    Outcomes = @(Get-WpdEventOutcomeValues)
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Coverage"] == [
        "complete",
        "partial",
        "unavailable",
        "not-collected",
        "unsupported",
    ]
    assert "healthy" not in payload["Coverage"]
    assert "healthy" not in payload["Status"]
    assert "healthy" not in payload["Outcomes"]
    assert payload["Outcomes"] == [
        "events-observed",
        "no-events-observed",
        "unavailable",
        "unsupported",
    ]


REQUIRED_PROFILES = [
    "applications",
    "change-history",
    "diagnostics-performance",
    "kernel-power",
    "whea",
]


def test_provider_table_documents_bounded_targets_without_any_write_api():
    """Every profile names a real log, at least one documented provider, at
    least one event id, its own elevation need and a read-only source; the
    reliability set the specification asks for is actually covered."""
    body = """
$table = @(Get-WpdEventProviderTable)
[pscustomobject]@{
    Names = @($table | ForEach-Object { $_.name })
    Rows = @($table | ForEach-Object {
        "{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f `
            $_.name, $_.logName, @($_.providers).Count, @($_.eventIds).Count, `
            $_.requiredElevation, $_.source, $_.windowsOnly
    })
    ProviderNames = @($table | ForEach-Object { @($_.providers) })
    ProfileProviders = @($table | ForEach-Object {
        "{0}|{1}" -f $_.name, (@($_.providers) -join ',')
    })
    DuplicateNames = @($table | Group-Object name | Where-Object { $_.Count -gt 1 }).Count
    NonIntegerIds = @($table | Where-Object {
            @($_.eventIds | Where-Object { $_ -isnot [int] }).Count -gt 0
        }).Count
    WriteCapableSource = @($table | Where-Object {
            $_.source -notmatch 'EventLogReader|Get-WinEvent'
        }).Count
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)
    providers = {}
    for entry in payload["ProfileProviders"]:
        name, joined = entry.split("|", 1)
        providers[name] = [part for part in joined.split(",") if part]

    assert sorted(payload["Names"]) == sorted(REQUIRED_PROFILES)
    assert payload["DuplicateNames"] == 0
    assert payload["NonIntegerIds"] == 0
    assert payload["WriteCapableSource"] == 0
    for row in payload["Rows"]:
        name, log_name, provider_count, id_count, elevation, source, windows_only = row.split("|")
        assert log_name, row
        assert int(provider_count) >= 1, row
        assert int(id_count) >= 1, row
        assert elevation in ("standard", "administrator"), row
        assert windows_only == "True", row
    # WHEA, Diagnostics-Performance and Kernel-Power must be real providers, and
    # the WHEA profile must target the WHEA logger rather than a filename hint.
    assert providers["whea"] == ["Microsoft-Windows-WHEA-Logger"]
    assert providers["diagnostics-performance"] == ["Microsoft-Windows-Diagnostics-Performance"]
    assert providers["kernel-power"] == ["Microsoft-Windows-Kernel-Power"]
    assert providers["applications"] == [
        "Application Error",
        "Application Hang",
        "Windows Error Reporting",
    ]
    # The change timeline is more than one provider, because a driver install, an
    # update and a software install are not the same event channel.
    change = providers["change-history"]
    assert "Microsoft-Windows-Kernel-PnP" in change
    assert "Microsoft-Windows-WindowsUpdateClient" in change
    assert "MsiInstaller" in change
    assert "Service Control Manager" in change
    assert "Microsoft-Windows-UserPnp" in change


def test_bounded_query_requires_an_explicit_window_and_a_bounded_count():
    """Targeted collection is bounded by construction: an explicit window, an
    explicit maximum event count inside the cap, and no default lookback."""
    body = """
$valid = New-WpdEventQuery -Profile 'whea' `
    -StartUtc '2026-09-01T00:00:00Z' -EndUtc '2026-09-10T00:00:00Z' -MaxEvents 200
$noWindow = New-WpdEventQuery -Profile 'whea' -MaxEvents 200
$backwards = New-WpdEventQuery -Profile 'whea' `
    -StartUtc '2026-09-10T00:00:00Z' -EndUtc '2026-09-01T00:00:00Z' -MaxEvents 200
$malformed = New-WpdEventQuery -Profile 'whea' `
    -StartUtc 'yesterday-ish' -EndUtc '2026-09-10T00:00:00Z' -MaxEvents 200
$tooMany = New-WpdEventQuery -Profile 'whea' `
    -StartUtc '2026-09-01T00:00:00Z' -EndUtc '2026-09-10T00:00:00Z' -MaxEvents 100000
$zero = New-WpdEventQuery -Profile 'whea' `
    -StartUtc '2026-09-01T00:00:00Z' -EndUtc '2026-09-10T00:00:00Z' -MaxEvents 0
$unknownThrew = $false
try { $null = New-WpdEventQuery -Profile 'not-a-profile' `
        -StartUtc '2026-09-01T00:00:00Z' -EndUtc '2026-09-10T00:00:00Z' -MaxEvents 10 }
catch { $unknownThrew = $true }
[pscustomobject]@{
    ValidStatus = $valid.status
    ValidLog = $valid.logName
    ValidMax = $valid.maxEvents
    ValidXPath = $valid.xpath
    ValidBounded = $valid.bounded
    ValidStart = $valid.windowStartUtc
    ValidEnd = $valid.windowEndUtc
    ValidProviders = @($valid.providers)
    ValidIds = @($valid.eventIds)
    NoWindowStatus = $noWindow.status
    NoWindowReason = $noWindow.reason
    BackwardsStatus = $backwards.status
    BackwardsReason = $backwards.reason
    MalformedStatus = $malformed.status
    MalformedReason = $malformed.reason
    TooManyStatus = $tooMany.status
    TooManyReason = $tooMany.reason
    TooManyMax = $tooMany.maxEvents
    ZeroStatus = $zero.status
    ZeroReason = $zero.reason
    UnknownThrew = $unknownThrew
    MaxCap = (Get-WpdEventMaximumEvents)
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["ValidStatus"] == "complete"
    assert payload["ValidLog"] == "System"
    assert payload["ValidMax"] == 200
    assert payload["ValidBounded"] is True
    assert "Microsoft-Windows-WHEA-Logger" in payload["ValidProviders"]
    assert payload["ValidStart"].startswith("2026-09-01T00:00:00")
    assert payload["ValidEnd"].startswith("2026-09-10T00:00:00")
    assert "TimeCreated" in payload["ValidXPath"]
    for key, reason in (
        ("NoWindow", "window-required"),
        ("Backwards", "window-end-before-start"),
        ("Malformed", "invalid-window-time"),
        ("TooMany", "max-events-above-cap"),
        ("Zero", "invalid-max-events"),
    ):
        assert payload[f"{key}Status"] == "unavailable", key
        assert payload[f"{key}Reason"] == reason, key
    # An over-cap request is refused, never silently clamped into a partial answer.
    assert payload["TooManyMax"] == payload["MaxCap"]
    assert payload["MaxCap"] == 2000
    assert payload["UnknownThrew"] is True


UNRENDERABLE_XML = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><Provider Name='nvlddmkm'/><EventID>13</EventID><Level>2</Level>"
    "<TimeCreated SystemTime='2026-09-10T09:00:00.0000000Z'/>"
    "<Computer>SYNTHETIC</Computer></System>"
    "<EventData><Data Name='DeviceName'>synthetic-gpu</Data>"
    "<Data Name='ResetCount'>3</Data></EventData></Event>"
)


def test_unrenderable_provider_keeps_raw_xml_and_is_never_silently_healthy():
    """A record whose provider cannot render its message keeps the raw XML, is
    still reported, is labelled partial and stays usable for correlation; a
    malformed XML payload and a malformed timestamp are labelled, never
    guessed and never dropped."""
    body = f"""
$unrenderable = [pscustomobject]@{{
    TimeCreated = '2026-09-10T09:00:00Z'
    ProviderName = 'nvlddmkm'
    Id = 13
    Level = 2
    LevelDisplayName = $null
    LogName = 'System'
    Message = $null
    RawXml = "{UNRENDERABLE_XML}"
}}
$nostructured = [pscustomobject]@{{
    TimeCreated = '2026-09-10T09:05:00Z'
    ProviderName = 'Mystery-Vendor-Provider'
    Id = 9001
    Level = 3
    LogName = 'System'
    Message = '[message text unavailable: The specified resource type cannot be found in the image file]'
    RawXml = $null
}}
$brokenXml = [pscustomobject]@{{
    TimeCreated = '2026-09-10T09:10:00Z'
    ProviderName = 'Broken-Xml-Provider'
    Id = 7
    Level = 4
    LogName = 'System'
    Message = $null
    RawXml = '<Event><EventData><Data Name='
}}
$badTime = [pscustomobject]@{{
    TimeCreated = 'not-a-timestamp'
    ProviderName = 'Microsoft-Windows-Kernel-Power'
    Id = 41
    Level = 1
    LevelName = 'Critical'
    LogName = 'System'
    Message = 'The system has rebooted without cleanly shutting down first.'
    RawXml = $null
}}
$a = ConvertTo-WpdEventRecord -Event $unrenderable
$b = ConvertTo-WpdEventRecord -Event $nostructured
$c = ConvertTo-WpdEventRecord -Event $brokenXml
$d = ConvertTo-WpdEventRecord -Event $badTime
$membership = Test-WpdEventWindowMembership -EventTime $d.timeCreatedUtc `
    -WindowStart '2026-09-10T00:00:00Z' -WindowEnd '2026-09-11T00:00:00Z'
[pscustomobject]@{{
    AProvider = $a.provider
    AId = $a.eventId
    ALevel = $a.level
    ALevelName = $a.levelName
    ATime = $a.timeCreatedUtc
    ATimeStatus = $a.timeStatus
    AMessageRendered = $a.messageRendered
    AMessageSource = $a.messageSource
    ARawXmlKept = ($a.rawXml -eq $unrenderable.RawXml)
    ARawXmlLength = $a.rawXml.Length
    AXmlStatus = $a.xmlStatus
    AEventDataDevice = $a.eventData['DeviceName']
    AEventDataResetCount = $a.eventData['ResetCount']
    AReasons = @($a.reasons)
    ACoverage = $a.coverage
    AUsable = $a.isUsable
    ASignature = $a.signature
    BMessageRendered = $b.messageRendered
    BMessageSource = $b.messageSource
    BXmlStatus = $b.xmlStatus
    BReasons = @($b.reasons)
    BCoverage = $b.coverage
    BUsable = $b.isUsable
    CRawXmlKept = ($c.rawXml -eq $brokenXml.RawXml)
    CXmlStatus = $c.xmlStatus
    CReasons = @($c.reasons)
    CCoverage = $c.coverage
    CUsable = $c.isUsable
    DTime = $d.timeCreatedUtc
    DTimeStatus = $d.timeStatus
    DMalformed = $d.malformedTime
    DReasons = @($d.reasons)
    DCoverage = $d.coverage
    DUsable = $d.isUsable
    DMembership = $membership
}} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    # Unrenderable provider: XML survives, metadata is readable, coverage is partial.
    assert payload["AProvider"] == "nvlddmkm"
    assert payload["AId"] == 13
    assert payload["ALevel"] == 2
    assert payload["ATime"].startswith("2026-09-10T09:00:00")
    assert payload["ATimeStatus"] == "complete"
    assert payload["AMessageRendered"] is False
    assert payload["AMessageSource"] == "xml-fallback"
    assert payload["ARawXmlKept"] is True
    assert payload["ARawXmlLength"] > 100
    assert payload["AXmlStatus"] == "complete"
    assert payload["AEventDataDevice"] == "synthetic-gpu"
    assert payload["AEventDataResetCount"] == "3"
    assert "message-not-rendered" in payload["AReasons"]
    assert payload["ACoverage"] == "partial"
    assert payload["AUsable"] is True
    assert payload["ASignature"].startswith("nvlddmkm|13|")

    # No structured data and no rendered text: still reported, still partial.
    assert payload["BMessageRendered"] is False
    assert payload["BMessageSource"] == "none"
    assert payload["BXmlStatus"] == "absent"
    assert "message-not-rendered" in payload["BReasons"]
    assert "no-structured-data" in payload["BReasons"]
    assert payload["BCoverage"] == "partial"
    assert payload["BUsable"] is True

    # Malformed XML keeps the raw payload and says so.
    assert payload["CRawXmlKept"] is True
    assert payload["CXmlStatus"] == "invalid"
    assert "invalid-event-xml" in payload["CReasons"]
    assert payload["CCoverage"] == "partial"
    assert payload["CUsable"] is True

    # Malformed timestamp: null time, explicit reason, unknown membership, kept.
    assert payload["DTime"] is None
    assert payload["DTimeStatus"] == "unavailable"
    assert payload["DMalformed"] is True
    assert "invalid-event-time" in payload["DReasons"]
    assert payload["DCoverage"] == "partial"
    assert payload["DUsable"] is True
    assert payload["DMembership"] == "unavailable"


def test_failed_query_is_unavailable_and_empty_query_is_not_healthy():
    """A query that fails, a query with no provider and a query that matched
    nothing are three different, stated answers - and none of them is health."""
    body = """
$query = New-WpdEventQuery -Profile 'whea' `
    -StartUtc '2026-09-01T00:00:00Z' -EndUtc '2026-09-10T00:00:00Z' -MaxEvents 200
$invalidQuery = New-WpdEventQuery -Profile 'whea' -MaxEvents 200

$thrown = Invoke-WpdEventQuery -Query $query -Collect {
    throw [System.UnauthorizedAccessException]::new('access is denied')
}
$refused = Invoke-WpdEventQuery -Query $query -Collect {
    New-WpdEventProviderResult -Status 'unavailable' -Reason 'access-denied' `
        -Items @() -Source 'EventLogReader System'
}
$unsupported = Invoke-WpdEventQuery -Query $query -Collect {
    New-WpdEventProviderResult -Status 'unsupported' -Reason 'log-not-present' `
        -Items @() -Source 'EventLogReader System'
}
$empty = Invoke-WpdEventQuery -Query $query -Collect { @() }
$noProvider = Invoke-WpdEventQuery -Query $query
$badQuery = Invoke-WpdEventQuery -Query $invalidQuery -Collect { @() }
$invalidStatusThrew = $false
try { $null = New-WpdEventProviderResult -Status 'healthy' -Items @() }
catch { $invalidStatusThrew = $true }

[pscustomobject]@{
    ThrownStatus = $thrown.status
    ThrownCoverage = $thrown.coverage
    ThrownOutcome = $thrown.outcome
    ThrownReason = $thrown.reason
    ThrownErrors = @($thrown.errors).Count
    ThrownCount = $thrown.recordCount
    ThrownHealthClaim = $thrown.healthClaim
    RefusedStatus = $refused.status
    RefusedCoverage = $refused.coverage
    RefusedOutcome = $refused.outcome
    RefusedReason = $refused.reason
    UnsupportedStatus = $unsupported.status
    UnsupportedCoverage = $unsupported.coverage
    UnsupportedOutcome = $unsupported.outcome
    EmptyStatus = $empty.status
    EmptyCoverage = $empty.coverage
    EmptyOutcome = $empty.outcome
    EmptyQuery = $empty.emptyQuery
    EmptyReason = $empty.reason
    EmptyHealthy = ($empty.status -eq 'healthy' -or $empty.coverage -eq 'healthy' -or $empty.healthClaim -eq 'healthy')
    EmptyInterpretation = $empty.interpretation
    NoProviderStatus = $noProvider.status
    NoProviderCoverage = $noProvider.coverage
    NoProviderOutcome = $noProvider.outcome
    NoProviderReason = $noProvider.reason
    BadQueryStatus = $badQuery.status
    BadQueryReason = $badQuery.reason
    InvalidStatusThrew = $invalidStatusThrew
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    # A provider exception is an error with unavailable coverage, never a pass.
    assert payload["ThrownStatus"] == "error"
    assert payload["ThrownCoverage"] == "unavailable"
    assert payload["ThrownOutcome"] == "unavailable"
    assert payload["ThrownReason"] == "provider-failed"
    assert payload["ThrownErrors"] == 1
    assert payload["ThrownCount"] == 0
    assert payload["ThrownHealthClaim"] == "none"

    # A provider that states its own refusal keeps that statement.
    assert payload["RefusedStatus"] == "unavailable"
    assert payload["RefusedCoverage"] == "unavailable"
    assert payload["RefusedOutcome"] == "unavailable"
    assert payload["RefusedReason"] == "access-denied"
    assert payload["UnsupportedStatus"] == "unsupported"
    assert payload["UnsupportedCoverage"] == "unsupported"
    assert payload["UnsupportedOutcome"] == "unsupported"

    # A successful query that matched nothing is 'no-events-observed' and is
    # explicitly not health.
    assert payload["EmptyStatus"] == "unavailable"
    assert payload["EmptyCoverage"] == "unavailable"
    assert payload["EmptyOutcome"] == "no-events-observed"
    assert payload["EmptyQuery"] is True
    assert payload["EmptyReason"] == "no-events-observed"
    assert payload["EmptyHealthy"] is False
    assert "not evidence of health" in payload["EmptyInterpretation"]

    # No provider registered is unsupported, and an invalid query never runs.
    assert payload["NoProviderStatus"] == "unsupported"
    assert payload["NoProviderCoverage"] == "unsupported"
    assert payload["NoProviderOutcome"] == "unsupported"
    assert payload["NoProviderReason"] == "provider-not-supplied"
    assert payload["BadQueryStatus"] == "unavailable"
    assert payload["BadQueryReason"] == "window-required"
    assert payload["InvalidStatusThrew"] is True


def test_query_envelope_labels_unrenderable_records_and_truncation():
    """Rendered and unrenderable records are counted separately, the provider
    sources are named, and reaching the bound is a stated partial - not a
    complete answer."""
    body = """
$query = New-WpdEventQuery -Profile 'whea' `
    -StartUtc '2026-09-01T00:00:00Z' -EndUtc '2026-09-10T00:00:00Z' -MaxEvents 200
$mixed = Invoke-WpdEventQuery -Query $query -Collect {
    @(
        [pscustomobject]@{
            TimeCreated = '2026-09-02T01:00:00Z'
            ProviderName = 'Microsoft-Windows-WHEA-Logger'
            Id = 17
            Level = 3
            LevelDisplayName = 'Warning'
            LogName = 'System'
            Message = 'A corrected hardware error has occurred.'
            RawXml = '<Event><EventData><Data Name="ErrorSource">Corrected Machine Check</Data></EventData></Event>'
        }
        [pscustomobject]@{
            TimeCreated = '2026-09-02T02:00:00Z'
            ProviderName = 'Microsoft-Windows-WHEA-Logger'
            Id = 17
            Level = 3
            LogName = 'System'
            Message = 'A corrected hardware error has occurred.'
            RawXml = $null
        }
        [pscustomobject]@{
            TimeCreated = '2026-09-02T03:00:00Z'
            ProviderName = 'vendor-provider'
            Id = 77
            Level = 2
            LogName = 'System'
            Message = $null
            RawXml = '<Event><EventData><Data Name="DeviceName">synthetic-nic</Data></EventData></Event>'
        }
    )
}
$cappedQuery = New-WpdEventQuery -Profile 'kernel-power' `
    -StartUtc '2026-09-01T00:00:00Z' -EndUtc '2026-09-10T00:00:00Z' -MaxEvents 2
$capped = Invoke-WpdEventQuery -Query $cappedQuery -Collect {
    @(
        [pscustomobject]@{ TimeCreated = '2026-09-02T01:00:00Z'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; LogName = 'System'; Message = 'rebooted without cleanly shutting down'; RawXml = $null }
        [pscustomobject]@{ TimeCreated = '2026-09-02T02:00:00Z'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; LogName = 'System'; Message = 'rebooted without cleanly shutting down'; RawXml = $null }
    )
}
[pscustomobject]@{
    MixedStatus = $mixed.status
    MixedCoverage = $mixed.coverage
    MixedOutcome = $mixed.outcome
    MixedCount = $mixed.recordCount
    MixedRendered = $mixed.renderedCount
    MixedUnrenderable = $mixed.unrenderableCount
    MixedMalformedTime = $mixed.malformedTimeCount
    MixedReasons = @($mixed.reasons)
    MixedProviders = @($mixed.providers)
    MixedLog = $mixed.logName
    MixedProfile = $mixed.profile
    MixedStart = $mixed.windowStartUtc
    MixedEnd = $mixed.windowEndUtc
    MixedWarnings = @($mixed.warnings)
    MixedNeverHealthy = $mixed.neverHealthy
    CappedStatus = $capped.status
    CappedCoverage = $capped.coverage
    CappedTruncated = $capped.truncated
    CappedReason = $capped.reason
    CappedMax = $capped.maxEvents
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["MixedStatus"] == "partial"
    assert payload["MixedCoverage"] == "partial"
    assert payload["MixedOutcome"] == "events-observed"
    assert payload["MixedCount"] == 3
    assert payload["MixedRendered"] == 2
    assert payload["MixedUnrenderable"] == 1
    assert payload["MixedMalformedTime"] == 0
    assert "unrenderable-records:1" in payload["MixedReasons"]
    assert payload["MixedProviders"] == ["Microsoft-Windows-WHEA-Logger", "vendor-provider"]
    assert payload["MixedLog"] == "System"
    assert payload["MixedProfile"] == "whea"
    assert payload["MixedStart"].startswith("2026-09-01T00:00:00")
    assert payload["MixedEnd"].startswith("2026-09-10T00:00:00")
    assert payload["MixedNeverHealthy"] is True
    assert payload["CappedStatus"] == "partial"
    assert payload["CappedCoverage"] == "partial"
    assert payload["CappedTruncated"] is True
    assert payload["CappedReason"] == "bounded-limit-reached"
    assert payload["CappedMax"] == 2


def test_repeated_wifi_resets_group_with_first_last_count_and_proximity():
    """Repetitive events are grouped by provider, id and a normalized signature:
    identical resets with different volatile values land in one group that
    carries first/last/count and the incident proximity, the out-of-window
    occurrences stay labelled, and a malformed timestamp is retained inside the
    group without ever being counted as in-window."""
    body = """
$events = @()
$minutes = @(-90, -20, -5, 0, 35)
foreach ($offset in $minutes) {
    $time = ([datetime]'2026-09-10T08:30:00Z').AddMinutes($offset)
    $events += [pscustomobject]@{
        TimeCreated = $time
        ProviderName = 'Microsoft-Windows-WLAN-AutoConfig'
        Id = 8003
        Level = 3
        LevelName = 'Warning'
        LogName = 'System'
        Message = ("The wireless adapter was reset. Reset sequence 00{0} completed at index 0x1A2B." -f [math]::Abs($offset))
        RawXml = $null
    }
}
$events += [pscustomobject]@{
    TimeCreated = '2026-09-10T08:40:00Z'
    ProviderName = 'Microsoft-Windows-Kernel-Power'
    Id = 42
    Level = 4
    LogName = 'System'
    Message = 'Entering sleep state.'
    RawXml = $null
}
$events += [pscustomobject]@{
    TimeCreated = '2026-09-10T08:45:00Z'
    ProviderName = 'Microsoft-Windows-WLAN-AutoConfig'
    Id = 8003
    Level = 2
    LogName = 'System'
    Message = 'The wireless adapter was reset after a fatal error.'
    RawXml = $null
}
$events += [pscustomobject]@{
    TimeCreated = 'not-a-timestamp'
    ProviderName = 'Microsoft-Windows-WLAN-AutoConfig'
    Id = 8003
    Level = 3
    LogName = 'System'
    Message = ("The wireless adapter was reset. Reset sequence 00{0} completed at index 0x1A2B." -f 9)
    RawXml = $null
}
$records = @($events | ForEach-Object { ConvertTo-WpdEventRecord -Event $_ -LogName 'System' -Profile 'whea' })
$groups = @(Group-WpdRepetitiveEvent -Records $records -WindowStart '2026-09-10T08:00:00Z' `
        -WindowEnd '2026-09-10T09:00:00Z' -MarkerUtc '2026-09-10T08:30:00Z' -MinimumCount 3)
$wifi = $groups | Where-Object { $_.eventId -eq 8003 -and $_.count -gt 1 }
$single = $groups | Where-Object { $_.eventId -eq 8003 -and $_.count -eq 1 }
$sleep = $groups | Where-Object { $_.provider -like '*Kernel-Power*' }
[pscustomobject]@{
    GroupCount = $groups.Count
    WifiCount = $wifi.count
    WifiRetained = @($wifi.records).Count
    WifiFirst = $wifi.firstUtc
    WifiLast = $wifi.lastUtc
    WifiSpan = $wifi.spanSeconds
    WifiInWindow = $wifi.inWindowCount
    WifiOutOfWindow = $wifi.outOfWindowCount
    WifiUnknownTime = $wifi.unknownTimeCount
    WifiRepetitive = $wifi.repetitive
    WifiClassification = $wifi.classification
    WifiPlacement = $wifi.placement
    WifiNearestMinutes = $wifi.nearestOccurrenceMinutes
    WifiNearestSide = $wifi.nearestOccurrenceSide
    WifiMedianInterval = $wifi.medianIntervalSeconds
    WifiOccurrences = @($wifi.occurrences).Count
    WifiCoverage = $wifi.coverage
    WifiReasons = @($wifi.reasons)
    WifiInterpretation = $wifi.interpretation
    WifiOutOccurrences = @($wifi.outOfWindowOccurrences)
    WifiSignature = $wifi.signature
    SingleCount = $single.count
    SingleClassification = $single.classification
    SingleRepetitive = $single.repetitive
    SingleFirst = $single.firstUtc
    SinglePlacement = $single.placement
    SleepCount = $sleep.count
    SleepClassification = $sleep.classification
    SleepRepetitive = $sleep.repetitive
    SleepPlacement = $sleep.placement
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    # Six 8003 records: five share a normalized signature (the volatile counter
    # and hex index normalize away) and the malformed-time record joins them
    # without being counted as an occurrence.
    assert payload["GroupCount"] == 3
    assert payload["WifiCount"] == 5
    assert payload["WifiRetained"] == 6
    assert payload["WifiFirst"].startswith("2026-09-10T07:00:00")
    assert payload["WifiLast"].startswith("2026-09-10T09:05:00")
    assert payload["WifiSpan"] == 7500
    # Inside the 08:00-09:00 window: 08:10, 08:25, 08:30. Outside: 07:00, 09:05.
    assert payload["WifiInWindow"] == 3
    assert payload["WifiOutOfWindow"] == 2
    assert payload["WifiUnknownTime"] == 1
    assert len(payload["WifiOutOccurrences"]) == 2
    assert payload["WifiRepetitive"] is True
    assert payload["WifiClassification"] == "repetitive"
    assert payload["WifiPlacement"] == "in-window"
    # The marker is 08:30, so the nearest occurrence is the 08:30 one.
    assert payload["WifiNearestMinutes"] == 0
    assert payload["WifiNearestSide"] == "at"
    # Intervals 300, 900, 2100, 4200 -> median 1500.
    assert payload["WifiMedianInterval"] == 1500
    assert payload["WifiOccurrences"] == 5
    assert payload["WifiCoverage"] == "partial"
    assert "invalid-event-time" in payload["WifiReasons"]
    assert "repeated" in payload["WifiInterpretation"].lower()
    assert payload["WifiSignature"].startswith("Microsoft-Windows-WLAN-AutoConfig|8003|")

    # A different 8003 message is a different fault signature: isolated, and the
    # single occurrence still carries its time and placement.
    assert payload["SingleCount"] == 1
    assert payload["SingleClassification"] == "isolated"
    assert payload["SingleRepetitive"] is False
    assert payload["SingleFirst"].startswith("2026-09-10T08:45:00")
    assert payload["SinglePlacement"] == "in-window"

    # A single occurrence of another provider is isolated, never repetitive.
    assert payload["SleepCount"] == 1
    assert payload["SleepClassification"] == "isolated"
    assert payload["SleepRepetitive"] is False
    assert payload["SleepPlacement"] == "in-window"


def test_whea_classification_never_guesses_and_absence_is_not_health():
    """A WHEA record is classified from what the record itself states. A record
    that does not state corrected or uncorrected is unclassified, never assumed
    corrected; and an empty WHEA result is a stated absence, not health."""
    body = """
$correctedText = ConvertTo-WpdEventRecord -Event ([pscustomobject]@{
        TimeCreated = '2026-09-10T09:00:00Z'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Id = 17
        Level = 3; LogName = 'System'; Message = 'A corrected hardware error has occurred.'
        RawXml = '<Event><EventData><Data Name="ErrorSource">Corrected Machine Check</Data></EventData></Event>'
    }) -LogName 'System' -Profile 'whea'
$fatalText = ConvertTo-WpdEventRecord -Event ([pscustomobject]@{
        TimeCreated = '2026-09-10T11:00:00Z'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Id = 1
        Level = 1; LogName = 'System'; Message = 'A fatal hardware error has occurred.'
        RawXml = $null
    }) -LogName 'System' -Profile 'whea'
$uncorrectedText = ConvertTo-WpdEventRecord -Event ([pscustomobject]@{
        TimeCreated = '2026-09-10T11:30:00Z'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Id = 17
        Level = 2; LogName = 'System'; Message = 'A fatal hardware error has occurred. An uncorrected hardware error was reported.'
        RawXml = $null
    }) -LogName 'System' -Profile 'whea'
$silent = ConvertTo-WpdEventRecord -Event ([pscustomobject]@{
        TimeCreated = '2026-09-10T12:00:00Z'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Id = 47
        Level = 2; LogName = 'System'; Message = $null
        RawXml = '<Event><EventData><Data Name="ErrorSource">PCI Express Root Port</Data><Data Name="ErrorRecordId">7</Data></EventData></Event>'
    }) -LogName 'System' -Profile 'whea'
$xmlCorrected = ConvertTo-WpdEventRecord -Event ([pscustomobject]@{
        TimeCreated = '2026-09-10T12:30:00Z'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Id = 17
        Level = 3; LogName = 'System'; Message = $null
        RawXml = '<Event><EventData><Data Name="ErrorSource">Corrected Machine Check</Data></EventData></Event>'
    }) -LogName 'System' -Profile 'whea'
[pscustomobject]@{
    CorrectedText = (Get-WpdWheaClassification -Record $correctedText).classification
    CorrectedMarker = (Get-WpdWheaClassification -Record $correctedText).classificationReason
    FatalText = (Get-WpdWheaClassification -Record $fatalText).classification
    FatalMarker = (Get-WpdWheaClassification -Record $fatalText).classificationReason
    UncorrectedText = (Get-WpdWheaClassification -Record $uncorrectedText).classification
    SilentRecord = (Get-WpdWheaClassification -Record $silent).classification
    SilentReason = (Get-WpdWheaClassification -Record $silent).classificationReason
    XmlCorrected = (Get-WpdWheaClassification -Record $xmlCorrected).classification
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["CorrectedText"] == "corrected"
    assert payload["CorrectedMarker"] == "record-states-corrected"
    assert payload["FatalText"] == "uncorrected"
    assert payload["FatalMarker"] == "record-states-uncorrected"
    # 'uncorrected' must win over the 'corrected' substring it contains.
    assert payload["UncorrectedText"] == "uncorrected"
    # A record that never states its class stays unclassified.
    assert payload["SilentRecord"] == "unclassified"
    assert payload["SilentReason"] == "classification-not-in-record"
    # Structured XML that does state the class is usable even without a message.
    assert payload["XmlCorrected"] == "corrected"


def test_whea_recurrence_separates_corrected_from_uncorrected_components():
    """Recurrence is per hardware component and states whether the repeat is
    corrected or uncorrected; an uncorrected record is never softened and an
    empty result is never presented as health."""
    body = """
$events = @(
    [pscustomobject]@{ TimeCreated = '2026-09-10T09:00:00Z'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Id = 17; Level = 3; LogName = 'System'
        Message = 'A corrected hardware error has occurred.'
        RawXml = '<Event><EventData><Data Name="ErrorSource">Corrected Machine Check</Data><Data Name="Component">PCI Express Root Port</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = '2026-09-10T10:00:00Z'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Id = 17; Level = 3; LogName = 'System'
        Message = 'A corrected hardware error has occurred.'
        RawXml = '<Event><EventData><Data Name="ErrorSource">Corrected Machine Check</Data><Data Name="Component">PCI Express Root Port</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = '2026-09-10T11:00:00Z'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Id = 1; Level = 1; LogName = 'System'
        Message = 'A fatal hardware error has occurred.'
        RawXml = '<Event><EventData><Data Name="ErrorSource">Machine Check Exception</Data><Data Name="ErrorRecordId">11</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = '2026-09-10T12:00:00Z'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Id = 47; Level = 2; LogName = 'System'
        Message = $null
        RawXml = '<Event><EventData><Data Name="ErrorSource">PCI Express Root Port</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = 'not-a-timestamp'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Id = 17; Level = 3; LogName = 'System'
        Message = 'A corrected hardware error has occurred.'
        RawXml = '<Event><EventData><Data Name="ErrorSource">Corrected Machine Check</Data></EventData></Event>' }
)
$records = @($events | ForEach-Object { ConvertTo-WpdEventRecord -Event $_ -LogName 'System' -Profile 'whea' })
$analysis = Get-WpdWheaAnalysis -Records $records -MarkerUtc '2026-09-10T11:00:00Z' `
    -WindowStart '2026-09-10T08:00:00Z' -WindowEnd '2026-09-10T13:00:00Z'
$empty = Get-WpdWheaAnalysis -Records @() -WindowStart '2026-09-10T08:00:00Z' -WindowEnd '2026-09-10T13:00:00Z'
[pscustomobject]@{
    Total = $analysis.recordCount
    Corrected = $analysis.correctedCount
    Uncorrected = $analysis.uncorrectedCount
    Unclassified = $analysis.unclassifiedCount
    UnknownTime = $analysis.unknownTimeCount
    Severity = $analysis.severity
    Coverage = $analysis.coverage
    Status = $analysis.status
    RecurringCount = $analysis.recurringComponentCount
    Components = @($analysis.components | ForEach-Object {
            "{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}" -f $_.component, $_.count, $_.correctedCount, $_.uncorrectedCount, `
                $_.unclassifiedCount, $_.recurrence, $_.classification, $_.uncorrectedRecurrence
        })
    UncorrectedKeys = @($analysis.uncorrectedComponents)
    AbsenceIsNotHealth = $analysis.absenceIsNotHealth
    CausationDisclaimed = $analysis.causationDisclaimed
    CorrelationNotice = $analysis.correlationNotice
    Conclusion = $analysis.conclusion
    Reasons = @($analysis.reasons)
    EmptySeverity = $empty.severity
    EmptyCoverage = $empty.coverage
    EmptyInterpretation = $empty.interpretation
    EmptyIsNotHealth = $empty.absenceIsNotHealth
    EmptyNeverHealthy = ($empty.severity -eq 'healthy' -or $empty.coverage -eq 'healthy')
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Total"] == 5
    assert payload["Corrected"] == 3
    assert payload["Uncorrected"] == 1
    assert payload["Unclassified"] == 1
    assert payload["UnknownTime"] == 1
    assert payload["Severity"] == "uncorrected-present"
    assert payload["Coverage"] == "partial"
    assert payload["Status"] == "partial"
    assert payload["RecurringCount"] == 1
    components = {}
    for row in payload["Components"]:
        fields = row.split("|")
        components[fields[0]] = fields
    # Corrected Machine Check repeats three times including the unparsable one.
    assert components["Corrected Machine Check"][1] == "3"
    assert components["Corrected Machine Check"][2] == "3"
    assert components["Corrected Machine Check"][5] == "recurring"
    assert components["Corrected Machine Check"][6] == "corrected"
    # Machine Check Exception is a single uncorrected event.
    assert components["Machine Check Exception"][1] == "1"
    assert components["Machine Check Exception"][3] == "1"
    assert components["Machine Check Exception"][5] == "none"
    assert components["Machine Check Exception"][6] == "uncorrected"
    assert components["Machine Check Exception"][7] == "False"
    # PCI Express Root Port could not be classified, and says so.
    assert components["PCI Express Root Port"][4] == "1"
    assert components["PCI Express Root Port"][6] == "unclassified"
    assert payload["UncorrectedKeys"] == ["Machine Check Exception"]
    assert payload["AbsenceIsNotHealth"] is True
    assert payload["CausationDisclaimed"] is True
    assert "causation" in payload["CorrelationNotice"].lower()
    assert "not" in payload["CorrelationNotice"].lower()
    assert "unclassified" in payload["Reasons"]

    # Absence of WHEA records is a stated empty observation, never health.
    assert payload["EmptySeverity"] == "no-events"
    assert payload["EmptyCoverage"] == "unavailable"
    assert payload["EmptyIsNotHealth"] is True
    assert payload["EmptyNeverHealthy"] is False
    assert "absence" in payload["EmptyInterpretation"].lower()
    assert "not evidence of health" in payload["EmptyInterpretation"]


def test_wer_reports_crashes_hangs_and_live_kernel_metadata():
    """WER records are grouped into application crashes, application hangs and
    LiveKernelEvent reports with their bucket/signature metadata; a record whose
    message cannot be rendered is retained, never silently classified."""
    body = """
$crashMessage = @'
Faulting application name: synthapp.exe, version: 1.2.3.4, time stamp: 0x5f2a1b3c
Faulting module name: synthlib.dll, version: 9.8.7.6, time stamp: 0x11223344
Exception code: 0xc0000005
Fault offset: 0x00001234
Faulting process id: 0x1234
Faulting application path: C:\\Program Files\\Synth\\synthapp.exe
Faulting module path: C:\\Windows\\System32\\synthlib.dll
Report Id: 11111111-2222-3333-4444-555555555555
'@
$messageOnly = 'Faulting application name: synthmsg.exe, version: 4.5.6.7, time stamp: 0x00aa11bb
Faulting module name: msgmod.dll, version: 1.0.0.1, time stamp: 0x00cc22dd
Exception code: 0xc0000409
Fault offset: 0x00009999
Report Id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
$hangMessage = 'The program synchung.exe version 3.3.3.3 stopped interacting with Windows and was closed.'
$werXml = '<Event><EventData><Data Name="Bucket">bucket-livekernel-1</Data><Data Name="EventName">LiveKernelEvent</Data><Data Name="AppName">nvlddmkm</Data></EventData></Event>'
$werAppcrashXml = '<Event><EventData><Data Name="Bucket">bucket-appcrash-9</Data><Data Name="EventName">APPCRASH</Data><Data Name="AppName">synthapp.exe</Data></EventData></Event>'
$werSilentXml = '<Event><EventData><Data Name="Bucket">bucket-unknown-3</Data><Data Name="AppName">mystery.exe</Data></EventData></Event>'
$events = @(
    [pscustomobject]@{ TimeCreated = '2026-09-10T09:00:00Z'; ProviderName = 'Application Error'; Id = 1000; Level = 2; LogName = 'Application'
        Message = $crashMessage
        RawXml = '<Event><EventData><Data Name="AppName">synthapp.exe</Data><Data Name="AppVersion">1.2.3.4</Data><Data Name="ModuleName">synthlib.dll</Data><Data Name="ModuleVersion">9.8.7.6</Data><Data Name="ExceptionCode">0xc0000005</Data><Data Name="FaultOffset">0x00001234</Data><Data Name="ReportId">11111111-2222-3333-4444-555555555555</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = '2026-09-10T09:30:00Z'; ProviderName = 'Application Error'; Id = 1000; Level = 2; LogName = 'Application'
        Message = $crashMessage
        RawXml = '<Event><EventData><Data Name="AppName">synthapp.exe</Data><Data Name="AppVersion">1.2.3.4</Data><Data Name="ModuleName">synthlib.dll</Data><Data Name="ModuleVersion">9.8.7.6</Data><Data Name="ExceptionCode">0xc0000005</Data><Data Name="FaultOffset">0x00001234</Data><Data Name="ReportId">99999999-2222-3333-4444-555555555555</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = '2026-09-10T09:45:00Z'; ProviderName = 'Application Error'; Id = 1000; Level = 2; LogName = 'Application'
        Message = $messageOnly
        RawXml = $null }
    [pscustomobject]@{ TimeCreated = '2026-09-10T10:00:00Z'; ProviderName = 'Application Hang'; Id = 1002; Level = 2; LogName = 'Application'
        Message = $hangMessage
        RawXml = '<Event><EventData><Data Name="AppName">synchung.exe</Data><Data Name="AppVersion">3.3.3.3</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = '2026-09-10T10:10:00Z'; ProviderName = 'Windows Error Reporting'; Id = 1001; Level = 4; LogName = 'Application'
        Message = 'Fault bucket LKD_0x141_Tdr, type 0'
        RawXml = $werXml }
    [pscustomobject]@{ TimeCreated = '2026-09-10T10:20:00Z'; ProviderName = 'Windows Error Reporting'; Id = 1001; Level = 4; LogName = 'Application'
        Message = 'Fault bucket , type 0'
        RawXml = $werAppcrashXml }
    [pscustomobject]@{ TimeCreated = '2026-09-10T10:30:00Z'; ProviderName = 'Windows Error Reporting'; Id = 1001; Level = 4; LogName = 'Application'
        Message = $null
        RawXml = $werSilentXml }
)
$records = @($events | ForEach-Object { ConvertTo-WpdEventRecord -Event $_ -LogName 'Application' -Profile 'applications' })
$analysis = Get-WpdWerAnalysis -Records $records -WindowStart '2026-09-10T08:00:00Z' -WindowEnd '2026-09-10T11:00:00Z'
$empty = Get-WpdWerAnalysis -Records @() -WindowStart '2026-09-10T08:00:00Z' -WindowEnd '2026-09-10T11:00:00Z'
[pscustomobject]@{
    CrashCount = $analysis.crashCount
    CrashGroups = @($analysis.crashes).Count
    Hangs = $analysis.hangCount
    LiveKernel = $analysis.liveKernelEventCount
    WerReports = $analysis.werReportCount
    BlueScreen = $analysis.blueScreenCount
    AppCrash = $analysis.appCrashCount
    Unclassified = $analysis.unclassifiedCount
    Coverage = $analysis.coverage
    Status = $analysis.status
    Reasons = @($analysis.reasons)
    CrashRows = @($analysis.crashes | ForEach-Object {
            "{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}" -f $_.application, $_.applicationVersion, $_.module, `
                $_.moduleVersion, $_.exceptionCode, $_.count, $_.firstUtc, $_.lastUtc, @($_.reportIds).Count
        })
    HangRows = @($analysis.hangs | ForEach-Object { "{0}|{1}|{2}" -f $_.application, $_.applicationVersion, $_.count })
    LiveRows = @($analysis.liveKernelEvents | ForEach-Object { "{0}|{1}|{2}|{3}" -f $_.eventName, $_.bucket, $_.count, $_.firstUtc })
    UnclassifiedRecords = @($analysis.unclassifiedRecords).Count
    UnclassifiedKeptXml = @($analysis.unclassifiedRecords)[0].rawXml.Length -gt 10
    CorrelationNotice = $analysis.correlationNotice
    CausationDisclaimed = $analysis.causationDisclaimed
    Interpretation = $analysis.interpretation
    EmptyCoverage = $empty.coverage
    EmptyInterpretation = $empty.interpretation
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    # Three Application Error records collapse into two application signatures.
    assert payload["CrashCount"] == 3
    assert payload["CrashGroups"] == 2
    crashes = {}
    for row in payload["CrashRows"]:
        fields = row.split("|")
        crashes[fields[0]] = fields
    # The two identical crashes group with first/last and both report ids.
    assert crashes["synthapp.exe"][1] == "1.2.3.4"
    assert crashes["synthapp.exe"][2] == "synthlib.dll"
    assert crashes["synthapp.exe"][3] == "9.8.7.6"
    assert crashes["synthapp.exe"][4].lower() == "0xc0000005"
    assert crashes["synthapp.exe"][5] == "2"
    assert crashes["synthapp.exe"][6].startswith("2026-09-10T09:00:00")
    assert crashes["synthapp.exe"][7].startswith("2026-09-10T09:30:00")
    assert crashes["synthapp.exe"][8] == "2"
    # A record without structured data is parsed from its message text.
    assert crashes["synthmsg.exe"][2] == "msgmod.dll"
    assert crashes["synthmsg.exe"][4].lower() == "0xc0000409"

    assert payload["Hangs"] == 1
    assert payload["HangRows"] == ["synchung.exe|3.3.3.3|1"]

    # WER reports are classified by the report the record states, and the
    # LiveKernelEvent report keeps its bucket and device name.
    assert payload["WerReports"] == 3
    assert payload["LiveKernel"] == 1
    assert payload["AppCrash"] == 1
    assert payload["LiveRows"] == ["LiveKernelEvent|bucket-livekernel-1|1|2026-09-10T10:10:00.0000000Z"]

    # The report that states no event name is unclassified, retained with its raw
    # XML, and the analysis states its own partial coverage.
    assert payload["Unclassified"] == 1
    assert payload["UnclassifiedRecords"] == 1
    assert payload["UnclassifiedKeptXml"] is True
    assert payload["Coverage"] == "partial"
    assert payload["Status"] == "partial"
    assert "unclassified-records:1" in payload["Reasons"]
    assert payload["CausationDisclaimed"] is True
    assert "not causation" in payload["CorrelationNotice"].lower()

    # An empty WER result is a stated absence, not health.
    assert payload["EmptyCoverage"] == "unavailable"
    assert "not evidence of health" in payload["EmptyInterpretation"]


def test_boot_and_power_context_separates_correlation_from_causation():
    """Diagnostics-Performance boot/shutdown cost is reported with the component
    the record names, and Kernel-Power 41 is only called bugcheck-correlated when
    a bugcheck record is actually adjacent to it."""
    body = """
$events = @(
    [pscustomobject]@{ TimeCreated = '2026-09-10T07:00:00Z'; ProviderName = 'Microsoft-Windows-Diagnostics-Performance'; Id = 100; Level = 4
        LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'
        Message = 'Boot performance monitoring.'
        RawXml = '<Event><EventData><Data Name="BootTime">184000</Data><Data Name="Degradation">43000</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = '2026-09-10T07:00:05Z'; ProviderName = 'Microsoft-Windows-Diagnostics-Performance'; Id = 101; Level = 3
        LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'
        Message = 'This boot took longer than expected. Driver: synthnic.sys contributed to the delay.'
        RawXml = '<Event><EventData><Data Name="Degradation">12000</Data><Data Name="Name">synthnic.sys</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = '2026-09-10T07:10:00Z'; ProviderName = 'Microsoft-Windows-Diagnostics-Performance'; Id = 200; Level = 4
        LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'
        Message = 'Shutdown performance monitoring.'
        RawXml = '<Event><EventData><Data Name="ShutdownTime">25000</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = '2026-09-10T12:00:00Z'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; Level = 1
        LogName = 'System'
        Message = 'The system has rebooted without cleanly shutting down first.'
        RawXml = '<Event><EventData><Data Name="BugcheckCode">0</Data><Data Name="PowerButtonTimestamp">0</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = '2026-09-10T15:00:00Z'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; Level = 1
        LogName = 'System'
        Message = 'The system has rebooted without cleanly shutting down first.'
        RawXml = '<Event><EventData><Data Name="BugcheckCode">0</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = 'not-a-timestamp'; ProviderName = 'Microsoft-Windows-Diagnostics-Performance'; Id = 100; Level = 4
        LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'
        Message = 'Boot performance monitoring.'
        RawXml = '<Event><EventData><Data Name="BootTime">300000</Data><Data Name="Degradation">90000</Data></EventData></Event>' }
)
$records = @($events | ForEach-Object { ConvertTo-WpdEventRecord -Event $_ -LogName $_.LogName -Profile 'diagnostics-performance' })
$crash = ConvertTo-WpdEventRecord -Event ([pscustomobject]@{
        TimeCreated = '2026-09-10T12:02:00Z'; ProviderName = 'BugCheck'; Id = 1001; Level = 1; LogName = 'System'
        Message = 'The computer has rebooted from a bugcheck. Bugcheck 0x0000009F.'
        RawXml = '<Event><EventData><Data Name="BugcheckCode">159</Data></EventData></Event>'
    }) -LogName 'System' -Profile 'whea'
$context = Get-WpdBootShutdownContext -Records $records -CrashRecords @($crash) `
    -WindowStart '2026-09-10T00:00:00Z' -WindowEnd '2026-09-11T00:00:00Z'
$empty = Get-WpdBootShutdownContext -Records @() -WindowStart '2026-09-10T00:00:00Z' -WindowEnd '2026-09-11T00:00:00Z'
[pscustomobject]@{
    BootCount = $context.bootCount
    BootRows = @($context.boots | ForEach-Object {
            "{0}|{1}|{2}|{3}|{4}|{5}" -f $_.eventId, $_.bootTimeMs, $_.degradationMs, $_.componentName, $_.componentKind, $_.timeUtc
        })
    Slowest = $context.slowestBootMs
    Median = $context.medianBootMs
    DegradedCount = $context.degradedBootCount
    UnknownTime = $context.unknownTimeCount
    ShutdownCount = $context.shutdownCount
    ShutdownMs = @($context.shutdowns)[0].shutdownTimeMs
    PowerRows = @($context.powerEvents | ForEach-Object {
            "{0}|{1}|{2}|{3}|{4}" -f $_.eventId, $_.classification, $_.isUnexpectedShutdown, $_.bugcheckCode, $_.correlationStatus
        })
    Unexplained = $context.unexplainedShutdownCount
    Correlated = $context.bugcheckCorrelatedCount
    Coverage = $context.coverage
    Status = $context.status
    Reasons = @($context.reasons)
    CorrelationNotice = $context.correlationNotice
    CausationDisclaimed = $context.causationDisclaimed
    Interpretation = $context.interpretation
    EmptyCoverage = $empty.coverage
    EmptyInterpretation = $empty.interpretation
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["BootCount"] == 2
    boots = {}
    for row in payload["BootRows"]:
        fields = row.split("|")
        boots[fields[0]] = fields
    assert boots["100"][1] == "184000"
    assert boots["100"][2] == "43000"
    assert boots["100"][5].startswith("2026-09-10T07:00:00")
    assert boots["101"][2] == "12000"
    assert boots["101"][3] == "synthnic.sys"
    assert boots["101"][4] == "driver"
    # The unparsable record is retained but excluded from the trend maths.
    assert payload["Slowest"] == 184000
    assert payload["Median"] == 184000
    assert payload["DegradedCount"] == 2
    assert payload["UnknownTime"] == 1
    assert payload["Coverage"] == "partial"
    assert payload["Status"] == "partial"

    assert payload["ShutdownCount"] == 1
    assert payload["ShutdownMs"] == 25000

    power = {}
    for row in payload["PowerRows"]:
        fields = row.split("|")
        power[fields[1]] = fields
    # The 41 with no adjacent bugcheck is unexplained; the one two minutes from a
    # bugcheck record is correlated - and that is a correlation, not a cause.
    assert power["unexplained-shutdown"][1] == "unexplained-shutdown"
    assert power["unexplained-shutdown"][2] == "True"
    assert power["unexplained-shutdown"][4] == "no-crash-record-nearby"
    assert power["bugcheck-correlated"][2] == "False"
    assert power["bugcheck-correlated"][3].lower() == "0x0000009f"
    assert power["bugcheck-correlated"][4] == "crash-record-within-window"
    assert payload["Unexplained"] == 1
    assert payload["Correlated"] == 1
    assert payload["CausationDisclaimed"] is True
    assert "not causation" in payload["CorrelationNotice"].lower()

    assert payload["EmptyCoverage"] == "unavailable"
    assert "not evidence of health" in payload["EmptyInterpretation"]


def test_change_timeline_places_changes_around_the_symptom_date_boundary():
    """The driver/update/software/service change timeline is ordered around the
    symptom date with an explicit pre/on/post phase, an unparsable change is kept
    but never placed at an invented time, and proximity carries a correlation
    notice and a stated confidence instead of a causal claim."""
    body = """
$boundary = Resolve-WpdSymptomBoundary -SymptomDate '2026-09-10' -PreDays 7 -PostDays 2
$badBoundary = Resolve-WpdSymptomBoundary -SymptomDate 'not-a-date' -PreDays 7 -PostDays 2
$events = @(
    [pscustomobject]@{ TimeCreated = '2026-09-07T10:00:00Z'; ProviderName = 'Microsoft-Windows-Kernel-PnP'; Id = 410; Level = 4; LogName = 'System'
        Message = 'The device driver synthnic.sys was installed and started.'
        RawXml = '<Event><EventData><Data Name="DriverName">synthnic.sys</Data><Data Name="DriverVersion">3.1.0.7</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = '2026-09-09T22:00:00Z'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 19; Level = 4; LogName = 'System'
        Message = 'Installation Successful: Windows successfully installed the following update: 2026-09 Cumulative Update (KB5000001).'
        RawXml = '<Event><EventData><Data Name="updateTitle">2026-09 Cumulative Update (KB5000001)</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = '2026-09-10T08:00:00Z'; ProviderName = 'MsiInstaller'; Id = 11707; Level = 4; LogName = 'Application'
        Message = 'Product: Synthetic Agent -- Installation completed successfully.'
        RawXml = '<Event><EventData><Data Name="ProductName">Synthetic Agent</Data><Data Name="ProductVersion">5.0.1</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = '2026-09-11T09:00:00Z'; ProviderName = 'Service Control Manager'; Id = 7045; Level = 4; LogName = 'System'
        Message = 'A service was installed in the system: SyntheticService'
        RawXml = '<Event><EventData><Data Name="ServiceName">SyntheticService</Data><Data Name="ServiceFileName">C:\\Program Files\\Synth\\synthsvc.exe</Data></EventData></Event>' }
    [pscustomobject]@{ TimeCreated = 'not-a-timestamp'; ProviderName = 'Microsoft-Windows-Kernel-PnP'; Id = 410; Level = 4; LogName = 'System'
        Message = 'The device driver synthold.sys was installed and started.'
        RawXml = '<Event><EventData><Data Name="DriverName">synthold.sys</Data></EventData></Event>' }
)
$records = @($events | ForEach-Object { ConvertTo-WpdEventRecord -Event $_ -LogName $_.LogName -Profile 'change-history' })
$timeline = Get-WpdChangeTimeline -Records $records -Boundary $boundary
$empty = Get-WpdChangeTimeline -Records @() -Boundary $boundary
[pscustomobject]@{
    BoundaryStatus = $boundary.status
    BoundaryStart = $boundary.windowStartUtc
    BoundaryEnd = $boundary.windowEndUtc
    BoundarySymptom = $boundary.symptomDateUtc
    BoundaryPreDays = $boundary.preDays
    BoundaryPostDays = $boundary.postDays
    BoundaryInclusive = $boundary.boundaryInclusive
    BadBoundaryStatus = $badBoundary.status
    BadBoundaryReason = $badBoundary.reason
    EntryCount = @($timeline.entries).Count
    Order = @($timeline.entries | ForEach-Object { "{0}|{1}|{2}|{3}|{4}|{5}" -f $_.kind, $_.name, $_.phase, $_.side, $_.offsetFromSymptomSeconds, $_.confidence })
    DriverCount = $timeline.driverCount
    UpdateCount = $timeline.updateCount
    SoftwareCount = $timeline.softwareCount
    ServiceCount = $timeline.serviceCount
    PreSymptom = $timeline.preSymptomCount
    OnBoundary = $timeline.onSymptomDateCount
    PostSymptom = $timeline.postSymptomCount
    UnknownTime = $timeline.unknownTimeCount
    NearestBefore = @($timeline.nearestPreSymptomChanges | ForEach-Object { "{0}|{1}" -f $_.kind, $_.name })
    WithinWindow = @($timeline.entries | Where-Object { $_.withinWindow }).Count
    Coverage = $timeline.coverage
    Status = $timeline.status
    Reasons = @($timeline.reasons)
    CorrelationNotice = $timeline.correlationNotice
    CausationDisclaimed = $timeline.causationDisclaimed
    Limitations = @($timeline.entries)[0].limitations
    EmptyCoverage = $empty.coverage
    EmptyInterpretation = $empty.interpretation
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    # The symptom date is a boundary, not a point: a 7-day pre window and a
    # 2-day post window around 2026-09-10.
    assert payload["BoundaryStatus"] == "complete"
    assert payload["BoundaryStart"].startswith("2026-09-03T00:00:00")
    assert payload["BoundaryEnd"].startswith("2026-09-12T23:59:59")
    assert payload["BoundarySymptom"].startswith("2026-09-10T00:00:00")
    assert payload["BoundaryPreDays"] == 7
    assert payload["BoundaryPostDays"] == 2
    assert payload["BoundaryInclusive"] is True
    assert payload["BadBoundaryStatus"] == "unavailable"
    assert payload["BadBoundaryReason"] == "invalid-symptom-date"

    assert payload["EntryCount"] == 5
    order = [row.split("|") for row in payload["Order"]]
    kinds = [row[0] for row in order]
    assert kinds[:4] == ["driver", "update", "software", "service"]
    # The unparsable change is kept, is last, and has no invented time.
    assert kinds[4] == "driver"
    assert order[4][2] == "unknown"
    assert order[4][4] == ""
    assert payload["UnknownTime"] == 1

    # Phases and offsets are anchored on the symptom date.
    assert order[0][2] == "pre-symptom"
    assert order[0][3] == "before"
    assert int(order[0][4]) < 0
    assert order[2][2] == "on-symptom-date"
    assert order[3][2] == "post-symptom"
    assert order[3][3] == "after"
    assert int(order[3][4]) > 0
    assert payload["PreSymptom"] == 2
    assert payload["OnBoundary"] == 1
    assert payload["PostSymptom"] == 1
    # Four placed changes are inside the boundary; the unparsable one cannot be
    # claimed as inside a window at all.
    assert payload["WithinWindow"] == 4

    # Counts by change kind, and the changes nearest before the symptom date,
    # nearest first: the update is 2 hours before it, the driver 2.6 days.
    assert payload["DriverCount"] == 2
    assert payload["UpdateCount"] == 1
    assert payload["SoftwareCount"] == 1
    assert payload["ServiceCount"] == 1
    assert payload["NearestBefore"] == [
        "update|2026-09 Cumulative Update (KB5000001)",
        "driver|synthnic.sys",
    ]

    # Proximity is a correlation with stated confidence, never a cause.
    assert order[0][5] == "High"
    assert order[4][5] == "Low"
    assert payload["CausationDisclaimed"] is True
    assert "correlation is not causation" in payload["CorrelationNotice"].lower()
    assert any("not" in line.lower() for line in payload["Limitations"])

    assert payload["Coverage"] == "partial"
    assert payload["Status"] == "partial"
    assert "invalid-event-time" in payload["Reasons"]
    assert payload["EmptyCoverage"] == "unavailable"
    assert "not evidence of health" in payload["EmptyInterpretation"]
