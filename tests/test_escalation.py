"""Behavioral tests for the optional Tier 3 escalation adapters.

The module is imported into pwsh and every external command/provider is
injected. Linux runs therefore exercise parsing, consent, command construction,
cleanup, and descriptor contracts without invoking Windows tools.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE = REPO_ROOT / "src" / "Wpd.Escalation.psm1"


def run_pwsh(body: str) -> str:
    """Import the real escalation module and execute a PowerShell body."""
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    if not shutil.which(powershell):
        pytest.skip(f"{powershell} is required for the escalation gate")
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
    "ConvertFrom-WpdFltmcFilterOutput",
    "ConvertFrom-WpdFltmcInstanceOutput",
    "ConvertFrom-WpdPoolMonOutput",
    "Get-WpdDeepEscalationDescriptors",
    "Get-WpdEscalationDescriptors",
    "Get-WpdSearchContext",
    "Get-WpdWaitChainAnalysis",
    "Invoke-WpdDefenderPerformanceCapture",
    "Invoke-WpdMinifilterEscalation",
    "Invoke-WpdPoolEscalation",
    "Invoke-WpdProcDump",
    "Invoke-WpdWaitChain",
    "New-WpdAudioTracingDescriptor",
    "New-WpdGpuTracingDescriptor",
    "New-WpdHandleTracingDescriptor",
    "New-WpdHeapTracingDescriptor",
    "New-WpdResidentMemoryTracingDescriptor",
    "New-WpdUiTracingDescriptor",
    "New-WpdVirtualAllocTracingDescriptor",
    "Test-WpdEscalationCommandPresence",
]


def test_module_imports_without_windows_calls_and_exports_the_escalation_surface():
    body = """
$exported = @((Get-Command -Module 'Wpd.Escalation' -CommandType Function).Name)
[pscustomobject]@{ Exported = $exported; Count = $exported.Count } |
    ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)
    exported = set(payload["Exported"])
    missing = sorted(set(REQUIRED_COMMANDS) - exported)
    assert missing == [], f"module does not export: {missing}"
    assert payload["Count"] == len(exported)


def test_descriptors_cover_all_optional_escalations_and_have_safe_defaults():
    body = """
$descriptors = @(Get-WpdEscalationDescriptors)
$deep = @(Get-WpdDeepEscalationDescriptors)
[pscustomobject]@{
    Ids = @($descriptors | ForEach-Object { $_.id })
    DeepIds = @($deep | ForEach-Object { $_.id })
    InvalidTier = @($descriptors | Where-Object { $_.tier -ne 3 }).Count
    MissingConsent = @($descriptors | Where-Object { $_.consentRequired -ne $true }).Count
    UnsafeRemediation = @($descriptors | Where-Object { $_.automaticRemediation -ne $false }).Count
    MissingCleanup = @($descriptors | Where-Object { $null -eq $_.cleanup }).Count
    Uncollected = @($descriptors | Where-Object { $_.status -ne 'not-collected' }).Count
    Recommendations = @($descriptors | ForEach-Object { @($_.recommendations).Count } | Measure-Object -Sum).Sum
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)
    expected = {
        "wct",
        "procdump",
        "pool",
        "defender",
        "search",
        "minifilter",
        "heap",
        "virtualalloc",
        "resident-memory",
        "handles",
        "gpu",
        "audio",
        "ui",
    }
    assert set(payload["Ids"]) == expected
    assert {"heap", "virtualalloc", "resident-memory", "handles", "gpu", "audio", "ui"}.issubset(
        set(payload["DeepIds"])
    )
    assert payload["InvalidTier"] == 0
    assert payload["MissingConsent"] == 0
    assert payload["UnsafeRemediation"] == 0
    assert payload["MissingCleanup"] == 0
    assert payload["Uncollected"] == 0
    assert payload["Recommendations"] == 0


def test_consent_refusal_does_not_call_runners_or_create_output(tmp_path):
    output = str(tmp_path / "refused").replace("'", "''")
    body = f"""
$script:calls = 0
$runner = {{ param($name, $arguments) $script:calls++ }}
$wct = Invoke-WpdWaitChain -Consent:$false -ChainProvider {{ $script:calls++ }}
$dump = Invoke-WpdProcDump -ProcessId 1234 -OutputDirectory '{output}' -Consent:$false `
    -CommandTable @{{ 'procdump.exe' = $true }} -CommandRunner $runner
$pool = Invoke-WpdPoolEscalation -OutputDirectory '{output}' -Consent:$false `
    -CommandTable @{{ 'poolmon.exe' = $true }} -CommandRunner $runner
$defender = Invoke-WpdDefenderPerformanceCapture -OutputDirectory '{output}' -Consent:$false `
    -ModuleAvailable:$true -CommandTable @{{ 'New-MpPerformanceRecording' = $true }} -CommandRunner $runner
[pscustomobject]@{{
    Calls = $script:calls
    Statuses = @($wct.status, $dump.status, $pool.status, $defender.status)
    Exists = Test-Path -LiteralPath '{output}'
}} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)
    assert payload["Calls"] == 0
    assert payload["Statuses"] == ["not-collected"] * 4
    assert payload["Exists"] is False


def test_procdump_is_unavailable_when_not_present_and_never_downloads_or_defaults_to_full():
    body = """
$script:calls = 0
$runner = { param($name, $arguments) $script:calls++ }
$result = Invoke-WpdProcDump -ProcessId 4321 -OutputDirectory $env:TEMP `
    -Consent -CommandTable @{} -CommandRunner $runner
[pscustomobject]@{
    Status = $result.status
    Reason = $result.reason
    Calls = $script:calls
    Arguments = @($result.arguments)
    HasDownload = (($result | ConvertTo-Json -Depth 8) -match 'download|Install-Module|Invoke-WebRequest')
    HasFullDump = (($result | ConvertTo-Json -Depth 8) -match '(^|[^A-Za-z])-ma([^A-Za-z]|$)')
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)
    assert payload["Status"] == "unavailable"
    assert payload["Reason"] == "tool-not-found"
    assert payload["Calls"] == 0
    assert payload["Arguments"] == []
    assert payload["HasDownload"] is False
    assert payload["HasFullDump"] is False


def test_procdump_uses_mm_and_bounded_single_capture_through_injected_runner(tmp_path):
    output = str(tmp_path).replace("'", "''")
    body = f"""
$script:calls = @()
$runner = {{
    param($name, $arguments)
    $script:calls += [pscustomobject]@{{ Name = $name; Arguments = @($arguments) }}
    Set-Content -LiteralPath $arguments[-1] -Value 'synthetic mini dump' -Encoding Ascii
    return [pscustomobject]@{{ ExitCode = 0; Output = 'captured' }}
}}
$result = Invoke-WpdProcDump -ProcessId 4321 -OutputDirectory '{output}' -Consent `
    -EnableProcDump -CommandTable @{{ 'procdump.exe' = $true }} -CommandRunner $runner
[pscustomobject]@{{
    Status = $result.status
    Tool = $result.tool
    Arguments = @($script:calls[0].Arguments)
    OutputName = $result.artifactName
    ArtifactExists = Test-Path -LiteralPath $result.artifactPath
    FullFlag = @($script:calls[0].Arguments) -contains '-ma'
    MiniFlag = @($script:calls[0].Arguments) -contains '-mm'
    CountFlag = @($script:calls[0].Arguments) -contains '-n'
}} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)
    assert payload["Status"] == "success"
    assert payload["Tool"] == "procdump.exe"
    assert payload["MiniFlag"] is True
    assert payload["FullFlag"] is False
    assert payload["CountFlag"] is True
    assert "4321" in payload["Arguments"]
    assert payload["ArtifactExists"] is True
    assert payload["OutputName"].endswith(".dmp")


def test_wait_chain_analysis_is_point_in_time_and_detects_cycles():
    body = """
$chains = @(
    [pscustomobject]@{
        ProcessId = 100
        ThreadId = 10
        Nodes = @(
            [pscustomobject]@{ Type = 'Thread'; Id = 10; OwnerThreadId = 20; ObjectName = 'mutex-a'; Status = 'Blocked' }
            [pscustomobject]@{ Type = 'Thread'; Id = 20; OwnerThreadId = 10; ObjectName = 'mutex-b'; Status = 'Blocked' }
        )
    },
    [pscustomobject]@{
        ProcessId = 200
        ThreadId = 30
        Nodes = @(
            [pscustomobject]@{ Type = 'Thread'; Id = 30; OwnerThreadId = 0; ObjectName = 'event-a'; Status = 'Ready' }
        )
    }
)
$result = Get-WpdWaitChainAnalysis -Chains $chains
[pscustomobject]@{
    Status = $result.status
    PointInTime = $result.pointInTime
    ChainCount = @($result.chains).Count
    CycleCount = @($result.cycles).Count
    CycleThreads = @($result.cycles[0].threadIds)
    Limitation = $result.limitations[0]
} | ConvertTo-Json -Depth 10 -Compress
"""
    payload = run_pwsh_json(body)
    assert payload["Status"] == "success"
    assert payload["PointInTime"] is True
    assert payload["ChainCount"] == 2
    assert payload["CycleCount"] == 1
    assert set(payload["CycleThreads"]) == {10, 20}
    assert "listed synchronization" in payload["Limitation"]


def test_poolmon_parser_preserves_tags_and_sorts_targeted_growth_without_gflags():
    body = r"""
$lines = @(
    ' Tag     Allocs    Frees    Diff    Bytes      Per Alloc',
    ' ----    --------  -------  ------  ---------  ---------',
    ' File       1200      400     800    819200       1024',
    ' DrvA        900      100     800    409600        512',
    ' Zero          1        1       0         0          0'
)
$rows = @(ConvertFrom-WpdPoolMonOutput -Lines $lines)
[pscustomobject]@{
    Count = $rows.Count
    FirstTag = $rows[0].tag
    FirstDiff = $rows[0].difference
    FirstBytes = $rows[0].bytes
    Tags = @($rows | ForEach-Object { $_.tag })
    HasGflags = (($rows | ConvertTo-Json -Depth 8) -match 'gflags|Enable Pool Tagging')
    Descriptor = New-WpdPoolEscalationDescriptor -PoolTag 'File'
} | ConvertTo-Json -Depth 10 -Compress
"""
    payload = run_pwsh_json(body)
    assert payload["Count"] == 3
    assert payload["FirstTag"] == "File"
    assert payload["FirstDiff"] == 800
    assert payload["FirstBytes"] == 819200
    assert payload["Tags"] == ["File", "DrvA", "Zero"]
    assert payload["HasGflags"] is False
    assert payload["Descriptor"]["poolTag"] == "File"
    assert payload["Descriptor"]["legacyGflagsAction"] == "not-collected"


def test_defender_adapter_uses_documented_cmdlets_raw_report_and_cleans_failure(tmp_path):
    output = str(tmp_path).replace("'", "''")
    body = f"""
$script:calls = @()
$runner = {{
    param($name, $arguments)
    $script:calls += [pscustomobject]@{{ Name = $name; Arguments = @($arguments) }}
    if ($name -eq 'New-MpPerformanceRecording') {{
        Set-Content -LiteralPath $arguments[1] -Value 'partial' -Encoding Ascii
        return [pscustomobject]@{{ ExitCode = 0 }}
    }}
    return [pscustomobject]@{{ ExitCode = 7; Error = 'synthetic report failure' }}
}}
$result = Invoke-WpdDefenderPerformanceCapture -OutputDirectory '{output}' -Consent `
    -ModuleAvailable:$true -CommandTable @{{
        'New-MpPerformanceRecording' = $true
        'Get-MpPerformanceReport' = $true
    }} -CommandRunner $runner
[pscustomobject]@{{
    Status = $result.status
    Cleanup = $result.cleanup.status
    RecordingCall = @($script:calls | Where-Object {{ $_.Name -eq 'New-MpPerformanceRecording' }} | ForEach-Object {{ $_.Arguments }})
    ReportCall = @($script:calls | Where-Object {{ $_.Name -eq 'Get-MpPerformanceReport' }} | ForEach-Object {{ $_.Arguments }})
    RecordingStillExists = Test-Path -LiteralPath $result.recordingPath
    HasRaw = @($script:calls | Where-Object Name -eq 'Get-MpPerformanceReport')[0].Arguments -contains '-Raw'
}} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)
    assert payload["Status"] == "error"
    assert payload["Cleanup"] == "removed"
    assert payload["RecordingStillExists"] is False
    assert payload["RecordingCall"][0] == "-RecordTo"
    assert payload["ReportCall"][0] == "-Path"
    assert payload["HasRaw"] is True


def test_fltmc_parsers_and_minifilter_adapter_order_by_altitude():
    body = r"""
$filterLines = @(
    'Filter Name                     Num Instances    Altitude    Frame',
    '------------------------------  -------------  ---------  -----',
    'WdFilter                                  8       328010.5      0',
    'bindflt                                   1       409800         0',
    'LegacyFilter                              1       320000         0'
)
$instanceLines = @(
    'Filter                Volume Name                             Altitude        Instance Name',
    '--------------------  -------------------------------------  -------------  -------------',
    'WdFilter              C:                                      328010.5        WdFilter Instance',
    'bindflt               C:                                      409800          bindflt Instance'
)
$script:calls = @()
$runner = {
    param($name, $arguments)
    $script:calls += [pscustomobject]@{ Name = $name; Arguments = @($arguments) }
    if ($arguments -contains 'filters') { return $filterLines }
    return $instanceLines
}
$filters = @(ConvertFrom-WpdFltmcFilterOutput -Lines $filterLines)
$instances = @(ConvertFrom-WpdFltmcInstanceOutput -Lines $instanceLines)
$result = Invoke-WpdMinifilterEscalation -Consent -CommandTable @{
'fltmc.exe' = $true
} -CommandRunner $runner
[pscustomobject]@{
    FilterCount = $filters.Count
    FilterOrder = @($filters | ForEach-Object { $_.name })
    FirstAltitude = $filters[0].altitude
    InstanceCount = $instances.Count
    FirstVolume = $instances[0].volume
    Status = $result.status
    Calls = @($script:calls | ForEach-Object { "$($_.Name)|$($_.Arguments -join ',')" })
    ResultOrder = @($result.filters | ForEach-Object { $_.name })
} | ConvertTo-Json -Depth 10 -Compress
"""
    payload = run_pwsh_json(body)
    assert payload["FilterCount"] == 3
    assert payload["FilterOrder"] == ["LegacyFilter", "WdFilter", "bindflt"]
    assert payload["FirstAltitude"] == "320000"
    assert payload["InstanceCount"] == 2
    assert payload["FirstVolume"] == "C:"
    assert payload["Status"] == "success"
    assert payload["Calls"] == ["fltmc.exe|filters", "fltmc.exe|instances"]
    assert payload["ResultOrder"] == ["LegacyFilter", "WdFilter", "bindflt"]


def test_search_context_is_injected_and_reports_status_strings_and_index_counts():
    body = r"""
$service = { return [pscustomobject]@{ Status = 'Running'; StartType = 'Automatic'; Name = 'WSearch' } }
$index = { return [pscustomobject]@{
    Status = 'Indexing speed is reduced because of user activity'
    IndexedItems = 420000
    IndexPath = 'C:\ProgramData\Microsoft\Search\Data'
} }
$result = Get-WpdSearchContext -Consent -ServiceProvider $service -IndexProvider $index
[pscustomobject]@{
    Status = $result.status
    ServiceStatus = $result.service.status
    IndexStatus = $result.index.status
    IndexedItems = $result.index.indexedItems
    HasRawPath = (($result | ConvertTo-Json -Depth 8) -match 'ProgramData')
    RepairActions = @($result.recommendations).Count
} | ConvertTo-Json -Depth 10 -Compress
"""
    payload = run_pwsh_json(body)
    assert payload["Status"] == "success"
    assert payload["ServiceStatus"] == "Running"
    assert payload["IndexStatus"].startswith("Indexing speed")
    assert payload["IndexedItems"] == 420000
    assert payload["HasRawPath"] is False
    assert payload["RepairActions"] == 0


def test_deep_tracing_descriptors_are_analysis_only_and_do_not_claim_execution():
    body = """
$items = @(
    (New-WpdHeapTracingDescriptor),
    (New-WpdVirtualAllocTracingDescriptor),
    (New-WpdResidentMemoryTracingDescriptor),
    (New-WpdHandleTracingDescriptor),
    (New-WpdGpuTracingDescriptor),
    (New-WpdAudioTracingDescriptor),
    (New-WpdUiTracingDescriptor)
)
$commandText = @($items | ForEach-Object { @($_.commands); @($_.recommendations) }) -join '|'
[pscustomobject]@{
    Ids = @($items | ForEach-Object { $_.id })
    AllDescriptor = @($items | Where-Object { $_.status -eq 'not-collected' -and $_.mode -eq 'descriptor' }).Count
    AllConsent = @($items | Where-Object { $_.consentRequired -eq $true }).Count
    AllNoRemediation = @($items | Where-Object { $_.automaticRemediation -eq $false }).Count
    MissingQuestions = @($items | Where-Object { [string]::IsNullOrWhiteSpace($_.analysisQuestion) }).Count
    MissingEvidence = @($items | Where-Object { @($_.evidenceSignals).Count -eq 0 }).Count
    CommandText = $commandText
    HasWriteCommand = ($commandText -match 'Add-MpPreference|Set-|Remove-|Enable-|Disable-')
} | ConvertTo-Json -Depth 10 -Compress
"""
    payload = run_pwsh_json(body)
    assert payload["Ids"] == [
        "heap",
        "virtualalloc",
        "resident-memory",
        "handles",
        "gpu",
        "audio",
        "ui",
    ]
    assert payload["AllDescriptor"] == 7
    assert payload["AllConsent"] == 7
    assert payload["AllNoRemediation"] == 7
    assert payload["MissingQuestions"] == 0
    assert payload["MissingEvidence"] == 0
    assert payload["HasWriteCommand"] is False
