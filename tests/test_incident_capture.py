"""Behavioral regression tests for the incident-capture surface (v1.0).

Every test here exercises real PowerShell logic extracted from the collector by
AST, so a change to the collector that breaks the behavior fails these tests
instead of silently passing a source-regex check.

Covers the defects reported from the field run:
- network-state.json serialized to 555 MB because hosts entries were MatchInfo
  objects (not strings);
- the WPR trace window did not cover the counter window, so the trace could not
  explain the sampled pressure;
- commit charge was reported without per-process attribution;
- UDP exhaustion was invisible in a TCP-only network view;
- there was no way to mark the slowdown, so a fixed interval was captured
  instead of the incident;
- drive letters were not tied to a physical disk or the pagefile host.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "src" / "Invoke-WindowsPerformanceDiagnostics.ps1"

# Helper functions the functions under test depend on.
SUPPORT_FUNCTIONS = ["Get-SafeObjectProperty", "Get-CaseJsonProperty"]


def run_pwsh(body: str, functions: list[str]) -> str:
    """Extract `functions` from the collector by AST and run `body` against them."""
    assert shutil.which("pwsh"), "pwsh is required for the Linux verification gate"
    names = ", ".join(f"'{name}'" for name in functions)
    harness = f"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$null)
foreach ($name in @({names})) {{
    $found = @($ast.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }}, $true))
    if ($found.Count -eq 0) {{ throw "function $name not found in the collector" }}
    Invoke-Expression $found[0].Extent.Text
}}
$script:collectionErrors = New-Object System.Collections.ArrayList
function Add-CollectionError {{ param($Stage, $ErrorRecord) [void]$script:collectionErrors.Add([pscustomobject]@{{ Stage = $Stage; Message = $ErrorRecord.Exception.Message }}) }}
function Add-CollectionErrorText {{ param($Stage, $Message) [void]$script:collectionErrors.Add([pscustomobject]@{{ Stage = $Stage; Message = $Message }}) }}
Set-StrictMode -Version Latest
{body}
"""
    result = subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-Command", harness],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, f"pwsh failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    return result.stdout


def test_hosts_entries_are_plain_strings_even_for_matchinfo_style_inputs():
    """network-state.json ballooned to 555 MB because each hosts 'entry' was a
    MatchInfo object (PSProvider + reflection + assemblies + defined types).
    Entries must be flattened to plain strings."""
    body = r"""
$lines = @(
    '# Copyright (c) 1993-2009 Microsoft Corp.',
    '',
    '127.0.0.1       localhost',
    [pscustomobject]@{
        Line = '10.0.0.5    fileserver.corp.local'
        LineNumber = 4
        Filename = 'C:\Windows\System32\drivers\etc\hosts'
        PSProvider = 'Microsoft.PowerShell.Core\FileSystem'
        Context = [pscustomobject]@{ PreContext = @(); PostContext = @() }
        Matches = [System.Collections.ArrayList]::new()
    },
    '   ',
    '#comment only'
)
$entries = ConvertTo-HostsEntryLines -Lines $lines
$types = @($entries | ForEach-Object { $_.GetType().FullName } | Sort-Object -Unique)
$json = ($entries | ConvertTo-Json -Depth 6 -Compress)
[pscustomobject]@{
    Count = @($entries).Count
    Entries = @($entries)
    Types = @($types)
    JsonLength = $json.Length
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = json.loads(run_pwsh(body, ["ConvertTo-HostsEntryLines"] + SUPPORT_FUNCTIONS))

    assert payload["Count"] == 2
    assert payload["Entries"] == ["127.0.0.1       localhost", "10.0.0.5    fileserver.corp.local"]
    # every element is a real string, never a provider-backed object
    assert payload["Types"] == ["System.String"]
    # a hosts file must never serialize into a large document again
    assert payload["JsonLength"] < 500


def test_udp_endpoint_sample_groups_endpoints_by_owning_process():
    """The reported machine warned about UDP-port exhaustion while the tool only
    captured TCP connections. UDP endpoints must be counted per process."""
    netstat_text = [
        "Active Connections",
        "",
        "  Proto  Local Address          Foreign Address        State           PID",
        "  TCP    127.0.0.1:8080         0.0.0.0:0              LISTENING       4",
        "",
        "  Proto  Local Address          Foreign Address        State           PID",
        "  UDP    0.0.0.0:500            *:*                    1234",
        "  UDP    0.0.0.0:4500           *:*                    1234",
        "  UDP    0.0.0.0:5353           *:*                    5678",
        "  UDP    0.0.0.0:1900           *:*                    1234",
        "  UDP    [::]:3702              *:*                    9012",
    ]
    body = r"""
$stdin = Get-Content -LiteralPath $env:WPD_TEST_NETSTAT -Raw
$lines = @($stdin -split "`r?`n")
$sample = Get-UdpEndpointSample -NetstatOutput $lines
[pscustomobject]@{
    Total = $sample.TotalUdpEndpoints
    ByProcess = @($sample.EndpointsByProcess)
    HasTimestamp = ($null -ne $sample.TimestampUtc)
} | ConvertTo-Json -Depth 6 -Compress
"""
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.write("\n".join(netstat_text))
        netstat_path = handle.name

    assert shutil.which("pwsh")
    names = ", ".join(f"'{name}'" for name in ["Get-UdpEndpointSample"] + SUPPORT_FUNCTIONS)
    harness = f"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$null)
foreach ($name in @({names})) {{
    $found = @($ast.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }}, $true))
    Invoke-Expression $found[0].Extent.Text
}}
function Get-UtcTimestamp {{ return '2026-09-10T16:35:00.0000000Z' }}
Set-StrictMode -Version Latest
$env:WPD_TEST_NETSTAT = '{netstat_path}'
{body}
"""
    result = subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-Command", harness],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)

    # TCP rows must NOT be counted as UDP endpoints
    assert payload["Total"] == 5
    by_process = {row["OwningProcess"]: row["EndpointCount"] for row in payload["ByProcess"]}
    assert by_process == {1234: 3, 5678: 1, 9012: 1}
    # highest endpoint count first - the leaking process is the headline
    assert payload["ByProcess"][0]["OwningProcess"] == 1234
    assert payload["HasTimestamp"] is True


def test_marker_retention_keeps_the_window_around_the_marked_incident():
    """Without a marker the whole series is kept; with a marker only
    MarkerPreSeconds before and MarkerPostSeconds after survive, and the number
    of dropped samples is reported rather than silently discarded."""
    body = r"""
$base = [datetime]::Parse('2026-09-10T16:30:00Z').ToUniversalTime()
$samples = @()
for ($i = 0; $i -lt 180; $i++) {
    $samples += [pscustomobject]@{
        TimestampUtc = $base.AddSeconds($i).ToString('o')
        AverageCpuLoadPercent = $i
    }
}
$marker = $base.AddSeconds(120)   # mark at 16:32:00
$retained = Select-MarkerRetainedSeries -Samples $samples -MarkerTimeUtc $marker -MarkerPreSeconds 60 -MarkerPostSeconds 30
$noMarker = Select-MarkerRetainedSeries -Samples $samples -MarkerTimeUtc $null -MarkerPreSeconds 60 -MarkerPostSeconds 30
[pscustomobject]@{
    KeptCount = $retained.RetainedSampleCount
    DroppedCount = $retained.DroppedSampleCount
    MarkerApplied = $retained.MarkerApplied
    WindowStart = $retained.IncidentWindowStartUtc.ToString('o')
    WindowEnd = $retained.IncidentWindowEndUtc.ToString('o')
    FirstKept = @($retained.Series)[0].TimestampUtc
    LastKept = @($retained.Series)[-1].TimestampUtc
    NoMarkerCount = $noMarker.RetainedSampleCount
    NoMarkerDropped = $noMarker.DroppedSampleCount
    NoMarkerApplied = $noMarker.MarkerApplied
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = json.loads(run_pwsh(body, ["Select-MarkerRetainedSeries"] + SUPPORT_FUNCTIONS))

    # 60s before + 30s after, inclusive of both endpoints => 91 one-second samples
    assert payload["KeptCount"] == 91
    assert payload["DroppedCount"] == 180 - 91
    assert payload["MarkerApplied"] is True
    assert payload["WindowStart"] == "2026-09-10T16:31:00.0000000Z"
    assert payload["WindowEnd"] == "2026-09-10T16:32:30.0000000Z"
    assert payload["FirstKept"].startswith("2026-09-10T16:31:00")
    assert payload["LastKept"].startswith("2026-09-10T16:32:30")
    # unmarked runs keep everything (backwards compatible)
    assert payload["NoMarkerCount"] == 180
    assert payload["NoMarkerDropped"] == 0
    assert payload["NoMarkerApplied"] is False


def test_capture_window_coverage_flags_a_trace_that_starts_after_the_counters():
    """The reported defect: counters ended 16:35, WPR started 16:37, so the trace
    could not explain the pressure. The coverage check must name that case."""
    body = r"""
function New-Window($start, $end) {
    return [pscustomobject]@{ startedAtUtc = $start; completedAtUtc = $end }
}
$counters = New-Window '2026-09-10T16:30:00Z' '2026-09-10T16:35:00Z'

$good = Test-CaptureWindowCoverage -CaptureWindow $counters -WprStartUtc '2026-09-10T16:29:50Z' -WprStopUtc '2026-09-10T16:35:20Z'
$late = Test-CaptureWindowCoverage -CaptureWindow $counters -WprStartUtc '2026-09-10T16:37:00Z' -WprStopUtc '2026-09-10T16:38:02Z'
$early = Test-CaptureWindowCoverage -CaptureWindow $counters -WprStartUtc '2026-09-10T16:00:00Z' -WprStopUtc '2026-09-10T16:29:00Z'
$partial = Test-CaptureWindowCoverage -CaptureWindow $counters -WprStartUtc '2026-09-10T16:33:00Z' -WprStopUtc '2026-09-10T16:35:20Z'
$none = Test-CaptureWindowCoverage -CaptureWindow $counters -WprStartUtc $null -WprStopUtc $null
[pscustomobject]@{
    Good = $good.Status
    GoodCovers = $good.Covers
    Late = $late.Status
    LateCovers = $late.Covers
    LateDetail = $late.Detail
    Early = $early.Status
    Partial = $partial.Status
    None = $none.Status
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = json.loads(run_pwsh(body, ["Test-CaptureWindowCoverage"] + SUPPORT_FUNCTIONS))

    assert payload["Good"] == "covers-window"
    assert payload["GoodCovers"] is True
    assert payload["Late"] == "trace-starts-after-counters"
    assert payload["LateCovers"] is False
    assert "cannot explain the sampled pressure" in payload["LateDetail"]
    assert payload["Early"] == "trace-ends-before-counters"
    assert payload["Partial"] == "partial-overlap"
    assert payload["None"] == "no-trace"


def test_incident_window_labels_keep_out_of_window_events_instead_of_dropping_them():
    """Events outside the incident window are labelled, not discarded, so the
    report can separate incident evidence from background noise."""
    body = r"""
$events = @(
    [pscustomobject]@{ TimeCreated = [datetime]::Parse('2026-09-10T16:34:30Z').ToUniversalTime(); Id = 1; ProviderName = 'in-window-provider'; Message = 'during'; LevelDisplayName = 'Error'; LogName = 'System'; RawXml = '<Event/>' },
    [pscustomobject]@{ TimeCreated = [datetime]::Parse('2026-09-10T16:00:00Z').ToUniversalTime(); Id = 2; ProviderName = 'old-provider'; Message = 'before'; LevelDisplayName = 'Warning'; LogName = 'System'; RawXml = '<Event/>' },
    [pscustomobject]@{ TimeCreated = [datetime]::Parse('2026-09-10T17:10:00Z').ToUniversalTime(); Id = 3; ProviderName = 'later-provider'; Message = 'after'; LevelDisplayName = 'Information'; LogName = 'Application'; RawXml = '<Event/>' }
)
$labelled = @(Add-IncidentWindowLabels -Events $events -WindowStart ([datetime]::Parse('2026-09-10T16:35:00Z').ToUniversalTime()) -WindowEnd ([datetime]::Parse('2026-09-10T16:36:00Z').ToUniversalTime()) -WindowMinutes 15)
[pscustomobject]@{
    Total = $labelled.Count
    Labels = @($labelled | ForEach-Object { "$($_.Id):$($_.IncidentWindow)" })
    XmlKept = @($labelled | Where-Object { $_.RawXml -eq '<Event/>' }).Count
    Messages = @($labelled | ForEach-Object { $_.Message })
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = json.loads(
        run_pwsh(
            body,
            ["Add-IncidentWindowLabels", "Test-IncidentWindowMembership"] + SUPPORT_FUNCTIONS,
        )
    )

    assert payload["Total"] == 3, "no event may be dropped"
    assert payload["Labels"] == ["1:in-window", "2:out-of-window", "3:out-of-window"]
    assert payload["XmlKept"] == 3, "raw XML must survive labelling"
    assert payload["Messages"] == ["during", "before", "after"]


def test_volume_mapping_names_the_backing_disk_and_the_pagefile_host():
    """Low free space on an archive or backup drive is harmless; the report needs
    to know which physical disk backs each letter and where the pagefile lives."""
    body = r"""
$volumes = @(
    [pscustomobject]@{ DriveLetter = 'C:'; Label = 'System'; FileSystem = 'NTFS'; CapacityBytes = 1000000000000; FreeSpaceBytes = 120000000000; PercentFree = 12 },
    [pscustomobject]@{ DriveLetter = 'D:'; Label = 'Archive'; FileSystem = 'NTFS'; CapacityBytes = 4000000000000; FreeSpaceBytes = 40000000000; PercentFree = 1 },
    [pscustomobject]@{ DriveLetter = 'E:'; Label = 'Working'; FileSystem = 'NTFS'; CapacityBytes = 2000000000000; FreeSpaceBytes = 900000000000; PercentFree = 45 }
)
$map = @{
    'C:' = [pscustomobject]@{ DiskModel = 'Samsung SSD 990 PRO 2TB'; DiskDeviceId = '\\\\.\\PHYSICALDRIVE0' }
    'D:' = [pscustomobject]@{ DiskModel = 'Seagate Backup+ Hub'; DiskDeviceId = '\\\\.\\PHYSICALDRIVE2' }
    'E:' = [pscustomobject]@{ DiskModel = 'WD Black SN850X'; DiskDeviceId = '\\\\.\\PHYSICALDRIVE1' }
}
$pageFiles = @(
    [pscustomobject]@{ Name = 'C:\pagefile.sys'; DriveLetter = 'C:'; AllocatedBaseSizeMB = 4096; CurrentUsageMB = 2650; PeakUsageMB = 3980; TempPageFile = $false }
)
$rows = @(Get-VolumeStorageMapping -VolumeMetrics $volumes -DriveToDiskMap $map -PageFileMetrics $pageFiles)
[pscustomobject]@{
    Rows = @($rows | ForEach-Object { "$($_.DriveLetter)|$($_.PhysicalDiskModel)|$($_.HostsPageFile)|$($_.PercentFree)" })
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = json.loads(run_pwsh(body, ["Get-VolumeStorageMapping"] + SUPPORT_FUNCTIONS))

    assert payload["Rows"] == [
        "C:|Samsung SSD 990 PRO 2TB|True|12",
        "D:|Seagate Backup+ Hub|False|1",
        "E:|WD Black SN850X|False|45",
    ]


def test_gpu_counter_instance_paths_are_parsed_into_pid_engine_and_luid():
    """GPU attribution needs the owning PID and engine from the PDH instance
    name; the parser must be provable without a GPU."""
    body = r"""
$paths = @(
    '\\machinename\GPU Engine(pid_4321_luid_0x00000000_0x0000C4CC_phys_0_eng_1_engtype_3D)\Utilization Percentage',
    'pid_7788_luid_0x00000000_0x0000A1B2_phys_0_eng_0_engtype_VideoDecode',
    'GPU Adapter Memory(dedicated_usage_0x00000000_0x0000C4CC)',
    ''
)
$rows = @($paths | ForEach-Object { ConvertFrom-GpuCounterPath -Path $_ })
[pscustomobject]@{
    Parsed = @($rows | Where-Object { $null -ne $_ } | ForEach-Object { "$($_.ProcessId)|$($_.EngineType)|$($_.Luid)" })
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = json.loads(run_pwsh(body, ["ConvertFrom-GpuCounterPath"]))

    assert payload["Parsed"] == [
        "4321|3D|0x00000000_0x0000C4CC",
        "7788|VideoDecode|0x00000000_0x0000A1B2",
    ]


def test_plan_mode_advertises_performance_capture_without_starting_a_trace(tmp_path):
    """Plan mode must describe the concurrent capture and stay side-effect free."""
    output_directory = tmp_path / "plan-performance"
    assert shutil.which("pwsh")
    result = subprocess.run(
        [
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-File",
            str(SCRIPT),
            "-Mode",
            "Plan",
            "-PerformanceMode",
            "-MarkerMode",
            "-OutputDirectory",
            str(output_directory),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    manifest = json.loads((output_directory / "diagnostic-plan.json").read_text(encoding="utf-8-sig"))
    performance = manifest["performanceMode"]
    assert performance["concurrentCaptureWindow"] is True
    assert performance["baselineSeconds"] == 30
    assert performance["markerMode"] is True
    assert performance["markerPreSeconds"] == 60
    assert performance["markerPostSeconds"] == 30
    assert set(performance["stages"]) >= {
        "performance-counters",
        "process-commit-attribution",
        "kernel-pool",
        "pagefile-metrics",
        "gpu-metrics",
        "udp-endpoints",
        "storage-topology",
        "incident-events",
        "wpr-trace",
    }
    assert "collect-incident-performance-capture-after-explicit-consent" in manifest["plannedActions"]
    # plan mode must not create collection artifacts
    assert not (output_directory / "diagnostic-manifest.json").exists()


def test_schema_accepts_an_incident_capture_manifest(tmp_path):
    """A 1.2 manifest carrying the incident-capture blocks must validate, so the
    new evidence surface cannot drift away from the published contract."""
    import jsonschema

    schema = json.loads(
        (REPO_ROOT / "schema" / "diagnostic-report.schema.json").read_text(encoding="utf-8")
    )
    manifest = json.loads(
        json.dumps(
            {
                "schemaVersion": "1.2",
                "toolName": "Windows Performance Diagnostics Toolkit",
                "toolVersion": "1.0.0",
                "mode": "Collect",
                "safety": {
                    "localOnly": True,
                    "readOnly": True,
                    "requiresExplicitCollectionConsent": True,
                    "automaticUpload": False,
                    "automaticRemediation": False,
                    "automaticLogClearing": False,
                },
                "scope": {
                    "durationSeconds": 30,
                    "sampleIntervalSeconds": 1,
                    "performanceMode": True,
                    "markerMode": True,
                    "eventWindowMinutes": 15,
                    "maxTrackedProcesses": 60,
                },
                "captureWindow": {
                    "startedAtUtc": "2026-09-10T16:30:00.0000000Z",
                    "completedAtUtc": "2026-09-10T16:35:00.0000000Z",
                    "requestedBaselineSeconds": 30,
                    "actualBaselineSeconds": 300.0,
                    "sampleCount": 300,
                    "wprStartUtc": "2026-09-10T16:29:55.0000000Z",
                    "wprStopUtc": "2026-09-10T16:35:40.0000000Z",
                    "wprRequestedSeconds": 0,
                    "wprEffectiveSeconds": 315,
                    "wprAutoSizedDuration": True,
                    "wprActualSeconds": 345.2,
                    "concurrentStages": ["performance-counters", "gpu", "wpr"],
                },
                "incident": {
                    "markerMode": True,
                    "markerObservedAtUtc": "2026-09-10T16:34:00.0000000Z",
                    "markerSource": "file-or-enter",
                    "windowStartUtc": "2026-09-10T16:33:00.0000000Z",
                    "windowEndUtc": "2026-09-10T16:34:30.0000000Z",
                    "preSeconds": 60,
                    "postSeconds": 30,
                    "retainedSampleCount": 91,
                    "droppedSampleCount": 209,
                },
                "wpr": {
                    "status": "removed-oversized",
                    "profile": "GeneralProfile",
                    "requestedDurationSeconds": 0,
                    "effectiveDurationSeconds": 315,
                    "autoSizedDuration": True,
                    "actualDurationSeconds": 345.2,
                    "loggingMode": "memory",
                    "concurrentWithSampling": True,
                    "maxFileMB": 512,
                    "sizeLimitExceeded": True,
                    "traceRemovedOversized": True,
                    "etlBytes": 3400000000,
                    "relatedArtifacts": [{"Name": "wpr-trace.NGenPdb", "IsDirectory": True, "SizeBytes": 90000000}],
                },
                "processMemory": {
                    "artifact": "process-memory-samples.csv",
                    "topArtifact": "process-memory-top.json",
                    "distinctProcessCount": 25,
                    "top": [{"Name": "Lightroom", "PeakPrivateBytes": 12000000000}],
                },
                "gpu": {
                    "artifact": "gpu-metrics.json",
                    "adapterCount": 1,
                    "engineSampleCount": 12,
                    "processMemorySampleCount": 8,
                    "temperature": {"available": False, "reason": "no-windows-gpu-temperature-counter-set"},
                    "clocks": {"available": False, "reason": "no-windows-gpu-clock-counter-set"},
                },
                "pageFile": [
                    {
                        "Name": "C:\\pagefile.sys",
                        "DriveLetter": "C:",
                        "AllocatedBaseSizeMB": 4096,
                        "CurrentUsageMB": 2650,
                        "PeakUsageMB": 3980,
                        "TempPageFile": False,
                    }
                ],
                "kernelPool": {
                    "artifact": "kernel-pool-samples.json",
                    "sampleCount": 91,
                    "latestPoolPagedBytes": 1234567890,
                    "latestPoolNonpagedBytes": 987654321,
                },
                "storageMapping": {
                    "drives": [
                        {
                            "DriveLetter": "C:",
                            "PercentFree": 12,
                            "PhysicalDiskModel": "Samsung SSD 990 PRO 2TB",
                            "HostsPageFile": True,
                        }
                    ],
                    "note": "Drive letters are mapped to their backing physical disk and to the pagefile host.",
                },
                "network": {
                    "status": "completed",
                    "artifact": "network-state.json",
                    "udpEndpointCount": 1450,
                    "udpEndpointCountByProcess": [
                        {"OwningProcess": 4321, "ProcessName": "Lightroom", "EndpointCount": 900}
                    ],
                    "dynamicUdpPortRanges": [
                        {"Family": "ipv4", "StartPort": 49152, "PortCount": 16384, "EndPort": 65535}
                    ],
                    "dynamicUdpPortUsage": {"totalUdpEndpoints": 1450, "endpointsInsideDynamicRange": 1400},
                    "sectionErrorCount": 0,
                },
                "incidentEvents": {
                    "artifact": "incident-events.json",
                    "windowStartUtc": "2026-09-10T16:33:00.0000000Z",
                    "windowEndUtc": "2026-09-10T16:34:30.0000000Z",
                    "windowPaddingMinutes": 15,
                    "pulledEventCount": 40,
                    "inWindowEventCount": 6,
                    "logs": [{"LogName": "System", "EventCount": 20, "SkippedUnrenderableCount": 0, "Status": "completed"}],
                    "note": "Events outside the incident window are retained and labelled out-of-window.",
                },
                "liveKernelReports": [
                    {
                        "Name": "WATCHDOG-20260910-1601.dmp",
                        "FullPath": "C:\\Windows\\LiveKernelReports\\WATCHDOG-20260910-1601.dmp",
                        "SizeBytes": 1048576,
                        "LastWriteTimeUtc": "2026-09-10T16:02:00.0000000Z",
                        "Directory": "C:\\Windows\\LiveKernelReports",
                    }
                ],
                "collectionErrors": [],
                "artifacts": [],
            }
        )
    )
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(manifest), key=lambda e: list(e.path))
    assert not errors, [(list(e.path), e.message) for e in errors]
