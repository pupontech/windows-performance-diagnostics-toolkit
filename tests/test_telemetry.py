"""Provider-neutral behavioral tests for Wpd.Telemetry.psm1.

The tests execute the real PowerShell module through pwsh. Every Windows data
source is represented by injected rows or a provider scriptblock; Linux never
pretends to have Windows counters.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE = REPO_ROOT / "src" / "Wpd.Telemetry.psm1"


def run_pwsh(body: str) -> str:
    """Run a body after importing the module and return stdout."""
    powershell = shutil.which("pwsh")
    if not powershell:
        pytest.skip("pwsh is required for the telemetry module tests")
    module_path = str(MODULE).replace("'", "''")
    harness = f"""
$ErrorActionPreference = 'Stop'
Import-Module -Force '{module_path}'
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


def test_process_identity_uses_pid_and_start_time_and_detects_reuse():
    payload = run_json(
        r"""
$first = [pscustomobject]@{ Id = 42; StartTime = [datetime]'2026-01-01T00:00:00Z' }
$same = [pscustomobject]@{ Id = 42; StartTime = [datetime]'2026-01-01T00:00:00Z' }
$reused = [pscustomobject]@{ Id = 42; StartTime = [datetime]'2026-01-01T00:01:00Z' }
[pscustomobject]@{
    First = Get-ProcessIdentityKey -Process $first
    Same = Get-ProcessIdentityKey -Process $same
    Reused = Get-ProcessIdentityKey -Process $reused
    Identity = Get-ProcessIdentity -Process $first
} | ConvertTo-Json -Depth 8 -Compress
"""
    )

    assert payload["First"] == payload["Same"]
    assert payload["First"] != payload["Reused"]
    assert payload["Identity"]["ProcessId"] == 42
    assert payload["Identity"]["StartTimeUtc"].startswith("2026-01-01T00:00:00")
    assert payload["Identity"]["IdentityKey"] == payload["First"]


def test_interval_process_cpu_pairs_user_kernel_time_and_keeps_reuse_unknown():
    payload = run_json(
        r"""
$previous = @(
    [pscustomobject]@{
        ProcessId = 7; StartTime = [datetime]'2026-01-01T00:00:00Z'
        CpuTimeSeconds = 10; UserModeTimeSeconds = 7; KernelModeTimeSeconds = 3
    },
    [pscustomobject]@{
        ProcessId = 8; StartTime = [datetime]'2026-01-01T00:00:00Z'
        CpuTimeSeconds = 4; UserModeTimeSeconds = 3; KernelModeTimeSeconds = 1
    }
)
$current = @(
    [pscustomobject]@{
        ProcessId = 7; StartTime = [datetime]'2026-01-01T00:00:00Z'
        CpuTimeSeconds = 14; UserModeTimeSeconds = 9; KernelModeTimeSeconds = 5
        ProcessorUtility = 140
    },
    [pscustomobject]@{
        ProcessId = 8; StartTime = [datetime]'2026-01-01T00:01:00Z'
        CpuTimeSeconds = 12; UserModeTimeSeconds = 8; KernelModeTimeSeconds = 4
    },
    [pscustomobject]@{
        ProcessId = 9; StartTime = [datetime]'2026-01-01T00:02:00Z'
        CpuTimeSeconds = 1; UserModeTimeSeconds = 1; KernelModeTimeSeconds = 0
    }
)
$rows = @(Compare-ProcessSnapshots -PreviousRows $previous -CurrentRows $current -ElapsedSeconds 2 -LogicalProcessorCount 4)
$rows | ConvertTo-Json -Depth 10 -Compress
"""
    )

    assert len(payload) == 3
    matched = next(row for row in payload if row["ProcessId"] == 7)
    assert matched["Status"] == "matched"
    assert matched["CpuTimeSeconds"] == 4
    assert matched["UserTimeSeconds"] == 2
    assert matched["KernelTimeSeconds"] == 2
    assert matched["CpuTimePercent"] == 50
    assert matched["UtilityPercent"] == 140
    reused = next(row for row in payload if row["ProcessId"] == 8)
    assert reused["Status"] == "pid-reused"
    assert reused["CpuTimeSeconds"] is None
    short_lived = next(row for row in payload if row["ProcessId"] == 9)
    assert short_lived["Status"] == "short-lived"
    assert short_lived["CpuTimeSeconds"] is None


def test_continuous_process_series_keeps_short_lived_rows_and_accounts_for_gaps():
    payload = run_json(
        r"""
$start = [datetime]'2026-01-01T00:00:00Z'
$samples = @(
    [pscustomobject]@{
        MonotonicSeconds = 0
        TimestampUtc = $start
        Rows = @([pscustomobject]@{
            ProcessId = 100; StartTime = $start; CpuTimeSeconds = 1
            WorkingSetBytes = 1000; HandleCount = 2; ThreadCount = 3
        })
    },
    [pscustomobject]@{
        MonotonicSeconds = 1
        TimestampUtc = $start.AddSeconds(1)
        Rows = @(
            [pscustomobject]@{
                ProcessId = 100; StartTime = $start; CpuTimeSeconds = 3
                WorkingSetBytes = 1100; HandleCount = 3; ThreadCount = 4
            },
            [pscustomobject]@{
                ProcessId = 200; StartTime = $start.AddSeconds(0.5); CpuTimeSeconds = 9
            }
        )
    },
    [pscustomobject]@{
        MonotonicSeconds = 3
        TimestampUtc = $start.AddSeconds(3)
        Rows = @([pscustomobject]@{
            ProcessId = 100; StartTime = $start; CpuTimeSeconds = 7
            WorkingSetBytes = 1200; HandleCount = 4; ThreadCount = 5
        })
    }
)
$result = Measure-ProcessTelemetrySeries -Samples $samples -ExpectedIntervalSeconds 1 -LogicalProcessorCount 2
$result | ConvertTo-Json -Depth 12 -Compress
"""
    )

    assert payload["GapCount"] == 1
    assert payload["Gaps"][0]["MissingIntervals"] == 1
    assert payload["Gaps"][0]["MissingSeconds"] == 1
    series = payload["Series"]
    p100 = [row for row in series if row["ProcessId"] == 100]
    assert p100[1]["CpuTimeSeconds"] == 2
    assert p100[2]["CpuTimeSeconds"] == 4
    assert p100[2]["GapSeconds"] == 1
    p200 = next(row for row in series if row["ProcessId"] == 200)
    assert p200["IntervalStatus"] == "short-lived"
    assert p200["CpuTimeSeconds"] is None


def test_sampling_plan_clamps_subsecond_requests_to_configured_floor():
    payload = run_json(
        r"""
$config = [pscustomobject]@{ SamplingIntervalFloorSeconds = 1 }
$clamped = New-TelemetrySamplingPlan -RequestedIntervalSeconds 0.25 -Config $config
$accepted = New-TelemetrySamplingPlan -RequestedIntervalSeconds 2 -Config $config
[pscustomobject]@{ Clamped=$clamped; Accepted=$accepted } | ConvertTo-Json -Depth 8 -Compress
"""
    )

    assert payload["Clamped"]["EffectiveIntervalSeconds"] == 1
    assert payload["Clamped"]["WasClamped"] is True
    assert payload["Clamped"]["Status"] == "clamped"
    assert payload["Accepted"]["EffectiveIntervalSeconds"] == 2
    assert payload["Accepted"]["WasClamped"] is False


def test_cpu_summary_preserves_utility_per_core_and_cpu_group_views():
    payload = run_json(
        r"""
$rows = @(
    [pscustomobject]@{ ProcessorNumber=0; GroupNumber=0; CpuTimePercent=80; UtilityPercent=125; UserTimePercent=60; KernelTimePercent=20 },
    [pscustomobject]@{ ProcessorNumber=1; GroupNumber=0; CpuTimePercent=40; UtilityPercent=55; UserTimePercent=30; KernelTimePercent=10 },
    [pscustomobject]@{ ProcessorNumber=0; GroupNumber=1; CpuTimePercent=10; UtilityPercent=12; UserTimePercent=8; KernelTimePercent=2 }
)
Get-CpuSummary -Rows $rows | ConvertTo-Json -Depth 12 -Compress
"""
    )

    assert payload["PerCoreCount"] == 3
    assert payload["CpuGroupCount"] == 2
    core_zero = next(row for row in payload["PerCore"] if row["ProcessorNumber"] == 0 and row["GroupNumber"] == 0)
    assert core_zero["CpuTimePercent"] == 80
    assert core_zero["UtilityPercent"] == 125
    group_zero = next(row for row in payload["CpuGroups"] if row["GroupNumber"] == 0)
    assert group_zero["CpuTimePercent"] == 60
    assert group_zero["UtilityPercent"] == 90


def test_scheduler_summary_correlates_queue_and_context_switch_rows_null_safely():
    payload = run_json(
        r"""
$rows = @(
    [pscustomobject]@{ QueueLength=1; ContextSwitchesPerSec=10 },
    [pscustomobject]@{ QueueLength=2; ContextSwitchesPerSec=20 },
    [pscustomobject]@{ QueueLength=3; ContextSwitchesPerSec=30 },
    [pscustomobject]@{ QueueLength=$null; ContextSwitchesPerSec=40 }
)
Get-QueueContextSwitchCorrelation -Rows $rows | ConvertTo-Json -Depth 10 -Compress
"""
    )

    assert payload["Status"] == "measured"
    assert payload["SampleCount"] == 3
    assert payload["Correlation"] == 1


def test_dpc_isr_summary_reports_rates_and_configured_long_execution_evidence():
    payload = run_json(
        r"""
$rows = @(
    [pscustomobject]@{ DpcTimePercent=2; InterruptTimePercent=3; DpcsQueuedPerSec=10; InterruptsPerSec=20; DpcDurationMicroseconds=50; Provider='a' },
    [pscustomobject]@{ DpcTimePercent=4; InterruptTimePercent=5; DpcsQueuedPerSec=14; InterruptsPerSec=24; DpcDurationMicroseconds=250; Provider='b' }
)
$config = [pscustomobject]@{ DpcLongExecutionThresholdMicroseconds = 100 }
Get-DpcIsrMetrics -Rows $rows -Config $config | ConvertTo-Json -Depth 12 -Compress
"""
    )

    assert payload["DpcTimePercent"] == 3
    assert payload["InterruptTimePercent"] == 4
    assert payload["DpcsQueuedPerSec"] == 12
    assert payload["InterruptsPerSec"] == 22
    assert payload["LongExecutionCount"] == 1
    assert payload["LongExecutions"][0]["Provider"] == "b"


def test_memory_analysis_requires_two_independent_channels_for_paging_finding():
    payload = run_json(
        r"""
$config = [pscustomobject]@{
    PagingRateThresholdPerSec = 100
    CommitPressurePercent = 80
    AvailablePhysicalPercent = 20
}
$pressure = [pscustomobject]@{
    CommittedBytes=900; CommitLimitBytes=1000; AvailableBytes=100; PhysicalMemoryBytes=1000
    PagesInputPerSec=200; HardFaultsPerSec=30; FileBackedFaultsPerSec=5
    PagefileCurrentBytes=80; PagefileSizeBytes=100; WorkingSetBytes=500
}
$ample = [pscustomobject]@{
    CommittedBytes=400; CommitLimitBytes=1000; AvailableBytes=800; PhysicalMemoryBytes=1000
    PagesInputPerSec=200; HardFaultsPerSec=30; FileBackedFaultsPerSec=5
    PagefileCurrentBytes=10; PagefileSizeBytes=100; WorkingSetBytes=500
}
[pscustomobject]@{
    Pressure = Get-MemoryAnalysis -Rows @($pressure) -Config $config
    Ample = Get-MemoryAnalysis -Rows @($ample) -Config $config
} | ConvertTo-Json -Depth 12 -Compress
"""
    )

    pressure = payload["Pressure"]
    assert pressure["Commit"]["PercentCommittedBytesInUse"] == 90
    assert pressure["Physical"]["AvailablePercent"] == 10
    assert pressure["Pagefile"]["UsedPercent"] == 80
    assert pressure["PagingFinding"]["Status"] == "finding"
    assert pressure["HardFaults"]["Classification"] == "memory-pressure"
    ample = payload["Ample"]
    assert ample["PagingFinding"]["Status"] == "coverage"
    assert "without measured memory pressure" in ample["PagingFinding"]["Message"]


def test_pool_growth_uses_monotonic_elapsed_time_and_keeps_nulls_unavailable():
    payload = run_json(
        r"""
$rows = @(
    [pscustomobject]@{ MonotonicSeconds=0; PagedPoolBytes=100; NonPagedPoolBytes=50 },
    [pscustomobject]@{ MonotonicSeconds=5; PagedPoolBytes=150; NonPagedPoolBytes=80 }
)
Measure-PoolGrowth -Rows $rows | ConvertTo-Json -Depth 10 -Compress
"""
    )

    assert payload["ElapsedSeconds"] == 5
    assert payload["PagedPoolGrowthBytes"] == 50
    assert payload["NonPagedPoolGrowthBytes"] == 30
    assert payload["PagedPoolGrowthBytesPerSec"] == 10
    assert payload["NonPagedPoolGrowthBytesPerSec"] == 6


def test_disk_latency_pairs_raw_timer_counters_with_operation_bases():
    payload = run_json(
        r"""
$previous = @([pscustomobject]@{
    Name='0 C:'; AvgDiskReadTime=1000; DiskReads=100; AvgDiskWriteTime=2000; DiskWrites=50
    DiskReadBytes=1000; DiskWriteBytes=2000
})
$current = @([pscustomobject]@{
    Name='0 C:'; AvgDiskReadTime=6000; DiskReads=200; AvgDiskWriteTime=4000; DiskWrites=100
    DiskReadBytes=9000; DiskWriteBytes=5000; CurrentDiskQueueLength=4
})
$result = @(Measure-DiskLatency -PreviousRows $previous -CurrentRows $current -ElapsedSeconds 10 -FrequencyPerfTime 1000000)
$idle = @(Measure-DiskLatency -PreviousRows @([pscustomobject]@{ Name='idle'; AvgDiskReadTime=1; DiskReads=10 }) -CurrentRows @([pscustomobject]@{ Name='idle'; AvgDiskReadTime=2; DiskReads=10 }) -ElapsedSeconds 1 -FrequencyPerfTime 1000000)
[pscustomobject]@{ Active=$result; Idle=$idle } | ConvertTo-Json -Depth 12 -Compress
"""
    )

    active = payload["Active"][0]
    assert active["ReadLatencySeconds"] == 0.00005
    assert active["WriteLatencySeconds"] == 0.00004
    assert active["ReadBytesPerSec"] == 800
    assert active["WriteBytesPerSec"] == 300
    assert active["QueueLength"] == 4
    idle = payload["Idle"][0]
    assert idle["ReadLatencySeconds"] is None
    assert idle["ReadLatencyReason"] == "no-io"


def test_network_rates_include_retransmits_and_errors_for_each_address_family():
    payload = run_json(
        r"""
$previous = @(
    [pscustomobject]@{ Protocol='TCPv4'; BytesReceived=1000; BytesSent=2000; RetransmittedSegments=10; Errors=1 },
    [pscustomobject]@{ Protocol='TCPv6'; BytesReceived=500; BytesSent=700; RetransmittedSegments=4; Errors=2 }
)
$current = @(
    [pscustomobject]@{ Protocol='TCPv4'; BytesReceived=3000; BytesSent=4000; RetransmittedSegments=14; Errors=3 },
    [pscustomobject]@{ Protocol='TCPv6'; BytesReceived=1500; BytesSent=1700; RetransmittedSegments=8; Errors=5 }
)
@(Measure-NetworkRates -PreviousRows $previous -CurrentRows $current -ElapsedSeconds 2) | ConvertTo-Json -Depth 10 -Compress
"""
    )

    assert {row["Protocol"] for row in payload} == {"TCPv4", "TCPv6"}
    v4 = next(row for row in payload if row["Protocol"] == "TCPv4")
    assert v4["BytesReceivedPerSec"] == 1000
    assert v4["BytesSentPerSec"] == 1000
    assert v4["RetransmitsPerSec"] == 2
    assert v4["ErrorsPerSec"] == 1


def test_gpu_telemetry_has_explicit_unavailable_states_and_injected_values():
    payload = run_json(
        r"""
$none = Get-GpuTelemetry -Rows @()
$rows = @([pscustomobject]@{
    ProcessId=123; Adapter='Adapter A'; EngineType='3D'; UtilizationPercentage=65
    DedicatedUsageBytes=1000; SharedUsageBytes=200; TotalCommittedBytes=1200
})
$present = Get-GpuTelemetry -Rows $rows
[pscustomobject]@{ None=$none; Present=$present } | ConvertTo-Json -Depth 12 -Compress
"""
    )

    assert payload["None"]["Status"] == "unavailable"
    assert payload["None"]["Available"] is False
    assert payload["None"]["Temperature"]["Available"] is False
    assert payload["None"]["Clocks"]["Available"] is False
    assert payload["Present"]["Status"] == "available"
    assert payload["Present"]["Engines"][0]["UtilizationPercentage"] == 65
    assert payload["Present"]["ProcessMemory"][0]["DedicatedUsageBytes"] == 1000
    assert payload["Present"]["Temperature"]["Available"] is False


def test_duration_percentiles_and_incident_baseline_comparison_are_duration_aware():
    payload = run_json(
        r"""
$baseline = @(
    [pscustomobject]@{ LatencySeconds=1; DurationSeconds=1 },
    [pscustomobject]@{ LatencySeconds=2; DurationSeconds=1 },
    [pscustomobject]@{ LatencySeconds=3; DurationSeconds=1 },
    [pscustomobject]@{ LatencySeconds=4; DurationSeconds=1 }
)
$incident = @(
    [pscustomobject]@{ LatencySeconds=10; DurationSeconds=2 },
    [pscustomobject]@{ LatencySeconds=20; DurationSeconds=1 },
    [pscustomobject]@{ LatencySeconds=30; DurationSeconds=1 }
)
$percentiles = Get-DurationPercentiles -Rows $baseline -ValueProperty LatencySeconds -Percentiles @(50,95,99)
$comparison = Compare-IncidentBaseline -BaselineRows $baseline -IncidentRows $incident -ValueProperty LatencySeconds -Percentiles @(50,95,99)
[pscustomobject]@{ Percentiles=$percentiles; Comparison=$comparison } | ConvertTo-Json -Depth 12 -Compress
"""
    )

    assert payload["Percentiles"]["DurationSeconds"] == 4
    assert payload["Percentiles"]["P50"] == 2
    assert payload["Percentiles"]["P95"] == 4
    assert payload["Comparison"]["BaselineDurationSeconds"] == 4
    assert payload["Comparison"]["IncidentDurationSeconds"] == 4
    assert payload["Comparison"]["Incident"]["P95"] == 30
    assert payload["Comparison"]["DeltaP95"] == 26


def test_perflib_health_distinguishes_healthy_partial_unavailable_and_corruption():
    payload = run_json(
        r"""
$healthy = Get-PerflibHealth -Rows @(
    [pscustomobject]@{ Name='CPU'; Value=1 },
    [pscustomobject]@{ Name='Memory'; Value=2 }
)
$partial = Get-PerflibHealth -Rows @(
    [pscustomobject]@{ Name='CPU'; Value=1 },
    [pscustomobject]@{ Name='Memory'; Value=$null }
)
$unavailable = Get-PerflibHealth -Rows @()
$corrupt = Get-PerflibHealth -Rows @([pscustomobject]@{ Name='CPU'; Error='counter registration failed' })
[pscustomobject]@{ Healthy=$healthy; Partial=$partial; Unavailable=$unavailable; Corrupt=$corrupt } | ConvertTo-Json -Depth 10 -Compress
"""
    )

    assert payload["Healthy"]["Status"] == "healthy"
    assert payload["Partial"]["Status"] == "partial"
    assert payload["Unavailable"]["Status"] == "unavailable"
    assert payload["Corrupt"]["Status"] == "corrupted-suspected"


def test_process_sampling_uses_injected_provider_and_monotonic_clock_only():
    payload = run_json(
        r"""
$script:providerCalls = @()
$provider = {
    param($index)
    $script:providerCalls += $index
    return [pscustomobject]@{
        ProcessId=500; StartTime=[datetime]'2026-01-01T00:00:00Z'
        CpuTimeSeconds=($index + 1)
    }
}
$clock = { param($index) return [double]$index }
$sleep = { param($seconds) }
$result = Invoke-ProcessTelemetrySampling -Provider $provider -SampleCount 3 -SampleIntervalSeconds 1 -LogicalProcessorCount 1 -ClockProvider $clock -SleepProvider $sleep
[pscustomobject]@{ Calls=@($script:providerCalls); Result=$result } | ConvertTo-Json -Depth 12 -Compress
"""
    )

    assert payload["Calls"] == [0, 1, 2]
    assert payload["Result"]["SampleCount"] == 3
    assert payload["Result"]["Series"][1]["CpuTimeSeconds"] == 1


def test_null_and_counter_reset_math_is_unavailable_not_zero():
    payload = run_json(
        r"""
$cpu = Measure-IntervalCpu -PreviousRow ([pscustomobject]@{ CpuTimeSeconds=10 }) -CurrentRow ([pscustomobject]@{ CpuTimeSeconds=12 }) -ElapsedSeconds 0 -LogicalProcessorCount 2
$disk = @(Measure-DiskLatency -PreviousRows @([pscustomobject]@{ Name='d'; AvgDiskReadTime=10; DiskReads=10 }) -CurrentRows @([pscustomobject]@{ Name='d'; AvgDiskReadTime=5; DiskReads=20 }) -ElapsedSeconds 1 -FrequencyPerfTime 1000)
$percentiles = Get-DurationPercentiles -Rows @([pscustomobject]@{ Latency=$null; DurationSeconds=1 }) -ValueProperty Latency
[pscustomobject]@{ Cpu=$cpu; Disk=$disk[0]; Percentiles=$percentiles } | ConvertTo-Json -Depth 10 -Compress
"""
    )

    assert payload["Cpu"]["CpuTimeSeconds"] == 2
    assert payload["Cpu"]["CpuTimePercent"] is None
    assert payload["Disk"]["ReadLatencySeconds"] is None
    assert payload["Disk"]["ReadLatencyReason"] == "counter-reset"
    assert payload["Percentiles"]["Status"] == "unavailable"


def test_legacy_process_cpu_surface_keeps_unknown_semantics_and_cumulative_cpu():
    payload = run_json(
        r"""
$t = [datetime]'2026-01-01T00:00:00Z'
$start = @(
    [pscustomobject]@{ ProcessName='normal'; Id=1; StartTime=$t; CPU=10 },
    [pscustomobject]@{ ProcessName='zero'; Id=2; StartTime=$t; CPU=5 }
)
$baseline = New-ProcessCpuSnapshot -Processes $start
$end = @(
    [pscustomobject]@{ ProcessName='normal'; Id=1; StartTime=$t; CPU=15 },
    [pscustomobject]@{ ProcessName='zero'; Id=2; StartTime=$t; CPU=5 },
    [pscustomobject]@{ ProcessName='new'; Id=3; StartTime=$t; CPU=2 },
    [pscustomobject]@{ ProcessName='reused'; Id=1; StartTime=$t.AddMinutes(1); CPU=2 },
    [pscustomobject]@{ ProcessName='protected'; Id=4; CPU=2 }
)
$rows = @(Compare-ProcessCpuSnapshots -StartSnapshots $baseline -EndProcesses $end -ElapsedSeconds 5 -LogicalProcessors 4)
$byName = @{}
foreach ($row in $rows) { $byName[$row.ProcessName] = $row }
[pscustomobject]@{
    Normal=$byName['normal'].ProcessCpuPercent
    NormalCpu=$byName['normal'].CPU
    Zero=$byName['zero'].ProcessCpuPercent
    New=$byName['new'].ProcessCpuPercent
    Reused=$byName['reused'].ProcessCpuPercent
    Protected=$byName['protected'].ProcessCpuPercent
    Direct=Get-ProcessCpuPercentage -PreviousCPU 0 -CurrentCPU 4 -ElapsedSeconds 2 -LogicalProcessors 2
} | ConvertTo-Json -Depth 8 -Compress
"""
    )

    assert payload["Normal"] == 25
    assert payload["NormalCpu"] == 15
    assert payload["Zero"] == 0
    assert payload["New"] == "unknown"
    assert payload["Reused"] == "unknown"
    assert payload["Protected"] == "unknown"
    assert payload["Direct"] == 100


def test_raw_disk_compatibility_surface_uses_perf_time_and_reports_coverage():
    payload = run_json(
        r"""
$previous = [pscustomobject]@{
    Name='0 C:'; Frequency_PerfTime=[uint64]10000000; Timestamp_PerfTime=[uint64]100000000
    AvgDiskSecPerRead=[uint64]0; AvgDiskSecPerRead_Base=[uint32]0
    AvgDiskSecPerWrite=[uint64]0; AvgDiskSecPerWrite_Base=[uint32]0
    DiskReadBytesPerSec=[uint64]1000; DiskWriteBytesPerSec=[uint64]2000; DiskBytesPerSec=[uint64]3000
    CurrentDiskQueueLength=[uint32]0
}
$current = [pscustomobject]@{
    Name='0 C:'; Frequency_PerfTime=[uint64]10000000; Timestamp_PerfTime=[uint64]120000000
    AvgDiskSecPerRead=[uint64]500000; AvgDiskSecPerRead_Base=[uint32]100
    AvgDiskSecPerWrite=[uint64]100000; AvgDiskSecPerWrite_Base=[uint32]50
    DiskReadBytesPerSec=[uint64]5096; DiskWriteBytesPerSec=[uint64]4048; DiskBytesPerSec=[uint64]9144
    CurrentDiskQueueLength=[uint32]3
}
$active = @(Get-DiskCounterDeltas -Previous @($previous) -Current @($current) -TimestampUtc 't')[0]
$noBaseline = @(Get-DiskCounterDeltas -Previous $null -Current @($current) -TimestampUtc 't')[0]
[pscustomobject]@{
    Read=$active.ReadLatencySeconds
    Write=$active.WriteLatencySeconds
    Rate=$active.ReadBytesPerSec
    Queue=$active.CurrentQueueLength
    NoBaseline=$noBaseline.ReadLatencySeconds
    Coverage=@($noBaseline.CoverageReason)
} | ConvertTo-Json -Depth 8 -Compress
"""
    )

    assert abs(payload["Read"] - 0.0005) < 1e-9
    assert abs(payload["Write"] - 0.0002) < 1e-9
    assert payload["Rate"] == 2048
    assert payload["Queue"] == 3
    assert payload["NoBaseline"] is None
    assert "no-baseline" in payload["Coverage"]


def test_gpu_counter_path_parser_and_memory_provider_rows_are_pure_transforms():
    payload = run_json(
        r"""
$path = ConvertFrom-GpuCounterPath -Path '\\host\GPU Engine(pid_1234_luid_0x00000000_0x0000ABCD_phys_0_eng_1_engtype_3D)\Utilization Percentage'
$process = @(Get-PerProcessMemorySample -Rows @([pscustomobject]@{
    Name='worker'; IDProcess=7; PrivateBytes=100; WorkingSet=200; PageFileBytes=50; HandleCount=3; ThreadCount=4
}))
$pagefile = @(Get-PageFileMetrics -Rows @([pscustomobject]@{ Name='C:\pagefile.sys'; AllocatedBaseSize=100; CurrentUsage=40; PeakUsage=60 }))
$pool = Get-KernelPoolMetrics -Rows @([pscustomobject]@{ PoolPagedBytes=10; PoolNonpagedBytes=20 })
[pscustomobject]@{ Path=$path; Process=$process; Pagefile=$pagefile; Pool=$pool } | ConvertTo-Json -Depth 10 -Compress
"""
    )

    assert payload["Path"]["ProcessId"] == 1234
    assert payload["Path"]["EngineType"] == "3D"
    assert payload["Process"][0]["PrivateBytes"] == 100
    assert payload["Process"][0]["StartTime"] is None
    assert payload["Pagefile"][0]["CurrentUsageMB"] == 40
    assert payload["Pool"]["poolNonpagedBytes"] == 20
