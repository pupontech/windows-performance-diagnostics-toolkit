# Wpd.Telemetry.psm1
# Provider-neutral Tier 1 telemetry math for Windows Performance Diagnostics.
# The module deliberately consumes rows and providers instead of querying Windows
# directly. This keeps the math testable on non-Windows hosts and makes missing
# data explicit rather than silently converting it to zero.

Set-StrictMode -Version 2.0

function Get-TelemetryProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    try {
        if ($InputObject -is [System.Collections.IDictionary]) {
            if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        }
        $property = $InputObject.PSObject.Properties[$Name]
        if ($null -ne $property) { return $property.Value }
    }
    catch { }
    return $null
}

function Get-TelemetryFirstProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    foreach ($name in $Names) {
        $value = Get-TelemetryProperty -InputObject $InputObject -Name $name
        if ($null -ne $value) { return $value }
    }
    return $null
}

function ConvertTo-TelemetryFiniteDouble {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    try { $number = [double]$Value } catch { return $null }
    if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) { return $null }
    return $number
}

function ConvertTo-TelemetryUtcDateTime {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToUniversalTime() } catch { return $null }
}

function Get-ProcessIdentity {
    <#
      Return a stable process identity. Process V2 instance names are preferred
      when supplied; otherwise PID and StartTime are paired. A PID by itself is
      never accepted as an identity key because Windows reuses PIDs.
    #>
    param([AllowNull()][object]$Process)

    $processV2 = Get-TelemetryFirstProperty -InputObject $Process -Names @('ProcessV2Instance', 'ProcessV2Key', 'V2Instance')
    $processIdValue = Get-TelemetryFirstProperty -InputObject $Process -Names @('ProcessId', 'Id', 'PID', 'IDProcess')
    $processId = ConvertTo-TelemetryFiniteDouble -Value $processIdValue
    if ($null -ne $processId) { $processId = [int64]$processId }

    if ($null -eq $processId -and $null -ne $processV2) {
        $pidMatch = [regex]::Match([string]$processV2, '(?:^|[^0-9])pid[_:-]?(\d+)', 'IgnoreCase')
        if ($pidMatch.Success) { $processId = [int64]$pidMatch.Groups[1].Value }
    }

    if ($null -ne $processV2 -and -not [string]::IsNullOrWhiteSpace([string]$processV2)) {
        return [pscustomobject]@{
            Status = 'valid'
            Source = 'process-v2'
            ProcessId = $processId
            StartTimeUtc = $null
            StartTimeTicks = $null
            IdentityKey = ('v2|{0}' -f ([string]$processV2))
        }
    }

    $startTicksValue = Get-TelemetryFirstProperty -InputObject $Process -Names @('StartTimeTicks', 'StartTicks')
    $startTimeValue = Get-TelemetryFirstProperty -InputObject $Process -Names @('StartTimeUtc', 'StartTime', 'CreationTime')
    $startTicks = ConvertTo-TelemetryFiniteDouble -Value $startTicksValue
    $startTime = $null
    if ($null -ne $startTimeValue) { $startTime = ConvertTo-TelemetryUtcDateTime -Value $startTimeValue }
    if ($null -eq $startTicks -and $null -ne $startTime) { $startTicks = [int64]$startTime.Ticks }
    if ($null -ne $startTicks) { $startTicks = [int64]$startTicks }

    if ($null -eq $processId -or $null -eq $startTicks) {
        return [pscustomobject]@{
            Status = 'unavailable'
            Source = 'pid-start-time'
            ProcessId = $processId
            StartTimeUtc = if ($null -ne $startTime) { $startTime.ToString('o') } else { $null }
            StartTimeTicks = $startTicks
            IdentityKey = $null
        }
    }

    return [pscustomobject]@{
        Status = 'valid'
        Source = 'pid-start-time'
        ProcessId = $processId
        StartTimeUtc = if ($null -ne $startTime) { $startTime.ToString('o') } else { $null }
        StartTimeTicks = $startTicks
        IdentityKey = ('pid|{0}|{1}' -f $processId, $startTicks)
    }
}

function Get-ProcessIdentityKey {
    param([AllowNull()][object]$Process)
    $identity = Get-ProcessIdentity -Process $Process
    return $identity.IdentityKey
}

function Get-ProcessCumulativeSeconds {
    param(
        [AllowNull()][object]$Process,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    $value = Get-TelemetryFirstProperty -InputObject $Process -Names $Names
    if ($null -eq $value) { return $null }
    $number = ConvertTo-TelemetryFiniteDouble -Value $value
    if ($null -eq $number) { return $null }

    $unit = Get-TelemetryFirstProperty -InputObject $Process -Names @('CpuTimeUnit', 'TimeUnit')
    $base = Get-TelemetryFirstProperty -InputObject $Process -Names @('CpuTimeBase', 'TimeBase')
    if ($null -ne $base) {
        $baseNumber = ConvertTo-TelemetryFiniteDouble -Value $base
        if ($null -ne $baseNumber -and $baseNumber -gt 0) { return ($number / $baseNumber) }
    }
    if ($null -ne $unit -and ([string]$unit -match '100ns|ticks|tick')) {
        return ($number / 10000000.0)
    }
    return $number
}

function Get-ProcessCpuTimeSeconds {
    param([AllowNull()][object]$Process)

    $direct = Get-ProcessCumulativeSeconds -Process $Process -Names @('CpuTimeSeconds', 'CPUTimeSeconds', 'TotalCpuTimeSeconds', 'CPU')
    if ($null -ne $direct) { return $direct }
    $user = Get-ProcessCumulativeSeconds -Process $Process -Names @('UserTimeSeconds', 'UserModeTimeSeconds', 'UserModeTime', 'UserTime')
    $kernel = Get-ProcessCumulativeSeconds -Process $Process -Names @('KernelTimeSeconds', 'KernelModeTimeSeconds', 'KernelModeTime', 'KernelTime')
    if ($null -eq $user -or $null -eq $kernel) { return $null }
    return ($user + $kernel)
}

function Get-ProcessUtilityPercent {
    param([AllowNull()][object]$Process)
    return (ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $Process -Names @('UtilityPercent', 'ProcessorUtilityPercent', 'ProcessorUtility', 'Utility')))
}

function Get-CumulativeDelta {
    param(
        [AllowNull()][object]$Previous,
        [AllowNull()][object]$Current
    )

    if ($null -eq $Previous -or $null -eq $Current) { return $null }
    $delta = $Current - $Previous
    if ($delta -lt 0) { return $null }
    return $delta
}

function Measure-IntervalCpu {
    <# Derive CPU time and user/kernel splits from two cumulative rows. #>
    param(
        [AllowNull()][object]$PreviousRow,
        [AllowNull()][object]$CurrentRow,
        [AllowNull()][object]$ElapsedSeconds,
        [AllowNull()][object]$LogicalProcessorCount
    )

    $elapsed = ConvertTo-TelemetryFiniteDouble -Value $ElapsedSeconds
    $processors = ConvertTo-TelemetryFiniteDouble -Value $LogicalProcessorCount
    $previousCpu = Get-ProcessCpuTimeSeconds -Process $PreviousRow
    $currentCpu = Get-ProcessCpuTimeSeconds -Process $CurrentRow
    $cpuDelta = Get-CumulativeDelta -Previous $previousCpu -Current $currentCpu
    $previousUser = Get-ProcessCumulativeSeconds -Process $PreviousRow -Names @('UserTimeSeconds', 'UserModeTimeSeconds', 'UserModeTime', 'UserTime')
    $currentUser = Get-ProcessCumulativeSeconds -Process $CurrentRow -Names @('UserTimeSeconds', 'UserModeTimeSeconds', 'UserModeTime', 'UserTime')
    $previousKernel = Get-ProcessCumulativeSeconds -Process $PreviousRow -Names @('KernelTimeSeconds', 'KernelModeTimeSeconds', 'KernelModeTime', 'KernelTime')
    $currentKernel = Get-ProcessCumulativeSeconds -Process $CurrentRow -Names @('KernelTimeSeconds', 'KernelModeTimeSeconds', 'KernelModeTime', 'KernelTime')
    $userDelta = Get-CumulativeDelta -Previous $previousUser -Current $currentUser
    $kernelDelta = Get-CumulativeDelta -Previous $previousKernel -Current $currentKernel
    $percent = $null
    if ($null -ne $cpuDelta -and $null -ne $elapsed -and $elapsed -gt 0 -and $null -ne $processors -and $processors -gt 0) {
        $percent = [Math]::Round(($cpuDelta / ($elapsed * $processors)) * 100.0, 6)
    }

    $status = 'measured'
    if ($null -eq $cpuDelta) { $status = 'unavailable' }
    elseif ($null -eq $elapsed -or $elapsed -le 0) { $status = 'invalid-elapsed' }
    return [pscustomobject]@{
        Status = $status
        CpuTimeSeconds = $cpuDelta
        UserTimeSeconds = $userDelta
        KernelTimeSeconds = $kernelDelta
        CpuTimePercent = $percent
        UtilityPercent = Get-ProcessUtilityPercent -Process $CurrentRow
    }
}

function Compare-ProcessSnapshots {
    <#
      Pair two provider-supplied process snapshots by identity. A PID with a
      different start time is reported as pid-reused; a process seen at only the
      current endpoint is short-lived and has no fabricated zero CPU value.
    #>
    param(
        [AllowNull()][object[]]$PreviousRows,
        [AllowNull()][object[]]$CurrentRows,
        [AllowNull()][object]$ElapsedSeconds,
        [AllowNull()][object]$LogicalProcessorCount
    )

    $previousByKey = @{}
    $previousByPid = @{}
    foreach ($row in @($PreviousRows)) {
        $identity = Get-ProcessIdentity -Process $row
        if ($null -ne $identity.IdentityKey) {
            $previousByKey[$identity.IdentityKey] = [pscustomobject]@{ Row = $row; Identity = $identity }
            if ($null -ne $identity.ProcessId) { $previousByPid[[string]$identity.ProcessId] = $identity.IdentityKey }
        }
    }

    $results = @()
    foreach ($row in @($CurrentRows)) {
        $identity = Get-ProcessIdentity -Process $row
        $previous = $null
        $status = 'short-lived'
        $pidReuse = $false
        if ($null -ne $identity.IdentityKey -and $previousByKey.ContainsKey($identity.IdentityKey)) {
            $previous = $previousByKey[$identity.IdentityKey]
            $status = 'matched'
        }
        elseif ($null -ne $identity.ProcessId -and $previousByPid.ContainsKey([string]$identity.ProcessId)) {
            $status = 'pid-reused'
            $pidReuse = $true
        }
        elseif ($null -eq $identity.IdentityKey) {
            $status = 'identity-unavailable'
        }

        $measurement = $null
        if ($null -ne $previous) {
            $measurement = Measure-IntervalCpu -PreviousRow $previous.Row -CurrentRow $row -ElapsedSeconds $ElapsedSeconds -LogicalProcessorCount $LogicalProcessorCount
        }
        else {
            $measurement = [pscustomobject]@{
                Status = if ($status -eq 'pid-reused') { 'pid-reused' } else { 'unavailable' }
                CpuTimeSeconds = $null
                UserTimeSeconds = $null
                KernelTimeSeconds = $null
                CpuTimePercent = $null
                UtilityPercent = Get-ProcessUtilityPercent -Process $row
            }
        }
        [double]$processId = $null
        if ($null -ne $identity.ProcessId) { $processId = $identity.ProcessId }
        $results += [pscustomobject]@{
            ProcessId = $processId
            ProcessName = Get-TelemetryFirstProperty -InputObject $row -Names @('ProcessName', 'Name', 'InstanceName')
            IdentityKey = $identity.IdentityKey
            StartTimeUtc = $identity.StartTimeUtc
            StartTimeTicks = $identity.StartTimeTicks
            Status = $status
            PidReuse = $pidReuse
            CpuTimeSeconds = $measurement.CpuTimeSeconds
            UserTimeSeconds = $measurement.UserTimeSeconds
            KernelTimeSeconds = $measurement.KernelTimeSeconds
            CpuTimePercent = $measurement.CpuTimePercent
            UtilityPercent = $measurement.UtilityPercent
            WorkingSetBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('WorkingSetBytes', 'WorkingSet64', 'WorkingSet'))
            HandleCount = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('HandleCount', 'Handles'))
            ThreadCount = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('ThreadCount', 'Threads'))
        }
    }
    return @($results)
}

function Get-TelemetryConfigValue {
    param(
        [AllowNull()][object]$Config,
        [Parameter(Mandatory = $true)][string[]]$Names,
        [AllowNull()][object]$DefaultValue
    )

    foreach ($name in $Names) {
        $parts = $name -split '\.'
        $current = $Config
        $found = $true
        foreach ($part in $parts) {
            $current = Get-TelemetryProperty -InputObject $current -Name $part
            if ($null -eq $current) { $found = $false; break }
        }
        if ($found) { return $current }
    }
    return $DefaultValue
}

function New-TelemetrySamplingPlan {
    param(
        [AllowNull()][object]$RequestedIntervalSeconds,
        [AllowNull()][object]$Config
    )

    $requested = ConvertTo-TelemetryFiniteDouble -Value $RequestedIntervalSeconds
    $floor = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryConfigValue -Config $Config -Names @('SamplingIntervalFloorSeconds', 'Sampling.FloorSeconds') -DefaultValue 1.0)
    if ($null -eq $floor -or $floor -lt 1.0) { $floor = 1.0 }
    if ($null -eq $requested -or $requested -le 0) {
        return [pscustomobject]@{
            Status = 'unavailable'
            RequestedIntervalSeconds = $requested
            EffectiveIntervalSeconds = $null
            FloorSeconds = $floor
            WasClamped = $false
        }
    }
    $effective = $requested
    $clamped = $false
    if ($effective -lt $floor) { $effective = $floor; $clamped = $true }
    return [pscustomobject]@{
        Status = if ($clamped) { 'clamped' } else { 'accepted' }
        RequestedIntervalSeconds = $requested
        EffectiveIntervalSeconds = $effective
        FloorSeconds = $floor
        WasClamped = $clamped
    }
}

function Test-TelemetrySamplingInterval {
    param(
        [AllowNull()][object]$IntervalSeconds,
        [AllowNull()][object]$Config
    )
    $plan = New-TelemetrySamplingPlan -RequestedIntervalSeconds $IntervalSeconds -Config $Config
    return ($plan.Status -eq 'accepted')
}

function Get-SampleMonotonicSeconds {
    param(
        [AllowNull()][object]$Sample,
        [int]$Index,
        [AllowNull()][object]$ExpectedIntervalSeconds
    )

    $value = Get-TelemetryFirstProperty -InputObject $Sample -Names @('MonotonicSeconds', 'MonotonicElapsedSeconds', 'ElapsedSeconds')
    $number = ConvertTo-TelemetryFiniteDouble -Value $value
    if ($null -ne $number) { return $number }
    $expected = ConvertTo-TelemetryFiniteDouble -Value $ExpectedIntervalSeconds
    if ($null -ne $expected -and $expected -gt 0) { return ($Index * $expected) }
    return [double]$Index
}

function Get-SampleProcessRows {
    param([AllowNull()][object]$Sample)

    $rows = Get-TelemetryFirstProperty -InputObject $Sample -Names @('Rows', 'Processes', 'ProcessRows')
    if ($null -ne $rows) { return @($rows) }
    if ($null -ne (Get-TelemetryFirstProperty -InputObject $Sample -Names @('ProcessId', 'Id', 'PID'))) { return @($Sample) }
    return @()
}

function Measure-ProcessTelemetrySeries {
    <#
      Convert timestamped provider rows into a continuous process series. The
      elapsed denominator is monotonic, and gaps are retained as evidence rather
      than being hidden by interpolating samples.
    #>
    param(
        [AllowNull()][object[]]$Samples,
        [AllowNull()][object]$ExpectedIntervalSeconds,
        [AllowNull()][object]$LogicalProcessorCount,
        [AllowNull()][object]$Config
    )

    $expected = ConvertTo-TelemetryFiniteDouble -Value $ExpectedIntervalSeconds
    $previousByKey = @{}
    $previousByPid = @{}
    $series = @()
    $gaps = @()
    $previousTime = $null
    $index = 0
    foreach ($sample in @($Samples)) {
        $currentTime = Get-SampleMonotonicSeconds -Sample $sample -Index $index -ExpectedIntervalSeconds $expected
        if ($null -ne $previousTime -and $null -ne $expected -and $expected -gt 0) {
            $sampleDelta = $currentTime - $previousTime
            if ($sampleDelta -gt $expected) {
                $missingSeconds = $sampleDelta - $expected
                $missingIntervals = [int][Math]::Floor(($sampleDelta / $expected) - 0.000001) - 1
                if ($missingIntervals -lt 1) { $missingIntervals = 1 }
                $gaps += [pscustomobject]@{
                    FromMonotonicSeconds = $previousTime
                    ToMonotonicSeconds = $currentTime
                    ElapsedSeconds = $sampleDelta
                    MissingIntervals = $missingIntervals
                    MissingSeconds = [Math]::Round($missingSeconds, 6)
                }
            }
        }

        foreach ($row in @(Get-SampleProcessRows -Sample $sample)) {
            $identity = Get-ProcessIdentity -Process $row
            $previous = $null
            $intervalStatus = 'short-lived'
            $gapSeconds = 0.0
            if ($null -ne $identity.IdentityKey -and $previousByKey.ContainsKey($identity.IdentityKey)) {
                $previous = $previousByKey[$identity.IdentityKey]
                $elapsed = $currentTime - $previous.Time
                if ($elapsed -gt 0) {
                    $measurement = Measure-IntervalCpu -PreviousRow $previous.Row -CurrentRow $row -ElapsedSeconds $elapsed -LogicalProcessorCount $LogicalProcessorCount
                    $intervalStatus = 'matched'
                    if ($null -ne $expected -and $elapsed -gt $expected) {
                        $intervalStatus = 'gap'
                        $gapSeconds = [Math]::Round($elapsed - $expected, 6)
                    }
                }
                else {
                    $measurement = [pscustomobject]@{ CpuTimeSeconds = $null; UserTimeSeconds = $null; KernelTimeSeconds = $null; CpuTimePercent = $null; UtilityPercent = Get-ProcessUtilityPercent -Process $row }
                    $intervalStatus = 'invalid-elapsed'
                }
            }
            elseif ($null -eq $identity.IdentityKey) {
                $measurement = [pscustomobject]@{ CpuTimeSeconds = $null; UserTimeSeconds = $null; KernelTimeSeconds = $null; CpuTimePercent = $null; UtilityPercent = Get-ProcessUtilityPercent -Process $row }
                $intervalStatus = 'identity-unavailable'
            }
            else {
                $measurement = [pscustomobject]@{ CpuTimeSeconds = $null; UserTimeSeconds = $null; KernelTimeSeconds = $null; CpuTimePercent = $null; UtilityPercent = Get-ProcessUtilityPercent -Process $row }
                if ($previousByPid.ContainsKey([string]$identity.ProcessId)) { $intervalStatus = 'pid-reused' }
            }

            $processId = $identity.ProcessId
            $series += [pscustomobject]@{
                SampleIndex = $index
                MonotonicSeconds = $currentTime
                ProcessId = $processId
                ProcessName = Get-TelemetryFirstProperty -InputObject $row -Names @('ProcessName', 'Name', 'InstanceName')
                IdentityKey = $identity.IdentityKey
                StartTimeUtc = $identity.StartTimeUtc
                StartTimeTicks = $identity.StartTimeTicks
                IntervalStatus = $intervalStatus
                GapSeconds = $gapSeconds
                CpuTimeSeconds = $measurement.CpuTimeSeconds
                UserTimeSeconds = $measurement.UserTimeSeconds
                KernelTimeSeconds = $measurement.KernelTimeSeconds
                CpuTimePercent = $measurement.CpuTimePercent
                UtilityPercent = $measurement.UtilityPercent
                WorkingSetBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('WorkingSetBytes', 'WorkingSet64', 'WorkingSet'))
                IoReadBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('IoReadBytes', 'ReadBytes', 'IOReadBytes'))
                IoWriteBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('IoWriteBytes', 'WriteBytes', 'IOWriteBytes'))
                HandleCount = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('HandleCount', 'Handles'))
                ThreadCount = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('ThreadCount', 'Threads'))
            }
            if ($null -ne $identity.IdentityKey) {
                $previousByKey[$identity.IdentityKey] = [pscustomobject]@{ Row = $row; Time = $currentTime }
                if ($null -ne $identity.ProcessId) { $previousByPid[[string]$identity.ProcessId] = $identity.IdentityKey }
            }
        }
        $previousTime = $currentTime
        $index++
    }

    $duration = $null
    if ($index -gt 1) {
        $last = Get-SampleMonotonicSeconds -Sample @($Samples)[-1] -Index ($index - 1) -ExpectedIntervalSeconds $expected
        $first = Get-SampleMonotonicSeconds -Sample @($Samples)[0] -Index 0 -ExpectedIntervalSeconds $expected
        $duration = $last - $first
    }
    return [pscustomobject]@{
        Status = if ($index -eq 0) { 'unavailable' } elseif ($gaps.Count -gt 0) { 'partial' } else { 'complete' }
        SampleCount = $index
        ObservedDurationSeconds = $duration
        GapCount = $gaps.Count
        Gaps = @($gaps)
        Series = @($series)
    }
}

Set-Alias -Name Get-ContinuousProcessTelemetry -Value Measure-ProcessTelemetrySeries

function Invoke-ProcessTelemetrySampling {
    <#
      Run a bounded provider-injected sampling loop. The default clock is only a
      deterministic index clock for fixtures; production callers provide a
      monotonic clock and sleep implementation at the seam.
    #>
    param(
        [AllowNull()][object]$Provider,
        [AllowNull()][object]$SampleCount,
        [AllowNull()][object]$DurationSeconds,
        [AllowNull()][object]$SampleIntervalSeconds,
        [AllowNull()][object]$LogicalProcessorCount,
        [AllowNull()][object]$Config,
        [AllowNull()][object]$ClockProvider,
        [AllowNull()][object]$SleepProvider
    )

    if ($null -eq $Provider) {
        return [pscustomobject]@{ Status = 'unavailable'; SampleCount = 0; ObservedDurationSeconds = $null; GapCount = 0; Gaps = @(); Series = @() }
    }
    $plan = New-TelemetrySamplingPlan -RequestedIntervalSeconds $SampleIntervalSeconds -Config $Config
    if ($plan.Status -eq 'unavailable') {
        return [pscustomobject]@{ Status = 'unavailable'; SampleCount = 0; ObservedDurationSeconds = $null; GapCount = 0; Gaps = @(); Series = @(); SamplingPlan = $plan }
    }
    $count = ConvertTo-TelemetryFiniteDouble -Value $SampleCount
    if ($null -eq $count) {
        $duration = ConvertTo-TelemetryFiniteDouble -Value $DurationSeconds
        if ($null -ne $duration -and $duration -ge 0) { $count = [Math]::Floor($duration / $plan.EffectiveIntervalSeconds) + 1 }
    }
    if ($null -eq $count -or $count -le 0) {
        return [pscustomobject]@{ Status = 'unavailable'; SampleCount = 0; ObservedDurationSeconds = $null; GapCount = 0; Gaps = @(); Series = @(); SamplingPlan = $plan }
    }
    $count = [int]$count
    $samples = @()
    for ($index = 0; $index -lt $count; $index++) {
        $rows = @(Invoke-TelemetryProvider -Provider $Provider -ArgumentList @($index))
        $monotonic = $null
        if ($null -ne $ClockProvider -and $ClockProvider -is [scriptblock]) {
            try { $monotonic = ConvertTo-TelemetryFiniteDouble -Value (& $ClockProvider $index) } catch { $monotonic = $null }
        }
        if ($null -eq $monotonic) { $monotonic = $index * $plan.EffectiveIntervalSeconds }
        $samples += [pscustomobject]@{ MonotonicSeconds = $monotonic; Rows = $rows }
        if ($index -lt ($count - 1) -and $null -ne $SleepProvider -and $SleepProvider -is [scriptblock]) {
            try { [void](& $SleepProvider $plan.EffectiveIntervalSeconds) } catch { }
        }
    }
    $result = Measure-ProcessTelemetrySeries -Samples $samples -ExpectedIntervalSeconds $plan.EffectiveIntervalSeconds -LogicalProcessorCount $LogicalProcessorCount -Config $Config
    Add-Member -InputObject $result -MemberType NoteProperty -Name SamplingPlan -Value $plan -Force
    return $result
}

Set-Alias -Name Invoke-ContinuousProcessTelemetry -Value Invoke-ProcessTelemetrySampling

function Get-TelemetryAverage {
    param(
        [AllowNull()][object[]]$Rows,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    $sum = 0.0
    $count = 0
    foreach ($row in @($Rows)) {
        $number = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names $Names)
        if ($null -ne $number) { $sum += $number; $count++ }
    }
    if ($count -eq 0) { return $null }
    return [Math]::Round($sum / $count, 6)
}

function Get-CpuSummary {
    <# Aggregate CPU rows without collapsing per-core or CPU-group detail. #>
    param(
        [AllowNull()][object[]]$Rows,
        [AllowNull()][object[]]$PreviousRows,
        [AllowNull()][object]$ElapsedSeconds,
        [AllowNull()][object]$LogicalProcessorCount
    )

    $inputRows = @($Rows)
    if ($inputRows.Count -eq 0 -and $null -ne $PreviousRows) {
        $inputRows = @(Compare-ProcessSnapshots -PreviousRows $PreviousRows -CurrentRows @($Rows) -ElapsedSeconds $ElapsedSeconds -LogicalProcessorCount $LogicalProcessorCount)
    }
    $coreMap = @{}
    $groupMap = @{}
    foreach ($row in $inputRows) {
        $core = Get-TelemetryFirstProperty -InputObject $row -Names @('ProcessorNumber', 'CoreNumber', 'Core', 'Processor')
        $group = Get-TelemetryFirstProperty -InputObject $row -Names @('GroupNumber', 'ProcessorGroup', 'Group')
        $coreKey = if ($null -eq $core) { 'unknown' } else { [string]$core }
        $groupKey = if ($null -eq $group) { 'unknown' } else { [string]$group }
        $coreMapKey = $groupKey + '|' + $coreKey
        if (-not $coreMap.ContainsKey($coreMapKey)) { $coreMap[$coreMapKey] = New-Object System.Collections.ArrayList }
        [void]$coreMap[$coreMapKey].Add($row)
        if (-not $groupMap.ContainsKey($groupKey)) { $groupMap[$groupKey] = New-Object System.Collections.ArrayList }
        [void]$groupMap[$groupKey].Add($row)
    }

    $perCore = @()
    foreach ($key in $coreMap.Keys) {
        $items = @($coreMap[$key])
        $core = Get-TelemetryFirstProperty -InputObject $items[0] -Names @('ProcessorNumber', 'CoreNumber', 'Core', 'Processor')
        $group = Get-TelemetryFirstProperty -InputObject $items[0] -Names @('GroupNumber', 'ProcessorGroup', 'Group')
        $perCore += [pscustomobject]@{
            ProcessorNumber = $core
            GroupNumber = $group
            SampleCount = $items.Count
            CpuTimePercent = Get-TelemetryAverage -Rows $items -Names @('CpuTimePercent', 'CpuTime', 'ProcessorTimePercent', 'PercentProcessorTime')
            UtilityPercent = Get-TelemetryAverage -Rows $items -Names @('UtilityPercent', 'ProcessorUtility', 'ProcessorUtilityPercent')
            UserTimePercent = Get-TelemetryAverage -Rows $items -Names @('UserTimePercent', 'UserPercent', 'PercentUserTime')
            KernelTimePercent = Get-TelemetryAverage -Rows $items -Names @('KernelTimePercent', 'KernelPercent', 'PrivilegedTimePercent', 'PercentPrivilegedTime')
            QueueLength = Get-TelemetryAverage -Rows $items -Names @('QueueLength', 'ProcessorQueueLength', 'Queue')
            ContextSwitchesPerSec = Get-TelemetryAverage -Rows $items -Names @('ContextSwitchesPerSec', 'ContextSwitchRate', 'ContextSwitches')
        }
    }

    $groups = @()
    foreach ($key in $groupMap.Keys) {
        $items = @($groupMap[$key])
        $group = Get-TelemetryFirstProperty -InputObject $items[0] -Names @('GroupNumber', 'ProcessorGroup', 'Group')
        $groups += [pscustomobject]@{
            GroupNumber = $group
            SampleCount = $items.Count
            CoreCount = @($items | ForEach-Object { Get-TelemetryFirstProperty -InputObject $_ -Names @('ProcessorNumber', 'CoreNumber', 'Core', 'Processor') } | Sort-Object -Unique).Count
            CpuTimePercent = Get-TelemetryAverage -Rows $items -Names @('CpuTimePercent', 'CpuTime', 'ProcessorTimePercent', 'PercentProcessorTime')
            UtilityPercent = Get-TelemetryAverage -Rows $items -Names @('UtilityPercent', 'ProcessorUtility', 'ProcessorUtilityPercent')
            UserTimePercent = Get-TelemetryAverage -Rows $items -Names @('UserTimePercent', 'UserPercent', 'PercentUserTime')
            KernelTimePercent = Get-TelemetryAverage -Rows $items -Names @('KernelTimePercent', 'KernelPercent', 'PrivilegedTimePercent', 'PercentPrivilegedTime')
            QueueLength = Get-TelemetryAverage -Rows $items -Names @('QueueLength', 'ProcessorQueueLength', 'Queue')
            ContextSwitchesPerSec = Get-TelemetryAverage -Rows $items -Names @('ContextSwitchesPerSec', 'ContextSwitchRate', 'ContextSwitches')
        }
    }
    return [pscustomobject]@{
        Status = if ($inputRows.Count -eq 0) { 'unavailable' } else { 'measured' }
        AverageCpuTimePercent = Get-TelemetryAverage -Rows $inputRows -Names @('CpuTimePercent', 'CpuTime', 'ProcessorTimePercent', 'PercentProcessorTime')
        AverageUtilityPercent = Get-TelemetryAverage -Rows $inputRows -Names @('UtilityPercent', 'ProcessorUtility', 'ProcessorUtilityPercent')
        UtilityMayExceed100 = (($perCore | Where-Object { $null -ne $_.UtilityPercent -and $_.UtilityPercent -gt 100 }).Count -gt 0)
        PerCoreCount = @($perCore).Count
        CpuGroupCount = @($groups).Count
        PerCore = @($perCore)
        CpuGroups = @($groups)
    }
}

function Get-PearsonCorrelation {
    param([double[]]$X, [double[]]$Y)
    if ($null -eq $X -or $null -eq $Y -or $X.Count -lt 2 -or $X.Count -ne $Y.Count) { return $null }
    $meanX = ($X | Measure-Object -Average).Average
    $meanY = ($Y | Measure-Object -Average).Average
    $numerator = 0.0
    $sumX = 0.0
    $sumY = 0.0
    for ($i = 0; $i -lt $X.Count; $i++) {
        $dx = $X[$i] - $meanX
        $dy = $Y[$i] - $meanY
        $numerator += $dx * $dy
        $sumX += $dx * $dx
        $sumY += $dy * $dy
    }
    if ($sumX -le 0 -or $sumY -le 0) { return $null }
    return [Math]::Round($numerator / ([Math]::Sqrt($sumX) * [Math]::Sqrt($sumY)), 6)
}

function Get-QueueContextSwitchCorrelation {
    param([AllowNull()][object[]]$Rows)

    $queue = @()
    $switches = @()
    foreach ($row in @($Rows)) {
        $queueValue = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('QueueLength', 'ProcessorQueueLength', 'Queue', 'QueueDepth'))
        $switchValue = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('ContextSwitchesPerSec', 'ContextSwitchRate', 'ContextSwitches'))
        if ($null -ne $queueValue -and $null -ne $switchValue) {
            $queue += $queueValue
            $switches += $switchValue
        }
    }
    $correlation = Get-PearsonCorrelation -X ([double[]]$queue) -Y ([double[]]$switches)
    return [pscustomobject]@{
        Status = if ($null -eq $correlation) { 'unavailable' } else { 'measured' }
        SampleCount = $queue.Count
        Correlation = $correlation
        QueueValues = @($queue)
        ContextSwitchValues = @($switches)
    }
}

Set-Alias -Name Get-SchedulerSummary -Value Get-QueueContextSwitchCorrelation

function Get-DpcIsrMetrics {
    param(
        [AllowNull()][object[]]$Rows,
        [AllowNull()][object]$Config
    )

    $threshold = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryConfigValue -Config $Config -Names @('DpcLongExecutionThresholdMicroseconds', 'Dpc.LongExecutionThresholdMicroseconds', 'Thresholds.DpcLongExecutionMicroseconds') -DefaultValue $null)
    $long = @()
    foreach ($row in @($Rows)) {
        $duration = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('DpcDurationMicroseconds', 'DpcExecutionTimeMicroseconds', 'ExecutionTimeMicroseconds', 'DpcDuration'))
        if ($null -ne $threshold -and $null -ne $duration -and $duration -gt $threshold) {
            $long += [pscustomobject]@{
                Provider = Get-TelemetryFirstProperty -InputObject $row -Names @('Provider', 'Source', 'Driver')
                Name = Get-TelemetryFirstProperty -InputObject $row -Names @('Name', 'InstanceName', 'Routine')
                DurationMicroseconds = $duration
                ThresholdMicroseconds = $threshold
            }
        }
    }
    return [pscustomobject]@{
        Status = if (@($Rows).Count -eq 0) { 'unavailable' } else { 'measured' }
        DpcTimePercent = Get-TelemetryAverage -Rows $Rows -Names @('DpcTimePercent', 'PercentDpcTime', 'DpcTime')
        InterruptTimePercent = Get-TelemetryAverage -Rows $Rows -Names @('InterruptTimePercent', 'PercentInterruptTime', 'InterruptTime')
        DpcsQueuedPerSec = Get-TelemetryAverage -Rows $Rows -Names @('DpcsQueuedPerSec', 'DpcQueuedPerSec', 'DpcsQueued')
        InterruptsPerSec = Get-TelemetryAverage -Rows $Rows -Names @('InterruptsPerSec', 'InterruptRate', 'Interrupts')
        LongExecutionThresholdMicroseconds = $threshold
        LongExecutionStatus = if ($null -eq $threshold) { 'unavailable' } else { 'evaluated' }
        LongExecutionCount = @($long).Count
        LongExecutions = @($long)
    }
}

Set-Alias -Name Get-DpcIsrSummary -Value Get-DpcIsrMetrics

function Get-TelemetryRatioPercent {
    param(
        [AllowNull()][object]$Numerator,
        [AllowNull()][object]$Denominator
    )
    $top = ConvertTo-TelemetryFiniteDouble -Value $Numerator
    $bottom = ConvertTo-TelemetryFiniteDouble -Value $Denominator
    if ($null -eq $top -or $null -eq $bottom -or $bottom -le 0) { return $null }
    return [Math]::Round(($top / $bottom) * 100.0, 6)
}

function Get-MemoryAnalysis {
    param(
        [AllowNull()][object[]]$Rows,
        [AllowNull()][object]$Config
    )

    $rowList = @($Rows)
    if ($rowList.Count -eq 0) {
        return [pscustomobject]@{
            Status = 'unavailable'
            Commit = [pscustomobject]@{ CommittedBytes = $null; CommitLimitBytes = $null; PercentCommittedBytesInUse = $null }
            Physical = [pscustomobject]@{ AvailableBytes = $null; PhysicalMemoryBytes = $null; AvailablePercent = $null; UsedPercent = $null }
            Pagefile = [pscustomobject]@{ CurrentBytes = $null; SizeBytes = $null; UsedPercent = $null }
            HardFaults = [pscustomobject]@{ HardFaultsPerSec = $null; FileBackedFaultsPerSec = $null; Classification = 'unavailable' }
            PagingFinding = [pscustomobject]@{ Status = 'unavailable'; Type = 'coverage'; Message = 'Paging pressure could not be evaluated because memory counters were unavailable.' }
            WorkingSetGrowthBytes = $null
        }
    }
    $row = $rowList[$rowList.Count - 1]
    $committed = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('CommittedBytes', 'CommitBytes', 'Committed'))
    $commitLimit = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('CommitLimitBytes', 'CommitLimit', 'CommitmentLimit'))
    $available = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('AvailableBytes', 'AvailablePhysicalBytes', 'Available'))
    $physical = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('PhysicalMemoryBytes', 'TotalPhysicalMemoryBytes', 'PhysicalTotalBytes'))
    $pagefileCurrent = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('PagefileCurrentBytes', 'PageFileCurrentBytes', 'PagefileUsedBytes'))
    $pagefileSize = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('PagefileSizeBytes', 'PageFileSizeBytes', 'PagefileLimitBytes'))
    $pagingRate = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('PagesInputPerSec', 'PagesPerSec', 'PagingInputPerSec', 'PageReadsPerSec'))
    $hardFaults = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('HardFaultsPerSec', 'PageFaultsPerSec', 'HardPageFaultsPerSec'))
    $fileBackedFaults = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('FileBackedFaultsPerSec', 'TransitionFaultsPerSec', 'CacheFaultsPerSec'))
    $commitPercent = Get-TelemetryRatioPercent -Numerator $committed -Denominator $commitLimit
    $availablePercent = Get-TelemetryRatioPercent -Numerator $available -Denominator $physical
    $pagefilePercent = Get-TelemetryRatioPercent -Numerator $pagefileCurrent -Denominator $pagefileSize
    $workingSetGrowth = $null
    if ($rowList.Count -gt 1) {
        $firstWorkingSet = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $rowList[0] -Names @('WorkingSetBytes', 'WorkingSet'))
        $lastWorkingSet = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('WorkingSetBytes', 'WorkingSet'))
        if ($null -ne $firstWorkingSet -and $null -ne $lastWorkingSet) { $workingSetGrowth = $lastWorkingSet - $firstWorkingSet }
    }

    $commitThreshold = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryConfigValue -Config $Config -Names @('CommitPressurePercent', 'Memory.CommitPressurePercent', 'Thresholds.CommitPercent') -DefaultValue $null)
    $availableThreshold = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryConfigValue -Config $Config -Names @('AvailablePhysicalPercent', 'Memory.AvailablePhysicalPercent', 'Thresholds.AvailablePhysicalPercent') -DefaultValue $null)
    $workingSetThreshold = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryConfigValue -Config $Config -Names @('WorkingSetGrowthBytes', 'Memory.WorkingSetGrowthBytes', 'Thresholds.WorkingSetGrowthBytes') -DefaultValue $null)
    $pagingThreshold = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryConfigValue -Config $Config -Names @('PagingRateThresholdPerSec', 'Memory.PagingRateThresholdPerSec', 'Thresholds.PagingRatePerSec') -DefaultValue $null)
    $commitPressure = ($null -ne $commitPercent -and $null -ne $commitThreshold -and $commitPercent -ge $commitThreshold)
    $physicalPressure = ($null -ne $availablePercent -and $null -ne $availableThreshold -and $availablePercent -le $availableThreshold)
    $workingSetPressure = ($null -ne $workingSetGrowth -and $null -ne $workingSetThreshold -and $workingSetGrowth -ge $workingSetThreshold)
    $independentPressure = $commitPressure -or $physicalPressure -or $workingSetPressure

    $pagingFinding = $null
    if ($null -eq $pagingRate -or $null -eq $pagingThreshold) {
        $pagingFinding = [pscustomobject]@{ Status = 'unavailable'; Type = 'coverage'; Message = 'Paging pressure could not be evaluated because the paging rate or configured rule was unavailable.' }
    }
    elseif ($pagingRate -ge $pagingThreshold -and $independentPressure) {
        $pagingFinding = [pscustomobject]@{ Status = 'finding'; Type = 'memory-paging'; Message = 'Paging rate and an independent memory-pressure channel were elevated.'; Confidence = 'Medium' }
    }
    elseif ($pagingRate -ge $pagingThreshold) {
        $pagingFinding = [pscustomobject]@{ Status = 'coverage'; Type = 'coverage'; Message = 'Paging rate was elevated without measured memory pressure.' }
    }
    else {
        $pagingFinding = [pscustomobject]@{ Status = 'not-elevated'; Type = 'none'; Message = 'Paging rate did not meet the configured rule.' }
    }

    $classification = 'observed'
    if ($null -eq $hardFaults) { $classification = 'unavailable' }
    elseif ($independentPressure) { $classification = 'memory-pressure' }
    elseif ($null -ne $fileBackedFaults -and $fileBackedFaults -gt 0) { $classification = 'file-backed' }
    return [pscustomobject]@{
        Status = 'measured'
        Commit = [pscustomobject]@{ CommittedBytes = $committed; CommitLimitBytes = $commitLimit; PercentCommittedBytesInUse = $commitPercent; Pressure = $commitPressure }
        Physical = [pscustomobject]@{ AvailableBytes = $available; PhysicalMemoryBytes = $physical; AvailablePercent = $availablePercent; UsedPercent = if ($null -ne $availablePercent) { [Math]::Round(100.0 - $availablePercent, 6) } else { $null }; Pressure = $physicalPressure }
        Pagefile = [pscustomobject]@{ CurrentBytes = $pagefileCurrent; SizeBytes = $pagefileSize; UsedPercent = $pagefilePercent }
        HardFaults = [pscustomobject]@{ HardFaultsPerSec = $hardFaults; FileBackedFaultsPerSec = $fileBackedFaults; Classification = $classification }
        WorkingSetGrowthBytes = $workingSetGrowth
        PagingFinding = $pagingFinding
    }
}

Set-Alias -Name Analyze-MemoryTelemetry -Value Get-MemoryAnalysis
Set-Alias -Name Get-MemoryPressureAnalysis -Value Get-MemoryAnalysis

function Measure-PoolGrowth {
    param(
        [AllowNull()][object[]]$Rows,
        [AllowNull()][object]$Config
    )

    $items = @($Rows)
    if ($items.Count -lt 2) {
        return [pscustomobject]@{ Status = 'unavailable'; ElapsedSeconds = $null; PagedPoolGrowthBytes = $null; NonPagedPoolGrowthBytes = $null; PagedPoolGrowthBytesPerSec = $null; NonPagedPoolGrowthBytesPerSec = $null }
    }
    $first = $items[0]
    $last = $items[$items.Count - 1]
    $firstTime = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $first -Names @('MonotonicSeconds', 'MonotonicElapsedSeconds'))
    $lastTime = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $last -Names @('MonotonicSeconds', 'MonotonicElapsedSeconds'))
    $elapsed = $null
    if ($null -ne $firstTime -and $null -ne $lastTime -and $lastTime -gt $firstTime) { $elapsed = $lastTime - $firstTime }
    $firstPaged = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $first -Names @('PagedPoolBytes', 'PoolPagedBytes'))
    $lastPaged = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $last -Names @('PagedPoolBytes', 'PoolPagedBytes'))
    $firstNonPaged = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $first -Names @('NonPagedPoolBytes', 'PoolNonpagedBytes', 'PoolNonPagedBytes'))
    $lastNonPaged = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $last -Names @('NonPagedPoolBytes', 'PoolNonpagedBytes', 'PoolNonPagedBytes'))
    $pagedGrowth = if ($null -ne $firstPaged -and $null -ne $lastPaged) { $lastPaged - $firstPaged } else { $null }
    $nonPagedGrowth = if ($null -ne $firstNonPaged -and $null -ne $lastNonPaged) { $lastNonPaged - $firstNonPaged } else { $null }
    $pagedRate = if ($null -ne $pagedGrowth -and $null -ne $elapsed) { [Math]::Round($pagedGrowth / $elapsed, 6) } else { $null }
    $nonPagedRate = if ($null -ne $nonPagedGrowth -and $null -ne $elapsed) { [Math]::Round($nonPagedGrowth / $elapsed, 6) } else { $null }
    return [pscustomobject]@{
        Status = if ($null -eq $elapsed) { 'partial' } else { 'measured' }
        ElapsedSeconds = $elapsed
        PagedPoolGrowthBytes = $pagedGrowth
        NonPagedPoolGrowthBytes = $nonPagedGrowth
        PagedPoolGrowthBytesPerSec = $pagedRate
        NonPagedPoolGrowthBytesPerSec = $nonPagedRate
    }
}

Set-Alias -Name Get-PoolGrowth -Value Measure-PoolGrowth

function Get-RawCounterDelta {
    param(
        [AllowNull()][object]$Previous,
        [AllowNull()][object]$Current,
        [Parameter(Mandatory = $true)][string[]]$Names
    )
    $oldValue = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $Previous -Names $Names)
    $newValue = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $Current -Names $Names)
    if ($null -eq $oldValue -or $null -eq $newValue) { return $null }
    $delta = $newValue - $oldValue
    if ($delta -lt 0) { return $null }
    return $delta
}

function Get-DiskLatencyValue {
    param(
        [AllowNull()][object]$Previous,
        [AllowNull()][object]$Current,
        [Parameter(Mandatory = $true)][string[]]$ValueNames,
        [Parameter(Mandatory = $true)][string[]]$BaseNames,
        [AllowNull()][object]$Frequency
    )
    if ($null -eq $Previous -or $null -eq $Current) { return [pscustomobject]@{ Value = $null; Reason = 'no-baseline' } }
    $frequencyNumber = ConvertTo-TelemetryFiniteDouble -Value $Frequency
    if ($null -eq $frequencyNumber -or $frequencyNumber -le 0) { return [pscustomobject]@{ Value = $null; Reason = 'missing-frequency' } }
    $valueDelta = Get-RawCounterDelta -Previous $Previous -Current $Current -Names $ValueNames
    if ($null -eq $valueDelta) {
        $oldValue = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $Previous -Names $ValueNames)
        $newValue = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $Current -Names $ValueNames)
        if ($null -ne $oldValue -and $null -ne $newValue -and $newValue -lt $oldValue) { return [pscustomobject]@{ Value = $null; Reason = 'counter-reset' } }
        return [pscustomobject]@{ Value = $null; Reason = 'missing-counter' }
    }
    $baseDelta = Get-RawCounterDelta -Previous $Previous -Current $Current -Names $BaseNames
    if ($null -eq $baseDelta) {
        $oldBase = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $Previous -Names $BaseNames)
        $newBase = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $Current -Names $BaseNames)
        if ($null -ne $oldBase -and $null -ne $newBase -and $newBase -eq $oldBase) { return [pscustomobject]@{ Value = $null; Reason = 'no-io' } }
        return [pscustomobject]@{ Value = $null; Reason = 'missing-counter' }
    }
    if ($baseDelta -le 0) { return [pscustomobject]@{ Value = $null; Reason = 'no-io' } }
    $value = ($valueDelta / $frequencyNumber) / $baseDelta
    if ([double]::IsNaN($value) -or [double]::IsInfinity($value) -or $value -lt 0) { return [pscustomobject]@{ Value = $null; Reason = 'invalid-result' } }
    return [pscustomobject]@{ Value = [Math]::Round($value, 9); Reason = $null }
}

function Measure-DiskLatency {
    param(
        [AllowNull()][object[]]$PreviousRows,
        [AllowNull()][object[]]$CurrentRows,
        [AllowNull()][object]$ElapsedSeconds,
        [AllowNull()][object]$FrequencyPerfTime,
        [AllowNull()][object]$Config
    )

    $elapsed = ConvertTo-TelemetryFiniteDouble -Value $ElapsedSeconds
    $frequency = ConvertTo-TelemetryFiniteDouble -Value $FrequencyPerfTime
    $previousMap = @{}
    foreach ($row in @($PreviousRows)) {
        $name = Get-TelemetryFirstProperty -InputObject $row -Names @('Name', 'InstanceName', 'DiskName', 'DeviceName', 'Path')
        if ($null -ne $name) { $previousMap[[string]$name] = $row }
    }
    $result = @()
    foreach ($row in @($CurrentRows)) {
        $name = Get-TelemetryFirstProperty -InputObject $row -Names @('Name', 'InstanceName', 'DiskName', 'DeviceName', 'Path')
        $previous = $null
        if ($null -ne $name -and $previousMap.ContainsKey([string]$name)) { $previous = $previousMap[[string]$name] }
        $readLatency = Get-DiskLatencyValue -Previous $previous -Current $row -ValueNames @('AvgDiskReadTime', 'AverageDiskReadTime', 'ReadTime') -BaseNames @('DiskReads', 'ReadOperations', 'ReadOperationCount') -Frequency $frequency
        $writeLatency = Get-DiskLatencyValue -Previous $previous -Current $row -ValueNames @('AvgDiskWriteTime', 'AverageDiskWriteTime', 'WriteTime') -BaseNames @('DiskWrites', 'WriteOperations', 'WriteOperationCount') -Frequency $frequency
        $readBytesDelta = Get-RawCounterDelta -Previous $previous -Current $row -Names @('DiskReadBytes', 'ReadBytes', 'BytesRead')
        $writeBytesDelta = Get-RawCounterDelta -Previous $previous -Current $row -Names @('DiskWriteBytes', 'WriteBytes', 'BytesWritten')
        $readRate = if ($null -ne $readBytesDelta -and $null -ne $elapsed -and $elapsed -gt 0) { [Math]::Round($readBytesDelta / $elapsed, 6) } else { $null }
        $writeRate = if ($null -ne $writeBytesDelta -and $null -ne $elapsed -and $elapsed -gt 0) { [Math]::Round($writeBytesDelta / $elapsed, 6) } else { $null }
        $result += [pscustomobject]@{
            Name = $name
            ElapsedSeconds = $elapsed
            ReadLatencySeconds = $readLatency.Value
            ReadLatencyReason = $readLatency.Reason
            WriteLatencySeconds = $writeLatency.Value
            WriteLatencyReason = $writeLatency.Reason
            ReadBytesPerSec = $readRate
            WriteBytesPerSec = $writeRate
            QueueLength = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('CurrentDiskQueueLength', 'QueueLength', 'DiskQueueLength'))
        }
    }
    return @($result)
}

Set-Alias -Name Get-DiskLatency -Value Measure-DiskLatency

function Invoke-TelemetryProvider {
    <# Execute an injected provider; never reaches into Windows implicitly. #>
    param(
        [AllowNull()][object]$Provider,
        [AllowNull()][object[]]$ArgumentList
    )
    if ($null -eq $Provider) { return $null }
    try {
        if ($Provider -is [scriptblock]) {
            if ($null -eq $ArgumentList) { return @(& $Provider) }
            return @(& $Provider @ArgumentList)
        }
        return @($Provider)
    }
    catch {
        return $null
    }
}

function Get-NetworkRowKey {
    param([AllowNull()][object]$Row)
    $protocol = Get-TelemetryFirstProperty -InputObject $Row -Names @('Protocol', 'AddressFamily', 'CounterSet')
    $name = Get-TelemetryFirstProperty -InputObject $Row -Names @('Name', 'InstanceName', 'Adapter', 'Interface')
    if ($null -eq $protocol -and $null -eq $name) { return $null }
    return ('{0}|{1}' -f $protocol, $name)
}

function Measure-NetworkRates {
    param(
        [AllowNull()][object[]]$PreviousRows,
        [AllowNull()][object[]]$CurrentRows,
        [AllowNull()][object]$ElapsedSeconds,
        [AllowNull()][object]$Config
    )

    $elapsed = ConvertTo-TelemetryFiniteDouble -Value $ElapsedSeconds
    $previousMap = @{}
    foreach ($row in @($PreviousRows)) {
        $key = Get-NetworkRowKey -Row $row
        if ($null -ne $key) { $previousMap[$key] = $row }
    }
    $result = @()
    foreach ($row in @($CurrentRows)) {
        $key = Get-NetworkRowKey -Row $row
        $previous = $null
        if ($null -ne $key -and $previousMap.ContainsKey($key)) { $previous = $previousMap[$key] }
        $receivedDelta = Get-RawCounterDelta -Previous $previous -Current $row -Names @('BytesReceived', 'BytesRecv', 'ReceivedBytes', 'OctetsReceived')
        $sentDelta = Get-RawCounterDelta -Previous $previous -Current $row -Names @('BytesSent', 'SentBytes', 'OctetsSent')
        $retransmitDelta = Get-RawCounterDelta -Previous $previous -Current $row -Names @('RetransmittedSegments', 'Retransmits', 'SegmentsRetransmitted')
        $errorDelta = Get-RawCounterDelta -Previous $previous -Current $row -Names @('Errors', 'ErrorsReceived', 'ReceiveErrors', 'ErrorsSent')
        $receivedRate = if ($null -ne $receivedDelta -and $null -ne $elapsed -and $elapsed -gt 0) { [Math]::Round($receivedDelta / $elapsed, 6) } else { $null }
        $sentRate = if ($null -ne $sentDelta -and $null -ne $elapsed -and $elapsed -gt 0) { [Math]::Round($sentDelta / $elapsed, 6) } else { $null }
        $retransmitRate = if ($null -ne $retransmitDelta -and $null -ne $elapsed -and $elapsed -gt 0) { [Math]::Round($retransmitDelta / $elapsed, 6) } else { $null }
        $errorRate = if ($null -ne $errorDelta -and $null -ne $elapsed -and $elapsed -gt 0) { [Math]::Round($errorDelta / $elapsed, 6) } else { $null }
        $result += [pscustomobject]@{
            Protocol = Get-TelemetryFirstProperty -InputObject $row -Names @('Protocol', 'AddressFamily', 'CounterSet')
            Name = Get-TelemetryFirstProperty -InputObject $row -Names @('Name', 'InstanceName', 'Adapter', 'Interface')
            ElapsedSeconds = $elapsed
            Status = if ($null -eq $previous) { 'no-baseline' } elseif ($null -eq $elapsed -or $elapsed -le 0) { 'invalid-elapsed' } else { 'measured' }
            BytesReceivedPerSec = $receivedRate
            BytesSentPerSec = $sentRate
            RetransmitsPerSec = $retransmitRate
            ErrorsPerSec = $errorRate
            RetransmittedSegments = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('RetransmittedSegments', 'Retransmits', 'SegmentsRetransmitted'))
            Errors = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('Errors', 'ErrorsReceived', 'ReceiveErrors', 'ErrorsSent'))
        }
    }
    return @($result)
}

function Get-NetworkSummary {
    param(
        [AllowNull()][object[]]$PreviousRows,
        [AllowNull()][object[]]$CurrentRows,
        [AllowNull()][object]$ElapsedSeconds,
        [AllowNull()][object]$Config
    )
    $rows = @(Measure-NetworkRates -PreviousRows $PreviousRows -CurrentRows $CurrentRows -ElapsedSeconds $ElapsedSeconds -Config $Config)
    return [pscustomobject]@{
        Status = if ($rows.Count -eq 0) { 'unavailable' } else { 'measured' }
        Rows = $rows
        TotalBytesReceivedPerSec = Get-TelemetryAverage -Rows $rows -Names @('BytesReceivedPerSec')
        TotalBytesSentPerSec = Get-TelemetryAverage -Rows $rows -Names @('BytesSentPerSec')
        TotalRetransmitsPerSec = Get-TelemetryAverage -Rows $rows -Names @('RetransmitsPerSec')
        TotalErrorsPerSec = Get-TelemetryAverage -Rows $rows -Names @('ErrorsPerSec')
    }
}

Set-Alias -Name Get-NetworkRates -Value Measure-NetworkRates
Set-Alias -Name Get-NetworkTelemetry -Value Get-NetworkSummary

function Get-PerProcessMemorySample {
    <#
      Normalize injected Win32_PerfFormattedData_PerfProc_Process-shaped rows.
      The module never queries CIM itself; callers supply Rows or a provider.
      _Total is excluded because it double-counts the per-process rows.
    #>
    param(
        [AllowNull()][object[]]$Rows,
        [AllowNull()][object]$Provider,
        [AllowNull()][object]$MaxProcesses = 60
    )

    $items = @($Rows)
    if ($items.Count -eq 0 -and $null -ne $Provider) {
        $items = @(Invoke-TelemetryProvider -Provider $Provider)
    }

    $max = ConvertTo-TelemetryFiniteDouble -Value $MaxProcesses
    if ($null -eq $max -or $max -lt 1) { $max = $null }
    $normalized = @()
    foreach ($row in $items) {
        $nameValue = Get-TelemetryFirstProperty -InputObject $row -Names @('Name', 'ProcessName', 'InstanceName')
        if ($null -ne $nameValue -and [string]$nameValue -eq '_Total') { continue }
        $processId = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('IDProcess', 'ProcessId', 'Id', 'PID'))
        if ($null -ne $processId) { $processId = [int64]$processId }
        $identity = Get-ProcessIdentity -Process $row
        $normalized += [pscustomobject]@{
            Name = if ($null -ne $nameValue) { [string]$nameValue } else { $null }
            Id = $processId
            ProcessId = $processId
            StartTime = $identity.StartTimeUtc
            IdentityKey = $identity.IdentityKey
            PrivateBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('PrivateBytes', 'PrivateBytesBytes'))
            WorkingSet = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('WorkingSet', 'WorkingSetBytes', 'WorkingSet64'))
            WorkingSetPrivate = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('WorkingSetPrivate', 'WorkingSetPrivateBytes'))
            PageFileBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('PageFileBytes', 'PagefileBytes'))
            PageFileBytesPeak = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('PageFileBytesPeak', 'PagefileBytesPeak'))
            VirtualBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('VirtualBytes', 'VirtualBytesBytes'))
            PoolPagedBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('PoolPagedBytes', 'PagedPoolBytes'))
            PoolNonpagedBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('PoolNonpagedBytes', 'PoolNonPagedBytes', 'NonPagedPoolBytes'))
            HandleCount = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('HandleCount', 'Handles'))
            ThreadCount = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('ThreadCount', 'Threads'))
        }
    }
    $ordered = @($normalized | Sort-Object -Property @{ Expression = { if ($null -eq $_.PrivateBytes) { -1 } else { $_.PrivateBytes } }; Descending = $true })
    if ($null -ne $max) { $ordered = @($ordered | Select-Object -First ([int]$max)) }
    return @($ordered)
}

function Get-PageFileMetrics {
    <# Normalize injected Win32_PageFileUsage-shaped rows without querying CIM. #>
    param(
        [AllowNull()][object[]]$Rows,
        [AllowNull()][object]$Provider
    )

    $items = @($Rows)
    if ($items.Count -eq 0 -and $null -ne $Provider) {
        $items = @(Invoke-TelemetryProvider -Provider $Provider)
    }
    $result = @()
    foreach ($row in $items) {
        $nameValue = Get-TelemetryFirstProperty -InputObject $row -Names @('Name', 'Path', 'PageFile')
        $name = if ($null -ne $nameValue) { [string]$nameValue } else { $null }
        $drive = $null
        if ($null -ne $name -and $name -match '^([A-Za-z]):') { $drive = $matches[1].ToUpperInvariant() + ':' }
        $result += [pscustomobject]@{
            Name = $name
            DriveLetter = $drive
            AllocatedBaseSizeMB = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('AllocatedBaseSizeMB', 'AllocatedBaseSize'))
            CurrentUsageMB = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('CurrentUsageMB', 'CurrentUsage'))
            PeakUsageMB = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('PeakUsageMB', 'PeakUsage'))
            TempPageFile = Get-TelemetryFirstProperty -InputObject $row -Names @('TempPageFile', 'TemporaryPageFile')
        }
    }
    return @($result)
}

function Get-KernelPoolMetrics {
    <# Normalize one injected Win32_PerfFormattedData_PerfOS_Memory row. #>
    param(
        [AllowNull()][object[]]$Rows,
        [AllowNull()][object]$Provider
    )

    $items = @($Rows)
    if ($items.Count -eq 0 -and $null -ne $Provider) {
        $items = @(Invoke-TelemetryProvider -Provider $Provider)
    }
    if ($items.Count -eq 0) {
        return [pscustomobject]@{
            Status = 'unavailable'
            poolPagedBytes = $null
            poolNonpagedBytes = $null
            poolPagedResidentBytes = $null
            systemCacheResidentBytes = $null
            cacheBytes = $null
        }
    }
    $row = $items[$items.Count - 1]
    return [pscustomobject]@{
        Status = 'measured'
        poolPagedBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('PoolPagedBytes', 'PagedPoolBytes'))
        poolNonpagedBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('PoolNonpagedBytes', 'PoolNonPagedBytes', 'NonPagedPoolBytes'))
        poolPagedResidentBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('PoolPagedResidentBytes', 'PagedPoolResidentBytes'))
        systemCacheResidentBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('SystemCacheResidentBytes', 'SystemCacheBytes'))
        cacheBytes = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('CacheBytes', 'SystemCacheBytes'))
    }
}

function ConvertFrom-GpuCounterPath {
    <# Parse a GPU Engine/Process Memory PDH instance path without a GPU. #>
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $instance = $Path
    if ($Path -match '\(([^()]*)\)') { $instance = $matches[1] }
    $pidMatch = [regex]::Match($instance, 'pid_(\d+)', 'IgnoreCase')
    if (-not $pidMatch.Success) { return $null }
    $engineMatch = [regex]::Match($instance, 'engtype_([A-Za-z0-9_]+)', 'IgnoreCase')
    $luidMatch = [regex]::Match($instance, 'luid_(0x[0-9a-fA-F]+_0x[0-9a-fA-F]+)', 'IgnoreCase')
    return [pscustomobject]@{
        ProcessId = [int]$pidMatch.Groups[1].Value
        EngineType = if ($engineMatch.Success) { $engineMatch.Groups[1].Value } else { $null }
        Luid = if ($luidMatch.Success) { $luidMatch.Groups[1].Value } else { $null }
        InstanceName = $instance
    }
}

function Get-GpuTelemetry {
    param(
        [AllowNull()][object[]]$Rows,
        [AllowNull()][object]$Provider
    )

    $items = @($Rows)
    if ($items.Count -eq 0 -and $null -ne $Provider) { $items = @(Invoke-TelemetryProvider -Provider $Provider) }
    $temperature = $null
    $clocks = $null
    foreach ($row in $items) {
        if ($null -eq $temperature) {
            $temperature = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('TemperatureCelsius', 'Temperature'))
        }
        if ($null -eq $clocks) {
            $clocks = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('ClockMHz', 'ClockSpeedMHz', 'ClocksMHz'))
        }
    }
    $engines = @()
    $memory = @()
    $adapters = @()
    foreach ($row in $items) {
        $adapter = Get-TelemetryFirstProperty -InputObject $row -Names @('Adapter', 'AdapterName', 'Description')
        if ($null -ne $adapter -and @($adapters | Where-Object { $_.Name -eq $adapter }).Count -eq 0) {
            $adapters += [pscustomobject]@{ Name = $adapter; DriverVersion = Get-TelemetryFirstProperty -InputObject $row -Names @('DriverVersion', 'Driver') }
        }
        $utilization = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('UtilizationPercentage', 'EngineUtilization', 'GpuUtilizationPercent', 'Utilization'))
        if ($null -ne $utilization -or $null -ne (Get-TelemetryFirstProperty -InputObject $row -Names @('EngineType', 'Engine', 'Luid'))) {
            $engines += [pscustomobject]@{
                ProcessId = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('ProcessId', 'PID', 'Id'))
                Adapter = $adapter
                EngineType = Get-TelemetryFirstProperty -InputObject $row -Names @('EngineType', 'Engine', 'Type')
                UtilizationPercentage = $utilization
            }
        }
        $dedicated = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('DedicatedUsageBytes', 'DedicatedUsage'))
        $shared = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('SharedUsageBytes', 'SharedUsage'))
        $total = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('TotalCommittedBytes', 'TotalCommitted', 'CommittedBytes'))
        if ($null -ne $dedicated -or $null -ne $shared -or $null -ne $total) {
            $memory += [pscustomobject]@{
                ProcessId = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('ProcessId', 'PID', 'Id'))
                Adapter = $adapter
                DedicatedUsageBytes = $dedicated
                SharedUsageBytes = $shared
                TotalCommittedBytes = $total
            }
        }
    }
    $available = ($items.Count -gt 0)
    return [pscustomobject]@{
        Status = if ($available) { 'available' } else { 'unavailable' }
        Available = $available
        Adapters = @($adapters)
        Engines = @($engines)
        ProcessMemory = @($memory)
        Temperature = if ($null -ne $temperature) { [pscustomobject]@{ Available = $true; ValueCelsius = $temperature; Reason = $null } } else { [pscustomobject]@{ Available = $false; ValueCelsius = $null; Reason = 'not-exposed-by-injected-gpu-counters' } }
        Clocks = if ($null -ne $clocks) { [pscustomobject]@{ Available = $true; ValueMHz = $clocks; Reason = $null } } else { [pscustomobject]@{ Available = $false; ValueMHz = $null; Reason = 'not-exposed-by-injected-gpu-counters' } }
    }
}

Set-Alias -Name Get-GpuMetrics -Value Get-GpuTelemetry
Set-Alias -Name Measure-GpuTelemetry -Value Get-GpuTelemetry

function Get-DurationPercentiles {
    param(
        [AllowNull()][object[]]$Rows,
        [AllowNull()][string]$ValueProperty,
        [AllowNull()][double[]]$Percentiles = @(50, 95, 99),
        [AllowNull()][object]$Config
    )

    $weighted = @()
    foreach ($row in @($Rows)) {
        $value = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryProperty -InputObject $row -Name $ValueProperty)
        if ($null -eq $value) { continue }
        $weight = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $row -Names @('DurationSeconds', 'Duration', 'ElapsedSeconds'))
        if ($null -eq $weight -or $weight -le 0) { $weight = 1.0 }
        $weighted += [pscustomobject]@{ Value = $value; Weight = $weight }
    }
    $sorted = @($weighted | Sort-Object -Property Value)
    $totalDuration = 0.0
    foreach ($entry in $sorted) { $totalDuration += $entry.Weight }
    $output = [ordered]@{
        Status = if ($sorted.Count -eq 0) { 'unavailable' } else { 'measured' }
        SampleCount = $sorted.Count
        DurationSeconds = if ($sorted.Count -eq 0) { $null } else { [Math]::Round($totalDuration, 6) }
    }
    foreach ($percentile in @($Percentiles)) {
        $key = 'P' + ([string]$percentile).Replace('.', '_')
        $selected = $null
        if ($sorted.Count -gt 0) {
            $target = $totalDuration * ([double]$percentile / 100.0)
            if ($target -le 0) { $target = $sorted[0].Weight }
            $cumulative = 0.0
            foreach ($entry in $sorted) {
                $cumulative += $entry.Weight
                if ($cumulative -ge $target) { $selected = $entry.Value; break }
            }
            if ($null -eq $selected) { $selected = $sorted[$sorted.Count - 1].Value }
        }
        $output[$key] = $selected
    }
    return [pscustomobject]$output
}

function Compare-IncidentBaseline {
    param(
        [AllowNull()][object[]]$BaselineRows,
        [AllowNull()][object[]]$IncidentRows,
        [AllowNull()][string]$ValueProperty,
        [AllowNull()][double[]]$Percentiles = @(50, 95, 99),
        [AllowNull()][object]$Config
    )
    $baseline = Get-DurationPercentiles -Rows $BaselineRows -ValueProperty $ValueProperty -Percentiles $Percentiles -Config $Config
    $incident = Get-DurationPercentiles -Rows $IncidentRows -ValueProperty $ValueProperty -Percentiles $Percentiles -Config $Config
    $output = [ordered]@{
        Status = if ($baseline.Status -eq 'measured' -and $incident.Status -eq 'measured') { 'measured' } else { 'partial' }
        Baseline = $baseline
        Incident = $incident
        BaselineDurationSeconds = $baseline.DurationSeconds
        IncidentDurationSeconds = $incident.DurationSeconds
    }
    foreach ($percentile in @($Percentiles)) {
        $key = 'P' + ([string]$percentile).Replace('.', '_')
        $deltaKey = 'Delta' + $key
        $oldValue = Get-TelemetryProperty -InputObject $baseline -Name $key
        $newValue = Get-TelemetryProperty -InputObject $incident -Name $key
        $output[$deltaKey] = if ($null -ne $oldValue -and $null -ne $newValue) { $newValue - $oldValue } else { $null }
    }
    return [pscustomobject]$output
}

Set-Alias -Name Get-DurationAwarePercentiles -Value Get-DurationPercentiles
Set-Alias -Name Compare-BaselineIncident -Value Compare-IncidentBaseline

function Get-PerflibHealth {
    param(
        [AllowNull()][object[]]$Rows,
        [AllowNull()][object]$Provider
    )

    $items = @($Rows)
    if ($items.Count -eq 0 -and $null -ne $Provider) { $items = @(Invoke-TelemetryProvider -Provider $Provider) }
    if ($items.Count -eq 0) {
        return [pscustomobject]@{ Status = 'unavailable'; ObservedCount = 0; MissingCount = 0; InvalidCount = 0; Reason = 'no-counter-rows' }
    }
    $missing = 0
    $invalid = 0
    $corrupt = 0
    foreach ($row in $items) {
        $error = Get-TelemetryFirstProperty -InputObject $row -Names @('Error', 'Exception', 'ProviderError')
        if ($null -ne $error) { $corrupt++; continue }
        $value = Get-TelemetryFirstProperty -InputObject $row -Names @('Value', 'CookedValue', 'CounterValue', 'Sample')
        if ($null -eq $value) { $missing++; continue }
        if ($null -eq (ConvertTo-TelemetryFiniteDouble -Value $value)) { $invalid++ }
    }
    $status = 'healthy'
    if ($corrupt -gt 0) { $status = 'corrupted-suspected' }
    elseif ($missing -gt 0 -or $invalid -gt 0) { $status = 'partial' }
    return [pscustomobject]@{
        Status = $status
        ObservedCount = $items.Count
        MissingCount = $missing
        InvalidCount = $invalid
        CorruptedCount = $corrupt
        Reason = if ($status -eq 'healthy') { $null } elseif ($status -eq 'partial') { 'one-or-more-counter-values-missing-or-invalid' } else { 'provider-reported-counter-error' }
    }
}

Set-Alias -Name Test-PerflibHealth -Value Get-PerflibHealth
Set-Alias -Name Get-PerflibHealthProbe -Value Get-PerflibHealth

function Get-ProcessSnapshotKey {
    param([AllowNull()][object]$Process)
    $identity = Get-ProcessIdentity -Process $Process
    if ($null -eq $identity.IdentityKey) { return $null }
    if ($identity.Source -eq 'process-v2') { return $identity.IdentityKey }
    return ('{0}_{1}' -f $identity.ProcessId, $identity.StartTimeTicks)
}

function New-ProcessCpuSnapshot {
    param([AllowNull()][object[]]$Processes)

    $snapshot = @{}
    foreach ($process in @($Processes)) {
        $key = Get-ProcessSnapshotKey -Process $process
        if ($null -eq $key) { continue }
        $identity = Get-ProcessIdentity -Process $process
        $snapshot[$key] = [pscustomobject]@{
            ProcessId = $identity.ProcessId
            StartTimeUtc = $identity.StartTimeUtc
            StartTimeTicks = $identity.StartTimeTicks
            CPU = Get-ProcessCpuTimeSeconds -Process $process
            CpuTimeSeconds = Get-ProcessCpuTimeSeconds -Process $process
            UserTimeSeconds = Get-ProcessCumulativeSeconds -Process $process -Names @('UserTimeSeconds', 'UserModeTimeSeconds', 'UserModeTime', 'UserTime')
            KernelTimeSeconds = Get-ProcessCumulativeSeconds -Process $process -Names @('KernelTimeSeconds', 'KernelModeTimeSeconds', 'KernelModeTime', 'KernelTime')
        }
    }
    return $snapshot
}

function Get-ProcessCpuPercentage {
    param(
        [AllowNull()][object]$PreviousCPU,
        [AllowNull()][object]$CurrentCPU,
        [AllowNull()][object]$ElapsedSeconds,
        [AllowNull()][object]$LogicalProcessors
    )

    $previous = ConvertTo-TelemetryFiniteDouble -Value $PreviousCPU
    $current = ConvertTo-TelemetryFiniteDouble -Value $CurrentCPU
    $elapsed = ConvertTo-TelemetryFiniteDouble -Value $ElapsedSeconds
    $processors = ConvertTo-TelemetryFiniteDouble -Value $LogicalProcessors
    if ($null -eq $previous -or $null -eq $current -or $null -eq $elapsed -or $null -eq $processors) { return 'unknown' }
    if ($elapsed -le 0 -or $processors -lt 1) { return 'unknown' }
    $delta = $current - $previous
    if ($delta -lt 0) { return 'unknown' }
    $percent = ($delta / ($elapsed * $processors)) * 100.0
    if ([double]::IsNaN($percent) -or [double]::IsInfinity($percent) -or $percent -gt 100.0) { return 'unknown' }
    return [Math]::Round($percent, 2)
}

function Compare-ProcessCpuSnapshots {
    param(
        [AllowNull()][object]$StartSnapshots,
        [AllowNull()][object[]]$EndProcesses,
        [AllowNull()][object]$ElapsedSeconds,
        [AllowNull()][object]$LogicalProcessors
    )

    $previousByPid = @{}
    if ($null -ne $StartSnapshots -and $StartSnapshots -is [System.Collections.IDictionary]) {
        foreach ($key in $StartSnapshots.Keys) {
            $entry = $StartSnapshots[$key]
            $pidValue = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $entry -Names @('ProcessId', 'Id', 'PID'))
            if ($null -ne $pidValue) { $previousByPid[[string][int64]$pidValue] = [string]$key }
            elseif ([string]$key -match '^(\d+)[_|]') { $previousByPid[$matches[1]] = [string]$key }
        }
    }
    $results = @()
    foreach ($process in @($EndProcesses)) {
        $key = Get-ProcessSnapshotKey -Process $process
        $identity = Get-ProcessIdentity -Process $process
        $currentCpu = Get-ProcessCpuTimeSeconds -Process $process
        $previous = $null
        $matched = $false
        if ($null -ne $StartSnapshots -and $null -ne $key -and $StartSnapshots -is [System.Collections.IDictionary] -and $StartSnapshots.ContainsKey($key)) {
            $previous = $StartSnapshots[$key]
            $matched = $true
        }
        $pidReuse = $false
        if (-not $matched -and $null -ne $identity.ProcessId -and $previousByPid.ContainsKey([string]$identity.ProcessId)) { $pidReuse = $true }
        $percent = 'unknown'
        $userDelta = $null
        $kernelDelta = $null
        if ($matched) {
            $percent = Get-ProcessCpuPercentage -PreviousCPU (Get-TelemetryFirstProperty -InputObject $previous -Names @('CPU', 'CpuTimeSeconds')) -CurrentCPU $currentCpu -ElapsedSeconds $ElapsedSeconds -LogicalProcessors $LogicalProcessors
            $userDelta = Get-CumulativeDelta -Previous (Get-TelemetryFirstProperty -InputObject $previous -Names @('UserTimeSeconds', 'UserTime')) -Current (Get-ProcessCumulativeSeconds -Process $process -Names @('UserTimeSeconds', 'UserModeTimeSeconds', 'UserModeTime', 'UserTime'))
            $kernelDelta = Get-CumulativeDelta -Previous (Get-TelemetryFirstProperty -InputObject $previous -Names @('KernelTimeSeconds', 'KernelTime')) -Current (Get-ProcessCumulativeSeconds -Process $process -Names @('KernelTimeSeconds', 'KernelModeTimeSeconds', 'KernelModeTime', 'KernelTime'))
        }
        $status = if ($matched) { 'matched' } elseif ($pidReuse) { 'pid-reused' } elseif ($null -eq $key) { 'identity-unavailable' } else { 'short-lived' }
        $results += [pscustomobject]@{
            ProcessName = Get-TelemetryFirstProperty -InputObject $process -Names @('ProcessName', 'Name', 'InstanceName')
            Id = $identity.ProcessId
            ProcessId = $identity.ProcessId
            IdentityKey = $key
            StartTimeUtc = $identity.StartTimeUtc
            StartTimeTicks = $identity.StartTimeTicks
            CPU = $currentCpu
            ProcessCpuPercent = $percent
            CpuTimePercent = if ($percent -eq 'unknown') { $null } else { $percent }
            UserTimeSeconds = $userDelta
            KernelTimeSeconds = $kernelDelta
            Status = $status
            PidReuse = $pidReuse
            WorkingSet64 = Get-TelemetryFirstProperty -InputObject $process -Names @('WorkingSet64', 'WorkingSetBytes', 'WorkingSet')
            Handles = Get-TelemetryFirstProperty -InputObject $process -Names @('Handles', 'HandleCount')
            ThreadCount = Get-TelemetryFirstProperty -InputObject $process -Names @('ThreadCount', 'Threads')
            Path = Get-TelemetryFirstProperty -InputObject $process -Names @('Path', 'ExecutablePath')
        }
    }
    return @($results)
}

function Get-FiniteNumericDelta {
    param(
        [AllowNull()][object]$Previous,
        [AllowNull()][object]$Current,
        [Parameter(Mandatory = $true)][string]$Name
    )
    return (Get-RawCounterDelta -Previous $Previous -Current $Current -Names @($Name))
}

function Get-AverageTimerDelta {
    param(
        [AllowNull()][object]$Previous,
        [AllowNull()][object]$Current,
        [Parameter(Mandatory = $true)][string]$ValueProperty,
        [Parameter(Mandatory = $true)][string]$BaseProperty,
        [AllowNull()][object]$FrequencyPerfTime
    )
    $value = Get-DiskLatencyValue -Previous $Previous -Current $Current -ValueNames @($ValueProperty) -BaseNames @($BaseProperty) -Frequency $FrequencyPerfTime
    return $value
}

function Get-RateFromDelta {
    param(
        [AllowNull()][object]$Previous,
        [AllowNull()][object]$Current,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][object]$ElapsedSeconds
    )
    $elapsed = ConvertTo-TelemetryFiniteDouble -Value $ElapsedSeconds
    if ($null -eq $elapsed -or $elapsed -le 0) { return $null }
    $delta = Get-FiniteNumericDelta -Previous $Previous -Current $Current -Name $Name
    if ($null -eq $delta) { return $null }
    return [Math]::Round($delta / $elapsed, 6)
}

function Get-DiskCounterDeltas {
    <# Compatibility surface for raw Win32_PerfRawData disk rows. #>
    param(
        [AllowNull()][object[]]$Previous,
        [AllowNull()][object[]]$Current,
        [AllowNull()][string]$TimestampUtc
    )

    if ($null -eq $Current) { return @() }
    $previousByName = @{}
    foreach ($row in @($Previous)) {
        $name = Get-TelemetryFirstProperty -InputObject $row -Names @('Name', 'InstanceName', 'DiskName')
        if ($null -ne $name) { $previousByName[[string]$name] = $row }
    }
    $result = @()
    foreach ($disk in @($Current)) {
        $nameValue = Get-TelemetryFirstProperty -InputObject $disk -Names @('Name', 'InstanceName', 'DiskName')
        if ($null -eq $nameValue) { continue }
        $name = [string]$nameValue
        $previousDisk = $null
        if ($previousByName.ContainsKey($name)) { $previousDisk = $previousByName[$name] }
        $frequency = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $disk -Names @('Frequency_PerfTime', 'FrequencyPerfTime'))
        $coverage = @()
        $readLatency = Get-AverageTimerDelta -Previous $previousDisk -Current $disk -ValueProperty 'AvgDiskSecPerRead' -BaseProperty 'AvgDiskSecPerRead_Base' -FrequencyPerfTime $frequency
        $writeLatency = Get-AverageTimerDelta -Previous $previousDisk -Current $disk -ValueProperty 'AvgDiskSecPerWrite' -BaseProperty 'AvgDiskSecPerWrite_Base' -FrequencyPerfTime $frequency
        $elapsed = $null
        if ($null -ne $previousDisk -and $null -ne $frequency -and $frequency -gt 0) {
            $oldTicks = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $previousDisk -Names @('Timestamp_PerfTime', 'TimestampPerfTime'))
            $newTicks = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $disk -Names @('Timestamp_PerfTime', 'TimestampPerfTime'))
            if ($null -ne $oldTicks -and $null -ne $newTicks -and $newTicks -gt $oldTicks) { $elapsed = ($newTicks - $oldTicks) / $frequency }
        }
        $readRate = Get-RateFromDelta -Previous $previousDisk -Current $disk -Name 'DiskReadBytesPerSec' -ElapsedSeconds $elapsed
        $writeRate = Get-RateFromDelta -Previous $previousDisk -Current $disk -Name 'DiskWriteBytesPerSec' -ElapsedSeconds $elapsed
        $totalRate = Get-RateFromDelta -Previous $previousDisk -Current $disk -Name 'DiskBytesPerSec' -ElapsedSeconds $elapsed
        if ($null -eq $readRate -or $null -eq $writeRate -or $null -eq $totalRate) { $coverage += 'no-throughput-window' }
        $queue = ConvertTo-TelemetryFiniteDouble -Value (Get-TelemetryFirstProperty -InputObject $disk -Names @('CurrentDiskQueueLength', 'QueueLength'))
        if ($null -eq $queue) { $coverage += 'missing-queue' }
        foreach ($latency in @($readLatency, $writeLatency)) {
            if ($null -ne $latency -and $null -ne $latency.Reason) { $coverage += $latency.Reason }
        }
        $result += [pscustomobject]@{
            TimestampUtc = $TimestampUtc
            Name = $name
            ReadLatencySeconds = $readLatency.Value
            WriteLatencySeconds = $writeLatency.Value
            ReadBytesPerSec = $readRate
            WriteBytesPerSec = $writeRate
            TotalBytesPerSec = $totalRate
            CurrentQueueLength = $queue
            CoverageReason = @($coverage | Select-Object -Unique)
        }
    }
    return @($result)
}

Export-ModuleMember -Function * -Alias *
