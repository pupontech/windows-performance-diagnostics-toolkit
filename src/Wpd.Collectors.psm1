#Requires -Version 5.1
<#
.SYNOPSIS
    Collector orchestration for the Windows Performance Diagnostics toolkit.

.DESCRIPTION
    This module composes the inventory, telemetry, ETW, events, escalation and
    common modules into one orchestrated collection run. It owns:

      - the static tier map (Tier 0 inventory, Tier 1 interval counters,
        Tier 2 trace, Tier 3 consented escalation);
      - a plan that selects the requested tiers, resolves the functional preset
        and fixes the cadence floor and the bounded capture policy;
      - Tier 0 collection with one query per run behind a session cache;
      - Tier 1 collection after cadence validation (no sub-second sampling);
      - Tier 2 capture strategy: Repro versus Flight Recorder, both bounded;
      - Tier 3 adapters gated by their own consent switch;
      - storage reliability, filter, Defender/Search, boot, network, GPU and
        power context views;
      - per-collector result envelopes, cleanup and self-monitoring.

    Nothing in this module is a health verdict. Every collector envelope uses
    the shared status/coverage vocabulary (success, partial, unavailable,
    not-collected, unsupported, error) and 'healthy' is never a value.

    Every external dependency is a seam: providers, command runners, clocks,
    free-space values and consent switches are injected. Without a seam the
    module performs no Windows-only work and reports the limitation instead.

.NOTES
    Windows PowerShell 5.1 compatible: no classes, no PS7-only operators, no
    using statements, no sub-second sampling.
#>

Set-StrictMode -Version Latest

$script:WpdCollectorModuleRoot = $PSScriptRoot
$script:WpdCollectorDependencyModules = @(
    'Wpd.Common.psm1',
    'Wpd.Inventory.psm1',
    'Wpd.Telemetry.psm1',
    'Wpd.Etw.psm1',
    'Wpd.Events.psm1',
    'Wpd.Escalation.psm1'
)

foreach ($dependency in $script:WpdCollectorDependencyModules) {
    if ([string]::IsNullOrWhiteSpace($script:WpdCollectorModuleRoot)) { continue }
    $dependencyPath = Join-Path -Path $script:WpdCollectorModuleRoot -ChildPath $dependency
    if (Test-Path -LiteralPath $dependencyPath -PathType Leaf) {
        Import-Module -Name $dependencyPath -Force -DisableNameChecking -ErrorAction Stop
    }
}

$script:WpdCollectorTiers = @(0, 1, 2, 3)

# Tier 0 session cache: one entry per run key. Static inventory is queried once
# per run (plan D3); this is the collector-level cache the Tier 0 wrapper and
# the plan share, on top of the inventory module's own provider cache.
$script:WpdCollectorTier0Cache = @{}

# In-flight Tier 2 capture state. A capture body scriptblock runs in this
# module's session state, so it reads the capture state (commands, runner,
# marker pair) from script scope rather than from the caller's local scope.
$script:WpdCollectorCaptureState = $null
$script:WpdCollectorCaptureRunner = $null

$script:WpdCollectorShapeByTier = @{
    0 = 'inventory'
    1 = 'interval-counters'
    2 = 'trace'
    3 = 'escalation'
}

# Tier 1 counter families. Each row names the counterset family the telemetry
# module owns; the ids are the collector ids the manifest reports.
$script:WpdCollectorTier1Table = @(
    [pscustomobject]@{ id = 'cpu'; title = 'CPU utilization, queues and context switches'; dataShape = 'interval-counters'; counterset = 'Processor Information'; specRefs = @('spec 64', 'P1-3') }
    [pscustomobject]@{ id = 'gpu-engines'; title = 'GPU engine utilization and memory'; dataShape = 'interval-counters'; counterset = 'GPU Engine / GPU Adapter Memory'; specRefs = @('spec 65', 'P1-3') }
    [pscustomobject]@{ id = 'kernel-pool'; title = 'Kernel pool growth'; dataShape = 'interval-counters'; counterset = 'Memory'; specRefs = @('spec 24', 'P1-3') }
    [pscustomobject]@{ id = 'memory'; title = 'Process and system memory'; dataShape = 'interval-counters'; counterset = 'Process V2 / Memory'; specRefs = @('spec 22', 'P1-3') }
    [pscustomobject]@{ id = 'network'; title = 'Per-adapter throughput and error rates'; dataShape = 'interval-counters'; counterset = 'Network Interface'; specRefs = @('spec 31', 'P1-3') }
    [pscustomobject]@{ id = 'pagefile'; title = 'Page file usage and paging pressure'; dataShape = 'interval-counters'; counterset = 'Paging File'; specRefs = @('spec 23', 'P1-3') }
    [pscustomobject]@{ id = 'perflib'; title = 'Perflib and counter availability health'; dataShape = 'interval-counters'; counterset = 'Perflib'; specRefs = @('spec 68', 'P1-3') }
    [pscustomobject]@{ id = 'process'; title = 'Per-process CPU and memory series'; dataShape = 'interval-counters'; counterset = 'Process V2'; specRefs = @('spec 22', 'P1-3') }
    [pscustomobject]@{ id = 'storage-io'; title = 'Disk latency, queue length and throughput'; dataShape = 'interval-counters'; counterset = 'PhysicalDisk / LogicalDisk'; specRefs = @('spec 26', 'P1-3') }
)

# --------------------------------------------------------------------------
# Section 1: small local helpers (property, clock, vocabulary)
# --------------------------------------------------------------------------

function Get-WpdCollectorProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][object]$DefaultValue = $null
    )

    if ($null -eq $InputObject) { return $DefaultValue }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $DefaultValue
    }
    if ($null -eq $InputObject.PSObject) { return $DefaultValue }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $DefaultValue }
    return $property.Value
}

function Get-WpdCollectorUtcTimestamp {
    <#
    .SYNOPSIS
        The UTC timestamp source for a run, injectable for deterministic tests.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$ClockProvider)

    if ($null -ne $ClockProvider) {
        try {
            if ($ClockProvider -is [scriptblock]) { return (ConvertTo-WpdIsoTimestamp -Value (& $ClockProvider)) }
            return (ConvertTo-WpdIsoTimestamp -Value $ClockProvider)
        }
        catch {
            return $null
        }
    }
    return (ConvertTo-WpdIsoTimestamp -Value ([datetime]::UtcNow))
}

function Test-WpdCollectorWindowsHost {
    <#
    .SYNOPSIS
        Whether this process runs on Windows. The composed modules keep their
        own copy of this gate; this one labels collector envelopes.

    .DESCRIPTION
        The host answer is injectable so a non-Windows test host can exercise
        the Windows-only branches explicitly instead of relying on the platform
        it happens to run on.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$HostIsWindows)

    if ($null -ne $HostIsWindows) { return ([bool]$HostIsWindows) }
    return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
}

function Get-WpdCollectorTier0CacheKey {
    <#
    .SYNOPSIS
        The Tier 0 session-cache key for one run.

    .DESCRIPTION
        Tier 0 is static inventory: it is collected once per run (plan D3). The
        key is derived from the preset, the privacy level and a host
        fingerprint, so a second Tier 0 collector in the same run is served from
        the cache while a different privacy level gets its own projection.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Preset = 'general',
        [AllowEmptyString()][string]$PrivacyLevel = 'Standard',
        [AllowEmptyString()][string]$HostFingerprint = 'local',
        [AllowEmptyString()][string]$CacheKey
    )

    if (-not [string]::IsNullOrWhiteSpace($CacheKey)) { return $CacheKey }
    return ('tier0|preset={0}|privacy={1}|host={2}' -f $Preset, $PrivacyLevel, $HostFingerprint)
}

# --------------------------------------------------------------------------
# Section 2: static tier map
# --------------------------------------------------------------------------

function Get-WpdCollectorTierMap {
    <#
    .SYNOPSIS
        The static collector map: one row per collector, tier by tier.

    .DESCRIPTION
        Tier 0 rows are the inventory capability map (so a Tier 0 collector can
        only exist where the inventory module documents a read-only API), Tier 1
        rows are the interval counter families, Tier 2 is the trace, and Tier 3
        rows are the escalation adapters, all of which need their own consent.

        Rows are deterministic (tier ascending, then id ascending) and carry the
        elevation the collector needs, the module that owns it and the shape of
        the data it produces. No row is a health claim.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $rows = @()

    foreach ($capability in @(Get-WpdInventoryCapabilityMap)) {
        $rows += [pscustomobject]@{
            id                = [string]$capability.id
            tier              = 0
            title             = [string]$capability.title
            source            = 'Wpd.Inventory'
            requiredElevation = [string]$capability.requiredElevation
            elevationReason   = [string]$capability.elevationReason
            windowsOnly       = [bool]$capability.windowsOnly
            cached            = $true
            consentRequired   = $false
            dataShape         = $script:WpdCollectorShapeByTier[0]
            specRefs          = @($capability.specRefs)
        }
    }

    foreach ($family in $script:WpdCollectorTier1Table) {
        $rows += [pscustomobject]@{
            id                = [string]$family.id
            tier              = 1
            title             = [string]$family.title
            source            = 'Wpd.Telemetry'
            requiredElevation = 'standard'
            elevationReason   = 'Performance counter paths are readable without elevation; elevation is only needed to read counters of another user session'
            windowsOnly       = $true
            cached            = $false
            consentRequired   = $false
            dataShape         = [string]$family.dataShape
            specRefs          = @($family.specRefs)
        }
    }

    $rows += [pscustomobject]@{
        id                = 'trace'
        tier              = 2
        title             = 'ETW/WPR recording (Repro or Flight Recorder)'
        source            = 'Wpd.Etw'
        requiredElevation = 'administrator'
        elevationReason   = 'wpr.exe must run elevated to start and stop a recording'
        windowsOnly       = $true
        cached            = $false
        consentRequired   = $false
        dataShape         = $script:WpdCollectorShapeByTier[2]
        specRefs          = @('spec 47', 'spec 48', 'spec 51')
    }

    foreach ($descriptor in @(Get-WpdEscalationDescriptors)) {
        $rows += [pscustomobject]@{
            id                = [string]$descriptor.id
            tier              = 3
            title             = [string]$descriptor.title
            source            = 'Wpd.Escalation'
            requiredElevation = 'not-stated'
            elevationReason   = 'The escalation descriptor does not state an elevation requirement; the adapter consent switch is the gate, and an absent tool is reported instead of assumed'
            windowsOnly       = $true
            cached            = $false
            consentRequired   = $true
            dataShape         = $script:WpdCollectorShapeByTier[3]
            specRefs          = @('spec 6', 'P1-4')
        }
    }

    return @($rows | Sort-Object -Property tier, id)
}

# --------------------------------------------------------------------------
# Section 3: capture strategy (Repro versus Flight Recorder, bounded storage)
# --------------------------------------------------------------------------

function Get-WpdCaptureStrategy {
    <#
    .SYNOPSIS
        The bounded storage policy for a Repro or a Flight Recorder capture.

    .DESCRIPTION
        Both modes are bounded, but they are bounded differently:

        - Repro records while the operator reproduces the issue and stops
          interactively; memory mode (the documented default) keeps the
          recording inside the circular buffer.
        - Flight Recorder is a continuous recording that is bounded by the
          circular buffer and the preset's trace budget. It refuses file mode
          outright, because a file-mode recording grows until the disk fills and
          there is nothing that stops it.

        Nothing here executes wpr.exe: this is the policy the Tier 2 collector
        validates before it starts a recording.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Repro', 'FlightRecorder')][string]$CaptureMode = 'Repro',
        [AllowNull()][object]$PresetProfile,
        [AllowEmptyString()][string]$Preset = 'general',
        [AllowNull()][object]$PresetTable,
        [switch]$AcceptUnboundedFileMode
    )

    $profile = $PresetProfile
    if ($null -eq $profile) {
        $profile = Get-WpdEtwPresetProfile -Preset $Preset -PresetTable $PresetTable -AllowFileMode:$AcceptUnboundedFileMode
    }

    $budgetMB = 0
    if ($null -ne (Get-WpdCollectorProperty -InputObject $profile -Name 'TraceBudgetMB')) { $budgetMB = [int]$profile.TraceBudgetMB }
    $maxDuration = 0
    if ($null -ne (Get-WpdCollectorProperty -InputObject $profile -Name 'MaxDurationSeconds')) { $maxDuration = [int]$profile.MaxDurationSeconds }
    $profileSpec = [string](Get-WpdCollectorProperty -InputObject $profile -Name 'ProfileSpec' -Default '')
    $effectivePreset = [string](Get-WpdCollectorProperty -InputObject $profile -Name 'EffectivePreset' -Default $Preset)

    $reasons = @()
    $status = 'success'

    if ($CaptureMode -eq 'FlightRecorder') {
        $markers = @('CAPTURE_START', 'CAPTURE_STOP')
        $storagePolicy = 'circular-memory'
        $bounded = $true
        if ([bool](Get-WpdCollectorProperty -InputObject $profile -Name 'Unbounded' -Default $false)) {
            $storagePolicy = 'unbounded-file'
            $bounded = $false
            $status = 'partial'
            $reasons += 'flight-recorder-refuses-unbounded-file-mode'
        }
        return [pscustomobject]@{
            CaptureMode        = $CaptureMode
            EffectivePreset    = $effectivePreset
            ProfileSpec        = $profileSpec
            Mode               = 'memory'
            FileModeRequested  = $false
            FileModePermitted  = $false
            InteractiveStop    = $false
            Continuous         = $true
            StoragePolicy      = $storagePolicy
            Bounded            = $bounded
            TraceBudgetMB      = $budgetMB
            MaxDurationSeconds = $maxDuration
            DurationBoundedBy  = 'circular-buffer-and-preset-max-duration'
            MarkerPair         = $markers
            StopPolicy         = 'stop-at-window-end-or-operator-stop'
            Status             = $status
            Reasons            = $reasons
            Notes              = @(
                'A Flight Recorder run is continuous: it is bounded by the circular memory buffer and the preset trace budget, not by the operator stopping it.',
                'File mode is refused for a Flight Recorder run because an unbounded recording would grow until the disk fills.'
            )
            UnboundedFileRefused = $true
        }
    }

    $mode = 'memory'
    $unbounded = $false
    if ($AcceptUnboundedFileMode) {
        $mode = 'file'
        $unbounded = $true
    }
    $storagePolicy = 'circular-memory'
    if ($unbounded) { $storagePolicy = 'unbounded-file' }
    if ($unbounded) {
        $status = 'partial'
        $reasons += 'unbounded-file-mode-accepted-explicitly'
    }

    return [pscustomobject]@{
        CaptureMode        = $CaptureMode
        EffectivePreset    = $effectivePreset
        ProfileSpec        = $profileSpec
        Mode               = $mode
        FileModeRequested  = $unbounded
        FileModePermitted  = $unbounded
        InteractiveStop    = $true
        Continuous         = $false
        StoragePolicy      = $storagePolicy
        Bounded            = (-not $unbounded)
        TraceBudgetMB      = $budgetMB
        MaxDurationSeconds = $maxDuration
        DurationBoundedBy  = 'preset-max-duration'
        MarkerPair         = @('REPRO_START', 'CAPTURE_STOP')
        StopPolicy         = 'stop-after-reproduction'
        Status             = $status
        Reasons            = $reasons
        Notes              = @(
            'A Repro run records while the operator reproduces the issue and is stopped by the operator; the marker pair brackets the reproduction.',
            'Memory mode is the documented default, so the recording stays inside the circular buffer.'
        )
        UnboundedFileRefused = $false
    }
}

# --------------------------------------------------------------------------
# Section 4: collector result envelopes and self-monitoring
# --------------------------------------------------------------------------

function New-WpdCollectorSelfMonitoring {
    <#
    .SYNOPSIS
        The informational overhead record of one collector.

    .DESCRIPTION
        Duration, CPU time and working set of the collector itself. The values
        are measured only when -MeasureProcess is supplied (or injected by the
        caller), so a test host never measures the wrong process and a missing
        measurement stays unavailable instead of becoming zero.

        This record is informational: thresholds are an owner decision, so
        nothing here evaluates a pass/fail line (plan P2-1).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Collector,
        [AllowNull()][object]$Tier,
        [AllowNull()][object]$DurationMs,
        [AllowNull()][object]$CpuSeconds,
        [AllowNull()][object]$WorkingSetBytes,
        [AllowNull()][object]$PeakWorkingSetBytes,
        [AllowNull()][object]$SampleCount,
        [AllowEmptyString()][string]$MeasurementSource = 'injected',
        [switch]$MeasureProcess
    )

    $notes = @()
    $source = $MeasurementSource
    $probeFailed = $false
    $probeReason = $null

    if ($MeasureProcess) {
        $source = 'process-probe'
        try {
            $process = [System.Diagnostics.Process]::GetCurrentProcess()
            if ($null -eq $DurationMs -or $null -eq $CpuSeconds) {
                if ($null -eq $CpuSeconds) { $CpuSeconds = $process.TotalProcessorTime.TotalSeconds }
            }
            if ($null -eq $WorkingSetBytes) { $WorkingSetBytes = $process.WorkingSet64 }
            if ($null -eq $PeakWorkingSetBytes) {
                try { $PeakWorkingSetBytes = $process.PeakWorkingSet64 } catch { $PeakWorkingSetBytes = $null }
            }
        }
        catch {
            $probeFailed = $true
            $probeReason = $_.Exception.Message
            $source = 'process-probe-failed'
            $notes += ('The collector process could not be measured: {0}' -f $probeReason)
        }
    }

    $duration = $null
    if ($null -ne $DurationMs) {
        try { $duration = [int64]$DurationMs } catch { $duration = $null }
    }
    $cpu = $null
    if ($null -ne $CpuSeconds) {
        try { $cpu = [double]$CpuSeconds } catch { $cpu = $null }
    }
    $workingSet = $null
    if ($null -ne $WorkingSetBytes) {
        try { $workingSet = [int64]$WorkingSetBytes } catch { $workingSet = $null }
    }
    $peak = $null
    if ($null -ne $PeakWorkingSetBytes) {
        try { $peak = [int64]$PeakWorkingSetBytes } catch { $peak = $null }
    }
    $samples = 0
    if ($null -ne $SampleCount) {
        try { $samples = [int]$SampleCount } catch { $samples = 0 }
    }

    $cpuPercent = $null
    if ($null -ne $cpu -and $null -ne $duration -and $duration -gt 0) {
        $cpuPercent = [math]::Round(($cpu / ($duration / 1000.0)) * 100.0, 3)
    }

    $present = 0
    if ($null -ne $duration) { $present++ }
    if ($null -ne $cpu) { $present++ }
    if ($null -ne $workingSet) { $present++ }
    $measurementStatus = 'unavailable'
    if ($present -eq 3) { $measurementStatus = 'complete' }
    elseif ($present -gt 0) { $measurementStatus = 'partial' }

    if ($measurementStatus -ne 'complete') {
        $notes += 'A collector that could not be measured is reported unavailable, not as zero overhead.'
    }
    $notes += 'Overhead thresholds are an owner decision; this record is informational and evaluates no threshold.'

    return [pscustomobject]@{
        collector              = $Collector
        tier                   = $Tier
        status                 = 'informational'
        coverage               = $measurementStatus
        measurementStatus      = $measurementStatus
        measurementSource      = $source
        durationMs             = $duration
        cpuSeconds             = $cpu
        cpuPercentOfCollector  = $cpuPercent
        workingSetBytes        = $workingSet
        peakWorkingSetBytes    = $peak
        sampleCount            = $samples
        thresholdsEvaluated    = $false
        probeFailed            = $probeFailed
        notes                  = @($notes)
    }
}

function New-WpdCollectorEnvelope {
    <#
    .SYNOPSIS
        One collector's result envelope, in the shared vocabulary.

    .DESCRIPTION
        The envelope is the shared collector result (status, coverage, records,
        timestamps, warnings, errors) extended with the collector tier, the
        cache flag, the self-monitoring record, the cleanup outcome and the
        stated reasons.

        The shared rule is inherited, not re-implemented: an empty successful
        collector is unavailable, and 'healthy' is not a status, a coverage or a
        reason. The envelope never claims health.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Collector,
        [Parameter(Mandatory = $true)][int]$Tier,
        [AllowEmptyString()][string]$Status = 'unavailable',
        [AllowEmptyString()][string]$Coverage,
        [AllowNull()][object]$Records,
        [AllowNull()][object[]]$Warnings = @(),
        [AllowNull()][object[]]$Errors = @(),
        [AllowNull()][object[]]$Reasons = @(),
        [AllowNull()][object]$StartedUtc,
        [AllowNull()][object]$CompletedUtc,
        [AllowNull()][object]$DurationMs,
        [AllowEmptyString()][string]$Source,
        [AllowEmptyString()][string]$Reason,
        [switch]$Cached,
        [AllowNull()][object]$SelfMonitoring,
        [AllowEmptyString()][string]$CleanupStatus = 'not-needed',
        [AllowNull()][object[]]$CleanupPaths = @(),
        [AllowEmptyString()][string]$CleanupReason,
        [switch]$AllowEmpty
    )

    $result = New-WpdCollectorResult -Collector $Collector -Status $Status -Coverage $Coverage `
        -Records $Records -Warnings $Warnings -Errors $Errors -StartedUtc $StartedUtc `
        -CompletedUtc $CompletedUtc -DurationMs $DurationMs -Source $Source -Reason $Reason `
        -AllowEmpty:$AllowEmpty

    $statedReason = [string]$result.reason
    if ([string]::IsNullOrWhiteSpace($statedReason) -and [string]$result.status -eq 'unavailable' -and [int]$result.recordCount -eq 0) {
        $statedReason = 'no-records-returned'
    }

    # PowerShell variables are case-insensitive: the accumulator must not be
    # called $reasons, or it would shadow the -Reasons parameter.
    $reasonList = @()
    foreach ($item in @($Reasons)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$item)) { $reasonList += [string]$item }
    }
    if (-not [string]::IsNullOrWhiteSpace($statedReason) -and $reasonList -notcontains $statedReason) {
        $reasonList = @($statedReason) + $reasonList
    }

    $cleanup = [pscustomobject][ordered]@{
        status = $CleanupStatus
        reason = $CleanupReason
        paths  = @($CleanupPaths)
    }

    $interpretation = 'The collector produced records; this envelope is evidence, not a health verdict.'
    if ([string]$result.status -ne 'success') {
        $interpretation = ('The collector did not produce a complete result ({0}); no health is claimed.' -f [string]$result.status)
    }

    return [pscustomobject][ordered]@{
        collector      = $Collector
        id             = $Collector
        tier           = $Tier
        status         = $result.status
        coverage       = $result.coverage
        startedUtc     = $result.startedUtc
        completedUtc   = $result.completedUtc
        durationMs     = $result.durationMs
        duration_ms    = $result.duration_ms
        recordCount    = $result.recordCount
        records        = @($result.records)
        warnings       = @($result.warnings)
        errors         = @($result.errors)
        reasons        = @($reasonList)
        reason         = $statedReason
        source         = $Source
        cached         = [bool]$Cached
        cleanup        = $cleanup
        selfMonitoring = $SelfMonitoring
        healthClaim    = 'none'
        neverHealthy   = $true
        interpretation = $interpretation
    }
}

# --------------------------------------------------------------------------
# Section 5: collector plan
# --------------------------------------------------------------------------

function New-WpdCollectorPlan {
    <#
    .SYNOPSIS
        The ordered collection contract for one run.

    .DESCRIPTION
        The plan answers, before anything is collected: which tiers run, in
        which order, under which resolved preset, with which privacy level,
        which cadence (never below the 1 s floor) and which bounded capture
        policy. Tier 3 collectors are consent gated and are listed as such.

        An unknown preset is a stated unavailable plan, not an exception, so a
        caller can report it. An unknown tier is rejected, because a tier that
        does not exist cannot be collected.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Preset = 'general',
        [AllowNull()][object]$Tier = @(0, 1, 2),
        [AllowEmptyString()][string]$PrivacyLevel = 'Standard',
        [ValidateSet('Repro', 'FlightRecorder')][string]$CaptureMode = 'Repro',
        [AllowNull()][object]$RequestedSampleIntervalSeconds,
        [AllowNull()][object]$Config,
        [AllowNull()][object]$PresetTable,
        [AllowNull()][object]$ClockProvider,
        [switch]$AcceptUnboundedFileMode
    )

    $tiers = @()
    foreach ($item in @($Tier)) {
        $value = 0
        try { $value = [int]$item } catch { $value = -1 }
        if ($script:WpdCollectorTiers -notcontains $value) {
            throw [System.ArgumentException]::new(
                ("unknown collector tier '{0}'; valid tiers are {1}" -f $item, ($script:WpdCollectorTiers -join ', '))
            )
        }
        if ($tiers -notcontains $value) { $tiers += $value }
    }
    $tiers = @($tiers | Sort-Object)
    if ($tiers.Count -eq 0) { $tiers = @(0) }

    $generatedUtc = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider

    $presetProfile = $null
    try {
        $presetProfile = Get-WpdEtwPresetProfile -Preset $Preset -PresetTable $PresetTable
    }
    catch {
        return [pscustomobject][ordered]@{
            id                      = 'plan-unavailable'
            status                  = 'unavailable'
            coverage                = 'unavailable'
            reason                  = 'unknown-preset'
            reasons                 = @('unknown-preset')
            preset                  = $Preset
            effectivePreset         = $Preset
            isAlias                 = $false
            privacyLevel            = $PrivacyLevel
            tiers                   = @($tiers)
            collectors              = @()
            collectorCount          = 0
            consentRequiredCollectors = @()
            requiresConsent         = $false
            requiresWindows         = $true
            captureMode             = $CaptureMode
            captureStrategy         = $null
            sampling                = $null
            generatedUtc            = $generatedUtc
            warnings                = @()
            errors                  = @([pscustomobject]@{ stage = 'plan'; message = $_.Exception.Message })
            healthClaim             = 'none'
        }
    }

    $collectors = @()
    $order = 0
    foreach ($row in @(Get-WpdCollectorTierMap)) {
        if ($tiers -notcontains [int]$row.tier) { continue }
        $order++
        $entry = $row.PSObject.Copy()
        Add-Member -InputObject $entry -MemberType NoteProperty -Name 'planOrder' -Value $order -Force
        $collectors += $entry
    }

    $consentIds = @($collectors | Where-Object { $_.consentRequired } | ForEach-Object { $_.id })
    $requiresWindows = (@($collectors | Where-Object { $_.windowsOnly }).Count -gt 0)

    $captureStrategy = $null
    if ($tiers -contains 2) {
        $captureStrategy = Get-WpdCaptureStrategy -CaptureMode $CaptureMode -PresetProfile $presetProfile `
            -Preset $Preset -PresetTable $PresetTable -AcceptUnboundedFileMode:$AcceptUnboundedFileMode
    }

    $sampling = $null
    if ($tiers -contains 1) {
        $requested = $RequestedSampleIntervalSeconds
        if ($null -eq $requested) { $requested = 1.0 }
        $sampling = New-TelemetrySamplingPlan -RequestedIntervalSeconds $requested -Config $Config
    }

    $status = 'success'
    $warnings = @()
    $reasons = @()
    if ($collectors.Count -eq 0) {
        $status = 'unavailable'
        $reasons += 'no-collector-selected'
    }
    if ($null -ne $sampling -and [string]$sampling.Status -ne 'accepted') {
        $status = 'partial'
        $reasons += ('sampling-interval-' + [string]$sampling.Status)
        $warnings += ('The requested sampling interval of {0} s was not accepted; the effective interval is {1} s.' -f $sampling.RequestedIntervalSeconds, $sampling.EffectiveIntervalSeconds)
    }
    if ($null -ne $captureStrategy -and [string]$captureStrategy.Status -ne 'success') {
        $status = 'partial'
        foreach ($item in @($captureStrategy.Reasons)) { $reasons += [string]$item }
    }

    $identity = '{0}|{1}|{2}|{3}|{4}' -f $Preset, $PrivacyLevel, $CaptureMode, ($tiers -join '-'), ($consentIds -join '-')
    $planId = 'plan-' + (Get-WpdSha256Text -Value $identity).Substring(0, 12)

    return [pscustomobject][ordered]@{
        id                        = $planId
        status                    = $status
        coverage                  = $(if ($status -eq 'success') { 'complete' } else { 'partial' })
        reason                    = $(if ($reasons.Count -gt 0) { [string]$reasons[0] } else { $null })
        reasons                   = @($reasons)
        preset                    = $Preset
        effectivePreset           = [string]$presetProfile.EffectivePreset
        isAlias                   = [bool]$presetProfile.IsAlias
        privacyLevel              = Get-WpdPrivacyLevel -Level $PrivacyLevel
        tiers                     = @($tiers)
        collectors                = @($collectors)
        collectorCount            = $collectors.Count
        consentRequiredCollectors = @($consentIds)
        requiresConsent           = ($consentIds.Count -gt 0)
        requiresWindows           = $requiresWindows
        captureMode               = $CaptureMode
        captureStrategy           = $captureStrategy
        sampling                  = $sampling
        generatedUtc              = $generatedUtc
        warnings                  = @($warnings)
        errors                    = @()
        healthClaim               = 'none'
    }
}

# --------------------------------------------------------------------------
# Section 6: Tier 0 collection (static inventory, once per run)
# --------------------------------------------------------------------------

function Get-WpdTier0CapabilitySource {
    <#
    .SYNOPSIS
        Read one capability envelope out of an inventory-shaped result.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InventoryResult,
        [Parameter(Mandatory = $true)][string]$Id
    )

    if ($null -eq $InventoryResult) { return $null }
    $capabilities = Get-WpdCollectorProperty -InputObject $InventoryResult -Name 'capabilities'
    if ($null -eq $capabilities) { return $null }
    if ($capabilities -is [System.Collections.IDictionary]) {
        if ($capabilities.Contains($Id)) { return $capabilities[$Id] }
        return $null
    }
    return (Get-WpdCollectorProperty -InputObject $capabilities -Name $Id)
}

function ConvertTo-WpdTier0CapabilityRecord {
    <#
    .SYNOPSIS
        Normalize one capability envelope into the Tier 0 record the wrapper
        carries, or state why the capability has no record.

    .DESCRIPTION
        A capability the provider did not return is 'unavailable' with the
        reason capability-not-returned. It is never silently dropped and it is
        never treated as clean.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [AllowNull()][object]$Envelope
    )

    if ($null -eq $Envelope) {
        return [pscustomobject][ordered]@{
            capability = $Id
            status     = 'unavailable'
            coverage   = 'unavailable'
            reason     = 'capability-not-returned'
            recordCount = 0
            items      = @()
            reasons    = @('capability-not-returned')
            warnings   = @()
            errors     = @()
            source     = $null
        }
    }

    $items = @(Get-WpdCollectorProperty -InputObject $Envelope -Name 'items' -Default @())
    $declaredCount = Get-WpdCollectorProperty -InputObject $Envelope -Name 'recordCount'
    $recordCount = $items.Count
    if ($null -ne $declaredCount) {
        try { $recordCount = [int]$declaredCount } catch { $recordCount = $items.Count }
    }

    return [pscustomobject][ordered]@{
        capability  = $Id
        status      = [string](Get-WpdCollectorProperty -InputObject $Envelope -Name 'status' -Default 'unavailable')
        coverage    = [string](Get-WpdCollectorProperty -InputObject $Envelope -Name 'coverage' -Default 'unavailable')
        reason      = Get-WpdCollectorProperty -InputObject $Envelope -Name 'reason'
        recordCount = $recordCount
        items       = @($items)
        reasons     = @(Get-WpdCollectorProperty -InputObject $Envelope -Name 'reasons' -Default @())
        warnings    = @(Get-WpdCollectorProperty -InputObject $Envelope -Name 'warnings' -Default @())
        errors      = @(Get-WpdCollectorProperty -InputObject $Envelope -Name 'errors' -Default @())
        source      = Get-WpdCollectorProperty -InputObject $Envelope -Name 'source'
    }
}

function Invoke-WpdTier0Collection {
    <#
    .SYNOPSIS
        Collect (or read) Tier 0 static inventory for one run.

    .DESCRIPTION
        Tier 0 is collected once per run (plan D3): the capability envelopes a
        provider returned are cached under the run's cache key, so a second
        Tier 0 call in the same run is served from the cache and the provider is
        not queried again. -Refresh re-queries explicitly.

        Each capability keeps its own envelope, so an unsupported or unavailable
        capability (an absent reliability counter, a capability that needs
        administrator, a capability the provider did not return) is stated
        instead of hiding its siblings. Tier 1 must never re-query Tier 0: it
        reads these envelopes.

        The aggregate status and coverage come from the shared data-quality
        summary, so an empty or unsupported Tier 0 result is never healthy.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$CacheKey,
        [AllowEmptyString()][string]$Preset = 'general',
        [AllowEmptyString()][string]$PrivacyLevel = 'Standard',
        [AllowEmptyString()][string]$HostFingerprint = 'local',
        [AllowNull()][object]$InventoryProvider,
        [AllowNull()][object]$Providers,
        [AllowNull()][object]$Context,
        [AllowNull()][object]$Capability,
        [AllowNull()][object]$ClockProvider,
        [AllowNull()][object]$SelfMonitoring,
        [switch]$Refresh
    )

    $hostWindows = Test-WpdCollectorWindowsHost
    $key = Get-WpdCollectorTier0CacheKey -Preset $Preset -PrivacyLevel $PrivacyLevel -HostFingerprint $HostFingerprint -CacheKey $CacheKey
    $startedUtc = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider

    $tier0Ids = @(Get-WpdCollectorTierMap | Where-Object { $_.tier -eq 0 } | ForEach-Object { $_.id })
    $requested = @()
    if ($null -eq $Capability -or @($Capability).Count -eq 0) {
        $requested = @($tier0Ids)
    }
    else {
        foreach ($id in @($Capability)) {
            $value = [string]$id
            if ($tier0Ids -notcontains $value) {
                throw [System.ArgumentException]::new(
                    ("unknown Tier 0 capability '{0}'; Tier 0 capabilities are {1}" -f $value, ($tier0Ids -join ', '))
                )
            }
            if ($requested -notcontains $value) { $requested += $value }
        }
    }

    $providerCalls = 0
    $cachedEnvelopes = $null
    $cacheHit = $false
    $providerErrors = @()

    if (-not $Refresh -and $script:WpdCollectorTier0Cache.ContainsKey($key)) {
        $cachedEnvelopes = $script:WpdCollectorTier0Cache[$key]['envelopes']
        $cacheHit = $true
    }
    else {
        $providerResult = $null
        $providerCalls = 1
        if ($null -ne $InventoryProvider) {
            $request = [pscustomobject][ordered]@{
                cacheKey     = $key
                capability   = @($requested)
                privacyLevel = Get-WpdPrivacyLevel -Level $PrivacyLevel
                providers    = $Providers
                context      = $Context
                refresh      = [bool]$Refresh
                preset       = $Preset
            }
            try {
                $providerResult = & $InventoryProvider $request
            }
            catch {
                $providerErrors += [pscustomobject]@{ stage = 'tier0-provider'; message = $_.Exception.Message }
                $providerResult = $null
            }
        }
        else {
            try {
                $providerResult = Get-WpdInventory -Providers $Providers -Context $Context `
                    -PrivacyLevel $PrivacyLevel -CacheKey $key -Refresh:$Refresh
            }
            catch {
                $providerErrors += [pscustomobject]@{ stage = 'tier0-inventory'; message = $_.Exception.Message }
                $providerResult = $null
            }
        }

        if ($null -ne $providerResult -and $null -ne (Get-WpdCollectorProperty -InputObject $providerResult -Name 'capabilities')) {
            $cachedEnvelopes = @{}
            $order = @(Get-WpdCollectorProperty -InputObject $providerResult -Name 'capabilityOrder' -Default @())
            if ($order.Count -eq 0) {
                $capabilities = Get-WpdCollectorProperty -InputObject $providerResult -Name 'capabilities'
                if ($capabilities -is [System.Collections.IDictionary]) {
                    $order = @($capabilities.Keys)
                }
            }
            foreach ($id in @($order)) {
                $cachedEnvelopes[[string]$id] = Get-WpdTier0CapabilitySource -InventoryResult $providerResult -Id ([string]$id)
            }
            $script:WpdCollectorTier0Cache[$key] = @{
                key         = $key
                createdUtc  = $startedUtc
                requested   = @($requested)
                envelopes   = $cachedEnvelopes
                privacyLevel = Get-WpdPrivacyLevel -Level $PrivacyLevel
            }
        }
        elseif ($null -eq $providerResult) {
            $cachedEnvelopes = @{}
        }
        else {
            $providerErrors += [pscustomobject]@{
                stage   = 'tier0-provider'
                message = 'The provider result carried no capabilities collection, so no Tier 0 capability could be projected.'
            }
            $cachedEnvelopes = @{}
        }
    }

    $records = @()
    foreach ($id in $requested) {
        $source = $null
        if ($null -ne $cachedEnvelopes -and $cachedEnvelopes.ContainsKey($id)) { $source = $cachedEnvelopes[$id] }
        $records += ConvertTo-WpdTier0CapabilityRecord -Id $id -Envelope $source
    }

    $completedUtc = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider
    $quality = Get-WpdDataQualitySummary -Records $records
    $itemRecordCount = 0
    foreach ($record in $records) { $itemRecordCount += [int]$record.recordCount }

    $status = [string]$quality.status
    $coverage = [string]$quality.coverage
    if (-not $cacheHit -and $providerCalls -eq 1 -and $providerErrors.Count -gt 0 -and $records.Count -eq 0) {
        $status = 'error'
        $coverage = 'unavailable'
    }

    $monitoring = $SelfMonitoring
    if ($null -eq $monitoring) {
        $monitoring = New-WpdCollectorSelfMonitoring -Collector 'tier0-inventory' -Tier 0 `
            -DurationMs $null -CpuSeconds $null -WorkingSetBytes $null -SampleCount $records.Count `
            -MeasurementSource 'not-measured'
    }

    $reasons = @()
    foreach ($reason in @($quality.reasons)) { $reasons += [string]$reason }
    if (-not $hostWindows) { $reasons += 'host-not-windows' }
    if ($cacheHit) { $reasons += 'served-from-tier0-cache' }
    if ($providerErrors.Count -gt 0) { $reasons += 'tier0-provider-error' }

    $envelope = New-WpdCollectorEnvelope -Collector 'tier0-inventory' -Tier 0 -Status $status -Coverage $coverage `
        -Records $records -Warnings @($quality.warnings) -Errors @($providerErrors) -Reasons $reasons `
        -StartedUtc $startedUtc -CompletedUtc $completedUtc `
        -Source $(if ($null -ne $InventoryProvider) { 'injected-tier0-provider' } else { 'Wpd.Inventory' }) `
        -Cached:$cacheHit -SelfMonitoring $monitoring -CleanupStatus 'not-needed'

    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'cacheKey' -Value $key -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'cacheHit' -Value $cacheHit -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'providerCallCount' -Value $providerCalls -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'capabilityCount' -Value $records.Count -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'capabilityOrder' -Value @($requested) -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'itemRecordCount' -Value $itemRecordCount -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'capabilityCounts' -Value $quality -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'hostWindows' -Value $hostWindows -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'privacyLevel' -Value (Get-WpdPrivacyLevel -Level $PrivacyLevel) -Force

    return $envelope
}

function Clear-WpdCollectorTier0Cache {
    <#
    .SYNOPSIS
        Drop the collector-level Tier 0 cache (all keys, or one key).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$CacheKey)

    if ([string]::IsNullOrWhiteSpace($CacheKey)) {
        $script:WpdCollectorTier0Cache = @{}
        return
    }
    if ($script:WpdCollectorTier0Cache.ContainsKey($CacheKey)) {
        $script:WpdCollectorTier0Cache.Remove($CacheKey)
    }
}

# --------------------------------------------------------------------------
# Section 7: Tier 1 collection (interval counters after cadence validation)
# --------------------------------------------------------------------------

function Invoke-WpdTier1Collection {
    <#
    .SYNOPSIS
        Sample one Tier 1 counter family after validating the cadence.

    .DESCRIPTION
        Performance counters are not designed for sub-second sampling, so an
        interval below the documented 1 s floor is rejected before any counter is
        read: the result is unavailable with the requested and effective
        intervals stated, and the provider seam is never invoked.

        With a valid cadence the sampling loop runs with the injected clock,
        sleep and provider seams, and the observed samples become a per-process
        series. Coverage is derived from expected versus observed samples and the
        detected gaps, so a missed interval is reported as partial coverage
        rather than smoothed away. No result of this function is a verdict.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Family = 'cpu',
        [AllowNull()][object]$SampleIntervalSeconds,
        [AllowNull()][object]$SampleCount,
        [AllowNull()][object]$DurationSeconds,
        [AllowNull()][object]$Provider,
        [AllowNull()][object]$ClockProvider,
        [AllowNull()][object]$SleepProvider,
        [AllowNull()][object]$LogicalProcessorCount,
        [AllowNull()][object]$Config,
        [AllowNull()][object]$SelfMonitoring
    )

    $tier1Ids = @(Get-WpdCollectorTierMap | Where-Object { $_.tier -eq 1 } | ForEach-Object { $_.id })
    if ($tier1Ids -notcontains $Family) {
        throw [System.ArgumentException]::new(
            ("unknown Tier 1 counter family '{0}'; Tier 1 families are {1}" -f $Family, ($tier1Ids -join ', '))
        )
    }

    $hostWindows = Test-WpdCollectorWindowsHost
    $plan = New-TelemetrySamplingPlan -RequestedIntervalSeconds $SampleIntervalSeconds -Config $Config

    $common = [ordered]@{
        family                 = $Family
        cadenceValidated       = $false
        sampleIntervalSeconds  = if ($null -ne $plan.RequestedIntervalSeconds) { [double]$plan.RequestedIntervalSeconds } else { $null }
        effectiveIntervalSeconds = $plan.EffectiveIntervalSeconds
        floorSeconds           = $plan.FloorSeconds
        samplingPlan           = $plan
        expectedSamples        = 0
        observedSamples        = 0
        gapCount               = 0
        gaps                   = @()
        observedDurationSeconds = $null
        samplingStatus         = $null
        hostWindows            = $hostWindows
        series                 = @()
    }

    if ([string]$plan.Status -ne 'accepted') {
        $reason = if ([string]$plan.Status -eq 'clamped') { 'sampling-interval-below-floor' } else { 'sampling-interval-invalid' }
        $monitoring = $SelfMonitoring
        if ($null -eq $monitoring) {
            $monitoring = New-WpdCollectorSelfMonitoring -Collector $Family -Tier 1 -DurationMs 0 `
                -MeasureProcess:$false -MeasurementSource 'rejected-before-sampling'
        }
        $envelope = New-WpdCollectorEnvelope -Collector $Family -Tier 1 -Status 'unavailable' -Coverage 'unavailable' `
            -Records @() -Reasons @($reason, 'no-sampling-performed') -Reason $reason `
            -Source 'cadence-validation' -SelfMonitoring $monitoring
        foreach ($key in $common.Keys) {
            Add-Member -InputObject $envelope -MemberType NoteProperty -Name $key -Value $common[$key] -Force
        }
        return $envelope
    }

    $expected = 0
    if ($null -ne $SampleCount) {
        try { $expected = [int]$SampleCount } catch { $expected = 0 }
    }
    elseif ($null -ne $DurationSeconds) {
        $duration = [double]$DurationSeconds
        $expected = [int][math]::Floor($duration / [double]$plan.EffectiveIntervalSeconds) + 1
    }
    if ($expected -le 0) { $expected = 1 }

    $startedUtc = Get-WpdCollectorUtcTimestamp -ClockProvider $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $sampling = Invoke-ProcessTelemetrySampling -Provider $Provider -SampleCount $SampleCount `
        -DurationSeconds $DurationSeconds -SampleIntervalSeconds $plan.EffectiveIntervalSeconds `
        -LogicalProcessorCount $LogicalProcessorCount -Config $Config `
        -ClockProvider $ClockProvider -SleepProvider $SleepProvider
    $stopwatch.Stop()

    $observed = 0
    if ($null -ne (Get-WpdCollectorProperty -InputObject $sampling -Name 'SampleCount')) { $observed = [int]$sampling.SampleCount }
    $gapCount = 0
    if ($null -ne (Get-WpdCollectorProperty -InputObject $sampling -Name 'GapCount')) { $gapCount = [int]$sampling.GapCount }
    $gaps = @(Get-WpdCollectorProperty -InputObject $sampling -Name 'Gaps' -Default @())
    $series = @(Get-WpdCollectorProperty -InputObject $sampling -Name 'Series' -Default @())
    $observedDuration = Get-WpdCollectorProperty -InputObject $sampling -Name 'ObservedDurationSeconds'
    $samplingStatus = [string](Get-WpdCollectorProperty -InputObject $sampling -Name 'samplingStatus' -Default (Get-WpdCollectorProperty -InputObject $sampling -Name 'Status' -Default 'unavailable'))

    $mappedStatus = 'unavailable'
    if ($samplingStatus -eq 'complete') { $mappedStatus = 'success' }
    elseif ($samplingStatus -eq 'partial') { $mappedStatus = 'partial' }

    $coverage = Resolve-WpdCoverageState -Status $mappedStatus -ExpectedSamples $expected `
        -ObservedSamples $observed -GapCount $gapCount

    $reasons = @()
    if ($gapCount -gt 0) { $reasons += 'sampling-gap' }
    if ($series.Count -eq 0) {
        $reasons += 'no-process-rows-observed'
        $mappedStatus = 'unavailable'
        $coverage = 'unavailable'
    }
    elseif ($mappedStatus -eq 'partial') {
        $reasons += 'partial-sampling-coverage'
    }

    $monitoring = $SelfMonitoring
    if ($null -eq $monitoring) {
        $monitoring = New-WpdCollectorSelfMonitoring -Collector $Family -Tier 1 `
            -DurationMs $stopwatch.ElapsedMilliseconds -SampleCount $observed `
            -MeasurementSource 'collector-stopwatch'
    }

    $envelope = New-WpdCollectorEnvelope -Collector $Family -Tier 1 -Status $mappedStatus -Coverage $coverage `
        -Records $series -Reasons $reasons `
        -Reason $(if ($series.Count -eq 0) { 'no-process-rows-observed' } else { $null }) `
        -StartedUtc $startedUtc `
        -CompletedUtc (Get-WpdCollectorUtcTimestamp -ClockProvider $null) `
        -Source 'Wpd.Telemetry' -SelfMonitoring $monitoring

    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'family' -Value $Family -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'cadenceValidated' -Value $true -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'sampleIntervalSeconds' -Value $common['sampleIntervalSeconds'] -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'effectiveIntervalSeconds' -Value $plan.EffectiveIntervalSeconds -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'floorSeconds' -Value $plan.FloorSeconds -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'samplingPlan' -Value $plan -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'expectedSamples' -Value $expected -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'observedSamples' -Value $observed -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'gapCount' -Value $gapCount -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'gaps' -Value @($gaps) -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'observedDurationSeconds' -Value $observedDuration -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'samplingStatus' -Value $samplingStatus -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'hostWindows' -Value $hostWindows -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'series' -Value @($series) -Force

    return $envelope
}

# --------------------------------------------------------------------------
# Section 8: Tier 2 capture (bounded storage, Repro versus Flight Recorder)
# --------------------------------------------------------------------------

function Get-WpdCollectorCoverageForStatus {
    <#
    .SYNOPSIS
        The coverage state that belongs to a collector status, in the shared
        vocabulary. 'healthy' is not a reachable answer.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Status)

    switch ($Status) {
        'success' { return 'complete' }
        'partial' { return 'partial' }
        'unsupported' { return 'unsupported' }
        'not-collected' { return 'not-collected' }
        default { return 'unavailable' }
    }
}

function Test-WpdCaptureStorageBound {
    <#
    .SYNOPSIS
        Whether a capture is allowed to start, given its bounded storage policy.

    .DESCRIPTION
        The bound is checked before any recording starts:

        - an unbounded file-mode recording is refused unless the caller
          explicitly accepts that the trace grows until the disk fills;
        - a requested duration above the preset maximum is refused;
        - the free space on the target volume must cover the preset budget plus
          headroom, and an unmeasurable free space is 'unavailable', never a
          pass.

        The free-space, duration and budget checks are the ETW module's
        documented preflight; this function adds the capture-mode policy on top
        and reports the bound in one record.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Strategy,
        [AllowNull()][object]$FreeSpaceBytes,
        [AllowEmptyString()][string]$OutputDirectory,
        [AllowNull()][object]$RequestedDurationSeconds,
        [AllowNull()][object]$MaxTraceSizeMB,
        [switch]$AcceptUnboundedFileMode
    )

    if ($null -eq $Strategy) {
        return [pscustomobject][ordered]@{
            Status         = 'strategy-required'
            Ready          = $false
            Bounded        = $false
            StoragePolicy  = $null
            Reason         = 'The capture storage bound cannot be checked without a capture strategy.'
            TraceBudgetMB  = $null
            FreeSpaceBytes = $FreeSpaceBytes
            RequiredBytes  = $null
            DeficitBytes   = $null
            Preflight      = $null
            Strategy       = $null
        }
    }

    $storagePolicy = [string](Get-WpdCollectorProperty -InputObject $Strategy -Name 'StoragePolicy' -Default 'circular-memory')
    $bounded = [bool](Get-WpdCollectorProperty -InputObject $Strategy -Name 'Bounded' -Default $true)
    $budgetMB = Get-WpdCollectorProperty -InputObject $Strategy -Name 'TraceBudgetMB'
    $maxDuration = Get-WpdCollectorProperty -InputObject $Strategy -Name 'MaxDurationSeconds'
    $mode = [string](Get-WpdCollectorProperty -InputObject $Strategy -Name 'Mode' -Default 'memory')

    if ($storagePolicy -eq 'unbounded-file' -and -not $AcceptUnboundedFileMode) {
        return [pscustomobject][ordered]@{
            Status         = 'unbounded-file-mode'
            Ready          = $false
            Bounded        = $false
            StoragePolicy  = $storagePolicy
            Reason         = 'File mode records to an unbounded file that grows until the disk fills; it is refused unless the caller explicitly accepts an unbounded recording.'
            TraceBudgetMB  = $budgetMB
            FreeSpaceBytes = $FreeSpaceBytes
            RequiredBytes  = $null
            DeficitBytes   = $null
            Preflight      = $null
            Strategy       = $Strategy
        }
    }

    $profile = [pscustomobject]@{
        TraceBudgetMB      = $budgetMB
        MaxDurationSeconds = $maxDuration
        Mode               = $mode
        Unbounded          = (-not $bounded)
    }

    # Only the supplied inputs reach the preflight: an absent free-space value
    # stays unmeasured (and therefore unavailable) instead of being guessed from
    # whatever drive the current directory happens to be on.
    $preflightArguments = @{
        PresetProfile            = $profile
        AcceptUnboundedFileMode  = [bool]$AcceptUnboundedFileMode
    }
    if ($null -ne $FreeSpaceBytes) { $preflightArguments['FreeSpaceBytes'] = $FreeSpaceBytes }
    if (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) { $preflightArguments['OutputDirectory'] = $OutputDirectory }
    if ($null -ne $RequestedDurationSeconds) { $preflightArguments['RequestedDurationSeconds'] = $RequestedDurationSeconds }
    if ($null -ne $MaxTraceSizeMB) { $preflightArguments['MaxTraceSizeMB'] = $MaxTraceSizeMB }

    $preflight = Test-WpdEtwCapturePreflight @preflightArguments

    return [pscustomobject][ordered]@{
        Status         = [string]$preflight.Status
        Ready          = [bool]$preflight.Ready
        Bounded        = $bounded
        StoragePolicy  = $storagePolicy
        Reason         = [string]$preflight.Reason
        TraceBudgetMB  = $preflight.TraceBudgetMB
        FreeSpaceBytes = $preflight.FreeSpaceBytes
        RequiredBytes  = $preflight.RequiredBytes
        DeficitBytes   = $preflight.DeficitBytes
        Preflight      = $preflight
        Strategy       = $Strategy
    }
}

function Invoke-WpdTier2Collection {
    <#
    .SYNOPSIS
        Run one bounded Tier 2 ETW/WPR capture.

    .DESCRIPTION
        The order is fixed and documented: resolve the preset, fix the bounded
        storage policy, preflight it, then -start, the incident marker pair, the
        capture body, -stop, and finally validate the produced trace.

        A capture that cannot be bounded never starts. A refused file mode, a
        duration above the preset maximum, an unmeasured free space or a deficit
        all end as a stated result with no command executed.

        A host that is not Windows cannot record: without an injected runner the
        result is 'unsupported', not an error. With an injected runner the whole
        sequence is exercised without executing wpr.exe anywhere.

        Cleanup is not optional: the stop is issued inside the ETW module's
        try/finally, so a body that throws still stops the recording, and every
        command that ran is kept as evidence in the envelope.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Preset = 'general',
        [ValidateSet('Repro', 'FlightRecorder')][string]$CaptureMode = 'Repro',
        [AllowEmptyString()][string]$EtlPath,
        [AllowEmptyString()][string]$InstanceName = 'wpd-collect',
        [AllowEmptyString()][string]$ProblemDescription,
        [AllowEmptyString()][string]$WprExePath,
        [AllowNull()][object]$PresetProfile,
        [AllowNull()][object]$PresetTable,
        [AllowNull()][object]$Runner,
        [AllowNull()][object]$StatusProbe,
        [AllowNull()][object]$Body,
        [AllowNull()][object]$WaitProvider,
        [AllowNull()][object]$FreeSpaceBytes,
        [AllowEmptyString()][string]$OutputDirectory,
        [AllowNull()][object]$RequestedDurationSeconds,
        [AllowNull()][object]$MaxTraceSizeMB,
        [AllowNull()][object]$SizeBytes,
        [AllowNull()][object]$ClockProvider,
        [AllowNull()][object]$SelfMonitoring,
        [AllowNull()][object]$HostIsWindows,
        [switch]$AllowFileMode,
        [switch]$AcceptUnboundedFileMode
    )

    $hostWindows = Test-WpdCollectorWindowsHost -HostIsWindows $HostIsWindows
    $startedUtc = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider
    $commandLog = New-Object System.Collections.ArrayList

    $profile = $PresetProfile
    if ($null -eq $profile) {
        try {
            $profile = Get-WpdEtwPresetProfile -Preset $Preset -PresetTable $PresetTable -AllowFileMode:$AllowFileMode
        }
        catch {
            $envelope = New-WpdCollectorEnvelope -Collector 'trace' -Tier 2 -Status 'unavailable' -Coverage 'unavailable' `
                -Records @() -Reason 'unknown-preset' -Reasons @('unknown-preset') `
                -Errors @([pscustomobject]@{ stage = 'preset'; message = $_.Exception.Message }) -Source 'Wpd.Etw'
            Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'preset' -Value $Preset -Force
            Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'captureMode' -Value $CaptureMode -Force
            Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'hostWindows' -Value $hostWindows -Force
            return $envelope
        }
    }

    $strategy = Get-WpdCaptureStrategy -CaptureMode $CaptureMode -PresetProfile $profile `
        -Preset $Preset -PresetTable $PresetTable -AcceptUnboundedFileMode:$AcceptUnboundedFileMode

    $bound = Test-WpdCaptureStorageBound -Strategy $strategy -FreeSpaceBytes $FreeSpaceBytes `
        -OutputDirectory $OutputDirectory -RequestedDurationSeconds $RequestedDurationSeconds `
        -MaxTraceSizeMB $MaxTraceSizeMB -AcceptUnboundedFileMode:$AcceptUnboundedFileMode

    $commonFields = [ordered]@{
        preset          = $Preset
        effectivePreset = [string](Get-WpdCollectorProperty -InputObject $profile -Name 'EffectivePreset' -Default $Preset)
        captureMode     = $CaptureMode
        strategy        = $strategy
        storageBound    = $bound
        capture         = $null
        traceValidation = $null
        commands        = @()
        markers         = @($strategy.MarkerPair)
        etlPath         = $(if ([string]::IsNullOrWhiteSpace($EtlPath)) { $null } else { $EtlPath })
        instanceName    = $InstanceName
        reproductionRequired = ($CaptureMode -eq 'Repro')
        hostWindows     = $hostWindows
        traceBudgetMB   = $strategy.TraceBudgetMB
        maxDurationSeconds = $strategy.MaxDurationSeconds
    }

    $finish = {
        param($Envelope, $Fields)

        foreach ($key in $Fields.Keys) {
            Add-Member -InputObject $Envelope -MemberType NoteProperty -Name $key -Value $Fields[$key] -Force
        }
        return $Envelope
    }

    if (-not $hostWindows -and $null -eq $Runner) {
        $envelope = New-WpdCollectorEnvelope -Collector 'trace' -Tier 2 -Status 'unsupported' -Coverage 'unsupported' `
            -Records @() -Reason 'host-not-windows' -Reasons @('host-not-windows', 'no-command-executed') `
            -Source 'Wpd.Etw' -CleanupStatus 'not-needed'
        return (& $finish $envelope $commonFields)
    }

    if (-not [bool]$bound.Ready) {
        $reason = 'capture-preflight-' + [string]$bound.Status
        $envelope = New-WpdCollectorEnvelope -Collector 'trace' -Tier 2 -Status 'unavailable' -Coverage 'unavailable' `
            -Records @() -Reason $reason -Reasons @($reason, 'no-command-executed') `
            -Source 'Wpd.Etw' -CleanupStatus 'not-needed'
        return (& $finish $envelope $commonFields)
    }

    $startCommand = New-WpdEtwWprStartCommand -PresetProfile $profile -Mode $strategy.Mode `
        -InstanceName $InstanceName -WprExePath $WprExePath
    $stopCommand = $null
    if (-not [string]::IsNullOrWhiteSpace($EtlPath)) {
        $stopCommand = New-WpdEtwWprStopCommand -EtlPath $EtlPath -ProblemDescription $ProblemDescription `
            -InstanceName $InstanceName -WprExePath $WprExePath
    }
    $cancelCommand = New-WpdEtwWprCancelCommand -InstanceName $InstanceName -WprExePath $WprExePath

    $markerStartName = [string]$strategy.MarkerPair[0]
    $markerEndName = [string]$strategy.MarkerPair[1]
    $markerStartCommand = New-WpdEtwWprMarkerCommand -Marker $markerStartName -InstanceName $InstanceName -WprExePath $WprExePath
    $markerEndCommand = New-WpdEtwWprMarkerCommand -Marker $markerEndName -Flush -InstanceName $InstanceName -WprExePath $WprExePath

    $baseRunner = $Runner
    if ($null -eq $baseRunner) {
        $baseRunner = {
            param($toolPath, $arguments)
            $null = & $toolPath @arguments
            return $LASTEXITCODE
        }
    }

    # A scriptblock created in this function cannot see the function's locals
    # when the ETW module invokes it, so the capture state lives in module script
    # scope for the duration of the capture. Every executed command is recorded
    # here, so the evidence survives even when the capture body throws before the
    # ETW module can report its stop result.
    $captureState = [pscustomobject]@{
        commandLog        = New-Object System.Collections.ArrayList
        baseRunner        = $baseRunner
        markerStartCommand = $markerStartCommand
        markerEndCommand  = $markerEndCommand
        waitProvider      = $WaitProvider
        captureMode       = $CaptureMode
        markerNames       = @($markerStartName, $markerEndName)
    }
    $previousCaptureState = $script:WpdCollectorCaptureState
    $script:WpdCollectorCaptureState = $captureState

    $decoratedRunner = {
        param($toolPath, $arguments)

        $state = $script:WpdCollectorCaptureState
        [void]$state.commandLog.Add((@($arguments) -join ' '))
        return (& $state.baseRunner $toolPath $arguments)
    }

    $effectiveBody = $Body
    if ($null -eq $effectiveBody) {
        $effectiveBody = {
            param($context)

            $state = $script:WpdCollectorCaptureState
            $null = Invoke-WpdEtwCommand -Command $state.markerStartCommand -Runner $script:WpdCollectorCaptureRunner
            if ($null -ne $state.waitProvider) { $null = & $state.waitProvider $context }
            $null = Invoke-WpdEtwCommand -Command $state.markerEndCommand -Runner $script:WpdCollectorCaptureRunner

            return [pscustomobject]@{
                Markers          = @($state.markerNames)
                CaptureMode      = $state.captureMode
                ReproductionOnly = ($state.captureMode -eq 'Repro')
            }
        }
    }
    $script:WpdCollectorCaptureRunner = $decoratedRunner

    $capture = $null
    $bodyFailure = $null
    try {
        $capture = Invoke-WpdEtwCapture -StartCommand $startCommand -StopCommand $stopCommand `
            -CancelCommand $cancelCommand -Body $effectiveBody -Runner $decoratedRunner `
            -StatusProbe $StatusProbe -ExpectedInstanceName $InstanceName -OwnerTag 'wpd-collectors'
    }
    catch {
        $bodyFailure = $_
    }
    finally {
        $script:WpdCollectorCaptureState = $previousCaptureState
        $script:WpdCollectorCaptureRunner = $null
    }

    $commandLog = $captureState.commandLog
    $commonFields['commands'] = @($commandLog)

    if ($null -ne $bodyFailure) {
        $envelope = New-WpdCollectorEnvelope -Collector 'trace' -Tier 2 -Status 'error' -Coverage 'unavailable' `
            -Records @() -Reason 'capture-body-failed' -Reasons @('capture-body-failed', 'cleanup-attempted') `
            -Errors @([pscustomobject]@{ stage = 'capture'; message = $bodyFailure.Exception.Message }) `
            -StartedUtc $startedUtc -CompletedUtc (Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider) `
            -Source 'Wpd.Etw' -CleanupStatus 'attempted-after-failure' `
            -CleanupPaths $(if ([string]::IsNullOrWhiteSpace($EtlPath)) { @() } else { @($EtlPath) }) `
            -CleanupReason 'The capture body failed; the recording is stopped by the capture cleanup and the commands that ran are retained.'
        return (& $finish $envelope $commonFields)
    }

    $validation = Get-WpdEtwTraceValidation -EtlPath $EtlPath -SizeBytes $SizeBytes -MaxTraceSizeMB $MaxTraceSizeMB `
        -StartExitCode $capture.StartExitCode -StopExitCode $capture.StopExitCode
    $commonFields['capture'] = $capture
    $commonFields['traceValidation'] = $validation

    $status = 'success'
    $reasons = @()
    if ([string]$capture.Status -eq 'error') {
        $status = 'error'
        $reasons += 'capture-failed'
    }
    elseif ([string]$capture.Status -eq 'partial') {
        $status = 'partial'
        $reasons += 'capture-partial'
    }
    if ([string]$validation.Status -eq 'partial') {
        if ($status -eq 'success') { $status = 'partial' }
        $reasons += 'trace-partial'
    }
    if (-not [bool]$validation.Exists) {
        if ($status -eq 'success') { $status = 'partial' }
        $reasons += 'trace-not-produced'
    }
    if ([string]$capture.SessionState -eq 'in-progress') {
        if ($status -eq 'success') { $status = 'partial' }
        $reasons += 'recording-still-running'
    }
    if ($reasons.Count -eq 0) { $reasons += 'bounded-capture-completed' }

    $cleanupStatus = 'not-needed'
    if ([bool]$capture.Started) {
        $cleanupStatus = 'partial'
        if ([bool]$capture.StopAttempted) { $cleanupStatus = 'complete' }
    }

    $records = @(
        [pscustomobject][ordered]@{
            kind              = 'capture'
            captureMode       = $CaptureMode
            storagePolicy     = $strategy.StoragePolicy
            bounded           = $strategy.Bounded
            started           = $capture.Started
            startExitCode     = $capture.StartExitCode
            stopAttempted     = $capture.StopAttempted
            stopExitCode      = $capture.StopExitCode
            cancelAttempted   = $capture.CancelAttempted
            sessionState      = $capture.SessionState
            cleanupGuaranteed = $capture.CleanupGuaranteed
            markers           = @($strategy.MarkerPair)
            commands          = @($commandLog)
            status            = $capture.Status
        },
        [pscustomobject][ordered]@{
            kind          = 'trace-validation'
            etlPath       = $EtlPath
            exists        = $validation.Exists
            etlBytes      = $validation.EtlBytes
            empty         = $validation.Empty
            oversized     = $validation.Oversized
            kept          = $validation.Kept
            traceRemoved  = $validation.TraceRemoved
            maxTraceSizeMB = $validation.MaxTraceSizeMB
            status        = $validation.Status
            reason        = $validation.Reason
        }
    )

    $monitoring = $SelfMonitoring
    if ($null -eq $monitoring) {
        $monitoring = New-WpdCollectorSelfMonitoring -Collector 'trace' -Tier 2 -MeasurementSource 'not-measured'
    }

    $envelope = New-WpdCollectorEnvelope -Collector 'trace' -Tier 2 -Status $status `
        -Coverage (Get-WpdCollectorCoverageForStatus -Status $status) `
        -Records $records -Reasons $reasons `
        -Warnings @($validation.Warnings) -Errors @($capture.Errors) `
        -StartedUtc $startedUtc -CompletedUtc (Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider) `
        -Source 'Wpd.Etw' -SelfMonitoring $monitoring -CleanupStatus $cleanupStatus `
        -CleanupPaths $(if ([string]::IsNullOrWhiteSpace($EtlPath)) { @() } else { @($EtlPath) }) `
        -CleanupReason 'The recording is stopped by the capture cleanup; the marker pair and the command log are retained as evidence.'

    return (& $finish $envelope $commonFields)
}

# --------------------------------------------------------------------------
# Section 9: Tier 3 escalation (opt-in adapters with their own consent)
# --------------------------------------------------------------------------

function ConvertTo-WpdTier3AdapterEnvelope {
    <#
    .SYNOPSIS
        Wrap one escalation adapter result in a collector envelope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Adapter,
        [AllowNull()][object]$AdapterResult,
        [AllowEmptyString()][string]$FallbackStatus,
        [AllowEmptyString()][string]$FallbackReason,
        [AllowNull()][object[]]$Errors = @(),
        [AllowNull()][object]$SelfMonitoring
    )

    $status = $FallbackStatus
    $coverage = $null
    $reason = $FallbackReason
    $items = @()
    $warnings = @()
    $adapterErrors = @($Errors)
    $cleanupStatus = 'not-needed'
    $cleanupPaths = @()
    $cleanupReason = $null

    if ($null -ne $AdapterResult) {
        if (-not [string]::IsNullOrWhiteSpace([string](Get-WpdCollectorProperty -InputObject $AdapterResult -Name 'status'))) {
            $status = [string]$AdapterResult.status
        }
        $coverage = Get-WpdCollectorProperty -InputObject $AdapterResult -Name 'coverage'
        if (-not [string]::IsNullOrWhiteSpace([string](Get-WpdCollectorProperty -InputObject $AdapterResult -Name 'reason'))) {
            $reason = [string]$AdapterResult.reason
        }
        $items = @(Get-WpdCollectorProperty -InputObject $AdapterResult -Name 'items' -Default @())
        $warnings = @(Get-WpdCollectorProperty -InputObject $AdapterResult -Name 'warnings' -Default @())
        $adapterErrors = @($adapterErrors) + @(Get-WpdCollectorProperty -InputObject $AdapterResult -Name 'errors' -Default @())
        $cleanup = Get-WpdCollectorProperty -InputObject $AdapterResult -Name 'cleanup'
        if ($null -ne $cleanup) {
            $cleanupStatus = [string](Get-WpdCollectorProperty -InputObject $cleanup -Name 'status' -Default 'not-needed')
            $cleanupPaths = @(Get-WpdCollectorProperty -InputObject $cleanup -Name 'paths' -Default @())
            $cleanupReason = Get-WpdCollectorProperty -InputObject $cleanup -Name 'reason'
        }
    }

    if ([string]::IsNullOrWhiteSpace($status)) { $status = 'unavailable' }
    if ([string]::IsNullOrWhiteSpace($coverage)) { $coverage = Get-WpdCollectorCoverageForStatus -Status $status }

    $records = @()
    if ($null -ne $AdapterResult) { $records = @($AdapterResult) }

    $envelope = New-WpdCollectorEnvelope -Collector $Adapter -Tier 3 -Status $status -Coverage $coverage `
        -Records $records -Warnings $warnings -Errors $adapterErrors `
        -Reasons $(if ([string]::IsNullOrWhiteSpace($reason)) { @() } else { @($reason) }) -Reason $reason `
        -Source 'Wpd.Escalation' -SelfMonitoring $SelfMonitoring `
        -CleanupStatus $cleanupStatus -CleanupPaths $cleanupPaths -CleanupReason $cleanupReason `
        -AllowEmpty

    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'adapter' -Value $Adapter -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'consentRequired' -Value $true -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'consentGiven' -Value ([bool](Get-WpdCollectorProperty -InputObject $AdapterResult -Name 'consentGiven' -Default $false)) -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'automaticRemediation' -Value ([bool](Get-WpdCollectorProperty -InputObject $AdapterResult -Name 'automaticRemediation' -Default $false)) -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'recommendations' -Value @(Get-WpdCollectorProperty -InputObject $AdapterResult -Name 'recommendations' -Default @()) -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'items' -Value @($items) -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'itemCount' -Value $items.Count -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'tool' -Value (Get-WpdCollectorProperty -InputObject $AdapterResult -Name 'tool') -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'artifactPath' -Value (Get-WpdCollectorProperty -InputObject $AdapterResult -Name 'artifactPath') -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'adapterResult' -Value $AdapterResult -Force
    foreach ($section in @('service', 'index', 'data', 'chains', 'cycles', 'filters', 'instances')) {
        $value = Get-WpdCollectorProperty -InputObject $AdapterResult -Name $section
        if ($null -ne $value) {
            Add-Member -InputObject $envelope -MemberType NoteProperty -Name $section -Value $value -Force
        }
    }

    return $envelope
}

function Invoke-WpdTier3Collection {
    <#
    .SYNOPSIS
        Run the requested Tier 3 escalation adapters behind their consent gates.

    .DESCRIPTION
        Tier 3 is opt-in per adapter: an adapter without consent is
        not-collected with the reason consent-required, and the adapter function
        itself is the thing that guarantees no side effect (its consent check runs
        before any tool is touched).

        Each adapter keeps its own envelope, so a failing or unavailable adapter
        (an absent tool, an absent module, a refused command) never hides a
        sibling result and never aborts the run. Absence is reported as absence -
        'unavailable' with tool-not-found or module-not-found, or 'unsupported' -
        never as a clean result and never as an exception the caller must catch.

        Nothing here remediates: no recommendation, no exclusion, no automatic
        change is produced by this orchestration.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Adapter,
        [switch]$Consent,
        [AllowNull()][hashtable]$AdapterConsent,
        [AllowNull()][hashtable]$CommandTable,
        [AllowNull()][scriptblock]$CommandRunner,
        [AllowNull()][scriptblock]$ChainProvider,
        [AllowNull()][scriptblock]$ServiceProvider,
        [AllowNull()][scriptblock]$IndexProvider,
        [AllowNull()][object]$PoolMonOutput,
        [AllowNull()][object]$ModuleAvailable,
        [AllowNull()][hashtable]$ModuleTable,
        [AllowNull()][object]$ProcessId,
        [AllowNull()][object]$ThreadId,
        [AllowEmptyString()][string]$PoolTag,
        [AllowEmptyString()][string]$OutputDirectory,
        [AllowEmptyString()][string]$PrivacyLevel = 'Standard',
        [AllowNull()][object]$ClockProvider,
        [AllowNull()][object]$SelfMonitoring
    )

    $tier3Rows = @(Get-WpdCollectorTierMap | Where-Object { $_.tier -eq 3 })
    $tier3Ids = @($tier3Rows | ForEach-Object { $_.id })

    $requested = @()
    if ($null -eq $Adapter -or @($Adapter).Count -eq 0) {
        $requested = @($tier3Ids)
    }
    else {
        foreach ($id in @($Adapter)) {
            $value = [string]$id
            if ($tier3Ids -notcontains $value) {
                throw [System.ArgumentException]::new(
                    ("unknown Tier 3 adapter '{0}'; Tier 3 adapters are {1}" -f $value, ($tier3Ids -join ', '))
                )
            }
            if ($requested -notcontains $value) { $requested += $value }
        }
    }

    $startedUtc = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider
    $adapterEnvelopes = @()
    $consentedAdapters = @()
    $resolvedOutputDirectory = $OutputDirectory
    if ([string]::IsNullOrWhiteSpace($resolvedOutputDirectory)) {
        $resolvedOutputDirectory = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'wpd-escalation'
    }

    foreach ($adapterId in $requested) {
        $consented = [bool]$Consent
        if ($null -ne $AdapterConsent -and $AdapterConsent.ContainsKey($adapterId)) {
            $consented = [bool]$AdapterConsent[$adapterId]
        }

        $adapterResult = $null
        $fallbackStatus = $null
        $fallbackReason = $null
        $adapterErrors = @()

        if ($consented) { $consentedAdapters += $adapterId }

        try {
            switch ($adapterId) {
                'wct' {
                    $adapterResult = Invoke-WpdWct -Consent:$consented -ChainProvider $ChainProvider `
                        -ProcessId $(if ($null -ne $ProcessId) { @([int]$ProcessId) } else { $null }) `
                        -ThreadId $(if ($null -ne $ThreadId) { @([int]$ThreadId) } else { $null }) `
                        -PrivacyLevel $PrivacyLevel
                }
                'procdump' {
                    if (-not $consented) {
                        $adapterResult = Invoke-WpdProcDump -ProcessId 1 -OutputDirectory $resolvedOutputDirectory `
                            -PrivacyLevel $PrivacyLevel
                    }
                    elseif ($null -eq $ProcessId) {
                        $fallbackStatus = 'not-collected'
                        $fallbackReason = 'process-id-required'
                    }
                    else {
                        $adapterResult = Invoke-WpdProcDump -ProcessId ([int]$ProcessId) -OutputDirectory $resolvedOutputDirectory `
                            -Consent -CommandTable $CommandTable -CommandRunner $CommandRunner -PrivacyLevel $PrivacyLevel
                    }
                }
                'defender' {
                    $adapterResult = Invoke-WpdDefenderPerformanceCapture -OutputDirectory $resolvedOutputDirectory `
                        -Consent:$consented -ModuleAvailable $ModuleAvailable -ModuleTable $ModuleTable `
                        -CommandTable $CommandTable -CommandRunner $CommandRunner -PrivacyLevel $PrivacyLevel
                }
                'search' {
                    $adapterResult = Get-WpdSearchContext -Consent:$consented -ServiceProvider $ServiceProvider `
                        -IndexProvider $IndexProvider -PrivacyLevel $PrivacyLevel
                }
                'minifilter' {
                    $adapterResult = Invoke-WpdMinifilterEscalation -Consent:$consented -CommandTable $CommandTable `
                        -CommandRunner $CommandRunner -PrivacyLevel $PrivacyLevel
                }
                'pool' {
                    $adapterResult = Invoke-WpdPoolEscalation -PoolTag $PoolTag -OutputDirectory $resolvedOutputDirectory `
                        -Consent:$consented -CommandTable $CommandTable -CommandRunner $CommandRunner `
                        -PoolMonOutput $PoolMonOutput -PrivacyLevel $PrivacyLevel
                }
                default {
                    $fallbackStatus = 'not-collected'
                    $fallbackReason = 'adapter-not-implemented'
                }
            }
        }
        catch {
            $fallbackStatus = 'error'
            $fallbackReason = 'adapter-orchestration-failed'
            $adapterErrors += [pscustomobject]@{ stage = $adapterId; message = $_.Exception.Message }
        }

        $adapterEnvelopes += ConvertTo-WpdTier3AdapterEnvelope -Adapter $adapterId -AdapterResult $adapterResult `
            -FallbackStatus $fallbackStatus -FallbackReason $fallbackReason -Errors $adapterErrors -SelfMonitoring $SelfMonitoring
    }

    $quality = Get-WpdDataQualitySummary -Records $adapterEnvelopes
    $monitoring = $SelfMonitoring
    if ($null -eq $monitoring) {
        $monitoring = New-WpdCollectorSelfMonitoring -Collector 'tier3-escalation' -Tier 3 -MeasurementSource 'not-measured'
    }

    $reasons = @()
    foreach ($reason in @($quality.reasons)) { $reasons += [string]$reason }
    if ($consentedAdapters.Count -eq 0) { $reasons += 'no-adapter-consented' }

    $envelope = New-WpdCollectorEnvelope -Collector 'tier3-escalation' -Tier 3 `
        -Status ([string]$quality.status) -Coverage ([string]$quality.coverage) `
        -Records $adapterEnvelopes -Reasons $reasons `
        -Warnings @($quality.warnings) -Errors @($quality.errors) `
        -StartedUtc $startedUtc -CompletedUtc (Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider) `
        -Source 'Wpd.Escalation' -SelfMonitoring $monitoring -CleanupStatus 'not-needed' -AllowEmpty

    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'adapterCount' -Value $adapterEnvelopes.Count -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'adapters' -Value @($adapterEnvelopes) -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'consentedAdapters' -Value @($consentedAdapters) -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'automaticRemediation' -Value $false -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'recommendations' -Value @() -Force
    Add-Member -InputObject $envelope -MemberType NoteProperty -Name 'privacyLevel' -Value (Get-WpdPrivacyLevel -Level $PrivacyLevel) -Force

    return $envelope
}

# --------------------------------------------------------------------------
# Section 10: storage reliability, filters, Defender/Search context
# --------------------------------------------------------------------------

function Get-WpdStorageReliabilityContext {
    <#
    .SYNOPSIS
        Pair storage devices with their reliability counters, per device.

    .DESCRIPTION
        A device that exposes a reliability counter is complete; a device that
        exposes none is unsupported with the reason stated, and its reliability
        object stays null rather than being filled with zeros. A storage
        capability that was never collected is unavailable, and an unsupported
        capability stays unsupported.

        Reliability values are context, not a verdict: SMART and vendor
        thresholds differ per device, so this function states values and an
        analysis-only interpretation, never health.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$StorageRecord,
        [AllowNull()][object[]]$ReliabilityRecord = @(),
        [AllowNull()][object]$ClockProvider
    )

    $base = [ordered]@{
        status           = 'unavailable'
        coverage         = 'unavailable'
        reason           = 'storage-capability-not-collected'
        deviceCount      = 0
        supportedCount   = 0
        unsupportedCount = 0
        devices          = @()
        assessment       = 'analysis-only'
        interpretation   = 'Reliability counters describe device wear and error history; they are context for the symptom window, not a health verdict and not a vendor-specific threshold judgement.'
        healthClaim      = 'none'
        neverHealthy     = $true
        generatedUtc     = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider
    }

    if ($null -eq $StorageRecord) {
        return [pscustomobject]$base
    }

    $items = @(Get-WpdCollectorProperty -InputObject $StorageRecord -Name 'items' -Default @())
    $recordStatus = [string](Get-WpdCollectorProperty -InputObject $StorageRecord -Name 'status' -Default 'unavailable')
    $recordReasons = @(Get-WpdCollectorProperty -InputObject $StorageRecord -Name 'reasons' -Default @())

    if ($items.Count -eq 0) {
        if ($recordStatus -eq 'unsupported') {
            $base['status'] = 'unsupported'
            $base['coverage'] = 'unsupported'
            $base['reason'] = 'storage-reliability-unsupported'
        }
        else {
            $base['reason'] = $(if ($recordReasons.Count -gt 0) { [string]$recordReasons[0] } else { 'storage-reliability-not-collected' })
        }
        return [pscustomobject]$base
    }

    $devices = @()
    foreach ($item in $items) {
        $deviceId = Get-WpdCollectorProperty -InputObject $item -Name 'DeviceId'
        if ([string]::IsNullOrWhiteSpace([string]$deviceId)) { $deviceId = Get-WpdCollectorProperty -InputObject $item -Name 'Id' }
        if ([string]::IsNullOrWhiteSpace([string]$deviceId)) { $deviceId = Get-WpdCollectorProperty -InputObject $item -Name 'FriendlyName' }
        if ([string]::IsNullOrWhiteSpace([string]$deviceId)) { $deviceId = Get-WpdCollectorProperty -InputObject $item -Name 'Name' }

        $match = $null
        foreach ($row in @($ReliabilityRecord)) {
            $rowDevice = Get-WpdCollectorProperty -InputObject $row -Name 'DeviceId'
            if ([string]::IsNullOrWhiteSpace([string]$rowDevice)) { $rowDevice = Get-WpdCollectorProperty -InputObject $row -Name 'Id' }
            if (-not [string]::IsNullOrWhiteSpace([string]$rowDevice) -and [string]$rowDevice -ieq [string]$deviceId) {
                $match = $row
                break
            }
        }

        $reliability = $null
        $status = 'unsupported'
        $reason = 'reliability-counter-not-reported'
        if ($null -ne $match) {
            $reliability = [pscustomobject][ordered]@{
                wear              = Get-WpdCollectorProperty -InputObject $match -Name 'Wear'
                temperature       = Get-WpdCollectorProperty -InputObject $match -Name 'Temperature'
                readErrorsTotal   = Get-WpdCollectorProperty -InputObject $match -Name 'ReadErrorsTotal'
                writeErrorsTotal  = Get-WpdCollectorProperty -InputObject $match -Name 'WriteErrorsTotal'
                powerOnHours      = Get-WpdCollectorProperty -InputObject $match -Name 'PowerOnHours'
                source            = 'Get-StorageReliabilityCounter'
            }
            $status = 'complete'
            $reason = 'reliability-counter-reported'
        }

        $devices += [pscustomobject][ordered]@{
            deviceId     = $deviceId
            friendlyName = Get-WpdCollectorProperty -InputObject $item -Name 'FriendlyName'
            mediaType    = Get-WpdCollectorProperty -InputObject $item -Name 'MediaType'
            sizeBytes    = Get-WpdCollectorProperty -InputObject $item -Name 'Size'
            status       = $status
            coverage     = $status
            reason       = $reason
            reliability  = $reliability
        }
    }

    $supported = @($devices | Where-Object { $_.status -eq 'complete' }).Count
    $unsupported = @($devices | Where-Object { $_.status -eq 'unsupported' }).Count

    $status = 'partial'
    $coverage = 'partial'
    if ($unsupported -eq 0 -and $supported -gt 0) {
        $status = 'success'
        $coverage = 'complete'
    }
    elseif ($supported -eq 0) {
        $status = 'unsupported'
        $coverage = 'unsupported'
    }

    $base['status'] = $status
    $base['coverage'] = $coverage
    $base['reason'] = $(if ($unsupported -gt 0) { 'some-devices-report-no-reliability-counter' } else { 'reliability-counters-reported' })
    $base['deviceCount'] = $devices.Count
    $base['supportedCount'] = $supported
    $base['unsupportedCount'] = $unsupported
    $base['devices'] = @($devices)

    return [pscustomobject]$base
}

function Get-WpdFilterContext {
    <#
    .SYNOPSIS
        Compose the Tier 0 filter state with the optional fltmc snapshot.

    .DESCRIPTION
        Filter and instance rows are ordered by numeric altitude, which is the
        documented load order. Reading the filter state needs administrator, so
        an unelevated run reports requires-administrator instead of an empty
        list.

        The result is read-only context: an altitude order is not a performance
        attribution, so no recommendation is produced.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$FilterRecord,
        [AllowNull()][object]$MinifilterResult,
        [AllowNull()][object[]]$Filter,
        [AllowNull()][object[]]$Instance,
        [AllowNull()][object]$ClockProvider
    )

    $filterRows = @()
    $instanceRows = @()
    $reasons = @()

    if ($null -ne $Filter) { $filterRows = @($Filter) }
    elseif ($null -ne $FilterRecord) { $filterRows = @(Get-WpdCollectorProperty -InputObject $FilterRecord -Name 'items' -Default @()) }

    if ($null -ne $Instance) { $instanceRows = @($Instance) }
    elseif ($null -ne $MinifilterResult) { $instanceRows = @(Get-WpdCollectorProperty -InputObject $MinifilterResult -Name 'items' -Default @()) }

    if ($null -ne $FilterRecord) {
        foreach ($reason in @(Get-WpdCollectorProperty -InputObject $FilterRecord -Name 'reasons' -Default @())) {
            $reasons += [string]$reason
        }
    }

    $orderedFilters = @($filterRows | Sort-Object -Property @{ Expression = { $altitude = Get-WpdCollectorProperty -InputObject $_ -Name 'altitude'; if ($null -eq $altitude) { [int]::MaxValue } else { [int]$altitude } } })
    $orderedInstances = @($instanceRows | Sort-Object -Property @{ Expression = { $altitude = Get-WpdCollectorProperty -InputObject $_ -Name 'altitude'; if ($null -eq $altitude) { [int]::MaxValue } else { [int]$altitude } } })

    $status = 'unavailable'
    $coverage = 'unavailable'
    $reason = 'filters-not-collected'
    if ($reasons.Count -gt 0) { $reason = [string]$reasons[0] }
    if ($orderedFilters.Count -gt 0 -and $orderedInstances.Count -gt 0) {
        $status = 'success'
        $coverage = 'complete'
        $reason = 'filters-and-instances-ordered-by-altitude'
    }
    elseif ($orderedFilters.Count -gt 0 -or $orderedInstances.Count -gt 0) {
        $status = 'partial'
        $coverage = 'partial'
        $reason = 'filters-or-instances-missing'
    }
    elseif ($null -ne $MinifilterResult) {
        $adapterStatus = [string](Get-WpdCollectorProperty -InputObject $MinifilterResult -Name 'status' -Default 'unavailable')
        if ($adapterStatus -ne 'success') {
            $status = $adapterStatus
            $coverage = Get-WpdCollectorCoverageForStatus -Status $adapterStatus
            $adapterReason = Get-WpdCollectorProperty -InputObject $MinifilterResult -Name 'reason'
            if (-not [string]::IsNullOrWhiteSpace([string]$adapterReason)) { $reason = [string]$adapterReason }
        }
    }

    return [pscustomobject][ordered]@{
        status                  = $status
        coverage                = $coverage
        reason                  = $reason
        reasons                 = @($reasons)
        filterCount             = $orderedFilters.Count
        instanceCount           = $orderedInstances.Count
        filters                 = @($orderedFilters)
        instances               = @($orderedInstances)
        orderKey                = 'numeric-altitude-ascending'
        elevationRequired       = $true
        elevationReason         = 'Reading the minifilter list and its instances needs administrator'
        readOnly                = $true
        assessment              = 'analysis-only'
        recommendations         = @()
        automaticRemediation    = $false
        interpretation          = 'An altitude order shows load order, not performance attribution; correlation with a symptom window is still required.'
        healthClaim             = 'none'
        neverHealthy            = $true
        generatedUtc            = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider
    }
}

function Get-WpdDefenderSearchContext {
    <#
    .SYNOPSIS
        Compose the Defender performance analyzer with the Search context.

    .DESCRIPTION
        Both adapters are consent gated by their own implementation, so without
        consent they report not-collected and nothing is queried. An absent
        Defender module is stated as unavailable (module-not-found), never as a
        failure and never as a clean result.

        This context never proposes a remediation or a Defender exclusion: the
        analyzer output is scan-impact evidence for correlation, not
        justification for a configuration change.
    #>
    [CmdletBinding()]
    param(
        [switch]$Consent,
        [AllowNull()][object]$DefenderResult,
        [AllowNull()][object]$SearchResult,
        [AllowEmptyString()][string]$OutputDirectory,
        [AllowNull()][object]$ModuleAvailable,
        [AllowNull()][hashtable]$ModuleTable,
        [AllowNull()][hashtable]$CommandTable,
        [AllowNull()][scriptblock]$CommandRunner,
        [AllowNull()][scriptblock]$ServiceProvider,
        [AllowNull()][scriptblock]$IndexProvider,
        [AllowEmptyString()][string]$PrivacyLevel = 'Standard',
        [AllowNull()][object]$ClockProvider
    )

    $resolvedOutputDirectory = $OutputDirectory
    if ([string]::IsNullOrWhiteSpace($resolvedOutputDirectory)) {
        $resolvedOutputDirectory = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'wpd-escalation'
    }

    $defender = $DefenderResult
    if ($null -eq $defender) {
        $defender = Invoke-WpdDefenderPerformanceCapture -OutputDirectory $resolvedOutputDirectory -Consent:$Consent `
            -ModuleAvailable $ModuleAvailable -ModuleTable $ModuleTable -CommandTable $CommandTable `
            -CommandRunner $CommandRunner -PrivacyLevel $PrivacyLevel
    }

    $search = $SearchResult
    if ($null -eq $search) {
        $search = Get-WpdSearchContext -Consent:$Consent -ServiceProvider $ServiceProvider `
            -IndexProvider $IndexProvider -PrivacyLevel $PrivacyLevel
    }

    $quality = Get-WpdDataQualitySummary -Records @($defender, $search)

    return [pscustomobject][ordered]@{
        status                     = [string]$quality.status
        coverage                   = [string]$quality.coverage
        consentGiven               = [bool]$Consent
        defender                   = $defender
        search                     = $search
        defenderStatus             = [string](Get-WpdCollectorProperty -InputObject $defender -Name 'status' -Default 'unavailable')
        searchStatus               = [string](Get-WpdCollectorProperty -InputObject $search -Name 'status' -Default 'unavailable')
        recommendations            = @()
        automaticRemediation       = $false
        defenderExclusionProposed  = $false
        interpretation             = 'Defender scan impact and Search index state describe scoped mechanisms; a second evidence channel is required before attributing the symptom, and no exclusion or tuning change is proposed here.'
        healthClaim                = 'none'
        neverHealthy               = $true
        generatedUtc               = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider
    }
}

# --------------------------------------------------------------------------
# Section 11: boot descriptors, network/GPU/power context, self-monitoring
# --------------------------------------------------------------------------

function New-WpdBootCollectionDescriptor {
    <#
    .SYNOPSIS
        Describe a quick or a deep boot recording. Never executes one.

    .DESCRIPTION
        Depth selects the documented mechanic:

        - 'quick' is the autologger -boottrace -addboot single-boot recording,
          completed by -stopboot and cancelled by -cancelboot. It measures the
          next boot only.
        - 'deep' is the On/Off transition scenario. It is always file backed and
          reboots the computer several times (the documented default is three),
          so it is reported with its iteration count instead of pretending to be
          a single boot.

        Both descriptors are descriptions with executed = $false and
        requiresOperatorApproval = $true: a boot recording changes what survives
        a reboot, which is an operator decision.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('quick', 'deep')][string]$Depth = 'quick',
        [AllowEmptyString()][string]$Preset = 'boot-slowdown',
        [AllowNull()][object]$PresetProfile,
        [AllowNull()][object]$PresetTable,
        [AllowEmptyString()][string]$ResultsPath,
        [AllowEmptyString()][string]$ProblemDescription,
        [AllowNull()][object]$NumIterations,
        [AllowEmptyString()][string]$WprExePath,
        [AllowNull()][object]$ClockProvider
    )

    $profile = $PresetProfile
    if ($null -eq $profile) {
        $profile = Get-WpdEtwPresetProfile -Preset $Preset -PresetTable $PresetTable
    }

    $scenario = [string](Get-WpdCollectorProperty -InputObject $profile -Name 'OnOffScenario' -Default '')
    if ([string]::IsNullOrWhiteSpace($scenario)) { $scenario = 'Boot' }

    if ($Depth -eq 'quick') {
        $descriptor = New-WpdEtwBootScenarioDescriptor -Scenario $scenario -Mechanism 'boottrace' `
            -Profile ([string]$profile.Profile) -Qualifier ([string]$profile.Qualifier) `
            -ResultsPath $ResultsPath -ProblemDescription $ProblemDescription -NumIterations 1 -WprExePath $WprExePath
        $depth = 'quick'
        $iterations = 1
        $analysisRequired = $true
    }
    else {
        $iterations = 3
        if ($null -ne $NumIterations) {
            try { $iterations = [int]$NumIterations } catch { $iterations = 3 }
        }
        $descriptor = New-WpdEtwBootScenarioDescriptor -Scenario $scenario -Mechanism 'onoff' `
            -Profile ([string]$profile.Profile) -Qualifier 'verbose' `
            -ResultsPath $ResultsPath -ProblemDescription $ProblemDescription -NumIterations $iterations -WprExePath $WprExePath
        $depth = 'deep'
        $analysisRequired = $true
    }

    return [pscustomobject][ordered]@{
        depth                   = $depth
        kind                    = 'boot-collection-descriptor'
        preset                  = $Preset
        effectivePreset         = [string](Get-WpdCollectorProperty -InputObject $profile -Name 'EffectivePreset' -Default $Preset)
        mechanism               = $descriptor.Mechanism
        scenario                = $descriptor.Scenario
        profileSpec             = $descriptor.ProfileSpec
        numIterations           = $iterations
        rebootCount             = $descriptor.RebootCount
        requiresReboot          = $descriptor.RequiresReboot
        executed                = $false
        requiresOperatorApproval = $true
        fileBacked              = $descriptor.FileBacked
        memoryMode              = $descriptor.MemoryMode
        analysisRequired        = $analysisRequired
        expectedArtifact        = $(if ([string]::IsNullOrWhiteSpace($ResultsPath)) { 'boot-performance.etl' } else { $ResultsPath })
        assignment              = $descriptor.Assignment
        completion              = $descriptor.Completion
        cleanup                 = $descriptor.Cleanup
        warnings                = @($descriptor.Warnings)
        healthClaim             = 'none'
        neverHealthy            = $true
        generatedUtc            = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider
    }
}

function Get-WpdNetworkContext {
    <#
    .SYNOPSIS
        Compose the Tier 0 network adapter state with the Tier 1 rates.

    .DESCRIPTION
        Adapter state (link speed, status, media type) comes from the static
        inventory capability; the throughput series comes from the interval
        collector. A nic capability that was never collected is unavailable with
        the reason stated, and an unavailable capability stays unavailable - an
        empty adapter list is never a clean result.

        The context is descriptive: bytes per second do not identify a cause.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$NicRecord,
        [AllowNull()][object]$TelemetryEnvelope,
        [AllowNull()][object]$ClockProvider
    )

    $adapters = @()
    $reasons = @()
    $status = 'unavailable'
    $coverage = 'unavailable'
    $reason = 'nic-capability-not-collected'

    if ($null -ne $NicRecord) {
        $adapters = @(Get-WpdCollectorProperty -InputObject $NicRecord -Name 'items' -Default @())
        foreach ($item in @(Get-WpdCollectorProperty -InputObject $NicRecord -Name 'reasons' -Default @())) { $reasons += [string]$item }
        $recordStatus = [string](Get-WpdCollectorProperty -InputObject $NicRecord -Name 'status' -Default 'unavailable')
        if ($adapters.Count -gt 0) {
            $status = 'success'
            $coverage = 'complete'
            $reason = 'adapter-state-and-rates-collected'
        }
        else {
            $status = $recordStatus
            $coverage = Get-WpdCollectorCoverageForStatus -Status $recordStatus
            if ($reasons.Count -gt 0) { $reason = [string]$reasons[0] }
        }
    }

    $upAdapters = @($adapters | Where-Object { [string](Get-WpdCollectorProperty -InputObject $_ -Name 'Status' -Default '') -ieq 'Up' })
    $linkSpeed = $null
    foreach ($adapter in $upAdapters) {
        $speed = Get-WpdCollectorProperty -InputObject $adapter -Name 'LinkSpeedBps'
        if ($null -ne $speed) {
            try {
                $value = [int64]$speed
                if ($null -eq $linkSpeed -or $value -gt $linkSpeed) { $linkSpeed = $value }
            }
            catch { }
        }
    }

    $telemetryRecords = @()
    $telemetryStatus = $null
    if ($null -ne $TelemetryEnvelope) {
        $telemetryRecords = @(Get-WpdCollectorProperty -InputObject $TelemetryEnvelope -Name 'records' -Default @())
        $telemetryStatus = [string](Get-WpdCollectorProperty -InputObject $TelemetryEnvelope -Name 'status' -Default 'unavailable')
    }
    $throughputAvailable = ($telemetryRecords.Count -gt 0)
    if ($status -eq 'success' -and $null -ne $telemetryStatus -and $telemetryStatus -ne 'success') {
        $status = 'partial'
        $coverage = 'partial'
        $reasons += 'rate-series-' + $telemetryStatus
    }
    if (-not $throughputAvailable) { $reasons += 'rate-series-not-available' }

    return [pscustomobject][ordered]@{
        status                = $status
        coverage              = $coverage
        reason                = $reason
        reasons               = @($reasons)
        adapterCount          = $adapters.Count
        upAdapterCount        = $upAdapters.Count
        linkSpeedBps          = $linkSpeed
        mediaTypes            = @($adapters | ForEach-Object { Get-WpdCollectorProperty -InputObject $_ -Name 'MediaType' } | Where-Object { $null -ne $_ })
        adapters              = @($adapters)
        telemetryStatus       = $telemetryStatus
        throughputRowCount    = $telemetryRecords.Count
        throughputAvailable   = $throughputAvailable
        assessment            = 'analysis-only'
        interpretation        = 'Adapter state and byte rates describe what moved on the wire; they do not identify which component caused the symptom.'
        healthClaim           = 'none'
        neverHealthy          = $true
        generatedUtc          = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider
    }
}

function Get-WpdGpuContext {
    <#
    .SYNOPSIS
        Compose the Tier 1 GPU series with the optional deep tracing descriptor.

    .DESCRIPTION
        The GPU engine and process-memory rows come from the Tier 1 collector and
        are summarized by the telemetry module's own GPU view, so the same
        counter-path parsing is used everywhere. As with every other series, an
        unavailable Tier 1 result stays unavailable, and a missing temperature or
        clock counter is reported as not exposed instead of being invented.

        Deep GPU tracing is only described (it needs a host-selected WPR profile),
        so the context states whether the descriptor exists - it never claims a
        timeline it did not record.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$TelemetryEnvelope,
        [AllowNull()][object]$DeepDescriptor,
        [AllowNull()][object]$ClockProvider
    )

    $status = 'unavailable'
    $coverage = 'unavailable'
    $reason = 'gpu-series-not-collected'
    $rows = @()
    $telemetryStatus = $null

    if ($null -ne $TelemetryEnvelope) {
        $rows = @(Get-WpdCollectorProperty -InputObject $TelemetryEnvelope -Name 'records' -Default @())
        $telemetryStatus = [string](Get-WpdCollectorProperty -InputObject $TelemetryEnvelope -Name 'status' -Default 'unavailable')
        if ($rows.Count -gt 0 -and $telemetryStatus -eq 'success') {
            $status = 'success'
            $coverage = 'complete'
            $reason = 'gpu-engine-series-collected'
        }
        elseif ($rows.Count -gt 0) {
            $status = 'partial'
            $coverage = 'partial'
            $reason = 'gpu-engine-series-' + $telemetryStatus
        }
        else {
            $status = $telemetryStatus
            $coverage = Get-WpdCollectorCoverageForStatus -Status $telemetryStatus
            $reason = 'gpu-engine-series-empty'
        }
    }

    $gpu = Get-GpuTelemetry -Rows $rows
    $utilizations = @()
    foreach ($engine in @($gpu.Engines)) {
        if ($null -ne $engine.UtilizationPercentage) { $utilizations += [double]$engine.UtilizationPercentage }
    }
    $maxUtilization = $null
    if ($utilizations.Count -gt 0) { $maxUtilization = ($utilizations | Measure-Object -Maximum).Maximum }

    $temperature = $null
    if ([bool]$gpu.Temperature.Available) { $temperature = $gpu.Temperature.ValueCelsius }

    return [pscustomobject][ordered]@{
        status                 = $status
        coverage               = $coverage
        reason                 = $reason
        telemetryStatus        = $telemetryStatus
        engineCount            = @($gpu.Engines).Count
        adapterCount           = @($gpu.Adapters).Count
        processMemoryRowCount  = @($gpu.ProcessMemory).Count
        maxUtilizationPercent  = $maxUtilization
        temperatureCelsius     = $temperature
        temperatureAvailable   = [bool]$gpu.Temperature.Available
        clocksAvailable        = [bool]$gpu.Clocks.Available
        deepTracingAvailable   = ($null -ne $DeepDescriptor)
        deepDescriptor         = $DeepDescriptor
        rowCount               = $rows.Count
        engines                = @($gpu.Engines)
        assessment             = 'analysis-only'
        interpretation         = 'GPU engine utilization and memory describe scheduler activity for the sampled window; deep timelines require the described trace before any overlap claim.'
        healthClaim            = 'none'
        neverHealthy           = $true
        generatedUtc           = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider
    }
}

function Get-WpdPowerContext {
    <#
    .SYNOPSIS
        Compose the Tier 0 power configuration with the Tier 1 processor utility.

    .DESCRIPTION
        The active power scheme and the available sleep states come from the
        static power capability; processor utility comes from the interval
        series and is reported as the maximum of the sampled rows, with that
        method stated, because this function makes no threshold judgement.

        A missing power capability is unavailable with the reason stated, and no
        thermal or throttling conclusion is drawn from counter values alone.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$PowerRecord,
        [AllowNull()][object]$TelemetryEnvelope,
        [AllowNull()][object]$ClockProvider
    )

    $items = @()
    $reasons = @()
    $status = 'unavailable'
    $coverage = 'unavailable'
    $reason = 'power-capability-not-collected'

    if ($null -ne $PowerRecord) {
        $items = @(Get-WpdCollectorProperty -InputObject $PowerRecord -Name 'items' -Default @())
        foreach ($item in @(Get-WpdCollectorProperty -InputObject $PowerRecord -Name 'reasons' -Default @())) { $reasons += [string]$item }
        $recordStatus = [string](Get-WpdCollectorProperty -InputObject $PowerRecord -Name 'status' -Default 'unavailable')
        if ($items.Count -gt 0) {
            $status = 'success'
            $coverage = 'complete'
            $reason = 'power-configuration-collected'
        }
        else {
            $status = $recordStatus
            $coverage = Get-WpdCollectorCoverageForStatus -Status $recordStatus
            if ($reasons.Count -gt 0) { $reason = [string]$reasons[0] }
        }
    }

    $scheme = $null
    $sleepStates = $null
    foreach ($item in $items) {
        $kind = [string](Get-WpdCollectorProperty -InputObject $item -Name 'kind' -Default '')
        if ($kind -eq 'power-active-scheme' -and $null -eq $scheme) { $scheme = $item }
        if ($kind -eq 'power-sleep-states' -and $null -eq $sleepStates) { $sleepStates = $item }
    }

    $utilityRows = @()
    $telemetryStatus = $null
    if ($null -ne $TelemetryEnvelope) {
        foreach ($row in @(Get-WpdCollectorProperty -InputObject $TelemetryEnvelope -Name 'records' -Default @())) {
            $utility = Get-WpdCollectorProperty -InputObject $row -Name 'UtilityPercent'
            if ($null -ne $utility) { $utilityRows += [double]$utility }
        }
        $telemetryStatus = [string](Get-WpdCollectorProperty -InputObject $TelemetryEnvelope -Name 'status' -Default 'unavailable')
    }

    $maxUtility = $null
    if ($utilityRows.Count -gt 0) { $maxUtility = ($utilityRows | Measure-Object -Maximum).Maximum }

    if ($status -eq 'success' -and $null -ne $telemetryStatus -and $telemetryStatus -ne 'success') {
        $status = 'partial'
        $coverage = 'partial'
        $reasons += 'processor-utility-' + $telemetryStatus
    }
    if ($utilityRows.Count -eq 0) { $reasons += 'processor-utility-not-available' }

    return [pscustomobject][ordered]@{
        status                = $status
        coverage              = $coverage
        reason                = $reason
        reasons               = @($reasons)
        itemCount             = $items.Count
        activeScheme          = $scheme
        sleepStates           = $sleepStates
        schemeCount           = @($items | Where-Object { [string](Get-WpdCollectorProperty -InputObject $_ -Name 'kind' -Default '') -eq 'power-active-scheme' }).Count
        items                 = @($items)
        telemetryStatus       = $telemetryStatus
        utilityRowCount       = $utilityRows.Count
        maxUtilityPercent     = $maxUtility
        utilityMethod         = 'maximum-of-sampled-rows'
        thermalThrottleClaim  = $false
        assessment            = 'analysis-only'
        interpretation        = 'The active scheme and processor utility describe the configured power path; a thermal or throttling conclusion needs thermal zone evidence, which this context does not have.'
        healthClaim           = 'none'
        neverHealthy          = $true
        generatedUtc          = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider
    }
}

function Get-WpdCollectorPerformanceReport {
    <#
    .SYNOPSIS
        Summarize the self-monitoring records of a run.

    .DESCRIPTION
        One row per collector, with the totals for the collectors that were
        measured and explicit counts for the ones that were not. The report is
        informational: it evaluates no threshold, so it cannot fail a run, and a
        collector that was never measured is counted as unmeasured rather than as
        zero overhead.
    #>
    [CmdletBinding()]
    param([AllowNull()][object[]]$Envelope)

    $rows = @()
    $measured = 0
    $partial = 0
    $unmeasured = 0
    $totalDuration = 0
    $totalCpu = 0.0
    $cpuMeasured = $false

    foreach ($item in @($Envelope)) {
        $monitoring = Get-WpdCollectorProperty -InputObject $item -Name 'selfMonitoring'
        if ($null -eq $monitoring) { continue }

        $measurementStatus = [string](Get-WpdCollectorProperty -InputObject $monitoring -Name 'measurementStatus' -Default 'unavailable')
        switch ($measurementStatus) {
            'complete' { $measured++ }
            'partial' { $partial++ }
            default { $unmeasured++ }
        }

        $duration = Get-WpdCollectorProperty -InputObject $monitoring -Name 'durationMs'
        if ($null -ne $duration) { $totalDuration += [int64]$duration }
        $cpu = Get-WpdCollectorProperty -InputObject $monitoring -Name 'cpuSeconds'
        if ($null -ne $cpu) { $totalCpu += [double]$cpu; $cpuMeasured = $true }

        $rows += [pscustomobject][ordered]@{
            collector           = [string](Get-WpdCollectorProperty -InputObject $monitoring -Name 'collector')
            tier                = Get-WpdCollectorProperty -InputObject $monitoring -Name 'tier'
            status              = [string](Get-WpdCollectorProperty -InputObject $item -Name 'status' -Default 'unavailable')
            coverage            = [string](Get-WpdCollectorProperty -InputObject $item -Name 'coverage' -Default 'unavailable')
            durationMs          = $duration
            cpuSeconds          = $cpu
            workingSetBytes     = Get-WpdCollectorProperty -InputObject $monitoring -Name 'workingSetBytes'
            sampleCount         = Get-WpdCollectorProperty -InputObject $monitoring -Name 'sampleCount'
            measurementStatus   = $measurementStatus
            measurementSource   = [string](Get-WpdCollectorProperty -InputObject $monitoring -Name 'measurementSource' -Default 'injected')
            thresholdsEvaluated = $false
        }
    }

    $totalCpuValue = $totalCpu
    if (-not $cpuMeasured) { $totalCpuValue = $null }

    return [pscustomobject][ordered]@{
        collectorCount      = $rows.Count
        measuredCount       = $measured
        partialCount        = $partial
        unmeasuredCount     = $unmeasured
        totalDurationMs     = $totalDuration
        totalCpuSeconds     = $totalCpuValue
        rows                = @($rows)
        informational       = $true
        thresholdsEvaluated = $false
        interpretation      = 'Collector overhead is informational while the overhead thresholds remain an owner decision.'
        healthClaim         = 'none'
        neverHealthy        = $true
    }
}

# --------------------------------------------------------------------------
# Section 12: cleanup and plan orchestration
# --------------------------------------------------------------------------

function New-WpdCollectorCleanupResult {
    <#
    .SYNOPSIS
        One cleanup outcome, with the reason stated for every status.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Status = 'not-needed',
        [AllowEmptyString()][string]$Reason,
        [AllowNull()][object[]]$Removed = @(),
        [AllowNull()][object[]]$Skipped = @()
    )

    return [pscustomobject][ordered]@{
        status  = $Status
        reason  = $Reason
        removed = @($Removed)
        skipped = @($Skipped)
    }
}

function Remove-WpdCollectorArtifact {
    <#
    .SYNOPSIS
        Remove one artifact this toolkit created, and nothing else.

    .DESCRIPTION
        Cleanup is deliberately narrow. An artifact is removed only when the
        caller states that the toolkit created it, when the path resolves inside
        the case root (when a root is supplied), and when it is not a reparse
        point. Everything else is preserved with the reason stated:

        - a path the toolkit did not create is preserved;
        - a path outside the case root is refused, so cleanup can never walk out
          of the case folder;
        - an already absent path is not-present, so a second cleanup is
          idempotent instead of an error.

        Nothing here is recursive: only the named path is removed.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Path,
        [AllowEmptyString()][string]$CaseRoot,
        [switch]$CreatedByToolkit
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return New-WpdCollectorCleanupResult -Status 'not-needed' -Reason 'no-path'
    }
    if (-not $CreatedByToolkit) {
        return New-WpdCollectorCleanupResult -Status 'preserved' -Reason 'not-created-by-toolkit' -Skipped @($Path)
    }

    $resolved = $Path
    try { $resolved = [System.IO.Path]::GetFullPath($Path) }
    catch {
        return New-WpdCollectorCleanupResult -Status 'failed' -Reason 'invalid-path' -Skipped @($Path)
    }

    if (-not [string]::IsNullOrWhiteSpace($CaseRoot)) {
        $root = $null
        try { $root = [System.IO.Path]::GetFullPath($CaseRoot) }
        catch { $root = $null }
        if ([string]::IsNullOrWhiteSpace($root)) {
            return New-WpdCollectorCleanupResult -Status 'failed' -Reason 'invalid-case-root' -Skipped @($resolved)
        }
        if (-not $root.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
            $root = $root + [System.IO.Path]::DirectorySeparatorChar
        }
        if (-not $resolved.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            return New-WpdCollectorCleanupResult -Status 'failed' -Reason 'outside-case-root' -Skipped @($resolved)
        }
    }

    try {
        if (-not (Test-Path -LiteralPath $resolved -PathType Any)) {
            return New-WpdCollectorCleanupResult -Status 'not-present' -Reason 'already-absent' -Skipped @($resolved)
        }
        $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
            return New-WpdCollectorCleanupResult -Status 'failed' -Reason 'reparse-point-not-removed' -Skipped @($resolved)
        }
        Remove-Item -LiteralPath $resolved -Force -ErrorAction Stop
        return New-WpdCollectorCleanupResult -Status 'removed' -Reason 'toolkit-artifact-removed' -Removed @($resolved)
    }
    catch {
        $result = New-WpdCollectorCleanupResult -Status 'failed' -Reason 'removal-failed' -Skipped @($resolved)
        Add-Member -InputObject $result -MemberType NoteProperty -Name 'message' -Value $_.Exception.Message -Force
        return $result
    }
}

function Invoke-WpdCollectorPlan {
    <#
    .SYNOPSIS
        Execute a collector plan, tier by tier, with one envelope per collector.

    .DESCRIPTION
        The plan's order is the run's order: Tier 0 first (collected once, then
        read from the cache by anything that needs it), then the interval
        families, then the trace, then the consented escalation adapters. Each
        collector produces its own envelope, so one failing collector is stated
        as a failure while its siblings report their own results, and the
        aggregate is a coverage summary - never a verdict.

        Every tier receives its own argument set, so the whole run is driven
        through injected seams. A tier that the plan does not select is not run
        and is reported as null rather than as an empty success.

        Cleanup runs after the envelopes are built and removes only artifacts the
        toolkit created; a run that created nothing reports not-needed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [AllowNull()][hashtable]$Tier0Arguments,
        [AllowNull()][object]$Tier1Family,
        [AllowNull()][hashtable]$Tier1Arguments,
        [AllowNull()][hashtable]$Tier1Provider,
        [AllowNull()][hashtable]$Tier2Arguments,
        [AllowNull()][object]$Tier3Adapter,
        [AllowNull()][hashtable]$Tier3Arguments,
        [AllowNull()][object[]]$Artifact,
        [AllowEmptyString()][string]$CaseRoot,
        [AllowNull()][object]$ClockProvider
    )

    $tiers = @(Get-WpdCollectorProperty -InputObject $Plan -Name 'tiers' -Default @())
    $startedUtc = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider

    $tier0 = $null
    $tier1Envelopes = @()
    $tier2 = $null
    $tier3 = $null
    $envelopes = @()
    $errors = @()

    if ($tiers -contains 0) {
        $arguments = @{}
        if ($null -ne $Tier0Arguments) { $arguments = $Tier0Arguments }
        try {
            $tier0 = Invoke-WpdTier0Collection @arguments
        }
        catch {
            $errors += [pscustomobject]@{ stage = 'tier0'; message = $_.Exception.Message }
            $tier0 = New-WpdCollectorEnvelope -Collector 'tier0-inventory' -Tier 0 -Status 'error' -Coverage 'unavailable' `
                -Records @() -Reason 'tier0-collection-failed' `
                -Errors @([pscustomobject]@{ stage = 'tier0'; message = $_.Exception.Message }) -Source 'Wpd.Inventory'
        }
        $envelopes += $tier0
    }

    if ($tiers -contains 1) {
        $families = @($Tier1Family)
        if ($families.Count -eq 0) {
            $families = @(Get-WpdCollectorTierMap | Where-Object { $_.tier -eq 1 } | ForEach-Object { $_.id })
        }
        foreach ($family in $families) {
            $arguments = @{ Family = [string]$family }
            if ($null -ne $Tier1Arguments) {
                foreach ($key in $Tier1Arguments.Keys) { $arguments[$key] = $Tier1Arguments[$key] }
            }
            if ($null -ne $Tier1Provider -and $Tier1Provider.ContainsKey([string]$family)) {
                $arguments['Provider'] = $Tier1Provider[[string]$family]
            }
            try {
                $tier1Envelopes += Invoke-WpdTier1Collection @arguments
            }
            catch {
                $errors += [pscustomobject]@{ stage = 'tier1'; family = [string]$family; message = $_.Exception.Message }
                $tier1Envelopes += New-WpdCollectorEnvelope -Collector ([string]$family) -Tier 1 -Status 'error' -Coverage 'unavailable' `
                    -Records @() -Reason 'tier1-collection-failed' `
                    -Errors @([pscustomobject]@{ stage = 'tier1'; message = $_.Exception.Message }) -Source 'Wpd.Telemetry'
            }
        }
        $envelopes += $tier1Envelopes
    }

    if ($tiers -contains 2) {
        $arguments = @{}
        if ($null -ne $Tier2Arguments) { $arguments = $Tier2Arguments }
        try {
            $tier2 = Invoke-WpdTier2Collection @arguments
        }
        catch {
            $errors += [pscustomobject]@{ stage = 'tier2'; message = $_.Exception.Message }
            $tier2 = New-WpdCollectorEnvelope -Collector 'trace' -Tier 2 -Status 'error' -Coverage 'unavailable' `
                -Records @() -Reason 'tier2-capture-failed' `
                -Errors @([pscustomobject]@{ stage = 'tier2'; message = $_.Exception.Message }) -Source 'Wpd.Etw'
        }
        $envelopes += $tier2
    }

    if ($tiers -contains 3) {
        $arguments = @{}
        if ($null -ne $Tier3Arguments) { $arguments = $Tier3Arguments }
        if ($null -ne $Tier3Adapter) { $arguments['Adapter'] = @($Tier3Adapter) }
        try {
            $tier3 = Invoke-WpdTier3Collection @arguments
        }
        catch {
            $errors += [pscustomobject]@{ stage = 'tier3'; message = $_.Exception.Message }
            $tier3 = New-WpdCollectorEnvelope -Collector 'tier3-escalation' -Tier 3 -Status 'error' -Coverage 'unavailable' `
                -Records @() -Reason 'tier3-collection-failed' `
                -Errors @([pscustomobject]@{ stage = 'tier3'; message = $_.Exception.Message }) -Source 'Wpd.Escalation' -AllowEmpty
        }
        $envelopes += $tier3
    }

    $cleanupResults = @()
    $cleanupRemoved = @()
    $cleanupSkipped = @()
    foreach ($artifactPath in @($Artifact)) {
        # Only artifacts this run states it created are registered here, so the
        # cleanup helper is asked to remove exactly those and nothing else.
        $cleanupResult = Remove-WpdCollectorArtifact -Path ([string]$artifactPath) -CaseRoot $CaseRoot -CreatedByToolkit
        $cleanupResults += $cleanupResult
        $cleanupRemoved += @($cleanupResult.removed)
        $cleanupSkipped += @($cleanupResult.skipped)
    }
    if ($cleanupResults.Count -eq 0) {
        $cleanupResults += New-WpdCollectorCleanupResult -Status 'not-needed' -Reason 'no-artifacts-registered'
    }

    $cleanupStatus = 'not-needed'
    if ($cleanupResults.Count -gt 0) {
        $cleanupStatus = [string]$cleanupResults[0].status
        if (@($cleanupResults | Where-Object { $_.status -eq 'failed' }).Count -gt 0) {
            $cleanupStatus = 'failed'
        }
        elseif (@($cleanupResults | Where-Object { $_.status -eq 'removed' }).Count -gt 0) {
            $cleanupStatus = 'removed'
        }
    }

    $quality = Get-WpdDataQualitySummary -Records $envelopes
    $report = Get-WpdCollectorPerformanceReport -Envelope $envelopes

    $reasons = @()
    foreach ($reason in @($quality.reasons)) { $reasons += [string]$reason }
    foreach ($entry in $errors) { $reasons += ('stage-failed:' + [string]$entry.stage) }

    $completedUtc = Get-WpdCollectorUtcTimestamp -ClockProvider $ClockProvider
    $status = [string]$quality.status
    if ($errors.Count -gt 0 -and $status -eq 'success') { $status = 'partial' }

    $result = [pscustomobject][ordered]@{
        status            = $status
        coverage          = $quality.coverage
        plan              = $Plan
        planId            = Get-WpdCollectorProperty -InputObject $Plan -Name 'id'
        tiers             = @($tiers)
        envelopes         = @($envelopes)
        envelopeCount     = $envelopes.Count
        tier0             = $tier0
        tier1             = @($tier1Envelopes)
        tier2             = $tier2
        tier3             = $tier3
        quality           = $quality
        performanceReport = $report
        cleanup           = [pscustomobject][ordered]@{
            status  = $cleanupStatus
            removed = @($cleanupRemoved)
            skipped = @($cleanupSkipped)
            results = @($cleanupResults)
        }
        reasons           = @($reasons)
        errors            = @($errors)
        generatedUtc      = [string](Get-WpdCollectorProperty -InputObject $Plan -Name 'generatedUtc')
        completedUtc      = $completedUtc
        healthClaim       = 'none'
        neverHealthy      = $true
    }

    return $result
}

Export-ModuleMember -Function @(
    'Clear-WpdCollectorTier0Cache',
    'Get-WpdCaptureStrategy',
    'Get-WpdCollectorPerformanceReport',
    'Get-WpdCollectorTier0CacheKey',
    'Get-WpdCollectorTierMap',
    'Get-WpdDefenderSearchContext',
    'Get-WpdFilterContext',
    'Get-WpdGpuContext',
    'Get-WpdNetworkContext',
    'Get-WpdPowerContext',
    'Get-WpdStorageReliabilityContext',
    'Invoke-WpdCollectorPlan',
    'Invoke-WpdTier0Collection',
    'Invoke-WpdTier1Collection',
    'Invoke-WpdTier2Collection',
    'Invoke-WpdTier3Collection',
    'New-WpdBootCollectionDescriptor',
    'New-WpdCollectorEnvelope',
    'New-WpdCollectorPlan',
    'New-WpdCollectorSelfMonitoring',
    'Remove-WpdCollectorArtifact',
    'Test-WpdCaptureStorageBound'
)
