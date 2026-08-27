[CmdletBinding()]
param(
    [ValidateSet('Plan', 'Collect')]
    [string]$Mode = 'Plan',

    [ValidateRange(5, 300)]
    [int]$DurationSeconds = 30,

    [ValidateRange(1, 1000)]
    [int]$MaxEventCount = 200,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location).Path -ChildPath 'windows-performance-diagnostics'),

    [switch]$ConfirmLocalCollection,

    [switch]$CaptureWpr,

    [switch]$ConfirmWprCapture,

    [ValidateSet('General')]
    [string]$WprProfile = 'General',

    [switch]$CaptureDefender,

    [switch]$ConfirmDefenderCapture
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptVersion = '0.4.0'

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $InputObject | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-UtcTimestamp {
    return (Get-Date).ToUniversalTime().ToString('o')
}

function Get-ArtifactMetadata {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    $artifacts = @()
    Get-ChildItem -LiteralPath $Directory -File | Where-Object { $_.Name -ne 'diagnostic-manifest.json' } | ForEach-Object {
        $artifacts += [pscustomobject]@{
            Name = $_.Name
            SizeBytes = $_.Length
            Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        }
    }
    return $artifacts
}

function Get-EventsSafe {
    <#
      Reads a log record-by-record via the low-level .NET reader instead of
      Get-WinEvent -FilterHashtable. Get-WinEvent eagerly formats every record's
      message text as it enumerates, and if even ONE record's provider has a
      missing/mismatched message-resource DLL it throws "EventLogException: The
      specified resource type cannot be found in the image file" and the ENTIRE
      query comes back empty - discarding thousands of good records along with
      the one bad one. Record-by-record lets us skip just the bad one.
      Returns the NEWEST up to MaxEvents records (sliding buffer).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [int]$MaxEvents = 200
    )

    $isoTime = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    $xpath = "*[System[TimeCreated[@SystemTime>='$isoTime']]]"
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
    $buffer = New-Object System.Collections.ArrayList
    $skipped = 0
    try {
        $rec = $reader.ReadEvent()
        while ($null -ne $rec) {
            try {
                $msg = $null
                try {
                    $msg = $rec.FormatDescription()
                }
                catch {
                    $msg = "[message text unavailable: $($_.Exception.Message)]"
                    $skipped++
                }
                $level = $null
                try {
                    $level = $rec.LevelDisplayName
                }
                catch {
                    $level = "Level$($rec.Level)"
                }
                [void]$buffer.Add([pscustomobject]@{
                    TimeCreated = $rec.TimeCreated
                    LevelDisplayName = $level
                    Id = $rec.Id
                    ProviderName = $rec.ProviderName
                    Message = $msg
                })
                if ($buffer.Count -gt $MaxEvents) {
                    $buffer.RemoveAt(0)
                }
            }
            finally {
                $rec.Dispose()
            }
            $rec = $reader.ReadEvent()
        }
    }
    finally {
        $reader.Dispose()
    }
    return [pscustomobject]@{
        Events = @($buffer)
        SkippedMessageCount = $skipped
    }
}

function Get-CrashAnalysis {
    <#
      Decodes BSOD/bugcheck evidence and flags unexplained abrupt shutdowns:
      Kernel-Power 41 without a matching BugCheck event (usually a hard freeze,
      power loss, or thermal cutout rather than a Windows-detected crash).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events
    )

    $bugchecks = @(
        $Events | Where-Object { $_.ProviderName -eq 'BugCheck' -and $_.Id -eq 1001 } | ForEach-Object {
            $code = $null
            if ($_.Message -match '0x[0-9A-Fa-f]{8}') {
                $code = $matches[0]
            }
            [pscustomobject]@{
                TimeCreated = $_.TimeCreated
                BugcheckCode = $code
                Message = $_.Message
            }
        }
    )

    $unexplained = @(
        $Events | Where-Object { $_.ProviderName -match 'Kernel-Power' -and $_.Id -eq 41 } | Where-Object {
            $crashTime = $_.TimeCreated
            -not ($bugchecks | Where-Object { [math]::Abs(($_.TimeCreated - $crashTime).TotalMinutes) -le 5 })
        } | ForEach-Object {
            [pscustomobject]@{
                TimeCreated = $_.TimeCreated
                Message = $_.Message
            }
        }
    )

    return [ordered]@{
        bugchecks = $bugchecks
        unexplainedShutdowns = $unexplained
    }
}

try {
    $resolvedOutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
    New-Item -ItemType Directory -Force -Path $resolvedOutputDirectory | Out-Null
}
catch {
    throw "OutputDirectory '$OutputDirectory' is not a valid local path: $($_.Exception.Message)"
}

$planManifest = [ordered]@{
    schemaVersion = '1.0'
    toolName = 'Windows Performance Diagnostics Toolkit'
    toolVersion = $ScriptVersion
    mode = 'Plan'
    generatedAtUtc = Get-UtcTimestamp
    outputDirectory = $resolvedOutputDirectory
    safety = [ordered]@{
        localOnly = $true
        readOnly = $true
        requiresExplicitCollectionConsent = $true
        automaticUpload = $false
        automaticRemediation = $false
        automaticLogClearing = $false
    }
    plannedActions = @(
        'write-local-plan-manifest',
        'collect-read-only-system-snapshots-after-explicit-consent',
        'export-bounded-system-event-summary-after-explicit-consent',
        'analyze-crash-evidence-after-explicit-consent',
        'write-local-artifact-hashes-after-explicit-consent'
    )
}

if ($CaptureWpr) {
    $planManifest.plannedActions += 'capture-wpr-etl-after-explicit-consent'
    $planManifest.wpr = [ordered]@{
        profile = $WprProfile
        durationSeconds = $DurationSeconds
    }
}

if ($CaptureDefender) {
    $planManifest.plannedActions += 'capture-defender-performance-etl-after-explicit-consent'
    $planManifest.defender = [ordered]@{
        durationSeconds = $DurationSeconds
    }
}

if ($Mode -eq 'Plan') {
    $planPath = Join-Path -Path $resolvedOutputDirectory -ChildPath 'diagnostic-plan.json'
    Write-JsonFile -InputObject $planManifest -Path $planPath
    Write-Output "Plan written to $planPath"
    exit 0
}

if (-not $ConfirmLocalCollection) {
    throw 'Collect mode requires -ConfirmLocalCollection. No diagnostic data was collected.'
}

if (-not $ConfirmWprCapture -and $CaptureWpr) {
    throw 'WPR capture requires -ConfirmWprCapture. No diagnostic data was collected.'
}

if (-not $ConfirmDefenderCapture -and $CaptureDefender) {
    throw 'Defender performance capture requires -ConfirmDefenderCapture. No diagnostic data was collected.'
}

if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'Collect mode is supported only on Windows. Use -Mode Plan for a non-collecting safety plan.'
}

$collectionErrors = @()
function Add-CollectionError {
    param([string]$Stage, [System.Management.Automation.ErrorRecord]$ErrorRecord)

    $script:collectionErrors += [pscustomobject]@{
        Stage = $Stage
        Message = $ErrorRecord.Exception.Message
    }
}

$startedAtUtc = Get-UtcTimestamp
$systemSummary = [ordered]@{}
try {
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $systemSummary = [ordered]@{
        ComputerName = $env:COMPUTERNAME
        WindowsCaption = $operatingSystem.Caption
        WindowsVersion = $operatingSystem.Version
        LastBootUpTime = $operatingSystem.LastBootUpTime
        Manufacturer = $computerSystem.Manufacturer
        Model = $computerSystem.Model
        TotalPhysicalMemoryBytes = $computerSystem.TotalPhysicalMemory
    }
}
catch {
    Add-CollectionError -Stage 'system-summary' -ErrorRecord $_
}

$samples = @()
for ($sampleIndex = 0; $sampleIndex -lt $DurationSeconds; $sampleIndex++) {
    try {
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
        $processors = Get-CimInstance -ClassName Win32_Processor
        $logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType = 3"
        $cpuLoads = @($processors | ForEach-Object { $_.LoadPercentage } | Where-Object { $null -ne $_ })
        $averageCpuLoad = $null
        if ($cpuLoads.Count -gt 0) {
            $averageCpuLoad = [Math]::Round((($cpuLoads | Measure-Object -Average).Average), 2)
        }
        $samples += [pscustomobject]@{
            TimestampUtc = Get-UtcTimestamp
            AverageCpuLoadPercent = $averageCpuLoad
            AvailableMemoryMB = [Math]::Round(($operatingSystem.FreePhysicalMemory / 1024), 2)
            TotalLogicalDiskFreeGB = [Math]::Round((($logicalDisks | Measure-Object -Property FreeSpace -Sum).Sum / 1GB), 2)
        }
    }
    catch {
        Add-CollectionError -Stage 'performance-sample' -ErrorRecord $_
        break
    }

    if ($sampleIndex -lt ($DurationSeconds - 1)) {
        Start-Sleep -Seconds 1
    }
}

try {
    $samples | Export-Csv -LiteralPath (Join-Path -Path $resolvedOutputDirectory -ChildPath 'performance-samples.csv') -NoTypeInformation -Encoding UTF8
}
catch {
    Add-CollectionError -Stage 'performance-export' -ErrorRecord $_
}

try {
    $processes = Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 20 -Property ProcessName, Id, CPU, WorkingSet64, Handles, Path
    Write-JsonFile -InputObject $processes -Path (Join-Path -Path $resolvedOutputDirectory -ChildPath 'top-processes.json')
}
catch {
    Add-CollectionError -Stage 'process-snapshot' -ErrorRecord $_
}

$systemLogInfo = $null
$safeEvents = $null
try {
    $eventStartTime = (Get-Date).AddHours(-24)
    $systemLogInfo = Get-WinEvent -ListLog 'System' -ErrorAction Stop
    $safeEvents = Get-EventsSafe -LogName 'System' -StartTime $eventStartTime -MaxEvents $MaxEventCount
    $events = $safeEvents.Events
    Write-JsonFile -InputObject $events -Path (Join-Path -Path $resolvedOutputDirectory -ChildPath 'system-events-last-24-hours.json')
}
catch {
    Add-CollectionError -Stage 'system-event-summary' -ErrorRecord $_
}

$crashAnalysis = [ordered]@{
    bugchecks = @()
    unexplainedShutdowns = @()
}
try {
    if ($safeEvents -and $safeEvents.Events.Count -gt 0) {
        $crashAnalysis = Get-CrashAnalysis -Events $safeEvents.Events
    }
}
catch {
    Add-CollectionError -Stage 'crash-analysis' -ErrorRecord $_
}

$wprStatus = $null
$wprStartedAtUtc = $null
$wprCompletedAtUtc = $null
$wprEtlFilePath = $null
$wprStartExitCode = $null
$wprStopExitCode = $null

if ($CaptureWpr) {
    $wprStatus = 'skipped-wpr-not-found'
    try {
        $wprExe = Join-Path $env:SystemRoot 'System32\wpr.exe'
        if (-not (Test-Path -LiteralPath $wprExe)) {
            Add-CollectionError -Stage 'wpr-capture' -ErrorRecord ([System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new('wpr.exe not found; WPR capture skipped'),
                'WprNotFound',
                [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                $null
            ))
        }
        else {
            $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isElevated) {
                Add-CollectionError -Stage 'wpr-capture' -ErrorRecord ([System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new('requires an elevated (Administrator) console; WPR capture skipped'),
                    'WprElevationRequired',
                    [System.Management.Automation.ErrorCategory]::PermissionDenied,
                    $null
                ))
                $wprStatus = 'skipped-elevation-required'
            }
            else {
                $wprStartedAtUtc = Get-UtcTimestamp
                $wprEtlPath = Join-Path $resolvedOutputDirectory 'wpr-trace.etl'
                try {
                    & $wprExe -start $WprProfile -filemode
                    $wprStartExitCode = $LASTEXITCODE
                }
                catch {
                    $wprStartExitCode = $LASTEXITCODE
                    Add-CollectionError -Stage 'wpr-capture' -ErrorRecord $_
                    $wprStatus = 'failed'
                }

                if ($wprStatus -ne 'failed') {
                    Start-Sleep -Seconds $DurationSeconds
                    try {
                        & $wprExe -stop $wprEtlPath
                        $wprStopExitCode = $LASTEXITCODE
                        $wprEtlFilePath = $wprEtlPath
                        $wprStatus = 'completed'
                    }
                    catch {
                        $wprStopExitCode = $LASTEXITCODE
                        Add-CollectionError -Stage 'wpr-capture' -ErrorRecord $_
                        $wprStatus = 'failed'
                    }
                    $wprCompletedAtUtc = Get-UtcTimestamp
                }
            }
        }
    }
    catch {
        Add-CollectionError -Stage 'wpr-capture' -ErrorRecord $_
        $wprStatus = 'failed'
    }
}

$defenderStatus = $null
$defenderStartedAtUtc = $null
$defenderCompletedAtUtc = $null
$defenderEtlFilePath = $null
$defenderModuleVersion = $null

if ($CaptureDefender) {
    $defenderStatus = 'skipped-defender-module-not-found'
    try {
        $defenderModule = Get-Module -ListAvailable -Name DefenderPerformance
        if ($null -eq $defenderModule) {
            Add-CollectionError -Stage 'defender-capture' -ErrorRecord ([System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new('DefenderPerformance module not found; Defender performance capture skipped'),
                'DefenderModuleNotFound',
                [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                $null
            ))
        }
        else {
            $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isElevated) {
                Add-CollectionError -Stage 'defender-capture' -ErrorRecord ([System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new('requires an elevated (Administrator) console; Defender performance capture skipped'),
                    'DefenderElevationRequired',
                    [System.Management.Automation.ErrorCategory]::PermissionDenied,
                    $null
                ))
                $defenderStatus = 'skipped-elevation-required'
            }
            else {
                $defenderStartedAtUtc = Get-UtcTimestamp
                $defenderEtlPath = Join-Path $resolvedOutputDirectory 'defender-performance.etl'
                try {
                    Import-Module -Name DefenderPerformance -ErrorAction Stop
                    New-MpPerformanceRecording -RecordTo $defenderEtlPath -Seconds $DurationSeconds -ErrorAction Stop
                    $defenderEtlFilePath = $defenderEtlPath
                    $defenderModuleVersion = (Get-Module -Name DefenderPerformance).Version.ToString()
                    $defenderStatus = 'completed'
                }
                catch {
                    Add-CollectionError -Stage 'defender-capture' -ErrorRecord $_
                    $defenderStatus = 'failed'
                }
                $defenderCompletedAtUtc = Get-UtcTimestamp
            }
        }
    }
    catch {
        Add-CollectionError -Stage 'defender-capture' -ErrorRecord $_
        $defenderStatus = 'failed'
    }
}

$completedAtUtc = Get-UtcTimestamp
$collectionManifest = [ordered]@{
    schemaVersion = '1.0'
    toolName = 'Windows Performance Diagnostics Toolkit'
    toolVersion = $ScriptVersion
    mode = 'Collect'
    startedAtUtc = $startedAtUtc
    completedAtUtc = $completedAtUtc
    outputDirectory = $resolvedOutputDirectory
    scope = [ordered]@{
        durationSeconds = $DurationSeconds
        maxSystemEvents = $MaxEventCount
        systemEventLookbackHours = 24
    }
    safety = $planManifest.safety
    system = $systemSummary
    systemEventLog = [ordered]@{
        enabled = $null
        recordCount = $null
        pulledCount = $null
        skippedUnrenderableCount = $null
    }
    crashAnalysis = $crashAnalysis
    collectionErrors = $collectionErrors
    artifacts = Get-ArtifactMetadata -Directory $resolvedOutputDirectory
}

if ($systemLogInfo -and $safeEvents) {
    $collectionManifest.systemEventLog = [ordered]@{
        enabled = $systemLogInfo.IsEnabled
        recordCount = $systemLogInfo.RecordCount
        pulledCount = $safeEvents.Events.Count
        skippedUnrenderableCount = $safeEvents.SkippedMessageCount
    }
}

if ($CaptureWpr) {
    $collectionManifest.wpr = [ordered]@{
        profile = $WprProfile
        durationSeconds = $DurationSeconds
        etlFilePath = $wprEtlFilePath
        startedAtUtc = $wprStartedAtUtc
        completedAtUtc = $wprCompletedAtUtc
        startExitCode = $wprStartExitCode
        stopExitCode = $wprStopExitCode
        status = $wprStatus
    }
}

if ($CaptureDefender) {
    $collectionManifest.defender = [ordered]@{
        durationSeconds = $DurationSeconds
        etlFilePath = $defenderEtlFilePath
        startedAtUtc = $defenderStartedAtUtc
        completedAtUtc = $defenderCompletedAtUtc
        moduleVersion = $defenderModuleVersion
        status = $defenderStatus
    }
}

$collectionManifestPath = Join-Path -Path $resolvedOutputDirectory -ChildPath 'diagnostic-manifest.json'
Write-JsonFile -InputObject $collectionManifest -Path $collectionManifestPath
Write-Output "Collection complete. Manifest written to $collectionManifestPath"
