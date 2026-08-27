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
    [string]$WprProfile = 'General'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptVersion = '0.2.0'

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

$resolvedOutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $resolvedOutputDirectory | Out-Null

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

try {
    $eventStartTime = (Get-Date).AddHours(-24)
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $eventStartTime } -MaxEvents $MaxEventCount |
        Select-Object -Property TimeCreated, Id, LevelDisplayName, ProviderName, Message
    Write-JsonFile -InputObject $events -Path (Join-Path -Path $resolvedOutputDirectory -ChildPath 'system-events-last-24-hours.json')
}
catch {
    Add-CollectionError -Stage 'system-event-summary' -ErrorRecord $_
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
    collectionErrors = $collectionErrors
    artifacts = Get-ArtifactMetadata -Directory $resolvedOutputDirectory
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

$collectionManifestPath = Join-Path -Path $resolvedOutputDirectory -ChildPath 'diagnostic-manifest.json'
Write-JsonFile -InputObject $collectionManifest -Path $collectionManifestPath
Write-Output "Collection complete. Manifest written to $collectionManifestPath"
