#Requires -Version 5.1
<#
.SYNOPSIS
    Tier 2 ETW surface: WPR markers, circular capture, boot descriptors and the
    WPAExporter adapter.

.DESCRIPTION
    All Windows-only work (wpr.exe, wpaexporter.exe, file-system probes) is
    reached through an injected seam, so the module loads and is testable on a
    host that has no Windows Performance Toolkit, and never pretends to have
    collected something it did not.

    Documented sources for every constructed command line:

    - WPR command-line options:
      https://learn.microsoft.com/windows-hardware/test/wpt/wpr-command-line-options
    - WPAExporter reference:
      https://learn.microsoft.com/windows-hardware/test/wpt/exporter

    Rejected by design: any bound the tool does not document (-maxduration,
    -filesize), -markerflush (obsolete), treating -filemode as bounded (it is
    unbounded until the disk fills), TSS argument names such as BootGeneral in a
    raw wpr.exe command line, and predicting wpaexporter output file names
    (they are generated; glob for them).

    This module is a dependency-free PowerShell 5.1 module: no class keyword,
    no PS7-only operators and no Windows-only call at import time.

.NOTES
    ASCII only. No BOM. Line feeds only. No write/remediation cmdlet anywhere.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------
# Section 1: vocabulary
# --------------------------------------------------------------------------

$script:WpdEtwPluginVersion = '1.0.0'

$script:WpdEtwStatusValues = @(
    'success'
    'partial'
    'unavailable'
    'unsupported'
    'not-collected'
    'error'
)

$script:WpdEtwCoverageStates = @(
    'complete'
    'partial'
    'unavailable'
    'not-collected'
    'unsupported'
)

$script:WpdEtwMarkerNames = @(
    'CAPTURE_START'
    'REPRO_START'
    'INCIDENT_START'
    'INCIDENT_PEAK'
    'INCIDENT_END'
    'CAPTURE_STOP'
)

# WPAExporter table names used by the bounded table plan. Every name is one the
# repository's own WPA analysis guide already documents
# (docs/wpa-analysis-guide.md: CPU Usage (Sampled), CPU Usage (Precise),
# Processes, Disk Usage, File I/O, Wait Analysis) or one the audit names as an
# analysis area (DPC/ISR, ReadyThread). No table name is invented here.
$script:WpdEtwDocumentedTables = @(
    'CPU Usage (Sampled)'
    'CPU Usage (Precise)'
    'Processes'
    'Disk Usage'
    'File I/O'
    'Wait Analysis'
    'DPC/ISR'
    'ReadyThread'
)

# WPR built-in profile names. These are the names the existing entry point
# already accepts; they are WPR built-in profiles, not TSS argument values
# (General/BootGeneral/Device/Memory/Storage/... are TSS-only and are rejected).
$script:WpdEtwDocumentedProfiles = @(
    'GeneralProfile'
    'CPU'
    'DiskIO'
    'FileIO'
    'Network'
    'Power'
    'GPU'
    'Registry'
)

# Preset policy table (decision D2: 13 canonical presets plus 3 deprecated
# aliases). memory mode is the documented default; an unbounded -filemode
# recording is never the default and is reachable only through -AllowFileMode.
# qualifier: 'light' marks a low-overhead long-running recording, 'verbose' the
# detail-oriented recordings.
$script:WpdEtwPresetTable = @(
    [pscustomobject]@{
        preset = 'general'; aliasOf = $null; profile = 'GeneralProfile'; qualifier = 'light'; mode = 'memory'; unbounded = $false
        traceBudgetMB = 512; maxDurationSeconds = 600; expectedDurationSeconds = 300; detailLevel = 'standard'
        tableBudget = 4; onOffScenario = $null
        analysisTables = @('CPU Usage (Sampled)', 'Processes', 'Disk Usage', 'Wait Analysis')
    }
    [pscustomobject]@{
        preset = 'cpu-heavy'; aliasOf = $null; profile = 'CPU'; qualifier = 'verbose'; mode = 'memory'; unbounded = $false
        traceBudgetMB = 768; maxDurationSeconds = 300; expectedDurationSeconds = 120; detailLevel = 'detailed'
        tableBudget = 4; onOffScenario = $null
        analysisTables = @('CPU Usage (Sampled)', 'CPU Usage (Precise)', 'Processes', 'ReadyThread')
    }
    [pscustomobject]@{
        preset = 'memory-pressure'; aliasOf = $null; profile = 'GeneralProfile'; qualifier = 'verbose'; mode = 'memory'; unbounded = $false
        traceBudgetMB = 1024; maxDurationSeconds = 600; expectedDurationSeconds = 300; detailLevel = 'detailed'
        tableBudget = 4; onOffScenario = $null
        analysisTables = @('CPU Usage (Sampled)', 'Processes', 'Disk Usage', 'Wait Analysis')
    }
    [pscustomobject]@{
        preset = 'memory-leak'; aliasOf = $null; profile = 'GeneralProfile'; qualifier = 'verbose'; mode = 'memory'; unbounded = $false
        traceBudgetMB = 1024; maxDurationSeconds = 900; expectedDurationSeconds = 600; detailLevel = 'detailed'
        tableBudget = 3; onOffScenario = $null
        analysisTables = @('CPU Usage (Sampled)', 'Processes', 'Wait Analysis')
    }
    [pscustomobject]@{
        preset = 'storage-io'; aliasOf = $null; profile = 'DiskIO'; qualifier = 'verbose'; mode = 'memory'; unbounded = $false
        traceBudgetMB = 768; maxDurationSeconds = 300; expectedDurationSeconds = 120; detailLevel = 'detailed'
        tableBudget = 3; onOffScenario = $null
        analysisTables = @('Disk Usage', 'File I/O', 'Processes')
    }
    [pscustomobject]@{
        preset = 'network'; aliasOf = $null; profile = 'Network'; qualifier = 'verbose'; mode = 'memory'; unbounded = $false
        traceBudgetMB = 512; maxDurationSeconds = 300; expectedDurationSeconds = 120; detailLevel = 'standard'
        tableBudget = 2; onOffScenario = $null
        analysisTables = @('Processes', 'CPU Usage (Sampled)')
    }
    [pscustomobject]@{
        preset = 'gpu'; aliasOf = $null; profile = 'GPU'; qualifier = 'verbose'; mode = 'memory'; unbounded = $false
        traceBudgetMB = 768; maxDurationSeconds = 300; expectedDurationSeconds = 120; detailLevel = 'detailed'
        tableBudget = 3; onOffScenario = $null
        analysisTables = @('CPU Usage (Sampled)', 'Processes', 'Disk Usage')
    }
    [pscustomobject]@{
        preset = 'ui-hang'; aliasOf = $null; profile = 'CPU'; qualifier = 'verbose'; mode = 'memory'; unbounded = $false
        traceBudgetMB = 512; maxDurationSeconds = 120; expectedDurationSeconds = 60; detailLevel = 'detailed'
        tableBudget = 4; onOffScenario = $null
        analysisTables = @('CPU Usage (Precise)', 'Wait Analysis', 'Processes', 'ReadyThread')
    }
    [pscustomobject]@{
        preset = 'ui-stutter'; aliasOf = $null; profile = 'CPU'; qualifier = 'verbose'; mode = 'memory'; unbounded = $false
        traceBudgetMB = 512; maxDurationSeconds = 180; expectedDurationSeconds = 120; detailLevel = 'detailed'
        tableBudget = 4; onOffScenario = $null
        analysisTables = @('CPU Usage (Precise)', 'Wait Analysis', 'Processes', 'DPC/ISR')
    }
    [pscustomobject]@{
        preset = 'boot-slowdown'; aliasOf = $null; profile = 'GeneralProfile'; qualifier = 'verbose'; mode = 'memory'; unbounded = $false
        traceBudgetMB = 768; maxDurationSeconds = 300; expectedDurationSeconds = 120; detailLevel = 'detailed'
        tableBudget = 3; onOffScenario = 'Boot'
        analysisTables = @('Processes', 'File I/O', 'Disk Usage')
    }
    [pscustomobject]@{
        preset = 'audio-glitch'; aliasOf = $null; profile = 'CPU'; qualifier = 'verbose'; mode = 'memory'; unbounded = $false
        traceBudgetMB = 512; maxDurationSeconds = 180; expectedDurationSeconds = 120; detailLevel = 'detailed'
        tableBudget = 3; onOffScenario = $null
        analysisTables = @('DPC/ISR', 'CPU Usage (Sampled)', 'Processes')
    }
    [pscustomobject]@{
        preset = 'power'; aliasOf = $null; profile = 'Power'; qualifier = 'light'; mode = 'memory'; unbounded = $false
        traceBudgetMB = 256; maxDurationSeconds = 900; expectedDurationSeconds = 600; detailLevel = 'standard'
        tableBudget = 2; onOffScenario = $null
        analysisTables = @('CPU Usage (Sampled)', 'Processes')
    }
    [pscustomobject]@{
        preset = 'intermittent'; aliasOf = $null; profile = 'GeneralProfile'; qualifier = 'light'; mode = 'memory'; unbounded = $false
        traceBudgetMB = 1024; maxDurationSeconds = 1800; expectedDurationSeconds = 900; detailLevel = 'standard'
        tableBudget = 4; onOffScenario = $null
        analysisTables = @('CPU Usage (Sampled)', 'CPU Usage (Precise)', 'Processes', 'Wait Analysis')
    }
    [pscustomobject]@{ preset = 'baseline'; aliasOf = 'general'; profile = $null; qualifier = $null; mode = $null; unbounded = $null
        traceBudgetMB = $null; maxDurationSeconds = $null; expectedDurationSeconds = $null; detailLevel = $null
        tableBudget = $null; onOffScenario = $null; analysisTables = @() }
    [pscustomobject]@{ preset = 'network-io'; aliasOf = 'network'; profile = $null; qualifier = $null; mode = $null; unbounded = $null
        traceBudgetMB = $null; maxDurationSeconds = $null; expectedDurationSeconds = $null; detailLevel = $null
        tableBudget = $null; onOffScenario = $null; analysisTables = @() }
    [pscustomobject]@{ preset = 'application-freeze'; aliasOf = 'ui-hang'; profile = $null; qualifier = $null; mode = $null; unbounded = $null
        traceBudgetMB = $null; maxDurationSeconds = $null; expectedDurationSeconds = $null; detailLevel = $null
        tableBudget = $null; onOffScenario = $null; analysisTables = @() }
)

# --------------------------------------------------------------------------
# Section 2: seams and stubs
# --------------------------------------------------------------------------

function Get-WpdEtwPresetTable {
    <#
    .SYNOPSIS
        The default preset to WPR profile policy table.
    .DESCRIPTION
        Returns the 13 canonical preset rows plus the 3 deprecated alias rows
        (D2). An alias row carries only aliasOf; the policy lives on the
        canonical row so an alias can never drift from its target.
    #>
    [CmdletBinding()]
    param()
    return @($script:WpdEtwPresetTable)
}

function Get-WpdEtwPresetProfile {
    <#
    .SYNOPSIS
        Resolves a functional preset to its WPR profile, qualifier and mode.
    .DESCRIPTION
        Memory mode is the documented default. File mode is unbounded until the
        disk fills, so it is reachable only through an explicit -AllowFileMode
        opt-in, and the returned policy flags it as unbounded.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Preset,
        [AllowNull()] $PresetTable,
        [switch] $AllowFileMode
    )

    $table = @($script:WpdEtwPresetTable)
    if ($null -ne $PresetTable) { $table = @($PresetTable) }

    $requested = $Preset.Trim()
    $row = @($table | Where-Object { $_.preset -eq $requested })
    if ($row.Count -eq 0) {
        $known = @($table | Where-Object { $null -eq $_.aliasOf } | ForEach-Object { $_.preset })
        throw ("Unknown performance preset '{0}'. Known presets: {1}" -f $requested, ($known -join ', '))
    }

    $requestedRow = $row[0]
    $effective = $requested
    $policy = $requestedRow
    if ($null -ne $requestedRow.aliasOf) {
        $effective = $requestedRow.aliasOf
        $canonical = @($table | Where-Object { $_.preset -eq $effective })
        if ($canonical.Count -eq 0) {
            throw ("Preset alias '{0}' points at unknown preset '{1}'" -f $requested, $effective)
        }
        $policy = $canonical[0]
    }

    $mode = 'memory'
    $unbounded = [bool]$policy.unbounded
    $fileModeRequested = $false
    if ($AllowFileMode) {
        $mode = 'file'
        $unbounded = $true
        $fileModeRequested = $true
    }

    $bufferSemantics = 'circular-memory'
    $circularBuffer = $true
    $boundedOnDisk = $true
    $modeNote = 'Memory mode is the documented default: the recording is held in the bounded circular buffer, so the trace cannot grow without limit on disk.'
    if ($unbounded) {
        $bufferSemantics = 'unbounded-file'
        $circularBuffer = $false
        $boundedOnDisk = $false
        $modeNote = 'File mode records to an unbounded file that can grow until it fills the disk; free disk space is the only bound, which is why this mode is an explicit opt-in.'
    }

    [pscustomobject]@{
        RequestedPreset = $requested
        EffectivePreset = $effective
        IsAlias = ($null -ne $requestedRow.aliasOf)
        Profile = $policy.profile
        Qualifier = $policy.qualifier
        ProfileSpec = ("{0}.{1}" -f $policy.profile, $policy.qualifier)
        Mode = $mode
        Unbounded = $unbounded
        FileModeRequested = $fileModeRequested
        BufferSemantics = $bufferSemantics
        CircularBuffer = $circularBuffer
        BoundedOnDisk = $boundedOnDisk
        ModeNote = $modeNote
        TraceBudgetMB = $policy.traceBudgetMB
        MaxDurationSeconds = $policy.maxDurationSeconds
        ExpectedDurationSeconds = $policy.expectedDurationSeconds
        DetailLevel = $policy.detailLevel
        TableBudget = $policy.tableBudget
        OnOffScenario = $policy.onOffScenario
        AnalysisTables = @($policy.analysisTables)
    }
}

# --------------------------------------------------------------------------
# Section 2: command construction seam
# --------------------------------------------------------------------------

function New-WpdEtwCommand {
    <#
    .SYNOPSIS
        Builds the command record every constructor returns.
    .DESCRIPTION
        The record is transport-neutral: Tool/ToolPath name the executable,
        Arguments is the exact argv array (no shell quoting is involved), and
        CommandLine is the audit string recorded in the manifest. Tests assert
        Arguments so an undocumented switch cannot hide inside quoting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Tool,
        [AllowNull()] [string] $ToolPath,
        [Parameter(Mandatory = $true)][string] $Kind,
        [AllowNull()] [string[]] $Arguments,
        [AllowNull()] [string] $ProfileSpec,
        [AllowNull()] [string] $Mode,
        [AllowNull()] [string] $InstanceName
    )

    $argv = @()
    if ($null -ne $Arguments) { $argv = @($Arguments) }
    foreach ($item in $argv) {
        if ($null -eq $item) { throw ("Command '{0}' contains a null argument" -f $Kind) }
    }

    $resolved = $Tool
    if (-not [string]::IsNullOrWhiteSpace($ToolPath)) { $resolved = $ToolPath }

    [pscustomobject]@{
        Kind = $Kind
        Tool = $Tool
        ToolPath = $resolved
        Arguments = @($argv)
        ArgumentCount = $argv.Count
        ProfileSpec = $ProfileSpec
        Mode = $Mode
        InstanceName = $InstanceName
        CommandLine = ("{0} {1}" -f $resolved, ($argv -join ' ')).Trim()
    }
}

function New-WpdEtwWprStartCommand {
    <#
    .SYNOPSIS
        Builds the documented `wpr -start` command line.

    .DESCRIPTION
        Documented form:
          wpr -start <profile> [-start <profilen>]... [-filemode]
              [-recordtempto <temp folder path>]
              [-onoffscenario <OnOff Transition Type>]
              [-onoffresultspath <path>] [-onoffproblemdescription <text>]
              [-numiterations <n>]

        The profile is named <profile name>[.{light|verbose}]. The qualifier
        comes from the preset policy unless it is supplied directly. -filemode
        is emitted only when the preset policy was built with an explicit file
        mode opt-in, because file mode is unbounded until the disk fills.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] $PresetProfile,
        [AllowNull()] [string] $Profile,
        [ValidateSet('light', 'verbose')][string] $Qualifier = 'verbose',
        [ValidateSet('memory', 'file')][string] $Mode = 'memory',
        [AllowNull()]
        [ValidateSet('Boot', 'FastStartup', 'Shutdown', 'RebootCycle', 'Standby', 'Hibernate')]
        [string] $OnOffScenario,
        [AllowNull()] [string] $OnOffResultsPath,
        [AllowNull()] [string] $OnOffProblemDescription,
        [AllowNull()] [int] $NumIterations,
        [AllowNull()] [string] $InstanceName,
        [AllowNull()] [string] $WprExePath
    )

    $profileName = $Profile
    $qualifierValue = $Qualifier
    $modeValue = $Mode
    if ($null -ne $PresetProfile) {
        $profileName = $PresetProfile.Profile
        $qualifierValue = $PresetProfile.Qualifier
        $modeValue = $PresetProfile.Mode
    }
    if ([string]::IsNullOrWhiteSpace($profileName)) {
        throw 'A preset policy or -Profile is required to build a wpr -start command.'
    }
    if ($qualifierValue -ne 'light' -and $qualifierValue -ne 'verbose') {
        throw ("Unsupported WPR profile qualifier '{0}'. Documented values are light and verbose." -f $qualifierValue)
    }

    $profileSpec = ("{0}.{1}" -f $profileName, $qualifierValue)
    $argv = New-Object System.Collections.ArrayList
    [void]$argv.Add('-start')
    [void]$argv.Add($profileSpec)
    if ($modeValue -eq 'file') { [void]$argv.Add('-filemode') }

    if (-not [string]::IsNullOrWhiteSpace($OnOffScenario)) {
        [void]$argv.Add('-onoffscenario')
        [void]$argv.Add($OnOffScenario)
        if (-not [string]::IsNullOrWhiteSpace($OnOffResultsPath)) {
            [void]$argv.Add('-onoffresultspath')
            [void]$argv.Add($OnOffResultsPath)
        }
        if (-not [string]::IsNullOrWhiteSpace($OnOffProblemDescription)) {
            [void]$argv.Add('-onoffproblemdescription')
            [void]$argv.Add($OnOffProblemDescription)
        }
        if ($PSBoundParameters.ContainsKey('NumIterations') -and $null -ne $NumIterations) {
            [void]$argv.Add('-numiterations')
            [void]$argv.Add(([string]$NumIterations))
        }
    }

    # -instancename must be the last parameter on the command line.
    if (-not [string]::IsNullOrWhiteSpace($InstanceName)) {
        [void]$argv.Add('-instancename')
        [void]$argv.Add($InstanceName)
    }

    return New-WpdEtwCommand -Tool 'wpr.exe' -ToolPath $WprExePath -Kind 'start' `
        -Arguments @($argv) -ProfileSpec $profileSpec -Mode $modeValue -InstanceName $InstanceName
}

function New-WpdEtwWprStopCommand {
    <#
    .SYNOPSIS
        Builds the documented `wpr -stop <file> <problem description>` command line.

    .DESCRIPTION
        Documented form: wpr -stop <file> <problem description> [-skipPdbGen]
        [-force] [-compress]. The file name is required; the problem description
        is recommended but optional, so it is omitted rather than defaulted when
        the caller does not supply one. -skipPdbGen is offered because it reduces
        the stop time by disabling ngen/embedded PDB generation, and -force is
        offered for a non-.etl target.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $EtlPath,
        [AllowNull()] [string] $ProblemDescription,
        [switch] $SkipPdbGen,
        [switch] $Force,
        [AllowNull()] [string] $InstanceName,
        [AllowNull()] [string] $WprExePath
    )

    $argv = New-Object System.Collections.ArrayList
    [void]$argv.Add('-stop')
    [void]$argv.Add($EtlPath)
    if (-not [string]::IsNullOrWhiteSpace($ProblemDescription)) { [void]$argv.Add($ProblemDescription) }
    if ($SkipPdbGen) { [void]$argv.Add('-skipPdbGen') }
    if ($Force) { [void]$argv.Add('-force') }
    if (-not [string]::IsNullOrWhiteSpace($InstanceName)) {
        [void]$argv.Add('-instancename')
        [void]$argv.Add($InstanceName)
    }

    return New-WpdEtwCommand -Tool 'wpr.exe' -ToolPath $WprExePath -Kind 'stop' `
        -Arguments @($argv) -InstanceName $InstanceName
}

function New-WpdEtwWprCancelCommand {
    <#
    .SYNOPSIS
        Builds the documented `wpr -cancel` command line.

    .DESCRIPTION
        `wpr -cancel` takes no arguments and returns an error when no instance is
        active, so the caller must treat that exit code as an expected outcome of
        a cleanup path rather than a capture failure.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [string] $InstanceName,
        [AllowNull()] [string] $WprExePath
    )

    $argv = New-Object System.Collections.ArrayList
    [void]$argv.Add('-cancel')
    if (-not [string]::IsNullOrWhiteSpace($InstanceName)) {
        [void]$argv.Add('-instancename')
        [void]$argv.Add($InstanceName)
    }

    return New-WpdEtwCommand -Tool 'wpr.exe' -ToolPath $WprExePath -Kind 'cancel' `
        -Arguments @($argv) -InstanceName $InstanceName
}

function New-WpdEtwWprStatusCommand {
    <#
    .SYNOPSIS
        Builds the documented `wpr -status [profiles] [collectors [-details]]` line.

    .DESCRIPTION
        The bare form reports whether a recording is active, its elapsed time,
        the dropped-event count and the logging mode. `collectors` adds per-
        collector information including lost buffers, which is how an abandoned
        session and a lossy session are both reconciled after the fact.
    #>
    [CmdletBinding()]
    param(
        [switch] $Collectors,
        [switch] $Details,
        [AllowNull()] [string] $InstanceName,
        [AllowNull()] [string] $WprExePath
    )

    $argv = New-Object System.Collections.ArrayList
    [void]$argv.Add('-status')
    if ($Details) {
        # -details is documented only together with collectors.
        [void]$argv.Add('collectors')
        [void]$argv.Add('-details')
    }
    elseif ($Collectors) {
        [void]$argv.Add('collectors')
    }
    if (-not [string]::IsNullOrWhiteSpace($InstanceName)) {
        [void]$argv.Add('-instancename')
        [void]$argv.Add($InstanceName)
    }

    return New-WpdEtwCommand -Tool 'wpr.exe' -ToolPath $WprExePath -Kind 'status' `
        -Arguments @($argv) -InstanceName $InstanceName
}

function New-WpdEtwWprProfilesCommand {
    <#
    .SYNOPSIS
        Builds the documented `wpr -profiles [<path>]` command line.

    .DESCRIPTION
        With no path this enumerates the built-in profiles; the enumeration is
        the authoritative check that a preset's profile name exists on the target
        machine, which is why it is offered as a first-class command.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [string] $ProfilePath,
        [AllowNull()] [string] $WprExePath
    )

    $argv = New-Object System.Collections.ArrayList
    [void]$argv.Add('-profiles')
    if (-not [string]::IsNullOrWhiteSpace($ProfilePath)) { [void]$argv.Add($ProfilePath) }

    return New-WpdEtwCommand -Tool 'wpr.exe' -ToolPath $WprExePath -Kind 'profiles' `
        -Arguments @($argv)
}

function New-WpdEtwWprMarkerCommand {
    <#
    .SYNOPSIS
        Builds the documented `wpr -marker <text> [-flush]` command line.

    .DESCRIPTION
        The marker text is the toolkit's incident marker name, so the marker
        event inside the ETL can be aligned to the counter window and to the
        WPAExporter -marks range. -markerflush is obsolete and is never emitted;
        the documented equivalent is -marker <text> -flush.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('CAPTURE_START', 'REPRO_START', 'INCIDENT_START', 'INCIDENT_PEAK', 'INCIDENT_END', 'CAPTURE_STOP')]
        [string] $Marker,
        [switch] $Flush,
        [AllowNull()] [string] $InstanceName,
        [AllowNull()] [string] $WprExePath
    )

    $argv = New-Object System.Collections.ArrayList
    [void]$argv.Add('-marker')
    [void]$argv.Add($Marker)
    if ($Flush) { [void]$argv.Add('-flush') }
    if (-not [string]::IsNullOrWhiteSpace($InstanceName)) {
        [void]$argv.Add('-instancename')
        [void]$argv.Add($InstanceName)
    }

    return New-WpdEtwCommand -Tool 'wpr.exe' -ToolPath $WprExePath -Kind 'marker' `
        -Arguments @($argv) -InstanceName $InstanceName
}

function New-WpdEtwBootScenarioDescriptor {
    <#
    .SYNOPSIS
        Describes an On/Off or autologger boot recording. Never executes it.

    .DESCRIPTION
        Two documented mechanics, deliberately kept as descriptions:

        - Mechanism 'onoff': wpr -start <profile> -onoffscenario <type>
          -onoffresultspath <path> -onoffproblemdescription <text>
          [-numiterations <n>]. On/off transitions are always logged to a file
          and reboot the computer three times by default, so this is not a
          single-boot capture unless -NumIterations is set.
        - Mechanism 'boottrace': wpr -boottrace -addboot <profile>, completed by
          wpr -boottrace -stopboot <file> <description> and cancelled by
          wpr -boottrace -cancelboot. -addboot only sets the autologger registry
          entries; the operating system starts the session after the next reboot,
          and -stopboot writes a trace only if that session actually ran.

        The returned descriptor carries Executed = $false and
        RequiresOperatorApproval = $true, because a boot recording changes what
        survives a reboot and is therefore an explicit operator decision (R4: no
        automatic remediation, no reboot).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Boot', 'FastStartup', 'Shutdown', 'RebootCycle', 'Standby', 'Hibernate')]
        [string] $Scenario,
        [ValidateSet('onoff', 'boottrace')][string] $Mechanism = 'onoff',
        [AllowNull()] [string] $Profile,
        [ValidateSet('light', 'verbose')][string] $Qualifier = 'verbose',
        [AllowNull()] [string] $ResultsPath,
        [AllowNull()] [string] $ProblemDescription,
        [AllowNull()] [int] $NumIterations,
        [AllowNull()] [string] $WprExePath
    )

    $profileName = $Profile
    if ([string]::IsNullOrWhiteSpace($profileName)) { $profileName = 'GeneralProfile' }
    $profileSpec = ("{0}.{1}" -f $profileName, $Qualifier)

    $warnings = @()
    $iterationCount = 3
    if ($Mechanism -eq 'onoff') {
        $assignment = New-WpdEtwWprStartCommand -Profile $profileName -Qualifier $Qualifier `
            -OnOffScenario $Scenario -OnOffResultsPath $ResultsPath `
            -OnOffProblemDescription $ProblemDescription -NumIterations $NumIterations -WprExePath $WprExePath
        if ($PSBoundParameters.ContainsKey('NumIterations') -and $null -ne $NumIterations) {
            $iterationCount = $NumIterations
        }
        $completion = $null
        if (-not [string]::IsNullOrWhiteSpace($ResultsPath)) {
            $completion = New-WpdEtwWprStopCommand -EtlPath $ResultsPath -ProblemDescription $ProblemDescription -WprExePath $WprExePath
        }
        $cleanup = New-WpdEtwWprCancelCommand -WprExePath $WprExePath
        if ($null -eq $completion) {
            $warnings += "No -ResultsPath was supplied: the recording has no target file, so the -stop command cannot be described yet."
        }
        $warnings += ("On/off scenario recording is always logged to a file, not to the memory circular buffer.")
        $warnings += ("The documented default is three reboots; this descriptor records {0}. A single-transition capture requires -numiterations 1." -f $iterationCount)
        $warnings += "The recording cannot start from this toolkit: it is returned as a descriptor for the operator to run after an explicit reboot approval."
    }
    else {
        $assignmentArgs = @('-boottrace', '-addboot', $profileSpec)
        $assignment = New-WpdEtwCommand -Tool 'wpr.exe' -ToolPath $WprExePath -Kind 'boottrace-addboot' `
            -Arguments $assignmentArgs -ProfileSpec $profileSpec
        $completionArgs = @('-boottrace', '-stopboot')
        if (-not [string]::IsNullOrWhiteSpace($ResultsPath)) { $completionArgs += $ResultsPath }
        if (-not [string]::IsNullOrWhiteSpace($ProblemDescription)) { $completionArgs += $ProblemDescription }
        $completion = New-WpdEtwCommand -Tool 'wpr.exe' -ToolPath $WprExePath -Kind 'boottrace-stopboot' -Arguments $completionArgs
        $cleanup = New-WpdEtwCommand -Tool 'wpr.exe' -ToolPath $WprExePath -Kind 'boottrace-cancelboot' `
            -Arguments @('-boottrace', '-cancelboot')
        $iterationCount = 1
        $warnings += "-addboot only configures the autologger registry entries; the operating system starts the session after the next reboot."
        $warnings += "-stopboot writes a trace only if that autologger session ran after a reboot; otherwise it removes the configuration and produces nothing."
        $warnings += "Never executed by this toolkit: the descriptor is returned for an operator-approved boot capture."
    }

    [pscustomobject]@{
        Kind = 'boot-descriptor'
        Mechanism = $Mechanism
        Scenario = $Scenario
        ProfileSpec = $profileSpec
        Executed = $false
        RequiresOperatorApproval = $true
        RequiresReboot = $true
        FileBacked = $true
        MemoryMode = $false
        RebootCount = $iterationCount
        SuggestedIterations = $iterationCount
        ResultsPath = $ResultsPath
        Assignment = $assignment
        Completion = $completion
        Cleanup = $cleanup
        Warnings = @($warnings)
    }
}

function New-WpdEtwExporterCommand {
    <#
    .SYNOPSIS
        Builds the documented wpaexporter.exe command line.

    .DESCRIPTION
        Documented form:

          wpaexporter.exe [-i] traceFile.etl -profile profile.wpaProfile
              [-delimiter <char>] [-prefix <prefix>] [-outputfolder <folder>]
              [-range <start> <end>] [-marks <M1> <M2>] [-regionsxml <manifest> ...]
              [-region <region_name>] [-symbols] [-tti]

        A .wpaProfile is required: it is the profile that selects the tables, and
        the documentation states it cannot be replaced by a preset name. The
        incident range can be a marker pair (-marks, which is how the toolkit's
        own CAPTURE_START/INCIDENT_*/CAPTURE_STOP markers are used) or a -range in
        seconds/milliseconds/nanoseconds. Without either, the whole trace is
        exported, which is stated in the Notes.

        Output file names are generated from the table and preset names, so this
        command never carries a file name: callers glob the output folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $TracePath,
        [AllowNull()] [string] $WpaProfilePath,
        [AllowNull()] [string] $OutputFolder,
        [AllowNull()] [string] $Prefix,
        [AllowNull()] [string] $Delimiter,
        [AllowNull()] [string] $RangeStart,
        [AllowNull()] [string] $RangeEnd,
        [AllowNull()] [string[]] $Marks,
        [switch] $Symbols,
        [switch] $Tti,
        [AllowNull()] $SymbolPolicy,
        [AllowNull()] [string] $ExporterPath
    )

    if ([string]::IsNullOrWhiteSpace($WpaProfilePath)) {
        throw 'wpaexporter requires a .wpaProfile: the profile selects the exported tables and cannot be replaced by a preset name.'
    }

    $markCount = 0
    if ($null -ne $Marks) { $markCount = @($Marks).Count }
    if ($markCount -ne 0 -and $markCount -ne 2) {
        throw ("The documented -marks form takes exactly two markers (<M1> <M2>); {0} were supplied." -f $markCount)
    }

    $hasRange = (-not [string]::IsNullOrWhiteSpace($RangeStart)) -or (-not [string]::IsNullOrWhiteSpace($RangeEnd))
    if ($hasRange -and ([string]::IsNullOrWhiteSpace($RangeStart) -or [string]::IsNullOrWhiteSpace($RangeEnd))) {
        throw 'The documented -range form takes a start and an end; supply both or neither.'
    }

    $notes = @()
    $useSymbols = [bool]$Symbols
    $symbolState = $null
    if ($null -ne $SymbolPolicy) {
        $symbolState = [string]$SymbolPolicy.State
        if ([bool]$SymbolPolicy.SymbolsPresent) { $useSymbols = $true }
        else { $notes += 'No managed symbols were found beside the trace, so -symbols is not used; symbol-dependent tables are reported as unavailable.' }
    }

    $argv = New-Object System.Collections.ArrayList
    [void]$argv.Add('-i')
    [void]$argv.Add($TracePath)
    [void]$argv.Add('-profile')
    [void]$argv.Add($WpaProfilePath)
    if (-not [string]::IsNullOrWhiteSpace($Delimiter)) {
        [void]$argv.Add('-delimiter')
        [void]$argv.Add($Delimiter)
    }
    if (-not [string]::IsNullOrWhiteSpace($Prefix)) {
        [void]$argv.Add('-prefix')
        [void]$argv.Add($Prefix)
    }
    if (-not [string]::IsNullOrWhiteSpace($OutputFolder)) {
        [void]$argv.Add('-outputfolder')
        [void]$argv.Add($OutputFolder)
    }
    if ($hasRange) {
        [void]$argv.Add('-range')
        [void]$argv.Add($RangeStart)
        [void]$argv.Add($RangeEnd)
    }
    if ($markCount -eq 2) {
        [void]$argv.Add('-marks')
        [void]$argv.Add([string]$Marks[0])
        [void]$argv.Add([string]$Marks[1])
    }
    if ($useSymbols) { [void]$argv.Add('-symbols') }
    if ($Tti) { [void]$argv.Add('-tti') }

    if (-not $hasRange -and $markCount -eq 0) {
        $notes += 'No -range and no -marks were supplied, so the entire trace duration is exported.'
    }

    $command = New-WpdEtwCommand -Tool 'wpaexporter.exe' -ToolPath $ExporterPath -Kind 'export' -Arguments @($argv)
    $command | Add-Member -NotePropertyName OutputFolder -NotePropertyValue $OutputFolder -Force
    $command | Add-Member -NotePropertyName Prefix -NotePropertyValue $Prefix -Force
    $command | Add-Member -NotePropertyName OutputNameIsGenerated -NotePropertyValue $true -Force
    $command | Add-Member -NotePropertyName Marks -NotePropertyValue @($Marks) -Force
    $command | Add-Member -NotePropertyName RangeStart -NotePropertyValue $RangeStart -Force
    $command | Add-Member -NotePropertyName RangeEnd -NotePropertyValue $RangeEnd -Force
    $command | Add-Member -NotePropertyName SymbolsUsed -NotePropertyValue $useSymbols -Force
    $command | Add-Member -NotePropertyName SymbolPolicyState -NotePropertyValue $symbolState -Force
    $command | Add-Member -NotePropertyName Notes -NotePropertyValue @($notes) -Force
    return $command
}

function Get-WpdEtwAnalysisTablePlan {
    <#
    .SYNOPSIS
        Bounded WPAExporter table selection for a preset.

    .DESCRIPTION
        The preset decides which tables matter; the plan caps how many are
        exported so a case folder cannot grow a table per analysis area. Tables
        dropped by the cap are recorded with a reason instead of disappearing
        silently, and every emitted name is one the repository's own WPA guide
        already documents - no table name is invented.

        A .wpaProfile remains required for the export itself; the table plan
        documents which tables that profile must select, it does not replace it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Preset,
        [AllowNull()] $PresetTable,
        [AllowNull()] [int] $MaxTables
    )

    $profile = Get-WpdEtwPresetProfile -Preset $Preset -PresetTable $PresetTable
    $requested = @($profile.AnalysisTables)
    $budget = [int]$profile.TableBudget
    $cap = $budget
    if ($PSBoundParameters.ContainsKey('MaxTables') -and $null -ne $MaxTables -and $MaxTables -gt 0) {
        if ($MaxTables -lt $budget) { $cap = [int]$MaxTables }
    }

    $selected = @()
    $excluded = @()
    $index = 0
    foreach ($table in $requested) {
        if ($index -lt $cap) {
            $selected += $table
        }
        else {
            $excluded += [pscustomobject]@{
                table = $table
                reason = ("Bounded by the exporter table budget ({0} of {1} tables selected for preset '{2}')." -f $cap, $requested.Count, $profile.EffectivePreset)
            }
        }
        $index++
    }

    $notSelectedByPreset = @()
    foreach ($documented in $script:WpdEtwDocumentedTables) {
        if ($requested -notcontains $documented) {
            $notSelectedByPreset += [pscustomobject]@{
                table = $documented
                reason = ("Not selected by preset '{0}'." -f $profile.EffectivePreset)
            }
        }
    }

    $hasSampled = ($selected -contains 'CPU Usage (Sampled)')
    $hasPrecise = ($selected -contains 'CPU Usage (Precise)')

    [pscustomobject]@{
        Preset = $profile.RequestedPreset
        EffectivePreset = $profile.EffectivePreset
        Tables = @($selected)
        TableCount = @($selected).Count
        TableBudget = $budget
        MaxTables = $cap
        Excluded = @($excluded)
        NotSelectedByPreset = @($notSelectedByPreset)
        DocumentedTables = @($script:WpdEtwDocumentedTables)
        KeepsSampledAndPrecise = ($hasSampled -and $hasPrecise)
        ExporterProfileRequired = $true
        ExporterProfileNote = 'A .wpaProfile is required for the export; this plan states which tables that profile must select.'
    }
}

function Get-WpdEtwTraceValidation {
    <#
    .SYNOPSIS
        Validates a produced ETL: presence, emptiness and the size policy.

    .DESCRIPTION
        A trace that was not produced is 'unavailable' with the reason stated; an
        empty trace is detected and reported; an oversized trace is reported with
        its real measured size and marked for removal (wpr.exe has no documented
        file-size switch, so the size is enforced after the trace is written);
        and a non-zero -start or -stop exit code downgrades the result.

        This function never asserts health: a produced trace is evidence, not a
        verdict (R2/R5).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [string] $EtlPath,
        [AllowNull()] [long] $SizeBytes,
        [AllowNull()] [int] $MaxTraceSizeMB,
        [AllowNull()] [int] $StartExitCode,
        [AllowNull()] [int] $StopExitCode
    )

    $capMB = 512
    if ($PSBoundParameters.ContainsKey('MaxTraceSizeMB') -and $null -ne $MaxTraceSizeMB -and $MaxTraceSizeMB -gt 0) {
        $capMB = [int]$MaxTraceSizeMB
    }
    $capBytes = [long]($capMB * 1MB)

    $startSucceeded = $true
    if ($PSBoundParameters.ContainsKey('StartExitCode') -and $null -ne $StartExitCode -and [int]$StartExitCode -ne 0) { $startSucceeded = $false }
    $stopSucceeded = $true
    if ($PSBoundParameters.ContainsKey('StopExitCode') -and $null -ne $StopExitCode -and [int]$StopExitCode -ne 0) { $stopSucceeded = $false }

    $exists = $false
    if ($PSBoundParameters.ContainsKey('SizeBytes') -and $null -ne $SizeBytes -and $SizeBytes -ge 0) { $exists = $true }

    $warnings = @()
    $result = [ordered]@{
        EtlPath = $EtlPath
        Exists = $exists
        EtlBytes = $null
        MaxTraceSizeMB = $capMB
        Empty = $false
        Oversized = $false
        Kept = $false
        TraceRemoved = $false
        StartSucceeded = $startSucceeded
        StopSucceeded = $stopSucceeded
        Healthy = $false
        Status = 'unavailable'
        Reason = ''
        Warnings = @()
    }

    if (-not $exists) {
        $result.Reason = 'The trace file was not produced, so no ETW evidence exists for this capture.'
        return [pscustomobject]$result
    }

    $result.EtlBytes = [long]$SizeBytes
    $result.Status = 'success'
    $result.Kept = $true
    $result.Reason = 'The trace exists and is within the size policy.'

    if ([long]$SizeBytes -eq 0) {
        $result.Empty = $true
        $result.Status = 'partial'
        $result.Reason = 'The trace exists but is empty: nothing was recorded in the capture window.'
    }
    elseif ([long]$SizeBytes -gt $capBytes) {
        $result.Oversized = $true
        $result.Status = 'partial'
        $result.Kept = $false
        $result.TraceRemoved = $true
        $result.Reason = ("The trace is {0} bytes, above the {1} MB advisory cap; it is removed from the case folder and its measured size is kept in the manifest." -f $SizeBytes, $capMB)
    }

    if (-not $startSucceeded) {
        $result.Status = 'partial'
        $warnings += ("wpr -start exited with code {0}." -f $StartExitCode)
    }
    if (-not $stopSucceeded) {
        $result.Status = 'partial'
        $warnings += ("wpr -stop exited with code {0}; the trace may be truncated or unmmerged." -f $StopExitCode)
    }

    $result.Warnings = @($warnings)
    return [pscustomobject]$result
}

function Test-WpdEtwCapturePreflight {
    <#
    .SYNOPSIS
        Free-space, trace-size and duration preflight before a capture starts.

    .DESCRIPTION
        A trace is only started when it can be completed:

        - the requested duration must not exceed the preset's maximum duration;
        - file mode is unbounded until the disk fills, so it is refused unless
          the caller explicitly accepts the unbounded recording;
        - the free space on the target volume must cover the preset's trace
          budget plus a safety headroom (a clamp is never silent);
        - an unmeasured free-space value is 'unavailable', never a pass (R2).

        Measuring free space is Windows-only work and is therefore attempted
        defensively: a failed measurement leaves the value unknown and the
        preflight reports 'unavailable' instead of assuming room.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] $PresetProfile,
        [AllowNull()] [string] $OutputDirectory,
        [AllowNull()] [long] $FreeSpaceBytes,
        [AllowNull()] [int] $RequestedDurationSeconds,
        [AllowNull()] [int] $MaxTraceSizeMB,
        [switch] $AcceptUnboundedFileMode
    )

    $warnings = @()
    $budgetMB = 512
    $maxDurationSeconds = 600
    $mode = 'memory'
    $unbounded = $false
    if ($null -ne $PresetProfile) {
        $budgetMB = [int]$PresetProfile.TraceBudgetMB
        $maxDurationSeconds = [int]$PresetProfile.MaxDurationSeconds
        $mode = [string]$PresetProfile.Mode
        $unbounded = [bool]$PresetProfile.Unbounded
    }

    if ($PSBoundParameters.ContainsKey('MaxTraceSizeMB') -and $null -ne $MaxTraceSizeMB -and $MaxTraceSizeMB -gt 0) {
        if ($MaxTraceSizeMB -le $budgetMB) {
            $budgetMB = [int]$MaxTraceSizeMB
        }
        else {
            $warnings += ("A requested trace size of {0} MB exceeds the preset budget of {1} MB; the preset budget is kept because the trace budget is a preset contract." -f $MaxTraceSizeMB, $budgetMB)
        }
    }

    $duration = $maxDurationSeconds
    if ($PSBoundParameters.ContainsKey('RequestedDurationSeconds') -and $null -ne $RequestedDurationSeconds) {
        $duration = [int]$RequestedDurationSeconds
    }

    $headroomBytes = [long]([Math]::Max(256L * 1MB, [long]($budgetMB * 1MB) / 4))
    $requiredBytes = [long]([long]($budgetMB * 1MB) + $headroomBytes)

    $freeBytes = $null
    if ($PSBoundParameters.ContainsKey('FreeSpaceBytes') -and $null -ne $FreeSpaceBytes -and $FreeSpaceBytes -ge 0) {
        $freeBytes = [long]$FreeSpaceBytes
    }
    elseif (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) {
        try {
            $root = [System.IO.Path]::GetPathRoot($OutputDirectory)
            if (-not [string]::IsNullOrWhiteSpace($root)) {
                $drive = New-Object System.IO.DriveInfo($root)
                $freeBytes = [long]$drive.AvailableFreeSpace
            }
        }
        catch {
            $freeBytes = $null
        }
    }

    if ($unbounded -and -not $AcceptUnboundedFileMode) {
        return [pscustomobject]@{
            Status = 'unbounded-file-mode'
            Ready = $false
            Mode = $mode
            Unbounded = $true
            TraceBudgetMB = $budgetMB
            MaxDurationSeconds = $maxDurationSeconds
            RequestedDurationSeconds = $duration
            FreeSpaceBytes = $freeBytes
            RequiredBytes = $requiredBytes
            DeficitBytes = $null
            DurationBounded = $true
            Reason = 'File mode records to an unbounded file that can grow until it fills the disk, so it requires an explicit acceptance (-AcceptUnboundedFileMode) or memory mode.'
            Warnings = @($warnings)
        }
    }

    if ($duration -gt $maxDurationSeconds) {
        return [pscustomobject]@{
            Status = 'duration-exceeds-preset'
            Ready = $false
            Mode = $mode
            Unbounded = $unbounded
            TraceBudgetMB = $budgetMB
            MaxDurationSeconds = $maxDurationSeconds
            RequestedDurationSeconds = $duration
            FreeSpaceBytes = $freeBytes
            RequiredBytes = $requiredBytes
            DeficitBytes = $null
            DurationBounded = $false
            Reason = ("The requested duration of {0} s exceeds the preset maximum of {1} s." -f $duration, $maxDurationSeconds)
            Warnings = @($warnings)
        }
    }

    if ($null -eq $freeBytes) {
        return [pscustomobject]@{
            Status = 'unavailable'
            Ready = $false
            Mode = $mode
            Unbounded = $unbounded
            TraceBudgetMB = $budgetMB
            MaxDurationSeconds = $maxDurationSeconds
            RequestedDurationSeconds = $duration
            FreeSpaceBytes = $null
            RequiredBytes = $requiredBytes
            DeficitBytes = $null
            DurationBounded = $true
            Reason = 'The free space on the target volume could not be measured, so the capture cannot be preflighted. Free space was not assumed.'
            Warnings = @($warnings)
        }
    }

    if ($freeBytes -lt $requiredBytes) {
        return [pscustomobject]@{
            Status = 'insufficient-space'
            Ready = $false
            Mode = $mode
            Unbounded = $unbounded
            TraceBudgetMB = $budgetMB
            MaxDurationSeconds = $maxDurationSeconds
            RequestedDurationSeconds = $duration
            FreeSpaceBytes = $freeBytes
            RequiredBytes = $requiredBytes
            DeficitBytes = [long]($requiredBytes - $freeBytes)
            DurationBounded = $true
            Reason = ("Only {0} bytes of free space are available for a trace that needs {1} bytes (budget plus headroom)." -f $freeBytes, $requiredBytes)
            Warnings = @($warnings)
        }
    }

    if ($unbounded) {
        $warnings += 'File mode is unbounded: the trace can grow until the disk fills, and only the free-space check above bounds it.'
    }

    [pscustomobject]@{
        Status = 'ready'
        Ready = $true
        Mode = $mode
        Unbounded = $unbounded
        TraceBudgetMB = $budgetMB
        MaxDurationSeconds = $maxDurationSeconds
        RequestedDurationSeconds = $duration
        FreeSpaceBytes = $freeBytes
        RequiredBytes = $requiredBytes
        DeficitBytes = 0
        DurationBounded = $true
        Reason = 'The preset budget, the requested duration and the free space check passed.'
        Warnings = @($warnings)
    }
}

function Test-WpdEtwAbandonedSession {
    <#
    .SYNOPSIS
        Detects a running WPR session left behind by this toolkit.

    .DESCRIPTION
        Reads `wpr -status` output. The bare status form reports whether a
        recording is active, its elapsed time, the dropped-event count and the
        logging mode, which is exactly the reconciliation the WPR gate needs.

        Ownership is proven by the documented -instancename value this toolkit
        set when it started the recording; -OwnerTag is the naming convention for
        instance names this toolkit builds, so an instance name equal to the
        expected name (or prefixed with the owner tag) is ours. A running session
        with any other instance name is another product's recording: it is
        reported as foreign and is NEVER cancelled, because the data does not
        belong to this toolkit.

        An unreadable status is 'unavailable' - never 'no session', which would
        make an abandoned recording look clean (R2).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [string] $StatusOutput,
        [AllowNull()] [string] $OwnerTag,
        [AllowNull()] [string] $ExpectedInstanceName
    )

    $result = [ordered]@{
        State = 'unavailable'
        Abandoned = $false
        Foreign = $false
        OwnerProven = $false
        CleanupRequired = $false
        CleanupCommand = $null
        StopSaveCommand = $null
        InstanceName = $null
        DroppedEvents = $null
        LoggingMode = $null
        Reason = 'The WPR status output could not be read, so the session state is unknown; it is not treated as clean.'
        StatusOutput = $StatusOutput
    }

    if ([string]::IsNullOrWhiteSpace($StatusOutput)) {
        return [pscustomobject]$result
    }

    $text = $StatusOutput
    if ($text -notmatch '(?i)recording is in progress') {
        # Documented no-session message: "There are no trace profiles running."
        $result.State = 'none'
        $result.Reason = 'No WPR recording is running.'
        return [pscustomobject]$result
    }

    $result.State = 'in-progress'
    $instanceMatch = [regex]::Match($text, '(?im)^\s*Instance name\s*:\s*(\S+)\s*$')
    if ($instanceMatch.Success) { $result.InstanceName = $instanceMatch.Groups[1].Value }
    $droppedMatch = [regex]::Match($text, '(?i)Dropped event\s*:\s*(\d+)')
    if ($droppedMatch.Success) { $result.DroppedEvents = [int]$droppedMatch.Groups[1].Value }
    $modeMatch = [regex]::Match($text, '(?i)Logging mode\s*:\s*(\S+)')
    if ($modeMatch.Success) { $result.LoggingMode = $modeMatch.Groups[1].Value }

    $ownerProven = $false
    if (-not [string]::IsNullOrWhiteSpace($result.InstanceName)) {
        if (-not [string]::IsNullOrWhiteSpace($ExpectedInstanceName) -and
            $result.InstanceName -eq $ExpectedInstanceName) {
            $ownerProven = $true
        }
        elseif (-not [string]::IsNullOrWhiteSpace($OwnerTag) -and
            $result.InstanceName.StartsWith($OwnerTag, [System.StringComparison]::OrdinalIgnoreCase)) {
            $ownerProven = $true
        }
    }
    $result.OwnerProven = $ownerProven

    if (-not $ownerProven) {
        $result.Foreign = $true
        $shown = 'unknown'
        if ($null -ne $result.InstanceName) { $shown = $result.InstanceName }
        $result.Reason = ("A WPR recording is in progress with instance name '{0}', which this toolkit did not start; it is reported and never cancelled because its data belongs to whoever started it." -f $shown)
        return [pscustomobject]$result
    }

    $result.Abandoned = $true
    $result.CleanupRequired = $true
    $result.CleanupCommand = New-WpdEtwWprCancelCommand -InstanceName $ExpectedInstanceName
    if (-not [string]::IsNullOrWhiteSpace($ExpectedInstanceName)) {
        $result.StopSaveCommand = New-WpdEtwWprStopCommand -EtlPath 'abandoned-session.etl' -InstanceName $ExpectedInstanceName
    }
    $result.Reason = ("A WPR recording started by this toolkit (instance name '{0}') is still running; it is abandoned and can be cancelled or stopped to save what it recorded." -f $result.InstanceName)
    return [pscustomobject]$result
}

function Invoke-WpdEtwCapture {
    <#
    .SYNOPSIS
        Runs a capture body with guaranteed stop/cancel cleanup.

    .DESCRIPTION
        The documented order is -start, the recording window, then -stop. The
        body runs inside try/finally so the stop always happens - a Ctrl-C, a
        sampling exception or an operator cancel cannot leave a recording
        running. If the stop itself fails, the documented -cancel is attempted as
        the second line of cleanup.

        A failed -start means no session exists: the body is not run and no stop
        or cancel is fabricated against a session that was never created.

        Afterwards the optional status probe is reconciled through
        Test-WpdEtwAbandonedSession, so the result records whether a recording is
        still running instead of assuming the stop worked.

        Runner is the command seam: param($toolPath, $arguments) returning an
        exit code. Without it the real executable is invoked and $LASTEXITCODE is
        used, which is Windows-only work.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $StartCommand,
        [AllowNull()] $StopCommand,
        [AllowNull()] $CancelCommand,
        [Parameter(Mandatory = $true)][scriptblock] $Body,
        [AllowNull()] [scriptblock] $Runner,
        [AllowNull()] $StatusProbe,
        [AllowNull()] [string] $ExpectedInstanceName,
        [AllowNull()] [string] $OwnerTag
    )

    $errors = @()
    $warnings = @()
    $commands = New-Object System.Collections.ArrayList

    $invokeRunner = {
        param($toolPath, $arguments)
        $null = & $toolPath @arguments
        return $LASTEXITCODE
    }
    if ($null -ne $Runner) { $invokeRunner = $Runner }

    $startResult = Invoke-WpdEtwCommand -Command $StartCommand -Runner $invokeRunner
    [void]$commands.Add($StartCommand.CommandLine)
    if (-not $startResult.Succeeded) {
        $errors += ("wpr -start did not succeed (exit code {0}) for '{1}'; no recording was created, so the capture body was not run." -f $startResult.ExitCode, $StartCommand.CommandLine)
        return [pscustomobject]@{
            Status = 'error'
            Stage = 'start'
            Started = $false
            StartExitCode = $startResult.ExitCode
            StopAttempted = $false
            StopExitCode = $null
            CancelAttempted = $false
            CancelExitCode = $null
            SessionReconciled = $null
            SessionState = $null
            CleanupGuaranteed = $true
            BodyResult = $null
            Commands = @($commands)
            Errors = @($errors)
            Warnings = @($warnings)
        }
    }

    $context = [pscustomobject]@{
        Started = $true
        StartExitCode = $startResult.ExitCode
        StartedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        ExpectedInstanceName = $ExpectedInstanceName
        OwnerTag = $OwnerTag
    }

    $bodyResult = $null
    $stopResult = $null
    $cancelResult = $null
    $sessionState = $null
    try {
        $bodyResult = & $Body $context
    }
    finally {
        if ($null -ne $StopCommand) {
            $stopResult = Invoke-WpdEtwCommand -Command $StopCommand -Runner $invokeRunner
            [void]$commands.Add($StopCommand.CommandLine)
            if (-not $stopResult.Succeeded) {
                $warnings += ("wpr -stop did not succeed (exit code {0}); the recorded data may not have been saved." -f $stopResult.ExitCode)
                if ($null -ne $CancelCommand) {
                    $cancelResult = Invoke-WpdEtwCommand -Command $CancelCommand -Runner $invokeRunner
                    [void]$commands.Add($CancelCommand.CommandLine)
                    if (-not $cancelResult.Succeeded) {
                        $errors += ("wpr -cancel did not succeed (exit code {0}); a recording may still be running." -f $cancelResult.ExitCode)
                    }
                }
                else {
                    $warnings += 'No cancel command was supplied, so a running recording could not be cancelled.'
                }
            }
        }
        else {
            $errors += 'No stop command was supplied: the recording started by this capture cannot be stopped by this toolkit.'
        }

        if ($null -ne $StatusProbe) {
            try {
                $statusText = & $StatusProbe $context
                $session = Test-WpdEtwAbandonedSession -StatusOutput $statusText -OwnerTag $OwnerTag -ExpectedInstanceName $ExpectedInstanceName
                $sessionState = $session.State
                if ($session.State -eq 'in-progress') {
                    $warnings += ("A WPR recording is still in progress after the stop attempt (instance name '{0}')." -f $session.InstanceName)
                }
            }
            catch {
                $sessionState = 'unavailable'
                $warnings += ("The WPR status check failed after the capture: {0}" -f $_.Exception.Message)
            }
        }
    }

    $status = 'success'
    if ($null -eq $stopResult -or -not $stopResult.Succeeded) { $status = 'partial' }
    if ($null -ne $cancelResult -and -not $cancelResult.Succeeded) { $status = 'error' }
    if ($null -eq $stopResult) { $status = 'error' }
    if ($sessionState -eq 'in-progress') { $status = 'partial' }

    $stopExit = $null
    if ($null -ne $stopResult) { $stopExit = $stopResult.ExitCode }
    $cancelExit = $null
    if ($null -ne $cancelResult) { $cancelExit = $cancelResult.ExitCode }

    [pscustomobject]@{
        Status = $status
        Stage = 'complete'
        Started = $true
        StartExitCode = $startResult.ExitCode
        StopAttempted = ($null -ne $stopResult)
        StopExitCode = $stopExit
        CancelAttempted = ($null -ne $cancelResult)
        CancelExitCode = $cancelExit
        SessionReconciled = ($sessionState -eq 'none')
        SessionState = $sessionState
        CleanupGuaranteed = $true
        BodyResult = $bodyResult
        Commands = @($commands)
        Errors = @($errors)
        Warnings = @($warnings)
    }
}

function Invoke-WpdEtwCommand {
    <#
    .SYNOPSIS
        Runs a constructed command through the injected runner seam.

    .DESCRIPTION
        Runner is param($toolPath, $arguments) and returns an exit code. The
        command record itself is data, so a test can assert the exact argv
        without a wpr.exe, and a run on Windows can invoke the real binary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Command,
        [Parameter(Mandatory = $true)][scriptblock] $Runner
    )

    $exitCode = $null
    $errorMessage = $null
    try {
        $exitCode = & $Runner $Command.ToolPath $Command.Arguments
    }
    catch {
        $errorMessage = $_.Exception.Message
    }

    $succeeded = $false
    if ($null -eq $errorMessage) {
        if ($null -ne $exitCode -and [int]$exitCode -eq 0) { $succeeded = $true }
    }

    [pscustomobject]@{
        Kind = $Command.Kind
        ToolPath = $Command.ToolPath
        Arguments = @($Command.Arguments)
        CommandLine = $Command.CommandLine
        ExitCode = $exitCode
        Succeeded = $succeeded
        Error = $errorMessage
    }
}

function Join-WpdEtwPath {
    <#
    .SYNOPSIS
        Joins a root and a child without requiring the root's drive to exist.
    .DESCRIPTION
        Join-Path resolves a drive provider, so it fails on a non-Windows host
        for a Windows path. This helper keeps the module loadable and testable
        on Linux while producing the correct Windows separators on Windows.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $Child
    )

    if ($Root -match '^[A-Za-z]:$') { return ($Root + '\' + $Child) }
    if ($Root.EndsWith('\') -or $Root.EndsWith('/')) { return ($Root + $Child) }
    if ($Root -match ':') { return ($Root + '\' + $Child) }
    return [System.IO.Path]::Combine($Root, $Child)
}

function Find-WpdEtwTool {
    <#
    .SYNOPSIS
        Discovers wpr.exe, wpa.exe and wpaexporter.exe.

    .DESCRIPTION
        Windows Performance Toolkit tools come from the ADK, not from an inbox
        feature, so their absence is a normal state. Each tool is looked up
        through the path probe (default: Test-Path -PathType Leaf) and reported
        as 'present' or 'not-present' with a reason. A missing tool is never an
        error and never a healthy result: the run continues and the analyzer
        reports the affected analysis as unavailable (D11, R2).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [string[]] $SearchPaths,
        [AllowNull()] [scriptblock] $PathProbe,
        [AllowNull()] [string] $WptRoot
    )

    $probe = { param($candidate) return (Test-Path -LiteralPath $candidate -PathType Leaf) }
    if ($null -ne $PathProbe) { $probe = $PathProbe }

    $roots = New-Object System.Collections.ArrayList
    if (-not [string]::IsNullOrWhiteSpace($WptRoot)) {
        [void]$roots.Add($WptRoot)
    }
    if ($null -ne $SearchPaths) {
        foreach ($candidate in $SearchPaths) {
            if (-not [string]::IsNullOrWhiteSpace($candidate)) { [void]$roots.Add($candidate) }
        }
    }
    if ($roots.Count -eq 0) {
        $programFiles = $env:ProgramFiles
        $programFilesX86 = ${env:ProgramFiles(x86)}
        $systemRoot = $env:SystemRoot
        if (-not [string]::IsNullOrWhiteSpace($systemRoot)) {
            [void]$roots.Add((Join-WpdEtwPath -Root $systemRoot -Child 'System32'))
        }
        if (-not [string]::IsNullOrWhiteSpace($programFiles)) {
            [void]$roots.Add((Join-WpdEtwPath -Root $programFiles -Child 'Windows Kits\10\Windows Performance Toolkit'))
        }
        if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
            [void]$roots.Add((Join-WpdEtwPath -Root $programFilesX86 -Child 'Windows Kits\10\Windows Performance Toolkit'))
        }
    }

    $catalog = @(
        [pscustomobject]@{ Tool = 'wpr'; FileName = 'wpr.exe'; Purpose = 'recording (markers, circular capture, boot descriptors)' }
        [pscustomobject]@{ Tool = 'wpa'; FileName = 'wpa.exe'; Purpose = 'interactive analysis of the trace' }
        [pscustomobject]@{ Tool = 'wpaexporter'; FileName = 'wpaexporter.exe'; Purpose = 'automated table export to CSV' }
    )

    $results = New-Object System.Collections.ArrayList
    foreach ($entry in $catalog) {
        $found = $null
        $candidates = New-Object System.Collections.ArrayList
        foreach ($root in $roots) {
            $candidate = Join-WpdEtwPath -Root $root -Child $entry.FileName
            [void]$candidates.Add($candidate)
            if ($null -eq $found) {
                $exists = $false
                try { $exists = [bool](& $probe $candidate) } catch { $exists = $false }
                if ($exists) { $found = $candidate }
            }
        }

        $status = 'not-present'
        $reason = ("{0} was not found in the searched locations; {1} is unavailable and the run continues without it." -f $entry.FileName, $entry.Purpose)
        if ($null -ne $found) {
            $status = 'present'
            $reason = ("{0} found; {1} is available." -f $found, $entry.Purpose)
        }

        [void]$results.Add([pscustomobject]@{
            Tool = $entry.Tool
            FileName = $entry.FileName
            Status = $status
            Found = ($null -ne $found)
            Path = $found
            SearchPaths = @($roots)
            Candidates = @($candidates)
            Purpose = $entry.Purpose
            Reason = $reason
        })
    }

    return @($results)
}

function Get-WpdEtwSymbolPolicy {
    <#
    .SYNOPSIS
        Symbols present/absent and the AllowSymbolDownload policy.

    .DESCRIPTION
        WPR writes managed symbols next to a trace (a .NGenPdb directory beside
        the ETL) and caches them under
        C:\ProgramData\WindowsPerformanceRecorder\NGenPdbs_Cache. When those
        symbols exist the exporter is given the documented -symbols switch; when
        they do not, symbol-dependent analysis is reported as unavailable rather
        than assumed. Symbols are never downloaded by this toolkit: enabling
        -AllowSymbolDownload only records that the operator permits a symbol path
        to be used, and the absence of a symbol path is stated as a limitation.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [string] $TracePath,
        [switch] $AllowSymbolDownload,
        [AllowNull()] [scriptblock] $PathProbe
    )

    $probe = { param($candidate) return (Test-Path -LiteralPath $candidate) }
    if ($null -ne $PathProbe) { $probe = $PathProbe }

    $symbolDirectory = $null
    if (-not [string]::IsNullOrWhiteSpace($TracePath)) {
        $symbolDirectory = ([System.IO.Path]::Combine(
            [System.IO.Path]::GetDirectoryName($TracePath),
            ([System.IO.Path]::GetFileNameWithoutExtension($TracePath) + '.NGenPdb')))
    }

    $present = $false
    if ($null -ne $symbolDirectory) {
        try { $present = [bool](& $probe $symbolDirectory) } catch { $present = $false }
    }

    $state = 'unavailable'
    $reason = 'No managed symbol directory was found beside the trace, so symbol-dependent analysis (managed code stacks) is unavailable. By-process CPU and I/O tables do not require symbols.'
    if ($present) {
        $state = 'available'
        $reason = 'Managed symbols were written beside the trace; the exporter receives the documented -symbols switch.'
    }

    $downloadAllowed = [bool]$AllowSymbolDownload
    $note = 'Symbol download is disabled by default; this toolkit does not download symbols.'
    if ($downloadAllowed) {
        $note = 'Symbol download was explicitly allowed by the operator, but symbols are not downloaded by this toolkit; a configured symbol path is used.'
    }

    [pscustomobject]@{
        TracePath = $TracePath
        SymbolDirectory = $symbolDirectory
        SymbolsPresent = $present
        State = $state
        UseSymbolsSwitch = $present
        DownloadAllowed = $downloadAllowed
        ManagedSymbolCachePath = 'C:\ProgramData\WindowsPerformanceRecorder\NGenPdbs_Cache'
        Reason = $reason
        Note = $note
    }
}



Export-ModuleMember -Function @(
    'Find-WpdEtwTool',
    'Get-WpdEtwAnalysisTablePlan',
    'Get-WpdEtwPresetProfile',
    'Get-WpdEtwPresetTable',
    'Get-WpdEtwSymbolPolicy',
    'Get-WpdEtwTraceValidation',
    'Invoke-WpdEtwCapture',
    'Invoke-WpdEtwCommand',
    'New-WpdEtwBootScenarioDescriptor',
    'New-WpdEtwExporterCommand',
    'New-WpdEtwWprCancelCommand',
    'New-WpdEtwWprMarkerCommand',
    'New-WpdEtwWprProfilesCommand',
    'New-WpdEtwWprStartCommand',
    'New-WpdEtwWprStatusCommand',
    'New-WpdEtwWprStopCommand',
    'Test-WpdEtwAbandonedSession',
    'Test-WpdEtwCapturePreflight'
)
