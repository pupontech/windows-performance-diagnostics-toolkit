#Requires -Version 5.1
<#
.SYNOPSIS
    Consent-gated, optional Tier 3 escalation adapters.

.DESCRIPTION
    This module contains small adapters for evidence that is too expensive,
    intrusive, or optional for the normal Tier 0/Tier 1 collection path. The
    adapters never run at import time, never fetch a tool, and never change
    system state. Every external command and Windows provider can be injected
    as a scriptblock for deterministic tests on non-Windows hosts.

    Wait Chain Traversal is represented as a point-in-time provider result. The
    module does not pretend that WCT is a scheduler or a general I/O analyzer.
    ProcDump uses one bounded mini dump by default (-mm and -n 1); no full dump
    mode is exposed. PoolMon output is parsed after capture and GFlags is only
    described as a legacy, non-collected step. Defender output is requested in
    its machine-readable Raw form. Search and minifilter evidence is read-only.

.NOTES
    ASCII only. No BOM. Windows PowerShell 5.1 compatible. No write-capable
    remediation commands are used by this module.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:WpdEscalationStatusValues = @(
    'success'
    'partial'
    'unavailable'
    'unsupported'
    'not-collected'
    'error'
)

$script:WpdEscalationPrivacyLevels = @(
    'Standard'
    'Redacted'
    'Full'
)

$script:WpdEscalationForbiddenFieldPattern = '(?i)(password|passwd|secret|token|credential|cookie|commandline|rawcommand|rawxml|documentcontent|privatekey)'

function Get-WpdEscalationProperty {
    <#
    .SYNOPSIS
        Read a property from a PSCustomObject or hashtable without throwing.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $InputObject,
        [Parameter(Mandatory = $true)] [string] $Name,
        [AllowNull()] [object] $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]$key -ieq $Name) {
                return $InputObject[$key]
            }
        }
        return $Default
    }

    if ($null -eq $InputObject.PSObject) {
        return $Default
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Default
    }

    return $property.Value
}

function Get-WpdEscalationUtcTimestamp {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return ([DateTime]::UtcNow.ToString('o') + 'Z')
}

function Get-WpdEscalationPrivacyLevel {
    <#
    .SYNOPSIS
        Normalize the privacy level used by an escalation result.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()] [string] $Level)

    if ([string]::IsNullOrWhiteSpace($Level)) {
        return 'Standard'
    }

    foreach ($candidate in $script:WpdEscalationPrivacyLevels) {
        if ($candidate -eq $Level) {
            return $candidate
        }
    }

    throw [System.ArgumentException]::new(
        "unknown escalation privacy level '$Level'; valid values are $($script:WpdEscalationPrivacyLevels -join ', ')"
    )
}

function Test-WpdEscalationWindowsHost {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
}

function Test-WpdEscalationCommandPresence {
    <#
    .SYNOPSIS
        Check a command using an optional case-insensitive injected table.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [AllowNull()] [hashtable] $CommandTable
    )

    if ($null -ne $CommandTable) {
        foreach ($key in $CommandTable.Keys) {
            if ([string]$key -ieq $Name) {
                $value = $CommandTable[$key]
                if ($value -is [bool]) {
                    return [bool]$value
                }
                if ($null -eq $value) {
                    return $false
                }
                if ($value -is [string]) {
                    return (-not [string]::IsNullOrWhiteSpace([string]$value))
                }
                return $true
            }
        }
        return $false
    }

    try {
        return ($null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue))
    }
    catch {
        return $false
    }
}

function Test-WpdEscalationModulePresence {
    <#
    .SYNOPSIS
        Check a PowerShell module using an optional injected availability value.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [AllowNull()] [object] $ModuleAvailable,
        [AllowNull()] [hashtable] $ModuleTable
    )

    if ($PSBoundParameters.ContainsKey('ModuleAvailable')) {
        if ($null -eq $ModuleAvailable) {
            return $false
        }
        return [bool]$ModuleAvailable
    }

    if ($null -ne $ModuleTable) {
        foreach ($key in $ModuleTable.Keys) {
            if ([string]$key -ieq $Name) {
                $value = $ModuleTable[$key]
                if ($value -is [bool]) {
                    return [bool]$value
                }
                return ($null -ne $value)
            }
        }
        return $false
    }

    try {
        return ($null -ne (Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue))
    }
    catch {
        return $false
    }
}

function Test-WpdEscalationConsent {
    [CmdletBinding()]
    [OutputType([bool])]
    param([bool] $Consent)

    return $Consent
}

function Protect-WpdEscalationText {
    <#
    .SYNOPSIS
        Remove path-like detail from standard escalation summaries.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] [object] $Value,
        [string] $Level = 'Standard'
    )

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value
    if ($Level -eq 'Full') {
        return $text
    }

    if ($text -match '(^|[\\/])Users([\\/]|$)' -or $text -match '^[A-Za-z]:[\\/]' -or $text.StartsWith('\\\\')) {
        return '<redacted-path>'
    }

    return $text
}

function Protect-WpdEscalationRecord {
    <#
    .SYNOPSIS
        Recursively remove credential-shaped fields and redact paths.

    .DESCRIPTION
        This helper is deliberately conservative. It does not make a raw
        command output safe by guessing; callers should select only fields they
        need and then pass them through this function before storing them.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Record,
        [string] $Level = 'Standard'
    )

    $normalizedLevel = Get-WpdEscalationPrivacyLevel -Level $Level
    if ($null -eq $Record) {
        return $null
    }

    if ($Record -is [string] -or $Record -is [char] -or $Record -is [ValueType]) {
        return Protect-WpdEscalationText -Value $Record -Level $normalizedLevel
    }

    if ($Record -is [System.Collections.IDictionary]) {
        $table = [ordered]@{}
        foreach ($key in $Record.Keys) {
            $keyText = [string]$key
            if ($keyText -match $script:WpdEscalationForbiddenFieldPattern) {
                continue
            }
            $table[$keyText] = Protect-WpdEscalationRecord -Record $Record[$key] -Level $normalizedLevel
        }
        return [pscustomobject]$table
    }

    if ($Record -is [System.Collections.IEnumerable]) {
        $items = @()
        foreach ($item in $Record) {
            $items += Protect-WpdEscalationRecord -Record $item -Level $normalizedLevel
        }
        return @($items)
    }

    $objectTable = [ordered]@{}
    foreach ($property in $Record.PSObject.Properties) {
        if ($property.Name -match $script:WpdEscalationForbiddenFieldPattern) {
            continue
        }
        $objectTable[$property.Name] = Protect-WpdEscalationRecord -Record $property.Value -Level $normalizedLevel
    }
    return [pscustomobject]$objectTable
}

function New-WpdEscalationCleanupResult {
    [CmdletBinding()]
    param(
        [string] $Status = 'not-needed',
        [string] $Reason,
        [string[]] $Paths = @()
    )

    return [pscustomobject][ordered]@{
        status  = $Status
        reason  = $Reason
        paths   = @($Paths)
    }
}

function Remove-WpdEscalationArtifact {
    <#
    .SYNOPSIS
        Remove only a partial artifact created by this module.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()] [string] $Path,
        [bool] $CreatedByToolkit = $false,
        [AllowEmptyString()] [string] $ParentDirectory,
        [bool] $ParentCreatedByToolkit = $false
    )

    if (-not $CreatedByToolkit -or [string]::IsNullOrWhiteSpace($Path)) {
        return New-WpdEscalationCleanupResult -Status 'preserved' -Reason 'not-created-by-toolkit'
    }

    $removed = @()
    try {
        if (Test-Path -LiteralPath $Path -PathType Any) {
            $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                return New-WpdEscalationCleanupResult -Status 'failed' -Reason 'reparse-point-not-removed' -Paths @($Path)
            }
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            $removed += $Path
        }

        if ($ParentCreatedByToolkit -and -not [string]::IsNullOrWhiteSpace($ParentDirectory) -and
            (Test-Path -LiteralPath $ParentDirectory -PathType Container)) {
            $children = @(Get-ChildItem -LiteralPath $ParentDirectory -Force -ErrorAction Stop)
            if ($children.Count -eq 0) {
                Remove-Item -LiteralPath $ParentDirectory -Force -ErrorAction Stop
                $removed += $ParentDirectory
            }
        }

        if ($removed.Count -gt 0) {
            return New-WpdEscalationCleanupResult -Status 'removed' -Reason 'partial-artifact-removed' -Paths $removed
        }

        return New-WpdEscalationCleanupResult -Status 'not-created' -Reason 'artifact-not-present'
    }
    catch {
        return New-WpdEscalationCleanupResult -Status 'failed' -Reason 'cleanup-failed' -Paths @($Path)
    }
}

function New-WpdEscalationResult {
    <#
    .SYNOPSIS
        Create a stable result envelope for every adapter.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Adapter,
        [string] $Status = 'not-collected',
        [string] $Coverage,
        [string] $Reason,
        [AllowNull()] [object] $Data,
        [object[]] $Items = @(),
        [object[]] $Warnings = @(),
        [object[]] $Errors = @(),
        [string[]] $Arguments = @(),
        [string] $Tool,
        [string] $ArtifactPath,
        [string] $ArtifactName,
        [string] $StartedUtc,
        [string] $CompletedUtc,
        [long] $DurationMs = 0,
        [AllowNull()] [object] $Cleanup,
        [bool] $ConsentGiven = $false,
        [string] $PrivacyLevel = 'Standard'
    )

    $normalizedStatus = @($script:WpdEscalationStatusValues | Where-Object { $_ -eq $Status })
    if ($normalizedStatus.Count -eq 0) {
        throw [System.ArgumentException]::new("unknown escalation status '$Status'")
    }

    if ([string]::IsNullOrWhiteSpace($Coverage)) {
        if ($Status -eq 'success') { $Coverage = 'complete' }
        elseif ($Status -eq 'partial') { $Coverage = 'partial' }
        elseif ($Status -eq 'unsupported') { $Coverage = 'unsupported' }
        elseif ($Status -eq 'not-collected') { $Coverage = 'not-collected' }
        else { $Coverage = 'unavailable' }
    }

    if ([string]::IsNullOrWhiteSpace($StartedUtc)) {
        $StartedUtc = Get-WpdEscalationUtcTimestamp
    }
    if ([string]::IsNullOrWhiteSpace($CompletedUtc)) {
        $CompletedUtc = Get-WpdEscalationUtcTimestamp
    }
    if ($null -eq $Cleanup) {
        $Cleanup = New-WpdEscalationCleanupResult
    }

    $result = [pscustomobject][ordered]@{
        adapter                = $Adapter
        tier                   = 3
        status                 = $normalizedStatus[0]
        coverage               = $Coverage
        reason                 = $Reason
        consentRequired        = $true
        consentGiven           = $ConsentGiven
        automaticRemediation   = $false
        recommendations        = @()
        tool                   = $Tool
        arguments              = @($Arguments)
        artifactPath           = $ArtifactPath
        artifactName           = $ArtifactName
        data                   = $Data
        items                  = @($Items)
        warnings               = @($Warnings)
        errors                 = @($Errors)
        startedUtc             = $StartedUtc
        completedUtc           = $CompletedUtc
        durationMs             = $DurationMs
        cleanup                = $Cleanup
        privacyLevel           = (Get-WpdEscalationPrivacyLevel -Level $PrivacyLevel)
    }

    foreach ($propertyName in @('chains', 'cycles', 'filters', 'instances', 'service', 'index')) {
        if ($null -ne $Data) {
            $value = Get-WpdEscalationProperty -InputObject $Data -Name $propertyName -Default $null
            if ($null -ne $value) {
                Add-Member -InputObject $result -MemberType NoteProperty -Name $propertyName -Value $value
            }
        }
    }
    return $result
}

function Invoke-WpdEscalationCommand {
    <#
    .SYNOPSIS
        Execute a command through the injectable command seam.

    .DESCRIPTION
        The seam receives two positional arguments: the command name/path and a
        single object[] argument list. A fixture can return lines or an object
        with ExitCode, Output, Error and Data fields. No shell string is built.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [object[]] $Arguments = @(),
        [AllowNull()] [scriptblock] $CommandRunner
    )

    if ($null -ne $CommandRunner) {
        return @(& $CommandRunner $Name ([object[]]$Arguments))
    }

    return @(& $Name @($Arguments))
}

function Get-WpdEscalationCommandExitCode {
    [CmdletBinding()]
    [OutputType([int])]
    param([AllowNull()] [object[]] $Execution)

    $found = $false
    $exitCode = 0
    foreach ($entry in @($Execution)) {
        if ($null -eq $entry) {
            continue
        }
        if ($entry -is [int] -or $entry -is [long]) {
            $candidate = $entry
        }
        else {
            $candidate = Get-WpdEscalationProperty -InputObject $entry -Name 'ExitCode' -Default $null
            if ($null -eq $candidate) {
                $candidate = Get-WpdEscalationProperty -InputObject $entry -Name 'exit_code' -Default $null
            }
        }
        if ($null -eq $candidate) {
            continue
        }
        try {
            $exitCode = [int]$candidate
            $found = $true
        }
        catch {
            $exitCode = 1
            $found = $true
        }
    }
    if ($found) {
        return $exitCode
    }
    return 0
}

function Get-WpdEscalationCommandOutput {
    [CmdletBinding()]
    [OutputType([object[]])]
    param([AllowNull()] [object[]] $Execution)

    $lines = @()
    foreach ($entry in @($Execution)) {
        if ($null -eq $entry) { continue }
        if ($entry -is [string]) {
            $lines += [string]$entry
            continue
        }
        $output = Get-WpdEscalationProperty -InputObject $entry -Name 'Output' -Default $null
        if ($null -eq $output) {
            $output = Get-WpdEscalationProperty -InputObject $entry -Name 'StdOut' -Default $null
        }
        if ($null -eq $output) {
            $output = Get-WpdEscalationProperty -InputObject $entry -Name 'Lines' -Default $null
        }
        if ($null -ne $output) {
            $lines += @($output)
        }
    }
    return @($lines)
}

function Get-WpdEscalationCommandData {
    [CmdletBinding()]
    [OutputType([object])]
    param([AllowNull()] [object[]] $Execution)

    foreach ($entry in @($Execution)) {
        if ($null -eq $entry -or $entry -is [string]) { continue }
        $data = Get-WpdEscalationProperty -InputObject $entry -Name 'Data' -Default $null
        if ($null -ne $data) { return $data }
        $data = Get-WpdEscalationProperty -InputObject $entry -Name 'Report' -Default $null
        if ($null -ne $data) { return $data }
    }
    return $null
}

function New-WpdEscalationOutputDirectory {
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory = $true)] [string] $Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'escalation output directory cannot be empty'
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $created = $false
    if (Test-Path -LiteralPath $fullPath -PathType Any) {
        $existing = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
        if (-not $existing.PSIsContainer) {
            throw 'escalation output path is not a directory'
        }
        if ($existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw 'escalation output directory is a reparse point'
        }
    }
    else {
        New-Item -ItemType Directory -Path $fullPath -Force -ErrorAction Stop | Out-Null
        $created = $true
    }

    return [pscustomobject]@{ path = $fullPath; created = $created }
}

function New-WpdEscalationArtifactPath {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)] [string] $Directory,
        [Parameter(Mandatory = $true)] [string] $BaseName,
        [Parameter(Mandatory = $true)] [string] $Extension
    )

    $safeBase = $BaseName -replace '[^A-Za-z0-9._-]', '_'
    $safeExtension = $Extension -replace '[^A-Za-z0-9.]', ''
    if (-not $safeExtension.StartsWith('.')) {
        $safeExtension = '.' + $safeExtension
    }
    $candidate = Join-Path -Path $Directory -ChildPath ($safeBase + $safeExtension)
    if (Test-Path -LiteralPath $candidate -PathType Any) {
        $candidate = Join-Path -Path $Directory -ChildPath ($safeBase + '-' + ([Guid]::NewGuid().ToString('N')) + $safeExtension)
    }

    return [pscustomobject]@{
        path  = $candidate
        name  = [System.IO.Path]::GetFileName($candidate)
        exists = $false
    }
}

# --------------------------------------------------------------------------
# Wait Chain Traversal
# --------------------------------------------------------------------------

function Get-WpdWaitChainNodeValue {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Node,
        [string] $Primary,
        [string] $Secondary
    )

    $value = Get-WpdEscalationProperty -InputObject $Node -Name $Primary -Default $null
    if ($null -eq $value -and -not [string]::IsNullOrWhiteSpace($Secondary)) {
        $value = Get-WpdEscalationProperty -InputObject $Node -Name $Secondary -Default $null
    }
    return $value
}

function Get-WpdWaitChainInt {
    [CmdletBinding()]
    [OutputType([int])]
    param([AllowNull()] [object] $Value)

    if ($null -eq $Value) { return $null }
    $parsed = 0
    if ([int]::TryParse(([string]$Value), [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
        return $parsed
    }
    return $null
}

function Get-WpdWaitChainCycleForChain {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object] $Chain)

    $nodes = @((Get-WpdEscalationProperty -InputObject $Chain -Name 'Nodes' -Default @()))
    if ($nodes.Count -eq 0) { return $null }

    $edges = @{}
    foreach ($node in $nodes) {
        $nodeId = Get-WpdWaitChainInt -Value (Get-WpdWaitChainNodeValue -Node $node -Primary 'ThreadId' -Secondary 'Id')
        $ownerId = Get-WpdWaitChainInt -Value (Get-WpdWaitChainNodeValue -Node $node -Primary 'OwnerThreadId' -Secondary 'WaitsForThreadId')
        if ($null -ne $nodeId -and $null -ne $ownerId -and $ownerId -gt 0) {
            $edges[[string]$nodeId] = $ownerId
        }
    }

    $start = Get-WpdWaitChainInt -Value (Get-WpdEscalationProperty -InputObject $Chain -Name 'ThreadId' -Default $null)
    if ($null -eq $start -and $edges.Count -gt 0) {
        $start = [int](@($edges.Keys)[0])
    }
    if ($null -eq $start) { return $null }

    $seen = @{}
    $path = @()
    $current = $start
    while ($null -ne $current -and $current -gt 0) {
        $key = [string]$current
        if ($seen.ContainsKey($key)) {
            $offset = [int]$seen[$key]
            $cycleIds = @($path[$offset..($path.Count - 1)])
            return [pscustomobject]@{
                threadIds = @($cycleIds | Select-Object -Unique)
                kind      = 'wait-cycle'
                status    = 'cycle-detected'
            }
        }
        $seen[$key] = $path.Count
        $path += $current
        if (-not $edges.ContainsKey($key)) { break }
        $current = [int]$edges[$key]
    }
    return $null
}

function Get-WpdWaitChainAnalysis {
    <#
    .SYNOPSIS
        Normalize point-in-time WCT chains and identify thread cycles.
    #>
    [CmdletBinding()]
    param([AllowNull()] [object[]] $Chains)

    $normalized = @()
    $cycles = @()
    $cycleKeys = @{}

    foreach ($chain in @($Chains)) {
        if ($null -eq $chain) { continue }
        $nodes = @((Get-WpdEscalationProperty -InputObject $chain -Name 'Nodes' -Default @()))
        $safeNodes = @()
        foreach ($node in $nodes) {
            if ($null -eq $node) { continue }
            $safeNodes += [pscustomobject][ordered]@{
                type           = Get-WpdWaitChainNodeValue -Node $node -Primary 'Type' -Secondary 'ObjectType'
                id             = Get-WpdWaitChainNodeValue -Node $node -Primary 'Id' -Secondary 'ThreadId'
                ownerThreadId  = Get-WpdWaitChainNodeValue -Node $node -Primary 'OwnerThreadId' -Secondary 'WaitsForThreadId'
                status         = Get-WpdWaitChainNodeValue -Node $node -Primary 'Status' -Secondary 'State'
            }
        }

        $chainId = Get-WpdEscalationProperty -InputObject $chain -Name 'ChainId' -Default $null
        if ($null -eq $chainId) {
            $chainId = 'chain-' + ([string]$normalized.Count + 1)
        }
        $safeChain = [pscustomobject][ordered]@{
            chainId    = [string]$chainId
            processId  = Get-WpdEscalationProperty -InputObject $chain -Name 'ProcessId' -Default $null
            threadId   = Get-WpdEscalationProperty -InputObject $chain -Name 'ThreadId' -Default $null
            status     = Get-WpdEscalationProperty -InputObject $chain -Name 'Status' -Default 'completed'
            nodes      = @($safeNodes)
        }
        $normalized += $safeChain

        $cycle = Get-WpdWaitChainCycleForChain -Chain $chain
        if ($null -ne $cycle) {
            $key = (@($cycle.threadIds | Sort-Object) -join ',')
            if (-not $cycleKeys.ContainsKey($key)) {
                $cycleKeys[$key] = $true
                $cycles += [pscustomobject][ordered]@{
                    chainId   = [string]$chainId
                    threadIds = @($cycle.threadIds)
                    kind      = $cycle.kind
                    status    = $cycle.status
                }
            }
        }
    }

    $status = 'success'
    $coverage = 'complete'
    if ($normalized.Count -eq 0) {
        $status = 'unavailable'
        $coverage = 'unavailable'
    }

    return [pscustomobject][ordered]@{
        adapter       = 'wct'
        tier          = 3
        status        = $status
        coverage      = $coverage
        pointInTime   = $true
        samplingMode  = 'point-in-time'
        chains        = @($normalized)
        cycles        = @($cycles)
        limitations   = @('WCT covers only the listed synchronization primitives; it is point-in-time evidence, not a scheduler or general I/O analysis.')
        recommendations = @()
        automaticRemediation = $false
    }
}

function Invoke-WpdWaitChain {
    <#
    .SYNOPSIS
        Run an injected WCT provider once after explicit consent.
    #>
    [CmdletBinding()]
    param(
        [Alias('ConfirmConsent', 'ConfirmEscalation')]
        [switch] $Consent,
        [AllowNull()] [scriptblock] $ChainProvider,
        [AllowNull()] [int[]] $ProcessId,
        [AllowNull()] [int[]] $ThreadId,
        [string] $PrivacyLevel = 'Standard'
    )

    $started = Get-WpdEscalationUtcTimestamp
    if (-not (Test-WpdEscalationConsent -Consent ([bool]$Consent))) {
        return New-WpdEscalationResult -Adapter 'wct' -Status 'not-collected' -Reason 'consent-required' -StartedUtc $started -ConsentGiven:$false -PrivacyLevel $PrivacyLevel
    }

    if ($null -eq $ChainProvider) {
        return New-WpdEscalationResult -Adapter 'wct' -Status 'unavailable' -Reason 'wct-provider-not-registered' -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }

    try {
        $provided = @(& $ChainProvider (,@($ProcessId)) (,@($ThreadId)))
        $chains = $provided
        if ($provided.Count -eq 1 -and $null -ne $provided[0]) {
            $candidate = $provided[0]
            $candidateChains = Get-WpdEscalationProperty -InputObject $candidate -Name 'Chains' -Default $null
            if ($null -ne $candidateChains) {
                $chains = @($candidateChains)
            }
        }
        $analysis = Get-WpdWaitChainAnalysis -Chains $chains
        $reason = 'no-wct-chains'
        if ($analysis.status -eq 'success') { $reason = 'point-in-time-wct-snapshot' }
        return New-WpdEscalationResult -Adapter 'wct' -Status $analysis.status -Coverage $analysis.coverage `
            -Reason $reason -Data $analysis -Items @($analysis.chains) -StartedUtc $started `
            -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }
    catch {
        return New-WpdEscalationResult -Adapter 'wct' -Status 'error' -Reason 'wct-provider-failed' `
            -Errors @([pscustomobject]@{ stage = 'wct'; message = $_.Exception.Message }) `
            -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }
}

# --------------------------------------------------------------------------
# ProcDump
# --------------------------------------------------------------------------

function New-WpdProcDumpArguments {
    <#
    .SYNOPSIS
        Build a bounded, mini-dump-only ProcDump argument list.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [ValidateRange(1, 2147483647)] [int] $ProcessId,
        [Parameter(Mandatory = $true)] [string] $ArtifactPath
    )

    if ([string]::IsNullOrWhiteSpace($ArtifactPath)) {
        throw 'ProcDump artifact path cannot be empty'
    }

    return @('-mm', '-n', '1', [string]$ProcessId, $ArtifactPath)
}

function Invoke-WpdProcDump {
    <#
    .SYNOPSIS
        Capture one consented mini dump only when ProcDump is already present.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [ValidateRange(1, 2147483647)] [int] $ProcessId,
        [string] $OutputDirectory = (Join-Path (Get-Location).Path 'wpd-escalation'),
        [Alias('ConfirmConsent', 'ConfirmEscalation')]
        [switch] $Consent,
        [switch] $EnableProcDump,
        [string] $ProcDumpPath,
        [AllowNull()] [hashtable] $CommandTable,
        [AllowNull()] [scriptblock] $CommandRunner,
        [string] $PrivacyLevel = 'Standard'
    )

    $started = Get-WpdEscalationUtcTimestamp
    if (-not (Test-WpdEscalationConsent -Consent ([bool]$Consent))) {
        return New-WpdEscalationResult -Adapter 'procdump' -Status 'not-collected' -Reason 'consent-required' `
            -StartedUtc $started -ConsentGiven:$false -PrivacyLevel $PrivacyLevel
    }

    $toolName = 'procdump.exe'
    $tool = $toolName
    if (-not [string]::IsNullOrWhiteSpace($ProcDumpPath)) {
        if (Test-Path -LiteralPath $ProcDumpPath -PathType Leaf) {
            $tool = [System.IO.Path]::GetFullPath($ProcDumpPath)
        }
        elseif ($EnableProcDump -and (Test-WpdEscalationCommandPresence -Name $ProcDumpPath -CommandTable $CommandTable)) {
            $tool = $ProcDumpPath
        }
        else {
            return New-WpdEscalationResult -Adapter 'procdump' -Status 'unavailable' -Reason 'tool-not-found' `
                -Tool $toolName -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
        }
    }
    elseif (-not (Test-WpdEscalationCommandPresence -Name $toolName -CommandTable $CommandTable)) {
        return New-WpdEscalationResult -Adapter 'procdump' -Status 'unavailable' -Reason 'tool-not-found' `
            -Tool $toolName -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }

    $directoryInfo = $null
    $artifactPath = $null
    $artifactName = $null
    $arguments = @()
    try {
        $directoryInfo = New-WpdEscalationOutputDirectory -Path $OutputDirectory
        $artifactInfo = New-WpdEscalationArtifactPath -Directory $directoryInfo.path -BaseName 'procdump-mini' -Extension '.dmp'
        $artifactPath = $artifactInfo.path
        $artifactName = $artifactInfo.name
        $arguments = New-WpdProcDumpArguments -ProcessId $ProcessId -ArtifactPath $artifactPath
        $execution = @(Invoke-WpdEscalationCommand -Name $tool -Arguments $arguments -CommandRunner $CommandRunner)
        $exitCode = Get-WpdEscalationCommandExitCode -Execution $execution
        if ($exitCode -ne 0) {
            throw "ProcDump returned exit code $exitCode"
        }
        if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
            throw 'ProcDump did not create the requested mini dump'
        }

        return New-WpdEscalationResult -Adapter 'procdump' -Status 'success' -Reason 'bounded-mini-dump-captured' `
            -Tool $toolName -Arguments $arguments -ArtifactPath $artifactPath -ArtifactName $artifactName `
            -Data ([pscustomobject]@{ processId = $ProcessId; dumpKind = 'mini'; dumpCount = 1 }) `
            -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }
    catch {
        $cleanupParent = $null
        $cleanupParentCreated = $false
        if ($null -ne $directoryInfo) {
            $cleanupParent = $directoryInfo.path
            $cleanupParentCreated = [bool]$directoryInfo.created
        }
        $cleanup = Remove-WpdEscalationArtifact -Path $artifactPath -CreatedByToolkit:($null -ne $artifactPath) `
            -ParentDirectory $cleanupParent -ParentCreatedByToolkit:$cleanupParentCreated
        return New-WpdEscalationResult -Adapter 'procdump' -Status 'error' -Reason 'capture-failed' `
            -Tool $toolName -Arguments $arguments -ArtifactPath $artifactPath -ArtifactName $artifactName `
            -Errors @([pscustomobject]@{ stage = 'procdump'; message = $_.Exception.Message }) `
            -Cleanup $cleanup -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }
}

# --------------------------------------------------------------------------
# PoolMon and pool-focused WPR descriptor
# --------------------------------------------------------------------------

function ConvertFrom-WpdPoolMonOutput {
    <#
    .SYNOPSIS
        Parse numeric PoolMon rows without retaining the console text.
    #>
    [CmdletBinding()]
    param([AllowNull()] [string[]] $Lines)

    $rows = @()
    foreach ($line in @($Lines)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $trimmed = $line.Trim()
        if ($trimmed -match '^(Tag|---|=)' -or $trimmed -match '^[- ]+$') { continue }
        $parts = @($trimmed -split '\s+')
        if ($parts.Count -lt 5) { continue }
        $tag = $parts[0]
        if ($tag -match '^(Tag|Type|Name)$' -or $tag -match '^-+$') { continue }
        $numbers = @($parts[1..($parts.Count - 1)] | Where-Object { $_ -match '^-?\d+$' })
        if ($numbers.Count -lt 4) { continue }

        $kind = $null
        foreach ($part in @($parts[1..($parts.Count - 1)])) {
            if ($part -notmatch '^-?\d+$') {
                $kind = $part
                break
            }
        }
        $perAllocation = $null
        if ($numbers.Count -ge 5) { $perAllocation = [long]$numbers[4] }
        $rows += [pscustomobject][ordered]@{
            tag           = $tag
            type          = $kind
            allocations   = [long]$numbers[0]
            frees         = [long]$numbers[1]
            difference    = [long]$numbers[2]
            bytes         = [long]$numbers[3]
            perAllocation = $perAllocation
        }
    }
    return @($rows)
}

function New-WpdPoolEscalationDescriptor {
    [CmdletBinding()]
    param([AllowEmptyString()] [string] $PoolTag)

    if (-not [string]::IsNullOrWhiteSpace($PoolTag) -and $PoolTag -notmatch '^[A-Za-z0-9 ?]{1,8}$') {
        throw 'pool tag contains unsupported characters'
    }

    return [pscustomobject][ordered]@{
        id                    = 'pool'
        title                 = 'Targeted kernel pool growth'
        tier                  = 3
        mode                  = 'descriptor'
        status                = 'not-collected'
        consentRequired       = $true
        automaticRemediation  = $false
        recommendations       = @()
        tool                  = 'poolmon.exe'
        poolTag               = $PoolTag
        targetedAnalysis      = 'pool-tag-growth-over-time'
        legacyGflagsAction    = 'not-collected'
        wpr                   = [pscustomobject][ordered]@{
            status          = 'not-collected'
            profile         = 'caller-supplied-or-discovered'
            startArguments  = @('-start', '<discovered-profile>')
            stopArguments   = @('-stop', '<output.etl>')
        }
        cleanup               = [pscustomobject][ordered]@{ strategy = 'created-artifacts-only'; onFailure = 'remove-partial-artifact'; onSuccess = 'retain-evidence' }
        privacy               = [pscustomobject][ordered]@{ default = 'Standard'; rawConsoleText = 'not-retained' }
        limitations           = @('PoolMon is an optional WDK tool and tag-to-component naming depends on local tag data.', 'Pool growth is evidence for correlation, not a causal or repair conclusion.')
    }
}

function Invoke-WpdPoolEscalation {
    <#
    .SYNOPSIS
        Capture one PoolMon snapshot through an injected command seam.

    .DESCRIPTION
        The adapter invokes PoolMon without changing global pool tagging state.
        A pool tag is selected from the parsed output, and an optional WPR
        recording uses only caller-supplied/discovered profile text with the
        documented start/stop command shape.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()] [string] $PoolTag,
        [string] $OutputDirectory = (Join-Path (Get-Location).Path 'wpd-escalation'),
        [Alias('ConfirmConsent', 'ConfirmEscalation')]
        [switch] $Consent,
        [switch] $CaptureWpr,
        [string] $WprProfile,
        [AllowNull()] [hashtable] $CommandTable,
        [AllowNull()] [scriptblock] $CommandRunner,
        [AllowNull()] [string[]] $PoolMonOutput,
        [string] $PrivacyLevel = 'Standard'
    )

    $started = Get-WpdEscalationUtcTimestamp
    if (-not (Test-WpdEscalationConsent -Consent ([bool]$Consent))) {
        return New-WpdEscalationResult -Adapter 'pool' -Status 'not-collected' -Reason 'consent-required' `
            -StartedUtc $started -ConsentGiven:$false -PrivacyLevel $PrivacyLevel
    }

    if ($null -eq $PoolMonOutput -and -not (Test-WpdEscalationCommandPresence -Name 'poolmon.exe' -CommandTable $CommandTable)) {
        return New-WpdEscalationResult -Adapter 'pool' -Status 'unavailable' -Reason 'tool-not-found' `
            -Tool 'poolmon.exe' -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }

    $directoryInfo = $null
    $wprPath = $null
    $wprName = $null
    $arguments = @()
    $warnings = @()
    try {
        $lines = @($PoolMonOutput)
        if ($null -eq $PoolMonOutput) {
            $poolExecution = @(Invoke-WpdEscalationCommand -Name 'poolmon.exe' -Arguments @() -CommandRunner $CommandRunner)
            $poolExitCode = Get-WpdEscalationCommandExitCode -Execution $poolExecution
            if ($poolExitCode -ne 0) { throw "PoolMon returned exit code $poolExitCode" }
            $lines = @(Get-WpdEscalationCommandOutput -Execution $poolExecution)
        }
        $rows = @(ConvertFrom-WpdPoolMonOutput -Lines $lines)
        if (-not [string]::IsNullOrWhiteSpace($PoolTag)) {
            $rows = @($rows | Where-Object { $_.tag -ieq $PoolTag })
        }
        $rows = @($rows | Sort-Object -Property difference, bytes -Descending)

        $wprResult = New-WpdEscalationCleanupResult -Status 'not-needed' -Reason 'wpr-not-requested'
        if ($CaptureWpr) {
            if ([string]::IsNullOrWhiteSpace($WprProfile)) {
                $warnings += 'wpr-profile-not-supplied'
                $wprResult = New-WpdEscalationCleanupResult -Status 'not-created' -Reason 'wpr-profile-not-supplied'
            }
            elseif (-not (Test-WpdEscalationCommandPresence -Name 'wpr.exe' -CommandTable $CommandTable)) {
                $warnings += 'wpr-tool-not-found'
                $wprResult = New-WpdEscalationCleanupResult -Status 'not-created' -Reason 'wpr-tool-not-found'
            }
            else {
                $directoryInfo = New-WpdEscalationOutputDirectory -Path $OutputDirectory
                $wprInfo = New-WpdEscalationArtifactPath -Directory $directoryInfo.path -BaseName 'pool-targeted' -Extension '.etl'
                $wprPath = $wprInfo.path
                $wprName = $wprInfo.name
                $startArguments = @('-start', $WprProfile)
                $startExecution = @(Invoke-WpdEscalationCommand -Name 'wpr.exe' -Arguments $startArguments -CommandRunner $CommandRunner)
                if ((Get-WpdEscalationCommandExitCode -Execution $startExecution) -ne 0) {
                    throw 'WPR pool recording failed to start'
                }
                try {
                    $stopArguments = @('-stop', $wprPath)
                    $stopExecution = @(Invoke-WpdEscalationCommand -Name 'wpr.exe' -Arguments $stopArguments -CommandRunner $CommandRunner)
                    if ((Get-WpdEscalationCommandExitCode -Execution $stopExecution) -ne 0) {
                        throw 'WPR pool recording failed to stop'
                    }
                    $arguments = @($startArguments + $stopArguments)
                    $wprResult = New-WpdEscalationCleanupResult -Status 'preserved' -Reason 'wpr-evidence-retained' -Paths @($wprPath)
                }
                catch {
                    $cleanupFailure = Remove-WpdEscalationArtifact -Path $wprPath -CreatedByToolkit:$true `
                        -ParentDirectory $directoryInfo.path -ParentCreatedByToolkit:([bool]$directoryInfo.created)
                    throw $_
                }
            }
        }

        $status = 'success'
        if ($rows.Count -eq 0) { $status = 'unavailable' }
        $reason = 'poolmon-no-rows'
        if ($status -eq 'success') { $reason = 'poolmon-targeted-analysis' }
        return New-WpdEscalationResult -Adapter 'pool' -Status $status `
            -Reason $reason `
            -Tool 'poolmon.exe' -Arguments $arguments -Items $rows `
            -Data ([pscustomobject]@{ poolTag = $PoolTag; wpr = $wprResult }) -Warnings $warnings `
            -ArtifactPath $wprPath -ArtifactName $wprName -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }
    catch {
        $cleanupParent = $null
        $cleanupParentCreated = $false
        if ($null -ne $directoryInfo) {
            $cleanupParent = $directoryInfo.path
            $cleanupParentCreated = [bool]$directoryInfo.created
        }
        $cleanup = Remove-WpdEscalationArtifact -Path $wprPath -CreatedByToolkit:($null -ne $wprPath) `
            -ParentDirectory $cleanupParent -ParentCreatedByToolkit:$cleanupParentCreated
        return New-WpdEscalationResult -Adapter 'pool' -Status 'error' -Reason 'capture-failed' `
            -Tool 'poolmon.exe' -Arguments $arguments -Errors @([pscustomobject]@{ stage = 'pool'; message = $_.Exception.Message }) `
            -Cleanup $cleanup -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }
}

# --------------------------------------------------------------------------
# Defender performance analyzer
# --------------------------------------------------------------------------

function Invoke-WpdDefenderPerformanceCapture {
    <#
    .SYNOPSIS
        Capture a Defender performance recording and request a Raw report.
    #>
    [CmdletBinding()]
    param(
        [string] $OutputDirectory = (Join-Path (Get-Location).Path 'wpd-escalation'),
        [Alias('ConfirmConsent', 'ConfirmEscalation')]
        [switch] $Consent,
        [AllowNull()] [object] $ModuleAvailable,
        [AllowNull()] [hashtable] $ModuleTable,
        [AllowNull()] [hashtable] $CommandTable,
        [AllowNull()] [scriptblock] $CommandRunner,
        [string] $PrivacyLevel = 'Standard'
    )

    $started = Get-WpdEscalationUtcTimestamp
    if (-not (Test-WpdEscalationConsent -Consent ([bool]$Consent))) {
        return New-WpdEscalationResult -Adapter 'defender' -Status 'not-collected' -Reason 'consent-required' `
            -StartedUtc $started -ConsentGiven:$false -PrivacyLevel $PrivacyLevel
    }

    if (-not (Test-WpdEscalationModulePresence -Name 'DefenderPerformance' -ModuleAvailable $ModuleAvailable -ModuleTable $ModuleTable)) {
        return New-WpdEscalationResult -Adapter 'defender' -Status 'unavailable' -Reason 'module-not-found' `
            -Tool 'DefenderPerformance' -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }
    if (-not (Test-WpdEscalationCommandPresence -Name 'New-MpPerformanceRecording' -CommandTable $CommandTable) -or
        -not (Test-WpdEscalationCommandPresence -Name 'Get-MpPerformanceReport' -CommandTable $CommandTable)) {
        return New-WpdEscalationResult -Adapter 'defender' -Status 'unavailable' -Reason 'command-not-found' `
            -Tool 'DefenderPerformance' -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }

    $directoryInfo = $null
    $recordingPath = $null
    $recordingName = $null
    $arguments = @()
    try {
        $directoryInfo = New-WpdEscalationOutputDirectory -Path $OutputDirectory
        $artifactInfo = New-WpdEscalationArtifactPath -Directory $directoryInfo.path -BaseName 'defender-performance' -Extension '.etl'
        $recordingPath = $artifactInfo.path
        $recordingName = $artifactInfo.name
        $recordArguments = @('-RecordTo', $recordingPath)
        $arguments = @($recordArguments)
        $recordExecution = @(Invoke-WpdEscalationCommand -Name 'New-MpPerformanceRecording' -Arguments $recordArguments -CommandRunner $CommandRunner)
        if ((Get-WpdEscalationCommandExitCode -Execution $recordExecution) -ne 0) {
            throw 'Defender performance recording failed to start or complete'
        }
        if (-not (Test-Path -LiteralPath $recordingPath -PathType Leaf)) {
            throw 'Defender performance recording did not create an ETL'
        }

        $reportArguments = @('-Path', $recordingPath, '-Raw')
        $arguments += @($reportArguments)
        $reportExecution = @(Invoke-WpdEscalationCommand -Name 'Get-MpPerformanceReport' -Arguments $reportArguments -CommandRunner $CommandRunner)
        if ((Get-WpdEscalationCommandExitCode -Execution $reportExecution) -ne 0) {
            throw 'Defender performance report failed'
        }
        $reportData = Get-WpdEscalationCommandData -Execution $reportExecution
        if ($null -eq $reportData) {
            $reportData = Get-WpdEscalationCommandOutput -Execution $reportExecution
        }
        $successResult = New-WpdEscalationResult -Adapter 'defender' -Status 'success' -Reason 'defender-raw-performance-report' `
            -Tool 'DefenderPerformance' -Arguments @($recordArguments + $reportArguments) `
            -ArtifactPath $recordingPath -ArtifactName $recordingName -Data (Protect-WpdEscalationRecord -Record $reportData -Level $PrivacyLevel) `
            -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
        Add-Member -InputObject $successResult -MemberType NoteProperty -Name recordingPath -Value $recordingPath
        Add-Member -InputObject $successResult -MemberType NoteProperty -Name recordingName -Value $recordingName
        return $successResult
    }
    catch {
        $cleanupParent = $null
        $cleanupParentCreated = $false
        if ($null -ne $directoryInfo) {
            $cleanupParent = $directoryInfo.path
            $cleanupParentCreated = [bool]$directoryInfo.created
        }
        $cleanup = Remove-WpdEscalationArtifact -Path $recordingPath -CreatedByToolkit:($null -ne $recordingPath) `
            -ParentDirectory $cleanupParent -ParentCreatedByToolkit:$cleanupParentCreated
        $failureResult = New-WpdEscalationResult -Adapter 'defender' -Status 'error' -Reason 'capture-failed' `
            -Tool 'DefenderPerformance' -Arguments $arguments -ArtifactPath $recordingPath -ArtifactName $recordingName `
            -Errors @([pscustomobject]@{ stage = 'defender'; message = $_.Exception.Message }) `
            -Cleanup $cleanup -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
        Add-Member -InputObject $failureResult -MemberType NoteProperty -Name recordingPath -Value $recordingPath
        Add-Member -InputObject $failureResult -MemberType NoteProperty -Name recordingName -Value $recordingName
        return $failureResult
    }
}

# --------------------------------------------------------------------------
# Windows Search context
# --------------------------------------------------------------------------

function ConvertTo-WpdSearchServiceRecord {
    [CmdletBinding()]
    param([AllowNull()] [object] $InputObject)

    if ($null -eq $InputObject) { return $null }
    return [pscustomobject][ordered]@{
        name      = 'WSearch'
        status    = Get-WpdEscalationProperty -InputObject $InputObject -Name 'Status' -Default 'unknown'
        startType = Get-WpdEscalationProperty -InputObject $InputObject -Name 'StartType' -Default $null
    }
}

function ConvertTo-WpdSearchIndexRecord {
    [CmdletBinding()]
    param([AllowNull()] [object] $InputObject)

    if ($null -eq $InputObject) { return $null }
    $count = Get-WpdEscalationProperty -InputObject $InputObject -Name 'IndexedItems' -Default $null
    if ($null -eq $count) { $count = Get-WpdEscalationProperty -InputObject $InputObject -Name 'IndexedItemCount' -Default $null }
    return [pscustomobject][ordered]@{
        status       = Get-WpdEscalationProperty -InputObject $InputObject -Name 'Status' -Default 'unknown'
        indexedItems = $count
        source       = 'Windows Search index status and count'
    }
}

function Get-WpdSearchContext {
    <#
    .SYNOPSIS
        Collect read-only WSearch service and index status context.

    .DESCRIPTION
        ServiceProvider and IndexProvider are test seams. The default service
        provider only runs on Windows. No index rebuild, reset, repair, or other
        state-changing action is issued by this adapter.
    #>
    [CmdletBinding()]
    param(
        [Alias('ConfirmConsent', 'ConfirmEscalation')]
        [switch] $Consent,
        [AllowNull()] [scriptblock] $ServiceProvider,
        [AllowNull()] [scriptblock] $IndexProvider,
        [string] $PrivacyLevel = 'Standard'
    )

    $started = Get-WpdEscalationUtcTimestamp
    if (-not (Test-WpdEscalationConsent -Consent ([bool]$Consent))) {
        return New-WpdEscalationResult -Adapter 'search' -Status 'not-collected' -Reason 'consent-required' `
            -StartedUtc $started -ConsentGiven:$false -PrivacyLevel $PrivacyLevel
    }

    if ($null -eq $ServiceProvider -and -not (Test-WpdEscalationWindowsHost)) {
        return New-WpdEscalationResult -Adapter 'search' -Status 'unsupported' -Reason 'host-not-windows' `
            -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }

    $service = $null
    $index = $null
    $warnings = @()
    try {
        if ($null -ne $ServiceProvider) {
            $service = ConvertTo-WpdSearchServiceRecord -InputObject (& $ServiceProvider)
        }
        elseif (Test-WpdEscalationWindowsHost) {
            $service = ConvertTo-WpdSearchServiceRecord -InputObject (Get-Service -Name 'WSearch' -ErrorAction Stop)
        }
    }
    catch {
        $warnings += 'search-service-query-failed'
    }

    try {
        if ($null -ne $IndexProvider) {
            $index = ConvertTo-WpdSearchIndexRecord -InputObject (& $IndexProvider)
        }
        else {
            $warnings += 'search-index-provider-not-registered'
        }
    }
    catch {
        $warnings += 'search-index-query-failed'
    }

    $status = 'success'
    $coverage = 'complete'
    if ($null -eq $service -and $null -eq $index) {
        $status = 'unavailable'
        $coverage = 'unavailable'
    }
    elseif ($null -eq $service -or $null -eq $index) {
        $status = 'partial'
        $coverage = 'partial'
    }

    $reason = 'search-context-partial-or-unavailable'
    if ($status -eq 'success') { $reason = 'search-service-and-index-context' }
    return New-WpdEscalationResult -Adapter 'search' -Status $status -Coverage $coverage `
        -Reason $reason `
        -Data ([pscustomobject][ordered]@{ service = $service; index = $index; recommendations = @() }) `
        -Warnings $warnings -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
}

# --------------------------------------------------------------------------
# Minifilters and fltmc parsing
# --------------------------------------------------------------------------

function ConvertFrom-WpdFltmcFilterOutput {
    <#
    .SYNOPSIS
        Parse rows from `fltmc filters` and preserve altitude as text.
    #>
    [CmdletBinding()]
    param([AllowNull()] [string[]] $Lines)

    $rows = @()
    foreach ($line in @($Lines)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $trimmed = $line.Trim()
        if ($trimmed -match '^(Filter Name|---|=)' -or $trimmed -match '^[- ]+$') { continue }
        $parts = @($trimmed -split '\s+')
        if ($parts.Count -lt 4) { continue }
        $name = $parts[0]
        if ($name -match '^(Filter|Name)$') { continue }
        $numberTokens = @($parts[1..($parts.Count - 1)] | Where-Object { $_ -match '^\d+(?:\.\d+)?$' })
        if ($numberTokens.Count -lt 3) { continue }
        $instanceCount = 0
        $frame = 0
        if (-not [int]::TryParse($numberTokens[0], [ref]$instanceCount)) { continue }
        if (-not [int]::TryParse($numberTokens[2], [ref]$frame)) { continue }
        $rows += [pscustomobject][ordered]@{
            name          = $name
            numInstances  = $instanceCount
            altitude      = [string]$numberTokens[1]
            frame         = $frame
        }
    }
    return @(Sort-WpdFltmcByAltitude -Rows $rows)
}

function ConvertFrom-WpdFltmcInstanceOutput {
    <#
    .SYNOPSIS
        Parse rows from `fltmc instances` without retaining raw device text.
    #>
    [CmdletBinding()]
    param([AllowNull()] [string[]] $Lines)

    $rows = @()
    foreach ($line in @($Lines)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $trimmed = $line.Trim()
        if ($trimmed -match '^(Filter\s+Volume|---|=)' -or $trimmed -match '^[- ]+$') { continue }
        $columns = @([regex]::Split($trimmed, '\s{2,}') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($columns.Count -lt 4) {
            $parts = @($trimmed -split '\s+')
            if ($parts.Count -lt 4) { continue }
            $columns = @($parts[0], $parts[1], $parts[2], ($parts[3..($parts.Count - 1)] -join ' '))
        }
        if ($columns[0] -ieq 'Filter') { continue }
        $altitude = [string]$columns[2].Trim()
        if ($altitude -notmatch '^\d+(?:\.\d+)?$') { continue }
        $rows += [pscustomobject][ordered]@{
            name         = [string]$columns[0].Trim()
            volume       = [string]$columns[1].Trim()
            altitude     = $altitude
            instanceName = [string]$columns[3].Trim()
        }
    }
    return @($rows)
}

function Sort-WpdFltmcByAltitude {
    [CmdletBinding()]
    param([AllowNull()] [object[]] $Rows)

    return @($Rows | Sort-Object -Property @{ Expression = {
        $value = 0.0
        if ([double]::TryParse(([string]$_.altitude), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$value)) {
            return $value
        }
        return [double]::MaxValue
    } }, name)
}

function Invoke-WpdMinifilterEscalation {
    <#
    .SYNOPSIS
        Collect read-only fltmc filter and instance tables after consent.
    #>
    [CmdletBinding()]
    param(
        [Alias('ConfirmConsent', 'ConfirmEscalation')]
        [switch] $Consent,
        [AllowNull()] [hashtable] $CommandTable,
        [AllowNull()] [scriptblock] $CommandRunner,
        [string] $PrivacyLevel = 'Standard'
    )

    $started = Get-WpdEscalationUtcTimestamp
    if (-not (Test-WpdEscalationConsent -Consent ([bool]$Consent))) {
        return New-WpdEscalationResult -Adapter 'minifilter' -Status 'not-collected' -Reason 'consent-required' `
            -StartedUtc $started -ConsentGiven:$false -PrivacyLevel $PrivacyLevel
    }
    if (-not (Test-WpdEscalationCommandPresence -Name 'fltmc.exe' -CommandTable $CommandTable)) {
        return New-WpdEscalationResult -Adapter 'minifilter' -Status 'unavailable' -Reason 'tool-not-found' `
            -Tool 'fltmc.exe' -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }

    $calls = @()
    try {
        $filterArguments = @('filters')
        $filterExecution = @(Invoke-WpdEscalationCommand -Name 'fltmc.exe' -Arguments $filterArguments -CommandRunner $CommandRunner)
        $calls += $filterArguments
        if ((Get-WpdEscalationCommandExitCode -Execution $filterExecution) -ne 0) { throw 'fltmc filters failed' }
        $filterLines = @(Get-WpdEscalationCommandOutput -Execution $filterExecution)
        $filters = @(ConvertFrom-WpdFltmcFilterOutput -Lines $filterLines)

        $instanceArguments = @('instances')
        $instanceExecution = @(Invoke-WpdEscalationCommand -Name 'fltmc.exe' -Arguments $instanceArguments -CommandRunner $CommandRunner)
        $calls += $instanceArguments
        if ((Get-WpdEscalationCommandExitCode -Execution $instanceExecution) -ne 0) { throw 'fltmc instances failed' }
        $instanceLines = @(Get-WpdEscalationCommandOutput -Execution $instanceExecution)
        $instances = @(ConvertFrom-WpdFltmcInstanceOutput -Lines $instanceLines)

        $orderedFilters = @(Sort-WpdFltmcByAltitude -Rows $filters)
        return New-WpdEscalationResult -Adapter 'minifilter' -Status 'success' -Reason 'fltmc-filter-instance-snapshot' `
            -Tool 'fltmc.exe' -Arguments $calls -Data ([pscustomobject][ordered]@{
                filters = @($orderedFilters)
                instances = @($instances)
                orderKey = 'numeric-altitude-ascending'
                assessment = 'analysis-only'
            }) -Items $orderedFilters -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }
    catch {
        return New-WpdEscalationResult -Adapter 'minifilter' -Status 'error' -Reason 'fltmc-query-failed' `
            -Tool 'fltmc.exe' -Arguments $calls -Errors @([pscustomobject]@{ stage = 'fltmc'; message = $_.Exception.Message }) `
            -StartedUtc $started -ConsentGiven:$true -PrivacyLevel $PrivacyLevel
    }
}

# --------------------------------------------------------------------------
# Deep tracing descriptors
# --------------------------------------------------------------------------

function New-WpdTracingDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Id,
        [Parameter(Mandatory = $true)] [string] $Title,
        [Parameter(Mandatory = $true)] [string] $AnalysisQuestion,
        [Parameter(Mandatory = $true)] [string[]] $EvidenceSignals,
        [Parameter(Mandatory = $true)] [string] $Provider,
        [string[]] $RelatedAdapters = @(),
        [string] $PrivacyNote = 'Trace data is local, consented, and retained only as disclosed evidence.'
    )

    return [pscustomobject][ordered]@{
        id                   = $Id
        title                = $Title
        tier                 = 3
        mode                 = 'descriptor'
        status               = 'not-collected'
        consentRequired      = $true
        automaticRemediation = $false
        recommendations      = @()
        provider             = $Provider
        commands             = @()
        analysisQuestion     = $AnalysisQuestion
        evidenceSignals      = @($EvidenceSignals)
        relatedAdapters      = @($RelatedAdapters)
        privacy              = [pscustomobject][ordered]@{ default = 'Standard'; note = $PrivacyNote; rawData = 'sensitive-by-default' }
        cleanup              = [pscustomobject][ordered]@{ strategy = 'created-artifacts-only'; onFailure = 'remove-partial-artifact'; onSuccess = 'retain-evidence' }
        limitations          = @('Descriptor only: the host must select and validate a supported trace provider.', 'A correlation in this evidence is not a causal or remediation conclusion.')
    }
}

function New-WpdHeapTracingDescriptor {
    [CmdletBinding()]
    param()
    return New-WpdTracingDescriptor -Id 'heap' -Title 'Heap allocation tracing' `
        -AnalysisQuestion 'Which heap allocation patterns and call stacks overlap the symptom window?' `
        -EvidenceSignals @('allocation-size-and-count-events', 'allocation-call-stacks', 'heap-growth-over-time') `
        -Provider 'host-selected-ETW-heap-provider' -RelatedAdapters @('resident-memory', 'handles')
}

function New-WpdVirtualAllocTracingDescriptor {
    [CmdletBinding()]
    param()
    return New-WpdTracingDescriptor -Id 'virtualalloc' -Title 'VirtualAlloc and virtual memory tracing' `
        -AnalysisQuestion 'Which reserve, commit, free, and protection transitions overlap the symptom window?' `
        -EvidenceSignals @('virtual-memory-reserve-commit-free-events', 'protection-transition-events', 'commit-size-over-time') `
        -Provider 'host-selected-ETW-virtual-memory-provider' -RelatedAdapters @('heap', 'resident-memory')
}

function New-WpdResidentMemoryTracingDescriptor {
    [CmdletBinding()]
    param()
    return New-WpdTracingDescriptor -Id 'resident-memory' -Title 'Resident memory and working-set tracing' `
        -AnalysisQuestion 'Which process and allocation regions remain resident or fault during the symptom window?' `
        -EvidenceSignals @('working-set-change-events', 'hard-fault-and-soft-fault-events', 'resident-page-lifetime') `
        -Provider 'host-selected-ETW-memory-provider' -RelatedAdapters @('virtualalloc', 'heap')
}

function New-WpdHandleTracingDescriptor {
    [CmdletBinding()]
    param()
    return New-WpdTracingDescriptor -Id 'handles' -Title 'Process handle tracing' `
        -AnalysisQuestion 'Which processes create, duplicate, or retain unusual handle counts during the symptom window?' `
        -EvidenceSignals @('handle-create-close-events', 'handle-duplication-events', 'per-process-handle-counts') `
        -Provider 'host-selected-ETW-handle-provider' -RelatedAdapters @('wct', 'resident-memory')
}

function New-WpdGpuTracingDescriptor {
    [CmdletBinding()]
    param()
    return New-WpdTracingDescriptor -Id 'gpu' -Title 'Deep GPU and composition tracing' `
        -AnalysisQuestion 'Do GPU engine scheduling, memory, present, or compositor timelines overlap the symptom window?' `
        -EvidenceSignals @('gpu-engine-timeline', 'gpu-process-memory', 'dwm-present-and-flush-timeline', 'wddm-driver-state') `
        -Provider 'host-selected-WPR-GPU-profile' -RelatedAdapters @('ui')
}

function New-WpdAudioTracingDescriptor {
    [CmdletBinding()]
    param()
    return New-WpdTracingDescriptor -Id 'audio' -Title 'Deep audio engine tracing' `
        -AnalysisQuestion 'Do audio engine scheduling, stream periods, device transitions, or glitches overlap the symptom window?' `
        -EvidenceSignals @('audio-engine-scheduling', 'stream-period-and-glitch-events', 'audio-device-state-transitions', 'audiodg-process-timeline') `
        -Provider 'host-selected-WPR-audio-profile' -RelatedAdapters @('ui')
}

function New-WpdUiTracingDescriptor {
    [CmdletBinding()]
    param()
    return New-WpdTracingDescriptor -Id 'ui' -Title 'Deep UI responsiveness tracing' `
        -AnalysisQuestion 'Which UI thread, input, present, window-message, or compositor intervals overlap the reported stall?' `
        -EvidenceSignals @('ui-thread-ready-and-running-timeline', 'window-message-responsiveness', 'input-latency-events', 'dwm-present-timeline') `
        -Provider 'host-selected-WPR-UI-profile' -RelatedAdapters @('wct', 'gpu', 'audio')
}

function New-WpdGpuEscalationDescriptor {
    [CmdletBinding()]
    param()
    return New-WpdGpuTracingDescriptor
}

function New-WpdAudioEscalationDescriptor {
    [CmdletBinding()]
    param()
    return New-WpdAudioTracingDescriptor
}

function New-WpdUiEscalationDescriptor {
    [CmdletBinding()]
    param()
    return New-WpdUiTracingDescriptor
}

function Get-WpdDeepEscalationDescriptors {
    [CmdletBinding()]
    param()
    return @(
        (New-WpdHeapTracingDescriptor)
        (New-WpdVirtualAllocTracingDescriptor)
        (New-WpdResidentMemoryTracingDescriptor)
        (New-WpdHandleTracingDescriptor)
        (New-WpdGpuTracingDescriptor)
        (New-WpdAudioTracingDescriptor)
        (New-WpdUiTracingDescriptor)
    )
}

function Get-WpdEscalationDescriptors {
    <#
    .SYNOPSIS
        Return the complete optional Tier 3 adapter descriptor set.
    #>
    [CmdletBinding()]
    param()

    return @(
        [pscustomobject][ordered]@{
            id = 'wct'; title = 'Wait Chain Traversal snapshot'; tier = 3; mode = 'adapter'; status = 'not-collected'; consentRequired = $true
            automaticRemediation = $false; recommendations = @(); provider = 'OpenThreadWaitChainSession/GetThreadWaitChain provider seam'
            commands = @(); analysisQuestion = 'Which listed synchronization chain or cycle is present at this instant?'
            evidenceSignals = @('thread-and-synchronization-object-chain', 'owner-thread-links', 'cycle-detection')
            cleanup = [pscustomobject]@{ strategy = 'no-temporary-artifact'; onFailure = 'close-provider-session'; onSuccess = 'retain-structured-snapshot' }
            privacy = [pscustomobject]@{ default = 'Standard'; rawData = 'sensitive-by-default' }
            limitations = @('Point-in-time result; WCT is limited to its documented synchronization primitives.')
        }
        [pscustomobject][ordered]@{
            id = 'procdump'; title = 'Bounded ProcDump mini dump'; tier = 3; mode = 'adapter'; status = 'not-collected'; consentRequired = $true
            automaticRemediation = $false; recommendations = @(); provider = 'procdump.exe when already present'
            commands = @('-mm', '-n', '1', '<PID>', '<dump-file>'); analysisQuestion = 'What user-mode state is captured in one consented mini dump?'
            evidenceSignals = @('mini-dump-stacks-and-referenced-metadata'); cleanup = [pscustomobject]@{ strategy = 'created-artifacts-only'; onFailure = 'remove-partial-artifact'; onSuccess = 'retain-evidence' }
            privacy = [pscustomobject]@{ default = 'Standard'; rawData = 'sensitive-by-default' }
            limitations = @('Mini dumps may contain sensitive process state and are not a full-memory capture.')
        }
        (New-WpdPoolEscalationDescriptor)
        [pscustomobject][ordered]@{
            id = 'defender'; title = 'Defender performance analyzer'; tier = 3; mode = 'adapter'; status = 'not-collected'; consentRequired = $true
            automaticRemediation = $false; recommendations = @(); provider = 'DefenderPerformance module'
            commands = @('New-MpPerformanceRecording -RecordTo <recording.etl>', 'Get-MpPerformanceReport -Path <recording.etl> -Raw')
            analysisQuestion = 'Which Defender scan dimensions overlap the symptom window?'
            evidenceSignals = @('top-paths', 'top-files', 'top-processes', 'top-file-extensions', 'top-scans')
            cleanup = [pscustomobject]@{ strategy = 'created-artifacts-only'; onFailure = 'remove-partial-artifact'; onSuccess = 'retain-evidence' }
            privacy = [pscustomobject]@{ default = 'Standard'; rawData = 'sensitive-by-default' }
            limitations = @('Defender scan work is a scoped mechanism and needs a second evidence channel for correlation.')
        }
        [pscustomobject][ordered]@{
            id = 'search'; title = 'Windows Search service and index context'; tier = 3; mode = 'adapter'; status = 'not-collected'; consentRequired = $true
            automaticRemediation = $false; recommendations = @(); provider = 'WSearch service and index status provider seam'; commands = @()
            analysisQuestion = 'What service state, published index status, and indexed-item count overlap the symptom window?'
            evidenceSignals = @('wsearch-service-state', 'published-index-status-string', 'indexed-item-count')
            cleanup = [pscustomobject]@{ strategy = 'no-temporary-artifact'; onFailure = 'none'; onSuccess = 'retain-structured-context' }
            privacy = [pscustomobject]@{ default = 'Standard'; rawData = 'paths-not-retained' }
            limitations = @('Index status and item count do not prove that Search caused the regression.')
        }
        [pscustomobject][ordered]@{
            id = 'minifilter'; title = 'Minifilter and instance ordering'; tier = 3; mode = 'adapter'; status = 'not-collected'; consentRequired = $true
            automaticRemediation = $false; recommendations = @(); provider = 'fltmc.exe filters/instances'; commands = @('filters', 'instances')
            analysisQuestion = 'Which filters and instances, ordered by numeric altitude, overlap the file-I/O symptom?'
            evidenceSignals = @('filter-name-and-altitude', 'instance-volume-and-altitude', 'filter-order')
            cleanup = [pscustomobject]@{ strategy = 'no-temporary-artifact'; onFailure = 'none'; onSuccess = 'retain-structured-snapshot' }
            privacy = [pscustomobject]@{ default = 'Standard'; rawData = 'volume-detail-limited' }
            limitations = @('An altitude order is not a performance attribution; assessment or trace evidence is still required.')
        }
        (Get-WpdDeepEscalationDescriptors)
    )
}

function Get-WpdEscalationPlan {
    [CmdletBinding()]
    param([string[]] $Adapter)

    $all = @(Get-WpdEscalationDescriptors)
    if ($null -eq $Adapter -or $Adapter.Count -eq 0) {
        return $all
    }
    return @($all | Where-Object { $Adapter -contains $_.id })
}

# Useful spelling aliases as functions keep discovery predictable for callers.
function Get-WpdWctAnalysis {
    [CmdletBinding()]
    param([AllowNull()] [object[]] $Chains)
    return Get-WpdWaitChainAnalysis -Chains $Chains
}

function Invoke-WpdWct {
    [CmdletBinding()]
    param(
        [Alias('ConfirmConsent', 'ConfirmEscalation')] [switch] $Consent,
        [AllowNull()] [scriptblock] $ChainProvider,
        [AllowNull()] [int[]] $ProcessId,
        [AllowNull()] [int[]] $ThreadId,
        [string] $PrivacyLevel = 'Standard'
    )
    return Invoke-WpdWaitChain -Consent:$Consent -ChainProvider $ChainProvider -ProcessId $ProcessId -ThreadId $ThreadId -PrivacyLevel $PrivacyLevel
}

Export-ModuleMember -Function @(
    'ConvertFrom-WpdFltmcFilterOutput',
    'ConvertFrom-WpdFltmcInstanceOutput',
    'ConvertFrom-WpdPoolMonOutput',
    'Get-WpdDeepEscalationDescriptors',
    'Get-WpdEscalationDescriptors',
    'Get-WpdEscalationPlan',
    'Get-WpdSearchContext',
    'Get-WpdWaitChainAnalysis',
    'Get-WpdWctAnalysis',
    'Invoke-WpdDefenderPerformanceCapture',
    'Invoke-WpdMinifilterEscalation',
    'Invoke-WpdPoolEscalation',
    'Invoke-WpdProcDump',
    'Invoke-WpdWaitChain',
    'Invoke-WpdWct',
    'New-WpdAudioEscalationDescriptor',
    'New-WpdAudioTracingDescriptor',
    'New-WpdGpuEscalationDescriptor',
    'New-WpdGpuTracingDescriptor',
    'New-WpdHandleTracingDescriptor',
    'New-WpdHeapTracingDescriptor',
    'New-WpdProcDumpArguments',
    'New-WpdPoolEscalationDescriptor',
    'New-WpdResidentMemoryTracingDescriptor',
    'New-WpdUiEscalationDescriptor',
    'New-WpdUiTracingDescriptor',
    'New-WpdVirtualAllocTracingDescriptor',
    'Protect-WpdEscalationRecord',
    'Remove-WpdEscalationArtifact',
    'Test-WpdEscalationCommandPresence',
    'Test-WpdEscalationModulePresence',
    'Test-WpdEscalationWindowsHost'
)
