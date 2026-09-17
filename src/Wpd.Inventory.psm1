#Requires -Version 5.1
<#
.SYNOPSIS
    Tier 0 static inventory and privilege capability map.

.DESCRIPTION
    Read-only, cached Tier 0 inventory collectors with an independent failure
    envelope per capability. Tier 0 is collected once per run and served from a
    session cache so a Tier 1 sampling loop never re-queries a static class.

    Every collector is injected through a provider seam
    (New-WpdInventoryProviderResult / Invoke-WpdInventoryCapability), so the
    collectors are testable without Windows and a missing or unsupported
    provider is reported as unavailable/unsupported instead of healthy.

    Privacy is enforced in one place (Protect-WpdInventoryRecord) for the
    Standard, Redacted and Full levels. Secrets, tokens, cookies, browser
    history, credential material and document contents are never collected in
    any level.

    This module is a dependency-free PowerShell 5.1 module: no class keyword,
    no PS7-only operators and no Windows-only call at import time. It is
    consumed by the collector composition card (t_eef69ce4) and integrated into
    the entry point by t_b5e3e5a3.

.NOTES
    ASCII only. No BOM. Line feeds only. No write/remediation cmdlet anywhere.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------
# Section 1: vocabulary
# --------------------------------------------------------------------------

$script:WpdInventoryPluginVersion = '1.0.0'

$script:WpdInventoryStatusValues = @(
    'success'
    'partial'
    'unavailable'
    'unsupported'
    'not-collected'
    'error'
)

$script:WpdInventoryCoverageStates = @(
    'complete'
    'partial'
    'unavailable'
    'not-collected'
    'unsupported'
)

$script:WpdInventoryPrivacyLevels = @(
    'Standard'
    'Redacted'
    'Full'
)

$script:WpdInventoryCache = @{}
$script:WpdInventoryLastCacheKey = $null

$script:WpdInventoryForbiddenNameTokens = @(
    'password'
    'passwd'
    'passphrase'
    'secret'
    'token'
    'apikey'
    'accesskey'
    'credential'
    'cookie'
    'privatekey'
    'connectionstring'
    'browserhistory'
    'history'
    'bookmark'
    'documentcontent'
    'documentbody'
    'documenttext'
    'recoverykey'
    'sessionkey'
    'sessiontoken'
    'sessioncookie'
    'mailbox'
)

$script:WpdInventoryIdentifierNameTokens = @(
    'serial'
    'macaddress'
    'uuid'
    'guid'
    'productkey'
    'imei'
    'hardwareid'
    'usersid'
    'sddid'
)

$script:WpdInventoryCommandLineNameTokens = @(
    'commandline'
    'command'
    'arguments'
    'args'
)

$script:WpdInventoryUserNameTokens = @(
    'username'
    'user'
    'owner'
    'account'
    'startname'
    'runas'
    'loggedon'
)

$script:WpdInventoryPathNameTokens = @(
    'path'
    'folder'
    'directory'
    'location'
    'volume'
)

$script:WpdInventoryMacAddressPattern = '^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$'

# --------------------------------------------------------------------------
# Section 2: helpers
# --------------------------------------------------------------------------

function Test-WpdInventoryWindowsHost {
    <#
    .SYNOPSIS
        True only on a Windows host.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
}

function Get-WpdInventoryUtcTimestamp {
    <#
    .SYNOPSIS
        Invariant ISO-8601 UTC timestamp (PS 5.1 safe: no -AsUTC).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return [System.DateTime]::UtcNow.ToString(
        'yyyy-MM-ddTHH:mm:ss.fffZ',
        [System.Globalization.CultureInfo]::InvariantCulture
    )
}

function Test-WpdInventoryElevatedProcess {
    <#
    .SYNOPSIS
        True only when the current process runs in an Administrator role.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not (Test-WpdInventoryWindowsHost)) {
        return $false
    }

    try {
        $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-WpdInventoryCapabilityMeta {
    <#
    .SYNOPSIS
        One capability map entry by id, or $null when unknown.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string] $Id
    )

    if ([string]::IsNullOrWhiteSpace($Id)) {
        return $null
    }

    $match = @(Get-WpdInventoryCapabilityMap | Where-Object { $_.id -eq $Id })
    if ($match.Count -eq 0) {
        return $null
    }

    return $match[0]
}

function Get-WpdInventoryContext {
    <#
    .SYNOPSIS
        Normalize the injected context (host, elevation, privacy, commands).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [hashtable] $Context,

        [AllowEmptyString()]
        [string] $PrivacyLevel
    )

    $effective = @{
        IsWindows    = (Test-WpdInventoryWindowsHost)
        IsElevated   = $false
        PrivacyLevel = 'Standard'
        CommandTable = $null
    }

    if ($null -ne $Context) {
        foreach ($key in @($Context.Keys)) {
            $effective[$key] = $Context[$key]
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($PrivacyLevel)) {
        $effective['PrivacyLevel'] = Get-WpdInventoryPrivacyLevel -Level $PrivacyLevel
    }
    else {
        $effective['PrivacyLevel'] = Get-WpdInventoryPrivacyLevel -Level ([string]$effective['PrivacyLevel'])
    }

    if (-not $Context -or -not $Context.ContainsKey('IsElevated')) {
        $effective['IsElevated'] = (Test-WpdInventoryElevatedProcess)
    }

    $effective['IsWindows'] = [bool]$effective['IsWindows']
    $effective['IsElevated'] = [bool]$effective['IsElevated']

    return $effective
}

function Resolve-WpdInventoryProviderEntry {
    <#
    .SYNOPSIS
        Normalize an injected provider into a descriptor with a callable body.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Provider,

        [int] $Index = 0
    )

    $entry = @{
        name              = "provider-$Index"
        source            = $null
        platform          = 'any'
        allowEmpty        = $false
        requiresElevation = $false
        collect           = $null
    }

    if ($Provider -is [scriptblock]) {
        $entry['collect'] = $Provider
    }
    elseif ($Provider -is [hashtable]) {
        foreach ($key in @($Provider.Keys)) {
            $entry[[string]$key] = $Provider[$key]
        }
    }
    elseif ($null -ne $Provider) {
        foreach ($property in @($Provider.PSObject.Properties)) {
            $entry[$property.Name] = $property.Value
        }
    }

    if ($null -eq $entry['collect']) {
        throw "inventory provider '$($entry['name'])' has no collect script block"
    }

    if ([string]::IsNullOrWhiteSpace([string]$entry['source'])) {
        $entry['source'] = [string]$entry['name']
    }

    return $entry
}

function Get-WpdInventoryProviderList {
    <#
    .SYNOPSIS
        Provider descriptors for one capability from an injected provider table.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [hashtable] $Providers,

        [AllowEmptyString()]
        [string] $Id
    )

    $list = @()
    if ($null -eq $Providers -or [string]::IsNullOrWhiteSpace($Id)) {
        return $list
    }

    $matched = @($Providers.Keys | Where-Object { $_ -eq $Id })
    if ($matched.Count -eq 0) {
        return $list
    }

    $index = 0
    foreach ($provider in @($Providers[$matched[0]])) {
        $list += (Resolve-WpdInventoryProviderEntry -Provider $provider -Index $index)
        $index++
    }

    return $list
}

function New-WpdInventoryEnvelope {
    <#
    .SYNOPSIS
        Build one capability envelope (shared by every exit path).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Capability,

        [string] $Status = 'unavailable',
        [string] $Coverage = 'unavailable',
        [AllowNull()] [string] $Source,
        [AllowNull()] $Items = @(),
        [string[]] $Warnings = @(),
        [object[]] $Errors = @(),
        [string[]] $Reasons = @(),
        [string] $PrivacyLevel = 'Standard',
        [string] $StartedUtc,
        [string] $CompletedUtc,
        [long] $DurationMs = 0,
        [bool] $Cached = $false
    )

    $records = @($Items)

    return [pscustomobject]@{
        id                = $Capability.id
        capability        = $Capability
        title             = $Capability.title
        tier              = $Capability.tier
        status            = $Status
        coverage          = $Coverage
        source            = $Source
        requiredElevation = $Capability.requiredElevation
        elevationReason   = $Capability.elevationReason
        privacyLevel      = $PrivacyLevel
        startedUtc        = $StartedUtc
        completedUtc      = $CompletedUtc
        durationMs        = $DurationMs
        recordCount       = $records.Count
        items             = $records
        warnings          = @($Warnings)
        errors            = @($Errors)
        reasons           = @($Reasons)
        cached            = $Cached
    }
}

function Test-WpdInventoryForbiddenField {
    <#
    .SYNOPSIS
        True when a field name must never be collected, at any privacy level.

    .DESCRIPTION
        Secrets, credential material, tokens, cookies, browser history and
        document contents are dropped before storage, at Standard, Redacted and
        Full alike. Dropping is by field name so it also applies to fields of a
        provider this module has never seen.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    $normalized = ([regex]::Replace($Name, '[^A-Za-z0-9]', '')).ToLowerInvariant()
    if ($normalized.Length -eq 0) {
        return $false
    }

    foreach ($token in $script:WpdInventoryForbiddenNameTokens) {
        if ($normalized.Contains($token)) {
            return $true
        }
    }

    return $false
}

function Get-WpdInventoryPrivacyLevel {
    <#
    .SYNOPSIS
        Normalize and validate a privacy level; default is Standard (D10).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()]
        [string] $Level
    )

    if ([string]::IsNullOrWhiteSpace($Level)) {
        return 'Standard'
    }

    $match = @($script:WpdInventoryPrivacyLevels | Where-Object { $_ -eq $Level })
    if ($match.Count -eq 0) {
        throw [System.ArgumentException]::new(
            "unknown privacy level '$Level'; valid values are $($script:WpdInventoryPrivacyLevels -join ', ')"
        )
    }

    return $match[0]
}

function Protect-WpdInventoryRecord {
    <#
    .SYNOPSIS
        Apply the privacy level to an inventory record before it is stored.

    .DESCRIPTION
        One place applies D10: forbidden fields are dropped at every level,
        device identifiers are hashed at Standard and Redacted, Redacted also
        hashes paths and user names and suppresses command lines, and Full is the
        explicit opt-in that keeps raw values. Nesting is walked to a bounded
        depth so a provider cannot smuggle a secret through a child object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Record,

        [AllowEmptyString()]
        [string] $Level,

        [int] $Depth = 8
    )

    $level = Get-WpdInventoryPrivacyLevel -Level $Level

    if ($null -eq $Record) {
        return $null
    }

    return (Protect-WpdInventoryValue -Value $Record -Level $level -Depth $Depth)
}

function Get-WpdInventoryNormalizedName {
    <#
    .SYNOPSIS
        Lower-case alphanumeric form of a field name for token matching.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return ''
    }

    return ([regex]::Replace($Name, '[^A-Za-z0-9]', '')).ToLowerInvariant()
}

function Get-WpdInventoryHash {
    <#
    .SYNOPSIS
        Stable short SHA-256 label for an identifying value (never reversible
        back to the value, and stable across runs for the same input).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Value
    )

    if ($null -eq $Value -or $Value.Length -eq 0) {
        return $null
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
        $hex = [System.BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
        return 'sha256:' + $hex.Substring(0, 12)
    }
    finally {
        $sha.Dispose()
    }
}

function Get-WpdInventoryFieldKind {
    <#
    .SYNOPSIS
        Classify a field name as forbidden, identifier, commandLine, user, path
        or none. Classification is by name, so an unknown provider field is
        still treated consistently.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Name
    )

    if (Test-WpdInventoryForbiddenField -Name $Name) {
        return 'forbidden'
    }

    $normalized = Get-WpdInventoryNormalizedName -Name $Name
    if ($normalized.Length -eq 0) {
        return 'none'
    }

    foreach ($token in $script:WpdInventoryIdentifierNameTokens) {
        if ($normalized.Contains($token)) {
            return 'identifier'
        }
    }

    foreach ($token in $script:WpdInventoryCommandLineNameTokens) {
        if ($normalized.Contains($token)) {
            return 'commandLine'
        }
    }

    foreach ($token in $script:WpdInventoryUserNameTokens) {
        if ($normalized.Contains($token)) {
            return 'user'
        }
    }

    foreach ($token in $script:WpdInventoryPathNameTokens) {
        if ($normalized.Contains($token)) {
            return 'path'
        }
    }

    return 'none'
}

function Protect-WpdInventoryValue {
    <#
    .SYNOPSIS
        Recursive privacy transform used by Protect-WpdInventoryRecord.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Value,

        [string] $Level = 'Standard',

        [int] $Depth = 8,

        [AllowEmptyString()]
        [AllowNull()]
        [string] $FieldName
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Depth -le 0) {
        if ($Value -is [string] -or -not ($Value -is [System.Collections.IEnumerable])) {
            return $Value
        }
        return '<privacy-depth-limit>'
    }

    if ($Value -is [string]) {
        $kind = Get-WpdInventoryFieldKind -Name $FieldName

        switch ($kind) {
            'identifier' {
                if ($Level -eq 'Full') { return $Value }
                return (Get-WpdInventoryHash -Value $Value)
            }
            'path' {
                if ($Level -eq 'Redacted') { return (Get-WpdInventoryHash -Value $Value) }
                return $Value
            }
            'user' {
                if ($Level -eq 'Redacted') { return (Get-WpdInventoryHash -Value $Value) }
                return $Value
            }
            'commandLine' {
                if ($Level -eq 'Redacted') { return $null }
                return $Value
            }
            default {
                if ($Level -ne 'Full' -and $Value -match $script:WpdInventoryMacAddressPattern) {
                    return (Get-WpdInventoryHash -Value $Value)
                }
                return $Value
            }
        }
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $mapped = @{}
        foreach ($key in @($Value.Keys)) {
            $childName = [string]$key
            if (Test-WpdInventoryForbiddenField -Name $childName) {
                continue
            }
            $mapped[$childName] = Protect-WpdInventoryValue -Value $Value[$key] -Level $Level -Depth ($Depth - 1) -FieldName $childName
        }
        return $mapped
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $mapped = @()
        foreach ($item in $Value) {
            $mapped += Protect-WpdInventoryValue -Value $item -Level $Level -Depth ($Depth - 1)
        }
        return $mapped
    }

    $properties = @($Value.PSObject.Properties)
    if ($properties.Count -eq 0) {
        return $Value
    }

    $mapped = [ordered]@{}
    foreach ($property in $properties) {
        if (Test-WpdInventoryForbiddenField -Name $property.Name) {
            continue
        }
        $mapped[$property.Name] = Protect-WpdInventoryValue -Value $property.Value -Level $Level -Depth ($Depth - 1) -FieldName $property.Name
    }

    return [pscustomobject]$mapped
}

function Test-WpdInventoryCommandPresence {
    <#
    .SYNOPSIS
        Case-insensitive presence detection against an injectable command table.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [AllowNull()]
        [hashtable] $CommandTable
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    if ($null -ne $CommandTable) {
        foreach ($key in @($CommandTable.Keys)) {
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        return $false
    }

    try {
        $null = Get-Command -Name $Name -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# --------------------------------------------------------------------------
# Section 3: capability map and provider seams
# --------------------------------------------------------------------------

function Get-WpdInventoryCapabilityMap {
    <#
    .SYNOPSIS
        Static capability map: tier, provider APIs, elevation and privacy needs.

    .DESCRIPTION
        One entry per Tier 0 capability. Each provider names the documented
        read-only inbox API that would supply the records, so a capability is
        never claimed from a write-capable or third-party API (rejection R7).
        'requiredElevation' is the level the *capability* needs: 'administrator'
        entries are reported unavailable with reason 'requires-administrator'
        when the run is not elevated, instead of silently returning nothing.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $capabilities = @(
        [pscustomobject]@{
            id = 'os'
            title = 'Operating system'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'standard'
            elevationReason = 'Win32_OperatingSystem, Win32_ComputerSystem and Win32_TimeZone are readable by a standard user'
            source = 'cim'
            privacy = 'paths'
            specRefs = @('P1-1', 'spec 63', 'spec 66')
            providers = @(
                [pscustomobject]@{ api = 'Get-CimInstance Win32_OperatingSystem'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_ComputerSystem'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_TimeZone'; kind = 'cim'; namespace = 'root/cimv2' }
            )
        }
        [pscustomobject]@{
            id = 'hardware'
            title = 'Hardware, topology and BIOS'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'standard'
            elevationReason = 'Win32_Processor, Win32_PhysicalMemory, Win32_BaseBoard and Win32_BIOS are readable by a standard user'
            source = 'cim'
            privacy = 'identifiers'
            specRefs = @('P1-1', 'spec 66')
            providers = @(
                [pscustomobject]@{ api = 'Get-CimInstance Win32_Processor'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_PhysicalMemory'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_BaseBoard'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_BIOS'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_Battery'; kind = 'cim'; namespace = 'root/cimv2' }
            )
        }
        [pscustomobject]@{
            id = 'drivers'
            title = 'Drivers and devices'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'standard'
            elevationReason = 'Get-PnpDevice and Win32_PnPSignedDriver are readable by a standard user'
            source = 'powershell'
            privacy = 'identifiers'
            specRefs = @('P1-1', 'platform section 11 [41]')
            providers = @(
                [pscustomobject]@{ api = 'Get-PnpDevice'; kind = 'powershell'; namespace = 'PnpDevice' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_PnPEntity'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_PnPSignedDriver'; kind = 'cim'; namespace = 'root/cimv2' }
            )
        }
        [pscustomobject]@{
            id = 'power'
            title = 'Power configuration and processor state'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'standard'
            elevationReason = 'powercfg /getactivescheme and powercfg /a report the active scheme and available sleep states without elevation'
            source = 'powercfg'
            privacy = 'none'
            specRefs = @('P1-1', 'platform section 7 [26]')
            providers = @(
                [pscustomobject]@{ api = 'powercfg /getactivescheme'; kind = 'process'; namespace = 'powercfg' }
                [pscustomobject]@{ api = 'powercfg /a'; kind = 'process'; namespace = 'powercfg' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_Processor'; kind = 'cim'; namespace = 'root/cimv2' }
            )
        }
        [pscustomobject]@{
            id = 'storage'
            title = 'Storage topology and reliability'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'standard'
            elevationReason = 'Get-PhysicalDisk and Get-StorageReliabilityCounter are readable by a standard user; a disk that exposes no reliability counter is reported unsupported'
            source = 'powershell'
            privacy = 'identifiers'
            specRefs = @('P1-1', 'spec 26', 'platform sections 1 and 10 [2][3][45]')
            providers = @(
                [pscustomobject]@{ api = 'Get-PhysicalDisk'; kind = 'powershell'; namespace = 'Storage' }
                [pscustomobject]@{ api = 'Get-StorageReliabilityCounter'; kind = 'powershell'; namespace = 'Storage' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_DiskDrive'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_LogicalDisk'; kind = 'cim'; namespace = 'root/cimv2' }
            )
        }
        [pscustomobject]@{
            id = 'nic'
            title = 'Network adapters'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'standard'
            elevationReason = 'Get-NetAdapter and Win32_NetworkAdapterConfiguration are readable by a standard user; MAC addresses are treated as identifiers'
            source = 'powershell'
            privacy = 'identifiers'
            specRefs = @('P1-1', 'spec 31')
            providers = @(
                [pscustomobject]@{ api = 'Get-NetAdapter'; kind = 'powershell'; namespace = 'NetAdapter' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_NetworkAdapterConfiguration'; kind = 'cim'; namespace = 'root/cimv2' }
            )
        }
        [pscustomobject]@{
            id = 'services'
            title = 'Services'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'standard'
            elevationReason = 'Win32_Service is readable by a standard user; service paths are privacy-redacted, never modified'
            source = 'cim'
            privacy = 'paths'
            specRefs = @('P1-1', 'platform section 10 [39]')
            providers = @(
                [pscustomobject]@{ api = 'Get-CimInstance Win32_Service'; kind = 'cim'; namespace = 'root/cimv2' }
            )
        }
        [pscustomobject]@{
            id = 'security'
            title = 'Security products'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'standard'
            elevationReason = 'root/SecurityCenter2 AntivirusProduct/AntiSpywareProduct/FirewallProduct and Get-MpComputerStatus are readable by a standard user; the legacy MSI product class is never queried because querying it triggers MSI reconfiguration'
            source = 'cim'
            privacy = 'none'
            specRefs = @('P1-1', 'spec 29')
            providers = @(
                [pscustomobject]@{ api = 'Get-CimInstance -Namespace root/SecurityCenter2 AntivirusProduct'; kind = 'cim'; namespace = 'root/SecurityCenter2' }
                [pscustomobject]@{ api = 'Get-CimInstance -Namespace root/SecurityCenter2 AntiSpywareProduct'; kind = 'cim'; namespace = 'root/SecurityCenter2' }
                [pscustomobject]@{ api = 'Get-CimInstance -Namespace root/SecurityCenter2 FirewallProduct'; kind = 'cim'; namespace = 'root/SecurityCenter2' }
                [pscustomobject]@{ api = 'Get-MpComputerStatus'; kind = 'powershell'; namespace = 'Defender' }
            )
        }
        [pscustomobject]@{
            id = 'startup'
            title = 'Startup registry, folders, services and tasks'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'standard'
            elevationReason = 'Autoruns-style inventory is readable by a standard user; command lines are suppressed at the Redacted level'
            source = 'mixed'
            privacy = 'paths'
            specRefs = @('P1-1', 'spec 41', 'platform section 10 [39]')
            providers = @(
                [pscustomobject]@{ api = 'Get-CimInstance Win32_StartupCommand'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; kind = 'registry'; namespace = 'registry' }
                [pscustomobject]@{ api = 'Get-ChildItem <startup folder>'; kind = 'filesystem'; namespace = 'startup-folder' }
                [pscustomobject]@{ api = 'Get-ScheduledTask'; kind = 'powershell'; namespace = 'ScheduledTasks' }
            )
        }
        [pscustomobject]@{
            id = 'filters'
            title = 'Filesystem filters (minifilters)'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'administrator'
            elevationReason = 'fltmc filter and instance queries require an elevated console; a non-elevated run is reported unavailable, never as no filters installed'
            source = 'fltmc'
            privacy = 'none'
            specRefs = @('P1-1', 'spec 28', 'platform section 2 [5]')
            providers = @(
                [pscustomobject]@{ api = 'fltmc filters'; kind = 'process'; namespace = 'fltmc' }
                [pscustomobject]@{ api = 'fltmc instances'; kind = 'process'; namespace = 'fltmc' }
            )
        }
        [pscustomobject]@{
            id = 'pagefiles'
            title = 'Pagefiles'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'standard'
            elevationReason = 'Win32_PageFileUsage and Win32_PageFileSetting are readable by a standard user'
            source = 'cim'
            privacy = 'paths'
            specRefs = @('P1-1', 'spec 20')
            providers = @(
                [pscustomobject]@{ api = 'Get-CimInstance Win32_PageFileUsage'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_PageFileSetting'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_ComputerSystem'; kind = 'cim'; namespace = 'root/cimv2' }
            )
        }
        [pscustomobject]@{
            id = 'virtualization'
            title = 'Virtualization based security and hypervisor state'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'standard'
            elevationReason = 'Win32_ComputerSystem.HypervisorPresent and root/Microsoft/Windows/DeviceGuard Win32_DeviceGuard are readable by a standard user'
            source = 'cim'
            privacy = 'none'
            specRefs = @('P1-1', 'spec 67', 'platform section 12 [46]')
            providers = @(
                [pscustomobject]@{ api = 'Get-CimInstance Win32_ComputerSystem'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard Win32_DeviceGuard'; kind = 'cim'; namespace = 'root/Microsoft/Windows/DeviceGuard' }
            )
        }
        [pscustomobject]@{
            id = 'encryption'
            title = 'BitLocker and TRIM context'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'administrator'
            elevationReason = 'Get-BitLockerVolume and manage-bde -status require elevation; TRIM state comes from fsutil behavior query DisableDeleteNotify'
            source = 'powershell'
            privacy = 'identifiers'
            specRefs = @('P1-1', 'spec 27')
            providers = @(
                [pscustomobject]@{ api = 'Get-BitLockerVolume'; kind = 'powershell'; namespace = 'BitLocker' }
                [pscustomobject]@{ api = 'manage-bde -status'; kind = 'process'; namespace = 'BitLocker' }
                [pscustomobject]@{ api = 'fsutil behavior query DisableDeleteNotify'; kind = 'process'; namespace = 'fsutil' }
            )
        }
        [pscustomobject]@{
            id = 'recentChanges'
            title = 'Recent changes'
            tier = 0
            windowsOnly = $true
            requiredElevation = 'standard'
            elevationReason = 'Win32_QuickFixEngineering and the uninstall registry keys are readable by a standard user; installed program names are inventory, never document contents'
            source = 'mixed'
            privacy = 'paths'
            specRefs = @('P1-1', 'spec 42')
            providers = @(
                [pscustomobject]@{ api = 'Get-CimInstance Win32_QuickFixEngineering'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-CimInstance Win32_PnPSignedDriver'; kind = 'cim'; namespace = 'root/cimv2' }
                [pscustomobject]@{ api = 'Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; kind = 'registry'; namespace = 'registry' }
            )
        }
    )

    return $capabilities
}

function Get-WpdInventoryProperty {
    <#
    .SYNOPSIS
        Defensive property reader: a missing field yields $null instead of an
        error, so one renamed provider field cannot abort a capability.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        $InputObject,

        [AllowEmptyString()]
        [string] $Name
    )

    if ($null -eq $InputObject -or [string]::IsNullOrWhiteSpace($Name)) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function ConvertTo-WpdInventoryProjection {
    <#
    .SYNOPSIS
        Project a provider instance onto an explicit, named field set.

    .DESCRIPTION
        Only the listed fields are copied, so a provider that starts returning a
        new sensitive property cannot leak it into today's inventory, and the
        privacy walk then sees a known field set.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string] $ClassName,

        [AllowNull()]
        $Instance,

        [AllowNull()]
        [string[]] $Fields,

        [AllowEmptyString()]
        [string] $Source
    )

    $projected = [ordered]@{}
    $projected['class'] = $ClassName

    foreach ($field in @($Fields)) {
        if ([string]::IsNullOrWhiteSpace($field)) {
            continue
        }
        $projected[$field] = Get-WpdInventoryProperty -InputObject $Instance -Name $field
    }

    if (-not [string]::IsNullOrWhiteSpace($Source)) {
        $projected['source'] = $Source
    }

    return [pscustomobject]$projected
}

function New-WpdInventoryScriptProvider {
    <#
    .SYNOPSIS
        Provider descriptor for an injected script block (Windows only).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string] $Source,

        [Parameter(Mandatory = $true)]
        [scriptblock] $Collect,

        [switch] $AllowEmpty
    )

    return [pscustomobject]@{
        name       = $Name
        source     = $Source
        platform   = 'windows'
        allowEmpty = [bool]$AllowEmpty
        collect    = $Collect
    }
}

function New-WpdInventoryCimProvider {
    <#
    .SYNOPSIS
        Provider descriptor for one read-only CIM class query.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string] $ClassName,

        [Parameter(Mandatory = $true)]
        [string[]] $Fields,

        [string] $Namespace = 'root/cimv2',

        [switch] $AllowEmpty
    )

    $className = $ClassName
    $classNamespace = $Namespace
    $fieldList = $Fields
    $source = "Get-CimInstance $ClassName"

    $collect = {
        if (-not (Get-Command -Name 'Get-CimInstance' -ErrorAction SilentlyContinue)) {
            throw [System.Management.Automation.CommandNotFoundException]::new('Get-CimInstance is not present')
        }

        $instances = @(Get-CimInstance -ClassName $className -Namespace $classNamespace -ErrorAction Stop)
        if ($instances.Count -eq 0) {
            return @()
        }

        return @($instances | ForEach-Object {
                ConvertTo-WpdInventoryProjection -ClassName $className -Instance $_ -Fields $fieldList -Source $source
            })
    }.GetNewClosure()

    return (New-WpdInventoryScriptProvider -Name $Name -Source $source -Collect $collect -AllowEmpty:$AllowEmpty)
}

function New-WpdInventoryCommandProvider {
    <#
    .SYNOPSIS
        Provider descriptor for one read-only inbox command line tool.

    .DESCRIPTION
        The command must already be present (otherwise the capability is
        unsupported), output is passed through the named parser, and a non-zero
        exit code becomes an explicit unavailable state instead of an empty
        success.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string] $CommandName,

        [Parameter(Mandatory = $true)]
        [string] $Parser,

        [string[]] $Arguments = @(),

        [AllowNull()]
        [hashtable] $ParserArguments,

        [switch] $AllowEmpty
    )

    $exe = $CommandName
    $argList = $Arguments
    $parserName = $Parser
    $parserArgs = $ParserArguments
    $source = (@($CommandName) + @($Arguments)) -join ' '

    $collect = {
        if (-not (Test-WpdInventoryCommandPresence -Name $exe)) {
            throw [System.Management.Automation.CommandNotFoundException]::new("$exe is not present")
        }

        $lines = @(& $exe @argList 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE

        if ($null -ne $exitCode -and $exitCode -ne 0) {
            return (New-WpdInventoryProviderResult -Status 'unavailable' `
                    -Reason ("$exe-exit-$exitCode") -Items @() -Source $source `
                    -Warnings @("$exe returned exit code $exitCode"))
        }

        if ($null -ne $parserArgs) {
            return (& $parserName -Lines $lines @parserArgs)
        }

        return (& $parserName -Lines $lines)
    }.GetNewClosure()

    return (New-WpdInventoryScriptProvider -Name $Name -Source $source -Collect $collect -AllowEmpty:$AllowEmpty)
}

function Get-WpdInventoryDefaultProviders {
    <#
    .SYNOPSIS
        The default (Windows) provider set, one entry per capability.

    .DESCRIPTION
        Every provider is a documented read-only inbox API (plan D7/R7): CIM
        classes, the Storage/PnpDevice/NetAdapter/ScheduledTasks/BitLocker
        cmdlets, the registry, and the inbox console tools powercfg, fltmc and
        fsutil. Nothing is downloaded, nothing is written, and no remediation
        cmdlet appears anywhere. Building this table performs no query.
    #>
    [CmdletBinding()]
    param()

    $providers = @{}

    # --- OS -----------------------------------------------------------------
    $providers['os'] = @(
        (New-WpdInventoryCimProvider -Name 'os-operating-system' -ClassName 'Win32_OperatingSystem' -Fields @(
                'Caption', 'Version', 'BuildNumber', 'OSArchitecture', 'InstallDate', 'LastBootUpTime',
                'Locale', 'TotalVisibleMemorySize', 'FreePhysicalMemory', 'WindowsDirectory', 'SystemDrive'
            ))
        (New-WpdInventoryCimProvider -Name 'os-computer-system' -ClassName 'Win32_ComputerSystem' -Fields @(
                'Name', 'Manufacturer', 'Model', 'SystemType', 'NumberOfProcessors', 'NumberOfLogicalProcessors',
                'TotalPhysicalMemory', 'HypervisorPresent', 'AutomaticManagedPagefile'
            ))
        (New-WpdInventoryCimProvider -Name 'os-time-zone' -ClassName 'Win32_TimeZone' -Fields @(
                'Caption', 'Bias', 'StandardName', 'DaylightName'
            ))
    )

    # --- Hardware, topology, BIOS -------------------------------------------
    $providers['hardware'] = @(
        (New-WpdInventoryCimProvider -Name 'hardware-processor' -ClassName 'Win32_Processor' -Fields @(
                'Name', 'Manufacturer', 'NumberOfCores', 'NumberOfLogicalProcessors', 'MaxClockSpeed',
                'CurrentClockSpeed', 'AddressWidth', 'Architecture', 'ProcessorId', 'LoadPercentage'
            ))
        (New-WpdInventoryCimProvider -Name 'hardware-memory' -ClassName 'Win32_PhysicalMemory' -Fields @(
                'BankLabel', 'DeviceLocator', 'Capacity', 'Speed', 'ConfiguredClockSpeed', 'Manufacturer', 'PartNumber', 'FormFactor'
            ) -AllowEmpty)
        (New-WpdInventoryCimProvider -Name 'hardware-baseboard' -ClassName 'Win32_BaseBoard' -Fields @(
                'Manufacturer', 'Product', 'Version', 'SerialNumber'
            ))
        (New-WpdInventoryCimProvider -Name 'hardware-bios' -ClassName 'Win32_BIOS' -Fields @(
                'Manufacturer', 'Name', 'Version', 'SMBIOSBIOSVersion', 'SMBIOSMajorVersion', 'SMBIOSMinorVersion',
                'ReleaseDate', 'SerialNumber', 'EmbeddedControllerMajorVersion', 'EmbeddedControllerMinorVersion'
            ))
        (New-WpdInventoryCimProvider -Name 'hardware-battery' -ClassName 'Win32_Battery' -Fields @(
                'Name', 'DeviceID', 'EstimatedChargeRemaining', 'BatteryStatus', 'DesignVoltage'
            ) -AllowEmpty)
    )

    # --- Drivers and devices ------------------------------------------------
    $providers['drivers'] = @(
        (New-WpdInventoryScriptProvider -Name 'drivers-pnp-entity' -Source 'Get-CimInstance Win32_PnPEntity' -Collect {
                if (-not (Test-WpdInventoryCommandPresence -Name 'Get-CimInstance')) {
                    throw [System.Management.Automation.CommandNotFoundException]::new('Get-CimInstance is not present')
                }
                $entities = @(Get-CimInstance -ClassName 'Win32_PnPEntity' -Namespace 'root/cimv2' -ErrorAction Stop)
                $projected = @($entities | ForEach-Object {
                        ConvertTo-WpdInventoryProjection -ClassName 'Win32_PnPEntity' -Instance $_ -Fields @(
                            'Name', 'DeviceID', 'Status', 'ConfigManagerErrorCode', 'Service', 'ClassGuid'
                        ) -Source 'Get-CimInstance Win32_PnPEntity'
                    })
                $problemDevices = @($projected | Where-Object { $_.Status -ne 'OK' })
                return (New-WpdInventoryProviderResult -Status 'success' -Items $projected -Source 'Get-CimInstance Win32_PnPEntity' `
                        -Warnings $(if ($problemDevices.Count -gt 0) { @("$($problemDevices.Count) device(s) report a non-OK status") } else { @() }))
            } -AllowEmpty)
        (New-WpdInventoryScriptProvider -Name 'drivers-pnp-device' -Source 'Get-PnpDevice' -Collect {
                if (-not (Test-WpdInventoryCommandPresence -Name 'Get-PnpDevice')) {
                    throw [System.Management.Automation.CommandNotFoundException]::new('Get-PnpDevice is not present')
                }
                $devices = @(Get-PnpDevice -ErrorAction Stop)
                return @($devices | ForEach-Object {
                        ConvertTo-WpdInventoryProjection -ClassName 'PnpDevice' -Instance $_ -Fields @(
                            'Class', 'FriendlyName', 'Status', 'Problem', 'InstanceId'
                        ) -Source 'Get-PnpDevice'
                    })
            } -AllowEmpty)
        (New-WpdInventoryCimProvider -Name 'drivers-signed-driver' -ClassName 'Win32_PnPSignedDriver' -Fields @(
                'DeviceName', 'DeviceClass', 'Manufacturer', 'DriverVersion', 'DriverDate', 'InfName', 'IsSigned'
            ) -AllowEmpty)
    )

    # --- Power configuration ------------------------------------------------
    $providers['power'] = @(
        (New-WpdInventoryCommandProvider -Name 'power-active-scheme' -CommandName 'powercfg.exe' `
                -Arguments @('/getactivescheme') -Parser 'ConvertFrom-WpdPowercfgOutput' `
                -ParserArguments @{ Kind = 'active-scheme' })
        (New-WpdInventoryCommandProvider -Name 'power-sleep-states' -CommandName 'powercfg.exe' `
                -Arguments @('/a') -Parser 'ConvertFrom-WpdPowercfgOutput' `
                -ParserArguments @{ Kind = 'sleep-states' })
        (New-WpdInventoryCimProvider -Name 'power-processor-state' -ClassName 'Win32_Processor' -Fields @(
                'Name', 'CurrentVoltage', 'CurrentClockSpeed', 'MaxClockSpeed', 'PowerManagementSupported',
                'PowerManagementCapabilities'
            ))
    )

    # --- Storage topology and reliability -----------------------------------
    $providers['storage'] = @(
        (New-WpdInventoryScriptProvider -Name 'storage-physical-disk' -Source 'Get-PhysicalDisk' -Collect {
                if (-not (Test-WpdInventoryCommandPresence -Name 'Get-PhysicalDisk')) {
                    throw [System.Management.Automation.CommandNotFoundException]::new('Get-PhysicalDisk is not present')
                }
                $disks = @(Get-PhysicalDisk -ErrorAction Stop)
                $records = @($disks | ForEach-Object {
                        ConvertTo-WpdInventoryProjection -ClassName 'PhysicalDisk' -Instance $_ -Fields @(
                            'FriendlyName', 'MediaType', 'BusType', 'Size', 'HealthStatus', 'OperationalStatus',
                            'SpindleSpeed', 'FirmwareVersion', 'SerialNumber', 'DeviceId'
                        ) -Source 'Get-PhysicalDisk'
                    })
                $reliability = @()
                foreach ($disk in $disks) {
                    $counter = $null
                    try {
                        $counter = Get-StorageReliabilityCounter -PhysicalDisk $disk -ErrorAction Stop
                    }
                    catch {
                        $counter = $null
                    }
                    $reliability += (ConvertTo-WpdStorageReliabilityRecord -Counters $counter -DeviceId ([string](Get-WpdInventoryProperty -InputObject $disk -Name 'DeviceId')))
                }
                return (New-WpdInventoryProviderResult -Status 'success' -Items ($records + $reliability) -Source 'Get-PhysicalDisk; Get-StorageReliabilityCounter')
            } -AllowEmpty)
        (New-WpdInventoryCimProvider -Name 'storage-disk-drive' -ClassName 'Win32_DiskDrive' -Fields @(
                'Model', 'InterfaceType', 'MediaType', 'Size', 'Status', 'Partitions', 'FirmwareRevision', 'SerialNumber'
            ) -AllowEmpty)
        (New-WpdInventoryCimProvider -Name 'storage-logical-disk' -ClassName 'Win32_LogicalDisk' -Fields @(
                'DeviceID', 'DriveType', 'FileSystem', 'Size', 'FreeSpace', 'VolumeName', 'VolumeSerialNumber'
            ) -AllowEmpty)
    )

    # --- Network adapters ---------------------------------------------------
    $providers['nic'] = @(
        (New-WpdInventoryScriptProvider -Name 'nic-net-adapter' -Source 'Get-NetAdapter' -Collect {
                if (-not (Test-WpdInventoryCommandPresence -Name 'Get-NetAdapter')) {
                    throw [System.Management.Automation.CommandNotFoundException]::new('Get-NetAdapter is not present')
                }
                $adapters = @(Get-NetAdapter -ErrorAction Stop)
                return @($adapters | ForEach-Object {
                        ConvertTo-WpdInventoryProjection -ClassName 'NetAdapter' -Instance $_ -Fields @(
                            'Name', 'InterfaceDescription', 'Status', 'LinkSpeed', 'MacAddress', 'DriverVersion', 'DriverProvider'
                        ) -Source 'Get-NetAdapter'
                    })
            } -AllowEmpty)
        (New-WpdInventoryCimProvider -Name 'nic-adapter-configuration' -ClassName 'Win32_NetworkAdapterConfiguration' -Fields @(
                'Description', 'MACAddress', 'DHCPEnabled', 'IPEnabled', 'DNSHostName', 'IPAddress', 'DefaultIPGateway', 'DNSServerSearchOrder'
            ) -AllowEmpty)
    )

    # --- Services -----------------------------------------------------------
    $providers['services'] = @(
        (New-WpdInventoryCimProvider -Name 'services-win32-service' -ClassName 'Win32_Service' -Fields @(
                'Name', 'DisplayName', 'State', 'Status', 'StartMode', 'DelayedAutoStart', 'StartName',
                'PathName', 'ProcessId', 'ServiceType', 'ExitCode'
            ))
    )

    # --- Security products --------------------------------------------------
    $providers['security'] = @(
        (New-WpdInventoryCimProvider -Name 'security-antivirus' -ClassName 'AntivirusProduct' `
                -Namespace 'root/SecurityCenter2' -Fields @('displayName', 'productState', 'timestamp', 'pathToSignedProductExe') -AllowEmpty)
        (New-WpdInventoryCimProvider -Name 'security-antispyware' -ClassName 'AntiSpywareProduct' `
                -Namespace 'root/SecurityCenter2' -Fields @('displayName', 'productState', 'timestamp') -AllowEmpty)
        (New-WpdInventoryCimProvider -Name 'security-firewall' -ClassName 'FirewallProduct' `
                -Namespace 'root/SecurityCenter2' -Fields @('displayName', 'productState', 'timestamp') -AllowEmpty)
        (New-WpdInventoryScriptProvider -Name 'security-defender-status' -Source 'Get-MpComputerStatus' -Collect {
                if (-not (Test-WpdInventoryCommandPresence -Name 'Get-MpComputerStatus')) {
                    return (New-WpdInventoryProviderResult -Status 'unsupported' -Reason 'defender-module-not-present' -Items @())
                }
                $status = Get-MpComputerStatus -ErrorAction Stop
                $projection = @(
                    (ConvertTo-WpdInventoryProjection -ClassName 'MpComputerStatus' -Instance $status -Fields @(
                            'AMRunningMode', 'AntivirusEnabled', 'AntispywareEnabled', 'RealTimeProtectionEnabled',
                            'AntivirusSignatureAge', 'AntivirusSignatureLastUpdated', 'NISEnabled', 'IsTamperProtected'
                        ) -Source 'Get-MpComputerStatus')
                )
                return (New-WpdInventoryProviderResult -Status 'success' -Items $projection -Source 'Get-MpComputerStatus')
            } -AllowEmpty)
    )

    # --- Startup inventory --------------------------------------------------
    $providers['startup'] = @(
        (New-WpdInventoryScriptProvider -Name 'startup-registry' -Source 'Get-ItemProperty HKLM/HKCU Run keys' -Collect {
                if (-not (Test-WpdInventoryWindowsHost)) {
                    throw [System.NotSupportedException]::new('the startup registry is Windows only')
                }
                $locations = @(
                    [pscustomobject]@{ key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; label = 'HKLM Run' }
                    [pscustomobject]@{ key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; label = 'HKLM RunOnce' }
                    [pscustomobject]@{ key = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; label = 'HKLM Run (32-bit)' }
                    [pscustomobject]@{ key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; label = 'HKCU Run' }
                    [pscustomobject]@{ key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; label = 'HKCU RunOnce' }
                )
                $records = @()
                $skipped = 0
                foreach ($location in $locations) {
                    if (-not (Test-Path -LiteralPath $location.key)) {
                        $skipped++
                        continue
                    }
                    $item = Get-ItemProperty -LiteralPath $location.key -ErrorAction SilentlyContinue
                    if ($null -eq $item) {
                        $skipped++
                        continue
                    }
                    $values = @($item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })
                    foreach ($value in $values) {
                        $records += ConvertTo-WpdStartupEntry -Source 'registry' -Location $location.label `
                            -Name ([string]$value.Name) -Command ([string]$value.Value) -Level 'Standard'
                    }
                }
                $warnings = @()
                if ($skipped -gt 0) {
                    $warnings += "$skipped startup registry location(s) were not readable"
                }
                return (New-WpdInventoryProviderResult -Status 'success' -Items $records -Source 'HKCU/HKLM Run and RunOnce' -Warnings $warnings)
            } -AllowEmpty)
        (New-WpdInventoryCimProvider -Name 'startup-command' -ClassName 'Win32_StartupCommand' -Fields @(
                'Name', 'Command', 'Location', 'User'
            ) -AllowEmpty)
        (New-WpdInventoryScriptProvider -Name 'startup-folders' -Source 'Get-ChildItem <startup folder>' -Collect {
                if (-not (Test-WpdInventoryWindowsHost)) {
                    throw [System.NotSupportedException]::new('the startup folders are Windows only')
                }
                $records = @()
                $folders = @(
                    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')
                    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
                )
                foreach ($folder in $folders) {
                    if ([string]::IsNullOrWhiteSpace($folder) -or -not (Test-Path -LiteralPath $folder)) {
                        continue
                    }
                    $items = @(Get-ChildItem -LiteralPath $folder -ErrorAction SilentlyContinue -Filter '*.lnk')
                    foreach ($item in $items) {
                        $records += ConvertTo-WpdStartupEntry -Source 'startup-folder' -Location $folder `
                            -Name ([string]$item.Name) -Command ([string]$item.FullName) -Level 'Standard'
                    }
                }
                return (New-WpdInventoryProviderResult -Status 'success' -Items $records -Source 'Startup folders')
            } -AllowEmpty)
        (New-WpdInventoryScriptProvider -Name 'startup-scheduled-tasks' -Source 'Get-ScheduledTask' -Collect {
                if (-not (Test-WpdInventoryCommandPresence -Name 'Get-ScheduledTask')) {
                    throw [System.Management.Automation.CommandNotFoundException]::new('Get-ScheduledTask is not present')
                }
                $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' })
                return @($tasks | ForEach-Object {
                        $record = ConvertTo-WpdStartupEntry -Source 'scheduled-task' -Location ([string]$_.TaskPath) `
                            -Name ([string]$_.TaskName) -Command ([string]$_.TaskPath) -Level 'Standard'
                        $record.State = [string]$_.State
                        $record
                    })
            } -AllowEmpty)
    )

    # --- Filesystem filters -------------------------------------------------
    $providers['filters'] = @(
        (New-WpdInventoryCommandProvider -Name 'filters-fltmc-filters' -CommandName 'fltmc.exe' `
                -Arguments @('filters') -Parser 'ConvertFrom-WpdFltmcFilterOutput')
        (New-WpdInventoryCommandProvider -Name 'filters-fltmc-instances' -CommandName 'fltmc.exe' `
                -Arguments @('instances') -Parser 'ConvertFrom-WpdFltmcInstanceOutput')
    )

    # --- Pagefiles ----------------------------------------------------------
    $providers['pagefiles'] = @(
        (New-WpdInventoryCimProvider -Name 'pagefiles-usage' -ClassName 'Win32_PageFileUsage' -Fields @(
                'Name', 'AllocatedBaseSize', 'CurrentUsage', 'PeakUsage', 'TempPageFile'
            ))
        (New-WpdInventoryCimProvider -Name 'pagefiles-setting' -ClassName 'Win32_PageFileSetting' -Fields @(
                'Name', 'InitialSize', 'MaximumSize'
            ) -AllowEmpty)
        (New-WpdInventoryCimProvider -Name 'pagefiles-computer-system' -ClassName 'Win32_ComputerSystem' -Fields @(
                'Name', 'AutomaticManagedPagefile', 'TotalPhysicalMemory'
            ))
    )

    # --- Virtualization / VBS -----------------------------------------------
    $providers['virtualization'] = @(
        (New-WpdInventoryScriptProvider -Name 'virtualization-context' -Source 'Win32_ComputerSystem; Win32_DeviceGuard' -Collect {
                if (-not (Test-WpdInventoryCommandPresence -Name 'Get-CimInstance')) {
                    throw [System.Management.Automation.CommandNotFoundException]::new('Get-CimInstance is not present')
                }
                $computerSystem = Get-CimInstance -ClassName 'Win32_ComputerSystem' -Namespace 'root/cimv2' -ErrorAction Stop
                $deviceGuard = $null
                try {
                    $deviceGuard = Get-CimInstance -ClassName 'Win32_DeviceGuard' -Namespace 'root/Microsoft/Windows/DeviceGuard' -ErrorAction Stop
                }
                catch {
                    $deviceGuard = $null
                }
                $record = ConvertTo-WpdVirtualizationContext -ComputerSystem $computerSystem -DeviceGuard $deviceGuard
                return (New-WpdInventoryProviderResult -Status 'success' -Items @($record) -Source 'Win32_ComputerSystem; Win32_DeviceGuard' -Warnings @($record.warnings))
            })
    )

    # --- BitLocker and TRIM context -----------------------------------------
    $providers['encryption'] = @(
        (New-WpdInventoryScriptProvider -Name 'encryption-bitlocker-volume' -Source 'Get-BitLockerVolume' -Collect {
                if (-not (Test-WpdInventoryCommandPresence -Name 'Get-BitLockerVolume')) {
                    return (New-WpdInventoryProviderResult -Status 'unsupported' -Reason 'bitlocker-module-not-present' -Items @())
                }
                $volumes = @(Get-BitLockerVolume -ErrorAction Stop)
                return @($volumes | ForEach-Object {
                        ConvertTo-WpdInventoryProjection -ClassName 'BitLockerVolume' -Instance $_ -Fields @(
                            'MountPoint', 'VolumeStatus', 'ProtectionStatus', 'EncryptionPercentage', 'LockStatus',
                            'EncryptionMethod', 'AutoUnlockEnabled', 'KeyProtector'
                        ) -Source 'Get-BitLockerVolume'
                    })
            } -AllowEmpty)
        (New-WpdInventoryCommandProvider -Name 'encryption-manage-bde' -CommandName 'manage-bde.exe' `
                -Arguments @('-status') -Parser 'ConvertFrom-WpdBitLockerStatusOutput' -AllowEmpty)
        (New-WpdInventoryCommandProvider -Name 'encryption-trim' -CommandName 'fsutil.exe' `
                -Arguments @('behavior', 'query', 'DisableDeleteNotify') -Parser 'ConvertFrom-WpdFsutilTrimOutput')
    )

    # --- Recent changes -----------------------------------------------------
    $providers['recentChanges'] = @(
        (New-WpdInventoryCimProvider -Name 'recent-changes-hotfix' -ClassName 'Win32_QuickFixEngineering' -Fields @(
                'HotFixID', 'Description', 'InstalledOn', 'InstalledBy', 'Caption'
            ) -AllowEmpty)
        (New-WpdInventoryScriptProvider -Name 'recent-changes-installed-programs' -Source 'Get-ItemProperty HKLM Uninstall keys' -Collect {
                if (-not (Test-WpdInventoryWindowsHost)) {
                    throw [System.NotSupportedException]::new('the uninstall registry is Windows only')
                }
                $keyPaths = @(
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                )
                $records = @()
                $warnings = @()
                foreach ($keyPath in $keyPaths) {
                    $entries = @(Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue)
                    foreach ($entry in $entries) {
                        $installDate = [string](Get-WpdInventoryProperty -InputObject $entry -Name 'InstallDate')
                        $displayName = [string](Get-WpdInventoryProperty -InputObject $entry -Name 'DisplayName')
                        if ([string]::IsNullOrWhiteSpace($displayName) -or [string]::IsNullOrWhiteSpace($installDate)) {
                            continue
                        }
                        $records += ConvertTo-WpdInventoryProjection -ClassName 'UninstallEntry' -Instance $entry -Fields @(
                            'DisplayName', 'DisplayVersion', 'Publisher', 'InstallDate', 'InstallLocation'
                        ) -Source 'Get-ItemProperty HKLM Uninstall'
                    }
                }
                $bounded = @($records | Sort-Object -Property InstallDate -Descending)
                if ($bounded.Count -gt 200) {
                    $warnings += "installed-program list truncated from $($bounded.Count) to 200 entries"
                    $bounded = @($bounded[0..199])
                }
                return (New-WpdInventoryProviderResult -Status 'success' -Items $bounded `
                        -Source 'Get-ItemProperty HKLM Uninstall' -Warnings $warnings)
            } -AllowEmpty)
    )

    return $providers
}

function New-WpdInventoryProviderResult {
    <#
    .SYNOPSIS
        Build an explicit provider result (including unsupported/unavailable).

    .DESCRIPTION
        A provider script block may return a plain record set, or this object to
        state something the caller cannot infer: that the API is absent, that
        the platform does not expose the data, or that the query was invalid.
        An explicit non-success status is never converted into a success.
    #>
    [CmdletBinding()]
    param(
        [string] $Status = 'success',
        [string] $Reason,
        [AllowNull()] $Items,
        [string] $Source,
        [string[]] $Warnings = @()
    )

    $normalized = @($script:WpdInventoryStatusValues | Where-Object { $_ -eq $Status })
    if ($normalized.Count -eq 0) {
        throw [System.ArgumentException]::new(
            "unknown inventory status '$Status'; valid values are $($script:WpdInventoryStatusValues -join ', ')"
        )
    }

    return [pscustomobject]@{
        wpdInventoryProviderResult = $true
        status                     = $normalized[0]
        reason                     = $Reason
        items                      = @($Items)
        source                     = $Source
        warnings                   = @($Warnings)
    }
}

function Invoke-WpdInventoryCapability {
    <#
    .SYNOPSIS
        Run one capability's providers inside its own failure envelope.

    .DESCRIPTION
        Never throws for a provider-level problem: an absent command, an
        unsupported platform, a provider exception or a provider that returns no
        data all become a stated status on that capability's envelope. A failing
        provider cannot abort a sibling capability because each capability is
        invoked separately by the caller, and inside a capability the failure is
        recorded, not rethrown.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Id,

        [AllowNull()]
        [hashtable] $Providers,

        [AllowNull()]
        [hashtable] $Context
    )

    $capability = Get-WpdInventoryCapabilityMeta -Id $Id
    if ($null -eq $capability) {
        throw [System.ArgumentException]::new("unknown inventory capability '$Id'")
    }

    $state = Get-WpdInventoryContext -Context $Context
    $privacyLevel = [string]$state['PrivacyLevel']
    $startedUtc = Get-WpdInventoryUtcTimestamp
    $startTicks = [System.Diagnostics.Stopwatch]::StartNew()

    $entries = @(Get-WpdInventoryProviderList -Providers $Providers -Id $Id)
    $sourceLabel = @($entries | ForEach-Object { $_.source }) -join '; '

    if ($entries.Count -eq 0) {
        return (New-WpdInventoryEnvelope -Capability $capability `
            -Status 'unavailable' -Coverage 'unavailable' -Source '<no-provider-registered>' `
            -Reasons @('provider-absent') -PrivacyLevel $privacyLevel `
            -StartedUtc $startedUtc -CompletedUtc (Get-WpdInventoryUtcTimestamp) `
            -DurationMs $startTicks.ElapsedMilliseconds)
    }

    if ($capability.requiredElevation -eq 'administrator' -and -not $state['IsElevated']) {
        return (New-WpdInventoryEnvelope -Capability $capability `
            -Status 'unavailable' -Coverage 'unavailable' -Source $sourceLabel `
            -Reasons @('requires-administrator') -PrivacyLevel $privacyLevel `
            -StartedUtc $startedUtc -CompletedUtc (Get-WpdInventoryUtcTimestamp) `
            -DurationMs $startTicks.ElapsedMilliseconds)
    }

    $items = @()
    $warnings = @()
    $errors = @()
    $reasons = @()
    $sources = @()
    $successCount = 0
    $failureCount = 0
    $emptyCount = 0
    $skippedCount = 0
    $unsupportedCount = 0
    $unavailableCount = 0

    foreach ($entry in $entries) {
        $entrySource = [string]$entry['source']

        if ([string]$entry['platform'] -eq 'windows' -and -not $state['IsWindows']) {
            $skippedCount++
            $reasons += 'host-not-windows:' + [string]$entry['name']
            continue
        }

        try {
            $result = & $entry['collect']
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            $unsupportedCount++
            $reasons += 'command-not-present:' + [string]$entry['name']
            continue
        }
        catch [System.PlatformNotSupportedException] {
            $unsupportedCount++
            $reasons += 'platform-not-supported:' + [string]$entry['name']
            continue
        }
        catch [System.NotSupportedException] {
            $unsupportedCount++
            $reasons += 'not-supported:' + [string]$entry['name']
            continue
        }
        catch {
            $failureCount++
            $errors += [pscustomobject]@{
                stage    = 'provider'
                provider = [string]$entry['name']
                source   = $entrySource
                message  = $_.Exception.Message
            }
            continue
        }

        $isProviderResult = $false
        if ($null -ne $result -and $null -ne $result.PSObject -and $null -ne $result.PSObject.Properties['wpdInventoryProviderResult']) {
            $isProviderResult = [bool]$result.PSObject.Properties['wpdInventoryProviderResult'].Value
        }

        if ($isProviderResult) {
            $sources += $(if ([string]::IsNullOrWhiteSpace([string]$result.source)) { $entrySource } else { [string]$result.source })
            $warnings += @($result.warnings)

            if ($result.status -eq 'success') {
                $produced = @($result.items)
                if ($produced.Count -eq 0 -and -not [bool]$entry['allowEmpty']) {
                    $emptyCount++
                    $reasons += 'no-data-returned:' + [string]$entry['name']
                    continue
                }
                $items += $produced
                $successCount++
            }
            elseif ($result.status -eq 'partial') {
                $items += @($result.items)
                $successCount++
                $warnings += "provider reported partial data: $($entry['name'])"
            }
            else {
                if ([string]::IsNullOrWhiteSpace([string]$result.reason)) {
                    $reasons += "$($result.status):" + [string]$entry['name']
                }
                else {
                    $reasons += [string]$result.reason
                }

                if ($result.status -eq 'unsupported') {
                    $unsupportedCount++
                }
                elseif ($result.status -eq 'error') {
                    $failureCount++
                    $errors += [pscustomobject]@{
                        stage    = 'provider'
                        provider = [string]$entry['name']
                        source   = $entrySource
                        message  = 'provider reported status error'
                    }
                }
                else {
                    $unavailableCount++
                }
            }
            continue
        }

        $sources += $entrySource
        $produced = @($result)
        if ($produced.Count -eq 0 -and -not [bool]$entry['allowEmpty']) {
            $emptyCount++
            $reasons += 'no-data-returned:' + [string]$entry['name']
            continue
        }

        $items += $produced
        $successCount++
    }

    if ($successCount -gt 0) {
        if ($failureCount -gt 0 -or $emptyCount -gt 0 -or $unsupportedCount -gt 0 -or $unavailableCount -gt 0 -or $skippedCount -gt 0) {
            $status = 'partial'
            $coverage = 'partial'
        }
        else {
            $status = 'success'
            $coverage = 'complete'
        }
    }
    elseif ($failureCount -gt 0) {
        $status = 'error'
        $coverage = 'unavailable'
    }
    elseif ($unavailableCount -gt 0 -or $emptyCount -gt 0) {
        $status = 'unavailable'
        $coverage = 'unavailable'
    }
    elseif ($unsupportedCount -gt 0 -or $skippedCount -gt 0) {
        $status = 'unsupported'
        $coverage = 'unsupported'
    }
    else {
        $status = 'unavailable'
        $coverage = 'unavailable'
        $reasons += 'no-provider-produced-data'
    }

    $protected = @($items | ForEach-Object { Protect-WpdInventoryRecord -Record $_ -Level $privacyLevel })
    $sourceResolved = @($sources | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    if ($sourceResolved.Count -eq 0) {
        $sourceResolved = @($sourceLabel)
    }

    return (New-WpdInventoryEnvelope -Capability $capability `
        -Status $status -Coverage $coverage -Source ($sourceResolved -join '; ') `
        -Items $protected -Warnings $warnings -Errors $errors -Reasons $reasons `
        -PrivacyLevel $privacyLevel -StartedUtc $startedUtc `
        -CompletedUtc (Get-WpdInventoryUtcTimestamp) -DurationMs $startTicks.ElapsedMilliseconds)
}

function Get-WpdInventoryCapability {
    <#
    .SYNOPSIS
        Return one capability envelope from cache, querying at most once.

    .DESCRIPTION
        The Tier 0 accessor for composition and reporting code: it never
        re-queries a capability that is already in the session cache, so a Tier 1
        sampling loop can read static inventory without touching a provider.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Id,

        [AllowNull()]
        [hashtable] $Providers,

        [AllowNull()]
        [hashtable] $Context,

        [AllowEmptyString()]
        [string] $CacheKey,

        [switch] $Refresh
    )

    if ($null -eq (Get-WpdInventoryCapabilityMeta -Id $Id)) {
        throw [System.ArgumentException]::new("unknown inventory capability '$Id'")
    }

    $key = $CacheKey
    if ([string]::IsNullOrWhiteSpace($key)) {
        $key = [string]$script:WpdInventoryLastCacheKey
    }
    if ([string]::IsNullOrWhiteSpace($key)) {
        $key = 'default'
    }

    if (-not $Refresh -and $script:WpdInventoryCache.ContainsKey($key)) {
        $entry = $script:WpdInventoryCache[$key]
        if ($entry['envelopes'].ContainsKey($Id)) {
            # Return a copy so a caller holding an earlier result never sees it mutate.
            $cached = $entry['envelopes'][$Id].PSObject.Copy()
            $cached.cached = $true
            return $cached
        }
    }

    $envelope = Invoke-WpdInventoryCapability -Id $Id -Providers $Providers -Context $Context

    if (-not $script:WpdInventoryCache.ContainsKey($key)) {
        $script:WpdInventoryCache[$key] = @{
            key        = $key
            createdUtc = Get-WpdInventoryUtcTimestamp
            envelopes  = @{}
            result     = $null
        }
    }
    $script:WpdInventoryCache[$key]['envelopes'][$Id] = $envelope
    $script:WpdInventoryLastCacheKey = $key

    return $envelope
}

function Get-WpdInventory {
    <#
    .SYNOPSIS
        Collect (or return cached) Tier 0 inventory for every capability.

    .DESCRIPTION
        Each capability is collected inside its own envelope, so one failing,
        unsupported or unavailable capability never aborts the run or hides the
        others. The result is stored in the session cache under -CacheKey and a
        second call is served from it (plan D3: Tier 0 is collected once).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [hashtable] $Providers,

        [AllowNull()]
        [hashtable] $Context,

        [AllowEmptyString()]
        [string] $PrivacyLevel,

        [AllowEmptyString()]
        [string] $CacheKey,

        [switch] $Refresh
    )

    $key = $CacheKey
    if ([string]::IsNullOrWhiteSpace($key)) {
        $key = 'default'
    }

    if (-not $Refresh -and $script:WpdInventoryCache.ContainsKey($key)) {
        $cachedEntry = $script:WpdInventoryCache[$key]
        if ($null -ne $cachedEntry['result']) {
            # Return a copy: a cache hit must not mutate the result an earlier
            # caller still holds (the cached flag is annotation, not state).
            $cachedResult = $cachedEntry['result'].PSObject.Copy()
            $cachedResult.cached = $true
            return $cachedResult
        }
    }

    $state = Get-WpdInventoryContext -Context $Context -PrivacyLevel $PrivacyLevel
    if ($null -eq $Providers) {
        $Providers = Get-WpdInventoryDefaultProviders
    }

    $ids = @((Get-WpdInventoryCapabilityMap) | ForEach-Object { $_.id })
    $envelopes = @{}
    $order = @()
    $warnings = @()
    $errors = @()
    $counts = @{
        success      = 0
        partial      = 0
        unavailable  = 0
        unsupported  = 0
        notCollected = 0
        error        = 0
        total        = 0
    }
    $recordCount = 0

    foreach ($id in $ids) {
        $envelope = Invoke-WpdInventoryCapability -Id $id -Providers $Providers -Context $state
        $envelopes[$id] = $envelope
        $order += $id
        $recordCount += $envelope.recordCount

        switch ([string]$envelope.status) {
            'partial' { $counts['partial']++ }
            'unavailable' { $counts['unavailable']++ }
            'unsupported' { $counts['unsupported']++ }
            'not-collected' { $counts['notCollected']++ }
            'error' { $counts['error']++ }
            default { $counts['success']++ }
        }

        foreach ($warning in @($envelope.warnings)) {
            $warnings += ('{0}: {1}' -f $id, [string]$warning)
        }
        foreach ($errorEntry in @($envelope.errors)) {
            $errors += [pscustomobject]@{
                capability = $id
                stage      = $errorEntry.stage
                provider   = $errorEntry.provider
                message    = $errorEntry.message
            }
        }
    }

    $counts['total'] = $order.Count

    $result = [pscustomobject]@{
        schemaVersion   = '1.0'
        tier            = 0
        generatedUtc    = Get-WpdInventoryUtcTimestamp
        privacyLevel    = [string]$state['PrivacyLevel']
        cacheKey        = $key
        isWindows       = [bool]$state['IsWindows']
        isElevated      = [bool]$state['IsElevated']
        capabilityOrder = $order
        capabilities    = $envelopes
        counts          = $counts
        recordCount     = $recordCount
        warnings        = $warnings
        errors          = $errors
        cached          = $false
    }

    $script:WpdInventoryCache[$key] = @{
        key        = $key
        createdUtc = Get-WpdInventoryUtcTimestamp
        envelopes  = $envelopes
        result     = $result
    }
    $script:WpdInventoryLastCacheKey = $key

    return $result
}

function Get-WpdInventoryCache {
    <#
    .SYNOPSIS
        Inspect the session cache without querying any provider.
    #>
    [CmdletBinding()]
    param()

    $entries = @()
    foreach ($key in @($script:WpdInventoryCache.Keys)) {
        $entry = $script:WpdInventoryCache[$key]
        $entries += [pscustomobject]@{
            key             = [string]$entry['key']
            createdUtc      = [string]$entry['createdUtc']
            privacyLevel    = $(
                if ($null -ne $entry['result']) { [string]$entry['result'].privacyLevel } else { $null }
            )
            capabilityCount = @($entry['envelopes'].Keys).Count
            recordCount     = $(
                if ($null -ne $entry['result']) { [int]$entry['result'].recordCount } else { 0 }
            )
            complete        = ($null -ne $entry['result'])
        }
    }

    return $entries
}

function Clear-WpdInventoryCache {
    <#
    .SYNOPSIS
        Drop cached Tier 0 results (all keys, or one key).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string] $CacheKey
    )

    if ([string]::IsNullOrWhiteSpace($CacheKey)) {
        $script:WpdInventoryCache = @{}
        $script:WpdInventoryLastCacheKey = $null
        return
    }

    if ($script:WpdInventoryCache.ContainsKey($CacheKey)) {
        $script:WpdInventoryCache.Remove($CacheKey)
    }

    if ([string]$script:WpdInventoryLastCacheKey -eq $CacheKey) {
        $script:WpdInventoryLastCacheKey = $null
    }
}

# --------------------------------------------------------------------------
# Section 4: output parsers
# --------------------------------------------------------------------------

function ConvertFrom-WpdFltmcFilterOutput {
    <#
    .SYNOPSIS
        Parse 'fltmc filters' output into altitude-ordered filter records.

    .DESCRIPTION
        Altitude order is the documented load order (the lowest altitude sees
        the I/O first), so the records are returned in ascending altitude order.
        An unparsable row becomes a parse warning; it never removes the rows that
        did parse.
    #>
    [CmdletBinding()]
    param([AllowNull()] [string[]] $Lines)

    $filters = @()
    $warnings = @()
    $lineNumber = 0

    foreach ($raw in @($Lines)) {
        $lineNumber++
        $line = [string]$raw
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^\s*Filter\s+Name\s') { continue }
        if ($line -match '^\s*-{3,}') { continue }

        $match = [regex]::Match($line, '^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$')
        if (-not $match.Success) {
            $warnings += ('line {0} not parsed: {1}' -f $lineNumber, $line.Trim())
            continue
        }

        $filters += [pscustomobject]@{
            name      = $match.Groups[1].Value
            instances = [int]$match.Groups[2].Value
            altitude  = [int]$match.Groups[3].Value
            frame     = [int]$match.Groups[4].Value
        }
    }

    $ordered = @($filters | Sort-Object -Property altitude)

    return [pscustomobject]@{
        kind          = 'filesystem-filters'
        view          = 'filters'
        order         = 'altitude-ascending'
        source        = 'fltmc filters'
        filterCount   = $ordered.Count
        filters       = $ordered
        parseWarnings = $warnings
    }
}

function ConvertFrom-WpdFltmcInstanceOutput {
    <#
    .SYNOPSIS
        Parse 'fltmc instances' output into altitude-ordered instances.
    #>
    [CmdletBinding()]
    param([AllowNull()] [string[]] $Lines)

    $instances = @()
    $warnings = @()
    $lineNumber = 0

    foreach ($raw in @($Lines)) {
        $lineNumber++
        $line = [string]$raw
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^\s*Filter\s+Volume\s+Name') { continue }
        if ($line -match '^\s*-{3,}') { continue }

        $match = [regex]::Match($line, '^(\S+)\s+(\S+)\s+(\d+)\s+(.+?)\s*$')
        if (-not $match.Success) {
            $warnings += ('line {0} not parsed: {1}' -f $lineNumber, $line.Trim())
            continue
        }

        $instances += [pscustomobject]@{
            filterName   = $match.Groups[1].Value
            volume       = $match.Groups[2].Value
            altitude     = [int]$match.Groups[3].Value
            instanceName = $match.Groups[4].Value
        }
    }

    $ordered = @($instances | Sort-Object -Property altitude)

    return [pscustomobject]@{
        kind          = 'filesystem-filters'
        view          = 'instances'
        order         = 'altitude-ascending'
        source        = 'fltmc instances'
        instanceCount = $ordered.Count
        instances     = $ordered
        parseWarnings = $warnings
    }
}

function ConvertFrom-WpdPowercfgOutput {
    <#
    .SYNOPSIS
        Parse powercfg output (active scheme, or the sleep-state report).

    .DESCRIPTION
        A report whose expected line is missing is reported unavailable with a
        reason: an absent line never becomes an empty success.
    #>
    [CmdletBinding()]
    param(
        [Alias('Text')]
        [AllowNull()] [string[]] $Lines,
        [string] $Kind = 'active-scheme'
    )

    $normalizedKind = [string]$Kind
    if ($normalizedKind -notin @('active-scheme', 'sleep-states')) {
        throw [System.ArgumentException]::new("unknown powercfg view '$Kind'; valid values are active-scheme, sleep-states")
    }

    if ($normalizedKind -eq 'active-scheme') {
        foreach ($raw in @($Lines)) {
            $line = [string]$raw
            $match = [regex]::Match($line, 'Power Scheme GUID:\s*([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\s*(\((.+)\))?')
            if ($match.Success) {
                return [pscustomobject]@{
                    kind        = 'power-active-scheme'
                    guid        = $match.Groups[1].Value.ToLowerInvariant()
                    name        = $match.Groups[3].Value
                    source      = 'powercfg /getactivescheme'
                    schemeCount = 1
                }
            }
        }

        return (New-WpdInventoryProviderResult -Status 'unavailable' -Reason 'active-scheme-line-not-found' -Items @() -Source 'powercfg /getactivescheme')
    }

    $available = @()
    $unavailable = @()
    $mode = 'unknown'

    foreach ($raw in @($Lines)) {
        $line = [string]$raw
        if ($line.Trim().Length -eq 0) { continue }

        if ($line -match 'following sleep states are available') {
            $mode = 'available'
            continue
        }
        if ($line -match 'following sleep states are not available') {
            $mode = 'unavailable'
            continue
        }

        $indent = $line.Length - $line.TrimStart().Length
        $trimmed = $line.Trim()

        if ($indent -ge 8) {
            if ($mode -eq 'unavailable' -and $unavailable.Count -gt 0) {
                $unavailable[$unavailable.Count - 1].reason = $trimmed
            }
            continue
        }

        if ($indent -ge 4) {
            if ($mode -eq 'available') {
                $available += $trimmed
            }
            elseif ($mode -eq 'unavailable') {
                $unavailable += [pscustomobject]@{ state = $trimmed; reason = $null }
            }
            continue
        }
    }

    if ($available.Count -eq 0 -and $unavailable.Count -eq 0) {
        return (New-WpdInventoryProviderResult -Status 'unavailable' -Reason 'sleep-state-lines-not-found' -Items @() -Source 'powercfg /a')
    }

    return [pscustomobject]@{
        kind          = 'power-sleep-states'
        source        = 'powercfg /a'
        available     = $available
        unavailable   = $unavailable
        parseWarnings = @()
    }
}

function ConvertFrom-WpdBitLockerStatusOutput {
    <#
    .SYNOPSIS
        Parse 'manage-bde -status' output into one record per volume.
    #>
    [CmdletBinding()]
    param([AllowNull()] [string[]] $Lines)

    $volumes = @()
    $warnings = @()
    $current = $null

    $fieldMap = [ordered]@{
        'BitLocker Version'    = 'bitLockerVersion'
        'Conversion Status'    = 'conversionStatus'
        'Percentage Encrypted' = 'encryptionPercentage'
        'Protection Status'    = 'protectionStatus'
        'Lock Status'          = 'lockStatus'
        'Identification Field' = 'identificationField'
    }

    foreach ($raw in @($Lines)) {
        $line = [string]$raw
        if ($line.Trim().Length -eq 0) { continue }

        $volumeMatch = [regex]::Match($line, '^\s*Volume\s+([A-Za-z]:)')
        if ($volumeMatch.Success) {
            if ($null -ne $current) { $volumes += [pscustomobject]$current }
            $current = [ordered]@{
                kind                 = 'bitlocker-volume'
                volume               = $volumeMatch.Groups[1].Value
                source               = 'manage-bde -status'
                bitLockerVersion     = $null
                conversionStatus     = $null
                encryptionPercentage = $null
                protectionStatus     = $null
                lockStatus           = $null
                identificationField  = $null
                keyProtectors        = @()
            }
            continue
        }

        if ($null -eq $current) { continue }

        $keyProtectorMatch = [regex]::Match($line, '^\s*Key Protectors:\s*(.+?)\s*$')
        if ($keyProtectorMatch.Success) {
            $current['keyProtectors'] = @($keyProtectorMatch.Groups[1].Value -split '\s*,\s*' | Where-Object { $_.Trim().Length -gt 0 })
            continue
        }

        foreach ($label in @($fieldMap.Keys)) {
            $fieldMatch = [regex]::Match($line, '^\s*' + [regex]::Escape($label) + ':\s*(.+?)\s*$')
            if (-not $fieldMatch.Success) { continue }

            $value = $fieldMatch.Groups[1].Value
            $target = [string]$fieldMap[$label]

            if ($target -eq 'encryptionPercentage') {
                $percentMatch = [regex]::Match($value, '([0-9]+(\.[0-9]+)?)')
                if ($percentMatch.Success) {
                    $current[$target] = [double]$percentMatch.Groups[1].Value
                }
                else {
                    $warnings += ('volume {0}: percentage encrypted value not parsed' -f $current['volume'])
                }
            }
            else {
                $current[$target] = $value
            }
            break
        }
    }

    if ($null -ne $current) { $volumes += [pscustomobject]$current }

    if ($volumes.Count -eq 0) {
        $warnings += 'no volume section found in manage-bde -status output'
    }

    return [pscustomobject]@{
        kind          = 'bitlocker-status'
        source        = 'manage-bde -status'
        volumeCount   = $volumes.Count
        volumes       = $volumes
        parseWarnings = $warnings
    }
}

function ConvertFrom-WpdFsutilTrimOutput {
    <#
    .SYNOPSIS
        Parse 'fsutil behavior query DisableDeleteNotify' into TRIM state.

    .DESCRIPTION
        DisableDeleteNotify = 0 means TRIM is enabled. A file system whose line
        is absent yields a null state plus a warning, and a report with no
        recognised line at all is unavailable.
    #>
    [CmdletBinding()]
    param([AllowNull()] [string[]] $Lines)

    $ntfs = $null
    $refs = $null

    foreach ($raw in @($Lines)) {
        $line = [string]$raw
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $ntfsMatch = [regex]::Match($line, '^\s*NTFS\s+DisableDeleteNotify\s*=\s*(\d+)')
        if ($ntfsMatch.Success) {
            $ntfs = [int]$ntfsMatch.Groups[1].Value
            continue
        }

        $refsMatch = [regex]::Match($line, '^\s*ReFS\s+DisableDeleteNotify\s*=\s*(\d+)')
        if ($refsMatch.Success) {
            $refs = [int]$refsMatch.Groups[1].Value
        }
    }

    if ($null -eq $ntfs -and $null -eq $refs) {
        return (New-WpdInventoryProviderResult -Status 'unavailable' -Reason 'trim-state-line-not-found' -Items @() -Source 'fsutil behavior query DisableDeleteNotify')
    }

    $warnings = @()
    if ($null -eq $ntfs) { $warnings += 'NTFS DisableDeleteNotify line not found' }
    if ($null -eq $refs) { $warnings += 'ReFS DisableDeleteNotify line not found' }

    $ntfsEnabled = $null
    if ($null -ne $ntfs) { $ntfsEnabled = ($ntfs -eq 0) }

    $refsEnabled = $null
    if ($null -ne $refs) { $refsEnabled = ($refs -eq 0) }

    return [pscustomobject]@{
        kind                    = 'trim-state'
        source                  = 'fsutil behavior query DisableDeleteNotify'
        ntfsDisableDeleteNotify = $ntfs
        refsDisableDeleteNotify = $refs
        ntfsTrimEnabled         = $ntfsEnabled
        refsTrimEnabled         = $refsEnabled
        parseWarnings           = $warnings
    }
}

function ConvertTo-WpdStorageReliabilityRecord {
    <#
    .SYNOPSIS
        Normalize one Get-StorageReliabilityCounter result.

    .DESCRIPTION
        A disk that exposes no reliability counter is recorded as not exposed
        with a note and null values: no wear, temperature or error value is ever
        invented, because the counter set publishes no default (R2).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] $Counters,
        [AllowEmptyString()] [string] $DeviceId
    )

    $record = [ordered]@{
        kind                 = 'storage-reliability'
        deviceId             = $DeviceId
        source               = 'Get-StorageReliabilityCounter'
        exposed              = ($null -ne $Counters)
        note                 = $null
        wear                 = $null
        temperatureCelsius   = $null
        readErrorsTotal      = $null
        readErrorsUncorrected = $null
        writeErrorsTotal     = $null
        writeErrorsUncorrected = $null
        powerOnHours         = $null
        startStopCycleCount  = $null
        loadUnloadCycleCount = $null
    }

    if ($null -eq $Counters) {
        $record['note'] = 'reliability-counter-not-exposed'
        return [pscustomobject]$record
    }

    $record['wear'] = Get-WpdInventoryProperty -InputObject $Counters -Name 'Wear'
    $record['temperatureCelsius'] = Get-WpdInventoryProperty -InputObject $Counters -Name 'Temperature'
    $record['readErrorsTotal'] = Get-WpdInventoryProperty -InputObject $Counters -Name 'ReadErrorsTotal'
    $record['readErrorsUncorrected'] = Get-WpdInventoryProperty -InputObject $Counters -Name 'ReadErrorsUncorrected'
    $record['writeErrorsTotal'] = Get-WpdInventoryProperty -InputObject $Counters -Name 'WriteErrorsTotal'
    $record['writeErrorsUncorrected'] = Get-WpdInventoryProperty -InputObject $Counters -Name 'WriteErrorsUncorrected'
    $record['powerOnHours'] = Get-WpdInventoryProperty -InputObject $Counters -Name 'PowerOnHours'
    $record['startStopCycleCount'] = Get-WpdInventoryProperty -InputObject $Counters -Name 'StartStopCycleCount'
    $record['loadUnloadCycleCount'] = Get-WpdInventoryProperty -InputObject $Counters -Name 'LoadUnloadCycleCount'

    return [pscustomobject]$record
}

function ConvertTo-WpdVirtualizationContext {
    <#
    .SYNOPSIS
        Build the virtualization/VBS context from Win32_ComputerSystem and
        root/Microsoft/Windows/DeviceGuard.

    .DESCRIPTION
        Only the documented SecurityServicesRunning values are named; an
        undocumented value is reported as unknown-<n> with a warning instead of
        being guessed. A missing Win32_DeviceGuard class is 'not-exposed', never
        'disabled': absence of the class is not evidence that VBS is off.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] $ComputerSystem,
        [AllowNull()] $DeviceGuard
    )

    $warnings = @()
    $services = @()
    $configured = @()
    $vbsStatus = 'not-exposed'
    $note = $null
    $codeIntegrityEnforced = $null
    $properties = @()

    $serviceNames = @{
        1 = 'Credential Guard'
        2 = 'HVCI'
        3 = 'System Guard Secure Launch'
    }

    if ($null -eq $DeviceGuard) {
        $note = 'device-guard-class-not-exposed'
    }
    else {
        $rawStatus = Get-WpdInventoryProperty -InputObject $DeviceGuard -Name 'VirtualizationBasedSecurityStatus'
        switch ([string]$rawStatus) {
            '0' { $vbsStatus = 'disabled' }
            '1' { $vbsStatus = 'enabled-not-running' }
            '2' { $vbsStatus = 'running' }
            default {
                $vbsStatus = "unknown-$rawStatus"
                $warnings += "undocumented VirtualizationBasedSecurityStatus value $rawStatus"
            }
        }

        foreach ($value in @(Get-WpdInventoryProperty -InputObject $DeviceGuard -Name 'SecurityServicesRunning')) {
            $name = [string]$serviceNames[[int]$value]
            if ([string]::IsNullOrWhiteSpace($name)) {
                $services += "unknown-$value"
                $warnings += "undocumented SecurityServicesRunning value $value; reported as unknown-$value"
            }
            else {
                $services += $name
            }
        }

        foreach ($value in @(Get-WpdInventoryProperty -InputObject $DeviceGuard -Name 'SecurityServicesConfigured')) {
            $name = [string]$serviceNames[[int]$value]
            if ([string]::IsNullOrWhiteSpace($name)) {
                $configured += "unknown-$value"
            }
            else {
                $configured += $name
            }
        }

        foreach ($value in @(Get-WpdInventoryProperty -InputObject $DeviceGuard -Name 'AvailableSecurityProperties')) {
            $properties += [int]$value
        }

        $enforcement = Get-WpdInventoryProperty -InputObject $DeviceGuard -Name 'CodeIntegrityPolicyEnforcementStatus'
        if ($null -ne $enforcement) {
            $codeIntegrityEnforced = ([int]$enforcement -eq 2)
        }
    }

    return [pscustomobject]@{
        kind                          = 'virtualization-context'
        source                        = 'Win32_ComputerSystem; Win32_DeviceGuard'
        hypervisorPresent             = [bool](Get-WpdInventoryProperty -InputObject $ComputerSystem -Name 'HypervisorPresent')
        vbsStatus                     = $vbsStatus
        note                          = $note
        securityServicesRunning       = $services
        securityServicesConfigured    = $configured
        availableSecurityProperties   = $properties
        codeIntegrityPolicyEnforced   = $codeIntegrityEnforced
        warnings                      = $warnings
    }
}

function ConvertTo-WpdStartupEntry {
    <#
    .SYNOPSIS
        Normalize one auto-start entry (registry, startup folder, task, service).

    .DESCRIPTION
        Presence in an auto-start location is inventory, not evidence of cost or
        of necessity (platform section 10 [39]), so an entry keeps its source and
        location and is never judged here. At the Redacted level the command line
        is suppressed.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()] [string] $Source,
        [AllowEmptyString()] [string] $Location,
        [AllowEmptyString()] [string] $Name,
        [AllowNull()] [string] $Command,
        [AllowEmptyString()] [string] $Level
    )

    $level = Get-WpdInventoryPrivacyLevel -Level $Level

    $record = [ordered]@{
        kind     = 'startup-entry'
        source   = $Source
        location = $Location
        name     = $Name
        command  = $Command
        enabled  = $true
        level    = $level
    }

    if ($level -eq 'Redacted') {
        $record['command'] = $null
    }

    return [pscustomobject]$record
}

Export-ModuleMember -Function @(
    'Clear-WpdInventoryCache',
    'ConvertFrom-WpdBitLockerStatusOutput',
    'ConvertFrom-WpdFltmcFilterOutput',
    'ConvertFrom-WpdFltmcInstanceOutput',
    'ConvertFrom-WpdFsutilTrimOutput',
    'ConvertFrom-WpdPowercfgOutput',
    'ConvertTo-WpdStartupEntry',
    'ConvertTo-WpdStorageReliabilityRecord',
    'ConvertTo-WpdVirtualizationContext',
    'Get-WpdInventory',
    'Get-WpdInventoryCache',
    'Get-WpdInventoryCapability',
    'Get-WpdInventoryCapabilityMap',
    'Get-WpdInventoryDefaultProviders',
    'Get-WpdInventoryPrivacyLevel',
    'Invoke-WpdInventoryCapability',
    'New-WpdInventoryProviderResult',
    'Protect-WpdInventoryRecord',
    'Test-WpdInventoryCommandPresence',
    'Test-WpdInventoryForbiddenField',
    'Test-WpdInventoryWindowsHost'
)
