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

    [ValidateSet('GeneralProfile', 'CPU', 'DiskIO', 'FileIO', 'Network', 'Power', 'GPU', 'Registry')]
    [string]$WprProfile = 'GeneralProfile',

    [switch]$CaptureDefender,

    [switch]$ConfirmDefenderCapture,

    [switch]$CollectMinidumps,

    [switch]$ConfirmMinidumpCollection,

    [switch]$CollectBootFailureLogs,

    [switch]$ConfirmBootFailureLogCollection,

    [switch]$ZipOutput,

    [string]$RemoteComputer,

    [string]$RemoteOutputDirectory,

    [System.Management.Automation.PSCredential]$Credential,

    [switch]$ConfirmRemoteCollection
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Single source of truth for the version is the VERSION file at the repo/bundle
# root; the constant below is only a fallback for standalone copies of the
# script (e.g. CI staging copies) - test_version_file_matches_script_fallback
# keeps the two in sync so drift fails CI.
$script:ScriptVersion = '0.7.0'
try {
    $script:ScriptVersion = (Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\VERSION') -ErrorAction Stop | Select-Object -First 1).Trim()
}
catch {
    # VERSION file not present (standalone copy) - fallback constant above
}

# Bounds for the consent-gated crash-evidence stages (advertised in Plan mode,
# enforced in Collect mode). Minidumps are typically <1 MB; MEMORY.DMP is
# recorded as metadata only and never copied.
$script:MaxMinidumpTotalBytes = 512MB
$script:MaxBootFailureLogBytes = 100MB

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # Explicit UTF-8 WITHOUT BOM: Windows PowerShell 5.1's Set-Content -Encoding
    # UTF8 writes a BOM while pwsh 7 does not, so manifests would differ by
    # engine. WriteAllText with UTF8Encoding($false) makes the JSON contract
    # byte-identical on both.
    $json = $InputObject | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-UtcTimestamp {
    return (Get-Date).ToUniversalTime().ToString('o')
}

function Get-ArtifactMetadata {
    <#
      Hashes ONLY the artifacts written during this run (Names whitelist).
      The output directory may contain stale files from earlier runs when a
      launcher reuses the same folder - certifying those would corrupt the
      SHA-256 trust anchor, so only tracked writes are listed.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory,

        [string[]]$Names = @()
    )

    $artifacts = @()
    foreach ($name in $Names) {
        $path = Join-Path -Path $Directory -ChildPath $name
        if (Test-Path -LiteralPath $path) {
            $item = Get-Item -LiteralPath $path
            $artifacts += [pscustomobject]@{
                Name = $name
                SizeBytes = $item.Length
                Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            }
        }
    }
    return $artifacts
}

function New-CasePackage {
    <#
      Zips EXACTLY the named relative files (this run's whitelisted artifacts
      plus the manifest) into a timestamped zip in the destination directory.
      Stale files in a reused output folder are never included - the zip
      certifies only this run's evidence. Pure file operation (Linux-testable);
      Collect mode calls it after the manifest is written, then records the
      package block back into the manifest on disk.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory,

        [Parameter(Mandatory = $true)]
        [string[]]$RelativeNames,

        [Parameter(Mandatory = $true)]
        [string]$DestinationDirectory,

        [Parameter(Mandatory = $true)]
        [string]$LeafName
    )

    $packageStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss')
    $packagePath = Join-Path -Path $DestinationDirectory -ChildPath "$LeafName-$packageStamp.zip"
    if (Test-Path -LiteralPath $packagePath) {
        throw "Case package already exists: $packagePath"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $packageFileStream = [System.IO.File]::Open($packagePath, [System.IO.FileMode]::Create)
    try {
        $packageArchive = New-Object System.IO.Compression.ZipArchive($packageFileStream, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($relativeName in $RelativeNames) {
                $sourceFile = Join-Path -Path $Directory -ChildPath $relativeName
                if (-not (Test-Path -LiteralPath $sourceFile)) {
                    continue
                }
                $entry = $packageArchive.CreateEntry($relativeName.Replace('\', '/'), [System.IO.Compression.CompressionLevel]::Optimal)
                $entryStream = $entry.Open()
                try {
                    $inputStream = [System.IO.File]::OpenRead($sourceFile)
                    try {
                        $inputStream.CopyTo($entryStream)
                    }
                    finally {
                        $inputStream.Dispose()
                    }
                }
                finally {
                    $entryStream.Dispose()
                }
            }
        }
        finally {
            $packageArchive.Dispose()
        }
    }
    finally {
        $packageFileStream.Dispose()
    }

    return $packagePath
}

function Add-CasePackageBlock {
    <#
      Zips the given artifact names + the manifest into a case package and
      records the 'package' block on the manifest object (mutated in place -
      [ordered] dictionaries and PSCustomObjects are both reference types).
      Shared by the local and the remote collect paths.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$CollectionManifest,

        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory,

        [string[]]$ArtifactNames = @()
    )

    try {
        $packageParent = Split-Path -Parent $OutputDirectory
        $packageLeaf = Split-Path -Leaf $OutputDirectory
        if (-not $packageLeaf) {
            $packageLeaf = 'wpd-case'
        }
        $packageRelativeNames = @($ArtifactNames) + @('diagnostic-manifest.json')
        $packagePath = New-CasePackage `
            -Directory $OutputDirectory `
            -RelativeNames $packageRelativeNames `
            -DestinationDirectory $packageParent `
            -LeafName $packageLeaf
        $packageItem = Get-Item -LiteralPath $packagePath
        $CollectionManifest.package = [ordered]@{
            enabled = $true
            status = 'completed'
            zipPath = $packagePath
            sizeBytes = $packageItem.Length
            sha256 = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
            includesManifest = $true
        }
    }
    catch {
        Add-CollectionError -Stage 'case-package' -ErrorRecord $_
        $CollectionManifest.package = [ordered]@{
            enabled = $true
            status = 'failed'
        }
    }
    return $CollectionManifest
}

function Invoke-ConsentedCapture {
    <#
      Shared skeleton for the WPR and Defender capture stages: readiness
      check -> elevation check -> capture body -> status/error recording.
      The per-stage differences (tool/module lookup, the capture call,
      exit-code/version details) live in the scriptblocks; the skip
      statuses, collectionErrors stage names, and error messages stay
      identical to the pre-refactor behavior (live-gated by WPD-08/09/10).
      Returns an [ordered] dict whose union of result fields is all
      initialized, so StrictMode never trips on a missing key.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$StageName,

        [Parameter(Mandatory = $true)]
        [string]$SkipStatusNotReady,

        [Parameter(Mandatory = $true)]
        [string]$NotReadyMessage,

        [Parameter(Mandatory = $true)]
        [string]$NotReadyErrorId,

        [Parameter(Mandatory = $true)]
        [string]$ElevationMessage,

        [Parameter(Mandatory = $true)]
        [string]$ElevationErrorId,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ReadyCheck,

        [Parameter(Mandatory = $true)]
        [scriptblock]$CaptureBody
    )

    $result = [ordered]@{
        status = $SkipStatusNotReady
        etlFilePath = $null
        startedAtUtc = $null
        completedAtUtc = $null
        startExitCode = $null
        stopExitCode = $null
        moduleVersion = $null
    }
    try {
        if (-not (& $ReadyCheck)) {
            Add-CollectionError -Stage $StageName -ErrorRecord ([System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new($NotReadyMessage),
                $NotReadyErrorId,
                [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                $null
            ))
        }
        else {
            $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isElevated) {
                Add-CollectionError -Stage $StageName -ErrorRecord ([System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new($ElevationMessage),
                    $ElevationErrorId,
                    [System.Management.Automation.ErrorCategory]::PermissionDenied,
                    $null
                ))
                $result.status = 'skipped-elevation-required'
            }
            else {
                $captureResult = & $CaptureBody
                foreach ($key in $captureResult.Keys) {
                    $result[$key] = $captureResult[$key]
                }
            }
        }
    }
    catch {
        Add-CollectionError -Stage $StageName -ErrorRecord $_
        $result.status = 'failed'
    }
    return $result
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

# Keywords for spotting VPN/filter/firewall/EDR/AV software by process name or
# install entry. Grouped by category so it is easy to extend when a new case
# turns up a product this list does not catch yet (e.g. the CrowdStrike+McAfee
# case, 2026-08-19 - the original list only covered consumer VPN/ad-filter
# names and missed both entirely).
$script:SecuritySoftwareKeywords = @(
    # EDR / endpoint AV (enterprise + consumer)
    'crowdstrike', 'falcon', 'mcafee', 'huntress', 'sentinelone', 'sentinel one', 'sophos',
    'carbonblack', 'carbon black', 'cylance', 'cybereason', 'tanium', 'deep instinct',
    'harfanglab', 'qualys', 'rapid7', 'malwarebytes', 'webroot', 'bitdefender', 'kaspersky',
    'avast', 'avg', 'f-secure', 'trendmicro', 'trend micro', 'symantec', 'norton', 'eset',
    'nod32', 'windows defender atp', 'microsoft defender for endpoint', 'cortex xdr',
    'palo alto',
    # DNS / content / web filtering
    'opendns', 'umbrella', 'dnsfilter', 'cleanbrowsing', 'netfree', 'techloq', 'circle',
    'net nanny', 'covenant eyes', 'x3watch', 'k9 web',
    # Firewall / proxy / VPN
    'vpn', 'proxy', 'firewall', 'fortinet', 'forticlient', 'checkpoint', 'check point',
    'globalprotect', 'pulse secure', 'anyconnect', 'sonicwall', 'cyberoam', 'zscaler',
    'forcepoint', 'barracuda', 'watchguard', 'netlimiter', 'pihole', 'adguard',
    'nordvpn', 'expressvpn', 'openvpn', 'wireguard', 'tailscale'
)

function Test-SecuritySoftwareMatch {
    <#
      Pure predicate used by the security-software inventory: true when the
      process/install name or company mentions a known EDR/AV, DNS-filter,
      firewall, proxy, or VPN product. Case-insensitive substring matching.
    #>
    param(
        [AllowNull()]
        [string]$Name,

        [AllowNull()]
        [string]$Company
    )

    $haystack = "$Name $Company".ToLowerInvariant()
    foreach ($keyword in $script:SecuritySoftwareKeywords) {
        if ($haystack.Contains($keyword.ToLowerInvariant())) {
            return $true
        }
    }
    return $false
}

function Get-PropertyValue {
    <#
      StrictMode-safe property read: returns $null when the object has no such
      property instead of throwing (registry Uninstall keys are sparse - many
      lack DisplayName/Publisher/InstallDate).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }
    return $null
}

function Get-NetworkState {
    <#
      Read-only network-state snapshot (pattern adopted from the field-tested
      RemoteDiagnostics capture-network-state.ps1). Captures the live network
      picture that disappears on reboot: IP configuration, adapter status,
      DNS servers/cache, routes, ARP, a DNS-vs-ping split test (raw-IP ping
      reachability versus name resolution - the classic discriminator between
      "DNS is broken" and "the network is down"), hosts-file entries, proxy
      settings, active TCP connections, and a security/VPN/filtering software
      inventory. No admin rights required; every section is independently
      guarded so one failure never loses the rest.
      Returns [pscustomobject]@{ State = <ordered dict>; Errors = @(...) }.
    #>

    $errors = @()
    $state = [ordered]@{}

    $state['capturedAtUtc'] = Get-UtcTimestamp
    $state['computerName'] = $env:COMPUTERNAME

    try {
        $state['ipConfigAll'] = ((ipconfig /all) -join "`n")
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'ipconfig'; Message = $_.Exception.Message }
    }

    try {
        $state['adapters'] = @(
            Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress
        )
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'adapters'; Message = $_.Exception.Message }
    }

    try {
        $state['connectionProfiles'] = @(
            Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity
        )
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'connection-profiles'; Message = $_.Exception.Message }
    }

    try {
        $state['dnsServerAddresses'] = @(
            Get-DnsClientServerAddress | Select-Object InterfaceAlias, AddressFamily, ServerAddresses
        )
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'dns-servers'; Message = $_.Exception.Message }
    }

    try {
        $state['dnsClientCache'] = @(
            Get-DnsClientCache | Select-Object -First 50 Entry, Name, Data, Status
        )
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'dns-cache'; Message = $_.Exception.Message }
    }

    try {
        $state['ipv4Routes'] = @(
            Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric
        )
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'routes'; Message = $_.Exception.Message }
    }

    try {
        $state['arpTable'] = ((arp -a) -join "`n")
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'arp'; Message = $_.Exception.Message }
    }

    # DNS-vs-ping split test: reach a public IP by raw address (link/routing
    # without DNS) and resolve public names (DNS). The combination tells the
    # technician whether the outage is in connectivity or in name resolution.
    # Probes are hard-timeout bounded (.NET Ping 2s; GetHostAddresses resolver
    # timeout) - Test-Connection/Resolve-DnsName can block for minutes when
    # ICMP/DNS is silently dropped (observed in batch-logon standard-user
    # sessions on CI runners).
    $pingTargets = @('8.8.8.8', '1.1.1.1')
    $pingResults = @()
    foreach ($target in $pingTargets) {
        $ping = New-Object System.Net.NetworkInformation.Ping
        try {
            $reply = $ping.Send($target, 2000)
            $pingResults += [pscustomobject]@{
                Target = $target
                Reachable = ($null -ne $reply -and $reply.Status -eq 'Success')
                ReplyCount = 1
            }
        }
        catch {
            $pingResults += [pscustomobject]@{
                Target = $target
                Reachable = $false
                ReplyCount = 0
                Error = $_.Exception.Message
            }
        }
        finally {
            $ping.Dispose()
        }
    }

    $dnsTargets = @('google.com', 'cloudflare.com', 'microsoft.com')
    $dnsResults = @()
    foreach ($domain in $dnsTargets) {
        try {
            $resolvedIps = @(
                [System.Net.Dns]::GetHostAddresses($domain) |
                    ForEach-Object { $_.IPAddressToString }
            )
            $dnsResults += [pscustomobject]@{
                Domain = $domain
                Resolved = ($resolvedIps.Count -gt 0)
                IpAddresses = @($resolvedIps)
            }
        }
        catch {
            $dnsResults += [pscustomobject]@{
                Domain = $domain
                Resolved = $false
                IpAddresses = @()
                Error = $_.Exception.Message
            }
        }
    }

    $rawIpReachable = @($pingResults | Where-Object { $_.Reachable }).Count -gt 0
    $dnsResolutionOk = @($dnsResults | Where-Object { $_.Resolved }).Count -gt 0
    $verdict = 'inconclusive'
    if ($rawIpReachable -and $dnsResolutionOk) {
        $verdict = 'dns-and-connectivity-ok'
    }
    elseif ($rawIpReachable -and -not $dnsResolutionOk) {
        $verdict = 'dns-failure'
    }
    elseif (-not $rawIpReachable -and $dnsResolutionOk) {
        $verdict = 'icmp-blocked-or-partial'
    }
    else {
        $verdict = 'connectivity-failure'
    }

    $state['dnsVsPing'] = [ordered]@{
        rawIpPing = @($pingResults)
        dnsResolution = @($dnsResults)
        rawIpReachable = $rawIpReachable
        dnsResolutionOk = $dnsResolutionOk
        verdict = $verdict
    }

    try {
        $hostsPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\drivers\etc\hosts'
        $activeEntries = @()
        if (Test-Path -LiteralPath $hostsPath) {
            $activeEntries = @(
                Get-Content -LiteralPath $hostsPath |
                    Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }
            )
        }
        $state['hostsFile'] = [ordered]@{
            path = $hostsPath
            activeEntryCount = $activeEntries.Count
            activeEntries = $activeEntries
        }
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'hosts-file'; Message = $_.Exception.Message }
    }

    try {
        $winhttpProxy = ((netsh winhttp show proxy) -join "`n")
        $ieProxy = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue |
            Select-Object ProxyEnable, ProxyServer, AutoConfigURL
        $state['proxySettings'] = [ordered]@{
            winhttpProxy = $winhttpProxy
            internetSettings = @($ieProxy)
        }
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'proxy'; Message = $_.Exception.Message }
    }

    try {
        # netstat -ano instead of Get-NetTCPConnection: the cmdlet enumerates
        # per-connection owning processes and can take minutes for a restricted
        # token (batch-logon standard user); netstat is native and instant.
        $tcpConnections = @(
            (& netstat -ano) | Where-Object { $_ -match '^\s*TCP' } | ForEach-Object {
                $parts = @(($_ -split '\s+') | Where-Object { $_ })
                if ($parts.Count -ge 5) {
                    [pscustomobject]@{
                        LocalAddress = $parts[1]
                        LocalPort = ($parts[1] -split ':')[-1]
                        RemoteAddress = $parts[2]
                        RemotePort = ($parts[2] -split ':')[-1]
                        State = $parts[3]
                        OwningProcess = $parts[4]
                    }
                }
            } | Where-Object { $_.State -in @('ESTABLISHED', 'LISTENING') } | Sort-Object LocalPort
        )
        $state['tcpConnections'] = $tcpConnections
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'tcp-connections'; Message = $_.Exception.Message }
    }

    try {
        $allProcesses = @(Get-Process | Sort-Object Name | Select-Object Name, Id, Company)
        $securityProcesses = @(
            $allProcesses | Where-Object { Test-SecuritySoftwareMatch -Name $_.Name -Company $_.Company }
        )

        $uninstallPaths = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $installedSecuritySoftware = @(
            Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
                Where-Object {
                    Test-SecuritySoftwareMatch `
                        -Name (Get-PropertyValue -InputObject $_ -Name 'DisplayName') `
                        -Company (Get-PropertyValue -InputObject $_ -Name 'Publisher')
                } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        )

        $state['securitySoftware'] = [ordered]@{
            keywordList = @($script:SecuritySoftwareKeywords)
            processMatches = @($securityProcesses)
            installedSoftwareMatches = @($installedSecuritySoftware)
        }
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'security-software'; Message = $_.Exception.Message }
    }

    $state['sectionErrors'] = @($errors)

    return [pscustomobject]@{
        State = $state
        Errors = @($errors)
    }
}

try {
    $resolvedOutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
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
        'collect-network-state-after-explicit-consent',
        'export-bounded-system-event-summary-after-explicit-consent',
        'analyze-crash-evidence-after-explicit-consent',
        'write-local-artifact-hashes-after-explicit-consent'
    )
    network = [ordered]@{
        subCollections = @(
            'ip-configuration',
            'adapter-status',
            'connection-profiles',
            'dns-server-configuration',
            'dns-client-cache',
            'ipv4-routing-table',
            'arp-table',
            'dns-vs-ping-split-test',
            'hosts-file',
            'proxy-settings',
            'tcp-connections',
            'security-software-inventory'
        )
    }
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

$minidumpSourcePath = if ($env:SystemRoot) { Join-Path $env:SystemRoot 'Minidump' } else { 'C:\Windows\Minidump' }

if ($CollectMinidumps) {
    $planManifest.plannedActions += 'collect-minidumps-after-explicit-consent'
    $planManifest.minidumps = [ordered]@{
        sourcePath = $minidumpSourcePath
        maxTotalBytes = $script:MaxMinidumpTotalBytes
        memoryDumpRecordedNotCopied = $true
    }
}

if ($CollectBootFailureLogs) {
    $planManifest.plannedActions += 'collect-boot-failure-evidence-after-explicit-consent'
    $planManifest.bootFailureLogs = [ordered]@{
        maxBytesPerFile = $script:MaxBootFailureLogBytes
        sources = @('srt-trail', 'boot-log', 'cbs-log', 'setupapi-panther', 'setupapi-error', 'dism-log')
    }
}

if ($ZipOutput) {
    # packaging is a local file operation on already-collected (consented)
    # artifacts - no separate consent gate, but it IS advertised in the plan
    $planManifest.plannedActions += 'package-local-case-folder-into-zip'
    $planManifest.package = [ordered]@{
        destination = (Split-Path -Parent $resolvedOutputDirectory)
        namePattern = '<output-leaf>-<UTC-stamp>.zip'
        includesManifest = $true
    }
}

if ($RemoteComputer) {
    # Remote mode changes the safety block: the collection runs on a remote
    # host over WinRM and the case folder is pulled back to THIS machine.
    # readOnly/automaticUpload/automaticRemediation/automaticLogClearing are
    # unchanged - the tool never enables WinRM, never mutates the target, and
    # the pull is consent-gated like every local write.
    $planManifest.plannedActions += 'collect-remotely-after-explicit-consent'
    $planManifest.safety.localOnly = $false
    $planManifest.safety.remoteTarget = $RemoteComputer
    $planManifest.safety.remoteTransport = 'winrm'
    $planManifest.remote = [ordered]@{
        computerName = $RemoteComputer
        transport = 'winrm'
    }
}

if ($Mode -eq 'Plan') {
    try {
        New-Item -ItemType Directory -Force -Path $resolvedOutputDirectory | Out-Null
    }
    catch {
        throw "OutputDirectory '$OutputDirectory' is not a valid local path: $($_.Exception.Message)"
    }
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

if (-not $ConfirmMinidumpCollection -and $CollectMinidumps) {
    throw 'Minidump collection requires -ConfirmMinidumpCollection. No diagnostic data was collected.'
}

if (-not $ConfirmBootFailureLogCollection -and $CollectBootFailureLogs) {
    throw 'Boot-failure log collection requires -ConfirmBootFailureLogCollection. No diagnostic data was collected.'
}

if (-not $ConfirmRemoteCollection -and $RemoteComputer) {
    throw 'Remote collection requires -ConfirmRemoteCollection. No diagnostic data was collected.'
}

if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'Collect mode is supported only on Windows. Use -Mode Plan for a non-collecting safety plan.'
}

# Consent gates passed: only now may the output directory be created, so a
# consent-refusing Collect leaves no side effects behind.
try {
    New-Item -ItemType Directory -Force -Path $resolvedOutputDirectory | Out-Null
}
catch {
    throw "OutputDirectory '$OutputDirectory' is not a valid local path: $($_.Exception.Message)"
}

$collectionErrors = @()
function Add-CollectionError {
    param([string]$Stage, [System.Management.Automation.ErrorRecord]$ErrorRecord)

    $script:collectionErrors += [pscustomobject]@{
        Stage = $Stage
        Message = $ErrorRecord.Exception.Message
    }
}

function Add-CollectionErrorText {
    param([string]$Stage, [string]$Message)

    $script:collectionErrors += [pscustomobject]@{
        Stage = $Stage
        Message = $Message
    }
}

if ($RemoteComputer) {
    # ---- Remote collection over WinRM (remote-exec, pull-back, verified) ----
    # The existing collector runs ON the target (stages execute locally there,
    # same consent gates, same skip semantics); the case folder is pulled back
    # and every pulled file's SHA-256 is verified against the remote manifest
    # before the local manifest is written. WinRM is never enabled by this
    # tool - Test-WSMan only reports availability.
    $remoteStatus = 'failed'
    $remoteWinrmStatus = 'failed-winrm-unavailable'
    $remoteOutDir = $null
    $remotePulledFileCount = 0
    $remoteVerifiedCount = 0
    $remoteHashVerificationFailed = $false
    $remoteStartedAtUtc = Get-UtcTimestamp
    $remotePulledManifest = $null
    $session = $null
    try {
        $wsmanParams = @{ ComputerName = $RemoteComputer; ErrorAction = 'Stop' }
        if ($Credential) {
            $wsmanParams.Credential = $Credential
        }
        $null = Test-WSMan @wsmanParams
        $remoteWinrmStatus = 'ok'

        $session = New-PSSession @wsmanParams
        if ($RemoteOutputDirectory) {
            $remoteOutDir = $RemoteOutputDirectory
        }
        else {
            $remoteOutDir = (Invoke-Command -Session $session -ScriptBlock { Join-Path $env:TEMP 'WPD-Remote-Case' })
        }
        $remoteScriptPath = Join-Path $remoteOutDir 'Invoke-WindowsPerformanceDiagnostics.ps1'
        Invoke-Command -Session $session -ScriptBlock {
            param($dir)
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
        } -ArgumentList $remoteOutDir
        Copy-Item -ToSession $session -Path $MyInvocation.MyCommand.Path -Destination $remoteScriptPath -Force

        # Named-parameter hashtable: splatting a string ARRAY would pass the
        # elements positionally ("-Mode" would bind to $Mode and fail the
        # ValidateSet) - a hashtable splat binds real parameter names.
        $remoteParams = @{
            Mode = 'Collect'
            ConfirmLocalCollection = $true
            OutputDirectory = $remoteOutDir
            DurationSeconds = $DurationSeconds
        }
        if ($CaptureWpr) {
            $remoteParams.CaptureWpr = $true
            $remoteParams.ConfirmWprCapture = $true
            $remoteParams.WprProfile = $WprProfile
        }
        if ($CaptureDefender) {
            $remoteParams.CaptureDefender = $true
            $remoteParams.ConfirmDefenderCapture = $true
        }
        if ($CollectMinidumps) {
            $remoteParams.CollectMinidumps = $true
            $remoteParams.ConfirmMinidumpCollection = $true
        }
        if ($CollectBootFailureLogs) {
            $remoteParams.CollectBootFailureLogs = $true
            $remoteParams.ConfirmBootFailureLogCollection = $true
        }

        Invoke-Command -Session $session -ScriptBlock {
            param($scriptPath, $invokeParams)
            & $scriptPath @invokeParams
        } -ArgumentList $remoteScriptPath, $remoteParams

        $remoteManifestPath = Join-Path $remoteOutDir 'diagnostic-manifest.json'
        $localManifestPath = Join-Path $resolvedOutputDirectory 'diagnostic-manifest.json'
        Copy-Item -FromSession $session -Path $remoteManifestPath -Destination $localManifestPath -Force
        $remotePulledManifest = Get-Content -LiteralPath $localManifestPath -Raw | ConvertFrom-Json

        foreach ($artifact in @($remotePulledManifest.artifacts)) {
            $remoteArtifactPath = Join-Path $remoteOutDir $artifact.Name
            $localArtifactPath = Join-Path $resolvedOutputDirectory $artifact.Name
            $localArtifactDir = Split-Path -Parent $localArtifactPath
            if (-not (Test-Path -LiteralPath $localArtifactDir)) {
                New-Item -ItemType Directory -Force -Path $localArtifactDir | Out-Null
            }
            Copy-Item -FromSession $session -Path $remoteArtifactPath -Destination $localArtifactPath -Force
            $remotePulledFileCount++
            $localHash = (Get-FileHash -LiteralPath $localArtifactPath -Algorithm SHA256).Hash
            if ($localHash -eq $artifact.Sha256) {
                $remoteVerifiedCount++
            }
            else {
                $remoteHashVerificationFailed = $true
            }
        }
        $remoteStatus = 'completed'
    }
    catch {
        Add-CollectionError -Stage 'remote-collection' -ErrorRecord $_
        $remoteStatus = 'failed'
    }

    # cleanup: remove OUR remote staging dir + session (documented in the plan)
    if ($session) {
        try {
            if ($remoteOutDir) {
                Invoke-Command -Session $session -ScriptBlock {
                    param($dir)
                    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
                } -ArgumentList $remoteOutDir
            }
        }
        catch {
            Add-CollectionError -Stage 'remote-cleanup' -ErrorRecord $_
        }
        try {
            Remove-PSSession -Session $session
        }
        catch {
            Add-CollectionError -Stage 'remote-cleanup' -ErrorRecord $_
        }
    }

    if ($remotePulledManifest) {
        $collectionManifest = $remotePulledManifest
        $collectionManifest | Add-Member -NotePropertyName 'remote' -NotePropertyValue ([ordered]@{
            computerName = $RemoteComputer
            transport = 'winrm'
            winrmStatus = $remoteWinrmStatus
            remoteOutputDirectory = $remoteOutDir
            status = $remoteStatus
            pulledFileCount = $remotePulledFileCount
            verifiedSha256Count = $remoteVerifiedCount
            hashVerificationFailed = $remoteHashVerificationFailed
            pulledAtUtc = Get-UtcTimestamp
        }) -Force
    }
    else {
        # WinRM/session/manifest failed before anything was pulled: write a
        # minimal manifest so the failure is inspectable
        $collectionManifest = [ordered]@{
            schemaVersion = '1.0'
            toolName = 'Windows Performance Diagnostics Toolkit'
            toolVersion = $ScriptVersion
            mode = 'Collect'
            startedAtUtc = $remoteStartedAtUtc
            completedAtUtc = Get-UtcTimestamp
            outputDirectory = $resolvedOutputDirectory
            safety = $planManifest.safety
            remote = [ordered]@{
                computerName = $RemoteComputer
                transport = 'winrm'
                winrmStatus = $remoteWinrmStatus
                status = $remoteStatus
            }
            collectionErrors = $collectionErrors
            artifacts = @()
        }
    }

    $collectedArtifacts = New-Object System.Collections.ArrayList
    if ($remotePulledManifest) {
        foreach ($artifact in @($remotePulledManifest.artifacts)) {
            [void]$collectedArtifacts.Add($artifact.Name)
        }
    }

    $collectionManifestPath = Join-Path -Path $resolvedOutputDirectory -ChildPath 'diagnostic-manifest.json'
    Write-JsonFile -InputObject $collectionManifest -Path $collectionManifestPath
    if ($ZipOutput) {
        $collectionManifest = Add-CasePackageBlock -CollectionManifest $collectionManifest -OutputDirectory $resolvedOutputDirectory -ArtifactNames @($collectedArtifacts)
        Write-JsonFile -InputObject $collectionManifest -Path $collectionManifestPath
    }
    Write-Output "Remote collection complete. Manifest written to $collectionManifestPath"
    exit 0
}

$collectedArtifacts = New-Object System.Collections.ArrayList
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
$consecutiveSampleFailures = 0
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
        $consecutiveSampleFailures = 0
    }
    catch {
        Add-CollectionError -Stage 'performance-sample' -ErrorRecord $_
        $consecutiveSampleFailures++
        # one transient CIM failure must not empty the whole CSV; give up only
        # after several consecutive failures
        if ($consecutiveSampleFailures -ge 3) {
            break
        }
    }

    if ($sampleIndex -lt ($DurationSeconds - 1)) {
        Start-Sleep -Seconds 1
    }
}

try {
    $samples | Export-Csv -LiteralPath (Join-Path -Path $resolvedOutputDirectory -ChildPath 'performance-samples.csv') -NoTypeInformation -Encoding UTF8
    [void]$collectedArtifacts.Add('performance-samples.csv')
}
catch {
    Add-CollectionError -Stage 'performance-export' -ErrorRecord $_
}

try {
    # CPU access can throw for individual processes (observed on Windows Server
    # VMs: 'Exception getting "CPU": The property TotalSeconds cannot be found'),
    # which previously aborted the whole snapshot. Guard per process and drop
    # processes without a comparable CPU value before sorting.
    $processes = @(Get-Process -ErrorAction SilentlyContinue) | ForEach-Object {
        $cpu = $null
        try { $cpu = $_.CPU } catch { }
        [pscustomobject]@{
            ProcessName = $_.ProcessName
            Id = $_.Id
            CPU = $cpu
            WorkingSet64 = $_.WorkingSet64
            Handles = $_.Handles
            Path = $_.Path
        }
    } | Where-Object { $null -ne $_.CPU } | Sort-Object -Property CPU -Descending | Select-Object -First 20
    Write-JsonFile -InputObject $processes -Path (Join-Path -Path $resolvedOutputDirectory -ChildPath 'top-processes.json')
    [void]$collectedArtifacts.Add('top-processes.json')
}
catch {
    Add-CollectionError -Stage 'process-snapshot' -ErrorRecord $_
}

$networkState = $null
$networkStatus = 'failed'
$networkSectionErrorCount = 0
try {
    # all network sub-collections are probe-bounded and independently guarded;
    # a single slow section never loses the rest
    $networkResult = Get-NetworkState
    $networkState = $networkResult.State
    $networkSectionErrorCount = @($networkResult.Errors).Count
    foreach ($sectionError in @($networkResult.Errors)) {
        Add-CollectionErrorText -Stage "network-state-$($sectionError.Section)" -Message $sectionError.Message
    }
    Write-JsonFile -InputObject $networkState -Path (Join-Path -Path $resolvedOutputDirectory -ChildPath 'network-state.json')
    [void]$collectedArtifacts.Add('network-state.json')
    $networkStatus = 'completed'
}
catch {
    Add-CollectionError -Stage 'network-state' -ErrorRecord $_
    $networkStatus = 'failed'
}

$systemLogInfo = $null
$safeEvents = $null
try {
    $eventStartTime = (Get-Date).AddHours(-24)
    $systemLogInfo = Get-WinEvent -ListLog 'System' -ErrorAction Stop
    $safeEvents = Get-EventsSafe -LogName 'System' -StartTime $eventStartTime -MaxEvents $MaxEventCount
    $events = $safeEvents.Events
    Write-JsonFile -InputObject $events -Path (Join-Path -Path $resolvedOutputDirectory -ChildPath 'system-events-last-24-hours.json')
    [void]$collectedArtifacts.Add('system-events-last-24-hours.json')
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

# ---- Minidump collection (consent-gated; read-only copy of crash dumps) ----
# Source files are never modified or deleted. MEMORY.DMP is recorded as
# metadata only - kernel dumps can be GBs and are not worth copying blind.
$minidumpStatus = $null
$minidumpMemoryDumpInfo = [ordered]@{
    exists = $false
    sizeBytes = $null
    lastWriteTimeUtc = $null
}
$minidumpCopiedCount = 0
$minidumpSkippedCount = 0
$minidumpTotalBytes = 0
$minidumpFiles = @()

if ($CollectMinidumps) {
    try {
        $minidumpDir = Join-Path $resolvedOutputDirectory 'minidumps'
        New-Item -ItemType Directory -Force -Path $minidumpDir | Out-Null

        $memoryDumpPath = Join-Path $env:SystemRoot 'MEMORY.DMP'
        if (Test-Path -LiteralPath $memoryDumpPath) {
            $memoryDumpItem = Get-Item -LiteralPath $memoryDumpPath
            $minidumpMemoryDumpInfo = [ordered]@{
                exists = $true
                sizeBytes = $memoryDumpItem.Length
                lastWriteTimeUtc = $memoryDumpItem.LastWriteTime.ToUniversalTime().ToString('o')
            }
        }

        $dumps = @(
            Get-ChildItem -LiteralPath $minidumpSourcePath -Filter '*.dmp' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending
        )
        if ($dumps.Count -eq 0 -and -not $minidumpMemoryDumpInfo.exists) {
            # no crash dumps and no kernel dump: healthy machines commonly have
            # none - record as skipped, not as an error
            $minidumpStatus = 'skipped-no-minidumps'
        }
        else {
            foreach ($dump in $dumps) {
                if (($minidumpTotalBytes + $dump.Length) -gt $script:MaxMinidumpTotalBytes) {
                    $minidumpSkippedCount++
                    continue
                }
                $minidumpDest = Join-Path $minidumpDir $dump.Name
                Copy-Item -LiteralPath $dump.FullName -Destination $minidumpDest -Force
                $minidumpTotalBytes += $dump.Length
                $minidumpCopiedCount++
                [void]$collectedArtifacts.Add("minidumps\$($dump.Name)")
                $minidumpFiles += [pscustomobject]@{
                    Name = $dump.Name
                    SizeBytes = $dump.Length
                    SourceLastWriteTimeUtc = $dump.LastWriteTime.ToUniversalTime().ToString('o')
                }
            }
            $minidumpStatus = 'completed'
        }
    }
    catch {
        Add-CollectionError -Stage 'minidump-collection' -ErrorRecord $_
        $minidumpStatus = 'failed'
    }
}

# ---- Boot-failure evidence (consent-gated; read-only copy of SRT/boot/CBS logs) ----
# Evidence a non-booting machine leaves behind: Startup-Repair trail, boot log
# (present only if boot logging was enabled), component servicing and setup
# logs. Oversized logs (CBS can grow to GBs) are recorded and skipped, never
# truncated - a truncated log is worse than no log.
$bootFailureStatus = $null
$bootFailureCopiedCount = 0
$bootFailureSkippedOversizedCount = 0
$bootFailureSources = @()

if ($CollectBootFailureLogs) {
    try {
        $bootFailureDir = Join-Path $resolvedOutputDirectory 'bootfailure'
        New-Item -ItemType Directory -Force -Path $bootFailureDir | Out-Null

        $bootFailureCandidates = @(
            [pscustomobject]@{ Name = 'srt-trail'; SourcePath = (Join-Path $env:SystemRoot 'System32\LogFiles\Srt\SrtTrail.txt') }
            [pscustomobject]@{ Name = 'boot-log'; SourcePath = (Join-Path $env:SystemRoot 'ntbtlog.txt') }
            [pscustomobject]@{ Name = 'cbs-log'; SourcePath = (Join-Path $env:SystemRoot 'Logs\CBS\CBS.log') }
            [pscustomobject]@{ Name = 'setupapi-panther'; SourcePath = (Join-Path $env:SystemRoot 'Panther\setupact.log') }
            [pscustomobject]@{ Name = 'setupapi-error'; SourcePath = (Join-Path $env:SystemRoot 'Panther\setuperr.log') }
            [pscustomobject]@{ Name = 'dism-log'; SourcePath = (Join-Path $env:SystemRoot 'Logs\DISM\dism.log') }
        )
        $bootFailureSourceEntries = @()
        foreach ($candidate in $bootFailureCandidates) {
            if (Test-Path -LiteralPath $candidate.SourcePath) {
                $candidateItem = Get-Item -LiteralPath $candidate.SourcePath
                $entry = [ordered]@{
                    name = $candidate.Name
                    sourcePath = $candidate.SourcePath
                    found = $true
                    sizeBytes = $candidateItem.Length
                    copied = $false
                    copiedTo = $null
                    skippedReason = $null
                }
                if ($candidateItem.Length -le $script:MaxBootFailureLogBytes) {
                    $bootFailureDest = Join-Path $bootFailureDir $candidateItem.Name
                    Copy-Item -LiteralPath $candidate.SourcePath -Destination $bootFailureDest -Force
                    $entry.copied = $true
                    $entry.copiedTo = "bootfailure\$($candidateItem.Name)"
                    $bootFailureCopiedCount++
                    [void]$collectedArtifacts.Add("bootfailure\$($candidateItem.Name)")
                }
                else {
                    $entry.skippedReason = 'oversized'
                    $bootFailureSkippedOversizedCount++
                }
            }
            else {
                $entry = [ordered]@{
                    name = $candidate.Name
                    sourcePath = $candidate.SourcePath
                    found = $false
                    sizeBytes = $null
                    copied = $false
                    copiedTo = $null
                    skippedReason = $null
                }
            }
            $bootFailureSourceEntries += $entry
        }
        $bootFailureSources = $bootFailureSourceEntries
        $bootFailureStatus = 'completed'
    }
    catch {
        Add-CollectionError -Stage 'boot-failure-log-collection' -ErrorRecord $_
        $bootFailureStatus = 'failed'
    }
}

if ($CaptureWpr) {
    $wprResult = Invoke-ConsentedCapture `
        -StageName 'wpr-capture' `
        -SkipStatusNotReady 'skipped-wpr-not-found' `
        -NotReadyMessage 'wpr.exe not found; WPR capture skipped' `
        -NotReadyErrorId 'WprNotFound' `
        -ElevationMessage 'requires an elevated (Administrator) console; WPR capture skipped' `
        -ElevationErrorId 'WprElevationRequired' `
        -ReadyCheck { Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\wpr.exe') } `
        -CaptureBody {
            $wprExe = Join-Path $env:SystemRoot 'System32\wpr.exe'
            $startedAtUtc = Get-UtcTimestamp
            $etlPath = Join-Path $resolvedOutputDirectory 'wpr-trace.etl'
            $startExitCode = $null
            $stopExitCode = $null
            $startFailed = $false
            try {
                & $wprExe -start $WprProfile -filemode
                $startExitCode = $LASTEXITCODE
                if ($startExitCode -ne 0) {
                    $startFailed = $true
                }
            }
            catch {
                Add-CollectionError -Stage 'wpr-capture' -ErrorRecord $_
                $startFailed = $true
            }

            if ($startFailed) {
                Add-CollectionError -Stage 'wpr-capture' -ErrorRecord ([System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new("wpr.exe -start $WprProfile failed with exit code $startExitCode; WPR capture skipped (an already-running trace is left untouched)"),
                    'WprStartFailed',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    $null
                ))
                return [ordered]@{ status = 'failed'; startedAtUtc = $startedAtUtc; startExitCode = $startExitCode }
            }

            Start-Sleep -Seconds $DurationSeconds
            try {
                & $wprExe -stop $etlPath
                $stopExitCode = $LASTEXITCODE
                $completedAtUtc = Get-UtcTimestamp
                if ((Test-Path -LiteralPath $etlPath) -and (Get-Item -LiteralPath $etlPath).Length -gt 0) {
                    [void]$collectedArtifacts.Add('wpr-trace.etl')
                    return [ordered]@{
                        status = 'completed'
                        etlFilePath = $etlPath
                        startedAtUtc = $startedAtUtc
                        completedAtUtc = $completedAtUtc
                        startExitCode = $startExitCode
                        stopExitCode = $stopExitCode
                    }
                }
                else {
                    Add-CollectionError -Stage 'wpr-capture' -ErrorRecord ([System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new("wpr.exe -stop reported exit code $stopExitCode but no wpr-trace.etl was produced"),
                        'WprEtlMissing',
                        [System.Management.Automation.ErrorCategory]::InvalidData,
                        $null
                    ))
                    return [ordered]@{ status = 'failed'; startedAtUtc = $startedAtUtc; completedAtUtc = $completedAtUtc; startExitCode = $startExitCode; stopExitCode = $stopExitCode }
                }
            }
            catch {
                Add-CollectionError -Stage 'wpr-capture' -ErrorRecord $_
                return [ordered]@{ status = 'failed'; startedAtUtc = $startedAtUtc; startExitCode = $startExitCode }
            }
        }
}

if ($CaptureDefender) {
    $defenderResult = Invoke-ConsentedCapture `
        -StageName 'defender-capture' `
        -SkipStatusNotReady 'skipped-defender-module-not-found' `
        -NotReadyMessage 'DefenderPerformance module not found; Defender performance capture skipped' `
        -NotReadyErrorId 'DefenderModuleNotFound' `
        -ElevationMessage 'requires an elevated (Administrator) console; Defender performance capture skipped' `
        -ElevationErrorId 'DefenderElevationRequired' `
        -ReadyCheck { $null -ne (Get-Module -ListAvailable -Name DefenderPerformance) } `
        -CaptureBody {
            $startedAtUtc = Get-UtcTimestamp
            $etlPath = Join-Path $resolvedOutputDirectory 'defender-performance.etl'
            try {
                Import-Module -Name DefenderPerformance -ErrorAction Stop
                New-MpPerformanceRecording -RecordTo $etlPath -Seconds $DurationSeconds -ErrorAction Stop
                [void]$collectedArtifacts.Add('defender-performance.etl')
                return [ordered]@{
                    status = 'completed'
                    etlFilePath = $etlPath
                    startedAtUtc = $startedAtUtc
                    completedAtUtc = Get-UtcTimestamp
                    moduleVersion = (Get-Module -Name DefenderPerformance).Version.ToString()
                }
            }
            catch {
                Add-CollectionError -Stage 'defender-capture' -ErrorRecord $_
                return [ordered]@{ status = 'failed'; startedAtUtc = $startedAtUtc; completedAtUtc = Get-UtcTimestamp }
            }
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
    network = [ordered]@{
        status = $networkStatus
        artifact = 'network-state.json'
        dnsVsPing = [ordered]@{
            rawIpReachable = $null
            dnsResolutionOk = $null
            verdict = 'inconclusive'
        }
        securitySoftwareMatches = [ordered]@{
            processMatches = 0
            installedSoftwareMatches = 0
        }
        sectionErrorCount = $networkSectionErrorCount
    }
    collectionErrors = $collectionErrors
    artifacts = Get-ArtifactMetadata -Directory $resolvedOutputDirectory -Names @($collectedArtifacts)
}

if ($systemLogInfo -and $safeEvents) {
    $collectionManifest.systemEventLog = [ordered]@{
        enabled = $systemLogInfo.IsEnabled
        recordCount = $systemLogInfo.RecordCount
        pulledCount = $safeEvents.Events.Count
        skippedUnrenderableCount = $safeEvents.SkippedMessageCount
    }
}

if ($networkState) {
    $dnsVsPingState = $networkState['dnsVsPing']
    $securitySoftwareState = $networkState['securitySoftware']
    $collectionManifest.network = [ordered]@{
        status = $networkStatus
        artifact = 'network-state.json'
        dnsVsPing = [ordered]@{
            rawIpReachable = if ($null -ne $dnsVsPingState) { $dnsVsPingState['rawIpReachable'] } else { $null }
            dnsResolutionOk = if ($null -ne $dnsVsPingState) { $dnsVsPingState['dnsResolutionOk'] } else { $null }
            verdict = if ($null -ne $dnsVsPingState) { $dnsVsPingState['verdict'] } else { 'inconclusive' }
        }
        securitySoftwareMatches = [ordered]@{
            processMatches = if ($null -ne $securitySoftwareState) { @($securitySoftwareState['processMatches']).Count } else { 0 }
            installedSoftwareMatches = if ($null -ne $securitySoftwareState) { @($securitySoftwareState['installedSoftwareMatches']).Count } else { 0 }
        }
        sectionErrorCount = $networkSectionErrorCount
    }
}

if ($CaptureWpr) {
    $collectionManifest.wpr = [ordered]@{
        profile = $WprProfile
        durationSeconds = $DurationSeconds
        etlFilePath = $wprResult.etlFilePath
        startedAtUtc = $wprResult.startedAtUtc
        completedAtUtc = $wprResult.completedAtUtc
        startExitCode = $wprResult.startExitCode
        stopExitCode = $wprResult.stopExitCode
        status = $wprResult.status
    }
}

if ($CaptureDefender) {
    $collectionManifest.defender = [ordered]@{
        durationSeconds = $DurationSeconds
        etlFilePath = $defenderResult.etlFilePath
        startedAtUtc = $defenderResult.startedAtUtc
        completedAtUtc = $defenderResult.completedAtUtc
        moduleVersion = $defenderResult.moduleVersion
        status = $defenderResult.status
    }
}

if ($CollectMinidumps) {
    $collectionManifest.minidumps = [ordered]@{
        enabled = $true
        status = $minidumpStatus
        sourcePath = $minidumpSourcePath
        maxTotalBytes = $script:MaxMinidumpTotalBytes
        memoryDump = $minidumpMemoryDumpInfo
        copiedCount = $minidumpCopiedCount
        skippedCount = $minidumpSkippedCount
        totalBytes = $minidumpTotalBytes
        files = @($minidumpFiles)
    }
}

if ($CollectBootFailureLogs) {
    $collectionManifest.bootFailureLogs = [ordered]@{
        enabled = $true
        status = $bootFailureStatus
        maxBytesPerFile = $script:MaxBootFailureLogBytes
        copiedCount = $bootFailureCopiedCount
        skippedOversizedCount = $bootFailureSkippedOversizedCount
        sourceEntries = @($bootFailureSources)
    }
}

$collectionManifestPath = Join-Path -Path $resolvedOutputDirectory -ChildPath 'diagnostic-manifest.json'
Write-JsonFile -InputObject $collectionManifest -Path $collectionManifestPath
Write-Output "Collection complete. Manifest written to $collectionManifestPath"

if ($ZipOutput) {
    $collectionManifest = Add-CasePackageBlock -CollectionManifest $collectionManifest -OutputDirectory $resolvedOutputDirectory -ArtifactNames @($collectedArtifacts)
    Write-JsonFile -InputObject $collectionManifest -Path $collectionManifestPath
}
