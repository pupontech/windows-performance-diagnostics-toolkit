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

    [switch]$ConfirmDefenderCapture
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptVersion = '0.5.0'

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
    $pingTargets = @('8.8.8.8', '1.1.1.1')
    $pingResults = @()
    foreach ($target in $pingTargets) {
        try {
            $replies = @(Test-Connection -ComputerName $target -Count 3 -ErrorAction SilentlyContinue)
            $pingResults += [pscustomobject]@{
                Target = $target
                Reachable = ($replies.Count -gt 0)
                ReplyCount = $replies.Count
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
    }

    $dnsTargets = @('google.com', 'cloudflare.com', 'microsoft.com')
    $dnsResults = @()
    foreach ($domain in $dnsTargets) {
        try {
            $resolvedIps = @(
                Resolve-DnsName -Name $domain -ErrorAction Stop |
                    Where-Object { $_.Type -in @('A', 'AAAA') } |
                    ForEach-Object { $_.IPAddress }
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
        $state['tcpConnections'] = @(
            Get-NetTCPConnection -ErrorAction SilentlyContinue |
                Where-Object { $_.State -in @('Established', 'Listen') } |
                Sort-Object LocalPort |
                Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
        )
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
                $wprStartExitCode = $null
                $wprStartFailed = $false
                try {
                    & $wprExe -start $WprProfile -filemode
                    $wprStartExitCode = $LASTEXITCODE
                    if ($wprStartExitCode -ne 0) {
                        $wprStartFailed = $true
                    }
                }
                catch {
                    Add-CollectionError -Stage 'wpr-capture' -ErrorRecord $_
                    $wprStartFailed = $true
                }

                if ($wprStartFailed) {
                    $wprStatus = 'failed'
                    Add-CollectionError -Stage 'wpr-capture' -ErrorRecord ([System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new("wpr.exe -start $WprProfile failed with exit code $wprStartExitCode; WPR capture skipped (an already-running trace is left untouched)"),
                        'WprStartFailed',
                        [System.Management.Automation.ErrorCategory]::InvalidOperation,
                        $null
                    ))
                }
                else {
                    Start-Sleep -Seconds $DurationSeconds
                    try {
                        & $wprExe -stop $wprEtlPath
                        $wprStopExitCode = $LASTEXITCODE
                        $wprCompletedAtUtc = Get-UtcTimestamp
                        if ((Test-Path -LiteralPath $wprEtlPath) -and (Get-Item -LiteralPath $wprEtlPath).Length -gt 0) {
                            $wprEtlFilePath = $wprEtlPath
                            [void]$collectedArtifacts.Add('wpr-trace.etl')
                            $wprStatus = 'completed'
                        }
                        else {
                            Add-CollectionError -Stage 'wpr-capture' -ErrorRecord ([System.Management.Automation.ErrorRecord]::new(
                                [System.Exception]::new("wpr.exe -stop reported exit code $wprStopExitCode but no wpr-trace.etl was produced"),
                                'WprEtlMissing',
                                [System.Management.Automation.ErrorCategory]::InvalidData,
                                $null
                            ))
                            $wprStatus = 'failed'
                        }
                    }
                    catch {
                        Add-CollectionError -Stage 'wpr-capture' -ErrorRecord $_
                        $wprStatus = 'failed'
                    }
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
                    [void]$collectedArtifacts.Add('defender-performance.etl')
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
