<#
.SYNOPSIS
  Execution harness for the live matrix cases WPD-06 and WPD-07
  (docs/windows-live-test-matrix.md).

.DESCRIPTION
  Runs ONE case on a Windows host and returns an unambiguous verdict:

    WPD-06  Create a controlled application error/event, then run collection -
            the event summary is bounded by -MaxEventCount and contains the
            recent System-log evidence that an independent Event Viewer query
            sees.
    WPD-07  Watch Defender, startup entries, event-log sizes and system
            configuration before/after a collection - no exclusions, startup
            edits, log clearing, repair actions, uploads or policy changes
            occur.

  The harness is the test rig, not the subject under test. It may create its own
  preconditions on a disposable host (a controlled System-log event and, only
  when the platform has no reusable event source, one harness-registered
  source); every harness-side change is recorded in the result JSON and the
  matrix preconditions are checked before any case runs.

  Exit code 0 = PASS, 1 = FAIL, 2 = precondition/NOT RUN. The result JSON is
  written to <StagingRoot>\results and contains no credentials.

.PARAMETER Case
  WPD-06 or WPD-07.

.PARAMETER ToolkitScript
  Absolute path of the Invoke-WindowsPerformanceDiagnostics.ps1 under test.

.PARAMETER Label
  Short build label recorded in the results (e.g. 'source-52dfbad',
  'release-1.0.0').

.EXAMPLE
  pwsh -File .\tests\live\Invoke-WpdLiveCase0607.ps1 -Case WPD-06 `
    -ToolkitScript C:\WPD\toolkit-source\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
    -Label source-52dfbad -MaxEventCount 50
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('WPD-06', 'WPD-07')]
    [string]$Case,

    [Parameter(Mandatory = $true)]
    [string]$ToolkitScript,

    [Parameter(Mandatory = $true)]
    [string]$Label,

    [string]$StagingRoot = 'C:\WPD',

    [ValidateRange(5, 300)]
    [int]$DurationSeconds = 5,

    [ValidateRange(5, 1000)]
    [int]$MaxEventCount = 200,

    [ValidateRange(30, 900)]
    [int]$TimeoutSeconds = 300,

    [int]$ControlledEventId = 777,

    [string]$ControlledEventSource = 'WpdLiveControl'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

#region generic helpers ----------------------------------------------------------

function Get-WpdSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}

function Get-WpdStringSha256 {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return 'null' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
}

function Test-WpdElevated {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WpdProperty {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-WpdUtcStamp {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
    catch { return [string]$Value }
}

function Write-WpdJsonFile {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }
    $json = $InputObject | ConvertTo-Json -Depth 12
    if ($null -eq $json) { $json = 'null' }
    Set-Content -LiteralPath $Path -Value $json -Encoding utf8
}

function Invoke-WpdWindowsPowerShellChild {
    <#
      Runs a script block on the machine's Windows PowerShell 5.1 host and
      returns the last JSON object it printed. Two reasons this exists:
        - Windows PowerShell owns cmdlets PowerShell 7 does not ship (the
          Defender module's native host, New-EventLog/Write-EventLog), and the
          case must not depend on which host the harness itself was launched
          with;
        - the child host keeps the emitted result machine readable while the
          parent harness records it verbatim.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptText
    )

    $wps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $wps)) {
        return [pscustomobject]@{ ok = $false; json = $null; raw = ''; error = 'Windows PowerShell 5.1 host not found' }
    }
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptText))
    $raw = ''
    try {
        $raw = (@(& $wps -NoProfile -NonInteractive -EncodedCommand $encoded 2>&1) | Out-String)
    }
    catch {
        return [pscustomobject]@{ ok = $false; json = $null; raw = ''; error = $_.Exception.Message }
    }

    $jsonLine = @($raw -split "`r?`n" | Where-Object { $_ -and ([string]$_).Trim().StartsWith('{') } | Select-Object -Last 1)
    $json = $null
    if ($jsonLine) {
        try { $json = ($jsonLine | ConvertFrom-Json) }
        catch { return [pscustomobject]@{ ok = $false; json = $null; raw = $raw; error = "child JSON could not be parsed: $($_.Exception.Message)" } }
    }
    if ($null -eq $json) {
        $firstLine = @($raw -split "`r?`n" | Where-Object { $_ } | Select-Object -First 1)
        return [pscustomobject]@{ ok = $false; json = $null; raw = $raw; error = "child returned no JSON: $firstLine" }
    }
    return [pscustomobject]@{ ok = $true; json = $json; raw = $raw; error = $null }
}

#endregion

#region pure comparison helpers (unit-testable off Windows) ----------------------

function Get-WpdEventKey {
    <#
      Identity of one collected System-log row: event id + provider + the
      TimeCreated second + a short hash of the message text. The artifact and the
      independent live query are read through different code paths, so the
      identity has to be a value comparison rather than an object reference; the
      message hash is what stops two different events inside the same second
      (common on a busy host) from being treated as the same row.
    #>
    param([AllowNull()]$Row)
    if ($null -eq $Row) { return '' }
    $id = [string](Get-WpdProperty -InputObject $Row -Name 'Id')
    $provider = [string](Get-WpdProperty -InputObject $Row -Name 'ProviderName')
    $stamp = Get-WpdUtcStamp -Value (Get-WpdProperty -InputObject $Row -Name 'TimeCreated')
    if ($null -eq $stamp) { $stamp = '' }
    $stamp = $stamp.Substring(0, [Math]::Min(19, $stamp.Length))
    $messageHash = Get-WpdStringSha256 ([string](Get-WpdProperty -InputObject $Row -Name 'Message'))
    $messageHash = $messageHash.Substring(0, [Math]::Min(16, $messageHash.Length))
    return ('{0}|{1}|{2}|{3}' -f $id, $provider, $stamp, $messageHash)
}

function Compare-WpdEventEvidence {
    <#
      Compares the collected event summary against rows an independent Event
      Viewer query returns. Reports, without deciding:
        - how many artifact rows exist and what bound was requested,
        - whether the artifact is ordered newest-first,
        - which artifact rows the live log does not contain,
        - the artifact's own time span,
        - how many artifact rows fall outside the 24-hour lookback.
      A row count above the requested bound, or any artifact row the live log
      cannot corroborate, is the failure signature this case exists to catch.
    #>
    param(
        [AllowEmptyCollection()][object[]]$ArtifactRows = @(),
        [AllowEmptyCollection()][object[]]$LiveRows = @(),
        [int]$Bound = 0,
        [AllowNull()]$LookbackStartUtc = $null
    )

    $artifactKeys = New-Object System.Collections.ArrayList
    $times = New-Object System.Collections.ArrayList
    foreach ($row in @($ArtifactRows)) {
        [void]$artifactKeys.Add((Get-WpdEventKey -Row $row))
        $time = Get-WpdProperty -InputObject $row -Name 'TimeCreated'
        if ($null -ne $time) {
            try { [void]$times.Add(([datetime]$time).ToUniversalTime()) } catch { }
        }
    }

    $orderedNewestFirst = $true
    for ($index = 1; $index -lt $times.Count; $index++) {
        if ($times[$index] -gt $times[$index - 1]) { $orderedNewestFirst = $false }
    }

    $liveKeys = @{}
    foreach ($row in @($LiveRows)) { $liveKeys[(Get-WpdEventKey -Row $row)] = $true }
    $missing = @($artifactKeys | Where-Object { -not $liveKeys.ContainsKey($_) })

    $outsideLookback = 0
    $lookback = $null
    if ($null -ne $LookbackStartUtc) {
        try { $lookback = ([datetime]$LookbackStartUtc).ToUniversalTime() } catch { $lookback = $null }
    }
    if ($null -ne $lookback) {
        foreach ($time in $times) {
            if ($time -lt $lookback) { $outsideLookback++ }
        }
    }

    $sorted = @($times | Sort-Object)
    return [pscustomobject]@{
        artifactCount        = @($ArtifactRows).Count
        bound                = $Bound
        liveRowCount         = @($LiveRows).Count
        orderedNewestFirst   = $orderedNewestFirst
        duplicateKeys        = (@($artifactKeys).Count - @($artifactKeys | Select-Object -Unique).Count)
        missingFromLiveLog   = @($missing)
        rowsOutsideLookback  = $outsideLookback
        oldestArtifactUtc    = if ($sorted.Count -gt 0) { $sorted[0].ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } else { $null }
        newestArtifactUtc    = if ($sorted.Count -gt 0) { $sorted[$sorted.Count - 1].ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } else { $null }
    }
}

function ConvertFrom-WpdNetstat {
    <# Parses `netstat -ano` text into (Protocol, LocalAddress, RemoteAddress, State, ProcessId) rows. #>
    param([AllowEmptyCollection()][string[]]$Lines = @())

    $rows = New-Object System.Collections.ArrayList
    foreach ($line in @($Lines)) {
        if ($null -eq $line) { continue }
        $text = ([string]$line).Trim()
        if ($text.Length -eq 0) { continue }
        $tokens = @($text -split '\s+')
        if ($tokens.Count -lt 4) { continue }
        $protocol = $tokens[0].ToUpperInvariant()
        if ($protocol -eq 'TCP') {
            if ($tokens.Count -lt 5) { continue }
            [void]$rows.Add([pscustomobject]@{
                Protocol      = 'TCP'
                LocalAddress  = $tokens[1]
                RemoteAddress = $tokens[2]
                State         = $tokens[3]
                ProcessId     = $tokens[4]
                Raw           = $text
            })
        }
        elseif ($protocol -eq 'UDP') {
            [void]$rows.Add([pscustomobject]@{
                Protocol      = 'UDP'
                LocalAddress  = $tokens[1]
                RemoteAddress = $tokens[2]
                State         = ''
                ProcessId     = $tokens[3]
                Raw           = $text
            })
        }
    }
    return @($rows)
}

function Test-WpdRemoteAddressIsLocal {
    <# True when a netstat endpoint is loopback, unspecified or empty (no peer). #>
    param([AllowNull()][string]$RemoteAddress)

    if ([string]::IsNullOrWhiteSpace($RemoteAddress)) { return $true }
    $text = ([string]$RemoteAddress).Trim()
    $hostPart = $text
    $separator = $text.LastIndexOf(':')
    if ($separator -gt 0) { $hostPart = $text.Substring(0, $separator) }
    $hostPart = $hostPart.Trim('[', ']')
    if ($hostPart -eq '' -or $hostPart -eq '*' -or $hostPart -eq '0.0.0.0' -or $hostPart -eq '::' -or $hostPart -eq '::1') { return $true }
    if ($hostPart -like '127.*') { return $true }
    if ($hostPart -like '::ffff:127.*') { return $true }
    if ($hostPart -like 'fe80:*') { return $true }
    return $false
}

$script:WpdBannedProcessNames = @(
    'dism.exe', 'dismhost.exe', 'sfc.exe', 'chkdsk.exe', 'procmon.exe', 'procmon64.exe',
    'procdump.exe', 'procdump64.exe', 'defrag.exe', 'msizap.exe', 'wbadmin.exe', 'vssadmin.exe',
    'mpcmdrun.exe', 'wusa.exe', 'wevtutil.exe', 'schtasks.exe', 'reg.exe', 'sc.exe',
    'net.exe', 'net1.exe', 'takeown.exe', 'attrib.exe', 'bcdedit.exe', 'reagentc.exe',
    'cleanmgr.exe', 'fsutil.exe', 'bitsadmin.exe', 'certutil.exe', 'curl.exe', 'wget.exe'
)

$script:WpdBannedCommandPatterns = @(
    'Clear-EventLog', 'Set-MpPreference', 'Add-MpPreference', 'Remove-MpPreference',
    'wevtutil(\s|\S)*\scl\s', 'wevtutil(\s|\S)*clear-log',
    'Repair-Volume', 'Repair-WindowsImage', 'Start-Defrag', 'Optimize-Volume',
    'schtasks(\s|\S)*/create', 'reg(\s|\S)*delete', 'sc(\s|\S)*delete',
    'Invoke-WebRequest', 'Invoke-RestMethod', 'Start-BitsTransfer', 'Net\.WebClient',
    'certutil(\s|\S)*-urlcache', 'Expand-Archive(\s|\S)*http'
)

function Get-WpdBannedProcessMatch {
    <#
      Classifies a process observed inside the collector's own process tree.
      Read-only native tooling (netstat, netsh, conhost, the collector itself)
      must not match; remediation, log-clearing, policy and transfer tooling
      must.
    #>
    param(
        [AllowNull()][string]$ProcessName,
        [AllowNull()][string]$CommandLine
    )

    $matchedPatterns = New-Object System.Collections.ArrayList
    $name = ''
    if (-not [string]::IsNullOrWhiteSpace($ProcessName)) {
        $name = [System.IO.Path]::GetFileName(([string]$ProcessName).Trim()).ToLowerInvariant()
    }
    if ($name -and ($script:WpdBannedProcessNames -contains $name)) {
        [void]$matchedPatterns.Add("name:$name")
    }
    foreach ($pattern in $script:WpdBannedCommandPatterns) {
        if (-not [string]::IsNullOrWhiteSpace($CommandLine) -and ([string]$CommandLine) -match $pattern) {
            [void]$matchedPatterns.Add("command:$pattern")
        }
    }
    return @($matchedPatterns)
}

function Compare-WpdState {
    <#
      Strict machine-state comparison. Anything under `strict` that changed
      across the case window is a persistence / configuration finding; the
      comparison is value based (JSON per surface) so array order never fakes a
      delta.
    #>
    param(
        [Parameter(Mandatory = $true)]$Before,
        [Parameter(Mandatory = $true)]$After
    )

    $deltas = New-Object System.Collections.ArrayList
    foreach ($surface in @($Before.strict.Keys)) {
        $beforeJson = ($Before.strict[$surface] | ConvertTo-Json -Depth 8 -Compress)
        $afterJson = ($After.strict[$surface] | ConvertTo-Json -Depth 8 -Compress)
        if ($beforeJson -ne $afterJson) {
            [void]$deltas.Add([pscustomobject]@{
                surface = $surface
                before  = $beforeJson
                after   = $afterJson
            })
        }
    }
    return @($deltas)
}

function Get-WpdEventLogClearingVerdict {
    <#
      A cleared log resets its oldest record number and shrinks the record count.
      Normal use only ever appends, so this is an unambiguous signal; wrapping a
      full log raises the oldest record number instead.
    #>
    param(
        [AllowNull()]$BeforeLogs,
        [AllowNull()]$AfterLogs
    )

    $verdicts = New-Object System.Collections.ArrayList
    foreach ($logName in @('System', 'Application')) {
        $before = @(@($BeforeLogs) | Where-Object { $null -ne $_ -and $_.name -eq $logName })
        $after = @(@($AfterLogs) | Where-Object { $null -ne $_ -and $_.name -eq $logName })
        if ($before.Count -eq 0 -or $after.Count -eq 0) {
            [void]$verdicts.Add([pscustomobject]@{
                log = $logName; status = 'not-assessable'; cleared = $null; reason = 'log state unavailable'
            })
            continue
        }
        $b = $before[0]
        $a = $after[0]
        $cleared = $false
        if ($null -ne $b.oldestRecordNumber -and $null -ne $a.oldestRecordNumber) {
            if ([int64]$a.oldestRecordNumber -lt [int64]$b.oldestRecordNumber) { $cleared = $true }
        }
        if ($null -ne $b.fileSize -and $null -ne $a.fileSize -and $null -ne $b.recordCount -and $null -ne $a.recordCount) {
            if ([int64]$a.fileSize -lt [int64]$b.fileSize -and [int64]$a.recordCount -lt [int64]$b.recordCount) { $cleared = $true }
        }
        [void]$verdicts.Add([pscustomobject]@{
            log               = $logName
            status            = 'assessed'
            cleared           = $cleared
            beforeOldest      = $b.oldestRecordNumber
            afterOldest       = $a.oldestRecordNumber
            beforeRecordCount = $b.recordCount
            afterRecordCount  = $a.recordCount
            beforeFileSize    = $b.fileSize
            afterFileSize     = $a.fileSize
        })
    }
    return @($verdicts)
}

#endregion

#region assertions ---------------------------------------------------------------

$script:wpdAssertions = New-Object System.Collections.ArrayList
$script:wpdFailures = New-Object System.Collections.ArrayList

function Add-WpdAssertion {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Expected,
        [AllowNull()]$Observed,
        [Parameter(Mandatory = $true)][bool]$Outcome
    )
    [void]$script:wpdAssertions.Add([pscustomobject]@{
        name     = $Name
        expected = $Expected
        observed = [string]$Observed
        outcome  = if ($Outcome) { 'pass' } else { 'fail' }
    })
    if (-not $Outcome) {
        [void]$script:wpdFailures.Add(('{0}: expected {1}; observed {2}' -f $Name, $Expected, [string]$Observed))
        Write-Output "ASSERT-FAIL [$Name] expected: $Expected | observed: $Observed"
    }
    else {
        Write-Output "assert-pass [$Name] $Observed"
    }
}

#endregion

#region environment record -------------------------------------------------------

function Get-WpdEnvironmentRecord {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $wps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $wpsVersion = $null
    if (Test-Path -LiteralPath $wps) {
        $wpsVersion = (& $wps -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>&1) -join ' '
    }

    return [ordered]@{
        recordedAtUtc           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        recordedAtLocal         = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
        osCaption               = $os.Caption
        osVersion               = $os.Version
        osBuildNumber           = $os.BuildNumber
        osArchitecture          = $os.OSArchitecture
        osProductType           = $os.ProductType
        computerSystemModel     = $cs.Model
        machineIdentifier       = $env:COMPUTERNAME
        runnerName              = $env:RUNNER_NAME
        runnerOs                = $env:RUNNER_OS
        runnerImage             = $env:ImageOS
        harnessUser             = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        harnessElevated         = (Test-WpdElevated)
        collectorRuntime        = $wps
        collectorRuntimeVersion = $wpsVersion
        harnessHostVersion      = $PSVersionTable.PSVersion.ToString()
        gitCommit               = $env:GITHUB_SHA
        gitRef                  = $env:GITHUB_REF
        gitWorkflowRunId        = $env:GITHUB_RUN_ID
        gitRepository           = $env:GITHUB_REPOSITORY
    }
}

#endregion

#region machine-state fingerprinting ---------------------------------------------

function Get-WpdRunKeyEntries {
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $entries = @()
    foreach ($key in $keys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        $item = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if ($null -eq $item) { continue }
        foreach ($property in $item.PSObject.Properties) {
            if ($property.Name -like 'PS*') { continue }
            $entries += ('{0}|{1}|{2}' -f $key, $property.Name, (Get-WpdStringSha256 ([string]$property.Value)))
        }
    }
    return @($entries | Sort-Object)
}

function Get-WpdStartupFolderEntries {
    $folders = @(
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'),
        (Join-Path $env:AppData 'Microsoft\Windows\Start Menu\Programs\Startup')
    )
    $entries = @()
    foreach ($folder in $folders) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        foreach ($item in @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue)) {
            $entries += ('{0}|{1}' -f $folder, $item.Name)
        }
    }
    return @($entries | Sort-Object)
}

function Get-WpdStartupApprovedEntries {
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    )
    $entries = @()
    foreach ($key in $keys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        $item = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if ($null -eq $item) { continue }
        foreach ($property in $item.PSObject.Properties) {
            if ($property.Name -like 'PS*') { continue }
            $entries += ('{0}|{1}|{2}' -f $key, $property.Name, (Get-WpdStringSha256 ([string]$property.Value)))
        }
    }
    return @($entries | Sort-Object)
}

function Get-WpdWinlogonEntries {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $entries = @()
    if (-not (Test-Path -LiteralPath $key)) { return @() }
    $item = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    if ($null -eq $item) { return @() }
    foreach ($name in @('Shell', 'Userinit', 'Taskman', 'AppSetup', 'VmApplet')) {
        $value = Get-WpdProperty -InputObject $item -Name $name
        if ($null -eq $value) { continue }
        $entries += ('{0}|{1}|{2}' -f $key, $name, (Get-WpdStringSha256 ([string]$value)))
    }
    return @($entries | Sort-Object)
}

function Get-WpdRegistryTreeFingerprint {
    <# Recursive path|name|value-hash dump of a registry key - policy-change detection. #>
    param([Parameter(Mandatory = $true)][string]$Path)
    $entries = @()
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    try {
        $items = @(Get-ChildItem -LiteralPath $Path -Recurse -ErrorAction SilentlyContinue) + @(Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue)
        foreach ($item in $items) {
            if ($null -eq $item) { continue }
            foreach ($property in $item.PSObject.Properties) {
                if ($property.Name -like 'PS*') { continue }
                $value = [string]$property.Value
                $entries += ('{0}|{1}|{2}' -f $item.PSPath, $property.Name, (Get-WpdStringSha256 $value))
            }
        }
    }
    catch {
        $entries += ('{0}|unavailable|{1}' -f $Path, $_.Exception.Message)
    }
    return @($entries | Sort-Object)
}

function Get-WpdDefenderPreferences {
    <#
      Defender preferences are read through Windows PowerShell 5.1 (the Defender
      module's native host) so the surface is captured even when the harness
      itself runs on PowerShell 7.
    #>
    $child = @'
$ErrorActionPreference = 'Stop'
function Get-ChildProp {
    param($InputObject, [string]$Name)
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}
$result = [ordered]@{ available = $false }
try {
    $pref = Get-MpPreference -ErrorAction Stop
    $status = $null
    try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { $status = $null }
    $result.available = $true
    $result.exclusionPath          = @(Get-ChildProp $pref 'ExclusionPath' | Sort-Object)
    $result.exclusionExtension     = @(Get-ChildProp $pref 'ExclusionExtension' | Sort-Object)
    $result.exclusionProcess       = @(Get-ChildProp $pref 'ExclusionProcess' | Sort-Object)
    $result.exclusionIpAddress     = @(Get-ChildProp $pref 'ExclusionIpAddress' | Sort-Object)
    $result.disableRealtimeMonitoring    = (Get-ChildProp $pref 'DisableRealtimeMonitoring')
    $result.disableBehaviorMonitoring    = (Get-ChildProp $pref 'DisableBehaviorMonitoring')
    $result.disableIOAVProtection        = (Get-ChildProp $pref 'DisableIOAVProtection')
    $result.disableScriptScanning        = (Get-ChildProp $pref 'DisableScriptScanning')
    $result.disableArchiveScanning       = (Get-ChildProp $pref 'DisableArchiveScanning')
    $result.disableRemovableDriveScanning = (Get-ChildProp $pref 'DisableRemovableDriveScanning')
    $result.puaProtection                = (Get-ChildProp $pref 'PUAProtection')
    $result.mapsReporting                = (Get-ChildProp $pref 'MAPSReporting')
    $result.submitSamplesConsent         = (Get-ChildProp $pref 'SubmitSamplesConsent')
    $result.disableCatchupScanning       = (Get-ChildProp $pref 'DisableCatchupFullScan')
    $result.status = [ordered]@{
        antivirusEnabled            = (Get-ChildProp $status 'AntivirusEnabled')
        amServiceEnabled            = (Get-ChildProp $status 'AMServiceEnabled')
        realTimeProtectionEnabled   = (Get-ChildProp $status 'RealTimeProtectionEnabled')
        behaviorMonitoringEnabled   = (Get-ChildProp $status 'BehaviorMonitoringEnabled')
        onAccessProtectionEnabled   = (Get-ChildProp $status 'OnAccessProtectionEnabled')
        ioavProtectionEnabled       = (Get-ChildProp $status 'IoavProtectionEnabled')
        antispywareEnabled          = (Get-ChildProp $status 'AntispywareEnabled')
        isTamperProtected           = (Get-ChildProp $status 'IsTamperProtected')
    }
}
catch {
    $result.reason = $_.Exception.Message
}
$result | ConvertTo-Json -Depth 6 -Compress
'@

    $probe = Invoke-WpdWindowsPowerShellChild -ScriptText $child
    if (-not $probe.ok) {
        return [ordered]@{ available = $false; reason = "defender preference probe failed: $($probe.error)" }
    }
    return $probe.json
}

function Get-WpdServiceState {
    $rows = @()
    foreach ($serviceName in @('WinDefend', 'wscsvc', 'SecurityHealthService', 'WdNisSvc', 'Sense')) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction Stop
            $rows += ('{0}|{1}|{2}' -f $service.Name, $service.Status, $service.StartType)
        }
        catch {
            $rows += ('{0}|absent|- ' -f $serviceName)
        }
    }
    return @($rows | Sort-Object)
}

function Get-WpdEventLogState {
    $rows = @()
    foreach ($logName in @('System', 'Application', 'Security')) {
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $rows += [pscustomobject]@{
                name                 = $logName
                enabled              = $log.IsEnabled
                maxBytes             = [int64]$log.MaximumSizeInBytes
                mode                 = [string]$log.LogMode
                recordCount          = [int64]$log.RecordCount
                oldestRecordNumber   = if ($null -ne $log.OldestRecordNumber) { [int64]$log.OldestRecordNumber } else { $null }
                fileSize             = [int64]$log.FileSize
                fingerprint          = ('{0}|enabled={1}|maxBytes={2}|mode={3}' -f $log.LogName, $log.IsEnabled, $log.MaximumSizeInBytes, $log.LogMode)
            }
        }
        catch {
            $rows += [pscustomobject]@{
                name                 = $logName
                enabled              = $null
                maxBytes             = $null
                mode                 = $null
                recordCount          = $null
                oldestRecordNumber   = $null
                fileSize             = $null
                fingerprint          = ('{0}|unavailable:{1}' -f $logName, $_.Exception.Message)
            }
        }
    }
    return @($rows | Sort-Object -Property name)
}

function Get-WpdToolkitScheduledTasks {
    try {
        return @(Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.TaskPath -eq '\' -and $_.TaskName -match 'wpd|diagnostic|performance|toolkit' } |
            ForEach-Object { '{0}{1}|{2}' -f $_.TaskPath, $_.TaskName, $_.State } |
            Sort-Object)
    }
    catch {
        return @("unavailable: $($_.Exception.Message)")
    }
}

function Get-WpdAdministratorsMembers {
    try {
        return @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { $_.Name } | Sort-Object)
    }
    catch {
        return @("unavailable: $($_.Exception.Message)")
    }
}

function Get-WpdHostsFileHash {
    $hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hostsFile) { return (Get-WpdSha256 -Path $hostsFile) }
    return 'absent'
}

$script:WpdDefenderRegistryPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions',
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection',
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Policy Manager',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
)

function Get-WpdDefenderRegistryState {
    <#
      Strict Defender registry surface. Deliberately limited to the exclusion,
      protection and policy subkeys: the rest of HKLM\SOFTWARE\Microsoft\
      Windows Defender (Signature Updates, MpEngine, Scan history) is refreshed
      by definition updates while the case runs and must not be read as a
      configuration change. The full-tree digest is recorded separately as
      evidence.
    #>
    $entries = @()
    foreach ($path in $script:WpdDefenderRegistryPaths) {
        $entries += Get-WpdRegistryTreeFingerprint -Path $path
    }
    return @($entries | Sort-Object)
}

function Get-WpdDefenderTreeDigest {
    param([Parameter(Mandatory = $true)][string]$Path)
    $entries = @(Get-WpdRegistryTreeFingerprint -Path $Path)
    return ('{0}|{1}' -f $entries.Count, (Get-WpdStringSha256 (($entries | Sort-Object) -join "`n")))
}

function Get-WpdState {
    <#
      Machine-state snapshot. STRICT surfaces are compared before/after the case
      and any delta fails it (no persistence, no configuration change, no
      Defender tampering, no startup or log-configuration edit). RECORD-ONLY
      surfaces are captured as evidence but never gate the verdict, because they
      can legitimately churn inside the case window.
    #>
    $defenderPreferences = Get-WpdDefenderPreferences
    $eventLogs = Get-WpdEventLogState

    $state = [ordered]@{
        capturedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        strict        = [ordered]@{
            administrators        = Get-WpdAdministratorsMembers
            defenderPreferences   = $defenderPreferences
            defenderRegistry      = Get-WpdDefenderRegistryState
            defenderService       = Get-WpdServiceState
            runKeys               = Get-WpdRunKeyEntries
            startupFolder         = Get-WpdStartupFolderEntries
            startupApproved       = Get-WpdStartupApprovedEntries
            winlogon              = Get-WpdWinlogonEntries
            eventLogs             = @($eventLogs | ForEach-Object { $_.fingerprint })
            toolkitScheduledTasks = Get-WpdToolkitScheduledTasks
            hostsFileSha256       = Get-WpdHostsFileHash
        }
        recordOnly    = [ordered]@{
            firewallProfiles       = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { '{0}|enabled={1}' -f $_.Name, $_.Enabled } | Sort-Object)
            eventLogCounters       = $eventLogs
            rootScheduledTaskCount = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -eq '\' }).Count
            fileSystemFreePercentC = $null
            defenderFullTreeDigest = Get-WpdDefenderTreeDigest -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
        }
    }

    try {
        $drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
        if ($drive -and $drive.Size -gt 0) {
            $state.recordOnly.fileSystemFreePercentC = [Math]::Round(($drive.FreeSpace / $drive.Size) * 100, 2)
        }
    }
    catch { }

    return $state
}

#endregion

#region manifest checks ----------------------------------------------------------

function Get-WpdManifest {
    param([Parameter(Mandatory = $true)][string]$OutputDirectory)
    $path = Join-Path $OutputDirectory 'diagnostic-manifest.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
}

function Get-WpdManifestEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)]$Manifest
    )

    $records = @()
    foreach ($entry in @($Manifest.artifacts)) {
        if ($null -eq $entry) { continue }
        $name = [string]$entry.Name
        $declaredSize = $entry.SizeBytes
        $declaredHash = [string]$entry.Sha256
        $platformName = $name.Replace([char]92, [System.IO.Path]::DirectorySeparatorChar).Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        $path = Join-Path -Path $OutputDirectory -ChildPath $platformName
        $exists = Test-Path -LiteralPath $path -PathType Leaf
        $actualSize = if ($exists) { (Get-Item -LiteralPath $path).Length } else { $null }
        $actualHash = if ($exists) { Get-WpdSha256 -Path $path } else { $null }
        $fullPath = if ($exists) { (Get-Item -LiteralPath $path).FullName } else { $path }
        $records += [pscustomobject]@{
            name              = $name
            fullPath          = $fullPath
            declaredSha256    = $declaredHash
            declaredSizeBytes = $declaredSize
            fileExists        = $exists
            actualSha256      = $actualHash
            actualSizeBytes   = $actualSize
            hashMatches       = ($exists -and ($declaredHash -eq $actualHash))
            sizeMatches       = ($exists -and ([int64]$declaredSize -eq $actualSize))
        }
    }
    return $records
}

function Get-WpdUnlistedFiles {
    param(
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)]$Manifest
    )

    $listed = @{}
    foreach ($entry in @($Manifest.artifacts)) {
        if ($null -eq $entry) { continue }
        $listed[[string]$entry.Name.Replace('/', '\').ToUpperInvariant()] = $true
    }

    $unlisted = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $OutputDirectory -Recurse -File -ErrorAction SilentlyContinue)) {
        $relative = $file.FullName.Substring($OutputDirectory.TrimEnd('\').Length + 1).Replace('/', '\')
        if ($relative -eq 'diagnostic-manifest.json') { continue }
        if (-not $listed.ContainsKey($relative.ToUpperInvariant())) {
            $unlisted += $relative
        }
    }
    return @($unlisted | Sort-Object)
}

function Get-WpdCollectionErrorRecords {
    param($Manifest)
    $rows = @()
    foreach ($errorRecord in @($Manifest.collectionErrors)) {
        if ($null -eq $errorRecord) { continue }
        $rows += [pscustomobject]@{ stage = [string]$errorRecord.Stage; message = [string]$errorRecord.Message }
    }
    return $rows
}

function Get-WpdArtifactsOutsideDirectory {
    <# Retention/persistence check: no collected artifact may be written outside the case folder. #>
    param(
        [AllowNull()]$ManifestEvidence,
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )

    $root = $OutputDirectory.TrimEnd('\') + '\'
    $outside = @()
    foreach ($row in @($ManifestEvidence)) {
        if ($null -eq $row) { continue }
        if (-not ([string]$row.fullPath).StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            $outside += [string]$row.fullPath
        }
    }
    return @($outside)
}

function Get-WpdSafetyDeclarationCheck {
    param($Manifest)

    $parts = @()
    $ok = $true
    $sawAny = $false

    $safetyProperty = if ($null -ne $Manifest) { $Manifest.PSObject.Properties['safety'] } else { $null }
    if ($null -ne $safetyProperty -and $null -ne $safetyProperty.Value) {
        $sawAny = $true
        $s = $safetyProperty.Value
        $parts += ('safety(localOnly={0},readOnly={1},requiresExplicitCollectionConsent={2},automaticUpload={3},automaticRemediation={4},automaticLogClearing={5})' -f `
            $s.localOnly, $s.readOnly, $s.requiresExplicitCollectionConsent, $s.automaticUpload, $s.automaticRemediation, $s.automaticLogClearing)
        $ok = $ok -and ($s.localOnly -eq $true) -and ($s.readOnly -eq $true) -and ($s.requiresExplicitCollectionConsent -eq $true) -and `
            ($s.automaticUpload -eq $false) -and ($s.automaticRemediation -eq $false) -and ($s.automaticLogClearing -eq $false)
    }

    $privacyProperty = if ($null -ne $Manifest) { $Manifest.PSObject.Properties['privacy'] } else { $null }
    if ($null -ne $privacyProperty -and $null -ne $privacyProperty.Value) {
        $sawAny = $true
        $p = $privacyProperty.Value
        $parts += ('privacy(secretsCollected={0},redactionApplied={1},level={2},requestedLevel={3})' -f `
            $p.secretsCollected, $p.redactionApplied, $p.level, $p.requestedLevel)
        $ok = $ok -and ($p.secretsCollected -eq $false)
    }

    if (-not $sawAny) {
        $parts += 'no safety or privacy declaration block present'
        $ok = $false
    }

    return [pscustomobject]@{ ok = $ok; observed = ($parts -join ' ') }
}

#endregion

#region event-log queries --------------------------------------------------------

function Get-WpdLiveEventCount {
    <# Counts recent records in a log (newest-first read, capped) for the bound math. #>
    param(
        [Parameter(Mandatory = $true)][string]$LogName,
        [Parameter(Mandatory = $true)][datetime]$StartTime,
        [int]$Cap = 5000
    )

    $isoTime = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    $xpath = "*[System[TimeCreated[@SystemTime>='$isoTime']]]"
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
    $query.ReverseDirection = $true
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
    $count = 0
    try {
        $record = $reader.ReadEvent()
        while ($null -ne $record -and $count -lt $Cap) {
            $count++
            $record.Dispose()
            $record = $reader.ReadEvent()
        }
        if ($null -ne $record) { $record.Dispose() }
    }
    finally {
        $reader.Dispose()
    }
    return $count
}

function Get-WpdLiveEventRows {
    <#
      Independent Event Viewer query mirroring the collector's own bounded
      newest-first read, used as the comparison source for WPD-06. Optionally
      stops at -MaxRows and can be windowed with -MinimumUtc.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$LogName,
        [Parameter(Mandatory = $true)][datetime]$StartTime,
        [int]$MaxRows = 200,
        [AllowNull()]$MinimumUtc = $null
    )

    $isoTime = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    $xpath = "*[System[TimeCreated[@SystemTime>='$isoTime']]]"
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
    $query.ReverseDirection = $true
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
    $buffer = New-Object System.Collections.ArrayList
    $minimum = $null
    if ($null -ne $MinimumUtc) {
        try { $minimum = ([datetime]$MinimumUtc).ToUniversalTime() } catch { $minimum = $null }
    }
    try {
        $record = $reader.ReadEvent()
        while ($null -ne $record) {
            $keep = $true
            if ($null -ne $minimum) {
                $created = $record.TimeCreated
                if ($null -ne $created -and ([datetime]$created).ToUniversalTime() -lt $minimum) { $keep = $false }
            }
            if (-not $keep) {
                $record.Dispose()
                break
            }
            $level = $null
            try { $level = $record.LevelDisplayName } catch { $level = "Level$($record.Level)" }
            $message = $null
            try { $message = $record.FormatDescription() } catch { $message = '[message text unavailable]' }
            [void]$buffer.Add([pscustomobject]@{
                TimeCreated      = $record.TimeCreated
                LevelDisplayName = $level
                Id               = $record.Id
                ProviderName     = $record.ProviderName
                Message          = $message
            })
            $record.Dispose()
            if (@($buffer).Count -ge $MaxRows) { break }
            $record = $reader.ReadEvent()
        }
    }
    finally {
        $reader.Dispose()
    }
    return @($buffer)
}

function Get-WpdNewestEventCrossApi {
    <# Newest record of a log read through Get-WinEvent (a different API than the reader above). #>
    param([Parameter(Mandatory = $true)][string]$LogName)
    try {
        $event = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
        if ($null -eq $event) { return $null }
        return [pscustomobject]@{
            Id           = $event.Id
            ProviderName = $event.ProviderName
            TimeCreated  = $event.TimeCreated
        }
    }
    catch {
        return $null
    }
}

function Get-WpdControlledEventRecord {
    param(
        [Parameter(Mandatory = $true)][int]$EventId,
        [AllowNull()][string]$ProviderName
    )

    foreach ($attempt in 1..5) {
        foreach ($row in @(Get-WpdLiveEventRows -LogName 'System' -StartTime (Get-Date).AddHours(-2) -MaxRows 500)) {
            if ([int]$row.Id -ne $EventId) { continue }
            if ($ProviderName -and [string]$row.ProviderName -ne $ProviderName) { continue }
            return $row
        }
        Start-Sleep -Seconds 1
    }
    return $null
}

function New-WpdControlledSystemEvent {
    <#
      Writes one controlled System-log event through the Windows PowerShell 5.1
      host (Write-EventLog/New-EventLog are not part of PowerShell 7). Preferred
      mode uses the built-in 'EventLog' source, which needs no registration and
      therefore leaves no machine change at all; the fallback registers a
      harness-owned source and records that as a harness change, cleaned up
      after the case.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$EventId,
        [Parameter(Mandatory = $true)][string]$SourceName
    )

    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $message = "WPD-06 controlled System-log event. Harness-written at $stamp for the live collection-safety case; no user data is included."
    $escapedMessage = $message.Replace("'", "''")
    $escapedSource = $SourceName.Replace("'", "''")

    $child = @"
`$ErrorActionPreference = 'Stop'
`$eventId = $EventId
`$sourceName = '$escapedSource'
`$message = '$escapedMessage'
`$mode = 'built-in-source'
`$sourceUsed = 'EventLog'
`$harnessChange = `$null
`$errorText = `$null
try {
    Write-EventLog -LogName 'System' -Source 'EventLog' -EventId `$eventId -EntryType Error -Message `$message -ErrorAction Stop
}
catch {
    `$errorText = `$_.Exception.Message
    try {
        `$existing = [System.Diagnostics.EventLog]::SourceExists(`$sourceName)
        if (-not `$existing) { New-EventLog -LogName 'System' -Source `$sourceName -ErrorAction Stop }
        Write-EventLog -LogName 'System' -Source `$sourceName -EventId `$eventId -EntryType Error -Message `$message -ErrorAction Stop
        `$mode = 'registered-source'
        `$sourceUsed = `$sourceName
        `$errorText = `$null
        if (`$existing) {
            `$harnessChange = "System-log event source ('`$sourceName') already existed; harness wrote event `$eventId with it"
        }
        else {
            `$harnessChange = "harness registered System-log event source ('`$sourceName') to write controlled event `$eventId; removed after the case"
        }
    }
    catch {
        `$mode = 'failed'
        `$sourceUsed = `$sourceName
        `$errorText = (`$errorText + ' ; fallback: ' + `$_.Exception.Message)
    }
}
[pscustomobject]@{ mode = `$mode; source = `$sourceUsed; harnessChange = `$harnessChange; error = `$errorText } | ConvertTo-Json -Depth 4 -Compress
"@

    $written = Invoke-WpdWindowsPowerShellChild -ScriptText $child
    $mode = 'failed'
    $sourceUsed = $SourceName
    $harnessChange = $null
    $errorText = $null
    if ($written.ok) {
        $mode = [string](Get-WpdProperty -InputObject $written.json -Name 'mode')
        $sourceUsed = [string](Get-WpdProperty -InputObject $written.json -Name 'source')
        $harnessChange = Get-WpdProperty -InputObject $written.json -Name 'harnessChange'
        $errorText = Get-WpdProperty -InputObject $written.json -Name 'error'
    }
    else {
        $errorText = "event write host failed: $($written.error)"
    }

    $record = $null
    if ($mode -ne 'failed') {
        $record = Get-WpdControlledEventRecord -EventId $EventId -ProviderName $sourceUsed
        if ($null -eq $record) {
            $mode = 'failed'
            $errorText = "event was written but could not be read back from the System log (id $EventId, provider '$sourceUsed')"
        }
    }

    return [pscustomobject]@{
        mode          = $mode
        source        = $sourceUsed
        eventId       = $EventId
        message       = $message
        writtenAtUtc  = $stamp
        record        = $record
        harnessChange = $harnessChange
        error         = $errorText
    }
}

function Remove-WpdControlledEventSource {
    <# Best-effort restoration of the machine: only a harness-registered source is removed. #>
    param([AllowNull()]$ControlledEvent)
    if ($null -eq $ControlledEvent) { return 'no controlled event was created' }
    if ($ControlledEvent.mode -ne 'registered-source') { return "nothing to clean up (mode=$($ControlledEvent.mode))" }

    $escapedSource = ([string]$ControlledEvent.source).Replace("'", "''")
    $child = @"
`$ErrorActionPreference = 'Stop'
`$sourceName = '$escapedSource'
if ([System.Diagnostics.EventLog]::SourceExists(`$sourceName)) {
    Remove-EventLog -Source `$sourceName -ErrorAction Stop
    'removed'
} else {
    'absent'
}
"@
    $removal = Invoke-WpdWindowsPowerShellChild -ScriptText $child
    if ($removal.ok -or $removal.raw -match 'removed') {
        return "removed harness-registered System-log source '$($ControlledEvent.source)'"
    }
    return "cleanup of source '$($ControlledEvent.source)' failed: $($removal.error)"
}

#endregion

#region monitored collection -----------------------------------------------------

function Start-WpdMonitoredCollection {
    <#
      Runs the consented collection on Windows PowerShell 5.1 and observes it
      while it runs:
        - process creation (system-wide evidence, classified per process inside
          the collector's own process tree),
        - network endpoints owned by the collector tree (netstat -ano, filtered
          by owning process id),
        - the token owner of the collector process.
      The monitors are the harness's instruments; the collector is never told
      about them and never sees them.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][int]$Duration,
        [Parameter(Mandatory = $true)][int]$MaxEvents,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][int]$Timeout
    )

    $wps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $wps
    $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode Collect -ConfirmLocalCollection -DurationSeconds {1} -MaxEventCount {2} -OutputDirectory "{3}"' -f `
        $ScriptPath, $Duration, $MaxEvents, $OutputDirectory
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = Split-Path -Parent $ScriptPath

    <#
      The collector child must be given a Windows PowerShell module path.
      PowerShell 7's PSModulePath makes a Windows PowerShell 5.1 child fail to
      autoload Get-FileHash ("The term 'Get-FileHash' is not recognized"), which
      breaks the artifact-hashing stage, so no manifest is written and the
      collector exits 1. Verified by probe run 35079147824 on windows-2022:
      a child started with the inherited PowerShell 7 module path could not
      resolve Get-FileHash, while the same child with the Windows PowerShell
      module directories could. The rest of the environment is copied verbatim
      so the collector sees exactly what the console step saw.
    #>
    $modulePathParts = New-Object System.Collections.ArrayList
    foreach ($scope in @('User', 'Machine')) {
        $scopeValue = [System.Environment]::GetEnvironmentVariable('PSModulePath', $scope)
        if ($scopeValue) {
            foreach ($part in ([string]$scopeValue).Split(';')) {
                if ($part) { [void]$modulePathParts.Add($part) }
            }
        }
    }
    foreach ($fallback in @(
            (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'),
            (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'))) {
        [void]$modulePathParts.Add($fallback)
    }
    $collectorModulePath = (@($modulePathParts | Select-Object -Unique) -join ';')

    foreach ($entry in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $psi.EnvironmentVariables[[string]$entry.Key] = [string]$entry.Value
    }
    $psi.EnvironmentVariables['PSModulePath'] = $collectorModulePath

    $sourceIdentifier = 'WpdLive0607ProcessStart'
    $monitorNotes = New-Object System.Collections.ArrayList
    $processCreations = New-Object System.Collections.ArrayList
    $connectionSamples = New-Object System.Collections.ArrayList
    $ownerSamples = New-Object System.Collections.ArrayList
    $monitorAvailable = $false
    try {
        Register-CimIndicationEvent -Query 'SELECT * FROM Win32_ProcessStartTrace' -SourceIdentifier $sourceIdentifier -ErrorAction Stop | Out-Null
        $monitorAvailable = $true
        [void]$monitorNotes.Add('Win32_ProcessStartTrace monitor registered (elevated console required); process creation is observed system-wide and classified per collector-tree membership')
    }
    catch {
        [void]$monitorNotes.Add("Win32_ProcessStartTrace monitor unavailable: $($_.Exception.Message)")
    }

    $process = [System.Diagnostics.Process]::Start($psi)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    $treePids = @{}
    $treePids[[int]$process.Id] = $true
    $treeProcessNames = @{}
    $treeProcessNames[[int]$process.Id] = 'powershell.exe'
    $connectionSampleCount = 0
    $deadline = (Get-Date).AddSeconds($Timeout)
    $lastOwner = $null

    while (-not $process.HasExited -and (Get-Date) -lt $deadline) {
        if ($monitorAvailable) {
            try {
                foreach ($eventRecord in @(Get-Event -SourceIdentifier $sourceIdentifier -ErrorAction SilentlyContinue)) {
                    $processIdValue = [int](Get-WpdProperty -InputObject $eventRecord.SourceEventArgs.NewEvent -Name 'ProcessID')
                    $parentIdValue = [int](Get-WpdProperty -InputObject $eventRecord.SourceEventArgs.NewEvent -Name 'ParentProcessID')
                    $processNameValue = [string](Get-WpdProperty -InputObject $eventRecord.SourceEventArgs.NewEvent -Name 'ProcessName')
                    Remove-Event -EventIdentifier $eventRecord.EventIdentifier -ErrorAction SilentlyContinue
                    if ($processIdValue -le 0) { continue }
                    $commandLine = $null
                    try {
                        $instance = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$processIdValue" -ErrorAction Stop
                        if ($null -ne $instance) { $commandLine = [string]$instance.CommandLine }
                    }
                    catch { }
                    [void]$processCreations.Add([pscustomobject]@{
                        atUtc          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                        processName    = $processNameValue
                        processId      = $processIdValue
                        parentProcessId = $parentIdValue
                        commandLine    = $commandLine
                    })
                    if ($treePids.ContainsKey($parentIdValue)) {
                        $treePids[$processIdValue] = $true
                        $treeProcessNames[$processIdValue] = $processNameValue
                    }
                }
            }
            catch {
                $note = "process-creation drain: $($_.Exception.Message)"
                if (-not $monitorNotes.Contains($note)) { [void]$monitorNotes.Add($note) }
            }
        }

        if ($connectionSampleCount -lt 400) {
            try {
                $netstatRows = ConvertFrom-WpdNetstat -Lines @(& netstat -ano 2>$null)
                $connectionSampleCount++
                foreach ($row in @($netstatRows)) {
                    $ownerId = 0
                    if (-not [int]::TryParse([string]$row.ProcessId, [ref]$ownerId)) { continue }
                    if (-not $treePids.ContainsKey($ownerId)) { continue }
                    [void]$connectionSamples.Add([pscustomobject]@{
                        atUtc         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                        protocol      = $row.Protocol
                        localAddress  = $row.LocalAddress
                        remoteAddress = $row.RemoteAddress
                        state         = $row.State
                        processId     = $ownerId
                    })
                }
            }
            catch {
                $note = "netstat sample: $($_.Exception.Message)"
                if (-not $monitorNotes.Contains($note)) { [void]$monitorNotes.Add($note) }
            }
        }

        try {
            $live = Get-Process -Id $process.Id -IncludeUserName -ErrorAction Stop
            $ownerName = [string]$live.UserName
            if ($ownerName -and $ownerName -ne $lastOwner) {
                [void]$ownerSamples.Add([pscustomobject]@{ atUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); pid = $process.Id; owner = $ownerName })
                $lastOwner = $ownerName
            }
        }
        catch { }

        if ($process.WaitForExit(500)) { break }
    }

    if ($monitorAvailable) {
        try {
            foreach ($eventRecord in @(Get-Event -SourceIdentifier $sourceIdentifier -ErrorAction SilentlyContinue)) {
                $processIdValue = [int](Get-WpdProperty -InputObject $eventRecord.SourceEventArgs.NewEvent -Name 'ProcessID')
                $parentIdValue = [int](Get-WpdProperty -InputObject $eventRecord.SourceEventArgs.NewEvent -Name 'ParentProcessID')
                $processNameValue = [string](Get-WpdProperty -InputObject $eventRecord.SourceEventArgs.NewEvent -Name 'ProcessName')
                Remove-Event -EventIdentifier $eventRecord.EventIdentifier -ErrorAction SilentlyContinue
                [void]$processCreations.Add([pscustomobject]@{
                    atUtc           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                    processName     = $processNameValue
                    processId       = $processIdValue
                    parentProcessId = $parentIdValue
                    commandLine     = $null
                })
                if ($treePids.ContainsKey($parentIdValue)) { $treePids[$processIdValue] = $true }
            }
        }
        catch { }
        try { Unregister-Event -SourceIdentifier $sourceIdentifier -Force -ErrorAction SilentlyContinue } catch { }
    }

    $timedOut = -not $process.HasExited
    if ($timedOut) {
        try { $process.Kill() } catch { }
        [void]$monitorNotes.Add("collector did not finish within ${Timeout}s and was killed")
    }
    if (-not $timedOut) { $process.WaitForExit() }
    $stdoutTask.Wait(10000) | Out-Null
    $stderrTask.Wait(10000) | Out-Null
    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    ("--- stdout ---`n{0}`n--- stderr ---`n{1}" -f $stdout, $stderr) | Set-Content -LiteralPath $LogPath -Encoding utf8

    $treeCreations = @()
    foreach ($creation in @($processCreations)) {
        if ($treePids.ContainsKey([int]$creation.processId)) {
            $match = Get-WpdBannedProcessMatch -ProcessName $creation.processName -CommandLine $creation.commandLine
            $treeCreations += [pscustomobject]@{
                atUtc           = $creation.atUtc
                processName     = $creation.processName
                processId       = $creation.processId
                parentProcessId = $creation.parentProcessId
                commandLine     = $creation.commandLine
                bannedMatches   = @($match)
            }
        }
    }

    $nonLocal = @()
    foreach ($sample in @($connectionSamples)) {
        if ($sample.protocol -ne 'TCP') { continue }
        if (-not (Test-WpdRemoteAddressIsLocal -RemoteAddress $sample.remoteAddress)) {
            $nonLocal += $sample
        }
    }

    return [pscustomobject]@{
        exitCode           = if ($timedOut) { $null } else { $process.ExitCode }
        pid                = $process.Id
        timedOut           = $timedOut
        stdout             = $stdout
        stderr             = $stderr
        logPath            = $LogPath
        modulePath         = $collectorModulePath
        monitorAvailable   = $monitorAvailable
        monitorNotes       = @($monitorNotes)
        processCreations   = @($processCreations)
        collectorTree      = @($treeCreations)
        connectionSamples  = @($connectionSamples)
        connectionSampleCount = $connectionSampleCount
        nonLocalConnections = @($nonLocal)
        ownerSamples       = @($ownerSamples)
    }
}

#endregion

#region case bodies --------------------------------------------------------------

$stagingRootFull = (New-Item -ItemType Directory -Force -Path $StagingRoot).FullName
$caseDirectory = (New-Item -ItemType Directory -Force -Path (Join-Path $stagingRootFull "$Case\$Label")).FullName
$logsDirectory = (New-Item -ItemType Directory -Force -Path (Join-Path $stagingRootFull 'logs')).FullName
$resultsDirectory = (New-Item -ItemType Directory -Force -Path (Join-Path $stagingRootFull 'results')).FullName

if (-not (Test-Path -LiteralPath $ToolkitScript -PathType Leaf)) {
    throw "PRECONDITION FAILED: toolkit script not found at '$ToolkitScript'"
}
$ToolkitScript = (Get-Item -LiteralPath $ToolkitScript).FullName
$toolkitHash = Get-WpdSha256 -Path $ToolkitScript

$preconditionNotes = New-Object System.Collections.ArrayList
$harnessChanges = New-Object System.Collections.ArrayList
$transcript = Join-Path $logsDirectory ("{0}-{1}-harness.log" -f $Case, $Label)
$stateBefore = $null
$stateAfter = $null
$stateDeltas = @()
$run = $null
$manifest = $null
$manifestEvidence = @()
$unlistedFiles = @()
$collectionErrors = @()
$artifactsOutside = @()
$caseOutcome = 'FAIL'
$outcomeReason = $null
$controlledEvent = $null
$controlledEventCleanup = 'not attempted'
$controlledRetained = $null
$eventEvidence = $null
$eventComparisonFile = $null
$liveEventCount = $null
$requestedBound = $null
$eventLogClearing = @()
$defenderSurface = $null
$manifestEventBlock = $null

Start-Transcript -LiteralPath $transcript -Force | Out-Null

Write-Output "=== $Case ($Label) ==="
Write-Output "toolkit script: $ToolkitScript"
Write-Output "toolkit sha256: $toolkitHash"

if (-not (Test-WpdElevated)) {
    [void]$preconditionNotes.Add('harness console is NOT elevated; both WPD-06 (controlled System event write) and WPD-07 require an elevated console for their preconditions')
}

$environment = Get-WpdEnvironmentRecord

try {
    $stateBefore = Get-WpdState

    if ($Case -eq 'WPD-06') {
        # ---- matrix WPD-06 ----------------------------------------------------
        # Action: create a controlled application error/event, then run
        # collection. Expectation: the event summary is bounded by
        # -MaxEventCount and contains the recent System-log evidence.
        Add-WpdAssertion -Name 'precondition-elevated-console' -Expected 'harness console is elevated' `
            -Observed (Test-WpdElevated) -Outcome (Test-WpdElevated)

        $lookbackStart = (Get-Date).AddHours(-24)
        $liveEventCount = Get-WpdLiveEventCount -LogName 'System' -StartTime $lookbackStart -Cap 5000
        [void]$preconditionNotes.Add("System log records in the last 24h at harness start: $liveEventCount")
        Add-WpdAssertion -Name 'precondition-enough-recent-system-events' -Expected 'at least 11 System-log records in the last 24h so a bounded newest-first summary is a strict subset' `
            -Observed $liveEventCount -Outcome ($liveEventCount -ge 11)

        if ($liveEventCount -lt 11) {
            $caseOutcome = 'NOT RUN'
            $outcomeReason = "System log carries only $liveEventCount record(s) in the last 24 hours; -MaxEventCount cannot be exercised as a bound on this host"
        }
        else {
            $requestedBound = [Math]::Min($MaxEventCount, [Math]::Max(10, $liveEventCount - 1))
            Write-Output "requested -MaxEventCount bound: $requestedBound (matrix bound ceiling $MaxEventCount, live 24h records $liveEventCount)"

            $controlledEvent = New-WpdControlledSystemEvent -EventId $ControlledEventId -SourceName $ControlledEventSource
            if ($controlledEvent.harnessChange) { [void]$harnessChanges.Add($controlledEvent.harnessChange) }
            Write-Output "controlled event mode=$($controlledEvent.mode) source=$($controlledEvent.source) id=$($ControlledEventId)"
            Add-WpdAssertion -Name 'controlled-system-event-created' -Expected "a System-log event with id $ControlledEventId is readable independently after the harness wrote it" `
                -Observed $(if ($controlledEvent.record) { "$($controlledEvent.record.ProviderName) id=$($controlledEvent.record.Id) at $(Get-WpdUtcStamp -Value $controlledEvent.record.TimeCreated)" } else { "write failed: $($controlledEvent.error)" }) `
                -Outcome ($null -ne $controlledEvent.record)

            $collectStartedAt = Get-Date
            $run = Start-WpdMonitoredCollection -ScriptPath $ToolkitScript -OutputDirectory $caseDirectory `
                -Duration $DurationSeconds -MaxEvents $requestedBound `
                -LogPath (Join-Path $logsDirectory "$Case-$Label-console.log") -Timeout $TimeoutSeconds
            $collectEndedAt = Get-Date
            $stateAfter = Get-WpdState
            $stateDeltas = @(Compare-WpdState -Before $stateBefore -After $stateAfter)

            Add-WpdAssertion -Name 'collection-exit-code' -Expected '0' -Observed $run.exitCode -Outcome ($run.exitCode -eq 0)
            Add-WpdAssertion -Name 'process-creation-monitor-available' -Expected 'Win32_ProcessStartTrace monitor registered for the collection window' `
                -Observed $run.monitorAvailable -Outcome ($run.monitorAvailable)
            Add-WpdAssertion -Name 'collector-child-module-path-is-windows-powershell' -Expected 'the collector child is given the Windows PowerShell 5.1 module directories so its cmdlet autoloading works' `
                -Observed $run.modulePath -Outcome ([string]$run.modulePath -match 'WindowsPowerShell\\v1\.0\\Modules')

            $manifest = Get-WpdManifest -OutputDirectory $caseDirectory
            Add-WpdAssertion -Name 'manifest-present' -Expected 'diagnostic-manifest.json parses as JSON' `
                -Observed $(if ($null -ne $manifest) { 'parsed' } else { 'missing or unparseable' }) -Outcome ($null -ne $manifest)

            $artifactPath = Join-Path $caseDirectory 'system-events-last-24-hours.json'
            $artifactExists = Test-Path -LiteralPath $artifactPath -PathType Leaf
            $artifactRows = @()
            if ($artifactExists) {
                try { $artifactRows = @(Get-Content -LiteralPath $artifactPath -Raw | ConvertFrom-Json) } catch { $artifactRows = @() }
            }
            Add-WpdAssertion -Name 'event-summary-artifact-present' -Expected 'system-events-last-24-hours.json exists and is non-empty' `
                -Observed $(if ($artifactExists) { "@($($artifactRows.Count)) rows" } else { 'absent' }) -Outcome ($artifactExists -and $artifactRows.Count -gt 0)

            if ($null -ne $manifest) {
                $manifestEvidence = @(Get-WpdManifestEvidence -OutputDirectory $caseDirectory -Manifest $manifest)
                $listedEventArtifact = @($manifestEvidence | Where-Object { $_.name -eq 'system-events-last-24-hours.json' })
                Add-WpdAssertion -Name 'event-summary-listed-in-manifest' -Expected 'the event summary is a hashed manifest artifact' `
                    -Observed $(if ($listedEventArtifact.Count -gt 0) { "$($listedEventArtifact[0].declaredSha256.Substring(0,12)) hashMatches=$($listedEventArtifact[0].hashMatches)" } else { 'not listed' }) `
                    -Outcome ($listedEventArtifact.Count -eq 1)
                $unlistedFiles = @(Get-WpdUnlistedFiles -OutputDirectory $caseDirectory -Manifest $manifest)
                Add-WpdAssertion -Name 'every-emitted-data-artifact-is-listed' -Expected 'no unlisted file in the case folder' `
                    -Observed $(if ($unlistedFiles.Count -eq 0) { 'none unlisted' } else { $unlistedFiles -join ', ' }) -Outcome ($unlistedFiles.Count -eq 0)
                $artifactsOutside = @(Get-WpdArtifactsOutsideDirectory -ManifestEvidence $manifestEvidence -OutputDirectory $caseDirectory)
                Add-WpdAssertion -Name 'artifacts-confined-to-case-directory' -Expected 'every collected artifact is written inside the case folder (no persistence elsewhere)' `
                    -Observed $(if ($artifactsOutside.Count -eq 0) { 'all inside case folder' } else { $artifactsOutside -join ', ' }) -Outcome ($artifactsOutside.Count -eq 0)
                $collectionErrors = @(Get-WpdCollectionErrorRecords -Manifest $manifest)
                $safetyCheck = Get-WpdSafetyDeclarationCheck -Manifest $manifest
                Add-WpdAssertion -Name 'safety-declarations-hold' -Expected 'localOnly/readOnly true, automaticUpload/Remediation/LogClearing false, explicit consent required, and secretsCollected false when the build declares a privacy block' `
                    -Observed $safetyCheck.observed -Outcome $safetyCheck.ok
                $remoteStatus = 'absent'
                if ($null -ne $manifest.PSObject.Properties['remote'] -and $null -ne $manifest.remote) { $remoteStatus = [string]$manifest.remote.status }
                Add-WpdAssertion -Name 'no-remote-transmission' -Expected 'manifest.remote.status is not completed (no -ConfirmRemoteCollection was passed)' `
                    -Observed $remoteStatus -Outcome ($remoteStatus -ne 'completed')
                $manifestEventBlock = $manifest.systemEventLog
                if ($null -ne $manifestEventBlock) {
                    Add-WpdAssertion -Name 'manifest-system-event-log-block-populated' -Expected 'enabled/recordCount/pulledCount/skippedUnrenderableCount are all reported' `
                        -Observed ("enabled={0} recordCount={1} pulledCount={2} skippedUnrenderableCount={3}" -f $manifestEventBlock.enabled, $manifestEventBlock.recordCount, $manifestEventBlock.pulledCount, $manifestEventBlock.skippedUnrenderableCount) `
                        -Outcome ($null -ne $manifestEventBlock.enabled -and $null -ne $manifestEventBlock.recordCount -and $null -ne $manifestEventBlock.pulledCount -and $null -ne $manifestEventBlock.skippedUnrenderableCount)
                    Add-WpdAssertion -Name 'artifact-row-count-matches-manifest-pulled-count' -Expected 'the event artifact row count equals manifest.systemEventLog.pulledCount' `
                        -Observed ("artifact={0} pulledCount={1}" -f $artifactRows.Count, $manifestEventBlock.pulledCount) `
                        -Outcome ($null -ne $manifestEventBlock.pulledCount -and [int]$manifestEventBlock.pulledCount -eq $artifactRows.Count)
                }
                else {
                    Add-WpdAssertion -Name 'manifest-system-event-log-block-populated' -Expected 'systemEventLog block present' -Observed 'absent' -Outcome $false
                }
            }

            # Independent Event Viewer query for the same window, mirroring the
            # collector's bounded newest-first read.
            $liveRows = @()
            if ($artifactRows.Count -gt 0) {
                $oldestArtifact = ($artifactRows | ForEach-Object { [datetime]$_.TimeCreated } | Sort-Object | Select-Object -First 1)
                $liveRows = @(Get-WpdLiveEventRows -LogName 'System' -StartTime $lookbackStart -MaxRows 2000 -MinimumUtc $oldestArtifact)
            }
            $eventEvidence = Compare-WpdEventEvidence -ArtifactRows $artifactRows -LiveRows $liveRows -Bound $requestedBound -LookbackStartUtc $lookbackStart
            $eventComparisonFile = Join-Path $logsDirectory "$Case-$Label-event-comparison.json"
            Write-WpdJsonFile -InputObject ([ordered]@{
                case                = $Case
                label               = $Label
                requestedBound      = $requestedBound
                live24hCount        = $liveEventCount
                comparison          = $eventEvidence
                artifactRows        = @($artifactRows)
                independentLiveRows = @($liveRows)
                recordedAtUtc       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            }) -Path $eventComparisonFile

            Add-WpdAssertion -Name 'event-summary-bounded-by-max-event-count' -Expected "no more than the requested bound of $requestedBound rows" `
                -Observed ("$($eventEvidence.artifactCount) rows (bound $requestedBound)") -Outcome ($eventEvidence.artifactCount -le $requestedBound)
            Add-WpdAssertion -Name 'bounded-truncation-exercised' -Expected 'the live 24h log holds more records than the bound, so the summary is a strict subset and the bound really truncated' `
                -Observed ("live24h=$liveEventCount artifact=$($eventEvidence.artifactCount) bound=$requestedBound") -Outcome ($liveEventCount -gt $requestedBound)
            Add-WpdAssertion -Name 'event-summary-newest-first' -Expected 'artifact rows are ordered newest-first' `
                -Observed $eventEvidence.orderedNewestFirst -Outcome ($eventEvidence.orderedNewestFirst)
            # Identical rows (same id, provider, second and message) are recorded
            # as evidence but are not a failure: a busy host legitimately logs
            # repeated identical events, and the bound only has to be honoured.
            Add-WpdAssertion -Name 'every-artifact-event-exists-in-live-system-log' -Expected 'each collected row is corroborated by an independent Event Viewer read of the live System log' `
                -Observed $(if ($eventEvidence.missingFromLiveLog.Count -eq 0) { "all $($eventEvidence.artifactCount) rows corroborated" } else { "missing: $($eventEvidence.missingFromLiveLog -join ', ')" }) `
                -Outcome ($eventEvidence.missingFromLiveLog.Count -eq 0)
            Add-WpdAssertion -Name 'artifact-events-inside-24h-lookback' -Expected 'no collected row predates the 24h lookback the collector declares' `
                -Observed ("rowsOutsideLookback=$($eventEvidence.rowsOutsideLookback) oldest=$($eventEvidence.oldestArtifactUtc) newest=$($eventEvidence.newestArtifactUtc)") `
                -Outcome ($eventEvidence.rowsOutsideLookback -eq 0)

            $newestCrossApi = Get-WpdNewestEventCrossApi -LogName 'System'
            $newestArtifactRow = $null
            $newestArtifactTime = $null
            if ($artifactRows.Count -gt 0) {
                $newestArtifactRow = @($artifactRows | Sort-Object -Property @{ Expression = { [datetime]$_.TimeCreated } } -Descending)[0]
                $newestArtifactTime = ([datetime]$newestArtifactRow.TimeCreated).ToUniversalTime()
            }
            # Anchor check through a second event API: the live log must be at
            # least as new as the summary's newest row (newer traffic after the
            # collection is normal), and the summary's newest row itself is
            # corroborated by the windowed row comparison above.
            $crossApiAnchored = ($null -ne $newestCrossApi -and $null -ne $newestArtifactTime -and
                ([datetime]$newestCrossApi.TimeCreated).ToUniversalTime() -ge $newestArtifactTime)
            Add-WpdAssertion -Name 'artifact-anchored-to-live-log-through-second-api' -Expected 'the live System log read through Get-WinEvent is at least as new as the summary newest row, so the bounded summary is anchored at the live log head' `
                -Observed $(if ($newestArtifactRow -and $newestCrossApi) { "artifact newest=$(Get-WpdUtcStamp -Value $newestArtifactRow.TimeCreated) ($($newestArtifactRow.ProviderName)/$($newestArtifactRow.Id)); live newest=$(Get-WpdUtcStamp -Value $newestCrossApi.TimeCreated) ($($newestCrossApi.ProviderName)/$($newestCrossApi.Id))" } else { 'one side unavailable' }) `
                -Outcome $crossApiAnchored

            $controlledRetained = $false
            if ($controlledEvent.record -and $artifactRows.Count -gt 0) {
                $controlledKey = Get-WpdEventKey -Row $controlledEvent.record
                $controlledRetained = @($artifactRows | Where-Object { (Get-WpdEventKey -Row $_) -eq $controlledKey }).Count -gt 0
            }
            # A controlled event displaced by newer traffic is still honest
            # evidence as long as the displacement is independently measurable:
            # count the System rows written after it and confirm they alone
            # exceed the bound.
            $displacement = $null
            if (-not $controlledRetained -and $controlledEvent.record) {
                $displacement = Get-WpdLiveEventCount -LogName 'System' -StartTime ([datetime]$controlledEvent.record.TimeCreated) -Cap 5000
            }
            Add-WpdAssertion -Name 'controlled-event-retained-or-displacement-explained' -Expected 'the controlled event is inside the bounded summary, or the newest-first bound demonstrably displaced it with at least that many newer System records' `
                -Observed $(if ($controlledRetained) { 'retained in artifact' } elseif ($null -ne $displacement) { "displaced; $displacement System records written at/after it versus bound $requestedBound" } else { 'no controlled event record was readable' }) `
                -Outcome ($controlledRetained -or ($null -ne $displacement -and $displacement -gt $requestedBound))

            Add-WpdAssertion -Name 'no-configuration-change-or-persistence' -Expected 'no strict-configuration delta across the collection' `
                -Observed $(if ($stateDeltas.Count -eq 0) { 'no delta' } else { ($stateDeltas | ForEach-Object { $_.surface }) -join ', ' }) `
                -Outcome ($stateDeltas.Count -eq 0)

            if ($run.exitCode -eq 0 -and $eventEvidence.artifactCount -gt 0 -and $eventEvidence.artifactCount -le $requestedBound -and
                $eventEvidence.missingFromLiveLog.Count -eq 0 -and $eventEvidence.orderedNewestFirst -and $eventEvidence.rowsOutsideLookback -eq 0 -and
                $stateDeltas.Count -eq 0 -and $unlistedFiles.Count -eq 0 -and $artifactsOutside.Count -eq 0 -and $crossApiAnchored -and
                ($controlledRetained -or ($null -ne $displacement -and $displacement -gt $requestedBound))) {
                $caseOutcome = 'PASS'
            }
        }
    }
    elseif ($Case -eq 'WPD-07') {
        # ---- matrix WPD-07 ----------------------------------------------------
        # Action: watch Defender, startup entries, event-log sizes and system
        # configuration before/after. Expectation: no exclusions, startup edits,
        # log clearing, repair actions, uploads or policy changes.
        Add-WpdAssertion -Name 'precondition-elevated-console' -Expected 'harness console is elevated (Defender/startup/log-state reads and the process monitor require it)' `
            -Observed (Test-WpdElevated) -Outcome (Test-WpdElevated)

        $defenderPreferences = $stateBefore.strict['defenderPreferences']
        $defenderPreferencesAvailable = $false
        if ($null -ne $defenderPreferences) {
            $availableProperty = Get-WpdProperty -InputObject $defenderPreferences -Name 'available'
            $defenderPreferencesAvailable = ($availableProperty -eq $true)
        }
        $defenderRegistryAvailable = @($stateBefore.strict['defenderRegistry']).Count -gt 0
        $defenderServiceAvailable = @($stateBefore.strict['defenderService']).Count -gt 0
        $defenderSurface = [pscustomobject]@{
            preferencesAvailable = $defenderPreferencesAvailable
            registryKeysObserved = @($stateBefore.strict['defenderRegistry']).Count
            servicesObserved     = @($stateBefore.strict['defenderService']).Count
        }
        Add-WpdAssertion -Name 'precondition-defender-surface-captured' -Expected 'at least one Defender surface (Get-MpPreference, the Defender registry keys, or the WinDefend service) was captured before and after' `
            -Observed ("preferences=$defenderPreferencesAvailable registryKeys=$($defenderSurface.registryKeysObserved) services=$($defenderSurface.servicesObserved)") `
            -Outcome ($defenderPreferencesAvailable -or $defenderRegistryAvailable -or $defenderServiceAvailable)

        Write-WpdJsonFile -InputObject $stateBefore -Path (Join-Path $logsDirectory "$Case-$Label-configuration-before.json")

        $run = Start-WpdMonitoredCollection -ScriptPath $ToolkitScript -OutputDirectory $caseDirectory `
            -Duration $DurationSeconds -MaxEvents $MaxEventCount `
            -LogPath (Join-Path $logsDirectory "$Case-$Label-console.log") -Timeout $TimeoutSeconds

        $stateAfter = Get-WpdState
        Write-WpdJsonFile -InputObject $stateAfter -Path (Join-Path $logsDirectory "$Case-$Label-configuration-after.json")

        $stateDeltas = @(Compare-WpdState -Before $stateBefore -After $stateAfter)
        $deltaSurfaces = @($stateDeltas | ForEach-Object { $_.surface })

        Add-WpdAssertion -Name 'collection-exit-code' -Expected '0' -Observed $run.exitCode -Outcome ($run.exitCode -eq 0)
        Add-WpdAssertion -Name 'process-creation-monitor-available' -Expected 'Win32_ProcessStartTrace monitor registered for the collection window' `
            -Observed $run.monitorAvailable -Outcome ($run.monitorAvailable)
        Add-WpdAssertion -Name 'collector-child-module-path-is-windows-powershell' -Expected 'the collector child is given the Windows PowerShell 5.1 module directories so its cmdlet autoloading works' `
            -Observed $run.modulePath -Outcome ([string]$run.modulePath -match 'WindowsPowerShell\\v1\.0\\Modules')

        $manifest = Get-WpdManifest -OutputDirectory $caseDirectory
        Add-WpdAssertion -Name 'manifest-present' -Expected 'diagnostic-manifest.json parses as JSON' `
            -Observed $(if ($null -ne $manifest) { 'parsed' } else { 'missing or unparseable' }) -Outcome ($null -ne $manifest)

        $defenderSettingDelta = @($stateDeltas | Where-Object { $_.surface -in @('defenderPreferences', 'defenderService') })
        Add-WpdAssertion -Name 'no-defender-exclusion-or-setting-delta' -Expected 'Defender exclusions, protection switches and service state are identical before/after (no exclusions added, nothing disabled)' `
            -Observed $(if ($defenderSettingDelta.Count -eq 0) { 'no delta' } else { ($defenderSettingDelta | ForEach-Object { $_.surface }) -join ', ' }) `
            -Outcome ($defenderSettingDelta.Count -eq 0)

        $defenderRegistryDelta = @($stateDeltas | Where-Object { $_.surface -eq 'defenderRegistry' })
        Add-WpdAssertion -Name 'no-defender-policy-registry-delta' -Expected 'HKLM Defender configuration/policy keys are byte-identical before/after' `
            -Observed $(if ($defenderRegistryDelta.Count -eq 0) { 'no delta' } else { 'registry changed' }) -Outcome ($defenderRegistryDelta.Count -eq 0)

        $startupDelta = @($stateDeltas | Where-Object { $_.surface -in @('runKeys', 'startupFolder', 'startupApproved', 'winlogon') })
        Add-WpdAssertion -Name 'no-startup-entry-delta' -Expected 'Run/RunOnce keys, Startup folders, StartupApproved and Winlogon values are identical before/after (no startup edits, no autostart persistence)' `
            -Observed $(if ($startupDelta.Count -eq 0) { 'no delta' } else { ($startupDelta | ForEach-Object { $_.surface }) -join ', ' }) -Outcome ($startupDelta.Count -eq 0)

        $eventLogConfigDelta = @($stateDeltas | Where-Object { $_.surface -eq 'eventLogs' })
        Add-WpdAssertion -Name 'no-event-log-configuration-delta' -Expected 'event-log sizes, retention modes and enabled state are identical before/after' `
            -Observed $(if ($eventLogConfigDelta.Count -eq 0) { 'no delta' } else { 'log configuration changed' }) -Outcome ($eventLogConfigDelta.Count -eq 0)

        $eventLogClearing = @(Get-WpdEventLogClearingVerdict -BeforeLogs $stateBefore.recordOnly['eventLogCounters'] -AfterLogs $stateAfter.recordOnly['eventLogCounters'])
        $clearedLogs = @($eventLogClearing | Where-Object { $_.cleared -eq $true })
        Add-WpdAssertion -Name 'no-event-log-clearing' -Expected 'no log lost records: oldest record numbers never move backwards and no log shrank in records' `
            -Observed (($eventLogClearing | ForEach-Object { "$($_.log) old:$($_.beforeOldest)->$($_.afterOldest) records:$($_.beforeRecordCount)->$($_.afterRecordCount)" }) -join ' ; ') `
            -Outcome ($clearedLogs.Count -eq 0)

        $treeProcesses = @($run.collectorTree)
        $treeBanned = @($treeProcesses | Where-Object { @($_.bannedMatches).Count -gt 0 })
        Add-WpdAssertion -Name 'no-repair-or-remediation-tool-in-collector-tree' -Expected 'no repair, scan, log-clearing, policy or transfer tooling launched by the collector' `
            -Observed $(if ($treeBanned.Count -eq 0) { "none; collector tree spawned $(@($treeProcesses | ForEach-Object { $_.processName } | Select-Object -Unique) -join ', ')" } else { ($treeBanned | ForEach-Object { "$($_.processName)[$(@($_.bannedMatches) -join ',')]" }) -join ' ; ' }) `
            -Outcome ($treeBanned.Count -eq 0)

        $nonLocal = @($run.nonLocalConnections)
        Add-WpdAssertion -Name 'no-non-loopback-connection-from-collector' -Expected 'no TCP endpoint owned by the collector tree leaves the machine (no upload/transmission)' `
            -Observed $(if ($nonLocal.Count -eq 0) { "no non-loopback endpoint in $($run.connectionSampleCount) netstat samples" } else { ($nonLocal | ForEach-Object { "$($_.remoteAddress)" }) -join ', ' }) `
            -Outcome ($nonLocal.Count -eq 0)

        if ($null -ne $manifest) {
            $manifestEvidence = @(Get-WpdManifestEvidence -OutputDirectory $caseDirectory -Manifest $manifest)
            $unlistedFiles = @(Get-WpdUnlistedFiles -OutputDirectory $caseDirectory -Manifest $manifest)
            $artifactsOutside = @(Get-WpdArtifactsOutsideDirectory -ManifestEvidence $manifestEvidence -OutputDirectory $caseDirectory)
            $collectionErrors = @(Get-WpdCollectionErrorRecords -Manifest $manifest)
            Add-WpdAssertion -Name 'every-emitted-data-artifact-is-listed' -Expected 'no unlisted file in the case folder' `
                -Observed $(if ($unlistedFiles.Count -eq 0) { 'none unlisted' } else { $unlistedFiles -join ', ' }) -Outcome ($unlistedFiles.Count -eq 0)
            Add-WpdAssertion -Name 'artifacts-confined-to-case-directory' -Expected 'every collected artifact is written inside the case folder' `
                -Observed $(if ($artifactsOutside.Count -eq 0) { 'all inside case folder' } else { $artifactsOutside -join ', ' }) -Outcome ($artifactsOutside.Count -eq 0)
            $safetyCheck = Get-WpdSafetyDeclarationCheck -Manifest $manifest
            Add-WpdAssertion -Name 'safety-declarations-hold' -Expected 'localOnly/readOnly true, automaticUpload/Remediation/LogClearing false, explicit consent required, and secretsCollected false when the build declares a privacy block' `
                -Observed $safetyCheck.observed -Outcome $safetyCheck.ok
            $remoteStatus = 'absent'
            if ($null -ne $manifest.PSObject.Properties['remote'] -and $null -ne $manifest.remote) { $remoteStatus = [string]$manifest.remote.status }
            Add-WpdAssertion -Name 'no-remote-transmission-declared' -Expected 'manifest.remote.status is not completed (no -ConfirmRemoteCollection was passed)' `
                -Observed $remoteStatus -Outcome ($remoteStatus -ne 'completed')
        }

        Add-WpdAssertion -Name 'no-configuration-change-or-persistence' -Expected 'no strict-configuration delta at all across the collection' `
            -Observed $(if ($stateDeltas.Count -eq 0) { 'no delta' } else { ($deltaSurfaces -join ', ') }) -Outcome ($stateDeltas.Count -eq 0)

        if ($run.exitCode -eq 0 -and $stateDeltas.Count -eq 0 -and $clearedLogs.Count -eq 0 -and $treeBanned.Count -eq 0 -and
            $nonLocal.Count -eq 0 -and $unlistedFiles.Count -eq 0 -and $artifactsOutside.Count -eq 0 -and $run.monitorAvailable) {
            $caseOutcome = 'PASS'
        }
    }
}
catch {
    $caseOutcome = 'FAIL'
    [void]$script:wpdFailures.Add("harness exception: $($_.Exception.Message)")
    Write-Output "harness exception: $($_.Exception.Message)"
    Write-Output $_.ScriptStackTrace
}
finally {
    $controlledEventCleanup = Remove-WpdControlledEventSource -ControlledEvent $controlledEvent
    Write-Output "controlled-event cleanup: $controlledEventCleanup"

    $result = [ordered]@{
        case                 = $Case
        label                = $Label
        verdict              = $caseOutcome
        outcomeReason        = $outcomeReason
        harness              = 'tests/live/Invoke-WpdLiveCase0607.ps1'
        recordedAtUtc        = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        matrixReference      = 'docs/windows-live-test-matrix.md'
        matrixExpectation    = if ($Case -eq 'WPD-06') {
            'Event summary should be bounded by -MaxEventCount and contain the recent System-log evidence when accessible.'
        }
        else {
            'No exclusions, startup edits, log clearing, repair actions, uploads, or policy changes occur.'
        }
        toolkit              = [ordered]@{
            path   = $ToolkitScript
            sha256 = $toolkitHash
            label  = $Label
        }
        environment          = $environment
        preconditions        = [ordered]@{
            notes                   = @($preconditionNotes)
            harnessChanges          = @($harnessChanges)
            durationSeconds         = $DurationSeconds
            maxEventCountRequested  = $MaxEventCount
            maxEventCountUsed       = if ($null -ne $requestedBound) { $requestedBound } else { $MaxEventCount }
            liveSystemEventsLast24h = $liveEventCount
            stagingRoot             = $stagingRootFull
            caseDirectory           = $caseDirectory
        }
        collection           = if ($null -ne $run) {
            [ordered]@{
                exitCode  = $run.exitCode
                pid       = $run.pid
                timedOut  = $run.timedOut
                childModulePath = $run.modulePath
                consoleLog = $run.logPath
            }
        } else { $null }
        eventEvidence        = $eventEvidence
        eventComparisonFile  = $eventComparisonFile
        controlledEvent      = if ($null -ne $controlledEvent) {
            [ordered]@{
                mode               = $controlledEvent.mode
                source             = $controlledEvent.source
                eventId            = $controlledEvent.eventId
                writtenAtUtc       = $controlledEvent.writtenAtUtc
                retainedInArtifact = $controlledRetained
                record             = $controlledEvent.record
                cleanup            = $controlledEventCleanup
            }
        } else { $null }
        manifestEventBlock   = $manifestEventBlock
        manifestArtifacts    = $manifestEvidence
        unlistedFiles        = $unlistedFiles
        artifactsOutsideCase = $artifactsOutside
        collectionErrors     = $collectionErrors
        configurationDeltas  = @($stateDeltas)
        eventLogClearing     = @($eventLogClearing)
        defenderSurface      = $defenderSurface
        configurationStrictBefore = if ($stateBefore) { $stateBefore.strict } else { $null }
        configurationStrictAfter  = if ($stateAfter) { $stateAfter.strict } else { $null }
        configurationRecordOnlyBefore = if ($stateBefore) { $stateBefore.recordOnly } else { $null }
        configurationRecordOnlyAfter  = if ($stateAfter) { $stateAfter.recordOnly } else { $null }
        monitors             = if ($null -ne $run) {
            [ordered]@{
                processCreationMonitorAvailable = $run.monitorAvailable
                processCreationMonitorNotes     = @($run.monitorNotes)
                processCreationsObserved        = @($run.processCreations).Count
                collectorTreeProcesses          = @($run.collectorTree)
                connectionSamples               = $run.connectionSampleCount
                nonLocalConnections             = @($run.nonLocalConnections)
                ownerSamples                    = @($run.ownerSamples)
                sampleOfConnectionEndpoints     = @($run.connectionSamples | Select-Object -First 20)
            }
        } else { $null }
        assertions           = @($script:wpdAssertions)
        failures             = @($script:wpdFailures)
        harnessLog           = $transcript
        sanitization         = @(
            'No credentials are recorded: the harness creates no account and no secret for these cases.',
            'The controlled event message is harness-authored text; it contains no user data, path or identifier beyond the UTC timestamp.',
            'Defender exclusion lists, startup entries and registry values are recorded as SHA-256 fingerprints, so no machine-specific path or value text is published.',
            'Raw event-log rows stay in the case folder on the runner; only the comparison summary is published.',
            'Harness-generated configuration snapshots (configuration-before/after.json) are uploaded as evidence for the test rig, not as collected user data.'
        )
    }

    $resultPath = Join-Path $resultsDirectory ("{0}-{1}.json" -f $Case, $Label)
    try { Stop-Transcript | Out-Null } catch { }
    Write-WpdJsonFile -InputObject $result -Path $resultPath

    Write-Output "RESULT $Case [$Label]: $caseOutcome ($resultPath)"
    Write-Output ("assertions: {0} pass / {1} fail" -f (@($script:wpdAssertions | Where-Object { $_.outcome -eq 'pass' }).Count), ($script:wpdFailures.Count))
    foreach ($failure in $script:wpdFailures) { Write-Output "FAILURE: $failure" }
}

if ($caseOutcome -eq 'PASS') { exit 0 }
if ($caseOutcome -eq 'NOT RUN') { exit 2 }
exit 1

#endregion
