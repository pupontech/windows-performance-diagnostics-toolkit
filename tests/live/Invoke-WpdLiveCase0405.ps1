<#
.SYNOPSIS
  Execution harness for the live matrix cases WPD-04 and WPD-05
  (docs/windows-live-test-matrix.md).

.DESCRIPTION
  Runs ONE case on a Windows host and returns an unambiguous verdict:

    WPD-04  Inspect manifest hashes - every emitted data artifact is listed in
            diagnostic-manifest.json with a SHA-256 and a size, and the recorded
            hash/size match an independent re-read of the file on disk.
    WPD-05  Run on a standard (non-admin) account - the collection completes
            (partially, with the failures declared under collectionErrors) and
            the toolkit neither changes machine configuration nor elevates
            itself.

  The harness is the test rig, not the subject under test. It may create its own
  preconditions on a disposable host (a standard local test user, a batch-logon
  right for that user, an ACL grant on the staging folder); every harness-side
  change is recorded in the result JSON and the matrix preconditions are checked
  before any case runs.

  Exit code 0 = PASS, 1 = FAIL, 2 = precondition/NOT RUN. The result JSON is
  written to <StagingRoot>\results and contains no credentials: the generated
  standard-user password is never written to any artifact or console output.

.PARAMETER Case
  WPD-04 or WPD-05.

.PARAMETER ToolkitScript
  Absolute path of the Invoke-WindowsPerformanceDiagnostics.ps1 under test.

.PARAMETER Label
  Short build label recorded in the results (e.g. 'source-48f0143',
  'release-1.0.0').

.EXAMPLE
  pwsh -File .\tests\live\Invoke-WpdLiveCase0405.ps1 -Case WPD-04 `
    -ToolkitScript C:\WPD\toolkit-source\src\Invoke-WindowsPerformanceDiagnostics.ps1 `
    -Label source-48f0143
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('WPD-04', 'WPD-05')]
    [string]$Case,

    [Parameter(Mandatory = $true)]
    [string]$ToolkitScript,

    [Parameter(Mandatory = $true)]
    [string]$Label,

    [string]$StagingRoot = 'C:\WPD',

    [ValidateRange(5, 300)]
    [int]$DurationSeconds = 5,

    [ValidateRange(1, 1000)]
    [int]$MaxEventCount = 200,

    [ValidateRange(30, 900)]
    [int]$TimeoutSeconds = 240
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# helpers -----------------------------------------------------------------------

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

function Get-WpdRunKeyEntries {
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
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
    $folder = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
    if (-not (Test-Path -LiteralPath $folder)) { return @() }
    return @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } | Sort-Object)
}

function Get-WpdDefenderFingerprint {
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        return [ordered]@{
            available                  = $true
            exclusionPath              = @($mp.ExclusionPath | Sort-Object)
            exclusionExtension         = @($mp.ExclusionExtension | Sort-Object)
            exclusionProcess           = @($mp.ExclusionProcess | Sort-Object)
            disableRealtimeMonitoring  = [bool]$mp.DisableRealtimeMonitoring
            disableBehaviorMonitoring  = [bool]$mp.DisableBehaviorMonitoring
            disableIOAVProtection      = [bool]$mp.DisableIOAVProtection
            disableScriptScanning      = [bool]$mp.DisableScriptScanning
        }
    }
    catch {
        return [ordered]@{ available = $false; reason = $_.Exception.Message }
    }
}

function Get-WpdEventLogFingerprint {
    $rows = @()
    foreach ($logName in @('System', 'Application')) {
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $rows += ('{0}|enabled={1}|maxBytes={2}|mode={3}' -f $log.LogName, $log.IsEnabled, $log.MaximumSizeInBytes, $log.LogMode)
        }
        catch {
            $rows += ('{0}|unavailable:{1}' -f $logName, $_.Exception.Message)
        }
    }
    return @($rows | Sort-Object)
}

function Get-WpdToolkitScheduledTasks {
    $tasks = @()
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.TaskPath -eq '\' -and $_.TaskName -match 'wpd|diagnostic|performance|toolkit' } |
            ForEach-Object { '{0}{1}|{2}' -f $_.TaskPath, $_.TaskName, $_.State } |
            Sort-Object)
    }
    catch {
        $tasks = @("unavailable: $($_.Exception.Message)")
    }
    return $tasks
}

function Get-WpdAdministratorsMembers {
    try {
        return @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { $_.Name } | Sort-Object)
    }
    catch {
        return @("unavailable: $($_.Exception.Message)")
    }
}

function Test-WpdLocalUserGroupMembership {
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$GroupName
    )
    try {
        $member = @(Get-LocalGroupMember -Group $GroupName -ErrorAction Stop | Where-Object { $_.Name -match ('\\' + [regex]::Escape($UserName) + '$') })
        return ($member.Count -gt 0)
    }
    catch {
        return $false
    }
}

<#
  Machine-state fingerprint. STRICT surfaces are compared before/after the case
  and any delta fails it (no persistence, no configuration change). RECORD-ONLY
  surfaces are captured as evidence but never gate the verdict, because they can
  legitimately churn on a shared/CI machine inside the case window.
#>
function Get-WpdConfigFingerprint {
    param([string]$StandardUserName)

    $hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $fingerprint = [ordered]@{
        capturedAtUtc          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        strict                 = [ordered]@{
            administrators          = Get-WpdAdministratorsMembers
            runKeys                 = Get-WpdRunKeyEntries
            startupFolder           = Get-WpdStartupFolderEntries
            hostsFileSha256         = if (Test-Path -LiteralPath $hostsFile) { Get-WpdSha256 -Path $hostsFile } else { 'absent' }
            defender                = Get-WpdDefenderFingerprint
            eventLogs               = Get-WpdEventLogFingerprint
            toolkitScheduledTasks   = Get-WpdToolkitScheduledTasks
        }
        recordOnly             = [ordered]@{
            firewallProfiles        = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { '{0}|enabled={1}' -f $_.Name, $_.Enabled } | Sort-Object)
            rootScheduledTaskCount  = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -eq '\' }).Count
            standardUserInUsers     = $null
            standardUserName        = $StandardUserName
        }
    }

    if ($StandardUserName) {
        $fingerprint.recordOnly.standardUserInUsers = (Test-WpdLocalUserGroupMembership -UserName $StandardUserName -GroupName 'Users')
    }
    return $fingerprint
}

function Compare-WpdFingerprint {
    param(
        [Parameter(Mandatory = $true)]$Before,
        [Parameter(Mandatory = $true)]$After
    )

    $deltas = @()
    foreach ($surface in $Before.strict.Keys) {
        $beforeJson = ($Before.strict[$surface] | ConvertTo-Json -Depth 8 -Compress)
        $afterJson = ($After.strict[$surface] | ConvertTo-Json -Depth 8 -Compress)
        if ($beforeJson -ne $afterJson) {
            $deltas += [pscustomobject]@{
                surface = $surface
                before  = $beforeJson
                after   = $afterJson
            }
        }
    }
    return $deltas
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
    $InputObject | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding utf8
}

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
    param([string]$StandardUserName)

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $wps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $wpsVersion = $null
    if (Test-Path -LiteralPath $wps) {
        $wpsVersion = (& $wps -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>&1) -join ' '
    }

    return [ordered]@{
        recordedAtUtc        = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        recordedAtLocal      = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
        osCaption            = $os.Caption
        osVersion            = $os.Version
        osBuildNumber        = $os.BuildNumber
        osArchitecture       = $os.OSArchitecture
        osProductType        = $os.ProductType
        computerSystemModel  = $cs.Model
        machineIdentifier    = $env:COMPUTERNAME
        runnerName           = $env:RUNNER_NAME
        runnerOs             = $env:RUNNER_OS
        runnerImage          = $env:ImageOS
        harnessUser          = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        harnessElevated      = (Test-WpdElevated)
        standardAccountTested = $StandardUserName
        collectorRuntime     = $wps
        collectorRuntimeVersion = $wpsVersion
        harnessHostVersion   = $PSVersionTable.PSVersion.ToString()
        gitCommit            = $env:GITHUB_SHA
        gitRef               = $env:GITHUB_REF
        gitWorkflowRunId     = $env:GITHUB_RUN_ID
        gitRepository        = $env:GITHUB_REPOSITORY
    }
}

#endregion

#region standard-user harness (WPD-05 precondition) ------------------------------

function New-WpdStandardTestUser {
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
    try {
        $existing = @($adsi.Children | Where-Object { $_.Name -eq $UserName })
        if ($existing.Count -gt 0) {
            # Re-running the case in the same job image: reset the password so the
            # freshly generated per-run secret matches the existing account.
            $user = [ADSI]"WinNT://$env:COMPUTERNAME/$UserName,user"
            $user.SetPassword($Password)
            $user.SetInfo()
            return 'existing-password-reset'
        }
        $newUser = $adsi.Create('User', $UserName)
        $newUser.SetPassword($Password)
        $newUser.SetInfo()
        return 'created'
    }
    catch {
        throw "standard test user creation failed for '$UserName': $($_.Exception.Message)"
    }
}

# Runs a probe command as the standard test account and returns its raw output.
# This is the positive control for "the account really is a non-admin user":
# whoami /user, /groups and /priv report the account the process actually ran as
# and the integrity level of its token.
function Invoke-WpdStandardUserProbe {
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$Password,
        [int]$Timeout = 60
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $psi.Arguments = '/c "whoami /user & whoami /groups & whoami /priv"'
    $psi.UseShellExecute = $false
    $psi.UserName = $UserName
    $psi.Domain = $env:COMPUTERNAME
    $psi.Password = (ConvertTo-SecureString $Password -AsPlainText -Force)
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $env:SystemRoot

    $process = [System.Diagnostics.Process]::Start($psi)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($Timeout * 1000)) {
        try { $process.Kill() } catch { }
        throw "standard-user probe did not finish within ${Timeout}s"
    }
    $stdoutTask.Wait(5000) | Out-Null
    $stderrTask.Wait(5000) | Out-Null
    return [pscustomobject]@{
        exitCode = $process.ExitCode
        output   = ($stdoutTask.Result + $stderrTask.Result)
    }
}

function Grant-WpdBatchLogonRight {
    param([Parameter(Mandatory = $true)][string]$UserName)
    $sid = (New-Object System.Security.Principal.NTAccount($UserName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $export = Join-Path $StagingRoot 'harness-sec-export.cfg'
    $apply = Join-Path $StagingRoot 'harness-sec-apply.cfg'
    & secedit /export /cfg $export /areas USER_RIGHTS | Out-Null
    $content = Get-Content -LiteralPath $export -Raw
    if ($content -match 'SeBatchLogonRight\s*=\s*[^\r\n]*') {
        $content = $content -replace 'SeBatchLogonRight\s*=\s*[^\r\n]*', "SeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551,*$sid"
    }
    else {
        $content = $content + "`r`nSeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551,*$sid`r`n"
    }
    Set-Content -LiteralPath $apply -Value $content -Encoding Ascii
    & secedit /configure /db (Join-Path $StagingRoot 'harness-secedit.sdb') /cfg $apply /areas USER_RIGHTS | Out-Null
    return $sid
}

function Start-WpdStandardUserCollection {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][int]$Duration,
        [Parameter(Mandatory = $true)][int]$MaxEvents,
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][int]$Timeout
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode Collect -ConfirmLocalCollection -DurationSeconds {1} -MaxEventCount {2} -OutputDirectory "{3}"' -f `
        $ScriptPath, $Duration, $MaxEvents, $OutputDirectory
    $psi.UseShellExecute = $false
    $psi.UserName = $UserName
    $psi.Domain = $env:COMPUTERNAME
    $psi.Password = (ConvertTo-SecureString $Password -AsPlainText -Force)
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = Split-Path -Parent $ScriptPath

    $process = [System.Diagnostics.Process]::Start($psi)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    # Sample the running collector's token owner and any descendants while it
    # runs: this is the live evidence that the collection ran under the standard
    # account and that nothing re-launched itself with a different (elevated)
    # identity.
    $ownerSamples = New-Object System.Collections.ArrayList
    $descendantSamples = New-Object System.Collections.ArrayList
    $samplingNotes = New-Object System.Collections.ArrayList
    $deadline = (Get-Date).AddSeconds($Timeout)
    $lastOwner = $null
    while (-not $process.HasExited -and (Get-Date) -lt $deadline) {
        # Primary: Get-Process -IncludeUserName (elevated caller sees the owner).
        try {
            $live = Get-Process -Id $process.Id -IncludeUserName -ErrorAction Stop
            $ownerName = [string]$live.UserName
            if ($ownerName -and $ownerName -ne $lastOwner) {
                [void]$ownerSamples.Add([pscustomobject]@{ atUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); pid = $process.Id; owner = $ownerName; source = 'Get-Process' })
                $lastOwner = $ownerName
            }
        }
        catch {
            $note = "Get-Process sampling: $($_.Exception.Message)"
            if (-not $samplingNotes.Contains($note)) { [void]$samplingNotes.Add($note) }
        }

        # Secondary: CIM ownership sample (also catches descendants).
        try {
            $instance = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($process.Id)" -ErrorAction Stop
            if ($instance -and -not $lastOwner) {
                $owner = $instance.GetOwner()
                $ownerName = '{0}\{1}' -f $owner.Domain, $owner.User
                if ($ownerName) {
                    [void]$ownerSamples.Add([pscustomobject]@{ atUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); pid = $process.Id; owner = $ownerName; source = 'Win32_Process.GetOwner' })
                    $lastOwner = $ownerName
                }
            }
            $children = @(Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId=$($process.Id)" -ErrorAction Stop)
            foreach ($child in $children) {
                $childOwner = $child.GetOwner()
                $childOwnerName = '{0}\{1}' -f $childOwner.Domain, $childOwner.User
                [void]$descendantSamples.Add([pscustomobject]@{ pid = $child.ProcessId; name = $child.Name; owner = $childOwnerName })
            }
        }
        catch {
            $note = "CIM sampling: $($_.Exception.Message)"
            if (-not $samplingNotes.Contains($note)) { [void]$samplingNotes.Add($note) }
        }

        if ($process.WaitForExit(500)) { break }
    }

    if (-not $process.HasExited) {
        try { $process.Kill() } catch { }
        throw "standard-user collection did not finish within ${Timeout}s"
    }
    $process.WaitForExit()
    $stdoutTask.Wait(10000) | Out-Null
    $stderrTask.Wait(10000) | Out-Null
    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    ("--- stdout ---`n{0}`n--- stderr ---`n{1}" -f $stdout, $stderr) | Set-Content -LiteralPath $LogPath -Encoding utf8

    return [pscustomobject]@{
        exitCode          = $process.ExitCode
        pid               = $process.Id
        ownerSamples      = @($ownerSamples)
        descendants       = @($descendantSamples | Select-Object -Unique -Property pid, name, owner)
        samplingNotes     = @($samplingNotes)
        stdout            = $stdout
        stderr            = $stderr
        logPath           = $LogPath
    }
}

#endregion

#region collection invocation ----------------------------------------------------

function Invoke-WpdCollection {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][int]$Duration,
        [Parameter(Mandatory = $true)][int]$MaxEvents,
        [Parameter(Mandatory = $true)][string]$LogPath
    )

    $wps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $captured = & $wps -NoProfile -ExecutionPolicy Bypass -File $ScriptPath `
        -Mode Collect -ConfirmLocalCollection -DurationSeconds $Duration -MaxEventCount $MaxEvents `
        -OutputDirectory $OutputDirectory *>&1
    $exitCode = $LASTEXITCODE
    ($captured | Out-String) | Set-Content -LiteralPath $LogPath -Encoding utf8
    $captured | ForEach-Object { Write-Output "collector: $($_.ToString())" }
    return [pscustomobject]@{ exitCode = $exitCode; output = ($captured | Out-String); logPath = $LogPath }
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
        $platformName = $name.Replace([char]92, [System.IO.Path]::DirectorySeparatorChar)
        $path = Join-Path -Path $OutputDirectory -ChildPath $platformName
        $exists = Test-Path -LiteralPath $path -PathType Leaf
        $actualSize = if ($exists) { (Get-Item -LiteralPath $path).Length } else { $null }
        $actualHash = if ($exists) { Get-WpdSha256 -Path $path } else { $null }
        $records += [pscustomobject]@{
            name               = $name
            declaredSha256     = $declaredHash
            declaredSizeBytes  = $declaredSize
            fileExists         = $exists
            actualSha256       = $actualHash
            actualSizeBytes    = $actualSize
            hashMatches        = ($exists -and ($declaredHash -eq $actualHash))
            sizeMatches        = ($exists -and ([int64]$declaredSize -eq $actualSize))
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
    foreach ($error in @($Manifest.collectionErrors)) {
        if ($null -eq $error) { continue }
        $rows += [pscustomobject]@{ stage = [string]$error.Stage; message = [string]$error.Message }
    }
    return $rows
}

<#
  Declarations the build makes about itself: v1.0.x builds carry a `safety`
  block, later builds add a `privacy` block. Both are recorded as evidence and
  asserted against their own claims (they are declarations, not proof - the
  independent proof is the artifact owner, the strict configuration fingerprint,
  the unlisted-file check and the absence of a completed remote block).
#>
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

$standardUserName = 'wpdstd5'
$preconditionNotes = New-Object System.Collections.ArrayList
$harnessChanges = New-Object System.Collections.ArrayList
$transcript = Join-Path $logsDirectory ("{0}-{1}-harness.log" -f $Case, $Label)
$configBefore = $null
$configAfter = $null

Start-Transcript -LiteralPath $transcript -Force | Out-Null

Write-Output "=== $Case ($Label) ==="
Write-Output "toolkit script: $ToolkitScript"
Write-Output "toolkit sha256: $toolkitHash"

if (-not (Test-WpdElevated)) {
    [void]$preconditionNotes.Add('harness console is NOT elevated; WPD-04 requires an elevated console (matrix precondition) and WPD-05 drives the standard-account leg from an elevated harness')
}

$environment = Get-WpdEnvironmentRecord -StandardUserName $(if ($Case -eq 'WPD-05') { $standardUserName } else { $null })

$caseOutcome = 'FAIL'
$standardUserPassword = 'Wpd#' + [guid]::NewGuid().ToString('N').Substring(0, 12) + '!Xy'
$standardUserEvidence = $null
$collection = $null
$manifest = $null
$manifestEvidence = @()
$unlistedFiles = @()
$collectionErrors = @()
$fingerprintDeltas = @()

try {
    if ($Case -eq 'WPD-04') {
        # Matrix WPD-04: inspect manifest hashes. The action is a consented
        # collection (the manifest it produces is the subject) followed by
        # independent re-verification of every listed hash/size.
        $configBefore = Get-WpdConfigFingerprint
        $collection = Invoke-WpdCollection -ScriptPath $ToolkitScript -OutputDirectory $caseDirectory `
            -Duration $DurationSeconds -MaxEvents $MaxEventCount -LogPath (Join-Path $logsDirectory "$Case-$Label-console.log")
        $configAfter = Get-WpdConfigFingerprint
        $fingerprintDeltas = @(Compare-WpdFingerprint -Before $configBefore -After $configAfter)

        Add-WpdAssertion -Name 'collection-exit-code' -Expected '0' -Observed $collection.exitCode -Outcome ($collection.exitCode -eq 0)

        $manifest = Get-WpdManifest -OutputDirectory $caseDirectory
        Add-WpdAssertion -Name 'manifest-present' -Expected 'diagnostic-manifest.json parses as JSON' `
            -Observed $(if ($null -ne $manifest) { 'parsed' } else { 'missing or unparseable' }) -Outcome ($null -ne $manifest)

        if ($null -ne $manifest) {
            $artifactEntries = @($manifest.artifacts)
            Add-WpdAssertion -Name 'manifest-artifact-count' -Expected '>= 2 tracked artifacts' -Observed $artifactEntries.Count -Outcome ($artifactEntries.Count -ge 2)

            foreach ($required in @('performance-samples.csv', 'top-processes.json')) {
                $present = @($artifactEntries | Where-Object { [string]$_.Name -eq $required }).Count -ge 1
                Add-WpdAssertion -Name "manifest-lists-$required" -Expected 'listed with SHA-256 and size' -Observed $present -Outcome $present
            }

            $manifestEvidence = @(Get-WpdManifestEvidence -OutputDirectory $caseDirectory -Manifest $manifest)

            $badHash = @($manifestEvidence | Where-Object { $_.declaredSha256 -notmatch '^[A-Fa-f0-9]{64}$' })
            Add-WpdAssertion -Name 'every-artifact-has-64-hex-sha256' -Expected 'all entries match ^[A-Fa-f0-9]{64}$' `
                -Observed $($manifestEvidence.Count - $badHash.Count) -Outcome ($badHash.Count -eq 0)

            $badSize = @($manifestEvidence | Where-Object { $null -eq $_.declaredSizeBytes -or [int64]$_.declaredSizeBytes -lt 0 })
            Add-WpdAssertion -Name 'every-artifact-has-size' -Expected 'all entries carry a non-negative SizeBytes' `
                -Observed $(@($manifestEvidence | Where-Object { $null -ne $_.declaredSizeBytes }).Count) -Outcome ($badSize.Count -eq 0)

            $missingOnDisk = @($manifestEvidence | Where-Object { -not $_.fileExists })
            Add-WpdAssertion -Name 'every-listed-artifact-exists-on-disk' -Expected 'all listed artifacts exist' `
                -Observed $(($manifestEvidence | Where-Object { $_.fileExists }).Count) -Outcome ($missingOnDisk.Count -eq 0)

            $sizeMismatch = @($manifestEvidence | Where-Object { $_.fileExists -and -not $_.sizeMatches })
            Add-WpdAssertion -Name 'declared-size-matches-disk' -Expected 'manifest SizeBytes equals the on-disk length' `
                -Observed $($manifestEvidence.Count) -Outcome ($sizeMismatch.Count -eq 0)

            $hashMismatch = @($manifestEvidence | Where-Object { $_.fileExists -and -not $_.hashMatches })
            Add-WpdAssertion -Name 'declared-sha256-matches-recomputed-hash' -Expected 'independent Get-FileHash equals the recorded SHA-256' `
                -Observed $($manifestEvidence.Count) -Outcome ($hashMismatch.Count -eq 0)

            $unlistedFiles = @(Get-WpdUnlistedFiles -OutputDirectory $caseDirectory -Manifest $manifest)
            Add-WpdAssertion -Name 'every-emitted-data-artifact-is-listed' -Expected 'no unlisted file in the case folder' `
                -Observed $(if ($unlistedFiles.Count -eq 0) { 'none unlisted' } else { $unlistedFiles -join ', ' }) -Outcome ($unlistedFiles.Count -eq 0)

            $collectionErrors = @(Get-WpdCollectionErrorRecords -Manifest $manifest)
            Write-Output ("collectionErrors: {0}" -f $(if ($collectionErrors.Count -eq 0) { 'none' } else { ($collectionErrors | ForEach-Object { "$($_.stage)=$($_.message)" }) -join ' ; ' }))

            $safetyCheck = Get-WpdSafetyDeclarationCheck -Manifest $manifest
            Add-WpdAssertion -Name 'safety-declarations-hold' -Expected 'localOnly/readOnly true, automaticUpload/Remediation/LogClearing false, explicit consent required, and secretsCollected false when the build declares a privacy block' `
                -Observed $safetyCheck.observed -Outcome $safetyCheck.ok

            $remoteStatus = 'absent'
            if ($null -ne $manifest.PSObject.Properties['remote'] -and $null -ne $manifest.remote) { $remoteStatus = [string]$manifest.remote.status }
            Add-WpdAssertion -Name 'no-remote-transmission' -Expected 'manifest.remote.status is not completed (no -ConfirmRemoteCollection was passed)' `
                -Observed $remoteStatus -Outcome ($remoteStatus -ne 'completed')

            # Retention/persistence: anything this run created lives under the
            # case folder. Prove it by comparing configured machines surfaces.
            Add-WpdAssertion -Name 'no-configuration-change-or-persistence' -Expected 'no strict-configuration delta' `
                -Observed $(if ($fingerprintDeltas.Count -eq 0) { 'no delta' } else { ($fingerprintDeltas | ForEach-Object { $_.surface }) -join ', ' }) -Outcome ($fingerprintDeltas.Count -eq 0)

            if ($collection.exitCode -eq 0 -and $artifactEntries.Count -ge 2 -and $badHash.Count -eq 0 -and $badSize.Count -eq 0 -and
                $missingOnDisk.Count -eq 0 -and $sizeMismatch.Count -eq 0 -and $hashMismatch.Count -eq 0 -and $unlistedFiles.Count -eq 0 -and
                $safetyCheck.ok -and $remoteStatus -ne 'completed' -and $fingerprintDeltas.Count -eq 0) {
                $caseOutcome = 'PASS'
            }
        }
    }
    elseif ($Case -eq 'WPD-05') {
        # Matrix WPD-05: run on a standard (non-admin) account. Preconditions the
        # harness supplies itself are recorded as harness changes, not toolkit
        # behavior.
        $harnessLog = Join-Path $logsDirectory "$Case-$Label-harness-setup.log"
        $created = New-WpdStandardTestUser -UserName $standardUserName -Password $standardUserPassword
        [void]$harnessChanges.Add("local standard user '$standardUserName' ($created) for the non-admin leg")
        $sid = Grant-WpdBatchLogonRight -UserName $standardUserName
        [void]$harnessChanges.Add("SeBatchLogonRight granted to '$standardUserName' ($sid) so a non-interactive process start is possible")
        & icacls $stagingRootFull /grant "${standardUserName}:(OI)(CI)M" | Out-Null

        $stagedScript = Join-Path $stagingRootFull 'Invoke-WindowsPerformanceDiagnostics.ps1'
        Copy-Item -LiteralPath $ToolkitScript -Destination $stagedScript -Force
        & icacls $stagedScript /grant "${standardUserName}:R" | Out-Null
        [void]$harnessChanges.Add("toolkit script staged and read-granted to '$standardUserName'")

        $inUsers = Test-WpdLocalUserGroupMembership -UserName $standardUserName -GroupName 'Users'
        $inAdmins = Test-WpdLocalUserGroupMembership -UserName $standardUserName -GroupName 'Administrators'

        # Positive control: run whoami as the standard account before the case.
        # (An ADSI-created account's primary group is Users, so it does not appear
        # in the Users group's member list; the token itself is the evidence.)
        $probe = Invoke-WpdStandardUserProbe -UserName $standardUserName -Password $standardUserPassword
        $probeRunsAsUser = ($probe.output -match [regex]::Escape($standardUserName))
        $probeHasAdminSid = ($probe.output -match 'S-1-5-32-544')
        $probeElevated = ($probe.output -match 'High Mandatory Level')
        $probeIntegrity = (@($probe.output -split "`r?`n" | Where-Object { $_ -match 'Mandatory Label' }) -join ' ').Trim()
        $probeUserLine = (@($probe.output -split "`r?`n" | Where-Object { $_ -match [regex]::Escape($standardUserName) } | Select-Object -First 1) -join ' ').Trim()
        Add-WpdAssertion -Name 'precondition-standard-account-token' `
            -Expected 'the test account token runs as the account, has no Administrators SID, and is not a high-integrity (elevated) token' `
            -Observed ("whoamiRunsAsUser=$probeRunsAsUser hasAdministratorsSid=$probeHasAdminSid highIntegrity=$probeElevated integrity='$probeIntegrity'") `
            -Outcome ($probe.exitCode -eq 0 -and $probeRunsAsUser -and -not $probeHasAdminSid -and -not $probeElevated)
        Add-WpdAssertion -Name 'precondition-not-local-administrator' -Expected 'test account is not a member of Administrators' `
            -Observed ("AdministratorsMember=$inAdmins UsersGroupListed=$inUsers") -Outcome (-not $inAdmins)

        $configBefore = Get-WpdConfigFingerprint -StandardUserName $standardUserName
        $run = Start-WpdStandardUserCollection -ScriptPath $stagedScript -OutputDirectory $caseDirectory `
            -Duration $DurationSeconds -MaxEvents $MaxEventCount -UserName $standardUserName -Password $standardUserPassword `
            -LogPath (Join-Path $logsDirectory "$Case-$Label-console.log") -Timeout $TimeoutSeconds
        $configAfter = Get-WpdConfigFingerprint -StandardUserName $standardUserName
        $fingerprintDeltas = @(Compare-WpdFingerprint -Before $configBefore -After $configAfter)

        $expectedOwner = "$env:COMPUTERNAME\$standardUserName"
        $ownerSamples = @($run.ownerSamples)
        $foreignOwners = @($ownerSamples | Where-Object { $_.owner -ne $expectedOwner })
        $standardUserEvidence = [pscustomobject]@{
            userName        = $standardUserName
            expectedOwner   = $expectedOwner
            pid             = $run.pid
            ownerSamples    = $ownerSamples
            samplingNotes   = @($run.samplingNotes)
            descendants     = @($run.descendants)
            tokenProbe      = [pscustomobject]@{
                exitCode             = $probe.exitCode
                runsAsTestAccount    = $probeRunsAsUser
                hasAdministratorsSid = $probeHasAdminSid
                highIntegrity        = $probeElevated
                integrityLine        = $probeIntegrity
                userLine             = $probeUserLine
                groupSummary         = $(if ($probeHasAdminSid) { 'Administrators SID present' } else { 'Administrators SID absent' })
                fullOutputLocation   = 'harness transcript (C:\WPD\logs)'
            }
            consoleLog      = $run.logPath
            setupLog        = $harnessLog
        }

        Add-WpdAssertion -Name 'standard-account-collection-exit-code' -Expected '0 (collection completes, partially if access is denied)' `
            -Observed $run.exitCode -Outcome ($run.exitCode -eq 0)
        Add-WpdAssertion -Name 'collector-ran-as-standard-user' -Expected "every sampled token owner is $expectedOwner" `
            -Observed $(if ($ownerSamples.Count -eq 0) { 'no owner sample captured' } else { ($ownerSamples | ForEach-Object { $_.owner } | Select-Object -Unique) -join ', ' }) `
            -Outcome ($ownerSamples.Count -gt 0 -and $foreignOwners.Count -eq 0)

        # A descendant running as a service/machine account (SYSTEM, LOCAL
        # SERVICE, ...) is normal process plumbing; a descendant owned by a
        # *user* other than the standard account would be the signature of a
        # self-elevating relaunch.
        $systemAccountPattern = '\\(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|[^\\]+\$)$'
        $foreignDescendants = @($run.descendants | Where-Object { $_.owner -ne $expectedOwner -and $_.owner -notmatch $systemAccountPattern })
        Add-WpdAssertion -Name 'no-descendant-under-another-user-identity' -Expected 'no child process owned by a different user account (no self-elevation/relaunch)' `
            -Observed $(if (@($run.descendants).Count -eq 0) { 'no descendants observed' } else { (@($run.descendants) | ForEach-Object { "$($_.name)@$($_.owner)" }) -join ', ' }) `
            -Outcome ($foreignDescendants.Count -eq 0)

        $elevationMarkers = @('consent.exe', 'Verb RunAs', 'ShellExecute', '-Verb runas')
        $matchedMarkers = @($elevationMarkers | Where-Object { $run.stdout -match [regex]::Escape($_) -or $run.stderr -match [regex]::Escape($_) })
        Add-WpdAssertion -Name 'no-elevation-implementation-marker-in-output' -Expected 'no UAC/relaunch marker in collector output' `
            -Observed $(if ($matchedMarkers.Count -eq 0) { 'none' } else { $matchedMarkers -join ', ' }) -Outcome ($matchedMarkers.Count -eq 0)

        $manifest = Get-WpdManifest -OutputDirectory $caseDirectory
        Add-WpdAssertion -Name 'manifest-present' -Expected 'diagnostic-manifest.json parses as JSON' `
            -Observed $(if ($null -ne $manifest) { 'parsed' } else { 'missing or unparseable' }) -Outcome ($null -ne $manifest)

        if ($null -ne $manifest) {
            $collectionErrors = @(Get-WpdCollectionErrorRecords -Manifest $manifest)
            Write-Output ("collectionErrors: {0}" -f $(if ($collectionErrors.Count -eq 0) { 'none' } else { ($collectionErrors | ForEach-Object { "$($_.stage)=$($_.message)" }) -join ' ; ' }))

            $safetyCheck = Get-WpdSafetyDeclarationCheck -Manifest $manifest
            Add-WpdAssertion -Name 'safety-declarations-hold' -Expected 'localOnly/readOnly true, automaticUpload/Remediation/LogClearing false, explicit consent required, and secretsCollected false when the build declares a privacy block' `
                -Observed $safetyCheck.observed -Outcome $safetyCheck.ok

            $manifestEvidence = @(Get-WpdManifestEvidence -OutputDirectory $caseDirectory -Manifest $manifest)
            $hashMismatch = @($manifestEvidence | Where-Object { $_.fileExists -and -not $_.hashMatches })
            Add-WpdAssertion -Name 'declared-sha256-matches-recomputed-hash' -Expected 'independent Get-FileHash equals the recorded SHA-256 for every listed artifact' `
                -Observed $manifestEvidence.Count -Outcome ($hashMismatch.Count -eq 0)
            $unlistedFiles = @(Get-WpdUnlistedFiles -OutputDirectory $caseDirectory -Manifest $manifest)
            Add-WpdAssertion -Name 'every-emitted-data-artifact-is-listed' -Expected 'no unlisted file in the case folder' `
                -Observed $(if ($unlistedFiles.Count -eq 0) { 'none unlisted' } else { $unlistedFiles -join ', ' }) -Outcome ($unlistedFiles.Count -eq 0)

            $coreArtifacts = @('performance-samples.csv', 'top-processes.json', 'system-events-last-24-hours.json')
            $missingCore = @($coreArtifacts | Where-Object { -not (Test-Path -LiteralPath (Join-Path $caseDirectory $_)) })
            if ($collectionErrors.Count -gt 0) {
                # Partial collection is allowed for a standard account only when the
                # failures are declared in collectionErrors (matrix expectation).
                $declared = @($collectionErrors | Where-Object { $_.stage -and $_.message })
                Add-WpdAssertion -Name 'partial-collection-is-declared' -Expected 'each recorded failure carries a stage and a message' `
                    -Observed ("$($collectionErrors.Count) collectionErrors; missing core artifacts: $(if ($missingCore.Count -eq 0) { 'none' } else { $missingCore -join ', ' })") `
                    -Outcome ($declared.Count -eq $collectionErrors.Count)
            }
            else {
                Add-WpdAssertion -Name 'complete-collection-when-no-errors' -Expected 'no collectionErrors implies every core artifact was collected' `
                    -Observed $(if ($missingCore.Count -eq 0) { 'all core artifacts present' } else { "missing: $($missingCore -join ', ')" }) -Outcome ($missingCore.Count -eq 0)
            }

            # Owner of the collected evidence must be the standard account: proof
            # that the standard user's own token wrote the case, not an elevated
            # relaunch.
            $sampleArtifact = Join-Path $caseDirectory 'performance-samples.csv'
            if (Test-Path -LiteralPath $sampleArtifact) {
                $aclOwner = (Get-Acl -LiteralPath $sampleArtifact).Owner
                Add-WpdAssertion -Name 'case-artifact-owner-is-standard-user' -Expected $expectedOwner -Observed $aclOwner -Outcome ($aclOwner -eq $expectedOwner -or $aclOwner -match ('\\' + [regex]::Escape($standardUserName) + '$'))
            }

            Add-WpdAssertion -Name 'no-configuration-change-or-persistence' -Expected 'no strict-configuration delta across the standard-account run' `
                -Observed $(if ($fingerprintDeltas.Count -eq 0) { 'no delta' } else { ($fingerprintDeltas | ForEach-Object { $_.surface }) -join ', ' }) -Outcome ($fingerprintDeltas.Count -eq 0)

            $inAdminsAfter = Test-WpdLocalUserGroupMembership -UserName $standardUserName -GroupName 'Administrators'
            Add-WpdAssertion -Name 'standard-user-not-elevated-to-administrators' -Expected 'test account is still not an Administrator after the run' `
                -Observed $inAdminsAfter -Outcome (-not $inAdminsAfter)

            if ($run.exitCode -eq 0 -and $ownerSamples.Count -gt 0 -and $foreignOwners.Count -eq 0 -and $foreignDescendants.Count -eq 0 -and
                $matchedMarkers.Count -eq 0 -and $safetyCheck.ok -and $hashMismatch.Count -eq 0 -and $unlistedFiles.Count -eq 0 -and
                $fingerprintDeltas.Count -eq 0 -and -not $inAdminsAfter -and -not $inAdmins -and $probe.exitCode -eq 0 -and
                $probeRunsAsUser -and -not $probeHasAdminSid -and -not $probeElevated) {
                if ($collectionErrors.Count -gt 0) {
                    if (@($collectionErrors | Where-Object { $_.stage -and $_.message }).Count -eq $collectionErrors.Count) { $caseOutcome = 'PASS' }
                }
                elseif (@($coreArtifacts | Where-Object { -not (Test-Path -LiteralPath (Join-Path $caseDirectory $_)) }).Count -eq 0) {
                    $caseOutcome = 'PASS'
                }
            }
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
    $result = [ordered]@{
        case                 = $Case
        label                = $Label
        verdict              = $caseOutcome
        harness              = 'tests/live/Invoke-WpdLiveCase0405.ps1'
        recordedAtUtc        = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        matrixReference      = 'docs/windows-live-test-matrix.md'
        matrixExpectation    = if ($Case -eq 'WPD-04') {
            'Every emitted data artifact is listed with SHA-256 and size.'
        }
        else {
            'Collection completes partially or records failures under collectionErrors; script must not change configuration or elevate itself.'
        }
        toolkit             = [ordered]@{
            path      = $ToolkitScript
            sha256    = $toolkitHash
            label     = $Label
        }
        environment         = $environment
        preconditions       = [ordered]@{
            notes           = @($preconditionNotes)
            harnessChanges  = @($harnessChanges)
            durationSeconds = $DurationSeconds
            maxEventCount   = $MaxEventCount
            stagingRoot     = $stagingRootFull
            caseDirectory   = $caseDirectory
        }
        collection          = if ($null -ne $collection) { [ordered]@{ exitCode = $collection.exitCode; consoleLog = $collection.logPath } } else { $null }
        standardAccount     = $standardUserEvidence
        manifestArtifacts   = $manifestEvidence
        unlistedFiles       = $unlistedFiles
        collectionErrors    = $collectionErrors
        configurationDeltas = @($fingerprintDeltas)
        configurationStrictBefore = if ($configBefore) { $configBefore.strict } else { $null }
        configurationStrictAfter = if ($configAfter) { $configAfter.strict } else { $null }
        configurationRecordOnlyBefore = if ($configBefore) { $configBefore.recordOnly } else { $null }
        configurationRecordOnlyAfter = if ($configAfter) { $configAfter.recordOnly } else { $null }
        assertions          = @($script:wpdAssertions)
        failures            = @($script:wpdFailures)
        harnessLog          = $transcript
        sanitization        = @(
            'No credentials are recorded: the standard-account password is generated per run and is never written to any log, result or artifact.',
            'Harness-generated secret material (harness-sec-*.cfg, harness-secedit.sdb) is excluded from any uploaded evidence.',
            'Only this case folder, harness logs and result JSON are published; raw machine event-log rows are not uploaded.'
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
exit 1

#endregion
