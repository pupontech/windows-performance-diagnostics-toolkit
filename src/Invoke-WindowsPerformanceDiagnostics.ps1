[CmdletBinding()]
param(
    [ValidateSet('Plan', 'Collect', 'Verify')]
    [string]$Mode = 'Plan',

    [ValidateRange(5, 300)]
    [int]$DurationSeconds = 30,

    [ValidateRange(1, 1000)]
    [int]$MaxEventCount = 200,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location).Path -ChildPath 'windows-performance-diagnostics'),

    [string]$InputDirectory,

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

    [switch]$ConfirmRemoteCollection,

    [string]$SymptomContext,

    [ValidateSet('baseline', 'cpu-heavy', 'memory-pressure', 'storage-io', 'network-io', 'boot-slowdown', 'application-freeze')]
    [string]$Preset,

    # ---- Incident capture mode (v1.0) -----------------------------------
    # Everything below shares ONE capture window: WPR, process/commit samples,
    # GPU, memory, disk and UDP/endpoint series all start and stop together so
    # the trace can actually explain the counters.
    [switch]$PerformanceMode,

    # WPR trace window. 0 = AUTO: sized to cover the whole capture window
    # (baseline + marker post-window + a margin) so the trace can never end
    # before the counters it is supposed to explain.
    [ValidateRange(0, 600)]
    [int]$WprDurationSeconds = 0,

    [ValidateRange(0, 4096)]
    [int]$WprMaxFileMB = 512,

    [ValidateRange(1, 30)]
    [int]$SampleIntervalSeconds = 1,

    [switch]$MarkerMode,

    [ValidateRange(0, 600)]
    [int]$MarkerPreSeconds = 60,

    [ValidateRange(5, 600)]
    [int]$MarkerPostSeconds = 30,

    [ValidateRange(0, 120)]
    [int]$EventWindowMinutes = 15,

    [ValidateRange(1, 500)]
    [int]$MaxTrackedProcesses = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Single source of truth for the version is the VERSION file at the repo/bundle
# root; the constant below is only a fallback for standalone copies of the
# script (e.g. CI staging copies) - test_version_file_matches_script_fallback
# keeps the two in sync so drift fails CI.
$script:ScriptVersion = '1.0.0'
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

# Effective WPR trace window. An explicit -WprDurationSeconds is honoured
# verbatim; 0 (the default) auto-sizes the trace to outlast the counter window
# (baseline + the marker post-window + a margin) so the ETL can never end before
# the counters it is supposed to explain. Computed here because Plan mode
# advertises it too.
$markerExtraSeconds = if ($MarkerMode) { $MarkerPostSeconds } else { 0 }
$effectiveWprDurationSeconds = $WprDurationSeconds
if ($effectiveWprDurationSeconds -le 0) {
    $effectiveWprDurationSeconds = [Math]::Min(600, [Math]::Max(60, ($DurationSeconds + $markerExtraSeconds + 15)))
}

# Collection-error accumulator and its helpers are defined before any mode
# dispatch so the shared Collect-tail function (Write-CollectionOutputs) can be
# exercised by fixture tests that dot-source the script in Plan mode.
# ArrayList (not @()) so the manifest can hold a live reference: array += would
# rebind the variable and tail-stage errors added after manifest construction
# would silently not appear in the written manifest.
$script:collectionErrors = New-Object System.Collections.ArrayList
function Add-CollectionError {
    param([string]$Stage, [System.Management.Automation.ErrorRecord]$ErrorRecord)

    [void]$script:collectionErrors.Add([pscustomobject]@{
        Stage = $Stage
        Message = $ErrorRecord.Exception.Message
    })
}

function Add-CollectionErrorText {
    param([string]$Stage, [string]$Message)

    [void]$script:collectionErrors.Add([pscustomobject]@{
        Stage = $Stage
        Message = $Message
    })
}

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

function Get-RemoteSafetyBlock {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteTarget
    )

    return [ordered]@{
        localOnly = $false
        readOnly = $true
        requiresExplicitCollectionConsent = $true
        automaticUpload = $false
        automaticRemediation = $false
        automaticLogClearing = $false
        remoteTarget = $RemoteTarget
        remoteTransport = 'winrm'
    }
}

function New-RemoteStagingPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseDirectory,

        [Parameter(Mandatory = $true)]
        [string]$Nonce
    )

    if ([string]::IsNullOrWhiteSpace($BaseDirectory)) {
        throw 'Remote staging base directory cannot be empty.'
    }
    if ($Nonce -notmatch '^[A-Za-z0-9-]+$') {
        throw 'Remote staging nonce contains unsupported characters.'
    }

    return Join-Path -Path $BaseDirectory -ChildPath ('WPD-Remote-Case-' + $Nonce)
}

function Get-RemoteVerificationStatus {
    param(
        [bool]$HashVerificationFailed,
        [int]$PulledFileCount,
        [int]$VerifiedFileCount
    )

    if ($HashVerificationFailed -or ($PulledFileCount -ne $VerifiedFileCount)) {
        return 'failed'
    }
    return 'completed'
}

function Get-ValidatedRemoteArtifactName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw 'Remote manifest contains an empty artifact name.'
    }

    $normalizedName = $Name.Replace('/', '\')
    if ($normalizedName.StartsWith('\') -or $normalizedName -match '^[A-Za-z]:') {
        throw "Remote manifest artifact name must be relative: $Name"
    }
    foreach ($segment in $normalizedName.Split([char]92)) {
        if ($segment -eq '.' -or $segment -eq '..') {
            throw "Remote manifest artifact name contains a traversal segment: $Name"
        }
    }
    if ($normalizedName -match '[:*?"<>|]') {
        throw "Remote manifest artifact name contains an unsupported character: $Name"
    }

    return $normalizedName
}

function Get-CaseJsonProperty {
    param(
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return $InputObject[$Name]
        }
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }
    return $null
}

function Test-CasePathContained {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$Candidate
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $candidateFull = [System.IO.Path]::GetFullPath($Candidate)
    $rootRoot = [System.IO.Path]::GetPathRoot($rootFull)
    if ($rootFull -eq $rootRoot) {
        $rootPrefix = $rootFull
    }
    else {
        $rootPrefix = $rootFull.TrimEnd([char]92, [char]47) + [System.IO.Path]::DirectorySeparatorChar
    }
    return $candidateFull.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Invoke-CasePackageVerification {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory,

        [Parameter(Mandatory = $true)]
        [object]$Manifest,

        [object[]]$ArtifactEntries = @()
    )

    $summary = [ordered]@{ status = 'not-present' }
    $errors = @()
    $package = Get-CaseJsonProperty -InputObject $Manifest -Name 'package'
    if ($null -eq $package) {
        return [pscustomobject]@{ Summary = $summary; Errors = @() }
    }

    $packageStatus = [string](Get-CaseJsonProperty -InputObject $package -Name 'status')
    if ($packageStatus -ne 'completed') {
        $summary.status = 'not-verified'
        $errors += "Manifest package status is '$packageStatus', not completed."
        return [pscustomobject]@{ Summary = $summary; Errors = $errors }
    }

    try {
        $declaredZipPath = [string](Get-CaseJsonProperty -InputObject $package -Name 'zipPath')
        if ([string]::IsNullOrWhiteSpace($declaredZipPath)) {
            throw 'Manifest package is missing zipPath.'
        }
        $zipLeaf = @([string]$declaredZipPath -split '[\\/]')[-1]
        if ([string]::IsNullOrWhiteSpace($zipLeaf) -or $zipLeaf -in @('.', '..')) {
            throw 'Manifest package zipPath does not contain a safe file name.'
        }
        # Package files are deliberately written next to the case directory.
        # Use only the recorded leaf after relocation; never open an arbitrary
        # absolute path supplied by a manifest.
        $zipPath = Join-Path -Path (Split-Path -Parent $Directory) -ChildPath $zipLeaf
        if (-not (Test-Path -LiteralPath $zipPath -PathType Leaf)) {
            throw "Case package not found beside InputDirectory: $zipPath"
        }
        $zipItem = Get-Item -LiteralPath $zipPath -ErrorAction Stop
        if (($zipItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Case package is a reparse point: $zipPath"
        }
        $declaredSizeValue = Get-CaseJsonProperty -InputObject $package -Name 'sizeBytes'
        $declaredHash = [string](Get-CaseJsonProperty -InputObject $package -Name 'sha256')
        if ($null -eq $declaredSizeValue) {
            throw 'Manifest package is missing sizeBytes.'
        }
        if ($zipItem.Length -ne [int64]$declaredSizeValue) {
            throw "Case package size mismatch (manifest=$declaredSizeValue, actual=$($zipItem.Length))."
        }
        if ($declaredHash -notmatch '^[A-Fa-f0-9]{64}$') {
            throw 'Manifest package has an invalid SHA-256.'
        }
        $actualZipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($actualZipHash -ne $declaredHash) {
            throw "Case package hash mismatch (manifest=$declaredHash, actual=$actualZipHash)."
        }
        if ((Get-CaseJsonProperty -InputObject $package -Name 'includesManifest') -ne $true) {
            throw 'Manifest package must declare includesManifest=true.'
        }

        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $archive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            $entryMap = @{}
            foreach ($entry in @($archive.Entries)) {
                $entryName = [string]$entry.FullName
                if ($entryMap.ContainsKey($entryName)) {
                    throw "Case package contains duplicate entry '$entryName'."
                }
                $entryMap[$entryName] = $entry
            }
            $summary.entryCount = $entryMap.Count

            $expectedEntryMap = @{}
            $expectedEntryMap['diagnostic-manifest.json'] = $true
            $outerArtifactsByName = @{}
            foreach ($artifact in $ArtifactEntries) {
                $nameValue = Get-CaseJsonProperty -InputObject $artifact -Name 'Name'
                if ($null -eq $nameValue) {
                    throw 'Manifest package comparison found an artifact without Name.'
                }
                $normalizedName = Get-ValidatedRemoteArtifactName -Name ([string]$nameValue)
                $entryName = $normalizedName.Replace('\', '/')
                if ($expectedEntryMap.ContainsKey($entryName)) {
                    throw "Manifest package expected-entry list contains duplicate '$entryName'."
                }
                $expectedEntryMap[$entryName] = $true
                $outerArtifactsByName[$normalizedName.ToUpperInvariant()] = $artifact
            }

            if ($entryMap.Count -ne $expectedEntryMap.Count) {
                throw "Case package entry count mismatch (expected=$($expectedEntryMap.Count), actual=$($entryMap.Count))."
            }
            foreach ($expectedName in $expectedEntryMap.Keys) {
                if (-not $entryMap.ContainsKey($expectedName)) {
                    throw "Case package is missing entry '$expectedName'."
                }
            }
            foreach ($actualName in $entryMap.Keys) {
                if (-not $expectedEntryMap.ContainsKey($actualName)) {
                    throw "Case package contains unexpected entry '$actualName'."
                }
            }

            foreach ($entryName in $outerArtifactsByName.Keys) {
                $outerArtifact = $outerArtifactsByName[$entryName]
                $zipEntryName = ([string](Get-CaseJsonProperty -InputObject $outerArtifact -Name 'Name')).Replace('\', '/')
                $zipEntry = $entryMap[$zipEntryName]
                $declaredEntrySize = [int64](Get-CaseJsonProperty -InputObject $outerArtifact -Name 'SizeBytes')
                if ($zipEntry.Length -ne $declaredEntrySize) {
                    throw "Case package entry size mismatch: $zipEntryName"
                }
                $entryHasher = [System.Security.Cryptography.SHA256]::Create()
                $entryStream = $zipEntry.Open()
                try {
                    $entryDigest = $entryHasher.ComputeHash($entryStream)
                }
                finally {
                    $entryStream.Dispose()
                    $entryHasher.Dispose()
                }
                $entryHash = ([System.BitConverter]::ToString($entryDigest)).Replace('-', '')
                $declaredEntryHash = [string](Get-CaseJsonProperty -InputObject $outerArtifact -Name 'Sha256')
                if ($entryHash -ne $declaredEntryHash) {
                    throw "Case package entry hash mismatch: $zipEntryName"
                }
            }

            $manifestEntry = $entryMap['diagnostic-manifest.json']
            $manifestReader = New-Object System.IO.StreamReader($manifestEntry.Open())
            try {
                $innerManifest = $manifestReader.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop
            }
            finally {
                $manifestReader.Dispose()
            }
            if ((Get-CaseJsonProperty -InputObject $innerManifest -Name 'mode') -ne 'Collect') {
                throw 'Case package manifest is not a Collect manifest.'
            }
            $innerArtifactValue = Get-CaseJsonProperty -InputObject $innerManifest -Name 'artifacts'
            $innerArtifacts = @($innerArtifactValue)
            $innerByName = @{}
            foreach ($innerArtifact in $innerArtifacts) {
                $innerName = [string](Get-CaseJsonProperty -InputObject $innerArtifact -Name 'Name')
                if (-not [string]::IsNullOrWhiteSpace($innerName)) {
                    $innerByName[$innerName.ToUpperInvariant()] = $innerArtifact
                }
            }
            foreach ($outerName in $outerArtifactsByName.Keys) {
                if (-not $innerByName.ContainsKey($outerName)) {
                    throw "Case package manifest is missing artifact '$outerName'."
                }
                $outerArtifact = $outerArtifactsByName[$outerName]
                $innerArtifact = $innerByName[$outerName]
                if ([int64](Get-CaseJsonProperty -InputObject $outerArtifact -Name 'SizeBytes') -ne [int64](Get-CaseJsonProperty -InputObject $innerArtifact -Name 'SizeBytes') -or
                    [string](Get-CaseJsonProperty -InputObject $outerArtifact -Name 'Sha256') -ne [string](Get-CaseJsonProperty -InputObject $innerArtifact -Name 'Sha256')) {
                    throw "Case package manifest disagrees with the outer artifact manifest for '$outerName'."
                }
            }
        }
        finally {
            $archive.Dispose()
        }
        $summary.status = 'verified'
        $summary.path = $zipPath
    }
    catch {
        $errors += "Case package verification failed: $($_.Exception.Message)"
        $summary.status = 'failed'
    }
    return [pscustomobject]@{ Summary = $summary; Errors = $errors }
}

function Invoke-CaseVerification {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    $report = [ordered]@{
        reportType = 'case-verification'
        verifierVersion = '1.0'
        mode = 'Verify'
        status = 'failed'
        inputDirectory = $Directory
        manifestPath = $null
        artifactCount = 0
        verifiedArtifactCount = 0
        package = [ordered]@{ status = 'not-present' }
        errors = @()
        warnings = @()
        verifiedAtUtc = Get-UtcTimestamp
    }
    $errors = @()

    try {
        $resolvedDirectory = [System.IO.Path]::GetFullPath($Directory)
    }
    catch {
        $errors += "InputDirectory '$Directory' is not a valid path: $($_.Exception.Message)"
        $report.errors = $errors
        return $report
    }
    $report.inputDirectory = $resolvedDirectory

    if (-not (Test-Path -LiteralPath $resolvedDirectory -PathType Container)) {
        $errors += "InputDirectory '$resolvedDirectory' does not exist or is not a directory."
        $report.errors = $errors
        return $report
    }

    try {
        $directoryItem = Get-Item -LiteralPath $resolvedDirectory -ErrorAction Stop
        if (($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            $errors += "InputDirectory '$resolvedDirectory' is a reparse point; verification refuses redirected paths."
            $report.errors = $errors
            return $report
        }
    }
    catch {
        $errors += "Unable to inspect InputDirectory '$resolvedDirectory': $($_.Exception.Message)"
        $report.errors = $errors
        return $report
    }

    $manifestPath = Join-Path -Path $resolvedDirectory -ChildPath 'diagnostic-manifest.json'
    $report.manifestPath = $manifestPath
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        $errors += "Manifest not found: $manifestPath"
        $report.errors = $errors
        return $report
    }

    try {
        $manifestItem = Get-Item -LiteralPath $manifestPath -ErrorAction Stop
        if (($manifestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'manifest is a reparse point'
        }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $errors += "Manifest could not be read or parsed: $($_.Exception.Message)"
        $report.errors = $errors
        return $report
    }

    foreach ($requiredProperty in @('schemaVersion', 'toolName', 'toolVersion', 'mode', 'safety')) {
        $value = Get-CaseJsonProperty -InputObject $manifest -Name $requiredProperty
        if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
            $errors += "Manifest is missing required property '$requiredProperty'."
        }
    }
    if ((Get-CaseJsonProperty -InputObject $manifest -Name 'toolName') -ne 'Windows Performance Diagnostics Toolkit') {
        $errors += 'Manifest toolName is not the Windows Performance Diagnostics Toolkit.'
    }
    if ((Get-CaseJsonProperty -InputObject $manifest -Name 'mode') -ne 'Collect') {
        $errors += 'Verify mode accepts only a Collect manifest.'
    }

    $safety = Get-CaseJsonProperty -InputObject $manifest -Name 'safety'
    if ($null -eq $safety) {
        $errors += 'Manifest safety block is missing.'
    }
    else {
        foreach ($safetyProperty in @('localOnly', 'readOnly', 'requiresExplicitCollectionConsent', 'automaticUpload', 'automaticRemediation', 'automaticLogClearing')) {
            $value = Get-CaseJsonProperty -InputObject $safety -Name $safetyProperty
            if ($null -eq $value -or -not ($value -is [bool])) {
                $errors += "Manifest safety.$safetyProperty must be a boolean."
            }
        }
        foreach ($falseSafetyProperty in @('readOnly', 'requiresExplicitCollectionConsent', 'automaticUpload', 'automaticRemediation', 'automaticLogClearing')) {
            $value = Get-CaseJsonProperty -InputObject $safety -Name $falseSafetyProperty
            if ($falseSafetyProperty -eq 'readOnly' -and $value -ne $true) {
                $errors += 'Manifest safety.readOnly must be true.'
            }
            elseif ($falseSafetyProperty -eq 'requiresExplicitCollectionConsent' -and $value -ne $true) {
                $errors += 'Manifest safety.requiresExplicitCollectionConsent must be true.'
            }
            elseif ($falseSafetyProperty -ne 'readOnly' -and $falseSafetyProperty -ne 'requiresExplicitCollectionConsent' -and $value -ne $false) {
                $errors += "Manifest safety.$falseSafetyProperty must be false."
            }
        }
    }

    $artifactValue = Get-CaseJsonProperty -InputObject $manifest -Name 'artifacts'
    if ($null -eq $artifactValue) {
        $errors += 'Manifest artifacts array is missing.'
        $artifactEntries = @()
    }
    elseif ($artifactValue -is [System.Array]) {
        $artifactEntries = @($artifactValue)
    }
    else {
        $artifactEntries = @($artifactValue)
    }
    $report.artifactCount = $artifactEntries.Count
    $seenNames = @{}
    $verifiedCount = 0

    foreach ($artifact in $artifactEntries) {
        $nameValue = Get-CaseJsonProperty -InputObject $artifact -Name 'Name'
        if ($null -eq $nameValue -or [string]::IsNullOrWhiteSpace([string]$nameValue)) {
            $errors += 'Manifest artifact entry is missing Name.'
            continue
        }
        $name = [string]$nameValue
        try {
            $normalizedName = Get-ValidatedRemoteArtifactName -Name $name
        }
        catch {
            $errors += $_.Exception.Message
            continue
        }
        $nameKey = $normalizedName.ToUpperInvariant()
        if ($seenNames.ContainsKey($nameKey)) {
            $errors += "Manifest contains duplicate artifact '$normalizedName'."
            continue
        }
        $seenNames[$nameKey] = $true
        $platformRelativeName = $normalizedName.Replace([char]92, [System.IO.Path]::DirectorySeparatorChar)
        $artifactPath = Join-Path -Path $resolvedDirectory -ChildPath $platformRelativeName
        try {
            if (-not (Test-CasePathContained -Root $resolvedDirectory -Candidate $artifactPath)) {
                throw "artifact path escapes InputDirectory: $name"
            }
            if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
                throw "artifact is missing: $name"
            }
            $artifactItem = Get-Item -LiteralPath $artifactPath -ErrorAction Stop
            if (($artifactItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "artifact is a reparse point: $name"
            }
            $declaredSizeValue = Get-CaseJsonProperty -InputObject $artifact -Name 'SizeBytes'
            $declaredHash = [string](Get-CaseJsonProperty -InputObject $artifact -Name 'Sha256')
            if ($null -eq $declaredSizeValue) {
                throw "artifact is missing SizeBytes: $name"
            }
            $declaredSize = [int64]$declaredSizeValue
            if ($declaredSize -lt 0 -or $artifactItem.Length -ne $declaredSize) {
                throw "artifact size mismatch: $name (manifest=$declaredSize, actual=$($artifactItem.Length))"
            }
            if ($declaredHash -notmatch '^[A-Fa-f0-9]{64}$') {
                throw "artifact has an invalid SHA-256: $name"
            }
            $actualHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($actualHash -ne $declaredHash) {
                throw "artifact hash mismatch: $name (manifest=$declaredHash, actual=$actualHash)"
            }
            $verifiedCount++
        }
        catch {
            $errors += $_.Exception.Message
        }
    }
    $report.verifiedArtifactCount = $verifiedCount
    $packageVerification = Invoke-CasePackageVerification `
        -Directory $resolvedDirectory `
        -Manifest $manifest `
        -ArtifactEntries $artifactEntries
    $report.package = $packageVerification.Summary
    $errors += @($packageVerification.Errors)
    $report.errors = $errors
    if ($errors.Count -eq 0) {
        $report.status = 'verified'
    }
    return $report
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

function Test-IsElevatedConsole {
    <#
      True only when the current process is running in an Administrator role.
      Isolated so both the consent-gated capture helper and the concurrent WPR
      job path make the SAME decision, and so the non-admin branch stays
      testable. Returns $false on hosts without a Windows principal (Linux CI).
    #>
    param()

    try {
        $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
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
            $isElevated = Test-IsElevatedConsole
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
                # the capture body may emit native-tool output (wpr.exe -start/
                # -stop print to stdout) BEFORE its final return - pick the LAST
                # result dictionary out of the stream instead of assuming a
                # single-object return (WPD-10 caught this: an array of stray
                # strings + the dict made '.Keys' throw even though the ETL was
                # written fine)
                $captureOutput = @(& $CaptureBody)
                $captureResult = $captureOutput | Where-Object { $_ -is [System.Collections.IDictionary] } | Select-Object -Last 1
                if ($null -eq $captureResult) {
                    throw "Capture body for stage '$StageName' did not return a result object"
                }
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
      Returns the newest up to MaxEvents records and stops reading once that
      bound is reached.
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
    # Read newest first. This makes MaxEvents a real I/O bound instead of a
    # sliding buffer over every matching record in a busy 24-hour log.
    $query.ReverseDirection = $true
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
                if ($buffer.Count -ge $MaxEvents) {
                    break
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

function ConvertTo-HostsEntryLines {
    <#
      Flattens hosts-file content into plain, non-empty, non-comment STRINGS.

      Root cause this exists for: the previous implementation piped Select-String
      output straight into the network state, so every "entry" was a MatchInfo
      object whose PSObject graph drags in PSProvider, reflection metadata,
      assemblies and defined types. Network-state.json serialized to 555 MB as a
      result. A hosts file has a handful of lines, so the report should be a
      handful of bytes.

      Accepts file lines OR MatchInfo-like objects (anything with .Line) so a
      future refactor cannot silently reintroduce provider objects.
    #>
    param([AllowNull()][object[]]$Lines)

    $entries = @()
    foreach ($line in @($Lines)) {
        if ($null -eq $line) { continue }
        $text = $null
        if ($line -is [string]) {
            $text = $line
        }
        else {
            $text = Get-SafeObjectProperty -InputObject $line -Name 'Line'
            if ($null -eq $text) { $text = [string]$line }
        }
        $trimmed = ([string]$text).Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed.StartsWith('#')) { continue }
        $entries += [string]$trimmed
    }
    return , @($entries)
}

function Get-EventsWithRawXml {
    <#
      Reads a log via the low-level .NET reader and returns each record with its
      raw event XML. Windows cannot render the message when a provider's
      message-resource DLL is missing or mismatched - the XML survives, so a
      technician can still read the EventData (the nvlddmkm / TDR / LiveKernel
      fault path hits this constantly). Record-by-record keeps one bad provider
      from wiping the query, exactly like Get-EventsSafe.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$LogName,
        [Parameter(Mandatory = $true)][datetime]$StartTime,
        [int]$MaxEvents = 200,
        [int]$MaxXmlChars = 8000
    )

    $isoTime = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    $xpath = "*[System[TimeCreated[@SystemTime>='$isoTime']]]"
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
    $query.ReverseDirection = $true
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
                $rawXml = $null
                try {
                    $rawXml = $rec.ToXml()
                }
                catch {
                    $rawXml = $null
                }
                if ($null -ne $rawXml -and $rawXml.Length -gt $MaxXmlChars) {
                    $rawXml = $rawXml.Substring(0, $MaxXmlChars) + '<!-- truncated -->'
                }
                [void]$buffer.Add([pscustomobject]@{
                    TimeCreated = $rec.TimeCreated
                    LevelDisplayName = $level
                    Id = $rec.Id
                    ProviderName = $rec.ProviderName
                    LogName = [string]$LogName
                    Message = $msg
                    RawXml = $rawXml
                })
                if ($buffer.Count -ge $MaxEvents) {
                    break
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

function Add-IncidentWindowLabels {
    <#
      Pure labelling step: every event keeps its row and gains an
      IncidentWindow field of 'in-window' or 'out-of-window' (or $null when the
      window is unusable). Out-of-window events are labelled, never dropped, so
      the report can distinguish "happened during the incident" from "background
      noise that also exists on this machine".
    #>
    param(
        [AllowNull()][object[]]$Events,
        [AllowNull()][object]$WindowStart,
        [AllowNull()][object]$WindowEnd,
        [int]$WindowMinutes = 15
    )

    $rows = @()
    foreach ($event in @($Events)) {
        if ($null -eq $event) { continue }
        $rows += [pscustomobject]@{
            TimeCreated = Get-SafeObjectProperty -InputObject $event -Name 'TimeCreated'
            IncidentWindow = Test-IncidentWindowMembership `
                -EventTime (Get-SafeObjectProperty -InputObject $event -Name 'TimeCreated') `
                -WindowStart $WindowStart `
                -WindowEnd $WindowEnd `
                -WindowMinutes $WindowMinutes
            LevelDisplayName = Get-SafeObjectProperty -InputObject $event -Name 'LevelDisplayName'
            Id = Get-SafeObjectProperty -InputObject $event -Name 'Id'
            ProviderName = Get-SafeObjectProperty -InputObject $event -Name 'ProviderName'
            LogName = Get-SafeObjectProperty -InputObject $event -Name 'LogName'
            Message = Get-SafeObjectProperty -InputObject $event -Name 'Message'
            RawXml = Get-SafeObjectProperty -InputObject $event -Name 'RawXml'
        }
    }
    return $rows
}

function Get-StorageTopology {
    <#
      Maps each drive letter to the physical disk that backs it, plus the
      partition/offset. Low free space on a drive that does not back the working
      set, the pagefile, or the application cache is irrelevant to a
      performance complaint; without this map the report cannot say which
      volumes actually matter. Uses Win32_LogicalDiskToPartition +
      Win32_DiskDriveToDiskPartition (documented association classes).
    #>
    param()

    $driveToDisk = [ordered]@{}
    try {
        $partitionToDisk = @{}
        foreach ($mapping in @(Get-CimInstance -ClassName 'Win32_DiskDriveToDiskPartition' -ErrorAction Stop)) {
            $disk = $mapping.Antecedent
            $partition = $mapping.Dependent
            if ($null -eq $disk -or $null -eq $partition) { continue }
            $partitionToDisk[[string]$partition.DeviceID] = [string]$disk.DeviceID
        }

        $diskDetails = @{}
        foreach ($disk in @(Get-CimInstance -ClassName 'Win32_DiskDrive' -ErrorAction Stop)) {
            $diskDetails[[string]$disk.DeviceID] = [pscustomobject]@{
                Model = [string]$disk.Model
                SerialNumber = [string]$disk.SerialNumber
                MediaType = [string]$disk.MediaType
                SizeBytes = Get-SafeObjectProperty -InputObject $disk -Name 'Size'
            }
        }

        foreach ($mapping in @(Get-CimInstance -ClassName 'Win32_LogicalDiskToPartition' -ErrorAction Stop)) {
            $partition = $mapping.Antecedent
            $logicalDisk = $mapping.Dependent
            if ($null -eq $partition -or $null -eq $logicalDisk) { continue }
            $partitionId = [string]$partition.DeviceID
            $deviceId = [string]$logicalDisk.DeviceID
            $diskId = $null
            if ($partitionToDisk.ContainsKey($partitionId)) { $diskId = $partitionToDisk[$partitionId] }
            $diskInfo = $null
            if ($null -ne $diskId -and $diskDetails.ContainsKey($diskId)) { $diskInfo = $diskDetails[$diskId] }
            $driveToDisk[$deviceId] = [pscustomobject]@{
                DriveLetter = $deviceId
                PartitionDeviceId = $partitionId
                DiskDeviceId = $diskId
                DiskModel = if ($null -ne $diskInfo) { $diskInfo.Model } else { $null }
                DiskSerialNumber = if ($null -ne $diskInfo) { $diskInfo.SerialNumber } else { $null }
                DiskMediaType = if ($null -ne $diskInfo) { $diskInfo.MediaType } else { $null }
                DiskSizeBytes = if ($null -ne $diskInfo) { $diskInfo.SizeBytes } else { $null }
            }
        }
    }
    catch {
        Add-CollectionErrorText -Stage 'storage-topology' -Message "Storage topology mapping unavailable: $($_.Exception.Message)"
    }
    return $driveToDisk
}

function Get-VolumeStorageMapping {
    <#
      Joins per-volume free space (Get-VolumeMetrics output) with the drive
      letter -> physical disk map and the pagefile placement, so a report can
      say "C: is on the NVMe, D: (archive) is on the SATA drive and is NOT the
      pagefile host". Pure join over supplied data.
    #>
    param(
        [AllowNull()][object[]]$VolumeMetrics,
        [AllowNull()][object]$DriveToDiskMap,
        [AllowNull()][object[]]$PageFileMetrics
    )

    $pageFileDrives = @()
    foreach ($pageFile in @($PageFileMetrics)) {
        $driveLetter = Get-SafeObjectProperty -InputObject $pageFile -Name 'DriveLetter'
        if (-not [string]::IsNullOrWhiteSpace([string]$driveLetter)) { $pageFileDrives += ([string]$driveLetter).ToUpperInvariant() }
    }

    $rows = @()
    foreach ($volume in @($VolumeMetrics)) {
        if ($null -eq $volume) { continue }
        $driveLetter = [string](Get-SafeObjectProperty -InputObject $volume -Name 'DriveLetter')
        $diskInfo = $null
        if ($null -ne $DriveToDiskMap) {
            if ($DriveToDiskMap -is [System.Collections.IDictionary]) {
                if ($DriveToDiskMap.Contains($driveLetter)) { $diskInfo = $DriveToDiskMap[$driveLetter] }
            }
            else {
                $property = $DriveToDiskMap.PSObject.Properties[$driveLetter]
                if ($null -ne $property) { $diskInfo = $property.Value }
            }
        }
        $rows += [pscustomobject]@{
            DriveLetter = $driveLetter
            Label = Get-SafeObjectProperty -InputObject $volume -Name 'Label'
            FileSystem = Get-SafeObjectProperty -InputObject $volume -Name 'FileSystem'
            CapacityBytes = Get-SafeObjectProperty -InputObject $volume -Name 'CapacityBytes'
            FreeSpaceBytes = Get-SafeObjectProperty -InputObject $volume -Name 'FreeSpaceBytes'
            PercentFree = Get-SafeObjectProperty -InputObject $volume -Name 'PercentFree'
            PhysicalDiskModel = if ($null -ne $diskInfo) { Get-SafeObjectProperty -InputObject $diskInfo -Name 'DiskModel' } else { $null }
            PhysicalDiskDeviceId = if ($null -ne $diskInfo) { Get-SafeObjectProperty -InputObject $diskInfo -Name 'DiskDeviceId' } else { $null }
            HostsPageFile = ($pageFileDrives -contains $driveLetter.ToUpperInvariant())
        }
    }
    return $rows
}

function Start-WprBoundedCaptureJob {
    <#
      Runs one COMPLETE bounded WPR trace as a background job: start, wait out
      the window while the parent keeps sampling counters, then stop and report.

      Bounding, using ONLY documented wpr.exe behavior
      (https://learn.microsoft.com/windows-hardware/test/wpt/wpr-command-line-options):
      - MEMORY mode is used deliberately (no -filemode). Microsoft documents
        -filemode as "the data is recorded to an unbounded file, which can grow
        in size until it fills the disk" and states the default is memory; the
        memory buffer is the documented circular buffer, so the trace cannot
        balloon on disk the way the reported 1.13 GB run did.
      - Duration is bounded by the caller's window. The job stops the trace as
        soon as the caller writes the stop sentinel (the parent does that the
        moment counter sampling ends), and falls back to its own maximum window
        if the sentinel never arrives. The recorded duration is the MEASURED wall
        clock, never the requested value.
      - MaxFileMB is an ADVISORY post-capture cap. wpr.exe has no documented
        file-size switch, so the size is enforced after the trace is written: an
        oversized ETL (and the managed-symbol files WPR writes next to it) is
        removed and reported, instead of shipping gigabytes in the case folder.

      Returns a live job object whose result carries
      { StartExitCode, StopExitCode, StartedAtUtc, CompletedAtUtc, ElapsedSeconds,
        EtlPath, EtlBytes, SizeLimitExceeded, TraceRemoved, RelatedArtifacts, Error }.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WprExePath,
        [Parameter(Mandatory = $true)][string]$Profile,
        [Parameter(Mandatory = $true)][string]$EtlPath,
        [ValidateRange(5, 600)][int]$DurationSeconds = 60,
        [ValidateRange(0, 4096)][int]$MaxFileMB = 512,
        [bool]$KeepOversizedTrace = $false,
        [Parameter(Mandatory = $true)][string]$StopSentinelPath
    )

    return Start-Job -ScriptBlock {
        param($ExePath, $TraceProfile, $OutputPath, $Seconds, $MaxFileMB, $KeepOversized, $StopSentinel)

        $result = [ordered]@{
            StartExitCode = $null
            StopExitCode = $null
            StartedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
            CompletedAtUtc = $null
            ElapsedSeconds = $null
            EtlPath = $OutputPath
            EtlBytes = $null
            SizeLimitExceeded = $false
            TraceRemoved = $false
            RelatedArtifacts = @()
            Error = $null
        }

        $startArguments = @('-start', $TraceProfile)
        try {
            & $ExePath @startArguments
            $result.StartExitCode = $LASTEXITCODE
        }
        catch {
            $result.StartExitCode = -1
            $result.Error = $_.Exception.Message
            $result.CompletedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
            return [pscustomobject]$result
        }

        if ($result.StartExitCode -eq 0) {
            # Wait for the caller's stop sentinel (sampling finished) or the
            # maximum window, whichever comes first. A fixed sleep here made the
            # trace outlive the counters it is supposed to explain.
            $deadline = (Get-Date).AddSeconds($Seconds)
            while ((Get-Date) -lt $deadline) {
                if (Test-Path -LiteralPath $StopSentinel -PathType Leaf) { break }
                Start-Sleep -Milliseconds 500
            }
            try {
                & $ExePath -stop $OutputPath
                $result.StopExitCode = $LASTEXITCODE
            }
            catch {
                $result.StopExitCode = -1
                $result.Error = $_.Exception.Message
            }
        }

        $result.CompletedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        try {
            $result.ElapsedSeconds = [Math]::Round(
                (New-TimeSpan -Start ([datetime]$result.StartedAtUtc) -End ([datetime]$result.CompletedAtUtc)).TotalSeconds, 2)
        }
        catch {
            $result.ElapsedSeconds = $null
        }

        if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
            $etlItem = Get-Item -LiteralPath $OutputPath
            $result.EtlBytes = $etlItem.Length

            # WPR writes managed-symbol artifacts alongside the trace; collect
            # them so the case folder does not silently carry a second payload.
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
            $siblings = @()
            try {
                $siblings = @(Get-ChildItem -LiteralPath $etlItem.DirectoryName -Force -ErrorAction Stop |
                    Where-Object {
                        $_.FullName -ne $etlItem.FullName -and
                        $_.Name -like ($baseName + '*')
                    })
            }
            catch {
                $siblings = @()
            }
            foreach ($sibling in $siblings) {
                $siblingBytes = $null
                if (-not $sibling.PSIsContainer) { $siblingBytes = $sibling.Length }
                $result.RelatedArtifacts += [pscustomobject]@{
                    Name = $sibling.Name
                    FullPath = $sibling.FullName
                    IsDirectory = [bool]$sibling.PSIsContainer
                    SizeBytes = $siblingBytes
                }
            }

            if ($MaxFileMB -gt 0 -and ([int64]$etlItem.Length -gt ([int64]$MaxFileMB * 1MB))) {
                $result.SizeLimitExceeded = $true
                if (-not $KeepOversized) {
                    Remove-Item -LiteralPath $etlItem.FullName -Force -ErrorAction SilentlyContinue
                    foreach ($sibling in $siblings) {
                        Remove-Item -LiteralPath $sibling.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    $result.TraceRemoved = -not (Test-Path -LiteralPath $OutputPath -PathType Leaf)
                }
            }
        }

        return [pscustomobject]$result
    } -ArgumentList $WprExePath, $Profile, $EtlPath, $DurationSeconds, $MaxFileMB, $KeepOversizedTrace, $StopSentinelPath
}

function Get-UdpEndpointSample {
    <#
      One UDP endpoint census: total endpoints, endpoints grouped by owning
      PID/process, and how many fall inside the configured dynamic range.
      UDP exhaustion is invisible to a TCP-only view, and endpoint counts that
      grow across samples identify the process that is leaking them.

      -NetstatOutput lets a test feed synthetic `netstat -ano` text instead of
      running netstat, so the grouping math is verifiable off-Windows.
    #>
    param(
        [AllowNull()][string[]]$NetstatOutput
    )

    if ($null -ne $NetstatOutput) {
        $netstatLines = @($NetstatOutput)
    }
    else {
        $netstatLines = @(& netstat -ano)
    }

    $endpoints = @(
        $netstatLines | Where-Object { $_ -match '^\s*UDP' } | ForEach-Object {
            $parts = @(($_ -split '\s+') | Where-Object { $_ })
            if ($parts.Count -ge 4) {
                $localEndpoint = $parts[1]
                $owningProcess = $parts[3]
                $processName = $null
                try {
                    $processName = (Get-Process -Id ([int]$owningProcess) -ErrorAction Stop).ProcessName
                }
                catch {
                    $processName = $null
                }
                [pscustomobject]@{
                    LocalAddress = ($localEndpoint -split ':')[0]
                    LocalPort = [int](($localEndpoint -split ':')[-1])
                    OwningProcess = [int]$owningProcess
                    ProcessName = $processName
                }
            }
        }
    )
    if ($endpoints.Count -eq 0) { return $null }

    $byProcess = @(
        $endpoints | Group-Object -Property OwningProcess | ForEach-Object {
            [pscustomobject]@{
                OwningProcess = [int]$_.Name
                ProcessName = @($_.Group | Select-Object -First 1)[0].ProcessName
                EndpointCount = $_.Count
            }
        } | Sort-Object -Property EndpointCount -Descending
    )

    return [pscustomobject]@{
        TimestampUtc = Get-UtcTimestamp
        TotalUdpEndpoints = $endpoints.Count
        EndpointsByProcess = @($byProcess)
    }
}

function Select-MarkerRetainedSeries {
    <#
      Pure retention rule for marker mode. Without a marker the whole baseline
      series is returned (unchanged behavior). With a marker the retained series
      is MarkerPreSeconds of samples before the marker plus every sample up to
      MarkerPostSeconds after it; the caller reports what was dropped so the
      retention is explicit rather than silent.
    #>
    param(
        [AllowNull()][object[]]$Samples,
        [AllowNull()][object]$MarkerTimeUtc,
        [ValidateRange(0, 600)][int]$MarkerPreSeconds = 60,
        [ValidateRange(5, 600)][int]$MarkerPostSeconds = 30
    )

    $all = @($Samples | Where-Object { $null -ne $_ })
    if ($null -eq $MarkerTimeUtc) {
        return [pscustomobject]@{
            Series = $all
            IncidentWindowStartUtc = $null
            IncidentWindowEndUtc = $null
            RetainedSampleCount = $all.Count
            DroppedSampleCount = 0
            MarkerApplied = $false
        }
    }

    $markerUtc = $null
    try { $markerUtc = ([datetime]$MarkerTimeUtc).ToUniversalTime() } catch { $markerUtc = $null }
    if ($null -eq $markerUtc) {
        return [pscustomobject]@{
            Series = $all
            IncidentWindowStartUtc = $null
            IncidentWindowEndUtc = $null
            RetainedSampleCount = $all.Count
            DroppedSampleCount = 0
            MarkerApplied = $false
        }
    }

    $windowStart = $markerUtc.AddSeconds(-1 * $MarkerPreSeconds)
    $windowEnd = $markerUtc.AddSeconds($MarkerPostSeconds)
    $retained = @()
    foreach ($sample in $all) {
        $stamp = Get-SafeObjectProperty -InputObject $sample -Name 'TimestampUtc'
        if ($null -eq $stamp) { continue }
        $sampleUtc = $null
        try { $sampleUtc = ([datetime]$stamp).ToUniversalTime() } catch { $sampleUtc = $null }
        if ($null -eq $sampleUtc) { continue }
        if ($sampleUtc -ge $windowStart -and $sampleUtc -le $windowEnd) {
            $retained += $sample
        }
    }

    return [pscustomobject]@{
        Series = $retained
        IncidentWindowStartUtc = $windowStart
        IncidentWindowEndUtc = $windowEnd
        RetainedSampleCount = $retained.Count
        DroppedSampleCount = ($all.Count - $retained.Count)
        MarkerApplied = $true
    }
}

function Test-CaptureWindowCoverage {
    <#
      Pure check that the WPR trace actually covers the counter-sampling window.
      A trace that starts after the counters stopped cannot explain the pressure
      they recorded - that was a real defect, so the report must be able to say
      so instead of implying the ETL covers the incident.
      Returns { Covers, Status, Detail } where Status is one of
      'covers-window', 'trace-starts-after-counters', 'trace-ends-before-counters',
      'partial-overlap', 'no-trace', 'no-window'.
    #>
    param(
        [AllowNull()][object]$CaptureWindow,
        [AllowNull()][object]$WprStartUtc,
        [AllowNull()][object]$WprStopUtc
    )

    $samplingStart = Get-CaseJsonProperty -InputObject $CaptureWindow -Name 'startedAtUtc'
    $samplingEnd = Get-CaseJsonProperty -InputObject $CaptureWindow -Name 'completedAtUtc'

    if ($null -eq $samplingStart -or $null -eq $samplingEnd) {
        return [pscustomobject]@{ Covers = $false; Status = 'no-window'; Detail = 'Counter window start/end unavailable; overlap cannot be established.' }
    }
    if ($null -eq $WprStartUtc -or $null -eq $WprStopUtc) {
        return [pscustomobject]@{ Covers = $false; Status = 'no-trace'; Detail = 'No WPR trace was recorded for this collection.' }
    }

    try {
        $sStart = ([datetime]$samplingStart).ToUniversalTime()
        $sEnd = ([datetime]$samplingEnd).ToUniversalTime()
        $tStart = ([datetime]$WprStartUtc).ToUniversalTime()
        $tStop = ([datetime]$WprStopUtc).ToUniversalTime()
    }
    catch {
        return [pscustomobject]@{ Covers = $false; Status = 'no-window'; Detail = 'Window timestamps could not be parsed.' }
    }

    if ($tStart -ge $sEnd) {
        return [pscustomobject]@{
            Covers = $false
            Status = 'trace-starts-after-counters'
            Detail = "The trace started at $($tStart.ToString('o')), after the counters stopped at $($sEnd.ToString('o')); the trace cannot explain the sampled pressure."
        }
    }
    if ($tStop -le $sStart) {
        return [pscustomobject]@{
            Covers = $false
            Status = 'trace-ends-before-counters'
            Detail = "The trace ended at $($tStop.ToString('o')), before the counters started at $($sStart.ToString('o')); the trace cannot explain the sampled pressure."
        }
    }
    if ($tStart -gt $sStart -or $tStop -lt $sEnd) {
        return [pscustomobject]@{
            Covers = $false
            Status = 'partial-overlap'
            Detail = "The trace window $($tStart.ToString('o'))..$($tStop.ToString('o')) only partially overlaps the counter window $($sStart.ToString('o'))..$($sEnd.ToString('o'))."
        }
    }
    return [pscustomobject]@{
        Covers = $true
        Status = 'covers-window'
        Detail = "The trace window $($tStart.ToString('o'))..$($tStop.ToString('o')) fully covers the counter window $($sStart.ToString('o'))..$($sEnd.ToString('o'))."
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
        # Event Viewer may display this source as "BugCheck", while the
        # underlying provider is usually Microsoft-Windows-WER-SystemErrorReporting.
        $Events | Where-Object {
            $_.Id -eq 1001 -and
            ($_.ProviderName -eq 'BugCheck' -or $_.ProviderName -match 'WER-SystemErrorReporting')
        } | ForEach-Object {
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

function Resolve-DnsAddressesBounded {
    <#
      Resolves one name through the asynchronous .NET resolver with a hard
      caller-side timeout. GetHostAddresses() is synchronous and can block for
      minutes when DNS is silently dropped; do not use it in Collect mode.
      A timed-out resolver task is deliberately not awaited further: it may
      finish later, but it cannot hold up the diagnostic pipeline.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [ValidateRange(1, 30000)][int]$TimeoutMilliseconds = 2000,
        [AllowNull()][scriptblock]$Resolver
    )

    if ($null -eq $Resolver) {
        $Resolver = {
            param($Name)
            [System.Net.Dns]::GetHostAddressesAsync($Name)
        }
    }
    $task = & $Resolver $Domain
    if ($null -eq $task) {
        throw "DNS resolution did not return a task for '$Domain'."
    }
    if (-not $task.Wait($TimeoutMilliseconds)) {
        throw "DNS resolution timed out after $TimeoutMilliseconds ms for '$Domain'."
    }
    return @($task.Result | ForEach-Object { $_.IPAddressToString })
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
    # Probes are hard-timeout bounded (.NET Ping 2s; asynchronous DNS resolver
    # waited for no more than 2s) - Test-Connection/Resolve-DnsName can block for minutes when
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
                Resolve-DnsAddressesBounded -Domain $domain -TimeoutMilliseconds 2000
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
            # Materialize plain strings BEFORE serialization. Select-String /
            # Where-Object emit MatchInfo objects whose PSObject graph pulls in
            # PSProvider, reflection metadata, assemblies and defined types; a
            # single hosts file then serializes into hundreds of megabytes.
            $activeEntries = ConvertTo-HostsEntryLines -Lines @(Get-Content -LiteralPath $hostsPath)
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
        # Cast to a plain string array: a registry read returns provider-backed
        # objects that drag the whole PSObject graph into the JSON.
        $ieProxyValues = @()
        $ieProxy = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
        if ($null -ne $ieProxy) {
            foreach ($proxyName in @('ProxyEnable', 'ProxyServer', 'AutoConfigURL')) {
                $proxyValue = Get-PropertyValue -InputObject $ieProxy -Name $proxyName
                if ($null -ne $proxyValue) {
                    $ieProxyValues += [pscustomobject]@{
                        Name = $proxyName
                        Value = [string]$proxyValue
                    }
                }
            }
        }
        $state['proxySettings'] = [ordered]@{
            winhttpProxy = $winhttpProxy
            internetSettings = @($ieProxyValues)
        }
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'proxy'; Message = $_.Exception.Message }
    }

    try {
        # netstat -ano instead of Get-NetTCPConnection: the cmdlet enumerates
        # per-connection owning processes and can take minutes for a restricted
        # token (batch-logon standard user); netstat is native and instant.
        # UDP has no State column, so it is parsed separately - UDP endpoint
        # exhaustion is a real fault mode that a TCP-only view cannot see.
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

        $udpEndpoints = @(
            (& netstat -ano) | Where-Object { $_ -match '^\s*UDP' } | ForEach-Object {
                $parts = @(($_ -split '\s+') | Where-Object { $_ })
                if ($parts.Count -ge 4) {
                    $localEndpoint = $parts[1]
                    $owningProcess = $parts[3]
                    $processName = $null
                    try {
                        $processName = (Get-Process -Id ([int]$owningProcess) -ErrorAction Stop).ProcessName
                    }
                    catch {
                        $processName = $null
                    }
                    [pscustomobject]@{
                        LocalAddress = ($localEndpoint -split ':')[0]
                        LocalPort = [int](($localEndpoint -split ':')[-1])
                        OwningProcess = [int]$owningProcess
                        ProcessName = $processName
                    }
                }
            }
        )
        $state['udpEndpoints'] = $udpEndpoints
        $state['udpEndpointCountByProcess'] = @(
            $udpEndpoints | Group-Object -Property OwningProcess | ForEach-Object {
                [pscustomobject]@{
                    OwningProcess = [int]$_.Name
                    ProcessName = @($_.Group | Select-Object -First 1)[0].ProcessName
                    EndpointCount = $_.Count
                }
            } | Sort-Object -Property EndpointCount -Descending
        )
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'tcp-connections'; Message = $_.Exception.Message }
    }

    try {
        # The configured dynamic (ephemeral) port ranges bound how many UDP
        # endpoints can exist at once - the denominator for an exhaustion call.
        $dynamicUdpRanges = @()
        foreach ($family in @('ipv4', 'ipv6')) {
            try {
                $rangeOutput = ((& netsh int $family show dynamicport udp) -join ' ')
                $startMatch = [regex]::Match($rangeOutput, 'start port\s*:\s*(\d+)', 'IgnoreCase')
                $numberMatch = [regex]::Match($rangeOutput, 'number of ports\s*:\s*(\d+)', 'IgnoreCase')
                if ($startMatch.Success -and $numberMatch.Success) {
                    $rangeStart = [int]$startMatch.Groups[1].Value
                    $rangeCount = [int]$numberMatch.Groups[1].Value
                    $dynamicUdpRanges += [pscustomobject]@{
                        Family = $family
                        StartPort = $rangeStart
                        PortCount = $rangeCount
                        EndPort = $rangeStart + $rangeCount - 1
                    }
                }
            }
            catch {
                $errors += [pscustomobject]@{ Section = "dynamic-udp-range-$family"; Message = $_.Exception.Message }
            }
        }
        $state['dynamicUdpPortRanges'] = @($dynamicUdpRanges)
        $inRangeCount = 0
        foreach ($endpoint in $udpEndpoints) {
            foreach ($range in $dynamicUdpRanges) {
                if ($endpoint.LocalPort -ge $range.StartPort -and $endpoint.LocalPort -le $range.EndPort) {
                    $inRangeCount++
                    break
                }
            }
        }
        $state['dynamicUdpPortUsage'] = [ordered]@{
            totalUdpEndpoints = $udpEndpoints.Count
            endpointsInsideDynamicRange = $inRangeCount
        }
    }
    catch {
        $errors += [pscustomobject]@{ Section = 'dynamic-udp-range'; Message = $_.Exception.Message }
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

if ($Mode -eq 'Verify') {
    if ([string]::IsNullOrWhiteSpace($InputDirectory)) {
        throw 'Verify mode requires -InputDirectory. No files were modified.'
    }
    $verificationReport = Invoke-CaseVerification -Directory $InputDirectory
    Write-Output ($verificationReport | ConvertTo-Json -Depth 8)
    if ($verificationReport.status -ne 'verified') {
        exit 1
    }
    exit 0
}

# ---- Telemetry helpers (used by Collect mode, dot-sourceable for tests) ----

function Get-SafeObjectProperty {
    <#
      StrictMode-safe property read for arbitrary objects (processes, CIM
      instances, raw counter snapshots). Returns $null when the property is
      absent or its getter throws - protected/exiting process properties such
      as StartTime, CPU or Path can throw even though the process object exists,
      and one bad process must not abort the whole snapshot stage.
    #>
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    try {
        $property = $InputObject.PSObject.Properties[$Name]
        if ($null -ne $property) { return $property.Value }
    }
    catch { }
    return $null
}

function Get-PerProcessMemorySample {
    <#
      Repeated per-process commit attribution from
      Win32_PerfFormattedData_PerfProc_Process. Working-set alone cannot answer
      "what consumed the commit charge": PrivateBytes is the process commit
      charge, PageFileBytes is its pagefile-backed share, and WorkingSetPrivate
      separates private resident memory from shared pages. _Total is excluded
      (it double-counts the per-process rows). Returns a flat PSCustomObject
      list, never provider-backed objects, so JSON serialization stays small.
    #>
    param(
        [ValidateRange(1, 2000)][int]$MaxProcesses = 60
    )

    $counters = @(Get-CimInstance -ClassName 'Win32_PerfFormattedData_PerfProc_Process' -ErrorAction Stop |
        Where-Object { $_.Name -ne '_Total' })
    if ($counters.Count -eq 0) { return @() }

    return @($counters | ForEach-Object {
        [pscustomobject]@{
            Name = [string]$_.Name
            Id = [int]$_.IDProcess
            PrivateBytes = [int64]$_.PrivateBytes
            WorkingSet = [int64]$_.WorkingSet
            WorkingSetPrivate = [int64]$_.WorkingSetPrivate
            PageFileBytes = [int64]$_.PageFileBytes
            PageFileBytesPeak = [int64]$_.PageFileBytesPeak
            VirtualBytes = [int64]$_.VirtualBytes
            PoolPagedBytes = [int64]$_.PoolPagedBytes
            PoolNonpagedBytes = [int64]$_.PoolNonpagedBytes
            HandleCount = [int]$_.HandleCount
            ThreadCount = [int]$_.ThreadCount
        }
    } | Sort-Object -Property PrivateBytes -Descending | Select-Object -First $MaxProcesses)
}

function Get-KernelPoolMetrics {
    <#
      System-wide paged/nonpaged kernel pool from
      Win32_PerfFormattedData_PerfOS_Memory. Pool growth is a classic cause of
      unexplained commit/nonpaged charge that per-process views miss.
    #>
    param()

    try {
        $memory = Get-CimInstance -ClassName 'Win32_PerfFormattedData_PerfOS_Memory' -ErrorAction Stop
        return [pscustomobject]@{
            poolPagedBytes = Get-SafeObjectProperty -InputObject $memory -Name 'PoolPagedBytes'
            poolNonpagedBytes = Get-SafeObjectProperty -InputObject $memory -Name 'PoolNonpagedBytes'
            poolPagedResidentBytes = Get-SafeObjectProperty -InputObject $memory -Name 'PoolPagedResidentBytes'
            systemCacheResidentBytes = Get-SafeObjectProperty -InputObject $memory -Name 'SystemCacheResidentBytes'
            cacheBytes = Get-SafeObjectProperty -InputObject $memory -Name 'CacheBytes'
        }
    }
    catch {
        Add-CollectionErrorText -Stage 'kernel-pool' -Message "Win32_PerfFormattedData_PerfOS_Memory pool counters unavailable: $($_.Exception.Message)"
        return $null
    }
}

function Get-PageFileMetrics {
    <#
      Pagefile size, current usage, peak usage and location from
      Win32_PageFileUsage (AllocatedBaseSize/CurrentUsage/PeakUsage are MiB,
      Name is the pagefile path). TempPageFile marks a system-managed temporary
      pagefile. Returns null when the class is unavailable.
    #>
    param()

    try {
        $pageFiles = @(Get-CimInstance -ClassName 'Win32_PageFileUsage' -ErrorAction Stop)
        if ($pageFiles.Count -eq 0) { return $null }
        return @($pageFiles | ForEach-Object {
            [pscustomobject]@{
                Name = [string]$_.Name
                DriveLetter = if ($_.Name -match '^([A-Za-z]):') { $matches[1].ToUpperInvariant() + ':' } else { $null }
                AllocatedBaseSizeMB = Get-SafeObjectProperty -InputObject $_ -Name 'AllocatedBaseSize'
                CurrentUsageMB = Get-SafeObjectProperty -InputObject $_ -Name 'CurrentUsage'
                PeakUsageMB = Get-SafeObjectProperty -InputObject $_ -Name 'PeakUsage'
                TempPageFile = Get-SafeObjectProperty -InputObject $_ -Name 'TempPageFile'
            }
        })
    }
    catch {
        Add-CollectionErrorText -Stage 'pagefile-metrics' -Message "Win32_PageFileUsage unavailable: $($_.Exception.Message)"
        return $null
    }
}

function ConvertFrom-GpuCounterPath {
    <#
      Pure parser for a PDH instance path such as
      "\\<machine>\GPU Engine(pid_1234_luid_0x00000000_0x0000ABCD_phys_0_eng_1_engtype_3D)\Utilization Percentage"
      or the already-split instance name "pid_1234_..._engtype_3D".
      Returns the PID, engine type and LUID, or $null when the instance is not a
      per-process GPU instance. Kept separate from the collection so it is
      testable without a GPU.
    #>
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $instance = $Path
    if ($Path -match '\(([^()]*)\)') { $instance = $matches[1] }

    $pidMatch = [regex]::Match($instance, 'pid_(\d+)', 'IgnoreCase')
    if (-not $pidMatch.Success) { return $null }

    $engineMatch = [regex]::Match($instance, 'engtype_([A-Za-z0-9_]+)', 'IgnoreCase')
    $luidMatch = [regex]::Match($instance, 'luid_(0x[0-9a-fA-F]+_0x[0-9a-fA-F]+)', 'IgnoreCase')

    return [pscustomobject]@{
        ProcessId = [int]$pidMatch.Groups[1].Value
        EngineType = if ($engineMatch.Success) { $engineMatch.Groups[1].Value } else { $null }
        Luid = if ($luidMatch.Success) { $luidMatch.Groups[1].Value } else { $null }
        InstanceName = $instance
    }
}

function Get-GpuMetrics {
    <#
      GPU attribution from the Windows GPU performance-counter sets:
      GPU Engine (*)\Utilization Percentage (per process+engine) and
      GPU Process Memory (*)\Dedicated Usage / Shared Usage / Total Committed.
      GPU description, driver version, adapter RAM and video-processor driver
      come from Win32_VideoController. Temperature and clocks are NOT available
      from these counter sets on most systems, so they are reported as
      unavailable rather than guessed. Returns a flat PSCustomObject block or
      $null when the GPU counters are absent (integrated/headless hosts).
    #>
    param()

    $block = [ordered]@{
        collectedAtUtc = Get-UtcTimestamp
        adapters = @()
        engines = @()
        processMemory = @()
        temperature = [ordered]@{ available = $false; reason = 'no-windows-gpu-temperature-counter-set' }
        clocks = [ordered]@{ available = $false; reason = 'no-windows-gpu-clock-counter-set' }
    }

    try {
        $controllers = @(Get-CimInstance -ClassName 'Win32_VideoController' -ErrorAction Stop)
        $block.adapters = @($controllers | ForEach-Object {
            [pscustomobject]@{
                Name = [string](Get-SafeObjectProperty -InputObject $_ -Name 'Name')
                DriverVersion = [string](Get-SafeObjectProperty -InputObject $_ -Name 'DriverVersion')
                DriverDate = [string](Get-SafeObjectProperty -InputObject $_ -Name 'DriverDate')
                AdapterRAMBytes = Get-SafeObjectProperty -InputObject $_ -Name 'AdapterRAM'
                VideoProcessor = [string](Get-SafeObjectProperty -InputObject $_ -Name 'VideoProcessor')
                Status = [string](Get-SafeObjectProperty -InputObject $_ -Name 'Status')
                PNPDeviceID = [string](Get-SafeObjectProperty -InputObject $_ -Name 'PNPDeviceID')
            }
        })
    }
    catch {
        Add-CollectionErrorText -Stage 'gpu-adapter-info' -Message "Win32_VideoController unavailable: $($_.Exception.Message)"
    }

    $counterAvailable = $false
    try {
        $engineCounters = Get-Counter -Counter '\GPU Engine(*)\Utilization Percentage' -ErrorAction Stop
        $counterAvailable = $true
        $engineRows = @()
        foreach ($sample in @($engineCounters.CounterSamples)) {
            $parsed = ConvertFrom-GpuCounterPath -Path $sample.InstanceName
            if ($null -eq $parsed) { continue }
            $value = $null
            try { $value = [double]$sample.CookedValue } catch { $value = $null }
            $engineRows += [pscustomobject]@{
                ProcessId = $parsed.ProcessId
                EngineType = $parsed.EngineType
                Luid = $parsed.Luid
                UtilizationPercent = $value
            }
        }
        $block.engines = @($engineRows | Sort-Object -Property UtilizationPercent -Descending | Select-Object -First 200)
    }
    catch {
        $block.engines = @()
        Add-CollectionErrorText -Stage 'gpu-engine-counters' -Message "GPU Engine counters unavailable: $($_.Exception.Message)"
    }

    try {
        $memoryCounters = Get-Counter -Counter '\GPU Process Memory(*)\Dedicated Usage' -ErrorAction Stop
        $counterAvailable = $true
        $memoryRows = @()
        foreach ($sample in @($memoryCounters.CounterSamples)) {
            $parsed = ConvertFrom-GpuCounterPath -Path $sample.InstanceName
            if ($null -eq $parsed) { continue }
            $dedicated = $null
            try { $dedicated = [int64]$sample.CookedValue } catch { $dedicated = $null }
            $memoryRows += [pscustomobject]@{
                ProcessId = $parsed.ProcessId
                Luid = $parsed.Luid
                DedicatedUsageBytes = $dedicated
            }
        }
        $block.processMemory = @($memoryRows | Sort-Object -Property DedicatedUsageBytes -Descending | Select-Object -First 200)
    }
    catch {
        $block.processMemory = @()
        Add-CollectionErrorText -Stage 'gpu-process-memory-counters' -Message "GPU Process Memory counters unavailable: $($_.Exception.Message)"
    }

    if (-not $counterAvailable -and $block.adapters.Count -eq 0) {
        return $null
    }
    return $block
}

function Test-IncidentWindowMembership {
    <#
      Pure classifier for an event timestamp against the incident window.
      Returns 'in-window' when the event falls inside the marked incident
      window padded by the configured minutes, 'out-of-window' otherwise, and
      $null when the window or timestamp is unusable. Never silently drops an
      out-of-window event: the caller labels and retains it.
    #>
    param(
        [AllowNull()][object]$EventTime,
        [AllowNull()][object]$WindowStart,
        [AllowNull()][object]$WindowEnd,
        [int]$WindowMinutes = 15
    )

    if ($null -eq $EventTime -or $null -eq $WindowStart -or $null -eq $WindowEnd) { return $null }
    try {
        $eventUtc = ([datetime]$EventTime).ToUniversalTime()
        $startUtc = ([datetime]$WindowStart).ToUniversalTime().AddMinutes(-1 * $WindowMinutes)
        $endUtc = ([datetime]$WindowEnd).ToUniversalTime().AddMinutes($WindowMinutes)
    }
    catch {
        return $null
    }
    if ($eventUtc -ge $startUtc -and $eventUtc -le $endUtc) { return 'in-window' }
    return 'out-of-window'
}

function Get-ProcessSnapshotKey {
    <#
      Identity key for a process snapshot: PID + process start time ticks.
      PID alone is unsafe because Windows reuses PIDs; the start time
      distinguishes a reused PID from the original process. Returns $null when
      the PID or StartTime is unavailable (protected/exiting process), which
      makes the pairing report 'unknown' instead of mis-attributing CPU.
    #>
    param([AllowNull()][object]$Process)

    $id = Get-SafeObjectProperty -InputObject $Process -Name 'Id'
    if ($null -eq $id) { return $null }
    $start = Get-SafeObjectProperty -InputObject $Process -Name 'StartTime'
    if ($null -eq $start) { return $null }
    try {
        $ticks = ([datetime]$start).Ticks
    }
    catch {
        return $null
    }
    return ('{0}_{1}' -f $id, $ticks)
}

function New-ProcessCpuSnapshot {
    <#
      Builds the baseline dictionary keyed by PID+StartTime ticks with the
      cumulative CPU seconds observed at snapshot time. Processes whose identity
      or CPU value cannot be read are skipped; their interval result is
      'unknown', never zero.
    #>
    param([AllowNull()][object[]]$Processes)

    $snapshot = @{}
    foreach ($process in @($Processes)) {
        $key = Get-ProcessSnapshotKey -Process $process
        if ($null -eq $key) { continue }
        $cpu = Get-SafeObjectProperty -InputObject $process -Name 'CPU'
        if ($null -ne $cpu) {
            try { $cpu = [double]$cpu } catch { $cpu = $null }
        }
        $snapshot[$key] = [pscustomobject]@{ CPU = $cpu }
    }
    return $snapshot
}

function Compare-ProcessCpuSnapshots {
    <#
      Pure pairing of a baseline snapshot with the end-process enumeration. Only
      processes present at BOTH endpoints with the same PID+StartTime are
      matched; reused PIDs, new processes and processes whose properties are
      protected return 'unknown'. ElapsedSeconds is the monotonic stopwatch
      window that brackets the two CPU snapshots so numerator and denominator
      describe the same interval. The cumulative CPU seconds are preserved
      alongside the normalized percentage.
    #>
    param(
        [AllowNull()][object]$StartSnapshots,
        [AllowNull()][object[]]$EndProcesses,
        [AllowNull()][object]$ElapsedSeconds,
        [AllowNull()][object]$LogicalProcessors
    )

    $results = @()
    foreach ($process in @($EndProcesses)) {
        if ($null -eq $process) { continue }
        $key = Get-ProcessSnapshotKey -Process $process
        $currentCpu = Get-SafeObjectProperty -InputObject $process -Name 'CPU'
        if ($null -ne $currentCpu) {
            try { $currentCpu = [double]$currentCpu } catch { $currentCpu = $null }
        }
        $previousCpu = $null
        if ($null -ne $key -and $null -ne $StartSnapshots -and $StartSnapshots.ContainsKey($key)) {
            $previousCpu = $StartSnapshots[$key].CPU
        }
        $percent = Get-ProcessCpuPercentage -PreviousCPU $previousCpu -CurrentCPU $currentCpu -ElapsedSeconds $ElapsedSeconds -LogicalProcessors $LogicalProcessors
        $results += [pscustomobject]@{
            ProcessName = Get-SafeObjectProperty -InputObject $process -Name 'ProcessName'
            Id = Get-SafeObjectProperty -InputObject $process -Name 'Id'
            CPU = $currentCpu
            ProcessCpuPercent = $percent
            WorkingSet64 = Get-SafeObjectProperty -InputObject $process -Name 'WorkingSet64'
            Handles = Get-SafeObjectProperty -InputObject $process -Name 'Handles'
            Path = Get-SafeObjectProperty -InputObject $process -Name 'Path'
        }
    }
    return $results
}

function Get-ProcessCpuPercentage {
    <#
      Calculate elapsed-time-based CPU percentage for a single process.
      Returns 'unknown' when PreviousCPU/CurrentCPU is missing, when the elapsed
      window is invalid, or when the logical processor count is unknown - the
      percentage cannot be normalized without it, so guessing a count would
      fabricate a measurement. A valid zero delta is a measured 0%. Impossible
      values (> 100% after normalization, e.g. a CPU counter reset or mismatched
      windows) are reported as 'unknown' rather than clamped to a plausible
      number.
    #>
    param(
        [AllowNull()]
        $PreviousCPU,

        [AllowNull()]
        $CurrentCPU,

        [AllowNull()]
        $ElapsedSeconds,

        [AllowNull()]
        $LogicalProcessors
    )

    if ($null -eq $PreviousCPU -or $null -eq $CurrentCPU) { return 'unknown' }
    if ($null -eq $ElapsedSeconds) { return 'unknown' }
    if ($null -eq $LogicalProcessors) { return 'unknown' }

    $elapsed = 0.0
    $cores = 0
    try { $elapsed = [double]$ElapsedSeconds } catch { return 'unknown' }
    try { $cores = [int]$LogicalProcessors } catch { return 'unknown' }
    if ($elapsed -le 0 -or $cores -lt 1) { return 'unknown' }

    $previous = 0.0
    $current = 0.0
    try {
        $previous = [double]$PreviousCPU
        $current = [double]$CurrentCPU
    }
    catch {
        return 'unknown'
    }
    if ([double]::IsNaN($previous) -or [double]::IsNaN($current) -or
        [double]::IsInfinity($previous) -or [double]::IsInfinity($current)) {
        return 'unknown'
    }

    $delta = $current - $previous
    if ($delta -lt 0) { return 'unknown' }
    $perProcessorSeconds = $elapsed * $cores
    if ($perProcessorSeconds -le 0) { return 'unknown' }
    $pct = [Math]::Round(($delta / $perProcessorSeconds) * 100, 2)
    if ($pct -gt 100) { return 'unknown' }
    return $pct
}

function Get-DiskMetrics {
    <#
      Reads per-disk I/O metrics via Win32_PerfFormattedData_PerfDisk_PhysicalDisk.
      Uses formatted counters (rates computed by the CIM provider between polls).
      A single 1 Hz poll yields noisy/zero rates for sub-second bursts; this is
      documented as a sampling limitation. Returns null when CIM classes are
      unavailable (e.g. Linux, restricted tokens). Never replaces missing readings
      with zero. _Total instance is excluded.
    #>
    param()

    try {
        $counters = @(Get-CimInstance -ClassName 'Win32_PerfFormattedData_PerfDisk_PhysicalDisk' -ErrorAction Stop |
            Where-Object { $_.Name -ne '_Total' } |
            Select-Object -First 64)
        if ($counters.Count -eq 0) { return $null }
        return @($counters | ForEach-Object {
            [pscustomobject]@{
                Name = $_.Name
                PercentDiskTime = $_.PercentDiskTime
                PercentDiskReadTime = $_.PercentDiskReadTime
                PercentDiskWriteTime = $_.PercentDiskWriteTime
                DiskReadsPerSec = $_.DiskReadsPerSec
                DiskWritesPerSec = $_.DiskWritesPerSec
                DiskBytesPerSec = $_.DiskBytesPerSec
                DiskReadBytesPerSec = $_.DiskReadBytesPerSec
                DiskWriteBytesPerSec = $_.DiskWriteBytesPerSec
                CurrentDiskQueueLength = $_.CurrentDiskQueueLength
                AvgDiskReadQueueLength = $_.AvgDiskReadQueueLength
                AvgDiskWriteQueueLength = $_.AvgDiskWriteQueueLength
            }
        })
    }
    catch {
        Add-CollectionErrorText -Stage 'disk-metrics' -Message "Win32_PerfFormattedData_PerfDisk_PhysicalDisk unavailable: $($_.Exception.Message)"
        return $null
    }
}

function Get-RawDiskMetrics {
    <#
      Reads the raw physical-disk performance class
      (Win32_PerfRawData_PerfDisk_PhysicalDisk; invariant CIM class, documented
      at https://learn.microsoft.com/en-us/previous-versions/aa394308(v=vs.85)).
      Raw counters are cumulative, so latency/throughput are computed by
      Get-DiskCounterDeltas between two snapshots. Returns a bounded snapshot
      plus a source error string when the class is unavailable. Missing data is
      never replaced with zero, and the request/output is bounded.
    #>
    param([int]$MaxDisks = 64)

    $result = [ordered]@{ Disks = $null; Error = $null }
    try {
        $counters = @(Get-CimInstance -ClassName 'Win32_PerfRawData_PerfDisk_PhysicalDisk' -ErrorAction Stop |
            Where-Object { $_.Name -ne '_Total' } |
            Select-Object -First $MaxDisks)
        if ($counters.Count -gt 0) {
            $result.Disks = @($counters)
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Get-FiniteNumericDelta {
    <#
      Difference between two raw counter readings, or $null when either reading
      is missing or not a finite number. Never coerces $null to zero.
    #>
    param(
        [AllowNull()][object]$Previous,
        [AllowNull()][object]$Current,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $previousRaw = Get-SafeObjectProperty -InputObject $Previous -Name $Name
    $currentRaw = Get-SafeObjectProperty -InputObject $Current -Name $Name
    if ($null -eq $previousRaw -or $null -eq $currentRaw) { return $null }
    try {
        $previousValue = [double]$previousRaw
        $currentValue = [double]$currentRaw
    }
    catch {
        return $null
    }
    if ([double]::IsNaN($previousValue) -or [double]::IsNaN($currentValue) -or
        [double]::IsInfinity($previousValue) -or [double]::IsInfinity($currentValue)) {
        return $null
    }
    return ($currentValue - $previousValue)
}

function Get-AverageTimerDelta {
    <#
      Raw PERF_AVERAGE_TIMER conversion used for AvgDiskSecPerRead /
      AvgDiskSecPerWrite: (value delta / Frequency_PerfTime) / operation-base
      delta. Returns $null with a coverage reason when there is no baseline, no
      I/O, a counter reset, a missing property or a missing frequency - never a
      fake zero latency.
    #>
    param(
        [AllowNull()][object]$Previous,
        [AllowNull()][object]$Current,
        [Parameter(Mandatory = $true)][string]$ValueProperty,
        [Parameter(Mandatory = $true)][string]$BaseProperty,
        [AllowNull()][object]$FrequencyPerfTime
    )

    if ($null -eq $Previous -or $null -eq $Current) {
        return [pscustomobject]@{ Value = $null; Reason = 'no-baseline' }
    }
    if ($null -eq $FrequencyPerfTime) {
        return [pscustomobject]@{ Value = $null; Reason = 'missing-frequency' }
    }
    $frequency = 0.0
    try { $frequency = [double]$FrequencyPerfTime } catch { return [pscustomobject]@{ Value = $null; Reason = 'missing-frequency' } }
    if ($frequency -le 0) { return [pscustomobject]@{ Value = $null; Reason = 'missing-frequency' } }

    $valueDelta = Get-FiniteNumericDelta -Previous $Previous -Current $Current -Name $ValueProperty
    if ($null -eq $valueDelta) { return [pscustomobject]@{ Value = $null; Reason = 'missing-counter' } }
    if ($valueDelta -lt 0) { return [pscustomobject]@{ Value = $null; Reason = 'counter-reset' } }
    $baseDelta = Get-FiniteNumericDelta -Previous $Previous -Current $Current -Name $BaseProperty
    if ($null -eq $baseDelta) { return [pscustomobject]@{ Value = $null; Reason = 'missing-counter' } }
    if ($baseDelta -le 0) { return [pscustomobject]@{ Value = $null; Reason = 'no-io' } }

    $seconds = ($valueDelta / $frequency) / $baseDelta
    if ([double]::IsNaN($seconds) -or [double]::IsInfinity($seconds) -or $seconds -lt 0) {
        return [pscustomobject]@{ Value = $null; Reason = 'invalid-result' }
    }
    return [pscustomobject]@{ Value = [Math]::Round($seconds, 6); Reason = $null }
}

function Get-RateFromDelta {
    <#
      Cumulative-counter rate: (current - previous) / elapsed seconds. Returns
      $null for a missing/reset counter or invalid window, never zero.
    #>
    param(
        [AllowNull()][object]$Previous,
        [AllowNull()][object]$Current,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$ElapsedSeconds
    )

    if ($null -eq $ElapsedSeconds) { return $null }
    $elapsed = 0.0
    try { $elapsed = [double]$ElapsedSeconds } catch { return $null }
    if ($elapsed -le 0) { return $null }
    $delta = Get-FiniteNumericDelta -Previous $Previous -Current $Current -Name $Name
    if ($null -eq $delta -or $delta -lt 0) { return $null }
    $rate = $delta / $elapsed
    if ([double]::IsNaN($rate) -or [double]::IsInfinity($rate) -or $rate -lt 0) { return $null }
    return [Math]::Round($rate, 2)
}

function Get-DiskCounterDeltas {
    <#
      Pure per-disk derived metrics from two raw Win32_PerfRawData snapshots.
      Computes read/write latency, throughput and instantaneous queue depth.
      Returns null fields with a coverage reason when a counter cannot be paired
      - missing data is never reported as zero. Bounded by the number of disks
      supplied.
    #>
    param(
        [AllowNull()][object[]]$Previous,
        [AllowNull()][object[]]$Current,
        [AllowNull()][string]$TimestampUtc
    )

    $results = @()
    if ($null -eq $Current) { return $results }

    $previousByName = @{}
    foreach ($previousDisk in @($Previous)) {
        $name = Get-SafeObjectProperty -InputObject $previousDisk -Name 'Name'
        if ($null -ne $name) { $previousByName[[string]$name] = $previousDisk }
    }

    foreach ($disk in @($Current)) {
        $name = Get-SafeObjectProperty -InputObject $disk -Name 'Name'
        if ($null -eq $name) { continue }
        $name = [string]$name
        $previousDisk = $null
        if ($previousByName.ContainsKey($name)) { $previousDisk = $previousByName[$name] }

        $frequency = Get-SafeObjectProperty -InputObject $disk -Name 'Frequency_PerfTime'
        $coverage = @()

        $readLatency = Get-AverageTimerDelta -Previous $previousDisk -Current $disk -ValueProperty 'AvgDiskSecPerRead' -BaseProperty 'AvgDiskSecPerRead_Base' -FrequencyPerfTime $frequency
        $writeLatency = Get-AverageTimerDelta -Previous $previousDisk -Current $disk -ValueProperty 'AvgDiskSecPerWrite' -BaseProperty 'AvgDiskSecPerWrite_Base' -FrequencyPerfTime $frequency

        $elapsed = $null
        if ($null -ne $previousDisk) {
            $previousTimestamp = Get-SafeObjectProperty -InputObject $previousDisk -Name 'Timestamp_PerfTime'
            $currentTimestamp = Get-SafeObjectProperty -InputObject $disk -Name 'Timestamp_PerfTime'
            if ($null -ne $frequency -and $null -ne $previousTimestamp -and $null -ne $currentTimestamp) {
                try {
                    $frequencyValue = [double]$frequency
                    $tickDelta = [double]$currentTimestamp - [double]$previousTimestamp
                    if ($frequencyValue -gt 0 -and $tickDelta -gt 0) {
                        $elapsed = $tickDelta / $frequencyValue
                    }
                }
                catch { $elapsed = $null }
            }
        }

        $readBytesPerSec = $null
        $writeBytesPerSec = $null
        $totalBytesPerSec = $null
        if ($null -ne $elapsed -and $elapsed -gt 0 -and $null -ne $previousDisk) {
            $readBytesPerSec = Get-RateFromDelta -Previous $previousDisk -Current $disk -Name 'DiskReadBytesPerSec' -ElapsedSeconds $elapsed
            $writeBytesPerSec = Get-RateFromDelta -Previous $previousDisk -Current $disk -Name 'DiskWriteBytesPerSec' -ElapsedSeconds $elapsed
            $totalBytesPerSec = Get-RateFromDelta -Previous $previousDisk -Current $disk -Name 'DiskBytesPerSec' -ElapsedSeconds $elapsed
        }
        else {
            $coverage += 'no-throughput-window'
        }

        $queueRaw = Get-SafeObjectProperty -InputObject $disk -Name 'CurrentDiskQueueLength'
        $queue = $null
        if ($null -ne $queueRaw) {
            try {
                $queueValue = [double]$queueRaw
                if (-not ([double]::IsNaN($queueValue) -or [double]::IsInfinity($queueValue))) { $queue = $queueValue }
            }
            catch { $queue = $null }
        }
        if ($null -eq $queue) { $coverage += 'missing-queue' }

        foreach ($latency in @($readLatency, $writeLatency)) {
            if ($null -ne $latency -and $null -ne $latency.Reason) { $coverage += $latency.Reason }
        }

        $results += [pscustomobject]@{
            TimestampUtc = $TimestampUtc
            Name = $name
            ReadLatencySeconds = $readLatency.Value
            WriteLatencySeconds = $writeLatency.Value
            ReadBytesPerSec = $readBytesPerSec
            WriteBytesPerSec = $writeBytesPerSec
            TotalBytesPerSec = $totalBytesPerSec
            CurrentQueueLength = $queue
            CoverageReason = @($coverage | Select-Object -Unique)
        }
    }
    return $results
}

function Get-MemoryMetrics {
    <#
      Reads memory committed bytes, commit limit, and paging-file activity from
      Win32_PerfFormattedData_PerfOS_Memory. AvailableBytes is read from this
      class (not Win32_OperatingSystem which lacks CommittedBytes/CommitLimit).
      Page faults (soft+hard) are in PageFaultsPerSec; hard-fault input is
      PagesInputPersec/PageReadsPersec. Returns null when CIM classes are
      unavailable. Per-source errors are captured, never silently zero-filled.
    #>
    param()

    $result = [ordered]@{
        committedBytes = $null
        commitLimitBytes = $null
        availableBytes = $null
        pageFaultsPerSec = $null
        pageReadsPerSec = $null
        pageWritesPerSec = $null
        pagesInputPerSec = $null
        pagesOutputPerSec = $null
        _errors = @()
    }

    try {
        $mem = Get-CimInstance -ClassName 'Win32_PerfFormattedData_PerfOS_Memory' -ErrorAction Stop
        $result.committedBytes = $mem.CommittedBytes
        $result.commitLimitBytes = $mem.CommitLimit
        $result.availableBytes = $mem.AvailableBytes
        $result.pageFaultsPerSec = $mem.PageFaultsPerSec
        $result.pageReadsPerSec = $mem.PageReadsPersec
        $result.pageWritesPerSec = $mem.PageWritesPersec
        $result.pagesInputPerSec = $mem.PagesInputPersec
        $result.pagesOutputPerSec = $mem.PagesOutputPersec
    }
    catch {
        $result._errors += "PerfOS_Memory: $($_.Exception.Message)"
    }

    # If all core fields are null, treat the whole result as unavailable
    if ($null -eq $result.committedBytes -and $null -eq $result.availableBytes) {
        return $null
    }
    return $result
}

function Get-VolumeMetrics {
    <#
      Reads per-volume free space and total capacity via Win32_Volume.
      Returns null when CIM classes are unavailable.
    #>
    param()

    try {
        $volumes = @(Get-CimInstance -ClassName 'Win32_Volume' -Filter "DriveType = 3" -ErrorAction Stop)
        if ($volumes.Count -eq 0) { return $null }
        return @($volumes | ForEach-Object {
            [pscustomobject]@{
                DriveLetter = $_.DriveLetter
                Label = $_.Label
                FileSystem = $_.FileSystem
                CapacityBytes = $_.Capacity
                FreeSpaceBytes = $_.FreeSpace
                PercentFree = if ($null -ne $_.FreeSpace -and $null -ne $_.Capacity -and [double]$_.Capacity -gt 0) {
                    [Math]::Round(([double]$_.FreeSpace / [double]$_.Capacity) * 100, 2)
                } else { $null }
            }
        })
    }
    catch {
        Add-CollectionErrorText -Stage 'volume-metrics' -Message "Win32_Volume unavailable: $($_.Exception.Message)"
        return $null
    }
}

function ConvertTo-HtmlEncoded {
    <#
      HTML-encode text for safe embedding. Uses [System.Net.WebUtility]::HtmlEncode
      which is available on PS 5.1 and pwsh 7. Never produces raw <, >, &, or " in
      output. No external assets or scripts.
    #>
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Get-SampleTimestamp {
    param([AllowNull()][object]$Sample)

    if ($null -eq $Sample) { return $null }
    $value = Get-SafeObjectProperty -InputObject $Sample -Name 'TimestampUtc'
    if ($null -eq $value) { return $null }
    return [string]$value
}

function Get-FiniteNumericCount {
    <#
      Counts samples whose named property is a finite real number. This is the
      coverage denominator - array length alone would count nulls as data.
    #>
    param(
        [AllowNull()][object[]]$Samples,
        [Parameter(Mandatory = $true)][string]$ValueProperty
    )

    $count = 0
    foreach ($sample in @($Samples)) {
        $raw = Get-SafeObjectProperty -InputObject $sample -Name $ValueProperty
        if ($null -eq $raw) { continue }
        try {
            $value = [double]$raw
            if (-not ([double]::IsNaN($value) -or [double]::IsInfinity($value))) { $count++ }
        }
        catch { }
    }
    return $count
}

function Get-SustainedWindow {
    <#
      Finds the longest run of consecutive samples whose selected value meets
      the threshold ANYWHERE in the series (including mid-run followed by
      recovery). Only finite numeric readings count; a null/non-numeric reading
      breaks the run. Returns the window (count, start/end timestamp, peak) or
      $null. Pure and fixture-testable.
    #>
    param(
        [AllowNull()][object[]]$Samples,
        [string]$ValueProperty,
        [AllowNull()][scriptblock]$ValueSelector,
        [double]$Threshold,
        [int]$MinimumConsecutive = 5,
        [ValidateSet('ge', 'gt')][string]$Comparator = 'ge'
    )

    $best = $null
    $run = 0
    $runStart = $null
    $runEnd = $null
    $runPeak = $null
    $sampleList = @($Samples)
    for ($i = 0; $i -lt $sampleList.Count; $i++) {
        $sample = $sampleList[$i]
        $raw = $null
        if ($null -ne $ValueSelector) {
            try { $raw = & $ValueSelector $sample } catch { $raw = $null }
        }
        elseif (-not [string]::IsNullOrEmpty($ValueProperty)) {
            $raw = Get-SafeObjectProperty -InputObject $sample -Name $ValueProperty
        }
        $value = 0.0
        $isFinite = $false
        if ($null -ne $raw) {
            try {
                $value = [double]$raw
                $isFinite = -not ([double]::IsNaN($value) -or [double]::IsInfinity($value))
            }
            catch { $isFinite = $false }
        }
        $meets = $false
        if ($isFinite) {
            if ($Comparator -eq 'gt') { $meets = $value -gt $Threshold }
            else { $meets = $value -ge $Threshold }
        }
        if ($meets) {
            if ($run -eq 0) { $runStart = $i; $runPeak = $value }
            $run++
            $runEnd = $i
            if ($value -gt $runPeak) { $runPeak = $value }
            if ($run -ge $MinimumConsecutive -and ($null -eq $best -or $run -gt $best.Count)) {
                $best = [pscustomobject]@{
                    Count = $run
                    StartIndex = $runStart
                    EndIndex = $runEnd
                    StartTimestampUtc = Get-SampleTimestamp -Sample $sampleList[$runStart]
                    EndTimestampUtc = Get-SampleTimestamp -Sample $sampleList[$runEnd]
                    Peak = $runPeak
                }
            }
        }
        else {
            $run = 0
            $runStart = $null
            $runEnd = $null
            $runPeak = $null
        }
    }
    return $best
}

function Evaluate-Findings {
    <#
      Pure evaluation function over collected telemetry. Produces findings with
      source artifact, metric, window, measured values, rule conditions,
      uncertainty, next steps, and suggested WPR profile. Sustained evidence is
      required and the qualifying run may occur ANYWHERE in the series (a burst
      followed by recovery is found). Only finite readings count; nulls break a
      streak. Coverage warnings report missing/insufficient CPU/disk/memory
      data. Never reports unknown as healthy. No causal claims, no health score.
    #>
    param(
        [object[]]$Samples,

        [AllowNull()]
        [object[]]$DiskSeries,

        [AllowNull()]
        [object]$VolumeMetrics,

        [AllowNull()]
        [object]$MemoryMetrics,

        [AllowNull()]
        [string]$WindowStart,

        [AllowNull()]
        [string]$WindowEnd,

        [AllowNull()]
        [object]$CaptureWindow,

        [AllowNull()]
        [object]$ProcessMemoryTop,

        [AllowNull()]
        [object]$MemoryMetricsRaw
    )

    $findings = @()
    $sustainedThreshold = 5
    $sampleList = @($Samples)
    $cpuValidCount = Get-FiniteNumericCount -Samples $sampleList -ValueProperty 'AverageCpuLoadPercent'

    # ---- Evidence coverage: does the trace cover the counters? ----------------
    # Without this check the report can imply an ETL explains pressure it never
    # observed (the defect this release fixes).
    if ($null -ne $CaptureWindow) {
        $wprStart = Get-CaseJsonProperty -InputObject $CaptureWindow -Name 'wprStartUtc'
        $wprStop = Get-CaseJsonProperty -InputObject $CaptureWindow -Name 'wprStopUtc'
        $coverage = Test-CaptureWindowCoverage -CaptureWindow $CaptureWindow -WprStartUtc $wprStart -WprStopUtc $wprStop
        if ($coverage.Status -eq 'covers-window') {
            $findings += [pscustomobject]@{
                category = 'evidence-coverage'
                sourceArtifact = 'diagnostic-manifest.json'
                metric = 'captureWindow'
                windowStart = Get-CaseJsonProperty -InputObject $CaptureWindow -Name 'startedAtUtc'
                windowEnd = Get-CaseJsonProperty -InputObject $CaptureWindow -Name 'completedAtUtc'
                measuredValues = [ordered]@{
                    requestedBaselineSeconds = Get-CaseJsonProperty -InputObject $CaptureWindow -Name 'requestedBaselineSeconds'
                    actualBaselineSeconds = Get-CaseJsonProperty -InputObject $CaptureWindow -Name 'actualBaselineSeconds'
                    wprRequestedSeconds = Get-CaseJsonProperty -InputObject $CaptureWindow -Name 'wprRequestedSeconds'
                    wprActualSeconds = Get-CaseJsonProperty -InputObject $CaptureWindow -Name 'wprActualSeconds'
                }
                ruleCondition = 'The WPR trace window fully covers the counter sampling window'
                uncertainty = 'Overlap is a timing guarantee only; it does not prove the trace recorded every event the counters summarize'
                nextSteps = 'Open wpr-trace.etl in WPA and align it to the cited counter window'
                suggestedWprProfile = $null
            }
        }
        elseif ($coverage.Status -ne 'no-trace') {
            $findings += [pscustomobject]@{
                category = 'coverage'
                sourceArtifact = 'diagnostic-manifest.json'
                metric = 'traceWindowOverlap'
                windowStart = Get-CaseJsonProperty -InputObject $CaptureWindow -Name 'startedAtUtc'
                windowEnd = Get-CaseJsonProperty -InputObject $CaptureWindow -Name 'completedAtUtc'
                measuredValues = [ordered]@{
                    status = $coverage.Status
                    detail = $coverage.Detail
                    wprStartUtc = $wprStart
                    wprStopUtc = $wprStop
                }
                ruleCondition = 'The WPR trace window does not fully cover the counter sampling window'
                uncertainty = 'The trace cannot explain pressure recorded outside its own window'
                nextSteps = 'Re-run with -PerformanceMode so the trace and counters share one capture window'
                suggestedWprProfile = $null
            }
        }
    }

    # ---- Commit attribution: which process holds the commit charge -----------
    if ($null -ne $ProcessMemoryTop) {
        $topProcesses = @($ProcessMemoryTop | Where-Object { $null -ne (Get-SafeObjectProperty -InputObject $_ -Name 'PeakPrivateBytes') } |
            Sort-Object -Property PeakPrivateBytes -Descending | Select-Object -First 5)
        if ($topProcesses.Count -gt 0) {
            $commitLimit = if ($null -ne $MemoryMetricsRaw) { Get-SafeObjectProperty -InputObject $MemoryMetricsRaw -Name 'commitLimitBytes' } else { $null }
            $peakSampleCommit = $null
            foreach ($commitSample in $sampleList) {
                $value = Get-SafeObjectProperty -InputObject $commitSample -Name 'CommittedBytes'
                if ($null -ne $value -and ($null -eq $peakSampleCommit -or [int64]$value -gt [int64]$peakSampleCommit)) {
                    $peakSampleCommit = [int64]$value
                }
            }
            $topSum = ($topProcesses | Measure-Object -Property PeakPrivateBytes -Sum).Sum
            $attributedPercent = $null
            if ($null -ne $commitLimit -and [int64]$commitLimit -gt 0 -and $null -ne $topSum) {
                $attributedPercent = [Math]::Round((([double]$topSum / [double]$commitLimit) * 100), 2)
            }
            $first = $topProcesses[0]
            $findings += [pscustomobject]@{
                category = 'commit-attribution'
                sourceArtifact = 'process-memory-samples.csv'
                metric = 'PeakPrivateBytes'
                windowStart = $WindowStart
                windowEnd = $WindowEnd
                measuredValues = [ordered]@{
                    peakSystemCommittedBytes = $peakSampleCommit
                    commitLimitBytes = $commitLimit
                    topProcesses = @($topProcesses)
                    topFivePeakPrivateBytesSum = $topSum
                    topFivePercentOfCommitLimit = $attributedPercent
                }
                ruleCondition = 'Per-process private bytes (commit charge) attributed across the sampled window'
                uncertainty = 'PrivateBytes is the process commit charge; shared pages and kernel pool are attributed separately and a process may legitimately reserve more than it uses'
                nextSteps = "Start with $($first.Name): compare its PrivateBytes trend against the commit curve, then check the kernel-pool and pagefile findings for charge that is not per-process"
                suggestedWprProfile = 'GeneralProfile'
            }
        }
    }

    # ---- CPU: sustained >= 80% anywhere in the series ----
    $cpuWindow = Get-SustainedWindow -Samples $sampleList -ValueProperty 'AverageCpuLoadPercent' -Threshold 80 -MinimumConsecutive $sustainedThreshold -Comparator 'ge'
    if ($null -ne $cpuWindow) {
        $findings += [pscustomobject]@{
            category = 'cpu-pressure'
            sourceArtifact = 'performance-samples.csv'
            metric = 'AverageCpuLoadPercent'
            windowStart = $cpuWindow.StartTimestampUtc
            windowEnd = $cpuWindow.EndTimestampUtc
            measuredValues = [ordered]@{
                consecutiveSamplesAboveThreshold = $cpuWindow.Count
                peakValue = $cpuWindow.Peak
                validCpuReadings = $cpuValidCount
                totalSamples = $sampleList.Count
            }
            ruleCondition = "AverageCpuLoadPercent >= 80% for $($cpuWindow.Count) consecutive samples"
            uncertainty = 'CPU load does not identify the responsible process; correlation is not causation'
            nextSteps = 'Collect a WPR CPU trace to identify the top CPU consumer during the cited window'
            suggestedWprProfile = 'CPU'
        }
    }

    if ($cpuValidCount -eq 0) {
        $findings += [pscustomobject]@{
            category = 'coverage'
            sourceArtifact = 'performance-samples.csv'
            metric = 'noSamples'
            windowStart = $null
            windowEnd = $null
            measuredValues = [ordered]@{ validCpuReadings = 0; totalSamples = $sampleList.Count }
            ruleCondition = 'No finite CPU readings collected'
            uncertainty = 'Insufficient evidence - cannot assess CPU pressure'
            nextSteps = 'Check for CIM/WMI errors and re-run collection'
            suggestedWprProfile = $null
        }
    }
    elseif ($cpuValidCount -lt 3) {
        $findings += [pscustomobject]@{
            category = 'coverage'
            sourceArtifact = 'performance-samples.csv'
            metric = 'insufficientSamples'
            windowStart = $null
            windowEnd = $null
            measuredValues = [ordered]@{ validCpuReadings = $cpuValidCount; totalSamples = $sampleList.Count }
            ruleCondition = 'Fewer than 3 finite CPU readings collected'
            uncertainty = 'Findings based on insufficient data are unreliable'
            nextSteps = 'Re-run collection with a longer duration or check for CIM errors'
            suggestedWprProfile = $null
        }
    }

    # ---- Memory: sustained commit pressure (per-sample series) ----
    $commitWindow = Get-SustainedWindow -Samples $sampleList -ValueSelector {
        param($sample)
        $committed = Get-SafeObjectProperty -InputObject $sample -Name 'CommittedBytes'
        $limit = Get-SafeObjectProperty -InputObject $sample -Name 'CommitLimitBytes'
        if ($null -eq $committed -or $null -eq $limit) { return $null }
        try {
            $committedValue = [double]$committed
            $limitValue = [double]$limit
            if ($limitValue -le 0) { return $null }
            return ($committedValue / $limitValue) * 100
        }
        catch { return $null }
    } -Threshold 90 -MinimumConsecutive $sustainedThreshold -Comparator 'ge'

    if ($null -ne $commitWindow) {
        $peakCommitted = Get-SafeObjectProperty -InputObject $sampleList[$commitWindow.EndIndex] -Name 'CommittedBytes'
        $peakLimit = Get-SafeObjectProperty -InputObject $sampleList[$commitWindow.EndIndex] -Name 'CommitLimitBytes'
        $findings += [pscustomobject]@{
            category = 'memory-pressure'
            sourceArtifact = 'performance-samples.csv'
            metric = 'CommittedBytes'
            windowStart = $commitWindow.StartTimestampUtc
            windowEnd = $commitWindow.EndTimestampUtc
            measuredValues = [ordered]@{
                consecutiveSamplesAtOrAbove90Percent = $commitWindow.Count
                peakCommitPercent = $commitWindow.Peak
                committedBytesAtPeak = $peakCommitted
                commitLimitBytesAtPeak = $peakLimit
            }
            ruleCondition = "Committed bytes at or above 90% of the commit limit for $($commitWindow.Count) consecutive samples"
            uncertainty = 'High commit charge does not alone cause disk thrashing; paging depends on available physical memory and working set'
            nextSteps = 'Check the paging indicator finding; if elevated, collect a WPR GeneralProfile trace covering the cited window'
            suggestedWprProfile = 'GeneralProfile'
        }
    }

    # ---- Memory: sustained paging input (pages read to resolve hard faults) ----
    $pagingWindow = Get-SustainedWindow -Samples $sampleList -ValueProperty 'PagesInputPerSec' -Threshold 100 -MinimumConsecutive $sustainedThreshold -Comparator 'gt'
    if ($null -ne $pagingWindow) {
        $findings += [pscustomobject]@{
            category = 'memory-paging'
            sourceArtifact = 'performance-samples.csv'
            metric = 'PagesInputPerSec'
            windowStart = $pagingWindow.StartTimestampUtc
            windowEnd = $pagingWindow.EndTimestampUtc
            measuredValues = [ordered]@{
                consecutiveSamplesAbove100 = $pagingWindow.Count
                peakPagesInputPerSec = $pagingWindow.Peak
            }
            ruleCondition = "PagesInputPersec > 100 for $($pagingWindow.Count) consecutive samples"
            uncertainty = 'PagesInputPersec counts pages read to resolve hard page faults (a paging volume indicator, not an exact hard-fault count) and does not identify the responsible process'
            nextSteps = 'Collect a WPR GeneralProfile trace covering the cited window to identify the process with the largest working-set change'
            suggestedWprProfile = 'GeneralProfile'
        }
    }

    $pagingValidCount = Get-FiniteNumericCount -Samples $sampleList -ValueProperty 'PagesInputPerSec'
    if ($pagingValidCount -eq 0) {
        $findings += [pscustomobject]@{
            category = 'coverage'
            sourceArtifact = 'performance-samples.csv'
            metric = 'pagesInputPerSec'
            windowStart = $null
            windowEnd = $null
            measuredValues = [ordered]@{
                pagesInputPerSec = $null
                pageFaultsPerSec = if ($MemoryMetrics) { $MemoryMetrics.pageFaultsPerSec } else { $null }
            }
            ruleCondition = 'PagesInputPersec unavailable; cannot determine the hard page fault paging rate'
            uncertainty = 'PageFaultsPerSec includes soft faults; the hard-fault paging rate is unknown'
            nextSteps = 'Verify elevation or re-run with administrator privileges for complete memory counters'
            suggestedWprProfile = $null
        }
    }

    # ---- Disk: sustained queue depth / latency per disk, from the in-window series ----
    $diskRows = @()
    if ($null -ne $DiskSeries) { $diskRows = @($DiskSeries) }
    if ($diskRows.Count -gt 0) {
        $diskNames = @($diskRows | ForEach-Object { Get-SafeObjectProperty -InputObject $_ -Name 'Name' } | Where-Object { $null -ne $_ -and "$_" -ne '' } | Select-Object -Unique)
        foreach ($diskName in $diskNames) {
            $rows = @($diskRows | Where-Object { (Get-SafeObjectProperty -InputObject $_ -Name 'Name') -eq $diskName })
            $queueWindow = Get-SustainedWindow -Samples $rows -ValueProperty 'CurrentQueueLength' -Threshold 2 -MinimumConsecutive $sustainedThreshold -Comparator 'ge'
            if ($null -ne $queueWindow) {
                $findings += [pscustomobject]@{
                    category = 'disk-pressure'
                    sourceArtifact = 'disk-samples.json'
                    metric = 'CurrentQueueLength'
                    windowStart = $queueWindow.StartTimestampUtc
                    windowEnd = $queueWindow.EndTimestampUtc
                    measuredValues = [ordered]@{
                        disk = $diskName
                        consecutiveSamplesAtOrAbove2 = $queueWindow.Count
                        peakQueueLength = $queueWindow.Peak
                    }
                    ruleCondition = "CurrentDiskQueueLength >= 2 on $diskName for $($queueWindow.Count) consecutive intervals"
                    uncertainty = 'Disk queue depth indicates I/O contention; process attribution requires a disk I/O trace'
                    nextSteps = 'Collect a WPR DiskIO trace covering the cited window to identify the process generating I/O'
                    suggestedWprProfile = 'DiskIO'
                }
            }
            $latencyWindow = Get-SustainedWindow -Samples $rows -ValueProperty 'ReadLatencySeconds' -Threshold 0.02 -MinimumConsecutive $sustainedThreshold -Comparator 'ge'
            if ($null -ne $latencyWindow) {
                $findings += [pscustomobject]@{
                    category = 'disk-latency'
                    sourceArtifact = 'disk-samples.json'
                    metric = 'ReadLatencySeconds'
                    windowStart = $latencyWindow.StartTimestampUtc
                    windowEnd = $latencyWindow.EndTimestampUtc
                    measuredValues = [ordered]@{
                        disk = $diskName
                        consecutiveSamplesAtOrAbove20ms = $latencyWindow.Count
                        peakReadLatencySeconds = $latencyWindow.Peak
                    }
                    ruleCondition = "Read latency >= 20 ms on $diskName for $($latencyWindow.Count) consecutive intervals"
                    uncertainty = 'Latency is derived from paired raw disk counters; it does not identify the requesting process'
                    nextSteps = 'Collect a WPR DiskIO trace covering the cited window'
                    suggestedWprProfile = 'DiskIO'
                }
            }
        }
    }
    else {
        $findings += [pscustomobject]@{
            category = 'coverage'
            sourceArtifact = 'disk-samples.json'
            metric = 'diskSeriesUnavailable'
            windowStart = $null
            windowEnd = $null
            measuredValues = [ordered]@{ intervalCount = 0 }
            ruleCondition = 'No paired raw disk counter intervals were collected'
            uncertainty = 'Cannot assess sustained disk contention'
            nextSteps = 'Run as Administrator to enable disk performance counters and re-run collection'
            suggestedWprProfile = $null
        }
    }

    # ---- Volume: low free space (state captured inside the window) ----
    if ($null -ne $VolumeMetrics) {
        foreach ($volume in @($VolumeMetrics)) {
            $percentFree = Get-SafeObjectProperty -InputObject $volume -Name 'PercentFree'
            if ($null -eq $percentFree) {
                $findings += [pscustomobject]@{
                    category = 'coverage'
                    sourceArtifact = 'volume-metrics.json'
                    metric = 'volumeFreeSpaceUnavailable'
                    windowStart = $null
                    windowEnd = $null
                    measuredValues = [ordered]@{ driveLetter = Get-SafeObjectProperty -InputObject $volume -Name 'DriveLetter' }
                    ruleCondition = 'Free space or capacity unavailable for this volume'
                    uncertainty = 'Cannot assess free space on this volume'
                    nextSteps = 'Verify CIM access or run as Administrator'
                    suggestedWprProfile = $null
                }
                continue
            }
            try { $percentValue = [double]$percentFree } catch { continue }
            if ($percentValue -lt 10) {
                $findings += [pscustomobject]@{
                    category = 'disk-space'
                    sourceArtifact = 'volume-metrics.json'
                    metric = 'PercentFree'
                    windowStart = $WindowStart
                    windowEnd = $WindowEnd
                    measuredValues = [ordered]@{
                        driveLetter = Get-SafeObjectProperty -InputObject $volume -Name 'DriveLetter'
                        percentFree = $percentValue
                        freeSpaceBytes = Get-SafeObjectProperty -InputObject $volume -Name 'FreeSpaceBytes'
                        capacityBytes = Get-SafeObjectProperty -InputObject $volume -Name 'CapacityBytes'
                    }
                    ruleCondition = "Free space below 10% on $(Get-SafeObjectProperty -InputObject $volume -Name 'DriveLetter')"
                    uncertainty = 'Low free space can degrade performance but does not alone cause slowness'
                    nextSteps = 'Review large files and consider volume cleanup'
                    suggestedWprProfile = $null
                }
            }
        }
    }
    else {
        $findings += [pscustomobject]@{
            category = 'coverage'
            sourceArtifact = 'volume-metrics.json'
            metric = 'volumeMetricsUnavailable'
            windowStart = $null
            windowEnd = $null
            measuredValues = [ordered]@{ available = $false }
            ruleCondition = 'Volume metrics unavailable'
            uncertainty = 'Cannot assess disk space'
            nextSteps = 'Verify CIM access or run as Administrator'
            suggestedWprProfile = $null
        }
    }

    if ($null -eq $MemoryMetrics) {
        $findings += [pscustomobject]@{
            category = 'coverage'
            sourceArtifact = 'performance-samples.csv'
            metric = 'memoryMetricsUnavailable'
            windowStart = $null
            windowEnd = $null
            measuredValues = [ordered]@{ available = $false }
            ruleCondition = 'Memory performance counters unavailable'
            uncertainty = 'Cannot assess memory pressure or paging'
            nextSteps = 'Run as Administrator to enable memory performance counters'
            suggestedWprProfile = $null
        }
    }

    return $findings
}

function ConvertTo-FindingsHtml {
    <#
      Generate a standalone offline report.html from findings and manifest data.
      No external assets/scripts, no traversal links, all text HTML-encoded.
      Uses [System.Net.WebUtility]::HtmlEncode for PS 5.1 compatibility.
    #>
    param(
        [object[]]$Findings,

        [AllowNull()]
        [object]$Manifest,

        [AllowNull()]
        [string]$SymptomContext
    )

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en">')
    [void]$sb.AppendLine('<head>')
    [void]$sb.AppendLine('<meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
    [void]$sb.AppendLine('<title>Windows Performance Diagnostics Report</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine('body{font-family:system-ui,sans-serif;margin:2em;color:#222;line-height:1.5}')
    [void]$sb.AppendLine('h1,h2,h3{margin-top:1.2em}')
    [void]$sb.AppendLine('table{border-collapse:collapse;width:100%;margin:1em 0}')
    [void]$sb.AppendLine('th,td{border:1px solid #ccc;padding:.5em;text-align:left}')
    [void]$sb.AppendLine('th{background:#f5f5f5}')
    [void]$sb.AppendLine('.finding{border:1px solid #ddd;padding:1em;margin:1em 0;border-radius:4px}')
    [void]$sb.AppendLine('.warning{background:#fff3cd;border-color:#ffc107}')
    [void]$sb.AppendLine('.coverage{background:#e2e3e5;border-color:#6c757d}')
    [void]$sb.AppendLine('.pressure{background:#f8d7da;border-color:#dc3545}')
    [void]$sb.AppendLine('.info{background:#d1ecf1;border-color:#17a2b8}')
    [void]$sb.AppendLine('a{color:#0066cc}')
    [void]$sb.AppendLine('.no-external{font-size:.85em;color:#666}')
    [void]$sb.AppendLine('</style>')
    [void]$sb.AppendLine('</head>')
    [void]$sb.AppendLine('<body>')

    [void]$sb.AppendLine('<h1>Windows Performance Diagnostics Report</h1>')

    if ($Manifest) {
        [void]$sb.AppendLine('<h2>Collection Summary</h2>')
        [void]$sb.AppendLine('<table>')
        [void]$sb.AppendLine("<tr><th>Tool Version</th><td>$(ConvertTo-HtmlEncoded (Get-CaseJsonProperty -InputObject $Manifest -Name 'toolVersion'))</td></tr>")
        [void]$sb.AppendLine("<tr><th>Schema Version</th><td>$(ConvertTo-HtmlEncoded (Get-CaseJsonProperty -InputObject $Manifest -Name 'schemaVersion'))</td></tr>")
        [void]$sb.AppendLine("<tr><th>Collection Window</th><td>$(ConvertTo-HtmlEncoded (Get-CaseJsonProperty -InputObject $Manifest -Name 'startedAtUtc')) to $(ConvertTo-HtmlEncoded (Get-CaseJsonProperty -InputObject $Manifest -Name 'completedAtUtc'))</td></tr>")
        $scopeValue = Get-CaseJsonProperty -InputObject $Manifest -Name 'scope'
        if ($null -ne $scopeValue) {
            $durationValue = Get-CaseJsonProperty -InputObject $scopeValue -Name 'durationSeconds'
            if ($null -ne $durationValue) {
                [void]$sb.AppendLine("<tr><th>Duration</th><td>$(ConvertTo-HtmlEncoded $durationValue) seconds</td></tr>")
            }
        }
        # Capture-window honesty: what was requested vs what actually elapsed,
        # for the counters AND the trace. A report that says "30 seconds" while
        # the run took four minutes is misleading.
        $captureWindowValue = Get-CaseJsonProperty -InputObject $Manifest -Name 'captureWindow'
        if ($null -ne $captureWindowValue) {
            $actualBaseline = Get-CaseJsonProperty -InputObject $captureWindowValue -Name 'actualBaselineSeconds'
            $requestedBaseline = Get-CaseJsonProperty -InputObject $captureWindowValue -Name 'requestedBaselineSeconds'
            $wprRequested = Get-CaseJsonProperty -InputObject $captureWindowValue -Name 'wprRequestedSeconds'
            $wprActual = Get-CaseJsonProperty -InputObject $captureWindowValue -Name 'wprActualSeconds'
            $windowStart = Get-CaseJsonProperty -InputObject $captureWindowValue -Name 'startedAtUtc'
            $windowEnd = Get-CaseJsonProperty -InputObject $captureWindowValue -Name 'completedAtUtc'
            [void]$sb.AppendLine("<tr><th>Capture Window</th><td>$(ConvertTo-HtmlEncoded $windowStart) to $(ConvertTo-HtmlEncoded $windowEnd)</td></tr>")
            [void]$sb.AppendLine("<tr><th>Baseline Sampling</th><td>$(ConvertTo-HtmlEncoded $requestedBaseline) s requested; $(ConvertTo-HtmlEncoded $actualBaseline) s actual</td></tr>")
            if ($null -ne $wprRequested -or $null -ne $wprActual) {
                [void]$sb.AppendLine("<tr><th>WPR Trace</th><td>$(ConvertTo-HtmlEncoded $wprRequested) s requested; $(ConvertTo-HtmlEncoded $wprActual) s actual (concurrent with sampling)</td></tr>")
            }
            $concurrentStages = Get-CaseJsonProperty -InputObject $captureWindowValue -Name 'concurrentStages'
            if ($null -ne $concurrentStages) {
                $stageText = if ($concurrentStages -is [array]) { $concurrentStages -join ', ' } else { [string]$concurrentStages }
                [void]$sb.AppendLine("<tr><th>Concurrent Stages</th><td>$(ConvertTo-HtmlEncoded $stageText)</td></tr>")
            }
        }
        $incidentValue = Get-CaseJsonProperty -InputObject $Manifest -Name 'incident'
        if ($null -ne $incidentValue) {
            $markerObserved = Get-CaseJsonProperty -InputObject $incidentValue -Name 'markerObservedAtUtc'
            if ($null -ne $markerObserved) {
                $markerSourceText = Get-CaseJsonProperty -InputObject $incidentValue -Name 'markerSource'
                $preSeconds = Get-CaseJsonProperty -InputObject $incidentValue -Name 'preSeconds'
                $postSeconds = Get-CaseJsonProperty -InputObject $incidentValue -Name 'postSeconds'
                $keptCount = Get-CaseJsonProperty -InputObject $incidentValue -Name 'retainedSampleCount'
                $droppedCount = Get-CaseJsonProperty -InputObject $incidentValue -Name 'droppedSampleCount'
                [void]$sb.AppendLine("<tr><th>Incident Marker</th><td>$(ConvertTo-HtmlEncoded $markerObserved) (source: $(ConvertTo-HtmlEncoded $markerSourceText))</td></tr>")
                [void]$sb.AppendLine("<tr><th>Retention</th><td>$(ConvertTo-HtmlEncoded $preSeconds) s before / $(ConvertTo-HtmlEncoded $postSeconds) s after; $(ConvertTo-HtmlEncoded $keptCount) samples kept, $(ConvertTo-HtmlEncoded $droppedCount) dropped</td></tr>")
            }
        }
        $pageFileValue = Get-CaseJsonProperty -InputObject $Manifest -Name 'pageFile'
        if ($null -ne $pageFileValue -and @($pageFileValue).Count -gt 0) {
            foreach ($pageFile in @($pageFileValue)) {
                $pageFileName = Get-CaseJsonProperty -InputObject $pageFile -Name 'Name'
                $allocated = Get-CaseJsonProperty -InputObject $pageFile -Name 'AllocatedBaseSizeMB'
                $current = Get-CaseJsonProperty -InputObject $pageFile -Name 'CurrentUsageMB'
                $peak = Get-CaseJsonProperty -InputObject $pageFile -Name 'PeakUsageMB'
                [void]$sb.AppendLine("<tr><th>Pagefile</th><td>$(ConvertTo-HtmlEncoded $pageFileName): $(ConvertTo-HtmlEncoded $allocated) MiB allocated, $(ConvertTo-HtmlEncoded $current) MiB current, $(ConvertTo-HtmlEncoded $peak) MiB peak</td></tr>")
            }
        }
        $storageMappingValue = Get-CaseJsonProperty -InputObject $Manifest -Name 'storageMapping'
        if ($null -ne $storageMappingValue) {
            $driveRows = @(Get-CaseJsonProperty -InputObject $storageMappingValue -Name 'drives')
            if ($driveRows.Count -gt 0) {
                $parts = @()
                foreach ($drive in $driveRows) {
                    $letter = Get-CaseJsonProperty -InputObject $drive -Name 'DriveLetter'
                    $model = Get-CaseJsonProperty -InputObject $drive -Name 'PhysicalDiskModel'
                    $percentFree = Get-CaseJsonProperty -InputObject $drive -Name 'PercentFree'
                    $hostsPageFile = Get-CaseJsonProperty -InputObject $drive -Name 'HostsPageFile'
                    $pageFileLabel = if ($hostsPageFile -eq $true) { 'pagefile host' } else { 'no pagefile' }
                    $parts += ("{0} on {1} ({2}% free, {3})" -f $letter, $model, $percentFree, $pageFileLabel)
                }
                [void]$sb.AppendLine("<tr><th>Volumes</th><td>$(ConvertTo-HtmlEncoded ($parts -join '; '))</td></tr>")
            }
            $storageNote = Get-CaseJsonProperty -InputObject $storageMappingValue -Name 'note'
            if ($null -ne $storageNote) {
                [void]$sb.AppendLine("<tr><th>Volume Relevance</th><td>$(ConvertTo-HtmlEncoded $storageNote)</td></tr>")
            }
        }
        [void]$sb.AppendLine('</table>')
    }

    if ($SymptomContext) {
        [void]$sb.AppendLine('<h2>Reported Symptom</h2>')
        [void]$sb.AppendLine("<p>$(ConvertTo-HtmlEncoded $SymptomContext)</p>")
    }
    $manifestSymptom = if ($Manifest) { Get-CaseJsonProperty -InputObject $Manifest -Name 'symptom' } else { $null }
    if ($null -ne $manifestSymptom) {
        $presetValue = Get-CaseJsonProperty -InputObject $manifestSymptom -Name 'preset'
        if ($null -ne $presetValue -and "$presetValue" -ne '') {
            [void]$sb.AppendLine("<p>Collection preset: $(ConvertTo-HtmlEncoded $presetValue)</p>")
        }
    }

    # Findings are bucketed for the report AND every bucket is rendered. A
    # category that matches no bucket would silently vanish from report.html
    # while still sitting in findings.json - the Windows live gate catches that,
    # and the local suite asserts it directly. Attribution ('commit-*') and any
    # future category share the supporting-evidence section, so a new category
    # can never be dropped just because the report does not know it yet.
    $pressureFindings = @($Findings | Where-Object { $_.category -match 'pressure|paging|disk' })
    $coverageFindings = @($Findings | Where-Object { $_.category -eq 'coverage' })
    $evidenceFindings = @($Findings | Where-Object { $_.category -eq 'evidence-coverage' })
    $otherFindings = @($Findings | Where-Object {
            $_.category -notmatch 'pressure|paging|disk|coverage'
        })

    if ($pressureFindings.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Observed Pressure</h2>')
        [void]$sb.AppendLine('<p class="no-external">These findings describe measured system pressure. Correlation is not causation.</p>')
        foreach ($finding in $pressureFindings) {
            $cssClass = 'finding pressure'
            [void]$sb.AppendLine("<div class='$cssClass'>")
            [void]$sb.AppendLine("<h3>$(ConvertTo-HtmlEncoded $finding.category)</h3>")
            [void]$sb.AppendLine("<table>")
            [void]$sb.AppendLine("<tr><th>Source</th><td>$(ConvertTo-HtmlEncoded $finding.sourceArtifact)</td></tr>")
            [void]$sb.AppendLine("<tr><th>Metric</th><td>$(ConvertTo-HtmlEncoded $finding.metric)</td></tr>")
            if ($finding.windowStart) {
                [void]$sb.AppendLine("<tr><th>Window</th><td>$(ConvertTo-HtmlEncoded $finding.windowStart) to $(ConvertTo-HtmlEncoded $finding.windowEnd)</td></tr>")
            }
            [void]$sb.AppendLine("<tr><th>Rule</th><td>$(ConvertTo-HtmlEncoded $finding.ruleCondition)</td></tr>")
            # The measured numbers are the evidence; a finding that names a rule
            # without the values behind it cannot be checked by the reader.
            foreach ($measuredName in @($finding.measuredValues.PSObject.Properties.Name)) {
                [void]$sb.AppendLine("<tr><th>$(ConvertTo-HtmlEncoded $measuredName)</th><td>$(ConvertTo-HtmlEncoded ($finding.measuredValues.$measuredName))</td></tr>")
            }
            [void]$sb.AppendLine("<tr><th>Uncertainty</th><td>$(ConvertTo-HtmlEncoded $finding.uncertainty)</td></tr>")
            [void]$sb.AppendLine("<tr><th>Next Steps</th><td>$(ConvertTo-HtmlEncoded $finding.nextSteps)</td></tr>")
            if ($finding.suggestedWprProfile) {
                [void]$sb.AppendLine("<tr><th>Suggested WPR Profile</th><td>$(ConvertTo-HtmlEncoded $finding.suggestedWprProfile)</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
            [void]$sb.AppendLine('</div>')
        }
    }

    if ($coverageFindings.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Coverage Warnings</h2>')
        [void]$sb.AppendLine('<p class="no-external">The following data sources were unavailable or had insufficient samples. Unknown does not mean healthy.</p>')
        foreach ($finding in $coverageFindings) {
            $cssClass = 'finding coverage'
            [void]$sb.AppendLine("<div class='$cssClass'>")
            [void]$sb.AppendLine("<h3>$(ConvertTo-HtmlEncoded $finding.metric)</h3>")
            [void]$sb.AppendLine("<table>")
            [void]$sb.AppendLine("<tr><th>Source</th><td>$(ConvertTo-HtmlEncoded $finding.sourceArtifact)</td></tr>")
            [void]$sb.AppendLine("<tr><th>Condition</th><td>$(ConvertTo-HtmlEncoded $finding.ruleCondition)</td></tr>")
            [void]$sb.AppendLine("<tr><th>Uncertainty</th><td>$(ConvertTo-HtmlEncoded $finding.uncertainty)</td></tr>")
            [void]$sb.AppendLine("<tr><th>Next Steps</th><td>$(ConvertTo-HtmlEncoded $finding.nextSteps)</td></tr>")
            [void]$sb.AppendLine('</table>')
            [void]$sb.AppendLine('</div>')
        }
    }

    if ($evidenceFindings.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Evidence Coverage</h2>')
        [void]$sb.AppendLine('<p class="no-external">These findings describe how well the captured evidence covers the window it is supposed to explain.</p>')
        foreach ($finding in $evidenceFindings) {
            [void]$sb.AppendLine("<div class='finding coverage'>")
            [void]$sb.AppendLine("<h3>$(ConvertTo-HtmlEncoded $finding.metric)</h3>")
            [void]$sb.AppendLine('<table>')
            [void]$sb.AppendLine("<tr><th>Source</th><td>$(ConvertTo-HtmlEncoded $finding.sourceArtifact)</td></tr>")
            [void]$sb.AppendLine("<tr><th>Condition</th><td>$(ConvertTo-HtmlEncoded $finding.ruleCondition)</td></tr>")
            foreach ($measuredName in @($finding.measuredValues.PSObject.Properties.Name)) {
                [void]$sb.AppendLine("<tr><th>$(ConvertTo-HtmlEncoded $measuredName)</th><td>$(ConvertTo-HtmlEncoded ($finding.measuredValues.$measuredName))</td></tr>")
            }
            [void]$sb.AppendLine("<tr><th>Uncertainty</th><td>$(ConvertTo-HtmlEncoded $finding.uncertainty)</td></tr>")
            [void]$sb.AppendLine("<tr><th>Next Steps</th><td>$(ConvertTo-HtmlEncoded $finding.nextSteps)</td></tr>")
            [void]$sb.AppendLine('</table>')
            [void]$sb.AppendLine('</div>')
        }
    }

    if ($otherFindings.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Attribution And Supporting Evidence</h2>')
        [void]$sb.AppendLine('<p class="no-external">Attribution is not proof of causation: it says where a resource went, not why the machine slowed down.</p>')
        foreach ($finding in $otherFindings) {
            [void]$sb.AppendLine("<div class='finding pressure'>")
            [void]$sb.AppendLine("<h3>$(ConvertTo-HtmlEncoded $finding.category)</h3>")
            [void]$sb.AppendLine('<table>')
            [void]$sb.AppendLine("<tr><th>Source</th><td>$(ConvertTo-HtmlEncoded $finding.sourceArtifact)</td></tr>")
            [void]$sb.AppendLine("<tr><th>Metric</th><td>$(ConvertTo-HtmlEncoded $finding.metric)</td></tr>")
            if ($finding.windowStart) {
                [void]$sb.AppendLine("<tr><th>Window</th><td>$(ConvertTo-HtmlEncoded $finding.windowStart) to $(ConvertTo-HtmlEncoded $finding.windowEnd)</td></tr>")
            }
            [void]$sb.AppendLine("<tr><th>Rule</th><td>$(ConvertTo-HtmlEncoded $finding.ruleCondition)</td></tr>")
            foreach ($measuredName in @($finding.measuredValues.PSObject.Properties.Name)) {
                [void]$sb.AppendLine("<tr><th>$(ConvertTo-HtmlEncoded $measuredName)</th><td>$(ConvertTo-HtmlEncoded ($finding.measuredValues.$measuredName))</td></tr>")
            }
            [void]$sb.AppendLine("<tr><th>Uncertainty</th><td>$(ConvertTo-HtmlEncoded $finding.uncertainty)</td></tr>")
            [void]$sb.AppendLine("<tr><th>Next Steps</th><td>$(ConvertTo-HtmlEncoded $finding.nextSteps)</td></tr>")
            [void]$sb.AppendLine('</table>')
            [void]$sb.AppendLine('</div>')
        }
    }

    if ($pressureFindings.Count -eq 0) {
        # Every source was usable and no sustained rule threshold was breached.
        # That is a completed measurement with a clear result, not missing
        # evidence - 'Insufficient Evidence' is reserved for the coverage
        # section above, so an operator can tell 'nothing sustained' apart from
        # 'we could not measure this'.
        [void]$sb.AppendLine('<div class="finding info">')
        [void]$sb.AppendLine('<h3>No Sustained Pressure Detected</h3>')
        [void]$sb.AppendLine('<p>The collected window was measured and no pressure rule was breached for a sustained period. This does not prove the system is healthy - a short or intermittent slowdown can fall outside the sampled window. did not trigger any pressure rules. Consider re-running with a longer duration or different WPR profile.</p>')
        [void]$sb.AppendLine('</div>')
    }

    # Artifacts list. Every interpolated field is HTML-encoded, including
    # SizeBytes (a remote manifest is not trusted to constrain it). Links are
    # fixed relative names that have already been validated by the caller.
    $manifestArtifacts = if ($Manifest) { Get-CaseJsonProperty -InputObject $Manifest -Name 'artifacts' } else { $null }
    if ($null -ne $manifestArtifacts -and @($manifestArtifacts).Count -gt 0) {
        [void]$sb.AppendLine('<h2>Collected Artifacts</h2>')
        [void]$sb.AppendLine('<p class="no-external">Links are relative to this report. report.html is hashed in diagnostic-manifest.json but is omitted from this index because a report cannot contain its own hash; diagnostic-manifest.json is the manifest, not an artifact.</p>')
        [void]$sb.AppendLine('<table>')
        [void]$sb.AppendLine('<tr><th>Name</th><th>Size (bytes)</th><th>SHA-256</th></tr>')
        foreach ($artifact in @($manifestArtifacts)) {
            $nameValue = [string]$artifact.Name
            $safeName = ConvertTo-HtmlEncoded $nameValue
            $safeSize = ConvertTo-HtmlEncoded ([string]$artifact.SizeBytes)
            $safeHash = ConvertTo-HtmlEncoded ([string]$artifact.Sha256)
            $linkValue = ConvertTo-HtmlEncoded ($nameValue.Replace('\', '/'))
            [void]$sb.AppendLine("<tr><td><a href=`"$linkValue`">$safeName</a></td><td>$safeSize</td><td><code>$safeHash</code></td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    }

    [void]$sb.AppendLine('<footer class="no-external">Generated by Windows Performance Diagnostics Toolkit. No external assets or scripts.</footer>')
    [void]$sb.AppendLine('</body>')
    [void]$sb.AppendLine('</html>')

    return $sb.ToString()
}

function Write-CollectionOutputs {
    <#
      Shared Collect tail (local and fixture-testable): generate findings.json,
      then build the manifest artifact index, then generate report.html against
      that index, then recompute the index so report.html is hashed too, then
      write the manifest. The report is deliberately generated before its own
      hash exists (a file cannot contain its own SHA-256); report.html is still
      registered in the final manifest and therefore in the case package and
      Verify. Returns the updated manifest object.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$OutputDirectory,

        [Parameter(Mandatory = $true)][object]$CollectionManifest,

        [Parameter(Mandatory = $true)][System.Collections.ArrayList]$CollectedArtifacts,

        [object[]]$Samples = @(),

        [AllowNull()][object[]]$DiskSeries,

        [AllowNull()][object]$VolumeMetrics,

        [AllowNull()][object]$MemoryMetrics,

        [AllowNull()][string]$SymptomContext,

        [AllowNull()][object]$CaptureWindow,

        [AllowNull()][object]$ProcessMemoryTop
    )

    $windowStart = Get-CaseJsonProperty -InputObject $CollectionManifest -Name 'startedAtUtc'
    $windowEnd = Get-CaseJsonProperty -InputObject $CollectionManifest -Name 'completedAtUtc'

    # Disk interval series (raw paired counters) and volume state are evidence:
    # write and register them here so the shared tail - not the Windows-only
    # loop - owns artifact registration and the fixture test covers it.
    try {
        $diskSeriesOutput = @()
        if ($null -ne $DiskSeries) { $diskSeriesOutput = @($DiskSeries) }
        Write-JsonFile -InputObject $diskSeriesOutput -Path (Join-Path -Path $OutputDirectory -ChildPath 'disk-samples.json')
        if (-not $CollectedArtifacts.Contains('disk-samples.json')) { [void]$CollectedArtifacts.Add('disk-samples.json') }
    }
    catch {
        Add-CollectionError -Stage 'disk-series-export' -ErrorRecord $_
    }

    try {
        # Always emit the artifact (empty array when unavailable) so coverage
        # findings never cite a source artifact that does not exist.
        $volumeOutput = @()
        if ($null -ne $VolumeMetrics) { $volumeOutput = @($VolumeMetrics) }
        Write-JsonFile -InputObject $volumeOutput -Path (Join-Path -Path $OutputDirectory -ChildPath 'volume-metrics.json')
        if (-not $CollectedArtifacts.Contains('volume-metrics.json')) { [void]$CollectedArtifacts.Add('volume-metrics.json') }
    }
    catch {
        Add-CollectionError -Stage 'volume-metrics-export' -ErrorRecord $_
    }

    $findingsList = @()
    try {
        $findingsList = @(Evaluate-Findings -Samples $Samples -DiskSeries $DiskSeries -VolumeMetrics $VolumeMetrics -MemoryMetrics $MemoryMetrics -WindowStart $windowStart -WindowEnd $windowEnd -CaptureWindow $CaptureWindow -ProcessMemoryTop $ProcessMemoryTop -MemoryMetricsRaw $MemoryMetrics)
        Write-JsonFile -InputObject $findingsList -Path (Join-Path -Path $OutputDirectory -ChildPath 'findings.json')
        if (-not $CollectedArtifacts.Contains('findings.json')) { [void]$CollectedArtifacts.Add('findings.json') }
    }
    catch {
        Add-CollectionError -Stage 'findings-generation' -ErrorRecord $_
    }

    # Index BEFORE report generation: excludes report.html (self-hash impossible).
    $CollectionManifest.artifacts = Get-ArtifactMetadata -Directory $OutputDirectory -Names @($CollectedArtifacts)

    try {
        $reportHtml = ConvertTo-FindingsHtml -Findings $findingsList -Manifest $CollectionManifest -SymptomContext $SymptomContext
        [System.IO.File]::WriteAllText((Join-Path -Path $OutputDirectory -ChildPath 'report.html'), $reportHtml, (New-Object System.Text.UTF8Encoding($false)))
        if (-not $CollectedArtifacts.Contains('report.html')) { [void]$CollectedArtifacts.Add('report.html') }
    }
    catch {
        Add-CollectionError -Stage 'report-generation' -ErrorRecord $_
    }

    # Final index includes report.html so Verify/package/remote pull cover it.
    $CollectionManifest.artifacts = Get-ArtifactMetadata -Directory $OutputDirectory -Names @($CollectedArtifacts)

    Write-JsonFile -InputObject $CollectionManifest -Path (Join-Path -Path $OutputDirectory -ChildPath 'diagnostic-manifest.json')
    return $CollectionManifest
}

try {
    $resolvedOutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
}
catch {
    throw "OutputDirectory '$OutputDirectory' is not a valid local path: $($_.Exception.Message)"
}

$planManifest = [ordered]@{
    schemaVersion = if ($SymptomContext) { '1.1' } else { '1.0' }
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

if ($PerformanceMode) {
    $planManifest.plannedActions += 'collect-incident-performance-capture-after-explicit-consent'
    $planManifest.performanceMode = [ordered]@{
        concurrentCaptureWindow = $true
        baselineSeconds = $DurationSeconds
        sampleIntervalSeconds = $SampleIntervalSeconds
        markerMode = [bool]$MarkerMode
        markerPreSeconds = $MarkerPreSeconds
        markerPostSeconds = $MarkerPostSeconds
        maxTrackedProcesses = $MaxTrackedProcesses
        eventWindowMinutes = $EventWindowMinutes
        stages = @(
            'performance-counters',
            'process-commit-attribution',
            'kernel-pool',
            'pagefile-metrics',
            'gpu-metrics',
            'udp-endpoints',
            'storage-topology',
            'incident-events',
            'wpr-trace'
        )
        note = 'All stages share one wall-clock capture window so the trace covers the counters.'
    }
}

if ($CaptureWpr) {
    $planManifest.plannedActions += 'capture-wpr-etl-after-explicit-consent'
    $planManifest.wpr = [ordered]@{
        profile = $WprProfile
        durationSeconds = $effectiveWprDurationSeconds
        requestedDurationSeconds = $WprDurationSeconds
        autoSizedDuration = ($WprDurationSeconds -le 0)
        maxFileMB = $WprMaxFileMB
        loggingMode = 'memory'
        concurrentWithSampling = $true
    }
}

if ($CaptureDefender) {
    $planManifest.plannedActions += 'capture-defender-performance-etl-after-explicit-consent'
    $planManifest.defender = [ordered]@{
        durationSeconds = $effectiveWprDurationSeconds
        requestedDurationSeconds = $WprDurationSeconds
        autoSizedDuration = ($WprDurationSeconds -le 0)
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

if ($SymptomContext -or $Preset) {
    $symptomBlock = [ordered]@{
        collectionWindow = [ordered]@{
            requestedAtUtc = Get-UtcTimestamp
        }
    }
    if ($SymptomContext) { $symptomBlock.reported = $SymptomContext }
    if ($Preset) { $symptomBlock.preset = $Preset }
    $planManifest.symptom = $symptomBlock
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

$script:collectionErrors = New-Object System.Collections.ArrayList

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
    $remoteStagingOwned = $false
    $remoteStagingNonce = [Guid]::NewGuid().ToString('N')
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
            # A caller-supplied path is a BASE only. Never treat it as an
            # owned directory: create and later remove a unique child.
            $remoteOutDir = New-RemoteStagingPath `
                -BaseDirectory $RemoteOutputDirectory `
                -Nonce $remoteStagingNonce
        }
        else {
            $remoteOutDir = (Invoke-Command -Session $session -ScriptBlock {
                param($nonce)
                Join-Path $env:TEMP ('WPD-Remote-Case-' + $nonce)
            } -ArgumentList $remoteStagingNonce)
        }
        $remoteScriptPath = Join-Path $remoteOutDir 'Invoke-WindowsPerformanceDiagnostics.ps1'
        $remoteDirectoryCreated = Invoke-Command -Session $session -ScriptBlock {
            param($dir)
            if (Test-Path -LiteralPath $dir) { return $false }
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            return $true
        } -ArgumentList $remoteOutDir
        if (-not [bool]$remoteDirectoryCreated) {
            throw "Remote staging directory already exists; refusing to use it: $remoteOutDir"
        }
        $remoteStagingOwned = $true
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
        if ($SymptomContext) {
            $remoteParams.SymptomContext = $SymptomContext
        }
        if ($Preset) {
            $remoteParams.Preset = $Preset
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
        # The incident-capture surface travels with a remote collection, or the
        # remote manifest would advertise a window the remote run never used.
        if ($PerformanceMode) {
            $remoteParams.PerformanceMode = $true
            $remoteParams.SampleIntervalSeconds = $SampleIntervalSeconds
            $remoteParams.EventWindowMinutes = $EventWindowMinutes
            $remoteParams.MaxTrackedProcesses = $MaxTrackedProcesses
        }
        if ($MarkerMode) {
            $remoteParams.MarkerMode = $true
            $remoteParams.MarkerPreSeconds = $MarkerPreSeconds
            $remoteParams.MarkerPostSeconds = $MarkerPostSeconds
        }
        if ($CaptureWpr) {
            $remoteParams.WprDurationSeconds = $WprDurationSeconds
            $remoteParams.WprMaxFileMB = $WprMaxFileMB
        }

        Invoke-Command -Session $session -ScriptBlock {
            param($scriptPath, $invokeParams)
            & $scriptPath @invokeParams
        } -ArgumentList $remoteScriptPath, $remoteParams

        $remoteManifestPath = Join-Path $remoteOutDir 'diagnostic-manifest.json'
        $localManifestPath = Join-Path $resolvedOutputDirectory 'diagnostic-manifest.json'
        Copy-Item -FromSession $session -Path $remoteManifestPath -Destination $localManifestPath -Force
        $remotePulledManifest = Get-Content -LiteralPath $localManifestPath -Raw | ConvertFrom-Json
        if ($remotePulledManifest.mode -ne 'Collect') {
            throw 'Remote manifest mode was not Collect; refusing to certify the pulled case.'
        }

        foreach ($artifact in @($remotePulledManifest.artifacts)) {
            $artifactName = Get-ValidatedRemoteArtifactName -Name ([string]$artifact.Name)
            $remoteArtifactPath = Join-Path $remoteOutDir $artifactName
            $localArtifactPath = Join-Path $resolvedOutputDirectory $artifactName
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
        $remoteStatus = Get-RemoteVerificationStatus `
            -HashVerificationFailed $remoteHashVerificationFailed `
            -PulledFileCount $remotePulledFileCount `
            -VerifiedFileCount $remoteVerifiedCount
        if ($remoteStatus -eq 'failed') {
            Add-CollectionErrorText `
                -Stage 'remote-hash-verification' `
                -Message 'One or more pulled remote artifacts failed SHA-256 verification.'
        }
    }
    catch {
        Add-CollectionError -Stage 'remote-collection' -ErrorRecord $_
        $remoteStatus = 'failed'
    }

    # cleanup: remove OUR remote staging dir + session (documented in the plan)
    if ($session) {
        try {
            if ($remoteStagingOwned -and $remoteOutDir) {
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
        $remotePulledManifest.safety = Get-RemoteSafetyBlock -RemoteTarget $RemoteComputer
        $remoteManifestErrors = @()
        if ($remotePulledManifest.PSObject.Properties.Name -contains 'collectionErrors') {
            $remoteManifestErrors = @($remotePulledManifest.collectionErrors)
        }
        $remotePulledManifest.collectionErrors = @($remoteManifestErrors) + @($collectionErrors)
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
    if ($remoteStatus -eq 'completed') {
        Write-Output "Remote collection complete. Manifest written to $collectionManifestPath"
        exit 0
    }
    Write-Output "Remote collection failed. Manifest written to $collectionManifestPath"
    exit 1
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

# Logical processor count: when unknown the per-process CPU percentage is
# reported as 'unknown' rather than normalizing against a guessed count.
$logicalProcessorCount = $null
try {
    $procInfo = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue
    if ($procInfo) {
        $logicalSum = @($procInfo | ForEach-Object { Get-SafeObjectProperty -InputObject $_ -Name 'NumberOfLogicalProcessors' } | Where-Object { $null -ne $_ } | Measure-Object -Sum).Sum
        if ($null -ne $logicalSum -and [int]$logicalSum -ge 1) { $logicalProcessorCount = [int]$logicalSum }
    }
}
catch { }
if ($null -eq $logicalProcessorCount) {
    Add-CollectionErrorText -Stage 'logical-processor-count' -Message 'Logical processor count unavailable; per-process CPU percentages are reported as unknown.'
}

# Monotonic stopwatch brackets the two CPU snapshots so the CPU-delta window
# matches the elapsed denominator exactly. It is stopped only after the end
# enumeration (see the process-snapshot stage below): stopping it before that
# would exclude CPU accrued during CSV export / summary polls from the
# denominator while the numerator delta still included it.
$cpuStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$processStartSnapshots = New-ProcessCpuSnapshot -Processes @(Get-Process -ErrorAction SilentlyContinue)

# ---- Incident capture window -------------------------------------------------
# WPR, the perf counters, the process/commit series, GPU, pagefile/pool and the
# UDP series all share ONE wall-clock window. Previously the trace started after
# the counter sampling finished, so the ETL could not explain pressure the
# counters recorded; the capture is now concurrent by construction.
$wprBackgroundJob = $null
$wprStartedAtUtc = $null
$wprEtlPath = Join-Path -Path $resolvedOutputDirectory -ChildPath 'wpr-trace.etl'
# The stop sentinel is the handshake that ends the trace exactly when counter
# sampling ends. It lives outside the case folder so it can never be mistaken
# for collected evidence, and it is removed after the job is joined.
$wprStopSentinelPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "wpd-wpr-stop-$PID.signal"
$wprCaptureStatus = 'not-requested'
$wprStartExitCode = $null
$wprStartError = $null

# Effective trace window: an explicit -WprDurationSeconds is honoured verbatim,
# otherwise the trace is sized to outlast the counters (baseline + the marker
# post-window) so the ETL always covers what the counters recorded. The value is
# computed once, next to the parameter validation, so Plan mode advertises the
# same number Collect mode uses.

if ($CaptureWpr) {
    $wprExe = Join-Path $env:SystemRoot 'System32\wpr.exe'
    if (-not (Test-Path -LiteralPath $wprExe)) {
        $wprCaptureStatus = 'skipped-wpr-not-found'
        Add-CollectionErrorText -Stage 'wpr-capture' -Message 'wpr.exe not found; WPR capture skipped'
    }
    elseif (-not (Test-IsElevatedConsole)) {
        # Same gate as every other consent-gated capture: a non-admin console is
        # skipped with an explicit reason, never auto-elevated and never left to
        # fail halfway through starting a trace.
        $wprCaptureStatus = 'skipped-elevation-required'
        Add-CollectionErrorText -Stage 'wpr-capture' -Message 'WPR capture requires an elevated (Administrator) console; WPR capture skipped'
    }
    else {
        # Run the whole bounded trace IN A BACKGROUND JOB so the trace
        # and the counter/process samples occupy the same wall-clock
        # window. Previously WPR started only after sampling finished,
        # which made the ETL useless for explaining the counters.
        $wprStartedAtUtc = Get-UtcTimestamp
        $wprCaptureStatus = 'running'
        $wprBackgroundJob = Start-WprBoundedCaptureJob `
            -WprExePath $wprExe `
            -Profile $WprProfile `
            -EtlPath $wprEtlPath `
            -DurationSeconds $effectiveWprDurationSeconds `
            -MaxFileMB $WprMaxFileMB `
            -StopSentinelPath $wprStopSentinelPath
    }
}

# Marker channel: -MarkerMode watches for the operator pressing Enter (or
# writing the marker file) so a short slowdown can be captured deliberately
# instead of hoping a fixed interval lands on it.
$markerFilePath = Join-Path -Path $resolvedOutputDirectory -ChildPath 'incident-marker.txt'
$markerTimeUtc = $null
$markerSource = $null
$markerJob = $null
if ($MarkerMode) {
    # A paste/console read cannot be trusted in non-interactive hosts, so the
    # job writes a plain file the sampler polls. The file is also the documented
    # automation path (`Set-Content incident-marker.txt`).
    $markerJob = Start-Job -ScriptBlock {
        param($Path)
        try {
            [void](Read-Host 'Press Enter (or type MARK) when the slowdown happens')
            $stamp = (Get-Date).ToUniversalTime().ToString('o')
            Set-Content -LiteralPath $Path -Value $stamp -Encoding Ascii -ErrorAction Stop
            return [pscustomobject]@{ MarkerFile = $Path; WrittenAtUtc = $stamp }
        }
        catch {
            return [pscustomobject]@{ MarkerFile = $Path; Error = $_.Exception.Message }
        }
    } -ArgumentList $markerFilePath
}

$samples = New-Object System.Collections.ArrayList
$diskSeries = New-Object System.Collections.ArrayList
$processMemorySeries = New-Object System.Collections.ArrayList
$kernelPoolSeries = New-Object System.Collections.ArrayList
$udpSeries = New-Object System.Collections.ArrayList
$volumeMetrics = $null
$pageFileMetrics = $null
$storageTopology = $null
$gpuMetrics = $null
$previousDiskRaw = $null
$diskSourceError = $null
$consecutiveSampleFailures = 0
$sampleIndex = 0
$samplerStartUtc = Get-UtcTimestamp
$samplingStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$captureComplete = $false

# Sampling stops at the configured baseline duration, or MarkerPostSeconds after
# the operator marks the slowdown (whichever comes first once a marker exists).
while (-not $captureComplete) {
    try {
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
        $processors = Get-CimInstance -ClassName Win32_Processor
        $logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType = 3"
        $sampleTimestamp = Get-UtcTimestamp
        $cpuLoads = @($processors | ForEach-Object { Get-SafeObjectProperty -InputObject $_ -Name 'LoadPercentage' } | Where-Object { $null -ne $_ })
        $averageCpuLoad = $null
        if ($cpuLoads.Count -gt 0) {
            $averageCpuLoad = [Math]::Round((($cpuLoads | Measure-Object -Average).Average), 2)
        }

        $memMetrics = Get-MemoryMetrics

        # ---- Per-process commit attribution (every sample) ----------------
        # Working set cannot explain a system commit charge: PrivateBytes and
        # PageFileBytes attribute the commitment to the process that caused it.
        $processRows = @()
        try {
            $processRows = @(Get-PerProcessMemorySample -MaxProcesses $MaxTrackedProcesses)
            foreach ($row in $processRows) {
                [void]$processMemorySeries.Add([pscustomobject]@{
                    TimestampUtc = $sampleTimestamp
                    Name = $row.Name
                    Id = $row.Id
                    PrivateBytes = $row.PrivateBytes
                    WorkingSet = $row.WorkingSet
                    WorkingSetPrivate = $row.WorkingSetPrivate
                    PageFileBytes = $row.PageFileBytes
                    PageFileBytesPeak = $row.PageFileBytesPeak
                    VirtualBytes = $row.VirtualBytes
                    PoolPagedBytes = $row.PoolPagedBytes
                    PoolNonpagedBytes = $row.PoolNonpagedBytes
                })
            }
        }
        catch {
            Add-CollectionError -Stage 'process-memory-sample' -ErrorRecord $_
        }

        # ---- Kernel pool (every sample) -----------------------------------
        try {
            $poolSample = Get-KernelPoolMetrics
            if ($null -ne $poolSample) {
                [void]$kernelPoolSeries.Add([pscustomobject]@{
                    TimestampUtc = $sampleTimestamp
                    PoolPagedBytes = $poolSample.poolPagedBytes
                    PoolNonpagedBytes = $poolSample.poolNonpagedBytes
                    PoolPagedResidentBytes = $poolSample.poolPagedResidentBytes
                    SystemCacheResidentBytes = $poolSample.systemCacheResidentBytes
                    CacheBytes = $poolSample.cacheBytes
                })
            }
        }
        catch {
            Add-CollectionError -Stage 'kernel-pool-sample' -ErrorRecord $_
        }

        # ---- Pagefile (first sample; size/peak are not per-second series) ---
        if ($null -eq $pageFileMetrics) {
            $pageFileMetrics = Get-PageFileMetrics
        }

        # ---- UDP endpoint series (per-PID growth over time) ---------------
        if ($PerformanceMode) {
            try {
                $udpSample = Get-UdpEndpointSample
                if ($null -ne $udpSample) {
                    [void]$udpSeries.Add($udpSample)
                }
            }
            catch {
                Add-CollectionError -Stage 'udp-endpoint-sample' -ErrorRecord $_
            }
        }

        # Per-volume free space captured inside the sample window (first sample).
        if ($null -eq $volumeMetrics) {
            $volumeMetrics = Get-VolumeMetrics
        }
        if ($null -eq $storageTopology) {
            $storageTopology = Get-StorageTopology
        }
        # GPU snapshot inside the SAME window as the counters (the counter walk
        # costs a second or two, so it is taken once, on the first sample).
        if ($null -eq $gpuMetrics) {
            try {
                $gpuMetrics = Get-GpuMetrics
            }
            catch {
                Add-CollectionError -Stage 'gpu-metrics' -ErrorRecord $_
            }
        }

        # Raw disk counters sampled inside the window; derived metrics need a
        # baseline interval, so the first sample only establishes the baseline.
        $rawDisk = Get-RawDiskMetrics
        if ($null -ne $rawDisk.Error) { $diskSourceError = $rawDisk.Error }
        if ($null -ne $previousDiskRaw -and $null -ne $rawDisk.Disks) {
            foreach ($deltaRow in @(Get-DiskCounterDeltas -Previous $previousDiskRaw -Current $rawDisk.Disks -TimestampUtc $sampleTimestamp)) {
                [void]$diskSeries.Add($deltaRow)
            }
        }
        if ($null -ne $rawDisk.Disks) {
            $previousDiskRaw = $rawDisk.Disks
        }
        else {
            # A missing raw poll is a coverage gap, not a longer interval. The
            # next usable poll establishes a new baseline and cannot bridge it.
            $previousDiskRaw = $null
        }

        $availableMemoryMB = $null
        if ($null -ne $operatingSystem.FreePhysicalMemory) {
            $availableMemoryMB = [Math]::Round(([double]$operatingSystem.FreePhysicalMemory / 1024), 2)
        }
        $totalLogicalDiskFreeGB = $null
        $freeSpaceMeasure = $logicalDisks | Where-Object { $null -ne (Get-SafeObjectProperty -InputObject $_ -Name 'FreeSpace') } | Measure-Object -Property FreeSpace -Sum
        if ($null -ne $freeSpaceMeasure -and $freeSpaceMeasure.Count -gt 0) {
            $totalLogicalDiskFreeGB = [Math]::Round(([double]$freeSpaceMeasure.Sum / 1GB), 2)
        }

        $topPrivateBytes = $null
        $topPrivateProcess = $null
        $topPageFileBytes = $null
        $topPageFileProcess = $null
        if ($processRows.Count -gt 0) {
            $topPrivate = @($processRows | Sort-Object -Property PrivateBytes -Descending | Select-Object -First 1)[0]
            $topPrivateBytes = $topPrivate.PrivateBytes
            $topPrivateProcess = $topPrivate.Name
            $topPageFile = @($processRows | Sort-Object -Property PageFileBytes -Descending | Select-Object -First 1)[0]
            $topPageFileBytes = $topPageFile.PageFileBytes
            $topPageFileProcess = $topPageFile.Name
        }

        [void]$samples.Add([pscustomobject]@{
            TimestampUtc = $sampleTimestamp
            AverageCpuLoadPercent = $averageCpuLoad
            AvailableMemoryMB = $availableMemoryMB
            TotalLogicalDiskFreeGB = $totalLogicalDiskFreeGB
            CommittedBytes = if ($memMetrics) { $memMetrics.committedBytes } else { $null }
            CommitLimitBytes = if ($memMetrics) { $memMetrics.commitLimitBytes } else { $null }
            AvailableBytes = if ($memMetrics) { $memMetrics.availableBytes } else { $null }
            PageFaultsPerSec = if ($memMetrics) { $memMetrics.pageFaultsPerSec } else { $null }
            PageReadsPerSec = if ($memMetrics) { $memMetrics.pageReadsPerSec } else { $null }
            PagesInputPerSec = if ($memMetrics) { $memMetrics.pagesInputPerSec } else { $null }
            PagesOutputPerSec = if ($memMetrics) { $memMetrics.pagesOutputPerSec } else { $null }
            TopPrivateBytesProcessName = $topPrivateProcess
            TopPrivateBytes = $topPrivateBytes
            TopPageFileBytesProcessName = $topPageFileProcess
            TopPageFileBytes = $topPageFileBytes
            SumPrivateBytes = if ($processRows.Count -gt 0) { ($processRows | Measure-Object -Property PrivateBytes -Sum).Sum } else { $null }
        })
        $consecutiveSampleFailures = 0
    }
    catch {
        Add-CollectionError -Stage 'performance-sample' -ErrorRecord $_
        $consecutiveSampleFailures++
        if ($consecutiveSampleFailures -ge 3) {
            break
        }
    }

    $sampleIndex++
    $elapsedSeconds = $samplingStopwatch.Elapsed.TotalSeconds

    # Marker detection: an operator Enter (job-written file) or a direct file
    # write both count. The post-window starts at the FIRST observed marker.
    if ($MarkerMode -and $null -eq $markerTimeUtc) {
        try {
            if (Test-Path -LiteralPath $markerFilePath -PathType Leaf) {
                $markerRaw = (Get-Content -LiteralPath $markerFilePath -ErrorAction Stop | Select-Object -First 1)
                $parsedMarker = $null
                try { $parsedMarker = ([datetime]$markerRaw).ToUniversalTime() } catch { $parsedMarker = $null }
                if ($null -eq $parsedMarker) { $parsedMarker = (Get-Date).ToUniversalTime() }
                $markerTimeUtc = $parsedMarker
                $markerSource = 'file-or-enter'
                Write-Output ("Incident marker recorded at {0}; sampling for {1} more seconds." -f $markerTimeUtc.ToString('o'), $MarkerPostSeconds)
            }
        }
        catch {
            Add-CollectionError -Stage 'incident-marker-read' -ErrorRecord $_
        }
    }

    if ($null -ne $markerTimeUtc) {
        $postMarkerSeconds = ((Get-Date).ToUniversalTime() - $markerTimeUtc).TotalSeconds
        if ($postMarkerSeconds -ge $MarkerPostSeconds) {
            $captureComplete = $true
        }
    }
    elseif ($elapsedSeconds -ge $DurationSeconds) {
        $captureComplete = $true
    }

    $percentComplete = [Math]::Min(100, [Math]::Floor(($elapsedSeconds / $DurationSeconds) * 100))
    $progressSuffix = ''
    if ($null -ne $markerTimeUtc) { $progressSuffix = '; incident marked' }
    Write-Output ([string]::Format('Sampling progress: sample {0}; {1}% of {2}-second baseline{3}', $sampleIndex, $percentComplete, $DurationSeconds, $progressSuffix))

    if (-not $captureComplete) {
        # Schedule against the original start time. This avoids drifting by the
        # collection cost of each sample while keeping a steady cadence.
        $nextSampleDueSeconds = $sampleIndex * $SampleIntervalSeconds
        $sleepMilliseconds = [Math]::Max(0, [int][Math]::Round(($nextSampleDueSeconds - $samplingStopwatch.Elapsed.TotalSeconds) * 1000))
        if ($sleepMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $sleepMilliseconds
        }
    }
}

$samplingStopwatch.Stop()
$completedAtSamplingUtc = Get-UtcTimestamp
$samplingActualSeconds = [Math]::Round((New-TimeSpan -Start ([datetime]$samplerStartUtc) -End ([datetime]$completedAtSamplingUtc)).TotalSeconds, 2)

# Counter sampling is done: end the trace now so the ETL window matches the
# counter window (the job also self-terminates at its maximum window).
if ($null -ne $wprBackgroundJob) {
    try {
        Set-Content -LiteralPath $wprStopSentinelPath -Value $completedAtSamplingUtc -Encoding Ascii -ErrorAction Stop
    }
    catch {
        Add-CollectionError -Stage 'wpr-stop-signal' -ErrorRecord $_
    }
}

# ---- Concurrent WPR trace: stop it and record the REAL duration ---------------
# The trace ran in parallel with the counters, so its window covers the same
# interval by construction. Report the measured wall clock, not the request.
$wprResult = [ordered]@{
    status = $wprCaptureStatus
    etlFilePath = $null
    startedAtUtc = $wprStartedAtUtc
    completedAtUtc = $null
    startExitCode = $null
    stopExitCode = $null
    moduleVersion = $null
    requestedDurationSeconds = $WprDurationSeconds
    effectiveDurationSeconds = $effectiveWprDurationSeconds
    autoSizedDuration = ($WprDurationSeconds -le 0)
    actualDurationSeconds = $null
    etlBytes = $null
    maxFileMB = $WprMaxFileMB
    sizeLimitExceeded = $false
    traceRemovedOversized = $false
    relatedArtifacts = @()
    loggingMode = 'memory'
    concurrentWithSampling = $true
}

if ($null -ne $wprBackgroundJob) {
    try {
        # The sentinel is already written (sampling finished), so the job exits
        # after one poll interval plus the ETL flush. The timeout only has to
        # cover a hung trace, not the trace window.
        $jobCompleted = Wait-Job -Job $wprBackgroundJob -Timeout 180
        if ($null -eq $jobCompleted) {
            Stop-Job -Job $wprBackgroundJob -ErrorAction SilentlyContinue
            Add-CollectionErrorText -Stage 'wpr-capture' -Message 'WPR background capture did not finish within its window; job stopped'
        }
        $jobOutput = @(Receive-Job -Job $wprBackgroundJob -ErrorAction SilentlyContinue)
        $jobRecord = $jobOutput | Where-Object { $_ -is [psobject] -and $null -ne $_.PSObject.Properties['StartExitCode'] } | Select-Object -Last 1
        if ($null -ne $jobRecord) {
            $wprResult.startExitCode = $jobRecord.StartExitCode
            $wprResult.stopExitCode = $jobRecord.StopExitCode
            $wprResult.completedAtUtc = $jobRecord.CompletedAtUtc
            $wprResult.etlBytes = $jobRecord.EtlBytes
            $wprResult.sizeLimitExceeded = [bool]$jobRecord.SizeLimitExceeded
            $wprResult.traceRemovedOversized = [bool]$jobRecord.TraceRemoved
            $wprResult.relatedArtifacts = @($jobRecord.RelatedArtifacts)
            if ($null -ne $jobRecord.Error) {
                Add-CollectionErrorText -Stage 'wpr-capture' -Message ([string]$jobRecord.Error)
            }
            if ($null -ne $jobRecord.StartedAtUtc -and $null -ne $jobRecord.CompletedAtUtc) {
                try {
                    $wprResult.actualDurationSeconds = [Math]::Round(
                        (New-TimeSpan -Start ([datetime]$jobRecord.StartedAtUtc) -End ([datetime]$jobRecord.CompletedAtUtc)).TotalSeconds, 2)
                }
                catch {
                    $wprResult.actualDurationSeconds = $null
                }
            }
            if ($wprResult.sizeLimitExceeded) {
                $etlMiB = [Math]::Round(([double]$wprResult.etlBytes / 1MB), 1)
                if ($wprResult.traceRemovedOversized) {
                    Add-CollectionErrorText -Stage 'wpr-capture' -Message "WPR trace was $etlMiB MiB, over the $WprMaxFileMB MiB cap; the oversized trace and its symbol artifacts were removed. Raise -WprMaxFileMB to keep it."
                }
                else {
                    Add-CollectionErrorText -Stage 'wpr-capture' -Message "WPR trace was $etlMiB MiB, over the $WprMaxFileMB MiB cap, and was kept because the oversized-trace policy was disabled."
                }
            }
        }
    }
    catch {
        Add-CollectionError -Stage 'wpr-capture' -ErrorRecord $_
        $wprResult.status = 'failed'
    }
    finally {
        Remove-Job -Job $wprBackgroundJob -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $wprStopSentinelPath -Force -ErrorAction SilentlyContinue
    }

    if ($wprResult.status -eq 'running') {
        if ($wprResult.startExitCode -ne 0) {
            $wprResult.status = 'failed'
            Add-CollectionErrorText -Stage 'wpr-capture' -Message "wpr.exe -start $WprProfile failed with exit code $($wprResult.startExitCode); WPR capture failed"
        }
        elseif ($wprResult.stopExitCode -ne 0) {
            $wprResult.status = 'failed'
            Add-CollectionErrorText -Stage 'wpr-capture' -Message "wpr.exe -stop reported exit code $($wprResult.stopExitCode); WPR capture failed"
        }
        elseif ($wprResult.traceRemovedOversized) {
            $wprResult.status = 'removed-oversized'
        }
        elseif (Test-Path -LiteralPath $wprEtlPath -PathType Leaf) {
            $wprResult.status = 'completed'
            $wprResult.etlFilePath = $wprEtlPath
            [void]$collectedArtifacts.Add('wpr-trace.etl')
        }
        else {
            $wprResult.status = 'failed'
            Add-CollectionErrorText -Stage 'wpr-capture' -Message 'wpr.exe -stop succeeded but no wpr-trace.etl was produced'
        }
    }
}

# Marker job cleanup (its result is only used to explain how the marker arrived).
if ($null -ne $markerJob) {
    try {
        [void](Wait-Job -Job $markerJob -Timeout 5)
        [void](Receive-Job -Job $markerJob -ErrorAction SilentlyContinue)
    }
    catch {
        Add-CollectionError -Stage 'incident-marker-job' -ErrorRecord $_
    }
    finally {
        Remove-Job -Job $markerJob -Force -ErrorAction SilentlyContinue
    }
}

# ---- Incident window retention ------------------------------------------------
# With a marker, keep MarkerPreSeconds before it plus MarkerPostSeconds after;
# without one, keep the whole baseline series (existing behavior).
$markerRetention = Select-MarkerRetainedSeries `
    -Samples @($samples) `
    -MarkerTimeUtc $markerTimeUtc `
    -MarkerPreSeconds $MarkerPreSeconds `
    -MarkerPostSeconds $MarkerPostSeconds
$samples = @($markerRetention.Series)
$incidentWindowStartUtc = $markerRetention.IncidentWindowStartUtc
$incidentWindowEndUtc = $markerRetention.IncidentWindowEndUtc

# Every series describes the SAME window as the retained samples, so the CSV/JSON
# artifacts cannot disagree about which minutes of the run they cover.
if ($markerRetention.MarkerApplied) {
    $diskSeries = @((Select-MarkerRetainedSeries -Samples @($diskSeries) -MarkerTimeUtc $markerTimeUtc -MarkerPreSeconds $MarkerPreSeconds -MarkerPostSeconds $MarkerPostSeconds).Series)
    $processMemorySeries = @((Select-MarkerRetainedSeries -Samples @($processMemorySeries) -MarkerTimeUtc $markerTimeUtc -MarkerPreSeconds $MarkerPreSeconds -MarkerPostSeconds $MarkerPostSeconds).Series)
    $kernelPoolSeries = @((Select-MarkerRetainedSeries -Samples @($kernelPoolSeries) -MarkerTimeUtc $markerTimeUtc -MarkerPreSeconds $MarkerPreSeconds -MarkerPostSeconds $MarkerPostSeconds).Series)
    $udpSeries = @((Select-MarkerRetainedSeries -Samples @($udpSeries) -MarkerTimeUtc $markerTimeUtc -MarkerPreSeconds $MarkerPreSeconds -MarkerPostSeconds $MarkerPostSeconds).Series)
}

# Formatted summary counters (manifest convenience only; findings use the series).
$diskMetrics = Get-DiskMetrics
if ($null -ne $diskSourceError) {
    Add-CollectionErrorText -Stage 'disk-metrics' -Message "Win32_PerfRawData_PerfDisk_PhysicalDisk unavailable: $diskSourceError"
}

try {
    $samples | Export-Csv -LiteralPath (Join-Path -Path $resolvedOutputDirectory -ChildPath 'performance-samples.csv') -NoTypeInformation -Encoding UTF8
    [void]$collectedArtifacts.Add('performance-samples.csv')
}
catch {
    Add-CollectionError -Stage 'performance-export' -ErrorRecord $_
}

# Repeated per-process commit/per-pagefile series - the answer to "what consumed
# the commit charge", as CSV (one row per process per sample) plus a top-consumer
# summary the report can cite.
try {
    $processMemorySeries | Export-Csv -LiteralPath (Join-Path -Path $resolvedOutputDirectory -ChildPath 'process-memory-samples.csv') -NoTypeInformation -Encoding UTF8
    [void]$collectedArtifacts.Add('process-memory-samples.csv')
}
catch {
    Add-CollectionError -Stage 'process-memory-export' -ErrorRecord $_
}

$processMemoryTop = @()
try {
    if ($processMemorySeries.Count -gt 0) {
        $processMemoryTop = @(
            $processMemorySeries | Group-Object -Property Name | ForEach-Object {
                $rows = @($_.Group)
                $peakPrivate = ($rows | Measure-Object -Property PrivateBytes -Maximum).Maximum
                $lastRow = $rows | Sort-Object -Property TimestampUtc | Select-Object -Last 1
                $firstRow = $rows | Sort-Object -Property TimestampUtc | Select-Object -First 1
                $growth = $null
                if ($null -ne $firstRow -and $null -ne $lastRow -and $null -ne $firstRow.PrivateBytes -and $null -ne $lastRow.PrivateBytes) {
                    $growth = [int64]$lastRow.PrivateBytes - [int64]$firstRow.PrivateBytes
                }
                [pscustomobject]@{
                    Name = $_.Name
                    PeakPrivateBytes = $peakPrivate
                    PeakWorkingSetBytes = ($rows | Measure-Object -Property WorkingSet -Maximum).Maximum
                    PeakPageFileBytes = ($rows | Measure-Object -Property PageFileBytes -Maximum).Maximum
                    PeakPoolPagedBytes = ($rows | Measure-Object -Property PoolPagedBytes -Maximum).Maximum
                    PeakPoolNonpagedBytes = ($rows | Measure-Object -Property PoolNonpagedBytes -Maximum).Maximum
                    PrivateBytesGrowth = $growth
                    SampleCount = $rows.Count
                }
            } | Sort-Object -Property PeakPrivateBytes -Descending | Select-Object -First 25
        )
    }
    Write-JsonFile -InputObject $processMemoryTop -Path (Join-Path -Path $resolvedOutputDirectory -ChildPath 'process-memory-top.json')
    [void]$collectedArtifacts.Add('process-memory-top.json')
}
catch {
    Add-CollectionError -Stage 'process-memory-top-export' -ErrorRecord $_
}

try {
    Write-JsonFile -InputObject @($kernelPoolSeries) -Path (Join-Path -Path $resolvedOutputDirectory -ChildPath 'kernel-pool-samples.json')
    [void]$collectedArtifacts.Add('kernel-pool-samples.json')
}
catch {
    Add-CollectionError -Stage 'kernel-pool-export' -ErrorRecord $_
}

if ($PerformanceMode) {
    try {
        Write-JsonFile -InputObject @($udpSeries) -Path (Join-Path -Path $resolvedOutputDirectory -ChildPath 'udp-samples.json')
        [void]$collectedArtifacts.Add('udp-samples.json')
    }
    catch {
        Add-CollectionError -Stage 'udp-samples-export' -ErrorRecord $_
    }
}

if ($null -ne $gpuMetrics) {
    try {
        Write-JsonFile -InputObject $gpuMetrics -Path (Join-Path -Path $resolvedOutputDirectory -ChildPath 'gpu-metrics.json')
        [void]$collectedArtifacts.Add('gpu-metrics.json')
    }
    catch {
        Add-CollectionError -Stage 'gpu-metrics-export' -ErrorRecord $_
    }
}

if ($null -ne $pageFileMetrics) {
    try {
        Write-JsonFile -InputObject @($pageFileMetrics) -Path (Join-Path -Path $resolvedOutputDirectory -ChildPath 'pagefile-metrics.json')
        [void]$collectedArtifacts.Add('pagefile-metrics.json')
    }
    catch {
        Add-CollectionError -Stage 'pagefile-export' -ErrorRecord $_
    }
}

# disk-samples.json / volume-metrics.json are written and registered by the
# shared Write-CollectionOutputs tail (exercised by the fixture regression).

try {
    $processEnds = @(Get-Process -ErrorAction SilentlyContinue)
    # Capture elapsed and stop here so the numerator (CPU delta between the two
    # snapshots) and the denominator (this stopwatch) cover the same interval.
    $cpuElapsedSeconds = $cpuStopwatch.Elapsed.TotalSeconds
    $cpuStopwatch.Stop()
    $processes = @(Compare-ProcessCpuSnapshots -StartSnapshots $processStartSnapshots -EndProcesses $processEnds -ElapsedSeconds $cpuElapsedSeconds -LogicalProcessors $logicalProcessorCount) |
        Sort-Object -Property { if ($_.ProcessCpuPercent -ne 'unknown') { [double]$_.ProcessCpuPercent } else { -1 } } -Descending |
        Select-Object -First 20
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

# ---- Incident-correlated event evidence ---------------------------------------
# The latest-200-System-log view cannot answer "what happened when it froze", so
# the incident window (marked time +/- EventWindowMinutes, or the collection
# window when unmarked) drives a multi-log query that keeps raw XML. Events
# outside the window are labelled, not discarded - the report can then separate
# "happened during the incident" from background noise.
$incidentEvents = @()
$incidentEventSummary = @()
$correlationWindowStart = if ($null -ne $incidentWindowStartUtc) { $incidentWindowStartUtc } else { $samplerStartUtc }
$correlationWindowEnd = if ($null -ne $incidentWindowEndUtc) { $incidentWindowEndUtc } else { $completedAtSamplingUtc }
try {
    $paddedStart = ([datetime]$correlationWindowStart).AddMinutes(-1 * $EventWindowMinutes)
    $paddedEnd = ([datetime]$correlationWindowEnd).AddMinutes($EventWindowMinutes)
    $logNames = @('System', 'Application')
    # These logs are optional/permission-limited; skip silently when absent.
    foreach ($optionalLog in @(
            'Microsoft-Windows-WER/Operational',
            'Microsoft-Windows-Kernel-LiveDump/Operational',
            'Microsoft-Windows-DriverFrameworks-UserMode/Operational',
            'Microsoft-Windows-Kernel-PnP/Configuration')) {
        try {
            $null = Get-WinEvent -ListLog $optionalLog -ErrorAction Stop
            $logNames += $optionalLog
        }
        catch {
            # log not present on this SKU - not an error
        }
    }

    foreach ($logName in $logNames) {
        try {
            $perLog = Get-EventsWithRawXml -LogName $logName -StartTime $paddedStart -MaxEvents $MaxEventCount -MaxXmlChars 8000
            foreach ($row in @($perLog.Events)) {
                $incidentEvents += $row
            }
            $incidentEventSummary += [pscustomobject]@{
                LogName = $logName
                EventCount = @($perLog.Events).Count
                SkippedUnrenderableCount = $perLog.SkippedMessageCount
                Status = 'completed'
            }
        }
        catch {
            Add-CollectionErrorText -Stage "incident-events-$logName" -Message $_.Exception.Message
            $incidentEventSummary += [pscustomobject]@{
                LogName = $logName
                EventCount = 0
                SkippedUnrenderableCount = $null
                Status = 'failed'
            }
        }
    }

    $labelledEvents = @(Add-IncidentWindowLabels `
        -Events $incidentEvents `
        -WindowStart $correlationWindowStart `
        -WindowEnd $correlationWindowEnd `
        -WindowMinutes $EventWindowMinutes)
    $inWindowEvents = @($labelledEvents | Where-Object { $_.IncidentWindow -eq 'in-window' })

    Write-JsonFile -InputObject $labelledEvents -Path (Join-Path -Path $resolvedOutputDirectory -ChildPath 'incident-events.json')
    [void]$collectedArtifacts.Add('incident-events.json')
}
catch {
    Add-CollectionError -Stage 'incident-events' -ErrorRecord $_
}

# LiveKernelReports (WHEA/TDR residue) is file-system evidence, not an event log.
$liveKernelReports = @()
try {
    $liveKernelDir = Join-Path $env:SystemRoot 'LiveKernelReports'
    if (Test-Path -LiteralPath $liveKernelDir) {
        $liveKernelReports = @(
            Get-ChildItem -LiteralPath $liveKernelDir -Recurse -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 50 | ForEach-Object {
                    [pscustomobject]@{
                        Name = $_.Name
                        FullPath = $_.FullName
                        SizeBytes = $_.Length
                        LastWriteTimeUtc = $_.LastWriteTimeUtc.ToString('o')
                        Directory = $_.DirectoryName
                    }
                }
        )
    }
    Write-JsonFile -InputObject $liveKernelReports -Path (Join-Path -Path $resolvedOutputDirectory -ChildPath 'livekernelreports.json')
    [void]$collectedArtifacts.Add('livekernelreports.json')
}
catch {
    Add-CollectionError -Stage 'livekernelreports' -ErrorRecord $_
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

# Volume -> physical disk -> pagefile relevance map (pure join over already
# collected data, so it can never fail on a live provider).
$volumeStorageMapping = @()
try {
    $volumeStorageMapping = @(Get-VolumeStorageMapping -VolumeMetrics @($volumeMetrics) -DriveToDiskMap $storageTopology -PageFileMetrics @($pageFileMetrics))
}
catch {
    Add-CollectionError -Stage 'storage-mapping' -ErrorRecord $_
}
# Schema 1.2 adds the incident-capture surface (concurrent window, marker,
# process commit attribution, GPU, pagefile/pool, UDP, correlated events).
# Older 1.0/1.1 manifests stay valid - this only widens the contract.
$manifestSchemaVersion = '1.0'
if ($SymptomContext -or $Preset) { $manifestSchemaVersion = '1.1' }
if ($PerformanceMode -or $MarkerMode) { $manifestSchemaVersion = '1.2' }

$collectionManifest = [ordered]@{
    schemaVersion = $manifestSchemaVersion
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
        sampleIntervalSeconds = $SampleIntervalSeconds
        performanceMode = [bool]$PerformanceMode
        markerMode = [bool]$MarkerMode
        eventWindowMinutes = $EventWindowMinutes
        maxTrackedProcesses = $MaxTrackedProcesses
    }
    captureWindow = [ordered]@{
        startedAtUtc = $samplerStartUtc
        completedAtUtc = $completedAtSamplingUtc
        requestedBaselineSeconds = $DurationSeconds
        actualBaselineSeconds = $samplingActualSeconds
        sampleCount = @($samples).Count
        # The evidence for "the trace covers the counters": both stages report
        # their own real start/stop inside this one window.
        wprStartUtc = $wprStartedAtUtc
        wprStopUtc = $wprResult.completedAtUtc
        wprRequestedSeconds = $WprDurationSeconds
        wprEffectiveSeconds = $effectiveWprDurationSeconds
        wprAutoSizedDuration = ($WprDurationSeconds -le 0)
        wprActualSeconds = $wprResult.actualDurationSeconds
        gpuCollectedAtUtc = if ($null -ne $gpuMetrics) { $gpuMetrics.collectedAtUtc } else { $null }
        concurrentStages = @('performance-counters', 'process-commit', 'kernel-pool', 'disk', 'gpu', 'udp', 'wpr')
    }
    incident = [ordered]@{
        markerMode = [bool]$MarkerMode
        markerObservedAtUtc = $markerTimeUtc
        markerSource = $markerSource
        windowStartUtc = $incidentWindowStartUtc
        windowEndUtc = $incidentWindowEndUtc
        preSeconds = $MarkerPreSeconds
        postSeconds = $MarkerPostSeconds
        retainedSampleCount = @($samples).Count
        droppedSampleCount = if ($null -ne $markerRetention) { $markerRetention.DroppedSampleCount } else { 0 }
    }
    safety = $planManifest.safety
    system = $systemSummary
    processMemory = [ordered]@{
        artifact = 'process-memory-samples.csv'
        topArtifact = 'process-memory-top.json'
        distinctProcessCount = @($processMemoryTop).Count
        top = @($processMemoryTop | Select-Object -First 10)
    }
    gpu = [ordered]@{
        artifact = 'gpu-metrics.json'
        adapterCount = if ($null -ne $gpuMetrics) { @($gpuMetrics.adapters).Count } else { 0 }
        engineSampleCount = if ($null -ne $gpuMetrics) { @($gpuMetrics.engines).Count } else { 0 }
        processMemorySampleCount = if ($null -ne $gpuMetrics) { @($gpuMetrics.processMemory).Count } else { 0 }
        temperature = if ($null -ne $gpuMetrics) { $gpuMetrics.temperature } else { [ordered]@{ available = $false } }
        clocks = if ($null -ne $gpuMetrics) { $gpuMetrics.clocks } else { [ordered]@{ available = $false } }
    }
    pageFile = @($pageFileMetrics)
    kernelPool = [ordered]@{
        artifact = 'kernel-pool-samples.json'
        sampleCount = @($kernelPoolSeries).Count
        latestPoolPagedBytes = if (@($kernelPoolSeries).Count -gt 0) { @($kernelPoolSeries)[-1].PoolPagedBytes } else { $null }
        latestPoolNonpagedBytes = if (@($kernelPoolSeries).Count -gt 0) { @($kernelPoolSeries)[-1].PoolNonpagedBytes } else { $null }
    }
    storageMapping = [ordered]@{
        drives = @($volumeStorageMapping)
        note = 'Drive letters are mapped to their backing physical disk and to the pagefile host so low free space on an unrelated archive or backup volume is not read as a performance cause.'
    }
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
        # UDP visibility: a TCP-only network view cannot see UDP-port
        # exhaustion, which was the actual warning on the reported machine.
        udpEndpointCount = if ($null -ne $networkState -and $null -ne $networkState.PSObject.Properties['udpEndpoints']) { @($networkState.udpEndpoints).Count } else { $null }
        udpEndpointCountByProcess = if ($null -ne $networkState -and $null -ne $networkState.PSObject.Properties['udpEndpointCountByProcess']) { @($networkState.udpEndpointCountByProcess) } else { @() }
        dynamicUdpPortRanges = if ($null -ne $networkState -and $null -ne $networkState.PSObject.Properties['dynamicUdpPortRanges']) { @($networkState.dynamicUdpPortRanges) } else { @() }
        dynamicUdpPortUsage = if ($null -ne $networkState -and $null -ne $networkState.PSObject.Properties['dynamicUdpPortUsage']) { $networkState.dynamicUdpPortUsage } else { $null }
    }
    incidentEvents = [ordered]@{
        artifact = 'incident-events.json'
        windowStartUtc = $correlationWindowStart
        windowEndUtc = $correlationWindowEnd
        windowPaddingMinutes = $EventWindowMinutes
        pulledEventCount = @($incidentEvents).Count
        inWindowEventCount = if ($null -ne $inWindowEvents) { @($inWindowEvents).Count } else { 0 }
        logs = @($incidentEventSummary)
        note = 'Events outside the incident window are retained and labelled out-of-window; they are not evidence of the incident.'
    }
    liveKernelReports = @($liveKernelReports)
    collectionErrors = $collectionErrors
    artifacts = @()
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
        udpEndpointCount = if ($networkState.Contains('udpEndpoints')) { @($networkState['udpEndpoints']).Count } else { $null }
        dynamicUdpPortRanges = if ($networkState.Contains('dynamicUdpPortRanges')) { @($networkState['dynamicUdpPortRanges']) } else { @() }
        udpEndpointCountByProcess = if ($networkState.Contains('udpEndpointCountByProcess')) { @($networkState['udpEndpointCountByProcess']) } else { @() }
    }
}

if ($CaptureWpr) {
    $collectionManifest.wpr = [ordered]@{
        profile = $WprProfile
        durationSeconds = $DurationSeconds
        requestedDurationSeconds = $WprDurationSeconds
        actualDurationSeconds = $wprResult.actualDurationSeconds
        maxFileMB = $WprMaxFileMB
        concurrentWithSampling = $true
        etlFilePath = $wprResult.etlFilePath
        etlBytes = $wprResult.etlBytes
        startedAtUtc = $wprResult.startedAtUtc
        completedAtUtc = $wprResult.completedAtUtc
        startExitCode = $wprResult.startExitCode
        stopExitCode = $wprResult.stopExitCode
        status = $wprResult.status
    }
}

if ($null -ne $gpuMetrics) {
    $collectionManifest.gpu = [ordered]@{
        artifact = 'gpu-metrics.json'
        adapterCount = @($gpuMetrics.adapters).Count
        engineSampleCount = @($gpuMetrics.engines).Count
        processMemorySampleCount = @($gpuMetrics.processMemory).Count
        temperature = $gpuMetrics.temperature
        clocks = $gpuMetrics.clocks
    }
}

if ($null -ne $pageFileMetrics) {
    $collectionManifest.pageFile = @($pageFileMetrics)
}

if ($kernelPoolSeries.Count -gt 0) {
    $lastPool = $kernelPoolSeries[$kernelPoolSeries.Count - 1]
    $collectionManifest.kernelPool = [ordered]@{
        artifact = 'kernel-pool-samples.json'
        sampleCount = $kernelPoolSeries.Count
        latestPoolPagedBytes = $lastPool.PoolPagedBytes
        latestPoolNonpagedBytes = $lastPool.PoolNonpagedBytes
    }
}

if ($null -ne $storageTopology) {
    $collectionManifest.storageMapping = [ordered]@{
        drives = @(Get-VolumeStorageMapping -VolumeMetrics $volumeMetrics -DriveToDiskMap $storageTopology -PageFileMetrics $pageFileMetrics)
        note = 'HostsPageFile identifies the volume backing the pagefile; free space on other volumes does not bound paging performance.'
    }
}

if ($processMemoryTop.Count -gt 0) {
    $collectionManifest.processMemory = [ordered]@{
        artifact = 'process-memory-samples.csv'
        topArtifact = 'process-memory-top.json'
        distinctProcessCount = @($processMemorySeries | Group-Object -Property Name).Count
        top = @($processMemoryTop | Select-Object -First 5)
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

if ($diskMetrics) {
    $collectionManifest.diskMetrics = $diskMetrics
}

if ($volumeMetrics) {
    $collectionManifest.volumeMetrics = $volumeMetrics
}

$finalMemMetrics = Get-MemoryMetrics
if ($finalMemMetrics) {
    $memErrors = $finalMemMetrics._errors
    $finalMemMetrics.Remove('_errors')
    $collectionManifest.memoryMetrics = $finalMemMetrics
    foreach ($memErr in $memErrors) {
        Add-CollectionErrorText -Stage 'memory-metrics' -Message $memErr
    }
}

# Symptom context is recorded whenever either the free text or the preset is
# supplied - a preset-only run must not silently drop the preset.
if ($SymptomContext -or $Preset) {
    $collectionManifest.symptom = [ordered]@{
        collectionWindow = [ordered]@{
            requestedAtUtc = Get-UtcTimestamp
            startedAtUtc = $startedAtUtc
            completedAtUtc = $completedAtUtc
        }
    }
    if ($SymptomContext) { $collectionManifest.symptom.reported = $SymptomContext }
    if ($Preset) { $collectionManifest.symptom.preset = $Preset }
}

# Generate findings.json/report.html, hash ALL evidence into the manifest, then
# package. Write-CollectionOutputs is the same function exercised by the
# fixture-driven Collect-tail regression test.
$collectionManifest = Write-CollectionOutputs `
    -OutputDirectory $resolvedOutputDirectory `
    -CollectionManifest $collectionManifest `
    -CollectedArtifacts $collectedArtifacts `
    -Samples @($samples) `
    -DiskSeries @($diskSeries) `
    -VolumeMetrics $volumeMetrics `
    -MemoryMetrics $finalMemMetrics `
    -SymptomContext $SymptomContext `
    -CaptureWindow $collectionManifest.captureWindow `
    -ProcessMemoryTop @($processMemoryTop)

$collectionManifestPath = Join-Path -Path $resolvedOutputDirectory -ChildPath 'diagnostic-manifest.json'
Write-Output "Collection complete. Manifest written to $collectionManifestPath"

if ($ZipOutput) {
    $collectionManifest = Add-CasePackageBlock -CollectionManifest $collectionManifest -OutputDirectory $resolvedOutputDirectory -ArtifactNames @($collectedArtifacts)
    Write-JsonFile -InputObject $collectionManifest -Path $collectionManifestPath
}
