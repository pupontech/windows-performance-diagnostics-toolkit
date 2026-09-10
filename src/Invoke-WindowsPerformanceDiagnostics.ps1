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
    [string]$Preset
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Single source of truth for the version is the VERSION file at the repo/bundle
# root; the constant below is only a fallback for standalone copies of the
# script (e.g. CI staging copies) - test_version_file_matches_script_fallback
# keeps the two in sync so drift fails CI.
$script:ScriptVersion = '0.9.0'
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
        [string]$WindowEnd
    )

    $findings = @()
    $sustainedThreshold = 5
    $sampleList = @($Samples)
    $cpuValidCount = Get-FiniteNumericCount -Samples $sampleList -ValueProperty 'AverageCpuLoadPercent'

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

    # Separate findings by category
    $pressureFindings = @($Findings | Where-Object { $_.category -match 'pressure|paging|disk' })
    $coverageFindings = @($Findings | Where-Object { $_.category -eq 'coverage' })

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

    if ($pressureFindings.Count -eq 0 -and $coverageFindings.Count -eq 0) {
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

        [AllowNull()][string]$SymptomContext
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
        $findingsList = @(Evaluate-Findings -Samples $Samples -DiskSeries $DiskSeries -VolumeMetrics $VolumeMetrics -MemoryMetrics $MemoryMetrics -WindowStart $windowStart -WindowEnd $windowEnd)
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

$samples = New-Object System.Collections.ArrayList
$diskSeries = New-Object System.Collections.ArrayList
$volumeMetrics = $null
$previousDiskRaw = $null
$diskSourceError = $null
$consecutiveSampleFailures = 0
$sampleIndex = 0
# DurationSeconds is a wall-clock budget for the baseline sample window.  A
# slow CIM request can finish just after the deadline, but it cannot add an
# extra one-second sleep per sample and prolong the whole window.
$samplingStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
while ($samplingStopwatch.Elapsed.TotalSeconds -lt $DurationSeconds) {
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

        # Per-volume free space captured inside the sample window (first sample).
        if ($null -eq $volumeMetrics) {
            $volumeMetrics = Get-VolumeMetrics
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
        if ($null -ne $rawDisk.Disks) { $previousDiskRaw = $rawDisk.Disks }

        $availableMemoryMB = $null
        if ($null -ne $operatingSystem.FreePhysicalMemory) {
            $availableMemoryMB = [Math]::Round(([double]$operatingSystem.FreePhysicalMemory / 1024), 2)
        }
        $totalLogicalDiskFreeGB = $null
        $freeSpaceMeasure = $logicalDisks | Where-Object { $null -ne (Get-SafeObjectProperty -InputObject $_ -Name 'FreeSpace') } | Measure-Object -Property FreeSpace -Sum
        if ($null -ne $freeSpaceMeasure -and $freeSpaceMeasure.Count -gt 0) {
            $totalLogicalDiskFreeGB = [Math]::Round(([double]$freeSpaceMeasure.Sum / 1GB), 2)
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
    $percentComplete = [Math]::Min(100, [Math]::Floor(($elapsedSeconds / $DurationSeconds) * 100))
    Write-Output ([string]::Format('Sampling progress: sample {0}; {1}% of {2}-second baseline', $sampleIndex, $percentComplete, $DurationSeconds))

    # Schedule against the original start time. This avoids drifting by the
    # collection cost of each sample while keeping a roughly one-second cadence.
    $nextSampleDueSeconds = [Math]::Min($sampleIndex, $DurationSeconds)
    $sleepMilliseconds = [Math]::Max(0, [int][Math]::Round(($nextSampleDueSeconds - $samplingStopwatch.Elapsed.TotalSeconds) * 1000))
    if ($sleepMilliseconds -gt 0) {
        Start-Sleep -Milliseconds $sleepMilliseconds
    }
}

$completedAtSamplingUtc = Get-UtcTimestamp

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
                $etlExists = Test-Path -LiteralPath $etlPath -PathType Leaf
                $etlBytes = 0
                if ($etlExists) {
                    $etlBytes = (Get-Item -LiteralPath $etlPath).Length
                }
                if ($stopExitCode -eq 0 -and $etlExists -and $etlBytes -gt 0) {
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
                    if ($stopExitCode -ne 0) {
                        $wprStopErrorId = 'WprStopFailed'
                        $wprStopMessage = "wpr.exe -stop reported exit code $stopExitCode; WPR capture failed (etlExists=$etlExists, etlBytes=$etlBytes)"
                    }
                    else {
                        $wprStopErrorId = 'WprEtlMissing'
                        $wprStopMessage = "wpr.exe -stop succeeded but no non-empty wpr-trace.etl was produced (etlExists=$etlExists, etlBytes=$etlBytes)"
                    }
                    Add-CollectionError -Stage 'wpr-capture' -ErrorRecord ([System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new($wprStopMessage),
                        $wprStopErrorId,
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
    schemaVersion = if ($SymptomContext) { '1.1' } else { '1.0' }
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
    -SymptomContext $SymptomContext

$collectionManifestPath = Join-Path -Path $resolvedOutputDirectory -ChildPath 'diagnostic-manifest.json'
Write-Output "Collection complete. Manifest written to $collectionManifestPath"

if ($ZipOutput) {
    $collectionManifest = Add-CasePackageBlock -CollectionManifest $collectionManifest -OutputDirectory $resolvedOutputDirectory -ArtifactNames @($collectedArtifacts)
    Write-JsonFile -InputObject $collectionManifest -Path $collectionManifestPath
}
