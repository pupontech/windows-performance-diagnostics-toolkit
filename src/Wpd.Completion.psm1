#Requires -Version 5.1
# Read-only completion summary for a persisted case directory.

function Get-WpdCompletionProperty {
    param([AllowNull()][object]$InputObject, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function ConvertTo-WpdCompletionOutcome {
    param([AllowNull()][object]$Status)
    $value = ([string]$Status).ToLowerInvariant()
    if ($value -in @('success', 'completed', 'complete')) { return 'succeeded' }
    if ($value -like 'skipped-*' -or $value -in @('not-requested', 'not-collected')) { return 'skipped' }
    if ($value -eq 'partial') { return 'partial' }
    return 'failed'
}

function Add-WpdCompletionStage {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Stages,
        [string]$Collector,
        [AllowNull()][object]$Status,
        [AllowNull()][object]$Coverage
    )
    $stage = [ordered]@{
        collector = $Collector
        status = [string]$Status
        outcome = ConvertTo-WpdCompletionOutcome -Status $Status
    }
    if ($null -ne $Coverage) { $stage.coverage = [string]$Coverage }
    [void]$Stages.Add([pscustomobject]$stage)
}

function Test-WpdSafeCompletionArtifactName {
    param([AllowNull()][object]$Name)
    if ($null -eq $Name) { return $false }
    $text = ([string]$Name).Replace('\', '/')
    if (-not $text -or $text -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*$') { return $false }
    foreach ($segment in $text.Split('/')) {
        if (-not $segment -or $segment -eq '.' -or $segment -eq '..') { return $false }
    }
    return $true
}

function Test-WpdSafeCompletionPhysicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $root = [System.IO.Path]::GetPathRoot($fullPath)
    }
    catch { return $false }
    if ([string]::IsNullOrWhiteSpace($root)) { return $false }
    $current = $root
    try {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) { return $false }
    }
    catch { return $false }
    $separatorChars = @([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $relativePath = $fullPath.Substring($root.Length)
    foreach ($segment in $relativePath.Split([char[]]$separatorChars, [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $current = [System.IO.Path]::Combine($current, $segment)
        if (-not (Test-Path -LiteralPath $current -PathType Any)) { return $true }
        try {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) { return $false }
        }
        catch { return $false }
    }
    return $true
}

function Get-WpdRunCompletion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [string[]]$RequiredArtifacts = @('diagnostic-manifest.json', 'report.html'),
        [int]$CollectorExitCode = 0
    )

    try { $absoluteCase = [System.IO.Path]::GetFullPath($CaseDirectory) }
    catch {
        return [pscustomobject]@{
            status = 'failed'
            caseDirectory = [string]$CaseDirectory
            reportPath = $null
            stages = @()
            artifacts = @()
            missingArtifacts = @('diagnostic-manifest.json', 'report.html')
            reasons = @('case-directory-invalid-path')
        }
    }
    if (-not (Test-WpdSafeCompletionPhysicalPath -Path $absoluteCase)) {
        return [pscustomobject]@{
            status = 'failed'
            caseDirectory = $absoluteCase
            reportPath = $null
            stages = @()
            artifacts = @()
            missingArtifacts = @()
            reasons = @('case-directory-path-unsafe')
        }
    }
    $manifestPath = [System.IO.Path]::Combine($absoluteCase, 'diagnostic-manifest.json')
    $stages = New-Object System.Collections.ArrayList
    $artifactRows = New-Object System.Collections.ArrayList
    $missingArtifacts = New-Object System.Collections.ArrayList
    $reasons = New-Object System.Collections.ArrayList
    $hardFailure = $false
    if ($CollectorExitCode -ne 0) {
        [void]$reasons.Add(('collector-exit-code:{0}' -f $CollectorExitCode))
        $hardFailure = $true
    }
    $manifestValid = $false
    $manifest = $null
    $manifestPathSafe = Test-WpdSafeCompletionPhysicalPath -Path $manifestPath
    if (-not $manifestPathSafe) {
        [void]$reasons.Add('manifest-path-unsafe')
        $hardFailure = $true
    }
    elseif (-not [System.IO.File]::Exists($manifestPath)) {
        [void]$missingArtifacts.Add('diagnostic-manifest.json')
        [void]$reasons.Add('manifest-missing')
    }
    else {
        try {
            $manifest = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($manifestPath)) -ErrorAction Stop
            if ($null -eq $manifest -or $manifest -is [array] -or $manifest -is [string]) { throw 'Invalid manifest root.' }
            if ([string](Get-WpdCompletionProperty -InputObject $manifest -Name 'mode') -ceq 'Collect') { $manifestValid = $true }
            else { [void]$reasons.Add('manifest-mode-not-collect') }
        }
        catch {
            [void]$reasons.Add('manifest-malformed')
        }
    }
    $reportPath = [System.IO.Path]::Combine($absoluteCase, 'report.html')
    $reportPathSafe = Test-WpdSafeCompletionPhysicalPath -Path $reportPath
    if (-not $reportPathSafe) {
        $reportPath = $null
        [void]$reasons.Add('artifact-path-unsafe:report.html')
        $hardFailure = $true
    }
    elseif (-not [System.IO.File]::Exists($reportPath)) { $reportPath = $null }
    if ($null -eq $reportPath) { [void]$missingArtifacts.Add('report.html') }
    if (-not $manifestValid) {
        $unverifiedNames = New-Object System.Collections.ArrayList
        foreach ($requested in @($RequiredArtifacts) + @('diagnostic-manifest.json', 'report.html')) {
            if (-not (Test-WpdSafeCompletionArtifactName -Name $requested)) {
                if (-not $reasons.Contains('unsafe-required-artifact-name')) { [void]$reasons.Add('unsafe-required-artifact-name') }
                continue
            }
            $safeRequested = ([string]$requested).Replace('\', '/')
            if (-not $unverifiedNames.Contains($safeRequested)) { [void]$unverifiedNames.Add($safeRequested) }
        }
        foreach ($name in @($unverifiedNames)) {
            $relativePath = ([string]$name).Replace('/', [System.IO.Path]::DirectorySeparatorChar)
            $path = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($absoluteCase, $relativePath))
            $exists = $false
            $pathSafe = Test-WpdSafeCompletionPhysicalPath -Path $path
            if (-not $pathSafe) {
                [void]$reasons.Add(('artifact-path-unsafe:{0}' -f $name))
            }
            elseif ($name -eq 'diagnostic-manifest.json') { $exists = $manifestPathSafe -and [System.IO.File]::Exists($manifestPath) }
            elseif ($name -eq 'report.html') { $exists = ($null -ne $reportPath) }
            else { $exists = [System.IO.File]::Exists($path) }
            if (-not $exists -and -not $missingArtifacts.Contains([string]$name)) { [void]$missingArtifacts.Add([string]$name) }
            elseif ($exists -and $name -ne 'diagnostic-manifest.json') { [void]$reasons.Add(('required-artifact-not-verified:{0}' -f $name)) }
            [void]$artifactRows.Add([pscustomobject]@{
                name = [string]$name
                exists = [bool]$exists
                hashCheckStatus = if (-not $exists) { 'missing' } elseif ($name -eq 'diagnostic-manifest.json') { 'not-applicable' } else { 'not-registered' }
            })
        }
        return [pscustomobject]@{
            status = 'failed'
            caseDirectory = $absoluteCase
            reportPath = $reportPath
            stages = @($stages)
            artifacts = @($artifactRows)
            missingArtifacts = @($missingArtifacts)
            reasons = @($reasons)
        }
    }

    $required = New-Object System.Collections.ArrayList
    foreach ($requested in @($RequiredArtifacts) + @('diagnostic-manifest.json', 'report.html')) {
        if (-not (Test-WpdSafeCompletionArtifactName -Name $requested)) {
            if (-not $reasons.Contains('unsafe-required-artifact-name')) { [void]$reasons.Add('unsafe-required-artifact-name') }
            $hardFailure = $true
            continue
        }
        $safeRequested = ([string]$requested).Replace('\', '/')
        if (-not $required.Contains($safeRequested)) { [void]$required.Add($safeRequested) }
    }
    $registry = @{}
    foreach ($item in @($manifest.artifacts)) {
        $registeredName = Get-WpdCompletionProperty -InputObject $item -Name 'Name'
        if (-not (Test-WpdSafeCompletionArtifactName -Name $registeredName)) {
            if (-not $reasons.Contains('unsafe-registered-artifact-name')) { [void]$reasons.Add('unsafe-registered-artifact-name') }
            $hardFailure = $true
            continue
        }
        $safeRegisteredName = ([string]$registeredName).Replace('\', '/')
        $registry[$safeRegisteredName] = $item
    }
    $names = @($required) + @($registry.Keys)
    $artifactRows = New-Object System.Collections.ArrayList
    $missingArtifacts = New-Object System.Collections.ArrayList
    foreach ($name in $names | Select-Object -Unique) {
        if (-not (Test-WpdSafeCompletionArtifactName -Name $name)) { continue }
        $relativePath = ([string]$name).Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        $path = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($absoluteCase, $relativePath))
        $casePrefix = $absoluteCase.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
        if (-not $path.StartsWith($casePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            [void]$reasons.Add('artifact-path-outside-case')
            $hardFailure = $true
            continue
        }
        if (-not (Test-WpdSafeCompletionPhysicalPath -Path $path)) {
            [void]$reasons.Add(('artifact-path-unsafe:{0}' -f $name))
            $hardFailure = $true
            [void]$artifactRows.Add([pscustomobject]@{ name = [string]$name; exists = $false; hashCheckStatus = 'unsafe-path' })
            continue
        }
        $exists = [System.IO.File]::Exists($path)
        if (-not $exists) {
            [void]$missingArtifacts.Add([string]$name)
            [void]$reasons.Add(('artifact-missing:{0}' -f $name))
            $hardFailure = $true
        }
        $hashStatus = 'not-registered'
        if ([string]$name -eq 'diagnostic-manifest.json') { $hashStatus = 'not-applicable' }
        elseif (-not $exists) { $hashStatus = 'missing' }
        elseif ($registry.ContainsKey([string]$name)) {
            $expectedHash = Get-WpdCompletionProperty -InputObject $registry[[string]$name] -Name 'Sha256'
            if ($null -eq $expectedHash -or -not ([string]$expectedHash).Trim()) {
                $hashStatus = 'not-registered'
                $hardFailure = $true
                [void]$reasons.Add(('artifact-hash-not-registered:{0}' -f $name))
            }
            else {
                try {
                    $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
                    if ([string]::Equals($actualHash, [string]$expectedHash, [System.StringComparison]::OrdinalIgnoreCase)) { $hashStatus = 'match' }
                    else {
                        $hashStatus = 'mismatch'
                        $hardFailure = $true
                        [void]$reasons.Add(('artifact-hash-mismatch:{0}' -f $name))
                    }
                }
                catch {
                    $hashStatus = 'unreadable'
                    $hardFailure = $true
                    [void]$reasons.Add(('artifact-unreadable:{0}' -f $name))
                }
            }
        }
        elseif ($required.Contains([string]$name) -and [string]$name -ne 'diagnostic-manifest.json' -and $exists) {
            $hardFailure = $true
            [void]$reasons.Add(('required-artifact-not-registered:{0}' -f $name))
        }
        [void]$artifactRows.Add([pscustomobject]@{ name = [string]$name; exists = [bool]$exists; hashCheckStatus = $hashStatus })
    }

    $stages = New-Object System.Collections.ArrayList
    $tiers = Get-WpdCompletionProperty -InputObject $manifest -Name 'tiers'
    $coverageRows = Get-WpdCompletionProperty -InputObject $tiers -Name 'coverage'
    foreach ($row in @($coverageRows)) {
        if ($null -eq $row) { continue }
        Add-WpdCompletionStage -Stages $stages -Collector ([string]$row.collector) -Status $row.status -Coverage $row.coverage
    }
    $tier3 = Get-WpdCompletionProperty -InputObject $tiers -Name 'tier3'
    $adapterRows = Get-WpdCompletionProperty -InputObject $tier3 -Name 'adapters'
    foreach ($adapter in @($adapterRows)) {
        if ($null -eq $adapter) { continue }
        Add-WpdCompletionStage -Stages $stages -Collector ([string]$adapter.id) -Status $adapter.status -Coverage $adapter.coverage
    }
    if ($null -ne $tier3 -and @($adapterRows).Count -eq 0) {
        Add-WpdCompletionStage -Stages $stages -Collector 'tier3-optional-escalation' -Status $tier3.status -Coverage $tier3.coverage
    }
    foreach ($name in @('wpr', 'minidumps', 'bootFailureLogs', 'package')) {
        $item = $manifest.$name
        if ($null -ne $item) { Add-WpdCompletionStage -Stages $stages -Collector $name -Status $item.status -Coverage $null }
    }
    $collectionErrors = @(Get-WpdCompletionProperty -InputObject $manifest -Name 'collectionErrors' | Where-Object { $null -ne $_ })
    if ($collectionErrors.Count -gt 0) {
        [void]$reasons.Add(('collection-errors:{0}' -f $collectionErrors.Count))
        foreach ($item in $collectionErrors) {
            $stageName = Get-WpdCompletionProperty -InputObject $item -Name 'Stage'
            if ($null -eq $stageName) { $stageName = Get-WpdCompletionProperty -InputObject $item -Name 'stage' }
            if ($null -eq $stageName -or -not ([string]$stageName).Trim()) { $stageName = 'collection-error' }
            Add-WpdCompletionStage -Stages $stages -Collector ([string]$stageName) -Status 'error' -Coverage $null
        }
    }
    $partial = @($stages | Where-Object { $_.outcome -eq 'partial' -or $_.outcome -eq 'failed' }).Count -gt 0
    $status = if ($partial) { 'partial' } else { 'completed' }
    if ($CollectorExitCode -ne 0 -or $hardFailure) { $status = 'failed' }
    return [pscustomobject]@{
        status = $status
        caseDirectory = $absoluteCase
        reportPath = $reportPath
        stages = @($stages)
        artifacts = @($artifactRows)
        missingArtifacts = @($missingArtifacts)
        reasons = @($reasons)
    }
}

function Show-WpdRunCompletion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Completion,
        [switch]$OpenOutputs,
        [scriptblock]$PresentationRunner
    )

    Write-Host ('Run summary: {0}' -f [string]$Completion.status)
    Write-Host 'Stages:'
    foreach ($stage in @($Completion.stages)) {
        Write-Host ('  {0}: {1} ({2})' -f [string]$stage.collector, [string]$stage.status, [string]$stage.outcome)
    }
    foreach ($name in @($Completion.missingArtifacts)) { Write-Host ('Missing artifact: {0}' -f [string]$name) }
    foreach ($reason in @($Completion.reasons)) { Write-Host ('Issue: {0}' -f [string]$reason) }
    Write-Host ('Case folder: {0}' -f [string]$Completion.caseDirectory)
    if ($null -ne $Completion.reportPath) { Write-Host ('Final report: {0}' -f [string]$Completion.reportPath) }

    $presentationStatus = 'not-requested'
    $presentationReason = $null
    $failures = New-Object System.Collections.ArrayList
    $openedCase = $false
    $openedReport = $false
    if ($OpenOutputs) {
        $verified = $false
        $verifiedCompletion = $null
        try {
            if ([string]$Completion.status -in @('completed', 'partial') -and @($Completion.missingArtifacts).Count -eq 0) {
                $recheckRequired = New-Object System.Collections.ArrayList
                foreach ($artifact in @($Completion.artifacts)) {
                    $artifactName = Get-WpdCompletionProperty -InputObject $artifact -Name 'name'
                    if ($null -ne $artifactName -and [string]$artifactName -ne 'diagnostic-manifest.json') {
                        [void]$recheckRequired.Add([string]$artifactName)
                    }
                }
                $verifiedCompletion = Get-WpdRunCompletion -CaseDirectory ([string]$Completion.caseDirectory) -RequiredArtifacts @($recheckRequired)
                $verified = ($verifiedCompletion.status -ne 'failed' -and
                    @($verifiedCompletion.missingArtifacts).Count -eq 0 -and
                    $null -ne $verifiedCompletion.reportPath)
                foreach ($artifact in @($verifiedCompletion.artifacts)) {
                    if (-not $artifact.exists -or $artifact.hashCheckStatus -notin @('match', 'not-applicable')) { $verified = $false }
                    if ($artifact.name -eq 'report.html' -and $artifact.hashCheckStatus -ne 'match') { $verified = $false }
                }
            }
        }
        catch {
            $verified = $false
        }
        if (-not $verified) {
            $presentationStatus = 'refused'
            $presentationReason = 'completion-not-verified'
        }
        elseif ($null -ne $PresentationRunner) {
            try {
                $caseResult = & $PresentationRunner -Action 'open-case' -Path ([string]$verifiedCompletion.caseDirectory)
                if ($caseResult -is [bool] -and -not $caseResult) { throw 'Presentation runner refused the case folder.' }
                $openedCase = $true
                $reportResult = & $PresentationRunner -Action 'open-report' -Path ([string]$verifiedCompletion.reportPath)
                if ($reportResult -is [bool] -and -not $reportResult) { throw 'Presentation runner refused the report.' }
                $openedReport = $true
                $presentationStatus = 'opened'
            }
            catch {
                [void]$failures.Add('presentation-runner-failed')
                $presentationStatus = 'failed'
                $presentationReason = 'presentation-runner-failed'
            }
        }
        elseif ([string]$env:CI -ieq 'true') {
            $presentationStatus = 'suppressed'
            $presentationReason = 'ci-environment'
        }
        elseif ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
            $presentationStatus = 'suppressed'
            $presentationReason = 'non-windows-host'
        }
        else {
            try {
                Start-Process -FilePath ([string]$verifiedCompletion.caseDirectory) -ErrorAction Stop
                $openedCase = $true
                Start-Process -FilePath ([string]$verifiedCompletion.reportPath) -ErrorAction Stop
                $openedReport = $true
                $presentationStatus = 'opened'
            }
            catch {
                [void]$failures.Add('presentation-command-failed')
                $presentationStatus = 'failed'
                $presentationReason = 'presentation-command-failed'
            }
        }
    }

    return [pscustomobject]@{
        status = $presentationStatus
        reason = $presentationReason
        openedCase = [bool]$openedCase
        openedReport = [bool]$openedReport
        failures = @($failures)
    }
}

Export-ModuleMember -Function Get-WpdRunCompletion, Show-WpdRunCompletion
