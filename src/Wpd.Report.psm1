#Requires -Version 5.1
# Wpd.Report.psm1
# Evidence-first finding normalization and offline technician report rendering.
# This module is provider-neutral: all Windows data is supplied by callers.

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:WpdReportCategories = @(
    'cpu-pressure'
    'memory-pressure'
    'memory-paging'
    'memory-leak'
    'disk-pressure'
    'disk-latency'
    'disk-space'
    'commit-attribution'
    'network-errors'
    'gpu-saturation'
    'ui-responsiveness'
    'boot-degradation'
    'power-throttling'
    'audio-glitch'
    'crash-evidence'
    'servicing-failure'
    'evidence-coverage'
    'coverage'
)

$script:WpdReportSeverities = @('informational', 'low', 'medium', 'high')
$script:WpdReportConfidences = @('High', 'Medium', 'Low')
$script:WpdReportCoverages = @('complete', 'partial', 'unavailable', 'not-collected', 'unsupported')
$script:WpdReportOutcomes = @('FINDINGS IDENTIFIED', 'ROOT CAUSE NOT IDENTIFIED')

function ConvertTo-WpdReportArray {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return @()
    }
    if ($Value -is [string]) {
        return @($Value)
    }
    return @($Value)
}

function Get-WpdReportProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][object]$Default
    )

    if ($null -eq $InputObject) {
        return $Default
    }
    try {
        if ($InputObject -is [System.Collections.IDictionary]) {
            if ($InputObject.Contains($Name)) {
                return $InputObject[$Name]
            }
            foreach ($key in @($InputObject.Keys)) {
                if ([string]$key -ieq $Name) {
                    return $InputObject[$key]
                }
            }
        }
        $property = $InputObject.PSObject.Properties[$Name]
        if ($null -ne $property) {
            return $property.Value
        }
    }
    catch {
        return $Default
    }
    return $Default
}

function Get-WpdReportFirstProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string[]]$Names,
        [AllowNull()][object]$Default
    )

    foreach ($name in $Names) {
        $value = Get-WpdReportProperty -InputObject $InputObject -Name $name
        if ($null -ne $value) {
            return $value
        }
    }
    return $Default
}

function ConvertTo-WpdReportFiniteNumber {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }
    try {
        $number = [double]$Value
        if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) {
            return $null
        }
        return $number
    }
    catch {
        return $null
    }
}

function ConvertTo-WpdReportUtcDateTime {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [datetimeoffset]) {
        return ([datetimeoffset]$Value).UtcDateTime
    }
    if ($Value -is [datetime]) {
        return ([datetime]$Value).ToUniversalTime()
    }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.ToUniversalTime()
    }
    return $null
}

function ConvertTo-WpdReportTimestamp {
    param([AllowNull()][object]$Value)

    $utc = ConvertTo-WpdReportUtcDateTime -Value $Value
    if ($null -eq $utc) {
        return $null
    }
    return $utc.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Test-WpdReportSafeRelativePath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }
    if ($Path.IndexOf([char]0) -ge 0) {
        return $false
    }
    $normalized = $Path.Replace('/', '\')
    if ($normalized.StartsWith('\') -or $normalized -match '^[A-Za-z]:') {
        return $false
    }
    if ($normalized -match '[:*?"<>|%#]') {
        return $false
    }
    foreach ($segment in $normalized.Split([char]92)) {
        if ($segment -eq '.' -or $segment -eq '..') {
            return $false
        }
    }
    return $true
}

function ConvertTo-WpdReportForwardPath {
    param([AllowNull()][string]$Path)

    if ($null -eq $Path) {
        return $null
    }
    return $Path.Replace('\', '/')
}

function ConvertTo-WpdReportDisplayValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }
    if ($Value -is [string] -or $Value -is [ValueType]) {
        return [string]$Value
    }
    try {
        return ($Value | ConvertTo-Json -Depth 8 -Compress)
    }
    catch {
        return [string]$Value
    }
}

function ConvertTo-WpdReportHtmlEncoded {
    param([AllowNull()][object]$Value)

    return [System.Net.WebUtility]::HtmlEncode((ConvertTo-WpdReportDisplayValue -Value $Value))
}

function Get-WpdReportCoverage {
    param(
        [AllowEmptyString()][string]$Status,
        [AllowEmptyString()][string]$Coverage,
        [AllowNull()][object]$ObservedSamples,
        [AllowNull()][object]$ExpectedSamples
    )

    $candidate = if (-not [string]::IsNullOrWhiteSpace($Coverage)) { $Coverage.ToLowerInvariant() } else { '' }
    if ($candidate -eq 'healthy') {
        return 'unavailable'
    }
    if ($script:WpdReportCoverages -contains $candidate) {
        $normalized = $candidate
    }
    else {
        $normalizedStatus = if ($null -eq $Status) { '' } else { $Status.ToLowerInvariant() }
        switch ($normalizedStatus) {
            'success' { $normalized = 'complete' }
            'completed' { $normalized = 'complete' }
            'partial' { $normalized = 'partial' }
            'not-collected' { $normalized = 'not-collected' }
            'unsupported' { $normalized = 'unsupported' }
            default { $normalized = 'unavailable' }
        }
    }
    $observed = 0
    try { $observed = [int]$ObservedSamples } catch { $observed = 0 }
    $expected = 0
    try { $expected = [int]$ExpectedSamples } catch { $expected = 0 }
    if ($normalized -eq 'complete' -and $expected -gt 0 -and $observed -lt $expected) {
        $normalized = 'partial'
    }
    if ($observed -le 0 -and ($normalized -eq 'complete' -or $normalized -eq 'partial')) {
        return 'unavailable'
    }
    return $normalized
}

function Get-WpdReportStatusForCoverage {
    param([AllowEmptyString()][string]$Coverage)

    switch ($Coverage) {
        'complete' { return 'success' }
        'partial' { return 'partial' }
        'not-collected' { return 'not-collected' }
        'unsupported' { return 'unsupported' }
        default { return 'unavailable' }
    }
}

function Test-WpdReportQualitySufficient {
    param(
        [AllowNull()][object]$Quality,
        [int]$MinimumSamples = 1,
        [double]$MinimumDurationSeconds = 0
    )

    if ($null -eq $Quality) {
        return $false
    }
    $coverage = [string](Get-WpdReportProperty -InputObject $Quality -Name 'coverage')
    if ([string]::IsNullOrWhiteSpace($coverage)) {
        $coverage = Get-WpdReportCoverage `
            -Status ([string](Get-WpdReportProperty -InputObject $Quality -Name 'status')) `
            -Coverage '' `
            -ObservedSamples (Get-WpdReportProperty -InputObject $Quality -Name 'observedSamples') `
            -ExpectedSamples (Get-WpdReportProperty -InputObject $Quality -Name 'expectedSamples')
    }
    if ($coverage -ne 'complete' -and $coverage -ne 'partial') {
        return $false
    }
    $explicit = Get-WpdReportProperty -InputObject $Quality -Name 'sufficient'
    if ($null -ne $explicit -and -not [bool]$explicit) {
        return $false
    }
    $usable = Get-WpdReportProperty -InputObject $Quality -Name 'isUsable'
    if ($null -eq $usable) {
        $usable = Get-WpdReportProperty -InputObject $Quality -Name 'usable'
    }
    if ($null -ne $usable -and -not [bool]$usable) {
        return $false
    }
    $observed = 0
    try {
        $observed = [int](Get-WpdReportFirstProperty -InputObject $Quality -Names @('observedSamples', 'sampleCount', 'recordCount') -Default 0)
    }
    catch { $observed = 0 }
    if ($observed -lt [math]::Max(1, $MinimumSamples)) {
        return $false
    }
    if ($MinimumDurationSeconds -gt 0) {
        $duration = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportProperty -InputObject $Quality -Name 'durationSeconds')
        if ($null -eq $duration -or $duration -lt $MinimumDurationSeconds) {
            return $false
        }
    }
    return $true
}

function Get-WpdReportCategories {
    return $script:WpdReportCategories
}

function Get-WpdReportOutcomeValues {
    return $script:WpdReportOutcomes
}

function Get-WpdReportSeverityValues {
    return $script:WpdReportSeverities
}

function Get-WpdReportConfidenceValues {
    return $script:WpdReportConfidences
}

function Get-WpdConfidenceValues {
    return Get-WpdReportConfidenceValues
}

function Get-WpdReportCoverageStates {
    return $script:WpdReportCoverages
}

function Get-WpdReportCategoryTitle {
    param([AllowEmptyString()][string]$Category)

    if ($script:WpdReportCategories -notcontains $Category) {
        return 'Other finding'
    }
    $text = $Category.Replace('-', ' ')
    $words = @($text.Split(' '))
    $result = @()
    foreach ($word in $words) {
        if ([string]::IsNullOrWhiteSpace($word)) { continue }
        $result += $word.Substring(0, 1).ToUpperInvariant() + $word.Substring(1)
    }
    return ($result -join ' ')
}

function Get-WpdReportArtifactName {
    param([AllowNull()][object]$Artifact)

    if ($Artifact -is [string]) {
        return [string]$Artifact
    }
    return [string](Get-WpdReportFirstProperty -InputObject $Artifact -Names @('Name', 'name', 'Path', 'path', 'artifact') -Default '')
}

function Get-WpdReportArtifactHash {
    param([AllowNull()][object]$Artifact)

    return [string](Get-WpdReportFirstProperty -InputObject $Artifact -Names @('Sha256', 'sha256', 'Hash', 'hash') -Default '')
}

function Test-WpdReportArtifactHasHash {
    param([AllowNull()][object]$Artifact)

    $hash = Get-WpdReportArtifactHash -Artifact $Artifact
    return (-not [string]::IsNullOrWhiteSpace($hash) -and $hash -match '^[A-Fa-f0-9]{64}$')
}

function New-WpdEvidenceIndexRecord {
    param(
        [AllowEmptyString()][string]$Id,
        [Alias('ArtifactName')][AllowEmptyString()][string]$Artifact,
        [Alias('EvidencePath')][AllowEmptyString()][string]$Path,
        [AllowEmptyString()][string]$Metric,
        [AllowNull()][object]$Value,
        [AllowNull()][object]$ValueRange,
        [AllowNull()][object]$WindowStartUtc,
        [AllowNull()][object]$WindowEndUtc,
        [AllowEmptyString()][string]$Quality = 'unavailable',
        [AllowEmptyString()][string]$Status,
        [AllowEmptyString()][string]$Collector,
        [AllowEmptyString()][string]$Source
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = $Artifact
    }
    $recordPath = $Path
    $start = ConvertTo-WpdReportTimestamp -Value $WindowStartUtc
    $end = ConvertTo-WpdReportTimestamp -Value $WindowEndUtc
    $qualityValue = Get-WpdReportCoverage -Status $Status -Coverage $Quality -ObservedSamples 1 -ExpectedSamples 1
    $recordStatus = Get-WpdReportStatusForCoverage -Coverage $qualityValue
    $safe = Test-WpdReportSafeRelativePath -Path $Path
    $reason = $null
    if (-not $safe) {
        $reason = 'unsafe-path'
        $recordPath = $null
        $recordStatus = 'unavailable'
        $qualityValue = 'unavailable'
    }
    elseif ([string]::IsNullOrWhiteSpace($Artifact) -or [string]::IsNullOrWhiteSpace($Metric)) {
        $reason = 'incomplete-provenance'
        $recordStatus = 'unavailable'
        $qualityValue = 'unavailable'
    }
    if (($null -ne $WindowStartUtc -and $null -eq $start) -or ($null -ne $WindowEndUtc -and $null -eq $end)) {
        $reason = 'invalid-window-time'
        $recordStatus = 'unavailable'
        $qualityValue = 'unavailable'
    }
    if ($null -eq $Value) {
        if ($null -eq $reason) { $reason = 'missing-measurement' }
        $recordStatus = 'unavailable'
        $qualityValue = 'unavailable'
    }
    if ([string]::IsNullOrWhiteSpace($Id)) {
        $identity = '{0}|{1}|{2}|{3}|{4}' -f $Artifact, $Path, $Metric, $start, $end
        $algorithm = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($identity)
            $digest = $algorithm.ComputeHash($bytes)
            $Id = 'evidence-' + ([System.BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant().Substring(0, 16)
        }
        finally {
            $algorithm.Dispose()
        }
    }
    $range = $ValueRange
    if ($null -eq $range) {
        $number = ConvertTo-WpdReportFiniteNumber -Value $Value
        if ($null -ne $number) {
            $range = [ordered]@{ min = $number; max = $number }
        }
        else {
            $range = $null
        }
    }
    return [pscustomobject]@{
        id = $Id
        artifact = $Artifact
        path = $recordPath
        metric = $Metric
        value = $Value
        valueRange = $range
        windowStart = $start
        windowEnd = $end
        collector = $Collector
        source = $Source
        status = $recordStatus
        coverage = $qualityValue
        quality = $qualityValue
        artifactRegistered = $false
        hashed = $false
        linkable = $false
        reason = $reason
    }
}

function Get-WpdReportIndexRecords {
    param([AllowNull()][object]$EvidenceIndex)

    if ($null -eq $EvidenceIndex) {
        return @()
    }
    if ($EvidenceIndex -is [System.Array]) {
        return @($EvidenceIndex | Where-Object { $null -ne $_ })
    }
    $records = Get-WpdReportFirstProperty -InputObject $EvidenceIndex -Names @('records', 'items', 'evidence')
    if ($null -ne $records) {
        return @($records | Where-Object { $null -ne $_ })
    }
    if ($null -ne (Get-WpdReportProperty -InputObject $EvidenceIndex -Name 'id')) {
        return @($EvidenceIndex)
    }
    return @()
}

function Get-WpdReportIndexArtifacts {
    param([AllowNull()][object]$EvidenceIndex)

    if ($null -eq $EvidenceIndex -or $EvidenceIndex -is [System.Array]) {
        return @()
    }
    $artifacts = Get-WpdReportFirstProperty -InputObject $EvidenceIndex -Names @('artifacts', 'artifactRecords')
    if ($null -eq $artifacts) {
        return @()
    }
    return @($artifacts | Where-Object { $null -ne $_ })
}

function New-WpdEvidenceIndex {
    param(
        [AllowNull()][object[]]$Records = @(),
        [AllowNull()][object[]]$Artifacts = @()
    )

    $artifactRows = @()
    $artifactMap = @{}
    foreach ($artifact in (ConvertTo-WpdReportArray -Value $Artifacts)) {
        if ($null -eq $artifact) { continue }
        $name = Get-WpdReportArtifactName -Artifact $artifact
        $safe = Test-WpdReportSafeRelativePath -Path $name
        $hash = Get-WpdReportArtifactHash -Artifact $artifact
        $hashed = Test-WpdReportArtifactHasHash -Artifact $artifact
        $registered = [bool]$safe
        $normalized = [pscustomobject]@{
            name = $name
            path = if ($safe) { ConvertTo-WpdReportForwardPath -Path $name } else { $null }
            sizeBytes = Get-WpdReportFirstProperty -InputObject $artifact -Names @('SizeBytes', 'sizeBytes', 'Length')
            sha256 = if ($hashed) { $hash } else { $null }
            safePath = [bool]$safe
            hashed = [bool]$hashed
            registered = [bool]$registered
            reason = if (-not $safe) { 'unsafe-path' } elseif (-not $hashed) { 'missing-or-invalid-sha256' } else { $null }
        }
        $artifactRows += $normalized
        if ($safe) {
            $artifactMap[$name] = $normalized
            $artifactMap[(ConvertTo-WpdReportForwardPath -Path $name)] = $normalized
        }
    }

    $recordRows = @()
    $recordIds = @{}
    $errors = @()
    foreach ($record in (ConvertTo-WpdReportArray -Value $Records)) {
        if ($null -eq $record) { continue }
        $id = [string](Get-WpdReportProperty -InputObject $record -Name 'id')
        $artifactName = [string](Get-WpdReportFirstProperty -InputObject $record -Names @('artifact', 'artifactName', 'sourceArtifact') -Default '')
        $path = [string](Get-WpdReportFirstProperty -InputObject $record -Names @('path', 'evidencePath') -Default $artifactName)
        $metric = [string](Get-WpdReportProperty -InputObject $record -Name 'metric')
        $value = Get-WpdReportProperty -InputObject $record -Name 'value'
        $startValue = Get-WpdReportFirstProperty -InputObject $record -Names @('windowStart', 'windowStartUtc')
        $endValue = Get-WpdReportFirstProperty -InputObject $record -Names @('windowEnd', 'windowEndUtc')
        $qualityValue = [string](Get-WpdReportFirstProperty -InputObject $record -Names @('quality', 'coverage', 'status') -Default 'unavailable')
        $sourceValue = [string](Get-WpdReportProperty -InputObject $record -Name 'source')
        $collectorValue = [string](Get-WpdReportProperty -InputObject $record -Name 'collector')
        $rangeValue = Get-WpdReportProperty -InputObject $record -Name 'valueRange'
        $normalizedRecord = New-WpdEvidenceIndexRecord -Id $id -Artifact $artifactName -Path $path `
            -Metric $metric -Value $value -ValueRange $rangeValue -WindowStartUtc $startValue `
            -WindowEndUtc $endValue -Quality $qualityValue -Collector $collectorValue -Source $sourceValue
        $recordId = [string]$normalizedRecord.id
        if ($recordIds.ContainsKey($recordId)) {
            $errors += ('duplicate-evidence-id:' + $recordId)
            continue
        }
        $recordIds[$recordId] = $true
        $normalizedPath = ConvertTo-WpdReportForwardPath -Path $normalizedRecord.path
        $artifactRecord = $null
        if ($null -ne $normalizedPath -and $artifactMap.ContainsKey($normalizedPath)) {
            $artifactRecord = $artifactMap[$normalizedPath]
        }
        elseif ($null -ne $normalizedRecord.path -and $artifactMap.ContainsKey([string]$normalizedRecord.path)) {
            $artifactRecord = $artifactMap[[string]$normalizedRecord.path]
        }
        if ($null -ne $artifactRecord -and $artifactRecord.registered) {
            $normalizedRecord.artifactRegistered = $true
            $normalizedRecord.hashed = [bool]$artifactRecord.hashed
            $normalizedRecord.linkable = $true
            $normalizedRecord.reason = if ($artifactRecord.hashed) { $null } else { 'missing-or-invalid-sha256' }
        }
        else {
            $normalizedRecord.artifactRegistered = $false
            $normalizedRecord.hashed = $false
            $normalizedRecord.linkable = $false
            if ($null -eq $normalizedRecord.reason) {
                $normalizedRecord.reason = 'artifact-not-registered-or-hashed'
            }
        }
        $recordRows += $normalizedRecord
    }

    $registeredCount = @($artifactRows | Where-Object { $_.registered }).Count
    $linkableCount = @($recordRows | Where-Object { $_.linkable }).Count
    $status = 'unavailable'
    $coverage = 'unavailable'
    $unhashedCount = @($artifactRows | Where-Object { $_.registered -and -not $_.hashed }).Count
    if ($recordRows.Count -gt 0 -and $errors.Count -eq 0 -and $linkableCount -eq $recordRows.Count -and $unhashedCount -eq 0) {
        $status = 'success'
        $coverage = 'complete'
    }
    elseif ($recordRows.Count -gt 0) {
        $status = 'partial'
        $coverage = 'partial'
    }
    if ($recordRows.Count -eq 0) {
        $errors += 'no-evidence-records'
    }
    $byId = @{}
    foreach ($row in $recordRows) {
        $byId[[string]$row.id] = $row
    }
    return [pscustomobject]@{
        status = $status
        coverage = $coverage
        records = @($recordRows)
        items = @($recordRows)
        artifacts = @($artifactRows)
        artifactCount = $artifactRows.Count
        registeredArtifactCount = $registeredCount
        hashedArtifactCount = @($artifactRows | Where-Object { $_.hashed }).Count
        unhashedArtifactCount = $unhashedCount
        recordCount = $recordRows.Count
        linkableRecordCount = $linkableCount
        byId = $byId
        errors = @($errors | Select-Object -Unique)
        reasons = @($errors | Select-Object -Unique)
    }
}

function Get-WpdReportEvidenceFromFinding {
    param([AllowNull()][object]$Finding)

    $evidence = Get-WpdReportProperty -InputObject $Finding -Name 'evidence'
    if ($null -eq $evidence) {
        return @()
    }
    return @($evidence | Where-Object { $null -ne $_ })
}

function Test-WpdEvidenceLinks {
    param(
        [AllowNull()][object[]]$Findings = @(),
        [AllowNull()][object]$EvidenceIndex
    )

    $records = @(Get-WpdReportIndexRecords -EvidenceIndex $EvidenceIndex)
    $byId = @{}
    foreach ($record in $records) {
        $id = [string](Get-WpdReportProperty -InputObject $record -Name 'id')
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $byId[$id] = $record
        }
    }
    $missingEvidence = @()
    $unregisteredArtifacts = @()
    $invalidFindings = @()
    $causeMissingEvidence = @()
    $errors = @()
    $checked = 0
    foreach ($finding in (ConvertTo-WpdReportArray -Value $Findings)) {
        if ($null -eq $finding) { continue }
        $findingId = [string](Get-WpdReportProperty -InputObject $finding -Name 'id')
        $evidenceRows = @(Get-WpdReportEvidenceFromFinding -Finding $finding)
        if ($evidenceRows.Count -eq 0) {
            $invalidFindings += $findingId
            $errors += ('finding-has-no-evidence:' + $findingId)
            continue
        }
        foreach ($evidence in $evidenceRows) {
            $checked++
            $evidenceId = if ($evidence -is [string]) { [string]$evidence } else { [string](Get-WpdReportProperty -InputObject $evidence -Name 'id') }
            if ([string]::IsNullOrWhiteSpace($evidenceId) -or -not $byId.ContainsKey($evidenceId)) {
                if (-not [string]::IsNullOrWhiteSpace($evidenceId)) {
                    $missingEvidence += $evidenceId
                }
                else {
                    $missingEvidence += '<missing-id>'
                }
                continue
            }
            $record = $byId[$evidenceId]
            $linkable = Get-WpdReportProperty -InputObject $record -Name 'linkable'
            if ($null -eq $linkable) {
                $linkable = [bool](Get-WpdReportProperty -InputObject $record -Name 'artifactRegistered') -and [bool](Get-WpdReportProperty -InputObject $record -Name 'hashed')
            }
            if (-not [bool]$linkable) {
                $path = [string](Get-WpdReportFirstProperty -InputObject $record -Names @('path', 'artifact') -Default '')
                $unregisteredArtifacts += $path
            }
        }
        $causeRows = Get-WpdReportFirstProperty -InputObject $finding -Names @('possibleCauses', 'causes') -Default @()
        foreach ($cause in (ConvertTo-WpdReportArray -Value $causeRows)) {
            if ($null -eq $cause) { continue }
            $causeIds = @(Get-WpdReportProperty -InputObject $cause -Name 'evidenceIds' -Default @())
            if ($causeIds.Count -eq 0) {
                $causeMissingEvidence += '<missing-id>'
                continue
            }
            foreach ($causeIdValue in $causeIds) {
                $causeId = [string]$causeIdValue
                $checked++
                if ([string]::IsNullOrWhiteSpace($causeId) -or -not $byId.ContainsKey($causeId)) {
                    if ([string]::IsNullOrWhiteSpace($causeId)) { $causeMissingEvidence += '<missing-id>' } else { $causeMissingEvidence += $causeId }
                    continue
                }
                $causeRecord = $byId[$causeId]
                $causeLinkable = Get-WpdReportProperty -InputObject $causeRecord -Name 'linkable'
                if ($null -eq $causeLinkable) {
                    $causeLinkable = [bool](Get-WpdReportProperty -InputObject $causeRecord -Name 'artifactRegistered') -and [bool](Get-WpdReportProperty -InputObject $causeRecord -Name 'hashed')
                }
                if (-not [bool]$causeLinkable) {
                    $causePath = [string](Get-WpdReportFirstProperty -InputObject $causeRecord -Names @('path', 'artifact') -Default '')
                    $unregisteredArtifacts += $causePath
                }
            }
        }
    }
    $missingEvidence = @($missingEvidence | Select-Object -Unique)
    $causeMissingEvidence = @($causeMissingEvidence | Select-Object -Unique)
    $unregisteredArtifacts = @($unregisteredArtifacts | Select-Object -Unique)
    $invalidFindings = @($invalidFindings | Select-Object -Unique)
    if ($missingEvidence.Count -gt 0) {
        foreach ($id in $missingEvidence) { $errors += ('missing-evidence:' + $id) }
    }
    if ($unregisteredArtifacts.Count -gt 0) {
        foreach ($path in $unregisteredArtifacts) { $errors += ('unregistered-artifact:' + $path) }
    }
    if ($causeMissingEvidence.Count -gt 0) {
        foreach ($id in $causeMissingEvidence) { $errors += ('missing-cause-evidence:' + $id) }
    }
    return [pscustomobject]@{
        valid = ($missingEvidence.Count -eq 0 -and $unregisteredArtifacts.Count -eq 0 -and $invalidFindings.Count -eq 0 -and $causeMissingEvidence.Count -eq 0)
        status = if ($missingEvidence.Count -eq 0 -and $unregisteredArtifacts.Count -eq 0 -and $invalidFindings.Count -eq 0 -and $causeMissingEvidence.Count -eq 0) { 'success' } else { 'partial' }
        checkedCount = $checked
        findingCount = @(ConvertTo-WpdReportArray -Value $Findings).Count
        missingEvidenceIds = $missingEvidence
        unregisteredArtifacts = $unregisteredArtifacts
        causeMissingEvidenceIds = $causeMissingEvidence
        invalidFindings = $invalidFindings
        errors = @($errors | Select-Object -Unique)
    }
}

function Validate-WpdEvidenceLinks {
    param(
        [AllowNull()][object[]]$Findings = @(),
        [AllowNull()][object]$EvidenceIndex
    )

    return Test-WpdEvidenceLinks -Findings $Findings -EvidenceIndex $EvidenceIndex
}

function Assert-WpdEvidenceLinks {
    param(
        [AllowNull()][object[]]$Findings = @(),
        [AllowNull()][object]$EvidenceIndex
    )

    $result = Test-WpdEvidenceLinks -Findings $Findings -EvidenceIndex $EvidenceIndex
    if (-not $result.valid) {
        throw ('Evidence link validation failed: ' + (@($result.errors) -join '; '))
    }
    return $result
}

function New-WpdDataQualityRecord {
    param(
        [Alias('Name')][AllowEmptyString()][string]$Collector,
        [AllowEmptyString()][string]$Status = 'unavailable',
        [AllowEmptyString()][string]$Coverage,
        [int]$ExpectedSamples = 0,
        [int]$ObservedSamples = 0,
        [int]$GapCount = 0,
        [int]$DroppedCount = 0,
        [AllowNull()][object]$DurationSeconds,
        [int]$MinimumSamples = 1,
        [double]$MinimumDurationSeconds = 0,
        [AllowNull()][object[]]$Reasons = @(),
        [AllowNull()][object[]]$Warnings = @(),
        [AllowNull()][object[]]$Errors = @(),
        [AllowEmptyString()][string]$SourceArtifact
    )

    $expected = [math]::Max(0, $ExpectedSamples)
    $observed = [math]::Max(0, $ObservedSamples)
    $gaps = [math]::Max(0, $GapCount)
    $dropped = [math]::Max(0, $DroppedCount)
    $missing = [math]::Max(0, $expected - $observed)
    $coverageValue = Get-WpdReportCoverage -Status $Status -Coverage $Coverage -ObservedSamples $observed -ExpectedSamples $expected
    $qualityReasons = @()
    $qualityReasons += @(ConvertTo-WpdReportArray -Value $Reasons)
    if ($observed -eq 0) { $qualityReasons += 'no-measurements' }
    if ($missing -gt 0 -or $gaps -gt 0 -or $dropped -gt 0) { $qualityReasons += 'sample-gap' }
    if ($observed -lt [math]::Max(1, $MinimumSamples)) { $qualityReasons += 'insufficient-samples' }
    $durationValue = ConvertTo-WpdReportFiniteNumber -Value $DurationSeconds
    if ($MinimumDurationSeconds -gt 0 -and ($null -eq $durationValue -or $durationValue -lt $MinimumDurationSeconds)) {
        $qualityReasons += 'insufficient-duration'
    }
    $usable = ($observed -gt 0 -and ($coverageValue -eq 'complete' -or $coverageValue -eq 'partial'))
    $sufficient = ($usable -and $observed -ge [math]::Max(1, $MinimumSamples))
    if ($MinimumDurationSeconds -gt 0) {
        $sufficient = ($sufficient -and $null -ne $durationValue -and $durationValue -ge $MinimumDurationSeconds)
    }
    return [pscustomobject]@{
        collector = $Collector
        status = Get-WpdReportStatusForCoverage -Coverage $coverageValue
        coverage = $coverageValue
        expectedSamples = $expected
        observedSamples = $observed
        sampleCount = $observed
        missingSamples = $missing
        gapCount = $gaps
        droppedCount = $dropped
        durationSeconds = $durationValue
        isUsable = [bool]$usable
        usable = [bool]$usable
        sufficient = [bool]$sufficient
        minimumSamples = [math]::Max(1, $MinimumSamples)
        minimumDurationSeconds = $MinimumDurationSeconds
        sourceArtifact = $SourceArtifact
        reasons = @($qualityReasons | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
        warnings = @(ConvertTo-WpdReportArray -Value $Warnings)
        errors = @(ConvertTo-WpdReportArray -Value $Errors)
    }
}

function Get-WpdDataQualitySummary {
    param([AllowNull()][object[]]$Records = @())

    $items = @(ConvertTo-WpdReportArray -Value $Records | Where-Object { $null -ne $_ })
    $complete = 0
    $partial = 0
    $unavailable = 0
    $notCollected = 0
    $unsupported = 0
    $usable = 0
    $sufficient = 0
    $reasons = @()
    $warnings = @()
    $errors = @()
    foreach ($record in $items) {
        $coverage = [string](Get-WpdReportProperty -InputObject $record -Name 'coverage')
        if ([string]::IsNullOrWhiteSpace($coverage)) {
            $coverage = Get-WpdReportCoverage `
                -Status ([string](Get-WpdReportProperty -InputObject $record -Name 'status')) `
                -Coverage '' `
                -ObservedSamples (Get-WpdReportFirstProperty -InputObject $record -Names @('observedSamples', 'sampleCount', 'recordCount') -Default 0) `
                -ExpectedSamples (Get-WpdReportProperty -InputObject $record -Name 'expectedSamples')
        }
        switch ($coverage) {
            'complete' { $complete++ }
            'partial' { $partial++ }
            'not-collected' { $notCollected++ }
            'unsupported' { $unsupported++ }
            default { $unavailable++ }
        }
        $isUsable = Get-WpdReportProperty -InputObject $record -Name 'isUsable'
        if ($null -eq $isUsable) { $isUsable = Get-WpdReportProperty -InputObject $record -Name 'usable' }
        if ($null -eq $isUsable) { $isUsable = ($coverage -eq 'complete' -or $coverage -eq 'partial') }
        if ([bool]$isUsable) { $usable++ }
        if ([bool](Get-WpdReportProperty -InputObject $record -Name 'sufficient')) { $sufficient++ }
        $reasons += @(Get-WpdReportProperty -InputObject $record -Name 'reasons' -Default @())
        $warnings += @(Get-WpdReportProperty -InputObject $record -Name 'warnings' -Default @())
        $errors += @(Get-WpdReportProperty -InputObject $record -Name 'errors' -Default @())
    }
    $coverageOverall = 'unavailable'
    if ($items.Count -gt 0 -and $unavailable -eq 0 -and $notCollected -eq 0 -and $unsupported -eq 0 -and $partial -eq 0) {
        $coverageOverall = 'complete'
    }
    elseif ($complete -gt 0 -or $partial -gt 0) {
        $coverageOverall = 'partial'
    }
    elseif ($items.Count -gt 0 -and $unsupported -eq $items.Count) {
        $coverageOverall = 'unsupported'
    }
    elseif ($items.Count -gt 0 -and $notCollected -eq $items.Count) {
        $coverageOverall = 'not-collected'
    }
    $statusOverall = Get-WpdReportStatusForCoverage -Coverage $coverageOverall
    return [pscustomobject]@{
        status = $statusOverall
        coverage = $coverageOverall
        totalCollectors = $items.Count
        completeCount = $complete
        partialCount = $partial
        unavailableCount = $unavailable
        notCollectedCount = $notCollected
        unsupportedCount = $unsupported
        usableCollectorCount = $usable
        sufficientCollectorCount = $sufficient
        sufficient = ($items.Count -gt 0 -and $sufficient -eq $items.Count)
        records = @($items)
        reasons = @($reasons | Where-Object { $null -ne $_ } | Select-Object -Unique)
        warnings = @($warnings | Where-Object { $null -ne $_ })
        errors = @($errors | Where-Object { $null -ne $_ })
    }
}

function New-WpdDataQualitySummary {
    param([AllowNull()][object[]]$Records = @())

    return Get-WpdDataQualitySummary -Records $Records
}

function ConvertTo-WpdFindingEvidence {
    param([AllowNull()][object]$Evidence)

    if ($Evidence -is [string]) {
        return [pscustomobject]@{ id = [string]$Evidence }
    }
    $id = [string](Get-WpdReportProperty -InputObject $Evidence -Name 'id')
    return [pscustomobject]@{
        id = $id
        artifact = Get-WpdReportFirstProperty -InputObject $Evidence -Names @('artifact', 'sourceArtifact')
        path = Get-WpdReportFirstProperty -InputObject $Evidence -Names @('path', 'evidencePath')
        metric = Get-WpdReportProperty -InputObject $Evidence -Name 'metric'
        value = Get-WpdReportProperty -InputObject $Evidence -Name 'value'
        windowStart = Get-WpdReportFirstProperty -InputObject $Evidence -Names @('windowStart', 'windowStartUtc')
        windowEnd = Get-WpdReportFirstProperty -InputObject $Evidence -Names @('windowEnd', 'windowEndUtc')
        quality = Get-WpdReportFirstProperty -InputObject $Evidence -Names @('quality', 'coverage')
    }
}

function ConvertTo-WpdFindingRule {
    param([AllowNull()][object]$Rule)

    if ($null -eq $Rule) {
        return $null
    }
    return [pscustomobject]@{
        id = Get-WpdReportFirstProperty -InputObject $Rule -Names @('id', 'Id')
        threshold = Get-WpdReportProperty -InputObject $Rule -Name 'threshold'
        minimumSamples = Get-WpdReportFirstProperty -InputObject $Rule -Names @('minimumSamples', 'MinimumSamples')
        minimumDurationSeconds = Get-WpdReportFirstProperty -InputObject $Rule -Names @('minimumDurationSeconds', 'MinimumDurationSeconds')
        comparator = Get-WpdReportProperty -InputObject $Rule -Name 'comparator'
        thresholdBasis = Get-WpdReportProperty -InputObject $Rule -Name 'thresholdBasis'
    }
}

function ConvertTo-WpdFindingIncident {
    param([AllowNull()][object]$Incident)

    if ($null -eq $Incident) {
        return $null
    }
    $start = ConvertTo-WpdReportTimestamp -Value (Get-WpdReportFirstProperty -InputObject $Incident -Names @('windowStart', 'windowStartUtc', 'startUtc'))
    $end = ConvertTo-WpdReportTimestamp -Value (Get-WpdReportFirstProperty -InputObject $Incident -Names @('windowEnd', 'windowEndUtc', 'endUtc'))
    return [pscustomobject]@{
        id = Get-WpdReportFirstProperty -InputObject $Incident -Names @('id', 'incidentId')
        windowStart = $start
        windowEnd = $end
        markerUtc = ConvertTo-WpdReportTimestamp -Value (Get-WpdReportFirstProperty -InputObject $Incident -Names @('markerUtc', 'markerObservedAtUtc'))
        source = Get-WpdReportProperty -InputObject $Incident -Name 'source'
    }
}

function ConvertTo-WpdFindingCause {
    param(
        [AllowNull()][object]$Cause,
        [string[]]$EvidenceIds
    )

    if ($Cause -is [string]) {
        return [pscustomobject]@{ cause = [string]$Cause; evidenceIds = @($EvidenceIds) }
    }
    $ids = @(Get-WpdReportProperty -InputObject $Cause -Name 'evidenceIds' -Default @())
    if ($ids.Count -eq 0) { $ids = @($EvidenceIds) }
    return [pscustomobject]@{
        cause = Get-WpdReportFirstProperty -InputObject $Cause -Names @('cause', 'Cause', 'name', 'Name')
        evidenceIds = @($ids)
    }
}

function ConvertTo-WpdFindingCorrelation {
    param([AllowNull()][object]$Correlation)

    if ($Correlation -is [string]) {
        return [pscustomobject]@{ with = [string]$Correlation; kind = 'related'; note = 'Correlation is not causation.' }
    }
    return [pscustomobject]@{
        with = Get-WpdReportFirstProperty -InputObject $Correlation -Names @('with', 'With', 'metric', 'Metric')
        kind = Get-WpdReportFirstProperty -InputObject $Correlation -Names @('kind', 'Kind') -Default 'related'
        note = Get-WpdReportFirstProperty -InputObject $Correlation -Names @('note', 'Note') -Default 'Correlation is not causation.'
    }
}

function New-WpdFinding {
    param(
        [AllowEmptyString()][string]$Id,
        [AllowEmptyString()][string]$Category = 'coverage',
        [AllowEmptyString()][string]$Severity = 'informational',
        [AllowEmptyString()][string]$Confidence = 'Low',
        [AllowNull()][string]$Title,
        [AllowNull()][string]$Summary,
        [AllowNull()][object]$Incident,
        [AllowNull()][object[]]$Evidence = @(),
        [AllowNull()][object]$EvidenceIndex,
        [AllowNull()][object[]]$Correlations = @(),
        [AllowNull()][object[]]$PossibleCauses = @(),
        [AllowNull()][object[]]$NextSteps = @(),
        [AllowNull()][object[]]$Limitations = @(),
        [AllowNull()][object]$Rule,
        [AllowEmptyString()][string]$SourceArtifact,
        [AllowEmptyString()][string]$Metric,
        [AllowNull()][object]$WindowStart,
        [AllowNull()][object]$WindowEnd,
        [AllowNull()][object]$MeasuredValues,
        [AllowNull()][object]$SymbolsAvailable,
        [AllowNull()][string]$RuleCondition,
        [AllowNull()][string]$Uncertainty,
        [AllowNull()][string]$SuggestedWprProfile,
        [AllowNull()][string]$SeverityReason,
        [AllowNull()][string]$ConfidenceReason,
        [AllowNull()][object]$Status
    )

    if ([string]::IsNullOrWhiteSpace($Category)) { $Category = 'coverage' }
    $knownCategory = ($script:WpdReportCategories -contains $Category)
    if ($script:WpdReportSeverities -notcontains $Severity.ToLowerInvariant()) {
        $Severity = 'informational'
    }
    else {
        $Severity = $Severity.ToLowerInvariant()
    }
    if ($script:WpdReportConfidences -notcontains $Confidence) {
        $Confidence = 'Low'
    }
    if ([string]::IsNullOrWhiteSpace($Id)) {
        $safeCategory = ($Category -replace '[^A-Za-z0-9_-]', '-')
        $safeMetric = ($Metric -replace '[^A-Za-z0-9_-]', '-')
        $Id = 'finding-' + $safeCategory + '-' + $safeMetric
    }
    $evidenceRows = @()
    foreach ($evidenceValue in (ConvertTo-WpdReportArray -Value $Evidence)) {
        if ($null -eq $evidenceValue) { continue }
        $evidenceRows += (ConvertTo-WpdFindingEvidence -Evidence $evidenceValue)
    }
    $evidenceIds = @($evidenceRows | ForEach-Object { [string]$_.id } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    $incidentValue = ConvertTo-WpdFindingIncident -Incident $Incident
    if ($null -eq $incidentValue) {
        $incidentValue = $null
    }
    if ([string]::IsNullOrWhiteSpace($SourceArtifact) -and $evidenceRows.Count -gt 0) {
        $SourceArtifact = [string](Get-WpdReportProperty -InputObject $evidenceRows[0] -Name 'artifact')
    }
    if ([string]::IsNullOrWhiteSpace($Metric) -and $evidenceRows.Count -gt 0) {
        $Metric = [string](Get-WpdReportProperty -InputObject $evidenceRows[0] -Name 'metric')
    }
    $startText = ConvertTo-WpdReportTimestamp -Value $WindowStart
    $endText = ConvertTo-WpdReportTimestamp -Value $WindowEnd
    if ($null -eq $startText -and $null -ne $incidentValue) { $startText = $incidentValue.windowStart }
    if ($null -eq $endText -and $null -ne $incidentValue) { $endText = $incidentValue.windowEnd }
    if ($null -eq $startText -and $evidenceRows.Count -gt 0) { $startText = Get-WpdReportProperty -InputObject $evidenceRows[0] -Name 'windowStart' }
    if ($null -eq $endText -and $evidenceRows.Count -gt 0) { $endText = Get-WpdReportProperty -InputObject $evidenceRows[0] -Name 'windowEnd' }
    if ($null -eq $Title -or [string]::IsNullOrWhiteSpace([string]$Title)) {
        $Title = Get-WpdReportCategoryTitle -Category $Category
    }
    if ($null -eq $Summary -or [string]::IsNullOrWhiteSpace([string]$Summary)) {
        $Summary = [string]$Title
    }
    $next = @(ConvertTo-WpdReportArray -Value $NextSteps)
    $limits = @(ConvertTo-WpdReportArray -Value $Limitations)
    if ($null -eq $Uncertainty -or [string]::IsNullOrWhiteSpace([string]$Uncertainty)) {
        if ($limits.Count -gt 0) { $Uncertainty = [string]$limits[0] } else { $Uncertainty = 'Evidence is limited; correlation is not causation.' }
    }
    if ($limits.Count -eq 0) { $limits = @([string]$Uncertainty) }
    $symbolState = $SymbolsAvailable
    if ($null -eq $symbolState) {
        $symbolState = Get-WpdReportFirstProperty -InputObject $MeasuredValues `
            -Names @('symbolsAvailable', 'SymbolsAvailable', 'hasSymbols', 'HasSymbols', 'symbolStatus', 'SymbolStatus')
    }
    if ($null -ne $symbolState) {
        $symbolText = ([string]$symbolState).ToLowerInvariant()
        if ($symbolText -eq 'available' -or $symbolText -eq 'present' -or $symbolText -eq 'true' -or $symbolText -eq 'yes') {
            $symbolState = $true
        }
        elseif ($symbolText -eq 'missing' -or $symbolText -eq 'unavailable' -or $symbolText -eq 'unsupported' -or $symbolText -eq 'false' -or $symbolText -eq 'no') {
            $symbolState = $false
        }
        else {
            $symbolState = [bool]$symbolState
        }
    }
    if ($Category -match '(?i)^(ui-responsiveness|ui-hang|ui-stutter)$' -and $symbolState -ne $true) {
        if (-not (@($limits) | ForEach-Object { [string]$_ } | Where-Object { $_ -match '(?i)cannot attribute without symbols' })) {
            $limits += 'Cannot attribute without symbols.'
        }
    }
    $correlationRows = @()
    foreach ($correlation in (ConvertTo-WpdReportArray -Value $Correlations)) {
        if ($null -ne $correlation) { $correlationRows += (ConvertTo-WpdFindingCorrelation -Correlation $correlation) }
    }
    $causeRows = @()
    foreach ($cause in (ConvertTo-WpdReportArray -Value $PossibleCauses)) {
        if ($null -eq $cause) { continue }
        $causeRow = ConvertTo-WpdFindingCause -Cause $cause -EvidenceIds $evidenceIds
        if (-not [string]::IsNullOrWhiteSpace([string]$causeRow.cause)) {
            $causeRows += $causeRow
        }
    }
    $measured = if ($null -eq $MeasuredValues) { [ordered]@{} } else { $MeasuredValues }
    $ruleValue = ConvertTo-WpdFindingRule -Rule $Rule
    $validation = $null
    if ($null -ne $EvidenceIndex) {
        $validation = Test-WpdEvidenceLinks -Findings @([pscustomobject]@{ id = $Id; evidence = $evidenceRows; possibleCauses = $causeRows }) -EvidenceIndex $EvidenceIndex
    }
    $findingStatus = if ($evidenceRows.Count -gt 0) { 'finding' } else { 'coverage' }
    if ($null -ne $Status -and -not [string]::IsNullOrWhiteSpace([string]$Status)) {
        $findingStatus = [string]$Status
    }
    return [pscustomobject]@{
        id = $Id
        category = $Category
        categoryKnown = [bool]$knownCategory
        severity = $Severity
        severityReason = $SeverityReason
        confidence = $Confidence
        confidenceReason = $ConfidenceReason
        title = [string]$Title
        summary = [string]$Summary
        incident = $incidentValue
        evidence = @($evidenceRows)
        correlations = @($correlationRows)
        possibleCauses = @($causeRows)
        nextSteps = @($next)
        limitations = @($limits)
        rule = $ruleValue
        validation = $validation
        findingStatus = $findingStatus
        sourceArtifact = $SourceArtifact
        metric = $Metric
        windowStart = $startText
        windowEnd = $endText
        measuredValues = $measured
        symbolsAvailable = $symbolState
        ruleCondition = $RuleCondition
        uncertainty = $Uncertainty
        suggestedWprProfile = $SuggestedWprProfile
    }
}

function Get-WpdRuleField {
    param(
        [AllowNull()][object]$Rule,
        [string]$Name,
        [AllowNull()][object]$Default
    )

    return Get-WpdReportProperty -InputObject $Rule -Name $Name -Default $Default
}

function Get-WpdRuleDefaultSeverity {
    param([AllowNull()][object]$Rule)

    $severity = Get-WpdRuleField -Rule $Rule -Name 'severity' -Default $null
    if ($severity -is [string]) { return [string]$severity }
    return [string](Get-WpdReportFirstProperty -InputObject $severity -Names @('default', 'Default') -Default 'informational')
}

function Get-WpdRuleDefaultConfidence {
    param([AllowNull()][object]$Rule)

    $confidence = Get-WpdRuleField -Rule $Rule -Name 'confidence' -Default $null
    if ($confidence -is [string]) { return [string]$confidence }
    return [string](Get-WpdReportFirstProperty -InputObject $confidence -Names @('default', 'Default') -Default 'Low')
}

function Get-WpdRuleSeverityForRun {
    param(
        [AllowNull()][object]$Rule,
        [AllowNull()][object]$Run,
        [AllowEmptyString()][string]$Metric
    )

    $default = (Get-WpdRuleDefaultSeverity -Rule $Rule).ToLowerInvariant()
    if ($script:WpdReportSeverities -notcontains $default) { $default = 'informational' }
    $selected = $default
    $selectedReason = $null
    $severitySpec = Get-WpdRuleField -Rule $Rule -Name 'severity' -Default $null
    $escalations = if ($severitySpec -is [string]) { @() } else { @(Get-WpdReportProperty -InputObject $severitySpec -Name 'escalations' -Default @()) }
    $rank = @{ informational = 0; low = 1; medium = 2; high = 3 }
    foreach ($escalation in $escalations) {
        if ($null -eq $escalation -or $null -eq $Run) { continue }
        $candidate = (Get-WpdReportFirstProperty -InputObject $escalation -Names @('severity', 'Severity', 'level', 'Level') -Default '').ToLowerInvariant()
        if ($script:WpdReportSeverities -notcontains $candidate) { continue }
        $meets = $true
        $minimumSamples = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportFirstProperty -InputObject $escalation -Names @('minimumSamples', 'MinimumSamples', 'minSamples', 'MinSamples') -Default $null)
        if ($null -ne $minimumSamples -and $Run.count -lt $minimumSamples) { $meets = $false }
        $peakThreshold = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportFirstProperty -InputObject $escalation -Names @('peakThreshold', 'PeakThreshold', 'minimumPeak', 'MinimumPeak') -Default $null)
        if ($null -ne $peakThreshold -and $Run.peak -lt $peakThreshold) { $meets = $false }
        $durationThreshold = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportFirstProperty -InputObject $escalation -Names @('minimumDurationSeconds', 'MinimumDurationSeconds', 'minDurationSeconds', 'MinDurationSeconds') -Default $null)
        if ($null -ne $durationThreshold -and $Run.durationSeconds -lt $durationThreshold) { $meets = $false }
        $when = [string](Get-WpdReportFirstProperty -InputObject $escalation -Names @('when', 'When', 'condition', 'Condition') -Default '')
        if ($when -match '(?i)at\s+or\s+above\s+([0-9]+(?:\.[0-9]+)?)\s*percent') {
            $proseThreshold = [double]$Matches[1]
            if ($Run.peak -lt $proseThreshold) { $meets = $false }
        }
        if ($when -match '(?i)at\s+least\s+([0-9]+(?:\.[0-9]+)?)\s+consecutive\s+samples') {
            if ($Run.count -lt [double]$Matches[1]) { $meets = $false }
        }
        if ($when -match '(?i)at\s+least\s+([0-9]+(?:\.[0-9]+)?)\s+seconds') {
            if ($Run.durationSeconds -lt [double]$Matches[1]) { $meets = $false }
        }
        if ($when -match '(?i)at\s+or\s+above\s+([0-9]+(?:\.[0-9]+)?)\s*ms') {
            $proseThreshold = [double]$Matches[1] / 1000.0
            if ($Metric -match '(?i)latency|duration|seconds' -and $Run.peak -lt $proseThreshold) { $meets = $false }
        }
        if ($meets -and $rank[$candidate] -gt $rank[$selected]) {
            $selected = $candidate
            $selectedReason = if ([string]::IsNullOrWhiteSpace($when)) { 'explicit escalation condition met' } else { $when }
        }
    }
    return [pscustomobject]@{ severity = $selected; reason = $selectedReason }
}

function Get-WpdRuleConfidenceForRun {
    param(
        [AllowNull()][object]$Rule,
        [AllowNull()][object]$Run,
        [AllowNull()][object[]]$Correlations
    )

    $confidence = Get-WpdRuleDefaultConfidence -Rule $Rule
    if ($script:WpdReportConfidences -notcontains $confidence) { $confidence = 'Low' }
    $correlationRows = @(ConvertTo-WpdReportArray -Value $Correlations)
    $confidenceSpec = Get-WpdRuleField -Rule $Rule -Name 'confidence' -Default $null
    $conditions = if ($confidenceSpec -is [string]) { @() } else { @(Get-WpdReportProperty -InputObject $confidenceSpec -Name 'conditions' -Default @()) }
    $rank = @{ Low = 0; Medium = 1; High = 2 }
    $selectedReason = $null
    foreach ($condition in $conditions) {
        if ($null -eq $condition -or $null -eq $Run) { continue }
        $candidate = [string](Get-WpdReportFirstProperty -InputObject $condition -Names @('level', 'Level', 'confidence', 'Confidence') -Default '')
        if ($script:WpdReportConfidences -notcontains $candidate) { continue }
        $minimumSamples = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportFirstProperty -InputObject $condition -Names @('minimumSamples', 'MinimumSamples', 'minSamples', 'MinSamples') -Default $null)
        $minimumCorrelations = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportFirstProperty -InputObject $condition -Names @('minimumCorrelations', 'MinimumCorrelations', 'minimumIndependentEvidence', 'MinimumIndependentEvidence') -Default $null)
        $meets = $true
        if ($null -ne $minimumSamples -and $Run.count -lt $minimumSamples) { $meets = $false }
        if ($null -ne $minimumCorrelations -and $correlationRows.Count -lt $minimumCorrelations) { $meets = $false }
        if ($meets -and $rank[$candidate] -gt $rank[$confidence]) {
            $confidence = $candidate
            $selectedReason = [string](Get-WpdReportFirstProperty -InputObject $condition -Names @('when', 'When', 'reason', 'Reason') -Default '')
        }
    }
    if ($correlationRows.Count -gt 0 -and $confidence -eq 'Low') {
        $confidence = 'Medium'
        if ([string]::IsNullOrWhiteSpace($selectedReason)) { $selectedReason = 'an independent correlation was measured in the same window' }
    }
    return [pscustomobject]@{ confidence = $confidence; reason = $selectedReason }
}

function Get-WpdReportSampleTimestamp {
    param([AllowNull()][object]$Sample)

    return ConvertTo-WpdReportUtcDateTime -Value (Get-WpdReportFirstProperty -InputObject $Sample -Names @('TimestampUtc', 'timestampUtc', 'Timestamp', 'TimeCreated', 'timeCreatedUtc'))
}

function Get-WpdReportRuleValue {
    param(
        [AllowNull()][object]$Sample,
        [AllowEmptyString()][string]$Metric
    )

    $value = Get-WpdReportProperty -InputObject $Sample -Name $Metric
    if ($null -ne $value) { return ConvertTo-WpdReportFiniteNumber -Value $value }
    if ($Metric -eq 'CommitPercent') {
        $committed = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportFirstProperty -InputObject $Sample -Names @('CommittedBytes', 'committedBytes'))
        $limit = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportFirstProperty -InputObject $Sample -Names @('CommitLimitBytes', 'commitLimitBytes'))
        if ($null -ne $committed -and $null -ne $limit -and $limit -gt 0) { return ($committed / $limit) * 100.0 }
    }
    if ($Metric -eq 'AvailableMemoryMB') {
        $bytes = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportFirstProperty -InputObject $Sample -Names @('AvailableBytes', 'availableBytes'))
        if ($null -ne $bytes) { return $bytes / 1MB }
    }
    if ($Metric -eq 'PageFileUsagePercent') {
        $used = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportFirstProperty -InputObject $Sample -Names @('CurrentUsageMB', 'PagefileCurrentBytes'))
        $size = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportFirstProperty -InputObject $Sample -Names @('AllocatedBaseSizeMB', 'PagefileSizeBytes'))
        if ($null -ne $used -and $null -ne $size -and $size -gt 0) { return ($used / $size) * 100.0 }
    }
    return $null
}

function Test-WpdRuleComparison {
    param(
        [AllowNull()][object]$Value,
        [AllowEmptyString()][string]$Comparator,
        [AllowNull()][object]$Threshold
    )

    $number = ConvertTo-WpdReportFiniteNumber -Value $Value
    $limit = ConvertTo-WpdReportFiniteNumber -Value $Threshold
    if ($null -eq $number -or $null -eq $limit) { return $false }
    switch ($Comparator.ToLowerInvariant()) {
        'gt' { return ($number -gt $limit) }
        '>' { return ($number -gt $limit) }
        'ge' { return ($number -ge $limit) }
        '>=' { return ($number -ge $limit) }
        'lt' { return ($number -lt $limit) }
        '<' { return ($number -lt $limit) }
        'le' { return ($number -le $limit) }
        '<=' { return ($number -le $limit) }
        'eq' { return ($number -eq $limit) }
        default { return $false }
    }
}

function Get-WpdReportIntervalSeconds {
    param([AllowNull()][object[]]$Rows)

    $timestamps = @()
    foreach ($row in (ConvertTo-WpdReportArray -Value $Rows)) {
        $stamp = Get-WpdReportSampleTimestamp -Sample $row
        if ($null -ne $stamp) { $timestamps += $stamp }
    }
    $timestamps = @($timestamps | Sort-Object)
    if ($timestamps.Count -lt 2) {
        foreach ($row in (ConvertTo-WpdReportArray -Value $Rows)) {
            $duration = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportFirstProperty -InputObject $row -Names @('DurationSeconds', 'durationSeconds', 'ElapsedSeconds'))
            if ($null -ne $duration -and $duration -gt 0) { return $duration }
        }
        return 1.0
    }
    $gaps = @()
    for ($i = 1; $i -lt $timestamps.Count; $i++) {
        $gap = ($timestamps[$i] - $timestamps[$i - 1]).TotalSeconds
        if ($gap -gt 0) { $gaps += $gap }
    }
    if ($gaps.Count -eq 0) { return 1.0 }
    return [double](($gaps | Measure-Object -Average).Average)
}

function Test-WpdReportTrend {
    param(
        [AllowNull()][object[]]$Rows,
        [AllowNull()][object]$Run,
        [AllowEmptyString()][string]$Metric,
        [AllowNull()][object]$Trend
    )

    if ($null -eq $Trend -or $null -eq $Run) { return $true }
    $direction = [string](Get-WpdReportFirstProperty -InputObject $Trend -Names @('direction', 'Direction') -Default 'increasing')
    $minimumDelta = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportFirstProperty -InputObject $Trend -Names @('minimumDeltaPercent', 'MinimumDeltaPercent', 'minimumDelta', 'MinimumDelta') -Default 0)
    if ($null -eq $minimumDelta) { $minimumDelta = 0.0 }
    $minimumTrendSamples = 1
    try { $minimumTrendSamples = [int](Get-WpdReportFirstProperty -InputObject $Trend -Names @('minimumSamples', 'MinimumSamples') -Default 1) } catch { $minimumTrendSamples = 1 }
    $window = $Run.count
    try { $requestedWindow = [int](Get-WpdReportFirstProperty -InputObject $Trend -Names @('monotonicWindow', 'MonotonicWindow') -Default $window) } catch { $requestedWindow = $window }
    if ($requestedWindow -gt 1) { $window = [math]::Min($window, $requestedWindow) }
    $window = [math]::Max(2, $window)
    if ($Run.count -lt [math]::Max(2, $minimumTrendSamples) -or $Run.count -lt $window) { return $false }
    $items = @(ConvertTo-WpdReportArray -Value $Rows)
    $firstWindow = [int]$Run.startIndex
    $lastWindow = [int]$Run.endIndex - $window + 1
    for ($windowStart = $firstWindow; $windowStart -le $lastWindow; $windowStart++) {
        $values = @()
        $identityValues = @()
        $identityObserved = $false
        $identityComplete = $true
        for ($i = $windowStart; $i -lt ($windowStart + $window); $i++) {
            if ($i -ge $items.Count) { $identityComplete = $false; break }
            $value = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportRuleValue -Sample $items[$i] -Metric $Metric)
            if ($null -eq $value) { $identityComplete = $false; break }
            $values += $value
            $processId = Get-WpdReportFirstProperty -InputObject $items[$i] -Names @('ProcessId', 'processId', 'Pid', 'pid')
            $startTime = Get-WpdReportFirstProperty -InputObject $items[$i] -Names @('StartTimeUtc', 'startTimeUtc', 'ProcessStartTimeUtc')
            if ($null -ne $processId -or $null -ne $startTime) { $identityObserved = $true }
            if ($null -eq $processId -or $null -eq $startTime) { $identityComplete = $false }
            $identityValues += ([string]$processId + '|' + [string](ConvertTo-WpdReportTimestamp -Value $startTime))
        }
        if ($values.Count -ne $window) { continue }
        if ($identityObserved -and (-not $identityComplete -or @($identityValues | Select-Object -Unique).Count -ne 1)) { continue }
        $monotonic = $true
        for ($i = 1; $i -lt $values.Count; $i++) {
            if ($direction -match '(?i)decreas' -and $values[$i] -gt $values[$i - 1]) { $monotonic = $false; break }
            if ($direction -notmatch '(?i)decreas' -and $values[$i] -lt $values[$i - 1]) { $monotonic = $false; break }
        }
        if (-not $monotonic) { continue }
        $delta = if ($direction -match '(?i)decreas') { $values[0] - $values[$values.Count - 1] } else { $values[$values.Count - 1] - $values[0] }
        if ($delta -ge $minimumDelta) { return $true }
    }
    return $false
}

function Find-WpdSustainedRuleRun {
    param(
        [AllowNull()][object[]]$Rows,
        [AllowEmptyString()][string]$Metric,
        [AllowEmptyString()][string]$Comparator,
        [AllowNull()][object]$Threshold,
        [int]$MinimumSamples = 1,
        [double]$MinimumDurationSeconds = 0,
        [AllowNull()][object]$Trend
    )

    $items = @(ConvertTo-WpdReportArray -Value $Rows)
    $items = @($items | Sort-Object -Property @{ Expression = {
        $stamp = Get-WpdReportSampleTimestamp -Sample $_
        if ($null -eq $stamp) { return [datetime]::MaxValue }
        return $stamp
    } })
    $minimum = [math]::Max(1, $MinimumSamples)
    $interval = Get-WpdReportIntervalSeconds -Rows $items
    $best = $null
    $runStart = $null
    $runValues = @()
    for ($i = 0; $i -lt $items.Count; $i++) {
        $value = Get-WpdReportRuleValue -Sample $items[$i] -Metric $Metric
        $meets = Test-WpdRuleComparison -Value $value -Comparator $Comparator -Threshold $Threshold
        if ($meets) {
            if ($null -eq $runStart) { $runStart = $i; $runValues = @() }
            $runValues += $value
        }
        else {
            if ($null -ne $runStart) {
                $runEnd = $i - 1
                $count = $runEnd - $runStart + 1
                $duration = $count * $interval
                $firstTime = Get-WpdReportSampleTimestamp -Sample $items[$runStart]
                $lastTime = Get-WpdReportSampleTimestamp -Sample $items[$runEnd]
                if ($null -ne $firstTime -and $null -ne $lastTime) {
                    $duration = [double](($lastTime - $firstTime).TotalSeconds + $interval)
                }
                if ($count -ge $minimum -and ($MinimumDurationSeconds -le 0 -or $duration -ge $MinimumDurationSeconds)) {
                    if ($null -eq $best -or $count -gt $best.count) {
                        $best = [pscustomobject]@{
                            startIndex = $runStart
                            endIndex = $runEnd
                            count = $count
                            durationSeconds = $duration
                            peak = [double](($runValues | Measure-Object -Maximum).Maximum)
                            values = @($runValues)
                            windowStart = ConvertTo-WpdReportTimestamp -Value $firstTime
                            windowEnd = ConvertTo-WpdReportTimestamp -Value $lastTime
                        }
                    }
                }
                $runStart = $null
                $runValues = @()
            }
        }
    }
    if ($null -ne $runStart) {
        $runEnd = $items.Count - 1
        $count = $runEnd - $runStart + 1
        $duration = $count * $interval
        $firstTime = Get-WpdReportSampleTimestamp -Sample $items[$runStart]
        $lastTime = Get-WpdReportSampleTimestamp -Sample $items[$runEnd]
        if ($null -ne $firstTime -and $null -ne $lastTime) {
            $duration = [double](($lastTime - $firstTime).TotalSeconds + $interval)
        }
        if ($count -ge $minimum -and ($MinimumDurationSeconds -le 0 -or $duration -ge $MinimumDurationSeconds)) {
            if ($null -eq $best -or $count -gt $best.count) {
                $best = [pscustomobject]@{
                    startIndex = $runStart
                    endIndex = $runEnd
                    count = $count
                    durationSeconds = $duration
                    peak = [double](($runValues | Measure-Object -Maximum).Maximum)
                    values = @($runValues)
                    windowStart = ConvertTo-WpdReportTimestamp -Value $firstTime
                    windowEnd = ConvertTo-WpdReportTimestamp -Value $lastTime
                }
            }
        }
    }
    if ($null -eq $best) { return $null }
    if (-not (Test-WpdReportTrend -Rows $items -Run $best -Metric $Metric -Trend $Trend)) { return $null }
    return $best
}

function Get-WpdRuleCorrelationMatches {
    param(
        [AllowNull()][object[]]$Rows,
        [AllowNull()][object]$Run,
        [AllowNull()][object[]]$Requirements
    )

    $matches = @()
    $items = @(ConvertTo-WpdReportArray -Value $Rows)
    if ($null -eq $Run) { return $matches }
    foreach ($requirement in (ConvertTo-WpdReportArray -Value $Requirements)) {
        if ($null -eq $requirement) { continue }
        $metric = [string](Get-WpdReportFirstProperty -InputObject $requirement -Names @('metric', 'Metric') -Default '')
        $comparator = [string](Get-WpdReportFirstProperty -InputObject $requirement -Names @('comparator', 'Comparator') -Default 'ge')
        $threshold = Get-WpdReportFirstProperty -InputObject $requirement -Names @('threshold', 'Threshold')
        $found = $null
        $startIndex = [int]$Run.startIndex
        $endIndex = [int]$Run.endIndex
        for ($i = $startIndex; $i -le $endIndex -and $i -lt $items.Count; $i++) {
            $value = Get-WpdReportRuleValue -Sample $items[$i] -Metric $metric
            if (Test-WpdRuleComparison -Value $value -Comparator $comparator -Threshold $threshold) {
                $found = $value
                break
            }
        }
        if ($null -ne $found) {
            $matches += [pscustomobject]@{
                metric = $metric
                value = $found
                comparator = $comparator
                threshold = $threshold
                kind = Get-WpdReportProperty -InputObject $requirement -Name 'kind' -Default 'related'
                note = Get-WpdReportProperty -InputObject $requirement -Name 'note' -Default 'Correlation is not causation.'
            }
        }
    }
    return @($matches)
}

function Test-WpdReportSeriesContainsMetric {
    param(
        [AllowNull()][object[]]$Rows,
        [AllowEmptyString()][string]$Metric
    )

    foreach ($row in (ConvertTo-WpdReportArray -Value $Rows)) {
        if ($null -ne (Get-WpdReportRuleValue -Sample $row -Metric $Metric)) { return $true }
    }
    return $false
}

function Get-WpdRuleSeries {
    param(
        [AllowEmptyString()][string]$Metric,
        [AllowNull()][object]$Rule,
        [AllowNull()][object[]]$Samples,
        [AllowNull()][object[]]$DiskSeries,
        [AllowNull()][object[]]$ProcessSamples,
        [AllowNull()][object[]]$EventRows
    )

    $source = [string](Get-WpdReportProperty -InputObject $Rule -Name 'sourceArtifact')
    if ($source -match '(?i)disk' -or $Metric -match '(?i)Latency|QueueLength') {
        $diskRows = @(ConvertTo-WpdReportArray -Value $DiskSeries)
        if ($diskRows.Count -gt 0 -and (Test-WpdReportSeriesContainsMetric -Rows $diskRows -Metric $Metric)) { return $diskRows }
    }
    if ($source -match '(?i)process-memory' -or $Metric -match '(?i)WorkingSet|PoolGrowth') {
        $processRows = @(ConvertTo-WpdReportArray -Value $ProcessSamples)
        if ($processRows.Count -gt 0 -and (Test-WpdReportSeriesContainsMetric -Rows $processRows -Metric $Metric)) {
            return $processRows
        }
    }
    if ($source -match '(?i)incident-events|event' -or $Metric -match '(?i)HangEvents|Bugcheck|SignatureCount') {
        $eventRows = @(ConvertTo-WpdReportArray -Value $EventRows)
        if ($eventRows.Count -gt 0 -and (Test-WpdReportSeriesContainsMetric -Rows $eventRows -Metric $Metric)) {
            return $eventRows
        }
    }
    return @(ConvertTo-WpdReportArray -Value $Samples)
}

function Get-WpdReportGeneratedEvidence {
    param(
        [string]$Id,
        [string]$Artifact,
        [string]$Metric,
        [AllowNull()][object]$Value,
        [AllowNull()][object]$Run,
        [string]$Collector = 'analysis'
    )

    $start = if ($null -ne $Run) { $Run.windowStart } else { $null }
    $end = if ($null -ne $Run) { $Run.windowEnd } else { $null }
    return New-WpdEvidenceIndexRecord -Id $Id -Artifact $Artifact -Path $Artifact -Metric $Metric `
        -Value $Value -WindowStartUtc $start -WindowEndUtc $end -Quality 'complete' -Collector $Collector -Source 'rule'
}

function Invoke-WpdReportRuleAnalysis {
    param(
        [AllowNull()][object[]]$Samples = @(),
        [AllowNull()][object[]]$DiskSeries = @(),
        [AllowNull()][object[]]$ProcessSamples = @(),
        [AllowNull()][object[]]$EventRows = @(),
        [AllowNull()][object[]]$Rules = @()
    )

    $findings = @()
    $generatedRecords = @()
    $ruleIndex = 0
    foreach ($rule in (ConvertTo-WpdReportArray -Value $Rules)) {
        if ($null -eq $rule) { continue }
        $ruleId = [string](Get-WpdReportFirstProperty -InputObject $rule -Names @('id', 'Id') -Default ('rule-' + $ruleIndex))
        $metric = [string](Get-WpdReportFirstProperty -InputObject $rule -Names @('metric', 'Metric') -Default '')
        $sourceArtifact = [string](Get-WpdReportProperty -InputObject $rule -Name 'sourceArtifact' -Default 'performance-samples.csv')
        $comparator = [string](Get-WpdReportProperty -InputObject $rule -Name 'comparator' -Default 'ge')
        $threshold = Get-WpdReportProperty -InputObject $rule -Name 'threshold'
        $minimumSamples = 1
        try { $minimumSamples = [int](Get-WpdReportFirstProperty -InputObject $rule -Names @('minimumSamples', 'MinimumSamples') -Default 1) } catch { $minimumSamples = 1 }
        $minimumDuration = 0.0
        try { $minimumDuration = [double](Get-WpdReportFirstProperty -InputObject $rule -Names @('minimumDurationSeconds', 'MinimumDurationSeconds') -Default 0) } catch { $minimumDuration = 0.0 }
        $series = Get-WpdRuleSeries -Metric $metric -Rule $rule -Samples $Samples -DiskSeries $DiskSeries -ProcessSamples $ProcessSamples -EventRows $EventRows
        $run = Find-WpdSustainedRuleRun -Rows $series -Metric $metric -Comparator $comparator -Threshold $threshold `
            -MinimumSamples $minimumSamples -MinimumDurationSeconds $minimumDuration -Trend (Get-WpdReportProperty -InputObject $rule -Name 'trend')
        if ($null -eq $run) {
            $ruleIndex++
            continue
        }
        $requirements = @(Get-WpdReportProperty -InputObject $rule -Name 'correlationRequirements' -Default @())
        $correlations = @(Get-WpdRuleCorrelationMatches -Rows $series -Run $run -Requirements $requirements)
        $requiredAny = @($requirements | Where-Object { [string](Get-WpdReportProperty -InputObject $_ -Name 'kind' -Default '') -eq 'required-any-of' })
        $pagingRule = ($metric -match '(?i)^PagesInputPerSec$' -or $ruleId -match '(?i)paging')
        if ($requiredAny.Count -gt 0 -and $correlations.Count -eq 0) {
            # A rule that qualified its primary metric but missed a declared
            # independent channel is not a finding.  Keep the measured signal
            # as a coverage record so the technician can see why attribution was
            # withheld.  Paging has a more specific explanation because a high
            # Pages Input/sec rate must never become a Pages/sec-only conclusion.
            $evidenceId = $ruleId + ':evidence:0'
            $evidence = Get-WpdReportGeneratedEvidence -Id $evidenceId -Artifact $sourceArtifact -Metric $metric `
                -Value ([ordered]@{ peak = $run.peak; count = $run.count; durationSeconds = $run.durationSeconds }) -Run $run
            $generatedRecords += $evidence
            if ($pagingRule) {
                $coverageTitle = 'Elevated paging without measured memory pressure'
                $coverageSummary = 'Paging activity was elevated without measured memory pressure; no memory-paging conclusion is emitted from the paging rate alone.'
                $coverageUncertainty = 'Pages Input/sec is a paging volume indicator, not an exact fault count or proof of memory shortage.'
                $coverageNextSteps = @('Collect commit, available-memory and process working-set evidence over the same window.')
                $coverageLimitations = @('The paging rate alone cannot identify memory pressure or a responsible process.')
                $coverageCondition = 'The configured paging rule qualified for ' + [string]$run.count + ' samples, but no independent pressure channel qualified'
            }
            else {
                $coverageTitle = 'Required corroborating evidence was unavailable'
                $coverageSummary = 'The primary metric qualified, but no declared independent correlation qualified; the report withholds a causal finding.'
                $coverageUncertainty = 'A single metric does not establish attribution when the rule declares an independent correlation requirement.'
                $coverageNextSteps = @('Collect the required corroborating evidence over the same incident window.')
                $coverageLimitations = @('The primary metric alone cannot establish the reported condition or its cause.')
                $coverageCondition = 'The configured rule qualified for ' + [string]$run.count + ' samples, but no required independent correlation qualified'
            }
            $coverageFinding = New-WpdFinding -Id ($ruleId + ':coverage:0') -Category 'coverage' `
                -Severity 'informational' -Confidence 'Low' -Title $coverageTitle `
                -Summary $coverageSummary `
                -Evidence @($evidence) -SourceArtifact $sourceArtifact -Metric $metric `
                -WindowStart $run.windowStart -WindowEnd $run.windowEnd `
                -MeasuredValues ([ordered]@{ peak = $run.peak; consecutiveSamples = $run.count; durationSeconds = $run.durationSeconds }) `
                -RuleCondition $coverageCondition `
                -Uncertainty $coverageUncertainty `
                -NextSteps $coverageNextSteps `
                -Limitations $coverageLimitations `
                -SuggestedWprProfile (Get-WpdReportProperty -InputObject $rule -Name 'suggestedWprProfile') `
                -Rule $rule
            $findings += $coverageFinding
            $ruleIndex++
            continue
        }
        $evidenceId = $ruleId + ':evidence:0'
        $evidenceValue = [ordered]@{ peak = $run.peak; count = $run.count; durationSeconds = $run.durationSeconds }
        $evidence = Get-WpdReportGeneratedEvidence -Id $evidenceId -Artifact $sourceArtifact -Metric $metric -Value $evidenceValue -Run $run
        $generatedRecords += $evidence
        $correlationEvidence = @()
        foreach ($correlation in $correlations) {
            $correlationId = $ruleId + ':correlation:' + [string]$correlation.metric
            $correlationRecord = Get-WpdReportGeneratedEvidence -Id $correlationId -Artifact $sourceArtifact -Metric ([string]$correlation.metric) `
                -Value $correlation.value -Run $run -Collector 'correlation'
            $generatedRecords += $correlationRecord
            $correlationEvidence += $correlationRecord
        }
        $confidenceDecision = Get-WpdRuleConfidenceForRun -Rule $rule -Run $run -Correlations $correlations
        $severityDecision = Get-WpdRuleSeverityForRun -Rule $rule -Run $run -Metric $metric
        $confidence = $confidenceDecision.confidence
        $severity = $severityDecision.severity
        $finding = New-WpdFinding -Id ($ruleId + ':0') `
            -Category ([string](Get-WpdReportProperty -InputObject $rule -Name 'category' -Default 'coverage')) `
            -Severity $severity -Confidence $confidence `
            -Title (Get-WpdReportProperty -InputObject $rule -Name 'title') `
            -Summary (Get-WpdReportProperty -InputObject $rule -Name 'summary') `
            -Evidence @($evidence) + @($correlationEvidence) `
            -Correlations $correlations -SourceArtifact $sourceArtifact -Metric $metric `
            -WindowStart $run.windowStart -WindowEnd $run.windowEnd `
            -MeasuredValues $evidenceValue `
            -RuleCondition ($metric + ' ' + $comparator + ' ' + [string]$threshold + ' qualified for ' + [string]$run.count + ' consecutive samples') `
            -Uncertainty (Get-WpdReportProperty -InputObject $rule -Name 'uncertainty') `
            -NextSteps (ConvertTo-WpdReportArray -Value (Get-WpdReportProperty -InputObject $rule -Name 'nextSteps')) `
            -SuggestedWprProfile (Get-WpdReportProperty -InputObject $rule -Name 'suggestedWprProfile') `
            -SeverityReason $severityDecision.reason -ConfidenceReason $confidenceDecision.reason `
            -Rule $rule
        $findings += $finding
        $ruleIndex++
    }
    return [pscustomobject]@{
        findings = @($findings)
        evidenceRecords = @($generatedRecords)
    }
}

function Get-WpdNoEvidenceOf {
    param(
        [AllowNull()][object[]]$Candidates = @(),
        [AllowNull()][object[]]$DataQuality = @(),
        [AllowNull()][object]$EvidenceIndex
    )

    $qualityRows = @(ConvertTo-WpdReportArray -Value $DataQuality)
    $byCollector = @{}
    foreach ($quality in $qualityRows) {
        $collector = [string](Get-WpdReportProperty -InputObject $quality -Name 'collector')
        if (-not [string]::IsNullOrWhiteSpace($collector)) { $byCollector[$collector] = $quality }
    }
    $result = @()
    foreach ($candidate in (ConvertTo-WpdReportArray -Value $Candidates)) {
        if ($null -eq $candidate) { continue }
        $collector = [string](Get-WpdReportFirstProperty -InputObject $candidate -Names @('collector', 'Collector') -Default '')
        $quality = $null
        if ($byCollector.ContainsKey($collector)) { $quality = $byCollector[$collector] }
        if ($null -eq $quality) { continue }
        $minimumSamples = 1
        try { $minimumSamples = [int](Get-WpdReportFirstProperty -InputObject $candidate -Names @('minimumSamples', 'MinimumSamples') -Default 1) } catch { $minimumSamples = 1 }
        $minimumDuration = 0.0
        try { $minimumDuration = [double](Get-WpdReportFirstProperty -InputObject $candidate -Names @('minimumDurationSeconds', 'MinimumDurationSeconds') -Default 0) } catch { $minimumDuration = 0.0 }
        if (-not (Test-WpdReportQualitySufficient -Quality $quality -MinimumSamples $minimumSamples -MinimumDurationSeconds $minimumDuration)) {
            continue
        }
        $topic = [string](Get-WpdReportFirstProperty -InputObject $candidate -Names @('topic', 'Topic', 'name', 'Name') -Default 'the requested condition')
        $ids = @(Get-WpdReportProperty -InputObject $candidate -Name 'evidenceIds' -Default @())
        if ($null -ne $EvidenceIndex) {
            $candidateCheck = Test-WpdEvidenceLinks -Findings @([pscustomobject]@{ id = $topic; evidence = @($ids) }) -EvidenceIndex $EvidenceIndex
            if (-not $candidateCheck.valid) { continue }
        }
        $result += [pscustomobject]@{
            id = Get-WpdReportFirstProperty -InputObject $candidate -Names @('id', 'Id')
            collector = $collector
            topic = $topic
            text = 'No strong evidence of ' + $topic + ' was found in the measured window.'
            evidenceIds = @($ids)
            quality = $quality
        }
    }
    return @($result)
}

function Test-WpdReportSampleHasMeasurement {
    param([AllowNull()][object]$Sample)

    if ($null -eq $Sample) { return $false }
    $ignored = @(
        'timestamp', 'timestamputc', 'timecreated', 'timecreatedutc', 'starttimeutc', 'endtimeutc',
        'durationseconds', 'elapsedseconds', 'processid', 'pid', 'threadid', 'id', 'incidentid',
        'name', 'displayname', 'provider', 'source', 'artifact', 'artifactid'
    )
    foreach ($property in @($Sample.PSObject.Properties)) {
        $name = [string]$property.Name
        if ($ignored -contains $name.ToLowerInvariant()) { continue }
        if ($null -ne (ConvertTo-WpdReportFiniteNumber -Value $property.Value)) { return $true }
    }
    return $false
}

function Get-WpdReportDefaultQualityFromSamples {
    param([AllowNull()][object[]]$Samples)

    $items = @(ConvertTo-WpdReportArray -Value $Samples)
    if ($items.Count -eq 0) {
        return New-WpdDataQualityRecord -Collector 'samples' -Status 'unavailable' -ExpectedSamples 0 -ObservedSamples 0 -MinimumSamples 1
    }
    $valid = 0
    $first = $null
    $last = $null
    foreach ($sample in $items) {
        $stamp = Get-WpdReportSampleTimestamp -Sample $sample
        if ($null -eq $stamp) { continue }
        if ($null -eq $first) { $first = $stamp }
        $last = $stamp
        $hasValue = Test-WpdReportSampleHasMeasurement -Sample $sample
        if ($hasValue) { $valid++ }
    }
    $duration = $null
    if ($null -ne $first -and $null -ne $last) { $duration = [double](($last - $first).TotalSeconds + (Get-WpdReportIntervalSeconds -Rows $items)) }
    $status = if ($valid -eq $items.Count) { 'success' } elseif ($valid -gt 0) { 'partial' } else { 'unavailable' }
    return New-WpdDataQualityRecord -Collector 'samples' -Status $status -ExpectedSamples $items.Count `
        -ObservedSamples $valid -GapCount ($items.Count - $valid) -DurationSeconds $duration -MinimumSamples 1
}

function Get-WpdReportTimelineRows {
    param(
        [AllowNull()][object[]]$Timeline,
        [AllowNull()][object]$Incident
    )

    $start = $null
    $end = $null
    if ($null -ne $Incident) {
        $start = ConvertTo-WpdReportUtcDateTime -Value (Get-WpdReportFirstProperty -InputObject $Incident -Names @('windowStart', 'windowStartUtc', 'startUtc'))
        $end = ConvertTo-WpdReportUtcDateTime -Value (Get-WpdReportFirstProperty -InputObject $Incident -Names @('windowEnd', 'windowEndUtc', 'endUtc'))
    }
    $rows = @()
    foreach ($item in (ConvertTo-WpdReportArray -Value $Timeline)) {
        if ($null -eq $item) { continue }
        $stamp = Get-WpdReportSampleTimestamp -Sample $item
        $windowStatus = 'unavailable'
        if ($null -ne $stamp -and $null -ne $start -and $null -ne $end) {
            if ($stamp -ge $start -and $stamp -le $end) { $windowStatus = 'in-window' } else { $windowStatus = 'out-of-window' }
        }
        $rows += [pscustomobject]@{
            TimestampUtc = ConvertTo-WpdReportTimestamp -Value $stamp
            Source = Get-WpdReportFirstProperty -InputObject $item -Names @('Source', 'source', 'Provider', 'provider', 'LogName', 'logName')
            Event = Get-WpdReportFirstProperty -InputObject $item -Names @('Event', 'event', 'Message', 'message', 'Title', 'title', 'Id', 'id')
            Provider = Get-WpdReportFirstProperty -InputObject $item -Names @('Provider', 'provider', 'ProviderName', 'providerName')
            EventId = Get-WpdReportFirstProperty -InputObject $item -Names @('EventId', 'eventId', 'Id', 'id')
            InIncidentWindow = $windowStatus
            Raw = $item
        }
    }
    return @($rows | Sort-Object -Property TimestampUtc)
}

function Get-WpdReportProcessTables {
    param(
        [AllowNull()][object[]]$ProcessSamples,
        [AllowNull()][object]$Incident
    )

    if ($null -eq $Incident) { return @() }
    $incidentId = Get-WpdReportFirstProperty -InputObject $Incident -Names @('id', 'incidentId')
    $start = ConvertTo-WpdReportUtcDateTime -Value (Get-WpdReportFirstProperty -InputObject $Incident -Names @('windowStart', 'windowStartUtc', 'startUtc'))
    $end = ConvertTo-WpdReportUtcDateTime -Value (Get-WpdReportFirstProperty -InputObject $Incident -Names @('windowEnd', 'windowEndUtc', 'endUtc'))
    $rows = @()
    foreach ($item in (ConvertTo-WpdReportArray -Value $ProcessSamples)) {
        if ($null -eq $item) { continue }
        $stamp = Get-WpdReportSampleTimestamp -Sample $item
        if ($null -ne $start -and $null -ne $end) {
            if ($null -eq $stamp -or $stamp -lt $start -or $stamp -gt $end) { continue }
        }
        $rows += $item
    }
    $orderedRows = @($rows | Sort-Object -Property @{ Expression = { Get-WpdReportSampleTimestamp -Sample $_ } })
    return @([pscustomobject]@{
        id = if ($null -ne $incidentId) { [string]$incidentId } else { 'incident-process' }
        incidentId = $incidentId
        windowStart = ConvertTo-WpdReportTimestamp -Value $start
        windowEnd = ConvertTo-WpdReportTimestamp -Value $end
        scope = 'incident-window'
        rows = $orderedRows
    })
}

function Get-WpdReportRealFindings {
    param(
        [AllowNull()][object[]]$Findings,
        [AllowNull()][object]$EvidenceIndex
    )

    $result = @()
    foreach ($finding in (ConvertTo-WpdReportArray -Value $Findings)) {
        if ($null -eq $finding) { continue }
        $category = [string](Get-WpdReportProperty -InputObject $finding -Name 'category')
        if ($category -eq 'coverage' -or $category -eq 'evidence-coverage') { continue }
        $evidenceRows = @(Get-WpdReportEvidenceFromFinding -Finding $finding)
        if ($evidenceRows.Count -eq 0) { continue }
        if ($null -ne $EvidenceIndex) {
            $validation = Test-WpdEvidenceLinks -Findings @($finding) -EvidenceIndex $EvidenceIndex
            if (-not $validation.valid) { continue }
        }
        else {
            $validation = Get-WpdReportProperty -InputObject $finding -Name 'validation'
            if ($null -ne $validation -and -not [bool](Get-WpdReportProperty -InputObject $validation -Name 'valid')) {
                continue
            }
        }
        $result += $finding
    }
    return @($result)
}

function Get-WpdReportTechnicianSummary {
    param(
        [AllowNull()][object[]]$Findings,
        [AllowEmptyString()][string]$Outcome,
        [AllowNull()][object]$DataQuality,
        [AllowNull()][object]$EvidenceIndex
    )

    $real = @(Get-WpdReportRealFindings -Findings $Findings -EvidenceIndex $EvidenceIndex)
    if ($real.Count -eq 0) {
        return 'ROOT CAUSE NOT IDENTIFIED: no rule fired with sufficient evidence quality in the supplied window.'
    }
    $titles = @($real | ForEach-Object { [string](Get-WpdReportProperty -InputObject $_ -Name 'title') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 3)
    return ('FINDINGS IDENTIFIED: ' + ($titles -join '; ') + '. Review the linked evidence; correlation is not causation.')
}

function New-WpdTechnicianReport {
    param(
        [AllowNull()][object[]]$Findings = @(),
        [AllowNull()][object]$EvidenceIndex,
        [AllowNull()][object[]]$Artifacts = @(),
        [AllowNull()][object[]]$DataQuality = @(),
        [AllowNull()][object[]]$Timeline = @(),
        [AllowNull()][object[]]$ProcessSamples = @(),
        [AllowNull()][object]$Incident,
        [AllowNull()][object]$Manifest,
        [AllowNull()][object[]]$NoEvidenceCandidates = @(),
        [AllowNull()][object[]]$BaselineRows = @(),
        [AllowNull()][object[]]$IncidentRows = @(),
        [AllowEmptyString()][string]$ValueProperty,
        [AllowNull()][double[]]$Percentiles = @(50, 95, 99),
        [AllowNull()][object[]]$Rules = @(),
        [AllowNull()][object[]]$Samples = @(),
        [AllowNull()][object[]]$DiskSeries = @(),
        [AllowNull()][object[]]$EventRows = @()
    )

    $findingRows = @()
    foreach ($finding in (ConvertTo-WpdReportArray -Value $Findings)) {
        if ($null -ne $finding) { $findingRows += $finding }
    }
    $generated = Invoke-WpdReportRuleAnalysis -Samples $Samples -DiskSeries $DiskSeries -ProcessSamples $ProcessSamples -EventRows $EventRows -Rules $Rules
    $findingRows += @($generated.findings)
    $recordRows = @($generated.evidenceRecords)
    foreach ($finding in $findingRows) {
        foreach ($evidence in (Get-WpdReportEvidenceFromFinding -Finding $finding)) {
            if ($null -ne $evidence -and $null -ne (Get-WpdReportProperty -InputObject $evidence -Name 'id')) {
                $recordRows += $evidence
            }
        }
    }
    if ($null -eq $EvidenceIndex) {
        $EvidenceIndex = New-WpdEvidenceIndex -Records $recordRows -Artifacts $Artifacts
    }
    else {
        $existingRecords = @(Get-WpdReportIndexRecords -EvidenceIndex $EvidenceIndex)
        $existingArtifacts = @(Get-WpdReportIndexArtifacts -EvidenceIndex $EvidenceIndex)
        if ($recordRows.Count -gt 0) {
            $allRecords = @()
            $seenRecordIds = @{}
            foreach ($record in @($existingRecords) + @($recordRows)) {
                if ($null -eq $record) { continue }
                $recordId = [string](Get-WpdReportProperty -InputObject $record -Name 'id')
                if ([string]::IsNullOrWhiteSpace($recordId)) {
                    $allRecords += $record
                    continue
                }
                if (-not $seenRecordIds.ContainsKey($recordId)) {
                    $seenRecordIds[$recordId] = $true
                    $allRecords += $record
                }
            }
            $allArtifacts = @()
            $seenArtifactNames = @{}
            foreach ($artifact in @(ConvertTo-WpdReportArray -Value $Artifacts) + @($existingArtifacts)) {
                if ($null -eq $artifact) { continue }
                $artifactName = ConvertTo-WpdReportForwardPath -Path (Get-WpdReportArtifactName -Artifact $artifact)
                if ([string]::IsNullOrWhiteSpace($artifactName)) {
                    $allArtifacts += $artifact
                    continue
                }
                if (-not $seenArtifactNames.ContainsKey($artifactName)) {
                    $seenArtifactNames[$artifactName] = $true
                    $allArtifacts += $artifact
                }
            }
            $EvidenceIndex = New-WpdEvidenceIndex -Records $allRecords -Artifacts $allArtifacts
        }
    }
    $validation = Test-WpdEvidenceLinks -Findings $findingRows -EvidenceIndex $EvidenceIndex
    $qualityRows = @(ConvertTo-WpdReportArray -Value $DataQuality)
    if ($qualityRows.Count -eq 0 -and @($Samples).Count -gt 0) {
        $qualityRows = @(Get-WpdReportDefaultQualityFromSamples -Samples $Samples)
    }
    $qualitySummary = Get-WpdDataQualitySummary -Records $qualityRows
    $timelineRows = Get-WpdReportTimelineRows -Timeline $Timeline -Incident $Incident
    $processTables = Get-WpdReportProcessTables -ProcessSamples $ProcessSamples -Incident $Incident
    $baselineComparisons = @()
    if (@(ConvertTo-WpdReportArray -Value $BaselineRows).Count -gt 0 -or @(ConvertTo-WpdReportArray -Value $IncidentRows).Count -gt 0) {
        if (-not [string]::IsNullOrWhiteSpace($ValueProperty)) {
            $baselineComparisons = @(Compare-WpdBaselineIncident -BaselineRows $BaselineRows -IncidentRows $IncidentRows -ValueProperty $ValueProperty -Percentiles $Percentiles)
        }
    }
    $noEvidence = @(Get-WpdNoEvidenceOf -Candidates $NoEvidenceCandidates -DataQuality $qualityRows -EvidenceIndex $EvidenceIndex)
    $realFindings = @(Get-WpdReportRealFindings -Findings $findingRows -EvidenceIndex $EvidenceIndex)
    $outcome = if ($realFindings.Count -gt 0) { 'FINDINGS IDENTIFIED' } else { 'ROOT CAUSE NOT IDENTIFIED' }
    $summary = Get-WpdReportTechnicianSummary -Findings $findingRows -Outcome $outcome -DataQuality $qualitySummary -EvidenceIndex $EvidenceIndex
    $sections = @('technician-summary', 'coverage', 'timeline', 'incident-process', 'findings')
    if ($baselineComparisons.Count -gt 0) { $sections += 'baseline-comparison' }
    if ($noEvidence.Count -gt 0) { $sections += 'no-evidence-of' }
    if (@(Get-WpdReportIndexArtifacts -EvidenceIndex $EvidenceIndex).Count -gt 0) { $sections += 'artifacts' }
    return [pscustomobject]@{
        status = if (-not $validation.valid) { 'partial' } elseif (
            $qualitySummary.coverage -notin @('complete', 'partial') -and
            [string](Get-WpdReportProperty -InputObject $EvidenceIndex -Name 'coverage') -notin @('complete', 'partial')
        ) { 'unavailable' } else { 'success' }
        outcome = $outcome
        technicianSummary = $summary
        summary = $summary
        sections = @($sections)
        findings = @($findingRows)
        evidenceIndex = $EvidenceIndex
        evidenceValidation = $validation
        dataQuality = $qualitySummary
        coverage = $qualitySummary
        timeline = @($timelineRows)
        processTables = @($processTables)
        baselineComparisons = @($baselineComparisons)
        noEvidenceOf = @($noEvidence)
        artifacts = @(Get-WpdReportIndexArtifacts -EvidenceIndex $EvidenceIndex)
        incident = $Incident
        manifest = $Manifest
    }
}

function Compare-WpdBaselineIncident {
    param(
        [AllowNull()][object[]]$BaselineRows = @(),
        [AllowNull()][object[]]$IncidentRows = @(),
        [AllowEmptyString()][string]$ValueProperty,
        [AllowNull()][double[]]$Percentiles = @(50, 95, 99)
    )

    function Get-WpdWeightedPercentiles {
        param([AllowNull()][object[]]$Rows)

        $entries = @()
        foreach ($row in (ConvertTo-WpdReportArray -Value $Rows)) {
            if ($null -eq $row) { continue }
            $value = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportProperty -InputObject $row -Name $ValueProperty)
            if ($null -eq $value) { continue }
            $weight = ConvertTo-WpdReportFiniteNumber -Value (Get-WpdReportFirstProperty -InputObject $row -Names @('DurationSeconds', 'durationSeconds', 'Duration', 'ElapsedSeconds') -Default 1)
            if ($null -eq $weight -or $weight -le 0) { $weight = 1.0 }
            $entries += [pscustomobject]@{ value = $value; weight = $weight }
        }
        $ordered = @($entries | Sort-Object -Property value)
        $duration = 0.0
        foreach ($entry in $ordered) { $duration += [double]$entry.weight }
        $result = [ordered]@{
            status = if ($ordered.Count -gt 0) { 'measured' } else { 'unavailable' }
            sampleCount = $ordered.Count
            durationSeconds = if ($ordered.Count -gt 0) { [math]::Round($duration, 6) } else { $null }
        }
        foreach ($percentile in (ConvertTo-WpdReportArray -Value $Percentiles)) {
            $key = 'P' + ([string]$percentile).Replace('.', '_')
            $selected = $null
            if ($ordered.Count -gt 0) {
                $target = $duration * ([double]$percentile / 100.0)
                if ($target -le 0) { $target = $ordered[0].weight }
                $cumulative = 0.0
                foreach ($entry in $ordered) {
                    $cumulative += [double]$entry.weight
                    if ($cumulative -ge $target) { $selected = $entry.value; break }
                }
                if ($null -eq $selected) { $selected = $ordered[$ordered.Count - 1].value }
            }
            $result[$key] = $selected
        }
        return [pscustomobject]$result
    }

    $baseline = Get-WpdWeightedPercentiles -Rows $BaselineRows
    $incident = Get-WpdWeightedPercentiles -Rows $IncidentRows
    $output = [ordered]@{
        status = if ($baseline.status -eq 'measured' -and $incident.status -eq 'measured') { 'measured' } else { 'partial' }
        baseline = $baseline
        incident = $incident
        BaselineDurationSeconds = $baseline.durationSeconds
        IncidentDurationSeconds = $incident.durationSeconds
    }
    foreach ($percentile in (ConvertTo-WpdReportArray -Value $Percentiles)) {
        $key = 'P' + ([string]$percentile).Replace('.', '_')
        $oldValue = Get-WpdReportProperty -InputObject $baseline -Name $key
        $newValue = Get-WpdReportProperty -InputObject $incident -Name $key
        $output['Delta' + $key] = if ($null -ne $oldValue -and $null -ne $newValue) { [double]$newValue - [double]$oldValue } else { $null }
    }
    return [pscustomobject]$output
}

function Get-WpdDurationPercentiles {
    param(
        [AllowNull()][object[]]$Rows = @(),
        [AllowEmptyString()][string]$ValueProperty,
        [AllowNull()][double[]]$Percentiles = @(50, 95, 99)
    )

    $comparison = Compare-WpdBaselineIncident -BaselineRows $Rows -IncidentRows $Rows -ValueProperty $ValueProperty -Percentiles $Percentiles
    return $comparison.baseline
}

function Get-WpdReportEvidenceLookup {
    param(
        [AllowNull()][object]$EvidenceIndex,
        [AllowNull()][object]$Evidence
    )

    $id = if ($Evidence -is [string]) { [string]$Evidence } else { [string](Get-WpdReportProperty -InputObject $Evidence -Name 'id') }
    foreach ($record in (Get-WpdReportIndexRecords -EvidenceIndex $EvidenceIndex)) {
        if ([string](Get-WpdReportProperty -InputObject $record -Name 'id') -eq $id) { return $record }
    }
    return $null
}

function Write-WpdReportHtml {
    param(
        [Alias('OutputPath')][Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Report
    )

    $html = ConvertTo-WpdHtmlReport -Report $Report
    $parent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Path))
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [void][System.IO.Directory]::CreateDirectory($parent)
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $html, $utf8)
    return [pscustomobject]@{ path = $Path; status = 'success'; bytes = (Get-Item -LiteralPath $Path).Length }
}

function ConvertTo-WpdHtmlReport {
    param(
        [AllowNull()][object]$Report,
        [AllowNull()][object[]]$Findings,
        [AllowNull()][object]$Manifest,
        [AllowNull()][object]$EvidenceIndex,
        [AllowNull()][object]$DataQuality,
        [AllowNull()][object[]]$Timeline,
        [AllowNull()][object[]]$ProcessTables,
        [AllowNull()][object[]]$Artifacts,
        [AllowNull()][string]$TechnicianSummary
    )

    if ($null -ne $Report) {
        if ($null -eq $Findings) { $Findings = Get-WpdReportProperty -InputObject $Report -Name 'findings' }
        if ($null -eq $Manifest) { $Manifest = Get-WpdReportProperty -InputObject $Report -Name 'manifest' }
        if ($null -eq $EvidenceIndex) { $EvidenceIndex = Get-WpdReportProperty -InputObject $Report -Name 'evidenceIndex' }
        if ($null -eq $DataQuality) { $DataQuality = Get-WpdReportProperty -InputObject $Report -Name 'dataQuality' }
        if ($null -eq $Timeline) { $Timeline = Get-WpdReportProperty -InputObject $Report -Name 'timeline' }
        if ($null -eq $ProcessTables) { $ProcessTables = Get-WpdReportProperty -InputObject $Report -Name 'processTables' }
        if ($null -eq $Artifacts) { $Artifacts = Get-WpdReportProperty -InputObject $Report -Name 'artifacts' }
        if ($null -eq $TechnicianSummary) { $TechnicianSummary = [string](Get-WpdReportFirstProperty -InputObject $Report -Names @('technicianSummary', 'summary') -Default '') }
    }
    $findingsRows = @(ConvertTo-WpdReportArray -Value $Findings)
    $artifactRows = @(ConvertTo-WpdReportArray -Value $Artifacts)
    if ($artifactRows.Count -eq 0) { $artifactRows = @(Get-WpdReportIndexArtifacts -EvidenceIndex $EvidenceIndex) }
    $summaryText = if ([string]::IsNullOrWhiteSpace($TechnicianSummary)) { 'ROOT CAUSE NOT IDENTIFIED: no technician summary was supplied.' } else { $TechnicianSummary }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine('<!DOCTYPE html>')
    [void]$builder.AppendLine('<html lang="en">')
    [void]$builder.AppendLine('<head>')
    [void]$builder.AppendLine('<meta charset="utf-8">')
    [void]$builder.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$builder.AppendLine('<title>Windows Performance Diagnostics Technician Report</title>')
    [void]$builder.AppendLine('<style>body{font-family:Arial,sans-serif;margin:2em;color:#222;line-height:1.45}h1,h2,h3{margin-top:1.2em}table{border-collapse:collapse;width:100%;margin:1em 0}th,td{border:1px solid #bbb;padding:.45em;text-align:left;vertical-align:top}th{background:#f0f0f0}.finding{border:1px solid #bbb;padding:1em;margin:1em 0}.coverage{background:#f5f5f5}.warning{background:#fff4cc}.small{font-size:.9em;color:#555}code{white-space:pre-wrap;word-break:break-word}a{color:#0645ad}</style>')
    [void]$builder.AppendLine('</head>')
    [void]$builder.AppendLine('<body>')

    [void]$builder.AppendLine('<h1>Technician Summary</h1>')
    [void]$builder.AppendLine(('<p>{0}</p>' -f (ConvertTo-WpdReportHtmlEncoded -Value $summaryText)))
    $outcome = if ($null -ne $Report) { Get-WpdReportProperty -InputObject $Report -Name 'outcome' } else { $null }
    if ($null -ne $outcome) {
        [void]$builder.AppendLine(('<p><strong>Outcome:</strong> {0}</p>' -f (ConvertTo-WpdReportHtmlEncoded -Value $outcome)))
    }

    [void]$builder.AppendLine('<h2>Coverage</h2>')
    if ($null -eq $DataQuality) {
        [void]$builder.AppendLine('<p class="coverage">Data quality was not supplied; conclusions are not available.</p>')
    }
    else {
        [void]$builder.AppendLine('<table><tr><th>Collector</th><th>Status</th><th>Coverage</th><th>Observed</th><th>Expected</th><th>Duration (s)</th><th>Reasons</th></tr>')
        $qualityRows = Get-WpdReportProperty -InputObject $DataQuality -Name 'records'
        if ($null -eq $qualityRows) { $qualityRows = $DataQuality }
        foreach ($quality in (ConvertTo-WpdReportArray -Value $qualityRows)) {
            if ($null -eq $quality) { continue }
            [void]$builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $quality -Name 'collector')), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $quality -Name 'status')), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $quality -Name 'coverage')), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportFirstProperty -InputObject $quality -Names @('observedSamples', 'sampleCount'))), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $quality -Name 'expectedSamples')), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $quality -Name 'durationSeconds')), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $quality -Name 'reasons'))))
        }
        [void]$builder.AppendLine('</table>')
    }

    [void]$builder.AppendLine('<h2>Aligned Timeline</h2>')
    if (@(ConvertTo-WpdReportArray -Value $Timeline).Count -eq 0) {
        [void]$builder.AppendLine('<p class="coverage">No timeline rows were supplied.</p>')
    }
    else {
        [void]$builder.AppendLine('<table><tr><th>UTC</th><th>Source</th><th>Event</th><th>Incident relation</th></tr>')
        foreach ($row in (ConvertTo-WpdReportArray -Value $Timeline)) {
            [void]$builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $row -Name 'TimestampUtc')), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $row -Name 'Source')), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $row -Name 'Event')), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $row -Name 'InIncidentWindow'))))
        }
        [void]$builder.AppendLine('</table>')
    }

    [void]$builder.AppendLine('<h2>Incident-window Process Tables</h2>')
    foreach ($table in (ConvertTo-WpdReportArray -Value $ProcessTables)) {
        if ($null -eq $table) { continue }
        [void]$builder.AppendLine(('<h3>{0}</h3>' -f (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $table -Name 'id'))))
        [void]$builder.AppendLine(('<p class="small">Scope: {0}; {1} to {2}</p>' -f `
            (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $table -Name 'scope')), `
            (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $table -Name 'windowStart')), `
            (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $table -Name 'windowEnd'))))
        $rows = @(Get-WpdReportProperty -InputObject $table -Name 'rows' -Default @())
        if ($rows.Count -eq 0) {
            [void]$builder.AppendLine('<p class="coverage">No process samples fell inside the incident window.</p>')
            continue
        }
        [void]$builder.AppendLine('<table><tr><th>UTC</th><th>Process</th><th>PID</th><th>Start time</th><th>CPU</th><th>Evidence row</th></tr>')
        foreach ($row in $rows) {
            [void]$builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td><code>{5}</code></td></tr>' -f `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportFirstProperty -InputObject $row -Names @('TimestampUtc', 'timestampUtc'))), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportFirstProperty -InputObject $row -Names @('ProcessName', 'processName', 'Name'))), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportFirstProperty -InputObject $row -Names @('ProcessId', 'processId', 'Id'))), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportFirstProperty -InputObject $row -Names @('StartTimeUtc', 'startTimeUtc'))), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportFirstProperty -InputObject $row -Names @('CpuPercent', 'ProcessCpuPercent', 'CpuTimePercent'))), `
                (ConvertTo-WpdReportHtmlEncoded $row)))
        }
        [void]$builder.AppendLine('</table>')
    }

    [void]$builder.AppendLine('<h2>Findings</h2>')
    if ($findingsRows.Count -eq 0) {
        [void]$builder.AppendLine('<p class="coverage">No findings were emitted. This is not evidence that an unmeasured condition was absent.</p>')
    }
    else {
        $known = @($findingsRows | Where-Object { [bool](Get-WpdReportProperty -InputObject $_ -Name 'categoryKnown') -or $script:WpdReportCategories -contains [string](Get-WpdReportProperty -InputObject $_ -Name 'category') })
        $unknown = @($findingsRows | Where-Object { $known -notcontains $_ })
        foreach ($group in @(@{ heading = 'Observed Findings'; rows = $known }, @{ heading = 'Other Findings'; rows = $unknown })) {
            $groupRows = @($group.rows)
            if ($groupRows.Count -eq 0) { continue }
            [void]$builder.AppendLine(('<h3>{0}</h3>' -f (ConvertTo-WpdReportHtmlEncoded $group.heading)))
            foreach ($finding in $groupRows) {
                $category = [string](Get-WpdReportProperty -InputObject $finding -Name 'category')
                [void]$builder.AppendLine('<div class="finding">')
                [void]$builder.AppendLine(('<h4>{0}: {1}</h4>' -f (ConvertTo-WpdReportHtmlEncoded $category), (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $finding -Name 'title'))))
                [void]$builder.AppendLine(('<p>{0}</p>' -f (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $finding -Name 'summary'))))
                [void]$builder.AppendLine('<table>')
                foreach ($pair in @(
                    @('Severity', 'severity'),
                    @('Confidence', 'confidence'),
                    @('Source artifact', 'sourceArtifact'),
                    @('Metric', 'metric'),
                    @('Window start', 'windowStart'),
                    @('Window end', 'windowEnd'),
                    @('Rule', 'ruleCondition'),
                    @('Measured values', 'measuredValues'),
                    @('Uncertainty', 'uncertainty'),
                    @('Next steps', 'nextSteps'),
                    @('Limitations', 'limitations')
                )) {
                    [void]$builder.AppendLine(('<tr><th>{0}</th><td>{1}</td></tr>' -f (ConvertTo-WpdReportHtmlEncoded $pair[0]), (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportProperty -InputObject $finding -Name $pair[1]))))
                }
                $evidenceRows = @(Get-WpdReportEvidenceFromFinding -Finding $finding)
                if ($evidenceRows.Count -gt 0) {
                    $links = @()
                    foreach ($evidence in $evidenceRows) {
                        $record = Get-WpdReportEvidenceLookup -EvidenceIndex $EvidenceIndex -Evidence $evidence
                        if ($null -ne $record -and [bool](Get-WpdReportProperty -InputObject $record -Name 'linkable')) {
                            $path = ConvertTo-WpdReportForwardPath -Path ([string](Get-WpdReportFirstProperty -InputObject $record -Names @('path', 'artifact')))
                            if (Test-WpdReportSafeRelativePath -Path $path) {
                                $href = ConvertTo-WpdReportHtmlEncoded -Value $path
                                $label = ConvertTo-WpdReportHtmlEncoded -Value ([string](Get-WpdReportProperty -InputObject $record -Name 'id'))
                                $links += ('<a href="' + $href + '">' + $label + '</a>')
                                continue
                            }
                        }
                        $links += ('<code>' + (ConvertTo-WpdReportHtmlEncoded -Value (Get-WpdReportProperty -InputObject $evidence -Name 'id')) + '</code>')
                    }
                    [void]$builder.AppendLine(('<tr><th>Evidence</th><td>{0}</td></tr>' -f ($links -join ', ')))
                }
                [void]$builder.AppendLine('</table>')
                [void]$builder.AppendLine('</div>')
            }
        }
    }

    if (@(ConvertTo-WpdReportArray -Value $artifactRows).Count -gt 0) {
        [void]$builder.AppendLine('<h2>Raw Artifacts</h2>')
        [void]$builder.AppendLine('<p class="small">Links are emitted only for registered artifacts with a safe relative path; a missing SHA-256 is shown as incomplete integrity metadata.</p>')
        [void]$builder.AppendLine('<table><tr><th>Artifact</th><th>Size</th><th>SHA-256</th><th>Link state</th></tr>')
        foreach ($artifact in $artifactRows) {
            $name = Get-WpdReportArtifactName -Artifact $artifact
            $safe = Test-WpdReportSafeRelativePath -Path $name
            $hashed = Test-WpdReportArtifactHasHash -Artifact $artifact
            $href = ConvertTo-WpdReportForwardPath -Path $name
            $nameCell = if ($safe) {
                '<a href="' + (ConvertTo-WpdReportHtmlEncoded $href) + '">' + (ConvertTo-WpdReportHtmlEncoded $name) + '</a>'
            }
            else {
                '<code>' + (ConvertTo-WpdReportHtmlEncoded $name) + '</code>'
            }
            [void]$builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td><code>{2}</code></td><td>{3}</td></tr>' -f `
                $nameCell, `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportFirstProperty -InputObject $artifact -Names @('SizeBytes', 'sizeBytes', 'Length'))), `
                (ConvertTo-WpdReportHtmlEncoded (Get-WpdReportArtifactHash -Artifact $artifact)), `
                (ConvertTo-WpdReportHtmlEncoded -Value $(if ($safe -and $hashed) { 'registered-and-hashed' } elseif ($safe) { 'registered-missing-hash' } else { 'not-linkable' })) ))
        }
        [void]$builder.AppendLine('</table>')
    }

    [void]$builder.AppendLine('<footer class="small">Offline report. Evidence is descriptive; recommendations are advisory and no remediation is performed.</footer>')
    [void]$builder.AppendLine('</body>')
    [void]$builder.AppendLine('</html>')
    return $builder.ToString()
}

function New-WpdReport {
    param(
        [AllowNull()][object[]]$Findings = @(),
        [AllowNull()][object]$EvidenceIndex,
        [AllowNull()][object[]]$Artifacts = @(),
        [AllowNull()][object[]]$DataQuality = @(),
        [AllowNull()][object[]]$Timeline = @(),
        [AllowNull()][object[]]$ProcessSamples = @(),
        [AllowNull()][object]$Incident,
        [AllowNull()][object]$Manifest,
        [AllowNull()][object[]]$NoEvidenceCandidates = @(),
        [AllowNull()][object[]]$BaselineRows = @(),
        [AllowNull()][object[]]$IncidentRows = @(),
        [AllowEmptyString()][string]$ValueProperty,
        [AllowNull()][double[]]$Percentiles = @(50, 95, 99),
        [AllowNull()][object[]]$Rules = @(),
        [AllowNull()][object[]]$Samples = @(),
        [AllowNull()][object[]]$DiskSeries = @(),
        [AllowNull()][object[]]$EventRows = @()
    )

    return New-WpdTechnicianReport -Findings $Findings -EvidenceIndex $EvidenceIndex `
        -Artifacts $Artifacts -DataQuality $DataQuality -Timeline $Timeline `
        -ProcessSamples $ProcessSamples -Incident $Incident -Manifest $Manifest `
        -NoEvidenceCandidates $NoEvidenceCandidates -BaselineRows $BaselineRows `
        -IncidentRows $IncidentRows -ValueProperty $ValueProperty -Percentiles $Percentiles `
        -Rules $Rules -Samples $Samples -DiskSeries $DiskSeries -EventRows $EventRows
}

function Invoke-WpdReportAnalysis {
    param(
        [AllowNull()][object[]]$Findings = @(),
        [AllowNull()][object]$EvidenceIndex,
        [AllowNull()][object[]]$Artifacts = @(),
        [AllowNull()][object[]]$DataQuality = @(),
        [AllowNull()][object[]]$Timeline = @(),
        [AllowNull()][object[]]$ProcessSamples = @(),
        [AllowNull()][object]$Incident,
        [AllowNull()][object]$Manifest,
        [AllowNull()][object[]]$NoEvidenceCandidates = @(),
        [AllowNull()][object[]]$BaselineRows = @(),
        [AllowNull()][object[]]$IncidentRows = @(),
        [AllowEmptyString()][string]$ValueProperty,
        [AllowNull()][double[]]$Percentiles = @(50, 95, 99),
        [AllowNull()][object[]]$Rules = @(),
        [AllowNull()][object[]]$Samples = @(),
        [AllowNull()][object[]]$DiskSeries = @(),
        [AllowNull()][object[]]$EventRows = @()
    )

    return New-WpdTechnicianReport -Findings $Findings -EvidenceIndex $EvidenceIndex `
        -Artifacts $Artifacts -DataQuality $DataQuality -Timeline $Timeline `
        -ProcessSamples $ProcessSamples -Incident $Incident -Manifest $Manifest `
        -NoEvidenceCandidates $NoEvidenceCandidates -BaselineRows $BaselineRows `
        -IncidentRows $IncidentRows -ValueProperty $ValueProperty -Percentiles $Percentiles `
        -Rules $Rules -Samples $Samples -DiskSeries $DiskSeries -EventRows $EventRows
}

Set-Alias -Name New-WpdTechnicianReportPackage -Value New-WpdTechnicianReport
Set-Alias -Name ConvertTo-WpdReportHtml -Value ConvertTo-WpdHtmlReport
Set-Alias -Name ConvertTo-WpdStandaloneHtml -Value ConvertTo-WpdHtmlReport
Set-Alias -Name Write-WpdHtmlReport -Value Write-WpdReportHtml
Set-Alias -Name Compare-WpdIncidentBaseline -Value Compare-WpdBaselineIncident
Set-Alias -Name Test-WpdFindingEvidence -Value Test-WpdEvidenceLinks

Export-ModuleMember -Function @(
    'Assert-WpdEvidenceLinks',
    'Compare-WpdBaselineIncident',
    'ConvertTo-WpdFindingEvidence',
    'ConvertTo-WpdFindingRule',
    'ConvertTo-WpdHtmlReport',
    'Get-WpdConfidenceValues',
    'Get-WpdDataQualitySummary',
    'Get-WpdDurationPercentiles',
    'Get-WpdNoEvidenceOf',
    'Get-WpdReportCategories',
    'Get-WpdReportConfidenceValues',
    'Get-WpdReportCoverageStates',
    'Get-WpdReportOutcomeValues',
    'Get-WpdReportSeverityValues',
    'Invoke-WpdReportAnalysis',
    'New-WpdDataQualityRecord',
    'New-WpdDataQualitySummary',
    'New-WpdEvidenceIndex',
    'New-WpdEvidenceIndexRecord',
    'New-WpdFinding',
    'New-WpdReport',
    'New-WpdTechnicianReport',
    'Test-WpdEvidenceLinks',
    'Test-WpdFindingEvidence',
    'Validate-WpdEvidenceLinks',
    'Write-WpdHtmlReport',
    'Write-WpdReportHtml'
) -Alias @(
    'New-WpdTechnicianReportPackage',
    'ConvertTo-WpdReportHtml',
    'ConvertTo-WpdStandaloneHtml',
    'Compare-WpdIncidentBaseline'
)
