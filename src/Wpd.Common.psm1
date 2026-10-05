#Requires -Version 5.1
# Wpd.Common.psm1
# Shared timestamp, result, coverage, quality, evidence and privacy helpers.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:WpdCoverageStates = @(
    'complete'
    'partial'
    'unavailable'
    'not-collected'
    'unsupported'
)

$script:WpdStatusValues = @(
    'success'
    'partial'
    'unavailable'
    'not-collected'
    'unsupported'
    'error'
)

$script:WpdConfidenceValues = @(
    'High'
    'Medium'
    'Low'
)

function ConvertTo-WpdArray {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return @()
    }
    return @($Value)
}

function Get-WpdCoverageStates {
    return $script:WpdCoverageStates
}

function Get-WpdStatusValues {
    return $script:WpdStatusValues
}

function Get-WpdConfidenceValues {
    return $script:WpdConfidenceValues
}

function Test-WpdConfidence {
    param([AllowEmptyString()][string]$Confidence)

    return ($script:WpdConfidenceValues -contains $Confidence)
}

function Test-WpdCoverageState {
    param([AllowEmptyString()][string]$State)

    return ($script:WpdCoverageStates -contains $State)
}

function Resolve-WpdCoverageState {
    param(
        [AllowEmptyString()][string]$Status = 'success',
        [int]$ExpectedSamples = 0,
        [int]$ObservedSamples = 0,
        [int]$GapCount = 0,
        [int]$DroppedCount = 0
    )

    $normalized = if ($null -eq $Status) { '' } else { $Status.ToLowerInvariant() }
    if ($normalized -eq 'not-collected' -or $normalized -eq 'unsupported') {
        return $normalized
    }
    if ($normalized -eq 'error' -or $normalized -eq 'failed' -or $normalized -eq 'unavailable' -or $normalized -eq 'healthy') {
        return 'unavailable'
    }
    if ($normalized -ne 'success' -and $normalized -ne 'partial') {
        return 'unavailable'
    }
    if ($ObservedSamples -le 0) {
        return 'unavailable'
    }
    if ($normalized -eq 'partial') {
        return 'partial'
    }
    if ($ExpectedSamples -gt 0 -and $ObservedSamples -lt $ExpectedSamples) {
        return 'partial'
    }
    if ($GapCount -gt 0 -or $DroppedCount -gt 0) {
        return 'partial'
    }
    return 'complete'
}

function Get-WpdConfidence {
    param(
        [AllowEmptyString()][string]$Coverage = 'unavailable',
        [int]$SampleCount = 0,
        [int]$MinimumSamples = 1,
        [AllowNull()][object]$EvidenceCount = 0,
        [AllowNull()][object]$DurationSeconds,
        [int]$MinimumDurationSeconds = 0,
        [AllowNull()][object]$HasIndependentEvidence
    )

    $normalizedCoverage = if ($null -eq $Coverage) { '' } else { $Coverage.ToLowerInvariant() }
    $evidenceCountValue = 0
    try { $evidenceCountValue = [int]$EvidenceCount } catch { $evidenceCountValue = 0 }
    if ($normalizedCoverage -notin @('complete', 'partial') -or $SampleCount -lt [math]::Max(1, $MinimumSamples) -or $evidenceCountValue -lt 1) {
        return 'Low'
    }
    if ($null -ne $DurationSeconds -and $MinimumDurationSeconds -gt 0) {
        try {
            if ([double]$DurationSeconds -lt [double]$MinimumDurationSeconds) {
                return 'Low'
            }
        }
        catch {
            return 'Low'
        }
    }
    if ($null -ne $HasIndependentEvidence -and -not [bool]$HasIndependentEvidence) {
        return 'Medium'
    }
    if ($normalizedCoverage -eq 'partial') {
        return 'Medium'
    }
    return 'High'
}

function Get-WpdConfidenceExplanation {
    param(
        [AllowEmptyString()][string]$Confidence,
        [AllowEmptyString()][string]$Coverage,
        [AllowEmptyString()][string]$Reason
    )

    if (-not (Test-WpdConfidence -Confidence $Confidence)) {
        return 'Low: confidence is unavailable because the supplied confidence value is invalid.'
    }
    if (-not [string]::IsNullOrWhiteSpace($Reason)) {
        return ($Confidence + ': ' + $Reason)
    }
    if ([string]$Coverage -eq 'complete' -and $Confidence -eq 'High') {
        return 'High: complete coverage and sufficient evidence were recorded.'
    }
    if ([string]$Coverage -eq 'partial' -and $Confidence -eq 'Medium') {
        return 'Medium: evidence is usable but coverage is partial.'
    }
    return ($Confidence + ': evidence quality limits the conclusion.')
}

function ConvertTo-WpdUtcDateTime {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [datetime]) {
        return ([datetime]$Value).ToUniversalTime()
    }
    if ($Value -is [datetimeoffset]) {
        return ([datetimeoffset]$Value).UtcDateTime
    }

    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.ToUniversalTime()
    }
    return $null
}

function ConvertTo-WpdIsoTimestamp {
    param([AllowNull()][object]$Value)

    $utc = ConvertTo-WpdUtcDateTime -Value $Value
    if ($null -eq $utc) {
        return $null
    }
    return $utc.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-WpdUtcTimestamp {
    param([AllowNull()][object]$Now)

    if ($null -eq $Now) {
        return (ConvertTo-WpdIsoTimestamp -Value ([datetime]::UtcNow))
    }
    return (ConvertTo-WpdIsoTimestamp -Value $Now)
}

function Get-WpdTimeZoneInfo {
    param([AllowEmptyString()][string]$TimeZoneId)

    if ([string]::IsNullOrWhiteSpace($TimeZoneId)) {
        return [System.TimeZoneInfo]::Local
    }
    try {
        return [System.TimeZoneInfo]::FindSystemTimeZoneById($TimeZoneId)
    }
    catch {
        return $null
    }
}

function Format-WpdLocalTimestamp {
    param(
        [Parameter(Mandatory = $true)][datetime]$UtcDateTime,
        [Parameter(Mandatory = $true)][System.TimeZoneInfo]$TimeZone
    )

    $local = [System.TimeZoneInfo]::ConvertTimeFromUtc($UtcDateTime, $TimeZone)
    $offset = $TimeZone.GetUtcOffset($UtcDateTime)
    $sign = if ($offset.TotalMinutes -lt 0) { '-' } else { '+' }
    $absoluteOffset = $offset.Duration().ToString('hh\:mm', [System.Globalization.CultureInfo]::InvariantCulture)
    return ($local.ToString('yyyy-MM-ddTHH:mm:ss.fffffff', [System.Globalization.CultureInfo]::InvariantCulture) + $sign + $absoluteOffset)
}

function Get-WpdTimeContext {
    param(
        [AllowNull()][object]$Now,
        [AllowEmptyString()][string]$TimeZoneId
    )

    $utc = if ($null -eq $Now) { [datetime]::UtcNow } else { ConvertTo-WpdUtcDateTime -Value $Now }
    $zone = Get-WpdTimeZoneInfo -TimeZoneId $TimeZoneId
    if ($null -eq $utc) {
        return [pscustomobject]@{
            status = 'unavailable'
            utcTimestamp = $null
            isoTimestamp = $null
            localTimestamp = $null
            timeZoneId = if ($null -ne $zone) { $zone.Id } else { $TimeZoneId }
            utcOffsetMinutes = $null
            reason = 'invalid-timestamp'
        }
    }
    if ($null -eq $zone) {
        return [pscustomobject]@{
            status = 'unavailable'
            utcTimestamp = $null
            isoTimestamp = $null
            localTimestamp = $null
            timeZoneId = $TimeZoneId
            utcOffsetMinutes = $null
            reason = 'invalid-timezone'
        }
    }

    $offset = $zone.GetUtcOffset($utc)
    return [pscustomobject]@{
        status = 'complete'
        utcTimestamp = ConvertTo-WpdIsoTimestamp -Value $utc
        isoTimestamp = ConvertTo-WpdIsoTimestamp -Value $utc
        localTimestamp = Format-WpdLocalTimestamp -UtcDateTime $utc -TimeZone $zone
        timeZoneId = $zone.Id
        utcOffsetMinutes = [int]$offset.TotalMinutes
        reason = $null
    }
}

function New-WpdIncidentWindow {
    param(
        [Alias('MarkerUtc')][AllowNull()][object]$MarkerTimeUtc,
        [Alias('StartUtc')][AllowNull()][object]$WindowStartUtc,
        [Alias('EndUtc')][AllowNull()][object]$WindowEndUtc,
        [int]$PreSeconds = 60,
        [int]$PostSeconds = 30,
        [string]$Source = 'marker'
    )

    $marker = $null
    $start = $null
    $end = $null
    $reason = $null
    if ($null -ne $MarkerTimeUtc) {
        $marker = ConvertTo-WpdUtcDateTime -Value $MarkerTimeUtc
        if ($null -eq $marker) {
            return [pscustomobject]@{
                status = 'unavailable'
                coverage = 'unavailable'
                windowStartUtc = $null
                windowEndUtc = $null
                startUtc = $null
                endUtc = $null
                markerUtc = $null
                durationSeconds = $null
                source = $Source
                reason = 'invalid-marker-time'
                reasons = @('invalid-marker-time')
            }
        }
    }

    if ($PreSeconds -lt 0 -or $PostSeconds -lt 0) {
        return [pscustomobject]@{
            status = 'unavailable'
            coverage = 'unavailable'
            windowStartUtc = $null
            windowEndUtc = $null
            startUtc = $null
            endUtc = $null
            markerUtc = if ($null -ne $marker) { ConvertTo-WpdIsoTimestamp -Value $marker } else { $null }
            durationSeconds = $null
            source = $Source
            reason = 'negative-window-padding'
            reasons = @('negative-window-padding')
        }
    }

    if ($null -ne $WindowStartUtc) {
        $start = ConvertTo-WpdUtcDateTime -Value $WindowStartUtc
        if ($null -eq $start) {
            $reason = 'invalid-window-start'
        }
    }
    if ($null -ne $WindowEndUtc) {
        $end = ConvertTo-WpdUtcDateTime -Value $WindowEndUtc
        if ($null -eq $end) {
            $reason = 'invalid-window-end'
        }
    }
    if ($null -ne $reason) {
        return [pscustomobject]@{
            status = 'unavailable'
            coverage = 'unavailable'
            windowStartUtc = $null
            windowEndUtc = $null
            startUtc = $null
            endUtc = $null
            markerUtc = if ($null -ne $marker) { ConvertTo-WpdIsoTimestamp -Value $marker } else { $null }
            durationSeconds = $null
            source = $Source
            reason = $reason
            reasons = @($reason)
        }
    }

    if ($null -eq $start -and $null -ne $marker) {
        $start = $marker.AddSeconds(-1 * $PreSeconds)
    }
    if ($null -eq $end -and $null -ne $marker) {
        $end = $marker.AddSeconds($PostSeconds)
    }
    if ($null -eq $start -or $null -eq $end) {
        $reason = 'incident-window-not-provided'
        return [pscustomobject]@{
            status = 'unavailable'
            coverage = 'unavailable'
            windowStartUtc = $null
            windowEndUtc = $null
            startUtc = $null
            endUtc = $null
            markerUtc = if ($null -ne $marker) { ConvertTo-WpdIsoTimestamp -Value $marker } else { $null }
            durationSeconds = $null
            source = $Source
            reason = $reason
            reasons = @($reason)
        }
    }
    if ($end -lt $start) {
        $reason = 'window-end-before-start'
        return [pscustomobject]@{
            status = 'unavailable'
            coverage = 'unavailable'
            windowStartUtc = $null
            windowEndUtc = $null
            startUtc = $null
            endUtc = $null
            markerUtc = if ($null -ne $marker) { ConvertTo-WpdIsoTimestamp -Value $marker } else { $null }
            durationSeconds = $null
            source = $Source
            reason = $reason
            reasons = @($reason)
        }
    }

    $startText = ConvertTo-WpdIsoTimestamp -Value $start
    $endText = ConvertTo-WpdIsoTimestamp -Value $end
    return [pscustomobject]@{
        status = 'complete'
        coverage = 'complete'
        windowStartUtc = $startText
        windowEndUtc = $endText
        startUtc = $startText
        endUtc = $endText
        markerUtc = if ($null -ne $marker) { ConvertTo-WpdIsoTimestamp -Value $marker } else { $null }
        durationSeconds = [int64][math]::Round(($end - $start).TotalSeconds)
        source = $Source
        reason = $null
        reasons = @()
    }
}

function Test-WpdIncidentWindowMembership {
    param(
        [Alias('Time', 'TimestampUtc')][AllowNull()][object]$EventTime,
        [Alias('WindowStartUtc')][AllowNull()][object]$WindowStart,
        [Alias('WindowEndUtc')][AllowNull()][object]$WindowEnd
    )

    $eventUtc = ConvertTo-WpdUtcDateTime -Value $EventTime
    $startUtc = ConvertTo-WpdUtcDateTime -Value $WindowStart
    $endUtc = ConvertTo-WpdUtcDateTime -Value $WindowEnd
    if ($null -eq $eventUtc -or $null -eq $startUtc -or $null -eq $endUtc -or $endUtc -lt $startUtc) {
        return 'unavailable'
    }
    if ($eventUtc -ge $startUtc -and $eventUtc -le $endUtc) {
        return 'in-window'
    }
    return 'out-of-window'
}

function Get-WpdUptimeInfo {
    param(
        [Alias('SystemInfo', 'ProviderData')][AllowNull()][object]$OperatingSystem,
        [Alias('Now')][AllowNull()][object]$NowUtc,
        [AllowNull()][object]$BootTimeUtc,
        [AllowNull()][object]$UptimeSeconds
    )

    $now = if ($null -eq $NowUtc) { [datetime]::UtcNow } else { ConvertTo-WpdUtcDateTime -Value $NowUtc }
    if ($null -eq $now) {
        return [pscustomobject]@{
            status = 'unavailable'
            coverage = 'unavailable'
            bootTimeUtc = $null
            uptimeSeconds = $null
            source = 'provider'
            reason = 'invalid-now-time'
        }
    }

    $bootValue = $BootTimeUtc
    $source = 'provider'
    if ($null -eq $bootValue -and $null -ne $OperatingSystem) {
        $bootValue = Get-WpdFirstProperty -InputObject $OperatingSystem -Names @('LastBootUpTime', 'BootTimeUtc', 'BootTime', 'LastBootTime', 'SystemBootTime')
    }
    $boot = if ($null -ne $bootValue) { ConvertTo-WpdUtcDateTime -Value $bootValue } else { $null }
    $uptime = $null
    if ($null -ne $UptimeSeconds) {
        try {
            if (-not [double]::IsNaN([double]$UptimeSeconds) -and -not [double]::IsInfinity([double]$UptimeSeconds) -and [double]$UptimeSeconds -ge 0) {
                $uptime = [double]$UptimeSeconds
                $boot = $now.AddSeconds(-1 * $uptime)
                $source = 'uptime'
            }
        }
        catch { }
    }

    if ($null -eq $boot -and $null -eq $OperatingSystem -and $null -eq $BootTimeUtc -and $null -eq $UptimeSeconds) {
        try {
            if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
                $uptime = [double]([System.Environment]::TickCount64 / 1000.0)
                $boot = $now.AddSeconds(-1 * $uptime)
                $source = 'system-tick-count'
            }
        }
        catch { }
    }

    if ($null -eq $boot) {
        return [pscustomobject]@{
            status = 'unavailable'
            coverage = 'unavailable'
            bootTimeUtc = $null
            uptimeSeconds = $null
            source = $source
            reason = 'boot-time-unavailable'
        }
    }
    if ($boot -gt $now) {
        return [pscustomobject]@{
            status = 'unavailable'
            coverage = 'unavailable'
            bootTimeUtc = $null
            uptimeSeconds = $null
            source = $source
            reason = 'boot-time-after-now'
        }
    }
    if ($null -eq $uptime) {
        $uptime = [double]($now - $boot).TotalSeconds
    }
    $bootText = ConvertTo-WpdIsoTimestamp -Value $boot
    return [pscustomobject]@{
        status = 'complete'
        coverage = 'complete'
        bootTimeUtc = $bootText
        uptimeSeconds = $uptime
        source = $source
        reason = $null
    }
}

function New-WpdDataQualityRecord {
    param(
        [Alias('Name')][string]$Collector,
        [string]$Status = 'success',
        [int]$ExpectedSamples = 0,
        [int]$ObservedSamples = 0,
        [int]$GapCount = 0,
        [int]$DroppedCount = 0,
        [AllowNull()][object]$WindowStartUtc,
        [AllowNull()][object]$WindowEndUtc,
        [AllowNull()][object[]]$Reasons = @(),
        [AllowNull()][object[]]$Warnings = @(),
        [AllowNull()][object[]]$Errors = @(),
        [string]$SourceArtifact
    )

    $expected = [math]::Max(0, $ExpectedSamples)
    $observed = [math]::Max(0, $ObservedSamples)
    $gaps = [math]::Max(0, $GapCount)
    $dropped = [math]::Max(0, $DroppedCount)
    $missing = [math]::Max(0, ($expected - $observed))
    $coverage = Resolve-WpdCoverageState `
        -Status $Status `
        -ExpectedSamples $expected `
        -ObservedSamples $observed `
        -GapCount $gaps `
        -DroppedCount $dropped
    $qualityReasons = @(ConvertTo-WpdArray -Value $Reasons)
    if ($observed -eq 0 -and $qualityReasons -notcontains 'no-measurements') {
        $qualityReasons += 'no-measurements'
    }
    if (($missing -gt 0 -or $gaps -gt 0 -or $dropped -gt 0) -and $qualityReasons -notcontains 'sample-gap') {
        $qualityReasons += 'sample-gap'
    }

    $start = ConvertTo-WpdIsoTimestamp -Value $WindowStartUtc
    $end = ConvertTo-WpdIsoTimestamp -Value $WindowEndUtc
    if (($null -ne $WindowStartUtc -and $null -eq $start) -or ($null -ne $WindowEndUtc -and $null -eq $end)) {
        $coverage = 'unavailable'
        if ($qualityReasons -notcontains 'invalid-window-time') {
            $qualityReasons += 'invalid-window-time'
        }
    }
    $durationSeconds = $null
    if ($null -ne $start -and $null -ne $end) {
        $startDate = ConvertTo-WpdUtcDateTime -Value $start
        $endDate = ConvertTo-WpdUtcDateTime -Value $end
        if ($null -ne $startDate -and $null -ne $endDate -and $endDate -ge $startDate) {
            $durationSeconds = [double]($endDate - $startDate).TotalSeconds
        }
        else {
            $coverage = 'unavailable'
            if ($qualityReasons -notcontains 'invalid-window-order') {
                $qualityReasons += 'invalid-window-order'
            }
        }
    }
    $usable = ($observed -gt 0 -and ($coverage -eq 'complete' -or $coverage -eq 'partial'))
    $normalizedStatus = if ($coverage -eq 'complete') { 'success' } elseif ($coverage -eq 'partial') { 'partial' } else { 'unavailable' }
    return [pscustomobject]@{
        collector = $Collector
        status = $normalizedStatus
        coverage = $coverage
        expectedSamples = $expected
        observedSamples = $observed
        sampleCount = $observed
        missingSamples = $missing
        gapCount = $gaps
        droppedCount = $dropped
        isUsable = [bool]$usable
        usable = [bool]$usable
        windowStartUtc = $start
        windowEndUtc = $end
        durationSeconds = $durationSeconds
        sourceArtifact = $SourceArtifact
        reasons = $qualityReasons
        warnings = @(ConvertTo-WpdArray -Value $Warnings)
        errors = @(ConvertTo-WpdArray -Value $Errors)
    }
}

function ConvertTo-WpdFiniteNumber {
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

function Measure-WpdSampleQuality {
    param(
        [AllowNull()][object[]]$Samples,
        [string]$ValueProperty = 'Value',
        [AllowNull()][object]$ExpectedStartUtc,
        [AllowNull()][object]$ExpectedEndUtc,
        [double]$IntervalSeconds = 1,
        [string]$Collector = 'samples',
        [string]$SourceArtifact
    )

    $start = ConvertTo-WpdUtcDateTime -Value $ExpectedStartUtc
    $end = ConvertTo-WpdUtcDateTime -Value $ExpectedEndUtc
    $qualityReasons = @()
    $invalidTimestampCount = 0
    $invalidValueCount = 0
    $validSamples = @()
    foreach ($sample in @($Samples)) {
        if ($null -eq $sample) {
            $invalidValueCount++
            continue
        }
        $stampValue = Get-WpdObjectProperty -InputObject $sample -Name 'TimestampUtc'
        if ($null -eq $stampValue) {
            $stampValue = Get-WpdObjectProperty -InputObject $sample -Name 'Timestamp'
        }
        $stamp = ConvertTo-WpdUtcDateTime -Value $stampValue
        if ($null -eq $stamp) {
            $invalidTimestampCount++
            continue
        }
        if ($null -ne $start -and $stamp -lt $start) {
            $invalidTimestampCount++
            continue
        }
        if ($null -ne $end -and $stamp -gt $end) {
            $invalidTimestampCount++
            continue
        }
        $value = Get-WpdObjectProperty -InputObject $sample -Name $ValueProperty
        $number = ConvertTo-WpdFiniteNumber -Value $value
        if ($null -eq $number) {
            $invalidValueCount++
            continue
        }
        $validSamples += $sample
    }

    $expected = 0
    if ($null -ne $start -and $null -ne $end -and $end -ge $start -and $IntervalSeconds -gt 0) {
        $expected = [int][math]::Floor((($end - $start).TotalSeconds / $IntervalSeconds) + 0.0000001) + 1
    }
    elseif ($null -eq $start -and $null -eq $end) {
        $expected = $validSamples.Count
    }
    else {
        $qualityReasons += 'invalid-window-or-interval'
    }
    $observed = $validSamples.Count
    $missing = [math]::Max(0, ($expected - $observed))
    if ($missing -gt 0) {
        $qualityReasons += 'sample-gap'
    }
    if ($invalidTimestampCount -gt 0) {
        $qualityReasons += 'invalid-timestamp'
    }
    if ($invalidValueCount -gt 0) {
        $qualityReasons += 'missing-value'
    }
    $status = if ($observed -eq 0) { 'unavailable' } elseif ($missing -gt 0 -or $invalidTimestampCount -gt 0 -or $invalidValueCount -gt 0) { 'partial' } else { 'success' }
    $quality = New-WpdDataQualityRecord `
        -Collector $Collector `
        -Status $status `
        -ExpectedSamples $expected `
        -ObservedSamples $observed `
        -GapCount $missing `
        -DroppedCount ($invalidTimestampCount + $invalidValueCount) `
        -WindowStartUtc $ExpectedStartUtc `
        -WindowEndUtc $ExpectedEndUtc `
        -Reasons $qualityReasons `
        -SourceArtifact $SourceArtifact
    Add-Member -InputObject $quality -MemberType NoteProperty -Name invalidTimestampCount -Value $invalidTimestampCount
    Add-Member -InputObject $quality -MemberType NoteProperty -Name invalidValueCount -Value $invalidValueCount
    Add-Member -InputObject $quality -MemberType NoteProperty -Name intervalSeconds -Value $IntervalSeconds
    Add-Member -InputObject $quality -MemberType NoteProperty -Name validSamples -Value $validSamples
    return $quality
}

function Get-WpdObjectProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][object]$Default
    )

    if ($null -eq $InputObject) {
        return $Default
    }
    try {
        if ($InputObject -is [System.Collections.IDictionary] -and $InputObject.Contains($Name)) {
            return $InputObject[$Name]
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

function Get-WpdFirstProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    foreach ($name in $Names) {
        $value = Get-WpdObjectProperty -InputObject $InputObject -Name $name
        if ($null -ne $value) {
            return $value
        }
    }
    return $null
}

function Get-WpdPrivacyLevel {
    param([AllowEmptyString()][string]$Level = 'Standard')

    if ([string]::IsNullOrWhiteSpace($Level)) {
        return 'Standard'
    }
    foreach ($known in @('Standard', 'Redacted', 'Full')) {
        if ($known -eq $Level) {
            return $known
        }
    }
    return 'Standard'
}

function Test-WpdSafeRelativePath {
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
    if ($normalized -match '[:*?"<>|]') {
        return $false
    }
    foreach ($segment in $normalized.Split([char]92)) {
        if ($segment -eq '.' -or $segment -eq '..') {
            return $false
        }
    }
    return $true
}

function Get-WpdSha256Text {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Value)
        $digest = $algorithm.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Protect-WpdPath {
    param(
        [AllowNull()][string]$Path,
        [Alias('Level')][AllowEmptyString()][string]$PrivacyLevel = 'Standard'
    )

    if ($null -eq $Path) {
        return $null
    }
    $level = Get-WpdPrivacyLevel -Level $PrivacyLevel
    if ($level -eq 'Redacted') {
        return ('sha256:' + (Get-WpdSha256Text -Value $Path))
    }
    return $Path
}

function Test-WpdSensitiveFieldName {
    param([AllowEmptyString()][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }
    return ($Name -match '(?i)(password|passwd|secret|token|cookie|credential|authorization|auth[-_ ]?header|api[-_ ]?key|access[-_ ]?key|connection[-_ ]?string|session[-_ ]?key|private[-_ ]?key|document[-_ ]?content|browser[-_ ]?history|mail[-_ ]?box)')
}

function Protect-WpdPrivacyRecord {
    param(
        [AllowNull()][object]$Record,
        [Alias('Level')][AllowEmptyString()][string]$PrivacyLevel = 'Standard',
        [switch]$AllowFull
    )

    if ($null -eq $Record) {
        return $null
    }
    $level = Get-WpdPrivacyLevel -Level $PrivacyLevel
    if ($level -eq 'Full' -and -not $AllowFull) {
        throw 'Full privacy requires explicit -AllowFull opt-in.'
    }
    if ($Record -is [string] -or $Record -is [ValueType]) {
        return $Record
    }
    if ($Record -is [System.Array]) {
        $array = @()
        foreach ($value in @($Record)) {
            $array += Protect-WpdPrivacyRecord -Record $value -PrivacyLevel $level -AllowFull:$AllowFull
        }
        return , $array
    }

    $copy = [ordered]@{}
    if ($Record -is [System.Collections.IDictionary]) {
        $propertyNames = @($Record.Keys | ForEach-Object { [string]$_ })
    }
    else {
        $propertyNames = @($Record.PSObject.Properties | ForEach-Object { $_.Name })
    }
    foreach ($name in $propertyNames) {
        if (Test-WpdSensitiveFieldName -Name $name) {
            continue
        }
        if ($level -eq 'Redacted' -and $name -match '(?i)(commandline|command)') {
            continue
        }
        $value = if ($Record -is [System.Collections.IDictionary]) {
            $Record[$name]
        }
        else {
            Get-WpdObjectProperty -InputObject $Record -Name $name
        }
        if ($level -eq 'Redacted' -and $name -match '(?i)(username|user|account|path|filename|directory|folder|root|location)') {
            if ($null -ne $value -and ($value -is [string] -or $value -is [ValueType])) {
                $copy[$name] = Protect-WpdPath -Path ([string]$value) -PrivacyLevel 'Redacted'
                continue
            }
        }
        $copy[$name] = Protect-WpdPrivacyRecord -Record $value -PrivacyLevel $level -AllowFull:$AllowFull
    }
    return [pscustomobject]$copy
}

function New-WpdEvidenceRecord {
    param(
        [Alias('ArtifactName')][AllowEmptyString()][string]$Artifact,
        [Alias('EvidencePath')][AllowEmptyString()][string]$Path,
        [AllowEmptyString()][string]$Metric,
        [AllowNull()][object]$Value,
        [AllowNull()][object]$WindowStartUtc,
        [AllowNull()][object]$WindowEndUtc,
        [string]$Collector,
        [AllowEmptyString()][string]$Quality = 'unavailable',
        [string]$Source,
        [string]$EvidenceId
    )

    $safePath = Test-WpdSafeRelativePath -Path $Path
    if (-not $safePath) {
        return [pscustomobject]@{
            id = $null
            status = 'unavailable'
            coverage = 'unavailable'
            artifact = $Artifact
            path = $null
            metric = $Metric
            value = $null
            windowStartUtc = $null
            windowEndUtc = $null
            collector = $Collector
            quality = 'unavailable'
            source = $Source
            provenance = $null
            reason = 'unsafe-path'
        }
    }
    if ([string]::IsNullOrWhiteSpace($Artifact) -or [string]::IsNullOrWhiteSpace($Metric)) {
        return [pscustomobject]@{
            id = $null
            status = 'unavailable'
            coverage = 'unavailable'
            artifact = $Artifact
            path = $Path
            metric = $Metric
            value = $null
            windowStartUtc = $null
            windowEndUtc = $null
            collector = $Collector
            quality = 'unavailable'
            source = $Source
            provenance = $null
            reason = 'incomplete-provenance'
        }
    }

    $start = ConvertTo-WpdIsoTimestamp -Value $WindowStartUtc
    $end = ConvertTo-WpdIsoTimestamp -Value $WindowEndUtc
    if (($null -ne $WindowStartUtc -and $null -eq $start) -or ($null -ne $WindowEndUtc -and $null -eq $end)) {
        return [pscustomobject]@{
            id = $null
            status = 'unavailable'
            coverage = 'unavailable'
            artifact = $Artifact
            path = $Path
            metric = $Metric
            value = $null
            windowStartUtc = $start
            windowEndUtc = $end
            collector = $Collector
            quality = 'unavailable'
            source = $Source
            provenance = $null
            reason = 'invalid-window-time'
        }
    }
    if ($null -eq $Value) {
        return [pscustomobject]@{
            id = $null
            status = 'unavailable'
            coverage = 'unavailable'
            artifact = $Artifact
            path = $Path
            metric = $Metric
            value = $null
            windowStartUtc = $start
            windowEndUtc = $end
            collector = $Collector
            quality = 'unavailable'
            source = $Source
            provenance = $null
            reason = 'missing-measurement'
        }
    }

    $normalizedQuality = [string]$Quality
    if ($normalizedQuality -eq 'healthy' -or $script:WpdCoverageStates -notcontains $normalizedQuality) {
        $normalizedQuality = 'unavailable'
    }
    if ($normalizedQuality -eq 'unavailable' -or $normalizedQuality -eq 'not-collected' -or $normalizedQuality -eq 'unsupported') {
        $evidenceStatus = 'unavailable'
    }
    else {
        $evidenceStatus = $normalizedQuality
    }
    if ([string]::IsNullOrWhiteSpace($EvidenceId)) {
        $identity = '{0}|{1}|{2}|{3}|{4}' -f $Artifact, $Path, $Metric, $start, $end
        $EvidenceId = 'evidence-' + (Get-WpdSha256Text -Value $identity).Substring(0, 16)
    }
    return [pscustomobject]@{
        id = $EvidenceId
        status = $evidenceStatus
        coverage = $normalizedQuality
        artifact = $Artifact
        path = $Path
        metric = $Metric
        value = $Value
        windowStartUtc = $start
        windowEndUtc = $end
        collector = $Collector
        quality = $normalizedQuality
        source = $Source
        provenance = [pscustomobject]@{
            artifact = $Artifact
            path = $Path
            metric = $Metric
            collector = $Collector
        }
        reason = $null
    }
}

function Get-WpdDataQualitySummary {
    param([AllowNull()][object[]]$Records)

    $items = @($Records | Where-Object { $null -ne $_ })
    $completeCount = 0
    $partialCount = 0
    $unavailableCount = 0
    $notCollectedCount = 0
    $unsupportedCount = 0
    $usableCount = 0
    $reasons = @()
    $warnings = @()
    $errors = @()
    foreach ($item in $items) {
        $coverage = [string](Get-WpdObjectProperty -InputObject $item -Name 'coverage')
        switch ($coverage) {
            'complete' { $completeCount++ }
            'partial' { $partialCount++ }
            'not-collected' { $notCollectedCount++ }
            'unsupported' { $unsupportedCount++ }
            default { $unavailableCount++ }
        }
        $isUsable = Get-WpdObjectProperty -InputObject $item -Name 'isUsable'
        if ($null -eq $isUsable) {
            $isUsable = ($coverage -eq 'complete' -or $coverage -eq 'partial')
        }
        if ([bool]$isUsable) {
            $usableCount++
        }
        $reasons += @(Get-WpdObjectProperty -InputObject $item -Name 'reasons' -Default @())
        $warnings += @(Get-WpdObjectProperty -InputObject $item -Name 'warnings' -Default @())
        $errors += @(Get-WpdObjectProperty -InputObject $item -Name 'errors' -Default @())
    }

    if ($items.Count -eq 0) {
        $overall = 'unavailable'
        $overallStatus = 'unavailable'
    }
    elseif ($completeCount -eq $items.Count) {
        $overall = 'complete'
        $overallStatus = 'success'
    }
    elseif (($completeCount + $partialCount) -gt 0) {
        $overall = 'partial'
        $overallStatus = 'partial'
    }
    elseif ($unsupportedCount -eq $items.Count) {
        $overall = 'unsupported'
        $overallStatus = 'unsupported'
    }
    elseif ($notCollectedCount -eq $items.Count) {
        $overall = 'not-collected'
        $overallStatus = 'not-collected'
    }
    else {
        $overall = 'unavailable'
        $overallStatus = 'unavailable'
    }

    return [pscustomobject]@{
        status = $overallStatus
        coverage = $overall
        totalCollectors = $items.Count
        completeCount = $completeCount
        partialCount = $partialCount
        unavailableCount = $unavailableCount
        notCollectedCount = $notCollectedCount
        unsupportedCount = $unsupportedCount
        usableCollectorCount = $usableCount
        records = $items
        reasons = @($reasons | Select-Object -Unique)
        warnings = @($warnings)
        errors = @($errors)
    }
}

function New-WpdCollectorResult {
    param(
        [Alias('Name')][string]$Collector,
        [string]$Status = 'unavailable',
        [string]$Coverage,
        [AllowNull()][object]$Records,
        [AllowNull()][object[]]$Warnings = @(),
        [AllowNull()][object[]]$Errors = @(),
        [AllowNull()][object]$StartedUtc,
        [AllowNull()][object]$CompletedUtc,
        [AllowNull()][object]$DurationMs,
        [string]$Source,
        [string]$Reason,
        [switch]$AllowEmpty
    )

    $items = @(ConvertTo-WpdArray -Value $Records)
    $normalizedStatus = [string]$Status
    if ($normalizedStatus -eq 'healthy') {
        $normalizedStatus = 'unavailable'
    }
    elseif ($normalizedStatus -eq 'failed') {
        $normalizedStatus = 'error'
    }
    elseif ($normalizedStatus -eq 'completed') {
        $normalizedStatus = 'success'
    }
    if ($script:WpdStatusValues -notcontains $normalizedStatus) {
        $normalizedStatus = 'unavailable'
    }
    if ($normalizedStatus -eq 'success' -and $items.Count -eq 0 -and -not $AllowEmpty) {
        $normalizedStatus = 'unavailable'
    }
    if ([string]::IsNullOrWhiteSpace($Coverage)) {
        if ($normalizedStatus -eq 'success') {
            $normalizedCoverage = 'complete'
        }
        else {
            $normalizedCoverage = 'unavailable'
        }
    }
    else {
        $normalizedCoverage = [string]$Coverage
    }
    if ($normalizedCoverage -eq 'healthy') {
        $normalizedCoverage = 'unavailable'
    }

    $start = ConvertTo-WpdIsoTimestamp -Value $StartedUtc
    $end = ConvertTo-WpdIsoTimestamp -Value $CompletedUtc
    $invalidWindowTime = (($null -ne $StartedUtc -and $null -eq $start) -or ($null -ne $CompletedUtc -and $null -eq $end))
    $invalidWindowOrder = $false
    if (-not $invalidWindowTime -and $null -ne $start -and $null -ne $end) {
        $startDateForValidation = ConvertTo-WpdUtcDateTime -Value $start
        $endDateForValidation = ConvertTo-WpdUtcDateTime -Value $end
        $invalidWindowOrder = ($null -eq $startDateForValidation -or $null -eq $endDateForValidation -or $endDateForValidation -lt $startDateForValidation)
    }
    if ($invalidWindowTime -or $invalidWindowOrder) {
        if ([string]::IsNullOrWhiteSpace($Reason)) {
            $Reason = if ($invalidWindowTime) { 'invalid-window-time' } else { 'invalid-window-order' }
        }
        if ($normalizedStatus -eq 'success' -or $normalizedStatus -eq 'partial') {
            $normalizedStatus = 'partial'
            $normalizedCoverage = 'partial'
        }
    }
    $elapsed = $null
    if ($null -ne $DurationMs) {
        try { $elapsed = [int64]$DurationMs } catch { $elapsed = $null }
    }
    if ($null -eq $elapsed -and $null -ne $start -and $null -ne $end) {
        $startDate = ConvertTo-WpdUtcDateTime -Value $start
        $endDate = ConvertTo-WpdUtcDateTime -Value $end
        if ($null -ne $startDate -and $null -ne $endDate -and $endDate -ge $startDate) {
            $elapsed = [int64][math]::Round(($endDate - $startDate).TotalMilliseconds)
        }
    }
    if ($null -eq $elapsed) {
        $elapsed = 0
    }

    return [pscustomobject]@{
        collector = $Collector
        status = $normalizedStatus
        coverage = $normalizedCoverage
        startedUtc = $start
        completedUtc = $end
        durationMs = $elapsed
        duration_ms = $elapsed
        records = $items
        recordCount = $items.Count
        warnings = ConvertTo-WpdArray -Value $Warnings
        errors = ConvertTo-WpdArray -Value $Errors
        source = $Source
        reason = $Reason
    }
}

Export-ModuleMember -Function *
