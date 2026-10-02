#Requires -Version 5.1
<#
.SYNOPSIS
    Targeted reliability event analysis: WHEA, WER, boot/power and change history.

.DESCRIPTION
    Bounded, targeted event collection over the documented reliability and
    serviceability providers (Microsoft-Windows-WHEA-Logger,
    Microsoft-Windows-Diagnostics-Performance/Operational,
    Microsoft-Windows-Kernel-Power, Microsoft-Windows-Kernel-PnP,
    Microsoft-Windows-WindowsUpdateClient, Application Error, Application Hang,
    Windows Error Reporting, MsiInstaller and Service Control Manager).

    Design rules carried by this module:

    - Every query is bounded (explicit window, explicit maximum event count,
      newest first) and runs inside its own failure envelope, so one
      unrenderable provider or one failed query cannot abort a sibling query.
    - A record whose message text cannot be rendered keeps its raw event XML;
      the record is still reported, labelled and readable, never dropped.
    - A failed query is 'unavailable' and an empty query is
      'no-events-observed'. Neither is health: this module never emits a
      healthy verdict, and WHEA absence is explicitly not health.
    - Repetitive events are grouped with first/last/count and incident
      proximity instead of being collapsed into a single line.
    - Change history (driver, update, software, service) is correlated with the
      symptom date, and every correlation states that correlation is not
      causation. Nothing here recommends or performs remediation.

.NOTES
    ASCII only. No BOM. Line feeds only. No write, repair or remediation cmdlet.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Section 1: vocabulary
# ---------------------------------------------------------------------------

$script:WpdEventCoverageStates = @(
    'complete'
    'partial'
    'unavailable'
    'not-collected'
    'unsupported'
)

$script:WpdEventStatusValues = @(
    'success'
    'partial'
    'unavailable'
    'not-collected'
    'unsupported'
    'error'
)

$script:WpdEventOutcomeValues = @(
    'events-observed'
    'no-events-observed'
    'unavailable'
    'unsupported'
)

# Refusal threshold for one bounded query. A request above it is invalid, never
# silently clamped, so a caller can never mistake a truncated answer for a
# complete one.
$script:WpdEventMaximumEvents = 2000

function Get-WpdEventCoverageStates {
    <#
    .SYNOPSIS
        The coverage vocabulary used by every event envelope.
    #>
    [CmdletBinding()]
    param()

    return $script:WpdEventCoverageStates
}

function Get-WpdEventStatusValues {
    <#
    .SYNOPSIS
        The status vocabulary used by every event envelope.
    #>
    [CmdletBinding()]
    param()

    return $script:WpdEventStatusValues
}

function Get-WpdEventOutcomeValues {
    <#
    .SYNOPSIS
        The outcome vocabulary for a bounded event query.

    .DESCRIPTION
        'events-observed' and 'no-events-observed' describe a query that ran
        successfully; 'unavailable' and 'unsupported' describe a query that did
        not produce a usable answer. 'no-events-observed' is deliberately not
        'healthy': absence of matching events is not evidence of health.
    #>
    [CmdletBinding()]
    param()

    return $script:WpdEventOutcomeValues
}

function Test-WpdEventWindowsHost {
    <#
    .SYNOPSIS
        True when the current host can execute Windows event log providers.

    .DESCRIPTION
        Platform detection only. No provider is queried, so the module can be
        imported and inspected on a non-Windows host.
    #>
    [CmdletBinding()]
    param()

    try {
        return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
    }
    catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# Section 2: shared helpers
# ---------------------------------------------------------------------------

function Get-WpdEventMaximumEvents {
    <#
    .SYNOPSIS
        The hard cap on the number of records one targeted query may return.

    .DESCRIPTION
        A bounded query is the whole point of targeted collection: the cap is a
        refusal threshold, not a silent truncation point. A request above the cap
        is reported invalid instead of being clamped, so no caller can believe it
        received every record when it did not.
    #>
    [CmdletBinding()]
    param()

    return $script:WpdEventMaximumEvents
}

function Get-WpdEventObjectProperty {
    <#
    .SYNOPSIS
        Read one property from an object, dictionary or XML node, or $null.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }
    try {
        if ($InputObject -is [System.Collections.IDictionary]) {
            if ($InputObject.Contains($Name)) {
                return $InputObject[$Name]
            }
            return $null
        }
        $property = $InputObject.PSObject.Properties[$Name]
        if ($null -ne $property) {
            return $property.Value
        }
    }
    catch {
        return $null
    }
    return $null
}

function Get-WpdEventFirstProperty {
    <#
    .SYNOPSIS
        The first non-null value among the named properties of an object.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    foreach ($name in $Names) {
        $value = Get-WpdEventObjectProperty -InputObject $InputObject -Name $name
        if ($null -ne $value) {
            return $value
        }
    }
    return $null
}

function ConvertTo-WpdEventUtcDateTime {
    <#
    .SYNOPSIS
        Parse a value into a UTC DateTime, or $null when it is not a timestamp.

    .DESCRIPTION
        Malformed timestamps return $null rather than throwing and rather than
        being coerced to "now": an unparsable event time must surface as a data
        quality problem, never as a plausible-looking time.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [datetime]) {
        $date = [datetime]$Value
        if ($date.Kind -eq [System.DateTimeKind]::Unspecified) {
            return ([datetime]::SpecifyKind($date, [System.DateTimeKind]::Utc))
        }
        return $date.ToUniversalTime()
    }
    if ($Value -is [datetimeoffset]) {
        return ([datetimeoffset]$Value).UtcDateTime
    }
    if ($Value -is [string] -and [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.ToUniversalTime()
    }
    return $null
}

function ConvertTo-WpdEventIsoTimestamp {
    <#
    .SYNOPSIS
        Render a value as an ISO-8601 UTC timestamp, or $null when unparsable.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    $utc = ConvertTo-WpdEventUtcDateTime -Value $Value
    if ($null -eq $utc) {
        return $null
    }
    return $utc.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Resolve-WpdEventCoverageState {
    <#
    .SYNOPSIS
        Map a status plus observation counts onto the shared coverage vocabulary.

    .DESCRIPTION
        Deliberately identical in behaviour to the shared common helper: any
        failure-ish or 'healthy' status collapses to 'unavailable', and zero
        observed records is never 'complete'.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Status = 'success',
        [int]$ExpectedEvents = 0,
        [int]$ObservedEvents = 0,
        [int]$GapCount = 0,
        [int]$DroppedCount = 0
    )

    $normalized = if ($null -eq $Status) { '' } else { $Status.ToLowerInvariant() }
    if ($normalized -eq 'not-collected' -or $normalized -eq 'unsupported') {
        return $normalized
    }
    if ($normalized -in @('error', 'failed', 'unavailable', 'healthy', 'no-events-observed')) {
        return 'unavailable'
    }
    if ($normalized -ne 'success' -and $normalized -ne 'partial') {
        return 'unavailable'
    }
    if ($ObservedEvents -le 0) {
        return 'unavailable'
    }
    if ($normalized -eq 'partial') {
        return 'partial'
    }
    if ($ExpectedEvents -gt 0 -and $ObservedEvents -lt $ExpectedEvents) {
        return 'partial'
    }
    if ($GapCount -gt 0 -or $DroppedCount -gt 0) {
        return 'partial'
    }
    return 'complete'
}

# ---------------------------------------------------------------------------
# Section 3: targeted provider table
# ---------------------------------------------------------------------------

function Get-WpdEventProviderTable {
    <#
    .SYNOPSIS
        The documented, read-only targeted event profiles.

    .DESCRIPTION
        Each profile is a bounded query target: one log, the documented provider
        name(s) that write the reliability records, the event ids this module
        understands and a statement of what the profile is evidence for. Nothing
        is queried while building the table, and every profile reads through
        EventLogReader/Get-WinEvent: there is no provider invalidation, no log
        clear, no counter reset and no repair command anywhere in the table.

        Event ids are listed so the query is narrow. They are classification
        hints for the same provider's own records; a classification that is not
        present in the record itself is reported as unclassified rather than
        guessed from the id alone.
    #>
    [CmdletBinding()]
    param()

    return @(
        [pscustomobject]@{
            name              = 'whea'
            logName           = 'System'
            providers         = @('Microsoft-Windows-WHEA-Logger')
            eventIds          = @(1, 17, 18, 19, 20, 47)
            purpose           = 'WHEA hardware error records, corrected versus uncorrected, and their recurrence'
            source            = 'EventLogReader XPath on System for Microsoft-Windows-WHEA-Logger with a TimeCreated window'
            requiredElevation = 'standard'
            elevationReason   = 'The System log is readable without elevation on a default installation'
            windowsOnly       = $true
            defaultMaxEvents  = 500
        }
        [pscustomobject]@{
            name              = 'diagnostics-performance'
            logName           = 'Microsoft-Windows-Diagnostics-Performance/Operational'
            providers         = @('Microsoft-Windows-Diagnostics-Performance')
            eventIds          = @(100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 200, 203, 206)
            purpose           = 'Boot and shutdown duration, degradation and the driver/service/application component named in the report'
            source            = 'EventLogReader XPath on Microsoft-Windows-Diagnostics-Performance/Operational with a TimeCreated window'
            requiredElevation = 'standard'
            elevationReason   = 'Reading an inbox operational log does not require elevation'
            windowsOnly       = $true
            defaultMaxEvents  = 500
        }
        [pscustomobject]@{
            name              = 'kernel-power'
            logName           = 'System'
            providers         = @('Microsoft-Windows-Kernel-Power')
            eventIds          = @(41, 42, 107, 109, 131)
            purpose           = 'Unexpected shutdown and power transition context around a crash or freeze'
            source            = 'EventLogReader XPath on System for Microsoft-Windows-Kernel-Power with a TimeCreated window'
            requiredElevation = 'standard'
            elevationReason   = 'The System log is readable without elevation on a default installation'
            windowsOnly       = $true
            defaultMaxEvents  = 200
        }
        [pscustomobject]@{
            name              = 'applications'
            logName           = 'Application'
            providers         = @('Application Error', 'Application Hang', 'Windows Error Reporting')
            eventIds          = @(1000, 1002, 1001)
            purpose           = 'WER application crash, hang and LiveKernelEvent reports with their bucket and signature metadata'
            source            = 'EventLogReader XPath on Application for the WER providers with a TimeCreated window'
            requiredElevation = 'standard'
            elevationReason   = 'The Application log is readable without elevation on a default installation'
            windowsOnly       = $true
            defaultMaxEvents  = 500
        }
        [pscustomobject]@{
            name              = 'change-history'
            logName           = 'System'
            providers         = @('Microsoft-Windows-Kernel-PnP', 'Microsoft-Windows-WindowsUpdateClient', 'MsiInstaller', 'Service Control Manager', 'Microsoft-Windows-UserPnp')
            eventIds          = @(400, 410, 411, 430, 431, 19, 20, 7045, 11707, 11708, 11724, 20001, 20003, 20009)
            purpose           = 'Driver, device, update, software and service installation change timeline'
            source            = 'EventLogReader XPath on System for the Kernel-PnP/UpdateClient/SCM/UserPnp providers with a TimeCreated window, plus the Application-log MsiInstaller records'
            requiredElevation = 'standard'
            elevationReason   = 'The System log is readable without elevation on a default installation'
            windowsOnly       = $true
            defaultMaxEvents  = 500
        }
    )
}

function Get-WpdEventProviderProfile {
    <#
    .SYNOPSIS
        One provider profile by name, or $null when the name is unknown.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Profile)

    foreach ($entry in @(Get-WpdEventProviderTable)) {
        if ([string]::Equals([string]$entry.name, $Profile, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $entry
        }
    }
    return $null
}

function New-WpdEventQuery {
    <#
    .SYNOPSIS
        Build one bounded, targeted event query for a documented profile.

    .DESCRIPTION
        A query always carries an explicit UTC window, an explicit maximum event
        count inside the cap and an XPath that filters on the provider, the
        event ids and the window. There is no default lookback: an unbounded
        request is an unavailable query, not a full-log scan.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Profile,
        [AllowNull()][object]$StartUtc,
        [AllowNull()][object]$EndUtc,
        [AllowNull()][object]$MaxEvents,
        [switch]$AllowEmpty
    )

    $descriptor = Get-WpdEventProviderProfile -Profile $Profile
    if ($null -eq $descriptor) {
        throw [System.ArgumentException]::new(
            "unknown event profile '$Profile'; valid profiles are $((@(Get-WpdEventProviderTable) | ForEach-Object { $_.name }) -join ', ')"
        )
    }

    $cap = $script:WpdEventMaximumEvents
    $maxValue = if ($null -eq $MaxEvents) { [int]$descriptor.defaultMaxEvents } else { 0 }
    if ($null -ne $MaxEvents) {
        try { $maxValue = [int]$MaxEvents }
        catch { $maxValue = -1 }
    }

    $base = [ordered]@{
        profile           = [string]$descriptor.name
        logName           = [string]$descriptor.logName
        providers         = @($descriptor.providers)
        eventIds          = @($descriptor.eventIds)
        purpose           = [string]$descriptor.purpose
        source            = [string]$descriptor.source
        requiredElevation = [string]$descriptor.requiredElevation
        windowsOnly       = [bool]$descriptor.windowsOnly
    }

    $invalid = {
        param([string]$Reason)

        return [pscustomobject]@{
            status            = 'unavailable'
            coverage          = 'unavailable'
            outcome           = 'unavailable'
            reason            = $Reason
            reasons           = @($Reason)
            profile           = $base['profile']
            logName           = $base['logName']
            providers         = $base['providers']
            eventIds          = $base['eventIds']
            purpose           = $base['purpose']
            source            = $base['source']
            requiredElevation = $base['requiredElevation']
            windowsOnly       = $base['windowsOnly']
            maxEvents         = $maxValue
            maximumEvents     = $cap
            windowStartUtc    = $null
            windowEndUtc      = $null
            durationSeconds   = $null
            xpath             = $null
            bounded           = $false
            allowEmpty        = [bool]$AllowEmpty
        }
    }

    if ($null -eq $StartUtc -or $null -eq $EndUtc) {
        return (& $invalid 'window-required')
    }

    $start = ConvertTo-WpdEventUtcDateTime -Value $StartUtc
    $end = ConvertTo-WpdEventUtcDateTime -Value $EndUtc
    if ($null -eq $start -or $null -eq $end) {
        return (& $invalid 'invalid-window-time')
    }
    if ($end -lt $start) {
        return (& $invalid 'window-end-before-start')
    }
    if ($maxValue -le 0) {
        return (& $invalid 'invalid-max-events')
    }
    if ($maxValue -gt $cap) {
        $maxValue = $cap
        return (& $invalid 'max-events-above-cap')
    }

    $startIso = $start.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $endIso = $end.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $providerFilter = @($base['providers'] | ForEach-Object { "Provider[@Name='$($_)']" }) -join ' or '
    $idFilter = @($base['eventIds'] | ForEach-Object { "EventID=$($_)" }) -join ' or '
    $xpath = "*[System[($providerFilter) and ($idFilter) and TimeCreated[@SystemTime>='$startIso' and @SystemTime<='$endIso']]]"

    return [pscustomobject]@{
        status            = 'complete'
        coverage          = 'complete'
        outcome           = 'events-observed'
        reason            = $null
        reasons           = @()
        profile           = $base['profile']
        logName           = $base['logName']
        providers         = $base['providers']
        eventIds          = $base['eventIds']
        purpose           = $base['purpose']
        source            = $base['source']
        requiredElevation = $base['requiredElevation']
        windowsOnly       = $base['windowsOnly']
        maxEvents         = $maxValue
        maximumEvents     = $cap
        windowStartUtc    = $startIso
        windowEndUtc      = $endIso
        durationSeconds   = [int64][math]::Round(($end - $start).TotalSeconds)
        xpath             = $xpath
        bounded           = $true
        allowEmpty        = [bool]$AllowEmpty
    }
}

# ---------------------------------------------------------------------------
# Section 4: record normalization (raw XML and malformed data survive)
# ---------------------------------------------------------------------------

function Get-WpdEventLevelName {
    <#
    .SYNOPSIS
        The level name for a numeric event level, or a neutral placeholder.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Level)

    $value = $null
    try { $value = [int]$Level } catch { $value = $null }
    if ($null -eq $value) {
        return $null
    }
    switch ($value) {
        0 { return 'LogAlways' }
        1 { return 'Critical' }
        2 { return 'Error' }
        3 { return 'Warning' }
        4 { return 'Information' }
        5 { return 'Verbose' }
        default { return "Level$value" }
    }
}

function Get-WpdEventXmlEventData {
    <#
    .SYNOPSIS
        Parse the EventData/UserData name-value pairs out of a raw event XML.

    .DESCRIPTION
        This is what keeps an unrenderable provider usable: when Windows cannot
        resolve the provider's message-resource DLL, the XML still carries the
        structured values. A malformed payload returns an empty set and a status
        of 'invalid' rather than throwing, so the caller can keep the raw text.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$RawXml)

    $empty = [pscustomobject]@{ status = 'absent'; values = [ordered]@{} }
    if ($null -eq $RawXml -or [string]::IsNullOrWhiteSpace([string]$RawXml)) {
        return $empty
    }

    try {
        $document = [System.Xml.XmlDocument]::new()
        $document.LoadXml([string]$RawXml)
    }
    catch {
        return [pscustomobject]@{ status = 'invalid'; values = [ordered]@{} }
    }

    $values = [ordered]@{}
    try {
        foreach ($node in @($document.SelectNodes("//*[local-name()='Data']"))) {
            $name = $node.GetAttribute('Name')
            if ([string]::IsNullOrWhiteSpace($name)) {
                continue
            }
            $text = [string]$node.InnerText
            if ($values.Contains($name)) {
                $values[$name] = ([string]$values[$name] + '; ' + $text)
            }
            else {
                $values[$name] = $text
            }
        }
    }
    catch {
        return [pscustomobject]@{ status = 'invalid'; values = [ordered]@{} }
    }

    return [pscustomobject]@{ status = 'complete'; values = $values }
}

function ConvertTo-WpdEventSignatureToken {
    <#
    .SYNOPSIS
        Normalize text into a stable repetition signature fragment.

    .DESCRIPTION
        Digits, hex runs, GUIDs and whitespace runs are removed so two records
        that differ only in volatile values (a counter, a timestamp, a port)
        group together. Normalization is deliberately conservative: it never
        removes a device or component name, because that is the part a technician
        needs to tell one repeating fault from another.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Text)

    if ($null -eq $Text) {
        return ''
    }
    $value = ([string]$Text).ToLowerInvariant().Trim()
    if ($value.Length -eq 0) {
        return ''
    }
    $value = [regex]::Replace($value, '\{[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\}', '{guid}')
    $value = [regex]::Replace($value, '(?<![0-9a-z])0x[0-9a-f]+(?![0-9a-z])', '0xhex')
    $value = [regex]::Replace($value, '[0-9]+', '')
    $value = [regex]::Replace($value, '\s+', ' ')
    $value = $value.Trim()
    if ($value.Length -gt 120) {
        $value = $value.Substring(0, 120)
    }
    return $value
}

function ConvertTo-WpdEventRecord {
    <#
    .SYNOPSIS
        Normalize one raw event record into a citable WPD event record.

    .DESCRIPTION
        The record is never dropped and never silently upgraded:

        - When the provider cannot render its message, the raw XML is preserved
          and the EventData is parsed from it, so the fault path (device, error
          code) is still readable. messageSource states which of the two was
          used and coverage drops to 'partial'.
        - When neither the message nor the XML is usable, the record is still
          reported with reasons 'message-not-rendered' and 'no-structured-data'.
        - When the timestamp cannot be parsed, timeCreatedUtc stays $null, the
          record is marked malformedTime and any window membership check for it
          answers 'unavailable' - it can never be counted as an in-window event.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Event,
        [AllowEmptyString()][string]$LogName,
        [AllowEmptyString()][string]$Profile,
        [int]$MaxXmlChars = 8000,
        [AllowNull()][object[]]$SignatureFields = @()
    )

    $reasons = @()
    $timeValue = Get-WpdEventFirstProperty -InputObject $Event -Names @('TimeCreatedUtc', 'TimeCreated', 'Timestamp', 'TimeGenerated', 'DateTime')
    $timeUtc = ConvertTo-WpdEventUtcDateTime -Value $timeValue
    $malformedTime = $false
    $timeStatus = 'complete'
    if ($null -eq $timeUtc) {
        $timeStatus = 'unavailable'
        $malformedTime = $true
        $reasons += 'invalid-event-time'
    }

    $provider = [string](Get-WpdEventFirstProperty -InputObject $Event -Names @('ProviderName', 'Provider', 'SourceName', 'Source'))
    $eventIdValue = Get-WpdEventFirstProperty -InputObject $Event -Names @('Id', 'EventId', 'EventID')
    $eventId = $null
    try { $eventId = [int]$eventIdValue } catch { $eventId = $null }
    $levelValue = Get-WpdEventFirstProperty -InputObject $Event -Names @('Level', 'LevelValue')
    $level = $null
    try { $level = [int]$levelValue } catch { $level = $null }
    $levelName = [string](Get-WpdEventFirstProperty -InputObject $Event -Names @('LevelDisplayName', 'LevelName'))
    if ([string]::IsNullOrWhiteSpace($levelName)) {
        $levelName = Get-WpdEventLevelName -Level $level
    }

    $message = Get-WpdEventFirstProperty -InputObject $Event -Names @('Message', 'MessageText', 'Description')
    $messageText = if ($null -eq $message) { $null } else { [string]$message }
    $messageRendered = $true
    if ($null -eq $messageText -or [string]::IsNullOrWhiteSpace($messageText) -or $messageText -match '^\[message text unavailable') {
        $messageRendered = $false
        $messageText = $null
        $reasons += 'message-not-rendered'
    }

    $rawXml = Get-WpdEventFirstProperty -InputObject $Event -Names @('RawXml', 'Xml')
    if ($null -eq $rawXml -and $null -ne $Event) {
        try {
            $toXml = $Event.PSObject.Methods['ToXml']
            if ($null -ne $toXml) {
                $rawXml = $Event.ToXml()
            }
        }
        catch {
            $rawXml = $null
        }
    }
    $rawXmlText = if ($null -eq $rawXml) { $null } else { [string]$rawXml }
    if ($null -ne $rawXmlText -and $rawXmlText.Length -gt $MaxXmlChars) {
        $rawXmlText = $rawXmlText.Substring(0, $MaxXmlChars) + '<!-- truncated -->'
    }

    $parsedData = Get-WpdEventXmlEventData -RawXml $rawXmlText
    $eventData = $parsedData.values
    if ($parsedData.status -eq 'invalid') {
        $reasons += 'invalid-event-xml'
    }

    $messageSource = 'none'
    if ($messageRendered) {
        $messageSource = 'rendered'
    }
    elseif ($eventData.Count -gt 0) {
        $messageSource = 'xml-fallback'
    }
    else {
        $reasons += 'no-structured-data'
    }

    $signatureText = $null
    if ($messageRendered) {
        $signatureText = $messageText
    }
    elseif ($eventData.Count -gt 0) {
        $parts = @()
        foreach ($name in @($eventData.Keys | Select-Object -First 3)) {
            $parts += ("{0}={1}" -f $name, [string]$eventData[$name])
        }
        $signatureText = ($parts -join '; ')
    }
    $signatureDetail = ConvertTo-WpdEventSignatureToken -Text $signatureText

    $extraParts = @()
    foreach ($field in @(ConvertTo-WpdEventArray -Value $SignatureFields)) {
        $value = Get-WpdEventObjectProperty -InputObject $Event -Name ([string]$field)
        if ($null -ne $value) {
            $extraParts += ("{0}={1}" -f $field, (ConvertTo-WpdEventSignatureToken -Text $value))
        }
        elseif ($eventData.Contains([string]$field)) {
            $extraParts += ("{0}={1}" -f $field, (ConvertTo-WpdEventSignatureToken -Text $eventData[[string]$field]))
        }
    }
    if ($extraParts.Count -gt 0) {
        $signatureDetail = (@($signatureDetail) + @($extraParts)) -join '|'
    }

    if ([string]::IsNullOrWhiteSpace($LogName)) {
        $LogName = [string](Get-WpdEventFirstProperty -InputObject $Event -Names @('LogName', 'Log'))
    }

    $coverage = if ($reasons.Count -gt 0) { 'partial' } else { 'complete' }
    return [pscustomobject]@{
        profile         = $Profile
        logName         = $LogName
        provider        = $provider
        eventId         = $eventId
        level           = $level
        levelName       = $levelName
        timeCreatedUtc  = ConvertTo-WpdEventIsoTimestamp -Value $timeUtc
        timeStatus      = $timeStatus
        malformedTime   = $malformedTime
        message         = $messageText
        messageRendered = $messageRendered
        messageSource   = $messageSource
        rawXml          = $rawXmlText
        xmlStatus       = $parsedData.status
        eventData       = $eventData
        signature       = ("{0}|{1}|{2}" -f $provider, [string]$eventId, $signatureDetail)
        reasons         = @($reasons | Select-Object -Unique)
        coverage        = $coverage
        status          = if ($coverage -eq 'complete') { 'success' } else { 'partial' }
        isUsable        = $true
        sourceRecord    = $Event
    }
}

function ConvertTo-WpdEventArray {
    <#
    .SYNOPSIS
        Wrap a possibly-null, possibly-scalar value into an array.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return @()
    }
    return @($Value)
}

function Test-WpdEventWindowMembership {
    <#
    .SYNOPSIS
        'in-window', 'out-of-window' or 'unavailable' for one event time.

    .DESCRIPTION
        An out-of-window event is labelled, never dropped: the caller can compare
        what happened during the incident with what the machine does all day.
        An unparsable time or an unusable window is 'unavailable', which is not
        the same answer as 'out-of-window'.
    #>
    [CmdletBinding()]
    param(
        [Alias('Time', 'TimestampUtc')][AllowNull()][object]$EventTime,
        [Alias('WindowStartUtc')][AllowNull()][object]$WindowStart,
        [Alias('WindowEndUtc')][AllowNull()][object]$WindowEnd
    )

    $eventUtc = ConvertTo-WpdEventUtcDateTime -Value $EventTime
    $startUtc = ConvertTo-WpdEventUtcDateTime -Value $WindowStart
    $endUtc = ConvertTo-WpdEventUtcDateTime -Value $WindowEnd
    if ($null -eq $eventUtc -or $null -eq $startUtc -or $null -eq $endUtc -or $endUtc -lt $startUtc) {
        return 'unavailable'
    }
    if ($eventUtc -ge $startUtc -and $eventUtc -le $endUtc) {
        return 'in-window'
    }
    return 'out-of-window'
}

# ---------------------------------------------------------------------------
# Section 5: bounded query execution (one failure envelope per query)
# ---------------------------------------------------------------------------

function New-WpdEventProviderResult {
    <#
    .SYNOPSIS
        Build an explicit provider result, including a refusal or an absence.

    .DESCRIPTION
        A provider script block normally returns records. When it cannot query
        (log missing, access denied, provider absent) it returns this object so
        the caller does not have to guess the difference between "no events" and
        "could not look". An unknown status - in particular a 'healthy' verdict -
        is rejected outright.
    #>
    [CmdletBinding()]
    param(
        [string]$Status = 'success',
        [AllowEmptyString()][string]$Reason,
        [AllowNull()][object]$Items,
        [AllowEmptyString()][string]$Source,
        [AllowNull()][object[]]$Warnings = @()
    )

    $normalized = @($script:WpdEventStatusValues | Where-Object { $_ -eq $Status })
    if ($normalized.Count -eq 0) {
        throw [System.ArgumentException]::new(
            "unknown event status '$Status'; valid values are $($script:WpdEventStatusValues -join ', ')"
        )
    }

    return [pscustomobject]@{
        wpdEventProviderResult = $true
        status                 = $normalized[0]
        reason                 = $Reason
        items                  = @($Items)
        source                 = $Source
        warnings               = @($Warnings)
    }
}

function Invoke-WpdEventQuery {
    <#
    .SYNOPSIS
        Run one bounded query inside its own failure envelope.

    .DESCRIPTION
        Never throws for a provider-level problem. An exception becomes
        status 'error' with coverage 'unavailable', a stated provider refusal is
        preserved, a missing provider is 'unsupported', a matched-nothing query is
        'no-events-observed' and a bound-limited query is 'partial' with
        truncated set. The envelope always states healthClaim 'none': no outcome
        of this function is a health verdict.

        Records are normalized through ConvertTo-WpdEventRecord, so unrenderable
        records keep their raw XML, are counted separately and never disappear.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Query,
        [AllowNull()][scriptblock]$Collect,
        [AllowNull()][object[]]$SignatureFields = @()
    )

    $hostWindows = Test-WpdEventWindowsHost
    $emptyEnvelope = {
        param($Status, $Coverage, $Outcome, $Reason, [object[]]$Reasons, $Start, $End, $MaxEvents)

        return [pscustomobject]@{
            profile             = if ($null -ne $Query) { $Query.profile } else { $null }
            logName             = if ($null -ne $Query) { $Query.logName } else { $null }
            providers           = @()
            status              = $Status
            coverage            = $Coverage
            outcome             = $Outcome
            reason              = $Reason
            reasons             = @($Reasons)
            windowStartUtc      = $Start
            windowEndUtc        = $End
            maxEvents           = $MaxEvents
            bounded             = $true
            truncated           = $false
            emptyQuery          = ($Outcome -eq 'no-events-observed')
            recordCount         = 0
            renderedCount       = 0
            unrenderableCount   = 0
            malformedTimeCount  = 0
            neverHealthy        = $true
            healthClaim         = 'none'
            interpretation      = $Reason
            hostWindows         = $hostWindows
            source              = if ($null -ne $Query) { $Query.source } else { $null }
            durationMs          = 0
            records             = @()
            warnings            = @()
            errors              = @()
        }
    }

    if ($null -eq $Query) {
        return (& $emptyEnvelope 'unavailable' 'unavailable' 'unavailable' 'query-required' @('query-required') $null $null $null)
    }
    if ([string]$Query.status -ne 'complete') {
        $reason = if ([string]::IsNullOrWhiteSpace([string]$Query.reason)) { 'invalid-query' } else { [string]$Query.reason }
        return (& $emptyEnvelope 'unavailable' 'unavailable' 'unavailable' $reason @($reason) $null $null $Query.maxEvents)
    }
    if ($null -eq $Collect) {
        return (& $emptyEnvelope 'unsupported' 'unsupported' 'unsupported' 'provider-not-supplied' @('provider-not-supplied') $Query.windowStartUtc $Query.windowEndUtc $Query.maxEvents)
    }

    $warnings = @()
    $errors = @()
    $reasons = @()
    $items = @()
    $explicitStatus = $null
    $explicitReason = $null
    $providerSource = [string]$Query.source
    $startTicks = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $result = & $Collect
    }
    catch {
        $startTicks.Stop()
        $errors += [pscustomobject]@{
            stage   = 'query'
            profile = [string]$Query.profile
            logName = [string]$Query.logName
            message = $_.Exception.Message
        }
        $envelope = (& $emptyEnvelope 'error' 'unavailable' 'unavailable' 'provider-failed' @('provider-failed') $Query.windowStartUtc $Query.windowEndUtc $Query.maxEvents)
        $envelope.errors = $errors
        $envelope.durationMs = $startTicks.ElapsedMilliseconds
        return $envelope
    }

    $isProviderResult = $false
    if ($null -ne $result -and $null -ne $result.PSObject -and $null -ne $result.PSObject.Properties['wpdEventProviderResult']) {
        $isProviderResult = [bool]$result.PSObject.Properties['wpdEventProviderResult'].Value
    }

    if ($isProviderResult) {
        $warnings += @($result.warnings)
        if (-not [string]::IsNullOrWhiteSpace([string]$result.source)) {
            $providerSource = [string]$result.source
        }
        $providerStatus = [string]$result.status
        if ($providerStatus -eq 'success' -or $providerStatus -eq 'partial') {
            $items = @($result.items)
            if ($providerStatus -eq 'partial') {
                $reasons += 'provider-reported-partial'
            }
        }
        else {
            $explicitStatus = $providerStatus
            $explicitReason = if ([string]::IsNullOrWhiteSpace([string]$result.reason)) {
                ($providerStatus + ':' + [string]$Query.profile)
            }
            else {
                [string]$result.reason
            }
        }
    }
    else {
        $items = @(ConvertTo-WpdEventArray -Value $result)
    }

    $startTicks.Stop()

    if ($null -ne $explicitStatus) {
        if ($explicitStatus -eq 'unsupported') {
            $status = 'unsupported'
            $coverage = 'unsupported'
            $outcome = 'unsupported'
        }
        elseif ($explicitStatus -eq 'error') {
            $status = 'error'
            $coverage = 'unavailable'
            $outcome = 'unavailable'
            $errors += [pscustomobject]@{
                stage   = 'query'
                profile = [string]$Query.profile
                logName = [string]$Query.logName
                message = 'provider reported status error'
            }
        }
        elseif ($explicitStatus -eq 'not-collected') {
            $status = 'not-collected'
            $coverage = 'not-collected'
            $outcome = 'unavailable'
        }
        else {
            $status = 'unavailable'
            $coverage = 'unavailable'
            $outcome = 'unavailable'
        }
        $reasons += $explicitReason
        $envelope = (& $emptyEnvelope $status $coverage $outcome $explicitReason $reasons $Query.windowStartUtc $Query.windowEndUtc $Query.maxEvents)
        $envelope.warnings = $warnings
        $envelope.errors = $errors
        $envelope.durationMs = $startTicks.ElapsedMilliseconds
        $envelope.source = $providerSource
        return $envelope
    }

    $records = @()
    foreach ($item in $items) {
        if ($null -eq $item) {
            continue
        }
        $records += (ConvertTo-WpdEventRecord -Event $item -LogName ([string]$Query.logName) `
                -Profile ([string]$Query.profile) -SignatureFields $SignatureFields)
    }

    $recordCount = $records.Count
    $renderedCount = @($records | Where-Object { $_.messageRendered }).Count
    $unrenderableCount = $recordCount - $renderedCount
    $malformedTimeCount = @($records | Where-Object { $_.malformedTime }).Count
    $providers = @($records | ForEach-Object { $_.provider } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    $truncated = ($recordCount -ge [int]$Query.maxEvents)

    if ($recordCount -eq 0) {
        $reason = 'no-events-observed'
        $emptyResult = (& $emptyEnvelope 'unavailable' 'unavailable' 'no-events-observed' $reason @($reason) $Query.windowStartUtc $Query.windowEndUtc $Query.maxEvents)
        $emptyResult.interpretation = ('The bounded query completed and matched no {0} records. Absence of matching events is not evidence of health.' -f [string]$Query.profile)
        return $emptyResult
    }

    if ($unrenderableCount -gt 0) {
        $reasons += ('unrenderable-records:' + $unrenderableCount)
    }
    if ($malformedTimeCount -gt 0) {
        $reasons += ('malformed-time-records:' + $malformedTimeCount)
    }
    if ($truncated) {
        $reasons += 'bounded-limit-reached'
    }

    $reasons = @($reasons | Select-Object -Unique)
    if ($reasons.Count -gt 0) {
        $status = 'partial'
        $coverage = 'partial'
    }
    else {
        $status = 'success'
        $coverage = 'complete'
    }
    $interpretation = ('{0} matching record(s) were collected inside the bounded window; {1} could not be rendered and were kept with their raw XML.' -f $recordCount, $unrenderableCount)
    if ($truncated) {
        $interpretation = $interpretation + ' The maximum event count was reached, so more matching records may exist.'
    }

    return [pscustomobject]@{
        profile             = [string]$Query.profile
        logName             = [string]$Query.logName
        providers           = @($providers)
        status              = $status
        coverage            = $coverage
        outcome             = 'events-observed'
        reason              = if ($reasons.Count -gt 0) { $reasons[0] } else { $null }
        reasons             = @($reasons)
        windowStartUtc      = [string]$Query.windowStartUtc
        windowEndUtc        = [string]$Query.windowEndUtc
        maxEvents           = [int]$Query.maxEvents
        bounded             = $true
        truncated           = [bool]$truncated
        emptyQuery          = $false
        recordCount         = $recordCount
        renderedCount       = $renderedCount
        unrenderableCount   = $unrenderableCount
        malformedTimeCount  = $malformedTimeCount
        neverHealthy        = $true
        healthClaim         = 'none'
        interpretation      = $interpretation
        hostWindows         = $hostWindows
        source              = $providerSource
        durationMs          = $startTicks.ElapsedMilliseconds
        records             = @($records)
        warnings            = @($warnings)
        errors              = @($errors)
    }
}

# ---------------------------------------------------------------------------
# Section 6: repetitive event grouping
# ---------------------------------------------------------------------------

function Get-WpdEventMedianValue {
    <#
    .SYNOPSIS
        Median of a numeric list, or $null for an empty list.
    #>
    [CmdletBinding()]
    param([AllowNull()][object[]]$Values)

    $items = @($Values | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ } | Sort-Object)
    if ($items.Count -eq 0) {
        return $null
    }
    $middle = [int][math]::Floor($items.Count / 2)
    if ($items.Count % 2 -eq 1) {
        return $items[$middle]
    }
    return (($items[$middle - 1] + $items[$middle]) / 2)
}

function Group-WpdRepetitiveEvent {
    <#
    .SYNOPSIS
        Group records into repetitive event patterns with first/last/count,
        interval statistics and incident proximity.

    .DESCRIPTION
        Records are grouped by provider, event id and a normalized signature, so
        a fault that repeats with a different volatile value (a sequence number,
        a hex code, a timestamp) is one group instead of dozens of lines.

        Every occurrence keeps its own window label: 'inWindowCount' counts the
        occurrences inside the incident window and 'outOfWindowOccurrences' lists
        the ones outside it, because "this happens all day" and "this started
        during the incident" are different findings. A record whose timestamp
        cannot be parsed is retained in the group, counted in
        'unknownTimeCount' and never counted as in-window; a group holding one
        is explicitly partial.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object[]]$Records,
        [AllowNull()][object]$WindowStart,
        [AllowNull()][object]$WindowEnd,
        [AllowNull()][object]$MarkerUtc,
        [int]$MinimumCount = 3,
        [int]$MaxOccurrences = 25
    )

    $startUtc = ConvertTo-WpdEventUtcDateTime -Value $WindowStart
    $endUtc = ConvertTo-WpdEventUtcDateTime -Value $WindowEnd
    $markerUtc = ConvertTo-WpdEventUtcDateTime -Value $MarkerUtc
    $windowStatus = 'not-provided'
    if ($null -ne $WindowStart -or $null -ne $WindowEnd) {
        if ($null -ne $startUtc -and $null -ne $endUtc -and $endUtc -ge $startUtc) {
            $windowStatus = 'complete'
        }
        else {
            $windowStatus = 'invalid'
        }
    }

    $order = New-Object System.Collections.ArrayList
    $buckets = @{}
    foreach ($record in @(ConvertTo-WpdEventArray -Value $Records)) {
        if ($null -eq $record) {
            continue
        }
        $key = [string](Get-WpdEventObjectProperty -InputObject $record -Name 'signature')
        if ([string]::IsNullOrWhiteSpace($key)) {
            $provider = [string](Get-WpdEventObjectProperty -InputObject $record -Name 'provider')
            $eventId = [string](Get-WpdEventObjectProperty -InputObject $record -Name 'eventId')
            $key = ('{0}|{1}|' -f $provider, $eventId)
        }
        if (-not $buckets.ContainsKey($key)) {
            $buckets[$key] = New-Object System.Collections.ArrayList
            [void]$order.Add($key)
        }
        [void]$buckets[$key].Add($record)
    }

    $groups = @()
    foreach ($key in @($order)) {
        $members = @($buckets[$key])
        $times = @()
        $unknownTimes = @()
        foreach ($member in $members) {
            $timeUtc = ConvertTo-WpdEventUtcDateTime -Value (Get-WpdEventObjectProperty -InputObject $member -Name 'timeCreatedUtc')
            if ($null -eq $timeUtc) {
                $unknownTimes += $member
            }
            else {
                $times += $timeUtc
            }
        }
        $times = @($times | Sort-Object)
        $occurrences = @($times | ForEach-Object { ConvertTo-WpdEventIsoTimestamp -Value $_ })
        $occurrencesTruncated = $false
        if ($occurrences.Count -gt $MaxOccurrences) {
            $occurrences = @($occurrences[0..($MaxOccurrences - 1)])
            $occurrencesTruncated = $true
        }

        $count = $times.Count
        $firstUtc = if ($count -gt 0) { $times[0] } else { $null }
        $lastUtc = if ($count -gt 0) { $times[$count - 1] } else { $null }
        $spanSeconds = if ($count -gt 1) { [int64][math]::Round(($lastUtc - $firstUtc).TotalSeconds) } else { 0 }

        $inWindowCount = 0
        $outOfWindowCount = 0
        $outOfWindowOccurrences = @()
        foreach ($timeUtc in $times) {
            if ($windowStatus -eq 'complete') {
                if ($timeUtc -ge $startUtc -and $timeUtc -le $endUtc) {
                    $inWindowCount++
                }
                else {
                    $outOfWindowCount++
                    $outOfWindowOccurrences += (ConvertTo-WpdEventIsoTimestamp -Value $timeUtc)
                }
            }
        }

        $intervals = @()
        for ($index = 1; $index -lt $count; $index++) {
            $intervals += [double]($times[$index] - $times[$index - 1]).TotalSeconds
        }

        $nearestMinutes = $null
        $nearestSide = $null
        if ($null -ne $markerUtc -and $count -gt 0) {
            $nearest = $null
            $nearestDelta = $null
            foreach ($timeUtc in $times) {
                $delta = [double]($timeUtc - $markerUtc).TotalSeconds
                if ($null -eq $nearestDelta -or [math]::Abs($delta) -lt [math]::Abs($nearestDelta)) {
                    $nearestDelta = $delta
                    $nearest = $timeUtc
                }
            }
            $nearestMinutes = [math]::Round([math]::Abs($nearestDelta) / 60.0, 2)
            if ($nearestDelta -eq 0) { $nearestSide = 'at' }
            elseif ($nearestDelta -lt 0) { $nearestSide = 'before' }
            else { $nearestSide = 'after' }
        }

        $reasons = @()
        if ($unknownTimes.Count -gt 0) {
            $reasons += 'invalid-event-time'
        }
        if ($windowStatus -ne 'complete') {
            $reasons += ('incident-window-' + $windowStatus)
        }
        elseif ($inWindowCount -eq 0 -and $count -gt 0) {
            $reasons += 'all-occurrences-outside-incident-window'
        }
        $reasons = @($reasons | Select-Object -Unique)

        $placement = 'unknown'
        if ($count -gt 0) {
            if ($windowStatus -eq 'complete') {
                $placement = if ($inWindowCount -gt 0) { 'in-window' } else { 'outside-window' }
            }
            else {
                $placement = 'unlabelled'
            }
        }

        $repetitive = ($count -ge [math]::Max(2, $MinimumCount))
        $classification = if ($repetitive) { 'repetitive' } else { 'isolated' }
        $firstRecord = $members[0]
        $interpretation = if ($repetitive) {
            ('The same {0} event {1} repeated {2} time(s) between {3} and {4} (span {5}s); {6} of {7} occurrence(s) fall inside the incident window.' -f `
                [string]$firstRecord.provider, [string]$firstRecord.eventId, $count, `
                (ConvertTo-WpdEventIsoTimestamp -Value $firstUtc), (ConvertTo-WpdEventIsoTimestamp -Value $lastUtc), $spanSeconds, $inWindowCount, $count)
        }
        else {
            ('A single {0} event {1} was recorded at {2}; it is not a repetition pattern.' -f `
                [string]$firstRecord.provider, [string]$firstRecord.eventId, (ConvertTo-WpdEventIsoTimestamp -Value $firstUtc))
        }
        if ($unknownTimes.Count -gt 0) {
            $interpretation = $interpretation + (' {0} record(s) in this group carry an unparsable timestamp and are not counted as occurrences.' -f $unknownTimes.Count)
        }

        $groups += [pscustomobject]@{
            signature                = $key
            provider                 = [string]$firstRecord.provider
            eventId                  = $firstRecord.eventId
            level                    = $firstRecord.level
            levelName                = [string]$firstRecord.levelName
            classification           = $classification
            repetitive               = [bool]$repetitive
            count                    = $count
            retainedCount            = $members.Count
            unknownTimeCount         = $unknownTimes.Count
            firstUtc                 = ConvertTo-WpdEventIsoTimestamp -Value $firstUtc
            lastUtc                  = ConvertTo-WpdEventIsoTimestamp -Value $lastUtc
            spanSeconds              = $spanSeconds
            medianIntervalSeconds    = Get-WpdEventMedianValue -Values $intervals
            minimumIntervalSeconds   = if ($intervals.Count -gt 0) { [double]($intervals | Measure-Object -Minimum).Minimum } else { $null }
            maximumIntervalSeconds   = if ($intervals.Count -gt 0) { [double]($intervals | Measure-Object -Maximum).Maximum } else { $null }
            occurrences              = @($occurrences)
            occurrencesTruncated     = [bool]$occurrencesTruncated
            inWindowCount            = $inWindowCount
            outOfWindowCount         = $outOfWindowCount
            outOfWindowOccurrences   = @($outOfWindowOccurrences)
            windowStatus             = $windowStatus
            placement                = $placement
            nearestOccurrenceMinutes = $nearestMinutes
            nearestOccurrenceSide    = $nearestSide
            reasons                  = @($reasons)
            coverage                 = if ($reasons.Count -gt 0) { 'partial' } else { 'complete' }
            status                   = if ($reasons.Count -gt 0) { 'partial' } else { 'success' }
            interpretation           = $interpretation
            records                  = @($members)
            unknownTimeRecords       = @($unknownTimes)
        }
    }

    return @($groups | Sort-Object -Property @{ Expression = { $_.count }; Descending = $true }, @{ Expression = { $_.firstUtc }; Descending = $false })
}

# ---------------------------------------------------------------------------
# Section 7: WHEA corrected versus uncorrected recurrence
# ---------------------------------------------------------------------------

function Get-WpdWheaClassification {
    <#
    .SYNOPSIS
        Classify one WHEA record as corrected, uncorrected or unclassified.

    .DESCRIPTION
        The classification comes from what the record itself states: its rendered
        message or, when the provider cannot render, the structured EventData in
        its raw XML. 'uncorrected' and 'fatal' are tested before 'corrected'
        because the word 'uncorrected' contains 'corrected'.

        A record that never states its class is 'unclassified'. Windows records
        WHEA events whose severity is only decodable with the provider's message
        resources or the error-record decoder, and guessing 'corrected' from an
        event id would be exactly the kind of unsupported claim this toolkit
        refuses (plan R7). Event ids are hints the query uses to stay narrow, not
        a severity oracle.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Record)

    if ($null -eq $Record) {
        return [pscustomobject]@{
            classification       = 'unclassified'
            classificationReason = 'classification-not-in-record'
            component            = 'unidentified-hardware'
            text                 = $null
        }
    }

    $parts = @()
    $message = [string](Get-WpdEventObjectProperty -InputObject $Record -Name 'message')
    if (-not [string]::IsNullOrWhiteSpace($message)) {
        $parts += $message
    }
    $eventData = Get-WpdEventObjectProperty -InputObject $Record -Name 'eventData'
    if ($null -ne $eventData) {
        foreach ($name in @($eventData.Keys)) {
            $parts += ('{0}={1}' -f $name, [string]$eventData[$name])
        }
    }
    $text = ($parts -join ' | ')
    $lower = $text.ToLowerInvariant()

    $classification = 'unclassified'
    $reason = 'classification-not-in-record'
    if ($lower -match 'uncorrected' -or $lower -match '\bfatal\b') {
        $classification = 'uncorrected'
        $reason = 'record-states-uncorrected'
    }
    elseif ($lower -match 'corrected') {
        $classification = 'corrected'
        $reason = 'record-states-corrected'
    }

    return [pscustomobject]@{
        classification       = $classification
        classificationReason = $reason
        component            = (Get-WpdWheaComponentKey -Record $Record)
        text                 = if ([string]::IsNullOrWhiteSpace($text)) { $null } else { $text }
    }
}

function Get-WpdWheaComponentKey {
    <#
    .SYNOPSIS
        The hardware key a WHEA record belongs to, or a stated fallback.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Record)

    $eventData = Get-WpdEventObjectProperty -InputObject $Record -Name 'eventData'
    if ($null -ne $eventData) {
        foreach ($name in @('ErrorSource', 'Component', 'ErrorType', 'DeviceName', 'ErrorRecordSource')) {
            if ($eventData.Contains($name)) {
                $value = [string]$eventData[$name]
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    return $value
                }
            }
        }
    }
    return 'unidentified-hardware'
}

function Get-WpdWheaAnalysis {
    <#
    .SYNOPSIS
        Corrected versus uncorrected WHEA recurrence, per hardware component.

    .DESCRIPTION
        Recurrence is grouped by the hardware key the record names, and every
        group states whether the repeats are corrected, uncorrected, a mix of
        both or unclassified. An uncorrected record is never softened, an
        unclassified record is never promoted to a severity, and an empty result
        is a stated absence with 'absenceIsNotHealth' set: no WHEA records is not
        the same statement as no hardware problem, because the log may have
        rolled over, the query may not cover the boot, or the platform may not
        report hardware errors at all.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object[]]$Records,
        [AllowNull()][object]$MarkerUtc,
        [AllowNull()][object]$WindowStart,
        [AllowNull()][object]$WindowEnd,
        [AllowNull()][object]$Envelope
    )

    $items = @(ConvertTo-WpdEventArray -Value $Records)
    $correlationNotice = 'WHEA recurrence is reported as a correlation with the recorded window. Correlation is not causation: a WHEA record does not by itself prove that the hardware caused the reported symptom.'
    $absenceNotice = 'No WHEA records were observed in the bounded window. Absence of WHEA records is not evidence of health: the log may have rolled over, the query may not cover the boot, or the platform may not report hardware errors.'

    if ($items.Count -eq 0) {
        $queryCoverage = if ($null -ne $Envelope) { [string]$Envelope.coverage } else { 'unavailable' }
        $coverage = if ($queryCoverage -eq 'unsupported' -or $queryCoverage -eq 'not-collected') { $queryCoverage } else { 'unavailable' }
        return [pscustomobject]@{
            recordCount              = 0
            correctedCount           = 0
            uncorrectedCount         = 0
            unclassifiedCount        = 0
            unknownTimeCount         = 0
            severity                 = 'no-events'
            coverage                 = $coverage
            status                   = if ($coverage -eq 'complete') { 'success' } else { 'unavailable' }
            components               = @()
            recurringComponentCount  = 0
            uncorrectedComponents    = @()
            reasons                  = @('no-events-observed')
            absenceIsNotHealth       = $true
            causationDisclaimed      = $true
            correlationNotice        = $correlationNotice
            conclusion               = $absenceNotice
            interpretation           = $absenceNotice
        }
    }

    $order = New-Object System.Collections.ArrayList
    $buckets = @{}
    $correctedCount = 0
    $uncorrectedCount = 0
    $unclassifiedCount = 0
    $unknownTimeCount = 0
    $classificationCounts = @{}
    $timeCounts = @{}

    foreach ($record in $items) {
        $classification = Get-WpdWheaClassification -Record $record
        $key = [string]$classification.component
        if (-not $buckets.ContainsKey($key)) {
            $buckets[$key] = New-Object System.Collections.ArrayList
            $classificationCounts[$key] = @{ corrected = 0; uncorrected = 0; unclassified = 0 }
            $timeCounts[$key] = @()
            [void]$order.Add($key)
        }
        [void]$buckets[$key].Add($record)

        switch ($classification.classification) {
            'corrected' { $correctedCount++; $classificationCounts[$key].corrected++ }
            'uncorrected' { $uncorrectedCount++; $classificationCounts[$key].uncorrected++ }
            default { $unclassifiedCount++; $classificationCounts[$key].unclassified++ }
        }
        $timeUtc = ConvertTo-WpdEventUtcDateTime -Value (Get-WpdEventObjectProperty -InputObject $record -Name 'timeCreatedUtc')
        if ($null -eq $timeUtc) {
            $unknownTimeCount++
        }
        else {
            $timeCounts[$key] += $timeUtc
        }
    }

    $components = @()
    $recurringCount = 0
    $uncorrectedComponents = @()
    foreach ($key in @($order)) {
        $counts = $classificationCounts[$key]
        $times = @($timeCounts[$key] | Sort-Object)
        $count = $buckets[$key].Count
        $recurrence = if ($times.Count -ge 2 -or $count -ge 2) { 'recurring' } else { 'none' }
        if ($recurrence -eq 'recurring') {
            $recurringCount++
        }
        $classificationLabel = 'unclassified'
        if ($counts.uncorrected -gt 0 -and $counts.corrected -gt 0) { $classificationLabel = 'mixed' }
        elseif ($counts.uncorrected -gt 0 -and $counts.unclassified -gt 0) { $classificationLabel = 'mixed' }
        elseif ($counts.uncorrected -gt 0) { $classificationLabel = 'uncorrected' }
        elseif ($counts.corrected -gt 0 -and $counts.unclassified -gt 0) { $classificationLabel = 'mixed' }
        elseif ($counts.corrected -gt 0) { $classificationLabel = 'corrected' }
        $hasUncorrected = ($counts.uncorrected -gt 0)
        if ($hasUncorrected) {
            $uncorrectedComponents += $key
        }
        $components += [pscustomobject]@{
            component             = $key
            count                 = $count
            correctedCount        = $counts.corrected
            uncorrectedCount      = $counts.uncorrected
            unclassifiedCount     = $counts.unclassified
            firstUtc              = if ($times.Count -gt 0) { ConvertTo-WpdEventIsoTimestamp -Value $times[0] } else { $null }
            lastUtc               = if ($times.Count -gt 0) { ConvertTo-WpdEventIsoTimestamp -Value $times[$times.Count - 1] } else { $null }
            spanSeconds           = if ($times.Count -gt 1) { [int64][math]::Round(($times[$times.Count - 1] - $times[0]).TotalSeconds) } else { 0 }
            recurrence            = $recurrence
            uncorrectedRecurrence = [bool]($hasUncorrected -and $counts.uncorrected -ge 2)
            classification        = $classificationLabel
            records               = @($buckets[$key])
        }
    }

    $severity = 'unclassified-only'
    if ($uncorrectedCount -gt 0) { $severity = 'uncorrected-present' }
    elseif ($correctedCount -gt 0 -and $unclassifiedCount -gt 0) { $severity = 'mixed-classification' }
    elseif ($correctedCount -gt 0) { $severity = 'corrected-only' }

    $reasons = @()
    if ($unclassifiedCount -gt 0) { $reasons += 'unclassified' }
    if ($unknownTimeCount -gt 0) { $reasons += 'invalid-event-time' }
    if ($null -eq $Envelope) { $reasons += 'query-coverage-not-linked' }
    $queryCoverage = if ($null -ne $Envelope) { [string]$Envelope.coverage } else { '' }
    $coverage = 'complete'
    if ($reasons.Count -gt 0 -or $queryCoverage -eq 'partial' -or $queryCoverage -eq 'unavailable' -or $queryCoverage -eq 'unsupported') {
        $coverage = 'partial'
    }
    $status = if ($coverage -eq 'complete') { 'success' } else { 'partial' }

    $conclusion = if ($severity -eq 'uncorrected-present') {
        ('{0} uncorrected WHEA record(s) are present across {1} component(s); uncorrected errors are reported as recorded, never softened, and their link to the symptom is a correlation.' -f $uncorrectedCount, $uncorrectedComponents.Count)
    }
    elseif ($severity -eq 'corrected-only') {
        ('Only corrected WHEA records were observed ({0} record(s)); corrected errors are reported as a firmware/hardware correction path, not as a performance cause.' -f $correctedCount)
    }
    elseif ($severity -eq 'mixed-classification') {
        ('{0} corrected and {1} unclassified WHEA record(s) were observed; the unclassified records cannot be attributed to a severity from the record itself.' -f $correctedCount, $unclassifiedCount)
    }
    else {
        ('{0} WHEA record(s) were observed but none of them states a corrected or uncorrected class, so none is attributed a severity.' -f $unclassifiedCount)
    }

    return [pscustomobject]@{
        recordCount             = $items.Count
        correctedCount          = $correctedCount
        uncorrectedCount        = $uncorrectedCount
        unclassifiedCount       = $unclassifiedCount
        unknownTimeCount        = $unknownTimeCount
        severity                = $severity
        coverage                = $coverage
        status                  = $status
        components              = @($components)
        recurringComponentCount = $recurringCount
        uncorrectedComponents   = @($uncorrectedComponents)
        markerUtc               = ConvertTo-WpdEventIsoTimestamp -Value $MarkerUtc
        windowStartUtc          = ConvertTo-WpdEventIsoTimestamp -Value $WindowStart
        windowEndUtc            = ConvertTo-WpdEventIsoTimestamp -Value $WindowEnd
        reasons                 = @($reasons | Select-Object -Unique)
        absenceIsNotHealth      = $true
        causationDisclaimed     = $true
        correlationNotice       = $correlationNotice
        conclusion              = $conclusion
        interpretation          = $conclusion
    }
}

# ---------------------------------------------------------------------------
# Section 8: Windows Error Reporting (crashes, hangs, LiveKernelEvent)
# ---------------------------------------------------------------------------

function Get-WpdWerCrashMetadata {
    <#
    .SYNOPSIS
        Application crash metadata from structured EventData or the message text.

    .DESCRIPTION
        Structured EventData is preferred and the rendered message is the
        fallback, because either can be missing: a provider can fail to render
        while the XML still carries AppName/ModuleName/ExceptionCode, and a
        record copied from a report may only have the message. Nothing is
        invented: a field that is not present stays $null.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Record)

    $eventData = Get-WpdEventObjectProperty -InputObject $Record -Name 'eventData'
    $message = [string](Get-WpdEventObjectProperty -InputObject $Record -Name 'message')

    $lookup = {
        param([string[]]$Names, [string]$Pattern)

        if ($null -ne $eventData) {
            foreach ($name in $Names) {
                if ($eventData.Contains($name)) {
                    $value = [string]$eventData[$name]
                    if (-not [string]::IsNullOrWhiteSpace($value)) {
                        return $value.Trim()
                    }
                }
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($message) -and $message -match $Pattern) {
            $value = $matches[1].Trim().TrimEnd(',')
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                return $value
            }
        }
        return $null
    }

    $application = & $lookup @('AppName', 'Application', 'FaultingApplicationName') 'Faulting application name:\s*([^,\r\n]+)'
    $applicationVersion = & $lookup @('AppVersion') 'Faulting application name:.*?version:\s*([^,\r\n]+)'
    $module = & $lookup @('ModuleName', 'FaultingModuleName') 'Faulting module name:\s*([^,\r\n]+)'
    $moduleVersion = & $lookup @('ModuleVersion') 'Faulting module name:.*?version:\s*([^,\r\n]+)'
    $exceptionCode = & $lookup @('ExceptionCode') 'Exception code:\s*([^,\r\n]+)'
    $faultOffset = & $lookup @('FaultOffset') 'Fault offset:\s*([^,\r\n]+)'
    $reportId = & $lookup @('ReportId', 'ReportID') 'Report Id:\s*([^,\r\n]+)'
    $signatureSource = 'message-text'
    if ($null -ne $eventData -and $eventData.Contains('AppName')) {
        $signatureSource = 'event-data'
    }
    elseif ($null -eq $application) {
        $signatureSource = 'none'
    }

    return [pscustomobject]@{
        application        = $application
        applicationVersion = $applicationVersion
        module             = $module
        moduleVersion      = $moduleVersion
        exceptionCode      = $exceptionCode
        faultOffset        = $faultOffset
        reportId           = $reportId
        signatureSource    = $signatureSource
    }
}

function Get-WpdWerReportMetadata {
    <#
    .SYNOPSIS
        WER report kind, bucket and application for one Windows Error Reporting
        record.

    .DESCRIPTION
        The report kind is only ever what the record itself states ('Event Name'
        in the message or the EventName value in the XML). A WER record that does
        not state its kind is 'unclassified' with the reason
        'classification-not-in-record': WER writes records whose meaning is only
        decodable from the report body, and turning one of those into a crash
        would be a fabricated finding.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Record)

    $eventData = Get-WpdEventObjectProperty -InputObject $Record -Name 'eventData'
    $message = [string](Get-WpdEventObjectProperty -InputObject $Record -Name 'message')

    $eventName = $null
    if ($null -ne $eventData -and $eventData.Contains('EventName')) {
        $eventName = [string]$eventData['EventName']
    }
    elseif (-not [string]::IsNullOrWhiteSpace($message) -and $message -match 'Event Name:\s*([^\r\n]+)') {
        $eventName = $matches[1]
    }
    if ($null -ne $eventName) {
        $eventName = $eventName.Trim()
    }

    $bucket = $null
    if ($null -ne $eventData -and $eventData.Contains('Bucket')) {
        $bucket = [string]$eventData['Bucket']
    }
    elseif (-not [string]::IsNullOrWhiteSpace($message) -and $message -match 'Fault bucket([^:]*):\s*([^,\r\n]+)') {
        $bucket = $matches[2]
    }
    if ($null -ne $bucket) {
        $bucket = $bucket.Trim()
        if ([string]::IsNullOrWhiteSpace($bucket)) {
            $bucket = $null
        }
    }

    $application = $null
    if ($null -ne $eventData -and $eventData.Contains('AppName')) {
        $application = [string]$eventData['AppName']
    }
    elseif (-not [string]::IsNullOrWhiteSpace($message) -and $message -match '(?m)^\s*AppName:\s*([^\r\n]+)') {
        $application = $matches[1].Trim()
    }

    $kind = 'unclassified'
    $reason = 'classification-not-in-record'
    if (-not [string]::IsNullOrWhiteSpace($eventName)) {
        $normalized = $eventName.ToLowerInvariant()
        if ($normalized -match 'livekernel') { $kind = 'live-kernel-event'; $reason = 'record-states-livekernel-event' }
        elseif ($normalized -match 'bluescreen|bugcheck') { $kind = 'blue-screen'; $reason = 'record-states-blue-screen' }
        elseif ($normalized -match 'apphang|hang') { $kind = 'app-hang'; $reason = 'record-states-app-hang' }
        elseif ($normalized -match 'appcrash|crash') { $kind = 'app-crash'; $reason = 'record-states-app-crash' }
        elseif ($normalized -match 'kernel') { $kind = 'kernel-event'; $reason = 'record-states-kernel-event' }
        else { $kind = 'other'; $reason = 'record-states-other-event' }
    }

    return [pscustomobject]@{
        eventName            = $eventName
        kind                 = $kind
        bucket               = $bucket
        application          = $application
        classificationReason = $reason
        isLiveKernelEvent    = [bool]($kind -eq 'live-kernel-event')
        isBlueScreen         = [bool]($kind -eq 'blue-screen')
        isAppCrash           = [bool]($kind -eq 'app-crash')
    }
}

function Get-WpdWerAnalysis {
    <#
    .SYNOPSIS
        Application crash, hang and LiveKernelEvent report analysis.

    .DESCRIPTION
        Application Error records become crash signatures (application, module,
        exception code) with repetition counts and first/last times; Application
        Hang records become hangs; Windows Error Reporting records are classified
        by the report they state, with LiveKernelEvent kept separate from
        BlueScreen and APPCRASH. A record that states no report kind is retained
        as unclassified with its raw XML, and the analysis reports partial
        coverage instead of guessing. An empty result is a stated absence with
        'absenceIsNotHealth' set.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object[]]$Records,
        [AllowNull()][object]$MarkerUtc,
        [AllowNull()][object]$WindowStart,
        [AllowNull()][object]$WindowEnd,
        [AllowNull()][object]$Envelope
    )

    $items = @(ConvertTo-WpdEventArray -Value $Records)
    $correlationNotice = 'Crash, hang and WER report timing is reported as a correlation with the recorded window. Correlation is not causation: a crash record does not by itself prove what the user experienced, and a crash is not automatically the cause of a reported slowdown.'
    $absenceNotice = 'No crash, hang or Windows Error Reporting records were observed in the bounded window. Absence of WER records is not evidence of health: WER reporting can be disabled, the log can roll over, and the query may not cover the boot.'

    $crashGroups = @{}
    $crashOrder = New-Object System.Collections.ArrayList
    $hangGroups = @{}
    $hangOrder = New-Object System.Collections.ArrayList
    $liveGroups = @{}
    $liveOrder = New-Object System.Collections.ArrayList
    $unclassifiedRecords = @()
    $crashCount = 0
    $hangCount = 0
    $werReportCount = 0
    $liveKernelEventCount = 0
    $blueScreenCount = 0
    $appCrashCount = 0
    $appHangReportCount = 0
    $otherReportCount = 0

    foreach ($record in $items) {
        $provider = [string](Get-WpdEventObjectProperty -InputObject $record -Name 'provider')
        $eventId = Get-WpdEventObjectProperty -InputObject $record -Name 'eventId'
        $timeUtc = ConvertTo-WpdEventUtcDateTime -Value (Get-WpdEventObjectProperty -InputObject $record -Name 'timeCreatedUtc')
        $timeText = ConvertTo-WpdEventIsoTimestamp -Value $timeUtc

        $isCrash = ($provider -match '(?i)application error') -or ($eventId -eq 1000)
        $isHang = ($provider -match '(?i)application hang') -or ($eventId -eq 1002)
        $isWerReport = ($provider -match '(?i)windows error reporting') -or ($eventId -eq 1001)

        if ($isCrash) {
            $crashCount++
            $meta = Get-WpdWerCrashMetadata -Record $record
            $key = '{0}|{1}|{2}' -f $meta.application, $meta.module, $meta.exceptionCode
            if (-not $crashGroups.ContainsKey($key)) {
                $crashGroups[$key] = New-Object System.Collections.ArrayList
                [void]$crashOrder.Add($key)
            }
            [void]$crashGroups[$key].Add([pscustomobject]@{
                    record     = $record
                    timeUtc    = $timeUtc
                    timeText   = $timeText
                    reportId   = $meta.reportId
                    metadata   = $meta
                })
            continue
        }

        if ($isHang) {
            $hangCount++
            $meta = Get-WpdWerCrashMetadata -Record $record
            $key = '{0}|{1}' -f $meta.application, $meta.applicationVersion
            if (-not $hangGroups.ContainsKey($key)) {
                $hangGroups[$key] = New-Object System.Collections.ArrayList
                [void]$hangOrder.Add($key)
            }
            [void]$hangGroups[$key].Add([pscustomobject]@{ record = $record; timeUtc = $timeUtc; timeText = $timeText; metadata = $meta })
            continue
        }

        if ($isWerReport) {
            $werReportCount++
            $meta = Get-WpdWerReportMetadata -Record $record
            switch ($meta.kind) {
                'live-kernel-event' {
                    $liveKernelEventCount++
                    $key = '{0}|{1}' -f $meta.eventName, $meta.bucket
                    if (-not $liveGroups.ContainsKey($key)) {
                        $liveGroups[$key] = New-Object System.Collections.ArrayList
                        [void]$liveOrder.Add($key)
                    }
                    [void]$liveGroups[$key].Add([pscustomobject]@{ record = $record; timeUtc = $timeUtc; timeText = $timeText; metadata = $meta })
                }
                'blue-screen' { $blueScreenCount++ }
                'app-crash' { $appCrashCount++ }
                'app-hang' { $appHangReportCount++ }
                'unclassified' {
                    $unclassifiedRecords += $record
                }
                default { $otherReportCount++ }
            }
            continue
        }

        $unclassifiedRecords += $record
    }

    $crashes = @()
    foreach ($key in @($crashOrder)) {
        $members = @($crashGroups[$key])
        $times = @($members | Where-Object { $null -ne $_.timeUtc } | ForEach-Object { $_.timeUtc } | Sort-Object)
        $meta = $members[0].metadata
        $crashes += [pscustomobject]@{
            application        = $meta.application
            applicationVersion = $meta.applicationVersion
            module             = $meta.module
            moduleVersion      = $meta.moduleVersion
            exceptionCode      = $meta.exceptionCode
            faultOffset        = $meta.faultOffset
            count              = $members.Count
            firstUtc           = if ($times.Count -gt 0) { ConvertTo-WpdEventIsoTimestamp -Value $times[0] } else { $null }
            lastUtc            = if ($times.Count -gt 0) { ConvertTo-WpdEventIsoTimestamp -Value $times[$times.Count - 1] } else { $null }
            reportIds          = @($members | ForEach-Object { $_.reportId } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
            signatureSource    = $meta.signatureSource
            unknownTimeCount   = @($members | Where-Object { $null -eq $_.timeUtc }).Count
            records            = @($members | ForEach-Object { $_.record })
        }
    }

    $hangs = @()
    foreach ($key in @($hangOrder)) {
        $members = @($hangGroups[$key])
        $times = @($members | Where-Object { $null -ne $_.timeUtc } | ForEach-Object { $_.timeUtc } | Sort-Object)
        $meta = $members[0].metadata
        $hangs += [pscustomobject]@{
            application        = $meta.application
            applicationVersion = $meta.applicationVersion
            count              = $members.Count
            firstUtc           = if ($times.Count -gt 0) { ConvertTo-WpdEventIsoTimestamp -Value $times[0] } else { $null }
            lastUtc            = if ($times.Count -gt 0) { ConvertTo-WpdEventIsoTimestamp -Value $times[$times.Count - 1] } else { $null }
            records            = @($members | ForEach-Object { $_.record })
        }
    }

    $liveKernelEvents = @()
    foreach ($key in @($liveOrder)) {
        $members = @($liveGroups[$key])
        $times = @($members | Where-Object { $null -ne $_.timeUtc } | ForEach-Object { $_.timeUtc } | Sort-Object)
        $meta = $members[0].metadata
        $liveKernelEvents += [pscustomobject]@{
            eventName        = $meta.eventName
            bucket           = $meta.bucket
            application      = $meta.application
            count            = $members.Count
            firstUtc         = if ($times.Count -gt 0) { ConvertTo-WpdEventIsoTimestamp -Value $times[0] } else { $null }
            lastUtc          = if ($times.Count -gt 0) { ConvertTo-WpdEventIsoTimestamp -Value $times[$times.Count - 1] } else { $null }
            evidenceKind     = 'wer-event'
            records          = @($members | ForEach-Object { $_.record })
        }
    }

    $reasons = @()
    if ($unclassifiedRecords.Count -gt 0) {
        $reasons += ('unclassified-records:' + $unclassifiedRecords.Count)
    }
    if ($null -eq $Envelope) {
        $reasons += 'query-coverage-not-linked'
    }
    elseif ([string]$Envelope.coverage -ne 'complete') {
        $reasons += ('query-coverage-' + [string]$Envelope.coverage)
    }

    $total = ($crashCount + $hangCount + $werReportCount + $unclassifiedRecords.Count)
    if ($total -eq 0) {
        $queryCoverage = if ($null -ne $Envelope) { [string]$Envelope.coverage } else { 'unavailable' }
        $coverage = if ($queryCoverage -eq 'unsupported' -or $queryCoverage -eq 'not-collected') { $queryCoverage } else { 'unavailable' }
        return [pscustomobject]@{
            recordCount           = 0
            crashCount            = 0
            crashes               = @()
            hangCount             = 0
            hangs                 = @()
            werReportCount        = 0
            liveKernelEventCount  = 0
            liveKernelEvents      = @()
            blueScreenCount       = 0
            appCrashCount         = 0
            appHangReportCount    = 0
            otherReportCount      = 0
            unclassifiedCount     = 0
            unclassifiedRecords   = @()
            coverage              = $coverage
            status                = if ($coverage -eq 'complete') { 'success' } else { 'unavailable' }
            reasons               = @('no-events-observed')
            absenceIsNotHealth    = $true
            causationDisclaimed   = $true
            correlationNotice     = $correlationNotice
            interpretation        = $absenceNotice
            windowStartUtc        = ConvertTo-WpdEventIsoTimestamp -Value $WindowStart
            windowEndUtc          = ConvertTo-WpdEventIsoTimestamp -Value $WindowEnd
            markerUtc             = ConvertTo-WpdEventIsoTimestamp -Value $MarkerUtc
        }
    }

    $coverage = if ($reasons.Count -gt 0) { 'partial' } else { 'complete' }
    $status = if ($coverage -eq 'complete') { 'success' } else { 'partial' }
    $interpretation = ('{0} application crash record(s), {1} application hang record(s) and {2} Windows Error Reporting record(s) were observed in the bounded window; {3} of the WER report(s) are LiveKernelEvent reports, {4} are BlueScreen and {5} are APPCRASH.' -f `
            $crashCount, $hangCount, $werReportCount, $liveKernelEventCount, $blueScreenCount, $appCrashCount)
    if ($unclassifiedRecords.Count -gt 0) {
        $interpretation = $interpretation + (' {0} record(s) could not be classified from the record itself and are retained with their raw XML.' -f $unclassifiedRecords.Count)
    }

    return [pscustomobject]@{
        recordCount           = $items.Count
        crashCount            = $crashCount
        crashes               = @($crashes)
        hangCount             = $hangCount
        hangs                 = @($hangs)
        werReportCount        = $werReportCount
        liveKernelEventCount  = $liveKernelEventCount
        liveKernelEvents      = @($liveKernelEvents)
        blueScreenCount       = $blueScreenCount
        appCrashCount         = $appCrashCount
        appHangReportCount    = $appHangReportCount
        otherReportCount      = $otherReportCount
        unclassifiedCount     = $unclassifiedRecords.Count
        unclassifiedRecords   = @($unclassifiedRecords)
        coverage              = $coverage
        status                = $status
        reasons               = @($reasons | Select-Object -Unique)
        absenceIsNotHealth    = $true
        causationDisclaimed   = $true
        correlationNotice     = $correlationNotice
        interpretation        = $interpretation
        windowStartUtc        = ConvertTo-WpdEventIsoTimestamp -Value $WindowStart
        windowEndUtc          = ConvertTo-WpdEventIsoTimestamp -Value $WindowEnd
        markerUtc             = ConvertTo-WpdEventIsoTimestamp -Value $MarkerUtc
    }
}

# ---------------------------------------------------------------------------
# Section 9: Diagnostics-Performance and Kernel-Power context
# ---------------------------------------------------------------------------

function Get-WpdEventNumericValue {
    <#
    .SYNOPSIS
        First numeric value among the named EventData keys, or $null.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Record,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    $eventData = Get-WpdEventObjectProperty -InputObject $Record -Name 'eventData'
    if ($null -eq $eventData) {
        return $null
    }
    foreach ($name in $Names) {
        if (-not $eventData.Contains($name)) {
            continue
        }
        $raw = [string]$eventData[$name]
        if ([string]::IsNullOrWhiteSpace($raw)) {
            continue
        }
        $value = $null
        try { $value = [double]$raw } catch { $value = $null }
        if ($null -ne $value) {
            return $value
        }
    }
    return $null
}

function Get-WpdBootComponentKind {
    <#
    .SYNOPSIS
        The component kind a Diagnostics-Performance record itself states.

    .DESCRIPTION
        The kind is taken from the record's own text ('Driver:', 'Service:',
        'Application:'). When the record states no component the kind is derived
        from what the record does carry - a boot duration or a shutdown duration -
        and otherwise it stays 'unclassified' with a stated reason instead of
        being inferred from an event id table.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Record,
        [AllowNull()][object]$BootTimeMs,
        [AllowNull()][object]$ShutdownTimeMs
    )

    $message = [string](Get-WpdEventObjectProperty -InputObject $Record -Name 'message')
    if (-not [string]::IsNullOrWhiteSpace($message)) {
        if ($message -match '(?i)\bdriver\b') { return 'driver' }
        if ($message -match '(?i)\bservice\b') { return 'service' }
        if ($message -match '(?i)\b(application|startup|app)\b') { return 'startup-application' }
    }
    if ($null -ne $BootTimeMs) { return 'boot' }
    if ($null -ne $ShutdownTimeMs) { return 'shutdown' }
    return 'unclassified'
}

function Get-WpdBootComponentName {
    <#
    .SYNOPSIS
        The component name a Diagnostics-Performance record names, if any.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Record)

    $eventData = Get-WpdEventObjectProperty -InputObject $Record -Name 'eventData'
    if ($null -ne $eventData) {
        foreach ($name in @('Name', 'DriverName', 'ServiceName', 'FriendlyName', 'FileName')) {
            if ($eventData.Contains($name)) {
                $value = [string]$eventData[$name]
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    return $value
                }
            }
        }
    }
    $message = [string](Get-WpdEventObjectProperty -InputObject $Record -Name 'message')
    if (-not [string]::IsNullOrWhiteSpace($message) -and $message -match '(?i)(?:Driver|Service|Application|File)\s*:\s*([^\s,;]+)') {
        return $matches[1]
    }
    return $null
}

function Get-WpdEventBugcheckCode {
    <#
    .SYNOPSIS
        The bugcheck code a crash record states, as a 0x-formatted string.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Record)

    $eventData = Get-WpdEventObjectProperty -InputObject $Record -Name 'eventData'
    if ($null -ne $eventData) {
        foreach ($name in @('BugcheckCode', 'BugCheckCode')) {
            if ($eventData.Contains($name)) {
                $raw = [string]$eventData[$name]
                if (-not [string]::IsNullOrWhiteSpace($raw)) {
                    if ($raw -match '^(?i)0x[0-9a-f]+$') {
                        return ('0x' + $raw.Substring(2).ToUpperInvariant())
                    }
                    $numeric = $null
                    try { $numeric = [int64]$raw } catch { $numeric = $null }
                    if ($null -ne $numeric -and $numeric -gt 0) {
                        return ('0x' + $numeric.ToString('X8', [System.Globalization.CultureInfo]::InvariantCulture))
                    }
                }
            }
        }
    }
    $message = [string](Get-WpdEventObjectProperty -InputObject $Record -Name 'message')
    if (-not [string]::IsNullOrWhiteSpace($message) -and $message -match '(?i)Bugcheck\s+(0x[0-9a-f]+)') {
        return ('0x' + $matches[1].Substring(2).ToUpperInvariant())
    }
    return $null
}

function Get-WpdBootShutdownContext {
    <#
    .SYNOPSIS
        Boot/shutdown cost from Diagnostics-Performance plus Kernel-Power context.

    .DESCRIPTION
        Diagnostics-Performance records give boot and shutdown duration and the
        component the record names (driver, service, startup application), with
        the slowest and median boot and the degraded-boot count. Kernel-Power 41
        ('the system has rebooted without cleanly shutting down') is classified as
        'bugcheck-correlated' only when a bugcheck crash record is actually within
        the correlation window, and as 'unexplained-shutdown' otherwise; the code
        reported is the one the crash record states.

        Correlation is not causation: an adjacent crash record and a slow boot
        share a timeline, not a proven causal link, and the envelope carries
        'causationDisclaimed' and the notice wording. Boot-trend maths uses only
        parseable timestamps; a record with an unparsable time is counted in
        'unknownTimeCount' and excluded from the trend rather than being placed at
        an invented point in time.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object[]]$Records,
        [AllowNull()][object[]]$CrashRecords = @(),
        [AllowNull()][object]$MarkerUtc,
        [AllowNull()][object]$WindowStart,
        [AllowNull()][object]$WindowEnd,
        [int]$CorrelationWindowMinutes = 5
    )

    $items = @(ConvertTo-WpdEventArray -Value $Records)
    $crashItems = @(ConvertTo-WpdEventArray -Value $CrashRecords)
    $correlationNotice = 'Boot, shutdown and power events are reported as a timeline correlation. Correlation is not causation: proximity between a boot cost and a crash, or between a bugcheck and a Kernel-Power 41 record, does not establish what caused the reported symptom.'
    $absenceNotice = 'No Diagnostics-Performance boot or Kernel-Power records were observed in the bounded window. Absence of these records is not evidence of health: the operational log may not be enabled, the log may have rolled over, and the query may not cover the boot.'

    $boots = @()
    $shutdowns = @()
    $powerEvents = @()
    $unknownTimeCount = 0

    foreach ($record in $items) {
        $provider = [string](Get-WpdEventObjectProperty -InputObject $record -Name 'provider')
        $eventIdValue = Get-WpdEventObjectProperty -InputObject $record -Name 'eventId'
        $eventId = $null
        try { $eventId = [int]$eventIdValue } catch { $eventId = $null }
        $timeUtc = ConvertTo-WpdEventUtcDateTime -Value (Get-WpdEventObjectProperty -InputObject $record -Name 'timeCreatedUtc')

        $bootTimeMs = Get-WpdEventNumericValue -Record $record -Names @('BootTime', 'BootDurationMs', 'BootDuration')
        $degradationMs = Get-WpdEventNumericValue -Record $record -Names @('Degradation', 'DegradationMs', 'DegradationTime')
        $shutdownTimeMs = Get-WpdEventNumericValue -Record $record -Names @('ShutdownTime', 'ShutdownDurationMs', 'ShutdownDuration')

        $isDiagnosticsPerformance = ($provider -match '(?i)diagnostics-performance')
        $isKernelPower = ($provider -match '(?i)kernel-power')

        if ($isDiagnosticsPerformance) {
            if ($null -eq $timeUtc) {
                $unknownTimeCount++
                continue
            }
            if ($null -ne $shutdownTimeMs) {
                $shutdowns += [pscustomobject]@{
                    eventId       = $eventId
                    shutdownTimeMs = [int64][math]::Round($shutdownTimeMs)
                    timeUtc       = ConvertTo-WpdEventIsoTimestamp -Value $timeUtc
                    componentName = Get-WpdBootComponentName -Record $record
                    componentKind = Get-WpdBootComponentKind -Record $record -BootTimeMs $bootTimeMs -ShutdownTimeMs $shutdownTimeMs
                    record        = $record
                }
                continue
            }
            if ($null -ne $bootTimeMs -or ($null -ne $eventId -and $eventId -ge 100 -and $eventId -le 110)) {
                $boots += [pscustomobject]@{
                    eventId       = $eventId
                    bootTimeMs    = if ($null -ne $bootTimeMs) { [int64][math]::Round($bootTimeMs) } else { $null }
                    degradationMs = if ($null -ne $degradationMs) { [int64][math]::Round($degradationMs) } else { $null }
                    componentName = Get-WpdBootComponentName -Record $record
                    componentKind = Get-WpdBootComponentKind -Record $record -BootTimeMs $bootTimeMs -ShutdownTimeMs $shutdownTimeMs
                    timeUtc       = ConvertTo-WpdEventIsoTimestamp -Value $timeUtc
                    record        = $record
                }
            }
            continue
        }

        if ($isKernelPower -and $eventId -eq 41) {
            $correlatedCrash = $null
            $correlationStatus = 'no-crash-record-nearby'
            if ($null -ne $timeUtc) {
                foreach ($crash in $crashItems) {
                    $crashTime = ConvertTo-WpdEventUtcDateTime -Value (Get-WpdEventObjectProperty -InputObject $crash -Name 'timeCreatedUtc')
                    if ($null -eq $crashTime) {
                        continue
                    }
                    if ([math]::Abs(($crashTime - $timeUtc).TotalMinutes) -le $CorrelationWindowMinutes) {
                        $correlatedCrash = $crash
                        $correlationStatus = 'crash-record-within-window'
                        break
                    }
                }
            }
            else {
                $correlationStatus = 'shutdown-time-unusable'
            }
            $bugcheckCode = $null
            if ($null -ne $correlatedCrash) {
                $bugcheckCode = Get-WpdEventBugcheckCode -Record $correlatedCrash
            }
            $classification = if ($null -ne $correlatedCrash) { 'bugcheck-correlated' } else { 'unexplained-shutdown' }
            $powerEvents += [pscustomobject]@{
                eventId               = $eventId
                timeUtc               = ConvertTo-WpdEventIsoTimestamp -Value $timeUtc
                classification        = $classification
                isUnexpectedShutdown  = [bool]($null -eq $correlatedCrash)
                bugcheckCode          = $bugcheckCode
                correlationStatus     = $correlationStatus
                correlationWindowMinutes = $CorrelationWindowMinutes
                interpretation        = if ($null -ne $correlatedCrash) {
                    'A Kernel-Power 41 record is within the correlation window of a bugcheck crash record; the two are reported together as a timeline correlation, not as a proven cause.'
                }
                else {
                    'A Kernel-Power 41 record has no bugcheck crash record within the correlation window, so the non-clean shutdown is reported as unexplained rather than attributed.'
                }
                record                = $record
            }
            continue
        }

        if ($isKernelPower) {
            $powerEvents += [pscustomobject]@{
                eventId               = $eventId
                timeUtc               = ConvertTo-WpdEventIsoTimestamp -Value $timeUtc
                classification        = 'power-transition'
                isUnexpectedShutdown  = $false
                bugcheckCode          = $null
                correlationStatus     = 'not-applicable'
                correlationWindowMinutes = $CorrelationWindowMinutes
                interpretation        = 'A power transition record was observed; it is context for a shutdown or resume, not a fault.'
                record                = $record
            }
        }
    }

    $bootDurations = @($boots | Where-Object { $null -ne $_.bootTimeMs } | ForEach-Object { [double]$_.bootTimeMs })
    $slowestBootMs = if ($bootDurations.Count -gt 0) { [int64]($bootDurations | Measure-Object -Maximum).Maximum } else { $null }
    $medianBootMs = Get-WpdEventMedianValue -Values $bootDurations
    if ($null -ne $medianBootMs) { $medianBootMs = [int64][math]::Round($medianBootMs) }
    $degradedBootCount = @($boots | Where-Object { $null -ne $_.degradationMs -and [int64]$_.degradationMs -gt 0 }).Count
    $unexplainedCount = @($powerEvents | Where-Object { $_.classification -eq 'unexplained-shutdown' }).Count
    $correlatedCount = @($powerEvents | Where-Object { $_.classification -eq 'bugcheck-correlated' }).Count

    $reasons = @()
    if ($unknownTimeCount -gt 0) { $reasons += 'invalid-event-time' }
    if ($boots.Count -gt 0 -and $bootDurations.Count -eq 0) { $reasons += 'no-usable-boot-duration' }
    if ($boots.Count -gt 0 -and $bootDurations.Count -lt $boots.Count) { $reasons += 'boot-trend-partial' }

    if ($items.Count -eq 0 -or ($boots.Count -eq 0 -and $shutdowns.Count -eq 0 -and $powerEvents.Count -eq 0)) {
        return [pscustomobject]@{
            recordCount               = $items.Count
            bootCount                 = 0
            boots                     = @()
            shutdownCount             = 0
            shutdowns                 = @()
            powerEventCount           = 0
            powerEvents               = @()
            slowestBootMs             = $null
            medianBootMs              = $null
            degradedBootCount         = 0
            unexplainedShutdownCount  = 0
            bugcheckCorrelatedCount   = 0
            unknownTimeCount          = $unknownTimeCount
            coverage                  = 'unavailable'
            status                    = 'unavailable'
            reasons                   = @('no-events-observed')
            absenceIsNotHealth        = $true
            causationDisclaimed       = $true
            correlationNotice         = $correlationNotice
            interpretation            = $absenceNotice
            windowStartUtc            = ConvertTo-WpdEventIsoTimestamp -Value $WindowStart
            windowEndUtc              = ConvertTo-WpdEventIsoTimestamp -Value $WindowEnd
            markerUtc                 = ConvertTo-WpdEventIsoTimestamp -Value $MarkerUtc
        }
    }

    $coverage = if ($reasons.Count -gt 0) { 'partial' } else { 'complete' }
    $status = if ($coverage -eq 'complete') { 'success' } else { 'partial' }
    $interpretation = ('{0} boot record(s) and {1} shutdown record(s) were observed; the slowest boot was {2} ms and {3} boot(s) reported a degradation. {4} Kernel-Power 41 record(s) were observed, {5} of them unexplained and {6} within the correlation window of a bugcheck record.' -f `
            $boots.Count, $shutdowns.Count, [string]$slowestBootMs, $degradedBootCount, $powerEvents.Count, $unexplainedCount, $correlatedCount)
    if ($unknownTimeCount -gt 0) {
        $interpretation = $interpretation + (' {0} record(s) carry an unparsable timestamp and are excluded from the trend maths.' -f $unknownTimeCount)
    }

    return [pscustomobject]@{
        recordCount               = $items.Count
        bootCount                 = $boots.Count
        boots                     = @($boots)
        shutdownCount             = $shutdowns.Count
        shutdowns                 = @($shutdowns)
        powerEventCount           = $powerEvents.Count
        powerEvents               = @($powerEvents)
        slowestBootMs             = $slowestBootMs
        medianBootMs              = $medianBootMs
        degradedBootCount         = $degradedBootCount
        unexplainedShutdownCount  = $unexplainedCount
        bugcheckCorrelatedCount   = $correlatedCount
        unknownTimeCount          = $unknownTimeCount
        coverage                  = $coverage
        status                    = $status
        reasons                   = @($reasons | Select-Object -Unique)
        absenceIsNotHealth        = $true
        causationDisclaimed       = $true
        correlationNotice         = $correlationNotice
        interpretation            = $interpretation
        windowStartUtc            = ConvertTo-WpdEventIsoTimestamp -Value $WindowStart
        windowEndUtc              = ConvertTo-WpdEventIsoTimestamp -Value $WindowEnd
        markerUtc                 = ConvertTo-WpdEventIsoTimestamp -Value $MarkerUtc
    }
}

# ---------------------------------------------------------------------------
# Section 10: symptom-date boundary and change timeline
# ---------------------------------------------------------------------------

function Get-WpdEventConfidence {
    <#
    .SYNOPSIS
        The stated confidence enum (High, Medium, Low) for one conclusion.

    .DESCRIPTION
        Same conditions as the shared helper: coverage must be complete or
        partial, at least the minimum sample count and at least one evidence
        record must exist, otherwise the answer is Low. Partial coverage or
        missing independent evidence caps the answer at Medium. It is a stated
        enum, never a percentage and never a health verdict.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Coverage = 'unavailable',
        [int]$SampleCount = 0,
        [int]$MinimumSamples = 1,
        [AllowNull()][object]$EvidenceCount = 0,
        [AllowNull()][object]$HasIndependentEvidence,
        [AllowNull()][object]$DurationSeconds,
        [int]$MinimumDurationSeconds = 0
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

function Resolve-WpdSymptomBoundary {
    <#
    .SYNOPSIS
        The symptom-date boundary used to place changes and events in time.

    .DESCRIPTION
        The symptom date is treated as a boundary, not an instant: the window
        starts at midnight UTC 'PreDays' before the symptom date and ends at the
        last tick of the 'PostDays'-th day after it, so a change made on the
        symptom date itself is inside the window and is labelled separately from
        changes before and after it. An unparsable symptom date is 'unavailable':
        a timeline with no anchor must not silently become an all-time list.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$SymptomDate,
        [int]$PreDays = 7,
        [int]$PostDays = 2,
        [switch]$ExclusiveBoundary
    )

    # A date-only symptom value is a UTC calendar date, not a local-midnight
    # instant converted to UTC: otherwise the boundary would shift by the host
    # offset and a change made on the symptom date could land outside it.
    $symptomUtc = $null
    if ($SymptomDate -is [string] -and ([string]$SymptomDate).Trim() -match '^\d{4}-\d{2}-\d{2}$') {
        $parsedDate = [datetime]::MinValue
        if ([datetime]::TryParseExact(([string]$SymptomDate).Trim(), 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsedDate)) {
            $symptomUtc = [datetime]::SpecifyKind($parsedDate, [System.DateTimeKind]::Utc)
        }
    }
    else {
        $symptomUtc = ConvertTo-WpdEventUtcDateTime -Value $SymptomDate
    }
    if ($null -eq $symptomUtc) {
        return [pscustomobject]@{
            status               = 'unavailable'
            coverage             = 'unavailable'
            reason               = 'invalid-symptom-date'
            reasons              = @('invalid-symptom-date')
            symptomDateUtc       = $null
            symptomDateEndUtc    = $null
            windowStartUtc       = $null
            windowEndUtc         = $null
            preDays              = $PreDays
            postDays             = $PostDays
            boundaryInclusive    = (-not $ExclusiveBoundary.IsPresent)
        }
    }
    if ($PreDays -lt 0 -or $PostDays -lt 0) {
        return [pscustomobject]@{
            status               = 'unavailable'
            coverage             = 'unavailable'
            reason               = 'negative-symptom-window'
            reasons              = @('negative-symptom-window')
            symptomDateUtc       = $null
            symptomDateEndUtc    = $null
            windowStartUtc       = $null
            windowEndUtc         = $null
            preDays              = $PreDays
            postDays             = $PostDays
            boundaryInclusive    = (-not $ExclusiveBoundary.IsPresent)
        }
    }

    $symptomStart = $symptomUtc.Date
    $windowStart = $symptomStart.AddDays(-1 * $PreDays)
    $symptomEnd = $symptomStart.AddDays(1).AddTicks(-1)
    $windowEnd = $symptomStart.AddDays($PostDays).AddDays(1).AddTicks(-1)

    return [pscustomobject]@{
        status            = 'complete'
        coverage          = 'complete'
        reason            = $null
        reasons           = @()
        symptomDateUtc    = ConvertTo-WpdEventIsoTimestamp -Value $symptomStart
        symptomDateEndUtc = ConvertTo-WpdEventIsoTimestamp -Value $symptomEnd
        windowStartUtc    = ConvertTo-WpdEventIsoTimestamp -Value $windowStart
        windowEndUtc      = ConvertTo-WpdEventIsoTimestamp -Value $windowEnd
        preDays           = $PreDays
        postDays          = $PostDays
        boundaryInclusive = (-not $ExclusiveBoundary.IsPresent)
    }
}

function ConvertTo-WpdChangeEntry {
    <#
    .SYNOPSIS
        Normalize one change-history record into a timeline entry.

    .DESCRIPTION
        The change kind (driver, update, software, service) is derived from the
        provider and the record's own structured values or text - never from an
        assumption about what an event id means. The entry is then placed
        relative to the symptom-date boundary: 'pre-symptom', 'on-symptom-date' or
        'post-symptom', with a signed offset. A record with an unparsable
        timestamp is retained, marked 'unknown', excluded from the ordered
        timeline body and given Low confidence, rather than being placed at an
        invented point in time.

        Every entry carries its own correlation notice and limitations: a change
        that precedes a symptom shares a timeline with it and nothing more.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Record,
        [AllowNull()][object]$Boundary
    )

    $provider = [string](Get-WpdEventObjectProperty -InputObject $Record -Name 'provider')
    $eventData = Get-WpdEventObjectProperty -InputObject $Record -Name 'eventData'
    $message = [string](Get-WpdEventObjectProperty -InputObject $Record -Name 'message')
    $eventId = Get-WpdEventObjectProperty -InputObject $Record -Name 'eventId'
    $timeUtc = ConvertTo-WpdEventUtcDateTime -Value (Get-WpdEventObjectProperty -InputObject $Record -Name 'timeCreatedUtc')

    $kind = 'unclassified'
    $classificationReason = 'change-kind-not-in-record'
    $nameKeys = @('Name', 'Title', 'FileName')
    if ($provider -match '(?i)msiinstaller') {
        $kind = 'software'
        $classificationReason = 'record-states-software-install'
        $nameKeys = @('ProductName', 'Product', 'Name', 'Title')
    }
    elseif ($provider -match '(?i)windowsupdateclient') {
        $kind = 'update'
        $classificationReason = 'record-states-update'
        $nameKeys = @('updateTitle', 'Title', 'Name', 'updateName')
    }
    elseif ($provider -match '(?i)service control manager' -or $eventId -eq 7045) {
        $kind = 'service'
        $classificationReason = 'record-states-service-installation'
        $nameKeys = @('ServiceName', 'Name', 'Title')
    }
    elseif ($null -ne $eventData -and $eventData.Contains('DriverName')) {
        $kind = 'driver'
        $classificationReason = 'record-states-driver'
        $nameKeys = @('DriverName', 'Name', 'FileName')
    }
    elseif ($provider -match '(?i)kernel-pnp|userpnp' -or ($message -match '(?i)\bdriver\b')) {
        $kind = 'driver'
        $classificationReason = 'record-states-driver'
        $nameKeys = @('DriverName', 'Name', 'FileName', 'DeviceName')
    }

    $name = $null
    $version = $null
    if ($null -ne $eventData) {
        foreach ($key in $nameKeys) {
            if ($eventData.Contains($key)) {
                $value = [string]$eventData[$key]
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    $name = $value
                    break
                }
            }
        }
        foreach ($key in @('DriverVersion', 'ProductVersion', 'Version', 'updateVersion')) {
            if ($eventData.Contains($key)) {
                $value = [string]$eventData[$key]
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    $version = $value
                    break
                }
            }
        }
    }
    if ($null -eq $name -and -not [string]::IsNullOrWhiteSpace($message)) {
        if ($message -match '(?i)(?:driver|service|product|update)[:\s]+([^\s,;]+)') {
            $name = $matches[1]
        }
        elseif ($message -match '(?i)installed the following update:\s*([^\.]+)') {
            $name = $matches[1].Trim()
        }
    }

    $symptomStart = $null
    $symptomEnd = $null
    $windowStart = $null
    $windowEnd = $null
    if ($null -ne $Boundary -and [string]$Boundary.status -eq 'complete') {
        $symptomStart = ConvertTo-WpdEventUtcDateTime -Value $Boundary.symptomDateUtc
        $symptomEnd = ConvertTo-WpdEventUtcDateTime -Value $Boundary.symptomDateEndUtc
        $windowStart = ConvertTo-WpdEventUtcDateTime -Value $Boundary.windowStartUtc
        $windowEnd = ConvertTo-WpdEventUtcDateTime -Value $Boundary.windowEndUtc
    }

    $phase = 'unknown'
    $side = $null
    $offset = $null
    $withinWindow = $false
    if ($null -ne $timeUtc -and $null -ne $symptomStart) {
        $offset = [int64][math]::Round(($timeUtc - $symptomStart).TotalSeconds)
        if ($timeUtc -lt $symptomStart) {
            $phase = 'pre-symptom'
            $side = 'before'
        }
        elseif ($timeUtc -le $symptomEnd) {
            $phase = 'on-symptom-date'
            $side = 'on-boundary'
        }
        else {
            $phase = 'post-symptom'
            $side = 'after'
        }
        if ($null -ne $windowStart -and $null -ne $windowEnd) {
            $withinWindow = [bool]($timeUtc -ge $windowStart -and $timeUtc -le $windowEnd)
        }
    }

    $signatureSource = 'none'
    if ($null -ne $eventData -and $eventData.Count -gt 0) {
        $signatureSource = 'event-data'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($message)) {
        $signatureSource = 'message-text'
    }

    $recordCoverage = [string](Get-WpdEventObjectProperty -InputObject $Record -Name 'coverage')
    $confidenceCoverage = if ($recordCoverage -eq 'complete' -or $recordCoverage -eq 'partial') { $recordCoverage } else { 'unavailable' }
    $confidence = Get-WpdEventConfidence -Coverage $confidenceCoverage -SampleCount 1 -EvidenceCount 1 `
        -HasIndependentEvidence $true
    if ($null -eq $timeUtc -or $kind -eq 'unclassified' -or $confidenceCoverage -eq 'unavailable') {
        $confidence = 'Low'
    }
    elseif ($signatureSource -eq 'message-text' -and $confidence -eq 'High') {
        $confidence = 'Medium'
    }

    $limitations = @(
        'The change record states that a change happened; it does not state that the change affected performance.'
        'Proximity between this change and the symptom date is a timeline correlation, not evidence of causation.'
    )
    if ($null -eq $timeUtc) {
        $limitations += 'This record carries an unparsable timestamp, so its position relative to the symptom date is unknown.'
    }
    if ($kind -eq 'unclassified') {
        $limitations += 'The record does not state which kind of change it is, so it is reported as unclassified.'
    }

    return [pscustomobject]@{
        kind                 = $kind
        classificationReason = $classificationReason
        name                 = $name
        version              = $version
        provider             = $provider
        eventId              = $eventId
        logName              = [string](Get-WpdEventObjectProperty -InputObject $Record -Name 'logName')
        timeUtc              = ConvertTo-WpdEventIsoTimestamp -Value $timeUtc
        timeStatus           = [string](Get-WpdEventObjectProperty -InputObject $Record -Name 'timeStatus')
        malformedTime        = [bool]($null -eq $timeUtc)
        phase                = $phase
        side                 = $side
        offsetFromSymptomSeconds = $offset
        withinWindow         = $withinWindow
        signatureSource      = $signatureSource
        coverage             = $confidenceCoverage
        confidence           = $confidence
        causationEstablished = $false
        correlationNotice    = 'Correlation is not causation: this change is reported because of when it happened, not because it is proven to have caused the symptom.'
        limitations          = @($limitations)
        evidenceKind         = 'event-log-change'
        record               = $Record
    }
}

function Get-WpdChangeTimeline {
    <#
    .SYNOPSIS
        Driver, update, software and service change timeline around the symptom
        date, with correlation-not-causation confidence.

    .DESCRIPTION
        Entries are ordered by time and labelled pre-symptom, on-symptom-date or
        post-symptom against the resolved symptom boundary. The nearest changes
        before the symptom date are listed separately, because "what changed just
        before this started" is the useful question - and every entry states that
        proximity is a correlation, carries its own limitations and a stated
        confidence enum. Records with an unparsable timestamp are kept at the end
        of the timeline with phase 'unknown' and Low confidence. An empty result
        is a stated absence with 'absenceIsNotHealth' set, never health.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object[]]$Records,
        [AllowNull()][object]$Boundary,
        [AllowNull()][object]$SymptomDate,
        [int]$PreDays = 7,
        [int]$PostDays = 2,
        [int]$NearestChangeCount = 5
    )

    $resolvedBoundary = $Boundary
    if ($null -eq $resolvedBoundary) {
        $resolvedBoundary = Resolve-WpdSymptomBoundary -SymptomDate $SymptomDate -PreDays $PreDays -PostDays $PostDays
    }
    $items = @(ConvertTo-WpdEventArray -Value $Records)
    $correlationNotice = 'Correlation is not causation: the change timeline is a correlation with the symptom date, not a causal chain. A driver, update or installation that precedes a symptom shares a time window with it and nothing more.'
    $absenceNotice = 'No driver, update, software or service change records were observed in the bounded window. Absence of change records is not evidence of health: the change logs may not be enabled, the log may have rolled over, and the query may not cover the period the user described.'

    $entries = @($items | ForEach-Object { ConvertTo-WpdChangeEntry -Record $_ -Boundary $resolvedBoundary })
    $placed = @($entries | Where-Object { $null -ne $_.timeUtc } | Sort-Object -Property @{ Expression = { $_.timeUtc }; Descending = $false })
    $unplaced = @($entries | Where-Object { $null -eq $_.timeUtc })
    $ordered = @(@($placed) + @($unplaced))

    $driverCount = @($entries | Where-Object { $_.kind -eq 'driver' }).Count
    $updateCount = @($entries | Where-Object { $_.kind -eq 'update' }).Count
    $softwareCount = @($entries | Where-Object { $_.kind -eq 'software' }).Count
    $serviceCount = @($entries | Where-Object { $_.kind -eq 'service' }).Count
    $unclassifiedCount = @($entries | Where-Object { $_.kind -eq 'unclassified' }).Count
    $preSymptomCount = @($entries | Where-Object { $_.phase -eq 'pre-symptom' }).Count
    $onSymptomDateCount = @($entries | Where-Object { $_.phase -eq 'on-symptom-date' }).Count
    $postSymptomCount = @($entries | Where-Object { $_.phase -eq 'post-symptom' }).Count
    $unknownTimeCount = $unplaced.Count
    $nearestPreSymptomChanges = @($placed |
            Where-Object { $_.phase -eq 'pre-symptom' } |
            Sort-Object -Property @{ Expression = { [math]::Abs([double]$_.offsetFromSymptomSeconds) }; Descending = $false } |
            Select-Object -First ([math]::Max(1, $NearestChangeCount)))

    $reasons = @()
    if ($unknownTimeCount -gt 0) { $reasons += 'invalid-event-time' }
    if ($unclassifiedCount -gt 0) { $reasons += 'unclassified-records' }
    if ($null -eq $resolvedBoundary -or [string]$resolvedBoundary.status -ne 'complete') { $reasons += 'symptom-boundary-unavailable' }

    if ($entries.Count -eq 0) {
        return [pscustomobject]@{
            recordCount             = $items.Count
            entryCount              = 0
            entries                 = @()
            driverCount             = 0
            updateCount             = 0
            softwareCount           = 0
            serviceCount            = 0
            unclassifiedCount       = 0
            preSymptomCount         = 0
            onSymptomDateCount      = 0
            postSymptomCount        = 0
            unknownTimeCount        = 0
            nearestPreSymptomChanges = @()
            boundary                = $resolvedBoundary
            symptomDateUtc          = if ($null -ne $resolvedBoundary) { $resolvedBoundary.symptomDateUtc } else { $null }
            windowStartUtc          = if ($null -ne $resolvedBoundary) { $resolvedBoundary.windowStartUtc } else { $null }
            windowEndUtc            = if ($null -ne $resolvedBoundary) { $resolvedBoundary.windowEndUtc } else { $null }
            coverage                = 'unavailable'
            status                  = 'unavailable'
            reasons                 = @('no-events-observed')
            absenceIsNotHealth      = $true
            causationDisclaimed     = $true
            correlationNotice       = $correlationNotice
            interpretation          = $absenceNotice
        }
    }

    $coverage = if ($reasons.Count -gt 0) { 'partial' } else { 'complete' }
    $status = if ($coverage -eq 'complete') { 'success' } else { 'partial' }
    $interpretation = ('{0} change record(s) were observed: {1} driver, {2} update, {3} software and {4} service change(s); {5} before the symptom date, {6} on the symptom date and {7} after it.' -f `
            $entries.Count, $driverCount, $updateCount, $softwareCount, $serviceCount, $preSymptomCount, $onSymptomDateCount, $postSymptomCount)
    if ($unknownTimeCount -gt 0) {
        $interpretation = $interpretation + (' {0} record(s) carry an unparsable timestamp and are listed separately with an unknown position.' -f $unknownTimeCount)
    }

    return [pscustomobject]@{
        recordCount              = $items.Count
        entryCount               = $entries.Count
        entries                  = @($ordered)
        driverCount              = $driverCount
        updateCount              = $updateCount
        softwareCount            = $softwareCount
        serviceCount             = $serviceCount
        unclassifiedCount        = $unclassifiedCount
        preSymptomCount          = $preSymptomCount
        onSymptomDateCount       = $onSymptomDateCount
        postSymptomCount         = $postSymptomCount
        unknownTimeCount         = $unknownTimeCount
        nearestPreSymptomChanges = @($nearestPreSymptomChanges)
        boundary                 = $resolvedBoundary
        symptomDateUtc           = if ($null -ne $resolvedBoundary) { $resolvedBoundary.symptomDateUtc } else { $null }
        windowStartUtc           = if ($null -ne $resolvedBoundary) { $resolvedBoundary.windowStartUtc } else { $null }
        windowEndUtc             = if ($null -ne $resolvedBoundary) { $resolvedBoundary.windowEndUtc } else { $null }
        coverage                 = $coverage
        status                   = $status
        reasons                  = @($reasons | Select-Object -Unique)
        absenceIsNotHealth       = $true
        causationDisclaimed      = $true
        correlationNotice        = $correlationNotice
        interpretation           = $interpretation
    }
}

Export-ModuleMember -Function *
