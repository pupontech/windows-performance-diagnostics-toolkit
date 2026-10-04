#Requires -Version 5.1
<#
.SYNOPSIS
  Verifies a two-run WPD UX proof on a real Windows host.

.DESCRIPTION
  Capture mode writes a harness-owned file-hash receipt immediately after the
  first launcher run. Verify mode consumes both exact case paths and that
  receipt; it never guesses a latest case, starts collection, opens a GUI, or
  cleans up files. See docs/run-ux-acceptance.md for the input contracts.
#>
[CmdletBinding(DefaultParameterSetName = 'Verify')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Capture')]
    [switch]$CaptureFirstCaseBaseline,

    [Parameter(Mandatory = $true)]
    [string]$FirstCaseDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'Verify')]
    [string]$SecondCaseDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'Capture')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Verify')]
    [string]$BaselineReceiptPath,

    [Parameter(Mandatory = $true)]
    [string]$FirstRunLogPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Verify')]
    [string]$SecondRunLogPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Verify')]
    [string]$ToolkitScriptPath,

    [Parameter(ParameterSetName = 'Verify')]
    [string]$SummaryEnvelopePath,

    [Parameter(ParameterSetName = 'Verify')]
    [AllowNull()]
    [object]$SummaryEnvelope,

    [Parameter(Mandatory = $true, ParameterSetName = 'Verify')]
    [string]$PresentationArgvReceiptPath,

    [string]$RootDirectory = 'C:\WPD-Case',

    [string]$BaselineSentinelPath,

    [string]$ExpectedSentinelSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-WpdProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Test-WpdCaseLeafName {
    param([AllowEmptyString()][string]$LeafName)

    if ([string]::IsNullOrWhiteSpace($LeafName)) { return $false }
    if ($LeafName -notmatch '^(?<stamp>\d{8}T\d{6}(?:\.\d{1,7})?Z)-(?<runid>[A-Za-z0-9][A-Za-z0-9-]{7,})$') {
        return $false
    }
    try {
        $stamp = [string]$matches.stamp
        $null = [datetime]::new(
            [int]$stamp.Substring(0, 4),
            [int]$stamp.Substring(4, 2),
            [int]$stamp.Substring(6, 2),
            [int]$stamp.Substring(9, 2),
            [int]$stamp.Substring(11, 2),
            [int]$stamp.Substring(13, 2),
            [System.DateTimeKind]::Utc
        )
        return $true
    }
    catch { return $false }
}

function Get-WpdSummaryEnvelopeErrors {
    param(
        [Parameter(Mandatory = $true)][object]$Envelope,
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$ReportPath,
        [AllowEmptyString()][string]$SearchStatus
    )

    $errors = New-Object System.Collections.ArrayList
    $status = [string](Get-WpdProperty -InputObject $Envelope -Name 'status')
    if ($status -notin @('completed', 'partial', 'failed')) {
        [void]$errors.Add("summary status must be completed, partial or failed; observed '$status'")
    }

    $exitCodeValue = Get-WpdProperty -InputObject $Envelope -Name 'exitCode'
    $exitCode = 0
    if ($null -eq $exitCodeValue -or -not [int]::TryParse([string]$exitCodeValue, [ref]$exitCode)) {
        [void]$errors.Add('summary exitCode is missing or not an integer')
    }

    foreach ($pair in @(
        @{ name = 'caseDirectory'; expected = $CaseDirectory },
        @{ name = 'manifestPath'; expected = $ManifestPath },
        @{ name = 'reportPath'; expected = $ReportPath }
    )) {
        $observed = [string](Get-WpdProperty -InputObject $Envelope -Name $pair.name)
        if ([string]::IsNullOrWhiteSpace($observed) -or
            -not [string]::Equals($observed, [string]$pair.expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            [void]$errors.Add("summary $($pair.name) does not identify the actual run path '$($pair.expected)'")
        }
    }

    $summaryErrorsValue = Get-WpdProperty -InputObject $Envelope -Name 'errors'
    $missingJsonValue = Get-WpdProperty -InputObject $Envelope -Name 'missingJson'
    $hasErrorsProperty = $false
    $hasMissingJsonProperty = $false
    if ($Envelope -is [System.Collections.IDictionary]) {
        $hasErrorsProperty = $Envelope.Contains('errors')
        $hasMissingJsonProperty = $Envelope.Contains('missingJson')
        if ($hasErrorsProperty) { $summaryErrorsValue = $Envelope['errors'] }
        if ($hasMissingJsonProperty) { $missingJsonValue = $Envelope['missingJson'] }
    }
    else {
        $errorsProperty = $Envelope.PSObject.Properties['errors']
        $missingJsonProperty = $Envelope.PSObject.Properties['missingJson']
        $hasErrorsProperty = $null -ne $errorsProperty
        $hasMissingJsonProperty = $null -ne $missingJsonProperty
        if ($hasErrorsProperty) { $summaryErrorsValue = $errorsProperty.Value }
        if ($hasMissingJsonProperty) { $missingJsonValue = $missingJsonProperty.Value }
    }
    if (-not $hasErrorsProperty -or $null -eq $summaryErrorsValue) { [void]$errors.Add('summary errors array is missing or null') }
    if (-not $hasMissingJsonProperty -or $null -eq $missingJsonValue) { [void]$errors.Add('summary missingJson array is missing or null') }
    $summaryErrors = @($summaryErrorsValue | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $missingJson = @($missingJsonValue | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($exitCode -ne 0 -and $status -ne 'failed') {
        [void]$errors.Add("nonzero exitCode '$exitCode' requires failed status")
    }
    if ($status -eq 'completed' -and $summaryErrors.Count -gt 0) {
        [void]$errors.Add('summary errors cannot have completed status')
    }
    if ($status -eq 'completed' -and $missingJson.Count -gt 0) {
        [void]$errors.Add('missing JSON evidence cannot have completed status')
    }
    if ($status -eq 'completed' -and $SearchStatus -eq 'partial') {
        [void]$errors.Add('partial Search evidence cannot have completed status')
    }

    $stagesValue = Get-WpdProperty -InputObject $Envelope -Name 'stages'
    $stages = @($stagesValue)
    if ($null -eq $stagesValue -or $stages.Count -eq 0) {
        [void]$errors.Add('summary per-stage status list is missing or empty')
    }
    foreach ($stage in $stages) {
        $stageName = [string](Get-WpdProperty -InputObject $stage -Name 'name')
        $stageStatus = [string](Get-WpdProperty -InputObject $stage -Name 'status')
        $stageReason = [string](Get-WpdProperty -InputObject $stage -Name 'reason')
        if ([string]::IsNullOrWhiteSpace($stageName) -or [string]::IsNullOrWhiteSpace($stageStatus)) {
            [void]$errors.Add('every summary stage must include a name and status')
            continue
        }
        if ($stageStatus -match '^skipped' -and [string]::IsNullOrWhiteSpace($stageReason)) {
            [void]$errors.Add("skipped stage '$stageName' must include its reason")
        }
        if ($status -eq 'completed' -and $stageStatus -in @('partial', 'failed')) {
            [void]$errors.Add("stage '$stageName' status '$stageStatus' cannot have completed summary status")
        }
    }

    $renderedText = [string](Get-WpdProperty -InputObject $Envelope -Name 'renderedText')
    if ([string]::IsNullOrWhiteSpace($renderedText)) {
        [void]$errors.Add('summary renderedText is missing')
    }
    else {
        foreach ($text in @($status, $CaseDirectory, $ReportPath)) {
            if ([string]::IsNullOrWhiteSpace($text) -or
                $renderedText.IndexOf($text, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
                [void]$errors.Add("rendered summary does not show '$text'")
            }
        }
    }
    return @($errors)
}

function Test-WpdPathContained {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Candidate
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $candidateFull = [System.IO.Path]::GetFullPath($Candidate)
    $rootPrefix = $rootFull.TrimEnd([char]92, [char]47) + [System.IO.Path]::DirectorySeparatorChar
    return $candidateFull.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Resolve-WpdCaseDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "case directory does not exist: $Path"
    }
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "case directory is a reparse point: $Path"
    }
    $full = [System.IO.Path]::GetFullPath($item.FullName).TrimEnd([char]92, [char]47)
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd([char]92, [char]47)
    $parent = [System.IO.Path]::GetDirectoryName($full).TrimEnd([char]92, [char]47)
    if (-not [string]::Equals($parent, $rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "case directory must be an immediate child of '$rootFull': $full"
    }
    if (-not (Test-WpdCaseLeafName -LeafName ([System.IO.Path]::GetFileName($full)))) {
        throw "case directory leaf does not match the UTC timestamp/run-id contract: $full"
    }
    return $full
}

function Get-WpdFileSnapshot {
    param([Parameter(Mandatory = $true)][string]$CaseDirectory)

    $rows = New-Object System.Collections.ArrayList
    foreach ($item in @(Get-ChildItem -LiteralPath $CaseDirectory -Recurse -Force -ErrorAction Stop)) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "case contains a reparse point; refusing to follow it: $($item.FullName)"
        }
        if ($item.PSIsContainer) { continue }
        $relative = $item.FullName.Substring($CaseDirectory.TrimEnd([char]92, [char]47).Length + 1).Replace('/', '\')
        $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        [void]$rows.Add([pscustomobject]@{ relativePath = $relative; length = [int64]$item.Length; sha256 = $hash })
    }
    return @($rows | Sort-Object -Property relativePath)
}

function Compare-WpdFileSnapshots {
    param(
        [AllowEmptyCollection()][object[]]$Expected = @(),
        [AllowEmptyCollection()][object[]]$Actual = @()
    )

    $differences = New-Object System.Collections.ArrayList
    $expectedMap = @{}
    $actualMap = @{}
    foreach ($row in @($Expected)) { $expectedMap[[string]$row.relativePath] = $row }
    foreach ($row in @($Actual)) { $actualMap[[string]$row.relativePath] = $row }
    foreach ($name in @($expectedMap.Keys + $actualMap.Keys | Sort-Object -Unique)) {
        if (-not $expectedMap.ContainsKey($name)) {
            [void]$differences.Add("new file: $name")
            continue
        }
        if (-not $actualMap.ContainsKey($name)) {
            [void]$differences.Add("missing file: $name")
            continue
        }
        $before = $expectedMap[$name]
        $after = $actualMap[$name]
        if ([int64]$before.length -ne [int64]$after.length -or [string]$before.sha256 -ne [string]$after.sha256) {
            [void]$differences.Add("changed file: $name")
        }
    }
    return @($differences)
}

function Assert-WpdRunLog {
    param(
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][string]$LogPath
    )

    if (-not (Test-WpdPathContained -Root $CaseDirectory -Candidate $LogPath)) {
        throw "run-owned diagnostics log must be inside its case directory: $LogPath"
    }
    if (-not (Test-Path -LiteralPath $LogPath -PathType Leaf)) {
        throw "run-owned diagnostics log is missing: $LogPath"
    }
}

function Get-WpdValidatedCaseEvidence {
    param([Parameter(Mandatory = $true)][string]$CaseDirectory)

    $manifestPath = Join-Path $CaseDirectory 'diagnostic-manifest.json'
    $reportPath = Join-Path $CaseDirectory 'report.html'
    $searchPath = Join-Path $CaseDirectory 'escalation\search-service-context.json'
    $minifilterPath = Join-Path $CaseDirectory 'escalation\minifilter-enumeration.json'
    foreach ($path in @($manifestPath, $reportPath, $searchPath, $minifilterPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "required final case artifact is missing: $path" }
    }
    if ((Get-Item -LiteralPath $reportPath).Length -le 0) { throw "report is empty: $reportPath" }

    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $search = Get-Content -LiteralPath $searchPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $minifilter = Get-Content -LiteralPath $minifilterPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "required case JSON is missing or invalid under '$CaseDirectory': $($_.Exception.Message)"
    }
    if ([string]$manifest.mode -ne 'Collect') { throw "manifest mode is not Collect: $manifestPath" }
    if ([string]$search.status -ne 'partial') { throw "Search snapshot must retain honest partial status; observed '$($search.status)'" }
    if ([string]$minifilter.status -ne 'success' -or @($minifilter.data.filters).Count -lt 1) {
        throw "minifilter snapshot lacks successful real filter evidence: $minifilterPath"
    }

    $required = @(
        'report.html',
        'escalation/search-service-context.json',
        'escalation/minifilter-enumeration.json'
    )
    foreach ($name in $required) {
        $entries = @($manifest.artifacts | Where-Object { [string]$_.Name -eq $name })
        if ($entries.Count -ne 1) { throw "manifest must register exactly one artifact named '$name'" }
        $entry = $entries[0]
        if ([string]$entry.Sha256 -notmatch '^[A-Fa-f0-9]{64}$') { throw "manifest SHA-256 is malformed for '$name'" }
        $artifactPath = Join-Path $CaseDirectory ($name.Replace('/', '\'))
        $actualHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256 -ErrorAction Stop).Hash
        $actualSize = (Get-Item -LiteralPath $artifactPath -ErrorAction Stop).Length
        if ([string]$entry.Sha256 -ne $actualHash) { throw "manifest SHA-256 mismatch for '$name'" }
        if ($null -eq $entry.SizeBytes -or [int64]$entry.SizeBytes -ne $actualSize) { throw "manifest size mismatch for '$name'" }
    }

    foreach ($name in @('escalation/search-service-context.json', 'escalation/minifilter-enumeration.json')) {
        $records = @($manifest.evidenceIndex.records | Where-Object { [string]$_.artifact -eq $name -and $_.registered -eq $true })
        if ($records.Count -ne 1) { throw "evidence index must register exactly one '$name' record" }
    }

    return [pscustomobject]@{
        caseDirectory = $CaseDirectory
        manifestPath = $manifestPath
        reportPath = $reportPath
        searchStatus = [string]$search.status
        minifilterStatus = [string]$minifilter.status
        manifest = $manifest
    }
}

function Read-WpdSummaryEnvelope {
    param(
        [AllowNull()][object]$Envelope,
        [AllowEmptyString()][string]$EnvelopePath
    )

    if ($null -ne $Envelope -and -not [string]::IsNullOrWhiteSpace($EnvelopePath)) {
        throw 'supply either SummaryEnvelope or SummaryEnvelopePath, not both'
    }
    if ($null -eq $Envelope -and [string]::IsNullOrWhiteSpace($EnvelopePath)) {
        throw 'summary proof input is required: supply SummaryEnvelopePath or SummaryEnvelope'
    }
    if (-not [string]::IsNullOrWhiteSpace($EnvelopePath)) {
        if (-not (Test-Path -LiteralPath $EnvelopePath -PathType Leaf)) { throw "summary envelope is missing: $EnvelopePath" }
        try { return (Get-Content -LiteralPath $EnvelopePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop) }
        catch { throw "summary envelope is invalid JSON: $($_.Exception.Message)" }
    }
    return $Envelope
}

function Assert-WpdPresentationArgvReceipt {
    param(
        [Parameter(Mandatory = $true)][string]$ReceiptPath,
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][string]$ReportPath
    )

    if (-not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf)) { throw "injected-runner argv proof is missing: $ReceiptPath" }
    try { $receipt = Get-Content -LiteralPath $ReceiptPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "injected-runner argv proof is invalid JSON: $($_.Exception.Message)" }
    if ($receipt.runnerInjected -ne $true) { throw 'presentation proof did not use an injected runner' }
    if ($receipt.guiOpened -ne $false) { throw 'presentation proof must not claim or open a GUI on CI' }
    if ([string]$receipt.presentationStatus -ne 'accepted') { throw "injected presentation runner did not accept the request (status='$($receipt.presentationStatus)')" }
    $runnerExitCode = 0
    if ($null -eq $receipt.runnerExitCode -or -not [int]::TryParse([string]$receipt.runnerExitCode, [ref]$runnerExitCode)) {
        throw 'injected presentation runner receipt has no integer runnerExitCode'
    }
    if ($runnerExitCode -ne 0) { throw "injected presentation runner returned exit code $runnerExitCode" }
    if (-not [string]::Equals([string]$receipt.caseDirectory, $CaseDirectory, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'injected runner receipt does not identify the final case directory'
    }
    if (-not [string]::Equals([string]$receipt.reportPath, $ReportPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'injected runner receipt does not identify the final report path'
    }
    $argv = @($receipt.argv | ForEach-Object { [string]$_ })
    if (-not ($argv | Where-Object { [string]::Equals($_, $CaseDirectory, [System.StringComparison]::OrdinalIgnoreCase) })) {
        throw 'Windows argv proof did not pass the exact final case path as an argument'
    }
    if (-not ($argv | Where-Object { [string]::Equals($_, $ReportPath, [System.StringComparison]::OrdinalIgnoreCase) })) {
        throw 'Windows argv proof did not pass the exact final report path as an argument'
    }
}

function Invoke-WpdProductionVerify {
    param(
        [Parameter(Mandatory = $true)][string]$ToolkitScript,
        [Parameter(Mandatory = $true)][string]$CaseDirectory
    )

    if (-not (Test-Path -LiteralPath $ToolkitScript -PathType Leaf)) { throw "production collector script is missing: $ToolkitScript" }
    if ($PSVersionTable.PSVersion.Major -le 5) { $engine = Join-Path $PSHOME 'powershell.exe' }
    else { $engine = Join-Path $PSHOME 'pwsh.exe' }
    if (-not (Test-Path -LiteralPath $engine -PathType Leaf)) { throw "current PowerShell engine executable is missing: $engine" }

    $output = @(& $engine -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ToolkitScript -Mode Verify -InputDirectory $CaseDirectory 2>&1)
    $exitCode = $LASTEXITCODE
    $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
    if ($exitCode -ne 0) { throw "production Verify failed for '$CaseDirectory' (exit $exitCode): $text" }
    try { $result = $text | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "production Verify output was not valid JSON for '$CaseDirectory': $text" }
    if ([string]$result.status -ne 'verified' -or [string]$result.package.status -ne 'verified') {
        throw "production Verify did not verify the case and package at '$CaseDirectory'"
    }
    return $result
}

if ($env:OS -ne 'Windows_NT') {
    throw 'This is a real-Windows proof harness. Do not run collection or claim Windows proof on Linux.'
}

try {
    if ([string]::IsNullOrWhiteSpace($BaselineSentinelPath) -xor [string]::IsNullOrWhiteSpace($ExpectedSentinelSha256)) {
        throw 'BaselineSentinelPath and ExpectedSentinelSha256 must be supplied together'
    }
    if ($ExpectedSentinelSha256 -and $ExpectedSentinelSha256 -notmatch '^[A-Fa-f0-9]{64}$') {
        throw 'ExpectedSentinelSha256 must contain exactly 64 hexadecimal characters'
    }
    $rootItem = Get-Item -LiteralPath $RootDirectory -ErrorAction Stop
    if (-not $rootItem.PSIsContainer) { throw "case root is not a directory: $RootDirectory" }
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "case root is a reparse point: $RootDirectory" }
    $rootFull = [System.IO.Path]::GetFullPath($rootItem.FullName).TrimEnd([char]92, [char]47)
    $firstFull = Resolve-WpdCaseDirectory -Path $FirstCaseDirectory -Root $rootFull
    Assert-WpdRunLog -CaseDirectory $firstFull -LogPath $FirstRunLogPath

    if ($PSCmdlet.ParameterSetName -eq 'Capture') {
        if (Test-WpdPathContained -Root $rootFull -Candidate $BaselineReceiptPath) {
            throw 'baseline receipt must be outside RootDirectory; it is harness-owned evidence, not case output'
        }
        if (Test-Path -LiteralPath $BaselineReceiptPath) { throw "baseline receipt already exists; refusing to overwrite: $BaselineReceiptPath" }
        $firstSnapshot = @(Get-WpdFileSnapshot -CaseDirectory $firstFull)
        $sentinelHash = $null
        if ($BaselineSentinelPath) {
            if (-not (Test-Path -LiteralPath $BaselineSentinelPath -PathType Leaf)) { throw "baseline sentinel is missing: $BaselineSentinelPath" }
            $sentinelHash = (Get-FileHash -LiteralPath $BaselineSentinelPath -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($sentinelHash -ne $ExpectedSentinelSha256) { throw 'baseline sentinel hash does not match ExpectedSentinelSha256' }
        }
        $receipt = [ordered]@{
            format = 'wpd-run-ux-first-case-baseline-v1'
            capturedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            rootDirectory = $rootFull
            firstCaseDirectory = $firstFull
            firstRunLogPath = [System.IO.Path]::GetFullPath($FirstRunLogPath)
            files = @($firstSnapshot)
            sentinelPath = if ($BaselineSentinelPath) { [System.IO.Path]::GetFullPath($BaselineSentinelPath) } else { $null }
            sentinelSha256 = $sentinelHash
        }
        $receiptParent = Split-Path -Parent $BaselineReceiptPath
        if (-not (Test-Path -LiteralPath $receiptParent -PathType Container)) { throw "baseline receipt parent directory is missing: $receiptParent" }
        $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $BaselineReceiptPath -Encoding UTF8
        Write-Output "PASS: captured first-case baseline for $firstFull"
        Write-Output "Baseline receipt: $BaselineReceiptPath"
        exit 0
    }

    $secondFull = Resolve-WpdCaseDirectory -Path $SecondCaseDirectory -Root $rootFull
    if ([string]::Equals($firstFull, $secondFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'the two launcher runs must use distinct case directories'
    }
    Assert-WpdRunLog -CaseDirectory $secondFull -LogPath $SecondRunLogPath
    if (-not (Test-Path -LiteralPath $BaselineReceiptPath -PathType Leaf)) { throw "first-case baseline receipt is missing: $BaselineReceiptPath" }
    try { $baseline = Get-Content -LiteralPath $BaselineReceiptPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "first-case baseline receipt is invalid JSON: $($_.Exception.Message)" }
    if ([string]$baseline.format -ne 'wpd-run-ux-first-case-baseline-v1') { throw 'first-case baseline receipt format is unsupported' }
    if (-not [string]::Equals([string]$baseline.firstCaseDirectory, $firstFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'first-case baseline receipt does not identify the supplied first run directory'
    }
    if (-not [string]::Equals([string]$baseline.rootDirectory, $rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'first-case baseline receipt was captured under a different case root'
    }
    if (-not [string]::Equals([string]$baseline.firstRunLogPath, [System.IO.Path]::GetFullPath($FirstRunLogPath), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'first-case baseline receipt does not identify the supplied first-run diagnostics log'
    }

    $baselineDifferences = @(Compare-WpdFileSnapshots -Expected @($baseline.files) -Actual @(Get-WpdFileSnapshot -CaseDirectory $firstFull))
    if ($baselineDifferences.Count -gt 0) { throw "first run changed after its baseline: $($baselineDifferences -join '; ')" }
    $sentinelPath = [string]$baseline.sentinelPath
    $sentinelHash = [string]$baseline.sentinelSha256
    if ($BaselineSentinelPath) {
        if ($sentinelPath -and -not [string]::Equals($sentinelPath, [System.IO.Path]::GetFullPath($BaselineSentinelPath), [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'supplied sentinel path differs from the baseline receipt'
        }
        if ($sentinelHash -and $ExpectedSentinelSha256 -ne $sentinelHash) { throw 'supplied sentinel hash differs from the baseline receipt' }
        $sentinelPath = [System.IO.Path]::GetFullPath($BaselineSentinelPath)
        $sentinelHash = $ExpectedSentinelSha256
    }
    if ($sentinelPath) {
        if (-not (Test-Path -LiteralPath $sentinelPath -PathType Leaf)) { throw "baseline sentinel disappeared: $sentinelPath" }
        if ((Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256 -ErrorAction Stop).Hash -ne $sentinelHash) {
            throw "baseline sentinel changed after the first run: $sentinelPath"
        }
    }

    $firstEvidence = Get-WpdValidatedCaseEvidence -CaseDirectory $firstFull
    $secondEvidence = Get-WpdValidatedCaseEvidence -CaseDirectory $secondFull
    $summary = Read-WpdSummaryEnvelope -Envelope $SummaryEnvelope -EnvelopePath $SummaryEnvelopePath
    $summaryErrors = @(Get-WpdSummaryEnvelopeErrors -Envelope $summary -CaseDirectory $secondFull `
        -ManifestPath $secondEvidence.manifestPath -ReportPath $secondEvidence.reportPath -SearchStatus $secondEvidence.searchStatus)
    if ($summaryErrors.Count -gt 0) { throw "summary envelope failed acceptance: $($summaryErrors -join '; ')" }
    if ([string]$summary.status -ne 'partial') { throw "expected honest partial summary for partial Search evidence; observed '$($summary.status)'" }
    if ([int]$summary.exitCode -ne 0) { throw "launcher summary reports a nonzero exit code: $($summary.exitCode)" }
    Assert-WpdPresentationArgvReceipt -ReceiptPath $PresentationArgvReceiptPath -CaseDirectory $secondFull -ReportPath $secondEvidence.reportPath

    $firstBeforeVerify = @(Get-WpdFileSnapshot -CaseDirectory $firstFull)
    $secondBeforeVerify = @(Get-WpdFileSnapshot -CaseDirectory $secondFull)
    $firstVerify = Invoke-WpdProductionVerify -ToolkitScript $ToolkitScriptPath -CaseDirectory $firstFull
    $secondVerify = Invoke-WpdProductionVerify -ToolkitScript $ToolkitScriptPath -CaseDirectory $secondFull
    $firstAfterVerify = @(Get-WpdFileSnapshot -CaseDirectory $firstFull)
    $secondAfterVerify = @(Get-WpdFileSnapshot -CaseDirectory $secondFull)
    $firstVerifyChanges = @(Compare-WpdFileSnapshots -Expected $firstBeforeVerify -Actual $firstAfterVerify)
    $secondVerifyChanges = @(Compare-WpdFileSnapshots -Expected $secondBeforeVerify -Actual $secondAfterVerify)
    if ($firstVerifyChanges.Count -gt 0 -or $secondVerifyChanges.Count -gt 0) {
        throw "Verify modified case files: first=[$($firstVerifyChanges -join '; ')] second=[$($secondVerifyChanges -join '; ')]"
    }
    $finalBaselineDifferences = @(Compare-WpdFileSnapshots -Expected @($baseline.files) -Actual $firstAfterVerify)
    if ($finalBaselineDifferences.Count -gt 0) { throw "first case changed during Verify: $($finalBaselineDifferences -join '; ')" }
    if ($sentinelPath -and (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256 -ErrorAction Stop).Hash -ne $sentinelHash) {
        throw "baseline sentinel changed during Verify: $sentinelPath"
    }

    Write-Output "PASS: distinct immediate case folders: $firstFull ; $secondFull"
    Write-Output "PASS: first case, report, run log and evidence unchanged after second run and Verify"
    Write-Output "PASS: required report/Search/minifilter artifacts are final, hashed and indexed"
    Write-Output "PASS: honest summary status=$($summary.status); case=$($summary.caseDirectory); report=$($summary.reportPath)"
    Write-Output "PASS: injected runner received exact case/report Windows argv; no GUI was opened"
    Write-Output "PASS: production Verify accepted both packages and remained read-only (first=$($firstVerify.package.status), second=$($secondVerify.package.status))"
    exit 0
}
catch {
    Write-Error $_
    exit 1
}
