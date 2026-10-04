[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('GuidedCollect', 'IncidentCollect', 'StandaloneCollect')]
    [string]$LaunchMode,

    # Optional retained handoff owned by a caller/CI invocation.
    [string]$RunReceiptPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Wpd.CasePath.psm1'
Import-Module -Name $modulePath -Force -ErrorAction Stop
$collectorPath = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-WindowsPerformanceDiagnostics.ps1'
$baseDirectory = Get-WpdDefaultCaseBaseDirectory
$environmentReceiptPath = [string]$env:WPD_RUN_RECEIPT_PATH
if (-not [string]::IsNullOrWhiteSpace($RunReceiptPath) -and
    -not [string]::IsNullOrWhiteSpace($environmentReceiptPath) -and
    -not [string]::Equals($RunReceiptPath, $environmentReceiptPath, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'RunReceiptPath and WPD_RUN_RECEIPT_PATH identify different receipt paths.'
}
$callerOwnedReceipt = $false
if (-not [string]::IsNullOrWhiteSpace($RunReceiptPath)) {
    $receiptPath = $RunReceiptPath
    $callerOwnedReceipt = $true
}
elseif (-not [string]::IsNullOrWhiteSpace($environmentReceiptPath)) {
    $receiptPath = $environmentReceiptPath
    $callerOwnedReceipt = $true
}
else {
    $receiptPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('wpd-run-receipt-' + [Guid]::NewGuid().ToString('N') + '.json')
}
if ($callerOwnedReceipt) {
    $receiptPath = [System.IO.Path]::GetFullPath($receiptPath)
    if ([System.IO.Directory]::Exists($receiptPath) -or [System.IO.File]::Exists($receiptPath)) {
        throw "Caller-owned run receipt already exists; refusing to overwrite: $receiptPath"
    }
    $receiptParent = [System.IO.Path]::GetDirectoryName($receiptPath)
    if (-not [System.IO.Directory]::Exists($receiptParent)) {
        throw "Caller-owned run receipt parent directory does not exist: $receiptParent"
    }
}

$collectorParameters = @{
    Mode = 'Collect'
    ConfirmLocalCollection = $true
    CaseBaseDirectory = $baseDirectory
    RunReceiptPath = $receiptPath
    DurationSeconds = 30
    OpenOutputs = $true
}
if (-not [string]::IsNullOrWhiteSpace([string]$env:WPD_COMPLETION_ENVELOPE_PATH)) {
    $collectorParameters.CompletionEnvelopePath = [string]$env:WPD_COMPLETION_ENVELOPE_PATH
}

switch ($LaunchMode) {
    'GuidedCollect' {
        $collectorParameters.CaptureWpr = $true
        $collectorParameters.ConfirmWprCapture = $true
        $collectorParameters.CollectMinidumps = $true
        $collectorParameters.ConfirmMinidumpCollection = $true
        $collectorParameters.CollectBootFailureLogs = $true
        $collectorParameters.ConfirmBootFailureLogCollection = $true
        $collectorParameters.CollectSearchContext = $true
        $collectorParameters.CollectMinifilters = $true
        $collectorParameters.ConfirmEscalationCollection = $true
        $collectorParameters.ZipOutput = $true
    }
    'IncidentCollect' {
        $collectorParameters.DurationSeconds = 120
        $collectorParameters.PerformanceMode = $true
        $collectorParameters.MarkerMode = $true
        $collectorParameters.CaptureWpr = $true
        $collectorParameters.ConfirmWprCapture = $true
        $collectorParameters.CollectMinidumps = $true
        $collectorParameters.ConfirmMinidumpCollection = $true
        $collectorParameters.CollectBootFailureLogs = $true
        $collectorParameters.ConfirmBootFailureLogCollection = $true
        $collectorParameters.CollectSearchContext = $true
        $collectorParameters.CollectMinifilters = $true
        $collectorParameters.ConfirmEscalationCollection = $true
        $collectorParameters.ZipOutput = $true
    }
    'StandaloneCollect' {
        $collectorParameters.CollectMinidumps = $true
        $collectorParameters.ConfirmMinidumpCollection = $true
        $collectorParameters.CollectBootFailureLogs = $true
        $collectorParameters.ConfirmBootFailureLogCollection = $true
        $collectorParameters.CollectSearchContext = $true
        $collectorParameters.CollectMinifilters = $true
        $collectorParameters.ConfirmEscalationCollection = $true
        $collectorParameters.ZipOutput = $true
    }
}

$presentationArgvReceiptPath = [string]$env:WPD_PRESENTATION_ARGV_RECEIPT_PATH
if (-not [string]::IsNullOrWhiteSpace($presentationArgvReceiptPath)) {
    $presentationCalls = New-Object System.Collections.ArrayList
    $collectorParameters.PresentationRunner = {
        param([string]$Action, [string]$Path)
        [void]$presentationCalls.Add([pscustomobject]@{ action = $Action; path = $Path })
        if ($Action -notin @('open-case', 'open-report')) {
            throw "Unexpected injected presentation action: $Action"
        }
        if ($Action -eq 'open-report') {
            if ($presentationCalls.Count -ne 2 -or $presentationCalls[0].action -ne 'open-case') {
                throw 'Injected presenter did not receive the final case before the final report.'
            }
            $caseArgument = [string]$presentationCalls[0].path
            $reportArgument = [string]$presentationCalls[1].path
            if ([string]::IsNullOrWhiteSpace($caseArgument) -or [string]::IsNullOrWhiteSpace($reportArgument)) {
                throw 'Injected presenter received an empty output path.'
            }
            $argvReceipt = [ordered]@{
                runnerInjected = $true
                guiOpened = $false
                presentationStatus = 'accepted'
                runnerExitCode = 0
                caseDirectory = $caseArgument
                reportPath = $reportArgument
                argv = @($caseArgument, $reportArgument)
            }
            $receiptStream = [System.IO.File]::Open([System.IO.Path]::GetFullPath($presentationArgvReceiptPath), [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
                $receiptBytes = [System.Text.Encoding]::UTF8.GetBytes(($argvReceipt | ConvertTo-Json -Compress))
                $receiptStream.Write($receiptBytes, 0, $receiptBytes.Length)
                $receiptStream.Flush()
            }
            finally { $receiptStream.Dispose() }
        }
        return $true
    }.GetNewClosure()
}

$collectorSucceeded = $false
$receipt = $null
$casePath = $null
$manifestPath = $null
$logPath = $null
try {
    try {
        & $collectorPath @collectorParameters
        $collectorSucceeded = $true
    }
    catch {
        Write-Host ('[ERROR] Collection failed: ' + $_.Exception.Message)
    }
    finally {
        # A terminating collector error can leave the transcript active when the
        # launcher invokes the entry point in this PowerShell process.
        try { Stop-Transcript | Out-Null } catch { }
    }

    if (-not [System.IO.File]::Exists($receiptPath)) {
        Write-Host '[ERROR] No run receipt was created; no run directory was handed off.'
        exit 1
    }
    try {
        $receipt = Get-Content -LiteralPath $receiptPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Host ('[ERROR] Run receipt could not be read: ' + $_.Exception.Message)
        exit 1
    }
    if ($null -eq $receipt.PSObject.Properties['casePath'] -or $null -eq $receipt.PSObject.Properties['runId']) {
        Write-Host '[ERROR] Run receipt does not contain an exact casePath and runId.'
        exit 1
    }

    $casePath = [System.IO.Path]::GetFullPath([string]$receipt.casePath)
    $expectedBase = [System.IO.Path]::GetFullPath($baseDirectory)
    $actualParent = [System.IO.Path]::GetDirectoryName($casePath)
    $comparison = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
    $leafMatch = [regex]::Match([System.IO.Path]::GetFileName($casePath), '^(?<stamp>\d{8}T\d{9}Z)-(?<runId>[A-Za-z0-9-]{1,64})$')
    if (-not [string]::Equals($actualParent, $expectedBase, $comparison) -or -not $leafMatch.Success -or $leafMatch.Groups['runId'].Value -ne [string]$receipt.runId) {
        Write-Host '[ERROR] Run receipt is not bound to a new child beneath this launch base.'
        exit 1
    }
    if (-not [System.IO.Directory]::Exists($casePath)) {
        Write-Host '[ERROR] The exact run directory from the receipt no longer exists.'
        exit 1
    }

    $manifestPath = Join-Path -Path $casePath -ChildPath 'diagnostic-manifest.json'
    $logPath = Join-Path -Path $casePath -ChildPath ('diagnostics-run-' + [string]$receipt.runId + '.log')
    $reportPath = Join-Path -Path $casePath -ChildPath 'report.html'
    Write-Host ('Case directory: ' + $casePath)
    Write-Host ('Run log: ' + $logPath)
    Write-Host ('Report path (if generated): ' + $reportPath)
    if (-not [System.IO.File]::Exists($manifestPath)) {
        Write-Host ('[ERROR] Collection did not produce the expected manifest: ' + $manifestPath)
        exit 1
    }
    if (-not [System.IO.File]::Exists($logPath)) {
        Write-Host ('[ERROR] Collection did not produce the expected run log: ' + $logPath)
        exit 1
    }
    Write-Host ('Collection manifest verified: ' + $manifestPath)
    if (-not $collectorSucceeded) { exit 1 }
    exit 0
}
finally {
    if (-not $callerOwnedReceipt -and [System.IO.File]::Exists($receiptPath)) {
        try { [System.IO.File]::Delete($receiptPath) } catch { }
    }
}
