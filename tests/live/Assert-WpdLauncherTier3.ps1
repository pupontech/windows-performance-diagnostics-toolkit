#Requires -Version 5.1
[CmdletBinding()]
param([string]$CaseDirectory = 'C:\WPD-Case')
$ErrorActionPreference = 'Stop'
$manifest = Get-Content -LiteralPath (Join-Path $CaseDirectory 'diagnostic-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -ne '1.3') { throw 'Launcher did not engage the tiered collection path.' }
if (@($manifest.tiers.tier3.adapters).Count -ne 2) { throw 'Expected Search and minifilter execution results.' }
foreach ($relative in @('escalation/search-service-context.json', 'escalation/minifilter-enumeration.json')) {
    $path = Join-Path $CaseDirectory $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('Launcher output missing: ' + $relative) }
    $record = @( $manifest.artifacts | Where-Object { $_.Name -eq $relative } )
    if ($record.Count -ne 1 -or $record[0].Sha256 -ne (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash) { throw ('Launcher evidence not correctly hash-registered: ' + $relative) }
    if (@($manifest.evidenceIndex.records | Where-Object { $_.artifact -eq $relative -and $_.registered }).Count -ne 1) { throw ('Launcher evidence not indexed: ' + $relative) }
}
$search = Get-Content -LiteralPath (Join-Path $CaseDirectory 'escalation/search-service-context.json') -Raw | ConvertFrom-Json
$filters = Get-Content -LiteralPath (Join-Path $CaseDirectory 'escalation/minifilter-enumeration.json') -Raw | ConvertFrom-Json
if ($search.status -ne 'partial' -or $null -eq $search.data.service -or $null -ne $search.data.index) { throw 'Search service snapshot missing or index coverage overstated.' }
if ($filters.status -ne 'success' -or @($filters.data.filters).Count -lt 1) { throw 'Minifilter snapshot did not contain real filter evidence.' }
Write-Output ('Launcher Tier 3 evidence verified under ' + $CaseDirectory)
