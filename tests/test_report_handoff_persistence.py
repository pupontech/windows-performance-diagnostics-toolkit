"""Exercise the production report-handoff caller with an absent report module."""

import json

from test_entrypoint_tiered_integration import SCRIPT, INTEGRATION_FUNCTIONS, run_pwsh


def test_unavailable_report_handoff_is_persisted_in_the_manifest(tmp_path):
    root = tmp_path.as_posix()
    result = json.loads(run_pwsh(f"""
$resolvedOutputDirectory = '{root}'
$collectionManifestPath = Join-Path $resolvedOutputDirectory 'diagnostic-manifest.json'
$collectionManifest = [ordered]@{{ evidenceIndex = $null; incident = $null }}
$collectionManifest | ConvertTo-Json | Set-Content -LiteralPath $collectionManifestPath
'[]' | Set-Content -LiteralPath (Join-Path $resolvedOutputDirectory 'findings.json')
$collectedArtifacts = New-Object System.Collections.ArrayList
$coverageRecords = @()
$samples = @()
$diskSeries = @()
$incidentEvents = @()
$script:WpdTieredEngaged = $true
function Get-ArtifactMetadata {{ return @() }}
function Write-JsonFile {{ param($InputObject, $Path); [System.IO.File]::WriteAllText($Path, ($InputObject | ConvertTo-Json -Depth 30)) }}
$tree = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT.as_posix()}', [ref]$null, [ref]$null)
$blocks = @($tree.EndBlock.Statements | Where-Object {{
    $_ -is [System.Management.Automation.Language.IfStatementAst] -and
    $_.Extent.Text -like '*$reportHandoff = Write-WpdTechnicianReportHandoff*'
}})
if ($blocks.Count -ne 1) {{ throw 'Expected one production report-handoff caller' }}
Invoke-Expression $blocks[0].Extent.Text
Get-Content -LiteralPath $collectionManifestPath -Raw
""", INTEGRATION_FUNCTIONS))
    assert result.get('reportHandoff', {}).get('status') == 'unavailable'
    assert result['reportHandoff']['reason'] == 'report-module-not-loaded'
    assert not (tmp_path / 'case' / 'technician-report.html').exists()
