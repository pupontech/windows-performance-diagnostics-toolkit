"""Exercise the real completion-envelope caller under StrictMode."""
import json
import pytest

from test_entrypoint_tiered_integration import SCRIPT, INTEGRATION_FUNCTIONS, run_pwsh


def test_completion_envelope_handles_stages_without_optional_coverage(tmp_path):
    envelope = tmp_path / 'completion.json'
    result = json.loads(run_pwsh(f"""
$CompletionEnvelopePath = '{envelope.as_posix()}'
$completion = [pscustomobject]@{{ status = 'partial'; caseDirectory = '{tmp_path.as_posix()}/case'; reportPath = '{tmp_path.as_posix()}/case/report.html'; stages = @([pscustomobject]@{{ collector = 'wpr'; status = 'skipped-wpr-not-found'; outcome = 'skipped' }}); reasons = @(); missingArtifacts = @() }}
$effectiveCompletionExitCode = 0
$resolvedOutputDirectory = $completion.caseDirectory
$renderedSummaryLines = @('Run summary: partial', ('Case folder: ' + $completion.caseDirectory), ('Final report: ' + $completion.reportPath))
$tree = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT.as_posix()}', [ref]$null, [ref]$null)
$blocks = @($tree.EndBlock.Statements | Where-Object {{ $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('$completionEnvelope = [ordered]') }})
if ($blocks.Count -ne 1) {{ throw 'Expected one production completion-envelope caller' }}
Invoke-Expression $blocks[0].Extent.Text
Get-Content -LiteralPath $CompletionEnvelopePath -Raw
""", INTEGRATION_FUNCTIONS))
    assert result['status'] == 'partial'
    assert result['stages'][0]['reason'] == 'skipped-wpr-not-found'


def test_standalone_without_completion_module_does_not_break_verified_explicit_case(tmp_path):
    result = json.loads(run_pwsh(f"""
$PSScriptRoot = '{tmp_path.as_posix()}'
$verificationFailure = $null
$OpenOutputs = $false
$CompletionEnvelopePath = ''
$tree = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT.as_posix()}', [ref]$null, [ref]$null)
$blocks = @($tree.EndBlock.Statements | Where-Object {{ $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('Completion summary unavailable') }})
if ($blocks.Count -ne 1) {{ throw 'Standalone completion compatibility guard missing' }}
$completionModulePath = Join-Path $PSScriptRoot 'Wpd.Completion.psm1'
Invoke-Expression $blocks[0].Extent.Text 3>$null
[pscustomobject]@{{ standaloneAllowed = $true }} | ConvertTo-Json
""", INTEGRATION_FUNCTIONS))
    assert result['standaloneAllowed'] is True


@pytest.mark.parametrize('setup', ["$verificationFailure = 'invalid case'", '$OpenOutputs = $true', "$CompletionEnvelopePath = 'requested.json'"])
def test_standalone_fallback_refuses_failed_verification_or_requested_presentation(tmp_path, setup):
    result = json.loads(run_pwsh(f"""
$PSScriptRoot = '{tmp_path.as_posix()}'
$verificationFailure = $null
$OpenOutputs = $false
$CompletionEnvelopePath = ''
{setup}
$tree = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT.as_posix()}', [ref]$null, [ref]$null)
$blocks = @($tree.EndBlock.Statements | Where-Object {{ $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('Completion summary unavailable') }})
if ($blocks.Count -ne 1) {{ throw 'Standalone completion compatibility guard missing' }}
$completionModulePath = Join-Path $PSScriptRoot 'Wpd.Completion.psm1'
$refused = $false
try {{ Invoke-Expression $blocks[0].Extent.Text 3>$null }} catch {{ $refused = $true }}
[pscustomobject]@{{ refused = $refused }} | ConvertTo-Json
""", INTEGRATION_FUNCTIONS))
    assert result['refused'] is True



def test_completion_handoff_cannot_mutate_the_already_packaged_case(tmp_path):
    case = tmp_path / 'case'
    case.mkdir()
    envelope = case / 'unregistered-envelope.json'
    result = json.loads(run_pwsh(f"""
$CompletionEnvelopePath = '{envelope.as_posix()}'
$completion = [pscustomobject]@{{ status = 'partial'; caseDirectory = '{case.as_posix()}'; reportPath = '{case.as_posix()}/report.html'; stages = @(); reasons = @(); missingArtifacts = @() }}
$effectiveCompletionExitCode = 0
$resolvedOutputDirectory = $completion.caseDirectory
$renderedSummaryLines = @('Run summary: partial')
$tree = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT.as_posix()}', [ref]$null, [ref]$null)
$blocks = @($tree.EndBlock.Statements | Where-Object {{ $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('$completionEnvelope = [ordered]') }})
if ($blocks.Count -ne 1) {{ throw 'Expected one completion-envelope caller' }}
Invoke-Expression $blocks[0].Extent.Text 3>$null
[pscustomobject]@{{ written = Test-Path -LiteralPath $CompletionEnvelopePath }} | ConvertTo-Json
""", INTEGRATION_FUNCTIONS))
    assert result['written'] is False
    assert list(case.iterdir()) == []


