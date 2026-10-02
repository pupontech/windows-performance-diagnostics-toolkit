"""Execute the real Tier 3 dispatch and publication path without live providers."""
import json
import pytest

from test_entrypoint_tiered_integration import INTEGRATION_FUNCTIONS, run_pwsh

FUNCTIONS = INTEGRATION_FUNCTIONS + ["Invoke-WpdSelectedEscalations"]


def test_dispatch_forwards_consent_through_real_module_call(tmp_path):
    from test_entrypoint_tiered_integration import SCRIPT
    result = json.loads(run_pwsh(f"""
Import-Module '{(SCRIPT.parent / 'Wpd.Escalation.psm1').as_posix()}' -Prefix WpdSurface -Force
function Write-JsonFile {{ param($InputObject, $Path); [System.IO.File]::WriteAllText($Path, ($InputObject | ConvertTo-Json -Depth 30)) }}
$artifacts = New-Object System.Collections.ArrayList
$r = Invoke-WpdSelectedEscalations -RequestedAdapter @('minifilter-enumeration') -Consent -OutputDirectory '{tmp_path.as_posix()}' -CollectedArtifacts $artifacts
Get-Content -LiteralPath (Join-Path '{tmp_path.as_posix()}' $artifacts[0]) -Raw
""", FUNCTIONS))
    assert result['consentGiven'] is True
    assert result['reason'] != 'consent-required'
    from datetime import datetime
    assert datetime.fromisoformat(result['startedUtc'].replace('Z', '+00:00')).utcoffset().total_seconds() == 0
    assert datetime.fromisoformat(result['completedUtc'].replace('Z', '+00:00')).utcoffset().total_seconds() == 0




def test_selected_minifilters_execute_and_publish_evidence(tmp_path):
    result = json.loads(run_pwsh(f"""
$script:calls = @()
function Test-WpdModuleCommand {{ param($Name); return $true }}
function Invoke-WpdModuleCall {{
    param($Name, $Arguments)
    $script:calls += $Name
    if (-not $Arguments.Consent) {{ throw 'consent was not forwarded' }}
    return [pscustomobject]@{{ status = 'success'; coverage = 'complete'; reason = 'snapshot'; items = @(@{{ name = 'WdFilter' }}); data = @{{ filters = @(@{{ name = 'WdFilter' }}) }} }}
}}
function Write-JsonFile {{ param($InputObject, $Path); [System.IO.File]::WriteAllText($Path, ($InputObject | ConvertTo-Json -Depth 30)) }}
$artifacts = New-Object System.Collections.ArrayList
$r = Invoke-WpdSelectedEscalations -RequestedAdapter @('minifilter-enumeration') -Consent -OutputDirectory '{tmp_path.as_posix()}' -CollectedArtifacts $artifacts
[pscustomobject]@{{ result = $r; calls = @($script:calls); artifacts = @($artifacts) }} | ConvertTo-Json -Depth 30
""", FUNCTIONS))
    assert result['calls'] == ['Invoke-WpdMinifilterEscalation']
    assert result['result']['status'] == 'success'
    assert result['result']['coverage'] == 'complete'
    assert result['result']['recordCount'] == 1
    assert result['artifacts'] == ['escalation/minifilter-enumeration.json']
    artifact = json.loads((tmp_path / result['artifacts'][0]).read_text())
    assert artifact['data']['filters'][0]['name'] == 'WdFilter'


def test_search_uses_real_adapter_and_reports_missing_index_as_partial(tmp_path):
    from test_entrypoint_tiered_integration import SCRIPT
    result = json.loads(run_pwsh(f"""
Import-Module '{(SCRIPT.parent / 'Wpd.Escalation.psm1').as_posix()}' -Prefix WpdSurface -Force
function Invoke-WpdModuleCall {{
    param($Name, $Arguments)
    $command = Get-WpdModuleCommandName -Name $Name
    $Arguments.ServiceProvider = {{ [pscustomobject]@{{ Name = 'WSearch'; Status = 'Running'; StartType = 'Automatic' }} }}
    & $command @Arguments
}}
function Write-JsonFile {{ param($InputObject, $Path); [System.IO.File]::WriteAllText($Path, ($InputObject | ConvertTo-Json -Depth 30)) }}
$artifacts = New-Object System.Collections.ArrayList
$r = Invoke-WpdSelectedEscalations -RequestedAdapter @('search-service-context') -Consent -OutputDirectory '{tmp_path.as_posix()}' -CollectedArtifacts $artifacts
$r | ConvertTo-Json -Depth 30
""", FUNCTIONS))
    assert result['status'] == 'partial'
    assert result['coverage'] == 'partial'
    assert result['recordCount'] == 1
    artifact = json.loads((tmp_path / 'escalation/search-service-context.json').read_text())
    assert artifact['data']['service']['name'] == 'WSearch'
    assert artifact['data']['index'] is None
    assert 'search-index-provider-not-registered' in artifact['warnings']


def test_collect_caller_executes_selected_adapters_before_evidence_index(tmp_path):
    from test_entrypoint_tiered_integration import SCRIPT
    result = json.loads(run_pwsh(f"""
$resolvedOutputDirectory = '{tmp_path.as_posix()}'
$script:WpdRequestedEscalationAdapter = @('minifilter-enumeration')
$script:WpdEffectivePrivacyLevel = 'Standard'
$script:WpdTieredEngaged = $true
$ConfirmEscalationCollection = $true
$collectedArtifacts = New-Object System.Collections.ArrayList
function Test-WpdModuleCommand {{ param($Name); return $true }}
function Invoke-WpdModuleCall {{ param($Name, $Arguments); [pscustomobject]@{{ status = 'success'; coverage = 'complete'; reason = 'snapshot'; items = @(@{{ name = 'WdFilter' }}) }} }}
function Write-JsonFile {{ param($InputObject, $Path); [System.IO.File]::WriteAllText($Path, ($InputObject | ConvertTo-Json -Depth 30)) }}
function Add-CollectionErrorText {{ param($Stage, $Message); throw 'No errors expected' }}
$tree = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT.as_posix()}', [ref]$null, [ref]$null)
$blocks = @($tree.EndBlock.Statements | Where-Object {{ $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text -like '*$script:WpdEscalationExecution = Invoke-WpdSelectedEscalations*' }})
if ($blocks.Count -ne 1) {{ throw 'Production Collect does not execute selected Tier 3 adapters' }}
Invoke-Expression $blocks[0].Extent.Text
[pscustomobject]@{{ result = $script:WpdEscalationExecution; artifacts = @($collectedArtifacts) }} | ConvertTo-Json -Depth 30
""", FUNCTIONS))
    assert result['result']['status'] == 'success'
    assert result['artifacts'] == ['escalation/minifilter-enumeration.json']
    source = SCRIPT.read_text()
    assert source.index('$script:WpdEscalationExecution = Invoke-WpdSelectedEscalations') < source.index('foreach ($artifactEntry in @(Get-ArtifactMetadata')


def test_tier3_manifest_uses_execution_results_not_planned_descriptors():
    from test_entrypoint_tiered_integration import SCRIPT
    result = json.loads(run_pwsh("""
$r = New-WpdTieredCollectBlock -Tier3 ([pscustomobject]@{ status = 'partial'; coverage = 'partial'; recordCount = 1; adapters = @(@{ id = 'search-service-context'; status = 'partial'; artifact = 'escalation/search-service-context.json' }); reasons = @('index-unavailable') })
$r.tier3 | ConvertTo-Json -Depth 30
""", INTEGRATION_FUNCTIONS + ['New-WpdTieredCollectBlock']))
    assert result['recordCount'] == 1
    assert result['adapters'][0]['artifact'] == 'escalation/search-service-context.json'
    assert result['reasons'] == ['index-unavailable']
    source = SCRIPT.read_text()
    assert '$tier3StatusRecord = $script:WpdEscalationExecution.status' in source
    assert 'recordCount = $script:WpdEscalationExecution.recordCount' in source


@pytest.mark.parametrize('adapter', ['../escaped', 'unknown-adapter', '/absolute'])
def test_unknown_adapter_is_refused_before_any_side_effect(tmp_path, adapter):
    output = tmp_path / 'case'
    result = json.loads(run_pwsh(f"""
function Test-WpdModuleCommand {{ throw 'provider must not be queried' }}
$artifacts = New-Object System.Collections.ArrayList
try {{
    Invoke-WpdSelectedEscalations -RequestedAdapter @('minifilter-enumeration', '{adapter}') -Consent -OutputDirectory '{output.as_posix()}' -CollectedArtifacts $artifacts | Out-Null
    $refused = $false
}} catch {{ $refused = $_.Exception.Message -like '*Unknown Tier 3 adapter*' }}
[pscustomobject]@{{ refused = $refused; artifacts = @($artifacts) }} | ConvertTo-Json
""", FUNCTIONS))
    assert result['refused'] is True
    assert result['artifacts'] == []
    assert not output.exists()


@pytest.mark.parametrize('level', ['Standard', 'Redacted', 'Full'])
def test_privacy_label_never_claims_whole_case_redaction(tmp_path, level):
    from test_entrypoint_tiered_integration import SCRIPT
    result = json.loads(run_pwsh(f"""
$script:WpdEffectivePrivacyLevel = '{level}'
$PrivacyLevel = '{level}'
$collectionManifest = @{{}}
$tree = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT.as_posix()}', [ref]$null, [ref]$null)
$assignment = @($tree.FindAll({{ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$collectionManifest.privacy' }}, $true))
if ($assignment.Count -ne 1) {{ throw 'Expected one Collect privacy assignment' }}
Invoke-Expression $assignment[0].Extent.Text
$collectionManifest.privacy | ConvertTo-Json -Depth 10
""", INTEGRATION_FUNCTIONS))
    assert result['redactionApplied'] is False
    assert result['secretsCollected'] is None
    assert result['wholeCaseRedaction'] == 'not-implemented'
    assert result['sensitiveDataWarning'] is True
    import jsonschema
    schema = json.loads((SCRIPT.parent.parent / 'schema/diagnostic-report.schema.json').read_text())
    jsonschema.Draft7Validator(schema['definitions']['privacy']).validate(result)


@pytest.mark.parametrize('scenario', ['no-selection', 'no-consent', 'missing-module', 'publication-failure', 'deferred-adapter', 'provider-error'])
def test_execution_failure_and_opt_in_boundaries(tmp_path, scenario):
    output = tmp_path / 'case'
    result = json.loads(run_pwsh(f"""
$scenario = '{scenario}'
$script:calls = 0
function Test-WpdModuleCommand {{ param($Name); return ($scenario -ne 'missing-module') }}
function Invoke-WpdModuleCall {{
    param($Name, $Arguments)
    $script:calls++
    if ($scenario -eq 'provider-error') {{ throw 'controlled provider failure' }}
    [pscustomobject]@{{ status = 'success'; coverage = 'complete'; reason = 'snapshot'; items = @(@{{ name = 'WdFilter' }}) }}
}}
function Write-JsonFile {{
    param($InputObject, $Path)
    if ($scenario -eq 'publication-failure') {{ throw 'controlled publication failure' }}
    [System.IO.File]::WriteAllText($Path, ($InputObject | ConvertTo-Json -Depth 30))
}}
$artifacts = New-Object System.Collections.ArrayList
$requested = @('minifilter-enumeration')
if ($scenario -eq 'no-selection') {{ $requested = @() }}
if ($scenario -eq 'deferred-adapter') {{ $requested = @('wait-chain-traversal') }}
$refused = $false
$r = $null
try {{
    $r = Invoke-WpdSelectedEscalations -RequestedAdapter $requested -Consent:($scenario -ne 'no-consent') -OutputDirectory '{output.as_posix()}' -CollectedArtifacts $artifacts
}} catch {{ $refused = $_.Exception.Message -like '*explicit consent*' }}
[pscustomobject]@{{ result = $r; refused = $refused; calls = $script:calls; artifacts = @($artifacts) }} | ConvertTo-Json -Depth 30
""", FUNCTIONS))
    if scenario == 'no-consent':
        assert result['refused'] is True
        assert not output.exists()
    elif scenario == 'no-selection':
        assert result['result']['status'] == 'not-collected'
        assert not output.exists()
    else:
        assert result['result']['status'] == 'unavailable'
        assert result['result']['coverage'] == 'unavailable'
        assert result['result']['recordCount'] == 0
    if scenario in ['no-selection', 'no-consent', 'missing-module', 'deferred-adapter']:
        assert result['calls'] == 0
    if scenario in ['no-selection', 'no-consent', 'publication-failure', 'provider-error']:
        assert result['artifacts'] == []


def test_escalation_evidence_index_uses_snapshot_window_not_incident_window():
    from test_entrypoint_tiered_integration import SCRIPT
    result = json.loads(run_pwsh(f"""
$resolvedOutputDirectory = 'unused'
$collectedArtifacts = @('escalation/search-service-context.json')
$startedAtUtc = '2026-10-02T01:00:00Z'
$completedAtUtc = '2026-10-02T01:00:30Z'
$script:WpdEscalationExecution = [pscustomobject]@{{ adapters = @([pscustomobject]@{{ artifact = 'escalation/search-service-context.json'; startedUtc = '2026-10-02T01:00:31Z'; completedUtc = '2026-10-02T01:00:32Z' }}) }}
$evidenceIndexRecords = @()
$indexCounter = 0
function Get-ArtifactMetadata {{ param($Directory, $Names); [pscustomobject]@{{ Name = $Names[0]; Sha256 = ('a' * 64); SizeBytes = 10 }} }}
$tree = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT.as_posix()}', [ref]$null, [ref]$null)
$blocks = @($tree.FindAll({{ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] -and $n.Variable.Extent.Text -eq '$artifactEntry' -and $n.Extent.Text -like '*$evidenceIndexRecords*' }}, $true))
if ($blocks.Count -ne 1) {{ throw 'Expected one production evidence index loop' }}
Invoke-Expression $blocks[0].Extent.Text
$evidenceIndexRecords[0] | ConvertTo-Json -Depth 10
""", INTEGRATION_FUNCTIONS))
    assert result['windowStart'] == '2026-10-02T01:00:31Z'
    assert result['windowEnd'] == '2026-10-02T01:00:32Z'


def test_plan_resolves_real_search_and_minifilter_module_descriptors(tmp_path):
    from test_entrypoint_tiered_integration import SCRIPT, run_tool
    output = tmp_path / 'plan'
    r = run_tool('-Mode', 'Plan', '-Preset', 'general', '-CollectSearchContext', '-CollectMinifilters', '-ConfirmEscalationCollection', '-OutputDirectory', str(output))
    assert r.returncode == 0, r.stderr
    plan = json.loads((output / 'diagnostic-plan.json').read_text())
    assert plan['tiers']['escalation']['reasons'] == []
    result = json.loads(run_pwsh(f"""
Import-Module '{(SCRIPT.parent / 'Wpd.Escalation.psm1').as_posix()}' -Prefix WpdSurface -Force
New-WpdEscalationSelectionBlock -RequestedAdapter @('search-service-context', 'minifilter-enumeration') -Consent | ConvertTo-Json -Depth 30
""", INTEGRATION_FUNCTIONS + ['New-WpdEscalationSelectionBlock']))
    assert sorted(row['id'] for row in result['adapters']) == ['minifilter', 'search']
