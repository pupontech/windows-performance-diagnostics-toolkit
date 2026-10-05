"""Cross-engine launcher module paths must not inherit the PS7 process path."""
import json
from pathlib import Path
from test_entrypoint_tiered_integration import run_pwsh, INTEGRATION_FUNCTIONS

LAUNCHER = Path(__file__).resolve().parents[1] / 'src' / 'Invoke-WpdLauncher.ps1'


def test_native_module_path_is_first_and_registered_paths_are_preserved():
    result = json.loads(run_pwsh(f"""
$tree = [System.Management.Automation.Language.Parser]::ParseFile('{LAUNCHER.as_posix()}', [ref]$null, [ref]$null)
$found = @($tree.FindAll({{ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-WpdWindowsPowerShellModulePath' }}, $true))
if ($found.Count -ne 1) {{ throw 'Native launcher module-path builder missing' }}
Invoke-Expression $found[0].Extent.Text
$env:PSModulePath = 'C:\\Program Files\\PowerShell\\7\\Modules'
$value = Get-WpdWindowsPowerShellModulePath -NativeModuleDirectory 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules' -RegisteredPaths @('C:\\UserModules;C:\\MachineModules', '')
[pscustomobject]@{{ value = $value; inherited = $env:PSModulePath }} | ConvertTo-Json -Compress
""", INTEGRATION_FUNCTIONS))
    assert result['value'].split(';') == ['C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules', 'C:\\UserModules', 'C:\\MachineModules']
    assert result['inherited'] == 'C:\\Program Files\\PowerShell\\7\\Modules'


def test_native_path_setup_precedes_sibling_import_and_is_version_gated():
    source = LAUNCHER.read_text(encoding='utf-8-sig')
    assert '$PSVersionTable.PSVersion.Major -le 5' in source
    assert source.index('$env:PSModulePath = Get-WpdWindowsPowerShellModulePath') < source.index('Import-Module -Name $modulePath')
    assert "GetEnvironmentVariable('PSModulePath', 'User')" in source
    assert "GetEnvironmentVariable('PSModulePath', 'Machine')" in source
