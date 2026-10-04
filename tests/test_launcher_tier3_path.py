"""Default case destination and actual launcher feature propagation."""
from pathlib import Path

import pytest
import os
import shutil
import subprocess

from test_entrypoint_tiered_integration import POWERSHELL_EXE, SCRIPT

ROOT = Path(__file__).resolve().parents[1]


def test_windows_default_case_base_is_c_root_not_current_directory():
    text = (ROOT / 'src' / 'Wpd.CasePath.psm1').read_text()
    assert "return 'C:\\WPD-Case'" in text


@pytest.mark.skipif(os.name != 'nt', reason='Windows C drive default requires Windows')
def test_real_plan_without_output_override_uses_c_root(tmp_path):
    result = subprocess.run([POWERSHELL_EXE, '-NoProfile', '-File', str(SCRIPT), '-Mode', 'Plan'], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert r'C:\WPD-Case\diagnostic-plan.json' in result.stdout
    assert Path(r'C:\WPD-Case\diagnostic-plan.json').is_file()
    assert not (tmp_path / 'windows-performance-diagnostics').exists()



@pytest.mark.parametrize('name', ['START-HERE.bat', 'Run-Diagnostics.bat'])
def test_launcher_case_is_under_c_root(name):
    data = (ROOT / name).read_bytes()
    assert b'set "OUTDIR=C:\\WPD-Case"' in data
    assert b'C:\\Temp\\WPD-Case' not in data
    assert data.count(b'\n') == data.count(b'\r\n')
    assert data.isascii()


def test_shared_launcher_selects_real_tier3_collectors():
    text = (ROOT / 'src' / 'Invoke-WpdLauncher.ps1').read_text()
    for flag in ['CollectSearchContext = $true', 'CollectMinifilters = $true', 'ConfirmEscalationCollection = $true']:
        assert flag in text
    assert 'Search service and minifilter snapshots' in (ROOT / 'Run-Diagnostics.bat').read_text()


@pytest.mark.parametrize('label', ['collect_ready', 'incident_ready'])
def test_guided_collection_modes_select_real_tier3_collectors(label):
    text = (ROOT / 'START-HERE.bat').read_text()
    block = text.split(':' + label + '\n', 1)[1].split('goto :run', 1)[0]
    expected_mode = 'GuidedCollect' if label == 'collect_ready' else 'IncidentCollect'
    assert f'set "LAUNCHMODE={expected_mode}"' in block
    launcher = (ROOT / 'src' / 'Invoke-WpdLauncher.ps1').read_text()
    for flag in ['CollectSearchContext = $true', 'CollectMinifilters = $true', 'ConfirmEscalationCollection = $true']:
        assert flag in launcher
    assert 'Run log:' in launcher
    assert 'Collection manifest verified:' in launcher


def test_launchers_handoff_the_exact_case_without_pipelines_or_shared_pointers():
    helper = (ROOT / 'src' / 'Invoke-WpdLauncher.ps1').read_text()
    assert 'RunReceiptPath = $receiptPath' in helper
    assert 'wpd-run-receipt-' in helper
    assert 'ConfirmLocalCollection = $true' in helper
    assert '$actualParent, $expectedBase' in helper
    assert 'Report path (if generated):' in helper
    assert 'Tee-Object' not in helper
    for name in ['START-HERE.bat', 'Run-Diagnostics.bat']:
        text = (ROOT / name).read_text()
        assert 'Invoke-WpdLauncher.ps1' in text
        assert 'Tee-Object' not in text
        assert 'diagnostic-manifest.json' not in text


def test_case_path_and_launcher_powershell_parse(tmp_path):
    if not shutil.which(POWERSHELL_EXE):
        pytest.skip('PowerShell is required for parser validation')
    files = [
        ROOT / 'src' / 'Wpd.CasePath.psm1',
        ROOT / 'src' / 'Invoke-WpdLauncher.ps1',
        SCRIPT,
    ]
    literals = ', '.join("'" + str(path).replace("'", "''") + "'" for path in files)
    harness = tmp_path / 'parse-powershell.ps1'
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"foreach ($path in @({literals})) {{\n"
        "  $tokens = $null; $errors = $null\n"
        "  [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null\n"
        "  if ($errors.Count -gt 0) { throw ($path + ': ' + ($errors -join '; ')) }\n"
        "}\n",
        encoding='utf-8',
    )
    result = subprocess.run(
        [POWERSHELL_EXE, '-NoLogo', '-NoProfile', '-File', str(harness)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name == 'nt', reason='would pass the platform gate and enter live Collect')
def test_launcher_refusal_leaves_no_default_case_base(tmp_path):
    launcher = ROOT / 'src' / 'Invoke-WpdLauncher.ps1'
    result = subprocess.run(
        [POWERSHELL_EXE, '-NoLogo', '-NoProfile', '-File', str(launcher), '-LaunchMode', 'StandaloneCollect'],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 1
    assert 'supported only on Windows' in result.stdout + result.stderr
    assert 'No run receipt was created' in result.stdout + result.stderr
    assert not (tmp_path / 'windows-performance-diagnostics').exists()
