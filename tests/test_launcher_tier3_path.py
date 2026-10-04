"""Default case destination and actual launcher feature propagation."""
from pathlib import Path

import pytest
import os
import subprocess

from test_entrypoint_tiered_integration import POWERSHELL_EXE, SCRIPT

ROOT = Path(__file__).resolve().parents[1]


def test_windows_script_default_is_c_root_not_current_directory():
    text = SCRIPT.read_text()
    assert "{ 'C:\\WPD-Case' }" in text.split('[string]$OutputDirectory =', 1)[1].split('\n', 1)[0]


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


def test_standalone_launcher_selects_real_tier3_collectors():
    text = (ROOT / 'Run-Diagnostics.bat').read_text()
    invocation = next(line for line in text.splitlines() if '-Mode Collect' in line)
    for flag in ['-CollectSearchContext', '-CollectMinifilters', '-ConfirmEscalationCollection']:
        assert flag in invocation
    assert 'Search service and minifilter snapshots' in text


@pytest.mark.parametrize('label', ['collect_ready', 'incident_ready'])
def test_guided_collection_modes_select_real_tier3_collectors(label):
    text = (ROOT / 'START-HERE.bat').read_text()
    block = text.split(':' + label + '\n', 1)[1].split('goto :run', 1)[0]
    for flag in ['-CollectSearchContext', '-CollectMinifilters', '-ConfirmEscalationCollection']:
        assert flag in block
    assert 'escalation\\search-service-context.json' in text
    assert 'escalation\\minifilter-enumeration.json' in text
