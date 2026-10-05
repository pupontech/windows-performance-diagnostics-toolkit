"""Absent/null error metadata is not an invented error record."""
import json
import pytest
from test_run_completion import _valid_case, _ps_quote, run_pwsh_json


@pytest.mark.parametrize('omit', [False, True])
def test_null_or_absent_collection_errors_does_not_invent_a_failed_stage(tmp_path, omit):
    case = tmp_path / 'case'
    _valid_case(case)
    path = case / 'diagnostic-manifest.json'
    manifest = json.loads(path.read_text(encoding='utf-8'))
    if omit:
        del manifest['collectionErrors']
    else:
        manifest['collectionErrors'] = None
    path.write_text(json.dumps(manifest), encoding='utf-8')
    result = run_pwsh_json(tmp_path, f'Get-WpdRunCompletion -CaseDirectory {_ps_quote(case)} | ConvertTo-Json -Depth 20 -Compress')
    assert not any(s['collector'] == 'collection-error' for s in result['stages'])
    assert not any(r.startswith('collection-errors:') for r in result['reasons'])
