"""Case ZIP artifact identities use the same normalization in both manifests."""

import hashlib
import json
import zipfile

import pytest

from test_entrypoint_tiered_integration import run_tool
from test_plan_mode import _write_minimal_collect_case


@pytest.mark.parametrize('artifact_name', ['case/technician-report.html', r'case\technician-report.html'])
def test_package_verify_accepts_normalized_nested_artifact_names(tmp_path, artifact_name):
    case = _write_minimal_collect_case(tmp_path)
    nested = case / 'case' / 'technician-report.html'
    nested.parent.mkdir()
    nested.write_bytes(b'<html>offline report</html>')
    manifest_path = case / 'diagnostic-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['artifacts'].append({
        'Name': artifact_name,
        'SizeBytes': nested.stat().st_size,
        'Sha256': hashlib.sha256(nested.read_bytes()).hexdigest(),
    })
    archive_path = case.parent / 'nested-case.zip'
    with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('performance-samples.csv', (case / 'performance-samples.csv').read_bytes())
        archive.writestr('case/technician-report.html', nested.read_bytes())
        archive.writestr('diagnostic-manifest.json', json.dumps(manifest))
    data = archive_path.read_bytes()
    manifest['package'] = {
        'enabled': True, 'status': 'completed', 'zipPath': str(archive_path),
        'sizeBytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
        'includesManifest': True,
    }
    manifest_path.write_text(json.dumps(manifest))
    result = run_tool('-Mode', 'Verify', '-InputDirectory', str(case))
    report = json.loads(result.stdout)
    assert result.returncode == 0, report
    assert report['package']['status'] == 'verified'
    assert report['verifiedArtifactCount'] == 2
