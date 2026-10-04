"""Stable registered transcript evidence, without running live collection."""
import json
from test_entrypoint_tiered_integration import SCRIPT, run_pwsh


def test_transcript_stops_before_registration_and_its_final_bytes_are_hashed(tmp_path):
    path = tmp_path / 'diagnostics-run-test.log'
    path.write_text('collection output\n', encoding='ascii')
    result = json.loads(run_pwsh(f"""
$path = '{path.as_posix()}'
$artifacts = New-Object System.Collections.ArrayList
function Stop-Transcript {{ param($ErrorAction); [System.IO.File]::AppendAllText($path, 'FINAL FOOTER') }}
Complete-WpdRunTranscript -TranscriptPath $path -ArtifactNames $artifacts -TranscriptStarted
$before = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
Complete-WpdRunTranscript -TranscriptPath $path -ArtifactNames $artifacts
[pscustomobject]@{{ names = @($artifacts); bytes = [System.IO.File]::ReadAllText($path); before = $before; after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }} | ConvertTo-Json -Compress
""", ['Complete-WpdRunTranscript']))
    assert result['names'] == ['diagnostics-run-test.log']
    assert result['bytes'].endswith('FINAL FOOTER')
    assert result['before'] == result['after']


def test_both_local_and_remote_callers_finalize_and_register_before_packaging():
    source = SCRIPT.read_text(encoding='utf-8-sig')
    calls = 'Complete-WpdRunTranscript -TranscriptPath $transcriptPath -ArtifactNames $collectedArtifacts'
    assert source.count(calls) == 2
    for call_offset in (source.index(calls), source.rindex(calls)):
        remainder = source[call_offset:]
        metadata = remainder.index('$collectionManifest.artifacts = Get-ArtifactMetadata')
        package = remainder.index('$collectionManifest = Add-CasePackageBlock')
        assert metadata < package
        assert 'Stop-Transcript' not in remainder[:package]
