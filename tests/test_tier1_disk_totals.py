"""Behavioral regression for aggregate LogicalDisk counter rows."""

import json

from test_entrypoint_tiered_integration import run_pwsh


def test_total_disk_counter_is_not_counted_as_an_additional_volume():
    result = json.loads(run_pwsh(
        """
$rows = @(
    [pscustomobject]@{ Name = 'C:'; FreeMegabytes = 1024; PercentFreeSpace = 25 },
    [pscustomobject]@{ Name = 'D:'; FreeMegabytes = 2048; PercentFreeSpace = 50 },
    [pscustomobject]@{ Name = '_Total'; FreeMegabytes = 3072; PercentFreeSpace = 40 }
)
Get-WpdTier1SampleRow -LogicalDiskCounterRows $rows | ConvertTo-Json -Depth 10 -Compress
""",
        ['Get-WpdIntegrationProperty', 'Get-WpdIntegrationNumber', 'Get-WpdTier1SampleRow'],
    ))
    assert result['TotalLogicalDiskFreeGB'] == 3.0
    assert [row['Name'] for row in result['LogicalDisks']] == ['C:', 'D:']
