"""Behavioral tests for the provider-neutral findings and technician report module.

The module is exercised through pwsh with synthetic objects only.  No Windows
provider, event log, trace reader, or network endpoint is queried by these tests.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE = REPO_ROOT / "src" / "Wpd.Report.psm1"


def run_pwsh(body: str) -> str:
    """Import the real report module and execute a PowerShell body."""
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    if not shutil.which(powershell):
        pytest.skip(f"{powershell} is required for the report module tests")
    module_path = str(MODULE).replace("'", "''")
    harness = f"""
$ErrorActionPreference = 'Stop'
Import-Module -Name '{module_path}' -Force -DisableNameChecking
Set-StrictMode -Version Latest
{body}
"""
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-Command", harness],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, (
        f"pwsh failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    return result.stdout.strip()


def run_json(body: str):
    output = run_pwsh(body)
    assert output, "PowerShell body did not emit JSON"
    return json.loads(output)


ARTIFACTS_PS = r"""
$artifacts = @(
    [pscustomobject]@{ Name = 'performance-samples.csv'; SizeBytes = 123; Sha256 = ('a' * 64) },
    [pscustomobject]@{ Name = 'incident-events.json'; SizeBytes = 321; Sha256 = ('b' * 64) },
    [pscustomobject]@{ Name = 'process-memory-samples.csv'; SizeBytes = 456; Sha256 = ('c' * 64) }
)
"""


def test_module_exports_report_surface_and_forbids_healthy_states():
    payload = run_json(
        r"""
$exported = @((Get-Command -Module 'Wpd.Report' -CommandType Function).Name)
[pscustomobject]@{
    Exported = $exported
    Categories = @(Get-WpdReportCategories)
    Outcomes = @(Get-WpdReportOutcomeValues)
    HasHealthy = (($exported -contains 'Get-WpdHealthyScore') -or (@(Get-WpdReportCategories) -contains 'healthy') -or (@(Get-WpdReportOutcomeValues) -contains 'healthy'))
} | ConvertTo-Json -Depth 8 -Compress
"""
    )
    required = {
        "New-WpdFinding",
        "New-WpdEvidenceIndex",
        "New-WpdEvidenceIndexRecord",
        "Test-WpdEvidenceLinks",
        "New-WpdDataQualityRecord",
        "Get-WpdDataQualitySummary",
        "Compare-WpdBaselineIncident",
        "Get-WpdNoEvidenceOf",
        "Invoke-WpdReportAnalysis",
        "New-WpdTechnicianReport",
        "ConvertTo-WpdHtmlReport",
        "Write-WpdReportHtml",
    }
    assert required.issubset(set(payload["Exported"]))
    assert payload["HasHealthy"] is False
    assert {
        "cpu-pressure",
        "memory-pressure",
        "memory-paging",
        "memory-leak",
        "disk-pressure",
        "disk-latency",
        "disk-space",
        "commit-attribution",
        "network-errors",
        "gpu-saturation",
        "ui-responsiveness",
        "boot-degradation",
        "power-throttling",
        "audio-glitch",
        "crash-evidence",
        "servicing-failure",
        "evidence-coverage",
        "coverage",
    }.issubset(set(payload["Categories"]))


def test_new_finding_has_rich_shape_and_preserves_legacy_provenance():
    payload = run_json(
        ARTIFACTS_PS
        + r"""
$evidence = New-WpdEvidenceIndexRecord -Id 'ev-cpu-1' -Artifact 'performance-samples.csv' `
    -Path 'performance-samples.csv' -Metric 'AverageCpuLoadPercent' -Value 94 `
    -WindowStartUtc '2026-09-10T12:00:00Z' -WindowEndUtc '2026-09-10T12:00:10Z' -Quality 'complete'
$index = New-WpdEvidenceIndex -Records @($evidence) -Artifacts $artifacts
$finding = New-WpdFinding -Id 'cpu-pressure-sustained:0' -Category 'cpu-pressure' `
    -Severity 'high' -Confidence 'High' -Title 'Sustained CPU pressure' `
    -Summary 'The measured CPU series stayed elevated during the incident.' `
    -Incident ([pscustomobject]@{ Id = 'incident-1'; WindowStartUtc = '2026-09-10T12:00:00Z'; WindowEndUtc = '2026-09-10T12:00:10Z' }) `
    -Evidence @($evidence) -EvidenceIndex $index `
    -Correlations @([pscustomobject]@{ With = 'process-cpu'; Kind = 'overlap'; Note = 'The process table overlaps the same window.' }) `
    -PossibleCauses @([pscustomobject]@{ Cause = 'A CPU-bound workload'; EvidenceIds = @('ev-cpu-1') }) `
    -NextSteps @('Collect a CPU trace over the cited window.') `
    -Limitations @('The counter does not identify causation.') `
    -SourceArtifact 'performance-samples.csv' -Metric 'AverageCpuLoadPercent' `
    -WindowStart '2026-09-10T12:00:00Z' -WindowEnd '2026-09-10T12:00:10Z' `
    -MeasuredValues ([ordered]@{ peak = 94 }) `
    -RuleCondition 'AverageCpuLoadPercent >= configured threshold' -Uncertainty 'Correlation is not causation.' `
    -SuggestedWprProfile 'CPU' -Rule ([pscustomobject]@{ Id = 'cpu-pressure-sustained'; Threshold = 80; MinimumSamples = 5; MinimumDurationSeconds = 5 })
[pscustomobject]@{
    Finding = $finding
    LinkCheck = Test-WpdEvidenceLinks -Findings @($finding) -EvidenceIndex $index
} | ConvertTo-Json -Depth 16 -Compress
"""
    )
    finding = payload["Finding"]
    for key in (
        "id",
        "category",
        "severity",
        "confidence",
        "title",
        "summary",
        "incident",
        "evidence",
        "correlations",
        "possibleCauses",
        "nextSteps",
        "limitations",
        "rule",
        "sourceArtifact",
        "metric",
        "windowStart",
        "windowEnd",
        "measuredValues",
        "ruleCondition",
        "uncertainty",
        "suggestedWprProfile",
    ):
        assert key in finding, key
    assert finding["id"] == "cpu-pressure-sustained:0"
    assert finding["confidence"] == "High"
    assert finding["evidence"][0]["id"] == "ev-cpu-1"
    assert finding["possibleCauses"][0]["evidenceIds"] == ["ev-cpu-1"]
    assert payload["LinkCheck"]["valid"] is True


def test_evidence_index_rejects_dangling_ids_and_unsafe_artifact_paths():
    payload = run_json(
        ARTIFACTS_PS
        + r"""
$good = New-WpdEvidenceIndexRecord -Id 'ev-good' -Artifact 'performance-samples.csv' `
    -Path 'performance-samples.csv' -Metric 'Value' -Value 1 -Quality 'complete'
$unsafe = New-WpdEvidenceIndexRecord -Id 'ev-unsafe' -Artifact 'performance-samples.csv' `
    -Path '../secrets.txt' -Metric 'Value' -Value 1 -Quality 'complete'
$encoded = New-WpdEvidenceIndexRecord -Id 'ev-encoded' -Artifact 'performance-samples.csv' `
    -Path 'sub/%2e%2e/secrets.txt' -Metric 'Value' -Value 1 -Quality 'complete'
$index = New-WpdEvidenceIndex -Records @($good, $unsafe) -Artifacts $artifacts
$validFinding = New-WpdFinding -Id 'good' -Category 'coverage' -Severity 'informational' `
    -Confidence 'Low' -Title 'Measured' -Summary 'Measured evidence.' -Evidence @($good) -EvidenceIndex $index
$dangling = [pscustomobject]@{ id = 'dangling'; category = 'coverage'; evidence = @([pscustomobject]@{ id = 'ev-missing'; artifact = 'incident-events.json'; path = 'incident-events.json' }) }
[pscustomobject]@{
    Index = $index
    Good = Test-WpdEvidenceLinks -Findings @($validFinding) -EvidenceIndex $index
    Bad = Test-WpdEvidenceLinks -Findings @($dangling) -EvidenceIndex $index
    UnsafePath = $unsafe.path
    UnsafeReason = $unsafe.reason
    EncodedPath = $encoded.path
    EncodedReason = $encoded.reason
} | ConvertTo-Json -Depth 12 -Compress
"""
    )
    assert payload["UnsafePath"] is None
    assert payload["UnsafeReason"] == "unsafe-path"
    assert payload["EncodedPath"] is None
    assert payload["EncodedReason"] == "unsafe-path"
    assert payload["Good"]["valid"] is True
    assert payload["Bad"]["valid"] is False
    assert "ev-missing" in payload["Bad"]["missingEvidenceIds"]


def test_data_quality_summary_marks_nulls_only_unavailable_and_partial():
    payload = run_json(
        r"""
$nulls = New-WpdDataQualityRecord -Collector 'cpu' -Status 'success' -ExpectedSamples 5 `
    -ObservedSamples 0 -DurationSeconds 5 -MinimumSamples 5 -MinimumDurationSeconds 5
$partial = New-WpdDataQualityRecord -Collector 'disk' -Status 'partial' -ExpectedSamples 5 `
    -ObservedSamples 4 -GapCount 1 -DroppedCount 0 -DurationSeconds 5 -MinimumSamples 3 -MinimumDurationSeconds 3
$inferredPartial = New-WpdDataQualityRecord -Collector 'network' -Status 'success' -ExpectedSamples 5 `
    -ObservedSamples 3 -DurationSeconds 5 -MinimumSamples 3 -MinimumDurationSeconds 3
$complete = New-WpdDataQualityRecord -Collector 'memory' -Status 'success' -ExpectedSamples 5 `
    -ObservedSamples 5 -DurationSeconds 5 -MinimumSamples 5 -MinimumDurationSeconds 5
$summary = Get-WpdDataQualitySummary -Records @($nulls, $partial, $complete)
[pscustomobject]@{
    Nulls = $nulls
    Partial = $partial
    InferredPartial = $inferredPartial
    Summary = $summary
    HasHealthy = (($nulls.status -eq 'healthy') -or ($nulls.coverage -eq 'healthy') -or ($summary.status -eq 'healthy'))
} | ConvertTo-Json -Depth 12 -Compress
"""
    )
    assert payload["Nulls"]["status"] == "unavailable"
    assert payload["Nulls"]["coverage"] == "unavailable"
    assert payload["Nulls"]["sufficient"] is False
    assert payload["Partial"]["coverage"] == "partial"
    assert payload["Partial"]["isUsable"] is True
    assert payload["InferredPartial"]["coverage"] == "partial"
    assert payload["Summary"]["coverage"] == "partial"
    assert payload["Summary"]["totalCollectors"] == 3
    assert payload["HasHealthy"] is False


def test_duration_aware_baseline_incident_comparison_uses_row_durations():
    payload = run_json(
        r"""
$baseline = @(
    [pscustomobject]@{ LatencySeconds = 1; DurationSeconds = 1 },
    [pscustomobject]@{ LatencySeconds = 2; DurationSeconds = 1 },
    [pscustomobject]@{ LatencySeconds = 3; DurationSeconds = 1 },
    [pscustomobject]@{ LatencySeconds = 4; DurationSeconds = 1 }
)
$incident = @(
    [pscustomobject]@{ LatencySeconds = 10; DurationSeconds = 2 },
    [pscustomobject]@{ LatencySeconds = 20; DurationSeconds = 1 },
    [pscustomobject]@{ LatencySeconds = 30; DurationSeconds = 1 }
)
$result = Compare-WpdBaselineIncident -BaselineRows $baseline -IncidentRows $incident `
    -ValueProperty 'LatencySeconds' -Percentiles @(50, 95, 99)
$result | ConvertTo-Json -Depth 12 -Compress
"""
    )
    assert payload["status"] == "measured"
    assert payload["BaselineDurationSeconds"] == 4
    assert payload["IncidentDurationSeconds"] == 4
    assert payload["baseline"]["P50"] == 2
    assert payload["incident"]["P50"] == 10
    assert payload["incident"]["P95"] == 30
    assert payload["DeltaP95"] == 26


def test_no_evidence_of_statements_are_gated_by_sufficient_quality():
    payload = run_json(
        r"""
$available = New-WpdDataQualityRecord -Collector 'cpu' -Status 'success' -ExpectedSamples 10 `
    -ObservedSamples 10 -DurationSeconds 10 -MinimumSamples 5 -MinimumDurationSeconds 5
$missing = New-WpdDataQualityRecord -Collector 'gpu' -Status 'unavailable' -ExpectedSamples 10 `
    -ObservedSamples 0 -DurationSeconds 10 -MinimumSamples 5 -MinimumDurationSeconds 5
$candidates = @(
    [pscustomobject]@{ Id = 'cpu-pressure'; Topic = 'sustained CPU pressure'; Collector = 'cpu'; EvidenceIds = @('ev-cpu') },
    [pscustomobject]@{ Id = 'gpu-reset'; Topic = 'a GPU reset'; Collector = 'gpu'; EvidenceIds = @('ev-gpu') }
)
$statements = @(Get-WpdNoEvidenceOf -Candidates $candidates -DataQuality @($available, $missing))
[pscustomobject]@{
    Count = $statements.Count
    Statements = $statements
} | ConvertTo-Json -Depth 10 -Compress
"""
    )
    assert payload["Count"] == 1
    assert payload["Statements"][0]["id"] == "cpu-pressure"
    assert "No strong evidence" in payload["Statements"][0]["text"]
    assert payload["Statements"][0]["evidenceIds"] == ["ev-cpu"]


def test_no_evidence_of_statements_with_an_index_cannot_emit_dangling_links():
    payload = run_json(
        r"""
$artifact = [pscustomobject]@{ Name = 'samples.json'; Sha256 = ('2' * 64) }
$evidence = New-WpdEvidenceIndexRecord -Id 'ev-present' -Artifact 'samples.json' -Path 'samples.json' -Metric 'Value' -Value 1 -Quality 'complete'
$index = New-WpdEvidenceIndex -Records @($evidence) -Artifacts @($artifact)
$quality = New-WpdDataQualityRecord -Collector 'samples' -Status 'success' -ObservedSamples 3 -ExpectedSamples 3 -DurationSeconds 3
$candidates = @(
    [pscustomobject]@{ Id = 'present'; Topic = 'measured absence'; Collector = 'samples'; EvidenceIds = @('ev-present') },
    [pscustomobject]@{ Id = 'missing'; Topic = 'unmeasured absence'; Collector = 'samples'; EvidenceIds = @('ev-missing') }
)
$statements = @(Get-WpdNoEvidenceOf -Candidates $candidates -DataQuality @($quality) -EvidenceIndex $index)
[pscustomobject]@{ Ids = @($statements | ForEach-Object { $_.id }); EvidenceIds = @($statements[0].evidenceIds) } | ConvertTo-Json -Depth 8 -Compress
"""
    )
    assert payload["Ids"] == ["present"]
    assert payload["EvidenceIds"] == ["ev-present"]


def test_analysis_requires_two_channels_for_paging_and_emits_root_cause_when_unresolved():
    payload = run_json(
        ARTIFACTS_PS
        + r"""
$rules = @(
    [pscustomobject]@{
        Id = 'memory-paging-with-pressure'; Category = 'memory-paging'; SourceArtifact = 'performance-samples.csv'; Metric = 'PagesInputPerSec'; Comparator = 'gt'; Threshold = 100; MinimumSamples = 3; MinimumDurationSeconds = 3
        CorrelationRequirements = @(
            [pscustomobject]@{ Metric = 'CommitPercent'; Comparator = 'ge'; Threshold = 90; Kind = 'required-any-of'; Note = 'commit pressure' },
            [pscustomobject]@{ Metric = 'AvailableMemoryMB'; Comparator = 'le'; Threshold = 512; Kind = 'required-any-of'; Note = 'low available memory' }
        )
        Severity = [pscustomobject]@{ Default = 'medium' }
        Confidence = [pscustomobject]@{ Default = 'Medium' }
        SuggestedWprProfile = 'GeneralProfile'; Uncertainty = 'Paging volume is not a fault count.'; NextSteps = 'Collect a trace.'
    }
)
$start = [datetime]'2026-09-10T12:00:00Z'
$ample = @(0..3 | ForEach-Object { [pscustomobject]@{ TimestampUtc = $start.AddSeconds($_); PagesInputPerSec = 200; CommitPercent = 40; AvailableMemoryMB = 4096 } })
$pressure = @(0..3 | ForEach-Object { [pscustomobject]@{ TimestampUtc = $start.AddSeconds($_); PagesInputPerSec = 200; CommitPercent = 95; AvailableMemoryMB = 256 } })
$ampleReport = Invoke-WpdReportAnalysis -Samples $ample -Rules $rules -Artifacts $artifacts
$pressureReport = Invoke-WpdReportAnalysis -Samples $pressure -Rules $rules -Artifacts $artifacts
$emptyReport = Invoke-WpdReportAnalysis -Samples @([pscustomobject]@{ TimestampUtc = $start; PagesInputPerSec = $null }) -Rules $rules -Artifacts $artifacts
[pscustomobject]@{
    AmpleFindings = @($ampleReport.findings)
    PressureFindings = @($pressureReport.findings)
    EmptyOutcome = $emptyReport.outcome
    EmptyQuality = $emptyReport.dataQuality.coverage
} | ConvertTo-Json -Depth 18 -Compress
"""
    )
    ample_categories = {row["category"] for row in payload["AmpleFindings"]}
    pressure_categories = {row["category"] for row in payload["PressureFindings"]}
    assert "memory-paging" not in ample_categories
    assert "coverage" in ample_categories
    assert "memory-paging" in pressure_categories
    assert any("without measured memory pressure" in row["summary"] for row in payload["AmpleFindings"])
    assert payload["EmptyOutcome"] == "ROOT CAUSE NOT IDENTIFIED"
    assert payload["EmptyQuality"] == "unavailable"


def test_unmet_required_correlation_emits_a_coverage_record_without_a_real_finding():
    payload = run_json(
        r"""
$artifact = [pscustomobject]@{ Name = 'correlation.json'; Sha256 = ('7' * 64) }
$rule = [pscustomobject]@{
    Id = 'queue-with-cpu'; Category = 'cpu-pressure'; SourceArtifact = 'correlation.json'; Metric = 'Queue'; Comparator = 'ge'; Threshold = 2; MinimumSamples = 2; MinimumDurationSeconds = 1
    CorrelationRequirements = @([pscustomobject]@{ Metric = 'Cpu'; Comparator = 'ge'; Threshold = 80; Kind = 'required-any-of' })
    Severity = [pscustomobject]@{ Default = 'medium' }; Confidence = [pscustomobject]@{ Default = 'Medium' }
}
$start = [datetime]'2026-09-10T12:00:00Z'
$samples = @(0..1 | ForEach-Object { [pscustomobject]@{ TimestampUtc = $start.AddSeconds($_); Queue = 3; Cpu = 20 } })
$report = Invoke-WpdReportAnalysis -Samples $samples -Rules @($rule) -Artifacts @($artifact)
[pscustomobject]@{
    Categories = @($report.findings | ForEach-Object { $_.category })
    Outcome = $report.outcome
    Validation = $report.evidenceValidation.valid
} | ConvertTo-Json -Depth 10 -Compress
"""
    )
    assert payload["Categories"] == ["coverage"]
    assert payload["Outcome"] == "ROOT CAUSE NOT IDENTIFIED"
    assert payload["Validation"] is True


def test_technician_report_orders_summary_timeline_and_incident_process_table():
    payload = run_json(
        ARTIFACTS_PS
        + r"""
$evidence = New-WpdEvidenceIndexRecord -Id 'ev-ui' -Artifact 'incident-events.json' `
    -Path 'incident-events.json' -Metric 'ApplicationHangEvents' -Value 1 `
    -WindowStartUtc '2026-09-10T12:00:00Z' -WindowEndUtc '2026-09-10T12:00:10Z' -Quality 'complete'
$index = New-WpdEvidenceIndex -Records @($evidence) -Artifacts $artifacts
$finding = New-WpdFinding -Id 'ui-hang-events:0' -Category 'ui-responsiveness' -Severity 'medium' `
    -Confidence 'Medium' -Title 'Application hang observed' -Summary 'A hang event overlaps the incident.' `
    -Evidence @($evidence) -EvidenceIndex $index -SourceArtifact 'incident-events.json' `
    -Metric 'ApplicationHangEvents' -MeasuredValues ([ordered]@{ count = 1 })
$timeline = @(
    [pscustomobject]@{ TimestampUtc = '2026-09-10T12:00:08Z'; Source = 'System'; Event = 'late' },
    [pscustomobject]@{ TimestampUtc = '2026-09-10T12:00:01Z'; Source = 'Application'; Event = 'early' }
)
$process = @(
    [pscustomobject]@{ TimestampUtc = '2026-09-10T11:59:59Z'; ProcessId = 1; StartTimeUtc = '2026-09-10T11:00:00Z'; ProcessName = 'outside'; CpuPercent = 99 },
    [pscustomobject]@{ TimestampUtc = '2026-09-10T12:00:05Z'; ProcessId = 2; StartTimeUtc = '2026-09-10T11:00:00Z'; ProcessName = 'inside'; CpuPercent = 55 }
)
$report = New-WpdTechnicianReport -Findings @($finding) -EvidenceIndex $index -Artifacts $artifacts `
    -Timeline $timeline -ProcessSamples $process `
    -Incident ([pscustomobject]@{ Id = 'incident-1'; WindowStartUtc = '2026-09-10T12:00:00Z'; WindowEndUtc = '2026-09-10T12:00:10Z' })
[pscustomobject]@{
    Sections = @($report.sections)
    Summary = $report.technicianSummary
    Timeline = @($report.timeline)
    ProcessRows = @($report.processTables[0].rows)
    Html = ConvertTo-WpdHtmlReport -Report $report
} | ConvertTo-Json -Depth 20 -Compress
"""
    )
    assert payload["Sections"][:4] == [
        "technician-summary",
        "coverage",
        "timeline",
        "incident-process",
    ]
    assert "ROOT CAUSE NOT IDENTIFIED" not in payload["Summary"]
    assert [row["Event"] for row in payload["Timeline"]] == ["early", "late"]
    assert [row["ProcessName"] for row in payload["ProcessRows"]] == ["inside"]
    assert "Technician Summary" in payload["Html"]
    assert payload["Html"].index("Technician Summary") < payload["Html"].index("Coverage")


def test_html_escapes_untrusted_values_has_no_script_or_external_assets_and_links_registered_artifacts():
    payload = run_json(
        r"""
$artifacts = @(
    [pscustomobject]@{ Name = 'incident-events.json'; SizeBytes = 4; Sha256 = ('d' * 64) }
)
$evidence = New-WpdEvidenceIndexRecord -Id 'ev-xss' -Artifact 'incident-events.json' `
    -Path 'incident-events.json' -Metric 'Event<Metric' -Value '<img src=x onerror=alert(1)>' -Quality 'complete'
$index = New-WpdEvidenceIndex -Records @($evidence) -Artifacts $artifacts
$finding = New-WpdFinding -Id 'mystery:0' -Category 'vendor<unknown' -Severity 'informational' `
    -Confidence 'Low' -Title '<script>alert(1)</script>' -Summary 'A <b>raw</b> summary' `
    -Evidence @($evidence) -EvidenceIndex $index -SourceArtifact 'incident-events.json' `
    -Metric 'Event<Metric' -MeasuredValues ([ordered]@{ raw = '<svg onload=alert(1)>' })
$report = New-WpdTechnicianReport -Findings @($finding) -EvidenceIndex $index -Artifacts $artifacts
$html = ConvertTo-WpdHtmlReport -Report $report
[pscustomobject]@{
    Html = $html
    HasScript = ($html -match '(?i)<script')
    HasExternal = ($html -match '(?i)(https?://|<link\b|src=)')
    HasEscapedTitle = ($html -match '&lt;script&gt;alert\(1\)&lt;/script&gt;')
    HasRawTitle = ($html -match '<script>alert\(1\)</script>')
    HasArtifactLink = ($html -match 'href="incident-events\.json"')
    HasFallback = ($html -match 'Other Findings')
} | ConvertTo-Json -Depth 6 -Compress
"""
    )
    assert payload["HasScript"] is False
    assert payload["HasExternal"] is False
    assert payload["HasEscapedTitle"] is True
    assert payload["HasRawTitle"] is False
    assert payload["HasArtifactLink"] is True
    assert payload["HasFallback"] is True


def test_malformed_finding_is_downgraded_without_fake_percentage_confidence():
    payload = run_json(
        r"""
$finding = New-WpdFinding -Id 'bad:0' -Category 'not-a-known-category' -Severity 'not-a-severity' `
    -Confidence '87%' -Title $null -Summary $null -Evidence @()
[pscustomobject]@{
    Finding = $finding
    HasNumericConfidence = ($finding.confidence -is [double] -or "$($finding.confidence)" -match '%')
    HasHealthScore = ($finding.PSObject.Properties.Name -contains 'healthScore')
} | ConvertTo-Json -Depth 10 -Compress
"""
    )
    assert payload["Finding"]["category"] == "not-a-known-category"
    assert payload["Finding"]["severity"] == "informational"
    assert payload["Finding"]["confidence"] == "Low"
    assert payload["Finding"]["title"] == "Other finding"
    assert payload["HasNumericConfidence"] is False
    assert payload["HasHealthScore"] is False


def test_common_confidence_export_and_ui_attribution_limitation_are_explicit():
    payload = run_json(
        r"""
$artifact = [pscustomobject]@{ Name = 'incident-events.json'; SizeBytes = 1; Sha256 = ('e' * 64) }
$evidence = New-WpdEvidenceIndexRecord -Id 'ev-ui-symbols' -Artifact 'incident-events.json' `
    -Path 'incident-events.json' -Metric 'ApplicationHangEvents' -Value 1 -Quality 'complete'
$index = New-WpdEvidenceIndex -Records @($evidence) -Artifacts @($artifact)
$finding = New-WpdFinding -Id 'ui:0' -Category 'ui-responsiveness' -Severity 'medium' `
    -Confidence 'Medium' -Title 'UI hang observed' -Summary 'A hang was recorded.' `
    -Evidence @($evidence) -EvidenceIndex $index -MeasuredValues ([ordered]@{ SymbolsAvailable = $false })
[pscustomobject]@{
    ConfidenceValues = @(Get-WpdConfidenceValues)
    Limitations = @($finding.limitations)
} | ConvertTo-Json -Depth 8 -Compress
"""
    )
    assert payload["ConfidenceValues"] == ["High", "Medium", "Low"]
    assert any("cannot attribute without symbols" in value.lower() for value in payload["Limitations"])


def test_report_does_not_promote_missing_evidence_to_a_root_cause_finding():
    payload = run_json(
        r"""
$finding = New-WpdFinding -Id 'bad:0' -Category 'cpu-pressure' -Severity 'high' `
    -Confidence 'High' -Title 'Unproven CPU pressure' -Summary 'There is no cited measurement.' -Evidence @()
$report = New-WpdTechnicianReport -Findings @($finding)
[pscustomobject]@{
    Outcome = $report.outcome
    Status = $report.status
    Validation = $report.evidenceValidation.valid
    Summary = $report.technicianSummary
} | ConvertTo-Json -Depth 8 -Compress
"""
    )
    assert payload["Outcome"] == "ROOT CAUSE NOT IDENTIFIED"
    assert payload["Status"] != "success"
    assert payload["Validation"] is False
    assert "ROOT CAUSE NOT IDENTIFIED" in payload["Summary"]


def test_dangling_possible_cause_evidence_invalidates_the_finding():
    payload = run_json(
        r"""
$artifact = [pscustomobject]@{ Name = 'cause.json'; Sha256 = ('4' * 64) }
$evidence = New-WpdEvidenceIndexRecord -Id 'ev-observed' -Artifact 'cause.json' -Path 'cause.json' -Metric 'Value' -Value 1 -Quality 'complete'
$index = New-WpdEvidenceIndex -Records @($evidence) -Artifacts @($artifact)
$finding = New-WpdFinding -Id 'cause:0' -Category 'cpu-pressure' -Severity 'medium' -Confidence 'Medium' `
    -Title 'Unsupported cause' -Summary 'The cause is not supported by the cited index.' -Evidence @($evidence) `
    -PossibleCauses @([pscustomobject]@{ Cause = 'Missing process evidence'; EvidenceIds = @('ev-missing') }) -EvidenceIndex $index
$report = New-WpdTechnicianReport -Findings @($finding) -EvidenceIndex $index
[pscustomobject]@{
    FindingValid = $finding.validation.valid
    FindingMissing = @($finding.validation.causeMissingEvidenceIds)
    LinkValid = (Test-WpdEvidenceLinks -Findings @($finding) -EvidenceIndex $index).valid
    Outcome = $report.outcome
} | ConvertTo-Json -Depth 10 -Compress
"""
    )
    assert payload["FindingValid"] is False
    assert payload["FindingMissing"] == ["ev-missing"]
    assert payload["LinkValid"] is False
    assert payload["Outcome"] == "ROOT CAUSE NOT IDENTIFIED"


def test_empty_report_is_unavailable_rather_than_successful_or_healthy():
    payload = run_json(
        r"""
$report = New-WpdTechnicianReport -Findings @() -Samples @() -Rules @()
[pscustomobject]@{
    Status = $report.status
    Outcome = $report.outcome
    Quality = $report.dataQuality.coverage
    EvidenceCoverage = $report.evidenceIndex.coverage
} | ConvertTo-Json -Depth 8 -Compress
"""
    )
    assert payload["Status"] == "unavailable"
    assert payload["Outcome"] == "ROOT CAUSE NOT IDENTIFIED"
    assert payload["Quality"] == "unavailable"
    assert payload["EvidenceCoverage"] == "unavailable"


def test_report_merges_generated_evidence_into_a_supplied_index():
    payload = run_json(
        r"""
$artifact = [pscustomobject]@{ Name = 'performance-samples.csv'; SizeBytes = 2; Sha256 = ('f' * 64) }
$existingEvidence = New-WpdEvidenceIndexRecord -Id 'ev-existing' -Artifact 'performance-samples.csv' `
    -Path 'performance-samples.csv' -Metric 'Existing' -Value 1 -Quality 'complete'
$index = New-WpdEvidenceIndex -Records @($existingEvidence) -Artifacts @($artifact)
$rule = [pscustomobject]@{
    Id = 'cpu-generated'; Category = 'cpu-pressure'; SourceArtifact = 'performance-samples.csv'; Metric = 'Value'; Comparator = 'ge'; Threshold = 80; MinimumSamples = 2; MinimumDurationSeconds = 1
    Severity = [pscustomobject]@{ Default = 'medium' }; Confidence = [pscustomobject]@{ Default = 'Medium' }
}
$start = [datetime]'2026-09-10T12:00:00Z'
$samples = @(0..1 | ForEach-Object { [pscustomobject]@{ TimestampUtc = $start.AddSeconds($_); Value = 90 } })
$report = New-WpdTechnicianReport -EvidenceIndex $index -Artifacts @($artifact) -Samples $samples -Rules @($rule)
[pscustomobject]@{
    Validation = $report.evidenceValidation.valid
    RecordIds = @($report.evidenceIndex.records | ForEach-Object { $_.id })
    FindingIds = @($report.findings | ForEach-Object { $_.id })
} | ConvertTo-Json -Depth 10 -Compress
"""
    )
    assert payload["Validation"] is True
    assert "ev-existing" in payload["RecordIds"]
    assert "cpu-generated:0" in payload["FindingIds"]


def test_safe_artifact_without_hash_is_linkable_but_reports_missing_integrity_metadata():
    payload = run_json(
        r"""
$artifact = [pscustomobject]@{ Name = 'raw-output.json'; SizeBytes = 4 }
$evidence = New-WpdEvidenceIndexRecord -Id 'ev-raw' -Artifact 'raw-output.json' `
    -Path 'raw-output.json' -Metric 'Value' -Value 1 -Quality 'complete'
$index = New-WpdEvidenceIndex -Records @($evidence) -Artifacts @($artifact)
$finding = New-WpdFinding -Id 'raw:0' -Category 'coverage' -Severity 'informational' `
    -Confidence 'Low' -Title 'Raw output' -Summary 'Measured output.' -Evidence @($evidence)
$report = New-WpdTechnicianReport -Findings @($finding) -EvidenceIndex $index -Artifacts @($artifact)
$html = ConvertTo-WpdHtmlReport -Report $report
[pscustomobject]@{
    Registered = $report.evidenceIndex.artifacts[0].registered
    Hashed = $report.evidenceIndex.artifacts[0].hashed
    Linkable = $report.evidenceIndex.records[0].linkable
    HtmlHasLink = ($html -match 'href="raw-output\.json"')
    Reason = $report.evidenceIndex.artifacts[0].reason
} | ConvertTo-Json -Depth 10 -Compress
"""
    )
    assert payload["Registered"] is True
    assert payload["Hashed"] is False
    assert payload["Linkable"] is True
    assert payload["HtmlHasLink"] is True
    assert payload["Reason"] == "missing-or-invalid-sha256"


def test_rule_analysis_uses_generic_numeric_samples_and_explicit_severity_escalation():
    payload = run_json(
        r"""
$artifact = [pscustomobject]@{ Name = 'custom-samples.json'; SizeBytes = 2; Sha256 = ('1' * 64) }
$rule = [pscustomobject]@{
    Id = 'custom-pressure'; Category = 'cpu-pressure'; SourceArtifact = 'custom-samples.json'; Metric = 'CustomMetric'; Comparator = 'ge'; Threshold = 80; MinimumSamples = 3; MinimumDurationSeconds = 2
    Severity = [pscustomobject]@{
        Default = 'medium'
        Escalations = @([pscustomobject]@{ Severity = 'high'; PeakThreshold = 95; MinimumSamples = 3 })
    }
    Confidence = [pscustomobject]@{ Default = 'Low' }
}
$start = [datetime]'2026-09-10T12:00:00Z'
$samples = @(0..2 | ForEach-Object { [pscustomobject]@{ TimestampUtc = $start.AddSeconds($_); CustomMetric = 100 } })
$report = Invoke-WpdReportAnalysis -Samples $samples -Rules @($rule) -Artifacts @($artifact)
[pscustomobject]@{
    Severity = $report.findings[0].severity
    Quality = $report.dataQuality.coverage
    Validation = $report.evidenceValidation.valid
} | ConvertTo-Json -Depth 10 -Compress
"""
    )
    assert payload["Severity"] == "high"
    assert payload["Quality"] == "complete"
    assert payload["Validation"] is True


def test_rule_analysis_sorts_out_of_order_timestamps_before_duration_checks():
    payload = run_json(
        r"""
$artifact = [pscustomobject]@{ Name = 'ordered.json'; Sha256 = ('3' * 64) }
$rule = [pscustomobject]@{
    Id = 'ordered-run'; Category = 'cpu-pressure'; SourceArtifact = 'ordered.json'; Metric = 'Value'; Comparator = 'ge'; Threshold = 1; MinimumSamples = 3; MinimumDurationSeconds = 2
    Severity = [pscustomobject]@{ Default = 'medium' }; Confidence = [pscustomobject]@{ Default = 'Medium' }
}
$start = [datetime]'2026-09-10T12:00:00Z'
$samples = @(
    [pscustomobject]@{ TimestampUtc = $start.AddSeconds(2); Value = 5 },
    [pscustomobject]@{ TimestampUtc = $start; Value = 5 },
    [pscustomobject]@{ TimestampUtc = $start.AddSeconds(1); Value = 5 }
)
$report = Invoke-WpdReportAnalysis -Samples $samples -Rules @($rule) -Artifacts @($artifact)
[pscustomobject]@{ Count = @($report.findings).Count; Start = $report.findings[0].windowStart; End = $report.findings[0].windowEnd } | ConvertTo-Json -Depth 8 -Compress
"""
    )
    assert payload["Count"] == 1
    assert payload["Start"] == "2026-09-10T12:00:00.0000000Z"
    assert payload["End"] == "2026-09-10T12:00:02.0000000Z"


def test_disk_rules_fall_back_to_generic_samples_when_no_disk_series_is_supplied():
    payload = run_json(
        r"""
$artifact = [pscustomobject]@{ Name = 'disk-samples.json'; Sha256 = ('5' * 64) }
$rule = [pscustomobject]@{
    Id = 'disk-fallback'; Category = 'disk-pressure'; SourceArtifact = 'disk-samples.json'; Metric = 'CurrentQueueLength'; Comparator = 'ge'; Threshold = 2; MinimumSamples = 2; MinimumDurationSeconds = 1
    Severity = [pscustomobject]@{ Default = 'medium' }; Confidence = [pscustomobject]@{ Default = 'Medium' }
}
$start = [datetime]'2026-09-10T12:00:00Z'
$samples = @(0..1 | ForEach-Object { [pscustomobject]@{ TimestampUtc = $start.AddSeconds($_); CurrentQueueLength = 4 } })
$diskSeries = @(0..1 | ForEach-Object { [pscustomobject]@{ TimestampUtc = $start.AddSeconds($_); OtherMetric = 1 } })
$report = Invoke-WpdReportAnalysis -Samples $samples -DiskSeries $diskSeries -Rules @($rule) -Artifacts @($artifact)
[pscustomobject]@{ Count = @($report.findings).Count; Validation = $report.evidenceValidation.valid } | ConvertTo-Json -Depth 8 -Compress
"""
    )
    assert payload["Count"] == 1
    assert payload["Validation"] is True


def test_trend_rules_do_not_call_a_transient_spike_a_memory_leak():
    payload = run_json(
        r"""
$artifact = [pscustomobject]@{ Name = 'process-memory-samples.csv'; Sha256 = ('6' * 64) }
$rule = [pscustomobject]@{
    Id = 'leak-trend'; Category = 'memory-leak'; SourceArtifact = 'process-memory-samples.csv'; Metric = 'WorkingSetGrowthPercent'; Comparator = 'ge'; Threshold = 10; MinimumSamples = 3; MinimumDurationSeconds = 2
    Trend = [pscustomobject]@{ Direction = 'increasing'; MinimumDeltaPercent = 20; MinimumSamples = 3; MonotonicWindow = 3 }
    Severity = [pscustomobject]@{ Default = 'medium' }; Confidence = [pscustomobject]@{ Default = 'Medium' }
}
$start = [datetime]'2026-09-10T12:00:00Z'
$samples = @(
    [pscustomobject]@{ TimestampUtc = $start; WorkingSetGrowthPercent = 10; ProcessId = 7; StartTimeUtc = $start.AddMinutes(-5) },
    [pscustomobject]@{ TimestampUtc = $start.AddSeconds(1); WorkingSetGrowthPercent = 40; ProcessId = 7; StartTimeUtc = $start.AddMinutes(-5) },
    [pscustomobject]@{ TimestampUtc = $start.AddSeconds(2); WorkingSetGrowthPercent = 15; ProcessId = 7; StartTimeUtc = $start.AddMinutes(-5) }
)
$report = Invoke-WpdReportAnalysis -ProcessSamples $samples -Rules @($rule) -Artifacts @($artifact)
[pscustomobject]@{ Count = @($report.findings).Count; Outcome = $report.outcome } | ConvertTo-Json -Depth 8 -Compress
"""
    )
    assert payload["Count"] == 0
    assert payload["Outcome"] == "ROOT CAUSE NOT IDENTIFIED"
