"""Pure-helper coverage for the WPD-06/07 live-case harness.

The tests extract the real helper function bodies (and the harness's own
classification tables) from the harness AST and run those bodies against
synthetic data. No live collection, no Windows-only provider and no event log is
touched here: these are the off-Windows guards for the comparison logic that the
live case depends on.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
HARNESS = REPO_ROOT / "tests" / "live" / "Invoke-WpdLiveCase0607.ps1"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

EVENT_FUNCTIONS = [
    "Get-WpdProperty",
    "Get-WpdUtcStamp",
    "Get-WpdEventKey",
    "Compare-WpdEventEvidence",
]
NETWORK_FUNCTIONS = ["ConvertFrom-WpdNetstat", "Test-WpdRemoteAddressIsLocal"]
BANNED_FUNCTIONS = ["Get-WpdBannedProcessMatch"]
BANNED_ASSIGNMENTS = ["$script:WpdBannedProcessNames", "$script:WpdBannedCommandPatterns"]
STATE_FUNCTIONS = ["Compare-WpdState"]
CLEARING_FUNCTIONS = ["Get-WpdEventLogClearingVerdict"]


def _ps_literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def run_pwsh(body: str, functions: list[str], assignments: list[str] | None = None) -> str:
    """Extract harness functions/assignments by AST and execute a test body."""
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    if not shutil.which(powershell):
        pytest.skip(f"{powershell} is required for the live-helper gate")
    assert HARNESS.is_file(), f"live harness is missing: {HARNESS}"
    names = ", ".join(_ps_literal(name) for name in functions)
    assignment_names = ", ".join(_ps_literal(name) for name in (assignments or []))
    harness_path = str(HARNESS).replace("'", "''")
    command = f"""
$ErrorActionPreference = 'Stop'
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{harness_path}', [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {{ throw "harness parse failed: $($parseErrors.Count) error(s)" }}
foreach ($name in @({names})) {{
    $found = @($ast.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }}, $true))
    if ($found.Count -ne 1) {{ throw "expected exactly one function named $name, found $($found.Count)" }}
    Invoke-Expression $found[0].Extent.Text
}}
foreach ($assignmentName in @({assignment_names})) {{
    $found = @($ast.FindAll({{ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq $assignmentName }}, $true))
    if ($found.Count -ne 1) {{ throw "expected exactly one assignment to $assignmentName, found $($found.Count)" }}
    Invoke-Expression $found[0].Extent.Text
}}
Set-StrictMode -Version Latest
{body}
"""
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-Command", command],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, (
        f"pwsh failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    return result.stdout.strip()


def run_pwsh_json(body: str, functions: list[str], assignments: list[str] | None = None) -> dict:
    output = run_pwsh(body, functions, assignments)
    assert output, "PowerShell helper body emitted no JSON"
    return json.loads(output.splitlines()[-1])


def test_harness_parses_is_ascii_and_declares_both_cases():
    raw = HARNESS.read_bytes()
    assert all(byte < 128 for byte in raw), "the live-case harness must stay ASCII-only"
    text = raw.decode("ascii")
    assert "[ValidateSet('WPD-06', 'WPD-07')]" in text
    assert "exit 0" in text and "exit 1" in text and "exit 2" in text, (
        "the harness must keep the PASS/FAIL/NOT-RUN exit-code contract"
    )
    # A parse failure is a hard error: the AST gate inside run_pwsh throws.
    payload = run_pwsh_json(
        "[pscustomobject]@{ ok = $true } | ConvertTo-Json -Compress",
        EVENT_FUNCTIONS[:1],
    )
    assert payload == {"ok": True}


def test_event_evidence_accepts_an_ordered_bounded_corroborated_summary():
    payload = run_pwsh_json(
        r"""
$lookback = [datetime]::UtcNow.AddHours(-24)
$live = @(
    [pscustomobject]@{ TimeCreated = $lookback.AddHours(23); Id = 5000; ProviderName = 'Live'; Message = 'm1' }
    [pscustomobject]@{ TimeCreated = $lookback.AddHours(22); Id = 5001; ProviderName = 'Live'; Message = 'm2' }
    [pscustomobject]@{ TimeCreated = $lookback.AddHours(21); Id = 777; ProviderName = 'WpdLiveControl'; Message = 'controlled' }
    [pscustomobject]@{ TimeCreated = $lookback.AddHours(20); Id = 5002; ProviderName = 'Live'; Message = 'm4' }
)
$artifact = @($live[0..2])
$evidence = Compare-WpdEventEvidence -ArtifactRows $artifact -LiveRows $live -Bound 3 -LookbackStartUtc $lookback
[pscustomobject]@{
    count = $evidence.artifactCount
    liveCount = $evidence.liveRowCount
    ordered = $evidence.orderedNewestFirst
    missing = @($evidence.missingFromLiveLog).Count
    duplicates = $evidence.duplicateKeys
    outside = $evidence.rowsOutsideLookback
    oldest = $evidence.oldestArtifactUtc
    newest = $evidence.newestArtifactUtc
} | ConvertTo-Json -Compress
""",
        EVENT_FUNCTIONS,
    )

    assert payload["count"] == 3
    assert payload["liveCount"] == 4
    assert payload["ordered"] is True
    assert payload["missing"] == 0
    assert payload["duplicates"] == 0
    assert payload["outside"] == 0
    assert payload["oldest"] < payload["newest"]


def test_event_evidence_flags_fabricated_unordered_and_out_of_lookback_rows():
    payload = run_pwsh_json(
        r"""
$lookback = [datetime]::UtcNow.AddHours(-24)
$live = @(
    [pscustomobject]@{ TimeCreated = $lookback.AddHours(1); Id = 10; ProviderName = 'Live'; Message = 'm' }
)
$artifact = @(
    [pscustomobject]@{ TimeCreated = $lookback.AddHours(1); Id = 10; ProviderName = 'Live'; Message = 'm' }
    [pscustomobject]@{ TimeCreated = $lookback.AddHours(3); Id = 99; ProviderName = 'Fabricated'; Message = 'x' }
    [pscustomobject]@{ TimeCreated = $lookback.AddHours(-5); Id = 11; ProviderName = 'Live'; Message = 'old' }
)
$evidence = Compare-WpdEventEvidence -ArtifactRows $artifact -LiveRows $live -Bound 5 -LookbackStartUtc $lookback
[pscustomobject]@{
    ordered = $evidence.orderedNewestFirst
    missing = @($evidence.missingFromLiveLog)
    missingCount = @($evidence.missingFromLiveLog).Count
    outside = $evidence.rowsOutsideLookback
    bounded = ($evidence.artifactCount -le $evidence.bound)
} | ConvertTo-Json -Compress
""",
        EVENT_FUNCTIONS,
    )

    assert payload["ordered"] is False
    assert payload["missingCount"] == 2
    assert "Fabricated" in payload["missing"][0]
    assert payload["outside"] == 1
    assert payload["bounded"] is True


def test_netstat_parser_keeps_tcp_and_udp_rows_and_ignores_headers():
    payload = run_pwsh_json(
        r"""
$text = @(
    ''
    'Active Connections'
    '  Proto  Local Address          Foreign Address        State           PID'
    '  TCP    127.0.0.1:51422        127.0.0.1:51423        ESTABLISHED     4321'
    '  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1024'
    '  TCP    [::1]:49670            [::]:0                 LISTENING       2048'
    '  UDP    0.0.0.0:5353           *:*                                    3000'
    '  UDP    [::]:3702              *:*                                    3001'
    '  TCP    10.0.0.7:50123        93.184.216.34:443      ESTABLISHED     5555'
)
$rows = @(ConvertFrom-WpdNetstat -Lines $text)
$local = @($rows | ForEach-Object { Test-WpdRemoteAddressIsLocal -RemoteAddress $_.RemoteAddress })
$remoteSample = @($rows | Where-Object { $_.ProcessId -eq '5555' })[0]
[pscustomobject]@{
    count = $rows.Count
    protocols = (($rows | ForEach-Object { $_.Protocol } | Select-Object -Unique) -join '|')
    pids = (($rows | ForEach-Object { $_.ProcessId }) -join ',')
    udpProcessId = @($rows | Where-Object { $_.Protocol -eq 'UDP' })[0].ProcessId
    locals = ($local -join ',')
    remoteIsLocal = (Test-WpdRemoteAddressIsLocal -RemoteAddress $remoteSample.RemoteAddress)
    wildcardIsLocal = (Test-WpdRemoteAddressIsLocal -RemoteAddress '*:*')
    emptyIsLocal = (Test-WpdRemoteAddressIsLocal -RemoteAddress '')
} | ConvertTo-Json -Compress
""",
        NETWORK_FUNCTIONS,
    )

    assert payload["count"] == 6
    assert payload["protocols"] == "TCP|UDP"
    assert payload["pids"] == "4321,1024,2048,3000,3001,5555"
    assert payload["udpProcessId"] == "3000"
    assert payload["locals"] == "True,True,True,True,True,False"
    assert payload["remoteIsLocal"] is False
    assert payload["wildcardIsLocal"] is True
    assert payload["emptyIsLocal"] is True


def test_banned_tooling_classifier_allows_readonly_native_tools_and_flags_remediation():
    output = run_pwsh(
        r"""
$cases = @(
    @{ name = 'netstat.exe'; command = 'netstat -ano' }
    @{ name = 'netsh.exe'; command = 'netsh int ipv4 show dynamicport udp' }
    @{ name = 'conhost.exe'; command = 'conhost.exe 0x4' }
    @{ name = 'wevtutil.exe'; command = 'wevtutil cl System' }
    @{ name = 'dism.exe'; command = 'DISM /Online /Cleanup-Image /RestoreHealth' }
    @{ name = 'sfc.exe'; command = 'sfc /scannow' }
    @{ name = 'powershell.exe'; command = 'powershell -Command Clear-EventLog -LogName System' }
    @{ name = 'powershell.exe'; command = "Invoke-WebRequest -Uri https://example.invalid/x" }
    @{ name = 'MpCmdRun.exe'; command = 'MpCmdRun.exe -RemoveDefinitions -All' }
)
$results = foreach ($case in $cases) {
    [pscustomobject]@{
        name = $case.name
        matches = @(Get-WpdBannedProcessMatch -ProcessName $case.name -CommandLine $case.command).Count
    }
}
($results | ForEach-Object { ('{0}={1}' -f $_.name, $_.matches) }) -join ';'
""",
        BANNED_FUNCTIONS,
        BANNED_ASSIGNMENTS,
    )

    counts: dict[str, int] = {}
    for entry in output.split(";"):
        name, _, value = entry.partition("=")
        counts[name] = counts.get(name, 0) + int(value)

    # Read-only native tooling the collector legitimately uses must not match.
    assert counts["netstat.exe"] == 0
    assert counts["netsh.exe"] == 0
    assert counts["conhost.exe"] == 0

    # Remediation, log-clearing, policy and transfer tooling must match (by name,
    # by command line, or both).
    for banned in (
        "wevtutil.exe",
        "dism.exe",
        "sfc.exe",
        "powershell.exe",
        "MpCmdRun.exe",
    ):
        assert counts[banned] >= 1, f"{banned} was not classified as banned tooling"


def test_state_comparison_reports_only_changed_strict_surfaces():
    payload = run_pwsh_json(
        r"""
$before = [ordered]@{
    strict = [ordered]@{
        defenderPreferences = [ordered]@{ available = $true; exclusionPath = @() }
        runKeys = @('HKCU|One|hash-old')
        eventLogs = @('System|enabled=True|maxBytes=20971520|mode=Circular')
    }
}
$after = [ordered]@{
    strict = [ordered]@{
        defenderPreferences = [ordered]@{ available = $true; exclusionPath = @('C:\Temp') }
        runKeys = @('HKCU|One|hash-old')
        eventLogs = @('System|enabled=True|maxBytes=20971520|mode=Circular')
    }
}
$deltas = @(Compare-WpdState -Before $before -After $after)
$unchanged = @(Compare-WpdState -Before $before -After $before)
[pscustomobject]@{
    changedCount = $deltas.Count
    changedSurface = [string]$deltas[0].surface
    afterValue = [string]$deltas[0].after
    unchangedCount = $unchanged.Count
} | ConvertTo-Json -Compress
""",
        STATE_FUNCTIONS,
    )

    assert payload["changedCount"] == 1
    assert payload["changedSurface"] == "defenderPreferences"
    assert "C:\\\\Temp" in payload["afterValue"] or "C:\\Temp" in payload["afterValue"]
    assert payload["unchangedCount"] == 0


def test_event_log_clearing_verdict_detects_a_cleared_log_only():
    payload = run_pwsh_json(
        r"""
$before = @(
    [pscustomobject]@{ name = 'System'; oldestRecordNumber = 100; recordCount = 500; fileSize = 20000000 }
    [pscustomobject]@{ name = 'Application'; oldestRecordNumber = 10; recordCount = 50; fileSize = 4000000 }
)
$appended = @(
    [pscustomobject]@{ name = 'System'; oldestRecordNumber = 101; recordCount = 505; fileSize = 20010000 }
    [pscustomobject]@{ name = 'Application'; oldestRecordNumber = 10; recordCount = 52; fileSize = 4002000 }
)
$cleared = @(
    [pscustomobject]@{ name = 'System'; oldestRecordNumber = 1; recordCount = 0; fileSize = 0 }
    [pscustomobject]@{ name = 'Application'; oldestRecordNumber = 10; recordCount = 52; fileSize = 4002000 }
)
$wrapped = @(
    [pscustomobject]@{ name = 'System'; oldestRecordNumber = 900; recordCount = 500; fileSize = 20000000 }
    [pscustomobject]@{ name = 'Application'; oldestRecordNumber = 10; recordCount = 52; fileSize = 4002000 }
)
$appendedVerdict = @(Get-WpdEventLogClearingVerdict -BeforeLogs $before -AfterLogs $appended | Where-Object { $_.cleared -eq $true })
$clearedVerdict = @(Get-WpdEventLogClearingVerdict -BeforeLogs $before -AfterLogs $cleared | Where-Object { $_.cleared -eq $true })
$wrappedVerdict = @(Get-WpdEventLogClearingVerdict -BeforeLogs $before -AfterLogs $wrapped | Where-Object { $_.cleared -eq $true })
$missingVerdict = @(Get-WpdEventLogClearingVerdict -BeforeLogs @() -AfterLogs $appended)
[pscustomobject]@{
    appendedCleared = $appendedVerdict.Count
    clearedCleared = $clearedVerdict.Count
    clearedLog = if ($clearedVerdict.Count -gt 0) { $clearedVerdict[0].log } else { '' }
    wrappedCleared = $wrappedVerdict.Count
    missingStatus = $missingVerdict[0].status
} | ConvertTo-Json -Compress
""",
        CLEARING_FUNCTIONS,
    )

    assert payload["appendedCleared"] == 0
    assert payload["clearedCleared"] == 1
    assert payload["clearedLog"] == "System"
    assert payload["wrappedCleared"] == 0
    assert payload["missingStatus"] == "not-assessable"


def test_live_gates_job_runs_both_cases_against_both_builds():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"]["wpd-live-gates"]
    steps = job["steps"]

    case_steps = [
        step
        for step in steps
        if step.get("name", "").startswith(("WPD-06", "WPD-07"))
    ]
    assert len(case_steps) == 4, "expected WPD-06/07 for the checked-out build and the published release"

    names = [step["name"] for step in case_steps]
    assert sum("build under test" in name for name in names) == 2
    assert sum("published release" in name for name in names) == 2

    for step in case_steps:
        body = step["run"]
        assert "Invoke-WpdLiveCase0607.ps1" in body
        assert "exit $LASTEXITCODE" in body, "a NON-EXIT verdict must fail the step"
        assert "-Case WPD-0" in body

    wpd06 = [step for step in case_steps if step["name"].startswith("WPD-06")]
    wpd07 = [step for step in case_steps if step["name"].startswith("WPD-07")]
    assert all("-MaxEventCount 50" in step["run"] for step in wpd06)
    assert all("-MaxEventCount 200" in step["run"] for step in wpd07)

    release_steps = [step for step in case_steps if "published release" in step["name"]]
    assert all("steps.wpd0405_release.outputs.ok == 'true'" in step.get("if", "") for step in release_steps)
    assert all(step.get("if") == "always()" for step in case_steps if "build under test" in step["name"])
