"""Behavioral tests for Wpd.Etw.psm1 (Tier 2 ETW/WPR surface).

The module runs on Linux: every Windows-only call (wpr.exe, wpaexporter.exe,
file-system probes) is reached through an injected seam, so these tests assert
the exact documented argv and the failure semantics without pretending to be
Windows. The documented sources are:

- https://learn.microsoft.com/windows-hardware/test/wpt/wpr-command-line-options
- https://learn.microsoft.com/windows-hardware/test/wpt/exporter

Tests MUST fail if an undocumented switch (for example -maxduration or
-filesize) appears in a constructed command line, or if a boot descriptor is
ever executed rather than described.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE = REPO_ROOT / "src" / "Wpd.Etw.psm1"


def run_pwsh(body: str) -> str:
    """Import the real ETW module and execute a test body."""
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    assert shutil.which(powershell), f"{powershell} is required for the etw gate"
    module_path = str(MODULE).replace("'", "''")
    harness = f"""
$ErrorActionPreference = 'Stop'
Import-Module -Name '{module_path}' -Force
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
    return result.stdout


def run_pwsh_json(body: str) -> dict:
    output = run_pwsh(body)
    assert output.strip(), "PowerShell body emitted no JSON"
    return json.loads(output)


REQUIRED_COMMANDS = [
    "Find-WpdEtwTool",
    "Get-WpdEtwAnalysisTablePlan",
    "Get-WpdEtwPresetProfile",
    "Get-WpdEtwPresetTable",
    "Get-WpdEtwSymbolPolicy",
    "Get-WpdEtwTraceValidation",
    "Invoke-WpdEtwCapture",
    "Invoke-WpdEtwCommand",
    "New-WpdEtwBootScenarioDescriptor",
    "New-WpdEtwExporterCommand",
    "New-WpdEtwWprCancelCommand",
    "New-WpdEtwWprMarkerCommand",
    "New-WpdEtwWprProfilesCommand",
    "New-WpdEtwWprStartCommand",
    "New-WpdEtwWprStatusCommand",
    "New-WpdEtwWprStopCommand",
    "Test-WpdEtwAbandonedSession",
    "Test-WpdEtwCapturePreflight",
]


def test_module_imports_and_exports_the_etw_surface():
    """The module loads on a non-Windows host without touching wpr.exe, and
    exports exactly the documented command surface."""
    body = """
$exported = @((Get-Command -Module 'Wpd.Etw' -CommandType Function).Name)
[pscustomobject]@{
    Loaded = $true
    Exported = $exported
    Count = $exported.Count
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)
    exported = set(payload["Exported"])
    missing = sorted(set(REQUIRED_COMMANDS) - exported)
    assert missing == [], f"module does not export: {missing}"
    assert payload["Count"] == len(exported)


CANONICAL_PRESETS = [
    "general",
    "cpu-heavy",
    "memory-pressure",
    "memory-leak",
    "storage-io",
    "network",
    "gpu",
    "ui-hang",
    "ui-stutter",
    "boot-slowdown",
    "audio-glitch",
    "power",
    "intermittent",
]

DEPRECATED_ALIASES = {
    "baseline": "general",
    "network-io": "network",
    "application-freeze": "ui-hang",
}

# Documented WPR built-in profiles the existing entry point already accepts.
DOCUMENTED_BUILT_IN_PROFILES = {
    "GeneralProfile",
    "CPU",
    "DiskIO",
    "FileIO",
    "Network",
    "Power",
    "GPU",
    "Registry",
}

# TSS argument values that are NOT WPR built-in profile names and must never be
# used in a raw wpr.exe command line.
TSS_ONLY_PROFILE_NAMES = [
    "BootGeneral",
    "Device",
    "Memory",
    "Storage",
    "Wait",
    "SQL",
    "Graphic",
    "Xaml",
    "VSOD_CPU",
    "VSOD_Leak",
]


def test_preset_table_maps_every_preset_to_a_documented_wpr_profile():
    """Thirteen canonical presets plus three deprecated aliases resolve to a
    documented built-in WPR profile, a qualifier, a bounded trace budget and a
    bounded table list. No TSS argument name leaks in as a profile name."""
    body = """
$table = @(Get-WpdEtwPresetTable)
$rows = @($table | ForEach-Object {
    [pscustomobject]@{
        preset = $_.preset
        aliasOf = $_.aliasOf
        profile = $_.profile
        qualifier = $_.qualifier
        mode = $_.mode
        traceBudgetMB = $_.traceBudgetMB
        maxDurationSeconds = $_.maxDurationSeconds
        analysisTables = @($_.analysisTables)
        unbounded = $_.unbounded
    }
})
[pscustomobject]@{
    Rows = $rows
    Presets = @($rows | Where-Object { -not $_.aliasOf } | ForEach-Object { $_.preset })
    Duplicates = @($rows | Group-Object preset | Where-Object { $_.Count -gt 1 }).Count
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)
    rows = payload["Rows"]
    by_preset = {row["preset"]: row for row in rows}

    assert sorted(payload["Presets"]) == sorted(CANONICAL_PRESETS)
    assert payload["Duplicates"] == 0

    for alias, canonical in DEPRECATED_ALIASES.items():
        assert alias in by_preset, f"missing deprecated alias {alias}"
        assert by_preset[alias]["aliasOf"] == canonical, alias
        # An alias row is an alias, not a second policy.
        assert by_preset[alias]["traceBudgetMB"] is None, alias

    for preset in CANONICAL_PRESETS:
        row = by_preset[preset]
        assert row["aliasOf"] is None, preset
        assert row["profile"] in DOCUMENTED_BUILT_IN_PROFILES, preset
        assert row["qualifier"] in ("light", "verbose"), preset
        assert row["mode"] == "memory", preset
        assert row["unbounded"] is False, preset
        assert row["traceBudgetMB"] > 0, preset
        assert row["maxDurationSeconds"] > 0, preset
        assert len(row["analysisTables"]) > 0, preset

    joined = " ".join(str(row["profile"]) for row in rows)
    for tss_name in TSS_ONLY_PROFILE_NAMES:
        assert tss_name not in joined.split(), f"TSS-only name used as profile: {tss_name}"


def test_get_preset_profile_resolves_aliases_and_keeps_file_mode_opt_in():
    """An alias resolves to its canonical preset, memory mode is the default, and
    file mode is only reachable with an explicit opt-in that flags the recording
    as unbounded."""
    body = """
$alias = Get-WpdEtwPresetProfile -Preset 'baseline'
$networkAlias = Get-WpdEtwPresetProfile -Preset 'network-io'
$freezeAlias = Get-WpdEtwPresetProfile -Preset 'application-freeze'
$canonical = Get-WpdEtwPresetProfile -Preset 'cpu-heavy'
$file = Get-WpdEtwPresetProfile -Preset 'general' -AllowFileMode
$unknown = $null
try { Get-WpdEtwPresetProfile -Preset 'not-a-preset' | Out-Null } catch { $unknown = $_.Exception.Message }
[pscustomobject]@{
    AliasRequested = $alias.RequestedPreset
    AliasEffective = $alias.EffectivePreset
    AliasProfile = $alias.Profile
    NetworkAliasEffective = $networkAlias.EffectivePreset
    FreezeAliasEffective = $freezeAlias.EffectivePreset
    CanonicalProfile = $canonical.Profile
    CanonicalQualifier = $canonical.Qualifier
    CanonicalMode = $canonical.Mode
    CanonicalUnbounded = $canonical.Unbounded
    CanonicalFileModeRequested = $canonical.FileModeRequested
    FileMode = $file.Mode
    FileUnbounded = $file.Unbounded
    FileModeRequested = $file.FileModeRequested
    UnknownRejected = ($null -ne $unknown)
    UnknownMessage = $unknown
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["AliasRequested"] == "baseline"
    assert payload["AliasEffective"] == "general"
    assert payload["AliasProfile"] in DOCUMENTED_BUILT_IN_PROFILES
    assert payload["NetworkAliasEffective"] == "network"
    assert payload["FreezeAliasEffective"] == "ui-hang"
    assert payload["CanonicalProfile"] == "CPU"
    assert payload["CanonicalQualifier"] in ("light", "verbose")
    assert payload["CanonicalMode"] == "memory"
    assert payload["CanonicalUnbounded"] is False
    assert payload["CanonicalFileModeRequested"] is False
    assert payload["FileMode"] == "file"
    assert payload["FileUnbounded"] is True
    assert payload["FileModeRequested"] is True
    assert payload["UnknownRejected"] is True
    assert "not-a-preset" in payload["UnknownMessage"]


def test_memory_mode_is_the_bounded_circular_buffer_and_file_mode_is_unbounded():
    """Memory mode is the documented default and is the bounded circular buffer;
    file mode records to an unbounded file whose only bound is free disk space.
    The policy states which one it is instead of leaving it to the reader."""
    body = """
$memory = Get-WpdEtwPresetProfile -Preset 'general'
$file = Get-WpdEtwPresetProfile -Preset 'general' -AllowFileMode
[pscustomobject]@{
    MemorySemantics = $memory.BufferSemantics
    MemoryCircular = $memory.CircularBuffer
    MemoryBounded = $memory.BoundedOnDisk
    MemoryNote = $memory.ModeNote
    FileSemantics = $file.BufferSemantics
    FileCircular = $file.CircularBuffer
    FileBounded = $file.BoundedOnDisk
    FileNote = $file.ModeNote
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["MemorySemantics"] == "circular-memory"
    assert payload["MemoryCircular"] is True
    assert payload["MemoryBounded"] is True
    assert "circular" in payload["MemoryNote"].lower()

    assert payload["FileSemantics"] == "unbounded-file"
    assert payload["FileCircular"] is False
    assert payload["FileBounded"] is False
    assert "unbounded" in payload["FileNote"].lower()
    assert "disk" in payload["FileNote"].lower()


def test_start_command_uses_only_documented_wpr_arguments():
    """`wpr -start <profile>[.{light|verbose}]` plus the documented On/Off and
    -instancename options, and nothing else. The verbose/light qualifier comes
    from the preset; -filemode appears only for an explicit file-mode opt-in."""
    body = """
$general = Get-WpdEtwPresetProfile -Preset 'general'
$cpu = Get-WpdEtwPresetProfile -Preset 'cpu-heavy'
$file = Get-WpdEtwPresetProfile -Preset 'general' -AllowFileMode
$onoff = New-WpdEtwWprStartCommand -PresetProfile $cpu -OnOffScenario 'Boot' `
    -OnOffResultsPath 'C:\\case\\wpr-analysis\\boot.etl' -OnOffProblemDescription 'slow boot' -NumIterations 1
$instanced = New-WpdEtwWprStartCommand -PresetProfile $general -InstanceName 'WpdSession1'
$memory = New-WpdEtwWprStartCommand -PresetProfile $general
$fileMode = New-WpdEtwWprStartCommand -PresetProfile $file
[pscustomobject]@{
    MemoryTool = $memory.Tool
    MemoryArguments = @($memory.Arguments)
    MemoryLine = $memory.CommandLine
    MemoryKind = $memory.Kind
    MemoryMode = $memory.Mode
    MemoryProfileSpec = $memory.ProfileSpec
    FileArguments = @($fileMode.Arguments)
    OnOffArguments = @($onoff.Arguments)
    InstancedArguments = @($instanced.Arguments)
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["MemoryTool"] == "wpr.exe"
    assert payload["MemoryKind"] == "start"
    assert payload["MemoryMode"] == "memory"
    assert payload["MemoryProfileSpec"] == "GeneralProfile.light"
    assert payload["MemoryArguments"] == ["-start", "GeneralProfile.light"]

    # File mode is reachable only through the explicit opt-in.
    assert payload["FileArguments"] == ["-start", "GeneralProfile.light", "-filemode"]

    # On/Off options are passed in the documented order, and the recording is
    # described for a single iteration rather than the default three reboots.
    assert payload["OnOffArguments"] == [
        "-start",
        "CPU.verbose",
        "-onoffscenario",
        "Boot",
        "-onoffresultspath",
        "C:\\case\\wpr-analysis\\boot.etl",
        "-onoffproblemdescription",
        "slow boot",
        "-numiterations",
        "1",
    ]

    # -instancename must be the last parameter.
    assert payload["InstancedArguments"][-2:] == ["-instancename", "WpdSession1"]

    for invented in ("-maxduration", "-filesize", "-maxfile", "-markerflush", "-duration", "-size"):
        assert invented not in payload["MemoryLine"], payload["MemoryLine"]
        for argv in (
            payload["MemoryArguments"],
            payload["FileArguments"],
            payload["OnOffArguments"],
            payload["InstancedArguments"],
        ):
            assert invented not in argv, (invented, argv)


DOCUMENTED_MARKERS = [
    "CAPTURE_START",
    "REPRO_START",
    "INCIDENT_START",
    "INCIDENT_PEAK",
    "INCIDENT_END",
    "CAPTURE_STOP",
]


def test_marker_commands_use_the_documented_marker_form():
    """`wpr -marker <text> [-flush]` for every incident marker, never the
    obsolete -markerflush, and never a marker name the toolkit did not define."""
    body = """
$commands = @($env:WPD_ETW_MARKERS -split ',' | ForEach-Object {
    $command = New-WpdEtwWprMarkerCommand -Marker $_
    [pscustomobject]@{ Marker = $_; Arguments = @($command.Arguments); Line = $command.CommandLine; Tool = $command.Tool }
})
$flushed = New-WpdEtwWprMarkerCommand -Marker 'INCIDENT_PEAK' -Flush
$instanced = New-WpdEtwWprMarkerCommand -Marker 'CAPTURE_STOP' -InstanceName 'WpdSession1'
$invalid = $null
try { New-WpdEtwWprMarkerCommand -Marker 'SOMETHING_ELSE' | Out-Null } catch { $invalid = $_.Exception.Message }
[pscustomobject]@{
    Commands = $commands
    FlushArguments = @($flushed.Arguments)
    InstancedArguments = @($instanced.Arguments)
    InvalidRejected = ($null -ne $invalid)
} | ConvertTo-Json -Depth 6 -Compress
"""
    environ = dict(os.environ)
    environ["WPD_ETW_MARKERS"] = ",".join(DOCUMENTED_MARKERS)
    powershell = os.environ.get("WPD_POWERSHELL_EXE", "pwsh")
    assert shutil.which(powershell)
    module_path = str(MODULE).replace("'", "''")
    harness = f"""
$ErrorActionPreference = 'Stop'
Import-Module -Name '{module_path}' -Force
Set-StrictMode -Version Latest
{body}
"""
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-Command", harness],
        capture_output=True,
        check=False,
        text=True,
        env=environ,
    )
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    payload = json.loads(result.stdout)

    assert [row["Marker"] for row in payload["Commands"]] == DOCUMENTED_MARKERS
    for row in payload["Commands"]:
        assert row["Tool"] == "wpr.exe"
        assert row["Arguments"] == ["-marker", row["Marker"]], row
        assert row["Line"] == f"wpr.exe -marker {row['Marker']}"

    assert payload["FlushArguments"] == ["-marker", "INCIDENT_PEAK", "-flush"]
    assert payload["InstancedArguments"][-2:] == ["-instancename", "WpdSession1"]
    assert payload["InvalidRejected"] is True
    joined = " ".join(row["Line"] for row in payload["Commands"])
    assert "-markerflush" not in joined


def test_lifecycle_and_status_commands_use_only_documented_argv():
    """`wpr -stop <file> <problem description>`, `wpr -cancel`, `wpr -status
    [profiles] [collectors [-details]]` and `wpr -profiles [<path>]`, each in
    its documented shape and never with an invented switch."""
    body = """
$stop = New-WpdEtwWprStopCommand -EtlPath 'C:\\case\\wpr-trace.etl' -ProblemDescription 'sustained CPU pressure'
$stopFast = New-WpdEtwWprStopCommand -EtlPath 'C:\\case\\wpr-trace.etl' -ProblemDescription 'slow app' -SkipPdbGen -Force
$stopInstanced = New-WpdEtwWprStopCommand -EtlPath 'C:\\case\\wpr-trace.etl' -InstanceName 'WpdSession1'
$cancel = New-WpdEtwWprCancelCommand
$cancelInstanced = New-WpdEtwWprCancelCommand -InstanceName 'WpdSession1'
$status = New-WpdEtwWprStatusCommand
$statusCollectors = New-WpdEtwWprStatusCommand -Collectors -Details
$profiles = New-WpdEtwWprProfilesCommand
$profilesPath = New-WpdEtwWprProfilesCommand -ProfilePath 'C:\\case\\custom.wprp'
[pscustomobject]@{
    Stop = @($stop.Arguments); StopKind = $stop.Kind; StopTool = $stop.Tool
    StopFast = @($stopFast.Arguments)
    StopInstanced = @($stopInstanced.Arguments)
    Cancel = @($cancel.Arguments)
    CancelInstanced = @($cancelInstanced.Arguments)
    Status = @($status.Arguments)
    StatusCollectors = @($statusCollectors.Arguments)
    Profiles = @($profiles.Arguments)
    ProfilesPath = @($profilesPath.Arguments)
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["StopTool"] == "wpr.exe"
    assert payload["StopKind"] == "stop"
    assert payload["Stop"] == ["-stop", "C:\\case\\wpr-trace.etl", "sustained CPU pressure"]
    assert payload["StopFast"] == [
        "-stop",
        "C:\\case\\wpr-trace.etl",
        "slow app",
        "-skipPdbGen",
        "-force",
    ]
    # -instancename stays last; -stop without a description is still documented
    # (the description is recommended, not required).
    assert payload["StopInstanced"][:2] == ["-stop", "C:\\case\\wpr-trace.etl"]
    assert payload["StopInstanced"][-2:] == ["-instancename", "WpdSession1"]

    assert payload["Cancel"] == ["-cancel"]
    assert payload["CancelInstanced"][-2:] == ["-instancename", "WpdSession1"]

    assert payload["Status"] == ["-status"]
    assert payload["StatusCollectors"] == ["-status", "collectors", "-details"]

    assert payload["Profiles"] == ["-profiles"]
    assert payload["ProfilesPath"] == ["-profiles", "C:\\case\\custom.wprp"]

    for argv in (
        payload["Stop"],
        payload["StopFast"],
        payload["StopInstanced"],
        payload["Cancel"],
        payload["CancelInstanced"],
        payload["Status"],
        payload["StatusCollectors"],
        payload["Profiles"],
        payload["ProfilesPath"],
    ):
        for invented in ("-maxduration", "-filesize", "-maxfile", "-markerflush", "-recordtempto"):
            assert invented not in argv, (invented, argv)


def test_boot_scenario_descriptors_describe_without_rebooting_or_executing():
    """On/Off scenario recording and autologger boot tracing are returned as
    descriptors only: nothing is executed, the reboot requirement is stated, and
    the documented default of three on/off reboots is reported instead of being
    presented as a single-boot capture."""
    body = """
$onoff = New-WpdEtwBootScenarioDescriptor -Scenario 'Boot' -Mechanism 'onoff' -Profile 'GeneralProfile' `
    -ResultsPath 'C:\\case\\wpr-analysis\\boot.etl' -ProblemDescription 'slow boot' -NumIterations 1
$onoffDefault = New-WpdEtwBootScenarioDescriptor -Scenario 'Shutdown' -Mechanism 'onoff' -Profile 'GeneralProfile'
$autologger = New-WpdEtwBootScenarioDescriptor -Scenario 'FastStartup' -Mechanism 'boottrace' -Profile 'GeneralProfile' `
    -ResultsPath 'C:\\case\\wpr-analysis\\boot.etl' -ProblemDescription 'slow startup'
[pscustomobject]@{
    OnOffKind = $onoff.Kind
    OnOffExecuted = $onoff.Executed
    OnOffRequiresOperatorApproval = $onoff.RequiresOperatorApproval
    OnOffRequiresReboot = $onoff.RequiresReboot
    OnOffFileBacked = $onoff.FileBacked
    OnOffRebootCount = $onoff.RebootCount
    OnOffAssignment = @($onoff.Assignment.Arguments)
    OnOffCompletion = @($onoff.Completion.Arguments)
    OnOffCleanup = @($onoff.Cleanup.Arguments)
    DefaultRebootCount = $onoffDefault.RebootCount
    DefaultWarning = ($onoffDefault.Warnings -join ' ')
    AutoKind = $autologger.Kind
    AutoExecuted = $autologger.Executed
    AutoRequiresReboot = $autologger.RequiresReboot
    AutoFileBacked = $autologger.FileBacked
    AutoAssignment = @($autologger.Assignment.Arguments)
    AutoCompletion = @($autologger.Completion.Arguments)
    AutoCleanup = @($autologger.Cleanup.Arguments)
    AutoWarnings = ($autologger.Warnings -join ' ')
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["OnOffKind"] == "boot-descriptor"
    assert payload["OnOffExecuted"] is False
    assert payload["OnOffRequiresOperatorApproval"] is True
    assert payload["OnOffRequiresReboot"] is True
    # On/off transitions are always logged to a file, never to the memory arena.
    assert payload["OnOffFileBacked"] is True
    assert payload["OnOffRebootCount"] == 1
    assert payload["DefaultRebootCount"] == 3
    assert "three" in payload["DefaultWarning"].lower()

    assert payload["OnOffAssignment"] == [
        "-start",
        "GeneralProfile.verbose",
        "-onoffscenario",
        "Boot",
        "-onoffresultspath",
        "C:\\case\\wpr-analysis\\boot.etl",
        "-onoffproblemdescription",
        "slow boot",
        "-numiterations",
        "1",
    ]
    assert payload["OnOffCompletion"][0] == "-stop"
    assert payload["OnOffCleanup"] == ["-cancel"]

    # Autologger tracing configures registry entries; it records nothing until
    # the machine has rebooted, and -stopboot yields no trace without that boot.
    assert payload["AutoKind"] == "boot-descriptor"
    assert payload["AutoExecuted"] is False
    assert payload["AutoRequiresReboot"] is True
    assert payload["AutoFileBacked"] is True
    assert payload["AutoAssignment"][:3] == ["-boottrace", "-addboot", "GeneralProfile.verbose"]
    assert payload["AutoCompletion"][:2] == ["-boottrace", "-stopboot"]
    assert payload["AutoCleanup"] == ["-boottrace", "-cancelboot"]
    assert "reboot" in payload["AutoWarnings"].lower()

    for argv in (payload["OnOffAssignment"], payload["AutoAssignment"]):
        for invented in ("-maxduration", "-filesize", "-markerflush"):
            assert invented not in argv, (invented, argv)


def test_tool_discovery_reports_absent_wpt_tools_without_failing():
    """wpr.exe, wpa.exe and wpaexporter.exe are discovered through the path
    probe. A missing tool is 'not-present' with a reason, never an error and
    never a healthy result, so an absent Windows Performance Toolkit degrades a
    run instead of aborting it."""
    body = """
$probe = {
    param($path)
    # Only the WPR binary exists on this synthetic host.
    return ($path -like '*wpr.exe')
}
$tools = @(Find-WpdEtwTool -SearchPaths @('C:\\Program Files\\Windows Kits\\10\\Windows Performance Toolkit') -PathProbe $probe)
$legacyProbe = { param($path) return $false }
$absent = @(Find-WpdEtwTool -SearchPaths @('C:\\Program Files\\Windows Kits\\10\\Windows Performance Toolkit') -PathProbe $legacyProbe)
[pscustomobject]@{
    Tools = @($tools | ForEach-Object {
        [pscustomobject]@{ Tool = $_.Tool; Status = $_.Status; Path = $_.Path; Reason = $_.Reason; Found = $_.Found }
    })
    Absent = @($absent | ForEach-Object {
        [pscustomobject]@{ Tool = $_.Tool; Status = $_.Status; Path = $_.Path; Reason = $_.Reason; Found = $_.Found }
    })
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert [row["Tool"] for row in payload["Tools"]] == ["wpr", "wpa", "wpaexporter"]
    by_tool = {row["Tool"]: row for row in payload["Tools"]}

    assert by_tool["wpr"]["Found"] is True
    assert by_tool["wpr"]["Status"] == "present"
    assert by_tool["wpr"]["Path"].lower().endswith("wpr.exe")

    assert by_tool["wpaexporter"]["Found"] is False
    assert by_tool["wpaexporter"]["Status"] == "not-present"
    assert by_tool["wpaexporter"]["Path"] is None
    assert "wpaexporter" in by_tool["wpaexporter"]["Reason"].lower()

    # Nothing found: every tool is not-present with a reason and no exception.
    assert {row["Status"] for row in payload["Absent"]} == {"not-present"}
    for row in payload["Absent"]:
        assert row["Reason"], row
        assert row["Found"] is False


def test_symbol_policy_reports_presence_and_never_downloads_by_default():
    """Managed symbols written beside the trace are detected. Their absence is an
    'unavailable' state for symbol-dependent analysis, and symbol download stays
    off unless explicitly enabled - the toolkit never fetches symbols itself."""
    body = """
$presentProbe = { param($path) return ($path -like '*.NGenPdb') }
$absentProbe = { param($path) return $false }
$present = Get-WpdEtwSymbolPolicy -TracePath 'C:\\case\\wpr-trace.etl' -PathProbe $presentProbe
$absent = Get-WpdEtwSymbolPolicy -TracePath 'C:\\case\\wpr-trace.etl' -PathProbe $absentProbe
$optedIn = Get-WpdEtwSymbolPolicy -TracePath 'C:\\case\\wpr-trace.etl' -PathProbe $absentProbe -AllowSymbolDownload
[pscustomobject]@{
    PresentSymbolsPresent = $present.SymbolsPresent
    PresentState = $present.State
    PresentUseSymbolsSwitch = $present.UseSymbolsSwitch
    PresentDownloadAllowed = $present.DownloadAllowed
    PresentSymbolDirectory = $present.SymbolDirectory
    AbsentSymbolsPresent = $absent.SymbolsPresent
    AbsentState = $absent.State
    AbsentUseSymbolsSwitch = $absent.UseSymbolsSwitch
    AbsentDownloadAllowed = $absent.DownloadAllowed
    AbsentReason = $absent.Reason
    OptedInDownloadAllowed = $optedIn.DownloadAllowed
    OptedInNote = $optedIn.Note
} | ConvertTo-Json -Depth 6 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["PresentSymbolsPresent"] is True
    assert payload["PresentState"] == "available"
    assert payload["PresentUseSymbolsSwitch"] is True
    assert payload["PresentDownloadAllowed"] is False
    assert payload["PresentSymbolDirectory"].endswith("wpr-trace.NGenPdb")

    assert payload["AbsentSymbolsPresent"] is False
    assert payload["AbsentState"] == "unavailable"
    assert payload["AbsentUseSymbolsSwitch"] is False
    assert payload["AbsentDownloadAllowed"] is False
    # Absence is stated as a limitation, never as health.
    assert "symbol" in payload["AbsentReason"].lower()

    assert payload["OptedInDownloadAllowed"] is True
    # Even when enabled, the toolkit itself does not fetch symbols.
    assert "not downloaded by this toolkit" in payload["OptedInNote"].lower()


def test_capture_preflight_gates_on_space_duration_and_unbounded_file_mode():
    """The preflight refuses a capture that cannot fit, one that outruns the
    preset's maximum duration, and file mode (unbounded until the disk fills)
    unless it is explicitly accepted. An unmeasured free-space value is
    'unavailable' - never a pass."""
    body = """
$general = Get-WpdEtwPresetProfile -Preset 'general'
$file = Get-WpdEtwPresetProfile -Preset 'general' -AllowFileMode
$ready = Test-WpdEtwCapturePreflight -PresetProfile $general -FreeSpaceBytes 10737418240 -RequestedDurationSeconds 300
$tight = Test-WpdEtwCapturePreflight -PresetProfile $general -FreeSpaceBytes 104857600 -RequestedDurationSeconds 300
$long = Test-WpdEtwCapturePreflight -PresetProfile $general -FreeSpaceBytes 10737418240 -RequestedDurationSeconds 3600
$fileMode = Test-WpdEtwCapturePreflight -PresetProfile $file -FreeSpaceBytes 10737418240 -RequestedDurationSeconds 300
$fileAccepted = Test-WpdEtwCapturePreflight -PresetProfile $file -FreeSpaceBytes 10737418240 -RequestedDurationSeconds 300 -AcceptUnboundedFileMode
$unmeasured = Test-WpdEtwCapturePreflight -PresetProfile $general -RequestedDurationSeconds 300
[pscustomobject]@{
    ReadyStatus = $ready.Status
    ReadyFlag = $ready.Ready
    ReadyRequiredBytes = $ready.RequiredBytes
    ReadyBudgetMB = $ready.TraceBudgetMB
    ReadyDurationBounded = $ready.DurationBounded
    TightStatus = $tight.Status
    TightReady = $tight.Ready
    TightDeficitBytes = $tight.DeficitBytes
    TightReason = $tight.Reason
    LongStatus = $long.Status
    LongReady = $long.Ready
    LongMaxDuration = $long.MaxDurationSeconds
    FileStatus = $fileMode.Status
    FileReady = $fileMode.Ready
    FileReason = $fileMode.Reason
    FileAcceptedStatus = $fileAccepted.Status
    FileAcceptedReady = $fileAccepted.Ready
    FileAcceptedWarnings = ($fileAccepted.Warnings -join ' ')
    UnmeasuredStatus = $unmeasured.Status
    UnmeasuredReady = $unmeasured.Ready
    UnmeasuredReason = $unmeasured.Reason
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["ReadyStatus"] == "ready"
    assert payload["ReadyFlag"] is True
    assert payload["ReadyBudgetMB"] == 512
    # The requirement is the trace budget plus headroom, not the budget alone.
    assert payload["ReadyRequiredBytes"] > 512 * 1024 * 1024
    assert payload["ReadyDurationBounded"] is True

    assert payload["TightStatus"] == "insufficient-space"
    assert payload["TightReady"] is False
    assert payload["TightDeficitBytes"] > 0
    assert "space" in payload["TightReason"].lower()

    assert payload["LongStatus"] == "duration-exceeds-preset"
    assert payload["LongReady"] is False
    assert payload["LongMaxDuration"] == 600

    assert payload["FileStatus"] == "unbounded-file-mode"
    assert payload["FileReady"] is False
    assert "unbounded" in payload["FileReason"].lower()

    assert payload["FileAcceptedStatus"] == "ready"
    assert payload["FileAcceptedReady"] is True
    assert "unbounded" in payload["FileAcceptedWarnings"].lower()

    # No free-space measurement: unavailable, not a pass.
    assert payload["UnmeasuredStatus"] == "unavailable"
    assert payload["UnmeasuredReady"] is False
    assert "free space" in payload["UnmeasuredReason"].lower()


ACTIVE_STATUS = (
    "WPR recording is in progress...\n\n"
    "Time since start        : 00:04:27\n\n"
    "Dropped event           : 0\n\n"
    "Logging mode            : Memory\n\n"
    "Profiles                : GeneralProfile.light\n"
)

NO_SESSION_STATUS = "There are no trace profiles running.\n"


def _run_status(status_text: str, instance_name: str = "WpdSession1", owner_tag: str = "WPD"):
    body = f"""
$status = @'
{status_text}
'@
$result = Test-WpdEtwAbandonedSession -StatusOutput $status -OwnerTag '{owner_tag}' -ExpectedInstanceName '{instance_name}'
[pscustomobject]@{{
    State = $result.State
    Abandoned = $result.Abandoned
    Foreign = $result.Foreign
    CleanupRequired = $result.CleanupRequired
    CleanupCommand = @($result.CleanupCommand | Where-Object {{ $null -ne $_ }} | ForEach-Object {{ $_.Arguments }})
    StopSaveCommand = @($result.StopSaveCommand | Where-Object {{ $null -ne $_ }} | ForEach-Object {{ $_.Arguments }})
    DroppedEvents = $result.DroppedEvents
    LoggingMode = $result.LoggingMode
    Reason = $result.Reason
}} | ConvertTo-Json -Depth 6 -Compress
"""
    return run_pwsh_json(body)


def test_abandoned_session_is_detected_only_when_this_toolkit_started_it():
    """A running WPR session that this toolkit started is abandoned, and carries
    the documented -cancel cleanup plus a -stop that can still save what was
    recorded. A session started by someone else is reported as foreign and is
    never cancelled."""
    own = ACTIVE_STATUS + "\nInstance name           : WpdSession1\nOwner                   : WPD\n"
    payload = _run_status(own)

    assert payload["State"] == "in-progress"
    assert payload["Abandoned"] is True
    assert payload["Foreign"] is False
    assert payload["CleanupRequired"] is True
    assert payload["CleanupCommand"] == ["-cancel", "-instancename", "WpdSession1"]
    assert payload["StopSaveCommand"][0] == "-stop"
    assert payload["StopSaveCommand"][-2:] == ["-instancename", "WpdSession1"]
    assert payload["DroppedEvents"] == 0
    assert payload["LoggingMode"] == "Memory"

    foreign = _run_status(ACTIVE_STATUS + "\nInstance name           : SomeoneElsesSession\n")
    assert foreign["State"] == "in-progress"
    assert foreign["Abandoned"] is False
    assert foreign["Foreign"] is True
    assert foreign["CleanupRequired"] is False
    assert foreign["CleanupCommand"] == []
    assert "did not start" in foreign["Reason"]

    none = _run_status(NO_SESSION_STATUS)
    assert none["State"] == "none"
    assert none["Abandoned"] is False
    assert none["CleanupRequired"] is False

    # An unreadable status is unavailable, never "clean".
    unknown = _run_status("")
    assert unknown["State"] == "unavailable"
    assert unknown["Abandoned"] is False
    assert unknown["CleanupRequired"] is False
    assert "could not be read" in unknown["Reason"].lower()


LIFECYCLE_BODY = """
$runner = {
    param($toolPath, $arguments)
    [void]$global:Log.Add(($arguments -join ' '))
    if ($arguments -contains '-stop' -and $global:FailStop) { return 1 }
    return 0
}
$global:Log = New-Object System.Collections.ArrayList
"""


def test_capture_runs_start_then_body_then_stop_and_reconciles_the_session():
    """The documented order is -start, the body (markers and sampling), then
    -stop; the result carries the exit codes and proves no session was left
    running by reconciling with `wpr -status`."""
    body = (
        LIFECYCLE_BODY
        + """
$global:FailStop = $false
$start = New-WpdEtwWprStartCommand -Profile 'GeneralProfile' -Qualifier 'light'
$marker = New-WpdEtwWprMarkerCommand -Marker 'INCIDENT_PEAK'
$stop = New-WpdEtwWprStopCommand -EtlPath 'C:\\case\\wpr-trace.etl' -ProblemDescription 'incident'
$cancel = New-WpdEtwWprCancelCommand
$bodyRan = $false
$result = Invoke-WpdEtwCapture -StartCommand $start -StopCommand $stop -CancelCommand $cancel -Runner $runner `
    -StatusProbe { return 'There are no trace profiles running.' } -Body {
        param($capture)
        $global:bodyRan = $true
        return [pscustomobject]@{ Marker = 'INCIDENT_PEAK' }
    }
$bodyRan = $global:bodyRan
[pscustomobject]@{
    Status = $result.Status
    Started = $result.Started
    StartExitCode = $result.StartExitCode
    StopAttempted = $result.StopAttempted
    StopExitCode = $result.StopExitCode
    CancelAttempted = $result.CancelAttempted
    SessionReconciled = $result.SessionReconciled
    CleanupGuaranteed = $result.CleanupGuaranteed
    BodyRan = $bodyRan
    BodyResult = $result.BodyResult
    Log = @($global:Log)
    Commands = @($result.Commands)
} | ConvertTo-Json -Depth 8 -Compress
"""
    )
    payload = run_pwsh_json(body)

    assert payload["Status"] == "success"
    assert payload["Started"] is True
    assert payload["StartExitCode"] == 0
    assert payload["StopAttempted"] is True
    assert payload["StopExitCode"] == 0
    assert payload["CancelAttempted"] is False
    assert payload["CleanupGuaranteed"] is True
    assert payload["SessionReconciled"] is True
    assert payload["BodyRan"] is True
    assert payload["BodyResult"]["Marker"] == "INCIDENT_PEAK"
    assert payload["Log"] == [
        "-start GeneralProfile.light",
        "-stop C:\\case\\wpr-trace.etl incident",
    ]


def test_capture_stops_the_trace_even_when_the_body_throws():
    """A body failure (a Ctrl-C, a sampling error) must not leave a recording
    running: the stop still happens, and when the stop itself fails the
    documented -cancel is used as the second line of cleanup."""
    body = (
        LIFECYCLE_BODY
        + """
$global:FailStop = $true
$start = New-WpdEtwWprStartCommand -Profile 'CPU' -Qualifier 'verbose'
$stop = New-WpdEtwWprStopCommand -EtlPath 'C:\\case\\wpr-trace.etl' -ProblemDescription 'incident'
$cancel = New-WpdEtwWprCancelCommand
$failure = $null
$result = $null
try {
    $result = Invoke-WpdEtwCapture -StartCommand $start -StopCommand $stop -CancelCommand $cancel -Runner $runner `
        -StatusProbe { return 'There are no trace profiles running.' } -Body {
            param($capture)
            throw 'operator cancelled the capture'
        }
}
catch { $failure = $_.Exception.Message }
[pscustomobject]@{
    Failure = $failure
    Log = @($global:Log)
} | ConvertTo-Json -Depth 8 -Compress
"""
    )
    payload = run_pwsh_json(body)

    assert payload["Failure"] == "operator cancelled the capture"
    # start, then stop (failed exit code), then the documented cancel.
    assert payload["Log"] == [
        "-start CPU.verbose",
        "-stop C:\\case\\wpr-trace.etl incident",
        "-cancel",
    ]


def test_capture_reports_an_error_and_does_not_run_the_body_when_start_fails():
    """A failed -start means no recording exists: the body must not run and no
    stop/cancel may be fabricated against a session that was never created."""
    body = (
        LIFECYCLE_BODY
        + """
$global:FailStop = $false
$runner = {
    param($toolPath, $arguments)
    [void]$global:Log.Add(($arguments -join ' '))
    return 5
}
$start = New-WpdEtwWprStartCommand -Profile 'GPU' -Qualifier 'verbose'
$stop = New-WpdEtwWprStopCommand -EtlPath 'C:\\case\\wpr-trace.etl' -ProblemDescription 'incident'
$cancel = New-WpdEtwWprCancelCommand
$result = Invoke-WpdEtwCapture -StartCommand $start -StopCommand $stop -CancelCommand $cancel -Runner $runner `
    -Body { param($capture) throw 'the body must not run' }
[pscustomobject]@{
    Status = $result.Status
    Started = $result.Started
    StartExitCode = $result.StartExitCode
    StopAttempted = $result.StopAttempted
    CancelAttempted = $result.CancelAttempted
    Errors = @($result.Errors)
    Log = @($global:Log)
} | ConvertTo-Json -Depth 8 -Compress
"""
    )
    payload = run_pwsh_json(body)

    assert payload["Status"] == "error"
    assert payload["Started"] is False
    assert payload["StartExitCode"] == 5
    assert payload["StopAttempted"] is False
    assert payload["CancelAttempted"] is False
    assert payload["Log"] == ["-start GPU.verbose"]
    assert any("wpr -start" in message for message in payload["Errors"])


def test_exporter_command_requires_a_profile_and_never_invents_output_names():
    """`wpaexporter.exe [-i] trace.etl -profile profile.wpaProfile [...]` needs a
    real .wpaProfile (a preset name is not a substitute), marker ranges come from
    the incident markers, and output file names are generated - the plan states
    the folder and prefix, never a file name."""
    body = """
$profile = 'C:\\case\\wpr-analysis\\wpd-general.wpaProfile'
$export = New-WpdEtwExporterCommand -TracePath 'C:\\case\\wpr-trace.etl' -WpaProfilePath $profile `
    -OutputFolder 'C:\\case\\wpr-analysis' -Prefix 'general' -Delimiter ','
$marks = New-WpdEtwExporterCommand -TracePath 'C:\\case\\wpr-trace.etl' -WpaProfilePath $profile `
    -OutputFolder 'C:\\case\\wpr-analysis' -Marks @('INCIDENT_START', 'INCIDENT_END') -Symbols -Tti
$range = New-WpdEtwExporterCommand -TracePath 'C:\\case\\wpr-trace.etl' -WpaProfilePath $profile `
    -RangeStart '1s' -RangeEnd '500ms'
$noProfile = $null
try { New-WpdEtwExporterCommand -TracePath 'C:\\case\\wpr-trace.etl' | Out-Null } catch { $noProfile = $_.Exception.Message }
[pscustomobject]@{
    Tool = $export.Tool
    Kind = $export.Kind
    Arguments = @($export.Arguments)
    MarksArguments = @($marks.Arguments)
    RangeArguments = @($range.Arguments)
    OutputFolder = $export.OutputFolder
    OutputNameIsGenerated = $export.OutputNameIsGenerated
    Properties = @($export.PSObject.Properties.Name)
    NoProfileRejected = ($null -ne $noProfile)
    NoProfileMessage = $noProfile
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["Tool"] == "wpaexporter.exe"
    assert payload["Kind"] == "export"
    assert payload["Arguments"] == [
        "-i",
        "C:\\case\\wpr-trace.etl",
        "-profile",
        "C:\\case\\wpr-analysis\\wpd-general.wpaProfile",
        "-delimiter",
        ",",
        "-prefix",
        "general",
        "-outputfolder",
        "C:\\case\\wpr-analysis",
    ]

    # The marker range is expressed with the documented -marks switch, and
    # -symbols is only added when symbols were found beside the trace.
    assert payload["MarksArguments"] == [
        "-i",
        "C:\\case\\wpr-trace.etl",
        "-profile",
        "C:\\case\\wpr-analysis\\wpd-general.wpaProfile",
        "-outputfolder",
        "C:\\case\\wpr-analysis",
        "-marks",
        "INCIDENT_START",
        "INCIDENT_END",
        "-symbols",
        "-tti",
    ]
    assert payload["RangeArguments"] == [
        "-i",
        "C:\\case\\wpr-trace.etl",
        "-profile",
        "C:\\case\\wpr-analysis\\wpd-general.wpaProfile",
        "-range",
        "1s",
        "500ms",
    ]

    # Output names are generated by the tool: the command must not carry one.
    assert payload["OutputNameIsGenerated"] is True
    assert "OutputFileName" not in payload["Properties"]
    assert "OutputFile" not in payload["Properties"]

    assert payload["NoProfileRejected"] is True
    assert ".wpaProfile" in payload["NoProfileMessage"]


def test_analysis_table_plan_is_bounded_by_preset_and_keeps_sampled_distinct_from_precise():
    """Table selection is preset-driven, capped, and never invents a table name.
    A sampled-vs-precise preset keeps both tables, because sampled utilization
    hides Ready-starvation that the precise table shows."""
    body = """
$general = Get-WpdEtwAnalysisTablePlan -Preset 'general'
$cpu = Get-WpdEtwAnalysisTablePlan -Preset 'cpu-heavy'
$bounded = Get-WpdEtwAnalysisTablePlan -Preset 'general' -MaxTables 1
$alias = Get-WpdEtwAnalysisTablePlan -Preset 'baseline'
[pscustomobject]@{
    GeneralTables = @($general.Tables)
    GeneralCount = @($general.Tables).Count
    GeneralBudget = $general.TableBudget
    GeneralExporterProfileRequired = $general.ExporterProfileRequired
    CpuTables = @($cpu.Tables)
    CpuHasSampled = (@($cpu.Tables) -contains 'CPU Usage (Sampled)')
    CpuHasPrecise = (@($cpu.Tables) -contains 'CPU Usage (Precise)')
    BoundedTables = @($bounded.Tables)
    BoundedExcluded = @($bounded.Excluded)
    BoundedReason = ($bounded.Excluded | Select-Object -First 1).reason
    AliasPreset = $alias.Preset
    AliasEffective = $alias.EffectivePreset
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["GeneralCount"] <= payload["GeneralBudget"]
    assert payload["GeneralExporterProfileRequired"] is True
    assert payload["GeneralTables"] == ["CPU Usage (Sampled)", "Processes", "Disk Usage", "Wait Analysis"]

    assert payload["CpuHasSampled"] is True
    assert payload["CpuHasPrecise"] is True

    assert payload["BoundedTables"] == ["CPU Usage (Sampled)"]
    assert payload["BoundedReason"] is not None
    assert "budget" in payload["BoundedReason"].lower()
    # A bounded-out table is recorded, never silently dropped.
    assert len(payload["BoundedExcluded"]) == payload["GeneralCount"] - 1

    assert payload["AliasPreset"] == "baseline"
    assert payload["AliasEffective"] == "general"


def test_trace_validation_detects_missing_empty_oversized_and_failed_stop():
    """Trace validation never claims health: a missing trace is 'unavailable', an
    empty trace is detected, an oversized trace is reported and removed while its
    measured size is kept, and a non-zero -stop exit code downgrades the result."""
    body = """
$good = Get-WpdEtwTraceValidation -EtlPath 'C:\\case\\wpr-trace.etl' -SizeBytes 2097152 -MaxTraceSizeMB 512 -StartExitCode 0 -StopExitCode 0
$missing = Get-WpdEtwTraceValidation -EtlPath 'C:\\case\\wpr-trace.etl' -MaxTraceSizeMB 512 -StartExitCode 0 -StopExitCode 0
$empty = Get-WpdEtwTraceValidation -EtlPath 'C:\\case\\wpr-trace.etl' -SizeBytes 0 -MaxTraceSizeMB 512 -StartExitCode 0 -StopExitCode 0
$oversize = Get-WpdEtwTraceValidation -EtlPath 'C:\\case\\wpr-trace.etl' -SizeBytes 2147483648 -MaxTraceSizeMB 512 -StartExitCode 0 -StopExitCode 0
$failedStop = Get-WpdEtwTraceValidation -EtlPath 'C:\\case\\wpr-trace.etl' -SizeBytes 2097152 -MaxTraceSizeMB 512 -StartExitCode 0 -StopExitCode 1
[pscustomobject]@{
    GoodStatus = $good.Status
    GoodHealthy = $good.Healthy
    GoodKept = $good.Kept
    GoodTraceRemoved = $good.TraceRemoved
    MissingStatus = $missing.Status
    MissingReason = $missing.Reason
    MissingHealthy = $missing.Healthy
    EmptyStatus = $empty.Status
    EmptyEmpty = $empty.Empty
    EmptyHealthy = $empty.Healthy
    OversizeStatus = $oversize.Status
    OversizeOversized = $oversize.Oversized
    OversizeKept = $oversize.Kept
    OversizeTraceRemoved = $oversize.TraceRemoved
    OversizeEtlBytes = $oversize.EtlBytes
    FailedStopStatus = $failedStop.Status
    FailedStopStopSucceeded = $failedStop.StopSucceeded
} | ConvertTo-Json -Depth 8 -Compress
"""
    payload = run_pwsh_json(body)

    assert payload["GoodStatus"] == "success"
    assert payload["GoodKept"] is True
    assert payload["GoodTraceRemoved"] is False

    assert payload["MissingStatus"] == "unavailable"
    assert payload["MissingHealthy"] is False
    assert "not produced" in payload["MissingReason"].lower()

    assert payload["EmptyStatus"] == "partial"
    assert payload["EmptyEmpty"] is True
    assert payload["EmptyHealthy"] is False

    assert payload["OversizeStatus"] == "partial"
    assert payload["OversizeOversized"] is True
    assert payload["OversizeKept"] is False
    assert payload["OversizeTraceRemoved"] is True
    # The real measured size is preserved for the manifest after removal.
    assert payload["OversizeEtlBytes"] == 2147483648

    assert payload["FailedStopStatus"] == "partial"
    assert payload["FailedStopStopSucceeded"] is False


FORBIDDEN_TOKENS = [
    "-maxduration",
    "-filesize",
    "-maxfile",
    "-markerflush",
    "Xperfview",
    "xperfview",
]

FORBIDDEN_REMEDIATION = [
    "RestoreHealth",
    "chkdsk",
    "bcdedit",
    "Set-MpPreference",
    "Stop-Service",
    "Start-Service",
]


def test_module_source_is_ascii_lf_bom_free_ps51_safe_and_non_remediating():
    """The module must be loadable by Windows PowerShell 5.1 (ASCII, no BOM, LF,
    no class/PS7-only syntax), must not construct an invented or obsolete WPR
    switch, and must not invoke a remediation command.

    The switch/command checks run over non-comment tokens only: a help block may
    NAME a rejected flag to explain the rejection (that is documentation), but an
    argument, parameter or command name must never be one.
    """
    raw = MODULE.read_bytes()

    assert not raw.startswith(b"\xef\xbb\xbf"), "module must not start with a UTF-8 BOM"
    assert all(byte < 128 for byte in raw), "module must be ASCII-only"
    assert b"\r\n" not in raw, "module must use line feeds only"

    body = """
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('REPLACE_ME', [ref]$tokens, [ref]$parseErrors)
$code = @($tokens | Where-Object { $_.Kind -ne [System.Management.Automation.Language.TokenKind]::Comment -and $_.Kind -ne [System.Management.Automation.Language.TokenKind]::EndOfInput })
$functions = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
$commandNames = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
    ForEach-Object { $_.GetCommandName() } | Where-Object { $null -ne $_ })
[pscustomobject]@{
    Errors = @($parseErrors).Count
    Functions = $functions.Count
    CodeText = (@($code | ForEach-Object { $_.Text }) -join ' ')
    Keywords = @($code | ForEach-Object { $_.Kind.ToString() })
    Commands = @($commandNames)
} | ConvertTo-Json -Depth 6 -Compress
""".replace("REPLACE_ME", str(MODULE).replace("'", "''"))
    payload = run_pwsh_json(body)

    assert payload["Errors"] == 0, "module must parse without errors"
    assert payload["Functions"] >= 18

    code_text = payload["CodeText"]
    lowered = code_text.lower()

    for token in FORBIDDEN_TOKENS:
        assert token.lower() not in lowered, f"forbidden WPR token used in code: {token}"
    for token in FORBIDDEN_REMEDIATION:
        assert token.lower() not in lowered, f"remediation command used in code: {token}"

    # PowerShell 7-only constructs the module must not rely on.
    keywords = {keyword.lower() for keyword in payload["Keywords"]}
    assert "class" not in keywords
    assert "using" not in keywords
    assert "??" not in code_text

    # No command in the module may be a remediation verb (invoked or aliased).
    for command in payload["Commands"]:
        for verb in FORBIDDEN_REMEDIATION:
            assert verb.lower() not in command.lower(), f"remediation command invoked: {command}"
