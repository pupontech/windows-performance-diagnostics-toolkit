import json
import platform
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "src" / "Invoke-WindowsPerformanceDiagnostics.ps1"


def run_tool(*arguments: str) -> subprocess.CompletedProcess[str]:
    assert shutil.which("pwsh"), "pwsh is required for the Linux verification gate"
    return subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-File", str(SCRIPT), *arguments],
        capture_output=True,
        check=False,
        text=True,
    )


def test_plan_mode_writes_a_local_only_read_only_manifest(tmp_path):
    """Plan mode must work without touching Windows-only collection APIs."""
    output_directory = tmp_path / "diagnostic-plan"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert manifest["schemaVersion"] == "1.0"
    assert manifest["mode"] == "Plan"
    assert manifest["safety"]["localOnly"] is True
    assert manifest["safety"]["readOnly"] is True
    assert manifest["safety"]["requiresExplicitCollectionConsent"] is True
    assert "repair" not in manifest["plannedActions"]
    assert "registry-change" not in manifest["plannedActions"]


def test_collect_mode_refuses_to_collect_without_explicit_consent(tmp_path):
    result = run_tool("-Mode", "Collect", "-OutputDirectory", str(tmp_path / "no-consent"))

    assert result.returncode != 0
    assert "requires -ConfirmLocalCollection" in result.stderr


def test_collect_mode_refuses_non_windows_hosts_before_any_collection(tmp_path):
    if platform.system() == "Windows":
        return

    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-OutputDirectory",
        str(tmp_path / "linux-host"),
    )

    assert result.returncode != 0
    assert "supported only on Windows" in result.stderr


def test_plan_mode_with_wpr_lists_capture_action_and_scope(tmp_path):
    """Plan mode must advertise the WPR capture action without invoking it."""
    output_directory = tmp_path / "plan-wpr"
    result = run_tool(
        "-Mode",
        "Plan",
        "-CaptureWpr",
        "-OutputDirectory",
        str(output_directory),
    )

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "capture-wpr-etl-after-explicit-consent" in manifest["plannedActions"]
    assert manifest["wpr"]["profile"] == "GeneralProfile"
    assert manifest["wpr"]["durationSeconds"] == 30


def test_plan_mode_without_wpr_has_no_wpr_section(tmp_path):
    """Plan mode must not advertise WPR unless -CaptureWpr is requested."""
    output_directory = tmp_path / "plan-plain"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "wpr" not in manifest
    assert "capture-wpr-etl-after-explicit-consent" not in manifest["plannedActions"]


def test_wpr_capture_refuses_without_wpr_consent(tmp_path):
    """WPR is a separate consent gate from local collection, checked before any run."""
    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-CaptureWpr",
        "-OutputDirectory",
        str(tmp_path / "no-wpr-consent"),
    )

    assert result.returncode != 0
    assert "requires -ConfirmWprCapture" in result.stderr


def test_collect_with_wpr_consent_still_refuses_non_windows_hosts(tmp_path):
    if platform.system() == "Windows":
        return

    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-ConfirmWprCapture",
        "-CaptureWpr",
        "-OutputDirectory",
        str(tmp_path / "linux-wpr-host"),
    )

    assert result.returncode != 0
    assert "supported only on Windows" in result.stderr


def test_plan_mode_with_defender_lists_capture_action_and_scope(tmp_path):
    """Plan mode must advertise the Defender capture action without invoking it."""
    output_directory = tmp_path / "plan-defender"
    result = run_tool(
        "-Mode",
        "Plan",
        "-CaptureDefender",
        "-OutputDirectory",
        str(output_directory),
    )

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "capture-defender-performance-etl-after-explicit-consent" in manifest["plannedActions"]
    assert manifest["defender"]["durationSeconds"] == 30


def test_plan_mode_without_defender_has_no_defender_section(tmp_path):
    """Plan mode must not advertise Defender capture unless -CaptureDefender is requested."""
    output_directory = tmp_path / "plan-plain-defender"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "defender" not in manifest
    assert "capture-defender-performance-etl-after-explicit-consent" not in manifest["plannedActions"]


def test_plan_mode_with_wpr_and_defender_lists_both_capture_actions(tmp_path):
    """Both consent-gated captures can be planned in the same run."""
    output_directory = tmp_path / "plan-both"
    result = run_tool(
        "-Mode",
        "Plan",
        "-CaptureWpr",
        "-CaptureDefender",
        "-OutputDirectory",
        str(output_directory),
    )

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "capture-wpr-etl-after-explicit-consent" in manifest["plannedActions"]
    assert "capture-defender-performance-etl-after-explicit-consent" in manifest["plannedActions"]
    assert manifest["wpr"]["profile"] == "GeneralProfile"
    assert manifest["defender"]["durationSeconds"] == 30


def test_defender_capture_refuses_without_defender_consent(tmp_path):
    """Defender capture is a separate consent gate from local collection, checked before any run."""
    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-CaptureDefender",
        "-OutputDirectory",
        str(tmp_path / "no-defender-consent"),
    )

    assert result.returncode != 0
    assert "requires -ConfirmDefenderCapture" in result.stderr


def test_collect_with_defender_consent_still_refuses_non_windows_hosts(tmp_path):
    if platform.system() == "Windows":
        return

    result = run_tool(
        "-Mode",
        "Collect",
        "-ConfirmLocalCollection",
        "-ConfirmDefenderCapture",
        "-CaptureDefender",
        "-OutputDirectory",
        str(tmp_path / "linux-defender-host"),
    )

    assert result.returncode != 0
    assert "supported only on Windows" in result.stderr


def test_release_packaging_files_present():
    """The deploy bundle must ship launchers and unblock guidance."""
    assert (REPO_ROOT / "Run-Diagnostics.bat").is_file()
    assert (REPO_ROOT / "START-HERE.bat").is_file()
    assert (REPO_ROOT / "README-FIRST.txt").is_file()
    assert (REPO_ROOT / "make-deploy-bundle.sh").is_file()


def test_report_schema_is_valid_json():
    """The machine-readable report contract must parse and be draft-07."""
    import json as json_module

    schema_path = REPO_ROOT / "schema" / "diagnostic-report.schema.json"
    assert schema_path.is_file()
    schema = json_module.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert schema["properties"]["mode"]["enum"] == ["Plan", "Collect"]


def test_run_diagnostics_bat_is_quote_safe_and_ci_safe():
    """Regression for v0.2.1: a trailing backslash before a closing quote in a
    powershell.exe -File argument becomes a literal quote character, which made
    GetFullPath throw 'Illegal characters in path.' on Windows. The bat must
    also skip the interactive pause under CI so GitHub runners do not hang."""
    bat = (REPO_ROOT / "Run-Diagnostics.bat").read_bytes()

    assert b"\r\n" in bat  # CRLF line endings required for .bat files
    assert b'\\"' not in bat, "backslash-immediately-before-quote hazard in Run-Diagnostics.bat"

    text = bat.decode("ascii")
    assert "-Mode Collect" in text
    assert "-ConfirmLocalCollection" in text  # consent flag must be passed explicitly
    assert 'if not "%CI%"=="true" pause' in text  # CI-safe pause guard


def test_plan_mode_lists_crash_analysis_action(tmp_path):
    """Plan mode must advertise crash-evidence analysis without running it."""
    output_directory = tmp_path / "plan-crash"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "analyze-crash-evidence-after-explicit-consent" in manifest["plannedActions"]


def test_plan_mode_lists_network_state_action_and_scope(tmp_path):
    """Plan mode must advertise the read-only network-state collection and its
    sub-collections without touching Windows-only network cmdlets."""
    output_directory = tmp_path / "plan-network"
    result = run_tool("-Mode", "Plan", "-OutputDirectory", str(output_directory))

    assert result.returncode == 0, result.stderr

    manifest_path = output_directory / "diagnostic-plan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    assert "collect-network-state-after-explicit-consent" in manifest["plannedActions"]
    assert manifest["network"]["subCollections"] == [
        "ip-configuration",
        "adapter-status",
        "connection-profiles",
        "dns-server-configuration",
        "dns-client-cache",
        "ipv4-routing-table",
        "arp-table",
        "dns-vs-ping-split-test",
        "hosts-file",
        "proxy-settings",
        "tcp-connections",
        "security-software-inventory",
    ]


def test_network_keyword_matching_is_pure_and_strict_mode_safe():
    """Test-SecuritySoftwareMatch (dot-sourced from the collector) must catch
    EDR/AV/DNS-filter/VPN products by name or company without false-positives,
    and Get-PropertyValue must return $null for missing properties instead of
    throwing under Set-StrictMode -Version Latest (registry Uninstall keys are
    sparse)."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        "$null = . '" + script + "' -Mode Plan -OutputDirectory /tmp/wpd-net-test; "
        "$r = [ordered]@{"
        "crowdstrike=(Test-SecuritySoftwareMatch -Name 'CSAgent' -Company 'CrowdStrike, Inc.');"
        "sentinel=(Test-SecuritySoftwareMatch -Name 'SentinelAgent' -Company 'SentinelOne');"
        "mcafee=(Test-SecuritySoftwareMatch -Name 'McAfee WebAdvisor' -Company '');"
        "openvpn=(Test-SecuritySoftwareMatch -Name 'OpenVPN' -Company '');"
        "pihole=(Test-SecuritySoftwareMatch -Name 'pihole' -Company '');"
        "chrome=(Test-SecuritySoftwareMatch -Name 'chrome' -Company 'Google LLC');"
        "notepad=(Test-SecuritySoftwareMatch -Name 'notepad' -Company 'Microsoft Corporation');"
        "missingProp=(Get-PropertyValue -InputObject ([pscustomobject]@{DisplayName='x'}) -Name 'Publisher')"
        "}; $r | ConvertTo-Json -Depth 4"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    matches = json.loads(result.stdout)

    assert matches["crowdstrike"] is True
    assert matches["sentinel"] is True
    assert matches["mcafee"] is True
    assert matches["openvpn"] is True
    assert matches["pihole"] is True
    assert matches["chrome"] is False
    assert matches["notepad"] is False
    assert matches["missingProp"] is None


def test_network_state_collection_is_resilient_and_structured(tmp_path):
    """Get-NetworkState (dot-sourced, Windows cmdlets mocked) must produce the
    full structured snapshot, compute the DNS-vs-ping verdict, and keep every
    other section when one fails - all StrictMode-safe on sparse registry
    keys. Runs on the Linux verification host; windows-verify exercises the
    real cmdlets on windows-2022/2025."""
    script = str(SCRIPT).replace("\\", "/")
    # .NET on Linux normalizes the backslash child path to forward slashes,
    # so the fixture tree mirrors what Join-Path resolves to here (on Windows
    # the native separator produces the same physical file).
    hosts_file = tmp_path / "System32" / "drivers" / "etc" / "hosts"
    hosts_file.parent.mkdir(parents=True)
    hosts_file.write_text(
        "# comment line\n127.0.0.1 localhost\n\n0.0.0.0 ads.example.com\n",
        encoding="utf-8",
    )
    command = (
        "$null = . '" + script + "' -Mode Plan -OutputDirectory /tmp/wpd-net-state; "
        "$env:SystemRoot = '" + str(tmp_path) + "'; "
        "function ipconfig { param($x) 'Windows IP Configuration','   IPv4 Address. . . : 192.168.1.50' }; "
        "function arp { param($x) 'Interface: 192.168.1.50','192.168.1.1 aa-bb-cc-dd-ee-ff dynamic' }; "
        "function netsh { param($a,$b,$c) 'Current WinHTTP proxy settings:','Direct access (no proxy server).' }; "
        "function Get-NetAdapter { [pscustomobject]@{Name='Ethernet';InterfaceDescription='Test Adapter';Status='Up';LinkSpeed='1 Gbps';MacAddress='00:11:22:33:44:55'} }; "
        "function Get-NetConnectionProfile { [pscustomobject]@{Name='testnet';InterfaceAlias='Ethernet';NetworkCategory='Private';IPv4Connectivity='Internet';IPv6Connectivity='NoTraffic'} }; "
        "function Get-DnsClientServerAddress { [pscustomobject]@{InterfaceAlias='Ethernet';AddressFamily=2;ServerAddresses=@('8.8.8.8','1.1.1.1')} }; "
        "function Get-DnsClientCache { [pscustomobject]@{Entry='google.com';Name='google.com';Data='142.250.1.1';Status='Success'} }; "
        "function Get-NetRoute { [pscustomobject]@{DestinationPrefix='0.0.0.0/0';NextHop='192.168.1.1';InterfaceAlias='Ethernet';RouteMetric=10} }; "
        "function Test-Connection { param($ComputerName,$Count) [pscustomobject]@{Address=$ComputerName;ResponseTime=5;StatusCode=0} }; "
        "function Resolve-DnsName { param($Name) [pscustomobject]@{Name=$Name;Type='A';IPAddress='1.2.3.4'} }; "
        "function Get-NetTCPConnection { [pscustomobject]@{LocalAddress='0.0.0.0';LocalPort=443;RemoteAddress='1.2.3.4';RemotePort=50000;State='Established';OwningProcess=1234} }; "
        "function Get-Process { [pscustomobject]@{Name='chrome';Id=1;Company='Google LLC'},[pscustomobject]@{Name='csagent';Id=2;Company='CrowdStrike, Inc.'} }; "
        "function Get-ItemProperty { param($Path,$ErrorAction) [pscustomobject]@{DisplayName='Google Chrome';DisplayVersion='1.0';Publisher='Google LLC'},[pscustomobject]@{DisplayName='CrowdStrike Falcon';Publisher='CrowdStrike, Inc.'},[pscustomobject]@{DisplayVersion='2.0'} }; "
        "$good = (Get-NetworkState).State | ConvertTo-Json -Depth 8; "
        "function Get-NetAdapter { throw 'mocked adapter failure' }; "
        "$bad = Get-NetworkState; "
        "$badSections = @($bad.Errors | ForEach-Object { $_.Section }) -join ','; "
        "[ordered]@{good=$good;badSections=$badSections;badVerdict=$bad.State.dnsVsPing.verdict} | ConvertTo-Json -Depth 8"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    parsed = json.loads(result.stdout)
    state = json.loads(parsed["good"])

    # full structured snapshot with every section present
    for section in (
        "ipConfigAll", "adapters", "connectionProfiles", "dnsServerAddresses",
        "dnsClientCache", "ipv4Routes", "arpTable", "dnsVsPing", "hostsFile",
        "proxySettings", "tcpConnections", "securitySoftware",
    ):
        assert section in state, f"missing network-state section: {section}"

    # DNS-vs-ping split test: both mocks succeed -> both green
    assert state["dnsVsPing"]["rawIpReachable"] is True
    assert state["dnsVsPing"]["dnsResolutionOk"] is True
    assert state["dnsVsPing"]["verdict"] == "dns-and-connectivity-ok"
    assert len(state["dnsVsPing"]["rawIpPing"]) == 2
    assert len(state["dnsVsPing"]["dnsResolution"]) == 3

    # hosts file: comments and blank lines excluded
    assert state["hostsFile"]["activeEntryCount"] == 2
    assert state["hostsFile"]["activeEntries"] == [
        "127.0.0.1 localhost",
        "0.0.0.0 ads.example.com",
    ]

    # security inventory: chrome is not a match, csagent is; the sparse
    # uninstall key (no DisplayName) must not throw under StrictMode
    assert [p["Name"] for p in state["securitySoftware"]["processMatches"]] == ["csagent"]
    assert [s["DisplayName"] for s in state["securitySoftware"]["installedSoftwareMatches"]] == [
        "CrowdStrike Falcon"
    ]
    assert state["sectionErrors"] == []

    # resilience: a failing section is recorded and never loses the rest
    assert parsed["badSections"] == "adapters"
    assert parsed["badVerdict"] == "dns-and-connectivity-ok"


def test_crash_analysis_decodes_bugchecks_and_flags_unexplained_shutdowns():
    """Get-CrashAnalysis (pure function, dot-sourced from the collector) must
    decode BugCheck 1001 codes and flag Kernel-Power 41 without a nearby
    bugcheck as an unexplained shutdown."""
    script = str(SCRIPT).replace("\\", "/")
    command = (
        f"$null = . '{script}' -Mode Plan -OutputDirectory /tmp/wpd-crash-test; "
        "$r = Get-CrashAnalysis -Events @("
        # bugcheck 3 minutes before the first Kernel-Power 41 -> within the
        # 5-minute window, so that 41 is explained; the -30min one is not
        "[pscustomobject]@{ProviderName='BugCheck';Id=1001;TimeCreated=(Get-Date).AddMinutes(-3);"
        "Message='The bugcheck was: 0x0000001A (0x0000000000041790, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000)'},"
        "[pscustomobject]@{ProviderName='Microsoft-Windows-Kernel-Power';Id=41;TimeCreated=(Get-Date).AddMinutes(-2);"
        "Message='The system has rebooted without cleanly shutting down first.'},"
        "[pscustomobject]@{ProviderName='Microsoft-Windows-Kernel-Power';Id=41;TimeCreated=(Get-Date).AddMinutes(-30);"
        "Message='The system has rebooted without cleanly shutting down first.'}"
        "); $r | ConvertTo-Json -Depth 6"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    analysis = json.loads(result.stdout)

    assert len(analysis["bugchecks"]) == 1
    assert analysis["bugchecks"][0]["BugcheckCode"] == "0x0000001A"
    # the -2min Kernel-Power 41 has a matching bugcheck -> not unexplained;
    # the -30min one has none -> unexplained
    assert len(analysis["unexplainedShutdowns"]) == 1


def test_start_here_bat_is_elevation_safe_and_quote_safe():
    """START-HERE.bat must self-elevate via UAC, present a console menu, run the
    selected collection with the WPR/Defender consent flags, and stay CI-safe
    and quote-safe like the other bat."""
    bat = (REPO_ROOT / "START-HERE.bat").read_bytes()

    assert b"\r\n" in bat  # CRLF line endings required for .bat files
    assert b'\\"' not in bat, "backslash-immediately-before-quote hazard in START-HERE.bat"
    assert all(b < 128 for b in bat), "START-HERE.bat must be pure ASCII"
    # cmd parser regression: parenthesized if/for blocks with parens in the
    # body kill the bat ('. was unexpected at this time.'); goto-style only
    import re as re_module

    for line in bat.decode("ascii").splitlines():
        assert not re_module.match(r"\s*(if|for)\b.*\(\s*$", line), (
            f"parenthesized block in START-HERE.bat: {line!r}"
        )

    text = bat.decode("ascii")
    # UAC self-elevation: net session probe + re-launch with RunAs
    assert "net session >nul 2>&1" in text
    assert "-Verb RunAs" in text
    # CI must never hang on UAC: guard the elevation attempt
    assert 'if "%CI%"=="true"' in text
    # Console menu with the five options
    for option in ("1 - Full collection", "2 - Basic collection",
                   "3 - Full + WPR + Defender", "4 - Plan preview", "5 - Exit"):
        assert option in text, f"missing menu option {option!r}"
    # Consent flags must be passed explicitly per option
    assert "-Mode Collect" in text
    assert "-ConfirmLocalCollection" in text
    assert "-CaptureWpr" in text
    assert "-ConfirmWprCapture" in text
    assert "-CaptureDefender" in text
    assert "-ConfirmDefenderCapture" in text
    # Defender-strip resilience: pre-flight existence check with recovery steps
    assert "src\\Invoke-WindowsPerformanceDiagnostics.ps1 was not found" in text
    # Result visibility: log everything with Tee-Object, never a silent failure
    assert "Tee-Object" in text
    assert "diagnostic-manifest.json" in text
    # No trailing backslash before the closing quote of -OutputDirectory
    assert '-OutputDirectory \'%OUTDIR%\'' in text
    assert 'if not "%CI%"=="true" pause' in text  # CI-safe pause guard
