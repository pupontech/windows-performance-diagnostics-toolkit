# Authoritative Sources: Windows Platform Performance Domains

Research base for platform-level evidence domains: what Microsoft (and a small
number of practitioner references) publishes about each domain, which APIs and
tools produce the evidence, how that evidence can be read, and what it cannot
establish.

Verified 2026-09-15: every URL in this document was fetched and returned
HTTP 200, then registered in a citation ledger that assigns the `[n]` numbers.
Ledger render emits an em dash between URL and title; it is normalized to an
ASCII hyphen-minus here so the file stays pure ASCII.

## How to use this document

- `[n]` refers to the Sources block at the end of this document. Numbers are
  ledger identities: they are stable within this document and must not be
  renumbered by hand.
- Quoted thresholds and figures are attributed to the source that publishes
  them. A published figure is a starting reference from that source, not a
  universal pass/fail line for another machine.
- Correlation is not causation: an observation that coincides with a symptom is
  a hypothesis to be tested with a second, independent evidence channel.
- This document is a source map. It does not define tool switches, thresholds,
  or remediation steps; those must come from the cited page for the exact
  tool version in use.

## 1. Storage latency and health

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [1] | [Performance history for drives](https://learn.microsoft.com/en-us/windows-server/storage/storage-spaces/performance-history-for-drives) | Storage Spaces Direct performance history; `Physical Disk` counter set; PowerShell `Get-PhysicalDisk ... \| Get-ClusterPerf` | Documented for cluster drives, and performance history is not available for OS boot drives; cannot be collected while the server is down |
| [2] | [Get-StorageReliabilityCounter](https://learn.microsoft.com/en-us/powershell/module/storage/get-storagereliabilitycounter) | `Get-StorageReliabilityCounter` by `-PhysicalDisk` or `-Disk` | Returns reliability counters for the specified disk; the reference publishes no interpretation thresholds |
| [3] | [Get-PhysicalDisk](https://learn.microsoft.com/en-us/powershell/module/storage/get-physicaldisk) | `Get-PhysicalDisk`, `-HealthStatus` filter, provider-reported `OperationalStatus` / `HealthStatus` | Enumerates what the installed Storage Management Providers expose; a healthy status is a provider state, not a latency measurement |
| [4] | [Collecting Performance Data](https://learn.microsoft.com/en-us/windows/win32/perfctrs/collecting-performance-data) | Performance counter API (`\Process(X)\% Processor Time` and related counters) | Defines what a counter aggregates (for example, per-process processor time is the sum of its threads); it does not define performance thresholds |
| [63] | [Capacity planning for Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/active-directory-server/capacity-planning-for-active-directory-domain-services) | Published storage response-time reference figures by media type (for example 7,200 rpm: 9 to 12.5 ms; 10,000 rpm: 6 to 10 ms; 15,000 rpm: 4 to 6 ms; SSD: 1 to 3 ms) | Figures belong to AD capacity planning for that role; they are reference ranges for planning, not detection thresholds |

**Evidence interpretation**

- The drive latency series map to classic counters: `physicaldisk.latency.read` is `Avg. Disk sec/Read`, `physicaldisk.latency.write` is `Avg. Disk sec/Writes`, and `physicaldisk.latency.average` is `Avg. Disk sec/Transfer`.[1]
- Those counters are measured by `partmgr.sys` and do not include much of the Windows software stack nor any network hops, so they are representative of device hardware performance.[1] A high value therefore points at the device or its path; a low value does not clear the filesystem filters, antivirus, or network layers above it.
- Counters are measured over the entire interval, not sampled: a drive that is idle for 9 seconds but completes 30 IOs in the 10th second records 3 IOs per second for that 10-second interval.[1] Short stalls are averaged down, so interval length must be chosen deliberately.
- Reliability counters (`Get-StorageReliabilityCounter`) come from the storage provider for a specific disk, and the cmdlet reference defines no health thresholds, so any pass/fail rule must be sourced elsewhere and attributed.[2]
- Volume/drive health fields such as `OperationalStatus` and `HealthStatus` are provider states surfaced by `Get-PhysicalDisk`, not latency measurements.[3]

## 2. Filesystem filters (minifilters and I/O interception)

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [5] | [About File System Filter Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-file-system-filter-drivers) | Architecture reference for minifilters that attach to the file system software stack | Describes how filters work, not how to attribute a user-visible regression to one |
| [6] | [Minifilter Diagnostics assessment](https://learn.microsoft.com/en-us/windows-hardware/test/assessments/minifilter-diagnostics) | Windows ADK assessments with minifilter diagnostic mode (File Handling, Internet Explorer startup, Boot Performance (Fast Startup)); analysis in Windows Assessment Console, Windows ASC, or WPA | Scenario-scoped: results reflect the workload the assessment ran, on that machine, with the filters installed at that time |
| [7] | [BypassIO for Filter Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/bypassio) | BypassIO support model; filters can veto bypass, and Microsoft states minifilters are encouraged to minimize vetoing | Documents an optimization path and who can block it; it is not a measurement API |
| [8] | [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) | Real-time file system, Registry, process and thread activity with filterable trace output | Unfiltered capture can be very large and exposes paths, command lines and user data; it shows activity, not cost attribution |

**Evidence interpretation**

- Minifilters run code on most file I/O, so a poorly implemented one can cause perceived slowness; minifilter diagnostic mode exists specifically to identify such drivers by running three I/O-intensive tasks.[6]
- Per-minifilter results are duration metrics grouped by workload or callback type, with callback counts and average/maximum call times; boot results are organized by boot phase (17 phases, and one filter can affect several phases).[6]
- Microsoft states there are no remediation steps for at least one minifilter metric because it depends only on the applications installed on the system.[6] That is a direct statement of the evidence's limit: identifying a slow callback is not the same as authorizing a change to it.
- The documented comparison method is a controlled one: run the assessments on two identical systems that differ only by antivirus software, or on one system before and after a change, then compare results side by side.[6]

## 3. Microsoft Defender Antivirus

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [9] | [Performance analyzer for Microsoft Defender Antivirus](https://learn.microsoft.com/en-us/defender-endpoint/tune-performance-defender-antivirus) | `New-MpPerformanceRecording`, then `Get-MpPerformanceReport` over the recording (for example top files, scans per file) | Requires the issue to reproduce while recording; it reports Defender's own scan work |
| [10] | [Performance Analyzer reference](https://learn.microsoft.com/en-us/defender-endpoint/performance-analyzer-reference) | `Get-MpPerformanceReport` parameters such as `-MinDuration`, `-Raw`, and top-N breakdowns with `ConvertTo-Json` | Cmdlet reference; parameters and prerequisites are version-dependent |
| [11] | [Troubleshoot Defender performance issues](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-performance-issues) | Microsoft's list of common reasons for elevated Defender CPU (unsigned binaries, complex file formats such as HTA/CHM, obfuscated scripts, file hash computation) | Explains mechanisms and possible tuning; changing exclusions or protection features is a security decision |
| [12] | [Collect Defender diagnostic data](https://learn.microsoft.com/en-us/defender-endpoint/collect-diagnostic-data) | Support diagnostic bundle (`MpSupportFiles.cab`) | Sensitive bundle: generate locally, disclose contents before any transfer |
| [13] | [Defender command-line arguments](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus) | `MpCmdRun` for scans, security intelligence, and related tasks | Collection and scanning must be kept separate; it can change protection state |

**Evidence interpretation**

- The performance analyzer answers "which files, extensions, processes and scans account for Defender's scan time" on the recorded window, which is a scoped attribution of Defender's own work.[9][10]
- A path exclusion works for scanning flows, but Microsoft notes that behavior monitoring and network real-time inspection can still cause performance issues, so an exclusion does not automatically explain or remove cost.[11]
- Because Defender's scan work is a response to files, binaries, and formats present on the machine, peak Defender activity is a mechanism and not proof that Defender caused a user-visible regression: the recording window must overlap the symptom and a second evidence channel (disk I/O, CPU by process) should be used to corroborate.[9][11]

## 4. Windows Search indexing

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [14] | [Troubleshoot Windows Search performance](https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/windows-search-performance-issues) | Published indexer status strings, indexed-item counts (Settings, Searching Windows), tuning guidance, `wsearch` service state | Status text and counting rules are product-defined; guidance is client-SKU oriented |
| [15] | [Fix problems in Windows Search](https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/fix-problems-in-windows-search) | Built-in Search and Indexing troubleshooter (`msdt.exe -ep WindowsHelp id SearchDiagnostic`) | Troubleshooter resets Windows Search to the default experience; it is a repair path, not a measurement |

**Evidence interpretation**

- Microsoft publishes scale guidance for the indexer: a typical user's computer indexes fewer than 30,000 items, a power user up to 300,000, and performance issues may begin above 400,000 items; the indexer can index up to 1 million items, beyond which it may fail or cause resource problems.[14]
- Some indexer activity is by design rather than a defect: the indexer slows down while the user is active, waits for idle, pauses on low battery, and pauses on group policy while on battery, and it stops when memory or disk is insufficient.[14] Observed indexer load therefore has to be read against the current status string.
- The published status messages form a documented vocabulary (for example "Indexing speed is reduced because of user activity", "Indexing is waiting for computer to become idle", "Index is performing maintenance"), which makes the status field citable evidence for what the indexer believes it is doing.[14]
- Index size is described as generally about 10 percent of indexed content, and a rebuild can take up to 24 hours to complete, which bounds how quickly a rebuild-based change can be validated.[14]

## 5. Networking and retransmissions

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [16] | [Network-related performance counters](https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-performance-counters) | Counter lists for IPv4/IPv6, TCPv4/TCPv6 (including `Segments Retransmitted/sec`, `Connection Failures`, `Connections Reset`), network interface/adapter, WFP, RSC, per-NIC activity | Counter lists define what is measured, not what value is acceptable |
| [17] | [Diagnose packet loss](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/diagnose-packet-loss) | Pktmon traces with drop reasons; `netsh trace start scenario=InternetClient` or `scenario=InternetServer` as a fallback; `Get-NetAdapterStatistics` or count | Microsoft describes the netsh component-level traces as noisy and not clear, and to be used only when pktmon is inconclusive |
| [18] | [Packet Monitor (Pktmon)](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon) | Packet interception at multiple stack locations, per-component counters, drop reporting, ETL logs, Windows Admin Center extension, Netmon parsers | Tells you where in the stack a packet was dropped and why, for the capture window |
| [19] | [TCP/IP performance known issues](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/tcpip-performance-known-issues) | Throughput measurement with ctsTraffic against a baseline; TCP receive window autotuning level (`netsh int tcp set global autotuninglevel=normal`, `Get-NetTCPSetting` / `Set-NetTCPSetting`) | Diagnoses specific documented throughput scenarios; it is not a general latency tool |
| [20] | [Network adapter performance tuning](https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-performance-tuning-nics) | TCP receive window autotuning levels and link-speed-dependent receive window sizes | Tuning guidance; changing global TCP settings affects all connections |

**Evidence interpretation**

- Retransmission evidence is a rate counter: `Segments Retransmitted/sec` is in the TCPv4/TCPv6 resource-utilization list, and connection failures or resets are listed separately as potential-problem counters.[16] A non-zero retransmission rate alone does not establish a fault; it must be compared against a baseline and read together with discard/error counters on the same interval.
- Drop evidence with a reason is stronger than a plain discard count: Packet Monitor intercepts packets at multiple points in the stack, reports drop reasons, and distinguishes an intended destination from a component that is interfering with the packet.[18]
- Pktmon drop reasons and per-component counters are the documented first step for a packet-loss investigation; the netsh scenario traces are explicitly described as noisy and are reserved for when pktmon is inconclusive.[17]
- When the adapter is the suspect, Microsoft points to adapter discard counters or `Get-NetAdapterStatistics` rather than to a stack trace, so adapter-level and stack-level evidence must be kept distinct.[17]

## 6. GPU, DWM and composition

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [21] | [Desktop Window Manager (DWM) API reference](https://learn.microsoft.com/en-us/windows/win32/api/_dwm) | DWM APIs (for example `DwmFlush`, which blocks the caller until the next present) | API reference; no performance counters or thresholds are published here |
| [22] | [WDDM overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/windows-vista-display-driver-model-design-guide) | WDDM version history and features, including GPU scheduling, virtual memory management, TDR, and hardware-accelerated GPU scheduling (WDDM 2.6, Windows 10 1903) | Driver-model reference: it explains the mechanism, not the current machine's cost |
| [23] | [Improve power consumption and battery life](https://learn.microsoft.com/en-us/windows/apps/develop/performance/power) | Capturing a trace and analyzing it with WPA (`wpa.exe gputrace.etl`), including checking for unnecessary work and measuring vsync waiting in the background | App-developer guidance; the technique transfers, the app-specific conclusions do not |
| [24] | [Using WPA to analyze Modern Standby issues](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/using-windows-performance-analyzer-to-analyze-modern-standby-issues) | WPA trace capture and viewing for Modern Standby diagnostics | Modern Standby specific; requires supported hardware/firmware behavior |
| [70] | [PresentMon](https://github.com/GameTechDev/PresentMon) | Frame timing and presentation capture (external, open-source tool) | Third-party tool maintained outside Microsoft documentation; output depends on the graphics stack |

**Evidence interpretation**

- Composition and GPU evidence is timeline-based: ETW traces opened in WPA are the documented way to examine graphics work and the desktop compositor, including versusync waiting in the background.[23]
- Hardware-accelerated GPU scheduling and TDR are WDDM features whose availability depends on driver model version, so a capability or state observation must be read against the WDDM version in use.[22]
- A high per-process GPU figure for a compositor is a pipeline observation, not a cause: DWM exists to composite and present, and the relevant evidence is whether present/flush work is delayed relative to the symptom window.[21][23]
- Frame-level timing from a dedicated capture tool answers questions that ETW summaries do not (frame times, presentation mode), but it is a third-party measurement whose validity depends on its own capture configuration.[70]

## 7. Power and processor utility

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [25] | [CPU usage exceeds 100% if Turbo Boost is active](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/cpu-usage-exceeds-100) | Time-based versus utility performance counters; how frequency affects reported work | Explains why utility can exceed 100 percent; it is a measurement-semantics page |
| [26] | [Powercfg command-line options](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options) | `powercfg /energy`, `/batteryreport`, `/sleepstudy`, `/systempowerreport`, `/srumutil`, `/requests`, `/waketimers`, and power scheme query/change options | Reports are generated for a defined observation window (for example `/energy` defaults to 60 seconds and should be run when idle) |
| [27] | [Power and performance tuning](https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/hardware/power/power-performance-tuning) | Minimum/maximum processor performance state, processor performance boost mode, frequency cap verification via the `% of maximum frequency` counter | Processor support is required for frequency caps; tuning changes affect the whole system |
| [28] | [CPU Analysis](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/cpu-analysis) | WPT/WPA CPU investigation techniques; processor power management and C-state background | Assessment-oriented guide; techniques assume WPA and a captured trace |
| [63] | [Capacity planning for Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/active-directory-server/capacity-planning-for-active-directory-domain-services) | States that `% Processor Utility` can exceed 100 percent on systems with Turbo mode | Documented in an AD capacity-planning context |

**Evidence interpretation**

- Time-based counters measure the percentage of time the processor is busy, while utility counters measure how much work the processor actually performs; a processor that is busy 100 percent of the time but clocked at half frequency performs about half the work.[25]
- Because of that, `% Processor Utility` values above 100 percent on boost-capable systems are a documented measurement outcome rather than an error.[25][63]
- Frequency caps require processor support, and the `% of maximum frequency` counter in the Processor group is Microsoft's stated way to see whether a cap was applied.[27]
- `powercfg` evidence is generated by a command with a defined scope: for example `/energy` analyzes common energy-efficiency and battery-life problems into an HTML or XML report and should be used when the computer is idle, with a default observation duration of 60 seconds, while `/batteryreport` reports battery usage characteristics over the system lifetime and `/srumutil` dumps Energy Estimation data from SRUM.[26]

## 8. Thermal evidence and its limits

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [29] | [Windows thermal management framework](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/design-guide) | Thermal manager, thermal zones, managed drivers, sensors; ACPI-driven periodic evaluation and throttling percentages | The framework is firmware/OS/driver cooperative; the OS has no insight into why a thermal zone is at its current throttling level |
| [30] | [Thermal examples, requirements and diagnostics](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/examples--requirements-and-diagnostics) | Event channels and IDs: System log Kernel-Power 125 (thermal zone enumerated), Microsoft-Windows-Kernel-Power/Thermal-Operational Kernel-Power 114 (zone engaged/disengaged passive cooling); Microsoft-Windows-Kernel-ACPI for temperature, zone and fan activity; WPA ThermalZone device throttle graph | Evidence is per-zone and per-event; temperature is reported by firmware |
| [31] | [Device-level thermal management](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/device-level-thermal-management) | ACPI thermal zones and coordinated OS cooling actions | Architecture reference for the mechanism |
| [32] | [ACPI-defined devices](https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/acpi-defined-devices) | Thermal zone description objects: `_TZD`, `_PSL`, `_PSV`, `_HOT`, `_CRT`, `_TC1`/`_TC2`, `_TSP`, `_TMP`, `_NTT`, `_DTI`, `_ALx`, `_ACx`; logical processor idling via the Processor Aggregator (`ACPI000C`) | The zone topology and thresholds are defined in platform firmware, not by Windows |

**Evidence interpretation**

- Microsoft states plainly that the operating system has no insight into why a thermal zone is set at its current throttling level.[29] An observed throttling percentage or frequency reduction is therefore evidence that a throttle state exists, not evidence of the specific physical cause.
- The documented evidence channel is thermal events: a zone being enumerated, a zone engaging or disengaging passive cooling, and Kernel-ACPI events for temperature, zone activity, and fan activity, with throttling percentage, temperature and cooling policy changes visible in the trace.[30]
- Critical thermal behavior is logged through firmware methods (`_CRT` for shutdown, `_HOT` for hibernate), so the presence or absence of those events depends on the platform's ACPI description.[30][32]
- Thermal mitigations can be implemented by throttling devices or by parking processor cores when the zone passive limit is crossed, so "cores are parked" and "clocks are reduced" are different observed mechanisms and should not be conflated.[32]

## 9. Boot and logon critical paths

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [33] | [On/Off Transition Performance assessments](https://learn.microsoft.com/en-us/windows-hardware/test/assessments/onoff-transition-performance) | Assessments for boot (Fast Startup), hibernate, and related transitions | Assessment runs a defined scenario; results are comparative |
| [34] | [Results for the On/Off assessments](https://learn.microsoft.com/en-us/windows-hardware/test/assessments/results-for-the-onoff-assessments) | Issue analysis in the assessment results, with links into WPA | Results are tied to the assessment configuration used |
| [35] | [WPR command-line options](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options) | `-onoffscenario` (Boot, FastStartup, Shutdown, RebootCycle, Standby, Hibernate), `-onoffresultspath`, `-onoffproblemdescription`, `-numiterations`, and `wpr -boottrace -addboot/-stopboot/-cancelboot` | Switches and available scenarios depend on the installed WPT build |
| [36] | [Distinguishing Fast Startup from wake-from-hibernation](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/distinguishing-fast-startup-from-wake-from-hibernation) | Three startup modes (cold, wake-from-hibernation, fast); `SYSTEM_POWER_STATE_CONTEXT` with `TargetSystemState` / `EffectiveSystemState`; hibernation file loading | Driver-facing reference: the distinction is available to drivers, not to a casual observer of boot time |
| [37] | [Evaluate Fast Startup using WPT](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/optimizing-performance-and-responsiveness-exercise-2) | Opening a Fast Startup trace in WPA, visualizing the activity timeline, and analyzing it | A guided exercise; the method transfers, its example conclusions do not |
| [38] | [Large WMI repository causes slow logon](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/large-wmi-repository-cause-slow-logon) | Documented case of slow logon associated with a large WMI repository | A specific documented failure mode; it does not generalize to all slow logons |

**Evidence interpretation**

- Boot and logon evidence is phase-oriented: minifilter boot results are organized by boot phase (17 phases, and one filter can appear in several phases), which is the documented basis for attributing time to a critical-path stage rather than to one component.[6][33]
- Fast Startup is not a cold boot: it loads the hibernation file into memory instead of initializing Windows, drivers, devices and services, and it is distinguishable from wake-from-hibernation only through power state context.[36] Comparing boot times across these modes without recording which mode occurred is not a valid comparison.
- The transition mode must be recorded with the trace: WPR exposes specific on/off scenarios and iterations, and a boot trace can be added and stopped separately, so the capture metadata is part of the evidence.[35]
- Logon slowness has multiple documented mechanisms, and Microsoft's own published cases (for example a large WMI repository on remote desktop servers) show that a correct finding for one environment is not a general cause to test everywhere.[38]

## 10. Startup inventory

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [39] | [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) | Enumerates auto-start extension points: logon entries, Explorer add-ons, scheduled tasks, services, drivers, and other auto-start locations; tabular UI with CLI output | An inventory tool: presence in an auto-start location is not evidence of cost or of necessity |
| [40] | [Startup apps](https://learn.microsoft.com/en-us/windows/win32/w8cookbook/startup-apps) | Task Manager Startup tab listing startup apps, with controls to enable/disable and a startup impact rating | Impact ratings are the platform's own classification, not a measured duration per app |

**Evidence interpretation**

- A startup inventory and a startup cost are different artifacts: Autoruns enumerates where something starts from, while the Task Manager Startup tab is the native place where a startup impact rating is exposed.[39][40]
- Because startup entries can be registered in several locations, a single-source inventory is incomplete; Autoruns documents the breadth of those locations, and any "startup item count" must state which locations were included.[39]
- Enabling or disabling a startup entry is a state change and therefore belongs to an approval-gated remediation phase, not to collection.[40]

## 11. Driver and device health

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [41] | [Get-PnpDevice](https://learn.microsoft.com/en-us/powershell/module/pnpdevice/get-pnpdevice) | `Get-PnpDevice`, including querying devices by status (error, degraded, unknown) | Device state as reported by Plug and Play for the current machine |
| [42] | [Introduction to WHEA](https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/introduction-to-the-windows-hardware-error-architecture) | Windows Hardware Error Architecture overview and standard error record format | Framework description: it defines how errors are represented |
| [43] | [WHEA hardware error events](https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/whea-hardware-error-events) | WHEA ETW events recorded in the system event log; each event contains an error record; querying the log or registering for notifications | A recorded hardware error event is a report from the platform; it does not by itself establish the failing part or the user-visible impact |
| [44] | [WHEA error records](https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/error-records) | Error record structure (header, section descriptors, sections) based on the UEFI CPER format; processor, memory, NMI, PCIe and PCI/PCI-X section types | Record structure defines what can be decoded, not what the machine should do |
| [45] | [Bug check code reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2) | Reference for bug check codes | Codes identify the checked condition; they are not root-cause statements by themselves |

**Evidence interpretation**

- Device health evidence from Plug and Play is a state claim ("this device reports error/degraded/unknown"), which is a starting point for investigation rather than a performance measurement.[41]
- Hardware error evidence is structured: WHEA raises an ETW event on each hardware error, records it in the system event log, and carries a standard error record whose sections identify the error class (processor, memory, PCIe, NMI, and so on).[42][43][44] Decoding the section is what makes the record meaningful; an undecoded event supports only "the platform reported a hardware error of this type at this time".
- Because the record format is shared by firmware, the OS and applications, a WHEA record is the most portable hardware-error evidence channel, but it is still an observation whose causality for a slow-machine symptom must be established with other evidence.[42][43]

## 12. Virtualization-based security (VBS) and memory integrity

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [46] | [Enable virtualization-based protection of code integrity](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity) | Memory integrity (HVCI) settings and enablement; VBS uses the Windows hypervisor as an isolated root of trust | Performance impact is documented as processor-generation dependent; enabling/disabling is a security decision |
| [47] | [Virtualization-based Security (VBS)](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) | VBS architecture: kernel-mode code integrity inside the isolated environment; nested virtualization or Guest VSM for VMs | Architecture and enablement guidance for OEMs and VMs |
| [48] | [Memory integrity and VBS enablement](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-hvci-enablement) | Hardware and firmware enablement requirements for memory integrity and VBS | Requirements are platform-specific (firmware, virtualization support) |

**Evidence interpretation**

- VBS status and memory integrity status are configuration facts that can be enumerated, and Microsoft documents the mechanism: kernel-mode code integrity runs inside the isolated environment, and kernel memory pages become executable only after code integrity checks there.[46][47]
- Microsoft states the performance relationship as generation dependent: memory integrity works better on newer processors, while older processors rely on an emulation of those features (Restricted User Mode) and will have a bigger impact on performance, and nested virtualization behaves better above a documented VM version.[46]
- Because the impact is documented as dependent on processor generation and virtualization support, VBS presence alone cannot be converted into a performance figure for a specific machine; that requires measurement on that machine with the feature state recorded.[46][48]

## 13. Privacy and diagnostic data

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [49] | [Configure Windows diagnostic data in your organization](https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization) | Diagnostic data settings (including diagnostic data off), collection methods, Group Policy and MDM management, diagnostic data processor configuration | Describes what Windows sends to Microsoft and how to govern it, not what a local collector should keep |
| [50] | [Windows 11 required diagnostic data events and fields](https://learn.microsoft.com/en-us/windows/privacy/required-diagnostic-events-fields-windows-11-24h2) | Event and field catalog for required diagnostic data | Catalog is version-specific (Windows 11 24H2/25H2 on this page) |
| [51] | [Manage connections from Windows components to Microsoft services](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services) | Endpoint/connection management for Windows components | Endpoint lists change; the page is the maintained reference |

**Evidence interpretation**

- OS diagnostic data policy governs what leaves the device; it is separate from the question of what a local diagnostic toolkit collects and retains, which must be governed by the toolkit's own consent and retention rules.[49]
- Microsoft publishes the fields contained in its own diagnostic events, which is the reference for judging whether a given field is plausibly sensitive if it appears in a local artifact as well.[50]
- Microsoft requires that Defender support bundles be generated locally and their contents disclosed before any transfer; the same rule is applied here to every local trace, dump and event export: sensitive by default, collected locally, transferred only to a disclosed destination.[12]

## 14. Integrity checks

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [52] | [Fix Windows Update corruptions using DISM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/fix-windows-update-errors) | `DISM.exe /Online /Cleanup-Image /RestoreHealth`, optionally with `/Source` and `/LimitAccess`; `DISM /Online /Cleanup-Image /ScanHealth` | Repair operations change system state and may use a source image; scan results come from the servicing stack |
| [53] | [Repair a Windows image](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/repair-a-windows-image) | DISM image health check and repair | Targets the Windows image/servicing store |
| [54] | [Use the System File Checker tool](https://support.microsoft.com/en-us/windows/experience/backup-recovery/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files) | `sfc` scanning of protected system files and replacement from cached copies | A scan result is scoped to the files it protects; details land in the CBS log |
| [55] | [Understanding App Control event IDs](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations) | CodeIntegrity - Operational event log (policy activation, executables, DLLs, drivers); documented event IDs including 3002, 3004, 3011, 3012, 3084, 3085, 3111 | Events describe code integrity decisions for specific files in specific sessions |
| [56] | [How System Guard helps protect Windows](https://learn.microsoft.com/en-us/windows/security/hardware-security/how-hardware-based-root-of-trust-helps-protect-windows) | System Guard and Secure Launch (dynamic root of trust for measurement); measurements signed and sealed with the TPM after boot | Requires TPM 2.0 class hardware; Secure Launch does not support earlier TPM versions |
| [57] | [Trusted Platform Module technology overview](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview) | Device health attestation with TPM 2.0 (for example Secure Boot enablement reporting) | Attestation states what the platform measured; it does not measure application performance |

**Evidence interpretation**

- Integrity checks answer a narrow question: whether the servicing store or protected files are intact and whether repair is possible, with `DISM /ScanHealth` as the documented verification step for the image path.[52][53]
- Code integrity events are decision records for individual files in a session: the CodeIntegrity - Operational log contains policy activation and enforcement events, including boot-image and page-hash verification outcomes and HVCI policy results.[55] A logged block is evidence about that file and policy, not a performance measurement.
- Attestation is a different evidence class from a health scan: it is a TPM-backed measurement of the boot chain, while DISM/SFC results are local file-state checks.[52][56][57]
- A "healthy" integrity result is not a performance verdict; it removes one class of cause and leaves the performance question open.[52][54]

## 15. Cross-cutting collection, tracing and threshold references

| # | Source | Supported APIs and tools | Limits of the evidence |
|---|---|---|---|
| [58] | [Windows Performance Analyzer](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-analyzer) | Creates graphs and data tables from ETW events recorded by WPR, Xperf or an assessment; can open any ETL | Interpretation depends on which providers the recording enabled |
| [59] | [Built-in recording profiles (WPR)](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/built-in-recording-profiles) | Built-in profile groups by function, plus custom profiles | Profiles control all aspects of a recording; choosing the wrong profile omits providers |
| [60] | [Windows Performance Toolkit](https://learn.microsoft.com/en-us/windows-hardware/test/wpt) | WPT components; recordings must be opened and analyzed with WPA | Documentation entry point for the toolkit |
| [61] | [Performance counters tools](https://learn.microsoft.com/en-us/windows/win32/perfctrs/performance-counters-tools) | Performance Monitor, data collector sets and reports; counter log formats | Counter collection is interval-based and count-limited; counters are not a trace |
| [62] | [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent) | Reading and filtering event logs from PowerShell | Events are written as they occur; a log read is not a capture |
| [64] | [About Event Tracing (ETW)](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing) | ETW overview: providers, controllers, consumers, and trace sessions | Framework documentation |
| [65] | [Event Tracing (ETW) portal](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal) | Entry point to ETW APIs and provider documentation | Entry point; individual provider semantics live elsewhere |
| [66] | [Performance Analysis of Logs (PAL) tool](https://learn.microsoft.com/en-us/biztalk/technical-guides/using-the-performance-analysis-of-logs-pal-tool) | Reads performance-monitor counter logs and analyses them against thresholds that are "originally based on thresholds defined by the Microsoft product teams, including BizTalk Server, and members of Microsoft support"; documents a 25 ms disk response-time reference as a conservative threshold | Published thresholds belong to the source and workload they came from |
| [67] | [Windows Internals](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals) | Reference book for Windows internals used by the official CPU analysis guide | A book: explanatory authority, not a measurement source |
| [68] | [randomascii (Bruce Dawson)](https://randomascii.wordpress.com) | Practitioner articles on Windows and ETW performance analysis | Individual practitioner writing: valuable method, not normative guidance |
| [69] | [NT Debugging blog (archived)](https://learn.microsoft.com/en-us/archive/blogs/ntdebugging) | Practitioner case studies in kernel and crash analysis | Archived Microsoft blog: historical method and examples |

**Evidence interpretation**

- Recordings are profile-scoped and must be read as such: a WPR profile decides which providers are enabled, WPA can open any ETL but can only show what was recorded, and Microsoft states recordings must be opened and analyzed with WPA.[58][59][60]
- Counters and traces answer different questions: performance counters are interval samples of defined objects, while ETW traces are event streams that can be attributed to a timeline.[61][64]
- Published thresholds exist and should be cited rather than invented: the PAL documentation states that its thresholds were originally defined by Microsoft product teams and support, and it publishes a 25 ms disk response-time figure described as conservative.[66]
- Practitioner references are useful for method and pitfalls (how to frame a trace, what typically goes wrong in analysis).[68][69]
- The official CPU analysis guide points to Windows Internals for background, and neither that book nor practitioner writing replaces the normative reference page for a given tool or counter.[28][67]
- Event logs are read-after-the-fact unless a capture was configured in advance, which is a practical constraint on what can be attributed to a past symptom window.[62]

## Known gaps in this research base

- No Microsoft documentation located in this pass defines a supported API for per-zone thermal throttling percentage as a counter; the documented channel is thermal events and Kernel-ACPI tracing.[30]
- No Microsoft documentation located in this pass defines quantitative thresholds for storage reliability counters, WHEA error severity, or Search indexer latency; published reference figures exist for storage response time in the capacity-planning source.[2][14][63]
- Diagnostics-Performance boot/logon event IDs are widely referenced in community answers, but no Microsoft reference page for that channel was located in this pass, so no event IDs from it are asserted here.[unverified]
- VBS/memory-integrity overhead is documented qualitatively (generation dependent) with no published percentage in the sources listed above.[46][unverified]

## Sources

[1] https://learn.microsoft.com/en-us/windows-server/storage/storage-spaces/performance-history-for-drives - Performance history for drives (Storage Spaces Direct)
[2] https://learn.microsoft.com/en-us/powershell/module/storage/get-storagereliabilitycounter - Get-StorageReliabilityCounter (Storage module)
[3] https://learn.microsoft.com/en-us/powershell/module/storage/get-physicaldisk - Get-PhysicalDisk (Storage module)
[4] https://learn.microsoft.com/en-us/windows/win32/perfctrs/collecting-performance-data - Collecting Performance Data (Performance Counters)
[5] https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-file-system-filter-drivers - About File System Filter Drivers
[6] https://learn.microsoft.com/en-us/windows-hardware/test/assessments/minifilter-diagnostics - Minifilter Diagnostics assessment
[7] https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/bypassio - BypassIO for Filter Drivers
[8] https://learn.microsoft.com/en-us/sysinternals/downloads/procmon - Process Monitor (Procmon) - Sysinternals
[9] https://learn.microsoft.com/en-us/defender-endpoint/tune-performance-defender-antivirus - Performance analyzer for Microsoft Defender Antivirus
[10] https://learn.microsoft.com/en-us/defender-endpoint/performance-analyzer-reference - Microsoft Defender Antivirus Performance Analyzer reference
[11] https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-performance-issues - Troubleshoot Microsoft Defender Antivirus performance issues
[12] https://learn.microsoft.com/en-us/defender-endpoint/collect-diagnostic-data - Collect Microsoft Defender Antivirus diagnostic data
[13] https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus - Microsoft Defender Antivirus command-line arguments (MpCmdRun)
[14] https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/windows-search-performance-issues - Troubleshoot Windows Search performance
[15] https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/fix-problems-in-windows-search - Fix problems in Windows Search
[16] https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-performance-counters - Network-Related Performance Counters
[17] https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/diagnose-packet-loss - Diagnose packet loss (Windows Client)
[18] https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon - Packet Monitor (Pktmon)
[19] https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/tcpip-performance-known-issues - TCP/IP performance known issues
[20] https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-performance-tuning-nics - Network adapter performance tuning in Windows Server
[21] https://learn.microsoft.com/en-us/windows/win32/api/_dwm - Desktop Window Manager (DWM) API reference
[22] https://learn.microsoft.com/en-us/windows-hardware/drivers/display/windows-vista-display-driver-model-design-guide - WDDM overview (Windows Display Driver Model)
[23] https://learn.microsoft.com/en-us/windows/apps/develop/performance/power - Improve power consumption and battery life (app performance guidance)
[24] https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/using-windows-performance-analyzer-to-analyze-modern-standby-issues - Using Windows Performance Analyzer to analyze Modern Standby issues
[25] https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/cpu-usage-exceeds-100 - CPU usage exceeds 100% if Turbo Boost is active (time-based vs utility counters)
[26] https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options - Powercfg command-line options
[27] https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/hardware/power/power-performance-tuning - Power and performance tuning (Windows Server)
[28] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/cpu-analysis - CPU Analysis (Windows Performance Toolkit assessment guide)
[29] https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/design-guide - Windows thermal management framework (design guide)
[30] https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/examples--requirements-and-diagnostics - Thermal management examples, requirements and diagnostics
[31] https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/device-level-thermal-management - Device-level thermal management
[32] https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/acpi-defined-devices - ACPI-defined devices (thermal zones)
[33] https://learn.microsoft.com/en-us/windows-hardware/test/assessments/onoff-transition-performance - On/Off Transition Performance assessments
[34] https://learn.microsoft.com/en-us/windows-hardware/test/assessments/results-for-the-onoff-assessments - Results for the On/Off assessments
[35] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options - WPR command-line options
[36] https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/distinguishing-fast-startup-from-wake-from-hibernation - Distinguishing Fast Startup from wake-from-hibernation
[37] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/optimizing-performance-and-responsiveness-exercise-2 - Exercise 2: Evaluate Fast Startup using the Windows Performance Toolkit
[38] https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/large-wmi-repository-cause-slow-logon - Large WMI repository causes slow logon
[39] https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns - Autoruns - Sysinternals
[40] https://learn.microsoft.com/en-us/windows/win32/w8cookbook/startup-apps - Startup apps (Task Manager startup impact)
[41] https://learn.microsoft.com/en-us/powershell/module/pnpdevice/get-pnpdevice - Get-PnpDevice (PnpDevice module)
[42] https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/introduction-to-the-windows-hardware-error-architecture - Introduction to the Windows Hardware Error Architecture (WHEA)
[43] https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/whea-hardware-error-events - WHEA hardware error events
[44] https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/error-records - WHEA error records
[45] https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2 - Bug check code reference
[46] https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity - Enable virtualization-based protection of code integrity (Memory integrity/HVCI)
[47] https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs - Virtualization-based Security (VBS) - OEM guidance
[48] https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-hvci-enablement - Memory integrity and VBS enablement
[49] https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization - Configure Windows diagnostic data in your organization
[50] https://learn.microsoft.com/en-us/windows/privacy/required-diagnostic-events-fields-windows-11-24h2 - Windows 11 required diagnostic data events and fields
[51] https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services - Manage connections from Windows components to Microsoft services
[52] https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/fix-windows-update-errors - Fix Windows Update corruptions using DISM
[53] https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/repair-a-windows-image - Repair a Windows image (DISM)
[54] https://support.microsoft.com/en-us/windows/experience/backup-recovery/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files - Use the System File Checker tool to repair missing or corrupted system files
[55] https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations - Understanding App Control (Code Integrity) event IDs
[56] https://learn.microsoft.com/en-us/windows/security/hardware-security/how-hardware-based-root-of-trust-helps-protect-windows - How System Guard helps protect Windows (hardware root of trust)
[57] https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview - Trusted Platform Module technology overview (device health attestation)
[58] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-analyzer - Windows Performance Analyzer
[59] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/built-in-recording-profiles - Built-in recording profiles (WPR)
[60] https://learn.microsoft.com/en-us/windows-hardware/test/wpt - Windows Performance Toolkit
[61] https://learn.microsoft.com/en-us/windows/win32/perfctrs/performance-counters-tools - Performance counters tools (Performance Monitor)
[62] https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent - Get-WinEvent (Microsoft.PowerShell.Diagnostics)
[63] https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/active-directory-server/capacity-planning-for-active-directory-domain-services - Capacity planning for Active Directory Domain Services (storage and CPU reference figures)
[64] https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing - About Event Tracing (ETW)
[65] https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal - Event Tracing (ETW) portal
[66] https://learn.microsoft.com/en-us/biztalk/technical-guides/using-the-performance-analysis-of-logs-pal-tool - Performance Analysis of Logs (PAL) tool
[67] https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals - Windows Internals (Sysinternals resources)
[68] https://randomascii.wordpress.com - Bruce Dawson (randomascii) - Windows and ETW performance analysis
[69] https://learn.microsoft.com/en-us/archive/blogs/ntdebugging - NT Debugging blog (Microsoft, archived)
[70] https://github.com/GameTechDev/PresentMon - PresentMon (frame timing and presentation capture)
