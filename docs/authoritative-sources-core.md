# Authoritative Microsoft Sources: Core Diagnostic Surfaces

Evidence base for the toolkit's core performance and reliability surfaces. Every
claim below was read from a Microsoft Learn page and every URL was checked for a
200 response on 2026-09-15 (see Section 16 for the check and how to repeat it).

Scope: WPT/WPR/WPA/WPAExporter, ETW, PerfMon/PDH and performance counters, TSS
performance scenarios, WPR On/Off boot tracing, Wait Chain Traversal, WER, WHEA,
Windows Storage reliability APIs, ProcDump, PoolMon, minifilter diagnostics, and
the Microsoft Defender performance analyzer.

Rules this document follows:

1. Microsoft documentation only. No third-party blogs, forums, or Q&A threads.
2. Only flags, functions, and status codes that appear in the cited page. Where
   a flag list was not read, the page is linked instead of paraphrased.
3. Discrepancies between Microsoft pages are reported as discrepancies, not
   silently resolved.
4. Nothing here authorizes remediation. Each section ends with the assumptions
   the current documentation contradicts.

---

## 1. Windows Performance Toolkit (WPT): WPR, WPA, WPAExporter

What it is: the Windows Performance Toolkit is included in the Windows
Assessment and Deployment Kit (ADK) [1]. It consists of two independent tools,
Windows Performance Recorder (WPR) and Windows Performance Analyzer (WPA);
support is maintained for the older command-line tool Xperf, but Xperfview is no
longer supported and all recordings must be opened and analyzed with WPA [1].
WPR creates Event Tracing for Windows (ETW) recordings from built-in profiles or
custom XML profiles and can also be driven through the WPRControl API [1][2].
WPA provides a graph explorer, pivotable and searchable data tables, and an
Issues window [1][3].

Direct URLs:

  https://learn.microsoft.com/en-us/windows-hardware/test/wpt
  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-recorder
  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-analyzer
  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpa-quick-start-guide
  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpa-step-by-step-guide
  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/list-of-wpa-graphs
  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/cpu-analysis
  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-analyzer-common-scenarios
  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-recorder-common-scenarios
  https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install

Supported semantics and terminology:

- The toolkit is installed with the Windows ADK [1][13]; WPR and WPA are
  independent tools with no shared runtime requirement beyond the ADK [1].
- WPR records ETW; WPA analyzes recordings created by WPR or by the Assessment
  Platform [1][2][3].
- Analysis entry points include the WPA quick start guide [6], the step-by-step
  guide [7], and the graph catalog [8]. The CPU analysis topic covers the CPU
  tables in detail [9].
- Scenario indexes: WPA common scenarios [12] and WPR common scenarios [11].
- WPR common scenarios cover basic system diagnosis, heap analysis, heap
  snapshots, resource-based analysis, on/off transitions, and custom
  profiles [11].

Version and requirement statements as published:

- WPR requires Windows 8 or later and WPA requires Windows 8 or later with
  .NET Framework 4.5 or later [1].
- The WPR command-line page separately states that WPR requires Windows 8.1 or
  later [4]. Treat this as a documentation discrepancy: the command-line page is
  the more restrictive statement.

Outdated assumptions to avoid:

- Xperfview is retired; do not present it as an analysis path [1].
- Xperf is a legacy command-line tool that WPT still supports, not the current
  recording interface; WPR profiles are the supported recording surface [1][2].
- Do not treat a WPT install as a Windows service or inbox feature; it comes from
  the ADK [1][13].

### 1.1 WPAExporter

WPAExporter is the command-line form of WPA for automated analysis: it exports
tables from a single trace and profile to CSV, optionally restricted to a time
range, with the goal of batch analysis at scale [5].

Verified syntax [5]:

  wpaexporter.exe [-i] traceFile.etl -profile profile.wpaProfile
      [-delimiter <char>] [-prefix <prefix>] [-outputfolder <folder>]
      [-range <start> <end>] [-marks <M1> <M2>] [-regionsxml <manifest> ...]
      [-region <region_name>] [-symbols] [-tti] [-h | /?]

Observed semantics [5]:

- A trace file and a .wpaProfile profile are both required; the -i flag itself is
  optional [5].
- -range uses nanoseconds by default and also accepts s, ms, and us suffixes,
  for example 1s, 100ms, 500us [5].
- Time ranges can be numeric, two named markers, or regions of interest [5].
- Without a time range, the entire trace duration is exported [5].
- -region requires at least one regions-of-interest manifest supplied with
  -regionsxml [5].
- Output file names are generated from table and preset names; -prefix and
  -outputfolder only modify them [5].
- -tti processes the trace even in the presence of time inversions [5].

Outdated assumptions to avoid:

- Comparative Analysis Views cannot be exported by WPAExporter [5].
- Do not invent an output-file name: names are generated, so downstream tooling
  must glob for the produced CSVs [5].
- Do not assume the .wpaProfile can be omitted in favour of a preset name; the
  profile is what selects the tables [5].

## 2. WPR command-line semantics

WPR exposes a small command line whose complexity lives in the recording
profiles [4].

First-level options as published [4]: -help, -profiles, -purgecache, -start,
-marker, -markerflush (obsolete), -status, -profiledetails, -exportprofile,
-providers, -cancel, -stop, -merge, -flush, -log, -disablepagingexecutive,
-heaptracingconfig, -snapshotconfig, -capturestateondemand, -pmcsources,
-pmcsessions, -setprofint, -profint, -resetprofint, -boottrace,
-enableperiodicsnapshot, -disableperiodicsnapshot, -singlesnapshot.

Verified syntax fragments [4]:

  wpr -start <profile> [-start <profilen>]... [-filemode]
      [-recordtempto <temp folder path>]
      [-onoffscenario <OnOff Transition Type>]
      [-onoffresultspath <path to which the trace files are saved>]
      [-onoffproblemdescription <description of the scenario>]
      [-numiterations <number of iterations for OnOff tracing>]

  wpr -stop <file> <problem description> [-skipPdbGen] [-force] [-compress]

  wpr -status [profiles] [collectors [-details]]

  wpr -profiles [<path>]
  wpr -profiledetails <profile1>+<profile2>+...+<profilen> [-filemode]
  wpr -exportprofile <profile1>+<profile2>+...+<profilen> <ExportedFileName.wprp> [-filemode]
  wpr -merge <trace files ...> <merged file> [-skipPdbGen] [-compress] [-supresspii] [-mergeonly] [-injectonly]
  wpr -cancel

Observed semantics [4]:

- Profiles are named <profile> := [<filename.wprp>!]<profile name>[.{light|verbose}];
  up to 64 profiles can be given on one command line, and the verbose version is
  used when neither qualifier is given unless only a light version exists [4].
- The default recording mode is memory; -filemode records to an unbounded file
  that can grow until it fills the disk [4].
- -stop <file> requires the file name; the problem description is optional but
  recommended; -force disables the warning when the extension is not .etl [4].
- -instancename must be the last parameter, and every later command that
  manipulates that session must repeat the same -instancename or it will report
  that no trace profiles are running (error code 0xc5583000 in the example) [4].
- WPR writes managed symbols next to traces and caches them in
  C:\ProgramData\WindowsPerformanceRecorder\NGenPdbs_Cache; -skipPdbGen reduces
  stop time by disabling dynamic generation of ngen and embedded PDBs [4].

Outdated assumptions to avoid:

- -markerflush is documented as obsolete [4].
- Do not assume file mode is the default; the default is memory mode [4].
- Do not assume that an unbounded -filemode capture is bounded by anything other
  than free disk space [4].

## 3. WPR On/Off boot tracing

WPR ships built-in profiles for on/off transitions [10]:

  On/Off - Boot
  On/Off - FastStartup
  On/Off - Shutdown
  On/Off - RebootCycle
  On/Off - Standby/Resume
  On/Off - Hibernate/Resume

Two documented mechanics exist, and they are different:

1. Autologger (boot) tracing through -boottrace [4]:

   wpr -boottrace {-addboot [<filename.wprp>!]<profile> [-addboot <profile> ...]
       [-filemode] [-recordtempto <temp folder path>]
     | -stopboot <recording filename> <Problem description>
     | -cancelboot}

   -addboot sets the autologger registry entries and takes the same options as
   -start, but does not start the trace immediately; the operating system starts
   the autologger after the reboot [4]. -stopboot removes the autologger, stops
   the recording, and merges everything into the given file, but it saves a trace
   only if the autologger session actually ran after a reboot; otherwise it only
   removes the configuration [4]. -cancelboot removes the autologger and cancels
   the recording [4].

2. On/Off scenario recording through -start [4]:

   wpr -start <profile> -onoffscenario <Boot|FastStartup|Shutdown|RebootCycle|Standby|Hibernate>
       -onoffresultspath <path> -onoffproblemdescription <text> [-numiterations <n>]

Observed behavior [10]: these profiles reboot the computer three times by
default and on/off transitions are always logged to a file.

Assessment-platform equivalent: the On/Off Transition Performance assessments
measure power-on transitions (boot, resume from standby S3, resume from hibernate
S4), power-off transitions, the boot interval (power button to desktop with
startup tasks processed), and the shutdown interval, and they link into WPA for
deeper analysis [32].

TSS equivalent: -StartAutoLogger schedules boot-time collection, and TSS exposes
a WPR profile named BootGeneral for that purpose [30].

Outdated assumptions to avoid:

- -boottrace alone records nothing; it configures registry entries for
  autologger or globallogger sessions [4].
- A boot trace requires a reboot between -addboot and -stopboot; -stopboot
  without that reboot silently yields no trace [4].
- Do not expect memory-mode buffering for on/off transitions: they are always
  logged to a file [10].
- The default three reboots mean a single on/off recording is not a one-boot
  capture unless -numiterations is set [4][10].

## 4. ETW: Event Tracing for Windows

ETW is an efficient kernel-level tracing facility that logs kernel or
application-defined events to a log file, consumed in real time or from a file,
and enabled or disabled dynamically without restarting the computer or the
application [14].

The model has three components [14]:

- Controllers: define log file size and location, start and stop sessions,
  enable providers, manage the buffer pool, and obtain session statistics
  (buffers used and delivered, events and buffers lost).
- Providers: contain the instrumentation; a controller enables or disables them.
- Consumers: select one or more sessions, may receive events in chronological
  order across sessions, and may specify start and end times.

Provider types [14]:

- MOF (classic) providers: RegisterTraceGuids and TraceEvent; events defined by
  MOF classes; enabled by only one trace session at a time.
- WPP providers: same registration functions, decoding information in TMF files
  compiled into the binary PDB; enabled by only one trace session at a time.
- Manifest-based providers: EventRegister and EventWrite; events defined by a
  manifest; enabled by up to eight trace sessions simultaneously.
- TraceLogging providers: TraceLoggingRegister and TraceLoggingWrite;
  self-describing events; enabled by up to eight trace sessions simultaneously.
- Manifest-based or TraceLogging is recommended for Windows Vista or later [14].

Session configuration and provider enablement [16]:

- Allocate an EVENT_TRACE_PROPERTIES structure large enough to also hold the
  session and log file names, then call StartTrace.
- Enable classic providers with EnableTrace, manifest-based providers with
  EnableTraceEx, and use EnableTraceEx2 on Windows 8.1 / Windows Server 2012 R2
  and later for payload, scope, and stack-walk filters [16].
- TraceSetInformation adds information such as trace version info to the
  extended data section of events [16].
- Up to eight trace sessions can enable and receive events from the same
  manifest-based provider; only one session can enable a classic provider, and a
  second enabling session takes over (the first stops receiving events) [16].
- Discover provider levels and keywords with "logman query <provider-name>" or
  "wevtutil gp <provider-name>", and enumerate manifest-based providers with
  "wevtutil ep" [16].

The ETW documentation set is indexed from the Event Tracing portal [15], the
controller, provider, and consumer functions are catalogued on the Evntrace.h API
reference [18], and wevtutil is documented as the Windows command for event log
and provider queries [26].

Command-line tooling published by Microsoft [17]: Logman (manage and schedule
performance counter and event trace log collections), Tracelog (control an event
trace session), Tracerpt (process event trace logs and generate reports and CSV),
Tracefmt and Tracepdb (WPP software tracing), plus WPR, WPA, xperf, and PerfView
as the analysis and capture tools [17].

Missing or lost events are documented to occur when the total event size exceeds
64 KB, when the ETW buffer is smaller than the event, when a real-time consumer
is too slow or absent, and when the logging disk cannot keep up with the logging
rate; the user has no control over the first three [14].

Outdated assumptions to avoid:

- Do not assume a classic (MOF or WPP) provider can feed several sessions in
  parallel; only manifest-based and TraceLogging providers reach eight [14][16].
- Do not assume logman or wevtutil list filter data requirements: the commands
  list level and keywords only, and the provider must document any filter
  data [16].
- Do not treat lost events as an application defect by default; the documented
  causes include buffer and disk limitations that the collector controls [14].

## 5. PerfMon, PDH, and performance counters

Windows Performance Counters provide a high-level abstraction layer with a
consistent interface for collecting system data such as processor, memory, and
disk usage statistics [19]. The system is organized into consumers, providers,
countersets, counters, instances, and counter values; countersets are called
performance objects in some APIs [19].

Provider architecture [19]:

- A V1 provider publishes data through a performance DLL that runs in the
  consumer's process and is installed with an .ini file; the V1 provider
  architecture is deprecated and new providers should use the V2 architecture.
- A V2 provider publishes data through the performance counter provider APIs and
  is installed with a .man (XML manifest) file.

The explicit collection limits stated by Microsoft [19]: performance counters
are optimized for administrative and diagnostic data discovery and collection,
are not appropriate for high-frequency data collection or application profiling,
and are not designed to be collected more than once per second. Microsoft points
at lower-overhead alternatives for system information (Process Status Helper,
GlobalMemoryStatusEx, GetSystemTimes, GetProcessTimes) and at ETW for profiling,
for example tracelog.exe with -critsec, -dpcisr, -eflag, or -ProfileSource, or
Hardware Counter Profiling [19]. Windows Performance Counters are not the same
thing as the QueryPerformanceCounter API, which returns a high-precision
timestamp [19].

Process identity requires special handling. Microsoft documents that the legacy
Process counterset can mix same-named process instances when processes start or
end between samples. On Windows 11 and later, the Process V2 counterset includes
the process ID in the instance name and avoids that instance-matching problem
[19]. The toolkit should prefer Process V2 when the counterset exists; on older
systems or when it is unavailable, direct process APIs paired by PID plus
StartTime are safer than the legacy instance name alone.

Task Manager, Resource Monitor, Performance Monitor, typeperf.exe, logman.exe,
and relog.exe are the built-in consumers [19][20]. PowerShell and WMI reach the
same data, and C/C++ and .NET reach it through the counter APIs [19].

PDH is the high-level consumer API [21]:

- PDH simplifies query parsing, metadata caching, instance matching between
  samples, formatted-value computation, and log file reading and writing.
- PDH uses the registry functions for V1 providers and the PerfLib V2 consumer
  functions for V2 providers.
- The documented workflow is: create a query, add counters, collect the data,
  display it, close the query.
- PDH cannot be used in Windows OneCore (UWP) apps; those must use the PerfLib V2
  consumer functions instead [21].
- PdhAddCounter, PdhAddEnglishCounter, PdhCollectQueryData, PdhCollectQueryDataEx,
  PdhCollectQueryDataWithTime, PdhComputeCounterStatistics, PdhCalculateCounterFromRawValue,
  and PdhCloseQuery are part of the pdh.h surface [22].
- Counter paths follow the shape [Performance counter object]\<Instance>\<Counter Name>,
  for example [Processor Information]\<CPU 0\>\% Processor Time; objects without
  multiple instances omit the instance segment [27].

Counter-log capture is exposed on the documented command line [23][24][25]. A
data collector set can be created with "logman create counter <name> -o
<file.blg> -f bincirc -v mmddhhmm -max <MB> -c <counters...> -si <interval>",
started with "logman start <name>", and stopped with "logman stop <name>";
logman, typeperf, and relog are the documented command-line tools for counter
logs, real-time counter sampling, and log conversion [27].

A practical display limit documented in the Microsoft scenario guide [27]:
Performance Monitor displays a maximum of 1,000 data points in a graph, so a
one-second interval log covers only 16 minutes and 40 seconds before the tool
summarizes and combines samples (a high-density capture); in that state the graph
can disagree with the Minimum or Maximum values of the same counter, and the tool
shows how many samples were combined in each data point.

Related entry points: Performance Monitor troubleshooting [29] and the Windows
client performance troubleshooting hub [28], whose sub-categories include
performance monitoring tools and slow performance.

Outdated assumptions to avoid:

- Do not design a collector around sub-second counter sampling; Microsoft states
  counters are not designed to be collected more than once per second [19].
- Do not present the V1 provider model (performance DLL plus .ini) as current;
  it is deprecated in favour of V2 manifests [19].
- Do not use PDH for Windows OneCore / UWP apps, and do not confuse performance
  counters with QueryPerformanceCounter [19][21].
- Do not read a long-window PerfMon graph as raw data when the interval is one
  second; it is summarized, and min/max values are the tell [27].

## 6. TSS performance scenarios (TroubleShootingScript toolset)

TSS is a Microsoft-signed PowerShell toolset and framework for data collection
and diagnostics, downloadable as TSS.zip from https://aka.ms/getTSS [30]. It must
run in an elevated PowerShell window (PowerShell ISE is not supported), the EULA
must be accepted once, and the execution policy should be set at process scope
with "Set-ExecutionPolicy -scope Process -ExecutionPolicy RemoteSigned -Force" [30].

Verbs and their documented meaning [30]:

  -Start             (default; starts ETW component traces or tools such as WPR)
  -StartAutoLogger   (collect at boot time; stop later with .\TSS.ps1 -Stop)
  -StartDiag         (limited present use; can combine with arguments such as NET_DFSn)
  -StartNoWait       (traces survive sign-out; stop later with .\TSS.ps1 -Stop)
  -CollectLog        (commonly used with DND_SetupReport)

The toolset publishes these performance scenarios [31].

  .\TSS.ps1 -SDP Perf                     performance issue, slow startup, or bug check
  .\TSS.ps1 -Scenario PRF_General         unexplained degradation across components,
                                          intermittent or multi-symptom issues
  .\TSS.ps1 -Scenario PRF_UWP             black screen after logon (with
                                          -set crashmode, -crash, -StartAutoLogger)
  .\TSS.ps1 -Scenario PRF_Perflib         missing or corrupt performance counters,
                                          blank or incomplete PerfMon data,
                                          perflib.dll CPU or memory problems,
                                          Event ID 1008 or 1023

Support tools and commands selectable alongside the scenario [30]:

  -PerfMon <CounterSetName> [-PerfIntervalSec <n>]   default interval 10 seconds
  -PerfMonLong <CounterSetName> [-PerfLongIntervalMin <n>]   default 10 minutes
  -PoolMon <Start|Stop|Both>
  -ProcDump <PID>
  -WPR <WPRprofile> [-SkipPdbGen] [-WPROptions '<option string>']
  -Xperf <Profile> [-XperfMaxFileMB <n>] [-XperfTag <PoolTag>] [-XperfPIDs <PID>]
  -StartAutoLogger (schedule collection after the next restart)

Names must be discovered on the machine, not guessed: .\TSS.ps1
-ListSupportedScenarioTrace lists scenario names, -ListSupportedTrace lists
component traces, -ListSupportedPerfCounter lists perfmon counter sets,
-ListETWProviders lists provider GUIDs for a component or scenario,
-ListSupportedNetshScenario lists netsh scenarios, and -ListSupportedXperfTrace
style enumeration is the documented pattern for the other families [30].

Outdated assumptions to avoid:

- TSS is not an inbox tool; the documented distribution channel is the TSS.zip
  download at https://aka.ms/getTSS [30].
- The WPR profile names accepted by TSS (General, BootGeneral, CPU, Device,
  Memory, Network, Registry, Storage, Wait, SQL, Graphic, Xaml, VSOD_CPU,
  VSOD_Leak) are TSS argument values, not WPR built-in profile names; do not use
  them in a raw wpr.exe command line [30].
- Do not invent a scenario name such as PRF_<topic>; only names returned by the
  enumeration cmdlets are supported [30].

## 7. Wait Chain Traversal (WCT)

WCT allows debuggers to diagnose application hangs and deadlocks [33]. A wait
chain is an alternating sequence of threads and synchronization objects in which
each thread waits for the object that follows, and that object is owned by the
next thread in the chain [33].

Supported synchronization primitives [33]: Advanced Local Procedure Call (ALPC),
COM, critical section objects, mutex objects, the SendMessage function, and wait
operations on processes and threads.

API semantics [33][35]:

- Create a session with OpenThreadWaitChainSession and retrieve chains with
  GetThreadWaitChain; sessions are represented by a handle of type HWCT.
- Synchronous sessions cannot be cancelled and block the calling thread until a
  wait chain has been retrieved.
- Asynchronous sessions do not block the calling thread and can be cancelled with
  CloseThreadWaitChainSession; results arrive through an application-supplied
  WaitChainCallback function, and the caller can pass an opaque context pointer
  through GetThreadWaitChain that is handed to the callback.
- The worked example is documented under Using WCT [34], and the function and
  structure reference is the Wct.h API surface [35].

Outdated assumptions to avoid:

- WCT reports waits only for the listed primitives; do not present it as a
  general scheduler or I/O wait analyzer [33].
- Do not treat a completed (rather than blocked) synchronous query as a live
  analysis loop; synchronous sessions block, which is why asynchronous sessions
  with a callback are the documented pattern for monitoring [33].
- The WCT reference lives under the Win32 debugging documentation and the Wct.h
  API surface, not under process and thread APIs, so links should point there [33][35].

## 8. Windows Error Reporting (WER)

WER is an event-based feedback infrastructure that gathers information about
hardware and software problems Windows can detect, reports it to Microsoft, and
returns available solutions [36]. Since Windows Vista, Windows provides crash, no
-response, and kernel fault reporting by default without application changes; the
WER API exists for application-specific problems that are not crashes,
non-responses, or kernel faults [36].

Report parameters [36]: a small set of values that describes a problem uniquely,
including application name, application version, module name, module version, and
error code. When WER checks for a solution it first asks whether the problem is
already known; the server can return a solution, request more information, or
create an issue for a developer [36].

Local dumps [37]:

- The feature stores full user-mode dumps locally after a user-mode crash; it is
  not enabled by default and enabling it requires administrator privileges.
- Configuration lives under
  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps.
- DumpFolder is REG_EXPAND_SZ with a default of %LOCALAPPDATA%\CrashDumps; service
  crashes land in service-specific profile folders (for example
  %WINDIR%\System32\Config\SystemProfile for System services and
  %WINDIR%\ServiceProfiles for Network and Local services).
- DumpCount is REG_DWORD with a default of 10; when the maximum is exceeded the
  oldest dump is replaced.
- DumpType is REG_DWORD: 0 custom, 1 mini (default), 2 full.
- CustomDumpFlags is REG_DWORD, used only when DumpType is 0, and is a bitwise
  combination of MINIDUMP_TYPE values; the documented default example is 0x00000121
  (MiniDumpWithDataSegs, MiniDumpWithUnloadedModules, MiniDumpWithProcessThreadData).
- Per-application keys under LocalDumps override the global values.
- After a crash, and before termination, the system checks the registry to decide
  whether to collect a dump; if the application supports recovery the dump is
  collected before the recovery callback.
- Local dumps are configured and controlled independently of the rest of WER, so
  they still work when WER is disabled or the user cancels reporting.
- No local dump is collected when automatic debugging for application crashes is
  configured.

Windows 11 additions documented on the same page [37]: Task Manager can create
live memory dumps for kernel and user-mode processes (Processes or Details tab,
right-click, "Create live memory dump file"), and ProcDump has been extended with
trigger types such as thread creation or exit, specific performance counters, and
hung windows [37].

Related: the WER settings reference is [38], and the application-facing overview
of the report lifecycle is [36].

Outdated assumptions to avoid:

- Local dumps do not require WER to be enabled, and they are not the same report
  as the one sent to Microsoft [37].
- The default dump type is a mini dump (DumpType 1), not a full dump [37].
- The default dump count is 10 per folder, and old dumps are silently replaced
  rather than accumulated [37].
- "Problem Reports and Solutions" is Windows Vista-era naming; the documented
  later surface is Action Center and the "View all problem reports" and "View
  reliability history" entry points [36].

## 9. Windows Hardware Error Architecture (WHEA)

WHEA provides support for hardware error reporting and recovery [39]. The design
guide covers the architecture overview, platform-specific hardware error driver
(PSHED) plug-ins, and how user-mode applications communicate with the WHEA
platform [39].

Documented user-mode surfaces [40][41][42]:

- WHEA-aware user-mode applications include hardware error event processing
  applications (events, event log queries, notification registration) and WHEA
  management applications (the management interface, documented as supported on
  Windows Server 2008, Windows Vista SP1, and later) [40].
- The provider that logs hardware error events is
  Microsoft-Windows-WHEA-Logger; it is designed for desktop scenarios and
  provides a human-readable message with the main details of the event [41].
- The documented query pattern uses the Windows Event Log API (EvtQuery against
  the System channel with the XPath
  *[System/Provider[@Name="Microsoft-Windows-WHEA-Logger"]], EvtNext, EvtClose) [41].
- Registration for notification of hardware error events is the other documented
  approach [42].

Crash correlation: Bug Check 0x124 WHEA_UNCORRECTABLE_ERROR is the bug check the
debugger documentation associates with WHEA [43].

Outdated assumptions to avoid:

- Do not present a generic user-mode API for reading raw WHEA error records; the
  documented paths are the event log provider and the WHEA management interface [40][41].
- Do not treat the absence of Microsoft-Windows-WHEA-Logger entries as proof that
  hardware is healthy; it is a reporting surface for errors the platform
  reports [41].
- WHEA management interfaces are documented as supported from Windows Server 2008
  and Windows Vista SP1 onward, so older-version advice should not be reused [40].

## 10. Windows Storage reliability APIs

Two documented paths exist: the Storage module cmdlets, and the storage
prediction IOCTL.

Storage module [44][45][46]:

- Get-StorageReliabilityCounter returns the storage reliability counters for a
  specified PhysicalDisk or Disk; the counters cover device temperature, errors,
  wear, and how long the device has been in use [44].
- Verified example output fields include DeviceId, LoadUnloadCycleCount,
  LoadUnloadCycleCountMax, ManufactureDate, PowerOnHours, ReadErrorsCorrected,
  ReadErrorsTotal, ReadErrorsUncorrected, StartStopCycleCount,
  StartStopCycleCountMax, Temperature, TemperatureMax, Wear, WriteErrorsCorrected,
  WriteErrorsTotal, and WriteErrorsUncorrected [44].
- The documented usage shape is Get-PhysicalDisk -FriendlyName "<name>" |
  Get-StorageReliabilityCounter | Format-List [44].
- Get-PhysicalDisk returns PhysicalDisk objects from all available storage
  management providers and supports filtering by HealthStatus among other
  properties [45]; Get-Disk is the companion cmdlet for the disk object [46].

The storage prediction interface is IOCTL_STORAGE_PREDICT_FAILURE, with results
reported in the STORAGE_PREDICT_FAILURE structure [47][48].

- Polls for a prediction of device failure and works with IDE drives that support
  SMART; for SCSI drives the class driver attempts to verify equivalent support
  through the Information Exception Control Page.
- The disk class driver reports results in the PredictFailure member of
  STORAGE_PREDICT_FAILURE in the output buffer; a nonzero PredictFailure means
  the disk has bad sectors and is predicting a failure, and 512 bytes of
  vendor-specific information are returned in VendorSpecific [47].
- A PredictFailure value of zero means the disk is not predicting a failure [47].
- If the device does not support failure prediction, the IOCTL fails with
  STATUS_INVALID_DEVICE_REQUEST and the output buffer contents are undefined [47].
- The page lists monitoring the event log and registering for the
  WMI_STORAGE_PREDICT_FAILURE_EVENT_GUID WMI event as other means of checking for
  disk failure [47].

Outdated assumptions to avoid:

- An unsupported prediction IOCTL returns STATUS_INVALID_DEVICE_REQUEST rather
  than a negative prediction; treat that as "not reported", never as "healthy" [47].
- Reliability counters are per-device-reported values (temperature, wear, power-on
  hours, error counters); they are not a normalized health score, and fields such
  as Wear and PowerOnHours can be blank for a device that does not report them [44].
- Do not build on the failure-prediction path as the only storage-health signal;
  the Storage module cmdlets and the IOCTL expose different sets of data [44][47].

## 11. ProcDump

ProcDump is a command-line utility whose primary purpose is monitoring an
application for CPU spikes and generating crash dumps during a spike; it also
performs hung window monitoring using the same window-hang definition as Windows
and Task Manager, unhandled exception monitoring, dumps based on performance
counter values, and general-purpose process dumping from scripts [49]. The page
is published as ProcDump v12.01 and reports it runs on Windows 11 and higher for
client, and Windows Server 2016 and higher for server [49].

Verified capture syntax [49]:

  procdump.exe [-mm] [-ma] [-mt] [-mp] [-mc <Mask>] [-md <Callback_DLL>] [-mk]
      [-n <Count>] [-s <Seconds>]
      [-c|-cl <CPU_Usage> [-u]] [-m|-ml <Commit_Usage>]
      [-p|-pl <Counter> <Threshold>] [-h]
      [-e [1] [-g] [-b] [-ld] [-ud] [-ct] [-et]]
      [-l] [-t] [-f <Include_Filter>, ...] [-fx <Exclude_Filter>, ...]
      [-dc <Comment>] [-o] [-r [1..5] [-a]] [-at <Timeout>] [-wer] [-64]
      {{[-w] <Process_Name> | <Service_Name> | <PID>} [<Dump_File> | <Dump_Folder>]}
      | {-x <Dump_Folder> <Image_File> [Argument, ...]}

Verified install/uninstall syntax [49]:

  procdump.exe -i [Dump_Folder] [-mm] [-ma] [-mt] [-mp] [-mc <Mask>]
      [-md <Callback_DLL>] [-mk] [-r] [-at <Timeout>] [-k] [-wer]
  procdump.exe -u

Documented dump types [49]: -mm mini (default, stacks and what they reference,
all metadata), -ma full (all memory), -mt triage (directly referenced memory,
limited metadata; removal of sensitive information is attempted but not
guaranteed), -mp MiniPlus (all private memory and read/write image or mapped
memory, with the largest private area over 512 MB excluded; CLR processes are
dumped as full), -mc custom MINIDUMP_TYPE mask, -md callback dump via a
MiniDumpWriteDump callback DLL, -mk also writes a kernel dump with the kernel
stacks of the process threads.

Documented triggers and conditions [49]: -c and -cl for CPU above or below a
threshold, -m and -ml for memory commit thresholds, -p and -pl for performance
counter thresholds, -h for a hung window (no response to window messages for at
least 5 seconds), -e for unhandled exceptions with the 1 modifier for first-chance
exceptions and -ld / -ud / -ct / -et for module load, module unload, thread
create, and thread exit, -f and -fx include and exclude filters, -n dump count,
-s seconds between dumps, -w to wait for a process to launch, -x to launch and
dump, -r clones with optional -a avoid-outage, -k to kill after cloning or at end
of collection, -dc to add a dump comment, -o to overwrite, -at to cancel the
trigger's collection after N seconds, -l to display debug logging, -wer for WER
integration, and -64 for 64-bit dump capture.

Outdated assumptions to avoid:

- The default dump type is mini (-mm), not full; a plain "procdump <pid>" does
  not capture all memory [49].
- Dumps can contain sensitive data: the triage type only attempts, and does not
  guarantee, removal of sensitive information [49].
- -h is not a "hang detector" in the generic sense; it triggers on a window that
  does not respond to window messages for at least 5 seconds [49].
- -k and -r change the target's lifecycle; they are not passive capture
  options [49].

## 12. PoolMon

PoolMon (poolmon.exe) is the Memory Pool Monitor: it displays data the operating
system collects about memory allocations from the system paged and nonpaged
kernel pools and the memory pools used for Terminal Services sessions, grouped by
pool allocation tag [50]. It is used to detect memory leaks in drivers and to
observe allocation and free patterns over time [50].

Distribution and helpers [50]:

- PoolMon ships in the \Tools\Other subdirectory of the Windows Driver Kit
  (WDK).
- It can display the Windows components and commonly used drivers that assign
  each pool tag, using the pooltag.txt file installed with PoolMon and the
  Debugging Tools for Windows packages.

Commands are split into a startup command and run-time commands [51], and the
startup command page is [52].

Requirements [51]:

- The version described runs only on Windows XP and later.
- Display requirements: the Command Prompt window must be at least 80 characters
  wide and 53 rows high, and the buffer at least 500 characters wide and 2000 rows
  high, or the display is truncated.
- Required files: poolmon.exe, msdis130.dll, msvcp70.dll, msvcr70.dll, and
  pooltag.txt.
- Pool tagging requirement: the page states that pool tagging is enabled with
  GFlags by checking "Enable Pool Tagging" in the Global Flags dialog and then
  restarting the computer.

Worked method: the debugging documentation provides a step-by-step method for
using PoolMon to find a kernel-mode memory leak [54].

Outdated assumptions to avoid:

- The GFlags page states that pool tagging is permanently enabled on Windows, the
  "Enable pool tagging" check box on the Global Flags dialog is unavailable, and
  commands to enable or disable pool tagging fail [53]. The PoolMon requirements
  page still documents the older enable-and-reboot step [51]; treat that step as
  legacy and verify the tag list is populated rather than changing global flags.
- PoolMon is a WDK tool, not an inbox Windows tool, and its tag-to-component
  naming depends on pooltag.txt being present [50][51].
- A truncated display from an undersized console is a display limitation, not
  missing data [51].

## 13. Minifilter diagnostics

A minifilter driver is a file system filter that intercepts requests targeted at
a file system or another file system filter, and exposes callbacks for pre and
post processing of file I/O [55]. The Filter Manager (FltMgr.sys) is a
system-supplied kernel-mode driver that implements and exposes the functionality
common to file system filters; it is installed with Windows but becomes active
only when a minifilter driver is loaded, and it attaches to the file system stack
for a target volume [56].

Diagnostic assessment [55]:

- Minifilter diagnostic mode runs three I/O-intensive tasks: standard file system
  operations (moving, copying, deleting), loading an application while monitoring
  the I/O required for its dependencies, and booting the computer while
  monitoring I/O for boot and shutdown impact.
- The mode is a setting ("Enable Minifilter Diagnostic Mode") of the File
  Handling, Internet Explorer Startup Performance, and Boot Performance (Fast
  Startup) assessments; it is disabled by default for those three, and the same
  three are also available with diagnostics enabled by default as
  "Minifilter Diagnostic: File Handling", "Minifilter Diagnostic: Internet
  Explorer", and "Minifilter Diagnostic: Boot Performance (Fast Startup)".
- Results can be analyzed in the Windows Assessment Console, Windows Assessment
  Services - Client (Windows ASC), or WPA; all three drill down to minifilter
  and callback level.
- Published metrics: Longest Delay (longest delay in the trace for major I/O
  operations such as Create, Control, Cleanup, Information, Read, Write, and
  Acquire lock), Minifilter Delay, Average Call Length, and Minifilter Callbacks
  (call counts by callback type).
- The ETL artifacts produced by the three assessments are named FileOrg.etl,
  IELaunch_Warm_1 through IELaunch_Warm_3, IELaunch_Cold_1, and a set of
  FastStartup_Analysis-* files for the boot assessment.

Ordering model [56][57]:

- Minifilters attach in a defined order; the operating system determines the
  order by load order groups and altitudes, and the attachment at a particular
  altitude on a particular volume is an instance [56].
- A filter's altitude is an infinite-precision string interpreted as a decimal
  number; a filter with a low numerical altitude loads below one with a higher
  numerical altitude [57].
- System-defined load order groups have documented altitude ranges, for example
  FSFilter Anti-Virus 320000-329999, FSFilter Activity Monitor 360000-389999,
  FSFilter Continuous Backup 280000-289999, FSFilter Replication 300000-309999,
  FSFilter Undelete 340000-349999, FSFilter Top 400000-409999, and the legacy
  Filter group 420000-429999 [57].
- FltMgr calls preoperation callbacks in altitude order from highest to lowest
  and postoperation callbacks in reverse [56].

Outdated assumptions to avoid:

- Identify filter ordering by altitude and load order group, not by vendor or
  product name; the altitude is the ordering key and must be unique per
  filter [57].
- Minifilter diagnostics is an assessment-platform feature, not a WPR profile; it
  is one of the three listed assessments with the diagnostic mode enabled [55].
- A high Minifilter Callbacks count is documented as informational with no
  remediation step, since it depends on what is installed; it is not itself a
  finding of poor performance [55].

## 14. Microsoft Defender performance analyzer

The performance analyzer for Microsoft Defender Antivirus is a PowerShell
command-line tool that helps determine which files, file extensions, and
processes might cause performance issues on an endpoint during antivirus scans;
the gathered information is intended to assess performance issues before
remediation actions are applied [58]. Performance events of the type
Microsoft-Antimalware-Engine are recorded through the analyzer [58]. Report
dimensions documented on the page include top paths, top files, top processes,
and top file extensions that impact scan time, plus combinations such as top
files per extension, top paths per extension, top processes per path, top scans
per file, and top scans per file per process [58].

Version and platform requirements [58]:

- Platform version 4.18.2108.7 or later.
- PowerShell 5.1, PowerShell ISE, or remote PowerShell (4.18.2201.10 or later),
  and PowerShell 7.x (4.18.2201.10 or later).
- On Windows Server 2012 R2, the Windows ADK (which contains the Windows
  Performance Toolkit) is required.
- Supported operating systems: Windows 10, Windows 11, Windows Server 2016 and
  later, and Windows Server 2012 R2 when onboarded with the modern unified
  solution for Windows Server 2016 and 2012 R2.

Verified workflow [58]:

  New-MpPerformanceRecording -RecordTo <recording.etl>     start the recording
  (reproduce the issue, then press ENTER to stop and save, or Ctrl+C to cancel)
  Get-MpPerformanceReport -Path <recording.etl> -TopFiles 3 -TopScansPerFile 10
  (Get-MpPerformanceReport -Path <recording.etl> -Topscans 1000).TopScans | ConvertTo-Json -Depth 1
  (-Raw is recommended for machine-readable output)

References for parameters and output fields are the performance analyzer
reference [59], New-MpPerformanceRecording [60], and Get-MpPerformanceReport [61].

Outdated assumptions to avoid:

- Do not assume the analyzer runs everywhere: the platform version floor and the
  Windows Server 2012 R2 ADK requirement are explicit [58].
- The analyzer measures scan impact; the page does not present its output as
  justification for an exclusion, and tuning remains a separate, reviewable
  decision [58].
- Use -Raw for machine-readable output instead of parsing formatted text [58].

## 15. Cross-cutting notes for implementers

- Terminology: Microsoft now uses "recording" for WPR output and "trace" for the
  analyzer input, "counterset" alongside "performance object" for counters, and
  "minifilter" (with Filter Manager, FltMgr) rather than "filter driver" for the
  supported file system filter model [2][19][56].
- Provider naming: WHEA hardware error events come from
  Microsoft-Windows-WHEA-Logger, and Defender performance analysis depends on
  Microsoft-Antimalware-Engine events [41][58].
- Counter semantics: counter paths, instances, and values are the portable
  vocabulary; a collector should record the counter path, the interval, and the
  log format rather than a display label [19][27].
- Collection boundaries: performance counters are not designed for sub-second
  sampling, on/off transitions always write files, and WPR file mode is
  unbounded unless the profile or the caller bounds it [4][10][19].
- Reporting boundaries: local dumps and ETLs are independently configurable and
  may contain sensitive data; the WER page notes that triage dumps only attempt
  to remove sensitive information [37][49].

## 16. How these URLs were verified

Method, applied on 2026-09-15:

1. Candidate URLs were discovered through the Microsoft Learn search API
   (https://learn.microsoft.com/api/search) and through links inside pages that
   were read, so that section-level pages are reached from a Microsoft page
   rather than guessed.
2. Every URL in this document was fetched over HTTPS with a browser user agent
   and a redirect-following client; only URLs that returned HTTP 200 are listed.
   Guessed paths that returned 404 were discarded rather than rewritten into
   plausible-looking URLs (for example, /windows-hardware/test/wpt/wpaexporter
   and /windows-hardware/test/wpt/onoff-transition are not real; the real pages
   are /windows-hardware/test/wpt/exporter and
   /windows-hardware/test/wpt/recording-onoff-transitions) [5][10].
3. Claims are limited to what the fetched page text states; where a page was
   consulted only as a pointer (for example the WER settings reference [38], the
   Performance Monitor troubleshooting page [29], and the WHEA hardware error
   events index [42]), it is linked without paraphrasing its contents.

To repeat the check, fetch each URL in the Sources block below and require an
HTTP 200:

  curl -sS -o /dev/null -L -w "%{http_code} %{url_effective}\n" <url>

Sources whose pages carry a "Last updated" date should be re-read when that date
changes; the pages used here were last updated between 2019 and 2026.

## Sources

[1] https://learn.microsoft.com/en-us/windows-hardware/test/wpt - Windows Performance Toolkit (WPT) overview
[2] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-recorder - Windows Performance Recorder (WPR)
[3] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-analyzer - Windows Performance Analyzer (WPA)
[4] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options - WPR command-line options
[5] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/exporter - Exporter (WPAExporter) reference
[6] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpa-quick-start-guide - WPA quick start guide
[7] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpa-step-by-step-guide - WPA step-by-step guide
[8] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/list-of-wpa-graphs - List of WPA graphs
[9] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/cpu-analysis - CPU analysis in WPA
[10] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/recording-onoff-transitions - Recording on/off transitions
[11] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-recorder-common-scenarios - WPR common scenarios
[12] https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-analyzer-common-scenarios - WPA common scenarios
[13] https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install - Download and install the Windows ADK
[14] https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing - About Event Tracing (ETW)
[15] https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal - Event Tracing portal
[16] https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session - Configuring and starting an ETW session
[17] https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-tools - Event tracing tools
[18] https://learn.microsoft.com/en-us/windows/win32/api/evntrace - Evntrace.h API reference
[19] https://learn.microsoft.com/en-us/windows/win32/perfctrs/about-performance-counters - About performance counters
[20] https://learn.microsoft.com/en-us/windows/win32/perfctrs/performance-counters-tools - Performance counter tools
[21] https://learn.microsoft.com/en-us/windows/win32/perfctrs/using-the-pdh-functions-to-consume-counter-data - Using PDH functions to consume counter data
[22] https://learn.microsoft.com/en-us/windows/win32/api/pdh - Pdh.h API reference
[23] https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/logman - logman
[24] https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/typeperf - typeperf
[25] https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/relog - relog
[26] https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil - wevtutil
[27] https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-performance-problems-in-windows - Troubleshoot performance problems in Windows (scenario guide)
[28] https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/performance-overview - Windows client performance troubleshooting documentation
[29] https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/troubleshoot-issues-performance-monitor - Troubleshooting issues with Performance Monitor
[30] https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-tss/introduction-to-troubleshootingscript-toolset-tss - Introduction to the TroubleShootingScript (TSS) toolset
[31] https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-tss/collect-data-analyze-troubleshoot-performance-scenarios - Collect data to analyze and troubleshoot performance scenarios (TSS)
[32] https://learn.microsoft.com/en-us/windows-hardware/test/assessments/onoff-transition-performance - On/Off Transition Performance assessments
[33] https://learn.microsoft.com/en-us/windows/win32/debug/wait-chain-traversal - Wait chain traversal
[34] https://learn.microsoft.com/en-us/windows/win32/debug/using-wct - Using WCT
[35] https://learn.microsoft.com/en-us/windows/win32/api/wct - Wct.h API reference
[36] https://learn.microsoft.com/en-us/windows/win32/wer/about-wer - About Windows Error Reporting
[37] https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps - Collecting user-mode dumps
[38] https://learn.microsoft.com/en-us/windows/win32/wer/wer-settings - WER settings
[39] https://learn.microsoft.com/en-us/windows-hardware/drivers/whea - WHEA design guide
[40] https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/windows-hardware-error-architecture-aware-user-mode-applications - WHEA-aware user-mode applications
[41] https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/querying-the-system-event-log-for-hardware-error-events - Querying the System event log for hardware error events
[42] https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/whea-hardware-error-events - WHEA hardware error events
[43] https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x124---whea-uncorrectable-error - Bug Check 0x124 WHEA_UNCORRECTABLE_ERROR
[44] https://learn.microsoft.com/en-us/powershell/module/storage/get-storagereliabilitycounter - Get-StorageReliabilityCounter
[45] https://learn.microsoft.com/en-us/powershell/module/storage/get-physicaldisk - Get-PhysicalDisk
[46] https://learn.microsoft.com/en-us/powershell/module/storage/get-disk - Get-Disk
[47] https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ni-ntddstor-ioctl_storage_predict_failure - IOCTL_STORAGE_PREDICT_FAILURE
[48] https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_predict_failure - STORAGE_PREDICT_FAILURE structure
[49] https://learn.microsoft.com/en-us/sysinternals/downloads/procdump - ProcDump
[50] https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/poolmon - PoolMon overview
[51] https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/poolmon-requirements - PoolMon requirements
[52] https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/poolmon-startup-command - PoolMon startup command
[53] https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags - Global Flags Editor (GFlags) overview
[54] https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/using-poolmon-to-find-a-kernel-mode-memory-leak - Use PoolMon to find a kernel-mode memory leak
[55] https://learn.microsoft.com/en-us/windows-hardware/test/assessments/minifilter-diagnostics - Minifilter Diagnostics
[56] https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts - Filter Manager concepts
[57] https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers - Load order groups and altitudes for minifilter drivers
[58] https://learn.microsoft.com/en-us/defender-endpoint/tune-performance-defender-antivirus - Performance analyzer for Microsoft Defender Antivirus
[59] https://learn.microsoft.com/en-us/defender-endpoint/performance-analyzer-reference - Microsoft Defender Antivirus performance analyzer reference
[60] https://learn.microsoft.com/en-us/powershell/module/defenderperformance/new-mpperformancerecording - New-MpPerformanceRecording
[61] https://learn.microsoft.com/en-us/powershell/module/defenderperformance/get-mpperformancereport - Get-MpPerformanceReport
