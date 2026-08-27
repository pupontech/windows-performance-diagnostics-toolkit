# WPA Analysis Guide for Captured ETL

How to open the `wpr-trace.etl` produced by the Windows Performance Diagnostics
Toolkit in Windows Performance Analyzer (WPA), which tables to read, how to
correlate the trace with the companion `performance-samples.csv` and
`system-events-last-24-hours.json` artifacts, and the evidence-first rules that
keep you from mistaking correlation for causation.

This document links ONLY to official Microsoft documentation under
`learn.microsoft.com/windows-hardware/test/wpt`. No third-party blogs, no forums.

Every link below is a Microsoft Learn page:

  Windows Performance Toolkit (overview)
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/
  Windows Performance Analyzer (WPA)
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-analyzer
  WPA Quick Start Guide
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpa-quick-start-guide
  WPA User Interface / Graph Explorer
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/graph-explorer
  WPA Analysis Tab
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/analysis-tab
  List of WPA Graphs
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/list-of-wpa-graphs
  CPU Analysis
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/cpu-analysis
  Loading Symbols
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/loading-symbols
  Windows Performance Recorder (WPR)
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-recorder
  WPR Command-Line Options
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options
  Critical Path and Wait Analysis (CPU Usage (Precise) walkthrough)
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/optimizing-performance-and-responsiveness-exercise-3
  WPA Common Scenarios
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-analyzer-common-scenarios

## 1. What the toolkit produced

A single Collect run with `-CaptureWpr -ConfirmWprCapture` writes, into one
output folder, the following artifacts (see `docs/report-schema.md` for the full
contract):

  diagnostic-manifest.json              run metadata, hashes, WPR status block
  performance-samples.csv               1 Hz CPU/memory/disk samples over the window
  top-processes.json                    top 20 processes by CPU, snapshot at end
  system-events-last-24-hours.json      System event log, preceding 24 hours
  wpr-trace.etl                         ONLY when WPR capture ran (General profile)

The manifest's `wpr` block tells you the exact trace window:

  wpr.startedAtUtc     ISO-8601 UTC time the trace began
  wpr.completedAtUtc   ISO-8601 UTC time the trace ended
  wpr.status           completed | skipped-wpr-not-found |
                       skipped-elevation-required | failed
  wpr.etlFilePath      path to the .etl on disk

If `wpr.status` is anything other than `completed`, there is NO `wpr-trace.etl`
to analyze. Do not open WPA looking for one. The CSV/JSON evidence still stands
on its own.

The toolkit captures with the built-in `General` profile in file mode:

  wpr.exe -start General -filemode
  wpr.exe -stop <etl path>

That is the only profile the toolkit uses today (schema enum: `"General"`).
The `General` profile is First Level Triage: CPU (sampled), Disk I/O, process
lifetimes, and reference set / memory working-set data. Treat it as a broad
overview capture, not a targeted profile for one subsystem.

## 2. Opening wpr-trace.etl in WPA

WPA is part of the Windows Performance Toolkit, which ships in the Windows ADK.
Install location is typically:

  C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\wpa.exe

Open the trace:

  1. Launch wpa.exe (elevation is NOT required to VIEW a trace).
  2. File > Open > Select wpr-trace.etl.
  3. WPA parses the ETL and populates Graph Explorer with the graphs that this
     particular trace contains. The General profile exposes Computation,
     Storage, and System Activity graphs.

If WPA shows a "symbols needed" prompt or blank stacks, load symbols once:

  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/loading-symbols

For the toolkit's General capture you do NOT need symbols to read the
summary-level tables (utilization by process). Symbols only matter when you
expand call stacks to function names. State this clearly so an analyst does not
block on symbol setup before doing anything useful.

Quick Start walkthrough (official, step by step):

  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpa-quick-start-guide

### UI orientation (ASCII)

After opening the trace, WPA presents this layout:

  +---------------------------------------------------------------+
  |  Title bar: wpr-trace.etl                                     |
  +---------------------------+-----------------------------------+
  |  Graph Explorer           |  Analysis Tab                     |
  |  (left rail)              |  (right pane)                     |
  |                           |                                   |
  |  System Activity          |   drag a graph thumbnail from     |
  |    Processes              |   Graph Explorer here to open     |
  |    Thread Lifetimes       |   its table.                      |
  |  Computation              |                                   |
  |    CPU Usage (Sampled)    |   Each table has a blue bar at    |
  |    CPU Usage (Precise)    |   the top: the timeline/zoom.     |
  |  Storage                  |   Drag the bar ends to zoom the   |
  |    Disk Usage             |   trace window.                   |
  |    File I/O               |                                   |
  +---------------------------+-----------------------------------+

Workflow:

  a. Find the graph you want in Graph Explorer (left).
  b. Drag its thumbnail onto the Analysis tab (right). WPA opens the table.
  c. Use the blue bar at the top of the table to zoom into the busy interval.
  d. Right-click a column header to add/remove/pivot columns.

The full graph catalog for this trace is here:

  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/list-of-wpa-graphs

## 3. Key tables

The task names three tables. Their official WPA names and how to reach them:

  Task name        | Official WPA graph / subtype            | Graph Explorer path
  -----------------|-----------------------------------------|-----------------------
  CPU Usage        | CPU Usage (Sampled) or (Precise)       | Computation
  Disk I/O         | Disk Usage / File I/O                   | Storage
  Process Lifetime | Processes > Lifetime by Process         | System Activity

### 3.1 CPU Usage

Two related tables:

  CPU Usage (Sampled)   -- profile-interval sampling; shows WHERE CPU time
                           went (by process, by stack). Good for "which process
                           burned CPU".
  CPU Usage (Precise)   -- context-switch based; shows WHY a thread waited and
                           what readied it. Good for "why was this slow".

Official reference and column meanings:

  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/cpu-analysis
  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/optimizing-performance-and-responsiveness-exercise-3

Useful `CPU Usage (Sampled)` presets (drag the thumbnail, then apply preset):

  Utilization by Process, Stack     -- totals per process, expandable to stacks
  Utilization by Process and Thread -- per-process, per-thread breakdown

Useful `CPU Usage (Precise)` columns (from the official exercise):

  % CPU Usage       percentage of total CPU over the visible window
  Count             number of context switches the row represents
  CPU Usage (ms)    CPU time of the new thread after the switch
  NewProcess        process that owns the thread switched IN
  NewThreadId       thread switched IN
  NewThreadStack    what the new thread was doing / blocked on
  Ready(s)          time spent in the Ready queue (preemption / starvation)
  ReadyingThreadId  thread that readied the new thread
  ReadyingProcess   process that owns the readying thread
  Waits(s)          time the thread waited on a resource

Read order for a slowness complaint:

  1. CPU Usage (Sampled) > Utilization by Process, Stack.
     The top rows are the highest aggregate CPU users. Note the process names.
  2. Cross-check those process names against top-processes.json (Section 4.2).
  3. If a specific action was slow, open CPU Usage (Precise) and follow
     Ready(s) / Waits(s): a big Ready(s) means the thread was starved, not
     compute-bound; a big Waits(s) points at a resource (I/O, lock, paging).

### 3.2 Disk I/O

Official graph list (Storage section):

  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/list-of-wpa-graphs

Relevant `Disk Usage` subtypes:

  Activity by IO Type, Process   -- reads/writes/flushes per process
  IO Time by Process, IO Type    -- time the device spent on each process's I/O
  Service Time by Process, Path   -- device service time per file path + stack
  Size by Process, Path Name      -- bytes moved per process/path
  Throughput by Process, IO Type  -- MB/s per process

Also useful, `File I/O`:

  Size by File Name, Process, Stack   -- which files were read/written
  Duration by Process, Thread, Type   -- how long file ops took

Read order for a "disk-bound" complaint:

  1. Disk Usage > IO Time by Process, IO Type. The tallest bars are the
     processes spending the most device time.
  2. Expand the worst process: Service Time by Process, Path Name shows WHICH
     files. A few large/slow paths are the lead, not the whole process.
  3. If IO Time is low but the machine still feels slow, disk is NOT your
     bottleneck -- go back to CPU or to memory/reference-set tables.

### 3.3 Process Lifetime

Official name in WPA: `Processes > Lifetime by Process` (the task calls this
"Process Lifetime"). Catalog entry:

  https://learn.microsoft.com/en-us/windows-hardware/test/wpt/list-of-wpa-graphs

What it shows: each process's start and exit time across the trace window, drawn
as horizontal bars on a timeline. Related: `Thread Lifetimes > By Process,
Thread` for per-thread lifetimes, and `Transient Process Tree` for spawn
relationships.

Read order:

  1. Open Processes > Lifetime by Process. Each bar spans a process's life.
  2. Look for processes that START or EXIT inside your symptom window -- a
     process that spins up exactly when the slowdown begins is a candidate, not
     a conclusion (see Section 5).
  3. Correlate bar start/end times with the manifest trace window and with
     system-events JSON timestamps (Section 4.3).

## 4. Correlation with the companion artifacts

The ETL is one evidence stream. The CSV and JSON are independent streams
captured in the same run. They disagree usefully: the CSV is a coarse 1 Hz
poll, the ETL is a fine-grained ETW record, the JSON is the System event log.
Triangulate; do not pick one.

### 4.1 Trace window anchor

Everything lines up on UTC time. Establish the window first:

  manifest.wpr.startedAtUtc      -> trace start
  manifest.wpr.completedAtUtc    -> trace end
  performance-samples.csv TimestampUtc (first row)  -> ~ same start
  performance-samples.csv TimestampUtc (last row)   -> ~ same end

WPA's internal timeline is relative (seconds from trace start). To map a WPA
time `T` (seconds) to UTC:

  UTC = wpr.startedAtUtc + T seconds

Use this to say "the CPU spike at WPA t=12.3s is 12.3s after trace start", then
convert with the manifest timestamp for the written report.

### 4.2 performance-samples.csv

Columns (emitted by the collector, once per second):

  TimestampUtc
  AverageCpuLoadPercent
  AvailableMemoryMB
  TotalLogicalDiskFreeGB

How to use it with WPA:

  +-------------------+-----------------------------------------------+
  | Question          | Where to read it                              |
  +-------------------+-----------------------------------------------+
  | Broad trend over  | performance-samples.csv (1 Hz, whole window)  |
  | the whole window  |                                               |
  | Which process?    | WPA CPU Usage (Sampled) by Process            |
  | Memory pressure    | AvailableMemoryMB in CSV; WPA reference-set   |
  | Disk free falling | TotalLogicalDiskFreeGB in CSV                 |
  +-------------------+-----------------------------------------------+

The CSV answers "was the machine busy at all, and when". WPA answers "which
process/thread/file, and why". If the CSV shows AverageCpuLoadPercent flat at 5%
the entire window, no CPU table in WPA will reveal a CPU culprit -- the symptom
was not CPU. Lead with the CSV.

top-processes.json is a snapshot taken at the END of collection (Get-Process
sorted by CPU, top 20). Use it to name the persistent CPU hogs, then confirm
their share inside the trace window with CPU Usage (Sampled). A process can top
the snapshot yet be idle during the sampled window -- the JSON is a point in
time, the ETL is the interval.

### 4.3 system-events-last-24-hours.json

Columns (System event log, preceding 24 hours, up to MaxEventCount):

  TimeCreated
  Id
  LevelDisplayName      (e.g. Error, Warning, Information)
  ProviderName
  Message

How to use it with WPA:

  1. Filter the JSON to LevelDisplayName in (Error, Warning) inside the trace
     window [startedAtUtc, completedAtUtc].
  2. For each such event, convert its TimeCreated to WPA-relative time and look
     at the WPA tables at that instant: was CPU, disk, or a process transition
     happening then?
  3. Use Process Lifetime bars to see if a process exited (crashed) near an
     Error event -- WER/crash events often pair with a short process lifetime.

The 24-hour JSON is WIDER than the trace window. Only events whose TimeCreated
falls inside [startedAtUtc, completedAtUtc] are directly correlatable with the
ETL. Events outside that window are context, not correlation.

### 4.4 Correlation worked example (ASCII)

Symptom: "Explorer froze for ~3 seconds around 14:02:11 UTC."

  manifest.wpr.startedAtUtc = 14:02:00 UTC
  manifest.wpr.completedAtUtc = 14:02:30 UTC

  CSV (1 Hz):
    Time(UTC)   CPU%   AvailMemMB
    14:02:10    41      ...
    14:02:11    97      ...   <- spike
    14:02:12    88
    14:02:13    52

  WPA CPU Usage (Precise) at t = 11s (14:02:11 UTC):
    NewProcess = SearchIndexer (high Ready(s) -> starved Explorer)
    Waits(s) on Explorer thread = 2.9s

  JSON system-events in window:
    14:02:11  Warning  Microsoft-Windows-Search  "indexing throttle"

  Conclusion (evidence-first): At 14:02:11 the CPU spike coincides with
  SearchIndexer saturating the CPU (Precise shows Explorer starved via Ready(s)),
  and a Search Warning is logged at the same second. Three independent streams
  agree on timing and actor. This is a supported correlation -- but see Section 5
  before calling SearchIndexer "the cause".

## 5. Evidence-first causality rules

The toolkit's safety contract (README.md, rule 6) is explicit: correlation is
not causation. Apply these rules every time you write a finding.

  1. SEPARATE layers. A finding has four allowed states, stated explicitly:
       Observation   -- "X happened" (a measured fact from one stream)
       Correlation   -- "X and Y co-occur in time" (two streams align)
       Hypothesis    -- "X may cause Y because <mechanism>" (a testable claim)
       Conclusion    -- "X caused Y" (requires corroboration, not just timing)
     Never write a Conclusion from a single co-occurrence.

  2. TIMING is necessary, not sufficient. Two events at the same second can be
     coincident without one causing the other. Require a mechanism: WHICH WPA
     column links them? (Ready(s) starvation, Waits(s) on a resource, a process
     lifetime ending, an IO Time spike on the same path.) No mechanism = hypothesis.

  3. ONE stream is not proof. A CSV spike alone is an observation. An ETL spike
     alone is an observation. Agree them across at least two independent streams
     (CSV + ETL, or ETL + JSON) before promoting to correlation, and require a
     mechanism before promoting to hypothesis.

  4. DIRECTION matters. "Process P started, THEN slowdown began" permits P as a
     cause. "Slowdown began, THEN P started" does not -- P may be a symptom
     (the machine spawned P in response). Check Process Lifetime start times
     against the symptom onset from the CSV, not the other way around.

  5. ALTERNATIVE explanations first. Before naming a cause, list at least one
     other process/resource that could produce the same signature. If CPU Usage
     (Sampled) names process A but CPU Usage (Precise) shows A was READY-starved
     by B, the lead is B, not A. The sampled view misleads on its own.

  6. BOUNDS of the capture. The General profile is First Level Triage, not a
     targeted profile. Absence of evidence in this trace is NOT evidence of
     absence -- a missing table means the profile did not record that detail, or
     the symptom fell outside the 30 s window. Say "not captured", never "did not
     happen".

  7. NO repair from correlation. A supported correlation may justify a
     consent-gated, approval-gated remedy later (README.md phases 4-5). It never
     justifies silent remediation. The toolkit does not remediate; neither does
     this analysis.

Finding template (use for every written result):

  Observation : <fact from one stream, with timestamp + source file>
  Correlation : <second stream aligning, with timestamp>
  Mechanism   : <which WPA column/table links them, or "none identified">
  Hypothesis  : <X may cause Y> | Status: supported / unconfirmed
  Alternatives: <other actors that fit the same signature>
  Action      : none (analysis only) | escalate for approval-gated remedy

## 6. Common mistakes

  Mistake                                  | Fix
  -----------------------------------------|----------------------------------
  Opening WPA when wpr.status != completed  | No ETL exists; use CSV/JSON only.
  Treating top-processes.json as interval  | It is an end-of-run snapshot;
                                           | confirm in CPU Usage (Sampled).
  Calling a same-second event "the cause"  | Require a mechanism (Section 5.2).
  Reading only CPU Usage (Sampled)         | Sampled hides Ready(s) starvation;
                                           | check CPU Usage (Precise).
  Assuming a flat CSV means "healthy"       | CSV is 1 Hz and coarse; an ETL
                                           | spike can sit between samples.
  Using events older than the trace window | Only JSON events inside
                                           | [startedAtUtc, completedAtUtc] correlate.
  Blocking on symbols before any analysis  | Not needed for by-process tables.

## 7. References (official Microsoft only)

  Windows Performance Toolkit
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/
  Windows Performance Analyzer
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-analyzer
  WPA Quick Start Guide
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpa-quick-start-guide
  Graph Explorer
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/graph-explorer
  Analysis Tab
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/analysis-tab
  List of WPA Graphs
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/list-of-wpa-graphs
  CPU Analysis
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/cpu-analysis
  Loading Symbols
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/loading-symbols
  Windows Performance Recorder
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-recorder
  WPR Command-Line Options
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options
  Critical Path and Wait Analysis
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/optimizing-performance-and-responsiveness-exercise-3
  WPA Common Scenarios
    https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-analyzer-common-scenarios

Companion project docs:

  docs/report-schema.md            artifact contract + wpr object fields
  docs/official-microsoft-source-map.md  capability -> safety map
  README.md                        safety contract (rule 6: correlation != causation)
