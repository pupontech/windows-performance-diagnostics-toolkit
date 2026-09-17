# Performance overhead and trace-size budgets

Status: enforced limits plus a measurement plan.

This document records no live Windows overhead measurement: the collector
overhead protocol in `docs/test-and-live-gap-audit.md` section 9 has not been
run on representative hardware, so every number below is either an enforced
limit in the current code or a deterministic synthetic input used by
`tests/test_overhead_and_budgets.py`. Collector overhead thresholds remain an
owner decision (plan item U7); until they are approved, every self-monitoring
record stays informational and no run is labelled PASS.

## 1. Enforced budgets

These are the limits the current code actually applies. Each line is checked by
`tests/test_overhead_and_budgets.py` against the production value, so changing
the code without changing this document fails the suite.

- Tier 1 sampling floor: 1 s
- Trace budget: 256 MB to 1024 MB
- Maximum capture duration: 120 s to 1800 s
- Post-stop ETL size cap: 512 MB
- Free-space headroom: max(256 MB, budget / 4)

Where each limit lives:

| Limit | Source of truth | Enforced by |
| --- | --- | --- |
| 1 s sampling floor | `config/diagnostic-rules.json` `samplingFloorSeconds`, mirrored in `config/diagnostic-presets.json` | `New-TelemetrySamplingPlan` clamps any smaller request; `Invoke-WpdTier1Collection` rejects a clamped cadence before it calls a counter provider |
| Per-preset trace budget and duration | the preset table in `src/Wpd.Etw.psm1` (`traceBudgetMB`, `maxDurationSeconds`) | `Get-WpdEtwPresetProfile`, `Get-WpdCaptureStrategy`, `Test-WpdEtwCapturePreflight` |
| Free space = budget + headroom | `Test-WpdEtwCapturePreflight` | refuses the capture as `insufficient-space` and reports the exact `DeficitBytes` |
| Post-stop ETL size | `Get-WpdEtwTraceValidation` (default cap 512 MB, or the `-MaxTraceSizeMB` the caller passes) | an oversized trace is removed from the case folder and its measured size stays in the validation record |
| Unbounded file mode | `Get-WpdEtwPresetProfile -AllowFileMode`, `Get-WpdCaptureStrategy` | refused unless the caller explicitly accepts an unbounded recording; a Flight Recorder refuses it outright |

Two rules make the budget honest:

1. A requested duration above the preset maximum is refused before anything
   starts, so an over-long capture cannot begin and be truncated later.
2. A free-space value that cannot be measured is `unavailable`, never a pass.
   The preflight does not assume room, and it does not guess a volume from the
   current working directory.

The per-preset numbers behind that 256 MB to 1024 MB range (memory mode, with
`expectedDurationSeconds` between 60 s and 900 s) are the module's own preset
contract. `config/diagnostic-presets.json` separately declares a case-level
`traceSizeBudget` between 2048 MiB and 8192 MiB, with file mode for
`boot-slowdown` and `intermittent`. That document is validated by
`tests/test_rules_presets.py`, but no module in `src/` reads it yet, so the
number enforced today is the module table above. Wiring the case-level budget
into the preflight is entry-point integration work, not a measurement result.

## 2. Measurable on Linux

A non-Windows host cannot query a Windows counter, start `wpr.exe` or measure a
volume, but it can exercise every policy seam with injected inputs. The suite
does exactly that, with deterministic synthetic timing instead of sleeping:

- Cadence validation: every Tier 1 family rejects a sub-second interval and the
  provider seam records zero calls, so a rejected cadence cannot sample.
- Pacing: with an injected clock and an injected sleep seam the loop requests
  exactly the floored interval, never anything shorter, and a rejected request
  sleeps zero times.
- Static inventory is collected once per run: the second Tier 0 call for the
  same run key is served from the collector cache without a provider call, a
  different privacy level gets its own projection, `-Refresh` re-queries, and
  the inventory module's own session cache is sticky and returns copies.
- Recorder bound: every canonical preset resolves to a bounded memory-mode
  recording with a positive budget and duration; the Flight Recorder refuses
  file mode; a file-mode strategy is refused before any command is built.
- Preflight arithmetic: budget plus headroom, a real deficit, the exact byte
  boundary that passes, an over-long duration, and an unmeasured volume that
  stays `unavailable`.
- Post-stop size policy: kept, empty, removed-because-oversized and
  not-produced outcomes, including the Tier 2 sequence that carries the limit
  through to the produced artifact.
- Gap and loss reporting: a skipped sample interval appears as a gap with its
  real elapsed and missing seconds and the series is not interpolated; invalid
  timestamps and values are counted as dropped; ETW event loss parsed from the
  documented `wpr -status` text is reported as measured, and an absent
  dropped-event line stays unknown instead of becoming zero.
- Self-monitoring shape: duration, CPU time and working set are recorded when
  measured, stay `unavailable` when they are not, and the portfolio report sums
  only what was measured.

What a Linux run cannot tell you: the cost of a real counter query, the cost of
a real event-log read, or anything about the timing of a real capture. Those
values are injected in the tests precisely so that the assertions stay
deterministic.

## 3. Requires Windows

- Real Tier 1 counter cost: Perflib query latency, the Process V2 vs
  PID+StartTime identity cost, and the effect of reading another user session's
  counters (which needs elevation).
- Real trace behaviour: `wpr.exe -profiles` availability, memory-mode buffer
  behaviour, actual ETL bytes for the requested duration, and WPR's own
  dropped-buffer counts under load.
- Real free space on the target volume (`System.IO.DriveInfo`), including a
  volume that is too small or is on a different drive than the case folder.
- Windows-only context collectors: event-log reads, storage reliability,
  filter-driver enumeration, Defender and Search indexing probes, power scheme
  reads, minidump and boot/WinRE collection, and the optional escalation tools.
- ETW event loss that only a real recording produces, and the collector's own
  CPU time and working set while a real workload runs.
- The collection itself: file-system writes into the case folder, `wpr.exe`
  child process cost, temp file growth, and cleanup.

The procedure for the Windows side is already written: freeze the image, power
plan, CPU count, Defender state, output path and workload; run at least three
baseline and three collector repetitions at the 1 s cadence for comparability;
record collector PID and WPR child PID, process CPU time, private bytes and
working set, read and write bytes, output bytes, ETL bytes, sample count,
skipped samples, collection errors and WPR status; set the pass/fail numbers
before collecting results. See `docs/test-and-live-gap-audit.md` section 9 and
gate O13.

## 4. Approximate target budgets

These are planning targets, not measurements. They are stated in the units the
code enforces so a future measurement can be compared against them.

- Tier 1 sampling: one query per family per second. A window of N seconds
  produces `floor(N / 1) + 1` expected samples, so a 60 s window expects 61
  samples per family and a 900 s window expects 901.
- Tier 1 coverage: any shortfall is reported as a gap and downgrades coverage
  to `partial`; the suite treats "3 expected, 3 observed, 1 gap" as partial.
- Tier 2 trace: 256 MB to 1024 MB per recording in memory mode. Before the
  recording starts, the target volume must have that budget plus
  `max(256 MB, budget / 4)` of free space, and the post-stop ETL check has the
  last word on size.
- Case folder: the sum of the traces requested in the run plus reports and
  logs. Only one recording is active at a time (one instance name), so the
  peak is one trace plus headroom, not the sum of the preset budgets.
- Collector self-monitoring: no CPU, memory or wall-time threshold is defined.
  A measured collector is reported with its duration, CPU seconds and working
  set; an unmeasured one is reported `unavailable`, never as zero overhead.

Until thresholds are approved, "low overhead" is a claim this toolkit does not
make.

## 5. Known gaps in the current reporting

- Tier 2 capture warnings are not propagated to the collector envelope: the
  envelope carries the trace-validation warnings and the capture errors, while
  a capture-level warning such as "a recording is still in progress" is
  reported on the capture record and as the reason `recording-still-running`.
  The state is not hidden, but the warning text lives on the capture record.
- The post-stop size cap defaults to 512 MB when a caller omits
  `-MaxTraceSizeMB`. The Tier 2 collector passes the parameter through, so a
  caller that does not supply the preset budget silently gets the default cap
  rather than that preset's budget.
- The process probe reads the collector's CPU time and working set but not its
  own duration, which is measured by the caller's stopwatch. A probe-only
  record is therefore `partial`, not `complete`.
- The case-level `traceSizeBudget` in `config/diagnostic-presets.json` is
  declared and validated but not consumed by `src/` yet (see section 1).

## 6. Where the checks live

| Requirement | Test |
| --- | --- |
| Declared 1 s floor in both configs | `test_the_declared_sampling_floor_is_one_second_in_both_configs` |
| Sub-second requests clamped, absent requests unavailable | `test_the_sampling_plan_clamps_every_sub_second_request_to_the_floor` |
| Every Tier 1 family rejects a sub-second cadence without sampling | `test_every_tier_one_family_rejects_a_sub_second_interval_without_sampling` |
| Sampling paces the floored interval and never sleeps sub-second | `test_tier_one_sampling_paces_the_floored_interval_and_never_sleeps_sub_second` |
| Tier 0 collected once per run and cached | `test_static_inventory_is_collected_once_per_run_and_served_from_cache` |
| Circular recorder hard bound, file mode opt-in only | `test_the_circular_recorder_is_hard_bounded_for_every_preset` |
| Free-space preflight and unmeasured space | `test_the_wpr_preflight_refuses_insufficient_space_and_never_assumes_room` |
| Duration and trace-size limits enforced | `test_the_capture_duration_and_trace_size_limits_are_enforced` |
| Sample gaps, skips and dropped samples reported | `test_sample_gaps_and_skips_are_reported_and_never_smoothed` |
| ETW loss reported, foreign recording never cancelled | `test_etw_loss_is_reported_and_a_foreign_recording_is_never_cancelled` |
| Self-monitoring emits CPU, memory and duration | `test_self_monitoring_emits_collector_cpu_memory_and_duration` |
| This document separates Linux from Windows work | `test_the_overhead_document_is_ascii_and_separates_linux_from_windows_work` |
| This document's budget lines match the code | `test_the_overhead_document_budget_lines_match_the_enforced_preset_policy` |

Run them with:

    python -m pytest tests/test_overhead_and_budgets.py -q

The suite imports the real modules and injects every provider, clock, sleep,
runner and free-space value, so it passes on a host without Windows PowerShell
or `wpr.exe`, and it fails if a budget is loosened in the code without the
documented value changing with it.
