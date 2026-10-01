# Test and Live Gap Audit

Status: audit-only. This document records what the current tests and workflows
actually prove, what they do not prove, and a deterministic path to close the
gaps. It does not claim that a Linux run is a Windows client validation.

The repository currently has 34 documented WPD IDs in
`docs/windows-live-test-matrix.md:27-60`, while the requested fixture plan has
30 rows. The proposed matrix below normalizes the 34 IDs into 30 fixture rows by
combining tests that are one user-facing flow (for example WPD-03/WPD-04 and
WPD-33/WPD-34). No documented ID is discarded.

## 1. Evidence snapshot and preservation of current WIP

Snapshot facts:

- Branch: `feat/crash-servicing-findings`; HEAD at audit start was
  `678e47d ci: pin release flow to v1.0.0 (#10)`.
- The working tree already contained 12 staged paths, 2 paths with additional
  unstaged edits, and 3 untracked research/audit documents. This audit must not
  reset, stash, clean, checkout, commit, or overwrite that work.
- Staged paths were: `.github/workflows/ci.yml`, `CHANGELOG.md`, `README.md`,
  `START-HERE.bat`, `docs/ROADMAP.md`,
  `docs/minidump-boot-failure-collection.md`, `docs/report-schema.md`,
  `docs/windows-live-test-matrix.md`, `schema/diagnostic-report.schema.json`,
  `src/Invoke-WindowsPerformanceDiagnostics.ps1`,
  `tests/test_crash_servicing_findings.py`, and
  `tests/test_plan_mode.py`.
- The source and crash/servicing test paths were both staged and modified in
  the worktree: the staged diff was `src/...ps1 +793/-44` and
  `tests/test_crash_servicing_findings.py +492`; the additional unstaged diff
  was `src/...ps1 +116/-8` and
  `tests/test_crash_servicing_findings.py +241/-4`.
- The untracked paths observed before this document was written were
  `docs/audit-v1-to-spec.md`, `docs/authoritative-sources-core.md`, and
  `docs/authoritative-sources-platform.md`. They are preserved.
- The crash/servicing file was a moving target during the audit. Counts and line
  references below describe the working-tree version read for this document,
  not the older staged version. Re-read it before editing that path.
- WPD-09 creates a random password inside the Windows workflow for one run. No
  password, token, credential, or connection string is copied into this audit.

The only repository artifact written by this task is this file:
`docs/test-and-live-gap-audit.md`.

Commands actually run for this audit:

- `python3 -m pytest tests/ -q` at `2026-09-15T15:11:54+02:00`: **148 passed in
  102.31 seconds**.
- The test suite exercises the working-tree versions of all four Python test
  files. It is not evidence that Windows PowerShell 5.1 ran those Python tests.
- Source and workflow contents were read in full, including the complete
  current `src/Invoke-WindowsPerformanceDiagnostics.ps1`, both workflow files,
  all four Python test files, and all three `.bat` launchers. The source was
  changing concurrently, so symbol names are more stable anchors than line
  numbers; line numbers are the read-time references.

## 2. Exact current Python test inventory

There are four Python test files and 148 collected tests in the working tree:

| File | Lines | Tests | Execution model | Main specification areas |
| --- | ---: | ---: | --- | --- |
| `tests/test_plan_mode.py` | 1-2824 | 117 | Real `pwsh -File` runs for Plan, Verify, and refusal paths; source and launcher assertions; selected PowerShell helper harnesses | modes, consent, package/remote safety, network/crash helpers, schemas, Verify, findings/report, telemetry math, tail wiring |
| `tests/test_incident_capture.py` | 1-645 | 11 | AST extracts the real function bodies and runs them under `pwsh`; one Plan and one schema test also invoke the real script/schema | incident window, marker retention, WPR coverage contract, GPU/UDP/storage mapping, report and schema |
| `tests/test_crash_servicing_findings.py` | 1-729 | 16 | AST extracts real crash/servicing/findings functions and drives synthetic files and objects under `pwsh` | bounded servicing analysis, crash correlation, crash/servicing findings, report and schema |
| `tests/test_wpr_bounded_capture.py` | 1-176 | 4 | AST extracts `Start-WprBoundedCaptureJob` and supplies a fake `wpr.exe` shell program | documented WPR arguments, caller stop, size cap and cleanup |

The suite has no `*.Tests.ps1` files and no Pester invocation. `pytest` is the
only test runner. The common helpers make this important distinction explicit:
`test_plan_mode.py:13-20` calls `pwsh -File`, while the incident and crash files'
`run_pwsh` helpers parse the production script's AST, extract selected function
text, and execute it with `Invoke-Expression` (`test_incident_capture.py:33-57`,
`test_crash_servicing_findings.py:25-50`). The WPR helper does the same at
`test_wpr_bounded_capture.py:23-69`.

### 2.1 `test_plan_mode.py` - exact 117-test inventory

The following list preserves every current test name. The text after each name
states the assertion focus, not an assumption that the complete Windows Collect
path ran.

Mode, consent, progress and WPR planning (`:58-209`):

- `test_plan_mode_writes_a_local_only_read_only_manifest`: real Plan invocation
  writes a BOM-free Plan manifest with the read-only safety flags and no repair
  actions.
- `test_collect_mode_refuses_to_collect_without_explicit_consent`: Collect
  without local consent fails before creating the output directory.
- `test_collect_mode_refuses_non_windows_hosts_before_any_collection`: a
  confirmed Collect on a non-Windows host fails at the platform gate and leaves
  no output directory.
- `test_collect_progress_uses_a_wall_clock_deadline_and_launchers_explain_extra_stages`:
  source and launcher text contain stopwatch/progress/shared-window messaging
  and avoid the old unbounded sleep wording.
- `test_plan_mode_with_wpr_lists_capture_action_and_scope`: Plan advertises
  GeneralProfile, auto-sized duration, memory logging, cap, and concurrent WPR.
- `test_plan_mode_without_wpr_has_no_wpr_section`: ordinary Plan does not
  advertise WPR.
- `test_wpr_capture_refuses_without_wpr_consent`: WPR has a separate consent
  gate and refusal has no side effects.
- `test_collect_with_wpr_consent_still_refuses_non_windows_hosts`: both local
  and WPR consent do not bypass the non-Windows refusal.

Release metadata, encoding and optional capture plans/gates (`:211-478`):

- `test_release_flow_uses_the_real_workflow_token_for_asset_probes`: release
  workflow source uses the workflow token expression rather than a fake token.
- `test_project_security_automation_covers_action_updates_and_code_scanning`:
  Dependabot/security workflow configuration contains the expected automation.
- `test_runtime_and_automation_files_follow_the_encoding_rule`: runtime and
  automation files are ASCII/BOM-free where the house rule requires it.
- `test_plan_mode_with_defender_lists_capture_action_and_scope`: Defender Plan
  has its action and duration/consent scope.
- `test_plan_mode_without_defender_has_no_defender_section`: Defender is absent
  from a plain Plan.
- `test_plan_mode_with_wpr_and_defender_lists_both_capture_actions`: WPR and
  Defender requests are both represented without collapsing their gates.
- `test_defender_capture_refuses_without_defender_consent`: Defender capture
  refuses without its specific consent.
- `test_collect_with_defender_consent_still_refuses_non_windows_hosts`: a
  Defender-consented Collect still stops before collection off Windows.
- `test_plan_mode_with_minidumps_lists_action_and_scope`: minidump Plan records
  the bounded source and max-total policy.
- `test_plan_mode_without_minidumps_has_no_section`: minidump scope is omitted
  when not requested.
- `test_minidump_collection_refuses_without_consent`: minidump capture has an
  explicit gate.
- `test_collect_with_minidump_consent_still_refuses_non_windows_hosts`: consent
  does not bypass the platform gate.
- `test_plan_mode_with_boot_failure_logs_lists_action_and_scope`: boot-failure
  Plan advertises bounded sources and servicing analysis.
- `test_plan_mode_without_boot_failure_logs_has_no_section`: boot-failure scope
  is omitted unless requested.
- `test_boot_failure_log_collection_refuses_without_consent`: boot-log capture
  has its own gate.
- `test_collect_with_boot_failure_consent_still_refuses_non_windows_hosts`:
  confirmed boot-log collection still refuses off Windows.

Package, remote and elevation helpers (`:496-739`):

- `test_plan_mode_with_zip_output_lists_action_and_scope`: Plan records local
  ZIP destination/name and manifest inclusion.
- `test_plan_mode_without_zip_output_has_no_package_section`: no package block
  appears when packaging was not requested.
- `test_new_case_package_zips_only_named_files`: package creation includes only
  the certified artifact names, not arbitrary sibling files.
- `test_plan_mode_with_remote_lists_action_and_remote_safety_block`: remote Plan
  records WinRM target/transport and changes only the local-only safety field.
- `test_plan_mode_without_remote_keeps_local_only_safety`: local runs retain the
  local-only safety block.
- `test_remote_collection_refuses_without_consent`: remote mode has a separate
  consent gate.
- `test_remote_collection_still_refuses_non_windows_hosts`: remote flags do not
  enable collection on a non-Windows host.
- `test_remote_helpers_fail_closed_for_safety_and_hash_verification`: helper
  functions reject unsafe paths/statuses and report hash verification failures.
- `test_remote_collection_source_uses_owned_staging_and_fail_closed_status`:
  source inspection checks unique staging, cleanup and failure status behavior.
- `test_invoke_consented_capture_skip_and_elevation_paths`: the consented
  capture helper has explicit skip/elevation branches; it does not prove the
  real Defender module or WPR binary.
- `test_winre_puller_bat_is_ascii_crlf_and_consent_safe`: WinRE launcher text,
  CRLF, read-only defaults and explicit boot-configuration warning are checked.

Packaging/version/schema/WPR checks (`:772-941`):

- `test_release_packaging_files_present`: release bundle inputs and hash assets
  exist.
- `test_bundle_rejects_same_version_from_non_tagged_head`: dirty/version/tag
  packaging protection refuses the wrong release source.
- `test_version_file_matches_script_fallback`: `VERSION` and the PowerShell
  fallback version agree.
- `test_report_schema_is_valid_json`: report schema parses as JSON.
- `test_run_diagnostics_bat_is_quote_safe_and_ci_safe`: basic launcher quoting,
  explicit flags, failure branch and CI-safe pause are checked statically.
- `test_run_diagnostics_bat_reports_collection_failures`: the launcher has a
  visible nonzero/no-manifest failure path.
- `test_wpr_capture_completed_requires_zero_stop_exit_code`: a successful WPR
  result requires a zero stop exit code rather than ETL existence alone.

Network and crash helper behavior (`:921-1233`):

- `test_plan_mode_lists_crash_analysis_action`: crash analysis is advertised in
  Plan.
- `test_plan_mode_lists_network_state_action_and_scope`: network subcollections
  and the explicit post-consent action are advertised.
- `test_network_keyword_matching_is_pure_and_strict_mode_safe`: security/network
  keyword matching returns deterministic values under StrictMode.
- `test_network_state_collection_is_resilient_and_structured`: network section
  failures are isolated and structured instead of aborting the full result.
- `test_bounded_dns_resolution_returns_results_and_times_out_without_blocking`:
  bounded DNS returns results and a timeout path does not block indefinitely.
- `test_event_reader_reads_newest_records_and_stops_at_the_requested_limit`:
  newest event ordering and maximum record count are enforced.
- `test_disk_interval_baseline_is_reset_after_an_unavailable_raw_poll`: an
  unavailable raw-disk poll resets the pair baseline and does not fabricate a
  delta across the gap.
- `test_crash_analysis_decodes_bugchecks_and_flags_unexplained_shutdowns`:
  BugCheck codes and unmatched Kernel-Power 41 events are decoded from synthetic
  records.
- `test_crash_analysis_recognizes_real_windows_bugcheck_provider`: the WER
  SystemErrorReporting provider form is accepted.
- `test_artifact_metadata_hashes_only_whitelisted_names`: artifact metadata
  includes only the named certified files.
- `test_emitted_plan_validates_against_schema`: a real Plan output validates
  against the published report schema.

Verification, launcher source and release documentation (`:1262-1490`):

- `test_start_here_bat_is_elevation_safe_and_quote_safe`: START-HERE contains
  expected menu/UAC/quoting/CI-safe patterns.
- `test_human_facing_release_metadata_matches_version`: README/changelog/release
  text uses the current version.
- `test_wpa_guide_matches_the_collector_wpr_profile`: the WPA guide names the
  selected WPR profile.
- `test_verify_mode_accepts_a_valid_collect_case_without_writing_it`: a minimal
  intact case returns verified without changing the case.
- `test_verify_mode_fails_on_a_tampered_artifact`: an artifact byte change is
  rejected with a mismatch.
- `test_verify_mode_requires_an_input_directory`: Verify rejects a missing input
  directory argument.
- `test_verify_mode_validates_the_recorded_case_package`: a recorded ZIP and
  package metadata are checked.
- `test_verify_mode_rejects_an_unexpected_case_package_entry`: an unexpected ZIP
  entry is refused.
- `test_verify_mode_rejects_traversal_without_reading_outside_the_case`: path
  traversal is refused without reading outside the case.
- `test_case_verification_schema_is_valid_json`: Verify schema JSON parses.

Symptom and preset recording (`:1504-1673`):

- `test_plan_mode_records_symptom_context_and_collection_window`: exact symptom
  text is preserved separately from the requested window.
- `test_plan_mode_without_symptom_has_no_symptom_block`: no symptom block is
  emitted without symptom input.
- `test_plan_mode_records_preset_parameters`: selected preset is recorded with
  its input parameters.
- `test_plan_mode_symptom_is_forwarded_to_remote_plan`: remote Plan preserves
  symptom context.
- `test_collect_mode_records_symptom_separately_from_collection_window`:
  Collect manifest separates reported context from capture timestamps.
- `test_symptom_context_preserves_backwards_compatibility`: legacy symptom
  shape remains accepted.
- `test_verify_mode_accepts_manifest_with_symptom_context`: Verify accepts the
  versioned symptom extension.
- `test_verify_mode_accepts_manifest_with_findings_artifact`: Verify accepts a
  case that includes findings output.

Telemetry helpers, null semantics and source-class checks (`:1679-1940`):

- `test_collect_manifest_includes_extended_telemetry_fields`: manifest source
  contains the incident/telemetry blocks.
- `test_performance_samples_csv_backward_compatibility`: legacy CSV columns and
  compatibility behavior remain valid.
- `test_plan_mode_reports_preset_in_manifest`: Plan records a preset even when
  symptom text is absent.
- `test_process_cpu_percentage_helper_returns_correct_values`: interval CPU
  arithmetic returns expected finite percentages.
- `test_cpu_percentage_requires_logical_processors`: CPU percentage is unknown
  when processor count is unavailable.
- `test_cpu_pid_reuse_detection`: PID plus start-time identity rejects reused
  PIDs.
- `test_disk_metrics_helper_returns_null_on_unavailable_cim`: missing formatted
  disk CIM returns null/coverage rather than zero.
- `test_memory_metrics_helper_returns_null_on_unavailable_cim`: missing memory
  CIM returns null/coverage.
- `test_volume_metrics_helper_returns_null_on_unavailable_cim`: missing volume
  CIM returns null/coverage.
- `test_disk_metrics_class_name_is_correct_in_source`: the documented formatted
  disk class name is used.
- `test_memory_metrics_class_name_is_correct_in_source`: the documented memory
  class name is used.
- `test_memory_metrics_includes_page_faults_distinction`: hard page-fault and
  paging fields are distinct.
- `test_memory_schema_includes_page_faults_per_sec`: schema includes the paging
  rate field.

Findings and offline report behavior (`:1946-2230`):

- `test_findings_engine_pure_function_cpu_pressure`: synthetic sustained CPU
  pressure produces the expected finding.
- `test_findings_engine_no_spike_only_finding`: an isolated spike does not
  become a sustained-pressure finding.
- `test_findings_engine_insufficient_samples`: too few samples become a
  coverage/insufficient-data result.
- `test_html_report_escapes_xss_payloads`: finding and symptom HTML is escaped.
- `test_html_report_is_offline_only_no_external_assets`: report has no scripts or
  external URLs/assets.
- `test_html_report_contains_no_health_score`: report does not invent a health
  score.
- `test_findings_json_no_health_score`: machine-readable findings also omit a
  health score.
- `test_plan_mode_does_not_produce_findings_or_report`: Plan creates only Plan
  output, not Collect artifacts.
- `test_verify_mode_accepts_findings_json_and_report_html`: Verify accepts the
  registered findings/report pair.
- `test_verify_fails_on_tampered_report_html`: report tampering is detected.
- `test_collect_mode_refuses_without_consent_even_with_symptom`: symptom input
  cannot bypass local consent.

Memory, disk and volume coverage (`:2251-2400`):

- `test_findings_engine_memory_pressure_from_fixture`: committed-memory pressure
  from a fixture yields a memory finding.
- `test_findings_engine_hard_page_fault_detection`: sustained hard faults yield
  the paging finding.
- `test_findings_engine_coverage_when_hard_faults_null`: null hard faults yield
  coverage uncertainty, not a healthy/zero result.
- `test_disk_telemetry_helper_handles_unsupported_counters`: unsupported disk
  counters are represented as unavailable.
- `test_memory_telemetry_helper_handles_unavailable_cim`: memory helper
  preserves unavailable status.
- `test_volume_telemetry_helper_handles_unavailable_cim`: volume helper
  preserves unavailable status.
- `test_unknown_telemetry_not_zero`: unknown measurements never become zero.

Production pairing/math, sustained windows and shared Collect tail (`:2413-2824`):

- `test_process_snapshot_pairing_uses_pid_and_start_time`: process snapshots
  pair by PID and start time, with reused/new/protected cases unknown.
- `test_disk_counter_deltas_raw_latency_throughput_queue`: raw disk counter
  deltas produce latency, throughput and queue values.
- `test_sustained_window_counts_finite_readings_and_nulls_break_streak`: nulls
  break a qualifying run and only finite readings count.
- `test_findings_cpu_sustained_streak_found_anywhere`: a sustained run is found
  wherever it occurs in the series, not only at the end.
- `test_findings_disk_series_sustained_and_single_read_ignored`: disk findings
  require a sustained interval and ignore one-off readings.
- `test_findings_coverage_warnings_for_missing_series`: missing series produce
  explicit coverage warnings.
- `test_cpu_interval_stopwatch_spans_the_end_enumeration`: CPU timing includes
  the end process enumeration in the denominator.
- `test_html_report_with_no_findings_reports_measured_clear_window`: a clear
  measured window is stated explicitly.
- `test_html_report_encodes_artifact_size_bytes`: artifact byte sizes are HTML
  encoded.
- `test_volume_percent_free_null_when_free_space_missing`: missing free-space
  data stays null.
- `test_volume_metrics_null_guard_production`: production volume null guards are
  present.
- `test_plan_mode_preset_without_symptom_is_recorded`: preset-only Plan keeps
  the preset block without inventing symptom text.
- `test_collection_errors_reference_is_live_for_tail_stages`: the mutable error
  accumulator carries late tail-stage failures into the manifest.
- `test_live_collect_tail_calls_shared_write_collection_outputs`: the real
  Collect tail calls the shared output writer.
- `test_collect_tail_shared_function_registers_evidence_and_verify_detects_tamper`:
  a fixture-driven shared tail writes/registers evidence and Verify rejects a
  tampered output.

What this file does not prove: a top-level successful Collect on Windows, real
CIM/PDH/EventLog/WPR data, an elevated Defender recording, a real minidump copy,
or a launcher invoked by a human double-click. Its explicit full-Collect tests
stop at consent/platform gates on this host, or extract only the shared tail.

### 2.2 `test_incident_capture.py` - exact 11-test inventory

All helper tests use the production function text through the AST harness. The
module docstring at `:1-17` records the field defects being protected.

- `test_hosts_entries_are_plain_strings_even_for_matchinfo_style_inputs` (`:61`):
  MatchInfo-like host lines flatten to two plain strings, `System.String` types,
  and JSON under 500 characters.
- `test_udp_endpoint_sample_groups_endpoints_by_owning_process` (`:101`):
  synthetic `netstat -ano` counts only UDP, groups by owner PID, sorts the
  highest count first, and includes a timestamp.
- `test_marker_retention_keeps_the_window_around_the_marked_incident` (`:165`):
  180 one-second samples retain the inclusive 60-second pre/30-second post
  window and report dropped counts; no-marker mode retains all samples.
- `test_capture_window_coverage_flags_a_trace_that_starts_after_the_counters`
  (`:210`): coverage distinguishes `covers-window`, late start, early stop,
  partial overlap and no trace.
- `test_incident_window_labels_keep_out_of_window_events_instead_of_dropping_them`
  (`:247`): all events remain, out-of-window events are labelled, and RawXml is
  preserved.
- `test_volume_mapping_names_the_backing_disk_and_the_pagefile_host` (`:277`):
  drive letters map to physical disks and only the pagefile host is marked.
- `test_gpu_counter_instance_paths_are_parsed_into_pid_engine_and_luid` (`:308`):
  GPU PDH instance paths yield PID, engine type and LUID without a GPU.
- `test_plan_mode_advertises_performance_capture_without_starting_a_trace`
  (`:331`): Plan describes one concurrent performance window and creates no
  collection artifact.
- `test_report_renders_every_finding_category_it_publishes` (`:378`): known and
  unknown finding categories, metrics and measured values all reach the offline
  report; a pressure report does not claim no pressure.
- `test_report_still_states_a_result_when_only_attribution_findings_exist`
  (`:467`): attribution-only output still states that no sustained pressure was
  detected.
- `test_schema_accepts_an_incident_capture_manifest` (`:494`): a synthetic 1.2
  incident manifest with telemetry, GPU, pagefile, storage, events and WPR
  blocks validates against the published schema.

### 2.3 `test_crash_servicing_findings.py` - exact current 16-test inventory

The current worktree version is `:1-729`; the staged version was older. These
are synthetic helper tests, not physical crash or boot-failure runs.

- `test_servicing_parser_deduplicates_cbs_and_hresult_signatures` (`:53`): CBS
  and HRESULT signatures deduplicate with counts/line ranges and raw line text
  is not copied into analysis.
- `test_servicing_file_analysis_scans_copied_logs_and_preserves_collection_shape`
  (`:88`): copied logs are scanned while non-copied logs remain
  `not-copied`.
- `test_servicing_file_analysis_rejects_reparse_point_logs` (`:138`): a symlinked
  copied-log path is refused instead of followed outside the case.
- `test_servicing_file_analysis_hard_bounds_a_growing_input_stream` (`:178`): a
  growing FIFO-like input is bounded by `MaxScanBytes` and marked truncated.
- `test_servicing_file_analysis_skips_a_file_over_the_scan_bound` (`:220`): an
  oversized file is not read and is marked `oversized`.
- `test_servicing_file_analysis_merges_signature_ranges_across_chunks` (`:250`):
  1000-line chunk boundaries preserve signature count and first/last line.
- `test_crash_analysis_correlates_dumps_and_deduplicates_live_kernel_signatures`
  (`:277`): nearby BugCheck correlation, unexplained shutdowns, old dumps and
  filename-only LiveKernel signatures are represented and deduplicated.
- `test_crash_analysis_rejects_bugcheck_correlation_after_lookback_end` (`:332`):
  a post-window dump does not borrow a nearby bugcheck code.
- `test_crash_analysis_prefers_source_time_over_stale_filename_date` (`:357`):
  an in-window source timestamp outranks a stale filename date.
- `test_findings_engine_publishes_crash_and_servicing_evidence` (`:382`): crash
  and recurring CBS data become crash-evidence/servicing-failure findings with
  source artifacts and counts.
- `test_findings_engine_ignores_missing_optional_crash_arrays` (`:440`): absent
  optional arrays do not become one-element findings.
- `test_findings_engine_reports_partial_servicing_log_coverage` (`:472`): one
  readable log plus one unavailable/oversized log yields a partial-coverage
  finding.
- `test_findings_engine_surfaces_failed_servicing_analysis` (`:508`): analyzer
  failure is distinct from normal no-log coverage and retains its error.
- `test_report_renders_crash_and_servicing_finding_metrics` (`:541`): crash and
  servicing categories, heading and metrics are visible in HTML.
- `test_collection_tail_writes_and_forwards_servicing_analysis` (`:574`): the
  shared tail writes/registers servicing analysis and forwards both evidence
  blocks into findings.
- `test_schema_accepts_extended_crash_and_servicing_analysis` (`:624`): extended
  crash and bounded servicing structures validate against the schema.

### 2.4 `test_wpr_bounded_capture.py` - exact current 4-test inventory

The fake executable writes only its arguments and a controlled zero-filled ETL;
it does not create a real ETW trace or provider payload (`:73-89`).

- `test_trace_stops_on_the_caller_signal_instead_of_its_full_window` (`:120`):
  a 0.3-second stop signal ends a nominal 30-second job well before the full
  window and keeps a small ETL.
- `test_trace_is_started_with_only_documented_wpr_arguments` (`:140`): exactly
  `-start GeneralProfile` and `-stop <etl>` are used; invented size/file-mode
  switches are absent.
- `test_oversized_trace_and_its_symbol_files_are_removed` (`:156`): a 24 MB fake
  ETL over an 8 MB cap and its `.NGenPdb` directory are removed while measured
  size is retained.
- `test_trace_within_the_cap_is_kept` (`:169`): an under-cap ETL remains on disk
  for later hashing.

## 3. Mapping tests to specification sections and identifying gaps

The section numbers below follow the 100-section specification referenced by the
existing repository audit (`docs/audit-v1-to-spec.md:14-15,345-383`). A test
name or schema fixture is evidence of a contract; it is not evidence that a
real Windows provider supplied the values.

| Spec area | Current automated evidence | Status and exact limitation |
| --- | --- | --- |
| 1-8: entry points, consent, read-only safety, process identity | Plan/refusal tests `test_plan_mode.py:58-209,2237`; PID/start-time tests `:1727,1795,2413`; launcher source checks `:741,854,1262` | PARTIAL: mode/refusal and helper identity are covered; no before/after system safety snapshot, no full standard-user basic collection, and no full PS 5.1 function runtime suite |
| 9-15: process/CPU sampling and workload behavior | CPU math/pairing tests `test_plan_mode.py:1727-1830,2413`; hosted 8-second workload `ci.yml:329-355` | PARTIAL: the hosted workload proves one finite interval CPU value, not short-lived process visibility, per-core/DPC/scheduler data, or collector overhead |
| 16-23: responsiveness, memory, pagefile, pool, leaks | Memory/pagefile/pool-shaped fixtures `test_plan_mode.py:1860-1997,2251-2387`; schema fixture `test_incident_capture.py:494-645` | PARTIAL: null semantics and some attribution shapes are covered; no UI hang, Wait Chain, handle/thread growth, real commit pressure, or pool-tag analysis |
| 24-30: storage, Defender, search, filesystem and reliability context | Raw disk math, volume mapping, Defender gate text and plan tests `test_plan_mode.py:258-478,2454,2679`; incident mapping `test_incident_capture.py:277` | PARTIAL: formulas and metadata are covered; no real storage reliability counters, Defender report parsing, filters, Search, SMART, TRIM or failure injection |
| 31-46: network, GPU, power, boot, WER/WHEA, drivers and symbols | Network/DNS/UDP/GPU helper tests `test_plan_mode.py:962-1128`, `test_incident_capture.py:101,308`; crash helper tests `test_plan_mode.py:1140-1175` and crash file | PARTIAL: synthetic parser and null paths only; no network retransmission counters, GPU workload/TDR values, power/thermal, WHEA providers, driver health or symbol validation |
| 47-53: WPR/repro/trace analysis | Four fake-WPR tests, WPR Plan and consent tests, hosted WPD-08/09/10 | PARTIAL: normal lifecycle/size/coverage contract is exercised; no `wpr -marker`, provider presence, ETW lost-event check, WPAExporter tables, sampled-vs-precise data, file-mode flight recorder or Ctrl-C recovery |
| 54-60: findings, evidence provenance, quality, baseline | Findings/report/coverage tests in `test_plan_mode.py:1946-2230,2507-2660`, incident report tests | PARTIAL: source artifact, metric, window and uncertainty fields are checked; no evidence index, severity/confidence model, collector-wide data-quality report, or incident-vs-baseline comparison |
| 61-63: presets and flight recorder | Plan records preset names/parameters at `test_plan_mode.py:1538,1710,2712`; source parameter list `src/...ps1:49-50` | MISLEADING/PARTIAL: current presets are metadata/forwarding only. Missing functional dispatch, the specified `general`, `memory-leak`, `network`, `gpu`, `ui-hang`, `ui-stutter`, `audio-glitch`, `power`, and `intermittent` behaviors, and all circular flight-recorder behavior |
| 64-70: sampling efficiency and event engine | Sustained-window/null tests, bounded event tests, incident event labelling | PARTIAL: a one-second floor and bounded event reads are tested; repeated full CIM scans, provider coverage, grouping/dedup and performance cost are not measured |
| 71-80: finding taxonomy, privacy and no-data behavior | Finding/report/schema tests, XSS/offline tests and null-as-unknown tests | PARTIAL: no-data-is-not-healthy and offline HTML are protected; most finding types, privacy modes, path/IP redaction and explicit confidence are absent |
| 83-87: collector framework, output tree and machine-readable report | Manifest/schema/Verify and shared-tail tests; CI checks selected artifacts | PARTIAL: outputs are hash-registered and Verify is read-only; no uniform per-collector status/duration/records/errors, coverage/data-quality artifact, evidence index or documented hierarchical case tree |
| 88: test framework | 148 Python tests across four files; `pytest` in CI | PARTIAL: no Pester and no full PowerShell 5.1 runtime test harness |
| 89: deterministic fixtures / 30 scenarios | Synthetic helper objects/files and one fake WPR executable | MISSING as a matrix: there is no fixture directory or one-to-one normalized 30-row test driver |
| 90: Windows VM tests | Hosted Windows 2022/2025 smoke jobs | PARTIAL: selected gates run; no complete scenario matrix, no provider-fixture run under both engines, and no client-only Defender/MOTW behavior |
| 91: trace validation | WPR fake lifecycle and `Test-CaptureWindowCoverage` tests | PARTIAL: existence, exit codes, measured duration and size cap are checked; provider/lost-event/WPA analysis is not |
| 92: output validation | JSON schema tests, artifact hash tests, Verify tamper tests, hosted artifact assertions | PARTIAL: headline files are checked; no all-artifact cross-file reference validation or CSV/ETL semantic validation |
| 93: overhead | WPR test wall time only; hosted workload only checks finite process CPU | MISSING: no measurement of the toolkit process CPU, memory, disk writes, sample loss, event loss or incremental WPR cost |

## 4. PowerShell engine, runtime and launcher coverage

### 4.1 What the workflows execute

| Workflow/job and lines | Engine/runtime evidence | What is not covered |
| --- | --- | --- |
| `linux-verify`, `.github/workflows/ci.yml:10-40` | Runs `pytest tests/ -q` and a `pwsh` parser gate. The workflow has no PowerShell install step; it assumes `ubuntu-latest` supplies `pwsh`. | No Windows PowerShell 5.1 exists on the Linux runner. The Python helpers always invoke `pwsh`, not `powershell.exe`; a passing Linux suite is not a PS 5.1 runtime result. |
| `windows-verify`, `ci.yml:42-355` | Matrix is `windows-2022` and `windows-2025` (`:42-46`). It parses with Windows PowerShell 5.1 (`:50-63`) and `pwsh` (`:65-78`), runs Plan/refusal tests under `pwsh` (`:80-155`), invokes `Run-Diagnostics.bat` and START-HERE options 2, 1 and 4 through `cmd` (`:157-171`), checks selected artifacts/Verify (`:173-327`), and runs a controlled CPU workload (`:329-355`). | It does not run all 148 Python tests on Windows or execute the helper harness under PS 5.1. It does not run START-HERE option 3 or 5, invalid interactive input, a human standard-user double-click, the WinRE launcher, Defender success, a controlled disk/GPU/UDP fault, or a full marker capture. |
| `wpd-live-gates`, `ci.yml:363-585` | WPD-08 uses the Windows PowerShell 5.1 executable for refusal (`:371-393`); WPD-10 uses the same executable for elevated real `wpr.exe` (`:429-462`); WPD-09 creates a per-run local standard identity and starts Windows PowerShell 5.1 with `CreateProcessWithLogonW` semantics (`:495-572`). | It does not run Defender WPD-12/13/14. Its step named WPD-12 is actually remote WinRM (`:464-493`), which conflicts with the repository matrix where WPD-12 is Defender consent (`docs/windows-live-test-matrix.md:40`). The WPD gate artifact upload excludes `*.etl` and `*.NGENPDB` (`ci.yml:574-585`), so existence was checked in the job but the raw ETL is not preserved there. |
| `wpd-release-flow`, `ci.yml:603-1041` | Exercises tag/hash reconstruction, extraction, Unblock-File, required files, per-file hashes, and `Run-Diagnostics.bat` from the clean extraction (`:910-1016`). It records HTTP/MOTW/Defender observations (`:655-741`). | Direct private-release download and real Defender quarantine are explicitly N/A when the runner cannot obtain/stamp the asset or real-time protection is disabled (`:732-740`). The flow does not run START-HERE, Pull-BootFailureLogs, Verify from the extracted case, or option 3. |
| CodeQL, `.github/workflows/codeql.yml:15-31` | Static analysis only for Actions and Python; build mode is none. | No PowerShell parse or runtime coverage. |

Parsing is not runtime compatibility. The production parameter block is
PowerShell 5.1-shaped (`src/...ps1:1-83`) and the CI parses it with both engines,
but only a small subset of the top-level script runs under the Windows 5.1
executable. The helper tests use `pwsh` AST extraction and cannot detect a
PS 5.1-only runtime failure in a function that was not invoked by a Windows
smoke run.

### 4.2 Launcher coverage

| Launcher | Current evidence | Missing or misleading coverage |
| --- | --- | --- |
| `Run-Diagnostics.bat:1-28` | Static quote/CRLF/CI-safe/failure checks at `test_plan_mode.py:854-883`; live success via `windows-verify:157-159` and release flow `ci.yml:976-1016`. | No live missing-script preflight, child nonzero path, missing-manifest path, unusual quoted working directory, or standard-user double-click. The successful run does not exercise its failure branch. |
| `START-HERE.bat:1-177` | Static elevation/quoting checks at `test_plan_mode.py:1262`; hosted `cmd` calls option 2, 1 and 4 at `ci.yml:161-171`. | No live interactive menu, invalid choice, option 3 incident capture, option 5 exit, verify prompt, UAC branch, or standard-user visual/no-UAC behavior. `README-FIRST.txt:34-47` still describes four choices and a separate 30-second WPR trace, while START-HERE `:31-37,73-85,101-107` has five choices and one shared window. |
| `Pull-BootFailureLogs.bat:1-107` | Static ASCII/CRLF/read-only/consent-warning check at `test_plan_mode.py:741-769`. | No WinRE/WinPE execution, drive-letter validation, collision suffix, Robocopy cap behavior, or explicit opt-in/skip bcdedit test. This cannot be substituted by a normal hosted Windows runner. |

The documentation and workflow also have a naming defect: the current matrix
uses WPD-12 for Defender consent and the workflow uses WPD-12 for remote WinRM.
Give remote collection its own ID before using matrix results as release evidence.
The development workflow also still describes the live handoff as WPD-01..WPD-31
(`docs/development-workflow.md:62-74`) even though the current matrix includes
WPD-32..WPD-34.

## 5. Fixture gaps

Existing fixtures are valuable but narrow:

- They use fixed timestamps, synthetic PowerShell objects, temporary files,
  synthetic event XML and a fake WPR executable. This is deterministic and
  appropriate for parser/math/report tests.
- They prove real function bodies through AST extraction, rather than merely
  testing copied reimplementations. That does not make Windows-only providers
  available.
- `test_plan_mode.py:_write_minimal_collect_case` (`:23-55`) is a minimal
  Verify fixture, not a complete Collect fixture.
- The shared `Write-CollectionOutputs` tail is fixture-testable
  (`src/...ps1:4415` in the read snapshot), but the top-level Collect path
  still creates and queries Windows providers directly. On Linux, confirmed
  Collect stops at the platform check before those providers run.
- The current crash/servicing WIP adds reparse-point, growing-input and
  cross-chunk fixtures, but those remain synthetic file-system tests; they do
  not prove that WinRE/boot-failure copy commands supplied those files.

Missing fixture classes:

1. A complete provider-neutral Collect fixture that supplies deterministic CIM,
   PDH, EventLogReader, process, network, WPR and Defender results and exercises
   the manifest from start to finish.
2. Successful CIM fixtures for memory, formatted/raw disk, volume, processor,
   process commit, pagefile, kernel pool and video-controller rows. Existing
   null tests deliberately prove unavailable behavior instead.
3. Event fixtures for every requested log, newest-first truncation, malformed or
   unrenderable records, raw XML EventData and provider failures.
4. WPR start failure, stop failure, timeout, abandoned session, marker race,
   empty ETL, provider absence and ETW lost-event fixtures. The fake WPR tests
   only cover a clean fake start/stop and post-stop size policy.
5. Defender module absent, standard-user skip, elevated success, report failure
   and no-quarantine fixtures.
6. Full minidump copy/cap, MEMORY.DMP metadata-only, LiveKernelReports, boot
   failure source-copy, missing-source and partial-copy fixtures.
7. Fault-injected DNS/IP/ICMP, proxy, security-software and UDP dynamic-range
   fixtures with expected verdicts.
8. Short-lived/reused process fixtures across multiple samples, per-process
   commit growth, GPU engine/memory rows, separate storage volumes and pagefile
   mapping through the real output writer.
9. Launcher fixtures for all menu branches, quoted paths, missing script,
   child failure, interrupted input and CI/non-CI pause behavior.
10. Cross-engine golden output fixtures proving PS 5.1 and pwsh write the same
    schema-valid field set, null semantics, artifact names and BOM policy.

## 6. Proposed deterministic 30-row fixture matrix

This is a proposal, not a claim that these fixture directories already exist.
Each fixture should use a fixed UTC clock, fixed process IDs/start ticks, fixed
counter/event values, controlled fake command results, and a fresh temporary
case directory. `P` means current top-level Plan/Verify/refusal evidence,
`F` means current helper fixture evidence, `H` means current hosted Windows
coverage, and `O` means owner-live evidence still required.

| Fixture | WPD IDs | Deterministic scenario and expected assertion | Current evidence | Needed lane |
| --- | --- | --- | --- | --- |
| F01 | 01 | Plan baseline: write only `diagnostic-plan.json`, read-only safety, no Collect artifacts | P/H | P + both Windows engines |
| F02 | 02 | Local Collect without consent: exact refusal, no directory/artifacts | P/H | P + PS 5.1/pwsh |
| F03 | 03,04 | Successful basic Collect: fixed provider snapshot emits required files and every emitted file has size/hash metadata | P only; H smoke | H fixture + real smoke |
| F04 | 05 | Standard-user basic Collect: finite permitted data, explicit partial errors, no UAC/auto-elevation | WPR-only H | H standard identity |
| F05 | 06 | Controlled System event: fixed event appears, newest-first and `MaxEventCount` bound hold | F parser only | H event injection |
| F06 | 07 | Before/after safety baseline: Defender, startup, event-log config and system state byte/field comparison is unchanged | Missing | O client gate |
| F07 | 08 | WPR requested without WPR consent: refusal before any trace/artifact | P/H | H 5.1 + pwsh |
| F08 | 09 | WPR standard user: collect succeeds, `skipped-elevation-required`, no ETL and no elevation | H | H standard identity |
| F09 | 10 | Elevated WPR: nonempty ETL, zero start/stop exits, `completed`, hash registration | H step; ETL upload gap | H 5.1 and pwsh |
| F10 | 11 | Release/MOTW: fixed release hash, extraction, Unblock-File, required launchers and per-file hashes | H archive; MOTW N/A | H archive + O Defender client |
| F11 | 15 | START-HERE menu: options 1/2/4 success and explicit option/exit behavior | Static + H 1/2/4 | H cmd + interactive O |
| F12 | 16 | Crash event evidence: fixed BugCheck/Kernel-Power records produce bounded crashAnalysis and event counts | F synthetic | O existing-evidence client |
| F13 | 12,13 | Defender refusal and standard user skip: exact consent refusal, module/elevation status and no ETL | Plan/refusal P | H 5.1 standard identity |
| F14 | 14 | Elevated Defender: known module/platform, nonempty recording/report status, hash registration | Missing | H if supported + O client |
| F15 | 17 | Network fault variants: DNS works/fails, raw IP ping works/fails, section errors and UDP counts match seed | F network helpers | H fault fixture |
| F16 | 18,23 | Verify intact, tampered artifact/report, restored case: exact exit/status/errors and no Verify writes | P/F/H | P + H full case |
| F17 | 19 | Symptom and preset: exact injection text survives; preset-only case has no invented reported text | P only | P + H Collect |
| F18 | 20 | Controlled CPU workload: top process has finite interval CPU and no process-snapshot error | H workload | H + O client |
| F19 | 21 | Disk load and idle: paired raw intervals under load; null plus coverage reason when no finite interval | F math/null | H/O real disk |
| F20 | 22 | Findings/report: fixed finding citations, windows, standalone HTML and no health score | F/H output | H complete case |
| F21 | 24 | Marker incident: fixed samples/events, retained 60/30 window, WPR covers counters, dropped count agrees | F helper/Plan | H interactive + O |
| F22 | 25 | WPR cap: memory mode, measured duration, oversized ETL and symbol directory removed/recorded | F + H WPR | H long/capped run |
| F23 | 26 | Commit attribution: per-process CSV/top, pagefile/kernel-pool series and computed top-five percentage | Schema/Plan only | H/O memory workload |
| F24 | 27 | GPU: fixed adapter/engine/process-memory rows, unavailable temperature/clocks are explicit | F path parser | O GPU/TDR client |
| F25 | 28 | UDP pressure: seeded netstat/dynamic ranges and live comparison, bounded JSON size | F parser | O network client |
| F26 | 29 | Incident events: System/Application/optional logs, RawXml retained, in/out labels and counts agree | F labelling | H provider fixture + O |
| F27 | 30 | Storage mapping: every drive maps to a physical disk, pagefile host is flagged, archive free space is contextualized | F mapping | O multi-drive client |
| F28 | 31 | START-HERE option 3: shared window, Enter marker, UAC path, incident manifest and WPR coverage | Static only | O interactive client |
| F29 | 32 | Minidump outside lookback: dump remains visible, no false bugcheck, filename hint is not root cause | F crash helper | O existing dump client |
| F30 | 33,34 | Servicing normal and oversized: signatures/counts/ranges for bounded files; oversized file is explicit unavailable/partial | F current WIP | H fixture + O boot lab |

The first implementation of this matrix should have a small driver that runs the
same fixture IDs under `pwsh` and Windows PowerShell 5.1, emits one JSON result
per fixture, and fails on any expected artifact/status/hash mismatch. It should
not use wall-clock sleeps, real crash induction, production Defender mutation,
or credentials. Any live-provider adapter must be a test seam or a disposable
fixture host; it must not change the production safety defaults.

## 7. Proposed hosted Windows gates

Hosted gates should prove engine compatibility and controlled wiring, not
pretend to prove hardware-specific behavior.

| Gate | Runner/engine | Required assertion and evidence |
| --- | --- | --- |
| H01 parser and mode safety | windows-2022 and windows-2025; PS 5.1 and pwsh | Parse source; run Plan, local-consent refusal, optional-consent refusals and invalid path under each engine; assert exact exit/status and no refusal artifacts. Existing `windows-verify` is the starting point. |
| H02 full Python/helper suite | Windows matrix with `pytest` and pwsh | Run all four Python files on Windows. Add a separate PS 5.1 harness or Pester lane; do not relabel the existing pwsh AST tests as PS 5.1 coverage. |
| H03 provider fixture matrix | Windows 5.1 and pwsh | Run F01-F05, F07-F09, F13, F15-F17, F19-F22 and F30 against deterministic provider/command seams; preserve JSON results and hashes. |
| H04 controlled basic Collect | Windows elevated runner, short fixed duration | Assert every current advertised output artifact, manifest registration, schema validation, Verify intact/tamper behavior and report reachability. Current `ci.yml:250-327` covers only headline files and selected fields. |
| H05 WPR | elevated and standard identities, PS 5.1 and pwsh | Keep F07-F10, add provider/ETL/lost-event diagnostics, and upload sanitized manifest/log evidence. Preserve ETL only where policy allows; the current gate excludes it from upload. |
| H06 Defender | module-present and module-absent runners where available | Add F13/F14 with consent refusal, standard-user skip, elevated success or explicit unsupported status. Never auto-enable protection or upload raw Defender data. |
| H07 launcher branches | `cmd` plus both PowerShell engines | Exercise START-HERE 1, 2, 3, 4, 5, invalid/missing-script/failure paths and Run-Diagnostics success/failure. Keep Pull-BootFailureLogs in a separate WinPE gate. |
| H08 remote | loopback WinRM with a distinct remote ID | Keep the existing pulled-file/hash assertions, but rename the workflow case so it cannot be confused with Defender WPD-12. Record remote staging cleanup. |
| H09 release archive | Windows 5.1 and pwsh | Verify tag/source hash, clean extraction, Unblock-File and Run-Diagnostics. Mark real MOTW/Defender quarantine as N/A rather than PASS when runner conditions cannot reproduce it. |
| H10 output contract | Windows 5.1 and pwsh | Validate all JSON schemas, CSV headers/row types, artifact hash registration, cross-file references, and Verify after tamper/restore. |

Each hosted gate should upload only the minimum sanitized evidence needed to
review a failure. Do not upload credentials, bearer headers, raw user paths, or
large ETL/symbol files by default.

## 8. Owner-live-only gates

A hosted VM cannot substitute for these checks because the acceptance condition
is a physical client state, a client-only security product, a human interaction,
or a real hardware counter.

| Owner gate | Why hosted CI is insufficient | Required controlled run |
| --- | --- | --- |
| O01 no-side-effects baseline | The machine image and Defender policy are not the user's client state | Before/after Defender exclusions, startup entries, event-log config, policies, uploads and system configuration; record no mutation. |
| O02 MOTW and Defender recovery | Current release flow records N/A when downloads or real-time protection are unavailable | Win10/11 client with protection on: download verified release, extract without unblock, record quarantine if it occurs, use documented Protection History restore, Unblock-File and re-verify hashes. |
| O03 standard-user launcher/UAC | A hosted elevated runner plus a token-created user does not reproduce the human desktop/UAC path | Standard account: double-click Run-Diagnostics and START-HERE options 2/3; confirm no silent elevation, expected UAC only, logs and manifests. |
| O04 real disk latency/queue | VM storage and synthetic deltas do not prove physical device counters | Approved copy workload and idle run on a known SSD/HDD/NVMe; compare disk-samples, queue/latency null semantics and drive mapping. |
| O05 real memory/commit | Hosted memory pressure is not the reported endpoint workload | Bounded known memory workload; inspect process commit, pagefile, pool and findings without exhausting the client. |
| O06 GPU/TDR | GPU engine availability, temperature and driver behavior are hardware/SKU-specific | Approved GPU workload or existing TDR evidence; compare adapter/engine/process-memory rows and explicit unavailable fields. Do not induce a crash. |
| O07 UDP and network fault | Runner network, DNS and dynamic ranges differ from the affected client | Capture live `netstat -ano`, `netsh` dynamic ranges, DNS/IP split and bounded UDP samples during an approved fault or reproduction. |
| O08 unrenderable event XML | Provider installation and message-rendering failures vary by client | Compare System/Application/WER/driver/PnP records with Event Viewer; preserve RawXml for an unrenderable record and verify window labels/counts. |
| O09 storage/pagefile map | A VM normally lacks the user's separate archive/pagefile topology | Client with separate drives; verify every drive-to-physical mapping and pagefile host in manifest/report. |
| O10 crash/minidump history | Synthetic objects do not prove Windows copied real dumps or bounded event lookback | Use an approved client with existing crash evidence; verify copy caps, metadata, outside-lookback retention and no binary decoder claim. Never induce a crash for this test. |
| O11 boot/WinRE/servicing | WinRE/PE drive letters, SRT/CBS/Panther/DISM contents and failure modes are not present in normal CI | Disposable recovery environment for Pull-BootFailureLogs and a booting client with known copied servicing logs; test missing/oversized/partial sources and optional bcdedit opt-in. |
| O12 marker/incident interaction | A scripted signal is not the operator pressing Enter during the real symptom | Approved incident run with shared window, marker, WPR coverage, retained/dropped samples and event labels. |
| O13 collector overhead | VM scheduling and idle load do not define the user's performance budget | Run the protocol in the next section on representative idle and controlled workload states. |

Owner results should include the exact release hash, OS/build, elevation state,
pre/post evidence paths, manifest, and a PASS/FAIL/N/A reason. A missing
hardware or Defender capability is an explicit N/A with its detected version,
not a fabricated success.

## 9. Collector overhead measurement gap and protocol

Current tests do not measure the toolkit's own resource cost. The fake WPR test
measures that a caller signal beats a nominal full-window wait
(`test_wpr_bounded_capture.py:120-138`), and the hosted workload measures that
one process receives a finite CPU percentage (`ci.yml:329-355`). Neither
measures the collector process, child WPR process, event readers, bytes written,
sample loss, event loss, or incremental cost of `PerformanceMode`.

The source has elapsed-time stopwatches and repeated provider calls, but no
`collector-performance.json`, `eventsLost` field, overhead baseline, or threshold
(`src/...ps1` sampling and output stages; `docs/audit-v1-to-spec.md:69-83,376-381`).
The sampling loop performs repeated operating-system/CIM queries in its window;
that is a correctness and efficiency risk that must be measured before claiming
low overhead.

Proposed deterministic protocol:

1. Freeze the test image, OS/build, power plan, processor count, storage volume,
   Defender state, output path and workload. Use a 60-second run and a one-second
   sample interval for comparability; do not change production policy.
2. Run at least three baseline repetitions with no collector and no workload,
   then three repetitions each for basic Collect, Collect with WPR, and
   `PerformanceMode`. Use the same controlled CPU, memory and disk workload in a
   second block.
3. Record wall duration, collector PID and child WPR PID, process CPU time,
   private bytes/working set, read/write bytes, output bytes, ETL bytes, sample
   count, skipped samples, collection errors, WPR status and any available ETW
   loss signal. Record the same host counters for the baseline interval.
4. Report every repetition, median and high percentile. Separate collector cost
   from workload cost, and separate WPR incremental cost from the no-WPR run.
5. Set pass/fail thresholds before collecting results. Thresholds must be an
   owner/product decision; this audit does not invent a percentage or byte limit.
   Until thresholds and representative hardware are approved, label the result
   informational rather than PASS.
6. Repeat on at least one low-power client and one high-core client, and with
   `MaxTrackedProcesses` at its default and a bounded high value. Clean up WPR
   and temporary outputs in a finally path and record cleanup status.

The resulting artifact should be a small, schema-validated
`collector-performance.json` plus a CSV of repetitions. It must never include
raw passwords, bearer headers, or full user data. The artifact should be added
to the manifest only after the output contract and privacy policy are agreed.

## 10. Recommended closure order

P0 - make test evidence honest and repeatable:

1. Add a distinct remote test ID and update the matrix/workflow naming.
2. Add a Windows test lane for all Python files and a real PS 5.1 function
   harness (Pester is the natural PowerShell-native option, but the harness must
   exercise real functions rather than source regexes).
3. Introduce provider/command seams or a fixture adapter so one deterministic
   full-Collect case can run under both PowerShell engines without changing
   production safety defaults.
4. Implement the 30-row fixture driver and exact cross-file output assertions.
5. Add missing Defender, launcher branch, WPR failure/cleanup, event XML and
   servicing/minidump cases.

P1 - prove user-visible and hardware-sensitive behavior:

1. Run the hosted gates for safe, reproducible cases and preserve sanitized
   manifests/logs.
2. Run the owner gates on an approved Windows 10/11 client, without inducing a
   crash or changing Defender/boot policy except for an explicitly approved and
   reverted test.
3. Resolve the README-FIRST shared-window/options mismatch and document the
   final launcher behavior.

P2 - measure and enforce cost:

1. Run the overhead protocol and agree on thresholds.
2. Add the collector-performance artifact and a regression gate.
3. Hoist or batch repeated static/provider queries only after the measurement
   identifies the dominant cost; then add a before/after benchmark fixture.

Until these items are complete, the accurate release statement is: Python and
selected PowerShell helper behavior pass on this host; selected Plan/refusal,
launcher, WPR and smoke behavior runs on hosted Windows; hardware, Defender/MOTW,
interactive incident, WinRE, full provider fixture, and collector-overhead
validation remain partial or owner-live-only.
