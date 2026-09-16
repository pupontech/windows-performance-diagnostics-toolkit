"""Validation of the central rule and preset configuration.

config/diagnostic-rules.json and config/diagnostic-presets.json are data, so the
contract they must satisfy is enforced here: JSON validity, ASCII/no BOM,
preset-name uniqueness, alias resolution, counter/module/channel reference
integrity and the "no preset is metadata-only" rule (a preset that only changes
display text and does not select at least one Tier 1 counter, a WPR recording,
a duration, an analysis module, an event channel, a trace budget and a privacy
level is rejected).

The validator lives in this test module because the card that owns the config
files is a new-files-only card: there is no production Python module in this
repository, and the config must not be described by code that does not exist.
Windows PowerShell consumes the same JSON at run time; these tests are the
Linux-side gate.

Every negative assertion below runs the validator against a mutated copy of the
shipped document, so the validator is proven to reject the defect rather than
being trusted.
"""

import copy
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = REPO_ROOT / "config"
PRESETS_PATH = CONFIG_DIR / "diagnostic-presets.json"
RULES_PATH = CONFIG_DIR / "diagnostic-rules.json"

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

LEGACY_ALIASES = {
    "baseline": "general",
    "network-io": "network",
    "application-freeze": "ui-hang",
}

# Metrics whose elevated value alone is not a conclusion: a finding built on
# them must carry an independent corroborating channel (spec 19/71, plan P0-4).
TWO_CHANNEL_METRICS = ("PagesInputPerSec", "pagesInputPerSec")


def load_document(path):
    """Read a JSON config document with the byte-level rules the toolkit uses."""
    raw = path.read_bytes()
    assert raw[:3] != b"\xef\xbb\xbf", "%s must not start with a UTF-8 BOM" % path.name
    text = raw.decode("ascii")
    return json.loads(text)


# ---------------------------------------------------------------------------
# Validators (the test module's own logic, exercised below with real defects)
# ---------------------------------------------------------------------------


def validate_presets_document(document, rules_document=None):
    """Return the list of contract violations found in a presets document."""
    errors = []
    if document.get("artifact") != "diagnostic-presets":
        errors.append("artifact must be 'diagnostic-presets'")
    if not document.get("schemaVersion"):
        errors.append("schemaVersion is required")
    if document.get("samplingFloorSeconds") != 1:
        errors.append("samplingFloorSeconds must be the documented 1 second floor")

    for key in (
        "canonicalPresets",
        "aliases",
        "privacyLevels",
        "privacyDefault",
        "wpr",
        "analysisModules",
        "eventChannels",
        "escalationOptions",
        "counters",
        "remediation",
        "presets",
    ):
        if key not in document:
            errors.append("top-level key missing: %s" % key)
    if errors:
        return errors

    canonical = list(document["canonicalPresets"])
    presets = document["presets"]
    aliases = document["aliases"]

    if sorted(canonical) != sorted(CANONICAL_PRESETS):
        errors.append("canonicalPresets must be exactly the 13 specification names")
    if sorted(presets) != sorted(canonical):
        errors.append("presets must define exactly the canonical names")
    duplicate_names = [name for name in presets if list(presets).count(name) > 1]
    if duplicate_names:
        errors.append("duplicate preset names: %s" % duplicate_names)

    behavioural_fields = (
        "tier1Counters",
        "tier1SampleIntervalSeconds",
        "tier2",
        "expectedDurationSeconds",
        "analysisModules",
        "eventChannels",
        "escalationOptions",
        "traceSizeBudget",
        "privacyLevel",
    )
    signatures = {}
    for name, preset in presets.items():
        if any(field not in preset for field in behavioural_fields):
            continue
        signature = json.dumps(
            {field: preset[field] for field in behavioural_fields}, sort_keys=True
        )
        signatures.setdefault(signature, []).append(name)
    for names in signatures.values():
        if len(names) > 1:
            errors.append(
                "presets with identical behaviour: %s" % sorted(names)
            )

    for alias, target in aliases.items():
        if alias in canonical:
            errors.append("alias %s shadows a canonical preset name" % alias)
        if target not in canonical:
            errors.append("alias %s resolves to an unknown preset %s" % (alias, target))

    privacy_levels = list(document["privacyLevels"])
    if document["privacyDefault"] not in privacy_levels:
        errors.append("privacyDefault is not a declared privacy level")

    wpr = document["wpr"]
    verified_profiles = list(wpr.get("verifiedProfiles", []))
    detail_levels = list(wpr.get("detailLevels", []))
    modes = list(wpr.get("modes", []))
    if not verified_profiles:
        errors.append("wpr.verifiedProfiles must list the profile names in use")
    if not list(wpr.get("discoveryCommand", "")):
        errors.append("wpr.discoveryCommand must state how profiles are confirmed")
    if wpr.get("fileModeRequiresOptIn") is not True:
        errors.append("wpr.fileModeRequiresOptIn must be true")

    modules = {entry["id"] for entry in document["analysisModules"]}
    channels = {entry["id"] for entry in document["eventChannels"]}
    escalations = {entry["id"] for entry in document["escalationOptions"]}
    counters = {entry["id"] for entry in document["counters"]}
    if rules_document is not None:
        counters |= {entry["id"] for entry in rules_document.get("counters", [])}

    for name, preset in presets.items():
        prefix = "preset %s" % name
        required = (
            "displayName",
            "symptomSummary",
            "tier1Counters",
            "tier1SampleIntervalSeconds",
            "tier2",
            "expectedDurationSeconds",
            "analysisModules",
            "eventChannels",
            "escalationOptions",
            "traceSizeBudget",
            "privacyLevel",
            "remediation",
        )
        for key in required:
            if key not in preset:
                errors.append("%s: missing %s" % (prefix, key))
        if any(key not in preset for key in required):
            continue

        if not preset["tier1Counters"]:
            errors.append("%s: tier1Counters must select at least one counter" % prefix)
        for counter in preset["tier1Counters"]:
            if counter not in counters:
                errors.append("%s: unknown counter %s" % (prefix, counter))

        interval = preset["tier1SampleIntervalSeconds"]
        if not isinstance(interval, int) or interval < document["samplingFloorSeconds"]:
            errors.append("%s: tier1SampleIntervalSeconds is below the floor" % prefix)

        tier2 = preset["tier2"]
        if not tier2.get("wprProfiles"):
            errors.append("%s: tier2.wprProfiles must name a WPR profile" % prefix)
        for profile in tier2.get("wprProfiles", []):
            if profile not in verified_profiles:
                errors.append("%s: unverified WPR profile %s" % (prefix, profile))
        if tier2.get("wprDetail") not in detail_levels:
            errors.append("%s: tier2.wprDetail is not light or verbose" % prefix)
        if tier2.get("wprMode") not in modes:
            errors.append("%s: tier2.wprMode is not a declared recording mode" % prefix)
        if tier2.get("wprMode") == "file" and not tier2.get("fileModeOptIn"):
            errors.append("%s: file mode requires an explicit opt-in" % prefix)

        duration = preset["expectedDurationSeconds"]
        if not isinstance(duration, int) or duration <= 0:
            errors.append("%s: expectedDurationSeconds must be a positive integer" % prefix)
        elif duration < interval * 2:
            errors.append("%s: expected duration does not cover two samples" % prefix)

        if not preset["analysisModules"]:
            errors.append("%s: analysisModules must select at least one module" % prefix)
        for module in preset["analysisModules"]:
            if module not in modules:
                errors.append("%s: unknown analysis module %s" % (prefix, module))

        if not preset["eventChannels"]:
            errors.append("%s: eventChannels must select at least one channel" % prefix)
        for channel in preset["eventChannels"]:
            if channel not in channels:
                errors.append("%s: unknown event channel %s" % (prefix, channel))

        for escalation in preset["escalationOptions"]:
            if escalation not in escalations:
                errors.append("%s: unknown escalation option %s" % (prefix, escalation))

        budget = preset["traceSizeBudget"]
        if not isinstance(budget.get("budgetMiB"), int) or budget["budgetMiB"] <= 0:
            errors.append("%s: traceSizeBudget.budgetMiB must be a positive integer" % prefix)
        if not budget.get("basis"):
            errors.append("%s: traceSizeBudget.basis must state what bounds the trace" % prefix)
        if not budget.get("overBudgetAction"):
            errors.append("%s: traceSizeBudget.overBudgetAction is required" % prefix)

        if preset["privacyLevel"] not in privacy_levels:
            errors.append("%s: privacyLevel is not a declared level" % prefix)

        remediation = preset["remediation"]
        if remediation.get("automaticRemediation") is not False:
            errors.append("%s: automaticRemediation must be false" % prefix)
        if not remediation.get("operatorConfirmationRequired"):
            errors.append("%s: operator confirmation must be required" % prefix)

    return errors


def validate_rules_document(document):
    """Return the list of contract violations found in a rules document."""
    errors = []
    if document.get("artifact") != "diagnostic-rules":
        errors.append("artifact must be 'diagnostic-rules'")
    if not document.get("schemaVersion"):
        errors.append("schemaVersion is required")
    if document.get("samplingFloorSeconds") != 1:
        errors.append("samplingFloorSeconds must be the documented 1 second floor")

    for key in (
        "severities",
        "confidenceLevels",
        "categories",
        "counters",
        "rules",
        "coverageRules",
    ):
        if key not in document:
            errors.append("top-level key missing: %s" % key)
    if errors:
        return errors

    severities = list(document["severities"])
    confidence_levels = list(document["confidenceLevels"])
    categories = set(document["categories"])
    counters = {entry["id"] for entry in document["counters"]}
    counter_fields = {entry["field"] for entry in document["counters"]}
    metric_names = counters | counter_fields

    rule_ids = [rule["id"] for rule in document["rules"]]
    if len(rule_ids) != len(set(rule_ids)):
        errors.append("rule ids must be unique")

    for rule in document["rules"]:
        prefix = "rule %s" % rule.get("id", "<missing>")
        for key in (
            "id",
            "category",
            "sourceArtifact",
            "metric",
            "comparator",
            "threshold",
            "thresholdBasis",
            "minimumSamples",
            "minimumDurationSeconds",
            "severity",
            "confidence",
            "suggestedWprProfile",
            "uncertainty",
        ):
            if key not in rule:
                errors.append("%s: missing %s" % (prefix, key))
        if "id" not in rule or "metric" not in rule:
            continue

        if rule["category"] not in categories:
            errors.append("%s: unknown category %s" % (prefix, rule["category"]))
        if rule["metric"] not in metric_names:
            errors.append("%s: metric %s is not in the counter catalogue" % (prefix, rule["metric"]))
        if rule["comparator"] not in ("ge", "gt", "le", "lt"):
            errors.append("%s: unsupported comparator %s" % (prefix, rule["comparator"]))
        if not isinstance(rule["threshold"], (int, float)) or isinstance(rule["threshold"], bool):
            errors.append("%s: threshold must be numeric" % prefix)
        if not isinstance(rule["minimumSamples"], int) or rule["minimumSamples"] < 1:
            errors.append("%s: minimumSamples must be a positive integer" % prefix)
        if rule["minimumDurationSeconds"] < rule["minimumSamples"] * document["samplingFloorSeconds"]:
            errors.append("%s: minimum duration is shorter than the sample requirement" % prefix)
        if rule["severity"].get("default") not in severities:
            errors.append("%s: unknown default severity" % prefix)
        for escalation in rule["severity"].get("escalations", []):
            if escalation.get("severity") not in severities:
                errors.append("%s: unknown escalated severity" % prefix)
            if not escalation.get("when"):
                errors.append("%s: severity escalation needs a stated condition" % prefix)
        if rule["confidence"].get("default") not in confidence_levels:
            errors.append("%s: unknown default confidence" % prefix)
        conditions = rule["confidence"].get("conditions", [])
        if not conditions:
            errors.append("%s: confidence logic needs stated conditions" % prefix)
        for condition in conditions:
            if condition.get("level") not in confidence_levels:
                errors.append("%s: unknown confidence level" % prefix)
            if not condition.get("when"):
                errors.append("%s: confidence condition needs a stated condition" % prefix)
        if not rule.get("suggestedWprProfile"):
            errors.append("%s: a suggested WPR profile is required" % prefix)

        correlations = rule.get("correlationRequirements", [])
        if rule["metric"] in TWO_CHANNEL_METRICS:
            if not correlations:
                errors.append("%s: a paging-rate rule needs a second channel" % prefix)
            for correlation in correlations:
                if correlation.get("metric") == rule["metric"]:
                    errors.append("%s: the corroborating channel repeats the primary metric" % prefix)

    for rule in document["coverageRules"]:
        prefix = "coverage rule %s" % rule.get("id", "<missing>")
        if rule.get("category") not in categories:
            errors.append("%s: unknown category" % prefix)
        if not rule.get("reason"):
            errors.append("%s: coverage rules must state why data is unusable" % prefix)
    return errors


# ---------------------------------------------------------------------------
# Configuration files
# ---------------------------------------------------------------------------


def test_config_files_exist_and_are_strict_ascii_json():
    for path in (PRESETS_PATH, RULES_PATH):
        assert path.is_file(), "config file missing: %s" % path
        document = load_document(path)
        assert isinstance(document, dict), "%s must be a JSON object" % path.name


def test_presets_document_satisfies_its_own_validator():
    presets = load_document(PRESETS_PATH)
    rules = load_document(RULES_PATH)
    assert validate_presets_document(presets, rules) == []


def test_rules_document_satisfies_its_own_validator():
    rules = load_document(RULES_PATH)
    assert validate_rules_document(rules) == []


def test_every_canonical_preset_is_present_and_functional():
    presets = load_document(PRESETS_PATH)["presets"]
    assert sorted(presets) == sorted(CANONICAL_PRESETS)
    for name, preset in presets.items():
        assert preset["tier1Counters"], name
        assert preset["analysisModules"], name
        assert preset["traceSizeBudget"]["budgetMiB"] > 0, name
        assert preset["remediation"]["automaticRemediation"] is False, name


def test_legacy_preset_names_resolve_to_the_canonical_names():
    document = load_document(PRESETS_PATH)
    aliases = document["aliases"]
    for alias, target in LEGACY_ALIASES.items():
        assert aliases.get(alias) == target
        assert target in document["presets"]


def test_presets_are_not_metadata_only():
    """Two presets may not differ in display text alone."""
    presets = load_document(PRESETS_PATH)["presets"]
    behavioural = (
        "tier1Counters",
        "tier2",
        "expectedDurationSeconds",
        "analysisModules",
        "eventChannels",
        "escalationOptions",
        "traceSizeBudget",
        "privacyLevel",
    )
    signatures = {}
    for name, preset in presets.items():
        signature = json.dumps({key: preset[key] for key in behavioural}, sort_keys=True)
        signatures.setdefault(signature, []).append(name)
    duplicates = {sig: names for sig, names in signatures.items() if len(names) > 1}
    assert duplicates == {}, "presets with identical behaviour: %s" % duplicates


# ---------------------------------------------------------------------------
# Negative cases: the validator must reject the defect, not be trusted
# ---------------------------------------------------------------------------


def _presets_with(mutate):
    presets = copy.deepcopy(load_document(PRESETS_PATH))
    rules = load_document(RULES_PATH)
    mutate(presets)
    return presets, rules


def test_validator_rejects_a_metadata_only_preset():
    def mutate(document):
        document["presets"]["power"] = {
            "displayName": "Power",
            "symptomSummary": "Power-related slowness",
        }

    document, rules = _presets_with(mutate)
    errors = validate_presets_document(document, rules)
    assert any("power" in error and "tier1Counters" in error for error in errors)
    assert any("power" in error and "traceSizeBudget" in error for error in errors)


def test_validator_rejects_a_preset_without_analysis_modules():
    def mutate(document):
        document["presets"]["gpu"]["analysisModules"] = []

    document, rules = _presets_with(mutate)
    errors = validate_presets_document(document, rules)
    assert any("gpu" in error and "analysisModules" in error for error in errors)


def test_validator_rejects_a_preset_without_a_trace_budget():
    def mutate(document):
        del document["presets"]["storage-io"]["traceSizeBudget"]

    document, rules = _presets_with(mutate)
    errors = validate_presets_document(document, rules)
    assert any("storage-io" in error and "traceSizeBudget" in error for error in errors)


def test_validator_rejects_two_presets_with_identical_behaviour():
    def mutate(document):
        document["presets"]["gpu"] = copy.deepcopy(document["presets"]["cpu-heavy"])

    document, rules = _presets_with(mutate)
    errors = validate_presets_document(document, rules)
    assert any("identical behaviour" in error and "gpu" in error for error in errors)
    assert any("identical behaviour" in error and "cpu-heavy" in error for error in errors)


def test_validator_rejects_an_alias_that_shadows_a_canonical_name():
    def mutate(document):
        document["aliases"]["general"] = "cpu-heavy"

    document, rules = _presets_with(mutate)
    errors = validate_presets_document(document, rules)
    assert any("shadows a canonical preset name" in error for error in errors)


def test_validator_rejects_an_unknown_wpr_profile():
    def mutate(document):
        document["presets"]["cpu-heavy"]["tier2"]["wprProfiles"] = ["CpuMagicProfile"]

    document, rules = _presets_with(mutate)
    errors = validate_presets_document(document, rules)
    assert any("unverified WPR profile" in error for error in errors)


def test_validator_rejects_an_unbounded_file_mode_capture_without_opt_in():
    def mutate(document):
        document["presets"]["intermittent"]["tier2"]["wprMode"] = "file"
        document["presets"]["intermittent"]["tier2"]["fileModeOptIn"] = False

    document, rules = _presets_with(mutate)
    errors = validate_presets_document(document, rules)
    assert any("file mode requires an explicit opt-in" in error for error in errors)


def test_validator_rejects_a_preset_that_would_remediate_automatically():
    def mutate(document):
        document["presets"]["memory-leak"]["remediation"]["automaticRemediation"] = True

    document, rules = _presets_with(mutate)
    errors = validate_presets_document(document, rules)
    assert any("automaticRemediation must be false" in error for error in errors)


def test_validator_rejects_a_paging_rule_without_a_second_channel():
    rules = copy.deepcopy(load_document(RULES_PATH))
    for rule in rules["rules"]:
        if rule["metric"] in TWO_CHANNEL_METRICS:
            rule["correlationRequirements"] = []
    errors = validate_rules_document(rules)
    assert any("needs a second channel" in error for error in errors)


def test_validator_rejects_a_duplicate_rule_id():
    rules = copy.deepcopy(load_document(RULES_PATH))
    rules["rules"].append(copy.deepcopy(rules["rules"][0]))
    errors = validate_rules_document(rules)
    assert any("rule ids must be unique" in error for error in errors)


def test_validator_rejects_an_unknown_metric_and_category():
    rules = copy.deepcopy(load_document(RULES_PATH))
    rules["rules"][0]["metric"] = "MadeUpMetric"
    rules["rules"][0]["category"] = "made-up-category"
    errors = validate_rules_document(rules)
    assert any("not in the counter catalogue" in error for error in errors)
    assert any("unknown category" in error for error in errors)


def test_validator_rejects_confidence_or_severity_without_a_stated_condition():
    rules = copy.deepcopy(load_document(RULES_PATH))
    rules["rules"][0]["confidence"]["conditions"] = []
    rules["rules"][0]["severity"]["escalations"] = [{"severity": "high"}]
    errors = validate_rules_document(rules)
    assert any("confidence logic needs stated conditions" in error for error in errors)
    assert any("severity escalation needs a stated condition" in error for error in errors)


def test_validator_rejects_a_threshold_in_no_units():
    rules = copy.deepcopy(load_document(RULES_PATH))
    rules["rules"][0]["threshold"] = "eighty"
    errors = validate_rules_document(rules)
    assert any("threshold must be numeric" in error for error in errors)


# ---------------------------------------------------------------------------
# Content the specification requires beyond structural validity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", CANONICAL_PRESETS)
def test_preset_declares_the_full_functional_contract(name):
    preset = load_document(PRESETS_PATH)["presets"][name]
    assert preset["tier1Counters"]
    assert preset["tier1SampleIntervalSeconds"] >= 1
    assert preset["tier2"]["wprProfiles"]
    assert preset["tier2"]["wprDetail"] in ("light", "verbose")
    assert preset["tier2"]["wprMode"] in ("memory", "file")
    assert preset["expectedDurationSeconds"] >= 60
    assert preset["analysisModules"]
    assert preset["eventChannels"]
    assert isinstance(preset["escalationOptions"], list)
    assert preset["traceSizeBudget"]["budgetMiB"] >= 256
    assert preset["privacyLevel"] in ("Standard", "Redacted", "Full")
    assert preset["remediation"]["automaticRemediation"] is False


def test_paging_rule_requires_memory_pressure_corroboration():
    rules = load_document(RULES_PATH)
    paging_rules = [
        rule for rule in rules["rules"] if rule["metric"] in TWO_CHANNEL_METRICS
    ]
    assert paging_rules, "the paging rule must exist in the central rule file"
    for rule in paging_rules:
        assert rule["correlationRequirements"], rule["id"]
        for correlation in rule["correlationRequirements"]:
            assert correlation["metric"] != rule["metric"]


def test_thresholds_are_declared_outside_code_and_carry_a_basis():
    rules = load_document(RULES_PATH)
    for rule in rules["rules"]:
        assert rule["thresholdBasis"], rule["id"]
        assert rule["uncertainty"], rule["id"]


def test_coverage_rules_forbid_no_data_as_health():
    rules = load_document(RULES_PATH)
    assert rules["coverageRules"]
    for rule in rules["coverageRules"]:
        assert rule["outcome"] != "healthy", rule["id"]
        assert rule["reason"], rule["id"]
