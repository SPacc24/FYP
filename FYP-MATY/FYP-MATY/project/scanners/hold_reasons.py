"""Canonical reviewer-facing explanations for held CVE applicability decisions."""
from __future__ import annotations

DEFAULT_HOLD_EXPLANATION = 'The available evidence did not support an applicability decision.'
DEFAULT_HOLD_RESOLUTION = 'Review the published record directly against the observed service.'

HOLD_REASONS: dict[str, tuple[str, str]] = {
    'observed_version_missing': (
        'No concrete version was observed for this service.',
        'Collect a concrete version banner, versioned CPE, or authorised local inventory source.',
    ),
    'observed_version_missing_with_exceptions': (
        'No concrete version was observed and the record contains version exceptions that cannot be evaluated.',
        'Collect a concrete version so the published exceptions can be applied.',
    ),
    'observed_version_is_range': (
        'The fingerprint reported a version range rather than one concrete version.',
        'Collect a more specific fingerprint that resolves the range to one version.',
    ),
    'unsupported_or_custom_version_range': (
        'The published range uses a version scheme for which this scanner has no independently validated comparator.',
        "Use a validated comparator for the record's declared version scheme, or verify manually against the published record.",
    ),
    'published_version_rule_not_comparable': (
        'The published version rule could not be compared safely against the observed version.',
        'Collect a version at matching precision or verify manually against the published record.',
    ),
    'affected_upper_bound_unparseable': (
        'The upper bound could not be ordered safely against the observed version.',
        'Collect a package-level version with the release/revision precision required by the published rule.',
    ),
    'affected_lower_bound_unparseable': (
        'The lower bound could not be ordered safely against the observed version.',
        'Collect a package-level version with the release/revision precision required by the published rule.',
    ),
    'affected_cpe_context_not_satisfied': (
        'The published affected CPE context was not satisfied by the observed evidence.',
        'Collect evidence for the specific platform, package, module, or CPE context named by the record.',
    ),
    'ambiguous_wildcard_single_version': (
        'The record states a wildcard version without a structured unbounded range that can be evaluated safely.',
        'Verify manually unless the record provides an explicit affected range or defaultStatus=affected.',
    ),
    'wildcard_range_requires_version_scheme_specific_expansion': (
        'The published range contains a wildcard that requires version-scheme-specific expansion.',
        'Use a validated comparator/expander for that scheme or verify manually.',
    ),
    'unsupported_product_identity': (
        'The observed evidence did not establish a product identity suitable for structured affected-product matching.',
        'Collect a clearer product identity, preferably a product/version fingerprint or CPE.',
    ),
    'fingerprint_confidence_advisory': (
        'Fingerprint confidence is advisory context only and does not create or suppress CVE applicability.',
        'No action is required unless stronger identity evidence is desired.',
    ),
    'cve_index_unavailable': (
        'The official CVE catalogue was unavailable, so no applicability decision could be made.',
        'Rebuild or restore the official CVE index and re-run correlation.',
    ),
    'cve_sources_unavailable': (
        'No CVE source was available, so correlation did not run.',
        'Restore the official CVE source and re-run correlation.',
    ),
    'cve_matcher_error': (
        'The matcher encountered an execution error before reaching an applicability decision.',
        'Review the retained error evidence and repair the matcher/runtime fault.',
    ),
    'index_records_skipped': (
        'Some CVE catalogue records could not be read, so coverage may be incomplete.',
        'Rebuild the CVE index and inspect source-data or parser errors.',
    ),
}
KNOWN_HOLD_REASONS = frozenset(HOLD_REASONS)


def reason_name(reason: str) -> str:
    return str(reason or '').strip().partition(':')[0]


def describe_hold(reason: str) -> dict[str, str | bool]:
    raw = str(reason or '').strip()
    name, _, detail = raw.partition(':')
    explanation, resolution = HOLD_REASONS.get(name, (DEFAULT_HOLD_EXPLANATION, DEFAULT_HOLD_RESOLUTION))
    if detail and name in KNOWN_HOLD_REASONS:
        explanation = f'{explanation} (detail: {detail})'
    return {
        'reason': raw,
        'name': name,
        'detail': detail,
        'explanation': explanation,
        'resolution': resolution,
        'registered': name in KNOWN_HOLD_REASONS,
    }
