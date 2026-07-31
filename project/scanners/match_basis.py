"""Canonical display vocabulary for structured CVE applicability bases."""
from __future__ import annotations

DISPLAY_LABELS: dict[str, str] = {
    'structured_exact_version': 'Observed version exactly matches a published affected version',
    'structured_affected_range': "Observed version falls within a published affected range using the record's declared version scheme",
    'structured_range_lower_endpoint': 'Observed version exactly matches the published lower endpoint of an affected range',
    'structured_range_inclusive_upper_endpoint': 'Observed version exactly matches the published inclusive upper endpoint of an affected range',
    'structured_default_status_affected': 'The matched product record explicitly defines otherwise-unlisted versions as affected',
    'structured_default_status_affected_without_version_exception': 'The matched product record explicitly marks the version branch as affected without an exception',
    'exact_application_cpe': 'Observed application CPE identity matches a published affected application CPE',
    'exact_component_cpe': 'Observed platform-component CPE identity matches a published affected component CPE',
    'exact_os_cpe': 'Observed operating-system CPE identity matches a published affected operating-system CPE',
    'exact_affected_cpe_version': 'Observed version exactly matches the version in a published affected CPE',
    'structured_affected_component_version': 'Observed protocol component version is explicitly named in the published affected-version data',
    'structured_affected_component_exact_version': 'Observed protocol component version exactly matches the published affected component version',
    'structured_component_default_status_affected': 'The published affected component record defines otherwise-unlisted component versions as affected',
}


def display_match_reason(match_basis: str, fallback: str = '') -> str:
    raw = str(match_basis or '').strip()
    if not raw:
        return fallback or 'Published affected data matched the observed service evidence.'
    name, _, detail = raw.partition(':')
    text = DISPLAY_LABELS.get(name, raw.replace('_', ' ').strip().capitalize())
    if detail:
        text += f': {detail}'
    return text
