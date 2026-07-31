from __future__ import annotations

from unittest import TestCase

from scanners.windows_patch_applicability import assess_windows_cve_patch, enrich_windows_patch_states


CVE = "CVE-2099-99999"
PRODUCT = "Microsoft Windows 11 Version 23H2 for x64-based Systems"


def remediation(kb="KB9999999", fixed="10.0.22631.3155"):
    return {
        "cve_id": CVE,
        "product": PRODUCT,
        "kb": kb,
        "kb_candidates": [kb] if kb else [],
        "fixed_build": fixed,
        "source": "fixture",
    }


def inventory(*, ubr="4000", installed=None):
    return {
        "ok": True,
        "host": "10.10.10.30",
        "product": "Microsoft Windows 11 Pro",
        "version": "10.0.22631",
        "build": "22631",
        "ubr": ubr,
        "installed_kbs": installed or [],
    }


def row(scope="host_os"):
    return {
        "host": "10.10.10.30",
        "cve_id": CVE,
        "match_scope": scope,
        "product": "Microsoft Windows 11",
        "os_vendor": "Microsoft",
        "os_family": "Windows",
    }


class WindowsPatchApplicabilityTests(TestCase):
    def test_direct_vendor_remediation_kb_is_observed(self):
        result = assess_windows_cve_patch(row(), inventory(ubr="2000", installed=["KB9999999"]), [remediation()])
        self.assertEqual(result["patch_state"], "Remediation observed")
        self.assertEqual(result["observed_remediation_kbs"], ["KB9999999"])

    def test_later_directly_observed_revision_satisfies_fixed_build(self):
        result = assess_windows_cve_patch(row(), inventory(ubr="4000"), [remediation(fixed="10.0.22631.3155")])
        self.assertEqual(result["patch_state"], "Remediation observed")
        self.assertIn("fixed build", result["patch_basis"].lower())

    def test_older_exact_revision_reports_update_not_observed(self):
        result = assess_windows_cve_patch(row(), inventory(ubr="2000"), [remediation(fixed="10.0.22631.3155")])
        self.assertEqual(result["patch_state"], "Applicable update not observed")

    def test_missing_kb_without_revision_precision_is_not_proof(self):
        result = assess_windows_cve_patch(row(), inventory(ubr=""), [remediation(fixed="10.0.22631.3155")])
        self.assertEqual(result["patch_state"], "Insufficient patch evidence")
        self.assertIn("missing KB", result["patch_basis"])

    def test_service_and_non_windows_cves_are_not_reclassified(self):
        service_row = row(scope="service")
        linux_row = {**row(), "product": "Linux kernel", "os_vendor": "Linux", "os_family": "Linux"}
        rows = [service_row, linux_row]
        calls = []

        def lookup(cve_id):
            calls.append(cve_id)
            return [remediation()], {"status": "available"}

        assessments, diagnostics = enrich_windows_patch_states(rows, [inventory()], lookup)
        self.assertEqual(assessments, [])
        self.assertEqual(diagnostics, [])
        self.assertEqual(calls, [])
        self.assertNotIn("patch_state", service_row)
        self.assertNotIn("patch_state", linux_row)

    def test_host_windows_row_is_enriched_without_changing_cve_identity(self):
        target = row()
        assessments, diagnostics = enrich_windows_patch_states(
            [target], [inventory(ubr="4000")], lambda _cve: ([remediation()], {"status": "available"})
        )
        self.assertEqual(target["cve_id"], CVE)
        self.assertEqual(target["patch_state"], "Remediation observed")
        self.assertEqual(len(assessments), 1)
        self.assertEqual(diagnostics, [{"status": "available"}])
