# CVSS 3.1 / 4.0 dual-version update

This update changes the CVE/CVSS path so CVSS 3.1 and CVSS 4.0 are preserved and displayed independently.

## Implemented

- CVE catalogue records now retain `cvss_metrics["3.1"]` and `cvss_metrics["4.0"]` simultaneously.
- No conversion or fallback from one CVSS version to the other.
- CNA metrics take precedence for a version; ADP data may fill a version the CNA did not publish.
- NVD fallback also retains both 3.1 and 4.0 where NVD publishes them.
- Published vectors are recomputed for integrity checking. Inconsistent metadata is retained for audit but marked unverified.
- Scanner CVE rows carry the complete dual-version metric structure to the results layer.
- CVE Review contains:
  - CVE References table: CVE, affected service, match evidence, status, publisher, verification, links.
  - Vulnerability Severity table with CVSS 3.1 / CVSS 4.0 / Both display modes.
- Sorting uses the selected CVSS version. Missing metrics are not treated as zero.
- PDF report includes separate published CVSS 3.1 and CVSS 4.0 columns.
- Existing single-metric fields are retained only for backward compatibility with older downstream code.

## Catalogue rebuild

A catalogue produced by the old single-CVSS index format must be rebuilt. `install.sh` already runs the official CVE catalogue sync/build during a fresh Kali installation.
