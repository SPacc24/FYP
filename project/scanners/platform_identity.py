from __future__ import annotations

"""Evidence-derived host/platform identity handling.

The scanner deliberately keeps host operating-system identity separate from
application/service identity.  This module only parses and merges evidence that
collectors actually returned; it contains no expected targets, product versions,
CVE identifiers, lab addresses, or vulnerability-specific shortcuts.
"""

import re
from copy import deepcopy
from typing import Any, Iterable, Mapping


def _text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", _text(value).lower()).strip()


def cpe_parts(value: str) -> tuple[str, str, str, str] | None:
    raw = _text(value).lower()
    if raw.startswith("cpe:2.3:"):
        parts = raw.split(":")
        if len(parts) >= 6:
            return parts[2], parts[3], parts[4], parts[5]
    if raw.startswith("cpe:/"):
        parts = raw.split(":")
        # CPE 2.2 permits product-only names such as
        # cpe:/o:microsoft:windows with no explicit version component.
        if len(parts) >= 4:
            return parts[1].lstrip("/"), parts[2], parts[3], parts[4] if len(parts) >= 5 else ""
    return None


def os_cpes(values: Iterable[Any]) -> list[str]:
    out: list[str] = []
    for value in values or []:
        clean = _text(value)
        parts = cpe_parts(clean)
        if parts and parts[0] == "o" and clean not in out:
            out.append(clean)
    return out


def _family_from_text(*values: Any) -> str:
    """Classify only broad OS family terminology present in observed text."""
    blob = " ".join(_norm(v) for v in values if _text(v))
    if "windows" in blob:
        return "Windows"
    if any(token in blob for token in ("macos", "mac os", "darwin", "os x")):
        return "macOS"
    if "ios" in blob:
        return "iOS"
    if "linux" in blob:
        return "Linux"
    if "freebsd" in blob:
        return "FreeBSD"
    if "openbsd" in blob:
        return "OpenBSD"
    if "netbsd" in blob:
        return "NetBSD"
    if "solaris" in blob or "sunos" in blob:
        return "Solaris"
    return ""


def _vendor_from_text(family: str, *values: Any) -> str:
    blob = " ".join(_norm(v) for v in values if _text(v))
    if "microsoft" in blob or family == "Windows":
        return "Microsoft"
    if "apple" in blob or family in {"macOS", "iOS"}:
        return "Apple"
    return ""


def _concrete_cpe_version(values: Iterable[Any]) -> str:
    versions: set[str] = set()
    for value in values or []:
        parts = cpe_parts(_text(value))
        if not parts or parts[0] != "o":
            continue
        version = _text(parts[3])
        if version not in {"", "*", "-"}:
            versions.add(version)
    return next(iter(versions)) if len(versions) == 1 else ""


def identity_quality(identity: Mapping[str, Any]) -> str:
    if _text(identity.get("evidence_kind")) == "service_os_hint":
        return "Service-level OS hint (supporting only)"
    # Nmap OS detection is explicitly probabilistic.  Never describe one of its
    # hypotheses as an "exact" release merely because an osclass contains an
    # osgen/CPE value.  Exactness is reserved for directly asserted evidence.
    if _text(identity.get("evidence_kind")) == "probabilistic_fingerprint":
        return "Probabilistic OS fingerprint"
    if (
        _text(identity.get("build"))
        and _text(identity.get("family")) == "Windows"
        and not identity_is_precise_for_cve(identity)
    ):
        return "Build observed; exact Windows release unresolved"
    if _text(identity.get("build")):
        return "Exact build observed"
    if _text(identity.get("release")) and not _looks_like_range(identity.get("release")):
        return "Exact release observed"
    if _text(identity.get("version")) and not _looks_like_range(identity.get("version")):
        return "Version evidence observed"
    if os_cpes(identity.get("cpe") or []):
        return "OS CPE observed"
    product = _text(identity.get("product") or identity.get("name"))
    if product and not _looks_like_range(product):
        return "Product identity observed"
    if _text(identity.get("family")):
        return "OS family only"
    return "Incomplete identity"


def _looks_like_range(value: Any) -> bool:
    text = _text(value)
    return bool(
        re.search(r"\b\d+(?:\.\d+)*\s+(?:-|to|through|thru)\s+\d+(?:\.\d+)*\b", text, re.I)
        or re.search(r"\b(?:windows|macos|os x)\s+\d+\s*(?:-|to)\s*\d+\b", text, re.I)
    )


def normalise_host_identity(identity: Mapping[str, Any]) -> dict[str, Any]:
    cpes = os_cpes(identity.get("cpe") or identity.get("os_cpe") or [])
    name = _text(identity.get("name") or identity.get("product"))
    family = _text(identity.get("family")) or _family_from_text(name, identity.get("vendor"), *cpes)
    vendor = _text(identity.get("vendor")) or _vendor_from_text(family, name, *cpes)
    generation = _text(identity.get("generation"))
    release = _text(identity.get("release")) or generation
    version = _text(identity.get("version")) or _concrete_cpe_version(cpes)
    build = _text(identity.get("build"))
    product = _text(identity.get("product")) or name
    if not product and family:
        product = f"{vendor} {family}".strip()
    sources = identity.get("sources") or identity.get("source") or []
    if isinstance(sources, str):
        sources = [sources]
    evidence_refs = identity.get("evidence_references") or identity.get("evidence_reference") or identity.get("raw_evidence_file") or []
    if isinstance(evidence_refs, str):
        evidence_refs = [evidence_refs]
    out = {
        "scope": "host_os",
        "host": _text(identity.get("host")),
        "name": name or product,
        "vendor": vendor,
        "family": family,
        "product": product,
        "release": release,
        "version": version,
        "build": build,
        "architecture": _text(identity.get("architecture")),
        "generation": generation,
        "device_type": _text(identity.get("device_type")),
        "accuracy": _text(identity.get("accuracy")),
        "evidence_kind": _text(identity.get("evidence_kind")),
        "cpe": cpes,
        "hostnames": sorted({_text(x) for x in identity.get("hostnames") or [] if _text(x)}),
        "domains": sorted({_text(x) for x in identity.get("domains") or [] if _text(x)}),
        "sources": sorted({_text(x) for x in sources if _text(x)}),
        "evidence_references": sorted({_text(x) for x in evidence_refs if _text(x)}),
        "endpoint": _text(identity.get("endpoint")),
        "raw": _text(identity.get("raw"))[:1200],
        "resolution_basis": _text(identity.get("resolution_basis")),
        "resolution_candidate": bool(identity.get("resolution_candidate")),
        "resolution_source": _text(identity.get("resolution_source")),
    }
    out["quality"] = (
        "Microsoft advisory build-line product candidate"
        if out["resolution_candidate"]
        else identity_quality(out)
    )
    return out


def _identity_signature(identity: Mapping[str, Any]) -> tuple[str, str, str, str, tuple[str, ...]]:
    return (
        _norm(identity.get("vendor")),
        _norm(identity.get("product") or identity.get("name")),
        _norm(identity.get("version") or identity.get("release")),
        _norm(identity.get("build")),
        tuple(sorted(_norm(x) for x in identity.get("cpe") or [])),
    )


def merge_host_identity(observations: list[dict[str, Any]], identity: Mapping[str, Any]) -> None:
    clean = normalise_host_identity(identity)
    if not (clean.get("product") or clean.get("family") or clean.get("cpe") or clean.get("build")):
        return
    sig = _identity_signature(clean)
    for existing in observations:
        if _identity_signature(existing) != sig:
            continue
        for key in ("hostnames", "domains", "sources", "evidence_references", "cpe"):
            existing[key] = sorted(set(existing.get(key) or []) | set(clean.get(key) or []))
        for key in ("vendor", "family", "product", "release", "version", "build", "architecture", "generation", "device_type", "accuracy", "endpoint", "raw"):
            if not existing.get(key) and clean.get(key):
                existing[key] = clean[key]
        # If duplicate evidence arrives through multiple collectors, retain the
        # strongest collection semantics rather than whichever row was parsed
        # first. This is generic provenance reconciliation, not product mapping.
        if clean.get("evidence_kind") and (
            not existing.get("evidence_kind")
            or _identity_authority(clean) < _identity_authority(existing)
        ):
            existing["evidence_kind"] = clean["evidence_kind"]
        existing["quality"] = identity_quality(existing)
        return
    observations.append(clean)


def _field(script: Mapping[str, Any], *names: str) -> str:
    fields = script.get("fields") or {}
    if not isinstance(fields, Mapping):
        fields = {}
    wanted = {_norm(x) for x in names}
    for key, value in fields.items():
        if _norm(key) not in wanted:
            continue
        if isinstance(value, list):
            return _text(value[0] if value else "")
        return _text(value)
    output = _text(script.get("output"))
    for name in names:
        match = re.search(rf"(?im)^\s*{re.escape(name)}\s*:\s*(.+?)\s*$", output)
        if match:
            return _text(match.group(1))
    return ""


def _script_identity(script: Mapping[str, Any], host: str, source: str, evidence_reference: str, endpoint: str = "") -> dict[str, Any] | None:
    script_id = _text(script.get("id")).lower()
    output = _text(script.get("output"))
    if not script_id:
        return None

    if script_id == "smb-os-discovery":
        os_name = _field(script, "OS", "os")
        os_cpe = _field(script, "OS CPE", "CPE", "cpe")
        computer = _field(script, "Computer name", "computer_name", "NetBIOS computer name", "NetBIOS_Computer_Name")
        fqdn = _field(script, "FQDN", "DNS computer name", "DNS_Computer_Name")
        domain = _field(script, "Domain name", "domain_name", "NetBIOS domain name", "NetBIOS_Domain_Name", "DNS domain name", "DNS_Domain_Name")
        forest = _field(script, "Forest name", "forest_name", "DNS tree name", "DNS_Tree_Name")
        if not any((os_name, os_cpe, computer, fqdn, domain, forest)):
            return None
        family = _family_from_text(os_name, os_cpe)
        return {
            "host": host,
            "name": os_name,
            "product": os_name,
            "family": family,
            "vendor": _vendor_from_text(family, os_name, os_cpe),
            "cpe": os_cpes([os_cpe]) if os_cpe else [],
            "hostnames": [x for x in (computer, fqdn) if x],
            "domains": [x for x in (domain, forest) if x],
            "source": source or script_id,
            "evidence_kind": "protocol_assertion",
            "evidence_reference": evidence_reference,
            "endpoint": endpoint,
            "raw": output,
        }

    if script_id.endswith("ntlm-info"):
        build = _field(script, "Product_Version", "Product Version", "product_version")
        computer = _field(script, "NetBIOS_Computer_Name", "NetBIOS Computer Name", "DNS_Computer_Name", "DNS Computer Name")
        dns_computer = _field(script, "DNS_Computer_Name", "DNS Computer Name")
        domain = _field(script, "NetBIOS_Domain_Name", "NetBIOS Domain Name", "DNS_Domain_Name", "DNS Domain Name", "DNS_Tree_Name")
        if not any((build, computer, dns_computer, domain)):
            return None
        # Product_Version in these Microsoft NTLM discovery scripts describes
        # the remote Windows product version.  We retain the numeric build as
        # evidence without mapping it to a marketing edition in code.
        return {
            "host": host,
            "name": "Microsoft Windows" if build else "",
            "product": "Microsoft Windows" if build else "",
            "family": "Windows" if build else "",
            "vendor": "Microsoft" if build else "",
            "version": build,
            "build": build,
            "hostnames": [x for x in (computer, dns_computer) if x],
            "domains": [domain] if domain else [],
            "source": source or script_id,
            "evidence_kind": "protocol_assertion",
            "evidence_reference": evidence_reference,
            "endpoint": endpoint,
            "raw": output,
        }
    return None


def extract_host_identities_from_nmap(parsed: Mapping[str, Any], *, source: str = "nmap", evidence_reference: str = "") -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for host_row in parsed.get("hosts") or []:
        if not isinstance(host_row, Mapping):
            continue
        host = _text(host_row.get("address"))
        for raw_identity in host_row.get("os_identities") or []:
            if not isinstance(raw_identity, Mapping):
                continue
            identity = dict(raw_identity)
            # Nmap may attach OS/CPE hints to an individual service probe. Those
            # hints describe that service fingerprint, not the host OS. Retain
            # them on the service row but never promote them into host identity.
            if _text(identity.get("evidence_kind")) == "service_os_hint" or _text(identity.get("source")) == "nmap_service_os_evidence":
                continue
            identity["host"] = identity.get("host") or host
            identity["source"] = source if identity.get("source") in {None, "", "nmap_os_detection"} else identity.get("source")
            identity["evidence_kind"] = identity.get("evidence_kind") or "probabilistic_fingerprint"
            identity["evidence_reference"] = evidence_reference or identity.get("raw_evidence_file")
            identity["hostnames"] = list(host_row.get("hostnames") or [])
            merge_host_identity(observations, identity)
        for script in host_row.get("scripts") or []:
            if isinstance(script, Mapping):
                identity = _script_identity(script, host, source, evidence_reference)
                if identity:
                    merge_host_identity(observations, identity)
        for port in host_row.get("ports") or []:
            if not isinstance(port, Mapping):
                continue
            endpoint = f"{port.get('port')}/{port.get('protocol')}"
            # Per-service ``ostype`` / OS CPE values stay attached to the
            # service observation. They are not host-level identity evidence.
            # Host identity requires host-level OS detection or a protocol
            # assertion such as SMB/NTLM host identity evidence.
            for script in port.get("scripts") or []:
                if isinstance(script, Mapping):
                    identity = _script_identity(script, host, source, evidence_reference, endpoint)
                    if identity:
                        merge_host_identity(observations, identity)
    return observations


def merge_host_identity_map(identity_map: dict[str, list[dict[str, Any]]], identities: Iterable[Mapping[str, Any]]) -> None:
    for identity in identities:
        host = _text(identity.get("host"))
        if not host:
            continue
        bucket = identity_map.setdefault(host, [])
        merge_host_identity(bucket, identity)



def _reported_accuracy(identity: Mapping[str, Any]) -> int | None:
    value = _text(identity.get("accuracy"))
    return int(value) if value.isdigit() else None


def _identity_authority(identity: Mapping[str, Any]) -> int:
    """Return evidence authority based on collection semantics, not OS facts.

    Lower values are stronger.  The ordering is generic and contains no target,
    product-release, build, CVE, or vulnerability-specific knowledge.
    """
    kind = _text(identity.get("evidence_kind"))
    if kind in {"operator_inventory", "authenticated_inventory"}:
        return 0
    if kind in {"protocol_assertion", "protocol_correlation"}:
        return 1
    if kind == "official_product_resolution":
        # Vendor advisory product resolution is metadata, not observed identity.
        # Keep it below even probabilistic scan evidence and never make it a
        # CVE applicability input.
        return 4
    if kind == "service_os_hint":
        return 2
    if kind == "probabilistic_fingerprint":
        return 3
    # Unknown collector semantics remain usable, but never outrank evidence
    # explicitly marked as directly observed/authenticated.
    return 2


def _fingerprint_is_ambiguous(identity: Mapping[str, Any]) -> bool:
    product = _text(identity.get("product") or identity.get("name"))
    if not product:
        return True
    # Ambiguity is detected from the observed fingerprint grammar itself.  This
    # does not encode any operating-system names, releases, or version map.
    return bool(re.search(r"\s+or\s+", product, re.I) or _looks_like_range(product))


def identity_is_precise_for_cve(identity: Mapping[str, Any]) -> bool:
    """Return whether a host identity is precise enough for OS CVE matching.

    A build number does not turn a generic or ranged marketing label into an
    exact Windows product. This prevents observations such as "Windows 7 - 10"
    plus an NTLM build from expanding into every CVE for several releases.
    No build-to-release table or target-specific rule is used.
    """
    product = _text(identity.get("product") or identity.get("name"))
    family = _text(identity.get("family"))
    if not product or _looks_like_range(product) or _fingerprint_is_ambiguous(identity):
        return False

    cpes = os_cpes(identity.get("cpe") or [])
    if cpes:
        concrete_products = []
        for cpe in cpes:
            parts = cpe_parts(cpe)
            if not parts:
                continue
            _part, _vendor, cpe_product, _version = parts
            normalised = _norm(cpe_product)
            if normalised and normalised not in {"windows", "windows server"}:
                concrete_products.append(normalised)
        if concrete_products:
            return True

    if family == "Windows":
        generic = {
            "windows",
            "microsoft windows",
            "windows server",
            "microsoft windows server",
        }
        if _norm(product) in generic:
            return False
        # A directly observed release-bearing product name is sufficient; the
        # numeric build remains independent supporting evidence.
        return bool(
            re.search(r"\b(?:windows\s+)?(?:server\s+)?\d{1,4}[a-z0-9]*\b", _norm(product))
            or _text(identity.get("release"))
        )

    return bool(
        cpes
        or _text(identity.get("version"))
        or _text(identity.get("release"))
        or _text(identity.get("build"))
    )


def _correlate_complementary_direct_identities(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Join complementary direct host-OS observations without product mapping.

    Some protocols expose a concrete OS product/CPE while another protocol on
    the same host exposes the numeric OS build.  Neither observation should be
    rewritten into a release using an internal lookup table.  When the direct
    evidence agrees on host, OS family/vendor, and exactly one build value is
    observed, create a provenance-preserving composite identity that carries
    both facts.  Original observations remain in the inventory unchanged.
    """
    correlated = [dict(row) for row in rows]
    by_family: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if _identity_authority(row) > 1:
            continue
        family_key = _norm(row.get("family"))
        if not family_key:
            continue
        by_family.setdefault(family_key, []).append(row)

    for family_rows in by_family.values():
        direct_rows = [
            row for row in family_rows
            if _text(row.get("evidence_kind")) in {"protocol_assertion", "authenticated_inventory", "operator_inventory"}
        ]
        build_values = {
            _text(row.get("build") or row.get("version"))
            for row in direct_rows
            if _text(row.get("build") or row.get("version"))
        }
        if len(build_values) != 1:
            continue
        observed_build = next(iter(build_values))

        product_rows = [
            row for row in direct_rows
            if identity_is_precise_for_cve(row)
            and not _text(row.get("build") or row.get("version"))
        ]
        if not product_rows:
            continue

        build_rows = [
            row for row in direct_rows
            if _text(row.get("build") or row.get("version")) == observed_build
        ]
        if not build_rows:
            continue

        for product_row in product_rows:
            product_vendor = _norm(product_row.get("vendor"))
            compatible_build_rows = [
                row for row in build_rows
                if not product_vendor
                or not _norm(row.get("vendor"))
                or _norm(row.get("vendor")) == product_vendor
            ]
            if not compatible_build_rows:
                continue

            sources = set(product_row.get("sources") or [])
            references = set(product_row.get("evidence_references") or [])
            hostnames = set(product_row.get("hostnames") or [])
            domains = set(product_row.get("domains") or [])
            cpes = set(product_row.get("cpe") or [])
            for build_row in compatible_build_rows:
                sources.update(build_row.get("sources") or [])
                references.update(build_row.get("evidence_references") or [])
                hostnames.update(build_row.get("hostnames") or [])
                domains.update(build_row.get("domains") or [])
                cpes.update(build_row.get("cpe") or [])

            composite = normalise_host_identity({
                **product_row,
                "version": observed_build,
                "build": observed_build,
                "cpe": sorted(cpes),
                "hostnames": sorted(hostnames),
                "domains": sorted(domains),
                "sources": sorted(sources),
                "evidence_references": sorted(references),
                "evidence_kind": "protocol_correlation",
                "resolution_basis": "correlated_complementary_direct_host_identity_evidence",
                "resolution_candidate": False,
                "resolution_source": "",
            })
            if not any(_identity_signature(existing) == _identity_signature(composite) for existing in correlated):
                correlated.append(composite)
    return correlated


def reconcile_host_identities(identities: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Retain all evidence while selecting only defensible CVE identities.

    Direct evidence outranks probabilistic fingerprints.  When only Nmap-style
    probabilistic fingerprints exist, only the highest reported-accuracy,
    unambiguous hypothesis is eligible.  Equal-confidence conflicting guesses
    remain visible but are not promoted into CVE applicability.
    """
    rows = [normalise_host_identity(x) for x in identities or []]
    if not rows:
        return []
    rows = _correlate_complementary_direct_identities(rows)
    global_strongest = min(_identity_authority(row) for row in rows)

    by_family: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        family_key = _norm(row.get("family")) or "__unknown__"
        by_family.setdefault(family_key, []).append(row)

    for family_rows in by_family.values():
        strongest = min(_identity_authority(row) for row in family_rows)
        strongest_rows = [row for row in family_rows if _identity_authority(row) == strongest]

        if global_strongest < 3 and strongest >= 3:
            for row in family_rows:
                row["cve_eligible"] = False
                row["reconciliation_status"] = "supporting_only"
                row["reconciliation_reason"] = (
                    "Probabilistic OS fingerprint retained as evidence but excluded from CVE applicability because stronger directly observed host-OS evidence exists."
                )
                row["authority_tier"] = _identity_authority(row)
            continue

        if strongest < 3:
            # A stronger direct observation exists. Preserve all weaker rows as
            # audit evidence, but do not let them expand CVE applicability. If
            # complementary direct observations were correlated into a richer
            # product+version identity, the unversioned component observation is
            # supporting evidence rather than a second CVE lookup input.
            correlation_rows = [
                row for row in strongest_rows
                if _text(row.get("evidence_kind")) == "protocol_correlation"
            ]
            for row in family_rows:
                eligible = _identity_authority(row) == strongest
                subsumed_by_correlation = False
                if eligible and correlation_rows and not _text(row.get("build") or row.get("version")):
                    row_product = _norm(row.get("product") or row.get("name"))
                    row_cpes = set(os_cpes(row.get("cpe") or []))
                    for composite in correlation_rows:
                        composite_product = _norm(composite.get("product") or composite.get("name"))
                        composite_cpes = set(os_cpes(composite.get("cpe") or []))
                        if row_product and row_product == composite_product and (
                            not row_cpes or not composite_cpes or row_cpes <= composite_cpes
                        ):
                            subsumed_by_correlation = True
                            break
                if subsumed_by_correlation:
                    eligible = False

                row["cve_eligible"] = eligible
                row["reconciliation_status"] = "authoritative" if eligible else "supporting_only"
                if eligible:
                    row["reconciliation_reason"] = "Highest-authority directly observed host identity for this OS family."
                elif subsumed_by_correlation:
                    row["reconciliation_reason"] = (
                        "Direct host identity retained as source evidence; a correlated direct identity carries the same product/CPE plus the independently observed version/build for CVE applicability."
                    )
                else:
                    row["reconciliation_reason"] = "Lower-authority host identity retained as evidence but excluded from CVE applicability."
                row["authority_tier"] = _identity_authority(row)
            continue

        # Only probabilistic fingerprints are available.  Use Nmap's own
        # reported accuracy ordering; do not invent an internal confidence score.
        accuracies = [_reported_accuracy(row) for row in strongest_rows]
        numeric = [value for value in accuracies if value is not None]
        highest = max(numeric) if numeric else None
        contenders = [
            row for row in strongest_rows
            if highest is None or _reported_accuracy(row) == highest
        ]
        unambiguous = [row for row in contenders if not _fingerprint_is_ambiguous(row)]
        signatures = {_identity_signature(row) for row in unambiguous}
        uniquely_resolved = len(signatures) == 1
        chosen_sig = next(iter(signatures)) if uniquely_resolved else None

        for row in family_rows:
            eligible = bool(chosen_sig and _identity_signature(row) == chosen_sig)
            row["cve_eligible"] = eligible
            row["reconciliation_status"] = "fallback_fingerprint" if eligible else "supporting_only"
            if eligible:
                row["reconciliation_reason"] = "Highest reported-accuracy unambiguous OS fingerprint; no stronger direct identity was observed."
            elif row in contenders and _fingerprint_is_ambiguous(row):
                row["reconciliation_reason"] = "Ambiguous probabilistic OS fingerprint retained as evidence but excluded from CVE applicability."
            elif row in contenders and not uniquely_resolved:
                row["reconciliation_reason"] = "Conflicting equal-authority OS fingerprints retained as evidence; no single identity was promoted to CVE applicability."
            else:
                row["reconciliation_reason"] = "Lower-ranked probabilistic OS fingerprint retained as evidence but excluded from CVE applicability."
            row["authority_tier"] = _identity_authority(row)

    for row in rows:
        if _text(row.get("evidence_kind")) == "service_os_hint":
            row["cve_eligible"] = False
            row["reconciliation_status"] = "service_hint_only"
            row["reconciliation_reason"] = (
                "Service-level OS/CPE fingerprint retained as endpoint context only; "
                "it is not host operating-system evidence and cannot drive host CVE applicability."
            )
            row["authority_tier"] = _identity_authority(row)
            row["quality"] = identity_quality(row)
            continue
        if bool(row.get("resolution_candidate")) or _text(row.get("evidence_kind")) == "official_product_resolution":
            row["cve_eligible"] = False
            row["reconciliation_status"] = "advisory_context_only"
            row["reconciliation_reason"] = (
                "Microsoft advisory product/build metadata is retained only as remediation context; "
                "it is not observed host identity and cannot drive CVE applicability."
            )
            row["authority_tier"] = _identity_authority(row)
            row["quality"] = identity_quality(row)
            continue
        if row.get("cve_eligible") and not identity_is_precise_for_cve(row):
            row["cve_eligible"] = False
            row["reconciliation_status"] = "identity_evidence_gap"
            row["reconciliation_reason"] = (
                "Host identity was retained as evidence but is too generic or "
                "ambiguous for operating-system CVE applicability."
            )
            row["quality"] = identity_quality(row)

    return rows


def host_identity_inventory(identity_map: Mapping[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for host in sorted(identity_map):
        identities = reconcile_host_identities(identity_map.get(host) or [])
        identities.sort(key=lambda x: (
            _identity_authority(x),
            0 if x.get("cve_eligible") else 1,
            0 if x.get("build") else 1,
            0 if x.get("version") else 1,
            -(_reported_accuracy(x) or 0),
            _norm(x.get("product")),
        ))
        cve_identities = [deepcopy(x) for x in identities if x.get("cve_eligible")]
        rows.append({
            "host": host,
            "identities": identities,
            "cve_identities": cve_identities,
            "best": cve_identities[0] if cve_identities else (identities[0] if identities else {}),
        })
    return rows


def host_identity_gaps(identity_map: Mapping[str, list[dict[str, Any]]], hosts: Iterable[str]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for host in hosts:
        identities = list(identity_map.get(str(host)) or [])
        if not identities:
            gaps.append({
                "host": str(host),
                "scope": "host_os",
                "observed_identity": "Not established",
                "remaining_gap": "Operating-system identity not established",
                "quality": "Incomplete identity",
            })
            continue
        best = host_identity_inventory({str(host): identities})[0]["best"]
        missing: list[str] = []
        if not best.get("product"):
            missing.append("product")
        if not (best.get("version") or best.get("release") or best.get("build")):
            missing.append("release/build")
        if missing:
            gaps.append({
                "host": str(host),
                "scope": "host_os",
                "observed_identity": _text(best.get("product") or best.get("family") or best.get("name")) or "OS family evidence",
                "remaining_gap": "Exact " + " and ".join(missing) + " not established",
                "quality": best.get("quality") or identity_quality(best),
            })
    return gaps


def _service_component_identity(service: Mapping[str, Any], identity: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return a directly observed platform/component identity from a service row.

    Components are only created from collector observations that explicitly
    identify a distinct software layer (for example a connector).  The scanner
    never manufactures operating-system subsystems or filesystem components
    from CVE prose.
    """
    kind = _text(identity.get("kind")).lower()
    if kind not in {"connector", "platform_component", "runtime_component", "protocol_component"}:
        return None
    product = _text(identity.get("product"))
    version = _text(identity.get("version"))
    cpes = []
    for raw in identity.get("cpe") or []:
        clean = _text(raw)
        parts = cpe_parts(clean)
        if parts and parts[0] == "a" and clean not in cpes:
            cpes.append(clean)
    if not (product or cpes):
        return None
    sources = identity.get("sources") or identity.get("source") or []
    if isinstance(sources, str):
        sources = [sources]
    return {
        "scope": "platform_component",
        "host": _text(service.get("host")),
        "port": service.get("port"),
        "protocol": _text(service.get("protocol")),
        "service": _text(identity.get("service") or service.get("service")),
        "kind": kind,
        "vendor": _text(identity.get("vendor")),
        "product": product,
        "version": version,
        "cpe": cpes,
        "sources": sorted({_text(x) for x in sources if _text(x)}),
        "evidence": _text(identity.get("evidence"))[:1200],
    }


def platform_component_inventory(services: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Inventory directly observed non-host software components.

    This inventory is intentionally conservative.  A component only exists in
    the output when a collector observed it as a distinct layer; absence of a
    component observation does not mean that the component is absent.
    """
    rows: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for service in services or []:
        for identity in service.get("observed_identities") or []:
            if not isinstance(identity, Mapping):
                continue
            row = _service_component_identity(service, identity)
            if not row:
                continue
            sig = (
                row.get("host"), row.get("port"), row.get("protocol"),
                _norm(row.get("product")), _norm(row.get("version")),
                tuple(sorted(_norm(x) for x in row.get("cpe") or [])),
            )
            if sig in seen:
                continue
            seen.add(sig)
            rows.append(row)
    return sorted(rows, key=lambda row: (
        _text(row.get("host")), int(row.get("port") or 0), _text(row.get("product")), _text(row.get("version"))
    ))
