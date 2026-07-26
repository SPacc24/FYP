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
        "cpe": cpes,
        "hostnames": sorted({_text(x) for x in identity.get("hostnames") or [] if _text(x)}),
        "domains": sorted({_text(x) for x in identity.get("domains") or [] if _text(x)}),
        "sources": sorted({_text(x) for x in sources if _text(x)}),
        "evidence_references": sorted({_text(x) for x in evidence_refs if _text(x)}),
        "endpoint": _text(identity.get("endpoint")),
        "raw": _text(identity.get("raw"))[:1200],
    }
    out["quality"] = identity_quality(out)
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
        computer = _field(script, "Computer name", "computer_name", "NetBIOS computer name", "NetBIOS_Computer_Name")
        fqdn = _field(script, "FQDN", "DNS computer name", "DNS_Computer_Name")
        domain = _field(script, "Domain name", "domain_name", "NetBIOS domain name", "NetBIOS_Domain_Name", "DNS domain name", "DNS_Domain_Name")
        forest = _field(script, "Forest name", "forest_name", "DNS tree name", "DNS_Tree_Name")
        if not any((os_name, computer, fqdn, domain, forest)):
            return None
        family = _family_from_text(os_name)
        return {
            "host": host,
            "name": os_name,
            "product": os_name,
            "family": family,
            "vendor": _vendor_from_text(family, os_name),
            "hostnames": [x for x in (computer, fqdn) if x],
            "domains": [x for x in (domain, forest) if x],
            "source": source or script_id,
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
            identity["host"] = identity.get("host") or host
            identity["source"] = source if identity.get("source") in {None, "", "nmap_os_detection", "nmap_service_os_evidence"} else identity.get("source")
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
            attrs = port.get("service_attributes") or {}
            os_values = list(port.get("os_cpe") or [])
            ostype = _text(attrs.get("ostype") if isinstance(attrs, Mapping) else "")
            if os_values or ostype:
                merge_host_identity(observations, {
                    "host": host,
                    "name": ostype,
                    "product": ostype,
                    "family": _family_from_text(ostype, *os_values),
                    "cpe": os_values,
                    "source": source,
                    "evidence_reference": evidence_reference,
                    "endpoint": endpoint,
                    "hostnames": [attrs.get("hostname")] if isinstance(attrs, Mapping) and attrs.get("hostname") else [],
                })
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


def host_identity_inventory(identity_map: Mapping[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for host in sorted(identity_map):
        identities = [deepcopy(x) for x in identity_map.get(host) or []]
        identities.sort(key=lambda x: (
            0 if x.get("build") else 1,
            0 if x.get("version") else 1,
            -int(str(x.get("accuracy") or "0")) if str(x.get("accuracy") or "").isdigit() else 0,
            _norm(x.get("product")),
        ))
        rows.append({"host": host, "identities": identities, "best": identities[0] if identities else {}})
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
