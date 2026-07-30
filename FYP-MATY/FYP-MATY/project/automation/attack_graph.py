"""Build a living attack graph from scan evidence (no hardcoded hosts)."""

from __future__ import annotations

from typing import Any

from exploitation.module_catalog import (
    PortEvidence,
    extract_port_evidence,
    get_module_catalog,
    normalise_service,
)


def _port_rows(parsed_results: dict[str, Any] | None) -> list[PortEvidence]:
    rows = extract_port_evidence(parsed_results or {})
    if rows:
        return list(rows)
    # Minimal fallback from flat ports list
    out: list[PortEvidence] = []
    target = str((parsed_results or {}).get("target") or (parsed_results or {}).get("target_ip") or "unknown")
    for port in (parsed_results or {}).get("ports") or []:
        if not isinstance(port, dict):
            continue
        try:
            pnum = int(port.get("port") or port.get("portid") or 0)
        except (TypeError, ValueError):
            continue
        if pnum <= 0:
            continue
        svc = normalise_service(str(port.get("service") or port.get("name") or ""))
        cves = port.get("cves") or []
        cve_set = frozenset(str(c).upper() for c in cves if str(c).strip())
        out.append(
            PortEvidence(
                target=str(port.get("ip") or port.get("target") or target),
                port=pnum,
                service=svc,
                product=str(port.get("product") or ""),
                version=str(port.get("version") or ""),
                cves=cve_set,
            )
        )
    return out


def build_attack_graph(
    parsed_results: dict[str, Any] | None,
    *,
    flags: set[str] | None = None,
    catalog_keys: list[str] | None = None,
) -> dict[str, Any]:
    """Return nodes/edges suitable for mission UI and debrief."""
    flags = set(flags or [])
    rows = _port_rows(parsed_results)
    catalog = get_module_catalog()

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    internet_id = "zone:edge"
    nodes[internet_id] = {
        "id": internet_id,
        "kind": "zone",
        "label": "Authorised edge / Ethernet scope",
        "status": "active",
    }

    matched_keys: set[str] = set(catalog_keys or [])
    hosts_with_catalog = set()

    for row in rows:
        host_id = f"host:{row.target}"
        if host_id not in nodes:
            nodes[host_id] = {
                "id": host_id,
                "kind": "host",
                "label": row.target,
                "ip": row.target,
                "status": "discovered",
                "services": [],
            }
            edges.append(
                {
                    "id": f"e:{internet_id}->{host_id}",
                    "source": internet_id,
                    "target": host_id,
                    "kind": "discovery",
                    "label": "in scope",
                }
            )

        svc_id = f"svc:{row.target}:{row.port}"
        label = f"{row.service or 'unknown'}/{row.port}"
        if row.product:
            label = f"{label} ({row.product} {row.version})".strip()
        status = "exposed"
        if row.cves:
            status = "cve_candidate"

        nodes[svc_id] = {
            "id": svc_id,
            "kind": "service",
            "label": label,
            "host": row.target,
            "port": row.port,
            "service": row.service,
            "product": row.product,
            "version": row.version,
            "cves": sorted(row.cves),
            "status": status,
        }
        nodes[host_id]["services"].append(svc_id)
        edges.append(
            {
                "id": f"e:{host_id}->{svc_id}",
                "source": host_id,
                "target": svc_id,
                "kind": "exposes",
                "label": str(row.port),
            }
        )

        hits = catalog.matching_msf_modules(row)
        for hit in hits:
            matched_keys.add(hit.key)
            hosts_with_catalog.add(row.target)
            mod_id = f"mod:{hit.key}:{row.target}:{row.port}"
            nodes[mod_id] = {
                "id": mod_id,
                "kind": "module",
                "label": hit.title,
                "catalog_key": hit.key,
                "module_type": hit.module_type,
                "risk": hit.risk,
                "status": "proposed",
            }
            edges.append(
                {
                    "id": f"e:{svc_id}->{mod_id}",
                    "source": svc_id,
                    "target": mod_id,
                    "kind": "catalog_match",
                    "label": hit.module_type,
                }
            )

        web_hits = catalog.matching_web_profiles(row)
        for profile in web_hits:
            matched_keys.add(profile.key)
            hosts_with_catalog.add(row.target)
            wid = f"web:{profile.key}:{row.target}:{row.port}"
            nodes[wid] = {
                "id": wid,
                "kind": "web_profile",
                "label": profile.title,
                "catalog_key": profile.key,
                "risk": profile.risk,
                "status": "proposed",
            }
            edges.append(
                {
                    "id": f"e:{svc_id}->{wid}",
                    "source": svc_id,
                    "target": wid,
                    "kind": "web_match",
                    "label": "web",
                }
            )

    if flags.intersection({"branch_ms17_suppressed", "ms17_not_exploitable"}):
        for nid, node in list(nodes.items()):
            if node.get("kind") == "module" and "ms17_010_exploit" in str(node.get("catalog_key") or ""):
                node["status"] = "suppressed"
                node["label"] = f"{node['label']} (suppressed — not evidenced)"

    if flags.intersection({"foothold_proved"}):
        for nid, node in nodes.items():
            if node.get("kind") == "host":
                node["status"] = "foothold" if node.get("status") == "discovered" else node["status"]

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {
            "hosts": sum(1 for n in nodes.values() if n["kind"] == "host"),
            "services": sum(1 for n in nodes.values() if n["kind"] == "service"),
            "catalog_matches": len(matched_keys),
            "hosts_with_catalog": len(hosts_with_catalog),
        },
        "matched_catalog_keys": sorted(matched_keys),
    }
