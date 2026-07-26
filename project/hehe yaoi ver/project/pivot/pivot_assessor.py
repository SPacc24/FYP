import ipaddress
from datetime import datetime
from typing import Any


HIGH_VALUE_SERVICES = {
    "microsoft-ds": "SMB service may support lateral movement or file share access.",
    "netbios-ssn": "NetBIOS/SMB exposure may support Windows lateral movement.",
    "ms-wbt-server": "RDP exposure may support remote access if credentials are valid.",
    "rdp": "RDP exposure may support remote access if credentials are valid.",
    "wsman": "WinRM exposure may support remote administration.",
    "ssh": "SSH exposure may support remote administration.",
    "ftp": "FTP exposure may expose files or weak authentication.",
    "http": "Web service may expose internal applications.",
    "https": "Web service may expose internal applications.",
}


class PivotAssessor:
    """
    Safe pivot-awareness module.

    This does NOT exploit or bypass anything.
    It checks whether, after a successful CALDERA operation,
    other already-scanned hosts should be treated as post-pivot targets.
    """

    def __init__(self, operation_manager=None):
        self.operation_manager = operation_manager

    def assess(
        self,
        parsed_results: dict[str, Any] | None,
        mapping_results: dict[str, Any] | None,
        operation_results: dict[str, Any] | None,
        target: str | None = None,
    ) -> dict[str, Any]:
        parsed_results = parsed_results or {}
        mapping_results = mapping_results or {}
        operation_results = operation_results or {}

        entry_host = self._entry_host(parsed_results, operation_results, target)
        operation_success = int(operation_results.get("success_count", 0) or 0) > 0

        discovered_hosts = self._extract_hosts(parsed_results, mapping_results)
        agents = self._get_live_agents()
        agent_index = self._agent_index(agents)

        candidates = []
        for host, info in discovered_hosts.items():
            if not host or host == "Unknown":
                continue
            if self._same_host(host, entry_host):
                continue

            services = info.get("services", [])
            interesting = self._interesting_services(services)
            if not interesting:
                continue

            segment_relation = self._segment_relation(entry_host, host)
            has_agent = host in agent_index

            reasons = [item["reason"] for item in interesting]
            if segment_relation == "cross_segment":
                reasons.append("Host appears to be in a different network segment from the entry host.")
            if has_agent:
                reasons.append("A live CALDERA agent is visible for this host.")

            candidates.append({
                "host": host,
                "hostname": info.get("hostname", ""),
                "os": info.get("os", "Unknown"),
                "segment": self._segment_label(host),
                "segment_relation": segment_relation,
                "has_live_agent": has_agent,
                "services": services,
                "interesting_services": interesting,
                "reasons": reasons,
                "tag": "post-pivot-candidate",
            })

        pivot_possible = operation_success and bool(candidates)

        if not operation_success:
            status = "not_applicable"
            summary = "Pivot assessment skipped because no CALDERA technique succeeded."
        elif not candidates:
            status = "no_pivot_targets"
            summary = "CALDERA succeeded, but no additional post-pivot targets were identified from the scan data."
        else:
            status = "pivot_candidates_found"
            summary = f"CALDERA succeeded on the entry host and {len(candidates)} post-pivot candidate(s) were identified."

        paths = [
            {
                "from": entry_host,
                "to": item["host"],
                "relation": item["segment_relation"],
                "reason": "; ".join(item["reasons"][:3]),
            }
            for item in candidates
        ]

        return {
            "ok": True,
            "mode": "safe_pivot_awareness",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "status": status,
            "summary": summary,
            "entry_host": entry_host,
            "operation_success": operation_success,
            "pivot_possible": pivot_possible,
            "candidate_count": len(candidates),
            "reachable_targets": candidates,
            "paths": paths,
            "risk_component": self._score_pivot(candidates, operation_success),
            "limitations": [
                "This module does not exploit systems.",
                "Reachability is inferred from authorised scan results and CALDERA agent visibility.",
                "Actual firewall or ACL enforcement should be confirmed during lab testing.",
            ],
        }

    def _entry_host(self, parsed_results, operation_results, target):
        agent_host = operation_results.get("agent_host")
        if agent_host and agent_host != "unknown":
            return str(agent_host)

        if target:
            return str(target)

        if parsed_results.get("target_ip"):
            return str(parsed_results.get("target_ip"))

        hosts = parsed_results.get("hosts") or []
        if hosts:
            return str(hosts[0].get("address", {}).get("primary", "Unknown"))

        return "Unknown"

    def _extract_hosts(self, parsed_results, mapping_results):
        hosts: dict[str, dict[str, Any]] = {}

        for host in parsed_results.get("hosts", []) or []:
            ip = str(host.get("address", {}).get("primary", "Unknown"))
            hosts.setdefault(ip, {
                "hostname": host.get("hostname", ""),
                "os": host.get("os", {}).get("name", parsed_results.get("os", "Unknown")) if isinstance(host.get("os"), dict) else parsed_results.get("os", "Unknown"),
                "services": [],
            })

            for port in host.get("port_findings", []) or []:
                hosts[ip]["services"].append(self._normalise_service(port))

        for svc in parsed_results.get("service_inventory", []) or []:
            ip = str(svc.get("host") or parsed_results.get("target_ip") or "Unknown")
            hosts.setdefault(ip, {
                "hostname": "",
                "os": parsed_results.get("os", "Unknown"),
                "services": [],
            })
            hosts[ip]["services"].append(self._normalise_service(svc))

        for vuln in mapping_results.get("vulnerabilities", []) or []:
            ip = str(vuln.get("host") or "Unknown")
            hosts.setdefault(ip, {
                "hostname": "",
                "os": parsed_results.get("os", "Unknown"),
                "services": [],
            })
            hosts[ip]["services"].append(self._normalise_service(vuln))

        for info in hosts.values():
            seen = set()
            unique = []
            for svc in info["services"]:
                key = (svc.get("port"), svc.get("protocol"), svc.get("service"))
                if key not in seen:
                    unique.append(svc)
                    seen.add(key)
            info["services"] = unique

        return hosts

    def _normalise_service(self, item):
        return {
            "port": item.get("port", "N/A"),
            "protocol": item.get("protocol", "tcp"),
            "state": item.get("state", "open"),
            "service": str(item.get("service", "unknown")).lower(),
            "product": item.get("product", ""),
            "version": item.get("version", ""),
        }

    def _interesting_services(self, services):
        results = []
        for svc in services:
            if str(svc.get("state", "open")).lower() != "open":
                continue

            name = str(svc.get("service", "")).lower()
            if name in HIGH_VALUE_SERVICES:
                results.append({
                    "port": svc.get("port"),
                    "service": name,
                    "reason": HIGH_VALUE_SERVICES[name],
                })

        return results

    def _get_live_agents(self):
        if not self.operation_manager:
            return []

        try:
            status = self.operation_manager.check_readiness()
            return status.get("trusted_online_agents") or status.get("online_agents") or []
        except Exception:
            return []

    def _agent_index(self, agents):
        index = {}
        for agent in agents or []:
            for value in [
                agent.get("host"),
                agent.get("hostname"),
                agent.get("paw"),
                agent.get("ip"),
                agent.get("host_ip"),
            ]:
                if value:
                    index[str(value).lower()] = agent
        return index

    def _same_host(self, a, b):
        return str(a or "").lower().strip() == str(b or "").lower().strip()

    def _segment_label(self, host):
        try:
            ip = ipaddress.ip_address(host)
            if ip.version == 4:
                parts = str(ip).split(".")
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except ValueError:
            pass
        return "unknown-segment"

    def _segment_relation(self, source, target):
        source_segment = self._segment_label(source)
        target_segment = self._segment_label(target)

        if "unknown" in source_segment or "unknown" in target_segment:
            return "unknown"

        return "same_segment" if source_segment == target_segment else "cross_segment"

    def _score_pivot(self, candidates, operation_success):
        if not operation_success or not candidates:
            return 0.0

        score = 0.0

        for candidate in candidates:
            score += 0.35

            if candidate.get("segment_relation") == "cross_segment":
                score += 0.45

            if candidate.get("has_live_agent"):
                score += 0.25

            score += min(len(candidate.get("interesting_services", [])) * 0.15, 0.45)

        return round(min(score, 2.0), 2)