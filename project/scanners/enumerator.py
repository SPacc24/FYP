
from __future__ import annotations
import json, os, re, ipaddress, contextvars, threading, logging, time, random, socket, copy
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from storage import scan_store
from config import Config
from . import command_builders
from . import match_basis as match_basis_registry
from .targets import expand_target_input, is_private_ip
from .tooling import which, outfile, run_cmd as _run_cmd
from .parsers import detect_tool_error, parse_httpx_jsonl, parse_nmap_xml
from .fingerprint_validator import validate_service_fingerprint
from .acl_mapper import detect_firewall_acl
from .ssh_crypto_intel import collect_ssh_cryptography
from .mitre_cve import (
    OFFICIAL_CVE_SOURCE,
    search_with_held as mitre_search_with_held,
    search_component_candidates as mitre_search_component_candidates,
    status as mitre_status,
)
from .nvd_client import (
    lookup_cve_metrics as nvd_lookup_cve_metrics,
    status as nvd_status,
)
from .msrc_client import lookup_cve_remediations as msrc_lookup_cve_remediations, status as msrc_status
from .cisa_kev import enrich_cve_rows as enrich_cisa_kev_rows
from .windows_patch_inventory import collect_windows_patch_inventory, inventory_host_identity, windows_target_applicability
from .windows_patch_applicability import enrich_windows_patch_states
from .windows_advisory import (
    status as windows_advisory_status,
    corroborate_cves_for_observed_windows_context as windows_advisory_corroborate_cves_for_observed_windows_context,
)
from .cpe_utils import parse_cpe
from .scan_profiles import normalise_scan_options, is_tool_enabled, selected_ports
from .collector_plan import setting as collector_setting, nse_script_preflight
from .result_contracts import (
    LIFECYCLE_LABELS,
    analyse_nmap_port_batch,
    build_endpoint_coverage,
    build_selected_plan_readiness,
    derive_result_state,
    execution_lifecycle,
)
from .scoring_policy import cvss_verifier_status, apply_cvss_selection
from .evidence_recovery import (
    collector_needed, merge_endpoint_observations, missing_evidence_types, recovery_candidates,
    recovery_intensity_ladder, recovery_port_batches, recovery_snapshot,
)
from .platform_identity import (
    extract_host_identities_from_nmap, merge_host_identity_map, host_identity_inventory,
    host_identity_gaps, identity_is_precise_for_cve, platform_component_inventory,
)
from .objectives import infer_objectives, evidence_gaps_for_service
from .passive_intel import (
    build_passive_summary, build_relationship_graph, candidate_domains, collect_certificate_transparency,
    collect_dns, collect_reverse_dns, collect_tls, infer_passive_findings, load_fingerprints,
    build_dns_relationships, build_certificate_correlation, load_passive_policy, write_passive_package,
)
from .active_validation import (
    build_active_summary, collect_api_discovery, collect_container_exposure, collect_kubernetes_exposure,
    collect_targeted_web_discovery, collect_vpn_validation, collect_federation_detection, collect_tls_intelligence, build_noise_evaluation, load_active_policy, write_active_package, service_url, _fetch, parse_external_validation, parse_external_result, build_information_gathering_summary,
)
from .enterprise_readiness import (
    EnterprisePolicyError, build_decision_register, build_enterprise_readiness_summary,
    build_evidence_manifest, load_engagement_policy,
    load_enterprise_review_policy, validate_scope,
)
from enumeration import build_enumeration_intelligence, build_operational_maturity_package


_CURRENT_SCAN_ID = contextvars.ContextVar('current_scan_id', default='')

logger = logging.getLogger(__name__)

# Phase 3 can contain targets reached only through the operator-established
# SOCKS pivot. Keep the access map keyed by scan ID because TCP discovery
# batches run in worker threads where ContextVar values are not inherited.
_PIVOT_TARGETS_BY_SCAN: dict[str, set[str]] = {}
_PIVOT_TARGETS_LOCK = threading.Lock()


def _register_pivot_targets(scan_id: str, targets: Iterable[str]) -> set[str]:
    normalised: set[str] = set()
    for value in targets or []:
        try:
            normalised.add(str(ipaddress.ip_address(str(value).strip())))
        except ValueError:
            continue
    with _PIVOT_TARGETS_LOCK:
        if normalised:
            _PIVOT_TARGETS_BY_SCAN[str(scan_id)] = normalised
        else:
            _PIVOT_TARGETS_BY_SCAN.pop(str(scan_id), None)
    return normalised


def _pivot_targets(scan_id: str) -> set[str]:
    with _PIVOT_TARGETS_LOCK:
        return set(_PIVOT_TARGETS_BY_SCAN.get(str(scan_id)) or set())


def _clear_pivot_targets(scan_id: str) -> None:
    with _PIVOT_TARGETS_LOCK:
        _PIVOT_TARGETS_BY_SCAN.pop(str(scan_id), None)


def _command_mentions_target(cmd: list[str], target: str) -> bool:
    """Match an IP in argv without relying on shell parsing."""
    pattern = re.compile(rf'(?<![0-9A-Fa-f:.]){re.escape(target)}(?![0-9A-Fa-f:.])')
    return any(pattern.search(str(arg)) for arg in cmd)


def _pivot_wrap_command(scan_id: str, cmd: list[str]) -> tuple[list[str] | None, str]:
    """Adapt one TCP-capable target command for the established SOCKS pivot.

    Returns ``(None, reason)`` when the collector cannot produce truthful
    evidence through a TCP SOCKS transport. Direct-target commands are returned
    unchanged.
    """
    targets = _pivot_targets(scan_id)
    if not targets or not cmd:
        return cmd, ''
    matched = {target for target in targets if _command_mentions_target(cmd, target)}
    if not matched:
        return cmd, ''

    exe = Path(str(cmd[0])).name.lower()
    # Local/passive commands can contain target strings in a filter or filename;
    # they are not data-plane connections and must not be proxy-wrapped.
    if exe in {'tshark', 'p0f', 'git', 'jq'}:
        return cmd, ''

    proxychains = which('proxychains4')
    if not proxychains:
        return None, 'proxychains4_unavailable_for_pivot_target'
    try:
        from pivot.runtime import get_pivot_engine
        engine = get_pivot_engine()
        if not engine.is_socks_ready():
            return None, 'operator_established_socks_pivot_not_ready'
        config_path = getattr(
            engine,
            'proxychains_config_path',
            str(Path(__file__).resolve().parent.parent / 'proxychains4.conf'),
        )
    except Exception:
        config_path = str(Path(__file__).resolve().parent.parent / 'proxychains4.conf')

    if exe == 'nmap':
        args = [str(value) for value in cmd]
        # These evidence types need raw IP/UDP/L2 semantics and cannot be
        # represented honestly through a TCP SOCKS tunnel.
        if '-sU' in args:
            return None, 'udp_scanning_not_supported_through_socks_pivot'
        if '-O' in args:
            return None, 'active_os_fingerprinting_not_supported_through_socks_pivot'
        if '-sn' in args:
            return None, 'nmap_host_discovery_not_supported_through_socks_pivot'
        args = [value for value in args if value != '-sS']
        insert_at = 1
        if '-Pn' not in args:
            args.insert(insert_at, '-Pn')
            insert_at += 1
        if '-sT' not in args:
            args.insert(insert_at, '-sT')
        return [proxychains, '-q', '-f', config_path, *args], ''

    # These tools use ordinary TCP sockets and can be routed by ProxyChains.
    proxy_compatible = {
        'curl', 'openssl', 'ssh-audit', 'smbclient', 'smbmap', 'ldapsearch',
        'rpcinfo', 'showmount', 'pg_isready', 'telnet', 'nc', 'netcat',
        'enum4linux-ng',
    }
    if exe in proxy_compatible:
        return [proxychains, '-q', '-f', config_path, *[str(value) for value in cmd]], ''

    # Never silently fall back to direct traffic for a target whose retained
    # Phase 2 access method is pivot-only.
    return None, f'{exe or "collector"}_not_proxy_compatible'

def _describe_command(cmd: list[str]) -> str:
    if not cmd:
        return 'No command executed.'
    exe = Path(str(cmd[0])).name.lower()
    joined = ' '.join(map(str, cmd)).lower()

    # Specific nmap script checks must be evaluated before generic -sV wording.
    if 'nmap' in exe and '--script' in cmd:
        script_text = joined
        if 'http-title' in script_text or 'http-headers' in script_text or 'http-enum' in script_text:
            if 'http-auth-finder' in script_text:
                return 'Checked Tomcat/HTTP titles, headers, auth hints, and exposed paths.'
            return 'Collected HTTP titles, headers, and server banner evidence.'
        if 'ftp-anon' in script_text or 'ftp-syst' in script_text:
            return 'Checked FTP banner, anonymous-login, and system evidence.'
        if 'telnet-' in script_text:
            return 'Checked Telnet service exposure and protocol/security hints.'
        if 'smtp-commands' in script_text or 'smtp-open-relay' in script_text:
            return 'Checked SMTP command and banner behaviour.'
        if 'dns-recursion' in script_text or 'dns-zone-transfer' in script_text or 'dns-nsid' in script_text:
            return 'Checked DNS recursion, NSID, and zone-transfer evidence.'
        if 'smb-os-discovery' in script_text or 'smb2-capabilities' in script_text or 'smb2-time' in script_text:
            return 'Collected SMB-exposed host/OS identity, capabilities, and time evidence without share/user enumeration.'
        if 'smb-enum' in script_text or 'smb-protocols' in script_text or 'smb-security-mode' in script_text:
            return 'Checked SMB protocol and security-mode evidence.'
        if 'ntlm-info' in script_text:
            return 'Collected protocol-exposed NTLM host identity metadata without successful authentication.'
        if 'msrpc-enum' in script_text:
            return 'Collected Microsoft RPC endpoint mapper metadata without invoking RPC application methods.'
        if 'nbstat' in script_text:
            return 'Collected NetBIOS naming identity evidence without user or share enumeration.'
        if 'rmi-dumpregistry' in script_text:
            return 'Checked Java RMI registry exposure evidence.'
        if 'mysql-' in script_text:
            return 'Checked MySQL version and service information evidence.'
        if 'pgsql-' in script_text or 'postgres' in script_text:
            return 'Checked PostgreSQL banner and pgsql-empty-password evidence where enabled by policy.'
        if 'vnc-info' in script_text:
            return 'Checked VNC protocol and authentication evidence.'
        if 'x11-access' in script_text:
            return 'Checked X11 access-control exposure evidence.'
        if 'irc-info' in script_text:
            return 'Checked IRC banner and server information evidence.'
        if 'ajp-' in script_text:
            return 'Checked AJP header evidence.'
        if 'ldap-rootdse' in script_text:
            return 'Checked LDAP RootDSE naming-context evidence without authentication.'
        if 'krb5-info' in script_text:
            return 'Checked Kerberos realm/service evidence without credential use.'
        if 'ssl-enum-ciphers' in script_text:
            return 'Checked TLS protocol and cipher evidence.'
        if 'rdp-enum-encryption' in script_text:
            return 'Checked RDP encryption and NLA negotiation evidence.'
        if 'banner' in script_text:
            return 'Re-probed service banner evidence for exposed or unknown services.'

    if 'nmap' in exe and '-sn' in cmd:
        return 'Target Reachability Validation.'
    if 'nmap' in exe and '-sU' in cmd:
        return 'Targeted UDP Service Discovery.'
    if 'nmap' in exe and '-p-' in cmd:
        return 'Discovered open TCP ports across a full-range follow-up scan.'
    if 'nmap' in exe and '-sV' in cmd:
        return 'Service Identity Fingerprinting.'
    if exe == 'dig':
        return 'Collected DNS context evidence such as SOA/NS/version.bind where applicable.'
    if exe in {'mtr','traceroute'}:
        return 'Captured the network route path to the target.'
    if exe == 'arp-scan':
        return 'Checked local ARP visibility for the target address or local range.'
    if exe in {'httpx', 'httpx-toolkit'}:
        return 'Probed HTTP service details such as status, title, server, and technology hints.'
    if exe == 'snmpget':
        return 'Collected targeted SNMP system identity OIDs only.'
    if exe == 'ldapsearch':
        return 'Collected LDAP RootDSE naming-context and capability evidence without authentication.'
    if exe == 'rpcinfo':
        return 'Collected RPC program mapping evidence.'
    if exe == 'showmount':
        return 'Collected NFS export readiness evidence without mounting shares.'
    if exe == 'ssh-audit':
        return 'Collected SSH cryptographic algorithm evidence without login attempts.'
    if exe == 'curl':
        return 'Collected HTTP header/security context with a single metadata request.'
    if exe == 'jq':
        return 'Formatted the normalised JSON evidence package.'
    return 'Protocol / Service Evidence Collection.'

def _result_has_output_evidence(result: dict[str, Any], output_file: Path | None = None) -> bool:
    text = ' '.join(str(result.get(k) or '') for k in ('stdout', 'stderr', 'error'))
    if output_file and Path(output_file).exists():
        try:
            text += '\n' + Path(output_file).read_text(encoding='utf-8', errors='ignore')[:12000]
        except Exception:
            pass
    return bool(text.strip())


def _coerce_text(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return str(value)


def _captured_command_output(result: dict[str, Any], output_file: Path | None = None, limit: int = 200000) -> tuple[str, bool]:
    """Return real captured command output for the UI command log."""
    parts: list[str] = []
    stdout = _coerce_text(result.get('stdout') or '')
    stderr = _coerce_text(result.get('stderr') or '')
    if stdout.strip():
        parts.append(stdout.rstrip())
    if stderr.strip():
        parts.append('[stderr]\n' + stderr.rstrip())
    path_value = output_file or result.get('output_file') or ''
    path = Path(path_value) if path_value else None
    if path and path.exists():
        try:
            file_text = path.read_text(encoding='utf-8', errors='ignore')
            current = '\n'.join(parts)
            if file_text.strip() and file_text.strip() not in current:
                parts.append(f'[evidence file: {path}]\n' + file_text.rstrip())
        except Exception as exc:
            parts.append(f'[evidence file: {path}]\nUnable to read evidence file: {exc}')
    output = '\n\n'.join(parts).strip()
    if not output:
        output = '[no console output captured]'
    truncated = len(output) > limit
    if truncated:
        output = output[:limit] + f"\n\n[output display truncated; full evidence file: {path or result.get('output_file') or 'not available'}]"
    return output, truncated



def _summarise_command_output_for_ui(output: str, command: str = '', output_file: str = '') -> str:
    """Return a concise operator-facing summary while preserving raw output separately."""
    text = str(output or '').strip()
    cmd = str(command or '').lower()
    if not text or text == '[no console output captured]':
        return 'No console output was returned. Check the evidence file if one was generated.'

    # Nmap XML should never be shown as the first thing an operator reads.
    if '<nmaprun' in text or 'Starting Nmap' in text:
        open_lines = []
        for m in re.finditer(r'(\d{1,5})/(tcp|udp)\s+open\s+([^\s<]+)', text, re.I):
            open_lines.append(f"{m.group(1)}/{m.group(2)} open {m.group(3)}")
        if not open_lines:
            for m in re.finditer(r'<port protocol="(tcp|udp)" portid="(\d+)">.*?<state state="open".*?(?:<service name="([^"]+)")?', text, re.I | re.S):
                service = m.group(3) or 'unknown'
                open_lines.append(f"{m.group(2)}/{m.group(1)} open {service}")
        if open_lines:
            return 'Open service findings:\n' + '\n'.join(open_lines[:30])
        if '0 hosts up' in text.lower() or 'no open ports' in text.lower():
            return 'No open service findings were returned by this Nmap command.'
        return 'Nmap completed. Raw XML output is available below.'

    if 'tshark' in cmd or 'passive_packet_inventory' in str(output_file).lower():
        ips = sorted(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))[:20]
        protocols = []
        for p in ('ARP','DHCP','LLMNR','MDNS','NBNS'):
            if p.lower() in text.lower():
                protocols.append(p)
        summary = []
        if protocols:
            summary.append('Observed protocols: ' + ', '.join(protocols))
        if ips:
            summary.append('Observed IP hints: ' + ', '.join(ips))
        m = re.search(r'(\d+) packets captured', text, re.I)
        if m:
            summary.append(f"Packets captured: {m.group(1)}")
        return '\n'.join(summary) if summary else 'Passive capture completed; no protocol summary could be extracted.'

    if 'ssh-audit' in cmd:
        lines=[]
        for pat in (r'\(gen\) banner:\s*([^\n\r]+)', r'\(gen\) software:\s*([^\n\r]+)', r'\(fin\) ([^\n\r]+)'):
            for m in re.finditer(pat, text):
                lines.append(m.group(1).strip())
        fails=len(re.findall(r'\[fail\]', text))
        warns=len(re.findall(r'\[warn\]', text))
        if fails or warns:
            lines.append(f'SSH posture observations: {fails} fail marker(s), {warns} warning marker(s).')
        return '\n'.join(lines[:12]) if lines else 'SSH audit completed; raw output is available below.'

    # Generic concise first lines for normal text tools.
    useful=[]
    for line in text.splitlines():
        clean=line.strip()
        if not clean or clean.startswith('<?xml') or clean.startswith('<!DOCTYPE'):
            continue
        useful.append(clean)
        if len(useful) >= 12:
            break
    return '\n'.join(useful) if useful else 'Command completed. Raw output is available below.'

def _active_command_delay() -> None:
    """Policy-driven spacing between active probes. This is for authorised low-noise operation, not bypassing monitoring."""
    try:
        policy = _load_recon_policy()
        guard = _policy_required(policy, 'active_command_guardrails')
        if not bool(guard.get('enabled', True)):
            return
        base = float(guard.get('min_delay_seconds', 0))
        jitter = float(guard.get('max_jitter_seconds', 0))
        delay = max(0.0, base) + (random.random() * max(0.0, jitter))
        if delay > 0:
            time.sleep(delay)
    except Exception:
        return


def run_cmd(cmd: list[str], output_file: Path | None = None, timeout: int = 300, tool_writes_file: bool = False) -> dict[str, Any]:
    sid = _CURRENT_SCAN_ID.get()
    original_cmd = [str(value) for value in cmd]
    purpose = _describe_command(original_cmd)
    adapted_cmd, pivot_skip_reason = _pivot_wrap_command(sid, original_cmd) if sid else (original_cmd, '')
    if adapted_cmd is None:
        if output_file:
            try:
                Path(output_file).parent.mkdir(parents=True, exist_ok=True)
                if not Path(output_file).exists():
                    Path(output_file).write_text('', encoding='utf-8')
            except OSError:
                pass
        result = {
            'success': True,
            'returncode': 0,
            'stdout': '',
            'stderr': '',
            'error': '',
            'output_file': str(output_file or ''),
            'pivot_transport': 'socks_proxy',
            'pivot_not_applicable': True,
            'pivot_skip_reason': pivot_skip_reason,
            'lifecycle_state': 'not_applicable',
        }
        if sid:
            command_text = ' '.join(original_cmd)
            scan_store.log_command(
                sid,
                command=command_text,
                purpose=purpose,
                output='',
                output_summary=f'Not applicable through SOCKS pivot: {pivot_skip_reason}',
                status='Not Applicable - Pivot Transport',
                exit_code=0,
                output_file=str(output_file or ''),
                output_truncated=False,
            )
        return result

    cmd = [str(value) for value in adapted_cmd]
    command_text = ' '.join(cmd)
    exe = Path(str(cmd[0])).name.lower() if cmd else ''
    _active_command_delay()
    result = _run_cmd(cmd, output_file=output_file, timeout=timeout, tool_writes_file=tool_writes_file)
    if cmd != original_cmd:
        result['pivot_transport'] = 'socks_proxy'
        result['pivot_wrapped'] = True
    if not result.get('success'):
        result['lifecycle_state'] = execution_lifecycle(result, False)
    diagnosis = detect_tool_error(
        _coerce_text(result.get('stderr')),
        _coerce_text(result.get('stdout')),
        exe,
    )
    if diagnosis:
        result['tool_diagnosis'] = diagnosis

    if sid:
        output, truncated = _captured_command_output(result, output_file)
        status = 'Completed Successfully' if result.get('success') else ('Timed Out - Partial Results Retained' if str(result.get('error','')).lower() == 'timeout' else 'Failed - Command Error')
        scan_store.log_command(
            sid,
            command=command_text,
            purpose=purpose,
            output=output,
            output_summary=_summarise_command_output_for_ui(output, command_text, str(output_file or result.get('output_file') or '')),
            status=status,
            exit_code=result.get('returncode',''),
            output_file=str(output_file or result.get('output_file') or ''),
            output_truncated=truncated,
        )
        if not result.get('success'):
            err = (result.get('error') or result.get('stderr') or 'command did not complete successfully')[:220]
            scan_store.log(sid, f'Command did not complete successfully: {err}', 'WARN')
        elif diagnosis:
            level = 'INFO' if diagnosis.startswith('No open ports discovered') else 'WARN'
            scan_store.log(sid, f'{exe} diagnostic: {diagnosis}', level)
    return result


def _chunk_ports(ports: Iterable[int], batch_size: int) -> list[list[int]]:
    """Split a selected port iterable into deterministic bounded batches."""
    size = max(1, int(batch_size))
    batches: list[list[int]] = []
    current: list[int] = []
    for value in ports:
        port = int(value)
        if port < 1 or port > 65535:
            continue
        current.append(port)
        if len(current) >= size:
            batches.append(current)
            current = []
    if current:
        batches.append(current)
    return batches


def _run_cmd_with_retry(
    scan_id: str,
    cmd: list[str],
    output_file: Path,
    timeout_seconds: int,
    retry_failed_batches: bool,
    retry_count: int,
) -> dict[str, Any]:
    """Run one discovery command with bounded command-level retries.

    This is deliberately separate from Nmap's packet retransmission setting.
    A retry may follow a non-zero command failure, but an already timed-out
    command is never retried because that simply multiplies the timeout cost.
    Closed ports or zero open ports are not retry conditions.
    """
    token = _CURRENT_SCAN_ID.set(scan_id)
    try:
        attempts = 1 + (max(0, int(retry_count)) if retry_failed_batches else 0)
        last: dict[str, Any] = {}
        for attempt in range(1, attempts + 1):
            last = run_cmd(cmd, output_file, int(timeout_seconds), True)
            last['attempts'] = attempt
            if last.get('success'):
                return last
            if last.get('timed_out'):
                scan_store.log(
                    scan_id,
                    f'Discovery batch timed out on attempt {attempt}/{attempts}; timeout results are not retried.',
                    'WARN',
                )
                return last
            if attempt < attempts:
                scan_store.log(
                    scan_id,
                    f'Discovery batch failed on attempt {attempt}/{attempts}; retrying within operator limit.',
                    'WARN',
                )
        return last
    finally:
        _CURRENT_SCAN_ID.reset(token)


def _run_port_batch_wave(
    scan_id: str,
    jobs: list[tuple[int, list[int], Path, list[str]]],
    *,
    timeout_seconds: int,
    retry_failed_batches: bool,
    retry_count: int,
    parallel_workers: int,
) -> list[tuple[int, list[int], Path, dict[str, Any]]]:
    """Execute one sequential/parallel wave and return results in batch order."""
    if not jobs:
        return []
    workers = max(1, min(int(parallel_workers), len(jobs)))
    if workers == 1:
        return [
            (index, ports, path, _run_cmd_with_retry(
                scan_id, cmd, path, timeout_seconds, retry_failed_batches, retry_count
            ))
            for index, ports, path, cmd in jobs
        ]

    completed: list[tuple[int, list[int], Path, dict[str, Any]]] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='autopentest-port-batch') as executor:
        future_map = {
            executor.submit(
                _run_cmd_with_retry,
                scan_id,
                cmd,
                path,
                timeout_seconds,
                retry_failed_batches,
                retry_count,
            ): (index, ports, path)
            for index, ports, path, cmd in jobs
        }
        for future in as_completed(future_map):
            index, ports, path = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    'success': False,
                    'returncode': -1,
                    'error': str(exc),
                    'stdout': '',
                    'stderr': str(exc),
                    'output_file': str(path),
                }
                scan_store.log(scan_id, f'Parallel discovery batch {index} failed: {exc}', 'WARN')
            completed.append((index, ports, path, result))
    return sorted(completed, key=lambda item: item[0])


def _publish_partial(scan_id: str, **kwargs: Any) -> None:
    current = scan_store.get(scan_id) or {}
    results = current.get('results') or {}
    results.update(kwargs)
    scan_store.update(scan_id, results=results)



class ReconPolicyError(RuntimeError):
    pass

def _load_recon_policy() -> dict[str, Any]:
    """Load policy values controlling recon behaviour. Fail closed if unavailable."""
    candidates = [Path('project/policies/recon_policy.json'), Path('policies/recon_policy.json')]
    path = next((x for x in candidates if x.exists()), None)
    if path is None:
        raise ReconPolicyError('Recon policy file is missing; scan aborted rather than using hardcoded defaults.')
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except Exception as exc:
        raise ReconPolicyError(f'Recon policy could not be parsed: {exc}') from exc

    # Optional external TCP micro-batch profile. This keeps port coverage policy-owned
    # instead of embedded in scanner logic, while preserving backwards compatibility.
    profile_file = data.get('tcp_micro_batch_profile_file')
    if profile_file:
        profile_candidates = [Path(profile_file), Path('project') / profile_file]
        profile_path = next((p for p in profile_candidates if p.exists()), None)
        if profile_path:
            try:
                profile_data = json.loads(profile_path.read_text(encoding='utf-8'))
                profile_name = str(data.get('tcp_micro_batch_profile') or profile_data.get('default_profile') or 'full')
                selected = (profile_data.get('profiles') or {}).get(profile_name) or {}
                if selected.get('tcp_micro_batches'):
                    data['tcp_micro_batches'] = selected['tcp_micro_batches']
            except Exception as exc:
                raise ReconPolicyError(f'TCP port profile could not be parsed: {exc}') from exc

    required = ['tcp_discovery_stages', 'critical_banner_ports', 'stop_conditions', 'scan_postures', 'ttl_hints', 'acl_detection', 'httpx_options', 'active_command_guardrails', 'active_validation_guardrails']
    missing = [k for k in required if k not in data]
    if missing:
        raise ReconPolicyError(f'Recon policy is incomplete; missing keys: {missing}')
    return data


def _policy_required(policy: dict[str, Any], key: str) -> Any:
    if key not in policy:
        raise ReconPolicyError(f'Recon policy is incomplete; missing key: {key}')
    return policy[key]


def _policy_nested(policy: dict[str, Any], section: str, key: str) -> Any:
    data = _policy_required(policy, section)
    if not isinstance(data, dict) or key not in data:
        raise ReconPolicyError(f'Recon policy is incomplete; missing key: {section}.{key}')
    return data[key]



def _load_collector_registry() -> dict[str, Any]:
    candidates = [Path('project/policies/collector_registry.json'), Path('policies/collector_registry.json')]
    path = next((x for x in candidates if x.exists()), None)
    if path is None:
        raise ReconPolicyError('Collector registry is missing; scan aborted rather than using hardcoded collector logic.')
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception as exc:
        raise ReconPolicyError(f'Collector registry could not be parsed: {exc}') from exc


def _collector_required(collector_id: str) -> dict[str, Any]:
    registry = _load_collector_registry()
    if collector_id not in registry:
        raise ReconPolicyError(f'Collector registry is incomplete; missing collector: {collector_id}')
    item = registry[collector_id]
    if not isinstance(item, dict):
        raise ReconPolicyError(f'Collector registry entry is invalid: {collector_id}')
    return item


def _collector_scripts(collector_id: str) -> list[str]:
    item = _collector_required(collector_id)
    scripts = item.get('nmap_scripts') or []
    if not isinstance(scripts, list) or not all(isinstance(x, str) and x.strip() for x in scripts):
        raise ReconPolicyError(f'Collector {collector_id} must define nmap_scripts as a non-empty string list.')
    return [x.strip() for x in scripts]


def _collector_ports(collector_id: str) -> set[int]:
    item = _collector_required(collector_id)
    ports = item.get('ports') or []
    if not isinstance(ports, list):
        raise ReconPolicyError(f'Collector {collector_id} must define ports as a list.')
    return {int(x) for x in ports}


def _script_output_for_host_port(service_level_checks: list[dict[str, Any]], host: str, port: int) -> str:
    chunks: list[str] = []
    for item in service_level_checks or []:
        if str(item.get('host')) != str(host):
            continue
        if item.get('port') not in (None, '', port, str(port)) and str(item.get('port')) != str(port):
            continue
        for row in item.get('rows') or []:
            if str(row.get('host')) != str(host) or int(row.get('port') or 0) != int(port):
                continue
            for script in row.get('scripts') or []:
                chunks.append(str(script.get('id') or ''))
                chunks.append(str(script.get('output') or ''))
        if item.get('output_file'):
            chunks.append(_read_text(item.get('output_file'))[:12000])
        if item.get('output'):
            chunks.append(str(item.get('output'))[:12000])
    return '\n'.join(chunks)


def _parse_http_forms_from_html(html: str) -> dict[str, Any]:
    """Extract low-impact form/input hints. This does not send payloads."""
    forms: list[dict[str, Any]] = []
    for m in re.finditer(r'<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>', html or '', flags=re.I|re.S):
        attrs = m.group('attrs') or ''
        body = m.group('body') or ''
        def attr(name: str, text: str = attrs) -> str:
            q = re.search(rf'{name}\s*=\s*["\']([^"\']+)["\']', text, flags=re.I)
            if q:
                return q.group(1)
            q = re.search(rf'{name}\s*=\s*([^\s>]+)', text, flags=re.I)
            return q.group(1) if q else ''
        inputs = []
        for im in re.finditer(r'<(?:input|textarea|select)\b(?P<attrs>[^>]*)>', body, flags=re.I|re.S):
            ia = im.group('attrs') or ''
            inputs.append({'name': attr('name', ia), 'type': (attr('type', ia) or im.group(0).split()[0].strip('<')).lower()})
        forms.append({'method': (attr('method') or 'GET').upper(), 'action': attr('action'), 'inputs': inputs})
    links = sorted(set(re.findall(r'href\s*=\s*["\']([^"\']+)["\']', html or '', flags=re.I)))[:50]
    return {'forms': forms, 'links': links}


def _collect_single_page_form_hints(host: str, port: int, url: str) -> dict[str, Any]:
    curl_bin = which('curl')
    if not curl_bin:
        return {'success': False, 'forms': [], 'links': [], 'error': 'curl not found'}
    p = outfile('web_form_hints', f'{host}_{port}', 'html')

    guard = _policy_required(_load_recon_policy(), 'http_probe_guardrails')
    result = run_cmd(command_builders.curl_get(curl_bin, url, int(_policy_required(guard, 'curl_timeout_seconds')), int(_policy_required(guard, 'max_redirects'))), p, 30)
    html = Path(p).read_text(encoding='utf-8', errors='ignore') if Path(p).exists() else str(result.get('stdout') or '')
    parsed = _parse_http_forms_from_html(html)
    return {**result, **parsed, 'output_file': str(p), 'url': url}


def _host_environment_items(environment: list[dict[str, Any]], host: str) -> list[dict[str, Any]]:
    return [x for x in environment or [] if str(x.get('host')) == str(host)]


def _host_ttl(environment: list[dict[str, Any]], host: str) -> int | None:
    for item in _host_environment_items(environment, host):
        if item.get('ttl') is not None:
            try:
                return int(item.get('ttl'))
            except Exception:
                return None
    return None




def _classify_network_layer(host: str, environment: list[dict[str, Any]] | None = None, ports: list[int] | None = None) -> dict[str, Any]:
    """Retain network facts without converting TTL/port patterns into device or OS identity.

    Older builds treated a high TTL plus a small management-port set as an
    ``infrastructure_observed`` target.  That heuristic could silently defer
    otherwise applicable collectors and made behaviour depend on assumptions
    about the unknown target.  The scanner now records TTL/port density only;
    dedicated evidence collectors establish platform identity.
    """
    ttl = _host_ttl(environment or [], host)
    pset = set(int(p) for p in (ports or []))
    policy = _load_recon_policy()
    role = 'unclassified_target'
    evidence: list[str] = []
    if ttl is not None:
        evidence.append(f'ttl:{ttl}')
    if pset:
        evidence.append('ports:' + ','.join(map(str, sorted(pset)[:20])))
    if len(pset) >= int(_policy_nested(policy, 'stop_conditions', 'high_density_after_top20')):
        role = 'high_service_density_observed'
    try:
        ip = ipaddress.ip_address(str(host))
        address_scope = 'private' if ip.is_private else 'public'
    except Exception:
        address_scope = 'hostname_or_unparsed'
    return {
        'host': host,
        'role': role,
        'scan_posture': 'default',
        'matched_cidr': '',
        'description': 'Network observations only; operating-system and device identity require dedicated evidence.',
        'address_scope': address_scope,
        'evidence': evidence,
    }


def _scan_posture(host: str, environment: list[dict[str, Any]] | None = None, ports: list[int] | None = None) -> dict[str, Any]:
    policy = _load_recon_policy()
    layer = _classify_network_layer(host, environment, ports)
    postures = _policy_required(policy, 'scan_postures')
    if 'default' not in postures:
        raise ReconPolicyError('Recon policy is incomplete; missing scan_postures.default')
    selected = layer.get('scan_posture') or 'default'
    if selected not in postures:
        raise ReconPolicyError(f'Recon policy is incomplete; missing scan posture: {selected}')
    return {**dict(postures['default']), **dict(postures[selected]), 'network_layer': layer, 'scan_posture': selected}

def _is_infrastructure_target(host: str, environment: list[dict[str, Any]] | None = None, ports: list[int] | None = None) -> bool:
    """Compatibility hook retained for callers; no target role is guessed from TTL/ports."""
    _ = (host, environment, ports)
    return False

def _acl_filtering_indicator(host: str, filtered_count: int, closed_count: int, total_sampled: int) -> dict[str, Any] | None:
    policy = _load_recon_policy()
    cfg = _policy_required(policy, 'acl_detection')
    threshold = float(_policy_nested(policy, 'acl_detection', 'filtered_ratio_threshold'))
    min_sampled = int(_policy_nested(policy, 'acl_detection', 'min_sampled_ports'))
    if total_sampled < min_sampled:
        return None
    ratio = float(filtered_count) / float(max(total_sampled, 1))
    if ratio >= threshold:
        return {'host': host, 'indicator': 'acl_or_firewall_filtering_suspected', 'evidence': f'{filtered_count}/{total_sampled} sampled TCP ports were filtered/no-response.', 'interpretation': 'An intermediate ACL/firewall may be filtering results. Treat negative scan results as incomplete.'}
    return None

def _build_network_topology_summary(hosts: list[str], environment: list[dict[str, Any]], open_map: dict[str, list[int]], environment_context_indicators: list[dict[str, Any]]) -> dict[str, Any]:
    layers: dict[str, dict[str, Any]] = {}
    for host in hosts or []:
        layer = _classify_network_layer(host, environment, open_map.get(host) or [])
        role = str(layer.get('role') or 'unknown')
        item = layers.setdefault(role, {'role': role, 'scan_posture': layer.get('scan_posture') or 'default', 'description': layer.get('description',''), 'hosts': []})
        host_indicators = [d for d in environment_context_indicators or [] if str(d.get('host')) == str(host)]
        item['hosts'].append({'host': host, 'ttl': _host_ttl(environment, host), 'open_tcp_ports': sorted(set(int(p) for p in (open_map.get(host) or []))), 'environment_context_indicators': host_indicators, 'reliability': 'environment_context_observed' if host_indicators else 'baseline_observed'})
    return {'layers': list(layers.values()), 'classification_mode': 'dynamic_evidence_based_no_hardcoded_ip_ranges'}

def _host_profile_from_observations(host: str, ports: list[int], environment: list[dict[str, Any]]) -> dict[str, Any]:
    ttl = _host_ttl(environment, host)
    pset = set(int(p) for p in ports or [])
    hints: list[str] = []
    # TTL and common ports are retained as environment facts only.
    # They never assign a target operating system.
    if len(pset) > 10:
        hints.append('high_service_density')
    if len(pset) <= 3 and ({22,80,443} & pset):
        hints.append('perimeter_or_management_like')
    return {'host': host, 'ttl': ttl, 'ports': sorted(pset), 'hints': hints}


def _should_stop_discovery(host: str, ports: list[int], environment: list[dict[str, Any]], topn: int, policy: dict[str, Any]) -> tuple[bool, str]:
    """Full Recon does not stop just because a lab/legacy host is dense.

    High service density is still recorded as an environment context indicator, but it
    must not cause Telnet, RPC, VNC, NFS, Tomcat/AJP, SNMP, AD, database or
    cloud-native validation to be skipped. Filtering is treated as likely
    segmentation/ACL evidence rather than proof of environment context.
    """
    profile = _host_profile_from_observations(host, ports, environment)
    pset = set(int(p) for p in ports or [])
    stop_cfg = _policy_required(policy, 'stop_conditions')
    if not bool(stop_cfg.get('stop_on_high_density_in_full', False)):
        if _classify_network_layer(host, environment, ports).get('scan_posture') == 'infrastructure_observed':
            return True, 'Infrastructure-like target observed; top-port expansion complete; service validation will remain policy-gated.'
        return False, ''
    high_density = int(_policy_nested(policy, 'stop_conditions', 'high_density_after_top20'))
    if topn >= 20 and len(pset) >= high_density:
        return True, f'High service density observed after top-{topn}; high-value validation continues within policy.'
    sufficient_after_top50 = int(_policy_nested(policy, 'stop_conditions', 'sufficient_services_after_top50'))
    if _classify_network_layer(host, environment, ports).get('scan_posture') == 'infrastructure_observed':
        return True, 'Infrastructure-like target observed; further top-port expansion deferred.'
    if topn >= 50 and len(pset) >= sufficient_after_top50:
        return True, f'Sufficient attack-surface evidence collected by top-{topn}; further top-port expansion deferred.'
    return False, ''


def _has_host_indicator(environment_context_indicators: list[dict[str, Any]], host: str, name: str) -> bool:
    return any(str(x.get('host')) == str(host) and str(x.get('indicator')) == name for x in environment_context_indicators or [])



def _default_capture_interface() -> str:
    """Return the default outbound interface without probing the network."""
    env_iface = os.getenv('AUTOPENTEST_PASSIVE_INTERFACE', '').strip()
    if env_iface:
        return env_iface
    try:
        # /proc/net/route is local host state, not network probing.
        for line in Path('/proc/net/route').read_text(errors='ignore').splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == '00000000':
                return parts[0]
    except Exception:
        pass
    return ''


def _collect_passive_local_inventory(
    scan_id: str,
    coverage: list[dict[str, Any]],
    raw: list[dict[str, Any]],
    enabled_fn,
    authorised_targets: list[str],
    scan_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Listen-only local inventory. No target packets are generated."""
    result = {'tshark': {}, 'p0f': {}, 'summary': []}
    policy = _load_recon_policy().get('passive_local_inventory') or {}
    if not policy.get('enabled', True):
        coverage.append(_coverage('passive_packet_inventory', scan_store.STATUS_EMPTY, 'Passive local inventory disabled', 'Listen-only packet inventory disabled by policy.', '', {'success': True, 'lifecycle_state': 'disabled_policy'}))
        coverage.append(_coverage('passive_os_fingerprinting', scan_store.STATUS_EMPTY, 'Passive OS fingerprinting disabled', 'Listen-only p0f fingerprinting disabled by policy.', '', {'success': True, 'lifecycle_state': 'disabled_policy'}))
        return result
    collector_plan = (scan_options or {}).get('collector_plan') or {}
    workflow_context = (scan_options or {}).get('workflow_context') or {}
    workflow_iface = str(workflow_context.get('route_interface') or '').strip()
    requested_iface = str(collector_setting(collector_plan, 'passive_packet_inventory', 'interface', '') or '').strip()
    # Phased missions bind interface-dependent collectors to the Phase 1 route.
    # Legacy/non-phased scans retain the existing explicit/default behaviour.
    iface = workflow_iface or requested_iface or _default_capture_interface()
    if not iface:
        msg = 'No approved capture interface configured; set AUTOPENTEST_PASSIVE_INTERFACE to enable listen-only passive inventory.'
        if enabled_fn('passive_packet_inventory'):
            coverage.append(_coverage('passive_packet_inventory', scan_store.STATUS_EMPTY, 'Capture interface unavailable', msg, '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
        if enabled_fn('passive_os_fingerprinting'):
            coverage.append(_coverage('passive_os_fingerprinting', scan_store.STATUS_EMPTY, 'Capture interface unavailable', msg, '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
        return result
    if enabled_fn('passive_packet_inventory'):
        tshark_bin = which('tshark')
        if tshark_bin:
            p = outfile('passive_packet_inventory', iface, 'txt')
            duration = str(int(collector_setting(collector_plan, 'passive_packet_inventory', 'duration_seconds', policy.get('duration_seconds') or 30)))
            filt = str(policy.get('tshark_filter') or 'arp or mdns or dhcp or llmnr')
            target_filters: list[str] = []
            target_set = set(authorised_targets)
            for target in authorised_targets:
                address = ipaddress.ip_address(target)
                if address.version == 4:
                    target_filters.extend([
                        f'ip.addr == {address}',
                        f'arp.src.proto_ipv4 == {address}',
                        f'arp.dst.proto_ipv4 == {address}',
                    ])
                else:
                    target_filters.append(f'ipv6.addr == {address}')
            if target_filters:
                filt = f'({filt}) and ({" or ".join(target_filters)})'
            cmd = command_builders.tshark_passive_capture(tshark_bin, iface, int(duration), filt)
            r = run_cmd(cmd, p, int(duration)+30)
            output, _ = _captured_command_output(r, Path(p))
            r['lifecycle_state'] = execution_lifecycle(r, bool(output.strip()))
            ips = sorted({ip for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output) if ip in target_set})[:200]
            result['tshark'] = {'interface': iface, 'duration_seconds': int(duration), 'filter': filt, 'observed_ips': ips, 'output_file': str(p)}
            if ips:
                result['summary'].append(f'Passive local packet inventory observed {len(ips)} IP address hint(s) on {iface}.')
            coverage.append(_coverage('passive_packet_inventory', _status_from_result(r, bool(output.strip())), 'Listen-only ARP/mDNS/DHCP/LLMNR inventory', f'{len(ips)} IP hint(s) retained from ambient traffic; no target probes generated.', str(p), r))
            _add_raw(raw, 'passive_packet_inventory', '', '', str(p), 'text', bool(output.strip()))
        else:
            coverage.append(_coverage('passive_packet_inventory', scan_store.STATUS_EMPTY, 'Packet capture tool unavailable', 'tshark not available for listen-only packet inventory.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
    if enabled_fn('passive_os_fingerprinting') and not bool(policy.get('allow_ambient_p0f', False)):
        coverage.append(_coverage(
            'passive_os_fingerprinting',
            scan_store.STATUS_EMPTY,
            'Policy scope protection',
            'Ambient p0f capture skipped because it cannot be restricted to the authorised target set.',
            '',
            {'success': True, 'lifecycle_state': 'scope_blocked'},
        ))
    elif enabled_fn('passive_os_fingerprinting'):
        p0f_bin = which('p0f')
        if p0f_bin:
            p = outfile('passive_os_fingerprinting', iface, 'txt')
            duration = int(policy.get('p0f_duration_seconds') or policy.get('duration_seconds') or 120)
            # timeout is used to stop p0f after a bounded passive window.
            timeout_bin = which('timeout')
            cmd = command_builders.p0f_passive_capture(p0f_bin, iface, timeout_bin=timeout_bin, duration_seconds=duration)
            r = run_cmd(cmd, p, duration+30)
            output, _ = _captured_command_output(r, Path(p))
            r['lifecycle_state'] = execution_lifecycle(r, bool(output.strip()))
            result['p0f'] = {'interface': iface, 'duration_seconds': duration, 'output_file': str(p), 'observed': bool(output.strip())}
            if output.strip():
                result['summary'].append('Passive OS fingerprinting retained p0f ambient traffic hints.')
            coverage.append(_coverage('passive_os_fingerprinting', _status_from_result(r, bool(output.strip())), 'Listen-only p0f passive OS hints', 'p0f passive capture completed; no target probes generated.', str(p), r))
            _add_raw(raw, 'passive_os_fingerprinting', '', '', str(p), 'text', bool(output.strip()))
        else:
            coverage.append(_coverage('passive_os_fingerprinting', scan_store.STATUS_EMPTY, 'Passive OS tool unavailable', 'p0f not available for passive OS fingerprinting.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
    return result

TASKS = [
    'Scope and Target Validation',
    'Passive Network Observation',
    'Passive Intelligence Correlation',
    'TCP Service Discovery',
    'Service Identity Fingerprinting',
    'Preliminary Attack Surface Assembly',
    'Protocol-Specific Evidence Collection',
    'Windows Patch Evidence Collection',
    'Evidence Gap Review',
    'Evidence Normalisation and Merge',
    'MITRE CVE Correlation',
    'Handoff Package Preparation',
    'Final Report Data Assembly',
]
_TASK_ALIASES = {
    'Target Preparation': 'Scope and Target Validation',
    'Environment Characterisation': 'Passive Network Observation',
    'Host Availability Check': 'Scope and Target Validation',
    'Passive Intelligence Collection': 'Passive Intelligence Correlation',
    'Low-Impact Service Discovery': 'TCP Service Discovery',
    'Service Identity Collection': 'Service Identity Fingerprinting',
    'Preliminary Attack Surface Report': 'Preliminary Attack Surface Assembly',
    'Objective-Based Evidence Collection': 'Protocol-Specific Evidence Collection',
    'Modern Active Validation': 'Protocol-Specific Evidence Collection',
    'Native Protocol Metadata Enrichment': 'Protocol-Specific Evidence Collection',
    'Evidence Consolidation': 'Evidence Normalisation and Merge',
    'CVE Review': 'MITRE CVE Correlation',
    'Handoff Preparation': 'Handoff Package Preparation',
    'Report Preparation': 'Final Report Data Assembly',
}

def _task_name(name: str) -> str:
    return _TASK_ALIASES.get(name, name)


def _status_from_result(result: dict[str, Any], produced: bool = True) -> str:
    if not result.get('success'): return scan_store.STATUS_FAILED
    return scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY

def _finish(scan_id: str, task: str, status: str, summary: str = '') -> None:
    scan_store.set_task(scan_id, _task_name(task), status, summary=summary)

def _extract_ttl(text: str) -> int | None:
    m = re.search(r'ttl[= ](\d+)', text or '', re.I)
    return int(m.group(1)) if m else None

def _environment_role_hint(ttl: int | None, service_count: int = 0) -> str:
    """Describe observed environment facts without inferring an operating system."""
    if service_count > 20:
        return 'high_service_density_observed'
    if ttl is not None:
        return 'ttl_observed'
    return 'undetermined'

def _detect_environment_context_indicators(open_ports: list[int], banners: dict[int, str] | None = None, ttl: int | None = None, filtered_count: int = 0, retransmission_warning: bool = False, host_profile: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    port_count = len(open_ports or [])
    if port_count > 10:
        indicators.append({
            'indicator': 'high_service_density',
            'evidence': f'{port_count} open TCP ports were observed during staged discovery.',
            'interpretation': 'This can indicate a lab-style host, exposed legacy server, infrastructure concentration, or possible lab-style or synthetic service behaviour. Full Recon continues high-value validation and records the observation.',
        })
    if filtered_count >= 10:
        indicators.append({
            'indicator': 'filtered_no_response_pattern',
            'evidence': f'{filtered_count} ports were reported as filtered/no-response.',
            'interpretation': 'Filtering/no-response behaviour can indicate firewall policy, endpoint filtering, or scan handling controls.',
        })
    if retransmission_warning:
        indicators.append({
            'indicator': 'retransmission_cap_hit',
            'evidence': 'Nmap reported retransmission cap behaviour during staged discovery.',
            'interpretation': 'The target or path may be filtering, rate-limiting, or dropping probes. Treat negative evidence as incomplete and continue only policy-approved validation.',
        })
    banners = banners or {}
    non_empty = [b for b in banners.values() if b]
    if len(non_empty) > 5 and len(set(non_empty)) <= 2:
        indicators.append({
            'indicator': 'repeated_banner_pattern',
            'evidence': 'Multiple services returned highly similar banner text.',
            'interpretation': 'Repeated banners may indicate synthetic service behaviour or an environment context pattern.',
        })
    if ttl is not None and ttl >= 200 and port_count > 10:
        indicators.append({
            'indicator': 'high_ttl_with_many_services',
            'evidence': f'TTL {ttl} was observed with {port_count} open ports.',
            'interpretation': 'A high observed TTL combined with high service density is unusual network evidence and should be reviewed without assigning an operating-system or device role.',
        })
    return indicators



def _environment_is_local_or_internal(host: str, environment: list[dict[str, Any]]) -> bool:
    """Return True when evidence suggests the scanner is operating inside the lab/internal segment."""
    try:
        if ipaddress.ip_address(host).is_private:
            return True
    except Exception:
        pass
    # Keep this conservative; absence of proof does not make a target external.
    return False

def _critical_banner_ports(open_ports: list[int], environment_context_observed: bool = False) -> list[int]:
    """Return all observed ports for Full Recon when policy requests full identity coverage."""
    ports = sorted(set(int(p) for p in (open_ports or []) if str(p).isdigit() or isinstance(p, int)))
    policy = _load_recon_policy()
    if bool(policy.get('full_fingerprint_all_observed_ports', True)):
        return ports
    preferred = [int(p) for p in _policy_required(policy, 'critical_banner_ports')]
    selected = [p for p in preferred if p in set(ports)]
    if not selected:
        selected = ports[:3 if environment_context_observed else 6]
    return selected

def _build_follow_up_objectives(open_map: dict[str, list[int]], environment_context_indicators: list[dict[str, Any]], services: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Suggested follow-up only; recon does not execute noisy validation by default."""
    suggestions: list[dict[str, Any]] = []
    all_ports = sorted({int(p) for ports in (open_map or {}).values() for p in ports})
    environment_context_present = bool(environment_context_indicators)
    def add(name: str, reason: str, trigger: str, noise: str = 'medium') -> None:
        suggestions.append({'objective': name, 'reason': reason, 'trigger': trigger, 'noise': noise, 'execution': 'not_auto_executed'})
    if environment_context_present:
        add('Environment context review', 'High-density, filtering, or mixed-profile observations were retained for interpretation. Full Recon still validates high-value services within policy.', 'environment_context_indicator', 'medium')
    if all_ports:
        add('Full TCP coverage', 'Full 65k TCP sweep was deferred; Full Recon uses micro-batched high-value coverage plus targeted expansion instead.', 'port_coverage_gap', 'high')
    if any(p in all_ports for p in [80,443,8080,8180,8009]):
        add('Web path discovery', 'Directory/content discovery was deferred; use only if web evidence remains insufficient.', 'web_surface_observed', 'high')
        add('Web exploitation validation', 'SQL injection, command injection, upload and authentication testing are deferred to downstream web-validation modules.', 'web_surface_observed', 'high')
    if any(p in all_ports for p in [139,445]):
        add('Deep SMB enumeration', 'Broad SMB enumeration and permission mapping were deferred; use only after approval.', 'smb_surface_observed', 'medium-high')
        add('SMB/WinRM authentication surface validation', 'SMB exposure was observed. Credential validation and WinRM checks are deferred to downstream validation modules.', 'smb_or_windows_surface_observed', 'high')
    if any(p in all_ports for p in [22]):
        add('SSH cryptographic posture review', 'SSH posture review is deferred to downstream validation.', 'ssh_observed', 'medium')
    if any(p in all_ports for p in [111,2049]):
        add('NFS/RPC export validation', 'NFS deep listing/statfs checks were deferred.', 'nfs_rpc_surface_observed', 'medium-high')
    if any(p in all_ports for p in [3306,5432,1433,1521]):
        add('Database authentication validation', 'Empty-password/default credential checks were deferred to downstream validation.', 'database_surface_observed', 'high')
    if any(p in all_ports for p in [53,161,123,137,138,2049]):
        add('Targeted UDP follow-up', 'Broad UDP discovery is deferred by default; run only where service evidence justifies it.', 'udp_relevance_possible', 'medium-high')
    return suggestions

def _build_environment_summary(environment: list[dict[str, Any]], environment_context_indicators: list[dict[str, Any]]) -> dict[str, Any]:
    ttl_values = [x.get('ttl') for x in environment if x.get('ttl') is not None]
    return {
        'items': environment,
        'ttl_values': ttl_values,
        'role_hints': sorted({str(x.get('role_hint')) for x in environment if x.get('role_hint')}),
        'environment_context_indicators': environment_context_indicators,
    }



def _build_authentication_surface_readiness(services: list[dict[str, Any]], environment: list[dict[str, Any]], smb_summary: dict[str, Any], service_level_checks: list[dict[str, Any]] | None = None, credential_validation_items: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    service_level_checks = service_level_checks or []
    credential_validation_items = credential_validation_items or []
    for s in services or []:
        host = s.get('host')
        port = int(s.get('port') or 0)
        svc = str(s.get('service') or '').lower()
        prod = str(s.get('product') or '')
        check_text = _script_output_for_host_port(service_level_checks, str(host), port).lower()
        if port in {21,2121} or svc == 'ftp':
            anonymous_allowed = any(x in check_text for x in ['anonymous ftp login allowed', 'ftp code 230', 'logged in as ftp'])
            anonymous_denied = any(x in check_text for x in ['anonymous ftp login allowed' if False else 'anonymous ftp login allowed']) is False and 'ftp-anon' in check_text and not anonymous_allowed
            evidence = 'FTP exposed; anonymous access status checked where safe.'
            if anonymous_allowed:
                evidence = 'FTP exposed; anonymous access appears allowed from collected ftp-anon evidence.'
            elif 'ftp-anon' in check_text:
                evidence = 'FTP exposed; ftp-anon check did not confirm anonymous access.'
            rows.append({'host':host,'port':port,'protocol':s.get('protocol'),'service':'ftp','candidate_type':'authentication_surface_candidate','anonymous_allowed': anonymous_allowed, 'safe_recon_checks':['ftp-anon','ftp-syst'] if check_text else [], 'evidence': evidence, 'recommended_downstream_module':'credential_validation','recon_boundary':'Recon checked anonymous/system hints only; no brute force or password attempts performed.'})
        if port == 22 or svc == 'ssh':
            auth_methods = sorted(set(re.findall(r'\b(publickey|password|keyboard-interactive|gssapi[^,\s]*)\b', check_text, flags=re.I)))
            password_auth = any(str(x).lower() == 'password' for x in auth_methods)
            evidence = f'SSH exposed ({prod or "banner available"}); auth-method readiness collected where available.'
            if auth_methods:
                evidence += ' Advertised auth methods: ' + ', '.join(auth_methods) + '.'
            rows.append({'host':host,'port':port,'protocol':s.get('protocol'),'service':'ssh','candidate_type':'authentication_surface_candidate','password_auth_advertised': password_auth, 'auth_methods': auth_methods, 'safe_recon_checks':['ssh-auth-methods'] if check_text else [], 'evidence':evidence,'recommended_downstream_module':'credential_validation','recon_boundary':'Recon requests advertised authentication methods only; no login attempts performed.'})
        if port in {139,445} or 'smb' in svc or 'netbios' in svc or 'microsoft-ds' in svc:
            signing_required = None
            if 'message signing enabled and required' in check_text or 'signing enabled and required' in check_text:
                signing_required = True
            elif 'message signing enabled but not required' in check_text or 'not required' in check_text:
                signing_required = False
            dialect_hints = sorted(set(re.findall(r'\bSMBv?\s*([123](?:\.[0-9])?)\b', check_text, flags=re.I)))
            evidence = 'SMB/NetBIOS surface exposed; dialect/signing readiness collected where safe. Share/user enumeration deferred.'
            rows.append({'host':host,'port':port,'protocol':s.get('protocol'),'service':'smb','candidate_type':'authentication_surface_candidate','smb_signing_required': signing_required, 'smb_dialect_hints': dialect_hints, 'safe_recon_checks':['smb2-security-mode','smb-protocols'] if check_text else [], 'evidence':evidence,'recommended_downstream_module':'credential_validation','recon_boundary':'Recon checks SMB protocol/signing only; no share, user, RID, password, or permission enumeration performed.'})
        if port in {5985,5986} or svc == 'winrm':
            related = [x for x in credential_validation_items if str(x.get('host')) == str(host) and int(x.get('port') or 0) == port]
            auth_headers = []
            for item in related:
                if item.get('auth_headers'):
                    auth_headers.extend(item.get('auth_headers') or [])
            rows.append({'host':host,'port':port,'protocol':s.get('protocol'),'service':'winrm','candidate_type':'authentication_surface_candidate','auth_headers': sorted(set(auth_headers)), 'safe_recon_checks':['wsman_head'] if related else [], 'evidence':'WinRM management surface exposed; listener/header readiness collected where available. Authentication validation deferred.','recommended_downstream_module':'credential_validation','recon_boundary':'Recon probes the WSMan endpoint only; no authentication attempts performed.'})
    return _dedupe_dicts(rows, ('host','port','service','candidate_type'))



def _split_technology_hints(tech_items: list[Any]) -> tuple[list[str], list[str]]:
    """Split web technology hints into evidence-backed and unverified buckets.

    ProjectDiscovery/httpx fingerprints can include false-positive CPE/tech hints.
    Only conservative server/framework hints remain in evidence-backed conclusions;
    noisy guesses such as bun/phpMyAdmin/metasploit are retained as unverified hints.
    """
    observed: list[str] = []
    unverified: list[str] = []
    noisy_terms = {'bun', 'phpmyadmin', 'metasploit'}
    conservative_terms = ('apache', 'nginx', 'iis', 'php', 'ubuntu', 'debian', 'tomcat', 'mod_dav', 'openssh')
    for item in tech_items or []:
        value = str(item or '').strip()
        if not value:
            continue
        low = value.lower()
        if any(term in low for term in noisy_terms):
            unverified.append(value)
        elif any(term in low for term in conservative_terms):
            observed.append(value)
        else:
            unverified.append(value)
    return sorted(set(observed)), sorted(set(unverified))

def _build_web_exploitation_readiness(services: list[dict[str, Any]], web_summary: dict[str, Any], web_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    web_ports = {80,443,8080,8180,8009,8443}
    for s in services or []:
        port = int(s.get('port') or 0)
        svc = str(s.get('service') or '').lower()
        prod = str(s.get('product') or '')
        if port in web_ports or 'http' in svc or 'ajp' in svc or 'apache' in prod.lower() or 'tomcat' in prod.lower():
            host = s.get('host')
            tech = []
            auth_pages = []
            input_surfaces = []
            upload_surfaces = []
            for item in web_items or []:
                if str(item.get('host')) != str(host):
                    continue
                if item.get('port') and str(item.get('port')) != str(port):
                    continue
                if item.get('tech'):
                    raw_tech = item.get('tech') if isinstance(item.get('tech'), list) else [str(item.get('tech'))]
                    observed_tech, _unverified_tech = _split_technology_hints(raw_tech)
                    tech.extend(observed_tech)
                path = str(item.get('path') or '').lower()
                if any(x in path for x in ['login','admin','manager','phpmyadmin']):
                    auth_pages.append(item.get('path'))
                if any(x in path for x in ['search','query','id=','user','login']):
                    input_surfaces.append(item.get('path'))
                if 'upload' in path:
                    upload_surfaces.append(item.get('path'))
            rows.append({'host':host,'port':port,'protocol':s.get('protocol'),'service':s.get('service'),'candidate_type':'web_exploitation_candidate','framework_or_technology_hints':sorted(set([x for x in tech if x]))[:12], 'auth_surfaces':sorted(set([x for x in auth_pages if x]))[:12], 'input_surfaces':sorted(set([x for x in input_surfaces if x]))[:12], 'upload_surfaces':sorted(set([x for x in upload_surfaces if x]))[:12], 'evidence':'Web/application surface exposed; SQLi/command-injection/content discovery validation deferred to downstream module.', 'recommended_downstream_module':'web_validation', 'recon_boundary':'No SQLi, command injection, vulnerability scanner, or large path discovery executed by recon.'})
    return _dedupe_dicts(rows, ('host','port','service','candidate_type'))

def _build_exploit_validation_candidates(services: list[dict[str, Any]], cves: list[dict[str, Any]], observations: list[dict[str, Any]], web_summary: dict[str, Any], smb_summary: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for c in cves or []:
        candidates.append({
            'category': 'cve_supported_service_candidate',
            'host': c.get('host'),
            'ports': c.get('ports') or c.get('port'),
            'service': c.get('service'),
            'product': c.get('product'),
            'version': c.get('version'),
            'cve': c.get('cve_id') or c.get('id'),
            'handoff_stage': 'exploit_validation_candidate',
            'recon_boundary': 'Recon evidence only; no exploitation executed by recon module.',
        })
    for o in observations or []:
        obs = str(o.get('observation') or '').lower()
        if any(k in obs for k in ['anonymous ftp', 'anonymous smb', 'admin or management web path', 'phpmyadmin', 'database service exposed']):
            candidates.append({
                'category': 'exposure_validation_candidate',
                'host': o.get('host'),
                'ports': f"{o.get('port')}/{o.get('protocol')}" if o.get('port') else '',
                'service': o.get('service'),
                'evidence': o.get('evidence'),
                'handoff_stage': 'controlled_validation_candidate',
                'recon_boundary': 'Candidate CVE input prepared for downstream validation; recon does not attempt access.',
            })
    return candidates

def _coverage_display_status(tool: str, raw_status: str, note: str = '', result: dict[str, Any] | None = None) -> str:
    """Return clean user-facing status wording for evidence collection rows.

    A completed command must not be shown as timed out simply because its output
    contains the word "timeout". Timeout/failed states are based on command
    execution state first, then the collected evidence state.
    """
    result = result or {}
    explicit_state = str(result.get('lifecycle_state') or '').strip().lower()
    if explicit_state in LIFECYCLE_LABELS:
        return LIFECYCLE_LABELS[explicit_state]
    tool_l = (tool or '').lower()
    raw_l = (raw_status or '').lower()
    note_l = (note or '').lower()
    err_l = ' '.join(str(result.get(k) or '') for k in ('stderr', 'error')).lower()
    command_l = str(result.get('command') or '').lower()
    result_success = bool(result.get('success', raw_status != scan_store.STATUS_FAILED))
    returncode = result.get('returncode')

    combined_context = ' '.join([tool_l, raw_l, note_l, err_l, command_l])

    if 'invalid line in colon file' in combined_context or 'missing colon' in combined_context or 'invalid credential combo' in combined_context:
        return 'Input Invalid'
    if tool_l in {'directory_discovery', 'gobuster'} and ('timeout' in err_l or result.get('error') == 'timeout'):
        m = re.search(r'(\d+)\s+path\(s\) observed', note_l)
        if m and int(m.group(1)) > 0:
            return 'Partial Results Captured'
    if 'credential wordlist missing' in combined_context or 'wordlist missing' in combined_context or 'configure a credential file' in combined_context:
        return 'Input Missing'
    if ('not available' in combined_context and 'disabled' in combined_context and ('or no ' in combined_context or 'evidence-trigger disabled' in combined_context)):
        return 'Not Executed - Unavailable/Disabled/Not Applicable'
    if 'not available or incompatible' in combined_context or ('fallback' in combined_context and ('not available' in combined_context or 'incompatible' in combined_context)):
        return 'Tool Unavailable - Fallback Used'
    if 'disabled by scan profile/policy' in combined_context or 'disabled by profile/policy' in combined_context or 'disabled by evidence-tool selection/policy' in combined_context or 'evidence-trigger disabled by default' in combined_context:
        return 'Disabled by Policy/Profile'
    if ('skipped' in combined_context and not result.get('command')) or 'skipped by policy' in combined_context or 'policy scope protection' in combined_context:
        return 'Skipped by Policy'
    if 'deferred' in combined_context and not result.get('command'):
        return 'Deferred'
    if 'disabled or binary unavailable' in combined_context:
        return 'Tool Disabled or Unavailable'
    if 'binary not found' in combined_context or 'command not found' in combined_context or 'tool binary was not found' in combined_context:
        return 'Tool Unavailable'
    if 'not observed' in combined_context or 'no http/https services observed' in combined_context or 'no smb service observed' in combined_context or 'no ldap service observed' in combined_context or 'no tls service observed' in combined_context or 'no rdp service observed' in combined_context or 'udp/161 not observed' in combined_context:
        return 'Not Applicable'
    if not result.get('command') and re.search(r'\bno\b.{0,120}\b(?:service|endpoint|surface|listener)\b.{0,80}\bobserved\b', combined_context):
        return 'Not Applicable'

    if not result_success:
        if returncode == -1 or result.get('error') == 'timeout' or 'command timed out' in err_l or err_l.strip() == 'timeout':
            return 'Timed Out - Incomplete'
        return 'Failed - Incomplete'

    if tool_l == 'directory_discovery' and ('0 path' in note_l or 'zero path' in note_l):
        return 'No Web Paths Observed'
    if raw_status == scan_store.STATUS_EMPTY:
        return 'No Evidence Observed'
    if raw_status == scan_store.STATUS_SUCCESS:
        return 'Completed'
    return str(raw_status or 'Evidence Status Unknown')


def _coverage(tool: str, status: str, info: str, note: str = '', output_file: str = '', result: dict[str, Any] | None = None) -> dict[str, Any]:
    result = result or {}
    raw_status = status
    display_status = _coverage_display_status(tool, raw_status, note, result)
    stderr = (result.get('stderr') or result.get('error') or '')
    stderr = ' '.join(str(stderr).split())[:260]
    failure = ''
    if display_status.startswith(('Failed', 'Timed Out', 'Input Invalid')):
        if result.get('returncode') == -1 and 'timeout' in str(stderr).lower():
            failure = 'Command timed out.'
        elif 'binary not found' in str(stderr).lower():
            failure = 'Tool binary was not found in PATH.'
        elif stderr:
            failure = stderr
        else:
            failure = f"Command exited with code {result.get('returncode')}"
    output_text, output_truncated = ('', False)
    if result:
        try:
            output_text, output_truncated = _captured_command_output(result, Path(output_file or result.get('output_file','')) if (output_file or result.get('output_file')) else None)
        except Exception:
            output_text, output_truncated = ('', False)
    return {
        'tool': tool,
        'status': display_status,
        'raw_status': raw_status,
        'evidence_type': info,
        'information_added': info,
        'note': note,
        'output_file': output_file or result.get('output_file',''),
        'command': result.get('command',''),
        'output': output_text,
        'output_truncated': output_truncated,
        'exit_code': result.get('returncode',''),
        'stderr_summary': stderr if display_status.startswith(('Failed', 'Timed Out')) else '',
        'failure_reason': failure,
        'lifecycle_state': str(result.get('lifecycle_state') or ''),
        'completion_reason': str(result.get('completion_reason') or ''),
        'timed_out': bool(result.get('timed_out')),
        'partial_output_retained': bool(result.get('partial_output_retained')),
    }


def _native_collector_result(tool: str, command: str, output_file: str, produced: bool, note: str = '') -> dict[str, Any]:
    """Result-like object for Python-native passive collectors so coverage and command logs stay consistent."""
    output = ''
    try:
        if output_file and Path(output_file).exists():
            output = Path(output_file).read_text(encoding='utf-8', errors='ignore')[:200000]
    except Exception as exc:
        output = f'Unable to read passive evidence file: {exc}'
    return {
        'success': True,
        'returncode': 0,
        'command': command,
        'stdout': output or note or '[no passive evidence observed]',
        'stderr': '',
        'error': '',
        'output_file': output_file,
        'tool': tool,
        'produced': produced,
    }


def _log_native_collector(scan_id: str, tool: str, command: str, purpose: str, output_file: str, produced: bool) -> dict[str, Any]:
    result = _native_collector_result(tool, command, output_file, produced)
    try:
        output, truncated = _captured_command_output(result, Path(output_file) if output_file else None)
    except Exception:
        output, truncated = (result.get('stdout') or '', False)
    scan_store.log_command(
        scan_id,
        command=command,
        purpose=purpose,
        output=output,
        status='Completed' if produced else 'No Evidence Observed',
        exit_code=0,
        output_file=output_file,
        output_truncated=truncated,
    )
    return result


def _add_raw(raw: list[dict[str, Any]], tool: str, host: str = '', port: int | str = '', path: str = '', parser: str = '', parsed: bool = False) -> None:
    raw.append({'tool': tool, 'host': host, 'port': port, 'file': path, 'parser': parser, 'parsed': parsed})

def _url_for(host: str, port: int, tls: bool=False) -> str:
    if tls or port in {443,8443,9443,636,993,995}: scheme='https'
    else: scheme='http'
    return f'{scheme}://{host}:{port}'

def _wordlist() -> str:
    # Prefer smaller, reliable Kali/SecLists wordlists for interactive recon.
    # Larger medium lists remain configurable through GOBUSTER_WORDLIST.
    candidates=[
        os.getenv('GOBUSTER_WORDLIST','').strip(),
        '/usr/share/wordlists/dirb/common.txt',
        '/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt',
        '/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt',
        Config.GOBUSTER_WORDLIST,
        '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
    ]
    for c in candidates:
        if c and Path(c).exists(): return c
    return Config.GOBUSTER_WORDLIST


def _read_text(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return ''


def _extract_samba_versions_from_smb(smb_items: list[dict[str, Any]]) -> dict[str, str]:
    """Return host -> Samba version discovered from SMB tool output.

    Nmap often reports Samba as a broad range like 3.X - 4.X. smb_share_listing and
    broad_smb_enumeration frequently expose the exact server string in comments,
    e.g. "metasploitable server (Samba 3.0.20-Debian)". That exact version
    must be fed back into CVE matching.
    """
    versions: dict[str, str] = {}
    for item in smb_items:
        host = str(item.get('host') or '')
        if not host:
            continue
        text_parts: list[str] = []
        text_parts.extend(str(value) for value in (item.get('lines') or []) if str(value).strip())
        text_parts.extend(str(value) for value in (item.get('script_evidence') or []) if str(value).strip())
        for row in item.get('rows') or []:
            if isinstance(row, dict):
                for key in ('product', 'version', 'extrainfo', 'fingerprint', 'banner', 'output'):
                    value = str(row.get(key) or '').strip()
                    if value:
                        text_parts.append(value)
            elif str(row).strip():
                text_parts.append(str(row))
        if item.get('output_file'):
            text_parts.append(_read_text(item.get('output_file')))
        text = '\n'.join(text_parts)
        m = re.search(r'Samba\s+([0-9][A-Za-z0-9._~:+-]+)', text, flags=re.I)
        if m:
            versions[host] = m.group(1).strip(') ,.;')
    return versions




def _native_tcp_probe(host: str, port: int, payload: bytes = b'', read_bytes: int = 4096, timeout: float = 4.0) -> tuple[str, str]:
    """Perform one bounded protocol metadata probe without authentication or writes."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if payload:
                sock.sendall(payload)
            try:
                data = sock.recv(read_bytes)
            except socket.timeout:
                data = b''
        return data.decode('utf-8', errors='replace'), ''
    except Exception as exc:
        return '', str(exc)[:180]


def _parse_mysql_handshake(text: str) -> dict[str, Any]:
    # MySQL handshake begins with protocol byte 0x0a followed by a NUL-terminated version string.
    m = re.search(r'\x0a?\s*([0-9]+(?:\.[0-9A-Za-z_+~:-]+)+)', text)
    if not m:
        m = re.search(r'([0-9]+\.[0-9]+\.[0-9A-Za-z_+~:-]+)', text)
    if m:
        return {'product': 'MySQL', 'version': m.group(1).strip(), 'protocol_family': 'mysql'}
    return {}


def _parse_postgres_probe(text: str) -> dict[str, Any]:
    m = re.search(r'PostgreSQL\s+([0-9]+(?:\.[0-9]+){0,3})', text, re.I)
    if m:
        return {'product': 'PostgreSQL', 'version': m.group(1), 'protocol_family': 'postgresql'}
    if 'accepting connections' in text.lower() or 'no response' in text.lower() or 'rejecting connections' in text.lower():
        return {'product': 'PostgreSQL', 'protocol_family': 'postgresql', 'readiness': text.strip()[:200]}
    return {}


def _parse_irc_probe(text: str) -> dict[str, Any]:
    m = re.search(r'(UnrealIRCd)\s+([0-9]+(?:\.[0-9]+){1,4})', text, re.I)
    if m:
        return {'product': 'UnrealIRCd', 'version': m.group(2), 'protocol_family': 'irc'}
    if 'irc' in text.lower():
        return {'product': 'IRC', 'protocol_family': 'irc'}
    return {}


def _parse_vnc_probe(text: str) -> dict[str, Any]:
    m = re.search(r'RFB\s+([0-9]{3})\.([0-9]{3})', text)
    if m:
        return {'product': 'RFB', 'version': f"{int(m.group(1))}.{int(m.group(2))}", 'protocol_family': 'vnc'}
    return {}


def _parse_ftp_probe(text: str) -> dict[str, Any]:
    m = re.search(r'(vsFTPd|vsftpd)\s+([0-9][A-Za-z0-9._~:+-]+)', text, re.I)
    if m:
        return {'product': 'vsftpd', 'version': m.group(2), 'protocol_family': 'ftp'}
    m = re.search(r'(ProFTPD)\s+([0-9][A-Za-z0-9._~:+-]+)', text, re.I)
    if m:
        return {'product': 'ProFTPD', 'version': m.group(2), 'protocol_family': 'ftp'}
    return {}


def _parse_smtp_probe(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {'protocol_family': 'smtp'}
    if 'postfix' in text.lower():
        out['product'] = 'Postfix smtpd'
    caps = []
    for line in text.splitlines():
        line=line.strip()
        m = re.match(r'250[-\s]([A-Z0-9][A-Z0-9_-]+)', line, re.I)
        if m:
            caps.append(m.group(1).upper())
    if caps:
        out['capabilities'] = sorted(set(caps))
    return out if len(out) > 1 else {}


def _collect_native_protocol_enrichment(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Low-noise protocol-specific metadata probes that improve depth without brute force or exploitation."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for svc in services or []:
        host = str(svc.get('host') or '')
        try:
            port = int(svc.get('port') or 0)
        except Exception:
            continue
        name = str(svc.get('service') or '').lower()
        product = str(svc.get('product') or '').lower()
        if not host or not port:
            continue
        tool = ''
        payload = b''
        parser = None
        if port in {21, 2121} or name == 'ftp':
            tool, payload, parser = 'ftp_native_banner', b'SYST\r\nFEAT\r\nQUIT\r\n', _parse_ftp_probe
        elif port == 25 or 'smtp' in name:
            tool, payload, parser = 'smtp_native_ehlo', b'EHLO autopentest.local\r\nQUIT\r\n', _parse_smtp_probe
        elif port == 3306 or 'mysql' in name or 'mysql' in product:
            tool, payload, parser = 'mysql_native_handshake', b'', _parse_mysql_handshake
        elif port == 5432 or 'postgres' in name or 'postgres' in product:
            # PostgreSQL seldom discloses version without auth; capture protocol response/readiness only.
            tool, payload, parser = 'postgres_native_probe', b'\x00\x00\x00\x08\x04\xd2\x16/', _parse_postgres_probe
        elif port == 6667 or 'irc' in name or 'irc' in product:
            tool, payload, parser = 'irc_native_version', b'VERSION\r\nQUIT\r\n', _parse_irc_probe
        elif port == 5900 or 'vnc' in name or 'rfb' in product:
            tool, payload, parser = 'vnc_native_banner', b'', _parse_vnc_probe
        else:
            continue
        key = (host, port, tool)
        if key in seen:
            continue
        seen.add(key)
        text, error = _native_tcp_probe(host, port, payload=payload)
        parsed = parser(text) if parser else {}
        rows.append({'tool': tool, 'host': host, 'port': port, 'service': svc.get('service'), 'raw': text[:4000], 'error': error, 'parsed': parsed, 'recon_boundary': 'Single bounded protocol metadata probe only; no authentication, brute force, writes, mounting, or exploitation.'})
    return rows


def _apply_native_protocol_enrichment(services: list[dict[str, Any]], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for row in rows or []:
        parsed = row.get('parsed') or {}
        if not parsed:
            continue
        host = str(row.get('host') or '')
        port = int(row.get('port') or 0)
        for svc in services or []:
            if str(svc.get('host') or '') != host:
                continue
            try:
                svc_port = int(svc.get('port') or 0)
            except Exception:
                continue
            if svc_port != port:
                continue
            if parsed.get('product') and (not svc.get('product') or str(svc.get('product')).lower() in {'mysql', 'postgresql', 'irc', 'vnc', 'rfb', 'unknown'}):
                svc['product'] = parsed['product']
            if parsed.get('version') and not svc.get('version'):
                svc['version'] = parsed['version']
            details = svc.setdefault('protocol_metadata', {})
            details[row.get('tool') or 'native_protocol'] = parsed
            fingerprint_evidence = svc.setdefault('native_fingerprint_evidence', [])
            fingerprint_evidence.append({
                'tool': 'native_protocol',
                'collector': row.get('tool') or 'native_protocol',
                'product': parsed.get('product') or '',
                'version': parsed.get('version') or '',
                'confidence': 'exact' if parsed.get('version') else 'partial',
                'raw_evidence': row.get('raw') or '',
                'error': row.get('error') or '',
            })
            src = svc.setdefault('evidence_sources', [])
            if row.get('tool') and row.get('tool') not in src:
                src.append(row.get('tool'))
    return services


def _merge_smb_version_evidence(services: list[dict[str, Any]], smb_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    samba_versions = _extract_samba_versions_from_smb(smb_items)
    if not samba_versions:
        return services
    for row in services:
        host = str(row.get('host') or '')
        port = int(row.get('port') or 0)
        service = str(row.get('service') or '').lower()
        product = str(row.get('product') or '').lower()
        if host in samba_versions and (port in {139, 445} or 'samba' in product or 'netbios' in service or 'smb' in service):
            exact = samba_versions[host]
            row['product'] = 'Samba smbd'
            row['version'] = exact
            src = row.get('evidence_sources') or []
            for source in ('nmap', 'smb_share_listing'):
                if source not in src:
                    src.append(source)
            row['evidence_sources'] = src
            row['smb_enriched_version'] = True
    return services



def _attacker_outcome(product: str, cve_id: str, description: str) -> str:
    desc = (description or '').strip()
    if desc:
        first = re.split(r'(?<=[.!?])\s+', desc)[0]
        return f'Official CVE description outcome: {first[:260]}'
    return 'Official CVE record did not include enough outcome text in the indexed description.'


def _remediation_direction(product: str, cve_id: str) -> str:
    return 'Review the official CVE record and vendor advisory; apply the vendor-supported fixed version or documented mitigation.'



def _human_label(value: str) -> str:
    return re.sub(r'\s+', ' ', str(value or '').replace('_', ' ').replace('-', ' ')).strip().title()


def _flatten_observed_fields(value: Any, prefix: str = '') -> list[str]:
    """Flatten already-parsed collector fields without interpreting them."""
    rows: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f'{prefix}.{key}' if prefix else str(key)
            rows.extend(_flatten_observed_fields(item, child))
    elif isinstance(value, (list, tuple, set)):
        if value and all(not isinstance(item, (dict, list, tuple, set)) for item in value):
            rows.append(f'{prefix}: ' + ', '.join(str(item) for item in value))
        else:
            for idx, item in enumerate(value):
                rows.extend(_flatten_observed_fields(item, f'{prefix}[{idx}]'))
    elif value not in (None, '', [], {}):
        rows.append(f'{prefix}: {value}' if prefix else str(value))
    return rows


def _dedupe_observed_text(value: str) -> str:
    """Collapse exact repeated halves/phrases in collector output without altering facts."""
    text = re.sub(r'\s+', ' ', str(value or '')).strip()
    if not text:
        return ''
    words = text.split()
    # Some NSE/native adapters return the same parsed sentence twice.  Remove
    # exact repeated token blocks only; never rewrite non-identical evidence.
    for size in range(len(words) // 2, 3, -1):
        for start in range(0, len(words) - (2 * size) + 1):
            first = words[start:start + size]
            second = words[start + size:start + 2 * size]
            if first == second:
                words = words[:start + size] + words[start + 2 * size:]
                return ' '.join(words).strip()
    return text


_SECURITY_FIELD_TOKENS = {
    'anonymous', 'auth', 'authentication', 'encryption', 'encrypted', 'security', 'signing',
    'cipher', 'tls', 'ssl', 'version_bind_disclosed', 'capabilities', 'exports',
    'accepting_connections', 'protocol_version', 'security_types', 'headers', 'server',
    'powered_by', 'cookie', 'redirect', 'webdav', 'exposure', 'enabled', 'supported', 'required',
}
_SECURITY_SCRIPT_TOKENS = {
    'anon', 'auth', 'encryption', 'security', 'signing', 'protocol', 'cipher', 'tls', 'ssl',
    'vuln', 'access', 'recursion', 'zone-transfer', 'nsid', 'info', 'headers',
}


def _report_worthy_observation(check: str, evidence: str, source_kind: str = 'field') -> bool:
    """Select concise security-relevant facts using schema semantics, not product/CVE rules."""
    check_l = str(check or '').lower()
    evidence_l = str(evidence or '').lower()
    if source_kind == 'script':
        return any(token in check_l for token in _SECURITY_SCRIPT_TOKENS)
    field_name = check_l.split(':', 1)[0].replace('.', '_')
    if not any(token in field_name for token in _SECURITY_FIELD_TOKENS):
        return False
    # Negative inventory fields such as has_soa_answer=False are useful in the
    # appendix but should not be promoted as main-report security conditions.
    if re.search(r':\s*false\s*$', evidence_l):
        dangerous_negative = any(token in field_name for token in ('encryption', 'secure', 'signing', 'supported', 'required'))
        return dangerous_negative
    return True


def _extract_protocol_advertised_tcp_ports(values: list[Any]) -> list[int]:
    """Extract TCP endpoints explicitly advertised by captured protocol evidence.

    Currently this recognises the structured ``tcp_port:`` field emitted by
    Nmap's MSRPC endpoint-mapper collector.  It does not guess ports from
    product names or vulnerability data.
    """
    ports: set[int] = set()
    for value in values or []:
        text = str(value or '')
        for match in re.finditer(r'(?im)^\s*(?:[|_]\s*)?tcp_port\s*:\s*(\d{1,5})\s*$', text):
            port = int(match.group(1))
            if 1 <= port <= 65535:
                ports.add(port)
    return sorted(ports)


def _nmap_script_evidence_from_file(path_value: Any) -> list[tuple[str, str]]:
    """Read script IDs/output from an Nmap XML evidence file, including host scripts."""
    path = Path(str(path_value or ''))
    if not path.exists() or path.suffix.lower() != '.xml':
        return []
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return []
    rows: list[tuple[str, str]] = []
    for script in root.findall('.//script'):
        script_id = str(script.attrib.get('id') or '').strip()
        output = str(script.attrib.get('output') or '').strip()
        if script_id and output:
            rows.append((script_id, output))
    return rows


def _build_observed_security_evidence(
    service_level_checks: list[dict[str, Any]],
    modern_active_validation: dict[str, Any],
) -> list[dict[str, Any]]:
    """Normalize all collector facts for the technical appendix.

    This layer never assigns a CVE, severity, vulnerability status or expected
    target outcome.  It serialises structured fields and Nmap script output.
    """
    conditions: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add(host: Any, port: Any, protocol: str, source: str, check: str, evidence: str, source_kind: str) -> None:
        evidence = _dedupe_observed_text(evidence)
        if not evidence:
            return
        key = (str(host or ''), str(port or ''), str(check or source), evidence)
        if key in seen:
            return
        seen.add(key)
        conditions.append({
            'host': host or '',
            'port': port or '',
            'protocol': protocol or 'tcp',
            'source': source or 'collector',
            'check': check or source or 'observed evidence',
            'condition': _human_label(check or source or 'Observed evidence'),
            'evidence': evidence[:1200],
            'source_kind': source_kind,
            'classification': 'Observed evidence; no CVSS or vulnerability status inferred',
        })

    def consume(item: dict[str, Any], default_source: str = '') -> None:
        if not isinstance(item, dict):
            return
        source = str(item.get('tool') or default_source or 'collector')
        host = item.get('host')
        port = item.get('port')
        protocol = str(item.get('protocol') or 'tcp')
        for row in item.get('rows') or []:
            if not isinstance(row, dict):
                continue
            row_host = row.get('host') or host
            row_port = row.get('port') or row.get('portid') or port
            row_proto = str(row.get('protocol') or protocol)
            for script in row.get('scripts') or []:
                if isinstance(script, dict):
                    add(row_host, row_port, row_proto, source, str(script.get('id') or source), str(script.get('output') or ''), 'script')
        # Host-script output is not always attached to a port row by the parser.
        # The service-level check already carries the authorised endpoint, so
        # parse scripts from its own evidence file without inventing a port.
        for script_id, output in _nmap_script_evidence_from_file(item.get('output_file')):
            add(host, port, protocol, source, script_id, output, 'script')
        parsed = item.get('parsed') or {}
        if isinstance(parsed, dict) and str(parsed.get('evidence_state') or '').lower() == 'observed':
            fields = parsed.get('fields') or {}
            for line in _flatten_observed_fields(fields):
                check_name = line.split(':', 1)[0].strip() or source
                add(host, port, protocol, source, check_name, line, 'field')

    for item in service_level_checks or []:
        consume(item)
    for tool, items in (modern_active_validation or {}).items():
        if not isinstance(items, list):
            continue
        for item in items:
            consume(item, str(tool))

    # Collapse equivalent collector summaries while leaving the raw evidence
    # files untouched. Some NSE/native adapters expose both a structured value
    # and the same value embedded in a longer sentence.
    collapsed: list[dict[str, Any]] = []
    by_check: dict[tuple[str, str, str, str, str], int] = {}
    for row in conditions:
        group = (
            str(row.get('host') or ''), str(row.get('port') or ''),
            str(row.get('protocol') or ''), str(row.get('source') or ''),
            _identity_text(row.get('check')),
        )
        evidence = str(row.get('evidence') or '')
        normalized = _identity_text(evidence)
        existing_idx = by_check.get(group)
        if existing_idx is None:
            by_check[group] = len(collapsed)
            collapsed.append(row)
            continue
        existing = collapsed[existing_idx]
        existing_text = str(existing.get('evidence') or '')
        existing_norm = _identity_text(existing_text)
        if normalized == existing_norm or (normalized and existing_norm and (normalized in existing_norm or existing_norm in normalized)):
            # Prefer the concise representation for the normalized report; both
            # source outputs remain available in the raw command evidence.
            if len(evidence) < len(existing_text):
                collapsed[existing_idx] = row
            continue
        by_check[group + (str(len(collapsed)),)] = len(collapsed)
        collapsed.append(row)
    return sorted(collapsed, key=lambda row: (str(row.get('host')), int(row.get('port') or 0), str(row.get('check')), str(row.get('source'))))


def _build_observed_security_conditions(
    service_level_checks: list[dict[str, Any]],
    modern_active_validation: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return concise, report-worthy security observations from normalized evidence."""
    all_rows = _build_observed_security_evidence(service_level_checks, modern_active_validation)
    return [
        row for row in all_rows
        if _report_worthy_observation(str(row.get('check') or ''), str(row.get('evidence') or ''), str(row.get('source_kind') or 'field'))
    ]


def _direct_windows_identity_contexts(host_identities: list[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    """Return the strongest directly observed precise Windows identity per host.

    This adapter is deliberately evidence-semantic rather than target-specific:
    probabilistic fingerprints, service hints, and advisory-resolution metadata
    never qualify as direct Windows build context.
    """
    contexts: dict[str, dict[str, Any]] = {}
    for identity in host_identities or []:
        if str(identity.get('scope') or 'host_os') != 'host_os':
            continue
        host = str(identity.get('host') or '').strip()
        product = str(identity.get('product') or identity.get('name') or '').strip()
        family = str(identity.get('family') or '').strip().lower()
        vendor = str(identity.get('vendor') or '').strip().lower()
        build = str(identity.get('build') or identity.get('version') or identity.get('release') or '').strip()
        kind = str(identity.get('evidence_kind') or '').strip().lower()
        if not host or not product or not build:
            continue
        if family != 'windows' and 'microsoft' not in vendor and 'windows' not in product.lower():
            continue
        if kind in {'probabilistic_fingerprint', 'service_os_hint', 'official_product_resolution'} or bool(identity.get('resolution_candidate')):
            continue
        authority = int(identity.get('authority_tier') if str(identity.get('authority_tier') or '').isdigit() else 2)
        if authority > 2:
            continue
        if not identity_is_precise_for_cve(identity):
            continue
        candidate = dict(identity)
        candidate['_authority'] = authority
        current = contexts.get(host)
        if current is None or (authority, 0 if candidate.get('build') else 1) < (int(current.get('_authority') or 9), 0 if current.get('build') else 1):
            contexts[host] = candidate
    return contexts


def _observed_version_is_range(value: str) -> bool:
    text = str(value or '').strip()
    if not text:
        return False
    # Accept concrete and wildcard version tokens (for example 1.2.3 - 1.2.9
    # or 3.X - 4.X) without encoding any product-specific version facts.
    token = r'\d+(?:\.(?:\d+|[xX*])){0,5}[A-Za-z0-9._-]*'
    return bool(re.search(rf'{token}\s+(?:-|to|through|thru)\s+{token}', text, re.I))


def _identity_text(value: Any) -> str:
    return re.sub(r'[^a-z0-9]+', ' ', str(value or '').lower()).strip()


def _same_product_identity(left: Any, right: Any) -> bool:
    a, b = _identity_text(left), _identity_text(right)
    if not a or not b:
        return False
    if a == b:
        return True
    a_tokens = set(a.split())
    b_tokens = set(b.split())
    # Application/container and connector/server layers can share a vendor
    # token while representing different products. Do not collapse Coyote into
    # Tomcat merely because one observed label contains both words.
    if ('coyote' in a_tokens) != ('coyote' in b_tokens) and ('tomcat' in a_tokens or 'tomcat' in b_tokens):
        return False
    return bool(a_tokens and b_tokens and (a_tokens <= b_tokens or b_tokens <= a_tokens))


def _append_observed_identity(row: dict[str, Any], identity: dict[str, Any]) -> None:
    """Retain an observed identity without replacing a different software layer."""
    service = str(identity.get('service') or '').strip()
    product = str(identity.get('product') or '').strip()
    version = str(identity.get('version') or '').strip()
    if not product and not version and service.lower() in {'', 'unknown', 'unidentified'}:
        return
    cpes = [str(x) for x in identity.get('cpe') or [] if str(x).strip()]
    sources = identity.get('sources') or identity.get('source') or []
    if not isinstance(sources, list):
        sources = [sources]
    clean = {
        'kind': str(identity.get('kind') or 'observed_service'),
        'service': service,
        'product': product,
        'version': version,
        'cpe': list(dict.fromkeys(cpes)),
        'sources': list(dict.fromkeys(str(x) for x in sources if str(x).strip())),
        'evidence': str(identity.get('evidence') or '').strip()[:600],
    }
    identities = row.setdefault('observed_identities', [])
    sig = (_identity_text(service), _identity_text(product), version.lower(), clean['kind'])
    for existing in identities:
        existing_sig = (
            _identity_text(existing.get('service')), _identity_text(existing.get('product')),
            str(existing.get('version') or '').lower(), str(existing.get('kind') or ''),
        )
        if existing_sig == sig:
            existing['cpe'] = list(dict.fromkeys(list(existing.get('cpe') or []) + clean['cpe']))
            existing['sources'] = list(dict.fromkeys(list(existing.get('sources') or []) + clean['sources']))
            if clean['evidence'] and not existing.get('evidence'):
                existing['evidence'] = clean['evidence']
            return
    identities.append(clean)


def _current_identity(row: dict[str, Any], kind: str = 'observed_service', source: str = '') -> dict[str, Any]:
    return {
        'kind': kind,
        'service': row.get('service'),
        'product': row.get('product'),
        'version': row.get('version'),
        'cpe': row.get('cpe') or [],
        'source': source or (row.get('evidence_sources') or []),
        'evidence': row.get('extra') or row.get('extrainfo') or '',
    }


def _web_application_identity(item: dict[str, Any]) -> dict[str, Any] | None:
    """Extract a versioned application title only when corroborated by technology evidence."""
    title = str(item.get('title') or '').strip()
    tech = item.get('tech') or item.get('technologies') or []
    if not isinstance(tech, (list, tuple, set)):
        tech = [tech] if tech else []
    match = re.match(r'^(.{2,100}?)[/ ]v?(\d+(?:\.\d+){1,4}(?:[-._A-Za-z0-9]*)?)$', title)
    if not match:
        return None
    product = match.group(1).strip(' -/:')
    version = match.group(2).strip()
    product_tokens = {x for x in _identity_text(product).split() if len(x) >= 3}
    tech_tokens = {x for value in tech for x in _identity_text(value).split() if len(x) >= 3}
    if not product_tokens or not (product_tokens & tech_tokens):
        return None
    return {
        'kind': 'web_application',
        'service': 'http' if str(item.get('scheme') or '').lower() == 'http' else ('https' if str(item.get('scheme') or '').lower() == 'https' else ''),
        'product': product,
        'version': version,
        'source': 'httpx',
        'evidence': ' | '.join(x for x in [f'Title: {title}', ('Technology: ' + ', '.join(map(str, tech))) if tech else ''] if x),
    }


def _attach_web_observed_identities(services: list[dict[str, Any]], web_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_endpoint: dict[tuple[str, int], dict[str, Any]] = {}
    for row in services or []:
        try:
            by_endpoint[(str(row.get('host') or '').strip('[]').lower(), int(row.get('port') or 0))] = row
        except (TypeError, ValueError):
            continue
    for item in web_items or []:
        if not isinstance(item, dict):
            continue
        host, port = _endpoint_values(item)
        row = by_endpoint.get((host, port)) or by_endpoint.get((str(item.get('host') or '').strip('[]').lower(), port))
        if not row:
            continue
        identity = _web_application_identity(item)
        if identity:
            _append_observed_identity(row, identity)
    return services


def _attach_discovery_observed_identities(services: list[dict[str, Any]], discovery_evidence: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Preserve non-destructive service names observed during initial discovery."""
    by_endpoint: dict[tuple[str, int, str], dict[str, Any]] = {}
    for row in services or []:
        try:
            key = (str(row.get('host') or '').strip('[]').lower(), int(row.get('port') or 0), str(row.get('protocol') or 'tcp').lower())
        except (TypeError, ValueError):
            continue
        by_endpoint[key] = row
    for host, evidence in (discovery_evidence or {}).items():
        for observed in (evidence or {}).get('ports') or []:
            if str(observed.get('state') or '').lower() != 'open':
                continue
            try:
                port = int(observed.get('port') or 0)
            except (TypeError, ValueError):
                continue
            protocol = str(observed.get('protocol') or 'tcp').lower()
            row = by_endpoint.get((str(host).strip('[]').lower(), port, protocol))
            if not row:
                continue
            service_name = str(observed.get('service') or observed.get('name') or '').strip()
            if service_name:
                _append_observed_identity(row, {
                    'kind': 'discovery_service',
                    'service': service_name,
                    'source': 'operator_selected_discovery',
                })
                _refresh_transport_security(row)
    return services


def _identity_context_text(row: dict[str, Any]) -> str:
    primary = (_identity_text(row.get('service')), _identity_text(row.get('product')), str(row.get('version') or '').lower())
    parts: list[str] = []
    for ident in row.get('observed_identities') or []:
        sig = (_identity_text(ident.get('service')), _identity_text(ident.get('product')), str(ident.get('version') or '').lower())
        if sig == primary:
            continue
        label = ' '.join(x for x in [str(ident.get('product') or '').strip(), str(ident.get('version') or '').strip()] if x).strip()
        if not label:
            label = str(ident.get('service') or '').strip()
        if not label:
            continue
        kind = _human_label(str(ident.get('kind') or 'Observed identity'))
        text = f'{kind}: {label}'
        if text not in parts:
            parts.append(text)
    return '; '.join(parts)



def _service_identity_authority(row: dict[str, Any]) -> int:
    """Rank service identity evidence; lower is stronger."""
    attrs = row.get('service_attributes') or {}
    method = str(attrs.get('method') or '').strip().lower()
    product = str(row.get('product') or '').strip()
    version = str(row.get('version') or '').strip()
    service = str(row.get('service') or '').strip().lower()
    if method == 'probed' and (product or version):
        return 0
    if method == 'probed':
        return 1
    sources = {str(x).strip().lower() for x in row.get('evidence_sources') or [] if str(x).strip()}
    if (product or version) and any(token in source for source in sources for token in ('native', 'httpx', 'banner', 'protocol')):
        return 1
    if method == 'table':
        return 4
    if service in {'', 'unknown', 'unidentified'}:
        return 5
    if product or version:
        return 2
    return 3


def _refresh_transport_security(row: dict[str, Any]) -> dict[str, Any]:
    """Derive TLS transport from observed evidence, never from a port number."""
    attrs = row.get('service_attributes') or {}
    tunnel = str(attrs.get('tunnel') or '').strip().lower()
    tokens: list[str] = [
        str(row.get('service') or '').strip().lower(),
        str(row.get('identity_context') or '').strip().lower(),
    ]
    for identity in row.get('observed_identities') or []:
        tokens.extend([
            str(identity.get('service') or '').strip().lower(),
            str(identity.get('product') or '').strip().lower(),
        ])
    text = ' '.join(tokens).replace('_', ' ').replace('-', ' ')
    if tunnel in {'ssl', 'tls'} or re.search(r'(?<![a-z0-9])(https|ssl|tls)(?![a-z0-9])', text):
        row['transport_security'] = 'tls'
        row['transport_security_evidence'] = (
            f'nmap service tunnel={tunnel}' if tunnel in {'ssl', 'tls'}
            else 'observed HTTPS/TLS service identity'
        )
    elif row.get('transport_security') == 'tls':
        # Never erase stronger evidence established by an earlier merge.
        pass
    else:
        row.setdefault('transport_security', '')
    return row


def _merge_service_identity_rows(base_rows: list[dict[str, Any]], recovery_rows: list[dict[str, Any]], evidence_source: str) -> list[dict[str, Any]]:
    """Merge targeted re-probes using evidence authority, not first non-empty text."""
    by_key: dict[tuple[str, int, str], dict[str, Any]] = {}
    for row in base_rows or []:
        try:
            key = (str(row.get('host') or ''), int(row.get('port') or 0), str(row.get('protocol') or 'tcp').lower())
        except (TypeError, ValueError):
            continue
        _append_observed_identity(row, _current_identity(row, 'pre_recovery', 'existing_scan_evidence'))
        _refresh_transport_security(row)
        by_key[key] = row

    for extra in recovery_rows or []:
        try:
            key = (str(extra.get('host') or ''), int(extra.get('port') or 0), str(extra.get('protocol') or 'tcp').lower())
        except (TypeError, ValueError):
            continue
        current = by_key.get(key)
        if current is None:
            _refresh_transport_security(extra)
            base_rows.append(extra)
            by_key[key] = extra
            continue

        _append_observed_identity(current, _current_identity(extra, 'version_recovery', evidence_source))
        current_authority = _service_identity_authority(current)
        recovered_authority = _service_identity_authority(extra)
        recovered_is_stronger = recovered_authority < current_authority

        current_product = str(current.get('product') or '').strip()
        recovered_product = str(extra.get('product') or '').strip()
        current_version = str(current.get('version') or '').strip()
        recovered_version = str(extra.get('version') or '').strip()

        if recovered_is_stronger:
            recovered_service = str(extra.get('service') or '').strip()
            if recovered_service:
                current['service'] = recovered_service
            if recovered_product:
                current['product'] = recovered_product
                current_product = recovered_product
            if recovered_version:
                current['version'] = recovered_version
            if str(extra.get('extra') or extra.get('extrainfo') or '').strip():
                current['extra'] = extra.get('extra') or extra.get('extrainfo')
            if extra.get('service_attributes'):
                merged_attrs = dict(current.get('service_attributes') or {})
                merged_attrs.update({k: v for k, v in (extra.get('service_attributes') or {}).items() if str(v or '').strip()})
                current['service_attributes'] = merged_attrs
        else:
            recovered_service = str(extra.get('service') or '').strip()
            if recovered_service and str(current.get('service') or '').strip().lower() in {'', 'unknown', 'unidentified'}:
                current['service'] = recovered_service
            if recovered_product and not current_product:
                current['product'] = recovered_product
                current_product = recovered_product
            if recovered_version and (not current_version or _observed_version_is_range(current_version)):
                if not recovered_product or not current_product or _same_product_identity(current_product, recovered_product):
                    current['version'] = recovered_version
            if str(extra.get('extra') or extra.get('extrainfo') or '').strip() and not str(current.get('extra') or current.get('extrainfo') or '').strip():
                current['extra'] = extra.get('extra') or extra.get('extrainfo')
            merged_attrs = dict(current.get('service_attributes') or {})
            for key_name, value in (extra.get('service_attributes') or {}).items():
                if str(value or '').strip() and not str(merged_attrs.get(key_name) or '').strip():
                    merged_attrs[key_name] = value
            if merged_attrs:
                current['service_attributes'] = merged_attrs

        for cpe_field in ('cpe', 'os_cpe', 'hardware_cpe'):
            current[cpe_field] = list(dict.fromkeys(list(current.get(cpe_field) or []) + list(extra.get(cpe_field) or [])))
        sources = list(current.get('evidence_sources') or [])
        for source in list(extra.get('evidence_sources') or []) + [evidence_source]:
            if source and source not in sources:
                sources.append(source)
        current['evidence_sources'] = sources
        if extra.get('scripts'):
            current['scripts'] = list(current.get('scripts') or []) + [
                item for item in extra.get('scripts') or []
                if item not in (current.get('scripts') or [])
            ]
        current['identity_context'] = _identity_context_text(current)
        _refresh_transport_security(current)
    return base_rows


def _structured_prerequisite_context(match: dict[str, Any], service: dict[str, Any]) -> dict[str, Any]:
    req = match.get('structured_requirements') or {}
    modules = [str(x) for x in req.get('modules') or [] if str(x).strip()]
    platforms = [str(x) for x in req.get('platforms') or [] if str(x).strip()]
    package_name = str(req.get('package_name') or '').strip()
    published = {'modules': modules, 'platforms': platforms, 'package_name': package_name}
    tokens = modules + platforms + ([package_name] if package_name else [])
    if not tokens:
        return {'status': 'not_published', 'published': published, 'observed': [], 'note': 'No machine-readable prerequisite field was available in the matched affected entry. Narrative applicability conditions may still exist.'}
    evidence_text = ' '.join([
        str(service.get('service') or ''), str(service.get('product') or ''), str(service.get('version') or ''),
        str(service.get('extra') or service.get('extrainfo') or ''),
        ' '.join(str(x.get('output') or '') for x in (service.get('scripts') or []) if isinstance(x, dict)),
    ]).lower()
    observed = [token for token in tokens if _normalise_product_name(token) and _normalise_product_name(token) in _normalise_product_name(evidence_text)]
    status = 'observed' if len(observed) == len(tokens) else ('partially_observed' if observed else 'not_established')
    return {
        'status': status,
        'published': published,
        'observed': observed,
        'note': 'Structured prerequisites are reported separately from Candidate CVE correlation; absence of evidence is not treated as proof of absence.',
    }


def _enrich_missing_cvss_from_nvd(rows: list[dict[str, Any]], diagnostics: list[dict[str, Any]]) -> None:
    """Enrich only missing CVSS 3.1/4.0 metrics by exact CVE ID.

    CVE Program metrics always have precedence. NVD may fill a *missing* 3.1
    and/or 4.0 metric independently, but never overwrites, converts, or treats
    one CVSS version as a fallback for the other. Candidate generation and validation state are unchanged.
    """
    # PenPilot intentionally supports only CVSS 3.1 and CVSS 4.0. Each version
    # remains independent; neither is converted into or used as a fallback for
    # the other.
    supported_versions = ('3.1', '4.0')
    cache: dict[str, tuple[dict[str, dict[str, Any]], dict[str, Any]]] = {}
    nvd_unavailable = False
    for row in rows or []:
        primary = dict(row.get('source_cvss_metrics') or row.get('cvss_metrics') or {})
        row['cve_program_cvss_metrics'] = primary
        effective = dict(primary)
        missing_versions = [version for version in supported_versions if not isinstance(primary.get(version), dict)]
        if not missing_versions:
            row['effective_cvss_metrics'] = effective
            row['nvd_cvss_metrics'] = {}
            row['nvd_cvss_enrichment'] = {
                'status': 'not_required',
                'reason': 'CVE Program record already publishes both supported CVSS 3.1 and 4.0 metrics.',
                'versions': [],
                'requested_versions': [],
            }
            continue
        cve_id = str(row.get('cve_id') or '').upper()
        if not cve_id:
            row['effective_cvss_metrics'] = effective
            row['nvd_cvss_metrics'] = {}
            row['nvd_cvss_enrichment'] = {
                'status': 'not_queried', 'reason': 'CVE identifier unavailable.',
                'versions': [], 'requested_versions': missing_versions,
            }
            continue
        if nvd_unavailable:
            row['effective_cvss_metrics'] = effective
            row['nvd_cvss_metrics'] = {}
            row['nvd_cvss_enrichment'] = {
                'status': 'unavailable',
                'reason': 'NVD enrichment was unavailable earlier in this scan; additional network lookups were skipped.',
                'versions': [],
                'requested_versions': missing_versions,
            }
            continue
        if cve_id not in cache:
            cache[cve_id] = nvd_lookup_cve_metrics(cve_id)
        nvd_metrics, diagnostic = cache[cve_id]
        diagnostic_copy = dict(diagnostic)
        diagnostics.append(diagnostic_copy)
        matcher_status = str(diagnostic_copy.get('matcher_status') or diagnostic_copy.get('status') or '').lower()
        if matcher_status in {'degraded', 'error', 'disabled', 'unavailable'}:
            nvd_unavailable = True

        retained_nvd: dict[str, dict[str, Any]] = {}
        for version in missing_versions:
            metric = (nvd_metrics or {}).get(version)
            if isinstance(metric, dict):
                retained_nvd[version] = dict(metric)
                effective[version] = dict(metric)
        row['nvd_cvss_metrics'] = retained_nvd
        if retained_nvd:
            enrichment_status = 'available'
            enrichment_reason = (
                'NVD exact-ID metadata filled only CVSS version(s) missing from the CVE Program record; '
                'no published CVE Program metric was overwritten.'
            )
        elif matcher_status in {'degraded', 'error', 'disabled', 'unavailable'}:
            enrichment_status = 'unavailable'
            enrichment_reason = str(diagnostic_copy.get('reason') or 'NVD enrichment unavailable.')
        else:
            enrichment_status = 'no_metric_published'
            enrichment_reason = (
                'NVD was queried by exact CVE ID and returned no metric for the requested CVSS '
                f"version(s) ({', '.join(missing_versions)}). Versions outside this set are not "
                'requested by this pipeline and their absence here is not evidence that no metric exists.'
            )
        row['nvd_cvss_enrichment'] = {
            'status': enrichment_status,
            'reason': enrichment_reason,
            'versions': sorted(retained_nvd.keys()),
            'requested_versions': missing_versions,
            'parser_supported_versions': list(supported_versions),
            'lookup_state': matcher_status or 'available',
        }
        row['effective_cvss_metrics'] = effective


def _sanitise_export_paths(value: Any) -> Any:
    """Remove local project storage prefixes from exported client artifacts."""
    if isinstance(value, dict):
        return {key: _sanitise_export_paths(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitise_export_paths(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitise_export_paths(item) for item in value)
    if isinstance(value, str):
        pattern = re.compile(r'/(?:[^\s"\']+/)*storage/(?:scans|results)/([^\s"\']+)')
        return pattern.sub(lambda m: f'evidence/{Path(m.group(1)).name}', value)
    return value


def _build_security_observations(services: list[dict[str, Any]], smb_items: list[dict[str, Any]], web_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract pentester-facing exposure observations from collected evidence.

    These are not ranked or scored. They are grouped later so the report reads
    like a pentester workbench instead of a tool dump.
    """
    observations=[]; seen=set()
    def add(host, port, protocol, service, observation, evidence, category='Exposure'):
        key=(str(host), str(port), str(protocol), str(observation))
        if key not in seen:
            seen.add(key)
            observations.append({'host':host,'port':port,'protocol':protocol,'service':service,'observation':observation,'evidence':evidence,'category':category})
    for s in services:
        host=s.get('host'); port=s.get('port'); proto=s.get('protocol'); svc=str(s.get('service','')).lower(); prod=str(s.get('product',''))
        try: pnum = int(port or 0)
        except Exception: pnum = 0
        if svc == 'bindshell' or 'root shell' in prod.lower() or pnum == 1524:
            add(host, port, proto, s.get('service'), 'Shell-like service indicator observed on an exposed port.', 'Nmap service fingerprint identified a root-shell style service.', 'Remote Access')
        if pnum == 23 or svc == 'telnet':
            add(host, port, proto, s.get('service'), 'Plaintext remote administration service exposed.', 'Telnet service was identified on the target.', 'Remote Access')
        if pnum in {512,513,514} or svc in {'exec','login','shell'}:
            add(host, port, proto, s.get('service'), 'Legacy r-service remote access surface exposed.', 'rexec/rlogin/rsh-style service was observed.', 'Remote Access')
        if pnum in {2049, 111} or svc in {'nfs', 'rpcbind'}:
            add(host, port, proto, s.get('service'), 'RPC/NFS file-sharing surface observed.', 'RPC/NFS services were observed through rpcbind and NFS-related ports. Vendor identity is not asserted unless sufficient identifying evidence is collected.', 'File Sharing')
        if pnum == 6000 or svc.lower() == 'x11':
            add(host, port, proto, s.get('service'), 'X11 display service exposed.', 'Nmap identified an X11 service response.', 'Remote GUI')
        if pnum == 5900 or svc == 'vnc':
            add(host, port, proto, s.get('service'), 'VNC remote desktop service exposed.', 'Nmap identified a VNC service response.', 'Remote GUI')
        if pnum in {3306,5432} or svc in {'mysql','postgresql'}:
            add(host, port, proto, s.get('service'), 'Database service exposed on the network.', 'Service fingerprinting identified a database listener.', 'Database')
        if pnum == 8009 or 'ajp' in svc:
            add(host, port, proto, s.get('service'), 'AJP connector exposed.', 'AJP service was identified and checked with AJP scripts where available.', 'Web')
        if pnum in {8180, 8080, 8081, 8443} and (svc in {'unknown', ''} or not prod):
            add(host, port, proto, s.get('service'), 'Unknown application service observed.', 'Application service observed on this TCP port. Sufficient evidence was not available to confidently identify the underlying product; follow-up HTTP/Tomcat validation may be appropriate if in scope.', 'Web')
        if svc == 'ftp' or pnum in {21, 2121}:
            script_text = ' '.join(str(x.get('output','')) for x in (s.get('scripts') or []))
            if 'anonymous ftp login allowed' in script_text.lower() or 'ftp code 230' in script_text.lower():
                add(host, port, proto, s.get('service'), 'Anonymous FTP access allowed.', 'ftp-anon reported anonymous FTP login was allowed.', 'File Transfer')
    for item in smb_items:
        text='\n'.join(item.get('lines') or [])
        if item.get('output_file'):
            text += '\n' + _read_text(item.get('output_file'))
        if 'Anonymous login successful' in text or re.search(r'\bSharename\b', text, re.I):
            add(item.get('host'), 445, 'tcp', 'smb', 'Anonymous SMB share listing available.', 'smb_share_listing output includes anonymous access evidence or visible share names.', 'File Sharing')
    for item in web_items:
        if item.get('tool') == 'directory_discovery' or item.get('path'):
            path_value = str(item.get('path') or '').lower()
            evidence = f"Directory discovery reported {item.get('path')} with status {item.get('status_code')}."
            if 'phpmyadmin' in path_value:
                add(item.get('host'), item.get('port'), 'tcp', 'http', 'phpMyAdmin path observed.', evidence, 'Web')
            if 'phpinfo' in path_value or 'release-notes' in path_value or path_value.endswith('.txt'):
                add(item.get('host'), item.get('port'), 'tcp', 'http', 'Information-disclosure style web path observed.', evidence, 'Web')
            if 'admin' in path_value or 'manager' in path_value:
                add(item.get('host'), item.get('port'), 'tcp', 'http', 'Admin or management web path observed.', evidence, 'Web')
            if 'webdav' in path_value:
                add(item.get('host'), item.get('port'), 'tcp', 'http', 'WebDAV path observed.', evidence, 'Web')
        rows=item.get('rows') or []
        for row in rows:
            for script in row.get('scripts') or []:
                out=script.get('output','') or ''
                low=out.lower()
                if 'phpmyadmin' in low:
                    add(row.get('host'), row.get('port'), row.get('protocol'), row.get('service'), 'phpMyAdmin path observed.', f"Nmap HTTP script {script.get('id')} reported phpMyAdmin-related content.", 'Web')
                if 'phpinfo.php' in low or 'possible information file' in low:
                    add(row.get('host'), row.get('port'), row.get('protocol'), row.get('service'), 'Information-disclosure style web path observed.', f"Nmap HTTP script {script.get('id')} reported information file evidence.", 'Web')
                if 'directory listing' in low:
                    add(row.get('host'), row.get('port'), row.get('protocol'), row.get('service'), 'Directory listing or browsable web path observed.', f"Nmap HTTP script {script.get('id')} reported directory listing evidence.", 'Web')
                if 'manager/html' in low or 'admin' in low:
                    add(row.get('host'), row.get('port'), row.get('protocol'), row.get('service'), 'Admin or management web path observed.', f"Nmap HTTP script {script.get('id')} reported admin/manager path evidence.", 'Web')
    return sorted(observations, key=lambda o: (str(o.get('category')), str(o.get('host')), str(o.get('port')), str(o.get('observation'))))


def _summarise_web_inventory(web_items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    services: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []
    unverified_hints: list[dict[str, Any]] = []
    seen_services = set()
    seen_paths = set()
    seen_hints = set()
    for item in web_items:
        if item.get('tech'):
            raw_tech = item.get('tech') if isinstance(item.get('tech'), list) else [str(item.get('tech'))]
            _observed_tech, unverified_tech = _split_technology_hints(raw_tech)
            for hint in unverified_tech:
                key = (item.get('host'), item.get('port'), hint)
                if key not in seen_hints:
                    seen_hints.add(key)
                    unverified_hints.append({'host': item.get('host'), 'port': item.get('port'), 'hint': hint, 'source': 'httpx', 'interpretation': 'Unverified technology hint; excluded from MITRE matching and evidence-backed conclusions.'})
        if item.get('tool') == 'directory_discovery' or item.get('path'):
            key = (item.get('host'), item.get('port'), item.get('path'))
            if key not in seen_paths:
                seen_paths.add(key)
                paths.append({
                    'host': item.get('host'),
                    'port': item.get('port'),
                    'path': item.get('path'),
                    'status_code': item.get('status_code'),
                    'size': item.get('size'),
                    'source': item.get('tool') or 'directory_discovery',
                    'evidence_file': item.get('raw_evidence_file') or item.get('output_file') or '',
                })
        if item.get('tool') == 'nmap_http_scripts':
            for row in item.get('rows') or []:
                scripts = {s.get('id'): s.get('output') for s in row.get('scripts') or []}
                key = (row.get('host'), row.get('port'))
                if key not in seen_services:
                    seen_services.add(key)
                    services.append({
                        'host': row.get('host'),
                        'port': row.get('port'),
                        'service': row.get('service'),
                        'product': row.get('product'),
                        'version': row.get('version'),
                        'title': scripts.get('http-title', ''),
                        'server_header': scripts.get('http-server-header', ''),
                        'http_enum': scripts.get('http-enum', ''),
                        'evidence_file': item.get('output_file') or row.get('raw_evidence_file') or '',
                    })
    return {'services': services, 'paths': paths, 'unverified_technology_hints': unverified_hints}


def _summarise_smb_inventory(smb_items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    shares: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    for item in smb_items:
        tool = item.get('tool')
        host = item.get('host')
        output_file = item.get('output_file') or ''
        tools.append({'tool': tool, 'host': host, 'evidence_file': output_file})
        if tool == 'smb_share_listing':
            for line in item.get('lines') or []:
                m = re.match(r'^(?P<name>[A-Za-z0-9_$.-]+)\s+(?P<type>Disk|IPC|Printer)\s*(?P<comment>.*)$', line)
                if m and m.group('name').lower() not in {'sharename', '---------'}:
                    shares.append({
                        'host': host,
                        'share': m.group('name'),
                        'type': m.group('type'),
                        'comment': m.group('comment').strip(),
                        'source': 'smb_share_listing',
                        'evidence_file': output_file,
                    })
    return {'shares': shares, 'tools': tools}


def _detect_cross_host_evidence_contamination(smb_summary: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    shares = smb_summary.get('shares') or []
    hosts = {str(s.get('host')) for s in shares if s.get('host')}
    for host in hosts:
        host_shares = {str(s.get('share')) for s in shares if str(s.get('host')) == host}
        for other in hosts - {host}:
            other_shares = {str(s.get('share')) for s in shares if str(s.get('host')) == other}
            overlap = sorted((host_shares & other_shares) - {'IPC$', 'print$'})
            if len(overlap) >= 2:
                findings.append({'host': host, 'indicator': 'possible_cross_host_evidence_overlap', 'evidence': f'SMB share names overlap with {other}: {", ".join(overlap[:5])}', 'interpretation': 'Evidence should be reviewed to ensure artefacts were not reused across hosts.'})
    return findings


def _normalise_service_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[Any, int, str], dict[str, Any]] = {}
    for r in rows or []:
        key=(r.get('host'), int(r.get('port') or 0), r.get('protocol','tcp'))
        if key not in merged:
            merged[key] = dict(r)
            _append_observed_identity(merged[key], _current_identity(r, 'service_observation', r.get('evidence_sources') or []))
            continue
        current = merged[key]
        _append_observed_identity(current, _current_identity(r, 'service_observation', r.get('evidence_sources') or []))
        # Preserve the strongest non-empty primary display identity while every
        # conflicting/alternate observation remains in observed_identities.
        for field in ('service','product','version'):
            val = r.get(field)
            current_val = str(current.get(field) or '').strip()
            if val and (not current_val or current_val.lower() in {'unknown', 'unidentified product', 'dns service', 'mysql', 'postgresql', 'irc', 'vnc', 'rfb'}):
                if field != 'version' or not current.get('product') or not r.get('product') or _same_product_identity(current.get('product'), r.get('product')):
                    current[field] = val
        for field in ('cpe','scripts','evidence_sources'):
            values = current.get(field) or []
            incoming = r.get(field) or []
            if not isinstance(values, list): values=[values]
            if not isinstance(incoming, list): incoming=[incoming]
            for item in incoming:
                if item and item not in values:
                    values.append(item)
            current[field]=values
        if isinstance(r.get('protocol_metadata'), dict):
            current.setdefault('protocol_metadata', {}).update(r.get('protocol_metadata') or {})
    out=[]
    for r in merged.values():
        missing=[]
        if not r.get('product'): missing.append('product')
        if not r.get('version'): missing.append('version')
        if not r.get('cpe'): missing.append('cpe')
        r['missing_information']=missing
        r['identity_context'] = _identity_context_text(r)
        out.append(r)
    return sorted(out, key=lambda x:(str(x.get('host')), str(x.get('protocol')), int(x.get('port') or 0)))


def _endpoint_values(item: dict[str, Any]) -> tuple[str, int]:
    host = str(item.get('host') or item.get('target') or '').strip()
    try:
        port = int(item.get('port') or 0)
    except (TypeError, ValueError):
        port = 0
    url = str(item.get('url') or '')
    if url and (not host or not port):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = host or str(parsed.hostname or '')
            port = port or int(parsed.port or (443 if parsed.scheme == 'https' else 80))
        except (TypeError, ValueError):
            pass
    return host.strip('[]').lower(), port


def _same_endpoint(item: dict[str, Any], host: str, port: int) -> bool:
    item_host, item_port = _endpoint_values(item)
    return item_host == str(host).strip('[]').lower() and item_port == int(port)


def _http_evidence_for_service(
    host: str,
    port: int,
    web_items: list[dict[str, Any]],
    service_checks: list[dict[str, Any]],
) -> str:
    evidence: list[str] = []
    for item in (web_items or []) + (service_checks or []):
        if not isinstance(item, dict) or not _same_endpoint(item, host, port):
            continue
        webserver = str(item.get('webserver') or '').strip()
        if webserver:
            evidence.append(f'Server: {webserver}')
        title = str(item.get('title') or '').strip()
        if title:
            evidence.append(f'Title: {title}')
        technology = item.get('tech') or item.get('technologies') or []
        if isinstance(technology, (list, tuple, set)):
            evidence.extend(f'Technology: {value}' for value in technology if value)
        elif technology:
            evidence.append(f'Technology: {technology}')
        for cpe_item in item.get('cpe') or []:
            if isinstance(cpe_item, dict):
                product = str(cpe_item.get('product') or '').strip()
                vendor = str(cpe_item.get('vendor') or '').strip()
                if product:
                    evidence.append(f'CPE product: {vendor} {product}'.strip())
            elif cpe_item:
                evidence.append(f'CPE: {cpe_item}')
        headers = item.get('headers')
        if isinstance(headers, dict):
            for key, value in headers.items():
                if str(key).lower() == 'server' and value:
                    evidence.append(f'Server: {value}')
        parsed = item.get('parsed')
        if isinstance(parsed, dict):
            fields = parsed.get('fields')
            if isinstance(fields, dict):
                for key, value in fields.items():
                    if str(key).lower() in {'server', 'server_header'} and value:
                        evidence.append(f'Server: {value}')
        if str(item.get('tool') or '') == 'http_security_context' and item.get('output_file'):
            captured = _read_text(item.get('output_file'))
            for server in re.findall(r'(?im)^\s*server\s*:\s*([^\r\n]+)', captured):
                evidence.append(f'Server: {server.strip()}')
    return '\n'.join(dict.fromkeys(value for value in evidence if value))


def _split_observed_product_version(value: Any) -> tuple[str, str]:
    """Split a captured product label from a trailing slash/space version token.

    This is deliberately generic: it preserves what a collector observed and
    does not map the value to an expected product, OS release, or CVE.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return "", ""
    match = re.match(r"^(?P<product>.+?)(?:[/\s]+v?(?P<version>[0-9][A-Za-z0-9._+~-]*))$", text, re.I)
    if not match:
        return text, ""
    return match.group("product").strip(" /-_"), match.group("version").strip()


def _http_observed_identities_for_service(
    host: str,
    port: int,
    web_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return distinct software-layer identities directly observed over HTTP."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(kind: str, value: Any, source: str, cpe: list[str] | None = None) -> None:
        product, version = _split_observed_product_version(value)
        if not product:
            return
        sig = (kind, _identity_text(product), version.lower())
        if sig in seen:
            return
        seen.add(sig)
        rows.append({
            'kind': kind, 'service': 'http', 'product': product, 'version': version,
            'cpe': list(cpe or []), 'sources': [source], 'evidence': str(value or '').strip(),
        })

    for item in web_items or []:
        if not isinstance(item, dict) or not _same_endpoint(item, host, port):
            continue
        source = str(item.get('tool') or 'httpx')
        server = str(item.get('webserver') or '').strip()
        if server:
            add('connector', server, source)
        title = str(item.get('title') or '').strip()
        # A title is retained as an application identity only when it includes a
        # version-like product marker; arbitrary page titles are not products.
        title_product, title_version = _split_observed_product_version(title)
        if title_product and title_version:
            add('web_application', title, source)
        technologies = item.get('tech') or item.get('technologies') or []
        if not isinstance(technologies, (list, tuple, set)):
            technologies = [technologies] if technologies else []
        for technology in technologies:
            product, version = _split_observed_product_version(technology)
            if product and version:
                add('web_application', technology, source)
        for cpe_item in item.get('cpe') or []:
            if not isinstance(cpe_item, dict):
                continue
            product = str(cpe_item.get('product') or '').strip()
            cpe_value = str(cpe_item.get('cpe') or '').strip()
            if product:
                add('web_application', product, source, [cpe_value] if cpe_value else [])
    return rows


def _http_cpes_for_service(
    host: str,
    port: int,
    web_items: list[dict[str, Any]],
) -> list[str]:
    values: list[str] = []
    for item in web_items or []:
        if not isinstance(item, dict) or not _same_endpoint(item, host, port):
            continue
        for cpe_item in item.get('cpe') or []:
            if isinstance(cpe_item, dict):
                value = str(cpe_item.get('cpe') or '').strip()
            else:
                value = str(cpe_item or '').strip()
            if value and value not in values:
                values.append(value)
    return values


def _cpe_identity_tokens(value: str) -> set[str]:
    text = str(value or '').strip().lower()
    if not text.startswith('cpe:'):
        return set()
    parts = text.split(':')
    if len(parts) >= 6 and parts[1] == '2.3':
        fields = parts[3:5]
    elif len(parts) >= 5 and parts[1].startswith('/'):
        fields = parts[2:4]
    else:
        return set()
    return {
        token
        for field in fields
        for token in re.findall(r'[a-z0-9]+', field)
        if len(token) >= 3
    }


def _relevant_http_cpes(product: str, values: list[str]) -> list[str]:
    product_tokens = {token for token in re.findall(r'[a-z0-9]+', str(product or '').lower()) if len(token) >= 3}
    if not product_tokens:
        return []
    return [value for value in values if product_tokens & _cpe_identity_tokens(value)]


def _smb_evidence_for_service(
    host: str,
    port: int,
    smb_items: list[dict[str, Any]],
) -> str:
    if port not in {139, 445}:
        return ''
    evidence: list[str] = []
    for item in smb_items or []:
        if str(item.get('host') or '').lower() != str(host).lower():
            continue
        if item.get('lines'):
            evidence.extend(str(line) for line in item.get('lines') or [])
        for row in item.get('rows') or []:
            for script in row.get('scripts') or []:
                evidence.append(str(script.get('output') or ''))
        if item.get('output_file'):
            evidence.append(_read_text(item.get('output_file')))
    text = '\n'.join(value for value in evidence if value)
    match = re.search(
        r'(?im)^.*\b(?:Samba(?:\s+smbd)?(?:[/\s_-]+[0-9][A-Za-z0-9._+~-]*)?|Windows\s+Server(?:[/\s_-]+[0-9]{4})?).*$',
        text,
    )
    return match.group(0).strip() if match else ''


def _ssh_banner_for_service(
    host: str,
    port: int,
    ssh_profiles: list[dict[str, Any]],
    service_checks: list[dict[str, Any]],
) -> str:
    for item in ssh_profiles or []:
        if not _same_endpoint(item, host, port):
            continue
        software = str(item.get('server_software') or '').strip()
        protocol = str(item.get('protocol_version') or '2.0').strip()
        if software:
            return f'SSH-{protocol}-{software}'
    for item in service_checks or []:
        if str(item.get('tool') or '') != 'ssh_audit_native' or not _same_endpoint(item, host, port):
            continue
        parsed = item.get('parsed') or {}
        fields = parsed.get('fields') if isinstance(parsed, dict) else {}
        if isinstance(fields, dict):
            banner = str(fields.get('banner') or fields.get('software') or '').strip()
            if banner:
                return banner
    return ''


def _tls_evidence_for_service(
    host: str,
    port: int,
    tls_rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    return next(
        (
            dict(item)
            for item in tls_rows or []
            if isinstance(item, dict) and _same_endpoint(item, host, port) and not item.get('error')
        ),
        None,
    )


def _confidence_badge(score: float) -> str:
    if score >= 0.9:
        return f'High ({score:.2f})'
    if score >= 0.7:
        return f'Validated ({score:.2f})'
    if score >= 0.5:
        return f'Uncorroborated ({score:.2f})'
    return f'Low ({score:.2f})'


def _apply_service_fingerprints(
    services: list[dict[str, Any]],
    web_items: list[dict[str, Any]],
    smb_items: list[dict[str, Any]],
    ssh_profiles: list[dict[str, Any]],
    tls_rows: list[dict[str, Any]],
    service_checks: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Attach cross-tool consensus without discarding any raw service row."""
    fingerprints: list[dict[str, Any]] = []
    output: list[dict[str, Any]] = []
    for original in services or []:
        row = dict(original)
        raw_product = str(row.get('product') or '').strip()
        if 'coyote' in raw_product.lower():
            _append_observed_identity(row, {
                'kind': 'connector',
                'service': row.get('service'),
                'product': 'Apache-Coyote',
                'version': row.get('version'),
                'cpe': row.get('cpe') or [],
                'source': row.get('evidence_sources') or ['nmap'],
                'evidence': raw_product,
            })
            row['product'] = 'Apache-Coyote'
        host = str(row.get('host') or '')
        try:
            port = int(row.get('port') or 0)
        except (TypeError, ValueError):
            output.append(row)
            continue
        if not host or not 1 <= port <= 65535:
            output.append(row)
            continue
        # Preserve independent HTTP software layers before consensus selection.
        # This prevents a connector/server version from overwriting an observed
        # web-application version while still allowing both identities to be
        # correlated independently.
        for observed_identity in _http_observed_identities_for_service(host, port, web_items):
            _append_observed_identity(row, observed_identity)

        fingerprint = validate_service_fingerprint(
            host,
            port,
            row,
            http_response=_http_evidence_for_service(host, port, web_items, service_checks) or None,
            ssh_banner=_ssh_banner_for_service(host, port, ssh_profiles, service_checks) or None,
            smb_version=_smb_evidence_for_service(host, port, smb_items) or None,
            tls_cert=_tls_evidence_for_service(host, port, tls_rows),
            additional_evidence=list(row.get('native_fingerprint_evidence') or []),
        )
        fingerprint_dict = fingerprint.to_dict()
        # Keep canonical fields and add compatibility aliases used by the
        # results UI, diagnostics scripts, and older downstream consumers.
        fingerprint_dict.update({
            'host': fingerprint.target,
            'service': row.get('service', ''),
            'product': fingerprint.primary_product,
            'version': fingerprint.primary_version,
            'confidence': fingerprint.confidence_score,
            'reason': (
<<<<<<< HEAD
                'eligible_for_confirmed_cve_matching'
                if fingerprint.recommended_for_cve
                else 'candidate_enrichment_only'
=======
                'structured_cve_correlation_supported'
                if fingerprint.recommended_for_cve
                else 'identity_evidence_retained'
>>>>>>> 2521ca7f0d3b647d15fa553b1f1ef53400160f3c
            ),
        })
        fingerprints.append(fingerprint_dict)
        row['service_fingerprint'] = fingerprint_dict
        row['consensus_product'] = fingerprint.primary_product
        row['consensus_version'] = fingerprint.primary_version
        row['confidence_score'] = fingerprint.confidence_score
        row['confidence_badge'] = _confidence_badge(fingerprint.confidence_score)
        row['contradictions'] = list(fingerprint.contradictions)
        row['recommended_for_cve'] = fingerprint.recommended_for_cve
        # Never discard a product/version recovered from corroborating scripts or
<<<<<<< HEAD
        # native protocol evidence merely because it has not crossed the strict
        # confirmation threshold.  It remains candidate evidence and is labelled
        # as such downstream.
=======
        # Retain native protocol identity evidence even when it is not selected
        # as the primary display fingerprint.  Alternate observations remain
        # available with provenance for scope-aware CVE correlation.
>>>>>>> 2521ca7f0d3b647d15fa553b1f1ef53400160f3c
        if fingerprint.primary_product and not str(row.get('product') or '').strip():
            row['product'] = fingerprint.primary_product
        if fingerprint.primary_version and not str(row.get('version') or '').strip():
            row['version'] = fingerprint.primary_version
<<<<<<< HEAD
=======
        if fingerprint.primary_product or fingerprint.primary_version:
            _append_observed_identity(row, {
                'kind': 'fingerprint_consensus',
                'service': row.get('service'),
                'product': fingerprint.primary_product,
                'version': fingerprint.primary_version,
                'source': [item.tool for item in fingerprint.evidence_sources],
            })
>>>>>>> 2521ca7f0d3b647d15fa553b1f1ef53400160f3c
        if fingerprint.recommended_for_cve:
            current_product = str(row.get('product') or '').strip()
            if fingerprint.primary_product and not current_product:
                row['product'] = fingerprint.primary_product
                current_product = fingerprint.primary_product
            if fingerprint.primary_version and (not row.get('version') or _observed_version_is_range(str(row.get('version') or ''))):
                if not fingerprint.primary_product or not current_product or _same_product_identity(current_product, fingerprint.primary_product):
                    row['version'] = fingerprint.primary_version
            captured_cpes = _http_cpes_for_service(host, port, web_items)
            relevant_cpes = _relevant_http_cpes(fingerprint.primary_product, captured_cpes)
            if relevant_cpes:
                existing_cpes = list(row.get('cpe') or [])
                row['cpe'] = list(dict.fromkeys(existing_cpes + relevant_cpes))
        sources = list(row.get('evidence_sources') or [])
        for item in fingerprint.evidence_sources:
            if item.tool not in sources:
                sources.append(item.tool)
        row['evidence_sources'] = sources
        row['identity_context'] = _identity_context_text(row)
        output.append(row)
    return output, fingerprints

BASELINE_CVE_REFERENCE = 'Candidate CVE'
RELEVANT_VERSION_INFORMATION = 'Held CVE Matching Diagnostic'

def _normalise_product_name(value: str) -> str:
    return re.sub(r'[^a-z0-9]+', ' ', (value or '').lower()).strip()


def _classify_cve_match(service: dict[str, Any], match: dict[str, Any]) -> tuple[str, str]:
    """Verify that a Candidate CVE came from structured CVE Program evidence."""
    if match.get('source') != OFFICIAL_CVE_SOURCE:
        return 'Excluded - Non Official CVE Source', 'CVE source is not the official CVE Program / MITRE CVE List index.'
<<<<<<< HEAD
    basis = str(match.get('match_basis') or '')
    description = str(match.get('description') or '')
    product = str(service.get('product') or '')
    service_name = str(service.get('service') or '')
    cve_id = str(match.get('cve_id') or '')
    if match.get('low_confidence_candidate') or match.get('nvd_candidate'):
        return RELEVANT_VERSION_INFORMATION, 'Product/version was observed but the fingerprint is not corroborated enough for confirmation; retain as an analyst-review candidate.'
    context_classification, context_reason = _context_gate_for_cve(description, product, service_name)
    if context_classification == NOT_APPLICABLE_TO_CONTEXT:
        return context_classification, context_reason
    if context_classification:
        return context_classification, context_reason
    if not _strict_version_basis(basis):
        return RELEVANT_VERSION_INFORMATION, 'Observed version falls within an official affected range; additional context was not established.'
    if re.search(r'\bdenial of service\b|\bcrash\b|\bterminate\b|\bassertion\b|\bcontext-dependent\b|\brange header\b|\bcrafted input\b', description, re.I):
        return RELEVANT_VERSION_INFORMATION, 'Exact product/version evidence was observed, but the CVE requires contextual validation and remains a candidate reference.'
    return STRICT_CVE_MATCH, 'Official CVE product/version evidence matched the observed service; product/version condition is directly supported by recon evidence.'

=======
    matched_products = list(match.get('matched_product_tokens') or [])
    matched_versions = list(match.get('matched_version_tokens') or [])
    basis = str(match.get('match_basis') or '').strip()
    if not matched_products or not matched_versions or not basis:
        return 'Excluded - Incomplete Candidate Evidence', (
            'A Candidate CVE requires a structured product match, a concrete '
            'matched version, and a retained structured CVE Program basis.'
        )
    return BASELINE_CVE_REFERENCE, (
        'CVE Program structured affected data matched the observed or hypothesised '
        'product/platform identity and concrete version. This is a Candidate CVE only; '
        'target applicability and exploitability are not validated here.'
    )
>>>>>>> 2521ca7f0d3b647d15fa553b1f1ef53400160f3c



def _cve_finding_type(product: str, cve_id: str, description: str) -> str:
    text = ' '.join([product or '', cve_id or '', description or '']).lower()
    if 'backdoor' in text or 'shell' in text:
        return 'Product/version condition observed; backdoor applicability depends on package provenance'
    if 'execute arbitrary' in text or 'command' in text:
        return 'Command-execution related CVE'
    if 'denial of service' in text or 'crash' in text:
        return 'Availability-impact CVE'
    return 'Version-linked Candidate CVE'
def _display_match_reason(match_basis: str, fallback: str = '') -> str:
    return match_basis_registry.display_match_reason(match_basis, fallback)



def _candidate_evidence_profile(service: dict[str, Any]) -> tuple[str, str]:
    """Describe why a software identity produced a Candidate CVE.

    Candidate CVEs deliberately have no scanner-side confidence tier. The
    retained basis/provenance explains the observed or hypothesised software
    identity that entered structured CVE Program matching. Published CVSS is
    separate severity metadata, and downstream validation decides target
    applicability/exploitability.
    """
    scope = str(service.get('identity_scope') or 'application_service').strip().lower()
    kind = str(service.get('identity_kind') or '').strip().lower()
    evidence_kind = str(service.get('evidence_kind') or '').strip().lower()
    sources = {
        str(value).strip()
        for value in (service.get('evidence_sources') or service.get('sources') or [])
        if str(value).strip()
    }
    attrs = service.get('service_attributes') or {}
    method = str(attrs.get('method') or '').strip().lower()

    if scope == 'host_os':
        if evidence_kind == 'probabilistic_fingerprint' or 'nmap_os_identity' in sources:
            accuracy = service.get('accuracy')
            suffix = f" (Nmap accuracy {accuracy}%)" if str(accuracy or '').strip() else ''
            return (
                'Probabilistic OS fingerprint',
                'Candidate generated from a probabilistic host-OS fingerprint'
                + suffix + '; the fingerprint remains a hypothesis until downstream validation.',
            )
        return (
            'Direct host operating-system identity',
            'Candidate generated from directly observed host operating-system product/version evidence.',
        )

    if scope == 'platform_component' or kind in {'connector','platform_component','runtime_component','protocol_component'}:
        return (
            'Observed platform/protocol component version',
            'Candidate generated from an observed component product/version; downstream validation must confirm target applicability.',
        )

    if len(sources) >= 2:
        return (
            'Corroborated service product/version',
            'Candidate generated from a service product/version corroborated by multiple evidence sources.',
        )
    if method == 'probed' or sources:
        return (
            'Direct service product/version',
            'Candidate generated from a directly observed service product/version.',
        )
    return (
        'Service product/version observation',
        'Candidate generated from an observed service product/version.',
    )


def _build_cve_row(service: dict[str, Any], match: dict[str, Any], reference_type: str, reason: str) -> dict[str, Any]:
    observed_port = f"{service.get('port')}/{service.get('protocol')}"
    basis, evidence_note = _candidate_evidence_profile(service)
    return {
        'host': service.get('host'), 'port': service.get('port'), 'protocol': service.get('protocol'),
        'observed_ports': [observed_port],
        'service': service.get('service'), 'product': service.get('product'), 'version': service.get('version'),
        'cve_id': match.get('cve_id'), 'vulnerability': match.get('description'),
        'reference_type': 'Candidate CVE',
        'candidate_status': 'candidate',
        'validation_state': 'not_performed',
        'validation_status': 'not_validated',
        'candidate_basis': basis,
        'candidate_evidence_note': evidence_note,
        'candidate_source': OFFICIAL_CVE_SOURCE,
        'match_source': match.get('source') or OFFICIAL_CVE_SOURCE,
        'match_reason': reason,
        'display_match_reason': _display_match_reason(str(match.get('match_basis') or ''), reason),
        'identity_kind': service.get('identity_kind') or 'primary_service',
        'matched_product_tokens': match.get('matched_product_tokens', []),
        'matched_version_tokens': match.get('matched_version_tokens', []),
        'match_basis': match.get('match_basis',''),
        'product_match_basis': match.get('product_match_basis',''),
        'cve_publisher': match.get('cve_publisher') or 'CVE Program CNA',
        'cve_publisher_id': match.get('cve_publisher_id') or '',
        'affected_vendors': match.get('affected_vendors') or [],
        'affected_products': match.get('affected_products') or [],
        'affected_versions': match.get('affected_versions') or [],
        'affected_entries': match.get('affected_entries') or [],
        'affected_cpes': match.get('affected_cpes') or [],
        'source_cvss_metrics': match.get('cvss_metrics') or {},
        'source_cvss_score': match.get('cvss_score'),
        'source_cvss_severity': match.get('cvss_severity'),
        'source_cvss_vector': match.get('cvss_vector'),
        'source_cvss_version': match.get('cvss_version'),
        'source_cvss_source': match.get('cvss_source'),
        'attacker_outcome': _attacker_outcome(str(service.get('product','')), str(match.get('cve_id','')), str(match.get('description',''))),
        'remediation_direction': _remediation_direction(str(service.get('product','')), str(match.get('cve_id',''))),
        'finding_type': _cve_finding_type(str(service.get('product','')), str(match.get('cve_id','')), str(match.get('description',''))),
        'evidence_sources': service.get('evidence_sources',[]), 'references': match.get('references',[]),
        'fingerprint_evidence': (service.get('service_fingerprint') or {}).get('evidence_sources', []),
        'applicability_state': 'candidate_unvalidated',
        'applicability_context': _structured_prerequisite_context(match, service),
        'applicability_evidence': {
            'affected_host': str(service.get('host') or ''),
            'observed_identity': {
                'scope': str(service.get('identity_scope') or 'application_service'),
                'service': str(service.get('service') or ''),
                'product': str(service.get('product') or ''),
                'version': str(service.get('version') or ''),
                'endpoints': [observed_port],
                'sources': list(service.get('evidence_sources') or []),
            },
            'published_rule': {
                'vendors': list(match.get('affected_vendors') or []),
                'products': list(match.get('affected_products') or []),
                'versions': list(match.get('affected_versions') or []),
                'matched_affected_entry': copy.deepcopy(match.get('matched_affected_entry') or {}),
                'match_basis': str(match.get('match_basis') or ''),
                'product_match_basis': str(match.get('product_match_basis') or ''),
            },
        },
        'validation_boundary': 'Candidate correlation only. Applicability/exploitability is not asserted by recon and must be decided by the downstream validation stage.',
    }


def _build_host_cve_row(identity: dict[str, Any], match: dict[str, Any]) -> dict[str, Any]:
    product = str(identity.get('product') or identity.get('name') or identity.get('family') or '').strip()
    version = str(identity.get('build') or identity.get('version') or identity.get('release') or '').strip()
    sources = list(identity.get('sources') or [])
    refs = list(identity.get('evidence_references') or [])
    candidate_service = {
        **dict(identity),
        'identity_scope': 'host_os',
        'identity_kind': 'host_os',
        'evidence_sources': sources,
    }
    basis, evidence_note = _candidate_evidence_profile(candidate_service)
    prerequisite_context = _structured_prerequisite_context(match, {
        'service': 'host operating system',
        'product': product,
        'version': version,
        'extra': ' '.join(filter(None, [
            str(identity.get('family') or ''),
            str(identity.get('release') or ''),
            str(identity.get('build') or ''),
            ' '.join(str(x) for x in identity.get('cpe') or []),
        ])),
        'scripts': [],
    })
    return {
        'host': identity.get('host'),
        'port': 'host',
        'protocol': 'host',
        'observed_ports': ['host'],
        'service': 'Host Operating System',
        'product': product,
        'version': version,
        'release': identity.get('release') or '',
        'build': identity.get('build') or '',
        'os_family': identity.get('family') or '',
        'os_vendor': identity.get('vendor') or '',
        'cpe': list(identity.get('cpe') or []),
        'identity_quality': identity.get('quality') or '',
        'match_scope': 'host_os',
        'affected_asset': 'Host operating system hypothesis' if str(identity.get('evidence_kind') or '') == 'probabilistic_fingerprint' else 'Host operating system',
        'patch_state': 'Not established by unauthenticated reconnaissance',
        'component_exposure': 'Specific vulnerable component state is not independently asserted by Candidate CVE correlation.',
        'cve_id': match.get('cve_id'),
        'vulnerability': match.get('description'),
        'reference_type': 'Candidate CVE',
        'candidate_status': 'candidate',
        'validation_state': 'not_performed',
        'validation_status': 'not_validated',
        'candidate_basis': basis,
        'candidate_evidence_note': evidence_note,
        'candidate_source': OFFICIAL_CVE_SOURCE,
        'match_source': match.get('source') or OFFICIAL_CVE_SOURCE,
        'match_reason': 'CVE Program structured affected data matched the observed/hypothesised host-OS product and version.',
        'display_match_reason': _display_match_reason(str(match.get('match_basis') or ''), 'CVE Program affected data matched the host-OS Candidate CVE input.'),
        'identity_kind': 'host_os',
        'matched_product_tokens': match.get('matched_product_tokens', []),
        'matched_version_tokens': match.get('matched_version_tokens', []),
        'match_basis': match.get('match_basis', ''),
        'product_match_basis': match.get('product_match_basis', ''),
        'cve_publisher': match.get('cve_publisher') or 'CVE Program CNA',
        'cve_publisher_id': match.get('cve_publisher_id') or '',
        'affected_vendors': match.get('affected_vendors') or [],
        'affected_products': match.get('affected_products') or [],
        'affected_versions': match.get('affected_versions') or [],
        'affected_entries': match.get('affected_entries') or [],
        'affected_cpes': match.get('affected_cpes') or [],
        'source_cvss_metrics': match.get('cvss_metrics') or {},
        'source_cvss_score': match.get('cvss_score'),
        'source_cvss_severity': match.get('cvss_severity'),
        'source_cvss_vector': match.get('cvss_vector'),
        'source_cvss_version': match.get('cvss_version'),
        'source_cvss_source': match.get('cvss_source'),
        'attacker_outcome': _attacker_outcome(product, str(match.get('cve_id', '')), str(match.get('description', ''))),
        'remediation_direction': _remediation_direction(product, str(match.get('cve_id', ''))),
        'finding_type': _cve_finding_type(product, str(match.get('cve_id', '')), str(match.get('description', ''))),
        'evidence_sources': sources,
        'evidence_references': refs,
        'references': match.get('references', []),
        'fingerprint_evidence': refs,
        'applicability_state': 'candidate_unvalidated',
        'applicability_context': prerequisite_context,
        'applicability_evidence': {
            'affected_host': str(identity.get('host') or ''),
            'observed_identity': {
                'scope': 'host_os',
                'service': 'Host Operating System',
                'product': product,
                'version': version,
                'endpoints': ['host'],
                'sources': sources,
            },
            'published_rule': {
                'vendors': list(match.get('affected_vendors') or []),
                'products': list(match.get('affected_products') or []),
                'versions': list(match.get('affected_versions') or []),
                'matched_affected_entry': copy.deepcopy(match.get('matched_affected_entry') or {}),
                'match_basis': str(match.get('match_basis') or ''),
                'product_match_basis': str(match.get('product_match_basis') or ''),
            },
        },
        'validation_boundary': 'Candidate correlation only. Exact OS identity, patch state, applicability and exploitability remain downstream validation responsibilities.',
    }


def _generic_patch_state(raw_value: Any) -> str:
    """Map evidence wording to a stable generic state without product rules."""
    text = str(raw_value or '').strip().lower()
    if not text:
        return 'unknown'
    if 'supersed' in text:
        return 'superseded'
    if 'not applicable' in text:
        return 'not_applicable'
    if any(token in text for token in ('remediation observed', 'installed', 'already patched', 'fixed build observed')):
        return 'installed'
    if any(token in text for token in ('applicable update not observed', 'missing update', 'unpatched')):
        return 'missing'
    return 'unknown'


def _generic_validation_state(row: dict[str, Any]) -> str:
    raw = str(
        row.get('validation_state')
        or row.get('validation_status')
        or row.get('safe_validation_state')
        or ''
    ).strip().lower().replace(' ', '_')
    allowed = {'validated', 'not_validated', 'not_performed', 'unavailable'}
    if raw in allowed:
        return raw
    if row.get('validated') is True or row.get('validation_evidence'):
        return 'validated'
    if row.get('validation_attempted') is True:
        return 'not_validated'
    if row.get('validation_available') is False:
        return 'unavailable'
    return 'not_performed'


def _refresh_cve_display_context(rows: list[dict[str, Any]]) -> None:
    """Expose assurance context without changing Candidate CVE generation decisions."""
    for row in rows or []:
        applicability_state = str(row.get('applicability_state') or 'matched').strip().lower().replace(' ', '_')
        allowed_applicability_states = {
            'matched', 'version_match_prerequisite_unknown',
            'conflicting_authoritative_metadata', 'disputed',
            'not_applicable', 'insufficient_identity', 'not_established', 'held', 'candidate_unvalidated',
        }
        if applicability_state not in allowed_applicability_states:
            applicability_state = 'not_established'
        row['applicability_state'] = applicability_state
        row['patch_state_status'] = _generic_patch_state(row.get('patch_state'))
        row['validation_state'] = _generic_validation_state(row)

        base = str(row.get('display_match_reason') or row.get('match_reason') or row.get('match_basis') or '').strip()
        notes: list[str] = [base] if base else []
        corroboration = row.get('applicability_corroboration') or {}
        if isinstance(corroboration, dict) and corroboration.get('source'):
            mode = str(corroboration.get('mode') or '')
            if mode == 'canonical_component_plus_host_configuration':
                notes.append('Host/platform context was corroborated by the exact-CVE NVD configuration; the CVE Program affected entry supplied the component identity.')
            else:
                notes.append('Observed component and host/platform context were corroborated by exact-CVE NVD configuration/CPE data.')
        source_agreement = str(row.get('source_agreement') or '').strip()
        if source_agreement:
            notes.append(source_agreement)
        if applicability_state == 'candidate_unvalidated':
            notes.append('Candidate only: recon correlation has not established target applicability or exploitability; downstream validation is required.')
        elif applicability_state == 'conflicting_authoritative_metadata':
            notes.append('Applicability is held for review because authoritative structured sources disagree; this item is not a strict vulnerability match.')
        elif applicability_state == 'version_match_prerequisite_unknown':
            notes.append('The observed product/version is within structured affected data, but required feature/configuration prerequisites were not fully established; this item remains a review candidate.')
        elif applicability_state == 'disputed':
            notes.append('The published vulnerability record is disputed; this item remains a review candidate rather than a strict match.')
        patch_state = str(row.get('patch_state') or '').strip()
        if patch_state:
            notes.append(f'Patch state: {patch_state}.')
        if row.get('kev_listed') is True:
            notes.append('Threat context only (not an applicability input): this CVE is listed in the CISA Known Exploited Vulnerabilities catalog.')
        row['display_match_reason'] = ' '.join(item.rstrip() if item.endswith('.') else item.rstrip() + '.' for item in notes if item).strip()
        applicability = row.get('applicability_evidence')
        if isinstance(applicability, dict):
            applicability['corroboration'] = copy.deepcopy(row.get('applicability_corroboration') or {})
            applicability['applicability_state'] = row.get('applicability_state')
            applicability['patch_state'] = str(row.get('patch_state') or '')
            applicability['patch_state_status'] = row.get('patch_state_status')
            applicability['validation_state'] = row.get('validation_state')
            applicability['kev_listed'] = bool(row.get('kev_listed') is True)


def _merge_host_cve_duplicate(existing: dict[str, Any], identity: dict[str, Any]) -> None:
    for key in ('evidence_sources', 'evidence_references', 'cpe'):
        existing[key] = sorted(set(existing.get(key) or []) | set(identity.get(key if key != 'evidence_references' else 'evidence_references') or []))
    # Prefer the more concrete identity observation without discarding provenance.
    if identity.get('build') and not existing.get('build'):
        existing['build'] = identity.get('build')
        existing['version'] = identity.get('build')
    if identity.get('release') and not existing.get('release'):
        existing['release'] = identity.get('release')
    if identity.get('quality') and existing.get('identity_quality') in {'', 'Incomplete identity', 'OS family only'}:
        existing['identity_quality'] = identity.get('quality')


def _merge_cve_duplicate(existing: dict[str, Any], service: dict[str, Any]) -> None:
    """Merge same-protocol observations while keeping exact endpoint references.

    Downstream presentation code appends ``/<protocol>`` to ``port``.  For a
    multi-port same-protocol finding we therefore retain complete endpoint
    references in ``observed_ports`` and encode all but the last protocol in the
    display-compatible ``port`` value.  This prevents duplicated suffixes such
    as ``445/tcp/tcp`` without changing downstream/template code.
    """
    protocol = str(service.get('protocol') or existing.get('protocol') or 'tcp').lower()
    port_ref = f"{service.get('port')}/{protocol}"
    ports = existing.setdefault('observed_ports', [])
    if port_ref not in ports:
        ports.append(port_ref)
    applicability = existing.get('applicability_evidence')
    if isinstance(applicability, dict):
        observed = applicability.setdefault('observed_identity', {})
        endpoints = observed.setdefault('endpoints', [])
        if port_ref not in endpoints:
            endpoints.append(port_ref)
        sources = observed.setdefault('sources', [])
        for source in service.get('evidence_sources') or []:
            if source not in sources:
                sources.append(source)
    exact_ports = [str(value) for value in ports if str(value).strip()]
    protocols = {value.rsplit('/', 1)[-1].lower() for value in exact_ports if '/' in value}
    if len(protocols) == 1:
        common_protocol = next(iter(protocols))
        existing['protocol'] = common_protocol
        if len(exact_ports) == 1:
            existing['port'] = exact_ports[0].rsplit('/', 1)[0]
        else:
            # Core/report formatters append the common protocol once at the end.
            existing['port'] = ', '.join(exact_ports[:-1] + [exact_ports[-1].rsplit('/', 1)[0]])
    else:
        # Mixed-protocol records should normally be separated by the dedupe key;
        # preserve exact endpoint evidence rather than fabricating a protocol.
        existing['port'] = ', '.join(exact_ports)
        existing['protocol'] = 'mixed'


def _cve_dedupe_key(service: dict[str, Any], match: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(service.get('host') or ''),
        _normalise_product_name(str(service.get('product') or '')),
        str(service.get('version') or '').lower(),
        str(match.get('cve_id') or ''),
        str(service.get('protocol') or '').lower(),
    )


def _group_cve_matches_by_host(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Return canonical CVE references grouped by their associated target IP/host.

    The flat ``cve_matches`` contract is retained for compatibility, but all
    scanner-owned handoff/export consumers can use this host-first view to avoid
    collapsing identical CVE IDs observed on different targets. Host identity is
    taken from the canonical row (or its applicability evidence as a fallback),
    never inferred from ports, products, or neighbouring findings.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        applicability = row.get('applicability_evidence') or {}
        host = str(row.get('host') or (applicability.get('affected_host') if isinstance(applicability, dict) else '') or '').strip()
        if not host:
            host = 'unattributed'
        grouped.setdefault(host, []).append(row)
    for host, host_rows in grouped.items():
        host_rows.sort(key=lambda item: (
            str(item.get('cve_id') or ''),
            str(item.get('protocol') or ''),
            str(item.get('port') or ''),
            str(item.get('product') or ''),
        ))
    return dict(sorted(grouped.items(), key=lambda item: item[0]))



def _build_cve_review_summary(
    candidate_matches: list[dict[str, Any]],
    review_candidates: list[dict[str, Any]],
    diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarise Candidate CVE generation without implying validation."""
    rows = review_candidates or candidate_matches or []
    candidate_ids = {str(row.get('cve_id') or '').upper() for row in rows if row.get('cve_id')}
    bases: dict[str, set[str]] = {}
    for row in rows:
        cve_id = str(row.get('cve_id') or '').upper()
        if not cve_id:
            continue
        basis = str(row.get('candidate_basis') or 'Unclassified evidence')
        bases.setdefault(basis, set()).add(cve_id)

    identity_keys: set[tuple[str, str, str, str]] = set()
    for row in rows:
        applicability = row.get('applicability_evidence') or {}
        host = str(row.get('host') or (applicability.get('affected_host') if isinstance(applicability, dict) else '') or '').strip()
        product = str(row.get('product') or (applicability.get('observed_product') if isinstance(applicability, dict) else '') or '').strip().lower()
        version = str(row.get('version') or (applicability.get('observed_version') if isinstance(applicability, dict) else '') or '').strip().lower()
        scope = str(row.get('match_scope') or (applicability.get('identity_scope') if isinstance(applicability, dict) else '') or '').strip().lower()
        if product and version:
            identity_keys.add((host, product, version, scope))
    unmatched_software_identities: set[tuple[str, str, str, str]] = set()
    evaluated_records = 0
    rejected = 0
    vendor_resolved = 0
    source_unavailable = False
    matcher_degraded = False
    seen_summary: set[tuple[str, str, str, str, str]] = set()
    for item in diagnostics or []:
        product = str(item.get('product') or '').strip().lower()
        version = str(item.get('version') or item.get('observed_version') or '').strip().lower()
        scope = str(item.get('identity_scope') or '').strip().lower()
        host = str(item.get('host') or '').strip()
        if product and version:
            identity_keys.add((host, product, version, scope))
        reason = str(item.get('reason') or '')
        if reason == 'cve_candidate_coverage_gap':
            unmatched_software_identities.add((host, product, version, scope))
        if reason in {'cve_index_unavailable', 'cve_program_index_unavailable'}:
            source_unavailable = True
        if str(item.get('matcher_status') or '').lower() in {'error', 'degraded'}:
            matcher_degraded = True
        if reason == 'cve_program_candidate_search_summary':
            signature = (reason, product, version, scope, str(item.get('query') or ''))
            if signature in seen_summary:
                continue
            seen_summary.add(signature)
            evaluated_records += int(item.get('candidate_records_considered') or 0)
            rejected += int(item.get('version_rejected') or 0) + int(item.get('cpe_context_rejected') or 0)
        elif reason == 'held_version_candidates_resolved_by_external_build_context':
            vendor_resolved += int(item.get('resolved_cve_count') or 0)

    rejected = max(0, rejected - vendor_resolved)
    generation_state = 'unavailable' if source_unavailable else ('degraded' if matcher_degraded else 'available')

    # CVSS is published severity/triage metadata attached *after* a Candidate
    # CVE exists. Preserve 3.1 and 4.0 independently and report coverage for
    # the actual candidate set; neither version is a candidate-confidence tier
    # and neither can create, reject, promote or validate a candidate.
    cvss_candidate_ids: dict[str, set[str]] = {'3.1': set(), '4.0': set()}
    for row in rows:
        cve_id = str(row.get('cve_id') or '').upper()
        if not cve_id:
            continue
        metrics = row.get('effective_cvss_metrics') or row.get('source_cvss_metrics') or row.get('cvss_metrics') or {}
        if not isinstance(metrics, dict):
            continue
        for version in ('3.1', '4.0'):
            metric = metrics.get(version)
            if isinstance(metric, dict) and metric.get('cvss_score') is not None:
                cvss_candidate_ids[version].add(cve_id)

    cvss_summary = {
        version: {
            'published_candidates': len(cvss_candidate_ids[version]),
            'missing_candidates': max(0, len(candidate_ids) - len(cvss_candidate_ids[version])),
        }
        for version in ('3.1', '4.0')
    }
    cvss_summary['role'] = (
        'Published severity/triage metadata only. CVSS is not Candidate CVE confidence, '
        'does not generate or remove candidates, and does not perform validation.'
    )

    target_candidate_records = {
        (
            str(row.get('host') or ((row.get('applicability_evidence') or {}).get('affected_host') if isinstance(row.get('applicability_evidence'), dict) else '') or '').strip(),
            str(row.get('cve_id') or '').upper(),
        )
        for row in rows
        if row.get('cve_id')
    }

    return {
        'candidate_generation_state': generation_state,
        'identities_reviewed': len(identity_keys),
        'candidate_cves_considered': len(candidate_ids),
        'candidate_cves_retained': len(candidate_ids),
        'unique_candidate_ids': len(candidate_ids),
        'target_candidate_records': len(target_candidate_records),
        'identity_correlations_retained': len(rows),
        'unvalidated': len(candidate_ids),
        'candidate_basis': {name: len(ids) for name, ids in sorted(bases.items())},
        'structured_records_evaluated': evaluated_records,
        'rejected_during_structured_filtering': rejected,
        'vendor_version_resolutions': vendor_resolved,
        'windows_build_context_candidates': len({str(row.get('cve_id') or '').upper() for row in rows if row.get('windows_advisory_context')}),
        'unmatched_software_identities': len(unmatched_software_identities),
        'candidate_sources': {OFFICIAL_CVE_SOURCE: len(candidate_ids)},
        'cvss': cvss_summary,
        'nvd_role': 'Exact-ID enrichment only; NVD may fill missing published CVSS/metadata but cannot create, reject, promote or suppress Candidate CVEs.',
        'validation_boundary': 'All rows are unvalidated candidates. Applicability/exploitability is decided by the downstream validation stage.',
        'state_semantics': {
            'candidate': 'Evidence-backed CVE correlation requiring downstream validation.',
            'unavailable': 'Candidate generation could not run because the configured CVE Program index was unavailable.',
        },
    }


def _build_cve_matcher_audit(diagnostics: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Condense Candidate CVE matcher diagnostics into an audit trail."""
    keep_reasons = {
        'cve_program_candidate_search_summary',
        'cve_candidate_coverage_gap',
        'affected_cpe_context_not_satisfied',
        'published_version_rule_not_comparable',
        'candidate_evidence_incomplete',
        'cve_index_unavailable',
        'cve_program_index_unavailable',
        'windows_release_context_not_observed',
        'windows_build_context_not_satisfied',
        'windows_release_context_contradicted',
        'msrc_windows_build_context',
        'msrc_windows_build_context_incomplete',
        'msrc_windows_product_context',
        'msrc_windows_product_context_incomplete',
        'msrc_windows_build_product_resolution',
        'msrc_index_unavailable',
        'held_version_candidates_resolved_by_external_build_context',
        'external_version_context_did_not_intersect_cve_program_holds',
    }
    rows: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in diagnostics or []:
        reason = str(item.get('reason') or '')
        if reason not in keep_reasons and not item.get('cve_id'):
            continue
        row = {
            'host': str(item.get('host') or ''),
            'endpoint': '/'.join(filter(None, [str(item.get('port') or ''), str(item.get('protocol') or '')])),
            'product': str(item.get('product') or item.get('component') or ''),
            'version': str(item.get('version') or item.get('observed_version') or ''),
            'cve_id': str(item.get('cve_id') or ''),
            'source_stage': reason,
            'status': str(item.get('matcher_status') or ''),
            'decision': str(item.get('detail') or item.get('version_rule_reason') or item.get('effect') or ''),
            'query_mode': str(item.get('query_mode') or ''),
            'query': str(item.get('query') or ''),
            'considered': item.get('candidate_records_considered', ''),
            'matched': item.get('matched_count', ''),
            'rejected': int(item.get('version_rejected') or 0) + int(item.get('cpe_context_rejected') or 0),
        }
        sig = tuple(row.get(key) for key in ('host','endpoint','product','version','cve_id','source_stage','query','decision'))
        if sig in seen:
            continue
        seen.add(sig)
        rows.append(row)
        if len(rows) >= 250:
            break
    return rows

def _is_service(s: dict[str, Any], *, ports: set[int] | None = None, terms: set[str] | None = None, products: set[str] | None = None, protocol: str | None = None) -> bool:
    try:
        port = int(s.get('port') or 0)
    except Exception:
        port = 0
    proto = str(s.get('protocol') or '').lower()
    svc = str(s.get('service') or '').lower()
    prod = str(s.get('product') or '').lower()
    if protocol and proto != protocol:
        return False
    if not ports and not terms and not products:
        return True
    if ports and port in ports:
        return True
    if terms and any(t in svc for t in terms):
        return True
    if products and any(t in prod for t in products):
        return True
    return False


# Service-level active collectors were intentionally removed from recon.
# Downstream validation modules own deeper protocol, credential, and exploit checks.

def _resolve_windows_build_product_candidates(
    identity_map: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Do not promote MSRC build-line products into observed host identity.

    Microsoft advisory product/build data is remediation intelligence, not
    collection evidence.  A shared build line can correspond to many Windows
    editions, architectures, optional components, frameworks, and applications.
    Converting those advisory products into host identities creates a feedback
    loop where unobserved products become CVE lookup inputs.

    The function remains as a compatibility hook for callers and returns a
    diagnostic when build-only Windows evidence exists, but it never mutates
    ``identity_map`` and never creates a CVE-eligible identity.
    """
    diagnostics: list[dict[str, Any]] = []
    for host, identities in list(identity_map.items()):
        for identity in list(identities or []):
            if (
                str(identity.get("family") or "") != "Windows"
                or not str(identity.get("build") or "").strip()
                or identity_is_precise_for_cve(identity)
            ):
                continue
            diagnostics.append({
                "host": host,
                "identity_scope": "host_os",
                "observed_product": identity.get("product") or identity.get("name"),
                "observed_build": str(identity.get("build") or "").strip(),
                "reason": "msrc_build_line_not_promoted_to_identity",
                "matcher_status": "held",
                "detail": (
                    "Microsoft advisory build-line products are remediation context only; "
                    "they are not observed host identities and are not CVE lookup inputs."
                ),
            })
    return diagnostics


def _match_cves(
    services: list[dict[str, Any]],
    diagnostics: list[dict[str, Any]] | None = None,
    host_identities: list[dict[str, Any]] | None = None,
    windows_inventories: list[dict[str, Any]] | None = None,
    component_observations: list[dict[str, Any]] | None = None,
    *,
    return_review_candidates: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Generate an evidence-backed *Candidate CVE* queue.

<<<<<<< HEAD
    for s in services:
        cpe_text = ' '.join(s.get('cpe') or [])
        product_text = str(s.get('product',''))
        version_text = str(s.get('version',''))
        service_text = str(s.get('service',''))

        # Nmap often identifies legacy Windows editions in the product field but
        # leaves the version column blank. Preserve the observed edition while
        # deriving the OS version needed for targeted NVD enrichment.
        edition_text = f"{product_text} {service_text} {cpe_text}".lower()
        if not version_text.strip():
            windows_versions = (
                ('windows xp', '5.1'), ('windows server 2003', '5.2'),
                ('windows vista', '6.0'), ('windows 7', '6.1'),
                ('windows 8.1', '6.3'), ('windows 8', '6.2'),
                ('windows 10', '10.0'), ('windows 11', '10.0'),
            )
            for edition, derived in windows_versions:
                if edition in edition_text:
                    version_text = derived
                    break

        edition_is_concrete = any(token in edition_text for token in (
            'windows xp', 'windows server 2003', 'windows vista',
            'windows 7', 'windows 8', 'windows 10', 'windows 11'
        ))
        effective_confidence = s.get('confidence_score', 0.0)
        effective_recommended = bool(s.get('recommended_for_cve', False))
        if edition_is_concrete and version_text:
            effective_confidence = max(float(effective_confidence or 0.0), 0.85)
            effective_recommended = True

        matches, held_refs = mitre_search_with_held(
            product_text,
            version_text,
            service_text,
            cpe_text,
            confidence_score=effective_confidence,
            recommended_for_cve=effective_recommended,
=======
    Candidate generation is owned exclusively by the local CVE Program
    (cvelistV5) structured affected-data index. NVD is intentionally absent
    from this function: it may enrich an already-generated CVE ID later, but it
    cannot add, reject, promote or suppress Candidate CVEs.

    Downstream validation is a separate stage. Therefore a precise
    probabilistic OS hypothesis may generate Candidate CVEs while remaining an
    unresolved OS identity in the recon/reporting layer.
    """
    candidates: list[dict[str, Any]] = []
    index: dict[tuple[Any, ...], dict[str, Any]] = {}
    direct_windows_by_host = _direct_windows_identity_contexts(host_identities)

    def append_diagnostics(
        service: dict[str, Any],
        identity_scope: str,
        items: Iterable[dict[str, Any]],
        *,
        identity_kind: str = '',
    ) -> None:
        if diagnostics is None:
            return
        for item in items or []:
            diagnostics.append({
                'host': service.get('host'), 'port': service.get('port'), 'protocol': service.get('protocol'),
                'service': service.get('service'), 'product': service.get('product'), 'version': service.get('version'),
                'identity_kind': identity_kind or service.get('identity_kind') or 'primary_service',
                'identity_scope': identity_scope,
                **dict(item),
            })

    def key_for(service: dict[str, Any], match: dict[str, Any], scope: str) -> tuple[Any, ...]:
        matched_product = str((match.get('matched_product_tokens') or [service.get('product')])[0] or service.get('product') or '')
        return (
            str(service.get('host') or ''),
            str(match.get('cve_id') or '').upper(),
            _normalise_product_name(matched_product),
            str(service.get('version') or '').lower(),
            str(scope or ''),
            str(service.get('protocol') or '').lower(),
>>>>>>> 2521ca7f0d3b647d15fa553b1f1ef53400160f3c
        )

    def add_candidate(row: dict[str, Any], service: dict[str, Any], match: dict[str, Any], scope: str) -> None:
        key = key_for(service, match, scope)
        if key in index:
            existing = index[key]
            if scope == 'host_os':
                _merge_host_cve_duplicate(existing, service)
            else:
                _merge_cve_duplicate(existing, service)
            existing['candidate_sources'] = sorted(set(existing.get('candidate_sources') or []) | {OFFICIAL_CVE_SOURCE})
            # Multiple observations may support the same candidate. Preserve all
            # provenance without grading the candidate into confidence tiers.
            bases = [
                str(value).strip()
                for value in (existing.get('candidate_bases') or [existing.get('candidate_basis')])
                if str(value or '').strip()
            ]
            row_basis = str(row.get('candidate_basis') or '').strip()
            if row_basis and row_basis not in bases:
                bases.append(row_basis)
            existing['candidate_bases'] = bases
            if bases:
                existing['candidate_basis'] = bases[0]
            notes = [
                str(value).strip()
                for value in (existing.get('candidate_evidence_notes') or [existing.get('candidate_evidence_note')])
                if str(value or '').strip()
            ]
            row_note = str(row.get('candidate_evidence_note') or '').strip()
            if row_note and row_note not in notes:
                notes.append(row_note)
            existing['candidate_evidence_notes'] = notes
            if notes:
                existing['candidate_evidence_note'] = ' '.join(notes)
            return
        row['candidate_sources'] = [OFFICIAL_CVE_SOURCE]
        row['applicability_state'] = 'candidate_unvalidated'
        row['candidate_status'] = 'candidate'
        row['validation_state'] = 'not_performed'
        row['validation_status'] = 'not_validated'
        index[key] = row
        candidates.append(row)

    # Service/application and directly observed connector/component identities.
    for base_service in services or []:
        primary = dict(base_service)
        primary['identity_scope'] = 'application_service'
        variants: list[dict[str, Any]] = [primary]
        seen_variants = {(
            _identity_text(base_service.get('service')),
            _identity_text(base_service.get('product')),
            str(base_service.get('version') or '').lower(),
            'application_service',
        )}
        for identity in base_service.get('observed_identities') or []:
            product = str(identity.get('product') or '').strip()
            version = str(identity.get('version') or '').strip()
            service_name = str(identity.get('service') or base_service.get('service') or '').strip()
            if not product or not version:
                continue
            kind = str(identity.get('kind') or 'observed_identity').strip().lower()
            scope = 'platform_component' if kind in {'connector','platform_component','runtime_component','protocol_component'} else 'application_service'
            sig = (_identity_text(service_name), _identity_text(product), version.lower(), scope)
            if sig in seen_variants:
                continue
            seen_variants.add(sig)
            variant = dict(base_service)
            variant.update({
                'service': service_name or base_service.get('service'),
                'product': product,
                'version': version,
                'cpe': list(identity.get('cpe') or []),
                'identity_kind': identity.get('kind') or 'observed_identity',
                'identity_scope': scope,
                'evidence_sources': list(dict.fromkeys(
                    list(base_service.get('evidence_sources') or [])
                    + list(identity.get('sources') or ([] if not identity.get('source') else [identity.get('source')]))
                )),
            })
            variants.append(variant)

        for service in variants:
            product = str(service.get('product') or '').strip()
            version = str(service.get('version') or '').strip()
            service_name = str(service.get('service') or '').strip()
            scope = str(service.get('identity_scope') or 'application_service')
            cpe_text = ' '.join(str(value) for value in service.get('cpe') or [] if str(value).strip())
            # An exact observed application CPE is itself structured product/version
            # evidence. Do not discard it merely because the human-readable product
            # field is blank. The CVE Program matcher remains responsible for
            # deciding whether the CPE/product/version has an affected-data match.
            if not cpe_text and not product:
                continue
            matches, held = mitre_search_with_held(
                product,
                version,
                service_name,
                cpe_text,
                scope=scope,
                context_cpe=' '.join(str(value) for value in service.get('os_cpe') or [] if str(value).strip()),
                include_search_summary=True,
            )
            append_diagnostics(service, scope, held)
            held_reasons = {str(item.get('reason') or '') for item in held or [] if isinstance(item, dict)}
            input_gap_reasons = {
                'observed_version_missing', 'observed_version_is_range',
                'unsupported_product_identity', 'cve_index_unavailable',
                'cve_program_index_unavailable',
            }
            if diagnostics is not None and not matches and not (held_reasons & input_gap_reasons):
                diagnostics.append({
                    'host': service.get('host'), 'port': service.get('port'), 'protocol': service.get('protocol'),
                    'service': service_name, 'product': product, 'version': version,
                    'identity_kind': service.get('identity_kind') or 'primary_service',
                    'identity_scope': scope,
                    'reason': 'cve_candidate_coverage_gap',
                    'matcher_status': 'no_candidate',
                    'detail': 'Observed product/version produced no structured Candidate CVE in the configured CVE Program index.',
                })
            for match in matches:
                if match.get('source') != OFFICIAL_CVE_SOURCE:
                    continue
                candidate_service = dict(service)
                if not str(candidate_service.get('product') or '').strip():
                    candidate_service['product'] = str((match.get('matched_product_tokens') or [''])[0] or '').strip()
                if not str(candidate_service.get('version') or '').strip():
                    candidate_service['version'] = str((match.get('matched_version_tokens') or [''])[0] or '').strip()
                reference_type, reason = _classify_cve_match(candidate_service, match)
                if reference_type.startswith('Excluded'):
                    append_diagnostics(service, scope, [{
                        'cve_id': match.get('cve_id'),
                        'reason': 'candidate_evidence_incomplete',
                        'matcher_status': 'held',
                        'detail': reason,
                    }])
                    continue
                row = _build_cve_row(candidate_service, match, 'Candidate CVE', reason)
                row['match_scope'] = scope
                row['affected_asset'] = (
                    f"Platform component on {service.get('port')}/{service.get('protocol')}"
                    if scope == 'platform_component'
                    else f"Service endpoint {service.get('port')}/{service.get('protocol')}"
                )
                add_candidate(row, candidate_service, match, scope)

    # Protocol collectors can expose a component/version that is not the
    # endpoint's primary product. The CVE Program component index may generate
    # candidates directly; validation will establish whether the host context
    # actually makes the CVE applicable.
    host_vendor_by_host: dict[str, str] = {}
    for identity in host_identities or []:
        host = str(identity.get('host') or '')
        vendor = str(identity.get('vendor') or '').strip()
        if host and vendor and host not in host_vendor_by_host:
            host_vendor_by_host[host] = vendor

    for observation in component_observations or []:
        host = str(observation.get('host') or '')
        component = str(observation.get('component') or '').strip()
        version = str(observation.get('version') or '').strip()
        if not host or not component or not version:
            continue
        matches, held = mitre_search_component_candidates(
            component,
            version,
            host_vendor=host_vendor_by_host.get(host, ''),
        )
        service = {
            'host': host,
            'port': observation.get('port'),
            'protocol': observation.get('protocol'),
            'service': observation.get('service') or component,
            'product': component,
            'version': version,
            'identity_kind': 'protocol_component',
            'identity_scope': 'platform_component',
            'evidence_sources': list(observation.get('evidence_sources') or []),
        }
        append_diagnostics(service, 'platform_component', held, identity_kind='protocol_component')

        # Narrative Microsoft/Windows component records require directly observed
        # Windows host context. MSRC may corroborate or positively contradict the
        # same pre-existing CVE IDs, but missing MSRC/fixed-build context is not a
        # negative Candidate gate. The advisory lookup is batched and internally
        # cached so it never scales per matching CVE record.
        windows_context = direct_windows_by_host.get(host)
        narrative_microsoft_ids: set[str] = set()
        for match in matches:
            matched_entry = match.get('matched_affected_entry') or {}
            matched_vendor_blob = ' '.join(
                str(value or '')
                for value in (
                    matched_entry.get('vendor') if isinstance(matched_entry, dict) else '',
                    *(match.get('affected_vendors') or []),
                    *(match.get('affected_products') or []),
                )
            ).lower()
            if (
                str(match.get('match_basis') or '') == 'prose_affected_component_version_scrape'
                and ('microsoft' in matched_vendor_blob or 'windows' in matched_vendor_blob)
            ):
                cve_id = str(match.get('cve_id') or '').upper().strip()
                if cve_id:
                    narrative_microsoft_ids.add(cve_id)

        advisory_by_id: dict[str, dict[str, Any]] = {}
        if narrative_microsoft_ids and windows_context:
            advisory_rows, advisory_diagnostics = windows_advisory_corroborate_cves_for_observed_windows_context(
                str(windows_context.get('product') or windows_context.get('name') or ''),
                str(windows_context.get('build') or windows_context.get('version') or windows_context.get('release') or ''),
                sorted(narrative_microsoft_ids),
            )
            append_diagnostics(service, 'platform_component', advisory_diagnostics, identity_kind='protocol_component')
            advisory_by_id = {
                str(item.get('cve_id') or '').upper(): dict(item)
                for item in advisory_rows
                if str(item.get('cve_id') or '').strip()
            }

        for match in matches:
            effective_match = dict(match)
            matched_entry = effective_match.get('matched_affected_entry') or {}
            matched_vendor_blob = ' '.join(
                str(value or '')
                for value in (
                    matched_entry.get('vendor') if isinstance(matched_entry, dict) else '',
                    *(effective_match.get('affected_vendors') or []),
                    *(effective_match.get('affected_products') or []),
                )
            ).lower()
            narrative_component_match = str(effective_match.get('match_basis') or '') == 'prose_affected_component_version_scrape'
            microsoft_windows_context = 'microsoft' in matched_vendor_blob or 'windows' in matched_vendor_blob
            if narrative_component_match and microsoft_windows_context:
                if not windows_context:
                    append_diagnostics(service, 'platform_component', [{
                        'cve_id': effective_match.get('cve_id'),
                        'reason': 'windows_release_context_not_observed',
                        'matcher_status': 'held',
                        'detail': 'Narrative Microsoft/Windows component affected data was retained for audit but not promoted without directly observed Windows product/build context.',
                    }], identity_kind='protocol_component')
                    continue
                advisory_context = advisory_by_id.get(str(effective_match.get('cve_id') or '').upper())
                context_state = str((advisory_context or {}).get('context_state') or 'uncorroborated')
                if context_state == 'contradicted':
                    append_diagnostics(service, 'platform_component', [{
                        'cve_id': effective_match.get('cve_id'),
                        'reason': 'windows_release_context_contradicted',
                        'matcher_status': 'diagnostic',
                        'detail': 'Microsoft advisory context conflicts with the directly observed Windows release context. This is retained as diagnostic metadata only and does not add or remove the CVE Program Candidate.',
                    }], identity_kind='protocol_component')
                    effective_match['windows_advisory_context_state'] = 'contradicted'
                if context_state == 'corroborated':
                    effective_match['match_basis'] = 'prose_component_version_with_windows_product_context'
                    effective_match['windows_advisory_context'] = advisory_context
                elif advisory_context:
                    effective_match['windows_advisory_context_state'] = context_state
            row = _build_cve_row(
                service,
                effective_match,
                'Candidate CVE',
                'CVE Program structured component affected data matched an observed protocol/component product and version.',
            )
            if effective_match.get('windows_advisory_context'):
                row['windows_advisory_context'] = copy.deepcopy(effective_match['windows_advisory_context'])
                row['candidate_evidence_note'] = (
                    str(row.get('candidate_evidence_note') or '').strip() + ' '
                    + 'Direct Windows context is corroborated by Microsoft affected-product data for the same Candidate CVE ID; patch/KB state remains unestablished.'
                ).strip()
            elif effective_match.get('windows_advisory_context_state'):
                row['windows_advisory_context_state'] = str(effective_match.get('windows_advisory_context_state'))
            row['match_scope'] = 'platform_component'
            row['affected_asset'] = f"Observed component on {observation.get('port')}/{observation.get('protocol')}"
            row['patch_state'] = 'Not established from unauthenticated protocol evidence'
            add_candidate(row, service, effective_match, 'platform_component')

    # Host operating-system candidates. The caller supplies only identities
    # marked candidate_eligible by platform_identity.py.
    for identity in host_identities or []:
        if str(identity.get('scope') or 'host_os') != 'host_os':
            continue
        if 'candidate_eligible' in identity and not bool(identity.get('candidate_eligible')):
            continue
        if bool(identity.get('resolution_candidate')) or str(identity.get('evidence_kind') or '') in {'official_product_resolution','service_os_hint'}:
            if diagnostics is not None:
                diagnostics.append({
                    'host': identity.get('host'), 'port': 'host', 'protocol': 'host',
                    'service': 'Host Operating System',
                    'product': identity.get('product') or identity.get('name'),
                    'version': identity.get('build') or identity.get('version') or identity.get('release'),
                    'identity_kind': 'host_os', 'identity_scope': 'host_os',
                    'reason': 'advisory_identity_not_observed', 'matcher_status': 'held',
                    'detail': 'Advisory/service-level identity context was not observed as an authoritative host OS and was not used to generate a Candidate CVE.',
                })
            continue
        product = str(identity.get('product') or identity.get('name') or identity.get('family') or '').strip()
        version = str(identity.get('build') or identity.get('version') or identity.get('release') or '').strip()
        if not product or not version:
            continue
        cpe_text = ' '.join(str(value) for value in identity.get('cpe') or [] if str(value).strip())
        matches, held = mitre_search_with_held(
            product,
            version,
            'host operating system',
            cpe_text,
            scope='host_os',
            include_search_summary=True,
        )
        service = {
            **dict(identity),
            'host': identity.get('host'),
            'port': 'host',
            'protocol': 'host',
            'service': 'Host Operating System',
            'product': product,
            'version': version,
            'identity_scope': 'host_os',
            'identity_kind': 'host_os',
            'evidence_sources': list(identity.get('sources') or []),
        }
        append_diagnostics(service, 'host_os', held, identity_kind='host_os')
        effective_matches = list(matches)
        direct_windows_context = direct_windows_by_host.get(str(identity.get('host') or ''))
        advisory_context_by_id: dict[str, dict[str, Any]] = {}
        # Microsoft advisory data is enrichment/corroboration only. It receives
        # only CVE IDs already generated by the CVE Program matcher and cannot
        # promote held/custom-version records into Candidate CVEs.
        existing_candidate_ids = {
            str(item.get('cve_id') or '').upper()
            for item in effective_matches
            if str(item.get('cve_id') or '').strip()
        }
        if direct_windows_context and existing_candidate_ids:
            advisory_rows, advisory_diagnostics = windows_advisory_corroborate_cves_for_observed_windows_context(
                str(direct_windows_context.get('product') or direct_windows_context.get('name') or product),
                str(direct_windows_context.get('build') or direct_windows_context.get('version') or direct_windows_context.get('release') or version),
                existing_candidate_ids,
            )
            append_diagnostics(service, 'host_os', advisory_diagnostics, identity_kind='host_os')
            advisory_context_by_id = {
                str(item.get('cve_id') or '').upper(): dict(item)
                for item in advisory_rows
                if str(item.get('cve_id') or '').strip()
            }
        seen_match_ids_basis: set[tuple[str, str]] = set()
        for match in effective_matches:
            signature = (str(match.get('cve_id') or '').upper(), str(match.get('match_basis') or ''))
            if signature in seen_match_ids_basis:
                continue
            seen_match_ids_basis.add(signature)
            row = _build_host_cve_row(identity, match)
            advisory_context = advisory_context_by_id.get(str(match.get('cve_id') or '').upper())
            if advisory_context:
                row['windows_advisory_context_state'] = str(advisory_context.get('context_state') or 'uncorroborated')
                if str(advisory_context.get('context_state') or '') == 'corroborated':
                    row['windows_advisory_context'] = copy.deepcopy(advisory_context)
                    row['candidate_evidence_note'] = (
                        str(row.get('candidate_evidence_note') or '').strip() + ' '
                        + 'Microsoft advisory affected-product context corroborates this already-generated CVE Program Candidate; it did not create or remove the Candidate.'
                    ).strip()
            add_candidate(row, service, match, 'host_os')

    candidates.sort(key=lambda row: (
        str(row.get('host') or ''),
        str(row.get('cve_id') or ''),
        str(row.get('product') or ''),
        str(row.get('version') or ''),
        str(row.get('protocol') or ''),
    ))
    review = list(candidates) if return_review_candidates else []
    return candidates, review


def _canonicalise_downstream_mapping(
    mapping_result: dict[str, Any],
    cve_matches: list[dict[str, Any]],
) -> dict[str, Any]:
    """Remove downstream CVE guesses and inject scanner-owned canonical links.

    This integration guard lets teammate mapping logic continue to provide
    technique context while ensuring every emitted CVE originates from the
    official scanner index and captured service evidence.
    """
    removed_ids: set[str] = set()
    cve_pattern = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.I)

    def scrub(value: Any) -> Any:
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, dict):
            local_cve_removed = False
            for key in list(value):
                if key in {'cve_ids', 'cve_matches'}:
                    local_cve_removed = local_cve_removed or bool(value.get(key))
                    for item in value.get(key) or []:
                        if isinstance(item, str):
                            removed_ids.update(cve_pattern.findall(item.upper()))
                        elif isinstance(item, dict):
                            removed_ids.update(cve_pattern.findall(str(item.get('cve_id') or '').upper()))
                    value[key] = []
                else:
                    value[key] = scrub(value[key])
            if local_cve_removed:
                value['_legacy_cve_removed'] = True
            return value
        if isinstance(value, str):
            removed_ids.update(cve_pattern.findall(value.upper()))
            return re.sub(r'\s+', ' ', cve_pattern.sub('', value)).strip(' -:;,()')
        return value

    scrub(mapping_result)
    canonical_by_endpoint: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in cve_matches:
        key = (str(row.get('host') or ''), str(row.get('port') or ''))
        canonical_by_endpoint.setdefault(key, []).append({
            'cve_id': row.get('cve_id'),
            'severity': row.get('source_cvss_severity') or row.get('cvss_severity') or row.get('severity') or '',
            'cvss_score': row.get('source_cvss_score') if row.get('source_cvss_score') is not None else row.get('cvss_score'),
            'cvss_metrics': row.get('source_cvss_metrics') or row.get('cvss_metrics') or {},
            'match_basis': row.get('match_basis') or row.get('match_reason') or '',
            'references': row.get('references') or [],
            'source': row.get('source') or OFFICIAL_CVE_SOURCE,
        })

    severity_order = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    vulnerabilities = mapping_result.get('vulnerabilities') or []
    for finding in vulnerabilities:
        key = (str(finding.get('host') or ''), str(finding.get('port') or ''))
        canonical = canonical_by_endpoint.get(key, [])
        finding['cve_matches'] = canonical
        finding['cve_ids'] = [row['cve_id'] for row in canonical if row.get('cve_id')]
        finding['cve_source'] = OFFICIAL_CVE_SOURCE if canonical else ''
        finding['cve_contract_version'] = 'scanner-canonical-v1'
        if canonical:
            severities = [str(row.get('severity') or '').upper() for row in canonical]
            best = max(severities, key=lambda value: severity_order.get(value, -1), default='')
            if best:
                finding['severity'] = best.title()
        elif finding.pop('_legacy_cve_removed', False):
            # Do not retain a CVE-inflated risk label after its unsupported link
            # was removed. Exposure scoring remains a separate teammate concern.
            finding['severity'] = 'Info'
            finding['priority_score'] = 0

    mapping_result['top_risks'] = sorted(
        vulnerabilities,
        key=lambda row: (severity_order.get(str(row.get('severity') or '').upper(), -1), int(row.get('priority_score') or 0)),
        reverse=True,
    )[:5]
    mapping_result['severity_counts'] = {
        label: sum(1 for row in vulnerabilities if str(row.get('severity') or 'Info').lower() == label.lower())
        for label in ('Critical', 'High', 'Medium', 'Low', 'Info')
    }
    mapping_result['cve_source_of_truth'] = 'scanner_official_index'
    mapping_result['cve_contract_version'] = 'scanner-canonical-v1'
    mapping_result['legacy_cve_links_removed'] = len(removed_ids)
    mapping_result['score_semantics'] = 'exposure_priority_not_cvss'

    def remove_internal_markers(value: Any) -> None:
        if isinstance(value, dict):
            value.pop('_legacy_cve_removed', None)
            for item in value.values():
                remove_internal_markers(item)
        elif isinstance(value, list):
            for item in value:
                remove_internal_markers(item)

    remove_internal_markers(mapping_result)
    return mapping_result



_INTERNAL_REPORT_TOOLS = {'jq', 'python_normaliser'}

# These rows remain visible in the Technical Appendix when useful, but they are
# orchestration/summary records rather than independent evidence actions.
# Excluding them from the KPI prevents double-counting a collector and the
# package/summary that contains its output.
_EVIDENCE_ACTION_META_TOOLS = {
    'modern_active_validation', 'passive_intelligence',
    'nmap_tcp_operator_selected', 'operator_tcp_coverage', 'udp_operator_selected',
    'credential_validation_handoff', 'file_sharing_exposure',
    'deferred_banner_ports', 'host_availability_assumption',
    'acl_adaptive_pause', 'acl_adaptive_pause_udp',
}


def _build_scan_summary(
    *,
    targets_requested: int,
    live_hosts: list[str],
    scan_options: dict[str, Any],
    scanned_tcp_ports_by_host: dict[str, set[int]],
    scanned_udp_ports_by_host: dict[str, set[int]],
    discovery_evidence: dict[str, dict[str, Any]],
    open_map: dict[str, list[int]],
    all_services: list[dict[str, Any]],
    public_coverage: list[dict[str, Any]],
    cve_matches: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build an evidence-derived scan assurance summary.

    Counts are derived from the normalized operator selection and the discovery
    evidence that actually executed. Missing/untested coverage is never treated
    as closed or safe.
    """
    port_selection = (scan_options or {}).get('port_selection') or {}
    tcp_selection = port_selection.get('tcp') or {}
    udp_selection = port_selection.get('udp') or {}
    host_count = len(live_hosts or [])

    def configured_total(selection: dict[str, Any]) -> int:
        try:
            return max(0, int(selection.get('count') or 0)) * host_count
        except (TypeError, ValueError):
            return 0

    tcp_scanned = sum(len(set(scanned_tcp_ports_by_host.get(host, set()))) for host in live_hosts)
    udp_scanned = sum(len(set(scanned_udp_ports_by_host.get(host, set()))) for host in live_hosts)
    tcp_requested = configured_total(tcp_selection)
    udp_requested = configured_total(udp_selection)

    def state_counts(protocol: str, scanned: int) -> dict[str, int]:
        explicit: dict[tuple[str, int], str] = {}
        extraports = {'closed': 0, 'filtered': 0}
        for host in live_hosts:
            evidence = discovery_evidence.get(host) or {}
            for row in evidence.get('ports') or []:
                if str(row.get('protocol') or '').lower() != protocol:
                    continue
                try:
                    port = int(row.get('port') or 0)
                except (TypeError, ValueError):
                    continue
                if port:
                    explicit[(str(host), port)] = str(row.get('state') or 'unknown').lower()
            for row in evidence.get('extraports') or []:
                if str(row.get('protocol') or '').lower() != protocol:
                    continue
                state = str(row.get('state') or '').lower()
                if state in extraports:
                    try:
                        extraports[state] += max(0, int(row.get('count') or 0))
                    except (TypeError, ValueError):
                        pass
        open_count = sum(1 for state in explicit.values() if state == 'open')
        closed_count = extraports['closed'] + sum(1 for state in explicit.values() if state == 'closed')
        filtered_count = extraports['filtered'] + sum(1 for state in explicit.values() if state == 'filtered')
        accounted = min(scanned, open_count + closed_count + filtered_count)
        unknown_count = max(0, scanned - accounted)
        return {
            'open': open_count,
            'closed': closed_count,
            'filtered': filtered_count,
            'unknown': unknown_count,
        }

    tcp_states = state_counts('tcp', tcp_scanned)
    udp_states = state_counts('udp', udp_scanned)

    # open_map is the canonical TCP open-port set; use it when available so
    # the summary remains consistent with downstream fingerprinting.
    canonical_tcp_open = sum(len(set(open_map.get(host, []))) for host in live_hosts)
    if canonical_tcp_open:
        tcp_states['open'] = canonical_tcp_open
        accounted = tcp_states['open'] + tcp_states['closed'] + tcp_states['filtered']
        tcp_states['unknown'] = max(0, tcp_scanned - min(tcp_scanned, accounted))

    tcp_endpoints = {
        (str(row.get('host') or ''), int(row.get('port') or 0))
        for row in all_services or []
        if str(row.get('protocol') or '').lower() == 'tcp' and row.get('port')
    }
    versioned_products = {
        (
            str(row.get('host') or ''),
            int(row.get('port') or 0),
            str(row.get('protocol') or '').lower(),
            str(row.get('product') or '').strip().lower(),
            str(row.get('version') or '').strip().lower(),
        )
        for row in all_services or []
        if row.get('port') and str(row.get('product') or '').strip() and str(row.get('version') or '').strip()
    }

    status_counts = {
        'executed': 0,
        'completed_without_error': 0,
        'produced_evidence': 0,
        'no_evidence': 0,
        'failed': 0,
        'timed_out': 0,
        'not_executed': 0,
        'not_applicable': 0,
        'disabled': 0,
        'disabled_operator': 0,
        'disabled_policy': 0,
        'unavailable': 0,
        'deferred': 0,
        'scope_blocked': 0,
        'assumed_live': 0,
        'skipped_policy': 0,
        'not_executed_unspecified': 0,
        'skipped': 0,  # backward-compatible total not-executed alias
    }
    for row in public_coverage or []:
        tool_name = str(row.get('tool') or '').strip().lower()
        if tool_name in _EVIDENCE_ACTION_META_TOOLS:
            continue
        status = str(row.get('status') or '').strip()
        status_l = status.lower()
        lifecycle = str(row.get('lifecycle_state') or '').strip().lower()
        # Lifecycle is the canonical execution-state contract. Fall back to the
        # display status only for legacy rows that predate lifecycle metadata.
        if lifecycle == 'executed_timeout':
            status_counts['executed'] += 1; status_counts['failed'] += 1; status_counts['timed_out'] += 1; continue
        if lifecycle == 'executed_failed':
            status_counts['executed'] += 1; status_counts['failed'] += 1; continue
        if lifecycle == 'executed_evidence':
            status_counts['executed'] += 1; status_counts['completed_without_error'] += 1; status_counts['produced_evidence'] += 1; continue
        if lifecycle == 'executed_no_evidence':
            status_counts['executed'] += 1; status_counts['completed_without_error'] += 1; status_counts['no_evidence'] += 1; continue
        if lifecycle == 'not_applicable':
            status_counts['not_executed'] += 1; status_counts['not_applicable'] += 1; continue
        if lifecycle == 'disabled_operator':
            status_counts['not_executed'] += 1; status_counts['disabled'] += 1; status_counts['disabled_operator'] += 1; continue
        if lifecycle == 'disabled_policy':
            status_counts['not_executed'] += 1; status_counts['disabled'] += 1; status_counts['disabled_policy'] += 1; continue
        if lifecycle == 'tool_unavailable':
            status_counts['not_executed'] += 1; status_counts['unavailable'] += 1; continue
        if lifecycle == 'scope_blocked':
            status_counts['not_executed'] += 1; status_counts['scope_blocked'] += 1; continue
        if lifecycle == 'deferred':
            status_counts['not_executed'] += 1; status_counts['deferred'] += 1; continue
        if lifecycle == 'assumed_live':
            status_counts['not_executed'] += 1; status_counts['assumed_live'] += 1; continue
        if lifecycle == 'skipped_policy':
            status_counts['not_executed'] += 1; status_counts['skipped_policy'] += 1; continue
        if status_l.startswith('timed out'):
            status_counts['executed'] += 1
            status_counts['failed'] += 1
            status_counts['timed_out'] += 1
            continue
        if status_l.startswith(('failed', 'input invalid')):
            status_counts['executed'] += 1
            status_counts['failed'] += 1
            continue
        if status_l.startswith('not applicable'):
            status_counts['not_executed'] += 1; status_counts['not_applicable'] += 1; continue
        if status_l.startswith('disabled by operator'):
            status_counts['not_executed'] += 1; status_counts['disabled'] += 1; status_counts['disabled_operator'] += 1; continue
        if status_l.startswith('disabled by policy') or 'tool disabled' in status_l or 'disabled by profile/policy' in status_l:
            status_counts['not_executed'] += 1; status_counts['disabled'] += 1; status_counts['disabled_policy'] += 1; continue
        if status_l.startswith('scope blocked'):
            status_counts['not_executed'] += 1; status_counts['scope_blocked'] += 1; continue
        if status_l.startswith('not executed - assumed live'):
            status_counts['not_executed'] += 1; status_counts['assumed_live'] += 1; continue
        if status_l.startswith('tool unavailable') or status_l.startswith('input missing'):
            status_counts['not_executed'] += 1; status_counts['unavailable'] += 1; continue
        if status_l.startswith('deferred'):
            status_counts['not_executed'] += 1; status_counts['deferred'] += 1; continue
        if status_l.startswith('skipped by policy'):
            status_counts['not_executed'] += 1; status_counts['skipped_policy'] += 1; continue
        if status_l.startswith('not executed'):
            status_counts['not_executed'] += 1; status_counts['not_executed_unspecified'] += 1; continue
        status_counts['executed'] += 1
        status_counts['completed_without_error'] += 1
        if status_l.startswith(('no evidence', 'no web paths')):
            status_counts['no_evidence'] += 1
        else:
            status_counts['produced_evidence'] += 1
    status_counts['skipped'] = status_counts['not_executed']

    cve_ids = {
        str(row.get('cve_id') or '').upper()
        for row in list(cve_matches or [])
        if row.get('cve_id')
    }
    grouped_cves = _group_cve_matches_by_host(list(cve_matches or []))
    per_host_cve_review = {
        host: {
            'reference_items': len(host_rows),
            'unique_references': len({str(row.get('cve_id') or '').upper() for row in host_rows if row.get('cve_id')}),
        }
        for host, host_rows in grouped_cves.items()
    }
    return {
        'targets': {
            'requested': max(0, int(targets_requested or 0)),
            'reached': host_count,
        },
        'tcp': {
            'mode': str(tcp_selection.get('mode') or ''),
            'requested': tcp_requested,
            'scanned': tcp_scanned,
            'untested': max(0, tcp_requested - tcp_scanned),
            **tcp_states,
        },
        'udp': {
            'mode': str(udp_selection.get('mode') or ''),
            'requested': udp_requested,
            'scanned': udp_scanned,
            'untested': max(0, udp_requested - udp_scanned),
            **udp_states,
        },
        'services': {
            'tcp_open_endpoints': canonical_tcp_open,
            'tcp_reprobed': len(tcp_endpoints),
            'tcp_fingerprinted': len(tcp_endpoints),  # backward-compatible alias
            'versioned_service_endpoints': len(versioned_products),
            'versioned_products': len(versioned_products),  # backward-compatible alias
            'observed_endpoints': len({
                (str(row.get('host') or ''), int(row.get('port') or 0), str(row.get('protocol') or '').lower())
                for row in all_services or [] if row.get('port')
            }),
        },
        'evidence_checks': status_counts,
        'cve_review': {
            'unique_references': len(cve_ids),
            'reference_items': len(list(cve_matches or [])),
            'by_host': per_host_cve_review,
            'versioned_service_endpoints': len(versioned_products),
            'versioned_products': len(versioned_products),  # backward-compatible alias
        },
        'assurance_note': 'Untested coverage is reported separately and is never represented as closed, filtered, or secure.',
    }


def _public_tool_coverage(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    public: list[dict[str, Any]] = []
    credential_validation_rows: list[dict[str, Any]] = []
    for row in rows or []:
        tool_name = str(row.get('tool') or '').lower()
        if tool_name in _INTERNAL_REPORT_TOOLS:
            continue
        if tool_name == 'credential_validation':
            credential_validation_rows.append(row)
            continue
        public.append(row)

    if credential_validation_rows:
        statuses = [str(r.get('status') or '') for r in credential_validation_rows]
        notes = [str(r.get('note') or '') for r in credential_validation_rows if r.get('note')]
        affected = []
        for note in notes:
            m = re.search(r'(\d+\.\d+\.\d+\.\d+:\d+/[A-Za-z0-9_-]+)', note)
            if m:
                affected.append(m.group(1))
            elif note:
                affected.append(note)
        if any('Completed' in s for s in statuses):
            status = 'Completed'
        elif any('Input Invalid' in s for s in statuses):
            status = 'Input Invalid'
        elif any('Input Missing' in s for s in statuses):
            status = 'Input Missing'
        elif any('Timed Out' in s for s in statuses):
            status = 'Timed Out - Incomplete'
        else:
            status = 'Failed - Incomplete'
        output_files = [str(r.get('output_file') or '') for r in credential_validation_rows if r.get('output_file')]
        commands = [str(r.get('command') or '') for r in credential_validation_rows if r.get('command')]
        outputs = []
        for r in credential_validation_rows:
            out = str(r.get('output') or '')
            if out:
                outputs.append(out)
        note = 'Affected services: ' + ', '.join(sorted(set(affected))) if affected else 'Default credential checks were selected.'
        if status == 'Input Invalid':
            note = 'Credential combo file was invalid. ' + note
        public.append({
            'tool': 'Default credential checks',
            'status': status,
            'raw_status': status,
            'evidence_type': 'Default credential check evidence',
            'information_added': 'Default credential check evidence',
            'note': note,
            'output_file': ', '.join(Path(x).name for x in output_files[:5]),
            'command': '\n'.join(commands[:5]),
            'output': '\n\n---\n\n'.join(outputs[:5]),
            'output_truncated': any(r.get('output_truncated') for r in credential_validation_rows),
            'exit_code': ', '.join(str(r.get('exit_code','')) for r in credential_validation_rows[:5]),
            'stderr_summary': '; '.join(str(r.get('stderr_summary') or '') for r in credential_validation_rows if r.get('stderr_summary'))[:260],
            'failure_reason': '; '.join(str(r.get('failure_reason') or '') for r in credential_validation_rows if r.get('failure_reason'))[:260],
        })
    return public


def _build_service_summary(services: list[dict[str, Any]], cve_matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    linked_ports = {(str(c.get('host')), str(p)) for c in cve_matches or [] for p in (c.get('observed_ports') or [])}
    rows = []
    for s in services or []:
        port_ref = f"{s.get('port')}/{s.get('protocol')}"
        if (str(s.get('host')), port_ref) in linked_ports:
            status = 'CVE reference(s) linked'
        elif s.get('product') or s.get('version'):
            status = 'Service identified'
        else:
            status = 'Service observed; identity incomplete'
        rows.append({
            'host': s.get('host'),
            'port': s.get('port'),
            'protocol': s.get('protocol'),
            'service': s.get('service'),
            'product': s.get('product'),
            'version': s.get('version'),
            'status': status,
            'identity_context': s.get('identity_context') or '',
            'evidence_gaps': ', '.join(s.get('missing_information') or []),
            'confidence_score': s.get('confidence_score', 0.0),
            'confidence_badge': s.get('confidence_badge') or _confidence_badge(float(s.get('confidence_score') or 0.0)),
            'contradictions': list(s.get('contradictions') or []),
            'recommended_for_cve': bool(s.get('recommended_for_cve', False)),
        })
    return rows


def _status_sort_key(status: str) -> tuple[int, str]:
    s = (status or '').lower()
    if s == 'completed' or s.startswith('completed'):
        return (0, s)
    if 'partial results' in s:
        return (1, s)
    if 'no evidence' in s or 'not applicable' in s or 'no web paths' in s:
        return (2, s)
    if 'input missing' in s or 'input invalid' in s or 'unavailable' in s or 'disabled' in s:
        return (3, s)
    if 'timed out' in s or 'failed' in s or 'incomplete' in s:
        return (4, s)
    return (4, s)

def _sort_coverage(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=lambda r: (_status_sort_key(str(r.get('status',''))), str(r.get('tool','')), str(r.get('note',''))))



def _attack_surface_category(service: dict[str, Any]) -> str:
    svc = str(service.get('service') or '').lower()
    prod = str(service.get('product') or '').lower()
    try: port = int(service.get('port') or 0)
    except Exception: port = 0
    if port in {21, 2121} or 'ftp' in svc or 'ftp' in prod:
        return 'File Transfer Surface'
    if port in {23,22,512,513,514,1524,5900,6000} or any(x in svc for x in ['ssh','telnet','exec','login','bindshell','vnc','x11']):
        return 'Remote Access Surface'
    if any(x in svc for x in ['http','ajp']) or any(x in prod for x in ['apache','tomcat','coyote']):
        return 'Web Surface'
    if port in {139,445,137,2049,111} or any(x in svc for x in ['smb','netbios','nfs','rpcbind']):
        return 'File Sharing and RPC Surface'
    if port in {3306,5432} or any(x in svc for x in ['mysql','postgresql']):
        return 'Database Surface'
    if port in {25,53,6667,6697,1099,8787,3632} or any(x in svc for x in ['smtp','domain','irc','rmi','drb','distccd']):
        return 'Application Service Surface'
    return 'Other Observed Services'


def _gap_label(gap: str) -> str:
    value = str(gap or '').strip().lower()
    labels = {
        'product': 'Product name not identified',
        'version': 'Version not identified',
        'cpe': 'CPE not collected',
    }
    return labels.get(value, gap)


def _ports_intersect(card_ports: list[str], other_ports: list[str]) -> bool:
    card = {str(p).split('/')[0] for p in card_ports if p}
    other = {str(p).split('/')[0] for p in other_ports if p}
    return bool(card & other)


def _service_card_identity(s: dict[str, Any]) -> tuple[tuple[str, str, str, str], str, str, str, str]:
    host = str(s.get('host') or '')
    svc = str(s.get('service') or 'unknown')
    prod = str(s.get('product') or '')
    ver = str(s.get('version') or '')
    try:
        port = int(s.get('port') or 0)
    except Exception:
        port = 0
    svc_l = svc.lower()
    prod_l = prod.lower()
    if port in {137, 139, 445} or 'samba' in prod_l or 'netbios' in svc_l or 'smb' in svc_l or 'microsoft-ds' in svc_l:
        prod = prod or 'Samba/SMB'
        # One host-level SMB/NetBIOS card prevents UDP/137 and TCP/139/445 from
        # appearing as fragmented findings while preserving all observed ports.
        return (host, 'smb', '', ''), 'smb', prod, ver, 'File Sharing and RPC Surface'
    if port == 53 or svc_l in {'domain', 'dns'} or 'bind' in prod_l:
        prod = prod or 'DNS service'
        return (host, 'domain', prod, ver), 'domain', prod, ver, 'Application Service Surface'
    if port in {111, 2049} or svc_l in {'rpcbind', 'nfs'}:
        label = 'NFS/RPC'
        return (host, 'nfs-rpc', label, ''), 'nfs-rpc', label, '', 'File Sharing and RPC Surface'
    if port in {8180, 8080, 8081, 8443} and (svc_l in {'unknown', ''} or not prod):
        return (host, 'unknown-application', 'Unknown application service', ''), 'unknown-application', 'Unknown application service', '', 'Web Surface'
    return (host, svc, prod, ver), svc, prod, ver, _attack_surface_category(s)


def _dedupe_dicts(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for row in rows or []:
        key = tuple(str(row.get(k) or '') for k in keys)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _build_service_workbench(services: list[dict[str, Any]], cve_matches: list[dict[str, Any]], observations: list[dict[str, Any]], web_summary: dict[str, Any], smb_summary: dict[str, Any], service_checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cards: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for s in services or []:
        key, card_service, card_product, card_version, category = _service_card_identity(s)
        card = cards.setdefault(key, {
            'host': s.get('host'),
            'service': card_service or 'unknown',
            'product': card_product or '',
            'version': card_version or '',
            'category': category,
            'ports': [],
            'cve_findings': [],
            'observations': [],
            'evidence_gaps': [],
            'checks': [],
            'web_evidence': [],
            'web_paths': [],
            'smb_shares': [],
            'fingerprints': [],
            'state': 'Identified Service',
        })
        # Prefer stronger identity evidence when merged service cards start with
        # generic UDP/unknown rows and later TCP/banner evidence provides product/version.
        if card_product and (not card.get('product') or card.get('product') in {'Samba/SMB', 'Unknown application service', 'DNS service'}):
            card['product'] = card_product
        if card_version and not card.get('version'):
            card['version'] = card_version
        port_ref = f"{s.get('port')}/{s.get('protocol')}"
        if port_ref not in card['ports']:
            card['ports'].append(port_ref)
        if s.get('service_fingerprint'):
            card['fingerprints'].append(s.get('service_fingerprint'))
        for gap in s.get('missing_information') or []:
            label = _gap_label(gap)
            if label and label not in card['evidence_gaps']:
                card['evidence_gaps'].append(label)
    for card in cards.values():
        card_port_nums = {p.split('/')[0] for p in card.get('ports', [])}
        for cve in cve_matches or []:
            if str(cve.get('host')) != str(card.get('host')):
                continue
            product_match = str(cve.get('product') or '').lower() == str(card.get('product') or '').lower() and str(cve.get('version') or '').lower() == str(card.get('version') or '').lower()
            port_match = bool(set(str(p).split('/')[0] for p in (cve.get('observed_ports') or [])) & card_port_nums)
            if product_match or port_match:
                card['cve_findings'].append(cve)
        for obs in observations or []:
            if str(obs.get('host')) == str(card.get('host')) and str(obs.get('port')) in card_port_nums:
                card['observations'].append(obs)
        for check in service_checks or []:
            if str(check.get('host')) != str(card.get('host')):
                continue
            if str(check.get('status','')).lower().startswith('not applicable'):
                continue
            check_ports = re.findall(r'\d+', str(check.get('port') or ''))
            if _ports_intersect(card.get('ports', []), check_ports):
                card['checks'].append(check)
        if str(card.get('service','')).lower() in {'http','https','http-proxy','ajp13'} or 'apache' in str(card.get('product','')).lower() or 'tomcat' in str(card.get('product','')).lower():
            for w in (web_summary or {}).get('services') or []:
                if str(w.get('host')) == str(card.get('host')) and str(w.get('port')) in card_port_nums:
                    card['web_evidence'].append(w)
            for path in (web_summary or {}).get('paths') or []:
                if str(path.get('host')) == str(card.get('host')) and str(path.get('port')) in card_port_nums:
                    card['web_paths'].append(path)
        if card.get('service') == 'smb' or any(p.split('/')[0] in {'139','445','137'} for p in card.get('ports', [])):
            card['smb_shares'] = [sh for sh in ((smb_summary or {}).get('shares') or []) if str(sh.get('host')) == str(card.get('host'))]
        card['observations'] = _dedupe_dicts(card['observations'], ('observation', 'evidence'))
        card['checks'] = _dedupe_dicts(card['checks'], ('check', 'status', 'evidence_file'))
        card['cve_findings'] = _dedupe_dicts(card['cve_findings'], ('cve_id', 'product', 'version'))
        card['web_paths'] = _dedupe_dicts(card['web_paths'], ('path', 'status_code'))
        card['fingerprints'] = _dedupe_dicts(card['fingerprints'], ('target', 'port'))
        confidence_values = [float(item.get('confidence_score') or 0.0) for item in card['fingerprints']]
        card['confidence_score'] = max(confidence_values, default=0.0)
        card['confidence_badge'] = _confidence_badge(card['confidence_score'])
        card['contradictions'] = list(dict.fromkeys(
            contradiction
            for item in card['fingerprints']
            for contradiction in (item.get('contradictions') or [])
        ))
        # Recompute merged-card identity gaps from the final merged identity instead of
        # inheriting weaker UDP/unknown gaps after TCP/banner evidence improved the card.
        final_gaps = []
        if not str(card.get('product') or '').strip() or str(card.get('product') or '').strip().lower() in {'unidentified product', 'dns service'}:
            final_gaps.append('Product name not identified')
        if not str(card.get('version') or '').strip() and card.get('service') not in {'smb', 'nfs-rpc', 'unknown-application'}:
            final_gaps.append('Version not identified')
        if card.get('service') == 'smb' and str(card.get('product') or '').strip() and str(card.get('version') or '').strip():
            final_gaps = []
        if card.get('service') == 'domain' and str(card.get('product') or '').strip().lower() not in {'dns service', 'unidentified product'}:
            final_gaps = [g for g in final_gaps if g != 'Product name not identified']
        card['evidence_gaps'] = final_gaps
        if card['cve_findings']:
            card['state'] = 'CVE References Linked'
        elif card['observations']:
            card['state'] = 'Security-Relevant Exposure'
        elif card['evidence_gaps']:
            card['state'] = 'Identity Incomplete'
    state_order = {'CVE References Linked':0, 'Security-Relevant Exposure':1, 'Identity Incomplete':2, 'Identified Service':3}
    return sorted(cards.values(), key=lambda c: (c.get('category',''), state_order.get(c.get('state'),9), str(c.get('host')), str(c.get('ports'))))


def _build_attack_surface_sections(service_cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sections: dict[str, list[dict[str, Any]]] = {}
    for card in service_cards or []:
        sections.setdefault(str(card.get('category') or 'Other Observed Services'), []).append(card)
    order = ['Remote Access Surface', 'File Transfer Surface', 'Web Surface', 'File Sharing and RPC Surface', 'Database Surface', 'Application Service Surface', 'Other Observed Services']
    return [{'category': cat, 'services': sections[cat]} for cat in order if cat in sections]


def _build_key_exposure_indicators(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group repeated exposure indicators into pentester-readable rows."""
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}

    def family(o: dict[str, Any]) -> tuple[str, str]:
        obs = str(o.get('observation','')).lower()
        svc = str(o.get('service','')).lower()
        if 'anonymous ftp' in obs:
            return ('File Transfer', 'Anonymous FTP access allowed')
        if 'legacy r-service' in obs or svc in {'exec', 'login', 'shell', 'tcpwrapped'}:
            return ('Remote Access', 'Legacy r-services exposed')
        if 'nfs/rpc' in obs or 'rpc/nfs' in obs:
            return ('File Sharing', 'RPC/NFS file-sharing surface observed')
        if 'database service' in obs:
            return ('Database', 'Database services exposed on the network')
        if 'admin or management web path' in obs:
            return ('Web', 'Admin or management web paths observed')
        if 'directory listing' in obs:
            return ('Web', 'Directory listing or browsable web path observed')
        if 'information-disclosure' in obs:
            return ('Web', 'Information-disclosure style web path observed')
        if 'phpmyadmin' in obs:
            return ('Web', 'phpMyAdmin path observed')
        if 'anonymous smb' in obs:
            return ('File Sharing', 'Anonymous SMB share listing available')
        if 'shell-like' in obs:
            return ('Remote Access', 'Shell-like service indicator observed')
        if 'plaintext' in obs:
            return ('Remote Access', 'Plaintext remote administration service exposed')
        if 'vnc' in obs:
            return ('Remote GUI', 'VNC remote desktop service exposed')
        if 'x11' in obs:
            return ('Remote GUI', 'X11 display service exposed')
        if 'webdav' in obs:
            return ('Web', 'WebDAV path observed')
        if 'ajp' in obs:
            return ('Web', 'AJP connector exposed')
        return (str(o.get('category') or 'Exposure'), str(o.get('observation') or 'Exposure observed'))

    for o in observations or []:
        cat, title = family(o)
        key = (str(o.get('host') or ''), cat, title)
        row = groups.setdefault(key, {
            'host': o.get('host'),
            'category': cat,
            'service': o.get('service'),
            'observation': title,
            'evidence': o.get('evidence'),
            'ports': [],
            'protocols': [],
        })
        port_ref = f"{o.get('port')}/{o.get('protocol')}" if o.get('protocol') else str(o.get('port') or '')
        if port_ref and port_ref not in row['ports']:
            row['ports'].append(port_ref)
        if o.get('protocol') and o.get('protocol') not in row['protocols']:
            row['protocols'].append(o.get('protocol'))
    def sort_key(o: dict[str, Any]) -> tuple[int, str, str]:
        text = str(o.get('observation','')).lower()
        if 'shell' in text: rank = 0
        elif 'plaintext' in text or 'legacy' in text: rank = 1
        elif 'anonymous smb' in text: rank = 2
        elif 'admin' in text or 'phpmyadmin' in text or 'information' in text: rank = 3
        else: rank = 4
        return (rank, str(o.get('host')), ','.join(o.get('ports') or []))
    return sorted(groups.values(), key=sort_key)



def _component_versions_from_evidence(component: str, text: str) -> list[str]:
    """Extract directly stated protocol/component versions from collector output."""
    family = re.sub(r'[^a-z0-9]+', '', str(component or '').lower())
    evidence = str(text or '')
    if not family or not evidence:
        return []
    versions: list[str] = []
    patterns = (
        rf'(?i)(?<![a-z0-9]){re.escape(family)}\s*v(?:ersion\s*)?([0-9]+(?:\.[0-9]+)*)',
        rf'(?i)(?<![a-z0-9]){re.escape(family)}\s+version\s+([0-9]+(?:\.[0-9]+)*)',
    )
    for pattern in patterns:
        for match in re.finditer(pattern, evidence):
            value = str(match.group(1) or '').strip()
            if value and value not in versions:
                versions.append(value)
    return versions


def _build_protocol_component_observations(
    service_checks: list[dict[str, Any]],
    collector_plan: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build component identities only from successful direct collector evidence."""
    observations: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str, str, str]] = set()
    for item in service_checks or []:
        if not isinstance(item, dict):
            continue
        tool_id = str(item.get('tool') or '')
        plan_entry = (collector_plan or {}).get(tool_id) or {}
        components = [str(value).strip().lower() for value in plan_entry.get('component_families') or [] if str(value).strip()]
        if not components:
            continue
        lifecycle = str(item.get('lifecycle_state') or '').lower()
        if lifecycle != 'executed_evidence':
            continue
        evidence_parts = [str(value) for value in item.get('script_evidence') or [] if str(value).strip()]
        if not evidence_parts:
            evidence_parts.extend(output for _script_id, output in _nmap_script_evidence_from_file(item.get('output_file')))
        parsed = item.get('parsed') or {}
        if isinstance(parsed, dict):
            fields = parsed.get('fields') or {}
            if isinstance(fields, dict):
                evidence_parts.extend(str(value) for value in fields.values() if value not in (None, '', [], {}))
        evidence_text = '\n'.join(evidence_parts)
        try:
            port = int(item.get('port') or 0)
        except (TypeError, ValueError):
            port = 0
        host = str(item.get('host') or '')
        protocol = str(item.get('protocol') or 'tcp').lower()
        for component in components:
            for version in _component_versions_from_evidence(component, evidence_text):
                signature = (host, port, protocol, component, version)
                if signature in seen:
                    continue
                seen.add(signature)
                observations.append({
                    'host': host,
                    'port': port,
                    'protocol': protocol,
                    'service': str(item.get('service') or component),
                    'component': component,
                    'version': version,
                    'identity_kind': 'protocol_component',
                    'identity_scope': 'platform_component',
                    'evidence_sources': [tool_id],
                    'evidence_reference': str(item.get('output_file') or ''),
                    'evidence': evidence_text[:8000],
                })
    return observations


def _collector_service_applicable(plan_entry: dict[str, Any], service: dict[str, Any]) -> bool:
    if str(plan_entry.get('scope') or '') == 'host':
        return True

    allowed_protocols = {
        str(value).strip().lower()
        for value in plan_entry.get('protocols') or []
        if str(value).strip()
    }
    observed_protocol = str(service.get('protocol') or 'tcp').strip().lower()
    if allowed_protocols and observed_protocol not in allowed_protocols:
        return False

    families = [str(x).lower() for x in plan_entry.get('families') or [] if str(x).strip()]
    if not families:
        return True
    transport_security = str(service.get('transport_security') or '').strip().lower()
    if transport_security == 'tls' and any(family in {'tls', 'https'} for family in families):
        return True
    text = ' '.join(str(service.get(k) or '') for k in ('service','product','extrainfo','identity_context','transport_security')).lower().replace('_',' ').replace('-',' ')
    text = re.sub(r'\s+', ' ', text).strip()
    aliases = {
        'http': ('http','web','tomcat','apache coyote'), 'https': ('https','ssl','tls'), 'tls': ('tls','ssl','https'),
        'smb': ('smb','netbios','microsoft ds','samba'), 'netbios': ('netbios','smb','samba'),
        'dns': ('dns','domain','bind'), 'domain': ('domain','dns','bind'), 'ftp': ('ftp','vsftpd','proftpd'),
        'ssh': ('ssh','openssh'), 'telnet': ('telnet',), 'rdp': ('rdp','ms wbt server'), 'vnc': ('vnc','rfb'),
        'rpcbind': ('rpcbind','portmapper','port mapper','sun rpc','onc rpc'),
        'portmapper': ('portmapper','port mapper','rpcbind','sun rpc','onc rpc'),
        'mountd': ('mountd','mount daemon'),
        'msrpc': ('msrpc','epmap','microsoft rpc'), 'epmap': ('epmap','msrpc','microsoft rpc'),
        'nfs': ('nfs','network file system'), 'ldap': ('ldap',), 'kerberos': ('kerberos',),
        'winrm': ('winrm','wsman'), 'wsman': ('wsman','winrm'), 'snmp': ('snmp',), 'postgresql': ('postgres','postgresql'),
        'postgres': ('postgres','postgresql'), 'mssql': ('mssql','ms sql'), 'ms-sql': ('mssql','ms sql'),
        'redis': ('redis',), 'elasticsearch': ('elasticsearch',), 'ajp': ('ajp','jserv'), 'tomcat': ('tomcat',),
        'mysql': ('mysql',), 'smtp': ('smtp','postfix'), 'imap': ('imap',), 'pop3': ('pop3','pop'), 'nntp': ('nntp','news'), 'irc': ('irc','unrealircd'), 'kubernetes': ('kubernetes',),
        'docker': ('docker','container','registry'), 'registry': ('registry','docker'), 'vpn': ('vpn',),
    }

    def contains_phrase(value: str) -> bool:
        phrase = re.sub(r'\s+', ' ', str(value or '').strip().lower())
        if not phrase:
            return False
        return bool(re.search(r'(?<![a-z0-9])' + re.escape(phrase) + r'(?![a-z0-9])', text))

    for family in families:
        values = aliases.get(family, (family,))
        if any(contains_phrase(value) for value in values):
            return True
    return False


def _build_collector_coverage_matrix(
    services: list[dict[str, Any]],
    scan_options: dict[str, Any],
    public_coverage: list[dict[str, Any]],
    raw_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build an endpoint-oriented collector execution matrix.

    This reports operator intent, policy state, applicability and observed
    execution separately. It never infers vulnerability validity.
    """
    plan = scan_options.get('collector_plan') or {}
    coverage_by_tool: dict[str, list[dict[str, Any]]] = {}
    for item in public_coverage or []:
        coverage_by_tool.setdefault(str(item.get('tool') or ''), []).append(item)
    raw_by_endpoint: set[tuple[str, str, str]] = set()
    for item in raw_evidence or []:
        # A retained failure artefact is audit evidence about execution, not
        # positive endpoint evidence. Only successfully parsed/produced raw
        # artefacts may upgrade endpoint coverage to `executed_evidence`.
        if 'parsed' in item and not bool(item.get('parsed')):
            continue
        raw_by_endpoint.add((str(item.get('tool') or ''), str(item.get('host') or ''), str(item.get('port') or '')))

    rows: list[dict[str, Any]] = []
    endpoint_summary: list[dict[str, Any]] = []
    for service in services or []:
        host = str(service.get('host') or '')
        port = str(service.get('port') or '')
        protocol = str(service.get('protocol') or 'tcp').lower()
        endpoint = f'{port}/{protocol}' if port else protocol
        relevant = 0; evidence_count = 0; failed = 0; not_executed = 0
        for collector_id, entry in plan.items():
            if str(entry.get('scope') or '') == 'host' or not _collector_service_applicable(entry, service):
                continue
            relevant += 1
            if not entry.get('requested'):
                outcome = 'Disabled by operator'; lifecycle = 'disabled_operator'; not_executed += 1
            elif entry.get('policy_state') == 'blocked':
                outcome = 'Disabled by policy'; lifecycle = 'disabled_policy'; not_executed += 1
            else:
                candidates = coverage_by_tool.get(collector_id, [])
                matching = []
                endpoint_token = f'{host}:{port}' if host and port else ''
                for candidate in candidates:
                    note = str(candidate.get('note') or '')
                    command = str(candidate.get('command') or '')
                    if endpoint_token and (endpoint_token in note or endpoint_token in command):
                        matching.append(candidate)
                has_raw = (collector_id, host, port) in raw_by_endpoint
                terminal = matching[-1] if matching else None
                terminal_status = str((terminal or {}).get('status') or '')
                terminal_lifecycle = str((terminal or {}).get('lifecycle_state') or '').strip()
                if terminal and (terminal_lifecycle == 'executed_timeout' or terminal_status.lower().startswith('timed out')):
                    outcome = terminal_status or 'Timed Out - Incomplete'; lifecycle = 'executed_timeout'; failed += 1
                elif terminal and (terminal_lifecycle == 'executed_failed' or terminal_status.lower().startswith('failed')):
                    outcome = terminal_status or 'Failed - Incomplete'; lifecycle = 'executed_failed'; failed += 1
                elif has_raw:
                    outcome = 'Evidence retained'; lifecycle = 'executed_evidence'; evidence_count += 1
                elif matching:
                    candidate = matching[-1]
                    status = str(candidate.get('status') or 'Execution recorded')
                    outcome = status
                    lifecycle = str(candidate.get('lifecycle_state') or '').strip() or 'unspecified'
                    if lifecycle == 'executed_timeout' or status.lower().startswith('timed out'):
                        lifecycle = 'executed_timeout'; failed += 1
                    elif lifecycle == 'executed_failed' or status.lower().startswith('failed'):
                        lifecycle = 'executed_failed'; failed += 1
                    elif lifecycle in {'disabled_operator','disabled_policy','not_applicable','deferred','scope_blocked','tool_unavailable','insufficient_privilege','assumed_live','skipped_policy'}:
                        not_executed += 1
                    elif lifecycle == 'executed_no_evidence' or status.lower().startswith('no evidence'):
                        lifecycle = 'executed_no_evidence'
                    elif lifecycle == 'executed_evidence':
                        # A service-specific coverage record says the action ran,
                        # but without a retained raw artefact the matrix must not
                        # claim endpoint evidence that it cannot point to.
                        lifecycle = 'executed_no_evidence'
                        outcome = 'Executed - no endpoint-specific evidence retained'
                    else:
                        lifecycle = 'executed_no_evidence'
                        outcome = 'Execution recorded - no endpoint-specific evidence retained'
                elif candidates:
                    # Some collectors execute as one aggregate operation across
                    # several applicable services. Preserve that execution fact
                    # without pretending every endpoint produced evidence.
                    aggregate = candidates[-1]
                    aggregate_state = str(aggregate.get('lifecycle_state') or '').strip()
                    if aggregate_state in {'disabled_operator','disabled_policy','not_applicable','deferred','scope_blocked','tool_unavailable','insufficient_privilege','assumed_live','skipped_policy'}:
                        lifecycle = aggregate_state; outcome = str(aggregate.get('status') or 'Not executed'); not_executed += 1
                    elif aggregate_state == 'executed_timeout':
                        lifecycle = 'executed_timeout'; outcome = 'Timed Out - Incomplete'; failed += 1
                    elif aggregate_state == 'executed_failed':
                        lifecycle = 'executed_failed'; outcome = 'Failed - Incomplete'; failed += 1
                    else:
                        lifecycle = 'executed_no_evidence'; outcome = 'Executed - no endpoint-specific evidence retained'
                else:
                    outcome = 'Lifecycle assurance failure - no terminal execution record'; lifecycle = 'assurance_failure'; failed += 1
            rows.append({
                'host': host, 'endpoint': endpoint, 'service': service.get('service') or '',
                'collector': collector_id, 'group': entry.get('group') or '',
                'requested_mode': entry.get('mode') or '', 'policy_state': entry.get('policy_state') or '',
                'outcome': outcome, 'lifecycle_state': lifecycle,
            })
        endpoint_summary.append({
            'host': host, 'endpoint': endpoint, 'service': service.get('service') or '',
            'applicable_collectors': relevant, 'evidence_collectors': evidence_count,
            'failed_collectors': failed, 'not_executed_collectors': not_executed,
        })

    host_tools = {'ping','arp-scan','dig','route_trace','nmap_host_discovery','host_availability_assumption','passive_packet_inventory','passive_os_fingerprinting'}
    host_tools.update(str(tool_id) for tool_id, entry in plan.items() if str(entry.get('scope') or '') == 'host')
    host_lifecycle = [dict(item) for item in public_coverage or [] if str(item.get('tool') or '') in host_tools]
    recorded_host_tools = {str(item.get('tool') or '') for item in host_lifecycle}
    # Host-scoped collector choices belong in the assurance matrix even when
    # the operator disabled them. This makes the configuration/result contract
    # complete instead of only listing actions that happened to produce a row.
    for tool_id, entry in plan.items():
        if str(entry.get('scope') or '') != 'host' or str(tool_id) in recorded_host_tools:
            continue
        if not entry.get('requested'):
            status, lifecycle, note = 'Disabled by Operator', 'disabled_operator', 'Collector was disabled by the operator.'
        elif entry.get('policy_state') == 'blocked':
            status, lifecycle, note = 'Disabled by Policy', 'disabled_policy', entry.get('policy_reason') or 'Collector was blocked by effective policy.'
        else:
            status, lifecycle, note = 'Lifecycle Assurance Failure', 'assurance_failure', 'Collector was requested but no terminal execution lifecycle record was retained.'
        host_lifecycle.append({
            'tool': str(tool_id), 'status': status, 'raw_status': '',
            'evidence_type': 'Host-scoped collector lifecycle',
            'information_added': 'Host-scoped collector lifecycle',
            'note': note, 'output_file': '', 'command': '', 'output': '',
            'output_truncated': False, 'exit_code': '', 'stderr_summary': '',
            'failure_reason': '', 'lifecycle_state': lifecycle,
        })
    lifecycle_counts: dict[str, int] = {}
    for row in rows:
        state = str(row.get('lifecycle_state') or 'unspecified')
        lifecycle_counts[state] = lifecycle_counts.get(state, 0) + 1
    endpoint_failed_actions = sum(int(item.get('failed_collectors') or 0) for item in endpoint_summary)
    pipeline_failed_actions = sum(
        1 for item in public_coverage or []
        if str(item.get('tool') or '').strip().lower() not in _EVIDENCE_ACTION_META_TOOLS
        and str(item.get('lifecycle_state') or '').strip().lower() in {'executed_failed', 'executed_timeout', 'assurance_failure'}
    )
    summary = {
        'endpoints': len(endpoint_summary),
        'applicable_actions': sum(int(item.get('applicable_collectors') or 0) for item in endpoint_summary),
        'evidence_actions': sum(int(item.get('evidence_collectors') or 0) for item in endpoint_summary),
        # Keep the legacy field aligned with the overall scanner execution
        # lifecycle so the report cannot simultaneously claim 1 failure and 0.
        'failed_actions': max(endpoint_failed_actions, pipeline_failed_actions),
        'endpoint_failed_actions': endpoint_failed_actions,
        'pipeline_failed_actions': pipeline_failed_actions,
        'not_executed_actions': sum(int(item.get('not_executed_collectors') or 0) for item in endpoint_summary),
        'host_lifecycle_actions': len(host_lifecycle),
        'lifecycle_counts': lifecycle_counts,
    }
    return {'endpoint_rows': rows, 'endpoint_summary': endpoint_summary, 'host_lifecycle': host_lifecycle, 'summary': summary}


def _build_unresolved_identity_queue(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for service in services or []:
        product = str(service.get('product') or '').strip()
        version = str(service.get('version') or '').strip()
        service_name = str(service.get('service') or '').strip()
        gaps: list[str] = []
        if not service_name or service_name.lower() == 'unknown':
            gaps.append('Service protocol/application name unresolved')
        if not product:
            gaps.append('Product identity not established')
        if product and not version:
            gaps.append('Exact product version not established')
        elif version and _observed_version_is_range(version):
            gaps.append('Only a version range was observed')
        if not gaps:
            continue
        sources = [str(x) for x in service.get('evidence_sources') or [] if str(x)]
        rows.append({
            'host': service.get('host'), 'port': service.get('port'), 'protocol': service.get('protocol'),
            'service': service_name, 'product': product, 'version': version,
            'gaps': gaps, 'recovery_attempted': any(('version_recovery' in x or 'adaptive_evidence_recovery_' in x) for x in sources),
            'evidence_sources': sources,
        })
    return rows


def _build_pentester_summary(results: dict[str, Any]) -> list[str]:
    """Short report summary derived from scanner evidence; no proprietary scoring."""
    points: list[str] = []
    passive = results.get('passive_intelligence') or {}
    if passive.get('summary'):
        points.extend([str(x).rstrip('.') + '.' for x in passive.get('summary')[:2]])
    all_refs = list(results.get('cve_matches') or [])
    if all_refs:
        products: list[str] = []
        for c in all_refs:
            label = f"{c.get('product','').strip()} {c.get('version','').strip()}".strip()
            if label and label not in products:
                products.append(label)
        if products:
            points.append('CVE product/version references were linked to: ' + ', '.join(products[:8]) + ('.' if len(products) <= 8 else '; and additional observed identities.'))
    conditions = results.get('observed_security_conditions') or []
    if conditions:
        labels: list[str] = []
        for row in conditions:
            label = str(row.get('condition') or row.get('check') or '').strip()
            if label and label not in labels:
                labels.append(label)
        if labels:
            points.append('Direct security/protocol observations were retained for: ' + '; '.join(labels[:8]) + ('.' if len(labels) <= 8 else '; and additional checks.'))
    services = results.get('service_inventory') or []
    exposed_ports = {
        f"{s.get('port')}/{s.get('protocol')}" for s in services
        if s.get('port') and s.get('protocol')
    }
    if exposed_ports:
        points.append(f'The target presented {len(exposed_ports)} observed service endpoints across TCP/UDP evidence collection.')
    return points[:4]


def _start_cve_prefetch(scan_id: str, services: list[dict[str, Any]]) -> tuple[threading.Thread | None, dict[str, Any]]:
    holder: dict[str, Any] = {'ready': False, 'matches': []}
    if not services or not mitre_status().get('available'):
        return None, holder
    snapshot = [dict(s) for s in services]
    def worker() -> None:
        try:
            matches, _ = _match_cves(snapshot)
            holder.update({'ready': True, 'matches': matches})
            _publish_partial(scan_id, cve_matches=matches, cve_review_status='CVE review started')
        except Exception as exc:
            holder.update({'ready': True, 'error': str(exc)})
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return thread, holder

def _text_has_ssh_audit_evidence(text: str) -> bool:
    """Detect whether ssh-audit output contains usable recommendation/finding text."""
    value = str(text or '').strip().lower()
    if not value:
        return False
    markers = ('(rec)', 'algorithm to remove', 'key algorithm', 'enc algorithm', 'kex algorithm', 'mac algorithm', 'warning', 'fail', 'remove')
    return any(marker in value for marker in markers)


def _sanitize_hydra_combo_file(path: str) -> str:
    """Create a Hydra -C compatible combo file without invoking Hydra."""
    source = Path(path)
    if not source.exists():
        return ''

    valid: list[str] = []
    try:
        for line in source.read_text(encoding='utf-8', errors='ignore').splitlines():
            item = line.strip()
            if not item or item.startswith('#') or ':' not in item:
                continue
            user, password = item.split(':', 1)
            user = user.strip()
            password = password.strip()
            if not user or not password:
                continue
            valid.append(f'{user}:{password}')
    except OSError:
        return ''

    if not valid:
        return ''

    seen: set[str] = set()
    clean = []
    for item in valid:
        if item not in seen:
            seen.add(item)
            clean.append(item)

    out = scan_store.scan_path('hydra_combo_autopentest_sanitized.txt')
    out.write_text('\n'.join(clean) + '\n', encoding='utf-8')
    return str(out)


def _credential_combo_file() -> str:
    """Return a sanitized credential combo file for downstream validators."""
    configured = os.getenv('HYDRA_CREDENTIAL_FILE', '').strip()
    candidates = []
    if configured:
        candidates.append(configured)
    candidates.extend([
        '/usr/share/seclists/Passwords/Default-Credentials/default_credentials_for_services_unhashed.txt',
        '/usr/share/seclists/Passwords/Default-Credentials/default_credentials_for_services.txt',
        '/usr/share/seclists/Passwords/Common-Credentials/top-20.txt',
    ])
    packaged = Path(__file__).resolve().parents[1] / 'wordlists' / 'default_credentials_autopentest.txt'
    candidates.append(str(packaged))

    for item in candidates:
        candidate = Path(item)
        if candidate.exists() and candidate.stat().st_size > 0:
            sanitized = _sanitize_hydra_combo_file(str(candidate))
            if sanitized:
                return sanitized
    return ''


# Recon ownership boundary: the helpers above only prepare a sanitized combo
# file for compatibility/downstream validators. The recon pipeline does not run
# Hydra, brute force, or password attempts.


def run_pipeline(scan_id: str, target_input: str, scan_options: dict[str, Any] | None = None) -> None:
    _token = _CURRENT_SCAN_ID.set(scan_id)
    try:
        scan_store.log(scan_id, f"Pipeline started for target={target_input}")
    except Exception:
        pass
    incoming_options = dict(scan_options or {})
    incoming_ports = incoming_options.get('port_selection') or {}
    incoming_tcp = incoming_ports.get('tcp') or {}
    incoming_udp = incoming_ports.get('udp') or {}
    scan_options = normalise_scan_options(
        incoming_options.get('profile', 'full'),
        incoming_options.get('enabled_tools'),
        tcp_port_mode=incoming_tcp.get('mode'),
        tcp_custom_ports=incoming_tcp.get('custom_spec'),
        udp_port_mode=incoming_udp.get('mode'),
        udp_custom_ports=incoming_udp.get('custom_spec'),
        advanced_settings=incoming_options.get('advanced_settings') or {},
        collection_preset=incoming_options.get('collection_preset'),
        collector_plan=incoming_options.get('collector_plan') or None,
        host_discovery_settings=incoming_options.get('host_discovery') or None,
        service_identity_settings=incoming_options.get('service_identity') or None,
    )
    if incoming_options.get('technique_mode'):
        scan_options['technique_mode'] = incoming_options.get('technique_mode')
    workflow_context = incoming_options.get('workflow_context') or {}
    if isinstance(workflow_context, dict) and workflow_context:
        scan_options['workflow_context'] = dict(workflow_context)
    pivot_assessment_targets = _register_pivot_targets(
        scan_id,
        (scan_options.get('workflow_context') or {}).get('pivot_targets') or [],
    )
    if pivot_assessment_targets:
        scan_options['workflow_context']['pivot_transport'] = {
            'type': 'socks_proxy',
            'targets': sorted(pivot_assessment_targets),
            'tcp_connect_only': True,
            'raw_ip_udp_l2_not_applicable': True,
        }
    scan_store.update(scan_id, scan_options=scan_options)
    if scan_options.get('validation_errors'):
        message = '; '.join(scan_options.get('validation_errors') or [])
        scan_store.log(scan_id, f'Scan settings rejected before target interaction: {message}', 'ERROR')
        scan_store.update(scan_id, status=scan_store.STATUS_FAILED, error=message, completed_at=scan_store.now())
        scan_store.persist(scan_id)
        _clear_pivot_targets(scan_id)
        return
    def enabled(tool_id: str) -> bool:
        return is_tool_enabled(scan_options, tool_id)
    existing_tasks = (scan_store.get(scan_id) or {}).get('tasks') or []
    if existing_tasks:
        scan_store.append_tasks(scan_id, TASKS, phase='assessment')
    else:
        scan_store.init_tasks(scan_id, TASKS, phase='assessment')
    if scan_options.get('policy_status') != 'loaded':
        message = f"Recon policy is {scan_options.get('policy_status')}; scan stopped before target interaction."
        scan_store.log(scan_id, message, 'ERROR')
        scan_store.update(scan_id, status=scan_store.STATUS_FAILED, error=message, completed_at=scan_store.now())
        scan_store.persist(scan_id)
        _clear_pivot_targets(scan_id)
        return
    if scan_options.get('policy_conflicts'):
        scan_store.log(
            scan_id,
            'Policy conflicts resolved with explicit disablement taking precedence: '
            + ', '.join(scan_options.get('policy_conflicts') or []),
            'WARN',
        )
        scan_store.audit_event(scan_id, 'system', 'policy_conflicts_resolved', {
            'resolution': scan_options.get('policy_resolution'),
            'disabled_tools': scan_options.get('policy_conflicts') or [],
            'policy_sha256': scan_options.get('effective_policy_sha256'),
        })
    preflight_readiness = build_selected_plan_readiness(
        scan_options=scan_options,
        cve_source_status=mitre_status(),
        storage_paths=(scan_store.SCANS_DIR, scan_store.RESULTS_DIR),
        nse_preflight=nse_script_preflight,
    )
    _publish_partial(
        scan_id,
        selected_plan_readiness=preflight_readiness,
        result_state='core_tool_unavailable' if preflight_readiness.get('launch_blocked') else 'preflight_ready',
    )
    if preflight_readiness.get('launch_blocked'):
        message = (
            'Selected scan plan cannot start because required scanner components are unavailable: '
            + ', '.join(preflight_readiness.get('blocking_components') or [])
        )
        scan_store.log(scan_id, message, 'ERROR')
        scan_store.update(
            scan_id,
            status=scan_store.STATUS_FAILED,
            error=message,
            completed_at=scan_store.now(),
        )
        scan_store.persist(scan_id)
        _clear_pivot_targets(scan_id)
        return
    coverage=[]; raw=[]; observations=[]; web=[]; smb=[]; services=[]; udp_services=[]; udp_discovery_rows=[]; evidence_recovery_history=[]; service_level_checks=[]; environment_intelligence=[]; environment_context_indicators=[]; selected_objectives=[]; evidence_gaps=[]; scope_validation={}; enterprise_review_policy={}; passive_intelligence={}; modern_active_validation={}
    windows_patch_inventories: list[dict[str, Any]] = []
    windows_patch_assessments: list[dict[str, Any]] = []
    msrc_patch_diagnostics: list[dict[str, Any]] = []
    parser_warnings: list[dict[str, Any]] = []
    parser_warning_keys: set[tuple[str, str, str]] = set()
    discovery_evidence: dict[str, dict[str, list[dict[str, Any]]]] = {}
    firewall_posture_by_host: dict[str, dict[str, Any]] = {}
    requested_tcp_ports_by_host: dict[str, set[int]] = {}
    requested_udp_ports_by_host: dict[str, set[int]] = {}
    completed_tcp_ports_by_host: dict[str, set[int]] = {}
    completed_udp_ports_by_host: dict[str, set[int]] = {}
    endpoint_execution_batches: list[dict[str, Any]] = []
    requested_top_port_counts_by_host: dict[str, list[int]] = {}
    host_identity_map: dict[str, list[dict[str, Any]]] = {}

    def retain_parser_warnings(tool: str, path: str | Path, warnings: list[str], host: str = '', port: int | str = '') -> None:
        for warning in warnings or []:
            key = (tool, str(path), str(warning))
            if key in parser_warning_keys:
                continue
            parser_warning_keys.add(key)
            item = {'tool': tool, 'host': host, 'port': port, 'output_file': str(path), 'warning': str(warning)}
            parser_warnings.append(item)
            scan_store.log(scan_id, f'{tool} parser warning: {warning}', 'WARN')

    def parse_nmap_capture(
        path: str | Path,
        tool: str,
        host: str = '',
        port: int | str = '',
        protocol_hint: str = 'tcp',
        expect_ports: bool = True,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        parsed, warnings = parse_nmap_xml(path, protocol_hint=protocol_hint)
        if not expect_ports:
            warnings = [warning for warning in warnings if not warning.startswith('No ports found in output')]
        retain_parser_warnings(tool, path, warnings, host, port)
        merge_host_identity_map(
            host_identity_map,
            extract_host_identities_from_nmap(parsed, source=tool, evidence_reference=str(path)),
        )
        return list(parsed.get('services') or []), parsed

    def parse_httpx_capture(path: str | Path, host: str, port: int) -> list[dict[str, Any]]:
        rows, warnings = parse_httpx_jsonl(path)
        retain_parser_warnings('httpx', path, warnings, host, port)
        return rows

    def append_discovery_evidence(host: str, parsed: dict[str, Any], protocol_hint: str) -> None:
        target_data = discovery_evidence.setdefault(host, {'ports': [], 'extraports': []})
        for row in parsed.get('ports') or []:
            item = dict(row)
            item['host'] = item.get('host') or host
            item['protocol'] = item.get('protocol') or protocol_hint
            target_data['ports'].append(item)
        for row in parsed.get('extraports') or []:
            item = dict(row)
            item['host'] = item.get('host') or host
            item['protocol'] = item.get('protocol') or protocol_hint
            target_data['extraports'].append(item)
        pattern = detect_firewall_acl(target_data, host)
        if pattern is None:
            return
        current = firewall_posture_by_host.get(host)
        candidate = {'target': host, **pattern.to_dict()}
        if current is None or float(candidate.get('confidence') or 0.0) >= float(current.get('confidence') or 0.0):
            firewall_posture_by_host[host] = candidate
            scan_store.log(scan_id, f"Firewall posture for {host}: {pattern.description} Recommendation: {pattern.recommendation}", 'INFO')

    def acl_pause_requested(host: str) -> bool:
        guardrails = _policy_required(_load_recon_policy(), 'active_command_guardrails')
        return bool(
            firewall_posture_by_host.get(host)
            and guardrails.get('pause_on_environment_context_or_acl_indicator', False)
        )
    try:
        # 1
        task='Target Preparation'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        targets=expand_target_input(target_input, Config.MAX_EXPANDED_TARGETS)
        pivot_targets_current = _pivot_targets(scan_id).intersection(targets)
        direct_targets_current = [host for host in targets if host not in pivot_targets_current]
        engagement_policy = load_engagement_policy()
        enterprise_review_policy = load_enterprise_review_policy()
        scope_validation = validate_scope(targets, target_input, engagement_policy)
        scan_store.audit_event(scan_id, 'system', 'scope_validated', scope_validation)
        private_all=all(is_private_ip(t) for t in targets)
        scope_note = scope_validation.get('scope_mode', 'unknown')
        warning_note = '; '.join(scope_validation.get('warnings') or [])
        _finish(scan_id, task, scan_store.STATUS_SUCCESS, f'{len(targets)} target(s) accepted under {scope_note}. Private cyber-range addresses: {private_all}. {warning_note}')
        _publish_partial(scan_id, scope_validation=scope_validation)

        # Stage 0A: listen-only passive local inventory before any active validation.
        passive_local_inventory = _collect_passive_local_inventory(scan_id, coverage, raw, enabled, targets, scan_options)
        if passive_local_inventory.get('summary'):
            environment_intelligence.append({'type': 'passive_local_inventory', 'summary': passive_local_inventory.get('summary'), 'source': 'tshark_p0f_listen_only'})

        # Stage 0: explicit operator-controlled host/environment evidence.
        host_discovery_cfg = scan_options.get('host_discovery') or {}
        host_requested = host_discovery_cfg.get('requested') or {}
        host_effective = host_discovery_cfg.get('effective') or {}
        host_policy_blocked = set(host_discovery_cfg.get('policy_blocked') or [])
        # A pivot-only target was already observed during the operator-controlled
        # Phase 2 SOCKS enumeration. Retain that reachability evidence here rather
        # than attempting ICMP/L2/raw-IP probes that the SOCKS transport cannot carry.
        host_reachability_observed: set[str] = set(pivot_targets_current)

        task='Environment Characterisation'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        for host in targets:
            if host in pivot_targets_current:
                reason = f'{host}: retained Phase 2 SOCKS discovery evidence; this collector requires direct/raw-IP semantics and is not applicable through the pivot.'
                coverage.append(_coverage('ping', scan_store.STATUS_EMPTY, 'ICMP echo reachability and TTL evidence', reason, '', {'success': True, 'lifecycle_state': 'not_applicable', 'pivot_transport': 'socks_proxy'}))
                coverage.append(_coverage('dig', scan_store.STATUS_EMPTY, 'Reverse DNS / PTR evidence', reason, '', {'success': True, 'lifecycle_state': 'not_applicable', 'pivot_transport': 'socks_proxy'}))
                coverage.append(_coverage('route_trace', scan_store.STATUS_EMPTY, 'Bounded route-path evidence', reason, '', {'success': True, 'lifecycle_state': 'not_applicable', 'pivot_transport': 'socks_proxy'}))
                environment_intelligence.append({
                    'host': host,
                    'type': 'pivot_reachability',
                    'network_layer': _classify_network_layer(host),
                    'access_transport': 'socks_proxy',
                    'evidence_source': 'retained_phase2_discovery',
                })
                continue
            # ICMP echo is evidence only. Service discovery may still use -Pn,
            # therefore ICMP failure never suppresses an authorised target.
            if host_effective.get('icmp_echo'):
                ping_bin = which('ping')
                if ping_bin:
                    attempts = int(host_discovery_cfg.get('icmp_attempts') or 1)
                    timeout = int(host_discovery_cfg.get('icmp_timeout_seconds') or 2)
                    p = outfile('ping_ttl', host, 'txt')
                    r = run_cmd(command_builders.ping_echo(ping_bin, host, attempts, timeout), p, max(10, attempts * timeout + 5))
                    txt = Path(p).read_text(errors='ignore') if Path(p).exists() else ''
                    ttl = _extract_ttl(txt)
                    produced = bool(txt.strip())
                    r['lifecycle_state'] = execution_lifecycle(r, produced)
                    if r.get('success'):
                        host_reachability_observed.add(host)
                    environment_intelligence.append({'host':host,'type':'ttl_latency','ttl':ttl,'role_hint':_environment_role_hint(ttl),'network_layer':_classify_network_layer(host),'evidence_file':str(p)})
                    coverage.append(_coverage('ping', _status_from_result(r, produced), 'ICMP echo reachability and TTL evidence', f'{host} ttl={ttl if ttl is not None else "not observed"}; attempts={attempts}', str(p), r))
                    _add_raw(raw,'ping',host,'',str(p),'text',produced)
                else:
                    coverage.append(_coverage('ping', scan_store.STATUS_EMPTY, 'ICMP echo reachability and TTL evidence', 'ping binary is not available.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
            else:
                state = 'disabled_policy' if 'icmp_echo' in host_policy_blocked else 'disabled_operator'
                coverage.append(_coverage('ping', scan_store.STATUS_EMPTY, 'ICMP echo reachability and TTL evidence', 'ICMP echo was not executed.', '', {'success': True, 'lifecycle_state': state}))

            if host_effective.get('reverse_dns'):
                dig_bin = which('dig')
                if dig_bin:
                    p = outfile('reverse_dns', host, 'txt')
                    r = run_cmd(command_builders.dig_reverse(dig_bin, host, timeout_seconds=2, tries=1), p, 15)
                    txt = Path(p).read_text(errors='ignore') if Path(p).exists() else ''
                    produced = bool(txt.strip())
                    r['lifecycle_state'] = execution_lifecycle(r, produced)
                    coverage.append(_coverage('dig', _status_from_result(r, produced), 'Reverse DNS / PTR evidence', txt.strip() or 'No PTR answer observed.', str(p), r))
                    _add_raw(raw,'dig',host,'',str(p),'text',produced)
                else:
                    coverage.append(_coverage('dig', scan_store.STATUS_EMPTY, 'Reverse DNS / PTR evidence', 'dig binary is not available.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
            else:
                state = 'disabled_policy' if 'reverse_dns' in host_policy_blocked else 'disabled_operator'
                coverage.append(_coverage('dig', scan_store.STATUS_EMPTY, 'Reverse DNS / PTR evidence', 'Reverse DNS was not executed.', '', {'success': True, 'lifecycle_state': state}))

            if host_effective.get('route_trace'):
                traceroute_bin = which('traceroute')
                tracepath_bin = which('tracepath') if not traceroute_bin else None
                hops = int(host_discovery_cfg.get('route_max_hops') or 8)
                if traceroute_bin or tracepath_bin:
                    p = outfile('route_trace', host, 'txt')
                    cmd = command_builders.traceroute_path(traceroute_bin, host, hops) if traceroute_bin else command_builders.tracepath_path(tracepath_bin, host, hops)
                    r = run_cmd(cmd, p, max(20, hops * 2 + 5))
                    txt = Path(p).read_text(errors='ignore') if Path(p).exists() else ''
                    produced = bool(txt.strip())
                    r['lifecycle_state'] = execution_lifecycle(r, produced)
                    coverage.append(_coverage('route_trace', _status_from_result(r, produced), 'Bounded route-path evidence', f'Maximum hops requested: {hops}', str(p), r))
                    _add_raw(raw,'route_trace',host,'',str(p),'text',produced)
                else:
                    coverage.append(_coverage('route_trace', scan_store.STATUS_EMPTY, 'Bounded route-path evidence', 'Neither traceroute nor tracepath is available.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
            else:
                state = 'disabled_policy' if 'route_trace' in host_policy_blocked else 'disabled_operator'
                coverage.append(_coverage('route_trace', scan_store.STATUS_EMPTY, 'Bounded route-path evidence', 'Route tracing was not executed.', '', {'success': True, 'lifecycle_state': state}))

        _finish(scan_id, task, scan_store.STATUS_SUCCESS, 'Operator-selected environment characterisation processed')
        _publish_partial(scan_id, environment_summary=_build_environment_summary(environment_intelligence, environment_context_indicators))

        # Host availability evidence. These controls are independent from -Pn
        # service discovery so the operator can collect reachability evidence
        # without allowing ping filtering to hide authorised hosts.
        task='Host Availability Check'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        live=[]
        live_set: set[str] = set(host_reachability_observed)
        workflow_context = scan_options.get('workflow_context') or {}
        workflow_interface = str(workflow_context.get('route_interface') or '').strip()

        if host_effective.get('arp_discovery'):
            for host in sorted(pivot_targets_current):
                coverage.append(_coverage(
                    'arp-scan',
                    scan_store.STATUS_EMPTY,
                    'Scoped ARP reachability evidence',
                    f'{host}: ARP/L2 discovery is not applicable through the established SOCKS pivot; retained Phase 2 discovery evidence is used instead.',
                    '',
                    {'success': True, 'lifecycle_state': 'not_applicable', 'pivot_transport': 'socks_proxy'},
                ))
            arp_targets = [host for host in direct_targets_current if is_private_ip(host)]
            nonlocal_direct_targets = [host for host in direct_targets_current if host not in arp_targets]
            if nonlocal_direct_targets:
                coverage.append(_coverage(
                    'arp-scan',
                    scan_store.STATUS_EMPTY,
                    'Scoped ARP reachability evidence',
                    'ARP discovery is not applicable to non-private/direct targets: ' + ', '.join(nonlocal_direct_targets),
                    '',
                    {'success': True, 'lifecycle_state': 'not_applicable'},
                ))
            if arp_targets:
                arp_bin = which('arp-scan')
                if arp_bin:
                    # The arp-scan executable can carry CAP_NET_RAW/CAP_NET_ADMIN
                    # independently of the Python process. Execute it and report
                    # the actual terminal result rather than blocking solely on a
                    # parent-process raw-socket probe.
                    for host in arp_targets:
                        p=outfile('arp_scan',host,'txt')
                        r=run_cmd(command_builders.arp_scan(arp_bin, host, interface=workflow_interface),p,60)
                        text=Path(p).read_text(errors='ignore') if Path(p).exists() else ''
                        found=set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',text))
                        if host in found:
                            live_set.add(host)
                        command_ok = bool(r.get('success'))
                        produced = command_ok and host in found
                        stderr_text = ' '.join(str(r.get(key) or '') for key in ('stderr','error')).lower()
                        if not command_ok and any(token in stderr_text for token in ('permission denied','operation not permitted','must be root','cap_net_raw')):
                            r['lifecycle_state'] = 'insufficient_privilege'
                        else:
                            r['lifecycle_state'] = execution_lifecycle(r, produced)
                        if not command_ok:
                            note = f'{host}: ARP collector failed; stderr/exit evidence retained.'
                        else:
                            note = f'{host}: {"reply observed" if host in found else "no matching ARP reply retained"}'
                        coverage.append(_coverage('arp-scan', _status_from_result(r, produced), 'Scoped ARP reachability evidence', note, str(p), r))
                        _add_raw(raw,'arp-scan',host,'',str(p),'text',bool(text.strip()))
                else:
                    coverage.append(_coverage('arp-scan', scan_store.STATUS_EMPTY, 'Scoped ARP reachability evidence', 'arp-scan binary is not available.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
        else:
            state = 'disabled_policy' if 'arp_discovery' in host_policy_blocked else 'disabled_operator'
            coverage.append(_coverage('arp-scan', scan_store.STATUS_EMPTY, 'Scoped ARP reachability evidence', 'ARP discovery was not executed.', '', {'success': True, 'lifecycle_state': state}))

        if host_effective.get('nmap_host_discovery'):
            for host in sorted(pivot_targets_current):
                coverage.append(_coverage(
                    'nmap_host_discovery',
                    scan_store.STATUS_EMPTY,
                    'Nmap host availability evidence',
                    f'{host}: Nmap -sn is not applicable through a TCP SOCKS pivot; retained Phase 2 discovery evidence is used and Phase 3 continues with -Pn/-sT.',
                    '',
                    {'success': True, 'lifecycle_state': 'not_applicable', 'pivot_transport': 'socks_proxy'},
                ))
            nmap=which('nmap')
            if nmap and direct_targets_current:
                p=outfile('nmap_host_discovery',','.join(direct_targets_current),'xml')
                r=run_cmd(command_builders.nmap_host_discovery(nmap, direct_targets_current, p, interface=workflow_interface),p,600,True)
                _rows, host_discovery = parse_nmap_capture(p, 'nmap_host_discovery', expect_ports=False)
                nmap_live = [str(item.get('address')) for item in host_discovery.get('hosts') or [] if item.get('status') == 'up' and item.get('address')]
                live_set.update(nmap_live)
                r['lifecycle_state'] = execution_lifecycle(r, bool(nmap_live))
                coverage.append(_coverage('nmap_host_discovery', _status_from_result(r, bool(nmap_live)), 'Nmap host availability evidence', f'{len(nmap_live)} live direct host(s) found', str(p), r))
                _add_raw(raw,'nmap_host_discovery','','',str(p),'nmap_xml',bool(nmap_live))
            elif direct_targets_current and not nmap:
                coverage.append(_coverage('nmap_host_discovery', scan_store.STATUS_EMPTY, 'Nmap host availability evidence', 'nmap binary is not available.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
        else:
            state = 'disabled_policy' if 'nmap_host_discovery' in host_policy_blocked else 'disabled_operator'
            coverage.append(_coverage('nmap_host_discovery', scan_store.STATUS_EMPTY, 'Nmap host availability evidence', 'Nmap -sn host discovery was not executed.', '', {'success': True, 'lifecycle_state': state}))

        live = [host for host in targets if host in live_set]
        if not live and bool(host_discovery_cfg.get('assume_single_target_live', True)) and len(targets) == 1:
            live = list(targets)
            coverage.append(_coverage('host_availability_assumption', scan_store.STATUS_EMPTY, 'Scoped single-target continuation', 'No reachability collector established liveness; authorised service discovery will continue with -Pn and report reachability evidence separately.', '', {'success': True, 'lifecycle_state': 'assumed_live'}))
        elif not live and not host_effective.get('nmap_host_discovery'):
            # Multi-target scans still honour the explicit authorised target list.
            # -Pn service discovery is allowed to determine service reachability.
            live = list(targets)
            coverage.append(_coverage('host_availability_assumption', scan_store.STATUS_EMPTY, 'Authorised target continuation', 'Active Nmap host discovery was not selected; service discovery will continue against the authorised targets with -Pn.', '', {'success': True, 'lifecycle_state': 'assumed_live'}))

        _finish(scan_id, task, scan_store.STATUS_SUCCESS if live else scan_store.STATUS_EMPTY, f'{len(live)} host(s) selected for authorised enumeration')
        _publish_partial(scan_id, hosts=live)

        # 4 TCP port discovery
        task='Low-Impact Service Discovery'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        nmap=which('nmap'); open_map={h:[] for h in live}
        if enabled('tcp_discovery') and nmap and live:
            for host in live:
                # Category-A discovery: step through top-20 -> top-50 -> top-100 and evaluate after each pass.
                # This avoids a single obvious burst against Palo Alto Zone Protection/DoS policies.
                ttl_value = next((x.get('ttl') for x in environment_intelligence if x.get('host')==host and x.get('ttl') is not None), None)
                ports: list[int] = []
                host_environment_context: list[dict[str, Any]] = []
                policy = _load_recon_policy()
                posture = _scan_posture(host, environment_intelligence, ports)
                layer = posture.get('network_layer') or _classify_network_layer(host, environment_intelligence, ports)
                if layer.get('scan_posture') == 'infrastructure_observed' or posture.get('scan_posture') == 'infrastructure_observed':
                    # Infrastructure links/firewalls/routers: do not top-port sweep. Probe only management ports at near-zero rate.
                    operator_sequence = selected_ports(scan_options, 'tcp')
                    allowed_by_operator = None if isinstance(operator_sequence, range) else set(operator_sequence)
                    infra_values = [int(p) for p in _policy_required(posture, 'tcp_ports')]
                    if allowed_by_operator is not None:
                        infra_values = [p for p in infra_values if p in allowed_by_operator]
                    infra_ports = [str(p) for p in infra_values]
                    if not infra_ports:
                        coverage.append(_coverage('nmap_tcp_infrastructure_fingerprint', scan_store.STATUS_EMPTY, 'Operator port selection', 'No infrastructure-safe TCP ports overlap the operator-selected TCP coverage.', ''))
                        ports = []
                        continue
                    requested_tcp_ports_by_host.setdefault(host, set()).update(int(port) for port in infra_ports)
                    p = outfile('nmap_tcp_infrastructure_fingerprint', host, 'xml')
                    cmd = command_builders.nmap_infrastructure_discovery(nmap, host, [int(x) for x in infra_ports], list(_policy_required(posture, 'nmap_timing')), p)
                    advanced = scan_options.get('advanced_settings') or {}
                    r = _run_cmd_with_retry(
                        scan_id, cmd, p, int(advanced.get('command_timeout_seconds') or 600),
                        bool(advanced.get('retry_failed_batches', True)), int(advanced.get('retry_count') or 0)
                    )
                    rows, parsed_discovery = parse_nmap_capture(p, 'nmap_tcp_infrastructure_fingerprint', host)
                    execution_batch = analyse_nmap_port_batch(
                        host=host,
                        protocol='tcp',
                        requested_ports=(int(port) for port in infra_ports),
                        result=r,
                        parsed=parsed_discovery,
                    )
                    endpoint_execution_batches.append(execution_batch)
                    completed_tcp_ports_by_host.setdefault(host, set()).update(execution_batch['scanned_ports'])
                    r['lifecycle_state'] = execution_batch['lifecycle_state']
                    append_discovery_evidence(host, parsed_discovery, 'tcp')
                    ports = sorted({int(x['port']) for x in rows if x.get('port')})
                    coverage.append(_coverage('nmap_tcp_infrastructure_fingerprint', _status_from_result(r, bool(ports)), 'Infrastructure-safe TCP fingerprint', f'{len(ports)} management/service port(s) observed; application-layer collectors suppressed for {layer.get("role")}.', str(p), r))
                    _add_raw(raw, 'nmap_tcp_infrastructure_fingerprint', host, '', str(p), 'nmap_xml', True)
                    host_environment_context.append({'indicator':'infrastructure_scan_posture','evidence':f'{host} matched {layer.get("role")} ({layer.get("matched_cidr")}).','interpretation':'Target treated as router/firewall/infrastructure; application-layer enumeration suppressed.'})
                else:
                    # Operator-selected TCP coverage.  The UI chooses Full, Essentials,
                    # or Custom; policy still supplies the low-noise Nmap posture while
                    # advanced settings control batching/retries/parallel waves.
                    advanced = scan_options.get('advanced_settings') or {}
                    timeout_seconds = int(advanced.get('command_timeout_seconds') or 600)
                    retry_failed = bool(advanced.get('retry_failed_batches', True))
                    retry_count = int(advanced.get('retry_count') or 0)
                    batch_size = max(1, int(advanced.get('ports_per_batch') or 5))
                    parallel_enabled = bool(advanced.get('parallel_scanning', False))
                    parallel_workers = int(advanced.get('parallel_workers') or 1) if parallel_enabled else 1
                    selection = (scan_options.get('port_selection') or {}).get('tcp') or {}
                    selection_mode = str(selection.get('mode') or 'essentials')
                    selected_sequence = selected_ports(scan_options, 'tcp')
                    batches = _chunk_ports(selected_sequence, batch_size)
                    all_seen: set[int] = set()
                    micro_cfg = policy.get('tcp_micro_batching') or {}
                    timing = [x for x in list(micro_cfg.get('nmap_options') or ['-Pn', '-sS', '-T2', '--max-retries', '1']) if x != '--open']

                    scan_store.log(
                        scan_id,
                        f'TCP discovery mode={selection_mode} selected_ports={selection.get("count", len(selection.get("ports") or []))} '
                        f'batch_size={batch_size} parallel={parallel_enabled} workers={parallel_workers} timeout={timeout_seconds}s',
                        'INFO',
                    )

                    wave_width = max(1, parallel_workers)
                    for wave_start in range(0, len(batches), wave_width):
                        if acl_pause_requested(host):
                            coverage.append(_coverage('acl_adaptive_pause', scan_store.STATUS_EMPTY, 'Policy stop condition', f'Additional discovery batches paused for {host} after corroborated ACL behaviour.', ''))
                            break

                        wave = batches[wave_start:wave_start + wave_width]
                        jobs: list[tuple[int, list[int], Path, list[str]]] = []
                        for offset, clean_batch in enumerate(wave):
                            batch_index = wave_start + offset + 1
                            requested_tcp_ports_by_host.setdefault(host, set()).update(clean_batch)
                            out = outfile(f'nmap_tcp_batch_{batch_index}', host, 'xml')
                            cmd = command_builders.nmap_tcp_discovery(nmap, host, clean_batch, timing, out)
                            jobs.append((batch_index, clean_batch, out, cmd))

                        wave_results = _run_port_batch_wave(
                            scan_id,
                            jobs,
                            timeout_seconds=timeout_seconds,
                            retry_failed_batches=retry_failed,
                            retry_count=retry_count,
                            parallel_workers=parallel_workers,
                        )

                        for batch_index, clean_batch, out, r in wave_results:
                            rows, parsed_discovery = parse_nmap_capture(out, f'nmap_tcp_batch_{batch_index}', host)
                            execution_batch = analyse_nmap_port_batch(
                                host=host,
                                protocol='tcp',
                                requested_ports=clean_batch,
                                result=r,
                                parsed=parsed_discovery,
                            )
                            endpoint_execution_batches.append(execution_batch)
                            completed_tcp_ports_by_host.setdefault(host, set()).update(execution_batch['scanned_ports'])
                            r['lifecycle_state'] = execution_batch['lifecycle_state']
                            append_discovery_evidence(host, parsed_discovery, 'tcp')
                            batch_open = sorted({int(x['port']) for x in rows if x.get('port')})
                            all_seen.update(batch_open)
                            xml_text = Path(out).read_text(encoding='utf-8', errors='ignore') if Path(out).exists() else ''
                            filtered_count = sum(int(x) for x in re.findall(r'extraports state="filtered" count="(\d+)"', xml_text))
                            closed_count = sum(int(x) for x in re.findall(r'extraports state="closed" count="(\d+)"', xml_text))
                            combined_out = ' '.join(str(r.get(k) or '') for k in ('stdout', 'stderr', 'error'))
                            retransmission_warning = 'retransmission cap hit' in combined_out.lower() or 'giving up on port' in combined_out.lower()
                            cumulative_ports = sorted(all_seen)
                            profile = _host_profile_from_observations(host, cumulative_ports, environment_intelligence)
                            stage_indicators = _detect_environment_context_indicators(
                                cumulative_ports,
                                ttl=ttl_value,
                                filtered_count=filtered_count,
                                retransmission_warning=retransmission_warning,
                                host_profile=profile,
                            )
                            acl_indicator = _acl_filtering_indicator(host, filtered_count, closed_count, len(clean_batch))
                            if acl_indicator:
                                stage_indicators.append(acl_indicator)
                            coverage.append(_coverage(
                                f'nmap_tcp_batch_{batch_index}',
                                _status_from_result(r, bool(batch_open)),
                                f'TCP Discovery Batch {batch_index}',
                                f'{len(batch_open)} open TCP port(s) observed from {len(clean_batch)} operator-selected ports; '
                                f'{filtered_count} filtered/no-response; attempts={r.get("attempts", 1)}.',
                                str(out),
                                r,
                            ))
                            _add_raw(raw, f'nmap_tcp_batch_{batch_index}', host, '', str(out), 'nmap_xml', True)
                            if stage_indicators:
                                host_environment_context = stage_indicators

                        if acl_pause_requested(host):
                            coverage.append(_coverage('acl_adaptive_pause', scan_store.STATUS_EMPTY, 'Policy stop condition', f'Additional discovery batches paused for {host} after corroborated ACL behaviour.', ''))
                            break

                        min_sleep = float(micro_cfg.get('sleep_between_batches_seconds_min') or 0)
                        max_sleep = float(micro_cfg.get('sleep_between_batches_seconds_max') or min_sleep)
                        if wave_start + wave_width < len(batches) and max_sleep > 0:
                            time.sleep(random.uniform(min_sleep, max_sleep))

                    ports = sorted(all_seen)
                    coverage.append(_coverage(
                        'nmap_tcp_operator_selected',
                        scan_store.STATUS_SUCCESS if ports else scan_store.STATUS_EMPTY,
                        'TCP Service Discovery Summary',
                        f'{len(ports)} open TCP port(s) observed using {selection_mode} coverage; '
                        f'{selection.get("count", 0)} port(s) selected by operator.',
                        '',
                        {'success': True, 'cmd': 'operator-selected batched TCP discovery'},
                    ))
                if host_environment_context:
                    environment_context_indicators.extend([{**d,'host':host} for d in host_environment_context])
                    scan_store.log(scan_id, f'Environment context indicators observed on {host}; Full Recon continues high-value validation within policy.', 'INFO')
                # Port coverage is operator-owned. Do not add hidden policy expansion
                # ports after a Full/Essentials/Custom selection.
                expanded_ports = list(ports)
                coverage.append(_coverage(
                    'operator_tcp_coverage',
                    scan_store.STATUS_SUCCESS if expanded_ports else scan_store.STATUS_EMPTY,
                    'Operator-selected TCP coverage',
                    f'No hidden TCP expansion added; {len(expanded_ports)} open port(s) retained from the selected coverage.',
                    '',
                ))
                open_map[host] = expanded_ports
        elif not enabled('tcp_discovery'):
            scan_store.log(scan_id, 'TCP discovery was not selected for this scan.', 'INFO')
            coverage.append(_coverage('tcp_discovery', scan_store.STATUS_EMPTY, 'Operator-selected TCP discovery', 'TCP discovery was disabled by the operator.', '', {'success': True, 'lifecycle_state': 'disabled_operator'}))
        elif not nmap:
            coverage.append(_coverage('tcp_discovery', scan_store.STATUS_EMPTY, 'Operator-selected TCP discovery', 'nmap is not available for TCP discovery.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
        elif not live:
            coverage.append(_coverage('tcp_discovery', scan_store.STATUS_EMPTY, 'Operator-selected TCP discovery', 'No authorised target was available for TCP discovery.', '', {'success': True, 'lifecycle_state': 'not_applicable'}))
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if any(open_map.values()) else scan_store.STATUS_EMPTY, f'{sum(len(v) for v in open_map.values())} TCP port(s) observed')
        _publish_partial(
            scan_id,
            tcp_ports_observed=sum(len(v) for v in open_map.values()),
            firewall_posture=list(firewall_posture_by_host.values()),
            parser_warnings=parser_warnings,
        )

        # 5 service fingerprint
        task='Service Identity Collection'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        if enabled('service_fingerprint') and nmap:
            fingerprint_attempted = False
            for host, ports in open_map.items():
                if not ports:
                    continue
                fingerprint_attempted = True
                if acl_pause_requested(host):
                    coverage.append(_coverage('nmap_service_fingerprint', scan_store.STATUS_EMPTY, 'Policy stop condition', f'Service fingerprint follow-up paused for {host} after corroborated ACL behaviour.', ''))
                    continue
                host_environment_context_present = any(str(d.get('host')) == str(host) for d in environment_context_indicators)
                banner_ports = _critical_banner_ports(ports, environment_context_observed=host_environment_context_present)
                if not banner_ports:
                    coverage.append(_coverage('nmap_service_fingerprint', scan_store.STATUS_EMPTY, 'Suggested follow-up', 'No ports selected for banner-first service identity collection.', ''))
                    continue
                p=outfile('nmap_service_fingerprint',host,'xml'); port_arg=','.join(map(str,banner_ports))
                identity_cfg = scan_options.get('service_identity') or {}
                fingerprint_cmd = command_builders.nmap_service_fingerprint(
                    nmap, host, [], int(identity_cfg.get('version_intensity') or 0),
                    list(_policy_required(_load_recon_policy(), 'service_fingerprint_timing')), p,
                    banner_script=bool(identity_cfg.get('banner_script', True)), port_spec=port_arg,
                )
                fingerprint_timeout = max(1, int((scan_options.get('advanced_settings') or {}).get('command_timeout_seconds') or 600))
                r=run_cmd(fingerprint_cmd,p,fingerprint_timeout,True)
                rows, _parsed_fingerprint = parse_nmap_capture(p, 'nmap_service_fingerprint', host)
                services.extend(rows)
                skipped = sorted(set(ports) - set(banner_ports))
                note = f'{len(rows)} service row(s); critical-first banner set used'
                if skipped:
                    note += f'; {len(skipped)} port(s) retained for service-specific validation where applicable'
                coverage.append(_coverage('nmap_service_fingerprint', _status_from_result(r, bool(rows)), 'all observed service product version cpe', note, str(p), r)); _add_raw(raw,'nmap_service_fingerprint',host,'',str(p),'nmap_xml',True)
                if skipped:
                    coverage.append(_coverage('deferred_banner_ports', scan_store.STATUS_EMPTY, 'Service validation note', f'Non-banner service-specific validators will handle applicable ports: {", ".join(map(str, skipped[:20]))}', ''))
            if not fingerprint_attempted:
                coverage.append(_coverage('nmap_service_fingerprint', scan_store.STATUS_EMPTY, 'Service identity collection', 'No open TCP endpoint was available for service fingerprinting.', '', {'success': True, 'lifecycle_state': 'not_applicable'}))
        elif not enabled('service_fingerprint'):
            coverage.append(_coverage('nmap_service_fingerprint', scan_store.STATUS_EMPTY, 'Service identity collection', 'Service fingerprinting was disabled by the operator.', '', {'success': True, 'lifecycle_state': 'disabled_operator'}))
        else:
            coverage.append(_coverage('nmap_service_fingerprint', scan_store.STATUS_EMPTY, 'Service identity collection', 'nmap is not available for service fingerprinting.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if services else scan_store.STATUS_EMPTY, f'{len(services)} service record(s) extracted')
        _publish_partial(scan_id, service_inventory=services)

        # Cross-platform host OS identity. This collector does not assume an OS.
        # It reuses only TCP ports already inside the operator-authorised scope.
        os_plan_entry = (scan_options.get('collector_plan') or {}).get('nmap_os_identity') or {}
        if enabled('nmap_os_identity'):
            if not nmap:
                coverage.append(_coverage('nmap_os_identity', scan_store.STATUS_EMPTY, 'Cross-platform host OS fingerprint evidence', 'nmap is not available for active OS fingerprinting.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
            else:
                for host in live:
                    if host in pivot_targets_current:
                        coverage.append(_coverage(
                            'nmap_os_identity',
                            scan_store.STATUS_EMPTY,
                            'Cross-platform host OS fingerprint evidence',
                            f'{host}: active Nmap OS fingerprinting requires raw-IP packet semantics and is not applicable through the TCP SOCKS pivot.',
                            '',
                            {'success': True, 'lifecycle_state': 'not_applicable', 'pivot_transport': 'socks_proxy'},
                        ))
                        continue
                    open_ports = list(open_map.get(host) or [])
                    completed = set(completed_tcp_ports_by_host.get(host) or set())
                    non_open_candidates = sorted(completed - set(open_ports))
                    if not open_ports:
                        coverage.append(_coverage('nmap_os_identity', scan_store.STATUS_EMPTY, 'Cross-platform host OS fingerprint evidence', f'{host}: no observed open TCP endpoint was available for bounded OS fingerprinting.', '', {'success': True, 'lifecycle_state': 'not_applicable'}))
                        continue
                    # Nmap wants at least one open and one closed TCP port; a
                    # second closed port materially improves the closed-port
                    # probe set without widening authorised coverage.
                    probe_ports = list(dict.fromkeys(open_ports[:2] + non_open_candidates[:2]))
                    out = outfile('nmap_os_identity', host, 'xml')
                    timeout = int(collector_setting(scan_options.get('collector_plan') or {}, 'nmap_os_identity', 'timeout_seconds', 240) or 240)
                    before_count = len(host_identity_map.get(host) or [])
                    # OS fingerprinting uses its own timing profile. Reusing the
                    # service-fingerprint profile applied --scan-delay, which
                    # overrides Nmap's fixed inter-probe interval and corrupts
                    # the timing-derived SEQ tests that OS detection relies on.
                    _os_policy = _load_recon_policy()
                    _os_timing = list(
                        _os_policy.get('os_fingerprint_timing')
                        or _policy_required(_os_policy, 'service_fingerprint_timing')
                    )
                    cmd = command_builders.nmap_os_fingerprint(nmap, host, probe_ports, _os_timing, out)
                    r = run_cmd(cmd, out, timeout, True)
                    _rows, _parsed_os = parse_nmap_capture(out, 'nmap_os_identity', host, expect_ports=True)
                    produced = len(host_identity_map.get(host) or []) > before_count
                    r['lifecycle_state'] = execution_lifecycle(r, produced)
                    note = f'{host}: OS fingerprint attempted using {len(probe_ports)} already-authorised TCP port(s); no hidden port expansion.'
                    coverage.append(_coverage('nmap_os_identity', _status_from_result(r, produced), 'Cross-platform host OS fingerprint evidence', note, str(out), r))
                    _add_raw(raw, 'nmap_os_identity', host, '', str(out), 'nmap_xml', produced)
        else:
            state = 'disabled_policy' if os_plan_entry.get('policy_state') == 'blocked' else 'disabled_operator'
            coverage.append(_coverage('nmap_os_identity', scan_store.STATUS_EMPTY, 'Cross-platform host OS fingerprint evidence', 'Active OS fingerprinting was not executed.', '', {'success': True, 'lifecycle_state': state}))

        # 6 operator-selected UDP discovery. Full/Essentials/Custom uses the
        # same advanced batch, timeout, retry, and parallel controls as TCP.
        task='Low-Impact Service Discovery'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        if enabled('udp_discovery') and nmap:
            for host in live:
                if host in pivot_targets_current:
                    coverage.append(_coverage(
                        'udp_discovery',
                        scan_store.STATUS_EMPTY,
                        'Operator-selected UDP discovery',
                        f'{host}: UDP scanning is not applicable through the established TCP SOCKS pivot; no direct UDP traffic was sent.',
                        '',
                        {'success': True, 'lifecycle_state': 'not_applicable', 'pivot_transport': 'socks_proxy'},
                    ))
                    continue
                if acl_pause_requested(host):
                    coverage.append(_coverage('udp_discovery', scan_store.STATUS_EMPTY, 'Policy stop condition', f'UDP follow-up paused for {host} after corroborated ACL behaviour.', ''))
                    continue

                advanced = scan_options.get('advanced_settings') or {}
                timeout_seconds = int(advanced.get('command_timeout_seconds') or 600)
                retry_failed = bool(advanced.get('retry_failed_batches', True))
                retry_count = int(advanced.get('retry_count') or 0)
                batch_size = max(1, int(advanced.get('ports_per_batch') or 5))
                parallel_enabled = bool(advanced.get('parallel_scanning', False))
                parallel_workers = int(advanced.get('parallel_workers') or 1) if parallel_enabled else 1
                selection = (scan_options.get('port_selection') or {}).get('udp') or {}
                selection_mode = str(selection.get('mode') or 'essentials')
                batches = _chunk_ports(selected_ports(scan_options, 'udp'), batch_size)
                if not batches:
                    coverage.append(_coverage('udp_discovery', scan_store.STATUS_EMPTY, 'Operator port selection', 'No UDP ports were selected for discovery.', ''))
                    continue

                scan_store.log(
                    scan_id,
                    f'UDP discovery mode={selection_mode} selected_ports={selection.get("count", len(selection.get("ports") or []))} '
                    f'batch_size={batch_size} parallel={parallel_enabled} workers={parallel_workers} timeout={timeout_seconds}s',
                    'INFO',
                )
                wave_width = max(1, parallel_workers)
                host_udp_rows: list[dict[str, Any]] = []
                for wave_start in range(0, len(batches), wave_width):
                    if acl_pause_requested(host):
                        coverage.append(_coverage('acl_adaptive_pause_udp', scan_store.STATUS_EMPTY, 'Policy stop condition', f'Additional UDP discovery batches paused for {host} after corroborated ACL behaviour.', ''))
                        break
                    wave = batches[wave_start:wave_start + wave_width]
                    jobs: list[tuple[int, list[int], Path, list[str]]] = []
                    for offset, clean_batch in enumerate(wave):
                        batch_index = wave_start + offset + 1
                        requested_udp_ports_by_host.setdefault(host, set()).update(clean_batch)
                        out = outfile(f'nmap_udp_batch_{batch_index}', host, 'xml')
                        udp_timing = list(_policy_required(_scan_posture(host, environment_intelligence, open_map.get(host) or []), 'nmap_timing'))
                        cmd = command_builders.nmap_udp_discovery(nmap, host, clean_batch, udp_timing, out)
                        jobs.append((batch_index, clean_batch, out, cmd))

                    for batch_index, clean_batch, out, r_udp in _run_port_batch_wave(
                        scan_id, jobs, timeout_seconds=timeout_seconds,
                        retry_failed_batches=retry_failed, retry_count=retry_count,
                        parallel_workers=parallel_workers,
                    ):
                        rows_udp, parsed_udp = parse_nmap_capture(out, f'udp_discovery_batch_{batch_index}', host, protocol_hint='udp')
                        execution_batch = analyse_nmap_port_batch(
                            host=host,
                            protocol='udp',
                            requested_ports=clean_batch,
                            result=r_udp,
                            parsed=parsed_udp,
                        )
                        endpoint_execution_batches.append(execution_batch)
                        completed_udp_ports_by_host.setdefault(host, set()).update(execution_batch['scanned_ports'])
                        r_udp['lifecycle_state'] = execution_batch['lifecycle_state']
                        append_discovery_evidence(host, parsed_udp, 'udp')
                        udp_discovery_rows = merge_endpoint_observations(
                            udp_discovery_rows, parsed_udp.get('ports') or []
                        )
                        host_udp_rows.extend(rows_udp)
                        coverage.append(_coverage(
                            f'udp_discovery_batch_{batch_index}',
                            _status_from_result(r_udp, bool(rows_udp)),
                            f'UDP Discovery Batch {batch_index}',
                            f'{len(rows_udp)} UDP service row(s) observed from {len(clean_batch)} operator-selected ports; attempts={r_udp.get("attempts", 1)}.',
                            str(out),
                            r_udp,
                        ))
                        _add_raw(raw, f'udp_discovery_batch_{batch_index}', host, '', str(out), 'nmap_xml', bool(rows_udp))

                    micro_cfg = _load_recon_policy().get('tcp_micro_batching') or {}
                    min_sleep = float(micro_cfg.get('sleep_between_batches_seconds_min') or 0)
                    max_sleep = float(micro_cfg.get('sleep_between_batches_seconds_max') or min_sleep)
                    if wave_start + wave_width < len(batches) and max_sleep > 0:
                        time.sleep(random.uniform(min_sleep, max_sleep))

                udp_services.extend(host_udp_rows)
                coverage.append(_coverage(
                    'udp_operator_selected',
                    scan_store.STATUS_SUCCESS if host_udp_rows else scan_store.STATUS_EMPTY,
                    'UDP Discovery Summary',
                    f'{len(host_udp_rows)} UDP service row(s) observed using {selection_mode} coverage; '
                    f'{selection.get("count", 0)} port(s) selected by operator.',
                    '',
                ))
            _finish(scan_id, task, scan_store.STATUS_SUCCESS if udp_services else scan_store.STATUS_EMPTY, f'{len(udp_services)} UDP service row(s) observed')
        else:
            if not enabled('udp_discovery'):
                state, reason = 'disabled_operator', 'UDP discovery was disabled by the operator.'
            elif not nmap:
                state, reason = 'tool_unavailable', 'nmap is not available for UDP discovery.'
            elif not live:
                state, reason = 'not_applicable', 'No authorised target was available for UDP discovery.'
            else:
                state, reason = 'deferred', 'UDP discovery was deferred.'
            coverage.append(_coverage('udp_discovery', scan_store.STATUS_EMPTY, 'Operator-selected UDP discovery', reason, '', {'success': True, 'lifecycle_state': state}))
            _finish(scan_id, task, scan_store.STATUS_EMPTY, reason)

        _publish_partial(
            scan_id,
            firewall_posture=list(firewall_posture_by_host.values()),
            parser_warnings=parser_warnings,
        )

        all_services=services + udp_services
        # Adaptive evidence recovery is driven only by unresolved observed facts,
        # operator-normalised bounds, and already-authorised endpoints. It never
        # adds ports, assumes a product, or searches for a CVE. UDP open|filtered
        # endpoints remain uncertain unless follow-up evidence changes the state.
        recovery_cfg = (_load_recon_policy().get('version_evidence_recovery') or {})
        identity_cfg = scan_options.get('service_identity') or {}
        recovery_planning_rows = merge_endpoint_observations(all_services, udp_discovery_rows)
        recovery_before = recovery_snapshot(recovery_planning_rows)
        recovery_enabled = bool(
            enabled('service_fingerprint')
            and nmap
            and identity_cfg.get('version_recovery', recovery_cfg.get('enabled', True))
            and identity_cfg.get('adaptive_evidence_recovery', True)
        )
        include_uncertain_udp_recovery = False
        uncertain_udp_recovery_limit = 0
        recovery_budget_exhausted = False
        if recovery_enabled:
            initial_intensity = max(0, min(9, int(identity_cfg.get('version_intensity') or 0)))
            recovery_target = max(0, min(9, int(identity_cfg.get('recovery_intensity', recovery_cfg.get('nmap_version_intensity') or initial_intensity))))
            recovery_attempts = max(1, min(4, int(identity_cfg.get('recovery_attempts') or 1)))
            intensity_ladder = recovery_intensity_ladder(initial_intensity, recovery_target, recovery_attempts)
            max_ports = max(1, min(256, int(identity_cfg.get('recovery_max_ports', recovery_cfg.get('max_ports_per_host') or 64))))
            advanced_recovery = scan_options.get('advanced_settings') or {}
            recovery_timeout = max(1, int(advanced_recovery.get('command_timeout_seconds') or 600))
            recovery_batch_size = max(1, int(advanced_recovery.get('ports_per_batch') or 5))
            recovery_timing = list(_policy_required(_load_recon_policy(), 'service_fingerprint_timing'))
            udp_recovery_enabled = bool(identity_cfg.get('udp_evidence_recovery', True))
            include_uncertain_udp_recovery = bool(
                identity_cfg.get(
                    'recover_uncertain_udp',
                    recovery_cfg.get('include_uncertain_udp', False),
                )
            )
            uncertain_udp_recovery_limit = max(
                0,
                min(256, int(recovery_cfg.get('uncertain_udp_max_ports') or 0)),
            )
            tcp_recovery_timeout = max(
                1,
                min(
                    recovery_timeout,
                    int(recovery_cfg.get('tcp_command_timeout_seconds') or recovery_timeout),
                ),
            )
            udp_recovery_timeout = max(
                1,
                min(
                    recovery_timeout,
                    int(recovery_cfg.get('udp_command_timeout_seconds') or min(recovery_timeout, 45)),
                ),
            )
            recovery_budget_seconds = max(
                1,
                int(recovery_cfg.get('recovery_budget_seconds') or 120),
            )
            recovery_started = time.monotonic()
            retry_failed_recovery = bool(advanced_recovery.get('retry_failed_batches', True))
            retry_count_recovery = max(0, int(advanced_recovery.get('retry_count') or 0))
            recovery_parallel_enabled = bool(advanced_recovery.get('parallel_scanning', False))
            recovery_parallel_workers = (
                max(1, int(advanced_recovery.get('parallel_workers') or 1))
                if recovery_parallel_enabled else 1
            )

            def recovery_budget_remaining() -> float:
                return float(recovery_budget_seconds) - (time.monotonic() - recovery_started)

            for pass_index, intensity in enumerate(intensity_ladder, start=1):
                attempted_this_pass = 0
                for protocol in ('tcp', 'udp'):
                    if recovery_budget_remaining() <= 0:
                        recovery_budget_exhausted = True
                        break
                    if protocol == 'udp' and not udp_recovery_enabled:
                        continue
                    if protocol == 'tcp':
                        source_rows = [row for row in all_services if str(row.get('protocol') or '').lower() == 'tcp']
                    else:
                        source_rows = merge_endpoint_observations(
                            [row for row in all_services if str(row.get('protocol') or '').lower() == 'udp'],
                            udp_discovery_rows,
                        )
                    candidates = recovery_candidates(
                        source_rows,
                        protocol=protocol,
                        include_uncertain_udp=(protocol == 'udp' and include_uncertain_udp_recovery),
                        uncertain_udp_limit=uncertain_udp_recovery_limit,
                    )
                    candidates_by_host: dict[str, list[dict[str, Any]]] = {}
                    for candidate in candidates:
                        candidates_by_host.setdefault(str(candidate.get('host') or ''), []).append(candidate)

                    for recovery_host, host_candidates in sorted(candidates_by_host.items()):
                        if recovery_budget_remaining() <= 0:
                            recovery_budget_exhausted = True
                            break
                        if not recovery_host or acl_pause_requested(recovery_host):
                            if recovery_host:
                                evidence_recovery_history.append({
                                    'host': recovery_host, 'protocol': protocol, 'pass': pass_index,
                                    'intensity': intensity, 'status': 'paused_acl_policy',
                                    'attempted_ports': [],
                                })
                            continue
                        selected = sorted({int(row.get('port') or 0) for row in host_candidates if int(row.get('port') or 0) > 0})
                        recovery_batches = recovery_port_batches(selected, max_ports=max_ports, batch_size=recovery_batch_size)
                        if not recovery_batches:
                            continue
                        tool_id = f'adaptive_evidence_recovery_{protocol}_pass_{pass_index}'
                        jobs: list[tuple[int, list[int], Path, list[str]]] = []
                        missing_by_batch: dict[int, dict[str, list[str]]] = {}
                        for batch_index, recovery_ports in enumerate(recovery_batches, start=1):
                            attempted_this_pass += len(recovery_ports)
                            missing_by_batch[batch_index] = {
                                str(int(row.get('port') or 0)): list(row.get('recovery_missing_evidence') or [])
                                for row in host_candidates
                                if int(row.get('port') or 0) in recovery_ports
                            }
                            output_path = outfile(f'{tool_id}_batch_{batch_index}', recovery_host, 'xml')
                            command = command_builders.nmap_service_fingerprint(
                                nmap, recovery_host, recovery_ports, intensity, recovery_timing, output_path,
                                banner_script=bool(identity_cfg.get('banner_script', True)),
                                protocol=protocol,
                            )
                            jobs.append((batch_index, recovery_ports, output_path, command))

                        remaining_budget = recovery_budget_remaining()
                        if remaining_budget <= 0:
                            recovery_budget_exhausted = True
                            break
                        protocol_timeout = tcp_recovery_timeout if protocol == 'tcp' else udp_recovery_timeout
                        bounded_timeout = max(1, min(protocol_timeout, int(max(1.0, remaining_budget))))
                        wave_results = _run_port_batch_wave(
                            scan_id,
                            jobs,
                            timeout_seconds=bounded_timeout,
                            retry_failed_batches=retry_failed_recovery,
                            retry_count=retry_count_recovery,
                            parallel_workers=recovery_parallel_workers,
                        )

                        for batch_index, recovery_ports, output_path, result in wave_results:
                            recovered_rows, recovered_parsed = parse_nmap_capture(
                                output_path, tool_id, recovery_host, protocol_hint=protocol
                            )
                            append_discovery_evidence(recovery_host, recovered_parsed, protocol)
                            parsed_ports = list(recovered_parsed.get('ports') or [])
                            if protocol == 'udp':
                                udp_discovery_rows = merge_endpoint_observations(udp_discovery_rows, parsed_ports)
                                confirmed_rows = [row for row in parsed_ports if str(row.get('state') or '').lower() == 'open']
                            else:
                                confirmed_rows = list(recovered_rows)
                            all_services = _merge_service_identity_rows(all_services, confirmed_rows, tool_id)

                            additional_evidence = [
                                row for row in parsed_ports
                                if str(row.get('state') or '').lower() == 'open'
                                or str(row.get('product') or '').strip()
                                or (str(row.get('version') or '').strip() and not _observed_version_is_range(str(row.get('version') or '')))
                            ]
                            produced = bool(additional_evidence)
                            result['lifecycle_state'] = execution_lifecycle(result, produced)
                            unresolved_after = recovery_candidates(
                                merge_endpoint_observations(
                                    [row for row in all_services if str(row.get('protocol') or '').lower() == protocol],
                                    udp_discovery_rows if protocol == 'udp' else [],
                                ),
                                protocol=protocol,
                                include_uncertain_udp=(protocol == 'udp' and include_uncertain_udp_recovery),
                                uncertain_udp_limit=uncertain_udp_recovery_limit,
                            )
                            unresolved_keys = {
                                (str(row.get('host') or ''), int(row.get('port') or 0))
                                for row in unresolved_after
                            }
                            remaining_batch = sum(
                                1 for port in recovery_ports if (recovery_host, int(port)) in unresolved_keys
                            )
                            evidence_recovery_history.append({
                                'host': recovery_host,
                                'protocol': protocol,
                                'pass': pass_index,
                                'batch': batch_index,
                                'intensity': intensity,
                                'attempted_ports': list(recovery_ports),
                                'missing_evidence_by_port': missing_by_batch.get(batch_index, {}),
                                'confirmed_open_rows': len(confirmed_rows),
                                'additional_evidence_rows': len(additional_evidence),
                                'remaining_unresolved_ports': remaining_batch,
                                'lifecycle_state': result.get('lifecycle_state'),
                                'output_file': str(output_path),
                                'timeout_seconds': bounded_timeout,
                            })
                            coverage.append(_coverage(
                                tool_id,
                                _status_from_result(result, produced),
                                f'Adaptive {protocol.upper()} identity evidence recovery',
                                f'Pass {pass_index}/{len(intensity_ladder)}, batch {batch_index}/{len(recovery_batches)}, used Nmap version intensity {intensity} on {len(recovery_ports)} already-selected {protocol.upper()} endpoint(s) with unresolved identity/state evidence; no new port coverage was added; {remaining_batch} endpoint(s) in this batch remained unresolved.',
                                str(output_path),
                                result,
                            ))
                            _add_raw(raw, tool_id, recovery_host, '', str(output_path), 'nmap_xml', produced)

                    if recovery_budget_exhausted:
                        break
                if recovery_budget_exhausted or attempted_this_pass == 0:
                    break

            if recovery_budget_exhausted:
                elapsed = max(0.0, time.monotonic() - recovery_started)
                evidence_recovery_history.append({
                    'status': 'recovery_budget_exhausted',
                    'budget_seconds': recovery_budget_seconds,
                    'elapsed_seconds': round(elapsed, 3),
                })
                coverage.append(_coverage(
                    'adaptive_evidence_recovery_budget',
                    scan_store.STATUS_EMPTY,
                    'Adaptive evidence recovery budget',
                    f'Recovery budget of {recovery_budget_seconds} second(s) was exhausted; unresolved endpoint evidence remains reported as unresolved.',
                    '',
                    {'success': True, 'lifecycle_state': 'deferred'},
                ))

        recovery_planning_rows = merge_endpoint_observations(all_services, udp_discovery_rows)
        remaining_recovery_endpoints: list[dict[str, Any]] = []
        for protocol in ('tcp', 'udp'):
            for row in recovery_candidates(
                recovery_planning_rows,
                protocol=protocol,
                include_uncertain_udp=(protocol == 'udp' and include_uncertain_udp_recovery),
                uncertain_udp_limit=uncertain_udp_recovery_limit,
            ):
                remaining_recovery_endpoints.append({
                    'host': str(row.get('host') or ''),
                    'port': int(row.get('port') or 0),
                    'protocol': protocol,
                    'state': str(row.get('state') or ''),
                    'service': str(row.get('service') or ''),
                    'missing_evidence': list(row.get('recovery_missing_evidence') or []),
                })
        evidence_recovery_summary = {
            'enabled': recovery_enabled,
            'udp_enabled': bool(identity_cfg.get('udp_evidence_recovery', True)) if recovery_enabled else False,
            'initial_version_intensity': int(identity_cfg.get('version_intensity') or 0),
            'recovery_intensity': int(identity_cfg.get('recovery_intensity', recovery_cfg.get('nmap_version_intensity') or 0)),
            'configured_attempts': int(identity_cfg.get('recovery_attempts') or 1),
            'ports_per_batch': int((scan_options.get('advanced_settings') or {}).get('ports_per_batch') or 5),
            'uncertain_udp_recovery_enabled': bool(include_uncertain_udp_recovery) if recovery_enabled else False,
            'uncertain_udp_recovery_limit': int(uncertain_udp_recovery_limit) if recovery_enabled else 0,
            'budget_exhausted': bool(recovery_budget_exhausted) if recovery_enabled else False,
            'before': recovery_before,
            'after': recovery_snapshot(recovery_planning_rows),
            'remaining_unresolved_endpoints': remaining_recovery_endpoints,
            'history': evidence_recovery_history,
            'rule': 'Only already-selected endpoints with unresolved observed evidence are re-probed; no target/product/CVE facts are inferred.',
        }
        _publish_partial(scan_id, evidence_recovery=evidence_recovery_summary)

        selected_objectives = infer_objectives(all_services)
        preliminary_report = {
            'status': 'preliminary',
            'target_input': target_input,
            'observed_hosts': live,
            'observed_services': len(all_services),
            'attack_surface_objectives': selected_objectives,
            'environment_summary': _build_environment_summary(environment_intelligence, environment_context_indicators),
            'network_topology_summary': _build_network_topology_summary(live, environment_intelligence, open_map, environment_context_indicators),
        }
        _publish_partial(scan_id, service_inventory=all_services, preliminary_report=preliminary_report, attack_surface_objectives=selected_objectives, environment_summary=preliminary_report['environment_summary'], network_topology_summary=preliminary_report.get('network_topology_summary'))
        _finish(scan_id, 'Preliminary Attack Surface Report', scan_store.STATUS_SUCCESS, f'{len(selected_objectives)} attack-surface objective(s) selected from observed services')
        plan_entries = scan_options.get('collector_plan') or {}
        capability_recovery_plan: list[dict[str, Any]] = []
        for service in all_services:
            missing_types = missing_evidence_types(service)
            if not missing_types:
                continue
            for collector_id, plan_entry in sorted(plan_entries.items()):
                if not plan_entry.get('effective_enabled'):
                    continue
                if not _collector_service_applicable(plan_entry, service):
                    continue
                produces = {str(value) for value in plan_entry.get('produces') or [] if str(value)}
                relevant = sorted(produces & missing_types)
                if not relevant or not collector_needed(plan_entry, service):
                    continue
                capability_recovery_plan.append({
                    'host': str(service.get('host') or ''),
                    'port': int(service.get('port') or 0),
                    'protocol': str(service.get('protocol') or ''),
                    'collector': collector_id,
                    'missing_evidence': relevant,
                    'selection_basis': 'enabled collector capability intersects unresolved observed evidence',
                })
        evidence_recovery_summary['collector_capability_plan'] = capability_recovery_plan
        _publish_partial(scan_id, evidence_recovery=evidence_recovery_summary)

        def collector_surfaces(tool_id: str, fallback_families: list[str] | None = None) -> list[dict[str, Any]]:
            # Applicability is driven by observed service/product evidence, not a
            # fixed port in scanner code. Policy registries may still provide
            # common-port hints for initial identification, but arbitrary ports
            # work once their service identity is observed.
            entry = dict(plan_entries.get(tool_id) or {})
            if not entry and fallback_families:
                entry = {'scope': 'service', 'families': list(fallback_families), 'mode': 'auto'}
            # AUTO means service-applicable, not silently optional. Capability
            # metadata is used by the recovery planner, but an operator-enabled
            # collector is not suppressed merely because another source already
            # filled one of its fields.
            return [row for row in all_services if _collector_service_applicable(entry, row)]

        def disabled_collector_state(tool_id: str) -> tuple[str, str]:
            entry = plan_entries.get(tool_id) or {}
            if entry.get('policy_state') == 'blocked':
                return 'disabled_policy', entry.get('policy_reason') or 'Collector disabled by effective recon policy.'
            return 'disabled_operator', 'Collector disabled by operator collection plan.'

        http_ports = collector_surfaces('http_security_context', ['http', 'https'])
        smb_ports = collector_surfaces('smb_protocol_security', ['smb', 'netbios'])

        # 7 HTTP
        task='Application Fingerprinting'
        scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        if not enabled('httpx'):
            state, reason = disabled_collector_state('httpx')
            coverage.append(_coverage('httpx', scan_store.STATUS_EMPTY, 'HTTP probe technology title status', reason, '', {'success': True, 'lifecycle_state': state}))
        elif not http_ports:
            coverage.append(_coverage('httpx', scan_store.STATUS_EMPTY, 'HTTP probe technology title status', 'No applicable HTTP/HTTPS service was observed.', '', {'success': True, 'lifecycle_state': 'not_applicable'}))
        else:
            httpx_bin = which('httpx-toolkit', ['httpx'])
            if not httpx_bin:
                coverage.append(_coverage('httpx', scan_store.STATUS_EMPTY, 'HTTP probe technology title status', 'ProjectDiscovery httpx is not available.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
            else:
                # Capability probe only; do not show this as a user-facing enumeration command.
                probe = _run_cmd(command_builders.httpx_help(httpx_bin), timeout=20)
                probe_text = (probe.get('stdout','') + probe.get('stderr','')).lower()
                compatible = ('-json' in probe_text or '-jsonl' in probe_text) and '-title' in probe_text and ('-tech-detect' in probe_text or '-td' in probe_text)
                if not compatible:
                    coverage.append(_coverage('httpx', scan_store.STATUS_EMPTY, 'HTTP probe technology title status', 'Installed httpx command is not ProjectDiscovery httpx or lacks the required flags.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
                else:
                    for row in http_ports:
                        host = str(row.get('host') or '')
                        port = int(row.get('port') or 0)
                        if _is_infrastructure_target(host, environment_intelligence, open_map.get(host, [])):
                            coverage.append(_coverage('httpx', scan_store.STATUS_EMPTY, 'HTTP probe technology title status', f'HTTP evidence deferred for infrastructure-like target {host}:{port}.', '', {'success': True, 'lifecycle_state': 'deferred'}))
                            continue
                        service_name = str(row.get('service') or '').lower()
                        url = _url_for(host, port, any(token in service_name for token in ('ssl','https','tls')))
                        p = outfile('httpx', f'{host}_{port}', 'jsonl')
                        httpx_opts = _policy_required(_load_recon_policy(), 'httpx_options')
                        plan = scan_options.get('collector_plan') or {}
                        requested_rate = int(collector_setting(plan, 'httpx', 'rate_limit_per_second', _policy_required(httpx_opts, 'rate_limit_per_second')) or 1)
                        requested_threads = int(collector_setting(plan, 'httpx', 'threads', _policy_required(httpx_opts, 'threads')) or 1)
                        requested_timeout = int(collector_setting(plan, 'httpx', 'timeout_seconds', _policy_required(httpx_opts, 'timeout_seconds')) or 5)
                        effective_rate = min(requested_rate, int(_policy_required(httpx_opts, 'rate_limit_per_second')))
                        effective_threads = min(requested_threads, int(_policy_required(httpx_opts, 'threads')))
                        effective_timeout = min(requested_timeout, max(1, int(_policy_required(httpx_opts, 'timeout_seconds'))))
                        httpx_cmd = command_builders.httpx_probe(httpx_bin, url, effective_rate, effective_threads, effective_timeout)
                        r = run_cmd(httpx_cmd, p, 180)
                        parsed_httpx = parse_httpx_capture(p, host, port)
                        web.extend(parsed_httpx)
                        produced = bool(parsed_httpx)
                        r['lifecycle_state'] = execution_lifecycle(r, produced)
                        coverage.append(_coverage('httpx', _status_from_result(r, produced), 'HTTP probe technology title status', url, str(p), r))
                        _add_raw(raw, 'httpx', host, port, str(p), 'jsonl', produced)

        _finish(scan_id, task, scan_store.STATUS_SUCCESS if web else scan_store.STATUS_EMPTY, f'{len(web)} web evidence item(s) captured')
        _publish_partial(scan_id, web_inventory=web)

        # 8 Credential/Web readiness evidence collection.
        # These collectors support teammate weak-credential and web-validation modules without
        # performing brute force, share/user enumeration, SQLi, command injection, or exploitation.
        task='Application Fingerprinting'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        service_level_checks = []
        ssh_items=[]; ssh_crypto_profiles=[]; ldap_items=[]; tls_items=[]; rdp_items=[]; credential_validation_items=[]; snmp=[]

        def _service_is_infra(row: dict[str, Any]) -> bool:
            return _is_infrastructure_target(str(row.get('host')), environment_intelligence, open_map.get(str(row.get('host')), []))

        # SSH readiness: advertised auth methods only; no login attempts.
        ssh_surfaces = collector_surfaces('ssh_auth_methods', ['ssh'])
        if not enabled('ssh_auth_methods'):
            state, reason = disabled_collector_state('ssh_auth_methods')
            coverage.append(_coverage('ssh_auth_methods', scan_store.STATUS_EMPTY, 'SSH advertised authentication-method evidence', reason, '', {'success': True, 'lifecycle_state': state}))
        elif not ssh_surfaces:
            coverage.append(_coverage('ssh_auth_methods', scan_store.STATUS_EMPTY, 'SSH advertised authentication-method evidence', 'No applicable SSH service was observed.', '', {'success': True, 'lifecycle_state': 'not_applicable'}))
        elif not nmap:
            coverage.append(_coverage('ssh_auth_methods', scan_store.STATUS_EMPTY, 'SSH advertised authentication-method evidence', 'nmap is not available for SSH authentication-method evidence.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
        else:
            for s in ssh_surfaces:
                host = str(s.get('host'))
                port = int(s.get('port') or 22)
                if _service_is_infra(s):
                    coverage.append(_coverage('ssh_auth_methods', scan_store.STATUS_EMPTY, 'SSH advertised authentication-method evidence', f'SSH auth-method readiness deferred for infrastructure-like target {host}.', '', {'success': True, 'lifecycle_state': 'deferred'}))
                    continue
                scripts = ','.join(_collector_scripts('ssh_auth_methods'))
                p = outfile('nmap_ssh_auth_methods', f'{host}_{port}', 'xml')
                ssh_timeout = int(collector_setting(plan_entries, 'ssh_auth_methods', 'timeout_seconds', 180) or 180)
                r = run_cmd(command_builders.nmap_nse_collector(nmap, host, port, scripts.split(','), list(_policy_required(_load_recon_policy(), 'nmap_script_timing')), p), p, ssh_timeout, True)
                rows, _parsed_ssh = parse_nmap_capture(p, 'ssh_auth_methods', host, port)
                service_level_checks.append({'tool':'ssh_auth_methods','host':host,'port':port,'output_file':str(p),'rows':rows})
                ssh_items.append({'tool':'ssh_auth_methods','host':host,'port':port,'output_file':str(p),'rows':rows})
                r['lifecycle_state'] = execution_lifecycle(r, bool(rows))
                coverage.append(_coverage('ssh_auth_methods', _status_from_result(r, bool(rows)), 'SSH advertised authentication-method evidence', f'{host}:{port}/tcp; no login attempt performed.', str(p), r))
                _add_raw(raw, 'ssh_auth_methods', host, port, str(p), 'nmap_xml', bool(rows))

        # FTP readiness: anonymous/system status only; no brute force.
        ftp_surfaces = collector_surfaces('ftp_anonymous_status', ['ftp'])
        if not enabled('ftp_anonymous_status'):
            state, reason = disabled_collector_state('ftp_anonymous_status')
            coverage.append(_coverage('ftp_anonymous_status', scan_store.STATUS_EMPTY, 'FTP anonymous/system readiness evidence', reason, '', {'success': True, 'lifecycle_state': state}))
        elif not ftp_surfaces:
            coverage.append(_coverage('ftp_anonymous_status', scan_store.STATUS_EMPTY, 'FTP anonymous/system readiness evidence', 'No applicable FTP service was observed.', '', {'success': True, 'lifecycle_state': 'not_applicable'}))
        elif not nmap:
            coverage.append(_coverage('ftp_anonymous_status', scan_store.STATUS_EMPTY, 'FTP anonymous/system readiness evidence', 'nmap is not available for FTP readiness evidence.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
        else:
            for s in ftp_surfaces:
                host = str(s.get('host'))
                port = int(s.get('port') or 0)
                if _service_is_infra(s):
                    coverage.append(_coverage('ftp_anonymous_status', scan_store.STATUS_EMPTY, 'FTP anonymous/system readiness evidence', f'FTP readiness deferred for infrastructure-like target {host}.', '', {'success': True, 'lifecycle_state': 'deferred'}))
                    continue
                scripts = ','.join(_collector_scripts('ftp_anonymous_status'))
                p = outfile('nmap_ftp_readiness', f'{host}_{port}', 'xml')
                ftp_timeout = int(collector_setting(plan_entries, 'ftp_anonymous_status', 'timeout_seconds', 180) or 180)
                r = run_cmd(command_builders.nmap_nse_collector(nmap, host, port, scripts.split(','), list(_policy_required(_load_recon_policy(), 'nmap_script_timing')), p), p, ftp_timeout, True)
                rows, _parsed_ftp = parse_nmap_capture(p, 'ftp_anonymous_status', host, port)
                service_level_checks.append({'tool':'ftp_anonymous_status','host':host,'port':port,'output_file':str(p),'rows':rows})
                credential_validation_items.append({'tool':'ftp_anonymous_status','host':host,'port':port,'output_file':str(p),'rows':rows})
                r['lifecycle_state'] = execution_lifecycle(r, bool(rows))
                coverage.append(_coverage('ftp_anonymous_status', _status_from_result(r, bool(rows)), 'FTP anonymous/system readiness evidence', f'{host}:{port}/tcp; no brute force performed.', str(p), r))
                _add_raw(raw, 'ftp_anonymous_status', host, port, str(p), 'nmap_xml', bool(rows))

        # SMB readiness: dialect/signing only; no shares, users, RID cycling or credential attempts.
        smb_readiness_surfaces = collector_surfaces('smb_protocol_security', ['smb', 'netbios'])
        if not enabled('smb_protocol_security'):
            state, reason = disabled_collector_state('smb_protocol_security')
            coverage.append(_coverage('smb_protocol_security', scan_store.STATUS_EMPTY, 'SMB dialect/signing readiness evidence', reason, '', {'success': True, 'lifecycle_state': state}))
        elif not smb_readiness_surfaces:
            coverage.append(_coverage('smb_protocol_security', scan_store.STATUS_EMPTY, 'SMB dialect/signing readiness evidence', 'No applicable SMB/NetBIOS service was observed.', '', {'success': True, 'lifecycle_state': 'not_applicable'}))
        elif not nmap:
            coverage.append(_coverage('smb_protocol_security', scan_store.STATUS_EMPTY, 'SMB dialect/signing readiness evidence', 'nmap is not available for SMB readiness evidence.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
        else:
            for s in smb_readiness_surfaces:
                host = str(s.get('host'))
                port = int(s.get('port') or 445)
                if _service_is_infra(s):
                    coverage.append(_coverage('smb_protocol_security', scan_store.STATUS_EMPTY, 'SMB dialect/signing readiness evidence', f'SMB protocol/signing readiness deferred for infrastructure-like target {host}.', '', {'success': True, 'lifecycle_state': 'deferred'}))
                    continue
                scripts = ','.join(_collector_scripts('smb_protocol_security'))
                p = outfile('nmap_smb_protocol_security', f'{host}_{port}', 'xml')
                smb_timeout = int(collector_setting(plan_entries, 'smb_protocol_security', 'timeout_seconds', 240) or 240)
                r = run_cmd(command_builders.nmap_nse_collector(nmap, host, port, scripts.split(','), list(_policy_required(_load_recon_policy(), 'nmap_script_timing')), p), p, smb_timeout, True)
                rows, parsed_smb = parse_nmap_capture(p, 'smb_protocol_security', host, port, protocol_hint='tcp')
                script_outputs = [output for _script_id, output in _nmap_script_evidence_from_file(p)]
                produced = bool(script_outputs)
                r['lifecycle_state'] = execution_lifecycle(r, produced)
                item = {
                    'tool': 'smb_protocol_security',
                    'host': host,
                    'port': port,
                    'protocol': 'tcp',
                    'service': str(s.get('service') or 'smb'),
                    'output_file': str(p),
                    'rows': rows,
                    'script_evidence': script_outputs,
                    'parsed_nmap': parsed_smb,
                    'lifecycle_state': r['lifecycle_state'],
                }
                smb.append(item)
                service_level_checks.append(item)
                credential_validation_items.append(item)
                coverage.append(_coverage('smb_protocol_security', _status_from_result(r, produced), 'SMB dialect/signing readiness evidence', f'{host}:{port}/tcp; share/user enumeration not performed.', str(p), r))
                _add_raw(raw, 'smb_protocol_security', host, port, str(p), 'nmap_xml', produced)
        if smb_ports:
            coverage.append(_coverage('file_sharing_exposure', scan_store.STATUS_EMPTY, 'Downstream handoff', 'SMB/file-sharing exposure observed. Share listing, user enumeration, password validation and permission mapping are deferred.', ''))

        # WinRM readiness: WSMan endpoint/header check only; no authentication.
        winrm_surfaces = collector_surfaces('winrm_wsman_probe', ['winrm', 'wsman'])
        if not enabled('winrm_wsman_probe'):
            state, reason = disabled_collector_state('winrm_wsman_probe')
            coverage.append(_coverage('winrm_wsman_probe', scan_store.STATUS_EMPTY, 'WinRM WSMan listener/header readiness evidence', reason, '', {'success': True, 'lifecycle_state': state}))
        elif not winrm_surfaces:
            coverage.append(_coverage('winrm_wsman_probe', scan_store.STATUS_EMPTY, 'WinRM WSMan listener/header readiness evidence', 'No applicable WinRM/WSMan service was observed.', '', {'success': True, 'lifecycle_state': 'not_applicable'}))
        else:
            curl_bin = which('curl')
            if not curl_bin:
                coverage.append(_coverage('winrm_wsman_probe', scan_store.STATUS_EMPTY, 'WinRM WSMan listener/header readiness evidence', 'curl is not available for WinRM WSMan readiness evidence.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
            for s in winrm_surfaces if curl_bin else []:
                host = str(s.get('host'))
                port = int(s.get('port') or 0)
                scheme = 'https' if port == 5986 else 'http'
                url = f'{scheme}://{host}:{port}/wsman'
                p = outfile('winrm_wsman_probe', f'{host}_{port}', 'txt')
                guard = _policy_required(_load_recon_policy(), 'http_probe_guardrails')
                policy_curl_timeout = int(_policy_required(guard, 'curl_timeout_seconds'))
                requested_curl_timeout = int(collector_setting(plan_entries, 'winrm_wsman_probe', 'request_timeout_seconds', policy_curl_timeout) or policy_curl_timeout)
                effective_curl_timeout = max(1, min(policy_curl_timeout, requested_curl_timeout))
                cmd = command_builders.curl_headers(curl_bin, url, effective_curl_timeout, insecure=(scheme == 'https'))
                r = run_cmd(cmd, p, max(5, effective_curl_timeout + 5))
                output, _ = _captured_command_output(r, Path(p))
                auth_headers = re.findall(r'(?im)^WWW-Authenticate:\s*(.+)$', output)
                item = {'tool':'winrm_wsman_probe','host':host,'port':port,'url':url,'auth_headers':auth_headers,'output_file':str(p),'output':output[:4000]}
                credential_validation_items.append(item)
                service_level_checks.append(item)
                produced = bool(output.strip())
                r['lifecycle_state'] = execution_lifecycle(r, produced)
                coverage.append(_coverage('winrm_wsman_probe', _status_from_result(r, produced), 'WinRM WSMan listener/header readiness evidence', f'{host}:{port}/tcp; no authentication performed.', str(p), r))
                _add_raw(raw, 'winrm_wsman_probe', host, port, str(p), 'text', bool(output.strip()))

        # Web handoff readiness: one-page form/input/link extraction only; no crawling or payloads.
        if not enabled('html_form_parser'):
            state, reason = disabled_collector_state('html_form_parser')
            coverage.append(_coverage('html_form_parser', scan_store.STATUS_EMPTY, 'Web form/input/link readiness evidence', reason, '', {'success': True, 'lifecycle_state': state}))
        elif not http_ports:
            coverage.append(_coverage('html_form_parser', scan_store.STATUS_EMPTY, 'Web form/input/link readiness evidence', 'No applicable HTTP/HTTPS service was observed.', '', {'success': True, 'lifecycle_state': 'not_applicable'}))
        else:
            for s in http_ports:
                host = str(s.get('host'))
                port = int(s.get('port') or 0)
                if _is_infrastructure_target(host, environment_intelligence, open_map.get(host, [])):
                    coverage.append(_coverage('html_form_parser', scan_store.STATUS_EMPTY, 'Web form/input/link readiness evidence', f'Web form parsing deferred for infrastructure target {host}.', '', {'success': True, 'lifecycle_state': 'deferred'}))
                    continue
                url = _url_for(host, port, 'ssl' in str(s.get('service','')).lower())
                result = _collect_single_page_form_hints(host, port, url)
                item = {'tool':'html_form_parser','host':host,'port':port,'url':url,'forms':result.get('forms') or [],'links':result.get('links') or [],'output_file':result.get('output_file','')}
                web.append(item)
                produced = bool(item['forms'] or item['links'])
                result['lifecycle_state'] = execution_lifecycle(result, produced)
                coverage.append(_coverage('html_form_parser', _status_from_result(result, produced), 'Web form/input/link readiness evidence', f'{url}; one page fetched; no attack payloads or directory brute force.', result.get('output_file',''), result))
                _add_raw(raw, 'html_form_parser', host, port, result.get('output_file',''), 'html', bool(item['forms'] or item['links']))

        credential_surfaces=[s for s in all_services if int(s.get('port') or 0) in {21,22,23,139,445,5985,5986} or str(s.get('service','')).lower() in {'ftp','ssh','telnet','smb','netbios-ssn','microsoft-ds','winrm'}]
        if credential_surfaces:
            coverage.append(_coverage('credential_validation_handoff', scan_store.STATUS_EMPTY, 'Downstream handoff', f'Credential validation deferred for {len(credential_surfaces)} service surface(s); recon collected readiness evidence only and does not perform login attempts.', ''))
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if (service_level_checks or credential_validation_items) else scan_store.STATUS_EMPTY, f'{len(service_level_checks)} readiness evidence item(s) collected; validation collectors deferred')
        _publish_partial(scan_id, smb_inventory=smb, service_level_checks=service_level_checks, credential_validation=credential_validation_items)


        # Modern active validation: adaptive, evidence-only checks for enterprise services.
        # These collectors stay inside recon: no brute force, no exploitation, no authenticated access.
        # Discovery service names (including HTTPS) are evidence available before
        # collector planning. Attach them now so applicability decisions can use
        # the complete observed transport/service context.
        all_services = _attach_discovery_observed_identities(all_services, discovery_evidence)
        for _service_row in all_services:
            _refresh_transport_security(_service_row)

        task='Modern Active Validation'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        passive_intelligence = {'dns': [], 'reverse_dns': [], 'tls': [], 'certificate_transparency': [], 'findings': {}, 'relationships': [], 'dns_relationships': [], 'certificate_correlation': [], 'summary': [], 'policy': {}}
        modern_active_validation = {'smb_host_identity': [], 'netbios_identity': [], 'msrpc_metadata': [], 'ntlm_http_identity': [], 'ntlm_rdp_identity': [], 'ntlm_mssql_identity': [], 'ntlm_smtp_identity': [], 'ntlm_imap_identity': [], 'ntlm_pop3_identity': [], 'ntlm_nntp_identity': [], 'ntlm_telnet_identity': [], 'ldap_rootdse': [], 'kerberos_info': [], 'tls_cipher_validation': [], 'rdp_negotiation': [], 'api_discovery': [], 'targeted_web_discovery': [], 'kubernetes_exposure': [], 'container_exposure': [], 'vpn_validation': [], 'nuclei_safe': [], 'telnet_readiness': [], 'snmp_readiness': [], 'mssql_info': [], 'vnc_info': [], 'tomcat_ajp_readiness': [], 'redis_info': [], 'elasticsearch_info': [], 'ldapsearch_rootdse': [], 'snmp_targeted_oids': [], 'dns_context': [], 'http_security_context': [], 'rpcinfo_native': [], 'showmount_native': [], 'ssh_audit_native': [], 'ssh_crypto_profiles': [], 'federation_detection': [], 'tls_intelligence': [], 'noise_evaluation': {}, 'information_gathering_summary': [], 'summary': [], 'policy': {}, 'budget': {}}
        try:
            active_policy = load_active_policy()
            modern_active_validation['policy'] = {'nuclei_enabled_by_default': bool((active_policy.get('nuclei') or {}).get('enabled_by_default')), 'detection_budget_enabled': bool((active_policy.get('detection_budget') or {}).get('enabled', True))}
            budget_cfg = active_policy.get('detection_budget') or {}
            per_host_http_budget = int(budget_cfg.get('max_native_http_requests_per_host') or 18)
            modern_active_validation['budget'] = {'native_http_budget_per_host': per_host_http_budget, 'nmap_script_budget_per_host': int(budget_cfg.get('max_nmap_script_groups_per_host') or 5), 'enforced': bool(budget_cfg.get('enabled', True))}

            nmap_bin = which('nmap')
            timing = list(_policy_required(_load_recon_policy(), 'nmap_script_timing'))

            def run_nmap_validation(tool_id: str, surfaces: list[dict[str, Any]], scripts: list[str], evidence_label: str, extra_args_builder=None) -> None:
                plan_entry = (scan_options.get('collector_plan') or {}).get(tool_id) or {}
                if not enabled(tool_id):
                    state = 'disabled_policy' if plan_entry.get('policy_state') == 'blocked' else 'disabled_operator'
                    coverage.append(_coverage(tool_id, scan_store.STATUS_EMPTY, evidence_label, f'{tool_id} was not executed.', '', {'success': True, 'lifecycle_state': state}))
                    return
                if not surfaces:
                    coverage.append(_coverage(tool_id, scan_store.STATUS_EMPTY, evidence_label, f'No applicable {tool_id.replace("_", " ")} service was observed.', '', {'success': True, 'lifecycle_state': 'not_applicable'}))
                    return
                if not nmap_bin:
                    coverage.append(_coverage(tool_id, scan_store.STATUS_EMPTY, evidence_label, 'nmap is not available for this collector.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
                    return
                nse_state = nse_script_preflight(scripts)
                if nse_state.get('known') and nse_state.get('missing'):
                    coverage.append(_coverage(
                        tool_id, scan_store.STATUS_EMPTY, evidence_label,
                        'Required Nmap NSE script(s) are unavailable: ' + ', '.join(nse_state.get('missing') or []),
                        '', {'success': True, 'lifecycle_state': 'tool_unavailable', 'missing_nse_scripts': nse_state.get('missing') or []}
                    ))
                    return
                for svc in surfaces:
                    host = str(svc.get('host'))
                    port = int(svc.get('port') or 0)
                    protocol = str(svc.get('protocol') or 'tcp').strip().lower()
                    # Policy and observed protocol applicability already decide whether this
                    # bounded collector may run. Do not add a hidden OS/device heuristic.
                    p = outfile(tool_id, f'{host}_{port}', 'xml')
                    policy_timeout = int(active_policy.get('timeouts', {}).get('nmap_seconds', 180))
                    requested_timeout = int(collector_setting(scan_options.get('collector_plan') or {}, tool_id, 'timeout_seconds', policy_timeout) or policy_timeout)
                    effective_timeout = max(1, min(policy_timeout, requested_timeout))
                    extra_args = list(extra_args_builder(svc) or []) if extra_args_builder else []
                    command = command_builders.nmap_nse_collector(
                        nmap_bin, host, port, scripts, timing, p, protocol=protocol, extra_args=extra_args,
                    )
                    before_identity_count = len(host_identity_map.get(host) or [])
                    r = run_cmd(command, p, effective_timeout, True)
                    rows, _parsed_validation = parse_nmap_capture(p, tool_id, host, port)
                    script_outputs = []
                    for parsed_host in _parsed_validation.get('hosts') or []:
                        for script in parsed_host.get('scripts') or []:
                            if str(script.get('output') or '').strip(): script_outputs.append(script.get('output'))
                        for parsed_port in parsed_host.get('ports') or []:
                            for script in parsed_port.get('scripts') or []:
                                if str(script.get('output') or '').strip(): script_outputs.append(script.get('output'))
                    identity_added = len(host_identity_map.get(host) or []) > before_identity_count
                    produced = bool(script_outputs or identity_added)
                    item = {'tool': tool_id, 'host': host, 'port': port, 'protocol': protocol, 'scripts': scripts, 'rows': rows, 'script_evidence': script_outputs, 'output_file': str(p), 'recon_boundary': 'Evidence-only protocol validation; no credential use or exploitation.'}
                    if tool_id == 'msrpc_metadata':
                        item['advertised_tcp_ports'] = _extract_protocol_advertised_tcp_ports(script_outputs)
                        item['advertised_endpoint_policy'] = 'record_only_unless_operator_explicitly_enables_followup'
                    modern_active_validation.setdefault(tool_id, []).append(item)
                    service_level_checks.append(item)
                    r['lifecycle_state'] = execution_lifecycle(r, produced)
                    item['lifecycle_state'] = r['lifecycle_state']
                    coverage.append(_coverage(tool_id, _status_from_result(r, produced), evidence_label, f'{host}:{port}/{protocol}; no credentials, brute force, or exploitation performed.', str(p), r))
                    _add_raw(raw, tool_id, host, port, str(p), 'nmap_xml', produced)

            ldap_surfaces = collector_surfaces('ldap_rootdse', ['ldap'])
            kerberos_surfaces = collector_surfaces('kerberos_info', ['kerberos'])
            tls_surfaces = collector_surfaces('tls_cipher_validation', ['tls', 'https'])
            rdp_surfaces = collector_surfaces('rdp_negotiation', ['rdp'])
            scripts = active_policy.get('nmap_script_sets') or {}

            # Cross-platform identity enrichment. These collectors are selected
            # from observed protocol/service evidence; they do not assume the
            # target is Windows, macOS, Linux, or any other platform.
            smb_identity_surfaces = collector_surfaces('smb_host_identity', ['smb', 'netbios'])
            netbios_surfaces = [svc for svc in collector_surfaces('netbios_identity', ['netbios']) if str(svc.get('protocol') or '').lower() == 'udp' or 'netbios-ns' in str(svc.get('service') or '').lower()]
            msrpc_surfaces = collector_surfaces('msrpc_metadata', ['msrpc', 'epmap'])
            ntlm_http_surfaces = collector_surfaces('ntlm_http_identity', ['http', 'https', 'winrm', 'wsman'])
            ntlm_rdp_surfaces = collector_surfaces('ntlm_rdp_identity', ['rdp'])
            ntlm_mssql_surfaces = collector_surfaces('ntlm_mssql_identity', ['mssql', 'ms-sql'])
            ntlm_smtp_surfaces = collector_surfaces('ntlm_smtp_identity', ['smtp'])
            ntlm_imap_surfaces = collector_surfaces('ntlm_imap_identity', ['imap'])
            ntlm_pop3_surfaces = collector_surfaces('ntlm_pop3_identity', ['pop3'])
            ntlm_nntp_surfaces = collector_surfaces('ntlm_nntp_identity', ['nntp'])
            ntlm_telnet_surfaces = collector_surfaces('ntlm_telnet_identity', ['telnet'])

            run_nmap_validation('smb_host_identity', smb_identity_surfaces, scripts.get('smb_host_identity') or ['smb-os-discovery','smb2-capabilities','smb2-time'], 'SMB host/OS identity and capability evidence')
            run_nmap_validation('netbios_identity', netbios_surfaces, scripts.get('netbios_identity') or ['nbstat'], 'NetBIOS host naming identity evidence')
            run_nmap_validation('msrpc_metadata', msrpc_surfaces, scripts.get('msrpc_metadata') or ['msrpc-enum'], 'Microsoft RPC endpoint metadata evidence')

            # Protocol-advertised endpoint verification is an explicit operator
            # choice.  MSRPC endpoints are always recorded as evidence; they are
            # never silently added to the original TCP coverage.
            advertised_by_host: dict[str, set[int]] = {}
            for item in modern_active_validation.get('msrpc_metadata') or []:
                if not isinstance(item, dict):
                    continue
                host = str(item.get('host') or '')
                for advertised_port in item.get('advertised_tcp_ports') or []:
                    try:
                        value = int(advertised_port)
                    except (TypeError, ValueError):
                        continue
                    if host and 1 <= value <= 65535:
                        advertised_by_host.setdefault(host, set()).add(value)

            identity_controls = scan_options.get('service_identity') or {}
            follow_advertised = bool(identity_controls.get('follow_protocol_advertised_endpoints', False))
            advertised_limit = max(1, min(32, int(identity_controls.get('advertised_endpoint_limit') or 8)))
            if advertised_by_host and not follow_advertised:
                total_advertised = sum(len(values) for values in advertised_by_host.values())
                coverage.append(_coverage(
                    'protocol_advertised_endpoint_followup', scan_store.STATUS_EMPTY,
                    'Protocol-advertised endpoint verification',
                    f'{total_advertised} TCP endpoint(s) were advertised by protocol evidence and retained without verification because explicit follow-up is disabled.',
                    '', {'success': True, 'lifecycle_state': 'disabled_operator'},
                ))
            elif advertised_by_host and follow_advertised and nmap_bin:
                for advertised_host, advertised_ports in sorted(advertised_by_host.items()):
                    chosen = sorted(advertised_ports)[:advertised_limit]
                    out = outfile('protocol_advertised_endpoint_followup', advertised_host, 'xml')
                    cmd = command_builders.nmap_advertised_followup(
                        nmap_bin, advertised_host, chosen,
                        list(_policy_required(_load_recon_policy(), 'service_fingerprint_timing')), out,
                    )
                    timeout = min(300, max(30, int((scan_options.get('advanced_settings') or {}).get('command_timeout_seconds') or 300)))
                    r = run_cmd(cmd, out, timeout, True)
                    followed_rows, _followed_parsed = parse_nmap_capture(out, 'protocol_advertised_endpoint_followup', advertised_host)
                    all_services = _merge_service_identity_rows(all_services, followed_rows, 'protocol_advertised_endpoint_followup')
                    produced = bool(followed_rows)
                    r['lifecycle_state'] = execution_lifecycle(r, produced)
                    coverage.append(_coverage(
                        'protocol_advertised_endpoint_followup', _status_from_result(r, produced),
                        'Protocol-advertised endpoint verification',
                        f'{advertised_host}: verified {len(chosen)} explicitly advertised TCP endpoint(s); this was operator-enabled scope expansion and did not alter the original selected-port coverage.',
                        str(out), r,
                    ))
                    _add_raw(raw, 'protocol_advertised_endpoint_followup', advertised_host, '', str(out), 'nmap_xml', produced)
            elif advertised_by_host and follow_advertised and not nmap_bin:
                coverage.append(_coverage(
                    'protocol_advertised_endpoint_followup', scan_store.STATUS_EMPTY,
                    'Protocol-advertised endpoint verification',
                    'Protocol-advertised endpoints were observed but nmap is unavailable for explicit verification.',
                    '', {'success': True, 'lifecycle_state': 'tool_unavailable'},
                ))
            elif follow_advertised:
                coverage.append(_coverage(
                    'protocol_advertised_endpoint_followup', scan_store.STATUS_EMPTY,
                    'Protocol-advertised endpoint verification',
                    'No protocol-advertised TCP endpoints were observed for explicit verification.',
                    '', {'success': True, 'lifecycle_state': 'not_applicable'},
                ))
            def _http_ntlm_args(svc):
                text = ' '.join(str(svc.get(k) or '') for k in ('service','product','extra')).lower()
                return ['--script-args', 'http-ntlm-info.root=/wsman'] if ('winrm' in text or 'wsman' in text) else []
            run_nmap_validation('ntlm_http_identity', ntlm_http_surfaces, scripts.get('ntlm_http_identity') or ['http-ntlm-info'], 'HTTP/WinRM NTLM host identity evidence', _http_ntlm_args)
            run_nmap_validation('ntlm_rdp_identity', ntlm_rdp_surfaces, scripts.get('ntlm_rdp_identity') or ['rdp-ntlm-info'], 'RDP NTLM host identity evidence')
            run_nmap_validation('ntlm_mssql_identity', ntlm_mssql_surfaces, scripts.get('ntlm_mssql_identity') or ['ms-sql-ntlm-info'], 'MSSQL NTLM host identity evidence')
            run_nmap_validation('ntlm_smtp_identity', ntlm_smtp_surfaces, scripts.get('ntlm_smtp_identity') or ['smtp-ntlm-info'], 'SMTP NTLM host identity evidence')
            run_nmap_validation('ntlm_imap_identity', ntlm_imap_surfaces, scripts.get('ntlm_imap_identity') or ['imap-ntlm-info'], 'IMAP NTLM host identity evidence')
            run_nmap_validation('ntlm_pop3_identity', ntlm_pop3_surfaces, scripts.get('ntlm_pop3_identity') or ['pop3-ntlm-info'], 'POP3 NTLM host identity evidence')
            run_nmap_validation('ntlm_nntp_identity', ntlm_nntp_surfaces, scripts.get('ntlm_nntp_identity') or ['nntp-ntlm-info'], 'NNTP NTLM host identity evidence')
            run_nmap_validation('ntlm_telnet_identity', ntlm_telnet_surfaces, scripts.get('ntlm_telnet_identity') or ['telnet-ntlm-info'], 'Telnet NTLM host identity evidence')

            run_nmap_validation('ldap_rootdse', ldap_surfaces, scripts.get('ldap_rootdse') or ['ldap-rootdse'], 'LDAP RootDSE naming-context evidence')
            run_nmap_validation('kerberos_info', kerberos_surfaces, scripts.get('kerberos_info') or ['krb5-info'], 'Kerberos realm/service evidence')
            run_nmap_validation('tls_cipher_validation', tls_surfaces, scripts.get('tls_cipher_validation') or ['ssl-enum-ciphers'], 'TLS cipher/protocol validation evidence')
            run_nmap_validation('rdp_negotiation', rdp_surfaces, scripts.get('rdp_negotiation') or ['rdp-enum-encryption'], 'RDP encryption/NLA negotiation evidence')

            # Policy-driven Full Recon service coverage. Ports/services live in
            # active_validation_policy.json so reviewers can amend coverage without
            # changing scanner code.
            def policy_surfaces(tool_id: str) -> tuple[list[dict[str, Any]], str]:
                cfg = (active_policy.get('service_validation') or {}).get(tool_id) or {}
                ports = {int(x) for x in (cfg.get('ports') or [])}
                names = {str(x).lower() for x in (cfg.get('services') or [])}
                label = str(cfg.get('label') or tool_id.replace('_', ' ') + ' evidence')
                rows = []
                plan_entry = (scan_options.get('collector_plan') or {}).get(tool_id) or {}
                for svc in all_services:
                    port = int(svc.get('port') or 0)
                    name = str(svc.get('service') or '').lower()
                    product = str(svc.get('product') or '').lower()
                    if _collector_service_applicable(plan_entry, svc) or port in ports or name in names or any(n and n in product for n in names):
                        rows.append(svc)
                return rows, label

            for tool_id in ['telnet_readiness','snmp_readiness','mssql_info','vnc_info','tomcat_ajp_readiness']:
                surfaces, label = policy_surfaces(tool_id)
                run_nmap_validation(tool_id, surfaces, scripts.get(tool_id) or [], label)

            # Native targeted information-gathering collectors. These add depth
            # while staying recon-only: no auth attempts, no brute force, no
            # mounting, no writes, and no exploitation.
            def run_external_validation(tool_id: str, surfaces: list[dict[str, Any]], command_builder, label: str, timeout: int = 60) -> None:
                plan_entry = (scan_options.get('collector_plan') or {}).get(tool_id) or {}
                if not enabled(tool_id):
                    state = 'disabled_policy' if plan_entry.get('policy_state') == 'blocked' else 'disabled_operator'
                    coverage.append(_coverage(tool_id, scan_store.STATUS_EMPTY, label, f'{tool_id} was not executed.', '', {'success': True, 'lifecycle_state': state}))
                    return
                if not surfaces:
                    coverage.append(_coverage(tool_id, scan_store.STATUS_EMPTY, label, f'No applicable {tool_id.replace("_", " ")} service was observed.', '', {'success': True, 'lifecycle_state': 'not_applicable'}))
                    return
                for svc in surfaces:
                    host = str(svc.get('host'))
                    port = int(svc.get('port') or 0)
                    cmd = command_builder(host, port)
                    if not cmd or not which(str(cmd[0])):
                        coverage.append(_coverage(tool_id, scan_store.STATUS_EMPTY, label, f'{cmd[0] if cmd else tool_id} not available for {tool_id}.', '', {'success': True, 'lifecycle_state': 'tool_unavailable'}))
                        continue
                    out = outfile(tool_id, f'{host}_{port}', 'txt')
                    requested_timeout = int(collector_setting(scan_options.get('collector_plan') or {}, tool_id, 'timeout_seconds', timeout) or timeout)
                    effective_timeout = max(1, min(int(timeout), requested_timeout))
                    r = run_cmd(cmd, out, effective_timeout, False)
                    protocol = str(svc.get('protocol') or 'tcp').strip().lower()
                    parsed, produced = parse_external_result(tool_id, r)
                    r['lifecycle_state'] = execution_lifecycle(r, produced)
                    item = {
                        'tool': tool_id, 'host': host, 'port': port, 'protocol': protocol,
                        'command': ' '.join(map(str, cmd)), 'parsed': parsed,
                        'output_file': str(out), 'lifecycle_state': r['lifecycle_state'],
                        'recon_boundary': 'Targeted information gathering only; no credentials, brute force, writes, mounting, or exploitation.',
                    }
                    modern_active_validation.setdefault(tool_id, []).append(item)
                    service_level_checks.append(item)
                    coverage.append(_coverage(tool_id, _status_from_result(r, produced), label, f'{host}:{port}/{protocol}; targeted information-gathering evidence only.', str(out), r))
                    _add_raw(raw, tool_id, host, port, str(out), 'text', produced)

            ssh_surfaces = collector_surfaces('ssh_audit_native', ['ssh'])
            native_sets = []
            # Prefer native protocol tools over Nmap NSE where they provide the same evidence with less noise.
            dns_surfaces = collector_surfaces('dns_context', ['dns', 'domain'])
            snmp_surfaces, _ = policy_surfaces('snmp_readiness')
            rpc_surfaces = collector_surfaces('rpcinfo_native', ['rpcbind', 'portmapper', 'nfs', 'mountd'])
            nfs_surfaces = collector_surfaces('showmount_native', ['nfs', 'mountd', 'rpcbind', 'portmapper'])
            if enabled('ssh_audit_native'):
                policy_ssh_timeout = max(1, int(active_policy.get('timeouts', {}).get('http_seconds', 4)))
                requested_ssh_timeout = int(collector_setting(scan_options.get('collector_plan') or {}, 'ssh_audit_native', 'timeout_seconds', policy_ssh_timeout) or policy_ssh_timeout)
                timeout = max(1, min(policy_ssh_timeout, requested_ssh_timeout))
                for service in ssh_surfaces:
                    host = str(service.get('host') or '')
                    port = int(service.get('port') or 22)
                    if acl_pause_requested(host) or _is_infrastructure_target(host, environment_intelligence, open_map.get(host, [])):
                        coverage.append(_coverage('ssh_audit_native', scan_store.STATUS_EMPTY, 'SSH cryptographic posture', f'SSH cryptographic negotiation deferred for infrastructure/ACL-sensitive target {host}.', '', {'success': True, 'lifecycle_state': 'deferred'}))
                        continue
                    profile = collect_ssh_cryptography(host, port, timeout)
                    if profile is None:
                        coverage.append(_coverage('ssh_audit_native', scan_store.STATUS_EMPTY, 'SSH cryptographic posture', f'No SSH KEXINIT evidence returned from {host}:{port}; no retries issued.', '', {'success': True, 'lifecycle_state': 'executed_no_evidence'}))
                        continue
                    profile_data = profile.to_dict()
                    ssh_crypto_profiles.append(profile_data)
                    modern_active_validation['ssh_crypto_profiles'].append(profile_data)
                    item = {
                        'tool': 'ssh_audit_native',
                        'host': host,
                        'port': port,
                        'profile': profile_data,
                        'recon_boundary': 'One SSH identification/KEXINIT exchange; no key exchange completion, login, credentials, or authentication.',
                    }
                    modern_active_validation['ssh_audit_native'].append(item)
                    service_level_checks.append(item)
                    ssh_items.append(item)
                native_sets.append(('ssh_audit_native', modern_active_validation['ssh_audit_native'], 'SSH protocol identification and KEXINIT algorithm evidence; no authentication.'))
            else:
                ssh_plan = (scan_options.get('collector_plan') or {}).get('ssh_audit_native') or {}
                ssh_state = 'disabled_policy' if ssh_plan.get('policy_state') == 'blocked' else 'disabled_operator'
                coverage.append(_coverage('ssh_audit_native', scan_store.STATUS_EMPTY, 'SSH cryptographic posture', 'SSH cryptographic collection was not executed.', '', {'success': True, 'lifecycle_state': ssh_state}))
            run_external_validation('dns_context', dns_surfaces[:1], lambda h,p: command_builders.dig_version_bind('dig', h), 'DNS context collection using version.bind', 30)
            if enabled('snmp_targeted_oids') and snmp_surfaces:
                coverage.append(_coverage(
                    'snmp_targeted_oids', scan_store.STATUS_EMPTY,
                    'SNMP targeted system identity OID evidence',
                    'Not executed: SNMP v1/v2c requires an explicitly authorised community string. '
                    'The current IP/CIDR-only operator input model does not accept credentials, so the scanner does not guess or hardcode one.',
                    '', {'success': True, 'lifecycle_state': 'deferred'},
                ))
            elif enabled('snmp_targeted_oids'):
                coverage.append(_coverage(
                    'snmp_targeted_oids', scan_store.STATUS_EMPTY,
                    'SNMP targeted system identity OID evidence',
                    'No applicable SNMP service was observed.', '',
                    {'success': True, 'lifecycle_state': 'not_applicable'},
                ))
            run_external_validation('rpcinfo_native', rpc_surfaces[:1], lambda h,p: command_builders.rpcinfo_programs('rpcinfo', h), 'Native RPC program mapping evidence', 45)
            run_external_validation('showmount_native', nfs_surfaces[:1], lambda h,p: command_builders.showmount_exports('showmount', h), 'Native NFS export readiness evidence', 45)
            run_external_validation('ldapsearch_rootdse', ldap_surfaces, lambda h,p: command_builders.ldapsearch_rootdse('ldapsearch', h, p), 'Native LDAP RootDSE capability/naming-context evidence', 60)
            postgres_surfaces = collector_surfaces('postgres_readiness_native', ['postgresql', 'postgres'])
            run_external_validation('postgres_readiness_native', postgres_surfaces[:1], lambda h,p: command_builders.pg_isready('pg_isready', h, p, 4), 'Native PostgreSQL readiness evidence', 30)

            web_services = collector_surfaces('http_security_context', ['http', 'https'])
            http_context_request_timeout = int(collector_setting(scan_options.get('collector_plan') or {}, 'http_security_context', 'request_timeout_seconds', 5) or 5)
            run_external_validation('http_security_context', web_services, lambda h,p: command_builders.curl_headers('curl', service_url({'host': h, 'port': p}), http_context_request_timeout, insecure=True), 'HTTP security-header/authentication/cookie context evidence', 30)
            if enabled('federation_detection'):
                modern_active_validation['federation_detection'] = collect_federation_detection(web_services, active_policy)
                native_sets.append(('federation_detection', modern_active_validation['federation_detection'], 'Federation/OIDC/SAML metadata and authentication-surface markers only.'))
            if enabled('tls_intelligence'):
                modern_active_validation['tls_intelligence'] = collect_tls_intelligence(all_services, active_policy)
                native_sets.append(('tls_intelligence', modern_active_validation['tls_intelligence'], 'TLS handshake, ALPN, cipher and certificate metadata only.'))
            if enabled('targeted_web_discovery'):
                modern_active_validation['targeted_web_discovery'] = collect_targeted_web_discovery(web_services, active_policy)
                native_sets.append(('targeted_web_discovery', modern_active_validation['targeted_web_discovery'], 'Policy-limited robots/sitemap/security/admin marker checks; no wordlist brute force.'))
            else:
                state, reason = disabled_collector_state('targeted_web_discovery')
                coverage.append(_coverage('targeted_web_discovery', scan_store.STATUS_EMPTY, 'Targeted web discovery', reason, '', {'success': True, 'lifecycle_state': state}))
            if enabled('api_discovery'):
                modern_active_validation['api_discovery'] = collect_api_discovery(web_services, active_policy)
                native_sets.append(('api_discovery', modern_active_validation['api_discovery'], 'OpenAPI/Swagger/GraphQL documentation discovery only.'))
            else:
                state, reason = disabled_collector_state('api_discovery')
                coverage.append(_coverage('api_discovery', scan_store.STATUS_EMPTY, 'API documentation discovery', reason, '', {'success': True, 'lifecycle_state': state}))
            if enabled('kubernetes_exposure'):
                modern_active_validation['kubernetes_exposure'] = collect_kubernetes_exposure(all_services, active_policy)
                native_sets.append(('kubernetes_exposure', modern_active_validation['kubernetes_exposure'], 'Kubernetes unauthenticated metadata endpoint checks only.'))
            else:
                state, reason = disabled_collector_state('kubernetes_exposure')
                coverage.append(_coverage('kubernetes_exposure', scan_store.STATUS_EMPTY, 'Kubernetes metadata exposure evidence', reason, '', {'success': True, 'lifecycle_state': state}))
            if enabled('container_exposure'):
                modern_active_validation['container_exposure'] = collect_container_exposure(all_services, active_policy)
                native_sets.append(('container_exposure', modern_active_validation['container_exposure'], 'Container/registry metadata endpoint checks only.'))
            else:
                state, reason = disabled_collector_state('container_exposure')
                coverage.append(_coverage('container_exposure', scan_store.STATUS_EMPTY, 'Container/registry metadata evidence', reason, '', {'success': True, 'lifecycle_state': state}))
            if enabled('vpn_validation'):
                modern_active_validation['vpn_validation'] = collect_vpn_validation(web_services, (passive_intelligence or {}).get('findings') if isinstance(passive_intelligence, dict) else {}, active_policy)
                native_sets.append(('vpn_validation', modern_active_validation['vpn_validation'], 'VPN portal marker validation only; no authentication.'))
            else:
                state, reason = disabled_collector_state('vpn_validation')
                coverage.append(_coverage('vpn_validation', scan_store.STATUS_EMPTY, 'VPN portal marker evidence', reason, '', {'success': True, 'lifecycle_state': state}))

            # Native HTTP metadata checks for modern data stores/search services
            # such as Redis proxies and Elasticsearch. They are evidence-only,
            # policy-path based, and perform no writes/authentication.
            for native_tool, cfg in (active_policy.get('native_http_services') or {}).items():
                if not enabled(native_tool):
                    entry = (scan_options.get('collector_plan') or {}).get(native_tool) or {}
                    state = 'disabled_policy' if entry.get('policy_state') == 'blocked' else 'disabled_operator'
                    coverage.append(_coverage(native_tool, scan_store.STATUS_EMPTY, str(cfg.get('label') or native_tool.replace('_',' ') + ' evidence'), f'{native_tool} was not executed.', '', {'success': True, 'lifecycle_state': state}))
                    continue
                ports = {int(x) for x in (cfg.get('ports') or [])}
                plan_entry = (scan_options.get('collector_plan') or {}).get(native_tool) or {}
                candidates = [
                    service for service in all_services
                    if _collector_service_applicable(plan_entry, service)
                    or int(service.get('port') or 0) in ports
                ]
                rows_native = []
                for svc in candidates:
                    base = service_url(svc).rstrip('/')
                    for path in cfg.get('paths') or ['/']:
                        row = _fetch(base + str(path), timeout=float(active_policy.get('timeouts', {}).get('http_seconds', 4)))
                        blob = str(row).lower()
                        if int(row.get('status') or 0) in {200, 401, 403} or (int(row.get('status') or 0) not in {404} and any(str(m).lower() in blob for m in (cfg.get('markers') or []))):
                            row['evidence_observed'] = True
                            row['evidence_state'] = 'observed'
                            row.update({'host': svc.get('host'), 'port': svc.get('port'), 'category': native_tool, 'collection_method':'metadata_endpoint_probe', 'recon_boundary':'Metadata exposure check only; no writes, queries, authentication, or exploitation.'})
                            rows_native.append(row)
                modern_active_validation[native_tool] = rows_native
                native_sets.append((native_tool, rows_native, str(cfg.get('label') or native_tool.replace('_',' ') + ' evidence')))

            # Nuclei is enabled in Full Recon but constrained to safe info/low
            # fingerprint and misconfiguration evidence; intrusive/exploit tags are excluded.
            nuclei_bin = which('nuclei')
            nuclei_cfg = active_policy.get('nuclei') or {}
            if enabled('nuclei_safe') and nuclei_bin and web_services:
                urls_file = outfile('nuclei_safe_targets', 'web', 'txt')
                urls_file.write_text('\n'.join(sorted({service_url(s) for s in web_services})) + '\n', encoding='utf-8')
                out = outfile('nuclei_safe', 'web', 'jsonl')
                plan = scan_options.get('collector_plan') or {}
                requested_window_requests = max(1, int(collector_setting(plan, 'nuclei_safe', 'requests_per_window', 1) or 1))
                requested_window_seconds = max(1, int(collector_setting(plan, 'nuclei_safe', 'window_seconds', 2) or 2))
                requested_retries = int(collector_setting(plan, 'nuclei_safe', 'retries', nuclei_cfg.get('retries') or 0) or 0)
                policy_rps = max(0.01, float(nuclei_cfg.get('rate_limit_per_second') or 1.0))
                # Nuclei exposes an integer request count plus a rate-limit duration.
                # Increase the duration when necessary so operator customization can
                # only reduce activity relative to the policy ceiling.
                minimum_window = max(1, int(math.ceil(requested_window_requests / policy_rps)))
                effective_window_seconds = max(requested_window_seconds, minimum_window)
                effective_retries = min(requested_retries, int(nuclei_cfg.get('retries') or requested_retries or 0))
                templates_dir = os.getenv(str(nuclei_cfg.get('templates_directory_env') or 'NUCLEI_TEMPLATES_DIR'), '').strip()
                cmd = command_builders.nuclei_safe_templates(
                    nuclei_bin, urls_file, out,
                    nuclei_cfg.get('allowed_severities') or ['info','low'],
                    nuclei_cfg.get('allowed_tags') or ['tech','fingerprint','misconfig'],
                    nuclei_cfg.get('excluded_tags') or [], requested_window_requests,
                    effective_window_seconds, effective_retries, templates_dir=templates_dir,
                )
                r = run_cmd(cmd, out, int(active_policy.get('timeouts', {}).get('nuclei_seconds', 240)), True)
                rows = []
                try:
                    for line in out.read_text(encoding='utf-8', errors='ignore').splitlines():
                        if line.strip():
                            rows.append(json.loads(line))
                except Exception:
                    rows = []
                modern_active_validation['nuclei_safe'] = rows
                r['lifecycle_state'] = execution_lifecycle(r, bool(rows))
                coverage.append(_coverage('nuclei_safe', _status_from_result(r, bool(rows)), 'Nuclei safe informational/fingerprint/misconfiguration templates only', f'{len(rows)} safe nuclei evidence item(s) retained; intrusive/exploit/default-login tags excluded.', str(out), r))
                _add_raw(raw, 'nuclei_safe', '', '', str(out), 'jsonl', bool(rows))
            else:
                if not enabled('nuclei_safe'):
                    state, reason = 'disabled_operator', 'Nuclei safe evidence was not enabled in the effective collector plan.'
                    plan_entry = (scan_options.get('collector_plan') or {}).get('nuclei_safe') or {}
                    if plan_entry.get('policy_state') == 'blocked':
                        state, reason = 'disabled_policy', plan_entry.get('policy_reason') or 'Nuclei safe evidence is disabled by policy.'
                elif not nuclei_bin:
                    state, reason = 'tool_unavailable', 'nuclei binary is not available.'
                elif not web_services:
                    state, reason = 'not_applicable', 'No HTTP/HTTPS service was observed for Nuclei safe evidence.'
                else:
                    state, reason = 'deferred', 'Nuclei safe evidence was deferred.'
                coverage.append(_coverage('nuclei_safe', scan_store.STATUS_EMPTY, 'Nuclei safe informational/fingerprint/misconfiguration templates only', reason, '', {'success': True, 'lifecycle_state': state}))

            for tool_name, rows, note in native_sets:
                path = scan_store.scan_path(f'{tool_name}_{scan_id}.json')
                path.write_text(json.dumps(rows, indent=2, default=str), encoding='utf-8')
                produced = bool(rows)
                native_result = _log_native_collector(scan_id, tool_name, f'python-native active_validation {tool_name} items={len(rows)}', note, str(path), produced)
                plan_entry = (scan_options.get('collector_plan') or {}).get(tool_name) or {}
                applicable = str(plan_entry.get('scope') or '') == 'host' or any(_collector_service_applicable(plan_entry, service) for service in all_services)
                native_result['lifecycle_state'] = 'executed_evidence' if produced else ('executed_no_evidence' if applicable else 'not_applicable')
                lifecycle_note = f'{len(rows)} evidence item(s) retained.' if produced else ('Collector was applicable but produced no additional evidence.' if applicable else 'No applicable service was observed for this collector.')
                coverage.append(_coverage(tool_name, scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, note, lifecycle_note, str(path), native_result))
                _add_raw(raw, tool_name, '', '', str(path), 'json', produced)
                for evidence_row in rows or []:
                    evidence_host = str(evidence_row.get('host') or '') if isinstance(evidence_row, dict) else ''
                    evidence_port = evidence_row.get('port') if isinstance(evidence_row, dict) else ''
                    if evidence_host and evidence_port:
                        _add_raw(raw, tool_name, evidence_host, evidence_port, str(path), 'json', True)

            modern_active_validation['noise_evaluation'] = build_noise_evaluation(modern_active_validation)
            modern_active_validation['information_gathering_summary'] = build_information_gathering_summary(modern_active_validation)
            modern_active_validation['summary'] = build_active_summary(modern_active_validation) + modern_active_validation.get('information_gathering_summary', [])
            if modern_active_validation.get('noise_evaluation', {}).get('summary'):
                modern_active_validation['summary'].append(modern_active_validation['noise_evaluation']['summary'])
            active_path = write_active_package(scan_id, modern_active_validation)
            produced = bool(modern_active_validation.get('summary'))
            native_result = _log_native_collector(scan_id, 'modern_active_validation', 'python-native active_validation consolidate', 'Consolidated modern active validation evidence and budget metadata.', active_path, produced)
            coverage.append(_coverage('modern_active_validation', scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, 'Modern active enterprise validation summary', f'{len(modern_active_validation.get("summary") or [])} active validation summary item(s) retained.', active_path, native_result))
            _add_raw(raw, 'modern_active_validation', '', '', active_path, 'json', produced)
            scan_store.audit_event(scan_id, 'system', 'modern_active_validation_collected', {'summary_count': len(modern_active_validation.get('summary') or []), 'nuclei_enabled': enabled('nuclei_safe')})
            _publish_partial(scan_id, modern_active_validation=modern_active_validation)
            _finish(scan_id, task, scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, f'{len(modern_active_validation.get("summary") or [])} modern active validation summary item(s) retained')
        except Exception as exc:
            scan_store.log(scan_id, f'Modern active validation incomplete: {exc}', 'WARN')
            _finish(scan_id, task, scan_store.STATUS_FAILED, f'Modern active validation incomplete: {exc}')

        # Native protocol metadata enrichment. This is a low-volume depth pass:
        # one bounded metadata probe per applicable observed service where the
        # protocol can safely disclose product, version, capability or banner
        # information. Operator intent and policy permission are honoured before
        # any connection is made.
        task='Native Protocol Metadata Enrichment'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        native_entry = (scan_options.get('collector_plan') or {}).get('native_protocol_enrichment') or {}
        if not native_entry.get('requested') or native_entry.get('policy_state') == 'blocked':
            state = 'disabled_policy' if native_entry.get('policy_state') == 'blocked' else 'disabled_operator'
            reason = 'Collector was requested but blocked by effective recon policy.' if state == 'disabled_policy' else 'Collector was disabled by the operator.'
            coverage.append(_coverage('native_protocol_enrichment', scan_store.STATUS_EMPTY, 'Native protocol product/version/capability enrichment', reason, '', {'success': True, 'lifecycle_state': state}))
            modern_active_validation['native_protocol_enrichment'] = []
            _finish(scan_id, task, scan_store.STATUS_EMPTY, reason)
        else:
            native_services = [service for service in all_services if _collector_service_applicable(native_entry, service)]
            if not native_services:
                coverage.append(_coverage('native_protocol_enrichment', scan_store.STATUS_EMPTY, 'Native protocol product/version/capability enrichment', 'No applicable observed service was available for native protocol enrichment.', '', {'success': True, 'lifecycle_state': 'not_applicable'}))
                modern_active_validation['native_protocol_enrichment'] = []
                _finish(scan_id, task, scan_store.STATUS_EMPTY, 'No applicable observed service was available for native protocol enrichment.')
            else:
                try:
                    native_protocol_rows = _collect_native_protocol_enrichment(native_services)
                    all_services = _apply_native_protocol_enrichment(all_services, native_protocol_rows)
                    modern_active_validation['native_protocol_enrichment'] = native_protocol_rows
                    native_protocol_path = scan_store.scan_path(f'native_protocol_enrichment_{scan_id}.json')
                    native_protocol_path.write_text(json.dumps(native_protocol_rows, indent=2, default=str), encoding='utf-8')
                    produced = bool(native_protocol_rows)
                    lifecycle = 'executed_evidence' if produced else 'executed_no_evidence'
                    native_result = _log_native_collector(scan_id, 'native_protocol_enrichment', f'python-native native_protocol_enrichment services={len(native_services)}', 'Collected bounded protocol metadata from applicable observed services.', str(native_protocol_path), produced)
                    native_result['lifecycle_state'] = lifecycle
                    coverage.append(_coverage('native_protocol_enrichment', scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, 'Native protocol product/version/capability enrichment', f'{len(native_protocol_rows)} native protocol metadata item(s) retained from {len(native_services)} applicable service endpoint(s).', str(native_protocol_path), native_result))
                    _add_raw(raw, 'native_protocol_enrichment', '', '', str(native_protocol_path), 'json', produced)
                    for evidence_row in native_protocol_rows or []:
                        if isinstance(evidence_row, dict) and evidence_row.get('host') and evidence_row.get('port'):
                            _add_raw(raw, 'native_protocol_enrichment', str(evidence_row.get('host')), evidence_row.get('port'), str(native_protocol_path), 'json', True)
                    _finish(scan_id, task, scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, f'{len(native_protocol_rows)} native protocol metadata item(s) retained')
                except Exception as exc:
                    scan_store.log(scan_id, f'Native protocol metadata enrichment incomplete: {exc}', 'WARN')
                    coverage.append(_coverage('native_protocol_enrichment', scan_store.STATUS_FAILED, 'Native protocol product/version/capability enrichment', f'Collector execution failed: {exc}', '', {'success': False, 'lifecycle_state': 'executed_failed'}))
                    _finish(scan_id, task, scan_store.STATUS_FAILED, f'Native protocol metadata enrichment incomplete: {exc}')


        # Passive intelligence collection: evidence-only, policy-controlled and recon-scoped.
        task='Passive Intelligence Collection'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        passive_intelligence = {'dns': [], 'reverse_dns': [], 'tls': [], 'certificate_transparency': [], 'findings': {}, 'relationships': [], 'dns_relationships': [], 'certificate_correlation': [], 'summary': [], 'policy': {}}
        try:
            passive_policy = load_passive_policy()
            passive_intelligence['policy'] = {'ct_lookup_enabled': bool((passive_policy.get('ct_lookup') or {}).get('enabled')), 'dns_record_types': passive_policy.get('dns_record_types') or []}
            domains = candidate_domains(target_input, all_services, web, tls_items if 'tls_items' in locals() else [])
            if enabled('passive_dns'):
                dns_rows = collect_dns(domains, passive_policy)
                reverse_rows = collect_reverse_dns(live, passive_policy)
                passive_intelligence['dns'] = dns_rows
                passive_intelligence['reverse_dns'] = reverse_rows
            if enabled('passive_tls'):
                passive_intelligence['tls'] = collect_tls(live, all_services, passive_policy)
            if enabled('certificate_transparency'):
                passive_intelligence['certificate_transparency'] = collect_certificate_transparency(domains, passive_policy)
            passive_intelligence['dns_relationships'] = build_dns_relationships(passive_intelligence.get('dns') or [], passive_intelligence.get('reverse_dns') or [])
            passive_intelligence['certificate_correlation'] = build_certificate_correlation(passive_intelligence.get('tls') or [], all_services)
            if enabled('passive_fingerprinting'):
                findings = infer_passive_findings(passive_intelligence.get('dns') or [], passive_intelligence.get('tls') or [], web, load_fingerprints())
                passive_intelligence['findings'] = findings
                passive_intelligence['relationships'] = build_relationship_graph(domains, passive_intelligence.get('dns') or [], passive_intelligence.get('tls') or [], findings, passive_intelligence.get('certificate_transparency') or [])
            passive_intelligence['summary'] = build_passive_summary(passive_intelligence)
            passive_path = write_passive_package(scan_id, passive_intelligence)
            passive_plan = scan_options.get('collector_plan') or {}
            passive_components = {
                'passive_dns': bool(passive_intelligence.get('dns') or passive_intelligence.get('reverse_dns')),
                'passive_tls': bool(passive_intelligence.get('tls')),
                'passive_fingerprinting': bool(passive_intelligence.get('findings') or passive_intelligence.get('relationships')),
                'certificate_transparency': bool(passive_intelligence.get('certificate_transparency')),
            }
            for passive_tool, component_produced in passive_components.items():
                entry = passive_plan.get(passive_tool) or {}
                if not entry.get('requested'):
                    continue
                if entry.get('policy_state') == 'blocked':
                    coverage.append(_coverage(passive_tool, scan_store.STATUS_EMPTY, 'Passive intelligence component', 'Collector was requested but blocked by effective recon policy.', '', {'success': True, 'lifecycle_state': 'disabled_policy'}))
                    continue
                if passive_tool == 'passive_tls':
                    applicable = any(_collector_service_applicable(entry, service) for service in all_services)
                elif passive_tool == 'certificate_transparency':
                    applicable = bool(domains)
                else:
                    applicable = True
                lifecycle = 'executed_evidence' if component_produced else ('executed_no_evidence' if applicable else 'not_applicable')
                note = 'Evidence retained in passive intelligence package.' if component_produced else ('Collector executed but produced no additional evidence.' if applicable else 'No applicable input was observed for this collector.')
                coverage.append(_coverage(passive_tool, scan_store.STATUS_SUCCESS if component_produced else scan_store.STATUS_EMPTY, 'Passive intelligence component', note, passive_path, {'success': True, 'lifecycle_state': lifecycle}))
            produced = bool(passive_intelligence.get('summary') or passive_intelligence.get('dns') or passive_intelligence.get('reverse_dns') or passive_intelligence.get('tls') or passive_intelligence.get('relationships'))
            cmd_parts = []
            if enabled('passive_dns'):
                cmd_parts.append('collect_dns')
            if enabled('passive_tls'):
                cmd_parts.append('collect_tls')
            if enabled('passive_fingerprinting'):
                cmd_parts.append('infer_passive_findings')
            if enabled('certificate_transparency'):
                cmd_parts.append('collect_certificate_transparency')
            native_command = 'python-native passive_intel ' + ','.join(cmd_parts or ['disabled']) + f' domains={len(domains)} hosts={len(live)}'
            native_result = _log_native_collector(scan_id, 'passive_intelligence', native_command, 'Collected passive DNS/TLS/authentication/cloud/VPN/CDN/email/relationship evidence within recon scope.', passive_path, produced)
            coverage.append(_coverage('passive_intelligence', scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, 'Passive DNS/TLS/authentication/cloud/VPN/CDN/email/relationship intelligence', f'{len(passive_intelligence.get("summary") or [])} passive summary item(s) retained.', passive_path, native_result))
            _add_raw(raw, 'passive_intelligence', '', '', passive_path, 'json', produced)
            scan_store.audit_event(scan_id, 'system', 'passive_intelligence_collected', {'summary_count': len(passive_intelligence.get('summary') or []), 'ct_enabled': bool((passive_policy.get('ct_lookup') or {}).get('enabled'))})
            _publish_partial(scan_id, passive_intelligence=passive_intelligence)
            _finish(scan_id, task, scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, f'{len(passive_intelligence.get("summary") or [])} passive intelligence summary item(s) retained')
        except Exception as exc:
            scan_store.log(scan_id, f'Passive intelligence collection incomplete: {exc}', 'WARN')
            _finish(scan_id, task, scan_store.STATUS_FAILED, f'Passive intelligence collection incomplete: {exc}')


        # 16 Evidence consolidation
        task='Evidence Consolidation'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        smb_version_evidence_items = list(smb or [])
        smb_version_evidence_items.extend(list((modern_active_validation or {}).get('smb_host_identity') or []))
        smb_version_evidence_items.extend([
            item for item in (service_level_checks or [])
            if isinstance(item, dict) and str(item.get('tool') or '') in {'smb_host_identity', 'smb_protocol_security'}
        ])
        all_services=_merge_smb_version_evidence(all_services, smb_version_evidence_items)

        all_services = _attach_discovery_observed_identities(all_services, discovery_evidence)
        all_services = _attach_web_observed_identities(all_services, web)
        all_services=_normalise_service_rows(all_services)
        tls_fingerprint_rows = list((modern_active_validation or {}).get('tls_intelligence') or []) + list((passive_intelligence or {}).get('tls') or [])
        all_services, service_fingerprints = _apply_service_fingerprints(
            all_services,
            web,
            smb,
            ssh_crypto_profiles,
            tls_fingerprint_rows,
            service_level_checks,
        )
        # Fingerprint confidence is advisory only.  Official structured CVE
        # matching is never suppressed merely because recon confidence is low;
        # downstream validation receives the evidence and any contradictions.
        cve_skipped_services: list[dict[str, Any]] = []
        fingerprint_advisories = [
            {
                'host': service.get('host'), 'port': service.get('port'), 'protocol': service.get('protocol'),
                'service': service.get('service'), 'product': service.get('product'), 'version': service.get('version'),
                'confidence_score': service.get('confidence_score', 0.0),
                'contradictions': service.get('contradictions') or [],
                'note': 'Fingerprint confidence is advisory; Candidate CVE lookup was not suppressed.',
            }
            for service in all_services if not service.get('recommended_for_cve')
        ]
        security_observations=_build_security_observations(all_services, smb, web)
        observed_security_evidence = _build_observed_security_evidence(service_level_checks, modern_active_validation)
        observed_security_conditions = [row for row in observed_security_evidence if _report_worthy_observation(str(row.get('check') or ''), str(row.get('evidence') or ''), str(row.get('source_kind') or 'field'))]
        evidence_gaps=[{'host':s.get('host'),'port':s.get('port'),'protocol':s.get('protocol'),'service':s.get('service'),'gaps':evidence_gaps_for_service(s)} for s in all_services if evidence_gaps_for_service(s)]
        fingerprints_path = scan_store.scan_path(f'service_fingerprints_{scan_id}.json')
        fingerprints_path.write_text(json.dumps(service_fingerprints, indent=2, default=str), encoding='utf-8')
        _add_raw(raw, 'service_fingerprint_consensus', '', '', str(fingerprints_path), 'json', True)
        # Optional operator-exported Windows patch evidence. This collector
        # reads local JSON only and never authenticates to or modifies a target.
        task='Windows Patch Evidence Collection'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        if enabled('windows_patch_inventory'):
            patch_successes = 0
            patch_failures = 0
            timeout_seconds = int(collector_setting(scan_options.get('collector_plan') or {}, 'windows_patch_inventory', 'timeout_seconds', 45) or 45)
            for host in live:
                applicability, applicability_reason = windows_target_applicability(host_identity_map.get(str(host)) or host_identity_map.get(host) or [])
                if applicability == 'not_applicable':
                    inventory = {
                        'collector': 'windows_patch_inventory', 'host': str(host), 'ok': False,
                        'status': 'not_applicable', 'lifecycle_state': 'not_applicable',
                        'message': applicability_reason, 'mutates_target': False,
                    }
                else:
                    inventory = collect_windows_patch_inventory(host, timeout_seconds=timeout_seconds)
                    inventory['precollection_applicability'] = applicability
                    inventory['precollection_applicability_reason'] = applicability_reason
                windows_patch_inventories.append(inventory)
                safe_host = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(host))
                patch_path = scan_store.scan_path(f'windows_patch_inventory_{scan_id}_{safe_host}.json')
                patch_path.write_text(json.dumps(inventory, indent=2, default=str), encoding='utf-8')
                _add_raw(raw, 'windows_patch_inventory', host, 'host', str(patch_path), 'json', bool(inventory.get('ok')))
                identity = inventory_host_identity(inventory, str(patch_path))
                if identity:
                    merge_host_identity_map(host_identity_map, [identity])
                    patch_successes += 1
                elif str(inventory.get('lifecycle_state') or '') == 'executed_failed':
                    patch_failures += 1
                coverage_result = {
                    'success': str(inventory.get('lifecycle_state') or '') != 'executed_failed',
                    'returncode': -1 if str(inventory.get('lifecycle_state') or '') == 'executed_failed' else 0,
                    'command': f'python-native: local Windows inventory lookup host={host}',
                    'stdout': json.dumps(inventory, indent=2, default=str),
                    'stderr': '',
                    'error': '',
                    'output_file': str(patch_path),
                    'lifecycle_state': inventory.get('lifecycle_state') or ('executed_evidence' if inventory.get('ok') else 'executed_no_evidence'),
                }
                coverage.append(_coverage(
                    'windows_patch_inventory',
                    scan_store.STATUS_SUCCESS if inventory.get('ok') else (scan_store.STATUS_FAILED if coverage_result['lifecycle_state'] == 'executed_failed' else scan_store.STATUS_EMPTY),
                    'Operator-supplied Windows OS build and installed KB evidence',
                    f"{host}: {inventory.get('message') or inventory.get('status') or 'patch inventory evidence retained'}",
                    str(patch_path),
                    coverage_result,
                ))
            patch_task_status = scan_store.STATUS_SUCCESS if patch_successes else (scan_store.STATUS_FAILED if patch_failures else scan_store.STATUS_EMPTY)
            _finish(scan_id, task, patch_task_status, f'{patch_successes} host(s) produced local Windows patch evidence; {patch_failures} processing failure(s).')
        else:
            coverage.append(_coverage('windows_patch_inventory', scan_store.STATUS_EMPTY, 'Operator-supplied Windows OS build and installed KB evidence', 'Local inventory collection was not selected by the operator.', '', {'success': True, 'lifecycle_state': 'disabled_operator'}))
            _finish(scan_id, task, scan_store.STATUS_EMPTY, 'Local Windows patch inventory was not selected by the operator.')

        # Resume the consolidation lifecycle task that the optional authenticated
        # collector temporarily interrupted.
        task='Evidence Consolidation'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        windows_identity_resolution_diagnostics = (
            _resolve_windows_build_product_candidates(host_identity_map)
        )
        host_os_inventory = host_identity_inventory(host_identity_map)
        host_os_gaps = host_identity_gaps(host_identity_map, live)
        # Candidate CVE matching may consume precise probabilistic OS hypotheses,
        # but the displayed/established OS remains separate. All raw/conflicting
        # observations stay in host_identity_inventory for audit and reporting.
        flat_host_os_identities = [
            dict(identity)
            for row in host_os_inventory
            for identity in (row.get('candidate_identities') or [])
        ]
        platform_components = platform_component_inventory(all_services)
        protocol_component_observations = _build_protocol_component_observations(
            service_level_checks,
            scan_options.get('collector_plan') or {},
        )
        reported_components = list(platform_components)
        component_signatures = {
            (str(row.get('host') or ''), int(row.get('port') or 0), str(row.get('protocol') or ''), str(row.get('product') or ''), str(row.get('version') or ''))
            for row in reported_components
        }
        for observation in protocol_component_observations:
            display_row = dict(observation)
            display_row['kind'] = str(display_row.get('identity_kind') or 'protocol_component')
            display_row['product'] = str(display_row.get('component') or '')
            display_row['sources'] = list(display_row.get('evidence_sources') or [])
            display_row.setdefault('cpe', [])
            signature = (
                str(display_row.get('host') or ''), int(display_row.get('port') or 0),
                str(display_row.get('protocol') or ''), str(display_row.get('product') or ''),
                str(display_row.get('version') or ''),
            )
            if signature not in component_signatures:
                component_signatures.add(signature)
                reported_components.append(display_row)
        normalised={'hosts':live,'host_identity_inventory':host_os_inventory,'host_identity_gaps':host_os_gaps,'windows_identity_resolution_diagnostics':windows_identity_resolution_diagnostics,'platform_component_identities':reported_components,'protocol_component_observations':protocol_component_observations,'services':all_services,'service_fingerprints':service_fingerprints,'cve_skipped_services':cve_skipped_services,'fingerprint_advisories':fingerprint_advisories,'firewall_posture':list(firewall_posture_by_host.values()),'parser_warnings':parser_warnings,'environment_intelligence':environment_intelligence,'attack_surface_objectives':selected_objectives,'evidence_gaps':evidence_gaps,'web':web,'smb':smb,'snmp':snmp,'ssh':ssh_items,'ssh_crypto_profiles':ssh_crypto_profiles,'ldap':ldap_items,'tls':tls_items,'rdp':rdp_items,'credential_validation':credential_validation_items,'service_level_checks':service_level_checks,'security_observations':security_observations,'observed_security_conditions':observed_security_conditions,'observed_security_evidence':observed_security_evidence,'passive_intelligence':passive_intelligence,'passive_local_inventory': locals().get('passive_local_inventory', {}),'modern_active_validation':modern_active_validation,'windows_patch_inventory':windows_patch_inventories,'evidence_recovery':evidence_recovery_summary}
        p=scan_store.scan_path(f'normalised_{scan_id}.json'); p.write_text(json.dumps(normalised, indent=2, default=str), encoding='utf-8')
        # Normalised evidence is already written as formatted JSON. Internal formatting helpers are not shown as user-facing recon tools.
        _add_raw(raw,'python_normaliser','','',str(p),'json',True)
        _publish_partial(scan_id, service_inventory=all_services, host_identity_inventory=host_os_inventory, host_identity_gaps=host_os_gaps, platform_component_identities=reported_components, protocol_component_observations=protocol_component_observations, service_fingerprints=service_fingerprints, cve_skipped_services=cve_skipped_services, fingerprint_advisories=fingerprint_advisories, firewall_posture=list(firewall_posture_by_host.values()), parser_warnings=parser_warnings, ssh_crypto_profiles=ssh_crypto_profiles)
        _finish(scan_id, task, scan_store.STATUS_SUCCESS, f'{len(all_services)} service record(s) normalised; {len(evidence_gaps)} evidence gap item(s) retained')
        _finish(scan_id, 'Evidence Gap Review', scan_store.STATUS_SUCCESS if evidence_gaps else scan_store.STATUS_EMPTY, f'{len(evidence_gaps)} evidence gap item(s) identified')

        # 17 MITRE matching
        task='CVE Review'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        mitre = mitre_status()
        nvd_source_at_scan_start = dict(mitre.get('nvd_enrichment') or nvd_status())
        mitre['nvd_enrichment_at_scan_start'] = dict(nvd_source_at_scan_start)
        mitre["windows_advisory"] = windows_advisory_status()
        cve_matcher_diagnostics: list[dict[str, Any]] = list(
            windows_identity_resolution_diagnostics
        )
        cve_matches, cve_review_candidates = _match_cves(
            all_services,
            cve_matcher_diagnostics,
            flat_host_os_identities,
            windows_patch_inventories,
            protocol_component_observations,
            return_review_candidates=True,
        )
        if not mitre.get('available'):
            cve_matcher_diagnostics.append({
                'reason': 'cve_program_index_unavailable',
                'matcher_status': 'degraded',
                'index_file': mitre.get('index_file'),
                'rebuild_command': mitre.get('rebuild_command'),
                'detail': 'CVE Program candidate generation was unavailable. NVD is enrichment-only and cannot create replacement Candidate CVEs.',
            })
        # Microsoft remediation intelligence augments already-canonical Windows
        # host-OS CVE references only. It never creates a CVE match and never
        # treats a missing KB alone as proof of vulnerability.
        if windows_patch_inventories and cve_matches:
            windows_patch_assessments, msrc_patch_diagnostics = enrich_windows_patch_states(
                cve_matches,
                windows_patch_inventories,
                msrc_lookup_cve_remediations,
            )
            if windows_patch_assessments:
                patch_assessment_path = scan_store.scan_path(f'windows_patch_assessments_{scan_id}.json')
                patch_assessment_path.write_text(json.dumps(windows_patch_assessments, indent=2, default=str), encoding='utf-8')
                _add_raw(raw, 'msrc_windows_patch_assessment', '', 'host', str(patch_assessment_path), 'json', True)

        nvd_cvss_enrichment_diagnostics: list[dict[str, Any]] = []
        # NVD is exact-ID enrichment only. It receives only CVE IDs already
        # generated by the CVE Program Candidate CVE engine and cannot change
        # the candidate set.
        candidate_ids_before_nvd = {
            str(row.get('cve_id') or '').upper()
            for row in cve_matches if row.get('cve_id')
        }
        _enrich_missing_cvss_from_nvd(cve_matches, nvd_cvss_enrichment_diagnostics)
        candidate_ids_after_nvd = {
            str(row.get('cve_id') or '').upper()
            for row in cve_matches if row.get('cve_id')
        }
        if candidate_ids_before_nvd != candidate_ids_after_nvd:
            raise RuntimeError('NVD enrichment changed the Candidate CVE set; enrichment must be exact-ID metadata only.')
        # CISA KEV is post-candidate threat intelligence only. It cannot create,
        # suppress, or promote a CVE reference.
        kev_source = enrich_cisa_kev_rows(cve_review_candidates)
        selected_cvss_version = str((scan_options.get('cvss_selection') or {}).get('version') or '3.1')
        # CVSS starts here, after applicability/candidate states already exist.
        # It may score/order the review, but it cannot promote a candidate.
        cvss_scoring_verifiers = cvss_verifier_status()
        apply_cvss_selection(cve_review_candidates, selected_cvss_version)
        _refresh_cve_display_context(cve_review_candidates)
        cve_matches_by_host = _group_cve_matches_by_host(cve_matches)
        cve_review_candidates_by_host = _group_cve_matches_by_host(cve_review_candidates)
        cve_review_summary = _build_cve_review_summary(cve_matches, cve_review_candidates, cve_matcher_diagnostics)
        if isinstance(mitre.get('windows_advisory'), dict):
            mitre['windows_advisory']['candidate_context_matches'] = int(cve_review_summary.get('windows_build_context_candidates') or 0)
            mitre['windows_advisory']['custom_version_resolutions'] = int(cve_review_summary.get('vendor_version_resolutions') or 0)
        cve_matcher_audit = _build_cve_matcher_audit(cve_matcher_diagnostics)
        nvd_source = nvd_status()
        nvd_source['scan_start'] = dict(nvd_source_at_scan_start)
        nvd_source['scan_completion'] = {
            'cached_cve_metric_queries': int(nvd_source.get('cached_cve_metric_queries') or 0),
            'cached_cve_context_queries': int(nvd_source.get('cached_cve_context_queries') or 0),
        }
        nvd_source['metric_queries_added_during_assessment'] = max(
            0, int(nvd_source.get('cached_cve_metric_queries') or 0) - int(nvd_source_at_scan_start.get('cached_cve_metric_queries') or 0)
        )
        nvd_source['context_queries_added_during_assessment'] = max(
            0, int(nvd_source.get('cached_cve_context_queries') or 0) - int(nvd_source_at_scan_start.get('cached_cve_context_queries') or 0)
        )
        mitre['nvd_enrichment'] = dict(nvd_source)
        candidate_generation_state = str(cve_review_summary.get('candidate_generation_state') or 'available')
        matcher_degraded = any(str(item.get('matcher_status') or '').lower() in {'error', 'degraded'} for item in cve_matcher_diagnostics)
        cve_review_completeness = (
            'unavailable' if candidate_generation_state == 'unavailable'
            else ('degraded' if matcher_degraded else 'complete')
        )
        if candidate_generation_state == 'unavailable':
            cve_task_status = scan_store.STATUS_FAILED
            cve_task_message = (
                'Candidate CVE generation unavailable because the configured CVE Program index was not available. '
                'NVD enrichment cannot create replacement candidates.'
            )
        else:
            cve_task_status = scan_store.STATUS_SUCCESS if cve_review_candidates else scan_store.STATUS_EMPTY
            cve_task_message = (
                f"{len(cve_matches)} unvalidated Candidate CVE item(s); "
                f"{cve_review_summary.get('structured_records_evaluated', 0)} structured record(s) evaluated; "
                f"{len(cve_matcher_diagnostics)} matcher diagnostic item(s); review completeness={cve_review_completeness}."
            )
        _finish(
            scan_id, task,
            cve_task_status,
            cve_task_message,
        )
        _publish_partial(
            scan_id,
            cve_matches=cve_matches, cve_matches_by_host=cve_matches_by_host,
            cve_review_candidates=cve_review_candidates, cve_review_candidates_by_host=cve_review_candidates_by_host,
            cve_review_summary=cve_review_summary, cve_matcher_audit=cve_matcher_audit,
            host_identity_inventory=host_os_inventory, host_identity_gaps=host_os_gaps,
            platform_component_identities=reported_components, cve_skipped_services=cve_skipped_services,
            cve_matcher_diagnostics=cve_matcher_diagnostics, mitre_source=mitre,
            windows_patch_inventory=windows_patch_inventories, windows_patch_assessments=windows_patch_assessments,
            msrc_patch_diagnostics=msrc_patch_diagnostics, msrc_source=msrc_status(), kev_source=kev_source,
            nvd_source=nvd_source, cve_review_completeness=cve_review_completeness,
            cve_review_status=(
                'Candidate CVE generation unavailable — CVE Program index not loaded'
                if candidate_generation_state == 'unavailable'
                else f'{len(cve_review_candidates)} Candidate CVE item(s) generated; downstream validation pending'
            ),
        )

        # 18 Caldera Handoff
        task='Handoff Preparation'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        exploit_validation_candidates=_build_exploit_validation_candidates(all_services, cve_matches, security_observations, web_summary if 'web_summary' in locals() else {}, smb_summary if 'smb_summary' in locals() else {})
        # Detailed readiness is finalised during report preparation after web/SMB summaries are built.
        caldera_handoff={'enabled_for_execution': False, 'note':'Recon package prepared for teammate validation/exploitation/AI/CALDERA modules. Recon does not assert CVE applicability, execute exploits, or obtain access.', 'cve_semantics':'candidate_unvalidated', 'validation_boundary':'Downstream validation decides applicability/exploitability.', 'host_os_identities': flat_host_os_identities, 'services': [{'host':s['host'],'port':s['port'],'protocol':s['protocol'],'service':s['service'],'product':s.get('product',''),'version':s.get('version',''),'confidence_score':s.get('confidence_score',0.0),'recommended_for_cve':bool(s.get('recommended_for_cve',False))} for s in all_services], 'cve_matches': cve_matches, 'cve_matches_by_host': cve_matches_by_host, 'exploit_validation_candidates': exploit_validation_candidates}
        _finish(scan_id, task, scan_store.STATUS_SUCCESS, 'Caldera handoff context prepared')

        # 19 Report
        task='Report Preparation'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        public_coverage = _public_tool_coverage(_sort_coverage(coverage))

        # Preserve operator request, terminal execution, and reason as separate
        # fields for Phase 3 host-level evidence controls. Phase 2 mandatory
        # subnet discovery is retained in workflow/command history and is not
        # confused with this optional Phase 3 configuration.
        host_discovery_requested = (scan_options.get('host_discovery') or {}).get('effective') or {}
        host_discovery_tool_map = {
            'arp_discovery': 'arp-scan',
            'icmp_echo': 'ping',
            'nmap_host_discovery': 'nmap_host_discovery',
            'reverse_dns': 'dig',
            'route_trace': 'route_trace',
        }
        host_discovery_execution: dict[str, Any] = {}
        for setting_name, tool_name in host_discovery_tool_map.items():
            rows = [row for row in public_coverage if str(row.get('tool') or '') == tool_name]
            lifecycle_states = [str(row.get('lifecycle_state') or '') for row in rows]
            executed = any(state.startswith('executed_') for state in lifecycle_states)
            produced_evidence = any(state == 'executed_evidence' for state in lifecycle_states)
            host_discovery_execution[setting_name] = {
                'tool': tool_name,
                'requested': bool(host_discovery_requested.get(setting_name)),
                'executed': executed,
                'produced_evidence': produced_evidence,
                'statuses': [str(row.get('status') or '') for row in rows],
                'lifecycle_states': lifecycle_states,
                'notes': [str(row.get('note') or '') for row in rows if row.get('note')],
                'commands': [str(row.get('command') or '') for row in rows if row.get('command')],
            }
        service_summary = _build_service_summary(all_services, cve_matches)
        web_summary = _summarise_web_inventory(web)
        smb_summary = _summarise_smb_inventory(smb)
        contamination_indicators = _detect_cross_host_evidence_contamination(smb_summary)
        if contamination_indicators:
            environment_context_indicators.extend(contamination_indicators)
        key_exposure_indicators = _build_key_exposure_indicators(security_observations)
        service_workbench = _build_service_workbench(all_services, cve_matches, security_observations, web_summary, smb_summary, service_level_checks)
        attack_surface_sections = _build_attack_surface_sections(service_workbench)
        follow_up_objectives = _build_follow_up_objectives(open_map, environment_context_indicators, all_services)
        authentication_surface_readiness = _build_authentication_surface_readiness(all_services, environment_intelligence, smb_summary, service_level_checks, credential_validation_items)
        web_exploitation_readiness = _build_web_exploitation_readiness(all_services, web_summary, web)
        enumeration_intelligence = build_enumeration_intelligence(
            all_services,
            modern_active_validation=modern_active_validation,
            passive_intelligence=passive_intelligence,
            web_inventory=web,
            smb_summary=smb_summary,
        )
        knowledge_graph_path = scan_store.result_path(f'{scan_id}_knowledge_graph.json')
        knowledge_graph_path.parent.mkdir(parents=True, exist_ok=True)
        knowledge_graph_path.write_text(json.dumps(enumeration_intelligence.get('knowledge_graph') or {}, indent=2, default=str), encoding='utf-8')
        enumeration_intelligence['knowledge_graph_file'] = str(knowledge_graph_path)
        _add_raw(raw, 'knowledge_graph', '', '', str(knowledge_graph_path), 'json', True)
        enum_path = scan_store.result_path(f'{scan_id}_enumeration_intelligence.json')
        enum_path.write_text(json.dumps(enumeration_intelligence, indent=2, default=str), encoding='utf-8')
        enumeration_intelligence['enumeration_intelligence_file'] = str(enum_path)
        _add_raw(raw, 'enumeration_intelligence', '', '', str(enum_path), 'json', True)
        operational_maturity = build_operational_maturity_package(
            scan_id,
            target_input,
            all_services,
            raw,
            modern_active_validation,
            passive_intelligence,
            enumeration_intelligence,
            scan_store.get(scan_id).get('started_at') if scan_store.get(scan_id) else None,
        )
        _add_raw(raw, 'operational_maturity', '', '', operational_maturity.get('operational_maturity_file', ''), 'json', True)
        exploit_validation_candidates = _dedupe_dicts((exploit_validation_candidates or []) + authentication_surface_readiness + web_exploitation_readiness, ('host','port','service','category','candidate_type'))
        caldera_handoff['exploit_validation_candidates'] = exploit_validation_candidates
        caldera_handoff['authentication_surface_readiness'] = authentication_surface_readiness
        caldera_handoff['web_exploitation_readiness'] = web_exploitation_readiness
        decision_register = build_decision_register(all_services, selected_objectives, environment_context_indicators, evidence_gaps, enterprise_review_policy)
        evidence_manifest = build_evidence_manifest(scan_id, raw)
        enterprise_readiness = build_enterprise_readiness_summary(scope_validation, decision_register, evidence_manifest, enterprise_review_policy)
        scan_store.audit_event(scan_id, 'system', 'enterprise_readiness_compiled', {'decision_register_count': len(decision_register), 'evidence_manifest': evidence_manifest.get('manifest_file')})
        tcp_selection = ((scan_options or {}).get('port_selection') or {}).get('tcp') or {}
        udp_selection = ((scan_options or {}).get('port_selection') or {}).get('udp') or {}
        default_untested_reasons = {
            'tcp': (
                'disabled_operator' if not enabled('tcp_discovery')
                else 'tool_unavailable' if not nmap
                else 'policy_stop_condition' if any(acl_pause_requested(host) for host in live)
                else 'not_executed'
            ),
            'udp': (
                'disabled_operator' if not enabled('udp_discovery')
                else 'tool_unavailable' if not nmap
                else 'policy_stop_condition' if any(acl_pause_requested(host) for host in live)
                else 'not_executed'
            ),
        }
        endpoint_coverage = build_endpoint_coverage(
            live_hosts=live,
            scan_options=scan_options,
            batches=endpoint_execution_batches,
            default_untested_reasons=default_untested_reasons,
        )
        tcp_totals = endpoint_coverage['tcp']['totals']
        udp_totals = endpoint_coverage['udp']['totals']
        tcp_executed_total = int(tcp_totals['scanned'])
        udp_executed_total = int(udp_totals['scanned'])
        tcp_configured_total = int(tcp_totals['configured'])
        udp_configured_total = int(udp_totals['configured'])
        coverage_limitations: list[str] = []
        if tcp_executed_total < tcp_configured_total:
            coverage_limitations.append(
                f'{tcp_configured_total - tcp_executed_total} configured TCP host/port checks were not executed; see scan assurance for untested coverage.'
            )
        if udp_executed_total < udp_configured_total:
            coverage_limitations.append(
                f'{udp_configured_total - udp_executed_total} configured UDP host/port checks were not executed; see scan assurance for untested coverage.'
            )
        scan_coverage = {
            'label': 'Operator-selected port coverage',
            'full_tcp_sweep_performed': bool(
                str(tcp_selection.get('mode') or '').lower() == 'full'
                and tcp_configured_total > 0
                and tcp_executed_total == tcp_configured_total
            ),
            'tcp': endpoint_coverage['tcp']['hosts'],
            'udp': endpoint_coverage['udp']['hosts'],
            'protocol_totals': {
                'tcp': tcp_totals,
                'udp': udp_totals,
            },
            'invariants': {
                'tcp': endpoint_coverage['tcp']['invariant'],
                'udp': endpoint_coverage['udp']['invariant'],
            },
            'execution_batches': endpoint_execution_batches,
            'limitations': coverage_limitations,
        }
        collector_coverage_matrix = _build_collector_coverage_matrix(all_services, scan_options, public_coverage, raw)
        unresolved_identity_queue = _build_unresolved_identity_queue(all_services)
        # NVD source was snapshotted before and after CVE/CVSS enrichment above.
        msrc_source = msrc_status()

        scan_summary = _build_scan_summary(
            targets_requested=len(targets),
            live_hosts=live,
            scan_options=scan_options,
            scanned_tcp_ports_by_host=completed_tcp_ports_by_host,
            scanned_udp_ports_by_host=completed_udp_ports_by_host,
            discovery_evidence=discovery_evidence,
            open_map=open_map,
            all_services=all_services,
            public_coverage=public_coverage,
            cve_matches=cve_matches,
        )
        scan_summary['cve_candidate_review'] = copy.deepcopy(cve_review_summary)
        scan_summary.setdefault('cve_review', {}).update({
            'generation_state': str(cve_review_summary.get('candidate_generation_state') or 'available'),
            'candidate_cves_retained': int(cve_review_summary.get('candidate_cves_retained') or 0),
            'unique_candidate_ids': int(cve_review_summary.get('unique_candidate_ids') or 0),
            'target_candidate_records': int(cve_review_summary.get('target_candidate_records') or 0),
            'identity_correlations_retained': int(cve_review_summary.get('identity_correlations_retained') or 0),
        })
        canonical_cve_contract = {
            'version': 'scanner-candidate-v6',
            'source': OFFICIAL_CVE_SOURCE,
            'vulnerability_scoring': {
                'selection': scan_options.get('cvss_selection') or {'version': '3.1', 'label': 'CVSS 3.1'},
                'stage': 'post_match_only',
                'verifiers': cvss_scoring_verifiers,
                'rule': 'CVSS 3.1 and 4.0 enrich already-generated Candidate CVEs only; scoring cannot create, suppress or validate a candidate.',
            },
            'candidate_cve_references': cve_matches,
            'baseline_cve_references': cve_matches,  # compatibility alias
            'cve_references': cve_matches,           # compatibility alias
            'cve_references_by_host': cve_matches_by_host,
            'review_candidates': cve_review_candidates,
            'review_candidates_by_host': cve_review_candidates_by_host,
            'review_summary': cve_review_summary,
            'held_diagnostics': cve_matcher_diagnostics,
            'diagnostics': cve_matcher_diagnostics,
            'review_completeness': cve_review_completeness,
            'candidate_semantics': 'Every CVE row is an unvalidated Candidate CVE generated from CVE Program structured affected data.',
            'nvd_rule': 'NVD receives exact candidate CVE IDs for metadata/CVSS enrichment only and cannot add, remove, promote or suppress candidates.',
            'downstream_rule': (
                'Consume scanner-owned Candidate CVEs as validation inputs only. '
                'Downstream validation decides applicability/exploitability before any approved execution.'
            ),
        }
        selected_plan_readiness = preflight_readiness
        effective_settings = {
            'version': 'scanner-effective-settings-v1',
            'advanced': scan_options.get('advanced_settings_provenance') or {},
            'collectors': {
                collector_id: entry.get('setting_provenance') or {}
                for collector_id, entry in (scan_options.get('collector_plan') or {}).items()
                if entry.get('requested')
            },
            'host_discovery': {
                'requested': (scan_options.get('host_discovery') or {}).get('requested') or {},
                'effective': (scan_options.get('host_discovery') or {}).get('effective') or {},
                'policy_blocked': (scan_options.get('host_discovery') or {}).get('policy_blocked') or [],
            },
            'service_identity': scan_options.get('service_identity') or {},
            'port_selection': scan_options.get('port_selection') or {},
        }
        result_state = derive_result_state(
            readiness=selected_plan_readiness,
            services=all_services,
            baseline_cves=cve_matches,
            held_diagnostics=cve_matcher_diagnostics,
            cve_source_available=bool(mitre.get('available')),
        )
        current_scan = scan_store.get(scan_id) or {}
        workflow = dict(current_scan.get('workflow') or {})
        phase_results = dict(workflow.get('phase_results') or {})
        assessment_phase = dict(phase_results.get('assessment') or {})
        assessment_phase.update({
            'status': 'completed',
            'targets': list(targets),
            'target_count': len(targets),
            'service_count': len(all_services),
            'cve_count': len(cve_matches),
        })
        phase_results['assessment'] = assessment_phase
        workflow.update({
            'assessment_targets': list(targets),
            'assessment_target': target_input,
            'phase_results': phase_results,
        })
        package={'scan_id':scan_id,'target_input':target_input,'workflow':workflow,'phase_results':phase_results,'internal_host_inventory':workflow.get('discovered_hosts') or [],'scan_options':scan_options,'scan_coverage':scan_coverage,'scan_summary':scan_summary,'hosts':live,'host_identity_inventory':host_os_inventory,'host_identity_gaps':host_os_gaps,'host_os_identities':flat_host_os_identities,'platform_component_identities':reported_components,'protocol_component_observations':protocol_component_observations,'fingerprint_advisories':fingerprint_advisories,'scope_validation':scope_validation,'enterprise_readiness':enterprise_readiness,'passive_intelligence':passive_intelligence,'passive_local_inventory': locals().get('passive_local_inventory', {}),'modern_active_validation':modern_active_validation,'enumeration_intelligence':enumeration_intelligence,'operational_maturity':operational_maturity,'decision_register':decision_register,'evidence_manifest':evidence_manifest,'mitre_source':mitre,'nvd_source':nvd_source,'msrc_source':msrc_source,'kev_source':kev_source,'windows_patch_inventory':windows_patch_inventories,'windows_patch_assessments':windows_patch_assessments,'msrc_patch_diagnostics':msrc_patch_diagnostics,'tool_coverage':public_coverage,'host_discovery_execution':host_discovery_execution,'collector_coverage_matrix':collector_coverage_matrix,'unresolved_identity_queue':unresolved_identity_queue,'service_inventory':all_services,'service_summary':service_summary,'service_workbench':service_workbench,'attack_surface_sections':attack_surface_sections,'cve_matches':cve_matches,'cve_matches_by_host':cve_matches_by_host,'cve_findings_by_target':cve_matches_by_host,'cve_review_candidates':cve_review_candidates,'cve_review_candidates_by_host':cve_review_candidates_by_host,'cve_review_summary':cve_review_summary,'cve_matcher_audit':cve_matcher_audit,'baseline_cves':canonical_cve_contract['candidate_cve_references'],'cve_matcher_diagnostics':cve_matcher_diagnostics,'cve_review_completeness':cve_review_completeness,'nvd_cvss_enrichment_diagnostics':nvd_cvss_enrichment_diagnostics,'vulnerability_scoring':{'selection': scan_options.get('cvss_selection') or {'version':'3.1','label':'CVSS 3.1'}, 'stage':'post_match_only', 'verifiers':cvss_scoring_verifiers, 'rule':'CVSS/NVD enrichment never changes scan execution, evidence recovery, identity, Candidate CVE count, or validation state.'},'evidence_recovery':evidence_recovery_summary,'canonical_cve_contract':canonical_cve_contract,'service_level_checks':service_level_checks,'security_relevant_observations':security_observations,'observed_security_conditions':observed_security_conditions,'observed_security_evidence':observed_security_evidence,'key_exposure_indicators':key_exposure_indicators,'tcp_service_count':len([x for x in all_services if x.get('protocol')=='tcp']),'udp_service_count':len([x for x in all_services if x.get('protocol')=='udp']),'web_inventory':web,'web_summary':web_summary,'smb_inventory':smb,'smb_summary':smb_summary,'raw_evidence_index':raw,'caldera_handoff':caldera_handoff,'environment_summary':_build_environment_summary(environment_intelligence, environment_context_indicators),'attack_surface_objectives':selected_objectives,'evidence_gaps':evidence_gaps,'exploit_validation_candidates':exploit_validation_candidates,'authentication_surface_readiness':authentication_surface_readiness,'web_exploitation_readiness':web_exploitation_readiness,'suggested_follow_up_objectives':follow_up_objectives,'escalation_paused':False}
        package.update({
            'result_state': result_state,
            'selected_plan_readiness': selected_plan_readiness,
            'effective_settings': effective_settings,
            'service_fingerprints': service_fingerprints,
            'cve_skipped_services': cve_skipped_services,
            'parser_warnings': parser_warnings,
            'firewall_posture': list(firewall_posture_by_host.values()),
            'ssh_crypto_profiles': ssh_crypto_profiles,
            'escalation_paused': any(acl_pause_requested(host) for host in live),
        })
        package['pentester_summary'] = _build_pentester_summary(package)
        analysis_fields = {}
        try:
            from mapping.technique_mapper import map_vulnerabilities, select_attack_mode
            from ai.technique_planner import generate_ai_technique_plan

            services_by_host = {}
            for service in all_services:
                host = str(service.get('host') or target_input or 'Unknown')
                services_by_host.setdefault(host, []).append({
                    'port': service.get('port'),
                    'protocol': service.get('protocol', 'tcp'),
                    'state': service.get('state', 'open'),
                    'service': service.get('service', ''),
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'extrainfo': service.get('extrainfo', ''),
                    'cpe': service.get('cpe', []),
                    'scripts': service.get('scripts', []),
                })
            parsed_for_mapping = {
                'target_ip': target_input,
                'os': 'Unknown',
                'hosts': [
                    {'address': {'primary': host}, 'os': {'name': 'Unknown'}, 'port_findings': ports}
                    for host, ports in services_by_host.items()
                ],
                'ports': [
                    {
                        'port': service.get('port'),
                        'protocol': service.get('protocol', 'tcp'),
                        'state': service.get('state', 'open'),
                        'service': service.get('service', ''),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'extrainfo': service.get('extrainfo', ''),
                    }
                    for service in all_services
                ],
            }
            mapping_result = map_vulnerabilities(parsed_for_mapping)
            mapping_result = _canonicalise_downstream_mapping(mapping_result, cve_matches)
            mode = str(scan_options.get('technique_mode') or 'hybrid').lower()
            ai_plan = generate_ai_technique_plan(mapping_result, preferred_mode=mode)
            selected_ids = ai_plan.get('selected_technique_ids') or []
            mode_plan = select_attack_mode(mapping_result, mode, selected_ids)
            analysis_fields = {
                'mapping': mapping_result,
                'ai_plan': ai_plan,
                'attack_plan': {
                    'mode': mode_plan.get('mode', mode),
                    'description': mode_plan.get('description', ''),
                    'techniques': mode_plan.get('attack_plan') or mode_plan.get('recommended') or [],
                    'available_techniques': mapping_result.get('recommended_techniques', []),
                },
                'technique_mode': mode,
            }
        except Exception as analysis_exc:
            logger.warning('Scan analysis post-processing failed: %s', analysis_exc)
        out=scan_store.result_path(f'{scan_id}_handoff.json'); out.write_text(json.dumps(_sanitise_export_paths(package), indent=2, default=str), encoding='utf-8')
        package['handoff_file']=str(out)
        _finish(scan_id, task, scan_store.STATUS_SUCCESS, 'Report and handoff package assembled')
        scan_store.update(scan_id,status=scan_store.STATUS_SUCCESS,workflow_stage='completed',workflow=workflow,completed_at=scan_store.now(),results=package,**analysis_fields)
        scan_store.persist(scan_id)
        _clear_pivot_targets(scan_id)
    except Exception as e:
        scan_store.log(scan_id, f'Pipeline error: {e}', 'ERROR')
        current_scan = scan_store.get(scan_id) or {}
        workflow = dict(current_scan.get('workflow') or {})
        phase_results = dict(workflow.get('phase_results') or {})
        assessment_phase = dict(phase_results.get('assessment') or {})
        failed_targets = []
        try:
            failed_targets = expand_target_input(target_input, Config.MAX_EXPANDED_TARGETS)
        except Exception:
            failed_targets = []
        assessment_phase.update({
            'status': 'failed',
            'targets': failed_targets,
            'target_count': len(failed_targets),
            'error': str(e),
        })
        phase_results['assessment'] = assessment_phase
        workflow.update({
            'assessment_targets': failed_targets,
            'assessment_target': target_input,
            'phase_results': phase_results,
        })
        scan_store.update(
            scan_id,
            status=scan_store.STATUS_FAILED,
            workflow_stage='assessment_failed',
            workflow=workflow,
            error=str(e),
            completed_at=scan_store.now(),
        )
        scan_store.persist(scan_id)
        _clear_pivot_targets(scan_id)
