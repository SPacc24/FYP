"""Pure argv builders for external commands issued by scanner-owned code.

Builders return argument lists only. They never invoke a shell, read policy, or
perform network I/O. Timing/rate/timeout values are supplied by the caller from
the already-normalised scan policy so command construction cannot silently
invent a different scan intensity.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence


def _args(values: Sequence[str] | None) -> list[str]:
    return [str(v) for v in (values or []) if str(v).strip()]


def _ports(ports: Iterable[int | str]) -> str:
    return ','.join(str(int(p)) if str(p).isdigit() else str(p) for p in ports)


def curl_get(curl_bin: str, url: str, timeout_seconds: int, max_redirects: int) -> list[str]:
    return [curl_bin, '-sS', '--max-time', str(int(timeout_seconds)), '-L', '--max-redirs', str(int(max_redirects)), str(url)]


def curl_headers(curl_bin: str, url: str, timeout_seconds: int, *, insecure: bool = False) -> list[str]:
    cmd = [curl_bin]
    if insecure:
        cmd.append('-k')
    cmd += ['-I', '-sS', '--max-time', str(int(timeout_seconds)), str(url)]
    return cmd


def tshark_passive_capture(tshark_bin: str, interface: str, duration_seconds: int, display_filter: str) -> list[str]:
    return [tshark_bin, '-i', str(interface), '-a', f'duration:{int(duration_seconds)}', '-Y', str(display_filter)]


def p0f_passive_capture(p0f_bin: str, interface: str, *, timeout_bin: str | None = None, duration_seconds: int | None = None) -> list[str]:
    cmd = [p0f_bin, '-i', str(interface), '-p']
    if timeout_bin and duration_seconds is not None:
        return [timeout_bin, str(int(duration_seconds)), *cmd]
    return cmd


def ping_echo(ping_bin: str, host: str, attempts: int, wait_seconds: int) -> list[str]:
    return [ping_bin, '-c', str(int(attempts)), '-W', str(int(wait_seconds)), str(host)]


def dig_reverse(dig_bin: str, host: str, *, timeout_seconds: int = 2, tries: int = 1) -> list[str]:
    return [dig_bin, f'+time={int(timeout_seconds)}', f'+tries={int(tries)}', '-x', str(host), '+short']


def dig_version_bind(dig_bin: str, host: str) -> list[str]:
    return [dig_bin, '+nocmd', '+noall', '+answer', '@' + str(host), 'version.bind', 'CHAOS', 'TXT']


def traceroute_path(traceroute_bin: str, host: str, max_hops: int) -> list[str]:
    return [traceroute_bin, '-n', '-m', str(int(max_hops)), '-w', '1', str(host)]


def tracepath_path(tracepath_bin: str, host: str, max_hops: int) -> list[str]:
    return [tracepath_bin, '-n', '-m', str(int(max_hops)), str(host)]


def nmap_resilient_host_discovery(
    nmap_bin: str,
    subnet: str,
    output_file: Path | str,
    *,
    interface: str = '',
) -> list[str]:
    """Build a complementary bounded IP-layer host-discovery pass.

    The normal local Nmap discovery may prefer ARP on Ethernet. This second
    pass disables ARP discovery so ICMP/TCP probes can independently retain
    hosts that do not answer the first method.
    """
    cmd = [
        nmap_bin,
        '-sn',
        '-n',
        '--disable-arp-ping',
        '-PE',
        '-PS22,80,443,445,3389',
        '-PA80,443',
        '--max-retries',
        '1',
        '--host-timeout',
        '8s',
        '-oX',
        str(output_file),
    ]
    if str(interface or '').strip():
        cmd += ['-e', str(interface).strip()]
    cmd.append(str(subnet))
    return cmd


def arp_scan(arp_bin: str, host: str, *, interface: str = '') -> list[str]:
    cmd = [arp_bin]
    if str(interface or '').strip():
        cmd += ['--interface', str(interface).strip()]
    cmd.append(str(host))
    return cmd


def nmap_host_discovery(
    nmap_bin: str,
    targets: Sequence[str],
    output_file: Path | str,
    *,
    interface: str = '',
) -> list[str]:
    # Host inventory is IP-address based.  Reverse DNS is collected separately
    # when explicitly requested, so discovery itself must not block on a broken
    # or unreachable resolver supplied by the host environment.
    cmd = [nmap_bin, '-sn', '-n', '-oX', str(output_file)]
    if str(interface or '').strip():
        cmd += ['-e', str(interface).strip()]
    return [*cmd, *[str(t) for t in targets]]


def tracepath_observation(tracepath_bin: str, target: str, max_hops: int) -> list[str]:
    """Build a bounded, numeric tracepath observation command."""

    return [
        str(tracepath_bin),
        '-n',
        '-m',
        str(int(max_hops)),
        str(target),
    ]


def traceroute_observation(traceroute_bin: str, target: str, max_hops: int) -> list[str]:
    """Build a bounded, numeric traceroute observation command."""

    return [
        str(traceroute_bin),
        '-n',
        '-m',
        str(int(max_hops)),
        '-w',
        '1',
        '-q',
        '1',
        str(target),
    ]


def nmap_tcp_discovery(nmap_bin: str, host: str, ports: Iterable[int], timing: Sequence[str], output_file: Path | str) -> list[str]:
    return [nmap_bin, *_args(timing), '-p', _ports(ports), '-oX', str(output_file), str(host)]


def nmap_udp_discovery(nmap_bin: str, host: str, ports: Iterable[int], timing: Sequence[str], output_file: Path | str) -> list[str]:
    return [nmap_bin, '-Pn', '-sU', *_args(timing), '-p', _ports(ports), '-oX', str(output_file), str(host)]


def nmap_infrastructure_discovery(nmap_bin: str, host: str, ports: Iterable[int], timing: Sequence[str], output_file: Path | str) -> list[str]:
    return [nmap_bin, '-sS', '-p', _ports(ports), *[a for a in _args(timing) if a != '--open'], '-oX', str(output_file), str(host)]


def nmap_service_fingerprint(
    nmap_bin: str,
    host: str,
    ports: Iterable[int],
    version_intensity: int,
    timing: Sequence[str],
    output_file: Path | str,
    *,
    banner_script: bool = False,
    port_spec: str | None = None,
    protocol: str = 'tcp',
) -> list[str]:
    proto = str(protocol or 'tcp').strip().lower()
    transport = ['-Pn', '-sU'] if proto == 'udp' else []
    cmd = [nmap_bin, *transport, '-sV', '--version-intensity', str(int(version_intensity))]
    if banner_script:
        cmd += ['--script', 'banner']
    cmd += ['-p', str(port_spec) if port_spec is not None else _ports(ports), *_args(timing), '-oX', str(output_file), str(host)]
    return cmd


def nmap_os_fingerprint(
    nmap_bin: str,
    host: str,
    ports: Iterable[int],
    timing: Sequence[str],
    output_file: Path | str,
    *,
    max_os_tries: int = 2,
) -> list[str]:
    """Build a bounded OS fingerprint command.

    ``max_os_tries`` defaults to 2 so a single degraded sample cannot become the
    reported fingerprint set. The caller still supplies the timing profile; an
    OS-specific profile must not contain ``--scan-delay``, which overrides the
    fixed inter-probe interval Nmap's SEQ tests depend on.
    """
    tries = max(1, min(int(max_os_tries), 5))
    return [
        nmap_bin, '-Pn', '-O', '--osscan-limit', '--osscan-guess',
        '--max-os-tries', str(tries), '-p', _ports(ports),
        *_args(timing), '-oX', str(output_file), str(host),
    ]


def nmap_advertised_followup(nmap_bin: str, host: str, ports: Iterable[int], timing: Sequence[str], output_file: Path | str) -> list[str]:
    return [nmap_bin, '-Pn', '-sS', '-sV', '--version-intensity', '0', '-p', _ports(ports), *_args(timing), '-oX', str(output_file), str(host)]


def nmap_nse_collector(
    nmap_bin: str,
    host: str,
    port: int,
    scripts: Sequence[str],
    timing: Sequence[str],
    output_file: Path | str,
    *,
    protocol: str = 'tcp',
    extra_args: Sequence[str] | None = None,
) -> list[str]:
    proto = str(protocol or 'tcp').strip().lower()
    transport = ['-sU'] if proto == 'udp' else []
    return [
        nmap_bin, '-Pn', *transport, '--script', ','.join(_args(scripts)),
        '-p', str(int(port)), *_args(extra_args), *_args(timing),
        '-oX', str(output_file), str(host),
    ]


def httpx_help(httpx_bin: str) -> list[str]:
    return [httpx_bin, '-h']


def httpx_probe(httpx_bin: str, url: str, rate_limit: int, threads: int, timeout_seconds: int) -> list[str]:
    return [httpx_bin, '-json', '-title', '-tech-detect', '-status-code', '-server', '-follow-redirects', '-rl', str(int(rate_limit)), '-t', str(int(threads)), '-timeout', str(int(timeout_seconds)), '-u', str(url)]


def rpcinfo_programs(rpcinfo_bin: str, host: str) -> list[str]:
    return [rpcinfo_bin, '-p', str(host)]


def showmount_exports(showmount_bin: str, host: str) -> list[str]:
    return [showmount_bin, '-e', str(host)]


def ldapsearch_rootdse(ldapsearch_bin: str, host: str, port: int) -> list[str]:
    port = int(port)
    scheme = 'ldaps://' if port in {636, 3269} else 'ldap://'
    authority = str(host) if port in {389, 636} else f'{host}:{port}'
    return [ldapsearch_bin, '-x', '-H', scheme + authority, '-s', 'base', '+']


def pg_isready(pg_bin: str, host: str, port: int, timeout_seconds: int) -> list[str]:
    return [pg_bin, '-h', str(host), '-p', str(int(port)), '-t', str(int(timeout_seconds))]


def nuclei_safe_templates(nuclei_bin: str, urls_file: Path | str, output_file: Path | str, severities: Sequence[str], tags: Sequence[str], excluded_tags: Sequence[str], requests_per_window: int, window_seconds: int, retries: int, *, templates_dir: str = '') -> list[str]:
    cmd = [
        nuclei_bin, '-list', str(urls_file), '-jsonl', '-silent',
        '-severity', ','.join(_args(severities)), '-tags', ','.join(_args(tags)),
        '-exclude-tags', ','.join(_args(excluded_tags)),
        '-rate-limit', str(int(requests_per_window)), '-rate-limit-duration', f'{int(window_seconds)}s',
        '-retries', str(int(retries)), '-o', str(output_file),
    ]
    if str(templates_dir or '').strip():
        cmd += ['-templates', str(templates_dir).strip()]
    return cmd


def nmap_profile_scan(nmap_bin: str, target: str, ports: str, intensity: int, profile: str, output_file: Path | str) -> list[str]:
    """Build the legacy nmap_runner command without changing its public behavior."""
    cmd = [
        nmap_bin, '-Pn', '-T', str(int(intensity)), '-p', str(ports), '-oX', str(output_file),
    ]
    profile_name = str(profile or '').strip().lower()
    if profile_name == 'quick':
        cmd += ['-sV', '--version-light']
    elif profile_name == 'standard':
        cmd += ['-sV', '-sC']
    elif profile_name == 'deep':
        cmd += ['-sV', '--version-intensity', '5']
    cmd.append(str(target))
    return cmd


def git_log_head(git_bin: str, repo_dir: Path | str) -> list[str]:
    return [git_bin, '-C', str(repo_dir), 'log', '-1', '--format=%cI']


def git_clone_shallow(git_bin: str, repo_url: str, destination: Path | str) -> list[str]:
    return [git_bin, 'clone', '--depth', '1', str(repo_url), str(destination)]


def git_pull_ff_only(git_bin: str, repo_dir: Path | str) -> list[str]:
    return [git_bin, '-C', str(repo_dir), 'pull', '--ff-only']


def nmap_external_reachability(nmap_bin: str, host: str, output_file: Path | str) -> list[str]:
    """Build Phase 1 low-impact host-discovery probes without a port scan."""
    return [
        nmap_bin,
        '-sn',
        '-n',
        '-PE',
        '-PS80,443',
        '-PA80,443',
        '--host-timeout',
        '15s',
        '-oX',
        str(output_file),
        str(host),
    ]


def nmap_internal_host_discovery(
    nmap_bin: str,
    subnet: str,
    output_file: Path | str,
    *,
    interface: str = '',
) -> list[str]:
    """Build Phase 2 inventory-only host discovery for one authorised subnet."""
    cmd = [nmap_bin, '-sn', '-n', '-oX', str(output_file)]
    if str(interface or '').strip():
        cmd += ['-e', str(interface).strip()]
    cmd.append(str(subnet))
    return cmd


def tshark_passive_topology_observation(
    tshark_bin: str,
    interface: str,
    capture_filter: str,
    duration_seconds: int,
) -> list[str]:
    """Build a bounded passive topology-advertisement capture command."""
    return [
        tshark_bin,
        '-i',
        str(interface),
        '-a',
        f'duration:{int(duration_seconds)}',
        '-n',
        '-f',
        str(capture_filter),
        '-V',
    ]


def nmap_upnp_topology_metadata(
    nmap_bin: str,
    device: str,
    output_file: Path | str,
) -> list[str]:
    """Build the bounded UPnP metadata probe used only as supplemental evidence."""
    return [
        nmap_bin,
        '-Pn',
        '-n',
        '-sU',
        '-p',
        '1900',
        '--script',
        'upnp-info',
        '--script-timeout',
        '8s',
        '--host-timeout',
        '15s',
        '-oX',
        str(output_file),
        str(device),
    ]


def curl_topology_root_metadata(
    curl_bin: str,
    scheme: str,
    device: str,
) -> list[str]:
    """Build a short, byte-bounded root-page metadata observation command."""
    return [
        curl_bin,
        '-k',
        '-sS',
        '-L',
        '--connect-timeout',
        '2',
        '--max-time',
        '5',
        '--range',
        '0-262143',
        f'{scheme}://{device}/',
    ]
