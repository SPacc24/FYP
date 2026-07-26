from __future__ import annotations
import ipaddress, re

_TARGET_SPLIT_RE = re.compile(r'[\s,;]+')


def _target_tokens(value: str) -> list[str]:
    """Split operator target input into individual tokens.

    Supports the forms used by the web UI and CLI-style input:
    - single IP: 192.168.86.30
    - whitespace-separated IPs: 192.168.86.30 192.168.86.127
    - comma/semicolon-separated IPs
    - CIDR ranges
    - short ranges: 192.168.86.30-127
    - explicit ranges: 192.168.86.30-192.168.86.127
    """
    raw = (value or '').strip()
    if not raw:
        return []
    return [p.strip() for p in _TARGET_SPLIT_RE.split(raw) if p.strip()]


def expand_target_input(value: str, max_targets: int = 256) -> list[str]:
    raw = (value or '').strip()
    if not raw:
        raise ValueError('Target is required')

    targets: list[str] = []
    for part in _target_tokens(raw):
        if '/' in part:
            net = ipaddress.ip_network(part, strict=False)
            targets.extend(str(h) for h in net.hosts())
        elif '-' in part:
            left, right = [x.strip() for x in part.split('-', 1)]
            if re.match(r'^\d+$', right):
                base = left.rsplit('.', 1)[0]
                start = int(left.rsplit('.', 1)[1]); end = int(right)
                if end < start:
                    start, end = end, start
                for i in range(start, end + 1):
                    candidate = f'{base}.{i}'
                    ipaddress.ip_address(candidate)
                    targets.append(candidate)
            else:
                a = int(ipaddress.ip_address(left)); b = int(ipaddress.ip_address(right))
                if b < a: a, b = b, a
                targets.extend(str(ipaddress.ip_address(i)) for i in range(a, b + 1))
        else:
            ipaddress.ip_address(part)
            targets.append(part)

    deduped = []
    seen = set()
    for t in targets:
        if t not in seen:
            deduped.append(t); seen.add(t)
    if len(deduped) > max_targets:
        raise ValueError(f'Target expansion produced {len(deduped)} hosts; limit is {max_targets}')
    return deduped


def is_private_ip(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_private
