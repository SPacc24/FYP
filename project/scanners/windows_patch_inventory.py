from __future__ import annotations

"""Read-only authenticated Windows OS and patch evidence collection.

The collector deliberately consumes only a credential that has already been
approved and cached by the existing credential-audit workflow.  It does not
brute force, create services, start RemoteRegistry, execute a remote shell,
write files on the target, or modify registry/firewall/service state.
"""

import ipaddress
import re
import socket
from datetime import datetime, timezone
from typing import Any, Callable


COLLECTOR_ID = "windows_patch_inventory"


def _private_target(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if ip.version != 4 or not (ip.is_private or ip.is_loopback):
        return None
    return str(ip)


def _load_cached_credential(target: str) -> tuple[str, str] | None:
    """Read the existing credential cache without changing its implementation."""
    try:
        from exploitation.credential_audit import load_cached_smb_credential
    except Exception:
        return None
    try:
        return load_cached_smb_credential(target)
    except Exception:
        return None


def _split_account(account: str) -> tuple[str, str]:
    raw = str(account or "").strip()
    if "\\" in raw:
        domain, username = raw.split("\\", 1)
        return ("" if domain == "." else domain), username
    if "@" in raw:
        username, domain = raw.rsplit("@", 1)
        return domain, username
    return "", raw


def _property_value(record: dict[str, Any], key: str) -> Any:
    item = record.get(key)
    if isinstance(item, dict) and "value" in item:
        return item.get("value")
    return item


def _clean(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()
    return str(value).strip()


def _normalise_kb(value: Any) -> str:
    text = _clean(value).upper().replace(" ", "")
    match = re.search(r"(?:KB)?(\d{5,9})", text)
    return f"KB{match.group(1)}" if match else ""


def _query_rows(services: Any, query: str) -> list[dict[str, Any]]:
    enum = services.ExecQuery(query)
    rows: list[dict[str, Any]] = []
    while True:
        try:
            objects = enum.Next(0xFFFFFFFF, 1)
        except Exception as exc:
            # Impacket surfaces end-of-enumeration as S_FALSE.
            if "S_FALSE" in str(exc):
                break
            raise
        if not objects:
            break
        obj = objects[0]
        try:
            props = obj.getProperties() or {}
            rows.append({str(k): _property_value(props, str(k)) for k in props})
        finally:
            try:
                obj.RemRelease()
            except Exception:
                pass
    try:
        enum.RemRelease()
    except Exception:
        pass
    return rows


def _default_wmi_reader(target: str, username: str, password: str, domain: str, timeout_seconds: int) -> dict[str, Any]:
    """Collect WMI evidence through DCOM without remote process execution."""
    try:
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
        from impacket.dcerpc.v5.dcom import wmi
        from impacket.dcerpc.v5.dtypes import NULL
    except ModuleNotFoundError as exc:
        raise RuntimeError("impacket_unavailable") from exc

    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(max(3, min(int(timeout_seconds), 120)))
    dcom = None
    login = None
    services = None
    try:
        dcom = DCOMConnection(target, username, password, domain)
        interface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        login = wmi.IWbemLevel1Login(interface)
        services = login.NTLMLogin("//./root/cimv2", NULL, NULL)
        try:
            login.RemRelease()
        except Exception:
            pass
        login = None

        os_rows = _query_rows(
            services,
            "SELECT Caption,Version,BuildNumber,OSArchitecture,CSName,InstallDate,LastBootUpTime FROM Win32_OperatingSystem",
        )
        system_rows = _query_rows(
            services,
            "SELECT Name,Domain,Manufacturer,Model,SystemType FROM Win32_ComputerSystem",
        )
        qfe_rows = _query_rows(
            services,
            "SELECT HotFixID,Description,InstalledOn,InstalledBy,Caption FROM Win32_QuickFixEngineering",
        )
        return {"operating_system": os_rows, "computer_system": system_rows, "quick_fix_engineering": qfe_rows}
    finally:
        if services is not None:
            try:
                services.RemRelease()
            except Exception:
                pass
        if login is not None:
            try:
                login.RemRelease()
            except Exception:
                pass
        if dcom is not None:
            try:
                dcom.disconnect()
            except Exception:
                pass
        socket.setdefaulttimeout(previous_timeout)


def _default_registry_reader(target: str, username: str, password: str, domain: str, timeout_seconds: int) -> dict[str, Any]:
    """Read CurrentVersion values only when RemoteRegistry is already available.

    This function never starts/stops the RemoteRegistry service and never writes
    a registry value. Failure is non-fatal because WMI remains the primary
    inventory source.
    """
    try:
        from impacket.dcerpc.v5 import rrp, transport
    except ModuleNotFoundError as exc:
        raise RuntimeError("impacket_unavailable") from exc

    binding = rf"ncacn_np:{target}[\\pipe\\winreg]"
    rpc_transport = transport.DCERPCTransportFactory(binding)
    if hasattr(rpc_transport, "set_credentials"):
        rpc_transport.set_credentials(username, password, domain, "", "")
    dce = rpc_transport.get_dce_rpc()
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(max(3, min(int(timeout_seconds), 120)))
    key_handle = None
    root_handle = None
    try:
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)
        root = rrp.hOpenLocalMachine(dce)
        root_handle = root["phKey"]
        key = rrp.hBaseRegOpenKey(
            dce,
            root_handle,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        )
        key_handle = key["phkResult"]
        values: dict[str, Any] = {}
        for name in ("ProductName", "EditionID", "DisplayVersion", "ReleaseId", "CurrentBuild", "CurrentBuildNumber", "UBR"):
            try:
                _value_type, value = rrp.hBaseRegQueryValue(dce, key_handle, name)
            except Exception:
                continue
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-16-le", errors="ignore").rstrip("\x00")
                except Exception:
                    value = value.decode("utf-8", errors="ignore").rstrip("\x00")
            values[name] = value
        return values
    finally:
        if key_handle is not None:
            try:
                rrp.hBaseRegCloseKey(dce, key_handle)
            except Exception:
                pass
        if root_handle is not None:
            try:
                rrp.hBaseRegCloseKey(dce, root_handle)
            except Exception:
                pass
        try:
            dce.disconnect()
        except Exception:
            pass
        socket.setdefaulttimeout(previous_timeout)


def windows_target_applicability(identities: list[dict[str, Any]] | None) -> tuple[str, str]:
    """Classify only directly observed host-OS identity for authenticated use.

    Unknown identity remains eligible only because the operator explicitly chose
    this credentialed collector. An explicitly non-Windows identity is never
    probed with Windows WMI merely because SMB happens to be open.
    """
    rows = list(identities or [])
    if not rows:
        return "unknown", "No host operating-system identity was established before authenticated collection."
    blobs = []
    for row in rows:
        blobs.append(" ".join(_clean(row.get(key)).lower() for key in ("vendor", "family", "product", "name", "raw")))
    if any("windows" in blob or ("microsoft" in blob and "linux" not in blob) for blob in blobs):
        return "applicable", "Direct host identity evidence indicates Microsoft Windows."
    non_windows_tokens = ("linux", "ubuntu", "debian", "red hat", "rhel", "centos", "fedora", "darwin", "macos", "mac os", "freebsd", "openbsd", "netbsd", "solaris", "aix")
    if any(any(token in blob for token in non_windows_tokens) for blob in blobs):
        return "not_applicable", "Direct host identity evidence indicates a non-Windows operating system."
    return "unknown", "Host operating-system identity remains ambiguous; operator-selected authenticated collection may resolve it."


def collect_windows_patch_inventory(
    target: str,
    *,
    timeout_seconds: int = 30,
    credential_loader: Callable[[str], tuple[str, str] | None] | None = None,
    wmi_reader: Callable[[str, str, str, str, int], dict[str, Any]] | None = None,
    registry_reader: Callable[[str, str, str, str, int], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Collect structured Windows patch evidence using an existing credential.

    Returned structures never contain the password or username.  This keeps raw
    scan evidence and command logs safe even when collection fails.
    """
    target_ip = _private_target(target)
    base: dict[str, Any] = {
        "collector": COLLECTOR_ID,
        "host": str(target),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "method": "Impacket DCOM/WMI plus optional read-only RemoteRegistry query",
        "credential_source": "existing runtime_credentials cache",
        "mutates_target": False,
    }
    if not target_ip:
        return {**base, "ok": False, "status": "scope_blocked", "lifecycle_state": "scope_blocked", "message": "Authenticated patch inventory is restricted to authorised private/loopback IPv4 targets."}

    loader = credential_loader or _load_cached_credential
    credential = loader(target_ip)
    if not credential:
        return {**base, "host": target_ip, "ok": False, "status": "deferred", "lifecycle_state": "deferred", "message": "No approved cached SMB credential is available; authenticated Windows patch inventory was deferred."}

    account, password = credential
    domain, username = _split_account(account)
    if not username or not password:
        return {**base, "host": target_ip, "ok": False, "status": "deferred", "lifecycle_state": "deferred", "message": "Cached credential was incomplete; authenticated Windows patch inventory was deferred."}

    reader = wmi_reader or _default_wmi_reader
    try:
        raw = reader(target_ip, username, password, domain, int(timeout_seconds)) or {}
    except RuntimeError as exc:
        if str(exc) == "impacket_unavailable":
            return {**base, "host": target_ip, "ok": False, "status": "tool_unavailable", "lifecycle_state": "tool_unavailable", "message": "Impacket is not installed; Windows patch inventory could not run."}
        return {**base, "host": target_ip, "ok": False, "status": "failed", "lifecycle_state": "executed_failed", "message": "Authenticated WMI patch inventory failed."}
    except Exception as exc:
        # Do not propagate authentication strings or exception representations to
        # user-visible evidence; they may contain sensitive transport details.
        return {
            **base,
            "host": target_ip,
            "ok": False,
            "status": "failed",
            "lifecycle_state": "executed_failed",
            "message": "Authenticated WMI patch inventory failed or the required WMI/DCOM service was unavailable.",
            "error_type": type(exc).__name__,
        }

    registry_values: dict[str, Any] = {}
    registry_status = "not_attempted"
    registry = registry_reader or _default_registry_reader
    try:
        registry_values = registry(target_ip, username, password, domain, int(timeout_seconds)) or {}
        registry_status = "collected" if registry_values else "no_evidence"
    except Exception:
        # RemoteRegistry is commonly disabled.  Never start it: lack of this
        # optional read-only source must not turn successful WMI collection into
        # a failure.
        registry_status = "unavailable"

    os_rows = list(raw.get("operating_system") or [])
    system_rows = list(raw.get("computer_system") or [])
    qfe_rows = list(raw.get("quick_fix_engineering") or [])
    os_row = os_rows[0] if os_rows else {}
    system_row = system_rows[0] if system_rows else {}

    product = _clean(registry_values.get("ProductName")) or _clean(os_row.get("Caption"))
    version = _clean(os_row.get("Version"))
    build = _clean(registry_values.get("CurrentBuildNumber")) or _clean(registry_values.get("CurrentBuild")) or _clean(os_row.get("BuildNumber"))
    edition = _clean(registry_values.get("EditionID")) or product
    release = _clean(registry_values.get("DisplayVersion")) or _clean(registry_values.get("ReleaseId"))
    architecture = _clean(os_row.get("OSArchitecture")) or _clean(system_row.get("SystemType"))
    hostname = _clean(os_row.get("CSName")) or _clean(system_row.get("Name"))
    domain_name = _clean(system_row.get("Domain"))

    installed_updates: list[dict[str, str]] = []
    seen_kbs: set[str] = set()
    for row in qfe_rows:
        kb = _normalise_kb(row.get("HotFixID"))
        if not kb or kb in seen_kbs:
            continue
        seen_kbs.add(kb)
        installed_updates.append({
            "kb": kb,
            "description": _clean(row.get("Description")),
            "installed_on": _clean(row.get("InstalledOn")),
        })
    installed_updates.sort(key=lambda item: item["kb"])

    # Prefer directly observed CurrentVersion\UBR from an already-available
    # RemoteRegistry endpoint. WMI may occasionally expose a fourth component;
    # retain that only as a direct-observation fallback.
    ubr = _clean(registry_values.get("UBR"))
    version_parts = re.findall(r"\d+", version)
    if not ubr and len(version_parts) >= 4:
        ubr = version_parts[3]

    evidence = {
        **base,
        "host": target_ip,
        "ok": bool(product or build or installed_updates),
        "status": "collected" if (product or build or installed_updates) else "no_evidence",
        "lifecycle_state": "executed_evidence" if (product or build or installed_updates) else "executed_no_evidence",
        "product": product,
        "edition": edition,
        "release": release,
        "version": version,
        "build": build,
        "ubr": ubr,
        "architecture": architecture,
        "hostname": hostname,
        "domain": domain_name,
        "manufacturer": _clean(system_row.get("Manufacturer")),
        "model": _clean(system_row.get("Model")),
        "installed_kbs": sorted(seen_kbs),
        "installed_updates": installed_updates,
        "hotfix_count": len(installed_updates),
        "registry_evidence_status": registry_status,
        "evidence_limitations": [
            "Win32_QuickFixEngineering does not enumerate every Windows Installer or third-party update source.",
            "UBR/revision is retained only when directly observed through Windows version data or an already-available read-only RemoteRegistry endpoint; it is never inferred from a KB number.",
            "The collector never starts RemoteRegistry; if it is unavailable, UBR may remain unknown and fixed-build conclusions stay conservative.",
        ],
    }
    return evidence


def inventory_host_identity(inventory: dict[str, Any], evidence_reference: str = "") -> dict[str, Any] | None:
    """Convert successful WMI evidence into the scanner host-identity contract."""
    if not inventory.get("ok"):
        return None
    product = _clean(inventory.get("product"))
    version = _clean(inventory.get("version"))
    build = _clean(inventory.get("build"))
    if not (product or version or build):
        return None
    return {
        "host": _clean(inventory.get("host")),
        "scope": "host_os",
        "name": product,
        "vendor": "Microsoft" if "windows" in product.lower() else "",
        "family": "Windows" if "windows" in product.lower() else "",
        "product": product,
        "version": version,
        "build": build,
        "release": _clean(inventory.get("release")),
        "architecture": _clean(inventory.get("architecture")),
        "hostnames": [_clean(inventory.get("hostname"))] if _clean(inventory.get("hostname")) else [],
        "domains": [_clean(inventory.get("domain"))] if _clean(inventory.get("domain")) else [],
        "source": COLLECTOR_ID,
        "evidence_kind": "authenticated_inventory",
        "evidence_reference": evidence_reference,
        "raw": f"Authenticated read-only WMI OS identity; build={build}; version={version}; hotfixes={inventory.get('hotfix_count', 0)}",
    }
