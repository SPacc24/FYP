from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

import requests

from .cpe_utils import (
    concrete,
    evaluate_configurations,
    extract_cpes,
    format_cpe23,
    identity_matches,
    normalise_product,
    parse_cpe,
)
from .scoring_policy import (
    CvssVerifierUnavailableError,
    InvalidCvssVectorError,
    ScoringPolicyError,
    validate_published_metric,
)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SOURCE = "NVD CVE API 2.0"
CACHE_DIR = Path("storage/nvd_cache")
CACHE_FILE = CACHE_DIR / "service_queries.json"
CVE_METRIC_CACHE_FILE = CACHE_DIR / "cve_metric_queries.json"
CVE_CONTEXT_CACHE_FILE = CACHE_DIR / "cve_context_queries.json"
DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60
DEFAULT_DELAY_SECONDS = 6.5
DEFAULT_TIMEOUT_SECONDS = 20
ATTRIBUTION = "This product uses the NVD API but is not endorsed or certified by the NVD."
CACHE_SCHEMA_VERSION = "cve-review-v16-structured-v3"

_lock = threading.Lock()
_last_request_at = 0.0


def enabled() -> bool:
    return os.getenv("NVD_ENRICHMENT_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def _cache_ttl() -> int:
    try:
        return max(60, int(os.getenv("NVD_CACHE_TTL_SECONDS", str(DEFAULT_TTL_SECONDS))))
    except ValueError:
        return DEFAULT_TTL_SECONDS


def _delay_seconds() -> float:
    try:
        return max(0.0, float(os.getenv("NVD_REQUEST_DELAY_SECONDS", str(DEFAULT_DELAY_SECONDS))))
    except ValueError:
        return DEFAULT_DELAY_SECONDS


def _timeout_seconds() -> float:
    try:
        return max(3.0, float(os.getenv("NVD_REQUEST_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS))))
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS


def _load_cache() -> dict[str, Any]:
    try:
        if CACHE_FILE.exists():
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _save_cache(cache: dict[str, Any]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(CACHE_FILE)


def _cache_key(
    product: str,
    version: str,
    service: str,
    cpe: str,
    context_cpe: str = "",
) -> str:
    raw = "|".join((
        CACHE_SCHEMA_VERSION,
        product.strip().lower(),
        version.strip().lower(),
        service.strip().lower(),
        cpe.strip().lower(),
        context_cpe.strip().lower(),
    ))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _english_description(cve: dict[str, Any]) -> str:
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en":
            return str(item.get("value") or "")
    return ""


def _metrics(cve: dict[str, Any]) -> dict[str, dict[str, Any]]:
    metrics = cve.get("metrics") or {}
    output: dict[str, dict[str, Any]] = {}
    # PenPilot supports CVSS 3.1 and CVSS 4.0 only. Each is retained as an
    # independent published metric and is never converted into the other.
    groups = (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"))
    for group, version in groups:
        rows = metrics.get(group) or []
        if not rows:
            continue
        # Prefer NVD Primary, then the first published metric.
        ordered = sorted(rows, key=lambda row: 0 if str((row or {}).get("type") or "").lower() == "primary" else 1)
        for row in ordered:
            row = row or {}
            data = row.get("cvssData") or {}
            score = data.get("baseScore")
            vector = data.get("vectorString") or ""
            severity = row.get("baseSeverity") or data.get("baseSeverity") or ""
            if score is None or not vector:
                continue
            try:
                metric = validate_published_metric(version, score, severity, vector)
                metric["cvss_verification"] = "Vector recomputed; published score matches"
            except ScoringPolicyError as exc:
                try:
                    score_value = float(score)
                except (TypeError, ValueError):
                    continue
                if isinstance(exc, CvssVerifierUnavailableError):
                    integrity = "verifier_unavailable"
                    verification_status = "verifier_unavailable"
                    message = f"Published metric retained; independent verifier unavailable: {exc}"
                elif isinstance(exc, InvalidCvssVectorError):
                    integrity = "invalid_vector"
                    verification_status = "invalid_vector"
                    message = f"Published metric retained; vector could not be independently calculated: {exc}"
                else:
                    integrity = "published_source_inconsistent"
                    verification_status = "source_inconsistent"
                    message = f"Published metric could not be independently verified: {exc}"
                metric = {
                    "cvss_score": score_value,
                    "cvss_severity": str(severity or "").upper(),
                    "cvss_vector": str(vector),
                    "cvss_version": version,
                    "cvss_metric_integrity": integrity,
                    "cvss_verified": False,
                    "cvss_verification_status": verification_status,
                    "cvss_verification_method": (
                        "python_cvss4_library" if version == "4.0" else "internal_cvss31_formula"
                    ),
                    "cvss_verification": message,
                }
            raw_source = str(row.get("source") or "NVD")
            metric["cvss_source"] = raw_source
            metric["cvss_provider_role"] = row.get("type") or "NVD"
            metric["cvss_provider_name"] = "NVD" if ("nist.gov" in raw_source.lower() or raw_source.lower() == "nvd") else ""
            output[version] = metric
            break
    return output


def _metric(cve: dict[str, Any]) -> dict[str, Any]:
    """Backward-compatible preferred metric (3.1, then 4.0)."""
    metrics = _metrics(cve)
    return dict(metrics.get("3.1") or metrics.get("4.0") or {})


def _references(cve: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for item in cve.get("references") or []:
        url = item.get("url") if isinstance(item, dict) else None
        if url and url not in refs:
            refs.append(url)
    return refs[:10]


def _config_nodes(cve: dict[str, Any]) -> list[dict[str, Any]]:
    configs = cve.get("configurations") or []
    if isinstance(configs, dict):
        configs = [configs]
    return configs if isinstance(configs, list) else []


def _cpe_matches(cve: dict[str, Any], observed_cpe: str) -> bool:
    matched, _basis = evaluate_configurations(cve, extract_cpes(observed_cpe))
    return matched


def _version_tuple(value: str) -> tuple[int, ...]:
    import re
    return tuple(int(part) for part in re.findall(r"\d+", str(value or ""))[:6])


def _configuration_match(
    cve: dict[str, Any],
    product: str,
    version: str,
    observed_cpe: str,
    context_cpe: str = "",
) -> tuple[bool, str]:
    """Evaluate complete NVD applicability data without keyword-only findings."""
    primary_cpes = extract_cpes(observed_cpe)
    if primary_cpes:
        return evaluate_configurations(
            cve,
            primary_cpes,
            context_cpes=extract_cpes(context_cpe),
            observed_version=version,
        )

    observed_product = normalise_product(product)
    if not observed_product or not _version_tuple(version):
        return False, ""

    # Without a scanner-observed CPE, create a comparison CPE only after an
    # exact official vendor/product-name match. No edition or platform field is
    # invented, so clauses requiring those attributes remain unsatisfied.
    stack = list(_config_nodes(cve))
    synthetic: list[str] = []
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        stack.extend(node.get("nodes") or [])
        for match in node.get("cpeMatch") or []:
            if not isinstance(match, dict) or not bool(match.get("vulnerable", False)):
                continue
            criteria = parse_cpe(str(match.get("criteria") or match.get("cpe23Uri") or ""))
            if not criteria:
                continue
            product_name = normalise_product(criteria.get("product", ""))
            vendor_product = normalise_product(
                f"{criteria.get('vendor', '')} {criteria.get('product', '')}"
            )
            if observed_product not in {product_name, vendor_product}:
                continue
            candidate = {
                field: "*"
                for field in (
                    "part", "vendor", "product", "version", "update", "edition",
                    "language", "sw_edition", "target_sw", "target_hw", "other",
                )
            }
            candidate.update({
                "part": criteria.get("part", "a"),
                "vendor": criteria.get("vendor", "*"),
                "product": criteria.get("product", "*"),
                "version": version,
            })
            synthetic.append(format_cpe23(candidate))
    if synthetic:
        return evaluate_configurations(cve, synthetic, observed_version=version)
    return False, ""




def _normalise_query_identity(product: str, version: str, service: str) -> tuple[str, str, str]:
    """Normalise only formatting/protocol suffix noise from an observed identity.

    No OS edition, release, or build is derived in code. NVD candidate search
    remains structured-CPE/configuration gated; this helper only removes
    formatting/protocol suffix noise from concrete observed identities.
    """
    raw_product = " ".join(str(product or "").split())
    raw_version = " ".join(str(version or "").split())
    raw_service = " ".join(str(service or "").split())
    cleaned = raw_product
    for suffix in (" microsoft-ds", " netbios-ssn", " ms-wbt-server", " wsman", " httpapi"):
        if cleaned.lower().endswith(suffix):
            cleaned = cleaned[: -len(suffix)].strip()
    return cleaned, raw_version, raw_service


def _keyword(product: str, version: str, service: str) -> str:
    product = " ".join(product.split())
    version = " ".join(version.split())
    if product and version:
        return f"{product} {version}"
    if product:
        return product
    if service and version:
        return f"{service} {version}"
    return service


def _wait_for_rate_limit() -> None:
    global _last_request_at
    with _lock:
        wait = _delay_seconds() - (time.monotonic() - _last_request_at)
        if wait > 0:
            time.sleep(wait)
        _last_request_at = time.monotonic()


def _request(params: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    headers = {"User-Agent": "SP-FYP-AutoPenTest/1.0"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key

    _wait_for_rate_limit()
    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=_timeout_seconds())
    except requests.RequestException as exc:
        return None, {"reason": "nvd_network_error", "matcher_status": "degraded", "error": str(exc)}

    if response.status_code in {403, 429}:
        return None, {
            "reason": "nvd_rate_limited",
            "matcher_status": "degraded",
            "http_status": response.status_code,
            "message": "NVD enrichment temporarily unavailable because the public rate limit was reached.",
        }
    if response.status_code >= 500:
        return None, {"reason": "nvd_service_unavailable", "matcher_status": "degraded", "http_status": response.status_code}
    if not response.ok:
        return None, {"reason": "nvd_http_error", "matcher_status": "error", "http_status": response.status_code}
    try:
        return response.json(), {}
    except ValueError:
        return None, {"reason": "nvd_invalid_json", "matcher_status": "error"}


def _concrete_query_cpe(cpe: str, version: str = "") -> str:
    """Return one concrete CPE suitable for NVD's cpeName parameter."""
    for raw in extract_cpes(cpe):
        parsed = parse_cpe(raw)
        if not parsed:
            continue
        if not all(concrete(parsed.get(field, "")) for field in ("part", "vendor", "product")):
            continue
        candidate = dict(parsed)
        if not concrete(candidate.get("version", "")) and concrete(version):
            candidate["version"] = str(version).strip().lower()
        if not concrete(candidate.get("version", "")):
            continue
        return format_cpe23(candidate)
    return ""


def _request_candidate_pages(params: dict[str, Any], *, max_results: int = 4000) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch a bounded NVD candidate result set, preserving API diagnostics."""
    collected: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    start_index = 0
    page_size = min(2000, max_results)
    while len(collected) < max_results:
        page_params = dict(params)
        page_params["resultsPerPage"] = page_size
        page_params["startIndex"] = start_index
        data, diagnostic = _request(page_params)
        if data is None:
            diagnostics.append(dict(diagnostic or {}))
            break
        vulnerabilities = list(data.get("vulnerabilities") or [])
        collected.extend(vulnerabilities)
        total = int(data.get("totalResults") or len(collected))
        start_index += len(vulnerabilities)
        if not vulnerabilities or start_index >= total or len(collected) >= max_results:
            if total > max_results:
                diagnostics.append({
                    "reason": "nvd_candidate_result_cap",
                    "matcher_status": "degraded",
                    "total_results": total,
                    "retained_results": min(len(collected), max_results),
                    "max_results": max_results,
                })
            break
    return collected[:max_results], diagnostics


def search(
    product: str,
    version: str,
    service: str,
    cpe: str = "",
    *,
    context_cpe: str = "",
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    """Generate NVD structured-applicability candidates for an observed identity.

    Candidate generation is deliberately broader than final applicability: NVD
    may introduce a CVE for review only when its structured configuration/CPE
    evaluates against the concrete observed product/version.  Downstream code
    still decides whether the item is trusted as a strict match.
    """
    if not enabled():
        return tuple(), ({"reason": "nvd_enrichment_disabled", "matcher_status": "disabled"},)

    observed_cpe = next(
        (parse_cpe(value) for value in extract_cpes(cpe) if parse_cpe(value)),
        None,
    )
    if observed_cpe:
        if not str(product or "").strip() or str(product).lower().startswith("cpe:"):
            product = (
                f"{observed_cpe.get('vendor', '')} {observed_cpe.get('product', '')}"
                .replace("_", " ")
                .strip()
            )
        cpe_version = str(observed_cpe.get("version") or "")
        if not str(version or "").strip() and cpe_version not in {"", "*", "-"}:
            version = cpe_version

    product, version, service = _normalise_query_identity(product, version, service)
    if not str(version or "").strip():
        return tuple(), ({"reason": "observed_version_missing", "matcher_status": "held"},)
    if not str(product or service or "").strip():
        return tuple(), ({"reason": "observed_product_missing", "matcher_status": "held"},)

    key = _cache_key(product, version, service, cpe, context_cpe)
    cache = _load_cache()
    cached = cache.get(key) if isinstance(cache.get(key), dict) else None
    now = time.time()
    if cached and now - float(cached.get("cached_at") or 0) < _cache_ttl():
        return tuple(cached.get("results") or []), tuple(cached.get("diagnostics") or [])

    concrete_cpe = _concrete_query_cpe(cpe, version)
    query_mode = "cpeName" if concrete_cpe else "keywordSearch"
    query_value = concrete_cpe if concrete_cpe else (product or service)
    params: dict[str, Any] = (
        {"cpeName": concrete_cpe}
        if concrete_cpe
        else {"keywordSearch": query_value}
    )
    wrappers, request_diagnostics = _request_candidate_pages(params)
    if not wrappers and request_diagnostics:
        if cached:
            fallback_diag = list(cached.get("diagnostics") or []) + [
                {**item, "cache_fallback": True} for item in request_diagnostics
            ]
            return tuple(cached.get("results") or []), tuple(fallback_diag)
        return tuple(), tuple(request_diagnostics)

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    rejected_by_configuration = 0
    for wrapper in wrappers:
        cve = wrapper.get("cve") or {}
        cve_id = str(cve.get("id") or "")
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        applicable, match_basis = _configuration_match(
            cve,
            product,
            version,
            cpe or concrete_cpe,
            context_cpe,
        )
        if not applicable:
            rejected_by_configuration += 1
            continue
        cvss_metrics = _metrics(cve)
        preferred_metric = cvss_metrics.get("3.1") or cvss_metrics.get("4.0") or {}
        rows.append({
            "cve_id": cve_id,
            "description": _english_description(cve),
            "references": _references(cve),
            "source": NVD_SOURCE,
            "upstream_source": NVD_SOURCE,
            "identity_scope": "application_service",
            "matched_product_tokens": [product or service],
            "matched_version_tokens": [version],
            "match_basis": match_basis,
            "product_match_basis": "structured_nvd_configuration",
            "affected_cpes": [
                str(item.get("criteria") or item.get("cpe23Uri") or "")
                for item in _iter_cpe_matches(cve)
                if isinstance(item, dict) and bool(item.get("vulnerable", False))
            ],
            "cvss_metrics": cvss_metrics,
            "nvd_vuln_status": str(cve.get("vulnStatus") or ""),
            **preferred_metric,
        })

    diagnostics: list[dict[str, Any]] = list(request_diagnostics)
    diagnostics.append({
        "reason": "nvd_structured_candidate_search",
        "matcher_status": "available",
        "query_mode": query_mode,
        "query": query_value,
        "api_records_considered": len(wrappers),
        "structured_configuration_rejected": rejected_by_configuration,
        "result_count": len(rows),
        "cache": "miss",
    })
    cache[key] = {
        "cached_at": now,
        "query_mode": query_mode,
        "query": query_value,
        "results": rows,
        "diagnostics": diagnostics,
    }
    _save_cache(cache)
    return tuple(rows), tuple(diagnostics)


def _same_observed_product_rule(
    match: dict[str, Any],
    product: str,
    observed_cpe: str,
) -> bool:
    criteria = parse_cpe(str(match.get("criteria") or match.get("cpe23Uri") or ""))
    if not criteria:
        return False
    observed = next((parse_cpe(raw) for raw in extract_cpes(observed_cpe) if parse_cpe(raw)), None)
    if observed and identity_matches(criteria, observed, ignore_version=True):
        return True
    observed_product = normalise_product(product)
    criteria_product = normalise_product(criteria.get("product", ""))
    vendor_product = normalise_product(f"{criteria.get('vendor', '')} {criteria.get('product', '')}")
    return bool(observed_product and observed_product in {criteria_product, vendor_product})


def _relevant_vulnerable_rules(cve: dict[str, Any], product: str, observed_cpe: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for match in _iter_cpe_matches(cve):
        if not isinstance(match, dict) or not bool(match.get("vulnerable", False)):
            continue
        if not _same_observed_product_rule(match, product, observed_cpe):
            continue
        rules.append({
            "criteria": str(match.get("criteria") or match.get("cpe23Uri") or ""),
            "versionStartIncluding": str(match.get("versionStartIncluding") or ""),
            "versionStartExcluding": str(match.get("versionStartExcluding") or ""),
            "versionEndIncluding": str(match.get("versionEndIncluding") or ""),
            "versionEndExcluding": str(match.get("versionEndExcluding") or ""),
        })
    return rules


def assess_exact_cve_applicability(
    cve_id: str,
    product: str,
    version: str,
    cpe: str = "",
    *,
    context_cpe: str = "",
    scope: str = "application_service",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Assess one canonical CVE against NVD's exact structured configuration.

    This function never creates a strict CVE match.  It is used to detect
    corroboration or authoritative disagreement after a CVE ID is already
    known, and to make conflict states explicit.
    """
    cve, diagnostic = _fetch_exact_cve(cve_id)
    if not cve:
        return {
            "state": "unavailable",
            "source": NVD_SOURCE,
            "cve_id": str(cve_id or "").upper(),
            "rules": [],
        }, diagnostic

    configs = _config_nodes(cve)
    if not configs:
        result = {
            "state": "no_structured_configuration",
            "source": NVD_SOURCE,
            "cve_id": str(cve_id or "").upper(),
            "rules": [],
            "vuln_status": str(cve.get("vulnStatus") or ""),
            "description": _english_description(cve),
            "references": _references(cve),
        }
        return result, {**diagnostic, "applicability_state": result["state"], "identity_scope": scope}

    concrete_cpe = _concrete_query_cpe(cpe, version)
    applicable, basis = _configuration_match(
        cve,
        product,
        version,
        cpe or concrete_cpe,
        context_cpe,
    )
    rules = _relevant_vulnerable_rules(cve, product, cpe or concrete_cpe)
    if applicable:
        state = "matched"
    elif rules:
        # NVD contains a vulnerable rule for the same product/platform but the
        # observed concrete version/context did not satisfy it.  This is an
        # explicit structured disagreement, not mere absence of corroboration.
        state = "not_applicable"
    else:
        state = "not_corroborated"
    result = {
        "state": state,
        "source": NVD_SOURCE,
        "cve_id": str(cve_id or "").upper(),
        "basis": basis,
        "rules": rules,
        "vuln_status": str(cve.get("vulnStatus") or ""),
        "description": _english_description(cve),
        "references": _references(cve),
    }
    return result, {
        **diagnostic,
        "applicability_state": state,
        "match_basis": basis,
        "relevant_rule_count": len(rules),
        "identity_scope": scope,
    }



def _load_metric_cache() -> dict[str, Any]:
    try:
        if CVE_METRIC_CACHE_FILE.exists():
            data = json.loads(CVE_METRIC_CACHE_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _save_metric_cache(cache: dict[str, Any]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CVE_METRIC_CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(CVE_METRIC_CACHE_FILE)


def _load_context_cache() -> dict[str, Any]:
    try:
        if CVE_CONTEXT_CACHE_FILE.exists():
            data = json.loads(CVE_CONTEXT_CACHE_FILE.read_text(encoding='utf-8'))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _save_context_cache(cache: dict[str, Any]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CVE_CONTEXT_CACHE_FILE.with_suffix('.tmp')
    tmp.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding='utf-8')
    tmp.replace(CVE_CONTEXT_CACHE_FILE)


def _fetch_exact_cve(cve_id: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Fetch one exact NVD CVE record for corroboration, never candidate search."""
    cve_id = str(cve_id or '').strip().upper()
    if not cve_id.startswith('CVE-'):
        return None, {'reason': 'invalid_cve_id', 'matcher_status': 'held'}
    if not enabled():
        return None, {'reason': 'nvd_enrichment_disabled', 'matcher_status': 'disabled', 'cve_id': cve_id}

    cache = _load_context_cache()
    cached = cache.get(cve_id) if isinstance(cache.get(cve_id), dict) else None
    now = time.time()
    if cached and now - float(cached.get('cached_at') or 0) < _cache_ttl():
        cve = cached.get('cve')
        return (dict(cve) if isinstance(cve, dict) else None), {
            'reason': 'nvd_exact_cve_context', 'matcher_status': 'available',
            'cve_id': cve_id, 'cache': 'hit',
        }

    data, diagnostic = _request({'cveId': cve_id})
    if data is None:
        if cached and isinstance(cached.get('cve'), dict):
            return dict(cached['cve']), {**diagnostic, 'cve_id': cve_id, 'cache_fallback': True}
        return None, {**diagnostic, 'cve_id': cve_id}

    cve: dict[str, Any] | None = None
    for wrapper in data.get('vulnerabilities') or []:
        candidate = wrapper.get('cve') or {}
        if str(candidate.get('id') or '').upper() == cve_id:
            cve = dict(candidate)
            break
    cache[cve_id] = {'cached_at': now, 'cve': cve or {}}
    _save_context_cache(cache)
    return cve, {
        'reason': 'nvd_exact_cve_context', 'matcher_status': 'available',
        'cve_id': cve_id, 'cache': 'miss',
    }


def _normalised_tokens(value: str) -> list[str]:
    import re
    return [token for token in re.findall(r'[a-z0-9]+', normalise_product(value)) if token and not token.isdigit()]


def _component_matches_cpe_product(component: str, cpe_product: str) -> bool:
    component_name = normalise_product(component)
    product_name = normalise_product(cpe_product)
    if not component_name or not product_name:
        return False
    if component_name == product_name:
        return True
    product_tokens = _normalised_tokens(product_name)
    component_tokens = _normalised_tokens(component_name)
    if component_name in product_tokens or product_name in component_tokens:
        return True
    product_acronym = ''.join(token[0] for token in product_tokens) if len(product_tokens) >= 2 else ''
    component_acronym = ''.join(token[0] for token in component_tokens) if len(component_tokens) >= 2 else ''
    return component_name == product_acronym or product_name == component_acronym


def _equivalent_numeric_version(left: str, right: str) -> bool:
    def parts(value: str) -> tuple[int, ...]:
        values = list(_version_tuple(value))
        while len(values) > 1 and values[-1] == 0:
            values.pop()
        return tuple(values)
    a, b = parts(left), parts(right)
    return bool(a and b and a == b)


def _iter_cpe_matches(cve: dict[str, Any]):
    stack = list(_config_nodes(cve))
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        stack.extend(node.get('nodes') or [])
        for match in node.get('cpeMatch') or []:
            if isinstance(match, dict):
                yield match


def _component_primary_cpes(
    cve: dict[str, Any], component: str, component_version: str,
) -> list[str]:
    """Derive primary component CPEs only from this exact CVE configuration."""
    candidates: list[str] = []
    for match in _iter_cpe_matches(cve):
        if not bool(match.get('vulnerable', False)):
            continue
        criteria_text = str(match.get('criteria') or match.get('cpe23Uri') or '')
        criteria = parse_cpe(criteria_text)
        if not criteria or criteria.get('part') != 'a':
            continue
        if not _component_matches_cpe_product(component, criteria.get('product', '')):
            continue
        criteria_version = str(criteria.get('version') or '*')
        if criteria_version not in {'', '*', '-'} and not _equivalent_numeric_version(criteria_version, component_version):
            continue
        if criteria_version in {'', '*', '-'}:
            candidate = dict(criteria)
            candidate['version'] = component_version
            candidates.append(format_cpe23(candidate))
        else:
            candidates.append(criteria_text)
    return list(dict.fromkeys(candidates))


def corroborate_cve_component_context(
    cve_id: str,
    component: str,
    component_version: str,
    host_cpes: list[str] | tuple[str, ...],
) -> tuple[bool, str, dict[str, Any]]:
    """Corroborate an official component CVE against exact-ID NVD CPE logic.

    NVD is never used here to discover a CVE.  The caller supplies a canonical
    CVE Program ID, and this function only asks whether that exact CVE's CPE
    configuration is satisfied by the observed component plus authoritative
    host CPE context.
    """
    if not host_cpes:
        return False, '', {
            'reason': 'component_host_cpe_context_missing', 'matcher_status': 'held',
            'cve_id': str(cve_id or '').upper(),
        }
    cve, diagnostic = _fetch_exact_cve(cve_id)
    if not cve:
        return False, '', diagnostic
    primary_cpes = _component_primary_cpes(cve, component, component_version)
    if primary_cpes:
        matched, basis = evaluate_configurations(
            cve,
            primary_cpes,
            context_cpes=list(host_cpes),
            observed_version=component_version,
        )
        return bool(matched), str(basis or ''), {
            **diagnostic,
            'reason': 'nvd_exact_cve_component_context_corroboration',
            'matcher_status': 'available' if matched else 'held',
            'corroboration_mode': 'component_and_host_configuration',
            'component': component,
            'component_version': component_version,
            'primary_cpes': primary_cpes,
            'host_cpes': list(host_cpes),
            'configuration_basis': basis or '',
        }

    # If the exact NVD configuration *does* contain vulnerable application CPEs
    # but none correspond to the already-observed canonical component/version,
    # do not bypass that disagreement with a host-only match.  Host-only
    # corroboration is reserved for NVD records that omit application CPEs
    # altogether and express the same CVE solely through vulnerable platform
    # CPEs.
    vulnerable_application_cpes: list[str] = []
    for cpe_match in _iter_cpe_matches(cve):
        if not bool(cpe_match.get('vulnerable', False)):
            continue
        criteria_text = str(cpe_match.get('criteria') or cpe_match.get('cpe23Uri') or '')
        parsed = parse_cpe(criteria_text)
        if parsed and parsed.get('part') == 'a':
            vulnerable_application_cpes.append(criteria_text)
    if vulnerable_application_cpes:
        return False, '', {
            **diagnostic,
            'reason': 'nvd_exact_cve_component_cpe_mismatch',
            'matcher_status': 'held',
            'corroboration_mode': 'component_cpe_present_but_not_matched',
            'component': component,
            'component_version': component_version,
            'nvd_application_cpes': list(dict.fromkeys(vulnerable_application_cpes)),
            'host_cpes': list(host_cpes),
        }

    # Some exact NVD records model an affected protocol/component CVE only with
    # vulnerable platform/OS CPEs and do not repeat the component as a part=a
    # CPE.  The CVE Program affected entry has already established the component
    # product/version before this function is called, so in that representation
    # NVD is used only to corroborate that the observed host platform satisfies
    # the exact CVE configuration.  This is deliberately *not* a fallback CVE
    # discovery path and does not infer a component from an OS CPE.
    host_matched, host_basis = evaluate_configurations(cve, list(host_cpes))
    return bool(host_matched), str(host_basis or ''), {
        **diagnostic,
        'reason': 'nvd_exact_cve_host_context_corroboration',
        'matcher_status': 'available' if host_matched else 'held',
        'corroboration_mode': 'canonical_component_plus_host_configuration',
        'component': component,
        'component_version': component_version,
        'primary_cpes': [],
        'host_cpes': list(host_cpes),
        'configuration_basis': host_basis or '',
    }


def lookup_cve_metrics(cve_id: str) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Fetch optional NVD CVSS enrichment for one canonical CVE ID.

    The CVE Program record remains the source of applicability.  This helper
    only fills published CVSS versions that are missing from the canonical
    CVE record and never creates or changes a CVE match.
    """
    cve_id = str(cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return {}, {"reason": "invalid_cve_id", "matcher_status": "held"}
    if not enabled():
        return {}, {"reason": "nvd_enrichment_disabled", "matcher_status": "disabled", "cve_id": cve_id}

    cache = _load_metric_cache()
    cached = cache.get(cve_id) if isinstance(cache.get(cve_id), dict) else None
    now = time.time()
    if cached and now - float(cached.get("cached_at") or 0) < _cache_ttl():
        return dict(cached.get("metrics") or {}), {
            "reason": "nvd_cve_metric_enrichment",
            "matcher_status": "available",
            "cve_id": cve_id,
            "cache": "hit",
            "versions": sorted((cached.get("metrics") or {}).keys()),
        }

    data, diagnostic = _request({"cveId": cve_id})
    if data is None:
        if cached:
            return dict(cached.get("metrics") or {}), {**diagnostic, "cve_id": cve_id, "cache_fallback": True}
        return {}, {**diagnostic, "cve_id": cve_id}

    metrics: dict[str, dict[str, Any]] = {}
    for wrapper in data.get("vulnerabilities") or []:
        cve = wrapper.get("cve") or {}
        if str(cve.get("id") or "").upper() != cve_id:
            continue
        metrics = _metrics(cve)
        break

    cache[cve_id] = {"cached_at": now, "metrics": metrics}
    _save_metric_cache(cache)
    return metrics, {
        "reason": "nvd_cve_metric_enrichment",
        "matcher_status": "available",
        "cve_id": cve_id,
        "cache": "miss",
        "versions": sorted(metrics.keys()),
    }

def status() -> dict[str, Any]:
    cache = _load_cache()
    metric_cache = _load_metric_cache()
    context_cache = _load_context_cache()
    timestamps = []
    for source in (cache, metric_cache, context_cache):
        for item in source.values():
            if isinstance(item, dict):
                try:
                    ts = float(item.get("cached_at") or 0)
                except (TypeError, ValueError):
                    ts = 0
                if ts > 0:
                    timestamps.append(ts)
    latest = max(timestamps) if timestamps else 0.0
    now = time.time()
    return {
        "enabled": enabled(),
        "api_url": NVD_API_URL,
        "api_key_configured": bool(os.getenv("NVD_API_KEY", "").strip()),
        "cache_file": str(CACHE_FILE),
        "cve_metric_cache_file": str(CVE_METRIC_CACHE_FILE),
        "cve_context_cache_file": str(CVE_CONTEXT_CACHE_FILE),
        "cached_queries": len(cache),
        "cached_structured_candidate_queries": len(cache),
        "cached_cve_metric_queries": len(metric_cache),
        "cached_cve_context_queries": len(context_cache),
        "last_successful_cache_at_epoch": latest or None,
        "cache_age_seconds": int(max(0, now - latest)) if latest else None,
        "request_delay_seconds": _delay_seconds(),
        "cache_ttl_seconds": _cache_ttl(),
        "attribution": ATTRIBUTION,
    }
