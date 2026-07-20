from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from exploitation.web_validator import (
    RedirectPolicyError,
    StrictRedirectHandler,
    WebValidationService,
)


def scan_fixture(host="192.168.56.20"):
    return {
        "target_ip": host,
        "service_inventory": [
            {
                "host": host,
                "port": 80,
                "state": "open",
                "service": "http",
            }
        ],
        "web_inventory": [
            {
                "host": host,
                "port": 80,
                "url": f"http://{host}:80/",
                "title": "AutoPentest Lab Diagnostics",
            },
            {
                "tool": "html_form_parser",
                "host": host,
                "port": 80,
                "url": f"http://{host}:80/",
                "links": ["/diagnostics.php"],
                "forms": [
                    {
                        "action": "/diagnostics.php",
                        "method": "POST",
                        "inputs": [{"name": "host", "type": "text"}],
                    }
                ],
            },
        ],
    }


def fake_response(text):
    return {
        "status_code": 200,
        "text": text,
        "response_size": len(text.encode()),
        "truncated": False,
        "final_path": "/diagnostics.php",
        "redirects": [],
    }


def test_real_web_inventory_generates_one_action():
    service = WebValidationService(enabled=True, operating_system="windows")
    result = service.propose_actions(scan_fixture())

    assert result["ok"] is True
    assert result["count"] == 1
    action = result["actions"][0]
    assert action["target"] == "192.168.56.20"
    assert action["port"] == 80
    assert action["endpoint"] == "/diagnostics.php"
    assert action["parameter"] == "host"
    assert action["method"] == "POST"
    assert action["safe_default"] is False
    assert action["non_destructive"] is True


def test_public_target_is_rejected_even_with_matching_fingerprint():
    service = WebValidationService(enabled=True, operating_system="windows")
    result = service.propose_actions(scan_fixture("8.8.8.8"))
    assert result["actions"] == []


def test_evidence_is_not_combined_across_hosts():
    service = WebValidationService(enabled=True, operating_system="windows")
    results = scan_fixture()

    results["web_inventory"][0]["title"] = "Wrong title"
    results["web_inventory"].append({
        "host": "192.168.56.21",
        "port": 80,
        "url": "http://192.168.56.21:80/",
        "title": "AutoPentest Lab Diagnostics",
    })
    results["service_inventory"].append({
        "host": "192.168.56.21",
        "port": 80,
        "state": "open",
        "service": "http",
    })

    assert service.propose_actions(results)["actions"] == []


def test_matching_fields_must_be_on_the_same_form():
    service = WebValidationService(enabled=True, operating_system="windows")
    results = scan_fixture()
    results["web_inventory"][1]["forms"] = [
        {
            "action": "/diagnostics.php",
            "method": "GET",
            "inputs": [{"name": "host", "type": "text"}],
        },
        {
            "action": "/other",
            "method": "POST",
            "inputs": [{"name": "host", "type": "text"}],
        },
    ]

    assert service.propose_actions(results)["actions"] == []


def test_disabled_service_cannot_execute():
    service = WebValidationService(enabled=False, operating_system="windows")
    result = service.run_action(
        action_id="wv_forged",
        parsed_results=scan_fixture(),
        approved=True,
    )
    assert result["ok"] is False
    assert "disabled" in result["error"].lower()


def test_forged_action_id_is_rejected():
    service = WebValidationService(enabled=True, operating_system="windows")
    result = service.run_action(
        action_id="wv_forged",
        parsed_results=scan_fixture(),
        approved=True,
    )
    assert result["ok"] is False
    assert "not authorised" in result["error"].lower()


def test_approval_must_be_literal_true():
    service = WebValidationService(enabled=True, operating_system="windows")
    action = service.propose_actions(scan_fixture())["actions"][0]

    result = service.run_action(
        action_id=action["action_id"],
        parsed_results=scan_fixture(),
        approved=False,
    )
    assert result["ok"] is False
    assert "approval" in result["error"].lower()


def test_reflected_probe_does_not_confirm(monkeypatch):
    service = WebValidationService(enabled=True, operating_system="windows")
    action = service.propose_actions(scan_fixture())["actions"][0]
    probe = "127.0.0.1 & set /a 31000+2000"

    monkeypatch.setattr(service, "_probe", lambda: (probe, "33000"))
    monkeypatch.setattr(
        service,
        "_request",
        lambda *args, **kwargs: fake_response(f"Submitted: {probe}"),
    )

    result = service._execute(action)
    assert result["status"] == "not_confirmed"
    assert result["raw_payload_stored"] is False


def test_independently_derived_result_confirms(monkeypatch):
    service = WebValidationService(enabled=True, operating_system="windows")
    action = service.propose_actions(scan_fixture())["actions"][0]

    monkeypatch.setattr(
        service,
        "_probe",
        lambda: ("127.0.0.1 & set /a 31000+2000", "33000"),
    )
    monkeypatch.setattr(
        service,
        "_request",
        lambda *args, **kwargs: fake_response("Ping output\n33000\n"),
    )

    result = service._execute(action)
    assert result["status"] == "confirmed"
    assert result["confirmation_marker"] == "33000"


def test_unsupported_os_fails_closed():
    service = WebValidationService(
        enabled=True,
        operating_system="unsupported",
    )
    assert service.enabled is False
    assert service.status()["configured"] is False
    assert service.propose_actions(scan_fixture())["ok"] is False


def test_cross_host_redirect_is_blocked():
    handler = StrictRedirectHandler("192.168.56.20", 80, 2)
    request = MagicMock()
    request.full_url = "http://192.168.56.20:80/diagnostics.php"

    with pytest.raises(RedirectPolicyError, match="target IP"):
        handler.redirect_request(
            request,
            MagicMock(),
            302,
            "Found",
            {"Location": "http://192.168.56.21:80/diagnostics.php"},
            "http://192.168.56.21:80/diagnostics.php",
        )


def test_cross_path_redirect_is_blocked():
    handler = StrictRedirectHandler("192.168.56.20", 80, 2)
    request = MagicMock()
    request.full_url = "http://192.168.56.20:80/diagnostics.php"

    with pytest.raises(RedirectPolicyError, match="request path"):
        handler.redirect_request(
            request,
            MagicMock(),
            302,
            "Found",
            {"Location": "http://192.168.56.20:80/admin"},
            "http://192.168.56.20:80/admin",
        )



def test_inline_html_fingerprint_generates_action():
    host = "192.168.56.20"

    html = """
    <!doctype html>
    <html>
      <head>
        <title>AutoPentest Lab Diagnostics</title>
      </head>
      <body>
        <form action="/diagnostics.php" method="POST">
          <input type="text" name="host">
        </form>
      </body>
    </html>
    """

    results = {
        "target_ip": host,
        "service_inventory": [
            {
                "host": host,
                "port": 80,
                "state": "open",
                "service": "http",
            }
        ],
        "web_inventory": [
            {
                "host": host,
                "port": 80,
                "url": (
                    f"http://{host}:80/"
                    "diagnostics.php"
                ),
                "path": "/diagnostics.php",
                "text": html,
            }
        ],
    }

    service = WebValidationService(
        enabled=True,
        operating_system="linux",
    )

    result = service.propose_actions(
        results,
        allow_follow_up=False,
    )

    assert result["ok"] is True
    assert result["count"] == 1

    action = result["actions"][0]

    assert action["expected_page_title"] == (
        "AutoPentest Lab Diagnostics"
    )
    assert action["endpoint"] == "/diagnostics.php"
    assert action["parameter"] == "host"
    assert action["method"] == "POST"


def test_follow_up_detects_title_and_host_form(monkeypatch):
    host = "192.168.56.20"

    results = {
        "target_ip": host,
        "service_inventory": [
            {
                "host": host,
                "port": 80,
                "state": "open",
                "service": "http",
            }
        ],
        "web_inventory": [
            {
                "host": host,
                "port": 80,
                "url": (
                    f"http://{host}:80/"
                    "diagnostics.php"
                ),
                "path": "/diagnostics.php",
            }
        ],
    }

    html = """
    <html>
      <head>
        <title>AutoPentest Lab Diagnostics</title>
      </head>
      <body>
        <form action="/diagnostics.php" method="POST">
          <input name="host" type="text">
        </form>
      </body>
    </html>
    """

    service = WebValidationService(
        enabled=True,
        operating_system="linux",
    )

    monkeypatch.setattr(
        service,
        "_request",
        lambda *args, **kwargs: fake_response(html),
    )

    result = service.propose_actions(
        results,
        allow_follow_up=True,
    )

    assert result["ok"] is True
    assert result["count"] == 1
    assert result["collection_events"]
    assert (
        result["actions"][0]["endpoint"]
        == "/diagnostics.php"
    )


def test_invalid_page_generates_no_action():
    results = scan_fixture()

    results["web_inventory"][0]["title"] = (
        "Page Not Found"
    )
    results["web_inventory"][1]["forms"] = []

    service = WebValidationService(
        enabled=True,
        operating_system="linux",
    )

    result = service.propose_actions(
        results,
        allow_follow_up=False,
    )

    assert result["ok"] is True
    assert result["count"] == 0
    assert result["actions"] == []


def test_default_apache_page_generates_no_action():
    host = "192.168.56.20"

    results = {
        "target_ip": host,
        "service_inventory": [
            {
                "host": host,
                "port": 80,
                "state": "open",
                "service": "http",
            }
        ],
        "web_inventory": [
            {
                "host": host,
                "port": 80,
                "url": f"http://{host}:80/",
                "path": "/",
                "title": (
                    "Apache2 Ubuntu Default Page: "
                    "It works"
                ),
                "forms": [],
            }
        ],
    }

    service = WebValidationService(
        enabled=True,
        operating_system="linux",
    )

    result = service.propose_actions(
        results,
        allow_follow_up=False,
    )

    assert result["ok"] is True
    assert result["count"] == 0
    assert result["actions"] == []
