"""Small local test stub for the external 'responses' package.

It supports the subset used by this repository's Caldera unit tests. Runtime
application code does not import this module.
"""
from __future__ import annotations
from dataclasses import dataclass
from functools import wraps
import json as _json
import requests

GET = 'GET'
POST = 'POST'
PATCH = 'PATCH'
DELETE = 'DELETE'

@dataclass
class _Registered:
    method: str
    url: str
    json_body: object
    status: int

@dataclass
class _Request:
    method: str
    url: str
    body: bytes | None = None

@dataclass
class _Call:
    request: _Request

_registry: list[_Registered] = []
calls: list[_Call] = []
_original_request = None

class _FakeResponse:
    def __init__(self, payload, status_code: int):
        self._payload = payload
        self.status_code = status_code
        self.text = '' if payload is None else _json.dumps(payload)
    def json(self):
        return self._payload
    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f'{self.status_code} Error')

def add(method, url, json=None, status=200, **kwargs):
    _registry.append(_Registered(method.upper(), url, json, status))

def _request(self, method, url, **kwargs):
    body = kwargs.get('data')
    if body is None and 'json' in kwargs:
        body = _json.dumps(kwargs.get('json')).encode('utf-8')
    elif isinstance(body, str):
        body = body.encode('utf-8')
    calls.append(_Call(_Request(method.upper(), url, body)))
    for idx, item in enumerate(list(_registry)):
        if item.method == method.upper() and item.url == url:
            # Behave closely enough to responses: consume in registration order.
            _registry.pop(idx)
            return _FakeResponse(item.json_body, item.status)
    raise requests.ConnectionError(f'No mocked response for {method} {url}')

def activate(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        global _original_request
        _registry.clear()
        calls.clear()
        _original_request = requests.sessions.Session.request
        requests.sessions.Session.request = _request
        try:
            return func(*args, **kwargs)
        finally:
            requests.sessions.Session.request = _original_request
            _registry.clear()
    return wrapper
