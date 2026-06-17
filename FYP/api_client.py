
from __future__ import annotations
import requests
class CalderaClient:
    def __init__(self, base_url: str, api_key: str = ''):
        self.base_url=base_url.rstrip('/'); self.api_key=api_key
    def status(self):
        try:
            r=requests.get(self.base_url + '/api/v2/agents', headers={'KEY': self.api_key} if self.api_key else {}, timeout=5)
            return {'ready': r.ok, 'status_code': r.status_code, 'detail': 'reachable' if r.ok else r.text[:200]}
        except Exception as e:
            return {'ready': False, 'detail': str(e)}
