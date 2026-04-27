import requests

class CalderaClient:
    def __init__(self, base_url, api_key, verify_ssl=False):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "KEY": api_key,
            "Content-Type": "application/json"
        })
        self.verify_ssl = verify_ssl

    def health_check(self):
        r = self.session.get(f"{self.base_url}/api/v2/health", verify=self.verify_ssl)
        return r.status_code == 200

    def list_agents(self):
        r = self.session.get(f"{self.base_url}/api/v2/agents", verify=self.verify_ssl)
        r.raise_for_status()
        return r.json()

    def get_online_agents(self):
        agents = self.list_agents()
        return [a for a in agents if a.get("trusted") is True]

    def create_operation(self, name, adversary_id, group="red"):
        payload = {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "group": group,
            "state": "running",
            "autonomous": 1
        }
        r = self.session.post(f"{self.base_url}/api/v2/operations", json=payload, verify=self.verify_ssl)
        r.raise_for_status()
        return r.json()

    def get_operation(self, operation_id):
        r = self.session.get(f"{self.base_url}/api/v2/operations/{operation_id}", verify=self.verify_ssl)
        r.raise_for_status()
        return r.json()