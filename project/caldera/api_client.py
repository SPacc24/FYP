import requests

class CalderaClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "KEY": api_key,
            "Content-Type": "application/json"
        }

    def get(self, endpoint):
        url = f"{self.base_url}{endpoint}"
        response = requests.get(url, headers=self.headers, timeout=15)
        response.raise_for_status()
        return response.json()

    def post(self, endpoint, payload):
        url = f"{self.base_url}{endpoint}"
        response = requests.post(url, json=payload, headers=self.headers, timeout=15)
        response.raise_for_status()
        return response.json()

    def list_agents(self):
        return self.get("/api/v2/agents")

    def list_abilities(self):
        return self.get("/api/v2/abilities")

    def create_operation(self, payload):
        return self.post("/api/v2/operations", payload)