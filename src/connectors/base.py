from typing import Dict, Any, List
import time


class BaseConnector:
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.status = "active"
        self.last_sync = 0.0
        self.events_received = 0

    def fetch_events(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def test_connection(self) -> Dict[str, Any]:
        return {"connected": True, "connector": self.name}


class SplunkConnector(BaseConnector):
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.host = config.get("host", "localhost")
        self.port = config.get("port", 8089)
        self.token = config.get("token", "")

    def fetch_events(self) -> List[Dict[str, Any]]:
        try:
            import httpx
            response = httpx.get(
                f"https://{self.host}:{self.port}/services/search/jobs/export",
                headers={"Authorization": f"Bearer {self.token}"},
                params={"search": "index=security | head 100", "output_mode": "json"},
                timeout=10.0,
            )
            if response.status_code == 200:
                data = response.json()
                self.last_sync = time.time()
                return self._parse_results(data)
        except Exception:
            pass
        return []

    def _parse_results(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        events = []
        for result in data.get("results", []):
            events.append({
                "source": self.name,
                "severity": result.get("severity", "info"),
                "title": result.get("title", "Splunk Alert"),
                "description": result.get("description", ""),
                "asset": result.get("host", ""),
            })
        return events


class ELKConnector(BaseConnector):
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.host = config.get("host", "localhost")
        self.port = config.get("port", 9200)
        self.index = config.get("index", "security-*")

    def fetch_events(self) -> List[Dict[str, Any]]:
        try:
            import httpx
            response = httpx.get(
                f"http://{self.host}:{self.port}/{self.index}/_search",
                json={"query": {"match_all": {}}, "size": 100},
                timeout=10.0,
            )
            if response.status_code == 200:
                data = response.json()
                self.last_sync = time.time()
                return self._parse_hits(data)
        except Exception:
            pass
        return []

    def _parse_hits(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        events = []
        for hit in data.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            events.append({
                "source": self.name,
                "severity": src.get("severity", "info"),
                "title": src.get("message", "ELK Alert"),
                "asset": src.get("host", {}).get("name", ""),
            })
        return events


class GitHubConnector(BaseConnector):
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.token = config.get("token", "")
        self.org = config.get("org", "")

    def fetch_events(self) -> List[Dict[str, Any]]:
        try:
            import httpx
            response = httpx.get(
                f"https://api.github.com/repos/{self.org}/code-scanning/alerts",
                headers={"Authorization": f"token {self.token}", "Accept": "application/vnd.github+json"},
                timeout=10.0,
            )
            if response.status_code == 200:
                self.last_sync = time.time()
                return self._parse_alerts(response.json())
        except Exception:
            pass
        return []

    def _parse_alerts(self, alerts: list) -> List[Dict[str, Any]]:
        events = []
        for alert in alerts:
            events.append({
                "source": self.name,
                "severity": alert.get("security_severity_level", "medium"),
                "title": alert.get("rule", {}).get("description", "GitHub Alert"),
                "description": alert.get("most_recent_instance", {}).get("message", {}).get("text", ""),
                "asset": alert.get("repository", {}).get("full_name", ""),
            })
        return events


class WebhookConnector(BaseConnector):
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.url = config.get("url", "")
        self.headers = config.get("headers", {})

    def send_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        try:
            import httpx
            response = httpx.post(self.url, json=event, headers=self.headers, timeout=10.0)
            return {"sent": True, "status_code": response.status_code}
        except Exception as e:
            return {"sent": False, "error": str(e)}
