import time
import uuid
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class SecurityEvent:
    id: str
    source: str
    severity: str
    title: str
    description: str = ""
    asset: str = ""
    event_type: str = "alert"
    tags: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    acknowledged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "asset": self.asset,
            "event_type": self.event_type,
            "tags": self.tags,
            "timestamp": self.timestamp,
            "acknowledged": self.acknowledged,
        }


@dataclass
class Connector:
    id: str
    name: str
    connector_type: str
    config: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    status: str = "active"
    last_sync: float = 0.0
    events_received: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.connector_type,
            "enabled": self.enabled,
            "status": self.status,
            "last_sync": self.last_sync,
            "events_received": self.events_received,
        }


class SecurityHub:
    def __init__(self):
        self._events: List[SecurityEvent] = []
        self._connectors: Dict[str, Connector] = {}
        self._alert_rules: List[Dict[str, Any]] = []
        self._init_default_rules()

    def _init_default_rules(self) -> None:
        self._alert_rules = [
            {
                "name": "high_severity_alert",
                "condition": {"severity": ["critical", "high"]},
                "action": "notify",
            },
            {
                "name": "repeated_asset_alerts",
                "condition": {"asset_events_threshold": 5},
                "action": "escalate",
            },
        ]

    def register_connector(self, config: Dict[str, Any]) -> Connector:
        connector_id = str(uuid.uuid4())[:8]
        connector = Connector(
            id=connector_id,
            name=config["name"],
            connector_type=config.get("type", "custom"),
            config=config.get("config", {}),
        )
        self._connectors[connector_id] = connector
        return connector

    def remove_connector(self, connector_id: str) -> bool:
        if connector_id in self._connectors:
            del self._connectors[connector_id]
            return True
        return False

    def get_connectors(self) -> List[Connector]:
        return list(self._connectors.values())

    def ingest_event(self, event_data: Dict[str, Any]) -> SecurityEvent:
        event = SecurityEvent(
            id=str(uuid.uuid4())[:12],
            source=event_data.get("source", "unknown"),
            severity=event_data.get("severity", "info"),
            title=event_data.get("title", "Unknown event"),
            description=event_data.get("description", ""),
            asset=event_data.get("asset", ""),
            event_type=event_data.get("event_type", "alert"),
            tags=event_data.get("tags", []),
            raw_data=event_data.get("raw_data", {}),
        )

        self._events.append(event)

        connector = self._find_connector_by_name(event.source)
        if connector:
            connector.events_received += 1
            connector.last_sync = time.time()

        self._process_alert_rules(event)

        if len(self._events) > 50000:
            self._events = self._events[-25000:]

        return event

    def _find_connector_by_name(self, name: str) -> Optional[Connector]:
        for conn in self._connectors.values():
            if conn.name == name:
                return conn
        return None

    def _process_alert_rules(self, event: SecurityEvent) -> None:
        for rule in self._alert_rules:
            condition = rule.get("condition", {})
            if event.severity in condition.get("severity", []):
                pass

    def get_events(
        self,
        source: Optional[str] = None,
        severity: Optional[str] = None,
        asset: Optional[str] = None,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        events = self._events
        if source:
            events = [e for e in events if e.source == source]
        if severity:
            events = [e for e in events if e.severity == severity]
        if asset:
            events = [e for e in events if e.asset == asset]
        return events[-limit:]

    def get_event(self, event_id: str) -> Optional[SecurityEvent]:
        for event in self._events:
            if event.id == event_id:
                return event
        return None

    def acknowledge_event(self, event_id: str) -> bool:
        event = self.get_event(event_id)
        if event:
            event.acknowledged = True
            return True
        return False

    def get_dashboard_summary(self) -> Dict[str, Any]:
        total = len(self._events)
        by_severity = {}
        by_source = {}
        by_asset = {}

        for event in self._events:
            by_severity[event.severity] = by_severity.get(event.severity, 0) + 1
            by_source[event.source] = by_source.get(event.source, 0) + 1
            if event.asset:
                by_asset[event.asset] = by_asset.get(event.asset, 0) + 1

        unack = sum(1 for e in self._events if not e.acknowledged)

        risk_score = (
            by_severity.get("critical", 0) * 10
            + by_severity.get("high", 0) * 7
            + by_severity.get("medium", 0) * 4
            + by_severity.get("low", 0) * 1
        )

        return {
            "total_events": total,
            "unacknowledged": unack,
            "by_severity": by_severity,
            "by_source": by_source,
            "top_assets": dict(sorted(by_asset.items(), key=lambda x: x[1], reverse=True)[:10]),
            "risk_score": min(risk_score, 100),
            "active_connectors": sum(1 for c in self._connectors.values() if c.enabled),
        }

    def get_trends(self, days: int = 30) -> Dict[str, Any]:
        now = time.time()
        cutoff = now - (days * 86400)

        daily = {}
        for event in self._events:
            if event.timestamp >= cutoff:
                day = time.strftime("%Y-%m-%d", time.localtime(event.timestamp))
                daily[day] = daily.get(day, 0) + 1

        return {"period_days": days, "daily_counts": daily, "total": sum(daily.values())}

    def get_asset_risks(self) -> List[Dict[str, Any]]:
        asset_events = {}
        for event in self._events:
            if event.asset:
                if event.asset not in asset_events:
                    asset_events[event.asset] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
                asset_events[event.asset][event.severity] = asset_events[event.asset].get(event.severity, 0) + 1
                asset_events[event.asset]["total"] += 1

        result = []
        for asset, counts in asset_events.items():
            risk = counts["critical"] * 10 + counts["high"] * 7 + counts["medium"] * 4 + counts["low"]
            result.append({"asset": asset, "risk_score": risk, "event_counts": counts})

        return sorted(result, key=lambda x: x["risk_score"], reverse=True)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_events": len(self._events),
            "total_connectors": len(self._connectors),
            "active_connectors": sum(1 for c in self._connectors.values() if c.enabled),
            "acknowledged_events": sum(1 for e in self._events if e.acknowledged),
        }
