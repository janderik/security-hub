from typing import Dict, Any, List


class DashboardData:
    def __init__(self, hub):
        self.hub = hub

    def get_overview(self) -> Dict[str, Any]:
        summary = self.hub.get_dashboard_summary()
        trends = self.hub.get_trends(days=7)

        return {
            "summary": summary,
            "trends_7d": trends,
            "status": "healthy" if summary["risk_score"] < 30 else "warning" if summary["risk_score"] < 70 else "critical",
        }

    def get_threat_overview(self) -> Dict[str, Any]:
        summary = self.hub.get_dashboard_summary()
        return {
            "critical": summary["by_severity"].get("critical", 0),
            "high": summary["by_severity"].get("high", 0),
            "medium": summary["by_severity"].get("medium", 0),
            "low": summary["by_severity"].get("low", 0),
            "total": summary["total_events"],
        }

    def get_asset_risks(self) -> List[Dict[str, Any]]:
        return self.hub.get_asset_risks()

    def get_connector_status(self) -> List[Dict[str, Any]]:
        connectors = self.hub.get_connectors()
        return [
            {
                "name": c.name,
                "type": c.connector_type,
                "status": c.status,
                "last_sync": c.last_sync,
                "events_received": c.events_received,
            }
            for c in connectors
        ]

    def get_compliance_summary(self) -> Dict[str, Any]:
        summary = self.hub.get_dashboard_summary()
        total = summary["total_events"]

        return {
            "cis": {"score": max(0, 100 - summary["risk_score"]), "findings": total},
            "soc2": {"score": max(0, 100 - summary["risk_score"] * 0.8), "findings": int(total * 0.8)},
            "pci_dss": {"score": max(0, 100 - summary["risk_score"] * 1.2), "findings": int(total * 1.2)},
        }

    def get_alert_timeline(self, limit: int = 50) -> List[Dict[str, Any]]:
        events = self.hub.get_events(limit=limit)
        return [
            {
                "id": e.id,
                "title": e.title,
                "severity": e.severity,
                "source": e.source,
                "asset": e.asset,
                "timestamp": e.timestamp,
                "acknowledged": e.acknowledged,
            }
            for e in reversed(events)
        ]

    def render_html(self) -> str:
        summary = self.hub.get_dashboard_summary()
        trends = self.hub.get_trends(days=7)
        threats = self.get_threat_overview()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Hub Dashboard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #0f172a; color: #e2e8f0; }}
        .header {{ text-align: center; padding: 20px 0; }}
        .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }}
        .card {{ background: #1e293b; border-radius: 8px; padding: 20px; text-align: center; }}
        .card h3 {{ margin: 0 0 8px 0; color: #94a3b8; font-size: 14px; }}
        .card .value {{ font-size: 32px; font-weight: bold; }}
        .critical {{ color: #ef4444; }}
        .high {{ color: #f97316; }}
        .medium {{ color: #eab308; }}
        .low {{ color: #22c55e; }}
        .risk {{ font-size: 48px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Hub Dashboard</h1>
        <p>Risk Score: <span class="risk {'critical' if summary['risk_score'] > 70 else 'medium' if summary['risk_score'] > 30 else 'low'}">{summary['risk_score']}/100</span></p>
    </div>
    <div class="cards">
        <div class="card"><h3>Total Events</h3><div class="value">{summary['total_events']}</div></div>
        <div class="card"><h3>Critical</h3><div class="value critical">{threats['critical']}</div></div>
        <div class="card"><h3>High</h3><div class="value high">{threats['high']}</div></div>
        <div class="card"><h3>Active Connectors</h3><div class="value">{summary['active_connectors']}</div></div>
    </div>
    <div class="cards">
        <div class="card"><h3>Medium</h3><div class="value medium">{threats['medium']}</div></div>
        <div class="card"><h3>Low</h3><div class="value low">{threats['low']}</div></div>
        <div class="card"><h3>Unacknowledged</h3><div class="value">{summary['unacknowledged']}</div></div>
        <div class="card"><h3>7-Day Events</h3><div class="value">{trends['total']}</div></div>
    </div>
</body>
</html>"""
        return html
