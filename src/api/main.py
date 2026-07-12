from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

app = FastAPI(
    title="Security Hub API",
    description="Centralized security dashboard and event aggregation",
    version="1.0.0",
)

_hub = None


def _get_hub():
    global _hub
    if _hub is None:
        from src.hub.engine import SecurityHub
        _hub = SecurityHub()
    return _hub


class EventIngest(BaseModel):
    source: str
    severity: str = "info"
    title: str
    description: str = ""
    asset: str = ""
    event_type: str = "alert"
    tags: List[str] = Field(default_factory=list)


class ConnectorRegister(BaseModel):
    name: str
    type: str = "custom"
    config: Dict[str, Any] = Field(default_factory=dict)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/v1/events")
async def ingest_event(event: EventIngest):
    hub = _get_hub()
    result = hub.ingest_event(event.model_dump())
    return result.to_dict()


@app.get("/api/v1/events")
async def list_events(
    source: Optional[str] = None,
    severity: Optional[str] = None,
    asset: Optional[str] = None,
    limit: int = 100,
):
    hub = _get_hub()
    events = hub.get_events(source=source, severity=severity, asset=asset, limit=limit)
    return {"events": [e.to_dict() for e in events], "count": len(events)}


@app.get("/api/v1/events/{event_id}")
async def get_event(event_id: str):
    hub = _get_hub()
    event = hub.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event.to_dict()


@app.post("/api/v1/events/{event_id}/acknowledge")
async def acknowledge_event(event_id: str):
    hub = _get_hub()
    if not hub.acknowledge_event(event_id):
        raise HTTPException(status_code=404, detail="Event not found")
    return {"acknowledged": event_id}


@app.get("/api/v1/connectors")
async def list_connectors():
    hub = _get_hub()
    return {"connectors": [c.to_dict() for c in hub.get_connectors()]}


@app.post("/api/v1/connectors")
async def register_connector(connector: ConnectorRegister):
    hub = _get_hub()
    result = hub.register_connector(connector.model_dump())
    return result.to_dict()


@app.delete("/api/v1/connectors/{connector_id}")
async def remove_connector(connector_id: str):
    hub = _get_hub()
    if not hub.remove_connector(connector_id):
        raise HTTPException(status_code=404, detail="Connector not found")
    return {"deleted": connector_id}


@app.get("/api/v1/dashboard/summary")
async def dashboard_summary():
    hub = _get_hub()
    return hub.get_dashboard_summary()


@app.get("/api/v1/dashboard/trends")
async def dashboard_trends(days: int = 30):
    hub = _get_hub()
    return hub.get_trends(days)


@app.get("/api/v1/dashboard/assets")
async def dashboard_assets():
    hub = _get_hub()
    return {"assets": hub.get_asset_risks()}


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_html():
    hub = _get_hub()
    from src.dashboard.views import DashboardData
    dashboard = DashboardData(hub)
    return dashboard.render_html()


@app.get("/api/v1/stats")
async def stats():
    hub = _get_hub()
    return hub.get_stats()
