from src.hub.engine import SecurityHub, SecurityEvent, Connector


def test_register_connector():
    hub = SecurityHub()
    conn = hub.register_connector({"name": "test-splunk", "type": "splunk", "config": {"host": "localhost"}})
    assert conn.name == "test-splunk"
    assert conn.connector_type == "splunk"


def test_ingest_event():
    hub = SecurityHub()
    event = hub.ingest_event({
        "source": "test",
        "severity": "high",
        "title": "Test Alert",
        "asset": "server-01",
    })
    assert event.severity == "high"
    assert event.title == "Test Alert"


def test_dashboard_summary():
    hub = SecurityHub()
    hub.ingest_event({"source": "s1", "severity": "critical", "title": "t1"})
    hub.ingest_event({"source": "s1", "severity": "high", "title": "t2"})
    hub.ingest_event({"source": "s2", "severity": "low", "title": "t3"})

    summary = hub.get_dashboard_summary()
    assert summary["total_events"] == 3
    assert summary["by_severity"]["critical"] == 1
    assert summary["risk_score"] > 0


def test_get_events_filtered():
    hub = SecurityHub()
    hub.ingest_event({"source": "s1", "severity": "high", "title": "t1"})
    hub.ingest_event({"source": "s2", "severity": "low", "title": "t2"})

    events = hub.get_events(source="s1")
    assert len(events) == 1
    assert events[0].source == "s1"


def test_acknowledge_event():
    hub = SecurityHub()
    event = hub.ingest_event({"source": "test", "severity": "medium", "title": "ack me"})
    assert hub.acknowledge_event(event.id)
    updated = hub.get_event(event.id)
    assert updated.acknowledged is True


def test_asset_risks():
    hub = SecurityHub()
    hub.ingest_event({"source": "s1", "severity": "critical", "title": "t1", "asset": "web-01"})
    hub.ingest_event({"source": "s1", "severity": "high", "title": "t2", "asset": "web-01"})
    hub.ingest_event({"source": "s1", "severity": "low", "title": "t3", "asset": "db-01"})

    risks = hub.get_asset_risks()
    assert len(risks) == 2
    assert risks[0]["asset"] == "web-01"
    assert risks[0]["risk_score"] > risks[1]["risk_score"]


def test_remove_connector():
    hub = SecurityHub()
    conn = hub.register_connector({"name": "test", "type": "custom"})
    assert hub.remove_connector(conn.id)
    assert not hub.remove_connector("nonexistent")
