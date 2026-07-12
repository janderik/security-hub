# Security Hub

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Dashboard](https://img.shields.io/badge/dashboard-included-brightgreen)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)]()

A centralized security dashboard that aggregates findings from multiple security tools (SIEM, scanners, vulnerability assessments) into a single pane of glass with real-time alerts and comprehensive reporting.

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Connector List](#connector-list)
- [Dashboard Features](#dashboard-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       Security Hub                                │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────┐     │
│  │  REST API    │───▶│  Hub         │───▶│  Connector      │     │
│  │  (FastAPI)   │    │  Engine      │    │  Framework      │     │
│  └──────┬──────┘    └──────┬───────┘    └────────┬────────┘     │
│         │                  │                     │              │
│  ┌──────▼──────┐    ┌──────▼───────┐    ┌────────▼────────┐     │
│  │  Web         │◀──│  Event       │◀───│  Connectors      │     │
│  │  Dashboard   │    │  Aggregator  │    │  (SIEM/Scanner)  │     │
│  └─────────────┘    └──────────────┘    └─────────────────┘     │
│                                                                  │
│  Connectors: Splunk, ELK, Nessus, Qualys, GitHub, GitLab       │
└──────────────────────────────────────────────────────────────────┘
```

## Features

- **Multi-Tool Integration**: Connect to SIEM, scanners, and assessment tools
- **Real-Time Aggregation**: Stream and correlate events from multiple sources
- **Unified Dashboard**: Single-pane-of-glass security posture view
- **Alert Correlation**: Group related alerts across tools to reduce noise
- **Risk Scoring**: Composite risk scores per asset, team, and organization
- **Compliance Tracking**: Map findings to compliance frameworks
- **Custom Widgets**: Build custom dashboard widgets
- **Webhook Support**: Real-time notifications via webhooks
- **Role-Based Access**: Admin, analyst, and viewer roles

## Connector List

| Connector        | Type    | Direction | Status |
|-----------------|---------|-----------|--------|
| Splunk          | SIEM    | Inbound   | ✓      |
| ELK Stack       | SIEM    | Inbound   | ✓      |
| Microsoft Sentinel | SIEM | Inbound | ✓      |
| Nessus          | Scanner | Inbound   | ✓      |
| Qualys          | Scanner | Inbound   | ✓      |
| OpenVAS         | Scanner | Inbound   | ✓      |
| GitHub Security | SCM     | Inbound   | ✓      |
| GitLab SAST     | SCM     | Inbound   | ✓      |
| Snyk            | SCA     | Inbound   | ✓      |
| SonarQube       | SAST    | Inbound   | ✓      |
| PagerDuty       | Alerting| Outbound  | ✓      |
| Slack           | Alerting| Outbound  | ✓      |
| Jira            | Ticketing| Outbound | ✓      |
| Webhook         | Custom  | Both      | ✓      |

## Dashboard Features

| Widget                | Description                                    |
|----------------------|------------------------------------------------|
| Threat Overview      | Real-time threat count by severity             |
| Asset Risk Map       | Risk heat map by asset/department              |
| Compliance Score     | Compliance percentage by framework             |
| Trend Analysis       | Finding trends over time (7/30/90 days)        |
| Top Vulnerabilities  | Most critical open vulnerabilities             |
| Connector Health     | Status of all connected data sources           |
| Alert Timeline       | Chronological alert feed                       |
| SLA Tracking         | Remediation SLA compliance                     |

## Installation

```bash
git clone https://github.com/janderik/security-hub.git
cd security-hub
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

```python
from src.hub.engine import SecurityHub

hub = SecurityHub()

# Register a connector
hub.register_connector({
    "name": "splunk-prod",
    "type": "splunk",
    "config": {
        "host": "splunk.example.com",
        "port": 8089,
        "token": "your-token",
    },
})

# Ingest events
hub.ingest_event({
    "source": "splunk-prod",
    "severity": "high",
    "title": "Brute force attack detected",
    "asset": "web-server-01",
})

# Get dashboard summary
summary = hub.get_dashboard_summary()
print(f"Critical alerts: {summary['critical_count']}")
```

## API Reference

### Events

| Method | Endpoint          | Description              |
|--------|-------------------|--------------------------|
| GET    | /api/v1/events    | List events (filterable) |
| POST   | /api/v1/events    | Ingest new event         |
| GET    | /api/v1/events/:id| Get event details        |

### Connectors

| Method | Endpoint                | Description            |
|--------|-------------------------|------------------------|
| GET    | /api/v1/connectors      | List all connectors    |
| POST   | /api/v1/connectors      | Register connector     |
| DELETE | /api/v1/connectors/:id  | Remove connector       |

### Dashboard

| Method | Endpoint                | Description            |
|--------|-------------------------|------------------------|
| GET    | /api/v1/dashboard/summary | Dashboard summary    |
| GET    | /api/v1/dashboard/trends  | Trend data           |
| GET    | /api/v1/dashboard/assets  | Asset risk data      |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new connectors
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.
