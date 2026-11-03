"""JSON formatter for machine-readable output."""

import json
from datetime import datetime, timezone

from scanner.models import ScanResult


def format_json(result: ScanResult, provider: str, region: str = "") -> str:
    """Render scan results as a stable JSON schema.

    The schema is versioned so downstream consumers (CI pipelines, dashboards)
    can rely on a stable contract.
    """
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in result.findings:
        severity_counts[f.severity.value.lower()] += 1

    output = {
        "version": "1.0",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provider": provider,
            "region": region,
            "checks_run": result.checks_run,
            "findings_count": severity_counts,
            "total_findings": len(result.findings),
        },
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }

    return json.dumps(output, indent=2)
