"""Render a ScanResult to a machine-readable JSON report.

Mirrors the HTML reporter's data, but as JSON so the scanner can be
consumed by CI pipelines, dashboards, or other tooling.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from scanner import ScanResult


def render(result: ScanResult, output_path: str) -> str:
    """Write ``result`` as JSON to ``output_path`` and return the abs path."""
    data = {
        "target": result.target,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": result.summary(),
        "total": len(result.findings),
        "findings": [asdict(f) for f in result.findings],
        "errors": result.errors,
    }
    out = Path(output_path).resolve()
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return str(out)
