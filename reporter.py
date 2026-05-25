"""Render a ScanResult to a self-contained HTML report via Jinja2."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner import Finding, ScanResult

SEVERITY_ORDER = ["High", "Medium", "Low", "Info"]


def _group_by_severity(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Return findings grouped into a dict keyed by severity, in order."""
    grouped: dict[str, list[Finding]] = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)
    return grouped


def render(result: ScanResult, output_path: str) -> str:
    """Render ``result`` to ``output_path`` and return the absolute path.

    The template is loaded from the ``templates/`` directory that ships
    next to this file, so the report is portable regardless of where the
    user runs the CLI from.
    """
    here = Path(__file__).resolve().parent
    env = Environment(
        loader=FileSystemLoader(str(here / "templates")),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")

    html = template.render(
        target=result.target,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        summary=result.summary(),
        severities=SEVERITY_ORDER,
        grouped=_group_by_severity(result.findings),
        errors=result.errors,
        total=len(result.findings),
    )

    out = Path(output_path).resolve()
    out.write_text(html, encoding="utf-8")
    return str(out)
