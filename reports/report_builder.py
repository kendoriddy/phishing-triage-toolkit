from datetime import datetime
import json
from pathlib import Path

from jinja2 import Template

from config import OUTPUT_DIR


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Phishing Triage Report</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a2e; }
    h1 { color: #16213e; border-bottom: 3px solid #e94560; padding-bottom: 0.5rem; }
    .verdict { font-size: 1.4rem; font-weight: bold; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
    .critical { background: #fee2e2; color: #991b1b; }
    .high { background: #ffedd5; color: #9a3412; }
    .medium { background: #fef9c3; color: #854d0e; }
    .low { background: #dcfce7; color: #166534; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
    th, td { border: 1px solid #ddd; padding: 0.6rem; text-align: left; }
    th { background: #16213e; color: white; }
    .section { margin: 2rem 0; }
    ul { line-height: 1.8; }
    code { background: #f1f5f9; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.9rem; }
  </style>
</head>
<body>
  <h1>Phishing Triage Report</h1>
  <p><strong>Generated:</strong> {{ report.time }}</p>

  <div class="section">
    <h2>Email Summary</h2>
    <table>
      <tr><th>Field</th><th>Value</th></tr>
      <tr><td>From</td><td>{{ report.sender }}</td></tr>
      <tr><td>Subject</td><td>{{ report.subject }}</td></tr>
      <tr><td>To</td><td>{{ report.to }}</td></tr>
      <tr><td>Date</td><td>{{ report.date or 'N/A' }}</td></tr>
    </table>
  </div>

  <div class="section">
    <h2>Verdict</h2>
    <div class="verdict {{ report.risk_level|lower }}">
      Score: {{ report.risk_score }}/100 — {{ report.verdict }}
    </div>
  </div>

  <div class="section">
    <h2>Authentication</h2>
    <table>
      <tr><th>Check</th><th>Result</th></tr>
      {% for check, result in report.auth_results.items() %}
      <tr><td>{{ check|upper }}</td><td>{{ result }}</td></tr>
      {% endfor %}
    </table>
  </div>

  <div class="section">
    <h2>Indicators of Compromise</h2>
    {% for ioc_type, values in report.iocs.items() %}
      {% if values %}
      <h3>{{ ioc_type|upper }}</h3>
      <ul>
        {% for v in values %}
        <li><code>{{ v }}</code></li>
        {% endfor %}
      </ul>
      {% endif %}
    {% endfor %}
  </div>

  {% if report.timeline %}
  <div class="section">
    <h2>Incident Timeline (Simulation)</h2>
    <ul>
      {% for event in report.timeline %}
      <li>{{ event }}</li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}

  {% if report.whois_data and report.whois_data.domains %}
  <div class="section">
    <h2>Domain Age (WHOIS)</h2>
    <table>
      <tr><th>Domain</th><th>Age (days)</th><th>Registrar</th><th>Assessment</th></tr>
      {% for d in report.whois_data.domains %}
      <tr>
        <td><code>{{ d.domain }}</code></td>
        <td>{{ d.age_days if d.age_days is not none else 'N/A' }}</td>
        <td>{{ d.registrar or 'N/A' }}</td>
        <td>{{ d.risk_note or d.error or 'N/A' }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}

  {% if report.yara_data and report.yara_data.matches %}
  <div class="section">
    <h2>YARA Rule Matches</h2>
    <table>
      <tr><th>Rule</th><th>Severity</th><th>Target</th><th>Description</th></tr>
      {% for m in report.yara_data.matches %}
      <tr>
        <td><code>{{ m.rule }}</code></td>
        <td>{{ m.severity|upper }}</td>
        <td>{{ m.target }}</td>
        <td>{{ m.description }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}
</body>
</html>
"""


def build_report(
    email_data: dict,
    iocs: dict,
    score: int,
    verdict: str,
    vt_data: dict | None = None,
    talos_data: dict | None = None,
    whois_data: dict | None = None,
    yara_data: dict | None = None,
    timeline: list[str] | None = None,
    output_dir: Path | None = None,
) -> dict:
    """Build JSON and HTML triage report."""
    out_dir = output_dir or OUTPUT_DIR
    out_dir.mkdir(exist_ok=True)

    report = {
        "time": str(datetime.now()),
        "sender": email_data.get("from", "Unknown"),
        "subject": email_data.get("subject", "No Subject"),
        "to": email_data.get("to", "Unknown"),
        "date": email_data.get("date"),
        "auth_results": email_data.get("auth_results", {}),
        "attachments": email_data.get("attachments", []),
        "iocs": iocs,
        "risk_score": score,
        "risk_level": _risk_level_label(score),
        "verdict": verdict,
        "vt_data": vt_data or {},
        "talos_data": talos_data or {},
        "whois_data": whois_data or {},
        "yara_data": yara_data or {},
        "timeline": timeline or [],
    }

    json_path = out_dir / "report.json"
    with json_path.open("w") as f:
        json.dump(report, f, indent=4, default=str)

    html_path = out_dir / "report.html"
    html_path.write_text(Template(HTML_TEMPLATE).render(report=report))

    return report


def _risk_level_label(score: int) -> str:
    if score >= 81:
        return "Critical"
    if score >= 51:
        return "High"
    if score >= 21:
        return "Medium"
    return "Low"
