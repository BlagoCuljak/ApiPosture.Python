"""HTML output formatter."""

import html
from datetime import datetime, timezone

from apiposture.core.models.enums import Severity
from apiposture.core.models.scan_result import ScanResult
from apiposture.output.base import FormatterOptions, OutputFormatter

_CSS = """
:root{--panel:#fff;--border:#dbe3ee;--text:#1e293b;--muted:#64748b;--critical:#dc2626;--high:#ea580c;--medium:#d97706;--low:#2563eb;--shadow:rgba(15,23,42,0.08);}
*{box-sizing:border-box;}html{scroll-behavior:smooth;}
body{margin:0;padding:32px;background:linear-gradient(to bottom right,#f8fafc,#eef4fb);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif;line-height:1.6;}
.container{max-width:1500px;margin:0 auto;}
h1{font-size:42px;margin-bottom:8px;color:#0f172a;}h2{margin-top:50px;margin-bottom:20px;border-bottom:1px solid var(--border);padding-bottom:12px;color:#0f172a;}h3{margin-top:0;color:#1e293b;}
.meta{color:var(--muted);margin-bottom:40px;}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:18px;margin-bottom:40px;}
.summary-card{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:24px;transition:0.2s ease;box-shadow:0 6px 20px var(--shadow);}
.summary-card:hover{transform:translateY(-2px);}.summary-card .label{color:var(--muted);font-size:14px;}.summary-card .value{font-size:34px;font-weight:700;margin-top:8px;color:#0f172a;}
table{width:100%;border-collapse:collapse;margin-top:18px;margin-bottom:30px;border-radius:14px;box-shadow:0 6px 18px var(--shadow);}
th{background:#eff6ff;color:#1e293b;text-align:left;padding:15px;font-size:14px;border-bottom:1px solid var(--border);}
td{background:var(--panel);border-top:1px solid var(--border);padding:15px;vertical-align:top;}tr:hover td{background:#f8fbff;}
code{background:#eef2ff;color:#1d4ed8;padding:4px 8px;border-radius:6px;font-family:Consolas,monospace;font-size:13px;}
.finding{background:var(--panel);border:1px solid var(--border);border-left:6px solid var(--medium);border-radius:16px;padding:24px;margin-bottom:24px;transition:0.2s ease;box-shadow:0 6px 18px var(--shadow);}
.finding:hover{transform:translateY(-2px);}.finding.critical{border-left-color:var(--critical);}.finding.high{border-left-color:var(--high);}.finding.medium{border-left-color:var(--medium);}.finding.low{border-left-color:var(--low);}
.severity-badge{display:inline-block;padding:5px 12px;border-radius:999px;font-size:12px;font-weight:bold;text-transform:uppercase;margin-bottom:14px;}
.severity-critical{background:#fee2e2;color:#b91c1c;}.severity-high{background:#ffedd5;color:#c2410c;}.severity-medium{background:#fef3c7;color:#b45309;}.severity-low{background:#dbeafe;color:#1d4ed8;}.severity-info{background:#e5e7eb;color:#4b5563;}
.recommendation{margin-top:20px;background:#f8fafc;border:1px solid var(--border);border-radius:12px;padding:18px;}.recommendation-title{color:#2563eb;font-weight:bold;margin-bottom:10px;}
.severity-list{padding-left:18px;}.severity-list li{margin-bottom:8px;}
.success{padding:18px;border-radius:12px;background:#dcfce7;color:#166534;border:1px solid #86efac;font-weight:bold;}
.section-subtitle{color:var(--muted);margin-bottom:20px;}
"""


def _e(value: str | None) -> str:
    return html.escape(value or "", quote=True)


def _card(label: str, value: str) -> str:
    return f'<div class="summary-card"><div class="label">{_e(label)}</div><div class="value">{_e(value)}</div></div>'


class HtmlFormatter(OutputFormatter):
    """HTML output formatter — produces a self-contained HTML report."""

    def __init__(self, options: FormatterOptions | None = None) -> None:
        super().__init__(options)

    def format(self, result: ScanResult) -> str:
        lines: list[str] = []

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        lines.append(f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">')
        lines.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
        lines.append("<title>ApiPosture Security Scan Report</title>")
        lines.append(f"<style>{_CSS}</style></head>")
        lines.append('<body><div class="container">')
        lines.append("<h1>&#x1F6E1;&#xFE0F; ApiPosture Security Scan Report</h1>")
        lines.append(f'<div class="meta"><strong>Generated:</strong> {_e(now)} UTC</div>')

        # Summary
        lines.append("<h2>Summary</h2>")
        lines.append('<div class="summary-grid">')
        lines.append(_card("Files Scanned", str(len(result.files_scanned))))
        frameworks = ", ".join(f.value for f in result.frameworks_detected) or "None"
        lines.append(_card("Frameworks", frameworks))
        lines.append(_card("Endpoints", str(len(result.endpoints))))
        lines.append(_card("Findings", str(len(result.active_findings))))
        lines.append(_card("Suppressed", str(len(result.suppressed_findings))))
        lines.append(_card("Scan Duration", f"{result.duration_ms}ms"))
        lines.append("</div>")
        lines.append(f'<p class="section-subtitle"><strong>Scan Path:</strong> <code>{_e(str(result.scan_path))}</code></p>')

        # Severity breakdown
        summary = result.severity_summary
        severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        has_any = any(summary[s] > 0 for s in severities)
        if has_any:
            lines.append("<h2>Severity Breakdown</h2>")
            lines.append('<ul class="severity-list">')
            for severity in severities:
                count = summary[severity]
                if count > 0:
                    sev = severity.value.lower()
                    lines.append(
                        f'<li><span class="severity-badge severity-{_e(sev)}">{_e(severity.value.capitalize())}</span>'
                        f" &mdash; {count} finding(s)</li>"
                    )
            lines.append("</ul>")

        # Endpoints
        if result.endpoints:
            lines.append("<h2>Discovered Endpoints</h2>")
            lines.append("<table>")
            lines.append("  <thead><tr><th>Route</th><th>Methods</th><th>Classification</th><th>Framework</th><th>Function</th></tr></thead>")
            lines.append("  <tbody>")
            for ep in result.endpoints:
                lines.append(
                    f"    <tr>"
                    f"<td><code>{_e(ep.full_route)}</code></td>"
                    f"<td>{_e(ep.display_methods)}</td>"
                    f"<td>{_e(ep.classification.value)}</td>"
                    f"<td>{_e(ep.framework.value)}</td>"
                    f"<td><code>{_e(ep.function_name)}</code></td>"
                    f"</tr>"
                )
            lines.append("  </tbody></table>")

        # Findings
        if result.active_findings:
            lines.append("<h2>Security Findings</h2>")
            for finding in result.active_findings:
                sev = finding.severity.value.lower()
                lines.append(f'<div class="finding {_e(sev)}">')
                lines.append(f'  <span class="severity-badge severity-{_e(sev)}">{_e(finding.severity.value.capitalize())}</span>')
                lines.append(f"  <h3>[{_e(finding.rule_id)}] {_e(finding.rule_name)}</h3>")
                lines.append(f"  <p><strong>Endpoint:</strong> <code>{_e(finding.endpoint.full_route)} [{_e(finding.endpoint.display_methods)}]</code></p>")
                lines.append(f"  <p><strong>Location:</strong> <code>{_e(str(finding.location))}</code></p>")
                lines.append(f"  <p>{_e(finding.message)}</p>")
                if finding.recommendation:
                    lines.append(
                        f'  <div class="recommendation">'
                        f'<div class="recommendation-title">Recommendation</div>'
                        f"<div>{_e(finding.recommendation)}</div></div>"
                    )
                lines.append("</div>")
        else:
            lines.append("<h2>Security Findings</h2>")
            lines.append('<div class="success">&#x2705; No security findings detected!</div>')

        # Parse errors
        if result.parse_errors:
            lines.append("<h2>Parse Errors</h2><ul>")
            for path, error in result.parse_errors.items():
                lines.append(f"  <li><code>{_e(str(path))}</code>: {_e(error)}</li>")
            lines.append("</ul>")

        lines.append("</div></body></html>")
        return "\n".join(lines)
