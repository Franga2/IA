"""
GDPR Report Generator

Produces three output formats:
  1. HTML report — audit-ready, professional, usable by non-technical compliance officers
  2. JSON report — machine-readable, suitable for integration with other tools
  3. Console summary — quick overview for CLI output

Design: Report generation is completely decoupled from validation logic.
The reporter only consumes ValidationReport objects — it has no knowledge
of GDPR rules, making it easy to swap out templates or add new formats.
"""

import json
from datetime import datetime
from typing import Dict

from .models import (
    Article30Entry,
    ComplianceConflict,
    ComplianceStatus,
    Finding,
    FindingType,
    MinimizationConcern,
    Severity,
    TransferValidationResult,
    ValidationReport,
)

# ─────────────────────────────────────────────────────────────────────────────
# Status / Severity colour maps
# ─────────────────────────────────────────────────────────────────────────────

STATUS_BADGE: Dict[str, str] = {
    ComplianceStatus.COMPLIANT: "badge-compliant",
    ComplianceStatus.COMPLIANT_TIA_REQUIRED: "badge-tia",
    ComplianceStatus.NON_COMPLIANT: "badge-non-compliant",
    ComplianceStatus.REQUIRES_LEGAL_REVIEW: "badge-review",
    ComplianceStatus.NOT_APPLICABLE: "badge-na",
}

STATUS_LABEL: Dict[str, str] = {
    ComplianceStatus.COMPLIANT: "✅ Compliant",
    ComplianceStatus.COMPLIANT_TIA_REQUIRED: "⚠️ TIA Required",
    ComplianceStatus.NON_COMPLIANT: "❌ Non-Compliant",
    ComplianceStatus.REQUIRES_LEGAL_REVIEW: "🔍 Legal Review",
    ComplianceStatus.NOT_APPLICABLE: "➖ N/A (Intra-EEA)",
}

SEVERITY_BADGE: Dict[str, str] = {
    Severity.CRITICAL: "sev-critical",
    Severity.HIGH: "sev-high",
    Severity.MEDIUM: "sev-medium",
    Severity.LOW: "sev-low",
    Severity.INFO: "sev-info",
}


# ─────────────────────────────────────────────────────────────────────────────
# HTML Reporter
# ─────────────────────────────────────────────────────────────────────────────

class HTMLReporter:
    """Generates a professional HTML compliance report."""

    CSS = """
    <style>
      :root {
        --primary: #1e3a5f;
        --secondary: #2d6a9f;
        --success: #1a7a4a;
        --warning: #b45309;
        --danger: #b91c1c;
        --review: #6b21a8;
        --na: #6b7280;
        --bg: #f8fafc;
        --card: #ffffff;
        --border: #e2e8f0;
        --text: #1e293b;
        --muted: #64748b;
      }
      * { box-sizing: border-box; margin: 0; padding: 0; }
      body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
             color: var(--text); line-height: 1.6; }
      .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
      header { background: var(--primary); color: white; padding: 2rem;
               border-bottom: 4px solid #2d6a9f; }
      header h1 { font-size: 1.8rem; font-weight: 700; }
      header p { opacity: 0.85; margin-top: 0.25rem; font-size: 0.95rem; }
      .meta { display: flex; gap: 2rem; margin-top: 1rem; font-size: 0.85rem; opacity: 0.9; }
      .section { margin: 2rem 0; }
      .section-title { font-size: 1.2rem; font-weight: 700; color: var(--primary);
                       border-bottom: 2px solid var(--border); padding-bottom: 0.5rem;
                       margin-bottom: 1rem; }
      .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                      gap: 1rem; margin-bottom: 2rem; }
      .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px;
                   padding: 1.25rem; text-align: center; }
      .stat-card .value { font-size: 2.2rem; font-weight: 800; }
      .stat-card .label { font-size: 0.8rem; color: var(--muted); margin-top: 0.25rem; }
      .stat-card.danger .value { color: var(--danger); }
      .stat-card.warning .value { color: var(--warning); }
      .stat-card.success .value { color: var(--success); }
      .stat-card.info .value { color: var(--secondary); }
      table { width: 100%; border-collapse: collapse; background: var(--card);
              border-radius: 8px; overflow: hidden;
              box-shadow: 0 1px 3px rgba(0,0,0,0.08); font-size: 0.88rem; }
      th { background: var(--primary); color: white; padding: 0.75rem 1rem;
           text-align: left; font-weight: 600; }
      td { padding: 0.7rem 1rem; border-bottom: 1px solid var(--border); vertical-align: top; }
      tr:last-child td { border-bottom: none; }
      tr:hover td { background: #f1f5f9; }
      .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 999px;
               font-size: 0.75rem; font-weight: 600; white-space: nowrap; }
      .badge-compliant { background: #dcfce7; color: #166534; }
      .badge-tia { background: #fef9c3; color: #854d0e; }
      .badge-non-compliant { background: #fee2e2; color: #991b1b; }
      .badge-review { background: #f3e8ff; color: #6b21a8; }
      .badge-na { background: #f1f5f9; color: #475569; }
      .sev-critical { background: #fee2e2; color: #991b1b; }
      .sev-high { background: #ffedd5; color: #9a3412; }
      .sev-medium { background: #fef9c3; color: #854d0e; }
      .sev-low { background: #dbeafe; color: #1e40af; }
      .sev-info { background: #f1f5f9; color: #475569; }
      .finding-card { background: var(--card); border: 1px solid var(--border);
                      border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem;
                      border-left: 4px solid var(--danger); }
      .finding-card.sev-high { border-left-color: #ea580c; }
      .finding-card.sev-medium { border-left-color: #ca8a04; }
      .finding-card.sev-low { border-left-color: #2563eb; }
      .finding-header { display: flex; justify-content: space-between; align-items: flex-start;
                        gap: 1rem; margin-bottom: 0.75rem; }
      .finding-title { font-weight: 700; font-size: 0.95rem; }
      .finding-meta { font-size: 0.8rem; color: var(--muted); margin-bottom: 0.5rem; }
      .finding-desc { font-size: 0.88rem; margin-bottom: 0.75rem; }
      .finding-remediation { background: #f0fdf4; border: 1px solid #bbf7d0;
                             border-radius: 6px; padding: 0.75rem; font-size: 0.85rem; }
      .finding-remediation strong { color: var(--success); }
      .finding-ref { font-size: 0.78rem; color: var(--muted); margin-top: 0.5rem;
                     font-style: italic; }
      .conflict-card { background: #fff7ed; border: 1px solid #fed7aa;
                       border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }
      .conflict-title { font-weight: 700; color: #9a3412; margin-bottom: 0.5rem; }
      .conflict-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;
                       margin: 0.75rem 0; }
      .conflict-box { background: white; border: 1px solid var(--border);
                      border-radius: 6px; padding: 0.75rem; font-size: 0.85rem; }
      .conflict-box h4 { font-size: 0.8rem; font-weight: 700; margin-bottom: 0.4rem; }
      .conflict-box.gdpr h4 { color: #1e3a5f; }
      .conflict-box.pci h4 { color: #7c3aed; }
      .recommendation { background: #f0fdf4; border: 1px solid #bbf7d0;
                        border-radius: 6px; padding: 0.75rem; font-size: 0.85rem; }
      .legal-review-flag { display: inline-block; background: #fef3c7; color: #92400e;
                           border: 1px solid #fcd34d; border-radius: 4px; padding: 0.2rem 0.5rem;
                           font-size: 0.75rem; font-weight: 600; margin-top: 0.5rem; }
      .art30-card { background: var(--card); border: 1px solid var(--border);
                    border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }
      .art30-title { font-weight: 700; font-size: 1rem; margin-bottom: 0.75rem;
                     display: flex; justify-content: space-between; align-items: center; }
      .art30-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;
                    font-size: 0.85rem; }
      .art30-field label { font-weight: 600; color: var(--muted); font-size: 0.78rem;
                           display: block; margin-bottom: 0.2rem; }
      .tag { display: inline-block; background: #e2e8f0; color: #475569; padding: 0.15rem 0.5rem;
             border-radius: 4px; font-size: 0.75rem; margin: 0.1rem; }
      footer { text-align: center; padding: 2rem; color: var(--muted); font-size: 0.82rem;
               border-top: 1px solid var(--border); margin-top: 3rem; }
      @media print { .container { max-width: 100%; } header { -webkit-print-color-adjust: exact; } }
    </style>
    """

    def generate(self, report: ValidationReport, output_path: str) -> None:
        html = self._build_html(report)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def _build_html(self, r: ValidationReport) -> str:
        non_compliant_count = r.non_compliant_flows
        critical_findings = [f for f in r.findings if f.severity == Severity.CRITICAL]
        high_findings = [f for f in r.findings if f.severity == Severity.HIGH]

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GDPR Cross-Border Transfer Audit — {r.organization}</title>
  {self.CSS}
</head>
<body>
<header>
  <div class="container">
    <h1>🔒 GDPR Cross-Border Data Transfer Audit</h1>
    <p>Article 30 Processing Inventory &amp; Non-Compliance Findings Report</p>
    <div class="meta">
      <span>📋 Organization: <strong>{r.organization}</strong></span>
      <span>📅 Generated: <strong>{r.generated_at}</strong></span>
      <span>⚖️ Framework: <strong>GDPR Chapter V (Arts. 44–50)</strong></span>
    </div>
  </div>
</header>

<div class="container">

  {self._executive_summary(r, non_compliant_count, critical_findings, high_findings)}
  {self._transfer_overview(r)}
  {self._findings_section(r)}
  {self._article30_section(r)}
  {self._minimization_section(r)}
  {self._conflicts_section(r)}

</div>

<footer>
  <p>Generated by <strong>GDPR Flow Validator</strong> — Yuno Engineering Challenge</p>
  <p>This report is for compliance assessment purposes only and does not constitute legal advice.</p>
  <p>Consult your Data Protection Officer and legal counsel before making compliance decisions.</p>
</footer>
</body>
</html>"""

    def _executive_summary(self, r, non_compliant, critical, high):
        risk_level = "CRITICAL" if non_compliant > 0 or critical else "MEDIUM" if high else "LOW"
        risk_color = "danger" if risk_level == "CRITICAL" else "warning" if risk_level == "MEDIUM" else "success"
        return f"""
  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="summary-grid">
      <div class="stat-card info">
        <div class="value">{r.total_flows}</div>
        <div class="label">Total Data Flows</div>
      </div>
      <div class="stat-card info">
        <div class="value">{r.cross_border_flows}</div>
        <div class="label">Cross-Border Transfers</div>
      </div>
      <div class="stat-card success">
        <div class="value">{r.compliant_flows}</div>
        <div class="label">Compliant Flows</div>
      </div>
      <div class="stat-card warning">
        <div class="value">{r.tia_required_flows}</div>
        <div class="label">TIA Required</div>
      </div>
      <div class="stat-card danger">
        <div class="value">{r.non_compliant_flows}</div>
        <div class="label">Non-Compliant</div>
      </div>
      <div class="stat-card danger">
        <div class="value">{len(critical)}</div>
        <div class="label">Critical Findings</div>
      </div>
      <div class="stat-card warning">
        <div class="value">{len(r.minimization_concerns)}</div>
        <div class="label">Minimization Issues</div>
      </div>
      <div class="stat-card {risk_color}">
        <div class="value">{risk_level}</div>
        <div class="label">Overall Risk Level</div>
      </div>
    </div>
  </div>"""

    def _transfer_overview(self, r):
        rows = ""
        for result in r.transfer_results:
            flow = result.flow
            status_cls = STATUS_BADGE.get(result.status, "badge-na")
            status_lbl = STATUS_LABEL.get(result.status, result.status)
            cats = ", ".join(flow.data_categories)
            legal = flow.legal_basis or '<span style="color:#b91c1c;font-weight:700">NONE</span>'
            tia = "✅ Yes" if flow.tia_conducted else ("⚠️ Required" if result.tia_required else "N/A")
            rows += f"""
      <tr>
        <td><code>{flow.id}</code></td>
        <td>{flow.from_service}</td>
        <td>{flow.to_service}<br><small style="color:#64748b">{flow.to_country}</small></td>
        <td><small>{cats}</small></td>
        <td>{legal}</td>
        <td>{tia}</td>
        <td><span class="badge {status_cls}">{status_lbl}</span></td>
      </tr>"""

        return f"""
  <div class="section">
    <div class="section-title">Data Flow Transfer Overview</div>
    <table>
      <thead>
        <tr>
          <th>Flow ID</th><th>Source</th><th>Destination</th>
          <th>Data Categories</th><th>Legal Basis</th><th>TIA</th><th>Status</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""

    def _findings_section(self, r):
        if not r.findings:
            return '<div class="section"><div class="section-title">Compliance Findings</div><p>No findings — all flows are compliant.</p></div>'

        # Sort: Critical → High → Medium → Low
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        sorted_findings = sorted(r.findings, key=lambda f: severity_order.get(f.severity, 99))

        cards = ""
        for f in sorted_findings:
            sev_cls = SEVERITY_BADGE.get(f.severity, "sev-info")
            cats = ", ".join(f.data_categories)
            cards += f"""
    <div class="finding-card {sev_cls}">
      <div class="finding-header">
        <div>
          <div class="finding-title">{f.finding_type}</div>
          <div class="finding-meta">
            Flow: <code>{f.flow_id}</code> &nbsp;|&nbsp;
            {f.source} → {f.destination} &nbsp;|&nbsp;
            Data: {cats}
          </div>
        </div>
        <span class="badge {sev_cls}">{f.severity}</span>
      </div>
      <div class="finding-desc">{f.description}</div>
      <div class="finding-remediation">
        <strong>🔧 Remediation:</strong> {f.remediation}
      </div>
      <div class="finding-ref">📚 {f.legal_reference}</div>
    </div>"""

        return f"""
  <div class="section">
    <div class="section-title">Compliance Findings ({len(r.findings)} total)</div>
    {cards}
  </div>"""

    def _article30_section(self, r):
        cards = ""
        for entry in r.article30_entries:
            status_cls = STATUS_BADGE.get(entry.compliance_status, "badge-na")
            status_lbl = STATUS_LABEL.get(entry.compliance_status, entry.compliance_status)
            subjects = " ".join(f'<span class="tag">{s}</span>' for s in entry.data_subjects)
            cats = " ".join(f'<span class="tag">{c}</span>' for c in entry.data_categories)
            recipients = "<br>".join(f"• {rec}" for rec in entry.recipients)
            transfers = "<br>".join(f"• {t}" for t in entry.cross_border_transfers)
            safeguards = ", ".join(entry.transfer_safeguards)

            cards += f"""
    <div class="art30-card">
      <div class="art30-title">
        <span>{entry.activity_name}</span>
        <span class="badge {status_cls}">{status_lbl}</span>
      </div>
      <div class="art30-grid">
        <div class="art30-field"><label>Controller</label>{entry.controller}</div>
        <div class="art30-field"><label>Legal Basis (Processing)</label>{entry.legal_basis}</div>
        <div class="art30-field"><label>Data Subjects</label>{subjects}</div>
        <div class="art30-field"><label>Data Categories</label>{cats}</div>
        <div class="art30-field"><label>Recipients</label>{recipients}</div>
        <div class="art30-field"><label>Retention Period</label>{entry.retention_period}</div>
        <div class="art30-field"><label>Cross-Border Transfers</label>{transfers}</div>
        <div class="art30-field"><label>Transfer Safeguards</label>{safeguards}</div>
      </div>
    </div>"""

        return f"""
  <div class="section">
    <div class="section-title">Article 30 Processing Inventory ({len(r.article30_entries)} activities)</div>
    <p style="color:#64748b;font-size:0.85rem;margin-bottom:1rem">
      This inventory satisfies GDPR Art. 30 requirements for records of processing activities (RoPA).
      Maintain this document and update it whenever processing activities change.
    </p>
    {cards}
  </div>"""

    def _minimization_section(self, r):
        if not r.minimization_concerns:
            return ""
        cards = ""
        for concern in r.minimization_concerns:
            sev_cls = SEVERITY_BADGE.get(concern.severity, "sev-info")
            recipients_str = ", ".join(concern.recipients)
            cards += f"""
    <div class="finding-card {sev_cls}">
      <div class="finding-header">
        <div>
          <div class="finding-title">Data Minimization — {concern.data_category}</div>
          <div class="finding-meta">Recipients: {recipients_str}</div>
        </div>
        <span class="badge {sev_cls}">{concern.severity}</span>
      </div>
      <div class="finding-desc">{concern.description}</div>
      <div class="finding-remediation">
        <strong>🔧 Recommendation:</strong> {concern.recommendation}
      </div>
    </div>"""

        return f"""
  <div class="section">
    <div class="section-title">Data Minimization Analysis (Art. 5(1)(c))</div>
    {cards}
  </div>"""

    def _conflicts_section(self, r):
        if not r.compliance_conflicts:
            return ""
        cards = ""
        for conflict in r.compliance_conflicts:
            sev_cls = SEVERITY_BADGE.get(conflict.severity, "sev-info")
            review_flag = '<span class="legal-review-flag">⚖️ Requires DPO + Legal Review</span>' if conflict.requires_legal_review else ""
            cards += f"""
    <div class="conflict-card">
      <div class="conflict-title">⚡ Compliance Conflict — Flow {conflict.flow_id}: {conflict.source} → {conflict.destination}</div>
      <div class="conflict-grid">
        <div class="conflict-box gdpr">
          <h4>🇪🇺 GDPR Concern</h4>
          {conflict.gdpr_concern}
        </div>
        <div class="conflict-box pci">
          <h4>💳 PCI DSS Requirement</h4>
          {conflict.pci_requirement}
        </div>
      </div>
      <div class="recommendation">
        <strong>🔧 Recommended Resolution:</strong> {conflict.recommendation}
      </div>
      {review_flag}
    </div>"""

        return f"""
  <div class="section">
    <div class="section-title">Compliance Conflicts: GDPR vs. PCI DSS ({len(r.compliance_conflicts)} detected)</div>
    <p style="color:#64748b;font-size:0.85rem;margin-bottom:1rem">
      These conflicts represent scenarios where GDPR minimization requirements and PCI DSS
      obligations are in tension. Resolution requires joint DPO and CISO decision-making.
    </p>
    {cards}
  </div>"""


# ─────────────────────────────────────────────────────────────────────────────
# JSON Reporter
# ─────────────────────────────────────────────────────────────────────────────

class JSONReporter:
    """Generates a machine-readable JSON report."""

    def generate(self, report: ValidationReport, output_path: str) -> None:
        data = self._serialize(report)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _serialize(self, r: ValidationReport) -> dict:
        return {
            "metadata": {
                "organization": r.organization,
                "generated_at": r.generated_at,
                "framework": "GDPR Chapter V (Arts. 44-50)",
                "tool_version": "1.0.0",
            },
            "summary": {
                "total_flows": r.total_flows,
                "cross_border_flows": r.cross_border_flows,
                "compliant_flows": r.compliant_flows,
                "non_compliant_flows": r.non_compliant_flows,
                "tia_required_flows": r.tia_required_flows,
                "total_findings": len(r.findings),
                "critical_findings": sum(1 for f in r.findings if f.severity == Severity.CRITICAL),
                "high_findings": sum(1 for f in r.findings if f.severity == Severity.HIGH),
                "minimization_concerns": len(r.minimization_concerns),
                "compliance_conflicts": len(r.compliance_conflicts),
            },
            "transfer_results": [
                {
                    "flow_id": res.flow.id,
                    "from": res.flow.from_service,
                    "to": res.flow.to_service,
                    "to_country": res.destination_country,
                    "is_cross_border": res.is_cross_border,
                    "legal_basis": res.flow.legal_basis,
                    "tia_conducted": res.flow.tia_conducted,
                    "tia_required": res.tia_required,
                    "status": res.status,
                    "findings_count": len(res.findings),
                }
                for res in r.transfer_results
            ],
            "findings": [
                {
                    "flow_id": f.flow_id,
                    "type": f.finding_type,
                    "severity": f.severity,
                    "source": f.source,
                    "destination": f.destination,
                    "data_categories": f.data_categories,
                    "description": f.description,
                    "remediation": f.remediation,
                    "legal_reference": f.legal_reference,
                }
                for f in r.findings
            ],
            "article30_inventory": [
                {
                    "activity": e.activity_name,
                    "controller": e.controller,
                    "purpose": e.purpose,
                    "legal_basis": e.legal_basis,
                    "data_subjects": e.data_subjects,
                    "data_categories": e.data_categories,
                    "recipients": e.recipients,
                    "cross_border_transfers": e.cross_border_transfers,
                    "transfer_safeguards": e.transfer_safeguards,
                    "retention_period": e.retention_period,
                    "compliance_status": e.compliance_status,
                }
                for e in r.article30_entries
            ],
            "minimization_concerns": [
                {
                    "data_category": c.data_category,
                    "recipient_count": c.recipient_count,
                    "recipients": c.recipients,
                    "severity": c.severity,
                    "description": c.description,
                    "recommendation": c.recommendation,
                }
                for c in r.minimization_concerns
            ],
            "compliance_conflicts": [
                {
                    "flow_id": c.flow_id,
                    "source": c.source,
                    "destination": c.destination,
                    "gdpr_concern": c.gdpr_concern,
                    "pci_requirement": c.pci_requirement,
                    "severity": c.severity,
                    "recommendation": c.recommendation,
                    "requires_legal_review": c.requires_legal_review,
                }
                for c in r.compliance_conflicts
            ],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Console Summary
# ─────────────────────────────────────────────────────────────────────────────

class ConsoleSummary:
    """Prints a concise summary to stdout."""

    COLORS = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "green": "\033[92m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
        "magenta": "\033[95m",
        "gray": "\033[90m",
    }

    def _c(self, text: str, *colors: str) -> str:
        codes = "".join(self.COLORS.get(c, "") for c in colors)
        return f"{codes}{text}{self.COLORS['reset']}"

    def print(self, r: ValidationReport) -> None:
        print()
        print(self._c("=" * 70, "bold", "blue"))
        print(self._c(f"  GDPR CROSS-BORDER TRANSFER AUDIT — {r.organization}", "bold", "blue"))
        print(self._c("=" * 70, "bold", "blue"))
        print(f"  Generated: {r.generated_at}")
        print()

        # Summary stats
        print(self._c("  SUMMARY", "bold"))
        print(f"  Total flows:          {r.total_flows}")
        print(f"  Cross-border:         {r.cross_border_flows}")
        print(f"  Compliant:            {self._c(str(r.compliant_flows), 'green', 'bold')}")
        print(f"  TIA Required:         {self._c(str(r.tia_required_flows), 'yellow', 'bold')}")
        print(f"  Non-Compliant:        {self._c(str(r.non_compliant_flows), 'red', 'bold')}")
        print(f"  Total Findings:       {len(r.findings)}")
        critical = sum(1 for f in r.findings if f.severity == Severity.CRITICAL)
        if critical:
            print(f"  Critical Findings:    {self._c(str(critical), 'red', 'bold')} ⚠️")
        print()

        # Non-compliant flows
        non_compliant = [res for res in r.transfer_results if res.status == ComplianceStatus.NON_COMPLIANT]
        if non_compliant:
            print(self._c("  ❌ NON-COMPLIANT FLOWS", "bold", "red"))
            for res in non_compliant:
                print(f"    • {res.flow.id}: {res.flow.from_service} → {res.flow.to_service} ({res.destination_country})")
                for finding in res.findings:
                    if finding.severity == Severity.CRITICAL:
                        print(f"      {self._c('CRITICAL', 'red', 'bold')}: {finding.finding_type}")
            print()

        # TIA required
        tia_flows = [res for res in r.transfer_results if res.status == ComplianceStatus.COMPLIANT_TIA_REQUIRED]
        if tia_flows:
            print(self._c("  ⚠️  TIA REQUIRED", "bold", "yellow"))
            for res in tia_flows:
                print(f"    • {res.flow.id}: {res.flow.from_service} → {res.flow.to_service} ({res.destination_country})")
            print()

        # Conflicts
        if r.compliance_conflicts:
            print(self._c(f"  ⚡ COMPLIANCE CONFLICTS: {len(r.compliance_conflicts)} (GDPR vs PCI DSS)", "bold", "magenta"))
            for c in r.compliance_conflicts:
                print(f"    • {c.flow_id}: {c.source} → {c.destination}")
            print()

        print(self._c("=" * 70, "bold", "blue"))
        print()
