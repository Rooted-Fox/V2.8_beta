"""Professional report generator: HTML, CSV, JSON formats."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Optional

from store import FindingsStore


def _severity_color(severity: str) -> str:
    return {
        "critical": "#ff5c5c", "high": "#ffa94d",
        "medium": "#ffd43b", "low": "#748ffc", "info": "#6c7685"
    }.get(severity, "#6c7685")


def generate_html(app_name: Optional[str] = None) -> str:
    store = FindingsStore()
    findings = [dict(r) for r in store.all(app_name=app_name)]
    chains = [dict(r) for r in store.chains(app_name=app_name)]
    sev_summary = store.severity_summary(app_name=app_name)
    rem_summary = store.remediation_summary(app_name=app_name)
    total = len(findings)
    title = f"{app_name or 'All Applications'} — Security Assessment Report"
    date = datetime.utcnow().strftime("%B %d, %Y")

    critical = sev_summary.get("critical", 0)
    high = sev_summary.get("high", 0)
    overall_risk = "Critical" if critical > 0 else "High" if high > 0 else "Medium"

    # build findings HTML
    findings_html = ""
    for f in findings:
        sev = f.get("severity", "info")
        color = _severity_color(sev)
        cvss = f.get("cvss_score")
        cvss_str = f"{cvss}" if cvss else "N/A"
        findings_html += f"""
<div class="finding-card">
  <div class="finding-header" style="border-left: 4px solid {color};">
    <div>
      <h3>{f.get('vulnerability_name') or f.get('rationale','Finding')[:60]}</h3>
      <p class="meta">{f.get('url','N/A')} &middot; {f.get('cwe_id','')} {f.get('cwe_name','')}</p>
    </div>
    <div class="badges">
      <span class="badge" style="background:{color}20;color:{color};">{sev.upper()}</span>
      <span class="badge-cvss">CVSS {cvss_str}</span>
      <span class="badge-conf">{f.get('confidence',0)}% confidence</span>
    </div>
  </div>
  <div class="finding-body">
    <div class="section"><h4>Root Cause</h4><p>{f.get('root_cause','—')}</p></div>
    <div class="section"><h4>Technical Impact</h4><p>{f.get('technical_impact','—')}</p></div>
    <div class="section"><h4>Business Impact</h4><p>{f.get('business_impact','—')}</p></div>
    <div class="section"><h4>Attack Scenario</h4><p>{f.get('attack_scenario','—')}</p></div>
    <div class="section"><h4>Reproduction Steps</h4><pre>{f.get('reproduction_steps','—')}</pre></div>
    <div class="section"><h4>Remediation</h4><p>{f.get('remediation','—')}</p></div>
    <div class="section meta-row">
      <span>CVSS Vector: <code>{f.get('cvss_vector','N/A')}</code></span>
      <span>Validation: {f.get('validation_status','—').upper()}</span>
      <span>Status: {f.get('remediation_status','open').replace('_',' ').title()}</span>
    </div>
  </div>
</div>"""

    # attack chains HTML
    chains_html = ""
    for c in chains:
        chains_html += f"""
<div class="chain-card">
  <h3>{c.get('chain_name','Attack Chain')}</h3>
  <div class="chain-meta">
    <span>Risk Score: <strong>{c.get('risk_score',0)}</strong>/10</span>
    <span>Difficulty: {c.get('exploitation_difficulty','medium').title()}</span>
  </div>
  <div class="section"><h4>Attack Flow</h4><pre>{c.get('attack_flow','—')}</pre></div>
  <div class="section"><h4>Business Impact</h4><p>{c.get('business_impact','—')}</p></div>
  <div class="section"><h4>Mitigations</h4><p>{c.get('mitigations','—')}</p></div>
</div>"""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #f8f9fa; color: #1a1d23; line-height: 1.6; }}
  .page {{ max-width: 960px; margin: 0 auto; padding: 40px 24px; }}
  .cover {{ background: #11151c; color: #fff; padding: 48px; margin-bottom: 40px; border-radius: 8px; }}
  .cover h1 {{ font-size: 28px; font-weight: 600; margin-bottom: 8px; }}
  .cover .sub {{ color: #8b94a3; font-size: 15px; }}
  .exec-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 40px; }}
  .exec-card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px; text-align: center; }}
  .exec-card .val {{ font-size: 32px; font-weight: 700; }}
  .exec-card .lbl {{ font-size: 13px; color: #6b7280; margin-top: 4px; }}
  .critical {{ color: #dc2626; }} .high {{ color: #ea580c; }}
  .medium {{ color: #ca8a04; }} .low {{ color: #4f46e5; }}
  h2 {{ font-size: 20px; font-weight: 600; margin: 32px 0 16px; padding-bottom: 8px;
        border-bottom: 2px solid #e5e7eb; }}
  .finding-card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 8px;
                   margin-bottom: 20px; overflow: hidden; }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start;
                     padding: 16px 20px; background: #f9fafb; }}
  .finding-header h3 {{ font-size: 16px; font-weight: 600; margin-bottom: 4px; }}
  .finding-body {{ padding: 20px; }}
  .section {{ margin-bottom: 16px; }}
  .section h4 {{ font-size: 13px; font-weight: 600; color: #6b7280; text-transform: uppercase;
                 letter-spacing: 0.05em; margin-bottom: 6px; }}
  .section p, .section pre {{ font-size: 14px; white-space: pre-wrap; word-break: break-word; }}
  .badges {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-start; }}
  .badge {{ font-size: 12px; padding: 3px 10px; border-radius: 999px; font-weight: 600; }}
  .badge-cvss {{ font-size: 12px; padding: 3px 10px; border-radius: 4px;
                 background: #f3f4f6; color: #374151; font-family: monospace; }}
  .badge-conf {{ font-size: 12px; padding: 3px 10px; border-radius: 4px;
                  background: #eff6ff; color: #1d4ed8; }}
  .meta {{ font-size: 13px; color: #6b7280; margin-top: 4px; }}
  .meta-row {{ display: flex; gap: 20px; font-size: 13px; color: #6b7280;
               padding-top: 12px; border-top: 1px solid #f3f4f6; }}
  .chain-card {{ background: #fff; border: 1px solid #fde68a; border-radius: 8px;
                 padding: 20px; margin-bottom: 20px; }}
  .chain-card h3 {{ font-size: 16px; font-weight: 600; margin-bottom: 12px; }}
  .chain-meta {{ display: flex; gap: 20px; font-size: 13px; color: #6b7280; margin-bottom: 16px; }}
  code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
  .rem-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }}
  .rem-card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; text-align: center; }}
  @media print {{ body {{ background: #fff; }} .page {{ padding: 20px; }} }}
</style>
</head>
<body>
<div class="page">
  <div class="cover">
    <h1>{title}</h1>
    <p class="sub">Generated: {date} &nbsp;|&nbsp; Overall Risk: {overall_risk} &nbsp;|&nbsp; Total Findings: {total}</p>
  </div>

  <h2>Executive Summary</h2>
  <div class="exec-grid">
    <div class="exec-card"><div class="val critical">{sev_summary.get('critical',0)}</div><div class="lbl">Critical</div></div>
    <div class="exec-card"><div class="val high">{sev_summary.get('high',0)}</div><div class="lbl">High</div></div>
    <div class="exec-card"><div class="val medium">{sev_summary.get('medium',0)}</div><div class="lbl">Medium</div></div>
    <div class="exec-card"><div class="val low">{sev_summary.get('low',0)}</div><div class="lbl">Low</div></div>
  </div>

  <h2>Remediation Status</h2>
  <div class="rem-grid">
    <div class="rem-card"><div class="val">{rem_summary.get('open',0)}</div><div class="lbl">Open</div></div>
    <div class="rem-card"><div class="val">{rem_summary.get('in_progress',0)}</div><div class="lbl">In Progress</div></div>
    <div class="rem-card"><div class="val">{rem_summary.get('remediated',0)}</div><div class="lbl">Remediated</div></div>
  </div>

  {'<h2>Attack Chains</h2>' + chains_html if chains_html else ''}

  <h2>Findings</h2>
  {findings_html if findings_html else '<p style="color:#6b7280">No findings yet.</p>'}
</div>
</body>
</html>"""


def generate_csv(app_name: Optional[str] = None) -> str:
    store = FindingsStore()
    findings = [dict(r) for r in store.all(app_name=app_name)]
    output = io.StringIO()
    fields = ["id", "vulnerability_name", "severity", "cvss_score", "cvss_vector",
              "cwe_id", "cwe_name", "category", "url", "app_name",
              "confidence", "validation_status", "exploitable",
              "root_cause", "technical_impact", "business_impact",
              "remediation", "remediation_status", "created_at"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(findings)
    return output.getvalue()


def generate_csv_report(app_name: Optional[str] = None) -> str:
    """Pentest-report-style CSV: Affected URL, Vulnerable Parameter, Analysis,
    Description, Impact, Remediation Steps, Evidence. One row per evaluated
    finding, built from the rich fields Opus produces during triage."""
    store = FindingsStore()
    findings = [dict(r) for r in store.all(app_name=app_name)]

    output = io.StringIO()
    columns = ["Affected URL", "Vulnerable Parameter", "Analysis", "Description",
               "Impact", "Remediation Steps", "Evidence"]
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()

    for f in findings:
        analysis = " | ".join(filter(None, [
            f.get("root_cause"),
            f.get("attack_scenario"),
        ]))
        description = " — ".join(filter(None, [
            f.get("vulnerability_name"),
            f.get("rationale"),
        ]))
        impact = " | ".join(filter(None, [
            f"Technical: {f['technical_impact']}" if f.get("technical_impact") else None,
            f"Business: {f['business_impact']}" if f.get("business_impact") else None,
        ]))
        evidence = " | ".join(filter(None, [
            f.get("evidence_summary"),
            f"Reproduction: {f['reproduction_steps']}" if f.get("reproduction_steps") else None,
        ]))
        writer.writerow({
            "Affected URL": f.get("url") or "",
            "Vulnerable Parameter": f.get("vulnerable_parameter") or "N/A",
            "Analysis": analysis,
            "Description": description,
            "Impact": impact,
            "Remediation Steps": f.get("remediation") or "",
            "Evidence": evidence,
        })

    return output.getvalue()


def generate_json(app_name: Optional[str] = None) -> str:
    store = FindingsStore()
    findings = [dict(r) for r in store.all(app_name=app_name)]
    chains = [dict(r) for r in store.chains(app_name=app_name)]
    return json.dumps({"findings": findings, "attack_chains": chains}, indent=2, default=str)
