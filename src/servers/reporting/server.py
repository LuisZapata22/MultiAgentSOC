import json
import os
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Reporting")

REPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "reports")

@mcp.tool()
def save_report(report_json: str, filename: str = "") -> str:
    """
    Saves the final analyst report to disk as a JSON file.

    Args:
        report_json: JSON string of the complete report object.
        filename: Optional filename. If empty, auto-generates from timestamp.
    """
    os.makedirs(REPORT_DIR, exist_ok=True)

    if not filename:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"soc_report_{ts}.json"

    out_path = os.path.join(REPORT_DIR, filename)
    try:
        report = json.loads(report_json)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return json.dumps({"status": "saved", "path": out_path})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

@mcp.prompt()
def report_generation_template(
    validation_report_json: str,
    mitre_mappings_json: str,
    llm_summary_json: str
) -> str:
    """
    Returns the Claude-specific reporting prompt.

    Args:
        validation_report_json: The deterministic validation report JSON.
        mitre_mappings_json: The MITRE ATT&CK mappings JSON.
        llm_summary_json: The LLM-generated validation summary JSON.
    """
    ts = datetime.now(timezone.utc).isoformat()
    prompt = f"""You are a senior cybersecurity analyst producing a formal Incident Assessment Report.
Your report will be reviewed by a human analyst and must be precise, professional, and actionable.
This is a DEFENSIVE SECURITY REPORT ONLY — do not suggest or describe any offensive actions.
You must synthesize the technical findings into a cohesive narrative, avoiding simple recitation of logs. Explain the potential business impact of the identified threats.

Report Timestamp: {ts}

=== Deterministic Validation Report ===
{validation_report_json}

=== MITRE ATT&CK Mappings ===
{mitre_mappings_json}

=== Analyst Summary ===
{llm_summary_json}

Produce a formal JSON report object with the following structure:
```json
{{
  "report_id": "<generate a short UUID>",
  "generated_at": "{ts}",
  "executive_summary": "<2-3 sentences for a CISO-level audience>",
  "risk_level": "CRITICAL | HIGH | MEDIUM | LOW",
  "findings": [
    {{
      "id": "<sequential number>",
      "title": "<short finding title>",
      "description": "<detailed description>",
      "mitre_technique_id": "<e.g. T1046 or empty string>",
      "mitre_tactic": "<tactic name or empty string>",
      "severity": "critical | high | medium | low",
      "status": "CRITICAL | CONFIRMED | REVIEW_NEEDED | UNCONFIRMED",
      "recommended_action": "<specific, actionable next step for the analyst>"
    }}
  ],
  "recommended_next_steps": ["<step 1>", "<step 2>", "<step 3>"],
  "analyst_notes": "<any caveats, limitations of this automated analysis, or context>"
}}
```

After the JSON block, you MUST output the ENTIRE formal report formatted in pure Markdown. 
Precede the markdown report with this exact delimiter: === FORMAL REPORT ===

The Markdown report MUST include the following headers exactly:
# Problem analyzed
# Agents used
# Evidence processed
# Summarized conversation between agents
# Findings
# Prioritized risks
# Recommendations
# Human validation
# System limitations

Use proper markdown tables, bullet points, and formatting to make this a beautiful, readable document. Under the Findings section, include detailed explanations of each threat and reference the specific IP addresses and ports involved. Under Prioritized risks, explain the potential business impact of each critical threat.
"""
    return prompt

if __name__ == "__main__":
    mcp.run(transport='stdio')
