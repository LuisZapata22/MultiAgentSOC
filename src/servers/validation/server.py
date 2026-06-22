import json
from typing import List, Dict, Any
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Validation")

# Known high-risk MITRE techniques that automatically escalate severity
HIGH_RISK_TECHNIQUES = {
    "T1046",   # Network Service Discovery
    "T1110",   # Brute Force
    "T1071",   # Application Layer Protocol (C2)
    "T1021",   # Remote Services (Lateral Movement)
    "T1048",   # Exfiltration Over Alternative Protocol
    "T1059",   # Command and Scripting Interpreter
    "T1078",   # Valid Accounts
    "T1190",   # Exploit Public-Facing Application
    "T1133",   # External Remote Services
    "T1505",   # Server Software Component
}

@mcp.tool()
def validate_findings(findings_json: str) -> str:
    """
    Deterministically validates a list of findings against known thresholds and rules.
    Returns a validation report with pass/fail for each finding.

    Validation rules:
    - Findings without a MITRE technique ID are flagged as UNCONFIRMED.
    - Findings with a known HIGH_RISK technique ID are escalated to CRITICAL.
    - Findings with severity 'high' are flagged as CONFIRMED.
    - All others are set to REVIEW_NEEDED.

    Args:
        findings_json: JSON string of the findings (including MITRE mappings).
    """
    try:
        findings = json.loads(findings_json)
    except Exception as e:
        return json.dumps({"error": f"Failed to parse findings: {e}"})

    validated = []
    for f in findings:
        # Handle both direct findings and MITRE mapping entries
        if "mitre_mappings" in f:
            for mapping in f["mitre_mappings"]:
                tech_id = mapping.get("mitre_technique_id", "")
                result = _validate_single(mapping.get("original_finding", ""), tech_id, "medium")
                validated.append(result)
        else:
            finding_text = f.get("finding", "")
            severity = f.get("severity", "low")
            tech_id = f.get("mitre_technique_id", "")
            result = _validate_single(finding_text, tech_id, severity)
            validated.append(result)

    summary = {
        "total": len(validated),
        "critical": sum(1 for v in validated if v["status"] == "CRITICAL"),
        "confirmed": sum(1 for v in validated if v["status"] == "CONFIRMED"),
        "review_needed": sum(1 for v in validated if v["status"] == "REVIEW_NEEDED"),
        "unconfirmed": sum(1 for v in validated if v["status"] == "UNCONFIRMED"),
    }

    return json.dumps({"summary": summary, "validated_findings": validated})

def _validate_single(finding_text: str, tech_id: str, severity: str) -> Dict[str, Any]:
    if not tech_id:
        status = "UNCONFIRMED"
        reason = "No MITRE technique ID was assigned."
    elif tech_id in HIGH_RISK_TECHNIQUES:
        status = "CRITICAL"
        reason = f"Technique {tech_id} is on the HIGH_RISK watchlist."
    elif severity == "high":
        status = "CONFIRMED"
        reason = "Severity was rated high by the detection layer."
    else:
        status = "REVIEW_NEEDED"
        reason = "Requires human analyst review — severity is not high enough for automatic confirmation."

    return {
        "finding": finding_text,
        "mitre_technique_id": tech_id,
        "status": status,
        "reason": reason,
    }

@mcp.prompt()
def validation_summary_template(validated_json: str) -> str:
    """
    Returns a prompt template for the LLM to produce a plain-language validation summary.

    Args:
        validated_json: JSON string of the deterministic validation report.
    """
    prompt = f"""You are a senior SOC analyst reviewing an automatically generated validation report.

Validation Report:
{validated_json}

Your task:
1. Summarize the overall risk posture in 2-3 sentences.
2. List the top 3 most critical findings, explaining WHY they are risky in plain language.
3. Recommend a clear next action for the analyst (e.g., "Immediately isolate host 192.168.1.5", 
   "Escalate to Tier 2", "Continue monitoring — no immediate action required").

Keep the tone professional and concise. Your output will go directly into the final analyst report.
Return a JSON object with keys: "risk_summary", "top_findings", "recommended_action".
"""
    return prompt

if __name__ == "__main__":
    mcp.run(transport='stdio')
