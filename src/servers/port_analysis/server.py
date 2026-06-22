import json
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("PortAnalysis")

PORT_SUMMARIES = []

@mcp.tool()
def summarize_services(events_json: str) -> str:
    """
    Summarizes normalized events by destination port to identify exposed services.
    
    Args:
        events_json: JSON string of normalized events.
    """
    try:
        events = json.loads(events_json)
        port_summary = {}
        for ev in events:
            dport = ev.get("destination_port")
            if dport is None or dport == 0:
                continue
            
            # keep track of unique sources hitting this port
            src = ev.get("source_ip", "unknown")
            if dport not in port_summary:
                port_summary[dport] = set()
            port_summary[dport].add(src)
            
        # Convert sets to lengths for summary
        summary = {port: len(sources) for port, sources in port_summary.items()}
        return json.dumps(summary)
    except Exception as e:
        return f"Error summarizing services: {str(e)}"

@mcp.prompt()
def port_reasoning_template(events_json: str, previous_findings_json: str) -> str:
    """
    Returns the reasoning template for the Port Analyzer LLM agent.
    
    Args:
        events_json: JSON string of the events to analyze.
        previous_findings_json: JSON string of findings from the Detection phase.
    """
    prompt = f"""You are a specialized SOC Port Analysis Expert.
Review the following normalized network telemetry events and the initial findings from the Detection phase.
Your goal is to perform a deep-dive analysis on port-related behavior.

Initial Detection Findings:
{previous_findings_json}

Events:
{events_json}

Specifically look for:
1. Horizontal Scanning: One source IP connecting to the same port across many destination IPs.
2. Vertical Scanning: One source IP connecting to many different ports on a single destination IP.
3. Suspicious Port Usage: Use of common malware/backdoor ports, or standard services running on non-standard ports.

Output your findings as a strict JSON array of objects, where each object has:
- "finding": A brief string describing the port-related anomaly.
- "scan_type": "horizontal", "vertical", or "none".
- "severity": "low", "medium", or "high".
- "evidence_refs": A list of timestamp or ID strings from the events that support this finding.

Return ONLY the JSON array.
"""
    return prompt

@mcp.resource("port://summaries")
def get_port_summaries() -> str:
    """
    Returns intermediate port summaries.
    """
    return json.dumps(PORT_SUMMARIES)

if __name__ == "__main__":
    mcp.run(transport='stdio')
