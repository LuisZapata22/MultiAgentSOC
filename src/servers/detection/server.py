import json
from mcp.server.fastmcp import FastMCP
from typing import List, Dict, Any

mcp = FastMCP("Detection")

# In-memory store for intermediate detection results
DETECTION_RESULTS = []

@mcp.tool()
def correlate_events(events_json: str, group_by_key: str = "source_ip") -> str:
    """
    Groups a list of JSON events by a specific key.
    
    Args:
        events_json: JSON string representing a list of normalized events.
        group_by_key: The key to group by (e.g. 'source_ip', 'destination_port').
    """
    try:
        events = json.loads(events_json)
        grouped = {}
        for ev in events:
            val = ev.get(group_by_key, "unknown")
            if val not in grouped:
                grouped[val] = []
            grouped[val].append(ev)
        return json.dumps({k: len(v) for k, v in grouped.items()})
    except Exception as e:
        return f"Error correlating events: {str(e)}"

@mcp.prompt()
def detection_reasoning_template(events_json: str) -> str:
    """
    Returns the reasoning template for the Detection LLM agent.
    
    Args:
        events_json: JSON string of the events to analyze.
    """
    prompt = f"""You are a senior SOC analyst. Review the following normalized network telemetry events.
Your goal is to detect any anomalies, suspicious patterns, or indicators of compromise (IoC).

Events:
{events_json}

Look for:
1. Unusual volume of connections from a single source to many destinations (possible scanning).
2. Many failed connections.
3. Unusual ports being used.

Output your findings as a strict JSON array of objects, where each object has:
- "finding": A brief string describing the anomaly.
- "severity": "low", "medium", or "high".
- "evidence_refs": A list of timestamp or ID strings from the events that support this finding.
- "requires_port_analysis": boolean (true if the finding suggests port scanning or unusual port exposure).

Return ONLY the JSON array.
"""
    return prompt

@mcp.resource("detection://results")
def get_detection_results() -> str:
    """
    Returns the intermediate detection results.
    """
    return json.dumps(DETECTION_RESULTS)

if __name__ == "__main__":
    mcp.run(transport='stdio')
