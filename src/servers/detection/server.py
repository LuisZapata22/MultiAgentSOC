import sys
import os
from datetime import datetime
from mcp.server.fastmcp import FastMCP
from typing import List, Dict, Any

# Ensure src modules can be resolved if run standalone
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))

from src.detections.detection_engine import DetectionEngine
from src.models.schemas import TelemetryRecord

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

@mcp.tool()
def run_heuristic_detections(events_json: str) -> str:
    """
    Runs the programmatic heuristic detection engine over normalized telemetry.
    
    Args:
        events_json: JSON string representing a list of normalized events.
    """
    try:
        import json
        events = json.loads(events_json)
        records = []
        for ev in events:
            # Convert basic json to TelemetryRecord
            dt = datetime.fromtimestamp(ev.get("timestamp", 0))
            record = TelemetryRecord(
                timestamp=dt,
                source_ip=ev.get("source_ip"),
                destination_ip=ev.get("destination_ip"),
                destination_port=ev.get("destination_port"),
                dns_query=ev.get("raw_data", {}).get("query"),
                protocol=ev.get("protocol"),
                service=ev.get("service"),
                state=ev.get("connection_state"),
                bytes_sent=ev.get("bytes_sent"),
                bytes_received=ev.get("bytes_received"),
                raw_data=ev
            )
            records.append(record)
            
        engine = DetectionEngine()
        findings = engine.run(records)
        
        # Serialize findings back to JSON
        findings_list = []
        for f in findings:
            findings_list.append({
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value.lower(),
                "source_ip": f.source_ip,
                "destination_ip": f.destination_ip,
                "port": f.port,
                "protocol": f.protocol,
                "detection_type": f.detection_type,
                "evidence_refs": [f.evidence],
                "requires_port_analysis": "Port Scan" in f.detection_type or "Unusual Port" in f.detection_type
            })
            
        return json.dumps(findings_list)
    except Exception as e:
        return json.dumps({"error": f"Heuristic engine failed: {str(e)}"})

@mcp.prompt()
def detection_reasoning_template(events_json: str, heuristic_findings_json: str = "[]") -> str:
    """
    Returns the reasoning template for the Detection LLM agent.
    
    Args:
        events_json: JSON string of the events to analyze.
    """
    prompt = f"""You are a senior SOC analyst. Review the following normalized network telemetry events.
Your goal is to detect any anomalies, suspicious patterns, or indicators of compromise (IoC) that were MISSED by the programmatic heuristic rules.
The heuristic engine has already run and produced the following findings:

=== Heuristic Findings ===
{heuristic_findings_json}

=== Telemetry Events ===
{events_json}

Look for:
1. Unusual volume of connections from a single source to many destinations (possible scanning).
2. Many failed connections or dropped packets.
3. Unusual ports being used (e.g., standard services on high ports, or known malware ports like 4444).
4. Correlate multiple events: if an IP scans ports and then transfers a large amount of data, flag it as a compound attack.
5. Filter out obvious benign traffic (e.g. standard DNS to 8.8.8.8) to reduce false positives.

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
