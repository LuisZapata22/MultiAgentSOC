import json
from mcp.server.fastmcp import FastMCP

# Because we are running from a module potentially, we should handle imports gracefully.
from src.servers.evidence.parsers import parse_zeek_ndjson
from src.servers.evidence.models import NormalizedEvent

import os

mcp = FastMCP("Evidence")

# File-based store for the proof of concept to persist across stdio process restarts
DB_PATH = os.path.join(os.path.dirname(__file__), "normalized_events.json")

def load_events():
    if os.path.exists(DB_PATH):
        try:
            with open(DB_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_events(events):
    with open(DB_PATH, "w") as f:
        json.dump(events, f)

@mcp.tool()
def normalize_telemetry(file_path: str, source_type: str = "zeek") -> str:
    """
    Parses raw telemetry logs into a normalized schema and loads them into memory.
    
    Args:
        file_path: The absolute path to the log file.
        source_type: The type of log file (e.g., 'zeek').
    """
    global NORMALIZED_EVENTS
    if source_type.lower() != "zeek":
        return f"Error: source_type '{source_type}' is not supported yet."
    
    try:
        events = load_events()
        count = 0
        for event in parse_zeek_ndjson(file_path):
            events.append(event.model_dump())
            count += 1
        save_events(events)
        return f"Successfully normalized {count} events from {file_path}."
    except Exception as e:
        return f"Error parsing telemetry: {str(e)}"

@mcp.tool()
def read_evidence(limit: int = 100, offset: int = 0) -> str:
    """
    Fetch specific normalized events from the file store.
    
    Args:
        limit: Maximum number of events to return.
        offset: Number of events to skip.
    """
    events = load_events()
    page = events[offset:offset+limit]
    return json.dumps(page)

@mcp.resource("evidence://schemas/normalized_event")
def get_normalized_event_schema() -> str:
    """
    Returns the JSON schema for the normalized event.
    """
    return json.dumps(NormalizedEvent.model_json_schema(), indent=2)

if __name__ == "__main__":
    mcp.run(transport='stdio')
