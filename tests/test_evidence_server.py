import sys
import os
import asyncio

# Ensure src is in the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.servers.evidence.server import normalize_telemetry, read_evidence, get_normalized_event_schema

def test_server_logic():
    print("Testing get_normalized_event_schema()...")
    schema = get_normalized_event_schema()
    assert "NormalizedEvent" in schema
    print("Schema OK.")

    print("Testing normalize_telemetry()...")
    log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'zeek-capture.ndjson'))
    result = normalize_telemetry(log_path, "zeek")
    print("Normalize result:", result)
    assert "Successfully normalized" in result

    print("Testing read_evidence()...")
    evidence = read_evidence(limit=2)
    # the returned value is a json string array representation
    assert len(evidence) > 10
    print("Read evidence OK.")
    
    print("All direct logic tests passed!")

if __name__ == "__main__":
    test_server_logic()
