import asyncio
import os
import sys

# Ensure src is in the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.orchestrator.state_machine import OrchestratorStateMachine
from src.orchestrator.models import OrchestratorState
import sqlite3

async def test_workflow():
    db_path = "test_trace.db"
    
    # Cleanup old test db if exists
    if os.path.exists(db_path):
        os.remove(db_path)
        
    print("Initializing Orchestrator...")
    orchestrator = OrchestratorStateMachine(db_path=db_path)
    
    log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'zeek-capture.ndjson'))
    
    print("Starting process_telemetry...")
    await orchestrator.process_telemetry(log_path, source_type="zeek")
    
    assert orchestrator.state == OrchestratorState.DETECTING
    print("Workflow state correctly transitioned to DETECTING.")
    
    # Verify DB
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT sender, receiver, task, next_action FROM traces")
        rows = cursor.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "Host"
        assert rows[0][1] == "TelemetryAgent"
        assert rows[0][2] == "normalize_telemetry"
        assert rows[0][3] == "DETECTING"
        
    print("Trace log successfully validated!")
    
    # Cleanup
    os.remove(db_path)

if __name__ == "__main__":
    asyncio.run(test_workflow())
