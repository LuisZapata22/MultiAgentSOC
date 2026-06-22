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
    print("Telemetry parsing complete. State is DETECTING.")

    print("Running detection logic...")
    try:
        await orchestrator.run_detection()
        
        # Verify DB
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sender, receiver, task, next_action, llm_provider, fallback_triggered FROM traces")
            rows = cursor.fetchall()
            
            for row in rows:
                print(f"Trace row: {row}")
                
            assert len(rows) == 2 # One for Telemetry, one for Detection
            assert rows[1][0] == "DetectionAgent"
            
        print("Detection logic successfully executed!")
    except ValueError as e:
        print(f"Test aborted as expected due to missing config: {e}")
        print("Please copy .env.example to .env and add your API keys to run the full test.")
    
    # Cleanup
    os.remove(db_path)

if __name__ == "__main__":
    asyncio.run(test_workflow())
