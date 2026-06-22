import asyncio
import os
import sys

# Ensure src is in the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.orchestrator.state_machine import OrchestratorStateMachine
from src.orchestrator.models import OrchestratorState
import sqlite3

async def test_workflow():
    db_path = "test_trace_mitre.db"
    
    # Cleanup old test db if exists
    if os.path.exists(db_path):
        os.remove(db_path)
        
    print("Initializing Orchestrator...")
    orchestrator = OrchestratorStateMachine(db_path=db_path)
    
    # Manually force state to MITRE_MAPPING
    orchestrator.state = OrchestratorState.MITRE_MAPPING
    
    # Provide dummy findings to map
    orchestrator.current_findings = [{
        "finding": "Horizontal port scan detected on port 445.",
        "scan_type": "horizontal",
        "severity": "medium",
        "evidence_refs": ["evt_1", "evt_2"]
    }]
    
    print("Running MITRE mapping logic...")
    try:
        await orchestrator.run_mitre_mapping()
        
        # Verify DB
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sender, receiver, task, next_action FROM traces")
            rows = cursor.fetchall()
            
            for row in rows:
                print(f"Trace row: {row}")
                
            assert len(rows) == 1
            assert rows[0][0] == "MitreAgent"
            
        print("MITRE mapping logic successfully executed!")
    except ValueError as e:
        print(f"Test aborted as expected due to missing config: {e}")
        print("Please ensure your .env file is fully populated.")
    
    # Cleanup
    os.remove(db_path)

if __name__ == "__main__":
    asyncio.run(test_workflow())
