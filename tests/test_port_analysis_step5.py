import asyncio
import os
import sys

# Ensure src is in the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.orchestrator.state_machine import OrchestratorStateMachine
from src.orchestrator.models import OrchestratorState
import sqlite3

async def test_workflow():
    db_path = "test_trace_port.db"
    
    # Cleanup old test db if exists
    if os.path.exists(db_path):
        os.remove(db_path)
        
    print("Initializing Orchestrator...")
    orchestrator = OrchestratorStateMachine(db_path=db_path)
    
    # Manually force state to PORT_ANALYSIS to test this specific step
    orchestrator.state = OrchestratorState.PORT_ANALYSIS
    
    # Provide a dummy initial finding to simulate previous step
    orchestrator.current_findings = [{
        "finding": "High number of connection attempts to destination port 443.",
        "severity": "medium",
        "evidence_refs": [],
        "requires_port_analysis": True
    }]
    
    print("Running port analysis logic...")
    try:
        await orchestrator.run_port_analysis()
        
        # Verify DB
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sender, receiver, task, next_action FROM traces")
            rows = cursor.fetchall()
            
            for row in rows:
                print(f"Trace row: {row}")
                
            assert len(rows) == 1
            assert rows[0][0] == "PortAnalyzerAgent"
            
        print("Port analysis logic successfully executed!")
    except ValueError as e:
        print(f"Test aborted as expected due to missing config: {e}")
        print("Please ensure your .env file is fully populated.")
    
    # Cleanup
    os.remove(db_path)

if __name__ == "__main__":
    asyncio.run(test_workflow())
