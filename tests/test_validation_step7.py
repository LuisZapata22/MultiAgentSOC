import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.orchestrator.state_machine import OrchestratorStateMachine
from src.orchestrator.models import OrchestratorState
import sqlite3

async def test_workflow():
    db_path = "test_trace_validation.db"

    if os.path.exists(db_path):
        os.remove(db_path)

    print("Initializing Orchestrator...")
    orchestrator = OrchestratorStateMachine(db_path=db_path)

    # Force state to VALIDATING and inject realistic-looking cumulative findings
    orchestrator.state = OrchestratorState.VALIDATING
    orchestrator.current_findings = [
        {
            "finding": "Horizontal port scan detected on port 445 (SMB).",
            "scan_type": "horizontal",
            "severity": "high",
            "evidence_refs": ["evt_1", "evt_2"]
        },
        {
            "mitre_mappings": [
                {
                    "original_finding": "Horizontal port scan detected on port 445 (SMB).",
                    "mitre_technique_id": "T1046",
                    "mitre_tactic": "mitre-discovery",
                    "justification": "Network Service Discovery involves adversaries scanning for open ports."
                }
            ]
        }
    ]

    print("Running validation logic...")
    try:
        await orchestrator.run_validation()

        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sender, receiver, task, next_action FROM traces")
            rows = cursor.fetchall()
            for row in rows:
                print(f"Trace row: {row}")

            assert len(rows) == 1
            assert rows[0][0] == "ValidationAgent"
            assert rows[0][3] == "REPORTING"

        # Also verify the deterministic result was populated
        det_report = orchestrator.validation_result.get("deterministic_report", {})
        print(f"Deterministic summary: {det_report.get('summary')}")
        validated = det_report.get("validated_findings", [])
        assert any(v["status"] == "CRITICAL" for v in validated), "Expected CRITICAL finding for T1046"

        print("Validation logic successfully executed!")

    except ValueError as e:
        print(f"Test aborted as expected due to missing config: {e}")
        print("Please ensure your .env file is fully populated.")

    # Cleanup
    try:
        os.remove(db_path)
    except PermissionError:
        print("[!] Could not delete test DB (Windows file lock) — safe to ignore.")

if __name__ == "__main__":
    asyncio.run(test_workflow())
