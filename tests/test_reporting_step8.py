import asyncio
import os
import sys
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.orchestrator.state_machine import OrchestratorStateMachine
from src.orchestrator.models import OrchestratorState
import sqlite3

async def test_workflow():
    db_path = "test_trace_reporting.db"

    if os.path.exists(db_path):
        os.remove(db_path)

    print("Initializing Orchestrator...")
    orchestrator = OrchestratorStateMachine(db_path=db_path)

    # Force state to REPORTING and inject realistic accumulated pipeline state
    orchestrator.state = OrchestratorState.REPORTING

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
                    "justification": "Network Service Discovery matches port scanning behavior."
                }
            ]
        }
    ]

    orchestrator.validation_result = {
        "deterministic_report": {
            "summary": {"total": 2, "critical": 1, "confirmed": 0, "review_needed": 0, "unconfirmed": 1},
            "validated_findings": [
                {
                    "finding": "Horizontal port scan detected on port 445 (SMB).",
                    "mitre_technique_id": "T1046",
                    "status": "CRITICAL",
                    "reason": "Technique T1046 is on the HIGH_RISK watchlist."
                },
                {
                    "finding": "High connection volume to port 443.",
                    "mitre_technique_id": "",
                    "status": "UNCONFIRMED",
                    "reason": "No MITRE technique ID was assigned."
                }
            ]
        },
        "llm_summary": {
            "risk_summary": "Critical port scanning activity was detected from a single host.",
            "top_findings": ["SMB port scan indicating lateral movement preparation."],
            "recommended_action": "Isolate source host and escalate to Tier 2."
        }
    }

    print("Running reporting logic...")
    try:
        await orchestrator.run_reporting()

        # Verify DB
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sender, receiver, task, next_action FROM traces")
            rows = cursor.fetchall()
            for row in rows:
                print(f"Trace row: {row}")

            assert len(rows) == 1
            assert rows[0][0] == "ReportingAgent"
            assert rows[0][3] == "COMPLETE"

        # Verify report file exists
        assert os.path.exists(orchestrator.report_path), "Report file was not saved!"
        print(f"Report saved at: {orchestrator.report_path}")

        with open(orchestrator.report_path, 'r') as f:
            report = json.load(f)
            print(f"Report risk_level: {report.get('risk_level')}")
            print(f"Findings count: {len(report.get('findings', []))}")
            assert "findings" in report

        print("Reporting logic successfully executed!")

    except Exception as e:
        print(f"Error: {e}")
        raise

    # Cleanup
    try:
        os.remove(db_path)
    except PermissionError:
        print("[!] Could not delete test DB (Windows file lock) — safe to ignore.")

if __name__ == "__main__":
    asyncio.run(test_workflow())
