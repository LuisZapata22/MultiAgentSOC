from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
import os
import shutil
import sqlite3
import json

# Import our Orchestrator
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from src.orchestrator.state_machine import OrchestratorStateMachine
from src.orchestrator.models import OrchestratorState, ElicitationResponse

app = FastAPI(title="Agentic SOC Pipeline API")

# Enable CORS for the React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In a real app, specify the frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "trace.db"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# We use a global variable to hold the orchestrator instance for the demo
orchestrator_instance = None

async def run_pipeline_task(file_path: str):
    """
    Background task to run the complete pipeline end-to-end.
    The pipeline will automatically pause at elicitation points
    (via asyncio.Event) and resume when the analyst responds.
    """
    global orchestrator_instance
    try:
        print(f"[*] Starting background pipeline for {file_path}")
        await orchestrator_instance.process_telemetry(file_path)
        
        if orchestrator_instance.state == OrchestratorState.DETECTING:
            await orchestrator_instance.run_detection()

        # After elicitation, state may be BLOCKED (timeout)
        if orchestrator_instance.state == OrchestratorState.BLOCKED:
            print("[!] Pipeline killed due to elicitation timeout.")
            return
            
        if orchestrator_instance.state == OrchestratorState.PORT_ANALYSIS:
            await orchestrator_instance.run_port_analysis()
            
        if orchestrator_instance.state == OrchestratorState.MITRE_MAPPING:
            await orchestrator_instance.run_mitre_mapping()
            
        if orchestrator_instance.state == OrchestratorState.VALIDATING:
            await orchestrator_instance.run_validation()

        if orchestrator_instance.state == OrchestratorState.BLOCKED:
            print("[!] Pipeline killed due to elicitation timeout.")
            return
            
        if orchestrator_instance.state == OrchestratorState.REPORTING:
            await orchestrator_instance.run_reporting()

        if orchestrator_instance.state == OrchestratorState.BLOCKED:
            print("[!] Pipeline killed due to elicitation timeout.")
            return
            
        print("[*] Pipeline completely finished!")
    except Exception as e:
        print(f"[!] Pipeline fatal error: {e}")

@app.post("/api/upload")
async def upload_telemetry(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """
    Uploads a Zeek NDJSON log and starts the agentic pipeline.
    """
    global orchestrator_instance
    
    # Cleanup old DB to start fresh for demo
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except:
            pass
            
    orchestrator_instance = OrchestratorStateMachine(db_path=DB_PATH)
    
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    background_tasks.add_task(run_pipeline_task, file_path)
    return {"message": "Upload successful. Pipeline started.", "filename": file.filename}

@app.get("/api/status")
async def get_status():
    """
    Returns the current state of the Orchestrator.
    Includes elicitation request ID when in AWAITING_INPUT state.
    """
    global orchestrator_instance
    if not orchestrator_instance:
        return {"state": "IDLE"}
    
    response = {"state": orchestrator_instance.state.value}
    
    # Include elicitation info when pipeline is paused
    if orchestrator_instance.state == OrchestratorState.AWAITING_INPUT:
        pending = orchestrator_instance.elicitation_mgr.get_pending()
        if pending:
            response["elicitation_id"] = pending.id
    
    return response

@app.get("/api/traces")
async def get_traces():
    """
    Returns the history of agent-to-agent traces from SQLite.
    """
    if not os.path.exists(DB_PATH):
        return {"traces": []}
        
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM traces ORDER BY timestamp ASC")
            rows = cursor.fetchall()
            return {"traces": [dict(row) for row in rows]}
    except Exception as e:
        return {"traces": [], "error": str(e)}

@app.get("/api/report")
async def get_report():
    """
    Returns the final JSON report if the pipeline is COMPLETE.
    """
    global orchestrator_instance
    if not orchestrator_instance:
        raise HTTPException(status_code=404, detail="No pipeline run initialized.")
        
    if orchestrator_instance.state != OrchestratorState.COMPLETE:
        raise HTTPException(status_code=400, detail="Pipeline is not complete yet.")
        
    return {"report": orchestrator_instance.final_report}


# --- Elicitation Endpoints ---

@app.get("/api/elicitation/pending")
async def get_pending_elicitation():
    """
    Returns the current pending elicitation request if the pipeline is paused.
    """
    global orchestrator_instance
    if not orchestrator_instance:
        return {"pending": None}
    
    pending = orchestrator_instance.elicitation_mgr.get_pending()
    if not pending:
        return {"pending": None}
    
    return {"pending": pending.model_dump()}


class ElicitationResponseBody(BaseModel):
    request_id: str
    responses: dict


@app.post("/api/elicitation/respond")
async def respond_to_elicitation(body: ElicitationResponseBody):
    """
    Submits the analyst's response to a pending elicitation request.
    This unblocks the pipeline and allows it to resume.
    """
    global orchestrator_instance
    if not orchestrator_instance:
        raise HTTPException(status_code=404, detail="No pipeline run initialized.")
    
    response = ElicitationResponse(
        request_id=body.request_id,
        responses=body.responses
    )
    
    success = orchestrator_instance.elicitation_mgr.resolve(response)
    if not success:
        raise HTTPException(status_code=400, detail="No matching pending elicitation request found.")
    
    return {"status": "accepted", "message": "Response received. Pipeline resuming."}


@app.get("/api/elicitation/history")
async def get_elicitation_history():
    """
    Returns the full audit trail of all elicitation interactions.
    """
    global orchestrator_instance
    if not orchestrator_instance:
        return {"history": []}
    
    history = orchestrator_instance.elicitation_mgr.get_history()
    return {"history": history}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)
