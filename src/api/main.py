from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
import os
import shutil
import sqlite3

# Import our Orchestrator
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from src.orchestrator.state_machine import OrchestratorStateMachine
from src.orchestrator.models import OrchestratorState

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
    """
    global orchestrator_instance
    try:
        print(f"[*] Starting background pipeline for {file_path}")
        await orchestrator_instance.process_telemetry(file_path)
        
        if orchestrator_instance.state == OrchestratorState.DETECTING:
            await orchestrator_instance.run_detection()
            
        if orchestrator_instance.state == OrchestratorState.PORT_ANALYSIS:
            await orchestrator_instance.run_port_analysis()
            
        if orchestrator_instance.state == OrchestratorState.MITRE_MAPPING:
            await orchestrator_instance.run_mitre_mapping()
            
        if orchestrator_instance.state == OrchestratorState.VALIDATING:
            await orchestrator_instance.run_validation()
            
        if orchestrator_instance.state == OrchestratorState.REPORTING:
            await orchestrator_instance.run_reporting()
            
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
    """
    global orchestrator_instance
    if not orchestrator_instance:
        return {"state": "IDLE"}
    return {"state": orchestrator_instance.state.value}

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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)
