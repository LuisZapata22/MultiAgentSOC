import asyncio
import sqlite3
import json
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from .models import ElicitationRequest, ElicitationResponse


class ElicitationManager:
    """
    Manages the Human-in-the-Loop elicitation lifecycle:
    - Stores elicitation requests and responses in SQLite for audit trail.
    - Uses asyncio.Event to pause/resume the pipeline.
    - Enforces a 5-minute timeout — kills the pipeline if the analyst doesn't respond.
    """

    TIMEOUT_SECONDS = 300  # 5 minutes

    def __init__(self, db_path: str = "trace.db"):
        self.db_path = db_path
        self._pending_request: Optional[ElicitationRequest] = None
        self._pending_response: Optional[ElicitationResponse] = None
        self._resume_event: asyncio.Event = asyncio.Event()
        self._history: List[Dict[str, Any]] = []
        self._init_db()

    def _init_db(self):
        """Create the elicitations table if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS elicitations (
                    id TEXT PRIMARY KEY,
                    agent TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    context TEXT,
                    fields TEXT NOT NULL,
                    request_timestamp TEXT NOT NULL,
                    response TEXT,
                    response_timestamp TEXT,
                    status TEXT DEFAULT 'pending'
                )
            ''')
            conn.commit()

    async def request_input(self, req: ElicitationRequest) -> Optional[ElicitationResponse]:
        """
        Stores the elicitation request, pauses the pipeline, and waits for the
        analyst's response. Returns the response or None if timeout expires.

        This method BLOCKS the calling coroutine until either:
        1. The analyst submits a response (via resolve()), or
        2. The 5-minute timeout expires.
        """
        # Store in SQLite
        self._store_request(req)

        # Set as pending
        self._pending_request = req
        self._pending_response = None
        self._resume_event.clear()

        print(f"[*] ELICITATION: Pipeline paused. Waiting for analyst input...")
        print(f"    Agent: {req.agent} | Title: {req.title}")
        print(f"    Timeout: {self.TIMEOUT_SECONDS}s")

        try:
            # Wait for the analyst to respond, with timeout
            await asyncio.wait_for(
                self._resume_event.wait(),
                timeout=self.TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            print(f"[!] ELICITATION TIMEOUT: Analyst did not respond within {self.TIMEOUT_SECONDS}s. Killing pipeline.")
            self._update_status(req.id, "timeout")
            self._pending_request = None
            return None

        # Analyst responded
        response = self._pending_response
        self._pending_request = None
        self._pending_response = None
        return response

    def resolve(self, response: ElicitationResponse) -> bool:
        """
        Called by the API when the analyst submits their form.
        Stores the response and unblocks the pipeline.
        Returns True if successful, False if no matching pending request.
        """
        if not self._pending_request:
            print("[!] ELICITATION: No pending request to resolve.")
            return False

        if response.request_id != self._pending_request.id:
            print(f"[!] ELICITATION: Response ID {response.request_id} doesn't match pending {self._pending_request.id}")
            return False

        # Store response in SQLite
        self._store_response(response)

        # Add to in-memory history for the report
        self._history.append({
            "request": self._pending_request.model_dump(),
            "response": response.model_dump()
        })

        self._pending_response = response
        self._resume_event.set()

        print(f"[*] ELICITATION: Analyst responded to '{self._pending_request.title}'. Resuming pipeline.")
        return True

    def get_pending(self) -> Optional[ElicitationRequest]:
        """Returns the current pending elicitation request, if any."""
        return self._pending_request

    def get_history(self) -> List[Dict[str, Any]]:
        """Returns the full elicitation history for audit trail in the report."""
        # If in-memory history is empty, load from DB
        if not self._history:
            self._history = self._load_history_from_db()
        return self._history

    def _store_request(self, req: ElicitationRequest):
        """Persist the elicitation request to SQLite."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO elicitations
                (id, agent, stage, title, description, context, fields, request_timestamp, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
            ''', (
                req.id,
                req.agent,
                req.stage,
                req.title,
                req.description,
                json.dumps(req.context),
                json.dumps([f.model_dump() for f in req.fields]),
                req.timestamp
            ))
            conn.commit()

    def _store_response(self, resp: ElicitationResponse):
        """Persist the analyst's response to SQLite."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE elicitations
                SET response = ?, response_timestamp = ?, status = 'resolved'
                WHERE id = ?
            ''', (
                json.dumps(resp.responses),
                resp.timestamp,
                resp.request_id
            ))
            conn.commit()

    def _update_status(self, request_id: str, status: str):
        """Update the status of an elicitation record."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE elicitations SET status = ? WHERE id = ?',
                (status, request_id)
            )
            conn.commit()

    def _load_history_from_db(self) -> List[Dict[str, Any]]:
        """Load all resolved elicitation records from SQLite."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM elicitations WHERE status = 'resolved' ORDER BY request_timestamp ASC"
                )
                rows = cursor.fetchall()
                history = []
                for row in rows:
                    history.append({
                        "request": {
                            "id": row["id"],
                            "agent": row["agent"],
                            "stage": row["stage"],
                            "title": row["title"],
                            "description": row["description"],
                            "timestamp": row["request_timestamp"]
                        },
                        "response": {
                            "request_id": row["id"],
                            "responses": json.loads(row["response"]) if row["response"] else {},
                            "timestamp": row["response_timestamp"]
                        }
                    })
                return history
        except Exception:
            return []
