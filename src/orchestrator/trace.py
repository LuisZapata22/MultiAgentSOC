import sqlite3
import json
from .models import TraceRecord

class TraceLogger:
    def __init__(self, db_path: str = "trace.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    receiver TEXT NOT NULL,
                    task TEXT NOT NULL,
                    evidence_used TEXT,
                    result TEXT,
                    confidence REAL,
                    next_action TEXT,
                    llm_provider TEXT,
                    fallback_triggered BOOLEAN,
                    timestamp TEXT NOT NULL
                )
            ''')
            conn.commit()

    def log(self, record: TraceRecord):
        """
        Log a TraceRecord to the SQLite database.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO traces (
                    sender, receiver, task, evidence_used, result, confidence,
                    next_action, llm_provider, fallback_triggered, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                record.sender,
                record.receiver,
                record.task,
                json.dumps(record.evidence_used),
                json.dumps(record.result),
                record.confidence,
                record.next_action,
                record.llm_provider,
                record.fallback_triggered,
                record.timestamp
            ))
            conn.commit()
