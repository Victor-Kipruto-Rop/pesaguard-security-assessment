"""Append-only local evidence journal with a SHA-256 hash chain."""
from __future__ import annotations
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

class EvidenceStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS evidence (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE
            )""")

    def _connect(self):
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not event_type or len(event_type) > 80:
            raise ValueError("event_type must be 1..80 characters")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        created = datetime.now(timezone.utc).isoformat()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT event_hash FROM evidence ORDER BY sequence DESC LIMIT 1").fetchone()
            previous = row[0] if row else GENESIS
            material = "\n".join((created, event_type, canonical, previous))
            digest = hashlib.sha256(material.encode()).hexdigest()
            cursor = db.execute("INSERT INTO evidence(created_at,event_type,payload_json,previous_hash,event_hash) VALUES(?,?,?,?,?)",
                (created, event_type, canonical, previous, digest))
            sequence = cursor.lastrowid
        return {"sequence": sequence, "created_at": created, "event_type": event_type,
                "previous_hash": previous, "event_hash": digest}

    def verify(self) -> dict[str, Any]:
        expected_previous = GENESIS
        count = 0
        with self._connect() as db:
            rows = db.execute("SELECT created_at,event_type,payload_json,previous_hash,event_hash FROM evidence ORDER BY sequence").fetchall()
        for created, event_type, payload, previous, digest in rows:
            if previous != expected_previous:
                return {"valid": False, "verified_events": count, "failed_at": count + 1}
            material = "\n".join((created, event_type, payload, previous))
            expected = hashlib.sha256(material.encode()).hexdigest()
            if expected != digest:
                return {"valid": False, "verified_events": count, "failed_at": count + 1}
            expected_previous = digest
            count += 1
        return {"valid": True, "verified_events": count}
