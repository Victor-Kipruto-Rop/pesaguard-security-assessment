"""SQLite-backed per-target minute quota for active assessment requests."""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

class RateLimitExceeded(RuntimeError):
    pass

class TargetRateLimiter:
    def __init__(self, database_path: str | Path):
        self.path = str(database_path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS target_rate_limits (
                target_id TEXT PRIMARY KEY,
                minute_bucket INTEGER NOT NULL,
                request_count INTEGER NOT NULL
            )""")

    def reserve(self, target_id: str, requests: int, limit: int, now: float | None = None) -> None:
        if not target_id or requests < 1 or limit < 1 or requests > limit:
            raise RateLimitExceeded("Assessment request exceeds the configured target quota.")
        bucket = int((time.time() if now is None else now) // 60)
        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT minute_bucket, request_count FROM target_rate_limits WHERE target_id = ?",
                (target_id,),
            ).fetchone()
            current = row[1] if row and row[0] == bucket else 0
            if current + requests > limit:
                db.rollback()
                raise RateLimitExceeded("Target request rate limit exceeded for the current minute.")
            db.execute(
                """INSERT INTO target_rate_limits(target_id, minute_bucket, request_count)
                   VALUES(?,?,?) ON CONFLICT(target_id) DO UPDATE SET
                   minute_bucket=excluded.minute_bucket, request_count=excluded.request_count""",
                (target_id, bucket, current + requests),
            )
            db.commit()
