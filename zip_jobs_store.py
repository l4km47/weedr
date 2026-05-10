"""SQLite-backed zip job state for multi-worker safety and restart recovery."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any


class ZipJobsStore:
    def __init__(self, db_path: Path) -> None:
        self._path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS zip_jobs (
                    job_id TEXT PRIMARY KEY,
                    rel_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress REAL DEFAULT 0,
                    processed_bytes INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    folder_name TEXT,
                    download_name TEXT,
                    error TEXT,
                    started TEXT,
                    finished TEXT,
                    cancel_requested INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_zip_jobs_rel ON zip_jobs(rel_path)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_zip_jobs_status ON zip_jobs(status)"
            )
            self._conn.commit()

    def insert_job(
        self,
        job_id: str,
        rel_path: str,
        folder_name: str,
        download_name: str,
        started: str,
        status: str = "queued",
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO zip_jobs (
                    job_id, rel_path, status, folder_name, download_name, started,
                    progress, processed_bytes, total_bytes, error, finished, cancel_requested
                ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, NULL, NULL, 0)
                """,
                (job_id, rel_path, status, folder_name, download_name, started),
            )
            self._conn.commit()

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM zip_jobs WHERE job_id = ?", (job_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            return dict(row)

    def update_totals(
        self, job_id: str, total_bytes: int, processed_bytes: int, progress: float
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE zip_jobs SET total_bytes = ?, processed_bytes = ?, progress = ?
                WHERE job_id = ?
                """,
                (total_bytes, processed_bytes, progress, job_id),
            )
            self._conn.commit()

    def update_progress(self, job_id: str, processed_bytes: int, progress: float) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE zip_jobs SET processed_bytes = ?, progress = ?
                WHERE job_id = ?
                """,
                (processed_bytes, progress, job_id),
            )
            self._conn.commit()

    def set_status(
        self,
        job_id: str,
        status: str,
        error: str | None = None,
        finished: str | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE zip_jobs SET status = ?, error = ?, finished = COALESCE(?, finished)
                WHERE job_id = ?
                """,
                (status, error, finished, job_id),
            )
            self._conn.commit()

    def set_running(self, job_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE zip_jobs SET status = 'running' WHERE job_id = ?",
                (job_id,),
            )
            self._conn.commit()

    def mark_done(self, job_id: str, total_bytes: int, processed_bytes: int, finished: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE zip_jobs SET status = 'done', progress = 100,
                    total_bytes = ?, processed_bytes = ?, finished = ?, error = NULL
                WHERE job_id = ?
                """,
                (total_bytes, processed_bytes, finished, job_id),
            )
            self._conn.commit()

    def mark_error(self, job_id: str, err: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE zip_jobs SET status = 'error', error = ?, progress = 0
                WHERE job_id = ?
                """,
                (err, job_id),
            )
            self._conn.commit()

    def mark_cancelled(self, job_id: str, msg: str = "Cancelled") -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE zip_jobs SET status = 'cancelled', error = ?, progress = 0
                WHERE job_id = ?
                """,
                (msg, job_id),
            )
            self._conn.commit()

    def request_cancel(self, job_id: str) -> bool:
        """Return True if row existed."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE zip_jobs SET cancel_requested = 1 WHERE job_id = ?",
                (job_id,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def cancel_requested(self, job_id: str) -> bool:
        row = self.get_job(job_id)
        return bool(row and row.get("cancel_requested"))

    def delete_job_row(self, job_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM zip_jobs WHERE job_id = ?", (job_id,))
            self._conn.commit()

    def active_job_for_path(self, rel_path: str) -> dict[str, Any] | None:
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT * FROM zip_jobs WHERE rel_path = ?
                AND status IN ('queued', 'running')
                ORDER BY started DESC LIMIT 1
                """,
                (rel_path,),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def latest_done_for_path(self, rel_path: str) -> dict[str, Any] | None:
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT * FROM zip_jobs WHERE rel_path = ? AND status = 'done'
                ORDER BY (finished IS NULL), finished DESC, started DESC LIMIT 1
                """,
                (rel_path,),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def list_all_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM zip_jobs ORDER BY started DESC"
            )
            return [dict(r) for r in cur.fetchall()]
