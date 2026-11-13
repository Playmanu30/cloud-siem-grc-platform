"""
Persistence layer
SQLite-backed storage for security events, alerts and compliance reports.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .config import PROJECT_ROOT, get_settings
from .logging import get_logger

logger = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    message TEXT NOT NULL,
    event_id INTEGER REFERENCES events(id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL,
    framework TEXT NOT NULL,
    assessment_date TEXT NOT NULL,
    compliance_score REAL NOT NULL,
    total_controls INTEGER NOT NULL,
    report TEXT NOT NULL
);
"""


class Store:
    """Thin SQLite store; one connection per operation so it is safe across threads"""

    def __init__(self, database_url: str):
        if not database_url.startswith("sqlite:///"):
            raise ValueError(
                f"Unsupported database_url '{database_url}'. Only sqlite:/// URLs are supported."
            )

        self.path = Path(database_url[len("sqlite:///"):])
        if not self.path.is_absolute():
            self.path = PROJECT_ROOT / self.path
        self.path.parent.mkdir(parents=True, exist_ok=True)

        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ── Events ──────────────────────────────────────────────────

    def add_events(self, events: List[Dict[str, Any]]) -> int:
        if not events:
            return 0
        rows = [
            (
                e.get("event_type", "unknown"),
                e.get("severity", "info"),
                e.get("source", "unknown"),
                e.get("message", ""),
                e.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                json.dumps(e.get("details") or {}),
            )
            for e in events
        ]
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO events (event_type, severity, source, message, timestamp, details) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def query_events(
        self,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> Tuple[int, List[Dict[str, Any]]]:
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if source:
            clauses.append("source = ?")
            params.append(source)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        if until:
            clauses.append("timestamp <= ?")
            params.append(until)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()

        return total, [self._event_row(r) for r in rows]

    def severity_counts(self) -> Dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute("SELECT severity, COUNT(*) FROM events GROUP BY severity").fetchall()
        return {row[0]: row[1] for row in rows}

    def cloudtrail_events(self, limit: int = 5000) -> List[Dict[str, Any]]:
        """Rebuild raw-style CloudTrail events from storage for ATT&CK analysis"""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT details FROM events WHERE event_type LIKE 'aws.cloudtrail.%' "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()

        events = []
        for row in rows:
            details = json.loads(row["details"])
            events.append(
                {
                    "EventName": details.get("event_name"),
                    "EventTime": details.get("event_time"),
                    "SourceIPAddress": details.get("source_ip"),
                    "Username": details.get("user_name"),
                }
            )
        return events

    def count_events(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def source_counts(self) -> Dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute("SELECT source, COUNT(*) FROM events GROUP BY source").fetchall()
        return {row[0]: row[1] for row in rows}

    def top_source_ips(self, limit: int = 5) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT json_extract(details, '$.source_ip') AS ip, COUNT(*) AS hits "
                "FROM events WHERE json_extract(details, '$.source_ip') IS NOT NULL "
                "AND json_extract(details, '$.source_ip') != '' "
                "GROUP BY ip ORDER BY hits DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [{"ip": row["ip"], "events": row["hits"]} for row in rows]

    def tactic_counts(self) -> Dict[str, int]:
        """Count events per ATT&CK tactic, using the mitre block stored at collection time"""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT json_extract(details, '$.mitre.tactic_id') AS tactic, COUNT(*) "
                "FROM events WHERE json_extract(details, '$.mitre.tactic_id') IS NOT NULL "
                "GROUP BY tactic"
            ).fetchall()
        return {row[0]: row[1] for row in rows}

    # ── Alerts ──────────────────────────────────────────────────

    def add_alert(
        self,
        message: str,
        severity: str,
        rule: Optional[str] = None,
        event_id: Optional[int] = None,
    ) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO alerts (rule, severity, status, message, event_id, created_at) "
                "VALUES (?, ?, 'open', ?, ?, ?)",
                (rule, severity, message, event_id, datetime.now(timezone.utc).isoformat()),
            )
            return int(cursor.lastrowid)

    def add_alerts(self, alerts: List[Dict[str, Any]], dedupe_minutes: int = 0) -> int:
        """Bulk-insert alerts; optionally skip ones matching an open alert inside the window"""
        if not alerts:
            return 0

        now = datetime.now(timezone.utc)
        window_start = (now - timedelta(minutes=dedupe_minutes)).isoformat() if dedupe_minutes else None
        inserted = 0

        with self._connect() as conn:
            for alert in alerts:
                message = alert.get("message", "")
                if window_start:
                    duplicate = conn.execute(
                        "SELECT 1 FROM alerts WHERE rule = ? AND message = ? AND severity = ? "
                        "AND status = 'open' AND created_at >= ? LIMIT 1",
                        (
                            alert.get("rule"),
                            message,
                            alert.get("severity", "info"),
                            window_start,
                        ),
                    ).fetchone()
                    if duplicate:
                        continue
                conn.execute(
                    "INSERT INTO alerts (rule, severity, status, message, event_id, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        alert.get("rule"),
                        alert.get("severity", "info"),
                        alert.get("status", "open"),
                        message,
                        alert.get("event_id"),
                        alert.get("created_at") or now.isoformat(),
                    ),
                )
                inserted += 1

        return inserted

    def query_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> Tuple[int, List[Dict[str, Any]]]:
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT ?", [*params, limit]
            ).fetchall()

        return total, [dict(r) for r in rows]

    def update_alert_status(self, alert_id: int, status: str) -> Optional[Dict[str, Any]]:
        """Set an alert's status; returns the updated row or None when it does not exist"""
        with self._connect() as conn:
            cursor = conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
            if cursor.rowcount == 0:
                return None
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return dict(row) if row else None

    def alert_counts(self) -> Dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT severity, COUNT(*) FROM alerts WHERE status = 'open' GROUP BY severity"
            ).fetchall()
        return {row[0]: row[1] for row in rows}

    def alert_status_counts(self) -> Dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status").fetchall()
        return {row[0]: row[1] for row in rows}

    # ── Compliance reports ──────────────────────────────────────

    def add_report(self, report: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO reports (assessment_id, framework, assessment_date, "
                "compliance_score, total_controls, report) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    report.get("assessment_id", "unknown"),
                    report.get("framework", "unknown"),
                    report.get("assessment_date", datetime.now(timezone.utc).isoformat()),
                    float(report.get("compliance_score", 0.0)),
                    int(report.get("total_controls", 0)),
                    json.dumps(report),
                ),
            )

    def latest_report(self) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT report FROM reports ORDER BY id DESC LIMIT 1").fetchone()
        return json.loads(row["report"]) if row else None

    def query_reports(self, limit: int = 10) -> Tuple[int, List[Dict[str, Any]]]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
            rows = conn.execute(
                "SELECT assessment_id, framework, assessment_date, compliance_score, "
                "total_controls FROM reports ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return total, [dict(r) for r in rows]

    # ── Helpers ─────────────────────────────────────────────────

    @staticmethod
    def _event_row(row: sqlite3.Row) -> Dict[str, Any]:
        event = dict(row)
        event["details"] = json.loads(event["details"])
        return event


@lru_cache
def get_store() -> Store:
    """Return the process-wide store, creating the schema on first use"""
    store = Store(get_settings().database_url)
    logger.info("storage ready", path=str(store.path))
    return store
