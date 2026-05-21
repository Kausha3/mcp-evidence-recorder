import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .hashchain import GENESIS_HASH, event_hash
from .models import AuditEventIn, ChainVerification


class AuditStore:
    def __init__(self, database_path: Path):
        self.database_path = database_path
        self._write_lock = threading.Lock()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.init()

    @contextmanager
    def connect(self) -> Iterable[sqlite3.Connection]:
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init(self) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    schema_version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    method TEXT,
                    tool_name TEXT,
                    user_id TEXT,
                    session_id TEXT,
                    client_name TEXT,
                    upstream_url TEXT,
                    status_code INTEGER NOT NULL,
                    latency_ms INTEGER NOT NULL,
                    policy_decision TEXT NOT NULL,
                    policy_reason TEXT,
                    request_body TEXT,
                    response_body TEXT,
                    risks TEXT NOT NULL,
                    request_size_bytes INTEGER NOT NULL,
                    response_size_bytes INTEGER NOT NULL,
                    request_sha256 TEXT,
                    response_sha256 TEXT
                )
                """
            )
            self._add_column_if_missing(conn, "audit_events", "schema_version", "INTEGER NOT NULL DEFAULT 1")
            self._add_column_if_missing(conn, "audit_events", "request_sha256", "TEXT")
            self._add_column_if_missing(conn, "audit_events", "response_sha256", "TEXT")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(session_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_events(tool_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_method ON audit_events(method)")

    def insert_event(self, event: AuditEventIn) -> Dict[str, Any]:
        with self._write_lock:
            with self.connect() as conn:
                previous_hash = self._latest_hash(conn)
                created_at = datetime.now(timezone.utc).isoformat()
                payload = self._hash_payload(created_at, event)
                digest = event_hash(previous_hash, payload)
                cursor = conn.execute(
                    """
                    INSERT INTO audit_events (
                        schema_version, created_at, previous_hash, event_hash, direction, method, tool_name,
                        user_id, session_id, client_name, upstream_url, status_code,
                        latency_ms, policy_decision, policy_reason, request_body,
                        response_body, risks, request_size_bytes, response_size_bytes,
                        request_sha256, response_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.schema_version,
                        created_at,
                        previous_hash,
                        digest,
                        event.direction,
                        event.method,
                        event.tool_name,
                        event.user_id,
                        event.session_id,
                        event.client_name,
                        event.upstream_url,
                        event.status_code,
                        event.latency_ms,
                        event.policy_decision,
                        event.policy_reason,
                        json.dumps(event.request_body, ensure_ascii=False),
                        json.dumps(event.response_body, ensure_ascii=False),
                        json.dumps(event.risks, ensure_ascii=False),
                        event.request_size_bytes,
                        event.response_size_bytes,
                        event.request_sha256,
                        event.response_sha256,
                    ),
                )
                row = conn.execute("SELECT * FROM audit_events WHERE id = ?", (cursor.lastrowid,)).fetchone()
                if row is None:
                    raise RuntimeError("inserted audit event could not be read")
                return self._decode_row(row)

    def get_event(self, event_id: int) -> Dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM audit_events WHERE id = ?", (event_id,)).fetchone()
            if row is None:
                raise KeyError(event_id)
            return self._decode_row(row)

    def list_events(
        self,
        limit: int = 100,
        session_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        risk: Optional[str] = None,
        q: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        values: List[Any] = []
        if session_id:
            clauses.append("session_id = ?")
            values.append(session_id)
        if tool_name:
            clauses.append("tool_name = ?")
            values.append(tool_name)
        if risk:
            clauses.append("risks LIKE ?")
            values.append(f"%{risk}%")
        if q:
            clauses.append(
                "(request_body LIKE ? OR response_body LIKE ? OR method LIKE ? OR tool_name LIKE ?)"
            )
            values.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM audit_events {where} ORDER BY id DESC LIMIT ?"
        values.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(sql, values).fetchall()
            return [self._decode_row(row) for row in rows]

    def sessions(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    COALESCE(session_id, 'unknown') AS session_id,
                    MAX(user_id) AS user_id,
                    COUNT(*) AS events,
                    MIN(created_at) AS first_seen,
                    MAX(created_at) AS last_seen,
                    '[' || GROUP_CONCAT(TRIM(risks, '[]')) || ']' AS risk_blob
                FROM audit_events
                GROUP BY COALESCE(session_id, 'unknown')
                ORDER BY MAX(id) DESC
                LIMIT ?
                """,
                (max(1, min(limit, 1000)),),
            ).fetchall()
        summaries: List[Dict[str, Any]] = []
        for row in rows:
            risks = set()
            for value in str(row["risk_blob"] or "").replace('"', "").split(","):
                cleaned = value.strip()
                if cleaned:
                    risks.add(cleaned)
            summaries.append(
                {
                    "session_id": row["session_id"],
                    "user_id": row["user_id"],
                    "events": row["events"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "risks": sorted(risks),
                }
            )
        return summaries

    def export_events(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.list_events(limit=1000, session_id=session_id)

    def stats(self) -> Dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_events,
                    SUM(CASE WHEN policy_decision = 'deny' THEN 1 ELSE 0 END) AS denied_events,
                    SUM(CASE WHEN risks != '[]' THEN 1 ELSE 0 END) AS risky_events,
                    COUNT(DISTINCT COALESCE(session_id, 'unknown')) AS sessions,
                    AVG(latency_ms) AS avg_latency_ms,
                    MAX(created_at) AS last_event_at
                FROM audit_events
                """
            ).fetchone()
            top_tools = conn.execute(
                """
                SELECT COALESCE(tool_name, method, 'unknown') AS name, COUNT(*) AS count
                FROM audit_events
                GROUP BY COALESCE(tool_name, method, 'unknown')
                ORDER BY COUNT(*) DESC
                LIMIT 10
                """
            ).fetchall()
        return {
            "total_events": row["total_events"] or 0,
            "denied_events": row["denied_events"] or 0,
            "risky_events": row["risky_events"] or 0,
            "sessions": row["sessions"] or 0,
            "avg_latency_ms": round(row["avg_latency_ms"] or 0, 2),
            "last_event_at": row["last_event_at"],
            "top_tools": [{"name": item["name"], "count": item["count"]} for item in top_tools],
        }

    def verify_chain(self) -> ChainVerification:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
        previous = GENESIS_HASH
        checked = 0
        for row in rows:
            decoded = self._decode_row(row)
            payload = self._hash_payload_from_row(decoded)
            expected = event_hash(previous, payload)
            if row["previous_hash"] != previous or row["event_hash"] != expected:
                return ChainVerification(
                    ok=False,
                    checked_events=checked,
                    first_bad_event_id=row["id"],
                    expected_hash=expected,
                    actual_hash=row["event_hash"],
                )
            previous = row["event_hash"]
            checked += 1
        return ChainVerification(ok=True, checked_events=checked)

    def _latest_hash(self, conn: sqlite3.Connection) -> str:
        row = conn.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        return row["event_hash"] if row else GENESIS_HASH

    def _hash_payload(self, created_at: str, event: AuditEventIn) -> Dict[str, Any]:
        payload = {
            "schema_version": event.schema_version,
            "created_at": created_at,
            "direction": event.direction,
            "method": event.method,
            "tool_name": event.tool_name,
            "user_id": event.user_id,
            "session_id": event.session_id,
            "client_name": event.client_name,
            "upstream_url": event.upstream_url,
            "status_code": event.status_code,
            "latency_ms": event.latency_ms,
            "policy_decision": event.policy_decision,
            "policy_reason": event.policy_reason,
            "request_body": event.request_body,
            "response_body": event.response_body,
            "risks": event.risks,
            "request_size_bytes": event.request_size_bytes,
            "response_size_bytes": event.response_size_bytes,
        }
        if event.schema_version >= 2:
            payload["request_sha256"] = event.request_sha256
            payload["response_sha256"] = event.response_sha256
        return payload

    def _hash_payload_from_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        schema_version = row.get("schema_version", 1) or 1
        keys = [
            "created_at",
            "direction",
            "method",
            "tool_name",
            "user_id",
            "session_id",
            "client_name",
            "upstream_url",
            "status_code",
            "latency_ms",
            "policy_decision",
            "policy_reason",
            "request_body",
            "response_body",
            "risks",
            "request_size_bytes",
            "response_size_bytes",
        ]
        if schema_version >= 2:
            keys = ["schema_version"] + keys + ["request_sha256", "response_sha256"]
        return {
            key: row[key]
            for key in keys
        }

    def _decode_row(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["schema_version"] = data.get("schema_version", 1) or 1
        data["request_sha256"] = data.get("request_sha256")
        data["response_sha256"] = data.get("response_sha256")
        data["request_body"] = json.loads(data["request_body"]) if data["request_body"] else None
        data["response_body"] = json.loads(data["response_body"]) if data["response_body"] else None
        data["risks"] = json.loads(data["risks"]) if data["risks"] else []
        return data

    def _add_column_if_missing(
        self,
        conn: sqlite3.Connection,
        table: str,
        column: str,
        definition: str,
    ) -> None:
        columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
