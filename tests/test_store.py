from pathlib import Path
import sqlite3

from mcp_evidence.hashchain import GENESIS_HASH, event_hash
from mcp_evidence.models import AuditEventIn
from mcp_evidence.store import AuditStore


def test_store_hash_chain_verifies(tmp_path: Path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.insert_event(
        AuditEventIn(
            direction="proxy",
            method="tools/list",
            status_code=200,
            latency_ms=12,
            policy_decision="allow",
            request_body={"id": 1},
            response_body={"ok": True},
        )
    )
    store.insert_event(
        AuditEventIn(
            direction="proxy",
            method="tools/call",
            tool_name="read_file",
            status_code=200,
            latency_ms=25,
            policy_decision="allow",
            request_body={"id": 2},
            response_body={"content": []},
        )
    )

    verification = store.verify_chain()

    assert verification.ok is True
    assert verification.checked_events == 2
    assert store.stats()["total_events"] == 2
    assert store.stats()["sessions"] == 1


def test_new_events_include_raw_digests_in_hash_payload(tmp_path: Path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    event = store.insert_event(
        AuditEventIn(
            direction="proxy",
            method="tools/call",
            tool_name="read_file",
            status_code=200,
            latency_ms=10,
            policy_decision="allow",
            request_body={"id": "1"},
            response_body={"ok": True},
            request_sha256="request-digest",
            response_sha256="response-digest",
        )
    )

    assert event["schema_version"] == 2
    assert event["request_sha256"] == "request-digest"
    assert event["response_sha256"] == "response-digest"
    assert store.verify_chain().ok is True


def test_legacy_v1_chain_survives_migration(tmp_path: Path):
    db_path = tmp_path / "audit.sqlite3"
    conn = sqlite3.connect(db_path)
    payload = {
        "created_at": "2026-05-21T00:00:00+00:00",
        "direction": "proxy",
        "method": "tools/list",
        "tool_name": None,
        "user_id": None,
        "session_id": "legacy",
        "client_name": None,
        "upstream_url": "http://upstream/mcp",
        "status_code": 200,
        "latency_ms": 5,
        "policy_decision": "allow",
        "policy_reason": "default allow",
        "request_body": {"id": "legacy"},
        "response_body": {"ok": True},
        "risks": [],
        "request_size_bytes": 10,
        "response_size_bytes": 11,
    }
    digest = event_hash(GENESIS_HASH, payload)
    conn.execute(
        """
        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            response_size_bytes INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        INSERT INTO audit_events (
            created_at, previous_hash, event_hash, direction, method, tool_name,
            user_id, session_id, client_name, upstream_url, status_code, latency_ms,
            policy_decision, policy_reason, request_body, response_body, risks,
            request_size_bytes, response_size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["created_at"],
            GENESIS_HASH,
            digest,
            payload["direction"],
            payload["method"],
            payload["tool_name"],
            payload["user_id"],
            payload["session_id"],
            payload["client_name"],
            payload["upstream_url"],
            payload["status_code"],
            payload["latency_ms"],
            payload["policy_decision"],
            payload["policy_reason"],
            '{"id":"legacy"}',
            '{"ok":true}',
            "[]",
            payload["request_size_bytes"],
            payload["response_size_bytes"],
        ),
    )
    conn.commit()
    conn.close()

    store = AuditStore(db_path)

    assert store.verify_chain().ok is True
    assert store.get_event(1)["schema_version"] == 1
