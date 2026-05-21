import json
import zipfile
from io import BytesIO
from pathlib import Path

from mcp_evidence.evidence import build_evidence_bundle, events_to_csv


def test_events_to_csv_includes_digests():
    csv_text = events_to_csv(
        [
            {
                "id": 1,
                "schema_version": 2,
                "created_at": "2026-05-21T00:00:00+00:00",
                "event_hash": "event",
                "previous_hash": "previous",
                "session_id": "s1",
                "user_id": "u1",
                "method": "tools/call",
                "tool_name": "read_file",
                "status_code": 200,
                "policy_decision": "allow",
                "policy_reason": "default allow",
                "risks": [],
                "latency_ms": 12,
                "request_size_bytes": 10,
                "response_size_bytes": 20,
                "request_sha256": "request",
                "response_sha256": "response",
            }
        ]
    )

    assert "request_sha256" in csv_text
    assert "response" in csv_text


def test_build_evidence_bundle_contains_manifest_events_and_policy(tmp_path: Path):
    policy = tmp_path / "policy.json"
    policy.write_text('{"default_action":"allow"}', encoding="utf-8")

    bundle = build_evidence_bundle(
        events=[],
        chain={"ok": True, "checked_events": 0},
        policy_path=policy,
        session_id=None,
        service_name="Test Service",
    )

    with zipfile.ZipFile(BytesIO(bundle)) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("manifest.json"))

    assert {"manifest.json", "events.json", "events.csv", "policy.json"} <= names
    assert manifest["service"] == "Test Service"
    assert manifest["chain"]["ok"] is True
