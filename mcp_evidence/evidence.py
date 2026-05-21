import csv
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


CSV_FIELDS = [
    "id",
    "schema_version",
    "created_at",
    "event_hash",
    "previous_hash",
    "session_id",
    "user_id",
    "method",
    "tool_name",
    "status_code",
    "policy_decision",
    "policy_reason",
    "risks",
    "latency_ms",
    "request_size_bytes",
    "response_size_bytes",
    "request_sha256",
    "response_sha256",
]


def events_to_csv(events: List[Dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for event in events:
        writer.writerow(
            {
                "id": event["id"],
                "schema_version": event.get("schema_version", 1),
                "created_at": event["created_at"],
                "event_hash": event["event_hash"],
                "previous_hash": event["previous_hash"],
                "session_id": event["session_id"],
                "user_id": event["user_id"],
                "method": event["method"],
                "tool_name": event["tool_name"],
                "status_code": event["status_code"],
                "policy_decision": event["policy_decision"],
                "policy_reason": event["policy_reason"],
                "risks": ",".join(event["risks"]),
                "latency_ms": event["latency_ms"],
                "request_size_bytes": event["request_size_bytes"],
                "response_size_bytes": event["response_size_bytes"],
                "request_sha256": event.get("request_sha256"),
                "response_sha256": event.get("response_sha256"),
            }
        )
    return buffer.getvalue()


def build_evidence_bundle(
    *,
    events: List[Dict[str, Any]],
    chain: Dict[str, Any],
    policy_path: Path,
    session_id: Optional[str],
    service_name: str,
) -> bytes:
    manifest = {
        "service": service_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "event_count": len(events),
        "chain": chain,
        "files": [
            "manifest.json",
            "events.json",
            "events.csv",
            "policy.json",
        ],
    }
    policy_text = "{}"
    if policy_path.exists():
        policy_text = policy_path.read_text(encoding="utf-8")

    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        archive.writestr("events.json", json.dumps(events, indent=2, ensure_ascii=False))
        archive.writestr("events.csv", events_to_csv(events))
        archive.writestr("policy.json", policy_text)
    return output.getvalue()

