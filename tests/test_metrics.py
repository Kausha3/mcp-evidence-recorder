from pathlib import Path

from fastapi.testclient import TestClient

from mcp_evidence.models import AuditEventIn


def test_stats_and_metrics_report_audit_counts(tmp_path: Path):
    from mcp_evidence import main

    main.get_store.cache_clear()
    main.settings.database_path = tmp_path / "audit.sqlite3"
    main.settings.admin_token = None
    store = main.get_store()
    store.insert_event(
        AuditEventIn(
            direction="proxy",
            method="tools/call",
            tool_name="shell",
            status_code=403,
            latency_ms=7,
            policy_decision="deny",
            request_body={"id": "1"},
            response_body={"error": "denied"},
            risks=["secret_leak"],
        )
    )

    client = TestClient(main.app)
    stats = client.get("/api/stats").json()
    metrics = client.get("/metrics").text

    assert stats["stats"]["total_events"] == 1
    assert stats["stats"]["denied_events"] == 1
    assert stats["stats"]["risky_events"] == 1
    assert "mcp_evidence_events_total 1" in metrics
    assert "mcp_evidence_chain_verified 1" in metrics
