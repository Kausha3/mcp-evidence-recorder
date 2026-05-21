from pathlib import Path

from fastapi.testclient import TestClient


def test_admin_token_protects_api(monkeypatch, tmp_path: Path):
    from mcp_evidence import main

    main.get_store.cache_clear()
    main.settings.database_path = tmp_path / "audit.sqlite3"
    main.settings.admin_token = "secret-admin"

    client = TestClient(main.app)

    assert client.get("/api/events").status_code == 401
    assert client.get("/metrics").status_code == 401
    assert client.get("/api/events", headers={"authorization": "Bearer secret-admin"}).status_code == 200
    assert client.get("/metrics", headers={"authorization": "Bearer secret-admin"}).status_code == 200

    main.settings.admin_token = None


def test_proxy_token_protects_mcp(monkeypatch, tmp_path: Path):
    from mcp_evidence import main

    main.get_store.cache_clear()
    main.settings.database_path = tmp_path / "audit.sqlite3"
    main.settings.proxy_token = "proxy-secret"

    client = TestClient(main.app)

    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": "1", "method": "tools/list"})
    assert response.status_code == 401

    main.settings.proxy_token = None
