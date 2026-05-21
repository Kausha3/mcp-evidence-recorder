import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient


def make_upstream_app() -> FastAPI:
    app = FastAPI()

    @app.post("/mcp")
    async def mcp(body: dict):
        return {"jsonrpc": "2.0", "id": body.get("id"), "result": {"content": ["ok"]}}

    return app


def test_proxy_denies_and_records_policy(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "audit.sqlite3"))
    monkeypatch.setenv("TARGET_MCP_URL", "http://testserver/mcp")

    from mcp_evidence import main

    main.get_settings.cache_clear()
    main.get_store.cache_clear()
    main.get_policy_engine.cache_clear()
    main.settings.database_path = tmp_path / "audit.sqlite3"
    main.settings.target_mcp_url = "http://testserver/mcp"

    client = TestClient(main.app)
    response = client.post(
        "/mcp",
        headers={"x-session-id": "s1", "x-user-id": "u1"},
        json={
            "jsonrpc": "2.0",
            "id": "1",
            "method": "tools/call",
            "params": {"name": "shell", "arguments": {"cmd": "printenv"}},
        },
    )

    assert response.status_code == 403
    events = client.get("/api/events").json()["events"]
    assert len(events) == 1
    assert events[0]["policy_decision"] == "deny"
    assert client.get("/api/verify").json()["ok"] is True


def test_proxy_allows_and_records_response(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "audit.sqlite3"))
    monkeypatch.setenv("TARGET_MCP_URL", "http://upstream.test/mcp")

    from mcp_evidence import main

    main.get_settings.cache_clear()
    main.get_store.cache_clear()
    main.get_policy_engine.cache_clear()
    main.settings.database_path = tmp_path / "audit.sqlite3"
    main.settings.target_mcp_url = "http://upstream.test/mcp"

    def handler(request):
        body = json.loads(request.content.decode("utf-8"))
        return main.httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": body["id"], "result": {"content": ["ok"]}},
        )

    original_async_client = main.httpx.AsyncClient
    transport = main.httpx.MockTransport(handler)

    class MockAsyncClient:
        def __init__(self, *args, **kwargs):
            self.client = original_async_client(transport=transport)

        async def __aenter__(self):
            return self.client

        async def __aexit__(self, exc_type, exc, tb):
            await self.client.aclose()

    monkeypatch.setattr(main.httpx, "AsyncClient", MockAsyncClient)

    client = TestClient(main.app)
    response = client.post(
        "/mcp",
        headers={"x-session-id": "s2", "x-user-id": "u2"},
        json={
            "jsonrpc": "2.0",
            "id": "2",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "README.md"}},
        },
    )

    assert response.status_code == 200
    events = client.get("/api/events").json()["events"]
    assert len(events) == 1
    assert events[0]["tool_name"] == "read_file"
    assert events[0]["response_body"]["result"]["content"] == ["ok"]
