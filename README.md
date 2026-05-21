# MCP Evidence Recorder

A production-minded MVP for recording, searching, and exporting evidence from MCP traffic.

It runs as an HTTP sidecar in front of a streamable HTTP MCP server. Every proxied call is redacted, risk-scanned, written to SQLite, and chained with SHA-256 hashes so tampering can be detected later.

## Features

- HTTP MCP proxy at `/mcp`
- Persistent SQLite audit events
- Tamper-evident hash chain with `/api/verify`
- Versioned audit events with raw request/response SHA-256 digests
- Secret, PII, and prompt-injection marker detection
- JSON policy rules for allow/deny decisions
- Searchable dashboard at `/`
- JSON and CSV evidence export
- ZIP evidence bundle export with manifest, events, CSV, and policy snapshot
- Aggregate stats and Prometheus-compatible metrics
- Basic security headers for the dashboard/API
- Optional Slack webhook alerts
- Docker and docker-compose packaging
- Optional bearer-token auth for admin APIs and MCP proxy traffic
- Stdio MCP bridge for local stdio servers

## Run locally

```bash
python3 -m pip install -r requirements.txt
TARGET_MCP_URL=http://127.0.0.1:9000/mcp uvicorn mcp_evidence.main:app --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080`.

Makefile shortcuts:

```bash
make install
make mock-http
make run
```

Point MCP clients at:

```text
http://127.0.0.1:8080/mcp
```

For a quick demo upstream:

```bash
uvicorn examples.mock_mcp_server:app --host 127.0.0.1 --port 9000
```

## Run with Docker

```bash
docker compose up --build
```

By default, compose forwards to `http://host.docker.internal:9000/mcp`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `TARGET_MCP_URL` | `http://127.0.0.1:9000/mcp` | Upstream MCP HTTP endpoint |
| `DATABASE_PATH` | `data/audit.sqlite3` | SQLite audit database |
| `POLICY_PATH` | `config/policies.json` | JSON policy file |
| `MAX_BODY_BYTES` | `2000000` | Max request body accepted by proxy |
| `REQUEST_TIMEOUT_SECONDS` | `30` | Upstream timeout |
| `SLACK_WEBHOOK_URL` | empty | Optional risk alert destination |
| `ADMIN_TOKEN` | empty | Protects `/api/*` when set |
| `PROXY_TOKEN` | empty | Protects `/mcp` when set |

When `ADMIN_TOKEN` is set, enter it in the dashboard token field or call APIs with:

```bash
curl -H "authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:8080/api/events
```

When `PROXY_TOKEN` is set, MCP clients must send either:

```text
Authorization: Bearer <token>
```

or:

```text
X-API-Key: <token>
```

## Policy Format

```json
{
  "default_action": "allow",
  "rules": [
    {
      "id": "deny-shell-secrets",
      "action": "deny",
      "method": "tools/call",
      "tool_name": "shell",
      "param_regex": "(cat\\s+.*\\.env|printenv)",
      "reason": "Shell command appears to access secrets"
    }
  ]
}
```

Rules are evaluated in order. `param_regex` is matched against the full JSON-RPC request body.

## API

- `GET /health`
- `POST /mcp`
- `GET /api/events`
- `GET /api/events/{id}`
- `GET /api/sessions`
- `GET /api/verify`
- `GET /api/stats`
- `GET /metrics`
- `GET /api/evidence/export?format=json`
- `GET /api/evidence/export?format=csv`
- `GET /api/evidence/export?format=bundle`
- `POST /api/policies/reload`

New audit events are written with `schema_version: 2`. Their hash-chain payload includes the redacted request/response bodies, event metadata, and raw payload SHA-256 digests. Existing v1 rows remain verifiable after migration.

## Stdio MCP Bridge

The recorder proxies HTTP. To put a local stdio MCP server behind it, run the bridge and point the recorder at the bridge.

Terminal 1:

```bash
STDIO_MCP_COMMAND='["python3", "examples/mock_stdio_mcp_server.py"]' \
  uvicorn mcp_evidence.stdio_bridge:app --host 127.0.0.1 --port 9100
```

Terminal 2:

```bash
TARGET_MCP_URL=http://127.0.0.1:9100/mcp \
  uvicorn mcp_evidence.main:app --host 127.0.0.1 --port 8080
```

The bridge launches the command without a shell, forwards one JSON-RPC request at a time over stdin/stdout, and returns the response with the matching `id`.

Docker demo:

```bash
docker compose --profile stdio-demo up --build stdio-bridge
```

## Example Request

```bash
curl -s http://127.0.0.1:8080/mcp \
  -H 'content-type: application/json' \
  -H 'x-user-id: kausha' \
  -H 'x-session-id: demo-1' \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"shell","arguments":{"cmd":"printenv"}}}'
```

This request is denied by the sample policy and still written to the audit chain.

## Tests

```bash
python3 -m pytest
```

The repo also includes `.env.example` and a GitHub Actions workflow for pytest.

The stdio bridge test suite includes a real compatibility check against the official TypeScript MCP SDK:

```bash
npm install
python3 -m pytest tests/test_stdio_bridge.py
```
