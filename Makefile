.PHONY: install test run mock-http bridge clean-demo

install:
	python3 -m pip install -r requirements.txt

test:
	python3 -m pytest

run:
	TARGET_MCP_URL=$${TARGET_MCP_URL:-http://127.0.0.1:9000/mcp} uvicorn mcp_evidence.main:app --host 127.0.0.1 --port 8080

mock-http:
	uvicorn examples.mock_mcp_server:app --host 127.0.0.1 --port 9000

bridge:
	STDIO_MCP_COMMAND='["python3", "examples/mock_stdio_mcp_server.py"]' uvicorn mcp_evidence.stdio_bridge:app --host 127.0.0.1 --port 9100

clean-demo:
	python3 -c "from pathlib import Path; [p.unlink() for p in Path('data').glob('audit.sqlite3*') if p.is_file()]"
