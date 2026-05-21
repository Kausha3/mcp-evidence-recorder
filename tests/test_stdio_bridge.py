import sys

import pytest

from mcp_evidence.stdio_bridge import StdioMcpClient, parse_command


def test_parse_command_accepts_json_array():
    assert parse_command('["python3","server.py"]') == ["python3", "server.py"]


@pytest.mark.asyncio
async def test_stdio_client_round_trip():
    client = StdioMcpClient(
        [sys.executable, "examples/mock_stdio_mcp_server.py"],
        timeout_seconds=5,
    )
    try:
        response = await client.request(
            {
                "jsonrpc": "2.0",
                "id": "round-trip",
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "README.md"}},
            }
        )
    finally:
        await client.close()

    assert response["id"] == "round-trip"
    assert response["result"]["content"][0]["text"] == "stdio response from read_file"


@pytest.mark.asyncio
async def test_stdio_client_round_trip_against_official_typescript_sdk_server():
    client = StdioMcpClient(
        ["node", "examples/sdk_stdio_server.mjs"],
        timeout_seconds=10,
    )
    try:
        initialize = await client.request(
            {
                "jsonrpc": "2.0",
                "id": "init",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-evidence-test", "version": "0.1.0"},
                },
            }
        )
        await client.request(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            }
        )
        tools = await client.request(
            {
                "jsonrpc": "2.0",
                "id": "tools",
                "method": "tools/list",
                "params": {},
            }
        )
        call = await client.request(
            {
                "jsonrpc": "2.0",
                "id": "call",
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": {"message": "hello"},
                },
            }
        )
    finally:
        await client.close()

    assert initialize["result"]["serverInfo"]["name"] == "mcp-evidence-sdk-compat-server"
    assert any(tool["name"] == "echo" for tool in tools["result"]["tools"])
    assert call["result"]["content"][0]["text"] == "sdk:hello"
