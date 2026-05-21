from fastapi import FastAPI


app = FastAPI(title="Mock MCP Server")


@app.post("/mcp")
async def mcp(body: dict):
    method = body.get("method")
    request_id = body.get("id")
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file by path",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                            "required": ["path"],
                        },
                    },
                    {
                        "name": "shell",
                        "description": "Run a shell command",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"cmd": {"type": "string"}},
                            "required": ["cmd"],
                        },
                    },
                ]
            },
        }
    if method == "tools/call":
        params = body.get("params", {})
        name = params.get("name")
        if name == "read_file":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"content": [{"type": "text", "text": "mock file content"}]},
            }
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": "mock shell output"}]},
        }
    return {"jsonrpc": "2.0", "id": request_id, "result": {}}

