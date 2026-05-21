import json
import sys


def handle(message):
    method = message.get("method")
    request_id = message.get("id")
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file by path",
                        "inputSchema": {"type": "object"},
                    }
                ]
            },
        }
    if method == "tools/call":
        params = message.get("params", {})
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"stdio response from {params.get('name', 'unknown')}",
                    }
                ]
            },
        }
    return {"jsonrpc": "2.0", "id": request_id, "result": {}}


for line in sys.stdin:
    try:
        payload = json.loads(line)
        if payload.get("id") is None:
            continue
        print(json.dumps(handle(payload), separators=(",", ":")), flush=True)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": str(exc)},
                }
            ),
            flush=True,
        )

