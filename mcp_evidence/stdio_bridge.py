import asyncio
import json
import os
import shlex
import sys
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse


class StdioBridgeConfig:
    def __init__(self) -> None:
        self.command = parse_command(os.getenv("STDIO_MCP_COMMAND", ""))
        self.request_timeout_seconds = float(os.getenv("STDIO_REQUEST_TIMEOUT_SECONDS", "30"))
        self.max_body_bytes = int(os.getenv("MAX_BODY_BYTES", "2000000"))


def parse_command(value: str) -> List[str]:
    raw = value.strip()
    if not raw:
        return []
    if raw.startswith("["):
        parsed = json.loads(raw)
        if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
            raise ValueError("STDIO_MCP_COMMAND JSON value must be an array of strings")
        return parsed
    return shlex.split(raw)


class StdioMcpClient:
    def __init__(self, command: List[str], timeout_seconds: float = 30.0) -> None:
        if not command:
            raise ValueError("stdio MCP command is required")
        self.command = command
        self.timeout_seconds = timeout_seconds
        self.process: Optional[asyncio.subprocess.Process] = None
        self._lock = asyncio.Lock()
        self._stderr_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        if self.process and self.process.returncode is None:
            return
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._stderr_task = asyncio.create_task(self._drain_stderr())

    async def close(self) -> None:
        if self._stderr_task:
            self._stderr_task.cancel()
        if not self.process:
            return
        if self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()

    async def request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        await self.start()
        if not self.process or not self.process.stdin or not self.process.stdout:
            raise RuntimeError("stdio MCP process is not available")
        expected_id = payload.get("id")
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        async with self._lock:
            if self.process.returncode is not None:
                raise RuntimeError(f"stdio MCP process exited with {self.process.returncode}")
            self.process.stdin.write(encoded + b"\n")
            await self.process.stdin.drain()

            if expected_id is None:
                return {"jsonrpc": "2.0", "result": {"accepted": True}}

            deadline = asyncio.get_running_loop().time() + self.timeout_seconds
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError("timed out waiting for stdio MCP response")
                line = await asyncio.wait_for(self.process.stdout.readline(), timeout=remaining)
                if not line:
                    raise RuntimeError("stdio MCP process closed stdout")
                try:
                    response = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    continue
                if response.get("id") == expected_id:
                    return response

    async def _drain_stderr(self) -> None:
        if not self.process or not self.process.stderr:
            return
        while True:
            line = await self.process.stderr.readline()
            if not line:
                return
            sys.stderr.write(f"[stdio-mcp] {line.decode('utf-8', errors='replace')}")
            sys.stderr.flush()


config = StdioBridgeConfig()
stdio_client: Optional[StdioMcpClient] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global stdio_client
    if config.command:
        stdio_client = StdioMcpClient(config.command, config.request_timeout_seconds)
        await stdio_client.start()
    yield
    if stdio_client:
        await stdio_client.close()


app = FastAPI(title="MCP stdio HTTP Bridge", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health() -> Dict[str, Any]:
    running = bool(stdio_client and stdio_client.process and stdio_client.process.returncode is None)
    return {
        "ok": bool(config.command) and running,
        "command": config.command,
        "running": running,
    }


@app.post("/mcp")
async def mcp(request: Request) -> Response:
    if not config.command:
        raise HTTPException(status_code=500, detail="STDIO_MCP_COMMAND is not configured")
    raw_body = await request.body()
    if len(raw_body) > config.max_body_bytes:
        raise HTTPException(status_code=413, detail="request body exceeds MAX_BODY_BYTES")
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="request body must be JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="request body must be a JSON object")

    global stdio_client
    if stdio_client is None:
        stdio_client = StdioMcpClient(config.command, config.request_timeout_seconds)
    try:
        response = await stdio_client.request(body)
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return JSONResponse(content=response)

