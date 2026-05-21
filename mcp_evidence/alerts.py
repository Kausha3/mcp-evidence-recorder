from typing import List, Optional

import httpx


async def send_slack_alert(webhook_url: Optional[str], risks: List[str], summary: str) -> None:
    if not webhook_url or not risks:
        return
    payload = {
        "text": f"MCP Evidence Recorder alert: {', '.join(risks)}\n{summary}",
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(webhook_url, json=payload)

