from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class AuditEventIn(BaseModel):
    schema_version: int = 2
    direction: str
    method: Optional[str] = None
    tool_name: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    client_name: Optional[str] = None
    upstream_url: Optional[str] = None
    status_code: int
    latency_ms: int
    policy_decision: str
    policy_reason: Optional[str] = None
    request_body: Any = None
    response_body: Any = None
    risks: List[str] = []
    request_size_bytes: int = 0
    response_size_bytes: int = 0
    request_sha256: Optional[str] = None
    response_sha256: Optional[str] = None


class AuditEvent(BaseModel):
    id: int
    schema_version: int
    created_at: str
    previous_hash: str
    event_hash: str
    direction: str
    method: Optional[str]
    tool_name: Optional[str]
    user_id: Optional[str]
    session_id: Optional[str]
    client_name: Optional[str]
    upstream_url: Optional[str]
    status_code: int
    latency_ms: int
    policy_decision: str
    policy_reason: Optional[str]
    request_body: Any
    response_body: Any
    risks: List[str]
    request_size_bytes: int
    response_size_bytes: int
    request_sha256: Optional[str]
    response_sha256: Optional[str]


class ChainVerification(BaseModel):
    ok: bool
    checked_events: int
    first_bad_event_id: Optional[int] = None
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None


class SessionSummary(BaseModel):
    session_id: str
    user_id: Optional[str]
    events: int
    first_seen: str
    last_seen: str
    risks: List[str]


class PolicyDecision(BaseModel):
    allowed: bool
    reason: str
    rule_id: Optional[str] = None
