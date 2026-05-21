import hmac
from typing import Optional

from fastapi import HTTPException, Request, status


def extract_token(request: Request) -> Optional[str]:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    api_key = request.headers.get("x-api-key")
    if api_key:
        return api_key.strip()
    return None


def require_configured_token(request: Request, expected_token: Optional[str]) -> None:
    if not expected_token:
        return
    supplied = extract_token(request)
    if supplied and hmac.compare_digest(supplied, expected_token):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="valid bearer token or x-api-key required",
        headers={"WWW-Authenticate": "Bearer"},
    )

