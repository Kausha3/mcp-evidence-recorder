import hashlib
import json
from typing import Any, Dict, Optional


GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def event_hash(previous_hash: Optional[str], payload: Dict[str, Any]) -> str:
    previous = previous_hash or GENESIS_HASH
    digest = hashlib.sha256()
    digest.update(previous.encode("utf-8"))
    digest.update(canonical_json(payload).encode("utf-8"))
    return digest.hexdigest()

