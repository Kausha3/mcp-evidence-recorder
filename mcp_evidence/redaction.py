import re
from typing import Any, Dict, List


SECRET_KEY_PATTERN = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|authorization|bearer|private[_-]?key)"
)
SECRET_VALUE_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"),
]
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PHONE_PATTERN = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: Dict[str, Any] = {}
        for key, child in value.items():
            if SECRET_KEY_PATTERN.search(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact(child)
        return redacted
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_text(text: str) -> str:
    out = text
    for pattern in SECRET_VALUE_PATTERNS:
        out = pattern.sub("[REDACTED_SECRET]", out)
    out = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", out)
    out = SSN_PATTERN.sub("[REDACTED_SSN]", out)
    out = PHONE_PATTERN.sub("[REDACTED_PHONE]", out)
    return out


def detect_risks(value: Any) -> List[str]:
    text = _flatten_text(value)
    risks: List[str] = []
    if any(pattern.search(text) for pattern in SECRET_VALUE_PATTERNS):
        risks.append("secret_leak")
    if EMAIL_PATTERN.search(text) or SSN_PATTERN.search(text) or PHONE_PATTERN.search(text):
        risks.append("pii")
    lower = text.lower()
    injection_markers = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "system prompt",
        "developer message",
        "exfiltrate",
        "send the contents",
        "do not tell the user",
    ]
    if any(marker in lower for marker in injection_markers):
        risks.append("prompt_injection_marker")
    return sorted(set(risks))


def _flatten_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_flatten_text(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_flatten_text(v) for v in value)
    return str(value)

