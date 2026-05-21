import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import PolicyDecision


class PolicyEngine:
    def __init__(self, policy_path: Path):
        self.policy_path = policy_path
        self.rules: List[Dict[str, Any]] = []
        self.default_action = "allow"
        self.reload()

    def reload(self) -> None:
        if not self.policy_path.exists():
            self.rules = []
            self.default_action = "allow"
            return
        with self.policy_path.open("r", encoding="utf-8") as handle:
            document = json.load(handle)
        self.default_action = document.get("default_action", "allow")
        self.rules = document.get("rules", [])

    def decide(self, request_body: Any, method: Optional[str], tool_name: Optional[str]) -> PolicyDecision:
        for rule in self.rules:
            if not self._matches(rule, request_body, method, tool_name):
                continue
            action = rule.get("action", "allow")
            allowed = action == "allow"
            return PolicyDecision(
                allowed=allowed,
                reason=rule.get("reason") or f"{action} by policy",
                rule_id=rule.get("id"),
            )
        allowed = self.default_action == "allow"
        return PolicyDecision(allowed=allowed, reason=f"default {self.default_action}")

    def _matches(
        self,
        rule: Dict[str, Any],
        request_body: Any,
        method: Optional[str],
        tool_name: Optional[str],
    ) -> bool:
        if rule.get("method") and rule["method"] != method:
            return False
        if rule.get("tool_name") and rule["tool_name"] != tool_name:
            return False
        if rule.get("param_regex"):
            text = json.dumps(request_body, sort_keys=True)
            if not re.search(rule["param_regex"], text, flags=re.IGNORECASE):
                return False
        return True


def extract_mcp_metadata(body: Any) -> Dict[str, Optional[str]]:
    if not isinstance(body, dict):
        return {"method": None, "tool_name": None}
    method = body.get("method")
    tool_name = None
    params = body.get("params")
    if method == "tools/call" and isinstance(params, dict):
        tool_name = params.get("name")
    return {"method": method, "tool_name": tool_name}

