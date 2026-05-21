from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def reset_main_state(tmp_path: Path):
    from mcp_evidence import main

    main.get_store.cache_clear()
    main.get_policy_engine.cache_clear()
    main.settings.database_path = tmp_path / "audit.sqlite3"
    main.settings.target_mcp_url = "http://127.0.0.1:9000/mcp"
    main.settings.policy_path = Path("config/policies.json")
    main.settings.max_body_bytes = 2_000_000
    main.settings.admin_token = None
    main.settings.proxy_token = None
    yield
    main.get_store.cache_clear()
    main.get_policy_engine.cache_clear()
    main.settings.policy_path = Path("config/policies.json")
    main.settings.max_body_bytes = 2_000_000
    main.settings.admin_token = None
    main.settings.proxy_token = None

