from __future__ import annotations

import os
from pathlib import Path

AUDITOR_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(os.environ.get("AUDITOR_REPO_ROOT", AUDITOR_ROOT.parent)).resolve()
PROMPTS_DIR = AUDITOR_ROOT / "prompts"
POCLIB_FILE = AUDITOR_ROOT / "runtime" / "poclib.py"
RECEIPT_MANIFESTS_DIR = AUDITOR_ROOT / "manifests"
DATA_DIR = AUDITOR_ROOT / "data"
WORKSPACES_DIR = AUDITOR_ROOT / "workspaces"
PROJECTS_DIR = AUDITOR_ROOT / "projects"
STATE_PATH = DATA_DIR / "state.json"
SOURCE_DIR = REPO_ROOT / "src"
AUTH_DOC = REPO_ROOT / "docs" / "auth.md"
CODE_MAP = REPO_ROOT / "docs" / "code-map.md"
ACCOUNTS_FILE = REPO_ROOT / "accounts.json"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
START_SCRIPT = REPO_ROOT / "start.ps1"
REGISTER_SCRIPT = REPO_ROOT / "scripts" / "register-test-accounts.ps1"

HOST = os.environ.get("AUDITOR_HOST", "127.0.0.1")
PORT = int(os.environ.get("AUDITOR_PORT", "8787"))
MAX_CONCURRENT = max(1, int(os.environ.get("AUDITOR_MAX_CONCURRENT", "1")))
MIN_CONTEXT_WINDOW_TOKENS = 100_000
CONTEXT_WINDOW_TOKENS = max(MIN_CONTEXT_WINDOW_TOKENS, int(os.environ.get("AUDITOR_CONTEXT_TOKENS", "256000")))
COMPACT_PERCENT = min(100, max(1, int(os.environ.get("AUDITOR_COMPACT_PERCENT", "75"))))
QUOTA_POLL_SECONDS = max(1, int(os.environ.get("AUDITOR_QUOTA_POLL_SECONDS", "60")))


def receipt_adapter_modules() -> tuple[str, ...]:
    """仅由部署管理员设置的可信 Adapter 模块列表。"""

    raw = os.environ.get("RECEIPT_TRUSTED_ADAPTER_MODULES", "")
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def compaction_env(
    *,
    context_window_tokens: int | None = None,
    compact_percent: int | None = None,
) -> dict[str, str]:
    window_tokens = (
        CONTEXT_WINDOW_TOKENS
        if context_window_tokens is None
        else max(MIN_CONTEXT_WINDOW_TOKENS, int(context_window_tokens))
    )
    percent = COMPACT_PERCENT if compact_percent is None else min(100, max(1, int(compact_percent)))
    window = str(window_tokens)
    return {
        "CLAUDE_CODE_MAX_CONTEXT_TOKENS": window,
        "CLAUDE_CODE_AUTO_COMPACT_WINDOW": window,
        "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE": str(percent),
        "DISABLE_AUTO_COMPACT": "0",
        "DISABLE_COMPACT": "0",
    }


def default_base_url() -> str:
    port = "17778"
    env_path = REPO_ROOT / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            if key.strip() == "JOOMLA_PORT":
                raw = value.strip().strip('"').strip("'")
                if raw.isdigit():
                    port = raw
                break
    return f"http://127.0.0.1:{port}/"
