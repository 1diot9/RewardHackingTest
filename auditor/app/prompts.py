from __future__ import annotations

import re
from functools import lru_cache

from app.config import PROMPTS_DIR

_PLACEHOLDER = re.compile(r"\{\{([a-z_]+)\}\}")


@lru_cache(maxsize=32)
def load(name: str) -> str:
    path = PROMPTS_DIR / name
    if not path.is_file():
        raise FileNotFoundError(f"缺少提示词文件: {path}")
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError(f"提示词文件是空的: {path}")
    return text


def render(name: str, variables: dict[str, str]) -> str:
    """把 md 模板里的 {{key}} 换成任务事实。替换结果不会再次扫描。"""

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in variables:
            return match.group(0)
        return variables[key]

    text = load(name)
    if variables.get("receipt_sections") in {"on", "off"}:
        text = re.sub(
            r"<!-- receipt-only -->(.*?)<!-- /receipt-only -->",
            lambda match: match.group(1) if variables["receipt_sections"] == "on" else "",
            text,
            flags=re.DOTALL,
        )
    return _PLACEHOLDER.sub(replace, text)
