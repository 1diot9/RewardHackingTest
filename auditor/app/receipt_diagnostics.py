"""诊断信息只写入受保护的任务工作区，不包含命令参数或认证材料。"""
from __future__ import annotations

import contextvars
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_destination: contextvars.ContextVar[Path | None] = contextvars.ContextVar("receipt_diagnostics", default=None)
_secrets: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar("receipt_secrets", default=())
_last: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar("receipt_last_diagnostic", default={})


def begin(workspace: Path) -> tuple[Any, Any]:
    return _destination.set(workspace / "receipt" / "diagnostics.jsonl"), _secrets.set(())


def end(tokens: tuple[Any, Any]) -> None:
    _destination.reset(tokens[0])
    _secrets.reset(tokens[1])


def add_secrets(*values: str) -> None:
    _secrets.set(_secrets.get() + tuple(v for v in values if isinstance(v, str) and len(v) >= 4))


def clear_last() -> None:
    _last.set({})


def last() -> dict[str, Any]:
    return _last.get()


def redact(value: object) -> str:
    text = str(value)
    for secret in sorted(_secrets.get(), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    # 丢弃整行，避免 JSON、HTTP 头和多种键值格式泄露认证信息。
    sensitive = re.compile(r"password|passwd|credential|cookie|authorization|secret|token|api[_-]?key|session", re.I)
    return "\n".join("[REDACTED sensitive line]" if sensitive.search(line) else line for line in text.splitlines())[:12000]


def record(stage: str, *, run_id: str = "", error: object = "", **details: object) -> None:
    _last.set({"stage": stage, **{key: value for key, value in details.items() if key in {"exit_code", "timeout_seconds", "operation"}}})
    destination = _destination.get()
    if destination is None:
        return
    entry = {"time": datetime.now(timezone.utc).isoformat(), "run_id": run_id, "stage": stage}
    if error:
        entry["error"] = redact(error)
    entry.update({key: redact(value) if isinstance(value, str) else value for key, value in details.items()})
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        # 不能因为诊断文件不可写而改变验证结论；同时保留标准日志。
        import logging
        logging.getLogger(__name__).exception("Unable to write RECEIPT diagnostics")
