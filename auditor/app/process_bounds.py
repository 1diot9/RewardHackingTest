"""把验证步骤限制在墙钟时间内。超时后结束进程树，并留下当前步骤名。"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

STEP_FILE_ENV = "RECEIPT_STEP_FILE"
RESULT_FILE_ENV = "RECEIPT_RESULT_FILE"
WORKER_ENV = "RECEIPT_BROWSER_WORKER"
STEP_PREFIX_ENV = "RECEIPT_STEP_PREFIX"
# Playwright 自己的超时若能返回，就不必杀进程。只在它没有返回时再多等这几秒。
GRACE_SECONDS = 5


class StepTimeout(Exception):
    def __init__(self, step: str, timeout_seconds: float, index: int | None = None) -> None:
        self.step = step
        self.timeout_seconds = timeout_seconds
        self.index = index
        super().__init__(step)


def mark_step(step: str, index: int | None = None) -> None:
    """把当前步骤写到监督进程可读的文件。没有监督文件时什么也不做。"""
    path = os.environ.get(STEP_FILE_ENV)
    if not path:
        return
    payload: dict[str, Any] = {"step": step, "started": time.time()}
    if index is not None:
        payload["index"] = index
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def browser_runs_inprocess() -> bool:
    """测试注入的假 Playwright 留在当前进程。真实浏览器放到可杀死的子进程。"""
    if os.environ.get(WORKER_ENV) == "1":
        return True
    api = sys.modules.get("playwright.sync_api")
    factory = getattr(api, "sync_playwright", None) if api is not None else None
    module = str(getattr(factory, "__module__", "") or "")
    return bool(factory) and not module.startswith("playwright.")


def kill_process_tree(pid: int) -> None:
    if pid <= 0:
        return
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        return
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            return


def _drain(pipe: Any, sink: list[str]) -> None:
    try:
        sink.append(pipe.read())
    except Exception:
        sink.append("")


def _reap(proc: subprocess.Popen[str]) -> None:
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        return


def _release(proc: subprocess.Popen[str]) -> None:
    """结果已经写下时，只再给浏览器关闭一小段时间，然后结束进程树。"""
    if proc.poll() is not None:
        return
    try:
        proc.wait(timeout=GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        kill_process_tree(proc.pid)
        _reap(proc)


def _read_json_dict(path: Path) -> dict[str, Any] | None:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return None
    return loaded if isinstance(loaded, dict) else None


def run_bounded(
    command: list[str],
    timeout: int,
    step: str,
    *,
    cwd: Path | str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """运行外部命令。到时后结束整个进程树，避免子进程退出后孙子进程占住管道。"""
    proc = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    stdout: list[str] = []
    stderr: list[str] = []
    assert proc.stdout is not None and proc.stderr is not None
    readers = (
        threading.Thread(target=_drain, args=(proc.stdout, stdout), daemon=True),
        threading.Thread(target=_drain, args=(proc.stderr, stderr), daemon=True),
    )
    for reader in readers:
        reader.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_process_tree(proc.pid)
        _reap(proc)
        raise StepTimeout(step, timeout) from None
    for reader in readers:
        reader.join(2)
    return subprocess.CompletedProcess(
        command,
        1 if proc.returncode is None else proc.returncode,
        stdout[0] if stdout else "",
        stderr[0] if stderr else "",
    )


def _read_step(path: Path) -> dict[str, Any] | None:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(loaded, dict) or not isinstance(loaded.get("step"), str) or not isinstance(loaded.get("started"), (int, float)):
        return None
    return loaded


def supervise(
    proc: subprocess.Popen[str],
    step_file: Path,
    timeout_s: float,
    result_file: Path | None = None,
) -> dict[str, Any]:
    """等待子进程。结果文件一旦写好就返回；同一步停留超过 timeout_s 才结束进程树。"""
    current_step = "playwright_start"
    current_index: int | None = None
    current_started = time.time()
    while True:
        if result_file is not None:
            loaded = _read_json_dict(result_file)
            if loaded is not None:
                _release(proc)
                return {"timeout": False, "step": current_step, "index": current_index, "result": loaded}
        info = _read_step(step_file)
        if info is not None and float(info["started"]) != current_started:
            current_step = info["step"]
            current_index = info.get("index") if type(info.get("index")) is int else None
            current_started = float(info["started"])
        if time.time() - current_started > timeout_s:
            kill_process_tree(proc.pid)
            _reap(proc)
            late = _read_json_dict(result_file) if result_file is not None else None
            if late is not None:
                return {"timeout": False, "step": current_step, "index": current_index, "result": late}
            return {"timeout": True, "step": current_step, "index": current_index, "timeout_seconds": int(timeout_s)}
        if proc.poll() is not None:
            return {"timeout": False, "step": current_step, "index": current_index}
        time.sleep(0.2)


def run_browser_job(job: dict[str, Any], timeout_ms: int) -> dict[str, Any]:
    """在子进程里跑浏览器步骤。子进程空转时，父进程仍能按当前步骤返回。"""
    from app.config import AUDITOR_ROOT

    timeout_s = max(1.0, timeout_ms / 1000) + GRACE_SECONDS
    reported_timeout = max(1, int(timeout_ms / 1000))
    with tempfile.TemporaryDirectory(prefix="receipt-browser-") as raw:
        root = Path(raw)
        step_file = root / "step.json"
        result_file = root / "result.json"
        env = os.environ.copy()
        env[WORKER_ENV] = "1"
        env[STEP_FILE_ENV] = str(step_file)
        env[RESULT_FILE_ENV] = str(result_file)
        env["PYTHONUTF8"] = "1"
        proc = subprocess.Popen(
            [sys.executable, "-m", "app.browser_worker"],
            cwd=str(AUDITOR_ROOT),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(job).encode("utf-8"))
        proc.stdin.close()
        outcome = supervise(proc, step_file, timeout_s, result_file)
        if isinstance(outcome.get("result"), dict):
            return outcome["result"]
        if outcome.get("timeout"):
            outcome["timeout_seconds"] = reported_timeout
            return outcome
        loaded = _read_json_dict(result_file)
        if loaded is not None:
            return loaded
        return {"failed": True, "code": proc.returncode, "step": outcome.get("step") or "playwright_start", "index": outcome.get("index")}
