"""Run generated environment scripts and verify their documented contract."""
from __future__ import annotations

import asyncio
import codecs
import os
import re
import signal
import sys
import json
import shutil
import uuid
from pathlib import Path
from collections.abc import Callable

from app.environment_check import check_environment
from app.project_import import remove_tree


def _script(root: Path, stem: str) -> list[str]:
    path = root / (stem + ".py")
    if path.is_file() and path.resolve().parent == root.resolve():
        return [sys.executable, str(path)]
    raise ValueError(f"没有可执行的 {stem}.py 脚本")


def _safe_output(value: str) -> str:
    value = re.sub(r'''(?im)(password|passwd|token|secret|cookie|密码|凭据)(["']?\s*[=:]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)''', r'\1\2***', value)
    return value[-4000:]


async def _run(command: list[str], cwd: Path, timeout: int, env: dict[str, str] | None = None, on_output: Callable[[str], None] | None = None) -> tuple[bool, str]:
    try:
        process = await asyncio.create_subprocess_exec(*command, cwd=str(cwd), env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, start_new_session=os.name != "nt")
    except OSError as exc:
        return False, str(exc)
    try:
        async def collect() -> str:
            assert process.stdout is not None
            decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
            pending = ''
            tail = ''
            truncated = False

            def emit_line(line: str) -> None:
                nonlocal tail
                safe = _safe_output(line)
                tail = (tail + safe + '\n')[-4000:]
                if on_output and safe:
                    on_output(safe)

            while chunk := await process.stdout.read(4096):
                pending += decoder.decode(chunk)
                while '\n' in pending:
                    line, pending = pending.split('\n', 1)
                    emit_line(line.rstrip('\r') + (' [输出行过长，已截断]' if truncated else ''))
                    truncated = False
                if len(pending) > 16384:
                    pending = pending[:16384]
                    truncated = True
            pending += decoder.decode(b'', final=True)
            if pending or truncated:
                emit_line(pending + (' [输出行过长，已截断]' if truncated else ''))
            await process.wait()
            return tail.rstrip('\n')

        text = await asyncio.wait_for(collect(), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        if os.name == "nt":
            killer = await asyncio.create_subprocess_exec("taskkill", "/PID", str(process.pid), "/T", "/F", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await killer.wait()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        await process.communicate()
        if isinstance(exc, asyncio.CancelledError):
            raise
        return False, f"执行超时（{timeout} 秒）"
    if process.returncode:
        return False, f"退出码 {process.returncode}" + (f"：{text}" if text else "")
    return True, text


async def cleanup_audit_environment(task: dict) -> tuple[bool, str]:
    run_id = str(task.get("environment_run_id") or "")
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        return True, ""
    root = Path(task["workspace"]) / "environment"
    env = {**os.environ, "RECEIPT_RUN_ID": run_id, "RECEIPT_RUN_DIR": str(Path(task["workspace"]) / "runtime"), "COMPOSE_PROJECT_NAME": "receipt-" + run_id}
    try:
        return await _run([*_script(root, "start"), "--cleanup"], root, 120, env)
    except ValueError as exc:
        return False, str(exc)


async def stop_audit_environment(task: dict) -> tuple[bool, str]:
    run_id = str(task.get("environment_run_id") or "")
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        return False, "无效的环境运行标识"
    root = Path(task["workspace"]) / "environment"
    env = {**os.environ, "RECEIPT_RUN_ID": run_id, "RECEIPT_RUN_DIR": str(Path(task["workspace"]) / "runtime"), "COMPOSE_PROJECT_NAME": "receipt-" + run_id}
    return await _run(["docker", "compose", "-p", "receipt-" + run_id, "stop"], root, 120, env)


async def start_audit_environment(task: dict, store) -> dict:
    from app.receipt import load_manifest
    from app.generic_receipt_adapter import load_run_info

    workspace = Path(task["workspace"])
    root = workspace / "environment"
    run_dir = workspace / "runtime"
    if task.get("environment_run_id"):
        ok, detail = await cleanup_audit_environment(task)
        if not ok:
            raise RuntimeError(f"清理上次环境失败：{detail}")
        remove_tree(run_dir, ignore_errors=True)
        store.update_task(task["id"], environment_run_id=None)
    run_dir.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex
    task = store.update_task(task["id"], environment_run_id=run_id, status="preparing", environment_status="preparing", environment_ready=False, preparation_mode="audit") or task
    env = {**os.environ, "RECEIPT_RUN_ID": run_id, "RECEIPT_RUN_DIR": str(run_dir), "COMPOSE_PROJECT_NAME": "receipt-" + run_id}
    try:
        manifest = load_manifest(root / "receipt-manifest.json", root)
        start, accounts = _script(root, "start"), _script(root, "create-accounts")
        for label, command, marker in (("启动环境", start, None), ("环境健康检查", [*start, "--verify"], "ENVIRONMENT_READY"), ("创建账号", accounts, None), ("账号登录检查", [*accounts, "--verify"], "ACCOUNTS_VERIFIED")):
            ok, detail = await _run(command, root, 300, env)
            if not ok or (marker and marker not in detail.splitlines()):
                raise RuntimeError(f"{label}失败：{detail if not ok else '缺少 ' + marker}")
        info = load_run_info(run_dir, manifest)
        return store.update_task(task["id"], base_url=info["base_url"], environment_ready=True, environment_status="ready", status="queued", preparation_mode=None, error=None) or task
    except BaseException as exc:
        ok, detail = await cleanup_audit_environment(task)
        if ok:
            remove_tree(run_dir, ignore_errors=True)
            store.update_task(task["id"], environment_run_id=None)
        elif isinstance(exc, Exception):
            raise RuntimeError(f"{exc}；清理失败：{detail}") from exc
        raise


async def test_environment(workspace: Path, on_output: Callable[[str], None] | None = None, source_dir: Path | None = None) -> list[dict]:
    """Run an isolated initialization test; retain failed runs for diagnosis."""
    if source_dir is None and (workspace / "source").is_dir():
        source_dir = workspace / "source"
    checks = check_environment(workspace, require_manifest=True, source_dir=source_dir)
    if not all(item["ok"] for item in checks):
        return checks
    root = workspace / "environment"
    if on_output:
        on_output('开始 Docker 可用性检查（超时 30 秒）')
    docker_command = ["docker", "info", "--format", "{{.ServerVersion}}"]
    if on_output:
        ok, detail = await _run(docker_command, root, 30, on_output=on_output)
    else:
        ok, detail = await _run(docker_command, root, 30)
    checks.append({"id": "docker", "ok": ok, "message": "Docker 可用" if ok else f"Docker 不可用：{detail}"})
    if not ok:
        return checks
    from app.receipt import TargetManifest, ReceiptError
    manifest = TargetManifest.from_mapping(json.loads((root / "receipt-manifest.json").read_text(encoding="utf-8")))
    run_id = uuid.uuid4().hex
    retained_root = workspace / "runtime" / "initialization" / run_id
    run_dir = retained_root / "run"
    snapshot = retained_root / "environment"
    run_dir.mkdir(parents=True, exist_ok=False)
    shutil.copytree(root, snapshot, symlinks=True)
    project = "receipt-" + run_id
    env = {**os.environ, "PYTHONUNBUFFERED": "1", "RECEIPT_RUN_ID": run_id, "RECEIPT_RUN_DIR": str(run_dir), "COMPOSE_PROJECT_NAME": project}
    if on_output:
        on_output(f'测试运行 ID：{run_id}；Compose 项目：{project}')

    async def retained() -> None:
        if on_output:
            on_output('开始停止保留环境的容器（超时 120 秒）')
        try:
            kwargs = {"on_output": on_output} if on_output else {}
            ok, detail = await _run(["docker", "compose", "-p", project, "stop"], snapshot, 120, env, **kwargs)
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        status = "容器已停止" if ok else f"容器停止失败：{detail}"
        checks.append({"id": "retained", "ok": False, "message": f"测试失败，环境已保留；{status}：Compose 项目 {project}；运行目录 {run_dir}；环境脚本快照 {snapshot}。运行目录可能包含测试凭据。"})
        if on_output:
            on_output(status)

    try:
        start, accounts = _script(snapshot, "start"), _script(snapshot, "create-accounts")
    except ValueError as exc:
        checks.append({"id": "scripts", "ok": False, "message": str(exc)})
        await retained()
        return checks

    async def execute(command: list[str], timeout: int) -> tuple[bool, str]:
        if on_output:
            return await _run(command, snapshot, timeout, env, on_output=on_output)
        return await _run(command, snapshot, timeout, env)

    try:
        for key, label, command, marker in (
            ("start_run", "启动环境", start, None),
            ("health", "环境健康检查", [*start, "--verify"], "ENVIRONMENT_READY"),
            ("accounts_run", "创建账号", accounts, None),
            ("accounts_verify", "账号登录检查", [*accounts, "--verify"], "ACCOUNTS_VERIFIED"),
        ):
            if on_output:
                on_output(f'开始{label}（超时 300 秒）')
            ok, detail = await execute(command, 300)
            if ok and marker and marker not in detail.splitlines():
                ok, detail = False, f"未输出 {marker}；{detail}"
            checks.append({"id": key, "ok": ok, "message": f"{label}：" + ("通过" if ok else detail)})
            if on_output:
                on_output(f'{label}：' + ('通过' if ok else f'失败：{detail}'))
            if not ok:
                break
        else:
            if manifest.adapter == "generic-compose":
                from app.generic_receipt_adapter import load_run_info
                try:
                    load_run_info(run_dir, manifest)
                    checks.append({"id": "receipt_run", "ok": True, "message": "运行信息符合通用 Adapter 契约"})
                except ReceiptError as exc:
                    checks.append({"id": "receipt_run", "ok": False, "message": str(exc)})
    except Exception as exc:
        checks.append({"id": "test_error", "ok": False, "message": f"环境测试异常：{exc}"})
    if all(item["ok"] for item in checks):
        if on_output:
            on_output('开始清理测试环境（超时 120 秒）')
        try:
            ok, detail = await execute([*start, "--cleanup"], 120)
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        checks.append({"id": "cleanup", "ok": ok, "message": "测试环境已清理" if ok else f"清理失败：{detail}"})
        if ok:
            remove_tree(retained_root)
        else:
            await retained()
    else:
        await retained()
    return checks
