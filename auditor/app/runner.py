from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import shutil
import time
import traceback
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AsyncExitStack
from pathlib import Path
from urllib.parse import urlparse

from app.config import MAX_CONCURRENT, POCLIB_FILE, QUOTA_POLL_SECONDS, SOURCE_DIR, compaction_env
from app.gateway import quota_probe
from app.environment_test import stop_audit_environment, test_environment, start_audit_environment
from app.guard import allowed_hosts_for, pre_tool_decision
from app.hub import Hub
from app.poctool import build_audit_server
from app.pricing import Ledger, Prices, UsageAccumulator, price_of, summarize_model_usage, tokens_from_usage
from app.quota import RunClock, is_quota_signal
from app.receipt import ReceiptError, load_receipt_candidate
from app.receipt_execution import ReceiptExecutionError, receipt_failure_feedback, verify_receipt_candidate
from app.receipt_settings import receipt_configuration_errors, receipt_runtime_config
from app.reports import close_unresolved_reviews, list_reports, record_verification_attempt, save_review
from app.prompts import render
from app.store import Store, active_seconds, now_iso

CLOCK_CHECKPOINT_SECONDS = 5.0

class ConcurrencyLimiter:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.active = 0
        self.condition = asyncio.Condition()

    async def set_limit(self, limit: int) -> None:
        async with self.condition:
            self.limit = limit
            self.condition.notify_all()

    async def __aenter__(self) -> None:
        async with self.condition:
            await self.condition.wait_for(lambda: self.active < self.limit)
            self.active += 1

    async def __aexit__(self, *args: object) -> None:
        async with self.condition:
            self.active -= 1
            self.condition.notify_all()


_LIMITER = ConcurrencyLimiter(MAX_CONCURRENT)
_STOPS: dict[str, asyncio.Event] = {}
_REASONS: dict[str, str] = {}


class InitializationStopped(Exception):
    """The user stopped project initialization at a safe checkpoint."""


async def set_max_concurrent(limit: int) -> None:
    await _LIMITER.set_limit(limit)


def register_stop(task_id: str) -> asyncio.Event:
    event = asyncio.Event()
    _STOPS[task_id] = event
    _REASONS.pop(task_id, None)
    return event


def request_stop(task_id: str, reason: str) -> None:
    if task_id not in _REASONS:
        _REASONS[task_id] = reason
    event = _STOPS.get(task_id)
    if event is not None:
        event.set()


def stop_reason(task_id: str) -> str | None:
    return _REASONS.get(task_id)


def clear_stop(task_id: str) -> None:
    _STOPS.pop(task_id, None)
    _REASONS.pop(task_id, None)


def _redact(text: str, secret: str) -> str:
    if secret and secret in text:
        return text.replace(secret, "***")
    return text


def _clip(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def _artifact_counts(workspace: Path) -> dict[str, int]:
    findings = list((workspace / "findings").glob("*.md")) if (workspace / "findings").is_dir() else []
    poc_dir = workspace / "poc"
    pocs = [
        path
        for path in poc_dir.glob("*.py")
        if path.is_file() and path.name != "poclib.py"
    ] if poc_dir.is_dir() else []
    return {"findings": len(findings), "pocs": len(pocs)}


def _finding_names(workspace: Path) -> str:
    directory = workspace / "findings"
    if not directory.is_dir():
        return "（暂无）"
    names = sorted(path.name for path in directory.glob("*.md"))
    if not names:
        return "（暂无）"
    return "\n".join(f"- findings/{name}" for name in names[:100])


def _round_summary_path(workspace: Path, round_number: int) -> Path:
    return workspace / "notes" / f"round-{round_number:03d}-summary.md"


def _round_summary_ready(workspace: Path, round_number: int) -> bool:
    path = _round_summary_path(workspace, round_number)
    if not path.is_file():
        return False
    try:
        return bool(path.read_text(encoding="utf-8").strip())
    except (OSError, UnicodeError):
        return False


def _environment_ready(workspace: Path) -> bool:
    path = workspace / "environment" / "READY.md"
    try:
        return path.is_file() and bool(path.read_text(encoding="utf-8").strip())
    except (OSError, UnicodeError):
        return False


def _restored_active_round(workspace: Path, round_number: int) -> int | None:
    if round_number <= 0 or _round_summary_ready(workspace, round_number):
        return None
    return round_number


def _source_dir(task: dict) -> Path:
    """Use task-owned imports for new tasks while preserving resumability of old tasks."""
    return Path(str(task.get("source_dir") or SOURCE_DIR)).resolve()


def _security_policy_sources(source_dir: Path) -> list[Path]:
    """Collect every conventional security policy file, without letting one hide another."""
    try:
        root = source_dir.resolve()
    except OSError:
        return []
    found: list[Path] = []
    seen: set[Path] = set()
    for relative_dir in ("", ".github", "docs"):
        directory = root if not relative_dir else root / relative_dir
        if not directory.is_dir():
            continue
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for entry in sorted(entries, key=lambda item: item.name):
            if not entry.is_file() or entry.name.casefold() != "security.md":
                continue
            try:
                resolved = entry.resolve()
            except OSError:
                continue
            if resolved in seen or not resolved.is_relative_to(root):
                continue
            seen.add(resolved)
            found.append(entry)
    return found


def _security_policy_path(source_dir: Path) -> Path | None:
    sources = _security_policy_sources(source_dir)
    return sources[0] if sources else None


def _copy_security_policy(source_dir: Path, workspace: Path) -> bool:
    """Copy every conventional security policy into security-policy/ and write an index."""
    sources = _security_policy_sources(source_dir)
    if not sources:
        return False
    try:
        root = source_dir.resolve()
    except OSError:
        return False
    destination_root = workspace / "security-policy"
    if destination_root.exists():
        shutil.rmtree(destination_root)
    lines = [
        "# 安全政策索引",
        "",
        "收录判断以 `security-policy/` 下的全部副本为准。短的漏洞报告政策不能代替安全模型或已知限制文档。",
        "",
    ]
    for source in sources:
        relative = source.resolve().relative_to(root).as_posix()
        target = destination_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.resolve() != target.resolve():
            shutil.copyfile(source, target)
        lines.append(f"- `security-policy/{relative}`")
    lines.append("")
    (workspace / "SECURITY.md").write_text("\n".join(lines), encoding="utf-8")
    return True


def _variables(task: dict, workspace: Path) -> dict[str, str]:
    prices = task["prices"]
    return {
        "base_url": str(task.get("base_url") or "（未提供；仅做静态审计）"),
        "instruction": task["instruction"],
        "workspace": str(workspace),
        "source_dir": str(_source_dir(task)),
        "security_policy": "`SECURITY.md`（安全政策索引，正文在 `security-policy/`）" if _security_policy_path(_source_dir(task)) else "目标项目未提供常见位置的 SECURITY.md；不要将工作区旧文件视为本项目政策",
        "project_name": str(task.get("project_name") or "导入项目"),
        "budget": f"{float(task['budget']):.4f}",
        "duration": str(int(task["duration_seconds"])),
        "currency": task.get("currency") or "USD",
        "input_price": str(prices["input_per_mtok"]),
        "output_price": str(prices["output_per_mtok"]),
        "model": task["model"],
        "provider_name": task.get("provider_name") or "",
        "receipt_protocol": _receipt_protocol(task),
        "receipt_sections": "on" if task.get("receipt_enabled") and task.get("receipt_manifest") else "off",
    }


def _receipt_protocol(task: dict) -> str:
    if not task.get("receipt_enabled", False):
        return ""
    if not task.get("receipt_manifest"):
        return "本任务未绑定可信 RECEIPT Manifest；验证器不可用，不要提交验证器 PoC。"
    return (
        "动态验证 XSS 时，先用 `submit_poc` 登记一条候选项，再调用 `start_receipt` 验证这一条，不要自行写 `receipt/`。"
        "有攻击者脚本时，`submit_poc` 会写入 `poc/<poc_id>.py`，并把脚本正文快照进 `receipt/candidates/<poc_id>.json`；"
        "无攻击者步骤的反射型/DOM 型把 source 留空。校验失败时不会落盘。修改脚本或受害者动作后必须再次 `submit_poc`，然后对同一个 `poc_id` 重新 `start_receipt`。"
        "每次提交都必须提供 `victim_json`，它是包含实际受害者 URL 和动作的 JSON 对象字符串；`source` 必须为完整脚本或空字符串，不能是 placeholder。旧版批量提交工具已停用，继续旧任务时请重新阅读 ARTIFACTS.md。"
        "每次只验证当前这一条，不要连带重放其他候选项。`start_receipt` 只接收 `poc_id` 和 `findings/<文件名>.md`，报告可以在验证后创建，但路径必须一致。"
        "攻击者脚本必须使用 `poclib`，可以导入非受限模块（如 `base64`、`json`、`hashlib`、`hmac`）；请求仍须通过 `ctx.request`。可通过 `ctx.receipt_token` 将本轮挑战写进载荷。"
        "重放时 `ctx.username` 与 `ctx.password` 为空。需要登录的攻击者脚本必须在 `attacker_login_json` 中声明登录步骤；使用浏览器存储令牌的应用还需在 `attacker_auth_headers_json` 中声明存储键与请求头映射，由 `ctx.request` 自动发送认证信息。不要在脚本里调用目标登录接口。"
        "受害者 URL 或 `fill` / `select` 的 value 可使用 `{{receipt_token}}`。载荷在受害者页面真正执行的位置调用 "
        "`window.__receipt_accept(token)`。不要猜测或提交攻击者/受害者角色、账号、Cookie、密码或 CDP 地址；这些由验证器控制。"
    )


def prepare_workspace(task: dict) -> Path:
    workspace = Path(task["workspace"])
    source_dir = _source_dir(task)
    if not source_dir.is_dir():
        raise RuntimeError("导入的项目源码目录不存在")
    for directory in (workspace / "environment", workspace / "findings", workspace / "poc", workspace / "notes", workspace / "receipt" / "candidates"):
        directory.mkdir(parents=True, exist_ok=True)
    _copy_security_policy(source_dir, workspace)
    if task.get("base_url") and POCLIB_FILE.is_file():
        shutil.copyfile(POCLIB_FILE, workspace / "poc" / "poclib.py")
    (workspace / "ARTIFACTS.md").write_text(render("artifact-format.md", _variables(task, workspace)), encoding="utf-8")
    brief = render("task-brief.md", _variables(task, workspace))
    if task.get("automatic_environment") and (workspace / "runtime" / "receipt-run.json").is_file():
        brief += "\n测试账号与靶场地址记录在工作区 runtime/receipt-run.json，请勿在报告中泄露密码。\n"
    (workspace / "TASK.md").write_text(brief, encoding="utf-8")
    return workspace


def _candidate_public_view(poc_id: str, raw: dict) -> dict:
    view = {key: raw[key] for key in ("poc_id", "marker", "attacker_login", "attacker_auth_headers", "victim", "claim") if key in raw}
    script = raw.get("attacker_script")
    if isinstance(script, str) and script.strip():
        view["attacker_script_path"] = f"poc/{poc_id}.py"
    return view


def _review_candidate_context(workspace: Path, report_paths: list[str]) -> str:
    """Expose submitted candidate inputs, without exposing protected verification results or script bodies."""
    selected = []
    for report in list_reports(workspace, False):
        if report.path not in report_paths or not report.poc_id:
            continue
        path = workspace / "receipt" / "candidates" / f"{report.poc_id}.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(raw, dict):
            continue
        selected.append({"report": report.path, **_candidate_public_view(report.poc_id, raw)})
    return json.dumps(selected, ensure_ascii=False, indent=2) if selected else "（没有可用的已提交候选项；请根据报告和现有文件重建。）"


async def _verify_pending_reports(
    workspace: Path,
    base_url: str,
    verify_candidate: Callable[[str, str], Awaitable[Mapping[str, str]]],
    required_reports: set[str] | None = None,
) -> str | None:
    """Replay linked candidates and return a safe follow-up for every pending report."""
    pending = [
        report for report in list_reports(workspace, True)
        if report.review_status != "audit_failed"
        and (report.review_status == "pending" or report.path in (required_reports or set()))
    ]
    if not pending:
        return None

    def ready(poc_id: str) -> bool:
        try:
            load_receipt_candidate(workspace, poc_id, base_url=base_url)
        except ReceiptError:
            return False
        return True

    lines = ["检测到仍处于待验证状态的报告。系统已检查已提交的 RECEIPT 候选项："]
    for report in pending:
        if not report.poc_id or not ready(report.poc_id):
            lines.append(f"- `{report.path}`：没有可重放的关联候选项。请检查报告与现有测试脚本、受害者行为配置，按 ARTIFACTS.md 用 submit_poc 登记后再调用 start_receipt；若结论不构成可执行 XSS，请修正报告。")
            continue
        feedback = await verify_candidate(report.poc_id, report.path)
        verdict = feedback.get("verdict")
        save_review(workspace, report.path, report.poc_id, verdict if verdict in {"ACCEPTED", "REJECTED", "INDETERMINATE"} else None)
        lines.append(f"- `{report.path}`：系统已重放 `{report.poc_id}`，结果：{json.dumps(dict(feedback), ensure_ascii=False)}")
    lines.append("请保留所有报告，根据上述结果继续处理；没有候选项时必须先提交 submit_poc，再调用 start_receipt，不得因预期失败而跳过。无法提交时明确说明障碍。")
    return "\n".join(lines)


def _reports_needing_verification(
    workspace: Path,
    pending_review_reports: list[str] | None,
    verified_poc_ids: set[str],
) -> list:
    """代理本轮结束后仍会触发自动验证的报告。审计不通过不再计入。"""

    selected = set(pending_review_reports or [])
    reports = list_reports(workspace, True)
    required = {
        report.path for report in reports
        if report.path in selected and report.poc_id not in verified_poc_ids and report.review_status != "audit_failed"
    }
    return [report for report in reports if report.review_status == "pending" or report.path in required]


def _snapshot_reports(workspace: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in (workspace / "findings").glob("*.md") if path.is_file() and not path.is_symlink()}


def _restore_missing_reports(workspace: Path, snapshot: dict[str, bytes]) -> list[str]:
    directory = workspace / "findings"
    restored = []
    for name, content in snapshot.items():
        path = directory / name
        if not path.is_file() or path.is_symlink():
            directory.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                path.unlink()
            path.write_bytes(content)
            restored.append(name)
    return restored


def _github_change_prompt(task: dict) -> str:
    counts = task.get("github_change_counts")
    if not counts or not any(counts.values()):
        return ""
    return (
        "\n\n已从 GitHub 拉取最新源码，文件发生了变化。"
        "请注意检查原有漏洞在当前源码中是否仍然存在。"
    )


def _audit_prompt(
    task: dict,
    workspace: Path,
    ledger: Ledger,
    remaining_seconds: float,
    round_number: int,
    resume: bool,
) -> str:
    remaining_budget = max(0.0, float(task["budget"]) - ledger.spent)
    variables = _variables(task, workspace)
    variables.update(
        {
            "budget_remaining": f"{remaining_budget:.4f}",
            "time_remaining": str(max(0, int(remaining_seconds))),
            "spent": f"{ledger.spent:.4f}",
            "findings": _finding_names(workspace),
            "previous_summary_path": (
                _round_summary_path(workspace, round_number - 1).relative_to(workspace).as_posix()
                if round_number > 1
                else "（暂无）"
            ),
            "summary_path": _round_summary_path(workspace, round_number).relative_to(workspace).as_posix(),
        }
    )
    if task.get("pending_review_reports") is not None:
        variables["pending_reports"] = "\n".join(f"- `{path}`" for path in task["pending_review_reports"])
        variables["review_candidates"] = _review_candidate_context(workspace, task["pending_review_reports"])
        return render("review-pending.md", variables)
    if task.get("completion_mode") == "agent":
        prompt = render("run-agent-resume.md" if resume else "run-agent.md", variables)
    else:
        prompt = render("run-resume.md" if resume else "run.md", variables)
    prompt += _github_change_prompt(task)
    if task.get("follow_up_instruction"):
        prompt += "\n\n本次后续任务的用户指令（优先执行）：\n" + task["follow_up_instruction"]
    return prompt


def _summary_prompt(workspace: Path, round_number: int) -> str:
    relative = _round_summary_path(workspace, round_number).relative_to(workspace).as_posix()
    return render("write-summary.md", {"summary_path": relative})


class ConsecutiveToolGuard:
    """Track the last attempted tool call without storing its arguments."""

    def __init__(self, previous: str | None = None, persist: Callable[[str], None] | None = None) -> None:
        self.previous = previous
        self.persist = persist

    def check(self, name: str, arguments: dict) -> bool:
        payload = json.dumps([name, arguments], sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        repeated = fingerprint == self.previous
        if not repeated:
            self.previous = fingerprint
            if self.persist is not None:
                self.persist(fingerprint)
        return repeated


def _build_options(
    task: dict,
    workspace: Path,
    api_key: str,
    base_url: str,
    on_stderr,
    resume: str | None = None,
    *,
    environment_setup: bool = False,
    receipt_verifier: Callable[[str, str], Awaitable[Mapping[str, str]]] | None = None,
    proxy_settings: Mapping[str, object] | None = None,
    consecutive_tool_guard: ConsecutiveToolGuard | None = None,
    on_compact: Callable[[], None] | None = None,
):
    import os

    from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

    env = {
        "CLAUDE_AGENT_SDK_CLIENT_APP": "xss-auditor",
        "API_TIMEOUT_MS": "120000",
        "CLAUDE_CODE_MAX_RETRIES": "2",
        **compaction_env(
            context_window_tokens=task.get("context_window_tokens"),
            compact_percent=task.get("compact_percent"),
        ),
    }
    inherited = os.environ.get("PATH")
    if inherited:
        env["PATH"] = inherited
    if environment_setup and proxy_settings and proxy_settings.get("enabled"):
        proxy_url = str(proxy_settings.get("url") or "")
        bypass = ["localhost", "127.0.0.1", "::1", "host.docker.internal"]
        target = urlparse(str(task.get("base_url") or "")).hostname
        if target:
            bypass.append(target)
        for value in (os.environ.get("NO_PROXY", ""), os.environ.get("no_proxy", ""), str(proxy_settings.get("no_proxy") or "")):
            bypass.extend(part.strip() for part in value.split(",") if part.strip())
        no_proxy = ",".join(dict.fromkeys(bypass))
        env.update({"HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url,
                    "http_proxy": proxy_url, "https_proxy": proxy_url,
                    "NO_PROXY": no_proxy, "no_proxy": no_proxy})
    if base_url:
        env["ANTHROPIC_BASE_URL"] = base_url
    if api_key:
        env["ANTHROPIC_API_KEY"] = api_key
        env["ANTHROPIC_AUTH_TOKEN"] = api_key

    source_dir = _source_dir(task)
    lab_hosts = allowed_hosts_for(str(task.get("base_url") or ""))
    report_snapshot = _snapshot_reports(workspace) if not environment_setup else {}
    consecutive_guard = consecutive_tool_guard or ConsecutiveToolGuard()

    async def guard_tool(input_data, tool_use_id, context):
        del tool_use_id, context
        tool_name = str(input_data.get("tool_name") or "")
        tool_input = dict(input_data.get("tool_input") or {})
        if consecutive_guard.check(tool_name, tool_input):
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "禁止连续调用参数完全相同的同一个工具。请检查上次结果，修改参数或选择其他必要操作。",
                }
            }
        if not environment_setup:
            _restore_missing_reports(workspace, report_snapshot)
            report_snapshot.update(_snapshot_reports(workspace))
        reason = pre_tool_decision(
            workspace,
            tool_name,
            tool_input,
            lab_hosts,
            read_roots=(source_dir,),
            environment_setup=environment_setup,
        )
        if not reason:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }

    async def preserve_reports(input_data, tool_use_id, context):
        del input_data, tool_use_id, context
        if not environment_setup:
            restored = _restore_missing_reports(workspace, report_snapshot)
            report_snapshot.update(_snapshot_reports(workspace))
            if restored:
                return {"systemMessage": "禁止撤回报告，系统已恢复：" + ", ".join(restored)}
        return {}

    async def notify_compaction(input_data, tool_use_id, context):
        del input_data, tool_use_id, context
        if on_compact is not None:
            on_compact()
        return {}

    allowed_tools = ["Read", "Grep", "Glob", "Bash", "Write", "Edit"]
    if environment_setup:
        allowed_tools.extend(["PowerShell", "WebSearch", "WebFetch"])
    if task.get("base_url"):
        allowed_tools.append("mcp__audit__submit_poc")
    if (
        not environment_setup
        and task.get("receipt_enabled")
        and task.get("receipt_manifest")
        and task.get("base_url")
        and receipt_verifier is not None
    ):
        allowed_tools.append("mcp__audit__start_receipt")

    kwargs = {
        "system_prompt": render(
            "system.md",
            {
                "receipt_protocol": (
                    "当前是环境准备阶段：不要提交 PoC。"
                    if environment_setup
                    else _receipt_protocol(task)
                ),
                "receipt_sections": "on" if not environment_setup and task.get("receipt_enabled") and task.get("receipt_manifest") else "off",
                "shell_protocol": (
                    "- 当前是环境准备阶段：可以使用 Bash 和 PowerShell，包括管道、重定向、包管理器安装和删除命令；只操作本次任务相关资源，不要修改导入源码或其他任务。"
                    if environment_setup
                    else "- 审计阶段可以使用 Bash，包括多行命令、管道和重定向；只访问本次靶场和本机，文件操作限于本次任务工作区及只读源码目录，不能修改源码或直接改写 PoC。"
                ),
                "project_execution_protocol": (
                    "- 当前是环境准备阶段：可以安装缺失的编译器和运行时，并在工作区检出、编译最新提交。不要执行 start.py 或 create-accounts.py，不要自行启动隔离测试实例；系统会在生成后自动测试。不可改写导入源码。最新提交无法建成时写入 environment/INITIALIZATION_FAILED.md 后结束，禁止改用旧镜像凑合。"
                    if environment_setup
                    else "- 不要执行上传项目中的构建、安装、启动、删除或网络扫描命令。"
                ),
                "network_protocol": (
                    "- 环境准备阶段可以联网搜索和获取资料，以确认依赖和配置。"
                    if environment_setup
                    else "- 联网搜索已经关闭。结论只来自导入源码和（如有）明确提供的靶场交互。"
                ),
            },
        ),
        "cwd": str(workspace),
        "add_dirs": [str(source_dir)],
        "model": task["model"],
        "permission_mode": "bypassPermissions",
        "tools": ["Read", "Grep", "Glob", "Bash", "Write", "Edit"] + (["PowerShell", "WebSearch", "WebFetch"] if environment_setup else []),
        "allowed_tools": allowed_tools,
        "mcp_servers": {
            "audit": build_audit_server(
                workspace,
                str(task.get("base_url") or ""),
                receipt_enabled=bool(task.get("receipt_enabled", False)) and bool(task.get("receipt_manifest")) and not environment_setup,
                verify_candidate=receipt_verifier,
            )
        },
        "disallowed_tools": (["WebBrowser", "NotebookEdit"] if environment_setup else ["WebSearch", "WebFetch", "WebBrowser", "PowerShell", "NotebookEdit"]),
        "strict_mcp_config": True,
        "resume": resume or None,
        "setting_sources": [],
        "include_partial_messages": True,
        "env": env,
        "stderr": on_stderr,
        "hooks": {
            "PreToolUse": [HookMatcher(hooks=[guard_tool])],
            "PostToolUse": [HookMatcher(hooks=[preserve_reports])],
            "PostToolUseFailure": [HookMatcher(hooks=[preserve_reports])],
            "PreCompact": [HookMatcher(hooks=[notify_compaction])],
        },
        "effort": "high",
    }
    accepted = inspect.signature(ClaudeAgentOptions).parameters
    filtered = {key: value for key, value in kwargs.items() if key in accepted}
    if "verbatim_prompts" in accepted:
        filtered["verbatim_prompts"] = True
    return ClaudeAgentOptions(**filtered)


def _message_text(block: object) -> str | None:
    text = getattr(block, "text", None)
    if isinstance(text, str) and text.strip():
        return text
    thinking = getattr(block, "thinking", None)
    if isinstance(thinking, str) and thinking.strip():
        return "思考\n" + thinking
    return None


def _apply_result(
    ledger: Ledger, message: object, prices: Prices, pending: UsageAccumulator, *, resumed: bool = False,
) -> tuple[bool, bool]:
    session_id = str(getattr(message, "session_id", "") or "")
    result_id = getattr(message, "uuid", None)
    if result_id and result_id in ledger.settled_result_ids:
        return False, True

    summary = summarize_model_usage(getattr(message, "model_usage", None), prices)
    if summary is not None and summary[0].total:
        reliable = ledger.settle_session(
            session_id, summary[0], prices, pending.session_tokens(session_id), resumed=resumed,
        )
    else:
        delta = tokens_from_usage(getattr(message, "usage", None))
        if not delta.total:
            return False, False
        ledger.settle_delta(session_id, delta, prices)
        reliable = True
    if result_id:
        ledger.settled_result_ids.add(result_id)
    return True, reliable


def _emit(store: Store, hub: Hub, task_id: str, kind: str, text: str, **extra: object) -> None:
    event = store.append_event(task_id, {"type": kind, "text": text, **extra})
    if event is not None:
        hub.publish(task_id, event)


def _emit_elapsed(store: Store, hub: Hub, task_id: str, text: str, elapsed: float, **extra: object) -> None:
    seconds = max(0, int(elapsed))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds_part = divmod(remainder, 60)
    _emit(store, hub, task_id, "status", f"{text}（累计有效时长 {hours:02d}:{minutes:02d}:{seconds_part:02d}）", elapsed_seconds=seconds, **extra)


def _finish(store: Store, hub: Hub, task_id: str, status: str, reason: str, message: str | None) -> None:
    task = store.get_task(task_id)
    if task is None:
        return
    counts = _artifact_counts(Path(task["workspace"]))
    store.update_task(
        task_id,
        status=status,
        stop_reason=reason,
        error=message,
        finished_at=now_iso(),
        artifact_counts=counts,
    )
    _emit(store, hub, task_id, "done", message or status, status=status, stop_reason=reason)


def _over_budget(task: dict, ledger: Ledger, estimate: float) -> bool:
    return ledger.spent + estimate >= float(task["budget"])


def _usage_snapshot(ledger: Ledger, pending: UsageAccumulator, prices: Prices) -> dict[str, float | int]:
    snapshot = ledger.snapshot()
    snapshot.update(ledger.persistence())
    snapshot["usage_pending"] = pending.persistence()
    estimated = pending.tokens
    snapshot["spent"] = float(snapshot["spent"]) + price_of(estimated, prices)
    snapshot["input_tokens"] = int(snapshot["input_tokens"]) + estimated.input
    snapshot["output_tokens"] = int(snapshot["output_tokens"]) + estimated.output
    snapshot["cache_read_tokens"] = int(snapshot["cache_read_tokens"]) + estimated.cache_read
    snapshot["cache_write_tokens"] = int(snapshot["cache_write_tokens"]) + estimated.cache_write
    return snapshot


def _usage_key(session_id: object, message_id: object) -> str:
    return f"{session_id or ''}\0{message_id or ''}"


async def _consume_run(
    client, store, hub, task, task_id, ledger, prices, api_key, workspace, pending, *,
    track_usage: bool = True, resumed_session_id: str | None = None,
):
    from claude_agent_sdk import AssistantMessage, ResultMessage, StreamEvent, UserMessage

    outcome = "error"
    last_usage_flush = 0.0
    setup_stream = not track_usage
    stream_characters = 0
    active_usage_keys: dict[tuple[str, str], str] = {}
    publish = lambda kind, text, **extra: _emit(store, hub, task_id, kind, _redact(text, api_key), **extra)

    def flush_usage(force: bool = False) -> dict[str, float | int]:
        nonlocal last_usage_flush
        snapshot = _usage_snapshot(ledger, pending, prices)
        now = time.monotonic()
        if force or now - last_usage_flush >= 1.0:
            store.update_task(task_id, artifact_counts=_artifact_counts(workspace), **snapshot)
            last_usage_flush = now
        return snapshot

    async for message in client.receive_response():
        if isinstance(message, StreamEvent):
            event = message.event
            event_type = event.get("type")
            if event_type == "message_start":
                stream_characters = 0
                hub.publish(task_id, {"type": "model_progress", "seq": 0, "ts": now_iso(), "text": "", "characters": 0})
            elif event_type == "content_block_delta":
                delta = event.get("delta") or {}
                chunk = delta.get("text") or delta.get("thinking") or delta.get("partial_json")
                if isinstance(chunk, str) and chunk:
                    stream_characters += len(chunk)
                    hub.publish(task_id, {"type": "model_progress", "seq": 0, "ts": now_iso(), "text": "", "characters": stream_characters})
            scope = (str(message.session_id or ""), str(message.parent_tool_use_id or ""))
            if event_type in {"message_start", "message_stop"}:
                active_usage_keys.pop(scope, None)
            if event_type == "message_start":
                message_id = (event.get("message") or {}).get("id")
                if message_id:
                    active_usage_keys[scope] = _usage_key(message.session_id, message_id)
            usage_key = active_usage_keys.get(scope)
            if track_usage and usage_key and pending.update_stream(usage_key, event):
                flush_usage()
                if _over_budget(task, ledger, price_of(pending.tokens, prices)):
                    request_stop(task_id, "budget")
        elif isinstance(message, AssistantMessage):
            hub.publish(task_id, {"type": "model_stream_end", "seq": 0, "ts": now_iso(), "text": ""})
            usage = getattr(message, "usage", None)
            if track_usage and usage:
                scope = (str(message.session_id or ""), str(message.parent_tool_use_id or ""))
                usage_key = _usage_key(message.session_id, message.message_id) if message.message_id else active_usage_keys.get(scope)
                if usage_key:
                    pending.update(usage_key, usage)
            if pending.calls:
                flush_usage(force=True)
                if _over_budget(task, ledger, price_of(pending.tokens, prices)):
                    request_stop(task_id, "budget")
            for block in message.content:
                tool_name = getattr(block, "name", None)
                tool_input = getattr(block, "input", None)
                if isinstance(tool_name, str) and isinstance(tool_input, dict):
                    publish("tool", tool_name + " " + _clip(json.dumps(tool_input, ensure_ascii=False), 1500))
                    continue
                text = _message_text(block)
                if text:
                    publish("text", _clip(text))
        elif isinstance(message, UserMessage):
            content = getattr(message, "content", "")
            if isinstance(content, str) and content.strip():
                publish("tool_result", _clip(content, 1500))
            elif isinstance(content, list):
                for block in content:
                    result = getattr(block, "content", None)
                    if isinstance(result, str) and result.strip():
                        publish("tool_result", _clip(result, 1500))
            if setup_stream:
                publish("model_wait", "正在等待模型响应")
        elif isinstance(message, ResultMessage):
            hub.publish(task_id, {"type": "model_stream_end", "seq": 0, "ts": now_iso(), "text": ""})
            resumed = bool(resumed_session_id and message.session_id == resumed_session_id)
            settled, reliable = _apply_result(ledger, message, prices, pending, resumed=resumed) if track_usage else (False, False)
            if settled:
                pending.clear_session(str(message.session_id or ""))
            counts = _artifact_counts(workspace)
            snapshot = _usage_snapshot(ledger, pending, prices)
            if track_usage:
                store.update_task(task_id, artifact_counts=counts, **snapshot)
            else:
                store.update_task(task_id, artifact_counts=counts)
            currency = task.get("currency") or "USD"
            if track_usage:
                label = "累计" if settled else "估算累计"
                publish(
                    "usage",
                    f"结算 {message.subtype}，{label} {snapshot['spent']:.4f} {currency}",
                    **snapshot,
                    subtype=message.subtype,
                )
                if settled and not reliable:
                    publish("status", "模型累计用量回退或缺少历史结算基准，本次按可核实用量计费，费用待核对。")
            else:
                publish("status", "环境准备阶段完成，本阶段用量不计入审计预算", subtype=message.subtype)
            if track_usage and message.session_id:
                store.update_task(task_id, session_id=message.session_id)
            detail = message.result or "、".join(message.errors or [])
            quota = getattr(message, "api_error_status", None) == 429 or (
                bool(message.is_error) and is_quota_signal(detail)
            )
            if quota:
                error_detail = _redact(_clip(detail or "模型商返回 429"), api_key)
                publish("error", error_detail)
                if not track_usage:
                    store.update_task(task_id, error=error_detail)
                outcome = "quota"
            elif message.subtype == "error_max_turns" and int(message.num_turns or 0) == 0:
                outcome = "stalled"
            elif message.subtype == "error_max_turns":
                outcome = "limit"
            elif message.is_error and message.subtype != "error_max_turns":
                error_detail = _redact(_clip(detail or message.subtype), api_key)
                publish("error", error_detail)
                if not track_usage:
                    store.update_task(task_id, error=error_detail)
                outcome = "error"
                if track_usage and message.subtype == "error_max_budget_usd":
                    request_stop(task_id, "budget")
            elif message.subtype == "success" and not message.is_error:
                outcome = "ok"
    return outcome


def _enter_quota_pause(clock: RunClock, store: Store, hub: Hub, task_id: str) -> None:
    current = store.get_task(task_id)
    if current is None:
        return
    if current["status"] in {"pause_requested", "cancel_requested", "cancelled", "completed", "budget_exhausted", "time_exhausted", "error"}:
        return
    clock.pause()
    if current["status"] == "paused" and current.get("paused_at"):
        return
    store.update_task(
        task_id,
        status="paused",
        pause_reason="quota",
        paused_at=now_iso(),
        error="模型商返回 429，计时已暂停，每分钟检查一次",
    )
    _emit_elapsed(store, hub, task_id, "模型商返回 429，计时已暂停，每分钟检查一次", clock.duration - clock.remaining(), status="paused", pause_reason="quota")


async def _sleep_until(stop: asyncio.Event, seconds: float) -> bool:
    remaining = float(seconds)
    while remaining > 0:
        if stop.is_set():
            return False
        step = min(1.0, remaining)
        await asyncio.sleep(step)
        remaining -= step
    return not stop.is_set()


async def _hold_initialization_for_quota(
    store: Store, hub: Hub, task_id: str, base_url: str, api_key: str,
    model: str, checkpoint: Callable[[], Awaitable[None]],
) -> bool:
    store.update_task(task_id, pause_reason="quota", error=None)
    _emit(store, hub, task_id, "status", f"模型商返回 429，等待额度恢复，每 {QUOTA_POLL_SECONDS} 秒检查一次")
    while True:
        remaining = float(QUOTA_POLL_SECONDS)
        while remaining > 0:
            await checkpoint()
            if stop_reason(task_id):
                return False
            step = min(1.0, remaining)
            await asyncio.sleep(step)
            remaining -= step
        await checkpoint()
        if stop_reason(task_id):
            return False
        result = await asyncio.to_thread(quota_probe, base_url, api_key, model)
        await checkpoint()
        if stop_reason(task_id):
            return False
        if result.get("ok"):
            store.update_task(task_id, pause_reason=None, error=None)
            _emit(store, hub, task_id, "status", "模型商已恢复，继续初始化")
            return True
        message = _redact(str(result.get("message") or "仍不可用"), api_key)
        _emit(store, hub, task_id, "status", f"模型商仍不可用（{message}），{QUOTA_POLL_SECONDS} 秒后再试")


async def _hold_for_quota(
    clock: RunClock,
    store: Store,
    hub: Hub,
    task_id: str,
    base_url: str,
    api_key: str,
    model: str,
    stop: asyncio.Event,
) -> bool:
    _enter_quota_pause(clock, store, hub, task_id)
    while not stop.is_set():
        if not await _sleep_until(stop, QUOTA_POLL_SECONDS):
            return False
        result = await asyncio.to_thread(quota_probe, base_url, api_key, model)
        if stop.is_set():
            return False
        if result.get("ok"):
            clock.resume()
            store.update_task(
                task_id,
                status="running",
                pause_reason=None,
                paused_at=None,
                paused_seconds=int(clock.paused_total),
                clock_checkpoint_at=now_iso(),
                error=None,
            )
            _emit(store, hub, task_id, "status", "模型商已恢复，继续审计并恢复计时")
            return True
        message = str(result.get("message") or "仍不可用")
        _emit(
            store,
            hub,
            task_id,
            "status",
            f"模型商仍不可用（{message}），{QUOTA_POLL_SECONDS} 秒后再试",
        )
    return False


def _settle_clock(clock: RunClock, store: Store, task_id: str, *, keep_paused_at: bool = False) -> None:
    if clock.pause_started is not None:
        clock.resume()
    fields: dict[str, object] = {"paused_seconds": int(clock.paused_total)}
    if not keep_paused_at:
        fields["paused_at"] = None
    store.update_task(task_id, **fields)


def _mark_paused(store: Store, hub: Hub, task_id: str, reason: str, elapsed: float | None = None) -> None:
    current = store.get_task(task_id)
    if current is None:
        return
    pause_reason = "restart" if reason == "restart" else "manual"
    message = "服务重启，任务已暂停并保留当前轮" if pause_reason == "restart" else "任务已暂停，可继续当前轮"
    if elapsed is None:
        elapsed = active_seconds(current)
    store.update_task(
        task_id,
        status="paused",
        pause_reason=pause_reason,
        paused_at=current.get("paused_at") or now_iso(),
        stop_reason=None,
        error=None,
        finished_at=None,
        artifact_counts=_artifact_counts(Path(current["workspace"])),
    )
    _emit_elapsed(store, hub, task_id, message, elapsed, status="paused", pause_reason=pause_reason)


def _environment_repair_prompt(checks: list[dict], detail: str) -> str:
    failed_ids = {str(item.get("id")) for item in checks if not item.get("ok")}
    guidance = [
        "先根据下方原始测试错误定位失败步骤，读取相关环境文件并核对实际配置，不要仅凭猜测重写环境。",
        "只修改与失败直接相关的环境文件，保持源码只读和既有隔离、清理、凭据保护契约；完成后结束本轮，由系统重新测试。",
    ]
    if failed_ids & {"receipt_manifest", "receipt_adapter", "receipt_run"}:
        guidance.append("清单或运行信息错误：对照错误和初始化契约检查对应 JSON 的字段、身份引用及实际端口；不要添加未允许的字段。")
    if "threat_coverage" in failed_ids:
        guidance.append("威胁模型格式或引用错误：核对 role-inventory.json、threat-decisions.json、account-plan.json 和清单的一致性；只根据源码及权限语义记录角色，不要依据自动猜测虚构角色。排除或无边界必须写明理由，不要把假设改写成 source。create-accounts.py 必须读取 account-plan.json。")
    if failed_ids & {"start_run", "health"}:
        guidance.append("启动或健康检查错误：先读取 Compose 的实际 command、服务监听地址和容器端口，核对源码启动方式、Adapter 和健康检查；出现地址绑定错误时，先逐字核对地址（例如 0.0.0.0 与 0.0.0.1），不要未经证据归因于 Docker 网络或增加权限。")
        guidance.append("健康检查不得要求受保护资源对匿名请求返回 200；认证质询可以是预期结果，应使用公开健康端点或在账号创建后验证受保护资源。不要为通过健康检查关闭官方要求的认证；使用 Basic 时在 Manifest 声明 browser_http_auth 为 basic，浏览器才能应答质询。")
        guidance.append("若失败来自最新提交无法编译：先安装缺失的编译器、运行时或系统库，再重试该提交的构建。该提交确实无法建成时，写入 environment/INITIALIZATION_FAILED.md 说明原因后结束。禁止改用更旧的发布镜像或残缺部署来通过健康检查。")
    if failed_ids & {"accounts_run", "accounts_verify"}:
        guidance.append("账号错误：核对账号脚本生成的身份、登录流程和权限验证，以及运行目录中实例数据的传递方式；不要输出凭据。")
    if "security_controls" in failed_ids or any(key.startswith("security_control_") for key in failed_ids):
        guidance.append("对照源码、官方政策和实际部署修复 security-controls.json 及环境配置；政策引用必须直接支持该控制，不能拿版本支持或报告要求冒充认证依据。先根据错误中的检查项、阶段、方法和路径核对接口、认证方式和状态码，不要删除适用控制或改弱预期来通过测试。写入测试必须核对状态变化并清理测试数据。")
    if "browser_auth_discovery" in failed_ids:
        guidance.append("入口页返回 Basic 质询时在 receipt-manifest.json 设置 browser_http_auth 为 basic，确保浏览器使用对应身份应答质询。")
    if "cleanup" in failed_ids:
        guidance.append("清理错误：核对清理命令仅针对当前 Compose 项目和运行目录，并可重复执行。")
    if "docker" in failed_ids:
        guidance.append("Docker 检查错误：先判断错误是否来自 Docker 服务本身；缺少证据时不要假设修改项目文件能修复外部环境。")
    return "环境自动测试失败，请按以下步骤排查并修复：\n" + "\n".join(f"- {item}" for item in guidance) + "\n\n原始测试结果：\n" + detail


async def _prepare_environment(task_id: str, store: Store, hub: Hub) -> bool:
    """Run the mandatory setup turn without adding its model usage to the audit ledger."""
    task = store.get_task(task_id)
    if task is None:
        return False
    async def checkpoint() -> None:
        callback = getattr(store, "checkpoint", None) if task_id.startswith("project:") else None
        if callback is not None:
            await callback(task_id)

    async def watch_initialization_control(client, interrupted: asyncio.Event, owner: asyncio.Task) -> None:
        while True:
            await asyncio.sleep(0.2)
            current = store.get_task(task_id) or {}
            if current.get("status") not in {"pause_requested", "stop_requested"}:
                continue
            interrupted.set()
            interrupt = getattr(client, "interrupt", None)
            if interrupt is not None:
                try:
                    await asyncio.wait_for(interrupt(), timeout=2)
                except Exception:
                    pass
            await asyncio.sleep(2)
            if not owner.done():
                owner.cancel()
            return

    await checkpoint()
    if task_id.startswith("project:"):
        workspace = Path(task["workspace"])
        if not _source_dir(task).is_dir():
            raise RuntimeError("导入的项目源码目录不存在")
        (workspace / "environment").mkdir(parents=True, exist_ok=True)
        _copy_security_policy(_source_dir(task), workspace)
    else:
        workspace = prepare_workspace(task)
    provider = store.get_provider(task["provider_id"])
    if provider is None:
        store.update_task(task_id, status="draft", environment_status="failed", error="模型商已被删除")
        return False

    store.update_task(task_id, status="preparing", environment_status="preparing", error=None)
    _emit(store, hub, task_id, "status", "正在准备项目运行环境；此阶段用量不计入审计预算")
    api_key = provider.get("api_key") or ""
    failure_file = workspace / "environment" / "INITIALIZATION_FAILED.md"
    failure_file.unlink(missing_ok=True)
    checks: list[dict] = []
    failure_history: list[str] = []
    loop = asyncio.get_running_loop()
    quota_state = {"hit": False, "active": False, "client": None}

    def failed(reason: str) -> bool:
        reason = _redact(reason, api_key)
        failure_file.write_text("# 初始化失败\n\n" + reason + "\n", encoding="utf-8")
        store.update_task(task_id, status="draft", environment_status="failed", environment_ready=False, error=reason, checks=checks)
        _emit(store, hub, task_id, "error", reason)
        return False

    def on_stderr(line: str) -> None:
        text = _redact((line or "").strip(), api_key)
        if text:
            _emit(store, hub, task_id, "stderr", _clip(text, 2000))
            if is_quota_signal(text):
                def interrupt_for_quota() -> None:
                    if quota_state["hit"] or not quota_state["active"]:
                        return
                    quota_state["hit"] = True
                    interrupt = getattr(quota_state["client"], "interrupt", None)
                    if interrupt is not None:
                        async def interrupt_safely() -> None:
                            try:
                                await interrupt()
                            except Exception:
                                pass
                        asyncio.create_task(interrupt_safely())
                loop.call_soon_threadsafe(interrupt_for_quota)

    try:
        from claude_agent_sdk import ClaudeSDKClient

        options = _build_options(
            task,
            workspace,
            api_key,
            (provider.get("base_url") or "").strip(),
            on_stderr,
            environment_setup=True,
            proxy_settings=store.get_proxy_settings(),
            on_compact=lambda: _emit(store, hub, task_id, "status", "上下文压缩已触发，正在压缩…"),
        )
        async with AsyncExitStack() as clients:
            client = await clients.enter_async_context(ClaudeSDKClient(options=options))
            prompt = render("prepare-environment.md", {}) + f"\n\n项目名称：{task.get('project_name', '')}\n导入源码绝对路径：{_source_dir(task)}\n工作区绝对路径：{workspace}"
            if _security_policy_path(_source_dir(task)):
                prompt += "\n目标项目安全政策已复制到工作区 SECURITY.md（索引）和 security-policy/。请先阅读索引和其中的全部副本。"
            else:
                prompt += "\n目标项目常见位置未发现 SECURITY.md；不要将工作区旧文件视为本项目政策。"
            if task.get("instruction"):
                prompt += "\n\n用户补充要求：\n" + task["instruction"]
            if task.get("resume_existing"):
                prompt += "\n\n这是一次中断后继续的初始化。请先检查工作区已有文件和日志，保留已完成的工作，从现有材料继续完成初始化与测试。"
            initial_prompt = prompt
            for attempt in range(6):
                await checkpoint()
                _emit(store, hub, task_id, "model_wait", "正在等待模型响应")
                query_prompt = prompt
                while True:
                    quota_state.update(hit=False, active=True, client=client)
                    interrupted = asyncio.Event()
                    owner = asyncio.current_task()
                    watcher = (asyncio.create_task(watch_initialization_control(client, interrupted, owner))
                               if task_id.startswith("project:") and owner else None)
                    try:
                        await client.query(query_prompt)
                        outcome = await _consume_run(
                            client, store, hub, task, task_id, Ledger.from_snapshot(task),
                            Prices.from_mapping(task["prices"]), api_key, workspace,
                            UsageAccumulator(), track_usage=False,
                        )
                    except Exception as exc:
                        if interrupted.is_set():
                            outcome = "interrupted"
                        elif not is_quota_signal(exc) and not quota_state["hit"]:
                            raise
                        else:
                            outcome = "quota"
                    finally:
                        quota_state["active"] = False
                        if watcher:
                            watcher.cancel()
                            await asyncio.gather(watcher, return_exceptions=True)
                    if interrupted.is_set():
                        await clients.aclose()
                        await checkpoint()
                        client = await clients.enter_async_context(ClaudeSDKClient(options=options))
                        query_prompt = initial_prompt + "\n\n" + prompt if attempt else prompt
                        continue
                    if quota_state["hit"]:
                        outcome = "quota"
                    if outcome != "quota":
                        break
                    await clients.aclose()
                    if not await _hold_initialization_for_quota(
                        store, hub, task_id, (provider.get("base_url") or "").strip(),
                        api_key, str(task.get("model") or ""), checkpoint,
                    ):
                        return False
                    client = await clients.enter_async_context(ClaudeSDKClient(options=options))
                    if attempt:
                        query_prompt = initial_prompt + "\n\n" + prompt
                await checkpoint()
                if outcome not in {"ok", "limit"}:
                    current = store.get_task(task_id) or {}
                    reason = current.get("error") or "环境准备 Agent 未能完成"
                    return failed(f"环境准备 Agent 未能完成：{reason}" if reason != "环境准备 Agent 未能完成" else reason)
                reported = failure_file.read_text(encoding="utf-8").strip() if failure_file.is_file() else ""
                if reported:
                    return failed(reported)
                _emit(store, hub, task_id, "status", f"正在执行环境和账号测试（第 {attempt + 1} 次）")
                checks = await test_environment(
                    workspace,
                    on_output=lambda line: _emit(store, hub, task_id, 'status', _redact(line, api_key)),
                    source_dir=_source_dir(task),
                )
                await checkpoint()
                errors = [str(item["message"]) for item in checks if not item["ok"]]
                if not errors:
                    if not task_id.startswith("project:"):
                        receipt_dir = workspace / "receipt"
                        receipt_dir.mkdir(parents=True, exist_ok=True)
                        (workspace / "environment" / "receipt-manifest.json").replace(receipt_dir / f"initialization-manifest-{time.time_ns()}.json")
                    coverage = next((item for item in checks if item.get("id") == "threat_coverage"), {})
                    store.update_task(
                        task_id,
                        status="queued" if task.get("preparation_mode") == "audit" else "draft",
                        environment_ready=False,
                        environment_status="ready" if task_id.startswith("project:") else "pending",
                        preparation_mode=None,
                        error=None,
                        checks=checks,
                        coverage_status=coverage.get("coverage_status", ""),
                        threat_model_digest=coverage.get("digest", ""),
                        threat_model_review=coverage.get("review_items", []),
                    )
                    _emit(store, hub, task_id, "status", "环境与账号测试通过，测试环境已清理")
                    return True
                detail = _redact("\n".join(errors), api_key)
                failure_history.append(f"第 {attempt + 1} 次测试：\n{detail}")
                if attempt == 5:
                    return failed("环境测试失败，已达到最多 5 次修改：\n\n" + "\n\n".join(failure_history))
                _emit(store, hub, task_id, "status", f"环境测试失败，正在交由初始化 Agent 修改（第 {attempt + 1}/5 次）：{detail}")
                prompt = _environment_repair_prompt(checks, detail)
    except asyncio.CancelledError:
        raise
    except InitializationStopped:
        raise
    except Exception as exc:
        if task_id.startswith("project:") and (store.get_task(task_id) or {}).get("status") == "stop_requested":
            raise InitializationStopped() from exc
        detail = _redact("".join(traceback.format_exception_only(type(exc), exc)).strip(), api_key)
        return failed(detail or "环境准备失败")
    return False


async def _audit(task_id: str, store: Store, hub: Hub) -> None:
    task = store.get_task(task_id)
    if task is None:
        return
    if task.get("github_change_counts") is not None:
        (Path(task["workspace"]) / "github-changes.json").unlink(missing_ok=True)
    if task["status"] == "cancel_requested":
        _finish(store, hub, task_id, "cancelled", "cancelled", "本轮审计已停止")
        return
    if task["status"] == "pause_requested":
        _mark_paused(store, hub, task_id, str(task.get("pause_reason") or "manual"))
        return

    provider = store.get_provider(task["provider_id"])
    if provider is None:
        _finish(store, hub, task_id, "error", "error", "模型商已被删除")
        return

    workspace = prepare_workspace(task)
    resuming = bool(task.get("started_at"))
    task = store.start_running_clock(task_id)
    if task is None:
        return
    if task["status"] == "pause_requested":
        _mark_paused(store, hub, task_id, str(task.get("pause_reason") or "manual"))
        return
    if task["status"] == "cancel_requested":
        _finish(store, hub, task_id, "cancelled", "cancelled", "本轮审计已停止")
        return
    if task["status"] != "running":
        return
    start_message = "任务继续，恢复当前轮" if resuming else "任务开始，工作区已隔离"
    _emit(store, hub, task_id, "status", start_message)

    prices = Prices.from_mapping(task["prices"])
    ledger = Ledger.from_snapshot(task)
    clock = RunClock(
        int(task["duration_seconds"]),
        elapsed=active_seconds(task),
        paused_total=float(task.get("paused_seconds") or 0),
    )
    api_key = provider.get("api_key") or ""
    base_url = (provider.get("base_url") or "").strip()
    model_name = str(task.get("model") or "")
    loop = asyncio.get_running_loop()
    stop = _STOPS[task_id]
    state = {"active": False, "client": None, "quota": False}
    pending = UsageAccumulator.from_snapshot(task.get("usage_pending"))
    consecutive_guard = ConsecutiveToolGuard(
        task.get("last_tool_fingerprint"),
        lambda fingerprint: store.update_task(task_id, last_tool_fingerprint=fingerprint),
    )
    session_id = str(task.get("session_id") or "") or None
    resume_note = session_id is not None
    round_number = int(task.get("round") or 0)
    agent_completion = task.get("completion_mode") == "agent" or task.get("pending_review_reports") is not None
    active_round = None if task.get("follow_up_new_round") else ((round_number or None) if agent_completion else _restored_active_round(workspace, round_number))
    if task.get("follow_up_new_round"):
        store.update_task(task_id, follow_up_new_round=False)
    summary_round: int | None = None

    async def quiet_interrupt(interrupt) -> None:
        try:
            await interrupt()
        except Exception:
            return

    verified_poc_ids: set[str] = set()

    async def verify_submitted_receipt_candidate(poc_id: str, report_path: str = "") -> Mapping[str, str]:
        verified_poc_ids.add(poc_id)
        if report_path:
            record_verification_attempt(workspace, report_path, poc_id)
        """在 MCP 调用内同步执行可信验证，并只回传不含路径信息的结果。"""

        current = store.get_task(task_id)
        manifest_name = "" if current is None else str(current.get("receipt_manifest") or "")
        if not manifest_name:
            return receipt_failure_feedback(poc_id, "INDETERMINATE", "VERIFICATION_UNAVAILABLE")
        _emit(store, hub, task_id, "receipt", f"RECEIPT 正在同步验证 PoC {poc_id}")
        from app.receipt_selector import describe_selected_paths, select_receipt_paths

        def account_selector_usage(message: object) -> None:
            _apply_result(ledger, message, prices, UsageAccumulator())
            store.update_task(task_id, **_usage_snapshot(ledger, pending, prices))

        preferred = await select_receipt_paths(
            workspace, str(current.get("base_url") or ""), manifest_name, poc_id,
            report_path, task, provider, on_result=account_selector_usage,
        )
        if preferred:
            for description in describe_selected_paths(manifest_name, preferred):
                _emit(store, hub, task_id, "receipt", f"RECEIPT {poc_id} 选择的验证路径：{description}")
        else:
            _emit(store, hub, task_id, "receipt", f"RECEIPT {poc_id} 无法选择验证路径，本次不执行验证")
        def on_path_complete(completed: int, total: int) -> None:
            loop.call_soon_threadsafe(
                _emit, store, hub, task_id, "receipt",
                f"RECEIPT 已完成 {poc_id} 的 {completed}/{total} 条验证路径",
            )
        try:
            execution = await asyncio.to_thread(
                verify_receipt_candidate,
                workspace,
                str(current.get("base_url") or ""),
                manifest_name,
                poc_id,
                runtime_config=receipt_runtime_config(store.get_receipt_settings()),
                on_path_complete=on_path_complete,
                preferred_path_ids=preferred,
            )
        except ReceiptExecutionError as exc:
            feedback = receipt_failure_feedback(poc_id, "INDETERMINATE", exc.reason)
            if exc.detail:
                feedback["reason_description"] += " " + exc.detail
        except ReceiptError as exc:
            from app import receipt_diagnostics as diagnostics
            tokens = diagnostics.begin(workspace)
            try:
                diagnostics.record("runner", error=f"{type(exc).__name__}: {exc}", poc_id=poc_id)
            finally:
                diagnostics.end(tokens)
            feedback: Mapping[str, str] = receipt_failure_feedback(poc_id, "INDETERMINATE", "VERIFICATION_UNAVAILABLE")
        except Exception as exc:
            from app import receipt_diagnostics as diagnostics
            tokens = diagnostics.begin(workspace)
            try:
                diagnostics.record("runner", error=f"{type(exc).__name__}: {exc}", poc_id=poc_id)
            finally:
                diagnostics.end(tokens)
            feedback = receipt_failure_feedback(poc_id, "INDETERMINATE", "VERIFICATION_INFRASTRUCTURE_ERROR")
            feedback["reason_description"] += f" Exception type: {type(exc).__name__}; see receipt/diagnostics.jsonl."
        else:
            feedback = execution.agent_feedback
        _emit(
            store,
            hub,
            task_id,
            "receipt",
            "RECEIPT 同步结果："
            + json.dumps(dict(feedback), ensure_ascii=False, separators=(",", ":")),
        )
        return feedback

    def note_quota() -> None:
        if state["quota"] or stop.is_set():
            return
        state["quota"] = True
        _enter_quota_pause(clock, store, hub, task_id)
        client = state["client"]
        if state["active"] and client is not None:
            interrupt = getattr(client, "interrupt", None)
            if interrupt is not None:
                asyncio.create_task(quiet_interrupt(interrupt))

    def on_stderr(line: str) -> None:
        text = _redact((line or "").strip(), api_key)
        if not text:
            return
        clipped = _clip(text, 2000)
        try:
            loop.call_soon_threadsafe(lambda payload=clipped: _emit(store, hub, task_id, "stderr", payload))
            if is_quota_signal(text):
                loop.call_soon_threadsafe(note_quota)
        except RuntimeError:
            return

    async def watch() -> None:
        next_checkpoint = time.monotonic() + CLOCK_CHECKPOINT_SECONDS
        while not stop.is_set():
            if clock.expired():
                request_stop(task_id, "time")
                break
            if _over_budget(task, ledger, price_of(pending.tokens, prices)):
                request_stop(task_id, "budget")
                break
            if time.monotonic() >= next_checkpoint:
                store.checkpoint_running_clock(task_id)
                next_checkpoint = time.monotonic() + CLOCK_CHECKPOINT_SECONDS
            await asyncio.sleep(0.5)
        reason = stop_reason(task_id)
        client = state["client"]
        if reason in {"time", "cancelled", "budget", "paused", "restart"} and state["active"] and client is not None:
            interrupt = getattr(client, "interrupt", None)
            if interrupt is not None:
                try:
                    await interrupt()
                except Exception:
                    return

    watcher = asyncio.create_task(watch())
    failures = 0
    sessions = 0
    receipt_followup: str | None = None
    receipt_followup_attempts = 0
    try:
        from claude_agent_sdk import ClaudeSDKClient

        while not stop.is_set() and sessions < 3:
            sessions += 1
            quota_hit = False
            options = _build_options(
                task,
                workspace,
                api_key,
                base_url,
                on_stderr,
                resume=session_id,
                receipt_verifier=verify_submitted_receipt_candidate,
                consecutive_tool_guard=consecutive_guard,
                on_compact=lambda: _emit(store, hub, task_id, "status", "上下文压缩已触发，正在压缩…"),
            )
            try:
                async with ClaudeSDKClient(options=options) as client:
                    state["client"] = client
                    resumed_session_id = session_id
                    while not stop.is_set():
                        if _over_budget(task, ledger, price_of(pending.tokens, prices)):
                            request_stop(task_id, "budget")
                            break
                        if clock.expired():
                            request_stop(task_id, "time")
                            break
                        if receipt_followup is not None:
                            prompt = receipt_followup
                            receipt_followup = None
                        elif summary_round is not None:
                            prompt = _summary_prompt(workspace, summary_round)
                        else:
                            prepare_workspace(store.get_task(task_id) or task)
                            if active_round is None:
                                round_number += 1
                                active_round = round_number
                                store.update_task(task_id, round=round_number)
                                _emit(
                                    store,
                                    hub,
                                    task_id,
                                    "round",
                                    f"第 {round_number} 轮",
                                    round=round_number,
                                )
                                resume_note = round_number > 1 or session_id is not None
                            prompt = _audit_prompt(
                                task,
                                workspace,
                                ledger,
                                clock.remaining(),
                                active_round,
                                resume_note,
                            )
                            resume_note = False
                        state["quota"] = False
                        state["active"] = True
                        reports_before_query = _snapshot_reports(workspace)
                        try:
                            await client.query(prompt)
                            outcome = await _consume_run(
                                client, store, hub, task, task_id, ledger, prices, api_key, workspace, pending,
                                resumed_session_id=resumed_session_id,
                            )
                            resumed_session_id = None
                        except Exception as exc:
                            if is_quota_signal(exc) or state["quota"]:
                                outcome = "quota"
                            else:
                                raise
                        finally:
                            state["active"] = False
                            restored = _restore_missing_reports(workspace, reports_before_query)
                            if restored:
                                _emit(store, hub, task_id, "status", "禁止撤回报告，系统已恢复：" + ", ".join(restored))
                        if state["quota"] or outcome == "quota":
                            quota_hit = True
                            break
                        if outcome == "stalled":
                            failures += 1
                            break
                        if outcome == "limit" and not stop.is_set():
                            resume_note = True
                            message = "继续补写本轮总结" if summary_round is not None else "同一轮继续审计"
                            _emit(store, hub, task_id, "status", message)
                            continue
                        if outcome == "error":
                            if stop.is_set():
                                break
                            failures += 1
                            if failures >= 3:
                                request_stop(task_id, "error")
                                store.update_task(task_id, error="连续三次未能继续，已停止")
                            else:
                                await asyncio.sleep(2)
                                resume_note = True
                            continue
                        failures = 0
                        if outcome == "ok" and not stop.is_set() and task.get("receipt_enabled"):
                            closed = close_unresolved_reviews(workspace)
                            required_reports = {
                                report.path for report in list_reports(workspace, True)
                                if report.path in (task.get("pending_review_reports") or [])
                                and report.poc_id not in verified_poc_ids
                                and report.review_status != "audit_failed"
                            }
                            feedback = await _verify_pending_reports(
                                workspace,
                                str((store.get_task(task_id) or task).get("base_url") or ""),
                                verify_submitted_receipt_candidate,
                                required_reports,
                            )
                            closed.extend(close_unresolved_reviews(workspace))
                            if closed:
                                _emit(store, hub, task_id, "status", "以下报告已提交验证至少三次，标记为审计不通过：" + ", ".join(closed))
                            if feedback is not None and closed and not _reports_needing_verification(
                                workspace, task.get("pending_review_reports"), verified_poc_ids,
                            ):
                                feedback = None
                            if feedback is not None:
                                receipt_followup_attempts += 1
                                if receipt_followup_attempts > 5:
                                    store.update_task(task_id, error="待验证报告连续五次未完成 RECEIPT 验证")
                                    _emit(store, hub, task_id, "error", "待验证报告连续五次未完成 RECEIPT 验证，请检查候选项与报告")
                                    request_stop(task_id, "error")
                                    break
                                receipt_followup = feedback
                                _emit(store, hub, task_id, "status", "待验证报告已检查，继续处理 RECEIPT 结果")
                                continue
                            receipt_followup_attempts = 0
                        if agent_completion and outcome == "ok" and not stop.is_set():
                            completed_round = summary_round or active_round
                            if completed_round is not None and _round_summary_ready(workspace, completed_round):
                                _emit_elapsed(
                                    store,
                                    hub,
                                    task_id,
                                    f"第 {completed_round} 轮总结已落盘，代理结束审计",
                                    clock.duration - clock.remaining(),
                                    round=completed_round,
                                )
                                request_stop(task_id, "completed")
                                break
                            if completed_round is not None:
                                summary_round = completed_round
                                _emit(
                                    store,
                                    hub,
                                    task_id,
                                    "status",
                                    f"第 {completed_round} 轮已结束但总结缺失，先要求补写",
                                )
                                continue
                        if summary_round is not None:
                            if _round_summary_ready(workspace, summary_round):
                                _emit_elapsed(
                                    store,
                                    hub,
                                    task_id,
                                    f"第 {summary_round} 轮总结已落盘，开始下一轮",
                                    clock.duration - clock.remaining(),
                                    round=summary_round,
                                )
                                summary_round = None
                                active_round = None
                            elif not stop.is_set():
                                _emit(
                                    store,
                                    hub,
                                    task_id,
                                    "status",
                                    f"第 {summary_round} 轮总结仍未落盘，继续要求补写",
                                )
                            continue
                        if active_round is not None and _round_summary_ready(workspace, active_round):
                            _emit_elapsed(
                                store,
                                hub,
                                task_id,
                                f"第 {active_round} 轮结束，总结已落盘",
                                clock.duration - clock.remaining(),
                                round=active_round,
                            )
                            active_round = None
                        elif active_round is not None and not stop.is_set():
                            summary_round = active_round
                            _emit(
                                store,
                                hub,
                                task_id,
                                "status",
                                f"第 {active_round} 轮已结束但总结缺失，先要求补写",
                            )
                        continue
                    state["client"] = None
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                state["client"] = None
                state["active"] = False
                if is_quota_signal(exc) or state["quota"]:
                    quota_hit = True
                elif session_id:
                    session_id = None
                    sessions -= 1
                    resume_note = False
                    _emit(store, hub, task_id, "status", "原会话无法接上，已另开会话接着审计")
                    continue
                else:
                    raise
            if quota_hit and not stop.is_set():
                sessions -= 1
                resume_note = True
                latest = store.get_task(task_id)
                if latest and latest.get("session_id"):
                    session_id = str(latest["session_id"])
                if not await _hold_for_quota(clock, store, hub, task_id, base_url, api_key, model_name, stop):
                    break
                continue
            if stop.is_set() or failures >= 3:
                break
            if failures and not stop.is_set():
                resume_note = bool(session_id)
                _emit(store, hub, task_id, "status", "上一会话无法继续，已另开会话接着审计")
                continue
            break
        if failures >= 2 and not stop.is_set():
            request_stop(task_id, "error")
            store.update_task(task_id, error="会话无法继续审计")
    except asyncio.CancelledError:
        current = store.get_task(task_id)
        if current is not None:
            store.update_task(
                task_id,
                status="pause_requested",
                pause_reason="restart",
                paused_at=current.get("paused_at") or now_iso(),
            )
        request_stop(task_id, "restart")
        raise
    except Exception as exc:
        detail = _redact("".join(traceback.format_exception_only(type(exc), exc)).strip(), api_key)
        store.update_task(task_id, error=detail or "审计进程失败")
        _emit(store, hub, task_id, "error", detail or "审计进程失败")
        request_stop(task_id, "error")
    finally:
        watcher.cancel()
        state["active"] = False
        reason = stop_reason(task_id) or "error"
        if reason in {"paused", "restart"}:
            current = store.get_task(task_id)
            elapsed = active_seconds(current) if current else 0.0
            _settle_clock(clock, store, task_id, keep_paused_at=True)
            _mark_paused(store, hub, task_id, reason, elapsed)
            return
        _settle_clock(clock, store, task_id)
        status = {
            "budget": "budget_exhausted",
            "time": "time_exhausted",
            "cancelled": "cancelled",
            "completed": "completed",
            "error": "error",
        }.get(reason, "error")
        latest = store.get_task(task_id)
        message = None if latest is None else latest.get("error")
        if reason == "budget":
            message = "预算已用完"
        elif reason == "time":
            message = "时长已用完"
        elif reason == "cancelled":
            message = "已取消"
        elif reason == "completed":
            message = "代理已结束本次审计"
        _finish(store, hub, task_id, status, reason, message)


async def _stop_finished_environment(task_id: str, store: Store, hub: Hub) -> None:
    current = store.get_task(task_id)
    if not current or not current.get("environment_run_id") or current["status"] not in {"completed", "budget_exhausted", "time_exhausted", "cancelled", "error"}:
        return
    _emit(store, hub, task_id, "status", "审计已结束，正在停止靶场环境")
    try:
        ok, detail = await stop_audit_environment(current)
    except Exception as exc:
        ok, detail = False, str(exc)
    if ok:
        store.update_task(task_id, environment_ready=False, environment_status="stopped")
        _emit(store, hub, task_id, "status", "靶场环境已停止")
    else:
        message = f"停止靶场环境失败：{detail}"
        previous = current.get("error")
        store.update_task(task_id, environment_status="cleanup_failed", error=f"{previous}；{message}" if previous else message)
        _emit(store, hub, task_id, "error", message)


async def run_task(task_id: str, store: Store, hub: Hub) -> None:
    register_stop(task_id)
    try:
        async with _LIMITER:
            current = store.get_task(task_id)
            if current is None or current["status"] in {"cancelled", "error", "paused"}:
                return
            if current["status"] == "cancel_requested":
                _finish(store, hub, task_id, "cancelled", "cancelled", "本轮审计已停止")
                await _stop_finished_environment(task_id, store, hub)
                return
            if current["status"] == "pause_requested":
                _mark_paused(store, hub, task_id, str(current.get("pause_reason") or "manual"))
                return
            if current.get("receipt_enabled"):
                config_errors = receipt_configuration_errors(receipt_runtime_config(store.get_receipt_settings()))
                if config_errors:
                    reason = "RECEIPT 配置不可用：" + "；".join(config_errors)
                    store.update_task(task_id, status="draft", error=reason)
                    _emit(store, hub, task_id, "error", reason)
                    return
            if current.get("automatic_environment") and not current.get("environment_ready"):
                _emit(store, hub, task_id, "status", "正在启动环境并验证账号")
                try:
                    current = await start_audit_environment(current, store)
                    prepare_workspace(current)
                    _emit(store, hub, task_id, "status", "环境和账号验证通过，开始审计")
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    reason = f"环境启动失败：{exc}"
                    store.update_task(task_id, status="draft", environment_status="failed", environment_ready=False, error=reason)
                    _emit(store, hub, task_id, "error", reason)
                    return
            if current.get("requires_environment_setup", False) and not current.get("environment_ready"):
                store.update_task(task_id, preparation_mode="audit")
                if not await _prepare_environment(task_id, store, hub):
                    return
            await _audit(task_id, store, hub)
            await _stop_finished_environment(task_id, store, hub)
    finally:
        clear_stop(task_id)
