from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Annotated, Any

from app.poccheck import PocValidationError, commit_poc
from app.receipt import ReceiptError, load_receipt_candidate, prepare_receipt_candidate, write_receipt_candidate
from app.receipt_execution import receipt_failure_feedback
from app.reports import _FINDING_PATH, clear_review_for_poc, save_review

_DESCRIPTION = (
    "提交一个符合统一格式的 XSS PoC。检查通过后才写入 poc/<poc_id>.py。"
    "不要用 Write 或 Edit 修改 poc 目录。"
)

_RECEIPT_DESCRIPTION = (
    "登记一条 RECEIPT 候选项。检查通过后才写入文件：有攻击者脚本时写入 poc/<poc_id>.py，"
    "并始终把脚本正文快照写入 receipt/candidates/<poc_id>.json。无攻击者写入步骤时 source 留空，不写 py 文件。"
    "不要用 Write、Edit 或重定向修改 poc/ 或 receipt/。登记后调用 start_receipt 验证这一条。"
    "需要登录时在 attacker_login_json 声明步骤，不要在脚本里用 ctx.username 或 ctx.password 登录。"
    "目标需要回连时，在 callback_json 声明静态路由，脚本只读取 ctx.callback_origin，不要写主机名或自己监听。"
    '必须提供 victim_json，内容是描述实际受害者访问路径和动作的 JSON 字符串，例如 {"url":"/view","actions":[]}；'
    "有攻击者步骤时 source 必须是完整脚本，不能使用 placeholder。旧版批量提交接口已停用。"
)


def _load_json(value: Any, name: str) -> Any:
    if isinstance(value, str):
        if not value.strip():
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise ReceiptError(f"{name} 不是合法 JSON") from exc
    return value


def _register_receipt_poc(workspace: Path, base_url: str, args: dict) -> str:
    if not args.get("victim_json"):
        raise ReceiptError('缺少 victim_json：请传入描述实际受害者访问路径和动作的 JSON 字符串，例如 "{\\"url\\":\\"/view\\",\\"actions\\":[]}"；不要使用占位数据。')
    victim = _load_json(args.get("victim_json"), "victim_json")
    if not isinstance(victim, dict):
        raise ReceiptError("victim_json 必须是 JSON 对象")
    attacker_login = _load_json(args.get("attacker_login_json"), "attacker_login_json")
    if attacker_login is not None and not isinstance(attacker_login, list):
        raise ReceiptError("attacker_login_json 必须是 JSON 数组")
    auth_headers = _load_json(args.get("attacker_auth_headers_json"), "attacker_auth_headers_json")
    if auth_headers is not None and not isinstance(auth_headers, list):
        raise ReceiptError("attacker_auth_headers_json 必须是 JSON 数组")
    claim = _load_json(args.get("claim_json"), "claim_json")
    if claim is not None and not isinstance(claim, dict):
        raise ReceiptError("claim_json 必须是 JSON 对象")
    callback = _load_json(args.get("callback_json"), "callback_json")
    if callback is not None and not isinstance(callback, dict):
        raise ReceiptError("callback_json 必须是 JSON 对象")
    source = str(args.get("source") or "")
    if source.strip().lower() == "placeholder":
        raise ReceiptError("source 不能是 placeholder：有攻击者写入步骤时提交完整 Python 脚本；没有攻击者步骤时传空字符串。")
    raw: dict[str, Any] = {
        "poc_id": str(args.get("poc_id") or ""),
        "marker": str(args.get("marker") or ""),
        "attacker_script": source,
        "victim": victim,
    }
    if attacker_login is not None:
        raw["attacker_login"] = attacker_login
    if auth_headers is not None:
        raw["attacker_auth_headers"] = auth_headers
    if claim is not None:
        raw["claim"] = claim
    if callback is not None:
        raw["callback"] = callback
    candidate = prepare_receipt_candidate(workspace, base_url, raw)
    if candidate.attacker_script:
        commit_poc(workspace, base_url, candidate.poc_id, candidate.marker, candidate.attacker_script)
    write_receipt_candidate(workspace, candidate)
    cleared = clear_review_for_poc(workspace, candidate.poc_id)
    lines = []
    if candidate.attacker_script:
        lines.append(f"已写入 poc/{candidate.poc_id}.py")
        lines.append(f"可直接运行：python poc/{candidate.poc_id}.py")
    lines.append(f"已写入 receipt/candidates/{candidate.poc_id}.json")
    if cleared:
        lines.append("已有验证结论已改回待验证。")
    lines.append("请调用 start_receipt 验证这一条，并传入对应的 findings/<文件名>.md。")
    return "\n".join(lines)


def build_submit_poc(workspace: Path, base_url: str, *, receipt_enabled: bool = False):
    from claude_agent_sdk import tool

    schema: dict[str, Any] = {
        "poc_id": Annotated[str, "三位序号加英文短名，例如 001-finder-query。必须与脚本中的 poc_id 相同"],
        "marker": Annotated[str, "无害标记，例如 xss001finder。必须与脚本中的 marker 相同，不能包含网址或读取浏览器数据的代码"],
        "source": Annotated[
            str,
            "完整 Python 源码。启用 RECEIPT 且没有攻击者写入步骤时留空" if receipt_enabled else "完整 Python 源码。必须 from poclib import Poc，并按 ARTIFACTS.md 的模板调用 ctx.request 和 ctx.expect",
        ],
    }
    if receipt_enabled:
        schema["victim_json"] = Annotated[str, 'JSON 对象，包含 url，以及可选的 actions 和 login。例如 {"url":"/view?value={{receipt_token}}","actions":[]}']
        schema["attacker_login_json"] = Annotated[str, "可选。JSON 数组，攻击者登录步骤。不需要登录时留空"]
        schema["attacker_auth_headers_json"] = Annotated[str, '可选。JSON 数组，声明登录后浏览器存储到请求头的映射，例如 [{"source":"localStorage","key":"stirling_jwt","header":"Authorization","prefix":"Bearer "}]；不填实际令牌。']
        schema["claim_json"] = Annotated[str, '可选。JSON 对象，只能含 finding_type 和 note。留空表示省略']
        schema["callback_json"] = Annotated[str, '可选。JSON 对象，声明静态回连路由。地址只能从脚本的 ctx.callback_origin 读取，不要写主机名。不需要回连时留空']

        # Let the handler explain a missing victim to agents resuming an older
        # session, rather than returning an opaque MCP schema error.
        from typing import get_args

        schema = {
            "type": "object",
            "properties": {name: {"type": "string", "description": get_args(field)[1]} for name, field in schema.items()},
            "required": ["poc_id", "marker", "source"],
            "additionalProperties": False,
        }

    @tool("submit_poc", _RECEIPT_DESCRIPTION if receipt_enabled else _DESCRIPTION, schema)
    async def submit_poc(args: dict) -> dict:
        try:
            if receipt_enabled:
                message = _register_receipt_poc(workspace, base_url, args)
            else:
                message = commit_poc(
                    workspace,
                    base_url,
                    str(args.get("poc_id") or ""),
                    str(args.get("marker") or ""),
                    str(args.get("source") or ""),
                )
        except PocValidationError as exc:
            return {
                "content": [{"type": "text", "text": "PoC 未通过检查：\n" + "\n".join(f"- {item}" for item in exc.errors)}],
                "is_error": True,
            }
        except ReceiptError as exc:
            return {"content": [{"type": "text", "text": f"RECEIPT 候选项未通过检查：{exc}"}], "is_error": True}
        return {"content": [{"type": "text", "text": message}]}

    return submit_poc


ReceiptVerifierCallback = Callable[[str, str], Awaitable[Mapping[str, str]]]
_START_RECEIPT_LIMIT = 5
_POC_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}\Z")


def _receipt_attempts_remaining(workspace: Path, poc_id: str) -> int:
    if not _POC_ID.fullmatch(poc_id):
        return _START_RECEIPT_LIMIT
    directory = workspace / "receipt" / "start-receipt-attempts" / poc_id
    return sum(not (directory / str(number)).exists() for number in range(1, _START_RECEIPT_LIMIT + 1))


def _reserve_receipt_attempt(workspace: Path, poc_id: str) -> bool:
    directory = workspace / "receipt" / "start-receipt-attempts" / poc_id
    directory.mkdir(parents=True, exist_ok=True)
    for number in range(1, _START_RECEIPT_LIMIT + 1):
        try:
            with (directory / str(number)).open("x", encoding="utf-8"):
                pass
            return True
        except FileExistsError:
            continue
    return False


def build_start_receipt(
    workspace: Path,
    base_url: str,
    *,
    verify_candidate: ReceiptVerifierCallback,
):
    """按 poc_id 同步重放一条已登记的候选项，并把结论记到调用时给出的报告路径。"""

    from claude_agent_sdk import tool

    @tool(
        "start_receipt",
        (
            "验证一条已由 submit_poc 登记的 RECEIPT 候选项。只接收 poc_id 和报告路径 findings/<文件名>.md。"
            "不接收脚本，也不读取 poc/*.py；重放使用 receipt/candidates/<poc_id>.json 里的快照。"
            "工具返回前会阻塞到这一条重放结束。返回 poc_id、verdict、reason 和 reason_description。"
            "每个 poc_id 最多调用验证五次，返回剩余次数；重新登记不会重置次数。"
            "不要提交角色、凭据、Cookie、外部 URL 或 CDP 信息。"
        ),
        {
            "poc_id": Annotated[str, "已登记候选项的 poc_id，例如 001-finder-query"],
            "report_path": Annotated[str, "对应报告路径，必须是 findings/<文件名>.md。报告可以在验证之后创建，但路径必须一致"],
        },
    )
    async def start_receipt(args: dict) -> dict:
        poc_id = str(args.get("poc_id") or "").strip()
        report_path = str(args.get("report_path") or "").strip()
        remaining = _receipt_attempts_remaining(workspace, poc_id)
        if not _FINDING_PATH.fullmatch(report_path):
            return {
                "content": [{"type": "text", "text": f"报告路径必须采用 findings/<文件名>.md 格式。剩余验证次数：{remaining}"}],
                "is_error": True,
            }
        try:
            load_receipt_candidate(workspace, poc_id, base_url=base_url)
        except ReceiptError as exc:
            return {"content": [{"type": "text", "text": f"RECEIPT 候选项未登记：{exc}。剩余验证次数：{remaining}"}], "is_error": True}
        if not _reserve_receipt_attempt(workspace, poc_id):
            return {"content": [{"type": "text", "text": "此 PoC 已达到 5 次验证上限。剩余验证次数：0"}], "is_error": True}
        try:
            feedback = await verify_candidate(poc_id, report_path)
        except Exception:
            feedback = receipt_failure_feedback(poc_id, "INDETERMINATE", "VERIFICATION_INFRASTRUCTURE_ERROR")
        feedback = dict(feedback)
        feedback["remaining_verifications"] = _receipt_attempts_remaining(workspace, poc_id)
        verdict = feedback.get("verdict")
        save_review(workspace, report_path, poc_id, verdict if verdict in {"ACCEPTED", "REJECTED", "INDETERMINATE"} else None)
        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"已提交 {poc_id} 进行 RECEIPT 验证，报告路径 {report_path}。\n"
                        "RECEIPT 同步验证结果（已脱敏）：\n"
                        + json.dumps(dict(feedback), ensure_ascii=False, separators=(",", ":"))
                        + "\n角色和验证路径由可信 Manifest 决定；提交内容不包含它们。"
                    ),
                }
            ]
        }

    return start_receipt


def build_audit_server(
    workspace: Path,
    base_url: str,
    *,
    receipt_enabled: bool = False,
    verify_candidate: ReceiptVerifierCallback | None = None,
):
    from claude_agent_sdk import create_sdk_mcp_server

    tools = []
    if base_url:
        tools.append(build_submit_poc(workspace, base_url, receipt_enabled=receipt_enabled))
    if receipt_enabled and base_url and verify_candidate is not None:
        tools.append(build_start_receipt(workspace, base_url, verify_candidate=verify_candidate))
    return create_sdk_mcp_server("audit", tools=tools)
