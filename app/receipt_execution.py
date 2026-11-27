"""RECEIPT 的可信同步执行入口。

此模块不从 Agent 接收 Manifest、Adapter、身份或凭据。调用方只给出任务已绑定的
Manifest 名称和已提交的 poc_id；完整 Receipt 仅保存在任务工作区，Agent 只得到
经脱敏后的 verdict 与 reason。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from app import receipt_diagnostics as diagnostics
from app.config import POCLIB_FILE, RECEIPT_MANIFESTS_DIR
from app.receipt import (
    DockerAttackerExecutor,
    PathResult,
    ReceiptError,
    ReceiptResult,
    ReceiptVerdict,
    PlaywrightVictimDriver,
    ReceiptVerifier,
    load_manifest,
    load_receipt_candidate,
    target_adapter_for,
)
from app.receipt_settings import ReceiptRuntimeConfig, receipt_configuration_errors, receipt_runtime_config
from app.reports import load_principal_roles

_REJECT_REASONS = {
    "ATTACKER_FAILED",
    "ATTACKER_CREDENTIALS_NOT_INJECTED",
    "ATTACKER_LOGIN_FAILED",
    "ATTACKER_EVIDENCEMISSING", "ATTACKER_PERMISSIONERROR", "ATTACKER_ATTRIBUTEERROR",
    "ATTACKER_NAMEERROR", "ATTACKER_INDEXERROR",
    "ATTACKER_MODULENOTFOUNDERROR", "ATTACKER_IMPORTERROR", "ATTACKER_SYNTAXERROR",
    "ATTACKER_INDENTATIONERROR",     "ATTACKER_TIMEOUTERROR", "ATTACKER_CONNECTIONERROR",
    "ATTACKER_ASSERTIONERROR", "ATTACKER_KEYERROR", "ATTACKER_VALUEERROR", "ATTACKER_TYPEERROR",
    "ATTACKER_UNICODEERROR",
    "NO_BROWSER_BOUND_RECEIPT",
    "VICTIM_LOGIN_FAILED",
    "VICTIM_URL_AUTH_PARAMETER",
    "VICTIM_IDENTITY_CHANGED",
    "VICTIM_URL_OUTSIDE_ALLOWLIST",
}
_INDETERMINATE_REASONS = {
    "PATH_SELECTION_UNAVAILABLE",
    "PATH_BUDGET_EXHAUSTED",
    "ADAPTER_CONTRACT_ERROR",
    "ADAPTER_ERROR",
    "ATTACKER_SANDBOX_UNAVAILABLE",
    "ATTACKER_LOGIN_UNAVAILABLE",
    "ATTACKER_TIMEOUT",
    "ATTACKER_KILLED",
    "CALLBACK_UNAVAILABLE",
    "BROWSER_ERROR",
    "BROWSER_UNAVAILABLE",
    "RECEIPT_MANIFEST_UNAVAILABLE",
    "RECEIPT_BUNDLE_INVALID",
    "RECEIPT_CONFIGURATION_ERROR",
    "RECEIPT_VERIFIER_SETUP_ERROR",
    "RECEIPT_RESULT_STORAGE_ERROR",
}

_REASON_DESCRIPTIONS = {
    "PATH_SELECTION_UNAVAILABLE": "No trusted verification paths could be selected, so no paths were run.",
    "PATH_BUDGET_EXHAUSTED": "Verification is incomplete because the configured budget did not cover all trusted paths.",
    "ATTACKER_FAILED": "The attacker script exited unsuccessfully.",
    "ATTACKER_CREDENTIALS_NOT_INJECTED": "The attacker script reads ctx.username or ctx.password. RECEIPT does not pass those arguments. Declare attacker_login and any needed storage-to-header mappings; ctx.request attaches the authentication information automatically.",
    "ATTACKER_LOGIN_FAILED": "Attacker login failed or did not produce the declared authentication material. Check the login steps, selectors, and storage-to-header mappings.",
    "ATTACKER_LOGIN_UNAVAILABLE": "The target adapter cannot establish an attacker session.",
    "NO_BROWSER_BOUND_RECEIPT": "The victim browser did not receive a valid execution receipt.",
    "VICTIM_URL_AUTH_PARAMETER": "The submitted victim URL or login URL contains an authentication parameter. Victim URLs block built-in session parameter names plus manifest auth_query_params; login URLs also block sid and session.",
    "VICTIM_IDENTITY_CHANGED": "The victim browser session cookie changed after login. The submitted navigation replaced the authenticated victim.",
    "VICTIM_LOGIN_FAILED": "The victim browser could not establish the required authenticated session.",
    "VICTIM_URL_OUTSIDE_ALLOWLIST": "The victim URL is outside the permitted origins.",
    "ADAPTER_CONTRACT_ERROR": "The target adapter returned an invalid verification environment.",
    "ADAPTER_ERROR": "The target adapter could not complete the verification run.",
    "ATTACKER_SANDBOX_UNAVAILABLE": "The isolated attacker environment is unavailable or not configured.",
    "ATTACKER_TIMEOUT": "The attacker script exceeded the execution time limit.",
    "ATTACKER_KILLED": "The attacker process was killed before it finished. This comes from the runtime limit, not from a script assertion.",
    "CALLBACK_UNAVAILABLE": "The callback listener in the attacker container did not become ready.",
    "BROWSER_ERROR": "The victim browser encountered an error during verification.",
    "BROWSER_UNAVAILABLE": "The victim browser driver is unavailable.",
    "VERIFICATION_REJECTED": "The verification did not satisfy the acceptance criteria.",
    "VERIFICATION_INFRASTRUCTURE_ERROR": "The verification infrastructure encountered an error.",
    "VERIFICATION_UNAVAILABLE": "The verification service or its configuration is unavailable.",
    "RECEIPT_MANIFEST_UNAVAILABLE": "The task's trusted RECEIPT manifest is unavailable or invalid.",
    "RECEIPT_BUNDLE_INVALID": "This RECEIPT candidate is missing or invalid. Call submit_poc again to register this one candidate.",
    "RECEIPT_CONFIGURATION_ERROR": "The RECEIPT verifier is missing required server-side configuration.",
    "RECEIPT_VERIFIER_SETUP_ERROR": "The verifier could not prepare its trusted target environment.",
    "RECEIPT_RESULT_STORAGE_ERROR": "The verifier completed but could not save its protected result.",
}

_REASON_NEXT_STEPS = {
    "PATH_SELECTION_UNAVAILABLE": "Check the report, trusted role mappings, and path selector availability, then retry verification.",
    "PATH_BUDGET_EXHAUSTED": "Ask the operator to increase the trusted manifest's extension path budget and retry verification.",
    "ATTACKER_FAILED": "Check the submitted attacker script's control flow, request, and expected response before resubmitting. If the request must be authenticated, declare attacker_login and do not log in with ctx.username or ctx.password.",
    "ATTACKER_CREDENTIALS_NOT_INJECTED": "Remove the login request that uses ctx.username and ctx.password. Add attacker_login with a same-origin goto, one {{username}} fill, one {{password}} fill, the submit click, and a final assert_visible. Call submit_poc again for this candidate, then start_receipt.",
    "ATTACKER_LOGIN_FAILED": "Check the attacker_login steps and final assert_visible, and verify any declared storage keys and header mappings. ctx.request sends the injected authentication information.",
    "ATTACKER_LOGIN_UNAVAILABLE": "The configured target does not support an attacker login for this verification; continue with a PoC that does not require one or ask the operator to inspect the target setup.",
    "NO_BROWSER_BOUND_RECEIPT": "Check that the victim page reaches the payload and calls window.__receipt_accept with the current receipt token; verify the submitted actions and wait time.",
    "VICTIM_URL_AUTH_PARAMETER": "Remove authentication parameters from the victim and login URLs; use the declared login steps instead. A business parameter named sid or session is allowed on the victim URL unless this target lists it in auth_query_params.",
    "VICTIM_IDENTITY_CHANGED": "Keep the verifier-established victim session. Do not navigate to a URL that switches or replaces the session cookie.",
    "VICTIM_LOGIN_FAILED": "Check the submitted victim login steps, selectors, and post-login assertion before resubmitting.",
    "VICTIM_URL_OUTSIDE_ALLOWLIST": "Use only a same-origin victim URL and ensure submitted actions stay on the target origin.",
    "ATTACKER_TIMEOUT": "Reduce attacker-script work and verify its request completes within the verification timeout.",
    "ATTACKER_KILLED": "Retry once. If it persists, ask the operator to inspect the attacker runtime memory and process limits.",
    "CALLBACK_UNAVAILABLE": "Retry once. If it persists, ask the operator to inspect the attacker container runtime.",
    "BROWSER_ERROR": "Check the victim URL, login steps, actions, selectors, and target readiness, then resubmit.",
    "BROWSER_UNAVAILABLE": "The browser driver is unavailable; retry later or ask the operator to repair the verifier environment.",
    "ADAPTER_CONTRACT_ERROR": "The trusted target environment is invalid; ask the operator to inspect the RECEIPT adapter and environment snapshot.",
    "ADAPTER_ERROR": "The trusted target environment failed while running; retry later or ask the operator to inspect the environment.",
    "ATTACKER_SANDBOX_UNAVAILABLE": "The isolated attacker runtime is unavailable; ask the operator to repair the RECEIPT runtime before retrying.",
    "RECEIPT_MANIFEST_UNAVAILABLE": "The task's trusted manifest must be repaired or rebound by the operator before verification can continue.",
    "RECEIPT_BUNDLE_INVALID": "Call submit_poc again to register this one candidate; do not modify protected receipt files directly.",
    "RECEIPT_CONFIGURATION_ERROR": "Ask the operator to configure the RECEIPT signing key and pinned attacker image, then retry.",
    "RECEIPT_VERIFIER_SETUP_ERROR": "Ask the operator to inspect the trusted adapter and environment snapshot, then retry.",
    "RECEIPT_RESULT_STORAGE_ERROR": "Retry once; if it persists, ask the operator to inspect verifier result storage.",
    "VERIFICATION_REJECTED": "Review the submitted PoC, victim URL, and actions, then call submit_poc again for this candidate and start_receipt.",
    "VERIFICATION_INFRASTRUCTURE_ERROR": "Retry once; if it persists, ask the operator to inspect the verifier infrastructure.",
    "VERIFICATION_UNAVAILABLE": "Retry later or ask the operator to inspect the verifier configuration.",
}

_SCRIPT_ERRORS = {
    "EVIDENCEMISSING": "no evidence was observed; check the submitted request and its expected response",
    "PERMISSIONERROR": "a request outside the allowed target origin; use the target base URL",
    "ATTRIBUTEERROR": "an attribute error; check the response object and field names",
    "NAMEERROR": "an undefined name; check the script variables and imports",
    "INDEXERROR": "an index error; check the response structure before indexing",
    "MODULENOTFOUNDERROR": "a missing module; use only dependencies available in the attacker image",
    "IMPORTERROR": "an import failure; check the script imports and available dependencies",
    "SYNTAXERROR": "a syntax error; check the submitted script",
    "INDENTATIONERROR": "an indentation error; check the submitted script",
    "TIMEOUTERROR": "a timeout; check the request and target readiness",
    "CONNECTIONERROR": "a connection error; check the target URL and request",
    "ASSERTIONERROR": "an assertion failure; check the expected response",
    "KEYERROR": "a missing key; check the response structure",
    "VALUEERROR": "an invalid value; check parsing and input values",
    "TYPEERROR": "a type error; check the values passed to the script operations",
    "UNICODEERROR": "a text encoding error; keep the script output within the verifier character set",
}
for _error, _advice in _SCRIPT_ERRORS.items():
    _reason = "ATTACKER_" + _error
    _REASON_DESCRIPTIONS[_reason] = f"The attacker script reported {_advice}."
    _REASON_NEXT_STEPS[_reason] = "Correct the submitted attacker script based on this error, then call submit_poc again for this candidate and start_receipt."
_REASON_NEXT_STEPS["ATTACKER_EVIDENCEMISSING"] = (
    "Check the request and the expected response. If the action requires a logged-in attacker, declare attacker_login; "
    "RECEIPT does not pass username or password into the script, and ctx.request sends the injected session cookie."
)

_BROWSER_STAGES = {
    "playwright_start": "starting Playwright", "browser_launch": "launching the browser",
    "context_create": "creating the browser context", "request_restriction": "configuring browser request restrictions",
    "page_create": "creating the page", "sentinel_setup": "installing the receipt listener",
    "victim_login": "performing victim login", "victim_navigation": "navigating to the victim URL",
    "navigation_origin_check": "checking the navigation origin", "victim_action": "performing a victim action",
    "action_origin_check": "checking the action's resulting origin", "receipt_wait": "waiting for a receipt",
    "browser_close": "closing the browser",
}
_BROWSER_TYPES = {
    "playwright_timeout": "timed out", "playwright_error": "encountered a browser error",
    "receipt_error": "failed a verification check", "os_error": "encountered an operating system error",
    "unexpected_error": "encountered an unexpected error",
}


class ReceiptExecutionError(ReceiptError):
    """可安全返回给 Agent 的验证启动失败分类，不保存底层异常文本。"""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def receipt_failure_feedback(poc_id: str, verdict: str, reason: str) -> dict[str, str]:
    """Only return fixed descriptions; never expose exception or adapter details."""
    if reason not in _REASON_DESCRIPTIONS:
        reason = "VERIFICATION_REJECTED" if verdict == "REJECTED" else "VERIFICATION_INFRASTRUCTURE_ERROR"
    feedback = {
        "poc_id": poc_id,
        "verdict": verdict,
        "reason": reason,
        "reason_description": _REASON_DESCRIPTIONS[reason],
    }
    next_step = _REASON_NEXT_STEPS.get(reason)
    if next_step:
        feedback["next_step"] = next_step
    return feedback


@dataclass(frozen=True)
class ReceiptExecution:
    """一次同步验证的受控输出。"""

    agent_feedback: dict[str, str]
    result: dict[str, Any]
    artifact: str


def receipt_manifest_path(name: str, *, manifests_root: Path = RECEIPT_MANIFESTS_DIR) -> Path:
    candidate = manifests_root / (name or "").strip()
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(manifests_root.resolve())
    except (OSError, ValueError) as exc:
        raise ReceiptError("任务绑定的 RECEIPT Manifest 不存在或不在受信任目录") from exc
    if resolved.suffix.lower() != ".json":
        raise ReceiptError("任务绑定的 RECEIPT Manifest 必须是 JSON 文件")
    return resolved


def verify_receipt_candidate(
    workspace: Path,
    base_url: str,
    manifest_name: str,
    poc_id: str,
    *,
    runtime_config: ReceiptRuntimeConfig | None = None,
    on_path_complete: Callable[[int, int], None] | None = None,
    preferred_path_ids: tuple[str, ...] = (),
) -> ReceiptExecution:
    tokens = diagnostics.begin(workspace)
    try:
        return _verify_receipt_candidate(workspace, base_url, manifest_name, poc_id, runtime_config=runtime_config,
                                         on_path_complete=on_path_complete, preferred_path_ids=preferred_path_ids)
    except Exception as exc:
        cause = exc.__cause__ or exc
        diagnostics.record("verification_setup", error=f"{type(cause).__name__}: {cause}", poc_id=poc_id)
        raise
    finally:
        diagnostics.end(tokens)


def _verify_receipt_candidate(
    workspace: Path,
    base_url: str,
    manifest_name: str,
    poc_id: str,
    *,
    runtime_config: ReceiptRuntimeConfig | None = None,
    on_path_complete: Callable[[int, int], None] | None = None,
    preferred_path_ids: tuple[str, ...] = (),
) -> ReceiptExecution:
    """同步重放一个已登记的候选项，并落盘完整 Receipt。"""

    try:
        manifest_path = receipt_manifest_path(manifest_name)
        manifest = load_manifest(manifest_path, RECEIPT_MANIFESTS_DIR)
    except ReceiptError as exc:
        raise ReceiptExecutionError("RECEIPT_MANIFEST_UNAVAILABLE", "Manifest 加载或校验失败，请查看诊断日志。") from exc
    try:
        candidate = load_receipt_candidate(workspace, poc_id, base_url=base_url)
    except ReceiptError as exc:
        raise ReceiptExecutionError("RECEIPT_BUNDLE_INVALID", "候选 PoC 加载或校验失败，请查看诊断日志。") from exc
    config = runtime_config or receipt_runtime_config()
    errors = receipt_configuration_errors(config)
    if errors:
        diagnostics.record("configuration", error="; ".join(errors), poc_id=poc_id)
        raise ReceiptExecutionError("RECEIPT_CONFIGURATION_ERROR", "; ".join(errors))
    try:
        verifier = ReceiptVerifier(
            adapter=target_adapter_for(manifest, manifest_path.with_suffix("")) if manifest.adapter == "generic-compose" else target_adapter_for(manifest),
            attacker=DockerAttackerExecutor(
                image=config.attacker_image,
                poclib_file=POCLIB_FILE,
            ),
            browser=PlaywrightVictimDriver(),
            receipt_key=config.evidence_hmac_key.encode("utf-8"),
        )
    except ReceiptError as exc:
        raise ReceiptExecutionError("RECEIPT_VERIFIER_SETUP_ERROR") from exc
    principal_roles = load_principal_roles(manifest, manifest_path)
    result = verifier.verify(candidate, manifest, on_path_complete=on_path_complete, preferred_path_ids=preferred_path_ids)
    for path in result.paths:
        if path.verdict not in (ReceiptVerdict.ACCEPTED, ReceiptVerdict.NOT_RUN):
            diagnostics.record("path_result", run_id=path.run_id, reason=path.reason, verdict=path.verdict.value, evidence=json.dumps(path.evidence, ensure_ascii=False))
    result_mapping = result.public_mapping()
    directory = workspace / "receipt" / "results"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        filename = f"{candidate.poc_id}-{time.time_ns()}.json"
        (directory / filename).write_text(
            json.dumps({**result_mapping, "principal_roles": principal_roles}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ReceiptExecutionError("RECEIPT_RESULT_STORAGE_ERROR") from exc
    return ReceiptExecution(
        agent_feedback=receipt_agent_feedback(candidate.poc_id, result, principal_roles),
        result=result_mapping,
        artifact=f"receipt/results/{filename}",
    )


_MASKING_REASONS = {
    "ADAPTER_ERROR",
    "ADAPTER_CONTRACT_ERROR",
    "ATTACKER_SANDBOX_UNAVAILABLE",
    "ATTACKER_LOGIN_UNAVAILABLE",
    "ATTACKER_TIMEOUT",
    "ATTACKER_KILLED",
    "CALLBACK_UNAVAILABLE",
    "BROWSER_UNAVAILABLE",
    "PATH_BUDGET_EXHAUSTED",
    "VERIFICATION_INFRASTRUCTURE_ERROR",
}
_BROWSER_REVEAL_ORDER = ("BROWSER_ERROR", "VICTIM_LOGIN_FAILED", "NO_BROWSER_BOUND_RECEIPT", "VICTIM_URL_OUTSIDE_ALLOWLIST")


def _attacker_rejection(result: ReceiptResult) -> str:
    """已完成路径上的攻击者失败。基础设施错误不能把它从返回给 Agent 的说明里抹掉。"""
    reasons = [
        path.reason
        for path in result.paths
        if path.verdict == ReceiptVerdict.REJECTED and path.reason in _REJECT_REASONS and path.reason.startswith("ATTACKER_")
    ]
    for reason in ("ATTACKER_CREDENTIALS_NOT_INJECTED", "ATTACKER_LOGIN_FAILED", "ATTACKER_EVIDENCEMISSING"):
        if reason in reasons:
            return reason
    specific = sorted(reason for reason in reasons if reason != "ATTACKER_FAILED")
    if specific:
        return specific[0]
    return "ATTACKER_FAILED" if "ATTACKER_FAILED" in reasons else ""


def _describe_browser_failure(path: PathResult) -> tuple[str, str]:
    if path.reason == "BROWSER_ERROR":
        detail = path.evidence.get("browser_error")
        description = _REASON_DESCRIPTIONS["BROWSER_ERROR"]
        if isinstance(detail, dict):
            stage = _BROWSER_STAGES.get(detail.get("stage"))
            error_type = _BROWSER_TYPES.get(detail.get("type"))
            if stage and error_type:
                description = f"The victim browser {error_type} while {stage}."
                index = detail.get("action_index")
                if detail.get("stage") in {"victim_action", "action_origin_check"} and type(index) is int and 0 <= index < 30:
                    description += f" Victim action index: {index} (zero-based). Check this action and its selector."
                elif detail.get("stage") == "victim_login":
                    description += " Check the submitted victim login steps and selectors."
                elif detail.get("stage") == "victim_navigation":
                    description += " Check the victim URL and target availability."
            step = detail.get("step") if isinstance(detail, dict) else None
            if isinstance(step, str) and step:
                description += f" Step: {step}."
                step_index = detail.get("step_index")
                if type(step_index) is int and 0 <= step_index < 30:
                    description += f" Step index: {step_index}."
        return description, _REASON_NEXT_STEPS["BROWSER_ERROR"]
    description = _REASON_DESCRIPTIONS[path.reason]
    next_step = _REASON_NEXT_STEPS.get(path.reason, "")
    if path.reason == "NO_BROWSER_BOUND_RECEIPT":
        status = path.evidence.get("navigation_status")
        if type(status) is int and 100 <= status <= 599:
            description += f" Victim navigation returned HTTP {status}."
            if status in {401, 403}:
                next_step = "Check the victim login steps and access rights before checking payload execution."
            elif status == 404:
                next_step = "Check the victim URL; the page was not found."
    return description, next_step


def _completed_browser_path(result: ReceiptResult) -> PathResult | None:
    paths = [
        path for path in result.paths
        if path.reason in _BROWSER_REVEAL_ORDER and path.verdict in {ReceiptVerdict.REJECTED, ReceiptVerdict.INDETERMINATE}
    ]
    for reason in _BROWSER_REVEAL_ORDER:
        for path in paths:
            if path.reason == reason:
                return path
    return None


def _prepend_step(feedback: dict[str, str], step: str) -> None:
    if step:
        feedback["next_step"] = step + " " + feedback.get("next_step", "")


def _outcome_group_key(path: PathResult, roles: Mapping[str, str]) -> tuple[str, str, str, int | None, str]:
    """按可公开的受害者角色、结论和浏览器阻挡方式分组，不包含链路 ID。"""
    role = roles.get(path.victim_account, "")
    browser = path.evidence.get("browser_error")
    detail = browser if isinstance(browser, dict) else {}
    index = detail.get("action_index")
    action_index = index if type(index) is int else None
    blocker = detail.get("blocker") if detail.get("blocker") in {"not_found", "intercepted", "ambiguous"} else ""
    return role, path.verdict.value, path.reason, action_index, blocker


def _outcome_group_line(key: tuple[str, str, str, int | None, str], count: int) -> str:
    role, verdict, reason, action_index, blocker = key
    noun = "path" if count == 1 else "paths"
    line = f"victim role {role}: {count} {noun}, {verdict}, {reason}" if role else f"{count} {noun}, {verdict}, {reason}"
    if action_index is not None:
        line += f", victim action index {action_index}"
    if blocker == "not_found":
        line += ", element not found"
    elif blocker == "intercepted":
        line += ", element intercepted"
    elif blocker == "ambiguous":
        line += ", element matched more than once"
    return line


def _append_outcome_groups(feedback: dict[str, str], result: ReceiptResult, roles: Mapping[str, str]) -> None:
    """选中路径结论不一致时列出各组，相同结论仍保持原来的单句说明。"""
    ran = [
        path for path in result.paths
        if path.reason != "PATH_NOT_SELECTED" and path.verdict != ReceiptVerdict.NOT_RUN
    ]
    counts: dict[tuple[str, str, str, int | None, str], int] = {}
    order: list[tuple[str, str, str, int | None, str]] = []
    for path in ran:
        key = _outcome_group_key(path, roles)
        if key not in counts:
            order.append(key)
            counts[key] = 0
        counts[key] += 1
    if len(order) < 2:
        return
    lines = ". ".join(_outcome_group_line(key, counts[key]) for key in order)
    feedback["reason_description"] += " Selected paths did not all finish with this result. " + lines + "."
    _prepend_step(
        feedback,
        "A timeout or missing element on one victim role does not describe paths that completed their actions. "
        "If the report claims one victim, fix the completed paths' reason; do not remove an action that other victim roles were able to perform.",
    )


def _reveal_completed_paths(feedback: dict[str, str], result: ReceiptResult, safe_reason: str) -> None:
    """基础设施结论不能盖住另一条路径上已经发生的脚本或浏览器失败。"""
    if safe_reason not in _MASKING_REASONS:
        return
    script_reason = _attacker_rejection(result)
    if script_reason and script_reason != safe_reason:
        feedback["reason_description"] += (
            " A completed path rejected the attacker script before the victim browser ran. "
            + _REASON_DESCRIPTIONS[script_reason]
        )
        _prepend_step(feedback, _REASON_NEXT_STEPS.get(script_reason, ""))
    browser_path = _completed_browser_path(result)
    if browser_path is not None and browser_path.reason != safe_reason:
        description, step = _describe_browser_failure(browser_path)
        feedback["reason_description"] += " A completed path reached the victim browser. " + description
        _prepend_step(feedback, step)


def receipt_agent_feedback(
    poc_id: str,
    result: ReceiptResult,
    principal_roles: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """构造可以返回给 Agent 的最小结果，避免泄露 threat path 或证据细节。"""

    verdict = result.verdict
    decisive_path = result.decisive_path
    reason = decisive_path.reason
    if verdict == ReceiptVerdict.ACCEPTED:
        safe_reason = "BROWSER_BOUND_RECEIPT"
    elif verdict == ReceiptVerdict.REJECTED:
        safe_reason = reason if reason in _REJECT_REASONS or reason == "BROWSER_ERROR" else "VERIFICATION_REJECTED"
    else:
        safe_reason = reason if reason in _INDETERMINATE_REASONS else "VERIFICATION_INFRASTRUCTURE_ERROR"
    if verdict != ReceiptVerdict.ACCEPTED:
        feedback = receipt_failure_feedback(poc_id, verdict.value, safe_reason)
        if verdict == ReceiptVerdict.REJECTED and any(
            path.reason == "PATH_NOT_SELECTED" for path in result.paths
        ):
            feedback["reason_description"] += " Only selected paths were verified; other paths were not tested."
        if safe_reason.startswith("ATTACKER_") or safe_reason == "CALLBACK_UNAVAILABLE":
            detail = decisive_path.evidence.get("attacker_error", {})
            if isinstance(detail, dict) and detail.get("stage") in {"attacker_script", "attacker_timeout", "attacker_start", "attacker_login", "callback_start", "callback_prepare", "attacker_docker"}:
                feedback["reason_description"] += f" Stage: {detail['stage']}."
                if type(detail.get("exit_code")) is int:
                    feedback["reason_description"] += f" Exit code: {detail['exit_code']}."
                if type(detail.get("timeout_seconds")) is int:
                    feedback["reason_description"] += f" Timeout: {detail['timeout_seconds']} seconds."
                if isinstance(detail.get("step"), str) and detail["step"]:
                    feedback["reason_description"] += f" Step: {detail['step']}."
                if type(detail.get("index")) is int:
                    feedback["reason_description"] += f" Step index: {detail['index']}."
                feedback["reason_description"] += " See the protected receipt/diagnostics.jsonl for details."
        if safe_reason == "ADAPTER_ERROR":
            detail = decisive_path.evidence.get("error", {})
            if isinstance(detail, dict) and detail.get("stage") in {"adapter_open", "attacker", "victim_browser"}:
                feedback["reason_description"] += f" Stage: {detail['stage']}; exception: {detail.get('type', 'unknown')}."
                message = detail.get("message", "")
                if isinstance(message, str) and message.startswith("环境命令 "):
                    feedback["reason_description"] += " " + message
                feedback["reason_description"] += " See the protected receipt/diagnostics.jsonl for details."
        if safe_reason == "BROWSER_ERROR" or (
            safe_reason == "NO_BROWSER_BOUND_RECEIPT" and decisive_path.evidence.get("navigation_status") is not None
        ):
            description, step = _describe_browser_failure(decisive_path)
            feedback["reason_description"] = description
            if step:
                feedback["next_step"] = step
        _reveal_completed_paths(feedback, result, safe_reason)
        _append_outcome_groups(feedback, result, principal_roles or {})
        return feedback
    return {"poc_id": poc_id, "verdict": verdict.value, "reason": safe_reason}
