"""浏览器验证子进程。父进程按步骤文件监督，超时后可以结束这棵进程树。"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

from app.process_bounds import RESULT_FILE_ENV, STEP_PREFIX_ENV, StepTimeout, mark_step


def _write(payload: dict[str, Any]) -> None:
    path = os.environ.get(RESULT_FILE_ENV)
    if not path:
        return
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)


def _attacker(job: dict[str, Any]) -> dict[str, Any]:
    from app.generic_receipt_adapter import _login_cookie_header
    from app.receipt import AttackerAuthMissing, AttackerSession, AuthHeader

    os.environ[STEP_PREFIX_ENV] = "attacker_login"
    mark_step("attacker_login.start")
    headers = tuple(
        AuthHeader(item["source"], item["key"], item["header"], item.get("prefix", ""))
        for item in job.get("auth_headers") or []
    )
    try:
        value = _login_cookie_header(
            job["base_url"],
            tuple(_steps(job.get("steps") or [])),
            job["account"],
            int(job["timeout_ms"]),
            headers,
            job.get("http_credentials"),
        )
    except AttackerAuthMissing:
        return {"kind": "error", "error": "AttackerAuthMissing"}
    except StepTimeout as exc:
        return {"timeout": True, "step": exc.step, "index": exc.index, "timeout_seconds": max(1, int(job["timeout_ms"]) // 1000)}
    if isinstance(value, AttackerSession):
        return {"kind": "session", "cookie": value.cookie, "headers": value.headers}
    return {"kind": "cookie", "cookie": value}


def _victim(job: dict[str, Any]) -> dict[str, Any]:
    from app.receipt import LoginStep, PlaywrightVictimDriver, ReceiptCandidate, ReceiptError, TargetRun, ThreatPath

    os.environ[STEP_PREFIX_ENV] = "victim_login"
    validation_base = job.get("validation_base_url")
    if not isinstance(validation_base, str) or not validation_base:
        validation_base = job["base_url"]
    try:
        candidate = ReceiptCandidate.from_mapping(job["candidate"], base_url=validation_base)
    except ReceiptError:
        return {"failed": True, "error": "CANDIDATE_INVALID"}
    path = ThreatPath(
        id=job["path"]["id"],
        attacker_principal=job["path"]["attacker_principal"],
        victim_principal=job["path"]["victim_principal"],
        primary=bool(job["path"].get("primary")),
        accept_self_xss=bool(job["path"].get("accept_self_xss")),
    )
    account = job.get("victim_account") or {}

    def login_victim(page: Any, principal_id: str, steps: tuple[LoginStep, ...]) -> bool:
        from app.generic_receipt_adapter import _login

        if principal_id != path.victim_principal:
            return False
        if not steps:
            return True
        return _login(page, job["base_url"], steps, account)

    target = TargetRun(
        run_id=job.get("run_id") or "",
        base_url=job["base_url"],
        attacker_base_url=job["base_url"],
        allowed_origins=tuple(job["allowed_origins"]),
        attacker_network="",
        attacker_cookie_header="",
        login_victim=login_victim,
        snapshot_id="",
        victim_http_credentials=job.get("http_credentials"),
        victim_account=account or None,
    )
    evidence = PlaywrightVictimDriver().run(candidate, target, path, job["token"], int(job["timeout_ms"]))
    return {
        "kind": "evidence",
        "accepted": evidence.accepted,
        "reason": evidence.reason,
        "document_origin": evidence.document_origin,
        "action_trace": list(evidence.action_trace),
        "error_stage": evidence.error_stage,
        "error_type": evidence.error_type,
        "error_action_index": evidence.error_action_index,
        "navigation_status": evidence.navigation_status,
        "click_blocker": evidence.click_blocker,
        "error_step": evidence.error_step,
        "error_step_index": evidence.error_step_index,
    }


def _steps(raw: list[dict[str, Any]]) -> list[Any]:
    from app.receipt import LoginStep

    return [
        LoginStep(item["type"], item.get("path", ""), item.get("selector", ""), item.get("value", ""))
        for item in raw
    ]


def main() -> int:
    try:
        job = json.loads(sys.stdin.read() or "{}")
        if not isinstance(job, dict):
            payload: dict[str, Any] = {"failed": True, "error": "invalid_job"}
        elif job.get("op") == "attacker_login":
            payload = _attacker(job)
        elif job.get("op") == "victim_browser":
            payload = _victim(job)
        else:
            payload = {"failed": True, "error": "unknown_job"}
    except Exception as exc:
        payload = {"failed": True, "error": type(exc).__name__}
    _write(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
