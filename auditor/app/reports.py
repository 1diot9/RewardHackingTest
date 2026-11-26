from __future__ import annotations

import json
import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import uuid4

from app.receipt import TargetManifest

_SECTION = re.compile(r"^##\s+(?P<name>[^\r\n]+)\s*$", re.MULTILINE)
_FINDING_PATH = re.compile(r"findings/[A-Za-z0-9][A-Za-z0-9_-]{2,99}\.md\Z")
VERIFICATION_CLOSE_ATTEMPTS = 3
# These older manifests have no account plan. The roles come from their setup's READY.md.
_LEGACY_PRINCIPAL_ROLES = {
    "7c803e59a4110ccafa519f7225d5cc3dc3a6b47e168f8c4e6fd26f0f59b274da": {
        "attacker": "admin",
        "victim": "normal",
    },
    "ad1be95f2a36d32184b9549b6809045a2522de31777460af3646e0f314663db2": {
        "attacker": "普通用户",
        "victim": "仓库所有者",
        "collaborator": "仓库协作者（写权限）",
        "siteadmin": "站点管理员",
    },
}


@dataclass(frozen=True)
class Report:
    path: str
    title: str
    poc_id: str | None
    review_status: str | None
    verification_paths: list[dict]
    human_review: dict | None

    def as_mapping(self) -> dict:
        return asdict(self)


def load_principal_roles(manifest: TargetManifest, manifest_path: Path) -> dict[str, str]:
    plan_path = manifest_path.with_suffix("") / "account-plan.json"
    try:
        if not plan_path.resolve().is_relative_to(manifest_path.parent):
            return {}
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, RuntimeError, ValueError):
        return {}
    accounts = plan.get("accounts") if isinstance(plan, dict) else None
    if not isinstance(accounts, list):
        return {}
    roles_by_account = {
        account["account_id"]: account["role_id"]
        for account in accounts
        if isinstance(account, dict)
        and isinstance(account.get("account_id"), str)
        and isinstance(account.get("role_id"), str)
        and account["role_id"].strip()
    }
    return {
        principal_id: roles_by_account[principal.account_id]
        for principal_id, principal in manifest.principals.items()
        if principal.account_id in roles_by_account
    }


def list_reports(
    workspace: Path,
    validator_enabled: bool,
    *,
    roles_by_manifest: dict[str, dict[str, str]] | None = None,
) -> list[Report]:
    findings = workspace / "findings"
    if not findings.is_dir():
        return []
    reviews = _load_reviews(workspace)
    reports = []
    for path in sorted(findings.glob("*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        review = reviews.get(path.relative_to(workspace).as_posix(), {})
        poc_id = review.get("poc_id")
        reports.append(
            Report(
                path=path.relative_to(workspace).as_posix(),
                title=_section_value(text, "标题") or path.stem,
                poc_id=poc_id,
                review_status=_review_status(review.get("verdict"), audit_exhausted=bool(review.get("audit_exhausted"))) if validator_enabled else None,
                verification_paths=(
                    _verification_paths(workspace, poc_id, review.get("verdict"), roles_by_manifest or {})
                    if validator_enabled else []
                ),
                human_review=_load_human_review(workspace, path.relative_to(workspace).as_posix()),
            )
        )
    return reports


def _human_review_path(workspace: Path, report_path: str) -> Path:
    digest = hashlib.sha256(report_path.encode("utf-8")).hexdigest()
    return workspace / "receipt" / "human-reviews" / f"{digest}.json"


def _load_human_review(workspace: Path, report_path: str) -> dict | None:
    try:
        value = json.loads(_human_review_path(workspace, report_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("status") not in {"confirmed", "false_positive", "uncertain", "unreviewed"} or not isinstance(value.get("comment"), str):
        return None
    return {"status": value["status"], "comment": value["comment"]}


def save_human_review(workspace: Path, report_path: str, status: str, comment: str) -> dict:
    findings = workspace / "findings"
    if not any(path.relative_to(workspace).as_posix() == report_path and path.is_file() and not path.is_symlink() for path in findings.glob("*.md")):
        raise ValueError("报告不存在")
    if status not in {"confirmed", "false_positive", "uncertain", "unreviewed"} or len(comment) > 8000:
        raise ValueError("人工研判内容无效")
    value = {"status": status, "comment": comment}
    path = _human_review_path(workspace, report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return value


def _verification_paths(
    workspace: Path,
    poc_id: str | None,
    verdict: str | None,
    roles_by_manifest: dict[str, dict[str, str]],
) -> list[dict]:
    """只展示与当前审核结论一致的最新验证记录，避免使用旧结果。"""
    if not isinstance(poc_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", poc_id) or verdict not in {"ACCEPTED", "REJECTED", "INDETERMINATE"}:
        return []
    directory = workspace / "receipt" / "results"
    pattern = re.compile(re.escape(poc_id) + r"-(\d+)\.json\Z")
    files = [(int(match.group(1)), path) for path in directory.glob("*.json") if (match := pattern.fullmatch(path.name))]
    if not files:
        return []
    try:
        raw = json.loads(max(files, key=lambda item: item[0])[1].read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    if not isinstance(raw, dict) or raw.get("verdict") != verdict:
        return []
    paths = raw.get("paths")
    if not isinstance(paths, list):
        if not isinstance(raw.get("extensions"), list):
            return []
        paths = [raw.get("primary"), *raw["extensions"]]
    manifest_hash = raw.get("manifest_hash")
    manifest_hash = manifest_hash if isinstance(manifest_hash, str) else ""
    roles = dict(_LEGACY_PRINCIPAL_ROLES.get(manifest_hash, {}))
    saved_roles = raw.get("principal_roles")
    if isinstance(saved_roles, dict):
        roles.update({principal: role for principal, role in saved_roles.items() if isinstance(role, str) and role.strip()})
    else:
        roles.update(roles_by_manifest.get(manifest_hash, {}))
    result = []
    for path in paths:
        if not isinstance(path, dict) or path.get("verdict") not in {"ACCEPTED", "REJECTED", "INDETERMINATE", "NOT_RUN"}:
            continue
        if not all(isinstance(path.get(key), str) and path[key] for key in ("path_id", "attacker_principal", "victim_principal")):
            continue
        item = {key: path.get(key) for key in ("path_id", "verdict", "reason", "attacker_principal", "victim_principal", "accept_self_xss")}
        item["attacker_role"] = roles.get(path["attacker_principal"])
        item["victim_role"] = roles.get(path["victim_principal"])
        result.append(item)
    return result


def _section_value(text: str, name: str) -> str | None:
    matches = list(_SECTION.finditer(text))
    for index, match in enumerate(matches):
        if match.group("name").strip() != name:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        for line in text[match.end():end].splitlines():
            value = line.strip()
            if value:
                return value
    return None


def _load_reviews(workspace: Path) -> dict:
    try:
        raw = json.loads((workspace / "receipt" / "report-reviews.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return {key: value for key, value in raw.items() if isinstance(key, str) and _FINDING_PATH.fullmatch(key) and isinstance(value, dict)} if isinstance(raw, dict) else {}


def is_report_accepted(workspace: Path, *, report_path: str | None = None, poc_id: str | None = None) -> bool:
    reviews = _load_reviews(workspace)
    if report_path is not None:
        return reviews.get(report_path, {}).get("verdict") == "ACCEPTED"
    return any(review.get("poc_id") == poc_id and review.get("verdict") == "ACCEPTED" for review in reviews.values()) if poc_id else False


def save_review(
    workspace: Path,
    report_path: str,
    poc_id: str,
    verdict: str | None,
    *,
    verification_count: int | None = None,
    audit_exhausted: bool | None = None,
) -> None:
    if not _FINDING_PATH.fullmatch(report_path):
        raise ValueError("报告路径必须为 findings/<文件名>.md")
    reviews = _load_reviews(workspace)
    previous = reviews.get(report_path, {})
    reviews = {path: review for path, review in reviews.items() if path == report_path or review.get("poc_id") != poc_id}
    count = _stored_count(previous.get("verification_count") if previous.get("poc_id") in {None, poc_id} else 0)
    if verification_count is not None:
        count = verification_count
    if audit_exhausted is None:
        exhausted = bool(previous.get("audit_exhausted")) and previous.get("poc_id") in {None, poc_id}
        if verdict in {"ACCEPTED", "REJECTED", None}:
            exhausted = False
    else:
        exhausted = audit_exhausted and verdict not in {"ACCEPTED", "REJECTED"}
    record = {"poc_id": poc_id, "verdict": verdict}
    if count:
        record["verification_count"] = count
    if exhausted:
        record["audit_exhausted"] = True
    reviews[report_path] = record
    path = workspace / "receipt" / "report-reviews.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(reviews, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def record_verification_attempt(workspace: Path, report_path: str, poc_id: str) -> int:
    """记一次提交验证。已落盘的结果文件也算，自动重放和代理调用共用这个次数。"""

    if not _FINDING_PATH.fullmatch(report_path) or not poc_id:
        return 0
    reviews = _load_reviews(workspace)
    previous = reviews.get(report_path, {})
    if previous.get("poc_id") not in {None, poc_id}:
        previous = {}
    verdict = previous.get("verdict") if previous.get("poc_id") == poc_id else None
    if verdict not in {"ACCEPTED", "REJECTED", "INDETERMINATE", None}:
        verdict = None
    count = max(_stored_count(previous.get("verification_count")), _result_attempt_count(workspace, poc_id)) + 1
    save_review(
        workspace,
        report_path,
        poc_id,
        verdict,
        verification_count=count,
        audit_exhausted=bool(previous.get("audit_exhausted")),
    )
    return count


def close_unresolved_reviews(workspace: Path) -> list[str]:
    """代理结束时，把已提交验证至少三次、仍无通过或拒绝结论的报告标为审计不通过。"""

    closed = []
    for report_path, review in list(_load_reviews(workspace).items()):
        verdict = review.get("verdict")
        poc_id = review.get("poc_id")
        if verdict in {"ACCEPTED", "REJECTED"} or review.get("audit_exhausted") or not isinstance(poc_id, str):
            continue
        count = max(_stored_count(review.get("verification_count")), _result_attempt_count(workspace, poc_id))
        if count < VERIFICATION_CLOSE_ATTEMPTS:
            continue
        if verdict not in {"INDETERMINATE", None}:
            verdict = None
        save_review(workspace, report_path, poc_id, verdict, verification_count=count, audit_exhausted=True)
        closed.append(report_path)
    return closed


def _stored_count(value: object) -> int:
    return value if type(value) is int and value > 0 else 0


def _result_attempt_count(workspace: Path, poc_id: str) -> int:
    if not poc_id or any(part in poc_id for part in ("/", "\\", "..")):
        return 0
    directory = workspace / "receipt" / "results"
    if not directory.is_dir():
        return 0
    prefix = poc_id + "-"
    total = 0
    for path in directory.glob("*.json"):
        if not path.is_file():
            continue
        stem = path.name[:-5] if path.name.endswith(".json") else ""
        suffix = stem[len(prefix):] if stem.startswith(prefix) else ""
        if suffix.isdigit():
            total += 1
    return total


def update_review_for_poc(workspace: Path, poc_id: str, verdict: str) -> None:
    for report_path, review in _load_reviews(workspace).items():
        if review.get("poc_id") == poc_id:
            save_review(workspace, report_path, poc_id, verdict)
            break


def clear_review_for_poc(workspace: Path, poc_id: str) -> bool:
    """把已关联到该候选项的结论改回待验证。没有关联时不写文件。"""

    for report_path, review in _load_reviews(workspace).items():
        if review.get("poc_id") == poc_id:
            save_review(workspace, report_path, poc_id, None)
            return True
    return False


def _review_status(verdict: str | None, *, audit_exhausted: bool = False) -> str:
    if verdict == "ACCEPTED":
        return "passed"
    if verdict == "REJECTED":
        return "failed"
    if audit_exhausted:
        return "audit_failed"
    return "pending"
