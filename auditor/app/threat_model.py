"""Check that a generated threat model is closed over the roles it cites.

The checker proves a property of the files the initializer wrote: every listed
role has a disposition, every included attacker has a path and an
account, and the manifest is a projection of those decisions. It does not prove
that some uncited role system is absent. Assumptions stay reviewable and do not
fail initialization; creating an audit from the generated manifest requires an
operator acknowledgement while any review item remains.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.receipt import ReceiptError, TargetManifest

_IDENTIFIER = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
_DISPOSITIONS = frozenset({"include", "victim_only", "exclude"})
_EVIDENCE_KINDS = frozenset({"source", "official_doc", "historical_advisory", "assumption"})
_REVIEW_KINDS = frozenset({"official_doc", "historical_advisory", "assumption"})
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")


@dataclass
class ThreatModelReport:
    ok: bool
    coverage_status: str
    messages: list[str] = field(default_factory=list)
    review_items: list[dict[str, str]] = field(default_factory=list)
    digest: str = ""

    def as_check(self) -> dict[str, Any]:
        if self.messages:
            text = "威胁模型闭包未通过：" + "；".join(self.messages)
        elif self.review_items:
            text = "威胁模型闭包已通过，仍需人工确认：" + "；".join(item["message"] for item in self.review_items)
        else:
            text = "威胁模型闭包已闭合"
        return {
            "id": "threat_coverage",
            "ok": self.ok,
            "message": text[:2000],
            "coverage_status": self.coverage_status,
            "digest": self.digest,
            "review_items": self.review_items,
        }


def evaluate_threat_model(environment: Path, source_dir: Path | None) -> ThreatModelReport:
    """Return blocking gaps separately from items that only hold up task creation."""

    blocking: list[str] = []
    review: list[dict[str, str]] = []
    inventory = _load_object(environment / "role-inventory.json", "角色清单 role-inventory.json", blocking)
    decisions = _load_object(environment / "threat-decisions.json", "威胁决策 threat-decisions.json", blocking)
    accounts = _load_object(environment / "account-plan.json", "账号计划 account-plan.json", blocking)
    manifest_raw = _load_object(environment / "receipt-manifest.json", "receipt-manifest.json", blocking)
    if blocking:
        return _report(False, "incomplete", blocking, review, "")

    roles = _roles(inventory, blocking)
    dispositions = _dispositions(decisions, roles, blocking, review)
    victims = _victims(decisions, roles, dispositions, blocking)
    paths = _paths(decisions, roles, dispositions, victims, blocking)
    boundaries = _boundaries(decisions, roles, dispositions, victims, blocking, review)
    plan = _account_plan(accounts, blocking)
    _matrix(roles, dispositions, victims, paths, boundaries, blocking)
    _accounts_align(paths, plan, blocking)
    _script_reads_plan(environment / "create-accounts.py", blocking)
    projection = _projection(paths, plan)
    _manifest_matches(manifest_raw, projection, blocking)
    digest = "" if blocking else _digest(roles, dispositions, victims, paths, boundaries, plan, projection)
    if blocking:
        return _report(False, "incomplete", blocking, review, digest)
    status = "review_required" if review else "closed"
    return _report(True, status, [], review, digest)


def _report(ok: bool, status: str, blocking: list[str], review: list[dict[str, str]], digest: str) -> ThreatModelReport:
    unique_review: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in review:
        key = (item["code"], item["message"])
        if key not in seen:
            seen.add(key)
            unique_review.append(item)
    return ThreatModelReport(ok, status, blocking[:12], unique_review[:12], digest)


def _load_object(path: Path, label: str, blocking: list[str]) -> dict[str, Any] | None:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000:
            blocking.append(f"缺少或无法读取{label}")
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        blocking.append(f"{label} 不是有效 UTF-8 JSON")
        return None
    if not isinstance(raw, dict):
        blocking.append(f"{label} 的根节点必须是对象")
        return None
    return raw


def _roles(inventory: dict[str, Any] | None, blocking: list[str]) -> dict[str, dict[str, str]]:
    if inventory is None:
        return {}
    _only(inventory, {"roles", "clusters"}, "role-inventory.json", blocking)
    found: dict[str, dict[str, str]] = {}
    for item in _list(inventory.get("roles"), "role-inventory.json roles", blocking):
        if not isinstance(item, dict):
            blocking.append("role-inventory.json roles 项必须是对象")
            continue
        _only(item, {"id", "literal", "scope"}, "角色", blocking)
        role_id = _ident(item.get("id"), "角色 id", blocking)
        literal = _token(item.get("literal"), "角色字面量", blocking)
        scope = _scope(item.get("scope"), "角色作用域", blocking)
        if not role_id or not literal or not scope:
            continue
        if role_id in found:
            blocking.append(f"角色 id 重复：{role_id}")
            continue
        found[role_id] = {"id": role_id, "literal": literal, "scope": scope}
    if inventory is not None and not found and not any(message.startswith("role-inventory") for message in blocking):
        blocking.append("角色清单为空")
    return found


def _dispositions(
    decisions: dict[str, Any] | None,
    roles: dict[str, dict[str, str]],
    blocking: list[str],
    review: list[dict[str, str]],
) -> dict[str, dict[str, Any]]:
    if decisions is None:
        return {}
    _only(decisions, {"roles", "victims", "paths", "boundaries"}, "threat-decisions.json", blocking)
    found: dict[str, dict[str, Any]] = {}
    for item in _list(decisions.get("roles"), "threat-decisions.json roles", blocking):
        if not isinstance(item, dict):
            blocking.append("威胁决策中的角色必须是对象")
            continue
        _only(item, {"id", "disposition", "reason", "evidence"}, "威胁决策角色", blocking)
        role_id = _ident(item.get("id"), "处置角色", blocking)
        disposition = item.get("disposition")
        reason = _reason(item.get("reason"), f"角色 {role_id or '?'} 的处置理由", blocking)
        evidence = _evidence(item.get("evidence"), f"角色 {role_id or '?'} 的处置", blocking)
        if not role_id or evidence is None:
            continue
        if role_id not in roles:
            blocking.append(f"处置引用了未知角色 {role_id}")
            continue
        if disposition not in _DISPOSITIONS:
            blocking.append(f"角色 {role_id} 的处置必须是 include、victim_only 或 exclude")
            continue
        if role_id in found:
            blocking.append(f"角色 {role_id} 有多条处置")
            continue
        if not reason:
            continue
        found[role_id] = {"id": role_id, "disposition": disposition, "reason": reason, "evidence": evidence}
        if disposition != "exclude" or evidence["kind"] != "assumption":
            _note_evidence(evidence, f"角色 {role_id} 的处置依据需要人工确认", review)
    missing = [role_id for role_id in roles if role_id not in found]
    if missing:
        blocking.append("角色没有攻击者处置：" + "、".join(sorted(missing)))
    return found


def _victims(decisions: dict[str, Any] | None, roles: dict[str, dict[str, str]], dispositions: dict[str, dict[str, Any]], blocking: list[str]) -> list[dict[str, str]]:
    if decisions is None:
        return []
    victims = []
    seen: set[tuple[str, str]] = set()
    for item in _list(decisions.get("victims"), "threat-decisions.json victims", blocking):
        if not isinstance(item, dict):
            blocking.append("候选受害者必须是对象")
            continue
        _only(item, {"role_id", "account_id", "scope"}, "候选受害者", blocking)
        role_id = _ident(item.get("role_id"), "受害者角色", blocking)
        account_id = _ident(item.get("account_id"), "受害者账号", blocking)
        scope = _scope(item.get("scope"), "受害者作用域", blocking)
        if not role_id or not account_id or not scope:
            continue
        if role_id not in roles:
            blocking.append(f"候选受害者引用了未知角色 {role_id}")
            continue
        if dispositions.get(role_id, {}).get("disposition") == "exclude":
            blocking.append(f"已排除的角色 {role_id} 不能作为候选受害者")
            continue
        if roles[role_id]["scope"] != scope:
            blocking.append(f"候选受害者 {role_id} 的作用域与角色清单不一致")
            continue
        key = (role_id, scope)
        if key in seen:
            blocking.append(f"候选受害者重复：{role_id}")
            continue
        seen.add(key)
        victims.append({"role_id": role_id, "account_id": account_id, "scope": scope})
    return victims


def _paths(
    decisions: dict[str, Any] | None,
    roles: dict[str, dict[str, str]],
    dispositions: dict[str, dict[str, Any]],
    victims: list[dict[str, str]],
    blocking: list[str],
) -> list[dict[str, Any]]:
    if decisions is None:
        return []
    victim_keys = {(item["role_id"], item["scope"]) for item in victims}
    paths = []
    seen: set[str] = set()
    for item in _list(decisions.get("paths"), "threat-decisions.json paths", blocking):
        if not isinstance(item, dict):
            blocking.append("威胁路径必须是对象")
            continue
        _only(item, {"id", "attacker_role", "victim_role", "attacker_account", "victim_account", "scope", "primary", "accept_self_xss"}, "威胁路径", blocking)
        path_id = _ident(item.get("id"), "路径 id", blocking)
        attacker = _ident(item.get("attacker_role"), "路径攻击者", blocking)
        victim = _ident(item.get("victim_role"), "路径受害者", blocking)
        attacker_account = _ident(item.get("attacker_account"), "路径攻击者账号", blocking)
        victim_account = _ident(item.get("victim_account"), "路径受害者账号", blocking)
        scope = _scope(item.get("scope"), "路径作用域", blocking)
        primary = item.get("primary")
        self_xss = item.get("accept_self_xss")
        if not path_id or not attacker or not victim or not attacker_account or not victim_account or not scope:
            continue
        if path_id in seen:
            blocking.append(f"路径 id 重复：{path_id}")
            continue
        seen.add(path_id)
        if not isinstance(primary, bool) or not isinstance(self_xss, bool):
            blocking.append(f"路径 {path_id} 的 primary 和 accept_self_xss 必须是布尔值")
            continue
        if attacker not in roles or victim not in roles:
            blocking.append(f"路径 {path_id} 引用了未知角色")
            continue
        if roles[attacker]["scope"] != scope or roles[victim]["scope"] != scope:
            blocking.append(f"路径 {path_id} 的作用域与角色清单不一致")
            continue
        disposition = dispositions.get(attacker, {}).get("disposition")
        if disposition != "include":
            blocking.append(f"路径 {path_id} 的攻击者 {attacker} 未被纳入")
        if (victim, scope) not in victim_keys:
            blocking.append(f"路径 {path_id} 的受害者不在候选列表中")
        same_account = attacker_account == victim_account
        if same_account and not self_xss:
            blocking.append(f"路径 {path_id} 的双方使用了同一个账号")
        if not same_account and self_xss:
            blocking.append(f"路径 {path_id} 不是 self-XSS，不能设置 accept_self_xss")
        paths.append({
            "id": path_id,
            "attacker_role": attacker,
            "victim_role": victim,
            "attacker_account": attacker_account,
            "victim_account": victim_account,
            "scope": scope,
            "primary": primary,
            "accept_self_xss": self_xss,
        })
    included = {role_id for role_id, item in dispositions.items() if item["disposition"] == "include"}
    used = {path["attacker_role"] for path in paths}
    missing = sorted(included - used)
    if missing:
        blocking.append("已纳入的攻击者没有路径：" + "、".join(missing))
    if paths and sum(path["primary"] for path in paths) != 1:
        blocking.append("威胁决策必须且只能有一条 primary 路径")
    if dispositions and not paths and not included:
        blocking.append("威胁决策没有任何攻击路径")
    return paths


def _boundaries(
    decisions: dict[str, Any] | None,
    roles: dict[str, dict[str, str]],
    dispositions: dict[str, dict[str, Any]],
    victims: list[dict[str, str]],
    blocking: list[str],
    review: list[dict[str, str]],
) -> list[dict[str, Any]]:
    if decisions is None:
        return []
    victim_keys = {(item["role_id"], item["scope"]) for item in victims}
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in _list(decisions.get("boundaries"), "threat-decisions.json boundaries", blocking):
        if not isinstance(item, dict):
            blocking.append("边界说明必须是对象")
            continue
        _only(item, {"attacker_role", "victim_role", "scope", "reason", "evidence"}, "边界说明", blocking)
        attacker = _ident(item.get("attacker_role"), "边界攻击者", blocking)
        victim = _ident(item.get("victim_role"), "边界受害者", blocking)
        scope = _scope(item.get("scope"), "边界作用域", blocking)
        reason = _reason(item.get("reason"), "无边界理由", blocking)
        evidence = _evidence(item.get("evidence"), "无边界说明", blocking)
        if not attacker or not victim or not scope or evidence is None or not reason:
            continue
        if any(dispositions.get(role, {}).get("disposition") == "exclude" for role in (attacker, victim)):
            blocking.append(f"无边界说明 {attacker} → {victim} 包含已排除角色")
            continue
        if attacker not in roles or victim not in roles or (victim, scope) not in victim_keys:
            blocking.append(f"无边界说明 {attacker} → {victim} 引用了未知角色或受害者")
            continue
        key = (attacker, victim, scope)
        if key in seen:
            blocking.append(f"无边界说明重复：{attacker} → {victim}")
            continue
        seen.add(key)
        found.append({"attacker_role": attacker, "victim_role": victim, "scope": scope, "reason": reason, "evidence": evidence})
        _note_evidence(evidence, f"{attacker} → {victim} 的无边界依据需要人工确认", review)
    return found


def _account_plan(accounts: dict[str, Any] | None, blocking: list[str]) -> dict[str, dict[str, Any]]:
    if accounts is None:
        return {}
    _only(accounts, {"accounts"}, "account-plan.json", blocking)
    found: dict[str, dict[str, Any]] = {}
    for item in _list(accounts.get("accounts"), "account-plan.json accounts", blocking):
        if not isinstance(item, dict):
            blocking.append("账号计划项必须是对象")
            continue
        _only(item, {"account_id", "role_id", "scope", "extra_privileges", "extra_privilege_reason"}, "账号计划", blocking)
        account_id = _ident(item.get("account_id"), "账号 id", blocking)
        role_id = _ident(item.get("role_id"), "账号角色", blocking)
        scope = _scope(item.get("scope"), "账号作用域", blocking)
        extras = item.get("extra_privileges")
        if not account_id or not role_id or not scope:
            continue
        if not isinstance(extras, list) or any(not isinstance(value, str) or not _token(value, "", []) for value in extras):
            blocking.append(f"账号 {account_id} 的 extra_privileges 必须是角色字面量数组")
            continue
        reason = item.get("extra_privilege_reason", "")
        if extras and not _reason(reason, f"账号 {account_id} 的额外权限理由", blocking):
            continue
        if not extras and reason not in {"", None}:
            if not isinstance(reason, str):
                blocking.append(f"账号 {account_id} 的额外权限理由必须是字符串")
                continue
        if account_id in found:
            blocking.append(f"账号 id 重复：{account_id}")
            continue
        found[account_id] = {"account_id": account_id, "role_id": role_id, "scope": scope, "extra_privileges": list(extras)}
    return found


def _matrix(
    roles: dict[str, dict[str, str]],
    dispositions: dict[str, dict[str, Any]],
    victims: list[dict[str, str]],
    paths: list[dict[str, Any]],
    boundaries: list[dict[str, Any]],
    blocking: list[str],
) -> None:
    covered = {(path["attacker_role"], path["victim_role"], path["scope"]) for path in paths}
    recorded = {(item["attacker_role"], item["victim_role"], item["scope"]) for item in boundaries}
    for role_id, item in dispositions.items():
        if item["disposition"] != "include":
            continue
        scope = roles[role_id]["scope"]
        candidates = [victim for victim in victims if victim["scope"] == scope and victim["role_id"] != role_id]
        if not candidates:
            blocking.append(f"已纳入的攻击者 {role_id} 没有同作用域候选受害者")
            continue
        for victim in candidates:
            key = (role_id, victim["role_id"], scope)
            if key not in covered and key not in recorded:
                blocking.append(f"格子 {role_id} → {victim['role_id']}（{scope}）既没有路径也没有无边界说明")


def _accounts_align(paths: list[dict[str, Any]], plan: dict[str, dict[str, Any]], blocking: list[str]) -> None:
    expected: dict[str, tuple[str, str]] = {}
    for path in paths:
        pairs = (
            (path["attacker_account"], path["attacker_role"], path["scope"]),
            (path["victim_account"], path["victim_role"], path["scope"]),
        )
        for account_id, role_id, scope in pairs:
            previous = expected.get(account_id)
            if previous is not None and previous != (role_id, scope):
                blocking.append(f"账号 {account_id} 在不同路径中角色不一致")
                continue
            expected[account_id] = (role_id, scope)
            account = plan.get(account_id)
            if account is None:
                blocking.append(f"账号计划缺少 {account_id}")
                continue
            if account["role_id"] != role_id or account["scope"] != scope:
                blocking.append(f"账号 {account_id} 的角色或作用域与路径不一致")
    extra = sorted(set(plan) - set(expected))
    if extra:
        blocking.append("账号计划包含路径未使用的账号：" + "、".join(extra))


def _script_reads_plan(path: Path, blocking: list[str]) -> None:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, UnicodeError, SyntaxError):
        blocking.append("create-accounts.py 无法解析，不能确认它读取 account-plan.json")
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == "account-plan.json":
            return
    blocking.append("create-accounts.py 必须读取 account-plan.json")


def _projection(paths: list[dict[str, Any]], plan: dict[str, dict[str, Any]]) -> dict[str, Any]:
    principals = [{"id": account_id} for account_id in sorted(plan)]
    threat_paths = [
        {
            "id": path["id"],
            "attacker_principal": path["attacker_account"],
            "victim_principal": path["victim_account"],
            "primary": path["primary"],
            "accept_self_xss": path["accept_self_xss"],
        }
        for path in sorted(paths, key=lambda item: item["id"])
    ]
    return {
        "principals": principals,
        "threat_paths": threat_paths,
    }


def _manifest_matches(raw: dict[str, Any] | None, projection: dict[str, Any], blocking: list[str]) -> None:
    if raw is None:
        return
    try:
        TargetManifest.from_mapping(raw)
    except ReceiptError as exc:
        blocking.append(f"receipt-manifest.json 不符合验证器契约：{exc}")
        return
    principals = []
    for item in raw.get("principals") or []:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            account_id = item.get("account_id", item["id"])
            principals.append({"id": item["id"], "account_id": account_id})
    normalized = [{"id": item["id"]} for item in sorted(principals, key=lambda item: item["id"]) if item["id"] == item["account_id"]]
    if len(normalized) != len(principals) or normalized != projection["principals"]:
        blocking.append("receipt-manifest.json 的身份不是决策中的账号投影")
    paths = []
    for item in raw.get("threat_paths") or []:
        if not isinstance(item, dict):
            continue
        paths.append({
            "id": item.get("id"),
            "attacker_principal": item.get("attacker_principal"),
            "victim_principal": item.get("victim_principal"),
            "primary": bool(item.get("primary", False)),
            "accept_self_xss": bool(item.get("accept_self_xss", False)),
        })
    if sorted(paths, key=lambda item: str(item["id"])) != projection["threat_paths"]:
        blocking.append("receipt-manifest.json 的威胁路径与决策投影不一致")


def _note_evidence(evidence: dict[str, str], message: str, review: list[dict[str, str]]) -> None:
    if evidence["kind"] in _REVIEW_KINDS:
        review.append({"code": evidence["kind"], "message": message})


def _evidence(raw: Any, label: str, blocking: list[str]) -> dict[str, str] | None:
    if not isinstance(raw, dict):
        blocking.append(f"{label} 缺少证据")
        return None
    _only(raw, {"kind", "path", "literal"}, f"{label} 的证据", blocking)
    kind = raw.get("kind")
    path = raw.get("path", "")
    literal = raw.get("literal", "")
    if kind not in _EVIDENCE_KINDS:
        blocking.append(f"{label} 的证据种类无效")
        return None
    if not isinstance(path, str) or not isinstance(literal, str):
        blocking.append(f"{label} 的证据格式无效")
        return None
    if kind == "source" and (not path or not literal):
        blocking.append(f"{label} 的源码证据必须包含路径和字面量")
        return None
    if kind != "source" and not path and not literal:
        blocking.append(f"{label} 的证据必须留下位置或字面量")
        return None
    return {"kind": kind, "path": path, "literal": literal}


def _digest(*parts: Any) -> str:
    payload = json.dumps(_canonical(parts), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        normalized = {key: _canonical(item) for key, item in value.items()}
        if isinstance(normalized.get("role_ids"), list):
            normalized["role_ids"] = sorted(normalized["role_ids"])
        return normalized
    if isinstance(value, tuple):
        return [_canonical(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [_canonical(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True))
    if isinstance(value, list):
        items = [_canonical(item) for item in value]
        if items and all(isinstance(item, dict) and "id" in item for item in items):
            return sorted(items, key=lambda item: str(item["id"]))
        if items and all(isinstance(item, dict) and {"attacker_role", "victim_role", "scope"} <= set(item) for item in items):
            return sorted(items, key=lambda item: (item["attacker_role"], item["victim_role"], item["scope"]))
        return items
    return value


def _only(raw: dict[str, Any], allowed: set[str], label: str, blocking: list[str]) -> None:
    extra = sorted(set(raw) - allowed)
    if extra:
        blocking.append(f"{label} 包含不允许的字段：" + "、".join(extra))


def _list(raw: Any, label: str, blocking: list[str]) -> list[Any]:
    if not isinstance(raw, list):
        blocking.append(f"{label} 必须是数组")
        return []
    return raw


def _ident(raw: Any, label: str, blocking: list[str]) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > 80 or any(char not in _IDENTIFIER for char in raw):
        blocking.append(f"{label} 不是有效标识")
        return ""
    return raw


def _token(raw: Any, label: str, blocking: list[str]) -> str:
    if not isinstance(raw, str) or len(raw) > 80 or not _TOKEN.fullmatch(raw):
        if label:
            blocking.append(f"{label} 不是角色字面量")
        return ""
    return raw


def _scope(raw: Any, label: str, blocking: list[str]) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > 80 or any(char not in _IDENTIFIER for char in raw):
        blocking.append(f"{label} 不是有效作用域")
        return ""
    return raw


def _reason(raw: Any, label: str, blocking: list[str]) -> str:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 2000 or any(ord(char) < 32 for char in raw):
        blocking.append(f"{label} 为空或含控制字符")
        return ""
    return raw.strip()
