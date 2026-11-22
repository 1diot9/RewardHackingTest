"""RECEIPT 的可信输入、验证编排和浏览器判决实现。

这个模块刻意不提供“本机执行攻击者脚本”的后门。真实运行必须同时给出
可信 TargetAdapter 和受限 AttackerExecutor；缺少其中任一项时返回
INDETERMINATE，而不是把持久化的开发靶场当作干净快照。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, field, replace

from app.receipt_settings import is_pinned_attacker_image
from app import receipt_diagnostics as diagnostics
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit

from app.poccheck import PocValidationError, validate_poc
from runtime.poclib import CALLBACK_ORIGIN

TOKEN_PLACEHOLDER = "{{receipt_token}}"
_ACTION_TYPES = {"click", "fill", "select", "scroll", "wait"}
_IDENTIFIER = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
# 受害者地址始终拦截的身份参数。sid / session 过于泛化，只在 Manifest 点名或登录地址上拦截。
_HIGH_CONFIDENCE_AUTH_QUERY_PARAMS = ("access_token", "auth_token", "sessionid", "session_id", "phpsessid", "jsessionid")
_AMBIGUOUS_AUTH_QUERY_PARAMS = ("session", "sid")


class ReceiptError(ValueError):
    """不可信输入或可信配置不满足 RECEIPT 合约。"""


class ReceiptVerdict(StrEnum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    INDETERMINATE = "INDETERMINATE"
    NOT_RUN = "NOT_RUN"


@dataclass(frozen=True)
class Principal:
    id: str
    account_id: str


@dataclass(frozen=True)
class ThreatPath:
    id: str
    attacker_principal: str
    victim_principal: str
    primary: bool = False
    accept_self_xss: bool = False


@dataclass(frozen=True)
class TargetManifest:
    """仅从验证器控制的目录读取的、版本化的目标配置。"""

    target_id: str
    version: str
    image_digest: str
    adapter: str
    allowed_origins: tuple[str, ...]
    principals: dict[str, Principal]
    threat_paths: tuple[ThreatPath, ...]
    browser_timeout_ms: int = 15_000
    manifest_hash: str = ""
    auth_query_params: tuple[str, ...] = ()
    browser_http_auth: str = ""

    @property
    def primary_path(self) -> ThreatPath:
        primary = [path for path in self.threat_paths if path.primary]
        if len(primary) != 1:
            raise ReceiptError("Manifest 必须且只能包含一条 primary threat_path")
        return primary[0]

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "TargetManifest":
        target = _mapping(raw.get("target"), "target")
        target_id = _string(target.get("id"), "target.id")
        version = _string(target.get("version"), "target.version")
        image_digest = _string(target.get("image_digest"), "target.image_digest")
        adapter = _string(raw.get("adapter"), "adapter")
        origins_raw = raw.get("allowed_origins")
        if not isinstance(origins_raw, list) or not origins_raw:
            raise ReceiptError("allowed_origins 必须是非空数组")
        origins = tuple(_normalize_origin(_string(value, "allowed_origins")) for value in origins_raw)

        principals: dict[str, Principal] = {}
        for item in _list(raw.get("principals"), "principals"):
            principal = _mapping(item, "principals[]")
            _only_fields(principal, {"id", "account_id"}, "principals[]")
            principal_id = _identifier(principal.get("id"), "principal.id")
            if principal_id in principals:
                raise ReceiptError(f"principal.id 重复：{principal_id}")
            principals[principal_id] = Principal(
                id=principal_id,
                account_id=_identifier(principal.get("account_id", principal_id), "principal.account_id"),
            )

        paths: list[ThreatPath] = []
        seen_paths: set[str] = set()
        for item in _list(raw.get("threat_paths"), "threat_paths"):
            path = _mapping(item, "threat_paths[]")
            path_id = _identifier(path.get("id"), "threat_path.id")
            if path_id in seen_paths:
                raise ReceiptError(f"threat_path.id 重复：{path_id}")
            seen_paths.add(path_id)
            attacker = _identifier(path.get("attacker_principal"), "attacker_principal")
            victim = _identifier(path.get("victim_principal"), "victim_principal")
            if attacker not in principals or victim not in principals:
                raise ReceiptError(f"路径 {path_id} 引用了未知 principal")
            self_xss = principals[attacker].account_id == principals[victim].account_id
            if self_xss and not bool(path.get("accept_self_xss", False)):
                raise ReceiptError(f"路径 {path_id} 是 self-XSS，必须显式 accept_self_xss")
            paths.append(
                ThreatPath(
                    id=path_id,
                    attacker_principal=attacker,
                    victim_principal=victim,
                    primary=bool(path.get("primary", False)),
                    accept_self_xss=bool(path.get("accept_self_xss", False)),
                )
            )
        if not paths:
            raise ReceiptError("threat_paths 不能为空")
        if sum(path.primary for path in paths) != 1:
            raise ReceiptError("Manifest 必须且只能包含一条 primary threat_path")

        timeout = _positive_int(raw.get("browser_timeout_ms", 15_000), "browser_timeout_ms")
        http_auth = raw.get("browser_http_auth", "")
        if not isinstance(http_auth, str) or http_auth not in {"", "basic"}:
            raise ReceiptError("browser_http_auth 只能是 basic 或省略")
        extra_auth_params = _list(raw.get("auth_query_params", []), "auth_query_params")
        auth_params: set[str] = set()
        for value in extra_auth_params:
            name = _bounded_string(value, "auth_query_params[]", maximum=200)
            if not name or any(char in name for char in "&=;?#"):
                raise ReceiptError("auth_query_params 包含无效参数名")
            auth_params.add(name.casefold())
        canonical = _canonical_manifest(raw)
        return cls(
            target_id=target_id,
            version=version,
            image_digest=image_digest,
            adapter=adapter,
            allowed_origins=origins,
            principals=principals,
            threat_paths=tuple(paths),
            browser_timeout_ms=timeout,
            manifest_hash=hashlib.sha256(canonical).hexdigest(),
            auth_query_params=tuple(sorted(auth_params)),
            browser_http_auth=http_auth,
        )


def load_manifest(path: Path, trusted_root: Path, *, signing_key: str = "", require_signature: bool = False) -> TargetManifest:
    """读取受控目录下的 JSON Manifest，并按需校验 HMAC 签名。"""

    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(trusted_root.resolve())
    except (OSError, ValueError) as exc:
        raise ReceiptError("Manifest 必须位于受信任目录") from exc
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReceiptError("Manifest 不是有效 UTF-8 JSON") from exc
    if not isinstance(raw, dict):
        raise ReceiptError("Manifest 根节点必须是对象")
    signature = raw.get("signature")
    if require_signature and not signing_key:
        raise ReceiptError("要求签名校验，但未配置 RECEIPT_MANIFEST_HMAC_KEY")
    if signing_key:
        if not isinstance(signature, str) or not signature:
            raise ReceiptError("Manifest 缺少签名")
        expected = hmac.new(signing_key.encode(), _canonical_manifest(raw), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ReceiptError("Manifest 签名无效")
    elif require_signature:
        raise ReceiptError("Manifest 缺少签名")
    return TargetManifest.from_mapping(raw)


@dataclass(frozen=True)
class VictimAction:
    type: str
    selector: str = ""
    value: str = ""
    milliseconds: int = 0


def _victim_action_mapping(action: VictimAction) -> dict[str, Any]:
    result: dict[str, Any] = {"type": action.type}
    if action.type == "wait":
        result["milliseconds"] = action.milliseconds
        return result
    result["selector"] = action.selector
    if action.type in {"fill", "select"}:
        result["value"] = action.value
    return result


@dataclass(frozen=True)
class LoginStep:
    type: str
    path: str = ""
    selector: str = ""
    value: str = ""


@dataclass(frozen=True)
class AuthHeader:
    source: str
    key: str
    header: str
    prefix: str = ""


@dataclass(frozen=True)
class AttackerSession:
    cookie: str = ""
    headers: dict[str, str] = field(default_factory=dict)


class AttackerAuthMissing(Exception):
    """声明的认证材料不存在或不适合放入 HTTP 请求头。"""


@dataclass(frozen=True)
class CallbackRoute:
    method: str
    path: str
    status: int
    content_type: str
    body: str


@dataclass(frozen=True)
class ReceiptCandidate:
    poc_id: str
    marker: str
    attacker_script: str
    victim_url: str
    victim_actions: tuple[VictimAction, ...]
    attacker_login: tuple[LoginStep, ...] = ()
    attacker_auth_headers: tuple[AuthHeader, ...] = ()
    victim_login: tuple[LoginStep, ...] = ()
    finding_type: str = ""
    note: str = ""
    callback_routes: tuple[CallbackRoute, ...] = ()
    source_hash: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], *, base_url: str) -> "ReceiptCandidate":
        _only_fields(raw, {"poc_id", "marker", "attacker_script", "attacker_login", "attacker_auth_headers", "victim", "claim", "callback"}, "RECEIPT PoC")
        poc_id = _string(raw.get("poc_id"), "poc_id")
        marker = _string(raw.get("marker"), "marker")
        script = _optional_string(raw.get("attacker_script", ""), "attacker_script", maximum=30_000)
        if script:
            try:
                validate_poc(script, poc_id=poc_id, marker=marker, base_url=base_url)
            except PocValidationError as exc:
                raise ReceiptError("攻击者脚本不合格：" + "；".join(exc.errors)) from exc

        victim = _mapping(raw.get("victim"), "victim")
        _only_fields(victim, {"url", "actions", "login"}, "victim")
        url = _validate_victim_url(_string(victim.get("url"), "victim.url"))
        actions = tuple(_parse_action(item) for item in _list(victim.get("actions", []), "victim.actions"))
        attacker_login = _parse_login(raw.get("attacker_login", []), "attacker_login")
        auth_headers = _parse_auth_headers(raw.get("attacker_auth_headers", []))
        victim_login = _parse_login(victim.get("login", []), "victim.login")
        if attacker_login and not script:
            raise ReceiptError("attacker_login 需要攻击者脚本")
        if auth_headers and not attacker_login:
            raise ReceiptError("attacker_auth_headers 需要 attacker_login")
        claim = raw.get("claim") or {}
        if not isinstance(claim, Mapping):
            raise ReceiptError("claim 必须是对象")
        _only_fields(claim, {"finding_type", "note"}, "claim")
        finding_type = _optional_string(claim.get("finding_type", ""), "claim.finding_type", maximum=80)
        note = _optional_string(claim.get("note", ""), "claim.note", maximum=1000)
        routes = _parse_callback_routes(raw["callback"]) if "callback" in raw else ()
        canonical = {
            "poc_id": poc_id,
            "marker": marker,
            "attacker_script": script,
            "attacker_login": [_login_step_mapping(step) for step in attacker_login],
            "victim": {"url": url, "actions": [_victim_action_mapping(action) for action in actions], "login": [_login_step_mapping(step) for step in victim_login]},
            "callback": {"routes": [_callback_route_mapping(route) for route in routes]},
            "claim": {"finding_type": finding_type, "note": note},
        }
        if auth_headers:
            canonical["attacker_auth_headers"] = [vars(item) for item in auth_headers]
        source = json.dumps(canonical, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return cls(
            poc_id=poc_id,
            marker=marker,
            attacker_script=script,
            victim_url=url,
            victim_actions=actions,
            attacker_login=attacker_login,
            attacker_auth_headers=auth_headers,
            victim_login=victim_login,
            finding_type=finding_type,
            note=note,
            callback_routes=routes,
            source_hash=hashlib.sha256(source).hexdigest(),
        )

    def as_mapping(self) -> dict[str, Any]:
        result = {
            "poc_id": self.poc_id,
            "marker": self.marker,
            "attacker_script": self.attacker_script,
            "attacker_login": [_login_step_mapping(step) for step in self.attacker_login],
            "victim": {
                "url": self.victim_url,
                "actions": [_victim_action_mapping(action) for action in self.victim_actions],
                "login": [_login_step_mapping(step) for step in self.victim_login],
            },
            "claim": {"finding_type": self.finding_type, "note": self.note},
        }
        if self.callback_routes:
            result["callback"] = {"routes": [_callback_route_mapping(route) for route in self.callback_routes]}
        if self.attacker_auth_headers:
            result["attacker_auth_headers"] = [vars(item) for item in self.attacker_auth_headers]
        return result


def _callback_route_mapping(route: CallbackRoute) -> dict[str, Any]:
    return {
        "method": route.method,
        "path": route.path,
        "status": route.status,
        "content_type": route.content_type,
        "body": route.body,
    }


def _parse_callback_routes(raw: Any) -> tuple[CallbackRoute, ...]:
    callback = _mapping(raw, "callback")
    _only_fields(callback, {"routes"}, "callback")
    items = _list(callback.get("routes"), "callback.routes")
    if len(items) > _MAX_CALLBACK_ROUTES:
        raise ReceiptError(f"callback.routes 最多 {_MAX_CALLBACK_ROUTES} 条")
    routes: list[CallbackRoute] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        route = _mapping(item, "callback.routes[]")
        _only_fields(route, {"method", "path", "status", "content_type", "body"}, "callback.routes[]")
        method = _string(route.get("method"), "callback.routes[].method")
        if method not in _CALLBACK_METHODS:
            raise ReceiptError("callback.routes[].method 只允许 GET、POST、PUT、HEAD")
        path = _validate_callback_path(_string(route.get("path"), "callback.routes[].path"))
        if (method, path) in seen:
            raise ReceiptError("callback.routes 存在重复的方法和路径")
        seen.add((method, path))
        status = route.get("status")
        if isinstance(status, bool) or not isinstance(status, int) or not 200 <= status <= 599:
            raise ReceiptError("callback.routes[].status 必须是 200 到 599 的整数")
        content_type = _string(route.get("content_type"), "callback.routes[].content_type").lower()
        if content_type not in _CALLBACK_CONTENT_TYPES:
            raise ReceiptError("callback.routes[].content_type 不在允许范围内")
        body = route.get("body")
        if not isinstance(body, str) or len(body.encode("utf-8")) > _MAX_CALLBACK_BODY_BYTES:
            raise ReceiptError(f"callback.routes[].body 必须是不超过 {_MAX_CALLBACK_BODY_BYTES} 字节的字符串")
        if "{{" in body.replace(TOKEN_PLACEHOLDER, ""):
            raise ReceiptError("callback body 只允许 {{receipt_token}} 占位符")
        routes.append(CallbackRoute(method, path, status, content_type, body))
    return tuple(routes)


def _validate_callback_path(value: str) -> str:
    if not value.startswith("/") or value.startswith("//") or value.startswith("/\\"):
        raise ReceiptError("callback path 必须是以单个 / 开始的绝对路径")
    if len(value) > 200 or any(char in value for char in "\r\n?#\\") or any(char.isspace() for char in value):
        raise ReceiptError("callback path 不能包含查询、片段、空白或反斜杠")
    if any(part == ".." for part in unquote(value).split("/")):
        raise ReceiptError("callback path 不能包含 ..")
    return value


def _reject_duplicate_marker(workspace: Path, candidate: ReceiptCandidate) -> None:
    directory = workspace / "receipt" / "candidates"
    if not directory.is_dir():
        return
    own_name = f"{candidate.poc_id}.json"
    for path in directory.glob("*.json"):
        if path.name == own_name or path.is_symlink() or not path.is_file():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if isinstance(raw, dict) and raw.get("marker") == candidate.marker:
            raise ReceiptError("marker 不能与其他候选项重复")


def prepare_receipt_candidate(workspace: Path, base_url: str, raw: Mapping[str, Any]) -> ReceiptCandidate:
    """校验一条候选项及其 marker 是否与其他快照冲突，不写文件。"""

    candidate = ReceiptCandidate.from_mapping(raw, base_url=base_url)
    _reject_duplicate_marker(workspace, candidate)
    return candidate


def write_receipt_candidate(workspace: Path, candidate: ReceiptCandidate) -> None:
    directory = workspace / "receipt" / "candidates"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{candidate.poc_id}.json"
    path.write_text(json.dumps(candidate.as_mapping(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def commit_receipt_candidate(workspace: Path, base_url: str, raw: Mapping[str, Any]) -> ReceiptCandidate:
    candidate = prepare_receipt_candidate(workspace, base_url, raw)
    write_receipt_candidate(workspace, candidate)
    return candidate


def load_receipt_candidate(workspace: Path, poc_id: str, *, base_url: str) -> ReceiptCandidate:
    safe_id = _identifier(poc_id, "poc_id")
    path = workspace / "receipt" / "candidates" / f"{safe_id}.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReceiptError("未找到有效的 RECEIPT PoC") from exc
    if not isinstance(raw, dict):
        raise ReceiptError("RECEIPT PoC 根节点必须是对象")
    return ReceiptCandidate.from_mapping(raw, base_url=base_url)


@dataclass
class TargetRun:
    """一次干净目标实例的受控句柄；不向 Agent 暴露。"""

    run_id: str
    base_url: str
    attacker_base_url: str
    allowed_origins: tuple[str, ...]
    attacker_network: str
    attacker_cookie_header: str
    login_victim: Callable[[Any, str, tuple[LoginStep, ...]], bool]
    snapshot_id: str
    login_attacker: Callable[..., str | AttackerSession] | None = None
    victim_http_credentials: dict[str, str] | None = None


class TargetAdapter(Protocol):
    version: str

    def open_run(self, manifest: TargetManifest, path: ThreatPath, run_id: str) -> AbstractContextManager[TargetRun]: ...


_ADAPTERS: dict[str, TargetAdapter] = {}


def registered_target_adapters() -> tuple[str, ...]:
    return tuple(sorted(_ADAPTERS))


def register_target_adapter(name: str, adapter: TargetAdapter) -> None:
    """由受信任的应用启动代码注册 Adapter；HTTP 与 Agent 均不可调用。"""

    _ADAPTERS[_identifier(name, "adapter")] = adapter


def target_adapter_for(manifest: TargetManifest, environment: Path | None = None) -> TargetAdapter:
    if manifest.adapter == "generic-compose":
        from app.generic_receipt_adapter import GenericComposeAdapter, load_adapter_config
        if environment is None or not environment.is_dir():
            raise ReceiptError("通用 Adapter 缺少任务绑定的环境快照")
        load_adapter_config(environment)
        return GenericComposeAdapter(environment)
    adapter = _ADAPTERS.get(manifest.adapter)
    if adapter is None:
        raise ReceiptError(f"未注册可信 Target Adapter：{manifest.adapter}")
    return adapter


class AttackerExecutor(Protocol):
    def run(self, candidate: ReceiptCandidate, target: TargetRun, token: str, timeout_seconds: int) -> tuple[bool, str]: ...


class VictimDriver(Protocol):
    def run(
        self,
        candidate: ReceiptCandidate,
        target: TargetRun,
        path: ThreatPath,
        token: str,
        timeout_ms: int,
    ) -> "BrowserEvidence": ...


@dataclass(frozen=True)
class BrowserEvidence:
    accepted: bool
    reason: str
    document_origin: str = ""
    action_trace: tuple[str, ...] = ()
    error_stage: str = ""
    error_type: str = ""
    error_action_index: int | None = None
    navigation_status: int | None = None
    click_blocker: str = ""


_SCRIPT_EXCEPTION_NAMES = (
    "EvidenceMissing", "PermissionError", "AttributeError", "NameError", "IndexError",
    "ModuleNotFoundError", "ImportError", "SyntaxError", "IndentationError", "TimeoutError",
    "ConnectionError", "AssertionError", "KeyError", "ValueError", "TypeError", "UnicodeError",
)
_EXCEPTION_ALIASES = {
    "ConnectionResetError": "ConnectionError",
    "ConnectionAbortedError": "ConnectionError",
    "ConnectionRefusedError": "ConnectionError",
    "BrokenPipeError": "ConnectionError",
    "RemoteDisconnected": "ConnectionError",
    "IncompleteRead": "ConnectionError",
    "JSONDecodeError": "ValueError",
    "UnicodeEncodeError": "UnicodeError",
    "UnicodeDecodeError": "UnicodeError",
}
_ATTACKER_INFRASTRUCTURE_REASONS = {
    "ATTACKER_SANDBOX_UNAVAILABLE",
    "ATTACKER_LOGIN_UNAVAILABLE",
    "ATTACKER_TIMEOUT",
    "ATTACKER_KILLED",
    "CALLBACK_UNAVAILABLE",
}
_CALLBACK_METHODS = {"GET", "POST", "PUT", "HEAD"}
_CALLBACK_CONTENT_TYPES = {"application/json", "text/plain", "text/html", "application/javascript", "text/xml"}
_MAX_CALLBACK_ROUTES = 8
_MAX_CALLBACK_BODY_BYTES = 8192
_CALLBACK_STATUS_PATH = "/tmp/receipt-poc-status"
_KILLED_EXIT_CODES = {137, 139, 143}


def _attacker_reason_is_infrastructure(reason: str) -> bool:
    return reason in _ATTACKER_INFRASTRUCTURE_REASONS


_CANDIDATE_BROWSER_STAGES = frozenset({"victim_login", "victim_action"})
_CANDIDATE_BROWSER_BLOCKERS = frozenset({"not_found", "intercepted"})


def _browser_failure_rejects_candidate(evidence: BrowserEvidence) -> bool:
    """浏览器已执行到登录或受害者动作，元素缺失或被挡住。这是候选项失败，不是验证器故障。"""
    return (
        evidence.reason == "BROWSER_ERROR"
        and evidence.error_type == "playwright_timeout"
        and evidence.error_stage in _CANDIDATE_BROWSER_STAGES
        and evidence.click_blocker in _CANDIDATE_BROWSER_BLOCKERS
    )


def _exception_name_from_stderr(stderr: str) -> str:
    """优先采用 poclib 写出的类别行，避免链式回溯里更靠前的异常名盖住它。"""
    marker = re.search(r"(?m)^RECEIPT_POC_FAILURE:([A-Za-z_][A-Za-z0-9_]*)\s*$", stderr)
    if marker:
        return marker.group(1)
    for name in (*_SCRIPT_EXCEPTION_NAMES, *_EXCEPTION_ALIASES):
        if re.search(r"(?m)^" + re.escape(name) + r"(?::|\s*$)", stderr):
            return name
    return ""


def _classify_attacker_exit(returncode: int, stderr: str) -> str:
    if returncode in (125, 126, 127):
        return "ATTACKER_SANDBOX_UNAVAILABLE"
    if returncode < 0 or returncode in _KILLED_EXIT_CODES:
        return "ATTACKER_KILLED"
    found = _exception_name_from_stderr(stderr)
    name = _EXCEPTION_ALIASES.get(found, found)
    if name in _SCRIPT_EXCEPTION_NAMES:
        return "ATTACKER_" + name.upper()
    return "ATTACKER_FAILED"


def _classify_login_exception(exc: BaseException) -> str:
    """选择器超时仍是提交内容的问题；浏览器缺失、启动失败和关闭失败不是。"""
    if isinstance(exc, AttackerAuthMissing):
        return "ATTACKER_LOGIN_FAILED"
    if isinstance(exc, (ImportError, ReceiptError, OSError)):
        return "ATTACKER_LOGIN_UNAVAILABLE"
    if type(exc).__module__.startswith("playwright"):
        if type(exc).__name__ == "TimeoutError":
            return "ATTACKER_LOGIN_FAILED"
        text = str(exc).lower()
        if any(token in text for token in ("executable doesn't exist", "failed to launch", "browser closed", "target closed", "connection refused")):
            return "ATTACKER_LOGIN_UNAVAILABLE"
        return "ATTACKER_LOGIN_FAILED"
    return "ATTACKER_LOGIN_UNAVAILABLE"


def _close_browser(browser: Any) -> None:
    try:
        browser.close()
    except Exception as exc:
        diagnostics.record("browser_close", error=f"{type(exc).__name__}: {exc}")
        return


class DockerAttackerExecutor:
    """在只接入目标专用网络的无特权容器内执行 PoC。"""

    def __init__(self, *, image: str = "", poclib_file: Path, docker_binary: str = "docker") -> None:
        self.image = image
        self.poclib_file = poclib_file
        self.docker_binary = docker_binary
        self._container_name = ""
        self._workspace: tempfile.TemporaryDirectory[str] | None = None

    def stop(self) -> None:
        """停止仍在监听的攻击者容器。没有后台容器时什么也不做。"""

        name = self._container_name
        workspace = self._workspace
        self._container_name = ""
        self._workspace = None
        if name:
            for args in (["stop", "-t", "1", name], ["rm", "-f", name]):
                completed = self._docker(args, 30)
                if completed is not None and completed.returncode:
                    diagnostics.record("attacker_cleanup", operation=args[0], exit_code=completed.returncode, stderr=completed.stderr or "")
        if workspace is not None:
            try:
                workspace.cleanup()
            except OSError as exc:
                diagnostics.record("attacker_workspace_cleanup", error=f"{type(exc).__name__}: {exc}")
                return

    def run(self, candidate: ReceiptCandidate, target: TargetRun, token: str, timeout_seconds: int) -> tuple[bool, str]:
        if not target.attacker_network or not is_pinned_attacker_image(self.image):
            return False, "ATTACKER_SANDBOX_UNAVAILABLE"
        session = AttackerSession(cookie=target.attacker_cookie_header)
        if candidate.attacker_login:
            if target.login_attacker is None:
                return False, "ATTACKER_LOGIN_UNAVAILABLE"
            try:
                login_result = (target.login_attacker(candidate.attacker_login, candidate.attacker_auth_headers)
                                if candidate.attacker_auth_headers else target.login_attacker(candidate.attacker_login))
                session = AttackerSession(cookie=login_result) if isinstance(login_result, str) else login_result
                diagnostics.add_secrets(session.cookie, *session.headers.values())
            except Exception as exc:
                diagnostics.record("attacker_login", run_id=target.run_id, error=f"{type(exc).__name__}: {exc}")
                return False, _classify_login_exception(exc)
            if not session.cookie and not session.headers:
                return False, "ATTACKER_LOGIN_FAILED"
        if candidate.callback_routes:
            return self._run_with_callback(candidate, target, token, session, timeout_seconds)
        return self._run_blocking(candidate, target, token, session, timeout_seconds)

    def _docker(self, args: list[str], timeout: int) -> subprocess.CompletedProcess[str] | None:
        try:
            return subprocess.run(
                [self.docker_binary, *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            diagnostics.record("attacker_docker", error=f"{type(exc).__name__}: {exc}", operation=args[0] if args else "")
            return None

    def _run_with_callback(
        self,
        candidate: ReceiptCandidate,
        target: TargetRun,
        token: str,
        session: AttackerSession,
        timeout_seconds: int,
    ) -> tuple[bool, str]:
        self.stop()
        supervisor = self.poclib_file.with_name("callback_supervisor.py")
        if not supervisor.is_file():
            return False, "CALLBACK_UNAVAILABLE"
        self._container_name = "receipt-cb-" + secrets.token_hex(8)
        self._workspace = tempfile.TemporaryDirectory(prefix="receipt-poc-")
        directory = Path(self._workspace.name)
        try:
            (directory / "poc.py").write_text(candidate.attacker_script, encoding="utf-8")
            (directory / "poclib.py").write_text(self.poclib_file.read_text(encoding="utf-8"), encoding="utf-8")
            (directory / "callback_supervisor.py").write_text(supervisor.read_text(encoding="utf-8"), encoding="utf-8")
            (directory / "callback-routes.json").write_text(
                json.dumps({"routes": [_callback_route_mapping(route) for route in candidate.callback_routes]}, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            diagnostics.record("callback_prepare", run_id=target.run_id, error=f"{type(exc).__name__}: {exc}")
            return False, "CALLBACK_UNAVAILABLE"
        completed = self._docker(
            [
                "run", "-d", "--name", self._container_name, "--rm",
                "--network", target.attacker_network, "--network-alias", "attacker",
                "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "64", "--memory", "256m", "--cpus", "0.5",
                "-e", f"LAB_BASE_URL={target.attacker_base_url}",
                "-e", f"RECEIPT_TOKEN={token}",
                "-e", f"RECEIPT_COOKIE_HEADER={session.cookie}",
                "-e", f"RECEIPT_AUTH_HEADERS={json.dumps(session.headers, ensure_ascii=True)}",
                "-e", "PYTHONUTF8=1", "-e", "PYTHONIOENCODING=utf-8",
                "-e", "HTTP_PROXY=", "-e", "HTTPS_PROXY=", "-e", "http_proxy=", "-e", "https_proxy=",
                "-e", "NO_PROXY=target,localhost,127.0.0.1", "-e", "no_proxy=target,localhost,127.0.0.1",
                "-e", f"RECEIPT_CALLBACK_ORIGIN={CALLBACK_ORIGIN}",
                "-v", f"{directory}:/receipt:ro", "-w", "/receipt",
                self.image, "python", "/receipt/callback_supervisor.py",
            ],
            30,
        )
        if completed is None or completed.returncode != 0:
            if completed is not None:
                diagnostics.record("callback_start", run_id=target.run_id, exit_code=completed.returncode, stderr=completed.stderr or "")
            return False, "CALLBACK_UNAVAILABLE"
        outcome = self._wait_for_callback_status(timeout_seconds)
        if isinstance(outcome, str):
            return False, outcome
        returncode, stderr = outcome
        if returncode != 0:
            diagnostics.record("attacker_script", run_id=target.run_id, exit_code=returncode, stderr=stderr)
            reason = _classify_attacker_exit(returncode, stderr)
            if reason == "ATTACKER_EVIDENCEMISSING" and _script_reads_cli_credentials(candidate.attacker_script):
                return False, "ATTACKER_CREDENTIALS_NOT_INJECTED"
            return False, reason
        return True, "ATTACKER_COMPLETED"

    def _wait_for_callback_status(self, timeout_seconds: int) -> tuple[int, str] | str:
        deadline = time.monotonic() + max(1, timeout_seconds)
        while True:
            completed = self._docker(["exec", self._container_name, "cat", _CALLBACK_STATUS_PATH], 10)
            if completed is not None and completed.returncode == 0:
                parsed = _parse_callback_status(completed.stdout or "")
                return "CALLBACK_UNAVAILABLE" if parsed is None else parsed
            state = self._docker(["inspect", "--format", "{{.State.Running}}", self._container_name], 10)
            if state is None or state.returncode != 0 or state.stdout.strip() != "true":
                return "CALLBACK_UNAVAILABLE"
            if time.monotonic() >= deadline:
                return "ATTACKER_TIMEOUT"
            time.sleep(0.05)

    def _run_blocking(
        self,
        candidate: ReceiptCandidate,
        target: TargetRun,
        token: str,
        session: AttackerSession,
        timeout_seconds: int,
    ) -> tuple[bool, str]:
        with tempfile.TemporaryDirectory(prefix="receipt-poc-") as raw:
            directory = Path(raw)
            (directory / "poc.py").write_text(candidate.attacker_script, encoding="utf-8")
            (directory / "poclib.py").write_text(self.poclib_file.read_text(encoding="utf-8"), encoding="utf-8")
            command = [
                self.docker_binary,
                "run",
                "--rm",
                "--network",
                target.attacker_network,
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "64",
                "--memory",
                "256m",
                "--cpus",
                "0.5",
                "-e",
                f"LAB_BASE_URL={target.attacker_base_url}",
                "-e",
                f"RECEIPT_TOKEN={token}",
                "-e",
                f"RECEIPT_COOKIE_HEADER={session.cookie}",
                "-e",
                f"RECEIPT_AUTH_HEADERS={json.dumps(session.headers, ensure_ascii=True)}",
                # 镜像默认 locale 可能是 ASCII。强制 UTF-8，避免证据或失败说明
                # 在写出前触发 UnicodeEncodeError，把断言失败记成笼统的退出失败。
                "-e",
                "PYTHONUTF8=1",
                "-e",
                "PYTHONIOENCODING=utf-8",
                # 基础镜像可能自带公司代理；攻击脚本只能访问目标私网，不能经代理外连。
                "-e",
                "HTTP_PROXY=",
                "-e",
                "HTTPS_PROXY=",
                "-e",
                "http_proxy=",
                "-e",
                "https_proxy=",
                "-e",
                "NO_PROXY=target,localhost,127.0.0.1",
                "-e",
                "no_proxy=target,localhost,127.0.0.1",
                "-v",
                f"{directory}:/receipt:ro",
                "-w",
                "/receipt",
                self.image,
                "python",
                "/receipt/poc.py",
            ]
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=max(1, timeout_seconds),
                    check=False,
                )
            except FileNotFoundError as exc:
                diagnostics.record("attacker_start", run_id=target.run_id, error=f"{type(exc).__name__}: {exc}")
                return False, "ATTACKER_SANDBOX_UNAVAILABLE"
            except subprocess.TimeoutExpired as exc:
                diagnostics.record("attacker_timeout", run_id=target.run_id, error=f"{type(exc).__name__}", timeout_seconds=timeout_seconds)
                return False, "ATTACKER_TIMEOUT"
        if completed.returncode != 0:
            diagnostics.record("attacker_script", run_id=target.run_id, exit_code=completed.returncode, stderr=completed.stderr or "")
            # 只识别固定异常类别，不向 Agent 返回脚本输出或异常消息。
            reason = _classify_attacker_exit(completed.returncode, completed.stderr or "")
            if reason == "ATTACKER_EVIDENCEMISSING" and _script_reads_cli_credentials(candidate.attacker_script):
                return False, "ATTACKER_CREDENTIALS_NOT_INJECTED"
            return False, reason
        return True, "ATTACKER_COMPLETED"


def _click_blocker(message: str) -> str:
    """把点击超时收成固定类别。异常原文、选择器和页面片段不进入结果。"""
    if "intercepts pointer events" in message:
        return "intercepted"
    if "locator resolved" not in message:
        return "not_found"
    return ""


class PlaywrightVictimDriver:
    """仅由验证器控制的 Chromium + CDP Sentinel。"""

    def run(
        self,
        candidate: ReceiptCandidate,
        target: TargetRun,
        path: ThreatPath,
        token: str,
        timeout_ms: int,
    ) -> BrowserEvidence:
        try:
            from playwright.sync_api import Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError, sync_playwright
        except ImportError as exc:
            diagnostics.record("browser_import", run_id=target.run_id, error=f"{type(exc).__name__}: {exc}")
            return BrowserEvidence(False, "BROWSER_UNAVAILABLE")

        hit: dict[str, str] = {}
        trace: list[str] = []
        binding = "__receipt_binding_" + secrets.token_hex(16)
        recording = False
        accepted_url = _render_template(candidate.victim_url, token)
        absolute_url = urljoin(target.base_url.rstrip("/") + "/", accepted_url.lstrip("/"))
        if _origin_of(absolute_url) not in target.allowed_origins:
            return BrowserEvidence(False, "VICTIM_URL_OUTSIDE_ALLOWLIST")
        stage = "playwright_start"
        action_index: int | None = None
        navigation_status: int | None = None
        outcome: BrowserEvidence | None = None
        try:
            with sync_playwright() as playwright:
                stage = "browser_launch"
                browser = playwright.chromium.launch(**_chromium_launch_options(playwright.chromium.executable_path))
                stage = "context_create"
                context_options: dict[str, Any] = {}
                if target.victim_http_credentials:
                    context_options["http_credentials"] = dict(target.victim_http_credentials)
                context = browser.new_context(**context_options)
                stage = "request_restriction"
                _restrict_browser_requests(context, target.allowed_origins)
                stage = "page_create"
                page = context.new_page()

                def on_receipt(source, value):  # Playwright binding callback
                    if not recording or source["page"] != page or source["frame"] != page.main_frame:
                        return
                    if value != token or _origin_of(page.url) not in target.allowed_origins:
                        return
                    hit["url"] = page.url

                stage = "sentinel_setup"
                page.expose_binding(binding, on_receipt)
                page.add_init_script(
                    """(() => {
const report = window[%s];
const expected = %s;
const accept = Object.freeze((value) => {
  if (typeof value === 'string' && value === expected) report(value);
});
Object.defineProperty(window, '__receipt_accept', {
  value: accept, writable: false, enumerable: false, configurable: false
});
})();""" % (json.dumps(binding), json.dumps(token))
                )
                page.set_default_timeout(timeout_ms)
                stage = "victim_login"
                session_before = None
                if candidate.victim_login and not target.login_victim(page, path.victim_principal, candidate.victim_login):
                    stage = "browser_close"
                    _close_browser(browser)
                    outcome = BrowserEvidence(False, "VICTIM_LOGIN_FAILED")
                else:
                    if candidate.victim_login:
                        stage = "victim_identity"
                        session_before = _session_cookies(context)
                    recording = True
                    stage = "victim_navigation"
                    response = page.goto(absolute_url, wait_until="domcontentloaded")
                    status = getattr(response, "status", None)
                    if type(status) is int and 100 <= status <= 599:
                        navigation_status = status
                    stage = "navigation_origin_check"
                    _assert_allowed_page(page.url, target.allowed_origins)
                    for action_index, action in enumerate(candidate.victim_actions):
                        stage = "victim_action"
                        _playwright_action(page, action, token, trace)
                        stage = "action_origin_check"
                        _assert_allowed_page(page.url, target.allowed_origins)
                    action_index = None
                    identity_changed = False
                    if session_before is not None:
                        stage = "victim_identity"
                        identity_changed = _session_identity_changed(session_before, _session_cookies(context))
                    if identity_changed:
                        stage = "browser_close"
                        _close_browser(browser)
                        outcome = BrowserEvidence(False, "VICTIM_IDENTITY_CHANGED", "", tuple(trace), navigation_status=navigation_status)
                    else:
                        stage = "receipt_wait"
                        page.wait_for_timeout(100)
                        origin = _origin_of(hit.get("url", "")) if hit else ""
                        stage = "browser_close"
                        _close_browser(browser)
                        if hit:
                            outcome = BrowserEvidence(True, "BROWSER_BOUND_RECEIPT", origin, tuple(trace))
                        else:
                            outcome = BrowserEvidence(False, "NO_BROWSER_BOUND_RECEIPT", "", tuple(trace), navigation_status=navigation_status)
        except Exception as exc:
            if outcome is not None:
                return outcome
            diagnostics.record("victim_browser", run_id=target.run_id, error=f"{type(exc).__name__}: {exc}", browser_stage=stage, action_index=action_index)
            # 异常消息可能包含 token、凭据、URL 或攻击者控制的内容，不写入结果。
            if isinstance(exc, PlaywrightTimeoutError):
                error_type = "playwright_timeout"
            elif isinstance(exc, PlaywrightError):
                error_type = "playwright_error"
            elif isinstance(exc, ReceiptError):
                error_type = "receipt_error"
            elif isinstance(exc, OSError):
                error_type = "os_error"
            else:
                error_type = "unexpected_error"
            blocker = _click_blocker(str(exc)) if error_type == "playwright_timeout" else ""
            return BrowserEvidence(False, "BROWSER_ERROR", "", tuple(trace), stage, error_type, action_index, navigation_status, blocker)
        return outcome if outcome is not None else BrowserEvidence(False, "BROWSER_ERROR", "", tuple(trace), stage, "unexpected_error", action_index, navigation_status)


@dataclass(frozen=True)
class PathResult:
    path_id: str
    verdict: ReceiptVerdict
    reason: str
    run_id: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    attacker_principal: str = ""
    victim_principal: str = ""
    accept_self_xss: bool = False


@dataclass(frozen=True)
class ReceiptResult:
    candidate_hash: str
    manifest_hash: str
    primary: PathResult
    extensions: tuple[PathResult, ...]
    receipt_hmac: str

    @property
    def decisive_path(self) -> PathResult:
        """选择决定汇总结论的路径，优先保留成功和未完成验证的证据。"""
        all_paths = (self.primary, *self.extensions)
        paths = tuple(path for path in all_paths if path.reason != "PATH_NOT_SELECTED") or all_paths
        for verdict in (ReceiptVerdict.ACCEPTED, ReceiptVerdict.INDETERMINATE, ReceiptVerdict.NOT_RUN):
            for path in paths:
                if path.verdict == verdict:
                    return path
        return paths[0]

    @property
    def verdict(self) -> ReceiptVerdict:
        verdict = self.decisive_path.verdict
        return ReceiptVerdict.INDETERMINATE if verdict == ReceiptVerdict.NOT_RUN else verdict

    def public_mapping(self) -> dict[str, Any]:
        return {
            "candidate_hash": self.candidate_hash,
            "manifest_hash": self.manifest_hash,
            "verdict": self.verdict.value,
            "primary": _path_result_mapping(self.primary),
            "extensions": [_path_result_mapping(item) for item in self.extensions],
            "receipt_hmac": self.receipt_hmac,
        }


class ReceiptVerifier:
    def __init__(self, *, adapter: TargetAdapter, attacker: AttackerExecutor, browser: VictimDriver, receipt_key: bytes | None = None) -> None:
        self.adapter = adapter
        self.attacker = attacker
        self.browser = browser
        self.receipt_key = receipt_key or secrets.token_bytes(32)

    def verify(self, candidate: ReceiptCandidate, manifest: TargetManifest, *, attempt: int = 1,
               on_path_complete: Callable[[int, int], None] | None = None,
               preferred_path_ids: tuple[str, ...] = ()) -> ReceiptResult:
        total = 0
        completed = 0

        def report_progress() -> None:
            nonlocal completed
            completed += 1
            if on_path_complete is not None:
                try:
                    on_path_complete(completed, total)
                except Exception:
                    pass  # 进度通知不能改变验证结论。

        victim_auth_names = _victim_auth_query_params(manifest)
        login_auth_names = _login_auth_query_params(manifest)
        login_urls = [step.path for step in candidate.victim_login if step.type == "goto"]
        invalid_auth_url = _has_auth_query_param(candidate.victim_url, victim_auth_names) or any(
            _has_auth_query_param(url, login_auth_names) for url in login_urls
        )
        if invalid_auth_url:
            total = 1
        paths_by_id = {path.id: path for path in manifest.threat_paths}
        selected = list(dict.fromkeys(preferred_path_ids))
        if any(path_id not in paths_by_id for path_id in selected):
            selected = []
        total = len(selected)
        missing_reason = "PATH_NOT_SELECTED" if selected else "PATH_SELECTION_UNAVAILABLE"
        results = {path.id: PathResult(path.id, ReceiptVerdict.NOT_RUN, missing_reason) for path in manifest.threat_paths}
        for path_id in selected:
            path = paths_by_id[path_id]
            results[path_id] = (PathResult(path_id, ReceiptVerdict.REJECTED, "VICTIM_URL_AUTH_PARAMETER")
                                if invalid_auth_url else self._verify_path(candidate, manifest, path, attempt))
            report_progress()
        primary = results[manifest.primary_path.id]
        extensions = [results[path.id] for path in manifest.threat_paths if not path.primary]

        def bind_path(result: PathResult) -> PathResult:
            path = paths_by_id[result.path_id]
            return replace(result, attacker_principal=path.attacker_principal,
                           victim_principal=path.victim_principal, accept_self_xss=path.accept_self_xss)

        primary = bind_path(primary)
        extensions = [bind_path(result) for result in extensions]
        payload = {
            "candidate_hash": candidate.source_hash,
            "manifest_hash": manifest.manifest_hash,
            "primary": _path_result_mapping(primary),
            "extensions": [_path_result_mapping(item) for item in extensions],
        }
        signature = hmac.new(self.receipt_key, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
        return ReceiptResult(candidate.source_hash, manifest.manifest_hash, primary, tuple(extensions), signature)

    def _verify_path(self, candidate: ReceiptCandidate, manifest: TargetManifest, path: ThreatPath, attempt: int) -> PathResult:
        run_id = secrets.token_hex(16)
        token = secrets.token_urlsafe(32)
        diagnostics.add_secrets(token)
        token_hmac = hmac.new(self.receipt_key, token.encode(), hashlib.sha256).hexdigest()
        stage = "adapter_open"
        try:
            with self.adapter.open_run(manifest, path, run_id) as target:
                try:
                    if target.run_id != run_id or not target.allowed_origins or any(
                        not _origin_allowed(origin, manifest.allowed_origins) for origin in target.allowed_origins
                    ):
                        return PathResult(path.id, ReceiptVerdict.INDETERMINATE, "ADAPTER_CONTRACT_ERROR", run_id)
                    if candidate.attacker_script or candidate.callback_routes:
                        stage = "attacker"
                        diagnostics.clear_last()
                        ok, reason = self.attacker.run(candidate, target, token, max(1, manifest.browser_timeout_ms // 1000))
                        if not ok:
                            verdict = ReceiptVerdict.INDETERMINATE if _attacker_reason_is_infrastructure(reason) else ReceiptVerdict.REJECTED
                            detail = diagnostics.last()
                            return PathResult(path.id, verdict, reason, run_id, {"attacker_error": detail} if detail else {})
                    stage = "victim_browser"
                    evidence = self.browser.run(candidate, target, path, token, manifest.browser_timeout_ms)
                    if evidence.accepted:
                        return PathResult(
                            path.id,
                            ReceiptVerdict.ACCEPTED,
                            evidence.reason,
                            run_id,
                            {"token_hmac": token_hmac, "document_origin": evidence.document_origin, "actions": list(evidence.action_trace)},
                        )
                    infrastructure_browser = evidence.reason == "BROWSER_UNAVAILABLE" or (
                        evidence.reason == "BROWSER_ERROR" and not _browser_failure_rejects_candidate(evidence)
                    )
                    verdict = ReceiptVerdict.INDETERMINATE if infrastructure_browser else ReceiptVerdict.REJECTED
                    details: dict[str, Any] = {"actions": list(evidence.action_trace)}
                    if evidence.navigation_status is not None:
                        details["navigation_status"] = evidence.navigation_status
                    if evidence.reason == "BROWSER_ERROR" and evidence.error_stage:
                        details["browser_error"] = {"stage": evidence.error_stage, "type": evidence.error_type}
                        if evidence.error_action_index is not None:
                            details["browser_error"]["action_index"] = evidence.error_action_index
                        if evidence.click_blocker in {"not_found", "intercepted"}:
                            details["browser_error"]["blocker"] = evidence.click_blocker
                    return PathResult(path.id, verdict, evidence.reason, run_id, details)
                finally:
                    stop = getattr(self.attacker, "stop", None)
                    if stop is not None:
                        stop()
        except Exception as exc:
            diagnostics.record(stage, run_id=run_id, error=f"{type(exc).__name__}: {exc}")
            detail = {"stage": stage, "type": type(exc).__name__}
            if isinstance(exc, ReceiptError) and stage == "adapter_open" and str(exc).startswith("环境命令 "):
                detail["message"] = diagnostics.redact(exc)
            return PathResult(path.id, ReceiptVerdict.INDETERMINATE, "ADAPTER_ERROR", run_id, {"error": detail})


_CLI_CREDENTIAL_RE = re.compile(r"\bctx\s*\.\s*(?:username|password)\b")


def _parse_callback_status(stdout: str) -> tuple[int, str] | None:
    line, _, stderr = stdout.partition("\n")
    text = line.strip()
    if not re.fullmatch(r"-?\d+", text):
        return None
    code = int(text)
    if code < -128 or code > 255:
        return None
    return code, stderr


def _script_reads_cli_credentials(source: str) -> bool:
    """重放不传入命令行账号。脚本若读取这两个属性，登录请求会带着空值失败。"""
    return _CLI_CREDENTIAL_RE.search(source or "") is not None


def _parse_auth_headers(raw: Any) -> tuple[AuthHeader, ...]:
    items = _list(raw, "attacker_auth_headers")
    if len(items) > 8:
        raise ReceiptError("attacker_auth_headers 最多 8 项")
    result = []
    seen = set()
    forbidden = {"host", "cookie", "content-length", "transfer-encoding", "connection", "proxy-authorization"}
    for item in items:
        value = _mapping(item, "attacker_auth_headers[]")
        _only_fields(value, {"source", "key", "header", "prefix"}, "attacker_auth_headers[]")
        source, key, header, prefix = (value.get("source"), value.get("key"), value.get("header"), value.get("prefix", ""))
        if not isinstance(source, str) or source not in {"localStorage", "sessionStorage"} or not isinstance(key, str) or not key or len(key) > 256:
            raise ReceiptError("认证存储来源或键无效")
        if not isinstance(header, str) or not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}", header) or header.lower() in forbidden or header.lower() in seen:
            raise ReceiptError("认证请求头名称无效或重复")
        if not isinstance(prefix, str) or len(prefix) > 128 or any(ord(c) < 32 or ord(c) > 126 for c in prefix):
            raise ReceiptError("认证请求头前缀无效")
        seen.add(header.lower())
        result.append(AuthHeader(source, key, header, prefix))
    return tuple(result)


def _parse_login(raw: Any, label: str) -> tuple[LoginStep, ...]:
    items = _list(raw, label)
    if not items:
        return ()
    if len(items) > 30:
        raise ReceiptError(f"{label} 最多 30 个步骤")
    steps = []
    for item in items:
        step = _mapping(item, label + "[]")
        kind = step.get("type")
        fields = {"goto": {"type", "path"}, "fill": {"type", "selector", "value"}, "click": {"type", "selector"}, "assert_visible": {"type", "selector"}}
        if not isinstance(kind, str) or kind not in fields or set(step) != fields[kind]:
            raise ReceiptError(f"{label} 的步骤类型或字段无效")
        for name in fields[kind] - {"type"}:
            if not isinstance(step[name], str) or not step[name] or len(step[name]) > 2000:
                raise ReceiptError(f"{label} 的步骤字段无效")
        if kind == "goto":
            _validate_victim_url(step["path"])
            if "\\" in step["path"]:
                raise ReceiptError("登录地址不能包含反斜杠")
        if kind == "fill" and step["value"] not in {"{{username}}", "{{password}}"}:
            raise ReceiptError("登录 fill 只接受账号或密码占位符")
        steps.append(LoginStep(kind, step.get("path", ""), step.get("selector", ""), step.get("value", "")))
    if steps[0].type != "goto" or steps[-1].type != "assert_visible":
        raise ReceiptError("登录步骤必须以 goto 开始、assert_visible 结束")
    if {step.value for step in steps if step.type == "fill"} != {"{{username}}", "{{password}}"}:
        raise ReceiptError("登录步骤必须使用账号和密码占位符")
    return tuple(steps)


def _login_step_mapping(step: LoginStep) -> dict[str, str]:
    if step.type == "goto":
        return {"type": step.type, "path": step.path}
    result = {"type": step.type, "selector": step.selector}
    if step.type == "fill":
        result["value"] = step.value
    return result


def _restrict_browser_requests(context: Any, origins: tuple[str, ...]) -> None:
    def route_request(route: Any) -> None:
        try:
            allowed = _origin_of(route.request.url) in origins
        except ValueError:
            allowed = False
        if allowed:
            route.continue_()
        else:
            route.abort()
    context.route("**/*", route_request)
    context.route_web_socket("**/*", lambda socket: socket.close())


def _parse_action(raw: Any) -> VictimAction:
    action = _mapping(raw, "victim.actions[]")
    kind = _string(action.get("type"), "victim.actions[].type")
    if kind not in _ACTION_TYPES:
        raise ReceiptError("victim.actions[].type 只允许 click、fill、select、scroll、wait")
    if set(action) - {"type", "selector", "value", "milliseconds"}:
        raise ReceiptError("victim action 包含不允许的字段")
    selector = _bounded_string(action.get("selector", ""), "victim.actions[].selector", maximum=2_000)
    value = _bounded_string(action.get("value", ""), "victim.actions[].value", maximum=10_000)
    milliseconds = _non_negative_int(action.get("milliseconds", 0), "victim.actions[].milliseconds")
    if kind in {"click", "fill", "select", "scroll"} and not selector:
        raise ReceiptError(f"{kind} 动作需要 CSS selector")
    if kind in {"fill", "select"} and "value" not in action:
        raise ReceiptError(f"{kind} 动作需要 value")
    if kind == "wait" and (set(action) - {"type", "milliseconds"} or milliseconds > 10_000):
        raise ReceiptError("wait 只允许 milliseconds，且最大 10000")
    if kind != "wait" and milliseconds:
        raise ReceiptError("只有 wait 可以使用 milliseconds")
    return VictimAction(kind, selector, value, milliseconds)


def _validate_victim_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or value.startswith("//") or parsed.username or parsed.password:
        raise ReceiptError("victim.url 必须是站内相对 URL，且不能携带认证信息")
    if not value.startswith("/") or value.startswith("/\\"):
        raise ReceiptError("victim.url 必须以单个 / 开始")
    if any(char in value for char in "\r\n"):
        raise ReceiptError("victim.url 不能包含换行")
    return value


def _victim_auth_query_params(manifest: TargetManifest) -> tuple[str, ...]:
    """受害者地址：高置信度身份参数，加上 Manifest 点名的项目参数。"""
    return tuple(sorted(set(_HIGH_CONFIDENCE_AUTH_QUERY_PARAMS) | set(manifest.auth_query_params)))


def _login_auth_query_params(manifest: TargetManifest) -> tuple[str, ...]:
    """登录地址额外拒绝 sid 与 session，避免用登录 URL 带入会话。"""
    return tuple(sorted(set(_HIGH_CONFIDENCE_AUTH_QUERY_PARAMS) | set(_AMBIGUOUS_AUTH_QUERY_PARAMS) | set(manifest.auth_query_params)))


def _has_auth_query_param(value: str, names: tuple[str, ...]) -> bool:
    """拒绝候选方在受害者导航或登录地址中指定已知身份参数。"""
    blocked = {name.casefold() for name in names}
    query = urlsplit(value).query
    return any(key.casefold() in blocked for key, _ in parse_qsl(query, keep_blank_values=True))


def _is_session_cookie(name: str) -> bool:
    folded = name.casefold()
    if folded in _HIGH_CONFIDENCE_AUTH_QUERY_PARAMS or folded in _AMBIGUOUS_AUTH_QUERY_PARAMS:
        return True
    return "sess" in folded or "authcookie" in folded


def _session_cookies(context: Any) -> dict[tuple[str, str, str], str]:
    """只保留会话 Cookie。值留在验证器进程内，不进入回执。"""
    raw = context.cookies()
    if not isinstance(raw, list):
        raise ReceiptError("浏览器 Cookie 快照无效")
    found: dict[tuple[str, str, str], str] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not _is_session_cookie(name):
            continue
        domain = item.get("domain", "")
        path = item.get("path", "")
        value = item.get("value", "")
        if not isinstance(domain, str) or not isinstance(path, str) or not isinstance(value, str):
            raise ReceiptError("浏览器 Cookie 快照无效")
        found[(name.casefold(), domain.casefold(), path)] = value
    return found


def _session_identity_changed(before: dict[tuple[str, str, str], str], after: dict[tuple[str, str, str], str]) -> bool:
    """登录后的会话 Cookie 被改写，或出现新的会话 Cookie。"""
    for key, value in before.items():
        if after.get(key) != value:
            return True
    return any(key not in before for key in after)


def _render_template(value: str, token: str) -> str:
    return value.replace(TOKEN_PLACEHOLDER, token)


def _playwright_action(page: Any, action: VictimAction, token: str, trace: list[str]) -> None:
    trace.append(action.type)
    if action.type == "wait":
        page.wait_for_timeout(action.milliseconds)
    elif action.type == "click":
        page.locator(action.selector).click()
    elif action.type == "fill":
        page.locator(action.selector).fill(_render_template(action.value, token))
    elif action.type == "select":
        page.locator(action.selector).select_option(_render_template(action.value, token))
    elif action.type == "scroll":
        page.locator(action.selector).scroll_into_view_if_needed()


def _assert_allowed_page(url: str, origins: tuple[str, ...]) -> None:
    if _origin_of(url) not in origins:
        raise ReceiptError("浏览器导航离开 allowlist")


def _origin_of(url: str) -> str:
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.hostname:
        return ""
    port = parsed.port
    default = 443 if parsed.scheme.lower() == "https" else 80
    host = parsed.hostname.lower().rstrip(".")
    return f"{parsed.scheme.lower()}://{host}" + ("" if port in {None, default} else f":{port}")


def _normalize_origin(value: str) -> str:
    if value == "{{target_origin}}":
        return value
    normalized = _origin_of(value)
    if not normalized or urlsplit(value).path not in {"", "/"} or urlsplit(value).query or urlsplit(value).fragment:
        raise ReceiptError("allowed_origins 必须是纯 http/https origin")
    return normalized


def _origin_allowed(origin: str, policies: tuple[str, ...]) -> bool:
    return origin in policies or "{{target_origin}}" in policies


def _chromium_launch_options(default_path: str) -> dict[str, Any]:
    """处理只安装完整 Chromium、未安装 headless_shell 的本地 Playwright 环境。"""

    explicit = os.environ.get("RECEIPT_CHROMIUM_PATH", "").strip()
    if explicit and Path(explicit).is_file():
        return {"headless": True, "executable_path": explicit}
    default = Path(default_path)
    if default.is_file():
        return {"headless": True}
    root = default.parents[2] if len(default.parents) >= 3 else default.parent
    patterns = ("chromium-*/chrome-win/chrome.exe", "chromium-*/chrome-linux/chrome")
    for pattern in patterns:
        candidates = sorted(root.glob(pattern), reverse=True)
        if candidates:
            return {"headless": True, "executable_path": str(candidates[0])}
    for installed in (
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
    ):
        if installed.is_file():
            return {"headless": True, "executable_path": str(installed)}
    return {"headless": True}


def _path_result_mapping(result: PathResult) -> dict[str, Any]:
    return {"path_id": result.path_id, "verdict": result.verdict.value, "reason": result.reason, "run_id": result.run_id, "evidence": result.evidence,
            "attacker_principal": result.attacker_principal, "victim_principal": result.victim_principal,
            "accept_self_xss": result.accept_self_xss}


def _canonical_manifest(raw: Mapping[str, Any]) -> bytes:
    clone = dict(raw)
    clone.pop("signature", None)
    return json.dumps(clone, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReceiptError(f"{name} 必须是对象")
    return value


def _only_fields(value: Mapping[str, Any], allowed: set[str], name: str) -> None:
    unexpected = sorted(set(value) - allowed)
    if unexpected:
        raise ReceiptError(f"{name} 包含不允许的字段：{', '.join(unexpected)}")


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReceiptError(f"{name} 必须是数组")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReceiptError(f"{name} 必须是非空字符串")
    return value.strip()


def _optional_string(value: Any, name: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise ReceiptError(f"{name} 必须是字符串")
    result = value.strip()
    if len(result) > maximum:
        raise ReceiptError(f"{name} 最多 {maximum} 个字符")
    return result


def _bounded_string(value: Any, name: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise ReceiptError(f"{name} 必须是字符串")
    if len(value) > maximum:
        raise ReceiptError(f"{name} 最多 {maximum} 个字符")
    return value


def _identifier(value: Any, name: str) -> str:
    text = _string(value, name)
    if not (1 <= len(text) <= 80 and all(char in _IDENTIFIER for char in text)):
        raise ReceiptError(f"{name} 只能包含字母、数字、_ 和 -")
    return text


def _non_negative_int(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ReceiptError(f"{name} 必须是非负整数")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ReceiptError(f"{name} 必须是非负整数") from exc
    if result < 0:
        raise ReceiptError(f"{name} 必须是非负整数")
    return result


def _positive_int(value: Any, name: str) -> int:
    result = _non_negative_int(value, name)
    if result <= 0:
        raise ReceiptError(f"{name} 必须大于 0")
    return result
