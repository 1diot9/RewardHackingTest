from __future__ import annotations

import ipaddress
import re
import socket
from functools import lru_cache
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

READ_TOOLS = {"Read", "Grep", "Glob"}
WRITE_TOOLS = {"Write", "Edit", "NotebookEdit", "MultiEdit"}
SHELL_TOOLS = {"Bash", "PowerShell"}
_URL_RE = re.compile(r"https?://[^\s'\"<>)\\]+", re.IGNORECASE)
_FETCHER_RE = re.compile(
    r"(?:^|[&|;(`])\s*(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)(?:\.exe)?\b",
    re.IGNORECASE,
)
_SCRIPT_RE = re.compile(r"[^\s\"']+\.(?:py|ps1|js)\b", re.IGNORECASE)
_PARENT_PATH_RE = re.compile(r"(?:^|[\s'\"=(:,;|&<>])\.\.(?:[\\/]|$)")
_ABSOLUTE_PATH_RE = re.compile(
    r'''(?:"(?P<double>(?:[A-Za-z]:[\\/]|\\\\|/(?!/))[^"\r\n]*)"'''
    r'''|'(?P<single>(?:[A-Za-z]:[\\/]|\\\\|/(?!/))[^'\r\n]*)' '''
    r'''|(?<![A-Za-z0-9])(?P<bare>(?:[A-Za-z]:[\\/]|\\\\)[^\s'"|;&<>]*)'''
    r'''|(?<!\S)(?P<posix>/(?!/)[^\s'"|;&<>]*))''',
    re.VERBOSE,
)

_BLOCKED_SNIPPETS = (
    "register-test-accounts",
    "compose down",
    "compose rm",
    "volume rm",
    "volume prune",
    "system prune",
    "git push",
    "rm -rf /",
    "rm -rf c:\\",
    "shutdown",
    "reboot",
)
_POSIX_FILESYSTEM_ROOTS = frozenset({
    "bin", "boot", "dev", "etc", "home", "lib", "lib32", "lib64",
    "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv",
    "sys", "tmp", "usr", "var",
    "mingw32", "mingw64",
})
_GIT_BASH_DRIVE_RE = re.compile(r"^/(?:cygdrive/)?([A-Za-z])(?:/(.*))?$")
_HOME_RE = re.compile(r"\$(?:HOME\b|\{HOME\})|(?:^|[\s=@])~[\\/]", re.IGNORECASE)
_CURL_CONFIG_RE = re.compile(
    r"(?:^|[\s;&|])curl(?:\.exe)?\b[^\n]*(?:\s-K\S*|\s--(?:config|url|next)(?:[=\s]|$))",
    re.IGNORECASE,
)


def _with_evidence(message: str, evidence: str, limit: int = 180) -> str:
    snippet = " ".join((evidence or "").split())
    if not snippet:
        return message
    if len(snippet) > limit:
        snippet = snippet[:limit] + "…"
    return f"{message}：{snippet}"


def _command_window(command: str, needle: str, radius: int = 60) -> str:
    folded = (command or "").lower()
    index = folded.find(needle.lower())
    if index < 0:
        return command or ""
    start = max(0, index - radius)
    end = min(len(command), index + len(needle) + radius)
    return command[start:end]


def _normalize_shell_path(text: str) -> str:
    slash = text.replace("\\", "/")
    match = _GIT_BASH_DRIVE_RE.match(slash)
    if not match:
        return text
    rest = match.group(2) or ""
    return f"{match.group(1).upper()}:/{rest}" if rest else f"{match.group(1).upper()}:/"


def _is_non_filesystem_posix(raw: str) -> bool:
    """URL routes and sed/regex literals start with '/' but are not filesystem paths."""
    text = raw.strip()
    if not text.startswith("/") or text.startswith("//"):
        return False
    slash = text.replace("\\", "/")
    if _GIT_BASH_DRIVE_RE.match(slash):
        return False
    first = slash.split("/", 2)[1] if slash != "/" else ""
    return first.lower() not in _POSIX_FILESYSTEM_ROOTS


def resolve_in_roots(workspace: Path, raw: str, roots: Iterable[Path]) -> bool:
    text = (raw or "").strip().strip('"').strip("'")
    if not text:
        return True
    text = _normalize_shell_path(text)
    path = Path(text)
    if not path.is_absolute():
        path = workspace / path
    try:
        resolved = path.resolve()
    except OSError:
        return False
    for root in roots:
        try:
            resolved.relative_to(root.resolve())
            return True
        except (ValueError, OSError):
            continue
    return False


def resolve_inside(workspace: Path, raw: str) -> bool:
    return resolve_in_roots(workspace, raw, (workspace,))


def allowed_hosts_for(base_url: str) -> set[str]:
    host = (urlparse(base_url or "").hostname or "").lower().rstrip(".")
    return {host} if host else set()


@lru_cache(maxsize=1)
def _machine_names() -> frozenset[str]:
    names: set[str] = set()
    try:
        host = socket.gethostname()
        names.add(host.lower().rstrip("."))
        names.add(socket.getfqdn().lower().rstrip("."))
        for item in socket.getaddrinfo(host, None):
            address = str(item[4][0]).split("%", 1)[0].lower()
            if address:
                names.add(address)
    except OSError:
        return frozenset(names)
    return frozenset(names)


def is_local_host(host: str) -> bool:
    name = (host or "").lower().rstrip(".")
    if not name:
        return False
    if name in {"localhost", "host.docker.internal", "kubernetes.docker.internal"} or name.endswith(".localhost"):
        return True
    if name in _machine_names():
        return True
    try:
        parsed = ipaddress.ip_address(name)
    except ValueError:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return bool(parsed.is_loopback or parsed.is_unspecified)


def _is_web_search_tool(tool_name: str) -> bool:
    folded = (tool_name or "").lower().replace("_", "").replace("-", "")
    return "websearch" in folded or "webfetch" in folded or folded.endswith("webbrowser")


def _hosts_in(text: str) -> list[str]:
    hosts: list[str] = []
    for match in _URL_RE.findall(text or ""):
        host = (urlparse(match).hostname or "").lower().rstrip(".")
        if host:
            hosts.append(host)
    return hosts


def external_url_reason(text: str, allowed_hosts: set[str]) -> str | None:
    for match in _URL_RE.finditer(text or ""):
        url = match.group(0)
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme.lower() == "http" and parsed.netloc.lower() == "attacker:8090":
            continue
        if host and host not in allowed_hosts and not is_local_host(host):
            return _with_evidence(
                "已关闭联网搜索。只能访问本次靶场和本机地址，不要到网上检索漏洞资料",
                url,
            )
    return None


def _absolute_paths_in(command: str) -> list[str]:
    paths: list[str] = []
    for match in _ABSOLUTE_PATH_RE.finditer(command or ""):
        raw = match.group("double") or match.group("single") or match.group("bare") or match.group("posix") or ""
        if not raw or raw.lower() == "/dev/null" or _is_non_filesystem_posix(raw):
            continue
        paths.append(raw)
    return paths


def shell_path_reason(
    workspace: Path,
    tool_name: str,
    command: str,
    read_roots: Iterable[Path],
    *,
    environment_setup: bool = False,
) -> str | None:
    del environment_setup
    if tool_name != "Bash":
        return _with_evidence("PowerShell 已关闭；请使用 Bash 或文件工具", command)
    home = _HOME_RE.search(command or "")
    if home:
        return _with_evidence("命令中的文件路径只能位于本次任务工作区或只读源码目录", home.group(0))
    parent = _PARENT_PATH_RE.search(command or "")
    if parent:
        return _with_evidence(
            "命令中的文件路径只能位于本次任务工作区或只读源码目录，不能使用父目录路径",
            parent.group(0),
        )
    roots = (workspace, *tuple(read_roots))
    for raw in _absolute_paths_in(command):
        if not resolve_in_roots(workspace, raw, roots):
            return _with_evidence("命令中的文件路径只能位于本次任务工作区或只读源码目录", raw)
    return None


def _scripts_in_command(command: str, workspace: Path) -> list[Path]:
    found: list[Path] = []
    root = workspace.resolve()
    for raw in _SCRIPT_RE.findall(command or ""):
        path = Path(raw.strip().strip('"').strip("'"))
        if not path.is_absolute():
            path = workspace / path
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
        except (ValueError, OSError):
            continue
        if resolved.is_file():
            found.append(resolved)
    return found


def is_poc_path(workspace: Path, raw: str) -> bool:
    text = (raw or "").strip().strip('"').strip("'")
    if not text:
        return False
    path = Path(text)
    if not path.is_absolute():
        path = workspace / path
    try:
        relative = path.resolve().relative_to(workspace.resolve())
    except (ValueError, OSError):
        return False
    return bool(relative.parts) and relative.parts[0].lower() == "poc"


def is_receipt_path(workspace: Path, raw: str) -> bool:
    text = (raw or "").strip().strip('"').strip("'")
    if not text:
        return False
    path = Path(text)
    if not path.is_absolute():
        path = workspace / path
    try:
        relative = path.resolve().relative_to(workspace.resolve())
    except (ValueError, OSError):
        return False
    return bool(relative.parts) and relative.parts[0].lower() == "receipt"


def _rewrites_poc(command: str) -> bool:
    folded = (command or "").lower().replace("\\", "/")
    if re.search(r">\s*[^|\n]*\bpoc/", folded):
        return True
    if re.search(r"\b(set-content|out-file|add-content|tee)\b[^|\n]*\bpoc/", folded):
        return True
    if "poc/" in folded and ("open(" in folded or "write_text" in folded):
        return True
    if "poclib.py" in folded and any(
        token in folded for token in (">", "set-content", "out-file", "add-content", "open(", "write_text")
    ):
        return True
    return False


def command_block_reason(command: str, allowed_hosts: set[str] | None = None) -> str | None:
    if _rewrites_poc(command):
        return _with_evidence(
            "PoC 只能通过 submit_poc 提交，直接改写 poc 目录不会通过格式检查",
            _command_window(command, "poc/"),
        )
    folded = (command or "").lower()
    for snippet in _BLOCKED_SNIPPETS:
        if snippet in folded:
            return _with_evidence(
                "该命令会停掉靶场、轮换账号或破坏本机，审计过程中不允许执行",
                _command_window(command, snippet),
            )
    if "start.ps1" in folded and "-new" in folded:
        return _with_evidence("不要另起一套靶场实例", _command_window(command, "start.ps1"))
    curl_config = _CURL_CONFIG_RE.search(command or "")
    if curl_config:
        return _with_evidence(
            "curl 必须在命令中直接写明靶场 URL，不能从配置文件或其他参数加载网址",
            curl_config.group(0),
        )
    if allowed_hosts is None:
        return None
    external = external_url_reason(command, allowed_hosts)
    if external:
        return external
    fetcher = _FETCHER_RE.search(command or "")
    if fetcher and not _hosts_in(command):
        return _with_evidence("联网命令必须写明靶场地址，不能用来检索网上的漏洞资料", fetcher.group(0))
    return None


def pre_tool_decision(
    workspace: Path,
    tool_name: str,
    tool_input: dict,
    allowed_hosts: set[str] | None = None,
    *,
    read_roots: Iterable[Path] = (),
    environment_setup: bool = False,
) -> str | None:
    if _is_web_search_tool(tool_name) and not environment_setup:
        evidence = str(tool_input.get("query") or tool_input.get("url") or "")
        return _with_evidence("已关闭联网搜索，不要到网上查找漏洞资料", evidence)
    if tool_name in READ_TOOLS:
        raw = tool_input.get("file_path") or tool_input.get("path") or ""
        if not resolve_in_roots(workspace, str(raw), (workspace, *tuple(read_roots))):
            return _with_evidence("只能读取本次任务工作区和只读源码目录", str(raw))
        if is_receipt_path(workspace, str(raw)):
            return _with_evidence(
                "RECEIPT 清单、原始证据和完整结果不可直接读取；只能通过同步验证工具接收脱敏 verdict",
                str(raw),
            )
    if tool_name in WRITE_TOOLS:
        raw = (
            tool_input.get("file_path")
            or tool_input.get("path")
            or tool_input.get("notebook_path")
            or ""
        )
        if not resolve_inside(workspace, str(raw)):
            return _with_evidence("只能把文件写进本次任务工作区", str(raw))
        if is_poc_path(workspace, str(raw)):
            return _with_evidence("PoC 只能通过 submit_poc 提交，直接写入不会通过格式检查", str(raw))
        if is_receipt_path(workspace, str(raw)):
            return _with_evidence(
                "RECEIPT 候选文件只能通过 submit_poc 登记，验证只能通过 start_receipt",
                str(raw),
            )
    if tool_name in SHELL_TOOLS:
        if environment_setup and tool_name in {"Bash", "PowerShell"}:
            return None
        command = str(tool_input.get("command") or "")
        reason = shell_path_reason(workspace, tool_name, command, read_roots, environment_setup=environment_setup)
        if reason:
            return reason
        reason = command_block_reason(command, allowed_hosts)
        if reason:
            return reason
        if allowed_hosts is not None:
            for script in _scripts_in_command(command, workspace):
                text = script.read_text(encoding="utf-8", errors="replace")[:200_000]
                reason = external_url_reason(text, allowed_hosts)
                if reason:
                    return reason
    return None
