"""通用 Compose 目标适配器：消费初始化阶段的版本化文件契约。"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urljoin, urlsplit

from app.environment_test import _script
from app.project_import import remove_tree
from app import receipt_diagnostics as diagnostics
from app.process_bounds import STEP_PREFIX_ENV, StepTimeout, browser_runs_inprocess, mark_step, run_bounded, run_browser_job
from app.receipt import AttackerAuthMissing, AttackerSession, AuthHeader, LoginStep, ReceiptError, TargetManifest, TargetRun, ThreatPath, _origin_of

ADAPTER_NAME = "generic-compose"
# Docker Desktop 的默认地址池大约只有三十个网段。验证运行留下的网络会把它占满，
# 之后不带 --subnet 的 network create 会失败。攻击者网络改用这段专用地址。
_ATTACKER_SUBNET_INDEXES = 4096
_STALE_RECEIPT_NETWORK = re.compile(r"^receipt-[0-9a-f]{32}(?:_default|-attacker)$")
_STALE_NETWORK_SECONDS = 600


def _attacker_subnet(run_id: str, offset: int = 0) -> str:
    """从 10.240.0.0/16 切出一个 /28。这段不在 Docker Desktop 的默认地址池里。"""
    index = (int(run_id[:4], 16) + offset) % _ATTACKER_SUBNET_INDEXES
    return f"10.240.{index // 16}.{(index % 16) * 16}/28"


def _network_age_seconds(created: str, now: datetime) -> float | None:
    match = re.match(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))? ([+-]\d{4})", created.strip())
    if match is None:
        return None
    fraction = (match.group(3) or "0")[:6].ljust(6, "0")
    try:
        stamp = datetime.strptime(f"{match.group(1)} {match.group(2)}.{fraction} {match.group(4)}", "%Y-%m-%d %H:%M:%S.%f %z")
    except ValueError:
        return None
    return (now - stamp).total_seconds()


def _release_stale_receipt_networks(environment: Path, env: dict[str, str]) -> None:
    """删除超过十分钟且没有容器的验证网络，把默认地址池还给后续的 Compose。"""
    try:
        listed = _run(["docker", "network", "ls", "--format", "{{.Name}}"], environment, env, 30)
    except ReceiptError as exc:
        diagnostics.record("environment_cleanup", run_id=env.get("RECEIPT_RUN_ID", ""), error=f"{type(exc).__name__}: {exc}")
        return
    now = datetime.now(timezone.utc)
    for name in listed.splitlines():
        name = name.strip()
        if not _STALE_RECEIPT_NETWORK.fullmatch(name):
            continue
        try:
            inspected = _run(
                ["docker", "network", "inspect", name, "--format", "{{len .Containers}}|{{.Created}}"],
                environment, env, 30,
            )
        except ReceiptError:
            continue
        count, _, created = inspected.partition("|")
        age = _network_age_seconds(created, now)
        if count.strip() != "0" or age is None or age < _STALE_NETWORK_SECONDS:
            continue
        try:
            _run(["docker", "network", "rm", name], environment, env, 30)
        except ReceiptError as exc:
            diagnostics.record("environment_cleanup", run_id=env.get("RECEIPT_RUN_ID", ""), error=f"{type(exc).__name__}: {exc}")


def _create_attacker_network(environment: Path, env: dict[str, str], network: str, run_id: str) -> None:
    """创建只接目标容器的内部网络。网段冲突时换下一个，不用默认地址池。"""
    failure: ReceiptError | None = None
    for offset in range(8):
        subnet = _attacker_subnet(run_id, offset)
        try:
            _run(["docker", "network", "create", "--internal", "--subnet", subnet, network], environment, env, 60)
            return
        except ReceiptError as exc:
            failure = exc
            detail = getattr(exc, "detail", "")
            if offset < 7 and any(token in detail.lower() for token in ("overlap", "already exists")):
                continue
            raise
    if failure is not None:
        raise failure


def load_adapter_config(root: Path) -> dict[str, Any]:
    """加载初始化阶段声明的 Compose 拓扑。

    该文件只描述稳定的容器侧信息；实例地址和凭据均由每次运行写入的
    ``receipt-run.json`` 提供。认证步骤属于候选 PoC，不在这里固化。
    """
    try:
        file = root / "receipt-adapter.json"
        if file.is_symlink() or file.stat().st_size > 1_000_000:
            raise ValueError("配置文件无效")
        raw = json.loads(file.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or type(raw.get("version")) is not int or raw["version"] != 2:
            raise ValueError("version 必须为 2")
        if set(raw) != {"version", "target_service", "container_port"}:
            raise ValueError("包含不支持的字段")
        service, port = raw["target_service"], raw["container_port"]
        if not isinstance(service, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+", service):
            raise ValueError("target_service 无效")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("container_port 无效")
        return raw
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
        raise ReceiptError(f"通用 Adapter 配置无效：{exc}") from exc


def load_run_info(run_dir: Path, manifest: TargetManifest) -> dict[str, Any]:
    try:
        file = run_dir / "receipt-run.json"
        if file.is_symlink() or not file.resolve().is_relative_to(run_dir.resolve()) or file.stat().st_size > 1_000_000:
            raise ValueError("运行文件路径无效")
        raw = json.loads(file.read_text(encoding="utf-8"))
        url = urlsplit(raw["base_url"])
        if url.scheme != "http" or url.hostname != "127.0.0.1" or not url.port or url.path not in {"", "/"} or url.query or url.fragment or url.username or url.password:
            raise ValueError("base_url 必须是带端口的 127.0.0.1 HTTP 地址")
        accounts = raw["accounts"]
        for account_id in {account for path in manifest.threat_paths for account in (path.attacker_account, path.victim_account)}:
            account = accounts[account_id]
            if any(not isinstance(account.get(key), str) or not account[key] for key in ("username", "password")):
                raise ValueError("账号缺少凭据")
        return raw
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ReceiptError("运行信息无效或缺少 Manifest 对应账号") from exc


def _run(command: list[str], cwd: Path, env: dict[str, str], timeout: int) -> str:
    stage = " ".join(Path(part).name if index < 2 else part for index, part in enumerate(command[:3]))
    def register_accounts() -> None:
        try:
            run_info = json.loads((Path(env["RECEIPT_RUN_DIR"]) / "receipt-run.json").read_text(encoding="utf-8"))
            for account in run_info.get("accounts", {}).values():
                diagnostics.add_secrets(account.get("username", ""), account.get("password", ""))
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            pass
    try:
        result = run_bounded(command, timeout, stage, cwd=cwd, env=env)
        if result.returncode:
            register_accounts()
            diagnostics.record("environment_command", run_id=env.get("RECEIPT_RUN_ID", ""), command=stage,
                               exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
            error = ReceiptError(f"环境命令 {stage} 退出码 {result.returncode}")
            error.detail = result.stderr or result.stdout or ""
            raise error
        return result.stdout.strip()
    except StepTimeout as exc:
        register_accounts()
        diagnostics.record("environment_command", run_id=env.get("RECEIPT_RUN_ID", ""), command=stage,
                           error=f"{type(exc).__name__}: {exc.step}", timeout_seconds=timeout, step=exc.step)
        raise ReceiptError(f"环境命令 {stage} 超时（{timeout} 秒）") from exc
    except OSError as exc:
        diagnostics.record("environment_command", run_id=env.get("RECEIPT_RUN_ID", ""), command=stage, error=f"{type(exc).__name__}: {exc}")
        raise ReceiptError(f"环境命令 {stage} 启动失败：{type(exc).__name__}") from exc


def page_http_credentials(mode: str, account: dict[str, str]) -> dict[str, str] | None:
    """Credentials for a browser that must answer an HTTP Basic challenge as this account.

    Attacker scripts do not receive these credentials. An unauthenticated script
    stays unauthenticated, and a logged-in script uses its declared session.
    """
    if mode != "basic":
        return None
    return {"username": account["username"], "password": account["password"]}


def _wait_until_visible(page: Any, selector: str, timeout_ms: int, step: str, index: int) -> None:
    """在截止时间前轮询可见性。

    locator.wait_for 会等当前导航结束。单页应用注册 service worker 后，
    这次导航的 load 可能一直不来，Playwright 自己的超时也就不返回。
    is_visible 不等待导航，截止时间由本进程计算。
    """
    locator = page.locator(selector).first
    deadline = time.monotonic() + max(0.05, timeout_ms / 1000)
    while True:
        if locator.is_visible():
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise StepTimeout(step, timeout_ms / 1000, index)
        time.sleep(min(0.1, remaining))


def _login(
    page: Any,
    base_url: str,
    steps: tuple[LoginStep, ...],
    account: dict[str, str],
    timeout_ms: int = 15_000,
) -> bool:
    """执行候选 PoC 提交的受限认证步骤。"""
    prefix = os.environ.get(STEP_PREFIX_ENV) or "login"
    for index, step in enumerate(steps):
        kind = step.type
        mark_step(f"{prefix}.{kind}", index)
        try:
            if kind == "goto":
                page.goto(urljoin(base_url, step.path), wait_until="domcontentloaded")
            elif kind == "fill":
                page.locator(step.selector).fill(account["username" if step.value == "{{username}}" else "password"])
            elif kind == "click":
                # 登录提交通常只触发前端跳转，不会完成一次文档 load。
                # 点击若等待这次 load，驱动会一直占着，后面的可见性检查无法开始。
                page.locator(step.selector).click(no_wait_after=True)
            else:
                # A visibility assertion is an existence check, not an assertion
                # that a page contains exactly one matching element.  The attacker
                # may legitimately add another dashboard section before the victim
                # logs in, making common selectors such as `.there-are-items`
                # plural.  Keep fill/click strict, but accept the first visible
                # matching element for an explicit `assert_visible` login step.
                _wait_until_visible(page, step.selector, timeout_ms, f"{prefix}.{kind}", index)
        except StepTimeout:
            raise
        except Exception as exc:
            if type(exc).__name__ == "TimeoutError":
                raise StepTimeout(f"{prefix}.{kind}", 0, index) from exc
            raise
        mark_step(f"{prefix}.origin", index)
        if _origin_of(page.url) != _origin_of(base_url):
            raise ReceiptError("登录跳转超出目标来源")
    return True


def _login_cookie_header(
    base_url: str,
    steps: tuple[LoginStep, ...],
    account: dict[str, str],
    timeout_ms: int,
    auth_headers: tuple[AuthHeader, ...] = (),
    http_credentials: dict[str, str] | None = None,
    *,
    settle: Callable[[dict[str, Any]], None] | None = None,
) -> str | AttackerSession:
    """为受信任路径中的攻击者身份建立一次短暂的浏览器 Cookie 会话。"""
    if not browser_runs_inprocess():
        return _login_cookie_header_bounded(base_url, steps, account, timeout_ms, auth_headers, http_credentials)
    try:
        from playwright.sync_api import sync_playwright
        from app.receipt import _chromium_launch_options
    except ImportError as exc:
        raise ReceiptError("攻击者登录浏览器不可用") from exc
    def emit(payload: dict[str, Any]) -> None:
        if settle is None:
            return
        try:
            settle(payload)
        except Exception:
            return

    with sync_playwright() as playwright:
        mark_step("attacker_login.launch")
        browser = playwright.chromium.launch(**_chromium_launch_options(playwright.chromium.executable_path))
        try:
            context_options: dict[str, Any] = {}
            if http_credentials:
                context_options["http_credentials"] = http_credentials
            context = browser.new_context(**context_options)
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            try:
                _login(page, base_url, steps, account, timeout_ms=timeout_ms)
                mark_step("attacker_login.cookies")
                cookies = context.cookies(base_url)
                cookie = "; ".join(f"{item['name']}={item['value']}" for item in cookies)
                if not auth_headers:
                    emit({"kind": "cookie", "cookie": cookie})
                    return cookie
                headers = {}
                for item in auth_headers:
                    mark_step("attacker_login.storage")
                    value = page.evaluate("([source, key]) => window[source].getItem(key)", [item.source, item.key])
                    if not isinstance(value, str) or not value or len(value) > 8192 or any(ord(c) < 32 or ord(c) > 126 for c in value):
                        raise AttackerAuthMissing("声明的认证材料不存在或无效")
                    headers[item.header] = item.prefix + value
                emit({"kind": "session", "cookie": cookie, "headers": headers})
                return AttackerSession(cookie, headers)
            except StepTimeout as exc:
                emit({"timeout": True, "step": exc.step, "index": exc.index, "timeout_seconds": max(1, timeout_ms // 1000)})
                raise
            except AttackerAuthMissing:
                emit({"kind": "error", "error": "AttackerAuthMissing"})
                raise
        finally:
            try:
                mark_step("attacker_login.close")
                browser.close()
            except Exception as exc:
                diagnostics.record("attacker_browser_close", error=f"{type(exc).__name__}: {exc}")


def _login_cookie_header_bounded(
    base_url: str,
    steps: tuple[LoginStep, ...],
    account: dict[str, str],
    timeout_ms: int,
    auth_headers: tuple[AuthHeader, ...],
    http_credentials: dict[str, str] | None,
) -> str | AttackerSession:
    result = run_browser_job(
        {
            "op": "attacker_login",
            "base_url": base_url,
            "steps": [{"type": step.type, "path": step.path, "selector": step.selector, "value": step.value} for step in steps],
            "account": account,
            "timeout_ms": timeout_ms,
            "auth_headers": [
                {"source": item.source, "key": item.key, "header": item.header, "prefix": item.prefix}
                for item in auth_headers
            ],
            "http_credentials": http_credentials,
        },
        timeout_ms,
    )
    if result.get("timeout"):
        index = result.get("index")
        raise StepTimeout(str(result.get("step") or "attacker_login"), float(result.get("timeout_seconds") or 1), index if type(index) is int else None)
    if result.get("kind") == "cookie":
        return str(result.get("cookie") or "")
    if result.get("kind") == "session":
        headers = result.get("headers")
        if not isinstance(headers, dict):
            raise ReceiptError("攻击者登录浏览器不可用")
        return AttackerSession(str(result.get("cookie") or ""), {str(key): str(value) for key, value in headers.items()})
    if result.get("error") == "AttackerAuthMissing":
        raise AttackerAuthMissing("声明的认证材料不存在或无效")
    raise ReceiptError("攻击者登录浏览器不可用")


class GenericComposeAdapter:
    version = "generic-compose-2"

    def __init__(self, environment: Path) -> None:
        self.environment = environment

    @contextmanager
    def open_run(self, manifest: TargetManifest, path: ThreatPath, run_id: str) -> Iterator[TargetRun]:
        if not re.fullmatch(r"[0-9a-f]{32}", run_id):
            raise ReceiptError("运行标识无效")
        config = load_adapter_config(self.environment)
        with tempfile.TemporaryDirectory(prefix="receipt-run-", ignore_cleanup_errors=True) as temp:
            root = Path(temp)
            environment = root / "environment"
            shutil.copytree(self.environment, environment, symlinks=False)
            run_dir = root / "run"
            run_dir.mkdir()
            project = "receipt-" + run_id
            network = project + "-attacker"
            env = {**os.environ, "RECEIPT_RUN_ID": run_id, "RECEIPT_RUN_DIR": str(run_dir), "COMPOSE_PROJECT_NAME": project}
            start = _script(environment, "start")
            network_created = False
            network_connected = False
            try:
                _release_stale_receipt_networks(environment, env)
                _run(start, environment, env, 300)
                if "ENVIRONMENT_READY" not in _run([*start, "--verify"], environment, env, 300).splitlines():
                    raise ReceiptError("环境健康检查未通过")
                accounts_script = _script(environment, "create-accounts")
                _run(accounts_script, environment, env, 300)
                if "ACCOUNTS_VERIFIED" not in _run([*accounts_script, "--verify"], environment, env, 300).splitlines():
                    raise ReceiptError("账号验证未通过")
                info = load_run_info(run_dir, manifest)
                for account in info["accounts"].values():
                    diagnostics.add_secrets(account.get("username", ""), account.get("password", ""))
                base_url = info["base_url"]
                container = _run(["docker", "compose", "-p", project, "ps", "-q", config["target_service"]], environment, env, 60)
                if not re.fullmatch(r"[0-9a-f]{12,64}", container):
                    raise ReceiptError("目标服务不是单一容器")
                published = _run(["docker", "compose", "-p", project, "port", config["target_service"], str(config["container_port"])], environment, env, 60)
                if published != f"127.0.0.1:{urlsplit(base_url).port}":
                    raise ReceiptError("目标地址与 Compose 端口映射不一致")
                _create_attacker_network(environment, env, network, run_id)
                network_created = True
                _run(["docker", "network", "connect", "--alias", "target", network, container], environment, env, 60)
                network_connected = True

                def account_for(account_id: str) -> dict[str, str]:
                    return info["accounts"][account_id]

                def login_attacker(steps: tuple[LoginStep, ...], auth_headers: tuple[AuthHeader, ...] = ()) -> str | AttackerSession:
                    if not steps:
                        return ""
                    attacker = account_for(path.attacker_account)
                    args = (
                        base_url,
                        steps,
                        attacker,
                        manifest.browser_timeout_ms,
                    )
                    credentials = page_http_credentials(manifest.browser_http_auth, attacker)
                    if auth_headers and credentials:
                        return _login_cookie_header(*args, auth_headers, http_credentials=credentials)
                    if auth_headers:
                        return _login_cookie_header(*args, auth_headers)
                    if credentials:
                        return _login_cookie_header(*args, http_credentials=credentials)
                    return _login_cookie_header(*args)

                def login_victim(page: Any, principal_id: str, steps: tuple[LoginStep, ...]) -> bool:
                    if principal_id != path.victim_account:
                        return False
                    if not steps:
                        return True
                    return _login(page, base_url, steps, account_for(principal_id), timeout_ms=manifest.browser_timeout_ms)

                yield TargetRun(
                    run_id=run_id,
                    base_url=base_url,
                    attacker_base_url=f"http://target:{config['container_port']}/",
                    allowed_origins=(_origin_of(base_url),),
                    attacker_network=network,
                    attacker_cookie_header="",
                    login_victim=login_victim,
                    snapshot_id=project,
                    login_attacker=login_attacker,
                    victim_http_credentials=page_http_credentials(
                        manifest.browser_http_auth, account_for(path.victim_account)
                    ),
                    victim_account=account_for(path.victim_account),
                )
            finally:
                # 清理异常若继续抛出，会盖住 with 块里已经返回的路径结论，
                # 调用方只能把它记成 ADAPTER_ERROR。启动阶段的原始错误同样会被换掉。
                commands: list[list[str]] = []
                if network_connected:
                    commands.append(["docker", "network", "disconnect", network, container])
                if network_created:
                    commands.append(["docker", "network", "rm", network])
                commands.append([*start, "--cleanup"])
                for command in commands:
                    try:
                        _run(command, environment, env, 120 if command[-1] == "--cleanup" else 30)
                    except ReceiptError as exc:
                        diagnostics.record("environment_cleanup", run_id=run_id, error=f"{type(exc).__name__}: {exc}")
                        continue
                try:
                    remove_tree(root)
                except OSError as exc:
                    diagnostics.record("environment_cleanup", run_id=run_id, error=f"{type(exc).__name__}: {exc}")
