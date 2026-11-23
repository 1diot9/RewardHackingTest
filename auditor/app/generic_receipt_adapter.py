"""通用 Compose 目标适配器：消费初始化阶段的版本化文件契约。"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urljoin, urlsplit

from app.environment_test import _script
from app.project_import import remove_tree
from app import receipt_diagnostics as diagnostics
from app.process_bounds import STEP_PREFIX_ENV, StepTimeout, browser_runs_inprocess, mark_step, run_bounded, run_browser_job
from app.receipt import AttackerAuthMissing, AttackerSession, AuthHeader, LoginStep, ReceiptError, TargetManifest, TargetRun, ThreatPath, _origin_of

ADAPTER_NAME = "generic-compose"


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
        for principal in manifest.principals.values():
            account = accounts[principal.account_id]
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
            raise ReceiptError(f"环境命令 {stage} 退出码 {result.returncode}")
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


def _login(page: Any, base_url: str, steps: tuple[LoginStep, ...], account: dict[str, str]) -> bool:
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
                page.locator(step.selector).click()
            else:
                # A visibility assertion is an existence check, not an assertion
                # that a page contains exactly one matching element.  The attacker
                # may legitimately add another dashboard section before the victim
                # logs in, making common selectors such as `.there-are-items`
                # plural.  Keep fill/click strict, but accept the first visible
                # matching element for an explicit `assert_visible` login step.
                page.locator(step.selector).first.wait_for(state="visible")
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
) -> str | AttackerSession:
    """为受信任路径中的攻击者身份建立一次短暂的浏览器 Cookie 会话。"""
    if not browser_runs_inprocess():
        return _login_cookie_header_bounded(base_url, steps, account, timeout_ms, auth_headers, http_credentials)
    try:
        from playwright.sync_api import sync_playwright
        from app.receipt import _chromium_launch_options
    except ImportError as exc:
        raise ReceiptError("攻击者登录浏览器不可用") from exc
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
            _login(page, base_url, steps, account)
            mark_step("attacker_login.cookies")
            cookies = context.cookies(base_url)
            cookie = "; ".join(f"{item['name']}={item['value']}" for item in cookies)
            if not auth_headers:
                return cookie
            headers = {}
            for item in auth_headers:
                mark_step("attacker_login.storage")
                value = page.evaluate("([source, key]) => window[source].getItem(key)", [item.source, item.key])
                if not isinstance(value, str) or not value or len(value) > 8192 or any(ord(c) < 32 or ord(c) > 126 for c in value):
                    raise AttackerAuthMissing("声明的认证材料不存在或无效")
                headers[item.header] = item.prefix + value
            return AttackerSession(cookie, headers)
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
                _run(["docker", "network", "create", "--internal", network], environment, env, 60)
                network_created = True
                _run(["docker", "network", "connect", "--alias", "target", network, container], environment, env, 60)
                network_connected = True

                def account_for(principal_id: str) -> dict[str, str]:
                    principal = manifest.principals[principal_id]
                    return info["accounts"][principal.account_id]

                def login_attacker(steps: tuple[LoginStep, ...], auth_headers: tuple[AuthHeader, ...] = ()) -> str | AttackerSession:
                    if not steps:
                        return ""
                    attacker = account_for(path.attacker_principal)
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
                    if principal_id != path.victim_principal:
                        return False
                    if not steps:
                        return True
                    return _login(page, base_url, steps, account_for(principal_id))

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
                        manifest.browser_http_auth, account_for(path.victim_principal)
                    ),
                    victim_account=account_for(path.victim_principal),
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
