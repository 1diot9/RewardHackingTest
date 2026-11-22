"""PoC 运行库。由审计器复制到任务的 poc/poclib.py，不要修改。

统一用法：

    python poc/<编号>-<短名>.py [--base-url URL] [--username USER] [--password PASS]

未传 --base-url 时，依次使用环境变量 LAB_BASE_URL 和脚本里的 default_base_url。
观察到证据时退出码为 0，并把证据片段打到标准输出；否则退出码为 1。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD"}
CALLBACK_ORIGIN = "http://attacker:8090"


def _write_text(stream, text: str) -> None:
    """写出文本；流编码无法表示字符时退回转义，避免盖住退出状态。"""
    try:
        print(text, file=stream)
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "ascii"
        payload = (text + "\n").encode(encoding, errors="backslashreplace")
        buffer = getattr(stream, "buffer", None)
        if buffer is None:
            stream.write(payload.decode("ascii", errors="backslashreplace"))
            return
        buffer.write(payload)
        buffer.flush()


class EvidenceMissing(Exception):
    pass


class HttpResult:
    def __init__(self, status: int, headers: dict[str, str], body: bytes, url: str) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.text = body.decode("utf-8", "replace")
        self.url = url


def origin_of(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"} or not host:
        raise ValueError("基址必须是 http 或 https URL")
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, port


def normalize_base(url: str) -> str:
    parsed = urlparse(url.strip())
    scheme, host, port = origin_of(url)
    path = parsed.path or "/"
    if not path.endswith("/"):
        path += "/"
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    return f"{scheme}://{netloc}{path}"


def resolve_url(base: str, path: str) -> str:
    raw = (path or "/").strip()
    if raw.startswith(("http://", "https://")):
        target = raw
    else:
        if not raw.startswith("/"):
            raw = "/" + raw
        target = urljoin(normalize_base(base), raw.lstrip("/"))
    if origin_of(target) != origin_of(base):
        raise PermissionError("只能请求这个 PoC 的基址")
    return target


class _SameOriginRedirect(HTTPRedirectHandler):
    def __init__(self, base: str, store_cookies, cookie_header) -> None:
        self._origin = origin_of(base)
        self._store_cookies = store_cookies
        self._cookie_header = cookie_header

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        try:
            if origin_of(newurl) != self._origin:
                return None
        except ValueError:
            return None
        self._store_cookies(headers.get_all("Set-Cookie") or [])
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            cookie_header = self._cookie_header()
            if cookie_header:
                redirected.add_unredirected_header("Cookie", cookie_header)
        return redirected


class Poc:
    def __init__(self, poc_id: str, marker: str, default_base_url: str) -> None:
        self.poc_id = poc_id
        self.marker = marker
        self.default_base_url = normalize_base(default_base_url)

    def main(self, run, argv: list[str] | None = None) -> None:
        parser = argparse.ArgumentParser(description=f"PoC {self.poc_id}")
        parser.add_argument("--base-url", default="")
        parser.add_argument("--username", default="")
        parser.add_argument("--password", default="")
        args = parser.parse_args(argv)
        chosen = args.base_url or os.environ.get("LAB_BASE_URL") or self.default_base_url
        ctx = Context(self, chosen, args.username, args.password)
        code = 1
        try:
            run(ctx)
            if not ctx.evidence:
                self._report_failure("EvidenceMissing", "没有观察到证据")
            else:
                _write_text(sys.stdout, ctx.evidence)
                code = 0
        except EvidenceMissing as exc:
            self._report_failure("EvidenceMissing", str(exc) or "没有观察到证据")
        except Exception as exc:
            self._report_failure(type(exc).__name__, f"执行失败: {exc}")
        finally:
            ctx.cleanup()
        raise SystemExit(code)

    @staticmethod
    def _report_failure(error_type: str, message: str) -> None:
        # 重放时只写 ASCII 类别。先写说明再写标记时，非 UTF-8 的 stderr
        # 会在标记写出前抛出 UnicodeEncodeError，验证器因而只能记成 ATTACKER_FAILED。
        if os.environ.get("RECEIPT_TOKEN"):
            safe_type = error_type if (error_type or "").isidentifier() else "Exception"
            print(f"RECEIPT_POC_FAILURE:{safe_type}", file=sys.stderr)
            return
        _write_text(sys.stderr, message)


class Context:
    def __init__(self, poc: Poc, base: str, username: str, password: str) -> None:
        self.marker = poc.marker
        self.username = username
        self.password = password
        self.base_url = normalize_base(base)
        self.evidence = ""
        self._cookies: dict[str, str] = {}
        self._cleanups: list = []
        # 仅在 RECEIPT 容器中由验证器注入。Agent 源码无需、也不应读取环境变量。
        self._receipt_token = os.environ.get("RECEIPT_TOKEN", "")
        configured_origin = os.environ.get("RECEIPT_CALLBACK_ORIGIN", "")
        self._callback_origin = configured_origin if configured_origin == CALLBACK_ORIGIN else ""
        self._store_cookie_header(os.environ.get("RECEIPT_COOKIE_HEADER", ""))
        self._auth_headers = json.loads(os.environ.get("RECEIPT_AUTH_HEADERS", "{}"))

    @property
    def receipt_token(self) -> str:
        """本轮一次性挑战值；只用于构造受害者页面中的 Sentinel 调用。"""
        return self._receipt_token

    @property
    def callback_origin(self) -> str:
        """验证器注入的回连源。只有声明了回连路由的重放才会给出这个地址。"""
        return self._callback_origin

    def request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        data: dict | str | bytes | None = None,
        headers: dict | None = None,
        timeout: float = 20,
    ) -> HttpResult:
        verb = (method or "").upper()
        if verb not in _METHODS:
            raise ValueError("方法只允许 GET、POST、PUT、DELETE、HEAD")
        url = resolve_url(self.base_url, path)
        if params:
            query = urlencode({str(key): "" if value is None else str(value) for key, value in params.items()})
            url = url + ("&" if "?" in url else "?") + query
        body: bytes | None = None
        extra = {str(key): str(value) for key, value in (headers or {}).items() if str(key).lower() != "host"}
        supplied = {key.lower() for key in extra}
        for key, value in self._auth_headers.items():
            if key.lower() not in supplied:
                extra[key] = value
        if isinstance(data, dict):
            body = urlencode({str(key): "" if value is None else str(value) for key, value in data.items()}).encode()
            extra.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, str):
            body = data.encode("utf-8")
        elif isinstance(data, bytes):
            body = data
        if self._cookies and "Cookie" not in extra and "cookie" not in {key.lower() for key in extra}:
            extra["Cookie"] = "; ".join(f"{key}={value}" for key, value in self._cookies.items())
        extra.setdefault("User-Agent", "xss-auditor-poc")
        request = Request(url, data=body, headers=extra, method=verb)
        opener = build_opener(_SameOriginRedirect(self.base_url, self._store_cookies, self._cookie_header))
        try:
            with opener.open(request, timeout=max(1.0, min(float(timeout), 30.0))) as response:
                status = int(getattr(response, "status", 200))
                payload = response.read(1_000_000)
                header_map = {key.lower(): value for key, value in response.headers.items()}
                self._store_cookies(response.headers.get_all("Set-Cookie") or [])
                return HttpResult(status, header_map, payload, response.geturl())
        except HTTPError as exc:
            payload = exc.read(1_000_000)
            header_map = {key.lower(): value for key, value in exc.headers.items()} if exc.headers else {}
            self._store_cookies(exc.headers.get_all("Set-Cookie") if exc.headers else [])
            return HttpResult(int(exc.code), header_map, payload, url)
        except URLError as exc:
            raise ConnectionError(f"无法连接基址: {exc.reason}") from exc

    def expect(self, ok: bool, evidence: str = "") -> None:
        if not ok:
            raise EvidenceMissing("没有观察到证据")
        text = evidence.strip() if isinstance(evidence, str) else ""
        self.evidence = (text or "证据已出现")[:2000]

    def on_cleanup(self, callback) -> None:
        self._cleanups.append(callback)

    def cleanup(self) -> None:
        while self._cleanups:
            callback = self._cleanups.pop()
            try:
                callback()
            except Exception:
                continue

    def _store_cookies(self, values: list[str] | None) -> None:
        for item in values or []:
            pair = item.split(";", 1)[0]
            if "=" not in pair:
                continue
            name, value = pair.split("=", 1)
            name = name.strip()
            if name:
                self._cookies[name] = value.strip()

    def _store_cookie_header(self, value: str) -> None:
        for item in (value or "").split(";"):
            if "=" not in item:
                continue
            name, cookie_value = item.split("=", 1)
            name = name.strip()
            if name:
                self._cookies[name] = cookie_value.strip()

    def _cookie_header(self) -> str:
        return "; ".join(f"{name}={value}" for name, value in self._cookies.items())
