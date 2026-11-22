from __future__ import annotations

import json
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

OFFICIAL_ROOT = "https://api.anthropic.com"
_MAX_BYTES = 1_000_000
_MAX_PAGES = 8
_MAX_MODELS = 400


class GatewayHTTPError(Exception):
    def __init__(self, status: int, body: str = "") -> None:
        super().__init__(body or f"HTTP {status}")
        self.status = status
        self.body = body


def candidate_urls(base_url: str) -> list[str]:
    raw = (base_url or "").strip() or OFFICIAL_ROOT
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("模型商地址需要是 http 或 https URL")
    root = raw.rstrip("/")
    if root.endswith("/v1"):
        ordered = [root + "/models"]
    else:
        ordered = [root + "/v1/models", root + "/models"]
    unique: list[str] = []
    for item in ordered:
        if item not in unique:
            unique.append(item)
    return unique


def parse_models(payload: object) -> list[dict[str, str]]:
    rows: list[object]
    if isinstance(payload, dict):
        raw = payload.get("data")
        if not isinstance(raw, list):
            raw = payload.get("models")
        rows = raw if isinstance(raw, list) else []
    elif isinstance(payload, list):
        rows = list(payload)
    else:
        return []
    models: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in rows:
        model_id = ""
        name = ""
        if isinstance(item, str):
            model_id = item.strip()
            name = model_id
        elif isinstance(item, dict):
            model_id = str(item.get("id") or item.get("name") or item.get("model") or "").strip()
            name = str(item.get("display_name") or item.get("name") or model_id).strip()
        if not model_id or model_id in seen:
            continue
        seen.add(model_id)
        models.append({"id": model_id, "name": name or model_id})
    return models


def _next_page(url: str, payload: object) -> str | None:
    if not isinstance(payload, dict) or not payload.get("has_more"):
        return None
    last_id = payload.get("last_id")
    if not isinstance(last_id, str) or not last_id:
        return None
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["after_id"] = last_id
    query.setdefault("limit", "100")
    return urlunparse(parsed._replace(query=urlencode(query)))


def messages_url(base_url: str) -> str:
    raw = (base_url or "").strip() or OFFICIAL_ROOT
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("模型商地址需要是 http 或 https URL")
    root = raw.rstrip("/")
    if root.endswith("/v1"):
        return root + "/messages"
    return root + "/v1/messages"


def quota_recovered(status: int) -> bool:
    if status in {401, 403, 429} or status <= 0 or status >= 500:
        return False
    return True


def _http_post(url: str, api_key: str, payload: dict, timeout: float) -> tuple[int, object]:
    opener = build_opener(_RefuseRedirect())
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={
            "x-api-key": api_key,
            "Authorization": f"Bearer {api_key}",
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "xss-auditor",
        },
        method="POST",
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200))
            raw = response.read(_MAX_BYTES + 1)
    except HTTPError as exc:
        text = exc.read(_MAX_BYTES).decode("utf-8", "replace")
        raise GatewayHTTPError(exc.code, text[:300]) from exc
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise GatewayHTTPError(0, f"无法连接: {reason}") from exc
    except TimeoutError as exc:
        raise GatewayHTTPError(0, "请求超时") from exc
    if len(raw) > _MAX_BYTES:
        raise GatewayHTTPError(status, "响应过大")
    if not raw:
        return status, {}
    try:
        return status, json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return status, {}


def quota_probe(
    base_url: str,
    api_key: str,
    model: str,
    timeout: float = 20,
    transport=None,
) -> dict:
    key = (api_key or "").strip()
    if not key:
        return {"ok": False, "status": 0, "message": "还没有 API 密钥"}
    try:
        url = messages_url(base_url)
    except ValueError as exc:
        return {"ok": False, "status": 0, "message": str(exc)}
    payload = {
        "model": model or "claude",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "ping"}],
    }
    fetch = transport or _http_post
    try:
        status, _payload = fetch(url, key, payload, timeout)
    except GatewayHTTPError as exc:
        status = int(exc.status)
        detail = (exc.body or f"HTTP {status}").strip()
        return {"ok": quota_recovered(status), "status": status, "message": detail[:300] or f"HTTP {status}"}
    recovered = quota_recovered(int(status))
    message = "模型接口已恢复" if recovered else f"HTTP {status}"
    return {"ok": recovered, "status": int(status), "message": message}


def _http_get(url: str, api_key: str, timeout: float) -> tuple[int, object]:
    opener = build_opener(_RefuseRedirect())
    request = Request(
        url,
        headers={
            "x-api-key": api_key,
            "Authorization": f"Bearer {api_key}",
            "anthropic-version": "2023-06-01",
            "Accept": "application/json",
            "User-Agent": "xss-auditor",
        },
        method="GET",
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200))
            raw = response.read(_MAX_BYTES + 1)
    except HTTPError as exc:
        body = exc.read(_MAX_BYTES).decode("utf-8", "replace")
        raise GatewayHTTPError(exc.code, body[:300]) from exc
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise GatewayHTTPError(0, f"无法连接: {reason}") from exc
    except TimeoutError as exc:
        raise GatewayHTTPError(0, "请求超时") from exc
    if len(raw) > _MAX_BYTES:
        raise GatewayHTTPError(status, "响应过大")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise GatewayHTTPError(status, "响应不是 JSON") from exc
    return status, payload


class _RefuseRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def probe(
    base_url: str,
    api_key: str,
    timeout: float = 20,
    transport=None,
) -> dict:
    started = time.perf_counter()
    key = (api_key or "").strip()
    if not key:
        return _result(False, "还没有 API 密钥", 0, started, [])
    try:
        urls = candidate_urls(base_url)
    except ValueError as exc:
        return _result(False, str(exc), 0, started, [])

    fetch = transport or _http_get
    errors: list[str] = []
    for url in urls:
        page = url
        collected: list[dict[str, str]] = []
        seen: set[str] = set()
        status = 0
        failed = False
        for _ in range(_MAX_PAGES):
            try:
                status, payload = fetch(page, key, timeout)
            except GatewayHTTPError as exc:
                if exc.status in {401, 403}:
                    return _result(False, f"密钥被拒绝（HTTP {exc.status}）", exc.status, started, [])
                if exc.status in {301, 302, 303, 307, 308}:
                    return _result(False, "接口返回重定向，已停止请求", exc.status, started, [])
                errors.append(exc.body or f"HTTP {exc.status}")
                failed = True
                break
            batch = parse_models(payload)
            for model in batch:
                if model["id"] in seen:
                    continue
                seen.add(model["id"])
                collected.append(model)
                if len(collected) >= _MAX_MODELS:
                    break
            if len(collected) >= _MAX_MODELS:
                break
            nxt = _next_page(url, payload)
            if not nxt or nxt == page:
                break
            page = nxt
        if failed:
            continue
        if collected:
            return _result(True, f"已连通，获取到 {len(collected)} 个模型", status or 200, started, collected)
        if status == 200:
            return _result(True, "已连通，模型列表为空", status, started, [])
    message = errors[-1] if errors else "没有可用的模型列表接口"
    return _result(False, message, 0, started, [])


def _result(ok: bool, message: str, status: int, started: float, models: list[dict[str, str]]) -> dict:
    return {
        "ok": ok,
        "message": message,
        "status": status,
        "latency_ms": int((time.perf_counter() - started) * 1000),
        "models": models,
    }
