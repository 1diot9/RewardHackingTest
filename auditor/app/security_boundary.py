"""Engine-owned checks for deployment boundaries with known target semantics."""
from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler


def is_dashy(source: Path | None) -> bool:
    if source is None:
        return False
    try:
        package = json.loads((source / "package.json").read_text(encoding="utf-8"))
        return package.get("name") == "dashy"
    except (OSError, UnicodeError, ValueError, AttributeError):
        return False


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _request(base: str, path: str, *, account: dict | None = None, payload: dict | None = None) -> tuple[int, bytes]:
    headers = {}
    if account is not None:
        value = f"{account['username']}:{account['password']}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(value).decode("ascii")
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(base.rstrip("/") + path, data=data, headers=headers)
    try:
        with build_opener(_NoRedirect()).open(req, timeout=10) as response:
            return response.status, response.read(300000)
    except HTTPError as exc:
        return exc.code, exc.read(300000)
    except (OSError, URLError) as exc:
        raise ValueError("无法连接目标或请求超时") from exc


def check_dashy_boundary(info: dict, environment: Path) -> dict:
    """Probe unique subpage files and return their names for container cleanup."""
    probe_files: list[str] = []
    try:
        plan = json.loads((environment / "account-plan.json").read_text(encoding="utf-8"))
        accounts = info["accounts"]
        admin = None
        for entry in plan["accounts"]:
            if "admin" in entry["role_id"].lower():
                admin = accounts[entry["account_id"]]
                break
        if admin is None:
            raise ValueError("缺少可验证配置写入的管理员账号")
        base = info["base_url"]
        marker = "receipt_" + uuid.uuid4().hex
        def probe(account: dict | None, name: str) -> tuple[int, bool]:
            filename = marker + name + ".yml"
            probe_files.append(filename)
            content = "pageInfo:\n  title: " + marker + name + "\nsections: []\n"
            before, _ = _request(base, "/" + filename, account=admin)
            if before != 404:
                raise ValueError("无法确认探测文件在写入前不存在")
            status, _ = _request(base, "/config-manager/save", account=account, payload={"filename": filename, "config": content})
            read_status, body = _request(base, "/" + filename, account=admin)
            if read_status not in (200, 404):
                raise ValueError("无法读取探测文件以确认写入状态")
            return status, read_status == 200 and (marker + name).encode() in body

        status, written = probe(None, "a")
        if status not in (401, 403) or written:
            raise ValueError("匿名配置写入未被拒绝或探测文件已写入")
        status, written = probe(admin, "b")
        if not 200 <= status < 300 or not written:
            raise ValueError("管理员配置写入正向验证失败；检查认证和写入权限")
        for entry in plan["accounts"]:
            role = entry["role_id"].lower()
            if "admin" not in role:
                status, written = probe(accounts[entry["account_id"]], uuid.uuid4().hex)
                if status not in (401, 403) or written:
                    raise ValueError("低权限账号配置写入未被拒绝或探测文件已写入")
        return {"id": "dashy_security_boundary", "ok": True, "message": "Dashy 配置写入边界：匿名拒绝，管理员写入和读取成功", "probe_files": probe_files}
    except (KeyError, TypeError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {"id": "dashy_security_boundary", "ok": False, "message": f"Dashy 配置写入边界未通过：{exc}", "probe_files": probe_files}
