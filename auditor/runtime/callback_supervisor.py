"""可信回连监督进程。只随攻击者容器运行，不由候选项脚本导入。

先按验证器写入的路由表监听固定端口，再运行 PoC。脚本退出后继续应答，
直到容器被停止。响应只来自路由表和本轮 token，不回显请求内容。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

TOKEN_PLACEHOLDER = "{{receipt_token}}"
STATUS_PATH = Path("/tmp/receipt-poc-status")
LISTEN_PORT = 8090


def load_routes(path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    routes: dict[tuple[str, str], dict[str, Any]] = {}
    for item in raw["routes"]:
        routes[(str(item["method"]), str(item["path"]))] = item
    return routes


def make_handler(routes: dict[tuple[str, str], dict[str, Any]], token: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            self._respond()

        def do_POST(self) -> None:
            self._respond()

        def do_PUT(self) -> None:
            self._respond()

        def do_HEAD(self) -> None:
            self._respond()

        def _discard_body(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return
            remaining = min(max(length, 0), 65536)
            while remaining > 0:
                chunk = self.rfile.read(min(8192, remaining))
                if not chunk:
                    return
                remaining -= len(chunk)

        def _respond(self) -> None:
            self._discard_body()
            route = routes.get((self.command, urlsplit(self.path).path))
            if route is None:
                body = b""
                status = 404
                content_type = "text/plain"
            else:
                status = int(route["status"])
                content_type = str(route["content_type"])
                body = str(route["body"]).replace(TOKEN_PLACEHOLDER, token).encode("utf-8")
            outgoing = b"" if self.command == "HEAD" else body
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if outgoing:
                self.wfile.write(outgoing)

    return Handler


def run_poc(script: Path) -> tuple[int, str]:
    try:
        source = script.read_text(encoding="utf-8")
    except OSError:
        return 0, ""
    if not source.strip():
        return 0, ""
    completed = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(script.parent),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return completed.returncode, (completed.stderr or "")[:16000]


def write_status(code: int, stderr: str) -> None:
    partial = STATUS_PATH.with_suffix(".partial")
    partial.write_text(f"{code}\n{stderr}", encoding="utf-8")
    partial.replace(STATUS_PATH)


def main() -> None:
    routes = load_routes(Path("/receipt/callback-routes.json"))
    token = os.environ.get("RECEIPT_TOKEN", "")
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), make_handler(routes, token))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    code, stderr = run_poc(Path("/receipt/poc.py"))
    write_status(code, stderr)
    threading.Event().wait()


if __name__ == "__main__":
    main()
