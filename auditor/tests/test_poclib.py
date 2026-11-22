from __future__ import annotations

import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from runtime.poclib import Context, Poc


class _RedirectingLoginHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/login":
            self.send_error(404)
            return
        self.send_response(302)
        self.send_header("Location", "/home")
        self.send_header("Set-Cookie", "session=issued-on-redirect; Path=/")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/auth":
            self.send_response(200)
            self.end_headers()
            self.wfile.write((self.headers.get("Authorization", "") + "|" + self.headers.get("X-Api-Key", "")).encode())
            return
        if self.path == "/redirect-auth":
            self.send_response(302)
            self.send_header("Location", "/auth")
            self.end_headers()
            return
        if self.path != "/home":
            self.send_error(404)
            return
        if self.headers.get("Cookie") != "session=issued-on-redirect":
            self.send_error(403)
            return
        payload = b"authenticated"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


class PoclibRedirectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectingLoginHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_same_origin_redirect_retains_cookie_issued_by_redirect_response(self) -> None:
        port = self.server.server_address[1]
        base_url = f"http://127.0.0.1:{port}/"
        context = Context(Poc("001-redirect-cookie", "xss001redirect", base_url), base_url, "", "")

        response = context.request("POST", "/login", data={})

        self.assertEqual(response.status, 200)
        self.assertEqual(response.text, "authenticated")
        self.assertEqual(context._cookies, {"session": "issued-on-redirect"})

    def test_auth_headers_and_case_insensitive_override_survive_same_origin_redirect(self) -> None:
        base = f"http://127.0.0.1:{self.server.server_address[1]}/"
        with patch.dict("os.environ", {"RECEIPT_AUTH_HEADERS": '{"Authorization":"Bearer secret","X-Api-Key":"key"}'}):
            context = Context(Poc("001-auth-test", "xss001auth", base), base, "", "")
        self.assertEqual(context.request("GET", "/redirect-auth").text, "Bearer secret|key")
        self.assertEqual(context.request("GET", "/auth", headers={"authorization": "Bearer override"}).text, "Bearer override|key")

    def test_cross_origin_redirect_is_not_followed(self) -> None:
        destination = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectingLoginHandler)
        thread = threading.Thread(target=destination.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{self.server.server_address[1]}/"
            from runtime.poclib import _SameOriginRedirect
            handler = _SameOriginRedirect(base, lambda values: None, lambda: "")
            from urllib.request import Request
            from email.message import Message
            request = Request(base, headers={"Authorization": "Bearer secret"})
            self.assertIsNone(handler.redirect_request(request, None, 302, "Found", Message(), f"http://127.0.0.1:{destination.server_address[1]}/auth"))
        finally:
            destination.shutdown()
            destination.server_close()
            thread.join()
