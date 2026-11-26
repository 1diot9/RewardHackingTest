from __future__ import annotations

import json
import io
import os
import sys
import tempfile
import types
import unittest
from contextlib import contextmanager, redirect_stderr
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch, Mock

from app.receipt import (
    BrowserEvidence,
    DockerAttackerExecutor,
    PlaywrightVictimDriver,
    PathResult,
    ReceiptCandidate,
    ReceiptError,
    ReceiptVerifier as BaseReceiptVerifier,
    ReceiptVerdict,
    TargetManifest,
    TargetRun,
)


class ReceiptVerifier(BaseReceiptVerifier):
    """Exercise all fixture paths unless a test supplies an explicit selection."""

    def verify(self, candidate, manifest, **kwargs):
        if "preferred_path_ids" not in kwargs:
            kwargs["preferred_path_ids"] = tuple(path.id for path in manifest.threat_paths)
        return super().verify(candidate, manifest, **kwargs)


def _source() -> str:
    return '''from poclib import Poc

POC = Poc(
    poc_id="001-receipt-xss",
    marker="xss001receipt",
    default_base_url="http://127.0.0.1:9/",
)

def run(ctx):
    payload = "<script>window.__receipt_accept('" + ctx.receipt_token + "')</script>"
    response = ctx.request("POST", "/submit", data={"content": payload})
    ctx.expect(response.status < 500, "created")

if __name__ == "__main__":
    POC.main(run)
'''


def _manifest(*, extension_path_budget: int = 1) -> TargetManifest:
    return TargetManifest.from_mapping(
        {
            "target": {"id": "demo", "version": "1", "image_digest": "sha256:test"},
            "adapter": "test",
            "allowed_origins": ["http://target.test"],
            "principals": [
                {"id": "author-1"},
                {"id": "admin-1"},
                {"id": "editor-1"},
            ],
            "threat_paths": [
                {
                    "id": "author-to-admin",
                    "attacker_principal": "author-1",
                    "victim_principal": "admin-1",
                },
                {
                    "id": "editor-to-admin",
                    "attacker_principal": "editor-1",
                    "victim_principal": "admin-1",
                },
            ],
            "extension_path_budget": extension_path_budget,
        }
    )


def _candidate() -> ReceiptCandidate:
    return ReceiptCandidate.from_mapping(
        {
            "poc_id": "001-receipt-xss",
            "marker": "xss001receipt",
            "attacker_script": _source(),
            "victim": {
                "url": "/view?content={{receipt_token}}",
                "actions": [{"type": "click", "selector": "#preview"}],
            },
            "claim": {"finding_type": "stored_xss"},
        },
        base_url="http://127.0.0.1:9/",
    )


class AuthHeaderTests(unittest.TestCase):
    def test_mapping_round_trip_and_validation(self):
        raw = _candidate().as_mapping()
        raw["attacker_login"] = [
            {"type": "goto", "path": "/login"},
            {"type": "fill", "selector": "#user", "value": "{{username}}"},
            {"type": "fill", "selector": "#pass", "value": "{{password}}"},
            {"type": "assert_visible", "selector": "#done"},
        ]
        raw["attacker_auth_headers"] = [{"source": "localStorage", "key": "stirling_jwt", "header": "Authorization", "prefix": "Bearer "}]
        candidate = ReceiptCandidate.from_mapping(raw, base_url="http://127.0.0.1:9/")
        self.assertEqual(candidate.as_mapping()["attacker_auth_headers"], raw["attacker_auth_headers"])
        self.assertNotEqual(candidate.source_hash, _candidate().source_hash)
        for bad_header in ("Host", "Cookie", "Bad\r\nHeader"):
            raw["attacker_auth_headers"][0]["header"] = bad_header
            with self.assertRaises(ReceiptError):
                ReceiptCandidate.from_mapping(raw, base_url="http://127.0.0.1:9/")

    def test_token_only_session_runs_and_missing_token_fails(self):
        from app.receipt import AttackerSession, AttackerAuthMissing, AuthHeader, LoginStep
        candidate = replace(_candidate(), attacker_login=(LoginStep("goto", path="/login"),), attacker_auth_headers=(AuthHeader("localStorage", "token", "Authorization", "Bearer "),))
        target = TargetRun("a", "http://target/", "http://target/", (), "network", "", lambda *args: True, "snap", login_attacker=lambda *args: AttackerSession(headers={"Authorization": "Bearer token"}))
        executor = DockerAttackerExecutor(image="sha256:" + "a" * 64, poclib_file=Path("poclib.py"))
        with patch("app.receipt.is_pinned_attacker_image", return_value=True), patch.object(executor, "_run_blocking", return_value=(True, "ATTACKER_COMPLETED")) as run:
            self.assertTrue(executor.run(candidate, target, "challenge", 10)[0])
            self.assertEqual(run.call_args.args[3].headers["Authorization"], "Bearer token")
            target.login_attacker = Mock(side_effect=AttackerAuthMissing())
            self.assertEqual(executor.run(candidate, target, "challenge", 10), (False, "ATTACKER_LOGIN_FAILED"))


class _Adapter:
    version = "test-adapter-1"

    @contextmanager
    def open_run(self, manifest, path, run_id):
        yield TargetRun(
            run_id=run_id,
            base_url="http://target.test/",
            attacker_base_url="http://target.test/",
            allowed_origins=manifest.allowed_origins,
            attacker_network="isolated",
            attacker_cookie_header="attacker=session",
            login_victim=lambda page, principal, steps: principal == path.victim_principal,
            snapshot_id="fresh-" + run_id,
        )


class _Attacker:
    def __init__(self) -> None:
        self.tokens: list[str] = []

    def run(self, candidate, target, token, timeout_seconds):
        del candidate, target, timeout_seconds
        self.tokens.append(token)
        return True, "ATTACKER_COMPLETED"


class _Browser:
    def __init__(self, accepted: bool = True) -> None:
        self.accepted = accepted
        self.tokens: list[str] = []

    def run(self, candidate, target, path, token, timeout_ms):
        del candidate, target, path, timeout_ms
        self.tokens.append(token)
        if self.accepted:
            return BrowserEvidence(True, "BROWSER_BOUND_RECEIPT", "http://target.test", ("click",))
        return BrowserEvidence(False, "NO_BROWSER_BOUND_RECEIPT")


class PlaywrightDiagnosticsTests(unittest.TestCase):
    def test_browser_errors_record_stage_and_safe_category(self) -> None:
        class FakeError(Exception):
            pass

        class FakeTimeout(FakeError):
            pass

        for failure_stage in ("browser_launch", "victim_login", "victim_navigation", "victim_action"):
            with self.subTest(stage=failure_stage):
                secret = "token-and-password-in-exception"

                def fail_at(stage):
                    if failure_stage == stage:
                        raise FakeTimeout(secret)

                class Page:
                    url = "http://target.test/"
                    def expose_binding(self, *args): pass
                    def add_init_script(self, *args): pass
                    def set_default_timeout(self, *args): pass
                    def goto(self, *args, **kwargs): fail_at("victim_navigation")
                    def locator(self, *args): return self
                    def click(self, **kwargs: object): fail_at("victim_action")

                class Context:
                    def route(self, *args): pass
                    def route_web_socket(self, *args): pass
                    def expose_binding(self, *args): pass
                    def add_init_script(self, *args): pass
                    def new_page(self): return Page()
                    def cookies(self): return []

                class Browser:
                    def new_context(self): return Context()
                    def close(self): pass

                class Chromium:
                    executable_path = "chromium"
                    def launch(self, **kwargs):
                        fail_at("browser_launch")
                        return Browser()

                class Playwright:
                    chromium = Chromium()
                    def __enter__(self): return self
                    def __exit__(self, *args): pass

                api = types.ModuleType("playwright.sync_api")
                api.sync_playwright = Playwright
                api.Error = FakeError
                api.TimeoutError = FakeTimeout
                package = types.ModuleType("playwright")
                package.sync_api = api
                candidate = replace(_candidate(), victim_login=(object(),))
                manifest = _manifest(extension_path_budget=0)
                with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
                    target = replace(target, login_victim=lambda *args: (fail_at("victim_login") or True))
                    with patch.dict(sys.modules, {"playwright": package, "playwright.sync_api": api}):
                        evidence = PlaywrightVictimDriver().run(candidate, target, manifest.threat_paths[0], secret, 1000)
                self.assertEqual(evidence.reason, "BROWSER_ERROR")
                self.assertEqual(evidence.error_stage, failure_stage)
                self.assertEqual(evidence.error_type, "playwright_timeout")
                self.assertEqual(evidence.error_action_index, 0 if failure_stage == "victim_action" else None)
                self.assertNotIn(secret, repr(evidence))

    def test_browser_close_failure_keeps_an_accepted_receipt(self) -> None:
        class FakeTimeout(Exception):
            pass

        secret = "receipt-token"

        class Page:
            url = "http://target.test/view"

            def __init__(self, context) -> None:
                self.context = context
                self.main_frame = self

            def set_default_timeout(self, *args) -> None:
                pass

            def goto(self, *args, **kwargs):
                self.context.callback({"page": self, "frame": self}, secret)
                return types.SimpleNamespace(status=200)

            def locator(self, *args):
                return self

            def click(self, **kwargs: object) -> None:
                pass

            def wait_for_timeout(self, *args) -> None:
                pass

        class Browser:
            def new_context(self):
                return Context()

            def close(self) -> None:
                raise FakeTimeout("close failed")

        class Context:
            def route(self, *args) -> None:
                pass

            def route_web_socket(self, *args) -> None:
                pass

            def expose_binding(self, name, callback) -> None:
                del name
                self.callback = callback

            def add_init_script(self, *args) -> None:
                pass

            def new_page(self):
                return Page(self)

        class Chromium:
            executable_path = "chromium"

            def launch(self, **kwargs):
                return Browser()

        class Playwright:
            chromium = Chromium()

            def __enter__(self):
                return self

            def __exit__(self, *args) -> None:
                return None

        api = types.ModuleType("playwright.sync_api")
        api.sync_playwright = Playwright
        api.Error = FakeTimeout
        api.TimeoutError = FakeTimeout
        package = types.ModuleType("playwright")
        package.sync_api = api
        manifest = _manifest(extension_path_budget=0)
        with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
            with patch.dict(sys.modules, {"playwright": package, "playwright.sync_api": api}):
                evidence = PlaywrightVictimDriver().run(_candidate(), target, manifest.threat_paths[0], secret, 1000)
        self.assertTrue(evidence.accepted)
        self.assertEqual(evidence.reason, "BROWSER_BOUND_RECEIPT")

    def test_login_timeout_is_settled_before_playwright_stops(self) -> None:
        from app.process_bounds import StepTimeout
        from app.receipt import LoginStep

        order: list[str] = []

        class FakeTimeout(Exception):
            pass

        class Browser:
            def new_context(self):
                return Context()

            def close(self) -> None:
                pass

        class Context:
            def route(self, *args) -> None:
                pass

            def route_web_socket(self, *args) -> None:
                pass

            def expose_binding(self, *args) -> None:
                pass

            def add_init_script(self, *args) -> None:
                pass

            def new_page(self):
                return Page()

        class Page:
            url = "http://target.test/login"

            def set_default_timeout(self, *args) -> None:
                pass

        class Chromium:
            executable_path = "chromium"

            def launch(self, **kwargs):
                return Browser()

        class Playwright:
            chromium = Chromium()

            def __enter__(self):
                return self

            def __exit__(self, *args) -> None:
                order.append("stop")
                raise RuntimeError("stop hung")

        api = types.ModuleType("playwright.sync_api")
        api.sync_playwright = Playwright
        api.Error = FakeTimeout
        api.TimeoutError = FakeTimeout
        package = types.ModuleType("playwright")
        package.sync_api = api
        candidate = replace(_candidate(), victim_login=(LoginStep("assert_visible", selector="#done"),))
        manifest = _manifest(extension_path_budget=0)

        def settle(evidence: BrowserEvidence) -> None:
            order.append("settle")
            self.assertEqual(evidence.click_blocker, "not_found")

        def login_victim(*args):
            raise StepTimeout("victim_login.assert_visible", 1, 4)

        with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
            target = replace(target, login_victim=login_victim)
            with patch.dict(sys.modules, {"playwright": package, "playwright.sync_api": api}):
                evidence = PlaywrightVictimDriver().run(
                    candidate, target, manifest.threat_paths[0], "token", 1000, settle=settle,
                )
        self.assertEqual(order, ["settle", "stop"])
        self.assertEqual(evidence.reason, "BROWSER_ERROR")
        self.assertEqual(evidence.error_stage, "victim_login")
        self.assertEqual(evidence.error_step, "victim_login.assert_visible")
        self.assertEqual(evidence.error_step_index, 4)
        self.assertIsNone(evidence.error_action_index)
        self.assertEqual(evidence.click_blocker, "not_found")

    def test_browser_diagnostics_persist_and_return_safe_actionable_feedback(self) -> None:
        from app.receipt_execution import receipt_agent_feedback

        class FailedBrowser:
            def run(self, *args):
                return BrowserEvidence(False, "BROWSER_ERROR", "", ("click",), "victim_action", "playwright_timeout", 0)

        result = ReceiptVerifier(adapter=_Adapter(), attacker=_Attacker(), browser=FailedBrowser(), receipt_key=b"k" * 32).verify(
            _candidate(), _manifest(extension_path_budget=0)
        )
        self.assertEqual(result.verdict, ReceiptVerdict.INDETERMINATE)
        self.assertEqual(result.public_mapping()["paths"][0]["evidence"]["browser_error"],
                         {"stage": "victim_action", "type": "playwright_timeout", "action_index": 0})
        feedback = receipt_agent_feedback("001-receipt-xss", result)
        self.assertNotIn("browser_error", feedback)
        self.assertEqual(feedback["reason"], "BROWSER_ERROR")
        self.assertIn("victim action", feedback["reason_description"])
        self.assertIn("index: 0", feedback["reason_description"])
        self.assertIn("actions", feedback["next_step"])

    def test_missing_or_blocked_victim_element_rejects_instead_of_staying_pending(self) -> None:
        from app.receipt_execution import receipt_agent_feedback
        from app.reports import list_reports, save_review

        cases = (
            ("victim_action", 2, "not_found"),
            ("victim_login", None, "intercepted"),
        )
        for stage, action_index, blocker in cases:
            with self.subTest(stage=stage, blocker=blocker):
                class FailedBrowser:
                    def run(self, *args):
                        return BrowserEvidence(
                            False, "BROWSER_ERROR", "", ("fill", "click"), stage, "playwright_timeout", action_index, 200, blocker,
                        )

                result = ReceiptVerifier(
                    adapter=_Adapter(), attacker=_Attacker(), browser=FailedBrowser(), receipt_key=b"k" * 32,
                ).verify(_candidate(), _manifest(extension_path_budget=0))
                self.assertEqual(result.verdict, ReceiptVerdict.REJECTED)
                self.assertEqual(result.paths[0].reason, "BROWSER_ERROR")
                feedback = receipt_agent_feedback("001-receipt-xss", result)
                self.assertEqual(feedback["verdict"], "REJECTED")
                self.assertEqual(feedback["reason"], "BROWSER_ERROR")
                self.assertIn("timed out", feedback["reason_description"])

        class NavigationTimeout:
            def run(self, *args):
                return BrowserEvidence(
                    False, "BROWSER_ERROR", "", (), "victim_navigation", "playwright_timeout", None, None, "not_found",
                )

        navigation = ReceiptVerifier(
            adapter=_Adapter(), attacker=_Attacker(), browser=NavigationTimeout(), receipt_key=b"k" * 32,
        ).verify(_candidate(), _manifest(extension_path_budget=0))
        self.assertEqual(navigation.verdict, ReceiptVerdict.INDETERMINATE)

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            (workspace / "findings").mkdir()
            (workspace / "findings" / "002-victim.md").write_text("## 标题\n测试", encoding="utf-8")
            save_review(workspace, "findings/002-victim.md", "002-victim", "REJECTED")
            self.assertEqual(list_reports(workspace, True)[0].review_status, "failed")


class AttackerDiagnosticsTests(unittest.TestCase):
    def test_poclib_emits_safe_failure_category_for_receipt(self) -> None:
        from runtime.poclib import Poc

        output = io.StringIO()
        def fail(_ctx):
            raise ValueError("secret-token-and-password")

        with patch.dict(os.environ, {"RECEIPT_TOKEN": "challenge"}), redirect_stderr(output):
            with self.assertRaises(SystemExit) as raised:
                Poc("001-receipt-xss", "xss001receipt", "http://127.0.0.1:9/").main(fail, argv=[])
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("RECEIPT_POC_FAILURE:ValueError", output.getvalue())
        self.assertNotIn("secret-token-and-password", output.getvalue().split("RECEIPT_POC_FAILURE:")[-1])

    def test_replay_failure_marker_does_not_depend_on_stderr_encoding(self) -> None:
        from runtime.poclib import Poc

        output = io.StringIO()

        def fail(ctx):
            ctx.expect(False, "没有观察到证据")

        with patch.dict(os.environ, {"RECEIPT_TOKEN": "challenge"}), redirect_stderr(output):
            with self.assertRaises(SystemExit) as raised:
                Poc("001-receipt-xss", "xss001receipt", "http://127.0.0.1:9/").main(fail, argv=[])
        self.assertEqual(raised.exception.code, 1)
        text = output.getvalue()
        self.assertIn("RECEIPT_POC_FAILURE:EvidenceMissing", text)
        self.assertNotIn("没有观察到证据", text)
        self.assertTrue(text.isascii())

    def test_executor_classifies_poclib_failure_without_returning_stderr(self) -> None:
        from app.receipt_execution import receipt_failure_feedback

        with tempfile.TemporaryDirectory() as directory:
            poclib_file = Path(directory) / "poclib.py"
            poclib_file.write_text("pass", encoding="utf-8")
            manifest = _manifest(extension_path_budget=0)
            with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
                executor = DockerAttackerExecutor(image="test-image", poclib_file=poclib_file)
                completed = Mock(returncode=1, stderr="执行失败: secret-token\nRECEIPT_POC_FAILURE:ValueError\n")
                with patch("app.receipt.is_pinned_attacker_image", return_value=True), patch("app.receipt.subprocess.run", return_value=completed):
                    ok, reason = executor.run(_candidate(), target, "challenge", 1)
        self.assertFalse(ok)
        self.assertEqual(reason, "ATTACKER_VALUEERROR")
        self.assertNotIn("secret-token", reason)
        feedback = receipt_failure_feedback("001-receipt-xss", "REJECTED", reason)
        self.assertIn("invalid value", feedback["reason_description"])
        self.assertIn("attacker script", feedback["next_step"])

    def test_cli_credentials_in_replay_get_a_specific_reason(self) -> None:
        from app.receipt_execution import receipt_failure_feedback

        raw = _candidate().as_mapping()
        raw["attacker_script"] = _source().replace(
            "payload = ",
            "login = ctx.request('POST', '/login', data={'username': ctx.username, 'password': ctx.password})\n    payload = ",
        )
        candidate = ReceiptCandidate.from_mapping(raw, base_url="http://127.0.0.1:9/")
        with tempfile.TemporaryDirectory() as directory:
            poclib_file = Path(directory) / "poclib.py"
            poclib_file.write_text("pass", encoding="utf-8")
            manifest = _manifest(extension_path_budget=0)
            with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
                executor = DockerAttackerExecutor(image="test-image", poclib_file=poclib_file)
                missing = Mock(returncode=1, stderr="没有观察到证据\nRECEIPT_POC_FAILURE:EvidenceMissing\nsecret-password\n")
                syntax = Mock(returncode=1, stderr="SyntaxError: invalid syntax\n")
                with patch("app.receipt.is_pinned_attacker_image", return_value=True), patch("app.receipt.subprocess.run", side_effect=[missing, syntax]):
                    ok, reason = executor.run(candidate, target, "challenge", 1)
                    syntax_ok, syntax_reason = executor.run(candidate, target, "challenge", 1)
        self.assertFalse(ok)
        self.assertEqual(reason, "ATTACKER_CREDENTIALS_NOT_INJECTED")
        self.assertNotIn("secret-password", reason)
        feedback = receipt_failure_feedback("001-receipt-xss", "REJECTED", reason)
        self.assertIn("attacker_login", feedback["reason_description"])
        self.assertIn("ctx.username", feedback["reason_description"])
        self.assertIn("attacker_login", feedback["next_step"])
        self.assertNotIn("secret-password", str(feedback))
        self.assertFalse(syntax_ok)
        self.assertEqual(syntax_reason, "ATTACKER_SYNTAXERROR")

    def test_attacker_process_forces_utf8_and_decodes_stderr_as_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            poclib_file = Path(directory) / "poclib.py"
            poclib_file.write_text("pass", encoding="utf-8")
            manifest = _manifest(extension_path_budget=0)
            captured: dict = {}

            def fake_run(command, **kwargs):
                captured["command"] = command
                captured["kwargs"] = kwargs
                return Mock(returncode=1, stderr="RECEIPT_POC_FAILURE:EvidenceMissing\n")

            with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
                executor = DockerAttackerExecutor(image="test-image", poclib_file=poclib_file)
                with patch("app.receipt.is_pinned_attacker_image", return_value=True), patch("app.receipt.subprocess.run", side_effect=fake_run):
                    ok, reason = executor.run(_candidate(), target, "challenge", 1)
        self.assertFalse(ok)
        self.assertEqual(reason, "ATTACKER_EVIDENCEMISSING")
        self.assertIn("PYTHONUTF8=1", captured["command"])
        self.assertIn("PYTHONIOENCODING=utf-8", captured["command"])
        self.assertEqual(captured["kwargs"]["encoding"], "utf-8")
        self.assertEqual(captured["kwargs"]["errors"], "replace")

    def _run_exit(self, returncode: int, stderr: str, *, credentials: bool = False) -> str:
        raw = _candidate().as_mapping()
        if credentials:
            raw["attacker_script"] = _source().replace(
                "payload = ",
                "login = ctx.username + ctx.password\n    payload = ",
            )
        candidate = ReceiptCandidate.from_mapping(raw, base_url="http://127.0.0.1:9/")
        with tempfile.TemporaryDirectory() as directory:
            poclib_file = Path(directory) / "poclib.py"
            poclib_file.write_text("pass", encoding="utf-8")
            manifest = _manifest(extension_path_budget=0)
            with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
                executor = DockerAttackerExecutor(image="test-image", poclib_file=poclib_file)
                completed = Mock(returncode=returncode, stderr=stderr)
                with patch("app.receipt.is_pinned_attacker_image", return_value=True), patch("app.receipt.subprocess.run", return_value=completed):
                    ok, reason = executor.run(candidate, target, "challenge", 1)
        self.assertFalse(ok)
        return reason

    def test_marker_wins_over_an_earlier_traceback_name(self) -> None:
        stderr = "NameError: leaked\nRECEIPT_POC_FAILURE:ConnectionRefusedError\n"
        self.assertEqual(self._run_exit(1, stderr), "ATTACKER_CONNECTIONERROR")

    def test_known_exception_aliases_keep_their_category(self) -> None:
        self.assertEqual(self._run_exit(1, "RECEIPT_POC_FAILURE:JSONDecodeError\n"), "ATTACKER_VALUEERROR")
        self.assertEqual(self._run_exit(1, "RECEIPT_POC_FAILURE:UnicodeEncodeError\n"), "ATTACKER_UNICODEERROR")

    def test_killed_process_is_infrastructure_even_if_script_reads_credentials(self) -> None:
        self.assertEqual(self._run_exit(137, "Killed\n", credentials=True), "ATTACKER_KILLED")
        self.assertEqual(self._run_exit(1, "Killed\n", credentials=True), "ATTACKER_FAILED")

    def test_login_infrastructure_is_not_a_selector_failure(self) -> None:
        raw = _candidate().as_mapping()
        raw["attacker_login"] = [
            {"type": "goto", "path": "/login"},
            {"type": "fill", "selector": "#user", "value": "{{username}}"},
            {"type": "fill", "selector": "#password", "value": "{{password}}"},
            {"type": "click", "selector": "button"},
            {"type": "assert_visible", "selector": "#account"},
        ]
        candidate = ReceiptCandidate.from_mapping(raw, base_url="http://127.0.0.1:9/")
        timeout = type("TimeoutError", (Exception,), {"__module__": "playwright.sync_api"})
        launch = type("Error", (Exception,), {"__module__": "playwright.sync_api"})
        cases = (
            (ReceiptError("攻击者登录浏览器不可用"), "ATTACKER_LOGIN_UNAVAILABLE"),
            (timeout("waiting for #account"), "ATTACKER_LOGIN_FAILED"),
            (launch("BrowserType.launch: Executable doesn't exist"), "ATTACKER_LOGIN_UNAVAILABLE"),
        )
        for exc, expected in cases:
            with self.subTest(expected=expected):
                with tempfile.TemporaryDirectory() as directory:
                    poclib_file = Path(directory) / "poclib.py"
                    poclib_file.write_text("pass", encoding="utf-8")
                    manifest = _manifest(extension_path_budget=0)
                    with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
                        target = replace(target, login_attacker=lambda steps, error=exc: (_ for _ in ()).throw(error))
                        executor = DockerAttackerExecutor(image="test-image", poclib_file=poclib_file)
                        with patch("app.receipt.is_pinned_attacker_image", return_value=True):
                            ok, reason = executor.run(candidate, target, "challenge", 1)
                self.assertFalse(ok)
                self.assertEqual(reason, expected)


class ReceiptModelTests(unittest.TestCase):
    def test_candidate_rejects_external_victim_url(self) -> None:
        raw = _candidate().as_mapping()
        raw["victim"]["url"] = "https://evil.test/x"
        with self.assertRaises(ReceiptError):
            ReceiptCandidate.from_mapping(raw, base_url="http://127.0.0.1:9/")

    def test_candidate_keeps_poc_specific_login_steps(self) -> None:
        raw = _candidate().as_mapping()
        login = [
            {"type": "goto", "path": "/login"},
            {"type": "fill", "selector": "#user", "value": "{{username}}"},
            {"type": "fill", "selector": "#password", "value": "{{password}}"},
            {"type": "click", "selector": "button[type=submit]"},
            {"type": "assert_visible", "selector": "#account"},
        ]
        raw["attacker_login"] = login
        raw["victim"]["login"] = login
        candidate = ReceiptCandidate.from_mapping(raw, base_url="http://127.0.0.1:9/")
        self.assertEqual(candidate.attacker_login[0].path, "/login")
        self.assertEqual(candidate.victim_login[-1].selector, "#account")
        self.assertEqual(candidate.as_mapping()["victim"]["login"], login)

    def test_candidate_rejects_incomplete_login_steps(self) -> None:
        raw = _candidate().as_mapping()
        raw["victim"]["login"] = [
            {"type": "goto", "path": "/login"},
            {"type": "fill", "selector": "#user", "value": "{{username}}"},
            {"type": "assert_visible", "selector": "#account"},
        ]
        with self.assertRaises(ReceiptError):
            ReceiptCandidate.from_mapping(raw, base_url="http://127.0.0.1:9/")

    def test_manifest_accepts_only_basic_http_auth(self) -> None:
        raw = {
            "target": {"id": "demo", "version": "1", "image_digest": "sha256:test"},
            "adapter": "test",
            "allowed_origins": ["http://target.test"],
            "principals": [{"id": "author-1"}, {"id": "admin-1"}],
            "threat_paths": [{
                "id": "author-to-admin",
                "primary": True,
                "attacker_principal": "author-1",
                "victim_principal": "admin-1",
            }],
        }
        self.assertEqual(TargetManifest.from_mapping(raw).browser_http_auth, "")
        raw["browser_http_auth"] = "basic"
        self.assertEqual(TargetManifest.from_mapping(raw).browser_http_auth, "basic")
        raw["browser_http_auth"] = "bearer"
        with self.assertRaises(ReceiptError):
            TargetManifest.from_mapping(raw)

    def test_victim_browser_receives_http_credentials_only_when_set(self) -> None:
        seen: dict[str, object] = {}

        class Page:
            url = "http://target.test/view"
            main_frame = None

            def __init__(self, context) -> None:
                self.context = context
                self.main_frame = self

            def set_default_timeout(self, *args) -> None:
                pass

            def goto(self, *args, **kwargs):
                self.context.callback({"page": self, "frame": self}, "receipt-token")
                return types.SimpleNamespace(status=200)

            def locator(self, *args):
                return self

            def click(self, **kwargs: object) -> None:
                pass

            def wait_for_timeout(self, *args) -> None:
                pass

        class Context:
            def route(self, *args) -> None:
                pass

            def route_web_socket(self, *args) -> None:
                pass

            def expose_binding(self, name, callback) -> None:
                del name
                self.callback = callback

            def add_init_script(self, *args) -> None:
                pass

            def new_page(self):
                return Page(self)

        class Browser:
            def new_context(self, **kwargs):
                seen["kwargs"] = kwargs
                return Context()

            def close(self) -> None:
                pass

        class Chromium:
            executable_path = "chromium"

            def launch(self, **kwargs):
                return Browser()

        class Playwright:
            chromium = Chromium()

            def __enter__(self):
                return self

            def __exit__(self, *args) -> None:
                return None

        api = types.ModuleType("playwright.sync_api")
        api.sync_playwright = Playwright
        api.Error = Exception
        api.TimeoutError = Exception
        package = types.ModuleType("playwright")
        package.sync_api = api
        manifest = _manifest(extension_path_budget=0)
        credentials = {"username": "reader", "password": "secret2"}
        with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
            with patch.dict(sys.modules, {"playwright": package, "playwright.sync_api": api}):
                PlaywrightVictimDriver().run(_candidate(), target, manifest.threat_paths[0], "receipt-token", 1000)
                self.assertEqual(seen["kwargs"], {})
                evidence = PlaywrightVictimDriver().run(
                    _candidate(), replace(target, victim_http_credentials=credentials), manifest.threat_paths[0], "receipt-token", 1000,
                )
        self.assertEqual(seen["kwargs"], {"http_credentials": credentials})
        self.assertTrue(evidence.accepted)

    def test_changed_session_cookie_rejects_the_victim_browser(self) -> None:
        from app.receipt import LoginStep
        from app.receipt_execution import receipt_agent_feedback

        secret = "receipt-token"

        def run_with(jars: list[list[dict[str, str]]]) -> BrowserEvidence:
            class Page:
                url = "http://target.test/view"

                def __init__(self, context) -> None:
                    self.context = context
                    self.main_frame = self

                def set_default_timeout(self, *args) -> None:
                    del args

                def goto(self, *args, **kwargs):
                    del args, kwargs
                    self.context.callback({"page": self, "frame": self}, secret)
                    return types.SimpleNamespace(status=200)

                def locator(self, *args):
                    del args
                    return self

                def click(self, **kwargs: object) -> None:
                    return None

                def wait_for_timeout(self, *args) -> None:
                    del args

            class Context:
                def __init__(self) -> None:
                    self.reads = 0

                def route(self, *args) -> None:
                    del args

                def route_web_socket(self, *args) -> None:
                    del args

                def expose_binding(self, name, callback) -> None:
                    del name
                    self.callback = callback

                def add_init_script(self, *args) -> None:
                    del args

                def new_page(self) -> Page:
                    return Page(self)

                def cookies(self) -> list[dict[str, str]]:
                    jar = jars[min(self.reads, len(jars) - 1)]
                    self.reads += 1
                    return jar

            class Browser:
                def new_context(self, **kwargs):
                    del kwargs
                    return Context()

                def close(self) -> None:
                    return None

            class Chromium:
                executable_path = "chromium"

                def launch(self, **kwargs):
                    del kwargs
                    return Browser()

            class Playwright:
                chromium = Chromium()

                def __enter__(self):
                    return self

                def __exit__(self, *args) -> None:
                    return None

            api = types.ModuleType("playwright.sync_api")
            api.sync_playwright = Playwright
            api.Error = Exception
            api.TimeoutError = Exception
            package = types.ModuleType("playwright")
            package.sync_api = api
            manifest = _manifest(extension_path_budget=0)
            candidate = replace(_candidate(), victim_login=(LoginStep("goto", path="/login"),))
            with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
                target = replace(target, login_victim=lambda *args: True)
                with patch.dict(sys.modules, {"playwright": package, "playwright.sync_api": api}):
                    return PlaywrightVictimDriver().run(candidate, target, manifest.threat_paths[0], secret, 1000)

        session = {"name": "PHPSESSID", "value": "victim", "domain": "target.test", "path": "/"}
        csrf = {"name": "csrf", "value": "a", "domain": "target.test", "path": "/"}
        stable = run_with([[session, csrf], [{**session}, {**csrf, "value": "b"}]])
        self.assertTrue(stable.accepted)
        self.assertNotIn(secret, repr(stable))
        replaced = run_with([[session], [{**session, "value": "attacker"}]])
        self.assertFalse(replaced.accepted)
        self.assertEqual(replaced.reason, "VICTIM_IDENTITY_CHANGED")
        self.assertNotIn("attacker", repr(replaced))
        added = run_with([[session], [session, {"name": "EM_AUTHCOOKIE_x", "value": "other", "domain": "target.test", "path": "/"}]])
        self.assertEqual(added.reason, "VICTIM_IDENTITY_CHANGED")

        class IdentityBrowser:
            def run(self, *args):
                del args
                return BrowserEvidence(False, "VICTIM_IDENTITY_CHANGED")

        result = ReceiptVerifier(
            adapter=_Adapter(), attacker=_Attacker(), browser=IdentityBrowser(), receipt_key=b"k" * 32,
        ).verify(_candidate(), _manifest(extension_path_budget=0))
        self.assertEqual(result.verdict, ReceiptVerdict.REJECTED)
        self.assertEqual(receipt_agent_feedback("001-receipt-xss", result)["reason"], "VICTIM_IDENTITY_CHANGED")

    def test_manifest_rejects_implicit_self_xss(self) -> None:
        raw = {
            "target": {"id": "demo", "version": "1", "image_digest": "sha256:test"},
            "adapter": "test",
            "allowed_origins": ["http://target.test"],
            "principals": [{"id": "author-1"}],
            "threat_paths": [
                {"id": "self", "primary": True, "attacker_principal": "author-1", "victim_principal": "author-1"}
            ],
        }
        with self.assertRaises(ReceiptError):
            TargetManifest.from_mapping(raw)

    def test_manifest_rejects_aliases_for_same_account(self) -> None:
        raw = {"target": {"id": "demo", "version": "1", "image_digest": "test"},
               "adapter": "test", "allowed_origins": ["http://target.test"],
               "principals": [{"id": "a", "account_id": "same"}, {"id": "b", "account_id": "same"}],
               "threat_paths": [{"id": "alias", "primary": True, "attacker_principal": "a", "victim_principal": "b"}]}
        with self.assertRaises(ReceiptError):
            TargetManifest.from_mapping(raw)
        raw["threat_paths"][0]["accept_self_xss"] = True
        self.assertTrue(TargetManifest.from_mapping(raw).threat_paths[0].accept_self_xss)

    def test_submitted_victim_urls_reject_authentication_query_parameters(self) -> None:
        from dataclasses import replace
        from app.receipt_execution import receipt_agent_feedback

        manifest = replace(_manifest(extension_path_budget=0), auth_query_params=("session_id", "my_auth"))
        verifier = ReceiptVerifier(adapter=_Adapter(), attacker=_Attacker(), browser=_Browser(), receipt_key=b"k" * 32)
        for url in ("/view?SESSION_ID=abc", "/view?%6dy_auth=abc", "/view?my_auth="):
            with self.subTest(url=url):
                result = verifier.verify(replace(_candidate(), victim_url=url), manifest)
                self.assertEqual(result.paths[0].reason, "VICTIM_URL_AUTH_PARAMETER")
                self.assertEqual(receipt_agent_feedback("001-receipt-xss", result)["reason"], "VICTIM_URL_AUTH_PARAMETER")
        from app.receipt import LoginStep
        candidate = replace(_candidate(), victim_login=(LoginStep("goto", path="/login?my_auth=x"),))
        self.assertEqual(verifier.verify(candidate, manifest).paths[0].reason, "VICTIM_URL_AUTH_PARAMETER")
        self.assertEqual(verifier.verify(replace(_candidate(), victim_url="/view?content=ok"), manifest).verdict, ReceiptVerdict.ACCEPTED)
        plain = _manifest(extension_path_budget=0)
        self.assertEqual(verifier.verify(replace(_candidate(), victim_url="/admin/media.php?sid=1"), plain).verdict, ReceiptVerdict.ACCEPTED)
        self.assertEqual(
            verifier.verify(replace(_candidate(), victim_url="/view?session=business"), plain).verdict,
            ReceiptVerdict.ACCEPTED,
        )
        login_sid = replace(_candidate(), victim_login=(LoginStep("goto", path="/login?sid=1"),))
        self.assertEqual(verifier.verify(login_sid, plain).paths[0].reason, "VICTIM_URL_AUTH_PARAMETER")
        listed = replace(plain, auth_query_params=("sid",))
        self.assertEqual(
            verifier.verify(replace(_candidate(), victim_url="/admin/media.php?sid=1"), listed).paths[0].reason,
            "VICTIM_URL_AUTH_PARAMETER",
        )

    def test_manifest_keeps_declared_auth_parameters_without_builtin_names(self) -> None:
        raw = {"target": {"id": "demo", "version": "1", "image_digest": "test"},
               "adapter": "test", "allowed_origins": ["http://target.test"],
               "principals": [{"id": "a"}, {"id": "b"}],
               "threat_paths": [{"id": "a-b", "primary": True, "attacker_principal": "a", "victim_principal": "b"}],
               "auth_query_params": ["CustomKey"]}
        manifest = TargetManifest.from_mapping(raw)
        self.assertIn("customkey", manifest.auth_query_params)
        self.assertNotIn("session_id", manifest.auth_query_params)
        self.assertNotIn("sid", manifest.auth_query_params)
        raw["auth_query_params"] = ["bad=name"]
        with self.assertRaises(ReceiptError):
            TargetManifest.from_mapping(raw)

    def test_commit_round_trips_without_roles(self) -> None:
        from app.receipt import commit_receipt_candidate, load_receipt_candidate

        raw = _candidate().as_mapping()
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            committed = commit_receipt_candidate(workspace, "http://127.0.0.1:9/", raw)
            loaded = load_receipt_candidate(workspace, committed.poc_id, base_url="http://127.0.0.1:9/")
        self.assertEqual(loaded.source_hash, committed.source_hash)
        self.assertNotIn("attacker_principal", committed.as_mapping())
        self.assertNotIn("victim_principal", committed.as_mapping())

    def test_candidate_file_is_the_replay_source(self) -> None:
        from app.receipt import commit_receipt_candidate, load_receipt_candidate

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            committed = commit_receipt_candidate(workspace, "http://127.0.0.1:9/", _candidate().as_mapping())
            loaded = load_receipt_candidate(workspace, committed.poc_id, base_url="http://127.0.0.1:9/")
            self.assertFalse((workspace / "receipt" / "poc-manifest.json").exists())
            self.assertTrue((workspace / "receipt" / "candidates" / "001-receipt-xss.json").is_file())
            self.assertEqual(loaded.source_hash, committed.source_hash)
            self.assertEqual(loaded.poc_id, "001-receipt-xss")
            with self.assertRaises(ReceiptError):
                load_receipt_candidate(workspace, "002-not-listed", base_url="http://127.0.0.1:9/")

    def test_wait_action_round_trips_through_candidate_file(self) -> None:
        from app.receipt import commit_receipt_candidate, load_receipt_candidate

        raw = _candidate().as_mapping()
        raw["victim"]["actions"] = [{"type": "wait", "milliseconds": 600}]
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            committed = commit_receipt_candidate(workspace, "http://127.0.0.1:9/", raw)
            persisted = json.loads((workspace / "receipt" / "candidates" / "001-receipt-xss.json").read_text(encoding="utf-8"))
            loaded = load_receipt_candidate(workspace, committed.poc_id, base_url="http://127.0.0.1:9/")
        self.assertEqual(persisted["victim"]["actions"], [{"type": "wait", "milliseconds": 600}])
        self.assertEqual(loaded.source_hash, committed.source_hash)

    def test_candidate_snapshot_ignores_later_script_edits(self) -> None:
        from app.receipt import commit_receipt_candidate, load_receipt_candidate

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            committed = commit_receipt_candidate(workspace, "http://127.0.0.1:9/", _candidate().as_mapping())
            script = workspace / "poc" / "001-receipt-xss.py"
            script.parent.mkdir()
            script.write_text("changed after submission", encoding="utf-8")
            loaded = load_receipt_candidate(workspace, committed.poc_id, base_url="http://127.0.0.1:9/")
            self.assertEqual(loaded.attacker_script, committed.attacker_script)
            self.assertEqual(loaded.source_hash, committed.source_hash)
            self.assertNotIn("changed after submission", loaded.attacker_script)

    def test_commit_rejects_duplicate_marker_and_extra_fields_before_writing(self) -> None:
        from app.receipt import commit_receipt_candidate

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            first = _candidate().as_mapping()
            first["attacker_script"] = ""
            commit_receipt_candidate(workspace, "http://127.0.0.1:9/", first)
            duplicate = {
                "poc_id": "002-receipt-xss",
                "marker": first["marker"],
                "victim": {"url": "/other", "actions": []},
            }
            with self.assertRaises(ReceiptError):
                commit_receipt_candidate(workspace, "http://127.0.0.1:9/", duplicate)
            self.assertFalse((workspace / "receipt" / "candidates" / "002-receipt-xss.json").exists())
            again = dict(first)
            again["victim"] = {"url": "/updated", "actions": []}
            replaced = commit_receipt_candidate(workspace, "http://127.0.0.1:9/", again)
            self.assertEqual(replaced.victim_url, "/updated")
            self.assertEqual(replaced.marker, first["marker"])

        raw = _candidate().as_mapping()
        raw["attacker_principal"] = "author-1"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            with self.assertRaises(ReceiptError):
                commit_receipt_candidate(workspace, "http://127.0.0.1:9/", raw)
            self.assertFalse((workspace / "receipt" / "candidates" / "001-receipt-xss.json").exists())
            self.assertFalse((workspace / "receipt" / "poc-manifest.json").exists())


class ReceiptVerificationTests(unittest.TestCase):
    def test_execution_startup_failures_have_safe_specific_agent_feedback(self) -> None:
        from app.receipt_execution import ReceiptExecutionError, receipt_failure_feedback, verify_receipt_candidate

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ReceiptExecutionError) as raised:
                verify_receipt_candidate(Path(directory), "http://127.0.0.1:9/", "missing.json", "001-receipt-xss")
        self.assertEqual(raised.exception.reason, "RECEIPT_MANIFEST_UNAVAILABLE")
        feedback = receipt_failure_feedback("001-receipt-xss", "INDETERMINATE", raised.exception.reason)
        self.assertEqual(feedback["reason"], "RECEIPT_MANIFEST_UNAVAILABLE")
        self.assertIn("manifest", feedback["reason_description"])
        self.assertIn("operator", feedback["next_step"])

    def test_agent_feedback_redacts_threat_path_details(self) -> None:
        from app.receipt_execution import receipt_agent_feedback

        result = ReceiptVerifier(adapter=_Adapter(), attacker=_Attacker(), browser=_Browser(), receipt_key=b"k" * 32).verify(
            _candidate(), _manifest(extension_path_budget=1)
        )
        feedback = receipt_agent_feedback("001-receipt-xss", result)
        self.assertEqual(
            feedback,
            {
                "poc_id": "001-receipt-xss",
                "verdict": "ACCEPTED",
                "reason": "BROWSER_BOUND_RECEIPT",
            },
        )
        self.assertNotIn("author-to-admin", str(feedback))
        self.assertNotIn("editor-to-admin", str(feedback))

    def test_empty_attacker_script_skips_attacker_executor(self) -> None:
        raw = _candidate().as_mapping()
        raw["attacker_script"] = ""
        candidate = ReceiptCandidate.from_mapping(raw, base_url="http://127.0.0.1:9/")

        class MustNotRun:
            def run(self, candidate, target, token, timeout_seconds):
                raise AssertionError("无攻击者脚本时不应启动攻击者执行器")

        result = ReceiptVerifier(adapter=_Adapter(), attacker=MustNotRun(), browser=_Browser(), receipt_key=b"k" * 32).verify(
            candidate, _manifest(extension_path_budget=0)
        )
        self.assertEqual(result.verdict, ReceiptVerdict.ACCEPTED)

    def test_primary_then_budgeted_extension_uses_distinct_tokens(self) -> None:
        attacker = _Attacker()
        browser = _Browser()
        result = ReceiptVerifier(adapter=_Adapter(), attacker=attacker, browser=browser, receipt_key=b"k" * 32).verify(
            _candidate(), _manifest(extension_path_budget=1)
        )
        self.assertEqual(result.verdict, ReceiptVerdict.ACCEPTED)
        self.assertEqual(result.paths[0].path_id, "author-to-admin")
        self.assertEqual(len(result.paths[1:]), 1)
        self.assertEqual(result.paths[1:][0].path_id, "editor-to-admin")
        self.assertEqual(len(attacker.tokens), 2)
        self.assertEqual(len(set(attacker.tokens)), 2)
        self.assertEqual(attacker.tokens, browser.tokens)
        self.assertNotIn(attacker.tokens[0], str(result.public_mapping()))

    def test_primary_rejection_still_runs_extensions(self) -> None:
        from app.receipt_execution import receipt_agent_feedback
        attacker = _Attacker()
        result = ReceiptVerifier(adapter=_Adapter(), attacker=attacker, browser=_Browser(False), receipt_key=b"k" * 32).verify(
            _candidate(), _manifest(extension_path_budget=1)
        )
        self.assertEqual(result.verdict, ReceiptVerdict.REJECTED)
        self.assertEqual(result.paths[0].reason, "NO_BROWSER_BOUND_RECEIPT")
        feedback = receipt_agent_feedback("001-receipt-xss", result)
        self.assertEqual(feedback["reason"], "NO_BROWSER_BOUND_RECEIPT")
        self.assertEqual(feedback["reason_description"], "The victim browser did not receive a valid execution receipt.")
        self.assertEqual(len(result.paths[1:]), 1)
        self.assertEqual(result.paths[1:][0].verdict, ReceiptVerdict.REJECTED)
        self.assertEqual(len(attacker.tokens), 2)

    def test_extension_acceptance_after_primary_attacker_failure(self) -> None:
        from app.receipt_execution import receipt_agent_feedback

        class PermissionAttacker(_Attacker):
            def run(self, candidate, target, token, timeout_seconds):
                super().run(candidate, target, token, timeout_seconds)
                return (False, "ATTACKER_FAILED") if len(self.tokens) == 1 else (True, "ATTACKER_COMPLETED")

        class TrackingAdapter(_Adapter):
            def __init__(self):
                self.runs = []

            @contextmanager
            def open_run(self, manifest, path, run_id):
                self.runs.append((path.id, run_id))
                with super().open_run(manifest, path, run_id) as target:
                    yield target

        attacker, browser, adapter = PermissionAttacker(), _Browser(), TrackingAdapter()
        result = ReceiptVerifier(adapter=adapter, attacker=attacker, browser=browser, receipt_key=b"k" * 32).verify(
            _candidate(), _manifest()
        )
        self.assertEqual(result.paths[0].verdict, ReceiptVerdict.REJECTED)
        self.assertEqual(result.paths[1:][0].verdict, ReceiptVerdict.ACCEPTED)
        self.assertEqual(result.verdict, ReceiptVerdict.ACCEPTED)
        self.assertEqual(result.public_mapping()["verdict"], "ACCEPTED")
        paths = result.public_mapping()["paths"]
        self.assertEqual([(p["attacker_principal"], p["victim_principal"], p["verdict"]) for p in paths], [
            ("author-1", "admin-1", "REJECTED"), ("editor-1", "admin-1", "ACCEPTED"),
        ])
        self.assertEqual(len(set(attacker.tokens)), 2)
        self.assertEqual(browser.tokens, attacker.tokens[1:])
        self.assertEqual([path for path, _ in adapter.runs], [path.id for path in _manifest().threat_paths])
        self.assertEqual(len({run_id for _, run_id in adapter.runs}), 2)
        self.assertEqual(receipt_agent_feedback("001-receipt-xss", result), {
            "poc_id": "001-receipt-xss", "verdict": "ACCEPTED", "reason": "BROWSER_BOUND_RECEIPT",
        })

    def test_attacker_timeout_is_indeterminate_not_accepted(self) -> None:
        from app.receipt_execution import receipt_agent_feedback
        class TimeoutAttacker:
            def run(self, candidate, target, token, timeout_seconds):
                del candidate, target, token, timeout_seconds
                return False, "ATTACKER_TIMEOUT"

        result = ReceiptVerifier(adapter=_Adapter(), attacker=TimeoutAttacker(), browser=_Browser(), receipt_key=b"k" * 32).verify(
            _candidate(), _manifest()
        )
        self.assertEqual(result.verdict, ReceiptVerdict.INDETERMINATE)
        self.assertEqual(result.paths[0].reason, "ATTACKER_TIMEOUT")
        feedback = receipt_agent_feedback("001-receipt-xss", result)
        self.assertEqual(feedback["reason"], "ATTACKER_TIMEOUT")
        self.assertEqual(feedback["reason_description"], "The attacker script exceeded the execution time limit.")

    def test_path_verdicts_are_aggregated_without_short_circuiting(self) -> None:
        cases = (
            (ReceiptVerdict.REJECTED, ReceiptVerdict.ACCEPTED, ReceiptVerdict.ACCEPTED),
            (ReceiptVerdict.INDETERMINATE, ReceiptVerdict.ACCEPTED, ReceiptVerdict.ACCEPTED),
            (ReceiptVerdict.ACCEPTED, ReceiptVerdict.INDETERMINATE, ReceiptVerdict.ACCEPTED),
            (ReceiptVerdict.REJECTED, ReceiptVerdict.INDETERMINATE, ReceiptVerdict.INDETERMINATE),
            (ReceiptVerdict.INDETERMINATE, ReceiptVerdict.REJECTED, ReceiptVerdict.INDETERMINATE),
            (ReceiptVerdict.REJECTED, ReceiptVerdict.REJECTED, ReceiptVerdict.REJECTED),
        )
        for primary, extension, expected in cases:
            with self.subTest(primary=primary, extension=extension):
                manifest = _manifest()
                verifier = ReceiptVerifier(adapter=_Adapter(), attacker=_Attacker(), browser=_Browser())
                results = [PathResult(path.id, verdict, "test") for path, verdict in zip(manifest.threat_paths, (primary, extension))]
                with patch.object(verifier, "_verify_path", side_effect=results) as replay:
                    result = verifier.verify(_candidate(), manifest)
                self.assertEqual(result.verdict, expected)
                self.assertEqual(result.public_mapping()["verdict"], expected.value)
                self.assertEqual(replay.call_count, 2)

    def test_path_progress_reports_completed_replays_without_changing_verdict(self) -> None:
        verifier = ReceiptVerifier(adapter=_Adapter(), attacker=_Attacker(), browser=_Browser(False))
        progress = []
        result = verifier.verify(_candidate(), _manifest(), on_path_complete=lambda done, total: progress.append((done, total)))
        self.assertEqual(progress, [(1, 2), (2, 2)])
        self.assertEqual(len(result.paths[1:]), 1)

        def broken_progress(done, total):
            raise RuntimeError("notification failed")

        result = verifier.verify(_candidate(), _manifest(), on_path_complete=broken_progress)
        self.assertEqual(result.paths[0].reason, "NO_BROWSER_BOUND_RECEIPT")

    def test_only_selected_paths_run_for_every_verdict(self) -> None:
        manifest = _manifest()
        primary, extension = manifest.threat_paths
        no_selection = BaseReceiptVerifier(adapter=_Adapter(), attacker=_Attacker(), browser=_Browser(False))
        with patch.object(no_selection, '_verify_path') as replay:
            result = no_selection.verify(_candidate(), manifest)
        replay.assert_not_called()
        self.assertEqual(result.verdict, ReceiptVerdict.INDETERMINATE)
        verifier = ReceiptVerifier(adapter=_Adapter(), attacker=_Attacker(), browser=_Browser(False))
        for selected_verdict in (ReceiptVerdict.ACCEPTED, ReceiptVerdict.REJECTED, ReceiptVerdict.INDETERMINATE):
            with self.subTest(selected_verdict=selected_verdict):
                def run(candidate, model, path, attempt):
                    verdict = selected_verdict if path.id == extension.id else ReceiptVerdict.REJECTED
                    return PathResult(path.id, verdict, 'test')
                with patch.object(verifier, '_verify_path', side_effect=run) as replay:
                    result = verifier.verify(_candidate(), manifest, preferred_path_ids=(extension.id,))
                self.assertEqual([call.args[2].id for call in replay.call_args_list], [extension.id])
                self.assertEqual(result.paths[0].verdict, ReceiptVerdict.NOT_RUN)
                self.assertEqual(result.paths[0].reason, 'PATH_NOT_SELECTED')
                self.assertEqual(result.verdict, selected_verdict)
                mapping = result.public_mapping()
                self.assertEqual([item['path_id'] for item in mapping['paths']], [primary.id, extension.id])
                self.assertNotIn('primary', mapping)
                self.assertNotIn('extensions', mapping)
        with patch.object(verifier, '_verify_path', side_effect=lambda candidate, model, path, attempt:
                          PathResult(path.id, ReceiptVerdict.REJECTED, 'test')) as replay:
            result = verifier.verify(_candidate(), manifest, preferred_path_ids=('not-in-manifest',))
        replay.assert_not_called()
        self.assertEqual(result.verdict, ReceiptVerdict.INDETERMINATE)
        self.assertEqual(result.decisive_path.reason, 'PATH_SELECTION_UNAVAILABLE')

        with patch.object(verifier, '_verify_path', side_effect=lambda candidate, model, path, attempt:
                          PathResult(path.id, ReceiptVerdict.ACCEPTED, 'test')) as replay:
            result = verifier.verify(_candidate(), manifest, preferred_path_ids=(extension.id, primary.id))
        self.assertEqual([call.args[2].id for call in replay.call_args_list], [extension.id, primary.id])
        self.assertEqual(result.verdict, ReceiptVerdict.ACCEPTED)

    def test_unrun_paths_are_recorded_and_do_not_count_as_rejections(self) -> None:
        from app.receipt_execution import receipt_agent_feedback

        manifest = _manifest(extension_path_budget=0)
        for accepted in (False, True):
            with self.subTest(accepted=accepted):
                attacker = _Attacker()
                result = ReceiptVerifier(adapter=_Adapter(), attacker=attacker, browser=_Browser(accepted)).verify(
                    _candidate(), manifest, preferred_path_ids=(manifest.threat_paths[0].id,)
                )
                self.assertEqual(len(attacker.tokens), 1)
                self.assertEqual(len(result.paths[1:]), 1)
                skipped = result.paths[1:][0]
                self.assertEqual(skipped.path_id, manifest.threat_paths[1].id)
                self.assertEqual(skipped.verdict, ReceiptVerdict.NOT_RUN)
                self.assertEqual(skipped.reason, "PATH_NOT_SELECTED")
                self.assertEqual(skipped.run_id, "")
                self.assertEqual((skipped.attacker_principal, skipped.victim_principal), ("editor-1", "admin-1"))
                self.assertEqual(result.verdict, ReceiptVerdict.ACCEPTED if accepted else ReceiptVerdict.REJECTED)
                feedback = receipt_agent_feedback("001-receipt-xss", result)
                self.assertNotIn(skipped.path_id, str(feedback))

    def test_signature_covers_all_path_results(self) -> None:
        import hashlib
        import hmac

        key = b"k" * 32
        result = ReceiptVerifier(adapter=_Adapter(), attacker=_Attacker(), browser=_Browser(), receipt_key=key).verify(
            _candidate(), _manifest()
        )
        mapping = result.public_mapping()
        payload = {name: mapping[name] for name in ("candidate_hash", "manifest_hash", "paths")}
        expected = hmac.new(key, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
        self.assertEqual(mapping["receipt_hmac"], expected)

    def test_budget_preserves_primary_first_and_records_all_remaining_paths(self) -> None:
        manifest = _manifest()
        primary, extension = manifest.threat_paths
        third = replace(extension, id="other-path")
        manifest = replace(manifest, threat_paths=(extension, primary, third))
        verifier = ReceiptVerifier(adapter=_Adapter(), attacker=_Attacker(), browser=_Browser(False))
        with patch.object(verifier, "_verify_path", side_effect=lambda candidate, model, path, attempt: PathResult(
            path.id, ReceiptVerdict.REJECTED, "NO_BROWSER_BOUND_RECEIPT"
        )) as replay:
            result = verifier.verify(_candidate(), manifest, attempt=3)
        self.assertEqual([call.args[2].id for call in replay.call_args_list], [extension.id, primary.id, third.id])
        self.assertTrue(all(call.args[3] == 3 for call in replay.call_args_list))
        self.assertEqual([path.path_id for path in result.paths], [extension.id, primary.id, third.id])
        self.assertEqual(result.paths[1:][-1].verdict, ReceiptVerdict.REJECTED)
        self.assertEqual(result.verdict, ReceiptVerdict.REJECTED)

    def test_feedback_uses_extension_infrastructure_failure_and_its_diagnostics(self) -> None:
        from app.receipt_execution import receipt_agent_feedback

        manifest = _manifest()
        verifier = ReceiptVerifier(adapter=_Adapter(), attacker=_Attacker(), browser=_Browser())
        results = [
            PathResult(manifest.threat_paths[0].id, ReceiptVerdict.REJECTED, "ATTACKER_FAILED"),
            PathResult(manifest.threat_paths[1].id, ReceiptVerdict.INDETERMINATE, "BROWSER_ERROR", evidence={
                "browser_error": {"stage": "victim_action", "type": "playwright_timeout", "action_index": 1},
            }),
        ]
        with patch.object(verifier, "_verify_path", side_effect=results):
            result = verifier.verify(_candidate(), manifest)
        feedback = receipt_agent_feedback("001-receipt-xss", result)
        self.assertEqual(feedback["verdict"], "INDETERMINATE")
        self.assertEqual(feedback["reason"], "BROWSER_ERROR")
        self.assertIn("index: 1", feedback["reason_description"])
        self.assertIn("ATTACKER_FAILED", feedback["reason_description"])
        self.assertIn("BROWSER_ERROR", feedback["reason_description"])
        self.assertNotIn(manifest.threat_paths[0].id, str(feedback))
        self.assertNotIn(manifest.threat_paths[1].id, str(feedback))

    def test_feedback_groups_distinct_victim_outcomes_without_path_ids(self) -> None:
        from app.receipt import ReceiptResult
        from app.receipt_execution import receipt_agent_feedback

        roles = {"admin-account": "role-admin", "user-account": "role-user", "demo-account": "role-demo"}
        result = ReceiptResult(
            "candidate",
            "manifest",
            (
                PathResult("path-admin", ReceiptVerdict.REJECTED, "NO_BROWSER_BOUND_RECEIPT", victim_principal="admin-account"),
                PathResult(
                    "path-user",
                    ReceiptVerdict.INDETERMINATE,
                    "BROWSER_ERROR",
                    victim_principal="user-account",
                    evidence={"browser_error": {"stage": "victim_action", "type": "playwright_timeout", "action_index": 1, "blocker": "not_found"}},
                ),
                PathResult(
                    "path-demo",
                    ReceiptVerdict.INDETERMINATE,
                    "BROWSER_ERROR",
                    victim_principal="demo-account",
                    evidence={"browser_error": {"stage": "victim_action", "type": "playwright_timeout", "action_index": 1, "blocker": "intercepted"}},
                ),
                PathResult("path-skipped", ReceiptVerdict.NOT_RUN, "PATH_NOT_SELECTED", victim_principal="admin-account"),
            ),
            "hmac",
        )
        feedback = receipt_agent_feedback("001-receipt-xss", result, roles)
        description = feedback["reason_description"]
        self.assertEqual(feedback["verdict"], "INDETERMINATE")
        self.assertEqual(feedback["reason"], "BROWSER_ERROR")
        self.assertIn("victim role role-admin: 1 path, REJECTED, NO_BROWSER_BOUND_RECEIPT", description)
        self.assertIn("victim role role-user: 1 path, INDETERMINATE, BROWSER_ERROR, victim action index 1, element not found", description)
        self.assertIn("victim role role-demo: 1 path, INDETERMINATE, BROWSER_ERROR, victim action index 1, element intercepted", description)
        self.assertIn("does not describe paths that completed their actions", feedback["next_step"])
        rendered = str(feedback)
        for hidden in ("path-admin", "path-user", "path-demo", "path-skipped", "admin-account", "user-account", "demo-account", "PATH_NOT_SELECTED"):
            self.assertNotIn(hidden, rendered)

    def test_click_blocker_classifies_timeout_without_keeping_the_message(self) -> None:
        from app.receipt import _click_blocker

        secret = "secret-selector-token"
        missing = f'waiting for locator("{secret}")'
        covered = f'locator resolved to <button data-secret="{secret}"> intercepts pointer events'
        self.assertEqual(_click_blocker(missing), "not_found")
        self.assertEqual(_click_blocker(covered), "intercepted")
        self.assertEqual(_click_blocker(f"locator resolved to <button>{secret}</button>"), "")
        self.assertNotIn(secret, _click_blocker(missing))
        self.assertNotIn(secret, _click_blocker(covered))

    def test_browser_evidence_records_only_the_blocker_enum(self) -> None:
        class Driver:
            def run(self, candidate, target, path, token, timeout_ms):
                del candidate, target, path, token, timeout_ms
                return BrowserEvidence(False, "BROWSER_ERROR", "", ("click",), "victim_action", "playwright_timeout", 1, None, "not_found")

        manifest = _manifest(extension_path_budget=0)
        result = ReceiptVerifier(adapter=_Adapter(), attacker=_Attacker(), browser=Driver(), receipt_key=b"k" * 32).verify(
            _candidate(), manifest, preferred_path_ids=(manifest.threat_paths[0].id,)
        )
        self.assertEqual(result.verdict, ReceiptVerdict.REJECTED)
        self.assertEqual(result.paths[0].reason, "BROWSER_ERROR")
        self.assertEqual(result.paths[0].evidence["browser_error"], {
            "stage": "victim_action",
            "type": "playwright_timeout",
            "action_index": 1,
            "blocker": "not_found",
        })

    def test_adapter_error_feedback_reports_attacker_rejection_from_a_completed_path(self) -> None:
        from app.receipt_execution import receipt_agent_feedback

        manifest = _manifest()
        verifier = ReceiptVerifier(adapter=_Adapter(), attacker=_Attacker(), browser=_Browser())
        results = [
            PathResult(manifest.threat_paths[0].id, ReceiptVerdict.INDETERMINATE, "ADAPTER_ERROR"),
            PathResult(manifest.threat_paths[1].id, ReceiptVerdict.REJECTED, "ATTACKER_EVIDENCEMISSING"),
        ]
        with patch.object(verifier, "_verify_path", side_effect=results):
            result = verifier.verify(_candidate(), manifest)
        feedback = receipt_agent_feedback("001-receipt-xss", result)
        self.assertEqual(feedback["verdict"], "INDETERMINATE")
        self.assertEqual(feedback["reason"], "ADAPTER_ERROR")
        self.assertIn("no evidence was observed", feedback["reason_description"])
        self.assertIn("expected response", feedback["next_step"])
        self.assertNotIn(manifest.threat_paths[0].id, str(feedback))
        self.assertNotIn(manifest.threat_paths[1].id, str(feedback))

    def test_adapter_error_feedback_reports_a_completed_browser_rejection(self) -> None:
        from app.receipt_execution import receipt_agent_feedback

        manifest = _manifest()
        verifier = ReceiptVerifier(adapter=_Adapter(), attacker=_Attacker(), browser=_Browser())
        results = [
            PathResult(manifest.threat_paths[0].id, ReceiptVerdict.INDETERMINATE, "ADAPTER_ERROR"),
            PathResult(
                manifest.threat_paths[1].id,
                ReceiptVerdict.REJECTED,
                "NO_BROWSER_BOUND_RECEIPT",
                evidence={"navigation_status": 403, "actions": ["wait"]},
            ),
        ]
        with patch.object(verifier, "_verify_path", side_effect=results):
            result = verifier.verify(_candidate(), manifest)
        feedback = receipt_agent_feedback("001-receipt-xss", result)
        self.assertEqual(feedback["reason"], "ADAPTER_ERROR")
        self.assertIn("HTTP 403", feedback["reason_description"])
        self.assertIn("access rights", feedback["next_step"])
        self.assertNotIn(manifest.threat_paths[1].id, str(feedback))

    def test_killed_attacker_is_indeterminate(self) -> None:
        from app.receipt_execution import receipt_agent_feedback

        class KilledAttacker:
            def run(self, candidate, target, token, timeout_seconds):
                del candidate, target, token, timeout_seconds
                return False, "ATTACKER_KILLED"

        result = ReceiptVerifier(adapter=_Adapter(), attacker=KilledAttacker(), browser=_Browser(), receipt_key=b"k" * 32).verify(
            _candidate(), _manifest(extension_path_budget=0)
        )
        self.assertEqual(result.verdict, ReceiptVerdict.INDETERMINATE)
        self.assertEqual(result.paths[0].reason, "ATTACKER_KILLED")
        feedback = receipt_agent_feedback("001-receipt-xss", result)
        self.assertEqual(feedback["reason"], "ATTACKER_KILLED")
        self.assertIn("runtime limit", feedback["reason_description"])

    def test_unknown_failure_details_are_not_exposed(self) -> None:
        from app.receipt_execution import receipt_agent_feedback, receipt_failure_feedback

        class UntrustedAttacker:
            def run(self, candidate, target, token, timeout_seconds):
                return False, "SECRET_PATH_AND_TOKEN"

        result = ReceiptVerifier(adapter=_Adapter(), attacker=UntrustedAttacker(), browser=_Browser(), receipt_key=b"k" * 32).verify(
            _candidate(), _manifest()
        )
        feedback = receipt_agent_feedback("001-receipt-xss", result)
        self.assertEqual(feedback["reason"], "VERIFICATION_REJECTED")
        self.assertNotIn("SECRET", str(feedback))
        self.assertTrue(feedback["reason_description"])
        fallback = receipt_failure_feedback("001-receipt-xss", "INDETERMINATE", "SECRET")
        self.assertEqual(fallback["reason"], "VERIFICATION_INFRASTRUCTURE_ERROR")
        self.assertNotIn("SECRET", str(fallback))


def _callback_route(**overrides: object) -> dict:
    route: dict = {
        "method": "GET",
        "path": "/control/filtering/status",
        "status": 200,
        "content_type": "application/json",
        "body": "{\"url\":\"javascript:window.__receipt_accept('{{receipt_token}}')\"}",
    }
    route.update(overrides)
    return route


def _candidate_with_callback(**overrides: object) -> ReceiptCandidate:
    raw = _candidate().as_mapping()
    raw["callback"] = {"routes": [_callback_route(**overrides)]}
    return ReceiptCandidate.from_mapping(raw, base_url="http://127.0.0.1:9/")


class CallbackFixtureTests(unittest.TestCase):
    def test_routes_change_the_hash_and_round_trip(self) -> None:
        from app.receipt import commit_receipt_candidate, load_receipt_candidate

        plain = _candidate()
        routed = _candidate_with_callback()
        self.assertNotEqual(plain.source_hash, routed.source_hash)
        self.assertNotIn("callback", plain.as_mapping())
        self.assertEqual(routed.callback_routes[0].path, "/control/filtering/status")
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            committed = commit_receipt_candidate(workspace, "http://127.0.0.1:9/", routed.as_mapping())
            loaded = load_receipt_candidate(workspace, committed.poc_id, base_url="http://127.0.0.1:9/")
        self.assertEqual(loaded.source_hash, routed.source_hash)
        self.assertEqual(loaded.callback_routes[0].body, routed.callback_routes[0].body)

    def test_invalid_routes_are_rejected(self) -> None:
        cases = {
            "method": _callback_route(method="TRACE"),
            "path": _callback_route(path="/%2e%2e/secret"),
            "query": _callback_route(path="/status?x=1"),
            "status": _callback_route(status=199),
            "type": _callback_route(content_type="text/csv"),
            "placeholder": _callback_route(body="{{password}}"),
            "body": _callback_route(body="x" * 8193),
        }
        for name, route in cases.items():
            with self.subTest(name=name):
                raw = _candidate().as_mapping()
                raw["callback"] = {"routes": [route]}
                with self.assertRaises(ReceiptError):
                    ReceiptCandidate.from_mapping(raw, base_url="http://127.0.0.1:9/")
        raw = _candidate().as_mapping()
        raw["callback"] = {"routes": [_callback_route(path=f"/item-{index}") for index in range(9)]}
        with self.assertRaises(ReceiptError):
            ReceiptCandidate.from_mapping(raw, base_url="http://127.0.0.1:9/")

    def test_callback_container_stays_up_until_stop_and_blocking_mode_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            poclib_file = Path(directory) / "poclib.py"
            poclib_file.write_text("CALLBACK_ORIGIN = 'http://attacker:8090'\n", encoding="utf-8")
            (Path(directory) / "callback_supervisor.py").write_text("print('supervisor')\n", encoding="utf-8")
            manifest = _manifest(extension_path_budget=0)
            captured: list[list[str]] = []

            def fake_run(command, **kwargs):
                del kwargs
                captured.append(list(command))
                if command[1] == "exec":
                    return Mock(returncode=0, stdout="0\n", stderr="")
                return Mock(returncode=0, stdout="container\n", stderr="")

            with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
                executor = DockerAttackerExecutor(image="test-image", poclib_file=poclib_file)
                with patch("app.receipt.is_pinned_attacker_image", return_value=True), patch("app.receipt.subprocess.run", side_effect=fake_run):
                    try:
                        ok, reason = executor.run(_candidate_with_callback(), target, "challenge", 1)
                        command = captured[0]
                        mount = next(part for part in command if part.endswith(":/receipt:ro"))
                        saved = json.loads(Path(mount.removesuffix(":/receipt:ro"), "callback-routes.json").read_text(encoding="utf-8"))
                    finally:
                        executor.stop()
            callback_commands = list(captured)
            captured.clear()

            def blocking_run(command, **kwargs):
                del kwargs
                captured.append(list(command))
                return Mock(returncode=0, stdout="", stderr="")

            with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
                executor = DockerAttackerExecutor(image="test-image", poclib_file=poclib_file)
                with patch("app.receipt.is_pinned_attacker_image", return_value=True), patch("app.receipt.subprocess.run", side_effect=blocking_run):
                    blocking_ok, blocking_reason = executor.run(_candidate(), target, "challenge", 1)
                    blocking_command = captured[0]
        self.assertTrue(ok)
        self.assertEqual(reason, "ATTACKER_COMPLETED")
        self.assertIn("-d", command)
        self.assertEqual(command[command.index("--network-alias") + 1], "attacker")
        self.assertTrue(command[command.index("--name") + 1].startswith("receipt-cb-"))
        self.assertIn("RECEIPT_CALLBACK_ORIGIN=http://attacker:8090", command)
        self.assertEqual(command[-2:], ["python", "/receipt/callback_supervisor.py"])
        self.assertNotIn("-p", command)
        self.assertNotIn("--publish", command)
        self.assertIn("--read-only", command)
        self.assertIn("{{receipt_token}}", saved["routes"][0]["body"])
        self.assertNotIn("challenge", json.dumps(saved))
        self.assertEqual(callback_commands[-2][1], "stop")
        self.assertNotIn("stop", callback_commands[0])
        self.assertTrue(blocking_ok)
        self.assertEqual(blocking_reason, "ATTACKER_COMPLETED")
        self.assertNotIn("-d", blocking_command)
        self.assertNotIn("RECEIPT_CALLBACK_ORIGIN=http://attacker:8090", blocking_command)
        self.assertEqual(blocking_command[-1], "/receipt/poc.py")

    def test_callback_failures_do_not_return_script_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            poclib_file = Path(directory) / "poclib.py"
            poclib_file.write_text("pass\n", encoding="utf-8")
            (Path(directory) / "callback_supervisor.py").write_text("pass\n", encoding="utf-8")
            manifest = _manifest(extension_path_budget=0)

            def fake_run(command, **kwargs):
                del kwargs
                if command[1] == "exec":
                    return Mock(returncode=0, stdout="1\nRECEIPT_POC_FAILURE:ValueError\nsecret-token\n", stderr="")
                if command[1] == "inspect":
                    return Mock(returncode=0, stdout="false\n", stderr="")
                return Mock(returncode=0, stdout="container\n", stderr="")

            with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
                executor = DockerAttackerExecutor(image="test-image", poclib_file=poclib_file)
                with patch("app.receipt.is_pinned_attacker_image", return_value=True), patch("app.receipt.subprocess.run", side_effect=fake_run):
                    try:
                        ok, reason = executor.run(_candidate_with_callback(), target, "challenge", 1)
                    finally:
                        executor.stop()
        self.assertFalse(ok)
        self.assertEqual(reason, "ATTACKER_VALUEERROR")
        self.assertNotIn("secret-token", reason)

    def test_missing_listener_and_timeout_are_infrastructure(self) -> None:
        from app.receipt_execution import receipt_agent_feedback

        manifest = _manifest(extension_path_budget=0)
        with tempfile.TemporaryDirectory() as directory:
            poclib_file = Path(directory) / "poclib.py"
            poclib_file.write_text("pass\n", encoding="utf-8")
            with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
                executor = DockerAttackerExecutor(image="test-image", poclib_file=poclib_file)
                with patch("app.receipt.is_pinned_attacker_image", return_value=True), patch("app.receipt.subprocess.run", side_effect=AssertionError("docker")):
                    ok, reason = executor.run(_candidate_with_callback(), target, "challenge", 1)
        self.assertFalse(ok)
        self.assertEqual(reason, "CALLBACK_UNAVAILABLE")

        def still_running(command, **kwargs):
            del kwargs
            if command[1] == "exec":
                return Mock(returncode=1, stdout="", stderr="")
            if command[1] == "inspect":
                return Mock(returncode=0, stdout="true\n", stderr="")
            return Mock(returncode=0, stdout="container\n", stderr="")

        with tempfile.TemporaryDirectory() as ready:
            poclib_file = Path(ready) / "poclib.py"
            poclib_file.write_text("pass\n", encoding="utf-8")
            (Path(ready) / "callback_supervisor.py").write_text("pass\n", encoding="utf-8")
            with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
                executor = DockerAttackerExecutor(image="test-image", poclib_file=poclib_file)
                with patch("app.receipt.is_pinned_attacker_image", return_value=True), patch("app.receipt.subprocess.run", side_effect=still_running), patch("app.receipt.time.monotonic", side_effect=[0, 5]):
                    try:
                        ok, reason = executor.run(_candidate_with_callback(), target, "challenge", 1)
                    finally:
                        executor.stop()
        self.assertFalse(ok)
        self.assertEqual(reason, "ATTACKER_TIMEOUT")

        class Unavailable:
            def run(self, candidate, target, token, timeout_seconds):
                del candidate, target, token, timeout_seconds
                return False, "CALLBACK_UNAVAILABLE"

            def stop(self) -> None:
                return None

        result = ReceiptVerifier(adapter=_Adapter(), attacker=Unavailable(), browser=_Browser(), receipt_key=b"k" * 32).verify(
            _candidate(), manifest
        )
        feedback = receipt_agent_feedback("001-receipt-xss", result)
        self.assertEqual(result.verdict, ReceiptVerdict.INDETERMINATE)
        self.assertEqual(feedback["reason"], "CALLBACK_UNAVAILABLE")
        self.assertIn("callback listener", feedback["reason_description"])

    def test_browser_blocks_the_callback_origin(self) -> None:
        from app.receipt import _restrict_browser_requests
        from runtime.poclib import CALLBACK_ORIGIN

        calls: list[tuple[str, str]] = []

        class Route:
            def __init__(self, url: str) -> None:
                self.request = types.SimpleNamespace(url=url)

            def continue_(self) -> None:
                calls.append(("continue", self.request.url))

            def abort(self) -> None:
                calls.append(("abort", self.request.url))

        class Context:
            def route(self, pattern: str, handler) -> None:
                del pattern
                self.handler = handler

            def route_web_socket(self, *args) -> None:
                del args

        context = Context()
        _restrict_browser_requests(context, ("http://target.test",))
        context.handler(Route(CALLBACK_ORIGIN + "/control/filtering/status"))
        context.handler(Route("http://target.test/"))
        self.assertEqual(calls, [("abort", CALLBACK_ORIGIN + "/control/filtering/status"), ("continue", "http://target.test/")])

    def test_supervisor_serves_the_declared_body_without_echoing_the_request(self) -> None:
        import threading
        import urllib.error
        import urllib.request
        from http.server import ThreadingHTTPServer

        from runtime.callback_supervisor import make_handler

        routes = {
            ("GET", "/control/filtering/status"): {
                "status": 200,
                "content_type": "application/json",
                "body": "{\"url\":\"javascript:window.__receipt_accept('{{receipt_token}}')\"}",
            },
            ("POST", "/hook"): {
                "status": 201,
                "content_type": "text/plain",
                "body": "stored {{receipt_token}}",
            },
        }
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(routes, "round-token"))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/control/filtering/status?leak=supersecret",
                headers={"X-Leak": "supersecret"},
                method="GET",
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                body = response.read()
                content_type = response.headers["Content-Type"]
            self.assertEqual(content_type.split(";", 1)[0], "application/json")
            self.assertIn(b"round-token", body)
            self.assertNotIn(b"supersecret", body)

            posted = urllib.request.Request(
                f"http://127.0.0.1:{port}/hook?leak=supersecret",
                data=b"supersecret",
                headers={"X-Leak": "supersecret"},
                method="POST",
            )
            with urllib.request.urlopen(posted, timeout=2) as response:
                body = response.read()
                self.assertEqual(response.status, 201)
            self.assertEqual(body, b"stored round-token")
            self.assertNotIn(b"supersecret", body)

            missing = urllib.request.Request(
                f"http://127.0.0.1:{port}/missing?leak=supersecret",
                data=b"supersecret",
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(missing, timeout=2)
            payload = raised.exception.read()
            self.assertEqual(raised.exception.code, 404)
            self.assertEqual(payload, b"")
            self.assertNotIn(b"supersecret", payload)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_listener_outlives_the_script_and_stops_after_the_browser(self) -> None:
        events: list[str] = []

        class Attacker:
            def run(self, candidate, target, token, timeout_seconds):
                del candidate, target, token, timeout_seconds
                events.append("run")
                return True, "ATTACKER_COMPLETED"

            def stop(self) -> None:
                events.append("stop")

        class Browser:
            def run(self, candidate, target, path, token, timeout_ms):
                del candidate, target, path, token, timeout_ms
                events.append("browser")
                return BrowserEvidence(True, "BROWSER_BOUND_RECEIPT", "http://target.test", ())

        result = ReceiptVerifier(adapter=_Adapter(), attacker=Attacker(), browser=Browser(), receipt_key=b"k" * 32).verify(
            _candidate_with_callback(), _manifest(extension_path_budget=1)
        )
        self.assertEqual(result.verdict, ReceiptVerdict.ACCEPTED)
        self.assertEqual(events, ["run", "browser", "stop", "run", "browser", "stop"])

        failed: list[str] = []

        class FailedAttacker:
            def run(self, candidate, target, token, timeout_seconds):
                del candidate, target, token, timeout_seconds
                failed.append("run")
                return False, "ATTACKER_FAILED"

            def stop(self) -> None:
                failed.append("stop")

        class UnexpectedBrowser:
            def run(self, *args):
                failed.append("browser")
                raise AssertionError("脚本失败后不应打开受害者浏览器")

        rejected = ReceiptVerifier(adapter=_Adapter(), attacker=FailedAttacker(), browser=UnexpectedBrowser(), receipt_key=b"k" * 32).verify(
            _candidate_with_callback(), _manifest(extension_path_budget=0)
        )
        self.assertEqual(rejected.paths[0].verdict, ReceiptVerdict.REJECTED)
        self.assertEqual(failed, ["run", "stop", "run", "stop"])

    def test_routes_without_a_script_still_start_the_attacker_container(self) -> None:
        raw = _candidate().as_mapping()
        raw["attacker_script"] = ""
        raw["callback"] = {"routes": [_callback_route()]}
        candidate = ReceiptCandidate.from_mapping(raw, base_url="http://127.0.0.1:9/")
        started: list[str] = []

        class Attacker:
            def run(self, candidate, target, token, timeout_seconds):
                del candidate, target, token, timeout_seconds
                started.append("run")
                return True, "ATTACKER_COMPLETED"

            def stop(self) -> None:
                started.append("stop")

        result = ReceiptVerifier(adapter=_Adapter(), attacker=Attacker(), browser=_Browser(), receipt_key=b"k" * 32).verify(
            candidate, _manifest(extension_path_budget=0)
        )
        self.assertEqual(result.verdict, ReceiptVerdict.ACCEPTED)
        self.assertEqual(started, ["run", "stop", "run", "stop"])

    def test_callback_origin_accepts_only_the_verifier_value(self) -> None:
        from contextlib import redirect_stdout

        from runtime.poclib import CALLBACK_ORIGIN, Poc

        seen: list[str] = []

        def run(ctx) -> None:
            seen.append(ctx.callback_origin)
            ctx.expect(True, "ok")

        with patch.dict(os.environ, {"RECEIPT_CALLBACK_ORIGIN": CALLBACK_ORIGIN}):
            with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as raised:
                Poc("001-receipt-xss", "xss001receipt", "http://127.0.0.1:9/").main(run, argv=[])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(seen, [CALLBACK_ORIGIN])

        def rejected(ctx) -> None:
            seen.append(ctx.callback_origin)
            ctx.expect(True, "ok")

        with patch.dict(os.environ, {"RECEIPT_CALLBACK_ORIGIN": "http://evil.test"}):
            with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                Poc("001-receipt-xss", "xss001receipt", "http://127.0.0.1:9/").main(rejected, argv=[])
        self.assertEqual(seen, [CALLBACK_ORIGIN, ""])

    def test_submit_poc_stores_callback_routes(self) -> None:
        import asyncio

        from app.poctool import build_submit_poc
        from app.receipt import load_receipt_candidate

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            tool = build_submit_poc(workspace, "http://127.0.0.1:9/", receipt_enabled=True)
            saved = asyncio.run(tool.handler({
                "poc_id": "001-receipt-xss",
                "marker": "xss001receipt",
                "source": _source(),
                "victim_json": json.dumps({"url": "/view", "actions": []}),
                "attacker_login_json": "",
                "claim_json": "",
                "callback_json": json.dumps({"routes": [_callback_route()]}),
            }))
            self.assertNotIn("is_error", saved)
            loaded = load_receipt_candidate(workspace, "001-receipt-xss", base_url="http://127.0.0.1:9/")
            self.assertEqual(loaded.callback_routes[0].method, "GET")
            rejected = asyncio.run(tool.handler({
                "poc_id": "001-receipt-xss",
                "marker": "xss001receipt",
                "source": _source(),
                "victim_json": json.dumps({"url": "/view", "actions": []}),
                "callback_json": json.dumps({"routes": [_callback_route(method="TRACE")]}),
            }))
        self.assertTrue(rejected["is_error"])
        self.assertIn("callback", rejected["content"][0]["text"])


class ReceiptRepairTests(unittest.TestCase):
    def test_candidate_keeps_the_task_base_url_out_of_the_submitted_mapping(self) -> None:
        candidate = _candidate()
        self.assertEqual(candidate.validated_base_url, "http://127.0.0.1:9/")
        self.assertNotIn("validated_base_url", candidate.as_mapping())
        rebuilt = ReceiptCandidate.from_mapping(candidate.as_mapping(), base_url=candidate.validated_base_url)
        self.assertEqual(rebuilt.source_hash, candidate.source_hash)
        with self.assertRaises(ReceiptError):
            ReceiptCandidate.from_mapping(candidate.as_mapping(), base_url="http://127.0.0.1:8904/")

    def test_worker_rejects_the_ephemeral_port_and_navigates_with_it(self) -> None:
        from app.browser_worker import _victim
        from app.receipt import _evidence_from_worker

        invalid = _victim(self._job("http://127.0.0.1:8904/"))
        self.assertEqual(invalid, {"failed": True, "error": "CANDIDATE_INVALID"})
        self.assertEqual(_evidence_from_worker(invalid, run_id="run").reason, "RECEIPT_BUNDLE_INVALID")

        seen: dict[str, str] = {}

        class Driver:
            def run(self, candidate, target, path, token, timeout_ms, **kwargs):
                del path, token, timeout_ms, kwargs
                seen["validated"] = candidate.validated_base_url
                seen["base"] = target.base_url
                return BrowserEvidence(True, "BROWSER_BOUND_RECEIPT", target.base_url)

        with patch("app.receipt.PlaywrightVictimDriver", Driver):
            accepted = _victim(self._job("http://127.0.0.1:9/"))
        self.assertEqual(seen, {"validated": "http://127.0.0.1:9/", "base": "http://127.0.0.1:8904/"})
        self.assertEqual(accepted["reason"], "BROWSER_BOUND_RECEIPT")

    def test_worker_failure_records_the_category_without_the_exception_text(self) -> None:
        from app import receipt_diagnostics as diagnostics
        from app.receipt import _evidence_from_worker

        secret = "password-in-worker-crash"
        with tempfile.TemporaryDirectory() as directory:
            tokens = diagnostics.begin(Path(directory))
            try:
                evidence = _evidence_from_worker(
                    {"failed": True, "error": "RuntimeError", "step": "browser_launch", "error_message": secret},
                    run_id="run",
                )
            finally:
                diagnostics.end(tokens)
            text = (Path(directory) / "receipt" / "diagnostics.jsonl").read_text(encoding="utf-8")
        self.assertEqual(evidence.reason, "BROWSER_UNAVAILABLE")
        self.assertIn("RuntimeError", text)
        self.assertIn("browser_launch", text)
        self.assertNotIn(secret, text)

    def test_login_selector_timeout_rejects_the_candidate(self) -> None:
        from app.receipt import _browser_failure_rejects_candidate, _evidence_from_worker

        evidence = _evidence_from_worker({"timeout": True, "step": "victim_login.assert_visible", "index": 4})
        self.assertEqual(evidence.click_blocker, "not_found")
        self.assertEqual(evidence.error_step, "victim_login.assert_visible")
        self.assertEqual(evidence.error_step_index, 4)
        self.assertIsNone(evidence.error_action_index)
        self.assertTrue(_browser_failure_rejects_candidate(evidence))
        launch = _evidence_from_worker({"timeout": True, "step": "browser_launch"})
        self.assertEqual(launch.click_blocker, "")
        self.assertFalse(_browser_failure_rejects_candidate(launch))

        class FailedBrowser:
            def run(self, *args, **kwargs):
                del args, kwargs
                return evidence

        result = ReceiptVerifier(
            adapter=_Adapter(), attacker=_Attacker(), browser=FailedBrowser(), receipt_key=b"k" * 32,
        ).verify(_candidate(), _manifest(extension_path_budget=0))
        self.assertEqual(result.verdict, ReceiptVerdict.REJECTED)
        self.assertEqual(result.paths[0].evidence["browser_error"]["blocker"], "not_found")
        self.assertEqual(result.paths[0].evidence["browser_error"]["step"], "victim_login.assert_visible")

    def test_bundle_revalidation_stays_indeterminate(self) -> None:
        class BundleBrowser:
            def run(self, *args):
                del args
                return BrowserEvidence(False, "RECEIPT_BUNDLE_INVALID")

        result = ReceiptVerifier(
            adapter=_Adapter(), attacker=_Attacker(), browser=BundleBrowser(), receipt_key=b"k" * 32,
        ).verify(_candidate(), _manifest(extension_path_budget=0))
        self.assertEqual(result.verdict, ReceiptVerdict.INDETERMINATE)
        self.assertEqual(result.paths[0].reason, "RECEIPT_BUNDLE_INVALID")

    def _job(self, validation_base: str) -> dict:
        return {
            "candidate": _candidate().as_mapping(),
            "base_url": "http://127.0.0.1:8904/",
            "validation_base_url": validation_base,
            "path": {
                "id": "author-to-admin",
                "attacker_principal": "author-1",
                "victim_principal": "admin-1",
                "primary": True,
            },
            "allowed_origins": ["http://127.0.0.1:8904"],
            "victim_account": {},
            "run_id": "run",
            "token": "token",
            "timeout_ms": 1000,
        }

    def test_popup_receipt_accepts_only_an_allowed_main_frame(self) -> None:
        secret = "receipt-token"
        calls: dict[str, object] = {}

        class ChildFrame:
            pass

        class Page:
            def __init__(self, url: str, origin: str | None = None) -> None:
                self.url = url
                self.main_frame = self
                self.origin = origin

            def evaluate(self, script: str):
                del script
                if self.origin is None:
                    raise RuntimeError("origin unavailable")
                return self.origin

            def set_default_timeout(self, timeout: int) -> None:
                del timeout
                calls["callback"]({"page": self, "frame": self}, secret)

            def goto(self, *args, **kwargs):
                del args, kwargs
                return types.SimpleNamespace(status=200)

            def locator(self, selector: str):
                del selector
                return self

            def click(self, **kwargs: object) -> None:
                popup = Page("javascript:window.__receipt_accept('token')", "http://target.test")
                foreign = Page("http://evil.test/open")
                calls["callback"]({"page": self, "frame": ChildFrame()}, secret)
                calls["callback"]({"page": foreign, "frame": foreign}, secret)
                calls["callback"]({"page": popup, "frame": popup}, secret)

            def wait_for_timeout(self, timeout: int) -> None:
                del timeout

        class Context:
            def route(self, *args) -> None:
                del args

            def route_web_socket(self, *args) -> None:
                del args

            def expose_binding(self, name, callback) -> None:
                del name
                calls["callback"] = callback

            def add_init_script(self, script: str) -> None:
                calls["script"] = script

            def new_page(self) -> Page:
                return Page("http://target.test/view")

        class Browser:
            def new_context(self, **kwargs):
                del kwargs
                return Context()

            def close(self) -> None:
                return None

        class Chromium:
            executable_path = "chromium"

            def launch(self, **kwargs):
                del kwargs
                return Browser()

        class Playwright:
            chromium = Chromium()

            def __enter__(self):
                return self

            def __exit__(self, *args) -> None:
                return None

        api = types.ModuleType("playwright.sync_api")
        api.sync_playwright = Playwright
        api.Error = Exception
        api.TimeoutError = Exception
        package = types.ModuleType("playwright")
        package.sync_api = api
        manifest = _manifest(extension_path_budget=0)
        with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
            with patch.dict(sys.modules, {"playwright": package, "playwright.sync_api": api}):
                evidence = PlaywrightVictimDriver().run(_candidate(), target, manifest.threat_paths[0], secret, 1000)
        self.assertTrue(evidence.accepted)
        self.assertEqual(evidence.document_origin, "http://target.test")
        self.assertIn("__receipt_accept", str(calls["script"]))
        self.assertNotIn(secret, repr(evidence))

    def test_receipt_before_recording_is_ignored(self) -> None:
        secret = "receipt-token"
        holder: dict[str, object] = {}

        class Page:
            url = "http://target.test/view"
            main_frame = None

            def __init__(self) -> None:
                self.main_frame = self

            def set_default_timeout(self, timeout: int) -> None:
                del timeout
                holder["callback"]({"page": self, "frame": self}, secret)

            def goto(self, *args, **kwargs):
                del args, kwargs
                return types.SimpleNamespace(status=200)

            def locator(self, selector: str):
                del selector
                return self

            def click(self, **kwargs: object) -> None:
                return None

            def wait_for_timeout(self, timeout: int) -> None:
                del timeout

        class Context:
            def route(self, *args) -> None:
                del args

            def route_web_socket(self, *args) -> None:
                del args

            def expose_binding(self, name, callback) -> None:
                del name
                holder["callback"] = callback

            def add_init_script(self, script: str) -> None:
                del script

            def new_page(self) -> Page:
                return Page()

        class Browser:
            def new_context(self, **kwargs):
                del kwargs
                return Context()

            def close(self) -> None:
                return None

        class Chromium:
            executable_path = "chromium"

            def launch(self, **kwargs):
                del kwargs
                return Browser()

        class Playwright:
            chromium = Chromium()

            def __enter__(self):
                return self

            def __exit__(self, *args) -> None:
                return None

        api = types.ModuleType("playwright.sync_api")
        api.sync_playwright = Playwright
        api.Error = Exception
        api.TimeoutError = Exception
        package = types.ModuleType("playwright")
        package.sync_api = api
        manifest = _manifest(extension_path_budget=0)
        with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
            with patch.dict(sys.modules, {"playwright": package, "playwright.sync_api": api}):
                evidence = PlaywrightVictimDriver().run(_candidate(), target, manifest.threat_paths[0], secret, 200)
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.reason, "NO_BROWSER_BOUND_RECEIPT")

    def test_ambiguous_selector_rejects_without_returning_the_selector(self) -> None:
        from app.receipt_execution import receipt_agent_feedback

        secret = "#secret-marker-button"

        class FakeError(Exception):
            pass

        class FakeTimeout(FakeError):
            pass

        class Page:
            url = "http://target.test/view"

            def __init__(self) -> None:
                self.main_frame = self

            def set_default_timeout(self, timeout: int) -> None:
                del timeout

            def goto(self, *args, **kwargs):
                del args, kwargs
                return types.SimpleNamespace(status=200)

            def locator(self, selector: str):
                del selector

                def click(**kwargs: object) -> None:
                    raise FakeError(f'strict mode violation: locator("{secret}") resolved to 2 elements')

                return types.SimpleNamespace(click=click)

            def wait_for_timeout(self, timeout: int) -> None:
                del timeout

        class Context:
            def route(self, *args) -> None:
                del args

            def route_web_socket(self, *args) -> None:
                del args

            def expose_binding(self, *args) -> None:
                del args

            def add_init_script(self, *args) -> None:
                del args

            def new_page(self) -> Page:
                return Page()

        class Browser:
            def new_context(self, **kwargs):
                del kwargs
                return Context()

            def close(self) -> None:
                return None

        class Chromium:
            executable_path = "chromium"

            def launch(self, **kwargs):
                del kwargs
                return Browser()

        class Playwright:
            chromium = Chromium()

            def __enter__(self):
                return self

            def __exit__(self, *args) -> None:
                return None

        api = types.ModuleType("playwright.sync_api")
        api.sync_playwright = Playwright
        api.Error = FakeError
        api.TimeoutError = FakeTimeout
        package = types.ModuleType("playwright")
        package.sync_api = api
        manifest = _manifest(extension_path_budget=0)
        with _Adapter().open_run(manifest, manifest.threat_paths[0], "run") as target:
            with patch.dict(sys.modules, {"playwright": package, "playwright.sync_api": api}):
                evidence = PlaywrightVictimDriver().run(_candidate(), target, manifest.threat_paths[0], "receipt-token", 1000)
        self.assertEqual(evidence.reason, "BROWSER_ERROR")
        self.assertEqual(evidence.error_type, "playwright_error")
        self.assertEqual(evidence.error_stage, "victim_action")
        self.assertEqual(evidence.click_blocker, "ambiguous")
        self.assertNotIn(secret, repr(evidence))

        class AmbiguousBrowser:
            def run(self, *args):
                del args
                return evidence

        result = ReceiptVerifier(
            adapter=_Adapter(), attacker=_Attacker(), browser=AmbiguousBrowser(), receipt_key=b"k" * 32,
        ).verify(_candidate(), manifest)
        self.assertEqual(result.verdict, ReceiptVerdict.REJECTED)
        feedback = receipt_agent_feedback("001-receipt-xss", result)
        self.assertEqual(feedback["verdict"], "REJECTED")
        self.assertIn("index: 0", feedback["reason_description"])
        self.assertNotIn(secret, str(feedback))

    def test_live_popup_receipt_for_same_origin_and_javascript_urls(self) -> None:
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        token = "live-receipt-token"
        popup = "<!doctype html><script>window.__receipt_accept('%s')</script>" % token
        page = """<!doctype html>
<button id="http">http</button>
<button id="js">js</button>
<script>
document.getElementById('http').onclick = () => window.open('/popup', '_blank', 'noopener,noreferrer');
document.getElementById('js').onclick = () => window.open('javascript:void(window.__receipt_accept("%s"))', '_blank', 'noopener,noreferrer');
</script>""" % token

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                body = popup if self.path.startswith("/popup") else page
                data = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args) -> None:
                del format, args

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("playwright is not installed")
        del sync_playwright
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{port}"
            http_result = self._live_receipt(origin, "#http", token)
            script_result = self._live_receipt(origin, "#js", token)
        finally:
            server.shutdown()
            thread.join(timeout=5)
        if http_result.reason == "BROWSER_UNAVAILABLE":
            self.skipTest("chromium is not available")
        self.assertTrue(http_result.accepted, http_result.reason)
        self.assertEqual(http_result.document_origin, origin)
        # Chromium does not run the context init script for a javascript: popup opened with noopener.
        self.assertFalse(script_result.accepted)
        self.assertEqual(script_result.reason, "NO_BROWSER_BOUND_RECEIPT")

    def _live_receipt(self, origin: str, selector: str, token: str) -> BrowserEvidence:
        from app.receipt import ThreatPath, VictimAction

        candidate = replace(_candidate(), victim_url="/", victim_actions=(VictimAction("click", selector),))
        path = ThreatPath("author-to-admin", "author-1", "admin-1", False)
        target = TargetRun(
            run_id="live",
            base_url=origin + "/",
            attacker_base_url=origin + "/",
            allowed_origins=(origin,),
            attacker_network="",
            attacker_cookie_header="",
            login_victim=lambda *args: True,
            snapshot_id="live",
        )
        with patch("app.receipt.browser_runs_inprocess", return_value=True):
            return PlaywrightVictimDriver().run(candidate, target, path, token, 2000)

