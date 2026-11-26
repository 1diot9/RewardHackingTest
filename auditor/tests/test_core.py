from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from uuid import uuid4

from pydantic import ValidationError
from fastapi.testclient import TestClient

from app.config import compaction_env
from app.gateway import GatewayHTTPError, messages_url, quota_probe
from app.pricing import Ledger, Prices, Tokens, UsageAccumulator, price_of, summarize_model_usage
from app.quota import RunClock, is_quota_signal


class QuotaTests(unittest.TestCase):
    def test_pause_events_record_cumulative_active_time(self) -> None:
        from app.hub import Hub
        from app.runner import _enter_quota_pause, _mark_paused
        from app.store import Store

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = Store(root / "state.json")
            store.add_task({"id": "task", "workspace": str(root), "status": "running", "round": 1,
                            "next_seq": 1, "started_at": "2020-01-01T00:00:00+00:00",
                            "paused_at": "2020-01-01T00:02:00+00:00", "paused_seconds": 20})
            _mark_paused(store, Hub(), "task", "manual")
            events = [json.loads(line) for line in (root / "logs" / "round-001.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(events[-1]["elapsed_seconds"], 100)
            self.assertIn("累计有效时长 00:01:40", events[-1]["text"])

            store.update_task("task", status="running", paused_at=None)
            mark = {"now": 100.0}
            clock = RunClock(600, now=lambda: mark["now"], elapsed=150)
            _enter_quota_pause(clock, store, Hub(), "task")
            _enter_quota_pause(clock, store, Hub(), "task")
            events = [json.loads(line) for line in (root / "logs" / "round-001.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(events), 2)
            self.assertEqual(events[-1]["elapsed_seconds"], 150)
            self.assertEqual(events[-1]["pause_reason"], "quota")

    def test_clock_excludes_paused_time(self) -> None:
        mark = {"now": 0.0}
        clock = RunClock(100, now=lambda: mark["now"])
        mark["now"] = 40
        self.assertEqual(clock.remaining(), 60)
        self.assertTrue(clock.pause())
        self.assertFalse(clock.pause())
        mark["now"] = 90
        self.assertEqual(clock.remaining(), 60)
        self.assertFalse(clock.expired())
        clock.resume()
        mark["now"] = 150
        self.assertEqual(clock.remaining(), 0)
        self.assertTrue(clock.expired())

    def test_clock_restores_elapsed_and_previous_pauses(self) -> None:
        mark = {"now": 100.0}
        clock = RunClock(120, now=lambda: mark["now"], elapsed=50, paused_total=20)
        self.assertEqual(clock.remaining(), 70)
        mark["now"] = 120
        self.assertEqual(clock.remaining(), 50)
        clock.pause()
        mark["now"] = 150
        self.assertEqual(clock.remaining(), 50)
        clock.resume()
        self.assertEqual(clock.paused_total, 50)

    def test_quota_signal_is_http_429_only(self) -> None:
        self.assertTrue(is_quota_signal(429))
        self.assertTrue(is_quota_signal("Error code: 429"))
        self.assertFalse(is_quota_signal("port 14290", 500, None))

    def test_messages_probe_waits_on_429_and_accepts_other_client_errors(self) -> None:
        self.assertEqual(messages_url("https://gw.example/v1"), "https://gw.example/v1/messages")

        def exhausted(url, key, payload, timeout):
            del url, key, timeout
            self.assertEqual(payload["max_tokens"], 1)
            raise GatewayHTTPError(429, "insufficient quota")

        blocked = quota_probe("https://gw.example", "key", "demo", transport=exhausted)
        self.assertFalse(blocked["ok"])
        self.assertEqual(blocked["status"], 429)

        def reachable(url, key, payload, timeout):
            del url, key, payload, timeout
            raise GatewayHTTPError(400, "bad request")

        self.assertTrue(quota_probe("", "key", "demo", transport=reachable)["ok"])


class CompactionTests(unittest.TestCase):
    def test_context_window_and_compact_percent(self) -> None:
        env = compaction_env()
        self.assertEqual(env["CLAUDE_CODE_MAX_CONTEXT_TOKENS"], "256000")
        self.assertEqual(env["CLAUDE_CODE_AUTO_COMPACT_WINDOW"], "256000")
        self.assertEqual(env["CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"], "75")
        self.assertEqual(env["DISABLE_AUTO_COMPACT"], "0")
        self.assertEqual(env["DISABLE_COMPACT"], "0")

    def test_task_specific_context_window_and_compact_percent(self) -> None:
        env = compaction_env(context_window_tokens=128_000, compact_percent=60)
        self.assertEqual(env["CLAUDE_CODE_MAX_CONTEXT_TOKENS"], "128000")
        self.assertEqual(env["CLAUDE_CODE_AUTO_COMPACT_WINDOW"], "128000")
        self.assertEqual(env["CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"], "60")

    def test_task_input_validates_context_settings(self) -> None:
        from app.main import TaskIn

        common = {
            "instruction": "test",
            "base_url": "http://127.0.0.1:9/",
            "provider_id": "provider",
            "model": "model",
            "budget": 1,
            "duration_minutes": 1,
        }
        accepted = TaskIn(**common, context_window_tokens=100_000, compact_percent=100)
        self.assertEqual(accepted.context_window_tokens, 100_000)
        self.assertEqual(accepted.compact_percent, 100)
        self.assertEqual(accepted.completion_mode, "agent")

        for invalid in (
            {"context_window_tokens": 99_999},
            {"compact_percent": 0},
            {"compact_percent": 101},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                TaskIn(**common, **invalid)

    def test_defaults_expose_context_settings(self) -> None:
        from app.main import defaults

        values = defaults()
        self.assertEqual(values["context_window_tokens"], 256_000)
        self.assertEqual(values["compact_percent"], 75)

    def test_runner_applies_task_settings_and_old_task_defaults(self) -> None:
        from app.runner import _build_options

        with tempfile.TemporaryDirectory() as raw:
            custom = _build_options(
                {
                    "model": "demo",
                    "base_url": "http://127.0.0.1:9/",
                    "context_window_tokens": 128_000,
                    "compact_percent": 60,
                },
                Path(raw),
                "",
                "",
                lambda value: None,
            )
            legacy = _build_options(
                {"model": "demo", "base_url": "http://127.0.0.1:9/"},
                Path(raw),
                "",
                "",
                lambda value: None,
            )

        self.assertEqual(custom.env["CLAUDE_CODE_MAX_CONTEXT_TOKENS"], "128000")
        self.assertEqual(custom.env["CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"], "60")
        self.assertTrue(custom.include_partial_messages)
        self.assertEqual(legacy.env["CLAUDE_CODE_MAX_CONTEXT_TOKENS"], "256000")
        self.assertEqual(legacy.env["CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"], "75")

    def test_runner_exposes_sync_receipt_tool_only_for_a_bound_manifest(self) -> None:
        from app.runner import _build_options

        async def verifier(poc_id: str) -> dict[str, str]:
            return {"poc_id": poc_id, "verdict": "ACCEPTED", "reason": "BROWSER_BOUND_RECEIPT"}

        with tempfile.TemporaryDirectory() as raw:
            unbound = _build_options(
                {"model": "demo", "base_url": "http://127.0.0.1:9/", "receipt_enabled": True},
                Path(raw),
                "",
                "",
                lambda value: None,
                receipt_verifier=verifier,
            )
            bound = _build_options(
                {
                    "model": "demo",
                    "base_url": "http://127.0.0.1:9/",
                    "receipt_enabled": True,
                    "receipt_manifest": "trusted-target.json",
                },
                Path(raw),
                "",
                "",
                lambda value: None,
                receipt_verifier=verifier,
            )
        self.assertNotIn("mcp__audit__start_receipt", unbound.allowed_tools)
        self.assertIn("mcp__audit__start_receipt", bound.allowed_tools)

    def test_disabled_receipt_hides_protocol_but_preserves_artifact_format(self) -> None:
        from app.prompts import render
        from app.runner import _build_options

        off = {"receipt_sections": "off", "receipt_protocol": ""}
        on = {"receipt_sections": "on", "receipt_protocol": "enabled"}
        names = ("artifact-format.md", "task-brief.md", "system.md", "run.md", "run-agent.md", "run-resume.md", "run-agent-resume.md")
        for name in names:
            with self.subTest(name=name):
                result = render(name, off)
                self.assertNotIn("receipt", result.lower())
                self.assertNotIn("start_receipt", result)
        disabled = render("artifact-format.md", off)
        enabled = render("artifact-format.md", on)
        for heading in ("## 标题", "## 攻击者角色", "## 受害者角色", "## 类型", "## 前提", "## 入口", "## 代码位置", "## 原因", "## 复现", "## 证据", "## PoC", "# PoC 脚本"):
            self.assertIn(heading, disabled)
            self.assertIn(heading, enabled)
        self.assertIn("start_receipt", enabled)
        with tempfile.TemporaryDirectory() as raw:
            options = _build_options({"model": "demo", "base_url": "http://127.0.0.1:9/"}, Path(raw), "", "", lambda value: None)
        self.assertNotIn("receipt", options.system_prompt.lower())
        self.assertNotIn("mcp__audit__start_receipt", options.allowed_tools)

    def test_runner_enables_web_tools_only_during_environment_setup(self) -> None:
        from app.runner import _build_options

        with tempfile.TemporaryDirectory() as raw:
            args = ({"model": "demo"}, Path(raw), "", "", lambda value: None)
            setup = _build_options(*args, environment_setup=True)
            audit = _build_options(*args)
        for tool in ("WebSearch", "WebFetch", "PowerShell"):
            self.assertIn(tool, setup.tools)
            self.assertIn(tool, setup.allowed_tools)
            self.assertNotIn(tool, setup.disallowed_tools)
        for tool in ("WebSearch", "WebFetch", "PowerShell"):
            self.assertNotIn(tool, audit.tools)
            self.assertIn(tool, audit.disallowed_tools)
        self.assertNotIn("Agent", setup.tools)
        self.assertNotIn("Agent", audit.tools)
        self.assertIn("可以联网搜索", setup.system_prompt)
        self.assertIn("最新提交", setup.system_prompt)
        self.assertIn("联网搜索已经关闭", audit.system_prompt)

    def test_pre_tool_hook_rejects_consecutive_identical_calls(self) -> None:
        from app.runner import ConsecutiveToolGuard, _build_options

        async def scenario(root: Path) -> None:
            saved = []
            guard = ConsecutiveToolGuard(persist=saved.append)
            options = _build_options({"model": "demo"}, root, "", "", lambda _: None, consecutive_tool_guard=guard)
            hook = options.hooks["PreToolUse"][0].hooks[0]
            call = {"tool_name": "mcp__audit__submit_poc", "tool_input": {"poc_id": "001-test", "source": "placeholder"}}
            with mock.patch("app.runner.pre_tool_decision", return_value=None):
                self.assertEqual(await hook(call, "1", None), {})
                reordered = {"tool_name": call["tool_name"], "tool_input": {"source": "placeholder", "poc_id": "001-test"}}
                denied = await hook(reordered, "2", None)
                self.assertEqual(denied["hookSpecificOutput"]["permissionDecision"], "deny")
                self.assertIn("连续调用", denied["hookSpecificOutput"]["permissionDecisionReason"])
                self.assertEqual(await hook({"tool_name": "Read", "tool_input": {"file_path": "TASK.md"}}, "3", None), {})
                self.assertEqual(await hook(call, "4", None), {})
                changed = {"tool_name": call["tool_name"], "tool_input": {**call["tool_input"], "source": "fixed"}}
                self.assertEqual(await hook(changed, "5", None), {})
                restored = ConsecutiveToolGuard(saved[-1])
                resumed = _build_options({"model": "demo"}, root, "", "", lambda _: None, consecutive_tool_guard=restored)
                resumed_hook = resumed.hooks["PreToolUse"][0].hooks[0]
                self.assertEqual((await resumed_hook(changed, "6", None))["hookSpecificOutput"]["permissionDecision"], "deny")
                self.assertNotIn("placeholder", " ".join(saved))

        with tempfile.TemporaryDirectory() as raw:
            asyncio.run(scenario(Path(raw)))


class CompletionModeTests(unittest.IsolatedAsyncioTestCase):
    async def test_pending_reports_replay_and_missing_candidate_feedback(self) -> None:
        from app import runner
        from app.reports import save_review

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            findings = workspace / "findings"
            findings.mkdir()
            (findings / "001-linked.md").write_text("linked", encoding="utf-8")
            (findings / "002-missing.md").write_text("missing", encoding="utf-8")
            save_review(workspace, "findings/001-linked.md", "001-demo", "REJECTED")
            verifier = mock.AsyncMock(return_value={"poc_id": "001-demo", "verdict": "ACCEPTED", "reason": "OK"})

            def load_candidate(root, poc_id, *, base_url):
                del root, base_url
                if poc_id == "001-demo":
                    return mock.Mock(poc_id=poc_id)
                from app.receipt import ReceiptError
                raise ReceiptError("未找到有效的 RECEIPT PoC")

            with mock.patch.object(runner, "load_receipt_candidate", side_effect=load_candidate):
                feedback = await runner._verify_pending_reports(workspace, "http://localhost", verifier, {"findings/001-linked.md"})
            verifier.assert_awaited_once_with("001-demo", "findings/001-linked.md")
            self.assertIn("ACCEPTED", feedback)
            self.assertIn("002-missing.md", feedback)
            self.assertIn("提交", feedback)

    async def test_report_snapshots_restore_deleted_reports_but_keep_edits(self) -> None:
        from app.runner import _restore_missing_reports, _snapshot_reports

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            findings = workspace / "findings"
            findings.mkdir()
            report = findings / "001-test.md"
            report.write_text("original", encoding="utf-8")
            snapshot = _snapshot_reports(workspace)
            report.write_text("updated", encoding="utf-8")
            self.assertEqual(_restore_missing_reports(workspace, snapshot), [])
            snapshot.update(_snapshot_reports(workspace))
            report.unlink()
            self.assertEqual(_restore_missing_reports(workspace, snapshot), ["001-test.md"])
            self.assertEqual(report.read_text(encoding="utf-8"), "updated")

    async def test_agent_continues_after_automatic_receipt_feedback(self) -> None:
        from app import runner
        from app.hub import Hub
        from app.store import Store

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source"
            source.mkdir()
            (source / "view.html").write_text("<div></div>", encoding="utf-8")
            workspace = root / "workspace"
            (workspace / "notes").mkdir(parents=True)
            (workspace / "notes" / "round-001-summary.md").write_text("完成", encoding="utf-8")
            store = Store(root / "state.json")
            store.upsert_provider({"id": "provider", "api_key": "", "base_url": ""})
            task_id = "b" * 32
            store.add_task({
                "id": task_id, "workspace": str(workspace), "source_dir": str(source), "project_name": "demo",
                "instruction": "audit", "provider_id": "provider", "model": "demo",
                "prices": {"input_per_mtok": 1, "output_per_mtok": 1}, "budget": 1, "duration_seconds": 60,
                "currency": "USD", "completion_mode": "agent", "receipt_enabled": True, "status": "queued", "round": 0,
                "spent": 0, "input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0,
                "paused_seconds": 0, "next_seq": 1,
            })
            client = mock.MagicMock()
            client.__aenter__ = mock.AsyncMock(return_value=client)
            client.__aexit__ = mock.AsyncMock(return_value=None)
            client.query = mock.AsyncMock()
            replay = mock.AsyncMock(side_effect=["RECEIPT 结果：REJECTED，请修正报告。", None])
            runner.register_stop(task_id)
            try:
                with (
                    mock.patch("claude_agent_sdk.ClaudeSDKClient", return_value=client),
                    mock.patch.object(runner, "_build_options"),
                    mock.patch.object(runner, "_consume_run", new=mock.AsyncMock(return_value="ok")),
                    mock.patch.object(runner, "_verify_pending_reports", new=replay),
                ):
                    await runner._audit(task_id, store, Hub())
            finally:
                runner.clear_stop(task_id)

            self.assertEqual(client.query.await_count, 2)
            self.assertEqual(client.query.await_args_list[1].args[0], "RECEIPT 结果：REJECTED，请修正报告。")
            self.assertEqual((store.get_task(task_id) or {})["status"], "completed")

    async def test_agent_end_marks_a_report_audit_failed_after_three_verifications(self) -> None:
        from app import runner
        from app.hub import Hub
        from app.reports import list_reports, save_review
        from app.store import Store

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source"
            source.mkdir()
            (source / "view.html").write_text("<div></div>", encoding="utf-8")
            workspace = root / "workspace"
            (workspace / "notes").mkdir(parents=True)
            (workspace / "findings").mkdir()
            (workspace / "findings" / "002-demo.md").write_text("## 标题\n测试", encoding="utf-8")
            (workspace / "notes" / "round-001-summary.md").write_text("完成", encoding="utf-8")
            results = workspace / "receipt" / "results"
            results.mkdir(parents=True)
            for index in (1, 2, 3):
                (results / f"002-demo-{index}.json").write_text("{}", encoding="utf-8")
            save_review(workspace, "findings/002-demo.md", "002-demo", "INDETERMINATE")
            store = Store(root / "state.json")
            store.upsert_provider({"id": "provider", "api_key": "", "base_url": ""})
            task_id = "c" * 32
            store.add_task({
                "id": task_id, "workspace": str(workspace), "source_dir": str(source), "project_name": "demo",
                "instruction": "audit", "provider_id": "provider", "model": "demo",
                "prices": {"input_per_mtok": 1, "output_per_mtok": 1}, "budget": 1, "duration_seconds": 60,
                "currency": "USD", "completion_mode": "agent", "receipt_enabled": True, "status": "queued", "round": 0,
                "spent": 0, "input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0,
                "paused_seconds": 0, "next_seq": 1,
            })
            client = mock.MagicMock()
            client.__aenter__ = mock.AsyncMock(return_value=client)
            client.__aexit__ = mock.AsyncMock(return_value=None)
            client.query = mock.AsyncMock()
            replay = mock.AsyncMock(return_value="RECEIPT 结果仍待处理")
            runner.register_stop(task_id)
            try:
                with (
                    mock.patch("claude_agent_sdk.ClaudeSDKClient", return_value=client),
                    mock.patch.object(runner, "_build_options"),
                    mock.patch.object(runner, "_consume_run", new=mock.AsyncMock(return_value="ok")),
                    mock.patch.object(runner, "_verify_pending_reports", new=replay),
                ):
                    await runner._audit(task_id, store, Hub())
            finally:
                runner.clear_stop(task_id)

            self.assertEqual(client.query.await_count, 1)
            replay.assert_awaited()
            self.assertEqual(list_reports(workspace, True)[0].review_status, "audit_failed")
            self.assertEqual((store.get_task(task_id) or {})["status"], "completed")

    async def test_agent_mode_completes_after_a_successful_response_with_summary(self) -> None:
        from app import runner
        from app.hub import Hub
        from app.store import Store

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source"
            source.mkdir()
            (source / "view.html").write_text("<div></div>", encoding="utf-8")
            workspace = root / "workspace"
            (workspace / "notes").mkdir(parents=True)
            (workspace / "notes" / "round-001-summary.md").write_text(
                "## 已审查文件\n\n无\n\n## 发现的漏洞\n\n无\n\n## Todo List\n\n无\n",
                encoding="utf-8",
            )
            store = Store(root / "state.json")
            store.upsert_provider({"id": "provider", "api_key": "", "base_url": ""})
            task_id = "a" * 32
            store.add_task(
                {
                    "id": task_id,
                    "workspace": str(workspace),
                    "source_dir": str(source),
                    "project_name": "demo",
                    "instruction": "audit",
                    "provider_id": "provider",
                    "model": "demo",
                    "prices": {"input_per_mtok": 1, "output_per_mtok": 1},
                    "budget": 1,
                    "duration_seconds": 60,
                    "currency": "USD",
                    "completion_mode": "agent",
                    "status": "queued",
                    "round": 0,
                    "spent": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cache_read_tokens": 0,
                    "cache_write_tokens": 0,
                    "paused_seconds": 0,
                    "next_seq": 1,
                }
            )
            client = mock.MagicMock()
            client.__aenter__ = mock.AsyncMock(return_value=client)
            client.__aexit__ = mock.AsyncMock(return_value=None)
            client.query = mock.AsyncMock()
            runner.register_stop(task_id)
            try:
                with (
                    mock.patch("claude_agent_sdk.ClaudeSDKClient", return_value=client),
                    mock.patch.object(runner, "_build_options"),
                    mock.patch.object(runner, "_consume_run", new=mock.AsyncMock(return_value="ok")),
                ):
                    await runner._audit(task_id, store, Hub())
            finally:
                runner.clear_stop(task_id)

            completed = store.get_task(task_id) or {}
            self.assertEqual(completed["status"], "completed")
            self.assertEqual(completed["stop_reason"], "completed")
            events = [json.loads(line) for line in (workspace / "logs" / "round-001.jsonl").read_text(encoding="utf-8").splitlines()]
            round_end = next(event for event in events if "代理结束审计" in event["text"])
            self.assertEqual(round_end["round"], 1)
            self.assertGreaterEqual(round_end["elapsed_seconds"], 0)
            self.assertIn("累计有效时长", round_end["text"])
            self.assertIn("多个尚未发现的 XSS 漏洞", client.query.await_args.args[0])


class ProjectImportTests(unittest.TestCase):
    @staticmethod
    def _archive(entries: dict[str, bytes], link_name: str | None = None) -> io.BytesIO:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as bundle:
            for name, content in entries.items():
                bundle.writestr(name, content)
            if link_name:
                link = zipfile.ZipInfo(link_name)
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                bundle.writestr(link, "target")
        buffer.seek(0)
        return buffer

    def test_imports_zip_into_isolated_source_directory(self) -> None:
        from app.project_import import import_project_zip

        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw) / "source"
            imported = import_project_zip(self._archive({"app/": b"", "app/main.js": b"const x = 1"}), destination, "demo.zip")
            self.assertEqual(imported.project_name, "demo")
            self.assertEqual(imported.source_dir, destination)
            self.assertEqual((destination / "app" / "main.js").read_text(encoding="utf-8"), "const x = 1")

    def test_github_url_validation(self) -> None:
        from app.project_import import ProjectImportError, github_repository

        self.assertEqual(github_repository('https://github.com/owner/repo.git/'), ('owner', 'repo'))
        for url in ('http://github.com/owner/repo', 'https://github.com.evil.test/owner/repo',
                    'https://github.com/owner/repo/tree/main', 'https://user@github.com/owner/repo',
                    'https://github.com/owner/repo?x=1', 'https://[invalid'):
            with self.subTest(url=url), self.assertRaises(ProjectImportError):
                github_repository(url)

    def test_github_download_imports_default_branch_and_strips_archive_root(self) -> None:
        from app.project_import import import_github_project

        archive = self._archive({'repo-123/': b'', 'repo-123/src/main.py': b'print(1)'})
        response = mock.MagicMock()
        response.__enter__.return_value = archive
        opener = mock.Mock()
        opener.open.return_value = response
        with tempfile.TemporaryDirectory() as raw, mock.patch('app.project_import.build_opener', return_value=opener):
            destination = Path(raw) / 'source'
            imported = import_github_project('https://github.com/owner/repo', destination)
            self.assertEqual(imported.project_name, 'repo')
            self.assertEqual((destination / 'src' / 'main.py').read_text(), 'print(1)')
            self.assertEqual(opener.open.call_args.args[0].full_url, 'https://codeload.github.com/owner/repo/zip/HEAD')

    def test_github_download_failure_leaves_no_source(self) -> None:
        from urllib.error import URLError
        from app.project_import import ProjectImportError, import_github_project

        opener = mock.Mock()
        opener.open.side_effect = URLError('offline')
        with tempfile.TemporaryDirectory() as raw, mock.patch('app.project_import.build_opener', return_value=opener):
            destination = Path(raw) / 'source'
            with self.assertRaisesRegex(ProjectImportError, 'GitHub 下载失败'):
                import_github_project('https://github.com/owner/repo', destination)
            self.assertFalse(destination.exists())

    def test_github_archive_materializes_internal_links(self) -> None:
        from app.project_import import import_project_zip

        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as bundle:
            bundle.writestr('repo/AGENTS.md', 'instructions')
            bundle.writestr('repo/.agents/skills/a.txt', 'skill')
            for name, target in [('repo/CLAUDE.md', 'AGENTS.md'), ('repo/.claude/skills', '../.agents/skills')]:
                link = zipfile.ZipInfo(name)
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                bundle.writestr(link, target)
        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw) / 'source'
            import_project_zip(archive, destination, 'repo.zip', strip_root=True)
            self.assertEqual((destination / 'CLAUDE.md').read_text(), 'instructions')
            self.assertEqual((destination / '.claude/skills/a.txt').read_text(), 'skill')

    def test_github_archive_rejects_unsafe_links(self) -> None:
        from app.project_import import ProjectImportError, import_project_zip

        for target in ('../../outside', '/etc/passwd', 'C:/outside', 'link'):
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w') as bundle:
                bundle.writestr('repo/file', 'data')
                link = zipfile.ZipInfo('repo/link')
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                bundle.writestr(link, target)
            with tempfile.TemporaryDirectory() as raw, self.subTest(target=target):
                destination = Path(raw) / 'source'
                with self.assertRaises(ProjectImportError):
                    import_project_zip(archive, destination, 'repo.zip', strip_root=True)
                self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == 'nt', 'Windows sharing errors only')
    def test_publish_retries_transient_windows_sharing_error(self) -> None:
        from app.project_import import _publish_staging_directory

        with tempfile.TemporaryDirectory() as raw:
            staging = Path(raw) / 'staging'
            destination = Path(raw) / 'source'
            staging.mkdir()
            error = PermissionError('temporarily locked')
            error.winerror = 32
            with mock.patch.object(type(staging), 'replace', autospec=True,
                                   side_effect=[error, destination]) as replace, mock.patch('app.project_import.time.sleep'):
                _publish_staging_directory(staging, destination)
            self.assertEqual(replace.call_count, 2)

    def test_github_archive_expands_link_chains_and_nested_directory_links(self) -> None:
        from app.project_import import import_project_zip

        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as bundle:
            bundle.writestr('repo/files/original.txt', 'contents')
            for name, target in [('repo/copy', 'files'), ('repo/files/second.txt', 'first.txt'),
                                 ('repo/files/first.txt', 'original.txt')]:
                link = zipfile.ZipInfo(name)
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                bundle.writestr(link, target)
        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw) / 'source'
            import_project_zip(archive, destination, 'repo.zip', strip_root=True)
            for name in ('files/first.txt', 'files/second.txt', 'copy/second.txt'):
                self.assertEqual((destination / name).read_text(), 'contents')
                self.assertFalse((destination / name).is_symlink())

    def test_github_archive_rejects_link_cycles_and_expansion_over_limit(self) -> None:
        from app.project_import import ProjectImportError, import_project_zip

        for targets, limit in [([('a', 'b'), ('b', 'a')], 100),
                               ([('a', 'file'), ('b', 'a')], 8)]:
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w') as bundle:
                bundle.writestr('repo/file', 'data')
                for name, target in targets:
                    link = zipfile.ZipInfo('repo/' + name)
                    link.external_attr = (stat.S_IFLNK | 0o777) << 16
                    bundle.writestr(link, target)
            with tempfile.TemporaryDirectory() as raw, mock.patch('app.project_import.MAX_UNPACKED_BYTES', limit):
                destination = Path(raw) / 'source'
                with self.assertRaises(ProjectImportError):
                    import_project_zip(archive, destination, 'repo.zip', strip_root=True)
                self.assertFalse(destination.exists())

    def test_rejects_unsafe_or_empty_archives_without_leaving_source(self) -> None:
        from app.project_import import ProjectImportError, import_project_zip

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for archive in (
                self._archive({"../escape.txt": b"x"}),
                self._archive({"file.txt": b"x"}, link_name="link"),
                self._archive({}),
            ):
                destination = root / f"source-{uuid4().hex}"
                with self.assertRaises(ProjectImportError):
                    import_project_zip(archive, destination, "project.zip")
                self.assertFalse(destination.exists())

    def test_file_count_limit_is_enforced_without_partial_import(self) -> None:
        from app.project_import import ProjectImportError, import_project_zip

        with tempfile.TemporaryDirectory() as raw, mock.patch('app.project_import.MAX_PROJECT_FILES', 1):
            destination = Path(raw) / 'source'
            with self.assertRaisesRegex(ProjectImportError, '最多包含 1 个文件'):
                import_project_zip(self._archive({'a': b'a', 'b': b'b'}), destination, 'project.zip')
            self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == 'nt', 'Windows file names only')
    def test_rejects_unsafe_windows_names(self) -> None:
        from app.project_import import ProjectImportError, import_project_zip

        with tempfile.TemporaryDirectory() as raw:
            for name in ('file.txt:stream', 'dir./file', 'NUL.txt', 'folder /file'):
                with self.subTest(name=name), self.assertRaises(ProjectImportError):
                    import_project_zip(self._archive({name: b'x'}), Path(raw) / 'source', 'project.zip')

    def test_prepare_workspace_uses_imported_source_without_legacy_context(self) -> None:
        from app.runner import prepare_workspace

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workspace = root / "workspace"
            source = workspace / "source"
            source.mkdir(parents=True)
            (source / "view.html").write_text("<div>{{ value }}</div>", encoding="utf-8")
            task = {
                "workspace": str(workspace),
                "source_dir": str(source),
                "project_name": "demo",
                "base_url": "http://127.0.0.1:9/",
                "instruction": "test",
                "prices": {"input_per_mtok": 1, "output_per_mtok": 1},
                "budget": 1,
                "duration_seconds": 60,
                "currency": "USD",
                "model": "demo",
                "provider_name": "local",
            }
            prepare_workspace(task)
            task_file = workspace / "TASK.md"
            self.assertIn(str(source.resolve()), task_file.read_text(encoding="utf-8"))
            self.assertIn("未提供常见位置", task_file.read_text(encoding="utf-8"))
            self.assertFalse((workspace / "context").exists())
            (source / ".github").mkdir()
            (source / ".github" / "SECURITY.md").write_text("official policy", encoding="utf-8")
            prepare_workspace(task)
            index = (workspace / "SECURITY.md").read_text(encoding="utf-8")
            self.assertIn("security-policy/.github/SECURITY.md", index)
            self.assertEqual((workspace / "security-policy" / ".github" / "SECURITY.md").read_text(encoding="utf-8"), "official policy")
            self.assertIn("安全政策索引", task_file.read_text(encoding="utf-8"))
            (source / "SECURITY.md").write_text("root policy", encoding="utf-8")
            (source / "docs").mkdir()
            (source / "docs" / "security.md").write_text("security model", encoding="utf-8")
            prepare_workspace(task)
            index = (workspace / "SECURITY.md").read_text(encoding="utf-8")
            self.assertIn("security-policy/SECURITY.md", index)
            self.assertIn("security-policy/docs/security.md", index)
            self.assertEqual((workspace / "security-policy" / "SECURITY.md").read_text(encoding="utf-8"), "root policy")
            self.assertEqual((workspace / "security-policy" / "docs" / "security.md").read_text(encoding="utf-8"), "security model")
            self.assertEqual((workspace / "security-policy" / ".github" / "SECURITY.md").read_text(encoding="utf-8"), "official policy")
            task_file.write_text("outdated task", encoding="utf-8")
            (workspace / "ARTIFACTS.md").write_text("outdated format", encoding="utf-8")
            (workspace / "poc" / "poclib.py").write_text("outdated library", encoding="utf-8")
            finding = workspace / "findings" / "001-example.md"
            finding.write_text("preserved finding", encoding="utf-8")
            task["instruction"] = "updated instruction"
            prepare_workspace(task)
            self.assertIn("updated instruction", task_file.read_text(encoding="utf-8"))
            self.assertNotEqual((workspace / "ARTIFACTS.md").read_text(encoding="utf-8"), "outdated format")
            self.assertNotEqual((workspace / "poc" / "poclib.py").read_text(encoding="utf-8"), "outdated library")
            self.assertEqual(finding.read_text(encoding="utf-8"), "preserved finding")

    def test_projects_share_source_and_tasks_require_preflight(self) -> None:
        import app.main as main
        from fastapi.testclient import TestClient
        from app.store import Store

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            test_store = Store(root / "state.json")
            test_store.upsert_provider(
                {
                    "id": "provider",
                    "name": "Demo",
                    "base_url": "",
                    "api_key": "",
                    "currency": "USD",
                    "catalog": [{"id": "model", "name": "Model"}],
                    "models": [{"id": "model", "name": "Model", "input_per_mtok": 1, "output_per_mtok": 2}],
                }
            )
            with (
                mock.patch.object(main, "store", test_store),
                mock.patch.object(main, "WORKSPACES_DIR", root / "workspaces"),
                mock.patch.object(main, "PROJECTS_DIR", root / "projects"),
                mock.patch.object(main, "_schedule_task") as schedule,
            ):
                with TestClient(main.app) as client:
                    project = client.post("/api/projects", data={"name": "项目 A"}, files={"project_zip": ("demo.zip", self._archive({"src/app.js": b"export {}"}).getvalue(), "application/zip")}).json()
                    rejected = client.post('/api/tasks', data={'instruction': 'audit', 'provider_id': 'provider', 'model': 'model', 'budget': '1', 'duration_minutes': '10', 'project_id': project['id']})
                    self.assertEqual(rejected.status_code, 409)
                    test_store.set_project_initialization(project['id'], {'environment_status': 'ready'})
                    response = client.post(
                        "/api/tasks",
                        data={
                            "instruction": "审计模板输出",
                            "provider_id": "provider",
                            "model": "model",
                            "budget": "1",
                            "duration_minutes": "10",
                            "project_id": project["id"],
                        },
                    )
                    task = response.json()
                    schedule.assert_called_once_with(task['id'])
                    self.assertEqual(task["completion_mode"], "agent")
                    second = client.post("/api/tasks", data={"instruction": "再次审计", "provider_id": "provider", "model": "model", "budget": "1", "duration_minutes": "10", "project_id": project["id"]}).json()
                    self.assertEqual(task["source_dir"], second["source_dir"])
                    self.assertNotEqual(task["workspace"], second["workspace"])
                    self.assertEqual(schedule.call_count, 2)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(task["project_name"], "项目 A")
        self.assertEqual(task["status"], "queued")
        self.assertTrue(task["requires_environment_setup"])
        self.assertFalse(task["environment_ready"])

    def test_remove_tree_deletes_readonly_git_pack(self) -> None:
        import shutil
        from app.project_import import remove_tree

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "snapshot"
            pack = root / "environment" / "cacti" / ".git" / "objects" / "pack" / "pack.idx"
            pack.parent.mkdir(parents=True)
            pack.write_bytes(b"idx")
            (root / "environment" / "start.py").write_text("pass\n", encoding="utf-8")
            os.chmod(pack, stat.S_IREAD)
            if os.name == "nt":
                with self.assertRaises(PermissionError):
                    shutil.rmtree(root)
                self.assertTrue(pack.exists())
            remove_tree(root)
            self.assertFalse(root.exists())


class ReportProjectionTests(unittest.TestCase):
    @staticmethod
    def _report(poc: str) -> str:
        return f"""## 标题

模板输出 XSS

## PoC

poc/{poc}.py
"""

    def test_lists_only_findings_and_projects_latest_verdict(self) -> None:
        from app.reports import list_reports, save_review

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            findings = workspace / "findings"
            findings.mkdir()
            (findings / "001-demo.md").write_text(self._report("001-demo"), encoding="utf-8")
            (workspace / "notes").mkdir()
            (workspace / "notes" / "private.md").write_text("not a report", encoding="utf-8")
            save_review(workspace, "findings/001-demo.md", "001-other", "REJECTED")
            save_review(workspace, "findings/001-demo.md", "001-demo", "ACCEPTED")
            (findings / "001-demo.md").write_text("## 标题\n模板输出 XSS\n\n## PoC\n无", encoding="utf-8")

            reports = list_reports(workspace, validator_enabled=True)

        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].path, "findings/001-demo.md")
        self.assertEqual(reports[0].title, "模板输出 XSS")
        self.assertEqual(reports[0].poc_id, "001-demo")
        self.assertEqual(reports[0].review_status, "passed")

    def test_pending_when_validator_has_no_usable_result(self) -> None:
        from app.reports import list_reports, save_review

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            findings = workspace / "findings"
            findings.mkdir()
            (findings / "001-demo.md").write_text(self._report("001-demo"), encoding="utf-8")
            self.assertEqual(list_reports(workspace, validator_enabled=False)[0].review_status, None)
            self.assertEqual(list_reports(workspace, validator_enabled=True)[0].review_status, "pending")
            save_review(workspace, "findings/001-demo.md", "001-demo", "INDETERMINATE")
            self.assertEqual(list_reports(workspace, validator_enabled=True)[0].review_status, "pending")
            save_review(workspace, "findings/001-demo.md", "001-demo", "REJECTED")
            self.assertEqual(list_reports(workspace, validator_enabled=True)[0].review_status, "failed")

    def test_three_verification_attempts_close_as_audit_failed_when_agent_ends(self) -> None:
        from app.reports import close_unresolved_reviews, list_reports, record_verification_attempt, save_review

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            findings = workspace / "findings"
            results = workspace / "receipt" / "results"
            findings.mkdir(parents=True)
            results.mkdir(parents=True)
            (findings / "002-demo.md").write_text(self._report("002-demo"), encoding="utf-8")
            save_review(workspace, "findings/002-demo.md", "002-demo", "INDETERMINATE")
            for index in (1, 2):
                (results / f"002-demo-{index}.json").write_text("{}", encoding="utf-8")
            self.assertEqual(close_unresolved_reviews(workspace), [])
            self.assertEqual(list_reports(workspace, True)[0].review_status, "pending")

            self.assertEqual(record_verification_attempt(workspace, "findings/002-demo.md", "002-demo"), 3)
            (results / "002-demo-3.json").write_text("{}", encoding="utf-8")
            self.assertEqual(record_verification_attempt(workspace, "findings/002-demo.md", "002-demo"), 4)
            self.assertEqual(close_unresolved_reviews(workspace), ["findings/002-demo.md"])
            self.assertEqual(list_reports(workspace, True)[0].review_status, "audit_failed")
            save_review(workspace, "findings/002-demo.md", "002-demo", "REJECTED")
            self.assertEqual(list_reports(workspace, True)[0].review_status, "failed")
            save_review(workspace, "findings/002-demo.md", "002-demo", "ACCEPTED")
            self.assertEqual(list_reports(workspace, True)[0].review_status, "passed")

    def test_projects_latest_matching_path_results_without_evidence(self) -> None:
        from app.reports import list_reports, save_review

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            (workspace / "findings").mkdir()
            (workspace / "findings" / "001-demo.md").write_text(self._report("001-demo"), encoding="utf-8")
            save_review(workspace, "findings/001-demo.md", "001-demo", "ACCEPTED")
            results = workspace / "receipt" / "results"
            results.mkdir()
            path = {"path_id": "editor-admin", "attacker_account": "editor", "victim_account": "admin",
                    "verdict": "ACCEPTED", "reason": "BROWSER_BOUND_RECEIPT", "accept_self_xss": False,
                    "evidence": {"secret": "never displayed"}}
            (results / "001-demo-1.json").write_text(json.dumps({"verdict": "ACCEPTED", "primary": path, "extensions": []}), encoding="utf-8")
            projected = list_reports(workspace, True)[0].verification_paths
            self.assertEqual(projected[0]["attacker_account"], "editor")
            self.assertIsNone(projected[0]["attacker_role"])
            self.assertNotIn("evidence", projected[0])
            (results / "001-demo-2.json").write_text(json.dumps({"verdict": "ACCEPTED", "paths": [path]}), encoding="utf-8")
            self.assertEqual(list_reports(workspace, True)[0].verification_paths, projected)
            (results / "001-demo-3.json").write_text(json.dumps({"verdict": "REJECTED", "primary": path, "extensions": []}), encoding="utf-8")
            self.assertEqual(list_reports(workspace, True)[0].verification_paths, [])

    def test_reports_endpoint_uses_roles_for_the_recorded_manifest(self) -> None:
        from app import main
        from app.receipt import load_manifest
        from app.reports import save_review

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            (workspace / "findings").mkdir()
            (workspace / "findings" / "001-demo.md").write_text(self._report("001-demo"), encoding="utf-8")
            save_review(workspace, "findings/001-demo.md", "001-demo", "ACCEPTED")
            results = workspace / "receipt" / "results"
            results.mkdir()
            path = {"path_id": "primary", "attacker_account": "attacker", "victim_account": "victim"}
            manifest_path = workspace / "demo.json"
            manifest_path.write_text(json.dumps({
                "target": {"id": "demo", "version": "1", "image_digest": "demo@sha256:abc"},
                "adapter": "demo", "allowed_origins": ["{{target_origin}}"],
                "threat_paths": [{"id": "primary", "attacker_account": "attacker", "victim_account": "victim", "primary": True}],
            }), encoding="utf-8")
            plan_path = workspace / "demo" / "account-plan.json"
            plan_path.parent.mkdir()
            plan_path.write_text(json.dumps({"accounts": [
                {"account_id": "attacker", "role_id": "editor"}, {"account_id": "victim", "role_id": "owner"},
            ]}), encoding="utf-8")
            manifest_hash = load_manifest(manifest_path, workspace).manifest_hash
            task = {"workspace": raw, "receipt_enabled": True, "receipt_manifest": manifest_path.name}
            with mock.patch.object(main.store, "get_task", return_value=task), mock.patch.object(main, "RECEIPT_MANIFESTS_DIR", workspace):
                with TestClient(main.app) as client:
                    cases = (
                        (manifest_hash, {}, ("editor", "owner")),
                        ("older-manifest", {"principal_roles": {"attacker": "member", "victim": "manager"}}, ("member", "manager")),
                        ("7c803e59a4110ccafa519f7225d5cc3dc3a6b47e168f8c4e6fd26f0f59b274da", {}, ("admin", "normal")),
                        ("unknown-manifest", {}, (None, None)),
                    )
                    for recorded_hash, metadata, roles in cases:
                        with self.subTest(manifest_hash=recorded_hash):
                            record = {"verdict": "ACCEPTED", "manifest_hash": recorded_hash, "extensions": [],
                                      "primary": {**path, "verdict": "ACCEPTED"}, **metadata}
                            (results / "001-demo-1.json").write_text(json.dumps(record), encoding="utf-8")
                            response = client.get("/api/tasks/demo/reports")
                            self.assertEqual(response.status_code, 200)
                            projected = response.json()["reports"][0]["verification_paths"][0]
                            self.assertEqual((projected["attacker_role"], projected["victim_role"]), roles)


class PausePersistenceTests(unittest.TestCase):
    def _task(self, task_id: str, status: str, **extra: object) -> dict:
        return {
            "id": task_id,
            "status": status,
            "stop_reason": None,
            "pause_reason": None,
            "paused_at": None,
            "paused_seconds": 0,
            "finished_at": None,
            **extra,
        }

    def test_restart_recovers_runnable_tasks_and_keeps_manual_pause(self) -> None:
        from app.store import Store

        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as raw:
            state_path = Path(raw) / "state.json"
            tasks = [
                self._task("running", "running"),
                self._task(
                    "quota",
                    "paused",
                    pause_reason="quota",
                    paused_at=(now - timedelta(seconds=60)).isoformat(),
                    paused_seconds=5,
                ),
                self._task(
                    "manual",
                    "paused",
                    pause_reason="manual",
                    paused_at=(now - timedelta(seconds=30)).isoformat(),
                ),
                self._task(
                    "pausing",
                    "pause_requested",
                    pause_reason="manual",
                    paused_at=(now - timedelta(seconds=10)).isoformat(),
                ),
            ]
            state_path.write_text(json.dumps({"providers": [], "tasks": tasks}), encoding="utf-8")
            store = Store(state_path)
            self.assertEqual(set(store.recover_interrupted()), {"running", "quota"})

            running = store.get_task("running") or {}
            quota = store.get_task("quota") or {}
            manual = store.get_task("manual") or {}
            pausing = store.get_task("pausing") or {}
            self.assertEqual(running["status"], "queued")
            self.assertEqual(quota["status"], "queued")
            self.assertIsNotNone(quota["paused_at"])
            self.assertGreaterEqual(quota["paused_seconds"], 64)
            self.assertEqual((manual["status"], manual["pause_reason"]), ("paused", "manual"))
            self.assertEqual((pausing["status"], pausing["pause_reason"]), ("paused", "manual"))

    def test_restart_excludes_time_since_last_clock_checkpoint(self) -> None:
        from app.store import Store, active_seconds

        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as raw:
            store = Store(Path(raw) / "state.json")
            task = self._task("crashed", "running", started_at=(now - timedelta(seconds=3600)).isoformat(), clock_checkpoint_at=(now - timedelta(seconds=3540)).isoformat())
            store.add_task(task)
            self.assertEqual(store.recover_interrupted(), ["crashed"])
            recovered = store.get_task("crashed")
            self.assertAlmostEqual(active_seconds(recovered, now), 60, delta=1)
            self.assertEqual(store.recover_interrupted(), ["crashed"])
            settled = store.settle_pause("crashed", now + timedelta(seconds=30))
            self.assertAlmostEqual(active_seconds(settled, now + timedelta(seconds=30)), 60, delta=1)

    def test_clock_checkpoint_only_updates_running_tasks(self) -> None:
        from app.store import Store

        with tempfile.TemporaryDirectory() as raw:
            store = Store(Path(raw) / "state.json")
            store.add_task(self._task("running", "running"))
            store.add_task(self._task("paused", "paused", pause_reason="manual"))
            store.checkpoint_running_clock("running")
            store.checkpoint_running_clock("paused")
            self.assertIsNotNone(store.get_task("running").get("clock_checkpoint_at"))
            self.assertIsNone(store.get_task("paused").get("clock_checkpoint_at"))

    def test_resume_endpoint_settles_pause_and_schedules_task(self) -> None:
        import app.main as main
        from app.store import Store

        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as raw:
            test_store = Store(Path(raw) / "state.json")
            test_store.add_task(
                self._task(
                    "manual",
                    "paused",
                    pause_reason="manual",
                    paused_at=(now - timedelta(seconds=40)).isoformat(),
                    paused_seconds=3,
                )
            )
            with (
                mock.patch.object(main, "store", test_store),
                mock.patch.object(main, "_schedule_task") as schedule,
                mock.patch.dict(main._RUNNING, {}, clear=True),
            ):
                resumed = asyncio.run(main.resume_task("manual"))
            self.assertEqual(resumed["status"], "queued")
            self.assertIsNone(resumed["paused_at"])
            self.assertGreaterEqual(resumed["paused_seconds"], 42)
            schedule.assert_called_once_with("manual")

    def test_pause_endpoint_requests_recoverable_pause(self) -> None:
        import app.main as main
        from app.runner import clear_stop, stop_reason
        from app.store import Store

        with tempfile.TemporaryDirectory() as raw:
            test_store = Store(Path(raw) / "state.json")
            test_store.add_task(self._task("running", "running"))
            with mock.patch.object(main, "store", test_store):
                paused = asyncio.run(main.pause_task("running"))
            self.assertEqual(paused["status"], "pause_requested")
            self.assertEqual(paused["pause_reason"], "manual")
            self.assertEqual(stop_reason("running"), "paused")
            clear_stop("running")


class PricingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.prices = Prices(
            input_per_mtok=3,
            output_per_mtok=15,
            cache_read_per_mtok=0.3,
            cache_write_per_mtok=3.75,
        )

    def test_price_uses_caller_rates(self) -> None:
        tokens = Tokens(input=1_000_000, output=2_000_000, cache_read=1_000_000, cache_write=0)
        self.assertAlmostEqual(price_of(tokens, self.prices), 3 + 30 + 0.3)

    def test_absolute_usage_replaces_rather_than_sums(self) -> None:
        ledger = Ledger()
        ledger.apply_absolute(Tokens(input=100, output=20), 1)
        ledger.apply_absolute(Tokens(input=150, output=40), 1.5)
        self.assertAlmostEqual(ledger.spent, 1.5)
        self.assertEqual(ledger.tokens.input, 150)

    def test_new_session_is_added_after_reset(self) -> None:
        ledger = Ledger()
        ledger.apply_absolute(Tokens(input=100, output=50), 2)
        ledger.apply_absolute(Tokens(input=10, output=5), 0.4)
        self.assertAlmostEqual(ledger.spent, 2.4)
        self.assertEqual(ledger.tokens.input, 110)

    def test_delta_estimate_is_replaced_by_absolute_total(self) -> None:
        ledger = Ledger()
        ledger.apply_delta(Tokens(input=80, output=20), self.prices)
        self.assertEqual(ledger.mode, "delta")
        ledger.apply_absolute(Tokens(input=80, output=20), 0.2)
        self.assertAlmostEqual(ledger.spent, 0.2)
        self.assertEqual(ledger.tokens.total, 100)

    def test_model_usage_ignores_vendor_cost_field(self) -> None:
        summary = summarize_model_usage(
            {
                "demo": {
                    "inputTokens": 1_000_000,
                    "outputTokens": 0,
                    "cacheReadInputTokens": 0,
                    "cacheCreationInputTokens": 0,
                    "costUSD": 999,
                }
            },
            self.prices,
        )
        self.assertIsNotNone(summary)
        tokens, cost = summary or (Tokens(), 0)
        self.assertEqual(tokens.input, 1_000_000)
        self.assertAlmostEqual(cost, 3.0)

    def test_missing_cache_price_follows_input(self) -> None:
        prices = Prices.from_mapping({"input_per_mtok": 2, "output_per_mtok": 4})
        self.assertEqual(prices.cache_read_per_mtok, 2)
        self.assertEqual(prices.cache_write_per_mtok, 2)

    def test_stream_usage_merges_cumulative_output(self) -> None:
        usage = UsageAccumulator()
        self.assertTrue(
            usage.update_stream(
                "call-1",
                {
                    "type": "message_start",
                    "message": {
                        "usage": {
                            "input_tokens": 100,
                            "output_tokens": 1,
                            "cache_read_input_tokens": 20,
                        }
                    },
                },
            )
        )
        self.assertTrue(
            usage.update_stream(
                "call-1",
                {"type": "message_delta", "usage": {"output_tokens": 12}},
            )
        )
        self.assertEqual(usage.tokens, Tokens(input=100, output=12, cache_read=20))

    def test_stream_and_assistant_usage_are_not_double_counted(self) -> None:
        usage = UsageAccumulator()
        usage.update_stream(
            "session-1\0call-1",
            {"type": "message_start", "message": {"usage": {"input_tokens": 100}}},
        )
        usage.update("session-1\0call-1", {"input_tokens": 100, "output_tokens": 25})
        usage.update("session-2\0call-2", {"inputTokens": 40, "outputTokens": 10})
        self.assertEqual(usage.tokens, Tokens(input=140, output=35))
        usage.clear_session("session-1")
        self.assertEqual(usage.tokens, Tokens(input=40, output=10))

    def test_pending_usage_is_visible_before_final_result(self) -> None:
        from app.runner import _usage_snapshot

        usage = UsageAccumulator()
        usage.update("session-1\0call-1", {"input_tokens": 1_000_000, "output_tokens": 100_000})
        snapshot = _usage_snapshot(Ledger(), usage, self.prices)
        self.assertEqual(snapshot["input_tokens"], 1_000_000)
        self.assertEqual(snapshot["output_tokens"], 100_000)
        self.assertAlmostEqual(snapshot["spent"], 4.5)

    def test_ledger_restores_same_session_snapshot_without_double_counting(self) -> None:
        ledger = Ledger.from_snapshot(
            {
                "spent": 1.5,
                "input_tokens": 100,
                "output_tokens": 20,
                "cache_read_tokens": 5,
                "cache_write_tokens": 2,
            }
        )
        self.assertAlmostEqual(ledger.spent, 1.5)
        ledger.apply_absolute(Tokens(input=130, output=30, cache_read=5, cache_write=2), 1.9)
        self.assertAlmostEqual(ledger.spent, 1.9)
        self.assertEqual(ledger.tokens.input, 130)

    def test_resume_settles_only_usage_after_saved_session_baseline(self) -> None:
        ledger = Ledger()
        ledger.settle_session("session", Tokens(input=100, output=40), self.prices, Tokens())
        saved = {**ledger.snapshot(), **ledger.persistence(), "session_id": "session"}
        resumed = Ledger.from_snapshot(saved)
        resumed.settle_session("session", Tokens(input=120, output=45), self.prices, Tokens())
        self.assertEqual(resumed.tokens, Tokens(input=120, output=45))
        reset = Tokens(input=3, output=1)
        resumed.settle_session("session", reset, self.prices, reset, resumed=True)
        self.assertEqual(resumed.tokens, Tokens(input=123, output=46))
        resumed.settle_session("session", Tokens(input=7, output=2), self.prices, Tokens())
        self.assertEqual(resumed.tokens, Tokens(input=127, output=47))

    def test_regressing_session_counters_keep_each_settled_high_water_mark(self) -> None:
        ledger = Ledger()
        ledger.settle_session("session", Tokens(input=100, output=60), self.prices, Tokens())
        self.assertFalse(
            ledger.settle_session(
                "session", Tokens(input=120, output=55), self.prices, Tokens(input=20), resumed=True,
            )
        )
        self.assertEqual(ledger.tokens, Tokens(input=120, output=60))

        restored = Ledger.from_snapshot(ledger.persistence())
        restored.settle_session("session", Tokens(input=110, output=40), self.prices, Tokens())
        restored.settle_session("session", Tokens(input=125, output=63), self.prices, Tokens())
        restored.settle_session("new-session", Tokens(input=3, output=1), self.prices, Tokens())
        expected = Tokens(input=128, output=64)
        self.assertEqual(restored.tokens, expected)
        self.assertAlmostEqual(restored.spent, price_of(expected, self.prices))

    def test_replayed_delta_result_does_not_bill_again_after_restore(self) -> None:
        from app.runner import _apply_result

        ledger = Ledger()
        pending = UsageAccumulator()
        result = SimpleNamespace(session_id="session", uuid="result-1", usage={"input_tokens": 20})
        self.assertEqual(_apply_result(ledger, result, self.prices, pending), (True, True))
        restored = Ledger.from_snapshot(json.loads(json.dumps(ledger.persistence())))
        self.assertEqual(_apply_result(restored, result, self.prices, pending), (False, True))
        self.assertEqual(restored.tokens, Tokens(input=20))

        next_result = SimpleNamespace(session_id="session", uuid="result-2", usage={"input_tokens": 20})
        _apply_result(restored, next_result, self.prices, pending)
        self.assertEqual(restored.tokens, Tokens(input=40))

    def test_legacy_resume_uses_only_observed_new_calls(self) -> None:
        ledger = Ledger.from_snapshot({"spent": 2, "input_tokens": 100, "output_tokens": 50, "session_id": "old"})
        ledger.settle_session("old", Tokens(input=90, output=40), self.prices, Tokens(input=4, output=2))
        self.assertEqual(ledger.tokens, Tokens(input=104, output=52))
        self.assertAlmostEqual(ledger.spent, 2 + price_of(Tokens(input=4, output=2), self.prices))
        ledger.settle_session("old", Tokens(input=95, output=42), self.prices, Tokens())
        self.assertEqual(ledger.tokens, Tokens(input=109, output=54))

    def test_interleaved_sessions_keep_their_baselines_across_restore(self) -> None:
        main = Tokens(input=100, output=40, cache_read=1_000)
        selector = Tokens(input=10, output=5)
        ledger = Ledger.from_snapshot({
            "spent": price_of(main, self.prices),
            "input_tokens": main.input,
            "output_tokens": main.output,
            "cache_read_tokens": main.cache_read,
            "session_id": "main",
            "usage_baseline_session": "main",
            "usage_baseline": {"input_tokens": 100, "output_tokens": 40, "cache_read_input_tokens": 1_000},
        })
        ledger.settle_session("selector", selector, self.prices, Tokens())

        restored = Ledger.from_snapshot(ledger.persistence())
        main_total = Tokens(input=120, output=45, cache_read=1_400)
        selector_total = Tokens(input=12, output=6)
        restored.settle_session("main", main_total, self.prices, Tokens())
        restored.settle_session("selector", selector_total, self.prices, Tokens())
        restored.settle_session("main", main_total, self.prices, Tokens())

        expected = main_total.add(selector_total)
        self.assertEqual(restored.tokens, expected)
        self.assertAlmostEqual(restored.spent, price_of(expected, self.prices))

    def test_selector_usage_fallback_preserves_main_session_baseline(self) -> None:
        from app.runner import _apply_result

        ledger = Ledger()
        pending = UsageAccumulator()
        ledger.settle_session("main", Tokens(input=100), self.prices, Tokens())
        selector_result = SimpleNamespace(session_id="selector", usage={"input_tokens": 10})
        selector_retry = SimpleNamespace(session_id="selector", model_usage={"demo": {"inputTokens": 12}})
        main_result = SimpleNamespace(session_id="main", model_usage={"demo": {"inputTokens": 120}})
        self.assertEqual(_apply_result(ledger, selector_result, self.prices, pending), (True, True))
        self.assertEqual(_apply_result(ledger, selector_retry, self.prices, pending), (True, True))
        self.assertEqual(_apply_result(ledger, main_result, self.prices, pending), (True, True))
        self.assertEqual(ledger.tokens, Tokens(input=132))

    def test_legacy_main_session_without_baseline_survives_selector_settlement(self) -> None:
        ledger = Ledger.from_snapshot({
            "input_tokens": 110,
            "session_id": "main",
            "usage_baseline_session": "previous-selector",
            "usage_baseline": {"input_tokens": 10},
        })
        ledger.settle_session("selector", Tokens(input=5), self.prices, Tokens())
        restored = Ledger.from_snapshot(ledger.persistence())
        restored.settle_session("main", Tokens(input=120), self.prices, Tokens(input=20))
        restored.settle_session("main", Tokens(input=125), self.prices, Tokens())

        self.assertEqual(restored.tokens, Tokens(input=140))

    def test_restoring_snapshot_does_not_commit_live_estimate_twice(self) -> None:
        from app.runner import _usage_snapshot
        ledger = Ledger()
        ledger.settle_session("session", Tokens(input=100), self.prices, Tokens())
        pending = UsageAccumulator()
        pending.update("session\0new", {"input_tokens": 20})
        snapshot = _usage_snapshot(ledger, pending, self.prices)
        snapshot["session_id"] = "session"
        restored = Ledger.from_snapshot(snapshot)
        restored_pending = UsageAccumulator.from_snapshot(snapshot["usage_pending"])
        self.assertEqual(restored_pending.tokens.input, 20)
        restored.settle_session("session", Tokens(input=120), self.prices, Tokens())
        self.assertEqual(restored.tokens.input, 120)


class GuardTests(unittest.TestCase):
    def test_reads_only_allow_workspace_and_source(self) -> None:
        from app.guard import pre_tool_decision

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workspace = root / "workspaces" / "current"
            sibling = root / "workspaces" / "other"
            source = root / "src"
            workspace.mkdir(parents=True)
            sibling.mkdir(parents=True)
            source.mkdir()

            self.assertIsNone(
                pre_tool_decision(workspace, "Read", {"file_path": "TASK.md"}, read_roots=(source,))
            )
            self.assertIsNone(
                pre_tool_decision(workspace, "Grep", {"path": str(source)}, read_roots=(source,))
            )
            self.assertIsNotNone(
                pre_tool_decision(workspace, "Read", {"file_path": str(sibling / "TASK.md")}, read_roots=(source,))
            )
            self.assertIsNotNone(
                pre_tool_decision(workspace, "Glob", {"path": "../other"}, read_roots=(source,))
            )

    def test_write_must_stay_in_workspace(self) -> None:
        from app.guard import pre_tool_decision

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            self.assertIsNone(pre_tool_decision(workspace, "Write", {"file_path": "findings/001.md"}))
            self.assertIsNotNone(
                pre_tool_decision(
                    workspace,
                    "Edit",
                    {"file_path": str(workspace.parent / "src" / "index.php")},
                )
            )

    def test_receipt_artifacts_are_not_readable_by_agent_tools(self) -> None:
        from app.guard import pre_tool_decision

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            result = workspace / "receipt" / "results" / "001-example-1.json"
            result.parent.mkdir(parents=True)
            result.write_text('{"primary":{"path_id":"secret-path"}}', encoding="utf-8")
            self.assertIsNotNone(pre_tool_decision(workspace, "Read", {"file_path": str(result)}))

    def test_shell_paths_only_allow_workspace_and_source(self) -> None:
        from app.guard import pre_tool_decision

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workspace = root / "workspaces" / "current"
            sibling = root / "workspaces" / "other"
            source = root / "src"
            workspace.mkdir(parents=True)
            sibling.mkdir(parents=True)
            source.mkdir()
            poc = workspace / "poc" / "001-check.py"
            poc.parent.mkdir()
            poc.write_text("print('ok')\n", encoding="utf-8")

            self.assertIsNone(
                pre_tool_decision(
                    workspace,
                    "Bash",
                    {"command": "curl http://127.0.0.1:17778/index.php"},
                    {"127.0.0.1"},
                    read_roots=(source,),
                )
            )
            self.assertIsNone(
                pre_tool_decision(
                    workspace,
                    "Bash",
                    {
                        "command": (
                            "curl 'http://127.0.0.1:17778/index.php?q=<script>"
                            "alert(1);</script>'"
                        )
                    },
                    {"127.0.0.1"},
                    read_roots=(source,),
                )
            )
            self.assertIsNone(
                pre_tool_decision(
                    workspace,
                    "Bash",
                    {"command": "python poc/001-check.py"},
                    read_roots=(source,),
                )
            )
            self.assertIsNotNone(
                pre_tool_decision(
                    workspace,
                    "PowerShell",
                    {"command": f'Get-Content "{workspace / "TASK.md"}"'},
                    read_roots=(source,),
                )
            )
            self.assertIsNotNone(
                pre_tool_decision(
                    workspace,
                    "Bash",
                    {
                        "command": (
                            f'curl --data-binary "@{sibling / "TASK.md"}" '
                            "http://127.0.0.1:17778/index.php"
                        )
                    },
                    {"127.0.0.1"},
                    read_roots=(source,),
                )
            )
            self.assertIsNotNone(
                pre_tool_decision(
                    workspace,
                    "Bash",
                    {
                        "command": (
                            "curl http://127.0.0.1:17778/index.php; "
                            "cat ../other/TASK.md"
                        )
                    },
                    {"127.0.0.1"},
                    read_roots=(source,),
                )
            )
            self.assertIsNone(
                pre_tool_decision(
                    workspace,
                    "Bash",
                    {"command": f'grep -n echo "{source / "index.php"}"'},
                    read_roots=(source,),
                )
            )
            self.assertIsNotNone(
                pre_tool_decision(
                    workspace,
                    "Bash",
                    {
                        "command": (
                            "curl --data-binary @$HOME/secret "
                            "http://127.0.0.1:17778/index.php"
                        )
                    },
                    {"127.0.0.1"},
                    read_roots=(source,),
                )
            )
            self.assertIsNotNone(
                pre_tool_decision(
                    workspace,
                    "Bash",
                    {
                        "command": (
                            "curl --config=notes/curl.conf "
                            "http://127.0.0.1:17778/index.php"
                        )
                    },
                    {"127.0.0.1"},
                    read_roots=(source,),
                )
            )

    def test_shell_ignores_url_and_regex_literals_but_reports_real_paths(self) -> None:
        from app.guard import pre_tool_decision

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workspace = root / "workspaces" / "current"
            sibling = root / "workspaces" / "other"
            workspace.mkdir(parents=True)
            sibling.mkdir(parents=True)
            hosts = {"127.0.0.1"}
            login = (
                f'cd "{workspace.as_posix()}" && python -I -c "\n'
                "import json, urllib.request\n"
                "BASE='http://127.0.0.1:47918'\n"
                "d=json.load(open('runtime/receipt-run.json'))\n"
                "wo=d['accounts']['web-only']\n"
                "req=urllib.request.Request(BASE+'/api/v1/auth/login', "
                "data=json.dumps({'username':wo['username'],'password':wo['password']}).encode(), "
                "headers={'Content-Type':'application/json'})\n"
                "r=urllib.request.urlopen(req)\n"
                "print(r.status, r.read()[:150])\n"
                '"'
            )
            self.assertIsNone(pre_tool_decision(workspace, "Bash", {"command": login}, hosts))
            sed = (
                "sed -n '/public void requireReadAccess(User user, StoredFile file)/,/^    }/p' "
                "app/FileStorageService.java"
            )
            self.assertIsNone(pre_tool_decision(workspace, "Bash", {"command": sed}, hosts))
            resolved = workspace.resolve()
            drive = resolved.drive.rstrip(":").lower()
            rest = resolved.as_posix().split(":", 1)[1]
            self.assertIsNone(
                pre_tool_decision(
                    workspace,
                    "Bash",
                    {"command": f"cat /{drive}{rest}/TASK.md"},
                    hosts,
                )
            )

            outside = pre_tool_decision(
                workspace,
                "Bash",
                {"command": "python -c \"open('/etc/passwd')\""},
                hosts,
            )
            self.assertIsNotNone(outside)
            self.assertIn("/etc/passwd", outside or "")
            parent = pre_tool_decision(workspace, "Bash", {"command": "cat ../secret"}, hosts)
            self.assertIsNotNone(parent)
            self.assertIn("..", parent or "")
            remote = pre_tool_decision(
                workspace,
                "Bash",
                {"command": "curl https://nvd.nist.gov/vuln"},
                hosts,
            )
            self.assertIsNotNone(remote)
            self.assertIn("https://nvd.nist.gov/vuln", remote or "")
            read = pre_tool_decision(workspace, "Read", {"file_path": str(sibling / "TASK.md")})
            self.assertIsNotNone(read)
            self.assertIn("TASK.md", read or "")
            destroyed = pre_tool_decision(workspace, "Bash", {"command": "docker compose down -v"}, hosts)
            self.assertIsNotNone(destroyed)
            self.assertIn("compose down", destroyed or "")

    def test_shell_blocks_lab_destruction(self) -> None:
        from app.guard import command_block_reason

        self.assertIsNotNone(command_block_reason("powershell .\\scripts\\register-test-accounts.ps1"))
        self.assertIsNotNone(command_block_reason("docker compose down -v"))
        self.assertIsNotNone(command_block_reason(".\\start.ps1 -New"))
        self.assertIsNone(command_block_reason("python poc/001.py"))

    def test_environment_setup_allows_shell_and_web_without_relaxing_audit(self) -> None:
        from app.guard import pre_tool_decision

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw) / "workspace"
            workspace.mkdir()
            for command in ("printf test | cat > environment/output.txt", "rm -rf environment/tmp", "curl https://example.com/"):
                self.assertIsNone(pre_tool_decision(workspace, "Bash", {"command": command}, set(), environment_setup=True))
            self.assertIsNotNone(pre_tool_decision(workspace, "Bash", {"command": "curl https://example.com/"}, set()))
            for tool in ("WebSearch", "WebFetch"):
                self.assertIsNone(pre_tool_decision(workspace, tool, {}, set(), environment_setup=True))
                self.assertIsNotNone(pre_tool_decision(workspace, tool, {}, set()))
            self.assertIsNone(pre_tool_decision(workspace, "PowerShell", {"command": "winget install --id OpenJS.NodeJS.LTS -e"}, set(), environment_setup=True))
            self.assertIsNotNone(pre_tool_decision(workspace, "PowerShell", {"command": "Get-Location"}, set()))

    def test_audit_shell_allows_composition_but_keeps_guards(self) -> None:
        from app.guard import pre_tool_decision

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            allowed = "printf 'hello\\n' | sort > notes.txt\ncat notes.txt"
            self.assertIsNone(pre_tool_decision(workspace, "Bash", {"command": allowed}, {"127.0.0.1"}))
            for command in (
                "cat ../secret | sort",
                "echo test > poc/example.py",
                "curl https://example.com/ | cat",
                "docker compose down",
            ):
                self.assertIsNotNone(pre_tool_decision(workspace, "Bash", {"command": command}, {"127.0.0.1"}))

    def test_web_search_tools_are_denied(self) -> None:
        from app.guard import pre_tool_decision

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            hosts = {"127.0.0.1", "localhost"}
            self.assertIsNotNone(pre_tool_decision(workspace, "WebSearch", {"query": "joomla xss"}, hosts))
            self.assertIsNotNone(pre_tool_decision(workspace, "WebFetch", {"url": "https://nvd.nist.gov"}, hosts))
            self.assertIsNotNone(
                pre_tool_decision(workspace, "Bash", {"command": "curl https://nvd.nist.gov/vuln"}, hosts)
            )
            self.assertIsNone(
                pre_tool_decision(
                    workspace,
                    "Bash",
                    {"command": "curl http://127.0.0.1:17778/index.php"},
                    hosts,
                )
            )
            self.assertIsNone(
                pre_tool_decision(
                    workspace,
                    "Bash",
                    {"command": "curl http://127.0.0.8:9/ http://[::1]:9/"},
                    {"lab.example"},
                )
            )
            script = workspace / "poc" / "search.py"
            script.parent.mkdir()
            script.write_text("import urllib.request\nurllib.request.urlopen('https://cve.mitre.org/x')\n", encoding="utf-8")
            self.assertIsNotNone(pre_tool_decision(workspace, "Bash", {"command": "python poc/search.py"}, hosts))

    def test_attacker_callback_origin_is_allowed(self) -> None:
        from app.guard import pre_tool_decision

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            hosts = {"lab.example"}
            for url in ("http://attacker:8090", "http://attacker:8090/callback?x=1"):
                with self.subTest(url=url):
                    self.assertIsNone(pre_tool_decision(workspace, "Bash", {"command": f"curl {url}"}, hosts))
            for url in ("http://attacker:8091/", "https://attacker:8090/", "http://attacker:8090.example.com/"):
                with self.subTest(url=url):
                    self.assertIsNotNone(pre_tool_decision(workspace, "Bash", {"command": f"curl {url}"}, hosts))


class GatewayTests(unittest.TestCase):
    def test_candidate_urls_cover_root_and_v1(self) -> None:
        from app.gateway import candidate_urls

        self.assertEqual(
            candidate_urls(""),
            ["https://api.anthropic.com/v1/models", "https://api.anthropic.com/models"],
        )
        self.assertEqual(candidate_urls("https://gw.example/v1"), ["https://gw.example/v1/models"])
        self.assertEqual(
            candidate_urls("https://gw.example"),
            ["https://gw.example/v1/models", "https://gw.example/models"],
        )

    def test_parse_models_reads_anthropic_and_openai_shapes(self) -> None:
        from app.gateway import parse_models

        anthropic = parse_models({"data": [{"id": "claude-a", "display_name": "Claude A"}, {"id": "claude-a"}]})
        self.assertEqual(anthropic, [{"id": "claude-a", "name": "Claude A"}])
        openai = parse_models({"data": [{"id": "gpt"}]})
        self.assertEqual(openai[0]["id"], "gpt")

    def test_probe_uses_second_url_after_missing_list(self) -> None:
        from app.gateway import GatewayHTTPError, probe

        calls: list[str] = []

        def transport(url: str, api_key: str, timeout: float):
            del api_key, timeout
            calls.append(url)
            if url.endswith("/v1/models"):
                raise GatewayHTTPError(404, "missing")
            return 200, {"data": [{"id": "claude-sonnet", "display_name": "Sonnet"}]}

        result = probe("https://gw.example", "secret", transport=transport)
        self.assertTrue(result["ok"])
        self.assertEqual(result["models"][0]["id"], "claude-sonnet")
        self.assertEqual(calls, ["https://gw.example/v1/models", "https://gw.example/models"])

    def test_probe_stops_on_rejected_key(self) -> None:
        from app.gateway import GatewayHTTPError, probe

        def transport(url: str, api_key: str, timeout: float):
            del url, api_key, timeout
            raise GatewayHTTPError(401, "nope")

        result = probe("https://gw.example", "secret", transport=transport)
        self.assertFalse(result["ok"])
        self.assertIn("401", result["message"])
        self.assertEqual(result["models"], [])

    def test_probe_follows_one_extra_page(self) -> None:
        from app.gateway import probe

        def transport(url: str, api_key: str, timeout: float):
            del api_key, timeout
            if "after_id=" not in url:
                return 200, {"data": [{"id": "a"}], "has_more": True, "last_id": "a"}
            return 200, {"data": [{"id": "b"}], "has_more": False}

        result = probe("https://api.anthropic.com", "secret", transport=transport)
        self.assertEqual([item["id"] for item in result["models"]], ["a", "b"])


class ReceiptSettingsTests(unittest.TestCase):
    def test_auto_configuration_preserves_existing_settings_and_handles_failure(self) -> None:
        import app.main as main
        from app.store import Store

        image = "python@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"RECEIPT_EVIDENCE_HMAC_KEY": "", "RECEIPT_ATTACKER_IMAGE": ""}):
            store = Store(Path(directory) / "state.json")
            with mock.patch.object(main, "store", store), TestClient(main.app) as client:
                with mock.patch.object(main, "ensure_attacker_image", side_effect=RuntimeError("拉取失败")):
                    self.assertEqual(client.post("/api/receipt/settings/auto").status_code, 503)
                    self.assertEqual(store.get_receipt_settings(), {})
                with mock.patch.object(main, "ensure_attacker_image", return_value=image) as ensure:
                    response = client.post("/api/receipt/settings/auto")
                    self.assertTrue(response.json()["ready"])
                    saved = store.get_receipt_settings()
                    self.assertEqual(len(saved["evidence_hmac_key"]), 64)
                    self.assertNotIn(saved["evidence_hmac_key"], response.text)
                    client.post("/api/receipt/settings/auto")
                    self.assertEqual(store.get_receipt_settings(), saved)
                    ensure.assert_called_with(image)

    def test_image_preparation_pulls_missing_and_requires_digest(self) -> None:
        from app.receipt_settings import ensure_attacker_image
        import subprocess

        image = "python@sha256:" + "b" * 64
        missing = subprocess.CompletedProcess([], 1, "", "missing")
        pulled = subprocess.CompletedProcess([], 0, "", "")
        inspected = subprocess.CompletedProcess([], 0, json.dumps([image]), "")
        with mock.patch("app.receipt_settings.subprocess.run", side_effect=[missing, pulled, inspected]) as run:
            self.assertEqual(ensure_attacker_image(), image)
            self.assertEqual(run.call_args_list[1].args[0], ["docker", "pull", "python:3.12-slim"])
        with mock.patch("app.receipt_settings.subprocess.run", side_effect=[missing, pulled, inspected]):
            self.assertEqual(ensure_attacker_image(image), image)

    def test_settings_mask_secret_and_validate_pinned_image(self) -> None:
        import app.main as main
        from app.store import Store

        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.json")
            with mock.patch.object(main, "store", store):
                with TestClient(main.app) as client:
                    initial = client.get("/api/receipt/settings")
                    self.assertEqual(initial.status_code, 200)
                    self.assertFalse(initial.json()["has_evidence_hmac_key"])

                    rejected = client.put(
                        "/api/receipt/settings",
                        json={"evidence_hmac_key": "receipt-test-secret", "attacker_image": "example/receipt:latest"},
                    )
                    self.assertEqual(rejected.status_code, 400)

                    saved = client.put(
                        "/api/receipt/settings",
                        json={"evidence_hmac_key": "receipt-test-secret", "attacker_image": "example/receipt@sha256:" + "a" * 64},
                    )
                    self.assertEqual(saved.status_code, 200, saved.text)
                    payload = saved.json()
                    self.assertTrue(payload["ready"])
                    self.assertTrue(payload["has_evidence_hmac_key"])
                    self.assertNotIn("receipt-test-secret", json.dumps(payload))
                    self.assertEqual(store.get_receipt_settings()["evidence_hmac_key"], "receipt-test-secret")

    def test_automatic_task_start_rejects_failed_receipt_preflight(self) -> None:
        import app.main as main
        from app.store import Store

        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.json")
            task_id = "a" * 32
            store.add_task({"id": task_id, "project_id": "b" * 32, "status": "draft", "automatic_environment": True, "receipt_enabled": True})
            failed = [{"id": "receipt", "ok": False, "message": "RECEIPT 配置不可用：缺少证据签名密钥"}]
            with mock.patch.object(main, "store", store), mock.patch.object(main, "_receipt_preflight", return_value=failed), mock.patch.object(main, "_schedule_task") as schedule:
                with TestClient(main.app) as client:
                    response = client.post(f"/api/tasks/{task_id}/start")
            self.assertEqual(response.status_code, 409)
            self.assertIn("缺少证据签名密钥", response.json()["detail"])
            schedule.assert_not_called()
            self.assertEqual(store.get_task(task_id)["status"], "draft")

    def test_task_creation_requires_receipt_configuration(self) -> None:
        import app.main as main
        from app.store import Store

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = Store(root / "state.json")
            project_id = "c" * 32
            source = root / "projects" / project_id / "source"
            source.mkdir(parents=True)
            store.upsert_provider({"id": "provider", "name": "provider", "models": [{"id": "model", "input_per_mtok": 1, "output_per_mtok": 1}]})
            store.add_project({"id": project_id, "name": "project", "source_dir": str(source), "initialization": {"environment_status": "ready"}})
            with mock.patch.object(main, "store", store), mock.patch.object(main, "PROJECTS_DIR", root / "projects"), mock.patch.object(main, "WORKSPACES_DIR", root / "workspaces"):
                with TestClient(main.app) as client:
                    response = client.post(
                        "/api/tasks",
                        data={"project_id": project_id, "instruction": "audit", "provider_id": "provider", "model": "model", "budget": "1", "duration_minutes": "1", "receipt_enabled": "true"},
                    )
            self.assertEqual(response.status_code, 409)
            self.assertIn("缺少证据签名密钥", response.json()["detail"])
            self.assertEqual(store.list_tasks(), [])


class CatalogPriceTests(unittest.TestCase):
    def test_legacy_prices_are_migrated_once(self) -> None:
        import json
        import tempfile
        from pathlib import Path
        from app.store import Store

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps({"providers": [{"id": "p", "currency": "CNY", "models": [{"id": "old", "input_per_mtok": 1, "output_per_mtok": 2}]}]}), encoding="utf-8")
            store = Store(path)
            self.assertEqual(store.list_model_prices()[0]["currency"], "CNY")
            store.set_model_prices([])
            self.assertEqual(Store(path).list_model_prices(), [])

    def test_prices_accept_user_model_names_and_reject_duplicates(self) -> None:
        from fastapi import HTTPException

        from app.main import CatalogModelIn, ModelIn, match_priced_models, normalize_catalog

        catalog = normalize_catalog(
            [CatalogModelIn(id="claude-a", name="Claude A"), CatalogModelIn(id="claude-a", name="重复")]
        )
        self.assertEqual(catalog, [{"id": "claude-a", "name": "Claude A"}])
        priced = match_priced_models(
            [ModelIn(id="claude-a", input_per_mtok=1, output_per_mtok=2)],
            catalog,
        )
        self.assertEqual(priced[0]["id"], "claude-a")
        self.assertEqual(priced[0]["name"], "claude-a")
        self.assertEqual(match_priced_models([ModelIn(id="别的名字", input_per_mtok=1, output_per_mtok=2)], [])[0]["id"], "别的名字")
        with self.assertRaises(HTTPException):
            match_priced_models([ModelIn(id="a", input_per_mtok=1, output_per_mtok=2), ModelIn(id=" a ", input_per_mtok=1, output_per_mtok=2)], catalog)

    def test_endpoint_model_maps_to_independent_price_or_zero(self) -> None:
        from unittest.mock import patch
        from app.main import _selected_model

        provider = {"model": "model-a"}
        price = {"id": "model-a", "input_per_mtok": 3, "output_per_mtok": 5, "currency": "CNY"}
        with patch("app.main.store.list_model_prices", return_value=[price]):
            self.assertEqual(_selected_model(provider, "model-a"), price)
            self.assertIsNone(_selected_model(provider, "other"))
        with patch("app.main.store.list_model_prices", return_value=[]):
            selected = _selected_model(provider, "model-a")
            self.assertEqual(selected["input_per_mtok"], 0)
            self.assertEqual(selected["output_per_mtok"], 0)

    def test_currency_switches_to_cny(self) -> None:
        from app.main import normalize_currency

        self.assertEqual(normalize_currency("人民币"), "CNY")
        self.assertEqual(normalize_currency("rmb"), "CNY")
        self.assertEqual(normalize_currency("美元"), "USD")
        self.assertEqual(normalize_currency(""), "USD")


class PocFormatTests(unittest.TestCase):
    def _source(self, base: str = "http://127.0.0.1:9/", **replace: str) -> str:
        script = """from poclib import Poc

POC = Poc(
    poc_id="001-finder-query",
    marker="xss001finder",
    default_base_url="http://127.0.0.1:9/",
)

def run(ctx):
    response = ctx.request("GET", "/index.php", params={"q": ctx.marker})
    ctx.expect(ctx.marker in response.text, response.text[:500])

if __name__ == "__main__":
    POC.main(run)
"""
        script = script.replace("http://127.0.0.1:9/", base)
        for old, new in replace.items():
            script = script.replace(old, new)
        return script

    def test_common_encoding_and_crypto_modules_execute(self) -> None:
        import sys

        from app.poccheck import validate_poc
        from runtime import poclib

        source = self._source().replace(
            "from poclib import Poc",
            "import base64, json, hashlib, hmac, math\nfrom binascii import hexlify\nfrom poclib import Poc",
        ).replace(
            '    response = ctx.request("GET", "/index.php", params={"q": ctx.marker})',
            '    data = json.dumps({"q": ctx.marker}).encode()\n'
            '    digest = hashlib.pbkdf2_hmac("sha256", data, b"salt", 2)\n'
            '    encoded = base64.b64encode(hexlify(digest)).decode()\n'
            '    signature = hmac.new(digest, data, hashlib.sha256).hexdigest()\n'
            '    response = ctx.request("GET", "/index.php", params={"q": ctx.marker, "proof": encoded, "sig": signature, "n": math.floor(1.5)})',
        )
        validate_poc(source, poc_id="001-finder-query", marker="xss001finder", base_url="http://127.0.0.1:9/")
        namespace = {"__name__": "test_poc"}
        with mock.patch.dict(sys.modules, {"poclib": poclib}):
            exec(compile(source, "poc.py", "exec"), namespace)
        ctx = mock.Mock(marker="xss001finder")
        ctx.request.return_value.text = "xss001finder"
        namespace["run"](ctx)
        self.assertTrue(ctx.expect.call_args.args[0])
        self.assertTrue(ctx.request.call_args.kwargs["params"]["proof"])

    def test_rejects_blocked_imports_and_retains_poclib_rule(self) -> None:
        from app.poccheck import PocValidationError, validate_poc

        for statement in ("import socket", "import math, os", "from urllib.parse import quote", "from . import helper", "from json import *", "import poclib", "from poclib import Poc as P"):
            with self.subTest(statement=statement), self.assertRaises(PocValidationError):
                validate_poc(statement + "\n" + self._source(),
                             poc_id="001-finder-query", marker="xss001finder", base_url="http://127.0.0.1:9/")

    def test_valid_script_is_accepted_and_run_the_same_way(self) -> None:
        import asyncio

        from app.poccheck import commit_poc
        from app.poctool import build_submit_poc
        from runtime.poclib import Poc, resolve_url

        source = self._source()
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            message = commit_poc(workspace, "http://127.0.0.1:9", "001-finder-query", "xss001finder", source)
            self.assertIn("python poc/001-finder-query.py", message)
            self.assertTrue((workspace / "poc" / "001-finder-query.py").is_file())
            tool = build_submit_poc(workspace, "http://127.0.0.1:9/")
            rejected = asyncio.run(
                tool.handler({"poc_id": "001-finder-query", "marker": "xss001finder", "source": source.replace("ctx.expect", "print")})
            )
        self.assertTrue(rejected["is_error"])
        self.assertIn("ctx.expect", rejected["content"][0]["text"])
        self.assertEqual(
            resolve_url("http://127.0.0.1:9/", "/index.php"),
            "http://127.0.0.1:9/index.php",
        )
        with self.assertRaises(PermissionError):
            resolve_url("http://127.0.0.1:9/", "http://evil.test/x")

        def run(ctx):
            ctx.expect(True, "seen")

        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(io.StringIO()):
                Poc("001-finder-query", "xss001finder", "http://127.0.0.1:9/").main(run, argv=[])
        self.assertEqual(raised.exception.code, 0)

    def test_rejects_external_url_password_and_direct_write(self) -> None:
        from app.guard import command_block_reason, pre_tool_decision
        from app.poccheck import PocValidationError, validate_poc

        base = "http://127.0.0.1:9/"
        with self.assertRaises(PocValidationError) as external:
            validate_poc(
                self._source(**{"ctx.marker": '"http://evil.test/"'}),
                poc_id="001-finder-query",
                marker="xss001finder",
                base_url=base,
            )
        self.assertTrue(any("网址" in item for item in external.exception.errors))
        with self.assertRaises(PocValidationError):
            validate_poc(
                self._source() + "\npassword = 'secret'\n",
                poc_id="001-finder-query",
                marker="xss001finder",
                base_url=base,
            )
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            self.assertIsNotNone(pre_tool_decision(workspace, "Write", {"file_path": "poc/001-finder-query.py"}))
            self.assertIsNone(pre_tool_decision(workspace, "Write", {"file_path": "findings/001-finder-query.md"}))
        self.assertIsNotNone(command_block_reason("echo x > poc/001-finder-query.py"))
        self.assertIsNone(command_block_reason("python poc/001-finder-query.py"))

    def test_start_receipt_verifies_one_registered_candidate(self) -> None:
        from app.poctool import build_start_receipt, build_submit_poc
        from app.receipt import load_receipt_candidate

        victim = json.dumps({"url": "/index.php?q={{receipt_token}}", "actions": []})
        claim = json.dumps({"finding_type": "reflected_xss"})
        submit_args = {
            "poc_id": "001-finder-query",
            "marker": "xss001finder",
            "source": self._source(),
            "victim_json": victim,
            "attacker_login_json": "",
            "claim_json": claim,
        }
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            verified: list[str] = []
            submit_poc = build_submit_poc(workspace, "http://127.0.0.1:9/", receipt_enabled=True)
            self.assertEqual(submit_poc.input_schema["required"], ["poc_id", "marker", "source"])
            missing_victim = asyncio.run(submit_poc.handler({"poc_id": "001-finder-query", "marker": "xss001finder", "source": "placeholder"}))
            self.assertTrue(missing_victim["is_error"])
            self.assertIn("缺少 victim_json", missing_victim["content"][0]["text"])
            placeholder = asyncio.run(submit_poc.handler({**submit_args, "source": "placeholder"}))
            self.assertTrue(placeholder["is_error"])
            self.assertIn("source 不能是 placeholder", placeholder["content"][0]["text"])
            self.assertFalse((workspace / "receipt" / "candidates" / "001-finder-query.json").exists())
            saved = asyncio.run(submit_poc.handler(submit_args))
            self.assertNotIn("is_error", saved)
            self.assertFalse((workspace / "receipt" / "poc-manifest.json").exists())
            self.assertTrue((workspace / "poc" / "001-finder-query.py").is_file())
            self.assertTrue((workspace / "receipt" / "candidates" / "001-finder-query.json").is_file())

            invalid = asyncio.run(submit_poc.handler({**submit_args, "victim_json": "[]"}))
            self.assertTrue(invalid["is_error"])
            self.assertIn("victim_json", invalid["content"][0]["text"])

            async def verify_candidate(poc_id: str, report_path: str) -> dict[str, str]:
                self.assertEqual(report_path, "findings/001-finding.md")
                verified.append(poc_id)
                candidate = load_receipt_candidate(workspace, poc_id, base_url="http://127.0.0.1:9/")
                self.assertEqual(candidate.attacker_script, self._source().strip())
                (workspace / "poc" / "001-finder-query.py").write_text("changed after submission", encoding="utf-8")
                return {"poc_id": poc_id, "verdict": "REJECTED", "reason": "NO_BROWSER_BOUND_RECEIPT", "reason_description": "The victim browser did not receive a valid execution receipt."}

            tool = build_start_receipt(workspace, "http://127.0.0.1:9/", verify_candidate=verify_candidate)
            args = {"poc_id": "001-finder-query", "report_path": "findings/001-finding.md"}
            accepted = asyncio.run(tool.handler(args))
            self.assertNotIn("is_error", accepted)
            self.assertEqual(verified, ["001-finder-query"])
            self.assertIn('"verdict":"REJECTED"', accepted["content"][0]["text"])
            self.assertEqual(load_receipt_candidate(workspace, "001-finder-query", base_url="http://127.0.0.1:9/").attacker_script, self._source().strip())
            from app.reports import _load_reviews
            self.assertEqual(_load_reviews(workspace)["findings/001-finding.md"]["verdict"], "REJECTED")

            missing = asyncio.run(tool.handler({"poc_id": "002-missing", "report_path": "findings/002-missing.md"}))
            self.assertTrue(missing["is_error"])
            self.assertEqual(verified, ["001-finder-query"])
            self.assertNotIn("findings/002-missing.md", _load_reviews(workspace))

            async def broken_verifier(poc_id: str, report_path: str) -> dict[str, str]:
                raise RuntimeError("sensitive exception detail")

            failing_tool = build_start_receipt(workspace, "http://127.0.0.1:9/", verify_candidate=broken_verifier)
            failed = asyncio.run(failing_tool.handler(args))
            self.assertNotIn("is_error", failed)
            self.assertIn('"reason":"VERIFICATION_INFRASTRUCTURE_ERROR"', failed["content"][0]["text"])
            self.assertIn('"reason_description":"The verification infrastructure encountered an error."', failed["content"][0]["text"])
            self.assertNotIn("sensitive exception detail", failed["content"][0]["text"])
            self.assertEqual(_load_reviews(workspace)["findings/001-finding.md"]["verdict"], "INDETERMINATE")

            from app.reports import save_review
            save_review(workspace, "findings/001-finding.md", "001-finder-query", "ACCEPTED")
            revised = asyncio.run(submit_poc.handler(submit_args))
            self.assertNotIn("is_error", revised)
            self.assertIsNone(_load_reviews(workspace)["findings/001-finding.md"]["verdict"])

    def test_start_receipt_limits_each_poc_across_tool_instances(self) -> None:
        from app.poctool import build_start_receipt, build_submit_poc

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            submit = build_submit_poc(workspace, "http://127.0.0.1:9/", receipt_enabled=True)
            candidate = {"poc_id": "001-demo", "marker": "xss001demo", "source": "", "victim_json": json.dumps({"url": "/?q={{receipt_token}}", "actions": []})}
            self.assertNotIn("is_error", asyncio.run(submit.handler(candidate)))
            calls = []

            async def verify(poc_id: str, report_path: str) -> dict:
                calls.append(poc_id)
                return {"poc_id": poc_id, "verdict": "INDETERMINATE", "reason": "TEST"}

            args = {"poc_id": "001-demo", "report_path": "findings/001-demo.md"}
            for remaining in range(4, -1, -1):
                tool = build_start_receipt(workspace, "http://127.0.0.1:9/", verify_candidate=verify)
                result = asyncio.run(tool.handler(args))
                self.assertIn(f'"remaining_verifications":{remaining}', result["content"][0]["text"])
            self.assertNotIn("is_error", asyncio.run(submit.handler(candidate)))
            result = asyncio.run(tool.handler({**args, "report_path": "findings/002-other.md"}))
            self.assertTrue(result["is_error"])
            self.assertIn("剩余验证次数：0", result["content"][0]["text"])
            self.assertEqual(len(calls), 5)

            other = {**candidate, "poc_id": "002-demo", "marker": "xss002demo"}
            self.assertNotIn("is_error", asyncio.run(submit.handler(other)))
            result = asyncio.run(tool.handler({"poc_id": "002-demo", "report_path": "findings/002-demo.md"}))
            self.assertIn('"remaining_verifications":4', result["content"][0]["text"])

    def test_receipt_verify_api_replays_accepted_report(self) -> None:
        from app import main
        from app.reports import save_review

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            save_review(workspace, "findings/001-finding.md", "001-finder-query", "ACCEPTED")
            task = {"workspace": str(workspace), "base_url": "http://127.0.0.1:9/", "receipt_enabled": True, "receipt_manifest": "trusted.json"}
            store = mock.Mock()
            store.get_task.return_value = task
            store.recover_interrupted.return_value = []
            store.list_tasks.return_value = []
            store.list_projects.return_value = []
            with mock.patch.object(main, "store", store), mock.patch.object(main, "verify_receipt_candidate") as verify, \
                    mock.patch("app.runner._emit") as emit:
                verify.return_value = mock.Mock(result={"verdict": "REJECTED"}, artifact="receipt/results/test.json", agent_feedback={"verdict": "REJECTED"})
                with TestClient(main.app) as client:
                    response = client.post("/api/tasks/example/receipt/verify", json={"poc_id": "001-finder-query"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["feedback"]["verdict"], "REJECTED")
            self.assertIn("本次不执行验证", emit.call_args.args[4])
            verify.assert_called_once()
            from app.reports import _load_reviews
            self.assertEqual(_load_reviews(workspace)["findings/001-finding.md"]["verdict"], "REJECTED")


class PromptTests(unittest.TestCase):
    def test_prompts_are_files_and_not_embedded(self) -> None:
        from app.prompts import load, render

        system = load("system.md")
        self.assertIn("XSS", system)
        rendered_system = render(
            "system.md",
            {
                "receipt_protocol": "验证器已关闭",
                "shell_protocol": "- 不允许执行环境命令。",
                "project_execution_protocol": "- 不执行项目。",
                "network_protocol": "- 不联网。",
            },
        )
        self.assertNotIn("{{", rendered_system)
        rendered = render(
            "task-brief.md",
            {
                "base_url": "http://127.0.0.1:9/",
                "project_name": "demo",
                "instruction": "只看搜索框 {{base_url}}",
                "workspace": "W",
                "source_dir": "S",
                "budget": "1",
                "duration": "60",
                "currency": "USD",
                "input_price": "3",
                "output_price": "15",
                "model": "demo",
                "provider_name": "local",
            },
        )
        self.assertIn("http://127.0.0.1:9/", rendered)
        self.assertIn("{{base_url}}", rendered)
        self.assertNotIn("{{instruction}}", rendered)
        app_dir = Path(__file__).resolve().parents[1] / "app"
        blob = "\n".join(path.read_text(encoding="utf-8") for path in app_dir.glob("*.py"))
        self.assertNotIn("你是 Joomla 5.4.5 核心的 XSS 审计代理", blob)

    def test_resume_prompt_only_lists_summary_and_findings_paths(self) -> None:
        from app.prompts import render

        rendered = render(
            "run-resume.md",
            {
                "previous_summary_path": "notes/round-001-summary.md",
                "summary_path": "notes/round-002-summary.md",
                "findings": "- findings/001-demo.md",
                "spent": "9.0000",
                "budget_remaining": "1.0000",
                "time_remaining": "60",
                "currency": "CNY",
            },
        )
        self.assertIn("notes/round-001-summary.md", rendered)
        self.assertIn("notes/round-002-summary.md", rendered)
        self.assertIn("findings/001-demo.md", rendered)
        self.assertNotIn("预算", rendered)
        self.assertNotIn("时长", rendered)
        self.assertNotIn("CNY", rendered)
        self.assertNotIn("9.0000", rendered)

    def test_round_summary_must_exist_and_be_nonempty(self) -> None:
        from app.runner import _restored_active_round, _round_summary_path, _round_summary_ready

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            path = _round_summary_path(workspace, 7)
            self.assertEqual(path, workspace / "notes" / "round-007-summary.md")
            self.assertFalse(_round_summary_ready(workspace, 7))
            path.parent.mkdir()
            path.write_text("  \n", encoding="utf-8")
            self.assertFalse(_round_summary_ready(workspace, 7))
            path.write_text("# 第 7 轮总结\n", encoding="utf-8")
            self.assertTrue(_round_summary_ready(workspace, 7))
            self.assertIsNone(_restored_active_round(workspace, 7))

    def test_missing_summary_restores_current_round(self) -> None:
        from app.runner import _restored_active_round

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            self.assertEqual(_restored_active_round(workspace, 7), 7)
            self.assertIsNone(_restored_active_round(workspace, 0))


class EventWindowTests(unittest.TestCase):
    def test_round_logs_survive_pause_and_keep_history_pageable(self) -> None:
        from app.store import Store, read_events

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workspace = root / "workspace"
            store = Store(root / "state.json")
            store.add_task({"id": "task", "workspace": str(workspace), "status": "running", "round": 0, "next_seq": 1})
            store.append_event("task", {"type": "status", "text": "启动"})
            store.update_task("task", round=1)
            store.append_event("task", {"type": "round", "text": "第一轮"})
            store.update_task("task", status="paused")
            store.append_event("task", {"type": "status", "text": "暂停"})
            store = Store(root / "state.json")
            store.update_task("task", status="running")
            store.append_event("task", {"type": "status", "text": "继续"})
            store.update_task("task", round=2)
            store.append_event("task", {"type": "round", "text": "第二轮"})

            first = workspace / "logs" / "round-001.jsonl"
            second = workspace / "logs" / "round-002.jsonl"
            self.assertEqual([json.loads(line)["seq"] for line in first.read_text(encoding="utf-8").splitlines()], [2, 3, 4])
            self.assertEqual([json.loads(line)["seq"] for line in second.read_text(encoding="utf-8").splitlines()], [5])
            self.assertEqual([event["seq"] for event in read_events(workspace, 0)], [1, 2, 3, 4, 5])
            self.assertEqual([event["seq"] for event in read_events(workspace, 0, limit=2, before=5)], [3, 4])

    def test_read_events_keeps_only_the_latest_window(self) -> None:
        from app.store import read_events

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            path = workspace / "events.jsonl"
            path.write_text(
                "\n".join(f'{{"seq": {index}, "type": "text", "text": "n{index}"}}' for index in range(1, 6)),
                encoding="utf-8",
            )
            latest = read_events(workspace, 0, limit=2)
            self.assertEqual([item["seq"] for item in latest], [4, 5])
            self.assertEqual([item["seq"] for item in read_events(workspace, 3)], [4, 5])
            older = read_events(workspace, 0, limit=2, before=4)
            self.assertEqual([item["seq"] for item in older], [2, 3])


if __name__ == "__main__":
    unittest.main()
