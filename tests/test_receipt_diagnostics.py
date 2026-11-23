from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import receipt_diagnostics as diagnostics
from app.generic_receipt_adapter import _run
from app.process_bounds import StepTimeout
from app.receipt import ReceiptError, ReceiptVerifier, ReceiptVerdict
from app.receipt_execution import receipt_agent_feedback
from test_receipt import _Adapter, _Attacker, _Browser, _candidate, _manifest


class ReceiptDiagnosticsTests(unittest.TestCase):
    def test_command_failure_records_exit_and_redacts_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tokens = diagnostics.begin(root)
            try:
                diagnostics.add_secrets("private-value")
                failure = subprocess.CompletedProcess([], 17, "", "connection refused\nprivate-value\npassword=abc")
                with patch("app.generic_receipt_adapter.run_bounded", return_value=failure):
                    with self.assertRaisesRegex(ReceiptError, "退出码 17"):
                        _run(["python", "start.py"], root, {"RECEIPT_RUN_ID": "abc"}, 30)
                entry = json.loads((root / "receipt" / "diagnostics.jsonl").read_text(encoding="utf-8"))
                self.assertEqual(entry["exit_code"], 17)
                self.assertIn("connection refused", entry["stderr"])
                self.assertNotIn("private-value", entry["stderr"])
                self.assertNotIn("password=abc", entry["stderr"])
            finally:
                diagnostics.end(tokens)

    def test_adapter_error_contains_stage_and_logs_cause(self) -> None:
        class BrokenAdapter(_Adapter):
            def open_run(self, *args):
                raise ReceiptError("环境命令 python start.py 退出码 17")

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tokens = diagnostics.begin(root)
            try:
                result = ReceiptVerifier(adapter=BrokenAdapter(), attacker=_Attacker(), browser=_Browser(), receipt_key=b"k" * 32).verify(
                    _candidate(), _manifest(extension_path_budget=0), preferred_path_ids=("author-to-admin",))
                self.assertEqual(result.verdict, ReceiptVerdict.INDETERMINATE)
                self.assertEqual(result.primary.evidence["error"]["stage"], "adapter_open")
                self.assertIn("退出码 17", receipt_agent_feedback("poc", result)["reason_description"])
                self.assertIn("退出码 17", (root / "receipt" / "diagnostics.jsonl").read_text(encoding="utf-8"))
            finally:
                diagnostics.end(tokens)

    def test_command_timeout_records_limit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tokens = diagnostics.begin(root)
            try:
                with patch("app.generic_receipt_adapter.run_bounded", side_effect=StepTimeout("python start.py", 12)):
                    with self.assertRaisesRegex(ReceiptError, "超时（12 秒）"):
                        _run(["python", "start.py"], root, {"RECEIPT_RUN_ID": "abc"}, 12)
                entry = json.loads((root / "receipt" / "diagnostics.jsonl").read_text(encoding="utf-8"))
                self.assertEqual(entry["timeout_seconds"], 12)
                self.assertEqual(entry["step"], "python start.py")
                self.assertIn("StepTimeout", entry["error"])
            finally:
                diagnostics.end(tokens)
