from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import ModuleType

from app.process_bounds import StepTimeout, browser_runs_inprocess, run_bounded, supervise
from app.receipt import PathResult, ReceiptResult, ReceiptVerdict
from app.receipt_execution import receipt_agent_feedback


class ProcessBoundTests(unittest.TestCase):
    def test_command_timeout_names_the_step_and_returns(self) -> None:
        started = time.monotonic()
        with self.assertRaises(StepTimeout) as caught:
            run_bounded([sys.executable, "-c", "import time; time.sleep(30)"], 1, "python start.py")
        self.assertEqual(caught.exception.step, "python start.py")
        self.assertLess(time.monotonic() - started, 8)

    def test_browser_supervision_reports_the_stuck_step(self) -> None:
        script = (
            "import json,sys,time; "
            "json.dump({'step':'victim_login.click','index':2,'started':time.time()}, open(sys.argv[1],'w')); "
            "time.sleep(30)"
        )
        with tempfile.TemporaryDirectory() as raw:
            step_file = Path(raw) / "step.json"
            proc = subprocess.Popen([sys.executable, "-c", script, str(step_file)])
            started = time.monotonic()
            try:
                outcome = supervise(proc, step_file, 1)
            finally:
                if proc.poll() is None:
                    proc.kill()
            self.assertLess(time.monotonic() - started, 8)
            self.assertTrue(outcome["timeout"])
            self.assertEqual(outcome["step"], "victim_login.click")
            self.assertEqual(outcome["index"], 2)
            self.assertIsNotNone(proc.poll())

    def test_feedback_includes_login_and_browser_steps(self) -> None:
        attacker = ReceiptResult(
            "c", "m",
            PathResult("path", ReceiptVerdict.REJECTED, "ATTACKER_LOGIN_FAILED", evidence={
                "attacker_error": {"stage": "attacker_login", "step": "attacker_login.click", "index": 2, "timeout_seconds": 60},
            }),
            (), "sig",
        )
        attacker_feedback = receipt_agent_feedback("poc", attacker)
        self.assertIn("Step: attacker_login.click.", attacker_feedback["reason_description"])
        self.assertIn("Step index: 2.", attacker_feedback["reason_description"])
        self.assertIn("Timeout: 60 seconds.", attacker_feedback["reason_description"])

        browser = ReceiptResult(
            "c", "m",
            PathResult("path", ReceiptVerdict.INDETERMINATE, "BROWSER_ERROR", evidence={
                "browser_error": {"stage": "victim_login", "type": "playwright_timeout", "step": "victim_login.click", "step_index": 2},
            }),
            (), "sig",
        )
        browser_feedback = receipt_agent_feedback("poc", browser)
        self.assertIn("Step: victim_login.click.", browser_feedback["reason_description"])
        self.assertIn("Step index: 2.", browser_feedback["reason_description"])

    def test_patched_playwright_stays_in_process(self) -> None:
        api = ModuleType("playwright.sync_api")
        api.sync_playwright = lambda: None  # type: ignore[attr-defined]
        import sys as system
        previous = system.modules.get("playwright.sync_api")
        system.modules["playwright.sync_api"] = api
        try:
            self.assertTrue(browser_runs_inprocess())
        finally:
            if previous is None:
                system.modules.pop("playwright.sync_api", None)
            else:
                system.modules["playwright.sync_api"] = previous


if __name__ == "__main__":
    unittest.main()
