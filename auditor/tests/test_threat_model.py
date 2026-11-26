from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app.threat_model import evaluate_threat_model


def write_closed_model(
    environment: Path,
    source: Path,
    attacker: str = "a",
    victim: str = "b",
    path_id: str = "a-to-b",
    scope: str = "demo",
) -> dict:
    """Write a two-role model that projects to one manifest path."""

    source.mkdir(parents=True, exist_ok=True)
    (source / "roles.js").write_text(f'const roles = ["{attacker}", "{victim}"];\n', encoding="utf-8")
    evidence = {"kind": "source", "path": "roles.js", "literal": attacker}
    inventory = {
        "roles": [
            {"id": attacker, "literal": attacker, "scope": scope},
            {"id": victim, "literal": victim, "scope": scope},
        ],
    }
    decisions = {
        "roles": [
            {"id": attacker, "disposition": "include", "reason": "可以写入对方可见的内容", "evidence": {"kind": "source", "path": "roles.js", "literal": attacker}},
            {"id": victim, "disposition": "victim_only", "reason": "作为同作用域受害者", "evidence": {"kind": "source", "path": "roles.js", "literal": victim}},
        ],
        "victims": [{"role_id": victim, "account_id": victim, "scope": scope}],
        "paths": [{
            "id": path_id,
            "attacker_role": attacker,
            "victim_role": victim,
            "attacker_account": attacker,
            "victim_account": victim,
            "scope": scope,
            "primary": True,
            "accept_self_xss": False,
        }],
        "boundaries": [],
    }
    plan = {"accounts": [
        {"account_id": attacker, "role_id": attacker, "scope": scope, "extra_privileges": []},
        {"account_id": victim, "role_id": victim, "scope": scope, "extra_privileges": []},
    ]}
    environment.mkdir(parents=True, exist_ok=True)
    (environment / "role-inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
    (environment / "threat-decisions.json").write_text(json.dumps(decisions), encoding="utf-8")
    (environment / "account-plan.json").write_text(json.dumps(plan), encoding="utf-8")
    (environment / "create-accounts.py").write_text('ACCOUNT_PLAN = "account-plan.json"\n', encoding="utf-8")
    return {
        "target": {"id": "demo", "version": "1", "image_digest": "demo"},
        "adapter": "demo",
        "allowed_origins": ["{{target_origin}}"],
        "principals": [{"id": attacker}, {"id": victim}],
        "threat_paths": [{
            "id": path_id,
            "attacker_principal": attacker,
            "victim_principal": victim,
            "primary": True,
            "accept_self_xss": False,
        }],
        "extension_path_budget": 0,
    }


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


class ThreatModelTests(unittest.TestCase):
    def test_excluded_role_cannot_participate_and_assumption_needs_no_review(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            environment, source = root / "environment", root / "source"
            manifest = write_closed_model(environment, source)
            _write(environment / "receipt-manifest.json", manifest)
            decisions = json.loads((environment / "threat-decisions.json").read_text(encoding="utf-8"))
            decisions["roles"][1].update(disposition="exclude", evidence={"kind": "assumption", "path": "", "literal": "不参与"})
            _write(environment / "threat-decisions.json", decisions)
            report = evaluate_threat_model(environment, source)
            self.assertFalse(report.ok)
            self.assertTrue(any("候选受害者" in message and "排除" in message for message in report.messages), report.messages)
            self.assertFalse(any(item["code"] == "assumption" for item in report.review_items))

            decisions["victims"] = []
            decisions["boundaries"] = [{"attacker_role": "b", "victim_role": "a", "scope": "demo", "reason": "不适用", "evidence": {"kind": "source", "path": "roles.js", "literal": "b"}}]
            _write(environment / "threat-decisions.json", decisions)
            report = evaluate_threat_model(environment, source)
            self.assertTrue(any("无边界说明" in message and "排除" in message for message in report.messages), report.messages)
            self.assertTrue(any("受害者不在候选列表" in message for message in report.messages), report.messages)

    def test_excluded_assumption_keeps_closed_model_without_review(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            environment, source = root / "environment", root / "source"
            manifest = write_closed_model(environment, source)
            _write(environment / "receipt-manifest.json", manifest)
            (source / "roles.js").write_text('const roles = ["a", "b", "c"];\n', encoding="utf-8")
            inventory = json.loads((environment / "role-inventory.json").read_text(encoding="utf-8"))
            inventory["roles"].append({"id": "c", "literal": "c", "scope": "demo"})
            _write(environment / "role-inventory.json", inventory)
            decisions = json.loads((environment / "threat-decisions.json").read_text(encoding="utf-8"))
            decisions["roles"].append({"id": "c", "disposition": "exclude", "reason": "不参与", "evidence": {"kind": "assumption", "path": "", "literal": "不参与"}})
            _write(environment / "threat-decisions.json", decisions)
            report = evaluate_threat_model(environment, source)
            self.assertTrue(report.ok, report.messages)
            self.assertEqual(report.coverage_status, "closed")
            self.assertEqual(report.review_items, [])

    def test_closed_model_matches_manifest_projection(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            environment = root / "environment"
            manifest = write_closed_model(environment, root / "source")
            _write(environment / "receipt-manifest.json", manifest)
            report = evaluate_threat_model(environment, root / "source")
            self.assertTrue(report.ok, report.messages)
            self.assertEqual(report.coverage_status, "closed")
            self.assertEqual(report.review_items, [])
            self.assertTrue(report.digest)

    def test_legacy_inventory_data_does_not_affect_model_or_digest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            environment = root / "environment"
            manifest = write_closed_model(environment, root / "source")
            _write(environment / "receipt-manifest.json", manifest)
            current = evaluate_threat_model(environment, root / "source")
            inventory = json.loads((environment / "role-inventory.json").read_text(encoding="utf-8"))
            inventory["clusters"] = [{"invalid": "legacy data"}]
            _write(environment / "role-inventory.json", inventory)
            legacy = evaluate_threat_model(environment, root / "source")
            self.assertTrue(legacy.ok, legacy.messages)
            self.assertEqual(current.digest, legacy.digest)
            self.assertEqual(current.review_items, legacy.review_items)

    def test_assumption_remains_reviewable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            environment = root / "environment"
            source = root / "source"
            manifest = write_closed_model(environment, source)
            _write(environment / "receipt-manifest.json", manifest)
            decisions = json.loads((environment / "threat-decisions.json").read_text(encoding="utf-8"))
            decisions["roles"][0]["evidence"] = {"kind": "assumption", "path": "", "literal": "权限表未写明该边界"}
            _write(environment / "threat-decisions.json", decisions)
            assumed = evaluate_threat_model(environment, source)
            self.assertTrue(assumed.ok, assumed.messages)
            self.assertEqual(assumed.coverage_status, "review_required")
            self.assertTrue(any(item["code"] == "assumption" for item in assumed.review_items))

    def test_manifest_drift_same_account_and_budget_are_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            environment = root / "environment"
            manifest = write_closed_model(environment, root / "source")
            manifest["threat_paths"][0]["attacker_principal"] = "missing"
            _write(environment / "receipt-manifest.json", manifest)
            report = evaluate_threat_model(environment, root / "source")
            self.assertFalse(report.ok)
            self.assertTrue(any("投影" in message or "身份" in message or "路径" in message for message in report.messages))

            manifest = write_closed_model(environment, root / "source")
            decisions = json.loads((environment / "threat-decisions.json").read_text(encoding="utf-8"))
            decisions["paths"][0]["attacker_account"] = "b"
            decisions["paths"][0]["accept_self_xss"] = False
            _write(environment / "threat-decisions.json", decisions)
            same_account = evaluate_threat_model(environment, root / "source")
            self.assertTrue(any("同一个账号" in message for message in same_account.messages), same_account.messages)

            manifest = write_closed_model(environment, root / "source", path_id="primary-path")
            decisions = json.loads((environment / "threat-decisions.json").read_text(encoding="utf-8"))
            decisions["roles"].append({
                "id": "c",
                "disposition": "include",
                "reason": "另一写入角色",
                "evidence": {"kind": "source", "path": "roles.js", "literal": "b"},
            })
            manifest["extension_path_budget"] = 0
            _write(environment / "receipt-manifest.json", manifest)
            inventory = json.loads((environment / "role-inventory.json").read_text(encoding="utf-8"))
            (root / "source" / "roles.js").write_text('const roles = ["a", "b", "c"];\n', encoding="utf-8")
            inventory["roles"].append({"id": "c", "literal": "c", "scope": "demo"})
            decisions["victims"].append({"role_id": "c", "account_id": "c", "scope": "demo"})
            decisions["paths"].append({
                "id": "c-to-b",
                "attacker_role": "c",
                "victim_role": "b",
                "attacker_account": "c",
                "victim_account": "b",
                "scope": "demo",
                "primary": False,
                "accept_self_xss": False,
            })
            decisions["boundaries"] = []
            _write(environment / "role-inventory.json", inventory)
            _write(environment / "threat-decisions.json", decisions)
            plan = json.loads((environment / "account-plan.json").read_text(encoding="utf-8"))
            plan["accounts"].append({"account_id": "c", "role_id": "c", "scope": "demo", "extra_privileges": []})
            _write(environment / "account-plan.json", plan)
            under_budget = evaluate_threat_model(environment, root / "source")
            self.assertFalse(any("extension_path_budget" in message for message in under_budget.messages), under_budget.messages)

    def test_missing_matrix_cell_blocks_until_a_boundary_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            environment = root / "environment"
            manifest = write_closed_model(environment, root / "source")
            (root / "source" / "roles.js").write_text('const roles = ["a", "b", "c"];\n', encoding="utf-8")
            inventory = json.loads((environment / "role-inventory.json").read_text(encoding="utf-8"))
            inventory["roles"].append({"id": "c", "literal": "c", "scope": "demo"})
            decisions = json.loads((environment / "threat-decisions.json").read_text(encoding="utf-8"))
            decisions["roles"].append({
                "id": "c",
                "disposition": "victim_only",
                "reason": "另一名同作用域用户",
                "evidence": {"kind": "source", "path": "roles.js", "literal": "c"},
            })
            decisions["victims"].append({"role_id": "c", "account_id": "c", "scope": "demo"})
            _write(environment / "role-inventory.json", inventory)
            _write(environment / "threat-decisions.json", decisions)
            _write(environment / "receipt-manifest.json", manifest)
            open_cell = evaluate_threat_model(environment, root / "source")
            self.assertTrue(any("a → c" in message for message in open_cell.messages), open_cell.messages)

            decisions["boundaries"] = [{
                "attacker_role": "a",
                "victim_role": "c",
                "scope": "demo",
                "reason": "该受害者看不到 a 写入的资源",
                "evidence": {"kind": "source", "path": "roles.js", "literal": "c"},
            }]
            _write(environment / "threat-decisions.json", decisions)
            closed = evaluate_threat_model(environment, root / "source")
            self.assertTrue(closed.ok, closed.messages)

    def test_digest_ignores_key_order_and_changes_when_a_reason_changes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            environment = root / "environment"
            manifest = write_closed_model(environment, root / "source")
            _write(environment / "receipt-manifest.json", manifest)
            first = evaluate_threat_model(environment, root / "source")
            decisions = json.loads((environment / "threat-decisions.json").read_text(encoding="utf-8"))
            _write(environment / "threat-decisions.json", {key: decisions[key] for key in reversed(list(decisions))})
            second = evaluate_threat_model(environment, root / "source")
            self.assertEqual(first.digest, second.digest)
            decisions["roles"][0]["reason"] = "另一条理由"
            _write(environment / "threat-decisions.json", decisions)
            third = evaluate_threat_model(environment, root / "source")
            self.assertNotEqual(first.digest, third.digest)

    def test_acknowledgement_digest_tracks_boundary_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            environment = root / "environment"
            manifest = write_closed_model(environment, root / "source")
            _write(environment / "receipt-manifest.json", manifest)
            closed = evaluate_threat_model(environment, root / "source")
            decisions = json.loads((environment / "threat-decisions.json").read_text(encoding="utf-8"))
            decisions["boundaries"] = [{
                "attacker_role": "a",
                "victim_role": "b",
                "scope": "demo",
                "reason": "另一条资料来源",
                "evidence": {"kind": "source", "path": "roles.js", "literal": "b"},
            }]
            _write(environment / "threat-decisions.json", decisions)
            sourced = evaluate_threat_model(environment, root / "source")
            self.assertTrue(sourced.ok, sourced.messages)
            decisions["boundaries"][0]["evidence"] = {"kind": "assumption", "path": "", "literal": "资料不足"}
            _write(environment / "threat-decisions.json", decisions)
            assumed = evaluate_threat_model(environment, root / "source")
            self.assertNotEqual(sourced.digest, assumed.digest)
            self.assertEqual(assumed.coverage_status, "review_required")
