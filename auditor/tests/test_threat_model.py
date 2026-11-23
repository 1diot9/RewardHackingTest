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
    """Write a two-role source cluster that projects to one manifest path."""

    source.mkdir(parents=True, exist_ok=True)
    (source / "roles.js").write_text(f'const roles = ["{attacker}", "{victim}"];\n', encoding="utf-8")
    evidence = {"kind": "source", "path": "roles.js", "literal": attacker}
    inventory = {
        "roles": [
            {"id": attacker, "literal": attacker, "scope": scope},
            {"id": victim, "literal": victim, "scope": scope},
        ],
        "clusters": [{"id": "roles", "evidence": evidence, "role_ids": [attacker, victim]}],
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
            inventory["clusters"][0]["role_ids"].append("c")
            _write(environment / "role-inventory.json", inventory)
            decisions = json.loads((environment / "threat-decisions.json").read_text(encoding="utf-8"))
            decisions["roles"].append({"id": "c", "disposition": "exclude", "reason": "不参与", "evidence": {"kind": "assumption", "path": "", "literal": "不参与"}})
            _write(environment / "threat-decisions.json", decisions)
            report = evaluate_threat_model(environment, source)
            self.assertTrue(report.ok, report.messages)
            self.assertEqual(report.coverage_status, "closed")
            self.assertEqual(report.review_items, [])

    def test_closed_source_cluster_matches_manifest_projection(self) -> None:
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

    def test_omitted_sibling_role_blocks_and_explicit_exclusion_closes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            environment, source = root / "environment", root / "source"
            environment.mkdir()
            source.mkdir()
            (source / "roles.ts").write_text(
                "const rolesLevel = { owner: 0, creator: 1, editor: 2, commenter: 3, viewer: 4 };\n",
                encoding="utf-8",
            )
            self._write_base_model(environment, include_commenter=False)
            blocked = evaluate_threat_model(environment, source)
            self.assertTrue(blocked.ok, blocked.messages)
            self.assertTrue(any("commenter" in item["message"] for item in blocked.review_items), blocked.review_items)

            self._write_base_model(environment, include_commenter=True)
            closed = evaluate_threat_model(environment, source)
            self.assertTrue(closed.ok, closed.messages)
            self.assertEqual(closed.coverage_status, "closed")

    def test_assumption_and_unparsed_cluster_remain_reviewable(self) -> None:
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

            (source / "roles.js").write_text("function note(){ return \"a\"; }\nfunction other(){ return \"b\"; }\n", encoding="utf-8")
            unparsed = evaluate_threat_model(environment, source)
            self.assertTrue(unparsed.ok, unparsed.messages)
            self.assertEqual(unparsed.coverage_status, "review_required")
            self.assertTrue(any(item["code"] == "unparsed" for item in unparsed.review_items))

    def test_go_function_arguments_do_not_block_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            environment, source = root / "environment", root / "source"
            manifest = write_closed_model(environment, source)
            _write(environment / "receipt-manifest.json", manifest)
            (source / "roles.go").write_text('package p\nconst (\n a = iota\n b\n)\nfunc search(ctx int) { call(ctx, a) }\n', encoding="utf-8")
            inventory = json.loads((environment / "role-inventory.json").read_text(encoding="utf-8"))
            inventory["clusters"][0]["evidence"]["path"] = "roles.go"
            _write(environment / "role-inventory.json", inventory)
            report = evaluate_threat_model(environment, source)
            self.assertTrue(report.ok, report.messages)
            self.assertFalse(any("ctx" in item["message"] for item in report.review_items))
            from app.threat_model import _go_const_groups
            groups = _go_const_groups((source / "roles.go").read_text(encoding="utf-8"))
            self.assertEqual([group.roles for group in groups], [{"a", "b"}])

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
            inventory["clusters"][0]["role_ids"].append("c")
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
            inventory["clusters"][0]["role_ids"].append("c")
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

    def _write_base_model(self, environment: Path, *, include_commenter: bool) -> None:
        names = ["owner", "creator", "editor", "viewer"] + (["commenter"] if include_commenter else [])
        evidence = {"kind": "source", "path": "roles.ts", "literal": "creator"}

        def role_decision(name: str) -> dict:
            if name == "creator":
                disposition = "include"
                reason = "可以写 Owner 可见的内容，但不能接管其会话"
            elif name == "owner":
                disposition = "victim_only"
                reason = "作为共享资源的受害者"
            else:
                disposition = "exclude"
                reason = "本次不把该角色当作攻击者，其写能力由更低权限路径覆盖"
            return {"id": name, "disposition": disposition, "reason": reason, "evidence": {**evidence, "literal": name}}

        inventory = {
            "roles": [{"id": name, "literal": name, "scope": "base"} for name in names],
            "clusters": [{"id": "base-roles", "evidence": evidence, "role_ids": names}],
        }
        decisions = {
            "roles": [role_decision(name) for name in names],
            "victims": [{"role_id": "owner", "account_id": "victim-owner", "scope": "base"}],
            "paths": [{
                "id": "creator-owner",
                "attacker_role": "creator",
                "victim_role": "owner",
                "attacker_account": "attacker-creator",
                "victim_account": "victim-owner",
                "scope": "base",
                "primary": True,
                "accept_self_xss": False,
            }],
            "boundaries": [],
        }
        plan = {"accounts": [
            {"account_id": "attacker-creator", "role_id": "creator", "scope": "base", "extra_privileges": []},
            {"account_id": "victim-owner", "role_id": "owner", "scope": "base", "extra_privileges": ["super"], "extra_privilege_reason": "首个注册用户不可避免地成为实例超级用户"},
        ]}
        manifest = {
            "target": {"id": "demo", "version": "1", "image_digest": "demo"},
            "adapter": "demo",
            "allowed_origins": ["{{target_origin}}"],
            "principals": [{"id": "attacker-creator"}, {"id": "victim-owner"}],
            "threat_paths": [{
                "id": "creator-owner",
                "attacker_principal": "attacker-creator",
                "victim_principal": "victim-owner",
                "primary": True,
                "accept_self_xss": False,
            }],
            "extension_path_budget": 0,
        }
        _write(environment / "role-inventory.json", inventory)
        _write(environment / "threat-decisions.json", decisions)
        _write(environment / "account-plan.json", plan)
        _write(environment / "receipt-manifest.json", manifest)
        (environment / "create-accounts.py").write_text('ACCOUNT_PLAN = "account-plan.json"\n', encoding="utf-8")

    def test_hidden_siblings_are_not_treated_as_a_closed_cluster(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            environment, source = root / "environment", root / "source"
            self._write_literal_cluster(environment, source, 'const roles = { owner: 0, editor?: 2, viewer: 4 };\n', ["owner", "viewer"])
            optional = evaluate_threat_model(environment, source)
            self.assertTrue(optional.ok, optional.messages)
            self.assertTrue(any("editor" in item["message"] for item in optional.review_items), optional.review_items)

            self._write_literal_cluster(
                environment,
                source,
                'const roles = { owner: "administrator", editor: "editor" };\n',
                ["owner", "editor"],
            )
            valued = evaluate_threat_model(environment, source)
            self.assertTrue(valued.ok, valued.messages)
            self.assertTrue(any("administrator" in item["message"] for item in valued.review_items), valued.review_items)

            self._write_literal_cluster(environment, source, 'const roles = ["Super Users", "editor", "author"];\n', ["editor", "author"])
            opaque = evaluate_threat_model(environment, source)
            self.assertTrue(opaque.ok, opaque.messages)
            self.assertEqual(opaque.coverage_status, "review_required")
            self.assertTrue(any("Super Users" in item["message"] for item in opaque.review_items), opaque.review_items)

    def test_acknowledgement_digest_tracks_boundary_evidence_and_parse_status(self) -> None:
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

            _write(environment / "threat-decisions.json", json.loads((environment / "threat-decisions.json").read_text(encoding="utf-8")))
            (root / "source" / "roles.js").write_text('const roles = ["a", "b"];\n{', encoding="utf-8")
            unparsed = evaluate_threat_model(environment, root / "source")
            self.assertTrue(unparsed.ok, unparsed.messages)
            self.assertNotEqual(closed.digest, unparsed.digest)
            self.assertNotEqual(assumed.digest, unparsed.digest)

    def _write_literal_cluster(self, environment: Path, source: Path, source_text: str, names: list[str]) -> None:
        source.mkdir(parents=True, exist_ok=True)
        environment.mkdir(parents=True, exist_ok=True)
        (source / "roles.js").write_text(source_text, encoding="utf-8")
        evidence = {"kind": "source", "path": "roles.js", "literal": names[0]}
        decisions = []
        for name in names:
            disposition = "include" if name == names[0] else "victim_only" if name == names[-1] else "exclude"
            reason = "写入可见内容" if disposition == "include" else "同簇中的其他角色"
            decisions.append({"id": name, "disposition": disposition, "reason": reason, "evidence": {**evidence, "literal": name}})
        attacker, victim = names[0], names[-1]
        inventory = {
            "roles": [{"id": name, "literal": name, "scope": "demo"} for name in names],
            "clusters": [{"id": "roles", "evidence": evidence, "role_ids": names}],
        }
        payload = {
            "roles": decisions,
            "victims": [{"role_id": victim, "account_id": victim, "scope": "demo"}],
            "paths": [{
                "id": "forward",
                "attacker_role": attacker,
                "victim_role": victim,
                "attacker_account": attacker,
                "victim_account": victim,
                "scope": "demo",
                "primary": True,
                "accept_self_xss": False,
            }],
            "boundaries": [],
        }
        plan = {"accounts": [
            {"account_id": attacker, "role_id": attacker, "scope": "demo", "extra_privileges": []},
            {"account_id": victim, "role_id": victim, "scope": "demo", "extra_privileges": []},
        ]}
        manifest = {
            "target": {"id": "demo", "version": "1", "image_digest": "demo"},
            "adapter": "demo",
            "allowed_origins": ["{{target_origin}}"],
            "principals": [{"id": attacker}, {"id": victim}],
            "threat_paths": [{
                "id": "forward",
                "attacker_principal": attacker,
                "victim_principal": victim,
                "primary": True,
                "accept_self_xss": False,
            }],
            "extension_path_budget": 0,
        }
        _write(environment / "role-inventory.json", inventory)
        _write(environment / "threat-decisions.json", payload)
        _write(environment / "account-plan.json", plan)
        _write(environment / "receipt-manifest.json", manifest)
        (environment / "create-accounts.py").write_text('ACCOUNT_PLAN = "account-plan.json"\n', encoding="utf-8")
