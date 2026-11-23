"""Static preflight checks; generated files are never executed or trusted here."""
from pathlib import Path
import ast
import json

import yaml
from app.receipt import ReceiptError, TargetManifest


def check_environment(workspace: Path, *, require_manifest: bool = False, source_dir: Path | None = None) -> list[dict]:
    root = workspace / "environment"
    requirements = (
        ("compose", "Compose 配置", ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml")),
        ("start", "环境启动脚本", ("start.py",)),
        ("accounts", "测试账号创建脚本", ("create-accounts.py",)),
        ("ready", "环境说明", ("READY.md",)),
    )
    if require_manifest:
        requirements += (("receipt_manifest", "RECEIPT Manifest 候选文件", ("receipt-manifest.json",)),)
    results = []
    for key, label, names in requirements:
        found = None
        for name in names:
            path = root / name
            try:
                if path.is_file() and path.resolve().parent == root.resolve() and path.stat().st_size <= 1_000_000 and path.read_text(encoding="utf-8").strip():
                    found = name
                    break
            except (OSError, UnicodeError):
                continue
        error = ""
        if found:
            content = (root / found).read_text(encoding="utf-8")
            try:
                if key == "compose":
                    data = yaml.safe_load(content)
                    if not isinstance(data, dict) or not isinstance(data.get("services"), dict) or not data["services"]:
                        error = "必须包含非空 services 映射"
                elif key in {"start", "accounts"}:
                    ast.parse(content)
                elif key == "receipt_manifest":
                    data = json.loads(content)
                    if not isinstance(data, dict):
                        raise ValueError("Manifest 根节点必须是对象")
                    TargetManifest.from_mapping(data)
            except (yaml.YAMLError, SyntaxError, ValueError, ReceiptError) as exc:
                error = f"格式错误：{str(exc)[:200]}"
        results.append({"id": key, "ok": found is not None and not error, "message": f"{label}：{found or '缺失、为空或非 UTF-8'}{('；' + error) if error else ''}"})
    if require_manifest:
        try:
            manifest = TargetManifest.from_mapping(json.loads((root / "receipt-manifest.json").read_text(encoding="utf-8")))
            if manifest.adapter == "generic-compose":
                from app.generic_receipt_adapter import load_adapter_config
                load_adapter_config(root)
                results.append({"id": "receipt_adapter", "ok": True, "message": "通用 Adapter 配置有效"})
                from app.security_boundary import BoundaryError, load_boundary_plan
                try:
                    plan = load_boundary_plan(workspace, root, {p.account_id for p in manifest.principals.values()})
                    results.append({"id": "security_controls", "ok": True, "message": f"安全控制声明格式有效，共 {len(plan['controls'])} 项；覆盖性未经独立证明"})
                except BoundaryError as exc:
                    results.append({"id": "security_controls", "ok": False, "message": f"安全控制声明无效：{exc}"})
        except (OSError, UnicodeError, ValueError, ReceiptError) as exc:
            results.append({"id": "receipt_adapter", "ok": False, "message": f"Adapter 配置无效：{str(exc)[:200]}"})
        from app.threat_model import evaluate_threat_model
        results.append(evaluate_threat_model(root, source_dir).as_check())
    return results
