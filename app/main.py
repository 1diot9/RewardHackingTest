from __future__ import annotations

import asyncio
import json
import math
import os
import secrets
import shutil
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import File, Form, FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.config import (
    COMPACT_PERCENT,
    CONTEXT_WINDOW_TOKENS,
    DATA_DIR,
    HOST,
    MIN_CONTEXT_WINDOW_TOKENS,
    MAX_CONCURRENT,
    PORT,
    POCLIB_FILE,
    RECEIPT_MANIFESTS_DIR,
    WORKSPACES_DIR,
    PROJECTS_DIR,
)
from app.environment_check import check_environment
from app.environment_test import cleanup_audit_environment, stop_audit_environment
from app.gateway import probe as probe_gateway
from app.hub import Hub
from app.project_import import ProjectImportError, filesystem_path, github_repository, import_github_project, import_project_zip, remove_tree, source_file_hashes
from app.receipt_adapters import load_trusted_receipt_adapters
from app.reports import list_reports, load_principal_roles, save_human_review, update_review_for_poc
from app.receipt_execution import receipt_manifest_path, verify_receipt_candidate
from app.receipt_settings import ensure_attacker_image, is_pinned_attacker_image, receipt_configuration_errors, receipt_runtime_config
from app.runner import InitializationStopped, request_stop, run_task, prepare_workspace, _finish, _prepare_environment, set_max_concurrent
from app.receipt import (
    ReceiptError,
    load_manifest,
    target_adapter_for,
)
from app.store import Store, now_iso, read_events

store = Store()
hub = Hub()
_RUNNING: dict[str, asyncio.Task] = {}
_PROJECT_RUNNING: dict[str, asyncio.Task] = {}
_PROJECT_RESUME: dict[str, asyncio.Event] = {}
_DELETING_PROJECTS: set[str] = set()
_DELETING_TASKS: set[str] = set()
_SYNCING_TASKS: set[str] = set()
_PROJECT_SYNC_LOCKS: dict[str, asyncio.Lock] = {}
_TERMINAL_STATUSES = {"completed", "budget_exhausted", "time_exhausted", "cancelled", "error"}


class ProjectInitializationStore:
    """Adapt project initialization to the existing environment preparation runner."""

    def __init__(self, project_id: str):
        self.project_id = project_id

    def get_task(self, task_id: str) -> dict | None:
        project = store.get_project(self.project_id)
        return project.get("initialization") if project else None

    def get_provider(self, provider_id: str) -> dict | None:
        return store.get_provider(provider_id)

    def get_proxy_settings(self) -> dict:
        return store.get_proxy_settings()

    def update_task(self, task_id: str, **fields: object) -> dict | None:
        return store.update_project_initialization(self.project_id, **fields)

    def append_event(self, task_id: str, payload: dict) -> dict | None:
        return store.append_project_event(self.project_id, payload)

    async def checkpoint(self, task_id: str) -> None:
        current = self.get_task(task_id) or {}
        if current.get("status") == "stop_requested":
            raise InitializationStopped()
        if current.get("status") != "pause_requested":
            return
        self.update_task(task_id, status="paused", environment_status="paused")
        event = self.append_event(task_id, {"type": "status", "text": "初始化已暂停，可继续执行"})
        if event:
            hub.publish(task_id, event)
        await _PROJECT_RESUME.setdefault(self.project_id, asyncio.Event()).wait()
        if (self.get_task(task_id) or {}).get("status") == "stop_requested":
            raise InitializationStopped()


def _mark_project_initialization_stopped(project_id: str) -> None:
    store.update_project_initialization(project_id, status="stopped", environment_status="stopped", error=None)
    event = store.append_project_event(project_id, {"type": "status", "text": "初始化已停止，可重新初始化"})
    if event:
        hub.publish(f"project:{project_id}", event)


async def _sync_github_source(project: dict, destination: Path) -> dict:
    project_dir = _owned_directory(PROJECTS_DIR, project["id"])

    def sync_source() -> dict:
        destination.parent.mkdir(parents=True, exist_ok=True)
        import_github_project(project["github_url"], destination)
        baseline_path = project_dir / "github-file-hashes.json"
        previous = json.loads(baseline_path.read_text(encoding="utf-8")) if baseline_path.exists() else source_file_hashes(Path(project["source_dir"]))
        current = source_file_hashes(destination)
        changes = {
            "added": sorted(current.keys() - previous.keys()),
            "modified": sorted(name for name in current.keys() & previous.keys() if current[name] != previous[name]),
            "deleted": sorted(previous.keys() - current.keys()),
        }
        temporary = project_dir / f".github-file-hashes-{uuid4().hex}.tmp"
        try:
            temporary.write_text(json.dumps(current, ensure_ascii=True), encoding="utf-8")
            temporary.replace(baseline_path)
        finally:
            temporary.unlink(missing_ok=True)
        return {kind: len(paths) for kind, paths in changes.items()}

    async with _PROJECT_SYNC_LOCKS.setdefault(project["id"], asyncio.Lock()):
        job = asyncio.create_task(asyncio.to_thread(sync_source))
        try:
            return await asyncio.shield(job)
        except asyncio.CancelledError:
            await asyncio.gather(job, return_exceptions=True)
            remove_tree(destination, ignore_errors=True)
            raise
        except (ProjectImportError, OSError, ValueError, TypeError):
            remove_tree(destination, ignore_errors=True)
            raise


async def _initialize_project(project_id: str, *, resume: bool = False) -> None:
    adapter = ProjectInitializationStore(project_id)
    event_id = f"project:{project_id}"
    try:
        project = store.get_project(project_id)
        initialization = adapter.get_task(event_id)
        await adapter.checkpoint(event_id)
        if initialization:
            (Path(initialization["workspace"]) / "github-changes.json").unlink(missing_ok=True)
        if project and project.get("github_url") and not (resume and (project.get("initialization") or {}).get("github_synced")):
            project_dir = _owned_directory(PROJECTS_DIR, project_id)
            destination = project_dir / "initializations" / uuid4().hex
            event = adapter.append_event(event_id, {"type": "status", "text": "正在同步 GitHub 默认分支源码"})
            if event:
                hub.publish(event_id, event)
            counts = await _sync_github_source(project, destination)
            store.update_project(project_id, source_dir=str(destination))
            adapter.update_task(event_id, source_dir=str(destination), github_change_counts=counts, github_updated=any(counts.values()), github_synced=True)
            message = (f"GitHub 同步完成：新增 {counts['added']}、修改 {counts['modified']}、删除 {counts['deleted']} 个文件")
            event = adapter.append_event(event_id, {"type": "status", "text": message})
            if event:
                hub.publish(event_id, event)
        await adapter.checkpoint(event_id)
        if await _prepare_environment(event_id, adapter, hub):
            adapter.update_task(event_id, environment_status="ready")
    except InitializationStopped:
        _mark_project_initialization_stopped(project_id)
    except asyncio.CancelledError:
        current = adapter.get_task(event_id) or {}
        if current.get("status") == "stop_requested":
            _mark_project_initialization_stopped(project_id)
        elif current.get("status") in {"paused", "pause_requested"}:
            adapter.update_task(event_id, status="paused", environment_status="paused", error=None)
        else:
            adapter.update_task(event_id, status="preparing", environment_status="preparing", error=None)
        raise
    except Exception as exc:
        if (adapter.get_task(event_id) or {}).get("status") == "stop_requested":
            _mark_project_initialization_stopped(project_id)
        else:
            adapter.update_task(event_id, status="draft", environment_status="failed", error=str(exc))
    finally:
        _PROJECT_RESUME.pop(project_id, None)
        initialization = adapter.get_task(event_id)
        if initialization and initialization.get("error"):
            event = adapter.append_event(event_id, {"type": "error", "text": initialization["error"]})
            if event:
                hub.publish(event_id, event)


async def _stop_job(job: asyncio.Task | None) -> None:
    if job is None or job.done():
        return
    job.cancel()
    done, pending = await asyncio.wait({job}, timeout=15)
    if pending:
        raise HTTPException(status_code=409, detail="运行中的操作尚未停止，请稍后重试")
    await asyncio.gather(*done, return_exceptions=True)


def _owned_directory(root: Path, identifier: str, actual: str | None = None) -> Path:
    expected = root.resolve() / identifier
    if not identifier or len(identifier) != 32 or any(c not in "0123456789abcdef" for c in identifier):
        raise HTTPException(status_code=409, detail="数据目录标识无效，无法自动删除")
    if expected.resolve() != expected or (actual is not None and Path(actual).resolve() != expected):
        raise HTTPException(status_code=409, detail="数据目录不在预期位置，无法自动删除")
    return expected


def _require_generated_threat_model(project: dict, project_id: str) -> None:
    """Refuse to copy a generated manifest whose role closure is open or unacknowledged."""

    from app.threat_model import evaluate_threat_model

    report = evaluate_threat_model(_project_environment_root(project_id), Path(project["source_dir"]))
    if not report.ok:
        raise HTTPException(status_code=409, detail=("威胁模型闭包未通过：" + "；".join(report.messages))[:1500])
    if report.coverage_status != "review_required":
        return
    acknowledgement = (project.get("initialization") or {}).get("threat_model_ack") or {}
    if acknowledgement.get("digest") == report.digest:
        return
    detail = "威胁模型含未确认的假设：" + "；".join(item["message"] for item in report.review_items)
    raise HTTPException(status_code=409, detail=detail[:1500])


def _project_environment_root(project_id: str) -> Path:
    project_root = _owned_directory(PROJECTS_DIR, project_id)
    environment = project_root / "setup" / "environment"
    if not environment.resolve().is_relative_to(project_root):
        raise HTTPException(status_code=409, detail="环境文件目录不在项目内")
    return environment


def _remove_task_manifest(task: dict) -> None:
    name = f"task-{task['id']}.json"
    if task.get("generated_receipt_manifest") == name:
        (RECEIPT_MANIFESTS_DIR / name).unlink(missing_ok=True)
        remove_tree(RECEIPT_MANIFESTS_DIR / f"task-{task['id']}", ignore_errors=True)


_FROZEN_MANIFEST_FILES = ("receipt-manifest.json", "account-plan.json", "create-accounts.py")


def _replace_regular_file(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ReceiptError(f"{source.name} 无效")
    if destination.is_symlink():
        raise ReceiptError(f"{destination.name} 不能是符号链接")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".refreshing")
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _refresh_frozen_manifest(task: dict) -> None:
    """Replace a task's frozen RECEIPT manifest with the project's current one.

    The account plan and account script travel with the manifest. The restarted
    lab and the verifier both provision principals from those files.
    """

    if not task.get("receipt_enabled"):
        raise HTTPException(status_code=409, detail="此任务未启用验证器，不能更新清单")
    task_id = str(task.get("id") or "")
    owned_name = f"task-{task_id}.json"
    if task.get("receipt_manifest") != owned_name:
        raise HTTPException(status_code=409, detail="此任务没有独立冻结的清单")
    project_id = str(task.get("project_id") or "")
    project = store.get_project(project_id)
    if project is None or not Path(str(project.get("source_dir") or "")).is_dir():
        raise HTTPException(status_code=409, detail="项目不存在或源码目录不可用")
    if (project.get("initialization") or {}).get("environment_status") != "ready":
        raise HTTPException(status_code=409, detail="请先完成项目环境初始化")
    _require_generated_threat_model(project, project_id)
    environment = _project_environment_root(project_id)
    generated = environment / "receipt-manifest.json"
    snapshot = RECEIPT_MANIFESTS_DIR / f"task-{task_id}"
    workspace = Path(str(task.get("workspace") or ""))
    workspace_environment = workspace / "environment"
    try:
        if not workspace_environment.resolve().is_relative_to(workspace.resolve()):
            raise ReceiptError("工作区环境目录无效")
        manifest = load_manifest(generated, environment)
        if manifest.adapter == "generic-compose":
            if not snapshot.is_dir():
                raise ReceiptError("任务缺少环境快照")
            target_adapter_for(manifest, environment)
        else:
            target_adapter_for(manifest)
        sources = [environment / name for name in _FROZEN_MANIFEST_FILES]
        for source in sources:
            if source.is_symlink() or not source.is_file():
                raise ReceiptError(f"缺少 {source.name}")
        RECEIPT_MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)
        _replace_regular_file(generated, RECEIPT_MANIFESTS_DIR / owned_name)
        for source in sources:
            _replace_regular_file(source, workspace_environment / source.name)
            if snapshot.is_dir():
                _replace_regular_file(source, snapshot / source.name)
    except HTTPException:
        raise
    except (ReceiptError, OSError) as exc:
        raise HTTPException(status_code=409, detail=f"无法更新冻结清单：{exc}") from exc


def _refresh_follow_up_environment(task: dict) -> None:
    """Refresh project environment inputs while preserving reports and other task artifacts."""
    project_id = str(task.get("project_id") or "")
    project = store.get_project(project_id)
    if project is None or not Path(str(project.get("source_dir") or "")).is_dir():
        raise HTTPException(status_code=409, detail="项目不存在或源码目录不可用")
    if (project.get("initialization") or {}).get("environment_status") != "ready":
        raise HTTPException(status_code=409, detail="请先完成项目环境初始化")
    if project_id in _DELETING_PROJECTS or (project_id in _PROJECT_RUNNING and not _PROJECT_RUNNING[project_id].done()):
        raise HTTPException(status_code=409, detail="项目正在初始化或删除，请稍后重试")
    environment = _project_environment_root(project_id)
    try:
        if not environment.is_dir() or any(item.is_symlink() for item in environment.rglob("*")):
            raise ReceiptError("项目环境目录不存在或包含符号链接")
        if task.get("receipt_enabled") and task.get("receipt_manifest") == f"task-{task['id']}.json":
            _refresh_frozen_manifest(task)
        workspace_environment = Path(task["workspace"]) / "environment"
        if workspace_environment.is_symlink():
            raise ReceiptError("工作区环境目录不能是符号链接")
        _replace_environment_directory(environment, workspace_environment, ignore=shutil.ignore_patterns("threat-model.md", "INITIALIZATION_FAILED.md"))
        snapshot = RECEIPT_MANIFESTS_DIR / f"task-{task['id']}"
        if task.get("receipt_enabled") and task.get("receipt_manifest") == f"task-{task['id']}.json" and snapshot.is_dir():
            _replace_environment_directory(environment, snapshot)
    except (ReceiptError, OSError) as exc:
        raise HTTPException(status_code=409, detail=f"无法更新项目环境文件：{exc}") from exc


def _replace_environment_directory(source: Path, destination: Path, ignore=None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    suffix = uuid4().hex
    staged = destination.with_name(destination.name + ".new-" + suffix)
    backup = destination.with_name(destination.name + ".old-" + suffix)
    try:
        shutil.copytree(source, staged, ignore=ignore)
        if destination.exists():
            destination.rename(backup)
        try:
            staged.rename(destination)
        except OSError:
            if backup.exists():
                backup.rename(destination)
            raise
    finally:
        if staged.exists():
            remove_tree(staged)
        if backup.exists() and destination.exists():
            remove_tree(backup)


def _schedule_task(task_id: str) -> asyncio.Task:
    current = _RUNNING.get(task_id)
    if current is not None and not current.done():
        return current
    job = asyncio.create_task(run_task(task_id, store, hub))
    _RUNNING[task_id] = job

    def discard(completed: asyncio.Task) -> None:
        if _RUNNING.get(task_id) is completed:
            _RUNNING.pop(task_id, None)

    job.add_done_callback(discard)
    return job


def _schedule_project_initialization(project_id: str, *, resume: bool = False) -> asyncio.Task:
    current = _PROJECT_RUNNING.get(project_id)
    if current is not None and not current.done():
        return current
    job = asyncio.create_task(_initialize_project(project_id, resume=resume))
    _PROJECT_RUNNING[project_id] = job
    job.add_done_callback(lambda completed: _PROJECT_RUNNING.pop(project_id, None) if _PROJECT_RUNNING.get(project_id) is completed else None)
    return job


def _schedule_task_preparation(task_id: str) -> asyncio.Task:
    current = _RUNNING.get(task_id)
    if current is not None and not current.done():
        return current
    job = asyncio.create_task(_prepare_environment(task_id, store, hub))
    _RUNNING[task_id] = job
    job.add_done_callback(lambda completed: _RUNNING.pop(task_id, None) if _RUNNING.get(task_id) is completed else None)
    return job


def _mask(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 4:
        return "••••"
    return "••••" + secret[-4:]


def normalize_currency(value: str, *, strict: bool = False) -> str:
    folded = (value or "").strip()
    upper = folded.upper()
    if upper in {"CNY", "RMB"} or folded in {"人民币", "元"}:
        return "CNY"
    if upper == "USD" or folded == "美元" or not folded:
        return "USD"
    if strict:
        raise HTTPException(status_code=400, detail="货币只支持美元或人民币")
    return "USD"


def _public_provider(provider: dict) -> dict:
    model = provider.get("model")
    models = ([{"id": model, "name": model}] if model else provider.get("models") or [])
    return {
        "id": provider["id"],
        "name": provider["name"],
        "base_url": provider.get("base_url") or "",
        "currency": normalize_currency(str(provider.get("currency") or "USD")),
        "has_key": bool(provider.get("api_key")),
        "key_hint": _mask(provider.get("api_key") or ""),
        "catalog": provider.get("catalog") or [],
        "model": model or "",
        "models": models,
    }


def _check_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="靶场地址需要是 http 或 https URL")
    return value.strip()


def _check_prices(raw: dict) -> dict:
    try:
        input_price = float(raw["input_per_mtok"])
        output_price = float(raw["output_per_mtok"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="模型需要填写输入和输出单价") from exc
    if not math.isfinite(input_price) or not math.isfinite(output_price) or input_price < 0 or output_price < 0:
        raise HTTPException(status_code=400, detail="单价不能为负数")
    cache_read = raw.get("cache_read_per_mtok")
    cache_write = raw.get("cache_write_per_mtok")
    prices = {
        "input_per_mtok": input_price,
        "output_per_mtok": output_price,
        "cache_read_per_mtok": input_price if cache_read is None else float(cache_read),
        "cache_write_per_mtok": input_price if cache_write is None else float(cache_write),
    }
    if any(not math.isfinite(value) or value < 0 for value in prices.values()):
        raise HTTPException(status_code=400, detail="缓存单价不能为负数")
    return prices


class ModelIn(BaseModel):
    id: str = Field(min_length=1, max_length=200)
    input_per_mtok: float
    output_per_mtok: float
    cache_read_per_mtok: float | None = None
    cache_write_per_mtok: float | None = None
    currency: str = "USD"


class ProviderIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    base_url: str = ""
    api_key: str = ""
    currency: str = Field(default="USD", min_length=1, max_length=16)
    model: str = Field(default="", max_length=200)


class PricesIn(BaseModel):
    models: list[ModelIn] = Field(default_factory=list)


class CatalogModelIn(BaseModel):
    id: str = Field(min_length=1, max_length=200)
    name: str = ""


class CatalogIn(BaseModel):
    models: list[CatalogModelIn] = Field(default_factory=list)


class ProbeIn(BaseModel):
    provider_id: str = ""
    base_url: str = ""
    api_key: str = ""


class TaskIn(BaseModel):
    instruction: str = Field(min_length=1, max_length=8000)
    base_url: str = ""
    provider_id: str
    model: str
    budget: float = Field(gt=0)
    duration_minutes: int = Field(ge=1, le=10080)
    completion_mode: Literal["continuous", "agent"] = "agent"
    currency: str = ""
    context_window_tokens: int = Field(default=CONTEXT_WINDOW_TOKENS, ge=MIN_CONTEXT_WINDOW_TOKENS)
    compact_percent: int = Field(default=COMPACT_PERCENT, ge=1, le=100)
    receipt_enabled: bool = False
    receipt_manifest: str = Field(default="", max_length=200)


class FollowUpIn(BaseModel):
    instruction: str = Field(min_length=1, max_length=8000)
    budget: float = Field(default=0, ge=0, allow_inf_nan=False)
    duration_minutes: int = Field(default=0, ge=0, le=10080)


class PendingReviewIn(BaseModel):
    budget: float = Field(default=0, ge=0, allow_inf_nan=False)
    duration_minutes: int = Field(default=0, ge=0, le=10080)


class ReceiptVerifyIn(BaseModel):
    poc_id: str = Field(min_length=5, max_length=100)


class ReceiptSettingsIn(BaseModel):
    evidence_hmac_key: str = Field(default="", max_length=1024)
    attacker_image: str = Field(default="", max_length=1000)


class ConcurrencySettingsIn(BaseModel):
    max_concurrent: int = Field(ge=1, strict=True)


class ProxySettingsIn(BaseModel):
    enabled: bool = False
    url: str = Field(default="", max_length=2048)
    no_proxy: str = Field(default="", max_length=2048)


def _checked_base_url(value: str) -> str:
    base_url = value.strip()
    if not base_url:
        return ""
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="模型商地址需要是 http 或 https URL")
    return base_url


def _provider_record(body: ProviderIn, provider_id: str, api_key: str, models: list[dict], catalog: list[dict]) -> dict:
    return {
        "id": provider_id,
        "name": body.name.strip(),
        "base_url": _checked_base_url(body.base_url),
        "api_key": api_key,
        "model": body.model.strip(),
        "currency": normalize_currency(body.currency, strict=True),
        "catalog": catalog,
        "models": models,
    }


def normalize_catalog(models: list[CatalogModelIn]) -> list[dict]:
    catalog = []
    seen: set[str] = set()
    for model in models:
        model_id = model.id.strip()
        if not model_id or model_id in seen:
            continue
        seen.add(model_id)
        name = model.name.strip() or model_id
        catalog.append({"id": model_id, "name": name})
    return catalog


def match_priced_models(models: list[ModelIn], catalog: list[dict]) -> list[dict]:
    priced = []
    seen: set[str] = set()
    for model in models:
        model_id = model.id.strip()
        if not model_id:
            raise HTTPException(status_code=400, detail="模型名称不能为空")
        if model_id in seen:
            raise HTTPException(status_code=400, detail=f"模型重复: {model_id}")
        seen.add(model_id)
        priced.append({"id": model_id, "name": model_id, "currency": normalize_currency(model.currency, strict=True), **_check_prices(model.model_dump())})
    return priced


def _selected_model(provider: dict, model: str) -> dict | None:
    configured = provider.get("model")
    valid = model == configured if configured else any(item.get("id") == model for item in provider.get("models", []))
    if not valid or not model:
        return None
    price = next((item for item in store.list_model_prices() if item["id"] == model), None)
    return price or {"id": model, "input_per_mtok": 0, "output_per_mtok": 0, "cache_read_per_mtok": 0, "cache_write_per_mtok": 0, "currency": "USD"}


def _probe_credentials(body: ProbeIn) -> tuple[str, str]:
    base_url = body.base_url.strip()
    api_key = body.api_key.strip()
    if body.provider_id and not api_key:
        provider = store.get_provider(body.provider_id)
        if provider is None:
            raise HTTPException(status_code=404, detail="模型商不存在")
        api_key = provider.get("api_key") or ""
    return base_url, api_key


def _runtime_receipt_config():
    return receipt_runtime_config(store.get_receipt_settings())


def _receipt_source(setting_name: str, environment_name: str) -> str:
    if str(store.get_receipt_settings().get(setting_name) or "").strip():
        return "settings"
    return "environment" if os.environ.get(environment_name, "").strip() else "none"


def _public_receipt_settings() -> dict:
    config = _runtime_receipt_config()
    errors = receipt_configuration_errors(config)
    return {
        "has_evidence_hmac_key": bool(config.evidence_hmac_key),
        "evidence_hmac_key_hint": _mask(config.evidence_hmac_key),
        "evidence_hmac_key_source": _receipt_source("evidence_hmac_key", "RECEIPT_EVIDENCE_HMAC_KEY"),
        "attacker_image": config.attacker_image,
        "attacker_image_source": _receipt_source("attacker_image", "RECEIPT_ATTACKER_IMAGE"),
        "ready": not errors,
        "issues": errors,
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    del app
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    WORKSPACES_DIR.mkdir(parents=True, exist_ok=True)
    load_trusted_receipt_adapters()
    await set_max_concurrent(store.get_max_concurrent(MAX_CONCURRENT))
    for task_id in store.recover_interrupted():
        _schedule_task(task_id)
    for task in store.list_tasks():
        if task.get("status") == "preparing":
            _schedule_task_preparation(task["id"])
    for project in store.list_projects():
        if (project.get("initialization") or {}).get("status") == "preparing":
            _schedule_project_initialization(project["id"], resume=True)
    try:
        yield
    finally:
        project_jobs = [job for job in _PROJECT_RUNNING.values() if not job.done()]
        for job in project_jobs:
            job.cancel()
        if project_jobs:
            await asyncio.gather(*project_jobs, return_exceptions=True)
        jobs: list[asyncio.Task] = []
        for task_id, job in list(_RUNNING.items()):
            if job.done():
                continue
            task = store.get_task(task_id)
            if task is None or task["status"] in _TERMINAL_STATUSES:
                continue
            if task["status"] == "preparing" and task.get("preparation_mode") != "audit":
                job.cancel()
                jobs.append(job)
                continue
            manual_request = task["status"] == "pause_requested" and task.get("pause_reason") == "manual"
            reason = "paused" if manual_request else "restart"
            if not manual_request:
                store.update_task(
                    task_id,
                    status="pause_requested",
                    pause_reason="restart",
                    paused_at=task.get("paused_at") or now_iso(),
                )
            request_stop(task_id, reason)
            jobs.append(job)
        if jobs:
            _, pending = await asyncio.wait(jobs, timeout=10)
            for job in pending:
                job.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)


app = FastAPI(title="通用 XSS 审计器", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5179", "http://localhost:5179"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict:
    try:
        import claude_agent_sdk  # noqa: F401

        sdk = True
    except Exception:
        sdk = False
    return {"ok": True, "sdk": sdk}


@app.get("/api/defaults")
def defaults() -> dict:
    return {
        "base_url": "",
        "context_window_tokens": CONTEXT_WINDOW_TOKENS,
        "compact_percent": COMPACT_PERCENT,
        "receipt_enabled": False,
    }


@app.get("/api/receipt/settings")
def get_receipt_settings() -> dict:
    return _public_receipt_settings()


@app.get("/api/settings/concurrency")
def get_concurrency_settings() -> dict:
    return {"max_concurrent": store.get_max_concurrent(MAX_CONCURRENT)}


@app.get("/api/settings/proxy")
def get_proxy_settings() -> dict:
    return store.get_proxy_settings()


@app.put("/api/settings/proxy")
def update_proxy_settings(body: ProxySettingsIn) -> dict:
    url = body.url.strip()
    try:
        parsed = urlparse(url)
        valid = (parsed.scheme in {"http", "https"} and bool(parsed.hostname)
                 and parsed.port is not None and not parsed.username and not parsed.password
                 and not parsed.path.strip("/") and not parsed.query and not parsed.fragment)
    except ValueError:
        valid = False
    if (url and not valid) or (body.enabled and not url):
        raise HTTPException(status_code=422, detail="请输入不含账号密码、包含端口的 HTTP 或 HTTPS 代理地址")
    no_proxy = body.no_proxy.strip()
    if any(c in no_proxy for c in "\r\n"):
        raise HTTPException(status_code=422, detail="直连地址请用逗号分隔")
    return store.set_proxy_settings({"enabled": body.enabled, "url": url, "no_proxy": no_proxy})


@app.put("/api/settings/concurrency")
async def update_concurrency_settings(body: ConcurrencySettingsIn) -> dict:
    store.set_max_concurrent(body.max_concurrent)
    await set_max_concurrent(body.max_concurrent)
    return {"max_concurrent": body.max_concurrent}


@app.put("/api/receipt/settings")
def update_receipt_settings(body: ReceiptSettingsIn) -> dict:
    image = body.attacker_image.strip()
    if image and not is_pinned_attacker_image(image):
        raise HTTPException(status_code=400, detail="攻击者镜像必须使用 sha256 digest 固定版本")
    current = store.get_receipt_settings()
    key = body.evidence_hmac_key.strip() or str(current.get("evidence_hmac_key") or "").strip()
    store.set_receipt_settings({"evidence_hmac_key": key, "attacker_image": image})
    return _public_receipt_settings()


@app.post("/api/receipt/settings/auto")
def auto_configure_receipt_settings() -> dict:
    current = store.get_receipt_settings()
    config = receipt_runtime_config(current)
    if config.attacker_image and not is_pinned_attacker_image(config.attacker_image):
        raise HTTPException(status_code=400, detail="已配置的攻击者镜像必须使用 sha256 digest，请先修正")
    try:
        image = ensure_attacker_image(config.attacker_image)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if store.get_receipt_settings() != current:
        raise HTTPException(status_code=409, detail="设置在镜像准备期间发生变化，请重试")
    updated = dict(current)
    if not config.evidence_hmac_key:
        updated["evidence_hmac_key"] = secrets.token_hex(32)
    if not config.attacker_image:
        updated["attacker_image"] = image
    store.set_receipt_settings(updated)
    return _public_receipt_settings()


@app.get("/api/providers")
def list_providers() -> list[dict]:
    return [_public_provider(item) for item in store.list_providers()]


@app.get("/api/model-prices")
def list_model_prices() -> list[dict]:
    return store.list_model_prices()


@app.put("/api/model-prices")
def set_model_prices(body: PricesIn) -> list[dict]:
    return store.set_model_prices(match_priced_models(body.models, []))


@app.post("/api/providers")
def create_provider(body: ProviderIn) -> dict:
    record = _provider_record(body, uuid4().hex, body.api_key.strip(), [], [])
    return _public_provider(store.upsert_provider(record))


@app.put("/api/providers/{provider_id}")
def update_provider(provider_id: str, body: ProviderIn) -> dict:
    current = store.get_provider(provider_id)
    if current is None:
        raise HTTPException(status_code=404, detail="模型商不存在")
    api_key = body.api_key.strip() or current.get("api_key") or ""
    record = _provider_record(
        body,
        provider_id,
        api_key,
        current.get("models") or [],
        current.get("catalog") or [],
    )
    return _public_provider(store.upsert_provider(record))


@app.put("/api/providers/{provider_id}/catalog")
def update_catalog(provider_id: str, body: CatalogIn) -> dict:
    current = store.get_provider(provider_id)
    if current is None:
        raise HTTPException(status_code=404, detail="模型商不存在")
    current["catalog"] = normalize_catalog(body.models)
    return _public_provider(store.upsert_provider(current))


@app.put("/api/providers/{provider_id}/prices")
def update_prices(provider_id: str, body: PricesIn) -> dict:
    current = store.get_provider(provider_id)
    if current is None:
        raise HTTPException(status_code=404, detail="模型商不存在")
    current["models"] = match_priced_models(body.models, current.get("catalog") or [])
    return _public_provider(store.upsert_provider(current))


@app.post("/api/providers/probe")
def probe_provider(body: ProbeIn) -> dict:
    base_url, api_key = _probe_credentials(body)
    return probe_gateway(base_url, api_key)


@app.delete("/api/providers/{provider_id}")
def delete_provider(provider_id: str) -> dict:
    if not store.delete_provider(provider_id):
        raise HTTPException(status_code=404, detail="模型商不存在")
    return {"ok": True}


@app.get("/api/tasks")
def list_tasks() -> list[dict]:
    return store.list_tasks()


@app.get("/api/projects")
def list_projects() -> list[dict]:
    return store.list_projects()


class ProjectGithubIn(BaseModel):
    github_url: str = Field(min_length=1, max_length=2048)


@app.put("/api/projects/{project_id}/github")
def set_project_github(project_id: str, body: ProjectGithubIn) -> dict:
    project = store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    if project_id in _DELETING_PROJECTS or (project_id in _PROJECT_RUNNING and not _PROJECT_RUNNING[project_id].done()) or any(task["id"] in _SYNCING_TASKS for task in store.list_tasks() if task.get("project_id") == project_id):
        raise HTTPException(status_code=409, detail="项目正在同步、初始化或删除")
    try:
        owner, repo = github_repository(body.github_url)
        existing = project.get("github_url")
        if existing and tuple(part.lower() for part in github_repository(existing)) != (owner.lower(), repo.lower()):
            raise HTTPException(status_code=409, detail="项目已经关联其他 GitHub 仓库")
    except ProjectImportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return store.update_project(project_id, github_url=f"https://github.com/{owner}/{repo}")


@app.post("/api/projects")
async def create_project(name: str = Form(default="", max_length=200), project_zip: UploadFile | None = File(default=None), github_url: str = Form(default="", max_length=2048)) -> dict:
    name = name.strip()
    github_url = github_url.strip()
    if bool(project_zip) == bool(github_url):
        raise HTTPException(status_code=400, detail="请选择 ZIP 文件或填写 GitHub 仓库地址")
    if project_zip and not name:
        raise HTTPException(status_code=400, detail="项目名称不能为空")
    project_id = uuid4().hex
    root = PROJECTS_DIR / project_id
    try:
        if project_zip:
            imported = import_project_zip(project_zip.file, root / "source", project_zip.filename or "")
        else:
            imported = await asyncio.to_thread(import_github_project, github_url, root / "source")
    except ProjectImportError as exc:
        remove_tree(root, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return store.add_project({"id": project_id, "name": name or imported.project_name, "source_dir": str(imported.source_dir), "github_url": github_url, "created_at": now_iso()})


@app.post("/api/projects/{project_id}/initialize")
async def initialize_project(project_id: str, provider_id: str = Form(...), model: str = Form(...), instruction: str = Form(default="", max_length=8000)) -> dict:
    project = store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    if project_id in _DELETING_PROJECTS or (project_id in _PROJECT_RUNNING and not _PROJECT_RUNNING[project_id].done()) or (project.get("initialization") or {}).get("status") in {"paused", "pause_requested", "stop_requested"}:
        raise HTTPException(status_code=409, detail="项目正在初始化或删除")
    provider = store.get_provider(provider_id)
    selected = _selected_model(provider, model) if provider else None
    if provider is None or selected is None:
        raise HTTPException(status_code=400, detail="请选择有效的模型商和模型")
    root = _owned_directory(PROJECTS_DIR, project_id)
    if not Path(project["source_dir"]).is_dir():
        raise HTTPException(status_code=400, detail="项目源码目录不可用")
    previous = project.get("initialization") or {}
    initialization = {
        "id": f"project:{project_id}", "project_name": project["name"], "source_dir": project["source_dir"],
        "workspace": str(root / "setup"), "instruction": instruction.strip(),
        "provider_id": provider_id, "provider_name": provider["name"], "model": model,
        "prices": selected, "currency": normalize_currency(selected.get("currency") or "USD"),
        "base_url": "", "budget": 1, "duration_seconds": 3600, "status": "preparing",
        "environment_status": "preparing", "error": None, "next_seq": previous.get("next_seq", 1),
    }
    updated = store.set_project_initialization(project_id, initialization)
    _schedule_project_initialization(project_id)
    return updated


@app.post("/api/projects/{project_id}/initialization/pause")
async def pause_project_initialization(project_id: str) -> dict:
    project = store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    initialization = project.get("initialization") or {}
    if initialization.get("status") in {"paused", "pause_requested"}:
        return project
    job = _PROJECT_RUNNING.get(project_id)
    if initialization.get("status") != "preparing" or job is None or job.done():
        raise HTTPException(status_code=409, detail="当前初始化不能暂停")
    _PROJECT_RESUME.setdefault(project_id, asyncio.Event()).clear()
    store.update_project_initialization(project_id, status="pause_requested", environment_status="pause_requested")
    event_id = f"project:{project_id}"
    event = store.append_project_event(project_id, {"type": "status", "text": "已请求暂停，当前步骤结束后暂停"})
    if event:
        hub.publish(event_id, event)
    return store.get_project(project_id)


@app.post("/api/projects/{project_id}/initialization/resume")
async def resume_project_initialization(project_id: str) -> dict:
    project = store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    initialization = project.get("initialization") or {}
    paused = initialization.get("status") == "paused"
    failed = initialization.get("environment_status") == "failed"
    if not paused and not failed:
        raise HTTPException(status_code=409, detail="当前初始化不能继续")
    if project_id in _DELETING_PROJECTS:
        raise HTTPException(status_code=409, detail="项目正在删除")
    job = _PROJECT_RUNNING.get(project_id)
    if failed and job and not job.done():
        raise HTTPException(status_code=409, detail="初始化仍在结束，请稍后重试")
    fields = {"status": "preparing", "environment_status": "preparing", "error": None}
    if failed:
        fields["resume_existing"] = True
    store.update_project_initialization(project_id, **fields)
    event_id = f"project:{project_id}"
    event = store.append_project_event(project_id, {"type": "status", "text": "初始化已继续"})
    if event:
        hub.publish(event_id, event)
    if job and not job.done():
        _PROJECT_RESUME[project_id].set()
    else:
        _schedule_project_initialization(project_id, resume=True)
    return store.get_project(project_id)


@app.post("/api/projects/{project_id}/initialization/stop")
async def stop_project_initialization(project_id: str) -> dict:
    project = store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    if project_id in _DELETING_PROJECTS:
        raise HTTPException(status_code=409, detail="项目正在删除")
    status = (project.get("initialization") or {}).get("status")
    if status in {"stopped", "stop_requested"}:
        return project
    if status not in {"preparing", "pause_requested", "paused"}:
        raise HTTPException(status_code=409, detail="当前初始化不能停止")
    job = _PROJECT_RUNNING.get(project_id)
    if job is None or job.done():
        _mark_project_initialization_stopped(project_id)
    else:
        store.update_project_initialization(project_id, status="stop_requested", environment_status="stop_requested", error=None)
        event = store.append_project_event(project_id, {"type": "status", "text": "已请求停止，当前步骤结束后停止"})
        if event:
            hub.publish(f"project:{project_id}", event)
        _PROJECT_RESUME.setdefault(project_id, asyncio.Event()).set()
    return store.get_project(project_id)


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: str) -> dict:
    project = store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    if project_id in _DELETING_PROJECTS or any(task_id in _DELETING_TASKS for task_id in (item["id"] for item in store.list_tasks() if item.get("project_id") == project_id)):
        raise HTTPException(status_code=409, detail="项目正在删除")
    tasks = [task for task in store.list_tasks() if task.get("project_id") == project_id]
    if any(task["id"] in _SYNCING_TASKS for task in tasks):
        raise HTTPException(status_code=409, detail="项目正在同步 GitHub 源码")
    project_dir = _owned_directory(PROJECTS_DIR, project_id)
    task_dirs = [_owned_directory(WORKSPACES_DIR, task["id"], task["workspace"]) for task in tasks]
    _DELETING_PROJECTS.add(project_id)
    try:
        await _stop_job(_PROJECT_RUNNING.get(project_id))
        for task in tasks:
            await _stop_job(_RUNNING.get(task["id"]))
            ok, detail = await cleanup_audit_environment(store.get_task(task["id"]) or task)
            if not ok:
                raise HTTPException(status_code=500, detail=f"清理靶场失败：{detail}")
        for path in [*task_dirs, project_dir]:
            if path.exists():
                remove_tree(path)
        for task in tasks:
            _remove_task_manifest(task)
        store.delete_project(project_id)
        return {"ok": True}
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"删除文件失败：{exc}") from exc
    finally:
        _DELETING_PROJECTS.discard(project_id)


@app.delete("/api/tasks/{task_id}")
async def delete_task(task_id: str) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task_id in _DELETING_TASKS or task_id in _SYNCING_TASKS or task.get("project_id") in _DELETING_PROJECTS:
        raise HTTPException(status_code=409, detail="任务或项目正在删除")
    path = _owned_directory(WORKSPACES_DIR, task_id, task["workspace"])
    _DELETING_TASKS.add(task_id)
    try:
        await _stop_job(_RUNNING.get(task_id))
        ok, detail = await cleanup_audit_environment(store.get_task(task_id) or task)
        if not ok:
            raise HTTPException(status_code=500, detail=f"清理靶场失败：{detail}")
        if path.exists():
            remove_tree(path)
        if task.get("github_updated") is not None and task.get("project_id"):
            snapshot = _owned_directory(PROJECTS_DIR, task["project_id"]) / "snapshots" / task_id
            if snapshot.exists():
                remove_tree(snapshot)
        _remove_task_manifest(task)
        store.delete_task(task_id)
        return {"ok": True}
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"删除文件失败：{exc}") from exc
    finally:
        _DELETING_TASKS.discard(task_id)


@app.post("/api/tasks")
async def create_task(
    project_id: str = Form(...),
    instruction: str = Form(..., min_length=1, max_length=8000),
    base_url: str = Form(""),
    provider_id: str = Form(..., min_length=1),
    model: str = Form(..., min_length=1),
    budget: float = Form(..., gt=0),
    duration_minutes: int = Form(..., ge=1, le=10080),
    completion_mode: Literal["continuous", "agent"] = Form("agent"),
    currency: str = Form(""),
    context_window_tokens: int = Form(CONTEXT_WINDOW_TOKENS, ge=MIN_CONTEXT_WINDOW_TOKENS),
    compact_percent: int = Form(COMPACT_PERCENT, ge=1, le=100),
    receipt_enabled: bool = Form(False),
    receipt_manifest: str = Form("", max_length=200),
) -> dict:
    provider = store.get_provider(provider_id)
    if provider is None:
        raise HTTPException(status_code=400, detail="请先在设置里添加模型商")
    selected = _selected_model(provider, model)
    if selected is None:
        raise HTTPException(status_code=400, detail="所选模型不在该模型商下")
    project = store.get_project(project_id)
    if project is None or not Path(project["source_dir"]).is_dir():
        raise HTTPException(status_code=400, detail="项目不存在或源码目录不可用")
    if project_id in _DELETING_PROJECTS or (project_id in _PROJECT_RUNNING and not _PROJECT_RUNNING[project_id].done()):
        raise HTTPException(status_code=409, detail="项目正在初始化或删除，请稍后创建审计")
    if (project.get("initialization") or {}).get("environment_status") != "ready":
        raise HTTPException(status_code=409, detail="请先完成项目环境初始化")
    if receipt_enabled:
        config_errors = receipt_configuration_errors(_runtime_receipt_config())
        if config_errors:
            raise HTTPException(status_code=409, detail="RECEIPT 配置不可用：" + "；".join(config_errors))
    target_url = ""
    selected_receipt_manifest = ""
    if receipt_enabled and receipt_manifest:
        try:
            manifest_path = receipt_manifest_path(receipt_manifest)
            manifest = load_manifest(manifest_path, RECEIPT_MANIFESTS_DIR)
            target_adapter_for(manifest, manifest_path.with_suffix("")) if manifest.adapter == "generic-compose" else target_adapter_for(manifest)
            selected_receipt_manifest = manifest_path.name
        except ReceiptError as exc:
            raise HTTPException(status_code=409, detail=f"验证器配置不可用：{exc}") from exc
    task_id = uuid4().hex
    if receipt_enabled and not selected_receipt_manifest:
        _require_generated_threat_model(project, project_id)
        generated = _project_environment_root(project_id) / "receipt-manifest.json"
        try:
            if (project.get("initialization") or {}).get("environment_status") != "ready":
                raise ReceiptError("项目环境尚未初始化成功")
            manifest = load_manifest(generated, generated.parent)
            target_adapter_for(manifest, generated.parent) if manifest.adapter == "generic-compose" else target_adapter_for(manifest)
            RECEIPT_MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)
            selected_receipt_manifest = f"task-{task_id}.json"
            if manifest.adapter == "generic-compose":
                if any(item.is_symlink() for item in generated.parent.rglob("*")):
                    raise ReceiptError("环境文件不能包含符号链接")
                shutil.copytree(generated.parent, RECEIPT_MANIFESTS_DIR / f"task-{task_id}")
            shutil.copyfile(generated, RECEIPT_MANIFESTS_DIR / selected_receipt_manifest)
        except (ReceiptError, OSError) as exc:
            remove_tree(RECEIPT_MANIFESTS_DIR / f"task-{task_id}", ignore_errors=True)
            raise HTTPException(status_code=409, detail=f"项目 RECEIPT Manifest 不可用：{exc}") from exc
    workspace = WORKSPACES_DIR / task_id
    workspace.mkdir(parents=True, exist_ok=False)
    task = {
        "id": task_id,
        "instruction": instruction.strip(),
        "base_url": target_url,
        "project_id": project_id,
        "project_name": project["name"],
        "source_dir": project["source_dir"],
        "provider_id": provider["id"],
        "provider_name": provider["name"],
        "model": selected["id"],
        "prices": {
            "input_per_mtok": selected["input_per_mtok"],
            "output_per_mtok": selected["output_per_mtok"],
            "cache_read_per_mtok": selected.get("cache_read_per_mtok", selected["input_per_mtok"]),
            "cache_write_per_mtok": selected.get("cache_write_per_mtok", selected["input_per_mtok"]),
        },
        "currency": normalize_currency(
            str(selected.get("currency") or "USD"),
        ),
        "budget": float(budget),
        "duration_seconds": int(duration_minutes) * 60,
        "completion_mode": completion_mode,
        "context_window_tokens": context_window_tokens,
        "compact_percent": compact_percent,
        "receipt_enabled": receipt_enabled,
        "receipt_manifest": selected_receipt_manifest,
        "generated_receipt_manifest": selected_receipt_manifest if selected_receipt_manifest == f"task-{task_id}.json" else "",
        "requires_environment_setup": True,
        "automatic_environment": True,
        "environment_ready": False,
        "environment_status": "pending",
        "status": "queued",
        "stop_reason": None,
        "pause_reason": None,
        "spent": 0.0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "round": 0,
        "artifact_counts": {"findings": 0, "pocs": 0},
        "created_at": now_iso(),
        "started_at": None,
        "finished_at": None,
        "paused_at": None,
        "paused_seconds": 0,
        "error": None,
        "workspace": str(workspace),
        "session_id": None,
        "next_seq": 1,
    }
    prepare_workspace(task)
    initialization = project.get("initialization") or {}
    if initialization.get("environment_status") in {"ready", "incomplete"}:
        source_environment = _project_environment_root(project_id)
        if source_environment.is_dir():
            for item in source_environment.rglob("*"):
                if item.is_symlink():
                    continue
                if item.relative_to(source_environment).as_posix() in {"threat-model.md", "INITIALIZATION_FAILED.md"}:
                    continue
                destination = workspace / "environment" / item.relative_to(source_environment)
                if item.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                elif item.is_file():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, destination)
    saved = store.add_task(task)
    _schedule_task(task_id)
    return saved


@app.get("/api/tasks/{task_id}")
def get_task(task_id: str) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return task


@app.post("/api/tasks/{task_id}/prepare")
async def prepare_task(task_id: str) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task_id in _DELETING_TASKS or task.get("project_id") in _DELETING_PROJECTS or task["status"] != "draft" or (task_id in _RUNNING and not _RUNNING[task_id].done()):
        raise HTTPException(status_code=409, detail="当前不能准备环境")
    store.update_task(task_id, status="preparing", environment_status="preparing", environment_ready=False, preparation_mode="manual", error=None)
    _schedule_task_preparation(task_id)
    return store.get_task(task_id)


def _receipt_preflight(task: dict) -> list[dict]:
    if not task.get("receipt_enabled"):
        return []
    try:
        path = receipt_manifest_path(str(task.get("receipt_manifest") or ""), manifests_root=RECEIPT_MANIFESTS_DIR)
        manifest = load_manifest(path, RECEIPT_MANIFESTS_DIR)
        target_adapter_for(manifest, path.with_suffix("")) if manifest.adapter == "generic-compose" else target_adapter_for(manifest)
        config_errors = receipt_configuration_errors(_runtime_receipt_config())
        if config_errors:
            raise ReceiptError("；".join(config_errors))
        return [{"id": "receipt", "ok": True, "message": "Manifest、Adapter、证据签名密钥和固定攻击者镜像已配置；静态检查不保证隔离重放成功"}]
    except ReceiptError as exc:
        return [{"id": "receipt", "ok": False, "message": f"RECEIPT 配置不可用：{exc}"}]


def _preflight(task: dict) -> list[dict]:
    return [*check_environment(Path(task["workspace"])), *_receipt_preflight(task)]


@app.post("/api/tasks/{task_id}/check")
def check_task(task_id: str, receipt_manifest: str = Form("")) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task["status"] != "draft":
        raise HTTPException(status_code=409, detail="仅可检查待准备任务")
    if task.get("receipt_enabled"):
        task = store.update_task(task_id, receipt_manifest=receipt_manifest.strip()) or task
    checks = _preflight(task)
    ready = all(item["ok"] for item in checks)
    store.update_task(task_id, environment_ready=ready, environment_status="ready" if ready else "pending")
    return {"ready": ready, "checks": checks, "workspace": task["workspace"], "notice": "仅检查文件存在和基本配置；不执行脚本，不证明环境、账号或验证链可用。"}


@app.post("/api/tasks/{task_id}/start")
async def start_task(task_id: str) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task_id in _SYNCING_TASKS:
        raise HTTPException(status_code=409, detail="正在同步 GitHub 源码，请稍候")
    if task.get("automatic_environment") and task["status"] == "draft" and task_id not in _DELETING_TASKS and task.get("project_id") not in _DELETING_PROJECTS:
        receipt_checks = _receipt_preflight(task)
        if not all(item["ok"] for item in receipt_checks):
            raise HTTPException(status_code=409, detail=receipt_checks[0]["message"])
    elif task_id in _DELETING_TASKS or task.get("project_id") in _DELETING_PROJECTS or task["status"] != "draft" or not task.get("environment_ready") or not all(item["ok"] for item in _preflight(task)):
        raise HTTPException(status_code=409, detail="请先完成环境检查")
    project = store.get_project(task.get("project_id", ""))
    sync_fields = {}
    if project and project.get("github_url"):
        _SYNCING_TASKS.add(task_id)
        project_dir = _owned_directory(PROJECTS_DIR, task["project_id"])
        destination = project_dir / "snapshots" / task_id
        (Path(task["workspace"]) / "github-changes.json").unlink(missing_ok=True)
        try:
            counts = await _sync_github_source(project, destination)
            sync_fields = {"source_dir": str(destination), "github_updated": any(counts.values()), "github_change_counts": counts}
        except (ProjectImportError, OSError, ValueError, TypeError) as exc:
            remove_tree(destination, ignore_errors=True)
            raise HTTPException(status_code=502, detail=f"GitHub 源码同步失败：{exc}") from exc
        finally:
            _SYNCING_TASKS.discard(task_id)
    updated = store.update_task(task_id, status="queued", error=None, **sync_fields)
    _schedule_task(task_id)
    return updated


@app.get("/api/tasks/{task_id}/reports")
def task_reports(task_id: str) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    receipt_enabled = bool(task.get("receipt_enabled", False))
    roles_by_manifest = {}
    if receipt_enabled and (manifest_name := task.get("receipt_manifest")):
        try:
            manifest_path = receipt_manifest_path(manifest_name, manifests_root=RECEIPT_MANIFESTS_DIR)
            manifest = load_manifest(manifest_path, RECEIPT_MANIFESTS_DIR)
        except ReceiptError:
            pass
        else:
            roles_by_manifest[manifest.manifest_hash] = load_principal_roles(manifest, manifest_path)
    reports = list_reports(Path(task["workspace"]), receipt_enabled, roles_by_manifest=roles_by_manifest)
    return {"reports": [report.as_mapping() for report in reports]}


class HumanReviewIn(BaseModel):
    path: str
    status: Literal["unreviewed", "confirmed", "false_positive", "uncertain"]
    comment: str = Field(default="", max_length=8000)


@app.put("/api/tasks/{task_id}/reports/human-review")
def update_human_review(task_id: str, body: HumanReviewIn) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    try:
        return save_human_review(Path(task["workspace"]), body.path, body.status, body.comment)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/receipt/manifests")
def list_receipt_manifests() -> list[dict]:
    if not RECEIPT_MANIFESTS_DIR.is_dir():
        return []
    manifests: list[dict] = []
    for path in sorted(RECEIPT_MANIFESTS_DIR.glob("*.json")):
        if not path.is_file() or path.name.startswith("task-"):
            continue
        try:
            manifest = load_manifest(path, RECEIPT_MANIFESTS_DIR)
            target_adapter_for(manifest, path.with_suffix("")) if manifest.adapter == "generic-compose" else target_adapter_for(manifest)
        except ReceiptError:
            continue
        manifests.append({"name": path.name, "size": path.stat().st_size, "mtime": path.stat().st_mtime})
    return manifests


@app.post("/api/tasks/{task_id}/receipt/verify")
async def verify_receipt_poc(task_id: str, body: ReceiptVerifyIn) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if not task.get("receipt_enabled", False):
        raise HTTPException(status_code=409, detail="此任务未启用验证器")
    manifest_name = str(task.get("receipt_manifest") or "")
    if not manifest_name:
        raise HTTPException(status_code=409, detail="此任务未绑定可信 RECEIPT Manifest")
    from app.receipt_selector import describe_selected_paths
    from app.runner import _emit

    preferred: tuple[str, ...] = ()
    # A running audit owns its in-memory usage ledger; avoid racing its accounting.
    if task.get("status") not in {"running", "preparing", "pause_requested", "cancel_requested"}:
        provider = store.get_provider(str(task.get("provider_id") or ""))
        report = next((item for item in list_reports(Path(task["workspace"]), True) if item.poc_id == body.poc_id), None)
        if provider and report and task.get("prices") and task.get("model"):
            from app.pricing import Ledger, Prices, UsageAccumulator
            from app.receipt_selector import select_receipt_paths
            from app.runner import _apply_result, _usage_snapshot

            ledger = Ledger.from_snapshot(task)
            prices = Prices.from_mapping(task["prices"])
            pending = UsageAccumulator.from_snapshot(task.get("usage_pending"))

            def account_usage(message: object) -> None:
                _apply_result(ledger, message, prices, UsageAccumulator())
                store.update_task(task_id, **_usage_snapshot(ledger, pending, prices))

            preferred = await select_receipt_paths(Path(task["workspace"]), str(task["base_url"]), manifest_name,
                                                   body.poc_id, report.path, task, provider, account_usage)
    if preferred:
        for description in describe_selected_paths(manifest_name, preferred):
            _emit(store, hub, task_id, "receipt", f"RECEIPT {body.poc_id} 选择的验证路径：{description}")
    else:
        _emit(store, hub, task_id, "receipt", f"RECEIPT {body.poc_id} 未选择验证路径，本次不执行验证")
    try:
        execution = await asyncio.to_thread(
            verify_receipt_candidate,
            Path(task["workspace"]),
            str(task["base_url"]),
            manifest_name,
            body.poc_id,
            runtime_config=_runtime_receipt_config(),
            preferred_path_ids=preferred,
        )
    except ReceiptError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    update_review_for_poc(Path(task["workspace"]), body.poc_id, execution.result["verdict"])
    return {"result": execution.result, "artifact": execution.artifact, "feedback": execution.agent_feedback}


@app.post("/api/tasks/{task_id}/pause")
async def pause_task(task_id: str) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task["status"] in _TERMINAL_STATUSES:
        return task
    if task["status"] == "paused":
        return task
    if task["status"] == "pause_requested":
        return task
    if task["status"] not in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="当前任务不能暂停")
    store.update_task(
        task_id,
        status="pause_requested",
        pause_reason="manual",
        paused_at=task.get("paused_at") or now_iso(),
        stop_reason=None,
        error=None,
        finished_at=None,
    )
    request_stop(task_id, "paused")
    updated = store.get_task(task_id)
    return updated or task


@app.post("/api/tasks/{task_id}/resume")
async def resume_task(task_id: str) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task_id in _DELETING_TASKS or task.get("project_id") in _DELETING_PROJECTS:
        raise HTTPException(status_code=409, detail="任务或项目正在删除")
    if task["status"] in _TERMINAL_STATUSES or task["status"] in {"queued", "running"}:
        return task
    if task["status"] == "pause_requested":
        raise HTTPException(status_code=409, detail="任务仍在暂停中，请稍后再试")
    if task["status"] != "paused":
        raise HTTPException(status_code=409, detail="当前任务不能继续")
    if task.get("pause_reason") == "quota":
        raise HTTPException(status_code=409, detail="模型商额度尚未恢复，任务会自动继续")

    existing = _RUNNING.get(task_id)
    if existing is not None and not existing.done():
        try:
            await asyncio.wait_for(asyncio.shield(existing), timeout=5)
        except TimeoutError as exc:
            raise HTTPException(status_code=409, detail="任务仍在暂停中，请稍后再试") from exc
    if task_id in _DELETING_TASKS or task.get("project_id") in _DELETING_PROJECTS or store.get_task(task_id) is None:
        raise HTTPException(status_code=409, detail="任务或项目正在删除")
    store.settle_pause(task_id)
    updated = store.update_task(
        task_id,
        status="queued",
        pause_reason=None,
        paused_at=None,
        stop_reason=None,
        error=None,
        finished_at=None,
    )
    _schedule_task(task_id)
    return updated or task


@app.post("/api/tasks/{task_id}/stop")
async def stop_task(task_id: str) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task["status"] in _TERMINAL_STATUSES or task["status"] == "cancel_requested":
        return task
    if task["status"] == "pause_requested":
        raise HTTPException(status_code=409, detail="任务正在暂停，请稍后停止本轮")
    if task["status"] not in {"queued", "running", "paused"}:
        raise HTTPException(status_code=409, detail="当前任务不能停止")
    if task["status"] == "paused" and task.get("pause_reason") != "quota":
        existing = _RUNNING.get(task_id)
        if existing is not None and not existing.done():
            try:
                await asyncio.wait_for(asyncio.shield(existing), timeout=5)
            except TimeoutError as exc:
                raise HTTPException(status_code=409, detail="任务仍在暂停中，请稍后再试") from exc
        store.settle_pause(task_id)
        store.update_task(task_id, status="cancel_requested", pause_reason=None)
        cleanup_error = None
        if task.get("environment_run_id"):
            try:
                ok, detail = await stop_audit_environment(task)
            except Exception as exc:
                ok, detail = False, str(exc)
            if ok:
                store.update_task(task_id, environment_ready=False, environment_status="stopped")
            else:
                cleanup_error = f"停止靶场环境失败：{detail}"
                store.update_task(task_id, environment_status="cleanup_failed")
        _finish(store, hub, task_id, "cancelled", "cancelled", "本轮审计已停止")
        if cleanup_error:
            store.update_task(task_id, error=cleanup_error)
        return store.get_task(task_id) or task
    updated = store.update_task(task_id, status="cancel_requested", pause_reason=None, error=None)
    request_stop(task_id, "cancelled")
    return updated or task


@app.post("/api/tasks/{task_id}/follow-up")
async def follow_up_task(task_id: str, body: FollowUpIn) -> dict:
    return await _queue_follow_up(task_id, body, pending_reports=None)


@app.post("/api/tasks/{task_id}/review-pending")
async def review_pending_task(task_id: str, body: PendingReviewIn) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if not task.get("receipt_enabled"):
        raise HTTPException(status_code=409, detail="此任务未启用验证器")
    reports = [report.path for report in list_reports(Path(task["workspace"]), True) if report.review_status != "passed"]
    return await _queue_report_review(task_id, body, reports, "重新验证所有未审核通过的报告")


@app.post("/api/tasks/{task_id}/review-all")
async def review_all_task(task_id: str, body: PendingReviewIn) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if not task.get("receipt_enabled"):
        raise HTTPException(status_code=409, detail="此任务未启用验证器")
    reports = [report.path for report in list_reports(Path(task["workspace"]), True)]
    return await _queue_report_review(task_id, body, reports, "重新验证所有报告")


async def _queue_report_review(task_id: str, body: PendingReviewIn, reports: list[str], instruction: str) -> dict:
    if not reports:
        raise HTTPException(status_code=409, detail="没有需要验证的报告")
    return await _queue_follow_up(
        task_id,
        FollowUpIn(
            instruction=instruction,
            budget=body.budget,
            duration_minutes=body.duration_minutes,
        ),
        pending_reports=reports,
    )


async def _queue_follow_up(task_id: str, body: FollowUpIn, pending_reports: list[str] | None) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if not body.instruction.strip():
        raise HTTPException(status_code=422, detail="请输入后续指令")
    if task_id in _DELETING_TASKS or task.get("project_id") in _DELETING_PROJECTS:
        raise HTTPException(status_code=409, detail="任务或项目正在删除")
    if task["status"] not in _TERMINAL_STATUSES:
        raise HTTPException(status_code=409, detail="任务结束后才能提交后续指令")
    existing = _RUNNING.get(task_id)
    if existing is not None and not existing.done():
        raise HTTPException(status_code=409, detail="任务仍在清理环境，请稍后再试")
    if task.get("environment_status") == "cleanup_failed":
        raise HTTPException(status_code=409, detail="上次环境清理失败，请先清理环境")
    _refresh_follow_up_environment(task)
    finished = task.get("finished_at")
    finished_at = datetime.fromisoformat(finished) if finished and task.get("started_at") else None
    if finished_at is not None and finished_at.tzinfo is None:
        finished_at = finished_at.replace(tzinfo=timezone.utc)
    downtime = max(0.0, (datetime.now(timezone.utc) - finished_at).total_seconds()) if finished_at else 0.0
    updated = store.queue_follow_up(
        task_id, stop_reason=None, pause_reason=None, paused_at=None,
        paused_seconds=float(task.get("paused_seconds") or 0) + downtime,
        finished_at=None, error=None, session_id=None,
        last_tool_fingerprint=None,
        follow_up_instruction=body.instruction.strip(), follow_up_new_round=True,
        pending_review_reports=pending_reports,
        budget=float(task["budget"]) + body.budget,
        duration_seconds=int(task["duration_seconds"]) + body.duration_minutes * 60,
        environment_ready=False,
    )
    if updated is None:
        raise HTTPException(status_code=409, detail="任务状态已变化，请刷新后重试")
    _schedule_task(task_id)
    return updated


@app.post("/api/tasks/{task_id}/cancel", deprecated=True)
async def cancel_task(task_id: str) -> dict:
    return await pause_task(task_id)


def _safe_artifact(workspace: Path, relative: str) -> Path:
    if relative.startswith("/") or ".." in Path(relative).parts:
        raise HTTPException(status_code=400, detail="路径无效")
    allowed = relative == "TASK.md" or relative == "ARTIFACTS.md" or relative.startswith(("findings/", "poc/", "notes/", "receipt/"))
    if not allowed or relative.endswith("accounts.json"):
        raise HTTPException(status_code=404, detail="文件不存在")
    path = (workspace / relative).resolve()
    try:
        path.relative_to(workspace.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="路径无效") from exc
    if not path.is_file():
        raise HTTPException(status_code=404, detail="文件不存在")
    return path


@app.get("/api/tasks/{task_id}/artifacts")
def list_artifacts(task_id: str) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    workspace = Path(task["workspace"])
    files = []
    for relative in ("TASK.md", "ARTIFACTS.md"):
        path = workspace / relative
        if path.is_file():
            files.append(_file_row(workspace, path))
    for folder in ("findings", "poc", "notes", "receipt"):
        directory = workspace / folder
        if not directory.is_dir():
            continue
        for path in sorted(item for item in directory.rglob("*") if item.is_file() and _is_text_artifact(item)):
            files.append(_file_row(workspace, path))
    return {"files": files}


def _is_text_artifact(path: Path) -> bool:
    if "__pycache__" in path.parts or path.suffix.lower() in {".pyc", ".pyo"}:
        return False
    return True


def _file_row(workspace: Path, path: Path) -> dict:
    stat = path.stat()
    return {
        "path": path.relative_to(workspace).as_posix(),
        "size": stat.st_size,
        "mtime": stat.st_mtime,
    }


@app.get("/api/tasks/{task_id}/artifacts/content")
def artifact_content(task_id: str, path: str) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    file_path = _safe_artifact(Path(task["workspace"]), path)
    if file_path.stat().st_size > 512_000:
        raise HTTPException(status_code=400, detail="文件过大")
    return {"path": path, "content": file_path.read_text(encoding="utf-8", errors="replace")}


@app.get("/api/tasks/{task_id}/events/older")
def older_events(task_id: str, before: int, limit: int = 100) -> dict:
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    limit = min(max(limit, 1), 100)
    found = read_events(Path(task["workspace"]), 0, limit=limit + 1, before=before)
    has_more = len(found) > limit
    return {"events": found[-limit:] if has_more else found, "has_more": has_more}


@app.get("/api/tasks/{task_id}/events")
async def task_events(task_id: str, after: int = 0):
    task = store.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return _event_stream(task_id, Path(task["workspace"]), after)


@app.get("/api/projects/{project_id}/events/older")
def older_project_events(project_id: str, before: int, limit: int = 100) -> dict:
    project = store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    limit = min(max(limit, 1), 100)
    workspace = PROJECTS_DIR / project_id / "setup"
    found = read_events(workspace, 0, limit=limit + 1, before=before)
    has_more = len(found) > limit
    return {"events": found[-limit:] if has_more else found, "has_more": has_more}


@app.post("/api/projects/{project_id}/threat-model/acknowledge")
def acknowledge_threat_model(project_id: str) -> dict:
    project = store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    initialization = project.get("initialization") or {}
    if initialization.get("environment_status") != "ready":
        raise HTTPException(status_code=409, detail="请先完成项目环境初始化")
    from app.threat_model import evaluate_threat_model

    report = evaluate_threat_model(_project_environment_root(project_id), Path(project["source_dir"]))
    if not report.ok:
        raise HTTPException(status_code=409, detail=("威胁模型闭包未通过：" + "；".join(report.messages))[:1500])
    store.update_project_initialization(
        project_id,
        coverage_status=report.coverage_status,
        threat_model_digest=report.digest,
        threat_model_review=report.review_items,
        threat_model_ack={"digest": report.digest, "acknowledged_at": now_iso(), "coverage_status": report.coverage_status},
    )
    current = store.get_project(project_id)
    if current is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    return current


class ThreatRoleEdit(BaseModel):
    digest: str
    disposition: Literal["include", "victim_only", "exclude"]
    reason: str = Field(max_length=8000)
    evidence_kind: Literal["source", "official_doc", "historical_advisory", "assumption"]
    evidence_path: str = Field(max_length=2000)
    evidence_literal: str = Field(max_length=2000)


def _editable_threat_model(project_id: str) -> tuple[dict, Path, object]:
    from app.threat_model import evaluate_threat_model

    project = store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    if (project.get("initialization") or {}).get("environment_status") != "ready":
        raise HTTPException(status_code=409, detail="请先完成项目环境初始化")
    environment = _project_environment_root(project_id)
    report = evaluate_threat_model(environment, Path(project["source_dir"]))
    if not report.ok:
        raise HTTPException(status_code=409, detail="威胁模型闭包未通过：" + "；".join(report.messages))
    return project, environment, report


@app.get("/api/projects/{project_id}/threat-model/roles")
def get_threat_model_roles(project_id: str) -> dict:
    _, environment, report = _editable_threat_model(project_id)
    decisions = json.loads((environment / "threat-decisions.json").read_text(encoding="utf-8"))
    return {"digest": report.digest, "roles": decisions["roles"]}


@app.put("/api/projects/{project_id}/threat-model/roles/{role_id}")
def edit_threat_model_role(project_id: str, role_id: str, body: ThreatRoleEdit) -> dict:
    from app.threat_model import evaluate_threat_model

    project, environment, current = _editable_threat_model(project_id)
    if body.digest != current.digest:
        raise HTTPException(status_code=409, detail="威胁模型已变化，请重新加载后编辑")
    decision_file = environment / "threat-decisions.json"
    decisions = json.loads(decision_file.read_text(encoding="utf-8"))
    role = next((item for item in decisions["roles"] if item["id"] == role_id), None)
    if role is None:
        raise HTTPException(status_code=404, detail="角色不存在")
    evidence = {"kind": body.evidence_kind, "path": body.evidence_path.strip(), "literal": body.evidence_literal.strip()}
    if body.evidence_kind == "source":
        root = Path(project["source_dir"]).resolve()
        target = (root / evidence["path"]).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            raise HTTPException(status_code=400, detail="源码证据路径必须指向导入源码内的文件")
        try:
            if not evidence["literal"] or evidence["literal"] not in target.read_text(encoding="utf-8"):
                raise HTTPException(status_code=400, detail="源码证据字面量未在文件中找到")
        except (OSError, UnicodeError):
            raise HTTPException(status_code=400, detail="无法读取源码证据文件")
    role.update(disposition=body.disposition, reason=body.reason.strip(), evidence=evidence)
    payload = json.dumps(decisions, ensure_ascii=False, indent=2) + "\n"
    with tempfile.TemporaryDirectory(prefix="threat-model-") as temporary:
        staging = Path(temporary)
        for name in ("account-plan.json", "receipt-manifest.json", "create-accounts.py"):
            shutil.copy2(environment / name, staging / name)
        (staging / "threat-decisions.json").write_text(payload, encoding="utf-8")
        report = evaluate_threat_model(staging, Path(project["source_dir"]))
        if not report.ok:
            raise HTTPException(status_code=400, detail="修改与现有模型不一致：" + "；".join(report.messages))
        fd, name = tempfile.mkstemp(prefix=".threat-decisions-", suffix=".tmp", dir=environment)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
            os.replace(name, decision_file)
        finally:
            Path(name).unlink(missing_ok=True)
    checks = [report.as_check() if item.get("id") == "threat_coverage" else item for item in (project.get("initialization") or {}).get("checks", [])]
    store.update_project_initialization(project_id, coverage_status=report.coverage_status, threat_model_digest=report.digest, threat_model_review=report.review_items, threat_model_ack=None, checks=checks)
    return {"project": store.get_project(project_id), "digest": report.digest}


@app.get("/api/projects/{project_id}/environment")
def project_environment_files(project_id: str) -> dict:
    if store.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    root = _project_environment_root(project_id)
    files = []
    if root.is_dir():
        for path in sorted(root.rglob("*")):
            if path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root.resolve()) and path.stat().st_size <= 1_000_000:
                files.append(path.relative_to(root).as_posix())
    return {"files": files}


@app.get("/api/projects/{project_id}/environment/content")
def project_environment_content(project_id: str, path: str) -> dict:
    if store.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    root = _project_environment_root(project_id)
    requested = root / path
    resolved = requested.resolve()
    if not resolved.is_relative_to(root.resolve()) or not requested.is_file() or requested.is_symlink() or requested.stat().st_size > 1_000_000:
        raise HTTPException(status_code=404, detail="文件不存在")
    return {"path": path, "content": requested.read_text(encoding="utf-8", errors="replace")}


@app.get("/api/projects/{project_id}/events")
async def project_events(project_id: str, after: int = 0):
    if store.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    return _event_stream(f"project:{project_id}", PROJECTS_DIR / project_id / "setup", after)


def _event_stream(task_id: str, workspace: Path, after: int):

    async def generate():
        queue = hub.subscribe(task_id)
        last = after
        try:
            for event in read_events(workspace, after, limit=100):
                last = max(last, int(event["seq"]))
                yield _sse(event)
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                if event.get("type") in {"model_stream", "model_stream_end", "model_progress"}:
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                    continue
                if int(event["seq"]) <= last:
                    continue
                last = int(event["seq"])
                yield _sse(event)
                if event.get("type") == "done":
                    break
        finally:
            hub.unsubscribe(task_id, queue)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _sse(event: dict) -> str:
    return f"id: {event['seq']}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=False)
