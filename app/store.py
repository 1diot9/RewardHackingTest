from __future__ import annotations

import copy
import json
import threading
from datetime import datetime, timezone
from os import SEEK_END
from pathlib import Path

from app.config import DATA_DIR, STATE_PATH


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def active_seconds(task: dict, at: datetime | None = None) -> float:
    started = _parse_iso(task.get("started_at"))
    if started is None:
        return 0.0
    end = _parse_iso(task.get("finished_at")) or at or datetime.now(timezone.utc)
    paused_at = _parse_iso(task.get("paused_at"))
    if paused_at is not None:
        end = min(end, paused_at)
    paused = float(task.get("paused_seconds") or 0)
    return max(0.0, (end - started).total_seconds() - paused)


class Store:
    def __init__(self, path: Path = STATE_PATH) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._data: dict = {"providers": [], "tasks": [], "projects": [], "receipt_settings": {}}
        self.load()

    def load(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_file():
            self._data = json.loads(self.path.read_text(encoding="utf-8"))
            self._data.setdefault("providers", [])
            self._data.setdefault("tasks", [])
            self._data.setdefault("projects", [])
            if not isinstance(self._data.get("receipt_settings"), dict):
                self._data["receipt_settings"] = {}
        if "model_prices" not in self._data:
            prices = {}
            for provider in self._data["providers"]:
                for model in provider.get("models", []):
                    prices.setdefault(model["id"], {**model, "currency": provider.get("currency", "USD")})
            self._data["model_prices"] = list(prices.values())

    def get_receipt_settings(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._data.get("receipt_settings") or {})

    def get_proxy_settings(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._data.get("proxy_settings") or {"enabled": False, "url": "", "no_proxy": ""})

    def set_proxy_settings(self, settings: dict) -> dict:
        with self._lock:
            self._data["proxy_settings"] = copy.deepcopy(settings)
            self._save()
            return copy.deepcopy(settings)

    def get_max_concurrent(self, default: int) -> int:
        with self._lock:
            value = self._data.get("max_concurrent")
            return value if type(value) is int and value >= 1 else default

    def set_max_concurrent(self, value: int) -> None:
        with self._lock:
            self._data["max_concurrent"] = value
            self._save()

    def set_receipt_settings(self, settings: dict) -> dict:
        with self._lock:
            self._data["receipt_settings"] = copy.deepcopy(settings)
            self._save()
            return copy.deepcopy(self._data["receipt_settings"])

    def list_model_prices(self) -> list[dict]:
        with self._lock:
            return copy.deepcopy(self._data["model_prices"])

    def set_model_prices(self, prices: list[dict]) -> list[dict]:
        with self._lock:
            self._data["model_prices"] = copy.deepcopy(prices)
            self._save()
            return copy.deepcopy(prices)

    def _save(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(self._data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def recover_interrupted(self) -> list[str]:
        with self._lock:
            changed = False
            runnable: list[str] = []
            recovered_at = datetime.now(timezone.utc)
            for project in self._data["projects"]:
                initialization = project.get("initialization")
                if initialization and initialization.get("status") == "stop_requested":
                    initialization.update(status="stopped", environment_status="stopped", error=None)
                    changed = True
                if initialization and initialization.get("status") == "pause_requested":
                    initialization.update(status="paused", environment_status="paused", error=None)
                    changed = True
                if initialization and initialization.get("status") == "preparing":
                    initialization.update(environment_status="preparing", pause_reason=None, error=None)
                    changed = True
                elif initialization and initialization.get("status") == "paused" and initialization.get("pause_reason") == "restart":
                    initialization.update(status="preparing", environment_status="preparing", pause_reason=None, error=None)
                    changed = True
            for task in self._data["tasks"]:
                status = task["status"]
                if status == "preparing":
                    if task.get("automatic_environment") and task.get("environment_ready") and not task.get("preparation_mode"):
                        task.update(status="paused", pause_reason="manual", paused_at=recovered_at.isoformat(), environment_ready=False, error=None)
                    elif task.get("preparation_mode") == "audit":
                        task.update(status="queued", error=None)
                        runnable.append(task["id"])
                    else:
                        task.update(environment_status="preparing", error=None)
                    changed = True
                    continue
                if status == "cancel_requested":
                    task.update(status="cancelled", stop_reason="cancelled", pause_reason=None, finished_at=recovered_at.isoformat())
                    changed = True
                    continue
                if status == "pause_requested":
                    reason = task.get("pause_reason") or "manual"
                    task.update(
                        status="paused",
                        pause_reason=reason,
                        paused_at=task.get("paused_at") or recovered_at.isoformat(),
                        stop_reason=None,
                        error=None,
                        finished_at=None,
                    )
                    if reason != "manual":
                        self._settle_pause(task, recovered_at)
                        task.update(status="queued", pause_reason=None, paused_at=recovered_at.isoformat())
                        runnable.append(task["id"])
                    changed = True
                    continue
                if status in {"queued", "running"}:
                    if status == "running":
                        checkpoint = _parse_iso(task.get("clock_checkpoint_at"))
                        started = _parse_iso(task.get("started_at"))
                        if checkpoint and checkpoint <= recovered_at and (started is None or checkpoint >= started):
                            task["paused_at"] = checkpoint.isoformat()
                    task.update(
                        status="queued",
                        pause_reason=None,
                        stop_reason=None,
                        error=None,
                        finished_at=None,
                    )
                    runnable.append(task["id"])
                    changed = True
                    continue
                if status != "paused":
                    continue
                reason = task.get("pause_reason") or "quota"
                if reason == "manual":
                    task["pause_reason"] = "manual"
                    changed = True
                    continue
                self._settle_pause(task, recovered_at)
                task.update(
                    status="queued",
                    pause_reason=None,
                    paused_at=recovered_at.isoformat(),
                    stop_reason=None,
                    error=None,
                    finished_at=None,
                )
                runnable.append(task["id"])
                changed = True
            if changed:
                self._save()
            return runnable

    def checkpoint_running_clock(self, task_id: str) -> None:
        with self._lock:
            task = self._find(task_id)
            if task is not None and task.get("status") == "running":
                task["clock_checkpoint_at"] = now_iso()
                self._save()

    def start_running_clock(self, task_id: str) -> dict | None:
        with self._lock:
            task = self._find(task_id)
            if task is None or task.get("status") != "queued":
                return copy.deepcopy(task)
            at = datetime.now(timezone.utc)
            self._settle_pause(task, at)
            task.update(status="running", pause_reason=None, started_at=task.get("started_at") or at.isoformat(),
                        clock_checkpoint_at=at.isoformat(), finished_at=None, error=None)
            self._save()
            return copy.deepcopy(task)

    def settle_pause(self, task_id: str, at: datetime | None = None) -> dict | None:
        with self._lock:
            task = self._find(task_id)
            if task is None:
                return None
            self._settle_pause(task, at or datetime.now(timezone.utc))
            self._save()
            return copy.deepcopy(task)

    @staticmethod
    def _settle_pause(task: dict, at: datetime) -> None:
        paused_at = _parse_iso(task.get("paused_at"))
        if paused_at is not None:
            held = max(0.0, (at - paused_at).total_seconds())
            task["paused_seconds"] = int(task.get("paused_seconds") or 0) + int(held)
        task["paused_at"] = None

    def list_providers(self) -> list[dict]:
        with self._lock:
            return copy.deepcopy(self._data["providers"])

    def get_provider(self, provider_id: str) -> dict | None:
        with self._lock:
            for provider in self._data["providers"]:
                if provider["id"] == provider_id:
                    return copy.deepcopy(provider)
            return None

    def upsert_provider(self, provider: dict) -> dict:
        with self._lock:
            for index, current in enumerate(self._data["providers"]):
                if current["id"] == provider["id"]:
                    self._data["providers"][index] = provider
                    self._save()
                    return copy.deepcopy(provider)
            self._data["providers"].append(provider)
            self._save()
            return copy.deepcopy(provider)

    def delete_provider(self, provider_id: str) -> bool:
        with self._lock:
            before = len(self._data["providers"])
            self._data["providers"] = [
                item for item in self._data["providers"] if item["id"] != provider_id
            ]
            if len(self._data["providers"]) == before:
                return False
            self._save()
            return True

    def list_projects(self) -> list[dict]:
        with self._lock:
            return copy.deepcopy(self._data["projects"])

    def get_project(self, project_id: str) -> dict | None:
        return next((item for item in self.list_projects() if item["id"] == project_id), None)

    def add_project(self, project: dict) -> dict:
        with self._lock:
            self._data["projects"].append(project)
            self._save()
            return copy.deepcopy(project)

    def update_project(self, project_id: str, **fields: object) -> dict | None:
        with self._lock:
            project = next((item for item in self._data["projects"] if item["id"] == project_id), None)
            if project is None:
                return None
            project.update(fields)
            self._save()
            return copy.deepcopy(project)

    def set_project_initialization(self, project_id: str, initialization: dict) -> dict | None:
        with self._lock:
            project = next((item for item in self._data["projects"] if item["id"] == project_id), None)
            if project is None:
                return None
            project["initialization"] = copy.deepcopy(initialization)
            self._save()
            return copy.deepcopy(project)

    def update_project_initialization(self, project_id: str, **fields: object) -> dict | None:
        with self._lock:
            project = next((item for item in self._data["projects"] if item["id"] == project_id), None)
            if project is None or "initialization" not in project:
                return None
            project["initialization"].update(fields)
            self._save()
            return copy.deepcopy(project["initialization"])

    def append_project_event(self, project_id: str, payload: dict) -> dict | None:
        with self._lock:
            project = next((item for item in self._data["projects"] if item["id"] == project_id), None)
            if project is None or "initialization" not in project:
                return None
            initialization = project["initialization"]
            event = {**payload, "seq": initialization.get("next_seq", 1), "ts": now_iso()}
            initialization["next_seq"] = event["seq"] + 1
            self._save()
            path = Path(initialization["workspace"]) / "events.jsonl"
            _append_event_line(path, event)
            return event

    def delete_task(self, task_id: str) -> bool:
        with self._lock:
            before = len(self._data["tasks"])
            self._data["tasks"] = [item for item in self._data["tasks"] if item["id"] != task_id]
            if before == len(self._data["tasks"]):
                return False
            self._save()
            return True

    def delete_project(self, project_id: str) -> bool:
        with self._lock:
            before = len(self._data["projects"])
            self._data["projects"] = [item for item in self._data["projects"] if item["id"] != project_id]
            if before == len(self._data["projects"]):
                return False
            self._data["tasks"] = [item for item in self._data["tasks"] if item.get("project_id") != project_id]
            self._save()
            return True

    def list_tasks(self) -> list[dict]:
        with self._lock:
            tasks = copy.deepcopy(self._data["tasks"])
        tasks.sort(key=lambda item: item.get("created_at") or "", reverse=True)
        return tasks

    def get_task(self, task_id: str) -> dict | None:
        with self._lock:
            for task in self._data["tasks"]:
                if task["id"] == task_id:
                    return copy.deepcopy(task)
            return None

    def add_task(self, task: dict) -> dict:
        with self._lock:
            self._data["tasks"].append(task)
            self._save()
            return copy.deepcopy(task)

    def update_task(self, task_id: str, **fields: object) -> dict | None:
        with self._lock:
            task = self._find(task_id)
            if task is None:
                return None
            incoming_status = fields.get("status")
            if task["status"] in {"pause_requested", "cancel_requested"} and incoming_status in {"running", "queued", "preparing"}:
                fields = {key: value for key, value in fields.items() if key != "status"}
            if task["status"] in {"completed", "budget_exhausted", "time_exhausted", "cancelled", "error"}:
                if incoming_status and incoming_status != task["status"]:
                    fields = {key: value for key, value in fields.items() if key != "status"}
            task.update(fields)
            self._save()
            return copy.deepcopy(task)

    def queue_follow_up(self, task_id: str, **fields: object) -> dict | None:
        """仅将已结束任务转换为后续任务，防止重复提交。"""
        with self._lock:
            task = self._find(task_id)
            if task is None or task["status"] not in {"completed", "budget_exhausted", "time_exhausted", "cancelled", "error"}:
                return None
            task.update(fields, status="queued")
            self._save()
            return copy.deepcopy(task)

    def append_event(self, task_id: str, payload: dict) -> dict | None:
        with self._lock:
            task = self._find(task_id)
            if task is None:
                return None
            event = {
                **payload,
                "seq": task["next_seq"],
                "ts": now_iso(),
            }
            task["next_seq"] = int(task["next_seq"]) + 1
            self._save()
            workspace = Path(task["workspace"])
            round_number = int(task.get("round") or 0)
            path = (workspace / "logs" / f"round-{round_number:03d}.jsonl"
                    if round_number > 0 else workspace / "events.jsonl")
            _append_event_line(path, event)
            return event

    def _find(self, task_id: str) -> dict | None:
        for task in self._data["tasks"]:
            if task["id"] == task_id:
                return task
        return None


def _append_event_line(path: Path, event: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8")
    with path.open("a+b") as handle:
        if handle.seek(0, SEEK_END):
            handle.seek(-1, SEEK_END)
            if handle.read(1) != b"\n":
                # A stopped process may have left an incomplete record at EOF.
                line = b"\n" + line
        handle.write(line)


def read_events(
    workspace: Path,
    after: int,
    limit: int | None = None,
    before: int | None = None,
) -> list[dict]:
    paths = [workspace / "events.jsonl", *sorted((workspace / "logs").glob("round-*.jsonl"))]
    events: list[dict] = []
    for path in paths:
        if not path.is_file():
            continue
        with path.open("rb") as handle:
            for line in handle:
                try:
                    event = json.loads(line.decode("utf-8"))
                    seq = int(event.get("seq") or 0) if isinstance(event, dict) else 0
                except (ValueError, TypeError, OverflowError):
                    continue
                if seq <= after:
                    continue
                if before is not None and seq >= before:
                    continue
                events.append(event)
    events.sort(key=lambda event: int(event.get("seq") or 0))
    if limit is not None and limit >= 0 and len(events) > limit:
        return events[-limit:]
    return events
