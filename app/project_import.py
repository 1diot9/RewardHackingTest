from __future__ import annotations

import os
import hashlib
import posixpath
import re
import shutil
import stat
import uuid
import zipfile
import tempfile
import time
from collections import defaultdict, deque
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.parse import urlsplit
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

MAX_PROJECT_FILES = 100_000
MAX_UNPACKED_BYTES = 250 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 250 * 1024 * 1024


class ProjectImportError(ValueError):
    """The uploaded archive cannot become an isolated source tree."""


@dataclass(frozen=True)
class ImportedProject:
    source_dir: Path
    project_name: str
    file_count: int
    unpacked_bytes: int


def import_project_zip(archive: BinaryIO, destination: Path, filename: str, *, strip_root: bool = False) -> ImportedProject:
    """Validate and atomically extract a source ZIP into a task-owned directory."""
    if not filename.lower().endswith(".zip"):
        raise ProjectImportError("项目文件必须是 ZIP 压缩包")
    try:
        archive.seek(0)
        bundle = zipfile.ZipFile(archive)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ProjectImportError("项目压缩包已损坏或不是有效 ZIP") from exc

    try:
        members = bundle.infolist()
        _validate_entries(members, allow_links=strip_root)
        entries = [entry for entry in members if not entry.is_dir()]
        if not entries:
            raise ProjectImportError("项目压缩包不能为空")
        if len(entries) > MAX_PROJECT_FILES:
            raise ProjectImportError(f"项目压缩包最多包含 {MAX_PROJECT_FILES} 个文件")
        unpacked_bytes = sum(entry.file_size for entry in entries)
        if unpacked_bytes > MAX_UNPACKED_BYTES:
            raise ProjectImportError("项目解压后的总大小超过 250 MiB 限制")
        if strip_root:
            roots = {_archive_path(entry, allow_links=True).parts[0] for entry in entries}
            if len(roots) != 1 or any(len(_archive_path(entry, allow_links=True).parts) < 2 for entry in entries):
                raise ProjectImportError("GitHub 源码包结构无效")
        _extract_entries(bundle, entries, destination, strip_root=strip_root)
    finally:
        bundle.close()

    return ImportedProject(
        source_dir=destination,
        project_name=_project_name(filename),
        file_count=len(entries),
        unpacked_bytes=unpacked_bytes,
    )


def _validate_entries(entries: list[zipfile.ZipInfo], *, allow_links: bool = False) -> None:
    paths: set[PurePosixPath] = set()
    for entry in entries:
        path = _archive_path(entry, allow_links=allow_links)
        if path in paths:
            raise ProjectImportError("项目压缩包不能包含同名文件")
        paths.add(path)


def _archive_path(entry: zipfile.ZipInfo, *, allow_links: bool = False) -> PurePosixPath:
    raw = entry.filename.replace("\\", "/")
    path = PurePosixPath(raw)
    mode = entry.external_attr >> 16
    if stat.S_ISLNK(mode) and not allow_links:
        raise ProjectImportError("项目压缩包不能包含符号链接")
    raw_parts = raw.rstrip("/").split("/")
    if not raw or path.is_absolute() or any(part in {"", ".", ".."} for part in raw_parts):
        raise ProjectImportError("项目压缩包包含不安全的文件路径")
    if re.match(r"^[a-zA-Z]:", raw):
        raise ProjectImportError("项目压缩包包含不安全的文件路径")
    if os.name == "nt" and any(
        part.endswith((" ", "."))
        or re.search(r'[<>:"|?*\x00-\x1f]', part)
        or re.match(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", part, re.IGNORECASE)
        for part in path.parts
    ):
        raise ProjectImportError("项目压缩包包含 Windows 不支持的文件名")
    return path


def _extract_entries(bundle: zipfile.ZipFile, entries: list[zipfile.ZipInfo], destination: Path, *, strip_root: bool = False) -> None:
    destination = filesystem_path(destination)
    if destination.exists():
        raise ProjectImportError("项目源码目录已存在")
    staging = destination.with_name(f".{destination.name}-{uuid.uuid4().hex}.importing")
    written_bytes = 0
    written_files = len(entries)
    try:
        staging.mkdir(parents=True, exist_ok=False)
        links: list[tuple[PurePosixPath, PurePosixPath]] = []
        for entry in entries:
            relative = _archive_path(entry, allow_links=strip_root)
            if strip_root:
                relative = PurePosixPath(*relative.parts[1:])
            if stat.S_ISLNK(entry.external_attr >> 16):
                if entry.file_size > 4096:
                    raise ProjectImportError("项目符号链接目标无效")
                try:
                    raw_target = bundle.read(entry).decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ProjectImportError("项目符号链接目标无效") from exc
                if not raw_target or "\\" in raw_target or raw_target.startswith("/") or re.match(r"^[a-zA-Z]:", raw_target):
                    raise ProjectImportError("项目符号链接指向不安全的位置")
                target = PurePosixPath(posixpath.normpath(str(relative.parent / raw_target)))
                if target == PurePosixPath('.') or '..' in target.parts:
                    raise ProjectImportError("项目符号链接指向不安全的位置")
                _archive_path(zipfile.ZipInfo(str(target)))
                links.append((relative, target))
                continue
            target = staging.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(entry, "r") as source, target.open("xb") as output:
                while chunk := source.read(64 * 1024):
                    written_bytes += len(chunk)
                    if written_bytes > MAX_UNPACKED_BYTES:
                        raise ProjectImportError("项目解压后的总大小超过 250 MiB 限制")
                    output.write(chunk)
        link_targets = dict(links)
        dependents: dict[PurePosixPath, list[PurePosixPath]] = defaultdict(list)
        pending: dict[PurePosixPath, int] = {}
        for relative, target in links:
            dependencies = {
                link for link in link_targets
                if link == target or link in target.parents or target in link.parents
            }
            pending[relative] = len(dependencies)
            for dependency in dependencies:
                dependents[dependency].append(relative)
        ready = deque(path for path, count in pending.items() if count == 0)
        expanded = 0
        while ready:
            relative = ready.popleft()
            target = link_targets[relative]
            source = staging.joinpath(*target.parts)
            output = staging.joinpath(*relative.parts)
            if not source.exists() or output.exists():
                raise ProjectImportError("项目符号链接目标不存在或路径冲突")
            files = [source] if source.is_file() else [item for item in source.rglob('*') if item.is_file()]
            written_bytes += sum(item.stat().st_size for item in files)
            written_files += len(files)
            if written_bytes > MAX_UNPACKED_BYTES or written_files > MAX_PROJECT_FILES:
                raise ProjectImportError("展开项目符号链接后超过文件数量或大小限制")
            output.parent.mkdir(parents=True, exist_ok=True)
            if source.is_file():
                shutil.copyfile(source, output)
            else:
                shutil.copytree(source, output)
            expanded += 1
            for dependent in dependents[relative]:
                pending[dependent] -= 1
                if pending[dependent] == 0:
                    ready.append(dependent)
        if expanded != len(links):
            raise ProjectImportError("项目符号链接存在循环，无法安全导入")
        _publish_staging_directory(staging, destination)
    except (OSError, zipfile.BadZipFile) as exc:
        detail = f"（系统错误 {exc.winerror}）" if isinstance(exc, OSError) and getattr(exc, "winerror", None) else ""
        raise ProjectImportError(f"项目压缩包解压失败{detail}") from exc
    finally:
        remove_tree(staging, ignore_errors=True)


def _publish_staging_directory(staging: Path, destination: Path) -> None:
    """Retry transient Windows sharing errors while publishing the extracted tree."""
    for delay in (0.2, 0.4, 0.8, 1.6, 3.2, None):
        try:
            staging.replace(destination)
            return
        except OSError as exc:
            if os.name != "nt" or getattr(exc, "winerror", None) not in (5, 32, 33) or delay is None:
                raise
            if destination.exists():
                raise
            time.sleep(delay)


def remove_tree(path: Path, *, ignore_errors: bool = False) -> None:
    """Delete a directory tree, including read-only Git pack files on Windows."""
    target = filesystem_path(path)
    if not target.exists():
        return

    def onexc(func, failed: str, exc: BaseException) -> None:
        if isinstance(exc, FileNotFoundError):
            return
        if isinstance(exc, PermissionError):
            try:
                os.chmod(failed, stat.S_IWRITE)
                func(failed)
                return
            except FileNotFoundError:
                return
            except OSError:
                if ignore_errors:
                    return
                raise
        if ignore_errors:
            return
        raise exc

    shutil.rmtree(target, onexc=onexc)


def filesystem_path(path: Path) -> Path:
    """Use Windows extended-length paths without requiring a system-wide policy change."""
    if os.name != "nt":
        return path
    absolute = str(path.absolute())
    if absolute.startswith("\\\\?\\"):
        return Path(absolute)
    if absolute.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + absolute[2:])
    return Path("\\\\?\\" + absolute)


def _project_name(filename: str) -> str:
    stem = Path(filename).stem.strip()
    return stem[:120] or "导入项目"


def github_repository(url: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(url.strip())
    except ValueError as exc:
        raise ProjectImportError("请输入有效的 GitHub 仓库地址") from exc
    match = re.fullmatch(r"/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9_.-]+?)(?:\.git)?/?", parsed.path)
    if (parsed.scheme != "https" or parsed.netloc.lower() != "github.com" or parsed.query
            or parsed.fragment or not match or match.group(2) in {".", ".."}):
        raise ProjectImportError("请输入 GitHub 仓库地址，例如 https://github.com/owner/repo")
    return match.group(1), match.group(2)


def source_file_hashes(directory: Path) -> dict[str, str]:
    """Record file contents independent of ZIP metadata and entry order."""
    hashes = {}
    root = filesystem_path(directory)
    for path in sorted(p for p in root.rglob('*') if p.is_file()):
        file_digest = hashlib.sha256()
        with path.open('rb') as source:
            while chunk := source.read(1024 * 1024):
                file_digest.update(chunk)
        hashes[path.relative_to(root).as_posix()] = file_digest.hexdigest()
    return hashes


def import_github_project(url: str, destination: Path) -> ImportedProject:
    owner, repo = github_repository(url)
    request = Request(f"https://codeload.github.com/{owner}/{repo}/zip/HEAD", headers={"User-Agent": "Auditor-Project-Import"})
    try:
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        with build_opener(NoRedirect()).open(request, timeout=30) as response, tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as archive:
            size = 0
            while chunk := response.read(64 * 1024):
                size += len(chunk)
                if size > MAX_DOWNLOAD_BYTES:
                    raise ProjectImportError("GitHub 源码包超过 250 MiB 限制")
                archive.write(chunk)
            return import_project_zip(archive, destination, f"{repo}.zip", strip_root=True)
    except (HTTPError, URLError, OSError, TimeoutError) as exc:
        raise ProjectImportError("GitHub 下载失败，请检查仓库地址、访问权限和网络连接") from exc
