from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass


_PINNED_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-fA-F]{64}$")
DEFAULT_ATTACKER_IMAGE = "python:3.12-slim"


def ensure_attacker_image(image: str = "") -> str:
    """Ensure the configured image is local and return a digest-pinned reference."""
    reference = image or DEFAULT_ATTACKER_IMAGE

    def docker(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"Docker 执行失败或超时：{exc}") from exc

    def inspect() -> subprocess.CompletedProcess[str]:
        return docker("image", "inspect", reference, "--format", "{{json .RepoDigests}}")

    result = inspect()
    if result.returncode != 0 or (not image and not (result.stdout.strip() and result.stdout.strip() != "null" and result.stdout.strip() != "[]")):
        pulled = docker("pull", reference, timeout=600)
        if pulled.returncode != 0:
            raise RuntimeError(f"拉取攻击者镜像失败：{pulled.stderr.strip() or pulled.stdout.strip() or 'Docker 返回错误'}")
        result = inspect()
    if result.returncode != 0:
        raise RuntimeError(f"检查攻击者镜像失败：{result.stderr.strip() or 'Docker 返回错误'}")
    if image:
        return image
    try:
        digests = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("无法读取攻击者镜像 digest") from exc
    digest = next((value for value in digests or [] if isinstance(value, str) and is_pinned_attacker_image(value)), "")
    if not digest:
        raise RuntimeError("攻击者镜像没有可用的仓库 digest")
    return digest


@dataclass(frozen=True)
class ReceiptRuntimeConfig:
    evidence_hmac_key: str
    attacker_image: str


def is_pinned_attacker_image(value: str) -> bool:
    return bool(_PINNED_IMAGE.fullmatch((value or "").strip()))


def receipt_runtime_config(settings: Mapping[str, object] | None = None) -> ReceiptRuntimeConfig:
    values = settings or {}
    evidence_hmac_key = str(values.get("evidence_hmac_key") or "").strip()
    attacker_image = str(values.get("attacker_image") or "").strip()
    return ReceiptRuntimeConfig(
        evidence_hmac_key=evidence_hmac_key or os.environ.get("RECEIPT_EVIDENCE_HMAC_KEY", "").strip(),
        attacker_image=attacker_image or os.environ.get("RECEIPT_ATTACKER_IMAGE", "").strip(),
    )


def receipt_configuration_errors(config: ReceiptRuntimeConfig) -> list[str]:
    errors: list[str] = []
    if not config.evidence_hmac_key:
        errors.append("缺少证据签名密钥")
    if not is_pinned_attacker_image(config.attacker_image):
        errors.append("攻击者镜像必须使用 sha256 digest 固定版本")
    return errors
