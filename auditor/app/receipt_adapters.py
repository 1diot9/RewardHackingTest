"""加载由部署管理员安装的可信 RECEIPT Target Adapter。"""

from __future__ import annotations

import importlib

from app.config import receipt_adapter_modules


def load_trusted_receipt_adapters() -> None:
    """导入配置模块；模块需自行调用 ``register_target_adapter``。

    上传项目、任务 Manifest 和 Agent 输入均不会参与模块路径的构造，避免把不可信
    项目代码加载进验证器进程。
    """

    for module_name in receipt_adapter_modules():
        importlib.import_module(module_name)
