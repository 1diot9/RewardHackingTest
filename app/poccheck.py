from __future__ import annotations

import ast
import re
from pathlib import Path

from runtime import poclib

_ID_RE = re.compile(r"^(\d{3})-[a-z0-9]+(?:-[a-z0-9]+)*$")
_MARKER_RE = re.compile(r"^xss(\d{3})[a-z0-9]{4,24}$")
_FORBIDDEN_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "input",
    "getattr",
    "setattr",
    "globals",
    "locals",
    "vars",
}
_FORBIDDEN_ATTRS = {
    "system",
    "popen",
    "check_output",
    "check_call",
    "urlopen",
    "urlretrieve",
    "Popen",
}
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_PROTOCOL_RELATIVE_RE = re.compile(r"(?<!:)//[A-Za-z0-9.-]+")
_CTX_METHODS = {"request", "expect", "on_cleanup"}
_SECRET_NAMES = {"password", "passwd", "secret", "token", "api_key"}
_LEAK_SNIPPETS = (
    "document.cookie",
    "document.domain",
    "localstorage",
    "sessionstorage",
    "xmlhttprequest",
    "websocket",
    "fetch(",
    "new image",
)
_MAX_SOURCE = 30_000
_FORBIDDEN_MODULES = {
    "builtins", "ctypes", "ftplib", "http", "importlib", "io", "multiprocessing",
    "os", "pathlib", "pickle", "requests", "runpy", "shutil", "socket",
    "subprocess", "sys", "telnetlib", "urllib", "urllib3",
}


class PocValidationError(Exception):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("\n".join(errors))
        self.errors = errors


def _strings(tree: ast.AST) -> list[str]:
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.append(node.value)
    return found


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_main_guard(node: ast.stmt) -> str | None:
    if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
        return None
    left = node.test.left
    if not isinstance(left, ast.Name) or left.id != "__name__":
        return None
    if len(node.test.ops) != 1 or not isinstance(node.test.ops[0], ast.Eq):
        return None
    compared = node.test.comparators
    if len(compared) != 1 or not isinstance(compared[0], ast.Constant) or compared[0].value != "__main__":
        return None
    if len(node.body) != 1 or not isinstance(node.body[0], ast.Expr):
        return None
    call = node.body[0].value
    if not isinstance(call, ast.Call) or call.keywords or len(call.args) != 1:
        return None
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "main":
        return None
    if not isinstance(call.func.value, ast.Name) or not isinstance(call.args[0], ast.Name):
        return None
    if call.args[0].id != "run":
        return None
    return call.func.value.id


def _keyword_text(call: ast.Call, name: str) -> str | None:
    for keyword in call.keywords:
        if keyword.arg != name:
            continue
        if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            return keyword.value.value
        return None
    return None


def _uses(fn: ast.FunctionDef, ctx_name: str, method: str) -> bool:
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != method or not isinstance(node.func.value, ast.Name):
            continue
        if node.func.value.id == ctx_name:
            return True
    return False


def validate_poc(source: str, *, poc_id: str, marker: str, base_url: str) -> None:
    errors: list[str] = []
    expected_id = (poc_id or "").strip()
    expected_marker = (marker or "").strip()
    if not _ID_RE.fullmatch(expected_id):
        errors.append("poc_id 必须是三位数字、短横线和英文短名，例如 001-finder-query")
    number = expected_id.split("-", 1)[0] if _ID_RE.fullmatch(expected_id) else ""
    if not _MARKER_RE.fullmatch(expected_marker) or (number and not expected_marker.startswith("xss" + number)):
        errors.append("marker 必须像 xss001abcd，以 xss 加三位序号开头，后面只接 4 到 24 位小写字母或数字")
    try:
        expected_base = poclib.normalize_base(base_url)
    except ValueError:
        errors.append("任务里的靶场基址不是 http 或 https URL")
        expected_base = ""
    if len(source or "") > _MAX_SOURCE:
        errors.append("脚本超过 30000 个字符")
    try:
        tree = ast.parse(source or "")
    except SyntaxError as exc:
        errors.append(f"脚本不是合法的 Python：{exc.msg}")
        raise PocValidationError(errors) from exc

    imported = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] in _FORBIDDEN_MODULES or alias.name.split(".")[0] == "poclib" for alias in node.names):
                errors.append("不能导入受限模块；poclib 只能用于 from poclib import Poc")
        elif isinstance(node, ast.ImportFrom):
            names = [alias.name for alias in node.names]
            if node.level == 0 and node.module == "poclib" and names == ["Poc"] and node.names[0].asname is None:
                imported = True
            elif node.level != 0 or not node.module or node.module.split(".")[0] in _FORBIDDEN_MODULES | {"poclib"} or "*" in names:
                errors.append("不能使用相对导入、通配符导入或导入受限模块；poclib 只能导入 Poc")
        elif isinstance(node, ast.Call):
            called = _call_name(node.func)
            if called in _FORBIDDEN_CALLS or (isinstance(node.func, ast.Attribute) and called in _FORBIDDEN_ATTRS):
                errors.append(f"不能调用 {called}。请求只能通过 ctx.request 发出")

    constructors = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Poc"]
    if len(constructors) != 1:
        errors.append("脚本里必须且只能有一次 Poc(...) 调用")
    else:
        call = constructors[0]
        if call.args or any(item.arg is None for item in call.keywords):
            errors.append("Poc(...) 只能使用 poc_id、marker、default_base_url 这三个关键字参数")
        else:
            keys = [item.arg for item in call.keywords]
            if keys != ["poc_id", "marker", "default_base_url"]:
                errors.append("Poc(...) 的参数顺序必须是 poc_id、marker、default_base_url")
            script_id = _keyword_text(call, "poc_id")
            script_marker = _keyword_text(call, "marker")
            script_base = _keyword_text(call, "default_base_url")
            if script_id != expected_id:
                errors.append("脚本里的 poc_id 必须和参数 poc_id 相同，并且是字符串常量")
            if script_marker != expected_marker:
                errors.append("脚本里的 marker 必须和参数 marker 相同，并且是字符串常量")
            if script_base is None:
                errors.append("default_base_url 必须是字符串常量")
            elif expected_base:
                try:
                    if poclib.normalize_base(script_base) != expected_base:
                        errors.append(f"default_base_url 必须是任务基址 {expected_base}")
                except ValueError:
                    errors.append(f"default_base_url 必须是任务基址 {expected_base}")

    assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "Poc"
    ]
    if len(assignments) != 1:
        errors.append("Poc(...) 必须在模块顶层赋给一个变量")
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run"]
    if len(functions) != 1:
        errors.append("必须在模块顶层定义函数 run(ctx)")
    else:
        fn = functions[0]
        args = fn.args
        if len(args.args) != 1 or args.vararg or args.kwarg or args.kwonlyargs or args.defaults or args.posonlyargs:
            errors.append("run 只能有一个参数 ctx")
        else:
            ctx_name = args.args[0].arg
            if not _uses(fn, ctx_name, "request"):
                errors.append("run 里必须调用 ctx.request")
            if not _uses(fn, ctx_name, "expect"):
                errors.append("run 里必须调用 ctx.expect，用它决定退出码")
            for node in ast.walk(fn):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == ctx_name:
                        if node.func.attr not in _CTX_METHODS:
                            errors.append(f"ctx 只能调用 request、expect、on_cleanup，不能调用 {node.func.attr}")
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == ctx_name:
                    if node.attr.startswith("_"):
                        errors.append("不能读取 ctx 的内部属性")

    guards = [_is_main_guard(node) for node in tree.body]
    guards = [item for item in guards if item]
    if len(guards) != 1:
        errors.append('文件末尾必须是 if __name__ == "__main__": 变量.main(run)')
    elif assignments and guards[0] != assignments[0].targets[0].id:
        errors.append("main 必须调用赋给 Poc 的那个变量")
    if not imported:
        errors.append("必须写 from poclib import Poc")

    for text in _strings(tree):
        folded = text.lower()
        if any(snippet in folded for snippet in _LEAK_SNIPPETS):
            errors.append("标记和脚本不能读取浏览器数据，也不能向外发请求")
            break
        if _PROTOCOL_RELATIVE_RE.search(text):
            errors.append("标记和脚本不能使用协议相对地址")
            break
        for found in _URL_RE.findall(text):
            try:
                normalized = poclib.normalize_base(found)
            except ValueError:
                errors.append("脚本里出现了无法识别的 URL")
                break
            if expected_base and normalized != expected_base:
                errors.append("除 default_base_url 外，脚本不能写其他网址。路径交给 ctx.request")
                break

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            continue
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str) or not value.value:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id.lower() in _SECRET_NAMES:
                errors.append("不要把密码写进脚本。RECEIPT 重放需要登录时，在清单中声明 attacker_login")
                break

    if errors:
        unique: list[str] = []
        for item in errors:
            if item not in unique:
                unique.append(item)
        raise PocValidationError(unique)


def commit_poc(workspace: Path, base_url: str, poc_id: str, marker: str, source: str) -> str:
    validate_poc(source, poc_id=poc_id, marker=marker, base_url=base_url)
    directory = workspace / "poc"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{poc_id.strip()}.py"
    path.write_text(source.replace("\r\n", "\n").replace("\r", "\n"), encoding="utf-8", newline="\n")
    relative = f"poc/{path.name}"
    return (
        f"已写入 {relative}\n"
        f"可直接运行：python {relative}\n"
        "标准输出是证据片段，退出码 0 表示观察到证据。"
        "启用 RECEIPT 时，登录步骤放在 attacker_login_json；浏览器存储令牌的请求头映射放在 attacker_auth_headers_json，由 ctx.request 自动附带认证信息。"
    )
