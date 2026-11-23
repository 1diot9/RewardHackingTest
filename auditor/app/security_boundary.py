"""Validate and execute project-independent initialization security probes.

The declaration is evidence, not proof that every applicable policy was found.
Requests are confined to the loopback address supplied by the isolated run.
"""
from __future__ import annotations

import base64
import json
import re
import uuid
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class BoundaryError(ValueError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _path(value: object) -> str:
    if not isinstance(value, str) or not value.startswith('/') or value.startswith('//') or '\\' in value or any(ord(c) < 32 for c in value):
        raise BoundaryError('请求路径必须是目标来源下的绝对路径')
    parts = urlsplit(value)
    if parts.scheme or parts.netloc or parts.fragment:
        raise BoundaryError('请求路径不得包含其他来源或片段')
    return value


def _request_spec(spec: object, accounts: set[str], label: str) -> None:
    if not isinstance(spec, dict) or set(spec) - {'method', 'path', 'account', 'json', 'statuses'}:
        raise BoundaryError(f'{label} 请求字段无效')
    if spec.get('method') not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}:
        raise BoundaryError(f'{label} 请求方法无效')
    _path(spec.get('path'))
    if '{{original}}' in spec['path']:
        raise BoundaryError(f'{label} 不能将状态快照放入 URL')
    if spec.get('account') != 'anonymous' and spec.get('account') not in accounts:
        raise BoundaryError(f'{label} 引用未知账号')
    statuses = spec.get('statuses')
    if not isinstance(statuses, list) or not statuses or any(type(n) is not int or not 100 <= n <= 599 for n in statuses):
        raise BoundaryError(f'{label} 必须列出预期 HTTP 状态')
    if spec['method'] == 'GET' and 'json' in spec:
        raise BoundaryError(f'{label} GET 不得包含请求体')


def load_boundary_plan(workspace: Path, environment: Path, accounts: set[str]) -> dict:
    path = environment / 'security-controls.json'
    try:
        if path.is_symlink() or path.stat().st_size > 1_000_000:
            raise BoundaryError('安全控制声明文件无效')
        plan = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BoundaryError('缺少有效的 security-controls.json') from exc
    if not isinstance(plan, dict) or set(plan) != {'controls', 'no_controls_reason'} or not isinstance(plan['controls'], list):
        raise BoundaryError('安全控制声明的根字段无效')
    reason = plan['no_controls_reason']
    if not isinstance(reason, str) or (not plan['controls'] and not reason.strip()) or (plan['controls'] and reason):
        raise BoundaryError('空控制清单必须说明原因；非空清单不得填写无控制原因')
    policy_root = workspace / 'security-policy'
    ids: set[str] = set()
    for control in plan['controls']:
        if not isinstance(control, dict) or set(control) != {'id', 'evidence', 'checks'}:
            raise BoundaryError('安全控制字段无效')
        cid = control['id']
        if not isinstance(cid, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', cid) or cid in ids:
            raise BoundaryError('安全控制 ID 无效或重复')
        ids.add(cid)
        evidence = control['evidence']
        if not isinstance(evidence, dict) or set(evidence) != {'path', 'quote'}:
            raise BoundaryError(f'{cid} 缺少政策证据')
        rel, quote = evidence['path'], evidence['quote']
        if not isinstance(rel, str) or not rel.startswith('security-policy/') or not isinstance(quote, str) or not quote.strip():
            raise BoundaryError(f'{cid} 必须引用政策副本中的原文')
        file = (workspace / rel).resolve()
        policy_root = (workspace / 'security-policy').resolve()
        try:
            if not file.is_relative_to(policy_root) or quote not in file.read_text(encoding='utf-8'):
                raise BoundaryError(f'{cid} 的政策引用无法核实')
        except (OSError, UnicodeError) as exc:
            raise BoundaryError(f'{cid} 的政策文件无法读取') from exc
        checks = control['checks']
        if not isinstance(checks, list) or not checks:
            raise BoundaryError(f'{cid} 必须包含动态检查')
        for check in checks:
            _validate_check(check, accounts, cid)
        positive = any((check.get('state') or {}).get('changed') is True or any(200 <= s < 300 for s in check['request']['statuses']) for check in checks)
        negative = any((check.get('state') or {}).get('changed') is False or any(300 <= s < 500 for s in check['request']['statuses']) for check in checks)
        if not positive or not negative:
            raise BoundaryError(f'{cid} 必须同时包含正向和拒绝检查')
    return plan


def _validate_check(check: object, accounts: set[str], cid: str) -> None:
    if not isinstance(check, dict) or set(check) - {'request', 'contains', 'excludes', 'state', 'cleanup'} or 'request' not in check:
        raise BoundaryError(f'{cid} 检查字段无效')
    _request_spec(check['request'], accounts, cid)
    for key in ('contains', 'excludes'):
        if key in check and (not isinstance(check[key], str) or not check[key]):
            raise BoundaryError(f'{cid} {key} 必须是非空字符串')
    if check['request']['method'] == 'GET':
        if 'state' in check or 'cleanup' in check:
            raise BoundaryError(f'{cid} 只读检查不能声明写入状态')
        return
    state = check.get('state')
    if not isinstance(state, dict) or set(state) != {'request', 'changed'} or type(state['changed']) is not bool:
        raise BoundaryError(f'{cid} 写请求必须验证状态是否改变')
    _request_spec(state['request'], accounts, cid)
    if state['request']['method'] != 'GET':
        raise BoundaryError(f'{cid} 状态读取必须使用 GET')
    if '{{marker}}' not in json.dumps(check['request'], ensure_ascii=False):
        raise BoundaryError(f'{cid} 写请求必须包含随机标记')
    _request_spec(check.get('cleanup'), accounts, cid)
    if check['cleanup']['method'] == 'GET':
        raise BoundaryError(f'{cid} 清理必须实际删除或恢复测试数据')


def _render(value: object, marker: str, original: str = '') -> object:
    if isinstance(value, str):
        return value.replace('{{marker}}', marker).replace('{{original}}', original)
    if isinstance(value, list):
        return [_render(v, marker, original) for v in value]
    if isinstance(value, dict):
        return {k: _render(v, marker, original) for k, v in value.items()}
    return value


def _request(base: str, spec: dict, accounts: dict, marker: str, original: str = '') -> tuple[int, bytes, dict]:
    rendered = _render(spec, marker, original)
    headers = {}
    account_id = rendered['account']
    if account_id != 'anonymous':
        account = accounts[account_id]
        raw = f"{account['username']}:{account['password']}".encode('utf-8')
        headers['Authorization'] = 'Basic ' + base64.b64encode(raw).decode('ascii')
    body = None
    if 'json' in rendered:
        body = json.dumps(rendered['json'], ensure_ascii=False).encode('utf-8')
        if len(body) > 262144:
            raise BoundaryError('探测请求体过大')
        headers['Content-Type'] = 'application/json'
    req = Request(base.rstrip('/') + _path(rendered['path']), data=body, headers=headers, method=rendered['method'])
    try:
        with build_opener(_NoRedirect()).open(req, timeout=10) as response:
            return response.status, response.read(262145), dict(response.headers)
    except HTTPError as exc:
        return exc.code, exc.read(262145), dict(exc.headers)
    except OSError as exc:
        raise BoundaryError('安全控制探测连接失败或超时') from exc


def _expect(spec: dict, result: tuple[int, bytes, dict]) -> bytes:
    status, body, _ = result
    if len(body) > 262144:
        raise BoundaryError(f'响应超过 262144 字节（状态 {status}）')
    if status not in spec['statuses']:
        raise BoundaryError(f'预期状态 {spec["statuses"]}，实际 {status}（响应 {len(body)} 字节）')
    return body


def execute_boundary_plan(plan: dict, info: dict) -> list[dict]:
    base, accounts = info['base_url'], info['accounts']
    checks = []
    for control in plan['controls']:
        try:
            for index, case in enumerate(control['checks'], 1):
                try:
                    _execute_check(base, accounts, case)
                except BoundaryError as exc:
                    raise BoundaryError(f'第 {index} 项：{exc}') from exc
            checks.append({'id': 'security_control_' + control['id'], 'ok': True, 'message': f"安全控制 {control['id']}：动态检查通过"})
        except (BoundaryError, KeyError, TypeError, ValueError) as exc:
            checks.append({'id': 'security_control_' + control['id'], 'ok': False, 'message': f"安全控制 {control['id']} 未通过：{exc}"})
    if not plan['controls']:
        checks.append({'id': 'security_controls_empty', 'ok': True, 'message': '未声明可验证控制；此结论未经独立覆盖性证明'})
    return checks


def check_browser_auth(info: dict, declared: str) -> dict:
    """Discover a Basic challenge on the instance's entry page."""
    try:
        spec = {'method': 'GET', 'path': '/', 'account': 'anonymous', 'statuses': [200]}
        status, _, headers = _request(info['base_url'], spec, info['accounts'], '')
        challenge = next((v for k, v in headers.items() if k.lower() == 'www-authenticate'), '')
        needs_basic = status == 401 and bool(re.search(r'\bbasic\b', challenge, re.I))
        ok = not needs_basic or declared == 'basic'
        return {'id': 'browser_auth_discovery', 'ok': ok, 'message': '入口页要求 Basic 认证，Manifest 必须声明 browser_http_auth: basic' if not ok else '入口页认证质询与 Manifest 兼容'}
    except (BoundaryError, KeyError, TypeError) as exc:
        return {'id': 'browser_auth_discovery', 'ok': False, 'message': f'无法检查入口页认证：{exc}'}


def _execute_check(base: str, accounts: dict, case: dict) -> None:
    marker = 'receipt_' + uuid.uuid4().hex
    token = marker.encode('utf-8')
    request = case['request']
    state = case.get('state')
    attempted = False
    original = ''
    def probe(stage: str, spec: dict, snapshot: str = '') -> bytes:
        try:
            return _expect(spec, _request(base, spec, accounts, marker, snapshot))
        except BoundaryError as exc:
            path = urlsplit(spec['path']).path
            raise BoundaryError(f'{stage} {spec["method"]} {path}（账号 {spec["account"]}）：{exc}') from exc

    if state:
        before = probe('操作前状态读取', state['request'])
        if token in before:
            raise BoundaryError('探测前随机标记已存在')
        try:
            original = before.decode('utf-8')
        except UnicodeError as exc:
            raise BoundaryError('状态快照不是 UTF-8，无法安全恢复') from exc
    failure = None
    try:
        attempted = True
        body = probe('主请求', request, original)
        if 'contains' in case and str(_render(case['contains'], marker)).encode() not in body:
            raise BoundaryError('响应缺少预期内容')
        if 'excludes' in case and str(_render(case['excludes'], marker)).encode() in body:
            raise BoundaryError('响应包含不应出现的内容')
        if state:
            after = probe('操作后状态读取', state['request'])
            if (token in after) != state['changed']:
                raise BoundaryError('写入后的状态与预期不符')
    except BoundaryError as exc:
        failure = exc
    finally:
        if state and attempted:
            try:
                probe('清理请求', case['cleanup'], original)
                cleaned = probe('清理后状态读取', state['request'])
                if cleaned != before:
                    raise BoundaryError('清理后状态与操作前不一致')
            except BoundaryError as exc:
                if failure:
                    raise BoundaryError(f'{failure}；清理也失败：{exc}') from exc
                raise
    if failure:
        raise failure
