import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from app.receipt_selector import _send_deadline_reminders, describe_selected_paths, select_receipt_paths


class SelectorTests(unittest.IsolatedAsyncioTestCase):
    def test_path_descriptions_use_roles_and_never_show_account_ids(self):
        path = SimpleNamespace(id='primary', attacker_account='account-a', victim_account='account-b')
        with mock.patch('app.receipt_selector.receipt_manifest_path', return_value=Path('manifest.json')), \
             mock.patch('app.receipt_selector.load_manifest', return_value=SimpleNamespace(threat_paths=[path])), \
             mock.patch('app.receipt_selector.load_principal_roles', return_value={'account-a': 'editor', 'account-b': 'admin'}):
            self.assertEqual(describe_selected_paths('manifest.json', ('primary',)),
                             ['primary（攻击者：editor → 受害者：admin）'])
            self.assertEqual(describe_selected_paths('manifest.json', ('unknown',)), ['unknown'])

    async def test_deadline_reminders_stop_on_completion_and_report_remaining_time(self):
        client = SimpleNamespace(query=mock.AsyncMock())
        deadline = asyncio.get_running_loop().time() + 0.08
        await _send_deadline_reminders(client, deadline, interval=0.02, timeout=0.08)
        self.assertGreaterEqual(client.query.await_count, 1)
        self.assertLessEqual(client.query.await_count, 3)
        for call in client.query.await_args_list:
            self.assertIn('本次链路选择还剩约', call.args[0])

    async def test_selection_is_validated_and_untrusted_output_falls_back(self):
        class Result:
            def __init__(self, result):
                self.result = result
                self.is_error = False

        class Client:
            output = ''
            outputs = []
            options = None
            prompts = []
            def __init__(self, options):
                Client.options = options
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return None
            async def query(self, prompt):
                Client.prompts.append(prompt)
            async def receive_response(self):
                yield Result(Client.outputs.pop(0) if Client.outputs else Client.output)

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            (workspace / 'findings').mkdir()
            (workspace / 'findings' / 'one.md').write_text('editor writes; admin views', encoding='utf-8')
            path = SimpleNamespace(id='editor-admin', attacker_account='a', victim_account='b', accept_self_xss=False)
            manifest = SimpleNamespace(threat_paths=[path])
            candidate = SimpleNamespace(as_mapping=lambda: {'attacker_script': 'test'})
            with mock.patch('app.receipt_selector.receipt_manifest_path', return_value=workspace / 'manifest.json'), \
                 mock.patch('app.receipt_selector.load_manifest', return_value=manifest), \
                 mock.patch('app.receipt_selector.load_principal_roles', return_value={'a': 'editor', 'b': 'admin'}), \
                 mock.patch('app.receipt_selector.load_receipt_candidate', return_value=candidate), \
                 mock.patch('claude_agent_sdk.ClaudeSDKClient', Client), \
                 mock.patch('claude_agent_sdk.ResultMessage', Result):
                for output, expected in [
                    ({'path_ids': ['editor-admin'], 'uncertain': False}, ('editor-admin',)),
                    ({'path_ids': ['unknown'], 'uncertain': False}, ()),
                    ({'path_ids': ['editor-admin'], 'uncertain': True}, ()),
                    ({'path_ids': [], 'uncertain': False}, ()),
                ]:
                    Client.output = json.dumps(output)
                    Client.prompts = []
                    result = await select_receipt_paths(workspace, 'http://target', 'manifest.json', 'one',
                                                        'findings/one.md', {'model': 'test'}, {})
                    self.assertEqual(result, expected)
                self.assertEqual(Client.options.tools, [])
                self.assertTrue(Client.options.strict_mcp_config)
                self.assertEqual(Client.options.env['API_TIMEOUT_MS'], '300000')
                self.assertNotIn('account_id', Client.prompts[0])
                self.assertIn('editor-admin', Client.prompts[0])
                self.assertIn('必须至少选择一条', Client.prompts[0])
                self.assertIn('只选择最符合的一条', Client.prompts[0])
                self.assertIn('无法排除的其他可能链路', Client.prompts[0])
                self.assertIn('共用同一套登录和动作', Client.prompts[0])
                Client.outputs = [json.dumps({'path_ids': []}), json.dumps({'path_ids': ['editor-admin']})]
                Client.prompts = []
                result = await select_receipt_paths(workspace, 'http://target', 'manifest.json', 'one',
                                                    'findings/one.md', {'model': 'test'}, {})
                self.assertEqual(result, ('editor-admin',))
                self.assertEqual(len(Client.prompts), 2)

    async def test_single_confirmed_victim_role_narrows_selection(self):
        class Result:
            def __init__(self, result):
                self.result = result
                self.is_error = False

        class Client:
            output = ''
            def __init__(self, options):
                del options
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return None
            async def query(self, prompt):
                del prompt
            async def receive_response(self):
                yield Result(Client.output)

        both = json.dumps({'path_ids': ['editor-admin', 'editor-user']})
        user_only = json.dumps({'path_ids': ['editor-user']})
        paths = [
            SimpleNamespace(id='editor-admin', attacker_account='a', victim_account='b', accept_self_xss=False),
            SimpleNamespace(id='editor-user', attacker_account='a', victim_account='c', accept_self_xss=False),
        ]
        manifest = SimpleNamespace(threat_paths=paths)
        candidate = SimpleNamespace(as_mapping=lambda: {'attacker_script': 'test'})
        reports = {
            'only-admin': '## 受害者角色\n\nadmin\n\n## 类型\n\n存储型。\n',
            'unconfirmed': '## 受害者角色\n\nadmin，待确认是否还有其他角色。\n',
            'both-roles': '## 受害者角色\n\nadmin 与 user 都已确认。\n',
            'no-section': 'admin 打开页面。\n',
        }
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            (workspace / 'findings').mkdir()
            report = workspace / 'findings' / 'one.md'
            with mock.patch('app.receipt_selector.receipt_manifest_path', return_value=workspace / 'manifest.json'), \
                 mock.patch('app.receipt_selector.load_manifest', return_value=manifest), \
                 mock.patch('app.receipt_selector.load_principal_roles', return_value={'a': 'editor', 'b': 'admin', 'c': 'user'}), \
                 mock.patch('app.receipt_selector.load_receipt_candidate', return_value=candidate), \
                 mock.patch('claude_agent_sdk.ClaudeSDKClient', Client), \
                 mock.patch('claude_agent_sdk.ResultMessage', Result):
                expected = {
                    'only-admin': ('editor-admin',),
                    'unconfirmed': ('editor-admin', 'editor-user'),
                    'both-roles': ('editor-admin', 'editor-user'),
                    'no-section': ('editor-admin', 'editor-user'),
                }
                for name, text in reports.items():
                    report.write_text(text, encoding='utf-8')
                    Client.output = both
                    result = await select_receipt_paths(workspace, 'http://target', 'manifest.json', 'one',
                                                        'findings/one.md', {'model': 'test'}, {})
                    self.assertEqual(result, expected[name], name)
                report.write_text(reports['only-admin'], encoding='utf-8')
                Client.output = user_only
                result = await select_receipt_paths(workspace, 'http://target', 'manifest.json', 'one',
                                                    'findings/one.md', {'model': 'test'}, {})
                self.assertEqual(result, ('editor-user',))
