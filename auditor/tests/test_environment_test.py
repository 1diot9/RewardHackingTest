from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.environment_test import _run, test_environment, start_audit_environment, stop_audit_environment
from app.environment_check import check_environment
from app import runner
from app.store import Store


MANIFEST = {
    'target': {'id': 'demo', 'version': '1', 'image_digest': 'demo@sha256:abc'},
    'adapter': 'demo', 'allowed_origins': ['{{target_origin}}'],
    'principals': [{'id': 'a', 'account_id': 'a'}, {'id': 'b', 'account_id': 'b'}],
    'threat_paths': [{'id': 'a-to-b', 'attacker_principal': 'a', 'victim_principal': 'b', 'primary': True}],
}


def prepare(root: Path) -> Path:
    environment = root / 'environment'
    environment.mkdir()
    from test_threat_model import write_closed_model
    write_closed_model(environment, root / 'source')
    for name, content in {
        'compose.yaml': 'services:\n  app:\n    image: demo\n',
        'start.py': 'pass',
        'create-accounts.py': 'ACCOUNT_PLAN = "account-plan.json"\n',
        'READY.md': 'ready',
        'receipt-manifest.json': json.dumps(MANIFEST),
    }.items():
        (environment / name).write_text(content, encoding='utf-8')
    return environment


class EnvironmentTestCases(unittest.IsolatedAsyncioTestCase):
    async def test_failed_dashy_boundary_removes_probe_before_retaining_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            environment = prepare(root)
            manifest = {**MANIFEST, 'adapter': 'generic-compose', 'browser_http_auth': 'basic'}
            (environment / 'receipt-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
            (environment / 'receipt-adapter.json').write_text('{"version":2,"target_service":"app","container_port":80}', encoding='utf-8')
            (root / 'source' / 'package.json').write_text('{"name":"dashy"}', encoding='utf-8')
            commands = []
            async def run(command, cwd, timeout, env=None, **kwargs):
                commands.append(command)
                if '--verify' in command:
                    return True, 'ACCOUNTS_VERIFIED' if 'create-accounts' in ' '.join(command) else 'ENVIRONMENT_READY'
                return True, ''
            result = {'id': 'dashy_security_boundary', 'ok': False, 'message': 'anonymous write', 'probe_files': ['receipt_' + 'a' * 33 + '.yml']}
            with mock.patch('app.environment_test.check_environment', return_value=[{'id': 'static', 'ok': True}]), \
                 mock.patch('app.environment_test._run', side_effect=run), \
                 mock.patch('app.generic_receipt_adapter.load_run_info', return_value={'base_url': 'http://127.0.0.1:1234/', 'accounts': {}}), \
                 mock.patch('app.security_boundary.check_dashy_boundary', return_value=result):
                checks = await test_environment(root, source_dir=root / 'source')
            self.assertFalse(next(c for c in checks if c['id'] == 'dashy_security_boundary')['ok'])
            self.assertTrue(next(c for c in checks if c['id'] == 'dashy_probe_cleanup')['ok'])
            cleanup_index = next(i for i, c in enumerate(commands) if 'exec' in c)
            stop_index = next(i for i, c in enumerate(commands) if 'stop' in c)
            self.assertLess(cleanup_index, stop_index)

    async def test_stop_uses_only_the_task_compose_project(self):
        task = {'workspace': 'workspace', 'environment_run_id': 'a' * 32}
        with mock.patch('app.environment_test._run', new=mock.AsyncMock(return_value=(True, ''))) as run:
            self.assertEqual(await stop_audit_environment(task), (True, ''))
        command, root, timeout, env = run.await_args.args
        self.assertEqual(command, ['docker', 'compose', '-p', 'receipt-' + 'a' * 32, 'stop'])
        self.assertEqual(env['COMPOSE_PROJECT_NAME'], 'receipt-' + 'a' * 32)
        self.assertEqual(timeout, 120)

    async def test_terminal_audits_stop_only_their_environment(self):
        for status in ('completed', 'budget_exhausted', 'time_exhausted', 'cancelled', 'error', 'paused'):
            with self.subTest(status=status):
                task = {'id': 'test', 'status': 'running', 'environment_run_id': 'a' * 32, 'environment_ready': True}
                store = mock.Mock()
                store.get_task.side_effect = lambda _: task.copy()
                store.update_task.side_effect = lambda task_id, **fields: task.update(fields) or task.copy()
                async def audit(*args):
                    task['status'] = status
                with mock.patch.object(runner, '_audit', side_effect=audit), mock.patch.object(runner, 'stop_audit_environment', new=mock.AsyncMock(return_value=(True, ''))) as cleanup, mock.patch.object(runner, '_emit'):
                    await runner.run_task('test', store, mock.Mock())
                if status == 'paused':
                    cleanup.assert_not_awaited()
                    self.assertTrue(task['environment_ready'])
                else:
                    cleanup.assert_awaited_once()
                    self.assertEqual(cleanup.await_args.args[0]['environment_run_id'], 'a' * 32)
                    self.assertEqual(task['environment_run_id'], 'a' * 32)
                    self.assertEqual(task['environment_status'], 'stopped')

    async def test_cleanup_failure_retains_run_id_and_reports_error(self):
        task = {'id': 'test', 'status': 'running', 'environment_run_id': 'b' * 32, 'error': '审计失败'}
        store = mock.Mock()
        store.get_task.side_effect = lambda _: task.copy()
        store.update_task.side_effect = lambda task_id, **fields: task.update(fields) or task.copy()
        async def audit(*args):
            task['status'] = 'error'
        with mock.patch.object(runner, '_audit', side_effect=audit), mock.patch.object(runner, 'stop_audit_environment', new=mock.AsyncMock(return_value=(False, 'docker unavailable'))), mock.patch.object(runner, '_emit'):
            await runner.run_task('test', store, mock.Mock())
        self.assertEqual(task['environment_run_id'], 'b' * 32)
        self.assertEqual(task['environment_status'], 'cleanup_failed')
        self.assertIn('审计失败', task['error'])
        self.assertIn('docker unavailable', task['error'])

    def test_repair_feedback_preserves_errors_and_targets_failed_stage(self):
        detail = '启动环境：OSError: [Errno 99] Cannot assign requested address'
        prompt = runner._environment_repair_prompt([{'id': 'start_run', 'ok': False, 'message': detail}], detail)
        self.assertIn(detail, prompt)
        self.assertIn('实际 command', prompt)
        self.assertIn('0.0.0.0 与 0.0.0.1', prompt)
        self.assertIn('不要未经证据归因于 Docker 网络', prompt)
        self.assertNotIn('账号错误：', prompt)
        self.assertNotIn('角色闭包错误：', prompt)

    def test_repair_feedback_names_role_closure_failures(self):
        prompt = runner._environment_repair_prompt([
            {'id': 'threat_coverage', 'ok': False, 'message': '角色簇 base-roles 还缺同级角色：commenter'},
        ], '角色簇 base-roles 还缺同级角色：commenter')
        self.assertIn('角色闭包错误', prompt)
        self.assertIn('commenter', prompt)
        self.assertIn('不要删除已发现的同级角色', prompt)

    def test_repair_feedback_distinguishes_manifest_and_external_docker_errors(self):
        prompt = runner._environment_repair_prompt([
            {'id': 'receipt_manifest', 'ok': False, 'message': 'principals[] 包含不允许的字段：description'},
            {'id': 'docker', 'ok': False, 'message': 'daemon unavailable'},
        ], '原始错误')
        self.assertIn('不要添加未允许的字段', prompt)
        self.assertIn('Docker 服务本身', prompt)
        self.assertNotIn('启动或健康检查错误：', prompt)

    async def test_audit_start_records_validated_address_and_accounts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            task = {'id': 'test', 'workspace': str(root)}
            store = mock.Mock()
            store.update_task.side_effect = lambda task_id, **fields: task.update(fields) or task.copy()
            async def run(command, cwd, timeout, env):
                if '--verify' in command:
                    return True, 'ACCOUNTS_VERIFIED' if 'create-accounts' in ' '.join(command) else 'ENVIRONMENT_READY'
                if 'create-accounts' in ' '.join(command):
                    data = {'base_url': 'http://127.0.0.1:1234/', 'accounts': {key: {'username': key, 'password': 'secret'} for key in ('a', 'b')}}
                    (Path(env['RECEIPT_RUN_DIR']) / 'receipt-run.json').write_text(json.dumps(data), encoding='utf-8')
                return True, ''
            with mock.patch('app.environment_test._run', side_effect=run):
                result = await start_audit_environment(task, store)
            self.assertEqual(result['base_url'], 'http://127.0.0.1:1234/')
            self.assertTrue(result['environment_ready'])
            self.assertTrue((root / 'runtime' / 'receipt-run.json').exists())

    async def test_verified_environment_transitions_into_audit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            store = Store(root / 'state.json')
            store.add_task({'id': 'test', 'workspace': str(root), 'status': 'queued', 'automatic_environment': True,
                            'environment_ready': False, 'provider_id': 'provider', 'prices': {}, 'next_seq': 1})

            async def run(command, cwd, timeout, env):
                if '--verify' in command:
                    return True, 'ACCOUNTS_VERIFIED' if 'create-accounts' in ' '.join(command) else 'ENVIRONMENT_READY'
                if 'create-accounts' in ' '.join(command):
                    data = {'base_url': 'http://127.0.0.1:1234/', 'accounts': {key: {'username': key, 'password': 'secret'} for key in ('a', 'b')}}
                    (Path(env['RECEIPT_RUN_DIR']) / 'receipt-run.json').write_text(json.dumps(data), encoding='utf-8')
                return True, ''

            with mock.patch('app.environment_test._run', side_effect=run), mock.patch.object(store, 'get_provider', return_value={'api_key': ''}), mock.patch.object(runner, 'prepare_workspace', return_value=root), mock.patch.object(runner.Prices, 'from_mapping', side_effect=RuntimeError('audit entered')):
                with self.assertRaisesRegex(RuntimeError, 'audit entered'):
                    await runner.run_task('test', store, mock.Mock())
            task = store.get_task('test')
            self.assertEqual(task['status'], 'running')
            self.assertTrue(task['environment_ready'])
            self.assertIsNone(task['preparation_mode'])
            self.assertIsNotNone(task['started_at'])

    async def test_environment_completion_preserves_pending_stop(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / 'state.json')
            store.add_task({'id': 'test', 'status': 'cancel_requested'})
            result = store.update_task('test', status='queued', environment_ready=True)
            self.assertEqual(result['status'], 'cancel_requested')

    async def test_restart_offers_recovery_for_previously_stuck_audit(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / 'state.json')
            store.add_task({'id': 'test', 'status': 'preparing', 'automatic_environment': True, 'environment_ready': True})
            self.assertEqual(store.recover_interrupted(), [])
            task = store.get_task('test')
            self.assertEqual((task['status'], task['pause_reason']), ('paused', 'manual'))
            self.assertFalse(task['environment_ready'])

    async def test_failed_start_cleans_up_and_runner_never_audits(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            task = {'id': 'test', 'workspace': str(root), 'status': 'queued', 'automatic_environment': True}
            store = mock.Mock()
            store.get_task.side_effect = lambda _: task.copy()
            store.update_task.side_effect = lambda task_id, **fields: task.update(fields) or task.copy()
            with mock.patch('app.environment_test._run', new=mock.AsyncMock(side_effect=[(False, 'docker unavailable'), (True, '')])) as run, mock.patch.object(runner, '_audit', new=mock.AsyncMock()) as audit, mock.patch.object(runner, '_emit'):
                await runner.run_task('test', store, mock.Mock())
            audit.assert_not_awaited()
            self.assertIn('docker unavailable', task['error'])
            self.assertEqual(task['environment_status'], 'failed')
            self.assertEqual(run.await_args_list[-1].args[0][-1], '--cleanup')
            self.assertFalse((root / 'runtime').exists())

    async def test_generic_initialization_uses_run_directory_and_checks_accounts(self):
        from test_generic_receipt_adapter import config
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            environment = prepare(root)
            data = dict(MANIFEST)
            data['adapter'] = 'generic-compose'
            (environment / 'receipt-manifest.json').write_text(json.dumps(data), encoding='utf-8')
            (environment / 'receipt-adapter.json').write_text(json.dumps(config()), encoding='utf-8')
            run_dirs = []
            async def run(command, cwd, timeout, env=None):
                if command[0] == 'docker':
                    return True, 'docker'
                self.assertIsNotNone(env)
                run_dirs.append(Path(env['RECEIPT_RUN_DIR']))
                self.assertEqual(env['COMPOSE_PROJECT_NAME'], 'receipt-' + env['RECEIPT_RUN_ID'])
                if '--verify' in command:
                    return True, 'ACCOUNTS_VERIFIED' if 'create-accounts' in ' '.join(command) else 'ENVIRONMENT_READY'
                if 'create-accounts' in ' '.join(command):
                    info = {'base_url': 'http://127.0.0.1:1234/', 'accounts': {'a': {'username': 'a', 'password': 'x'}}}
                    (run_dirs[-1] / 'receipt-run.json').write_text(json.dumps(info), encoding='utf-8')
                return True, ''
            with mock.patch('app.environment_test._run', side_effect=run):
                checks = await test_environment(root)
            self.assertFalse(next(item for item in checks if item['id'] == 'receipt_run')['ok'])
            self.assertTrue(next(item for item in checks if item['id'] == 'retained')['message'].find(str(run_dirs[0])) >= 0)
            self.assertTrue(run_dirs[0].exists())

    async def test_real_scripts_are_executed_and_cleaned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            environment = prepare(root)
            (environment / 'start.py').write_text('import pathlib, sys\np = pathlib.Path(__file__).parent / "running"\nif "--verify" in sys.argv: print("ENVIRONMENT_READY")\nelif "--cleanup" in sys.argv: p.unlink(missing_ok=True)\nelse: p.write_text("ok")\n', encoding='utf-8')
            (environment / 'create-accounts.py').write_text('import sys\nACCOUNT_PLAN = "account-plan.json"\nif "--verify" in sys.argv: print("ACCOUNTS_VERIFIED")\n', encoding='utf-8')

            async def run(command, cwd, timeout, env=None):
                if command[0] == 'docker':
                    return True, 'test docker'
                return await _run(command, cwd, timeout, env)

            with mock.patch('app.environment_test._run', side_effect=run):
                checks = await test_environment(root)
            self.assertTrue(all(item['ok'] for item in checks), checks)
            self.assertEqual(list((root / 'runtime' / 'initialization').iterdir()), [])

    async def test_successful_cleanup_deletes_readonly_git_objects(self):
        import os
        import stat
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            environment = prepare(root)
            pack = environment / 'cacti' / '.git' / 'objects' / 'pack' / 'pack.idx'
            pack.parent.mkdir(parents=True)
            pack.write_bytes(b'idx')
            os.chmod(pack, stat.S_IREAD)
            (environment / 'start.py').write_text('import pathlib, sys\np = pathlib.Path(__file__).parent / "running"\nif "--verify" in sys.argv: print("ENVIRONMENT_READY")\nelif "--cleanup" in sys.argv: p.unlink(missing_ok=True)\nelse: p.write_text("ok")\n', encoding='utf-8')
            (environment / 'create-accounts.py').write_text('import sys\nACCOUNT_PLAN = "account-plan.json"\nif "--verify" in sys.argv: print("ACCOUNTS_VERIFIED")\n', encoding='utf-8')

            async def run(command, cwd, timeout, env=None):
                if command[0] == 'docker':
                    return True, 'test docker'
                return await _run(command, cwd, timeout, env)

            with mock.patch('app.environment_test._run', side_effect=run):
                checks = await test_environment(root)
            self.assertTrue(all(item['ok'] for item in checks), checks)
            self.assertEqual(list((root / 'runtime' / 'initialization').iterdir()), [])
            self.assertTrue(pack.is_file())

    async def test_runs_a_real_process_and_reports_exit_code(self):
        import sys
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / 'check.py'
            script.write_text('import sys\nprint("diagnostic")\nsys.exit(7)\n', encoding='utf-8')
            ok, output = await _run([sys.executable, str(script)], root, 10)
            self.assertFalse(ok)
            self.assertIn('diagnostic', output)

    async def test_process_output_is_streamed_before_exit_and_redacted(self):
        import sys
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / 'check.py'
            script.write_text('import time\nprint(\'password=secret\', flush=True)\ntime.sleep(0.5)\nprint("done", flush=True)\n', encoding='utf-8')
            lines = []
            received = asyncio.Event()
            def on_output(line):
                lines.append(line)
                received.set()
            job = asyncio.create_task(_run([sys.executable, str(script)], root, 10, on_output=on_output))
            await asyncio.wait_for(received.wait(), 5)
            self.assertFalse(job.done())
            self.assertEqual(lines, ['password=***'])
            ok, output = await job
            self.assertTrue(ok)
            self.assertIn('done', output)
            self.assertNotIn('secret', output)

    async def test_timeout_keeps_already_streamed_output(self):
        import sys
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / 'check.py'
            script.write_text('import time\nprint("waiting", flush=True)\ntime.sleep(10)\n', encoding='utf-8')
            lines = []
            ok, detail = await _run([sys.executable, str(script)], root, 1, on_output=lines.append)
            self.assertFalse(ok)
            self.assertIn('超时', detail)
            self.assertIn('waiting', lines)

    async def test_failed_environment_retains_run_and_script_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            replies = [(True, 'docker'), (True, 'started'), (True, 'ENVIRONMENT_READY'), (True, 'created'), (False, 'login failed'), (True, '')]
            with mock.patch('app.environment_test._run', new=mock.AsyncMock(side_effect=replies)) as run:
                checks = await test_environment(root)
            self.assertEqual([x['id'] for x in checks[-6:]], ['docker', 'start_run', 'health', 'accounts_run', 'accounts_verify', 'retained'])
            self.assertFalse(checks[-2]['ok'])
            self.assertFalse(any('--cleanup' in call.args[0] for call in run.await_args_list))
            env = run.await_args_list[-1].args[3]
            self.assertEqual(run.await_args_list[-1].args[0], ['docker', 'compose', '-p', env['COMPOSE_PROJECT_NAME'], 'stop'])
            self.assertTrue(Path(env['RECEIPT_RUN_DIR']).is_dir())
            self.assertTrue((Path(env['RECEIPT_RUN_DIR']).parent / 'environment' / 'start.py').is_file())
            self.assertIn(env['COMPOSE_PROJECT_NAME'], checks[-1]['message'])
            self.assertIn('容器已停止', checks[-1]['message'])

    async def test_failed_cleanup_retains_environment_and_reports_stop_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            replies = [(True, 'docker'), (True, ''), (True, 'ENVIRONMENT_READY'),
                       (True, ''), (True, 'ACCOUNTS_VERIFIED'), (False, 'cleanup failed'),
                       (False, 'stop failed')]
            with mock.patch('app.environment_test._run', new=mock.AsyncMock(side_effect=replies)) as run:
                checks = await test_environment(root)
            self.assertEqual(checks[-2]['id'], 'cleanup')
            self.assertIn('cleanup failed', checks[-2]['message'])
            self.assertIn('容器停止失败：stop failed', checks[-1]['message'])
            self.assertEqual(run.await_args_list[-1].args[0][-1], 'stop')
            self.assertTrue(Path(run.await_args_list[-1].args[3]['RECEIPT_RUN_DIR']).is_dir())

    async def test_docker_failure_does_not_execute_scripts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            with mock.patch('app.environment_test._run', new=mock.AsyncMock(return_value=(False, 'daemon unavailable'))) as run:
                checks = await test_environment(root)
            self.assertFalse(checks[-1]['ok'])
            self.assertEqual(run.await_count, 1)

    async def test_only_python_scripts_are_accepted_and_checked_for_syntax(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            environment = prepare(root)
            (environment / 'start.py').unlink()
            (environment / 'start.ps1').write_text('exit 0', encoding='utf-8')
            self.assertFalse(next(item for item in check_environment(root) if item['id'] == 'start')['ok'])
            (environment / 'start.py').write_text('def broken(:', encoding='utf-8')
            self.assertFalse(next(item for item in check_environment(root) if item['id'] == 'start')['ok'])

    async def test_failed_attempt_snapshots_are_isolated_from_later_edits(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            environment = prepare(root)
            async def run(command, cwd, timeout, env=None):
                return (True, 'docker') if command[0] == 'docker' else (False, 'start failed')
            with mock.patch('app.environment_test._run', side_effect=run):
                first = await test_environment(root)
                (environment / 'start.py').write_text('print("changed")', encoding='utf-8')
                second = await test_environment(root)
            runs = list((root / 'runtime' / 'initialization').iterdir())
            self.assertEqual(len(runs), 2)
            self.assertEqual({(item / 'environment' / 'start.py').read_text(encoding='utf-8') for item in runs}, {'pass', 'print("changed")'})
            self.assertNotEqual(first[-1]['message'], second[-1]['message'])

    async def test_manifest_is_validated_only_for_initialization(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            environment = prepare(root)
            (environment / 'receipt-manifest.json').write_text('{}', encoding='utf-8')
            self.assertTrue(all(item['ok'] for item in check_environment(root)))
            self.assertFalse(all(item['ok'] for item in check_environment(root, require_manifest=True)))

    async def test_initialization_retries_five_times_then_records_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'source'
            source.mkdir()
            prepare(root)
            task = {'workspace': str(root), 'source_dir': str(source), 'provider_id': 'p', 'prices': {}}
            store = mock.Mock()
            store.get_task.return_value = task
            store.get_provider.return_value = {'api_key': ''}
            client = mock.MagicMock()
            client.__aenter__ = mock.AsyncMock(return_value=client)
            client.__aexit__ = mock.AsyncMock(return_value=None)
            client.query = mock.AsyncMock()
            bad = [{'id': 'docker', 'ok': False, 'message': 'daemon unavailable'}]
            with mock.patch('claude_agent_sdk.ClaudeSDKClient', return_value=client), mock.patch.object(runner, 'prepare_workspace', return_value=root), mock.patch.object(runner, '_build_options'), mock.patch.object(runner, '_consume_run', new=mock.AsyncMock(return_value='ok')), mock.patch.object(runner, 'test_environment', new=mock.AsyncMock(return_value=bad)), mock.patch.object(runner, '_emit'), mock.patch.object(runner.Ledger, 'from_snapshot'), mock.patch.object(runner.Prices, 'from_mapping'):
                result = await runner._prepare_environment('t', store, mock.Mock())
            self.assertFalse(result)
            self.assertEqual(client.query.await_count, 6)
            self.assertIn('daemon unavailable', client.query.await_args_list[1].args[0])
            self.assertIn('第 6 次测试', (root / 'environment' / 'INITIALIZATION_FAILED.md').read_text(encoding='utf-8'))
            self.assertEqual(store.update_task.call_args.kwargs['environment_status'], 'failed')

    async def test_initialization_stops_when_agent_reports_unbuildable_commit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            task = {'workspace': str(root), 'source_dir': str(root), 'provider_id': 'p', 'prices': {}}
            store = mock.Mock()
            store.get_task.return_value = task
            store.get_provider.return_value = {'api_key': ''}
            client = mock.MagicMock()
            client.__aenter__ = mock.AsyncMock(return_value=client)
            client.__aexit__ = mock.AsyncMock(return_value=None)
            client.query = mock.AsyncMock()

            async def report_failure(*args, **kwargs):
                (root / 'environment' / 'INITIALIZATION_FAILED.md').write_text(
                    '最新提交无法编译：构建依赖的私有包不可用\n', encoding='utf-8')
                return 'ok'

            with mock.patch('claude_agent_sdk.ClaudeSDKClient', return_value=client), mock.patch.object(runner, 'prepare_workspace', return_value=root), mock.patch.object(runner, '_build_options'), mock.patch.object(runner, '_consume_run', side_effect=report_failure), mock.patch.object(runner, 'test_environment', new=mock.AsyncMock()) as test, mock.patch.object(runner, '_emit'), mock.patch.object(runner.Ledger, 'from_snapshot'), mock.patch.object(runner.Prices, 'from_mapping'):
                self.assertFalse(await runner._prepare_environment('t', store, mock.Mock()))
            test.assert_not_called()
            self.assertIn('私有包不可用', (root / 'environment' / 'INITIALIZATION_FAILED.md').read_text(encoding='utf-8'))
            self.assertEqual(store.update_task.call_args.kwargs['environment_status'], 'failed')

    async def test_initialization_keeps_model_failure_in_final_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            task = {'workspace': str(root), 'source_dir': str(root), 'provider_id': 'p', 'prices': {}}
            store = mock.Mock()
            store.get_task.side_effect = lambda _: task.copy()
            store.update_task.side_effect = lambda _, **fields: task.update(fields)
            store.get_provider.return_value = {'api_key': 'secret'}
            client = mock.MagicMock()
            client.__aenter__ = mock.AsyncMock(return_value=client)
            client.__aexit__ = mock.AsyncMock(return_value=None)
            client.query = mock.AsyncMock()

            async def fail(*args, **kwargs):
                task['error'] = 'API Error 500 secret'
                return 'error'

            with mock.patch('claude_agent_sdk.ClaudeSDKClient', return_value=client), mock.patch.object(runner, 'prepare_workspace', return_value=root), mock.patch.object(runner, '_build_options'), mock.patch.object(runner, '_consume_run', side_effect=fail), mock.patch.object(runner, '_emit'), mock.patch.object(runner.Ledger, 'from_snapshot'), mock.patch.object(runner.Prices, 'from_mapping'):
                self.assertFalse(await runner._prepare_environment('t', store, mock.Mock()))
            self.assertEqual(task['error'], '环境准备 Agent 未能完成：API Error 500 ***')

    async def test_initialization_polls_quota_and_retries_without_spending_repair_attempt(self):
        for first in ('quota', RuntimeError('HTTP 429')):
            with self.subTest(first=first), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                prepare(root)
                task = {'workspace': str(root), 'source_dir': str(root), 'provider_id': 'p', 'model': 'demo', 'prices': {}}
                store = mock.Mock()
                store.get_task.side_effect = lambda _: task.copy()
                store.update_task.side_effect = lambda _, **fields: task.update(fields)
                store.get_provider.return_value = {'api_key': 'key', 'base_url': 'https://example.com'}
                clients = []
                def make_client(**kwargs):
                    client = mock.MagicMock()
                    client.__aenter__ = mock.AsyncMock(return_value=client)
                    client.__aexit__ = mock.AsyncMock(return_value=None)
                    client.query = mock.AsyncMock()
                    clients.append(client)
                    return client
                probes = [{'ok': False, 'message': 'HTTP 429'}, {'ok': True}]
                with mock.patch('claude_agent_sdk.ClaudeSDKClient', side_effect=make_client), mock.patch.object(runner, 'QUOTA_POLL_SECONDS', 0), mock.patch.object(runner, 'quota_probe', side_effect=probes) as probe, mock.patch.object(runner, 'prepare_workspace', return_value=root), mock.patch.object(runner, '_build_options'), mock.patch.object(runner, '_consume_run', new=mock.AsyncMock(side_effect=[first, 'ok'])), mock.patch.object(runner, 'test_environment', new=mock.AsyncMock(return_value=[{'id': 'ok', 'ok': True, 'message': 'ok'}])) as test, mock.patch.object(runner, '_emit'), mock.patch.object(runner.Ledger, 'from_snapshot'), mock.patch.object(runner.Prices, 'from_mapping'):
                    self.assertTrue(await runner._prepare_environment('t', store, mock.Mock()))
                self.assertEqual(probe.call_count, 2)
                self.assertEqual(probe.call_args.args, ('https://example.com', 'key', 'demo'))
                self.assertEqual(len(clients), 2)
                self.assertEqual(clients[0].query.await_args, clients[1].query.await_args)
                self.assertEqual(test.await_count, 1)
                self.assertIsNone(task['pause_reason'])

    async def test_quota_wait_checks_stop_before_polling(self):
        store = mock.Mock()
        checkpoint = mock.AsyncMock(side_effect=runner.InitializationStopped())
        with mock.patch.object(runner, 'quota_probe') as probe, mock.patch.object(runner, '_emit'):
            with self.assertRaises(runner.InitializationStopped):
                await runner._hold_initialization_for_quota(store, mock.Mock(), 'project:p', '', 'key', 'demo', checkpoint)
        probe.assert_not_called()

    async def test_task_preparation_keeps_manifest_out_of_audit_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            task = {'workspace': str(root), 'source_dir': str(root), 'provider_id': 'p', 'prices': {}}
            store = mock.Mock()
            store.get_task.return_value = task
            store.get_provider.return_value = {'api_key': ''}
            client = mock.MagicMock()
            client.__aenter__ = mock.AsyncMock(return_value=client)
            client.__aexit__ = mock.AsyncMock(return_value=None)
            client.query = mock.AsyncMock()
            with mock.patch('claude_agent_sdk.ClaudeSDKClient', return_value=client), mock.patch.object(runner, 'prepare_workspace', return_value=root), mock.patch.object(runner, '_build_options'), mock.patch.object(runner, '_consume_run', new=mock.AsyncMock(return_value='ok')), mock.patch.object(runner, 'test_environment', new=mock.AsyncMock(return_value=[{'id': 'ok', 'ok': True, 'message': 'ok'}])), mock.patch.object(runner, '_emit'), mock.patch.object(runner.Ledger, 'from_snapshot'), mock.patch.object(runner.Prices, 'from_mapping'):
                self.assertTrue(await runner._prepare_environment('t', store, mock.Mock()))
            self.assertFalse((root / 'environment' / 'receipt-manifest.json').exists())
            self.assertEqual(len(list((root / 'receipt').glob('initialization-manifest-*.json'))), 1)
