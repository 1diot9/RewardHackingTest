from __future__ import annotations

import asyncio
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

import app.main as main
from app.store import Store
from test_threat_model import write_closed_model


class ProjectLifecycleTests(unittest.TestCase):
    def test_failed_initialization_can_resume_with_existing_workspace(self) -> None:
        async def scenario(root: Path) -> None:
            test_store = Store(root / 'state.json')
            original = {'status': 'draft', 'environment_status': 'failed', 'error': 'rate limit exceeded',
                        'workspace': str(root), 'provider_id': 'original', 'model': 'original-model',
                        'instruction': 'keep existing files', 'github_synced': True, 'next_seq': 1}
            test_store.add_project({'id': 'p1', 'initialization': original})
            with mock.patch.object(main, 'store', test_store), mock.patch.object(main, '_schedule_project_initialization') as schedule:
                project = await main.resume_project_initialization('p1')
            resumed = project['initialization']
            self.assertEqual((resumed['status'], resumed['environment_status']), ('preparing', 'preparing'))
            self.assertIsNone(resumed['error'])
            self.assertTrue(resumed['resume_existing'])
            for field in ('workspace', 'provider_id', 'model', 'instruction', 'github_synced'):
                self.assertEqual(resumed[field], original[field])
            schedule.assert_called_once_with('p1', resume=True)

        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(scenario(Path(directory)))

    def test_pause_interrupts_active_initialization_and_resume_retries(self) -> None:
        from app import runner

        async def scenario(root: Path) -> None:
            source = root / 'source'
            source.mkdir()
            task = {'status': 'preparing', 'environment_status': 'preparing', 'workspace': str(root),
                    'source_dir': str(source), 'provider_id': 'p', 'model': 'demo', 'prices': {}, 'next_seq': 1}
            test_store = Store(root / 'state.json')
            test_store.add_project({'id': 'p1', 'initialization': task})
            started, released = asyncio.Event(), asyncio.Event()
            clients = []

            def make_client(**kwargs):
                client = mock.MagicMock()
                client.__aenter__ = mock.AsyncMock(return_value=client)
                client.__aexit__ = mock.AsyncMock(return_value=None)
                client.query = mock.AsyncMock()
                client.interrupt = mock.AsyncMock(side_effect=released.set)
                clients.append(client)
                return client

            async def consume(*args, **kwargs):
                if len(clients) == 1:
                    started.set()
                    await released.wait()
                    return 'error'
                return 'ok'

            with mock.patch.object(main, 'store', test_store), mock.patch.object(test_store, 'get_provider', return_value={'api_key': 'key'}), mock.patch('claude_agent_sdk.ClaudeSDKClient', side_effect=make_client), mock.patch.object(runner, '_build_options'), mock.patch.object(runner.Prices, 'from_mapping'), mock.patch.object(runner, '_consume_run', side_effect=consume), mock.patch.object(runner, 'test_environment', new=mock.AsyncMock(return_value=[{'id': 'ok', 'ok': True, 'message': 'ok'}])):
                job = main._schedule_project_initialization('p1')
                try:
                    waiter = asyncio.create_task(started.wait())
                    await asyncio.wait({waiter, job}, timeout=2, return_when=asyncio.FIRST_COMPLETED)
                    waiter.cancel()
                    self.assertTrue(started.is_set(), test_store.get_project('p1')['initialization'].get('error'))
                    await main.pause_project_initialization('p1')
                    async def wait_paused():
                        while test_store.get_project('p1')['initialization']['status'] != 'paused':
                            await asyncio.sleep(0.01)
                    await asyncio.wait_for(wait_paused(), 3)
                    clients[0].interrupt.assert_awaited_once()
                    await main.resume_project_initialization('p1')
                    await asyncio.wait_for(job, 3)
                    self.assertEqual(test_store.get_project('p1')['initialization']['environment_status'], 'ready')
                    self.assertEqual(len(clients), 2)
                    self.assertEqual(clients[0].query.await_args, clients[1].query.await_args)
                finally:
                    if not job.done():
                        job.cancel()
                        await asyncio.gather(job, return_exceptions=True)
                    main._PROJECT_RUNNING.pop('p1', None)
                    main._PROJECT_RESUME.pop('p1', None)

        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(scenario(Path(directory)))

    def test_initialization_stop_during_work_and_pause(self) -> None:
        async def scenario(root: Path, paused: bool) -> None:
            test_store = Store(root / 'state.json')
            test_store.add_project({'id': 'p1', 'initialization': {'status': 'preparing', 'environment_status': 'preparing', 'workspace': str(root), 'next_seq': 1}})
            started = asyncio.Event()
            proceed = asyncio.Event()
            continued = []

            async def prepare(task_id, adapter, hub):
                started.set()
                await proceed.wait()
                await adapter.checkpoint(task_id)
                continued.append(True)
                return True

            with mock.patch.object(main, 'store', test_store), mock.patch.object(main, '_prepare_environment', side_effect=prepare):
                job = main._schedule_project_initialization('p1')
                try:
                    await started.wait()
                    if paused:
                        await main.pause_project_initialization('p1')
                        proceed.set()
                        await asyncio.sleep(0)
                        self.assertEqual(test_store.get_project('p1')['initialization']['status'], 'paused')
                    result = await main.stop_project_initialization('p1')
                    self.assertEqual(result['initialization']['status'], 'stop_requested')
                    proceed.set()
                    await asyncio.wait_for(job, 1)
                    self.assertEqual(test_store.get_project('p1')['initialization']['environment_status'], 'stopped')
                    self.assertFalse(continued)
                finally:
                    main._PROJECT_RUNNING.pop('p1', None)
                    main._PROJECT_RESUME.pop('p1', None)

        for paused in (False, True):
            with self.subTest(paused=paused), tempfile.TemporaryDirectory() as directory:
                asyncio.run(scenario(Path(directory), paused))

    def test_initialization_stop_survives_restart_and_stopped_pause_needs_no_job(self) -> None:
        async def scenario(root: Path) -> None:
            test_store = Store(root / 'state.json')
            test_store.add_project({'id': 'p1', 'initialization': {'status': 'stop_requested', 'environment_status': 'stop_requested'}})
            test_store.add_project({'id': 'p2', 'initialization': {'status': 'paused', 'environment_status': 'paused', 'workspace': str(root), 'next_seq': 1}})
            test_store.recover_interrupted()
            self.assertEqual(test_store.get_project('p1')['initialization']['status'], 'stopped')
            with mock.patch.object(main, 'store', test_store):
                result = await main.stop_project_initialization('p2')
            self.assertEqual(result['initialization']['status'], 'stopped')

        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(scenario(Path(directory)))

    def test_initialization_pause_waits_at_checkpoint_and_resumes(self) -> None:
        async def scenario(root: Path) -> None:
            test_store = Store(root / 'state.json')
            test_store.add_project({'id': 'p1', 'initialization': {'status': 'preparing', 'environment_status': 'preparing', 'workspace': str(root), 'next_seq': 1}})
            started = asyncio.Event()
            proceed = asyncio.Event()

            async def work() -> None:
                started.set()
                await proceed.wait()
                await main.ProjectInitializationStore('p1').checkpoint('project:p1')

            with mock.patch.object(main, 'store', test_store):
                job = asyncio.create_task(work())
                main._PROJECT_RUNNING['p1'] = job
                try:
                    await started.wait()
                    result = await main.pause_project_initialization('p1')
                    self.assertEqual(result['initialization']['status'], 'pause_requested')
                    proceed.set()
                    await asyncio.sleep(0)
                    self.assertEqual(test_store.get_project('p1')['initialization']['status'], 'paused')
                    self.assertFalse(job.done())
                    result = await main.resume_project_initialization('p1')
                    self.assertEqual(result['initialization']['status'], 'preparing')
                    await asyncio.wait_for(job, 1)
                finally:
                    main._PROJECT_RUNNING.pop('p1', None)
                    main._PROJECT_RESUME.pop('p1', None)

        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(scenario(Path(directory)))

    def test_initialization_pause_request_survives_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            test_store = Store(Path(directory) / 'state.json')
            test_store.add_project({'id': 'p1', 'initialization': {'status': 'pause_requested', 'environment_status': 'pause_requested'}})
            test_store.recover_interrupted()
            initialization = test_store.get_project('p1')['initialization']
            self.assertEqual((initialization['status'], initialization['environment_status']), ('paused', 'paused'))

    def test_restart_schedules_initialization_and_keeps_manual_pause(self) -> None:
        async def scenario(root: Path) -> None:
            test_store = Store(root / 'state.json')
            for project_id, status, reason in [('active', 'preparing', None), ('old_restart', 'paused', 'restart'), ('manual', 'paused', 'manual')]:
                test_store.add_project({'id': project_id, 'initialization': {'status': status, 'environment_status': status, 'pause_reason': reason}})
            with mock.patch.object(main, 'store', test_store), mock.patch.object(main, '_schedule_project_initialization') as schedule:
                async with main.lifespan(main.app):
                    self.assertEqual({call.args[0] for call in schedule.call_args_list}, {'active', 'old_restart'})
                    self.assertTrue(all(call.kwargs['resume'] for call in schedule.call_args_list))
                    self.assertEqual(test_store.get_project('manual')['initialization']['status'], 'paused')

        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(scenario(Path(directory)))

    def test_restart_recovers_task_preparation_by_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            test_store = Store(Path(directory) / 'state.json')
            for task_id, mode in [('audit', 'audit'), ('manual', 'manual')]:
                test_store.add_task({'id': task_id, 'status': 'preparing', 'preparation_mode': mode})
            self.assertEqual(test_store.recover_interrupted(), ['audit'])
            self.assertEqual(test_store.get_task('audit')['status'], 'queued')
            self.assertEqual(test_store.get_task('manual')['status'], 'preparing')

    def test_pending_reports_are_replayed_and_missing_candidates_are_returned_to_agent(self) -> None:
        from app import runner
        from app.reports import list_reports, save_review

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'findings').mkdir()
            for name in ('linked', 'unlinked', 'passed'):
                (root / 'findings' / f'{name}.md').write_text('## 标题\n测试', encoding='utf-8')
            save_review(root, 'findings/linked.md', 'linked', None)
            save_review(root, 'findings/passed.md', 'passed', 'ACCEPTED')
            from app.receipt import commit_receipt_candidate
            commit_receipt_candidate(root, 'http://127.0.0.1:1234/', {
                'poc_id': 'linked', 'marker': 'xss001linked', 'victim': {'url': '/linked', 'actions': []},
            })
            verify = mock.AsyncMock(return_value={'poc_id': 'linked', 'verdict': 'REJECTED', 'reason': 'ATTACKER_FAILED'})
            feedback = asyncio.run(runner._verify_pending_reports(root, 'http://127.0.0.1:1234/', verify))
            verify.assert_awaited_once_with('linked', 'findings/linked.md')
            self.assertIn('findings/unlinked.md', feedback)
            self.assertIn('没有可重放的关联候选项', feedback)
            self.assertIn('ATTACKER_FAILED', feedback)
            statuses = {report.path: report.review_status for report in list_reports(root, True)}
            self.assertEqual(statuses['findings/linked.md'], 'failed')
            self.assertEqual(statuses['findings/unlinked.md'], 'pending')
            self.assertEqual(statuses['findings/passed.md'], 'passed')
            feedback = asyncio.run(runner._verify_pending_reports(root, 'http://127.0.0.1:1234/', verify, {'findings/passed.md'}))
            self.assertEqual(verify.await_count, 1)  # Passed report has no candidate and is returned for preparation.
            self.assertIn('findings/passed.md', feedback)

    def test_human_report_review_persists_separately_from_automatic_review(self) -> None:
        from app.reports import save_review
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'findings').mkdir()
            (root / 'findings' / 'demo.md').write_text('## 标题\n测试', encoding='utf-8')
            save_review(root, 'findings/demo.md', 'demo', 'ACCEPTED')
            store = Store(root / 'state.json')
            store.add_task({'id': 't1', 'status': 'completed', 'workspace': raw, 'receipt_enabled': True})
            with mock.patch.object(main, 'store', store), TestClient(main.app) as client:
                url = '/api/tasks/t1/reports/human-review'
                body = {'path': 'findings/demo.md', 'status': 'false_positive', 'comment': '人工复核依据'}
                self.assertEqual(client.put(url, json=body).status_code, 200)
                report = client.get('/api/tasks/t1/reports').json()['reports'][0]
                self.assertEqual(report['review_status'], 'passed')
                self.assertEqual(report['human_review'], {'status': 'false_positive', 'comment': '人工复核依据'})
                body.update(status='confirmed', comment='补充验证')
                self.assertEqual(client.put(url, json=body).status_code, 200)
                self.assertEqual(client.get('/api/tasks/t1/reports').json()['reports'][0]['human_review']['comment'], '补充验证')
                self.assertEqual(client.put(url, json={**body, 'path': '../state.json'}).status_code, 404)
                self.assertEqual(client.put(url, json={**body, 'status': 'invalid'}).status_code, 422)
                self.assertEqual(client.put(url, json={**body, 'comment': 'x' * 8001}).status_code, 422)
                self.assertEqual(client.put('/api/tasks/missing/reports/human-review', json=body).status_code, 404)

    def test_pending_review_queues_unpassed_reports_and_uses_dedicated_prompt(self) -> None:
        from app import runner
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'findings').mkdir()
            (root / 'receipt').mkdir()
            for name in ('pending', 'passed', 'failed'):
                (root / 'findings' / f'{name}.md').write_text('## 标题\n测试', encoding='utf-8')
            (root / 'receipt' / 'report-reviews.json').write_text(json.dumps({
                'findings/passed.md': {'poc_id': 'passed', 'verdict': 'ACCEPTED'},
                'findings/failed.md': {'poc_id': 'failed', 'verdict': 'REJECTED'},
            }), encoding='utf-8')
            candidates = root / 'receipt' / 'candidates'
            candidates.mkdir()
            (candidates / 'failed.json').write_text(json.dumps({
                'poc_id': 'failed', 'attacker_script': 'SECRET_SCRIPT_BODY', 'victim': {'url': '/failed', 'actions': []},
            }), encoding='utf-8')
            (candidates / 'passed.json').write_text(json.dumps({
                'poc_id': 'passed', 'victim': {'url': '/passed', 'actions': []},
            }), encoding='utf-8')
            store = Store(root / 'state.json')
            store.add_task({'id': 't1', 'status': 'completed', 'budget': 2, 'duration_seconds': 900, 'workspace': raw, 'receipt_enabled': True, 'completion_mode': 'continuous'})
            with mock.patch.object(main, 'store', store), mock.patch.object(main, '_schedule_task') as schedule, mock.patch.object(main, '_refresh_follow_up_environment'):
                with TestClient(main.app) as client:
                    response = client.post('/api/tasks/t1/review-pending', json={'budget': 1, 'duration_minutes': 5})
                    self.assertEqual(response.status_code, 200, response.text)
                    task = response.json()
                    self.assertEqual(set(task['pending_review_reports']), {'findings/pending.md', 'findings/failed.md'})
                    self.assertEqual(task['budget'], 3)
                    self.assertEqual(client.post('/api/tasks/t1/review-pending', json={}).status_code, 409)
                    schedule.assert_called_once_with('t1')
            with mock.patch.object(runner, '_variables', return_value={}):
                prompt = runner._audit_prompt(task, root, mock.Mock(spent=0), 60, 1, True)
            self.assertIn('findings/pending.md', prompt)
            self.assertIn('findings/failed.md', prompt)
            self.assertNotIn('findings/passed.md', prompt)
            self.assertIn('重新验证前必须先检查', prompt)
            self.assertIn('受害者行为脚本或声明式配置', prompt)
            self.assertIn('poc/failed.py', prompt)
            self.assertIn('/failed', prompt)
            self.assertNotIn('/passed', prompt)
            self.assertNotIn('SECRET_SCRIPT_BODY', prompt)
            self.assertIn('不要寻找或报告新漏洞', prompt)

    def test_review_all_includes_passed_reports(self) -> None:
        from app.reports import save_review
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'findings').mkdir()
            for name in ('passed', 'pending'):
                (root / 'findings' / f'{name}.md').write_text('测试', encoding='utf-8')
            save_review(root, 'findings/passed.md', 'passed', 'ACCEPTED')
            store = Store(root / 'state.json')
            store.add_task({'id': 't1', 'status': 'completed', 'budget': 2, 'duration_seconds': 900, 'workspace': raw, 'receipt_enabled': True})
            with mock.patch.object(main, 'store', store), mock.patch.object(main, '_schedule_task'), mock.patch.object(main, '_refresh_follow_up_environment'), TestClient(main.app) as client:
                response = client.post('/api/tasks/t1/review-all', json={})
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(set(response.json()['pending_review_reports']), {'findings/passed.md', 'findings/pending.md'})

    def test_pending_review_requires_validator_and_pending_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            store = Store(Path(raw) / 'state.json')
            store.add_task({'id': 't1', 'status': 'completed', 'workspace': raw, 'receipt_enabled': False})
            with mock.patch.object(main, 'store', store), TestClient(main.app) as client:
                self.assertEqual(client.post('/api/tasks/t1/review-pending', json={}).status_code, 409)
                store.update_task('t1', receipt_enabled=True)
                self.assertEqual(client.post('/api/tasks/t1/review-pending', json={}).status_code, 409)

    def test_follow_up_limits_default_to_zero_and_reject_negative_values(self) -> None:
        from pydantic import ValidationError
        follow_up = main.FollowUpIn(instruction='重新验证')
        self.assertEqual(follow_up.budget, 0)
        self.assertEqual(follow_up.duration_minutes, 0)
        for values in ({'budget': -1}, {'duration_minutes': -1}):
            with self.assertRaises(ValidationError):
                main.FollowUpIn(instruction='重新验证', **values)

    def test_follow_up_always_refreshes_project_environment(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = Store(root / 'state.json')
            project_id = 'e' * 32
            source = root / 'projects' / project_id / 'source'
            environment = source.parent / 'setup' / 'environment'
            old = write_closed_model(environment, source, attacker='editor', victim='owner', path_id='editor-owner')
            (environment / 'receipt-manifest.json').write_text(json.dumps(old), encoding='utf-8')
            store.add_project({'id': project_id, 'name': 'demo', 'source_dir': str(source), 'initialization': {'environment_status': 'ready'}})
            manifests = root / 'manifests'

            def add_task(task_id: str) -> Path:
                workspace = root / 'workspaces' / task_id
                (workspace / 'environment').mkdir(parents=True)
                (workspace / 'findings').mkdir()
                (workspace / 'findings' / 'pending.md').write_text('## 标题\n待验证', encoding='utf-8')
                for name, content in {
                    'receipt-manifest.json': json.dumps(old),
                    'account-plan.json': '{"accounts":[]}',
                    'create-accounts.py': 'old\n',
                }.items():
                    (workspace / 'environment' / name).write_text(content, encoding='utf-8')
                snapshot = manifests / f'task-{task_id}'
                snapshot.mkdir(parents=True)
                (manifests / f'task-{task_id}.json').write_text(json.dumps(old), encoding='utf-8')
                for name, content in {
                    'receipt-manifest.json': json.dumps(old),
                    'account-plan.json': '{}',
                    'create-accounts.py': 'old\n',
                }.items():
                    (snapshot / name).write_text(content, encoding='utf-8')
                store.add_task({
                    'id': task_id,
                    'status': 'completed',
                    'budget': 1,
                    'duration_seconds': 60,
                    'workspace': str(workspace),
                    'project_id': project_id,
                    'receipt_enabled': True,
                    'receipt_manifest': f'task-{task_id}.json',
                    'generated_receipt_manifest': f'task-{task_id}.json',
                })
                return workspace

            kept = add_task('a' * 32)
            refreshed = add_task('b' * 32)
            store.update_task('b' * 32, environment_ready=True, environment_status='ready')
            blocked = add_task('c' * 32)
            updated = write_closed_model(environment, source, attacker='creator', victim='owner', path_id='creator-owner')
            (environment / 'receipt-manifest.json').write_text(json.dumps(updated), encoding='utf-8')
            (environment / 'create-accounts.py').write_text('ACCOUNT_PLAN = "account-plan.json"\nprint("new")\n', encoding='utf-8')
            (environment / 'extra-config.txt').write_text('latest', encoding='utf-8')
            (refreshed / 'environment' / 'obsolete.txt').write_text('old', encoding='utf-8')
            with mock.patch.object(main, 'store', store), mock.patch.object(main, 'PROJECTS_DIR', root / 'projects'), mock.patch.object(main, 'RECEIPT_MANIFESTS_DIR', manifests), mock.patch.object(main, 'target_adapter_for'), mock.patch.object(main, '_schedule_task'):
                with TestClient(main.app) as client:
                    unchanged = client.post('/api/tasks/' + 'a' * 32 + '/follow-up', json={'instruction': '继续', 'budget': 0, 'duration_minutes': 0})
                    self.assertEqual(unchanged.status_code, 200, unchanged.text)
                    self.assertEqual(json.loads((kept / 'environment' / 'receipt-manifest.json').read_text(encoding='utf-8')), updated)
                    refreshed_response = client.post('/api/tasks/' + 'b' * 32 + '/follow-up', json={'instruction': '按新清单复核', 'budget': 1, 'duration_minutes': 5, 'refresh_manifest': True})
                    self.assertEqual(refreshed_response.status_code, 200, refreshed_response.text)
                    self.assertIs(refreshed_response.json()['environment_ready'], False)
                    self.assertEqual(json.loads((refreshed / 'environment' / 'receipt-manifest.json').read_text(encoding='utf-8')), updated)
                    frozen = manifests / ('task-' + 'b' * 32)
                    self.assertEqual(json.loads((manifests / (frozen.name + '.json')).read_text(encoding='utf-8')), updated)
                    self.assertEqual(json.loads((frozen / 'receipt-manifest.json').read_text(encoding='utf-8')), updated)
                    self.assertIn('creator', (refreshed / 'environment' / 'account-plan.json').read_text(encoding='utf-8'))
                    self.assertIn('print("new")', (frozen / 'create-accounts.py').read_text(encoding='utf-8'))
                    self.assertEqual((frozen / 'extra-config.txt').read_text(encoding='utf-8'), 'latest')
                    self.assertEqual((refreshed / 'environment' / 'extra-config.txt').read_text(encoding='utf-8'), 'latest')
                    self.assertFalse((refreshed / 'environment' / 'obsolete.txt').exists())
                    review = client.post('/api/tasks/' + 'c' * 32 + '/review-pending', json={'budget': 0, 'duration_minutes': 0, 'refresh_manifest': True})
                    self.assertEqual(review.status_code, 200, review.text)
                    self.assertEqual(json.loads((blocked / 'environment' / 'receipt-manifest.json').read_text(encoding='utf-8')), updated)
                    decisions = json.loads((environment / 'threat-decisions.json').read_text(encoding='utf-8'))
                    decisions['roles'][0]['evidence'] = {'kind': 'assumption', 'path': '', 'literal': '资料不足'}
                    (environment / 'threat-decisions.json').write_text(json.dumps(decisions), encoding='utf-8')
                    stale = add_task('d' * 32)
                    rejected = client.post('/api/tasks/' + 'd' * 32 + '/follow-up', json={'instruction': '继续', 'refresh_manifest': True})
                    self.assertEqual(rejected.status_code, 409, rejected.text)
                    self.assertIn('未确认的假设', rejected.text)
                    self.assertEqual(store.get_task('d' * 32)['status'], 'completed')
                    self.assertEqual(json.loads((stale / 'environment' / 'receipt-manifest.json').read_text(encoding='utf-8')), old)

    def test_follow_up_reuses_task_and_extends_limits(self) -> None:
        from app.store import active_seconds
        with tempfile.TemporaryDirectory() as raw:
            store = Store(Path(raw) / 'state.json')
            store.add_task({'id': 't1', 'status': 'completed', 'started_at': '2020-01-01T00:00:00+00:00', 'finished_at': '2020-01-01T00:10:00+00:00', 'paused_seconds': 0, 'budget': 2, 'duration_seconds': 900, 'round': 2, 'workspace': raw, 'session_id': 'old'})
            with mock.patch.object(main, 'store', store), mock.patch.object(main, '_schedule_task') as schedule, mock.patch.object(main, '_refresh_follow_up_environment'):
                with TestClient(main.app) as client:
                    response = client.post('/api/tasks/t1/follow-up', json={'instruction': '重新验证已有漏洞', 'budget': 3, 'duration_minutes': 30})
                    self.assertEqual(response.status_code, 200, response.text)
                    task = response.json()
                    self.assertEqual(task['follow_up_instruction'], '重新验证已有漏洞')
                    self.assertTrue(task['follow_up_new_round'])
                    self.assertIsNone(task['session_id'])
                    self.assertEqual(task['budget'], 5)
                    self.assertEqual(task['duration_seconds'], 2700)
                    self.assertAlmostEqual(active_seconds(task), 600, delta=3)
                    self.assertEqual(client.post('/api/tasks/t1/follow-up', json={'instruction': '再次提交', 'budget': 1, 'duration_minutes': 1}).status_code, 409)
                    schedule.assert_called_once_with('t1')

    def test_stop_paused_task_allows_new_round_without_adding_budget(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            store = Store(Path(raw) / 'state.json')
            store.add_task({'id': 't1', 'status': 'paused', 'pause_reason': 'manual', 'paused_at': '2020-01-01T00:10:00+00:00', 'started_at': '2020-01-01T00:00:00+00:00', 'paused_seconds': 0, 'budget': 25, 'spent': 19, 'duration_seconds': 18000, 'round': 2, 'workspace': raw, 'session_id': 'old', 'next_seq': 1})
            with mock.patch.object(main, 'store', store), mock.patch.object(main, '_schedule_task'), mock.patch.object(main, '_refresh_follow_up_environment'):
                with TestClient(main.app) as client:
                    stopped = client.post('/api/tasks/t1/stop')
                    self.assertEqual(stopped.status_code, 200, stopped.text)
                    self.assertEqual(stopped.json()['status'], 'cancelled')
                    follow = client.post('/api/tasks/t1/follow-up', json={'instruction': '开始新一轮'})
                    self.assertEqual(follow.status_code, 200, follow.text)
                    self.assertIsNone(follow.json()['session_id'])
                    self.assertTrue(follow.json()['follow_up_new_round'])
                    self.assertEqual(follow.json()['budget'], 25)
                    self.assertEqual(follow.json()['spent'], 19)

    def test_stop_running_task_requests_interrupt(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            store = Store(Path(raw) / 'state.json')
            store.add_task({'id': 't1', 'status': 'running', 'workspace': raw})
            with mock.patch.object(main, 'store', store), mock.patch.object(main, '_schedule_task'), mock.patch.object(main, 'request_stop') as stop:
                with TestClient(main.app) as client:
                    response = client.post('/api/tasks/t1/stop')
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertEqual(response.json()['status'], 'cancel_requested')
                    stop.assert_called_once_with('t1', 'cancelled')

    def test_project_initialization_passes_proxy_to_agent(self) -> None:
        from app import runner

        async def scenario(root: Path) -> None:
            source = root / 'source'
            source.mkdir()
            task = {'workspace': str(root / 'setup'), 'source_dir': str(source), 'provider_id': 'p', 'model': 'm', 'prices': {}, 'instruction': '只修改启动脚本'}
            store = mock.Mock()
            store.get_project.return_value = {'initialization': task}
            store.get_provider.return_value = {'api_key': ''}
            store.get_proxy_settings.return_value = {'enabled': True, 'url': 'http://127.0.0.1:7890', 'no_proxy': 'internal.example'}
            client = mock.MagicMock()
            client.__aenter__ = mock.AsyncMock(return_value=client)
            client.__aexit__ = mock.AsyncMock(return_value=None)
            client.query = mock.AsyncMock()
            with mock.patch.object(main, 'store', store), mock.patch.object(runner, '_emit'), mock.patch('claude_agent_sdk.ClaudeSDKClient', return_value=client) as sdk, mock.patch.object(runner, '_consume_run', new=mock.AsyncMock(return_value='ok')), mock.patch.object(runner, 'test_environment', new=mock.AsyncMock(return_value=[{'ok': True}])), mock.patch.object(runner.Ledger, 'from_snapshot'), mock.patch.object(runner.Prices, 'from_mapping'):
                await main._initialize_project('p1')
            self.assertEqual(sdk.call_args.kwargs['options'].env['HTTPS_PROXY'], 'http://127.0.0.1:7890')
            self.assertIn('internal.example', sdk.call_args.kwargs['options'].env['NO_PROXY'])
            self.assertIn('只修改启动脚本', client.query.call_args_list[0].args[0])
            self.assertTrue(any(call.kwargs.get('environment_status') == 'ready' for call in store.update_project_initialization.call_args_list))

        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(scenario(Path(directory)))

    def test_create_project_from_github_and_reject_ambiguous_sources(self) -> None:
        from app.project_import import ImportedProject, ProjectImportError

        def download(url: str, destination: Path) -> ImportedProject:
            destination.mkdir(parents=True)
            (destination / 'main.py').write_text('source', encoding='utf-8')
            return ImportedProject(destination, 'repo', 1, 6)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = Store(root / 'state.json')
            with mock.patch.object(main, 'store', store), mock.patch.object(main, 'PROJECTS_DIR', root / 'projects'), mock.patch.object(main, 'import_github_project', side_effect=download):
                with TestClient(main.app) as client:
                    response = client.post('/api/projects', data={'github_url': 'https://github.com/owner/repo'})
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertEqual(response.json()['name'], 'repo')
                    self.assertEqual(response.json()['github_url'], 'https://github.com/owner/repo')
                    self.assertTrue((Path(response.json()['source_dir']) / 'main.py').is_file())
                    response = client.post('/api/projects', data={'github_url': 'https://github.com/owner/repo'}, files={'project_zip': ('x.zip', b'x')})
                    self.assertEqual(response.status_code, 400)
                    with mock.patch.object(main, 'import_github_project', side_effect=ProjectImportError('下载失败')):
                        response = client.post('/api/projects', data={'github_url': 'https://github.com/owner/missing'})
                        self.assertEqual(response.status_code, 400)
                        self.assertEqual(len(store.list_projects()), 1)

    def test_start_syncs_github_snapshot_and_handles_failure(self) -> None:
        from app.project_import import ProjectImportError
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            project_id = 'a' * 32
            source = root / 'projects' / project_id / 'source'
            source.mkdir(parents=True)
            (source / 'main.py').write_text('old', encoding='utf-8')
            (source / 'removed.py').write_text('file', encoding='utf-8')
            store = Store(root / 'state.json')
            store.add_project({'id': project_id, 'source_dir': str(source), 'github_url': 'https://github.com/owner/repo'})
            def download(url, destination):
                destination.mkdir(parents=True)
                (destination / 'main.py').write_text(download.content, encoding='utf-8')
                (destination / ('removed.py' if download.content == 'old' else 'added.py')).write_text('file', encoding='utf-8')
            with mock.patch.object(main, 'store', store), mock.patch.object(main, 'PROJECTS_DIR', root / 'projects'), mock.patch.object(main, '_schedule_task'), mock.patch.object(main, '_preflight', return_value=[]), mock.patch.object(main, 'import_github_project', side_effect=download):
                with TestClient(main.app) as client:
                    for index, content in enumerate(('old', 'new', 'new')):
                        task_id = str(index) * 32
                        workspace = root / task_id
                        workspace.mkdir()
                        store.add_task({'id': task_id, 'project_id': project_id, 'workspace': str(workspace), 'status': 'draft', 'environment_ready': True})
                        download.content = content
                        response = client.post(f'/api/tasks/{task_id}/start')
                        self.assertEqual(response.status_code, 200, response.text)
                        self.assertEqual(response.json()['github_updated'], index == 1)
                        self.assertEqual((Path(response.json()['source_dir']) / 'main.py').read_text(encoding='utf-8'), content)
                        self.assertFalse((workspace / 'github-changes.json').exists())
                        self.assertEqual(response.json()['github_change_counts'], {'added': int(index == 1), 'modified': int(index == 1), 'deleted': int(index == 1)})
                        if index == 1:
                            from app import runner
                            task = {**response.json(), 'budget': 1, 'duration_seconds': 60, 'instruction': 'audit', 'model': 'm', 'prices': {'input_per_mtok': 0, 'output_per_mtok': 0}}
                            prompt = runner._audit_prompt(task, workspace, mock.Mock(spent=0), 60, 1, False)
                            self.assertNotIn('github-changes.json', prompt)
                            self.assertNotIn('main.py', prompt)
                            self.assertIn('检查原有漏洞在当前源码中是否仍然存在', prompt)
                    task_id = '3' * 32
                    store.add_task({'id': task_id, 'project_id': project_id, 'workspace': raw, 'status': 'draft', 'environment_ready': True})
                    with mock.patch.object(main, 'import_github_project', side_effect=ProjectImportError('下载失败')):
                        self.assertEqual(client.post(f'/api/tasks/{task_id}/start').status_code, 502)
                    self.assertEqual(store.get_task(task_id)['status'], 'draft')

    def test_initialization_syncs_source_without_a_change_list(self) -> None:
        from app.project_import import ProjectImportError
        async def scenario(root: Path) -> None:
            project_id = 'a' * 32
            project_dir = root / 'projects' / project_id
            source = project_dir / 'source'
            source.mkdir(parents=True)
            (source / 'app.py').write_text('old', encoding='utf-8')
            store = Store(root / 'state.json')
            store.add_project({'id': project_id, 'source_dir': str(source), 'github_url': 'https://github.com/owner/repo', 'initialization': {'workspace': str(project_dir / 'setup'), 'status': 'preparing', 'environment_status': 'preparing'}})
            def download(url, destination):
                destination.mkdir(parents=True)
                (destination / 'app.py').write_text('new', encoding='utf-8')
            async def prepare(event_id, adapter, hub):
                task = adapter.get_task(event_id)
                self.assertEqual((Path(task['source_dir']) / 'app.py').read_text(encoding='utf-8'), 'new')
                self.assertFalse((Path(task['workspace']) / 'github-changes.json').exists())
                return True
            with mock.patch.object(main, 'store', store), mock.patch.object(main, 'PROJECTS_DIR', root / 'projects'), mock.patch.object(main, 'import_github_project', side_effect=download), mock.patch.object(main, '_prepare_environment', side_effect=prepare):
                await main._initialize_project(project_id)
                project = store.get_project(project_id)
                self.assertEqual(project['source_dir'], project['initialization']['source_dir'])
                self.assertEqual(project['initialization']['environment_status'], 'ready')
                self.assertTrue(project['initialization']['github_updated'])
                with mock.patch.object(main, 'import_github_project', side_effect=ProjectImportError('下载失败')), mock.patch.object(main, '_prepare_environment', new=mock.AsyncMock()) as prepare_mock:
                    await main._initialize_project(project_id)
                    prepare_mock.assert_not_awaited()
                    self.assertEqual(store.get_project(project_id)['initialization']['environment_status'], 'failed')
                    self.assertIn('下载失败', store.get_project(project_id)['initialization']['error'])
        with tempfile.TemporaryDirectory() as raw:
            asyncio.run(scenario(Path(raw)))

    def test_existing_project_can_be_linked_to_github(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            store = Store(Path(raw) / 'state.json')
            store.add_project({'id': 'p', 'name': 'repo'})
            with mock.patch.object(main, 'store', store), TestClient(main.app) as client:
                url = '/api/projects/p/github'
                self.assertEqual(client.put(url, json={'github_url': 'https://example.com/owner/repo'}).status_code, 400)
                response = client.put(url, json={'github_url': 'https://github.com/owner/repo.git'})
                self.assertEqual(response.json()['github_url'], 'https://github.com/owner/repo')
                self.assertEqual(client.put(url, json={'github_url': 'https://github.com/other/repo'}).status_code, 409)

    def test_import_and_delete_large_project_with_long_path(self) -> None:
        from app.project_import import filesystem_path

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = Store(root / 'state.json')
            archive = io.BytesIO()
            long_name = '/'.join(['nested-directory-' + 'x' * 25] * 6 + ['file.txt'])
            with zipfile.ZipFile(archive, 'w') as bundle:
                for index in range(10_001):
                    bundle.writestr(f'files/{index}.txt', b'x')
                bundle.writestr(long_name, b'long path')
            with mock.patch.object(main, 'store', store), mock.patch.object(main, 'PROJECTS_DIR', root / 'projects'):
                with TestClient(main.app) as client:
                    response = client.post('/api/projects', data={'name': 'large'}, files={'project_zip': ('large.zip', archive.getvalue(), 'application/zip')})
                    self.assertEqual(response.status_code, 200, response.text)
                    project = response.json()
                    target = Path(project['source_dir']).joinpath(*long_name.split('/'))
                    self.assertGreater(len(str(target)), 260)
                    self.assertEqual(filesystem_path(target).read_bytes(), b'long path')
                    self.assertEqual(client.delete(f"/api/projects/{project['id']}").status_code, 200)
                    self.assertFalse(Path(project['source_dir']).exists())

    def test_generic_environment_snapshot_is_bound_and_deleted(self) -> None:
        from test_generic_receipt_adapter import config, prepare
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = Store(root / 'state.json')
            store.upsert_provider({'id': 'p', 'name': 'provider', 'models': [{'id': 'm', 'input_per_mtok': 1, 'output_per_mtok': 2}]})
            store.set_receipt_settings({'evidence_hmac_key': 'test-receipt-key', 'attacker_image': 'example/receipt@sha256:' + 'a' * 64})
            project_id = 'b' * 32
            source = root / 'projects' / project_id / 'source'
            source.mkdir(parents=True)
            environment = source.parent / 'setup' / 'environment'
            environment.mkdir(parents=True)
            prepare(environment)
            manifest = write_closed_model(environment, source, attacker='author', victim='reader', path_id='a-b')
            manifest['adapter'] = 'generic-compose'
            (environment / 'receipt-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
            (environment / 'create-accounts.py').write_text('ACCOUNT_PLAN = "account-plan.json"\n', encoding='utf-8')
            store.add_project({'id': project_id, 'name': 'demo', 'source_dir': str(source), 'initialization': {'environment_status': 'ready'}})
            manifests = root / 'manifests'
            with mock.patch.object(main, 'store', store), mock.patch.object(main, 'PROJECTS_DIR', root / 'projects'), mock.patch.object(main, 'WORKSPACES_DIR', root / 'workspaces'), mock.patch.object(main, 'RECEIPT_MANIFESTS_DIR', manifests), mock.patch.object(main, '_schedule_task'):
                with TestClient(main.app) as client:
                    response = client.post('/api/tasks', data={'project_id': project_id, 'instruction': 'audit', 'provider_id': 'p', 'model': 'm', 'budget': '1', 'duration_minutes': '10', 'base_url': 'http://127.0.0.1:8000', 'receipt_enabled': 'true'})
                    self.assertEqual(response.status_code, 200, response.text)
                    task = response.json()
                    snapshot = manifests / f"task-{task['id']}"
                    (environment / 'receipt-adapter.json').write_text('{}', encoding='utf-8')
                    self.assertEqual(json.loads((snapshot / 'receipt-adapter.json').read_text(encoding='utf-8')), config())
                    self.assertEqual(client.delete(f"/api/tasks/{task['id']}").status_code, 200)
                    self.assertFalse(snapshot.exists())

    def test_generated_manifest_is_snapshotted_per_task_and_removed_on_delete(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = Store(root / 'state.json')
            store.upsert_provider({'id': 'p', 'name': 'provider', 'models': [{'id': 'm', 'input_per_mtok': 1, 'output_per_mtok': 2}]})
            store.set_receipt_settings({'evidence_hmac_key': 'test-receipt-key', 'attacker_image': 'example/receipt@sha256:' + 'a' * 64})
            project_id = 'a' * 32
            source = root / 'projects' / project_id / 'source'
            source.mkdir(parents=True)
            environment = source.parent / 'setup' / 'environment'
            environment.mkdir(parents=True)
            manifest = write_closed_model(environment, source)
            (environment / 'receipt-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
            store.add_project({'id': project_id, 'name': 'demo', 'source_dir': str(source), 'initialization': {'environment_status': 'ready'}})
            manifests = root / 'manifests'
            with mock.patch.object(main, 'store', store), mock.patch.object(main, 'PROJECTS_DIR', root / 'projects'), mock.patch.object(main, 'WORKSPACES_DIR', root / 'workspaces'), mock.patch.object(main, 'RECEIPT_MANIFESTS_DIR', manifests), mock.patch.object(main, 'target_adapter_for'), mock.patch.object(main, '_schedule_task'):
                with TestClient(main.app) as client:
                    response = client.post('/api/tasks', data={'project_id': project_id, 'instruction': 'audit', 'provider_id': 'p', 'model': 'm', 'budget': '1', 'duration_minutes': '10', 'base_url': 'http://127.0.0.1:8000', 'receipt_enabled': 'true'})
                    self.assertEqual(response.status_code, 200, response.text)
                    task = response.json()
                    snapshot = manifests / task['receipt_manifest']
                    self.assertEqual(json.loads(snapshot.read_text(encoding='utf-8')), manifest)
                    (environment / 'receipt-manifest.json').write_text('{}', encoding='utf-8')
                    self.assertEqual(json.loads(snapshot.read_text(encoding='utf-8')), manifest)
                    self.assertTrue((Path(task['workspace']) / 'environment' / 'receipt-manifest.json').exists())
                    self.assertEqual(client.delete(f"/api/tasks/{task['id']}").status_code, 200)
                    self.assertFalse(snapshot.exists())

    def test_threat_role_editor_validates_and_invalidates_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            project_id = 'e' * 32
            source = root / 'projects' / project_id / 'source'
            environment = source.parent / 'setup' / 'environment'
            manifest = write_closed_model(environment, source)
            (environment / 'receipt-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
            test_store = Store(root / 'state.json')
            test_store.add_project({'id': project_id, 'source_dir': str(source), 'initialization': {'environment_status': 'ready'}})
            with mock.patch.object(main, 'store', test_store), mock.patch.object(main, 'PROJECTS_DIR', root / 'projects'), TestClient(main.app) as client:
                url = f'/api/projects/{project_id}/threat-model/roles'
                result = client.get(url).json()
                self.assertEqual(len(result['roles']), 2)
                body = {'digest': result['digest'], 'disposition': 'include', 'reason': '重新核实后的理由', 'evidence_kind': 'assumption', 'evidence_path': '', 'evidence_literal': '待核实'}
                saved = client.put(url + '/a', json=body)
                self.assertEqual(saved.status_code, 200, saved.text)
                self.assertEqual(saved.json()['project']['initialization']['coverage_status'], 'review_required')
                self.assertEqual(client.put(url + '/a', json=body).status_code, 409)
                self.assertEqual(client.post(f'/api/projects/{project_id}/threat-model/acknowledge').status_code, 200)
                body['digest'] = saved.json()['digest']
                body['disposition'] = 'exclude'
                before = (environment / 'threat-decisions.json').read_text(encoding='utf-8')
                self.assertEqual(client.put(url + '/a', json=body).status_code, 400)
                self.assertEqual((environment / 'threat-decisions.json').read_text(encoding='utf-8'), before)
                body.update(disposition='include', evidence_kind='source', evidence_path='roles.js', evidence_literal='missing')
                self.assertEqual(client.put(url + '/a', json=body).status_code, 400)
                body.update(evidence_literal='a')
                saved = client.put(url + '/a', json=body)
                self.assertEqual(saved.status_code, 200, saved.text)
                self.assertEqual(saved.json()['project']['initialization']['coverage_status'], 'closed')
                self.assertIsNone(saved.json()['project']['initialization']['threat_model_ack'])

    def test_unacknowledged_assumption_blocks_generated_manifest_until_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = Store(root / 'state.json')
            store.upsert_provider({'id': 'p', 'name': 'provider', 'models': [{'id': 'm', 'input_per_mtok': 1, 'output_per_mtok': 2}]})
            store.set_receipt_settings({'evidence_hmac_key': 'test-receipt-key', 'attacker_image': 'example/receipt@sha256:' + 'a' * 64})
            project_id = 'd' * 32
            source = root / 'projects' / project_id / 'source'
            environment = source.parent / 'setup' / 'environment'
            manifest = write_closed_model(environment, source)
            decisions = json.loads((environment / 'threat-decisions.json').read_text(encoding='utf-8'))
            decisions['roles'][0]['evidence'] = {'kind': 'assumption', 'path': '', 'literal': '资料不足'}
            (environment / 'threat-decisions.json').write_text(json.dumps(decisions), encoding='utf-8')
            (environment / 'receipt-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
            store.add_project({'id': project_id, 'name': 'demo', 'source_dir': str(source), 'initialization': {'environment_status': 'ready'}})
            payload = {'project_id': project_id, 'instruction': 'audit', 'provider_id': 'p', 'model': 'm', 'budget': '1', 'duration_minutes': '10', 'receipt_enabled': 'true'}
            with mock.patch.object(main, 'store', store), mock.patch.object(main, 'PROJECTS_DIR', root / 'projects'), mock.patch.object(main, 'WORKSPACES_DIR', root / 'workspaces'), mock.patch.object(main, 'RECEIPT_MANIFESTS_DIR', root / 'manifests'), mock.patch.object(main, 'target_adapter_for'), mock.patch.object(main, '_schedule_task'):
                with TestClient(main.app) as client:
                    blocked = client.post('/api/tasks', data=payload)
                    self.assertEqual(blocked.status_code, 409, blocked.text)
                    self.assertIn('未确认的假设', blocked.text)
                    acknowledged = client.post(f'/api/projects/{project_id}/threat-model/acknowledge')
                    self.assertEqual(acknowledged.status_code, 200, acknowledged.text)
                    self.assertEqual(acknowledged.json()['initialization']['coverage_status'], 'review_required')
                    created = client.post('/api/tasks', data=payload)
                    self.assertEqual(created.status_code, 200, created.text)
                    decisions['roles'][0]['reason'] = '改写后的假设'
                    (environment / 'threat-decisions.json').write_text(json.dumps(decisions), encoding='utf-8')
                    stale = client.post('/api/tasks', data=payload)
                    self.assertEqual(stale.status_code, 409, stale.text)
                    self.assertIn('未确认的假设', stale.text)

    def test_initialization_materials_are_inherited_and_project_deletion_cascades(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = Store(root / 'state.json')
            store.upsert_provider({'id': 'p', 'name': 'provider', 'models': [{'id': 'm', 'input_per_mtok': 1, 'output_per_mtok': 2}]})
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w') as bundle:
                bundle.writestr('app.py', 'print(1)')

            async def prepare(event_id, adapter, hub):
                task = adapter.get_task(event_id)
                environment = Path(task['workspace']) / 'environment'
                environment.mkdir(parents=True, exist_ok=True)
                files = {'compose.yaml': 'services:\n  app:\n    image: example\n', 'start.py': 'pass', 'create-accounts.py': 'pass', 'receipt-manifest.json': '{}', 'READY.md': 'ready'}
                for name, content in files.items():
                    (environment / name).write_text(content, encoding='utf-8')
                event = adapter.append_event(event_id, {'type': 'text', 'text': 'preparing'})
                hub.publish(event_id, event)
                adapter.update_task(event_id, status='draft', environment_status='pending')
                return True

            with mock.patch.object(main, 'store', store), mock.patch.object(main, 'PROJECTS_DIR', root / 'projects'), mock.patch.object(main, 'WORKSPACES_DIR', root / 'workspaces'), mock.patch.object(main, '_prepare_environment', prepare), mock.patch.object(main, '_schedule_task'):
                with TestClient(main.app) as client:
                    project = client.post('/api/projects', data={'name': 'demo'}, files={'project_zip': ('demo.zip', archive.getvalue(), 'application/zip')}).json()
                    project_id = project['id']
                    response = client.post(f'/api/projects/{project_id}/initialize', data={'provider_id': 'p', 'model': 'm', 'instruction': '修复启动脚本'})
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json()['initialization']['instruction'], '修复启动脚本')
                    # The fake runner completes in the same event loop before the next request.
                    project = client.get('/api/projects').json()[0]
                    self.assertEqual(project['initialization']['environment_status'], 'ready')
                    self.assertEqual(client.get(f'/api/projects/{project_id}/events/older', params={'before': 100}).json()['events'][0]['text'], 'preparing')
                    self.assertIn('READY.md', client.get(f'/api/projects/{project_id}/environment').json()['files'])
                    self.assertEqual(client.get(f'/api/projects/{project_id}/environment/content', params={'path': '../events.jsonl'}).status_code, 404)
                    task = client.post('/api/tasks', data={'project_id': project_id, 'instruction': 'audit', 'provider_id': 'p', 'model': 'm', 'budget': '1', 'duration_minutes': '10'}).json()
                    self.assertTrue((Path(task['workspace']) / 'environment' / 'READY.md').is_file())
                    self.assertTrue((Path(task['workspace']) / 'environment' / 'receipt-manifest.json').exists())
                    self.assertEqual(client.delete(f'/api/projects/{project_id}').status_code, 200)
                    self.assertEqual(client.get('/api/tasks').json(), [])
                    self.assertFalse(Path(task['workspace']).exists())
                    self.assertFalse((root / 'projects' / project_id).exists())

    def test_deleting_task_cancels_running_job_before_removing_workspace(self) -> None:
        async def scenario(root: Path) -> None:
            store = Store(root / 'state.json')
            task_id = 'a' * 32
            workspace = root / 'workspaces' / task_id
            workspace.mkdir(parents=True)
            store.add_task({'id': task_id, 'workspace': str(workspace), 'status': 'running'})
            stopped = asyncio.Event()

            async def worker():
                try:
                    await asyncio.Event().wait()
                finally:
                    self.assertTrue(workspace.exists())
                    stopped.set()

            job = asyncio.create_task(worker())
            await asyncio.sleep(0)
            main._RUNNING[task_id] = job
            try:
                with mock.patch.object(main, 'store', store), mock.patch.object(main, 'WORKSPACES_DIR', root / 'workspaces'):
                    await main.delete_task(task_id)
                self.assertTrue(stopped.is_set())
                self.assertFalse(workspace.exists())
                self.assertIsNone(store.get_task(task_id))
            finally:
                main._RUNNING.pop(task_id, None)

        with tempfile.TemporaryDirectory() as raw:
            asyncio.run(scenario(Path(raw)))
