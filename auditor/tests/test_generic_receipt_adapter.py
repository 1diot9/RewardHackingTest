from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from app.generic_receipt_adapter import GenericComposeAdapter, _login, load_adapter_config, load_run_info, page_http_credentials
from app.receipt import LoginStep, ReceiptError, TargetManifest, target_adapter_for


def manifest():
    return TargetManifest.from_mapping({
        'target': {'id': 'example', 'version': '1', 'image_digest': 'example'},
        'adapter': 'generic-compose', 'allowed_origins': ['{{target_origin}}'],
        'principals': [{'id': 'a', 'account_id': 'author'}, {'id': 'b', 'account_id': 'reader'}],
        'threat_paths': [{'id': 'a-b', 'attacker_principal': 'a', 'victim_principal': 'b', 'primary': True}],
    })


def config():
    return {'version': 2, 'target_service': 'web', 'container_port': 8080}


def prepare(root: Path):
    (root / 'receipt-adapter.json').write_text(json.dumps(config()), encoding='utf-8')
    (root / 'start.py').write_text('pass', encoding='utf-8')
    (root / 'create-accounts.py').write_text('pass', encoding='utf-8')
    (root / 'compose.yaml').write_text('services:\n  web:\n    image: example\n', encoding='utf-8')


class GenericAdapterTests(unittest.TestCase):
    def test_login_visibility_assertion_allows_multiple_matching_elements(self):
        page = mock.MagicMock()
        page.url = 'http://127.0.0.1:1234/'
        locator = page.locator.return_value
        first = locator.first
        steps = (LoginStep('assert_visible', selector='.there-are-items'),)

        first.is_visible.return_value = True
        self.assertTrue(_login(page, 'http://127.0.0.1:1234/', steps, {}))

        page.locator.assert_called_once_with('.there-are-items')
        first.is_visible.assert_called()
        first.wait_for.assert_not_called()
        locator.wait_for.assert_not_called()

    def test_login_click_does_not_wait_for_document_load(self):
        page = mock.MagicMock()
        page.url = 'http://127.0.0.1:1234/'
        self.assertTrue(_login(page, 'http://127.0.0.1:1234/', (LoginStep('click', selector='#submit'),), {}))
        page.locator.return_value.click.assert_called_once_with(no_wait_after=True)

    def test_login_visibility_timeout_returns_at_the_deadline(self):
        import time
        from app.process_bounds import StepTimeout

        page = mock.MagicMock()
        page.url = 'http://127.0.0.1:1234/'
        page.locator.return_value.first.is_visible.return_value = False
        started = time.monotonic()
        with self.assertRaises(StepTimeout) as caught:
            _login(
                page, 'http://127.0.0.1:1234/',
                (LoginStep('assert_visible', selector='#gone'),), {}, timeout_ms=200,
            )
        self.assertEqual(caught.exception.step, 'login.assert_visible')
        self.assertEqual(caught.exception.index, 0)
        self.assertLess(time.monotonic() - started, 2)

    def test_configuration_and_run_info_reject_invalid_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            self.assertEqual(load_adapter_config(root)['container_port'], 8080)
            invalid = config()
            invalid['login_profiles'] = {}
            (root / 'receipt-adapter.json').write_text(json.dumps(invalid), encoding='utf-8')
            with self.assertRaises(ReceiptError):
                load_adapter_config(root)
            (root / 'receipt-run.json').write_text(json.dumps({'base_url': 'http://example.com:1234/', 'accounts': {}}), encoding='utf-8')
            with self.assertRaises(ReceiptError):
                load_run_info(root, manifest())
            with self.assertRaises(ReceiptError):
                target_adapter_for(manifest())

    def test_isolated_run_login_and_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            commands = []
            page = mock.MagicMock()
            login_steps = (
                LoginStep('goto', path='/login'),
                LoginStep('fill', selector='#user', value='{{username}}'),
                LoginStep('fill', selector='#pass', value='{{password}}'),
                LoginStep('click', selector='#submit'),
                LoginStep('assert_visible', selector='#account'),
            )

            def run(command, cwd, env, timeout):
                commands.append(command)
                self.assertEqual(env['COMPOSE_PROJECT_NAME'], 'receipt-' + 'a' * 32)
                if command[0] == 'docker' and 'ps' in command:
                    return 'f' * 64
                if command[0] == 'docker' and 'port' in command:
                    return '127.0.0.1:1234'
                if '--verify' in command:
                    return 'ACCOUNTS_VERIFIED' if 'create-accounts' in ' '.join(command) else 'ENVIRONMENT_READY'
                if 'create-accounts' in ' '.join(command):
                    data = {'base_url': 'http://127.0.0.1:1234/', 'accounts': {'author': {'username': 'author', 'password': 'secret1'}, 'reader': {'username': 'reader', 'password': 'secret2'}}}
                    (Path(env['RECEIPT_RUN_DIR']) / 'receipt-run.json').write_text(json.dumps(data), encoding='utf-8')
                return ''

            with mock.patch('app.generic_receipt_adapter._run', side_effect=run), \
                 mock.patch('app.generic_receipt_adapter._login_cookie_header', return_value='session=attacker') as cookie_login, \
                 mock.patch('app.generic_receipt_adapter._login', return_value=True) as victim_login:
                with GenericComposeAdapter(root).open_run(manifest(), manifest().primary_path, 'a' * 32) as target:
                    self.assertEqual(target.attacker_base_url, 'http://target:8080/')
                    self.assertEqual(target.attacker_cookie_header, '')
                    self.assertEqual(target.login_attacker(login_steps), 'session=attacker')
                    self.assertTrue(target.login_victim(page, 'b', login_steps))
                    self.assertFalse(target.login_victim(page, 'a', login_steps))
                cookie_login.assert_called_once_with(
                    'http://127.0.0.1:1234/', login_steps,
                    {'username': 'author', 'password': 'secret1'}, 15000,
                )
                victim_login.assert_called_once_with(
                    page, 'http://127.0.0.1:1234/', login_steps,
                    {'username': 'reader', 'password': 'secret2'},
                    timeout_ms=15000,
                )
                self.assertIsNone(target.victim_http_credentials)
                self.assertEqual(commands[-1][-1], '--cleanup')
                self.assertTrue(any('disconnect' in command for command in commands))
                self.assertTrue(any('rm' in command for command in commands))

    def test_basic_http_auth_is_limited_to_page_browsers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            secured = TargetManifest.from_mapping({
                'target': {'id': 'example', 'version': '1', 'image_digest': 'example'},
                'adapter': 'generic-compose', 'allowed_origins': ['{{target_origin}}'],
                'principals': [{'id': 'a', 'account_id': 'author'}, {'id': 'b', 'account_id': 'reader'}],
                'threat_paths': [{'id': 'a-b', 'attacker_principal': 'a', 'victim_principal': 'b', 'primary': True}],
                'browser_http_auth': 'basic',
            })
            login_steps = (
                LoginStep('goto', path='/login'),
                LoginStep('fill', selector='#user', value='{{username}}'),
                LoginStep('fill', selector='#pass', value='{{password}}'),
                LoginStep('click', selector='#submit'),
                LoginStep('assert_visible', selector='#account'),
            )

            def run(command, cwd, env, timeout):
                if command[0] == 'docker' and 'ps' in command:
                    return 'f' * 64
                if command[0] == 'docker' and 'port' in command:
                    return '127.0.0.1:1234'
                if '--verify' in command:
                    return 'ACCOUNTS_VERIFIED' if 'create-accounts' in ' '.join(command) else 'ENVIRONMENT_READY'
                if 'create-accounts' in ' '.join(command):
                    data = {'base_url': 'http://127.0.0.1:1234/', 'accounts': {'author': {'username': 'author', 'password': 'secret1'}, 'reader': {'username': 'reader', 'password': 'secret2'}}}
                    (Path(env['RECEIPT_RUN_DIR']) / 'receipt-run.json').write_text(json.dumps(data), encoding='utf-8')
                return ''

            with mock.patch('app.generic_receipt_adapter._run', side_effect=run), \
                 mock.patch('app.generic_receipt_adapter._login_cookie_header', return_value='session=attacker') as cookie_login:
                with GenericComposeAdapter(root).open_run(secured, secured.primary_path, 'a' * 32) as target:
                    self.assertEqual(target.victim_http_credentials, {'username': 'reader', 'password': 'secret2'})
                    self.assertEqual(target.login_attacker(()), '')
                    self.assertEqual(target.login_attacker(login_steps), 'session=attacker')
                cookie_login.assert_called_once_with(
                    'http://127.0.0.1:1234/', login_steps,
                    {'username': 'author', 'password': 'secret1'}, 15000,
                    http_credentials={'username': 'author', 'password': 'secret1'},
                )
            self.assertIsNone(page_http_credentials('', {'username': 'author', 'password': 'secret1'}))

    def test_start_failure_still_cleans_up(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            calls = []
            def run(command, cwd, env, timeout):
                calls.append(command)
                if '--cleanup' not in command:
                    raise ReceiptError('failure')
                return ''
            with mock.patch('app.generic_receipt_adapter._run', side_effect=run):
                with self.assertRaises(ReceiptError):
                    with GenericComposeAdapter(root).open_run(manifest(), manifest().primary_path, 'a' * 32):
                        self.fail('must not yield')
            self.assertEqual(calls[-1][-1], '--cleanup')

    def test_cleanup_failure_does_not_replace_the_run_result(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)

            def run(command, cwd, env, timeout):
                if command[0] == 'docker' and 'ps' in command:
                    return 'f' * 64
                if command[0] == 'docker' and 'port' in command:
                    return '127.0.0.1:1234'
                if '--verify' in command:
                    return 'ACCOUNTS_VERIFIED' if 'create-accounts' in ' '.join(command) else 'ENVIRONMENT_READY'
                if 'create-accounts' in ' '.join(command):
                    data = {'base_url': 'http://127.0.0.1:1234/', 'accounts': {'author': {'username': 'author', 'password': 'secret1'}, 'reader': {'username': 'reader', 'password': 'secret2'}}}
                    (Path(env['RECEIPT_RUN_DIR']) / 'receipt-run.json').write_text(json.dumps(data), encoding='utf-8')
                    return ''
                if command[0] == 'docker' and 'rm' in command or '--cleanup' in command:
                    raise ReceiptError('cleanup failed')
                return ''

            with mock.patch('app.generic_receipt_adapter._run', side_effect=run):
                with GenericComposeAdapter(root).open_run(manifest(), manifest().primary_path, 'a' * 32) as target:
                    self.assertEqual(target.attacker_base_url, 'http://target:8080/')

    def test_cleanup_failure_preserves_start_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)

            def run(command, cwd, env, timeout):
                if '--cleanup' in command:
                    raise ReceiptError('cleanup failed')
                raise ReceiptError('start failed')

            with mock.patch('app.generic_receipt_adapter._run', side_effect=run):
                with self.assertRaises(ReceiptError) as caught:
                    with GenericComposeAdapter(root).open_run(manifest(), manifest().primary_path, 'a' * 32):
                        self.fail('must not yield')
            self.assertIn('start failed', str(caught.exception))

    def test_foreign_host_port_is_rejected_and_cleaned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            calls = []
            def run(command, cwd, env, timeout):
                calls.append(command)
                if '--verify' in command:
                    return 'ACCOUNTS_VERIFIED' if 'create-accounts' in ' '.join(command) else 'ENVIRONMENT_READY'
                if 'create-accounts' in ' '.join(command):
                    data = {'base_url': 'http://127.0.0.1:1234/', 'accounts': {'author': {'username': 'a', 'password': 'x'}, 'reader': {'username': 'b', 'password': 'y'}}}
                    (Path(env['RECEIPT_RUN_DIR']) / 'receipt-run.json').write_text(json.dumps(data), encoding='utf-8')
                if 'ps' in command:
                    return 'f' * 64
                if 'port' in command:
                    return '127.0.0.1:9999'
                return ''
            with mock.patch('app.generic_receipt_adapter._run', side_effect=run):
                with self.assertRaises(ReceiptError):
                    with GenericComposeAdapter(root).open_run(manifest(), manifest().primary_path, 'a' * 32):
                        self.fail('must not yield')
            self.assertEqual(calls[-1][-1], '--cleanup')
            self.assertFalse(any('create' in command and 'network' in command for command in calls))

    def test_login_cookie_survives_browser_close_error(self):
        from app.generic_receipt_adapter import _login_cookie_header

        class Page:
            def set_default_timeout(self, timeout):
                pass

        class Context:
            def new_page(self):
                return Page()

            def cookies(self, url):
                return [{'name': 'Cacti', 'value': 'abc'}]

        class Browser:
            def new_context(self):
                return Context()

            def close(self):
                raise RuntimeError('close failed')

        class Chromium:
            executable_path = 'chromium'

            @staticmethod
            def launch(**kwargs):
                return Browser()

        class PlaywrightManager:
            chromium = Chromium()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        api = types.ModuleType('playwright.sync_api')
        api.sync_playwright = PlaywrightManager
        package = types.ModuleType('playwright')
        package.sync_api = api
        with mock.patch.dict(sys.modules, {'playwright': package, 'playwright.sync_api': api}):
            header = _login_cookie_header('http://127.0.0.1:1234/', (), {'username': 'author', 'password': 'secret'}, 1000)
        self.assertEqual(header, 'Cacti=abc')

    def test_login_extracts_declared_storage_headers_and_rejects_missing(self):
        from app.generic_receipt_adapter import _login_cookie_header
        from app.receipt import AuthHeader, AttackerAuthMissing

        page = mock.Mock()
        page.evaluate.side_effect = ['jwt-token', 'custom-key']
        context = mock.Mock()
        context.new_page.return_value = page
        context.cookies.return_value = []
        browser = mock.Mock()
        browser.new_context.return_value = context
        manager = mock.MagicMock()
        manager.__enter__.return_value.chromium.launch.return_value = browser
        manager.__enter__.return_value.chromium.executable_path = 'chromium'
        api = types.ModuleType('playwright.sync_api')
        api.sync_playwright = lambda: manager
        package = types.ModuleType('playwright')
        package.sync_api = api
        mappings = (AuthHeader('localStorage', 'stirling_jwt', 'Authorization', 'Bearer '), AuthHeader('sessionStorage', 'apiKey', 'X-Api-Key'))
        with mock.patch.dict(sys.modules, {'playwright': package, 'playwright.sync_api': api}), mock.patch('app.generic_receipt_adapter._login'):
            session = _login_cookie_header('http://127.0.0.1:1234/', (), {}, 1000, mappings)
            self.assertEqual(session.headers, {'Authorization': 'Bearer jwt-token', 'X-Api-Key': 'custom-key'})
            page.evaluate.side_effect = [None]
            with self.assertRaises(AttackerAuthMissing):
                _login_cookie_header('http://127.0.0.1:1234/', (), {}, 1000, mappings)

    def test_attacker_network_uses_a_subnet_outside_the_default_pools(self):
        from app.generic_receipt_adapter import _attacker_subnet, _create_attacker_network

        first = _attacker_subnet('a' * 32)
        second = _attacker_subnet('a' * 32, 1)
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith('10.240.'))
        self.assertTrue(first.endswith('/28'))
        calls = []

        def run(command, cwd, env, timeout):
            calls.append(command)
            if calls and command[-1] == 'receipt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-attacker' and len(calls) == 1:
                error = ReceiptError('环境命令 docker network create 退出码 1')
                error.detail = 'Pool overlaps with other one on this address space'
                raise error
            return 'ok'

        with mock.patch('app.generic_receipt_adapter._run', side_effect=run):
            _create_attacker_network(Path('.'), {}, 'receipt-' + 'a' * 32 + '-attacker', 'a' * 32)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1:4], ['network', 'create', '--internal'])
        self.assertEqual(calls[0][4], '--subnet')
        self.assertEqual(calls[1][5], second)

    def test_stale_empty_receipt_networks_are_removed(self):
        from datetime import datetime, timedelta, timezone
        from app.generic_receipt_adapter import _release_stale_receipt_networks

        old = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S.000000000 +0000 UTC')
        fresh = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.000000000 +0000 UTC')
        stale = 'receipt-' + 'ab' * 16 + '_default'
        busy = 'receipt-' + 'cd' * 16 + '-attacker'
        recent = 'receipt-' + 'ef' * 16 + '_default'
        removed = []

        def run(command, cwd, env, timeout):
            if command[1:3] == ['network', 'ls']:
                return '\n'.join([stale, busy, recent, 'lab-other_default', 'bridge'])
            if command[1:3] == ['network', 'inspect']:
                created = fresh if command[3] == recent else old
                count = '2' if command[3] == busy else '0'
                return f'{count}|{created}'
            if command[1:3] == ['network', 'rm']:
                removed.append(command[3])
                return command[3]
            return ''

        with mock.patch('app.generic_receipt_adapter._run', side_effect=run):
            _release_stale_receipt_networks(Path('.'), {})
        self.assertEqual(removed, [stale])


if __name__ == '__main__':
    unittest.main()
