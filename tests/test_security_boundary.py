import json
import tempfile
import threading
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app.security_boundary import BoundaryError, check_browser_auth, execute_boundary_plan, load_boundary_plan


class SecurityBoundaryTests(unittest.TestCase):
    def test_primary_and_cleanup_errors_are_both_reported_without_response_body(self):
        info = {'base_url': 'http://127.0.0.1:1234/', 'accounts': {}}
        read = {'method': 'GET', 'path': '/state', 'account': 'anonymous', 'statuses': [200]}
        case = {'request': {'method': 'POST', 'path': '/write', 'account': 'anonymous', 'statuses': [201]},
                'state': {'request': read, 'changed': True},
                'cleanup': {'method': 'DELETE', 'path': '/cleanup', 'account': 'anonymous', 'statuses': [204]}}
        plan = {'controls': [{'id': 'write', 'checks': [case]}]}
        with mock.patch('app.security_boundary._request', side_effect=[(200, b'initial', {}), (422, b'secret', {}), (401, b'secret', {})]):
            result = execute_boundary_plan(plan, info)[0]
        self.assertFalse(result['ok'])
        self.assertIn('主请求 POST /write', result['message'])
        self.assertIn('实际 422', result['message'])
        self.assertIn('清理请求 DELETE /cleanup', result['message'])
        self.assertIn('实际 401', result['message'])
        self.assertNotIn('secret', result['message'])

    def test_independent_http_checks_and_cleanup(self):
        class Handler(BaseHTTPRequestHandler):
            config = 'title: example\n'
            allow_anonymous = False
            write_but_reject = False

            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == '/':
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="test"')
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.config.encode())

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                allowed = self.allow_anonymous or self.headers.get('Authorization') == 'Basic YWRtaW46c2VjcmV0'
                if allowed or self.write_but_reject:
                    type(self).config = data['config']
                self.send_response(200 if allowed else 401)
                self.end_headers()

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            info = {'base_url': f'http://127.0.0.1:{server.server_port}/', 'accounts': {'admin': {'username': 'admin', 'password': 'secret'}}}
            read = {'method': 'GET', 'path': '/state', 'account': 'admin', 'statuses': [200]}
            cleanup = {'method': 'POST', 'path': '/write', 'account': 'admin', 'statuses': [200], 'json': {'config': '{{original}}'}}
            deny = {'request': {'method': 'POST', 'path': '/write', 'account': 'anonymous', 'statuses': [401], 'json': {'config': '{{original}}# {{marker}}'}},
                    'state': {'request': read, 'changed': False}, 'cleanup': cleanup}
            allow = {'request': {**deny['request'], 'account': 'admin', 'statuses': [200]},
                     'state': {'request': read, 'changed': True}, 'cleanup': cleanup}
            plan = {'controls': [{'id': 'write', 'checks': [deny, allow]}]}
            self.assertFalse(check_browser_auth(info, '')['ok'])
            self.assertTrue(check_browser_auth(info, 'basic')['ok'])
            self.assertTrue(execute_boundary_plan(plan, info)[0]['ok'])
            self.assertEqual(Handler.config, 'title: example\n')
            Handler.allow_anonymous = True
            self.assertFalse(execute_boundary_plan(plan, info)[0]['ok'])
            self.assertEqual(Handler.config, 'title: example\n')
            Handler.allow_anonymous = False
            Handler.write_but_reject = True
            self.assertFalse(execute_boundary_plan(plan, info)[0]['ok'])
            self.assertEqual(Handler.config, 'title: example\n')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_plan_evidence_and_mutation_requirements(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            environment = root / 'environment'
            environment.mkdir()
            policy = root / 'security-policy'
            policy.mkdir()
            (policy / 'security.md').write_text('Writes require authentication.', encoding='utf-8')
            file = environment / 'security-controls.json'
            file.write_text('{"controls":[],"no_controls_reason":"optional deployment"}', encoding='utf-8')
            self.assertEqual(load_boundary_plan(root, environment, {'admin'})['controls'], [])
            request = {'method': 'GET', 'path': '/admin', 'account': 'anonymous', 'statuses': [401]}
            allowed = {'method': 'GET', 'path': '/admin', 'account': 'admin', 'statuses': [200]}
            plan = {'controls': [{'id': 'auth', 'evidence': {'path': 'security-policy/security.md', 'quote': 'Writes require authentication.'}, 'checks': [{'request': request}, {'request': allowed}]}], 'no_controls_reason': ''}
            file.write_text(json.dumps(plan), encoding='utf-8')
            self.assertEqual(len(load_boundary_plan(root, environment, {'admin'})['controls']), 1)
            plan['controls'][0]['evidence']['quote'] = 'invented'
            file.write_text(json.dumps(plan), encoding='utf-8')
            with self.assertRaises(BoundaryError):
                load_boundary_plan(root, environment, {'admin'})
            plan['controls'][0]['evidence']['quote'] = 'Writes require authentication.'
            plan['controls'][0]['checks'][0]['request'] = {'method': 'POST', 'path': '/admin', 'account': 'anonymous', 'statuses': [403]}
            file.write_text(json.dumps(plan), encoding='utf-8')
            with self.assertRaises(BoundaryError):
                load_boundary_plan(root, environment, {'admin'})
