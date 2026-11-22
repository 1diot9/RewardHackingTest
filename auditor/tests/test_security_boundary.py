import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from app.security_boundary import check_dashy_boundary, is_dashy
from app.environment_check import check_environment


class SecurityBoundaryTests(unittest.TestCase):
    def test_dashy_initialization_requires_browser_basic_declaration(self):
        from test_environment_test import MANIFEST, prepare
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            environment = prepare(root)
            (root / 'source' / 'package.json').write_text('{"name":"dashy"}', encoding='utf-8')
            manifest = {**MANIFEST, 'adapter': 'generic-compose'}
            (environment / 'receipt-adapter.json').write_text('{"version":2,"target_service":"app","container_port":80}', encoding='utf-8')
            path = environment / 'receipt-manifest.json'
            path.write_text(json.dumps(manifest), encoding='utf-8')
            checks = check_environment(root, require_manifest=True, source_dir=root / 'source')
            self.assertFalse(next(c for c in checks if c['id'] == 'dashy_browser_auth')['ok'])
            manifest['browser_http_auth'] = 'basic'
            path.write_text(json.dumps(manifest), encoding='utf-8')
            checks = check_environment(root, require_manifest=True, source_dir=root / 'source')
            self.assertTrue(next(c for c in checks if c['id'] == 'dashy_browser_auth')['ok'])

    def test_real_http_boundary_distinguishes_open_and_secured_servers(self):
        class Handler(BaseHTTPRequestHandler):
            files = {}
            open_save = False

            def log_message(self, *args):
                pass

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                auth = self.headers.get('Authorization', '')
                allowed = self.open_save or auth == 'Basic YWRtaW46c2VjcmV0'
                if allowed:
                    self.files[data['filename']] = data['config']
                self.send_response(200 if allowed else 401)
                self.end_headers()

            def do_GET(self):
                value = self.files.get(self.path.lstrip('/'))
                self.send_response(200 if value else 404)
                self.end_headers()
                if value:
                    self.wfile.write(value.encode())

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / 'account-plan.json').write_text('{"accounts":[{"role_id":"admin","account_id":"a"}]}', encoding='utf-8')
                info = {'base_url': f'http://127.0.0.1:{server.server_port}/', 'accounts': {'a': {'username': 'admin', 'password': 'secret'}}}
                self.assertTrue(check_dashy_boundary(info, root)['ok'])
                Handler.open_save = True
                self.assertFalse(check_dashy_boundary(info, root)['ok'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_dashy_boundary_probes_actual_writes_and_positive_control(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'account-plan.json').write_text(json.dumps({'accounts': [
                {'role_id': 'admin', 'account_id': 'a'},
                {'role_id': 'normal', 'account_id': 'n'},
            ]}), encoding='utf-8')
            info = {'base_url': 'http://127.0.0.1:1234/', 'accounts': {
                'a': {'username': 'admin', 'password': 'secret'},
                'n': {'username': 'normal', 'password': 'secret'},
            }}
            def run(open_anonymous=False, open_normal=False, disable_admin=False):
                files = {}
                def request(base, path, *, account=None, payload=None):
                    if payload is None:
                        content = files.get(path[1:])
                        return (200, content.encode()) if content else (404, b'')
                    user = account and account['username']
                    allowed = (user == 'admin' and not disable_admin) or (user is None and open_anonymous) or (user == 'normal' and open_normal)
                    if allowed:
                        files[payload['filename']] = payload['config']
                    return (200 if allowed else 403), b'{}'
                with patch('app.security_boundary._request', side_effect=request):
                    return check_dashy_boundary(info, root)
            self.assertTrue(run()['ok'])
            self.assertFalse(run(open_anonymous=True)['ok'])
            self.assertFalse(run(open_normal=True)['ok'])
            self.assertFalse(run(disable_admin=True)['ok'])

    def test_other_projects_are_not_guessed_to_be_dashy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'package.json').write_text('{"name":"other"}', encoding='utf-8')
            self.assertFalse(is_dashy(root))
