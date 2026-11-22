from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from app.runner import ConcurrencyLimiter
from app.store import Store


class ConcurrencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_resize_wakes_waiters_and_does_not_interrupt_active_tasks(self) -> None:
        limiter = ConcurrencyLimiter(1)
        started = [asyncio.Event() for _ in range(3)]
        release = [asyncio.Event() for _ in range(3)]

        async def job(index: int) -> None:
            async with limiter:
                started[index].set()
                await release[index].wait()

        jobs = [asyncio.create_task(job(i)) for i in range(3)]
        try:
            await asyncio.wait_for(started[0].wait(), 1)
            self.assertFalse(started[1].is_set())
            await limiter.set_limit(2)
            await asyncio.wait_for(started[1].wait(), 1)
            await limiter.set_limit(1)
            release[0].set()
            await jobs[0]
            self.assertFalse(started[2].is_set())
            release[1].set()
            await asyncio.wait_for(started[2].wait(), 1)
        finally:
            for event in release:
                event.set()
            await asyncio.gather(*jobs)

    async def test_cancelled_waiter_does_not_consume_capacity(self) -> None:
        limiter = ConcurrencyLimiter(1)
        async with limiter:
            waiter = asyncio.create_task(limiter.__aenter__())
            await asyncio.sleep(0)
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
        async with limiter:
            self.assertEqual(limiter.active, 1)


class ConcurrencySettingsTests(unittest.TestCase):
    def test_proxy_settings_validate_persist_and_apply_to_initialization(self) -> None:
        from app import main
        from app.runner import _build_options

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            store = Store(path)
            with mock.patch.object(main, 'store', store):
                client = TestClient(main.app)
                self.assertFalse(client.get('/api/settings/proxy').json()['enabled'])
                for url in ('', 'socks5://localhost:1080', 'http://user:pass@localhost:7890', 'http://localhost'):
                    self.assertEqual(client.put('/api/settings/proxy', json={'enabled': True, 'url': url}).status_code, 422)
                settings = {'enabled': True, 'url': 'http://127.0.0.1:7890', 'no_proxy': 'internal.example'}
                self.assertEqual(client.put('/api/settings/proxy', json=settings).json(), settings)
                self.assertEqual(Store(path).get_proxy_settings(), settings)
            with mock.patch.dict('os.environ', {'NO_PROXY': 'existing.example'}, clear=True):
                args = ({'model': 'demo', 'base_url': 'http://lab.example:8000'}, Path(directory), '', '', lambda _: None)
                setup = _build_options(*args, environment_setup=True, proxy_settings=settings)
                audit = _build_options(*args, proxy_settings=settings)
                disabled = _build_options(*args, environment_setup=True, proxy_settings={**settings, 'enabled': False})
            self.assertEqual(setup.env['HTTPS_PROXY'], settings['url'])
            self.assertEqual(setup.env['http_proxy'], settings['url'])
            for host in ('localhost', '127.0.0.1', '::1', 'lab.example', 'internal.example', 'existing.example'):
                self.assertIn(host, setup.env['NO_PROXY'].split(','))
            self.assertNotIn('HTTPS_PROXY', audit.env)
            self.assertNotIn('HTTPS_PROXY', disabled.env)

    def test_api_validates_and_persists_setting(self) -> None:
        from app import main

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            store = Store(path)
            with mock.patch.object(main, 'store', store), mock.patch.object(main, 'set_max_concurrent', new_callable=mock.AsyncMock) as apply:
                client = TestClient(main.app)
                self.assertEqual(client.put('/api/settings/concurrency', json={'max_concurrent': 0}).status_code, 422)
                self.assertEqual(client.put('/api/settings/concurrency', json={'max_concurrent': 1.5}).status_code, 422)
                response = client.put('/api/settings/concurrency', json={'max_concurrent': 3})
                self.assertEqual(response.json(), {'max_concurrent': 3})
                apply.assert_awaited_once_with(3)
                self.assertEqual(client.get('/api/settings/concurrency').json(), {'max_concurrent': 3})
                self.assertEqual(Store(path).get_max_concurrent(1), 3)
