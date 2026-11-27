from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from claude_agent_sdk import AssistantMessage, ResultMessage, StreamEvent, TextBlock, UserMessage

from app import runner
from app.pricing import Ledger, Prices, Tokens, UsageAccumulator


class SetupStreamTests(unittest.IsolatedAsyncioTestCase):
    async def test_precompact_hook_notifies_without_changing_hook_output(self) -> None:
        for environment_setup in (False, True):
            with self.subTest(environment_setup=environment_setup):
                notify = mock.Mock()
                with mock.patch.object(runner, '_snapshot_reports', return_value={}):
                    options = runner._build_options(
                        {'model': 'test'}, Path('.'), '', '', lambda _: None,
                        environment_setup=environment_setup, on_compact=notify,
                    )
                hook = options.hooks['PreCompact'][0].hooks[0]
                result = await hook({'trigger': 'auto'}, None, {})
                self.assertEqual(result, {})
                notify.assert_called_once_with()

    async def test_distinct_stream_event_ids_count_one_model_call(self) -> None:
        class Client:
            async def receive_response(self):
                yield StreamEvent(uuid='event-1', session_id='s', event={'type': 'message_start', 'message': {'id': 'msg-1', 'usage': {'input_tokens': 100, 'output_tokens': 1}}})
                yield StreamEvent(uuid='event-2', session_id='s', event={'type': 'message_delta', 'usage': {'output_tokens': 10}})
                yield AssistantMessage(content=[], model='test', session_id='s', uuid='event-3', message_id='msg-1', usage={'input_tokens': 100, 'output_tokens': 10})

        pending = UsageAccumulator()
        with mock.patch.object(runner, '_emit'):
            await runner._consume_run(Client(), mock.Mock(), mock.Mock(), {'budget': 100}, 'task', Ledger(), Prices(1, 1, 1, 1), '', Path('.'), pending)
        self.assertEqual(pending.tokens.input, 100)
        self.assertEqual(pending.tokens.output, 10)

    async def test_usage_without_a_message_start_cannot_stop_budget(self) -> None:
        class Client:
            async def receive_response(self):
                for index, output in enumerate((4, 10)):
                    event = {'type': 'message_delta', 'usage': {'output_tokens': output}}
                    yield StreamEvent(uuid=f'event-{index}', session_id='s', event=event)
                yield ResultMessage(
                    subtype='success', duration_ms=0, duration_api_ms=0, is_error=False,
                    num_turns=1, session_id='s', model_usage={'test': {'outputTokens': 10}},
                )

        ledger = Ledger()
        pending = UsageAccumulator()
        with mock.patch.object(runner, '_emit'), mock.patch.object(runner, 'request_stop') as stop:
            outcome = await runner._consume_run(
                Client(), mock.Mock(), mock.Mock(), {'budget': 12}, 'task',
                ledger, Prices(0, 1_000_000, 0, 0), '', Path('.'), pending,
            )
            stop.assert_not_called()
        self.assertEqual(outcome, 'ok')
        self.assertEqual(ledger.spent, 10)
        self.assertFalse(pending.calls)

    async def test_closed_stream_cannot_absorb_usage_from_another_call(self) -> None:
        class Client:
            async def receive_response(self):
                events = (
                    {'type': 'message_start', 'message': {'id': 'msg-1', 'usage': {'input_tokens': 10}}},
                    {'type': 'message_stop'},
                    {'type': 'message_delta', 'usage': {'output_tokens': 50}},
                )
                for index, event in enumerate(events):
                    yield StreamEvent(uuid=f'event-{index}', session_id='s', event=event)
                yield AssistantMessage(
                    content=[], model='test', session_id='s', message_id='msg-2',
                    usage={'input_tokens': 5},
                )

        pending = UsageAccumulator()
        with mock.patch.object(runner, '_emit'):
            await runner._consume_run(
                Client(), mock.Mock(), mock.Mock(), {'budget': 100}, 'task',
                Ledger(), Prices(1, 1, 1, 1), '', Path('.'), pending,
            )
        self.assertEqual(pending.tokens.input, 15)
        self.assertEqual(pending.tokens.output, 0)

    async def test_reopened_session_can_settle_a_confirmed_counter_reset(self) -> None:
        class Client:
            async def receive_response(self):
                yield AssistantMessage(
                    content=[], model='test', session_id='s', message_id='m',
                    usage={'input_tokens': 10},
                )
                yield ResultMessage(
                    subtype='success', duration_ms=0, duration_api_ms=0, is_error=False,
                    num_turns=1, session_id='s', model_usage={'test': {'inputTokens': 10}},
                )

        prices = Prices(1, 1, 1, 1)
        original = Ledger()
        original.settle_session('s', Tokens(input=100), prices, Tokens())
        ledger = Ledger.from_snapshot(original.persistence())
        pending = UsageAccumulator()
        with mock.patch.object(runner, '_emit'):
            await runner._consume_run(
                Client(), mock.Mock(), mock.Mock(), {'budget': 100}, 'task',
                ledger, prices, '', Path('.'), pending, resumed_session_id='s',
            )
        self.assertEqual(ledger.tokens, Tokens(input=110))
        self.assertEqual(ledger.session_baselines['s'], Tokens(input=10))
        self.assertFalse(pending.calls)

    async def test_audit_stream_reports_character_counts_without_content(self) -> None:
        class Client:
            async def receive_response(self):
                for event in [
                    {'type': 'message_start'},
                    {'type': 'content_block_delta', 'delta': {'type': 'text_delta', 'text': '你好'}},
                    {'type': 'content_block_delta', 'delta': {'type': 'input_json_delta', 'partial_json': 'secret'}},
                ]:
                    yield StreamEvent(uuid='m', session_id='s', event=event)
                yield AssistantMessage(content=[TextBlock(text='你好')], model='test')

        hub = mock.Mock()
        with mock.patch.object(runner, '_emit'):
            await runner._consume_run(Client(), mock.Mock(), hub, {'budget': 100}, 'task', Ledger(), Prices(0, 0, 0, 0), 'secret', Path('.'), UsageAccumulator())
        events = [call.args[1] for call in hub.publish.call_args_list]
        self.assertEqual([event['characters'] for event in events[:-1]], [0, 2, 8])
        self.assertTrue(all(event['text'] == '' for event in events))
        self.assertEqual(events[-1]['type'], 'model_stream_end')

    async def test_model_failure_is_preserved_without_api_key(self) -> None:
        class Client:
            async def receive_response(self):
                yield ResultMessage(subtype='error_during_execution', duration_ms=0, duration_api_ms=0, is_error=True, num_turns=1, session_id='s', result='API Error 500 secret')

        store = mock.Mock()
        with mock.patch.object(runner, '_emit'):
            outcome = await runner._consume_run(Client(), store, mock.Mock(), {}, 'project:test', Ledger(), Prices(0, 0, 0, 0), 'secret', Path('.'), UsageAccumulator(), track_usage=False)
        self.assertEqual(outcome, 'error')
        store.update_task.assert_any_call('project:test', error='API Error 500 ***')

    async def test_long_setup_stream_counts_all_characters(self) -> None:
        class Client:
            async def receive_response(self):
                yield StreamEvent(uuid='m', session_id='s', event={'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text'}})
                yield StreamEvent(uuid='m', session_id='s', event={'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': 'a' * 13000}})
                yield StreamEvent(uuid='m', session_id='s', event={'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': 'LATEST'}})

        hub = mock.Mock()
        with mock.patch.object(runner, '_emit'):
            await runner._consume_run(Client(), mock.Mock(), hub, {}, 'project:test', Ledger(), Prices(0, 0, 0, 0), '', Path('.'), UsageAccumulator(), track_usage=False)
        snapshots = [call.args[1] for call in hub.publish.call_args_list]
        self.assertEqual([event['characters'] for event in snapshots], [13000, 13006])
        self.assertTrue(all(event['text'] == '' for event in snapshots))

    async def test_setup_stream_only_exposes_counts_and_records_final_message_once(self) -> None:
        def stream(event: dict) -> StreamEvent:
            return StreamEvent(uuid="message", session_id="session", event=event)

        messages = [
            stream({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            stream({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hello sec"}}),
            stream({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "ret!"}}),
            AssistantMessage(content=[TextBlock(text="hello secret!")], model="test"),
            UserMessage(content="tool result"),
        ]

        class Client:
            async def receive_response(self):
                for message in messages:
                    yield message

        hub = mock.Mock()
        store = mock.Mock()
        recorded = []
        with mock.patch.object(runner, "_emit", side_effect=lambda *args, **kwargs: recorded.append((args[3], args[4]))):
            await runner._consume_run(Client(), store, hub, {}, "project:test", Ledger(), Prices(0, 0, 0, 0), "secret", Path('.'), UsageAccumulator(), track_usage=False)

        live = [call.args[1] for call in hub.publish.call_args_list]
        self.assertEqual([event['characters'] for event in live[:-1]], [9, 13])
        self.assertTrue(all(event['text'] == '' for event in live))
        self.assertEqual(live[-1]['type'], 'model_stream_end')
        self.assertEqual(recorded, [('text', 'hello ***!'), ('tool_result', 'tool result'), ('model_wait', '正在等待模型响应')])

