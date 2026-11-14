import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import integration as app


def alert(level=12, ident='test'):
    return {'id': ident, 'agent': {'id': '001'}, 'rule': {'id': '100001', 'level': level}, 'full_log': 'password=hunter2 email=someone@example.com card=4111 1111 1111 1111'}


ANALYSIS = {'summary': 'Synthetic event', 'evidence': ['Supplied alert'], 'likely_cause': 'Unknown', 'impact': 'Unconfirmed', 'confidence': 'low', 'recommended_actions': ['Review original logs']}


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = {'database': str(Path(self.tmp.name) / 'queue.sqlite3'), 'queue_limit': 100, 'ai_attempts': 2, 'delivery_attempts': 3, 'telegram_interval': 1.2, 'ai_interval': 2, 'http_timeout': 1, 'retention_days': 30, 'chat_id': '6415347828', 'model': 'openai/gpt-4o-mini'}
        self.db = app.connect(self.cfg)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def row(self):
        return self.db.execute('SELECT * FROM queue').fetchone()

    def test_filter_all_boundaries(self):
        app.selftest_filter()
        for level in [0, 11, 17, True, '12', None]:
            self.assertEqual(app.enqueue(self.db, self.cfg, alert(level)), 'ignored')
        self.assertIsNone(self.row())

    def test_dedup_and_pre_storage_redaction(self):
        self.assertEqual(app.enqueue(self.db, self.cfg, alert()), 'queued')
        self.assertEqual(app.enqueue(self.db, self.cfg, alert()), 'duplicate')
        for value in ['hunter2', 'someone@example.com', '4111 1111 1111 1111']:
            self.assertNotIn(value, self.row()['payload'])
        changed = alert()
        changed['agent']['id'] = '002'
        self.assertEqual(app.enqueue(self.db, self.cfg, changed), 'queued')

    def test_missing_identity_does_not_collapse_unrelated_events(self):
        first, second = alert(), alert()
        del first['id']
        del second['id']
        second['full_log'] = 'Different event'
        self.assertEqual(app.enqueue(self.db, self.cfg, first), 'queued')
        self.assertEqual(app.enqueue(self.db, self.cfg, second), 'queued')

    def test_secret_redaction_nested_and_keys(self):
        data = {'access_token': 'sensitive', 'data': ['Bearer abcdef', 'sk-or-v1-' + 'a' * 40, '123456789:' + 'b' * 35, '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----']}
        output = json.dumps(app.redact(data))
        for secret in ['sensitive', 'abcdef', 'a' * 40, 'b' * 35, '\\nsecret']:
            self.assertNotIn(secret, output)

    def test_split_respects_telegram_unicode_limit(self):
        text = 'A😀' * 10000
        chunks = app.split_message(text)
        self.assertEqual(''.join(chunks), text)
        self.assertTrue(all(len(c.encode('utf-16-le')) // 2 + 50 <= 4096 for c in chunks))

    def test_schema_rejects_extra_or_wrong_fields(self):
        self.assertEqual(app.validated(ANALYSIS), ANALYSIS)
        for data in [{**ANALYSIS, 'execute': 'rm -rf'}, {**ANALYSIS, 'confidence': 'certain'}, {**ANALYSIS, 'evidence': 'not a list'}, {**ANALYSIS, 'summary': ''}]:
            with self.assertRaises(ValueError):
                app.validated(data)

    @patch.object(app, 'rate')
    @patch.object(app, 'post', return_value={'ok': True})
    @patch.object(app, 'analyse', side_effect=app.RemoteError())
    @patch.dict(app.os.environ, {'TELEGRAM_BOT_TOKEN': 'synthetic'})
    def test_ai_failure_retries_then_sends_fallback(self, analyse, post, rate):
        app.enqueue(self.db, self.cfg, alert())
        app.process(self.db, self.cfg, self.row())
        post.assert_not_called()
        self.assertGreater(self.row()['due'], app.time.time())
        app.process(self.db, self.cfg, self.row())
        self.assertIn('AI analysis unavailable', post.call_args.args[1]['text'])
        self.assertEqual(self.row()['status'], 'sent')

    @patch.object(app, 'rate')
    @patch.object(app, 'analyse', return_value=ANALYSIS)
    @patch.dict(app.os.environ, {'TELEGRAM_BOT_TOKEN': 'synthetic'})
    def test_partial_delivery_resumes_without_repeating_completed_parts(self, analyse, rate):
        data = alert()
        data['full_log'] = 'safe log ' * 900
        app.enqueue(self.db, self.cfg, data)
        with patch.object(app, 'post', side_effect=[{'ok': True}, app.RemoteError(120)]):
            app.process(self.db, self.cfg, self.row())
        self.assertEqual(self.row()['next_part'], 1)
        self.assertGreaterEqual(self.row()['due'], app.time.time() + 115)
        with patch.object(app, 'post', return_value={'ok': True}) as post:
            app.process(self.db, self.cfg, self.row())
            self.assertTrue(post.call_args.args[1]['text'].startswith('[2/'))
        self.assertEqual(analyse.call_count, 1)
        self.assertEqual(self.row()['status'], 'sent')

    @patch.object(app, 'rate')
    @patch.object(app, 'analyse', return_value=ANALYSIS)
    @patch.object(app, 'post', side_effect=app.RemoteError())
    @patch.dict(app.os.environ, {'TELEGRAM_BOT_TOKEN': 'synthetic'})
    def test_exhausted_delivery_retains_dead_letter(self, post, analyse, rate):
        app.enqueue(self.db, self.cfg, alert())
        for _ in range(3):
            app.process(self.db, self.cfg, self.row())
        self.assertEqual(self.row()['status'], 'dead')
        self.assertIsNotNone(self.row()['payload'])

    def test_enqueue_never_calls_network(self):
        with patch.object(app, 'post', side_effect=AssertionError('network forbidden')):
            app.enqueue(self.db, self.cfg, alert())

    def test_configuration_block_is_unique(self):
        spec = importlib.util.spec_from_file_location('installer', Path(__file__).with_name('install.py'))
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        original = '<ossec_config><integration><name>custom-other</name></integration></ossec_config><ossec_config></ossec_config>'
        updated = installer.integration_config(installer.integration_config(original))
        self.assertEqual(updated.count('<name>custom-llm-telegram</name>'), 1)
        self.assertIn('<name>custom-other</name>', updated)
        self.assertIn('<level>12</level>', updated)


if __name__ == '__main__':
    unittest.main()
