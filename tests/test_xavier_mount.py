"""HTTP mount contract tests; no live Xavier or database files."""
import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from build_pack import artifacts
from test_pack_to_xavier import make_record
from xavier_mount import main

TOKEN = 'secret-mount-test-token'


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, body):
        self.send_response(code)
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def handle_request(self):
        state = self.server.state
        state['calls'].append((self.command, self.path))
        if state.get('redirect'):
            self.send_response(307)
            self.send_header('Location', '/stolen')
            self.end_headers()
            return
        if state.get('fail') or self.headers.get('Authorization') != 'Bearer ' + TOKEN:
            return self.reply(500, {'error': TOKEN})
        if self.command == 'GET':
            if state.get('malformed'):
                return self.reply(200, {'unexpected': []})
            rows = list(state['memories'].values())
            query = parse_qs(urlsplit(self.path).query)
            offset = int(query.get('offset', ['0'])[0])
            limit = int(query.get('limit', ['100'])[0])
            return self.reply(200, {'memories': rows[offset:offset + limit],
                                    'total': len(rows)})
        if self.command == 'POST':
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if state.get('fail_second') and state['posts'] == 1:
                return self.reply(500, {'error': TOKEN})
            state['posts'] += 1
            identity = 'server-' + str(state['posts'])
            body['id'] = identity
            state['memories'][identity] = body
            return self.reply(201, {'id': identity})
        identity = unquote(urlsplit(self.path).path.removeprefix('/v1/memories/'))
        if not state.get('keep'):
            state['memories'].pop(identity, None)
        return self.reply(200, {})

    do_GET = handle_request
    do_POST = handle_request
    do_DELETE = handle_request

    def log_message(self, *args):
        pass


class MountTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pack = Path(self.tmp.name) / 'pack'
        for name, body in artifacts([make_record('r1'), make_record('r2')]).items():
            target = self.pack / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        self.receipt = Path(self.tmp.name) / 'receipt.json'
        self.server.state = {'memories': {}, 'calls': [], 'posts': 0}
        self.env = patch.dict(os.environ, {
            'XAVIER_URL': 'http://127.0.0.1:' + str(self.server.server_port),
            'XAVIER_TOKEN': TOKEN})
        self.env.start()
        self.addCleanup(self.env.stop)

    def invoke(self, action, *args):
        output = io.StringIO()
        with redirect_stdout(output):
            main([action, *map(str, args)])
        self.assertNotIn(TOKEN, output.getvalue())
        return json.loads(output.getvalue())

    def connect(self, *extra):
        return self.invoke('connect', '--source', self.pack, '--receipt', self.receipt,
                           '--revision', 'a' * 40, *extra)

    def test_connect_receipt_roundtrip_status_disconnect(self):
        self.assertTrue(self.connect()['verified'])
        saved = json.loads(self.receipt.read_text())
        self.assertEqual(saved['revision'], 'a' * 40)
        self.assertEqual(saved['manifest_sha256'], hashlib.sha256(
            (self.pack / 'manifest.json').read_bytes()).hexdigest())
        self.assertEqual([r['record_id'] for r in saved['records']], ['r1', 'r2'])
        self.assertEqual(self.invoke('status', '--receipt', self.receipt)['record_ids'],
                         ['server-1', 'server-2'])
        for memory in self.server.state['memories'].values():
            self.assertEqual(memory['metadata']['import_receipt']['revision'], 'a' * 40)
        self.invoke('disconnect', '--receipt', self.receipt)
        self.assertEqual(self.server.state['memories'], {})
        self.invoke('disconnect', '--receipt', self.receipt)  # idempotent

    def test_disconnect_without_receipt_and_namespace_isolation(self):
        self.connect()
        self.server.state['memories']['other'] = {'path': 'private/note', 'id': 'other'}
        self.invoke('disconnect', '--source', self.pack)
        self.assertEqual(set(self.server.state['memories']), {'other'})

    def test_receipt_does_not_delete_unlisted_namespace_record(self):
        self.connect()
        namespace = json.loads(self.receipt.read_text())['namespace']
        self.server.state['memories']['other'] = {'path': namespace + '/other', 'id': 'other'}
        self.invoke('disconnect', '--receipt', self.receipt)
        self.assertEqual(set(self.server.state['memories']), {'other'})

    def test_dry_run_all_actions_need_no_auth_or_network(self):
        with patch.dict(os.environ, {}, clear=True):
            self.connect('--dry-run')
            for action in ('status', 'disconnect'):
                self.invoke(action, '--source', self.pack, '--dry-run')
        self.assertEqual(self.server.state['calls'], [])
        self.assertFalse(self.receipt.exists())

    def test_errors_redacted(self):
        self.server.state['fail'] = True
        with self.assertRaises(SystemExit) as ctx:
            self.connect()
        self.assertIn('HTTP 500', str(ctx.exception))
        self.assertNotIn(TOKEN, str(ctx.exception))
        self.assertNotIn(os.environ['XAVIER_URL'], str(ctx.exception))

    def test_refuses_redirect(self):
        self.server.state['redirect'] = True
        with self.assertRaisesRegex(SystemExit, 'HTTP 307'):
            self.connect()
        self.assertEqual(len(self.server.state['calls']), 1)
        self.assertNotIn('/stolen', self.server.state['calls'][0][1])

    def test_partial_import_has_recovery_receipt(self):
        self.server.state['fail_second'] = True
        with self.assertRaises(SystemExit):
            self.connect()
        self.assertTrue(self.receipt.exists())
        self.assertEqual(len(self.server.state['memories']), 1)
        self.invoke('disconnect', '--receipt', self.receipt)
        self.assertEqual(self.server.state['memories'], {})

    def test_refuses_overwrite(self):
        self.connect()
        original = self.receipt.read_bytes()
        with self.assertRaises(SystemExit):
            self.connect()
        self.assertEqual(self.receipt.read_bytes(), original)
        self.receipt.unlink()
        with self.assertRaisesRegex(SystemExit, 'refusing overwrite'):
            self.connect()
        self.assertEqual(self.server.state['posts'], 2)

    def test_disconnect_verifies_deletions(self):
        self.connect()
        self.server.state['keep'] = True
        with self.assertRaisesRegex(SystemExit, 'mounted records remain'):
            self.invoke('disconnect', '--receipt', self.receipt)

    def test_status_and_disconnect_read_all_pages(self):
        self.connect()
        namespace = json.loads(self.receipt.read_text())['namespace']
        for number in range(105):
            identity = 'other-' + str(number)
            self.server.state['memories'][identity] = {
                'id': identity, 'path': namespace + '/' + identity}
        result = self.invoke('status', '--receipt', self.receipt)
        self.assertEqual(len(result['record_ids']), 107)
        self.invoke('disconnect', '--receipt', self.receipt)
        self.assertEqual(len(self.server.state['memories']), 105)
        self.assertNotIn('server-1', self.server.state['memories'])

    def test_manifest_pin_required_to_match(self):
        with self.assertRaisesRegex(SystemExit, 'Manifest hash mismatch'):
            self.connect('--manifest-sha256', '0' * 64)
        self.assertEqual(self.server.state['calls'], [])

    def test_tampered_pack_no_network(self):
        (self.pack / 'records/r1.json').write_text('{}')
        with self.assertRaises(SystemExit):
            self.connect()
        self.assertEqual(self.server.state['calls'], [])

    def test_bad_receipt_no_network(self):
        self.connect('--dry-run')
        self.receipt.write_text(json.dumps({'schema_version': 1, 'namespace': 'private'}))
        with self.assertRaises(SystemExit):
            self.invoke('disconnect', '--receipt', self.receipt)
        self.assertEqual(self.server.state['calls'], [])

    def test_refuses_remote_http_and_url_credentials(self):
        for url in ('http://example.com', 'https://user:password@example.com'):
            with patch.dict(os.environ, {'XAVIER_URL': url}):
                with self.assertRaises(SystemExit):
                    self.connect()
        self.assertEqual(self.server.state['calls'], [])

    def test_malformed_listing_fails_closed(self):
        self.server.state['malformed'] = True
        with self.assertRaisesRegex(SystemExit, 'Invalid memories listing'):
            self.connect()
        self.assertFalse(self.receipt.exists())

    def test_missing_token_no_network(self):
        with patch.dict(os.environ, {'XAVIER_TOKEN': ''}):
            with self.assertRaises(SystemExit):
                self.connect()
        self.assertEqual(self.server.state['calls'], [])

    def test_receipt_cannot_redirect_delete_using_memory_id(self):
        self.connect()
        receipt = json.loads(self.receipt.read_text())
        receipt['records'][0]['id'] = 'private-id'
        self.receipt.write_text(json.dumps(receipt))
        self.server.state['memories']['private-id'] = {'id': 'private-id', 'path': 'private/note'}
        self.invoke('disconnect', '--receipt', self.receipt)
        self.assertEqual(set(self.server.state['memories']), {'private-id'})


if __name__ == '__main__':
    unittest.main()
