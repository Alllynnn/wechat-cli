import hashlib
import hmac
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from wechat_cli.keys.scanner_macos import extract_keys


class MacKeysTest(unittest.TestCase):
    def run_scan(self, data, code=0):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / 'db_storage/session'
            db.mkdir(parents=True)
            salt = bytes(range(16))
            key = b'k' * 32
            page = salt + bytes(4016)
            mac_key = hashlib.pbkdf2_hmac('sha512', key, bytes(b ^ 0x3a for b in salt), 2, 32)
            page += hmac.new(mac_key, page[16:] + struct.pack('<I', 1), hashlib.sha512).digest()
            (db / 'session.db').write_bytes(page)
            out = root / 'saved.json'
            out.write_text('previous')
            def scan(*args, **kwargs):
                (Path(kwargs['cwd']) / 'all_keys.json').write_text(json.dumps(data))
                return subprocess.CompletedProcess(args, code, '', '')
            with patch('wechat_cli.keys.scanner_macos._find_binary', return_value='scanner'), patch('wechat_cli.keys.scanner_macos.subprocess.run', side_effect=scan):
                try:
                    result = extract_keys(str(db.parent), str(out))
                except RuntimeError:
                    self.assertEqual(out.read_text(), 'previous')
                    raise
            return result, json.loads(out.read_text())

    def test_native_output_without_salt(self):
        result, saved = self.run_scan({'session/session.db': {'enc_key': (b'k' * 32).hex()}})
        self.assertEqual(result, {bytes(range(16)).hex(): (b'k' * 32).hex()})
        self.assertEqual(len(saved), 1)

    def test_empty_output_preserves_previous(self):
        with self.assertRaises(RuntimeError):
            self.run_scan({})

    def test_failed_process_preserves_previous(self):
        with self.assertRaises(RuntimeError):
            self.run_scan({'session/session.db': {'enc_key': (b'k' * 32).hex()}}, 1)

    def test_wrong_key_preserves_previous(self):
        with self.assertRaises(RuntimeError):
            self.run_scan({'session/session.db': {'enc_key': (b'x' * 32).hex()}})

class InitTest(unittest.TestCase):
    def test_empty_existing_keys_retry_without_success(self):
        import importlib
        from click.testing import CliRunner
        module = importlib.import_module('wechat_cli.commands.init')
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'config.json'
            keys = Path(tmp) / 'all_keys.json'
            config.write_text('{"previous": true}')
            keys.write_text('{}')
            with patch.object(module, 'STATE_DIR', tmp), patch.object(module, 'CONFIG_FILE', str(config)), patch.object(module, 'KEYS_FILE', str(keys)), patch('wechat_cli.keys.extract_keys', return_value={}) as extract:
                result = CliRunner().invoke(module.init, ['--db-dir', tmp])
            extract.assert_called_once()
            self.assertEqual(result.exit_code, 1)
            self.assertNotIn('初始化完成!', result.output)
            self.assertEqual(json.loads(config.read_text()), {'previous': True})
