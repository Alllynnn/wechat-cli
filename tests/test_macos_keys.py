import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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
            extract.assert_called_once_with(tmp, str(keys), timeout=300)
            self.assertEqual(result.exit_code, 1)
            self.assertNotIn('初始化完成!', result.output)
            self.assertEqual(json.loads(config.read_text()), {'previous': True})

    def test_prepare_builds_helper_without_scanning(self):
        import importlib
        from click.testing import CliRunner
        module = importlib.import_module('wechat_cli.commands.init')
        with patch.object(module.sys, 'platform', 'darwin'), patch(
            'wechat_cli.keys.scanner_macos._find_binary', side_effect=RuntimeError('missing')
        ), patch('wechat_cli.keys.scanner_macos.build_probe', return_value={'binary': '/test/helper'}) as build, patch(
            'wechat_cli.keys.extract_keys'
        ) as extract:
            result = CliRunner().invoke(module.init, ['--prepare-helper'])
        self.assertEqual(result.exit_code, 0, result.output)
        build.assert_called_once_with()
        extract.assert_not_called()

    def test_dispatch_passes_macos_timeout(self):
        from wechat_cli.keys import extract_keys
        with patch('wechat_cli.keys.platform.system', return_value='Darwin'), patch(
            'wechat_cli.keys.scanner_macos.extract_keys', return_value={'salt': 'key'}
        ) as extract:
            self.assertEqual(extract_keys('/db', '/out', timeout=420), {'salt': 'key'})
        extract.assert_called_once_with('/db', '/out', pid=None, timeout=420)

    def test_windows_dispatch_keeps_existing_signature(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from wechat_cli.keys import extract_keys
        extract = Mock(return_value={})
        with patch('wechat_cli.keys.platform.system', return_value='Windows'), patch.dict(
            'sys.modules', {'wechat_cli.keys.scanner_windows': SimpleNamespace(extract_keys=extract)}
        ):
            extract_keys('/db', '/out', timeout=420)
        extract.assert_called_once_with('/db', '/out', pid=None)

    def test_sudo_init_restores_caller_ownership(self):
        import importlib
        from click.testing import CliRunner
        module = importlib.import_module('wechat_cli.commands.init')
        with tempfile.TemporaryDirectory() as tmp:
            config = str(Path(tmp) / 'config.json')
            keys = str(Path(tmp) / 'all_keys.json')
            with patch.object(module, 'STATE_DIR', tmp), patch.object(module, 'STATE_OWNER', (501, 20)), patch.object(
                module, 'CONFIG_FILE', config
            ), patch.object(module, 'KEYS_FILE', keys), patch('wechat_cli.keys.extract_keys', return_value={'salt': 'key'}), patch.object(module.os, 'chown') as chown:
                result = CliRunner().invoke(module.init, ['--db-dir', tmp])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual([call.args for call in chown.call_args_list], [(tmp, 501, 20), (keys, 501, 20), (config, 501, 20)])

    def test_sudo_uses_callers_home_for_config(self):
        import runpy
        from types import SimpleNamespace
        from wechat_cli.core import config
        with patch('platform.system', return_value='Darwin'), patch('os.geteuid', return_value=0, create=True), patch.dict(
            'os.environ', {'SUDO_USER': 'synthetic'}
        ), patch('pwd.getpwnam', return_value=SimpleNamespace(pw_dir='/synthetic/home', pw_uid=501, pw_gid=20)):
            values = runpy.run_path(config.__file__)
        self.assertEqual(values['STATE_DIR'], '/synthetic/home/.wechat-cli')
        self.assertEqual(values['STATE_OWNER'], (501, 20))
