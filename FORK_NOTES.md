# macOS scanner integration

This fork includes the Config.Cipher memory scanner from
[upstream PR #27](https://github.com/huohuoer/wechat-cli/pull/27), source commit
`294f5b7be2f4dda2a53280be77167d351f14e6db`. The C helper's original copyright and
Apache-2.0 attribution are preserved. The integration includes its helper
resources, Python transport and validation, and macOS regression tests; it does
not import that PR's unrelated platform, query, or cache changes.

## Install and initialize

Install this fork from source; the upstream npm/PyPI packages do not contain this
integration. Python 3.10+ and Xcode Command Line Tools are required on macOS.

```sh
git clone https://github.com/Alllynnn/wechat-cli.git
cd wechat-cli
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/wechat-cli init --prepare-helper
sudo "$PWD/.venv/bin/wechat-cli" init --force
.venv/bin/wechat-cli sessions --limit 5
```

Keep WeChat logged in and select the current account's database directory. Use
`--db-dir /path/to/db_storage` to select it explicitly. Scanning defaults to
300 seconds and accepts `--timeout 600` for a longer run. Helper cache names
include a source/resource digest so upgrades build a new helper when needed.

The helper reads Config.Cipher objects and XOR-obfuscated candidates. Candidate
keys travel through a bounded anonymous socket and are verified against each
database's page-one HMAC before saving. Key files are published atomically with
mode 0600. Empty or failed scans do not replace existing keys or report success.
An existing empty key file triggers a retry.

Only this tool's helper is signed. It does not re-sign WeChat, disable SIP,
restart WeChat, or attach LLDB. System permissions can still deny memory access.

## Validation

Run regression tests (including a native chunk-boundary test on macOS) with:

```sh
python -m unittest discover -s tests -v
```

The integrated `init` command was validated locally on macOS arm64 with WeChat 4.1.11: all 18
selected-account database keys passed HMAC verification, followed by successful
session and sample group-history queries. This is not a guarantee for every
WeChat version, account, or macOS security configuration. No keys, account paths,
chat data, local configuration, or generated helper binaries are committed.
