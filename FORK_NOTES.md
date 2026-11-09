# Local initialization fixes

This fork fixes two initialization errors in the upstream 0.2.4 code:

- macOS scanner results without `salt` metadata no longer produce an empty return map. Salts come from the selected account's databases and candidate keys must pass page-one HMAC verification.
- Empty extraction results no longer report initialization success. Existing empty or malformed key files trigger a retry; unsuccessful macOS scans preserve the previous key file.

Each macOS scan uses a private temporary directory and checks the scanner exit status, so stale output cannot be mistaken for a fresh result.

Run the regression tests with:

```sh
python -m unittest discover -s tests -v
```

## Extraction compatibility

These changes do not add a new memory-scanning algorithm. The bundled legacy scanner still returned no keys on a tested macOS arm64 installation with WeChat 4.1.11.

Successful local extraction used the independently built helper from [upstream PR #27](https://github.com/huohuoer/wechat-cli/pull/27), commit `294f5b7be2f4dda2a53280be77167d351f14e6db`. Its verified keys were then used with this fork to read sessions and sample group messages. That PR is not merged here, and its full changes have not been accepted as part of this fork.

No keys, account paths, chat data, local configuration, or generated helper binaries are included. Existing upstream initialization may still attempt to re-sign WeChat if process access is denied; this patch does not change that behavior.
