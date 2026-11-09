"""init 命令 — 交互式初始化，提取密钥并生成配置"""

import json
import os
import sys

import click

from ..core.config import STATE_DIR, STATE_OWNER, CONFIG_FILE, KEYS_FILE, auto_detect_db_dir


@click.command()
@click.option("--db-dir", default=None, help="微信数据目录路径（默认自动检测）")
@click.option("--force", is_flag=True, help="强制重新提取密钥")
@click.option("--prepare-helper", is_flag=True, help="macOS：编译并签名本工具的独立扫描器")
@click.option("--timeout", type=click.IntRange(1, 600), default=300, show_default=True,
              help="macOS 内存扫描超时秒数")
def init(db_dir, force, prepare_helper, timeout):
    """初始化 wechat-cli：提取密钥并生成配置"""
    click.echo("WeChat CLI 初始化")
    click.echo("=" * 40)

    if prepare_helper:
        if sys.platform != "darwin":
            raise click.ClickException("--prepare-helper 仅支持 macOS")
        from ..keys.scanner_macos import build_probe, _find_binary
        try:
            try:
                binary = _find_binary()
            except RuntimeError:
                binary = build_probe()["binary"]
        except (OSError, RuntimeError, ValueError) as error:
            raise click.ClickException(str(error)) from error
        click.echo(f"[+] 扫描器已就绪: {binary}")
        click.echo("请保持微信已登录，再执行 init；仅本工具 helper 被签名。")
        return

    # 1. 检查是否已初始化
    if os.path.exists(CONFIG_FILE) and os.path.exists(KEYS_FILE) and not force:
        try:
            with open(KEYS_FILE, encoding="utf-8") as f:
                existing_keys = json.load(f)
        except (OSError, ValueError):
            existing_keys = {}
        if isinstance(existing_keys, dict) and any(
            isinstance(info, dict) and info.get("enc_key")
            for name, info in existing_keys.items() if not name.startswith("_")
        ):
            click.echo(f"已初始化（配置: {CONFIG_FILE}）")
            click.echo("使用 --force 重新提取密钥")
            return
        click.echo("[!] 已有密钥文件为空或无效，重新提取")

    # 2. 创建状态目录
    os.makedirs(STATE_DIR, exist_ok=True)
    if STATE_OWNER is not None:
        os.chown(STATE_DIR, *STATE_OWNER)

    # 3. 确定 db_dir
    if db_dir is None:
        db_dir = auto_detect_db_dir()
        if db_dir is None:
            click.echo("[!] 未能自动检测到微信数据目录", err=True)
            click.echo("请通过 --db-dir 参数指定，例如:", err=True)
            click.echo("  wechat-cli init --db-dir ~/path/to/db_storage", err=True)
            sys.exit(1)
        click.echo(f"[+] 检测到微信数据目录: {db_dir}")
    else:
        db_dir = os.path.abspath(db_dir)
        if not os.path.isdir(db_dir):
            click.echo(f"[!] 目录不存在: {db_dir}", err=True)
            sys.exit(1)
        click.echo(f"[+] 使用指定数据目录: {db_dir}")

    # 4. 提取密钥
    click.echo("\n开始提取密钥...")
    try:
        from ..keys import extract_keys
        key_map = extract_keys(db_dir, KEYS_FILE, timeout=timeout)
        if not key_map:
            raise RuntimeError("未提取到有效密钥，初始化未完成")
        if STATE_OWNER is not None:
            os.chown(KEYS_FILE, *STATE_OWNER)
    except RuntimeError as e:
        click.echo(f"\n[!] 密钥提取失败: {e}", err=True)
        if "sudo" not in str(e).lower():
            click.echo("提示: macOS/Linux 可能需要 sudo 权限", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"\n[!] 密钥提取出错: {e}", err=True)
        sys.exit(1)

    # 5. 写入配置
    cfg = {
        "db_dir": db_dir,
    }
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    if STATE_OWNER is not None:
        os.chown(CONFIG_FILE, *STATE_OWNER)

    click.echo(f"\n[+] 初始化完成!")
    click.echo(f"    配置: {CONFIG_FILE}")
    click.echo(f"    密钥: {KEYS_FILE}")
    click.echo(f"    提取到 {len(key_map)} 个数据库密钥")
    click.echo("\n现在可以使用:")
    click.echo("  wechat-cli sessions")
    click.echo("  wechat-cli history \"联系人\"")
